//! zix WebRTC worker: the peers one dispatch worker holds, and the fixed order it answers them in.
//!
//! What:
//! - One worker's whole state: its peer table, the batch its replies are queued into, and where that
//!   batch sends. Every dispatch model builds one of these, so the three loops differ only in how
//!   they learn a datagram arrived.
//! - The drain order lives here and nowhere else: send what the peer owes, tell the application what
//!   arrived, then send what the application produced.
//! - The fan-out behind `ctx.broadcast` too, because the table it walks is this worker's own.
//!
//! Note:
//! - Reversing the last two loses a reply until the next datagram. connection.zig clears its
//!   outbound queue at the top of every handle, so a loop that feeds it several datagrams without
//!   draining between them drops the earlier replies.
//! - One batch carries every peer's replies for a wake, so a wake that answered four peers costs one
//!   send syscall on Linux. Off Linux the batch's portable sink sends them through std.Io one at a
//!   time, which is what the raw UDP engine already does there.
//! - Nothing here reads a clock. The caller passes the time in, which is what keeps a whole session
//!   testable with no socket and no waiting.

const std = @import("std");

const Config = @import("../config.zig");
const WebrtcServerConfig = Config.WebrtcServerConfig;
const common = @import("common.zig");
const connection = @import("../connection.zig");
const core = @import("../core.zig");
const datagram = @import("../../datagram.zig");
const fanout = @import("../fanout.zig");
const table = @import("../table.zig");

const IpAddress = std.Io.net.IpAddress;

/// How many replies one worker queues before the batch is put on the wire to make room. Sized for a
/// wake that answered a handful of peers, each owing a handshake flight.
pub const SEND_BATCH: usize = 64;

/// Everything building a worker can raise.
pub const Error = error{OutOfMemory};

/// The peers one dispatch worker holds, and how they are answered.
///
/// Usage:
/// ```zig
/// var worker = try Worker.initDescriptor(config, fd);
/// defer worker.deinit();
///
/// worker.serve(handler, address, datagram, now_ms);
/// worker.flush();
/// ```
pub const Worker = struct {
    config: WebrtcServerConfig,
    /// The per-connection options every peer this worker opens is built with.
    options: connection.Options,
    peers: table.Table,
    /// Replies waiting to go out, for every peer this worker holds.
    tx: datagram.SendBatch,
    /// Scratch for one outbound datagram, on its way from a peer into the batch.
    out: []u8,
    /// Where the batch flushes. Ignored when the batch carries a portable sink.
    fd: std.posix.socket_t,

    /// Build a worker that sends through a raw descriptor, which is the two Linux models.
    ///
    /// Param:
    /// config - WebrtcServerConfig (already validated by the server)
    /// fd - std.posix.socket_t (the bound socket this worker receives and replies on)
    ///
    /// Return:
    /// - Worker
    /// - error.OutOfMemory
    pub fn initDescriptor(config: WebrtcServerConfig, fd: std.posix.socket_t) Error!Worker {
        return build(config, fd, null);
    }

    /// Build a worker that sends through a std.Io socket, which is the portable model.
    ///
    /// Param:
    /// config - WebrtcServerConfig (already validated by the server)
    /// socket - std.Io.net.Socket (the bound socket this worker receives and replies on)
    ///
    /// Return:
    /// - Worker
    /// - error.OutOfMemory
    pub fn initSocket(config: WebrtcServerConfig, socket: std.Io.net.Socket) Error!Worker {
        return build(config, socket.handle, .{ .socket = socket, .io = config.io });
    }

    /// Free the peers and the buffers.
    pub fn deinit(self: *Worker) void {
        self.peers.deinit();
        self.tx.deinit();
        self.config.allocator.free(self.out);
    }

    /// Give one datagram to the peer it came from, opening that peer when the address is new.
    ///
    /// Note:
    /// - A datagram from an unknown address past the table's ceiling is dropped, which reads to that
    ///   peer as a connectivity check nobody answered. It retransmits and gets in once a slot frees.
    ///
    /// Param:
    /// handler - comptime core.HandlerFn
    /// address - IpAddress (who sent it)
    /// bytes - []const u8 (the datagram, borrowed for this call)
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - void
    pub fn serve(self: *Worker, comptime handler: core.HandlerFn, address: IpAddress, bytes: []const u8, now_ms: u64) void {
        const peer = self.peers.find(address) orelse open: {
            const opened = self.peers.acquire(address, self.options, common.drawSecrets(), now_ms) catch |err| {
                common.logSystem(self.config, .WARN, "could not open a peer: {s}", .{@errorName(err)});

                return;
            };

            break :open opened orelse {
                common.logSystem(self.config, .WARN, "peer table is full ({d}), dropping a datagram from a new address", .{self.peers.live});

                return;
            };
        };

        const outcome = peer.handle(bytes, now_ms) catch |err| {
            common.logSystem(self.config, .WARN, "peer raised {s}", .{@errorName(err)});

            return;
        };

        if (outcome.dead) {
            _ = self.peers.release(address);

            return;
        }

        if (outcome.established) common.logSystem(self.config, .INFO, "peer completed the dtls handshake", .{});

        // Media before the drain. It is not DTLS-wrapped, so it does not travel through the peer's
        // own outbound queue, and holding it back until after the handler would put a frame behind
        // whatever the application produced.
        if (outcome.media) self.forwardMedia(peer);
        if (outcome.keyframe_requested) self.forwardKeyframeRequest(peer);

        self.drainPeer(handler, peer, now_ms);
    }

    /// Give every peer its due deadlines, drain what that produced, and let go of the finished.
    ///
    /// Param:
    /// handler - comptime core.HandlerFn
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - void
    pub fn sweep(self: *Worker, comptime handler: core.HandlerFn, now_ms: u64) void {
        var walk = self.peers.iterator();
        while (walk.next()) |peer| {
            const outcome = peer.tick(now_ms);

            if (outcome.dead) continue;

            self.drainPeer(handler, peer, now_ms);
        }

        const dropped = self.peers.dropDead();

        if (dropped > 0) common.logSystem(self.config, .WARN, "dropped {d} peer(s), {d} still held", .{ dropped, self.peers.live });
    }

    /// Put everything queued on the wire.
    ///
    /// Note:
    /// - A failed send clears the batch rather than retrying it. UDP promises no delivery, and every
    ///   layer above this one already retransmits what it cannot lose.
    pub fn flush(self: *Worker) void {
        if (self.tx.count == 0) return;

        self.tx.flush(self.fd) catch |err| {
            common.logSystem(self.config, .WARN, "send batch failed: {s}", .{@errorName(err)});

            self.tx.reset();
        };
    }

    /// How long this worker may wait for the next datagram.
    ///
    /// Note:
    /// - The soonest deadline any peer holds, capped by the tick interval. With no peers at all it
    ///   is the tick interval, so a bound socket with nobody on it still wakes up regularly rather
    ///   than parking forever.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - u32 (milliseconds)
    pub fn waitMs(self: *Worker, now_ms: u64) u32 {
        const soonest = self.peers.earliestDeadline() orelse return self.config.tick_interval_ms;

        if (soonest <= now_ms) return 0;

        return @intCast(@min(soonest - now_ms, @as(u64, self.config.tick_interval_ms)));
    }

    /// True when a peer's deadline has come and the sweep is owed a pass.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - bool
    pub fn sweepDue(self: *Worker, now_ms: u64) bool {
        const soonest = self.peers.earliestDeadline() orelse return false;

        return soonest <= now_ms;
    }

    /// Answer one peer: send what it owes, tell the application what arrived, then send what the
    /// application produced.
    ///
    /// Note:
    /// - Two queue passes, and both are needed. The first carries acknowledgements and handshake
    ///   flights. The second carries whatever the handler queued, which does not exist until the
    ///   handler has run.
    fn drainPeer(self: *Worker, comptime handler: core.HandlerFn, peer: *connection.Connection, now_ms: u64) void {
        self.queueOutbound(peer, now_ms);

        while (peer.nextEvent(now_ms) catch null) |event| {
            var ctx = peer.context(now_ms) orelse break;
            ctx.fanout = .{ .worker = @ptrCast(self), .deliver = deliverBroadcast };

            handler(event, &ctx) catch |err| common.logSystem(self.config, .WARN, "handler returned {s}", .{@errorName(err)});
        }

        self.queueOutbound(peer, now_ms);
    }

    /// Take one handler's message to every peer this worker holds but the one it came from.
    ///
    /// Note:
    /// - Each of those peers is drained on the spot, because the drain order above only reaches the
    ///   peer whose datagram woke it. Without this a broadcast would sit in the other peers' send
    ///   queues until each of them next said something.
    /// - A peer with no channel open yet, or one whose send queue is full, is skipped rather than
    ///   raised. A room does not lose a message over one member who cannot take it.
    fn deliverBroadcast(worker: *anyopaque, from: IpAddress, now_ms: u64, kind: fanout.Kind, bytes: []const u8) usize {
        const self: *Worker = @ptrCast(@alignCast(worker));

        var took: usize = 0;
        var walk = self.peers.iterator();

        while (walk.next()) |peer| {
            if (peer.address.eql(&from)) continue;

            const channels = (peer.context(now_ms) orelse continue).channels;

            var index: usize = 0;
            var sent = false;

            while (channels.at(index)) |open| : (index += 1) {
                if (!open.isSendable()) continue;

                channels.sendMessage(open.stream_identifier, kind, bytes, now_ms) catch continue;

                sent = true;
            }

            if (!sent) continue;

            self.queueOutbound(peer, now_ms);
            took += 1;
        }

        return took;
    }

    /// Take one peer's media packet to every other peer this worker holds.
    ///
    /// Note:
    /// - Opened once by the peer that sent it and sealed once per receiver, because no two peers
    ///   share a key. That re-protection is the whole cost of forwarding, and it is why a room of
    ///   N costs N seals per packet rather than one send.
    /// - Nothing here reads the payload. What changes is the header, and only where a receiver
    ///   renumbers the stream.
    /// - A peer that cannot take it is skipped. One member that negotiated no media, or that is
    ///   past its stream ceiling, does not cost the rest of the room a frame.
    fn forwardMedia(self: *Worker, from: *connection.Connection) void {
        const opened = from.openedMedia() orelse return;

        var joined = false;
        var walk = self.peers.iterator();

        while (walk.next()) |peer| {
            if (peer.address.eql(&from.address)) continue;
            if (peer.isNewSource(opened.header.ssrc)) joined = true;

            const packet = peer.sealMedia(opened, self.out) orelse continue;

            self.queueDatagram(peer.address, packet);
        }

        // Somebody was just put on this stream, and a stream joined partway through cannot be
        // decoded until a keyframe arrives. Nothing in the browser asks for one on a watcher's
        // behalf, so the forwarder asks the source itself.
        if (joined) self.requestKeyframe(from, opened.header.ssrc);
    }

    /// Carry one receiver's keyframe request to whichever peer is sending that stream.
    ///
    /// Note:
    /// - The receiver's own packet is never relayed. It names this server as the peer to answer,
    ///   and a sender handed it would authenticate it against the wrong key. What travels is the
    ///   request, rebuilt and sealed for the sender.
    fn forwardKeyframeRequest(self: *Worker, from: *connection.Connection) void {
        const source_ssrc = from.takeKeyframeRequest() orelse return;

        var walk = self.peers.iterator();

        while (walk.next()) |peer| {
            if (peer.address.eql(&from.address)) continue;
            if (!peer.sendsStream(source_ssrc)) continue;

            self.requestKeyframe(peer, source_ssrc);

            return;
        }
    }

    /// Ask one peer for a fresh keyframe on a stream it is sending.
    fn requestKeyframe(self: *Worker, source: *connection.Connection, source_ssrc: u32) void {
        const request = source.sealKeyframeRequest(source_ssrc, self.out) orelse return;

        self.queueDatagram(source.address, request);
    }

    /// Move everything one peer has waiting into the batch.
    fn queueOutbound(self: *Worker, peer: *connection.Connection, now_ms: u64) void {
        while (peer.nextOutbound(now_ms, self.out) catch null) |packet| {
            self.queueDatagram(peer.address, packet);
        }
    }

    /// Put one datagram in the batch, making room for it when the batch is already full.
    fn queueDatagram(self: *Worker, address: IpAddress, packet: []const u8) void {
        const destination = datagram.ipToSockaddr6(address);

        if (self.tx.queue(destination, packet)) return;

        // The batch is full: put it on the wire, then take the one that did not fit.
        self.flush();

        if (!self.tx.queue(destination, packet)) {
            common.logSystem(self.config, .WARN, "dropped a {d} byte reply the send batch could not hold", .{packet.len});
        }
    }

    /// The shared construction both entry points end in.
    fn build(config: WebrtcServerConfig, fd: std.posix.socket_t, portable: ?datagram.PortableSink) Error!Worker {
        const datagram_bytes = common.sendBufBytes(config);

        var peers = try table.Table.init(config.allocator, config.max_peers);
        errdefer peers.deinit();

        var tx = try datagram.SendBatch.init(config.allocator, SEND_BATCH, SEND_BATCH * datagram_bytes);
        errdefer tx.deinit();

        tx.portable = portable;

        const out = try config.allocator.alloc(u8, datagram_bytes);

        return .{
            .config = config,
            .options = common.optionsFrom(config),
            .peers = peers,
            .tx = tx,
            .out = out,
            .fd = fd,
        };
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const builtin = @import("builtin");

const Tls = @import("../../../tls/Tls.zig");
const dialer = @import("../dialer.zig");
const session = @import("test_session.zig");
const socket_poll = @import("../../../utils/socket_poll.zig");
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// The two ports the whole-session tests below bind, kept out of the range the model files use.
const TEST_ANY_UFRAG_PORT: u16 = 19099;
const TEST_BROADCAST_PORT: u16 = 19100;

/// Longest one turn of the loop below waits for a datagram that may not come.
const TEST_POLL_MS: u32 = 5;

/// What the last broadcast reached, for the test that checks a whole room got one message.
var broadcast_reach: usize = 0;

/// Take every message to the rest of the room instead of back to its sender.
fn broadcastHandler(event: core.Event, ctx: *core.Context) !void {
    switch (event) {
        .MESSAGE => |message| broadcast_reach = ctx.broadcast(message.kind, message.payload),
        else => {},
    }
}

/// Mutable because Tls.Context owns its certificate bytes, so the field is not const.
var test_certificate_der = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };

fn noopHandler(_: core.Event, _: *core.Context) !void {}

/// A context carrying just the two fields this engine reads, so a test needs no certificate file.
fn testContext(allocator: std.mem.Allocator) !Tls.Context {
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");

    return .{
        .allocator = allocator,
        .cert_der = &test_certificate_der,
        .signing_key = .{ .ecdsa_p256 = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(secret)) },
        .alpn = &.{},
        .curves = &.{},
        .ciphers = &.{},
        .min_version = .TLS_1_3,
        .max_version = .TLS_1_3,
        .prefer_server_ciphers = false,
        .hsts_max_age_s = 0,
    };
}

/// A logger that writes nowhere: console off and no save_path, so nothing is opened and nothing is
/// printed. It gives the rejection and drop paths a destination, which keeps a test's expected
/// failure message out of the runner's logged-error count.
const Logger = @import("../../../logger/logger.zig").Logger;

var quiet_logger = Logger{ .config = .{}, .allocator = std.testing.allocator };

fn testConfig(io: std.Io, allocator: std.mem.Allocator, tls: *Tls.Context) WebrtcServerConfig {
    return .{
        .io = io,
        .allocator = allocator,
        .ip = "127.0.0.1",
        .port = 9083,
        .dispatch_model = .ASYNC,
        .ice_ufrag = "zixL",
        .ice_password = "zixlocalpasswordaaaaaa",
        .peer_ice_ufrag = "peer",
        .tls = tls,
        .max_peers = 4,
        .logger = &quiet_logger,
    };
}

fn testAddress(port: u16) IpAddress {
    return .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = port } };
}

/// A datagram socket on whatever port the kernel has free, so a worker in a test is built the way
/// the portable model builds one rather than on a descriptor that is not a socket.
///
/// Note:
/// - std.posix.socket_t is a pointer on Windows, so there is no portable stand-in value to pass
///   instead. A real socket is also what lets these tests flush without minding where it goes.
fn testSocket(io: std.Io) !std.Io.net.Socket {
    const local = try std.Io.net.IpAddress.parse("127.0.0.1", 0);

    return local.bind(io, .{ .mode = .dgram, .protocol = .udp });
}

test "zix webrtc: worker, a new worker holds nobody and waits the tick interval" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.tick_interval_ms = 250;

    const socket = try testSocket(threaded.io());
    defer socket.close(threaded.io());

    var worker = try Worker.initSocket(config, socket);
    defer worker.deinit();

    try std.testing.expectEqual(@as(usize, 0), worker.peers.live);
    try std.testing.expectEqual(@as(u32, 250), worker.waitMs(1_000));
    try std.testing.expect(!worker.sweepDue(1_000));
}

test "zix webrtc: worker, a deadline already passed means no waiting and a sweep is owed" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    const config = testConfig(threaded.io(), std.testing.allocator, &tls);

    const socket = try testSocket(threaded.io());
    defer socket.close(threaded.io());

    var worker = try Worker.initSocket(config, socket);
    defer worker.deinit();

    _ = (try worker.peers.acquire(testAddress(5000), worker.options, common.drawSecrets(), 0)).?;

    // The peer's idle deadline sits at 30 seconds, so before then the wait is capped by the tick
    // interval, and after it there is nothing left to wait for.
    try std.testing.expectEqual(config.tick_interval_ms, worker.waitMs(0));
    try std.testing.expect(!worker.sweepDue(0));

    try std.testing.expectEqual(@as(u32, 0), worker.waitMs(30_000));
    try std.testing.expect(worker.sweepDue(30_000));
}

test "zix webrtc: worker, a connectivity check is answered into the send batch" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    const config = testConfig(threaded.io(), std.testing.allocator, &tls);

    const socket = try testSocket(threaded.io());
    defer socket.close(threaded.io());

    var worker = try Worker.initSocket(config, socket);
    defer worker.deinit();

    var peer = try dialer.Dialer.init(std.testing.allocator, .{
        .local_ufrag = "peer",
        .local_password = "peerpasswordbbbbbbbbbb",
        .peer_ufrag = "zixL",
        .peer_password = "zixlocalpasswordaaaaaa",
        .transaction_id = @splat(0x77),
        .client_random = @splat(0x11),
        .client_eph_secret = @splat(0x44),
        .sctp_cookie = @splat(0x9C),
        .sctp_tag = 0x55667788,
        .sctp_initial_tsn = 5000,
    }, 0);
    defer peer.deinit();

    var send_buf: [1500]u8 = undefined;
    const check = (try peer.nextOutbound(0, &send_buf)).?;

    worker.serve(noopHandler, testAddress(5000), check, 0);

    // The peer is now held, and its success response is queued rather than already sent.
    try std.testing.expectEqual(@as(usize, 1), worker.peers.live);
    try std.testing.expectEqual(@as(usize, 1), worker.tx.count);
}

test "zix webrtc: worker, a datagram nobody can parse still opens the peer and queues nothing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    const config = testConfig(threaded.io(), std.testing.allocator, &tls);

    const socket = try testSocket(threaded.io());
    defer socket.close(threaded.io());

    var worker = try Worker.initSocket(config, socket);
    defer worker.deinit();

    worker.serve(noopHandler, testAddress(5000), &[_]u8{ 22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4 }, 0);

    try std.testing.expectEqual(@as(usize, 1), worker.peers.live);
    try std.testing.expectEqual(@as(usize, 0), worker.tx.count);
}

test "zix webrtc: worker, a table at its ceiling drops the stranger and keeps the peers it has" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.max_peers = 2;

    const socket = try testSocket(threaded.io());
    defer socket.close(threaded.io());

    var worker = try Worker.initSocket(config, socket);
    defer worker.deinit();

    const garbage = [_]u8{ 22, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 1, 2, 3, 4 };

    worker.serve(noopHandler, testAddress(5000), &garbage, 0);
    worker.serve(noopHandler, testAddress(5001), &garbage, 0);
    worker.serve(noopHandler, testAddress(5002), &garbage, 0);

    try std.testing.expectEqual(@as(usize, 2), worker.peers.live);
    try std.testing.expect(worker.peers.find(testAddress(5000)) != null);
    try std.testing.expect(worker.peers.find(testAddress(5002)) == null);
}

/// One turn of a dispatch loop, standing in for the model files: take everything waiting on the
/// socket, let the deadlines run, and send what all of that produced.
fn passOnce(served: *Worker, comptime handler: core.HandlerFn, socket: std.Io.net.Socket, io: std.Io) !void {
    var buf: [1500]u8 = undefined;

    while (try socket_poll.waitReady(socket.handle, socket_poll.READABLE, TEST_POLL_MS)) {
        const message = try socket.receive(io, &buf);

        served.serve(handler, message.from, message.data, common.monotonicMs());
    }

    served.sweep(handler, common.monotonicMs());
    served.flush();
}

test "zix webrtc: worker, a peer whose ufrag the config never named still carries a session" {
    // Both halves read common.monotonicMs, which only answers on Linux, so the sessions below are
    // driven there and the models this worker serves are Linux-only anyway.
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();

    var tls = try session.testContext(std.testing.allocator);
    var config = session.testConfig(io, std.testing.allocator, &tls, TEST_ANY_UFRAG_PORT);
    config.peer_ice_ufrag = "nobodybythisname";
    config.accept_any_peer_ice_ufrag = true;

    const socket = common.bindSocket(config) catch {
        std.log.info("the webrtc test port could not be bound, test skipped", .{});
        return;
    };
    defer socket.close(io);

    var served = try Worker.initSocket(config, socket);
    defer served.deinit();

    var driver = session.Driver.init(io, TEST_ANY_UFRAG_PORT, 0) catch {
        std.log.info("the webrtc test driver could not open its socket, test skipped", .{});
        return;
    };
    defer driver.deinit();

    var rounds: usize = 0;
    while (rounds < session.MAX_ROUNDS and !driver.done()) : (rounds += 1) {
        try driver.send();
        try passOnce(&served, session.echoHandler, socket, io);
        try driver.receive();
    }

    // The config names a peer this dialer is not, so the whole session rests on the ufrag compare
    // having been let go of rather than on the name matching.
    try std.testing.expectEqualStrings(session.MESSAGE, driver.echo());
    try std.testing.expectEqual(@as(usize, 1), served.peers.live);
}

test "zix webrtc: worker, a broadcast reaches the room and skips the peer that sent it" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();

    var tls = try session.testContext(std.testing.allocator);
    var config = session.testConfig(io, std.testing.allocator, &tls, TEST_BROADCAST_PORT);
    config.accept_any_peer_ice_ufrag = true;

    const socket = common.bindSocket(config) catch {
        std.log.info("the webrtc test port could not be bound, test skipped", .{});
        return;
    };
    defer socket.close(io);

    var served = try Worker.initSocket(config, socket);
    defer served.deinit();

    var room: [3]session.Driver = undefined;
    var joined: usize = 0;
    defer for (room[0..joined]) |*member| member.deinit();

    while (joined < room.len) : (joined += 1) {
        room[joined] = session.Driver.init(io, TEST_BROADCAST_PORT, 0) catch {
            std.log.info("the webrtc test driver could not open its socket, test skipped", .{});
            return;
        };
        room[joined].speak = false;
    }

    // Everybody joins first. A message sent before the last channel opened would reach a room that
    // is not all there yet, and this is about what a full room does.
    var rounds: usize = 0;
    while (rounds < session.MAX_ROUNDS and !everyoneOpened(&room)) : (rounds += 1) {
        for (&room) |*member| try member.send();

        try passOnce(&served, broadcastHandler, socket, io);

        for (&room) |*member| try member.receive();
    }

    try std.testing.expect(everyoneOpened(&room));
    try std.testing.expectEqual(@as(usize, 3), served.peers.live);

    broadcast_reach = 0;
    try room[0].say(common.monotonicMs());

    while (rounds < session.MAX_ROUNDS and !(room[1].done() and room[2].done())) : (rounds += 1) {
        for (&room) |*member| try member.send();

        try passOnce(&served, broadcastHandler, socket, io);

        for (&room) |*member| try member.receive();
    }

    try std.testing.expectEqual(@as(usize, 2), broadcast_reach);
    try std.testing.expectEqualStrings(session.MESSAGE, room[1].echo());
    try std.testing.expectEqualStrings(session.MESSAGE, room[2].echo());

    // The one who spoke is the one the fan-out skips, so nothing came back to it.
    try std.testing.expectEqual(@as(usize, 0), room[0].echo().len);
}

/// Whether every driver in a room has its channel, for the wait above.
fn everyoneOpened(room: []const session.Driver) bool {
    for (room) |*member| {
        if (!member.opened()) return false;
    }

    return true;
}

const dtls_exporter = @import("../../../tls/dtls_exporter.zig");
const feedback = @import("../media/feedback.zig");
const peer_media = @import("../media/peer_media.zig");
const rtcp = @import("../media/rtcp.zig");
const rtp = @import("../media/rtp.zig");
const srtcp = @import("../media/srtcp.zig");
const stream_set = @import("../media/stream_set.zig");

const TEST_PROFILE: dtls_exporter.SrtpProfile = .SRTP_AES128_CM_HMAC_SHA1_80;

/// One peer's SRTP keys, different per member so a packet really does have to be re-protected.
fn testKeys(seed: u8) dtls_exporter.SrtpKeys {
    return .{
        .client_write_key = @splat(seed),
        .server_write_key = @splat(seed +% 1),
        .client_write_salt = @splat(seed +% 2),
        .server_write_salt = @splat(seed +% 3),
    };
}

/// The browser half of one member: it writes with the client key and reads with the server key.
const TestMember = struct {
    address: IpAddress,
    keys: dtls_exporter.SrtpKeys,
    sending: stream_set.StreamSet,
    receiving: stream_set.StreamSet,
    control_sending: srtcp.Session,
    control_receiving: srtcp.Session,

    fn init(port: u16, seed: u8) !TestMember {
        const keys = testKeys(seed);

        return .{
            .address = testAddress(port),
            .keys = keys,
            .sending = try stream_set.StreamSet.init(TEST_PROFILE, keys.client_write_key, keys.client_write_salt),
            .receiving = try stream_set.StreamSet.init(TEST_PROFILE, keys.server_write_key, keys.server_write_salt),
            .control_sending = try srtcp.Session.init(TEST_PROFILE, keys.client_write_key, keys.client_write_salt),
            .control_receiving = try srtcp.Session.init(TEST_PROFILE, keys.server_write_key, keys.server_write_salt),
        };
    }

    /// Put this member in the worker's table, already keyed, as a finished handshake would.
    fn join(self: *TestMember, worker: *Worker) !void {
        const peer = (try worker.peers.acquire(self.address, worker.options, common.drawSecrets(), 0)).?;

        peer.media = try peer_media.PeerMedia.init(TEST_PROFILE, self.keys);
    }

    fn send(self: *TestMember, buffer: []u8, ssrc: u32, sequence: u16, payload: []const u8) ![]const u8 {
        const written = try rtp.write(buffer, .{
            .payload_type = 96,
            .sequence = sequence,
            .timestamp = 90 * @as(u32, sequence),
            .ssrc = ssrc,
        }, payload);

        return (try self.sending.sessionFor(ssrc)).protect(buffer, written.len);
    }

    fn receive(self: *TestMember, buffer: []u8, packet_len: usize) !rtp.Packet {
        const ssrc = (try rtp.read(buffer[0..packet_len])).header.ssrc;

        return rtp.read(try (try self.receiving.sessionFor(ssrc)).unprotect(buffer[0..packet_len]));
    }

    fn askForKeyframe(self: *TestMember, buffer: []u8, media_ssrc: u32) ![]const u8 {
        const written = try feedback.writePictureLoss(buffer, 0x9999_9999, media_ssrc);

        return self.control_sending.protect(buffer, written.len);
    }

    fn receiveControl(self: *TestMember, buffer: []u8, packet_len: usize) ![]const u8 {
        return self.control_receiving.unprotect(buffer[0..packet_len]);
    }
};

/// One queued datagram copied out of the batch, so a test can open it in place.
fn queuedAt(worker: *Worker, index: usize, out: []u8) []u8 {
    const iov = worker.tx.iovs[index];
    @memcpy(out[0..iov.len], iov.base[0..iov.len]);

    return out[0..iov.len];
}

test "zix webrtc: worker, one peer's media reaches the rest of the room and not its sender" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.carry_media = true;

    const socket = try testSocket(threaded.io());
    defer socket.close(threaded.io());

    var worker = try Worker.initSocket(config, socket);
    defer worker.deinit();

    var sender = try TestMember.init(5000, 0x11);
    var first = try TestMember.init(5001, 0x21);
    var second = try TestMember.init(5002, 0x31);

    try sender.join(&worker);
    try first.join(&worker);
    try second.join(&worker);

    var buffer: [256]u8 = undefined;
    const protected = try sender.send(&buffer, 0x1111_1111, 100, "camera bytes");

    worker.serve(noopHandler, sender.address, protected, 0);

    // Two members, two sealed copies, nothing back to the one who sent it, and one keyframe
    // request to the sender because both of them were just put on the stream.
    try std.testing.expectEqual(@as(usize, 3), worker.tx.count);

    var went_to_first: [256]u8 = undefined;
    const first_len = queuedAt(&worker, 0, &went_to_first).len;

    var went_to_second: [256]u8 = undefined;
    const second_len = queuedAt(&worker, 1, &went_to_second).len;

    // Different ciphertext each way, and the same payload out of both.
    try std.testing.expect(!std.mem.eql(u8, went_to_first[0..first_len], went_to_second[0..second_len]));
    try std.testing.expectEqualStrings("camera bytes", (try first.receive(&went_to_first, first_len)).payload);
    try std.testing.expectEqualStrings("camera bytes", (try second.receive(&went_to_second, second_len)).payload);

    var went_back: [256]u8 = undefined;
    const request_len = queuedAt(&worker, 2, &went_back).len;

    var walk = try rtcp.begin(try sender.receiveControl(&went_back, request_len));

    try std.testing.expectEqual(feedback.PayloadFormat.PLI, try feedback.payloadFormat(walk.next().?));

    // And the second packet finds nobody new, so nothing more is asked for.
    worker.tx.reset();

    var again: [256]u8 = undefined;
    worker.serve(noopHandler, sender.address, try sender.send(&again, 0x1111_1111, 101, "camera bytes"), 0);

    try std.testing.expectEqual(@as(usize, 2), worker.tx.count);
}

test "zix webrtc: worker, a peer alone in the room has its media opened and forwarded nowhere" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.carry_media = true;

    const socket = try testSocket(threaded.io());
    defer socket.close(threaded.io());

    var worker = try Worker.initSocket(config, socket);
    defer worker.deinit();

    var sender = try TestMember.init(5000, 0x11);
    try sender.join(&worker);

    var buffer: [256]u8 = undefined;
    const protected = try sender.send(&buffer, 0x1111_1111, 1, "nobody listening");

    worker.serve(noopHandler, sender.address, protected, 0);

    try std.testing.expectEqual(@as(usize, 0), worker.tx.count);
    try std.testing.expectEqual(@as(usize, 1), worker.peers.live);
}

test "zix webrtc: worker, a keyframe request reaches the peer sending that stream" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.carry_media = true;

    const socket = try testSocket(threaded.io());
    defer socket.close(threaded.io());

    var worker = try Worker.initSocket(config, socket);
    defer worker.deinit();

    var sender = try TestMember.init(5000, 0x11);
    var receiver = try TestMember.init(5001, 0x21);

    try sender.join(&worker);
    try receiver.join(&worker);

    // One packet first, so the sender is known to be the source of that stream and the receiver
    // has a route to name.
    var buffer: [256]u8 = undefined;
    worker.serve(noopHandler, sender.address, try sender.send(&buffer, 0x1111_1111, 1, "a frame"), 0);
    worker.tx.reset();

    var control_buf: [256]u8 = undefined;
    const asked = try receiver.askForKeyframe(&control_buf, 0x1111_1111);

    worker.serve(noopHandler, receiver.address, asked, 10);

    try std.testing.expectEqual(@as(usize, 1), worker.tx.count);

    var went_out: [256]u8 = undefined;
    const request_len = queuedAt(&worker, 0, &went_out).len;

    const compound = try sender.receiveControl(&went_out, request_len);
    var walk = try rtcp.begin(compound);
    const packet = walk.next().?;

    try std.testing.expectEqual(feedback.PayloadFormat.PLI, try feedback.payloadFormat(packet));
    try std.testing.expectEqual(@as(u32, 0x1111_1111), (try feedback.read(packet)).media_ssrc);
}

test "zix webrtc: worker, media from a peer of a server that carries none is dropped" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    const config = testConfig(threaded.io(), std.testing.allocator, &tls);

    const socket = try testSocket(threaded.io());
    defer socket.close(threaded.io());

    var worker = try Worker.initSocket(config, socket);
    defer worker.deinit();

    var sender = try TestMember.init(5000, 0x11);
    const listener = try TestMember.init(5001, 0x21);

    // Joined without keys, which is every peer of a server that answers no media.
    _ = (try worker.peers.acquire(sender.address, worker.options, common.drawSecrets(), 0)).?;
    _ = (try worker.peers.acquire(listener.address, worker.options, common.drawSecrets(), 0)).?;

    var buffer: [256]u8 = undefined;
    worker.serve(noopHandler, sender.address, try sender.send(&buffer, 0x1111_1111, 1, "unwanted"), 0);

    try std.testing.expectEqual(@as(usize, 0), worker.tx.count);
}

test "zix webrtc: worker, the sweep lets go of a peer that stopped speaking" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.peer_idle_ms = 5_000;

    const socket = try testSocket(threaded.io());
    defer socket.close(threaded.io());

    var worker = try Worker.initSocket(config, socket);
    defer worker.deinit();

    _ = (try worker.peers.acquire(testAddress(5000), worker.options, common.drawSecrets(), 0)).?;

    worker.sweep(noopHandler, 4_999);
    try std.testing.expectEqual(@as(usize, 1), worker.peers.live);

    worker.sweep(noopHandler, 5_000);
    try std.testing.expectEqual(@as(usize, 0), worker.peers.live);
}
