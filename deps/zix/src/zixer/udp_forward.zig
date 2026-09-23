//! zixer udp forward edge: the per-flow datagram relay a udp site serves

const std = @import("std");
const zix = @import("zix");

const site_cfg = @import("site_cfg.zig");
const udp_flow_table = @import("udp_flow_table.zig");

const socket_poll = zix.utils.socket_poll;

/// Largest udp payload, so a forwarded datagram is never truncated.
const MAX_DATAGRAM: usize = 65535;

/// Longest a down pump parks in its readiness wait before it rechecks the
/// stop and closing flags. Teardown and eviction land within one slice.
const POLL_MS: u32 = 50;

/// Consecutive receive failures before the up pump gives up.
const MAX_RECEIVE_FAILURES: usize = 100;

/// Everything one serving udp site owns. Heap-allocated so the up pump
/// thread and its down pump tasks keep stable pointers while the daemon
/// registry moves.
///
/// Note:
/// - Pick is per flow: a client addr:port sticks to one upstream for the
///   flow's life, new flows walk the upstreams round-robin. Udp has no
///   connect step and so no failure signal, every upstream always counts
///   as ready.
/// - Each flow forwards through its own ephemeral socket, so the upstream
///   sees one distinct peer per client (what ICE and DTLS state needs).
/// - A full table marks the stalest flow closing and drops the triggering
///   datagram, the protocols a udp site fronts all retransmit. Flows have
///   no idle expiry beyond that pressure, nothing in zixer carries a
///   timeout yet.
/// - The state lock guards the table and the pick cursor only, sections
///   under it never touch a socket. Datagram sends need no lock: one send
///   is one syscall, atomic per datagram.
pub const ForwardState = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    socket: std.Io.net.Socket,
    upstreams: []std.Io.net.IpAddress,
    wake_ip: []const u8,
    port: u16,
    cursor: u32 = 0,
    table: udp_flow_table.Table = .{},
    /// Slot sockets, parallel to the table. The up pump writes a slot's
    /// socket before its pump spawns and closes it after its pump reports
    /// done, so the pump only ever reads a stable value.
    flow_sockets: [udp_flow_table.FLOW_CAP]std.Io.net.Socket = undefined,
    state_lock: std.atomic.Value(bool) = .init(false),
    stop: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    /// Live down pump tasks. A concurrent group member releases its
    /// resources when the task returns, shutdown cancels the stragglers.
    pumps: std.Io.Group = .init,

    /// Build the forward state and start its up pump thread.
    ///
    /// Note:
    /// - socket is moved in here: the caller hands the bound datagram
    ///   socket over and must not touch it again, shutdown() closes it.
    ///   On error the caller still owns it.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (state and upstream addrs, long-lived)
    /// io - std.Io (must outlive the state)
    /// socket - std.Io.net.Socket (bound datagram socket for this site)
    /// cfg - *const site_cfg.SiteCfg (validated site config with upstreams)
    /// port - u16
    ///
    /// Return:
    /// - *ForwardState with the up pump running
    /// - error.ZixerBadUpstreamAddress when an upstream host is not a literal ip
    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        socket: std.Io.net.Socket,
        cfg: *const site_cfg.SiteCfg,
        port: u16,
    ) !*ForwardState {
        const state = try allocator.create(ForwardState);
        errdefer allocator.destroy(state);

        const upstreams = try allocator.alloc(std.Io.net.IpAddress, cfg.upstreams.len);
        errdefer allocator.free(upstreams);
        for (cfg.upstreams, 0..) |upstream, index| {
            upstreams[index] = std.Io.net.IpAddress.parse(upstream.host, upstream.port) catch return error.ZixerBadUpstreamAddress;
        }

        const wake_ip = try allocator.dupe(u8, cfg.ip);
        errdefer allocator.free(wake_ip);

        state.* = .{
            .allocator = allocator,
            .io = io,
            .socket = socket,
            .upstreams = upstreams,
            .wake_ip = wake_ip,
            .port = port,
        };

        state.thread = try std.Thread.spawn(.{}, upPumpLoop, .{state});

        return state;
    }

    /// Stop both pump directions, close every socket, release everything.
    ///
    /// Note:
    /// - The wake datagram is what unblocks the up pump's receive portably,
    ///   closing a socket another thread is blocked on is not reliable
    ///   cross-platform. Down pumps exit on their next poll slice.
    pub fn shutdown(state: *ForwardState) void {
        const io = state.io;

        state.stop.store(true, .release);
        wakeDatagram(io, state.wake_ip, state.port);
        if (state.thread) |thread| thread.join();
        state.pumps.cancel(io);

        // Every pump has returned, so the remaining flow sockets are idle.
        for (&state.table.flows, 0..) |*flow, index| {
            if (flow.active) state.flow_sockets[index].close(io);
        }

        state.socket.close(io);
        state.allocator.free(state.upstreams);
        state.allocator.free(state.wake_ip);

        const allocator = state.allocator;
        allocator.destroy(state);
    }
};

fn upPumpLoop(state: *ForwardState) void {
    const io = state.io;

    var buf: [MAX_DATAGRAM]u8 = undefined;
    var failures: usize = 0;
    while (!state.stop.load(.acquire)) {
        const message = state.socket.receive(io, &buf) catch {
            if (state.stop.load(.acquire)) return;

            failures += 1;
            if (failures >= MAX_RECEIVE_FAILURES) return;
            continue;
        };
        failures = 0;

        if (state.stop.load(.acquire)) return;
        if (message.flags.trunc) continue;

        forwardClientDatagram(state, message.from, message.data);
    }
}

/// Route one client datagram: an owned flow forwards on its slot's socket,
/// anything else claims a slot first.
fn forwardClientDatagram(state: *ForwardState, client: std.Io.net.IpAddress, data: []const u8) void {
    const io = state.io;

    lockState(state);
    if (state.table.findByClient(&client)) |index| {
        if (!state.table.flows[index].done) {
            state.table.touch(index);
            const upstream = state.upstreams[state.table.flows[index].upstream_index];
            const flow_socket = state.flow_sockets[index];
            unlockState(state);

            flow_socket.send(io, &upstream, data) catch {};
            return;
        }

        // The slot's pump died, reclaim it and treat the client as new.
        const dead_socket = state.flow_sockets[index];
        state.table.release(index);
        unlockState(state);
        dead_socket.close(io);
    } else {
        unlockState(state);
    }

    claimFlow(state, client, data);
}

/// Give a new client a slot: reap finished pumps, claim a free slot with
/// the next round-robin upstream, open its socket, start its down pump, and
/// forward the datagram. A full table marks the stalest flow closing and
/// drops this datagram instead.
fn claimFlow(state: *ForwardState, client: std.Io.net.IpAddress, data: []const u8) void {
    const io = state.io;

    reapDoneFlows(state);

    lockState(state);
    const index = state.table.findFree() orelse {
        if (state.table.lruVictim()) |victim| state.table.flows[victim].closing = true;
        unlockState(state);

        return;
    };
    const upstream_index = state.cursor;
    state.cursor = (state.cursor + 1) % @as(u32, @intCast(state.upstreams.len));
    state.table.claim(index, client, upstream_index);
    unlockState(state);

    const upstream = state.upstreams[upstream_index];
    const flow_socket = openFlowSocket(io, &upstream) catch {
        releaseSlot(state, index);
        return;
    };
    state.flow_sockets[index] = flow_socket;

    state.pumps.concurrent(io, downPumpTask, .{ state, index }) catch {
        flow_socket.close(io);
        releaseSlot(state, index);
        return;
    };

    flow_socket.send(io, &upstream, data) catch {};
}

/// Close and release every slot whose down pump has finished. The closes
/// happen outside the lock, and the up pump is the only closer.
fn reapDoneFlows(state: *ForwardState) void {
    var reaped: [udp_flow_table.FLOW_CAP]std.Io.net.Socket = undefined;
    var count: usize = 0;

    lockState(state);
    for (&state.table.flows, 0..) |*flow, index| {
        if (!flow.active or !flow.done) continue;

        reaped[count] = state.flow_sockets[index];
        count += 1;
        state.table.release(@intCast(index));
    }
    unlockState(state);

    for (reaped[0..count]) |socket| socket.close(state.io);
}

fn releaseSlot(state: *ForwardState, index: u32) void {
    lockState(state);
    state.table.release(index);
    unlockState(state);
}

/// Bind the upstream-facing socket for one flow. Its own ephemeral port is
/// the flow's identity toward the upstream, so every client appears as its
/// own peer there.
fn openFlowSocket(io: std.Io, upstream: *const std.Io.net.IpAddress) !std.Io.net.Socket {
    const local_ip = if (upstream.* == .ip6) "::" else "0.0.0.0";
    const local = try std.Io.net.IpAddress.parse(local_ip, 0);

    return local.bind(io, .{ .mode = .dgram, .protocol = .udp });
}

fn downPumpTask(state: *ForwardState, index: u32) void {
    downPump(state, index);

    lockState(state);
    state.table.flows[index].done = true;
    unlockState(state);
}

/// Relay upstream datagrams back to the flow's client until the site
/// stops, the slot is evicted, or the socket dies. Only the picked upstream
/// may speak down a flow, anything else at the ephemeral port drops.
fn downPump(state: *ForwardState, index: u32) void {
    const io = state.io;

    lockState(state);
    const client = state.table.flows[index].client;
    const upstream = state.upstreams[state.table.flows[index].upstream_index];
    unlockState(state);
    const flow_socket = state.flow_sockets[index];

    var buf: [MAX_DATAGRAM]u8 = undefined;
    while (!state.stop.load(.acquire)) {
        lockState(state);
        const closing = state.table.flows[index].closing;
        unlockState(state);

        if (closing) return;

        const ready = socket_poll.waitReady(flow_socket.handle, socket_poll.READABLE, POLL_MS) catch return;
        if (!ready) continue;

        const message = flow_socket.receive(io, &buf) catch return;

        if (message.flags.trunc) continue;
        if (!message.from.eql(&upstream)) continue;

        lockState(state);
        state.table.touch(index);
        unlockState(state);

        state.socket.send(io, &client, message.data) catch {};
    }
}

/// Send one datagram at the site's own port so a blocked receive returns.
/// A wildcard bind ip is reached through loopback.
fn wakeDatagram(io: std.Io, ip: []const u8, port: u16) void {
    const target = if (std.mem.eql(u8, ip, "0.0.0.0"))
        "127.0.0.1"
    else if (std.mem.eql(u8, ip, "::"))
        "::1"
    else
        ip;

    const addr = std.Io.net.IpAddress.parse(target, port) catch return;
    const local = std.Io.net.IpAddress.parse(if (addr == .ip6) "::" else "0.0.0.0", 0) catch return;
    const socket = local.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch return;
    defer socket.close(io);

    socket.send(io, &addr, "z") catch {};
}

fn lockState(state: *ForwardState) void {
    while (state.state_lock.swap(true, .acquire)) std.atomic.spinLoopHint();
}

fn unlockState(state: *ForwardState) void {
    state.state_lock.store(false, .release);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

const ECHO_BUF_SIZE: usize = 16 * 1024;

/// How long a test client waits for one reply.
const REPLY_WAIT_MS: u32 = 2000;

/// A udp upstream that answers every datagram with its tag byte in front,
/// and records how many distinct peers spoke to it (distinct flows).
const UdpEcho = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    tag: u8,
    stop: std.atomic.Value(bool) = .init(false),
    peers_seen: std.atomic.Value(u32) = .init(0),
    peer_ports: [8]u16 = @splat(0),
    thread: ?std.Thread = null,

    fn start(io: std.Io, port: u16, tag: u8) !*UdpEcho {
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
        const socket = try addr.bind(io, .{ .mode = .dgram, .protocol = .udp });

        const echo = try testing.allocator.create(UdpEcho);
        echo.* = .{ .io = io, .socket = socket, .tag = tag };
        echo.thread = try std.Thread.spawn(.{}, loop, .{echo});

        return echo;
    }

    fn loop(echo: *UdpEcho) void {
        var buf: [ECHO_BUF_SIZE]u8 = undefined;
        var reply: [ECHO_BUF_SIZE + 1]u8 = undefined;
        while (!echo.stop.load(.acquire)) {
            const ready = socket_poll.waitReady(echo.socket.handle, socket_poll.READABLE, 25) catch return;
            if (!ready) continue;

            const message = echo.socket.receive(echo.io, &buf) catch return;

            recordPeer(echo, addressPort(message.from));

            reply[0] = echo.tag;
            @memcpy(reply[1 .. 1 + message.data.len], message.data);

            echo.socket.send(echo.io, &message.from, reply[0 .. 1 + message.data.len]) catch {};
        }
    }

    /// Only the echo thread writes here, tests read after shutdown.
    fn recordPeer(echo: *UdpEcho, port: u16) void {
        const count = echo.peers_seen.load(.acquire);
        for (echo.peer_ports[0..count]) |known| {
            if (known == port) return;
        }

        if (count < echo.peer_ports.len) echo.peer_ports[count] = port;
        echo.peers_seen.store(count + 1, .release);
    }

    fn shutdown(echo: *UdpEcho) void {
        echo.stop.store(true, .release);
        if (echo.thread) |thread| thread.join();

        echo.socket.close(echo.io);
        testing.allocator.destroy(echo);
    }
};

fn addressPort(address: std.Io.net.IpAddress) u16 {
    return switch (address) {
        .ip4 => |ip4| ip4.port,
        .ip6 => |ip6| ip6.port,
    };
}

/// Bind the site's edge socket and build the forward over it.
fn startForward(io: std.Io, port: u16, upstreams: []const site_cfg.Upstream) !*ForwardState {
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
    const socket = try addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    errdefer socket.close(io);

    const cfg = site_cfg.SiteCfg{ .engine = .UDP, .ip = "127.0.0.1", .port = port, .upstreams = upstreams };

    return ForwardState.create(testing.allocator, io, socket, &cfg, port);
}

fn bindClient(io: std.Io) !std.Io.net.Socket {
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);

    return addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
}

/// One request datagram, one reply datagram.
fn sendAndReceive(io: std.Io, socket: std.Io.net.Socket, edge: *const std.Io.net.IpAddress, payload: []const u8, out: []u8) ![]const u8 {
    try socket.send(io, edge, payload);

    const ready = try socket_poll.waitReady(socket.handle, socket_poll.READABLE, REPLY_WAIT_MS);
    if (!ready) return error.ZixerNoReply;

    const message = try socket.receive(io, out);

    return message.data;
}

test "zix zixer: udp forward, one flow round trips through its own upstream socket" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const echo = try UdpEcho.start(io, 18834, 'A');
    defer echo.shutdown();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18834 }};
    const forward = try startForward(io, 18833, &upstreams);
    defer forward.shutdown();

    const client = try bindClient(io);
    defer client.close(io);
    const edge = try std.Io.net.IpAddress.parse("127.0.0.1", 18833);

    var out: [128]u8 = undefined;
    const reply = try sendAndReceive(io, client, &edge, "ping", &out);
    try testing.expectEqualStrings("Aping", reply);

    // One client is one flow, so the upstream saw exactly one peer.
    try testing.expectEqual(@as(u32, 1), echo.peers_seen.load(.acquire));
}

test "zix zixer: udp forward, two clients get two flows and their own replies" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const echo = try UdpEcho.start(io, 18829, 'B');
    defer echo.shutdown();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18829 }};
    const forward = try startForward(io, 18828, &upstreams);
    defer forward.shutdown();

    const first = try bindClient(io);
    defer first.close(io);
    const second = try bindClient(io);
    defer second.close(io);
    const edge = try std.Io.net.IpAddress.parse("127.0.0.1", 18828);

    var first_out: [128]u8 = undefined;
    var second_out: [128]u8 = undefined;
    const first_reply = try sendAndReceive(io, first, &edge, "from-first", &first_out);
    const second_reply = try sendAndReceive(io, second, &edge, "from-second", &second_out);

    // Each reply lands at the client that asked, and the upstream saw one
    // distinct peer per client even though both used the same edge port.
    try testing.expectEqualStrings("Bfrom-first", first_reply);
    try testing.expectEqualStrings("Bfrom-second", second_reply);
    try testing.expectEqual(@as(u32, 2), echo.peers_seen.load(.acquire));
}

test "zix zixer: udp forward, new flows round-robin and a flow stays put" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const first_echo = try UdpEcho.start(io, 18836, '1');
    defer first_echo.shutdown();
    const second_echo = try UdpEcho.start(io, 18837, '2');
    defer second_echo.shutdown();

    const upstreams = [_]site_cfg.Upstream{
        .{ .host = "127.0.0.1", .port = 18836 },
        .{ .host = "127.0.0.1", .port = 18837 },
    };
    const forward = try startForward(io, 18835, &upstreams);
    defer forward.shutdown();

    const first = try bindClient(io);
    defer first.close(io);
    const second = try bindClient(io);
    defer second.close(io);
    const edge = try std.Io.net.IpAddress.parse("127.0.0.1", 18835);

    var out: [128]u8 = undefined;
    const first_reply = try sendAndReceive(io, first, &edge, "x", &out);
    const first_tag = first_reply[0];

    var second_out: [128]u8 = undefined;
    const second_reply = try sendAndReceive(io, second, &edge, "y", &second_out);

    // The second flow picked the other upstream.
    try testing.expect(first_tag != second_reply[0]);

    // The first flow sticks to its pick, and its upstream still counts one
    // peer only.
    for (0..3) |_| {
        var again_out: [128]u8 = undefined;
        const again = try sendAndReceive(io, first, &edge, "x", &again_out);
        try testing.expectEqual(first_tag, again[0]);
    }
    try testing.expectEqual(@as(u32, 1), first_echo.peers_seen.load(.acquire));
    try testing.expectEqual(@as(u32, 1), second_echo.peers_seen.load(.acquire));
}

test "zix zixer: udp forward, a large datagram crosses intact both ways" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const echo = try UdpEcho.start(io, 18838, 'L');
    defer echo.shutdown();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18838 }};
    const forward = try startForward(io, 18827, &upstreams);
    defer forward.shutdown();

    const client = try bindClient(io);
    defer client.close(io);
    const edge = try std.Io.net.IpAddress.parse("127.0.0.1", 18827);

    var payload: [8192]u8 = undefined;
    for (&payload, 0..) |*byte, position| byte.* = @truncate(position *% 31);

    var out: [payload.len + 1]u8 = undefined;
    const reply = try sendAndReceive(io, client, &edge, &payload, &out);

    try testing.expectEqual(payload.len + 1, reply.len);
    try testing.expectEqual(@as(u8, 'L'), reply[0]);
    try testing.expectEqualSlices(u8, &payload, reply[1..]);
}

test "zix zixer: udp forward, shutdown frees the edge port" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18826 }};

    const forward = try startForward(io, 18824, &upstreams);
    forward.shutdown();

    // Udp binds strict (no reuse flags), so a successful rebind proves the
    // shutdown released the socket.
    const again = try startForward(io, 18824, &upstreams);
    again.shutdown();
}

test "zix zixer: udp forward, a bad upstream literal refuses to start" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "not-an-ip", .port = 9 }};

    try testing.expectError(error.ZixerBadUpstreamAddress, startForward(io, 18839, &upstreams));
}

// --------------------------------------------------------- //
// The wire check: a full WebRTC session with the zix engine's answering
// peer as the upstream. ICE checks, the DTLS handshake, the SCTP
// association, and a data channel echo all cross the per-flow forward.

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const WIRE_MESSAGE: []const u8 = "zixer-udp-forward-wire-check";
const WIRE_ANSWERER_UFRAG: []const u8 = "zixA";
const WIRE_ANSWERER_PASSWORD: []const u8 = "zixanswerpasswordaaaaaa";
const WIRE_DIALER_UFRAG: []const u8 = "zixD";
const WIRE_DIALER_PASSWORD: []const u8 = "zixdialerpasswordbbbbbb";

const WIRE_CERT_DER = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };

/// Passes the dialer gets before the session counts as failed. Each pass
/// parks at most 25ms, a loopback session finishes well inside this.
const WIRE_MAX_ROUNDS: usize = 400;

/// Monotonic milliseconds, the same raw clock the engine's own loops read.
/// Callers subtract their own start value, so a session clock begins near
/// zero. Non-linux answers 0, the wire check is linux-gated anyway.
fn wireNowMs() u64 {
    if (comptime @import("builtin").os.tag != .linux) return 0;

    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);

    return @as(u64, @intCast(ts.sec)) * std.time.ms_per_s + @as(u64, @intCast(@divTrunc(ts.nsec, std.time.ns_per_ms)));
}

fn wireSigningKey() !EcdsaP256.KeyPair {
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");

    return EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(secret));
}

fn wireAnswererOptions() !zix.Webrtc.ConnectionOptions {
    return .{
        .ice_ufrag = WIRE_ANSWERER_UFRAG,
        .ice_password = WIRE_ANSWERER_PASSWORD,
        .peer_ice_ufrag = WIRE_DIALER_UFRAG,
        .certificate_der = &WIRE_CERT_DER,
        .signing_key = try wireSigningKey(),
    };
}

fn wireAnswererSecrets() zix.Webrtc.Secrets {
    return .{
        .dtls_cookie = @splat(0x5A),
        .sctp_cookie = @splat(0x6B),
        .server_random = @splat(0x33),
        .server_eph_secret = @splat(0x22),
        .sctp_tag = 0x11223344,
        .sctp_initial_tsn = 1000,
    };
}

fn wireDialerOptions() zix.Webrtc.DialerOptions {
    return .{
        .local_ufrag = WIRE_DIALER_UFRAG,
        .local_password = WIRE_DIALER_PASSWORD,
        .peer_ufrag = WIRE_ANSWERER_UFRAG,
        .peer_password = WIRE_ANSWERER_PASSWORD,
        .transaction_id = @splat(0x77),
        .client_random = @splat(0x11),
        .client_eph_secret = @splat(0x44),
        .sctp_cookie = @splat(0x9C),
        .sctp_tag = 0x55667788,
        .sctp_initial_tsn = 5000,
        .check_interval_ms = 50,
        .setup_timeout_ms = 20_000,
    };
}

/// The upstream: the zix WebRTC answering peer on its own socket, echoing
/// every data channel message. One peer is enough, the forward gives it one
/// flow socket per client.
const RtcAnswerer = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    stop: std.atomic.Value(bool) = .init(false),
    established: std.atomic.Value(bool) = .init(false),
    /// The one peer port this answerer spoke to, zero until it did.
    peer_port: std.atomic.Value(u32) = .init(0),
    thread: ?std.Thread = null,

    fn start(io: std.Io, port: u16) !*RtcAnswerer {
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
        const socket = try addr.bind(io, .{ .mode = .dgram, .protocol = .udp });

        const answerer = try testing.allocator.create(RtcAnswerer);
        answerer.* = .{ .io = io, .socket = socket };
        answerer.thread = try std.Thread.spawn(.{}, loop, .{answerer});

        return answerer;
    }

    fn loop(answerer: *RtcAnswerer) void {
        var conn: ?zix.Webrtc.Connection = null;
        defer if (conn) |*inner| inner.deinit();

        var peer: std.Io.net.IpAddress = undefined;
        const base_ms = wireNowMs();
        var buf: [1500]u8 = undefined;
        var out: [1500]u8 = undefined;

        while (!answerer.stop.load(.acquire)) {
            const ready = socket_poll.waitReady(answerer.socket.handle, socket_poll.READABLE, 25) catch return;
            const now_ms = wireNowMs() - base_ms;

            if (ready) {
                const message = answerer.socket.receive(answerer.io, &buf) catch return;

                if (conn == null) {
                    const options = wireAnswererOptions() catch return;
                    conn = zix.Webrtc.Connection.init(testing.allocator, message.from, options, wireAnswererSecrets(), now_ms) catch return;
                    peer = message.from;
                    answerer.peer_port.store(addressPort(message.from), .release);
                }

                _ = conn.?.handle(message.data, now_ms) catch continue;

                while (conn.?.nextEvent(now_ms) catch null) |event| switch (event) {
                    .MESSAGE => |incoming| {
                        var ctx = conn.?.context(now_ms) orelse continue;
                        ctx.send(incoming.channel, incoming.kind, incoming.payload) catch {};
                    },
                    else => {},
                };
            }

            if (conn) |*inner| {
                _ = inner.tick(now_ms);
                if (inner.isEstablished()) answerer.established.store(true, .release);

                while (inner.nextOutbound(now_ms, &out) catch null) |packet| {
                    answerer.socket.send(answerer.io, &peer, packet) catch {};
                }
            }
        }
    }

    fn shutdown(answerer: *RtcAnswerer) void {
        answerer.stop.store(true, .release);
        if (answerer.thread) |thread| thread.join();

        answerer.socket.close(answerer.io);
        testing.allocator.destroy(answerer);
    }
};

test "zix zixer: udp forward, a webrtc session with the zix engine crosses the flow" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const answerer = try RtcAnswerer.start(io, 18821);
    defer answerer.shutdown();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18821 }};
    const forward = try startForward(io, 18822, &upstreams);
    defer forward.shutdown();

    // The dialing half only ever talks to the edge port, so a completed
    // session is proof the whole exchange crossed the forward.
    var dialer = try zix.Webrtc.Dialer.init(testing.allocator, wireDialerOptions(), 0);
    defer dialer.deinit();

    const local = try std.Io.net.IpAddress.parse("127.0.0.1", 18823);
    const socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    const edge = try std.Io.net.IpAddress.parse("127.0.0.1", 18822);

    const base_ms = wireNowMs();
    var out: [1500]u8 = undefined;
    var recv_buf: [1500]u8 = undefined;
    var echo_buf: [1500]u8 = undefined;
    var echo_len: usize = 0;
    var sent = false;

    var rounds: usize = 0;
    while (echo_len == 0 and rounds < WIRE_MAX_ROUNDS) : (rounds += 1) {
        var now_ms = wireNowMs() - base_ms;

        while (try dialer.nextOutbound(now_ms, &out)) |packet| try socket.send(io, &edge, packet);

        const ready = try socket_poll.waitReady(socket.handle, socket_poll.READABLE, 25);
        now_ms = wireNowMs() - base_ms;

        if (ready) {
            const message = try socket.receive(io, &recv_buf);
            _ = try dialer.handle(message.data, now_ms);

            while (try dialer.nextEvent(now_ms)) |event| switch (event) {
                .CHANNEL_OPEN => |channel| {
                    dialer.onChannelOpen(channel);

                    if (!sent) {
                        try dialer.send(.STRING, WIRE_MESSAGE, now_ms);
                        sent = true;
                    }
                },
                .MESSAGE => |incoming| {
                    echo_len = @min(incoming.payload.len, echo_buf.len);
                    @memcpy(echo_buf[0..echo_len], incoming.payload[0..echo_len]);
                },
                .CHANNEL_CLOSED => {},
            };
        }

        _ = try dialer.tick(now_ms);
        try testing.expect(!dialer.isDead());
    }

    try testing.expectEqualStrings(WIRE_MESSAGE, echo_buf[0..echo_len]);
    try testing.expect(answerer.established.load(.acquire));

    // The engine answered zixer's flow socket, never the dialer directly.
    const seen_port = answerer.peer_port.load(.acquire);
    try testing.expect(seen_port != 0);
    try testing.expect(seen_port != 18823);
}
