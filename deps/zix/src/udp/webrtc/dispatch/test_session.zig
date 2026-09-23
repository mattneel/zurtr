//! Test scaffolding: the dialing half of one WebRTC session over a real loopback socket.
//!
//! What:
//! - What epoll.zig and uring.zig both need to prove their loop actually carries a session: a TLS
//!   context with no certificate file, a server config, an echo handler, and a `Driver` that is the
//!   socket and the clock while zix.Webrtc.Dialer is everything else.
//! - Only tests import this. It holds no engine behaviour, so nothing in the shipped surface reaches
//!   for it.
//!
//! Note:
//! - The two models test against the same driver on purpose. A session that completes under one
//!   loop and not the other is then a difference in the loop, which is the only thing that differs.
//! - Both halves read the same monotonic clock, which is the one the Linux loops use. These tests
//!   are Linux-only for that reason, and for the models themselves.

const std = @import("std");

const Config = @import("../config.zig");
const WebrtcServerConfig = Config.WebrtcServerConfig;
const common = @import("common.zig");
const core = @import("../core.zig");
const dialer = @import("../dialer.zig");
const socket_poll = @import("../../../utils/socket_poll.zig");
const Tls = @import("../../../tls/Tls.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// What the dialer sends once its channel opens, and what it expects straight back.
pub const MESSAGE: []const u8 = "zix-webrtc-dispatch-round-trip";

/// How many passes a test gives the session before calling it failed. A round trip through ICE,
/// DTLS, SCTP, and DCEP is well inside this.
pub const MAX_ROUNDS: usize = 128;

/// Longest the dialer waits for a reply in one turn.
const POLL_MS: u32 = 25;

const MAX_DATAGRAM: usize = 1500;

/// The ICE credentials both halves are told, standing in for the SDP exchange a browser would do.
const ANSWERER_UFRAG: []const u8 = "zixL";
const ANSWERER_PASSWORD: []const u8 = "zixlocalpasswordaaaaaa";
const DIALER_UFRAG: []const u8 = "zixD";
const DIALER_PASSWORD: []const u8 = "zixdialerpasswordbbbbb";

/// Mutable because Tls.Context owns its certificate bytes, so the field is not const.
var test_certificate_der = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };

/// Echo every message straight back on the channel it arrived on.
pub fn echoHandler(event: core.Event, ctx: *core.Context) !void {
    switch (event) {
        .MESSAGE => |message| try ctx.send(message.channel, message.kind, message.payload),
        else => {},
    }
}

/// A context carrying just the two fields this engine reads, so a test needs no certificate file.
///
/// Param:
/// allocator - std.mem.Allocator
///
/// Return:
/// - Tls.Context
pub fn testContext(allocator: std.mem.Allocator) !Tls.Context {
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

/// A server config bound to the port the calling test owns.
///
/// Param:
/// io - std.Io
/// allocator - std.mem.Allocator
/// tls - *Tls.Context (must outlive the worker)
/// port - u16 (unique per test, so two models never contend)
///
/// Return:
/// - WebrtcServerConfig
/// A logger that writes nowhere: console off and no save_path, so nothing is opened and nothing is
/// printed. It gives the rejection and drop paths a destination, which keeps a test's expected
/// failure message out of the runner's logged-error count.
const Logger = @import("../../../logger/logger.zig").Logger;

var quiet_logger = Logger{ .config = .{}, .allocator = std.testing.allocator };

pub fn testConfig(io: std.Io, allocator: std.mem.Allocator, tls: *Tls.Context, port: u16) WebrtcServerConfig {
    return .{
        .io = io,
        .allocator = allocator,
        .ip = "127.0.0.1",
        .port = port,
        .dispatch_model = .EPOLL,
        .ice_ufrag = ANSWERER_UFRAG,
        .ice_password = ANSWERER_PASSWORD,
        .peer_ice_ufrag = DIALER_UFRAG,
        .tls = tls,
        .max_peers = 4,
        // Short, so a pass with nothing to read comes back quickly instead of parking a quarter of
        // a second at a time.
        .tick_interval_ms = 20,
        .logger = &quiet_logger,
    };
}

/// The dialing half: one socket, one dialer, and the message it is waiting to get back.
///
/// Usage:
/// ```zig
/// var driver = try Driver.init(io, server_port, dialer_port);
/// defer driver.deinit();
///
/// while (!driver.done()) {
///     try driver.send();
///     listener.pass(echoHandler);
///     try driver.receive();
/// }
/// ```
pub const Driver = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    server: std.Io.net.IpAddress,
    peer: dialer.Dialer,
    send_buf: [MAX_DATAGRAM]u8,
    recv_buf: [MAX_DATAGRAM]u8,
    echo_buf: [MAX_DATAGRAM]u8,
    echo_len: usize,
    sent: bool,
    /// Whether the channel is open, which is when this half has finished joining.
    open: bool,
    /// Whether to speak as soon as the channel opens. Set it false for a test where somebody else
    /// is the one speaking, and call `say` once the whole room has joined.
    speak: bool,

    /// Bind the dialing socket and start the session's clock.
    ///
    /// Param:
    /// io - std.Io
    /// server_port - u16 (where the worker under test listens)
    /// bind_port - u16 (this side's own port)
    ///
    /// Return:
    /// - Driver
    /// - whatever the bind or the dialer raised
    pub fn init(io: std.Io, server_port: u16, bind_port: u16) !Driver {
        const local = try std.Io.net.IpAddress.parse("127.0.0.1", bind_port);
        const socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
        errdefer socket.close(io);

        const server = try std.Io.net.IpAddress.parse("127.0.0.1", server_port);

        return .{
            .io = io,
            .socket = socket,
            .server = server,
            .peer = try dialer.Dialer.init(std.testing.allocator, dialerOptions(), common.monotonicMs()),
            .send_buf = undefined,
            .recv_buf = undefined,
            .echo_buf = undefined,
            .echo_len = 0,
            .sent = false,
            .open = false,
            .speak = true,
        };
    }

    pub fn deinit(self: *Driver) void {
        self.peer.deinit();
        self.socket.close(self.io);
    }

    /// Put everything the dialer has waiting on the wire.
    pub fn send(self: *Driver) !void {
        const now_ms = common.monotonicMs();

        while (try self.peer.nextOutbound(now_ms, &self.send_buf)) |packet| {
            try self.socket.send(self.io, &self.server, packet);
        }
    }

    /// Take whatever the worker sent back, and act on it until nothing is left to read.
    pub fn receive(self: *Driver) !void {
        while (try socket_poll.waitReady(self.socket.handle, socket_poll.READABLE, POLL_MS)) {
            const received = try self.socket.receive(self.io, &self.recv_buf);
            const now_ms = common.monotonicMs();

            _ = try self.peer.handle(received.data, now_ms);

            while (try self.peer.nextEvent(now_ms)) |event| switch (event) {
                .CHANNEL_OPEN => |channel| {
                    self.peer.onChannelOpen(channel);
                    self.open = true;

                    if (self.speak) try self.say(now_ms);
                },
                .MESSAGE => |incoming| {
                    self.echo_len = @min(incoming.payload.len, self.echo_buf.len);
                    @memcpy(self.echo_buf[0..self.echo_len], incoming.payload[0..self.echo_len]);
                },
                .CHANNEL_CLOSED => {},
            };

            if (self.echo_len > 0) return;
        }

        _ = try self.peer.tick(common.monotonicMs());
    }

    /// Send the round trip message, once. What `speak` does on channel open, for a driver that was
    /// told to stay quiet until the rest of the room had joined.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - void, and nothing at all when this driver has already spoken
    pub fn say(self: *Driver, now_ms: u64) !void {
        if (self.sent) return;

        try self.peer.send(.STRING, MESSAGE, now_ms);

        self.sent = true;
    }

    /// True once this half has a channel, which is when it has finished joining.
    pub fn opened(self: *const Driver) bool {
        return self.open;
    }

    /// True once the echo is in, or once the dialer gave up.
    pub fn done(self: *const Driver) bool {
        return self.echo_len > 0 or self.peer.isDead();
    }

    /// What came back, empty until it does.
    pub fn echo(self: *const Driver) []const u8 {
        return self.echo_buf[0..self.echo_len];
    }
};

/// The dialer's fixed starting values. Fixed rather than drawn, so a failing run is the same run
/// every time.
fn dialerOptions() dialer.Options {
    return .{
        .local_ufrag = DIALER_UFRAG,
        .local_password = DIALER_PASSWORD,
        .peer_ufrag = ANSWERER_UFRAG,
        .peer_password = ANSWERER_PASSWORD,
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
