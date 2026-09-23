//! zix WebRTC server: the public Server type and the dispatch_model switch. Each dispatch model
//! lives in its own file under dispatch/ (ADR-043).
//!
//! What:
//! - Server.init(handler, config) binds one UDP socket and answers WebRTC peers on it: ICE checks,
//!   the DTLS handshake, the SCTP association, and data channels over it. The handler is told what
//!   arrived and replies through its context.
//!
//! Note:
//! - `.ASYNC` is the portable single-worker loop, on every target zix builds for. `.EPOLL` and
//!   `.URING` are the per-core Linux models, one SO_REUSEPORT worker per core, and off Linux they
//!   are rejected before the socket is bound rather than silently downgraded (ADR-065).
//! - The per-core models count max_peers per worker, so a server with N workers holds up to
//!   N * max_peers peers.
//!
//! Usage:
//! ```zig
//! fn onEvent(event: zix.Webrtc.Event, ctx: *zix.Webrtc.Context) !void {
//!     switch (event) {
//!         .MESSAGE => |message| try ctx.send(message.channel, message.kind, message.payload),
//!         else => {},
//!     }
//! }
//!
//! var server = zix.Webrtc.Server.init(onEvent, config);
//! defer server.deinit();
//!
//! try server.run();
//! ```

const std = @import("std");
const builtin = @import("builtin");

const Config = @import("config.zig");
const WebrtcServerConfig = Config.WebrtcServerConfig;
const core = @import("core.zig");
const dispatch_support = @import("../../utils/dispatch_support.zig");
const ice_credentials = @import("ice/credentials.zig");

const common = @import("dispatch/common.zig");
const async_model = @import("dispatch/async.zig");
const epoll_model = @import("dispatch/epoll.zig");
const uring_model = @import("dispatch/uring.zig");

/// The application event handler (re-exported from core).
pub const HandlerFn = core.HandlerFn;
/// Something the application has to know about (re-exported from core).
pub const Event = core.Event;
/// One message that arrived on a data channel (re-exported from core).
pub const Message = core.Message;
/// What a handler answers through (re-exported from core).
pub const Context = core.Context;

// Internal generic implementation: use `Server.init(handler, config)` publicly.
fn WebrtcServerImpl(comptime handler: HandlerFn) type {
    return struct {
        const Self = @This();

        config: WebrtcServerConfig,

        /// Initialize the WebRTC server with the given config. Validation happens in run.
        ///
        /// Return:
        /// - Self
        pub fn init(config: WebrtcServerConfig) Self {
            return .{ .config = config };
        }

        pub fn deinit(self: *Self) void {
            _ = self;
        }

        /// Bind and serve. Blocks until an error occurs.
        ///
        /// Return:
        /// - !void
        /// - error.ZixPortNotConfigured when config.port is 0
        /// - error.ZixIceCredentialsRequired when the local ufrag or password is empty
        /// - error.ZixIceCredentialsInvalid when either is outside what RFC 8445 5.3 allows
        /// - error.ZixTlsRequired when config.tls is null (WebRTC has no cleartext mode)
        /// - error.ZixUnsupportedCertificateKey when that context's key is not ECDSA P-256
        /// - error.ZixDispatchModelUnsupported for .EPOLL or .URING off Linux
        pub fn run(self: *const Self) !void {
            if (self.config.port == 0) return error.ZixPortNotConfigured;

            if (self.config.ice_ufrag.len == 0 or self.config.ice_password.len == 0) {
                common.logSystem(self.config, .ERROR, "ice_ufrag and ice_password must both be set, a peer's checks cannot be verified without them", .{});

                return error.ZixIceCredentialsRequired;
            }

            // A password below the RFC length is a weak MAC key, and the length is the only signal
            // available that the caller has not generated one properly.
            const local: ice_credentials.Credentials = .{ .ufrag = self.config.ice_ufrag, .password = self.config.ice_password };
            local.validate() catch |err| {
                common.logSystem(self.config, .ERROR, "ice credentials rejected: {s}", .{@errorName(err)});

                return error.ZixIceCredentialsInvalid;
            };

            if (self.config.tls == null) {
                common.logSystem(self.config, .ERROR, "a tls context is required, webrtc has no cleartext mode", .{});

                return error.ZixTlsRequired;
            }

            // The one DTLS 1.2 suite this engine implements is ECDHE-ECDSA (RFC 5289), so an
            // Ed25519 or RSA certificate has nothing to sign the ServerKeyExchange with.
            if (common.ecdsaKey(self.config) == null) {
                common.logSystem(self.config, .ERROR, "the certificate key must be ecdsa p-256, this engine has no other suite", .{});

                return error.ZixUnsupportedCertificateKey;
            }

            // Reject an unrunnable model before binding, so a rejected config leaves nothing
            // behind (ADR-065).
            if (!dispatch_support.isSupported(self.config.dispatch_model)) {
                common.logSystem(self.config, .ERROR, "{s} dispatch is Linux-only, use .ASYNC on this platform.", .{dispatch_support.rejectedName(self.config.dispatch_model)});

                return error.ZixDispatchModelUnsupported;
            }

            return switch (self.config.dispatch_model) {
                .ASYNC => async_model.runAsync(handler, self.config),
                .EPOLL => epoll_model.runEpoll(handler, self.config),
                .URING => uring_model.runUring(handler, self.config),
            };
        }
    };
}

// --------------------------------------------------------------- //

/// webrtc server - initialize with a comptime handler and a runtime config.
///
/// Note:
/// - handler must be comptime: it is baked into the server type, so there is no dynamic
///   registration after init.
/// - WebRTC has no cleartext mode: run() requires a TLS context, and its certificate key has to be
///   ECDSA P-256.
///
/// Usage:
/// ```zig
/// var server = zix.Webrtc.Server.init(onEvent, .{
///     .io = io,
///     .allocator = allocator,
///     .ip = "0.0.0.0",
///     .port = 9083,
///     .dispatch_model = .ASYNC,
///     .ice_ufrag = "zixufrag",
///     .ice_password = "zixpasswordxxxxxxxxxxx",
///     .peer_ice_ufrag = "peerufrag",
///     .tls = &tls,
/// });
/// defer server.deinit();
///
/// try server.run();
/// ```
pub const Server = struct {
    /// Param:
    /// handler - comptime HandlerFn (baked into the server type)
    /// config - WebrtcServerConfig
    ///
    /// Return:
    /// - WebrtcServerImpl(handler)
    pub fn init(comptime handler: HandlerFn, config: WebrtcServerConfig) WebrtcServerImpl(handler) {
        return WebrtcServerImpl(handler).init(config);
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const Tls = @import("../../tls/Tls.zig");
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Ed25519 = std.crypto.sign.Ed25519;

/// Mutable because Tls.Context owns its certificate bytes, so the field is not const.
var test_certificate_der = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };
const TEST_UFRAG = "zixL";
const TEST_PASSWORD = "zixlocalpasswordaaaaaa";

fn noopHandler(_: Event, _: *Context) !void {}

fn testSigningKey() !EcdsaP256.KeyPair {
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");

    return EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(secret));
}

/// A context carrying just the two fields this engine reads, so a test needs no certificate file.
fn testContext(allocator: std.mem.Allocator, key: Tls.SigningKey) Tls.Context {
    return .{
        .allocator = allocator,
        .cert_der = &test_certificate_der,
        .signing_key = key,
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
const Logger = @import("../../logger/logger.zig").Logger;

var quiet_logger = Logger{ .config = .{}, .allocator = std.testing.allocator };

fn testConfig(io: std.Io, allocator: std.mem.Allocator, tls: *Tls.Context) WebrtcServerConfig {
    return .{
        .io = io,
        .allocator = allocator,
        .ip = "127.0.0.1",
        .port = 9083,
        .dispatch_model = .ASYNC,
        .ice_ufrag = TEST_UFRAG,
        .ice_password = TEST_PASSWORD,
        .peer_ice_ufrag = "peer",
        .tls = tls,
        .logger = &quiet_logger,
    };
}

test "zix webrtc: server run rejects port zero" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = testContext(std.testing.allocator, .{ .ecdsa_p256 = try testSigningKey() });
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.port = 0;

    var server = Server.init(noopHandler, config);
    defer server.deinit();

    try std.testing.expectError(error.ZixPortNotConfigured, server.run());
}

test "zix webrtc: server run rejects missing ice credentials" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = testContext(std.testing.allocator, .{ .ecdsa_p256 = try testSigningKey() });

    var no_ufrag = testConfig(threaded.io(), std.testing.allocator, &tls);
    no_ufrag.ice_ufrag = "";

    var without_ufrag = Server.init(noopHandler, no_ufrag);
    defer without_ufrag.deinit();
    try std.testing.expectError(error.ZixIceCredentialsRequired, without_ufrag.run());

    var no_password = testConfig(threaded.io(), std.testing.allocator, &tls);
    no_password.ice_password = "";

    var without_password = Server.init(noopHandler, no_password);
    defer without_password.deinit();
    try std.testing.expectError(error.ZixIceCredentialsRequired, without_password.run());
}

test "zix webrtc: server run rejects a password shorter than the rfc allows" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = testContext(std.testing.allocator, .{ .ecdsa_p256 = try testSigningKey() });
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.ice_password = "tooshort";

    var server = Server.init(noopHandler, config);
    defer server.deinit();

    try std.testing.expectError(error.ZixIceCredentialsInvalid, server.run());
}

test "zix webrtc: server run rejects a missing tls context" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = testContext(std.testing.allocator, .{ .ecdsa_p256 = try testSigningKey() });
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.tls = null;

    var server = Server.init(noopHandler, config);
    defer server.deinit();

    try std.testing.expectError(error.ZixTlsRequired, server.run());
}

test "zix webrtc: server run rejects a certificate key it cannot sign with" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const seed: [Ed25519.KeyPair.seed_length]u8 = @splat(0x31);
    var tls = testContext(std.testing.allocator, .{ .ed25519 = try Ed25519.KeyPair.generateDeterministic(seed) });

    var server = Server.init(noopHandler, testConfig(threaded.io(), std.testing.allocator, &tls));
    defer server.deinit();

    try std.testing.expectError(error.ZixUnsupportedCertificateKey, server.run());
}

test "zix webrtc: server run rejects the per-core models off linux" {
    // On Linux those models bind and never return, so there is nothing a test can call. What is
    // pinned here is the other half of ADR-065: everywhere else they are refused, not downgraded.
    if (comptime builtin.target.os.tag == .linux) {
        std.log.info("the per-core models bind and never return on Linux, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = testContext(std.testing.allocator, .{ .ecdsa_p256 = try testSigningKey() });

    for ([_]Config.DispatchModel{ .EPOLL, .URING }) |model| {
        var config = testConfig(threaded.io(), std.testing.allocator, &tls);
        config.dispatch_model = model;

        var server = Server.init(noopHandler, config);
        defer server.deinit();

        try std.testing.expectError(error.ZixDispatchModelUnsupported, server.run());
    }
}

test "zix webrtc: server run checks the config before it looks at the model" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = testContext(std.testing.allocator, .{ .ecdsa_p256 = try testSigningKey() });

    // A per-core model with a broken config is refused for the config, on every platform, so a
    // rejected config never reaches a bind whatever model it asked for.
    for ([_]Config.DispatchModel{ .EPOLL, .URING }) |model| {
        var config = testConfig(threaded.io(), std.testing.allocator, &tls);
        config.dispatch_model = model;
        config.port = 0;

        var server = Server.init(noopHandler, config);
        defer server.deinit();

        try std.testing.expectError(error.ZixPortNotConfigured, server.run());
    }
}

comptime {
    _ = common;
}
