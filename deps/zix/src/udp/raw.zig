//! zix udp raw-bytes datagram server (ADR-049).
//!
//! What:
//! - `Raw(handler)` serves variable-length datagrams up to `max_recv_buf`. The handler receives the
//!   datagram bytes, the peer address, and a `Sink` to reply through. Replies are coalesced and leave
//!   as one sendmmsg per received batch (or coalesced sendmsg per peer-run when GSO is on). This file
//!   is the thin server facade: init plus a
//!   `run()` switch over `dispatch_model`, mirroring `src/tcp/http1/server.zig`. The worker loops
//!   live in `dispatch/` and the handler / sink types in `core.zig`.
//!
//! Usage:
//! ```zig
//! fn handler(dg: []const u8, peer: *const std.Io.net.IpAddress, sink: *zix.Udp.Sink) void {
//!     sink.reply(dg); // echo back to the sender
//! }
//! const EchoServer = zix.Udp.Raw(handler);
//! var server = try EchoServer.init(config, .{}); // set config.allow_args + pass args for --ip / --port
//! try server.run();
//! ```

const std = @import("std");

const Config = @import("config.zig");
const UdpServerConfig = Config.UdpServerConfig;
const core = @import("core.zig");

const common = @import("dispatch/common.zig");
const dispatch_support = @import("../utils/dispatch_support.zig");
const async_model = @import("dispatch/async.zig");
const epoll_model = @import("dispatch/epoll.zig");
const uring_model = @import("dispatch/uring.zig");

// --------------------------------------------------------- //

/// The reply queue handed to a raw handler (re-exported from core).
pub const Sink = core.Sink;
/// A raw datagram handler (re-exported from core).
pub const HandlerFn = core.HandlerFn;

/// A raw-bytes UDP server bound to `handler`.
pub fn Raw(comptime handler: HandlerFn) type {
    return struct {
        const Self = @This();

        config: UdpServerConfig,

        /// Initialize. When `config.allow_args` is set, `--ip` / `--port` from `args` override the
        /// config, otherwise `args` is ignored. The final port must be non-zero. Pass `.{}` for `args`
        /// when not reading CLI, or `process.minimal.args` (std.process.Args) to read `--ip` / `--port`.
        pub fn init(config: UdpServerConfig, args: anytype) !Self {
            var cfg = config;
            // The parse only compiles when args is a real std.process.Args. Passing `.{}` (no CLI)
            // skips it at comptime, so the empty case does not need a process.Args value.
            if (comptime @TypeOf(args) == std.process.Args) {
                if (cfg.allow_args) cfg = Config.applyServerArgs(cfg, args);
            }

            if (cfg.port == 0) return error.ZixPortNotConfigured;

            return .{ .config = cfg };
        }

        pub fn deinit(self: *Self) void {
            _ = self;
        }

        /// Bind and serve. Blocks until an error occurs. The dispatch model selects the worker shape:
        /// `.ASYNC` runs a single worker, `.EPOLL` / `.URING` run one per CPU.
        ///
        /// Return:
        /// - !void
        /// - error.ZixDispatchModelUnsupported if dispatch_model is .EPOLL or .URING off Linux
        pub fn run(self: *const Self) !void {
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

// --------------------------------------------------------- //
// --------------------------------------------------------- //

fn noopHandler(_: []const u8, _: *const std.Io.net.IpAddress, _: *Sink) void {}

test "zix udp: Raw init, port zero returns PortNotConfigured" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const S = Raw(noopHandler);
    try std.testing.expectError(error.ZixPortNotConfigured, S.init(.{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .ip = "127.0.0.1",
        .port = 0,
        .dispatch_model = .ASYNC,
    }, .{}));
}

test "zix udp: Raw init, config preserved" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const S = Raw(noopHandler);
    var server = try S.init(.{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .ip = "127.0.0.1",
        .port = 9070,
        .dispatch_model = .EPOLL,
        .reuse_address = true,
        .recv_batch = 16,
    }, .{});
    defer server.deinit();

    try std.testing.expectEqual(@as(u16, 9070), server.config.port);
    try std.testing.expectEqual(Config.DispatchModel.EPOLL, server.config.dispatch_model);
    try std.testing.expect(server.config.reuse_address);
    try std.testing.expectEqual(@as(usize, 16), server.config.recv_batch);
}
