//! zix fix server: the public FixServer type and the dispatch_model switch. Each
//! dispatch model lives in its own file under dispatch/ (ADR-043).

const std = @import("std");
const core = @import("core.zig");
const FixServerConfig = @import("config.zig").FixServerConfig;
const FixServeOpts = core.FixServeOpts;
const common = @import("dispatch/common.zig");
const async_model = @import("dispatch/async.zig");
const epoll_model = @import("dispatch/epoll.zig");
const uring_model = @import("dispatch/uring.zig");
const ignoreSigpipe = @import("../../utils/ignore_sigpipe.zig").ignoreSigpipe;
const dispatch_support = @import("../../utils/dispatch_support.zig");

// --------------------------------------------------------- //

/// FIX 4.x session server. Dispatches connections via ASYNC, or EPOLL / URING
/// (Linux-only: run() rejects them elsewhere with error.ZixDispatchModelUnsupported).
/// Session messages (Logon, Logout, Heartbeat, TestRequest) are handled internally.
/// Application messages are dispatched to the handler.
///
/// Usage:
/// ```zig
/// const router = FixRouter(&[_]FixRoute{
///     .{ .msg_type = "D", .handler = handleOrder },
///     .{ .msg_type = "F", .handler = handleCancel },
/// });
/// var server = try FixServer.init(router.dispatch, .{ .io = io, .ip = "0.0.0.0", .port = 9500, .comp_id = "SRV" });
/// defer server.deinit();
/// try server.run();
/// ```
pub const FixServer = struct {
    const Self = @This();

    handler: ?core.HandlerFn,
    config: FixServerConfig,

    // --------------------------------------------------------- //

    /// Initialize.
    ///
    /// Param:
    /// handler - ?core.HandlerFn (built via FixRouter(&[_]FixRoute{...}).dispatch. null for
    ///   echo-only mode: reply to every non-session message as itself, backward compat)
    /// config - FixServerConfig
    ///
    /// Return:
    /// - !Self
    /// - error.ZixPortNotConfigured if config.port is 0
    pub fn init(handler: ?core.HandlerFn, config: FixServerConfig) !Self {
        if (config.port == 0) return error.ZixPortNotConfigured;

        return .{ .handler = handler, .config = config };
    }

    /// No-op, resources released inside run via defer.
    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Listen and serve FIX sessions using the server's comp_id.
    pub fn run(self: *Self) !void {
        ignoreSigpipe();

        const cfg = self.config;

        // Reject an unrunnable model before binding, so a rejected config leaves nothing behind (ADR-065).
        if (!dispatch_support.isSupported(cfg.dispatch_model)) {
            common.logSystem(cfg, .ERROR, "{s} dispatch is Linux-only, use .ASYNC on this platform.", .{dispatch_support.rejectedName(cfg.dispatch_model)});

            return error.ZixDispatchModelUnsupported;
        }

        const conn_opts = FixServeOpts{
            .logger = cfg.logger,
            .default_heartbeat_secs = cfg.default_heartbeat_secs,
            .heartbeat_timeout_ms = cfg.heartbeat_timeout_ms,
            .conn_timeout_ms = cfg.conn_timeout_ms,
            .handler_timeout_ms = cfg.handler_timeout_ms,
            .handler = self.handler,
        };

        // The comptime guards stay because those loops only compile on Linux: the check above
        // already rejected the model there, so the else arms never run.
        return switch (cfg.dispatch_model) {
            .ASYNC => async_model.runAsync(cfg, conn_opts),
            .EPOLL => if (comptime @import("builtin").target.os.tag == .linux)
                epoll_model.runEpoll(cfg, conn_opts)
            else
                error.ZixDispatchModelUnsupported,
            // Native io_uring ring path (ADR-037 Phase 4 extension).
            .URING => if (comptime @import("builtin").target.os.tag == .linux)
                uring_model.runUring(cfg, conn_opts)
            else
                error.ZixDispatchModelUnsupported,
        };
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix fix: FixServer.init, port zero returns PortNotConfigured" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(
        error.ZixPortNotConfigured,
        FixServer.init(null, .{ .io = io, .ip = "127.0.0.1", .port = 0, .comp_id = "SERVER", .dispatch_model = .ASYNC }),
    );
}

test "zix fix: FixServer.init, valid config succeeds and deinit is safe" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try FixServer.init(null, .{ .io = io, .ip = "127.0.0.1", .port = 9500, .comp_id = "SERVER", .dispatch_model = .ASYNC });
    server.deinit();
}

test "zix fix: FixServer.init with EPOLL dispatch model succeeds" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try FixServer.init(null, .{ .io = io, .ip = "127.0.0.1", .port = 9500, .comp_id = "SERVER", .dispatch_model = .EPOLL });
    server.deinit();
}

test "zix fix: FixServer EPOLL uses the workers field for worker count" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const server = try FixServer.init(null, .{
        .io = io,
        .ip = "127.0.0.1",
        .port = 9500,
        .comp_id = "SERVER",
        .dispatch_model = .EPOLL,
        .workers = 4,
    });
    try std.testing.expectEqual(@as(usize, 4), server.config.workers);
}
