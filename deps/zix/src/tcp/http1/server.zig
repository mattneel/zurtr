//! zix http1 server: the public Server type and the dispatch_model switch. Each
//! dispatch model lives in its own file under dispatch/ (ADR-043).

const std = @import("std");
const Config = @import("config.zig").Http1ServerConfig;
const core = @import("core.zig");
const HandlerFn = core.HandlerFn;
const common = @import("dispatch/common.zig");
const async_model = @import("dispatch/async.zig");
const epoll_model = @import("dispatch/epoll.zig");
const uring_model = @import("dispatch/uring.zig");
const tls_serve = @import("tls_serve.zig");
const tls_mux = @import("tls_mux.zig");
const ignoreSigpipe = @import("../../utils/ignore_sigpipe.zig").ignoreSigpipe;
const static_cache = @import("../../utils/static_cache.zig");
const dispatch_support = @import("../../utils/dispatch_support.zig");

// --------------------------------------------------------- //

/// Server type specialized over a comptime handler.
///
/// Note:
/// - handler is baked into the type, so run() takes no argument.
fn Http1ServerImpl(comptime handler: HandlerFn) type {
    return struct {
        config: Config,

        const Self = @This();

        pub fn init(config: Config) Self {
            return .{ .config = config };
        }

        pub fn deinit(_: *Self) void {}

        /// Dual-listener TLS accept thread for the thread model (.ASYNC): serves https on config.port
        /// (already overridden to tls_port by the caller) while the cleartext model runs on the
        /// original port.
        fn serveTlsThread(config: Config) void {
            tls_serve.runTls(handler, config) catch |err| {
                // The cleartext listener keeps serving on its own thread, so without this the
                // https side is dead and the server still looks healthy.
                common.logSystem(config, .ERROR, "the https listener on {s}:{d} stopped ({s}), cleartext is still serving", .{ config.ip, config.tls_port, @errorName(err) });
            };
        }

        pub fn run(self: *const Self) !void {
            ignoreSigpipe();

            // A forgotten port used to reach the bind and come back as whatever std called it, so
            // the config mistake read as a network failure. Rejected here like every other engine.
            if (self.config.port == 0) return error.ZixPortNotConfigured;

            // Reject an unrunnable model before any listener or TLS thread starts, so a rejected
            // config leaves nothing behind (ADR-065).
            if (!dispatch_support.isSupported(self.config.dispatch_model)) {
                common.logSystem(self.config, .ERROR, "{s} dispatch is Linux-only, use .ASYNC on this platform.", .{dispatch_support.rejectedName(self.config.dispatch_model)});

                return error.ZixDispatchModelUnsupported;
            }

            // Static serving is opt-in: when public_dir is set, fail fast if the directory is absent
            // rather than 404-ing every file request at runtime. Mirrors zix.Http.Server.run.
            if (self.config.public_dir.len > 0) {
                // One name used to cover missing, not-a-directory and permission-denied alike, so
                // a public_dir the process cannot enter reported as one that is not there.
                const dir = std.Io.Dir.openDir(std.Io.Dir.cwd(), self.config.io, self.config.public_dir, .{}) catch |err| return switch (err) {
                    error.FileNotFound => error.ZixPublicDirNotFound,
                    error.NotDir => error.ZixPublicDirNotADirectory,
                    else => error.ZixPublicDirUnreadable,
                };
                dir.close(self.config.io);

                // A failed install used to look exactly like caching being off, so a box out of
                // memory served every static file through the slow path and said nothing.
                const installed = static_cache.install(self.config.public_dir_cache_max_entries, self.config.public_dir_cache_ttl_ms) catch |err| downgrade: {
                    common.logSystem(self.config, .WARN, "the static cache could not be installed ({s}), every static request re-opens its file", .{@errorName(err)});

                    break :downgrade .DISABLED;
                };
                if (installed == .MISMATCHED) {
                    common.logSystem(self.config, .WARN, "a static cache is already installed in this process with different settings, keeping it", .{});
                }
            }

            if (self.config.tls != null) {
                const is_linux = comptime @import("builtin").target.os.tag == .linux;

                // Dual listener (tls_port): cleartext on port + TLS on tls_port from ONE worker
                // fleet, instead of a second server launch.
                if (self.config.tls_port != 0) {
                    if (self.config.tls_port == self.config.port) return error.ZixTlsPortConflict;

                    if (is_linux and self.config.dispatch_model == .EPOLL)
                        return epoll_model.runEpoll(self.config, handler);
                    if (is_linux and self.config.dispatch_model == .URING)
                        return uring_model.runUring(self.config, handler);

                    // Thread model (.ASYNC): one extra accept thread terminates TLS on tls_port
                    // (thread-per-connection, WebSocket + SSE included), the cleartext model runs
                    // below unchanged.
                    var tls_cfg = self.config;
                    tls_cfg.port = self.config.tls_port;
                    tls_cfg.tls_port = 0;

                    const tls_thread = try std.Thread.spawn(.{}, serveTlsThread, .{tls_cfg});
                    tls_thread.detach();
                } else {
                    // .EPOLL / .URING terminate TLS in an event-driven epoll-mux worker (keep-alive,
                    // thousands of connections per worker). The thread-per-connection blocking path
                    // (tls_serve) serves .ASYNC.
                    if (is_linux and (self.config.dispatch_model == .EPOLL or self.config.dispatch_model == .URING))
                        return tls_mux.runTlsMux(handler, self.config);

                    return tls_serve.runTls(handler, self.config);
                }
            }

            // The .EPOLL / .URING arms are comptime-guarded because their loops only compile on
            // Linux. The guard above already rejected them off Linux, so the else arm never runs.
            return switch (self.config.dispatch_model) {
                .ASYNC => async_model.runAsync(self.config, handler),
                .EPOLL => if (comptime @import("builtin").target.os.tag == .linux)
                    epoll_model.runEpoll(self.config, handler)
                else
                    error.ZixDispatchModelUnsupported,
                .URING => if (comptime @import("builtin").target.os.tag == .linux)
                    uring_model.runUring(self.config, handler)
                else
                    error.ZixDispatchModelUnsupported,
            };
        }
    };
}

/// http1 server - initialize with a comptime handler and a runtime config.
///
/// Note:
/// - handler must be comptime: it is baked into the server type, so there is no
///   dynamic registration after init. Pass a Router(routes).dispatch, a bare
///   handler, or a comptime wrapper that runs steps around an inner handler.
///
/// Usage:
/// ```zig
/// const Routes = zix.Http1.Router(&[_]zix.Http1.Route{
///     .{ .path = "/", .handler = home },
/// });
///
/// var server = zix.Http1.Server.init(Routes.dispatch, .{
///     .ip = "0.0.0.0",
///     .port = 8080,
/// });
/// try server.run();
/// ```
pub const Server = struct {
    /// Param:
    /// handler - comptime HandlerFn (baked into the server type)
    /// config - Http1ServerConfig
    ///
    /// Return:
    /// - Http1ServerImpl(handler)
    pub fn init(comptime handler: HandlerFn, config: Config) Http1ServerImpl(handler) {
        return Http1ServerImpl(handler).init(config);
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

fn testNoopHandler(_: *core.Request, _: *core.Response, _: *core.Context) anyerror!void {}

test "zix http1: Server.init valid config, deinit is safe" {
    var server = Server.init(testNoopHandler, .{
        .io = undefined,
        .ip = "127.0.0.1",
        .port = 9200,
        .dispatch_model = .ASYNC,
    });
    server.deinit();
}

test "zix http1: Server.init with EPOLL dispatch model" {
    var server = Server.init(testNoopHandler, .{
        .io = undefined,
        .ip = "127.0.0.1",
        .port = 9200,
        .dispatch_model = .EPOLL,
    });
    server.deinit();
}

test "zix http1: Server.init with URING dispatch model" {
    var server = Server.init(testNoopHandler, .{
        .io = undefined,
        .ip = "127.0.0.1",
        .port = 9200,
        .dispatch_model = .URING,
    });
    server.deinit();
}
