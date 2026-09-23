//! zix http2 server: the public Server type and the dispatch_model switch. Each
//! dispatch model lives in its own file under dispatch/ (ADR-043).

const std = @import("std");
const builtin = @import("builtin");
const core = @import("core.zig");
const Http2ServerConfig = @import("config.zig").Http2ServerConfig;
const common = @import("dispatch/common.zig");
const async_model = @import("dispatch/async.zig");
const epoll_model = @import("dispatch/epoll.zig");
const uring_model = @import("dispatch/uring.zig");
const tls_serve = @import("tls_serve.zig");
const tls_mux = @import("tls_mux.zig");
const ignoreSigpipe = @import("../../utils/ignore_sigpipe.zig").ignoreSigpipe;
const static_cache = @import("../../utils/static_cache.zig");
const dispatch_support = @import("../../utils/dispatch_support.zig");

const is_linux = builtin.target.os.tag == .linux;

pub const Route = core.Route;

// --------------------------------------------------------- //

/// HTTP/2 h2c server: initialize with a handler built via Router(routes).dispatch.
///
/// Usage:
/// ```zig
/// const router = zix.Http2.Router(&[_]zix.Http2.Route{
///     .{ .path = "/",     .handler = homeHandler },
///     .{ .path = "/echo", .handler = echoHandler },
/// });
/// var server = zix.Http2.Server.init(router.dispatch, .{ .io = io, .ip = "127.0.0.1", .port = 8082, .dispatch_model = .ASYNC });
/// defer server.deinit();
/// try server.run();
/// ```
pub const Http2Server = struct {
    const Self = @This();

    handler: core.HandlerFn,
    config: Http2ServerConfig,

    /// Initialize the HTTP/2 server with a handler and config. Validation happens in run.
    ///
    /// Return:
    /// - Self
    pub fn init(handler: core.HandlerFn, config: Http2ServerConfig) Self {
        return .{ .handler = handler, .config = config };
    }

    /// No-op: resources released inside run via defer.
    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Dual-listener TLS accept thread for the thread model (.ASYNC): serves h2-over-TLS on
    /// config.port (already overridden to tls_port by the caller) while the cleartext model
    /// runs on the original port.
    fn serveTlsThread(handler: core.HandlerFn, config: Http2ServerConfig) void {
        tls_serve.runTls(handler, config) catch |err| {
            // The cleartext listener keeps serving on its own thread, so without this the h2 TLS
            // side is dead and the server still looks healthy.
            common.logSystem(config, .ERROR, "the h2 TLS listener on {s}:{d} stopped ({s}), cleartext is still serving", .{ config.ip, config.tls_port, @errorName(err) });
        };
    }

    /// Listen and serve.
    ///
    /// Return:
    /// - !void
    /// - error.ZixPortNotConfigured if config.port is 0
    pub fn run(self: *Self) !void {
        if (self.config.port == 0) return error.ZixPortNotConfigured;

        const cfg = self.config;
        const handler = self.handler;

        // Reject an unrunnable model before any listener or TLS thread starts, so a rejected config
        // leaves nothing behind (ADR-065).
        if (!dispatch_support.isSupported(cfg.dispatch_model)) {
            common.logSystem(cfg, .ERROR, "{s} dispatch is Linux-only, use .ASYNC on this platform.", .{dispatch_support.rejectedName(cfg.dispatch_model)});

            return error.ZixDispatchModelUnsupported;
        }

        // Static serving is opt-in: when public_dir is set, fail fast if the directory is absent
        // rather than 404-ing every file request at runtime. Mirrors zix.Http1.Server.run.
        if (cfg.public_dir.len > 0) {
            // One name used to cover missing, not-a-directory and permission-denied alike, so
            // a public_dir the process cannot enter reported as one that is not there.
            const dir = std.Io.Dir.openDir(std.Io.Dir.cwd(), cfg.io, cfg.public_dir, .{}) catch |err| return switch (err) {
                error.FileNotFound => error.ZixPublicDirNotFound,
                error.NotDir => error.ZixPublicDirNotADirectory,
                else => error.ZixPublicDirUnreadable,
            };
            dir.close(cfg.io);

            // A failed install used to look exactly like caching being off, so a box out of
            // memory served every static file through the slow path and said nothing.
            const installed = static_cache.install(cfg.public_dir_cache_max_entries, cfg.public_dir_cache_ttl_ms) catch |err| downgrade: {
                common.logSystem(cfg, .WARN, "the static cache could not be installed ({s}), every static request re-opens its file", .{@errorName(err)});

                break :downgrade .DISABLED;
            };
            if (installed == .MISMATCHED) {
                common.logSystem(cfg, .WARN, "a static cache is already installed in this process with different settings, keeping it", .{});
            }
        }

        if (cfg.tls != null) {
            // Dual listener (tls_port): cleartext on port + TLS on tls_port from ONE worker
            // fleet, instead of a second server launch.
            if (cfg.tls_port != 0) {
                if (cfg.tls_port == cfg.port) return error.ZixTlsPortConflict;

                if (is_linux and cfg.dispatch_model == .EPOLL)
                    return epoll_model.runEpoll(handler, cfg);
                if (is_linux and cfg.dispatch_model == .URING)
                    return uring_model.runUring(handler, cfg);

                // Thread model (.ASYNC): one extra accept thread terminates TLS on tls_port
                // (thread-per-connection), the cleartext model runs below unchanged.
                var tls_cfg = cfg;
                tls_cfg.port = cfg.tls_port;
                tls_cfg.tls_port = 0;

                const tls_thread = try std.Thread.spawn(.{}, serveTlsThread, .{ handler, tls_cfg });
                tls_thread.detach();
            } else {
                // Multiplexed TLS for the event-loop models (no thread-per-conn): one epoll worker per
                // core terminates TLS in place and serves the resumable mux, so high concurrency does
                // not spawn a thread per connection. ASYNC keeps the thread-per-conn terminator,
                // which also serves TLS 1.2.
                if (is_linux and (cfg.dispatch_model == .EPOLL or cfg.dispatch_model == .URING))
                    return tls_mux.runTlsMux(handler, cfg);

                return tls_serve.runTls(handler, cfg);
            }
        }

        // The guard at the top already rejected .EPOLL / .URING off Linux, the comptime gate here
        // only keeps the Linux-only loops out of analysis there.
        return switch (cfg.dispatch_model) {
            .ASYNC => async_model.runAsync(handler, cfg),
            // .EPOLL is the shared-nothing multiplexed h2 event loop (Linux-only).
            .EPOLL => if (is_linux) epoll_model.runEpoll(handler, cfg) else error.ZixDispatchModelUnsupported,
            // .URING is the native io_uring shared-nothing loop (Linux-only). It probes the ring
            // at startup and falls back to .EPOLL when io_uring is unavailable.
            .URING => if (is_linux) uring_model.runUring(handler, cfg) else error.ZixDispatchModelUnsupported,
        };
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const empty_router = core.Router(&[_]Route{});

test "zix http2: Http2Server.run, port zero returns PortNotConfigured" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = Http2Server.init(empty_router.dispatch, .{ .io = io, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC });
    defer server.deinit();

    try std.testing.expectError(error.ZixPortNotConfigured, server.run());
}

test "zix http2: Http2Server.init, valid config succeeds and deinit is safe" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = Http2Server.init(empty_router.dispatch, .{ .io = io, .ip = "127.0.0.1", .port = 8082, .dispatch_model = .ASYNC });
    server.deinit();
}
