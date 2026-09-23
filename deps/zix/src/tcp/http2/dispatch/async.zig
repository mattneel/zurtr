//! zix http2 .ASYNC dispatch model.

const std = @import("std");
const core = @import("../core.zig");
const Http2ServerConfig = @import("../config.zig").Http2ServerConfig;
const common = @import("common.zig");
const async_cache = @import("../../../utils/async_cache.zig");
const logSystem = common.logSystem;

// --------------------------------------------------------- //
// ASYNC model

pub fn runAsync(handler: core.HandlerFn, cfg: Http2ServerConfig) !void {
    const io = cfg.io;
    const opts = common.serveOpts(cfg);

    // Each pool thread builds its own cache on first use, so they are reclaimed together when
    // the accept loop ends rather than living until process exit.
    defer _ = async_cache.reclaim();

    const addr = try std.Io.net.IpAddress.resolve(io, cfg.ip, cfg.port);
    var listener = try addr.listen(io, .{
        .reuse_address = true, // SO_REUSEADDR + SO_REUSEPORT on POSIX, applied to all models
        .kernel_backlog = cfg.kernel_backlog,
    });
    defer listener.deinit(io);

    // Announced below the bind, not above it: the old line claimed an address the listener
    // may never have taken.
    logSystem(cfg, .INFO, "listening on {s}:{d} (async)", .{ cfg.ip, cfg.port });

    while (true) {
        const stream = listener.accept(io) catch |err| {
            if (err != error.ConnectionAborted) {
                logSystem(cfg, .ERROR, "accept error: {}", .{err});
                break;
            }
            continue;
        };
        _ = io.async(common.dispatchConn, .{common.ConnTask{
            .fd = stream.socket.handle,
            .opts = opts,
            .handler = handler,
            .io = io,
        }});
    }
}
