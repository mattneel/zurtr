//! zix fix .ASYNC dispatch model.

const std = @import("std");
const core = @import("../core.zig");
const FixServerConfig = @import("../config.zig").FixServerConfig;
const FixServeOpts = core.FixServeOpts;
const common = @import("common.zig");
const logSystem = common.logSystem;
const ConnTask = common.ConnTask;
const dispatchConn = common.dispatchConn;

// --------------------------------------------------------- //
// ASYNC model

pub fn runAsync(cfg: FixServerConfig, conn_opts: FixServeOpts) !void {
    const io = cfg.io;

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
            if (err != error.ConnectionAborted) break;
            continue;
        };
        _ = io.async(dispatchConn, .{ConnTask{
            .stream = stream,
            .io = io,
            .comp_id = cfg.comp_id,
            .opts = conn_opts,
        }});
    }
}
