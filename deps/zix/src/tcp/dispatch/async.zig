//! zix tcp .ASYNC dispatch model.

const std = @import("std");
const Config = @import("../config.zig");
const TcpServerConfig = Config.TcpServerConfig;
const common = @import("common.zig");
const logSystem = common.logSystem;
const HandlerFn = common.HandlerFn;
const ConnTask = common.ConnTask;
const dispatchConn = common.dispatchConn;
const applyConnTimeout = common.applyConnTimeout;

// --------------------------------------------------------- //
// ASYNC model

pub fn runAsync(cfg: TcpServerConfig, handler: HandlerFn) !void {
    const io = cfg.io;

    const addr = try std.Io.net.IpAddress.resolve(io, cfg.ip, cfg.port);
    var net_server = try addr.listen(io, .{
        .mode = .stream,
        .protocol = .tcp,
        .reuse_address = true, // SO_REUSEADDR + SO_REUSEPORT on POSIX, applied to all models
        .kernel_backlog = cfg.kernel_backlog,
    });
    defer net_server.deinit(io);

    // Announced below the bind, not above it: the old line claimed an address the listener
    // may never have taken.
    logSystem(cfg, .INFO, "listening on {s}:{d} (async)", .{ cfg.ip, cfg.port });

    while (true) {
        const stream = net_server.accept(io) catch |err| {
            if (err != error.ConnectionAborted) {
                if (cfg.logger) |lg| lg.system(.WARN, "tcp", "accept error: {}", .{err});
                break;
            }
            continue;
        };
        applyConnTimeout(stream.socket.handle, cfg.recv_timeout_ms, cfg.send_timeout_ms);

        _ = io.async(dispatchConn, .{ConnTask{ .stream = stream, .io = io, .handler = handler, .logger = cfg.logger }});
    }
}
