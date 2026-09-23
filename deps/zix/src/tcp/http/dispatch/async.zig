//! zix http .ASYNC dispatch model: a single accept loop dispatches each
//! connection via io.async(). The shared io Threaded pool handles scheduling.

const std = @import("std");
const common = @import("common.zig");
const async_cache = @import("../../../utils/async_cache.zig");
const logSystem = common.logSystem;
const handleConnection = common.handleConnection;

// --------------------------------------------------------- //
// ASYNC model

pub fn runAsync(server: anytype, io: std.Io) !void {
    const cfg = server.config;

    // io.async needs a concrete function (no anytype param), so wrap the generic
    // handleConnection in a closure where the server pointer type is fixed.
    const Spawn = struct {
        fn handle(stream: std.Io.net.Stream, h_io: std.Io, srv: @TypeOf(server)) void {
            handleConnection(stream, h_io, srv);
        }
    };

    // Each pool thread builds its own cache on first use, so they are reclaimed together when
    // the accept loop ends rather than living until process exit.
    defer _ = async_cache.reclaim();

    const addr = std.Io.net.IpAddress.resolve(io, cfg.ip, cfg.port) catch |err| {
        logSystem(cfg, .ERROR, "resolve error: {}", .{err});
        return;
    };
    var net_server = addr.listen(io, .{
        .mode = .stream,
        .kernel_backlog = @intCast(cfg.kernel_backlog),
        .reuse_address = true, // SO_REUSEADDR + SO_REUSEPORT on POSIX, applied to all models
    }) catch |err| {
        logSystem(cfg, .ERROR, "listen error: {}", .{err});
        return;
    };
    defer net_server.deinit(io);

    // Announced below the bind, not above it: the old line claimed an address the listener
    // may never have taken.
    logSystem(cfg, .INFO, "listening on {s}:{d} (io.async)", .{ cfg.ip, cfg.port });

    while (true) {
        const stream = net_server.accept(io) catch |err| {
            if (err != error.ConnectionAborted) {
                logSystem(cfg, .ERROR, "accept error: {}", .{err});
                break;
            }
            continue;
        };
        _ = io.async(Spawn.handle, .{ stream, io, server });
    }
}
