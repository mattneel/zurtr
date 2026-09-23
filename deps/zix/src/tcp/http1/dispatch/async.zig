//! zix http1 .ASYNC dispatch model.

const std = @import("std");
const async_cache = @import("../../../utils/async_cache.zig");
const Config = @import("../config.zig").Http1ServerConfig;
const core = @import("../core.zig");
const HandlerFn = core.HandlerFn;
const common = @import("common.zig");
const logSystem = common.logSystem;
const ConnArgs = common.ConnArgs;
const connEntry = common.connEntry;

// --------------------------------------------------------- //
// ASYNC model

pub fn runAsync(config: Config, handler: HandlerFn) !void {
    const io = config.io;
    const addr = try std.Io.net.IpAddress.resolve(io, config.ip, config.port);
    var srv = try addr.listen(io, .{
        .mode = .stream,
        .kernel_backlog = config.kernel_backlog,
        .reuse_address = true,
    });
    defer srv.deinit(io);

    // Each pool thread builds its own cache on first use, so they are reclaimed together when
    // the accept loop ends rather than living until process exit.
    defer _ = async_cache.reclaim();

    var conn_registry = common.ConnRegistry{};
    const registry: ?*common.ConnRegistry = if (config.conn_timeout_ms > 0) &conn_registry else null;
    if (config.conn_timeout_ms > 0) {
        const sweeper = try std.Thread.spawn(.{}, common.connTimerLoop, .{ io, &conn_registry });
        sweeper.detach();
    }

    logSystem(config, .INFO, "listening on {s}:{d} (io.async)", .{ config.ip, config.port });

    while (true) {
        const stream = srv.accept(io) catch continue;
        _ = io.async(connEntry, .{ConnArgs{
            .stream = stream,
            .io = io,
            .handler = handler,
            .handler_timeout_ms = config.handler_timeout_ms,
            .conn_timeout_ms = config.conn_timeout_ms,
            .registry = registry,
            .send_date_header = config.send_date_header,
            .large_body_rcvbuf = config.large_body_rcvbuf,
            .max_recv_buf = config.max_recv_buf,
            .max_request_body = config.max_request_body,
            .public_dir = config.public_dir,
            .max_response_headers = config.max_response_headers.value(),
            .logger = config.logger,
            .compress = config.compress,
            .compression_min_size = config.compression_min_size,
            .compression_max_out = config.compression_max_out,
            .response_cache = config.response_cache,
            .cache_max_entries = config.cache_max_entries,
            .cache_max_value_bytes = config.cache_max_value_bytes,
            .cache_ttl_ms = config.cache_ttl_ms,
            .cache_max_total_bytes = config.cache_max_total_bytes,
        }});
    }
}
