//! rediz example: connect from a URL (parseUrl), cleartext and TLS.
//!
//! Note:
//! - parseUrl only parses: it returns a Config and the caller connects,
//!   so every non-URL knob can still be adjusted in between.
//! - REDIS_URL from the environment wins when set, the same way a consumer
//!   service would read its sidecar address.
//! - basic_connect.zig shows the same connect from a Config struct literal.
//! - Needs the Redis 8 container from containers/redis on 127.0.0.1:63980
//!   (cleartext) and 63981 (TLS), `zig build test-runner` owns the
//!   lifecycle.

const std = @import("std");
const rediz = @import("rediz");

const DEFAULT_URL: []const u8 = "redis://127.0.0.1:63980/0";
const TLS_URL: []const u8 = "rediss://127.0.0.1:63981";

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // cleartext: environment URL wins, fall back to the container default
    const url_text = process.environ_map.get("REDIS_URL") orelse DEFAULT_URL;
    const config = try rediz.parseUrl(url_text);
    std.debug.print("parsed: ip={s} port={d} database={d} tls={t}\n", .{
        config.ip,
        config.port,
        config.database,
        config.tls,
    });

    const conn = try rediz.Conn.connect(allocator, process.io, config);
    defer conn.deinit();

    try conn.ping();
    _ = try conn.set("url:key", "from-url", .{ .ex_s = 30 });
    std.debug.print("url:key -> {?s}\n", .{try conn.get("url:key")});
    _ = try conn.del(&.{"url:key"});

    // TLS: the rediss scheme flips config.tls to .REQUIRE
    const tls_config = try rediz.parseUrl(TLS_URL);
    std.debug.print("tls parsed: port={d} tls={t}\n", .{ tls_config.port, tls_config.tls });

    const tls_conn = try rediz.Conn.connect(allocator, process.io, tls_config);
    defer tls_conn.deinit();

    try tls_conn.ping();
    std.debug.print("tls session: {}\n", .{tls_conn.tls_session != null});

    std.debug.print("done\n", .{});
}
