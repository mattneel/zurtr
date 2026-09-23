//! rediz example: connect from a Config struct, inspect the session, first
//! round trips.
//!
//! Note:
//! - url_connect.zig shows the same connect from a URL (parseUrl).
//! - Needs the Redis 8 container from containers/redis on 127.0.0.1:63980
//!   (`zig build test-runner` owns the lifecycle).

const std = @import("std");
const rediz = @import("rediz");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 63980;

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const conn = try rediz.Conn.connect(allocator, process.io, .{
        .ip = IP,
        .port = PORT,
    });
    defer conn.deinit();

    std.debug.print("server major: {d}\n", .{conn.server_version_major});
    std.debug.print("protocol: {t}\n", .{conn.protocol_active});

    try conn.ping();
    std.debug.print("ping: PONG\n", .{});

    _ = try conn.set("example:hello", "world", .{});
    const value = try conn.get("example:hello");
    std.debug.print("get example:hello -> {s}\n", .{value.?});
    _ = try conn.del(&.{"example:hello"});

    std.debug.print("done\n", .{});
}
