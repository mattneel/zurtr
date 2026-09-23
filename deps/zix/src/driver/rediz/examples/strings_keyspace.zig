//! rediz example: string values, counters, and keyspace management.
//!
//! Note:
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

    // strings with expiry
    _ = try conn.set("demo:session", "token-abc", .{ .ex_s = 60 });
    std.debug.print("session ttl: {d}s\n", .{try conn.ttl("demo:session")});
    std.debug.print("session type: {s}\n", .{try conn.keyType("demo:session")});

    // counters
    _ = try conn.del(&.{"demo:visits"});
    _ = try conn.incr("demo:visits");
    _ = try conn.incrBy("demo:visits", 41);
    std.debug.print("visits: {?s}\n", .{try conn.get("demo:visits")});

    // multi-key round trip
    try conn.mset(&.{
        .{ .key = "demo:a", .value = "alpha" },
        .{ .key = "demo:b", .value = "beta" },
    });
    const values = try conn.mget(&.{ "demo:a", "demo:b", "demo:missing" });
    for (values, 0..) |value, index| {
        std.debug.print("mget[{d}]: {?s}\n", .{ index, value });
    }

    // cleanup
    const removed = try conn.del(&.{ "demo:session", "demo:visits", "demo:a", "demo:b" });
    std.debug.print("removed: {d}\n", .{removed});

    std.debug.print("done\n", .{});
}
