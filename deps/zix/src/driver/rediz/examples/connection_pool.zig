//! rediz example: per-worker pool with release and discard-heal.
//!
//! Note:
//! - Needs the Redis 8 container from containers/redis on 127.0.0.1:63980
//!   (`zig build test-runner` owns the lifecycle).
//! - One Pool per worker (shared-nothing): this example is a single worker.

const std = @import("std");
const rediz = @import("rediz");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 63980;

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pool = try rediz.Pool.init(allocator, process.io, .{
        .ip = IP,
        .port = PORT,
        .pool_size = 2,
        .retry_max = 2,
        .retry_delay_ms = 100,
    });
    defer pool.deinit();

    // acquire, use, release: the slot stays connected for reuse
    const first = try pool.acquire();
    try first.ping();
    _ = try first.set("pool:key", "value", .{ .ex_s = 30 });
    pool.release(first);
    std.debug.print("idle after release: {d}\n", .{pool.idleCount()});

    // the released connection is reused, not reconnected
    const reused = try pool.acquire();
    std.debug.print("reused same conn: {}\n", .{reused == first});
    const value = try reused.get("pool:key");
    std.debug.print("pool:key -> {?s}\n", .{value});

    // a broken connection goes through discard, the slot reconnects lazily
    pool.discard(reused);
    const healed = try pool.acquire();
    try healed.ping();
    _ = try healed.del(&.{"pool:key"});
    pool.release(healed);
    std.debug.print("healed after discard\n", .{});

    std.debug.print("done\n", .{});
}
