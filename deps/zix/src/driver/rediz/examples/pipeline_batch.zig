//! rediz example: pipeline several commands into one round trip.
//!
//! Note:
//! - Needs the Redis 8 container from containers/redis on 127.0.0.1:63980
//!   (`zig build test-runner` owns the lifecycle).
//! - max_pending_replies bounds the batch: add() sheds with
//!   error.RedizQueueFull beyond it instead of growing memory.

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
        .max_pending_replies = 8,
    });
    defer conn.deinit();

    var pipe = try conn.pipeline();
    try pipe.add(&.{ "SET", "batch:a", "1" });
    try pipe.add(&.{ "INCR", "batch:a" });
    try pipe.add(&.{ "INCR", "batch:a" });
    try pipe.add(&.{ "GET", "batch:a" });
    try pipe.add(&.{ "DEL", "batch:a" });

    const replies = try pipe.sync();
    for (replies, 0..) |reply, index| {
        switch (reply) {
            .simple => |line| std.debug.print("[{d}] {s}\n", .{ index, line }),
            .integer => |value| std.debug.print("[{d}] {d}\n", .{ index, value }),
            .bulk => |bytes| std.debug.print("[{d}] {s}\n", .{ index, bytes }),
            else => std.debug.print("[{d}] (other)\n", .{index}),
        }
    }

    std.debug.print("one flush, {d} replies\n", .{replies.len});

    std.debug.print("done\n", .{});
}
