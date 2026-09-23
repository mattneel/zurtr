//! postgrez example: pipelining, several statements in one round trip.
//!
//! Note:
//! - add() only queues, sync() sends the batch behind one Sync barrier and
//!   collects one result per statement in order.
//! - config.max_pending_replies bounds the queue (0 = no bound): beyond it
//!   add() sheds with error.PostgrezQueueFull instead of growing memory.
//! - Needs the PostgreSQL 18 container on 127.0.0.1:54180.

const std = @import("std");
const postgrez = @import("postgrez");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 54180;
const USER: []const u8 = "role_scram";
const PASSWORD: []const u8 = "postgrez_scram_pw";
const DATABASE: []const u8 = "postgrez_test";

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const conn = try postgrez.Conn.connect(allocator, process.io, .{
        .ip = IP,
        .port = PORT,
        .user = USER,
        .password = PASSWORD,
        .database = DATABASE,
        .max_pending_replies = 8,
    });
    defer conn.deinit();

    _ = try conn.exec("TRUNCATE logs", .{});

    var pipe = try conn.pipeline();
    try pipe.add("INSERT INTO logs (msg) VALUES ($1)", .{"batch-a"});
    try pipe.add("INSERT INTO logs (msg) VALUES ($1)", .{"batch-b"});
    try pipe.add("SELECT count(*) FROM logs", .{});

    const results = try pipe.sync();
    for (results, 0..) |result, index| {
        std.debug.print("statement {d}: status={s} affected={d}\n", .{
            index, @tagName(result.status), result.affected,
        });
    }

    std.debug.print("done\n", .{});
}
