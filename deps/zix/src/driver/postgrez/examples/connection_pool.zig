//! postgrez example: the per-worker shared-nothing pool.
//!
//! Note:
//! - Explicit acquire/release, lazy connect per slot, discard() frees a
//!   broken slot so the next acquire reconnects (with the retry knobs).
//! - One Pool belongs to ONE worker, no locking anywhere.
//! - Needs the PostgreSQL 18 container on 127.0.0.1:54180.

const std = @import("std");
const postgrez = @import("postgrez");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 54180;
const USER: []const u8 = "role_scram";
const PASSWORD: []const u8 = "postgrez_scram_pw";
const DATABASE: []const u8 = "postgrez_test";

// --------------------------------------------------------- //

const One = struct {
    one: i64,
};

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pool = try postgrez.Pool.init(allocator, process.io, .{
        .ip = IP,
        .port = PORT,
        .user = USER,
        .password = PASSWORD,
        .database = DATABASE,
        .pool_size = 3,
        .retry_max = 3,
        .retry_delay_ms = 600,
    });
    defer pool.deinit();

    // two live connections at once
    const first = try pool.acquire();
    const second = try pool.acquire();
    std.debug.print("distinct backends: {}\n", .{first.backend_pid != second.backend_pid});

    const one = try first.queryRow(One, "SELECT 1::int8 AS one", .{});
    std.debug.print("query through slot 1: {d}\n", .{one.?.one});

    const first_pid = first.backend_pid;
    pool.release(first);
    pool.release(second);
    std.debug.print("idle after release: {d}\n", .{pool.idleCount()});

    // released slots are reused, no reconnect
    const reused = try pool.acquire();
    std.debug.print("reused same backend: {}\n", .{reused.backend_pid == first_pid});
    pool.release(reused);

    std.debug.print("done\n", .{});
}
