//! postgrez example: LISTEN and NOTIFY on one connection.
//!
//! Note:
//! - notify() goes through pg_notify so the payload is fully parameterized.
//! - nextNotification serves pending notifications first, then blocks on
//!   the wire. The returned slices stay valid until the next call.
//! - Needs the PostgreSQL 18 container on 127.0.0.1:54180.

const std = @import("std");
const postgrez = @import("postgrez");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 54180;
const USER: []const u8 = "role_scram";
const PASSWORD: []const u8 = "postgrez_scram_pw";
const DATABASE: []const u8 = "postgrez_test";

const CHANNEL: []const u8 = "postgrez_jobs";

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
    });
    defer conn.deinit();

    try conn.listen(CHANNEL);
    try conn.notify(CHANNEL, "job-42");

    const note = (try conn.nextNotification()).?;
    std.debug.print("channel: {s}\n", .{note.channel});
    std.debug.print("payload: {s}\n", .{note.payload});
    std.debug.print("from own backend: {}\n", .{note.pid == conn.backend_pid});

    try conn.unlisten(CHANNEL);

    std.debug.print("done\n", .{});
}
