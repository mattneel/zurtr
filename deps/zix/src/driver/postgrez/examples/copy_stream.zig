//! postgrez example: COPY IN and COPY OUT streaming.
//!
//! Note:
//! - copyIn buffers writes and flushes in chunks, finish() ends the stream
//!   and reports the copied row count. copyOut streams the rows back.
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
    });
    defer conn.deinit();

    _ = try conn.exec("TRUNCATE metrics", .{});

    var copy_in = try conn.copyIn("COPY metrics (ts, value) FROM STDIN");
    try copy_in.write("2026-07-14 10:00:00\t42\n");
    try copy_in.write("2026-07-14 10:00:01\t43\n");
    try copy_in.write("2026-07-14 10:00:02\t44\n");

    const copied = try copy_in.finish();
    std.debug.print("copied in: {d}\n", .{copied});

    var copy_out = try conn.copyOut("COPY metrics TO STDOUT");
    defer copy_out.deinit();

    var sum: i64 = 0;
    while (try copy_out.next()) |line| {
        var field_it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, line, "\n"), '\t');
        _ = field_it.next();
        sum += try std.fmt.parseInt(i64, field_it.next().?, 10);
    }
    std.debug.print("copied out sum: {d}\n", .{sum});

    std.debug.print("done\n", .{});
}
