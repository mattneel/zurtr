//! postgrez example: server errors through the full SQLSTATE enum.
//!
//! Note:
//! - error.PostgrezServerError signals a server-reported failure, lastServerError()
//!   carries the mapped enum, the raw 5-char code, severity, and message.
//!   The connection stays usable afterwards.
//! - Needs the PostgreSQL 18 container on 127.0.0.1:54180.

const std = @import("std");
const postgrez = @import("postgrez");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 54180;
const USER: []const u8 = "role_scram";
const PASSWORD: []const u8 = "postgrez_scram_pw";
const DATABASE: []const u8 = "postgrez_test";

// --------------------------------------------------------- //

const Count = struct {
    count: i64,
};

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

    _ = try conn.exec("TRUNCATE users", .{});
    _ = try conn.exec(
        "INSERT INTO users (name, email, age) VALUES ($1, $2, $3)",
        .{ "Alice", "alice@errors.example", @as(i16, 30) },
    );

    // duplicate email: UNIQUE_VIOLATION
    _ = conn.exec(
        "INSERT INTO users (name, email, age) VALUES ($1, $2, $3)",
        .{ "Alice2", "alice@errors.example", @as(i16, 31) },
    ) catch |err| {
        if (err != error.PostgrezServerError) return err;

        const server_error = conn.lastServerError();
        switch (server_error.state) {
            .UNIQUE_VIOLATION => std.debug.print("conflict detected: {s} ({s})\n", .{
                server_error.message(), server_error.code,
            }),
            else => return err,
        }
    };

    // syntax error: SYNTAX_ERROR, and the connection recovers
    _ = conn.exec("SELEC 1", .{}) catch |err| {
        if (err != error.PostgrezServerError) return err;

        std.debug.print("state: {s}\n", .{@tagName(conn.lastServerError().state)});
    };

    const count = try conn.queryRow(Count, "SELECT count(*)::int8 AS count FROM users", .{});
    std.debug.print("connection still usable, rows: {d}\n", .{count.?.count});

    std.debug.print("done\n", .{});
}
