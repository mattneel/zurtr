//! postgrez example: prepared statements reused across executions.
//!
//! Note:
//! - prepare() describes the statement once (parameter OIDs + result
//!   columns), repeated exec/query skip the parse and describe rounds.
//! - A parameter whose Zig type picks a different OID than the server
//!   described falls back to the text wire form automatically.
//! - Needs the PostgreSQL 18 container on 127.0.0.1:54180.

const std = @import("std");
const postgrez = @import("postgrez");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 54180;
const USER: []const u8 = "role_scram";
const PASSWORD: []const u8 = "postgrez_scram_pw";
const DATABASE: []const u8 = "postgrez_test";

// --------------------------------------------------------- //

const LogLine = struct {
    msg: []const u8,
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

    _ = try conn.exec("TRUNCATE logs", .{});

    var insert = try conn.prepare("INSERT INTO logs (msg) VALUES ($1)");
    defer insert.deinit();
    std.debug.print("statement name: {s}\n", .{insert.name()});

    const batch = [_][]const u8{ "deploy", "migrate", "verify" };
    for (batch) |message| {
        const affected = try insert.exec(.{message});
        std.debug.print("inserted {s}: {d}\n", .{ message, affected });
    }

    var select = try conn.prepare("SELECT msg FROM logs WHERE msg = $1");
    defer select.deinit();

    const hit = try select.queryRow(LogLine, .{"migrate"});
    std.debug.print("found: {s}\n", .{hit.?.msg});

    const lines = try select.query(LogLine, .{"verify"});
    std.debug.print("verify rows: {d}\n", .{lines.len});

    std.debug.print("done\n", .{});
}
