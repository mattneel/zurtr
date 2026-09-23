//! postgrez example: connect from a Config struct, inspect the session, run
//! a first query.
//!
//! Note:
//! - url_connect.zig shows the same connect from a URL (parseUrl).
//! - Needs the PostgreSQL 18 container from containers/postgresql on
//!   127.0.0.1:54180 (`zig build test-runner` owns the lifecycle).

const std = @import("std");
const postgrez = @import("postgrez");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 54180;
const USER: []const u8 = "role_scram";
const PASSWORD: []const u8 = "postgrez_scram_pw";
const DATABASE: []const u8 = "postgrez_test";

// --------------------------------------------------------- //

const Version = struct {
    version: []const u8,
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

    std.debug.print("server major: {d}\n", .{conn.server_version_major});
    std.debug.print("protocol 3.2: {}\n", .{conn.protocol_code == postgrez.frontend.PROTOCOL_V3_2});
    std.debug.print("backend pid: {d}\n", .{conn.backend_pid});

    const row = try conn.queryRow(Version, "SELECT version() AS version", .{});
    std.debug.print("version: {s}\n", .{row.?.version[0..@min(row.?.version.len, 32)]});

    std.debug.print("done\n", .{});
}
