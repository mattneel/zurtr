//! postgrez example: the comptime row mapper (struct parser approach).
//!
//! Note:
//! - Columns bind by NAME, NULL needs an optional field, a missing column
//!   falls back to the field default, jsonb parses into a struct field.
//! - Needs the PostgreSQL 18 container on 127.0.0.1:54180.

const std = @import("std");
const postgrez = @import("postgrez");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 54180;
const USER: []const u8 = "role_scram";
const PASSWORD: []const u8 = "postgrez_scram_pw";
const DATABASE: []const u8 = "postgrez_test";

// --------------------------------------------------------- //

const Profile = struct {
    theme: []const u8,
    notifications: bool,
};

const User = struct {
    id: i64,
    name: []const u8,
    age: u16,
    bio: ?[]const u8,
    score: f64 = 0.0,
    profile: Profile,
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
        "INSERT INTO users (name, email, age, bio, score, profile) VALUES ($1, $2, $3, $4, $5, $6)",
        .{ "Alice", "alice@typed.example", @as(i16, 30), "likes zig", @as(f64, 1.5), "{\"theme\":\"dark\",\"notifications\":true}" },
    );
    _ = try conn.exec(
        "INSERT INTO users (name, email, age, profile) VALUES ($1, $2, $3, $4)",
        .{ "Bob", "bob@typed.example", @as(i16, 25), "{\"theme\":\"light\",\"notifications\":false}" },
    );

    const users = try conn.query(User, "SELECT id, name, age, bio, score, profile FROM users ORDER BY id", .{});

    for (users) |user| {
        std.debug.print("{d} {s} age={d} bio={s} score={d} theme={s}\n", .{
            user.id,
            user.name,
            user.age,
            user.bio orelse "<null>",
            user.score,
            user.profile.theme,
        });
    }

    const maybe_user = try conn.queryRow(User, "SELECT id, name, age, bio, score, profile FROM users WHERE name = $1", .{"Alice"});
    std.debug.print("queryRow hit: {}\n", .{maybe_user != null});

    const missing = try conn.queryRow(User, "SELECT id, name, age, bio, score, profile FROM users WHERE name = $1", .{"Nobody"});
    std.debug.print("queryRow miss is null: {}\n", .{missing == null});

    std.debug.print("done\n", .{});
}
