//! rediz example: typed JSON values (struct parser approach).
//!
//! Note:
//! - setJson stringifies any struct into the value, getJson parses it back
//!   by field NAME: NULL needs an optional field, a missing field falls
//!   back to the field default, unknown fields are ignored, nested structs
//!   parse in place.
//! - Needs the Redis 8 container from containers/redis on 127.0.0.1:63980
//!   (`zig build test-runner` owns the lifecycle).

const std = @import("std");
const rediz = @import("rediz");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 63980;

// --------------------------------------------------------- //

const Profile = struct {
    theme: []const u8,
    notifications: bool,
};

const User = struct {
    id: i64,
    name: []const u8,
    age: u16,
    bio: ?[]const u8 = null,
    score: f64 = 0.0,
    profile: Profile,
};

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const conn = try rediz.Conn.connect(allocator, process.io, .{
        .ip = IP,
        .port = PORT,
    });
    defer conn.deinit();

    _ = try conn.setJson("typed:user:1", User{
        .id = 1,
        .name = "Alice",
        .age = 30,
        .bio = "likes zig",
        .score = 1.5,
        .profile = .{ .theme = "dark", .notifications = true },
    }, .{ .ex_s = 60 });
    _ = try conn.setJson("typed:user:2", User{
        .id = 2,
        .name = "Bob",
        .age = 25,
        .profile = .{ .theme = "light", .notifications = false },
    }, .{ .ex_s = 60 });

    const keys = [_][]const u8{ "typed:user:1", "typed:user:2" };
    for (keys) |key| {
        const user = (try conn.getJson(User, key)).?;
        std.debug.print("{d} {s} age={d} bio={s} score={d} theme={s}\n", .{
            user.id,
            user.name,
            user.age,
            user.bio orelse "<null>",
            user.score,
            user.profile.theme,
        });
    }

    const missing = try conn.getJson(User, "typed:user:999");
    std.debug.print("getJson miss is null: {}\n", .{missing == null});

    _ = try conn.del(&keys);

    std.debug.print("done\n", .{});
}
