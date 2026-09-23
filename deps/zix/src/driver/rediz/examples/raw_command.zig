//! rediz example: the raw command API for anything without a typed wrapper.
//!
//! Note:
//! - Needs the Redis 8 container from containers/redis on 127.0.0.1:63980
//!   (`zig build test-runner` owns the lifecycle).

const std = @import("std");
const rediz = @import("rediz");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 63980;

// --------------------------------------------------------- //

fn printReply(reply: rediz.Reply, indent: usize) void {
    var pad: usize = 0;
    while (pad < indent) : (pad += 1) std.debug.print("  ", .{});

    switch (reply) {
        .simple => |line| std.debug.print("simple: {s}\n", .{line}),
        .bulk => |bytes| std.debug.print("bulk: {s}\n", .{bytes}),
        .integer => |value| std.debug.print("integer: {d}\n", .{value}),
        .double => |value| std.debug.print("double: {d}\n", .{value}),
        .boolean => |value| std.debug.print("boolean: {}\n", .{value}),
        .null => std.debug.print("null\n", .{}),
        .array => |items| {
            std.debug.print("array ({d}):\n", .{items.len});
            for (items) |item| printReply(item, indent + 1);
        },
        .map => |entries| {
            std.debug.print("map ({d}):\n", .{entries.len});
            for (entries) |entry| {
                printReply(entry.key, indent + 1);
                printReply(entry.value, indent + 2);
            }
        },
        .set => |items| {
            std.debug.print("set ({d}):\n", .{items.len});
            for (items) |item| printReply(item, indent + 1);
        },
        else => std.debug.print("(other)\n", .{}),
    }
}

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const conn = try rediz.Conn.connect(allocator, process.io, .{
        .ip = IP,
        .port = PORT,
    });
    defer conn.deinit();

    // hashes have no typed wrapper: raw command covers them
    _ = try conn.command(&.{ "HSET", "raw:profile", "name", "zix", "kind", "engine" });
    const profile = try conn.command(&.{ "HGETALL", "raw:profile" });
    printReply(profile, 0);

    // server introspection
    const dbsize = try conn.command(&.{"DBSIZE"});
    printReply(dbsize, 0);

    _ = try conn.del(&.{"raw:profile"});

    std.debug.print("done\n", .{});
}
