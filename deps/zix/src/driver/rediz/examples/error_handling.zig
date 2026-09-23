//! rediz example: server error replies and the mapped prefix enum.
//!
//! Note:
//! - Needs the Redis 8 container from containers/redis on 127.0.0.1:63980
//!   (`zig build test-runner` owns the lifecycle).

const std = @import("std");
const rediz = @import("rediz");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 63980;

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const conn = try rediz.Conn.connect(allocator, process.io, .{
        .ip = IP,
        .port = PORT,
    });
    defer conn.deinit();

    // wrong type: INCR on a list
    _ = try conn.del(&.{"err:list"});
    _ = try conn.command(&.{ "RPUSH", "err:list", "item" });

    _ = conn.incr("err:list") catch |err| switch (err) {
        error.RedizServerError => {
            const server_error = conn.lastServerError();
            std.debug.print("prefix: {t}\n", .{server_error.prefix});
            std.debug.print("message: {s}\n", .{server_error.message()});
        },
        else => return err,
    };

    // unknown command through the raw path
    _ = conn.command(&.{"NOSUCHCOMMAND"}) catch |err| switch (err) {
        error.RedizServerError => {
            std.debug.print("unknown command prefix: {t}\n", .{conn.lastServerError().prefix});
        },
        else => return err,
    };

    _ = try conn.del(&.{"err:list"});

    std.debug.print("done\n", .{});
}
