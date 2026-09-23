//! rediz example: connect over TLS (the container's TLS listener).
//!
//! Note:
//! - Needs the Redis 8 container from containers/redis on 127.0.0.1:63981
//!   (TLS port, `zig build test-runner` owns the lifecycle).
//! - The container certificate is ephemeral and self-signed: the client
//!   encrypts and verifies the handshake, chain trust is out of scope.

const std = @import("std");
const rediz = @import("rediz");

const IP: []const u8 = "127.0.0.1";
const TLS_PORT: u16 = 63981;

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const conn = try rediz.Conn.connect(allocator, process.io, .{
        .ip = IP,
        .port = TLS_PORT,
        .tls = .REQUIRE,
    });
    defer conn.deinit();

    std.debug.print("tls session: {}\n", .{conn.tls_session != null});
    std.debug.print("server cert der bytes: {d}\n", .{conn.tls_session.?.serverCertDer().len});

    try conn.ping();
    _ = try conn.set("tls:greeting", "encrypted hello", .{ .ex_s = 30 });
    const value = try conn.get("tls:greeting");
    std.debug.print("tls:greeting -> {?s}\n", .{value});
    _ = try conn.del(&.{"tls:greeting"});

    std.debug.print("done\n", .{});
}
