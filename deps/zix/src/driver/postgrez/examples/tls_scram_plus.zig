//! postgrez example: TLS with SCRAM-SHA-256-PLUS channel binding.
//!
//! Note:
//! - .REQUIRE fails the connect when the server refuses TLS, .PREFER would
//!   continue cleartext. Over TLS the driver picks SCRAM-SHA-256-PLUS
//!   automatically when the server offers it, binding the channel to the
//!   server certificate (tls-server-end-point).
//! - Needs the PostgreSQL 18 container on 127.0.0.1:54180.

const std = @import("std");
const postgrez = @import("postgrez");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 54180;
const USER: []const u8 = "role_scram_plus";
const PASSWORD: []const u8 = "postgrez_scram_plus_pw";
const DATABASE: []const u8 = "postgrez_test";

// --------------------------------------------------------- //

const One = struct {
    one: i64,
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
        .tls = .REQUIRE,
    });
    defer conn.deinit();

    const session = conn.tls_session orelse return error.PostgrezTlsSessionMissing;
    std.debug.print("tls active, server cert {d} bytes\n", .{session.serverCertDer().len});
    std.debug.print("mechanism: {s}\n", .{(conn.sasl_mechanism orelse return error.PostgrezSaslMissing).name()});

    const one = try conn.queryRow(One, "SELECT 1::int8 AS one", .{});
    std.debug.print("query over tls: {d}\n", .{one.?.one});

    std.debug.print("done\n", .{});
}
