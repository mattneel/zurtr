//! postgrez example: connect from a URL (parseUrl), cleartext and TLS.
//!
//! Note:
//! - parseUrl only parses: it returns a Config and the caller connects,
//!   so every non-URL knob can still be adjusted in between.
//! - DATABASE_URL from the environment wins when set, the same way a
//!   consumer service would read its database address.
//! - basic_connect.zig shows the same connect from a Config struct literal.
//! - Needs the PostgreSQL 18 container from containers/postgresql on
//!   127.0.0.1:54180, `zig build test-runner` owns the lifecycle.

const std = @import("std");
const postgrez = @import("postgrez");

const DEFAULT_URL: []const u8 = "postgres://role_scram:postgrez_scram_pw@127.0.0.1:54180/postgrez_test";
const TLS_URL: []const u8 = "postgres://role_scram_plus:postgrez_scram_plus_pw@127.0.0.1:54180/postgrez_test?sslmode=require";

// --------------------------------------------------------- //

const Answer = struct {
    answer: i64,
};

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // cleartext: environment URL wins, fall back to the container default
    const url_text = process.environ_map.get("DATABASE_URL") orelse DEFAULT_URL;
    const config = try postgrez.parseUrl(url_text);
    std.debug.print("parsed: ip={s} port={d} user={s} database={s} tls={t}\n", .{
        config.ip,
        config.port,
        config.user,
        config.database orelse "<null>",
        config.tls,
    });

    const conn = try postgrez.Conn.connect(allocator, process.io, config);
    defer conn.deinit();

    const row = try conn.queryRow(Answer, "SELECT 42 AS answer", .{});
    std.debug.print("query answer: {d}\n", .{row.?.answer});

    // TLS: sslmode=require flips config.tls to .REQUIRE
    const tls_config = try postgrez.parseUrl(TLS_URL);
    std.debug.print("tls parsed: user={s} tls={t}\n", .{ tls_config.user, tls_config.tls });

    const tls_conn = try postgrez.Conn.connect(allocator, process.io, tls_config);
    defer tls_conn.deinit();

    std.debug.print("tls session: {}\n", .{tls_conn.tls_session != null});

    std.debug.print("done\n", .{});
}
