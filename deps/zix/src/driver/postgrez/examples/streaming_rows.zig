//! postgrez example: the streaming row iterator with per-cell decode.
//!
//! Note:
//! - Binary first per OID, numeric and interval flow through the text
//!   fallback transparently.
//! - Needs the PostgreSQL 18 container on 127.0.0.1:54180.

const std = @import("std");
const postgrez = @import("postgrez");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 54180;
const USER: []const u8 = "role_scram";
const PASSWORD: []const u8 = "postgrez_scram_pw";
const DATABASE: []const u8 = "postgrez_test";

// --------------------------------------------------------- //

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

    var result = try conn.rows(
        \\SELECT n::int8 AS id,
        \\       (n * 1.5)::float8 AS score,
        \\       (n % 2 = 0) AS even,
        \\       'row-' || n::text AS label,
        \\       (n * 100)::numeric / 3 AS ratio,
        \\       CASE WHEN n = 2 THEN NULL ELSE 'set' END AS note
        \\FROM generate_series(1, 3) AS n
    , .{});
    defer result.deinit();

    while (try result.next()) |row| {
        const id = try row.get(i64, 0);
        const score = try row.get(f64, 1);
        const even = try row.get(bool, 2);
        const label = try row.get([]const u8, 3);
        const ratio = try row.get(f64, 4);
        const note = try row.get(?[]const u8, 5);

        std.debug.print("{d} score={d:.1} even={} label={s} ratio={d:.2} note={s}\n", .{
            id, score, even, label, ratio, note orelse "<null>",
        });
    }

    std.debug.print("affected tag rows: {d}\n", .{result.affected});
    std.debug.print("done\n", .{});
}
