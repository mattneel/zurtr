//! prometheuz example: PromQL instant query ("up") and a ranged query,
//! against a live Prometheus.
//!
//! Note:
//! - Needs the prometheus container on 127.0.0.1:19090
//!   (`zig build test-runner` owns the lifecycle).

const std = @import("std");
const prometheuz = @import("prometheuz");

const PROMETHEUS_IP: []const u8 = "127.0.0.1";
const PROMETHEUS_PORT: u16 = 19090;

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const config = prometheuz.QueryConfig{ .ip = PROMETHEUS_IP, .port = PROMETHEUS_PORT };

    var instant = try prometheuz.query(allocator, process.io, config, "up");
    defer instant.deinit();

    std.debug.print("instant query 'up': {d} series\n", .{instant.vector.len});
    for (instant.vector) |entry| std.debug.print("  value={d}\n", .{entry.value});

    const now_s = std.Io.Clock.real.now(process.io).toSeconds();
    var ranged = try prometheuz.queryRange(allocator, process.io, config, "up", now_s - 60, now_s, "15s");
    defer ranged.deinit();

    std.debug.print("range query 'up': {d} series\n", .{ranged.matrix.len});

    std.debug.print("done\n", .{});
}
