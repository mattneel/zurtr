//! prometheuz example: record an app-authored error counter, push it via
//! remote_write to a Prometheus receiver - the push path for app-authored
//! values (see remote_write_forward.zig for scraped values instead).
//!
//! Note:
//! - Needs the prometheus container (remote-write receiver enabled) on
//!   127.0.0.1:19090 (`zig build test-runner` owns the lifecycle).

const std = @import("std");
const prometheuz = @import("prometheuz");

const PROMETHEUS_IP: []const u8 = "127.0.0.1";
const PROMETHEUS_PORT: u16 = 19090;

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var registry = prometheuz.Registry.init(allocator);
    defer registry.deinit();

    const write_errors = try registry.counter("app_write_errors_total", "Failed write operations", &.{"reason"});
    write_errors.with(&.{"user_create_failed"}).inc();

    const samples = try registry.snapshot(allocator);

    try prometheuz.remoteWrite(allocator, process.io, .{ .ip = PROMETHEUS_IP, .port = PROMETHEUS_PORT }, samples);

    std.debug.print("pushed {d} sample(s)\n", .{samples.len});
    std.debug.print("done\n", .{});
}
