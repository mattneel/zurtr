//! prometheuz example: scrape node-exporter once, forward the scraped
//! samples via remote_write to a Prometheus receiver - the original
//! back-to-back surface, pushed instead of merely held in memory.
//!
//! Note:
//! - Needs the node-exporter container on 127.0.0.1:19100 and the
//!   prometheus container (remote-write receiver enabled) on
//!   127.0.0.1:19090 (`zig build test-runner` owns the lifecycle).

const std = @import("std");
const prometheuz = @import("prometheuz");

const NODE_EXPORTER_IP: []const u8 = "127.0.0.1";
const NODE_EXPORTER_PORT: u16 = 19100;
const PROMETHEUS_IP: []const u8 = "127.0.0.1";
const PROMETHEUS_PORT: u16 = 19090;

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var snapshot = try prometheuz.scrapeOnce(allocator, process.io, .{ .ip = NODE_EXPORTER_IP, .port = NODE_EXPORTER_PORT });
    defer snapshot.deinit();

    std.debug.print("scraped {d} samples, up={}\n", .{ snapshot.samples.len, snapshot.up });

    if (snapshot.up) {
        try prometheuz.remoteWrite(allocator, process.io, .{ .ip = PROMETHEUS_IP, .port = PROMETHEUS_PORT }, snapshot.samples);
        std.debug.print("pushed {d} samples\n", .{snapshot.samples.len});
    }

    std.debug.print("done\n", .{});
}
