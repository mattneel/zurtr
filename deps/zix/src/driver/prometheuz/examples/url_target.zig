//! prometheuz example: build each config from a target URL (parseScrapeUrl,
//! parseWriteUrl, parseQueryUrl) instead of a Config struct, then scrape,
//! push, and query once.
//!
//! Note:
//! - basic_scrape.zig shows the same scrape from a Config struct directly.
//! - Needs the node-exporter container on 127.0.0.1:19100 and the
//!   prometheus container on 127.0.0.1:19090 (`zig build test-runner`
//!   owns the lifecycle).

const std = @import("std");
const prometheuz = @import("prometheuz");

const TARGET_URL: []const u8 = "http://127.0.0.1:19100/metrics";
const WRITE_URL: []const u8 = "http://127.0.0.1:19090/api/v1/write";
const QUERY_URL: []const u8 = "http://127.0.0.1:19090";

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const scrape_config = try prometheuz.parseScrapeUrl(TARGET_URL);

    var snapshot = try prometheuz.scrapeOnce(allocator, process.io, scrape_config);
    defer snapshot.deinit();

    std.debug.print("target: {s}:{d}{s}\n", .{ scrape_config.ip, scrape_config.port, scrape_config.path });
    std.debug.print("scrape up: {}\n", .{snapshot.up});
    std.debug.print("samples: {d}\n", .{snapshot.samples.len});

    const write_config = try prometheuz.parseWriteUrl(WRITE_URL);

    try prometheuz.remoteWrite(allocator, process.io, write_config, snapshot.samples);
    std.debug.print("pushed {d} samples to {s}:{d}{s}\n", .{ snapshot.samples.len, write_config.ip, write_config.port, write_config.path });

    const query_config = try prometheuz.parseQueryUrl(QUERY_URL);

    var result = try prometheuz.query(allocator, process.io, query_config, "up");
    defer result.deinit();

    std.debug.print("query 'up': {d} series\n", .{result.vector.len});

    std.debug.print("done\n", .{});
}
