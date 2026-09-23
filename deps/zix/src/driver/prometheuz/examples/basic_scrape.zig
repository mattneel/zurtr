//! prometheuz example: one-shot scrape of a node-exporter /metrics
//! endpoint, print the family/sample counts.
//!
//! Note:
//! - url_target.zig shows the same scrape built from a URL (parseScrapeUrl).
//! - Needs the node-exporter container on 127.0.0.1:19100
//!   (`zig build test-runner` owns the lifecycle).

const std = @import("std");
const prometheuz = @import("prometheuz");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 19100;

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var snapshot = try prometheuz.scrapeOnce(allocator, process.io, .{ .ip = IP, .port = PORT });
    defer snapshot.deinit();

    std.debug.print("scrape up: {}\n", .{snapshot.up});
    std.debug.print("families: {d}\n", .{snapshot.families.len});
    std.debug.print("samples: {d}\n", .{snapshot.samples.len});

    std.debug.print("done\n", .{});
}
