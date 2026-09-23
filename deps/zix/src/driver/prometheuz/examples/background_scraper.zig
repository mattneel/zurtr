//! prometheuz example: the Scraper background poller - start it, read
//! latest() a few times as it publishes, then stop it.
//!
//! Note:
//! - Needs the node-exporter container on 127.0.0.1:19100
//!   (`zig build test-runner` owns the lifecycle).

const std = @import("std");
const prometheuz = @import("prometheuz");

const IP: []const u8 = "127.0.0.1";
const PORT: u16 = 19100;
const SCRAPE_INTERVAL_MS: u32 = 500;
const READS: usize = 3;

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var scraper = try prometheuz.Scraper.start(allocator, process.io, .{
        .ip = IP,
        .port = PORT,
        .scrape_interval_ms = SCRAPE_INTERVAL_MS,
    });
    defer scraper.deinit();

    var reads: usize = 0;
    while (reads < READS) : (reads += 1) {
        std.Io.sleep(process.io, .fromMilliseconds(SCRAPE_INTERVAL_MS + 100), .awake) catch {};

        var snapshot = scraper.latest();
        defer snapshot.release();

        std.debug.print("read {d}: up={} samples={d}\n", .{ reads, snapshot.up, snapshot.samples.len });
    }

    std.debug.print("done\n", .{});
}
