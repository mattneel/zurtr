//! prometheuz example: walk a scraped snapshot for the first counter,
//! gauge, histogram, and summary family it finds, using
//! snapshot.family()/sample.label() and the histogram/summary query
//! helpers (bucket(), quantile(), sumSample(), countSample()) - the full
//! text 0.0.4 depth, not scalar-only.
//!
//! Note:
//! - Needs the node-exporter container on 127.0.0.1:19100
//!   (`zig build test-runner` owns the lifecycle). Which families are
//!   histogram/summary depends on the exporter build, so this scans rather
//!   than naming specific metrics.

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

    var seen_counter = false;
    var seen_gauge = false;
    var seen_histogram = false;
    var seen_summary = false;

    for (snapshot.families) |family| {
        switch (family.metric_type) {
            .counter => if (!seen_counter) {
                std.debug.print("counter {s}: {d} sample(s)\n", .{ family.name, family.samples.len });
                seen_counter = true;
            },
            .gauge => if (!seen_gauge) {
                std.debug.print("gauge {s}: {d} sample(s)\n", .{ family.name, family.samples.len });
                seen_gauge = true;
            },
            .histogram => if (!seen_histogram) {
                std.debug.print("histogram {s}: count={?d}\n", .{ family.name, if (family.countSample()) |s| s.value else null });
                seen_histogram = true;
            },
            .summary => if (!seen_summary) {
                std.debug.print("summary {s}: sum={?d}\n", .{ family.name, if (family.sumSample()) |s| s.value else null });
                seen_summary = true;
            },
            .untyped => {},
        }
    }

    std.debug.print("saw counter={} gauge={} histogram={} summary={}\n", .{ seen_counter, seen_gauge, seen_histogram, seen_summary });
    std.debug.print("done\n", .{});
}
