//! prometheuz example: point scrapeOnce at an unreachable target, show the
//! failure surfaced through Snapshot (up = false, last_error), never
//! thrown.
//!
//! Note:
//! - No container needed: the target is deliberately unreachable.

const std = @import("std");
const prometheuz = @import("prometheuz");

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var snapshot = try prometheuz.scrapeOnce(allocator, process.io, .{
        .ip = "127.0.0.1",
        .port = 1,
        .conn_timeout_ms = 500,
    });
    defer snapshot.deinit();

    std.debug.print("up: {}\n", .{snapshot.up});
    std.debug.print("last_error: {s}\n", .{snapshot.last_error orelse "none"});
    std.debug.print("samples: {d}\n", .{snapshot.samples.len});

    std.debug.print("done\n", .{});
}
