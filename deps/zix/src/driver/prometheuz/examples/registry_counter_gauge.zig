//! prometheuz example: register a labeled Counter and a Gauge, record a
//! few values, then print the text 0.0.4 encoding via expose() - the
//! direct answer to "how do I add a value". No network, no server.
//!
//! Note:
//! - No container needed.

const std = @import("std");
const prometheuz = @import("prometheuz");

// --------------------------------------------------------- //

pub fn main(process: std.process.Init) !void {
    _ = process;

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var registry = prometheuz.Registry.init(allocator);
    defer registry.deinit();

    const write_errors = try registry.counter("app_write_errors_total", "Failed write operations", &.{"reason"});
    write_errors.with(&.{"user_create_failed"}).inc();
    write_errors.with(&.{"user_create_failed"}).inc();
    write_errors.with(&.{"tx_failed"}).add(3);

    const in_flight = try registry.gauge("in_flight_requests", "Requests being handled", &.{});
    in_flight.with(&.{}).set(7);
    in_flight.with(&.{}).inc();

    const body = try prometheuz.expose(allocator, &registry);
    std.debug.print("{s}", .{body});

    std.debug.print("done\n", .{});
}
