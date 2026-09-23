//! expose.zig: encode a Registry's current state as Prometheus text 0.0.4,
//! the inverse of parser.zig. The app wires the result into its own
//! GET /metrics route for a real Prometheus to pull.

const std = @import("std");
const registry_mod = @import("registry.zig");
const sample_mod = @import("sample.zig");

const MetricFamily = sample_mod.MetricFamily;
const MetricType = sample_mod.MetricType;

/// Format every family currently in `registry` as text 0.0.4 into a fresh
/// arena-owned buffer, suitable for a GET /metrics response body.
pub fn expose(arena: std.mem.Allocator, registry: *registry_mod.Registry) ![]const u8 {
    const families = try registry.families(arena);

    return exposeFamilies(arena, families);
}

/// Same encoder, taking already-parsed families directly (e.g. from
/// parser.parse, for a passthrough or a test).
pub fn exposeFamilies(arena: std.mem.Allocator, families: []const MetricFamily) ![]const u8 {
    var allocating = std.Io.Writer.Allocating.init(arena);
    const writer = &allocating.writer;

    for (families) |family| {
        try writer.print("# HELP {s} ", .{family.name});
        try writeEscaped(writer, family.help, false);
        try writer.writeByte('\n');

        try writer.print("# TYPE {s} {s}\n", .{ family.name, typeString(family.metric_type) });

        for (family.samples) |current_sample| {
            try writer.writeAll(current_sample.name);

            if (current_sample.labels.len > 0) {
                try writer.writeByte('{');
                for (current_sample.labels, 0..) |label, index| {
                    if (index > 0) try writer.writeByte(',');
                    try writer.print("{s}=\"", .{label.name});
                    try writeEscaped(writer, label.value, true);
                    try writer.writeByte('"');
                }
                try writer.writeByte('}');
            }

            try writer.writeByte(' ');
            try writeValue(writer, current_sample.value);

            if (current_sample.timestamp_ms) |timestamp_ms| try writer.print(" {d}", .{timestamp_ms});

            try writer.writeByte('\n');
        }
    }

    return allocating.toOwnedSlice();
}

// --------------------------------------------------------- //

fn typeString(metric_type: MetricType) []const u8 {
    return switch (metric_type) {
        .counter => "counter",
        .gauge => "gauge",
        .histogram => "histogram",
        .summary => "summary",
        .untyped => "untyped",
    };
}

fn writeValue(writer: anytype, value: f64) !void {
    if (std.math.isNan(value)) return writer.writeAll("Nan");
    if (std.math.isPositiveInf(value)) return writer.writeAll("+Inf");
    if (std.math.isNegativeInf(value)) return writer.writeAll("-Inf");

    try writer.print("{d}", .{value});
}

/// Escape `\` and newline always, `"` only for label values (HELP text is
/// never quoted, so a literal `"` needs no escape there).
fn writeEscaped(writer: anytype, text: []const u8, escape_quote: bool) !void {
    for (text) |byte| {
        switch (byte) {
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '"' => if (escape_quote) try writer.writeAll("\\\"") else try writer.writeByte(byte),
            else => try writer.writeByte(byte),
        }
    }
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;
const parser = @import("parser.zig");

test "prometheuz: expose formats a counter with labels" {
    var registry = registry_mod.Registry.init(testing.allocator);
    defer registry.deinit();

    const write_errors = try registry.counter("app_write_errors_total", "Failed write operations", &.{"reason"});
    write_errors.with(&.{"user_create_failed"}).inc();

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const body = try expose(arena_state.allocator(), &registry);

    try testing.expect(std.mem.indexOf(u8, body, "# HELP app_write_errors_total Failed write operations\n") != null);
    try testing.expect(std.mem.indexOf(u8, body, "# TYPE app_write_errors_total counter\n") != null);
    try testing.expect(std.mem.indexOf(u8, body, "app_write_errors_total{reason=\"user_create_failed\"} 1\n") != null);
}

test "prometheuz: expose escapes label values and help text" {
    var registry = registry_mod.Registry.init(testing.allocator);
    defer registry.deinit();

    const errors_by_path = try registry.counter("errors_total", "Errors, e.g. \"bad\" or a\\path", &.{"path"});
    errors_by_path.with(&.{"C:\\DIR\\FILE.TXT"}).inc();

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const body = try expose(arena_state.allocator(), &registry);

    // HELP text is free text, never quoted: a literal '"' needs no escape there.
    try testing.expect(std.mem.indexOf(u8, body, "\"bad\" or a\\\\path") != null);
    try testing.expect(std.mem.indexOf(u8, body, "path=\"C:\\\\DIR\\\\FILE.TXT\"") != null);
}

test "prometheuz: expose then parse round-trips a gauge value" {
    var registry = registry_mod.Registry.init(testing.allocator);
    defer registry.deinit();

    const in_flight = try registry.gauge("in_flight_requests", "Requests being handled", &.{});
    in_flight.with(&.{}).set(7);

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const body = try expose(arena, &registry);
    const parsed = try parser.parse(arena, body);

    try testing.expectEqual(@as(usize, 1), parsed.len);
    try testing.expectEqual(@as(f64, 7), parsed[0].samples[0].value);
    try testing.expectEqual(MetricType.gauge, parsed[0].metric_type);
}
