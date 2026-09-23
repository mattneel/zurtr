//! Behaviour tests: jzon.integer, the two write paths and the read back.
//! Verifies the paths are interchangeable, that the digits match std.fmt, and
//! that a value survives a write and a read unchanged.

const std = @import("std");
const jzon = @import("jzon");

const Sink = jzon.Sink;
const integer = jzon.integer;

/// Write one value both ways and return the bytes, having asserted they agree.
fn bothPaths(fmt_buf: []u8, table_buf: []u8, value: anytype) ![]const u8 {
    var fmt_sink: Sink = .init(fmt_buf);
    try integer.appendFmt(&fmt_sink, value);

    var table_sink: Sink = .init(table_buf);
    try integer.appendTable(&table_sink, value);

    try std.testing.expectEqualStrings(fmt_sink.filled(), table_sink.filled());

    return table_sink.filled();
}

// --------------------------------------------------------- //

test "jzon behaviour: both integer paths write the digits std.fmt writes" {
    const values = [_]i64{ 0, 1, 9, 10, 99, 100, 999, 1000, 65535, 1000000, -1, -9, -10, -12345 };

    for (values) |value| {
        var expected: [32]u8 = undefined;
        const reference = try std.fmt.bufPrint(&expected, "{d}", .{value});

        var fmt_buf: [32]u8 = undefined;
        var table_buf: [32]u8 = undefined;

        try std.testing.expectEqualStrings(reference, try bothPaths(&fmt_buf, &table_buf, value));
    }
}

test "jzon behaviour: both integer paths carry every width the same way" {
    var fmt_buf: [64]u8 = undefined;
    var table_buf: [64]u8 = undefined;

    try std.testing.expectEqualStrings("1", try bothPaths(&fmt_buf, &table_buf, @as(u1, 1)));
    try std.testing.expectEqualStrings("200", try bothPaths(&fmt_buf, &table_buf, @as(u8, 200)));
    try std.testing.expectEqualStrings("-100", try bothPaths(&fmt_buf, &table_buf, @as(i8, -100)));
    try std.testing.expectEqualStrings("40000", try bothPaths(&fmt_buf, &table_buf, @as(u16, 40000)));
    try std.testing.expectEqualStrings("-2000000000", try bothPaths(&fmt_buf, &table_buf, @as(i32, -2000000000)));
    try std.testing.expectEqualStrings("4000000000", try bothPaths(&fmt_buf, &table_buf, @as(u32, 4000000000)));
}

test "jzon behaviour: an integer survives a write and a read unchanged" {
    const values = [_]i64{ 0, 1, -1, 7, -7, 99, 100, 65536, -65536, 1234567890123, -1234567890123 };

    for (values) |value| {
        var buf: [32]u8 = undefined;
        var sink: Sink = .init(&buf);
        try integer.appendTable(&sink, value);

        try std.testing.expectEqual(value, try integer.parse(i64, sink.filled()));
    }
}

test "jzon behaviour: integer parse produces the target type, not a wider one" {
    try std.testing.expectEqual(@as(u8, 7), try integer.parse(u8, "7"));
    try std.testing.expectEqual(@as(i16, -300), try integer.parse(i16, "-300"));
    try std.testing.expectEqual(@as(u32, 4000000000), try integer.parse(u32, "4000000000"));
    try std.testing.expectEqual(@as(i64, -1), try integer.parse(i64, "-1"));
}

test "jzon behaviour: maxDigits is the buffer size a caller can size against" {
    inline for (.{ u8, i8, u16, i16, u32, i32, u64, i64 }) |Value| {
        var buf: [integer.maxDigits(Value)]u8 = undefined;

        var lowest: Sink = .init(&buf);
        try integer.appendTable(&lowest, @as(Value, std.math.minInt(Value)));
        try std.testing.expect(lowest.written() > 0);

        var highest: Sink = .init(&buf);
        try integer.appendTable(&highest, @as(Value, std.math.maxInt(Value)));
        try std.testing.expect(highest.written() > 0);
    }
}

test "jzon behaviour: integer parse reads back what appendFmt wrote" {
    const values = [_]u64{ 0, 1, 42, 1000, std.math.maxInt(u32), std.math.maxInt(u64) };

    for (values) |value| {
        var buf: [32]u8 = undefined;
        var sink: Sink = .init(&buf);
        try integer.appendFmt(&sink, value);

        try std.testing.expectEqual(value, try integer.parse(u64, sink.filled()));
    }
}
