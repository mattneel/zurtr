//! Edge tests: jzon.integer at its bounds.
//! Verifies the extremes of each width on both write paths, the exact-fit and
//! one-byte-short buffers, and every text a number can be read from wrongly.

const std = @import("std");
const jzon = @import("jzon");

const Sink = jzon.Sink;
const integer = jzon.integer;

// --------------------------------------------------------- //

test "jzon edge: both integer paths carry the extremes of every width" {
    inline for (.{ u1, u8, i8, u16, i16, u32, i32, u64, i64, u128, i128 }) |Value| {
        const extremes = [_]Value{ std.math.minInt(Value), std.math.maxInt(Value), 0 };

        for (extremes) |value| {
            var expected: [64]u8 = undefined;
            const reference = try std.fmt.bufPrint(&expected, "{d}", .{value});

            var fmt_buf: [64]u8 = undefined;
            var fmt_sink: Sink = .init(&fmt_buf);
            try integer.appendFmt(&fmt_sink, value);

            var table_buf: [64]u8 = undefined;
            var table_sink: Sink = .init(&table_buf);
            try integer.appendTable(&table_sink, value);

            try std.testing.expectEqualStrings(reference, fmt_sink.filled());
            try std.testing.expectEqualStrings(reference, table_sink.filled());
        }
    }
}

test "jzon edge: an integer fits a buffer of exactly its digit count" {
    var exact: [3]u8 = undefined;
    var fits: Sink = .init(&exact);
    try integer.appendTable(&fits, @as(u8, 255));
    try std.testing.expectEqualStrings("255", fits.filled());
    try std.testing.expectEqual(@as(usize, 0), fits.remaining());

    var exact_fmt: [4]u8 = undefined;
    var fits_fmt: Sink = .init(&exact_fmt);
    try integer.appendFmt(&fits_fmt, @as(i8, -128));
    try std.testing.expectEqualStrings("-128", fits_fmt.filled());
}

test "jzon edge: an integer one digit too long is refused by both paths" {
    var table_buf: [2]u8 = undefined;
    var table_sink: Sink = .init(&table_buf);
    try std.testing.expectError(error.NoSpaceLeft, integer.appendTable(&table_sink, @as(u16, 255)));
    try std.testing.expectEqual(@as(usize, 0), table_sink.written());

    var fmt_buf: [2]u8 = undefined;
    var fmt_sink: Sink = .init(&fmt_buf);
    try std.testing.expectError(error.NoSpaceLeft, integer.appendFmt(&fmt_sink, @as(u16, 255)));
    try std.testing.expectEqual(@as(usize, 0), fmt_sink.written());
}

test "jzon edge: both integer paths refuse a full buffer" {
    var buf: [2]u8 = undefined;

    var table_sink: Sink = .init(&buf);
    try table_sink.bytes("ab");
    try std.testing.expectError(error.NoSpaceLeft, integer.appendTable(&table_sink, @as(u8, 0)));

    var fmt_sink: Sink = .init(&buf);
    try fmt_sink.bytes("ab");
    try std.testing.expectError(error.NoSpaceLeft, integer.appendFmt(&fmt_sink, @as(u8, 0)));
}

test "jzon edge: integer parse carries the extremes of its target type" {
    try std.testing.expectEqual(@as(u8, 0), try integer.parse(u8, "0"));
    try std.testing.expectEqual(@as(u8, 255), try integer.parse(u8, "255"));
    try std.testing.expectEqual(@as(i8, 127), try integer.parse(i8, "127"));
    try std.testing.expectEqual(@as(i8, -128), try integer.parse(i8, "-128"));
    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), try integer.parse(u64, "18446744073709551615"));
    try std.testing.expectEqual(@as(i64, std.math.minInt(i64)), try integer.parse(i64, "-9223372036854775808"));
}

test "jzon edge: integer parse refuses a value one past the target type" {
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u8, "256"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(i8, "128"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(i8, "-129"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u64, "18446744073709551616"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(i64, "9223372036854775808"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(i64, "-9223372036854775809"));
}

test "jzon edge: integer parse refuses a negative value for an unsigned type" {
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u8, "-1"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u64, "-0"));
}

test "jzon edge: integer parse refuses a leading zero RFC 8259 does not allow" {
    try std.testing.expectEqual(@as(u32, 0), try integer.parse(u32, "0"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u32, "00"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u32, "007"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(i32, "-01"));
}

test "jzon edge: integer parse refuses text that is not a whole number" {
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u32, ""));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u32, "-"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u32, "+1"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u32, " 1"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u32, "1 "));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u32, "1.0"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u32, "1e2"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u32, "0x10"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(u32, "1_000"));
    try std.testing.expectError(error.JzonBadNumber, integer.parse(i32, "--1"));
}

test "jzon edge: maxDigits bounds the widest value of every width" {
    inline for (.{ u1, u8, i8, u16, i16, u32, i32, u64, i64, u128, i128 }) |Value| {
        var buf: [integer.maxDigits(Value)]u8 = undefined;

        var lowest: Sink = .init(&buf);
        try integer.appendTable(&lowest, @as(Value, std.math.minInt(Value)));
        try std.testing.expect(lowest.written() <= integer.maxDigits(Value));

        var highest: Sink = .init(&buf);
        try integer.appendTable(&highest, @as(Value, std.math.maxInt(Value)));
        try std.testing.expect(highest.written() <= integer.maxDigits(Value));
    }
}
