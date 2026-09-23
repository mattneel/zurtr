//! jzon integers, both directions.
//!
//! What:
//! - Two ways to write an integer as JSON text. `appendFmt` hands the value to
//!   `std.fmt`, `appendTable` writes the digits straight into the sink. They emit
//!   identical bytes, so a caller picks on cost alone.
//! - One way to read one back, with the target type's range enforced.
//!
//! Note:
//! - The digit conversion is the same in both write paths: two digits per
//!   iteration out of `std.fmt.digits2`. What separates them is the work around
//!   it. `appendFmt` builds a `std.Io.Writer` per call and runs the width and
//!   alignment pass before the digits land. `appendTable` runs the loop over a
//!   stack buffer and copies once.

const std = @import("std");

const Sink = @import("sink.zig").Sink;

/// How writing an integer can fail. Nothing is allocated, so a full buffer is
/// all of it.
pub const WriteError = @import("sink.zig").Error;

/// How reading an integer can fail. A value the target type cannot hold reports
/// the same way a malformed one does: the text is not a number this field takes.
pub const ReadError = error{JzonBadNumber};

/// Upper bound on the decimal length of any value of T, sign included.
///
/// Note:
/// - log10(2) is just under 1/3, so bits/3 + 1 never under-counts the digits.
///
/// Param:
/// T - type (comptime, the integer type to bound)
///
/// Return:
/// - comptime_int (the widest decimal length a value of T can occupy)
pub fn maxDigits(comptime T: type) comptime_int {
    const info = intInfo(T);
    const sign: comptime_int = if (info.signedness == .signed) 1 else 0;
    const magnitude_bits: comptime_int = @as(comptime_int, info.bits) - sign;

    return @max(magnitude_bits, 1) / 3 + 1 + sign;
}

/// Write an integer through `std.fmt`.
///
/// Note:
/// - Formats into the sink's unwritten tail, so the digits are not copied twice.
///
/// Param:
/// sink - *Sink (where the digits go)
/// value - anytype (any integer width, signed or unsigned)
///
/// Return:
/// - void
/// - error.NoSpaceLeft when the digits do not fit
pub fn appendFmt(sink: *Sink, value: anytype) WriteError!void {
    // Reject a non-integer at compile time, so both write paths take the same set
    // of types.
    _ = intInfo(@TypeOf(value));

    const printed = std.fmt.bufPrint(sink.tail(), "{d}", .{value}) catch
        return error.NoSpaceLeft;

    try sink.commit(printed.len);
}

/// Write an integer straight into the sink.
///
/// Note:
/// - `@abs` on a signed value yields the unsigned type of the same width, so the
///   most negative value converts without overflowing.
/// - The running value is held at 8 bits or wider whatever T is, so a narrow
///   field type still compares against the 100 and 10 the loop needs.
///
/// Param:
/// sink - *Sink (where the digits go)
/// value - anytype (any integer width, signed or unsigned)
///
/// Return:
/// - void
/// - error.NoSpaceLeft when the digits do not fit
pub fn appendTable(sink: *Sink, value: anytype) WriteError!void {
    const Value = @TypeOf(value);
    const info = intInfo(Value);
    const Magnitude = @Int(.unsigned, @max(info.bits, 8));

    var digits: [maxDigits(Value)]u8 = undefined;
    var start: usize = digits.len;
    var rest: Magnitude = @abs(value);

    while (rest >= 100) : (rest = @divTrunc(rest, 100)) {
        start -= 2;
        digits[start..][0..2].* = std.fmt.digits2(@intCast(rest % 100));
    }

    if (rest < 10) {
        start -= 1;
        digits[start] = '0' + @as(u8, @intCast(rest));
    } else {
        start -= 2;
        digits[start..][0..2].* = std.fmt.digits2(@intCast(rest));
    }

    if (info.signedness == .signed and value < 0) {
        start -= 1;
        digits[start] = '-';
    }

    try sink.bytes(digits[start..]);
}

/// Read an integer out of a number token's bytes.
///
/// Note:
/// - RFC 8259 6 allows a leading zero only when it is the whole integer part, so
///   `007` is rejected rather than read as 7.
/// - A minus sign against an unsigned target is rejected outright, `-0` included,
///   so the sign is a type error rather than a value that happens to fit.
/// - A fraction or an exponent is not an integer, so `1.0` and `1e2` are
///   rejected here. A float field reads those through the float path.
///
/// Param:
/// T - type (comptime, the integer type to produce)
/// text - []const u8 (the number token's bytes, as `Cursor.numberSpan` hands them back)
///
/// Return:
/// - T (the value)
/// - error.JzonBadNumber when the text is not an integer, or holds one T cannot carry
pub fn parse(comptime T: type, text: []const u8) ReadError!T {
    const info = intInfo(T);
    const Magnitude = @Int(.unsigned, @max(info.bits, 8));
    const Wide = @Int(.signed, @max(info.bits, 8) + 1);

    if (text.len == 0) return error.JzonBadNumber;

    const negative = text[0] == '-';
    const digits = if (negative) text[1..] else text;

    if (negative and info.signedness == .unsigned) return error.JzonBadNumber;
    if (digits.len == 0) return error.JzonBadNumber;
    if (digits[0] == '0' and digits.len > 1) return error.JzonBadNumber;

    var magnitude: Magnitude = 0;
    for (digits) |byte| {
        const digit = byte -% '0';
        if (digit > 9) return error.JzonBadNumber;

        const scaled = @mulWithOverflow(magnitude, 10);
        if (scaled[1] != 0) return error.JzonBadNumber;

        const summed = @addWithOverflow(scaled[0], @as(Magnitude, digit));
        if (summed[1] != 0) return error.JzonBadNumber;

        magnitude = summed[0];
    }

    if (!negative) return std.math.cast(T, magnitude) orelse error.JzonBadNumber;

    return std.math.cast(T, -@as(Wide, magnitude)) orelse error.JzonBadNumber;
}

/// The integer facts of T, or a compile error naming the type that is not one.
///
/// Note:
/// - Inline so the fields stay comptime-known at the call site, which is what
///   lets a width be built from `info.bits`.
inline fn intInfo(comptime T: type) std.builtin.Type.Int {
    return switch (@typeInfo(T)) {
        .int => |info| info,
        else => @compileError("jzon integer: " ++ @typeName(T) ++ " is not an integer"),
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Write one value both ways and assert the two agree with `expected`.
fn expectBothPaths(expected: []const u8, value: anytype) !void {
    var fmt_buf: [64]u8 = undefined;
    var fmt_sink: Sink = .init(&fmt_buf);
    try appendFmt(&fmt_sink, value);

    var table_buf: [64]u8 = undefined;
    var table_sink: Sink = .init(&table_buf);
    try appendTable(&table_sink, value);

    try std.testing.expectEqualStrings(expected, fmt_sink.filled());
    try std.testing.expectEqualStrings(expected, table_sink.filled());
}

test "jzon: both integer paths write the same digits" {
    try expectBothPaths("0", @as(u64, 0));
    try expectBothPaths("7", @as(u64, 7));
    try expectBothPaths("42", @as(u64, 42));
    try expectBothPaths("100", @as(u64, 100));
    try expectBothPaths("12345", @as(u32, 12345));
    try expectBothPaths("-1", @as(i32, -1));
    try expectBothPaths("-9876", @as(i32, -9876));
}

test "jzon: both integer paths write the extremes of their width" {
    try expectBothPaths("255", @as(u8, 255));
    try expectBothPaths("127", @as(i8, 127));
    try expectBothPaths("-128", @as(i8, -128));
    try expectBothPaths("18446744073709551615", @as(u64, std.math.maxInt(u64)));
    try expectBothPaths("9223372036854775807", @as(i64, std.math.maxInt(i64)));
    try expectBothPaths("-9223372036854775808", @as(i64, std.math.minInt(i64)));
}

test "jzon: maxDigits bounds every width it is asked about" {
    try std.testing.expect(maxDigits(u8) >= "255".len);
    try std.testing.expect(maxDigits(i8) >= "-128".len);
    try std.testing.expect(maxDigits(u64) >= "18446744073709551615".len);
    try std.testing.expect(maxDigits(i64) >= "-9223372036854775808".len);
    try std.testing.expect(maxDigits(u1) >= "1".len);
}

test "jzon: integer parse reads back what either path wrote" {
    const values = [_]i64{ 0, 1, -1, 9, 10, 99, 100, 12345, -12345, std.math.maxInt(i64), std.math.minInt(i64) };

    for (values) |value| {
        var buf: [32]u8 = undefined;
        var sink: Sink = .init(&buf);
        try appendTable(&sink, value);

        try std.testing.expectEqual(value, try parse(i64, sink.filled()));
    }
}

test "jzon: integer parse enforces the target type's range" {
    try std.testing.expectEqual(@as(u8, 255), try parse(u8, "255"));
    try std.testing.expectError(error.JzonBadNumber, parse(u8, "256"));
    try std.testing.expectError(error.JzonBadNumber, parse(u8, "-1"));
    try std.testing.expectEqual(@as(i8, -128), try parse(i8, "-128"));
    try std.testing.expectError(error.JzonBadNumber, parse(i8, "-129"));
    try std.testing.expectError(error.JzonBadNumber, parse(u64, "18446744073709551616"));
}

test "jzon: integer parse rejects text no integer can be read from" {
    try std.testing.expectError(error.JzonBadNumber, parse(u32, ""));
    try std.testing.expectError(error.JzonBadNumber, parse(u32, "-"));
    try std.testing.expectError(error.JzonBadNumber, parse(u32, "007"));
    try std.testing.expectError(error.JzonBadNumber, parse(u32, "1.0"));
    try std.testing.expectError(error.JzonBadNumber, parse(u32, "1e2"));
    try std.testing.expectError(error.JzonBadNumber, parse(u32, "12a"));
    try std.testing.expectError(error.JzonBadNumber, parse(i32, "--1"));
}
