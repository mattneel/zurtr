//! grpc-timeout header parser.
//! Format: <integer><unit> where unit is H/M/S/m/u/n.

const std = @import("std");

// --------------------------------------------------------- //

/// Parse a grpc-timeout header value to nanoseconds.
/// Unit characters: H (hours), M (minutes), S (seconds),
/// m (milliseconds), u (microseconds), n (nanoseconds).
///
/// Return:
/// - ?u64 (null on invalid format)
pub fn parseTimeout(value: []const u8) ?u64 {
    if (value.len < 2) return null;
    const unit_char = value[value.len - 1];
    const num_str = value[0 .. value.len - 1];
    const num = std.fmt.parseInt(u64, num_str, 10) catch return null;
    return switch (unit_char) {
        'H' => num * 3_600_000_000_000,
        'M' => num * 60_000_000_000,
        'S' => num * 1_000_000_000,
        'm' => num * 1_000_000,
        'u' => num * 1_000,
        'n' => num,
        else => null,
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix grpc: parseTimeout seconds" {
    try std.testing.expectEqual(@as(?u64, 5_000_000_000), parseTimeout("5S"));
}

test "zix grpc: parseTimeout milliseconds" {
    try std.testing.expectEqual(@as(?u64, 100_000_000), parseTimeout("100m"));
}

test "zix grpc: parseTimeout microseconds" {
    try std.testing.expectEqual(@as(?u64, 500_000), parseTimeout("500u"));
}

test "zix grpc: parseTimeout nanoseconds" {
    try std.testing.expectEqual(@as(?u64, 1), parseTimeout("1n"));
}

test "zix grpc: parseTimeout unknown unit returns null" {
    try std.testing.expect(parseTimeout("5X") == null);
}

test "zix grpc: parseTimeout empty returns null" {
    try std.testing.expect(parseTimeout("") == null);
}

test "zix grpc: parseTimeout non-numeric returns null" {
    try std.testing.expect(parseTimeout("abcS") == null);
}
