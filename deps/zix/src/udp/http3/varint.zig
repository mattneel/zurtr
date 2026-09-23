//! zix HTTP/3 QUIC variable-length integers (RFC 9000 16, Layer Q).
//!
//! What:
//! - The base codec every QUIC length / id / offset rides on. The top two bits of the first byte
//!   give the base-2 log of the length (1 / 2 / 4 / 8 bytes), the rest is the value in network order.
//! - Proven against the RFC 9000 Appendix A.1 worked decodings in the tests below.

const std = @import("std");

/// A decoded variable-length integer (RFC 9000 16): the value plus how many bytes it occupied.
pub const Varint = struct { value: u64, len: usize };

/// Decode a variable-length integer (RFC 9000 16, Appendix A.1).
///
/// Param:
/// data - []const u8 (the wire bytes, read from offset 0)
///
/// Return:
/// - Varint (value plus consumed length)
/// - error.ZixTruncated when fewer bytes are present than the length prefix demands
pub fn read(data: []const u8) error{ZixTruncated}!Varint {
    if (data.len == 0) return error.ZixTruncated;

    const prefix = data[0] >> 6;
    const length: usize = @as(usize, 1) << @intCast(prefix);

    if (data.len < length) return error.ZixTruncated;

    var value: u64 = data[0] & 0x3f;
    for (1..length) |i| value = (value << 8) + data[i];

    return .{ .value = value, .len = length };
}

/// The minimal number of bytes a value needs as a variable-length integer (RFC 9000 Table 4).
pub fn encodedLen(value: u64) usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    if (value <= 1073741823) return 4;

    return 8;
}

/// Encode a value as a variable-length integer on its minimal length (RFC 9000 16).
///
/// Param:
/// out - []u8 (destination, must hold at least encodedLen(value) bytes)
/// value - u64 (the value to encode)
///
/// Return:
/// - usize (the number of bytes written)
pub fn write(out: []u8, value: u64) usize {
    const length = encodedLen(value);
    const prefix: u8 = switch (length) {
        1 => 0x00,
        2 => 0x40,
        4 => 0x80,
        else => 0xc0,
    };

    for (0..length) |i| out[length - 1 - i] = @truncate(value >> @intCast(8 * i));
    out[0] |= prefix;

    return length;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix http3: RFC 9000 A.1 varint decode" {
    try std.testing.expectEqual(@as(u64, 151288809941952652), (try read(&hexBytes("c2197c5eff14e88c"))).value);
    try std.testing.expectEqual(@as(usize, 8), (try read(&hexBytes("c2197c5eff14e88c"))).len);
    try std.testing.expectEqual(@as(u64, 494878333), (try read(&hexBytes("9d7f3e7d"))).value);
    try std.testing.expectEqual(@as(u64, 15293), (try read(&hexBytes("7bbd"))).value);
    try std.testing.expectEqual(@as(u64, 37), (try read(&hexBytes("25"))).value);

    const non_minimal = try read(&hexBytes("4025"));
    try std.testing.expectEqual(@as(u64, 37), non_minimal.value);
    try std.testing.expectEqual(@as(usize, 2), non_minimal.len);

    try std.testing.expectError(error.ZixTruncated, read(&[_]u8{}));
    try std.testing.expectError(error.ZixTruncated, read(&hexBytes("c2")));
}

test "zix http3: RFC 9000 16 varint encode and length boundaries" {
    var buf: [8]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &hexBytes("25"), buf[0..write(&buf, 37)]);
    try std.testing.expectEqualSlices(u8, &hexBytes("7bbd"), buf[0..write(&buf, 15293)]);
    try std.testing.expectEqualSlices(u8, &hexBytes("9d7f3e7d"), buf[0..write(&buf, 494878333)]);
    try std.testing.expectEqualSlices(u8, &hexBytes("c2197c5eff14e88c"), buf[0..write(&buf, 151288809941952652)]);

    try std.testing.expectEqual(@as(usize, 1), encodedLen(63));
    try std.testing.expectEqual(@as(usize, 2), encodedLen(64));
    try std.testing.expectEqual(@as(usize, 2), encodedLen(16383));
    try std.testing.expectEqual(@as(usize, 4), encodedLen(16384));
    try std.testing.expectEqual(@as(usize, 4), encodedLen(1073741823));
    try std.testing.expectEqual(@as(usize, 8), encodedLen(1073741824));
}
