//! zix utils base32

const std = @import("std");

const charset_base32 = @import("charsets.zig").base32;

// --------------------------------------------------------- //

/// Encode input using base32.
///
/// Note:
/// - Free the result when finished.
///
/// Usage:
/// ```zig
/// const allocator = std.heap.smp_allocator;
/// const encoded = try encode(allocator, "Hello, Zig!");
/// defer allocator.free(encoded);
/// ```
pub fn encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    const out_len = ((input.len + 4) / 5) * 8;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    var input_idx: usize = 0;
    var output_idx: usize = 0;

    while (input_idx < input.len) {
        const b0 = input[input_idx];
        const b1 = if (input_idx + 1 < input.len) input[input_idx + 1] else 0;
        const b2 = if (input_idx + 2 < input.len) input[input_idx + 2] else 0;
        const b3 = if (input_idx + 3 < input.len) input[input_idx + 3] else 0;
        const b4 = if (input_idx + 4 < input.len) input[input_idx + 4] else 0;

        out[output_idx] = charset_base32[b0 >> 3];
        out[output_idx + 1] = charset_base32[((b0 & 0x07) << 2) | (b1 >> 6)];
        out[output_idx + 2] = if (input_idx + 1 < input.len) charset_base32[(b1 >> 1) & 0x1F] else '=';
        out[output_idx + 3] = if (input_idx + 1 < input.len) charset_base32[((b1 & 0x01) << 4) | (b2 >> 4)] else '=';
        out[output_idx + 4] = if (input_idx + 2 < input.len) charset_base32[((b2 & 0x0F) << 1) | (b3 >> 7)] else '=';
        out[output_idx + 5] = if (input_idx + 3 < input.len) charset_base32[(b3 >> 2) & 0x1F] else '=';
        out[output_idx + 6] = if (input_idx + 3 < input.len) charset_base32[((b3 & 0x03) << 3) | (b4 >> 5)] else '=';
        out[output_idx + 7] = if (input_idx + 4 < input.len) charset_base32[b4 & 0x1F] else '=';

        input_idx += 5;
        output_idx += 8;
    }

    return out[0..];
}

/// Decode input using base32.
///
/// Note:
/// - Free the result when finished.
///
/// Usage:
/// ```zig
/// const allocator = std.heap.smp_allocator;
/// const decoded = try decode(allocator, "JBSWY3DPFQQFU2LHEE======");
/// defer allocator.free(decoded);
/// ```
pub fn decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (input.len % 8 != 0) return error.InvalidLength;

    var table: [256]u8 = undefined;
    for (&table) |*v| {
        v.* = 0xFF;
    }

    for (charset_base32, 0..) |char, idx| {
        table[char] = @intCast(idx);
        // Only A-Z map to lowercase
        if (char >= 'A' and char <= 'Z') {
            table[char + 32] = @intCast(idx);
        }
    }

    var valid_len = input.len;
    while (valid_len > 0 and input[valid_len - 1] == '=') {
        valid_len -= 1;
    }
    const out_len = (valid_len * 5) / 8;

    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    var output_idx: usize = 0;
    var input_idx: usize = 0;

    while (input_idx < input.len) {
        var chunk: [8]u8 = undefined;
        for (&chunk) |*v| {
            v.* = 0;
        }

        for (0..8) |chunk_idx| {
            if (input_idx + chunk_idx < input.len and input[input_idx + chunk_idx] != '=') {
                const char_val = input[input_idx + chunk_idx];
                const decoded_val = table[char_val];

                if (decoded_val == 0xFF) return error.InvalidCharacter;
                chunk[chunk_idx] = decoded_val;
            }
        }

        if (output_idx < out_len) out[output_idx] = (chunk[0] << 3) | (chunk[1] >> 2);
        if (output_idx + 1 < out_len) out[output_idx + 1] = ((chunk[1] & 3) << 6) | (chunk[2] << 1) | (chunk[3] >> 4);
        if (output_idx + 2 < out_len) out[output_idx + 2] = ((chunk[3] & 0xF) << 4) | (chunk[4] >> 1);
        if (output_idx + 3 < out_len) out[output_idx + 3] = ((chunk[4] & 1) << 7) | (chunk[5] << 2) | (chunk[6] >> 3);
        if (output_idx + 4 < out_len) out[output_idx + 4] = ((chunk[6] & 7) << 5) | chunk[7];

        output_idx += 5;
        input_idx += 8;
    }

    return out[0..];
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils: base32 encode/decode (RFC 4648 test vectors + roundtrip)" {
    const allocator = std.testing.allocator;

    const test_cases = [_]struct {
        input: []const u8,
        expected_encoded: []const u8,
    }{
        .{ .input = "", .expected_encoded = "" },
        .{ .input = "f", .expected_encoded = "MY======" },
        .{ .input = "fo", .expected_encoded = "MZXQ====" },
        .{ .input = "foo", .expected_encoded = "MZXW6===" },
        .{ .input = "foob", .expected_encoded = "MZXW6YQ=" },
        .{ .input = "fooba", .expected_encoded = "MZXW6YTB" },
        .{ .input = "foobar", .expected_encoded = "MZXW6YTBOI======" },
        .{ .input = "Hello, Zig!", .expected_encoded = "JBSWY3DPFQQFU2LHEE======" },
    };

    for (test_cases) |tc| {
        const encoded = try encode(allocator, tc.input);
        defer allocator.free(encoded);

        try std.testing.expectEqualSlices(u8, tc.expected_encoded, encoded);

        const decoded = try decode(allocator, encoded);
        defer allocator.free(decoded);

        try std.testing.expectEqualSlices(u8, tc.input, decoded);
    }
}

test "zix utils: base32 decode supports lowercase" {
    const allocator = std.testing.allocator;
    const encoded_lower = "jBSWY3DPFQQFU2LHEAYC4MJWEE======";
    const decoded = try decode(allocator, encoded_lower);
    defer allocator.free(decoded);

    try std.testing.expectEqualSlices(u8, "Hello, Zig 0.16!", decoded);
}

test "zix utils: base32 decode invalid character" {
    const allocator = std.testing.allocator;
    const invalid = "JBSWY3DPFQQFU2LHEAYC4MJWEE!!!!!!";

    try std.testing.expectError(error.InvalidCharacter, decode(allocator, invalid));
}

test "zix utils: base32 decode invalid length" {
    const allocator = std.testing.allocator;
    const invalid_len = "JBSWY3DPFQQFU2LHEAYC4MJWEE";

    try std.testing.expectError(error.InvalidLength, decode(allocator, invalid_len));
}
