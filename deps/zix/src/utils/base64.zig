//! zix utils base64

const std = @import("std");

const charset_base64 = @import("charsets.zig").base64;

// --------------------------------------------------------- //

/// Encode input using base64 (RFC 4648).
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
    const out_len = ((input.len + 2) / 3) * 4;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    var input_idx: usize = 0;
    var output_idx: usize = 0;

    while (input_idx < input.len) {
        const b0 = input[input_idx];
        const b1 = if (input_idx + 1 < input.len) input[input_idx + 1] else 0;
        const b2 = if (input_idx + 2 < input.len) input[input_idx + 2] else 0;

        out[output_idx] = charset_base64[b0 >> 2];
        out[output_idx + 1] = charset_base64[((b0 & 0x03) << 4) | (b1 >> 4)];
        out[output_idx + 2] = if (input_idx + 1 < input.len) charset_base64[((b1 & 0x0F) << 2) | (b2 >> 6)] else '=';
        out[output_idx + 3] = if (input_idx + 2 < input.len) charset_base64[b2 & 0x3F] else '=';

        input_idx += 3;
        output_idx += 4;
    }

    return out[0..];
}

/// Decode input using base64 (RFC 4648).
///
/// Note:
/// - Free the result when finished.
///
/// Usage:
/// ```zig
/// const allocator = std.heap.smp_allocator;
/// const decoded = try decode(allocator, "SGVsbG8sIFppZyE=");
/// defer allocator.free(decoded);
/// ```
pub fn decode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (input.len % 4 != 0) return error.InvalidLength;

    var table: [256]u8 = undefined;
    for (&table) |*v| {
        v.* = 0xFF;
    }

    for (charset_base64, 0..) |char, idx| {
        table[char] = @intCast(idx);
    }

    // Count valid characters (exclude padding)
    var valid_len = input.len;
    while (valid_len > 0 and input[valid_len - 1] == '=') {
        valid_len -= 1;
    }
    if (valid_len == 0) return &[_]u8{};

    const out_len = (valid_len * 3) / 4;
    const out = try allocator.alloc(u8, out_len);
    errdefer allocator.free(out);

    var output_idx: usize = 0;
    var input_idx: usize = 0;

    while (input_idx < input.len) {
        var chunk: [4]u8 = undefined;
        for (&chunk) |*v| {
            v.* = 0;
        }

        var valid_chars: usize = 0;
        for (0..4) |i| {
            if (input_idx + i < input.len and input[input_idx + i] != '=') {
                const c = input[input_idx + i];
                const val = table[c];
                if (val == 0xFF) return error.InvalidCharacter;
                chunk[i] = val;
                valid_chars += 1;
            }
        }

        // Decode 4 chars -> 3 bytes (or fewer for padding)
        if (valid_chars >= 2) {
            if (output_idx < out_len) out[output_idx] = (chunk[0] << 2) | (chunk[1] >> 4);
        }
        if (valid_chars >= 3) {
            if (output_idx + 1 < out_len) out[output_idx + 1] = ((chunk[1] & 0x0F) << 4) | (chunk[2] >> 2);
        }
        if (valid_chars >= 4) {
            if (output_idx + 2 < out_len) out[output_idx + 2] = ((chunk[2] & 0x03) << 6) | chunk[3];
        }

        output_idx += 3;
        input_idx += 4;
    }

    return out[0..];
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils: base64 encode/decode (RFC 4648 test vectors + roundtrip)" {
    const allocator = std.testing.allocator;

    const test_cases = [_]struct {
        input: []const u8,
        expected_encoded: []const u8,
    }{
        .{ .input = "", .expected_encoded = "" },
        .{ .input = "f", .expected_encoded = "Zg==" },
        .{ .input = "fo", .expected_encoded = "Zm8=" },
        .{ .input = "foo", .expected_encoded = "Zm9v" },
        .{ .input = "foob", .expected_encoded = "Zm9vYg==" },
        .{ .input = "fooba", .expected_encoded = "Zm9vYmE=" },
        .{ .input = "foobar", .expected_encoded = "Zm9vYmFy" },
        .{ .input = "Hello, Zig!", .expected_encoded = "SGVsbG8sIFppZyE=" },
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

test "zix utils: base64 decode invalid character" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidCharacter, decode(allocator, "!!!!"));
}

test "zix utils: base64 decode invalid length" {
    const allocator = std.testing.allocator;
    const invalid_len = "SGVsbG8sIFppZyAwLjE2IQ="; // length 25, not multiple of 4
    try std.testing.expectError(error.InvalidLength, decode(allocator, invalid_len));
}

test "zix utils: base64 decode handles padding correctly" {
    const allocator = std.testing.allocator;
    const encoded = "Zg==";
    const decoded = try decode(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, "f", decoded);
}

test "zix utils: base64 decode handles no padding" {
    const allocator = std.testing.allocator;
    const encoded = "Zm9v";
    const decoded = try decode(allocator, encoded);
    defer allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, "foo", decoded);
}
