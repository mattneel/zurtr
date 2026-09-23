//! snappy.zig: a pure-Zig snappy block-format encoder.
//!
//! Note:
//! - Literals only, no back-reference matching. Spec-compliant: a snappy
//!   decoder must accept an all-literals stream, so real Prometheus servers
//!   decode this correctly. What is traded away is the compression ratio,
//!   not correctness - the remote_write payloads this driver pushes are
//!   modest (a scrape or a registry snapshot), so this keeps the encoder
//!   small and easy to verify. A real LZ77 matcher can be layered in later
//!   if payload size ever becomes a concern.

const std = @import("std");

const MAX_LITERAL_CHUNK: usize = 60;

/// Encode `input` as a snappy block: a varint uncompressed-length preamble,
/// followed by the input split into literal elements of at most 60 bytes
/// each (so every element tag fits in a single byte).
pub fn encode(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    try writeVarint(&out, allocator, input.len);

    var offset: usize = 0;
    while (offset < input.len) {
        // Explicit usize annotation matters here: @min over a fixed-size
        // array's comptime-bounded .len can otherwise infer a narrower
        // integer type than usize, silently wrapping the << 2 below.
        const chunk_len: usize = @min(input.len - offset, MAX_LITERAL_CHUNK);
        const tag: u8 = @intCast((chunk_len - 1) << 2); // wire type 00 = literal
        try out.append(allocator, tag);
        try out.appendSlice(allocator, input[offset..][0..chunk_len]);
        offset += chunk_len;
    }

    return out.toOwnedSlice(allocator);
}

fn writeVarint(out: *std.ArrayList(u8), allocator: std.mem.Allocator, raw_value: usize) !void {
    var remaining = raw_value;
    while (true) {
        const byte: u8 = @truncate(remaining & 0x7f);
        remaining >>= 7;
        if (remaining == 0) {
            try out.append(allocator, byte);
            return;
        }
        try out.append(allocator, byte | 0x80);
    }
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

/// Literal-only decode, for round-trip self-testing. Not exported: this
/// driver only ever produces snappy, never consumes it (scrape requests
/// identity encoding, see http_client.zig).
fn decodeLiteralsOnly(allocator: std.mem.Allocator, block: []const u8) ![]u8 {
    var pos: usize = 0;
    var shift: u6 = 0;
    var uncompressed_len: usize = 0;
    while (true) {
        const byte = block[pos];
        pos += 1;
        uncompressed_len |= @as(usize, byte & 0x7f) << shift;
        if (byte & 0x80 == 0) break;
        shift += 7;
    }

    var out = try allocator.alloc(u8, uncompressed_len);
    errdefer allocator.free(out);
    var written: usize = 0;

    while (pos < block.len) {
        const tag = block[pos];
        pos += 1;
        if (tag & 0x3 != 0) return error.PrometheuzUnsupportedTag; // only literals (00) expected

        const chunk_len: usize = (tag >> 2) + 1;
        @memcpy(out[written..][0..chunk_len], block[pos..][0..chunk_len]);
        pos += chunk_len;
        written += chunk_len;
    }

    return out;
}

test "prometheuz: snappy empty input" {
    const block = try encode(testing.allocator, "");
    defer testing.allocator.free(block);

    try testing.expectEqualSlices(u8, &.{0x00}, block);
}

test "prometheuz: snappy small input round-trips" {
    const input = "hello prometheus";
    const block = try encode(testing.allocator, input);
    defer testing.allocator.free(block);

    const decoded = try decodeLiteralsOnly(testing.allocator, block);
    defer testing.allocator.free(decoded);

    try testing.expectEqualStrings(input, decoded);
}

test "prometheuz: snappy input over one chunk splits and round-trips" {
    var input: [200]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @intCast(index % 256);

    const block = try encode(testing.allocator, &input);
    defer testing.allocator.free(block);

    const decoded = try decodeLiteralsOnly(testing.allocator, block);
    defer testing.allocator.free(decoded);

    try testing.expectEqualSlices(u8, &input, decoded);
}

test "prometheuz: snappy exactly 60 bytes stays one literal element" {
    var input: [60]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @intCast(index);

    const block = try encode(testing.allocator, &input);
    defer testing.allocator.free(block);

    // preamble varint(60) = [0x3c] (fits in one byte), then one tag byte
    // ((60-1)<<2)=0xec, then the 60 literal bytes: total 62 bytes.
    try testing.expectEqual(@as(usize, 62), block.len);
    try testing.expectEqual(@as(u8, 0x3c), block[0]);
    try testing.expectEqual(@as(u8, 0xec), block[1]);
}
