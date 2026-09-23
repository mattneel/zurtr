//! zix HTTP/3 QPACK / HPACK Huffman decoder (RFC 7541 Appendix B).
//!
//! What:
//! - Decodes the canonical Huffman code QPACK shares with HPACK, used for string literals (a request
//!   :path arrives Huffman-encoded). The 256-symbol code table is fixed by the RFC.
//! - The decoder walks the bitstream most-significant-bit first, emitting a symbol the moment the
//!   accumulated bits match a code of that exact length. Trailing all-ones bits are EOS padding and
//!   are ignored. Validated against the RFC 7541 C.4 worked example in the test below.

const std = @import("std");

const Code = struct { code: u32, bits: u8 };

/// The RFC 7541 Appendix B code table, indexed by byte value (0..255).
const table = [256]Code{
    .{ .code = 0x1ff8, .bits = 13 },    .{ .code = 0x7fffd8, .bits = 23 },   .{ .code = 0xfffffe2, .bits = 28 },  .{ .code = 0xfffffe3, .bits = 28 },
    .{ .code = 0xfffffe4, .bits = 28 }, .{ .code = 0xfffffe5, .bits = 28 },  .{ .code = 0xfffffe6, .bits = 28 },  .{ .code = 0xfffffe7, .bits = 28 },
    .{ .code = 0xfffffe8, .bits = 28 }, .{ .code = 0xffffea, .bits = 24 },   .{ .code = 0x3ffffffc, .bits = 30 }, .{ .code = 0xfffffe9, .bits = 28 },
    .{ .code = 0xfffffea, .bits = 28 }, .{ .code = 0x3ffffffd, .bits = 30 }, .{ .code = 0xfffffeb, .bits = 28 },  .{ .code = 0xfffffec, .bits = 28 },
    .{ .code = 0xfffffed, .bits = 28 }, .{ .code = 0xfffffee, .bits = 28 },  .{ .code = 0xfffffef, .bits = 28 },  .{ .code = 0xffffff0, .bits = 28 },
    .{ .code = 0xffffff1, .bits = 28 }, .{ .code = 0xffffff2, .bits = 28 },  .{ .code = 0x3ffffffe, .bits = 30 }, .{ .code = 0xffffff3, .bits = 28 },
    .{ .code = 0xffffff4, .bits = 28 }, .{ .code = 0xffffff5, .bits = 28 },  .{ .code = 0xffffff6, .bits = 28 },  .{ .code = 0xffffff7, .bits = 28 },
    .{ .code = 0xffffff8, .bits = 28 }, .{ .code = 0xffffff9, .bits = 28 },  .{ .code = 0xffffffa, .bits = 28 },  .{ .code = 0xffffffb, .bits = 28 },
    .{ .code = 0x14, .bits = 6 },       .{ .code = 0x3f8, .bits = 10 },      .{ .code = 0x3f9, .bits = 10 },      .{ .code = 0xffa, .bits = 12 },
    .{ .code = 0x1ff9, .bits = 13 },    .{ .code = 0x15, .bits = 6 },        .{ .code = 0xf8, .bits = 8 },        .{ .code = 0x7fa, .bits = 11 },
    .{ .code = 0x3fa, .bits = 10 },     .{ .code = 0x3fb, .bits = 10 },      .{ .code = 0xf9, .bits = 8 },        .{ .code = 0x7fb, .bits = 11 },
    .{ .code = 0xfa, .bits = 8 },       .{ .code = 0x16, .bits = 6 },        .{ .code = 0x17, .bits = 6 },        .{ .code = 0x18, .bits = 6 },
    .{ .code = 0x0, .bits = 5 },        .{ .code = 0x1, .bits = 5 },         .{ .code = 0x2, .bits = 5 },         .{ .code = 0x19, .bits = 6 },
    .{ .code = 0x1a, .bits = 6 },       .{ .code = 0x1b, .bits = 6 },        .{ .code = 0x1c, .bits = 6 },        .{ .code = 0x1d, .bits = 6 },
    .{ .code = 0x1e, .bits = 6 },       .{ .code = 0x1f, .bits = 6 },        .{ .code = 0x5c, .bits = 7 },        .{ .code = 0xfb, .bits = 8 },
    .{ .code = 0x7ffc, .bits = 15 },    .{ .code = 0x20, .bits = 6 },        .{ .code = 0xffb, .bits = 12 },      .{ .code = 0x3fc, .bits = 10 },
    .{ .code = 0x1ffa, .bits = 13 },    .{ .code = 0x21, .bits = 6 },        .{ .code = 0x5d, .bits = 7 },        .{ .code = 0x5e, .bits = 7 },
    .{ .code = 0x5f, .bits = 7 },       .{ .code = 0x60, .bits = 7 },        .{ .code = 0x61, .bits = 7 },        .{ .code = 0x62, .bits = 7 },
    .{ .code = 0x63, .bits = 7 },       .{ .code = 0x64, .bits = 7 },        .{ .code = 0x65, .bits = 7 },        .{ .code = 0x66, .bits = 7 },
    .{ .code = 0x67, .bits = 7 },       .{ .code = 0x68, .bits = 7 },        .{ .code = 0x69, .bits = 7 },        .{ .code = 0x6a, .bits = 7 },
    .{ .code = 0x6b, .bits = 7 },       .{ .code = 0x6c, .bits = 7 },        .{ .code = 0x6d, .bits = 7 },        .{ .code = 0x6e, .bits = 7 },
    .{ .code = 0x6f, .bits = 7 },       .{ .code = 0x70, .bits = 7 },        .{ .code = 0x71, .bits = 7 },        .{ .code = 0x72, .bits = 7 },
    .{ .code = 0xfc, .bits = 8 },       .{ .code = 0x73, .bits = 7 },        .{ .code = 0xfd, .bits = 8 },        .{ .code = 0x1ffb, .bits = 13 },
    .{ .code = 0x7fff0, .bits = 19 },   .{ .code = 0x1ffc, .bits = 13 },     .{ .code = 0x3ffc, .bits = 14 },     .{ .code = 0x22, .bits = 6 },
    .{ .code = 0x7ffd, .bits = 15 },    .{ .code = 0x3, .bits = 5 },         .{ .code = 0x23, .bits = 6 },        .{ .code = 0x4, .bits = 5 },
    .{ .code = 0x24, .bits = 6 },       .{ .code = 0x5, .bits = 5 },         .{ .code = 0x25, .bits = 6 },        .{ .code = 0x26, .bits = 6 },
    .{ .code = 0x27, .bits = 6 },       .{ .code = 0x6, .bits = 5 },         .{ .code = 0x74, .bits = 7 },        .{ .code = 0x75, .bits = 7 },
    .{ .code = 0x28, .bits = 6 },       .{ .code = 0x29, .bits = 6 },        .{ .code = 0x2a, .bits = 6 },        .{ .code = 0x7, .bits = 5 },
    .{ .code = 0x2b, .bits = 6 },       .{ .code = 0x76, .bits = 7 },        .{ .code = 0x2c, .bits = 6 },        .{ .code = 0x8, .bits = 5 },
    .{ .code = 0x9, .bits = 5 },        .{ .code = 0x2d, .bits = 6 },        .{ .code = 0x77, .bits = 7 },        .{ .code = 0x78, .bits = 7 },
    .{ .code = 0x79, .bits = 7 },       .{ .code = 0x7a, .bits = 7 },        .{ .code = 0x7b, .bits = 7 },        .{ .code = 0x7ffe, .bits = 15 },
    .{ .code = 0x7fc, .bits = 11 },     .{ .code = 0x3ffd, .bits = 14 },     .{ .code = 0x1ffd, .bits = 13 },     .{ .code = 0xffffffc, .bits = 28 },
    .{ .code = 0xfffe6, .bits = 20 },   .{ .code = 0x3fffd2, .bits = 22 },   .{ .code = 0xfffe7, .bits = 20 },    .{ .code = 0xfffe8, .bits = 20 },
    .{ .code = 0x3fffd3, .bits = 22 },  .{ .code = 0x3fffd4, .bits = 22 },   .{ .code = 0x3fffd5, .bits = 22 },   .{ .code = 0x7fffd9, .bits = 23 },
    .{ .code = 0x3fffd6, .bits = 22 },  .{ .code = 0x7fffda, .bits = 23 },   .{ .code = 0x7fffdb, .bits = 23 },   .{ .code = 0x7fffdc, .bits = 23 },
    .{ .code = 0x7fffdd, .bits = 23 },  .{ .code = 0x7fffde, .bits = 23 },   .{ .code = 0xffffeb, .bits = 24 },   .{ .code = 0x7fffdf, .bits = 23 },
    .{ .code = 0xffffec, .bits = 24 },  .{ .code = 0xffffed, .bits = 24 },   .{ .code = 0x3fffd7, .bits = 22 },   .{ .code = 0x7fffe0, .bits = 23 },
    .{ .code = 0xffffee, .bits = 24 },  .{ .code = 0x7fffe1, .bits = 23 },   .{ .code = 0x7fffe2, .bits = 23 },   .{ .code = 0x7fffe3, .bits = 23 },
    .{ .code = 0x7fffe4, .bits = 23 },  .{ .code = 0x1fffdc, .bits = 21 },   .{ .code = 0x3fffd8, .bits = 22 },   .{ .code = 0x7fffe5, .bits = 23 },
    .{ .code = 0x3fffd9, .bits = 22 },  .{ .code = 0x7fffe6, .bits = 23 },   .{ .code = 0x7fffe7, .bits = 23 },   .{ .code = 0xffffef, .bits = 24 },
    .{ .code = 0x3fffda, .bits = 22 },  .{ .code = 0x1fffdd, .bits = 21 },   .{ .code = 0xfffe9, .bits = 20 },    .{ .code = 0x3fffdb, .bits = 22 },
    .{ .code = 0x3fffdc, .bits = 22 },  .{ .code = 0x7fffe8, .bits = 23 },   .{ .code = 0x7fffe9, .bits = 23 },   .{ .code = 0x1fffde, .bits = 21 },
    .{ .code = 0x7fffea, .bits = 23 },  .{ .code = 0x3fffdd, .bits = 22 },   .{ .code = 0x3fffde, .bits = 22 },   .{ .code = 0xfffff0, .bits = 24 },
    .{ .code = 0x1fffdf, .bits = 21 },  .{ .code = 0x3fffdf, .bits = 22 },   .{ .code = 0x7fffeb, .bits = 23 },   .{ .code = 0x7fffec, .bits = 23 },
    .{ .code = 0x1fffe0, .bits = 21 },  .{ .code = 0x1fffe1, .bits = 21 },   .{ .code = 0x3fffe0, .bits = 22 },   .{ .code = 0x1fffe2, .bits = 21 },
    .{ .code = 0x7fffed, .bits = 23 },  .{ .code = 0x3fffe1, .bits = 22 },   .{ .code = 0x7fffee, .bits = 23 },   .{ .code = 0x7fffef, .bits = 23 },
    .{ .code = 0xfffea, .bits = 20 },   .{ .code = 0x3fffe2, .bits = 22 },   .{ .code = 0x3fffe3, .bits = 22 },   .{ .code = 0x3fffe4, .bits = 22 },
    .{ .code = 0x7ffff0, .bits = 23 },  .{ .code = 0x3fffe5, .bits = 22 },   .{ .code = 0x3fffe6, .bits = 22 },   .{ .code = 0x7ffff1, .bits = 23 },
    .{ .code = 0x3ffffe0, .bits = 26 }, .{ .code = 0x3ffffe1, .bits = 26 },  .{ .code = 0xfffeb, .bits = 20 },    .{ .code = 0x7fff1, .bits = 19 },
    .{ .code = 0x3fffe7, .bits = 22 },  .{ .code = 0x7ffff2, .bits = 23 },   .{ .code = 0x3fffe8, .bits = 22 },   .{ .code = 0x1ffffec, .bits = 25 },
    .{ .code = 0x3ffffe2, .bits = 26 }, .{ .code = 0x3ffffe3, .bits = 26 },  .{ .code = 0x3ffffe4, .bits = 26 },  .{ .code = 0x7ffffde, .bits = 27 },
    .{ .code = 0x7ffffdf, .bits = 27 }, .{ .code = 0x3ffffe5, .bits = 26 },  .{ .code = 0xfffff1, .bits = 24 },   .{ .code = 0x1ffffed, .bits = 25 },
    .{ .code = 0x7fff2, .bits = 19 },   .{ .code = 0x1fffe3, .bits = 21 },   .{ .code = 0x3ffffe6, .bits = 26 },  .{ .code = 0x7ffffe0, .bits = 27 },
    .{ .code = 0x7ffffe1, .bits = 27 }, .{ .code = 0x3ffffe7, .bits = 26 },  .{ .code = 0x7ffffe2, .bits = 27 },  .{ .code = 0xfffff2, .bits = 24 },
    .{ .code = 0x1fffe4, .bits = 21 },  .{ .code = 0x1fffe5, .bits = 21 },   .{ .code = 0x3ffffe8, .bits = 26 },  .{ .code = 0x3ffffe9, .bits = 26 },
    .{ .code = 0xffffffd, .bits = 28 }, .{ .code = 0x7ffffe3, .bits = 27 },  .{ .code = 0x7ffffe4, .bits = 27 },  .{ .code = 0x7ffffe5, .bits = 27 },
    .{ .code = 0xfffec, .bits = 20 },   .{ .code = 0xfffff3, .bits = 24 },   .{ .code = 0xfffed, .bits = 20 },    .{ .code = 0x1fffe6, .bits = 21 },
    .{ .code = 0x3fffe9, .bits = 22 },  .{ .code = 0x1fffe7, .bits = 21 },   .{ .code = 0x1fffe8, .bits = 21 },   .{ .code = 0x7ffff3, .bits = 23 },
    .{ .code = 0x3fffea, .bits = 22 },  .{ .code = 0x3fffeb, .bits = 22 },   .{ .code = 0x1ffffee, .bits = 25 },  .{ .code = 0x1ffffef, .bits = 25 },
    .{ .code = 0xfffff4, .bits = 24 },  .{ .code = 0xfffff5, .bits = 24 },   .{ .code = 0x3ffffea, .bits = 26 },  .{ .code = 0x7ffff4, .bits = 23 },
    .{ .code = 0x3ffffeb, .bits = 26 }, .{ .code = 0x7ffffe6, .bits = 27 },  .{ .code = 0x3ffffec, .bits = 26 },  .{ .code = 0x3ffffed, .bits = 26 },
    .{ .code = 0x7ffffe7, .bits = 27 }, .{ .code = 0x7ffffe8, .bits = 27 },  .{ .code = 0x7ffffe9, .bits = 27 },  .{ .code = 0x7ffffea, .bits = 27 },
    .{ .code = 0x7ffffeb, .bits = 27 }, .{ .code = 0xffffffe, .bits = 28 },  .{ .code = 0x7ffffec, .bits = 27 },  .{ .code = 0x7ffffed, .bits = 27 },
    .{ .code = 0x7ffffee, .bits = 27 }, .{ .code = 0x7ffffef, .bits = 27 },  .{ .code = 0x7fffff0, .bits = 27 },  .{ .code = 0x3ffffee, .bits = 26 },
};

/// The longest code length in the RFC 7541 Appendix B table.
const max_code_bits = 30;

/// One table entry ordered into its bits-length bucket: decode already knows the exact bit length it
/// just accumulated, so it only ever needs to compare against codes of that one length, never all 256.
const BucketEntry = struct { code: u32, sym: u8 };

/// `table` regrouped by code length: `sorted[bits_start[bits]..bits_start[bits + 1]]` holds every
/// entry whose code is exactly `bits` bits long. Built once at compile time (a histogram-sort of the
/// 256-entry table), so decode pays nothing for it at runtime.
const HuffmanIndex = struct {
    sorted: [table.len]BucketEntry,
    bits_start: [max_code_bits + 2]usize,
};

const huffman_index: HuffmanIndex = blk: {
    var counts: [max_code_bits + 1]usize = @splat(0);
    for (table) |entry| counts[entry.bits] += 1;

    var bits_start: [max_code_bits + 2]usize = undefined;
    bits_start[0] = 0;
    for (0..max_code_bits + 1) |bits| bits_start[bits + 1] = bits_start[bits] + counts[bits];

    var sorted: [table.len]BucketEntry = undefined;
    var cursor = bits_start;
    for (table, 0..) |entry, sym| {
        sorted[cursor[entry.bits]] = .{ .code = entry.code, .sym = @intCast(sym) };
        cursor[entry.bits] += 1;
    }

    break :blk .{ .sorted = sorted, .bits_start = bits_start };
};

/// Decode a Huffman-encoded string (RFC 7541 Appendix B) into `out`. Returns the decoded length, or
/// null if the output buffer is too small or a code does not resolve.
///
/// Param:
/// out - []u8 (destination for the decoded bytes)
/// input - []const u8 (the Huffman-encoded bytes)
///
/// Return:
/// - ?usize (decoded length, or null on overflow / a malformed code)
pub fn decode(out: []u8, input: []const u8) ?usize {
    var acc: u32 = 0;
    var nbits: u8 = 0;
    var out_len: usize = 0;

    for (input) |byte| {
        var bit: u8 = 8;
        while (bit > 0) {
            bit -= 1;
            acc = (acc << 1) | @as(u32, (byte >> @intCast(bit)) & 1);
            nbits += 1;

            // A code wider than the longest (30 bits) without a match is malformed. Checked before the
            // bucket lookup below, not after: bits_start only has entries through max_code_bits + 1.
            if (nbits > max_code_bits) return null;

            const bucket = huffman_index.sorted[huffman_index.bits_start[nbits]..huffman_index.bits_start[nbits + 1]];
            for (bucket) |entry| {
                if (entry.code == acc) {
                    if (out_len >= out.len) return null;
                    out[out_len] = entry.sym;
                    out_len += 1;
                    acc = 0;
                    nbits = 0;
                    break;
                }
            }
        }
    }

    // Trailing bits (fewer than 8) must be the all-ones EOS padding, which leaves no pending symbol.
    return out_len;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix http3: RFC 7541 C.4 Huffman decode of www.example.com" {
    const encoded = hexBytes("f1e3c2e5f23a6ba0ab90f4ff");
    var out: [64]u8 = undefined;
    const len = decode(&out, &encoded).?;

    try std.testing.expectEqualSlices(u8, "www.example.com", out[0..len]);
}

test "zix http3: Huffman decode of a path with digits and symbols" {
    // "/baseline2?a=20&b=22" Huffman-encoded (every byte is a short code).
    const encoded = hexBytes("6231a0b41aa28bfc1c0207c470085f");
    var out: [64]u8 = undefined;
    const len = decode(&out, &encoded).?;

    try std.testing.expectEqualSlices(u8, "/baseline2?a=20&b=22", out[0..len]);
}

test "zix http3: Huffman decode round-trips every symbol at every code length in the table" {
    // Every one of the 256 symbols, individually encoded then padded with the all-ones EOS pattern to
    // a byte boundary, must decode back to itself. This exercises every bits_start bucket boundary the
    // table lookup relies on (5 through 30 bits), not just the handful of lengths the two tests above
    // happen to touch.
    for (table, 0..) |entry, sym| {
        var bytes: [8]u8 = @splat(0xff);
        var bit_pos: usize = 0;

        var bits_left = entry.bits;
        while (bits_left > 0) {
            bits_left -= 1;

            const bit: u1 = @truncate((entry.code >> @intCast(bits_left)) & 1);
            const byte_idx = bit_pos / 8;
            const bit_idx: u3 = @intCast(7 - bit_pos % 8);
            if (bit == 1) bytes[byte_idx] |= @as(u8, 1) << bit_idx else bytes[byte_idx] &= ~(@as(u8, 1) << bit_idx);

            bit_pos += 1;
        }

        const total_bytes = (bit_pos + 7) / 8;

        var out: [1]u8 = undefined;
        const len = decode(&out, bytes[0..total_bytes]).?;
        try std.testing.expectEqual(@as(usize, 1), len);
        try std.testing.expectEqual(@as(u8, @intCast(sym)), out[0]);
    }
}
