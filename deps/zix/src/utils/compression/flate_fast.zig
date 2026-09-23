//! Fast gzip encoder for small bodies: greedy LZ over a single-probe hash
//! table, fixed-Huffman coding, one final block. Several times faster than
//! the std matcher on dynamic-response bodies because it never builds
//! dynamic trees, never initializes the std per-stream state, and emits
//! through precomputed bit-reversed code tables with a 64-bit accumulator.
//!
//! Note:
//! - Output is standard RFC 1952 gzip (fixed-Huffman DEFLATE inside), every
//!   decoder accepts it. The ratio sits near the std fastest level, well
//!   above huffman-only.
//! - Input is capped below 64 KiB so hash-table positions fit u16 with 0 as
//!   the never-written sentinel. The caller gates on fitsFast and falls back
//!   to the std path above the cap.

const std = @import("std");

const HASH_BITS = 13;
const HASH_SIZE = 1 << HASH_BITS;
const MIN_MATCH = 4;
const MAX_MATCH = 258;
const INPUT_CAP = 65535;

/// gzip header (10) + footer (8) + block header + accumulator slack.
const WRAP_SLACK = 64;

/// Worst-case output for input_len bytes: fixed-Huffman literals are at most
/// 9 bits per byte, plus container wrap and flush slack.
pub fn gzipFastBound(input_len: usize) usize {
    return input_len + input_len / 8 + WRAP_SLACK;
}

/// Whether input_len is inside the fast encoder's input cap and its
/// worst-case output fits out_cap.
pub fn fitsFast(input_len: usize, out_cap: usize) bool {
    return input_len < INPUT_CAP and gzipFastBound(input_len) <= out_cap;
}

// --------------------------------------------------------- //

fn bitReverse(value: u16, bits: u4) u16 {
    var out: u16 = 0;
    var i: u4 = 0;
    while (i < bits) : (i += 1) {
        out = (out << 1) | ((value >> @intCast(i)) & 1);
    }

    return out;
}

const LitCode = struct { code: u16, bits: u4 };

// Fixed-Huffman literal codes (RFC 1951 3.2.6), bit-reversed for LSB-first
// emission: 0-143 are 8-bit codes from 0x30, 144-255 are 9-bit from 0x190.
const lit_codes = blk: {
    @setEvalBranchQuota(20000);
    var table: [256]LitCode = undefined;
    for (0..144) |lit| {
        table[lit] = .{ .code = bitReverse(0x30 + @as(u16, @intCast(lit)), 8), .bits = 8 };
    }
    for (144..256) |lit| {
        table[lit] = .{ .code = bitReverse(0x190 + @as(u16, @intCast(lit - 144)), 9), .bits = 9 };
    }
    break :blk table;
};

const LenCode = struct { pattern: u32, bits: u6 };

// Length 3..258 to its full bit pattern: the length symbol's fixed code
// (symbols 257-279 are 7-bit, 280-285 8-bit) with the extra bits appended.
const len_codes = blk: {
    @setEvalBranchQuota(100000);
    const bases = [_]u16{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
    const extras = [_]u4{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
    var table: [MAX_MATCH + 1]LenCode = undefined;
    for (3..MAX_MATCH + 1) |len| {
        var symbol_index: usize = 0;
        for (bases, 0..) |base, idx| {
            if (len >= base and (idx == bases.len - 1 or len < bases[idx + 1])) symbol_index = idx;
        }
        const symbol = 257 + symbol_index;
        var code: u16 = undefined;
        var code_bits: u4 = undefined;
        if (symbol <= 279) {
            code = bitReverse(@intCast(symbol - 256), 7);
            code_bits = 7;
        } else {
            code = bitReverse(@intCast(0xC0 + (symbol - 280)), 8);
            code_bits = 8;
        }
        const extra_val: u32 = @intCast(len - bases[symbol_index]);
        table[len] = .{
            .pattern = @as(u32, code) | (extra_val << code_bits),
            .bits = @as(u6, code_bits) + extras[symbol_index],
        };
    }
    break :blk table;
};

const DistCode = struct { pattern: u32, bits: u6 };

fn distEntry(dist: u16) DistCode {
    const bases = [_]u16{ 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
    const extras = [_]u4{ 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
    var symbol: usize = 0;
    for (bases, 0..) |base, idx| {
        if (dist >= base and (idx == bases.len - 1 or dist < bases[idx + 1])) symbol = idx;
    }

    const code = bitReverse(@intCast(symbol), 5);
    const extra_val: u32 = dist - bases[symbol];

    return .{
        .pattern = @as(u32, code) | (extra_val << 5),
        .bits = 5 + @as(u6, extras[symbol]),
    };
}

// Distances 1..256 fully precomputed.
const dist_lo = blk: {
    @setEvalBranchQuota(200000);
    var table: [257]DistCode = undefined;
    for (1..257) |dist| table[dist] = distEntry(@intCast(dist));
    table[0] = .{ .pattern = 0, .bits = 0 };
    break :blk table;
};

const DistSlot = struct { code: u16, base: u16, extra_bits: u6 };

// Above distance 256 every fixed-code range is at least 128 wide, so each
// 128-wide slot maps to exactly one symbol. The slot stores code, base, and
// extra width, the runtime part is one subtract and one shift.
const dist_hi = blk: {
    @setEvalBranchQuota(200000);
    const bases = [_]u16{ 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
    const extras = [_]u4{ 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
    var table: [256]DistSlot = undefined;
    for (0..256) |slot| {
        const dist: u16 = (@as(u16, @intCast(slot)) << 7) + 1;
        var symbol: usize = 0;
        for (bases, 0..) |base, idx| {
            if (dist >= base and (idx == bases.len - 1 or dist < bases[idx + 1])) symbol = idx;
        }
        table[slot] = .{
            .code = bitReverse(@intCast(symbol), 5),
            .base = bases[symbol],
            .extra_bits = extras[symbol],
        };
    }
    break :blk table;
};

fn distCode(dist: u16) DistCode {
    if (dist < 257) return dist_lo[dist];

    const slot = dist_hi[(dist - 1) >> 7];

    return .{
        .pattern = @as(u32, slot.code) | (@as(u32, dist - slot.base) << 5),
        .bits = 5 + slot.extra_bits,
    };
}

// --------------------------------------------------------- //

const BitWriter = struct {
    bit_acc: u64 = 0,
    bit_count: u6 = 0,
    out: [*]u8,
    start: [*]u8,

    inline fn put(self: *BitWriter, pattern: u32, bits: u6) void {
        self.bit_acc |= @as(u64, pattern) << self.bit_count;
        self.bit_count += bits;
        if (self.bit_count >= 32) {
            std.mem.writeInt(u32, self.out[0..4], @truncate(self.bit_acc), .little);
            self.out += 4;
            self.bit_acc >>= 32;
            self.bit_count -= 32;
        }
    }

    fn finishByteAlign(self: *BitWriter) void {
        while (self.bit_count > 0) {
            self.out[0] = @truncate(self.bit_acc);
            self.out += 1;
            self.bit_acc >>= 8;
            self.bit_count = if (self.bit_count >= 8) self.bit_count - 8 else 0;
        }
    }

    fn written(self: *const BitWriter) usize {
        return @intFromPtr(self.out) - @intFromPtr(self.start);
    }
};

/// Per-worker hash head table. Positions are stored +1 so 0 marks an empty
/// slot, cleared per call (16 KiB memset, microseconds).
threadlocal var tl_head: [HASH_SIZE]u16 = undefined;

inline fn hash4(word: u32) u16 {
    return @intCast((word *% 0x9E3779B1) >> (32 - HASH_BITS));
}

/// Compress src as one gzip member into dst.
///
/// Note:
/// - The caller must gate with fitsFast(src.len, dst.len). Asserted here.
///
/// Return:
/// - usize, the number of bytes written to dst
pub fn gzipFastInto(src: []const u8, dst: []u8) usize {
    std.debug.assert(fitsFast(src.len, dst.len));

    const header = [_]u8{ 0x1f, 0x8b, 0x08, 0, 0, 0, 0, 0, 0, 0x03 };
    @memcpy(dst[0..header.len], &header);
    @memset(&tl_head, 0);

    var bit_writer = BitWriter{ .out = dst.ptr + header.len, .start = dst.ptr + header.len };

    // Block header, LSB-first: BFINAL=1, then BTYPE=01 (fixed).
    bit_writer.put(0b011, 3);

    var pos: usize = 0;
    const limit = if (src.len >= MIN_MATCH) src.len - MIN_MATCH + 1 else 0;
    while (pos < limit) {
        const word = std.mem.readInt(u32, src[pos..][0..4], .little);
        const slot = hash4(word);
        const candidate = tl_head[slot];
        tl_head[slot] = @intCast(pos + 1);

        if (candidate != 0) {
            const candidate_pos = candidate - 1;
            // DEFLATE's back-reference window is 32768: a farther candidate
            // is not encodable, treat the slot as a miss.
            if (pos - candidate_pos <= 32768 and
                std.mem.readInt(u32, src[candidate_pos..][0..4], .little) == word)
            {
                // Extend the match 8 bytes at a time.
                var len: usize = MIN_MATCH;
                const max_len = @min(MAX_MATCH, src.len - pos);
                while (len + 8 <= max_len) {
                    const ahead = std.mem.readInt(u64, src[pos + len ..][0..8], .little);
                    const behind = std.mem.readInt(u64, src[candidate_pos + len ..][0..8], .little);
                    const diff = ahead ^ behind;
                    if (diff != 0) {
                        len += @ctz(diff) / 8;
                        break;
                    }
                    len += 8;
                } else {
                    while (len < max_len and src[pos + len] == src[candidate_pos + len]) len += 1;
                }
                if (len > max_len) len = max_len;

                const len_entry = len_codes[len];
                bit_writer.put(len_entry.pattern, len_entry.bits);
                const dist_entry = distCode(@intCast(pos - candidate_pos));
                bit_writer.put(dist_entry.pattern, dist_entry.bits);

                // Hash every other covered byte, warm enough at half the cost.
                var insert_pos = pos + 1;
                const insert_end = @min(pos + len, limit);
                while (insert_pos < insert_end) : (insert_pos += 2) {
                    tl_head[hash4(std.mem.readInt(u32, src[insert_pos..][0..4], .little))] = @intCast(insert_pos + 1);
                }

                pos += len;
                continue;
            }
        }

        const lit = lit_codes[src[pos]];
        bit_writer.put(lit.code, lit.bits);
        pos += 1;
    }

    while (pos < src.len) : (pos += 1) {
        const lit = lit_codes[src[pos]];
        bit_writer.put(lit.code, lit.bits);
    }

    // End of block: symbol 256, seven zero bits.
    bit_writer.put(0, 7);
    bit_writer.finishByteAlign();

    const deflate_len = bit_writer.written();
    const tail = dst.ptr + header.len + deflate_len;
    const crc = std.hash.Crc32.hash(src);
    std.mem.writeInt(u32, tail[0..4], crc, .little);
    std.mem.writeInt(u32, tail[4..8], @intCast(src.len), .little);

    return header.len + deflate_len + 8;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const flate = @import("flate.zig");
const testing = std.testing;

fn roundTrip(data: []const u8) !void {
    const out_buf = try testing.allocator.alloc(u8, gzipFastBound(data.len));
    defer testing.allocator.free(out_buf);

    const out_len = gzipFastInto(data, out_buf);

    const plain = try flate.decompressGzipAlloc(testing.allocator, out_buf[0..out_len], INPUT_CAP + 1);
    defer testing.allocator.free(plain);

    try testing.expectEqualSlices(u8, data, plain);
}

test "zix compression: flate_fast, round-trips empty, tiny, and repetitive inputs" {
    try roundTrip("");
    try roundTrip("a");
    try roundTrip("abc");
    try roundTrip("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    try roundTrip("{\"items\":[{\"id\":1,\"name\":\"Alpha\"},{\"id\":2,\"name\":\"Alpha\"}]}");
}

test "zix compression: flate_fast, round-trips incompressible and uniform large inputs" {
    var prng = std.Random.DefaultPrng.init(42);
    const random_body = try testing.allocator.alloc(u8, 16 * 1024);
    defer testing.allocator.free(random_body);
    prng.random().bytes(random_body);

    try roundTrip(random_body);

    const zero_body = try testing.allocator.alloc(u8, 32 * 1024);
    defer testing.allocator.free(zero_body);
    @memset(zero_body, 0);

    try roundTrip(zero_body);
}

test "zix compression: flate_fast, round-trips a near-cap input and respects the bound" {
    const body = try testing.allocator.alloc(u8, INPUT_CAP - 1);
    defer testing.allocator.free(body);
    for (body, 0..) |*byte, i| byte.* = @truncate(i *% 31);

    try roundTrip(body);

    try testing.expect(!fitsFast(INPUT_CAP, 1 << 20));
    try testing.expect(!fitsFast(100, 64));
    try testing.expect(fitsFast(100, gzipFastBound(100)));
}

test "zix compression: flate_fast, compresses structured json well below identity" {
    var body_buf: [8 * 1024]u8 = undefined;
    var pos: usize = 0;
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        const chunk = "{\"id\":123,\"name\":\"Alpha Widget\",\"category\":\"electronics\",\"price\":328,\"quantity\":15,\"active\":true},";
        @memcpy(body_buf[pos..][0..chunk.len], chunk);
        pos += chunk.len;
    }

    var out_buf: [16 * 1024]u8 = undefined;
    const out_len = gzipFastInto(body_buf[0..pos], &out_buf);

    try testing.expect(out_len < pos / 2);
}
