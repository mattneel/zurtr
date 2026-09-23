//! Brotli codec (RFC 7932): an in-tree decoder and encoder, authored from the RFC.
//!
//! Note:
//! - std.compress has flate / zstd / lzma / xz but NO brotli, so the `br` content coding
//!   is implemented here from RFC 7932 (the format, the Appendix A static dictionary, and
//!   the Appendix B word transforms). The decoder is complete. The encoder targets a
//!   modest, response-friendly ratio and always falls back to a never-expand store.
//! - Transport-agnostic: it compresses and decompresses bytes and knows nothing about
//!   HTTP. The Accept-Encoding negotiation and the Content-Encoding / Vary headers live in
//!   the compression.zig facade and the per-engine write paths, not here. The signatures
//!   mirror flate.zig so the facade dispatches to either codec the same way.
//! - Bit convention (sec 1.5.1): the stream is read and written LSB-first for integer
//!   fields, MSB-first for prefix-code bits. The encoder is the exact inverse of the
//!   decoder, proven by self round-trip and by the system `brotli` CLI interop gates in
//!   rnd/0.5.x/verify-brotli*.
//! - The 122,784-byte static dictionary (Appendix A) is embedded from
//!   brotli_dictionary.bin (CRC-32 0x5136cb04), the same bytes the RFC serializes.

const std = @import("std");

const flate = @import("flate.zig");

/// Compression effort, shared with flate so the facade passes one Level to either codec.
pub const Level = flate.Level;

/// Default window log written to the stream header (sec 9.1). 22 gives a 4 MiB window,
/// matching what the system `brotli` CLI uses at its default quality.
const default_wbits: u6 = 22;

/// MLEN caps at 2^24 (sec 9.2: at most 6 nibbles encode MLEN - 1), so one meta-block
/// carries at most 16 MiB. Larger input is split across several meta-blocks.
const MAX_META_BLOCK_LEN: usize = 1 << 24;

const MAX_CODE_LEN = 15;
const MAX_SYMBOLS = 1024; // brotli's largest prefix alphabet (insert-and-copy = 704)

// Insert and copy length code tables (sec 5), read by the decoder and indexed by the
// encoder when it selects a length code.
const INSERT_LEN_EXTRA = [_]u6{ 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 12, 14, 24 };
const INSERT_LEN_BASE = [_]u32{ 0, 1, 2, 3, 4, 5, 6, 8, 10, 14, 18, 26, 34, 50, 66, 98, 130, 194, 322, 578, 1090, 2114, 6210, 22594 };

const COPY_LEN_EXTRA = [_]u6{ 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 8, 9, 10, 24 };
const COPY_LEN_BASE = [_]u32{ 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 18, 22, 30, 38, 54, 70, 102, 134, 198, 326, 582, 1094, 2118 };

const COMMAND_ALPHABET: usize = 704;
const DISTANCE_ALPHABET: usize = 64; // 16 + NDIRECT(0) + (48 << NPOSTFIX(0))
const LITERAL_ALPHABET: usize = 256;

/// Smallest bit width that addresses every symbol of the alphabet (sec 3.4 simple codes).
fn alphabetBits(alphabet_size: usize) u6 {
    if (alphabet_size <= 1) return 0;

    return @intCast(32 - @clz(@as(u32, @intCast(alphabet_size - 1))));
}

// --------------------------------------------------------- //
// Static dictionary (sec 8 + Appendix A/B)

/// Embedded static dictionary (Appendix A). The slice type keeps it as a byte array.
const DICT: []const u8 = @embedFile("brotli_dictionary.bin");

/// Bit-depth of the word count per length (Appendix A): NWORDS[len] = 1 << NDBITS[len]
/// for len >= 4, otherwise 0.
const NDBITS = [25]u5{ 0, 0, 0, 0, 10, 10, 11, 11, 10, 10, 10, 10, 10, 9, 9, 8, 7, 7, 8, 7, 7, 6, 6, 5, 5 };

/// Byte offset into DICT of the first word of each length, derived from NDBITS by the
/// sec 8 recursion. DOFFSET[25] is DICTSIZE.
const DOFFSET = blk: {
    var off: [26]u32 = undefined;
    off[0] = 0;
    var len: usize = 0;
    while (len <= 24) : (len += 1) {
        const nwords: u32 = if (len < 4) 0 else (@as(u32, 1) << NDBITS[len]);
        off[len + 1] = off[len] + @as(u32, @intCast(len)) * nwords;
    }
    break :blk off;
};

fn numWords(length: usize) u32 {
    return if (length < 4) 0 else (@as(u32, 1) << NDBITS[length]);
}

// Elementary transform identifiers, matching the RFC's serialization byte values: 0
// Identity, 1 FermentFirst, 2 FermentAll, 3..11 OmitFirst1..9, 12..20 OmitLast1..9.
const ID = 0;
const FF = 1;
const FA = 2;
const OF1 = 3;
const OF2 = 4;
const OF3 = 5;
const OF4 = 6;
const OF5 = 7;
const OF6 = 8;
const OF7 = 9;
const OF9 = 11;
const OL1 = 12;
const OL2 = 13;
const OL3 = 14;
const OL4 = 15;
const OL5 = 16;
const OL6 = 17;
const OL7 = 18;
const OL8 = 19;
const OL9 = 20;

const Transform = struct {
    prefix: []const u8,
    op: u8,
    suffix: []const u8,
};

const TRANSFORMS = [_]Transform{
    .{ .prefix = "", .op = ID, .suffix = "" },
    .{ .prefix = "", .op = ID, .suffix = " " },
    .{ .prefix = " ", .op = ID, .suffix = " " },
    .{ .prefix = "", .op = OF1, .suffix = "" },
    .{ .prefix = "", .op = FF, .suffix = " " },
    .{ .prefix = "", .op = ID, .suffix = " the " },
    .{ .prefix = " ", .op = ID, .suffix = "" },
    .{ .prefix = "s ", .op = ID, .suffix = " " },
    .{ .prefix = "", .op = ID, .suffix = " of " },
    .{ .prefix = "", .op = FF, .suffix = "" },
    .{ .prefix = "", .op = ID, .suffix = " and " },
    .{ .prefix = "", .op = OF2, .suffix = "" },
    .{ .prefix = "", .op = OL1, .suffix = "" },
    .{ .prefix = ", ", .op = ID, .suffix = " " },
    .{ .prefix = "", .op = ID, .suffix = ", " },
    .{ .prefix = " ", .op = FF, .suffix = " " },
    .{ .prefix = "", .op = ID, .suffix = " in " },
    .{ .prefix = "", .op = ID, .suffix = " to " },
    .{ .prefix = "e ", .op = ID, .suffix = " " },
    .{ .prefix = "", .op = ID, .suffix = "\"" },
    .{ .prefix = "", .op = ID, .suffix = "." },
    .{ .prefix = "", .op = ID, .suffix = "\">" },
    .{ .prefix = "", .op = ID, .suffix = "\n" },
    .{ .prefix = "", .op = OL3, .suffix = "" },
    .{ .prefix = "", .op = ID, .suffix = "]" },
    .{ .prefix = "", .op = ID, .suffix = " for " },
    .{ .prefix = "", .op = OF3, .suffix = "" },
    .{ .prefix = "", .op = OL2, .suffix = "" },
    .{ .prefix = "", .op = ID, .suffix = " a " },
    .{ .prefix = "", .op = ID, .suffix = " that " },
    .{ .prefix = " ", .op = FF, .suffix = "" },
    .{ .prefix = "", .op = ID, .suffix = ". " },
    .{ .prefix = ".", .op = ID, .suffix = "" },
    .{ .prefix = " ", .op = ID, .suffix = ", " },
    .{ .prefix = "", .op = OF4, .suffix = "" },
    .{ .prefix = "", .op = ID, .suffix = " with " },
    .{ .prefix = "", .op = ID, .suffix = "'" },
    .{ .prefix = "", .op = ID, .suffix = " from " },
    .{ .prefix = "", .op = ID, .suffix = " by " },
    .{ .prefix = "", .op = OF5, .suffix = "" },
    .{ .prefix = "", .op = OF6, .suffix = "" },
    .{ .prefix = " the ", .op = ID, .suffix = "" },
    .{ .prefix = "", .op = OL4, .suffix = "" },
    .{ .prefix = "", .op = ID, .suffix = ". The " },
    .{ .prefix = "", .op = FA, .suffix = "" },
    .{ .prefix = "", .op = ID, .suffix = " on " },
    .{ .prefix = "", .op = ID, .suffix = " as " },
    .{ .prefix = "", .op = ID, .suffix = " is " },
    .{ .prefix = "", .op = OL7, .suffix = "" },
    .{ .prefix = "", .op = OL1, .suffix = "ing " },
    .{ .prefix = "", .op = ID, .suffix = "\n\t" },
    .{ .prefix = "", .op = ID, .suffix = ":" },
    .{ .prefix = " ", .op = ID, .suffix = ". " },
    .{ .prefix = "", .op = ID, .suffix = "ed " },
    .{ .prefix = "", .op = OF9, .suffix = "" },
    .{ .prefix = "", .op = OF7, .suffix = "" },
    .{ .prefix = "", .op = OL6, .suffix = "" },
    .{ .prefix = "", .op = ID, .suffix = "(" },
    .{ .prefix = "", .op = FF, .suffix = ", " },
    .{ .prefix = "", .op = OL8, .suffix = "" },
    .{ .prefix = "", .op = ID, .suffix = " at " },
    .{ .prefix = "", .op = ID, .suffix = "ly " },
    .{ .prefix = " the ", .op = ID, .suffix = " of " },
    .{ .prefix = "", .op = OL5, .suffix = "" },
    .{ .prefix = "", .op = OL9, .suffix = "" },
    .{ .prefix = " ", .op = FF, .suffix = ", " },
    .{ .prefix = "", .op = FF, .suffix = "\"" },
    .{ .prefix = ".", .op = ID, .suffix = "(" },
    .{ .prefix = "", .op = FA, .suffix = " " },
    .{ .prefix = "", .op = FF, .suffix = "\">" },
    .{ .prefix = "", .op = ID, .suffix = "=\"" },
    .{ .prefix = " ", .op = ID, .suffix = "." },
    .{ .prefix = ".com/", .op = ID, .suffix = "" },
    .{ .prefix = " the ", .op = ID, .suffix = " of the " },
    .{ .prefix = "", .op = FF, .suffix = "'" },
    .{ .prefix = "", .op = ID, .suffix = ". This " },
    .{ .prefix = "", .op = ID, .suffix = "," },
    .{ .prefix = ".", .op = ID, .suffix = " " },
    .{ .prefix = "", .op = FF, .suffix = "(" },
    .{ .prefix = "", .op = FF, .suffix = "." },
    .{ .prefix = "", .op = ID, .suffix = " not " },
    .{ .prefix = " ", .op = ID, .suffix = "=\"" },
    .{ .prefix = "", .op = ID, .suffix = "er " },
    .{ .prefix = " ", .op = FA, .suffix = " " },
    .{ .prefix = "", .op = ID, .suffix = "al " },
    .{ .prefix = " ", .op = FA, .suffix = "" },
    .{ .prefix = "", .op = ID, .suffix = "='" },
    .{ .prefix = "", .op = FA, .suffix = "\"" },
    .{ .prefix = "", .op = FF, .suffix = ". " },
    .{ .prefix = " ", .op = ID, .suffix = "(" },
    .{ .prefix = "", .op = ID, .suffix = "ful " },
    .{ .prefix = " ", .op = FF, .suffix = ". " },
    .{ .prefix = "", .op = ID, .suffix = "ive " },
    .{ .prefix = "", .op = ID, .suffix = "less " },
    .{ .prefix = "", .op = FA, .suffix = "'" },
    .{ .prefix = "", .op = ID, .suffix = "est " },
    .{ .prefix = " ", .op = FF, .suffix = "." },
    .{ .prefix = "", .op = FA, .suffix = "\">" },
    .{ .prefix = " ", .op = ID, .suffix = "='" },
    .{ .prefix = "", .op = FF, .suffix = "," },
    .{ .prefix = "", .op = ID, .suffix = "ize " },
    .{ .prefix = "", .op = FA, .suffix = "." },
    .{ .prefix = "\xc2\xa0", .op = ID, .suffix = "" },
    .{ .prefix = " ", .op = ID, .suffix = "," },
    .{ .prefix = "", .op = FF, .suffix = "=\"" },
    .{ .prefix = "", .op = FA, .suffix = "=\"" },
    .{ .prefix = "", .op = ID, .suffix = "ous " },
    .{ .prefix = "", .op = FA, .suffix = ", " },
    .{ .prefix = "", .op = FF, .suffix = "='" },
    .{ .prefix = " ", .op = FF, .suffix = "," },
    .{ .prefix = " ", .op = FA, .suffix = "=\"" },
    .{ .prefix = " ", .op = FA, .suffix = ", " },
    .{ .prefix = "", .op = FA, .suffix = "," },
    .{ .prefix = "", .op = FA, .suffix = "(" },
    .{ .prefix = "", .op = FA, .suffix = ". " },
    .{ .prefix = " ", .op = FA, .suffix = "." },
    .{ .prefix = "", .op = FA, .suffix = "='" },
    .{ .prefix = " ", .op = FA, .suffix = ". " },
    .{ .prefix = " ", .op = FF, .suffix = "=\"" },
    .{ .prefix = " ", .op = FA, .suffix = "='" },
    .{ .prefix = " ", .op = FF, .suffix = "='" },
};

/// Ferment one position (sec 8): upper-case ASCII, or flip a bit in the next byte of a
/// 2- or 3-byte UTF-8 sequence. Returns the number of bytes consumed.
fn ferment(word: []u8, pos: usize) usize {
    if (word[pos] < 192) {
        if (word[pos] >= 97 and word[pos] <= 122) word[pos] ^= 32;
        return 1;
    } else if (word[pos] < 224) {
        if (pos + 1 < word.len) word[pos + 1] ^= 32;
        return 2;
    } else {
        if (pos + 2 < word.len) word[pos + 2] ^= 5;
        return 3;
    }
}

fn fermentFirst(word: []u8) void {
    if (word.len > 0) _ = ferment(word, 0);
}

fn fermentAll(word: []u8) void {
    var i: usize = 0;
    while (i < word.len) i += ferment(word, i);
}

/// Apply a transform to a base word, writing prefix + T(word) + suffix into out (sec 8).
/// Returns the number of bytes written.
fn applyTransform(transform: Transform, base: []const u8, out: []u8) usize {
    var n: usize = 0;
    @memcpy(out[n..][0..transform.prefix.len], transform.prefix);
    n += transform.prefix.len;

    var word: [38]u8 = undefined;
    @memcpy(word[0..base.len], base);

    var mid_start: usize = 0;
    var mid_len: usize = base.len;
    if (transform.op == FF) {
        fermentFirst(word[0..mid_len]);
    } else if (transform.op == FA) {
        fermentAll(word[0..mid_len]);
    } else if (transform.op >= OF1 and transform.op <= OF9) {
        const k = transform.op - 2; // OmitFirst1 is op 3
        if (k >= mid_len) mid_len = 0 else {
            mid_start = k;
            mid_len -= k;
        }
    } else if (transform.op >= OL1 and transform.op <= OL9) {
        const k = transform.op - 11; // OmitLast1 is op 12
        if (k >= mid_len) mid_len = 0 else mid_len -= k;
    }

    @memcpy(out[n..][0..mid_len], word[mid_start .. mid_start + mid_len]);
    n += mid_len;

    @memcpy(out[n..][0..transform.suffix.len], transform.suffix);
    n += transform.suffix.len;

    return n;
}

/// Resolve a dictionary reference (sec 8) into out, returning the bytes written.
fn dictionaryWord(length: u32, distance: u32, max_allowed: u32, out: []u8) !usize {
    if (length < 4 or length > 24) return error.ZixInvalidDictionaryLength;

    const word_id = distance - (max_allowed + 1);
    const index = word_id % numWords(length);
    const transform_id = word_id >> NDBITS[length];
    if (transform_id > 120) return error.ZixInvalidTransform;

    const offset = DOFFSET[length] + index * length;
    const base = DICT[offset .. offset + length];

    return applyTransform(TRANSFORMS[transform_id], base, out);
}

// --------------------------------------------------------- //
// Decoder: bit reader and prefix codes (sec 1.5.1, sec 3)

/// LSB-first bit reader (sec 1.5.1).
const BitReader = struct {
    bytes: []const u8,
    byte_pos: usize = 0,
    bit_pos: u3 = 0,

    fn readBit(self: *BitReader) !u1 {
        if (self.byte_pos >= self.bytes.len) return error.EndOfStream;

        const bit: u1 = @truncate(self.bytes[self.byte_pos] >> self.bit_pos);
        if (self.bit_pos == 7) {
            self.bit_pos = 0;
            self.byte_pos += 1;
        } else {
            self.bit_pos += 1;
        }

        return bit;
    }

    fn readBits(self: *BitReader, n: u6) !u32 {
        var value: u32 = 0;
        var i: u6 = 0;
        while (i < n) : (i += 1) {
            value |= @as(u32, try self.readBit()) << @intCast(i);
        }

        return value;
    }

    fn alignToByte(self: *BitReader) void {
        if (self.bit_pos != 0) {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
    }

    fn readBytes(self: *BitReader, n: usize) ![]const u8 {
        if (self.byte_pos + n > self.bytes.len) return error.EndOfStream;

        const slice = self.bytes[self.byte_pos .. self.byte_pos + n];
        self.byte_pos += n;

        return slice;
    }
};

/// Canonical prefix-code decoder built from per-symbol code lengths (sec 3.2).
const HuffmanDecoder = struct {
    single_symbol: ?u16 = null,
    count: [MAX_CODE_LEN + 1]u16 = std.mem.zeroes([MAX_CODE_LEN + 1]u16),
    first_code: [MAX_CODE_LEN + 1]u16 = std.mem.zeroes([MAX_CODE_LEN + 1]u16),
    first_symbol: [MAX_CODE_LEN + 1]u16 = std.mem.zeroes([MAX_CODE_LEN + 1]u16),
    symbols: [MAX_SYMBOLS]u16 = undefined,

    fn build(lengths: []const u8) !HuffmanDecoder {
        var self = HuffmanDecoder{};

        var nonzero: u16 = 0;
        var last_nonzero: u16 = 0;
        for (lengths, 0..) |len, sym| {
            if (len > MAX_CODE_LEN) return error.ZixInvalidCode;
            if (len != 0) {
                self.count[len] += 1;
                nonzero += 1;
                last_nonzero = @intCast(sym);
            }
        }

        // sec 3.4 / 3.5: a code with a single participating symbol emits no bits.
        if (nonzero <= 1) {
            self.single_symbol = if (nonzero == 1) last_nonzero else 0;
            return self;
        }

        var code: u16 = 0;
        var sym_off: u16 = 0;
        var len: usize = 1;
        while (len <= MAX_CODE_LEN) : (len += 1) {
            code = (code + self.count[len - 1]) << 1;
            self.first_code[len] = code;
            self.first_symbol[len] = sym_off;
            sym_off += self.count[len];
        }

        var fill = self.first_symbol;
        for (lengths, 0..) |len_s, sym| {
            if (len_s != 0) {
                self.symbols[fill[len_s]] = @intCast(sym);
                fill[len_s] += 1;
            }
        }

        return self;
    }

    fn readSymbol(self: *const HuffmanDecoder, br: *BitReader) !u16 {
        if (self.single_symbol) |s| return s;

        var code: u16 = 0;
        var len: usize = 1;
        while (len <= MAX_CODE_LEN) : (len += 1) {
            code = (code << 1) | (try br.readBit());
            if (self.count[len] != 0) {
                const rel = code -% self.first_code[len];
                if (rel < self.count[len]) return self.symbols[self.first_symbol[len] + rel];
            }
        }

        return error.ZixInvalidCode;
    }
};

/// The static code over code-length-code lengths 0..5 (sec 3.5 table), read LSB-first.
fn readCodeLengthCodeLength(br: *BitReader) !u8 {
    if (try br.readBit() == 0) {
        return if (try br.readBit() == 0) 0 else 3;
    }
    if (try br.readBit() == 0) return 4;
    if (try br.readBit() == 0) return 2;
    return if (try br.readBit() == 0) 1 else 5;
}

/// Read the code lengths of the 18-symbol code-length alphabet (sec 3.5).
fn readCodeLengthCode(br: *BitReader, hskip: u32, out: *[18]u8) !void {
    const order = [_]u8{ 1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    @memset(out, 0);

    var space: i64 = 32;
    var i: usize = hskip;
    while (i < 18) : (i += 1) {
        const len = try readCodeLengthCodeLength(br);
        out[order[i]] = len;
        if (len != 0) {
            space -= @as(i64, 32) >> @intCast(len);
            if (space <= 0) break;
        }
    }
}

/// Read the per-symbol code lengths using the code-length code, with repeat codes
/// 16 (copy previous, 3..6) and 17 (zeros, 3..10), modification rule per sec 3.5.
fn readSymbolLengths(br: *BitReader, cl: *const HuffmanDecoder, alphabet_size: usize, out: []u8) !void {
    @memset(out[0..alphabet_size], 0);

    var symbol: usize = 0;
    var prev_code_len: u8 = 8;
    var repeat: u32 = 0;
    var repeat_code_len: u8 = 0;
    var space: i64 = 32768;

    while (symbol < alphabet_size and space > 0) {
        const code_len = try cl.readSymbol(br);
        if (code_len < 16) {
            repeat = 0;
            out[symbol] = @intCast(code_len);
            symbol += 1;
            if (code_len != 0) {
                prev_code_len = @intCast(code_len);
                space -= @as(i64, 32768) >> @intCast(code_len);
            }
        } else {
            const extra_bits: u6 = if (code_len == 16) 2 else 3;
            const new_len: u8 = if (code_len == 16) prev_code_len else 0;
            if (repeat_code_len != new_len) {
                repeat = 0;
                repeat_code_len = new_len;
            }
            const old_repeat = repeat;
            if (repeat > 0) {
                repeat -= 2;
                repeat <<= @intCast(extra_bits);
            }
            repeat += (try br.readBits(extra_bits)) + 3;
            const delta = repeat - old_repeat;
            if (symbol + delta > alphabet_size) return error.Overflow;

            var k: u32 = 0;
            while (k < delta) : (k += 1) {
                out[symbol] = repeat_code_len;
                symbol += 1;
            }
            if (repeat_code_len != 0) space -= @as(i64, delta) << @intCast(15 - repeat_code_len);
        }
    }
}

fn readSimplePrefixCode(br: *BitReader, alphabet_size: usize) !HuffmanDecoder {
    const nsym = (try br.readBits(2)) + 1;
    const abits = alphabetBits(alphabet_size);

    var syms: [4]u16 = undefined;
    var i: u32 = 0;
    while (i < nsym) : (i += 1) {
        const s: u16 = @intCast(try br.readBits(abits));
        if (s >= alphabet_size) return error.ZixInvalidSymbol;
        var j: u32 = 0;
        while (j < i) : (j += 1) if (syms[j] == s) return error.ZixDuplicateSymbol;
        syms[i] = s;
    }

    if (nsym == 1) return .{ .single_symbol = syms[0] };

    var tree_select: u1 = 0;
    if (nsym == 4) tree_select = try br.readBit();

    var lengths: [MAX_SYMBOLS]u8 = undefined;
    @memset(lengths[0..alphabet_size], 0);
    switch (nsym) {
        2 => {
            lengths[syms[0]] = 1;
            lengths[syms[1]] = 1;
        },
        3 => {
            lengths[syms[0]] = 1;
            lengths[syms[1]] = 2;
            lengths[syms[2]] = 2;
        },
        4 => {
            if (tree_select == 0) {
                for (syms) |s| lengths[s] = 2;
            } else {
                lengths[syms[0]] = 1;
                lengths[syms[1]] = 2;
                lengths[syms[2]] = 3;
                lengths[syms[3]] = 3;
            }
        },
        else => unreachable,
    }

    return HuffmanDecoder.build(lengths[0..alphabet_size]);
}

fn readComplexPrefixCode(br: *BitReader, alphabet_size: usize, hskip: u32) !HuffmanDecoder {
    var cl_lengths: [18]u8 = undefined;
    try readCodeLengthCode(br, hskip, &cl_lengths);

    const cl = try HuffmanDecoder.build(&cl_lengths);

    var sym_lengths: [MAX_SYMBOLS]u8 = undefined;
    try readSymbolLengths(br, &cl, alphabet_size, &sym_lengths);

    return HuffmanDecoder.build(sym_lengths[0..alphabet_size]);
}

/// Read one prefix code (sec 3.4/3.5). The 2-bit prefix is 1 for simple, otherwise it
/// is HSKIP (0, 2, or 3) for a complex code.
fn readPrefixCode(br: *BitReader, alphabet_size: usize) !HuffmanDecoder {
    const selector = try br.readBits(2);
    if (selector == 1) return readSimplePrefixCode(br, alphabet_size);

    return readComplexPrefixCode(br, alphabet_size, selector);
}

// --------------------------------------------------------- //
// Decoder: meta-block preamble (sec 9.2 + sec 6)

fn readWindowBits(br: *BitReader) !u6 {
    if (try br.readBit() == 0) return 16;

    const n1 = try br.readBits(3);
    if (n1 != 0) return @intCast(17 + n1);

    const n2 = try br.readBits(3);
    if (n2 != 0) return @intCast(8 + n2);

    return 17;
}

/// NBLTYPES / NTREES variable-length uint, 1..256 (sec 9.2).
fn readBlockTypeCount(br: *BitReader) !u32 {
    if (try br.readBit() == 0) return 1;

    const n = try br.readBits(3);

    return (@as(u32, 1) << @intCast(n)) + 1 + (try br.readBits(@intCast(n)));
}

// The 26-symbol block count code: base value and extra-bit count per symbol (sec 6).
const BLOCK_COUNT_BASE = [_]u32{ 1, 5, 9, 13, 17, 25, 33, 41, 49, 65, 81, 97, 113, 145, 177, 209, 241, 305, 369, 497, 753, 1265, 2289, 4337, 8433, 16625 };
const BLOCK_COUNT_EXTRA = [_]u6{ 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 7, 8, 9, 10, 11, 12, 13, 24 };

/// One block count: a block-count code symbol then its extra bits (sec 6).
fn readBlockCount(br: *BitReader, code: *const HuffmanDecoder) !u32 {
    const sym = try code.readSymbol(br);
    if (sym >= BLOCK_COUNT_BASE.len) return error.ZixInvalidBlockCountCode;

    return BLOCK_COUNT_BASE[sym] + (try br.readBits(BLOCK_COUNT_EXTRA[sym]));
}

// --------------------------------------------------------- //
// Decoder: context modeling (sec 7)

/// Literal context mode (sec 7.1), two bits per literal block type.
const ContextMode = enum(u2) {
    LSB6 = 0,
    MSB6 = 1,
    UTF8 = 2,
    SIGNED = 3,
};

const MAX_BLOCK_TYPES = 256;
const CMAPL_MAX = 64 * MAX_BLOCK_TYPES;
const CMAPD_MAX = 4 * MAX_BLOCK_TYPES;

/// One context mode per literal block type, two bits each (sec 9.2 + sec 7.1).
fn readContextModes(br: *BitReader, nbltypesl: u32, out: []ContextMode) !void {
    var i: u32 = 0;
    while (i < nbltypesl) : (i += 1) out[i] = @enumFromInt(try br.readBits(2));
}

/// RLEMAX, the number of run-length codes (sec 7.3): a single 0 bit means 0, otherwise
/// the leading 1 is followed by four bits xxxx giving the value xxxx + 1 (range 1..16).
fn readRleMax(br: *BitReader) !u32 {
    if (try br.readBit() == 0) return 0;

    return (try br.readBits(4)) + 1;
}

/// The inverse move-to-front transform (sec 7.3), mapping the run-length-decoded values
/// back to prefix-code indexes in place.
fn inverseMoveToFront(values: []u8) void {
    var mtf: [256]u8 = undefined;
    for (&mtf, 0..) |*slot, i| slot.* = @intCast(i);

    for (values) |*vi| {
        const index = vi.*;
        const value = mtf[index];
        vi.* = value;

        var idx = index;
        while (idx > 0) : (idx -= 1) mtf[idx] = mtf[idx - 1];
        mtf[0] = value;
    }
}

/// Decode one context map of map_size values (sec 7.3): RLEMAX, a prefix code over
/// NTREES + RLEMAX symbols, the run-length-zero coded values, then the IMTF bit.
fn readContextMap(br: *BitReader, ntrees: u32, map_size: usize, out: []u8) !void {
    const rlemax = try readRleMax(br);
    const alphabet_size = ntrees + rlemax;

    const code = try readPrefixCode(br, alphabet_size);

    var i: usize = 0;
    while (i < map_size) {
        const sym = try code.readSymbol(br);
        if (sym == 0) {
            out[i] = 0;
            i += 1;
        } else if (sym <= rlemax) {
            const run = (@as(u32, 1) << @intCast(sym)) + (try br.readBits(@intCast(sym)));
            if (i + run > map_size) return error.ZixContextMapOverflow;

            var k: u32 = 0;
            while (k < run) : (k += 1) {
                out[i] = 0;
                i += 1;
            }
        } else {
            out[i] = @intCast(sym - rlemax);
            i += 1;
        }
    }

    const imtf = try br.readBit();
    if (imtf == 1) inverseMoveToFront(out[0..map_size]);
}

// --------------------------------------------------------- //
// Decoder: command machinery (sec 4, 5, 7.1, 7.2)

// The insert-and-copy length code is split into an insert length code and a copy length
// code by an 11-cell table (sec 5). Per cell index (cmd >> 6): the base insert code, the
// base copy code, and whether the distance is an implicit zero (cells 0 and 1, cmd<128).
const CELL_INSERT_BASE = [_]u8{ 0, 0, 0, 0, 8, 8, 0, 16, 8, 16, 16 };
const CELL_COPY_BASE = [_]u8{ 0, 8, 0, 8, 0, 8, 16, 0, 16, 8, 16 };

const InsertCopy = struct {
    insert_code: u8,
    copy_code: u8,
    distance_zero: bool,
};

/// Split an insert-and-copy length code into its insert and copy codes (sec 5). The copy
/// code is bits 0..2, the insert code is bits 3..5, each added to its per-cell base.
fn splitInsertCopy(cmd: u16) InsertCopy {
    const cell = cmd >> 6;

    return .{
        .insert_code = CELL_INSERT_BASE[cell] + @as(u8, @intCast((cmd >> 3) & 7)),
        .copy_code = CELL_COPY_BASE[cell] + @as(u8, @intCast(cmd & 7)),
        .distance_zero = cmd < 128,
    };
}

// sec 7.1 literal context lookup tables (UTF8 / Signed).
const Lut0 = [256]u8{
    0,  0,  0,  0,  0,  0,  0,  0,  0,  4,  4,  0,  0,  4,  0,  0,
    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
    8,  12, 16, 12, 12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12,
    44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12,
    12, 48, 52, 52, 52, 48, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48,
    52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24, 12, 28, 12, 12,
    12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56,
    60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 24, 12, 28, 12, 0,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,  0,  1,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
    2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,  2,  3,
};

const Lut1 = [256]u8{
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
    1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
    1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
};

const Lut2 = [256]u8{
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
    6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7,
};

/// Literal context ID from the context mode and the last two output bytes (sec 7.1).
fn literalContextId(mode: ContextMode, p1: u8, p2: u8) u8 {
    return switch (mode) {
        .LSB6 => p1 & 0x3f,
        .MSB6 => p1 >> 2,
        .UTF8 => Lut0[p1] | Lut1[p2],
        .SIGNED => (Lut2[p1] << 3) | Lut2[p2],
    };
}

/// Distance context ID from the copy length (sec 7.2): 0, 1, 2 for copy length 2, 3, 4
/// and 3 for any longer copy.
fn distanceContextId(copy_len: u32) u8 {
    return if (copy_len > 4) 3 else @intCast(copy_len - 2);
}

/// The four most recent backward distances, initialized once per stream (sec 4). Index 0
/// is the last distance, index 3 the fourth-to-last.
const DistanceRing = struct {
    d: [4]u32 = .{ 4, 11, 15, 16 },

    fn push(self: *DistanceRing, dist: u32) void {
        self.d[3] = self.d[2];
        self.d[2] = self.d[1];
        self.d[1] = self.d[0];
        self.d[0] = dist;
    }
};

const Distance = struct {
    value: u32,
    push: bool,
};

/// The short distance table for codes 0..15 (sec 4): codes 0..3 are the last, second,
/// third, and fourth-to-last distances, codes 4..9 modify the last distance by -1, +1,
/// -2, +2, -3, +3, and codes 10..15 modify the second-to-last distance the same way.
fn shortDistance(code: u16, ring: *const DistanceRing) i64 {
    switch (code) {
        0 => return ring.d[0],
        1 => return ring.d[1],
        2 => return ring.d[2],
        3 => return ring.d[3],
        else => {},
    }

    const slot: usize = if (code < 10) 0 else 1;
    const offsets = [_]i64{ -1, 1, -2, 2, -3, 3 };
    const idx: usize = if (code < 10) code - 4 else code - 10;

    return @as(i64, ring.d[slot]) + offsets[idx];
}

/// Resolve one distance code into a backward distance (sec 4). The first 16 codes are
/// short references into the ring buffer, the next NDIRECT are direct distances, and the
/// rest carry extra bits decoded with the NPOSTFIX / NDIRECT formula.
fn readDistance(br: *BitReader, code: u16, ring: *const DistanceRing, npostfix: u32, ndirect: u32) !Distance {
    if (code < 16) {
        const value = shortDistance(code, ring);
        if (value <= 0) return error.ZixInvalidDistance;

        return .{ .value = @intCast(value), .push = code != 0 };
    }

    if (code < 16 + ndirect) return .{ .value = code - 16 + 1, .push = true };

    const dadj: u32 = code - ndirect - 16;
    const ndistbits: u5 = @intCast(1 + (dadj >> @intCast(npostfix + 1)));
    const dextra: u64 = try br.readBits(ndistbits);
    const postfix_mask: u32 = (@as(u32, 1) << @intCast(npostfix)) - 1;
    const hcode: u32 = dadj >> @intCast(npostfix);
    const lcode: u32 = dadj & postfix_mask;
    const offset: u64 = (@as(u64, 2 + (hcode & 1)) << ndistbits) - 4;
    const value: u64 = ((offset + dextra) << @intCast(npostfix)) + lcode + ndirect + 1;

    return .{ .value = @intCast(value), .push = true };
}

// --------------------------------------------------------- //
// Decoder: the full stream decode (sec 10)

/// One block category (literals, insert-and-copy, or distances). When NBLTYPES >= 2 the
/// stream carries block-switch commands that flip the active block type mid-data.
const BlockCategory = struct {
    nbltypes: u32,
    btype: u32 = 0,
    prev_btype: u32 = 1,
    blen: u32 = 0,
    has_switch: bool = false,
    btype_code: HuffmanDecoder = undefined,
    blen_code: HuffmanDecoder = undefined,

    fn init(br: *BitReader) !BlockCategory {
        const nbltypes = try readBlockTypeCount(br);
        if (nbltypes < 2) return .{ .nbltypes = nbltypes, .blen = 16777216 };

        var cat = BlockCategory{ .nbltypes = nbltypes, .has_switch = true };
        cat.btype_code = try readPrefixCode(br, nbltypes + 2);
        cat.blen_code = try readPrefixCode(br, BLOCK_COUNT_BASE.len);
        cat.blen = try readBlockCount(br, &cat.blen_code);

        return cat;
    }

    fn consume(self: *BlockCategory, br: *BitReader) !void {
        if (self.blen == 0 and self.has_switch) {
            const sym = try self.btype_code.readSymbol(br);
            const next: u32 = switch (sym) {
                0 => self.prev_btype,
                1 => (self.btype + 1) % self.nbltypes,
                else => @as(u32, sym) - 2,
            };
            if (next >= self.nbltypes) return error.ZixInvalidBlockType;

            self.prev_btype = self.btype;
            self.btype = next;
            self.blen = try readBlockCount(br, &self.blen_code);
        }

        if (self.blen > 0) self.blen -= 1;
    }
};

/// Feature coverage of a decode, kept so the in-tree tests can assert which code paths a
/// vector exercised, not only that it round-tripped.
const Stats = struct {
    meta_blocks: usize = 0,
    compressed: usize = 0,
    uncompressed: usize = 0,
    metadata: usize = 0,
    block_switch: usize = 0,
};

const Decoder = struct {
    allocator: std.mem.Allocator,
    br: BitReader,
    stats: *Stats,
    limit: usize,
    out: std.ArrayList(u8) = .empty,
    window_size: u32 = 0,
    ring: DistanceRing = .{},
    p1: u8 = 0,
    p2: u8 = 0,

    fn pushByte(self: *Decoder, byte: u8) !void {
        try self.out.append(self.allocator, byte);
        self.p2 = self.p1;
        self.p1 = byte;
    }

    /// Decode the whole stream (sec 10), returning the owned uncompressed bytes.
    fn run(self: *Decoder) ![]u8 {
        const wbits = try readWindowBits(&self.br);
        self.window_size = (@as(u32, 1) << @intCast(wbits)) - 16;

        while (true) {
            const is_last = try self.br.readBit();
            if (is_last == 1 and try self.br.readBit() == 1) break;

            const mnibbles_code = try self.br.readBits(2);
            if (mnibbles_code == 3) {
                try self.skipMetadata();
            } else {
                const nibbles: u6 = @intCast(mnibbles_code + 4);
                const mlen = (try self.br.readBits(nibbles * 4)) + 1;

                // bound the total output before producing the block, so a bomb is rejected
                // up front with no per-byte check in the hot copy loop.
                if (self.out.items.len + mlen > self.limit) return error.ZixOutputTooLarge;

                var is_uncompressed = false;
                if (is_last == 0) is_uncompressed = (try self.br.readBit() == 1);

                if (is_uncompressed) {
                    try self.copyUncompressed(mlen);
                } else {
                    try self.decodeMetaBlock(mlen);
                }
            }

            if (is_last == 1) break;
        }

        return self.out.toOwnedSlice(self.allocator);
    }

    /// Metadata meta-block (MNIBBLES = 0, sec 9.2): skip MSKIPLEN bytes, produce nothing.
    fn skipMetadata(self: *Decoder) !void {
        self.stats.meta_blocks += 1;
        self.stats.metadata += 1;
        if (try self.br.readBit() != 0) return error.ZixBadReservedBit;

        const mskipbytes = try self.br.readBits(2);
        var mskiplen: u32 = 0;
        if (mskipbytes > 0) mskiplen = (try self.br.readBits(@intCast(mskipbytes * 8))) + 1;

        self.br.alignToByte();
        _ = try self.br.readBytes(mskiplen);
    }

    /// Uncompressed meta-block (ISUNCOMPRESSED): copy MLEN literal bytes verbatim.
    fn copyUncompressed(self: *Decoder, mlen: u32) !void {
        self.stats.meta_blocks += 1;
        self.stats.uncompressed += 1;
        self.br.alignToByte();
        const raw = try self.br.readBytes(mlen);

        try self.out.appendSlice(self.allocator, raw);
        if (mlen >= 2) {
            self.p2 = raw[mlen - 2];
            self.p1 = raw[mlen - 1];
        } else if (mlen == 1) {
            self.p2 = self.p1;
            self.p1 = raw[0];
        }
    }

    /// Compressed meta-block: parse the header (sec 9.2) and run the command loop (sec 10).
    fn decodeMetaBlock(self: *Decoder, mlen: u32) !void {
        self.stats.meta_blocks += 1;
        self.stats.compressed += 1;

        var cat_l = try BlockCategory.init(&self.br);
        var cat_i = try BlockCategory.init(&self.br);
        var cat_d = try BlockCategory.init(&self.br);
        if (cat_l.nbltypes >= 2 or cat_i.nbltypes >= 2 or cat_d.nbltypes >= 2) self.stats.block_switch += 1;

        const npostfix = try self.br.readBits(2);
        const ndirect = (try self.br.readBits(4)) << @intCast(npostfix);

        var cmode: [MAX_BLOCK_TYPES]ContextMode = undefined;
        try readContextModes(&self.br, cat_l.nbltypes, cmode[0..cat_l.nbltypes]);

        var cmapl: [CMAPL_MAX]u8 = undefined;
        const ntreesl = try readBlockTypeCount(&self.br);
        const cmapl_size = 64 * cat_l.nbltypes;
        @memset(cmapl[0..cmapl_size], 0);
        if (ntreesl >= 2) try readContextMap(&self.br, ntreesl, cmapl_size, &cmapl);

        var cmapd: [CMAPD_MAX]u8 = undefined;
        const ntreesd = try readBlockTypeCount(&self.br);
        const cmapd_size = 4 * cat_d.nbltypes;
        @memset(cmapd[0..cmapd_size], 0);
        if (ntreesd >= 2) try readContextMap(&self.br, ntreesd, cmapd_size, &cmapd);

        const htreel = try self.allocator.alloc(HuffmanDecoder, ntreesl);
        defer self.allocator.free(htreel);
        for (htreel) |*tree| tree.* = try readPrefixCode(&self.br, 256);

        const htreei = try self.allocator.alloc(HuffmanDecoder, cat_i.nbltypes);
        defer self.allocator.free(htreei);
        for (htreei) |*tree| tree.* = try readPrefixCode(&self.br, 704);

        const dist_alphabet = 16 + ndirect + (@as(u32, 48) << @intCast(npostfix));
        const htreed = try self.allocator.alloc(HuffmanDecoder, ntreesd);
        defer self.allocator.free(htreed);
        for (htreed) |*tree| tree.* = try readPrefixCode(&self.br, dist_alphabet);

        try self.out.ensureUnusedCapacity(self.allocator, mlen);

        var produced: u32 = 0;
        while (produced < mlen) {
            try cat_i.consume(&self.br);
            const command = try htreei[cat_i.btype].readSymbol(&self.br);
            const ic = splitInsertCopy(command);

            const insert_len = INSERT_LEN_BASE[ic.insert_code] + try self.br.readBits(INSERT_LEN_EXTRA[ic.insert_code]);
            const copy_len = COPY_LEN_BASE[ic.copy_code] + try self.br.readBits(COPY_LEN_EXTRA[ic.copy_code]);

            var k: u32 = 0;
            while (k < insert_len) : (k += 1) {
                try cat_l.consume(&self.br);
                const cid = literalContextId(cmode[cat_l.btype], self.p1, self.p2);
                const lit: u8 = @intCast(try htreel[cmapl[64 * cat_l.btype + cid]].readSymbol(&self.br));

                try self.pushByte(lit);
                produced += 1;
                if (produced == mlen) return;
            }

            var distance: u32 = undefined;
            var push_candidate = false;
            if (ic.distance_zero) {
                distance = self.ring.d[0];
            } else {
                try cat_d.consume(&self.br);
                const cid = distanceContextId(copy_len);
                const dcode = try htreed[cmapd[4 * cat_d.btype + cid]].readSymbol(&self.br);
                const d = try readDistance(&self.br, dcode, &self.ring, npostfix, ndirect);
                distance = d.value;
                push_candidate = d.push;
            }

            const max_allowed: u32 = @min(self.window_size, @as(u32, @intCast(self.out.items.len)));
            if (distance <= max_allowed) {
                // A real backward reference: push to the ring buffer here, after confirming
                // it is not a dictionary reference (sec 4, dictionary refs are not pushed).
                if (push_candidate) self.ring.push(distance);

                var j: u32 = 0;
                while (j < copy_len and produced < mlen) : (j += 1) {
                    const b = self.out.items[self.out.items.len - distance];

                    try self.pushByte(b);
                    produced += 1;
                }
            } else {
                var word: [38]u8 = undefined;
                const written = try dictionaryWord(copy_len, distance, max_allowed, &word);

                for (word[0..written]) |b| try self.pushByte(b);
                produced += @intCast(written);
            }
        }
    }
};

// --------------------------------------------------------- //
// Encoder: bit writer and canonical codes (sec 1.5.1, sec 3.2)

/// Errors the encoder can raise. InvalidWindowBits and InputTooLarge are brotli-specific
/// validation. BufferTooSmall and OutOfMemory are shared with flate.EncodeError, so the
/// into-buffer compress (compressBrotli) reports the same overflow error as compressGzip.
/// InputTooLarge guards the single-meta-block compressed path. The store path splits instead,
/// so it is the compressed encoder's limit.
pub const EncodeError = error{
    ZixInvalidWindowBits,
    ZixInputTooLarge,
    ZixBufferTooSmall,
    OutOfMemory,
};

/// LSB-first bit writer. Integer fields are packed LSB-first (writeInt), prefix-code bits
/// MSB-first (writeCode), matching the decoder's reader (sec 1.5.1).
const BitWriter = struct {
    bytes: std.ArrayList(u8) = .empty,
    bit_pos: u3 = 0,

    fn deinit(self: *BitWriter, allocator: std.mem.Allocator) void {
        self.bytes.deinit(allocator);
    }

    fn writeBit(self: *BitWriter, allocator: std.mem.Allocator, bit: u1) EncodeError!void {
        if (self.bit_pos == 0) try self.bytes.append(allocator, 0);

        const idx = self.bytes.items.len - 1;
        self.bytes.items[idx] |= @as(u8, bit) << self.bit_pos;
        self.bit_pos = if (self.bit_pos == 7) 0 else self.bit_pos + 1;
    }

    /// An integer field, least-significant bit first.
    fn writeInt(self: *BitWriter, allocator: std.mem.Allocator, value: u32, n: u6) EncodeError!void {
        var i: u6 = 0;
        while (i < n) : (i += 1) {
            try self.writeBit(allocator, @truncate(value >> @intCast(i)));
        }
    }

    /// A prefix-code value, most-significant bit first (how canonical codes are packed).
    fn writeCode(self: *BitWriter, allocator: std.mem.Allocator, value: u32, n: u6) EncodeError!void {
        var i: u6 = n;
        while (i > 0) {
            i -= 1;
            try self.writeBit(allocator, @truncate(value >> @intCast(i)));
        }
    }

    /// Advance to the next byte boundary, leaving the skipped bits as zero padding.
    fn alignToByte(self: *BitWriter) void {
        if (self.bit_pos != 0) self.bit_pos = 0;
    }

    /// Append whole bytes. Only valid right after alignToByte (the writer is byte-aligned).
    fn writeBytes(self: *BitWriter, allocator: std.mem.Allocator, data: []const u8) EncodeError!void {
        try self.bytes.appendSlice(allocator, data);
    }

    fn toOwnedSlice(self: *BitWriter, allocator: std.mem.Allocator) EncodeError![]u8 {
        return self.bytes.toOwnedSlice(allocator);
    }
};

/// Canonical prefix-code values from per-symbol code lengths, the encoder twin of the
/// decoder's HuffmanDecoder.build (sec 3.2). codes_out[s] holds the MSB-first code for
/// symbol s, valid only where lengths[s] != 0.
fn buildCanonicalCodes(lengths: []const u8, codes_out: []u16) void {
    var count = std.mem.zeroes([MAX_CODE_LEN + 1]u16);
    for (lengths) |len| {
        if (len != 0) count[len] += 1;
    }

    var next_code = std.mem.zeroes([MAX_CODE_LEN + 1]u16);
    var code: u16 = 0;
    var len: usize = 1;
    while (len <= MAX_CODE_LEN) : (len += 1) {
        code = (code + count[len - 1]) << 1;
        next_code[len] = code;
    }

    for (lengths, 0..) |len_s, s| {
        if (len_s != 0) {
            codes_out[s] = next_code[len_s];
            next_code[len_s] += 1;
        }
    }
}

/// Emit the stream window size, the inverse of the decoder's readWindowBits (sec 9.1).
fn writeWindowBits(bw: *BitWriter, allocator: std.mem.Allocator, wbits: u6) EncodeError!void {
    if (wbits < 10 or wbits > 24) return error.ZixInvalidWindowBits;

    if (wbits == 16) {
        try bw.writeBit(allocator, 0);
        return;
    }

    try bw.writeBit(allocator, 1);

    if (wbits >= 18 and wbits <= 24) {
        try bw.writeInt(allocator, wbits - 17, 3);
        return;
    }

    try bw.writeInt(allocator, 0, 3);
    if (wbits == 17) {
        try bw.writeInt(allocator, 0, 3);
        return;
    }

    try bw.writeInt(allocator, wbits - 8, 3);
}

/// Emit MNIBBLES + (MLEN - 1) with the minimal nibble count (sec 9.2).
fn writeMetaBlockLen(bw: *BitWriter, allocator: std.mem.Allocator, mlen: usize) EncodeError!void {
    const value: u32 = @intCast(mlen - 1);

    const nibbles: u6 = if (value < (1 << 16)) 4 else if (value < (1 << 20)) 5 else 6;

    try bw.writeInt(allocator, nibbles - 4, 2);
    try bw.writeInt(allocator, value, nibbles * 4);
}

/// A balanced (complete) set of code lengths over count distinct leaves, lengths within
/// one bit of log2(count). Returns the max length used. count must be >= 1.
fn balancedLengths(count: usize, out: []u8) u8 {
    if (count == 1) {
        out[0] = 1;
        return 1;
    }

    var log2_ceil: u8 = 0;
    while ((@as(usize, 1) << @intCast(log2_ceil)) < count) log2_ceil += 1;

    const capacity = @as(usize, 1) << @intCast(log2_ceil);
    const n_short = capacity - count; // leaves at depth log2_ceil - 1
    var i: usize = 0;
    while (i < count) : (i += 1) out[i] = if (i < n_short) log2_ceil - 1 else log2_ceil;

    return log2_ceil;
}

/// Largest insert-length code whose base is within reach of value (sec 5). The contiguous
/// code ranges guarantee the remainder fits the code's extra bits.
fn selectInsertCode(value: u32) u8 {
    var code: u8 = @intCast(INSERT_LEN_BASE.len - 1);
    while (INSERT_LEN_BASE[code] > value) code -= 1;

    return code;
}

/// Largest copy-length code whose base is within reach of value (sec 5).
fn selectCopyCode(value: u32) u8 {
    var code: u8 = @intCast(COPY_LEN_BASE.len - 1);
    while (COPY_LEN_BASE[code] > value) code -= 1;

    return code;
}

/// Emit a single-symbol prefix code in the simple format (sec 3.4, NSYM=1): selector 1,
/// NSYM-1 = 0, then the symbol value. The decoder returns it with no bits consumed.
fn writeSingleSymbolCode(bw: *BitWriter, allocator: std.mem.Allocator, symbol: u16, alphabet_size: usize) EncodeError!void {
    try bw.writeInt(allocator, 1, 2);
    try bw.writeInt(allocator, 0, 2);
    try bw.writeInt(allocator, symbol, alphabetBits(alphabet_size));
}

/// The static code-length-code table (sec 3.5), one entry per code-length value 0..5,
/// each the bit sequence the decoder reads (in stream order).
const CL_LEN_BITS = [6][]const u1{
    &[_]u1{ 0, 0 }, // 0
    &[_]u1{ 1, 1, 1, 0 }, // 1
    &[_]u1{ 1, 1, 0 }, // 2
    &[_]u1{ 0, 1 }, // 3
    &[_]u1{ 1, 0 }, // 4
    &[_]u1{ 1, 1, 1, 1 }, // 5
};

const CL_ORDER = [_]u8{ 1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11, 12, 13, 14, 15 };

/// Emit a complex prefix code (sec 3.5) over any alphabet: HSKIP 0 selector, the
/// code-length-code description, then every per-symbol length up to the last used symbol.
/// The code must have at least two participating symbols (single-symbol codes use the
/// simple format instead).
fn writeComplexCode(bw: *BitWriter, allocator: std.mem.Allocator, lengths: []const u8) EncodeError!void {
    try bw.writeInt(allocator, 0, 2); // selector = HSKIP 0 -> complex

    var last_used: usize = 0;
    for (lengths, 0..) |len, s| {
        if (len != 0) last_used = s;
    }

    // the code-length alphabet uses the distinct length values present in 0..last_used.
    var cl_present = std.mem.zeroes([18]bool);
    var s: usize = 0;
    while (s <= last_used) : (s += 1) cl_present[lengths[s]] = true;

    var cl_distinct: usize = 0;
    var cl_values: [18]u8 = undefined;
    for (cl_present, 0..) |present, v| {
        if (present) {
            cl_values[cl_distinct] = @intCast(v);
            cl_distinct += 1;
        }
    }

    var cl_bal: [18]u8 = undefined;
    _ = balancedLengths(cl_distinct, &cl_bal);

    var cl_lengths = std.mem.zeroes([18]u8);
    var i: usize = 0;
    while (i < cl_distinct) : (i += 1) cl_lengths[cl_values[i]] = cl_bal[i];

    // emit the code-length-code lengths in the fixed order via the static table, stopping
    // the moment the code is complete (space hits 0), exactly as the decoder stops reading.
    var space: i64 = 32;
    for (CL_ORDER) |sym| {
        const cl_len = cl_lengths[sym];
        for (CL_LEN_BITS[cl_len]) |bit| try bw.writeBit(allocator, bit);
        if (cl_len != 0) {
            space -= @as(i64, 32) >> @intCast(cl_len);
            if (space <= 0) break;
        }
    }

    // a single-value code-length-code emits no per-symbol bits (decoder reads it implicitly).
    if (cl_distinct <= 1) return;

    var cl_codes: [18]u16 = undefined;
    buildCanonicalCodes(&cl_lengths, &cl_codes);

    s = 0;
    while (s <= last_used) : (s += 1) {
        const len_val = lengths[s];
        try bw.writeCode(allocator, cl_codes[len_val], @intCast(cl_lengths[len_val]));
    }
}

// --------------------------------------------------------- //
// Encoder: store-only meta-blocks (the never-expand fallback)

/// Encode input as a brotli stream of uncompressed meta-blocks (store-only). Used as the
/// never-expand fallback: a stream that is never larger than the input plus a tiny header.
fn encodeUncompressedAlloc(allocator: std.mem.Allocator, input: []const u8, wbits: u6) EncodeError![]u8 {
    var bw: BitWriter = .{};
    errdefer bw.deinit(allocator);

    try writeWindowBits(&bw, allocator, wbits);

    var offset: usize = 0;
    while (offset < input.len) {
        const chunk = @min(input.len - offset, MAX_META_BLOCK_LEN);

        try bw.writeBit(allocator, 0); // ISLAST = 0
        try writeMetaBlockLen(&bw, allocator, chunk);
        try bw.writeBit(allocator, 1); // ISUNCOMPRESSED = 1

        bw.alignToByte();
        try bw.writeBytes(allocator, input[offset..][0..chunk]);

        offset += chunk;
    }

    // empty last meta-block: ISLAST = 1, ISLASTEMPTY = 1 (sec 9.2).
    try bw.writeBit(allocator, 1);
    try bw.writeBit(allocator, 1);

    return bw.toOwnedSlice(allocator);
}

// --------------------------------------------------------- //
// Encoder: LZ77 + distance codes + optimal Huffman + dictionary (sec 3, 4, 5, 8)

const MIN_MATCH: usize = 4;
const MAX_MATCH: usize = 16384; // bound the copy length to keep extra bits small
const HASH_BITS = 17;
const HASH_SIZE: usize = 1 << HASH_BITS;
const MAX_CHAIN: usize = 64; // hash-chain walk limit per position
const NO_POS: u32 = std.math.maxInt(u32);

const DICT_MIN_LEN: usize = 4;
const DICT_MAX_LEN: usize = 24;
const DHASH_BITS = 15;
const DHASH_SIZE: usize = 1 << DHASH_BITS;
const MAX_BITS: u8 = 15;

const DistanceCode = struct {
    code: u16,
    extra: u32,
    nextra: u6,
};

/// Encode a backward distance into its distance code and extra bits, the inverse of the
/// decoder's readDistance with NPOSTFIX=0 and NDIRECT=0 (sec 4). The codes split into two
/// interleaved series (even and odd dadj) whose value ranges tile 1, 2, 3, ... exactly.
fn distanceCode(value: u32) DistanceCode {
    var n: u5 = 1;
    while (n < 25) : (n += 1) {
        const span = @as(u32, 1) << n;

        const even_base = (@as(u32, 2) << n) - 3; // dadj = 2*(n-1), bit 0 = 0
        if (value >= even_base and value < even_base + span) {
            return .{ .code = 16 + 2 * (@as(u16, n) - 1), .extra = value - even_base, .nextra = n };
        }

        const odd_base = (@as(u32, 3) << n) - 3; // dadj = 2*(n-1)+1, bit 0 = 1
        if (value >= odd_base and value < odd_base + span) {
            return .{ .code = 16 + 2 * (@as(u16, n) - 1) + 1, .extra = value - odd_base, .nextra = n };
        }
    }

    unreachable; // every distance in a 2^24 window lands in a bucket with n <= 24
}

// The cell of the insert-and-copy table per (insert band, copy band), each band 0..2 for
// codes 0..7 / 8..15 / 16..23. All these cells encode an explicit distance (cmd >= 128).
const CELL_BY_BAND = [3][3]u16{
    .{ 2, 3, 6 },
    .{ 4, 5, 8 },
    .{ 7, 9, 10 },
};

/// Compose an insert-and-copy command symbol that carries an explicit distance (sec 5).
fn composeCommandExplicit(insert_code: u8, copy_code: u8) u16 {
    const insert_band = insert_code / 8;
    const copy_band = copy_code / 8;
    const cell = CELL_BY_BAND[insert_band][copy_band];

    return cell * 64 + (@as(u16, insert_code % 8) << 3) + (copy_code % 8);
}

/// The short distance code (0..15) that resolves to value, or null if none does (sec 4).
fn matchRingCode(ring: DistanceRing, value: u32) ?u16 {
    if (value == ring.d[0]) return 0;
    if (value == ring.d[1]) return 1;
    if (value == ring.d[2]) return 2;
    if (value == ring.d[3]) return 3;

    const offsets = [_]i64{ -1, 1, -2, 2, -3, 3 };
    for (offsets, 0..) |off, k| {
        const cand = @as(i64, ring.d[0]) + off;
        if (cand > 0 and @as(u32, @intCast(cand)) == value) return @intCast(4 + k);
    }
    for (offsets, 0..) |off, k| {
        const cand = @as(i64, ring.d[1]) + off;
        if (cand > 0 and @as(u32, @intCast(cand)) == value) return @intCast(10 + k);
    }

    return null;
}

/// Pick the cheapest distance code for value given the current ring, and advance the ring
/// exactly as the decoder would (sec 4). Short codes 1..15 push the resolved distance, code
/// 0 leaves the ring unchanged, the explicit code pushes too.
fn chooseDistance(ring: *DistanceRing, value: u32) DistanceCode {
    const short = matchRingCode(ring.*, value);
    if (short) |code| {
        if (code != 0) ring.push(value);

        return .{ .code = code, .extra = 0, .nextra = 0 };
    }

    const dc = distanceCode(value);
    ring.push(value);

    return dc;
}

const TreeCode = struct {
    lengths: []u8,
    codes: []u16,
    present: usize,
    single: u16,
};

fn writeTreeCode(bw: *BitWriter, allocator: std.mem.Allocator, tree: TreeCode, alphabet_size: usize) EncodeError!void {
    if (tree.present <= 1) {
        try writeSingleSymbolCode(bw, allocator, tree.single, alphabet_size);
        return;
    }

    try writeComplexCode(bw, allocator, tree.lengths);
}

/// Optimal length-limited Huffman code lengths over freq (sec 3.2). A single present symbol
/// gets length 0 (a zero-bit code). The rest are exact-merge Huffman lengths capped at
/// MAX_BITS via the standard overflow redistribution, assigned shortest to most frequent.
fn huffmanLengths(allocator: std.mem.Allocator, freq: []const u32, lengths_out: []u8) EncodeError!void {
    @memset(lengths_out, 0);

    var present: usize = 0;
    for (freq) |f| {
        if (f != 0) present += 1;
    }
    if (present < 2) return;

    // order: present symbols, sorted by frequency ascending (least frequent first).
    const order = try allocator.alloc(usize, present);
    defer allocator.free(order);
    {
        var idx: usize = 0;
        for (freq, 0..) |f, s| {
            if (f != 0) {
                order[idx] = s;
                idx += 1;
            }
        }
        std.mem.sort(usize, order, freq, struct {
            fn lt(freqs: []const u32, idx_a: usize, idx_b: usize) bool {
                return freqs[idx_a] < freqs[idx_b];
            }
        }.lt);
    }

    // exact Huffman by repeated merge of the two lightest nodes (O(n^2), fine for <= 704).
    const max_nodes = 2 * present - 1;
    const weight = try allocator.alloc(u64, max_nodes);
    defer allocator.free(weight);
    const parent = try allocator.alloc(usize, max_nodes);
    defer allocator.free(parent);
    const alive = try allocator.alloc(bool, max_nodes);
    defer allocator.free(alive);

    @memset(parent, std.math.maxInt(usize));
    @memset(alive, false);
    for (0..present) |i| {
        weight[i] = freq[order[i]];
        alive[i] = true;
    }

    var next = present;
    var remaining = present;
    while (remaining > 1) {
        var m1: usize = std.math.maxInt(usize);
        var m2: usize = std.math.maxInt(usize);
        for (0..next) |j| {
            if (!alive[j]) continue;
            if (m1 == std.math.maxInt(usize) or weight[j] < weight[m1]) {
                m2 = m1;
                m1 = j;
            } else if (m2 == std.math.maxInt(usize) or weight[j] < weight[m2]) {
                m2 = j;
            }
        }

        weight[next] = weight[m1] + weight[m2];
        parent[m1] = next;
        parent[m2] = next;
        alive[m1] = false;
        alive[m2] = false;
        alive[next] = true;
        next += 1;
        remaining -= 1;
    }

    // raw depth of each leaf = its code length before the 15-bit cap.
    var count = std.mem.zeroes([64]u32);
    var raw_max: u8 = 0;
    const raw_len = try allocator.alloc(u8, present);
    defer allocator.free(raw_len);
    for (0..present) |i| {
        var depth: u8 = 0;
        var node = i;
        while (parent[node] != std.math.maxInt(usize)) : (depth += 1) node = parent[node];
        raw_len[i] = depth;
        count[depth] += 1;
        if (depth > raw_max) raw_max = depth;
    }

    // cap lengths at MAX_BITS: move the overflow to MAX_BITS, then redistribute (zlib rule).
    var overflow: i64 = 0;
    var bits: usize = MAX_BITS + 1;
    while (bits <= raw_max) : (bits += 1) overflow += count[bits];

    if (overflow > 0) {
        bits = MAX_BITS + 1;
        while (bits <= raw_max) : (bits += 1) {
            count[MAX_BITS] += count[bits];
            count[bits] = 0;
        }

        while (overflow > 0) {
            var b: usize = MAX_BITS - 1;
            while (count[b] == 0) b -= 1;
            count[b] -= 1;
            count[b + 1] += 2;
            count[MAX_BITS] -= 1;
            overflow -= 2;
        }
    }

    // assign lengths shortest-to-most-frequent (order is ascending, so walk it from the end).
    var idx: usize = present;
    var len: usize = 1;
    while (len <= MAX_BITS) : (len += 1) {
        var c = count[len];
        while (c > 0) : (c -= 1) {
            idx -= 1;
            lengths_out[order[idx]] = @intCast(len);
        }
    }
}

/// Build an optimal Huffman tree over an alphabet from symbol frequencies, returning the
/// TreeCode shape so writeTreeCode can emit it. Caller owns lengths and codes.
fn buildOptimalTree(allocator: std.mem.Allocator, freq: []const u32, alphabet_size: usize) EncodeError!TreeCode {
    const lengths = try allocator.alloc(u8, alphabet_size);
    @memset(lengths, 0);
    const codes = try allocator.alloc(u16, alphabet_size);

    var present: usize = 0;
    var single: u16 = 0;
    for (freq, 0..) |f, s| {
        if (f != 0) {
            present += 1;
            single = @intCast(s);
        }
    }

    if (present >= 2) {
        try huffmanLengths(allocator, freq, lengths);
        buildCanonicalCodes(lengths, codes);
    }

    return .{ .lengths = lengths, .codes = codes, .present = present, .single = single };
}

fn hash4(bytes: []const u8, pos: usize, comptime bits: u6) usize {
    const v = std.mem.readInt(u32, bytes[pos..][0..4], .little);

    return (v *% 0x9E3779B1) >> (32 - bits);
}

const Command = struct {
    insert_len: u32,
    lit_off: usize,
    copy_len: u32, // 0 marks a trailing insert-only command (the copy is skipped at MLEN)
    distance: u32,
    is_dict: bool,
};

/// Encoder effort, set by the quality ladder. max_chain bounds the hash-chain walk,
/// use_dict toggles the static dictionary search, literal_contexts turns on the
/// per-context literal trees (sec 7, a ratio win on larger text).
const Params = struct {
    max_chain: usize = MAX_CHAIN,
    use_dict: bool = true,
    literal_contexts: bool = false,
};

/// A context needs at least this many literals before it earns its own literal tree.
/// Below it the context folds into the shared tree, so the per-tree header overhead is
/// only spent where it pays for itself.
const LIT_CONTEXT_THRESHOLD: u32 = 256;

/// A hash index over the identity dictionary words, chained by their first four bytes.
const DictIndex = struct {
    head: []u32,
    next: []u32,
    word_len: []u8,
    word_index: []u32,
    word_off: []u32,

    fn build(allocator: std.mem.Allocator) EncodeError!DictIndex {
        var total: usize = 0;
        var len: usize = DICT_MIN_LEN;
        while (len <= DICT_MAX_LEN) : (len += 1) total += numWords(len);

        var self: DictIndex = .{
            .head = try allocator.alloc(u32, DHASH_SIZE),
            .next = try allocator.alloc(u32, total),
            .word_len = try allocator.alloc(u8, total),
            .word_index = try allocator.alloc(u32, total),
            .word_off = try allocator.alloc(u32, total),
        };
        @memset(self.head, NO_POS);

        var entry: u32 = 0;
        len = DICT_MIN_LEN;
        while (len <= DICT_MAX_LEN) : (len += 1) {
            const words = numWords(len);
            var index: u32 = 0;
            while (index < words) : (index += 1) {
                const off = DOFFSET[len] + index * @as(u32, @intCast(len));
                const h = hash4(DICT, off, DHASH_BITS);

                self.word_len[entry] = @intCast(len);
                self.word_index[entry] = index;
                self.word_off[entry] = off;
                self.next[entry] = self.head[h];
                self.head[h] = entry;
                entry += 1;
            }
        }

        return self;
    }

    /// The longest identity dictionary word that equals the input at pos, or length 0.
    fn longestMatch(self: DictIndex, input: []const u8, pos: usize, best_index: *u32) usize {
        if (pos + 4 > input.len) return 0;

        const h = hash4(input, pos, DHASH_BITS);
        var entry = self.head[h];
        var best_len: usize = 0;
        var chain: usize = 0;
        while (entry != NO_POS and chain < 64) : (chain += 1) {
            const len: usize = self.word_len[entry];
            if (len > best_len and pos + len <= input.len) {
                const word = DICT[self.word_off[entry] .. self.word_off[entry] + len];
                if (std.mem.eql(u8, word, input[pos .. pos + len])) {
                    best_len = len;
                    best_index.* = self.word_index[entry];
                }
            }

            entry = self.next[entry];
        }

        return best_len;
    }
};

/// Greedy parse that considers both a local hash-chain match and a dictionary word at each
/// position, taking whichever is usable (a local back-reference is preferred when present).
fn parseWithDict(allocator: std.mem.Allocator, input: []const u8, wbits: u6, dindex: DictIndex, params: Params, commands: *std.ArrayList(Command)) EncodeError!void {
    const window: u32 = (@as(u32, 1) << @intCast(wbits)) - 16;

    const head = try allocator.alloc(u32, HASH_SIZE);
    defer allocator.free(head);
    @memset(head, NO_POS);

    const prev = try allocator.alloc(u32, input.len);
    defer allocator.free(prev);

    var lit_start: usize = 0;
    var i: usize = 0;
    while (i + MIN_MATCH <= input.len) {
        const h = hash4(input, i, HASH_BITS);

        var local_len: usize = 0;
        var local_dist: u32 = 0;
        var cand = head[h];
        var chain: usize = 0;
        while (cand != NO_POS and chain < params.max_chain) : (chain += 1) {
            const dist = i - cand;
            if (dist > window) break;

            const limit = @min(MAX_MATCH, input.len - i);
            var len: usize = 0;
            while (len < limit and input[cand + len] == input[i + len]) len += 1;
            if (len > local_len) {
                local_len = len;
                local_dist = @intCast(dist);
            }

            cand = prev[cand];
        }

        prev[i] = head[h];
        head[h] = @intCast(i);

        var dict_index: u32 = 0;
        const dict_len = if (params.use_dict) dindex.longestMatch(input, i, &dict_index) else 0;

        // a local back-reference is cheap. A dictionary reference costs a large distance, so
        // only reach for the dictionary when there is no usable local match (the gap case).
        const use_local = local_len >= MIN_MATCH;
        const use_dict = !use_local and dict_len >= MIN_MATCH;

        if (use_dict or use_local) {
            var c = Command{
                .insert_len = @intCast(i - lit_start),
                .lit_off = lit_start,
                .copy_len = 0,
                .distance = 0,
                .is_dict = use_dict,
            };

            if (use_dict) {
                const max_allowed: u32 = @intCast(@min(@as(usize, window), i));
                c.copy_len = @intCast(dict_len);
                c.distance = dict_index + max_allowed + 1;
            } else {
                c.copy_len = @intCast(local_len);
                c.distance = local_dist;
            }
            try commands.append(allocator, c);

            const match_len = c.copy_len;
            var j = i + 1;
            const end = i + match_len;
            while (j < end and j + MIN_MATCH <= input.len) : (j += 1) {
                const hj = hash4(input, j, HASH_BITS);
                prev[j] = head[hj];
                head[hj] = @intCast(j);
            }

            i = end;
            lit_start = i;
        } else {
            i += 1;
        }
    }

    if (lit_start < input.len) {
        try commands.append(allocator, .{
            .insert_len = @intCast(input.len - lit_start),
            .lit_off = lit_start,
            .copy_len = 0,
            .distance = 0,
            .is_dict = false,
        });
    }
}

/// Emit NBLTYPES / NTREES as the variable-length count (sec 9.2), the inverse of
/// readBlockTypeCount. value is 1..256.
fn writeBlockTypeCount(bw: *BitWriter, allocator: std.mem.Allocator, value: u32) EncodeError!void {
    if (value == 1) {
        try bw.writeBit(allocator, 0);
        return;
    }

    try bw.writeBit(allocator, 1);

    const m = value - 1;
    const n: u6 = @intCast(31 - @clz(m));
    try bw.writeInt(allocator, n, 3);
    try bw.writeInt(allocator, m - (@as(u32, 1) << @intCast(n)), n);
}

/// Emit a context map of `ntrees` trees over its values (sec 7.3 inverse): RLEMAX = 0, a
/// prefix code over the tree indices, the values one by one, IMTF off. With RLEMAX = 0 and
/// IMTF off the decoder reads each value straight back (no run-length, no move-to-front).
fn writeContextMap(bw: *BitWriter, allocator: std.mem.Allocator, cmap: []const u8, ntrees: usize) EncodeError!void {
    try bw.writeBit(allocator, 0); // RLEMAX = 0

    var freq = std.mem.zeroes([64]u32);
    for (cmap) |v| freq[v] += 1;

    const code = try buildOptimalTree(allocator, freq[0..ntrees], ntrees);
    try writeTreeCode(bw, allocator, code, ntrees);

    if (code.present > 1) {
        for (cmap) |v| try bw.writeCode(allocator, code.codes[v], @intCast(code.lengths[v]));
    }

    try bw.writeBit(allocator, 0); // IMTF off
}

/// The literal coding plan for a meta-block: either one flat tree, or, when context
/// modeling earns its keep, a UTF8 context mode (sec 7.1) with several trees selected per
/// literal by the two preceding output bytes through a context map.
const LitModel = struct {
    contexts: bool,
    mode: ContextMode = .LSB6,
    ntrees: u32 = 1,
    cmap: [64]u8 = std.mem.zeroes([64]u8),
    trees: []TreeCode = &.{},
    flat: TreeCode = undefined,

    /// The literal tree for the byte at input position j. The decoder derives the same
    /// context from its last two emitted bytes, which equal input[j-1] and input[j-2]
    /// because the output so far is exactly the input prefix.
    fn treeFor(self: *const LitModel, input: []const u8, index: usize) *const TreeCode {
        if (!self.contexts) return &self.flat;

        const c1: u8 = if (index >= 1) input[index - 1] else 0;
        const c2: u8 = if (index >= 2) input[index - 2] else 0;
        const ctx = literalContextId(self.mode, c1, c2);

        return &self.trees[self.cmap[ctx]];
    }
};

/// Build the literal coding plan. Without contexts it is one optimal tree over all
/// literals. With contexts each UTF8 context (sec 7.1) that carries at least
/// LIT_CONTEXT_THRESHOLD literals gets its own optimal tree. Sparser contexts share tree
/// 0. If no context earns a split it degrades to the single flat tree.
fn buildLitModel(scratch: std.mem.Allocator, input: []const u8, commands: []const Command, contexts: bool) EncodeError!LitModel {
    if (!contexts) {
        var lit_freq = std.mem.zeroes([LITERAL_ALPHABET]u32);
        for (commands) |c| {
            var k: usize = 0;
            while (k < c.insert_len) : (k += 1) lit_freq[input[c.lit_off + k]] += 1;
        }

        return .{ .contexts = false, .flat = try buildOptimalTree(scratch, &lit_freq, LITERAL_ALPHABET) };
    }

    const mode: ContextMode = .UTF8;

    const ctx_freq = try scratch.alloc([LITERAL_ALPHABET]u32, 64);
    for (ctx_freq) |*row| row.* = std.mem.zeroes([LITERAL_ALPHABET]u32);
    var ctx_count = std.mem.zeroes([64]u32);

    for (commands) |c| {
        var k: usize = 0;
        while (k < c.insert_len) : (k += 1) {
            const j = c.lit_off + k;
            const c1: u8 = if (j >= 1) input[j - 1] else 0;
            const c2: u8 = if (j >= 2) input[j - 2] else 0;
            const ctx = literalContextId(mode, c1, c2);

            ctx_freq[ctx][input[j]] += 1;
            ctx_count[ctx] += 1;
        }
    }

    // assign trees: a populous context gets its own, the rest fold into tree 0.
    const tree_freq = try scratch.alloc([LITERAL_ALPHABET]u32, 64);
    for (tree_freq) |*row| row.* = std.mem.zeroes([LITERAL_ALPHABET]u32);
    var cmap = std.mem.zeroes([64]u8);
    var ntrees: u32 = 1;
    for (0..64) |c| {
        if (ctx_count[c] >= LIT_CONTEXT_THRESHOLD) {
            cmap[c] = @intCast(ntrees);
            for (0..LITERAL_ALPHABET) |b| tree_freq[ntrees][b] = ctx_freq[c][b];
            ntrees += 1;
        } else {
            for (0..LITERAL_ALPHABET) |b| tree_freq[0][b] += ctx_freq[c][b];
        }
    }

    if (ntrees == 1) {
        // no context split earned its keep. Fall back to one flat tree over all literals.
        return .{ .contexts = false, .flat = try buildOptimalTree(scratch, &tree_freq[0], LITERAL_ALPHABET) };
    }

    const trees = try scratch.alloc(TreeCode, ntrees);
    for (0..ntrees) |t| trees[t] = try buildOptimalTree(scratch, &tree_freq[t], LITERAL_ALPHABET);

    return .{ .contexts = true, .mode = mode, .ntrees = ntrees, .cmap = cmap, .trees = trees };
}

/// Encode input as a single compressed brotli meta-block: greedy LZ77 with the static
/// dictionary, ring-buffer distances, and optimal per-block Huffman codes (sec 3..8).
fn encodeCompressedAlloc(allocator: std.mem.Allocator, input: []const u8, wbits: u6, params: Params) EncodeError![]u8 {
    if (input.len > MAX_META_BLOCK_LEN) return error.ZixInputTooLarge;

    var bw: BitWriter = .{};
    errdefer bw.deinit(allocator);

    try writeWindowBits(&bw, allocator, wbits);

    if (input.len == 0) {
        try bw.writeBit(allocator, 1);
        try bw.writeBit(allocator, 1);

        return bw.toOwnedSlice(allocator);
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();

    const dindex = try DictIndex.build(scratch);

    var commands: std.ArrayList(Command) = .empty;
    try parseWithDict(scratch, input, wbits, dindex, params, &commands);

    // distances: dict references use the explicit code without touching the ring, local
    // matches use the ring (sec 4, 8).
    const chosen = try scratch.alloc(DistanceCode, commands.items.len);
    var ring = DistanceRing{};
    for (commands.items, 0..) |c, idx| {
        if (c.copy_len == 0) continue;

        chosen[idx] = if (c.is_dict) distanceCode(c.distance) else chooseDistance(&ring, c.distance);
    }

    var cmd_freq = std.mem.zeroes([COMMAND_ALPHABET]u32);
    var dist_freq = std.mem.zeroes([DISTANCE_ALPHABET]u32);
    for (commands.items, 0..) |c, idx| {
        const insert_code = selectInsertCode(c.insert_len);
        if (c.copy_len > 0) {
            cmd_freq[composeCommandExplicit(insert_code, selectCopyCode(c.copy_len))] += 1;
            dist_freq[chosen[idx].code] += 1;
        } else {
            cmd_freq[composeCommandExplicit(insert_code, 0)] += 1;
        }
    }

    const lit_model = try buildLitModel(scratch, input, commands.items, params.literal_contexts);
    const cmd_code = try buildOptimalTree(scratch, &cmd_freq, COMMAND_ALPHABET);
    const dist_code = try buildOptimalTree(scratch, &dist_freq, DISTANCE_ALPHABET);

    try bw.writeBit(allocator, 1); // ISLAST = 1
    try bw.writeBit(allocator, 0); // ISLASTEMPTY = 0
    try writeMetaBlockLen(&bw, allocator, input.len);
    try bw.writeBit(allocator, 0); // NBLTYPESL = 1
    try bw.writeBit(allocator, 0); // NBLTYPESI = 1
    try bw.writeBit(allocator, 0); // NBLTYPESD = 1
    try bw.writeInt(allocator, 0, 2); // NPOSTFIX = 0
    try bw.writeInt(allocator, 0, 4); // NDIRECT = 0

    if (lit_model.contexts) {
        try bw.writeInt(allocator, @intFromEnum(lit_model.mode), 2);
        try writeBlockTypeCount(&bw, allocator, lit_model.ntrees); // NTREESL
        try writeContextMap(&bw, allocator, lit_model.cmap[0..64], lit_model.ntrees);
    } else {
        try bw.writeInt(allocator, @intFromEnum(ContextMode.LSB6), 2);
        try writeBlockTypeCount(&bw, allocator, 1); // NTREESL = 1
    }
    try writeBlockTypeCount(&bw, allocator, 1); // NTREESD = 1

    if (lit_model.contexts) {
        for (lit_model.trees) |t| try writeTreeCode(&bw, allocator, t, LITERAL_ALPHABET);
    } else {
        try writeTreeCode(&bw, allocator, lit_model.flat, LITERAL_ALPHABET);
    }
    try writeTreeCode(&bw, allocator, cmd_code, COMMAND_ALPHABET);
    try writeTreeCode(&bw, allocator, dist_code, DISTANCE_ALPHABET);

    for (commands.items, 0..) |c, idx| {
        const insert_code = selectInsertCode(c.insert_len);
        const copy_code: u8 = if (c.copy_len > 0) selectCopyCode(c.copy_len) else 0;
        const sym = composeCommandExplicit(insert_code, copy_code);

        try bw.writeCode(allocator, cmd_code.codes[sym], @intCast(cmd_code.lengths[sym]));
        try bw.writeInt(allocator, c.insert_len - INSERT_LEN_BASE[insert_code], INSERT_LEN_EXTRA[insert_code]);

        const copy_value: u32 = if (c.copy_len > 0) c.copy_len else COPY_LEN_BASE[0];
        try bw.writeInt(allocator, copy_value - COPY_LEN_BASE[copy_code], COPY_LEN_EXTRA[copy_code]);

        var k: usize = 0;
        while (k < c.insert_len) : (k += 1) {
            const j = c.lit_off + k;
            const lt = lit_model.treeFor(input, j);
            try bw.writeCode(allocator, lt.codes[input[j]], @intCast(lt.lengths[input[j]]));
        }

        if (c.copy_len > 0) {
            const dc = chosen[idx];
            try bw.writeCode(allocator, dist_code.codes[dc.code], @intCast(dist_code.lengths[dc.code]));
            try bw.writeInt(allocator, dc.extra, dc.nextra);
        }
    }

    return bw.toOwnedSlice(allocator);
}

/// Map a quality 0..11 to encoder effort. q0 is greedy with no dictionary. Higher q widens
/// the match search and turns the dictionary on. The chain depth is bounded so the top of
/// the ladder stays cheap (a response compressor wants a modest level, not q11).
fn qualityParams(quality: u8) Params {
    const q = @min(quality, 11);

    if (q == 0) return .{ .max_chain = 1, .use_dict = false };

    return .{
        .max_chain = @as(usize, 1) << @intCast(@min(q, 9)),
        .use_dict = q >= 2,
    };
}

// --------------------------------------------------------- //
// Public API. Mirrors flate.zig's four-function codec shape (a buffer-into and an alloc variant
// for each direction, plus compressBound), so the compression facade dispatches uniformly and a
// caller can swap codecs without changing call shape.

/// Errors the decoder surfaces to the caller, identical to flate.DecodeError so both codecs report
/// the same vocabulary. Internal format errors collapse to DecompressFailed. An over-cap output on
/// the alloc variant (decompression-bomb guard) is OutputTooLarge. An output that overflows the
/// caller buffer on decompressBrotli is BufferTooSmall.
pub const DecodeError = error{
    ZixDecompressFailed,
    ZixOutputTooLarge,
    ZixBufferTooSmall,
    OutOfMemory,
};

/// Upper bound on the compressed output for a given input length. The store fallback
/// guarantees the output never exceeds the input plus the per-meta-block framing.
///
/// Note:
/// - Stronger guarantee than flate.compressBound. brotli always also tries a store and keeps the
///   smaller, so the output never grows past the input plus this small framing. flate has no store
///   fallback in std, so flate's output can exceed the input on incompressible data and its bound
///   adds input / 8 to cover that. The two bounds are not interchangeable.
///
/// Param:
/// input_len - usize (uncompressed byte count)
///
/// Return:
/// - usize (a length the output is guaranteed to fit within)
pub fn compressBound(input_len: usize) usize {
    const blocks = input_len / MAX_META_BLOCK_LEN + 1;

    return input_len + 6 * blocks + 16;
}

/// Compress data at an explicit quality and window, never larger than a store of the same
/// input. Caller owns the returned slice.
///
/// Note:
/// - Always also produces a store-only stream and returns whichever is smaller, so the
///   output never grows past the input plus the store header (the guarantee a response
///   compressor needs on already-compressed or random bodies).
/// - When the dictionary is on it also encodes a no-dictionary variant and keeps the
///   smaller, so the dictionary never hurts.
///
/// Param:
/// allocator - std.mem.Allocator (owns the returned slice)
/// data - []const u8 (bytes to compress, at most 2^24 for the compressed path)
/// quality - u8 (0..11, clamped)
/// wbits - u6 (window log, 10..24)
///
/// Return:
/// - []u8 (a valid brotli stream, caller frees)
/// - error.ZixInvalidWindowBits / error.ZixInputTooLarge / error.OutOfMemory
pub fn compressQualityAlloc(allocator: std.mem.Allocator, data: []const u8, quality: u8, wbits: u6) EncodeError![]u8 {
    const params = qualityParams(quality);

    var best = try encodeCompressedAlloc(allocator, data, wbits, params);
    errdefer allocator.free(best);

    if (params.use_dict) {
        const no_dict = try encodeCompressedAlloc(allocator, data, wbits, .{ .max_chain = params.max_chain, .use_dict = false });
        if (no_dict.len < best.len) {
            allocator.free(best);
            best = no_dict;
        } else {
            allocator.free(no_dict);
        }
    }

    // a literal context model helps larger text. Try it at higher quality and keep it only
    // when it is smaller, so it never replaces a smaller flat or store result.
    if (quality >= 5) {
        const ctx_variant = try encodeCompressedAlloc(allocator, data, wbits, .{ .max_chain = params.max_chain, .use_dict = params.use_dict, .literal_contexts = true });
        if (ctx_variant.len < best.len) {
            allocator.free(best);
            best = ctx_variant;
        } else {
            allocator.free(ctx_variant);
        }
    }

    const stored = try encodeUncompressedAlloc(allocator, data, wbits);
    if (stored.len < best.len) {
        allocator.free(best);
        return stored;
    }

    allocator.free(stored);
    return best;
}

/// Compress data into a freshly allocated brotli stream, mapping the shared Level to a
/// brotli quality. The HTTP `br` content coding path.
///
/// Note:
/// - FASTEST favours latency (a shallow match search, dictionary on). DEFAULT favours
///   ratio (a deeper search). Both stay well under q11 so a response stays cheap to emit.
///
/// Param:
/// allocator - std.mem.Allocator (owns the returned slice)
/// data - []const u8 (bytes to compress)
/// level - Level (effort)
///
/// Return:
/// - []u8 (a valid brotli stream, caller frees)
/// - error.ZixInvalidWindowBits / error.ZixInputTooLarge / error.OutOfMemory
pub fn compressBrotliAlloc(allocator: std.mem.Allocator, data: []const u8, level: Level) EncodeError![]u8 {
    const quality: u8 = switch (level) {
        .FASTEST => 5,
        .DEFAULT => 9,
    };

    return compressQualityAlloc(allocator, data, quality, default_wbits);
}

/// Compress data into a caller-provided buffer at the shared Level, returning the byte count
/// written. The buffer-into counterpart to compressBrotliAlloc, mirroring flate.compressGzip so the
/// codec layer exposes the same shape for both codecs.
///
/// Note:
/// - Unlike flate.compressGzip, brotli cannot stream straight into out_buf: the encoder runs a
///   multi-variant search (compressed / store / dictionary / context) and keeps the smallest, which
///   is allocate-then-pick. So this compresses through compressBrotliAlloc and copies the result in,
///   still taking an allocator for the transient codec state, freed before return.
/// - out_buf must be at least compressBound(data.len) to be sure any input fits.
///
/// Param:
/// allocator - std.mem.Allocator (transient codec scratch, freed before return)
/// data - []const u8 (bytes to compress)
/// out_buf - []u8 (destination, size via compressBound)
/// level - Level (effort)
///
/// Return:
/// - usize (compressed byte count written into out_buf)
/// - error.ZixBufferTooSmall if out_buf cannot hold the result
/// - error.ZixInvalidWindowBits / error.ZixInputTooLarge / error.OutOfMemory
pub fn compressBrotli(allocator: std.mem.Allocator, data: []const u8, out_buf: []u8, level: Level) EncodeError!usize {
    const stream = try compressBrotliAlloc(allocator, data, level);
    defer allocator.free(stream);

    if (out_buf.len < stream.len) return error.ZixBufferTooSmall;

    @memcpy(out_buf[0..stream.len], stream);

    return stream.len;
}

/// Decompress a brotli stream into a freshly allocated buffer, capped at max_out (a
/// decompression-bomb guard). Caller owns the returned slice.
///
/// Param:
/// allocator - std.mem.Allocator (owns the returned slice)
/// compressed - []const u8 (brotli bytes)
/// max_out - usize (largest output accepted before error.ZixOutputTooLarge)
///
/// Return:
/// - []u8 (the decoded bytes, caller frees)
/// - error.ZixOutputTooLarge if the output would exceed max_out
/// - error.ZixDecompressFailed if the stream is malformed
/// - error.OutOfMemory
pub fn decompressBrotliAlloc(allocator: std.mem.Allocator, compressed: []const u8, max_out: usize) DecodeError![]u8 {
    var stats: Stats = .{};
    var decoder = Decoder{ .allocator = allocator, .br = .{ .bytes = compressed }, .stats = &stats, .limit = max_out };
    errdefer decoder.out.deinit(allocator);

    return decoder.run() catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.ZixOutputTooLarge => error.ZixOutputTooLarge,
        else => error.ZixDecompressFailed,
    };
}

/// Decompress a brotli stream into a caller-provided buffer, returning the inflated byte count.
/// The buffer-into counterpart to decompressBrotliAlloc, mirroring flate.decompressGzip.
///
/// Note:
/// - flate.decompressGzip takes no allocator (std streams inflate without a history window). brotli's
///   decoder needs heap (the output ring it back-references plus the Huffman tables), so this takes
///   one. Output beyond out_buf.len surfaces as error.ZixBufferTooSmall, matching flate's caller-buffer
///   semantics, not OutputTooLarge (which is the alloc variant's decompression-bomb guard).
///
/// Param:
/// allocator - std.mem.Allocator (transient codec scratch, freed before return)
/// compressed - []const u8 (brotli bytes)
/// out_buf - []u8 (destination for the inflated bytes)
///
/// Return:
/// - usize (inflated byte count written into out_buf)
/// - error.ZixBufferTooSmall if the inflated result does not fit out_buf
/// - error.ZixDecompressFailed if the stream is malformed
/// - error.OutOfMemory
pub fn decompressBrotli(allocator: std.mem.Allocator, compressed: []const u8, out_buf: []u8) DecodeError!usize {
    const decoded = decompressBrotliAlloc(allocator, compressed, out_buf.len) catch |err| switch (err) {
        error.ZixOutputTooLarge => return error.ZixBufferTooSmall,
        else => return err,
    };
    defer allocator.free(decoded);

    @memcpy(out_buf[0..decoded.len], decoded);

    return decoded.len;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

fn roundTripQuality(input: []const u8, quality: u8, wbits: u6) !void {
    const stream = try compressQualityAlloc(testing.allocator, input, quality, wbits);
    defer testing.allocator.free(stream);

    const back = try decompressBrotliAlloc(testing.allocator, stream, 1 << 20);
    defer testing.allocator.free(back);

    try testing.expectEqualSlices(u8, input, back);
}

test "zix compression: brotli empty input round-trips at every quality" {
    var q: u8 = 0;
    while (q <= 11) : (q += 1) try roundTripQuality("", q, 22);
}

test "zix compression: brotli short ascii round-trips at every quality" {
    const text = "the quick brown fox jumps over the lazy dog";
    var q: u8 = 0;
    while (q <= 11) : (q += 1) try roundTripQuality(text, q, 22);
}

test "zix compression: brotli every byte value round-trips (binary safe)" {
    var input: [256]u8 = undefined;
    for (&input, 0..) |*b, i| b.* = @intCast(i);

    try roundTripQuality(&input, 5, 18);
}

test "zix compression: brotli repetitive text shrinks well below the input" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var r: usize = 0;
    while (r < 80) : (r += 1) try buf.appendSlice(testing.allocator, "the quick brown fox jumps over the lazy dog. ");

    const stream = try compressQualityAlloc(testing.allocator, buf.items, 9, 22);
    defer testing.allocator.free(stream);

    try testing.expect(stream.len < buf.items.len / 4);

    const back = try decompressBrotliAlloc(testing.allocator, stream, 1 << 20);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, buf.items, back);
}

test "zix compression: brotli dictionary path round-trips short English text" {
    try roundTripQuality("information about the world and the people in the government", 9, 22);
    try roundTripQuality("The quick brown fox and the lazy dog went to the market.", 9, 22);
}

test "zix compression: brotli random data never expands beyond the store overhead" {
    var input: [8192]u8 = undefined;
    for (&input, 0..) |*b, i| b.* = @truncate((i *% 2654435761) >> 11);

    const stream = try compressQualityAlloc(testing.allocator, &input, 9, 22);
    defer testing.allocator.free(stream);

    try testing.expect(stream.len <= input.len + 8);

    const back = try decompressBrotliAlloc(testing.allocator, stream, 1 << 20);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, &input, back);
}

test "zix compression: brotli higher quality is no worse than quality 0 on repetitive data" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var r: usize = 0;
    while (r < 100) : (r += 1) try buf.appendSlice(testing.allocator, "lorem ipsum dolor sit amet ");

    const q0 = try compressQualityAlloc(testing.allocator, buf.items, 0, 22);
    defer testing.allocator.free(q0);
    const q9 = try compressQualityAlloc(testing.allocator, buf.items, 9, 22);
    defer testing.allocator.free(q9);

    try testing.expect(q9.len <= q0.len);
}

test "zix compression: brotli long repetitive input round-trips at high quality" {
    var input: [50000]u8 = undefined;
    const unit = "abcdefghij";
    for (&input, 0..) |*b, i| b.* = unit[i % unit.len];

    try roundTripQuality(&input, 11, 24);
}

test "zix compression: brotli Level mapping round-trips both efforts" {
    const text = "facade roundtrip over the brotli codec, repeated enough to compress. " ++
        "facade roundtrip over the brotli codec, repeated enough to compress.";

    inline for (.{ Level.FASTEST, Level.DEFAULT }) |level| {
        const stream = try compressBrotliAlloc(testing.allocator, text, level);
        defer testing.allocator.free(stream);

        const back = try decompressBrotliAlloc(testing.allocator, stream, 1 << 16);
        defer testing.allocator.free(back);
        try testing.expectEqualSlices(u8, text, back);
    }
}

test "zix compression: brotli out-of-range window bits is rejected" {
    try testing.expectError(error.ZixInvalidWindowBits, compressQualityAlloc(testing.allocator, "abc", 5, 9));
    try testing.expectError(error.ZixInvalidWindowBits, compressQualityAlloc(testing.allocator, "abc", 5, 25));
}

test "zix compression: brotli decode past the cap errors" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var r: usize = 0;
    while (r < 50) : (r += 1) try buf.appendSlice(testing.allocator, "compressible repeated body ");

    const stream = try compressQualityAlloc(testing.allocator, buf.items, 9, 22);
    defer testing.allocator.free(stream);

    try testing.expectError(error.ZixOutputTooLarge, decompressBrotliAlloc(testing.allocator, stream, 16));
}

test "zix compression: brotli truncated compressed stream errors as DecompressFailed" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var r: usize = 0;
    while (r < 40) : (r += 1) try buf.appendSlice(testing.allocator, "a compressible body that needs a real prefix code ");

    const stream = try compressQualityAlloc(testing.allocator, buf.items, 9, 22);
    defer testing.allocator.free(stream);

    // cut the stream mid-compressed-block: the command loop runs out of bits and fails.
    try testing.expectError(error.ZixDecompressFailed, decompressBrotliAlloc(testing.allocator, stream[0 .. stream.len / 2], 1 << 20));
}

test "zix compression: brotli decodes an external brotli CLI vector (interop)" {
    // printf 'the quick brown fox ' (x12) | brotli -c  (the static-dictionary vector).
    const vector = "\x1f\xef\x00\xf8\x8d\x94\x6e\xe6\xa2\x06\x31\xa3\xc3\x53\x68\x6f\x39\xc8\x24\xa3\xe5\x08\xdb\x74\x54\x16\x48\xd7\x16\x0f";

    var expected: [240]u8 = undefined;
    var i: usize = 0;
    while (i < 240) : (i += 20) @memcpy(expected[i .. i + 20], "the quick brown fox ");

    const back = try decompressBrotliAlloc(testing.allocator, vector, 1024);
    defer testing.allocator.free(back);

    try testing.expectEqualSlices(u8, &expected, back);
}

test "zix compression: brotli empty stream decodes to nothing (CLI 0x3f)" {
    const back = try decompressBrotliAlloc(testing.allocator, "\x3f", 16);
    defer testing.allocator.free(back);

    try testing.expectEqual(@as(usize, 0), back.len);
}

test "zix compression: brotli literal context model round-trips and never enlarges vs flat" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    const lines = [_][]const u8{
        "The quick brown fox jumps over the lazy dog. ",
        "Pack my box with five dozen liquor jugs! ",
        "How vexingly quick daft zebras jump. ",
        "Sphinx of black quartz, judge my vow. ",
    };
    var r: usize = 0;
    while (r < 160) : (r += 1) try buf.appendSlice(testing.allocator, lines[r % lines.len]);

    const flat = try encodeCompressedAlloc(testing.allocator, buf.items, 22, .{ .literal_contexts = false });
    defer testing.allocator.free(flat);
    const ctx = try encodeCompressedAlloc(testing.allocator, buf.items, 22, .{ .literal_contexts = true });
    defer testing.allocator.free(ctx);

    // the context-modeled stream decodes byte-exact through the decoder.
    const back = try decompressBrotliAlloc(testing.allocator, ctx, 1 << 20);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, buf.items, back);

    // on this varied text the context model is at least as small as the single-tree encode.
    try testing.expect(ctx.len <= flat.len);
}

test "zix compression: brotli a context split with a single populated context still round-trips" {
    // one dominant context keeps the model honest about sparse / unused trees.
    var buf: [4096]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = if (i % 8 == 0) @as(u8, 'a') else @as(u8, 'b');

    const ctx = try encodeCompressedAlloc(testing.allocator, &buf, 22, .{ .literal_contexts = true });
    defer testing.allocator.free(ctx);

    const back = try decompressBrotliAlloc(testing.allocator, ctx, 1 << 16);
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, &buf, back);
}

test "zix compression: brotli compressBound holds for compressible and random input" {
    var rand: [4096]u8 = undefined;
    for (&rand, 0..) |*b, i| b.* = @truncate((i *% 40503) >> 7);

    const stream = try compressQualityAlloc(testing.allocator, &rand, 9, 22);
    defer testing.allocator.free(stream);

    try testing.expect(stream.len <= compressBound(rand.len));
}

test "zix compression: brotli caller-buffer compress then decompress round-trips" {
    const input = "information about the world and the people in the government, repeated for ratio. " ++
        "information about the world and the people in the government, repeated for ratio.";

    var comp_buf: [256]u8 = undefined;
    const written = try compressBrotli(testing.allocator, input, &comp_buf, .DEFAULT);
    try testing.expect(written > 0 and written <= comp_buf.len);

    var out_buf: [256]u8 = undefined;
    const inflated = try decompressBrotli(testing.allocator, comp_buf[0..written], &out_buf);
    try testing.expectEqualSlices(u8, input, out_buf[0..inflated]);
}

test "zix compression: brotli caller-buffer compress never exceeds compressBound" {
    var input: [2048]u8 = undefined;
    for (&input, 0..) |*b, i| b.* = @intCast('a' + (i % 16));

    var comp_buf: [compressBound(input.len)]u8 = undefined;
    const written = try compressBrotli(testing.allocator, &input, &comp_buf, .DEFAULT);

    var out_buf: [2048]u8 = undefined;
    const inflated = try decompressBrotli(testing.allocator, comp_buf[0..written], &out_buf);
    try testing.expectEqualSlices(u8, &input, out_buf[0..inflated]);
}

test "zix compression: brotli compressBrotli reports BufferTooSmall on an undersized buffer" {
    // Random data brotli cannot shrink, so the store fallback is near the input size and overflows
    // the tiny destination.
    var input: [4096]u8 = undefined;
    for (&input, 0..) |*b, i| b.* = @truncate((i *% 2654435761) >> 11);

    var tiny: [8]u8 = undefined;
    try testing.expectError(error.ZixBufferTooSmall, compressBrotli(testing.allocator, &input, &tiny, .DEFAULT));
}

test "zix compression: brotli decompressBrotli reports BufferTooSmall when output exceeds the buffer" {
    const input = "the quick brown fox jumps over the lazy dog. " ++
        "the quick brown fox jumps over the lazy dog.";

    const stream = try compressBrotliAlloc(testing.allocator, input, .DEFAULT);
    defer testing.allocator.free(stream);

    var tiny: [4]u8 = undefined;
    try testing.expectError(error.ZixBufferTooSmall, decompressBrotli(testing.allocator, stream, &tiny));
}

// edge: empty and single-byte inputs through the caller-buffer pair.
test "zix compression: brotli caller-buffer round-trips empty and single-byte input" {
    inline for (.{ "", "x" }) |input| {
        var comp: [64]u8 = undefined;
        const n = try compressBrotli(testing.allocator, input, &comp, .DEFAULT);

        var out: [8]u8 = undefined;
        const m = try decompressBrotli(testing.allocator, comp[0..n], &out);
        try testing.expectEqualSlices(u8, input, out[0..m]);
    }
}

// edge: the BufferTooSmall boundary for compress is exactly the produced length, not a gross gap.
test "zix compression: brotli compressBrotli succeeds at the exact size and fails one byte short" {
    const input = "boundary text that compresses to a stable length under the default effort.";

    const ref = try compressBrotliAlloc(testing.allocator, input, .DEFAULT);
    defer testing.allocator.free(ref);
    try testing.expect(ref.len > 1);

    const exact = try testing.allocator.alloc(u8, ref.len);
    defer testing.allocator.free(exact);
    try testing.expectEqual(ref.len, try compressBrotli(testing.allocator, input, exact, .DEFAULT));

    const short = try testing.allocator.alloc(u8, ref.len - 1);
    defer testing.allocator.free(short);
    try testing.expectError(error.ZixBufferTooSmall, compressBrotli(testing.allocator, input, short, .DEFAULT));
}

// edge: the BufferTooSmall boundary for decompress is exactly the inflated length.
test "zix compression: brotli decompressBrotli succeeds at the exact size and fails one byte short" {
    const input = "boundary text that round-trips to a known length after inflation.";

    const stream = try compressBrotliAlloc(testing.allocator, input, .DEFAULT);
    defer testing.allocator.free(stream);

    var exact: [input.len]u8 = undefined;
    const n = try decompressBrotli(testing.allocator, stream, &exact);
    try testing.expectEqual(@as(usize, input.len), n);
    try testing.expectEqualSlices(u8, input, exact[0..n]);

    var short: [input.len - 1]u8 = undefined;
    try testing.expectError(error.ZixBufferTooSmall, decompressBrotli(testing.allocator, stream, &short));
}

// behaviour: the buffer variant is a faithful copy of the alloc variant, byte for byte.
test "zix compression: brotli compressBrotli writes the same bytes as compressBrotliAlloc" {
    const input = "the buffer-into and alloc variants must produce identical brotli streams.";

    const ref = try compressBrotliAlloc(testing.allocator, input, .DEFAULT);
    defer testing.allocator.free(ref);

    var buf: [256]u8 = undefined;
    const n = try compressBrotli(testing.allocator, input, &buf, .DEFAULT);
    try testing.expectEqualSlices(u8, ref, buf[0..n]);
}

// behaviour: binary-safe across every byte value through both caller-buffer directions.
test "zix compression: brotli every byte value round-trips through the caller-buffer variants" {
    var input: [256]u8 = undefined;
    for (&input, 0..) |*b, i| b.* = @intCast(i);

    var comp: [compressBound(256)]u8 = undefined;
    const n = try compressBrotli(testing.allocator, &input, &comp, .DEFAULT);

    var out: [256]u8 = undefined;
    const m = try decompressBrotli(testing.allocator, comp[0..n], &out);
    try testing.expectEqualSlices(u8, &input, out[0..m]);
}

// integration: the caller-buffer and alloc variants interoperate in both directions, so a stream
// produced by one decodes through the other.
test "zix compression: brotli caller-buffer and alloc variants interoperate both directions" {
    const input = "interop between compressBrotli/decompressBrotli and the alloc variants, both ways.";

    var cbuf: [256]u8 = undefined;
    const n = try compressBrotli(testing.allocator, input, &cbuf, .DEFAULT);
    const via_alloc = try decompressBrotliAlloc(testing.allocator, cbuf[0..n], 1 << 16);
    defer testing.allocator.free(via_alloc);
    try testing.expectEqualSlices(u8, input, via_alloc);

    const stream = try compressBrotliAlloc(testing.allocator, input, .DEFAULT);
    defer testing.allocator.free(stream);
    var obuf: [256]u8 = undefined;
    const m = try decompressBrotli(testing.allocator, stream, &obuf);
    try testing.expectEqualSlices(u8, input, obuf[0..m]);
}

// behaviour: both Level efforts survive the caller-buffer round-trip.
test "zix compression: brotli caller-buffer round-trip holds for both Level efforts" {
    const input = "level mapping over the caller-buffer path, long enough to actually compress a bit.";

    inline for (.{ Level.FASTEST, Level.DEFAULT }) |level| {
        var comp: [256]u8 = undefined;
        const n = try compressBrotli(testing.allocator, input, &comp, level);

        var out: [256]u8 = undefined;
        const m = try decompressBrotli(testing.allocator, comp[0..n], &out);
        try testing.expectEqualSlices(u8, input, out[0..m]);
    }
}
