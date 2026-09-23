//! HPACK: static table, Huffman codec, decoder (with dynamic table eviction), encoder.

const std = @import("std");

// --------------------------------------------------------- //

pub const HpackEntry = struct { name: []const u8, value: []const u8 };

pub const HPACK_STATIC: [62]HpackEntry = blk: {
    break :blk [62]HpackEntry{
        .{ .name = "", .value = "" }, // 0 (unused)
        .{ .name = ":authority", .value = "" }, // 1
        .{ .name = ":method", .value = "GET" }, // 2
        .{ .name = ":method", .value = "POST" }, // 3
        .{ .name = ":path", .value = "/" }, // 4
        .{ .name = ":path", .value = "/index.html" }, // 5
        .{ .name = ":scheme", .value = "http" }, // 6
        .{ .name = ":scheme", .value = "https" }, // 7
        .{ .name = ":status", .value = "200" }, // 8
        .{ .name = ":status", .value = "204" }, // 9
        .{ .name = ":status", .value = "206" }, // 10
        .{ .name = ":status", .value = "304" }, // 11
        .{ .name = ":status", .value = "400" }, // 12
        .{ .name = ":status", .value = "404" }, // 13
        .{ .name = ":status", .value = "500" }, // 14
        .{ .name = "accept-charset", .value = "" }, // 15
        .{ .name = "accept-encoding", .value = "gzip, deflate" }, // 16
        .{ .name = "accept-language", .value = "" }, // 17
        .{ .name = "accept-ranges", .value = "" }, // 18
        .{ .name = "accept", .value = "" }, // 19
        .{ .name = "access-control-allow-origin", .value = "" }, // 20
        .{ .name = "age", .value = "" }, // 21
        .{ .name = "allow", .value = "" }, // 22
        .{ .name = "authorization", .value = "" }, // 23
        .{ .name = "cache-control", .value = "" }, // 24
        .{ .name = "content-disposition", .value = "" }, // 25
        .{ .name = "content-encoding", .value = "" }, // 26
        .{ .name = "content-language", .value = "" }, // 27
        .{ .name = "content-length", .value = "" }, // 28
        .{ .name = "content-location", .value = "" }, // 29
        .{ .name = "content-range", .value = "" }, // 30
        .{ .name = "content-type", .value = "" }, // 31
        .{ .name = "cookie", .value = "" }, // 32
        .{ .name = "date", .value = "" }, // 33
        .{ .name = "etag", .value = "" }, // 34
        .{ .name = "expect", .value = "" }, // 35
        .{ .name = "expires", .value = "" }, // 36
        .{ .name = "from", .value = "" }, // 37
        .{ .name = "host", .value = "" }, // 38
        .{ .name = "if-match", .value = "" }, // 39
        .{ .name = "if-modified-since", .value = "" }, // 40
        .{ .name = "if-none-match", .value = "" }, // 41
        .{ .name = "if-range", .value = "" }, // 42
        .{ .name = "if-unmodified-since", .value = "" }, // 43
        .{ .name = "last-modified", .value = "" }, // 44
        .{ .name = "link", .value = "" }, // 45
        .{ .name = "location", .value = "" }, // 46
        .{ .name = "max-forwards", .value = "" }, // 47
        .{ .name = "proxy-authenticate", .value = "" }, // 48
        .{ .name = "proxy-authorization", .value = "" }, // 49
        .{ .name = "range", .value = "" }, // 50
        .{ .name = "referer", .value = "" }, // 51
        .{ .name = "refresh", .value = "" }, // 52
        .{ .name = "retry-after", .value = "" }, // 53
        .{ .name = "server", .value = "" }, // 54
        .{ .name = "set-cookie", .value = "" }, // 55
        .{ .name = "strict-transport-security", .value = "" }, // 56
        .{ .name = "transfer-encoding", .value = "" }, // 57
        .{ .name = "user-agent", .value = "" }, // 58
        .{ .name = "vary", .value = "" }, // 59
        .{ .name = "via", .value = "" }, // 60
        .{ .name = "www-authenticate", .value = "" }, // 61
    };
};

// --------------------------------------------------------- //

const HuffSym = struct { code: u32, bits: u5 };

pub const HUFF: [256]HuffSym = .{
    .{ .code = 0x1ff8, .bits = 13 }, // 0
    .{ .code = 0x7fffd8, .bits = 23 }, // 1
    .{ .code = 0xfffffe2, .bits = 28 }, // 2
    .{ .code = 0xfffffe3, .bits = 28 }, // 3
    .{ .code = 0xfffffe4, .bits = 28 }, // 4
    .{ .code = 0xfffffe5, .bits = 28 }, // 5
    .{ .code = 0xfffffe6, .bits = 28 }, // 6
    .{ .code = 0xfffffe7, .bits = 28 }, // 7
    .{ .code = 0xfffffe8, .bits = 28 }, // 8
    .{ .code = 0xffffea, .bits = 24 }, // 9
    .{ .code = 0x3ffffffc, .bits = 30 }, // 10
    .{ .code = 0xfffffe9, .bits = 28 }, // 11
    .{ .code = 0xfffffea, .bits = 28 }, // 12
    .{ .code = 0x3ffffffd, .bits = 30 }, // 13
    .{ .code = 0xfffffeb, .bits = 28 }, // 14
    .{ .code = 0xfffffec, .bits = 28 }, // 15
    .{ .code = 0xfffffed, .bits = 28 }, // 16
    .{ .code = 0xfffffee, .bits = 28 }, // 17
    .{ .code = 0xfffffef, .bits = 28 }, // 18
    .{ .code = 0xffffff0, .bits = 28 }, // 19
    .{ .code = 0xffffff1, .bits = 28 }, // 20
    .{ .code = 0xffffff2, .bits = 28 }, // 21
    .{ .code = 0x3ffffffe, .bits = 30 }, // 22
    .{ .code = 0xffffff3, .bits = 28 }, // 23
    .{ .code = 0xffffff4, .bits = 28 }, // 24
    .{ .code = 0xffffff5, .bits = 28 }, // 25
    .{ .code = 0xffffff6, .bits = 28 }, // 26
    .{ .code = 0xffffff7, .bits = 28 }, // 27
    .{ .code = 0xffffff8, .bits = 28 }, // 28
    .{ .code = 0xffffff9, .bits = 28 }, // 29
    .{ .code = 0xffffffa, .bits = 28 }, // 30
    .{ .code = 0xffffffb, .bits = 28 }, // 31
    .{ .code = 0x14, .bits = 6 }, // 32 ' '
    .{ .code = 0x3f8, .bits = 10 }, // 33 '!'
    .{ .code = 0x3f9, .bits = 10 }, // 34 '"'
    .{ .code = 0xffa, .bits = 12 }, // 35 '#'
    .{ .code = 0x1ff9, .bits = 13 }, // 36 '$'
    .{ .code = 0x15, .bits = 6 }, // 37 '%'
    .{ .code = 0xf8, .bits = 8 }, // 38 '&'
    .{ .code = 0x7fa, .bits = 11 }, // 39 '\''
    .{ .code = 0x3fa, .bits = 10 }, // 40 '('
    .{ .code = 0x3fb, .bits = 10 }, // 41 ')'
    .{ .code = 0xf9, .bits = 8 }, // 42 '*'
    .{ .code = 0x7fb, .bits = 11 }, // 43 '+'
    .{ .code = 0xfa, .bits = 8 }, // 44 ','
    .{ .code = 0x16, .bits = 6 }, // 45 '-'
    .{ .code = 0x17, .bits = 6 }, // 46 '.'
    .{ .code = 0x18, .bits = 6 }, // 47 '/'
    .{ .code = 0x0, .bits = 5 }, // 48 '0'
    .{ .code = 0x1, .bits = 5 }, // 49 '1'
    .{ .code = 0x2, .bits = 5 }, // 50 '2'
    .{ .code = 0x19, .bits = 6 }, // 51 '3'
    .{ .code = 0x1a, .bits = 6 }, // 52 '4'
    .{ .code = 0x1b, .bits = 6 }, // 53 '5'
    .{ .code = 0x1c, .bits = 6 }, // 54 '6'
    .{ .code = 0x1d, .bits = 6 }, // 55 '7'
    .{ .code = 0x1e, .bits = 6 }, // 56 '8'
    .{ .code = 0x1f, .bits = 6 }, // 57 '9'
    .{ .code = 0x5c, .bits = 7 }, // 58 ':'
    .{ .code = 0xfb, .bits = 8 }, // 59 ';'
    .{ .code = 0x7ffc, .bits = 15 }, // 60 '<'
    .{ .code = 0x20, .bits = 6 }, // 61 '='
    .{ .code = 0xffb, .bits = 12 }, // 62 '>'
    .{ .code = 0x3fc, .bits = 10 }, // 63 '?'
    .{ .code = 0x1ffa, .bits = 13 }, // 64 '@'
    .{ .code = 0x21, .bits = 6 }, // 65 'A'
    .{ .code = 0x5d, .bits = 7 }, // 66 'B'
    .{ .code = 0x5e, .bits = 7 }, // 67 'C'
    .{ .code = 0x5f, .bits = 7 }, // 68 'D'
    .{ .code = 0x60, .bits = 7 }, // 69 'E'
    .{ .code = 0x61, .bits = 7 }, // 70 'F'
    .{ .code = 0x62, .bits = 7 }, // 71 'G'
    .{ .code = 0x63, .bits = 7 }, // 72 'H'
    .{ .code = 0x64, .bits = 7 }, // 73 'I'
    .{ .code = 0x65, .bits = 7 }, // 74 'J'
    .{ .code = 0x66, .bits = 7 }, // 75 'K'
    .{ .code = 0x67, .bits = 7 }, // 76 'L'
    .{ .code = 0x68, .bits = 7 }, // 77 'M'
    .{ .code = 0x69, .bits = 7 }, // 78 'N'
    .{ .code = 0x6a, .bits = 7 }, // 79 'O'
    .{ .code = 0x6b, .bits = 7 }, // 80 'P'
    .{ .code = 0x6c, .bits = 7 }, // 81 'Q'
    .{ .code = 0x6d, .bits = 7 }, // 82 'R'
    .{ .code = 0x6e, .bits = 7 }, // 83 'S'
    .{ .code = 0x6f, .bits = 7 }, // 84 'T'
    .{ .code = 0x70, .bits = 7 }, // 85 'U'
    .{ .code = 0x71, .bits = 7 }, // 86 'V'
    .{ .code = 0x72, .bits = 7 }, // 87 'W'
    .{ .code = 0xfc, .bits = 8 }, // 88 'X'
    .{ .code = 0x73, .bits = 7 }, // 89 'Y'
    .{ .code = 0xfd, .bits = 8 }, // 90 'Z'
    .{ .code = 0x1ffb, .bits = 13 }, // 91 '['
    .{ .code = 0x7fff0, .bits = 19 }, // 92 '\\'
    .{ .code = 0x1ffc, .bits = 13 }, // 93 ']'
    .{ .code = 0x3ffc, .bits = 14 }, // 94 '^'
    .{ .code = 0x22, .bits = 6 }, // 95 '_'
    .{ .code = 0x7ffd, .bits = 15 }, // 96 '`'
    .{ .code = 0x3, .bits = 5 }, // 97 'a'
    .{ .code = 0x23, .bits = 6 }, // 98 'b'
    .{ .code = 0x4, .bits = 5 }, // 99 'c'
    .{ .code = 0x24, .bits = 6 }, // 100 'd'
    .{ .code = 0x5, .bits = 5 }, // 101 'e'
    .{ .code = 0x25, .bits = 6 }, // 102 'f'
    .{ .code = 0x26, .bits = 6 }, // 103 'g'
    .{ .code = 0x27, .bits = 6 }, // 104 'h'
    .{ .code = 0x6, .bits = 5 }, // 105 'i'
    .{ .code = 0x74, .bits = 7 }, // 106 'j'
    .{ .code = 0x75, .bits = 7 }, // 107 'k'
    .{ .code = 0x28, .bits = 6 }, // 108 'l'
    .{ .code = 0x29, .bits = 6 }, // 109 'm'
    .{ .code = 0x2a, .bits = 6 }, // 110 'n'
    .{ .code = 0x7, .bits = 5 }, // 111 'o'
    .{ .code = 0x2b, .bits = 6 }, // 112 'p'
    .{ .code = 0x76, .bits = 7 }, // 113 'q'
    .{ .code = 0x2c, .bits = 6 }, // 114 'r'
    .{ .code = 0x8, .bits = 5 }, // 115 's'
    .{ .code = 0x9, .bits = 5 }, // 116 't'
    .{ .code = 0x2d, .bits = 6 }, // 117 'u'
    .{ .code = 0x77, .bits = 7 }, // 118 'v'
    .{ .code = 0x78, .bits = 7 }, // 119 'w'
    .{ .code = 0x79, .bits = 7 }, // 120 'x'
    .{ .code = 0x7a, .bits = 7 }, // 121 'y'
    .{ .code = 0x7b, .bits = 7 }, // 122 'z'
    .{ .code = 0x7ffe, .bits = 15 }, // 123 '{'
    .{ .code = 0x7fc, .bits = 11 }, // 124 '|'
    .{ .code = 0x3ffd, .bits = 14 }, // 125 '}'
    .{ .code = 0x1ffd, .bits = 13 }, // 126 '~'
    .{ .code = 0xffffffc, .bits = 28 }, // 127
    .{ .code = 0xfffe6, .bits = 20 }, // 128
    .{ .code = 0x3fffd2, .bits = 22 }, // 129
    .{ .code = 0xfffe7, .bits = 20 }, // 130
    .{ .code = 0xfffe8, .bits = 20 }, // 131
    .{ .code = 0x3fffd3, .bits = 22 }, // 132
    .{ .code = 0x3fffd4, .bits = 22 }, // 133
    .{ .code = 0x3fffd5, .bits = 22 }, // 134
    .{ .code = 0x7fffd9, .bits = 23 }, // 135
    .{ .code = 0x3fffd6, .bits = 22 }, // 136
    .{ .code = 0x7fffda, .bits = 23 }, // 137
    .{ .code = 0x7fffdb, .bits = 23 }, // 138
    .{ .code = 0x7fffdc, .bits = 23 }, // 139
    .{ .code = 0x7fffdd, .bits = 23 }, // 140
    .{ .code = 0x7fffde, .bits = 23 }, // 141
    .{ .code = 0xffffeb, .bits = 24 }, // 142
    .{ .code = 0x7fffdf, .bits = 23 }, // 143
    .{ .code = 0xffffec, .bits = 24 }, // 144
    .{ .code = 0xffffed, .bits = 24 }, // 145
    .{ .code = 0x3fffd7, .bits = 22 }, // 146
    .{ .code = 0x7fffe0, .bits = 23 }, // 147
    .{ .code = 0xffffee, .bits = 24 }, // 148
    .{ .code = 0x7fffe1, .bits = 23 }, // 149
    .{ .code = 0x7fffe2, .bits = 23 }, // 150
    .{ .code = 0x7fffe3, .bits = 23 }, // 151
    .{ .code = 0x7fffe4, .bits = 23 }, // 152
    .{ .code = 0x1fffdc, .bits = 21 }, // 153
    .{ .code = 0x3fffd8, .bits = 22 }, // 154
    .{ .code = 0x7fffe5, .bits = 23 }, // 155
    .{ .code = 0x3fffd9, .bits = 22 }, // 156
    .{ .code = 0x7fffe6, .bits = 23 }, // 157
    .{ .code = 0x7fffe7, .bits = 23 }, // 158
    .{ .code = 0xffffef, .bits = 24 }, // 159
    .{ .code = 0x3fffda, .bits = 22 }, // 160
    .{ .code = 0x1fffdd, .bits = 21 }, // 161
    .{ .code = 0xfffe9, .bits = 20 }, // 162
    .{ .code = 0x3fffdb, .bits = 22 }, // 163
    .{ .code = 0x3fffdc, .bits = 22 }, // 164
    .{ .code = 0x7fffe8, .bits = 23 }, // 165
    .{ .code = 0x7fffe9, .bits = 23 }, // 166
    .{ .code = 0x1fffde, .bits = 21 }, // 167
    .{ .code = 0x7fffea, .bits = 23 }, // 168
    .{ .code = 0x3fffdd, .bits = 22 }, // 169
    .{ .code = 0x3fffde, .bits = 22 }, // 170
    .{ .code = 0xfffff0, .bits = 24 }, // 171
    .{ .code = 0x1fffdf, .bits = 21 }, // 172
    .{ .code = 0x3fffdf, .bits = 22 }, // 173
    .{ .code = 0x7fffeb, .bits = 23 }, // 174
    .{ .code = 0x7fffec, .bits = 23 }, // 175
    .{ .code = 0x1fffe0, .bits = 21 }, // 176
    .{ .code = 0x1fffe1, .bits = 21 }, // 177
    .{ .code = 0x3fffe0, .bits = 22 }, // 178
    .{ .code = 0x1fffe2, .bits = 21 }, // 179
    .{ .code = 0x7fffed, .bits = 23 }, // 180
    .{ .code = 0x3fffe1, .bits = 22 }, // 181
    .{ .code = 0x7fffee, .bits = 23 }, // 182
    .{ .code = 0x7fffef, .bits = 23 }, // 183
    .{ .code = 0xfffea, .bits = 20 }, // 184
    .{ .code = 0x3fffe2, .bits = 22 }, // 185
    .{ .code = 0x3fffe3, .bits = 22 }, // 186
    .{ .code = 0x3fffe4, .bits = 22 }, // 187
    .{ .code = 0x7ffff0, .bits = 23 }, // 188
    .{ .code = 0x3fffe5, .bits = 22 }, // 189
    .{ .code = 0x3fffe6, .bits = 22 }, // 190
    .{ .code = 0x7ffff1, .bits = 23 }, // 191
    .{ .code = 0x3ffffe0, .bits = 26 }, // 192
    .{ .code = 0x3ffffe1, .bits = 26 }, // 193
    .{ .code = 0xfffeb, .bits = 20 }, // 194
    .{ .code = 0x7fff1, .bits = 19 }, // 195
    .{ .code = 0x3fffe7, .bits = 22 }, // 196
    .{ .code = 0x7ffff2, .bits = 23 }, // 197
    .{ .code = 0x3fffe8, .bits = 22 }, // 198
    .{ .code = 0x1ffffec, .bits = 25 }, // 199
    .{ .code = 0x3ffffe2, .bits = 26 }, // 200
    .{ .code = 0x3ffffe3, .bits = 26 }, // 201
    .{ .code = 0x3ffffe4, .bits = 26 }, // 202
    .{ .code = 0x7ffffde, .bits = 27 }, // 203
    .{ .code = 0x7ffffdf, .bits = 27 }, // 204
    .{ .code = 0x3ffffe5, .bits = 26 }, // 205
    .{ .code = 0xfffff1, .bits = 24 }, // 206
    .{ .code = 0x1ffffed, .bits = 25 }, // 207
    .{ .code = 0x7fff2, .bits = 19 }, // 208
    .{ .code = 0x1fffe3, .bits = 21 }, // 209
    .{ .code = 0x3ffffe6, .bits = 26 }, // 210
    .{ .code = 0x7ffffe0, .bits = 27 }, // 211
    .{ .code = 0x7ffffe1, .bits = 27 }, // 212
    .{ .code = 0x3ffffe7, .bits = 26 }, // 213
    .{ .code = 0x7ffffe2, .bits = 27 }, // 214
    .{ .code = 0xfffff2, .bits = 24 }, // 215
    .{ .code = 0x1fffe4, .bits = 21 }, // 216
    .{ .code = 0x1fffe5, .bits = 21 }, // 217
    .{ .code = 0x3ffffe8, .bits = 26 }, // 218
    .{ .code = 0x3ffffe9, .bits = 26 }, // 219
    .{ .code = 0xffffffd, .bits = 28 }, // 220
    .{ .code = 0x7ffffe3, .bits = 27 }, // 221
    .{ .code = 0x7ffffe4, .bits = 27 }, // 222
    .{ .code = 0x7ffffe5, .bits = 27 }, // 223
    .{ .code = 0xfffec, .bits = 20 }, // 224
    .{ .code = 0xfffff3, .bits = 24 }, // 225
    .{ .code = 0xfffed, .bits = 20 }, // 226
    .{ .code = 0x1fffe6, .bits = 21 }, // 227
    .{ .code = 0x3fffe9, .bits = 22 }, // 228
    .{ .code = 0x1fffe7, .bits = 21 }, // 229
    .{ .code = 0x1fffe8, .bits = 21 }, // 230
    .{ .code = 0x7ffff3, .bits = 23 }, // 231
    .{ .code = 0x3fffea, .bits = 22 }, // 232
    .{ .code = 0x3fffeb, .bits = 22 }, // 233
    .{ .code = 0x1ffffee, .bits = 25 }, // 234
    .{ .code = 0x1ffffef, .bits = 25 }, // 235
    .{ .code = 0xfffff4, .bits = 24 }, // 236
    .{ .code = 0xfffff5, .bits = 24 }, // 237
    .{ .code = 0x3ffffea, .bits = 26 }, // 238
    .{ .code = 0x7ffff4, .bits = 23 }, // 239
    .{ .code = 0x3ffffeb, .bits = 26 }, // 240
    .{ .code = 0x7ffffe6, .bits = 27 }, // 241
    .{ .code = 0x3ffffec, .bits = 26 }, // 242
    .{ .code = 0x3ffffed, .bits = 26 }, // 243
    .{ .code = 0x7ffffe7, .bits = 27 }, // 244
    .{ .code = 0x7ffffe8, .bits = 27 }, // 245
    .{ .code = 0x7ffffe9, .bits = 27 }, // 246
    .{ .code = 0x7ffffea, .bits = 27 }, // 247
    .{ .code = 0x7ffffeb, .bits = 27 }, // 248
    .{ .code = 0xffffffe, .bits = 28 }, // 249
    .{ .code = 0x7ffffec, .bits = 27 }, // 250
    .{ .code = 0x7ffffed, .bits = 27 }, // 251
    .{ .code = 0x7ffffee, .bits = 27 }, // 252
    .{ .code = 0x7ffffef, .bits = 27 }, // 253
    .{ .code = 0x7fffff0, .bits = 27 }, // 254
    .{ .code = 0x3ffffee, .bits = 26 }, // 255
};

/// Decode a Huffman-encoded byte string into out.
///
/// Return:
/// - !usize (number of decoded bytes)
pub fn huffDecode(src: []const u8, out: []u8) !usize {
    var acc: u64 = 0;
    var bits: u8 = 0;
    var out_pos: usize = 0;

    for (src) |byte| {
        acc = (acc << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            var matched = false;
            for (HUFF, 0..) |sym, sym_idx| {
                if (bits < sym.bits) continue;
                const shift: u6 = @intCast(bits - sym.bits);
                const extracted: u32 = @intCast((acc >> shift) & (@as(u64, 1) << sym.bits) - 1);
                if (extracted == sym.code) {
                    if (out_pos >= out.len) return error.ZixOutputTooSmall;
                    out[out_pos] = @intCast(sym_idx);
                    out_pos += 1;
                    acc &= (@as(u64, 1) << shift) - 1;
                    bits -= sym.bits;
                    matched = true;
                    break;
                }
            }
            if (!matched) break;
        }
    }
    if (bits > 7) return error.ZixInvalidHuffman;
    return out_pos;
}

/// Encode src into out using HPACK Huffman.
///
/// Return:
/// - !usize (bytes written)
pub fn huffEncode(src: []const u8, out: []u8) !usize {
    var acc: u64 = 0;
    var bits: u8 = 0;
    var pos: usize = 0;

    for (src) |byte| {
        const sym = HUFF[byte];
        acc = (acc << sym.bits) | sym.code;
        bits += sym.bits;
        while (bits >= 8) {
            bits -= 8;
            if (pos >= out.len) return error.ZixOutputTooSmall;
            out[pos] = @intCast((acc >> @as(u6, @intCast(bits))) & 0xFF);
            pos += 1;
        }
    }
    if (bits > 0) {
        const pad_bits: u6 = @intCast(8 - bits);
        const padded: u8 = @intCast(((acc << pad_bits) | ((@as(u64, 1) << pad_bits) - 1)) & 0xFF);
        if (pos >= out.len) return error.ZixOutputTooSmall;
        out[pos] = padded;
        pos += 1;
    }
    return pos;
}

// --------------------------------------------------------- //

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const HpackDecoder = struct {
    dyn: [128]HpackEntry = undefined,
    dyn_count: usize = 0,
    dyn_size: usize = 0,
    max_size: usize = 4096,
    // dyn[] entries always slice into here, never into per-call scratch.
    // Scratch buffers are zeroed on stream-slot reuse, dyn_buf persists for the connection lifetime.
    dyn_buf: [8192]u8 = undefined,
    dyn_buf_pos: usize = 0,

    pub fn init() HpackDecoder {
        return .{};
    }

    fn staticEntry(idx: usize) ?HpackEntry {
        if (idx == 0 or idx > 61) return null;
        return HPACK_STATIC[idx];
    }

    fn dynEntry(self: *const HpackDecoder, idx: usize) ?HpackEntry {
        if (idx == 0 or idx > self.dyn_count) return null;
        return self.dyn[idx - 1];
    }

    fn getEntry(self: *const HpackDecoder, idx: usize) ?HpackEntry {
        if (idx <= 61) return staticEntry(idx);
        return self.dynEntry(idx - 61);
    }

    pub fn evictTo(self: *HpackDecoder, target: usize) void {
        while (self.dyn_count > 0 and self.dyn_size > target) {
            const last = self.dyn[self.dyn_count - 1];
            self.dyn_size -= last.name.len + last.value.len + 32;
            self.dyn_count -= 1;
        }
    }

    // Repack live dyn[] entries contiguously at the start of dyn_buf.
    // Called when dyn_buf_pos + needed > dyn_buf.len after eviction freed entries.
    // Safe: entries are stored oldest (low addr) -> newest (high addr). Compaction
    // writes oldest first at new_pos=0 so source always >= dest, no overlap.
    fn compactDynBuf(self: *HpackDecoder) void {
        var new_pos: usize = 0;
        var index: usize = self.dyn_count;

        while (index > 0) {
            index -= 1;
            const entry = &self.dyn[index];

            @memcpy(self.dyn_buf[new_pos..][0..entry.name.len], entry.name);
            entry.name = self.dyn_buf[new_pos..][0..entry.name.len];
            new_pos += entry.name.len;

            @memcpy(self.dyn_buf[new_pos..][0..entry.value.len], entry.value);
            entry.value = self.dyn_buf[new_pos..][0..entry.value.len];
            new_pos += entry.value.len;
        }

        self.dyn_buf_pos = new_pos;
    }

    fn addDynamic(self: *HpackDecoder, name: []const u8, value: []const u8) void {
        const entry_size = name.len + value.len + 32;
        if (entry_size > self.max_size) {
            self.evictTo(0);
            return;
        }

        self.evictTo(self.max_size - entry_size);
        if (self.dyn_count >= 128) return;

        // Copy name+value into dyn_buf so entries never alias per-stream scratch.
        const needed = name.len + value.len;
        if (self.dyn_buf_pos + needed > self.dyn_buf.len) self.compactDynBuf();
        if (self.dyn_buf_pos + needed > self.dyn_buf.len) return;

        @memcpy(self.dyn_buf[self.dyn_buf_pos..][0..name.len], name);
        const name_copy = self.dyn_buf[self.dyn_buf_pos..][0..name.len];
        self.dyn_buf_pos += name.len;

        @memcpy(self.dyn_buf[self.dyn_buf_pos..][0..value.len], value);
        const value_copy = self.dyn_buf[self.dyn_buf_pos..][0..value.len];
        self.dyn_buf_pos += value.len;

        var i: usize = self.dyn_count;
        while (i > 0) : (i -= 1) self.dyn[i] = self.dyn[i - 1];
        self.dyn[0] = .{ .name = name_copy, .value = value_copy };
        self.dyn_count += 1;
        self.dyn_size += entry_size;
    }

    fn decodeInt(src: []const u8, pos: *usize, prefix_bits: u3) !u64 {
        if (pos.* >= src.len) return error.ZixUnexpectedEOF;
        const mask: u8 = (@as(u8, 1) << prefix_bits) - 1;
        var val: u64 = src[pos.*] & mask;
        pos.* += 1;
        if (val < mask) return val;
        var shift: u6 = 0;
        while (true) {
            if (pos.* >= src.len) return error.ZixUnexpectedEOF;
            const b = src[pos.*];
            pos.* += 1;
            val += (@as(u64, b & 0x7F)) << shift;
            shift += 7;
            if ((b & 0x80) == 0) break;
            if (shift > 56) return error.ZixIntegerOverflow;
        }
        return val;
    }

    fn decodeString(src: []const u8, pos: *usize, scratch: []u8, scratch_pos: *usize) ![]const u8 {
        if (pos.* >= src.len) return error.ZixUnexpectedEOF;
        const hbit = (src[pos.*] & 0x80) != 0;
        const slen: usize = @intCast(try decodeInt(src, pos, 7));
        if (pos.* + slen > src.len) return error.ZixUnexpectedEOF;
        const raw = src[pos.*..][0..slen];
        pos.* += slen;
        if (!hbit) {
            if (scratch_pos.* + slen > scratch.len) return error.ZixScratchFull;
            @memcpy(scratch[scratch_pos.*..][0..slen], raw);
            const out = scratch[scratch_pos.*..][0..slen];
            scratch_pos.* += slen;
            return out;
        }
        const out_start = scratch_pos.*;
        const available = scratch.len - out_start;
        if (available == 0) return error.ZixScratchFull;
        const n = try huffDecode(raw, scratch[out_start..]);
        const out = scratch[out_start..][0..n];
        scratch_pos.* += n;
        return out;
    }

    // Copy src into scratch[pos..] and advance pos. All decoded output (including
    // indexed lookups) goes through scratch so callers get a stable, mutable slice.
    fn copyIntoScratch(src: []const u8, scratch: []u8, pos: *usize) ![]const u8 {
        if (pos.* + src.len > scratch.len) return error.ZixScratchFull;

        @memcpy(scratch[pos.*..][0..src.len], src);
        const result = scratch[pos.*..][0..src.len];
        pos.* += src.len;

        return result;
    }

    /// Decode a HPACK header block into out.
    /// All slices in decoded headers point into scratch (caller-owned, stable for call duration).
    /// dyn[] entries are stored in dyn_buf (connection-lifetime), never in scratch.
    ///
    /// Return:
    /// - !usize (number of headers decoded)
    pub fn decode(
        self: *HpackDecoder,
        block: []const u8,
        out: []Header,
        scratch: []u8,
    ) !usize {
        var pos: usize = 0;
        var n_out: usize = 0;
        var scratch_pos: usize = 0;

        while (pos < block.len) {
            if (n_out >= out.len) return error.ZixTooManyHeaders;
            const first = block[pos];

            if ((first & 0x80) != 0) {
                // Indexed: copy from static/dynamic table into scratch so callers get
                // stable slices even when dyn[] points into dyn_buf across requests.
                const idx: usize = @intCast(try decodeInt(block, &pos, 7));
                const entry = self.getEntry(idx) orelse return error.ZixInvalidIndex;
                out[n_out] = .{
                    .name = try copyIntoScratch(entry.name, scratch, &scratch_pos),
                    .value = try copyIntoScratch(entry.value, scratch, &scratch_pos),
                };
                n_out += 1;
            } else if ((first & 0x40) != 0) {
                const idx: usize = @intCast(try decodeInt(block, &pos, 6));
                const name = if (idx == 0) blk: {
                    break :blk try decodeString(block, &pos, scratch, &scratch_pos);
                } else blk: {
                    const entry = self.getEntry(idx) orelse return error.ZixInvalidIndex;
                    break :blk try copyIntoScratch(entry.name, scratch, &scratch_pos);
                };
                const value = try decodeString(block, &pos, scratch, &scratch_pos);
                self.addDynamic(name, value);
                out[n_out] = .{ .name = name, .value = value };
                n_out += 1;
            } else if ((first & 0x20) != 0) {
                const new_max: usize = @intCast(try decodeInt(block, &pos, 5));
                self.max_size = new_max;
                self.evictTo(new_max);
            } else {
                _ = (first & 0x10) != 0;
                const idx: usize = @intCast(try decodeInt(block, &pos, 4));
                const name = if (idx == 0) blk: {
                    break :blk try decodeString(block, &pos, scratch, &scratch_pos);
                } else blk: {
                    const entry = self.getEntry(idx) orelse return error.ZixInvalidIndex;
                    break :blk try copyIntoScratch(entry.name, scratch, &scratch_pos);
                };
                const value = try decodeString(block, &pos, scratch, &scratch_pos);
                out[n_out] = .{ .name = name, .value = value };
                n_out += 1;
            }
        }
        return n_out;
    }
};

// --------------------------------------------------------- //

pub const HpackEncoder = struct {
    buf: []u8,
    pos: usize,

    pub fn init(buf: []u8) HpackEncoder {
        return .{ .buf = buf, .pos = 0 };
    }

    pub fn encoded(self: *const HpackEncoder) []const u8 {
        return self.buf[0..self.pos];
    }

    fn writeInt(self: *HpackEncoder, val: u64, prefix_bits: u3, first_byte_high: u8) !void {
        const mask: u64 = (@as(u64, 1) << prefix_bits) - 1;
        if (val < mask) {
            if (self.pos >= self.buf.len) return error.ZixBufferFull;
            self.buf[self.pos] = first_byte_high | @as(u8, @intCast(val));
            self.pos += 1;
            return;
        }
        if (self.pos >= self.buf.len) return error.ZixBufferFull;
        self.buf[self.pos] = first_byte_high | @as(u8, @intCast(mask));
        self.pos += 1;
        var rem = val - mask;
        while (rem >= 0x80) {
            if (self.pos >= self.buf.len) return error.ZixBufferFull;
            self.buf[self.pos] = @intCast((rem & 0x7F) | 0x80);
            self.pos += 1;
            rem >>= 7;
        }
        if (self.pos >= self.buf.len) return error.ZixBufferFull;
        self.buf[self.pos] = @intCast(rem);
        self.pos += 1;
    }

    fn writeString(self: *HpackEncoder, str: []const u8) !void {
        var hbuf: [256]u8 = undefined;
        // Explicit ?usize so comptime evaluation (cached gRPC reply blocks) keeps the optional
        // type even when the error branch is statically unreachable.
        const hn: ?usize = huffEncode(str, &hbuf) catch null;
        if (hn != null and hn.? < str.len) {
            try self.writeInt(hn.?, 7, 0x80);
            if (self.pos + hn.? > self.buf.len) return error.ZixBufferFull;
            @memcpy(self.buf[self.pos..][0..hn.?], hbuf[0..hn.?]);
            self.pos += hn.?;
        } else {
            try self.writeInt(str.len, 7, 0x00);
            if (self.pos + str.len > self.buf.len) return error.ZixBufferFull;
            @memcpy(self.buf[self.pos..][0..str.len], str);
            self.pos += str.len;
        }
    }

    /// Encode a header. Uses indexed representation for static table exact matches,
    /// name-indexed literal for static name-only matches, or full literal otherwise.
    pub fn writeHeader(self: *HpackEncoder, name: []const u8, value: []const u8) !void {
        for (HPACK_STATIC[1..], 1..) |entry, i| {
            if (std.ascii.eqlIgnoreCase(entry.name, name) and
                std.mem.eql(u8, entry.value, value))
            {
                try self.writeInt(i, 7, 0x80);
                return;
            }
        }
        for (HPACK_STATIC[1..], 1..) |entry, i| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) {
                try self.writeInt(i, 4, 0x00);
                try self.writeString(value);
                return;
            }
        }
        try self.writeInt(0, 4, 0x00);
        try self.writeString(name);
        try self.writeString(value);
    }
};

// --------------------------------------------------------- //
// Response-header prefix cache

/// Cached HPACK encoding of a response prefix [:status, content-type, content-encoding] for a hot
/// triple. HpackEncoder is stateless (static table plus literal-without-indexing, never the dynamic
/// table or a size update), so this block is byte-identical on every connection, and a per-request
/// content-length field is valid HPACK appended after it. The cache skips the repeated static-table
/// scans and the Huffman encode of the same content-type on every response. Append-only: readers scan
/// 0..count lock-free (count published release-ordered after the slot is fully written), the spinlock
/// serializes only the rare insert (one per distinct triple).
const RESP_PREFIX_MAX = 32;
const RESP_CT_MAX = 64;
const RESP_CE_MAX = 32;
const RESP_BLOCK_MAX = 96;

const RespPrefix = struct {
    status: u16,
    ct_len: u8,
    ce_len: u8,
    block_len: u8,
    ct: [RESP_CT_MAX]u8,
    ce: [RESP_CE_MAX]u8,
    block: [RESP_BLOCK_MAX]u8,
};

var g_resp_prefix: [RESP_PREFIX_MAX]RespPrefix = undefined;
var g_resp_prefix_count: usize = 0;
var g_resp_prefix_lock: std.atomic.Value(bool) = .init(false);

fn respPrefixLookup(status: u16, content_type: []const u8, content_encoding: []const u8, count: usize) ?*const RespPrefix {
    for (g_resp_prefix[0..count]) |*entry| {
        if (entry.status == status and
            std.mem.eql(u8, entry.ct[0..entry.ct_len], content_type) and
            std.mem.eql(u8, entry.ce[0..entry.ce_len], content_encoding)) return entry;
    }

    return null;
}

/// Encode [:status, content-type, content-encoding] into dst, returning the byte length. An empty
/// content_type or content_encoding omits that header, matching writeHeader-based encoding.
fn encodePrefixInto(dst: []u8, status: u16, content_type: []const u8, content_encoding: []const u8) usize {
    var enc = HpackEncoder.init(dst);

    var status_str: [4]u8 = undefined;
    const status_s = std.fmt.bufPrint(&status_str, "{d}", .{status}) catch "200";
    enc.writeHeader(":status", status_s) catch return enc.pos;
    if (content_type.len > 0) enc.writeHeader("content-type", content_type) catch return enc.pos;
    if (content_encoding.len > 0) enc.writeHeader("content-encoding", content_encoding) catch return enc.pos;

    return enc.pos;
}

/// Write the [:status, content-type, content-encoding] prefix into dst, using the cache for a hot
/// triple. Encodes and caches on a miss. Falls back to a direct, uncached encode when the triple is
/// too long to cache or the cache is full, so correctness never depends on a cache hit.
fn writeRespPrefix(dst: []u8, status: u16, content_type: []const u8, content_encoding: []const u8) usize {
    const count = @atomicLoad(usize, &g_resp_prefix_count, .acquire);
    if (respPrefixLookup(status, content_type, content_encoding, count)) |entry| {
        @memcpy(dst[0..entry.block_len], entry.block[0..entry.block_len]);
        return entry.block_len;
    }

    if (content_type.len > RESP_CT_MAX or content_encoding.len > RESP_CE_MAX)
        return encodePrefixInto(dst, status, content_type, content_encoding);

    while (g_resp_prefix_lock.swap(true, .acquire)) std.atomic.spinLoopHint();
    defer g_resp_prefix_lock.store(false, .release);

    // Re-check under the lock: another worker may have inserted this triple since the load above.
    const now = @atomicLoad(usize, &g_resp_prefix_count, .acquire);
    if (respPrefixLookup(status, content_type, content_encoding, now)) |entry| {
        @memcpy(dst[0..entry.block_len], entry.block[0..entry.block_len]);
        return entry.block_len;
    }
    if (now == RESP_PREFIX_MAX)
        return encodePrefixInto(dst, status, content_type, content_encoding);

    var scratch: [256]u8 = undefined;
    const n = encodePrefixInto(&scratch, status, content_type, content_encoding);
    if (n == 0 or n > RESP_BLOCK_MAX)
        return encodePrefixInto(dst, status, content_type, content_encoding);

    const entry = &g_resp_prefix[now];
    entry.status = status;
    entry.ct_len = @intCast(content_type.len);
    entry.ce_len = @intCast(content_encoding.len);
    entry.block_len = @intCast(n);
    @memcpy(entry.ct[0..content_type.len], content_type);
    @memcpy(entry.ce[0..content_encoding.len], content_encoding);
    @memcpy(entry.block[0..n], scratch[0..n]);

    @atomicStore(usize, &g_resp_prefix_count, now + 1, .release);

    @memcpy(dst[0..n], scratch[0..n]);
    return n;
}

/// Encode a response header block [:status, content-type, content-encoding, content-length] into dst,
/// returning its length. The [:status, content-type, content-encoding] prefix is served from a
/// per-triple cache (byte-identical, the encoder is stateless), only content-length is encoded per
/// call. A null content_length omits the content-length field (a bodyless END_STREAM response).
///
/// Param:
/// dst - []u8 (destination, must hold the encoded block, e.g. HPACK_ENCODE_SCRATCH)
/// status - u16 (response status, e.g. 200)
/// content_type - []const u8 (empty omits the header)
/// content_encoding - []const u8 (empty omits the header)
/// content_length - ?u64 (null omits the header)
///
/// Return:
/// - usize (encoded block length in dst)
pub fn respHeaderBlock(dst: []u8, status: u16, content_type: []const u8, content_encoding: []const u8, content_length: ?u64) usize {
    var pos = writeRespPrefix(dst, status, content_type, content_encoding);

    if (content_length) |len| {
        var enc = HpackEncoder{ .buf = dst, .pos = pos };
        var cl_buf: [20]u8 = undefined;
        const cl_s = std.fmt.bufPrint(&cl_buf, "{d}", .{len}) catch "0";
        enc.writeHeader("content-length", cl_s) catch return pos;
        pos = enc.pos;
    }

    return pos;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http2: huffEncode and huffDecode roundtrip ascii" {
    const src = "hello";
    var enc_buf: [32]u8 = undefined;
    const n = try huffEncode(src, &enc_buf);
    var dec_buf: [32]u8 = undefined;
    const m = try huffDecode(enc_buf[0..n], &dec_buf);
    try std.testing.expectEqualStrings(src, dec_buf[0..m]);
}

test "zix http2: HpackEncoder.writeHeader indexed from static table" {
    var buf: [64]u8 = undefined;
    var enc = HpackEncoder.init(&buf);
    try enc.writeHeader(":method", "GET");
    try std.testing.expect(enc.pos > 0);
    try std.testing.expectEqual(@as(u8, 0x82), enc.encoded()[0]);
}

test "zix http2: HpackDecoder.decode indexed :method GET" {
    var buf: [64]u8 = undefined;
    var enc = HpackEncoder.init(&buf);
    try enc.writeHeader(":method", "GET");
    const block = enc.encoded();

    var dec = HpackDecoder.init();
    var out: [8]Header = undefined;
    var scratch: [256]u8 = undefined;
    const n = try dec.decode(block, &out, &scratch);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualStrings(":method", out[0].name);
    try std.testing.expectEqualStrings("GET", out[0].value);
}

test "zix http2: HpackDecoder dynamic table eviction respects max_size" {
    var dec = HpackDecoder.init();
    dec.max_size = 64;
    dec.addDynamic("x-long-name", "x-long-value");
    const before = dec.dyn_count;
    dec.addDynamic("another-long-name-that-fills-budget", "val");
    try std.testing.expect(dec.dyn_count <= before + 1);
}

test "zix http2: HpackDecoder addDynamic copies strings into dyn_buf" {
    var dec = HpackDecoder.init();
    const name = "x-custom";
    const value = "hello";
    dec.addDynamic(name, value);
    try std.testing.expectEqual(@as(usize, 1), dec.dyn_count);
    const dyn_base = @intFromPtr(&dec.dyn_buf[0]);
    const dyn_end = dyn_base + dec.dyn_buf.len;
    try std.testing.expect(@intFromPtr(dec.dyn[0].name.ptr) >= dyn_base);
    try std.testing.expect(@intFromPtr(dec.dyn[0].name.ptr) < dyn_end);
    try std.testing.expect(@intFromPtr(dec.dyn[0].value.ptr) >= dyn_base);
    try std.testing.expect(@intFromPtr(dec.dyn[0].value.ptr) < dyn_end);
    try std.testing.expectEqualStrings(name, dec.dyn[0].name);
    try std.testing.expectEqualStrings(value, dec.dyn[0].value);
}

test "zix http2: HpackDecoder indexed lookup after scratch zeroed returns correct value" {
    // Regression: dyn[] entries used to alias per-stream scratch. When scratch is zeroed
    // on stream-slot reuse, indexed HPACK lookups returned empty strings -> UNIMPLEMENTED.
    var dec = HpackDecoder.init();

    // Simulate request 1: incremental-indexing (0x40) adds :path to dynamic table.
    var scratch1: [256]u8 = undefined;
    var out1: [8]Header = undefined;
    // 0x44 = 0x40 | 4 (incremental indexing, name from static idx 4 = :path)
    // followed by literal value "/svc.Svc/Greet" (length-prefixed, not huffman)
    const path_value = "/svc.Svc/Greet";
    var block1: [32]u8 = undefined;
    block1[0] = 0x44;
    block1[1] = @intCast(path_value.len);
    @memcpy(block1[2..][0..path_value.len], path_value);
    _ = try dec.decode(block1[0 .. 2 + path_value.len], &out1, &scratch1);
    try std.testing.expectEqual(@as(usize, 1), dec.dyn_count);
    try std.testing.expectEqualStrings(":path", dec.dyn[0].name);
    try std.testing.expectEqualStrings(path_value, dec.dyn[0].value);

    // Zero the scratch (simulates stream-slot reuse: stream.* = std.mem.zeroes(Stream)).
    @memset(&scratch1, 0);

    // Simulate request 2: fully-indexed (0x80 | 62 = 0xBE) references :path from dyn table.
    // dyn[0] = :path, overall HPACK idx = 61 (static) + 1 (dyn slot) = 62 -> 0x80|62 = 0xBE.
    // Without fix: dec.dyn[0].value pointed into zeroed scratch -> empty string -> UNIMPLEMENTED.
    // With fix: dec.dyn[0].value points into dyn_buf -> "/svc.Svc/Greet" -> OK.
    var scratch2: [256]u8 = undefined;
    var out2: [8]Header = undefined;
    const block2 = [_]u8{0xBE}; // 0x80 | 62
    const count = try dec.decode(&block2, &out2, &scratch2);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqualStrings(":path", out2[0].name);
    try std.testing.expectEqualStrings(path_value, out2[0].value);
}

test "zix http2: HpackDecoder indexed output slices point into scratch not dyn_buf" {
    var dec = HpackDecoder.init();
    dec.addDynamic("x-test", "value");

    var scratch: [256]u8 = undefined;
    var out: [8]Header = undefined;
    const block = [_]u8{0xBE}; // dyn slot 1 -> overall HPACK idx 62 -> 0x80|62 = 0xBE
    _ = try dec.decode(&block, &out, &scratch);

    const scratch_base = @intFromPtr(&scratch[0]);
    const scratch_end = scratch_base + scratch.len;
    try std.testing.expect(@intFromPtr(out[0].name.ptr) >= scratch_base);
    try std.testing.expect(@intFromPtr(out[0].name.ptr) < scratch_end);
    try std.testing.expect(@intFromPtr(out[0].value.ptr) >= scratch_base);
    try std.testing.expect(@intFromPtr(out[0].value.ptr) < scratch_end);
}

test "zix http2: HpackDecoder dyn_buf compaction triggered and entries survive" {
    var dec = HpackDecoder.init();
    // Fill dyn_buf near capacity with one large entry, then evict it and add another.
    // Compaction must run and the surviving entry must remain readable.
    const large_value: [4000]u8 = @splat('x');
    dec.addDynamic("x-big", &large_value);
    try std.testing.expectEqual(@as(usize, 1), dec.dyn_count);

    // Evict the large entry by setting max_size = 0.
    dec.evictTo(0);
    try std.testing.expectEqual(@as(usize, 0), dec.dyn_count);

    // dyn_buf_pos still at 4000+5=4005. Now add a new entry, needs compaction.
    dec.addDynamic("x-new", "world");
    try std.testing.expectEqual(@as(usize, 1), dec.dyn_count);
    try std.testing.expectEqualStrings("x-new", dec.dyn[0].name);
    try std.testing.expectEqualStrings("world", dec.dyn[0].value);
}

test "zix http2: HPACK_STATIC index 8 is :status 200" {
    try std.testing.expectEqualStrings(":status", HPACK_STATIC[8].name);
    try std.testing.expectEqualStrings("200", HPACK_STATIC[8].value);
}

test "zix http2: respHeaderBlock matches writeHeader byte-for-byte" {
    // Reference: encode the four fields directly through writeHeader.
    var ref: [256]u8 = undefined;
    var enc = HpackEncoder.init(&ref);
    try enc.writeHeader(":status", "200");
    try enc.writeHeader("content-type", "application/json");
    try enc.writeHeader("content-length", "1234");
    const expect = enc.encoded();

    var got: [256]u8 = undefined;
    const n1 = respHeaderBlock(&got, 200, "application/json", "", 1234);
    try std.testing.expectEqualSlices(u8, expect, got[0..n1]);

    // Second call serves the cached prefix, output must stay byte-identical.
    var got2: [256]u8 = undefined;
    const n2 = respHeaderBlock(&got2, 200, "application/json", "", 1234);
    try std.testing.expectEqualSlices(u8, expect, got2[0..n2]);

    // Same triple, different content-length: prefix cached, length re-encoded.
    var ref3: [256]u8 = undefined;
    var enc3 = HpackEncoder.init(&ref3);
    try enc3.writeHeader(":status", "200");
    try enc3.writeHeader("content-type", "application/json");
    try enc3.writeHeader("content-length", "7");
    var got3: [256]u8 = undefined;
    const n3 = respHeaderBlock(&got3, 200, "application/json", "", 7);
    try std.testing.expectEqualSlices(u8, enc3.encoded(), got3[0..n3]);
}

test "zix http2: respHeaderBlock with content-encoding and bodyless response" {
    // With a content-encoding header and a content-length.
    var ref: [256]u8 = undefined;
    var enc = HpackEncoder.init(&ref);
    try enc.writeHeader(":status", "200");
    try enc.writeHeader("content-type", "text/plain");
    try enc.writeHeader("content-encoding", "br");
    try enc.writeHeader("content-length", "9");
    var got: [256]u8 = undefined;
    const n = respHeaderBlock(&got, 200, "text/plain", "br", 9);
    try std.testing.expectEqualSlices(u8, enc.encoded(), got[0..n]);

    // Bodyless: null content-length omits the field, prefix only.
    var ref2: [256]u8 = undefined;
    var enc2 = HpackEncoder.init(&ref2);
    try enc2.writeHeader(":status", "404");
    try enc2.writeHeader("content-type", "text/plain");
    var got2: [256]u8 = undefined;
    const n2 = respHeaderBlock(&got2, 404, "text/plain", "", null);
    try std.testing.expectEqualSlices(u8, enc2.encoded(), got2[0..n2]);
}

test "zix http2: respHeaderBlock round-trips through the decoder" {
    var block: [256]u8 = undefined;
    const n = respHeaderBlock(&block, 200, "application/json", "", 42);

    var dec = HpackDecoder.init();
    var out: [8]Header = undefined;
    var scratch: [256]u8 = undefined;
    const count = try dec.decode(block[0..n], &out, &scratch);
    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings(":status", out[0].name);
    try std.testing.expectEqualStrings("200", out[0].value);
    try std.testing.expectEqualStrings("content-type", out[1].name);
    try std.testing.expectEqualStrings("application/json", out[1].value);
    try std.testing.expectEqualStrings("content-length", out[2].name);
    try std.testing.expectEqualStrings("42", out[2].value);
}
