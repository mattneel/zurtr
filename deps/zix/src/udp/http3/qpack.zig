//! zix HTTP/3 QPACK header compression (RFC 9204, Layer P).
//!
//! What:
//! - The prefixed-integer codec every representation rides on (4.1.1, reusing the RFC 7541 integer),
//!   the read-only static table (the full Appendix A), the two unidirectional stream types (4.2), and
//!   the field line representations (4.5): Indexed Field Line, Literal Field Line with Name Reference,
//!   and Literal Field Line with Literal Name (4.5.6, the one a client has to use for a name the table
//!   carries no entry for, which is how `:protocol` arrives).
//! - For a static-only field section the Encoded Field Section Prefix is Required Insert Count 0 /
//!   Base 0 (two zero bytes). The dynamic table and decoder instructions live in qpack_dynamic.zig.
//! - Proven against the RFC 7541 Appendix C.1 integer vectors and RFC 9204 representations below.
//!
//! Note:
//! - The static-table encoding is live. StreamRegistry (the at-most-one encoder / decoder stream
//!   check) is implemented and tested but not enforced in the serve path yet (deferred).
//! - The string literals (4.1.2) of a field line stay as they arrived: a VALUE is handed over with its
//!   `H` bit, so only a caller that uses it pays for expanding it. A field NAME is expanded here, into
//!   the caller's scratch, because a name has to be readable to say which field the line is.

const std = @import("std");

const huffman = @import("huffman.zig");

/// A decoded prefixed integer (RFC 7541 5.1): the value plus how many bytes it occupied.
pub const IntResult = struct { value: u64, len: usize };

/// Decode an N-bit prefixed integer (RFC 7541 5.1, reused by QPACK 4.1.1). The low `prefix_bits` of
/// the first byte hold the value or, if all ones, a continuation follows.
pub fn decodePrefixedInt(data: []const u8, prefix_bits: u4) error{ZixTruncated}!IntResult {
    if (data.len == 0) return error.ZixTruncated;

    const max: u64 = (@as(u64, 1) << prefix_bits) - 1;
    const first: u64 = data[0] & @as(u8, @intCast(max));
    if (first < max) return .{ .value = first, .len = 1 };

    var value: u64 = max;
    var len: usize = 1;
    var shift: u6 = 0;
    while (true) {
        if (len >= data.len) return error.ZixTruncated;

        const byte = data[len];
        len += 1;
        value += @as(u64, byte & 0x7f) << shift;
        shift += 7;
        if (byte & 0x80 == 0) break;
    }

    return .{ .value = value, .len = len };
}

/// Encode an N-bit prefixed integer (RFC 7541 5.1). `high_bits` are the already-set bits above the
/// prefix in the first byte. Returns the number of bytes written.
pub fn encodePrefixedInt(out: []u8, prefix_bits: u4, high_bits: u8, value: u64) usize {
    const max: u64 = (@as(u64, 1) << prefix_bits) - 1;
    if (value < max) {
        out[0] = high_bits | @as(u8, @intCast(value));
        return 1;
    }

    out[0] = high_bits | @as(u8, @intCast(max));
    var remaining = value - max;
    var i: usize = 1;
    while (remaining >= 128) {
        out[i] = @as(u8, @intCast(remaining % 128)) + 128;
        remaining /= 128;
        i += 1;
    }
    out[i] = @intCast(remaining);

    return i + 1;
}

// --------------------------------------------------------------- //

/// A field line: a name and value (RFC 9204 Appendix A entries, and decoded representations).
pub const Field = struct { name: []const u8, value: []const u8 };

/// The RFC 9204 Appendix A static table, all 99 entries. A client references it by index and the
/// encoder must reference only entries the decoder knows, so a short table is not a smaller feature:
/// it is a name this decoder cannot resolve (`origin` is entry 90, and the WebTransport binding reads
/// exactly that field). `:authority` (0), `accept-encoding` (31) and `content-encoding` (42 br /
/// 43 gzip) are the entries the rest of this tree reaches for by name today.
///
/// Note:
/// - `:protocol` is not in Appendix A: a CONNECT carrying it spells the name out (4.5.6), which is why
///   that representation has to be decoded, not looked up.
pub const static_table = [_]Field{
    .{ .name = ":authority", .value = "" }, // 0
    .{ .name = ":path", .value = "/" }, // 1
    .{ .name = "age", .value = "0" }, // 2
    .{ .name = "content-disposition", .value = "" }, // 3
    .{ .name = "content-length", .value = "0" }, // 4
    .{ .name = "cookie", .value = "" }, // 5
    .{ .name = "date", .value = "" }, // 6
    .{ .name = "etag", .value = "" }, // 7
    .{ .name = "if-modified-since", .value = "" }, // 8
    .{ .name = "if-none-match", .value = "" }, // 9
    .{ .name = "last-modified", .value = "" }, // 10
    .{ .name = "link", .value = "" }, // 11
    .{ .name = "location", .value = "" }, // 12
    .{ .name = "referer", .value = "" }, // 13
    .{ .name = "set-cookie", .value = "" }, // 14
    .{ .name = ":method", .value = "CONNECT" }, // 15
    .{ .name = ":method", .value = "DELETE" }, // 16
    .{ .name = ":method", .value = "GET" }, // 17
    .{ .name = ":method", .value = "HEAD" }, // 18
    .{ .name = ":method", .value = "OPTIONS" }, // 19
    .{ .name = ":method", .value = "POST" }, // 20
    .{ .name = ":method", .value = "PUT" }, // 21
    .{ .name = ":scheme", .value = "http" }, // 22
    .{ .name = ":scheme", .value = "https" }, // 23
    .{ .name = ":status", .value = "103" }, // 24
    .{ .name = ":status", .value = "200" }, // 25
    .{ .name = ":status", .value = "304" }, // 26
    .{ .name = ":status", .value = "404" }, // 27
    .{ .name = ":status", .value = "503" }, // 28
    .{ .name = "accept", .value = "*/*" }, // 29
    .{ .name = "accept", .value = "application/dns-message" }, // 30
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" }, // 31
    .{ .name = "accept-ranges", .value = "bytes" }, // 32
    .{ .name = "access-control-allow-headers", .value = "cache-control" }, // 33
    .{ .name = "access-control-allow-headers", .value = "content-type" }, // 34
    .{ .name = "access-control-allow-origin", .value = "*" }, // 35
    .{ .name = "cache-control", .value = "max-age=0" }, // 36
    .{ .name = "cache-control", .value = "max-age=2592000" }, // 37
    .{ .name = "cache-control", .value = "max-age=604800" }, // 38
    .{ .name = "cache-control", .value = "no-cache" }, // 39
    .{ .name = "cache-control", .value = "no-store" }, // 40
    .{ .name = "cache-control", .value = "public, max-age=31536000" }, // 41
    .{ .name = "content-encoding", .value = "br" }, // 42
    .{ .name = "content-encoding", .value = "gzip" }, // 43
    .{ .name = "content-type", .value = "application/dns-message" }, // 44
    .{ .name = "content-type", .value = "application/javascript" }, // 45
    .{ .name = "content-type", .value = "application/json" }, // 46
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" }, // 47
    .{ .name = "content-type", .value = "image/gif" }, // 48
    .{ .name = "content-type", .value = "image/jpeg" }, // 49
    .{ .name = "content-type", .value = "image/png" }, // 50
    .{ .name = "content-type", .value = "text/css" }, // 51
    .{ .name = "content-type", .value = "text/html; charset=utf-8" }, // 52
    .{ .name = "content-type", .value = "text/plain" }, // 53
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" }, // 54
    .{ .name = "range", .value = "bytes=0-" }, // 55
    .{ .name = "strict-transport-security", .value = "max-age=31536000" }, // 56
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" }, // 57
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" }, // 58
    .{ .name = "vary", .value = "accept-encoding" }, // 59
    .{ .name = "vary", .value = "origin" }, // 60
    .{ .name = "x-content-type-options", .value = "nosniff" }, // 61
    .{ .name = "x-xss-protection", .value = "1; mode=block" }, // 62
    .{ .name = ":status", .value = "100" }, // 63
    .{ .name = ":status", .value = "204" }, // 64
    .{ .name = ":status", .value = "206" }, // 65
    .{ .name = ":status", .value = "302" }, // 66
    .{ .name = ":status", .value = "400" }, // 67
    .{ .name = ":status", .value = "403" }, // 68
    .{ .name = ":status", .value = "421" }, // 69
    .{ .name = ":status", .value = "425" }, // 70
    .{ .name = ":status", .value = "500" }, // 71
    .{ .name = "accept-language", .value = "" }, // 72
    .{ .name = "access-control-allow-credentials", .value = "FALSE" }, // 73
    .{ .name = "access-control-allow-credentials", .value = "TRUE" }, // 74
    .{ .name = "access-control-allow-headers", .value = "*" }, // 75
    .{ .name = "access-control-allow-methods", .value = "get" }, // 76
    .{ .name = "access-control-allow-methods", .value = "get, post, options" }, // 77
    .{ .name = "access-control-allow-methods", .value = "options" }, // 78
    .{ .name = "access-control-expose-headers", .value = "content-length" }, // 79
    .{ .name = "access-control-request-headers", .value = "content-type" }, // 80
    .{ .name = "access-control-request-method", .value = "get" }, // 81
    .{ .name = "access-control-request-method", .value = "post" }, // 82
    .{ .name = "alt-svc", .value = "clear" }, // 83
    .{ .name = "authorization", .value = "" }, // 84
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" }, // 85
    .{ .name = "early-data", .value = "1" }, // 86
    .{ .name = "expect-ct", .value = "" }, // 87
    .{ .name = "forwarded", .value = "" }, // 88
    .{ .name = "if-range", .value = "" }, // 89
    .{ .name = "origin", .value = "" }, // 90
    .{ .name = "purpose", .value = "prefetch" }, // 91
    .{ .name = "server", .value = "" }, // 92
    .{ .name = "timing-allow-origin", .value = "*" }, // 93
    .{ .name = "upgrade-insecure-requests", .value = "1" }, // 94
    .{ .name = "user-agent", .value = "" }, // 95
    .{ .name = "x-forwarded-for", .value = "" }, // 96
    .{ .name = "x-frame-options", .value = "deny" }, // 97
    .{ .name = "x-frame-options", .value = "sameorigin" }, // 98
};

/// The two QPACK unidirectional stream types (RFC 9204 4.2).
pub const encoder_stream_type: u64 = 0x02;
pub const decoder_stream_type: u64 = 0x03;

/// Tracks the at-most-one-each rule for the QPACK streams (RFC 9204 4.2). A second instance of either
/// type is an H3_STREAM_CREATION_ERROR.
pub const StreamRegistry = struct {
    encoder_open: bool = false,
    decoder_open: bool = false,

    pub fn register(self: *StreamRegistry, stream_type: u64) error{ZixStreamCreationError}!void {
        switch (stream_type) {
            encoder_stream_type => {
                if (self.encoder_open) return error.ZixStreamCreationError;
                self.encoder_open = true;
            },
            decoder_stream_type => {
                if (self.decoder_open) return error.ZixStreamCreationError;
                self.decoder_open = true;
            },
            else => {},
        }
    }
};

// --------------------------------------------------------------- //

/// A decoded Indexed Field Line (RFC 9204 4.5.2): which table and the index.
pub const IndexedFieldLine = struct { static: bool, index: u64, len: usize };

/// Decode an Indexed Field Line (RFC 9204 4.5.2): leading '1', then the 'T' table bit, then a 6-bit
/// prefix index.
pub fn decodeIndexedFieldLine(data: []const u8) error{ ZixTruncated, ZixNotIndexed }!IndexedFieldLine {
    if (data.len == 0) return error.ZixTruncated;
    if (data[0] & 0x80 == 0) return error.ZixNotIndexed;

    const is_static = data[0] & 0x40 != 0;
    const int = try decodePrefixedInt(data, 6);

    return .{ .static = is_static, .index = int.value, .len = int.len };
}

/// Encode an Indexed Field Line referencing the static table (RFC 9204 4.5.2). Returns bytes written.
pub fn encodeStaticIndexedFieldLine(out: []u8, index: u64) usize {
    return encodePrefixedInt(out, 6, 0x80 | 0x40, index);
}

/// A string literal (RFC 9204 4.1.2): an `H` bit, an N-bit prefix length, then the bytes, still
/// Huffman-coded when that bit is set. Expanding is the caller's call, not this layer's.
const StringLiteral = struct { bytes: []const u8, huffman: bool, len: usize };

/// Decode a string literal (RFC 9204 4.1.2) whose `H` bit and length prefix start at `data[0]`.
fn decodeStringLiteral(data: []const u8, prefix_bits: u4) error{ZixTruncated}!StringLiteral {
    if (data.len == 0) return error.ZixTruncated;

    const huffman_coded = data[0] & 0x80 != 0;
    const length = try decodePrefixedInt(data, prefix_bits);
    const end = length.len + @as(usize, @intCast(length.value));
    if (data.len < end) return error.ZixTruncated;

    return .{ .bytes = data[length.len..end], .huffman = huffman_coded, .len = end };
}

/// A decoded Literal Field Line with Name Reference (RFC 9204 4.5.4). `len` is the total bytes the
/// representation consumed, for walking a field section.
pub const LiteralNameRef = struct { static: bool, name_index: u64, value: []const u8, huffman: bool, len: usize };

/// Decode a Literal Field Line with Name Reference (RFC 9204 4.5.4): leading '01', the 'N' and 'T'
/// bits, a 4-bit prefix name index, then an 8-bit prefix string literal value.
pub fn decodeLiteralNameRef(data: []const u8) error{ ZixTruncated, ZixNotLiteralNameRef }!LiteralNameRef {
    if (data.len == 0) return error.ZixTruncated;
    if (data[0] & 0xc0 != 0x40) return error.ZixNotLiteralNameRef;

    const is_static = data[0] & 0x10 != 0;
    const name = try decodePrefixedInt(data, 4);
    const value = try decodeStringLiteral(data[name.len..], 7);

    return .{ .static = is_static, .name_index = name.value, .value = value.bytes, .huffman = value.huffman, .len = name.len + value.len };
}

/// A decoded Literal Field Line with Literal Name (RFC 9204 4.5.6). `len` is the total bytes the
/// representation consumed, for walking a field section.
///
/// Note:
/// - `name` is expanded into the caller's `name_scratch` when it arrived Huffman-coded, because a name
///   has to be readable to say which field the line is. A name that does not fit the scratch leaves
///   `name` empty: the line is then one the caller does not model, which is the caller's business and
///   not a decode failure. `value` keeps the coding it arrived in, like every other decoded value.
pub const LiteralLiteralName = struct {
    name: []const u8,
    name_huffman: bool,
    value: []const u8,
    huffman: bool,
    len: usize,
};

/// Decode a Literal Field Line with Literal Name (RFC 9204 4.5.6): leading '001', the 'N' bit, the
/// name's own 'H' bit, a 3-bit prefix name length, the name string, then an 8-bit prefix value length
/// and the value string.
///
/// Note:
/// - This is the only representation that can carry a name the static table has no entry for, which is
///   what makes it load-bearing for a WebTransport session: `:protocol` is in no static entry, so an
///   extended CONNECT spells it out (RFC 9220 4).
///
/// Param:
/// data - []const u8 (the field section, from this representation's first byte)
/// name_scratch - []u8 (destination for a Huffman-coded name; empty is legal and drops every such name)
///
/// Return:
/// - LiteralLiteralName
/// - error.ZixTruncated when the representation runs past `data`
/// - error.ZixNotLiteralLiteralName when the first byte is not this representation
pub fn decodeLiteralLiteralName(data: []const u8, name_scratch: []u8) error{ ZixTruncated, ZixNotLiteralLiteralName }!LiteralLiteralName {
    if (data.len == 0) return error.ZixTruncated;
    if (data[0] & 0xe0 != 0x20) return error.ZixNotLiteralLiteralName;

    const name_huffman = data[0] & 0x08 != 0;
    const name_length = try decodePrefixedInt(data, 3);
    const name_end = name_length.len + @as(usize, @intCast(name_length.value));
    if (data.len < name_end) return error.ZixTruncated;

    const encoded_name = data[name_length.len..name_end];
    const value = try decodeStringLiteral(data[name_end..], 7);

    return .{
        .name = if (name_huffman) expandName(name_scratch, encoded_name) else encoded_name,
        .name_huffman = name_huffman,
        .value = value.bytes,
        .huffman = value.huffman,
        .len = name_end + value.len,
    };
}

/// The bytes a Huffman-coded field name expands to, or empty when the scratch does not hold it. Both
/// outcomes let the walk move on, which is what the caller needs: an unreadable name is a field it
/// does not model. A bigger buffer would not buy it anything either, because every name it models is
/// short, `accept-encoding` (15) and `:authority` (10) included.
fn expandName(scratch: []u8, encoded: []const u8) []const u8 {
    const len = huffman.decode(scratch, encoded) orelse return "";

    return scratch[0..len];
}

/// Encode a Literal Field Line with Name Reference against the static table (RFC 9204 4.5.4): the
/// field name comes from a static entry, the value is written out as a plain (non-Huffman) literal.
///
/// Note:
/// - This is how a field whose exact name-and-value pair has no static entry is sent. `:status 413`
///   is one: the static table carries only a handful of statuses, so the name is borrowed from one
///   of those entries and the value is spelled out.
///
/// Param:
/// out - []u8 (destination, must hold the encoded field line)
/// name_index - u64 (static entry whose NAME is used, its value is ignored)
/// value - []const u8 (the field value, written literally)
///
/// Return:
/// - usize (bytes written)
pub fn encodeStaticLiteralNameRef(out: []u8, name_index: u64, value: []const u8) usize {
    // '01' literal-with-name-reference, N unset (may be indexed downstream), T set (static table).
    var pos = encodePrefixedInt(out, 4, 0x40 | 0x10, name_index);

    pos += encodePrefixedInt(out[pos..], 7, 0x00, value.len);
    @memcpy(out[pos..][0..value.len], value);

    return pos + value.len;
}

/// Look up a static-table entry by index, or null if out of range.
pub fn staticEntry(index: u64) ?Field {
    if (index >= static_table.len) return null;

    return static_table[@intCast(index)];
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

fn fieldIs(field: Field, name: []const u8, value: []const u8) bool {
    return std.mem.eql(u8, field.name, name) and std.mem.eql(u8, field.value, value);
}

test "zix http3: RFC 7541 C.1 prefixed integer decode and encode" {
    try std.testing.expectEqual(@as(u64, 10), (try decodePrefixedInt(&hexBytes("0a"), 5)).value);

    const v1337 = try decodePrefixedInt(&hexBytes("1f9a0a"), 5);
    try std.testing.expect(v1337.value == 1337 and v1337.len == 3);

    try std.testing.expectEqual(@as(u64, 42), (try decodePrefixedInt(&hexBytes("2a"), 8)).value);

    var buf: [16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &hexBytes("0a"), buf[0..encodePrefixedInt(&buf, 5, 0, 10)]);
    try std.testing.expectEqualSlices(u8, &hexBytes("1f9a0a"), buf[0..encodePrefixedInt(&buf, 5, 0, 1337)]);
    try std.testing.expectEqualSlices(u8, &hexBytes("2a"), buf[0..encodePrefixedInt(&buf, 8, 0, 42)]);

    const big: u64 = (1 << 62) - 1;
    const big_round = try decodePrefixedInt(buf[0..encodePrefixedInt(&buf, 5, 0, big)], 5);
    try std.testing.expectEqual(big, big_round.value);
}

test "zix http3: RFC 9204 Appendix A static table and 4.2 streams" {
    try std.testing.expect(fieldIs(static_table[0], ":authority", ""));
    try std.testing.expect(fieldIs(static_table[17], ":method", "GET"));
    try std.testing.expect(fieldIs(static_table[23], ":scheme", "https"));
    try std.testing.expect(fieldIs(static_table[25], ":status", "200"));

    // The content-negotiation entries: accept-encoding (request input) and content-encoding (served
    // codings). staticEntry resolves them so request decode maps index 31 to accept-encoding.
    try std.testing.expect(fieldIs(staticEntry(31).?, "accept-encoding", "gzip, deflate, br"));
    try std.testing.expect(fieldIs(staticEntry(42).?, "content-encoding", "br"));
    try std.testing.expect(fieldIs(staticEntry(43).?, "content-encoding", "gzip"));

    var registry = StreamRegistry{};
    try registry.register(encoder_stream_type);
    try registry.register(decoder_stream_type);
    try std.testing.expect(registry.encoder_open and registry.decoder_open);
    try std.testing.expectError(error.ZixStreamCreationError, registry.register(encoder_stream_type));
    try std.testing.expectError(error.ZixStreamCreationError, registry.register(decoder_stream_type));
}

test "zix http3: the static table is the whole Appendix A, origin included" {
    // A client may reference any Appendix A index, so a table that stops early is a name the decoder
    // cannot resolve. `origin` (90) is the one the WebTransport binding reads; the values 52/54 and 57
    // are the ones the RFC wraps mid-token in its own fixed-width table, so they are pinned here to
    // the unwrapped values: folding them wrongly in would be silent.
    try std.testing.expectEqual(@as(usize, 99), static_table.len);

    try std.testing.expect(fieldIs(staticEntry(0).?, ":authority", ""));
    try std.testing.expect(fieldIs(staticEntry(52).?, "content-type", "text/html; charset=utf-8"));
    try std.testing.expect(fieldIs(staticEntry(54).?, "content-type", "text/plain;charset=utf-8"));
    try std.testing.expect(fieldIs(staticEntry(57).?, "strict-transport-security", "max-age=31536000; includesubdomains"));
    try std.testing.expect(fieldIs(staticEntry(85).?, "content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"));
    try std.testing.expect(fieldIs(staticEntry(90).?, "origin", ""));
    try std.testing.expect(fieldIs(staticEntry(98).?, "x-frame-options", "sameorigin"));

    // Past the table is past what any client may reference.
    try std.testing.expect(staticEntry(99) == null);
}

test "zix http3: RFC 9204 4.5 static-table field line representations" {
    const idx_path = try decodeIndexedFieldLine(&hexBytes("c1"));
    try std.testing.expect(idx_path.static and fieldIs(static_table[idx_path.index], ":path", "/"));

    const idx_get = try decodeIndexedFieldLine(&hexBytes("d1"));
    try std.testing.expect(idx_get.static and fieldIs(static_table[idx_get.index], ":method", "GET"));

    const idx_status = try decodeIndexedFieldLine(&hexBytes("d9"));
    try std.testing.expect(idx_status.static and fieldIs(static_table[idx_status.index], ":status", "200"));

    var buf: [16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &hexBytes("d9"), buf[0..encodeStaticIndexedFieldLine(&buf, 25)]);

    const lit = try decodeLiteralNameRef(&hexBytes("500b6578616d706c652e636f6d"));
    try std.testing.expect(lit.static and std.mem.eql(u8, static_table[lit.name_index].name, ":authority"));
    try std.testing.expect(std.mem.eql(u8, lit.value, "example.com") and !lit.huffman);
}

test "zix http3: RFC 9204 4.5.6 literal field line with a literal name" {
    // `:protocol: webtransport` spelled out, which is the only way a name with no static entry can
    // arrive: leading '001' (0x27 with the 3-bit prefix saturated), the name length as a continuation
    // byte (0x02, so 9 in total), the name, then the value as an 8-bit prefix string literal.
    const encoded = hexBytes("27023a70726f746f636f6c0c7765627472616e73706f7274");
    var scratch: [32]u8 = undefined;

    const line = try decodeLiteralLiteralName(&encoded, &scratch);
    try std.testing.expectEqualStrings(":protocol", line.name);
    try std.testing.expect(!line.name_huffman);
    try std.testing.expectEqualStrings("webtransport", line.value);
    try std.testing.expect(!line.huffman);
    try std.testing.expectEqual(encoded.len, line.len);

    // The representations are told apart by their leading bits, in both directions.
    try std.testing.expectError(error.ZixNotLiteralNameRef, decodeLiteralNameRef(&encoded));
    try std.testing.expectError(error.ZixNotLiteralLiteralName, decodeLiteralLiteralName(&hexBytes("c1"), &scratch));

    // A name length left without its continuation byte is a truncated representation.
    try std.testing.expectError(error.ZixTruncated, decodeLiteralLiteralName(&hexBytes("27"), &scratch));
}

test "zix http3: RFC 9204 4.5.6 expands a Huffman-coded name and leaves the value coded" {
    // The same line with both strings Huffman-coded, the shape a browser sends: the name's 'H' bit is
    // set (0x2f) and so is the value's (0x89).
    const encoded = hexBytes("2f00b95d8749c87a3f89f058d360ea4567b13f");
    var scratch: [32]u8 = undefined;

    const line = try decodeLiteralLiteralName(&encoded, &scratch);
    try std.testing.expect(line.name_huffman);
    try std.testing.expectEqualStrings(":protocol", line.name);
    try std.testing.expect(line.huffman);

    // The value is handed over exactly as it arrived: Huffman("webtransport"), for the caller to
    // expand only if it is going to use it.
    try std.testing.expectEqualSlices(u8, &hexBytes("f058d360ea4567b13f"), line.value);
    try std.testing.expectEqual(encoded.len, line.len);

    // Without a scratch the name cannot be compared, so it comes back empty (the line is then not one
    // the caller models), and the representation is still measured out whole.
    const dropped = try decodeLiteralLiteralName(&encoded, &[_]u8{});
    try std.testing.expectEqual(@as(usize, 0), dropped.name.len);
    try std.testing.expect(dropped.name_huffman);
    try std.testing.expectEqualSlices(u8, line.value, dropped.value);
    try std.testing.expectEqual(encoded.len, dropped.len);
}

test "zix http3: RFC 9204 4.5.6 drops a Huffman name too long for the scratch" {
    // A 64-byte name, Huffman-coded to 56 bytes ('x' is a 7-bit code, repeated). The scratch holds 48,
    // so the name is unreadable and comes back empty, while the value and the length are still read:
    // the walk can move on either way.
    const encoded = hexBytes("2f31" ++ "f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9f3e7cf9" ++ "0176");
    var scratch: [48]u8 = undefined;

    const line = try decodeLiteralLiteralName(&encoded, &scratch);
    try std.testing.expect(line.name_huffman);
    try std.testing.expectEqual(@as(usize, 0), line.name.len);
    try std.testing.expectEqualStrings("v", line.value);
    try std.testing.expect(!line.huffman);
    try std.testing.expectEqual(encoded.len, line.len);
}

test "zix http3: encodeStaticLiteralNameRef writes a field line its own decoder reads back" {
    // The `:authority: example.com` line above, built rather than parsed: a 4-bit prefix name index
    // (0 fits in the prefix byte) and a plain 8-bit prefix string literal.
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &hexBytes("500b6578616d706c652e636f6d"), buf[0..encodeStaticLiteralNameRef(&buf, 0, "example.com")]);

    // A name index past what the 4-bit prefix holds, which is the shape a response status uses: the
    // prefix saturates and the remainder follows as a continuation byte.
    const status_len = encodeStaticLiteralNameRef(&buf, 24, "413");
    const decoded = try decodeLiteralNameRef(buf[0..status_len]);

    try std.testing.expect(decoded.static and !decoded.huffman);
    try std.testing.expectEqualStrings(":status", static_table[decoded.name_index].name);
    try std.testing.expectEqualStrings("413", decoded.value);
    try std.testing.expectEqual(status_len, decoded.len);
}
