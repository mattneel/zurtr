//! zixer h3 qpack: field section decode and encode for the edge (rfc 9204)

const std = @import("std");
const zix = @import("zix");

const qpack = zix.Http3.qpack;
const huffman = zix.Http3.huffman;

/// Most field lines one section carries, request or response. A section past
/// the bound is refused rather than truncated, so nothing is silently lost.
pub const MAX_FIELDS: usize = 64;

/// Longest single name or value the decoder expands out of Huffman coding.
pub const MAX_STRING: usize = 8 * 1024;

/// Scratch the decoder needs for one section, worst case every string coded.
pub const SCRATCH_BYTES: usize = 16 * 1024;

pub const Error = error{
    /// The block ended inside a representation.
    ZixerTruncated,
    /// The peer referenced its dynamic table. zixer advertises a zero-size
    /// table, so a reference to one is a protocol violation, not a miss.
    ZixerDynamicRef,
    /// A static index outside the rfc 9204 appendix A table.
    ZixerUnknownIndex,
    /// More field lines than MAX_FIELDS.
    ZixerTooManyFields,
    /// A Huffman string that does not decode.
    ZixerBadHuffman,
    /// The caller's scratch or output buffer ran out.
    ZixerBufferFull,
};

/// The only way encoding fails: the output buffer has no room.
pub const EncodeError = error{ZixerBufferFull};

/// One field line, borrowing the wire block or the decode scratch.
pub const Field = struct { name: []const u8, value: []const u8 };

/// A decoded field section.
pub const Section = struct {
    entries: [MAX_FIELDS]Field = undefined,
    len: usize = 0,

    /// The decoded field lines, in wire order.
    pub fn slice(section: *const Section) []const Field {
        return section.entries[0..section.len];
    }

    /// The value of the first field with this name, or null.
    pub fn get(section: *const Section, name: []const u8) ?[]const u8 {
        for (section.slice()) |field| {
            if (std.mem.eql(u8, field.name, name)) return field.value;
        }

        return null;
    }
};

/// Decode one encoded field section (rfc 9204 4.5).
///
/// Note:
/// - Only static-table references are accepted. zixer's SETTINGS advertise no
///   dynamic table, so a dynamic reference is a peer error.
/// - Huffman-coded strings expand into `scratch`, plain ones borrow `block`.
///   Both must outlive the returned section.
///
/// Param:
/// block - []const u8 (the encoded field section, prefix included)
/// scratch - []u8 (expansion space, SCRATCH_BYTES is the safe size)
///
/// Return:
/// - Section with the field lines in wire order
/// - Error when the block is malformed or outgrows the bounds
pub fn decodeSection(block: []const u8, scratch: []u8) Error!Section {
    // Encoded Field Section Prefix (rfc 9204 4.5.1): required insert count
    // then the sign bit plus delta base. A zero insert count is the only one
    // a static-only decoder can honour.
    const insert_count = qpack.decodePrefixedInt(block, 8) catch return error.ZixerTruncated;
    if (insert_count.value != 0) return error.ZixerDynamicRef;

    var pos = insert_count.len;
    if (pos >= block.len) return error.ZixerTruncated;
    const delta_base = qpack.decodePrefixedInt(block[pos..], 7) catch return error.ZixerTruncated;
    pos += delta_base.len;

    var section = Section{};
    var used: usize = 0;

    while (pos < block.len) {
        if (section.len >= MAX_FIELDS) return error.ZixerTooManyFields;

        const lead = block[pos];

        // Indexed field line (4.5.2): the static table bit must be set.
        if (lead & 0x80 != 0) {
            const indexed = qpack.decodeIndexedFieldLine(block[pos..]) catch return error.ZixerTruncated;
            if (!indexed.static) return error.ZixerDynamicRef;

            const entry = staticEntry(indexed.index) orelse return error.ZixerUnknownIndex;
            section.entries[section.len] = .{ .name = entry.name, .value = entry.value };
            section.len += 1;
            pos += indexed.len;
            continue;
        }

        // Literal field line with name reference (4.5.4).
        if (lead & 0xc0 == 0x40) {
            const literal = qpack.decodeLiteralNameRef(block[pos..]) catch return error.ZixerTruncated;
            if (!literal.static) return error.ZixerDynamicRef;

            const entry = staticEntry(literal.name_index) orelse return error.ZixerUnknownIndex;
            const value = try expand(literal.value, literal.huffman, scratch, &used);

            section.entries[section.len] = .{ .name = entry.name, .value = value };
            section.len += 1;
            pos += literal.len;
            continue;
        }

        // Literal field line with literal name (4.5.6).
        if (lead & 0xe0 == 0x20) {
            const name_huffman = lead & 0x08 != 0;
            const name_len = qpack.decodePrefixedInt(block[pos..], 3) catch return error.ZixerTruncated;
            var walk = pos + name_len.len;
            if (walk + name_len.value > block.len) return error.ZixerTruncated;

            const raw_name = block[walk..][0..@intCast(name_len.value)];
            walk += @intCast(name_len.value);
            const name = try expand(raw_name, name_huffman, scratch, &used);

            if (walk >= block.len) return error.ZixerTruncated;
            const value_huffman = block[walk] & 0x80 != 0;
            const value_len = qpack.decodePrefixedInt(block[walk..], 7) catch return error.ZixerTruncated;
            walk += value_len.len;
            if (walk + value_len.value > block.len) return error.ZixerTruncated;

            const raw_value = block[walk..][0..@intCast(value_len.value)];
            walk += @intCast(value_len.value);
            const value = try expand(raw_value, value_huffman, scratch, &used);

            section.entries[section.len] = .{ .name = name, .value = value };
            section.len += 1;
            pos = walk;
            continue;
        }

        // Post-base forms (4.5.3, 4.5.5) address the dynamic table.
        return error.ZixerDynamicRef;
    }

    return section;
}

/// Expand one wire string: Huffman coded into `scratch`, plain borrowed as is.
fn expand(raw: []const u8, coded: bool, scratch: []u8, used: *usize) Error![]const u8 {
    if (!coded) return raw;
    if (raw.len > MAX_STRING) return error.ZixerBufferFull;

    const room = scratch[used.*..];
    const written = huffman.decode(room, raw) orelse return error.ZixerBadHuffman;
    used.* += written;

    return room[0..written];
}

/// Look up an rfc 9204 appendix A entry, null when out of range.
pub fn staticEntry(index: u64) ?Field {
    if (index >= STATIC_TABLE.len) return null;

    return STATIC_TABLE[@intCast(index)];
}

/// Encodes a field section with static-table references only.
///
/// Note:
/// - An exact name plus value match becomes an indexed field line, a name
///   match a literal with name reference, anything else a literal with a
///   literal name. Strings go out uncoded: Huffman coding a response head
///   saves bytes the edge is not short of, and every client decodes both.
///
/// Usage:
/// ```zig
/// var buf: [4096]u8 = undefined;
/// var encoder = Encoder.init(&buf);
/// try encoder.field(":status", "200");
/// try encoder.field("content-length", "12");
/// const block = encoder.encoded();
/// ```
pub const Encoder = struct {
    buf: []u8,
    pos: usize,

    /// Start a section, writing the all-static prefix (insert count 0, base 0).
    pub fn init(buf: []u8) Encoder {
        var encoder = Encoder{ .buf = buf, .pos = 0 };
        if (buf.len >= 2) {
            buf[0] = 0;
            buf[1] = 0;
            encoder.pos = 2;
        }

        return encoder;
    }

    /// Append one field line.
    pub fn field(encoder: *Encoder, name: []const u8, value: []const u8) EncodeError!void {
        if (encoder.buf.len < 2) return error.ZixerBufferFull;

        if (exactIndex(name, value)) |index| {
            try encoder.reserve(prefixedLen(index, 6));
            encoder.pos += qpack.encodeStaticIndexedFieldLine(encoder.buf[encoder.pos..], index);
            return;
        }

        if (nameIndex(name)) |index| {
            try encoder.reserve(prefixedLen(index, 4) + prefixedLen(value.len, 7) + value.len);

            // Literal with name reference (4.5.4): '01', N clear, T set for the
            // static table, then the 4-bit name index.
            encoder.pos += qpack.encodePrefixedInt(encoder.buf[encoder.pos..], 4, 0x50, index);
            try encoder.writeString(value);
            return;
        }

        try encoder.reserve(prefixedLen(name.len, 3) + name.len + prefixedLen(value.len, 7) + value.len);

        // Literal with literal name (4.5.6): '001', N clear, H clear, then the
        // 3-bit name length.
        encoder.pos += qpack.encodePrefixedInt(encoder.buf[encoder.pos..], 3, 0x20, name.len);
        @memcpy(encoder.buf[encoder.pos..][0..name.len], name);
        encoder.pos += name.len;
        try encoder.writeString(value);
    }

    /// The encoded section so far.
    pub fn encoded(encoder: *const Encoder) []const u8 {
        return encoder.buf[0..encoder.pos];
    }

    fn writeString(encoder: *Encoder, value: []const u8) EncodeError!void {
        encoder.pos += qpack.encodePrefixedInt(encoder.buf[encoder.pos..], 7, 0x00, value.len);
        @memcpy(encoder.buf[encoder.pos..][0..value.len], value);
        encoder.pos += value.len;
    }

    fn reserve(encoder: *const Encoder, bytes: usize) EncodeError!void {
        if (encoder.pos + bytes > encoder.buf.len) return error.ZixerBufferFull;
    }
};

/// Bytes an N-bit prefixed integer occupies.
fn prefixedLen(value: u64, prefix_bits: u4) usize {
    const max: u64 = (@as(u64, 1) << prefix_bits) - 1;
    if (value < max) return 1;

    var remaining = value - max;
    var len: usize = 2;
    while (remaining >= 128) : (remaining /= 128) len += 1;

    return len;
}

/// The static index whose name and value both match, or null.
fn exactIndex(name: []const u8, value: []const u8) ?u64 {
    for (STATIC_TABLE, 0..) |entry, index| {
        if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) return index;
    }

    return null;
}

/// The first static index carrying this name, or null.
fn nameIndex(name: []const u8) ?u64 {
    for (STATIC_TABLE, 0..) |entry, index| {
        if (std.mem.eql(u8, entry.name, name)) return index;
    }

    return null;
}

/// The rfc 9204 appendix A static table, all 99 entries. The engine carries
/// the leading block it needs for pseudo-headers, the edge sees whatever a
/// browser sends, so it needs the whole table to decode a request.
pub const STATIC_TABLE = [_]Field{
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

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "zix zixer: h3 qpack, the static table matches rfc 9204 appendix A" {
    try testing.expectEqual(@as(usize, 99), STATIC_TABLE.len);

    // The engine's leading block is the same table, entry for entry.
    for (qpack.static_table, 0..) |entry, index| {
        try testing.expectEqualStrings(entry.name, STATIC_TABLE[index].name);
        try testing.expectEqualStrings(entry.value, STATIC_TABLE[index].value);
    }

    try testing.expectEqualStrings("user-agent", STATIC_TABLE[95].name);
    try testing.expectEqualStrings("content-type", STATIC_TABLE[52].name);
    try testing.expectEqualStrings("text/html; charset=utf-8", STATIC_TABLE[52].value);
    try testing.expect(staticEntry(99) == null);
}

test "zix zixer: h3 qpack, an indexed field line decodes off the static table" {
    // Prefix then :method GET (index 17) and :scheme https (index 23).
    const block = [_]u8{ 0x00, 0x00, 0xc0 | 17, 0xc0 | 23 };

    var scratch: [64]u8 = undefined;
    const section = try decodeSection(&block, &scratch);

    try testing.expectEqual(@as(usize, 2), section.len);
    try testing.expectEqualStrings(":method", section.entries[0].name);
    try testing.expectEqualStrings("GET", section.entries[0].value);
    try testing.expectEqualStrings("https", section.entries[1].value);
}

test "zix zixer: h3 qpack, a literal with name reference borrows the wire value" {
    var buf: [64]u8 = undefined;
    var encoder = Encoder.init(&buf);
    try encoder.field(":path", "/api/items");

    var scratch: [64]u8 = undefined;
    const section = try decodeSection(encoder.encoded(), &scratch);

    try testing.expectEqual(@as(usize, 1), section.len);
    try testing.expectEqualStrings(":path", section.entries[0].name);
    try testing.expectEqualStrings("/api/items", section.entries[0].value);
}

test "zix zixer: h3 qpack, a literal name round trips through the encoder" {
    var buf: [128]u8 = undefined;
    var encoder = Encoder.init(&buf);
    try encoder.field("x-zixer-test", "on");
    try encoder.field(":status", "200");
    try encoder.field("content-length", "42");

    var scratch: [128]u8 = undefined;
    const section = try decodeSection(encoder.encoded(), &scratch);

    try testing.expectEqual(@as(usize, 3), section.len);
    try testing.expectEqualStrings("x-zixer-test", section.entries[0].name);
    try testing.expectEqualStrings("on", section.entries[0].value);
    try testing.expectEqualStrings(":status", section.entries[1].name);
    try testing.expectEqualStrings("200", section.entries[1].value);
    try testing.expectEqualStrings("content-length", section.entries[2].name);
    try testing.expectEqualStrings("42", section.entries[2].value);
}

test "zix zixer: h3 qpack, an exact match encodes as one indexed byte" {
    var buf: [64]u8 = undefined;
    var encoder = Encoder.init(&buf);
    try encoder.field(":status", "200");

    // Prefix plus a single indexed byte for static entry 25.
    try testing.expectEqual(@as(usize, 3), encoder.encoded().len);
    try testing.expectEqual(@as(u8, 0xc0 | 25), encoder.encoded()[2]);
}

test "zix zixer: h3 qpack, a huffman coded value expands into the scratch" {
    // ':authority' name reference (static index 0) carrying the rfc 7541 C.4
    // Huffman coding of "www.example.com".
    const coded = [_]u8{ 0x50, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var block: [2 + coded.len]u8 = undefined;
    block[0] = 0;
    block[1] = 0;
    @memcpy(block[2..], &coded);

    var scratch: [64]u8 = undefined;
    const section = try decodeSection(&block, &scratch);

    try testing.expectEqual(@as(usize, 1), section.len);
    try testing.expectEqualStrings(":authority", section.entries[0].name);
    try testing.expectEqualStrings("www.example.com", section.entries[0].value);
}

test "zix zixer: h3 qpack, a dynamic table reference is refused" {
    // Required insert count 1: the section leans on a dynamic table zixer
    // never advertises.
    const dynamic_prefix = [_]u8{ 0x01, 0x00, 0xc0 | 17 };
    var scratch: [16]u8 = undefined;
    try testing.expectError(error.ZixerDynamicRef, decodeSection(&dynamic_prefix, &scratch));

    // Indexed field line with the static bit clear.
    const dynamic_index = [_]u8{ 0x00, 0x00, 0x80 | 3 };
    try testing.expectError(error.ZixerDynamicRef, decodeSection(&dynamic_index, &scratch));

    // Post-base indexed field line (4.5.3).
    const post_base = [_]u8{ 0x00, 0x00, 0x10 };
    try testing.expectError(error.ZixerDynamicRef, decodeSection(&post_base, &scratch));
}

test "zix zixer: h3 qpack, a truncated section and an unknown index both fault" {
    var scratch: [16]u8 = undefined;

    const truncated = [_]u8{ 0x00, 0x00, 0x20 | 0x04, 'a' };
    try testing.expectError(error.ZixerTruncated, decodeSection(&truncated, &scratch));

    // Static index 120 is past appendix A.
    const unknown = [_]u8{ 0x00, 0x00, 0xc0 | 0x3f, 120 - 63 };
    try testing.expectError(error.ZixerUnknownIndex, decodeSection(&unknown, &scratch));
}

test "zix zixer: h3 qpack, a full section refuses rather than truncating" {
    var buf: [4096]u8 = undefined;
    var encoder = Encoder.init(&buf);

    var name_buf: [24]u8 = undefined;
    for (0..MAX_FIELDS) |index| {
        const name = try std.fmt.bufPrint(&name_buf, "x-field-{d}", .{index});
        try encoder.field(name, "v");
    }

    var scratch: [1024]u8 = undefined;
    const full = try decodeSection(encoder.encoded(), &scratch);
    try testing.expectEqual(MAX_FIELDS, full.len);

    var over = Encoder.init(&buf);
    for (0..MAX_FIELDS + 1) |index| {
        const name = try std.fmt.bufPrint(&name_buf, "x-field-{d}", .{index});
        try over.field(name, "v");
    }
    try testing.expectError(error.ZixerTooManyFields, decodeSection(over.encoded(), &scratch));
}

test "zix zixer: h3 qpack, the encoder refuses to overflow its buffer" {
    var small: [8]u8 = undefined;
    var encoder = Encoder.init(&small);

    try testing.expectError(error.ZixerBufferFull, encoder.field("x-long-name-here", "and-a-long-value"));
}

test "zix zixer: h3 qpack, get finds a field by name" {
    var buf: [128]u8 = undefined;
    var encoder = Encoder.init(&buf);
    try encoder.field(":status", "404");
    try encoder.field("server", "upstream/1");

    var scratch: [64]u8 = undefined;
    const section = try decodeSection(encoder.encoded(), &scratch);

    try testing.expectEqualStrings("404", section.get(":status").?);
    try testing.expectEqualStrings("upstream/1", section.get("server").?);
    try testing.expect(section.get("x-missing") == null);
}
