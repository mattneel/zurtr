//! jzon string escape rules (RFC 8259 7).
//!
//! What:
//! - One rule set, used in both directions: which bytes a JSON string may not
//!   carry raw, and how each is spelled.
//! - Encoding matches `std.json.Stringify` at its default options byte for byte,
//!   so output from either side is interchangeable.
//! - Decoding reads every escape form `std.json` reads, and refuses an unpaired
//!   surrogate half the same way. It is handed a string token's body, so whether
//!   that body was bounded correctly is the read cursor's question.

const std = @import("std");

const Sink = @import("sink.zig").Sink;

/// How encoding can fail. Encoding never allocates, so a full buffer is all of it.
pub const EncodeError = @import("sink.zig").Error;

/// How decoding can fail: no room for the decoded bytes, or an escape the rules
/// do not spell.
pub const DecodeError = error{ NoSpaceLeft, JzonBadEscape };

const HEX_DIGITS = "0123456789abcdef";

/// One escaped form, held as a fixed array so the table below needs no pointers.
const Escaped = struct {
    text: [6]u8,
    len: u8,
};

/// The escaped form of every control byte. Five have a two-character spelling,
/// the rest go out as `\u00xx` with lowercase hex, which is what std emits.
const CONTROL: [0x20]Escaped = build: {
    var table: [0x20]Escaped = undefined;

    for (&table, 0..) |*entry, index| {
        const short: ?[]const u8 = switch (index) {
            0x08 => "\\b",
            0x09 => "\\t",
            0x0a => "\\n",
            0x0c => "\\f",
            0x0d => "\\r",
            else => null,
        };

        if (short) |form| {
            entry.* = .{ .text = .{ form[0], form[1], 0, 0, 0, 0 }, .len = 2 };
            continue;
        }

        entry.* = .{
            .text = .{ '\\', 'u', '0', '0', HEX_DIGITS[index >> 4], HEX_DIGITS[index & 0x0f] },
            .len = 6,
        };
    }

    break :build table;
};

/// Whether one byte cannot go out raw.
///
/// Note:
/// - This is the whole rule, and every scan over a string asks it. A scan that
///   classifies bytes some other way, a vector lane at a time say, still spells
///   each hit through `spell`, so the two never drift apart.
///
/// Param:
/// byte - u8 (the byte to classify)
///
/// Return:
/// - bool (true when the byte has to be escaped)
pub inline fn isEscaped(byte: u8) bool {
    return byte == '"' or byte == '\\' or byte < 0x20;
}

/// Whether `text` holds a byte that cannot go out raw.
///
/// Note:
/// - A parser uses this to decide it may hand back a slice of the source instead
///   of copying, and an emitter to skip the escape scan for a clean run.
///
/// Param:
/// text - []const u8 (the bytes to check)
///
/// Return:
/// - bool (true when at least one byte needs escaping)
pub fn needsEscape(text: []const u8) bool {
    for (text) |byte| {
        if (isEscaped(byte)) return true;
    }

    return false;
}

/// Write one byte's escaped spelling.
///
/// Note:
/// - Meant for a byte `isEscaped` accepts. Any other byte is written as itself,
///   which is what it would have been anyway, so a caller that classifies wrongly
///   still emits correct text.
///
/// Param:
/// sink - *Sink (where the spelling goes)
/// byte - u8 (the byte to spell)
///
/// Return:
/// - void
/// - error.NoSpaceLeft when the spelling does not fit
pub fn spell(sink: *Sink, byte: u8) EncodeError!void {
    switch (byte) {
        '"' => try sink.literal("\\\""),
        '\\' => try sink.literal("\\\\"),
        0x00...0x1f => {
            const entry = CONTROL[byte];
            try sink.bytes(entry.text[0..entry.len]);
        },
        else => try sink.byte(byte),
    }
}

/// Write `text` as a complete JSON string, quotes included.
///
/// Param:
/// sink - *Sink (where the string goes)
/// text - []const u8 (the bytes to escape and write)
///
/// Return:
/// - void
/// - error.NoSpaceLeft when the escaped form does not fit
pub fn encode(sink: *Sink, text: []const u8) EncodeError!void {
    try sink.byte('"');
    try encodeBody(sink, text);
    try sink.byte('"');
}

/// Write `text` escaped, without the surrounding quotes.
///
/// Note:
/// - Clean runs are copied whole, so a string with no escape costs one copy.
/// - Bytes at 0x7f and above go out unchanged, which is what std does with its
///   default options. A UTF-8 input stays UTF-8, nothing is escaped to ASCII.
///
/// Param:
/// sink - *Sink (where the bytes go)
/// text - []const u8 (the bytes to escape and write)
///
/// Return:
/// - void
/// - error.NoSpaceLeft when the escaped form does not fit
pub fn encodeBody(sink: *Sink, text: []const u8) EncodeError!void {
    var clean_from: usize = 0;
    var index: usize = 0;

    while (index < text.len) : (index += 1) {
        const byte = text[index];
        if (!isEscaped(byte)) continue;

        try sink.bytes(text[clean_from..index]);
        try spell(sink, byte);

        clean_from = index + 1;
    }

    try sink.bytes(text[clean_from..]);
}

/// Write the decoded value of an escaped string body.
///
/// Note:
/// - `raw` is a string token's bytes without its quotes, the shape
///   `Cursor.stringSpan` hands back.
/// - A `\u` escape becomes UTF-8. A high surrogate must be followed immediately
///   by a low one in `\u` notation, the rule std.json holds to, so an unpaired
///   half is error.JzonBadEscape rather than a replacement character.
///
/// Param:
/// sink - *Sink (where the decoded bytes go)
/// raw - []const u8 (the undecoded string body)
///
/// Return:
/// - void
/// - error.NoSpaceLeft when the decoded form does not fit
/// - error.JzonBadEscape on an escape the rules do not spell
pub fn decode(sink: *Sink, raw: []const u8) DecodeError!void {
    var index: usize = 0;

    while (index < raw.len) {
        if (raw[index] != '\\') {
            const start = index;
            while (index < raw.len and raw[index] != '\\') : (index += 1) {}

            try sink.bytes(raw[start..index]);
            continue;
        }

        index += 1;
        if (index == raw.len) return error.JzonBadEscape;

        const spelling = raw[index];
        index += 1;

        switch (spelling) {
            '"' => try sink.byte('"'),
            '\\' => try sink.byte('\\'),
            '/' => try sink.byte('/'),
            'b' => try sink.byte(0x08),
            'f' => try sink.byte(0x0c),
            'n' => try sink.byte('\n'),
            'r' => try sink.byte('\r'),
            't' => try sink.byte('\t'),
            'u' => index = try decodeUnicode(sink, raw, index),
            else => return error.JzonBadEscape,
        }
    }
}

/// Decode a `\u` escape whose four hex digits start at `index`, joining a
/// surrogate pair when the first half is a high surrogate.
///
/// Return:
/// - usize (the position just past the escape that was decoded)
/// - error.NoSpaceLeft when the encoded code point does not fit
/// - error.JzonBadEscape on a short escape, a bad hex digit, or an unpaired half
fn decodeUnicode(sink: *Sink, raw: []const u8, index: usize) DecodeError!usize {
    const first = try hexQuad(raw, index);
    const after_first = index + 4;

    if (first < 0xd800 or first > 0xdfff) {
        try writeUtf8(sink, first);

        return after_first;
    }

    if (first > 0xdbff) return error.JzonBadEscape;
    if (after_first + 6 > raw.len) return error.JzonBadEscape;
    if (raw[after_first] != '\\' or raw[after_first + 1] != 'u') return error.JzonBadEscape;

    const second = try hexQuad(raw, after_first + 2);
    if (second < 0xdc00 or second > 0xdfff) return error.JzonBadEscape;

    const codepoint: u21 = 0x10000 +
        ((@as(u21, first) - 0xd800) << 10) +
        (@as(u21, second) - 0xdc00);
    try writeUtf8(sink, codepoint);

    return after_first + 6;
}

/// Read the four hex digits of a `\u` escape.
fn hexQuad(raw: []const u8, index: usize) DecodeError!u16 {
    if (index + 4 > raw.len) return error.JzonBadEscape;

    var value: u16 = 0;
    for (raw[index..][0..4]) |byte| {
        const digit: u16 = switch (byte) {
            '0'...'9' => byte - '0',
            'a'...'f' => byte - 'a' + 10,
            'A'...'F' => byte - 'A' + 10,
            else => return error.JzonBadEscape,
        };

        value = value * 16 + digit;
    }

    return value;
}

/// Write one code point as UTF-8.
fn writeUtf8(sink: *Sink, codepoint: u21) DecodeError!void {
    var encoded: [4]u8 = undefined;
    const len = std.unicode.utf8Encode(codepoint, &encoded) catch return error.JzonBadEscape;

    try sink.bytes(encoded[0..len]);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Render the same string through std.json.Stringify, for the tests that assert
/// the two agree byte for byte.
fn stdEncoded(buf: []u8, text: []const u8) []const u8 {
    var writer = std.Io.Writer.fixed(buf);
    std.json.Stringify.value(text, .{}, &writer) catch unreachable;

    return writer.buffered();
}

test "jzon: escape leaves a clean string alone" {
    var buf: [32]u8 = undefined;
    var sink: Sink = .init(&buf);

    try encode(&sink, "hello world");

    try std.testing.expectEqualStrings("\"hello world\"", sink.filled());
}

test "jzon: escape spells the quote, the backslash and the named controls" {
    var buf: [64]u8 = undefined;
    var sink: Sink = .init(&buf);

    try encode(&sink, "a\"b\\c\nd\te\rf\x08g\x0ch");

    try std.testing.expectEqualStrings(
        "\"a\\\"b\\\\c\\nd\\te\\rf\\bg\\fh\"",
        sink.filled(),
    );
}

test "jzon: escape spells an unnamed control byte as lowercase hex" {
    var buf: [32]u8 = undefined;
    var sink: Sink = .init(&buf);

    try encode(&sink, "\x00\x0b\x1f");

    try std.testing.expectEqualStrings("\"\\u0000\\u000b\\u001f\"", sink.filled());
}

test "jzon: escape agrees with std.json.Stringify byte for byte" {
    const samples = [_][]const u8{
        "",
        "plain",
        "quote \" and backslash \\",
        "control \x00\x01\x0b\x1f end",
        "named \n\r\t\x08\x0c end",
        "utf8 \xc3\xa9 \xe2\x82\xac \xf0\x9f\x92\xa9",
        "delete \x7f byte",
    };

    for (samples) |sample| {
        var ours: [256]u8 = undefined;
        var sink: Sink = .init(&ours);
        try encode(&sink, sample);

        var theirs: [256]u8 = undefined;
        try std.testing.expectEqualStrings(stdEncoded(&theirs, sample), sink.filled());
    }
}

test "jzon: needsEscape sees exactly what encode would spell" {
    try std.testing.expect(!needsEscape("plain text"));
    try std.testing.expect(!needsEscape("\x7f\xff"));
    try std.testing.expect(needsEscape("with \" quote"));
    try std.testing.expect(needsEscape("with \\ backslash"));
    try std.testing.expect(needsEscape("with \n newline"));
}

test "jzon: isEscaped answers for the byte set encode rewrites" {
    try std.testing.expect(isEscaped('"'));
    try std.testing.expect(isEscaped('\\'));
    try std.testing.expect(isEscaped(0x00));
    try std.testing.expect(isEscaped(0x1f));
    try std.testing.expect(!isEscaped(0x20));
    try std.testing.expect(!isEscaped('a'));
    try std.testing.expect(!isEscaped(0x7f));
    try std.testing.expect(!isEscaped(0xff));
}

test "jzon: spell writes what encodeBody writes for the same byte" {
    for (0..256) |value| {
        const byte: u8 = @intCast(value);

        var one: [8]u8 = undefined;
        var spelled: Sink = .init(&one);
        try spell(&spelled, byte);

        var whole: [8]u8 = undefined;
        var encoded: Sink = .init(&whole);
        try encodeBody(&encoded, &[_]u8{byte});

        try std.testing.expectEqualStrings(encoded.filled(), spelled.filled());
    }
}

test "jzon: decode reverses every spelling encode produces" {
    const samples = [_][]const u8{
        "",
        "plain",
        "quote \" and backslash \\",
        "control \x00\x01\x0b\x1f end",
        "named \n\r\t\x08\x0c end",
        "utf8 \xc3\xa9 \xe2\x82\xac \xf0\x9f\x92\xa9",
    };

    for (samples) |sample| {
        var encoded: [256]u8 = undefined;
        var writer: Sink = .init(&encoded);
        try encodeBody(&writer, sample);

        var decoded: [256]u8 = undefined;
        var reader: Sink = .init(&decoded);
        try decode(&reader, writer.filled());

        try std.testing.expectEqualStrings(sample, reader.filled());
    }
}

test "jzon: decode accepts the escaped solidus encode never emits" {
    var buf: [16]u8 = undefined;
    var sink: Sink = .init(&buf);

    try decode(&sink, "a\\/b");

    try std.testing.expectEqualStrings("a/b", sink.filled());
}

test "jzon: decode joins a surrogate pair into one code point" {
    var buf: [16]u8 = undefined;
    var sink: Sink = .init(&buf);

    try decode(&sink, "\\ud83d\\udca9");

    try std.testing.expectEqualStrings("\xf0\x9f\x92\xa9", sink.filled());
}

test "jzon: decode rejects an unpaired surrogate half" {
    var buf: [16]u8 = undefined;

    var lone_high: Sink = .init(&buf);
    try std.testing.expectError(error.JzonBadEscape, decode(&lone_high, "\\ud83d"));

    var lone_low: Sink = .init(&buf);
    try std.testing.expectError(error.JzonBadEscape, decode(&lone_low, "\\udca9"));

    var high_then_plain: Sink = .init(&buf);
    try std.testing.expectError(error.JzonBadEscape, decode(&high_then_plain, "\\ud83d\\u0041"));
}
