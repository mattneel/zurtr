//! zix SDP attributes (RFC 8866 6).
//!
//! What:
//! - The `a=` line and its two forms: a bare name that means something by being present, and a
//!   name with a value after a colon.
//!
//! Note:
//! - Attribute names are compared exactly. RFC 8866 6 registers them in lower case and every
//!   sender uses that form, so a case-folding compare would only ever loosen what is accepted
//!   without making anything work that does not already.
//! - The value is everything after the first colon, untrimmed. `a=msid-semantic: WMS` really
//!   does carry a leading space, and which fields allow one is a question for the field.
//! - A name with a colon and nothing after it is a value form with an empty value, not a flag.
//!   The two mean different things to a reader checking for presence.
//! - Attributes appear at session level and inside a media section, and the same name can be in
//!   both. Which one wins is a rule per attribute, so the lookups here work over whatever region
//!   the caller hands in and never search a whole description on their own.

const std = @import("std");

const line = @import("line.zig");

/// What separates an attribute name from its value.
pub const SEPARATOR: u8 = ':';

/// Everything that stops an attribute from being built.
pub const Error = error{
    /// The output buffer is too small.
    ZixNoSpace,
};

/// One attribute, borrowed from the description it came from.
pub const Attribute = struct {
    name: []const u8,
    /// Null for the bare form, where presence is the whole meaning.
    value: ?[]const u8,

    /// Whether this is the bare form.
    ///
    /// Return:
    /// - bool
    pub fn isFlag(self: Attribute) bool {
        return self.value == null;
    }
};

/// Split one `a=` line value into a name and a value.
///
/// Param:
/// text - []const u8 (everything after `a=`)
///
/// Return:
/// - Attribute borrowing `text`
pub fn read(text: []const u8) Attribute {
    const at = std.mem.indexOfScalar(u8, text, SEPARATOR) orelse
        return .{ .name = text, .value = null };

    return .{ .name = text[0..at], .value = text[at + 1 ..] };
}

/// Walks the attributes of a validated region.
pub const Iterator = struct {
    lines: line.Iterator,

    /// Start over a region.
    ///
    /// Param:
    /// text - []const u8 (validated description or section)
    ///
    /// Return:
    /// - Iterator
    pub fn begin(text: []const u8) Iterator {
        return .{ .lines = .{ .text = text } };
    }

    /// The next attribute, or null at the end of the region.
    ///
    /// Return:
    /// - ?Attribute
    pub fn next(self: *Iterator) ?Attribute {
        while (self.lines.next()) |item| {
            if (item.kind != .ATTRIBUTE) continue;

            return read(item.value);
        }

        return null;
    }
};

/// The first attribute with a given name.
///
/// Param:
/// text - []const u8 (validated description or section)
/// name - []const u8
///
/// Return:
/// - ?Attribute
pub fn find(text: []const u8, name: []const u8) ?Attribute {
    var iterator = Iterator.begin(text);

    while (iterator.next()) |item| {
        if (std.mem.eql(u8, item.name, name)) return item;
    }

    return null;
}

/// The value of the first attribute with a given name.
///
/// Note:
/// - Null covers both "not there" and "there in the bare form", because neither carries a value
///   to read.
///
/// Param:
/// text - []const u8 (validated description or section)
/// name - []const u8
///
/// Return:
/// - ?[]const u8
pub fn findValue(text: []const u8, name: []const u8) ?[]const u8 {
    const found = find(text, name) orelse return null;

    return found.value;
}

/// Whether an attribute is present, in either form.
///
/// Param:
/// text - []const u8 (validated description or section)
/// name - []const u8
///
/// Return:
/// - bool
pub fn has(text: []const u8, name: []const u8) bool {
    return find(text, name) != null;
}

/// How many bytes an attribute line will take once written.
///
/// Param:
/// name - []const u8
/// value - ?[]const u8
///
/// Return:
/// - usize
pub fn writtenLen(name: []const u8, value: ?[]const u8) usize {
    const carried = value orelse return line.writtenLen(name);

    return lineLen(name.len + 1 + carried.len);
}

/// Write one attribute line, terminator included.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// name - []const u8
/// value - ?[]const u8 (null for the bare form)
///
/// Return:
/// - []const u8, the whole line
/// - error.ZixNoSpace
pub fn write(out: []u8, name: []const u8, value: ?[]const u8) Error![]const u8 {
    const carried = value orelse
        return line.write(out, .ATTRIBUTE, name) catch return error.ZixNoSpace;

    const total = lineLen(name.len + 1 + carried.len);

    if (out.len < total) return error.ZixNoSpace;

    // Built in place, because the name and value only become one string on the wire.
    out[0] = @intFromEnum(line.Kind.ATTRIBUTE);
    out[1] = '=';
    @memcpy(out[2..][0..name.len], name);
    out[2 + name.len] = SEPARATOR;
    @memcpy(out[3 + name.len ..][0..carried.len], carried);
    @memcpy(out[3 + name.len + carried.len ..][0..line.TERMINATOR.len], line.TERMINATOR);

    return out[0..total];
}

/// How long a line carrying a body of this many bytes ends up.
fn lineLen(body_len: usize) usize {
    return line.MIN_LINE_LEN + body_len + line.TERMINATOR.len;
}

// --------------------------------------------------------------------------------------- //
// test cases

const sample: []const u8 =
    "v=0\r\n" ++
    "a=group:BUNDLE 0\r\n" ++
    "a=ice-lite\r\n" ++
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
    "a=mid:0\r\n" ++
    "a=sctp-port:5000\r\n";

test "zix sdp: attribute read, the value form splits at the first colon" {
    const parsed = read("ice-ufrag:8hhY");

    try std.testing.expectEqualStrings("ice-ufrag", parsed.name);
    try std.testing.expectEqualStrings("8hhY", parsed.value.?);
    try std.testing.expect(!parsed.isFlag());
}

test "zix sdp: attribute read, a later colon stays inside the value" {
    const parsed = read("fingerprint:sha-256 AB:CD:EF");

    try std.testing.expectEqualStrings("fingerprint", parsed.name);
    try std.testing.expectEqualStrings("sha-256 AB:CD:EF", parsed.value.?);
}

test "zix sdp: attribute read, a bare name is a flag" {
    const parsed = read("ice-lite");

    try std.testing.expectEqualStrings("ice-lite", parsed.name);
    try std.testing.expect(parsed.isFlag());
}

test "zix sdp: attribute read, a name with an empty value is not a flag" {
    const parsed = read("mid:");

    try std.testing.expectEqualStrings("mid", parsed.name);
    try std.testing.expectEqualStrings("", parsed.value.?);
    try std.testing.expect(!parsed.isFlag());
}

test "zix sdp: attribute read, the leading space of a value is kept" {
    const parsed = read("msid-semantic: WMS");

    try std.testing.expectEqualStrings(" WMS", parsed.value.?);
}

test "zix sdp: attribute iterate, only attribute lines come back" {
    var iterator = Iterator.begin(sample);

    try std.testing.expectEqualStrings("group", iterator.next().?.name);
    try std.testing.expectEqualStrings("ice-lite", iterator.next().?.name);
    try std.testing.expectEqualStrings("mid", iterator.next().?.name);
    try std.testing.expectEqualStrings("sctp-port", iterator.next().?.name);
    try std.testing.expect(iterator.next() == null);
}

test "zix sdp: attribute find, a name that is there comes back" {
    const found = find(sample, "sctp-port") orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("5000", found.value.?);
}

test "zix sdp: attribute find, a name that is not there gives null" {
    try std.testing.expect(find(sample, "ice-ufrag") == null);
}

test "zix sdp: attribute find, the compare is exact" {
    // Every sender writes these in lower case, and accepting another spelling here would hide a
    // description that no other endpoint would read the same way.
    try std.testing.expect(find(sample, "SCTP-PORT") == null);
    try std.testing.expect(find(sample, "sctp-por") == null);
}

test "zix sdp: attribute findValue, a flag has no value to read" {
    try std.testing.expect(findValue(sample, "ice-lite") == null);
    try std.testing.expect(has(sample, "ice-lite"));
}

test "zix sdp: attribute has, presence is what a flag means" {
    try std.testing.expect(has(sample, "mid"));
    try std.testing.expect(!has(sample, "ice-mismatch"));
}

test "zix sdp: attribute find, a region search stops at the region" {
    const media_at = std.mem.indexOf(u8, sample, "m=").?;
    const session = sample[0..media_at];

    try std.testing.expect(has(session, "ice-lite"));
    try std.testing.expect(!has(session, "sctp-port"));
}

test "zix sdp: attribute write, the value form" {
    var buf: [32]u8 = undefined;

    try std.testing.expectEqualStrings("a=mid:0\r\n", try write(&buf, "mid", "0"));
}

test "zix sdp: attribute write, the bare form" {
    var buf: [32]u8 = undefined;

    try std.testing.expectEqualStrings("a=ice-lite\r\n", try write(&buf, "ice-lite", null));
}

test "zix sdp: attribute write, a buffer one byte short errors" {
    var buf: [8]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, write(&buf, "mid", "0"));
    try std.testing.expectError(error.ZixNoSpace, write(buf[0..5], "ice-lite", null));
}

test "zix sdp: attribute write, what was written reads back the same" {
    var buf: [64]u8 = undefined;
    const written = try write(&buf, "fingerprint", "sha-256 AB:CD");

    try line.validate(written);

    const found = find(written, "fingerprint") orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("sha-256 AB:CD", found.value.?);
}

test "zix sdp: attribute writtenLen, the length matches what was written" {
    var buf: [64]u8 = undefined;

    try std.testing.expectEqual(writtenLen("mid", "0"), (try write(&buf, "mid", "0")).len);
    try std.testing.expectEqual(
        writtenLen("ice-lite", null),
        (try write(&buf, "ice-lite", null)).len,
    );
}
