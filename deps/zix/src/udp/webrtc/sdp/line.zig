//! zix SDP line syntax (RFC 8866 5).
//!
//! What:
//! - The shape every line of a session description takes, which is one letter, an equals sign,
//!   and a value: reading them in order, finding one, and writing one.
//!
//! Note:
//! - Lines end with CRLF, and RFC 8866 5 says a parser should also accept a single LF. Browsers
//!   send CRLF and signaling paths that pass descriptions through text handling do not always
//!   keep it, so both are taken here and CRLF is what goes out.
//! - The type is exactly one character and it is case-sensitive. There is no continuation and no
//!   folding, so a line is a line.
//! - The value is everything after the equals sign, untrimmed. A leading space is part of some
//!   values a browser sends, and deciding what is padding belongs to whoever reads the field.
//! - A whole description is validated first, so walking it afterwards cannot fail and no caller
//!   repeats the check. Same shape as the SCTP chunk and parameter readers.

const std = @import("std");

/// What ends a line on the way out.
pub const TERMINATOR: []const u8 = "\r\n";

/// The shortest a line can be, being a type, an equals sign, and an empty value.
pub const MIN_LINE_LEN: usize = 2;

/// Everything that stops a line from being read or built.
pub const Error = error{
    /// A line without a type character followed by an equals sign.
    ZixMalformed,
    /// The output buffer is too small.
    ZixNoSpace,
};

/// The line types RFC 8866 5 defines.
pub const Kind = enum(u8) {
    VERSION = 'v',
    ORIGIN = 'o',
    SESSION_NAME = 's',
    INFORMATION = 'i',
    URI = 'u',
    EMAIL = 'e',
    PHONE = 'p',
    CONNECTION = 'c',
    BANDWIDTH = 'b',
    TIME = 't',
    REPEAT = 'r',
    ZONE = 'z',
    KEY = 'k',
    ATTRIBUTE = 'a',
    MEDIA = 'm',
    _,
};

/// One line, borrowed from the description it came from.
pub const Line = struct {
    kind: Kind,
    /// Everything after the equals sign, with the terminator taken off and nothing trimmed.
    value: []const u8,
    /// Where the type character sits in the text this was read from, which is what lets a
    /// caller cut the text into regions without walking it twice.
    offset: usize,
};

/// Check that every line in a description has a type and an equals sign.
///
/// Note:
/// - Empty lines are allowed and skipped. A description that came through a text channel often
///   picks one up at the end, and refusing it would reject a description that is otherwise fine.
///
/// Param:
/// text - []const u8 (a whole session description)
///
/// Return:
/// - void
/// - error.ZixMalformed
pub fn validate(text: []const u8) Error!void {
    var walker = Walker{ .text = text };

    while (walker.nextRaw()) |raw| {
        if (raw.len == 0) continue;
        if (raw.len < MIN_LINE_LEN) return error.ZixMalformed;
        if (raw[1] != '=') return error.ZixMalformed;
    }
}

/// Walks the lines of a validated description.
///
/// Note:
/// - Only construct this over text `validate` has accepted.
pub const Iterator = struct {
    text: []const u8,
    pos: usize = 0,

    /// The next line, or null at the end.
    ///
    /// Return:
    /// - ?Line
    pub fn next(self: *Iterator) ?Line {
        var walker = Walker{ .text = self.text, .pos = self.pos, .line_at = self.pos };

        while (walker.nextRaw()) |raw| {
            const start = walker.line_at;
            self.pos = walker.pos;

            if (raw.len < MIN_LINE_LEN) continue;

            return .{ .kind = @enumFromInt(raw[0]), .value = raw[2..], .offset = start };
        }

        self.pos = walker.pos;

        return null;
    }
};

/// The first line of a given type.
///
/// Param:
/// text - []const u8 (validated description or section)
/// kind - Kind
///
/// Return:
/// - ?Line
pub fn find(text: []const u8, kind: Kind) ?Line {
    var iterator = Iterator{ .text = text };

    while (iterator.next()) |item| {
        if (item.kind == kind) return item;
    }

    return null;
}

/// How many lines of a given type there are.
///
/// Param:
/// text - []const u8 (validated description or section)
/// kind - Kind
///
/// Return:
/// - usize
pub fn count(text: []const u8, kind: Kind) usize {
    var found: usize = 0;
    var iterator = Iterator{ .text = text };

    while (iterator.next()) |item| {
        if (item.kind == kind) found += 1;
    }

    return found;
}

/// How many bytes a line will take once written.
///
/// Param:
/// value - []const u8
///
/// Return:
/// - usize
pub fn writtenLen(value: []const u8) usize {
    return MIN_LINE_LEN + value.len + TERMINATOR.len;
}

/// Write one line, terminator included.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// kind - Kind
/// value - []const u8 (everything after the equals sign)
///
/// Return:
/// - []const u8, the whole line
/// - error.ZixNoSpace
pub fn write(out: []u8, kind: Kind, value: []const u8) Error![]const u8 {
    const total = writtenLen(value);

    if (out.len < total) return error.ZixNoSpace;

    out[0] = @intFromEnum(kind);
    out[1] = '=';
    @memcpy(out[MIN_LINE_LEN..][0..value.len], value);
    @memcpy(out[MIN_LINE_LEN + value.len ..][0..TERMINATOR.len], TERMINATOR);

    return out[0..total];
}

/// Splits text into lines on either terminator, keeping neither.
const Walker = struct {
    text: []const u8,
    pos: usize = 0,
    /// Where the line most recently returned starts.
    line_at: usize = 0,

    /// The next line as it stands, empty ones included.
    fn nextRaw(self: *Walker) ?[]const u8 {
        if (self.pos >= self.text.len) return null;

        const start = self.pos;
        self.line_at = start;
        const end = std.mem.indexOfScalarPos(u8, self.text, start, '\n') orelse {
            self.pos = self.text.len;

            return trimReturn(self.text[start..]);
        };

        self.pos = end + 1;

        return trimReturn(self.text[start..end]);
    }

    /// Take off the carriage return a CRLF leaves behind.
    fn trimReturn(raw: []const u8) []const u8 {
        if (raw.len != 0 and raw[raw.len - 1] == '\r') return raw[0 .. raw.len - 1];

        return raw;
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

const sample: []const u8 =
    "v=0\r\n" ++
    "o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n" ++
    "s=-\r\n" ++
    "t=0 0\r\n" ++
    "a=group:BUNDLE 0\r\n" ++
    "m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n" ++
    "a=mid:0\r\n";

test "zix sdp: line validate, a well formed description passes" {
    try validate(sample);
}

test "zix sdp: line validate, a line without an equals sign is refused" {
    try std.testing.expectError(error.ZixMalformed, validate("v=0\r\nbroken\r\n"));
}

test "zix sdp: line validate, a one character line is refused" {
    try std.testing.expectError(error.ZixMalformed, validate("v=0\r\nx\r\n"));
}

test "zix sdp: line validate, a trailing empty line is allowed" {
    try validate("v=0\r\n\r\n");
    try validate("v=0\r\n");
    try validate("v=0");
}

test "zix sdp: line iterate, every line comes back in order" {
    var iterator = Iterator{ .text = sample };

    try std.testing.expectEqual(Kind.VERSION, iterator.next().?.kind);
    try std.testing.expectEqual(Kind.ORIGIN, iterator.next().?.kind);
    try std.testing.expectEqual(Kind.SESSION_NAME, iterator.next().?.kind);
    try std.testing.expectEqual(Kind.TIME, iterator.next().?.kind);
    try std.testing.expectEqual(Kind.ATTRIBUTE, iterator.next().?.kind);
    try std.testing.expectEqual(Kind.MEDIA, iterator.next().?.kind);
    try std.testing.expectEqual(Kind.ATTRIBUTE, iterator.next().?.kind);
    try std.testing.expect(iterator.next() == null);
}

test "zix sdp: line iterate, the value keeps everything after the equals sign" {
    var iterator = Iterator{ .text = "a=msid-semantic: WMS\r\n" };
    const item = iterator.next().?;

    // The leading space is part of what a browser sends, so trimming it here would change the
    // value under whoever reads it.
    try std.testing.expectEqualStrings("msid-semantic: WMS", item.value);
}

test "zix sdp: line iterate, a bare newline ends a line just as well" {
    var iterator = Iterator{ .text = "v=0\no=- 1 2 IN IP4 0.0.0.0\n" };

    try std.testing.expectEqualStrings("0", iterator.next().?.value);
    try std.testing.expectEqualStrings("- 1 2 IN IP4 0.0.0.0", iterator.next().?.value);
    try std.testing.expect(iterator.next() == null);
}

test "zix sdp: line iterate, the two terminators can be mixed" {
    var iterator = Iterator{ .text = "v=0\r\ns=-\nt=0 0\r\n" };

    try std.testing.expectEqual(Kind.VERSION, iterator.next().?.kind);
    try std.testing.expectEqual(Kind.SESSION_NAME, iterator.next().?.kind);
    try std.testing.expectEqual(Kind.TIME, iterator.next().?.kind);
    try std.testing.expect(iterator.next() == null);
}

test "zix sdp: line iterate, a last line with no terminator is still a line" {
    var iterator = Iterator{ .text = "v=0\r\na=mid:0" };

    _ = iterator.next();

    try std.testing.expectEqualStrings("mid:0", iterator.next().?.value);
}

test "zix sdp: line iterate, empty lines are passed over" {
    var iterator = Iterator{ .text = "v=0\r\n\r\n\r\ns=-\r\n" };

    try std.testing.expectEqual(Kind.VERSION, iterator.next().?.kind);
    try std.testing.expectEqual(Kind.SESSION_NAME, iterator.next().?.kind);
    try std.testing.expect(iterator.next() == null);
}

test "zix sdp: line iterate, an empty description gives nothing" {
    var iterator = Iterator{ .text = "" };

    try std.testing.expect(iterator.next() == null);
}

test "zix sdp: line find, the first line of a type comes back" {
    const item = find(sample, .MEDIA) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("application 9 UDP/DTLS/SCTP webrtc-datachannel", item.value);
}

test "zix sdp: line find, a type that is not there gives null" {
    try std.testing.expect(find(sample, .CONNECTION) == null);
}

test "zix sdp: line find, the first of several is the one returned" {
    const item = find(sample, .ATTRIBUTE) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("group:BUNDLE 0", item.value);
}

test "zix sdp: line count, repeated types are counted" {
    try std.testing.expectEqual(@as(usize, 2), count(sample, .ATTRIBUTE));
    try std.testing.expectEqual(@as(usize, 1), count(sample, .MEDIA));
    try std.testing.expectEqual(@as(usize, 0), count(sample, .CONNECTION));
}

test "zix sdp: line kind, an unregistered type character survives as itself" {
    var iterator = Iterator{ .text = "q=something\r\n" };
    const item = iterator.next().?;

    try std.testing.expectEqual(@as(u8, 'q'), @intFromEnum(item.kind));
}

test "zix sdp: line write, the line ends with CRLF" {
    var buf: [32]u8 = undefined;
    const written = try write(&buf, .VERSION, "0");

    try std.testing.expectEqualStrings("v=0\r\n", written);
}

test "zix sdp: line write, an empty value is still a line" {
    var buf: [8]u8 = undefined;

    try std.testing.expectEqualStrings("s=\r\n", try write(&buf, .SESSION_NAME, ""));
}

test "zix sdp: line write, a buffer one byte short errors" {
    var buf: [4]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, write(&buf, .VERSION, "0"));
}

test "zix sdp: line write, what was written reads back the same" {
    var buf: [64]u8 = undefined;
    const written = try write(&buf, .MEDIA, "application 9 UDP/DTLS/SCTP webrtc-datachannel");

    try validate(written);

    const item = find(written, .MEDIA) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("application 9 UDP/DTLS/SCTP webrtc-datachannel", item.value);
}

test "zix sdp: line iterate, the offset points at the type character" {
    var iterator = Iterator{ .text = sample };

    while (iterator.next()) |item| {
        try std.testing.expectEqual(@intFromEnum(item.kind), sample[item.offset]);
        try std.testing.expectEqual(@as(u8, '='), sample[item.offset + 1]);
    }
}

test "zix sdp: line iterate, the offset survives an empty line before it" {
    const text = "v=0\r\n\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";

    var iterator = Iterator{ .text = text };
    _ = iterator.next();

    const media = iterator.next().?;

    try std.testing.expectEqualStrings("m=application", text[media.offset..][0..13]);
}

test "zix sdp: line writtenLen, the length matches what was written" {
    var buf: [64]u8 = undefined;
    const written = try write(&buf, .ATTRIBUTE, "mid:0");

    try std.testing.expectEqual(writtenLen("mid:0"), written.len);
}
