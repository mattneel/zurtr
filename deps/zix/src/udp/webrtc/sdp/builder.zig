//! zix SDP output buffer (RFC 8866 5).
//!
//! What:
//! - Appending lines to one buffer and keeping track of how far along it is. Nothing about what
//!   the lines mean, only that they go one after another and stop when the room runs out.
//!
//! Note:
//! - This exists because a description is written by more than one file. answer.zig writes the
//!   session level and media_answer.zig writes a section, both into the same buffer, and each
//!   keeping its own copy of the same append loop is how the two drift apart.
//! - Every append is bounds-checked and reports error.ZixNoSpace rather than truncating. A truncated
//!   description parses as a valid shorter one, so silently dropping the tail produces an answer
//!   that looks fine and is missing a fingerprint.
//! - `at` is public so a caller can take the slice written so far, and hand the remaining room to
//!   another writer without copying anything.

const std = @import("std");

const attribute = @import("attribute.zig");
const line = @import("line.zig");

/// The most digits an unsigned 64-bit number takes.
pub const MAX_DIGITS: usize = 20;

/// What stops a line from being appended.
pub const Error = error{
    /// The output buffer has no room left.
    ZixNoSpace,
};

/// Appends lines to one buffer, tracking how far along it is.
pub const Builder = struct {
    out: []u8,
    /// How many bytes have been written.
    at: usize = 0,

    /// Everything written so far.
    ///
    /// Return:
    /// - []const u8 borrowing the output buffer
    pub fn written(self: *const Builder) []const u8 {
        return self.out[0..self.at];
    }

    /// The room that is left.
    ///
    /// Return:
    /// - usize
    pub fn remaining(self: *const Builder) usize {
        return self.out.len - self.at;
    }

    /// Append one line of any type.
    ///
    /// Param:
    /// kind - line.Kind
    /// value - []const u8 (everything after the equals sign)
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSpace
    pub fn addLine(self: *Builder, kind: line.Kind, value: []const u8) Error!void {
        const wrote = line.write(self.out[self.at..], kind, value) catch return error.ZixNoSpace;

        self.at += wrote.len;
    }

    /// Append one attribute line, in either the flag or the value form.
    ///
    /// Param:
    /// name - []const u8
    /// value - ?[]const u8 (null for the flag form)
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSpace
    pub fn addAttribute(self: *Builder, name: []const u8, value: ?[]const u8) Error!void {
        const wrote = attribute.write(self.out[self.at..], name, value) catch return error.ZixNoSpace;

        self.at += wrote.len;
    }

    /// Append an attribute whose value is a number.
    ///
    /// Param:
    /// name - []const u8
    /// value - u64
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSpace
    pub fn addNumber(self: *Builder, name: []const u8, value: u64) Error!void {
        var digits: [MAX_DIGITS]u8 = undefined;

        try self.addAttribute(name, writeNumber(&digits, value));
    }
};

/// Write an unsigned number in base ten.
///
/// Param:
/// out - *[MAX_DIGITS]u8 (scratch, must outlive the result)
/// value - u64
///
/// Return:
/// - []const u8 borrowing `out`
pub fn writeNumber(out: *[MAX_DIGITS]u8, value: u64) []const u8 {
    var digits: [MAX_DIGITS]u8 = undefined;
    var count: usize = 0;
    var left = value;

    while (true) {
        digits[count] = '0' + @as(u8, @intCast(left % 10));
        count += 1;
        left /= 10;

        if (left == 0) break;
    }

    for (0..count) |index| out[index] = digits[count - 1 - index];

    return out[0..count];
}

/// Copy into a buffer already known to be long enough.
///
/// Param:
/// out - []u8
/// text - []const u8
///
/// Return:
/// - usize, how many bytes were copied
pub fn copy(out: []u8, text: []const u8) usize {
    @memcpy(out[0..text.len], text);

    return text.len;
}

// --------------------------------------------------------------------------------------- //
// test cases

const session = @import("session.zig");

test "zix sdp: builder addLine, lines land one after another" {
    var buf: [128]u8 = undefined;
    var builder = Builder{ .out = &buf };

    try builder.addLine(.VERSION, "0");
    try builder.addLine(.SESSION_NAME, "-");

    try std.testing.expectEqualStrings("v=0\r\ns=-\r\n", builder.written());
    try std.testing.expectEqual(@as(usize, 10), builder.at);
}

test "zix sdp: builder addAttribute, both attribute forms are written" {
    var buf: [128]u8 = undefined;
    var builder = Builder{ .out = &buf };

    try builder.addAttribute("ice-lite", null);
    try builder.addAttribute("mid", "0");

    try std.testing.expectEqualStrings("a=ice-lite\r\na=mid:0\r\n", builder.written());
}

test "zix sdp: builder addNumber, a number is written in base ten" {
    var buf: [128]u8 = undefined;
    var builder = Builder{ .out = &buf };

    try builder.addNumber("sctp-port", 5000);
    try builder.addNumber("max-message-size", 0);

    try std.testing.expectEqualStrings("a=sctp-port:5000\r\na=max-message-size:0\r\n", builder.written());
}

test "zix sdp: builder, a full buffer errors rather than truncating" {
    // A truncated description parses as a valid shorter one, which is the whole reason this
    // reports instead of writing what fits.
    var buf: [6]u8 = undefined;
    var builder = Builder{ .out = &buf };

    try builder.addLine(.VERSION, "0");

    try std.testing.expectError(error.ZixNoSpace, builder.addLine(.SESSION_NAME, "-"));
    try std.testing.expectError(error.ZixNoSpace, builder.addAttribute("mid", "0"));
    try std.testing.expectEqual(@as(usize, 5), builder.at);
}

test "zix sdp: builder remaining, it tracks what is left" {
    var buf: [32]u8 = undefined;
    var builder = Builder{ .out = &buf };

    try std.testing.expectEqual(@as(usize, 32), builder.remaining());

    try builder.addLine(.VERSION, "0");

    try std.testing.expectEqual(@as(usize, 27), builder.remaining());
}

test "zix sdp: builder, two writers share one buffer without copying" {
    // The shape answer.zig and media_answer.zig use: one writes the session level, the other
    // picks up at the same offset and writes a section.
    var buf: [256]u8 = undefined;
    var builder = Builder{ .out = &buf };

    try builder.addLine(.VERSION, "0");
    try builder.addLine(.ORIGIN, "- 1 1 IN IP4 0.0.0.0");
    try builder.addLine(.SESSION_NAME, "-");
    try builder.addLine(.TIME, "0 0");

    var section = Builder{ .out = buf[builder.at..] };
    try section.addLine(.MEDIA, "audio 9 UDP/TLS/RTP/SAVPF 111");
    try section.addAttribute("mid", "0");

    builder.at += section.at;

    const parsed = try session.parse(builder.written());
    try std.testing.expectEqual(@as(usize, 1), parsed.sectionCount());
    try std.testing.expect(std.mem.endsWith(u8, builder.written(), "a=mid:0\r\n"));
}

test "zix sdp: builder writeNumber, the edges write correctly" {
    var digits: [MAX_DIGITS]u8 = undefined;

    try std.testing.expectEqualStrings("0", writeNumber(&digits, 0));
    try std.testing.expectEqualStrings("9", writeNumber(&digits, 9));
    try std.testing.expectEqualStrings("10", writeNumber(&digits, 10));
    try std.testing.expectEqualStrings("18446744073709551615", writeNumber(&digits, std.math.maxInt(u64)));
}

test "zix sdp: builder copy, it reports what it copied" {
    var buf: [16]u8 = undefined;
    const count = copy(&buf, "abc");

    try std.testing.expectEqual(@as(usize, 3), count);
    try std.testing.expectEqualStrings("abc", buf[0..count]);
}
