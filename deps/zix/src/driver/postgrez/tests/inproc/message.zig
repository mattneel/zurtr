//! Byte framing for PostgreSQL v3 messages, both directions.
//!
//! Note:
//! - Every message except the startup packet is a one-byte tag, a big-endian
//!   i32 length that counts itself but not the tag, then the payload. The
//!   startup packet omits the tag, which is why beginUntagged exists.
//! - Writer never allocates. It reports overflow as a sticky flag checked once
//!   at the end rather than on every append, so building a message stays
//!   readable.

const std = @import("std");

pub const DecodeError = error{PostgrezTruncated};

/// Fixed-capacity message builder.
pub const Writer = struct {
    buf: []u8,
    len: usize = 0,
    /// Set once anything did not fit. Read it through `finish`.
    overflowed: bool = false,

    const Self = @This();

    pub fn reset(self: *Self) void {
        self.len = 0;
        self.overflowed = false;
    }

    /// Everything written so far.
    ///
    /// Return:
    /// - []const u8 on success
    /// - error.PostgrezTruncated when any append did not fit
    pub fn finish(self: *const Self) error{PostgrezTruncated}![]const u8 {
        if (self.overflowed) return error.PostgrezTruncated;

        return self.buf[0..self.len];
    }

    pub fn byte(self: *Self, value: u8) void {
        if (self.len + 1 > self.buf.len) {
            self.overflowed = true;

            return;
        }

        self.buf[self.len] = value;
        self.len += 1;
    }

    pub fn bytes(self: *Self, source: []const u8) void {
        if (self.len + source.len > self.buf.len) {
            self.overflowed = true;

            return;
        }

        @memcpy(self.buf[self.len..][0..source.len], source);
        self.len += source.len;
    }

    pub fn int16(self: *Self, value: i16) void {
        var encoded: [2]u8 = undefined;
        std.mem.writeInt(i16, &encoded, value, .big);
        self.bytes(&encoded);
    }

    pub fn int32(self: *Self, value: i32) void {
        var encoded: [4]u8 = undefined;
        std.mem.writeInt(i32, &encoded, value, .big);
        self.bytes(&encoded);
    }

    /// A NUL-terminated string, the protocol's only string form.
    pub fn cstring(self: *Self, text: []const u8) void {
        self.bytes(text);
        self.byte(0);
    }

    /// Start a tagged message, returning the marker its length field needs.
    pub fn beginMessage(self: *Self, tag: u8) usize {
        self.byte(tag);

        return self.beginUntagged();
    }

    /// Start an untagged message (the startup and SSL request packets).
    pub fn beginUntagged(self: *Self) usize {
        const marker = self.len;
        self.int32(0);

        return marker;
    }

    /// Patch the length field. It counts itself, so it is the distance from
    /// the marker to here.
    pub fn endMessage(self: *Self, marker: usize) void {
        if (self.overflowed or marker + 4 > self.len) return;

        const length: i32 = @intCast(self.len - marker);
        std.mem.writeInt(i32, self.buf[marker..][0..4], length, .big);
    }
};

/// Cursor over a received payload.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    const Self = @This();

    pub fn remaining(self: *const Self) usize {
        return self.buf.len - self.pos;
    }

    pub fn byte(self: *Self) DecodeError!u8 {
        if (self.pos + 1 > self.buf.len) return error.PostgrezTruncated;

        const value = self.buf[self.pos];
        self.pos += 1;

        return value;
    }

    pub fn bytes(self: *Self, count: usize) DecodeError![]const u8 {
        if (self.pos + count > self.buf.len) return error.PostgrezTruncated;

        const value = self.buf[self.pos..][0..count];
        self.pos += count;

        return value;
    }

    pub fn int16(self: *Self) DecodeError!i16 {
        const raw = try self.bytes(2);

        return std.mem.readInt(i16, raw[0..2], .big);
    }

    pub fn int32(self: *Self) DecodeError!i32 {
        const raw = try self.bytes(4);

        return std.mem.readInt(i32, raw[0..4], .big);
    }

    /// A NUL-terminated string, the terminator consumed but not returned.
    pub fn cstring(self: *Self) DecodeError![]const u8 {
        const end = std.mem.indexOfScalarPos(u8, self.buf, self.pos, 0) orelse return error.PostgrezTruncated;

        const value = self.buf[self.pos..end];
        self.pos = end + 1;

        return value;
    }

    /// The rest of the payload.
    pub fn rest(self: *Self) []const u8 {
        const value = self.buf[self.pos..];
        self.pos = self.buf.len;

        return value;
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez inproc: message writer frames a tagged message with its length" {
    var buf: [64]u8 = undefined;
    var writer = Writer{ .buf = &buf };

    const marker = writer.beginMessage('R');
    writer.int32(0);
    writer.endMessage(marker);

    const framed = try writer.finish();

    // tag, then a length of 8 covering the length field and the payload
    try testing.expectEqualSlices(u8, &[_]u8{ 'R', 0, 0, 0, 8, 0, 0, 0, 0 }, framed);
}

test "postgrez inproc: message writer frames an untagged startup packet" {
    var buf: [64]u8 = undefined;
    var writer = Writer{ .buf = &buf };

    const marker = writer.beginUntagged();
    writer.int32(196608);
    writer.endMessage(marker);

    const framed = try writer.finish();

    try testing.expectEqual(@as(usize, 8), framed.len);
    try testing.expectEqual(@as(i32, 8), std.mem.readInt(i32, framed[0..4], .big));
}

test "postgrez inproc: message writer reports overflow instead of truncating quietly" {
    var buf: [4]u8 = undefined;
    var writer = Writer{ .buf = &buf };

    writer.cstring("this does not fit");

    try testing.expectError(error.PostgrezTruncated, writer.finish());
}

test "postgrez inproc: message writer and reader round trip every field kind" {
    var buf: [64]u8 = undefined;
    var writer = Writer{ .buf = &buf };

    writer.byte(0x7f);
    writer.int16(-2);
    writer.int32(-70000);
    writer.cstring("channel");
    writer.bytes("tail");

    var reader = Reader{ .buf = try writer.finish() };

    try testing.expectEqual(@as(u8, 0x7f), try reader.byte());
    try testing.expectEqual(@as(i16, -2), try reader.int16());
    try testing.expectEqual(@as(i32, -70000), try reader.int32());
    try testing.expectEqualStrings("channel", try reader.cstring());
    try testing.expectEqualStrings("tail", reader.rest());
    try testing.expectEqual(@as(usize, 0), reader.remaining());
}

test "postgrez inproc: message reader reports a truncated field" {
    var reader = Reader{ .buf = &[_]u8{ 0, 1 } };

    try testing.expectError(error.PostgrezTruncated, reader.int32());
}

test "postgrez inproc: message reader reports a cstring with no terminator" {
    var reader = Reader{ .buf = "unterminated" };

    try testing.expectError(error.PostgrezTruncated, reader.cstring());
}
