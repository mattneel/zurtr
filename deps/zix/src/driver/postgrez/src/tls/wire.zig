//! TLS wire codec (RFC 8446 section 3, the TLS presentation language).
//!
//! Note:
//! - A bounds-checked Reader and a length-prefixed Writer used by the handshake, extension, and
//!   certificate layers. The Writer reserves a length field and patches it once the body is
//!   written, the natural shape for nested TLS vectors.

const std = @import("std");

pub const DecodeError = error{PostgrezTruncated};

// --------------------------------------------------------------- //

/// A bounds-checked cursor over a byte slice.
pub const Reader = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn readU8(self: *Reader) DecodeError!u8 {
        if (self.pos + 1 > self.buf.len) return error.PostgrezTruncated;

        const value = self.buf[self.pos];
        self.pos += 1;

        return value;
    }

    pub fn readU16(self: *Reader) DecodeError!u16 {
        if (self.pos + 2 > self.buf.len) return error.PostgrezTruncated;

        const value = std.mem.readInt(u16, self.buf[self.pos..][0..2], .big);
        self.pos += 2;

        return value;
    }

    pub fn readU24(self: *Reader) DecodeError!u32 {
        if (self.pos + 3 > self.buf.len) return error.PostgrezTruncated;

        const triplet = self.buf[self.pos..][0..3];
        self.pos += 3;

        return (@as(u32, triplet[0]) << 16) | (@as(u32, triplet[1]) << 8) | triplet[2];
    }

    pub fn readBytes(self: *Reader, n: usize) DecodeError![]const u8 {
        if (self.pos + n > self.buf.len) return error.PostgrezTruncated;

        const slice = self.buf[self.pos .. self.pos + n];
        self.pos += n;

        return slice;
    }

    pub fn remaining(self: *const Reader) usize {
        return self.buf.len - self.pos;
    }
};

// --------------------------------------------------------------- //

/// Appends into a caller buffer, with deferred length patching for nested vectors.
pub const Writer = struct {
    buf: []u8,
    len: usize = 0,

    pub fn writeU8(self: *Writer, value: u8) void {
        self.buf[self.len] = value;
        self.len += 1;
    }

    pub fn writeU16(self: *Writer, value: u16) void {
        std.mem.writeInt(u16, self.buf[self.len..][0..2], value, .big);
        self.len += 2;
    }

    pub fn writeU24(self: *Writer, value: u32) void {
        self.buf[self.len] = @intCast((value >> 16) & 0xff);
        self.buf[self.len + 1] = @intCast((value >> 8) & 0xff);
        self.buf[self.len + 2] = @intCast(value & 0xff);
        self.len += 3;
    }

    pub fn writeBytes(self: *Writer, bytes: []const u8) void {
        @memcpy(self.buf[self.len .. self.len + bytes.len], bytes);
        self.len += bytes.len;
    }

    /// Reserve a u16 length field, returning its index to patch once the body is written.
    pub fn placeU16(self: *Writer) usize {
        const marker = self.len;
        self.writeU16(0);

        return marker;
    }

    pub fn patchU16(self: *Writer, marker: usize) void {
        std.mem.writeInt(u16, self.buf[marker..][0..2], @intCast(self.len - marker - 2), .big);
    }

    /// Reserve a u24 length field (the handshake-message header length).
    pub fn placeU24(self: *Writer) usize {
        const marker = self.len;
        self.writeU24(0);

        return marker;
    }

    pub fn patchU24(self: *Writer, marker: usize) void {
        const value: u32 = @intCast(self.len - marker - 3);
        self.buf[marker] = @intCast((value >> 16) & 0xff);
        self.buf[marker + 1] = @intCast((value >> 8) & 0xff);
        self.buf[marker + 2] = @intCast(value & 0xff);
    }

    pub fn slice(self: *const Writer) []const u8 {
        return self.buf[0..self.len];
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "postgrez tls: wire reserve + patch a nested u16 vector" {
    var buf: [16]u8 = undefined;
    var writer = Writer{ .buf = &buf };

    writer.writeU8(0xaa);
    const vector = writer.placeU16();
    writer.writeU16(0x1122);
    writer.writeU8(0x33);
    writer.patchU16(vector);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0x00, 0x03, 0x11, 0x22, 0x33 }, writer.slice());

    var reader = Reader{ .buf = writer.slice() };
    try std.testing.expectEqual(@as(u8, 0xaa), try reader.readU8());
    try std.testing.expectEqual(@as(u16, 3), try reader.readU16());
    try std.testing.expectEqual(@as(u16, 0x1122), try reader.readU16());
    try std.testing.expectEqual(@as(u8, 0x33), try reader.readU8());
    try std.testing.expectError(error.PostgrezTruncated, reader.readU8());
}
