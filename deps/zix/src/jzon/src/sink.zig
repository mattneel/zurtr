//! jzon write cursor.
//!
//! What:
//! - A bounds-checked cursor over a caller-owned buffer. One write either fits
//!   whole and advances the position, or fails with error.NoSpaceLeft and leaves
//!   the position untouched, so a half-written value never lands.
//! - This file owns one thing: where the next byte goes and whether there is room
//!   for it. What the bytes mean belongs to the emitter above it.

const std = @import("std");

/// The only way a jzon write can fail. Serialize never allocates, so a full
/// buffer is its whole failure surface.
pub const Error = error{NoSpaceLeft};

/// A write cursor over a caller-owned buffer.
///
/// Note:
/// - One call is all-or-nothing. A sequence of calls is not: when the fourth of
///   five writes fails, the first three stay in the buffer.
///
/// Usage:
/// ```zig
/// var buf: [64]u8 = undefined;
/// var sink: Sink = .init(&buf);
///
/// try sink.byte('[');
/// try sink.literal("\"ok\"");
/// try sink.byte(']');
///
/// const rendered = sink.filled();
/// ```
pub const Sink = struct {
    buf: []u8,
    pos: usize,

    /// A cursor positioned at the start of `buf`.
    pub fn init(buf: []u8) Sink {
        return .{ .buf = buf, .pos = 0 };
    }

    /// How many bytes have been written.
    pub fn written(self: Sink) usize {
        return self.pos;
    }

    /// How many bytes are still free.
    pub fn remaining(self: Sink) usize {
        return self.buf.len - self.pos;
    }

    /// The region written so far.
    pub fn filled(self: Sink) []const u8 {
        return self.buf[0..self.pos];
    }

    /// Drop everything written and start over at the front of the buffer.
    pub fn reset(self: *Sink) void {
        self.pos = 0;
    }

    /// Write one byte.
    ///
    /// Param:
    /// value - u8 (the byte to write)
    ///
    /// Return:
    /// - void
    /// - error.NoSpaceLeft when the buffer is full
    pub fn byte(self: *Sink, value: u8) Error!void {
        if (self.pos == self.buf.len) return error.NoSpaceLeft;

        self.buf[self.pos] = value;
        self.pos += 1;
    }

    /// Write a run of bytes.
    ///
    /// Param:
    /// source - []const u8 (the bytes to copy in)
    ///
    /// Return:
    /// - void
    /// - error.NoSpaceLeft when the run does not fit whole
    pub fn bytes(self: *Sink, source: []const u8) Error!void {
        if (source.len > self.remaining()) return error.NoSpaceLeft;

        @memcpy(self.buf[self.pos..][0..source.len], source);
        self.pos += source.len;
    }

    /// Write a compile-time known run of bytes.
    ///
    /// Note:
    /// - The length is known at the call site, so the bound folds to one compare
    ///   and the copy to a fixed-size move. This is the form a generated emitter
    ///   uses for its baked key literals.
    ///
    /// Param:
    /// text - []const u8 (comptime, the bytes to copy in)
    ///
    /// Return:
    /// - void
    /// - error.NoSpaceLeft when the run does not fit whole
    pub fn literal(self: *Sink, comptime text: []const u8) Error!void {
        if (text.len > self.remaining()) return error.NoSpaceLeft;

        self.buf[self.pos..][0..text.len].* = text[0..text.len].*;
        self.pos += text.len;
    }

    /// Take `len` bytes of room and hand the region back to be filled directly.
    /// The position advances on return, so the caller owns filling all of it.
    ///
    /// Param:
    /// len - usize (how many bytes to take)
    ///
    /// Return:
    /// - []u8 (the reserved region)
    /// - error.NoSpaceLeft when that many bytes are not free
    pub fn reserve(self: *Sink, len: usize) Error![]u8 {
        if (len > self.remaining()) return error.NoSpaceLeft;

        const region = self.buf[self.pos..][0..len];
        self.pos += len;

        return region;
    }

    /// The unwritten tail, for a writer that reports its own length afterwards.
    /// Pair every call with `commit`.
    pub fn tail(self: Sink) []u8 {
        return self.buf[self.pos..];
    }

    /// Accept `len` bytes written into the region `tail` returned.
    ///
    /// Param:
    /// len - usize (how many bytes were written into the tail)
    ///
    /// Return:
    /// - void
    /// - error.NoSpaceLeft when `len` runs past the buffer
    pub fn commit(self: *Sink, len: usize) Error!void {
        if (len > self.remaining()) return error.NoSpaceLeft;

        self.pos += len;
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "jzon: sink writes bytes, literals and runs in order" {
    var buf: [32]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.byte('{');
    try sink.literal("\"id\":");
    try sink.bytes("42");
    try sink.byte('}');

    try std.testing.expectEqualStrings("{\"id\":42}", sink.filled());
    try std.testing.expectEqual(@as(usize, 9), sink.written());
    try std.testing.expectEqual(@as(usize, 23), sink.remaining());
}

test "jzon: sink reserve hands back a region the caller fills" {
    var buf: [8]u8 = undefined;
    var sink: Sink = .init(&buf);

    const region = try sink.reserve(3);
    @memcpy(region, "abc");

    try std.testing.expectEqualStrings("abc", sink.filled());
    try std.testing.expectEqual(@as(usize, 5), sink.remaining());
}

test "jzon: sink tail and commit take a foreign writer's length" {
    var buf: [16]u8 = undefined;
    var sink: Sink = .init(&buf);

    const printed = try std.fmt.bufPrint(sink.tail(), "{d}", .{12345});
    try sink.commit(printed.len);

    try std.testing.expectEqualStrings("12345", sink.filled());
}

test "jzon: sink reset drops what was written" {
    var buf: [8]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.bytes("hello");
    sink.reset();
    try sink.bytes("hi");

    try std.testing.expectEqualStrings("hi", sink.filled());
}

test "jzon: sink refuses a write that does not fit whole" {
    var buf: [4]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.bytes("ab");
    try std.testing.expectError(error.NoSpaceLeft, sink.bytes("cde"));

    // The rejected run left nothing behind, so the next write lands where the
    // failed one would have started.
    try std.testing.expectEqualStrings("ab", sink.filled());
    try sink.bytes("cd");
    try std.testing.expectEqualStrings("abcd", sink.filled());
}
