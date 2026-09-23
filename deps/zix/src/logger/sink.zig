//! Double-buffered byte accumulator for one logger destination.

const std = @import("std");

// --------------------------------------------------------- //

/// One destination's buffer pair: producers fill one buffer while the flush thread writes the other.
///
/// Note:
/// - `pending != 0` is the one invariant that says the flush thread owns `bufs[active ^ 1]` and may
///   be inside a write on it. Anything needing the descriptor to itself waits for `pending == 0`
///   first, which is why rotation and close never race a write in flight.
/// - Both buffers are the same size, allocated together, and only when the destination is enabled.
///   A logger with the destination off holds two empty slices and allocates nothing.
pub const Sink = struct {
    /// The buffer pair. Empty slices when this destination is disabled.
    bufs: [2][]u8 = .{ &.{}, &.{} },
    /// Which buffer producers append into.
    active: u1 = 0,
    /// Bytes already in `bufs[active]`.
    fill: usize = 0,
    /// Bytes in `bufs[active ^ 1]` waiting to be written. Zero means no write is in flight.
    pending: usize = 0,
    /// How many times a producer had to wait because both buffers were spoken for.
    stalls: u64 = 0,
    /// Lines appended since the sink was created.
    lines: u64 = 0,
    /// Batches written out since the sink was created. Against `lines` this is the batching ratio.
    writes: u64 = 0,

    const Self = @This();

    // --------------------------------------------------------- //

    /// Allocate the buffer pair.
    ///
    /// Param:
    /// each - usize (bytes per buffer, so the pair costs twice this)
    ///
    /// Return:
    /// - void
    /// - error.OutOfMemory when either buffer cannot be allocated
    pub fn alloc(self: *Self, allocator: std.mem.Allocator, each: usize) !void {
        self.bufs[0] = try allocator.alloc(u8, each);
        errdefer allocator.free(self.bufs[0]);

        self.bufs[1] = try allocator.alloc(u8, each);
    }

    pub fn free(self: *Self, allocator: std.mem.Allocator) void {
        for (&self.bufs) |*buf| {
            if (buf.len == 0) continue;

            allocator.free(buf.*);
            buf.* = &.{};
        }
    }

    /// Whether this destination has buffers at all.
    pub fn enabled(self: *const Self) bool {
        return self.bufs[0].len > 0;
    }

    /// Bytes one buffer holds.
    pub fn capacity(self: *const Self) usize {
        return self.bufs[0].len;
    }

    /// Copy one record plus its newline into the active buffer.
    ///
    /// Note:
    /// - Appends nothing and answers false when the record does not fit in the room left. The
    ///   caller then swaps buffers and tries again, so no partial record is ever written.
    ///
    /// Return:
    /// - true when the whole record went in
    /// - false when the active buffer has no room for it
    pub fn tryAppend(self: *Self, line: []const u8) bool {
        const needed = line.len + 1;
        const buf = self.bufs[self.active];
        if (self.fill + needed > buf.len) return false;

        @memcpy(buf[self.fill..][0..line.len], line);
        self.fill += line.len;
        buf[self.fill] = '\n';
        self.fill += 1;
        self.lines += 1;

        return true;
    }

    /// Whether a record could ever fit, even in an empty buffer. A false here means swapping
    /// buffers would not help, so the caller must not loop on tryAppend.
    pub fn couldEverFit(self: *const Self, line: []const u8) bool {
        return line.len + 1 <= self.bufs[0].len;
    }

    /// Hand the active buffer to the flush thread and start filling the other one.
    /// The caller has already checked that `pending == 0`.
    pub fn swap(self: *Self) void {
        self.pending = self.fill;
        self.active ^= 1;
        self.fill = 0;
    }

    /// The bytes the flush thread is to write. Empty when nothing is pending.
    pub fn pendingBytes(self: *const Self) []const u8 {
        if (self.pending == 0) return &.{};

        return self.bufs[self.active ^ 1][0..self.pending];
    }

    /// Nothing buffered and nothing in flight.
    pub fn isIdle(self: *const Self) bool {
        return self.fill == 0 and self.pending == 0;
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix logger sink: a disabled sink allocates nothing and reports itself disabled" {
    var sink = Sink{};

    try std.testing.expect(!sink.enabled());
    try std.testing.expectEqual(@as(usize, 0), sink.capacity());
    try std.testing.expect(sink.isIdle());
}

test "zix logger sink: tryAppend copies the record and its newline" {
    var sink = Sink{};
    try sink.alloc(std.testing.allocator, 64);
    defer sink.free(std.testing.allocator);

    try std.testing.expect(sink.tryAppend("first"));
    try std.testing.expect(sink.tryAppend("second"));

    try std.testing.expectEqualStrings("first\nsecond\n", sink.bufs[sink.active][0..sink.fill]);
    try std.testing.expectEqual(@as(u64, 2), sink.lines);
}

test "zix logger sink: tryAppend refuses a record that does not fit and leaves the buffer intact" {
    var sink = Sink{};
    try sink.alloc(std.testing.allocator, 16);
    defer sink.free(std.testing.allocator);

    try std.testing.expect(sink.tryAppend("0123456789"));
    const before = sink.fill;

    // 11 bytes with the newline, only 5 bytes of room left.
    try std.testing.expect(!sink.tryAppend("0123456789"));
    try std.testing.expectEqual(before, sink.fill);
    try std.testing.expectEqualStrings("0123456789\n", sink.bufs[sink.active][0..sink.fill]);
}

test "zix logger sink: couldEverFit separates a full buffer from an impossible record" {
    var sink = Sink{};
    try sink.alloc(std.testing.allocator, 16);
    defer sink.free(std.testing.allocator);

    // Fits an empty buffer, so a swap would let it through.
    try std.testing.expect(sink.couldEverFit("012345678901234"));

    // Longer than a whole buffer, so no amount of swapping helps.
    try std.testing.expect(!sink.couldEverFit("0123456789012345"));
}

test "zix logger sink: swap hands the filled buffer over and clears the new active one" {
    var sink = Sink{};
    try sink.alloc(std.testing.allocator, 64);
    defer sink.free(std.testing.allocator);

    try std.testing.expect(sink.tryAppend("handed over"));
    const was_active = sink.active;

    sink.swap();

    try std.testing.expectEqual(was_active ^ 1, sink.active);
    try std.testing.expectEqual(@as(usize, 0), sink.fill);
    try std.testing.expectEqualStrings("handed over\n", sink.pendingBytes());
    try std.testing.expect(!sink.isIdle());
}

test "zix logger sink: the two buffers are independent, so a swap does not disturb pending bytes" {
    var sink = Sink{};
    try sink.alloc(std.testing.allocator, 64);
    defer sink.free(std.testing.allocator);

    try std.testing.expect(sink.tryAppend("pending line"));
    sink.swap();

    // Writing into the new active buffer must not touch what the flush thread is holding.
    try std.testing.expect(sink.tryAppend("live line"));

    try std.testing.expectEqualStrings("pending line\n", sink.pendingBytes());
    try std.testing.expectEqualStrings("live line\n", sink.bufs[sink.active][0..sink.fill]);
}

test "zix logger sink: pendingBytes is empty once the write is marked done" {
    var sink = Sink{};
    try sink.alloc(std.testing.allocator, 32);
    defer sink.free(std.testing.allocator);

    try std.testing.expect(sink.tryAppend("done"));
    sink.swap();
    sink.pending = 0;

    try std.testing.expectEqual(@as(usize, 0), sink.pendingBytes().len);
    try std.testing.expect(sink.isIdle());
}
