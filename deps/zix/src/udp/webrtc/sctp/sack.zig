//! zix SCTP selective acknowledgement, the SACK chunk (RFC 9260 3.3.4).
//!
//! What:
//! - What a receiver tells a sender: everything up to the cumulative TSN arrived, these later
//!   runs arrived too, these TSNs arrived twice, and this much receive buffer is left.
//! - The gap blocks, which are the only way a sender learns that a hole is a hole rather than
//!   the end of what it sent.
//!
//! Note:
//! - Gap blocks are OFFSETS from the cumulative TSN, not TSNs. Reading them as absolute numbers
//!   works for a while and then fails once the counter wraps or the association has run long
//!   enough for the offsets to be small and the TSNs large. `GapAckBlock.firstTsn` does the
//!   addition in one place.
//! - Blocks are isolated: the TSN just before a block and the TSN just after it are both
//!   missing. Two adjacent runs are one block, never two.
//! - The duplicate list counts arrivals, not TSNs. The same TSN received three times is listed
//!   twice, and the list resets after every SACK.
//! - The gap block list is what tells the sender to fast retransmit, so a receiver that never
//!   reports blocks turns every loss into a timeout.

const std = @import("std");

const serial = @import("serial.zig");

/// Cumulative TSN ack, a_rwnd, block count, duplicate count.
pub const FIXED_LEN: usize = 12;

/// One gap ack block on the wire: a start offset and an end offset.
pub const GAP_BLOCK_LEN: usize = 4;

/// One duplicate TSN on the wire.
pub const DUPLICATE_LEN: usize = 4;

/// Everything that stops a SACK from being read or built.
pub const Error = error{
    /// Fewer bytes than the fixed fields and the lists the counts announce.
    ZixTruncated,
    /// More blocks or duplicates than the 16-bit counts can hold.
    ZixTooManyEntries,
    /// The output buffer is too small.
    ZixNoSpace,
};

/// One run of TSNs that arrived after a hole.
pub const GapAckBlock = struct {
    /// Offset from the cumulative TSN ack to the first TSN in the run.
    start: u16,
    /// Offset from the cumulative TSN ack to the last TSN in the run.
    end: u16,

    /// The first TSN this block acknowledges.
    ///
    /// Param:
    /// cumulative_tsn_ack - u32 (from the SACK this block came in)
    ///
    /// Return:
    /// - u32
    pub fn firstTsn(self: GapAckBlock, cumulative_tsn_ack: u32) u32 {
        return serial.Tsn.advance(cumulative_tsn_ack, self.start);
    }

    /// The last TSN this block acknowledges.
    ///
    /// Param:
    /// cumulative_tsn_ack - u32 (from the SACK this block came in)
    ///
    /// Return:
    /// - u32
    pub fn lastTsn(self: GapAckBlock, cumulative_tsn_ack: u32) u32 {
        return serial.Tsn.advance(cumulative_tsn_ack, self.end);
    }

    /// Whether a TSN falls inside this block.
    ///
    /// Param:
    /// cumulative_tsn_ack - u32 (from the SACK this block came in)
    /// tsn - u32
    ///
    /// Return:
    /// - bool
    pub fn covers(self: GapAckBlock, cumulative_tsn_ack: u32, tsn: u32) bool {
        const offset = serial.Tsn.distance(cumulative_tsn_ack, tsn);

        return offset >= self.start and offset <= self.end;
    }
};

/// A parsed SACK, borrowing the chunk value it was read from.
pub const Sack = struct {
    cumulative_tsn_ack: u32,
    /// Receive buffer the sender of this SACK has left, in bytes.
    advertised_rwnd: u32,
    gap_block_count: u16,
    duplicate_count: u16,
    /// The gap block list, still packed.
    blocks: []const u8,
    /// The duplicate TSN list, still packed.
    duplicates: []const u8,

    /// One gap block by position.
    ///
    /// Param:
    /// index - usize
    ///
    /// Return:
    /// - ?GapAckBlock, null past the end of the list
    pub fn gapBlock(self: Sack, index: usize) ?GapAckBlock {
        if (index >= self.gap_block_count) return null;

        const at = index * GAP_BLOCK_LEN;

        return .{
            .start = std.mem.readInt(u16, self.blocks[at..][0..2], .big),
            .end = std.mem.readInt(u16, self.blocks[at + 2 ..][0..2], .big),
        };
    }

    /// One duplicate TSN by position.
    ///
    /// Param:
    /// index - usize
    ///
    /// Return:
    /// - ?u32, null past the end of the list
    pub fn duplicate(self: Sack, index: usize) ?u32 {
        if (index >= self.duplicate_count) return null;

        const at = index * DUPLICATE_LEN;

        return std.mem.readInt(u32, self.duplicates[at..][0..4], .big);
    }

    /// The highest TSN this SACK acknowledges, block list included.
    ///
    /// Note:
    /// - Equal to the cumulative TSN ack when there are no blocks.
    ///
    /// Return:
    /// - u32
    pub fn highestTsnAcked(self: Sack) u32 {
        const last = self.gapBlock(self.gap_block_count -| 1) orelse return self.cumulative_tsn_ack;

        return last.lastTsn(self.cumulative_tsn_ack);
    }

    /// Whether a TSN is acknowledged by this SACK, cumulatively or through a block.
    ///
    /// Param:
    /// tsn - u32
    ///
    /// Return:
    /// - bool
    pub fn acknowledges(self: Sack, tsn: u32) bool {
        if (serial.Tsn.lessOrEqual(tsn, self.cumulative_tsn_ack)) return true;

        var index: usize = 0;
        while (self.gapBlock(index)) |block| : (index += 1) {
            if (block.covers(self.cumulative_tsn_ack, tsn)) return true;
        }

        return false;
    }
};

/// What goes into a SACK being built.
pub const Fields = struct {
    cumulative_tsn_ack: u32,
    advertised_rwnd: u32,
    /// Isolated runs received after the cumulative TSN, in increasing order.
    gap_blocks: []const GapAckBlock = &.{},
    /// TSNs received more than once since the last SACK, one entry per extra arrival.
    duplicates: []const u32 = &.{},
};

/// Size of the chunk value for given list lengths.
///
/// Param:
/// gap_block_count - usize
/// duplicate_count - usize
///
/// Return:
/// - usize
pub fn valueLen(gap_block_count: usize, duplicate_count: usize) usize {
    return FIXED_LEN + gap_block_count * GAP_BLOCK_LEN + duplicate_count * DUPLICATE_LEN;
}

/// Read a SACK chunk.
///
/// Param:
/// value - []const u8 (chunk value, so everything after the 4-byte chunk header)
///
/// Return:
/// - Sack borrowing `value`
/// - error.ZixTruncated if the body is shorter than the counts in its own header claim
pub fn read(value: []const u8) Error!Sack {
    if (value.len < FIXED_LEN) return error.ZixTruncated;

    const gap_block_count = std.mem.readInt(u16, value[8..10], .big);
    const duplicate_count = std.mem.readInt(u16, value[10..12], .big);

    const blocks_len = @as(usize, gap_block_count) * GAP_BLOCK_LEN;
    const duplicates_len = @as(usize, duplicate_count) * DUPLICATE_LEN;

    if (value.len < FIXED_LEN + blocks_len + duplicates_len) return error.ZixTruncated;

    return .{
        .cumulative_tsn_ack = std.mem.readInt(u32, value[0..4], .big),
        .advertised_rwnd = std.mem.readInt(u32, value[4..8], .big),
        .gap_block_count = gap_block_count,
        .duplicate_count = duplicate_count,
        .blocks = value[FIXED_LEN..][0..blocks_len],
        .duplicates = value[FIXED_LEN + blocks_len ..][0..duplicates_len],
    };
}

/// Write a SACK chunk value.
///
/// Note:
/// - The two lists are written in the order the wire format fixes: every gap block, then every
///   duplicate. Taking both up front is what keeps that order out of the caller's hands.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// fields - Fields
///
/// Return:
/// - []const u8 chunk value
/// - error.ZixTooManyEntries if either list is longer than 65535
/// - error.ZixNoSpace if the buffer cannot hold the fixed fields and both lists
pub fn write(out: []u8, fields: Fields) Error![]const u8 {
    if (fields.gap_blocks.len > std.math.maxInt(u16)) return error.ZixTooManyEntries;
    if (fields.duplicates.len > std.math.maxInt(u16)) return error.ZixTooManyEntries;

    const total = valueLen(fields.gap_blocks.len, fields.duplicates.len);

    if (out.len < total) return error.ZixNoSpace;

    std.mem.writeInt(u32, out[0..4], fields.cumulative_tsn_ack, .big);
    std.mem.writeInt(u32, out[4..8], fields.advertised_rwnd, .big);
    std.mem.writeInt(u16, out[8..10], @intCast(fields.gap_blocks.len), .big);
    std.mem.writeInt(u16, out[10..12], @intCast(fields.duplicates.len), .big);

    var at: usize = FIXED_LEN;

    for (fields.gap_blocks) |block| {
        std.mem.writeInt(u16, out[at..][0..2], block.start, .big);
        std.mem.writeInt(u16, out[at + 2 ..][0..2], block.end, .big);
        at += GAP_BLOCK_LEN;
    }

    for (fields.duplicates) |tsn| {
        std.mem.writeInt(u32, out[at..][0..4], tsn, .big);
        at += DUPLICATE_LEN;
    }

    return out[0..total];
}

// --------------------------------------------------------------------------------------- //
// test cases

test "zix sctp: sack write, a plain acknowledgement with no gaps round trips" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, .{ .cumulative_tsn_ack = 100, .advertised_rwnd = 65536 });

    try std.testing.expectEqual(FIXED_LEN, value.len);

    const parsed = try read(value);

    try std.testing.expectEqual(@as(u32, 100), parsed.cumulative_tsn_ack);
    try std.testing.expectEqual(@as(u32, 65536), parsed.advertised_rwnd);
    try std.testing.expectEqual(@as(u16, 0), parsed.gap_block_count);
    try std.testing.expectEqual(@as(u16, 0), parsed.duplicate_count);
    try std.testing.expectEqual(@as(u32, 100), parsed.highestTsnAcked());
}

test "zix sctp: sack write, the RFC 9260 worked example encodes as the RFC states" {
    // TSNs 10, 11, 12, 14, 15, 17 arrived, so 13 and 16 are the holes.
    var buf: [32]u8 = undefined;
    const value = try write(&buf, .{
        .cumulative_tsn_ack = 12,
        .advertised_rwnd = 4660,
        .gap_blocks = &.{ .{ .start = 2, .end = 3 }, .{ .start = 5, .end = 5 } },
    });

    const parsed = try read(value);

    try std.testing.expectEqual(@as(u32, 12), parsed.cumulative_tsn_ack);
    try std.testing.expectEqual(@as(u32, 4660), parsed.advertised_rwnd);
    try std.testing.expectEqual(@as(u16, 2), parsed.gap_block_count);

    const first = parsed.gapBlock(0).?;
    try std.testing.expectEqual(@as(u32, 14), first.firstTsn(parsed.cumulative_tsn_ack));
    try std.testing.expectEqual(@as(u32, 15), first.lastTsn(parsed.cumulative_tsn_ack));

    const second = parsed.gapBlock(1).?;
    try std.testing.expectEqual(@as(u32, 17), second.firstTsn(parsed.cumulative_tsn_ack));
    try std.testing.expectEqual(@as(u32, 17), second.lastTsn(parsed.cumulative_tsn_ack));

    try std.testing.expectEqual(@as(u32, 17), parsed.highestTsnAcked());
}

test "zix sctp: sack read, the worked example says exactly which TSNs are missing" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, .{
        .cumulative_tsn_ack = 12,
        .advertised_rwnd = 4660,
        .gap_blocks = &.{ .{ .start = 2, .end = 3 }, .{ .start = 5, .end = 5 } },
    });

    const parsed = try read(value);

    for ([_]u32{ 10, 11, 12, 14, 15, 17 }) |tsn| {
        try std.testing.expect(parsed.acknowledges(tsn));
    }

    try std.testing.expect(!parsed.acknowledges(13));
    try std.testing.expect(!parsed.acknowledges(16));
    try std.testing.expect(!parsed.acknowledges(18));
}

test "zix sctp: sack read, gap offsets are added to the cumulative TSN across a wrap" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, .{
        .cumulative_tsn_ack = 0xFFFFFFFE,
        .advertised_rwnd = 1500,
        .gap_blocks = &.{.{ .start = 2, .end = 4 }},
    });

    const parsed = try read(value);
    const block = parsed.gapBlock(0).?;

    // Reading the offsets as absolute TSNs would point at 2 through 4 instead.
    try std.testing.expectEqual(@as(u32, 0), block.firstTsn(parsed.cumulative_tsn_ack));
    try std.testing.expectEqual(@as(u32, 2), block.lastTsn(parsed.cumulative_tsn_ack));
    try std.testing.expect(parsed.acknowledges(1));
    try std.testing.expect(!parsed.acknowledges(0xFFFFFFFF));
}

test "zix sctp: sack write, duplicates follow the gap blocks" {
    var buf: [64]u8 = undefined;
    const value = try write(&buf, .{
        .cumulative_tsn_ack = 50,
        .advertised_rwnd = 8192,
        .gap_blocks = &.{.{ .start = 2, .end = 2 }},
        .duplicates = &.{ 48, 48, 49 },
    });

    try std.testing.expectEqual(valueLen(1, 3), value.len);

    const parsed = try read(value);

    try std.testing.expectEqual(@as(u16, 1), parsed.gap_block_count);
    try std.testing.expectEqual(@as(u16, 3), parsed.duplicate_count);
    try std.testing.expectEqual(@as(u32, 48), parsed.duplicate(0).?);
    try std.testing.expectEqual(@as(u32, 48), parsed.duplicate(1).?);
    try std.testing.expectEqual(@as(u32, 49), parsed.duplicate(2).?);
    try std.testing.expect(parsed.duplicate(3) == null);
}

test "zix sctp: sack read, a TSN at or below the cumulative ack is acknowledged" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, .{ .cumulative_tsn_ack = 100, .advertised_rwnd = 1500 });

    const parsed = try read(value);

    try std.testing.expect(parsed.acknowledges(100));
    try std.testing.expect(parsed.acknowledges(1));
    try std.testing.expect(!parsed.acknowledges(101));
}

test "zix sctp: sack read, an index past either list returns nothing" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, .{ .cumulative_tsn_ack = 5, .advertised_rwnd = 1500 });

    const parsed = try read(value);

    try std.testing.expect(parsed.gapBlock(0) == null);
    try std.testing.expect(parsed.duplicate(0) == null);
}

test "zix sctp: sack read, a body shorter than the fixed fields errors" {
    const short: [11]u8 = @splat(0);

    try std.testing.expectError(error.ZixTruncated, read(&short));
}

test "zix sctp: sack read, a block count larger than the body errors" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, .{ .cumulative_tsn_ack = 5, .advertised_rwnd = 1500 });

    std.mem.writeInt(u16, buf[8..10], 4, .big);

    try std.testing.expectError(error.ZixTruncated, read(value));
}

test "zix sctp: sack read, a duplicate count larger than the body errors" {
    var buf: [64]u8 = undefined;
    const value = try write(&buf, .{
        .cumulative_tsn_ack = 5,
        .advertised_rwnd = 1500,
        .gap_blocks = &.{.{ .start = 1, .end = 1 }},
    });

    std.mem.writeInt(u16, buf[10..12], 9, .big);

    try std.testing.expectError(error.ZixTruncated, read(value));
}

test "zix sctp: sack write, a buffer too small errors" {
    var buf: [FIXED_LEN]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, write(&buf, .{
        .cumulative_tsn_ack = 1,
        .advertised_rwnd = 1500,
        .gap_blocks = &.{.{ .start = 1, .end = 1 }},
    }));
}

test "zix sctp: sack read, trailing bytes past the lists are ignored" {
    var buf: [40]u8 = undefined;
    const value = try write(&buf, .{ .cumulative_tsn_ack = 7, .advertised_rwnd = 1500 });
    _ = value;

    // A peer that padded past the last list must not turn into a parse failure.
    const parsed = try read(buf[0 .. FIXED_LEN + 4]);

    try std.testing.expectEqual(@as(u32, 7), parsed.cumulative_tsn_ack);
}

test "zix sctp: sack block, a covered TSN inside a long run is found" {
    const block: GapAckBlock = .{ .start = 3, .end = 9 };

    try std.testing.expect(block.covers(100, 103));
    try std.testing.expect(block.covers(100, 109));
    try std.testing.expect(!block.covers(100, 102));
    try std.testing.expect(!block.covers(100, 110));
}
