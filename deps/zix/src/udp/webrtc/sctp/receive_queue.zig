//! zix SCTP receive-side TSN bookkeeping (RFC 9260 6.2, 6.7).
//!
//! What:
//! - What has arrived, expressed the way a SACK needs it: one cumulative point, the isolated
//!   runs above it, and the TSNs that arrived more than once.
//! - Turning that into a SACK chunk value.
//!
//! Note:
//! - This tracks TSN numbers only, never payload. What happens to the bytes is reassembly's job,
//!   and the two advance together because both only move on contiguous arrivals.
//! - Runs are kept merged and isolated: a TSN that touches a run extends it, and a TSN that
//!   joins two runs collapses them into one. That is what RFC 9260 3.3.4 means by gap blocks
//!   being isolated, and it also keeps the count small enough for a fixed array.
//! - A TSN that will not fit the run table is REFUSED rather than silently forgotten. Recording
//!   a TSN that cannot be reported would acknowledge data the peer then never resends.
//! - The duplicate list counts arrivals, not distinct TSNs, and resets every time a SACK goes
//!   out (RFC 9260 3.3.4). It is advisory, so an overflowing list drops entries rather than
//!   refusing the TSN.
//! - No allocation. The table sizes are fixed because a peer controls how fragmented the
//!   sequence gets, and a table that grew on demand would be the thing under attack.

const std = @import("std");

const sack = @import("sack.zig");
const serial = @import("serial.zig");

/// How many isolated runs can be tracked above the cumulative point.
pub const MAX_GAP_BLOCKS: usize = 32;

/// How many duplicate arrivals are reported in one SACK.
pub const MAX_DUPLICATES: usize = 16;

/// Largest chunk value a SACK from this queue can need.
pub const MAX_SACK_VALUE_LEN: usize = sack.FIXED_LEN +
    MAX_GAP_BLOCKS * sack.GAP_BLOCK_LEN +
    MAX_DUPLICATES * sack.DUPLICATE_LEN;

/// What recording a TSN did.
pub const Outcome = enum {
    /// Newly received and now tracked.
    RECORDED,
    /// Already known, and added to the duplicate report.
    DUPLICATE,
    /// No room to track it. Do not acknowledge it and do not deliver it.
    DROPPED,
};

/// A run of TSNs received with nothing missing inside it.
const Run = struct {
    first: u32,
    last: u32,
};

/// Tracks what has arrived, and builds the SACK that says so.
///
/// Usage:
/// ```zig
/// var queue = ReceiveQueue.init(peer_initial_tsn);
///
/// switch (queue.record(item.tsn)) {
///     .RECORDED => try reassembler.accept(item),
///     .DUPLICATE, .DROPPED => {},
/// }
///
/// var buf: [receive_queue.MAX_SACK_VALUE_LEN]u8 = undefined;
/// const value = try queue.writeSack(&buf, my_rwnd);
/// ```
pub const ReceiveQueue = struct {
    /// Highest TSN with nothing missing below it.
    cumulative_tsn: u32,
    runs: [MAX_GAP_BLOCKS]Run,
    run_count: usize,
    duplicates: [MAX_DUPLICATES]u32,
    duplicate_count: usize,

    /// Start expecting the peer's first TSN.
    ///
    /// Note:
    /// - The cumulative point starts one below it, which is what a SACK sent before any data
    ///   arrives has to report (RFC 9260 3.3.4).
    ///
    /// Param:
    /// peer_initial_tsn - u32 (from the peer's INIT or INIT ACK)
    ///
    /// Return:
    /// - ReceiveQueue
    pub fn init(peer_initial_tsn: u32) ReceiveQueue {
        return .{
            .cumulative_tsn = serial.Tsn.previous(peer_initial_tsn),
            .runs = undefined,
            .run_count = 0,
            .duplicates = undefined,
            .duplicate_count = 0,
        };
    }

    /// Note that a TSN arrived.
    ///
    /// Param:
    /// tsn - u32
    ///
    /// Return:
    /// - Outcome
    pub fn record(self: *ReceiveQueue, tsn: u32) Outcome {
        if (serial.Tsn.lessOrEqual(tsn, self.cumulative_tsn)) {
            self.noteDuplicate(tsn);

            return .DUPLICATE;
        }

        for (self.runs[0..self.run_count]) |run| {
            if (serial.Tsn.greaterOrEqual(tsn, run.first) and serial.Tsn.lessOrEqual(tsn, run.last)) {
                self.noteDuplicate(tsn);

                return .DUPLICATE;
            }
        }

        if (!self.insert(tsn)) return .DROPPED;

        self.absorb();

        return .RECORDED;
    }

    /// Whether anything is missing between the cumulative point and what has arrived.
    ///
    /// Note:
    /// - A hole means the next SACK should go out immediately rather than being delayed
    ///   (RFC 9260 7.2.4).
    ///
    /// Return:
    /// - bool
    pub fn hasGaps(self: ReceiveQueue) bool {
        return self.run_count > 0;
    }

    /// How many duplicate arrivals are waiting to be reported.
    ///
    /// Return:
    /// - usize
    pub fn duplicatesPending(self: ReceiveQueue) usize {
        return self.duplicate_count;
    }

    /// Fill in the gap blocks a SACK would carry.
    ///
    /// Note:
    /// - A run further than 65535 past the cumulative point cannot be expressed as an offset and
    ///   is left out. The peer's receive window keeps runs far closer than that in practice.
    ///
    /// Param:
    /// out - []sack.GapAckBlock (caller storage, at least MAX_GAP_BLOCKS to hold them all)
    ///
    /// Return:
    /// - []sack.GapAckBlock, a prefix of `out`
    pub fn gapBlocks(self: ReceiveQueue, out: []sack.GapAckBlock) []sack.GapAckBlock {
        var count: usize = 0;

        for (self.runs[0..self.run_count]) |run| {
            if (count == out.len) break;

            const start = serial.Tsn.distance(self.cumulative_tsn, run.first);
            const end = serial.Tsn.distance(self.cumulative_tsn, run.last);

            if (end > std.math.maxInt(u16)) continue;

            out[count] = .{ .start = @intCast(start), .end = @intCast(end) };
            count += 1;
        }

        return out[0..count];
    }

    /// Build a SACK chunk value and clear the duplicate report.
    ///
    /// Note:
    /// - The duplicate list resets here rather than in a separate call, because RFC 9260 3.3.4
    ///   ties the reset to the SACK actually going out and splitting the two invites reporting
    ///   the same arrival twice.
    ///
    /// Param:
    /// out - []u8 (at least MAX_SACK_VALUE_LEN bytes to hold the largest report)
    /// advertised_rwnd - u32 (receive buffer this endpoint has left, in bytes)
    ///
    /// Return:
    /// - []const u8 chunk value
    /// - error.ZixNoSpace if the buffer is too small for the report
    pub fn writeSack(self: *ReceiveQueue, out: []u8, advertised_rwnd: u32) sack.Error![]const u8 {
        var blocks: [MAX_GAP_BLOCKS]sack.GapAckBlock = undefined;

        const value = try sack.write(out, .{
            .cumulative_tsn_ack = self.cumulative_tsn,
            .advertised_rwnd = advertised_rwnd,
            .gap_blocks = self.gapBlocks(&blocks),
            .duplicates = self.duplicates[0..self.duplicate_count],
        });

        self.duplicate_count = 0;

        return value;
    }

    /// Move the cumulative point forward past TSNs the peer abandoned (RFC 3758 3.6).
    ///
    /// Param:
    /// new_cumulative_tsn - u32 (from a FORWARD TSN chunk)
    ///
    /// Return:
    /// - void
    pub fn skipTo(self: *ReceiveQueue, new_cumulative_tsn: u32) void {
        if (serial.Tsn.lessOrEqual(new_cumulative_tsn, self.cumulative_tsn)) return;

        self.cumulative_tsn = new_cumulative_tsn;

        var kept: usize = 0;
        for (self.runs[0..self.run_count]) |run| {
            if (serial.Tsn.lessOrEqual(run.last, self.cumulative_tsn)) continue;

            self.runs[kept] = run;

            // A run straddling the new point keeps only the part above it.
            if (serial.Tsn.lessOrEqual(self.runs[kept].first, self.cumulative_tsn)) {
                self.runs[kept].first = serial.Tsn.next(self.cumulative_tsn);
            }

            kept += 1;
        }

        self.run_count = kept;
        self.absorb();
    }

    /// Add a TSN to the run table, extending or merging where it touches. False when full.
    fn insert(self: *ReceiveQueue, tsn: u32) bool {
        const arriving = serial.Tsn.distance(self.cumulative_tsn, tsn);

        var at: usize = 0;
        while (at < self.run_count) : (at += 1) {
            const run = self.runs[at];

            if (tsn == serial.Tsn.previous(run.first)) {
                self.runs[at].first = tsn;
                self.mergeBackward(at);

                return true;
            }

            if (tsn == serial.Tsn.next(run.last)) {
                self.runs[at].last = tsn;
                self.mergeForward(at);

                return true;
            }

            if (serial.Tsn.distance(self.cumulative_tsn, run.first) > arriving) break;
        }

        if (self.run_count == MAX_GAP_BLOCKS) return false;

        var index = self.run_count;
        while (index > at) : (index -= 1) self.runs[index] = self.runs[index - 1];

        self.runs[at] = .{ .first = tsn, .last = tsn };
        self.run_count += 1;

        return true;
    }

    /// Join a run with the one after it when they became adjacent.
    fn mergeForward(self: *ReceiveQueue, at: usize) void {
        if (at + 1 >= self.run_count) return;
        if (self.runs[at + 1].first != serial.Tsn.next(self.runs[at].last)) return;

        self.runs[at].last = self.runs[at + 1].last;
        self.removeRun(at + 1);
    }

    /// Join a run with the one before it when they became adjacent.
    fn mergeBackward(self: *ReceiveQueue, at: usize) void {
        if (at == 0) return;
        if (self.runs[at].first != serial.Tsn.next(self.runs[at - 1].last)) return;

        self.runs[at - 1].last = self.runs[at].last;
        self.removeRun(at);
    }

    /// Pull the first run into the cumulative point while it sits directly above it.
    fn absorb(self: *ReceiveQueue) void {
        while (self.run_count > 0 and self.runs[0].first == serial.Tsn.next(self.cumulative_tsn)) {
            self.cumulative_tsn = self.runs[0].last;
            self.removeRun(0);
        }
    }

    /// Drop one run and close the gap it leaves in the table.
    fn removeRun(self: *ReceiveQueue, at: usize) void {
        var index = at;
        while (index + 1 < self.run_count) : (index += 1) self.runs[index] = self.runs[index + 1];

        self.run_count -= 1;
    }

    /// Add an arrival to the duplicate report, or drop it if the report is full.
    fn noteDuplicate(self: *ReceiveQueue, tsn: u32) void {
        if (self.duplicate_count == MAX_DUPLICATES) return;

        self.duplicates[self.duplicate_count] = tsn;
        self.duplicate_count += 1;
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

test "zix sctp: receive queue init, the cumulative point starts one below the peer's first TSN" {
    const queue = ReceiveQueue.init(100);

    try std.testing.expectEqual(@as(u32, 99), queue.cumulative_tsn);
    try std.testing.expect(!queue.hasGaps());
}

test "zix sctp: receive queue record, an in-order run advances the cumulative point" {
    var queue = ReceiveQueue.init(100);

    for (100..105) |tsn| {
        try std.testing.expectEqual(Outcome.RECORDED, queue.record(@intCast(tsn)));
    }

    try std.testing.expectEqual(@as(u32, 104), queue.cumulative_tsn);
    try std.testing.expect(!queue.hasGaps());
}

test "zix sctp: receive queue record, a hole leaves a gap block behind" {
    var queue = ReceiveQueue.init(100);

    _ = queue.record(100);
    _ = queue.record(102);

    try std.testing.expectEqual(@as(u32, 100), queue.cumulative_tsn);
    try std.testing.expect(queue.hasGaps());

    var blocks: [MAX_GAP_BLOCKS]sack.GapAckBlock = undefined;
    const reported = queue.gapBlocks(&blocks);

    try std.testing.expectEqual(@as(usize, 1), reported.len);
    try std.testing.expectEqual(@as(u16, 2), reported[0].start);
    try std.testing.expectEqual(@as(u16, 2), reported[0].end);
}

test "zix sctp: receive queue record, filling a hole absorbs the run past it" {
    var queue = ReceiveQueue.init(100);

    _ = queue.record(100);
    _ = queue.record(102);
    _ = queue.record(103);
    _ = queue.record(101);

    try std.testing.expectEqual(@as(u32, 103), queue.cumulative_tsn);
    try std.testing.expect(!queue.hasGaps());
}

test "zix sctp: receive queue record, a TSN joining two runs collapses them into one" {
    var queue = ReceiveQueue.init(100);

    _ = queue.record(102);
    _ = queue.record(104);

    try std.testing.expectEqual(@as(usize, 2), queue.run_count);

    _ = queue.record(103);

    try std.testing.expectEqual(@as(usize, 1), queue.run_count);

    var blocks: [MAX_GAP_BLOCKS]sack.GapAckBlock = undefined;
    const reported = queue.gapBlocks(&blocks);

    try std.testing.expectEqual(@as(usize, 1), reported.len);
    try std.testing.expectEqual(@as(u16, 3), reported[0].start);
    try std.testing.expectEqual(@as(u16, 5), reported[0].end);
}

test "zix sctp: receive queue record, a run extends downwards as well as upwards" {
    var queue = ReceiveQueue.init(100);

    _ = queue.record(105);
    _ = queue.record(104);
    _ = queue.record(106);

    try std.testing.expectEqual(@as(usize, 1), queue.run_count);

    var blocks: [MAX_GAP_BLOCKS]sack.GapAckBlock = undefined;
    const reported = queue.gapBlocks(&blocks);

    try std.testing.expectEqual(@as(u16, 5), reported[0].start);
    try std.testing.expectEqual(@as(u16, 7), reported[0].end);
}

test "zix sctp: receive queue record, blocks come out in increasing order however they arrived" {
    var queue = ReceiveQueue.init(100);

    _ = queue.record(110);
    _ = queue.record(104);
    _ = queue.record(107);

    var blocks: [MAX_GAP_BLOCKS]sack.GapAckBlock = undefined;
    const reported = queue.gapBlocks(&blocks);

    try std.testing.expectEqual(@as(usize, 3), reported.len);
    try std.testing.expectEqual(@as(u16, 5), reported[0].start);
    try std.testing.expectEqual(@as(u16, 8), reported[1].start);
    try std.testing.expectEqual(@as(u16, 11), reported[2].start);
}

test "zix sctp: receive queue record, a TSN below the cumulative point is a duplicate" {
    var queue = ReceiveQueue.init(100);

    _ = queue.record(100);

    try std.testing.expectEqual(Outcome.DUPLICATE, queue.record(100));
    try std.testing.expectEqual(Outcome.DUPLICATE, queue.record(99));
    try std.testing.expectEqual(@as(usize, 2), queue.duplicatesPending());
}

test "zix sctp: receive queue record, a TSN already inside a run is a duplicate" {
    var queue = ReceiveQueue.init(100);

    _ = queue.record(105);
    _ = queue.record(106);

    try std.testing.expectEqual(Outcome.DUPLICATE, queue.record(105));
    try std.testing.expectEqual(Outcome.DUPLICATE, queue.record(106));
}

test "zix sctp: receive queue record, the same TSN three times is reported twice" {
    var queue = ReceiveQueue.init(100);

    _ = queue.record(100);
    _ = queue.record(100);
    _ = queue.record(100);

    // RFC 9260 3.3.4 counts arrivals, so three arrivals are two duplicates.
    try std.testing.expectEqual(@as(usize, 2), queue.duplicatesPending());
}

test "zix sctp: receive queue record, a table full of runs refuses the next TSN" {
    var queue = ReceiveQueue.init(0);

    // Every other TSN, so nothing merges and every one costs a run.
    for (0..MAX_GAP_BLOCKS) |index| {
        const tsn: u32 = @intCast(2 + index * 2);
        try std.testing.expectEqual(Outcome.RECORDED, queue.record(tsn));
    }

    const beyond: u32 = 2 + MAX_GAP_BLOCKS * 2;
    try std.testing.expectEqual(Outcome.DROPPED, queue.record(beyond));

    // One that merges into an existing run still fits, because it costs no new entry.
    try std.testing.expectEqual(Outcome.RECORDED, queue.record(3));
}

test "zix sctp: receive queue sack, a report with no gaps is the cumulative point alone" {
    var queue = ReceiveQueue.init(100);
    _ = queue.record(100);

    var buf: [MAX_SACK_VALUE_LEN]u8 = undefined;
    const parsed = try sack.read(try queue.writeSack(&buf, 65536));

    try std.testing.expectEqual(@as(u32, 100), parsed.cumulative_tsn_ack);
    try std.testing.expectEqual(@as(u32, 65536), parsed.advertised_rwnd);
    try std.testing.expectEqual(@as(u16, 0), parsed.gap_block_count);
}

test "zix sctp: receive queue sack, the RFC 9260 worked example is reproduced" {
    var queue = ReceiveQueue.init(10);

    for ([_]u32{ 10, 11, 12, 14, 15, 17 }) |tsn| _ = queue.record(tsn);

    var buf: [MAX_SACK_VALUE_LEN]u8 = undefined;
    const parsed = try sack.read(try queue.writeSack(&buf, 4660));

    try std.testing.expectEqual(@as(u32, 12), parsed.cumulative_tsn_ack);
    try std.testing.expectEqual(@as(u16, 2), parsed.gap_block_count);
    try std.testing.expectEqual(@as(u16, 2), parsed.gapBlock(0).?.start);
    try std.testing.expectEqual(@as(u16, 3), parsed.gapBlock(0).?.end);
    try std.testing.expectEqual(@as(u16, 5), parsed.gapBlock(1).?.start);
    try std.testing.expectEqual(@as(u16, 5), parsed.gapBlock(1).?.end);
}

test "zix sctp: receive queue sack, duplicates are reported once and then cleared" {
    var queue = ReceiveQueue.init(100);

    _ = queue.record(100);
    _ = queue.record(100);

    var buf: [MAX_SACK_VALUE_LEN]u8 = undefined;
    const first = try sack.read(try queue.writeSack(&buf, 1500));

    try std.testing.expectEqual(@as(u16, 1), first.duplicate_count);
    try std.testing.expectEqual(@as(u32, 100), first.duplicate(0).?);

    const second = try sack.read(try queue.writeSack(&buf, 1500));
    try std.testing.expectEqual(@as(u16, 0), second.duplicate_count);
}

test "zix sctp: receive queue sack, a duplicate report that overflows drops the extra arrivals" {
    var queue = ReceiveQueue.init(100);
    _ = queue.record(100);

    for (0..MAX_DUPLICATES + 5) |_| _ = queue.record(100);

    try std.testing.expectEqual(MAX_DUPLICATES, queue.duplicatesPending());
}

test "zix sctp: receive queue skip, the cumulative point jumps past abandoned TSNs" {
    var queue = ReceiveQueue.init(100);

    _ = queue.record(105);
    queue.skipTo(103);

    try std.testing.expectEqual(@as(u32, 103), queue.cumulative_tsn);
    try std.testing.expect(queue.hasGaps());

    var blocks: [MAX_GAP_BLOCKS]sack.GapAckBlock = undefined;
    try std.testing.expectEqual(@as(u16, 2), queue.gapBlocks(&blocks)[0].start);
}

test "zix sctp: receive queue skip, a run directly above the new point is absorbed" {
    var queue = ReceiveQueue.init(100);

    _ = queue.record(104);
    _ = queue.record(105);
    queue.skipTo(103);

    try std.testing.expectEqual(@as(u32, 105), queue.cumulative_tsn);
    try std.testing.expect(!queue.hasGaps());
}

test "zix sctp: receive queue skip, a run straddling the new point keeps only its top" {
    var queue = ReceiveQueue.init(100);

    _ = queue.record(103);
    _ = queue.record(104);
    _ = queue.record(105);
    queue.skipTo(104);

    // 103 and 104 are gone, 105 sits directly above the new point, so it is absorbed too.
    try std.testing.expectEqual(@as(u32, 105), queue.cumulative_tsn);
    try std.testing.expectEqual(@as(usize, 0), queue.run_count);
}

test "zix sctp: receive queue skip, a point already passed changes nothing" {
    var queue = ReceiveQueue.init(100);
    _ = queue.record(100);

    queue.skipTo(50);

    try std.testing.expectEqual(@as(u32, 100), queue.cumulative_tsn);
}

test "zix sctp: receive queue record, a run straddling the TSN wrap stays in order" {
    var queue = ReceiveQueue.init(0xFFFFFFFE);

    _ = queue.record(0xFFFFFFFE);
    _ = queue.record(0);
    _ = queue.record(0xFFFFFFFF);

    try std.testing.expectEqual(@as(u32, 0), queue.cumulative_tsn);
    try std.testing.expect(!queue.hasGaps());
}

test "zix sctp: receive queue record, gap offsets across the wrap stay small" {
    var queue = ReceiveQueue.init(0xFFFFFFFE);

    _ = queue.record(0xFFFFFFFE);
    _ = queue.record(1);

    var blocks: [MAX_GAP_BLOCKS]sack.GapAckBlock = undefined;
    const reported = queue.gapBlocks(&blocks);

    // The cumulative point is 0xFFFFFFFE, so 1 is three steps past it, not an enormous number.
    try std.testing.expectEqual(@as(u16, 3), reported[0].start);
}
