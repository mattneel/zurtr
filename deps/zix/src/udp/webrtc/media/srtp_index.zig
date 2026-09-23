//! zix SRTP packet index and replay list (RFC 3711 3.3.1, 3.3.2, Appendix A).
//!
//! What:
//! - Where a packet sits in the stream. RTP carries a 16-bit sequence number, SRTP needs a 48-bit
//!   index, and the missing 32 bits are a rollover counter that is never sent. This file works
//!   out that counter, and remembers which indices have already been accepted.
//!
//! Note:
//! - The counter is guessed from the highest sequence number seen so far, choosing between the
//!   current counter and its neighbours so the index lands closest to what was expected. A packet
//!   that arrives 2^15 out of order is guessed wrong, which is the documented limit of the scheme
//!   and far past what a live stream does.
//! - Estimating and accepting are two calls, deliberately. RFC 3711 3.3.1 only updates the stored
//!   counter AFTER the packet authenticates, so a forged packet with a wild sequence number
//!   cannot drag the counter forward and lock out the real stream behind it.
//! - The replay list keeps the same shape: check before doing the expensive work, record after it
//!   passes. src/tls/dtls_record.zig has a sibling window for DTLS records, kept separate on
//!   purpose because that one indexes an explicit sequence number and this one indexes a guess.
//! - Bit 0 of the mask is the highest index itself, so index 0 is accepted exactly once even
//!   though the window starts at zero.

const std = @import("std");

/// How many values an RTP sequence number has.
pub const SEQUENCE_SPAN: i64 = 1 << 16;

/// Half of that, the point the estimate turns on (RFC 3711 Appendix A).
pub const SEQUENCE_MIDPOINT: i64 = 1 << 15;

/// How far back the replay list remembers. RFC 3711 3.3.2 requires at least 64.
pub const REPLAY_WINDOW_BITS: u48 = 64;

/// One packet's place in the stream.
pub const Index = struct {
    /// The rollover counter this packet belongs under.
    roc: u32,
    /// The sequence number as it arrived.
    sequence: u16,

    /// The 48-bit index the cipher and the replay list use.
    ///
    /// Return:
    /// - u48
    pub fn value(self: Index) u48 {
        return (@as(u48, self.roc) << 16) | @as(u48, self.sequence);
    }
};

/// The receiver-side rollover counter and highest sequence number (RFC 3711 3.3.1).
pub const Estimator = struct {
    /// The counter as it stands, which only `accept` moves.
    roc: u32 = 0,
    /// s_l in the RFC, the highest sequence number accepted under the current counter.
    highest_sequence: u16 = 0,
    /// Whether any packet has been accepted yet, which decides how the first one is read.
    started: bool = false,

    /// Work out which rollover counter a sequence number belongs under.
    ///
    /// Note:
    /// - Pure. Nothing is remembered until `accept` is called with the result.
    /// - The first packet of a stream sets the starting point rather than being compared against
    ///   one, so it always lands on the counter as it stands.
    ///
    /// Param:
    /// sequence - u16 (as it arrived in the packet)
    ///
    /// Return:
    /// - Index
    pub fn estimate(self: Estimator, sequence: u16) Index {
        if (!self.started) return .{ .roc = self.roc, .sequence = sequence };

        const highest: i64 = self.highest_sequence;
        const arrived: i64 = sequence;

        if (highest < SEQUENCE_MIDPOINT) {
            // Near the bottom of the range, so a much larger number is a straggler from before
            // the last wrap.
            if (arrived - highest > SEQUENCE_MIDPOINT) return .{ .roc = self.roc -% 1, .sequence = sequence };

            return .{ .roc = self.roc, .sequence = sequence };
        }

        // Near the top, so a much smaller number has wrapped into the next counter.
        if (highest - SEQUENCE_MIDPOINT > arrived) return .{ .roc = self.roc +% 1, .sequence = sequence };

        return .{ .roc = self.roc, .sequence = sequence };
    }

    /// Record an index as accepted. Call only after the packet authenticates.
    ///
    /// Param:
    /// index - Index (exactly what `estimate` returned for this packet)
    ///
    /// Return:
    /// - void
    pub fn accept(self: *Estimator, index: Index) void {
        if (!self.started) {
            self.started = true;
            self.roc = index.roc;
            self.highest_sequence = index.sequence;

            return;
        }

        // A straggler from before the last wrap moves nothing.
        if (index.roc == self.roc -% 1) return;

        if (index.roc == self.roc) {
            if (index.sequence > self.highest_sequence) self.highest_sequence = index.sequence;

            return;
        }

        self.roc = index.roc;
        self.highest_sequence = index.sequence;
    }

    /// The index the next packet this endpoint SENDS would carry.
    ///
    /// Note:
    /// - The sender side has no guessing to do (RFC 3711 3.3.1). It counts its own wraps, which
    ///   is what this is for.
    /// - Sequence numbers must be handed over in the order they go out. A sender that re-sends an
    ///   older packet has to protect it under the index it originally had, not a fresh one, and
    ///   passing the old number here reads as a wrap and moves the counter. zix does not resend
    ///   (RFC 4588 is not implemented), so nothing calls it that way today.
    ///
    /// Param:
    /// sequence - u16 (the sequence number about to be sent)
    ///
    /// Return:
    /// - Index
    pub fn forSend(self: *Estimator, sequence: u16) Index {
        if (self.started and sequence < self.highest_sequence) self.roc +%= 1;

        self.started = true;
        self.highest_sequence = sequence;

        return .{ .roc = self.roc, .sequence = sequence };
    }
};

/// The replay list, as a sliding window over accepted indices (RFC 3711 3.3.2).
pub const ReplayList = struct {
    /// The highest index accepted so far, the right edge of the window.
    highest: u48 = 0,
    /// Bit i marks (highest - i) as already accepted.
    window: u64 = 0,

    /// Whether an index is worth authenticating.
    ///
    /// Param:
    /// index - u48
    ///
    /// Return:
    /// - true when it is ahead of the window, or inside it and not yet accepted
    /// - false when it duplicates a packet or falls off the left edge
    pub fn isNew(self: ReplayList, index: u48) bool {
        if (index > self.highest) return true;

        const behind = self.highest - index;

        if (behind >= REPLAY_WINDOW_BITS) return false;

        return (self.window >> @intCast(behind)) & 1 == 0;
    }

    /// Record an index as accepted. Call only after the packet authenticates.
    ///
    /// Param:
    /// index - u48
    ///
    /// Return:
    /// - void
    pub fn accept(self: *ReplayList, index: u48) void {
        if (index > self.highest) {
            const advance = index - self.highest;

            self.window = if (advance >= REPLAY_WINDOW_BITS) 0 else self.window << @intCast(advance);
            self.window |= 1;
            self.highest = index;

            return;
        }

        const behind = self.highest - index;

        if (behind < REPLAY_WINDOW_BITS) self.window |= @as(u64, 1) << @intCast(behind);
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

test "zix media: srtp index value, the counter is the high 32 bits" {
    try std.testing.expectEqual(@as(u48, 0), (Index{ .roc = 0, .sequence = 0 }).value());
    try std.testing.expectEqual(@as(u48, 1), (Index{ .roc = 0, .sequence = 1 }).value());
    try std.testing.expectEqual(@as(u48, 65536), (Index{ .roc = 1, .sequence = 0 }).value());
    try std.testing.expectEqual(@as(u48, 131071), (Index{ .roc = 1, .sequence = 65535 }).value());
}

test "zix media: srtp index estimate, the first packet sets the starting point" {
    var estimator = Estimator{};

    // A stream can start anywhere, RTP picks its first sequence number at random.
    const first = estimator.estimate(40000);

    try std.testing.expectEqual(@as(u32, 0), first.roc);
    try std.testing.expectEqual(@as(u16, 40000), first.sequence);

    estimator.accept(first);

    try std.testing.expectEqual(@as(u16, 40000), estimator.highest_sequence);
    try std.testing.expectEqual(@as(u32, 0), estimator.roc);
}

test "zix media: srtp index estimate, packets in order keep the same counter" {
    var estimator = Estimator{};

    for (100..110) |sequence| {
        const index = estimator.estimate(@intCast(sequence));

        try std.testing.expectEqual(@as(u32, 0), index.roc);
        estimator.accept(index);
    }

    try std.testing.expectEqual(@as(u16, 109), estimator.highest_sequence);
}

test "zix media: srtp index estimate, the counter steps when the sequence wraps" {
    var estimator = Estimator{};
    estimator.accept(estimator.estimate(65534));
    estimator.accept(estimator.estimate(65535));

    const wrapped = estimator.estimate(0);

    try std.testing.expectEqual(@as(u32, 1), wrapped.roc);
    try std.testing.expectEqual(@as(u48, 65536), wrapped.value());

    estimator.accept(wrapped);

    try std.testing.expectEqual(@as(u32, 1), estimator.roc);
    try std.testing.expectEqual(@as(u16, 0), estimator.highest_sequence);
}

test "zix media: srtp index estimate, a straggler from before the wrap keeps the old counter" {
    var estimator = Estimator{};
    estimator.accept(estimator.estimate(65535));
    estimator.accept(estimator.estimate(1));

    try std.testing.expectEqual(@as(u32, 1), estimator.roc);

    // 65534 was sent before the wrap, so it belongs under the counter as it was.
    const straggler = estimator.estimate(65534);

    try std.testing.expectEqual(@as(u32, 0), straggler.roc);
    try std.testing.expectEqual(@as(u48, 65534), straggler.value());
}

test "zix media: srtp index accept, a straggler moves nothing" {
    var estimator = Estimator{};
    estimator.accept(estimator.estimate(65535));
    estimator.accept(estimator.estimate(1));

    estimator.accept(estimator.estimate(65534));

    try std.testing.expectEqual(@as(u32, 1), estimator.roc);
    try std.testing.expectEqual(@as(u16, 1), estimator.highest_sequence);
}

test "zix media: srtp index accept, an out-of-order packet inside the counter does not lower it" {
    var estimator = Estimator{};
    estimator.accept(estimator.estimate(100));
    estimator.accept(estimator.estimate(105));
    estimator.accept(estimator.estimate(102));

    try std.testing.expectEqual(@as(u16, 105), estimator.highest_sequence);
    try std.testing.expectEqual(@as(u32, 0), estimator.roc);
}

test "zix media: srtp index estimate, it is pure until accept is called" {
    // This is what keeps a forged packet from dragging the counter forward. Guessing costs
    // nothing until the tag has been checked.
    var estimator = Estimator{};
    estimator.accept(estimator.estimate(10));

    _ = estimator.estimate(60000);
    _ = estimator.estimate(0);
    _ = estimator.estimate(65535);

    try std.testing.expectEqual(@as(u32, 0), estimator.roc);
    try std.testing.expectEqual(@as(u16, 10), estimator.highest_sequence);
}

test "zix media: srtp index estimate, the midpoint decides which way a jump is read" {
    var estimator = Estimator{};
    estimator.accept(estimator.estimate(100));

    // Just inside half a range ahead is read as a forward jump, still under this counter.
    try std.testing.expectEqual(@as(u32, 0), estimator.estimate(100 + 32768).roc);

    // Just past it is read as a straggler from the previous counter instead.
    try std.testing.expectEqual(@as(u32, 0) -% 1, estimator.estimate(100 + 32769).roc);
}

test "zix media: srtp index estimate, near the top of the range a small number has wrapped" {
    var estimator = Estimator{};
    estimator.accept(estimator.estimate(40000));

    // 40000 - 32768 is 7232, so anything below that has wrapped.
    try std.testing.expectEqual(@as(u32, 1), estimator.estimate(7231).roc);
    try std.testing.expectEqual(@as(u32, 0), estimator.estimate(7232).roc);
}

test "zix media: srtp index, the counter wraps at its own ceiling without panicking" {
    var estimator = Estimator{ .roc = 0xFFFFFFFF, .highest_sequence = 65535, .started = true };
    const wrapped = estimator.estimate(0);

    try std.testing.expectEqual(@as(u32, 0), wrapped.roc);

    estimator.accept(wrapped);
    try std.testing.expectEqual(@as(u32, 0), estimator.roc);
}

test "zix media: srtp index forSend, the sender counts its own wraps" {
    var estimator = Estimator{};

    try std.testing.expectEqual(@as(u32, 0), estimator.forSend(65534).roc);
    try std.testing.expectEqual(@as(u32, 0), estimator.forSend(65535).roc);
    try std.testing.expectEqual(@as(u32, 1), estimator.forSend(0).roc);
    try std.testing.expectEqual(@as(u48, 65537), estimator.forSend(1).value());
}

test "zix media: srtp index replay, a fresh list accepts index zero exactly once" {
    var list = ReplayList{};

    try std.testing.expect(list.isNew(0));

    list.accept(0);

    try std.testing.expect(!list.isNew(0));
}

test "zix media: srtp index replay, a repeat is refused and a new one is not" {
    var list = ReplayList{};
    list.accept(100);

    try std.testing.expect(!list.isNew(100));
    try std.testing.expect(list.isNew(101));
    try std.testing.expect(list.isNew(99));

    list.accept(99);
    try std.testing.expect(!list.isNew(99));
}

test "zix media: srtp index replay, anything past the left edge is refused" {
    var list = ReplayList{};
    list.accept(1000);

    try std.testing.expect(list.isNew(1000 - REPLAY_WINDOW_BITS + 1));
    try std.testing.expect(!list.isNew(1000 - REPLAY_WINDOW_BITS));
    try std.testing.expect(!list.isNew(0));
}

test "zix media: srtp index replay, the window slides forward" {
    var list = ReplayList{};
    list.accept(10);
    list.accept(11);
    list.accept(50);

    // 10 and 11 are still inside the window at its new position, and 12 never arrived.
    try std.testing.expect(!list.isNew(10));
    try std.testing.expect(!list.isNew(11));
    try std.testing.expect(list.isNew(12));

    // Sliding far enough puts them off the left edge instead, which refuses them for the other
    // reason: too old to tell apart from a replay.
    list.accept(200);
    try std.testing.expect(!list.isNew(12));
}

test "zix media: srtp index replay, a jump past the window clears it" {
    var list = ReplayList{};
    list.accept(1);
    list.accept(1000);

    try std.testing.expect(!list.isNew(1000));
    try std.testing.expect(!list.isNew(1));

    // 1 is now off the left edge rather than remembered, which is the same answer for a
    // different reason, and 999 is inside the window and unseen.
    try std.testing.expect(list.isNew(999));
}

test "zix media: srtp index replay, an unauthenticated packet leaves no mark" {
    // isNew is a question, not a decision. Asking it repeatedly must not consume anything.
    var list = ReplayList{};
    list.accept(50);

    try std.testing.expect(list.isNew(51));
    try std.testing.expect(list.isNew(51));
    try std.testing.expect(list.isNew(51));

    list.accept(51);
    try std.testing.expect(!list.isNew(51));
}

test "zix media: srtp index, the estimator and the list work on the same number" {
    var estimator = Estimator{};
    var list = ReplayList{};

    const first = estimator.estimate(65535);
    try std.testing.expect(list.isNew(first.value()));

    estimator.accept(first);
    list.accept(first.value());

    const wrapped = estimator.estimate(0);
    try std.testing.expectEqual(@as(u48, 65536), wrapped.value());
    try std.testing.expect(list.isNew(wrapped.value()));

    estimator.accept(wrapped);
    list.accept(wrapped.value());

    // Replaying the packet from before the wrap is refused on its index, not on its sequence
    // number, which is the whole reason the index is 48 bits wide.
    try std.testing.expect(!list.isNew(estimator.estimate(65535).value()));
}
