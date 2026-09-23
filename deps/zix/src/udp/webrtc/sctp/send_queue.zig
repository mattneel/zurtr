//! zix SCTP send-side bookkeeping (RFC 9260 6.1, 6.3.3, 7.2.4, and RFC 3758 3.5).
//!
//! What:
//! - Every DATA chunk this endpoint has queued or sent and not yet had acknowledged, in TSN
//!   order, with what has happened to each: waiting for room, on the wire, acknowledged, or
//!   given up on.
//! - The three things that read from that: which chunk to send next, what a SACK actually told
//!   us, and which chunks a timeout or a run of gap reports means to send again.
//!
//! Note:
//! - TSNs are assigned here, one per chunk, in the order chunks are queued. Stream sequence
//!   numbers are not: they are per stream and belong to whatever owns the streams.
//! - Round trip samples come only from chunks that were never retransmitted. That is Karn's
//!   algorithm (RFC 9260 6.3.1 C5), and without it a retransmission acknowledged quickly looks
//!   like a fast path and drives the timeout down until nothing ever completes.
//! - A chunk acknowledged only by a gap block is marked but NOT dropped. A receiver is allowed
//!   to renege on gap blocks, and only the cumulative point is a promise. Chunks are freed when
//!   the cumulative point passes them.
//! - Missing reports are counted against the highest TSN newly acknowledged, not against
//!   everything unacknowledged (RFC 9260 7.2.4). A chunk above that point has not been passed
//!   over, it simply has not been reached.
//! - Abandonment is what partial reliability means on this side: a chunk past its retransmit
//!   count or its deadline is dropped and the receiver is told to skip it with a FORWARD TSN.
//!   Nothing here sends that chunk, it only says where the point would move to.
//! - This needs an allocator that reclaims. Chunks are freed as they are acknowledged.

const std = @import("std");

const chunk = @import("chunk.zig");
const data = @import("data.zig");
const forward_tsn = @import("forward_tsn.zig");
const sack = @import("sack.zig");
const serial = @import("serial.zig");

/// How many gap reports a chunk survives before it is retransmitted (RFC 9260 7.2.4).
pub const FAST_RETRANSMIT_THRESHOLD: u8 = 3;

/// Ceilings on how much unacknowledged data is held.
pub const Limits = struct {
    max_outstanding_chunks: usize = 512,
    max_outstanding_bytes: usize = 1024 * 1024,
};

/// How hard the sender tries before giving up on a chunk (RFC 3758 3.5).
///
/// Note:
/// - Both null is a fully reliable chunk, which is what a reliable data channel uses.
pub const Reliability = struct {
    /// Give up after this many retransmissions.
    max_retransmits: ?u16 = null,
    /// Give up once this point on the caller's clock has passed.
    expires_ms: ?u64 = null,
};

/// Where a chunk is in its life.
pub const State = enum {
    /// Queued, waiting for room in the congestion window.
    QUEUED,
    /// Sent and not yet acknowledged.
    IN_FLIGHT,
    /// Acknowledged, kept until the cumulative point passes it.
    ACKED,
    /// Given up on, and to be skipped with a FORWARD TSN.
    ABANDONED,
};

/// What the caller hands in to be sent.
pub const Outgoing = struct {
    stream_identifier: u16,
    /// Assigned by whatever owns the stream. Ignored when `unordered` is set.
    stream_sequence: u16 = 0,
    payload_protocol: u32 = 0,
    unordered: bool = false,
    beginning: bool = true,
    ending: bool = true,
    payload: []const u8,
    reliability: Reliability = .{},
};

/// One chunk being tracked.
pub const Outstanding = struct {
    tsn: u32,
    stream_identifier: u16,
    stream_sequence: u16,
    payload_protocol: u32,
    unordered: bool,
    beginning: bool,
    ending: bool,
    /// Owned copy, freed when the chunk is dropped.
    payload: []u8,
    reliability: Reliability,
    state: State,
    /// When it last went out, on the caller's clock.
    sent_ms: u64,
    retransmits: u16,
    /// Gap reports that passed over this chunk since it was last sent.
    missing_reports: u8,
    /// Whether a fast retransmit has already been spent on it.
    fast_retransmitted: bool,

    /// What this chunk costs on the wire, chunk header and padding included.
    ///
    /// Note:
    /// - RFC 9260 7.2 counts the padding against the congestion window, so this is the number
    ///   the window is fed.
    ///
    /// Return:
    /// - usize
    pub fn wireBytes(self: Outstanding) usize {
        return chunk.paddedLen(chunk.HEADER_LEN + data.FIXED_LEN + self.payload.len);
    }

    /// The chunk as it goes on the wire.
    ///
    /// Return:
    /// - data.Data borrowing this chunk's payload
    pub fn asData(self: Outstanding) data.Data {
        return .{
            .tsn = self.tsn,
            .stream_identifier = self.stream_identifier,
            .stream_sequence = self.stream_sequence,
            .payload_protocol = self.payload_protocol,
            .unordered = self.unordered,
            .beginning = self.beginning,
            .ending = self.ending,
            .payload = self.payload,
        };
    }
};

/// What one SACK changed.
pub const SackOutcome = struct {
    /// Bytes acknowledged for the first time, wire cost included.
    newly_acked_bytes: usize = 0,
    /// Bytes outstanding just before this SACK, which the congestion window needs.
    flight_before: usize = 0,
    /// Whether the cumulative point moved forward.
    advanced: bool = false,
    /// A round trip, when one could be taken without breaking Karn's algorithm.
    rtt_sample_ms: ?u64 = null,
    /// Whether any chunk reached the missing report threshold and is now queued again.
    fast_retransmit: bool = false,
    /// Whether nothing is left outstanding.
    all_acked: bool = false,
};

/// Everything that stops a chunk from being queued.
pub const Error = error{
    OutOfMemory,
    /// The outstanding limits are reached. Try again once something is acknowledged.
    ZixNoSpace,
    /// A DATA chunk must carry at least one byte (RFC 9260 3.3.1).
    ZixNoUserData,
};

/// Holds unacknowledged chunks and decides what happens to them.
///
/// Usage:
/// ```zig
/// var queue = SendQueue.init(allocator, .{}, local_initial_tsn);
/// defer queue.deinit();
///
/// _ = try queue.append(.{ .stream_identifier = 0, .payload = "hello" }, now_ms);
///
/// while (queue.nextToSend()) |item| {
///     if (window.available(queue.in_flight_bytes, peer_rwnd) < item.wireBytes()) break;
///     try send(item.asData());
///     queue.markSent(item.tsn, now_ms);
/// }
/// ```
pub const SendQueue = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    /// The TSN the next queued chunk gets.
    next_tsn: u32,
    /// The peer's last cumulative acknowledgement.
    peer_cumulative_tsn: u32,
    /// Chunks in TSN order.
    chunks: std.ArrayList(Outstanding),
    /// Bytes currently on the wire.
    in_flight_bytes: usize,
    /// Bytes held for chunks not yet acknowledged, queued ones included.
    outstanding_bytes: usize,

    /// Start numbering at this endpoint's initial TSN.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (must reclaim, see the file note)
    /// limits - Limits
    /// initial_tsn - u32 (this endpoint's initial TSN, as announced in its INIT)
    ///
    /// Return:
    /// - SendQueue
    pub fn init(allocator: std.mem.Allocator, limits: Limits, initial_tsn: u32) SendQueue {
        return .{
            .allocator = allocator,
            .limits = limits,
            .next_tsn = initial_tsn,
            .peer_cumulative_tsn = serial.Tsn.previous(initial_tsn),
            .chunks = .empty,
            .in_flight_bytes = 0,
            .outstanding_bytes = 0,
        };
    }

    /// Free everything still held.
    ///
    /// Return:
    /// - void
    pub fn deinit(self: *SendQueue) void {
        for (self.chunks.items) |item| self.allocator.free(item.payload);

        self.chunks.deinit(self.allocator);
    }

    /// How many chunks are being tracked.
    ///
    /// Return:
    /// - usize
    pub fn count(self: SendQueue) usize {
        return self.chunks.items.len;
    }

    /// Queue a chunk and give it a TSN.
    ///
    /// Param:
    /// item - Outgoing (payload is copied, so the caller's buffer may be reused)
    /// now_ms - u64 (monotonic milliseconds, only used if the chunk carries a deadline)
    ///
    /// Return:
    /// - u32, the TSN this chunk was given
    /// - error.ZixNoUserData if the payload is empty
    /// - error.ZixNoSpace if the outstanding limits are reached
    /// - error.OutOfMemory
    pub fn append(self: *SendQueue, item: Outgoing, now_ms: u64) Error!u32 {
        _ = now_ms;

        if (item.payload.len == 0) return error.ZixNoUserData;
        if (self.chunks.items.len >= self.limits.max_outstanding_chunks) return error.ZixNoSpace;

        const cost = chunk.paddedLen(chunk.HEADER_LEN + data.FIXED_LEN + item.payload.len);

        if (self.outstanding_bytes + cost > self.limits.max_outstanding_bytes) return error.ZixNoSpace;

        const owned = try self.allocator.dupe(u8, item.payload);
        errdefer self.allocator.free(owned);

        const tsn = self.next_tsn;

        try self.chunks.append(self.allocator, .{
            .tsn = tsn,
            .stream_identifier = item.stream_identifier,
            .stream_sequence = item.stream_sequence,
            .payload_protocol = item.payload_protocol,
            .unordered = item.unordered,
            .beginning = item.beginning,
            .ending = item.ending,
            .payload = owned,
            .reliability = item.reliability,
            .state = .QUEUED,
            .sent_ms = 0,
            .retransmits = 0,
            .missing_reports = 0,
            .fast_retransmitted = false,
        });

        self.next_tsn = serial.Tsn.next(tsn);
        self.outstanding_bytes += cost;

        return tsn;
    }

    /// The lowest-numbered chunk waiting to go out.
    ///
    /// Note:
    /// - Retransmissions come out here too, and because the list is in TSN order they come out
    ///   ahead of anything queued after them.
    ///
    /// Return:
    /// - ?*Outstanding, null when nothing is waiting
    pub fn nextToSend(self: *SendQueue) ?*Outstanding {
        for (self.chunks.items) |*item| {
            if (item.state == .QUEUED) return item;
        }

        return null;
    }

    /// Whether anything is waiting to go out.
    ///
    /// Return:
    /// - bool
    pub fn hasQueued(self: SendQueue) bool {
        for (self.chunks.items) |item| {
            if (item.state == .QUEUED) return true;
        }

        return false;
    }

    /// Record that a chunk has gone on the wire.
    ///
    /// Param:
    /// tsn - u32
    /// now_ms - u64 (monotonic milliseconds, used for the round trip measurement)
    ///
    /// Return:
    /// - void
    pub fn markSent(self: *SendQueue, tsn: u32, now_ms: u64) void {
        const item = self.find(tsn) orelse return;

        if (item.state != .QUEUED) return;

        item.state = .IN_FLIGHT;
        item.sent_ms = now_ms;
        item.missing_reports = 0;
        self.in_flight_bytes += item.wireBytes();
    }

    /// Apply an acknowledgement from the peer.
    ///
    /// Param:
    /// report - sack.Sack (as parsed off the wire)
    /// now_ms - u64 (monotonic milliseconds, when the SACK arrived)
    ///
    /// Return:
    /// - SackOutcome
    pub fn onSack(self: *SendQueue, report: sack.Sack, now_ms: u64) SackOutcome {
        var outcome: SackOutcome = .{ .flight_before = self.in_flight_bytes };

        const highest_acked = report.highestTsnAcked();

        for (self.chunks.items) |*item| {
            if (item.state == .ACKED or item.state == .ABANDONED) continue;
            if (!report.acknowledges(item.tsn)) continue;

            if (item.state == .IN_FLIGHT) {
                self.in_flight_bytes -= item.wireBytes();

                // Karn's algorithm: a retransmitted chunk gives an ambiguous round trip, because
                // the acknowledgement could be for either copy.
                if (item.retransmits == 0 and now_ms >= item.sent_ms) {
                    outcome.rtt_sample_ms = now_ms - item.sent_ms;
                }
            }

            outcome.newly_acked_bytes += item.wireBytes();
            item.state = .ACKED;
        }

        for (self.chunks.items) |*item| {
            if (item.state != .IN_FLIGHT) continue;
            if (!serial.Tsn.lessThan(item.tsn, highest_acked)) continue;

            item.missing_reports +|= 1;

            if (item.missing_reports < FAST_RETRANSMIT_THRESHOLD) continue;
            if (item.fast_retransmitted) continue;

            item.fast_retransmitted = true;
            item.state = .QUEUED;
            item.retransmits +|= 1;
            self.in_flight_bytes -= item.wireBytes();
            outcome.fast_retransmit = true;
        }

        if (serial.Tsn.greaterThan(report.cumulative_tsn_ack, self.peer_cumulative_tsn)) {
            self.peer_cumulative_tsn = report.cumulative_tsn_ack;
            outcome.advanced = true;
        }

        self.prune();

        outcome.all_acked = self.chunks.items.len == 0;

        return outcome;
    }

    /// The retransmission timer expired, so everything on the wire goes back in the queue.
    ///
    /// Note:
    /// - RFC 9260 6.3.3 E1 marks every outstanding chunk for retransmission, not just the oldest.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds, unused today, kept so the call site reads the same
    ///   as the others)
    ///
    /// Return:
    /// - void
    pub fn onTimeout(self: *SendQueue, now_ms: u64) void {
        _ = now_ms;

        for (self.chunks.items) |*item| {
            if (item.state != .IN_FLIGHT) continue;

            self.in_flight_bytes -= item.wireBytes();
            item.state = .QUEUED;
            item.retransmits +|= 1;
            item.missing_reports = 0;
            item.fast_retransmitted = false;
        }
    }

    /// Give up on chunks that have run past what their reliability allows.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - bool, true when at least one chunk was abandoned
    pub fn abandonExpired(self: *SendQueue, now_ms: u64) bool {
        var abandoned = false;

        for (self.chunks.items) |*item| {
            if (item.state == .ACKED or item.state == .ABANDONED) continue;
            if (!expired(item.*, now_ms)) continue;

            if (item.state == .IN_FLIGHT) self.in_flight_bytes -= item.wireBytes();

            item.state = .ABANDONED;
            abandoned = true;
        }

        return abandoned;
    }

    /// Where a FORWARD TSN would move the receiver's cumulative point.
    ///
    /// Note:
    /// - Only meaningful when something was abandoned. A run that is merely acknowledged needs
    ///   no FORWARD TSN, the peer already knows.
    ///
    /// Return:
    /// - ?u32, null when nothing has been abandoned below the next hole
    pub fn forwardTsnPoint(self: SendQueue) ?u32 {
        var point = self.peer_cumulative_tsn;
        var saw_abandoned = false;

        for (self.chunks.items) |item| {
            if (item.tsn != serial.Tsn.next(point)) break;
            if (item.state != .ACKED and item.state != .ABANDONED) break;

            if (item.state == .ABANDONED) saw_abandoned = true;
            point = item.tsn;
        }

        if (!saw_abandoned) return null;

        return point;
    }

    /// The stream entries that go with a FORWARD TSN.
    ///
    /// Note:
    /// - Ordered streams only, one entry per stream, carrying the highest sequence being skipped
    ///   (RFC 3758 3.2). An unordered chunk has no sequence to skip to.
    ///
    /// Param:
    /// point - u32 (from `forwardTsnPoint`)
    /// out - []forward_tsn.StreamEntry (caller storage, the scan stops when it is full)
    ///
    /// Return:
    /// - []forward_tsn.StreamEntry, a prefix of `out`
    pub fn forwardTsnStreams(self: SendQueue, point: u32, out: []forward_tsn.StreamEntry) []forward_tsn.StreamEntry {
        var found: usize = 0;

        for (self.chunks.items) |item| {
            if (serial.Tsn.greaterThan(item.tsn, point)) break;
            if (item.state != .ABANDONED) continue;
            if (item.unordered) continue;

            if (existingEntry(out[0..found], item.stream_identifier)) |slot| {
                if (serial.StreamSequence.greaterThan(item.stream_sequence, slot.stream_sequence)) {
                    slot.stream_sequence = item.stream_sequence;
                }

                continue;
            }

            if (found == out.len) break;

            out[found] = .{
                .stream_identifier = item.stream_identifier,
                .stream_sequence = item.stream_sequence,
            };
            found += 1;
        }

        return out[0..found];
    }

    /// Move the peer's cumulative point after a FORWARD TSN has gone out.
    ///
    /// Note:
    /// - The peer will confirm this in its next SACK. Moving it here is what lets the abandoned
    ///   chunks be freed instead of being held until then.
    ///
    /// Param:
    /// point - u32 (from `forwardTsnPoint`)
    ///
    /// Return:
    /// - void
    pub fn markForwarded(self: *SendQueue, point: u32) void {
        if (!serial.Tsn.greaterThan(point, self.peer_cumulative_tsn)) return;

        self.peer_cumulative_tsn = point;
        self.prune();
    }

    /// The chunk with a given TSN.
    fn find(self: *SendQueue, tsn: u32) ?*Outstanding {
        for (self.chunks.items) |*item| {
            if (item.tsn == tsn) return item;
        }

        return null;
    }

    /// Free the chunks the peer's cumulative point has passed.
    fn prune(self: *SendQueue) void {
        var removed: usize = 0;

        while (removed < self.chunks.items.len) : (removed += 1) {
            const item = self.chunks.items[removed];

            if (serial.Tsn.greaterThan(item.tsn, self.peer_cumulative_tsn)) break;

            self.outstanding_bytes -= item.wireBytes();
            self.allocator.free(item.payload);
        }

        if (removed == 0) return;

        const kept = self.chunks.items.len - removed;
        std.mem.copyForwards(Outstanding, self.chunks.items[0..kept], self.chunks.items[removed..]);
        self.chunks.shrinkRetainingCapacity(kept);
    }
};

/// Whether a chunk has run past what its reliability allows.
fn expired(item: Outstanding, now_ms: u64) bool {
    if (item.reliability.max_retransmits) |limit| {
        if (item.retransmits > limit) return true;
    }

    if (item.reliability.expires_ms) |deadline| {
        if (now_ms >= deadline) return true;
    }

    return false;
}

/// The entry already collected for a stream, if there is one.
fn existingEntry(entries: []forward_tsn.StreamEntry, stream_identifier: u16) ?*forward_tsn.StreamEntry {
    for (entries) |*slot| {
        if (slot.stream_identifier == stream_identifier) return slot;
    }

    return null;
}

// --------------------------------------------------------------------------------------- //
// test cases

fn testQueue() SendQueue {
    return SendQueue.init(std.testing.allocator, .{}, 100);
}

fn sackOf(buf: []u8, cumulative: u32, blocks: []const sack.GapAckBlock) !sack.Sack {
    return sack.read(try sack.write(buf, .{
        .cumulative_tsn_ack = cumulative,
        .advertised_rwnd = 65536,
        .gap_blocks = blocks,
    }));
}

test "zix sctp: send queue append, TSNs are handed out in order from the initial one" {
    var queue = testQueue();
    defer queue.deinit();

    try std.testing.expectEqual(@as(u32, 100), try queue.append(.{ .stream_identifier = 0, .payload = "a" }, 0));
    try std.testing.expectEqual(@as(u32, 101), try queue.append(.{ .stream_identifier = 0, .payload = "b" }, 0));
    try std.testing.expectEqual(@as(usize, 2), queue.count());
}

test "zix sctp: send queue append, an empty payload errors" {
    var queue = testQueue();
    defer queue.deinit();

    try std.testing.expectError(error.ZixNoUserData, queue.append(.{ .stream_identifier = 0, .payload = "" }, 0));
}

test "zix sctp: send queue append, the chunk limit refuses the next one" {
    var queue = SendQueue.init(std.testing.allocator, .{ .max_outstanding_chunks = 2 }, 100);
    defer queue.deinit();

    _ = try queue.append(.{ .stream_identifier = 0, .payload = "a" }, 0);
    _ = try queue.append(.{ .stream_identifier = 0, .payload = "b" }, 0);

    try std.testing.expectError(error.ZixNoSpace, queue.append(.{ .stream_identifier = 0, .payload = "c" }, 0));
}

test "zix sctp: send queue append, the byte limit counts the wire cost not the payload" {
    var queue = SendQueue.init(std.testing.allocator, .{ .max_outstanding_bytes = 40 }, 100);
    defer queue.deinit();

    // 4 chunk header plus 12 fixed fields plus 1 byte, padded to 20.
    _ = try queue.append(.{ .stream_identifier = 0, .payload = "a" }, 0);
    _ = try queue.append(.{ .stream_identifier = 0, .payload = "b" }, 0);

    try std.testing.expectError(error.ZixNoSpace, queue.append(.{ .stream_identifier = 0, .payload = "c" }, 0));
}

test "zix sctp: send queue send, a queued chunk becomes in flight and counts against the window" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{ .stream_identifier = 0, .payload = "hello" }, 0);

    const item = queue.nextToSend().?;
    try std.testing.expectEqual(@as(u32, 100), item.tsn);
    try std.testing.expectEqual(@as(usize, 24), item.wireBytes());

    queue.markSent(100, 1_000);

    try std.testing.expectEqual(@as(usize, 24), queue.in_flight_bytes);
    try std.testing.expect(queue.nextToSend() == null);
    try std.testing.expect(!queue.hasQueued());
}

test "zix sctp: send queue send, the chunk goes out with the fields it was queued with" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{
        .stream_identifier = 3,
        .stream_sequence = 7,
        .payload_protocol = 53,
        .payload = "body",
    }, 0);

    const outgoing = queue.nextToSend().?.asData();

    try std.testing.expectEqual(@as(u16, 3), outgoing.stream_identifier);
    try std.testing.expectEqual(@as(u16, 7), outgoing.stream_sequence);
    try std.testing.expectEqual(@as(u32, 53), outgoing.payload_protocol);
    try std.testing.expectEqualStrings("body", outgoing.payload);
    try std.testing.expect(outgoing.isWhole());
}

test "zix sctp: send queue sack, a cumulative acknowledgement frees the chunks it covers" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{ .stream_identifier = 0, .payload = "a" }, 0);
    _ = try queue.append(.{ .stream_identifier = 0, .payload = "b" }, 0);
    queue.markSent(100, 1_000);
    queue.markSent(101, 1_000);

    var buf: [64]u8 = undefined;
    const outcome = queue.onSack(try sackOf(&buf, 101, &.{}), 1_050);

    try std.testing.expect(outcome.advanced);
    try std.testing.expect(outcome.all_acked);
    try std.testing.expectEqual(@as(usize, 40), outcome.newly_acked_bytes);
    try std.testing.expectEqual(@as(usize, 40), outcome.flight_before);
    try std.testing.expectEqual(@as(usize, 0), queue.in_flight_bytes);
    try std.testing.expectEqual(@as(usize, 0), queue.count());
}

test "zix sctp: send queue sack, a round trip is measured off a chunk sent once" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{ .stream_identifier = 0, .payload = "a" }, 0);
    queue.markSent(100, 1_000);

    var buf: [64]u8 = undefined;
    const outcome = queue.onSack(try sackOf(&buf, 100, &.{}), 1_042);

    try std.testing.expectEqual(@as(u64, 42), outcome.rtt_sample_ms.?);
}

test "zix sctp: send queue sack, a retransmitted chunk gives no round trip" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{ .stream_identifier = 0, .payload = "a" }, 0);
    queue.markSent(100, 1_000);
    queue.onTimeout(2_000);
    queue.markSent(100, 2_000);

    var buf: [64]u8 = undefined;
    const outcome = queue.onSack(try sackOf(&buf, 100, &.{}), 2_030);

    // Karn's algorithm: the acknowledgement could be for either copy, so the number is a guess.
    try std.testing.expect(outcome.rtt_sample_ms == null);
}

test "zix sctp: send queue sack, a chunk acknowledged only by a gap block is kept" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{ .stream_identifier = 0, .payload = "a" }, 0);
    _ = try queue.append(.{ .stream_identifier = 0, .payload = "b" }, 0);
    queue.markSent(100, 1_000);
    queue.markSent(101, 1_000);

    var buf: [64]u8 = undefined;

    // 100 is missing, 101 arrived, so the cumulative point stays below both.
    const outcome = queue.onSack(try sackOf(&buf, 99, &.{.{ .start = 2, .end = 2 }}), 1_050);

    try std.testing.expect(!outcome.advanced);
    try std.testing.expect(!outcome.all_acked);

    // A receiver may renege on a gap block, so the chunk stays until the cumulative point moves.
    try std.testing.expectEqual(@as(usize, 2), queue.count());
    try std.testing.expectEqual(State.ACKED, queue.chunks.items[1].state);
    try std.testing.expectEqual(State.IN_FLIGHT, queue.chunks.items[0].state);
}

test "zix sctp: send queue sack, three gap reports over one chunk queue it again" {
    var queue = testQueue();
    defer queue.deinit();

    for (0..4) |_| _ = try queue.append(.{ .stream_identifier = 0, .payload = "x" }, 0);
    for (100..104) |tsn| queue.markSent(@intCast(tsn), 1_000);

    var buf: [64]u8 = undefined;

    // Each SACK acknowledges a later chunk while 100 stays missing.
    var outcome = queue.onSack(try sackOf(&buf, 99, &.{.{ .start = 2, .end = 2 }}), 1_010);
    try std.testing.expect(!outcome.fast_retransmit);

    outcome = queue.onSack(try sackOf(&buf, 99, &.{.{ .start = 2, .end = 3 }}), 1_020);
    try std.testing.expect(!outcome.fast_retransmit);

    outcome = queue.onSack(try sackOf(&buf, 99, &.{.{ .start = 2, .end = 4 }}), 1_030);

    try std.testing.expect(outcome.fast_retransmit);
    try std.testing.expectEqual(@as(u32, 100), queue.nextToSend().?.tsn);
}

test "zix sctp: send queue sack, a fast retransmit is spent only once per chunk" {
    var queue = testQueue();
    defer queue.deinit();

    for (0..4) |_| _ = try queue.append(.{ .stream_identifier = 0, .payload = "x" }, 0);
    for (100..104) |tsn| queue.markSent(@intCast(tsn), 1_000);

    var buf: [64]u8 = undefined;
    _ = queue.onSack(try sackOf(&buf, 99, &.{.{ .start = 2, .end = 2 }}), 1_010);
    _ = queue.onSack(try sackOf(&buf, 99, &.{.{ .start = 2, .end = 3 }}), 1_020);
    _ = queue.onSack(try sackOf(&buf, 99, &.{.{ .start = 2, .end = 4 }}), 1_030);

    queue.markSent(100, 1_040);

    const outcome = queue.onSack(try sackOf(&buf, 99, &.{.{ .start = 2, .end = 4 }}), 1_050);

    try std.testing.expect(!outcome.fast_retransmit);
}

test "zix sctp: send queue sack, a chunk above the highest acknowledged is not counted missing" {
    var queue = testQueue();
    defer queue.deinit();

    for (0..3) |_| _ = try queue.append(.{ .stream_identifier = 0, .payload = "x" }, 0);
    for (100..103) |tsn| queue.markSent(@intCast(tsn), 1_000);

    var buf: [64]u8 = undefined;

    for (0..5) |_| _ = queue.onSack(try sackOf(&buf, 100, &.{}), 1_010);

    // 101 and 102 were never passed over, they simply have not been reached.
    try std.testing.expectEqual(@as(u8, 0), queue.chunks.items[0].missing_reports);
    try std.testing.expect(!queue.hasQueued());
}

test "zix sctp: send queue timeout, everything on the wire goes back in the queue" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{ .stream_identifier = 0, .payload = "a" }, 0);
    _ = try queue.append(.{ .stream_identifier = 0, .payload = "b" }, 0);
    queue.markSent(100, 1_000);
    queue.markSent(101, 1_000);

    queue.onTimeout(3_000);

    try std.testing.expectEqual(@as(usize, 0), queue.in_flight_bytes);
    try std.testing.expectEqual(@as(u32, 100), queue.nextToSend().?.tsn);
    try std.testing.expectEqual(@as(u16, 1), queue.chunks.items[0].retransmits);
    try std.testing.expectEqual(@as(u16, 1), queue.chunks.items[1].retransmits);
}

test "zix sctp: send queue abandon, a chunk past its retransmit limit is given up on" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{
        .stream_identifier = 0,
        .payload = "lossy",
        .reliability = .{ .max_retransmits = 1 },
    }, 0);

    queue.markSent(100, 1_000);
    queue.onTimeout(2_000);

    try std.testing.expect(!queue.abandonExpired(2_000));

    queue.markSent(100, 2_000);
    queue.onTimeout(3_000);

    try std.testing.expect(queue.abandonExpired(3_000));
    try std.testing.expectEqual(State.ABANDONED, queue.chunks.items[0].state);
}

test "zix sctp: send queue abandon, a chunk past its deadline is given up on" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{
        .stream_identifier = 0,
        .payload = "stale",
        .reliability = .{ .expires_ms = 2_000 },
    }, 0);

    queue.markSent(100, 1_000);

    try std.testing.expect(!queue.abandonExpired(1_999));
    try std.testing.expect(queue.abandonExpired(2_000));
    try std.testing.expectEqual(@as(usize, 0), queue.in_flight_bytes);
}

test "zix sctp: send queue abandon, a fully reliable chunk is never given up on" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{ .stream_identifier = 0, .payload = "reliable" }, 0);
    queue.markSent(100, 1_000);

    for (0..20) |_| queue.onTimeout(9_999_999);

    try std.testing.expect(!queue.abandonExpired(9_999_999));
}

test "zix sctp: send queue forward, the point covers a run of abandoned chunks" {
    var queue = testQueue();
    defer queue.deinit();

    for (0..3) |_| _ = try queue.append(.{
        .stream_identifier = 1,
        .payload = "x",
        .reliability = .{ .expires_ms = 2_000 },
    }, 0);

    _ = try queue.append(.{ .stream_identifier = 1, .payload = "kept" }, 0);

    for (100..104) |tsn| queue.markSent(@intCast(tsn), 1_000);

    try std.testing.expect(queue.forwardTsnPoint() == null);

    _ = queue.abandonExpired(2_000);

    // 103 has no deadline, so the point stops just below it.
    try std.testing.expectEqual(@as(u32, 102), queue.forwardTsnPoint().?);
}

test "zix sctp: send queue forward, a run of acknowledgements alone needs no forward point" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{ .stream_identifier = 0, .payload = "a" }, 0);
    _ = try queue.append(.{ .stream_identifier = 0, .payload = "b" }, 0);
    queue.markSent(100, 1_000);
    queue.markSent(101, 1_000);

    var buf: [64]u8 = undefined;
    _ = queue.onSack(try sackOf(&buf, 99, &.{ .{ .start = 1, .end = 1 }, .{ .start = 2, .end = 2 } }), 1_050);

    try std.testing.expect(queue.forwardTsnPoint() == null);
}

test "zix sctp: send queue forward, the stream list carries the highest skipped sequence" {
    var queue = testQueue();
    defer queue.deinit();

    const lossy: Reliability = .{ .expires_ms = 2_000 };

    _ = try queue.append(.{ .stream_identifier = 1, .stream_sequence = 4, .payload = "a", .reliability = lossy }, 0);
    _ = try queue.append(.{ .stream_identifier = 1, .stream_sequence = 5, .payload = "b", .reliability = lossy }, 0);
    _ = try queue.append(.{ .stream_identifier = 2, .stream_sequence = 9, .payload = "c", .reliability = lossy }, 0);

    for (100..103) |tsn| queue.markSent(@intCast(tsn), 1_000);
    _ = queue.abandonExpired(2_000);

    const point = queue.forwardTsnPoint().?;

    var entries: [4]forward_tsn.StreamEntry = undefined;
    const listed = queue.forwardTsnStreams(point, &entries);

    try std.testing.expectEqual(@as(usize, 2), listed.len);
    try std.testing.expectEqual(@as(u16, 1), listed[0].stream_identifier);
    try std.testing.expectEqual(@as(u16, 5), listed[0].stream_sequence);
    try std.testing.expectEqual(@as(u16, 2), listed[1].stream_identifier);
    try std.testing.expectEqual(@as(u16, 9), listed[1].stream_sequence);
}

test "zix sctp: send queue forward, an unordered chunk is never listed" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{
        .stream_identifier = 1,
        .unordered = true,
        .payload = "loose",
        .reliability = .{ .expires_ms = 2_000 },
    }, 0);

    queue.markSent(100, 1_000);
    _ = queue.abandonExpired(2_000);

    const point = queue.forwardTsnPoint().?;

    var entries: [4]forward_tsn.StreamEntry = undefined;

    // An unordered message has no sequence to skip to, so naming one would skip a real message.
    try std.testing.expectEqual(@as(usize, 0), queue.forwardTsnStreams(point, &entries).len);
}

test "zix sctp: send queue forward, marking it sent frees the abandoned chunks" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{
        .stream_identifier = 1,
        .payload = "gone",
        .reliability = .{ .expires_ms = 2_000 },
    }, 0);

    queue.markSent(100, 1_000);
    _ = queue.abandonExpired(2_000);

    queue.markForwarded(queue.forwardTsnPoint().?);

    try std.testing.expectEqual(@as(usize, 0), queue.count());
    try std.testing.expect(queue.forwardTsnPoint() == null);
}

test "zix sctp: send queue sack, an acknowledgement below the current point changes nothing" {
    var queue = testQueue();
    defer queue.deinit();

    _ = try queue.append(.{ .stream_identifier = 0, .payload = "a" }, 0);
    queue.markSent(100, 1_000);

    var buf: [64]u8 = undefined;
    _ = queue.onSack(try sackOf(&buf, 100, &.{}), 1_050);

    const outcome = queue.onSack(try sackOf(&buf, 99, &.{}), 1_060);

    try std.testing.expect(!outcome.advanced);
    try std.testing.expectEqual(@as(usize, 0), queue.count());
}

test "zix sctp: send queue append, TSNs keep going across the wrap" {
    var queue = SendQueue.init(std.testing.allocator, .{}, 0xFFFFFFFF);
    defer queue.deinit();

    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), try queue.append(.{ .stream_identifier = 0, .payload = "a" }, 0));
    try std.testing.expectEqual(@as(u32, 0), try queue.append(.{ .stream_identifier = 0, .payload = "b" }, 0));

    queue.markSent(0xFFFFFFFF, 1_000);
    queue.markSent(0, 1_000);

    var buf: [64]u8 = undefined;
    const outcome = queue.onSack(try sackOf(&buf, 0, &.{}), 1_050);

    try std.testing.expect(outcome.all_acked);
}
