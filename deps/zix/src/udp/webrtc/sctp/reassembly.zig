//! zix SCTP reassembly and delivery (RFC 9260 6.5, 6.6, 6.9).
//!
//! What:
//! - Turns a stream of DATA chunks back into user messages. Chunks that arrive out of order wait
//!   here until the hole in front of them fills, fragments of one message are joined back
//!   together, and messages come out in the order the sender queued them.
//! - The receiving half of partial reliability: `skipTo` moves past chunks the sender has given
//!   up on, which is what a FORWARD TSN asks for (RFC 3758 3.6).
//!
//! Note:
//! - Delivery is strictly in TSN order, and that is what makes ordered streams work with no
//!   per-stream bookkeeping: a sender assigns increasing stream sequence numbers in increasing
//!   TSN order, so in-order TSNs are in-order stream sequences. An unordered chunk takes the
//!   same path and is simply not held up by a stream sequence it does not have.
//! - Without the interleaving extension (RFC 8260, not implemented) a sender may only fragment
//!   one message at a time, so exactly one message is ever under assembly. A fragment that
//!   arrives while another message is open is a protocol violation, not a second buffer.
//! - A chunk that does not fit the pending limits is refused with error.ZixNoSpace, and the caller
//!   must then NOT acknowledge that TSN. Dropping a chunk is legal and the sender retransmits.
//!   Acknowledging one that was dropped is not: the sender would never send it again.
//! - The payload of a returned message is borrowed and stays valid only until the next call.
//!   Copy it if it has to outlive that.
//! - This needs an allocator that actually reclaims. Chunks are freed as they are delivered, so
//!   an arena that never frees would grow for the life of the association.

const std = @import("std");

const data = @import("data.zig");
const serial = @import("serial.zig");

/// Ceilings that keep one peer from making this endpoint hold memory forever.
pub const Limits = struct {
    /// Largest message that will be reassembled, in bytes.
    max_message_bytes: usize = 256 * 1024,
    /// Largest total payload held for chunks waiting on a hole.
    max_pending_bytes: usize = 256 * 1024,
    /// Largest number of chunks held waiting on a hole.
    max_pending_chunks: usize = 512,
};

/// Everything that can go wrong taking or delivering a chunk.
pub const Error = error{
    OutOfMemory,
    /// A fragment that cannot belong to the message being assembled.
    ZixProtocolViolation,
    /// A message grew past max_message_bytes.
    ZixMessageTooLarge,
    /// No room to hold this chunk. Do not acknowledge its TSN.
    ZixNoSpace,
};

/// One complete user message.
pub const Message = struct {
    stream_identifier: u16,
    /// Meaningless when `unordered` is set.
    stream_sequence: u16,
    payload_protocol: u32,
    unordered: bool,
    /// Borrowed. Valid until the next call on the reassembler that produced it.
    payload: []const u8,
};

/// One chunk held until the TSNs in front of it arrive.
const Pending = struct {
    tsn: u32,
    stream_identifier: u16,
    stream_sequence: u16,
    payload_protocol: u32,
    unordered: bool,
    beginning: bool,
    ending: bool,
    /// Owned copy, freed when the chunk is delivered or dropped.
    payload: []u8,
};

/// What is known about the message currently being assembled.
const Partial = struct {
    stream_identifier: u16,
    stream_sequence: u16,
    payload_protocol: u32,
    unordered: bool,
};

/// Holds out-of-order chunks and hands back finished messages.
///
/// Usage:
/// ```zig
/// var reassembler = Reassembler.init(allocator, .{}, peer_initial_tsn);
/// defer reassembler.deinit();
///
/// reassembler.accept(chunk) catch |err| switch (err) {
///     error.ZixNoSpace => {}, // dropped, so leave the TSN unacknowledged
///     else => return err,
/// };
///
/// while (try reassembler.next()) |message| handle(message);
/// ```
pub const Reassembler = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    /// The TSN that has to arrive before anything else can be delivered.
    next_tsn: u32,
    pending: std.ArrayList(Pending),
    pending_bytes: usize,
    /// Bytes of the message currently being joined back together.
    assembling: std.ArrayList(u8),
    partial: ?Partial,
    /// A whole message handed out without being copied, freed on the next call.
    delivered: ?[]u8,

    /// Start expecting the peer's first TSN.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (must reclaim, see the file note)
    /// limits - Limits
    /// initial_tsn - u32 (the peer's initial TSN, from its INIT or INIT ACK)
    ///
    /// Return:
    /// - Reassembler
    pub fn init(allocator: std.mem.Allocator, limits: Limits, initial_tsn: u32) Reassembler {
        return .{
            .allocator = allocator,
            .limits = limits,
            .next_tsn = initial_tsn,
            .pending = .empty,
            .pending_bytes = 0,
            .assembling = .empty,
            .partial = null,
            .delivered = null,
        };
    }

    /// Free everything still held.
    ///
    /// Return:
    /// - void
    pub fn deinit(self: *Reassembler) void {
        for (self.pending.items) |item| self.allocator.free(item.payload);

        self.pending.deinit(self.allocator);
        self.assembling.deinit(self.allocator);
        self.releaseDelivered();
    }

    /// The highest TSN delivered with nothing missing before it.
    ///
    /// Note:
    /// - One below the TSN being waited for, so before anything arrives it is one below the
    ///   peer's initial TSN, which is exactly what a first SACK reports.
    ///
    /// Return:
    /// - u32
    pub fn cumulativeTsn(self: Reassembler) u32 {
        return serial.Tsn.previous(self.next_tsn);
    }

    /// How many chunks are waiting on a hole.
    ///
    /// Return:
    /// - usize
    pub fn pendingCount(self: Reassembler) usize {
        return self.pending.items.len;
    }

    /// Take one DATA chunk.
    ///
    /// Note:
    /// - A chunk already delivered, or already held, is ignored rather than refused. Duplicates
    ///   are the sender doing its job after a lost acknowledgement.
    ///
    /// Param:
    /// item - data.Data (payload is copied, so the caller's buffer may be reused)
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSpace if the pending limits are reached, in which case the TSN must be left
    ///   unacknowledged
    /// - error.OutOfMemory
    pub fn accept(self: *Reassembler, item: data.Data) Error!void {
        if (serial.Tsn.lessThan(item.tsn, self.next_tsn)) return;

        const at = self.insertionIndex(item.tsn) orelse return;

        if (self.pending.items.len >= self.limits.max_pending_chunks) return error.ZixNoSpace;
        if (self.pending_bytes + item.payload.len > self.limits.max_pending_bytes) return error.ZixNoSpace;

        const owned = try self.allocator.dupe(u8, item.payload);
        errdefer self.allocator.free(owned);

        try self.pending.insert(self.allocator, at, .{
            .tsn = item.tsn,
            .stream_identifier = item.stream_identifier,
            .stream_sequence = item.stream_sequence,
            .payload_protocol = item.payload_protocol,
            .unordered = item.unordered,
            .beginning = item.beginning,
            .ending = item.ending,
            .payload = owned,
        });

        self.pending_bytes += owned.len;
    }

    /// The next finished message, or null while one is still missing pieces.
    ///
    /// Note:
    /// - Call in a loop. One arriving chunk can complete several messages at once when it fills
    ///   the hole in front of a run that arrived early.
    ///
    /// Return:
    /// - ?Message borrowing memory valid until the next call
    /// - error.ZixProtocolViolation if a fragment cannot belong to the open message
    /// - error.ZixMessageTooLarge if a message grew past the limit
    /// - error.OutOfMemory
    pub fn next(self: *Reassembler) Error!?Message {
        self.releaseDelivered();

        while (self.takeHead()) |head| {
            self.next_tsn = serial.Tsn.next(self.next_tsn);

            if (try self.consume(head)) |message| return message;
        }

        return null;
    }

    /// Move past everything up to and including a TSN the sender abandoned (RFC 3758 3.6).
    ///
    /// Note:
    /// - Anything still held below the new point is dropped, and a message half assembled is
    ///   thrown away. The sender will never send those pieces again.
    ///
    /// Param:
    /// new_cumulative_tsn - u32 (from a FORWARD TSN chunk)
    ///
    /// Return:
    /// - bool, true when a half-assembled message was discarded
    pub fn skipTo(self: *Reassembler, new_cumulative_tsn: u32) bool {
        if (serial.Tsn.lessThan(new_cumulative_tsn, self.next_tsn)) return false;

        self.next_tsn = serial.Tsn.next(new_cumulative_tsn);

        var kept: usize = 0;
        for (self.pending.items) |item| {
            if (serial.Tsn.lessThan(item.tsn, self.next_tsn)) {
                self.pending_bytes -= item.payload.len;
                self.allocator.free(item.payload);

                continue;
            }

            self.pending.items[kept] = item;
            kept += 1;
        }

        self.pending.shrinkRetainingCapacity(kept);

        const had_partial = self.partial != null;
        self.partial = null;
        self.assembling.clearRetainingCapacity();

        return had_partial;
    }

    /// Where a TSN belongs in the pending list, or null if it is already there.
    fn insertionIndex(self: Reassembler, tsn: u32) ?usize {
        const arriving = serial.Tsn.distance(self.next_tsn, tsn);

        for (self.pending.items, 0..) |item, index| {
            const held = serial.Tsn.distance(self.next_tsn, item.tsn);

            if (held == arriving) return null;
            if (held > arriving) return index;
        }

        return self.pending.items.len;
    }

    /// Remove the chunk at the front of the hole, if it has arrived.
    fn takeHead(self: *Reassembler) ?Pending {
        if (self.pending.items.len == 0) return null;
        if (self.pending.items[0].tsn != self.next_tsn) return null;

        const head = self.pending.orderedRemove(0);
        self.pending_bytes -= head.payload.len;

        return head;
    }

    /// Fold one chunk into the message being assembled, and hand the message back if it closed.
    ///
    /// Takes ownership of the chunk's payload on every path: it is freed once folded in, freed
    /// on any error, or moved into `delivered` when the chunk is a whole message.
    fn consume(self: *Reassembler, head: Pending) Error!?Message {
        errdefer self.allocator.free(head.payload);

        if (head.beginning) {
            if (self.partial != null) return error.ZixProtocolViolation;

            // A whole message needs no assembly buffer at all, which is the common case: every
            // message that fits the path MTU arrives as one chunk.
            if (head.ending) {
                self.delivered = head.payload;

                return .{
                    .stream_identifier = head.stream_identifier,
                    .stream_sequence = head.stream_sequence,
                    .payload_protocol = head.payload_protocol,
                    .unordered = head.unordered,
                    .payload = head.payload,
                };
            }

            self.assembling.clearRetainingCapacity();
            self.partial = .{
                .stream_identifier = head.stream_identifier,
                .stream_sequence = head.stream_sequence,
                .payload_protocol = head.payload_protocol,
                .unordered = head.unordered,
            };
        } else {
            const open = self.partial orelse return error.ZixProtocolViolation;

            if (open.stream_identifier != head.stream_identifier) return error.ZixProtocolViolation;
            if (open.unordered != head.unordered) return error.ZixProtocolViolation;
            if (!open.unordered and open.stream_sequence != head.stream_sequence) return error.ZixProtocolViolation;
        }

        if (self.assembling.items.len + head.payload.len > self.limits.max_message_bytes) return error.ZixMessageTooLarge;

        try self.assembling.appendSlice(self.allocator, head.payload);

        // Folded in, so the chunk's own copy is done. Nothing below can fail, which is what
        // keeps this free and the errdefer above from ever both running.
        self.allocator.free(head.payload);

        if (!head.ending) return null;

        const open = self.partial.?;
        self.partial = null;

        return .{
            .stream_identifier = open.stream_identifier,
            .stream_sequence = open.stream_sequence,
            .payload_protocol = open.payload_protocol,
            .unordered = open.unordered,
            .payload = self.assembling.items,
        };
    }

    /// Free the buffer handed out by the previous call, if there was one.
    fn releaseDelivered(self: *Reassembler) void {
        const owned = self.delivered orelse return;

        self.allocator.free(owned);
        self.delivered = null;
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

fn chunkAt(tsn: u32, stream_sequence: u16, payload: []const u8) data.Data {
    return .{
        .tsn = tsn,
        .stream_identifier = 1,
        .stream_sequence = stream_sequence,
        .payload_protocol = 53,
        .payload = payload,
    };
}

fn fragmentAt(tsn: u32, stream_sequence: u16, payload: []const u8, beginning: bool, ending: bool) data.Data {
    var item = chunkAt(tsn, stream_sequence, payload);
    item.beginning = beginning;
    item.ending = ending;

    return item;
}

test "zix sctp: reassembly deliver, a whole message in order comes straight out" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 100);
    defer reassembler.deinit();

    try reassembler.accept(chunkAt(100, 0, "hello"));

    const message = (try reassembler.next()).?;

    try std.testing.expectEqualStrings("hello", message.payload);
    try std.testing.expectEqual(@as(u16, 1), message.stream_identifier);
    try std.testing.expectEqual(@as(u32, 53), message.payload_protocol);
    try std.testing.expect(try reassembler.next() == null);
}

test "zix sctp: reassembly deliver, the cumulative TSN starts one below the peer's first" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 100);
    defer reassembler.deinit();

    try std.testing.expectEqual(@as(u32, 99), reassembler.cumulativeTsn());

    try reassembler.accept(chunkAt(100, 0, "x"));
    _ = try reassembler.next();

    try std.testing.expectEqual(@as(u32, 100), reassembler.cumulativeTsn());
}

test "zix sctp: reassembly deliver, a chunk held for a hole comes out when the hole fills" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 100);
    defer reassembler.deinit();

    try reassembler.accept(chunkAt(101, 1, "second"));

    try std.testing.expect(try reassembler.next() == null);
    try std.testing.expectEqual(@as(usize, 1), reassembler.pendingCount());

    try reassembler.accept(chunkAt(100, 0, "first"));

    try std.testing.expectEqualStrings("first", (try reassembler.next()).?.payload);
    try std.testing.expectEqualStrings("second", (try reassembler.next()).?.payload);
    try std.testing.expect(try reassembler.next() == null);
    try std.testing.expectEqual(@as(usize, 0), reassembler.pendingCount());
}

test "zix sctp: reassembly deliver, a run that arrived backwards comes out forwards" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 10);
    defer reassembler.deinit();

    try reassembler.accept(chunkAt(13, 3, "d"));
    try reassembler.accept(chunkAt(12, 2, "c"));
    try reassembler.accept(chunkAt(11, 1, "b"));
    try reassembler.accept(chunkAt(10, 0, "a"));

    for ([_][]const u8{ "a", "b", "c", "d" }) |expected| {
        try std.testing.expectEqualStrings(expected, (try reassembler.next()).?.payload);
    }
}

test "zix sctp: reassembly deliver, a duplicate chunk is ignored" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 100);
    defer reassembler.deinit();

    try reassembler.accept(chunkAt(101, 1, "held"));
    try reassembler.accept(chunkAt(101, 1, "held again"));

    try std.testing.expectEqual(@as(usize, 1), reassembler.pendingCount());
}

test "zix sctp: reassembly deliver, a chunk already delivered is ignored" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 100);
    defer reassembler.deinit();

    try reassembler.accept(chunkAt(100, 0, "once"));
    _ = try reassembler.next();

    try reassembler.accept(chunkAt(100, 0, "again"));

    try std.testing.expectEqual(@as(usize, 0), reassembler.pendingCount());
    try std.testing.expect(try reassembler.next() == null);
}

test "zix sctp: reassembly fragment, three pieces join back into one message" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 500);
    defer reassembler.deinit();

    try reassembler.accept(fragmentAt(500, 7, "one ", true, false));
    try reassembler.accept(fragmentAt(501, 7, "two ", false, false));
    try reassembler.accept(fragmentAt(502, 7, "three", false, true));

    const message = (try reassembler.next()).?;

    try std.testing.expectEqualStrings("one two three", message.payload);
    try std.testing.expectEqual(@as(u16, 7), message.stream_sequence);
    try std.testing.expect(try reassembler.next() == null);
}

test "zix sctp: reassembly fragment, a message is not delivered until its last piece arrives" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 500);
    defer reassembler.deinit();

    try reassembler.accept(fragmentAt(500, 7, "one ", true, false));

    try std.testing.expect(try reassembler.next() == null);

    try reassembler.accept(fragmentAt(501, 7, "two", false, true));

    try std.testing.expectEqualStrings("one two", (try reassembler.next()).?.payload);
}

test "zix sctp: reassembly fragment, a fragment with no message open is a violation" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 500);
    defer reassembler.deinit();

    try reassembler.accept(fragmentAt(500, 7, "middle", false, false));

    try std.testing.expectError(error.ZixProtocolViolation, reassembler.next());
}

test "zix sctp: reassembly fragment, a second message opening mid-message is a violation" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 500);
    defer reassembler.deinit();

    try reassembler.accept(fragmentAt(500, 7, "open", true, false));
    try reassembler.accept(fragmentAt(501, 8, "open again", true, false));

    // One call drains both chunks, so the violation surfaces on the first.
    try std.testing.expectError(error.ZixProtocolViolation, reassembler.next());
}

test "zix sctp: reassembly fragment, a piece from another stream is a violation" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 500);
    defer reassembler.deinit();

    var stray = fragmentAt(501, 7, "elsewhere", false, true);
    stray.stream_identifier = 2;

    try reassembler.accept(fragmentAt(500, 7, "open", true, false));
    try reassembler.accept(stray);

    try std.testing.expectError(error.ZixProtocolViolation, reassembler.next());
}

test "zix sctp: reassembly fragment, a message past the size limit errors" {
    var reassembler = Reassembler.init(std.testing.allocator, .{ .max_message_bytes = 8 }, 500);
    defer reassembler.deinit();

    try reassembler.accept(fragmentAt(500, 7, "12345", true, false));
    try reassembler.accept(fragmentAt(501, 7, "67890", false, true));

    try std.testing.expectError(error.ZixMessageTooLarge, reassembler.next());
}

test "zix sctp: reassembly unordered, an unordered message is delivered like any other" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 100);
    defer reassembler.deinit();

    var item = chunkAt(100, 0, "loose");
    item.unordered = true;

    try reassembler.accept(item);

    const message = (try reassembler.next()).?;

    try std.testing.expect(message.unordered);
    try std.testing.expectEqualStrings("loose", message.payload);
}

test "zix sctp: reassembly unordered, fragments of an unordered message join without a sequence" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 100);
    defer reassembler.deinit();

    var first = fragmentAt(100, 0, "un", true, false);
    var second = fragmentAt(101, 0, "ordered", false, true);
    first.unordered = true;
    second.unordered = true;

    try reassembler.accept(first);
    try reassembler.accept(second);

    const message = (try reassembler.next()).?;

    try std.testing.expect(message.unordered);
    try std.testing.expectEqualStrings("unordered", message.payload);
}

test "zix sctp: reassembly unordered, mixing ordered and unordered pieces is a violation" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 100);
    defer reassembler.deinit();

    var second = fragmentAt(101, 0, "tail", false, true);
    second.unordered = true;

    try reassembler.accept(fragmentAt(100, 4, "head", true, false));
    try reassembler.accept(second);

    try std.testing.expectError(error.ZixProtocolViolation, reassembler.next());
}

test "zix sctp: reassembly skip, moving past an abandoned message delivers what follows" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 100);
    defer reassembler.deinit();

    try reassembler.accept(chunkAt(103, 3, "after"));

    try std.testing.expect(try reassembler.next() == null);

    // The sender gave up on 100 through 102.
    try std.testing.expect(!reassembler.skipTo(102));

    try std.testing.expectEqualStrings("after", (try reassembler.next()).?.payload);
    try std.testing.expectEqual(@as(u32, 103), reassembler.cumulativeTsn());
}

test "zix sctp: reassembly skip, a half-assembled message is reported as discarded" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 100);
    defer reassembler.deinit();

    try reassembler.accept(fragmentAt(100, 1, "half", true, false));

    try std.testing.expect(try reassembler.next() == null);
    try std.testing.expect(reassembler.skipTo(102));

    // What follows must not be glued onto the message that was thrown away.
    try reassembler.accept(chunkAt(103, 2, "fresh"));
    try std.testing.expectEqualStrings("fresh", (try reassembler.next()).?.payload);
}

test "zix sctp: reassembly skip, chunks below the new point are dropped" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 100);
    defer reassembler.deinit();

    try reassembler.accept(chunkAt(101, 1, "gone"));
    try reassembler.accept(chunkAt(105, 5, "kept"));

    try std.testing.expectEqual(@as(usize, 2), reassembler.pendingCount());

    _ = reassembler.skipTo(104);

    try std.testing.expectEqual(@as(usize, 1), reassembler.pendingCount());
    try std.testing.expectEqualStrings("kept", (try reassembler.next()).?.payload);
}

test "zix sctp: reassembly skip, a point already passed changes nothing" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 100);
    defer reassembler.deinit();

    try reassembler.accept(chunkAt(100, 0, "first"));
    _ = try reassembler.next();

    try std.testing.expect(!reassembler.skipTo(50));
    try std.testing.expectEqual(@as(u32, 100), reassembler.cumulativeTsn());
}

test "zix sctp: reassembly limits, too many held chunks refuses the next one" {
    var reassembler = Reassembler.init(std.testing.allocator, .{ .max_pending_chunks = 2 }, 100);
    defer reassembler.deinit();

    try reassembler.accept(chunkAt(102, 2, "a"));
    try reassembler.accept(chunkAt(103, 3, "b"));

    try std.testing.expectError(error.ZixNoSpace, reassembler.accept(chunkAt(104, 4, "c")));
}

test "zix sctp: reassembly limits, too many held bytes refuses the next one" {
    var reassembler = Reassembler.init(std.testing.allocator, .{ .max_pending_bytes = 8 }, 100);
    defer reassembler.deinit();

    try reassembler.accept(chunkAt(102, 2, "12345"));

    try std.testing.expectError(error.ZixNoSpace, reassembler.accept(chunkAt(103, 3, "6789")));

    // The refused chunk left nothing behind, so a smaller one still fits.
    try reassembler.accept(chunkAt(103, 3, "678"));
    try std.testing.expectEqual(@as(usize, 2), reassembler.pendingCount());
}

test "zix sctp: reassembly limits, held bytes are released as chunks are delivered" {
    var reassembler = Reassembler.init(std.testing.allocator, .{ .max_pending_bytes = 8 }, 100);
    defer reassembler.deinit();

    try reassembler.accept(chunkAt(100, 0, "12345678"));
    _ = try reassembler.next();

    try reassembler.accept(chunkAt(101, 1, "12345678"));
    try std.testing.expectEqual(@as(usize, 1), reassembler.pendingCount());
}

test "zix sctp: reassembly deliver, a run straddling the TSN wrap stays in order" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 0xFFFFFFFE);
    defer reassembler.deinit();

    try reassembler.accept(chunkAt(0, 2, "third"));
    try reassembler.accept(chunkAt(0xFFFFFFFF, 1, "second"));
    try reassembler.accept(chunkAt(0xFFFFFFFE, 0, "first"));

    for ([_][]const u8{ "first", "second", "third" }) |expected| {
        try std.testing.expectEqualStrings(expected, (try reassembler.next()).?.payload);
    }

    try std.testing.expectEqual(@as(u32, 0), reassembler.cumulativeTsn());
}

test "zix sctp: reassembly deliver, a message stays readable until the next call" {
    var reassembler = Reassembler.init(std.testing.allocator, .{}, 100);
    defer reassembler.deinit();

    try reassembler.accept(chunkAt(100, 0, "borrowed"));
    try reassembler.accept(chunkAt(101, 1, "next one"));

    const message = (try reassembler.next()).?;

    // Still valid here, before anything else is asked of the reassembler.
    try std.testing.expectEqualStrings("borrowed", message.payload);

    try std.testing.expectEqualStrings("next one", (try reassembler.next()).?.payload);
}
