//! zixer h3 streams: per-stream receive assembly and send buffering (rfc 9000 2)

const std = @import("std");

/// Concurrent request streams one connection may hold. Also the stream limit
/// the handshake advertises, so a client never opens more than there are slots.
pub const MAX_STREAMS: usize = 16;

/// Out-of-order fragments one receive stream tracks. QUIC may deliver STREAM
/// frames in any order, and a gap holds bytes back until it fills. Past this
/// the fragment is dropped and the peer retransmits it.
pub const MAX_RANGES: usize = 16;

/// Most bytes one request stream accepts, head plus body. A longer request is
/// refused with 413, never truncated.
pub const MAX_RECV_BYTES: usize = 1024 * 1024;

pub const Error = error{
    /// The stream grew past MAX_RECV_BYTES.
    ZixerStreamTooLarge,
    /// More out-of-order fragments than MAX_RANGES.
    ZixerTooManyGaps,
    /// The peer changed bytes it had already sent, or moved the fin.
    ZixerInconsistent,
    OutOfMemory,
};

/// A half-open byte range of one stream, in absolute stream offsets.
pub const Range = struct { start: u64, end: u64 };

/// One client stream being reassembled. Bytes live at their absolute offset,
/// so a gap simply stays unread until the missing fragment arrives.
pub const RecvStream = struct {
    active: bool = false,
    stream_id: u64 = 0,
    data: std.ArrayList(u8) = .empty,
    ranges: [MAX_RANGES]Range = @splat(.{ .start = 0, .end = 0 }),
    range_len: usize = 0,
    /// Total stream length, known once a STREAM frame carried the fin bit.
    fin_offset: ?u64 = null,
    /// Bytes already handed to the frame parser.
    consumed: usize = 0,
    /// The flow control limit granted to the peer on this stream, raised by
    /// MAX_STREAM_DATA as the peer's bytes are consumed (rfc 9000 4.1).
    granted: u64 = 0,

    /// Insert one STREAM frame's bytes at their offset. Duplicate bytes are
    /// idempotent, which is what a retransmission delivers.
    pub fn insert(recv: *RecvStream, allocator: std.mem.Allocator, offset: u64, bytes: []const u8, fin: bool) Error!void {
        const end = offset + bytes.len;
        if (end > MAX_RECV_BYTES) return error.ZixerStreamTooLarge;

        if (fin) {
            if (recv.fin_offset) |known| {
                if (known != end) return error.ZixerInconsistent;
            }
            recv.fin_offset = end;
        }
        if (recv.fin_offset) |known| {
            if (end > known) return error.ZixerInconsistent;
        }

        if (bytes.len == 0) return;

        if (recv.data.items.len < end) try recv.data.resize(allocator, @intCast(end));
        @memcpy(recv.data.items[@intCast(offset)..][0..bytes.len], bytes);

        try recv.addRange(.{ .start = offset, .end = end });
    }

    /// Merge one received range into the tracked set.
    fn addRange(recv: *RecvStream, incoming: Range) Error!void {
        var merged = incoming;

        // Absorb every range that touches or overlaps the new one, then append
        // the union, so the set stays minimal. Order does not matter: the
        // gapless prefix is the one range that starts at 0.
        var write: usize = 0;
        for (recv.ranges[0..recv.range_len]) |existing| {
            if (existing.end < merged.start or existing.start > merged.end) {
                recv.ranges[write] = existing;
                write += 1;
                continue;
            }

            merged.start = @min(merged.start, existing.start);
            merged.end = @max(merged.end, existing.end);
        }

        if (write >= MAX_RANGES) return error.ZixerTooManyGaps;

        recv.ranges[write] = merged;
        recv.range_len = write + 1;
    }

    /// The end offset of the gapless prefix from 0.
    pub fn contiguous(recv: *const RecvStream) u64 {
        for (recv.ranges[0..recv.range_len]) |range| {
            if (range.start == 0) return range.end;
        }

        return 0;
    }

    /// Whether every byte through the fin has arrived.
    pub fn complete(recv: *const RecvStream) bool {
        const fin = recv.fin_offset orelse return false;

        return recv.contiguous() >= fin;
    }

    /// The bytes the frame parser may read now: the gapless prefix past what it
    /// has already taken.
    pub fn readable(recv: *const RecvStream) []const u8 {
        const end: usize = @intCast(recv.contiguous());
        if (end <= recv.consumed) return &.{};

        return recv.data.items[recv.consumed..end];
    }

    /// Mark bytes of the readable window as parsed.
    pub fn take(recv: *RecvStream, count: usize) void {
        recv.consumed += count;
    }

    /// Total bytes received on this stream, for connection-level flow control.
    pub fn received(recv: *const RecvStream) u64 {
        var total: u64 = 0;
        for (recv.ranges[0..recv.range_len]) |range| total += range.end - range.start;

        return total;
    }

    /// Release the buffer and reset the slot.
    pub fn deinit(recv: *RecvStream, allocator: std.mem.Allocator) void {
        recv.data.deinit(allocator);
        recv.* = .{};
    }
};

/// One server response being written to a client stream. Bytes are appended as
/// the upstream produces them and released once they can no longer be needed
/// for a retransmission, so a long response never buffers more than its
/// unacknowledged window.
pub const SendStream = struct {
    active: bool = false,
    stream_id: u64 = 0,
    pending: std.ArrayList(u8) = .empty,
    /// Absolute stream offset of pending[0].
    base: u64 = 0,
    /// Next offset to put on the wire.
    sent: u64 = 0,
    /// Highest offset ever sent, which is what connection flow control charges.
    high_water: u64 = 0,
    /// Total stream length, set when the response body is finished.
    fin_offset: ?u64 = null,
    /// The client's per-stream flow control limit, raised by MAX_STREAM_DATA.
    stream_limit: u64 = 0,
    /// Bytes sent and neither acknowledged nor declared lost.
    unacked: usize = 0,
    /// Whether the fin bit has gone out. A response can be fully buffered and
    /// fully written and still owe the client its stream end.
    fin_sent: bool = false,

    /// Append response bytes at the end of the stream.
    pub fn append(send: *SendStream, allocator: std.mem.Allocator, bytes: []const u8) Error!void {
        if (send.fin_offset != null) return error.ZixerInconsistent;

        try send.pending.appendSlice(allocator, bytes);
    }

    /// Mark the response complete: the stream ends at what has been appended.
    pub fn finish(send: *SendStream) void {
        if (send.fin_offset == null) send.fin_offset = send.buffered();
    }

    /// The end offset of the appended bytes.
    pub fn buffered(send: *const SendStream) u64 {
        return send.base + send.pending.items.len;
    }

    /// The bytes at `offset`, at most `max` of them, or empty when that offset
    /// has been released or nothing is buffered there.
    pub fn chunk(send: *const SendStream, offset: u64, max: usize) []const u8 {
        if (offset < send.base or offset >= send.buffered()) return &.{};

        const from: usize = @intCast(offset - send.base);
        const available = send.pending.items.len - from;

        return send.pending.items[from..][0..@min(max, available)];
    }

    /// Rewind the send cursor to resend a lost range. A rewind past the end
    /// takes the fin with it, so the resend carries it again.
    pub fn rewind(send: *SendStream, offset: u64) void {
        if (offset < send.base or offset >= send.sent) return;

        send.sent = offset;
        if (send.fin_offset) |fin| {
            if (offset < fin) send.fin_sent = false;
        }
    }

    /// Drop buffered bytes below `offset`, which can no longer be resent.
    pub fn releaseTo(send: *SendStream, offset: u64) void {
        if (offset <= send.base) return;

        const drop: usize = @intCast(@min(offset - send.base, send.pending.items.len));
        if (drop == 0) return;

        std.mem.copyForwards(u8, send.pending.items[0 .. send.pending.items.len - drop], send.pending.items[drop..]);
        send.pending.shrinkRetainingCapacity(send.pending.items.len - drop);
        send.base += drop;
    }

    /// Whether the whole stream, fin included, has been put on the wire.
    pub fn fullySent(send: *const SendStream) bool {
        return send.fin_sent;
    }

    /// Whether the stream end still owes the client a fin bit.
    pub fn finPending(send: *const SendStream) bool {
        const fin = send.fin_offset orelse return false;

        return !send.fin_sent and send.sent >= fin;
    }

    /// Whether the stream is done: fully sent and fully acknowledged.
    pub fn retired(send: *const SendStream) bool {
        return send.fullySent() and send.unacked == 0;
    }

    /// Release the buffer and reset the slot.
    pub fn deinit(send: *SendStream, allocator: std.mem.Allocator) void {
        send.pending.deinit(allocator);
        send.* = .{};
    }
};

/// Fixed-slot stream tables for one connection.
pub const Table = struct {
    recv: [MAX_STREAMS]RecvStream = @splat(.{}),
    send: [MAX_STREAMS]SendStream = @splat(.{}),

    /// The receive slot for this stream id, claiming a free one when new.
    pub fn recvFor(table: *Table, stream_id: u64) ?*RecvStream {
        for (&table.recv) |*slot| {
            if (slot.active and slot.stream_id == stream_id) return slot;
        }

        for (&table.recv) |*slot| {
            if (slot.active) continue;

            slot.* = .{ .active = true, .stream_id = stream_id };
            return slot;
        }

        return null;
    }

    /// The receive slot for this stream id, without claiming one.
    pub fn findRecv(table: *Table, stream_id: u64) ?*RecvStream {
        for (&table.recv) |*slot| {
            if (slot.active and slot.stream_id == stream_id) return slot;
        }

        return null;
    }

    /// The send slot for this stream id, claiming a free one when new.
    pub fn sendFor(table: *Table, stream_id: u64) ?*SendStream {
        for (&table.send) |*slot| {
            if (slot.active and slot.stream_id == stream_id) return slot;
        }

        for (&table.send) |*slot| {
            if (slot.active) continue;

            slot.* = .{ .active = true, .stream_id = stream_id };
            return slot;
        }

        return null;
    }

    /// The send slot for this stream id, without claiming one.
    pub fn findSend(table: *Table, stream_id: u64) ?*SendStream {
        for (&table.send) |*slot| {
            if (slot.active and slot.stream_id == stream_id) return slot;
        }

        return null;
    }

    /// Release every slot.
    pub fn deinit(table: *Table, allocator: std.mem.Allocator) void {
        for (&table.recv) |*slot| {
            if (slot.active) slot.deinit(allocator);
        }
        for (&table.send) |*slot| {
            if (slot.active) slot.deinit(allocator);
        }
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "zix zixer: h3 streams, in order fragments read back whole" {
    var recv = RecvStream{ .active = true, .stream_id = 0 };
    defer recv.deinit(testing.allocator);

    try recv.insert(testing.allocator, 0, "hello ", false);
    try recv.insert(testing.allocator, 6, "world", true);

    try testing.expectEqual(@as(u64, 11), recv.contiguous());
    try testing.expect(recv.complete());
    try testing.expectEqualStrings("hello world", recv.readable());
}

test "zix zixer: h3 streams, a gap holds bytes back until it fills" {
    var recv = RecvStream{ .active = true, .stream_id = 4 };
    defer recv.deinit(testing.allocator);

    try recv.insert(testing.allocator, 6, "world", true);
    try testing.expectEqual(@as(u64, 0), recv.contiguous());
    try testing.expectEqual(@as(usize, 0), recv.readable().len);
    try testing.expect(!recv.complete());

    try recv.insert(testing.allocator, 0, "hello ", false);
    try testing.expectEqualStrings("hello world", recv.readable());
    try testing.expect(recv.complete());
}

test "zix zixer: h3 streams, a retransmitted fragment is idempotent" {
    var recv = RecvStream{ .active = true, .stream_id = 0 };
    defer recv.deinit(testing.allocator);

    try recv.insert(testing.allocator, 0, "abcd", false);
    try recv.insert(testing.allocator, 2, "cdef", false);
    try recv.insert(testing.allocator, 0, "abcd", false);

    try testing.expectEqual(@as(u64, 6), recv.contiguous());
    try testing.expectEqualStrings("abcdef", recv.readable());
    try testing.expectEqual(@as(usize, 1), recv.range_len);
}

test "zix zixer: h3 streams, take advances the parser window" {
    var recv = RecvStream{ .active = true, .stream_id = 0 };
    defer recv.deinit(testing.allocator);

    try recv.insert(testing.allocator, 0, "framebody", true);
    recv.take(5);

    try testing.expectEqualStrings("body", recv.readable());
    try testing.expectEqual(@as(u64, 9), recv.received());
}

test "zix zixer: h3 streams, a stream past the bound is refused" {
    var recv = RecvStream{ .active = true, .stream_id = 0 };
    defer recv.deinit(testing.allocator);

    try testing.expectError(error.ZixerStreamTooLarge, recv.insert(testing.allocator, MAX_RECV_BYTES, "x", false));
}

test "zix zixer: h3 streams, a moved fin is inconsistent" {
    var recv = RecvStream{ .active = true, .stream_id = 0 };
    defer recv.deinit(testing.allocator);

    try recv.insert(testing.allocator, 0, "abc", true);
    try testing.expectError(error.ZixerInconsistent, recv.insert(testing.allocator, 3, "de", true));
}

test "zix zixer: h3 streams, send buffers append and chunk by offset" {
    var send = SendStream{ .active = true, .stream_id = 0 };
    defer send.deinit(testing.allocator);

    try send.append(testing.allocator, "0123456789");
    try testing.expectEqual(@as(u64, 10), send.buffered());
    try testing.expectEqualStrings("01234", send.chunk(0, 5));
    try testing.expectEqualStrings("56789", send.chunk(5, 99));
    try testing.expectEqual(@as(usize, 0), send.chunk(10, 4).len);
}

test "zix zixer: h3 streams, releasing drops the acknowledged prefix" {
    var send = SendStream{ .active = true, .stream_id = 0 };
    defer send.deinit(testing.allocator);

    try send.append(testing.allocator, "0123456789");
    send.sent = 10;
    send.releaseTo(6);

    try testing.expectEqual(@as(u64, 6), send.base);
    try testing.expectEqualStrings("6789", send.chunk(6, 99));
    try testing.expectEqual(@as(usize, 0), send.chunk(0, 4).len);

    // A release below the base is a no-op, a duplicate ack cannot rewind it.
    send.releaseTo(2);
    try testing.expectEqual(@as(u64, 6), send.base);
}

test "zix zixer: h3 streams, rewinding resends from a lost offset" {
    var send = SendStream{ .active = true, .stream_id = 0 };
    defer send.deinit(testing.allocator);

    try send.append(testing.allocator, "0123456789");
    send.sent = 10;
    send.high_water = 10;

    send.fin_offset = 10;
    send.fin_sent = true;

    send.rewind(4);
    try testing.expectEqual(@as(u64, 4), send.sent);
    try testing.expectEqual(@as(u64, 10), send.high_water);
    try testing.expect(!send.fin_sent);

    // A rewind past the cursor never moves it forward.
    send.rewind(8);
    try testing.expectEqual(@as(u64, 4), send.sent);
}

test "zix zixer: h3 streams, a stream retires only once sent and acknowledged" {
    var send = SendStream{ .active = true, .stream_id = 0 };
    defer send.deinit(testing.allocator);

    try send.append(testing.allocator, "body");
    try testing.expect(!send.fullySent());

    send.finish();
    try testing.expectEqual(@as(?u64, 4), send.fin_offset);
    try testing.expect(!send.fullySent());

    send.sent = 4;
    send.unacked = 4;
    try testing.expect(!send.fullySent());
    try testing.expect(send.finPending());

    send.fin_sent = true;
    try testing.expect(send.fullySent());
    try testing.expect(!send.retired());

    send.unacked = 0;
    try testing.expect(send.retired());
}

test "zix zixer: h3 streams, the table claims and finds slots by id" {
    var table = Table{};
    defer table.deinit(testing.allocator);

    const first = table.recvFor(0).?;
    try testing.expectEqual(@as(u64, 0), first.stream_id);
    try testing.expectEqual(first, table.recvFor(0).?);
    try testing.expect(table.findRecv(4) == null);

    const second = table.recvFor(4).?;
    try testing.expect(first != second);

    const out = table.sendFor(0).?;
    try testing.expectEqual(out, table.findSend(0).?);
    try testing.expect(table.findSend(8) == null);
}

test "zix zixer: h3 streams, the table refuses past its slot count" {
    var table = Table{};
    defer table.deinit(testing.allocator);

    for (0..MAX_STREAMS) |index| {
        try testing.expect(table.recvFor(@as(u64, index) * 4) != null);
    }

    try testing.expect(table.recvFor(MAX_STREAMS * 4) == null);

    table.recv[0].deinit(testing.allocator);
    try testing.expect(table.recvFor(MAX_STREAMS * 4) != null);
}
