//! zix HTTP/3 request-stream reassembly: hold a request the client has not finished sending, so the
//! handler runs once and runs with the whole body.
//!
//! What:
//! - A worker-owned pool of request-stream buffers. QUIC carries a request as STREAM frames, and a
//!   client with a body commonly writes the HEADERS frame in one packet and the DATA frame in the
//!   next, so a request is whole only once the client ends its stream (the FIN bit).
//! - Bytes are inserted at their stream offset and only the contiguous prefix is ever read, so a
//!   retransmitted or reordered frame costs nothing and a gap holds the request back instead of
//!   corrupting it. This is the same shape the CRYPTO stream uses for a ClientHello that spans two
//!   packets (`tls.CryptoStream`).
//!
//! Note:
//! - The pool belongs to the worker, not to a connection: a worker holds 256 eagerly allocated
//!   connections, so a per-connection buffer would be paid 256 times over for something only a
//!   handful of requests use at any moment.
//! - Both dimensions come from the server config (`max_pending_request_streams` and
//!   `max_request_stream_bytes`), so a deployment that accepts large uploads sizes them itself
//!   instead of living with a built-in ceiling.
//! - Nothing here ever reports a cut body as a whole one. A request past the configured stream size
//!   is served with what arrived and reported through `bodyReceived()` / `bodyComplete()` on the
//!   handler's Request. A request that finds no slot at all is refused, and the caller answers 503
//!   rather than running a handler against a body it knows is missing.

const std = @import("std");

const demux = @import("demux.zig");

/// Default request streams one worker assembles at once (`max_pending_request_streams`). Only
/// requests whose client split them across packets ever take a slot, so this is sized for concurrent
/// uploads per worker, not for concurrent requests.
pub const default_pending_streams: usize = 16;

/// Default bytes one pending stream holds (`max_request_stream_bytes`): the HTTP/3 HEADERS frame plus
/// the body. A body past it is delivered cut to what fits and reported short, never as a whole one.
pub const default_stream_bytes: usize = 8192;

/// The smallest a pending stream may be configured to. Below this a HEADERS frame alone can overflow
/// the slot, which would turn every held request into a decode failure rather than a short body.
pub const min_stream_bytes: usize = 1024;

/// How long a stream may go without a new frame before its slot may be taken for another request, in
/// microseconds. A client that opens a request and stops must not hold a slot for the worker's life.
pub const stale_us: u64 = 2_000_000;

/// What one fed frame means for the stream it belongs to.
pub const Feed = union(enum) {
    /// The client ended the stream and its bytes are contiguous: decode and serve it, then release it.
    ready: *PendingStream,
    /// More bytes are expected on this stream. Carries the slot holding it, so the caller can keep
    /// the client's flow-control credit ahead of what it is still sending.
    waiting: *PendingStream,
    /// No slot could be opened for this stream, so nothing is held for it. The caller answers 503:
    /// the request is not run against a body the engine knows it is missing.
    refused,
};

/// One request stream being assembled out of the STREAM frames that carry it.
pub const PendingStream = struct {
    active: bool = false,
    /// The connection the stream belongs to, so the same stream id on two connections never mixes.
    cid: demux.ConnId = .{},
    stream_id: u64 = 0,
    /// Stream bytes at their own offsets, `max_request_stream_bytes` of them. Only the contiguous
    /// prefix is ever read.
    buf: []u8 = &.{},
    /// Which of those bytes have arrived, so a gap holds back everything past it. One bit per byte:
    /// at a byte each, the map would cost as much as the bytes it describes.
    present: std.bit_set.DynamicBitSetUnmanaged = .{},
    /// Length of the contiguous prefix from offset 0.
    covered: usize = 0,
    /// The stream length the client declared by ending the stream, null until that frame arrives.
    final_size: ?u64 = null,
    /// Stream bytes that did not fit the slot. An "at least" number: a retransmit of a frame that
    /// already overflowed counts again, which errs toward reporting a body as short.
    dropped: u64 = 0,
    /// The highest stream offset any frame on this stream has reached, which is what the client's
    /// flow-control limit is measured against (bytes past the slot still count: the client sent them).
    reached: u64 = 0,
    /// The cumulative MAX_STREAM_DATA the client has been granted on this stream. 0 until the first
    /// grant, when it starts from the handshake allowance.
    granted: u64 = 0,
    /// When the last frame for this stream arrived, for reclaiming a slot nobody is finishing.
    last_us: u64 = 0,

    /// Take one frame's bytes at their stream offset, counting whatever does not fit as dropped.
    fn insert(self: *PendingStream, offset: u64, data: []const u8) void {
        if (offset >= self.buf.len) {
            self.dropped += data.len;

            return;
        }

        const start: usize = @intCast(offset);
        const kept = @min(data.len, self.buf.len - start);
        self.dropped += data.len - kept;
        if (kept == 0) return;

        @memcpy(self.buf[start..][0..kept], data[0..kept]);
        self.present.setRangeValue(.{ .start = start, .end = start + kept }, true);

        while (self.covered < self.buf.len and self.present.isSet(self.covered)) self.covered += 1;
    }

    /// Extend the client's per-stream credit before its handshake allowance runs out (RFC 9000 4.2 /
    /// 19.10).
    ///
    /// Note:
    /// - Without this a request larger than the allowance deadlocks: the client blocks waiting for
    ///   credit while the engine waits for the rest of the request, and neither side moves. It is the
    ///   per-stream twin of `Connection.replenishMaxData`.
    /// - Credit is granted against how far the stream has reached, not against how much the slot
    ///   kept. A body past the slot size is still received, counted, and answered short, so the
    ///   client has to be able to finish sending it.
    ///
    /// Param:
    /// window - u64 (bytes of credit to keep available ahead of the client, flight.initial_max_stream_data)
    ///
    /// Return:
    /// - u64 (the new cumulative limit to advertise)
    /// - null when the current grant still has room
    pub fn replenishStreamData(self: *PendingStream, window: u64) ?u64 {
        if (self.granted == 0) self.granted = window;

        if (self.reached + window / 2 < self.granted) return null;

        self.granted = self.reached + window;

        return self.granted;
    }

    /// Whether the client has ended the stream and every byte this slot can hold has arrived.
    fn complete(self: *const PendingStream) bool {
        const final = self.final_size orelse return false;
        const wanted: u64 = @min(final, @as(u64, self.buf.len));

        return self.covered >= wanted;
    }

    /// Clear back to the idle state, keeping the buffers. The byte buffer is left as it is: `present`
    /// is what says which of it means anything.
    fn clear(self: *PendingStream) void {
        self.active = false;
        self.cid = .{};
        self.stream_id = 0;
        self.present.unsetAll();
        self.covered = 0;
        self.final_size = null;
        self.dropped = 0;
        self.reached = 0;
        self.granted = 0;
        self.last_us = 0;
    }

    /// The assembled stream bytes: the contiguous prefix, which is the whole request stream unless the
    /// body ran past the slot size.
    pub fn assembled(self: *const PendingStream) []const u8 {
        return self.buf[0..self.covered];
    }

    /// The same bytes to write into. The decode uses this to join a body the client split across
    /// several DATA frames, which it can only do in a buffer the worker owns.
    pub fn assembledMutable(self: *PendingStream) []u8 {
        return self.buf[0..self.covered];
    }
};

/// The worker's pool of request streams being assembled.
pub const Pool = struct {
    slots: []PendingStream = &.{},

    /// Open a pool of `streams` slots holding `stream_bytes` each.
    ///
    /// Note:
    /// - `streams` of 0 opens a pool that holds nothing: a request the client split across packets is
    ///   then refused rather than held. That is a valid deployment choice for a server whose routes
    ///   take no request body, and it costs no memory.
    /// - `stream_bytes` is raised to `min_stream_bytes` when smaller, so a slot always has room for a
    ///   HEADERS frame.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (owns the slots for the pool's life)
    /// streams - usize (`max_pending_request_streams`)
    /// stream_bytes - usize (`max_request_stream_bytes`)
    ///
    /// Return:
    /// - Pool (the caller must deinit it with the same allocator)
    /// - error.OutOfMemory
    pub fn init(allocator: std.mem.Allocator, streams: usize, stream_bytes: usize) !Pool {
        if (streams == 0) return .{};

        const bytes = @max(stream_bytes, min_stream_bytes);

        const slots = try allocator.alloc(PendingStream, streams);
        errdefer allocator.free(slots);

        var opened: usize = 0;
        errdefer for (slots[0..opened]) |*slot| {
            allocator.free(slot.buf);
            slot.present.deinit(allocator);
        };

        while (opened < slots.len) : (opened += 1) {
            const buf = try allocator.alloc(u8, bytes);
            errdefer allocator.free(buf);

            slots[opened] = .{
                .buf = buf,
                .present = try std.bit_set.DynamicBitSetUnmanaged.initEmpty(allocator, bytes),
            };
        }

        return .{ .slots = slots };
    }

    /// Give every slot back. Safe on a pool that was never opened.
    pub fn deinit(self: *Pool, allocator: std.mem.Allocator) void {
        for (self.slots) |*slot| {
            allocator.free(slot.buf);
            slot.present.deinit(allocator);
        }

        allocator.free(self.slots);
        self.slots = &.{};
    }

    /// Take one client request-stream frame.
    ///
    /// Param:
    /// now_us - u64 (monotonic microseconds, passed in so the pool needs no clock of its own)
    /// cid - *const demux.ConnId (the connection the stream belongs to)
    /// stream_id - u64
    /// offset - u64 (where these bytes sit in the stream)
    /// data - []const u8 (the stream bytes)
    /// fin - bool (whether this frame ends the stream)
    ///
    /// Return:
    /// - Feed (ready with the stream, waiting, or refused)
    pub fn feed(self: *Pool, now_us: u64, cid: *const demux.ConnId, stream_id: u64, offset: u64, data: []const u8, fin: bool) Feed {
        // A frame at offset 0 carries the start of the request, so it is the one worth taking a slot
        // from a stream that has assembled nothing.
        const carries_head = offset == 0;

        const slot = self.find(cid, stream_id) orelse self.open(now_us, cid, stream_id, carries_head) orelse return .refused;

        slot.last_us = now_us;
        slot.reached = @max(slot.reached, offset + data.len);
        slot.insert(offset, data);
        if (fin) slot.final_size = offset + data.len;

        return if (slot.complete()) .{ .ready = slot } else .{ .waiting = slot };
    }

    /// Give a served stream's slot back.
    pub fn release(self: *Pool, slot: *PendingStream) void {
        _ = self;
        slot.clear();
    }

    /// The slot already assembling this stream, if any.
    fn find(self: *Pool, cid: *const demux.ConnId, stream_id: u64) ?*PendingStream {
        for (self.slots) |*slot| {
            if (slot.active and slot.stream_id == stream_id and slot.cid.eql(cid)) return slot;
        }

        return null;
    }

    /// A slot for a stream not yet held, preferring in order: a free slot, the oldest slot nothing has
    /// fed for `stale_us`, and (only for a frame that carries the start of a request) the oldest slot
    /// holding nothing usable yet.
    ///
    /// Note:
    /// - That last preference is what keeps a busy pool serving. Once a request is refused its client
    ///   keeps sending, and those body-only frames open slots that can never complete on their own.
    ///   Without it a burst of refusals fills every slot with orphan fragments and the pool stops
    ///   accepting the request heads that would have used them.
    ///
    /// Return:
    /// - *PendingStream (claimed for this stream, cleared and stamped)
    /// - null when every slot is busy with a stream still making progress
    fn open(self: *Pool, now_us: u64, cid: *const demux.ConnId, stream_id: u64, carries_head: bool) ?*PendingStream {
        var stale: ?*PendingStream = null;
        var orphan: ?*PendingStream = null;

        for (self.slots) |*slot| {
            if (!slot.active) return claim(slot, cid, stream_id);

            if (now_us -| slot.last_us >= stale_us) {
                if (stale == null or slot.last_us < stale.?.last_us) stale = slot;

                continue;
            }

            if (carries_head and slot.covered == 0) {
                if (orphan == null or slot.last_us < orphan.?.last_us) orphan = slot;
            }
        }

        const slot = stale orelse orphan orelse return null;

        return claim(slot, cid, stream_id);
    }

    /// Hand a slot to a stream: cleared of whatever it held, stamped with the stream it now assembles.
    fn claim(slot: *PendingStream, cid: *const demux.ConnId, stream_id: u64) *PendingStream {
        slot.clear();
        slot.active = true;
        slot.cid = cid.*;
        slot.stream_id = stream_id;

        return slot;
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn testCid(tag: u8) demux.ConnId {
    return demux.ConnId.fromSlice(&[_]u8{ tag, 1, 2, 3, 4, 5, 6, 7 });
}

fn testPool(streams: usize) !Pool {
    return Pool.init(std.testing.allocator, streams, default_stream_bytes);
}

test "zix http3: reassembly joins a request whose body arrives in a later packet" {
    var pool = try testPool(default_pending_streams);
    defer pool.deinit(std.testing.allocator);

    const cid = testCid(0xaa);

    // The head, with the stream left open: nothing to serve yet.
    switch (pool.feed(1_000, &cid, 0, 0, "HEAD", false)) {
        .waiting => {},
        else => return error.TestUnexpectedResult,
    }

    // The body, ending the stream: now the whole thing is in hand.
    const fed = pool.feed(2_000, &cid, 0, 4, "BODY", true);
    const slot = switch (fed) {
        .ready => |ready| ready,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqualStrings("HEADBODY", slot.assembled());
    try std.testing.expectEqual(@as(u64, 0), slot.dropped);

    // Released, the slot serves the next request.
    pool.release(slot);
    try std.testing.expect(!slot.active);
}

test "zix http3: reassembly holds bytes past a gap until the gap is filled" {
    var pool = try testPool(default_pending_streams);
    defer pool.deinit(std.testing.allocator);

    const cid = testCid(0xbb);

    // The body overtakes the head, which a reordered pair of packets does. The stream ends here, but
    // its first four bytes are missing, so it is not servable yet.
    switch (pool.feed(1_000, &cid, 0, 4, "BODY", true)) {
        .waiting => {},
        else => return error.TestUnexpectedResult,
    }

    const slot = switch (pool.feed(2_000, &cid, 0, 0, "HEAD", false)) {
        .ready => |ready| ready,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqualStrings("HEADBODY", slot.assembled());
}

test "zix http3: reassembly takes a retransmitted frame without doubling it" {
    var pool = try testPool(default_pending_streams);
    defer pool.deinit(std.testing.allocator);

    const cid = testCid(0xcc);

    _ = pool.feed(1_000, &cid, 0, 0, "HEAD", false);
    _ = pool.feed(1_100, &cid, 0, 0, "HEAD", false);

    const slot = switch (pool.feed(1_200, &cid, 0, 4, "BODY", true)) {
        .ready => |ready| ready,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqualStrings("HEADBODY", slot.assembled());
}

test "zix http3: reassembly keeps two connections using the same stream id apart" {
    var pool = try testPool(default_pending_streams);
    defer pool.deinit(std.testing.allocator);

    const first = testCid(0x01);
    const second = testCid(0x02);

    _ = pool.feed(1_000, &first, 0, 0, "AAAA", false);
    _ = pool.feed(1_000, &second, 0, 0, "BBBB", false);

    const first_slot = switch (pool.feed(1_100, &first, 0, 4, "1111", true)) {
        .ready => |ready| ready,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("AAAA1111", first_slot.assembled());

    const second_slot = switch (pool.feed(1_100, &second, 0, 4, "2222", true)) {
        .ready => |ready| ready,
        else => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqualStrings("BBBB2222", second_slot.assembled());
}

test "zix http3: reassembly cuts a body past the configured stream size and says it did" {
    var pool = try testPool(default_pending_streams);
    defer pool.deinit(std.testing.allocator);

    const cid = testCid(0xdd);

    const head = "H";
    var body: [default_stream_bytes]u8 = @splat('z');

    _ = pool.feed(1_000, &cid, 0, 0, head, false);
    const slot = switch (pool.feed(1_100, &cid, 0, head.len, &body, true)) {
        .ready => |ready| ready,
        else => return error.TestUnexpectedResult,
    };

    // The stream is served rather than left hanging, cut to the slot, with the overflow counted so
    // the request can report a short body.
    try std.testing.expectEqual(@as(usize, default_stream_bytes), slot.assembled().len);
    try std.testing.expectEqual(@as(u64, head.len), slot.dropped);
}

test "zix http3: reassembly sizes a slot from the config rather than a built-in ceiling" {
    // The same overflow, on a pool configured to hold four times the default. What used to be a cut
    // body is now a whole one, which is the point of the knob.
    var pool = try Pool.init(std.testing.allocator, 2, default_stream_bytes * 4);
    defer pool.deinit(std.testing.allocator);

    const cid = testCid(0xd1);

    var body: [default_stream_bytes * 2]u8 = @splat('z');

    _ = pool.feed(1_000, &cid, 0, 0, "H", false);
    const slot = switch (pool.feed(1_100, &cid, 0, 1, &body, true)) {
        .ready => |ready| ready,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqual(@as(usize, 1 + body.len), slot.assembled().len);
    try std.testing.expectEqual(@as(u64, 0), slot.dropped);
}

test "zix http3: reassembly raises a stream size below the minimum instead of taking it" {
    // A slot smaller than a HEADERS frame would turn every held request into a decode failure, so a
    // configured size under the floor is raised to it.
    var pool = try Pool.init(std.testing.allocator, 1, 8);
    defer pool.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, min_stream_bytes), pool.slots[0].buf.len);
}

test "zix http3: reassembly holds nothing when the config asks for no pending streams" {
    var pool = try Pool.init(std.testing.allocator, 0, default_stream_bytes);
    defer pool.deinit(std.testing.allocator);

    const cid = testCid(0xd2);

    // Nothing is held, so the caller answers rather than waiting for a completion that never comes.
    switch (pool.feed(1_000, &cid, 0, 0, "HEAD", false)) {
        .refused => {},
        else => return error.TestUnexpectedResult,
    }
}

test "zix http3: reassembly refuses a new stream while every slot is still moving" {
    var pool = try testPool(4);
    defer pool.deinit(std.testing.allocator);

    const cid = testCid(0xee);

    // Every slot busy with a stream that has assembled a head and is still moving.
    var stream_id: u64 = 0;
    while (stream_id < 4 * 4) : (stream_id += 4) {
        switch (pool.feed(1_000, &cid, stream_id, 0, "HEAD", false)) {
            .waiting => {},
            else => return error.TestUnexpectedResult,
        }
    }

    // One more: refused rather than evicting a request another client is still sending. The caller
    // answers 503, so neither client is left without a response.
    switch (pool.feed(1_000, &cid, stream_id, 0, "HEAD", false)) {
        .refused => {},
        else => return error.TestUnexpectedResult,
    }

    // Once the held streams have gone quiet for stale_us, the oldest slot is taken.
    switch (pool.feed(1_000 + stale_us, &cid, stream_id, 0, "HEAD", false)) {
        .waiting => {},
        else => return error.TestUnexpectedResult,
    }
}

test "zix http3: reassembly extends a held stream's credit before the client runs out of it" {
    // The deadlock this prevents: the handshake grants the client a fixed per-stream budget, and a
    // request larger than it stops halfway. The client waits for credit, the engine waits for the
    // rest of the request, and nothing moves until the connection times out.
    const window: u64 = 1024;

    var pool = try testPool(1);
    defer pool.deinit(std.testing.allocator);

    const cid = testCid(0xf0);
    var body: [256]u8 = @splat('z');

    const slot = switch (pool.feed(1_000, &cid, 0, 0, &body, false)) {
        .waiting => |waiting| waiting,
        else => return error.TestUnexpectedResult,
    };

    // Well inside the budget: nothing to grant, so no frame rides the reply.
    try std.testing.expect(slot.replenishStreamData(window) == null);

    // Past half the window, the grant moves out ahead of where the stream has reached.
    _ = pool.feed(1_100, &cid, 0, body.len, &body, false);
    _ = pool.feed(1_200, &cid, 0, body.len * 2, &body, false);
    const granted = slot.replenishStreamData(window).?;

    try std.testing.expectEqual(@as(u64, body.len * 3 + window), granted);
    try std.testing.expect(granted > slot.reached);
}

test "zix http3: reassembly counts credit against what the client sent, not what the slot kept" {
    // A body past the slot is still received and still has to be finishable, so the credit tracks the
    // stream offset the client reached rather than the bytes that fit.
    var pool = try Pool.init(std.testing.allocator, 1, min_stream_bytes);
    defer pool.deinit(std.testing.allocator);

    const cid = testCid(0xf1);
    var body: [min_stream_bytes]u8 = @splat('z');

    _ = pool.feed(1_000, &cid, 0, 0, &body, false);
    const slot = switch (pool.feed(1_100, &cid, 0, body.len, &body, false)) {
        .waiting => |waiting| waiting,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqual(@as(usize, min_stream_bytes), slot.covered);
    try std.testing.expectEqual(@as(u64, min_stream_bytes * 2), slot.reached);
    try std.testing.expectEqual(@as(u64, min_stream_bytes), slot.dropped);
}

test "zix http3: reassembly gives a request head a slot an orphan fragment is sitting on" {
    // What a burst of refusals leaves behind: clients whose heads were refused keep sending bodies,
    // and those body-only frames hold slots that can never complete. A fresh head takes one back
    // rather than being refused behind fragments nobody is waiting on.
    var pool = try testPool(2);
    defer pool.deinit(std.testing.allocator);

    const cid = testCid(0xef);

    var stream_id: u64 = 0;
    while (stream_id < 2 * 4) : (stream_id += 4) {
        switch (pool.feed(1_000, &cid, stream_id, 64, "BODY", true)) {
            .waiting => {},
            else => return error.TestUnexpectedResult,
        }
    }

    switch (pool.feed(1_100, &cid, stream_id, 0, "HEAD", false)) {
        .waiting => {},
        else => return error.TestUnexpectedResult,
    }

    // The oldest orphan gave up its slot, and the head is the one being assembled now.
    const held = pool.find(&cid, stream_id).?;
    try std.testing.expectEqualStrings("HEAD", held.assembled());
}
