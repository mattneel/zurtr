//! zix WebTransport worker pool: the sessions, data streams, and pre-session stream buffers one worker
//! owns.
//!
//! What:
//! - The slots a WebTransport session needs, allocated once when the worker starts and recycled as
//!   sessions end: a `session.Session` per concurrent session, a `session.Stream` per data stream, and
//!   the send buffer each stream writes into.
//! - The orphan table: a data stream can arrive before the CONNECT that establishes its session (a
//!   client is free to send the handshake and the first streams in one flight, 4.6), so the worker
//!   holds a bounded number of such streams until the session appears, and rejects the rest with
//!   WT_BUFFERED_STREAM_REJECTED.
//! - Fixed capacity, no allocation on the receive path, and no pointer that outlives its slot: the
//!   pool returns null instead of growing, and the caller decides what a full pool means (a refused
//!   stream, a dropped datagram).
//!
//! Note:
//! - The pool belongs to the worker, not to a connection, for the same reason the HTTP/3 request
//!   reassembly pool does: a worker owns up to `max_connections` eagerly allocated connections, so a
//!   per-connection buffer would be paid hundreds of times over for something only a handful of
//!   sessions use at any moment.
//! - The send buffers are one contiguous allocation, so a worker's WebTransport memory cost is exactly
//!   `streams * stream_buffer_bytes`, paid once and independent of the session count.

const std = @import("std");

const session = @import("session.zig");
const stream_header = @import("stream_header.zig");

/// The compile-time ceilings a runtime configuration may not exceed. The connection-side session and
/// stream tables (connection.zig) are sized from these, so a configuration above them is rejected when
/// the server validates its config rather than silently truncated here.
pub const maxima = struct {
    /// Sessions one worker may hold at once.
    pub const sessions: usize = 64;
    /// Data streams one worker may hold at once.
    pub const streams: usize = 256;
    /// Pre-session streams one worker may buffer at once.
    pub const orphans: usize = 32;
};

/// The pool's sizing, taken from the server's WebTransport config.
pub const Config = struct {
    /// Session slots per worker. Each slot holds one session's state (a few hundred bytes plus the
    /// close-message buffer).
    sessions: usize = 16,
    /// Data stream slots per worker.
    streams: usize = 64,
    /// Send buffer per data stream slot, in bytes. This is both the application's write window and the
    /// bytes a lost packet can still be resent from, so it must cover the in-flight window a stream
    /// keeps: 16 KiB covers a path-MTU-sized flight several times over.
    stream_buffer_bytes: usize = 16 * 1024,
    /// Pre-session streams buffered per worker (4.6).
    orphans: usize = 8,
    /// Bytes buffered per pre-session stream. A client that opens a stream before its session is
    /// established typically sends a short first write; a longer one is refused rather than held.
    orphan_bytes: usize = 1024,
};

/// A data stream that arrived before the session it belongs to.
pub const Orphan = struct {
    /// Whether this slot holds a buffered stream.
    active: bool = false,
    /// The session (CONNECT stream id) the stream claims to belong to.
    session_id: u64 = 0,
    /// The QUIC stream id.
    stream_id: u64 = 0,
    /// Unidirectional or bidirectional.
    kind: stream_header.Kind = .bidi,
    /// The peer ended the stream.
    fin: bool = false,
    /// Bytes buffered in `buf`.
    len: usize = 0,
    /// The buffered bytes, without the stream header (the header is re-read from the client's stream
    /// for a bidirectional request stream, which the engine keeps decoding).
    buf: []u8 = &.{},
};

/// One worker's WebTransport slots.
pub const Pool = struct {
    /// Session slots and their occupancy flags.
    sessions: []session.Session,
    session_used: []bool,
    /// Data stream slots and their occupancy flags.
    streams: []session.Stream,
    stream_used: []bool,
    /// The send buffers, one slice per stream slot, carved out of one allocation.
    buffers: []u8,
    /// Bytes per stream send buffer.
    stream_buffer_bytes: usize,
    /// Pre-session stream slots.
    orphans: []Orphan,
    /// The orphan buffers, one slice per orphan slot, carved out of one allocation.
    orphan_buffers: []u8,
    /// Bytes per orphan buffer.
    orphan_buffer_bytes: usize,

    /// Allocate the worker's slots. Fails only on out-of-memory: an empty pool (every count 0) is legal
    /// and makes every acquisition return null, which is what a deployment that disables the feature
    /// per connection but keeps the server wants.
    pub fn init(allocator: std.mem.Allocator, config: Config) !Pool {
        const session_count = @min(config.sessions, maxima.sessions);
        const stream_count = @min(config.streams, maxima.streams);
        const orphan_count = @min(config.orphans, maxima.orphans);
        const buffer_bytes = @max(config.stream_buffer_bytes, min_stream_buffer_bytes);

        const sessions = try allocator.alloc(session.Session, session_count);
        errdefer allocator.free(sessions);

        const session_used = try allocator.alloc(bool, session_count);
        errdefer allocator.free(session_used);

        const streams = try allocator.alloc(session.Stream, stream_count);
        errdefer allocator.free(streams);

        const stream_used = try allocator.alloc(bool, stream_count);
        errdefer allocator.free(stream_used);

        const buffers = try allocator.alloc(u8, stream_count * buffer_bytes);
        errdefer allocator.free(buffers);

        const orphans = try allocator.alloc(Orphan, orphan_count);
        errdefer allocator.free(orphans);

        const orphan_buffer_bytes = @max(config.orphan_bytes, min_orphan_buffer_bytes);
        const orphan_buffers = try allocator.alloc(u8, orphan_count * orphan_buffer_bytes);
        errdefer allocator.free(orphan_buffers);

        var pool = Pool{
            .sessions = sessions,
            .session_used = session_used,
            .streams = streams,
            .stream_used = stream_used,
            .buffers = buffers,
            .stream_buffer_bytes = buffer_bytes,
            .orphans = orphans,
            .orphan_buffers = orphan_buffers,
            .orphan_buffer_bytes = orphan_buffer_bytes,
        };
        pool.reset();

        return pool;
    }

    /// Free every allocation. Callers must have released every slot (the server stops its workers
    /// before tearing the pool down).
    pub fn deinit(self: *Pool, allocator: std.mem.Allocator) void {
        allocator.free(self.sessions);
        allocator.free(self.session_used);
        allocator.free(self.streams);
        allocator.free(self.stream_used);
        allocator.free(self.buffers);
        allocator.free(self.orphans);
        allocator.free(self.orphan_buffers);
    }

    /// Mark every slot free and clear the orphan buffers. Called at init, and available to a caller that
    /// wants to drop everything (a connection table reset).
    pub fn reset(self: *Pool) void {
        for (self.session_used) |*used| used.* = false;
        for (self.stream_used) |*used| used.* = false;

        for (self.orphans, 0..) |*orphan, index| {
            const offset = index * self.orphan_buffer_bytes;
            orphan.* = .{ .buf = self.orphan_buffers[offset..][0..self.orphan_buffer_bytes] };
        }
    }

    /// The send buffer of stream slot `index`.
    fn bufferFor(self: *Pool, index: usize) []u8 {
        const offset = index * self.stream_buffer_bytes;

        return self.buffers[offset..][0..self.stream_buffer_bytes];
    }

    /// Take a free session slot, or null when every slot is live. Linear from the last allocation, so a
    /// steady-state worker with a few sessions never scans far.
    pub fn acquireSession(self: *Pool) ?*session.Session {
        for (self.session_used, 0..) |*used, index| {
            if (used.*) continue;

            used.* = true;
            const slot = &self.sessions[index];
            slot.* = .{};

            return slot;
        }

        return null;
    }

    /// Return a session slot. The caller detaches (or has already released) its streams first.
    pub fn releaseSession(self: *Pool, target: *session.Session) void {
        for (self.sessions, 0..) |*slot, index| {
            if (slot != target) continue;

            self.session_used[index] = false;
            slot.* = .{};

            return;
        }
    }

    /// Take a free stream slot with its send buffer attached, or null when every slot is live.
    pub fn acquireStream(self: *Pool) ?*session.Stream {
        for (self.stream_used, 0..) |*used, index| {
            if (used.*) continue;

            used.* = true;
            const slot = &self.streams[index];
            slot.* = .{ .buf = self.bufferFor(index) };

            return slot;
        }

        return null;
    }

    /// Return a stream slot. The caller must have detached it from its session, or be tearing the
    /// session down, since a released slot's buffer is immediately reusable.
    pub fn releaseStream(self: *Pool, target: *session.Stream) void {
        for (self.streams, 0..) |*slot, index| {
            if (slot != target) continue;

            self.stream_used[index] = false;
            slot.* = .{};

            return;
        }
    }

    /// The number of session slots in use, for diagnostics.
    pub fn sessionCount(self: *const Pool) usize {
        var count: usize = 0;
        for (self.session_used) |used| {
            if (used) count += 1;
        }

        return count;
    }

    /// The number of stream slots in use, for diagnostics.
    pub fn streamCount(self: *const Pool) usize {
        var count: usize = 0;
        for (self.stream_used) |used| {
            if (used) count += 1;
        }

        return count;
    }

    // ------------------------------------------------------------- //
    // Pre-session streams (4.6)
    // ------------------------------------------------------------- //

    /// Buffer the first bytes of a data stream whose session does not exist yet. Returns the slot to
    /// append to (an existing one for the same stream), or null when the buffer is full: the caller then
    /// resets the stream with WT_BUFFERED_STREAM_REJECTED.
    ///
    /// Param:
    /// session_id - u64 (the session the stream claims to belong to)
    /// stream_id - u64 (the QUIC stream id)
    /// kind - stream_header.Kind
    /// data - []const u8 (the stream bytes after the header)
    /// fin - bool (whether the peer ended the stream)
    ///
    /// Return:
    /// - ?*Orphan (the slot holding the stream, or null when there is no room)
    pub fn bufferOrphan(self: *Pool, session_id: u64, stream_id: u64, kind: stream_header.Kind, data: []const u8, fin: bool) ?*Orphan {
        var claimed = false;
        const slot = self.orphanFor(stream_id) orelse blk: {
            var fresh: ?*Orphan = null;
            for (self.orphans) |*orphan| {
                if (orphan.active) continue;

                orphan.* = .{
                    .active = true,
                    .session_id = session_id,
                    .stream_id = stream_id,
                    .kind = kind,
                    .buf = orphan.buf,
                };
                claimed = true;
                fresh = orphan;
                break;
            }

            break :blk fresh orelse return null;
        };

        // A write the slot cannot hold refuses the stream, and a slot claimed for it is given straight
        // back: leaving it active would burn a slot for a stream that was never buffered.
        if (slot.len + data.len > slot.buf.len) {
            if (claimed) {
                slot.active = false;
                slot.len = 0;
            }

            return null;
        }

        @memcpy(slot.buf[slot.len..][0..data.len], data);
        slot.len += data.len;
        if (fin) slot.fin = true;

        return slot;
    }

    /// The slot buffering `stream_id`, or null.
    pub fn orphanFor(self: *Pool, stream_id: u64) ?*Orphan {
        for (self.orphans) |*orphan| {
            if (orphan.active and orphan.stream_id == stream_id) return orphan;
        }

        return null;
    }

    /// Every orphan claiming to belong to `session_id`, in table order, by handing each to `visit`. Used
    /// when a session is established, to replay the streams a client opened before its CONNECT was
    /// answered. A visited slot is released.
    ///
    /// Param:
    /// session_id - u64
    /// visit - fn (context, *Orphan) void
    /// context - anytype
    pub fn drainOrphans(self: *Pool, session_id: u64, comptime visit: anytype, context: anytype) void {
        for (self.orphans) |*orphan| {
            if (!orphan.active or orphan.session_id != session_id) continue;

            visit(context, orphan);
            orphan.active = false;
            orphan.len = 0;
            orphan.fin = false;
        }
    }

    /// Release every buffered stream, when the session they waited for is refused or the connection goes
    /// away. Returns how many were dropped.
    pub fn dropOrphans(self: *Pool, session_id: u64) usize {
        var dropped: usize = 0;
        for (self.orphans) |*orphan| {
            if (!orphan.active or orphan.session_id != session_id) continue;

            orphan.active = false;
            orphan.len = 0;
            orphan.fin = false;
            dropped += 1;
        }

        return dropped;
    }
};

/// The smallest send buffer a stream slot may have: the header plus a short first write. A smaller
/// configuration is raised to it rather than accepted, since a stream whose buffer cannot hold its own
/// header could never be opened.
pub const min_stream_buffer_bytes: usize = 256;

/// The smallest buffer a pre-session stream slot may have: enough for a short first write plus the
/// stream header a bidirectional stream carries again once it is replayed.
pub const min_orphan_buffer_bytes: usize = 64;

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn testPool() !Pool {
    return Pool.init(std.testing.allocator, .{
        .sessions = 2,
        .streams = 3,
        .stream_buffer_bytes = 512,
        .orphans = 2,
        .orphan_bytes = 64,
    });
}

test "zix webtransport: the pool hands out slots, refuses past capacity, and recycles" {
    var pool = try testPool();
    defer pool.deinit(std.testing.allocator);

    const first = pool.acquireSession().?;
    const second = pool.acquireSession().?;
    try std.testing.expect(pool.acquireSession() == null);
    try std.testing.expect(first != second);
    try std.testing.expectEqual(@as(usize, 2), pool.sessionCount());

    // A released slot comes back empty and is handed out again.
    first.id = 4;
    pool.releaseSession(first);
    try std.testing.expectEqual(@as(usize, 1), pool.sessionCount());

    const reused = pool.acquireSession().?;
    try std.testing.expectEqual(@as(u64, 0), reused.id);

    pool.releaseSession(second);
    pool.releaseSession(reused);
    try std.testing.expectEqual(@as(usize, 0), pool.sessionCount());
}

test "zix webtransport: every stream slot carries its own send buffer" {
    var pool = try testPool();
    defer pool.deinit(std.testing.allocator);

    const a = pool.acquireStream().?;
    const b = pool.acquireStream().?;
    const c = pool.acquireStream().?;
    try std.testing.expect(pool.acquireStream() == null);

    try std.testing.expectEqual(@as(usize, 512), a.buf.len);
    try std.testing.expect(a.buf.ptr != b.buf.ptr and b.buf.ptr != c.buf.ptr);

    // The buffers are disjoint ranges of the pool's one allocation, which is what makes two sessions
    // safe to service in the same receive pass: a write through one slot cannot land in another.
    const a_end = @intFromPtr(a.buf.ptr) + a.buf.len;
    const b_end = @intFromPtr(b.buf.ptr) + b.buf.len;
    const c_end = @intFromPtr(c.buf.ptr) + c.buf.len;
    try std.testing.expect(a_end <= @intFromPtr(b.buf.ptr) or b_end <= @intFromPtr(a.buf.ptr));
    try std.testing.expect(b_end <= @intFromPtr(c.buf.ptr) or c_end <= @intFromPtr(b.buf.ptr));
    try std.testing.expect(a.buf.len + b.buf.len + c.buf.len == pool.buffers.len);

    a.buf[0] = 0x11;
    c.buf[0] = 0x33;
    try std.testing.expectEqual(@as(u8, 0x11), a.buf[0]);
    try std.testing.expectEqual(@as(u8, 0x33), c.buf[0]);

    pool.releaseStream(b);
    const recycled = pool.acquireStream().?;
    try std.testing.expectEqual(@as(u64, 0), recycled.id);
    try std.testing.expectEqual(@as(usize, 3), pool.streamCount());
}

test "zix webtransport: 4.6 the orphan table holds a bounded set of pre-session streams" {
    var pool = try testPool();
    defer pool.deinit(std.testing.allocator);

    const first = pool.bufferOrphan(0, 4, .bidi, "hello", false).?;
    try std.testing.expectEqual(@as(u64, 4), first.stream_id);
    try std.testing.expectEqual(@as(u64, 0), first.session_id);
    try std.testing.expectEqualStrings("hello", first.buf[0..first.len]);

    // A second frame of the same stream appends to the same slot, so a split header is reassembled in
    // one place instead of taking two slots.
    const same = pool.bufferOrphan(0, 4, .bidi, " world", true).?;
    try std.testing.expect(same == first);
    try std.testing.expectEqualStrings("hello world", first.buf[0..first.len]);
    try std.testing.expect(first.fin);

    // A slot whose buffer cannot hold the next write is refused, which is what makes the caller reset
    // the stream with WT_BUFFERED_STREAM_REJECTED.
    var big: [80]u8 = @splat(0x5a);
    try std.testing.expect(pool.bufferOrphan(0, 8, .uni, &big, false) == null);

    // A different stream takes the second slot, and past that the table is full.
    try std.testing.expect(pool.bufferOrphan(0, 12, .uni, "x", false) != null);
    try std.testing.expect(pool.bufferOrphan(0, 16, .uni, "y", false) == null);
}

test "zix webtransport: buffered streams are replayed to their session, and only theirs" {
    var pool = try testPool();
    defer pool.deinit(std.testing.allocator);

    _ = pool.bufferOrphan(0, 4, .bidi, "a", false).?;
    _ = pool.bufferOrphan(4, 8, .bidi, "b", true).?;

    const Collector = struct {
        count: usize = 0,
        stream_id: u64 = 0,
        bytes: usize = 0,
        last_fin: bool = false,

        fn visit(self: *@This(), orphan: *Orphan) void {
            self.count += 1;
            self.stream_id = orphan.stream_id;
            self.bytes = orphan.len;
            self.last_fin = orphan.fin;
        }
    };

    var collector = Collector{};
    pool.drainOrphans(0, Collector.visit, &collector);

    try std.testing.expectEqual(@as(usize, 1), collector.count);
    try std.testing.expectEqual(@as(u64, 4), collector.stream_id);
    try std.testing.expectEqual(@as(usize, 1), collector.bytes);
    try std.testing.expect(!collector.last_fin);

    // The other session's stream is still buffered, and dropping it reports the count.
    try std.testing.expectEqual(@as(usize, 1), pool.dropOrphans(4));
    try std.testing.expectEqual(@as(usize, 0), pool.dropOrphans(4));

    // A drained slot is free again, so a later stream can take it.
    try std.testing.expect(pool.bufferOrphan(0, 20, .uni, "z", false) != null);
}

test "zix webtransport: a tiny configured buffer is raised to one that can hold a stream header" {
    var pool = try Pool.init(std.testing.allocator, .{ .sessions = 1, .streams = 1, .stream_buffer_bytes = 4 });
    defer pool.deinit(std.testing.allocator);

    try std.testing.expectEqual(min_stream_buffer_bytes, pool.acquireStream().?.buf.len);
}

test "zix webtransport: an empty pool is legal and refuses every acquisition" {
    var pool = try Pool.init(std.testing.allocator, .{ .sessions = 0, .streams = 0, .orphans = 0 });
    defer pool.deinit(std.testing.allocator);

    try std.testing.expect(pool.acquireSession() == null);
    try std.testing.expect(pool.acquireStream() == null);
    try std.testing.expect(pool.bufferOrphan(0, 4, .bidi, "x", false) == null);
    try std.testing.expectEqual(@as(usize, 0), pool.sessionCount());
}
