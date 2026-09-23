//! Shared TLS connection transport for the multiplexed serve paths.
//!
//! What:
//! - The per-connection TLS byte transport that the tls_mux workers previously each owned a copy of:
//!   the resumable handshake session, the outbound-ciphertext backpressure buffer (staged on EAGAIN,
//!   flushed on EPOLLOUT), and the fd -> connection slot table.
//! - Ciphertext in, plaintext out, plaintext response in, records out. Engine loops stay per-engine
//!   (ADR-050): they feed this module instead of owning a copy.
//! - Per ADR-042 the per-engine tables stay per-engine, this module only shares the byte-identical
//!   transport machinery (same rule as slab.zig).

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const session = @import("../tcp/tls/tls_session.zig");
const Tls = @import("../tls/Tls.zig");
const slab = @import("slab.zig");

const allocator = std.heap.smp_allocator;

/// Inbound ciphertext read staging (may hold several records per read).
pub const read_staging_size: usize = 32 * 1024;

/// Event-data tag for TLS connections in a dual-listener loop (bit 32, above any fd). A worker that
/// hosts cleartext and TLS connections in one epoll instance registers TLS events as
/// `tls_event_tag | fd` so the loop can route the event without a table probe. TLS-only workers
/// register plain fds (tag 0).
pub const tls_event_tag: u64 = 1 << 32;

/// Initial size of the per-connection outbound-ciphertext backpressure buffer (grown on demand).
pub const write_buf_initial: usize = 16 * 1024;

/// The TLS byte transport of one multiplexed connection: the resumable TLS session plus the
/// outbound-ciphertext backpressure buffer. Engines embed it in their per-connection object
/// (field name `transport` everywhere) and keep their payload (request accumulator, h2 mux,
/// router server) next to it.
pub const Transport = struct {
    fd: posix.fd_t,
    tls: session.Session,

    // Outbound ciphertext staged on EAGAIN: a heap buffer flushed on the next EPOLLOUT. wbuf is the
    // allocation (capacity), the live bytes are wbuf[woff..wlen]. Capacity and length are tracked
    // separately so a grown buffer never transmits its uninitialized tail.
    wbuf: []u8 = &.{},
    woff: usize = 0,
    wlen: usize = 0,
    wclose: bool = false,
    want_out: bool = false,

    // First wbuf allocation size (h2 / grpc pass their tls_write_buf_initial knob here).
    wbuf_initial: usize = write_buf_initial,

    // The epoll data this connection was registered with. Defaults to the fd. A dual-listener
    // loop that tags TLS events in the data word overrides it after init, so an EPOLLOUT re-arm
    // never strips the tag.
    ep_data: u64 = 0,

    /// Fresh transport for an accepted TLS connection: a resumable session over the context's
    /// identity, nothing staged.
    pub fn init(fd: posix.fd_t, ctx: *const Tls.Context) Transport {
        return .{
            .fd = fd,
            // The chain the context loaded, or the single certificate it was built with: a context assembled
            // by hand (a test fixture) has no chain to speak of, and a session that is handed none would
            // present an empty Certificate message.
            // The same trap `Context.handshakeOptions` documents: `&.{ctx.cert_der}` here would be
            // an array constructed in this frame, and `Session.init` keeps the slice — so the
            // session would read a chain whose storage died with this call.
            .tls = session.Session.init(if (ctx.certificate_chain.len > 0) ctx.certificate_chain else ctx.singleCertChain(), ctx.signing_key, ctx.alpn),
            .ep_data = @intCast(fd),
        };
    }

    /// Free the backpressure buffer. The transport itself lives inside the engine's conn object,
    /// which the engine's freeConn releases.
    pub fn deinit(self: *Transport) void {
        if (self.wbuf.len > 0) allocator.free(self.wbuf);
    }

    /// Try to send `bytes` now, staging whatever does not fit and marking the connection for
    /// EPOLLOUT. Returns false on a fatal write error (the caller closes).
    ///
    /// Note:
    /// - TLS records must reach the peer in order (the AEAD nonce is the record sequence number).
    ///   If ciphertext is already staged, this MUST append rather than write directly, or a later
    ///   record would overtake the staged one on the wire and break decryption.
    pub fn sendRaw(self: *Transport, bytes: []const u8) bool {
        if (self.wlen > self.woff) {
            self.stageWrite(bytes);
            return true;
        }

        var off: usize = 0;
        while (off < bytes.len) {
            const rc = linux.write(self.fd, bytes[off..].ptr, bytes.len - off);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return false;
                    off += @intCast(rc);
                },
                .INTR => continue,
                .AGAIN => {
                    self.stageWrite(bytes[off..]);
                    return true;
                },
                else => return false,
            }
        }

        return true;
    }

    /// Append unsent ciphertext to the pending buffer (grown as needed) for the next EPOLLOUT.
    /// The live bytes are wbuf[woff..wlen]. Capacity (wbuf.len) is never used as the data length,
    /// so a grown buffer never flushes its uninitialized tail.
    fn stageWrite(self: *Transport, bytes: []const u8) void {
        const pending = self.wlen - self.woff;

        // Room already at the tail: append in place.
        if (self.wbuf.len - self.wlen >= bytes.len) {
            @memcpy(self.wbuf[self.wlen..][0..bytes.len], bytes);
            self.wlen += bytes.len;
            self.want_out = true;
            return;
        }

        const need = pending + bytes.len;

        // Compaction alone makes room: slide the live bytes to the front.
        if (self.wbuf.len >= need) {
            std.mem.copyForwards(u8, self.wbuf[0..pending], self.wbuf[self.woff..self.wlen]);
            self.woff = 0;
            self.wlen = pending;

            @memcpy(self.wbuf[self.wlen..][0..bytes.len], bytes);
            self.wlen += bytes.len;
            self.want_out = true;
            return;
        }

        // Grow: allocate a larger buffer and move the live bytes to its front.
        var new_cap: usize = if (self.wbuf.len == 0) self.wbuf_initial else self.wbuf.len * 2;
        while (new_cap < need) new_cap *= 2;

        const grown = allocator.alloc(u8, new_cap) catch {
            self.wclose = true;
            return;
        };
        @memcpy(grown[0..pending], self.wbuf[self.woff..self.wlen]);
        if (self.wbuf.len > 0) allocator.free(self.wbuf);
        self.wbuf = grown;
        self.woff = 0;
        self.wlen = pending;

        @memcpy(self.wbuf[self.wlen..][0..bytes.len], bytes);
        self.wlen += bytes.len;
        self.want_out = true;
    }

    /// Encrypt response plaintext into TLS records and send (staging on backpressure). The caller
    /// provides the sealed staging buffer, sized to its own record policy.
    ///
    /// Note:
    /// - A seal that produced nothing means the staging buffer was too small for the response. That
    ///   is reported as a dead connection rather than sent as a short read, because a peer cannot
    ///   tell a truncated body from a complete one.
    ///
    /// Return:
    /// - bool (false when the connection must close)
    pub fn sendPlain(self: *Transport, plaintext: []const u8, sealed: []u8) bool {
        const ct = self.tls.encrypt(plaintext, sealed);
        if (ct.len == 0) return false;

        return self.sendRaw(ct);
    }

    /// Encrypt one full record gathered from two source slices (staged prefix + payload tail) and
    /// send. Avoids copying the tail into an accumulator first. Ordering matches sendPlain:
    /// records leave in sequence order through sendRaw.
    ///
    /// Return:
    /// - bool (false when the connection must close, an empty seal included)
    pub fn sendPlainGather(self: *Transport, prefix: []const u8, tail: []const u8, sealed: []u8) bool {
        const ct = self.tls.encrypt2(prefix, tail, sealed);
        if (ct.len == 0) return false;

        return self.sendRaw(ct);
    }

    /// Flush staged outbound ciphertext on an EPOLLOUT. Returns false when the connection must
    /// close.
    pub fn onWritable(self: *Transport, epfd: posix.fd_t) bool {
        while (self.woff < self.wlen) {
            const rc = linux.write(self.fd, self.wbuf[self.woff..].ptr, self.wlen - self.woff);
            switch (posix.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return false;
                    self.woff += @intCast(rc);
                },
                .INTR => continue,
                .AGAIN => return true,
                else => return false,
            }
        }

        // Drained. Keep the buffer for reuse instead of freeing: under sustained backpressure the
        // stage/drain cycle repeats, and a free here plus a realloc on the next stageWrite churns
        // the shared allocator on the hot path. deinit releases it at close.
        self.woff = 0;
        self.wlen = 0;
        self.want_out = false;
        armOut(epfd, self.fd, self.ep_data, false);

        return !self.wclose;
    }
};

/// Re-arm a connection's epoll registration with or without EPOLLOUT, preserving the data word it
/// was registered with (a dual-listener loop tags TLS connections there).
pub fn armOut(epfd: posix.fd_t, fd: posix.fd_t, data: u64, on: bool) void {
    var flags: u32 = linux.EPOLL.IN | linux.EPOLL.RDHUP;
    if (on) flags |= linux.EPOLL.OUT;

    var ev = linux.epoll_event{ .events = flags, .data = .{ .u64 = data } };
    _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_MOD, fd, &ev);
}

/// Per-worker fd -> connection map over a demand-paged pointer slab (shared-nothing, one worker
/// owns a connection for its lifetime). Untouched slots cost no physical memory.
///
/// Param:
/// Conn - type (the engine's per-connection object)
/// max_fd - usize (slot count, indexed by fd)
/// free_conn - fn (releases one conn: payload, transport buffer, then the object itself)
pub fn ConnTable(comptime Conn: type, comptime max_fd: usize, comptime free_conn: fn (*Conn) void) type {
    return struct {
        slots: []?*Conn,

        const Self = @This();

        pub fn init() !Self {
            return .{ .slots = try slab.mapZeroedSlots(?*Conn, max_fd) };
        }

        pub fn deinit(self: *Self) void {
            for (self.slots) |maybe| {
                if (maybe) |conn| free_conn(conn);
            }
            slab.unmapSlots(self.slots);
        }

        pub fn get(self: *Self, fd: posix.fd_t) ?*Conn {
            const idx: usize = @intCast(fd);
            if (idx >= self.slots.len) return null;

            return self.slots[idx];
        }

        pub fn put(self: *Self, fd: posix.fd_t, conn: *Conn) void {
            self.slots[@intCast(fd)] = conn;
        }

        pub fn drop(self: *Self, fd: posix.fd_t) void {
            const idx: usize = @intCast(fd);
            if (idx >= self.slots.len) return;
            if (self.slots[idx]) |conn| free_conn(conn);
            self.slots[idx] = null;
        }
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn drainFd(fd: posix.fd_t, sink: []u8) usize {
    // The peer fd is non-blocking, so the drain stops at EAGAIN instead of parking the test.
    var total: usize = 0;
    while (total < sink.len) {
        const rc = linux.read(fd, sink[total..].ptr, sink.len - total);
        if (posix.errno(rc) != .SUCCESS or rc == 0) break;
        total += @intCast(rc);
    }

    return total;
}

fn setNonBlockTest(fd: posix.fd_t) void {
    const cur = linux.fcntl(fd, posix.F.GETFL, 0);
    const nonblock: u32 = @bitCast(posix.O{ .NONBLOCK = true });
    _ = linux.fcntl(fd, posix.F.SETFL, cur | @as(usize, nonblock));
}

test "zix multiplexers: tls_conn, sendRaw writes through when the socket has room" {
    if (@import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var pair: [2]posix.fd_t = undefined;
    try std.testing.expect(posix.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    var transport = Transport{ .fd = pair[0], .tls = undefined };
    defer transport.deinit();

    try std.testing.expect(transport.sendRaw("hello"));
    try std.testing.expect(!transport.want_out);

    var got: [16]u8 = undefined;
    const rc = linux.read(pair[1], &got, got.len);
    try std.testing.expect(posix.errno(rc) == .SUCCESS);
    try std.testing.expectEqualStrings("hello", got[0..@intCast(rc)]);
}

test "zix multiplexers: tls_conn, backpressure stages then onWritable flushes in order" {
    if (@import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var pair: [2]posix.fd_t = undefined;
    try std.testing.expect(posix.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    const wr_fd = pair[0];
    const rd_fd = pair[1];
    defer _ = linux.close(wr_fd);
    defer _ = linux.close(rd_fd);

    // Non-blocking on both ends: the sender so writes hit EAGAIN and stage, the reader so the
    // drain helper stops at EAGAIN. Smallest send buffer the kernel allows, to saturate fast.
    setNonBlockTest(wr_fd);
    setNonBlockTest(rd_fd);
    const tiny: u32 = 1;
    _ = linux.setsockopt(wr_fd, linux.SOL.SOCKET, linux.SO.SNDBUF, @ptrCast(&tiny), @sizeOf(u32));

    var transport = Transport{ .fd = wr_fd, .tls = undefined };
    defer transport.deinit();

    // Push chunks until at least one stages (the kernel rounds SNDBUF up, so loop past it).
    const chunk: [4096]u8 = @splat(0xAB);
    var pushed: usize = 0;
    while (!transport.want_out) {
        try std.testing.expect(transport.sendRaw(&chunk));
        pushed += chunk.len;
        try std.testing.expect(pushed < 1024 * 1024); // SNDBUF must saturate well before 1 MiB
    }

    // Staged tail appends in order while blocked (sendRaw must not bypass the queue).
    try std.testing.expect(transport.sendRaw("tail-marker"));
    pushed += "tail-marker".len;

    // Drain the peer, then flush the staged bytes. epfd is real so armOut's CTL_MOD is exercised
    // (the fd was never CTL_ADDed, the failed MOD is intentionally ignored by armOut).
    const epfd_rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    try std.testing.expect(posix.errno(epfd_rc) == .SUCCESS);
    const epfd: posix.fd_t = @intCast(epfd_rc);
    defer _ = linux.close(epfd);

    var sink: [1024 * 1024]u8 = undefined;
    var drained: usize = 0;
    while (transport.wlen > transport.woff) {
        drained += drainFd(rd_fd, sink[drained..]);
        try std.testing.expect(transport.onWritable(epfd));
    }
    drained += drainFd(rd_fd, sink[drained..]);

    try std.testing.expectEqual(pushed, drained);
    try std.testing.expect(!transport.want_out);
    try std.testing.expectEqualStrings("tail-marker", sink[drained - "tail-marker".len .. drained]);
}

test "zix multiplexers: tls_conn, stageWrite grows past wbuf_initial and keeps live bytes" {
    if (@import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // fd -1: every write fails, but stageWrite is exercised directly so no write happens.
    var transport = Transport{ .fd = -1, .tls = undefined, .wbuf_initial = 32 };
    defer transport.deinit();

    transport.stageWrite("0123456789abcdef0123456789abcdef"); // exactly wbuf_initial
    transport.stageWrite("-and-the-overflow-forces-a-grow");

    try std.testing.expect(transport.wbuf.len > 32);
    try std.testing.expect(!transport.wclose);
    try std.testing.expectEqualStrings(
        "0123456789abcdef0123456789abcdef-and-the-overflow-forces-a-grow",
        transport.wbuf[transport.woff..transport.wlen],
    );
}

test "zix multiplexers: tls_conn, ConnTable put get drop frees through free_conn" {
    if (@import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const Probe = struct {
        transport: Transport,

        var freed: usize = 0;

        fn freeConn(conn: *@This()) void {
            conn.transport.deinit();
            freed += 1;
            std.heap.smp_allocator.destroy(conn);
        }
    };

    var table = try ConnTable(Probe, 64, Probe.freeConn).init();
    defer table.deinit();

    const conn = try std.heap.smp_allocator.create(Probe);
    conn.* = .{ .transport = .{ .fd = 7, .tls = undefined } };
    table.put(7, conn);

    try std.testing.expectEqual(conn, table.get(7).?);
    try std.testing.expectEqual(@as(?*Probe, null), table.get(8));
    try std.testing.expectEqual(@as(?*Probe, null), table.get(9999)); // out of range is null, not a crash

    table.drop(7);
    try std.testing.expectEqual(@as(?*Probe, null), table.get(7));
    try std.testing.expectEqual(@as(usize, 1), Probe.freed);
}
