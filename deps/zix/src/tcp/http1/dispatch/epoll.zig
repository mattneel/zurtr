//! zix http1 .EPOLL dispatch model.

const std = @import("std");
const builtin = @import("builtin");
const Config = @import("../config.zig").Http1ServerConfig;
const core = @import("../core.zig");
const cache = @import("../../../utils/response_cache.zig");
const ws = @import("../websocket.zig");
const slab = @import("../../../multiplexers/slab.zig");
const tls_mux = @import("../tls_mux.zig");
const reuseport = @import("../../../multiplexers/reuseport.zig");
const listen_report = @import("../../../multiplexers/listen_report.zig");
const tls_conn = @import("../../../multiplexers/tls_conn.zig");
const Tls = @import("../../../tls/Tls.zig");
const HandlerFn = core.HandlerFn;
const common = @import("common.zig");
const logSystem = common.logSystem;
const setNoDelay = common.setNoDelay;
const setNonBlock = common.setNonBlock;
const setBusyPoll = common.setBusyPoll;
const pinToCpu = common.pinToCpu;
const getAvailableCpuCount = common.getAvailableCpuCount;
const decodeChunkedInBuf = core.decodeChunkedInBuf;
const parseGetFastPath = common.parseGetFastPath;
const effectiveCacheEntries = common.effectiveCacheEntries;
const MAX_FD = common.MAX_FD;
const MAX_DRAIN_RECV = common.MAX_DRAIN_RECV;

/// Max epoll events drained per epoll_wait call. 4096 reduces round-trips at
/// high connection counts where many fds can be ready simultaneously.
const EPOLL_MAX_EVENTS: usize = 4096;

/// Per-worker sink buffer for coalescing pipelined responses. 64 KiB gives enough
/// room for a full pipelined burst without mid-burst flushes.
const EPOLL_OUT_BUF_SIZE: usize = 64 * 1024;

/// Max write-pending staging buffers kept per size class on the per-worker pool. Past this a released
/// buffer is freed instead of pooled, so a pathological backpressure storm cannot grow the pool without bound.
const WRITE_POOL_CAP: usize = 64;

/// Size classes for write-pending staging buffers, smallest first. A stalled write stages only its
/// unflushed remainder, which for small responses is far below the 64 KiB sink. Bucketing the staging
/// buffer to the smallest class that fits the remainder stops a high-connection backpressure burst
/// (thousands of simultaneous stalls) from each pinning a full 64 KiB, the dominant term in the EPOLL
/// resident set at high concurrency. The largest class equals the sink, so a full-burst remainder
/// still fits, since the staged remainder never exceeds the sink buffer.
const WRITE_STAGE_CLASSES = [_]usize{ 8 * 1024, 32 * 1024, EPOLL_OUT_BUF_SIZE };

/// Per-worker pool of write-pending staging buffers. When a response does not fully flush on
/// EAGAIN (a slow client), the remainder is staged in a buffer until EPOLLOUT drains it. Rather than
/// allocate and free one per stall, the worker recycles a free-list per size class, so a backpressure
/// burst reuses allocations instead of churning the allocator. One worker thread owns it (threadlocal),
/// so no synchronization is needed.
const WritePendingPool = struct {
    /// One free-list per size class in WRITE_STAGE_CLASSES, each capped at WRITE_POOL_CAP entries.
    free: [WRITE_STAGE_CLASSES.len][WRITE_POOL_CAP][]u8 = undefined,
    counts: [WRITE_STAGE_CLASSES.len]usize = std.mem.zeroes([WRITE_STAGE_CLASSES.len]usize),

    /// Index of the smallest size class that holds need bytes, or null when need exceeds the largest
    /// class (never happens here: the staged remainder never exceeds the sink, which is the largest class).
    fn classOf(need: usize) ?usize {
        for (WRITE_STAGE_CLASSES, 0..) |size, idx| {
            if (need <= size) return idx;
        }

        return null;
    }

    /// Take a staging buffer sized to the smallest class that holds need bytes: pop one from that
    /// class free-list, else allocate one. Null only on a need past the largest class or alloc failure.
    fn acquire(self: *WritePendingPool, need: usize) ?[]u8 {
        const class = classOf(need) orelse return null;

        if (self.counts[class] > 0) {
            self.counts[class] -= 1;

            return self.free[class][self.counts[class]];
        }

        return std.heap.smp_allocator.alloc(u8, WRITE_STAGE_CLASSES[class]) catch null;
    }

    /// Return a drained buffer to its size-class free-list, or free it when that class is already full.
    /// The buffer length identifies its class, a length matching no class exactly is freed outright.
    fn release(self: *WritePendingPool, buf: []u8) void {
        const class = classOf(buf.len) orelse {
            std.heap.smp_allocator.free(buf);

            return;
        };

        if (WRITE_STAGE_CLASSES[class] != buf.len) {
            std.heap.smp_allocator.free(buf);

            return;
        }

        if (self.counts[class] < WRITE_POOL_CAP) {
            self.free[class][self.counts[class]] = buf;
            self.counts[class] += 1;

            return;
        }

        std.heap.smp_allocator.free(buf);
    }

    fn deinit(self: *WritePendingPool) void {
        for (0..WRITE_STAGE_CLASSES.len) |class| {
            for (self.free[class][0..self.counts[class]]) |buf| std.heap.smp_allocator.free(buf);

            self.counts[class] = 0;
        }
    }
};

threadlocal var tl_write_pool: WritePendingPool = .{};

/// Requests served by this worker thread (cleartext dispatch). Single-owner
/// plain increment (no contention), reported through the system logger at
/// worker exit so REUSEPORT skew across workers is measurable.
threadlocal var tl_requests_served: u64 = 0;

// --------------------------------------------------------- //
// EPOLL model (Linux only): shared-nothing, one listener + epoll per worker.
//
// Each worker owns a private SO_REUSEPORT listener and epoll instance. The
// kernel load-balances new connections across the per-worker listeners, so
// there is no accept thread, no shared queue, and no cross-thread fd handoff.
// A worker owns every fd it accepts for that connection's lifetime, and its
// ConnTable is private, so no slot is ever touched by two threads.

/// Per-connection read state. buf accumulates bytes until one or more whole
/// requests are present. filled is the live byte count held in buf. ws is set
/// once the connection upgrades to WebSocket: from then on buf holds raw frame
/// bytes and the engine echoes via the stored callback instead of parsing HTTP.
/// drain is the count of request-body bytes still to read and discard for a
/// body too large to buffer. The handler for that request has not run yet: it
/// waits for the drain so it can be told how many body bytes arrived. drain_received
/// accumulates that count and pending_head_len is how many head bytes are parked
/// at the front of buf for the deferred parse.
/// write_pending is a heap-owned slice of response bytes staged when a write
/// hits EAGAIN (send buffer full). The EPOLL loop arms EPOLLOUT and drains it
/// on the next writable event rather than blocking the worker. write_pending_off
/// tracks how many bytes have been flushed so far. write_pending_close marks
/// that the connection must close once the staged write drains.
const Conn = struct {
    fd: std.posix.fd_t,
    buf: []u8,
    /// Compact slab slot backing buf, returned to the free-list on close so the
    /// resident recv slab packs to the live connection count, not the fd range.
    slot: u32 = 0,
    filled: usize,
    /// Scan watermark for a split request head: bytes of buf already searched
    /// for the header terminator by an earlier readable event, so the next
    /// event resumes the scan instead of rescanning from zero.
    scan_from: usize = 0,
    ws: ?core.WsFrameFn = null,
    /// Whether 100 Continue was already sent for the request currently being
    /// parsed. The parse pass re-runs on every readable event while a body is
    /// still arriving, and the client only needs to be told once.
    continue_sent: bool = false,
    drain: usize = 0,
    /// Body bytes of the deferred request already taken off the socket, the ones
    /// that arrived with the head plus every byte the drain has discarded since.
    drain_received: usize = 0,
    /// Head bytes of the deferred request parked at the front of buf. Non-zero
    /// means a handler is waiting for the drain to finish.
    pending_head_len: usize = 0,
    write_pending: []u8 = &.{},
    write_pending_len: usize = 0,
    write_pending_off: usize = 0,
    write_pending_close: bool = false,
};

/// Private per-worker fd to Conn map. Not shared between workers: a connection
/// fd is accepted and served by a single worker, and freed before its fd can
/// be reused, so a stale slot is always zeroed by the time it is reused. Conn
/// structs are stored inline in slots (no pointer indirection).
///
/// Recv buffers live in a per-worker slab carved into fixed-size slots. A
/// connection draws a compact slot index from a free-list on accept (reusing a
/// closed connection's slot first), not its fd, so the resident slab tracks the
/// live connection count rather than the fd range. Indexing by fd instead spread
/// the touched pages across the whole fd space (fds climb under load and churn),
/// which held far more resident than the live set. Slots are page-aligned so a
/// closed slot's pages reclaim cleanly. Empty fd slots are identified by buf.len == 0.
const ConnTable = struct {
    slots: []Conn,
    slab: []u8,
    /// Usable recv bytes per connection (config.max_recv_buf or ws_recv_buf).
    buf_size: usize,
    /// Slab bytes per slot: buf_size rounded up to a page so a released slot's
    /// pages reclaim without touching a live neighbor slot.
    stride: usize,
    /// Stack of closed slot indices available for reuse, newest on top.
    free_slots: []u32,
    free_count: usize,
    /// Next never-used slot index. Slots are handed out compactly from 0, so the
    /// touched slab prefix bounds the resident recv memory.
    slot_top: usize,

    fn init(buf_size: usize) !ConnTable {
        // Slots are mmap'd (kernel-zeroed, demand-paged) rather than allocated +
        // memset: an untouched slot reads as zero (which get() treats as empty)
        // and costs no physical memory, and a memset would fault in all MAX_FD
        // slots per worker (which scales with core count). See multiplexers/slab.
        const conn_slots = try slab.mapZeroedSlots(Conn, MAX_FD);
        errdefer slab.unmapSlots(conn_slots);

        // Page-align the slot stride so a closed slot's MADV_DONTNEED reclaims
        // whole pages, never a page half-shared with a live neighbor slot.
        const stride = std.mem.alignForward(usize, buf_size, std.heap.page_size_min);

        // Slab is intentionally not memset: Linux demand-paging means physical
        // pages are only committed when a connection first recvs into its slot.
        const recv_slab = try std.heap.smp_allocator.alloc(u8, MAX_FD * stride);
        errdefer std.heap.smp_allocator.free(recv_slab);

        const free_slots = try std.heap.smp_allocator.alloc(u32, MAX_FD);

        return .{
            .slots = conn_slots,
            .slab = recv_slab,
            .buf_size = buf_size,
            .stride = stride,
            .free_slots = free_slots,
            .free_count = 0,
            .slot_top = 0,
        };
    }

    fn deinit(self: *ConnTable) void {
        for (self.slots) |*conn| {
            if (conn.buf.len == 0) continue;
            if (conn.write_pending.len > 0) std.heap.smp_allocator.free(conn.write_pending);
        }

        std.heap.smp_allocator.free(self.free_slots);
        std.heap.smp_allocator.free(self.slab);
        slab.unmapSlots(self.slots);
    }

    fn get(self: *ConnTable, fd: std.posix.fd_t) ?*Conn {
        const idx: usize = @intCast(fd);
        if (idx >= self.slots.len) return null;

        const conn = &self.slots[idx];

        return if (conn.buf.len > 0) conn else null;
    }

    /// Draw a compact slab slot: reuse a closed slot when one is free, else take
    /// the next never-used slot. Null when the slab is exhausted (all MAX_FD slots live).
    fn acquireSlot(self: *ConnTable) ?u32 {
        if (self.free_count > 0) {
            self.free_count -= 1;

            return self.free_slots[self.free_count];
        }

        if (self.slot_top >= MAX_FD) return null;

        const slot: u32 = @intCast(self.slot_top);
        self.slot_top += 1;

        return slot;
    }

    fn alloc(self: *ConnTable, fd: std.posix.fd_t) ?*Conn {
        const idx: usize = @intCast(fd);
        if (idx >= self.slots.len) return null;

        const slot = self.acquireSlot() orelse return null;
        const buf = self.slab[slot * self.stride ..][0..self.buf_size];
        self.slots[idx] = .{ .fd = fd, .buf = buf, .filled = 0, .slot = slot };

        return &self.slots[idx];
    }

    fn free(self: *ConnTable, fd: std.posix.fd_t) void {
        const idx: usize = @intCast(fd);
        if (idx >= self.slots.len) return;

        const conn = &self.slots[idx];
        if (conn.buf.len == 0) return;

        // Recycle a still-staged write buffer to the per-worker pool rather than freeing it, so a
        // connection that closes mid-stall hands its buffer to the next stall instead of the allocator.
        if (conn.write_pending.len > 0) tl_write_pool.release(conn.write_pending);

        // Return the slot pages to the OS and the slot index to the free-list, so the next accept
        // reuses a low slot and the resident slab stays packed to the live set.
        const slot = conn.slot;
        slab.releaseSlabPages(self.slab[slot * self.stride ..][0..self.stride]);
        self.free_slots[self.free_count] = slot;
        self.free_count += 1;

        conn.* = std.mem.zeroes(Conn);
    }
};

/// Accept every pending connection on listener_fd and register each in epfd.
/// Level-triggered, so draining to EAGAIN guarantees no accept is missed.
fn acceptAll(table: *ConnTable, epfd: std.posix.fd_t, listener_fd: std.posix.fd_t, busy_poll_us: u32) void {
    const linux = std.os.linux;

    while (true) {
        const rc = linux.accept4(listener_fd, null, null, std.posix.SOCK.NONBLOCK | std.posix.SOCK.CLOEXEC);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            .AGAIN => return,
            .INTR, .CONNABORTED => continue,
            else => return,
        }

        const conn_fd: std.posix.fd_t = @intCast(rc);
        setNoDelay(conn_fd);
        setBusyPoll(conn_fd, busy_poll_us);
        if (table.alloc(conn_fd) == null) {
            _ = linux.close(conn_fd);
            continue;
        }

        // Registered via the u64 data form (same bytes for an fd) so the dual-listener loop can
        // rely on the whole data word: TLS events carry a tag bit there, cleartext events must not.
        var ev = linux.epoll_event{
            .events = linux.EPOLL.IN | linux.EPOLL.RDHUP,
            .data = .{ .u64 = @intCast(conn_fd) },
        };
        if (std.posix.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, conn_fd, &ev)) != .SUCCESS) {
            table.free(conn_fd);
            _ = linux.close(conn_fd);
        }
    }
}

/// One readable event on an HTTP connection. Installs the response sink so
/// every response produced by the parse pass coalesces into one write per
/// event. The flush is non-blocking: if the send buffer is full (EAGAIN) the
/// remaining bytes are staged in conn.write_pending and EPOLLOUT is armed so
/// the worker is never parked waiting for a slow client. An upgraded connection
/// is handed to the WebSocket pump only after the flush.
fn serveEpollConn(comptime handler_fn: HandlerFn, conn: *Conn, body_buf: []u8, out_buf: []u8, handler_timeout_ms: u32, epfd: std.posix.fd_t, io: std.Io, arena: *std.heap.ArenaAllocator, do_read: bool) core.ConnOutcome {
    const linux = std.os.linux;

    var sink = core.RespSink{ .fd = conn.fd, .buf = out_buf };
    core.tl_resp_sink = &sink;
    const outcome = serveEpollConnInner(handler_fn, conn, body_buf, handler_timeout_ms, io, arena, do_read);
    core.tl_resp_sink = null;

    if (sink.failed) return .close;

    if (sink.len > 0) {
        const staged_resp = sink.buf[sink.off..sink.len];
        const written = core.writeNonBlockFD(conn.fd, staged_resp) orelse return .close;

        if (written < staged_resp.len) {
            const remaining = staged_resp[written..];
            const staged = tl_write_pool.acquire(remaining.len) orelse return .close;
            @memcpy(staged[0..remaining.len], remaining);
            conn.write_pending = staged;
            conn.write_pending_len = remaining.len;
            conn.write_pending_off = 0;
            conn.write_pending_close = (outcome == .close);

            var arm_ev = linux.epoll_event{
                .events = linux.EPOLL.IN | linux.EPOLL.OUT | linux.EPOLL.RDHUP,
                .data = .{ .u64 = @intCast(conn.fd) },
            };
            _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_MOD, conn.fd, &arm_ev);

            return .keep_alive;
        }
    }

    if (outcome == .close) return .close;

    // Just upgraded: a client can pipeline its first frame in the same packet
    // as the handshake request, so pump whatever is already buffered now
    // rather than waiting for another readable event (which may never come
    // until the client gets its echo).
    if (conn.ws) |on_frame| return serveEpollWs(conn, on_frame, body_buf, out_buf);

    return outcome;
}

/// Flush staged response bytes (conn.write_pending) for connections where a
/// prior write hit EAGAIN. Returns .keep_alive while bytes remain and
/// .close when the write completes and write_pending_close is set (or on
/// a permanent write error). Disarms EPOLLOUT once the buffer is drained.
fn serveEpollWrite(conn: *Conn, epfd: std.posix.fd_t) core.ConnOutcome {
    const linux = std.os.linux;

    const pending = conn.write_pending[conn.write_pending_off..conn.write_pending_len];
    const written = core.writeNonBlockFD(conn.fd, pending) orelse return .close;
    conn.write_pending_off += written;

    if (conn.write_pending_off < conn.write_pending_len) return .keep_alive;

    tl_write_pool.release(conn.write_pending);
    conn.write_pending = &.{};
    conn.write_pending_len = 0;
    conn.write_pending_off = 0;
    const should_close = conn.write_pending_close;
    conn.write_pending_close = false;

    var disarm_ev = linux.epoll_event{
        .events = linux.EPOLL.IN | linux.EPOLL.RDHUP,
        .data = .{ .u64 = @intCast(conn.fd) },
    };
    _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_MOD, conn.fd, &disarm_ev);

    return if (should_close) .close else .keep_alive;
}

/// What a peer gets when it hangs up part way through a request.
///
/// Note:
/// - Bytes left in conn.buf, or a head parked on a drain that can now never
///   reach zero, are a request that never finished arriving. The client is told
///   the request was refused, because a bare close reads the same to it as a
///   crash, a timeout, or a dropped connection.
/// - An idle keep-alive connection has neither and closes without a byte, which
///   is the ordinary end of a connection and not an error.
/// - Serving the partial request instead is the .ASYNC behaviour. This model
///   holds a request until its body is whole, so a handler here is never given
///   one that is not, and the answer comes from the engine.
///
/// Param:
/// conn - *Conn (the connection whose peer just hung up)
///
/// Return:
/// - core.ConnOutcome (always .close, the peer is gone either way)
fn hangupOutcome(conn: *Conn) core.ConnOutcome {
    if (conn.filled > 0 or conn.pending_head_len > 0) {
        core.writeAllFD(conn.fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};
    }

    return .close;
}

/// Parse and serve every complete request in conn.buf.
///
/// Note:
/// - do_read false skips the socket read and works only on what is already in
///   conn.buf. That is how a request whose body was drained is served: the bytes
///   it needs are its parked head, and reading again would take the next request.
fn serveEpollConnInner(comptime handler_fn: HandlerFn, conn: *Conn, body_buf: []u8, handler_timeout_ms: u32, io: std.Io, arena: *std.heap.ArenaAllocator, do_read: bool) core.ConnOutcome {
    const linux = std.os.linux;
    const fd = conn.fd;

    if (do_read) {
        const rc = linux.read(fd, conn.buf[conn.filled..].ptr, conn.buf.len - conn.filled);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return hangupOutcome(conn);

                conn.filled += n;
            },
            .AGAIN => {},
            .INTR => {},
            else => return .close,
        }
    }

    var consumed: usize = 0;
    var keep_alive = true;
    var scan_from = conn.scan_from;
    conn.scan_from = 0;
    while (consumed < conn.filled) {
        const rem = conn.buf[consumed..conn.filled];
        const header_end = std.mem.indexOfPos(u8, rem, scan_from, "\r\n\r\n") orelse {
            if (rem.len >= conn.buf.len) {
                core.writeAllFD(fd, "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n") catch {};
                return .close;
            }

            // Partial head: record the scan watermark so the next readable
            // event resumes the terminator search here instead of rescanning
            // every previously searched byte (recvHead's search_from, ported
            // to the event loop).
            conn.scan_from = if (rem.len > 3) rem.len - 3 else 0;
            break;
        };
        scan_from = 0;

        const parsed = parseGetFastPath(rem, header_end) orelse
            core.parseHeadAt(rem, header_end) catch |err| {
            core.writeAllFD(fd, core.parseErrorResponse(err)) catch {};
            return .close;
        };
        const head = parsed.head;

        // The client is holding its body back until the server agrees to take it.
        // Answering here rather than after the body means the wait is one round
        // trip instead of the client's own timeout. .ASYNC has always done this.
        if (head.expect_continue and !conn.continue_sent and (head.content_length > 0 or head.chunked_request)) {
            core.writeAllFD(fd, "HTTP/1.1 100 Continue\r\n\r\n") catch return .close;
            conn.continue_sent = true;
        }

        var body: []const u8 = &.{};
        var request_len = parsed.body_offset;
        if (head.chunked_request) {
            const decoded = decodeChunkedInBuf(rem[parsed.body_offset..], body_buf);
            switch (decoded.stop) {
                .COMPLETE => {},
                // Still arriving: keep the bytes and resume on the next event.
                .NEED_MORE => break,
                // Neither of these can ever complete, so waiting for more bytes
                // would hold the connection until the buffer filled and the peer
                // looked like it hung up. Answer the client instead.
                .MALFORMED => {
                    core.writeAllFD(fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};

                    return .close;
                },
                .TOO_LARGE => {
                    core.writeAllFD(fd, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};

                    return .close;
                },
            }

            body = body_buf[0..decoded.len];
            request_len = parsed.body_offset + decoded.consumed;
        } else if (head.content_length > 0) {
            // Refused before a byte of it is read or discarded, so a declared
            // length cannot make this worker consume an arbitrary body.
            if (core.tl_max_request_body != 0 and head.content_length > core.tl_max_request_body) {
                core.writeAllFD(fd, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};

                return .close;
            }

            const content_length: usize = @intCast(head.content_length);
            const need = parsed.body_offset + content_length;

            if (need <= rem.len) {
                body = rem[parsed.body_offset..need];
                request_len = need;
            } else if (conn.pending_head_len > 0) {
                // Deferred request re-entering after its drain finished: the body
                // was consumed off the socket and counted, so serve it now with
                // that total and the empty body slice.
                // The drain ran to zero before this branch was reached, so the body
                // is whole even though none of it can be handed over.
                core.tl_body_info = .{ .received = conn.drain_received, .complete = true };
                conn.pending_head_len = 0;
                conn.drain_received = 0;
                request_len = parsed.body_offset;
            } else if (need > conn.buf.len) {
                // Body is larger than the read buffer and can never fit. Hold the
                // handler until the remainder has drained off the socket, so the
                // count it is given comes from the reads that consumed the body
                // rather than from the header. The head bytes stay at the front
                // of buf for that deferred parse, which the MSG.TRUNC drain never
                // writes over. Same ordering the .URING model uses.
                core.setRecvBuf(fd, core.tl_large_body_rcvbuf);

                if (consumed > 0) {
                    std.mem.copyForwards(u8, conn.buf[0..parsed.body_offset], rem[0..parsed.body_offset]);
                }

                const present_body = rem.len - parsed.body_offset;
                conn.drain = content_length - present_body;
                conn.drain_received = present_body;
                conn.pending_head_len = parsed.body_offset;
                consumed = conn.filled;

                break;
            } else {
                break;
            }
        }

        if (handler_timeout_ms != 0) core.setTimeout(handler_timeout_ms);
        _ = arena.reset(.retain_capacity);
        core.invokeHandler(handler_fn, &head, body, fd, io, arena.allocator());

        consumed += request_len;
        tl_requests_served += 1;
        conn.continue_sent = false;

        // The handler may have promoted this connection to WebSocket via
        // WebSocket.serve. From here buf bytes are frames, not requests, so
        // stop the HTTP parse loop and let the WS path take over below.
        if (core.takeWebSocket()) |pending| {
            conn.ws = pending.on_frame;
            break;
        }

        if (!head.keep_alive) {
            keep_alive = false;
            break;
        }
    }

    if (consumed >= conn.filled) {
        conn.filled = 0;
    } else if (consumed > 0) {
        std.mem.copyForwards(u8, conn.buf[0 .. conn.filled - consumed], conn.buf[consumed..conn.filled]);
        conn.filled -= consumed;
    }

    return if (keep_alive) .keep_alive else .close;
}

/// Drive an engine-owned WebSocket connection for one readable event. Reads
/// to EAGAIN so pipelined frames arriving in one network burst are all drained
/// in a single epoll dispatch. Pump+compact runs after each read so a partial
/// frame in conn.buf never blocks the next read. Ping/close are auto-handled
/// by ws.pump. The worker is never parked here.
///
/// Return:
/// - .keep_alive when the connection may receive more frames
/// - .close on peer hangup, a close frame, write failure, or an oversize frame
fn serveEpollWs(conn: *Conn, on_frame: core.WsFrameFn, payload_buf: []u8, out_buf: []u8) core.ConnOutcome {
    const linux = std.os.linux;
    const fd = conn.fd;

    while (true) {
        if (conn.filled < conn.buf.len) {
            const rc = linux.read(fd, conn.buf[conn.filled..].ptr, conn.buf.len - conn.filled);
            switch (std.posix.errno(rc)) {
                .SUCCESS => {
                    const n: usize = @intCast(rc);
                    if (n == 0) return .close;

                    conn.filled += n;
                },
                .AGAIN => break,
                .INTR => continue,
                else => return .close,
            }
        }

        const result = ws.pump(fd, conn.buf[0..conn.filled], payload_buf, out_buf, on_frame);

        if (result.consumed >= conn.filled) {
            conn.filled = 0;
        } else if (result.consumed > 0) {
            std.mem.copyForwards(u8, conn.buf[0 .. conn.filled - result.consumed], conn.buf[result.consumed..conn.filled]);
            conn.filled -= result.consumed;
        }

        if (result.close) return .close;

        // A frame wider than the whole buffer can never complete: close rather
        // than spin on a connection that can make no progress.
        if (conn.filled >= conn.buf.len) return .close;
    }

    return .keep_alive;
}

/// Read and discard the remaining body bytes of an over-large request whose
/// handler has not run yet. Discards with MSG_TRUNC, so the kernel drops the
/// bytes in place: no copy into conn.buf, and the per-call chunk is not capped
/// by the buffer length. Reads to EAGAIN, never past conn.drain, so the next
/// request's bytes are left untouched. Every discarded byte is counted, because
/// that count is what the waiting handler will be told it received.
///
/// Return:
/// - .keep_alive while bytes remain, or once the body is fully drained
/// - .close on peer hangup
fn serveEpollDrain(conn: *Conn) core.ConnOutcome {
    const linux = std.os.linux;
    const fd = conn.fd;

    while (conn.drain > 0) {
        const want = @min(conn.drain, MAX_DRAIN_RECV);
        const rc = linux.recvfrom(fd, conn.buf.ptr, want, linux.MSG.TRUNC, null, null);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return .close;

                conn.drain -= n;
                conn.drain_received += n;
            },
            .AGAIN => return .keep_alive,
            .INTR => {},
            else => return .close,
        }
    }

    return .keep_alive;
}

/// Drain what is left of an over-large body, then serve the request that was
/// waiting on it. The head bytes were parked at the front of conn.buf, so the
/// normal parse pass re-reads them and hands the handler the counted total.
///
/// Return:
/// - .keep_alive while the drain is still running, or after the deferred request
///   was served on a keep-alive connection
/// - .close on peer hangup, where the parked request is answered 400 and dropped
///   rather than served, or when the deferred request asked to close
fn serveEpollDrainThenServe(comptime handler_fn: HandlerFn, conn: *Conn, body_buf: []u8, out_buf: []u8, handler_timeout_ms: u32, epfd: std.posix.fd_t, io: std.Io, arena: *std.heap.ArenaAllocator) core.ConnOutcome {
    const outcome = serveEpollDrain(conn);

    if (outcome == .close) {
        // Answered before the parked head is dropped, because that head is what
        // says a request was in flight when the peer left.
        const hangup = hangupOutcome(conn);
        conn.pending_head_len = 0;
        conn.drain_received = 0;

        return hangup;
    }

    if (conn.drain > 0 or conn.pending_head_len == 0) return outcome;

    conn.filled = conn.pending_head_len;

    return serveEpollConn(handler_fn, conn, body_buf, out_buf, handler_timeout_ms, epfd, io, arena, false);
}

/// One event on a dual-listener TLS connection: mirrors the tls_mux worker loop body (flush staged
/// ciphertext on EPOLLOUT, feed decrypted bytes on EPOLLIN, re-arm or reap).
fn serveTlsEvent(tls_conns: *tls_mux.ConnTable, epfd: std.posix.fd_t, ev: std.os.linux.epoll_event, payload_buf: []u8, out_buf: []u8) void {
    const linux = std.os.linux;
    const fd: std.posix.fd_t = @intCast(ev.data.u64 & (tls_conn.tls_event_tag - 1));

    const conn = tls_conns.get(fd) orelse return;
    var keep = true;

    if ((ev.events & (linux.EPOLL.HUP | linux.EPOLL.ERR)) != 0) {
        keep = false;
    } else {
        if ((ev.events & linux.EPOLL.OUT) != 0) keep = conn.transport.onWritable(epfd);
        if (keep and (ev.events & linux.EPOLL.IN) != 0) keep = tls_mux.onReadable(conn, payload_buf, out_buf);
        if (keep and conn.transport.want_out) tls_conn.armOut(epfd, fd, conn.transport.ep_data, true);
        if (keep and conn.transport.wclose and !conn.transport.want_out) keep = false;
    }

    if (!keep) {
        _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_DEL, fd, null);
        tls_conns.drop(fd);
        _ = linux.close(fd);
    }
}

const EpollWorkerCtx = struct {
    config: Config,
    worker_id: usize,
    /// CBPF steering wiring (config.reuseport_cbpf). Null = steering off.
    steering: ?reuseport.Steering = null,
    /// Where this worker says whether its listeners came up. Shared with the whole group and with
    /// runEpoll, which is what turns a failed bind into a returned error instead of a silent exit.
    report: *listen_report.Report,
};

/// Return a concrete epoll worker function with handler_fn baked in at compile
/// time. Thread.spawn receives the returned function, eliminating the indirect
/// HandlerFn call on every request in the event loop.
fn epollWorkerFn(comptime handler_fn: HandlerFn) fn (EpollWorkerCtx) void {
    return struct {
        fn run(ctx: EpollWorkerCtx) void {
            pinToCpu(ctx.worker_id);
            defer logSystem(ctx.config, .INFO, "epoll worker {d}: {d} requests served", .{ ctx.worker_id, tl_requests_served });

            const linux = std.os.linux;
            const config = ctx.config;
            const io = config.io;

            // Per-request scratch for the handler trio, reset before each request
            // so a long keep-alive connection never grows without bound.
            var req_arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
            defer req_arena.deinit();

            core.setDateHeader(config.send_date_header);
            core.setLargeBodyRcvbuf(config.large_body_rcvbuf);
            core.setMaxRequestBody(config.max_request_body);
            core.setAccessLogger(config.logger);
            core.setStatic(config.public_dir, io);
            core.setMaxResponseHeaders(config.max_response_headers.value());

            // Bind under the order gate: REUSEPORT group index i = worker i,
            // so the cpu-mod-N steering lands on the worker pinned to that slot.
            var bind_turn = reuseport.BindTurn.begin(ctx.steering, ctx.worker_id);
            defer bind_turn.release();

            // Every exit between here and the serve loop has to reach the group, or the workers
            // that did bind wait on one that is already gone.
            var slot = ctx.report.slot(io, error.ZixHttp1WorkerSetupFailed);
            defer slot.close();

            const addr = std.Io.net.IpAddress.resolve(io, config.ip, config.port) catch |err| {
                slot.fail(err);

                return;
            };
            var srv = addr.listen(io, .{
                .mode = .stream,
                .kernel_backlog = config.kernel_backlog,
                .reuse_address = true,
            }) catch |err| {
                slot.fail(err);

                return;
            };
            defer srv.deinit(io);
            const listener_fd = srv.socket.handle;

            setNonBlock(listener_fd);
            if (ctx.steering) |steer| _ = reuseport.attachCpuSteering(listener_fd, steer.group_size);

            const epfd_rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
            if (std.posix.errno(epfd_rc) != .SUCCESS) return;
            const epfd: std.posix.fd_t = @intCast(epfd_rc);
            defer _ = linux.close(epfd);

            var listener_ev = linux.epoll_event{
                .events = linux.EPOLL.IN,
                .data = .{ .u64 = @intCast(listener_fd) },
            };
            if (std.posix.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, listener_fd, &listener_ev)) != .SUCCESS) return;

            const ws_buf_size = if (config.ws_recv_buf > config.max_recv_buf) config.ws_recv_buf else config.max_recv_buf;
            var table = ConnTable.init(ws_buf_size) catch return;
            defer table.deinit();

            // Dual-listener TLS side (config.tls + config.tls_port): a second listen fd whose
            // connections terminate TLS in this same loop via the tls_mux connection machinery.
            // Everything below is mapped only when active, so a cleartext-only worker sees zero
            // layout change on its hot structures.
            const tls_ctx: ?*Tls.Context = if (config.tls_port != 0) config.tls else null;
            var tls_listener_fd: std.posix.fd_t = -1;
            var tls_srv: std.Io.net.Server = undefined;
            var tls_table: ?tls_mux.ConnTable = null;
            defer if (tls_table) |*tls_conns| tls_conns.deinit();
            defer if (tls_ctx != null and tls_listener_fd != -1) tls_srv.deinit(io);

            if (tls_ctx != null) {
                const tls_addr = std.Io.net.IpAddress.resolve(io, config.ip, config.tls_port) catch |err| {
                    slot.fail(err);

                    return;
                };
                tls_srv = tls_addr.listen(io, .{
                    .mode = .stream,
                    .kernel_backlog = config.kernel_backlog,
                    .reuse_address = true,
                }) catch |err| {
                    slot.fail(err);

                    return;
                };
                tls_listener_fd = tls_srv.socket.handle;
                setNonBlock(tls_listener_fd);
                if (ctx.steering) |steer| _ = reuseport.attachCpuSteering(tls_listener_fd, steer.group_size);

                var tls_lev = linux.epoll_event{
                    .events = linux.EPOLL.IN,
                    .data = .{ .u64 = @intCast(tls_listener_fd) },
                };
                if (std.posix.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, tls_listener_fd, &tls_lev)) != .SUCCESS) return;

                tls_table = tls_mux.ConnTable.init() catch return;
            }

            // Both groups joined: release the bind turn to the next worker.
            bind_turn.release();

            // Serve only once every worker is up. A group where one bind failed serves on none of
            // them, so the caller gets one honest failure instead of a half-listening server.
            slot.ok();
            if (ctx.report.awaitGroup(io) != null) return;

            // Free the per-worker write-pending staging pool when the worker exits. table.deinit
            // frees buffers still attached to live connections, this frees the recycled free-list, two
            // disjoint sets, so the order of these defers does not matter.
            defer tl_write_pool.deinit();

            // Sized from the same knob as the recv slot, not a fixed constant:
            // it holds a decoded chunked body and doubles as the WebSocket
            // payload buffer, so both callers are bounded by what a connection
            // may receive. .URING sizes its equivalent the same way.
            const body_buf = std.heap.smp_allocator.alloc(u8, ws_buf_size) catch return;
            defer std.heap.smp_allocator.free(body_buf);

            const out_buf = std.heap.smp_allocator.alloc(u8, EPOLL_OUT_BUF_SIZE) catch return;
            defer std.heap.smp_allocator.free(out_buf);

            // Per-worker response cache, owned for this worker's lifetime. Lives
            // on the worker stack so tl_cache stays valid until run() returns.
            var response_cache: cache.ResponseCache = undefined;
            var cache_on = false;
            if (config.response_cache) {
                if (cache.ResponseCache.init(std.heap.smp_allocator, .{
                    .max_entries = effectiveCacheEntries(config),
                    .max_value_bytes = config.cache_max_value_bytes,
                })) |built| {
                    response_cache = built;
                    cache_on = true;
                    core.setCache(&response_cache, config.cache_ttl_ms);
                } else |_| {
                    cache_on = false;
                }
            }
            defer if (cache_on) {
                core.setCache(null, 0);
                response_cache.deinit();
            };

            // Response compression, stateless per worker (no owned structure). Active
            // under .EPOLL and .URING, like the cache.
            if (config.compress) core.setCompression(config.compress, config.compression_min_size, config.compression_max_out);
            defer core.setCompression(false, 0, 0);

            var events: [EPOLL_MAX_EVENTS]linux.epoll_event = undefined;
            var epoll_timeout: i32 = -1;
            while (true) {
                const wait_rc = linux.epoll_wait(epfd, &events, EPOLL_MAX_EVENTS, epoll_timeout);
                switch (std.posix.errno(wait_rc)) {
                    .SUCCESS => {},
                    .INTR => continue,
                    else => return,
                }

                const event_count: usize = @intCast(wait_rc);
                if (event_count == 0) {
                    epoll_timeout = -1;
                    continue;
                }

                for (events[0..event_count]) |ev| {
                    if (ev.data.fd == listener_fd) {
                        acceptAll(&table, epfd, listener_fd, config.busy_poll_us);
                        continue;
                    }

                    if (tls_ctx) |tls_context| {
                        if (ev.data.fd == tls_listener_fd) {
                            tls_mux.acceptAll(&tls_table.?, epfd, tls_listener_fd, handler_fn, tls_context, tls_conn.tls_event_tag);
                            continue;
                        }
                        if (ev.data.u64 & tls_conn.tls_event_tag != 0) {
                            serveTlsEvent(&tls_table.?, epfd, ev, body_buf, out_buf);
                            continue;
                        }
                    }

                    const conn = table.get(ev.data.fd) orelse continue;
                    const outcome = if ((ev.events & (linux.EPOLL.HUP | linux.EPOLL.ERR)) != 0)
                        core.ConnOutcome.close
                    else if (conn.write_pending.len > conn.write_pending_off)
                        serveEpollWrite(conn, epfd)
                    else if (conn.drain > 0)
                        serveEpollDrainThenServe(handler_fn, conn, body_buf, out_buf, config.handler_timeout_ms, epfd, io, &req_arena)
                    else if (conn.ws) |on_frame|
                        serveEpollWs(conn, on_frame, body_buf, out_buf)
                    else
                        serveEpollConn(handler_fn, conn, body_buf, out_buf, config.handler_timeout_ms, epfd, io, &req_arena, true);

                    if (outcome == .close) {
                        _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_DEL, ev.data.fd, null);
                        table.free(ev.data.fd);
                        _ = linux.close(ev.data.fd);
                    }
                }

                epoll_timeout = 0;
            }
        }
    }.run;
}

pub fn runEpoll(config: Config, comptime handler_fn: HandlerFn) !void {
    const cpu = getAvailableCpuCount();
    const worker_count = if (config.workers == 0) cpu else config.workers;

    const threads = try std.heap.smp_allocator.alloc(std.Thread, worker_count);
    defer std.heap.smp_allocator.free(threads);

    // std.compress.flate.Compress is about 230 KB and is built on the handler's stack
    // frame, so a compressing handler (sendNegotiateCachedFD) needs more than the default
    // 512 KB worker stack. Thread stacks are demand-paged, so the larger limit costs
    // almost no RSS, and the bump applies only when compression is enabled.
    const worker_stack: usize = if (config.compress) @max(config.worker_stack_size_bytes, config.worker_stack_compress_bytes) else config.worker_stack_size_bytes;

    // CBPF steering: one shared bind-order gate, alive until join().
    var bind_gate = reuseport.BindOrderGate{};
    const steering: ?reuseport.Steering = if (config.reuseport_cbpf) .{ .gate = &bind_gate, .group_size = worker_count } else null;

    // What every worker says about its own listeners, so a bind that fails inside a worker thread
    // reaches this frame instead of ending that thread and nothing else.
    var report = listen_report.Report.init(worker_count);

    const worker = epollWorkerFn(handler_fn);
    for (threads, 0..) |*thread, worker_id| {
        thread.* = std.Thread.spawn(
            .{ .stack_size = worker_stack },
            worker,
            .{EpollWorkerCtx{ .config = config, .worker_id = worker_id, .steering = steering, .report = &report }},
        ) catch |err| {
            logSystem(config, .ERROR, "could not spawn worker {d} of {d} ({s})", .{ worker_id, worker_count, @errorName(err) });
            report.abandon(config.io, worker_count - worker_id, err);

            for (threads[0..worker_id]) |spawned| spawned.join();

            return error.ZixHttp1ListenFailed;
        };
    }

    if (report.awaitGroup(config.io)) |err| {
        logSystem(config, .ERROR, "not listening on {s}:{d}: {d} of {d} workers could not bind ({s})", .{ config.ip, config.port, report.failures(), worker_count, @errorName(err) });

        for (threads) |thread| thread.join();

        return error.ZixHttp1ListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is nothing
    // to announce: the old line claimed a listener that may never have come up.
    logSystem(config, .INFO, "listening on {s}:{d} (epoll, {d} workers, shared-nothing)", .{ config.ip, config.port, worker_count });
    if (config.tls != null and config.tls_port != 0)
        logSystem(config, .INFO, "dual listener: https/1.1 TLS on {s}:{d} (same workers)", .{ config.ip, config.tls_port });

    for (threads) |thread| thread.join();
}

fn testOkHandler(_: *core.Request, res: *core.Response, _: *core.Context) anyerror!void {
    res.setContentType(.TEXT_PLAIN);

    try res.send("ok");
}

fn testWsEcho(fd: std.posix.fd_t, opcode: u8, payload: []const u8) void {
    ws.sendFD(fd, @enumFromInt(opcode), payload) catch {};
}

test "zix http1: serveEpollConn answers a pipelined burst in order" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    // 16 pipelined requests arriving as one readable event.
    const request = "GET /pipeline HTTP/1.1\r\nHost: t\r\n\r\n";
    const depth = 16;
    var burst: [depth * request.len]u8 = undefined;
    for (0..depth) |i| {
        @memcpy(burst[i * request.len ..][0..request.len], request);
    }
    try std.testing.expectEqual(burst.len, std.os.linux.write(fds[0], &burst, burst.len));

    var conn_buf: [8 * 1024]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };
    var body_buf: [1024]u8 = undefined;
    var out_buf: [4 * 1024]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // epfd = -1: EPOLLOUT staging won't trigger for this burst (socketpair
    // buffer fits all 16 responses), so no epoll_ctl calls are made.
    const outcome = serveEpollConn(testOkHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, outcome);
    try std.testing.expectEqual(@as(usize, 0), conn.filled);

    // All 16 responses flushed in one coalesced write, parseable in order.
    var recv: [8 * 1024]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    try std.testing.expectEqual(@as(usize, depth), std.mem.count(u8, recv[0..n], "HTTP/1.1 200 OK\r\n"));
    try std.testing.expectEqual(@as(usize, depth), std.mem.count(u8, recv[0..n], "\r\n\r\nok"));
}

test "zix http1: EPOLL split head resumes the terminator scan from the watermark" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var conn_buf: [1024]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };
    var body_buf: [256]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // First event delivers a head with no terminator: nothing parses and the
    // watermark records how far the scan got (three bytes back, so a
    // terminator split across events is still found).
    const part1 = "GET /pipeline HTTP/1.1\r\nHost: t";
    try std.testing.expectEqual(part1.len, std.os.linux.write(fds[0], part1, part1.len));
    const first = serveEpollConn(testOkHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, first);
    try std.testing.expectEqual(part1.len, conn.filled);
    try std.testing.expectEqual(part1.len - 3, conn.scan_from);

    // The terminator arrives: the request completes and the watermark resets.
    const part2 = "\r\n\r\n";
    try std.testing.expectEqual(part2.len, std.os.linux.write(fds[0], part2, part2.len));
    const second = serveEpollConn(testOkHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, second);
    try std.testing.expectEqual(@as(usize, 0), conn.filled);
    try std.testing.expectEqual(@as(usize, 0), conn.scan_from);

    var recv: [1024]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    try std.testing.expect(std.mem.startsWith(u8, recv[0..n], "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, recv[0..n], "\r\n\r\nok"));
}

/// Echo the engine-counted received body size, so a test reads the value the
/// upload contract is built on rather than the Content-Length header.
fn testEchoReceivedHandler(req: *core.Request, res: *core.Response, _: *core.Context) anyerror!void {
    var buf: [48]u8 = undefined;
    const out = std.fmt.bufPrint(&buf, "{d}:{s}", .{ req.bodyReceived(), if (req.bodyComplete()) "whole" else "cut" }) catch return;

    res.setContentType(.TEXT_PLAIN);

    try res.send(out);
}

/// Read whatever is already waiting on a test socket, without blocking.
///
/// Note:
/// - A test that asserts on an answer has to fail when the answer is missing.
///   The server fd is still open at that point, so a blocking read would sit
///   there waiting for a byte that is never coming instead.
///
/// Param:
/// fd - std.posix.fd_t (the client side of the test pair)
/// buf - []u8 (scratch the bytes are read into)
///
/// Return:
/// - []u8 (the bytes available now, empty when there are none)
fn testReadNow(fd: std.posix.fd_t, buf: []u8) []u8 {
    const rc = std.os.linux.recvfrom(fd, buf.ptr, buf.len, std.os.linux.MSG.DONTWAIT, null, null);
    if (std.posix.errno(rc) != .SUCCESS) return buf[0..0];

    return buf[0..@intCast(rc)];
}

test "zix http1: EPOLL reports the counted body total for an over-large body" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    // Both event loops defer the handler until the drain finishes and hand it
    // the counted total, so the same request reports the same size on either.
    const fds = try core.testTcpPair();
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const body_len: usize = 4096;
    const head = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 4096\r\n\r\n";
    var body: [body_len]u8 = @splat('A');
    try std.testing.expectEqual(head.len, std.os.linux.write(fds[0], head, head.len));
    try std.testing.expectEqual(body_len, std.os.linux.write(fds[0], &body, body_len));

    var conn_buf: [256]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };
    var body_buf: [256]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Drive the event loop the way runEpoll does: the readable event parks the
    // head and arms the drain, then drain events run until the body is consumed
    // and the parked request is served with the counted total.
    const outcome = serveEpollConn(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, outcome);
    try std.testing.expectEqual(head.len, conn.pending_head_len);

    while (conn.drain > 0) {
        _ = serveEpollDrainThenServe(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena);
    }
    try std.testing.expectEqual(@as(usize, 0), conn.pending_head_len);

    var recv: [1024]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    try std.testing.expect(std.mem.endsWith(u8, recv[0..n], "\r\n\r\n4096:whole"));
}

test "zix http1: EPOLL never serves a request whose peer quit mid-drain" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    // The counterpart to .ASYNC reporting an incomplete body: this model does not
    // report one, it never invokes the handler at all. Nothing pinned that, and
    // a future edit could start serving the parked request on a hangup. The
    // client still gets an answer, which the last assertion pins.
    const fds = try core.testTcpPair();
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const head = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 4096\r\n\r\n";
    try std.testing.expectEqual(head.len, std.os.linux.write(fds[0], head, head.len));
    try std.testing.expectEqual(@as(usize, 10), std.os.linux.write(fds[0], "0123456789", 10));

    var conn_buf: [256]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };
    var body_buf: [256]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const served_before = tl_requests_served;

    // Event 1 parks the head and arms the drain.
    const first = serveEpollConn(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, first);
    try std.testing.expectEqual(head.len, conn.pending_head_len);
    try std.testing.expect(conn.drain > 0);

    // The peer goes away with the body unfinished.
    _ = std.os.linux.shutdown(fds[0], std.os.linux.SHUT.WR);

    const second = serveEpollDrainThenServe(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena);

    try std.testing.expectEqual(core.ConnOutcome.close, second);
    try std.testing.expectEqual(served_before, tl_requests_served);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_head_len);
    try std.testing.expectEqual(@as(usize, 0), conn.drain_received);

    var recv: [1024]u8 = undefined;
    try std.testing.expectStringStartsWith(testReadNow(fds[0], &recv), "HTTP/1.1 400 Bad Request\r\n");
}

test "zix http1: EPOLL answers 400 when the peer quits with a buffered request unfinished" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    // A body small enough to buffer never arms a drain, so it leaves by the
    // read-returned-zero path instead. The client must still be told, because a
    // silent close is what it cannot tell apart from a crash.
    const fds = try core.testTcpPair();
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const partial = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 100\r\n\r\nhello";
    try std.testing.expectEqual(partial.len, std.os.linux.write(fds[0], partial, partial.len));

    var conn_buf: [1024]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };
    var body_buf: [256]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const served_before = tl_requests_served;

    // Event 1 buffers head and the five body bytes, waiting for the other 95.
    const first = serveEpollConn(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, first);
    try std.testing.expectEqual(partial.len, conn.filled);
    try std.testing.expectEqual(@as(usize, 0), conn.drain);

    // The peer goes away with the other 95 never sent.
    _ = std.os.linux.shutdown(fds[0], std.os.linux.SHUT.WR);

    const second = serveEpollConn(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);

    try std.testing.expectEqual(core.ConnOutcome.close, second);
    try std.testing.expectEqual(served_before, tl_requests_served);

    var recv: [1024]u8 = undefined;
    const answer = testReadNow(fds[0], &recv);
    try std.testing.expectStringStartsWith(answer, "HTTP/1.1 400 Bad Request\r\n");
    try std.testing.expect(std.mem.indexOf(u8, answer, "Connection: close") != null);
}

test "zix http1: EPOLL closes an idle keep-alive connection without answering" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    // The other side of the rule above: a peer that leaves between requests owes
    // nothing and is owed nothing, so answering it would put a 400 on every
    // ordinary connection teardown.
    const fds = try core.testTcpPair();
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const req = "GET /ping HTTP/1.1\r\nHost: t\r\n\r\n";
    try std.testing.expectEqual(req.len, std.os.linux.write(fds[0], req, req.len));

    var conn_buf: [1024]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };
    var body_buf: [256]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const first = serveEpollConn(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, first);
    try std.testing.expectEqual(@as(usize, 0), conn.filled);

    var recv: [1024]u8 = undefined;
    try std.testing.expectStringStartsWith(testReadNow(fds[0], &recv), "HTTP/1.1 200 OK\r\n");

    // Nothing buffered when the peer leaves: the connection just ends.
    _ = std.os.linux.shutdown(fds[0], std.os.linux.SHUT.WR);

    const second = serveEpollConn(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);

    try std.testing.expectEqual(core.ConnOutcome.close, second);
    try std.testing.expectEqual(@as(usize, 0), testReadNow(fds[0], &recv).len);
}

test "zix http1: EPOLL drain consumes exactly the declared body so the pipelined request survives" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const fds = try core.testTcpPair();
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const body_len: usize = 4096;
    const head = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 4096\r\n\r\n";
    const follow = "GET /ping HTTP/1.1\r\nHost: t\r\n\r\n";
    var body: [body_len]u8 = @splat('A');
    try std.testing.expectEqual(head.len, std.os.linux.write(fds[0], head, head.len));
    try std.testing.expectEqual(body_len, std.os.linux.write(fds[0], &body, body_len));
    try std.testing.expectEqual(follow.len, std.os.linux.write(fds[0], follow, follow.len));

    var conn_buf: [256]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };
    var body_buf: [256]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Event 1 parks the POST head and arms the drain. Event 2 is the drain, which
    // must stop at the body end, answer the POST, and leave the GET on the socket.
    // Event 3 is the GET, which only parses when the drain neither over- nor
    // under-read.
    _ = serveEpollConn(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    const drained = serveEpollDrainThenServe(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, drained);
    try std.testing.expectEqual(@as(usize, 0), conn.drain);

    const second = serveEpollConn(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, second);

    var recv: [1024]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, recv[0..n], "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, recv[0..n], "\r\n\r\n0:whole"));
}

test "zix http1: EPOLL waits for a body that fits the buffer and then reports the full count" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const body_len: usize = 100;
    const head = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 100\r\n\r\n";
    var conn_buf: [1024]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };
    var body_buf: [256]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // The head arrives without its body: nothing is answered yet and the bytes
    // stay buffered for the next readable event.
    try std.testing.expectEqual(head.len, std.os.linux.write(fds[0], head, head.len));
    const first = serveEpollConn(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, first);
    try std.testing.expectEqual(head.len, conn.filled);
    try std.testing.expectEqual(@as(usize, 0), conn.drain);

    var body: [body_len]u8 = @splat('A');
    try std.testing.expectEqual(body_len, std.os.linux.write(fds[0], &body, body_len));
    const second = serveEpollConn(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, second);
    try std.testing.expectEqual(@as(usize, 0), conn.filled);

    var recv: [1024]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    try std.testing.expect(std.mem.endsWith(u8, recv[0..n], "\r\n\r\n100:whole"));
}

fn testCacheHandler(req: *core.Request, res: *core.Response, _: *core.Context) anyerror!void {
    if (core.cacheLookup(req.head)) |bytes| {
        try res.sendRaw(bytes);
        return;
    }

    return core.sendWithCacheFD(req.fd, req.head, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", core.cacheTtl());
}

test "zix http1: EPOLL refuses a declared body past the limit with 413" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    core.setMaxRequestBody(1024);
    defer core.setMaxRequestBody(0);

    // The declared length alone is enough to refuse, so the worker never arms a
    // drain for a body it was never going to accept.
    const head = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 65536\r\n\r\n";
    try std.testing.expectEqual(head.len, std.os.linux.write(fds[0], head, head.len));

    var conn_buf: [1024]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };
    var body_buf: [1024]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const outcome = serveEpollConn(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.close, outcome);
    try std.testing.expectEqual(@as(usize, 0), conn.drain);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_head_len);

    var recv: [512]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    try std.testing.expectStringStartsWith(recv[0..n], "HTTP/1.1 413 ");
}

test "zix http1: EPOLL sends 100 Continue once while the body is still arriving" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    // Head only: the client is waiting for the interim response before it sends
    // the body. The parse pass re-runs on every readable event until the body
    // lands, so the answer has to go out once, not once per event.
    const head = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n";
    try std.testing.expectEqual(head.len, std.os.linux.write(fds[0], head, head.len));

    var conn_buf: [1024]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };
    var body_buf: [1024]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const first = serveEpollConn(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, first);
    try std.testing.expect(conn.continue_sent);

    // A second event with the body: the request completes and the interim
    // response is not repeated.
    try std.testing.expectEqual(@as(usize, 4), std.os.linux.write(fds[0], "abcd", 4));
    const second = serveEpollConn(testEchoReceivedHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, second);
    try std.testing.expect(!conn.continue_sent);

    var recv: [512]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, recv[0..n], "HTTP/1.1 100 Continue\r\n\r\n"));
    try std.testing.expect(std.mem.startsWith(u8, recv[0..n], "HTTP/1.1 100 Continue\r\n\r\n"));
}

test "zix http1: EPOLL answers 400 on a malformed chunked body instead of waiting" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    // A chunk size that is not hex can never become valid by waiting. Treating it
    // as "not arrived yet" held the connection until the buffer filled and the
    // peer read as a hangup, with no answer sent.
    const req = "POST /u HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nab\r\n0\r\n\r\n";
    try std.testing.expectEqual(req.len, std.os.linux.write(fds[0], req, req.len));

    var conn_buf: [1024]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };
    var body_buf: [1024]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const outcome = serveEpollConn(testOkHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.close, outcome);

    var recv: [512]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    try std.testing.expect(std.mem.startsWith(u8, recv[0..n], "HTTP/1.1 400 "));
}

test "zix http1: EPOLL answers 413 for a chunked body past the body buffer" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const oversized: [64]u8 = @splat('A');
    const req = "POST /u HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n40\r\n".* ++ oversized ++ "\r\n0\r\n\r\n".*;
    try std.testing.expectEqual(req.len, std.os.linux.write(fds[0], &req, req.len));

    var conn_buf: [1024]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };

    // Decoded body larger than the worker's body buffer: it can never be served,
    // so the client is told rather than left waiting.
    var body_buf: [16]u8 = undefined;
    var out_buf: [1024]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const outcome = serveEpollConn(testOkHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.close, outcome);

    var recv: [512]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    try std.testing.expect(std.mem.startsWith(u8, recv[0..n], "HTTP/1.1 413 "));
}

test "zix http1: EPOLL path serves a miss then a hit from the cache" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var rc = try cache.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 256 });
    defer rc.deinit();

    core.setCache(&rc, 1000);
    defer core.setCache(null, 0);

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    // Two pipelined requests in one event: the first misses and stores, the
    // second hits the cache. Both responses are identical.
    const request = "GET /cached HTTP/1.1\r\nHost: t\r\n\r\n";
    var burst: [request.len * 2]u8 = undefined;
    @memcpy(burst[0..request.len], request);
    @memcpy(burst[request.len..], request);
    try std.testing.expectEqual(burst.len, std.os.linux.write(fds[0], &burst, burst.len));

    var conn_buf: [8 * 1024]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };
    var body_buf: [1024]u8 = undefined;
    var out_buf: [4 * 1024]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const outcome = serveEpollConn(testCacheHandler, &conn, &body_buf, &out_buf, 0, -1, undefined, &arena, true);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, outcome);

    var recv: [4 * 1024]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, recv[0..n], "HTTP/1.1 200 OK\r\n"));
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, recv[0..n], "\r\n\r\nhello"));

    // The entry is present for subsequent requests.
    const parsed = try core.parseHead(request);
    try std.testing.expect(core.cacheLookup(&parsed.head) != null);
}

test "zix http1: ConnTable inline slab alloc and free lifecycle" {
    var table = try ConnTable.init(256);
    defer table.deinit();

    try std.testing.expectEqual(@as(?*Conn, null), table.get(5));

    const conn = table.alloc(5).?;
    try std.testing.expectEqual(@as(std.posix.fd_t, 5), conn.fd);
    try std.testing.expectEqual(@as(usize, 256), conn.buf.len);

    const got = table.get(5).?;
    try std.testing.expectEqual(conn, got);

    table.free(5);
    try std.testing.expectEqual(@as(?*Conn, null), table.get(5));

    table.free(5);
}

test "zix http1: ConnTable slots read empty without an init memset (demand-paged)" {
    var table = try ConnTable.init(256);
    defer table.deinit();

    // The slots array is no longer memset, so this proves untouched slots across
    // the whole array still read as zero (empty), which is what keeps get()
    // correct while letting the array demand-page instead of being fully resident.
    for ([_]std.posix.fd_t{ 0, 1, 7, 100, 1000, 50000, MAX_FD - 1 }) |fd| {
        try std.testing.expectEqual(@as(?*Conn, null), table.get(fd));
    }
}

test "zix http1: ConnTable buf_size takes ws_recv_buf when larger" {
    var table = try ConnTable.init(512);
    defer table.deinit();

    const conn = table.alloc(3).?;
    try std.testing.expectEqual(@as(usize, 512), conn.buf.len);
}

test "zix http1: ConnTable packs recv buffers into compact slots, not the fd range" {
    var table = try ConnTable.init(4096);
    defer table.deinit();

    // Two connections on far-apart fds still draw adjacent low slab slots, so the
    // resident recv slab tracks the live count, not the fd values.
    const first = table.alloc(5000).?;
    const second = table.alloc(60000).?;

    const base = @intFromPtr(table.slab.ptr);
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(first.buf.ptr) - base);
    try std.testing.expectEqual(table.stride, @intFromPtr(second.buf.ptr) - base);

    // A closed slot returns to the free-list and is reused before a never-used one.
    table.free(5000);
    const reused = table.alloc(123).?;
    try std.testing.expectEqual(@as(usize, 0), @intFromPtr(reused.buf.ptr) - base);
}

test "zix http1: serveEpollWs drains pipelined frames to EAGAIN in one call" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]i32 = undefined;
    const linux = std.os.linux;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK, 0, &fds));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    // Two masked client text frames: "hi" (8 bytes) and "yo" (8 bytes) = 16 bytes total.
    const data = [_]u8{
        0x81, 0x82, 0x01, 0x02, 0x03, 0x04, 'h' ^ 0x01, 'i' ^ 0x02,
        0x81, 0x82, 0x05, 0x06, 0x07, 0x08, 'y' ^ 0x05, 'o' ^ 0x06,
    };
    try std.testing.expectEqual(data.len, linux.write(fds[0], &data, data.len));

    // conn.buf is 10 bytes: first read fills it (frame1 + 2 bytes of frame2),
    // pump extracts frame1, compact leaves 2 bytes, second read fetches the
    // remaining 6 bytes of frame2, pump extracts it. Third read yields EAGAIN.
    var conn_buf: [10]u8 = undefined;
    var conn = Conn{ .fd = fds[1], .buf = &conn_buf, .filled = 0 };
    var payload_buf: [128]u8 = undefined;
    var out_buf: [256]u8 = undefined;

    const outcome = serveEpollWs(&conn, testWsEcho, &payload_buf, &out_buf);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, outcome);
    try std.testing.expectEqual(@as(usize, 0), conn.filled);

    // Both echo frames arrive coalesced on fds[0].
    var recv: [128]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);

    var scratch: [128]u8 = undefined;
    const first = ws.parseFrame(recv[0..n], &scratch).?;
    try std.testing.expectEqualStrings("hi", first.frame.payload);

    const second = ws.parseFrame(recv[first.consumed..n], &scratch).?;
    try std.testing.expectEqualStrings("yo", second.frame.payload);
}

test "zix http1: EPOLL WritePendingPool recycles a released buffer instead of reallocating" {
    var pool = WritePendingPool{};
    defer pool.deinit();

    // First acquire allocates, release returns it to the free-list, the next acquire hands back the
    // very same buffer with no new allocation. That reuse is the whole point on a backpressure burst.
    const first = pool.acquire(EPOLL_OUT_BUF_SIZE).?;
    try std.testing.expectEqual(@as(usize, EPOLL_OUT_BUF_SIZE), first.len);

    pool.release(first);
    try std.testing.expectEqual(@as(usize, 1), pool.counts[WRITE_STAGE_CLASSES.len - 1]);

    const second = pool.acquire(EPOLL_OUT_BUF_SIZE).?;
    try std.testing.expectEqual(first.ptr, second.ptr);
    try std.testing.expectEqual(@as(usize, 0), pool.counts[WRITE_STAGE_CLASSES.len - 1]);

    pool.release(second);
}

test "zix http1: EPOLL WritePendingPool sizes a staging buffer to the smallest fitting class" {
    var pool = WritePendingPool{};
    defer pool.deinit();

    // A tiny remainder (the common small-response stall) draws the smallest class, not the 64 KiB
    // sink. That is what keeps a high-connection backpressure burst from pinning a full sink each.
    const small = pool.acquire(200).?;
    try std.testing.expectEqual(WRITE_STAGE_CLASSES[0], small.len);

    // A remainder between classes rounds up to the next class that holds it.
    const mid = pool.acquire(WRITE_STAGE_CLASSES[0] + 1).?;
    try std.testing.expectEqual(WRITE_STAGE_CLASSES[1], mid.len);

    // Release routes each buffer back to its own class free-list by length.
    pool.release(small);
    pool.release(mid);
    try std.testing.expectEqual(@as(usize, 1), pool.counts[0]);
    try std.testing.expectEqual(@as(usize, 1), pool.counts[1]);
}

test "zix http1: EPOLL WritePendingPool frees beyond the cap instead of growing unbounded" {
    var pool = WritePendingPool{};
    defer pool.deinit();

    // Fill the largest class free-list to the cap.
    var i: usize = 0;
    while (i < WRITE_POOL_CAP) : (i += 1) {
        const buf = std.heap.smp_allocator.alloc(u8, EPOLL_OUT_BUF_SIZE) catch unreachable;
        pool.release(buf);
    }
    try std.testing.expectEqual(WRITE_POOL_CAP, pool.counts[WRITE_STAGE_CLASSES.len - 1]);

    // One more release is freed directly (release owns it past the cap), so the pool never grows past
    // the cap and the buffer is not leaked.
    const extra = std.heap.smp_allocator.alloc(u8, EPOLL_OUT_BUF_SIZE) catch unreachable;
    pool.release(extra);
    try std.testing.expectEqual(WRITE_POOL_CAP, pool.counts[WRITE_STAGE_CLASSES.len - 1]);
}
