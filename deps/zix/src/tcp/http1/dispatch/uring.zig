//! zix http1 .URING (io_uring) dispatch model.

const std = @import("std");
const builtin = @import("builtin");
const Config = @import("../config.zig").Http1ServerConfig;
const core = @import("../core.zig");
const cache = @import("../../../utils/response_cache.zig");
const ws = @import("../websocket.zig");
const uring = @import("../../../multiplexers/ring.zig");
const ring_wait = @import("../../../multiplexers/ring_wait.zig");
const slab = @import("../../../multiplexers/slab.zig");
const tls_mux = @import("../tls_mux.zig");
const tls_conn = @import("../../../multiplexers/tls_conn.zig");
const reuseport = @import("../../../multiplexers/reuseport.zig");
const listen_report = @import("../../../multiplexers/listen_report.zig");
const Tls = @import("../../../tls/Tls.zig");
const HandlerFn = core.HandlerFn;
const IoUring = std.os.linux.IoUring;
const common = @import("common.zig");
const epoll_model = @import("epoll.zig");
const logSystem = common.logSystem;
const setNoDelay = common.setNoDelay;
const pinToCpu = common.pinToCpu;
const getAvailableCpuCount = common.getAvailableCpuCount;
const decodeChunkedInBuf = core.decodeChunkedInBuf;
const parseGetFastPath = common.parseGetFastPath;
const effectiveCacheEntries = common.effectiveCacheEntries;
const MAX_FD = common.MAX_FD;

// --------------------------------------------------------- //
// URING model: shared-nothing io_uring, one ring + listener per worker (ADR-037).
// Minimal correct core: multishot accept, an fd-indexed slot table with a
// generation-tagged user_data against fd reuse, a fixed per-connection recv
// buffer with a plain recv SQE (data lands directly in conn.buf, zero copy),
// one coalesced send per readable batch, and a batched CQE drain. Half-duplex
// per connection (at most one recv or one send in flight), so a blocking sink
// flush can never interleave with an in-flight send.
//
// 1. ring setup flags (SINGLE_ISSUER | DEFER_TASKRUN): measured null on the
//    12-core loopback box, but the reference ring engines run with them at
//    scale, so they are applied here behind a kernel-version probe with a
//    flagless fallback (initUringRing). Costless where the kernel lacks them,
//    and matches the reference engines' single-issuer fast path otherwise.
// 2. multishot recv + provided buffer ring: REVERTED, a regression. It forces a
//    memcpy from the kernel-selected buffer into conn.buf for accumulation, and
//    that copy (largest at pipeline depth 16) outweighs the multishot re-arm
//    saving the plain recv-into-conn.buf path avoids by receiving in place.

/// SQ entries per worker ring.
const URING_ENTRIES: u16 = 4096;

/// CQ entries per worker ring. Multishot accept plus a coalesced send per
/// readable batch can land many completions per enter at high connection
/// counts, so the completion queue is requested larger than the default (2x SQ)
/// via IORING_SETUP_CQSIZE to leave overflow headroom.
const URING_CQ_ENTRIES: u32 = 16 * 1024;

/// Max CQEs drained per loop pass.
const URING_CQE_BATCH: usize = 512;

/// Intra-batch submit stride: while dispatching a completion batch, staged
/// send SQEs are pushed to the kernel every this many completions instead of
/// only at the loop top. In a deep batch (hundreds of readable connections
/// per pass) the last response otherwise waits for every earlier request's
/// dispatch before its bytes even reach the kernel, which multiplies
/// per-request dispatch cost into closed-loop latency. One extra enter per
/// stride is noise next to that wait.
const URING_INTRA_SUBMIT: usize = 16;

/// Intra-batch submit floor: batches shallower than this skip the stride
/// entirely. A shallow batch drains in microseconds, so the early release
/// buys nothing there and the extra enters tax the high-rate low-concurrency
/// cells. Only deep batches carry the millisecond-scale wait the stride cuts.
const URING_INTRA_SUBMIT_MIN_BATCH: usize = 128;

/// Ceiling for the adaptive completion-wait: a hot loop waits for up to this
/// many completions per enter (bounded by the coalesce window) so wakeups
/// amortize instead of firing once per completion. A cooling loop decays back
/// to single-completion waits within a pass.
const URING_WAIT_COALESCE_MAX: u32 = 32;

/// Coalesce window in nanoseconds, the deadline on a wait_nr > 1 pass: a batch
/// shorter than wait_nr is never held past this. Far below any request round
/// trip, far above the enter cost it amortizes.
const URING_WAIT_COALESCE_NS: i64 = 20_000;

/// Per-connection staged-response buffer. Since URING is fully async (unlike
/// EPOLL), each connection needs its own buffer. 16 KiB easily covers the max
/// response (~12 KiB for `/json`) plus a tiny pipelined burst. Dropping this
/// from EPOLL's 64 KiB saves 48 KiB/conn, which is critical for memory limits
/// at high concurrency. A response larger than this grows send_buf up to
/// URING_SEND_BUF_MAX so it still leaves as one on-ring send.
const URING_SEND_BUF_SIZE: usize = 16 * 1024;

/// Hard ceiling for a grown per-connection send buffer. A handler emitting a
/// single response (or a coalesced pipelined batch) larger than
/// URING_SEND_BUF_SIZE grows send_buf up to this cap so the response still goes
/// out as one on-ring send, instead of a blocking off-ring write that would
/// stall every connection on the worker. Past the cap the core sink falls back
/// to a direct flush. 1 MiB covers any realistic inline response while bounding
/// worst-case per-connection memory.
const URING_SEND_BUF_MAX: usize = 1024 * 1024;

/// Idle-pool warm floor. The minimum number of closed connections' slab strides
/// kept warm (pages resident) when the worker is otherwise idle, so a trickle of
/// new connections after a quiet spell still lands on resident pages. Also the
/// number of strides pretouched at startup. The effective warm cap is clamped
/// between this floor and URING_IDLE_POOL_CEILING, see UringWorker.idleCap.
const URING_IDLE_POOL_FLOOR: usize = 8;

/// Idle-pool warm ceiling. The absolute upper bound on warm free strides per
/// worker, regardless of live concurrency. The earlier cap tracked live_count, so
/// at very high concurrency (thousands of live connections on one worker) the pool
/// kept a full reconnect of the working set warm: that doubled the resident set
/// (recv plus send buffers for every warm connection on top of the live ones) and
/// the L2/L3 plus TLB pressure cost more throughput than the spared allocations
/// won back. A few hundred warm strides already absorb steady churn, so the
/// ceiling holds the warm set below live_count where it would otherwise blow up,
/// and the rest is returned to the OS through releaseSlot's eviction. See idleCap.
const URING_IDLE_POOL_CEILING: usize = 256;

/// io_uring SQPOLL kernel-thread idle before it sleeps, in milliseconds. Inert
/// unless IORING_SETUP_SQPOLL is set (it is not here), kept for when it is.
const URING_SQ_THREAD_IDLE_MS: u32 = 1000;

/// Initialize a worker ring with the single-issuer fast-path flags, falling
/// back to a flagless ring when the kernel does not support them.
///
/// Note:
/// - SINGLE_ISSUER and DEFER_TASKRUN cut enter-time task-run overhead on a
///   one-thread-per-ring loop (kernel >= 6.1, and the ring is created,
///   submitted, and reaped on this one worker thread). CQSIZE enlarges the
///   completion queue to URING_CQ_ENTRIES and CLAMP keeps the requested sizes
///   within the kernel maximum. On an older kernel init_params returns an
///   error, so the flagless init is the correct fallback (the same fallback the
///   reference ring engines ship).
///
/// Return:
/// - IoUring on success
/// - error only when the flagless fallback also fails (no ring possible)
fn initUringRing() !IoUring {
    const linux = std.os.linux;
    var params = std.mem.zeroInit(linux.io_uring_params, .{
        .flags = linux.IORING_SETUP_SINGLE_ISSUER |
            linux.IORING_SETUP_DEFER_TASKRUN |
            linux.IORING_SETUP_CQSIZE |
            linux.IORING_SETUP_CLAMP,
        .cq_entries = URING_CQ_ENTRIES,
        .sq_thread_idle = URING_SQ_THREAD_IDLE_MS,
    });

    return IoUring.init_params(URING_ENTRIES, &params) catch return IoUring.init(URING_ENTRIES, 0);
}

/// WebSocket provided-buffer ring (ADR-037 Phase 4b). One ring per worker,
/// shared by every WebSocket connection, so an idle connection holds no recv
/// buffer: the kernel hands one over only when a frame actually arrives. That is
/// the memory-scaling win at high connection counts, and parsing in place out of
/// the selected buffer keeps the common whole-frame path zero-copy.
const WS_RING_BGID: u16 = 1;

const WS_RING_BUF_SIZE: u32 = 4096;

const WS_RING_BUF_COUNT: u16 = 256;

/// Per-connection ring state, stored inline in the fd-indexed slot table (an
/// empty slot reads as buf.len == 0). buf accumulates request (or frame) bytes
/// between recv completions. The staged window send_buf[staged_off..][0..staged]
/// is owned by the kernel while a send SQE is outstanding (inflight > 0), and a
/// short send advances staged_off past the sent prefix. closing marks a
/// connection that must be freed once the last send lands. ws is set once the
/// connection upgrades to WebSocket: from then on buf holds frame bytes and the
/// recv loop pumps frames instead of parsing HTTP.
const UringConn = struct {
    fd: std.posix.fd_t,
    gen: u24,
    buf: []u8,
    filled: usize,
    send_buf: []u8,
    staged: usize,
    /// Start offset of the staged bytes in send_buf. Nonzero only for a
    /// reserve-committed response (the sink's dead prefix before the
    /// right-aligned header), and after a short send (the sent prefix).
    staged_off: usize = 0,
    inflight: usize,
    closing: bool,
    /// Compact buffer-slab slot backing buf and send_buf, returned to the
    /// free-list on close so the resident slab packs to the live connection
    /// count and every run lays the working set out identically.
    slot: u32 = 0,
    /// send_buf was switched to a heap buffer by the sink's grow path (an
    /// oversized response). Freed on close: the next connection on this slot
    /// starts from the slab slice again.
    send_heap: bool = false,
    /// Zero-copy cache replay in flight: the outstanding send references these
    /// borrowed cache-slab bytes (send_buf stages nothing), and the pinned
    /// slot is released when the send completes or the connection tears down.
    direct: []const u8 = &.{},
    direct_slot: u32 = 0,
    /// Scan watermark for a split request head: bytes of buf already searched
    /// for the header terminator by an earlier recv completion, so the next
    /// completion resumes the scan instead of rescanning from zero.
    scan_from: usize = 0,
    /// Request-body bytes still to read and discard off the socket for a body
    /// too large to buffer. While > 0 the connection is draining, not parsing
    /// requests, and the handler invoke waits for the drain to finish.
    drain: usize = 0,
    /// Body bytes of the draining request consumed off the socket so far
    /// (buffered prefix plus drained remainder), served to the deferred
    /// handler as the received count.
    drain_received: usize = 0,
    /// Head bytes kept at the front of buf while the body drains. > 0 marks a
    /// request whose handler invoke is deferred to drain completion.
    pending_head_len: usize = 0,
    /// Whether 100 Continue was already sent for the request currently being
    /// parsed. The parse pass re-runs on every recv completion while a body is
    /// still arriving, and the client only needs to be told once.
    continue_sent: bool = false,
    ws: ?core.WsFrameFn = null,
};

/// Stage what a peer gets when it hangs up part way through a request, so the
/// close that follows carries a status instead of nothing.
///
/// Note:
/// - Bytes left in buf, or a head parked on a drain that can now never reach
///   zero, are a request that never finished arriving. The client is told the
///   request was refused, because a bare close reads the same to it as a crash,
///   a timeout, or a dropped connection.
/// - An idle keep-alive connection has neither and closes without a byte, which
///   is the ordinary end of a connection and not an error.
/// - Staged rather than written to the fd, so the worker never blocks on a send
///   buffer that is full. beginClose submits it and the close follows the send.
/// - Nothing is staged on a negative result (the socket is already dead), on a
///   WebSocket connection (a status line is not a frame), or when send_buf is
///   already carrying a response.
///
/// Param:
/// conn - *UringConn (the connection whose recv just completed)
/// recv_res - i32 (the recv cqe result, 0 for a clean hangup)
///
/// Return:
/// - bool (true when an answer was staged in conn.send_buf)
fn stageHangupAnswer(conn: *UringConn, recv_res: i32) bool {
    if (recv_res != 0 or conn.ws != null) return false;
    if (conn.filled == 0 and conn.pending_head_len == 0) return false;
    if (conn.staged > 0 or conn.direct.len > 0) return false;

    const answer = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    if (answer.len > conn.send_buf.len) return false;

    @memcpy(conn.send_buf[0..answer.len], answer);
    conn.staged_off = 0;
    conn.staged = answer.len;

    return true;
}

/// Which re-arm a parked process-queue entry retries.
const ParkKind = enum(u8) { recv, drain_recv, send, external };

/// Postponed re-arm reference for the process queue (config.process_queue_len).
/// Holds no request bytes: the connection's own buffers keep the data, the
/// entry only records which arm to retry once the submission queue has space.
/// The generation guards against fd reuse, a stale entry is skipped.
const ParkEntry = struct {
    fd: std.posix.fd_t,
    gen: u24,
    kind: ParkKind,
};

/// Ring-hosted TLS connection (dual listener, config.tls_port): the shared TLS connection
/// (tls_mux) plus ring bookkeeping. The ciphertext recv buffer is per connection because the
/// kernel fills it asynchronously (the .EPOLL paths read into per-event stack staging instead).
const UringTlsConn = struct {
    conn: tls_mux.TlsConn,
    gen: u24,
    cipher_buf: []u8,
};

fn freeUringTlsConn(ring_conn: *UringTlsConn) void {
    ring_conn.conn.transport.deinit();
    std.heap.smp_allocator.free(ring_conn.cipher_buf);
    std.heap.smp_allocator.destroy(ring_conn);
}

/// Per-worker fd -> UringTlsConn map for the dual-listener TLS side.
const TlsConnTable = tls_conn.ConnTable(UringTlsConn, MAX_FD, freeUringTlsConn);

/// Build a concrete io_uring worker with the handler and optional raw
/// interceptor baked in at compile time, mirroring epollWorkerFn.
fn UringWorker(comptime handler_fn: HandlerFn) type {
    return struct {
        ring: IoUring,
        /// fd-indexed inline connection table (mapZeroedSlots, demand-paged).
        /// An empty slot reads as buf.len == 0, mirroring the EPOLL ConnTable.
        slots: []UringConn,
        listener_fd: std.posix.fd_t,
        gen_counter: u24,
        recv_buf_size: usize,
        /// Per-connection send buffer size, set from config.uring_send_buf_size.
        /// Defaulted to the module const so dispatch-level tests need not set it.
        send_buf_size: usize = URING_SEND_BUF_SIZE,
        handler_timeout_ms: u32,
        /// SO_BUSY_POLL window applied to each accepted connection, set from config.busy_poll_us.
        /// Defaulted to 0 so dispatch-level tests need not set it (EPOLL parity).
        busy_poll_us: u32 = 0,
        /// Shared per-worker scratch for unmasking WebSocket frame payloads
        /// during a pump pass. Used transiently, never held across calls.
        ws_payload_buf: []u8,
        /// Shared per-worker scratch holding a decoded chunked request body while
        /// the handler runs. Sized to the recv buffer (a chunked body must be
        /// fully present in conn.buf to decode, so its decoded form never exceeds
        /// that). Used transiently, never held across calls.
        body_buf: []u8,
        /// Shared provided-buffer ring for WebSocket recvs (Phase 4b). null when
        /// the kernel does not support buffer rings: WebSocket then falls back to
        /// the plain recv-into-conn.buf path (4a).
        ws_bufs: ?IoUring.BufferGroup,
        /// One contiguous buffer slab for every connection's recv and send
        /// buffer, carved into page-multiple strides (recv + send back to back).
        /// A connection draws a compact slot from the free-list on accept, so
        /// the accept/close cycle does zero allocator calls and the hot working
        /// set occupies the same addresses on every run. Mirrors the EPOLL
        /// recv slab, extended with the per-connection send buffer URING needs.
        conn_slab: []u8 = &.{},
        /// Slab bytes per slot: recv_buf_size + send_buf_size rounded up to a
        /// page, so a released slot's pages reclaim without touching a live
        /// neighbor slot.
        stride: usize = 0,
        /// Stack of closed slot indices available for reuse, newest (warmest) on
        /// top, so steady churn recycles the same resident strides.
        free_slots: []u32 = &.{},
        free_count: usize = 0,
        /// Boundary inside free_slots: entries below it are cold (their slab
        /// pages were returned to the OS with MADV_DONTNEED), entries at or
        /// above it are warm (pages resident). When the warm span outgrows
        /// idleCap the oldest warm entry is advised away, which is the LRU
        /// eviction of the old linked pool with the same memory discipline.
        cold_count: usize = 0,
        /// Next never-used slot index. Slots are handed out compactly from 0,
        /// so the touched slab prefix bounds the resident buffer memory.
        slot_top: usize = 0,
        /// Live connections currently held in the slot table (this worker's
        /// concurrency). Incremented when an accepted connection installs into a
        /// slot, decremented when it is torn down. The warm idle-pool cap is
        /// derived from this so the pool always covers the active working set
        /// regardless of how many workers split the host, see idleCap.
        live_count: usize = 0,
        /// Minimum warm pool floor. See URING_IDLE_POOL_FLOOR. A field (not the
        /// constant directly) so tests can drive the eviction path with a small
        /// pool.
        idle_floor: usize = URING_IDLE_POOL_FLOOR,
        /// Absolute warm pool ceiling. See URING_IDLE_POOL_CEILING. A field (not
        /// the constant directly) so tests can drive the cap with a small pool and
        /// the entry can tune it for the host concurrency.
        idle_ceiling: usize = URING_IDLE_POOL_CEILING,
        /// Dual-listener TLS side (config.tls + config.tls_port). Inactive by default (-1 / null),
        /// so a cleartext-only worker sees zero layout change on its hot structures.
        tls_listener_fd: std.posix.fd_t = -1,
        tls_ctx: ?*Tls.Context = null,
        tls_conns: ?TlsConnTable = null,
        tls_gen_counter: u24 = 0,
        /// Per-worker scratch for the TLS WebSocket frame pump (coalesced echo frames).
        tls_out_buf: []u8 = &.{},
        /// Requests served by this worker (cleartext dispatch). Single-owner plain
        /// increment (no contention), reported through the system logger at worker
        /// exit so REUSEPORT skew across workers is measurable.
        requests_served: u64 = 0,
        /// The worker io, handed to the handler trio (ctx.io) for an inline driver
        /// call. Defaulted so dispatch-level tests that never touch it can omit it.
        io: std.Io = undefined,
        /// Per-request scratch arena for the handler trio, reset before each
        /// dispatch. A pointer to the run-scope arena so the worker stays movable.
        req_arena: *std.heap.ArenaAllocator = undefined,
        /// The multishot accept re-arm was lost to a full SQ. Retried at the top
        /// of the next loop pass. Without this a full SQ at re-arm time stopped
        /// the worker from ever accepting again while the kernel backlog filled.
        accept_pending: bool = false,
        /// Same lost-re-arm guard for the dual-listener TLS accept.
        tls_accept_pending: bool = false,
        /// Process queue (config.process_queue_len): FIFO ring of postponed
        /// re-arm references, preallocated once at startup. Empty = feature off.
        /// When full the newest entry is rejected (the connection falls back to
        /// the close path), so parked work always drains in arrival order.
        park_entries: []ParkEntry = &.{},
        /// Ring read position of the oldest parked entry.
        park_head: usize = 0,
        /// Parked entries currently in the ring.
        park_len: usize = 0,

        const Self = @This();
        const allocator = std.heap.smp_allocator;
        const linux = std.os.linux;

        fn deinit(self: *Self) void {
            for (self.slots) |*conn| {
                if (conn.buf.len == 0) continue;

                _ = linux.close(conn.fd);
                if (conn.send_heap) allocator.free(conn.send_buf);
            }

            slab.unmapSlots(self.slots);
            if (self.conn_slab.len > 0) slab.unmapSlots(self.conn_slab);
            if (self.free_slots.len > 0) allocator.free(self.free_slots);
            if (self.park_entries.len > 0) allocator.free(self.park_entries);
            allocator.free(self.ws_payload_buf);
            allocator.free(self.body_buf);
            if (self.ws_bufs) |*bg| bg.deinit(allocator);
            if (self.tls_conns) |*tls_table| tls_table.deinit();
            if (self.tls_out_buf.len > 0) allocator.free(self.tls_out_buf);
            self.ring.deinit();
        }

        /// Get an SQE, submitting the staged batch first when the SQ is full.
        fn getSqe(self: *Self) ?*linux.io_uring_sqe {
            return self.ring.get_sqe() catch {
                _ = self.ring.submit() catch return null;

                return self.ring.get_sqe() catch null;
            };
        }

        fn lookup(self: *Self, decoded: uring.Decoded) ?*UringConn {
            return self.lookupFd(decoded.fd, decoded.gen);
        }

        /// Slot lookup by fd + generation. An empty slot (buf.len == 0) or a
        /// mismatched generation means the fd was closed (and possibly reused),
        /// so the reference is stale and must be ignored.
        fn lookupFd(self: *Self, fd: std.posix.fd_t, gen: u24) ?*UringConn {
            const idx: usize = @intCast(fd);
            if (idx >= self.slots.len) return null;

            const conn = &self.slots[idx];
            if (conn.buf.len == 0 or conn.gen != gen) return null;

            return conn;
        }

        /// Park a postponed re-arm on the process queue (FIFO ring).
        ///
        /// Return:
        /// - true when parked
        /// - false when the feature is off (empty ring) or the ring is full
        ///   (reject-newest, the caller falls back to the close path)
        fn parkPush(self: *Self, kind: ParkKind, fd: std.posix.fd_t, gen: u24) bool {
            if (self.park_entries.len == 0) return false;
            if (self.park_len == self.park_entries.len) return false;

            const tail = (self.park_head + self.park_len) % self.park_entries.len;
            self.park_entries[tail] = .{ .fd = fd, .gen = gen, .kind = kind };
            self.park_len += 1;

            return true;
        }

        /// Pop the oldest parked entry, or null when the ring is empty.
        fn parkPop(self: *Self) ?ParkEntry {
            if (self.park_len == 0) return null;

            const entry = self.park_entries[self.park_head];
            self.park_head = (self.park_head + 1) % self.park_entries.len;
            self.park_len -= 1;

            return entry;
        }

        /// Retry postponed work once the SQ has space again: the lost accept
        /// re-arms first (a lost accept stalls the worker permanently), then the
        /// parked entries in FIFO order. Runs at the top of each loop pass,
        /// right after submit_and_wait pushed the staged SQEs to the kernel.
        /// Stops as soon as a retry re-parks (the SQ filled up again), the
        /// remaining entries wait for the next pass. Stale entries (gen
        /// mismatch after a close and fd reuse) are dropped as no-ops.
        fn drainParked(self: *Self) void {
            if (self.accept_pending) {
                self.accept_pending = false;
                self.armAccept();
                if (self.accept_pending) return;
            }

            if (self.tls_accept_pending) {
                self.tls_accept_pending = false;
                self.armTlsAccept();
                if (self.tls_accept_pending) return;
            }

            var budget = self.park_len;
            while (budget > 0) : (budget -= 1) {
                const entry = self.parkPop() orelse return;
                const before = self.park_len;

                // External watches carry no connection slot: re-arm directly.
                if (entry.kind == .external) {
                    _ = watchExternal(self, entry.fd);
                    if (self.park_len > before) return;

                    continue;
                }

                const conn = self.lookupFd(entry.fd, entry.gen) orelse continue;
                switch (entry.kind) {
                    .recv => self.armRecv(conn),
                    .drain_recv => self.armDrainRecv(conn),
                    .send => self.submitSend(conn),
                    .external => unreachable,
                }

                if (self.park_len > before) return;
            }
        }

        /// The slab stride backing a slot: recv buffer then send buffer, padded
        /// to the page-multiple stride so a released slot reclaims cleanly.
        fn slotStride(self: *Self, slot: u32) []u8 {
            return self.conn_slab[@as(usize, slot) * self.stride ..][0..self.stride];
        }

        fn slotRecvBuf(self: *Self, slot: u32) []u8 {
            return self.slotStride(slot)[0..self.recv_buf_size];
        }

        fn slotSendBuf(self: *Self, slot: u32) []u8 {
            return self.slotStride(slot)[self.recv_buf_size..][0..self.send_buf_size];
        }

        /// Draw a compact buffer-slab slot for a freshly accepted fd: reuse the
        /// newest freed slot (warmest, pages most likely resident), else take
        /// the next never-used slot. Null when the slab is exhausted (every
        /// slot live). No allocator call on any path.
        fn acquireSlot(self: *Self) ?u32 {
            if (self.free_count > 0) {
                self.free_count -= 1;
                if (self.cold_count > self.free_count) self.cold_count = self.free_count;

                return self.free_slots[self.free_count];
            }

            if ((self.slot_top + 1) * self.stride > self.conn_slab.len) return null;

            const slot: u32 = @intCast(self.slot_top);
            self.slot_top += 1;

            return slot;
        }

        /// Return a closed connection's slot to the free-list (warm, on top),
        /// then trim the oldest warm free slot past the cap: its stride pages go
        /// back to the OS with MADV_DONTNEED and the entry crosses the cold
        /// boundary. That is the LRU-tail eviction of the old linked pool, so
        /// the slot a churn accept is about to reuse is never the one reclaimed,
        /// and resident memory still tracks live connections.
        fn releaseSlot(self: *Self, slot: u32) void {
            self.free_slots[self.free_count] = slot;
            self.free_count += 1;

            if (self.free_count - self.cold_count > self.idleCap()) {
                slab.releaseSlabPages(self.slotStride(self.free_slots[self.cold_count]));
                self.cold_count += 1;
            }
        }

        /// Pretouch the first idle_floor strides of the buffer slab so the first
        /// accept burst runs on resident pages instead of first-touch faulting
        /// them under load, and the touched layout is identical on every run.
        /// Replaces the old allocation-based pool seeding: the slab needs no
        /// seeded objects, residency is the only startup cost left to pay.
        fn pretouchSlab(self: *Self) void {
            if (self.stride == 0) return;

            const strides = @min(self.idle_floor, self.conn_slab.len / self.stride);
            slab.pretouch(self.conn_slab[0 .. strides * self.stride]);
        }

        /// Warm free-slot cap. The warm span tracks live concurrency so steady
        /// churn finds a resident stride on top of the free stack, but it is
        /// clamped on both ends: the floor keeps a small warm reserve when the
        /// worker is idle, and the ceiling bounds the warm set so it never holds
        /// a full reconnect of a large working set resident. At low concurrency
        /// the cap is live_count (or the floor when idle). At high concurrency
        /// the ceiling holds the warm set below live_count, which is where an
        /// unclamped cap doubled the resident set and cost throughput.
        fn idleCap(self: *const Self) usize {
            return @min(self.idle_ceiling, @max(self.live_count, self.idle_floor));
        }

        /// Tear down a closed connection: free a heap-grown send buffer, hand
        /// the slab slot back (releaseSlot applies the warm cap and the page
        /// discipline), and zero the fd slot so it reads empty. No allocator
        /// call on the common path.
        fn destroyConn(self: *Self, conn: *UringConn) void {
            if (conn.direct.len > 0) {
                if (core.tl_cache) |resp_cache| resp_cache.unpin(conn.direct_slot);
            }
            if (conn.send_heap) allocator.free(conn.send_buf);
            self.live_count -= 1;
            if (self.free_slots.len > 0) self.releaseSlot(conn.slot);

            conn.* = std.mem.zeroes(UringConn);
        }

        /// Tear a connection down via a ring close (prep_close) instead of a
        /// synchronous linux.close on the worker thread. Under connection churn
        /// (short-lived and limited-keep-alive requests) teardown happens once
        /// per few requests, and a blocking close syscall on the hot loop kept
        /// the worker from reaping other completions while it ran, leaving cores
        /// idle. Handing the close to the kernel lets the worker keep draining
        /// CQEs. The slot is cleared first, so the .close CQE carries no
        /// connection and the loop ignores it. The kernel does not reuse the fd
        /// integer until the close actually runs, so no in-flight op (none is
        /// outstanding here anyway, the path is half-duplex) can target it.
        fn finishClose(self: *Self, conn: *UringConn) void {
            const fd = conn.fd;
            self.destroyConn(conn);

            const sqe = self.getSqe() orelse {
                // SQ momentarily full: close synchronously so the fd is never
                // leaked, then return.
                _ = linux.close(fd);
                return;
            };

            sqe.prep_close(fd);
            sqe.user_data = uring.packUserData(.close, 0, fd);
        }

        /// Close intent: flush staged bytes first when possible, otherwise free
        /// now. With a send in flight the free is deferred to the send CQE.
        fn beginClose(self: *Self, conn: *UringConn) void {
            conn.closing = true;
            if (conn.inflight > 0) return;

            if (conn.staged > 0 or conn.direct.len > 0) {
                self.submitSend(conn);
                return;
            }

            self.finishClose(conn);
        }

        fn armAccept(self: *Self) void {
            const sqe = self.getSqe() orelse {
                // SQ full even after a submit: mark the re-arm pending so the
                // loop retries next pass. Losing it stops accepting for good.
                self.accept_pending = true;
                return;
            };

            sqe.prep_multishot_accept(self.listener_fd, null, null, 0);
            sqe.user_data = uring.packUserData(.accept, 0, self.listener_fd);
        }

        fn armRecv(self: *Self, conn: *UringConn) void {
            if (conn.filled >= conn.buf.len) {
                self.beginClose(conn);
                return;
            }

            // WebSocket reads come off the shared provided-buffer ring when it is
            // available, so an idle connection ties up no recv buffer.
            if (conn.ws != null) {
                if (self.ws_bufs) |*bg| {
                    self.armWsRecv(conn, bg);
                    return;
                }
            }

            const sqe = self.getSqe() orelse {
                // SQ full: park the re-arm on the process queue when it is on
                // (retried next pass), otherwise keep the close behavior.
                if (self.parkPush(.recv, conn.fd, conn.gen)) return;

                self.beginClose(conn);
                return;
            };

            sqe.prep_recv(conn.fd, conn.buf[conn.filled..], 0);
            sqe.user_data = uring.packUserData(.recv, conn.gen, conn.fd);
        }

        /// Arm a discard recv for a connection draining an oversized request
        /// body whose handler invoke waits on the drain. MSG.TRUNC makes the
        /// kernel drop the bytes in place (no copy into conn.buf, so the kept
        /// head bytes survive), and the request is not capped by the buffer
        /// length, so a single recv drains up to the whole remaining body
        /// instead of one round-trip per buffer. Mirrors serveEpollDrain.
        /// Capping at conn.drain leaves any pipelined bytes after the body
        /// untouched on the socket.
        ///
        /// Note:
        /// - prep_recv derives len from the buffer slice, so len is overridden
        ///   after it to request the full remaining drain. With MSG.TRUNC the
        ///   kernel never writes the buffer, so a len past conn.buf.len is safe
        ///   (the same trick serveEpollDrain uses with recvfrom).
        fn armDrainRecv(self: *Self, conn: *UringConn) void {
            const want = @min(conn.drain, common.MAX_DRAIN_RECV);
            const sqe = self.getSqe() orelse {
                // SQ full: park like armRecv, close only when parking is off or full.
                if (self.parkPush(.drain_recv, conn.fd, conn.gen)) return;

                self.beginClose(conn);
                return;
            };

            sqe.prep_recv(conn.fd, conn.buf, linux.MSG.TRUNC);
            sqe.len = @intCast(want);
            sqe.user_data = uring.packUserData(.recv, conn.gen, conn.fd);
        }

        /// Arm a buffer-select recv for a WebSocket connection: the kernel picks
        /// a buffer from the shared ring only when a frame arrives. Submits and
        /// retries once if the SQ is momentarily full. A second failure parks
        /// on the process queue when it is on (the drain retries armRecv, which
        /// routes back here for a WS connection), otherwise closes.
        fn armWsRecv(self: *Self, conn: *UringConn, bg: *IoUring.BufferGroup) void {
            const ud = uring.packUserData(.recv, conn.gen, conn.fd);
            if (bg.recv(ud, conn.fd, 0)) |_| {
                return;
            } else |_| {
                _ = self.ring.submit() catch {};
                if (bg.recv(ud, conn.fd, 0)) |_| {} else |_| {
                    if (self.parkPush(.recv, conn.fd, conn.gen)) return;

                    self.beginClose(conn);
                }
            }
        }

        fn submitSend(self: *Self, conn: *UringConn) void {
            const sqe = self.getSqe() orelse {
                // SQ full: park the send when the process queue is on. The
                // staged bytes stay in conn.send_buf (inflight stays 0), the
                // retry re-enters here with the SQ drained.
                if (self.parkPush(.send, conn.fd, conn.gen)) return;

                self.finishClose(conn);
                return;
            };

            // Zero-copy cache replay: the send references the pinned slab
            // bytes directly, nothing was staged into send_buf for it.
            const payload = if (conn.direct.len > 0) conn.direct else conn.send_buf[conn.staged_off..][0..conn.staged];
            sqe.prep_send(conn.fd, payload, linux.MSG.NOSIGNAL);
            sqe.user_data = uring.packUserData(.send, conn.gen, conn.fd);

            conn.inflight = payload.len;
        }

        // ----------------------------------------------------- //

        fn handleAccept(self: *Self, cqe: linux.io_uring_cqe) void {
            const rearm = (cqe.flags & linux.IORING_CQE_F_MORE) == 0;
            defer if (rearm) self.armAccept();

            if (cqe.res < 0) return;

            const conn_fd: std.posix.fd_t = cqe.res;
            const idx: usize = @intCast(conn_fd);
            if (idx >= self.slots.len) {
                _ = linux.close(conn_fd);
                return;
            }

            setNoDelay(conn_fd);
            common.setBusyPoll(conn_fd, self.busy_poll_us);

            const slot = self.acquireSlot() orelse {
                _ = linux.close(conn_fd);
                return;
            };

            self.gen_counter +%= 1;
            const conn = &self.slots[idx];
            conn.* = .{
                .fd = conn_fd,
                .gen = self.gen_counter,
                .buf = self.slotRecvBuf(slot),
                .filled = 0,
                .send_buf = self.slotSendBuf(slot),
                .staged = 0,
                .inflight = 0,
                .closing = false,
                .slot = slot,
            };
            self.live_count += 1;

            self.armRecv(conn);

            // A churn-heavy closed loop measures accept-to-first-byte: push
            // the fresh recv SQE to the kernel now, not after the rest of the
            // completion batch dispatches. Accept rates are orders below
            // request rates, so the extra enter is noise.
            _ = self.ring.submit() catch {};
        }

        fn handleRecv(self: *Self, cqe: linux.io_uring_cqe, decoded: uring.Decoded) void {
            const has_buf = (cqe.flags & linux.IORING_CQE_F_BUFFER) != 0;

            const conn = self.lookup(decoded) orelse {
                // The connection was freed while this buffer-select recv was in
                // flight: hand the selected buffer back so it is not leaked.
                if (has_buf) {
                    if (self.ws_bufs) |*bg| bg.put(cqe) catch {};
                }

                return;
            };

            if (cqe.res <= 0) {
                // The buffer ring ran dry: re-arm rather than drop the connection.
                if (cqe.res == -@as(i32, @intFromEnum(linux.E.NOBUFS)) and conn.ws != null and self.ws_bufs != null) {
                    self.armRecv(conn);
                    return;
                }

                if (has_buf) {
                    if (self.ws_bufs) |*bg| bg.put(cqe) catch {};
                }

                // A request that was still arriving when the peer left is
                // answered here. beginClose submits the staged bytes and the
                // close follows the send completion.
                _ = stageHangupAnswer(conn, cqe.res);

                self.beginClose(conn);
                return;
            }

            // Large request-body overflow in progress: these bytes are body to
            // discard, counted toward the deferred request's received total,
            // not a new request. Count them down and keep draining off the
            // socket until the declared length is consumed, then serve the
            // deferred request.
            if (conn.drain > 0) {
                const n: usize = @intCast(cqe.res);
                const drained = @min(n, conn.drain);
                conn.drain -= drained;
                conn.drain_received += drained;
                if (conn.drain == 0) {
                    self.finishDrainedRequest(conn);
                } else {
                    self.armDrainRecv(conn);
                }

                return;
            }

            // WebSocket frames delivered into a ring-selected buffer: parse in
            // place, then recycle the buffer.
            if (has_buf) {
                const close = blk: {
                    const bg = if (self.ws_bufs) |*b| b else break :blk true;
                    const data = bg.get(cqe) catch break :blk true;
                    const should_close = self.wsHandleBuf(conn, data);
                    bg.put(cqe) catch {};

                    break :blk should_close;
                };

                self.afterDrain(conn, if (close) .close else .keep_alive);
                return;
            }

            conn.filled += @intCast(cqe.res);

            // Established WebSocket on the plain-recv fallback (no buffer ring).
            if (conn.ws != null) {
                const close = self.wsPump(conn);
                self.afterDrain(conn, if (close) .close else .keep_alive);

                return;
            }

            var outcome = self.dispatch(conn);

            // dispatch may have just upgraded this connection (the 101 is staged
            // and conn.ws is set). Pump any frames the client pipelined after the
            // handshake so the first echo rides out with the 101.
            if (conn.ws != null and conn.filled > 0) {
                if (self.wsPump(conn)) outcome = .close;
            }

            self.afterDrain(conn, outcome);
        }

        /// Submit the staged send when there is one, otherwise close, continue
        /// an oversized-body drain, or re-arm a recv. Shared by the HTTP and
        /// WebSocket recv completions.
        fn afterDrain(self: *Self, conn: *UringConn, outcome: core.ConnOutcome) void {
            if (conn.staged > 0 or conn.direct.len > 0) {
                self.submitSend(conn);
                if (outcome == .close) conn.closing = true;

                return;
            }

            if (outcome == .close) {
                self.beginClose(conn);
                return;
            }

            if (conn.drain > 0) {
                self.armDrainRecv(conn);
                return;
            }

            self.armRecv(conn);
        }

        /// Serve the request whose body just finished draining: the head bytes
        /// were kept at the front of buf, so the normal dispatch path re-parses
        /// them and invokes the handler with the counted received total.
        fn finishDrainedRequest(self: *Self, conn: *UringConn) void {
            conn.filled = conn.pending_head_len;

            const outcome = self.dispatch(conn);

            self.afterDrain(conn, outcome);
        }

        /// Pump every complete frame in conn.buf through the WebSocket frame
        /// loop, staging echoes after the bytes already in send_buf (the 101 on
        /// the first pass), then compact the trailing partial frame to the front
        /// of conn.buf for the next recv.
        ///
        /// Return:
        /// - bool (true when the connection must close: a close frame or a write
        ///   failure)
        fn wsPump(self: *Self, conn: *UringConn) bool {
            const result = ws.pumpRing(conn.fd, conn.buf[0..conn.filled], self.ws_payload_buf, conn.send_buf[conn.staged_off + conn.staged ..], conn.ws.?);
            conn.staged += result.staged;

            if (result.consumed >= conn.filled) {
                conn.filled = 0;
            } else if (result.consumed > 0) {
                std.mem.copyForwards(u8, conn.buf[0 .. conn.filled - result.consumed], conn.buf[result.consumed..conn.filled]);
                conn.filled -= result.consumed;
            }

            return result.close;
        }

        /// Handle a WebSocket frame batch delivered into a ring-selected buffer.
        /// With no carried partial frame the bytes are pumped straight from the
        /// selected buffer (zero copy) and only a trailing partial frame is
        /// copied into conn.buf. With a carry, the new bytes are appended into
        /// conn.buf and pumped from there.
        ///
        /// Return:
        /// - bool (true when the connection must close)
        fn wsHandleBuf(self: *Self, conn: *UringConn, data: []const u8) bool {
            if (conn.filled > 0) {
                const room = conn.buf.len - conn.filled;
                if (data.len > room) return true;

                @memcpy(conn.buf[conn.filled..][0..data.len], data);
                conn.filled += data.len;

                return self.wsPump(conn);
            }

            const result = ws.pumpRing(conn.fd, data, self.ws_payload_buf, conn.send_buf[conn.staged_off + conn.staged ..], conn.ws.?);
            conn.staged += result.staged;

            const leftover = data[result.consumed..];
            if (leftover.len > conn.buf.len) return true;

            if (leftover.len > 0) {
                @memcpy(conn.buf[0..leftover.len], leftover);
                conn.filled = leftover.len;
            } else {
                conn.filled = 0;
            }

            return result.close;
        }

        /// Parse every complete request in conn.buf and dispatch it. Responses
        /// stage into conn.send_buf through the core sink, so a pipelined burst
        /// coalesces into one send. Trailing partial bytes are compacted to the
        /// front for the next recv completion. Mirrors serveEpollConnInner's
        /// parse loop without the read.
        ///
        /// Note:
        /// - A chunked request body that is fully present in conn.buf is decoded
        ///   into self.body_buf and served. A body larger than the recv buffer
        ///   defers its handler: the remainder is drained off the socket and
        ///   counted (see armDrainRecv), then the handler runs with the counted
        ///   total and an empty body slice, so keep-alive survives. A WebSocket
        ///   upgrade switches the connection to the frame loop.
        fn dispatch(self: *Self, conn: *UringConn) core.ConnOutcome {
            const fd = conn.fd;

            var sink = core.RespSink{
                .fd = fd,
                .buf = conn.send_buf,
                .grow_allocator = allocator,
                .grow_cap = URING_SEND_BUF_MAX,
                // A slab-backed send_buf cannot be realloc'd: grow switches to a
                // heap buffer and flips buf_owned, adopted below as send_heap.
                .buf_owned = conn.send_heap,
                // Ring sends give borrowed cache bytes a natural lifetime (the
                // pin drops at the send CQE), so the zero-copy replay is on.
                .allow_direct = true,
            };
            core.tl_resp_sink = &sink;
            defer core.tl_resp_sink = null;

            var consumed: usize = 0;
            var keep_alive = true;
            var scan_from = conn.scan_from;
            conn.scan_from = 0;
            while (consumed < conn.filled) {
                const rem = conn.buf[consumed..conn.filled];
                const header_end = std.mem.indexOfPos(u8, rem, scan_from, "\r\n\r\n") orelse {
                    if (rem.len >= conn.buf.len) {
                        core.writeAllFD(fd, "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n") catch {};
                        keep_alive = false;
                        break;
                    }

                    // Partial head: record the scan watermark so the next recv
                    // completion resumes the terminator search here instead of
                    // rescanning every previously searched byte (recvHead's
                    // search_from, ported to the event loop).
                    conn.scan_from = if (rem.len > 3) rem.len - 3 else 0;
                    break;
                };
                scan_from = 0;

                const parsed = parseGetFastPath(rem, header_end) orelse
                    core.parseHeadAt(rem, header_end) catch |err| {
                    core.writeAllFD(fd, core.parseErrorResponse(err)) catch {};
                    keep_alive = false;
                    break;
                };
                const head = parsed.head;

                // The client is holding its body back until the server agrees to
                // take it. Answering here rather than after the body means the
                // wait is one round trip instead of the client's own timeout.
                // .ASYNC has always done this.
                if (head.expect_continue and !conn.continue_sent and (head.content_length > 0 or head.chunked_request)) {
                    core.writeAllFD(fd, "HTTP/1.1 100 Continue\r\n\r\n") catch {
                        keep_alive = false;

                        break;
                    };
                    conn.continue_sent = true;
                }

                var body: []const u8 = &.{};
                var request_len = parsed.body_offset;
                if (head.chunked_request) {
                    const decoded = decodeChunkedInBuf(rem[parsed.body_offset..], self.body_buf);
                    switch (decoded.stop) {
                        .COMPLETE => {},
                        // Still arriving: keep the bytes and resume on the next
                        // recv completion.
                        .NEED_MORE => break,
                        // Neither of these can ever complete, so waiting for more
                        // bytes would hold the connection until the buffer filled
                        // and the peer looked like it hung up. Answer the client.
                        .MALFORMED => {
                            core.writeAllFD(fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};
                            keep_alive = false;

                            break;
                        },
                        .TOO_LARGE => {
                            core.writeAllFD(fd, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};
                            keep_alive = false;

                            break;
                        },
                    }

                    body = self.body_buf[0..decoded.len];
                    request_len = parsed.body_offset + decoded.consumed;
                } else if (head.content_length > 0) {
                    // Refused before a byte of it is read or discarded, so a declared
                    // length cannot make this worker consume an arbitrary body.
                    if (core.tl_max_request_body != 0 and head.content_length > core.tl_max_request_body) {
                        core.writeAllFD(fd, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};
                        keep_alive = false;

                        break;
                    }

                    const content_length: usize = @intCast(head.content_length);
                    const need = parsed.body_offset + content_length;

                    if (need <= rem.len) {
                        body = rem[parsed.body_offset..need];
                        request_len = need;
                    } else if (conn.pending_head_len > 0) {
                        // Deferred request re-entering after its drain: the body
                        // was consumed off the socket and counted, serve it with
                        // the counted total and the empty body slice.
                        // The drain ran to zero before this branch was reached, so the body
                        // is whole even though none of it can be handed over.
                        core.tl_body_info = .{ .received = conn.drain_received, .complete = true };
                        conn.pending_head_len = 0;
                        conn.drain_received = 0;
                        request_len = parsed.body_offset;
                    } else if (need > conn.buf.len) {
                        // Body is larger than the recv buffer and can never fit.
                        // Hold the handler until the remainder drains off the
                        // socket, so the served count comes from the reads that
                        // consumed it. The head bytes stay at the front of buf
                        // for the deferred invoke (the MSG.TRUNC drain recvs
                        // never write the buffer).
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

                if (self.handler_timeout_ms != 0) core.setTimeout(self.handler_timeout_ms);
                _ = self.req_arena.reset(.retain_capacity);
                core.invokeHandler(handler_fn, &head, body, fd, self.io, self.req_arena.allocator());

                consumed += request_len;
                self.requests_served += 1;
                conn.continue_sent = false;

                // WebSocket upgrade: stop parsing HTTP and switch to the frame
                // loop. The 101 is already staged in the sink. Bytes the client
                // pipelined after the handshake are pumped by handleRecv.
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

            // The sink may have grown send_buf to fit an oversized response, so
            // adopt the (possibly heap-switched) buffer before submitSend and
            // handleSend reference it. A captured zero-copy replay transfers
            // with its pin, released at the send CQE (or teardown).
            conn.send_buf = sink.buf;
            conn.send_heap = sink.buf_owned;
            conn.staged = sink.len - sink.off;
            conn.staged_off = sink.off;
            conn.direct = sink.direct;
            conn.direct_slot = sink.direct_slot;
            if (sink.failed) return .close;

            return if (keep_alive) .keep_alive else .close;
        }

        fn handleSend(self: *Self, cqe: linux.io_uring_cqe, decoded: uring.Decoded) void {
            const conn = self.lookup(decoded) orelse return;

            if (cqe.res < 0) {
                // The send completed (with an error), so nothing is in flight
                // anymore: clear it or beginClose would wait for a CQE that
                // never comes. The staged remainder (and any borrowed replay,
                // whose pin drops here) is dropped too: the socket is dead, and
                // beginClose would otherwise re-submit it error after error.
                conn.inflight = 0;
                conn.staged = 0;
                conn.staged_off = 0;
                if (conn.direct.len > 0) {
                    if (core.tl_cache) |resp_cache| resp_cache.unpin(conn.direct_slot);
                    conn.direct = &.{};
                }
                self.beginClose(conn);
                return;
            }

            const sent: usize = @intCast(cqe.res);

            // Zero-copy cache replay: advance into the borrowed bytes on a
            // short send, release the pin once they are fully on the wire.
            if (conn.direct.len > 0) {
                if (sent < conn.direct.len) {
                    conn.direct = conn.direct[sent..];
                    conn.inflight = 0;
                    self.submitSend(conn);

                    return;
                }

                if (core.tl_cache) |resp_cache| resp_cache.unpin(conn.direct_slot);
                conn.direct = &.{};
                conn.inflight = 0;
            } else if (sent < conn.staged) {
                // A short send leaves a remainder: advance the staged window
                // past the sent prefix and send again before reading the next
                // request. No shift, the offset send references it in place.
                conn.staged_off += sent;
                conn.staged -= sent;
                conn.inflight = 0;
                self.submitSend(conn);

                return;
            } else {
                conn.staged = 0;
                conn.staged_off = 0;
                conn.inflight = 0;
            }

            if (conn.closing) {
                self.finishClose(conn);
                return;
            }

            // Responses staged before an oversized request went out first. Now
            // read and discard the rest of that body (counting it) before the
            // deferred handler runs.
            if (conn.drain > 0) {
                self.armDrainRecv(conn);
                return;
            }

            self.armRecv(conn);
        }

        // ----------------------------------------------------- //
        // Dual-listener TLS side (config.tls_port): ciphertext recv and the staged-ciphertext
        // flush ride the ring (tls_recv / tls_send ops), the TLS connection logic is tls_mux's
        // (shared with the .EPOLL paths). Half-duplex per connection: while a flush send is in
        // flight no recv is armed, so the transport's staging buffer is never compacted while
        // the kernel reads it.

        fn lookupTls(self: *Self, decoded: uring.Decoded) ?*UringTlsConn {
            const table = if (self.tls_conns) |*tls_table| tls_table else return null;

            const ring_conn = table.get(decoded.fd) orelse return null;
            if (ring_conn.gen != decoded.gen) return null;

            return ring_conn;
        }

        fn armTlsAccept(self: *Self) void {
            const sqe = self.getSqe() orelse {
                // Same lost-re-arm guard as armAccept, for the TLS listener.
                self.tls_accept_pending = true;
                return;
            };

            sqe.prep_multishot_accept(self.tls_listener_fd, null, null, 0);
            sqe.user_data = uring.packUserData(.tls_accept, 0, self.tls_listener_fd);
        }

        fn handleTlsAccept(self: *Self, cqe: linux.io_uring_cqe) void {
            const rearm = (cqe.flags & linux.IORING_CQE_F_MORE) == 0;
            defer if (rearm) self.armTlsAccept();

            if (cqe.res < 0) return;

            const conn_fd: std.posix.fd_t = cqe.res;
            const table = if (self.tls_conns) |*tls_table| tls_table else {
                _ = linux.close(conn_fd);
                return;
            };
            const idx: usize = @intCast(conn_fd);
            if (idx >= table.slots.len) {
                _ = linux.close(conn_fd);
                return;
            }

            setNoDelay(conn_fd);
            // The transport writes records directly (staging on EAGAIN), so the fd must be
            // non-blocking.
            common.setNonBlock(conn_fd);

            const ring_conn = allocator.create(UringTlsConn) catch {
                _ = linux.close(conn_fd);
                return;
            };
            const cipher_buf = allocator.alloc(u8, tls_conn.read_staging_size) catch {
                allocator.destroy(ring_conn);
                _ = linux.close(conn_fd);
                return;
            };

            self.tls_gen_counter +%= 1;
            ring_conn.* = .{
                .conn = .{
                    .transport = tls_conn.Transport.init(conn_fd, self.tls_ctx.?),
                    .handler = handler_fn,
                    .ctx = self.tls_ctx.?,
                },
                .gen = self.tls_gen_counter,
                .cipher_buf = cipher_buf,
            };
            table.put(conn_fd, ring_conn);

            self.armTlsRecv(ring_conn);
        }

        /// Tear a TLS connection down: drop it from the table (frees the conn object) and hand
        /// the fd close to the ring, mirroring finishClose.
        fn closeTls(self: *Self, ring_conn: *UringTlsConn) void {
            const fd = ring_conn.conn.transport.fd;
            if (self.tls_conns) |*tls_table| tls_table.drop(fd);

            const sqe = self.getSqe() orelse {
                _ = linux.close(fd);
                return;
            };
            sqe.prep_close(fd);
            sqe.user_data = uring.packUserData(.close, 0, fd);
        }

        fn armTlsRecv(self: *Self, ring_conn: *UringTlsConn) void {
            // Sized by what the session can take, not by the staging buffer. The staging buffer is
            // wider than one TLS record, so a busy socket (an upload in flight) would otherwise hand
            // the session two records at once, which it refuses by closing the connection.
            const room = ring_conn.conn.transport.tls.readRoom();
            if (room == 0) {
                self.closeTls(ring_conn);
                return;
            }

            const sqe = self.getSqe() orelse {
                self.closeTls(ring_conn);
                return;
            };
            sqe.prep_recv(ring_conn.conn.transport.fd, ring_conn.cipher_buf[0..@min(ring_conn.cipher_buf.len, room)], 0);
            sqe.user_data = uring.packUserData(.tls_recv, ring_conn.gen, ring_conn.conn.transport.fd);
        }

        /// Flush the transport's staged ciphertext (wbuf[woff..wlen]) with an on-ring send.
        fn submitTlsSend(self: *Self, ring_conn: *UringTlsConn) void {
            const transport = &ring_conn.conn.transport;

            const sqe = self.getSqe() orelse {
                self.closeTls(ring_conn);
                return;
            };
            sqe.prep_send(transport.fd, transport.wbuf[transport.woff..transport.wlen], linux.MSG.NOSIGNAL);
            sqe.user_data = uring.packUserData(.tls_send, ring_conn.gen, transport.fd);
        }

        fn handleTlsRecv(self: *Self, cqe: linux.io_uring_cqe, decoded: uring.Decoded) void {
            const ring_conn = self.lookupTls(decoded) orelse return;

            if (cqe.res <= 0) {
                // A request that was still arriving when the peer left is answered before the close,
                // the same as the .EPOLL TLS read loop does. A staged answer flushes first, and the
                // send completion runs the close.
                if (cqe.res == 0 and tls_mux.hangupAnswer(&ring_conn.conn)) {
                    self.submitTlsSend(ring_conn);
                    return;
                }

                self.closeTls(ring_conn);
                return;
            }

            const keep = tls_mux.onCiphertext(
                &ring_conn.conn,
                ring_conn.cipher_buf[0..@intCast(cqe.res)],
                self.ws_payload_buf,
                self.tls_out_buf,
            );
            const transport = &ring_conn.conn.transport;

            if (!keep) {
                self.closeTls(ring_conn);
                return;
            }

            // Backpressure-staged ciphertext: flush it on the ring before the next recv.
            if (transport.wlen > transport.woff) {
                self.submitTlsSend(ring_conn);
                return;
            }

            if (transport.wclose) {
                self.closeTls(ring_conn);
                return;
            }

            self.armTlsRecv(ring_conn);
        }

        fn handleTlsSend(self: *Self, cqe: linux.io_uring_cqe, decoded: uring.Decoded) void {
            const ring_conn = self.lookupTls(decoded) orelse return;
            const transport = &ring_conn.conn.transport;

            if (cqe.res <= 0) {
                self.closeTls(ring_conn);
                return;
            }

            transport.woff += @intCast(cqe.res);
            if (transport.woff < transport.wlen) {
                self.submitTlsSend(ring_conn);
                return;
            }

            // Drained. Keep the buffer for reuse (freed at close), mirroring the EPOLL flush.
            transport.woff = 0;
            transport.wlen = 0;
            transport.want_out = false;

            if (transport.wclose) {
                self.closeTls(ring_conn);
                return;
            }

            self.armTlsRecv(ring_conn);
        }

        // ----------------------------------------------------- //

        /// Arm a multishot POLLIN watch for a foreign (driver) fd on this
        /// ring, installed as the core.uringWatchFd trampoline for the worker
        /// thread. A full submission queue parks the arm, so a watch is never
        /// lost while the process queue has room. The completion path re-arms
        /// a lapsed multishot itself while the fd stays alive.
        fn watchExternal(ctx: *anyopaque, fd: std.posix.fd_t) bool {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const sqe = self.getSqe() orelse {
                return self.parkPush(.external, fd, 0);
            };

            sqe.prep_poll_add(fd, linux.POLL.IN);
            sqe.len = linux.IORING_POLL_ADD_MULTI;
            sqe.user_data = uring.packUserData(.external, 0, fd);

            return true;
        }

        fn run(self: *Self) void {
            core.tl_uring_watch = &watchExternal;
            core.tl_uring_watch_ctx = self;

            self.armAccept();
            if (self.tls_listener_fd != -1) self.armTlsAccept();

            // A batch wait is only safe when the kernel can bound it from inside the
            // wait. Without IORING_FEAT_EXT_ARG the ceiling drops to one completion,
            // which anything already queued satisfies, so a worker can never park on
            // completions its remaining connections will not produce.
            const coalesce_max: u32 = if (ring_wait.boundedWaitSupported(&self.ring)) URING_WAIT_COALESCE_MAX else 1;

            var wait_nr: u32 = 1;
            var cqes: [URING_CQE_BATCH]linux.io_uring_cqe = undefined;
            while (true) {
                // Hot-loop wakeup coalescing: when the last reap was large, wait for a
                // batch of completions per enter instead of one, bounded by the coalesce
                // window so a short batch is handed over rather than held. A pass that
                // only wants one completion needs no window, and skipping it there is
                // what lets an idle worker sleep instead of waking on a timer.
                if (wait_nr > 1) {
                    ring_wait.submitAndWaitTimeout(&self.ring, wait_nr, URING_WAIT_COALESCE_NS) catch |err| switch (err) {
                        error.SignalInterrupt => continue,
                        else => return,
                    };
                } else {
                    _ = self.ring.submit_and_wait(1) catch |err| switch (err) {
                        error.SignalInterrupt => continue,
                        else => return,
                    };
                }

                // The submit above pushed the staged SQEs to the kernel, so the
                // SQ has room again: retry the pending accept re-arm and the
                // parked process-queue entries before reaping new completions.
                self.drainParked();

                const count = self.ring.copy_cqes(&cqes, 0) catch return;
                wait_nr = @min(@max(@as(u32, @intCast(count / 2)), 1), coalesce_max);
                for (cqes[0..count], 0..) |cqe, cqe_idx| {
                    const decoded = uring.unpackUserData(cqe.user_data);
                    switch (decoded.op) {
                        .accept => self.handleAccept(cqe),
                        .recv => self.handleRecv(cqe, decoded),
                        .send => self.handleSend(cqe, decoded),
                        .timeout => {},
                        .close => {},
                        .tls_accept => self.handleTlsAccept(cqe),
                        .tls_recv => self.handleTlsRecv(cqe, decoded),
                        .tls_send => self.handleTlsSend(cqe, decoded),
                        .external => {
                            if (core.tl_external_cb) |cb| cb(decoded.fd);
                            // Multishot lapse: re-arm while the fd is alive. A
                            // negative res (closed or canceled) drops the watch,
                            // the owner's pump-on-submit is the recovery path.
                            if (cqe.res >= 0 and (cqe.flags & linux.IORING_CQE_F_MORE) == 0) {
                                _ = watchExternal(self, decoded.fd);
                            }
                        },
                    }

                    // Deep batch: release the staged sends every stride so
                    // early responses leave now, not after the whole batch.
                    if (count >= URING_INTRA_SUBMIT_MIN_BATCH and
                        (cqe_idx + 1) % URING_INTRA_SUBMIT == 0 and
                        self.ring.sq_ready() > 0)
                    {
                        _ = self.ring.submit() catch {};
                    }
                }
            }
        }
    };
}

const UringWorkerCtx = struct {
    config: Config,
    worker_id: usize,
    /// CBPF steering wiring (config.reuseport_cbpf). Null = steering off.
    steering: ?reuseport.Steering = null,
    /// Where this worker says whether its listeners came up, shared with the whole group.
    report: *listen_report.Report,
};

/// Return a concrete io_uring worker entry with handler_fn baked in at compile
/// time, mirroring epollWorkerFn so Thread.spawn gets a direct call.
fn uringWorkerFn(comptime handler_fn: HandlerFn) fn (UringWorkerCtx) void {
    return struct {
        fn run(ctx: UringWorkerCtx) void {
            pinToCpu(ctx.worker_id);

            const config = ctx.config;
            const io = config.io;

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

            // Every exit between here and the ring loop has to reach the group, or the workers
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

            if (ctx.steering) |steer| _ = reuseport.attachCpuSteering(listener_fd, steer.group_size);

            // Dual-listener TLS side: a second listener on tls_port whose connections terminate
            // TLS in this same ring loop (no separate epoll fleet).
            const tls_active = config.tls != null and config.tls_port != 0;
            var tls_srv: std.Io.net.Server = undefined;
            var tls_listener_fd: std.posix.fd_t = -1;
            if (tls_active) {
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
                if (ctx.steering) |steer| _ = reuseport.attachCpuSteering(tls_listener_fd, steer.group_size);
            }
            defer if (tls_active) tls_srv.deinit(io);

            // Both groups joined: release the bind turn to the next worker.
            bind_turn.release();

            // Serve only once every worker is up, so a group where one bind failed serves on none
            // of them and the caller gets one honest failure.
            slot.ok();
            if (ctx.report.awaitGroup(io) != null) return;

            const slots = slab.mapZeroedSlots(UringConn, MAX_FD) catch return;

            // Per-connection recv buffer size. WebSocket connections accumulate
            // frame bytes in conn.buf and unmask into ws_payload_buf, so both honor
            // config.ws_recv_buf when set (the URING analog of the EPOLL per-
            // connection WS recv buffer): a WS deployment gives frames room
            // independent of the small request max_recv_buf, so a deep pipelined
            // burst that spans several provided-buffer ring deliveries accumulates
            // in one connection buffer instead of forcing an early flush. 0 falls
            // back to max_recv_buf. The ring stays at WS_RING_BUF_SIZE, well below
            // conn.buf, so a carried partial frame always has room.
            const conn_buf_size = @max(config.max_recv_buf, config.ws_recv_buf);

            // One contiguous buffer slab for every connection (recv + send per
            // page-multiple stride), mmap'd so the base is page-aligned and
            // demand-paged: untouched strides cost no physical memory, exactly
            // like the EPOLL recv slab. THP is explicitly opted OUT: on a host
            // whose THP policy is "always", any touch in this contiguous slab
            // would materialize a whole 2 MiB extent (dozens of neighbor
            // strides) and khugepaged re-collapse would undo the cold-slot
            // MADV_DONTNEED, which roughly doubled resident memory at high
            // concurrency on the bench gate. The layout determinism comes from
            // the compact slots and the pretouch, not from the page size.
            const conn_stride = std.mem.alignForward(usize, conn_buf_size + config.uring_send_buf_size, std.heap.page_size_min);
            const conn_slab = slab.mapZeroedSlots(u8, MAX_FD * conn_stride) catch return;
            slab.adviseNoHugePages(conn_slab);

            // Compact-slot free-list (closed strides for reuse, warmest on top).
            const free_slots = std.heap.smp_allocator.alloc(u32, MAX_FD) catch return;

            // Per-worker scratch for unmasking WebSocket payloads. Sized to the
            // connection buffer, the largest frame a connection can accumulate.
            const ws_payload_buf = std.heap.smp_allocator.alloc(u8, conn_buf_size) catch return;

            // Per-worker scratch for a decoded chunked request body. Sized to the
            // connection buffer, since a chunked body must be fully present in
            // conn.buf to decode and its decoded form is always shorter than the raw
            // bytes.
            const body_buf = std.heap.smp_allocator.alloc(u8, conn_buf_size) catch return;

            // Process queue (config.process_queue_len): the FIFO ring of
            // postponed re-arm references, preallocated once. Empty when 0 (off).
            const park_entries: []ParkEntry = if (config.process_queue_len > 0)
                std.heap.smp_allocator.alloc(ParkEntry, config.process_queue_len) catch return
            else
                &.{};

            // Per-request scratch for the handler trio, reset before each dispatch
            // so a long pipelined burst never grows without bound.
            var req_arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
            defer req_arena.deinit();

            const Worker = UringWorker(handler_fn);
            var worker = Worker{
                .ring = undefined,
                .slots = slots,
                .conn_slab = conn_slab,
                .stride = conn_stride,
                .free_slots = free_slots,
                .park_entries = park_entries,
                .listener_fd = listener_fd,
                .gen_counter = 0,
                .io = io,
                .req_arena = &req_arena,
                .recv_buf_size = conn_buf_size,
                .send_buf_size = config.uring_send_buf_size,
                .idle_floor = config.uring_idle_pool_floor,
                .idle_ceiling = config.uring_idle_pool_ceiling,
                .handler_timeout_ms = config.handler_timeout_ms,
                .busy_poll_us = config.busy_poll_us,
                .ws_payload_buf = ws_payload_buf,
                .body_buf = body_buf,
                .ws_bufs = null,
                .tls_listener_fd = tls_listener_fd,
                .tls_ctx = if (tls_active) config.tls else null,
            };
            worker.ring = initUringRing() catch return;
            if (tls_active) {
                worker.tls_conns = TlsConnTable.init() catch return;
                worker.tls_out_buf = std.heap.smp_allocator.alloc(u8, tls_mux.RESPONSE_BUF_SIZE) catch return;
            }
            // Provided-buffer ring for WebSocket recvs (Phase 4b). Optional: a
            // kernel without buffer-ring support leaves it null, and WebSocket
            // uses the plain recv path.
            worker.ws_bufs = IoUring.BufferGroup.init(&worker.ring, std.heap.smp_allocator, WS_RING_BGID, WS_RING_BUF_SIZE, WS_RING_BUF_COUNT) catch null;
            defer worker.deinit();

            // Per-worker response cache (ADR-036), owned for this worker's
            // lifetime. Lock-free by ownership: this thread is the sole creator,
            // setter, and user, exactly like the EPOLL worker, so the same
            // install holds on the ring path. Lives on the worker stack so
            // tl_cache stays valid until run() returns.
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

            // Make the first strides of the buffer slab resident so the first
            // accept burst never first-touch faults under load, and the touched
            // layout is identical on every run.
            worker.pretouchSlab();

            worker.run();

            logSystem(config, .INFO, "uring worker {d}: {d} requests served", .{ ctx.worker_id, worker.requests_served });
        }
    }.run;
}

pub fn runUring(config: Config, comptime handler_fn: HandlerFn) !void {
    // Runtime probe: io_uring can be unavailable on this host (seccomp/sandbox,
    // RLIMIT_MEMLOCK, or an old kernel). Without this, every worker would fail
    // setup, return, and the server would vanish right after binding (a confusing
    // ServerStartTimeout downstream). Fall back to the EPOLL shared-nothing loop.
    var probe = initUringRing() catch |err| {
        logSystem(config, .WARN, "io_uring unavailable ({s}): not suited to this environment (commonly RLIMIT_MEMLOCK, the ulimit -l cap, too low for the ring size). Falling back to EPOLL.", .{@errorName(err)});

        return epoll_model.runEpoll(config, handler_fn);
    };
    probe.deinit();

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

    const worker = uringWorkerFn(handler_fn);
    for (threads, 0..) |*thread, worker_id| {
        thread.* = std.Thread.spawn(
            .{ .stack_size = worker_stack },
            worker,
            .{UringWorkerCtx{ .config = config, .worker_id = worker_id, .steering = steering, .report = &report }},
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
    logSystem(config, .INFO, "listening on {s}:{d} (io_uring, {d} workers, shared-nothing)", .{ config.ip, config.port, worker_count });
    if (config.tls != null and config.tls_port != 0)
        logSystem(config, .INFO, "dual listener: https/1.1 TLS on {s}:{d} (same workers, on-ring)", .{ config.ip, config.tls_port });

    for (threads) |thread| thread.join();
}

// Echo the received body size counted off the socket: the large-body drain
// path serves the counted total after the drain, otherwise it is the
// delivered body length.
fn testEchoLenHandler(req: *core.Request, res: *core.Response, ctx: *core.Context) anyerror!void {
    _ = ctx;

    var buf: [48]u8 = undefined;
    const out = std.fmt.bufPrint(&buf, "{d}:{s}", .{ req.bodyReceived(), if (req.bodyComplete()) "whole" else "cut" }) catch return;

    res.setContentType(.TEXT_PLAIN);

    try res.send(out);
}

// Build a UringWorker instance for dispatch-level tests. dispatch() reads only
// body_buf and handler_timeout_ms and never touches the ring, so the ring and
// slots can stay empty.
fn testUringWorker(comptime handler: HandlerFn, body_buf: []u8, arena: *std.heap.ArenaAllocator) UringWorker(handler) {
    return .{
        .ring = undefined,
        .slots = &[_]UringConn{},
        .listener_fd = -1,
        .gen_counter = 0,
        .io = undefined,
        .req_arena = arena,
        .recv_buf_size = body_buf.len,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &[_]u8{},
        .body_buf = body_buf,
        .ws_bufs = null,
    };
}

test "zix http1: URING dispatch decodes a fully-present chunked body" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var body_buf: [4096]u8 = undefined;
    var worker = testUringWorker(testEchoLenHandler, &body_buf, &arena);

    // One chunk "20" (2 bytes) then the zero terminator: decodes to "20".
    const req = "POST /u HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n20\r\n0\r\n\r\n";
    var conn_buf: [4096]u8 = undefined;
    @memcpy(conn_buf[0..req.len], req);
    var send_buf: [4096]u8 = undefined;
    var conn = UringConn{ .fd = fds[1], .gen = 0, .buf = &conn_buf, .filled = req.len, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    const outcome = worker.dispatch(&conn);

    try std.testing.expectEqual(core.ConnOutcome.keep_alive, outcome);
    try std.testing.expectEqual(@as(usize, 0), conn.drain);
    try std.testing.expectEqual(@as(usize, 0), conn.filled);

    // The handler saw a 2-byte decoded body, so it echoes "2".
    const resp = send_buf[0..conn.staged];
    try std.testing.expect(std.mem.indexOf(u8, resp, "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.endsWith(u8, resp, "\r\n\r\n2:whole"));
}

test "zix http1: URING dispatch refuses a declared body past the limit with 413" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var body_buf: [4096]u8 = undefined;
    var worker = testUringWorker(testEchoLenHandler, &body_buf, &arena);

    core.setMaxRequestBody(1024);
    defer core.setMaxRequestBody(0);

    // The declared length alone is enough to refuse, so the worker never defers
    // the request or arms a drain for a body it was never going to accept.
    const head = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 65536\r\n\r\n";
    var conn_buf: [4096]u8 = undefined;
    @memcpy(conn_buf[0..head.len], head);
    var send_buf: [4096]u8 = undefined;
    var conn = UringConn{ .fd = fds[1], .gen = 0, .buf = &conn_buf, .filled = head.len, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    const outcome = worker.dispatch(&conn);

    try std.testing.expectEqual(core.ConnOutcome.close, outcome);
    try std.testing.expectEqual(@as(usize, 0), conn.drain);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_head_len);
    try std.testing.expectStringStartsWith(send_buf[0..conn.staged], "HTTP/1.1 413 ");
}

test "zix http1: URING dispatch sends 100 Continue while the body is still arriving" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var body_buf: [4096]u8 = undefined;
    var worker = testUringWorker(testEchoLenHandler, &body_buf, &arena);

    // Head only: the client is waiting for the interim response before it sends
    // the body, so the request cannot complete until that answer goes out.
    const head = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n";
    var conn_buf: [4096]u8 = undefined;
    @memcpy(conn_buf[0..head.len], head);
    var send_buf: [4096]u8 = undefined;
    var conn = UringConn{ .fd = fds[1], .gen = 0, .buf = &conn_buf, .filled = head.len, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    const outcome = worker.dispatch(&conn);

    try std.testing.expectEqual(core.ConnOutcome.keep_alive, outcome);
    try std.testing.expect(conn.continue_sent);
    try std.testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", send_buf[0..conn.staged]);
}

test "zix http1: URING dispatch answers 400 on a malformed chunked body instead of waiting" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var body_buf: [4096]u8 = undefined;
    var worker = testUringWorker(testEchoLenHandler, &body_buf, &arena);

    // A chunk size that is not hex can never become valid by waiting. Treating it
    // as "not arrived yet" held the connection until the buffer filled and the
    // peer read as a hangup, with no answer sent.
    const req = "POST /u HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nab\r\n0\r\n\r\n";
    var conn_buf: [4096]u8 = undefined;
    @memcpy(conn_buf[0..req.len], req);
    var send_buf: [4096]u8 = undefined;
    var conn = UringConn{ .fd = fds[1], .gen = 0, .buf = &conn_buf, .filled = req.len, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    const outcome = worker.dispatch(&conn);

    try std.testing.expectEqual(core.ConnOutcome.close, outcome);

    // The ring stages responses into send_buf, the worker submits them, so the
    // answer is read from there rather than off the socket.
    const resp = send_buf[0..conn.staged];
    try std.testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 400 "));
}

test "zix http1: URING dispatch answers 413 for a chunked body past the body buffer" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // The decoded body is larger than the per-worker body buffer, so it can never
    // be served. That is a client error with an answer, not a body still on its way.
    var body_buf: [16]u8 = undefined;
    var worker = testUringWorker(testEchoLenHandler, &body_buf, &arena);

    const oversized: [64]u8 = @splat('A');
    const req = "POST /u HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n\r\n40\r\n".* ++ oversized ++ "\r\n0\r\n\r\n".*;
    var conn_buf: [4096]u8 = undefined;
    @memcpy(conn_buf[0..req.len], &req);
    var send_buf: [4096]u8 = undefined;
    var conn = UringConn{ .fd = fds[1], .gen = 0, .buf = &conn_buf, .filled = req.len, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    const outcome = worker.dispatch(&conn);

    try std.testing.expectEqual(core.ConnOutcome.close, outcome);

    const resp = send_buf[0..conn.staged];
    try std.testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 413 "));
}

test "zix http1: URING dispatch adopts a reserve-committed response with its staged offset" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var body_buf: [256]u8 = undefined;
    var worker = testUringWorker(testReserveHandler, &body_buf, &arena);

    const req = "GET /r HTTP/1.1\r\nHost: t\r\n\r\n";
    var conn_buf: [4096]u8 = undefined;
    @memcpy(conn_buf[0..req.len], req);
    var send_buf: [4096]u8 = undefined;
    var conn = UringConn{ .fd = fds[1], .gen = 0, .buf = &conn_buf, .filled = req.len, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    const outcome = worker.dispatch(&conn);

    // The staged window starts at the right-aligned header, not at zero, and
    // holds the complete response.
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, outcome);
    try std.testing.expect(conn.staged_off > 0);

    const resp = send_buf[conn.staged_off..][0..conn.staged];
    try std.testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, resp, "Content-Length: 8\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, resp, "\r\n\r\n{\"n\":42}"));
}

test "zix http1: URING dispatch resumes a split head scan from the watermark" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var body_buf: [256]u8 = undefined;
    var worker = testUringWorker(testOkHandler, &body_buf, &arena);

    // First completion delivers a head with no terminator: nothing parses and
    // the watermark records how far the scan got (three bytes back, so a
    // terminator split across completions is still found).
    const part1 = "GET /pipeline HTTP/1.1\r\nHost: t";
    var conn_buf: [1024]u8 = undefined;
    @memcpy(conn_buf[0..part1.len], part1);
    var send_buf: [1024]u8 = undefined;
    var conn = UringConn{ .fd = fds[1], .gen = 0, .buf = &conn_buf, .filled = part1.len, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    const first = worker.dispatch(&conn);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, first);
    try std.testing.expectEqual(@as(usize, 0), conn.staged);
    try std.testing.expectEqual(part1.len - 3, conn.scan_from);

    // The terminator arrives: the request completes and the watermark resets.
    const part2 = "\r\n\r\n";
    @memcpy(conn_buf[conn.filled..][0..part2.len], part2);
    conn.filled += part2.len;

    const second = worker.dispatch(&conn);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, second);
    try std.testing.expectEqual(@as(usize, 0), conn.scan_from);

    const resp = send_buf[0..conn.staged];
    try std.testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, resp, "\r\n\r\nok"));
}

test "zix http1: URING dispatch defers an oversized body and serves the counted total" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var body_buf: [256]u8 = undefined;
    var worker = testUringWorker(testEchoLenHandler, &body_buf, &arena);

    // Content-Length far exceeds the 256-byte conn.buf, with only a partial
    // body present: dispatch must defer the handler, arm the drain, and keep
    // the head bytes at the front of buf.
    const head = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 100000\r\n\r\n";
    const partial = "abcdef";
    var conn_buf: [256]u8 = undefined;
    @memcpy(conn_buf[0..head.len], head);
    @memcpy(conn_buf[head.len..][0..partial.len], partial);
    var send_buf: [4096]u8 = undefined;
    var conn = UringConn{ .fd = fds[1], .gen = 0, .buf = &conn_buf, .filled = head.len + partial.len, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    const outcome = worker.dispatch(&conn);

    // No response yet: the handler waits for the drain.
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, outcome);
    try std.testing.expectEqual(@as(usize, 100000 - partial.len), conn.drain);
    try std.testing.expectEqual(partial.len, conn.drain_received);
    try std.testing.expectEqual(head.len, conn.pending_head_len);
    try std.testing.expectEqual(@as(usize, 0), conn.filled);
    try std.testing.expectEqual(@as(usize, 0), conn.staged);

    // The drain completes: count the remainder the way handleRecv does, then
    // re-enter dispatch the way finishDrainedRequest does.
    conn.drain_received += conn.drain;
    conn.drain = 0;
    conn.filled = conn.pending_head_len;

    const second = worker.dispatch(&conn);

    // The handler echoed the counted total, not the header field.
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, second);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_head_len);
    try std.testing.expectEqual(@as(usize, 0), conn.drain_received);
    try std.testing.expectEqual(@as(usize, 0), conn.filled);

    const resp = send_buf[0..conn.staged];
    try std.testing.expect(std.mem.endsWith(u8, resp, "\r\n\r\n100000:whole"));
}

test "zix http1: URING dispatch waits for a body that fits the buffer and then reports the full count" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var body_buf: [256]u8 = undefined;
    var worker = testUringWorker(testEchoLenHandler, &body_buf, &arena);

    // Content-Length fits conn.buf, so this is the wait path rather than the
    // drain path: dispatch holds the head until the body lands.
    const head = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 100\r\n\r\n";
    var conn_buf: [256]u8 = undefined;
    @memcpy(conn_buf[0..head.len], head);
    var send_buf: [4096]u8 = undefined;
    var conn = UringConn{ .fd = fds[1], .gen = 0, .buf = &conn_buf, .filled = head.len, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    const first = worker.dispatch(&conn);

    // Nothing answered and nothing drained: the head is still buffered whole.
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, first);
    try std.testing.expectEqual(@as(usize, 0), conn.staged);
    try std.testing.expectEqual(head.len, conn.filled);
    try std.testing.expectEqual(@as(usize, 0), conn.drain);
    try std.testing.expectEqual(@as(usize, 0), conn.pending_head_len);

    @memset(conn_buf[head.len..][0..100], 'A');
    conn.filled = head.len + 100;

    const second = worker.dispatch(&conn);

    try std.testing.expectEqual(core.ConnOutcome.keep_alive, second);
    try std.testing.expectEqual(@as(usize, 0), conn.filled);
    try std.testing.expect(std.mem.endsWith(u8, send_buf[0..conn.staged], "\r\n\r\n100:whole"));
}

test "zix http1: URING keeps a deferred request parked while its drain is unfinished" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    // The counterpart to .ASYNC reporting an incomplete body: this model does not
    // report one, it holds the request until the drain finishes and serves
    // nothing if it never does. Nothing pinned that the parked request stays
    // parked.
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var body_buf: [256]u8 = undefined;
    var worker = testUringWorker(testEchoLenHandler, &body_buf, &arena);

    const head = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 100000\r\n\r\n";
    const partial = "abcdef";
    var conn_buf: [256]u8 = undefined;
    @memcpy(conn_buf[0..head.len], head);
    @memcpy(conn_buf[head.len..][0..partial.len], partial);
    var send_buf: [4096]u8 = undefined;
    var conn = UringConn{ .fd = fds[1], .gen = 0, .buf = &conn_buf, .filled = head.len + partial.len, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    const served_before = worker.requests_served;
    const outcome = worker.dispatch(&conn);

    // Parked: a drain still owing, a head held, nothing staged, nothing counted
    // as served. Only a drain that reaches zero releases it, which is what
    // finishDrainedRequest waits for.
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, outcome);
    try std.testing.expect(conn.drain > 0);
    try std.testing.expectEqual(head.len, conn.pending_head_len);
    try std.testing.expectEqual(@as(usize, 0), conn.staged);
    try std.testing.expectEqual(served_before, worker.requests_served);
}

test "zix http1: URING answers 400 when the peer quits with a request unfinished" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    // The counterpart of the .EPOLL hangup answer, which this model had no test
    // for at all: a recv completing with zero while a request is still arriving
    // leaves a status staged, and beginClose sends it before the close.
    var conn_buf: [256]u8 = undefined;
    var send_buf: [256]u8 = undefined;

    // Buffered partial: a declared body the peer stopped sending, small enough
    // that it never armed a drain.
    var buffered = UringConn{ .fd = -1, .gen = 0, .buf = &conn_buf, .filled = 54, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    try std.testing.expect(stageHangupAnswer(&buffered, 0));
    try std.testing.expectStringStartsWith(send_buf[0..buffered.staged], "HTTP/1.1 400 Bad Request\r\n");
    try std.testing.expect(std.mem.endsWith(u8, send_buf[0..buffered.staged], "Connection: close\r\n\r\n"));

    // Parked head: buf carries no bytes of its own, the request lives in the
    // drain that can now never reach zero.
    var parked = UringConn{ .fd = -1, .gen = 0, .buf = &conn_buf, .filled = 0, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };
    parked.pending_head_len = 49;
    parked.drain = 4096;

    try std.testing.expect(stageHangupAnswer(&parked, 0));
    try std.testing.expectStringStartsWith(send_buf[0..parked.staged], "HTTP/1.1 400 Bad Request\r\n");
}

test "zix http1: URING stages nothing when a hangup finds no request in flight" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    var conn_buf: [256]u8 = undefined;
    var send_buf: [256]u8 = undefined;

    // Idle keep-alive: the peer left between requests and owes nothing, so an
    // answer here would land on every ordinary connection teardown.
    var idle = UringConn{ .fd = -1, .gen = 0, .buf = &conn_buf, .filled = 0, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    try std.testing.expect(!stageHangupAnswer(&idle, 0));
    try std.testing.expectEqual(@as(usize, 0), idle.staged);

    // A negative result is a dead socket rather than a hangup, so staging bytes
    // for it is work that can only fail.
    var errored = UringConn{ .fd = -1, .gen = 0, .buf = &conn_buf, .filled = 54, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    try std.testing.expect(!stageHangupAnswer(&errored, -@as(i32, @intFromEnum(linux.E.CONNRESET))));
    try std.testing.expectEqual(@as(usize, 0), errored.staged);

    // WebSocket: the peer reads frames, and a status line is not one.
    var upgraded = UringConn{ .fd = -1, .gen = 0, .buf = &conn_buf, .filled = 54, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false, .ws = testWsEcho };

    try std.testing.expect(!stageHangupAnswer(&upgraded, 0));
    try std.testing.expectEqual(@as(usize, 0), upgraded.staged);

    // A response already staged owns send_buf, and overwriting it would drop an
    // answer the client is still owed.
    var answering = UringConn{ .fd = -1, .gen = 0, .buf = &conn_buf, .filled = 54, .send_buf = &send_buf, .staged = 7, .inflight = 0, .closing = false };

    try std.testing.expect(!stageHangupAnswer(&answering, 0));
    try std.testing.expectEqual(@as(usize, 7), answering.staged);
}

test "zix http1: URING dispatch compacts the deferred head behind a pipelined request" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var body_buf: [256]u8 = undefined;
    var worker = testUringWorker(testEchoLenHandler, &body_buf, &arena);

    // A small POST answers in the same batch, then the oversized POST defers:
    // its head must be compacted to the front of buf for the deferred invoke.
    const first_req = "POST /a HTTP/1.1\r\nHost: t\r\nContent-Length: 2\r\n\r\nhi";
    const head = "POST /u HTTP/1.1\r\nHost: t\r\nContent-Length: 50000\r\n\r\n";
    var conn_buf: [256]u8 = undefined;
    @memcpy(conn_buf[0..first_req.len], first_req);
    @memcpy(conn_buf[first_req.len..][0..head.len], head);
    var send_buf: [4096]u8 = undefined;
    var conn = UringConn{ .fd = fds[1], .gen = 0, .buf = &conn_buf, .filled = first_req.len + head.len, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    const outcome = worker.dispatch(&conn);

    // The small POST staged its "2" echo, the oversized one deferred with its
    // head moved to the buffer front.
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, outcome);
    try std.testing.expect(std.mem.endsWith(u8, send_buf[0..conn.staged], "\r\n\r\n2:whole"));
    try std.testing.expectEqual(@as(usize, 50000), conn.drain);
    try std.testing.expectEqual(@as(usize, 0), conn.drain_received);
    try std.testing.expectEqual(head.len, conn.pending_head_len);
    try std.testing.expectEqualStrings(head, conn_buf[0..head.len]);

    // The staged echo goes out before the drain recvs arm (handleSend), so
    // the deferred request stages into a cleared send_buf. Simulate that,
    // complete the drain, and expect the counted total.
    conn.staged = 0;
    conn.drain_received += conn.drain;
    conn.drain = 0;
    conn.filled = conn.pending_head_len;

    const second = worker.dispatch(&conn);

    try std.testing.expectEqual(core.ConnOutcome.keep_alive, second);
    try std.testing.expect(std.mem.endsWith(u8, send_buf[0..conn.staged], "\r\n\r\n50000:whole"));
}

fn testOkHandler(_: *core.Request, res: *core.Response, _: *core.Context) anyerror!void {
    res.setContentType(.TEXT_PLAIN);

    try res.send("ok");
}

// Renders its body in place via the reserve path, exercising the staged_off
// adoption in dispatch.
fn testReserveHandler(req: *core.Request, _: *core.Response, _: *core.Context) anyerror!void {
    const region = core.responseReserve(req.fd, 32) orelse return error.ZixReserveUnavailable;
    const body = "{\"n\":42}";
    @memcpy(region[0..body.len], body);

    try core.responseCommit(req.fd, 200, "application/json", body.len);
}

// Echo every WebSocket text/binary frame back to the connection, staging through
// the active send sink that wsHandleBuf installs.
fn testWsEcho(fd: std.posix.fd_t, opcode: u8, payload: []const u8) void {
    ws.sendFD(fd, @enumFromInt(opcode), payload) catch {};
}

test "zix http1: URING wsHandleBuf accumulates a frame split across ring deliveries" {
    var payload_buf: [256]u8 = undefined;
    const Worker = UringWorker(testOkHandler);
    var worker = Worker{
        .ring = undefined,
        .slots = &[_]UringConn{},
        .listener_fd = -1,
        .gen_counter = 0,
        .recv_buf_size = 256,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &payload_buf,
        .body_buf = &[_]u8{},
        .ws_bufs = null,
    };

    // A connection whose conn.buf (256) is larger than a single ring delivery, so a
    // frame whose payload arrives in a later delivery accumulates across passes
    // instead of being dropped. This is exactly the room config.ws_recv_buf buys.
    var conn_buf: [256]u8 = undefined;
    var send_buf: [256]u8 = undefined;
    var conn = UringConn{ .fd = -1, .gen = 1, .buf = &conn_buf, .filled = 0, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false, .ws = testWsEcho };

    // Two masked client text frames, "hi" then "yo". The first ring delivery carries
    // all of frame 1 and only the header plus mask of frame 2 (its payload is still
    // in flight), so frame 2 is a partial that must be carried into conn.buf.
    const frame1 = [_]u8{ 0x81, 0x82, 0x01, 0x02, 0x03, 0x04, 'h' ^ 0x01, 'i' ^ 0x02 };
    const frame2 = [_]u8{ 0x81, 0x82, 0x05, 0x06, 0x07, 0x08, 'y' ^ 0x05, 'o' ^ 0x06 };

    const close1 = worker.wsHandleBuf(&conn, frame1 ++ frame2[0..6]);
    try std.testing.expect(!close1);
    // Frame 1 echoed already, frame 2's 6 header+mask bytes carried for the next pass.
    try std.testing.expectEqual(@as(usize, 6), conn.filled);
    const staged_after_first = conn.staged;
    try std.testing.expect(staged_after_first > 0);

    // The second delivery brings frame 2's payload: it appends to the carry, the now
    // complete frame is pumped, and its echo stages after frame 1's.
    const close2 = worker.wsHandleBuf(&conn, frame2[6..8]);
    try std.testing.expect(!close2);
    try std.testing.expectEqual(@as(usize, 0), conn.filled);
    try std.testing.expect(conn.staged > staged_after_first);

    // Both echoes are well-formed server frames carrying the original payloads.
    var scratch: [64]u8 = undefined;
    const first = ws.parseFrame(send_buf[0..conn.staged], &scratch).?;
    try std.testing.expectEqualStrings("hi", first.frame.payload);

    const second = ws.parseFrame(send_buf[first.consumed..conn.staged], &scratch).?;
    try std.testing.expectEqualStrings("yo", second.frame.payload);
}

test "zix http1: initUringRing yields a usable ring (flags or flagless fallback)" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    // Skip where io_uring is unavailable (older kernel, or blocked by a seccomp
    // sandbox): the engine itself falls back to EPOLL in that case.
    var ring = initUringRing() catch {
        std.log.info("io_uring is unavailable on this kernel, test skipped", .{});
        return;
    };
    defer ring.deinit();

    // Usable whether the kernel accepted the single-issuer fast-path flags or
    // the flagless fallback was taken. Getting an SQE proves the queues mapped.
    _ = try ring.get_sqe();
}

test "zix http1: URING finishClose rings the close and recycles the slot" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    const gpa = std.testing.allocator;

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer _ = linux.close(fds[0]);
    // fds[1] is handed to finishClose, which closes it via the ring (not here).

    const Worker = UringWorker(testOkHandler);
    const ring = initUringRing() catch {
        std.log.info("io_uring is unavailable on this kernel, test skipped", .{});
        return;
    };

    const slots = try gpa.alloc(UringConn, @as(usize, @intCast(fds[1])) + 1);
    var free_slots: [4]u32 = undefined;
    var worker = Worker{
        .ring = ring,
        .slots = slots,
        .free_slots = &free_slots,
        .listener_fd = -1,
        .gen_counter = 0,
        .recv_buf_size = 64,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &[_]u8{},
        .body_buf = &[_]u8{},
        .ws_bufs = null,
        .live_count = 1,
    };
    for (worker.slots) |*slot| slot.* = std.mem.zeroes(UringConn);
    defer {
        worker.ring.deinit();
        gpa.free(slots);
    }

    // A connection parked in its fd slot. finishClose returns its buffer slot
    // to the free-list and zeroes the fd slot, so the fd reads empty after.
    var conn_buf: [64]u8 = undefined;
    var send_buf: [64]u8 = undefined;
    const conn = &worker.slots[@intCast(fds[1])];
    conn.* = .{ .fd = fds[1], .gen = 1, .buf = &conn_buf, .filled = 0, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = true, .slot = 3 };

    worker.finishClose(conn);

    // Slot cleared (reads empty) and the buffer slot recycled for reuse.
    try std.testing.expectEqual(@as(usize, 0), worker.slots[@intCast(fds[1])].buf.len);
    try std.testing.expectEqual(@as(usize, 1), worker.free_count);
    try std.testing.expectEqual(@as(u32, 3), worker.free_slots[0]);
    try std.testing.expectEqual(@as(usize, 0), worker.live_count);

    // The close was staged on the ring, not run as a synchronous syscall:
    // submit and reap its CQE, which must report success and carry the .close
    // tag so the run loop routes it to the no-op arm.
    _ = try worker.ring.submit_and_wait(1);
    var cqes: [4]linux.io_uring_cqe = undefined;
    const count = try worker.ring.copy_cqes(&cqes, 0);
    try std.testing.expect(count >= 1);

    const decoded = uring.unpackUserData(cqes[0].user_data);
    try std.testing.expectEqual(uring.OpKind.close, decoded.op);
    try std.testing.expectEqual(@as(i32, 0), cqes[0].res);
}

test "zix http1: URING releaseSlot pools warm under cap, acquireSlot reuses LIFO" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const page = std.heap.page_size_min;

    const Worker = UringWorker(testOkHandler);
    const conn_slab = try slab.mapZeroedSlots(u8, page * 4);
    defer slab.unmapSlots(conn_slab);
    var free_slots: [4]u32 = undefined;
    var worker = Worker{
        .ring = undefined,
        .slots = &[_]UringConn{},
        .conn_slab = conn_slab,
        .stride = page,
        .free_slots = &free_slots,
        .listener_fd = -1,
        .gen_counter = 0,
        .recv_buf_size = 64,
        .send_buf_size = 64,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &[_]u8{},
        .body_buf = &[_]u8{},
        .ws_bufs = null,
        .idle_floor = 4,
    };

    // Fresh slots hand out compactly from 0.
    try std.testing.expectEqual(@as(u32, 0), worker.acquireSlot().?);
    try std.testing.expectEqual(@as(u32, 1), worker.acquireSlot().?);
    try std.testing.expectEqual(@as(usize, 2), worker.slot_top);

    // The recv and send slices carve the same stride back to back.
    const recv_slice = worker.slotRecvBuf(1);
    const send_slice = worker.slotSendBuf(1);
    try std.testing.expectEqual(@intFromPtr(recv_slice.ptr) + 64, @intFromPtr(send_slice.ptr));

    // LIFO: the most recently released slot is reused first (warmest pages),
    // and the free stack shrinks back as slots are drawn.
    worker.releaseSlot(0);
    worker.releaseSlot(1);
    try std.testing.expectEqual(@as(usize, 2), worker.free_count);
    try std.testing.expectEqual(@as(u32, 1), worker.acquireSlot().?);
    try std.testing.expectEqual(@as(u32, 0), worker.acquireSlot().?);
    try std.testing.expectEqual(@as(usize, 0), worker.free_count);

    // Slab exhausted (4 one-page strides): the fifth fresh slot is refused.
    try std.testing.expectEqual(@as(u32, 2), worker.acquireSlot().?);
    try std.testing.expectEqual(@as(u32, 3), worker.acquireSlot().?);
    try std.testing.expectEqual(@as(?u32, null), worker.acquireSlot());
}

test "zix http1: URING process queue parks FIFO, rejects the newest at full, and wraps" {
    const Worker = UringWorker(testOkHandler);
    var entries: [2]ParkEntry = undefined;
    var worker = Worker{
        .ring = undefined,
        .slots = &[_]UringConn{},
        .listener_fd = -1,
        .gen_counter = 0,
        .recv_buf_size = 64,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &[_]u8{},
        .body_buf = &[_]u8{},
        .ws_bufs = null,
        .park_entries = &entries,
    };

    try std.testing.expect(worker.parkPush(.recv, 10, 1));
    try std.testing.expect(worker.parkPush(.send, 11, 2));

    // Full: the newest entry is rejected, the parked ones stay untouched.
    try std.testing.expect(!worker.parkPush(.recv, 12, 3));
    try std.testing.expectEqual(@as(usize, 2), worker.park_len);

    // FIFO: the oldest entry pops first.
    const first = worker.parkPop().?;
    try std.testing.expectEqual(@as(std.posix.fd_t, 10), first.fd);
    try std.testing.expectEqual(ParkKind.recv, first.kind);

    // Wrap: this push lands past the ring end and still pops in order.
    try std.testing.expect(worker.parkPush(.drain_recv, 12, 3));

    const second = worker.parkPop().?;
    try std.testing.expectEqual(@as(std.posix.fd_t, 11), second.fd);
    try std.testing.expectEqual(ParkKind.send, second.kind);

    const third = worker.parkPop().?;
    try std.testing.expectEqual(ParkKind.drain_recv, third.kind);
    try std.testing.expectEqual(@as(?ParkEntry, null), worker.parkPop());
}

test "zix http1: URING process queue off (len 0) never parks" {
    const Worker = UringWorker(testOkHandler);
    var worker = Worker{
        .ring = undefined,
        .slots = &[_]UringConn{},
        .listener_fd = -1,
        .gen_counter = 0,
        .recv_buf_size = 64,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &[_]u8{},
        .body_buf = &[_]u8{},
        .ws_bufs = null,
    };

    try std.testing.expect(!worker.parkPush(.recv, 10, 1));
    try std.testing.expectEqual(@as(usize, 0), worker.park_len);
    try std.testing.expectEqual(@as(?ParkEntry, null), worker.parkPop());
}

test "zix http1: URING drainParked drops a stale gen entry without touching the connection" {
    const Worker = UringWorker(testOkHandler);
    var slots: [16]UringConn = @splat(std.mem.zeroes(UringConn));
    var entries: [4]ParkEntry = undefined;
    var worker = Worker{
        .ring = undefined,
        .slots = &slots,
        .listener_fd = -1,
        .gen_counter = 0,
        .recv_buf_size = 64,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &[_]u8{},
        .body_buf = &[_]u8{},
        .ws_bufs = null,
        .park_entries = &entries,
    };

    var conn_buf: [64]u8 = undefined;
    var send_buf: [64]u8 = undefined;
    slots[5] = .{ .fd = 5, .gen = 2, .buf = &conn_buf, .filled = 0, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    // Parked under gen 1, then the fd closed and was reused under gen 2: the
    // entry is stale and must be a no-op, never an arm on the new connection.
    try std.testing.expect(worker.parkPush(.recv, 5, 1));

    worker.drainParked();

    try std.testing.expectEqual(@as(usize, 0), worker.park_len);
    try std.testing.expect(!slots[5].closing);
    try std.testing.expectEqual(@as(usize, 0), slots[5].filled);
}

test "zix http1: URING pending accept re-arm is retried by drainParked" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
    }

    const Worker = UringWorker(testOkHandler);
    var worker = Worker{
        .ring = initUringRing() catch {
            std.log.info("io_uring is unavailable on this kernel, test skipped", .{});
            return;
        },
        .slots = &[_]UringConn{},
        .listener_fd = fds[0],
        .gen_counter = 0,
        .recv_buf_size = 64,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &[_]u8{},
        .body_buf = &[_]u8{},
        .ws_bufs = null,
    };
    defer worker.ring.deinit();

    // Simulate an accept re-arm lost to a full SQ: the flag is set and no SQE
    // exists yet. drainParked must stage the accept and clear the flag.
    worker.accept_pending = true;

    worker.drainParked();

    try std.testing.expect(!worker.accept_pending);
    try std.testing.expectEqual(@as(u32, 1), worker.ring.sq_ready());
}

test "zix http1: URING drainParked re-arms a parked recv on the ring" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    const gpa = std.testing.allocator;

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
    }

    const Worker = UringWorker(testOkHandler);
    var entries: [4]ParkEntry = undefined;
    const ring = initUringRing() catch {
        std.log.info("io_uring is unavailable on this kernel, test skipped", .{});
        return;
    };

    const slots = try gpa.alloc(UringConn, @as(usize, @intCast(fds[1])) + 1);
    var worker = Worker{
        .ring = ring,
        .slots = slots,
        .listener_fd = -1,
        .gen_counter = 0,
        .recv_buf_size = 64,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &[_]u8{},
        .body_buf = &[_]u8{},
        .ws_bufs = null,
        .park_entries = &entries,
    };
    for (worker.slots) |*slot| slot.* = std.mem.zeroes(UringConn);
    defer {
        worker.ring.deinit();
        gpa.free(slots);
    }

    var conn_buf: [64]u8 = undefined;
    var send_buf: [64]u8 = undefined;
    const conn = &worker.slots[@intCast(fds[1])];
    conn.* = .{ .fd = fds[1], .gen = 1, .buf = &conn_buf, .filled = 0, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    // A recv parked while the SQ was full is re-armed on the next drain pass:
    // the entry leaves the ring and one recv SQE is staged for the connection.
    try std.testing.expect(worker.parkPush(.recv, fds[1], 1));

    worker.drainParked();

    try std.testing.expectEqual(@as(usize, 0), worker.park_len);
    try std.testing.expectEqual(@as(u32, 1), worker.ring.sq_ready());
    try std.testing.expect(!conn.closing);
}

test "zix http1: URING drainParked re-arms a parked WS recv through the buffer ring" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    const gpa = std.testing.allocator;

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
    }

    const Worker = UringWorker(testOkHandler);
    var entries: [4]ParkEntry = undefined;
    const ring = initUringRing() catch {
        std.log.info("io_uring is unavailable on this kernel, test skipped", .{});
        return;
    };

    const slots = try gpa.alloc(UringConn, @as(usize, @intCast(fds[1])) + 1);
    var worker = Worker{
        .ring = ring,
        .slots = slots,
        .listener_fd = -1,
        .gen_counter = 0,
        .recv_buf_size = 64,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &[_]u8{},
        .body_buf = &[_]u8{},
        .ws_bufs = null,
        .park_entries = &entries,
    };
    for (worker.slots) |*slot| slot.* = std.mem.zeroes(UringConn);
    defer {
        worker.ring.deinit();
        gpa.free(slots);
    }

    // Shared provided-buffer ring, skip where the kernel lacks buffer rings
    // (the engine then uses the plain recv path, covered by the test above).
    worker.ws_bufs = IoUring.BufferGroup.init(&worker.ring, gpa, WS_RING_BGID, WS_RING_BUF_SIZE, 4) catch {
        std.log.info("io_uring buffer groups are unavailable on this kernel, test skipped", .{});
        return;
    };
    defer if (worker.ws_bufs) |*bg| bg.deinit(gpa);

    var conn_buf: [64]u8 = undefined;
    var send_buf: [64]u8 = undefined;
    const conn = &worker.slots[@intCast(fds[1])];
    conn.* = .{ .fd = fds[1], .gen = 1, .buf = &conn_buf, .filled = 0, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false, .ws = testWsEcho };

    // A parked upgraded connection re-arms through armRecv -> armWsRecv: the
    // entry leaves the ring and one buffer-select recv SQE is staged, the
    // connection is never closed. The frames themselves waited in the kernel
    // socket buffer the whole time, so delay is the only possible symptom.
    try std.testing.expect(worker.parkPush(.recv, fds[1], 1));

    worker.drainParked();

    try std.testing.expectEqual(@as(usize, 0), worker.park_len);
    try std.testing.expectEqual(@as(u32, 1), worker.ring.sq_ready());
    try std.testing.expect(!conn.closing);
}

test "zix http1: URING idleCap clamps between the floor and the ceiling as live concurrency moves" {
    const Worker = UringWorker(testOkHandler);
    var worker = Worker{
        .ring = undefined,
        .slots = &[_]UringConn{},
        .listener_fd = -1,
        .gen_counter = 0,
        .recv_buf_size = 64,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &[_]u8{},
        .body_buf = &[_]u8{},
        .ws_bufs = null,
        .idle_floor = 8,
        .idle_ceiling = 256,
    };

    // Idle: the cap is the floor, so a quiet worker still keeps a small warm pool.
    try std.testing.expectEqual(@as(usize, 8), worker.idleCap());

    // Moderate load below the ceiling: the cap tracks the live connection count, so
    // the pool keeps a full reconnect of the working set warm.
    worker.live_count = 200;
    try std.testing.expectEqual(@as(usize, 200), worker.idleCap());

    // High load: the ceiling holds the warm set below live_count, so the worker does
    // not keep thousands of closed connections resident on top of the live ones.
    worker.live_count = 4096;
    try std.testing.expectEqual(@as(usize, 256), worker.idleCap());
}

test "zix http1: URING releaseSlot past the ceiling returns the oldest warm stride to the OS" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const page = std.heap.page_size_min;

    // Ceiling of 1 with a high live_count: the warm span is held at 1, so the
    // second release advises the oldest warm stride away (the LRU eviction).
    const Worker = UringWorker(testOkHandler);
    const conn_slab = try slab.mapZeroedSlots(u8, page * 4);
    defer slab.unmapSlots(conn_slab);
    var free_slots: [4]u32 = undefined;
    var worker = Worker{
        .ring = undefined,
        .slots = &[_]UringConn{},
        .conn_slab = conn_slab,
        .stride = page,
        .free_slots = &free_slots,
        .listener_fd = -1,
        .gen_counter = 0,
        .recv_buf_size = 64,
        .send_buf_size = 64,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &[_]u8{},
        .body_buf = &[_]u8{},
        .ws_bufs = null,
        .idle_floor = 1,
        .idle_ceiling = 1,
        .live_count = 4096,
    };

    // Without the ceiling, idleCap would be max(4096, 1) = 4096 and never evict.
    try std.testing.expectEqual(@as(usize, 1), worker.idleCap());

    @memset(worker.slotStride(0), 0xAA);
    @memset(worker.slotStride(1), 0xAA);

    // Release slot 0 (older) then slot 1 (newer). The second release overflows
    // the warm cap and evicts the OLDEST warm entry (slot 0): its pages return
    // to the OS and read zero, while the just-released slot 1 stays resident.
    worker.releaseSlot(0);
    worker.releaseSlot(1);

    try std.testing.expectEqual(@as(usize, 2), worker.free_count);
    try std.testing.expectEqual(@as(usize, 1), worker.cold_count);
    try std.testing.expectEqual(@as(u8, 0), worker.slotStride(0)[0]);
    try std.testing.expectEqual(@as(u8, 0xAA), worker.slotStride(1)[0]);

    // Reuse pops the warm slot first, then the cold one, both allocation-free,
    // and the cold boundary clamps back as the stack drains.
    try std.testing.expectEqual(@as(u32, 1), worker.acquireSlot().?);
    try std.testing.expectEqual(@as(u32, 0), worker.acquireSlot().?);
    try std.testing.expectEqual(@as(usize, 0), worker.cold_count);
}

test "zix http1: URING destroyConn frees a heap-grown send_buf and recycles the slot" {
    const gpa = std.heap.smp_allocator;

    const Worker = UringWorker(testOkHandler);
    var slots: [8]UringConn = @splat(std.mem.zeroes(UringConn));
    var free_slots: [4]u32 = undefined;
    var worker = Worker{
        .ring = undefined,
        .slots = &slots,
        .free_slots = &free_slots,
        .listener_fd = -1,
        .gen_counter = 0,
        .recv_buf_size = 64,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &[_]u8{},
        .body_buf = &[_]u8{},
        .ws_bufs = null,
        .live_count = 1,
    };

    // A connection whose send_buf was switched to a heap buffer by the sink's
    // grow path (send_heap). destroyConn frees it, returns the slab slot, and
    // zeroes the fd slot so the next accept starts from the slab slice again.
    var conn_buf: [64]u8 = undefined;
    const heap_send = try gpa.alloc(u8, 2 * URING_SEND_BUF_SIZE);
    slots[3] = .{ .fd = 3, .gen = 1, .buf = &conn_buf, .filled = 0, .send_buf = heap_send, .staged = 0, .inflight = 0, .closing = false, .slot = 2, .send_heap = true };

    worker.destroyConn(&slots[3]);

    try std.testing.expectEqual(@as(usize, 0), slots[3].buf.len);
    try std.testing.expect(!slots[3].send_heap);
    try std.testing.expectEqual(@as(usize, 1), worker.free_count);
    try std.testing.expectEqual(@as(u32, 2), worker.free_slots[0]);
    try std.testing.expectEqual(@as(usize, 0), worker.live_count);
}

test "zix http1: URING dispatch grows a slab-backed send_buf onto the heap for an oversized response" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var body_buf: [4096]u8 = undefined;
    var worker = testUringWorker(testBigBodyHandler, &body_buf, &arena);

    // send_buf far smaller than the response: the sink must switch to a heap
    // buffer (a slab slice cannot realloc), mark it, and stage the full bytes.
    const req = "GET /big HTTP/1.1\r\nHost: t\r\n\r\n";
    var conn_buf: [4096]u8 = undefined;
    @memcpy(conn_buf[0..req.len], req);
    var send_buf: [64]u8 = undefined;
    var conn = UringConn{ .fd = fds[1], .gen = 0, .buf = &conn_buf, .filled = req.len, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    const outcome = worker.dispatch(&conn);
    defer if (conn.send_heap) std.heap.smp_allocator.free(conn.send_buf);

    try std.testing.expectEqual(core.ConnOutcome.keep_alive, outcome);
    try std.testing.expect(conn.send_heap);
    try std.testing.expect(conn.send_buf.ptr != @as([*]u8, &send_buf));

    // The staged response is intact end to end on the heap buffer.
    const resp = conn.send_buf[0..conn.staged];
    const tail: [512]u8 = @splat('Z');

    try std.testing.expect(std.mem.indexOf(u8, resp, "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.endsWith(u8, resp, &tail));
}

test "zix http1: URING cache hit replays zero-copy with the slot pinned until teardown" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var rc = try cache.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 4096 });
    defer rc.deinit();
    core.setCache(&rc, 60_000);
    defer core.setCache(null, 1000);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var body_buf: [1024]u8 = undefined;
    var worker = testUringWorker(testCacheHitHandler, &body_buf, &arena);
    worker.live_count = 1;

    const req = "GET /cache HTTP/1.1\r\nHost: t\r\n\r\n";
    var conn_buf: [1024]u8 = undefined;
    @memcpy(conn_buf[0..req.len], req);
    var send_buf: [1024]u8 = undefined;
    var conn = UringConn{ .fd = fds[1], .gen = 0, .buf = &conn_buf, .filled = req.len, .send_buf = &send_buf, .staged = 0, .inflight = 0, .closing = false };

    // Miss: the response stages through the copy path, nothing borrowed.
    const first = worker.dispatch(&conn);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, first);
    try std.testing.expect(conn.staged > 0);
    try std.testing.expectEqual(@as(usize, 0), conn.direct.len);

    // Hit: the whole response is the borrowed cache-slab slice, the stage
    // buffer holds nothing, and the slot is pinned for the send lifetime.
    conn.staged = 0;
    @memcpy(conn_buf[0..req.len], req);
    conn.filled = req.len;

    const second = worker.dispatch(&conn);
    try std.testing.expectEqual(core.ConnOutcome.keep_alive, second);
    try std.testing.expectEqual(@as(usize, 0), conn.staged);
    try std.testing.expect(conn.direct.len > 0);
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", conn.direct);

    const slab_base = @intFromPtr(rc.slab.ptr);
    const direct_base = @intFromPtr(conn.direct.ptr);
    try std.testing.expect(direct_base >= slab_base and direct_base < slab_base + rc.slab.len);
    try std.testing.expectEqual(@as(u32, 1), rc.pins[conn.direct_slot]);

    // While pinned, a store for the same key is refused (bytes stay stable).
    const key = cache.hashKey("GET", "/cache", "");
    try std.testing.expect(!rc.store(key, "clobber", 60_000, cache.nowMillis()));

    // Teardown releases the pin (the send-completion path unpins the same way).
    const pinned_slot = conn.direct_slot;
    worker.destroyConn(&conn);
    try std.testing.expectEqual(@as(u32, 0), rc.pins[pinned_slot]);
}

// Replays the cached response on a hit (the whole-response idiom the entry
// json path uses), stores and writes on a miss.
fn testCacheHitHandler(req: *core.Request, res: *core.Response, _: *core.Context) anyerror!void {
    if (core.cacheLookup(req.head)) |bytes| {
        try res.sendRaw(bytes);
        return;
    }

    return core.sendWithCacheFD(req.fd, req.head, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello", core.cacheTtl());
}

test "zix http1: URING pretouchSlab touches only the floor strides and keeps them zero" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const page = std.heap.page_size_min;

    const Worker = UringWorker(testOkHandler);
    const conn_slab = try slab.mapZeroedSlots(u8, page * 4);
    defer slab.unmapSlots(conn_slab);
    var worker = Worker{
        .ring = undefined,
        .slots = &[_]UringConn{},
        .conn_slab = conn_slab,
        .stride = page,
        .listener_fd = -1,
        .gen_counter = 0,
        .recv_buf_size = 64,
        .send_buf_size = 64,
        .handler_timeout_ms = 0,
        .ws_payload_buf = &[_]u8{},
        .body_buf = &[_]u8{},
        .ws_bufs = null,
        .idle_floor = 2,
    };

    // Touches the first idle_floor strides without altering content, and a
    // zero floor (or an empty slab in dispatch-level tests) is a no-op.
    worker.pretouchSlab();
    try std.testing.expectEqual(@as(u8, 0), conn_slab[0]);
    try std.testing.expectEqual(@as(u8, 0), conn_slab[page]);

    worker.idle_floor = 0;
    worker.pretouchSlab();

    worker.conn_slab = &.{};
    worker.stride = 0;
    worker.pretouchSlab();
}

// Sends a body larger than the test connection's send_buf so the sink's
// grow-from-slab path runs end to end through dispatch.
fn testBigBodyHandler(_: *core.Request, res: *core.Response, _: *core.Context) anyerror!void {
    res.setContentType(.TEXT_PLAIN);

    const body: [512]u8 = @splat('Z');
    try res.send(&body);
}
