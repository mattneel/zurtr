//! zix http .URING dispatch model (Linux-only): shared-nothing io_uring ring per
//! worker. Each readable batch recvs into the connection buffer, runs one request
//! through processRequest with the response staged into a RespSink, and submits
//! one coalesced send. Half-duplex per connection, one request per buffer (matches
//! the EPOLL path, ADR-037 Phase 4 step 4).

const std = @import("std");
const builtin = @import("builtin");
const common = @import("common.zig");
const epoll_model = @import("epoll.zig");
const logSystem = common.logSystem;
const processRequest = common.processRequest;
const pinToCpu = common.pinToCpu;
const getAvailableCpuCount = common.getAvailableCpuCount;
const effectiveCacheEntries = common.effectiveCacheEntries;
const setNoDelay = common.setNoDelay;
const setNonBlock = common.setNonBlock;
const UringHttpConn = common.UringHttpConn;
const HttpProcOutcome = common.HttpProcOutcome;
const MAX_FD = common.MAX_FD;
const URING_CQE_BATCH = common.URING_CQE_BATCH;
const URING_SEND_BUF_SIZE = common.URING_SEND_BUF_SIZE;
const parser = @import("../parser.zig");
const rcache = @import("../../../utils/response_cache.zig");
const resp_mod = @import("../response.zig");
const setCache = resp_mod.setCache;
const setCompression = resp_mod.setCompression;
const RespSink = resp_mod.RespSink;
const writeAllFD = resp_mod.writeAllFD;
const uring = @import("../../../multiplexers/ring.zig");
const slab = @import("../../../multiplexers/slab.zig");
const reuseport = @import("../../../multiplexers/reuseport.zig");
const listen_report = @import("../../../multiplexers/listen_report.zig");
const tls_mux = @import("../tls_mux.zig");
const tls_conn = @import("../../../multiplexers/tls_conn.zig");
const Tls = @import("../../../tls/Tls.zig");
const IoUring = std.os.linux.IoUring;

/// SQ entries per worker ring.
const URING_ENTRIES: u16 = 4096;

/// CQ entries per worker ring (multishot completion headroom).
const URING_CQ_ENTRIES: u32 = 16 * 1024;

/// io_uring SQPOLL kernel-thread idle before it sleeps, in milliseconds. Inert
/// unless IORING_SETUP_SQPOLL is set (it is not here), kept for when it is.
const URING_SQ_THREAD_IDLE_MS: u32 = 1000;

/// Initialize a worker ring with the single-issuer fast-path flags, falling back
/// to a flagless ring when the kernel does not support them. Mirrors the
/// zix.Http1 ring init.
fn initUringRing() !IoUring {
    if (comptime builtin.os.tag != .linux) return error.ZixPlatformNotSupported;

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

/// Default minimum warm idle-connection pool floor. Overridden per worker from
/// config.uring_idle_pool_floor. Mirrors the zix.Http1 URING idle pool.
const URING_IDLE_POOL_FLOOR: usize = 8;

/// Default absolute warm idle-connection pool ceiling. Overridden per worker
/// from config.uring_idle_pool_ceiling. Mirrors the zix.Http1 URING idle pool.
const URING_IDLE_POOL_CEILING: usize = 256;

/// Which re-arm a parked process-queue entry retries. Mirrors the zix.Http1
/// URING park queue (this engine has no drain path, so recv and send only).
const ParkKind = enum(u8) { recv, send };

/// Postponed re-arm reference for the process queue (config.process_queue_len).
/// Holds no request bytes: the connection's own buffers keep the data, the
/// entry only records which arm to retry once the submission queue has space.
/// The generation guards against fd reuse, a stale entry is skipped.
const ParkEntry = struct {
    fd: std.posix.fd_t,
    gen: u24,
    kind: ParkKind,
};

// --------------------------------------------------------- //
// URING dispatch (Linux): shared-nothing io_uring ring per worker.

/// Per-worker io_uring completion loop, parameterized by the concrete server
/// pointer type (the router is comptime-baked into the server, ADR-043). Hoisting
/// this to module scope (instead of a struct local to uringWorker) lets the idle
/// pool and prewarm be unit-tested directly, mirroring the zix.Http1 URING worker.
///
/// Param:
/// ServerPtr - type (pointer to the Server instance)
fn UringWorker(comptime ServerPtr: type) type {
    return struct {
        ring: IoUring,
        slots: []?*UringHttpConn,
        listener_fd: std.posix.fd_t,
        gen_counter: u24,
        server: ServerPtr,
        io: std.Io,
        arena: *std.heap.ArenaAllocator,
        recv_buf_size: usize,
        /// Per-connection send buffer size, set from config.uring_send_buf_size.
        send_buf_size: usize = URING_SEND_BUF_SIZE,
        /// SO_BUSY_POLL window applied to each accepted connection, set from config.busy_poll_us.
        /// Defaulted to 0 so dispatch-level tests need not set it (EPOLL parity).
        busy_poll_us: u32 = 0,
        /// Warm idle-connection pool, doubly linked (most-recently-used at the head). A closed
        /// connection is pooled with its recv and send buffers intact instead of freed, so a later
        /// accept reuses the allocation. This removes the three per-connection heap allocations
        /// (struct + recv buf + send buf) from the steady-state accept/close cycle. Past idleCap the
        /// least-recently-used tail is evicted, so the buffer reclaimed is never the one a churn
        /// accept is about to reuse. Mirrors the zix.Http1 URING idle pool.
        warm_head: ?*UringHttpConn = null,
        warm_tail: ?*UringHttpConn = null,
        warm_count: usize = 0,
        /// Cold idle-connection stack. An evicted warm tail has its buffer pages returned to the OS
        /// (MADV_DONTNEED) and is pushed here. The struct and virtual allocation stay reusable, so an
        /// accept that drains the warm pool reuses a cold connection with no allocator call, paying
        /// only a recv first-touch fault. Singly linked via next.
        cold_head: ?*UringHttpConn = null,
        /// Live connections held in the slot table (this worker's concurrency). The warm pool cap is
        /// derived from this so the pool always covers the active working set. See idleCap.
        live_count: usize = 0,
        /// Minimum warm pool floor, set from config.uring_idle_pool_floor.
        idle_floor: usize = URING_IDLE_POOL_FLOOR,
        /// Absolute warm pool ceiling, set from config.uring_idle_pool_ceiling.
        idle_ceiling: usize = URING_IDLE_POOL_CEILING,
        /// Dual-listener TLS side (config.tls + config.tls_port). Inactive by default (-1 / null),
        /// so a cleartext-only worker sees zero layout change on its hot structures.
        tls_listener_fd: std.posix.fd_t = -1,
        tls_ctx: ?*Tls.Context = null,
        tls_conns: ?TlsConnTable = null,
        tls_gen_counter: u24 = 0,
        /// Requests served by this worker (cleartext dispatch). Single-owner plain
        /// increment (no contention), reported through the system logger at worker
        /// exit so REUSEPORT skew across workers is measurable.
        requests_served: u64 = 0,
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
        /// Mirrors the zix.Http1 URING park queue.
        park_entries: []ParkEntry = &.{},
        /// Ring read position of the oldest parked entry.
        park_head: usize = 0,
        /// Parked entries currently in the ring.
        park_len: usize = 0,

        const W = @This();
        const allocator = std.heap.smp_allocator;
        const lx = std.os.linux;

        const TlsWorker = tls_mux.Worker(ServerPtr);

        /// Ring-hosted TLS connection (dual listener): the shared TLS connection (tls_mux) plus
        /// ring bookkeeping. The ciphertext recv buffer is per connection because the kernel
        /// fills it asynchronously (the .EPOLL paths read into per-event stack staging instead).
        const UringTlsConn = struct {
            conn: TlsWorker.TlsConn,
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

        fn deinit(worker: *W) void {
            for (worker.slots) |maybe_conn| {
                if (maybe_conn) |conn| {
                    _ = lx.close(conn.fd);
                    allocator.free(conn.buf);
                    allocator.free(conn.send_buf);
                    allocator.destroy(conn);
                }
            }

            var warm = worker.warm_head;
            while (warm) |conn| {
                warm = conn.next;
                allocator.free(conn.buf);
                allocator.free(conn.send_buf);
                allocator.destroy(conn);
            }

            var cold = worker.cold_head;
            while (cold) |conn| {
                cold = conn.next;
                allocator.free(conn.buf);
                allocator.free(conn.send_buf);
                allocator.destroy(conn);
            }

            slab.unmapSlots(worker.slots);
            if (worker.park_entries.len > 0) allocator.free(worker.park_entries);
            if (worker.tls_conns) |*tls_table| tls_table.deinit();
            worker.ring.deinit();
        }

        /// Take a connection object for a freshly accepted fd: pop one from the idle pool (recv and
        /// send buffers intact) when available, otherwise allocate a new one with both buffers. The
        /// warm pool is preferred (pages resident, no fault), the cold pool is the fallback (reusable,
        /// its first recv faults the pages back). Returns null only when a fresh allocation fails. The
        /// caller resets the per-connection state fields.
        fn acquireConn(worker: *W) ?*UringHttpConn {
            if (worker.warm_head) |conn| {
                worker.warm_head = conn.next;
                if (worker.warm_head) |head| head.prev = null else worker.warm_tail = null;
                worker.warm_count -= 1;

                return conn;
            }

            if (worker.cold_head) |conn| {
                worker.cold_head = conn.next;

                return conn;
            }

            const conn = allocator.create(UringHttpConn) catch return null;
            const buf = allocator.alloc(u8, worker.recv_buf_size) catch {
                allocator.destroy(conn);
                return null;
            };
            const send_buf = allocator.alloc(u8, worker.send_buf_size) catch {
                allocator.free(buf);
                allocator.destroy(conn);
                return null;
            };
            conn.buf = buf;
            conn.send_buf = send_buf;

            return conn;
        }

        /// Seed the warm idle pool with idle_floor connections before the accept
        /// loop starts, so the first burst of accepts reuses resident buffers
        /// instead of allocating and first-touch faulting them under load. Without
        /// it the first run after startup pays every connection's allocation and
        /// page fault while a later run (pool already warm from the prior run) does
        /// not, which reads as a cold-first-run gap in back-to-back measurements.
        ///
        /// Note:
        /// - The seed count is idle_floor, the reserve the pool settles to when
        ///   idle (see idleCap). Seeding to it keeps the resident set identical to
        ///   steady state, so the cost is paid once at startup, not carried as
        ///   extra memory.
        /// - Each connection's recv and send buffers are touched page by page so
        ///   the pages are resident up front, not faulted on the first recv.
        /// - A partial allocation failure stops the seed early and leaves whatever
        ///   was already warmed. Startup never fails on a warm-pool short-fall: the
        ///   accept path still allocates on demand when the pool is empty.
        fn prewarmPool(worker: *W) void {
            var seeded: usize = 0;
            while (seeded < worker.idle_floor) : (seeded += 1) {
                const conn = allocator.create(UringHttpConn) catch break;
                const buf = allocator.alloc(u8, worker.recv_buf_size) catch {
                    allocator.destroy(conn);
                    break;
                };
                const send_buf = allocator.alloc(u8, worker.send_buf_size) catch {
                    allocator.free(buf);
                    allocator.destroy(conn);
                    break;
                };

                @memset(buf, 0);
                @memset(send_buf, 0);

                conn.buf = buf;
                conn.send_buf = send_buf;
                conn.prev = null;
                conn.next = worker.warm_head;
                if (worker.warm_head) |head| head.prev = conn;
                worker.warm_head = conn;
                if (worker.warm_tail == null) worker.warm_tail = conn;
                worker.warm_count += 1;
            }
        }

        /// Warm idle-pool cap, derived from this worker's live concurrency so the pool keeps up to one
        /// full reconnect of the live working set warm. The floor keeps a small warm reserve when idle.
        fn idleCap(worker: *const W) usize {
            return @min(worker.idle_ceiling, @max(worker.live_count, worker.idle_floor));
        }

        /// Evict the least-recently-used warm connection (the tail) to the cold stack: return its
        /// buffer pages to the OS with MADV_DONTNEED, unlink it from the warm pool, and push it cold.
        /// Reclaiming the LRU tail (not the connection just released, which is the hot head) keeps the
        /// active churn working set resident.
        fn evictColdTail(worker: *W) void {
            const victim = worker.warm_tail orelse return;

            worker.warm_tail = victim.prev;
            if (victim.prev) |p| p.next = null else worker.warm_head = null;
            worker.warm_count -= 1;

            slab.releaseSlabPages(victim.buf);
            slab.releaseSlabPages(victim.send_buf);

            victim.prev = null;
            victim.next = worker.cold_head;
            worker.cold_head = victim;
        }

        /// Return a closed connection to the warm idle pool, then trim the cold tail if the pool now
        /// exceeds the cap. A send_buf the grow allocator doubled for an oversized response is shrunk
        /// back to the base size so a connection that served one large response does not carry a
        /// multi-MiB buffer for life. Both steps are off the parse and handler hot path.
        fn releaseConn(worker: *W, conn: *UringHttpConn) void {
            if (conn.send_buf.len > worker.send_buf_size) {
                if (allocator.realloc(conn.send_buf, worker.send_buf_size)) |shrunk| {
                    conn.send_buf = shrunk;
                } else |_| {}
            }

            conn.prev = null;
            conn.next = worker.warm_head;
            if (worker.warm_head) |head| head.prev = conn;
            worker.warm_head = conn;
            if (worker.warm_tail == null) worker.warm_tail = conn;
            worker.warm_count += 1;

            if (worker.warm_count > worker.idleCap()) worker.evictColdTail();
        }

        fn getSqe(worker: *W) ?*lx.io_uring_sqe {
            return worker.ring.get_sqe() catch {
                _ = worker.ring.submit() catch return null;

                return worker.ring.get_sqe() catch null;
            };
        }

        fn lookup(worker: *W, decoded: uring.Decoded) ?*UringHttpConn {
            return worker.lookupFd(decoded.fd, decoded.gen);
        }

        /// Slot lookup by fd + generation. A mismatched generation means the fd
        /// was closed and reused, so the reference is stale and must be ignored.
        fn lookupFd(worker: *W, fd: std.posix.fd_t, gen: u24) ?*UringHttpConn {
            const idx: usize = @intCast(fd);
            if (idx >= worker.slots.len) return null;

            const conn = worker.slots[idx] orelse return null;
            if (conn.gen != gen) return null;

            return conn;
        }

        /// Park a postponed re-arm on the process queue (FIFO ring).
        ///
        /// Return:
        /// - true when parked
        /// - false when the feature is off (empty ring) or the ring is full
        ///   (reject-newest, the caller falls back to the close path)
        fn parkPush(worker: *W, kind: ParkKind, fd: std.posix.fd_t, gen: u24) bool {
            if (worker.park_entries.len == 0) return false;
            if (worker.park_len == worker.park_entries.len) return false;

            const tail = (worker.park_head + worker.park_len) % worker.park_entries.len;
            worker.park_entries[tail] = .{ .fd = fd, .gen = gen, .kind = kind };
            worker.park_len += 1;

            return true;
        }

        /// Pop the oldest parked entry, or null when the ring is empty.
        fn parkPop(worker: *W) ?ParkEntry {
            if (worker.park_len == 0) return null;

            const entry = worker.park_entries[worker.park_head];
            worker.park_head = (worker.park_head + 1) % worker.park_entries.len;
            worker.park_len -= 1;

            return entry;
        }

        /// Retry postponed work once the SQ has space again: the lost accept
        /// re-arms first (a lost accept stalls the worker permanently), then the
        /// parked entries in FIFO order. Runs at the top of each loop pass,
        /// right after submit_and_wait pushed the staged SQEs to the kernel.
        /// Stops as soon as a retry re-parks (the SQ filled up again), the
        /// remaining entries wait for the next pass. Stale entries (gen
        /// mismatch after a close and fd reuse) are dropped as no-ops.
        fn drainParked(worker: *W) void {
            if (worker.accept_pending) {
                worker.accept_pending = false;
                worker.armAccept();
                if (worker.accept_pending) return;
            }

            if (worker.tls_accept_pending) {
                worker.tls_accept_pending = false;
                worker.armTlsAccept();
                if (worker.tls_accept_pending) return;
            }

            var budget = worker.park_len;
            while (budget > 0) : (budget -= 1) {
                const entry = worker.parkPop() orelse return;
                const before = worker.park_len;

                const conn = worker.lookupFd(entry.fd, entry.gen) orelse continue;
                switch (entry.kind) {
                    .recv => worker.armRecv(conn),
                    .send => worker.submitSend(conn),
                }

                if (worker.park_len > before) return;
            }
        }

        fn destroyConn(worker: *W, conn: *UringHttpConn) void {
            worker.slots[@intCast(conn.fd)] = null;
            worker.live_count -= 1;

            worker.releaseConn(conn);
        }

        fn finishClose(worker: *W, conn: *UringHttpConn) void {
            _ = lx.close(conn.fd);
            worker.destroyConn(conn);
        }

        fn beginClose(worker: *W, conn: *UringHttpConn) void {
            conn.closing = true;
            if (conn.inflight > 0) return;

            if (conn.staged > 0) {
                worker.submitSend(conn);
                return;
            }

            worker.finishClose(conn);
        }

        fn armAccept(worker: *W) void {
            const sqe = worker.getSqe() orelse {
                // SQ full even after a submit: mark the re-arm pending so the
                // loop retries next pass. Losing it stops accepting for good.
                worker.accept_pending = true;
                return;
            };

            sqe.prep_multishot_accept(worker.listener_fd, null, null, 0);
            sqe.user_data = uring.packUserData(.accept, 0, worker.listener_fd);
        }

        fn armRecv(worker: *W, conn: *UringHttpConn) void {
            if (conn.filled >= conn.buf.len) {
                worker.beginClose(conn);
                return;
            }

            const sqe = worker.getSqe() orelse {
                // SQ full: park the re-arm on the process queue when it is on
                // (retried next pass), otherwise keep the close behavior.
                if (worker.parkPush(.recv, conn.fd, conn.gen)) return;

                worker.beginClose(conn);
                return;
            };

            sqe.prep_recv(conn.fd, conn.buf[conn.filled..], 0);
            sqe.user_data = uring.packUserData(.recv, conn.gen, conn.fd);
        }

        fn submitSend(worker: *W, conn: *UringHttpConn) void {
            const sqe = worker.getSqe() orelse {
                // SQ full: park the send when the process queue is on. The
                // staged bytes stay in conn.send_buf (inflight stays 0), the
                // retry re-enters here with the SQ drained.
                if (worker.parkPush(.send, conn.fd, conn.gen)) return;

                worker.finishClose(conn);
                return;
            };

            sqe.prep_send(conn.fd, conn.send_buf[0..conn.staged], lx.MSG.NOSIGNAL);
            sqe.user_data = uring.packUserData(.send, conn.gen, conn.fd);

            conn.inflight = conn.staged;
        }

        fn handleAccept(worker: *W, cqe: lx.io_uring_cqe) void {
            const rearm = (cqe.flags & lx.IORING_CQE_F_MORE) == 0;
            defer if (rearm) worker.armAccept();

            if (cqe.res < 0) return;

            const conn_fd: std.posix.fd_t = cqe.res;
            const idx: usize = @intCast(conn_fd);
            if (idx >= worker.slots.len) {
                _ = lx.close(conn_fd);
                return;
            }

            setNoDelay(conn_fd);
            common.setBusyPoll(conn_fd, worker.busy_poll_us);

            const conn = worker.acquireConn() orelse {
                _ = lx.close(conn_fd);
                return;
            };

            worker.gen_counter +%= 1;
            const buf = conn.buf;
            const send_buf = conn.send_buf;
            conn.* = .{
                .fd = conn_fd,
                .gen = worker.gen_counter,
                .buf = buf,
                .filled = 0,
                .send_buf = send_buf,
                .staged = 0,
                .inflight = 0,
                .closing = false,
            };
            worker.slots[idx] = conn;
            worker.live_count += 1;

            worker.armRecv(conn);
        }

        fn handleRecv(worker: *W, cqe: lx.io_uring_cqe, decoded: uring.Decoded) void {
            const conn = worker.lookup(decoded) orelse return;

            if (cqe.res <= 0) {
                worker.beginClose(conn);
                return;
            }

            conn.filled += @intCast(cqe.res);

            switch (worker.process(conn)) {
                .need_more => worker.armRecv(conn),
                .keep_alive => {
                    if (conn.staged > 0) worker.submitSend(conn) else worker.armRecv(conn);
                },
                .close => {
                    if (conn.staged > 0) {
                        worker.submitSend(conn);
                        conn.closing = true;
                    } else {
                        worker.beginClose(conn);
                    }
                },
            }
        }

        fn handleSend(worker: *W, cqe: lx.io_uring_cqe, decoded: uring.Decoded) void {
            const conn = worker.lookup(decoded) orelse return;

            if (cqe.res < 0) {
                worker.beginClose(conn);
                return;
            }

            const sent: usize = @intCast(cqe.res);
            if (sent < conn.staged) {
                std.mem.copyForwards(u8, conn.send_buf[0 .. conn.staged - sent], conn.send_buf[sent..conn.staged]);
                conn.staged -= sent;
                conn.inflight = 0;
                worker.submitSend(conn);

                return;
            }

            conn.staged = 0;
            conn.inflight = 0;

            if (conn.closing) {
                worker.finishClose(conn);
                return;
            }

            worker.armRecv(conn);
        }

        /// Find the header terminator (accumulating across recvs), then
        /// run one request with the response staged into a RespSink. The
        /// request is consumed (conn.filled reset to 0), matching the
        /// EPOLL one-request-per-buffer behavior.
        fn process(worker: *W, conn: *UringHttpConn) HttpProcOutcome {
            if (parser.findHeaderEnd(conn.buf[0..conn.filled], 0) == null) {
                if (conn.filled >= conn.buf.len) {
                    writeAllFD(conn.fd, "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n") catch {};
                    return .close;
                }

                return .need_more;
            }

            var sink = RespSink{ .fd = conn.fd, .buf = conn.send_buf };
            resp_mod.tl_resp_sink = &sink;
            _ = worker.arena.reset(.retain_capacity);

            const stream = std.Io.net.Stream{ .socket = .{ .handle = conn.fd, .address = undefined } };
            const outcome = processRequest(worker.server, stream, conn.fd, worker.io, conn.buf[0..conn.filled], worker.arena);
            resp_mod.tl_resp_sink = null;
            worker.requests_served += 1;

            conn.staged = sink.len;
            conn.filled = 0;
            if (sink.failed) return .close;

            return if (outcome == .keep_alive) .keep_alive else .close;
        }

        // ----------------------------------------------------- //
        // Dual-listener TLS side (config.tls_port): ciphertext recv and the staged-ciphertext
        // flush ride the ring (tls_recv / tls_send ops), the TLS connection logic is tls_mux's
        // (shared with the .EPOLL paths). Half-duplex per connection: while a flush send is in
        // flight no recv is armed, so the transport's staging buffer is never compacted while
        // the kernel reads it.

        fn lookupTls(worker: *W, decoded: uring.Decoded) ?*UringTlsConn {
            const table = if (worker.tls_conns) |*tls_table| tls_table else return null;

            const ring_conn = table.get(decoded.fd) orelse return null;
            if (ring_conn.gen != decoded.gen) return null;

            return ring_conn;
        }

        fn armTlsAccept(worker: *W) void {
            const sqe = worker.getSqe() orelse {
                // Same lost-re-arm guard as armAccept, for the TLS listener.
                worker.tls_accept_pending = true;
                return;
            };

            sqe.prep_multishot_accept(worker.tls_listener_fd, null, null, 0);
            sqe.user_data = uring.packUserData(.tls_accept, 0, worker.tls_listener_fd);
        }

        fn handleTlsAccept(worker: *W, cqe: lx.io_uring_cqe) void {
            const rearm = (cqe.flags & lx.IORING_CQE_F_MORE) == 0;
            defer if (rearm) worker.armTlsAccept();

            if (cqe.res < 0) return;

            const conn_fd: std.posix.fd_t = cqe.res;
            const table = if (worker.tls_conns) |*tls_table| tls_table else {
                _ = lx.close(conn_fd);
                return;
            };
            const idx: usize = @intCast(conn_fd);
            if (idx >= table.slots.len) {
                _ = lx.close(conn_fd);
                return;
            }

            setNoDelay(conn_fd);
            // The transport writes records directly (staging on EAGAIN), so the fd must be
            // non-blocking.
            setNonBlock(conn_fd);

            const ring_conn = allocator.create(UringTlsConn) catch {
                _ = lx.close(conn_fd);
                return;
            };
            const cipher_buf = allocator.alloc(u8, tls_conn.read_staging_size) catch {
                allocator.destroy(ring_conn);
                _ = lx.close(conn_fd);
                return;
            };

            worker.tls_gen_counter +%= 1;
            ring_conn.* = .{
                .conn = .{
                    .transport = tls_conn.Transport.init(conn_fd, worker.tls_ctx.?),
                    .server = worker.server,
                    .ctx = worker.tls_ctx.?,
                },
                .gen = worker.tls_gen_counter,
                .cipher_buf = cipher_buf,
            };
            table.put(conn_fd, ring_conn);

            worker.armTlsRecv(ring_conn);
        }

        /// Tear a TLS connection down: drop it from the table (frees the conn object) and hand
        /// the fd close to the ring.
        fn closeTls(worker: *W, ring_conn: *UringTlsConn) void {
            const fd = ring_conn.conn.transport.fd;
            if (worker.tls_conns) |*tls_table| tls_table.drop(fd);

            const sqe = worker.getSqe() orelse {
                _ = lx.close(fd);
                return;
            };
            sqe.prep_close(fd);
            sqe.user_data = uring.packUserData(.close, 0, fd);
        }

        fn armTlsRecv(worker: *W, ring_conn: *UringTlsConn) void {
            const sqe = worker.getSqe() orelse {
                worker.closeTls(ring_conn);
                return;
            };
            sqe.prep_recv(ring_conn.conn.transport.fd, ring_conn.cipher_buf, 0);
            sqe.user_data = uring.packUserData(.tls_recv, ring_conn.gen, ring_conn.conn.transport.fd);
        }

        /// Flush the transport's staged ciphertext (wbuf[woff..wlen]) with an on-ring send.
        fn submitTlsSend(worker: *W, ring_conn: *UringTlsConn) void {
            const transport = &ring_conn.conn.transport;

            const sqe = worker.getSqe() orelse {
                worker.closeTls(ring_conn);
                return;
            };
            sqe.prep_send(transport.fd, transport.wbuf[transport.woff..transport.wlen], lx.MSG.NOSIGNAL);
            sqe.user_data = uring.packUserData(.tls_send, ring_conn.gen, transport.fd);
        }

        fn handleTlsRecv(worker: *W, cqe: lx.io_uring_cqe, decoded: uring.Decoded) void {
            const ring_conn = worker.lookupTls(decoded) orelse return;

            if (cqe.res <= 0) {
                worker.closeTls(ring_conn);
                return;
            }

            const keep = TlsWorker.onCiphertext(&ring_conn.conn, ring_conn.cipher_buf[0..@intCast(cqe.res)], worker.io, worker.arena);
            const transport = &ring_conn.conn.transport;

            if (!keep) {
                worker.closeTls(ring_conn);
                return;
            }

            // Backpressure-staged ciphertext: flush it on the ring before the next recv.
            if (transport.wlen > transport.woff) {
                worker.submitTlsSend(ring_conn);
                return;
            }

            if (transport.wclose) {
                worker.closeTls(ring_conn);
                return;
            }

            worker.armTlsRecv(ring_conn);
        }

        fn handleTlsSend(worker: *W, cqe: lx.io_uring_cqe, decoded: uring.Decoded) void {
            const ring_conn = worker.lookupTls(decoded) orelse return;
            const transport = &ring_conn.conn.transport;

            if (cqe.res <= 0) {
                worker.closeTls(ring_conn);
                return;
            }

            transport.woff += @intCast(cqe.res);
            if (transport.woff < transport.wlen) {
                worker.submitTlsSend(ring_conn);
                return;
            }

            // Drained. Keep the buffer for reuse (freed at close), mirroring the EPOLL flush.
            transport.woff = 0;
            transport.wlen = 0;
            transport.want_out = false;

            if (transport.wclose) {
                worker.closeTls(ring_conn);
                return;
            }

            worker.armTlsRecv(ring_conn);
        }

        // ----------------------------------------------------- //

        fn run(worker: *W) void {
            worker.armAccept();
            if (worker.tls_listener_fd != -1) worker.armTlsAccept();

            var cqes: [URING_CQE_BATCH]lx.io_uring_cqe = undefined;
            while (true) {
                _ = worker.ring.submit_and_wait(1) catch |err| switch (err) {
                    error.SignalInterrupt => continue,
                    else => return,
                };

                // The submit above pushed the staged SQEs to the kernel, so the
                // SQ has room again: retry the pending accept re-arm and the
                // parked process-queue entries before reaping new completions.
                worker.drainParked();

                const count = worker.ring.copy_cqes(&cqes, 0) catch return;
                for (cqes[0..count]) |cqe| {
                    const decoded = uring.unpackUserData(cqe.user_data);
                    switch (decoded.op) {
                        .accept => worker.handleAccept(cqe),
                        .recv => worker.handleRecv(cqe, decoded),
                        .send => worker.handleSend(cqe, decoded),
                        .timeout => {},
                        .close => {},
                        .tls_accept => worker.handleTlsAccept(cqe),
                        .tls_recv => worker.handleTlsRecv(cqe, decoded),
                        .tls_send => worker.handleTlsSend(cqe, decoded),
                        .external => {},
                    }
                }
            }
        }
    };
}

/// One io_uring worker: a private SO_REUSEPORT listener and completion
/// loop. Each readable batch recvs into the connection buffer, runs one
/// request through processRequest with the response staged into a
/// RespSink, and submits one coalesced send. Half-duplex per connection,
/// one request per buffer (matches the EPOLL path, ADR-037 Phase 4 step 4).
fn uringWorker(server: anytype, io: std.Io, worker_id: usize, steering: ?reuseport.Steering, report: *listen_report.Report) void {
    const ServerPtr = @TypeOf(server);
    const cfg = server.config;

    pinToCpu(worker_id);

    // Bind under the order gate: REUSEPORT group index i = worker i,
    // so the cpu-mod-N steering lands on the worker pinned to that slot.
    var bind_turn = reuseport.BindTurn.begin(steering, worker_id);
    defer bind_turn.release();

    // Every exit between here and the ring loop has to reach the group, or the workers that did
    // bind wait on one that is already gone.
    var slot = report.slot(io, error.ZixHttpWorkerSetupFailed);
    defer slot.close();

    const addr = std.Io.net.IpAddress.resolve(io, cfg.ip, cfg.port) catch |err| {
        slot.fail(err);

        return;
    };
    var net_server = addr.listen(io, .{
        .mode = .stream,
        .kernel_backlog = @intCast(cfg.kernel_backlog),
        .reuse_address = true,
    }) catch |err| {
        slot.fail(err);

        return;
    };
    defer net_server.deinit(io);
    const listener_fd = net_server.socket.handle;

    if (steering) |steer| _ = reuseport.attachCpuSteering(listener_fd, steer.group_size);

    // Dual-listener TLS side: a second listener on tls_port whose connections terminate TLS in
    // this same ring loop (no separate epoll fleet).
    const tls_active = cfg.tls != null and cfg.tls_port != 0;
    var tls_srv: std.Io.net.Server = undefined;
    var tls_listener_fd: std.posix.fd_t = -1;
    if (tls_active) {
        const tls_addr = std.Io.net.IpAddress.resolve(io, cfg.ip, cfg.tls_port) catch |err| {
            slot.fail(err);

            return;
        };
        tls_srv = tls_addr.listen(io, .{
            .mode = .stream,
            .kernel_backlog = @intCast(cfg.kernel_backlog),
            .reuse_address = true,
        }) catch |err| {
            slot.fail(err);

            return;
        };
        tls_listener_fd = tls_srv.socket.handle;
        if (steering) |steer| _ = reuseport.attachCpuSteering(tls_listener_fd, steer.group_size);
    }
    defer if (tls_active) tls_srv.deinit(io);

    // Both groups joined: release the bind turn to the next worker.
    bind_turn.release();

    // Serve only once every worker is up, so a group where one bind failed serves on none of them
    // and the caller gets one honest failure.
    slot.ok();
    if (report.awaitGroup(io) != null) return;

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    _ = arena.allocator().alloc(u8, cfg.max_allocator_size) catch {};
    _ = arena.reset(.retain_capacity);

    // Per-worker response cache: lock-free by ownership, never shared.
    var response_cache: rcache.ResponseCache = undefined;
    var cache_on = false;
    if (cfg.response_cache) {
        if (rcache.ResponseCache.init(std.heap.smp_allocator, .{
            .max_entries = effectiveCacheEntries(cfg),
            .max_value_bytes = cfg.cache_max_value_bytes,
        })) |built| {
            response_cache = built;
            cache_on = true;
            setCache(&response_cache, cfg.cache_ttl_ms);
        } else |_| {
            cache_on = false;
        }
    }
    defer if (cache_on) {
        setCache(null, 0);
        response_cache.deinit();
    };

    // Response compression, stateless per worker. Active under .EPOLL and .URING,
    // like the cache.
    if (cfg.compress) setCompression(cfg.compress, cfg.compression_min_size, cfg.compression_max_out);
    defer setCompression(false, 0, 0);

    const slots = slab.mapZeroedSlots(?*UringHttpConn, MAX_FD) catch return;

    // Process queue (config.process_queue_len): the FIFO ring of postponed
    // re-arm references, preallocated once. Empty when 0 (off).
    const park_entries: []ParkEntry = if (cfg.process_queue_len > 0)
        std.heap.smp_allocator.alloc(ParkEntry, cfg.process_queue_len) catch return
    else
        &.{};

    const Worker = UringWorker(ServerPtr);

    var worker = Worker{
        .ring = undefined,
        .slots = slots,
        .park_entries = park_entries,
        .listener_fd = listener_fd,
        .gen_counter = 0,
        .server = server,
        .io = io,
        .arena = &arena,
        .recv_buf_size = cfg.max_recv_buf,
        .send_buf_size = cfg.uring_send_buf_size,
        .busy_poll_us = cfg.busy_poll_us,
        .idle_floor = cfg.uring_idle_pool_floor,
        .idle_ceiling = cfg.uring_idle_pool_ceiling,
        .tls_listener_fd = tls_listener_fd,
        .tls_ctx = if (tls_active) cfg.tls else null,
    };
    worker.ring = initUringRing() catch return;
    if (tls_active) worker.tls_conns = Worker.TlsConnTable.init() catch return;
    defer worker.deinit();

    // Seed the warm idle pool before the accept loop so the first burst reuses
    // resident buffers instead of faulting them in under load.
    worker.prewarmPool();

    worker.run();

    logSystem(cfg, .INFO, "uring worker {d}: {d} requests served", .{ worker_id, worker.requests_served });
}

// --------------------------------------------------------- //
// URING model

/// URING dispatch (Linux-only): shared-nothing io_uring ring per worker.
pub fn runUring(server: anytype, io: std.Io) !void {
    const cfg = server.config;

    // Runtime probe: io_uring can be unavailable on this host (seccomp/sandbox,
    // RLIMIT_MEMLOCK, or an old kernel). Without this, every worker would fail
    // setup, return, and the server would vanish right after binding (a confusing
    // ServerStartTimeout downstream). Fall back to the EPOLL shared-nothing loop.
    var probe = initUringRing() catch |err| {
        logSystem(cfg, .WARN, "io_uring unavailable ({s}): not suited to this environment (commonly RLIMIT_MEMLOCK, the ulimit -l cap, too low for the ring size). Falling back to EPOLL.", .{@errorName(err)});

        return epoll_model.runEpoll(server, io);
    };
    probe.deinit();

    const worker_count = if (cfg.workers == 0) getAvailableCpuCount() else cfg.workers;

    const threads = try std.heap.smp_allocator.alloc(std.Thread, worker_count);
    defer std.heap.smp_allocator.free(threads);

    // std.compress.flate.Compress is about 230 KB and is built on the handler's stack
    // frame, so a compressing handler (sendNegotiated) needs more than the default
    // 512 KB worker stack. Thread stacks are demand-paged, so the larger limit costs
    // almost no RSS, and the bump applies only when compression is enabled.
    const worker_stack: usize = if (cfg.compress) @max(cfg.worker_stack_size_bytes, cfg.worker_stack_compress_bytes) else cfg.worker_stack_size_bytes;

    // CBPF steering: one shared bind-order gate, alive until join().
    var bind_gate = reuseport.BindOrderGate{};
    const steering: ?reuseport.Steering = if (cfg.reuseport_cbpf) .{ .gate = &bind_gate, .group_size = worker_count } else null;

    // What every worker says about its own listeners, so a bind that fails inside a worker thread
    // reaches this frame instead of ending that thread and nothing else.
    var report = listen_report.Report.init(worker_count);

    for (threads, 0..) |*thread, idx| {
        thread.* = std.Thread.spawn(.{ .stack_size = worker_stack }, uringWorker, .{ server, io, idx, steering, &report }) catch |err| {
            logSystem(cfg, .ERROR, "could not spawn worker {d} of {d} ({s})", .{ idx, worker_count, @errorName(err) });
            report.abandon(io, worker_count - idx, err);

            for (threads[0..idx]) |spawned| spawned.join();

            return error.ZixHttpListenFailed;
        };
    }

    if (report.awaitGroup(io)) |err| {
        logSystem(cfg, .ERROR, "not listening on {s}:{d}: {d} of {d} workers could not bind ({s})", .{ cfg.ip, cfg.port, report.failures(), worker_count, @errorName(err) });

        for (threads) |thread| thread.join();

        return error.ZixHttpListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is nothing
    // to announce: the old line claimed a listener that may never have come up.
    logSystem(cfg, .INFO, "listening on {s}:{d} (io_uring, {d} workers, shared-nothing)", .{
        cfg.ip, cfg.port, worker_count,
    });
    if (cfg.tls != null and cfg.tls_port != 0)
        logSystem(cfg, .INFO, "dual listener: https/1.1 TLS on {s}:{d} (same workers, on-ring)", .{ cfg.ip, cfg.tls_port });

    for (threads) |thread| thread.join();
}

// --------------------------------------------------------- //

test "zix http: URING prewarmPool seeds the warm pool to idle_floor with sized buffers" {
    const gpa = std.heap.smp_allocator;

    const Worker = UringWorker(*u8);
    const recv_size: usize = 6 * 1024;
    const send_size: usize = 8 * 1024;
    var worker = Worker{
        .ring = undefined,
        .slots = &[_]?*UringHttpConn{},
        .listener_fd = -1,
        .gen_counter = 0,
        .server = undefined,
        .io = undefined,
        .arena = undefined,
        .recv_buf_size = recv_size,
        .send_buf_size = send_size,
        .idle_floor = 4,
    };

    worker.prewarmPool();

    try std.testing.expectEqual(@as(usize, 4), worker.warm_count);
    try std.testing.expect(worker.warm_head != null);
    try std.testing.expect(worker.warm_tail != null);

    // Every seeded connection carries buffers at the configured sizes, resident
    // and reusable: an accept pops them from the warm pool with no allocator call.
    var idx: usize = 0;
    while (idx < 4) : (idx += 1) {
        const conn = worker.acquireConn().?;
        try std.testing.expectEqual(recv_size, conn.buf.len);
        try std.testing.expectEqual(send_size, conn.send_buf.len);

        gpa.free(conn.buf);
        gpa.free(conn.send_buf);
        gpa.destroy(conn);
    }

    try std.testing.expectEqual(@as(usize, 0), worker.warm_count);
    try std.testing.expectEqual(@as(?*UringHttpConn, null), worker.warm_head);
    try std.testing.expectEqual(@as(?*UringHttpConn, null), worker.warm_tail);
}

test "zix http: URING prewarmPool with a zero floor seeds nothing" {
    const Worker = UringWorker(*u8);
    var worker = Worker{
        .ring = undefined,
        .slots = &[_]?*UringHttpConn{},
        .listener_fd = -1,
        .gen_counter = 0,
        .server = undefined,
        .io = undefined,
        .arena = undefined,
        .recv_buf_size = 4096,
        .send_buf_size = 4096,
        .idle_floor = 0,
    };

    worker.prewarmPool();

    try std.testing.expectEqual(@as(usize, 0), worker.warm_count);
    try std.testing.expectEqual(@as(?*UringHttpConn, null), worker.warm_head);
    try std.testing.expectEqual(@as(?*UringHttpConn, null), worker.warm_tail);
}

test "zix http: URING process queue parks FIFO, rejects the newest at full, and wraps" {
    const Worker = UringWorker(*u8);
    var entries: [2]ParkEntry = undefined;
    var worker = Worker{
        .ring = undefined,
        .slots = &[_]?*UringHttpConn{},
        .listener_fd = -1,
        .gen_counter = 0,
        .server = undefined,
        .io = undefined,
        .arena = undefined,
        .recv_buf_size = 64,
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
    try std.testing.expect(worker.parkPush(.recv, 12, 3));

    const second = worker.parkPop().?;
    try std.testing.expectEqual(@as(std.posix.fd_t, 11), second.fd);
    try std.testing.expectEqual(ParkKind.send, second.kind);

    const third = worker.parkPop().?;
    try std.testing.expectEqual(@as(std.posix.fd_t, 12), third.fd);
    try std.testing.expectEqual(@as(?ParkEntry, null), worker.parkPop());
}

test "zix http: URING process queue off (len 0) never parks" {
    const Worker = UringWorker(*u8);
    var worker = Worker{
        .ring = undefined,
        .slots = &[_]?*UringHttpConn{},
        .listener_fd = -1,
        .gen_counter = 0,
        .server = undefined,
        .io = undefined,
        .arena = undefined,
        .recv_buf_size = 64,
    };

    try std.testing.expect(!worker.parkPush(.recv, 10, 1));
    try std.testing.expectEqual(@as(usize, 0), worker.park_len);
    try std.testing.expectEqual(@as(?ParkEntry, null), worker.parkPop());
}

test "zix http: URING drainParked drops a stale gen entry without touching the connection" {
    const gpa = std.testing.allocator;

    const Worker = UringWorker(*u8);
    var slots: [16]?*UringHttpConn = @splat(null);
    var entries: [4]ParkEntry = undefined;
    var worker = Worker{
        .ring = undefined,
        .slots = &slots,
        .listener_fd = -1,
        .gen_counter = 0,
        .server = undefined,
        .io = undefined,
        .arena = undefined,
        .recv_buf_size = 64,
        .park_entries = &entries,
    };

    const conn = try gpa.create(UringHttpConn);
    conn.* = .{ .fd = 5, .gen = 2, .buf = try gpa.alloc(u8, 64), .filled = 0, .send_buf = try gpa.alloc(u8, 64), .staged = 0, .inflight = 0, .closing = false };
    defer {
        gpa.free(conn.buf);
        gpa.free(conn.send_buf);
        gpa.destroy(conn);
    }
    slots[5] = conn;

    // Parked under gen 1, then the fd closed and was reused under gen 2: the
    // entry is stale and must be a no-op, never an arm on the new connection.
    try std.testing.expect(worker.parkPush(.recv, 5, 1));

    worker.drainParked();

    try std.testing.expectEqual(@as(usize, 0), worker.park_len);
    try std.testing.expect(!conn.closing);
    try std.testing.expectEqual(@as(usize, 0), conn.filled);
}

test "zix http: URING pending accept re-arm is retried by drainParked" {
    if (comptime @import("builtin").target.os.tag != .linux) {
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

    const Worker = UringWorker(*u8);
    var worker = Worker{
        .ring = initUringRing() catch {
            std.log.info("io_uring is unavailable on this kernel, test skipped", .{});
            return;
        },
        .slots = &[_]?*UringHttpConn{},
        .listener_fd = fds[0],
        .gen_counter = 0,
        .server = undefined,
        .io = undefined,
        .arena = undefined,
        .recv_buf_size = 64,
    };
    defer worker.ring.deinit();

    // Simulate an accept re-arm lost to a full SQ: the flag is set and no SQE
    // exists yet. drainParked must stage the accept and clear the flag.
    worker.accept_pending = true;

    worker.drainParked();

    try std.testing.expect(!worker.accept_pending);
    try std.testing.expectEqual(@as(u32, 1), worker.ring.sq_ready());
}

test "zix http: URING drainParked re-arms a parked recv on the ring" {
    if (comptime @import("builtin").target.os.tag != .linux) {
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

    const Worker = UringWorker(*u8);
    var entries: [4]ParkEntry = undefined;
    var worker = Worker{
        .ring = initUringRing() catch {
            std.log.info("io_uring is unavailable on this kernel, test skipped", .{});
            return;
        },
        .slots = try gpa.alloc(?*UringHttpConn, @as(usize, @intCast(fds[1])) + 1),
        .listener_fd = -1,
        .gen_counter = 0,
        .server = undefined,
        .io = undefined,
        .arena = undefined,
        .recv_buf_size = 64,
        .park_entries = &entries,
    };
    @memset(worker.slots, null);
    defer {
        worker.ring.deinit();
        gpa.free(worker.slots);
    }

    const conn = try gpa.create(UringHttpConn);
    conn.* = .{ .fd = fds[1], .gen = 1, .buf = try gpa.alloc(u8, 64), .filled = 0, .send_buf = try gpa.alloc(u8, 64), .staged = 0, .inflight = 0, .closing = false };
    defer {
        gpa.free(conn.buf);
        gpa.free(conn.send_buf);
        gpa.destroy(conn);
    }
    worker.slots[@intCast(fds[1])] = conn;

    // A recv parked while the SQ was full is re-armed on the next drain pass:
    // the entry leaves the ring and one recv SQE is staged for the connection.
    try std.testing.expect(worker.parkPush(.recv, fds[1], 1));

    worker.drainParked();

    try std.testing.expectEqual(@as(usize, 0), worker.park_len);
    try std.testing.expectEqual(@as(u32, 1), worker.ring.sq_ready());
    try std.testing.expect(!conn.closing);
}
