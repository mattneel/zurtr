//! zix HTTP/3 URING dispatch: one SO_REUSEPORT worker per core, the kernel load-balancing connections by
//! 4-tuple (multicore). Each worker drives a real io_uring completion loop: a pool of recvmsg
//! submissions stays in flight and the kernel hands back datagrams (with peer address) as CQEs. A worker
//! whose host lacks io_uring (old kernel, seccomp, RLIMIT_MEMLOCK) falls back to the epoll loop, so
//! selecting .URING never strands a core. The recv / demux / respond code it drives lives in the common
//! module (common.zig), which the epoll worker (epoll.zig) imports too.

const std = @import("std");
const linux = std.os.linux;
const IoUring = std.os.linux.IoUring;

const Config = @import("../config.zig");
const Http3ServerConfig = Config.Http3ServerConfig;
const core = @import("../core.zig");
const datagram = @import("../../datagram.zig");
const recovery = @import("../recovery.zig");
const reassembly = @import("../reassembly.zig");
const common = @import("common.zig");
const wt_pool = @import("../webtransport/pool.zig");
const reuseport = @import("../../../multiplexers/reuseport.zig");
const listen_report = @import("../../../multiplexers/listen_report.zig");
const epoll = @import("epoll.zig");

/// io_uring submission-queue depth for an HTTP/3 .URING worker. The ring carries only recvmsg SQEs
/// (replies go out through the sendmmsg SendBatch), so this bounds the outstanding receives. A power of
/// two, at least uring_recv_slots.
const uring_entries: u16 = 256;

/// In-flight recvmsg submissions per .URING worker: how many datagrams the kernel can fill at once. More
/// slots means more receive parallelism and fewer submit round-trips, at slots * max_recv_buf bytes of
/// receive buffer per worker. Kept at or below uring_entries.
const uring_recv_slots: usize = 192;

/// Completions reaped per copy_cqes call on a .URING worker.
const uring_cqe_batch: usize = 256;

/// One dual-stack sockaddr_in6 length, for a recvmsg msghdr name field.
const sockaddr_in6_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in6);

/// Multishot recv. A provided buffer ring lets one multishot recvmsg SQE deliver a CQE per datagram
/// without re-arming per datagram (the one-shot re-arm churn): the kernel selects a buffer from the
/// ring for each completion and writes an io_uring_recvmsg_out header, the peer address, then the payload
/// into it. When the kernel ends the multishot (buffer exhaustion or error, no IORING_CQE_F_MORE), the
/// worker re-arms. Buffer-ring entries must be a power of two.
const uring_ring_bufs: u16 = 256;

/// The provided-buffer group id for the worker ring (one group per worker).
const uring_buf_group: u16 = 1;

/// user_data tag on the multishot recvmsg SQE (completions are identified by IORING_CQE_F_BUFFER, so the
/// tag is only for symmetry with the one-shot slot tags).
const uring_mshot_tag: u64 = std.math.maxInt(u64);

/// user_data tag on the periodic maintenance timeout SQE. Distinct from the recv-slot indices
/// (0..uring_recv_slots), the two send tags, and the multishot tag, so the completion loop can tell a
/// fired maintenance timer from an I/O completion and never mistakes it for a recv slot index.
const uring_timeout_tag: u64 = (1 << 32) + 2;

/// Bytes the kernel prefixes to each selected buffer: the io_uring_recvmsg_out header.
const recvmsg_out_hdr: usize = @sizeOf(linux.io_uring_recvmsg_out);

/// Bytes reserved for the peer address in each selected buffer (a dual-stack sockaddr_in6).
const mshot_name_reserve: usize = @sizeOf(std.posix.sockaddr.in6);

/// Double-buffered io_uring send state for one worker. While one buffer's previously-submitted sends
/// are still in flight on the ring (their SQEs not yet completed), the worker queues the next wake's
/// replies into the OTHER buffer, so a reply never waits behind a blocking send syscall the way a
/// single shared SendBatch flushed with sendmmsg would. Swapping only happens once the buffer coming
/// back around has zero outstanding sends. Until then the worker keeps queuing into the current
/// buffer (SendBatch.submitUring only resubmits the newly queued tail, so nothing is ever sent
/// twice). This is the send-side counterpart to the recv-side provided buffer ring above: recv stays
/// full via multishot + buffers, send stays full via two rotating batches instead of a syscall that
/// blocks the loop between wakes.
const UringTx = struct {
    bufs: [2]datagram.SendBatch,
    inflight: [2]usize = .{ 0, 0 },
    cur: usize = 0,

    /// The user_data tag each buffer's SQEs carry. Both sit well above any one-shot recv slot index
    /// (0..uring_recv_slots) and below the multishot tag (maxInt(u64)), so a completion's user_data
    /// alone says which of the two buffers (if any) it belongs to, with no risk of colliding with a
    /// recv completion's tag.
    const tags = [2]u64{ 1 << 32, (1 << 32) + 1 };

    fn init(allocator: std.mem.Allocator, count: usize, buf_bytes: usize) !UringTx {
        var first = try datagram.SendBatch.init(allocator, count, buf_bytes);
        errdefer first.deinit();
        const second = try datagram.SendBatch.init(allocator, count, buf_bytes);

        return .{ .bufs = .{ first, second } };
    }

    fn deinit(self: *UringTx) void {
        self.bufs[0].deinit();
        self.bufs[1].deinit();
    }

    /// Enable (or leave off) GSO coalescing on both buffers, mirroring the plain worker's tx.gso.
    fn setGso(self: *UringTx, enabled: bool) void {
        self.bufs[0].gso = enabled;
        self.bufs[1].gso = enabled;
    }

    /// The batch the worker queues this wake's replies into.
    fn active(self: *UringTx) *datagram.SendBatch {
        return &self.bufs[self.cur];
    }

    /// A completion's user_data matched one of the two send tags: apply it and report true so the
    /// caller's CQE loop skips the recv handling for this entry. False for any other tag (a recv
    /// completion, which the caller still has to process as one).
    fn reap(self: *UringTx, user_data: u64) bool {
        for (tags, 0..) |tag, i| {
            if (user_data == tag) {
                self.inflight[i] -|= 1;
                return true;
            }
        }

        return false;
    }

    /// True when the active buffer still holds replies not yet on the ring (a submit capped by a
    /// full SQ). The buffer must then stay active so the tail is resubmitted next wake: rotating
    /// it out would reset() it on swap-back and silently discard the tail.
    fn activeTailPending(self: *const UringTx) bool {
        return self.bufs[self.cur].ring_sent < self.bufs[self.cur].count;
    }

    /// Submit the active buffer's newly queued replies as sendmsg SQEs (not waited on here), then
    /// swap to the other buffer for the next wake if it currently has no sends in flight. If it
    /// does, keep queuing into the current buffer instead of swapping into one still being drained.
    /// A submit capped by a full SQ also defers the swap, so the unsent tail is retried, not reset.
    fn submitAndSwap(self: *UringTx, ring: *IoUring, fd: std.posix.socket_t) usize {
        const submitted = self.bufs[self.cur].submitUring(ring, fd, tags[self.cur]);
        self.inflight[self.cur] += submitted;

        if (self.activeTailPending()) return submitted;

        const other = 1 - self.cur;
        if (self.inflight[other] == 0) {
            self.bufs[other].reset();
            self.cur = other;
        }

        return submitted;
    }
};

/// Initialize one io_uring for an HTTP/3 worker. Each per-core worker is shared-nothing: one thread owns
/// the ring, submits, and reaps, so the kernel's fast paths for that shape apply:
/// - SINGLE_ISSUER: only this thread ever submits, so the kernel skips submitter-side locking.
/// - DEFER_TASKRUN: completion task work runs at submit_and_wait (the worker's own reap point) instead
///   of on every IRQ, cutting per-datagram overhead and cross-core wakeups under load.
/// These pair (DEFER_TASKRUN requires SINGLE_ISSUER) and need a recent kernel, so the init steps down to
/// COOP_TASKRUN, then to plain flags, so an older kernel still gets a ring. A kernel without io_uring (or
/// an RLIMIT_MEMLOCK cap too low) errors out, and the caller falls back to the epoll worker. No SQPOLL:
/// it needs privilege and a dedicated kernel poll thread per ring, the wrong trade for one worker per core.
fn initUringRing() !IoUring {
    const single_defer = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_DEFER_TASKRUN;
    if (IoUring.init(uring_entries, single_defer)) |ring| return ring else |_| {}

    if (IoUring.init(uring_entries, linux.IORING_SETUP_COOP_TASKRUN)) |ring| return ring else |_| {}

    return IoUring.init(uring_entries, 0);
}

/// Get a submission-queue entry, submitting the backlog and retrying once when the SQ is momentarily
/// full. Null when the ring cannot accept a submission.
fn uringGetSqe(ring: *IoUring) ?*linux.io_uring_sqe {
    return ring.get_sqe() catch {
        _ = ring.submit() catch return null;

        return ring.get_sqe() catch null;
    };
}

/// Arm (or re-arm) a recvmsg on `slot`: reset the msghdr name length (recvmsg shrinks it to the actual
/// peer), queue a recvmsg SQE on the worker socket, and tag it with the slot index so the completion
/// recovers which buffer and peer address it filled.
///
/// Return:
/// - true when the SQE was queued
/// - false when the SQ is full even after a submit (the caller must retry later, or the slot's
///   receive is lost for good)
fn armUringRecv(ring: *IoUring, msg: *linux.msghdr, slot: usize, fd: std.posix.socket_t) bool {
    msg.namelen = sockaddr_in6_len;

    const sqe = uringGetSqe(ring) orelse return false;
    sqe.prep_recvmsg(fd, msg, 0);
    sqe.user_data = @intCast(slot);

    return true;
}

/// Arm (or re-arm) the multishot recvmsg on the provided buffer group: one SQE yields a CQE per datagram
/// (each carrying a selected buffer id) until the kernel ends the multishot, when the caller re-arms. The
/// msghdr only reserves the name / control space. The kernel writes the recvmsg_out header, the peer
/// address, then the payload into each selected buffer.
///
/// Return:
/// - true when the SQE was queued
/// - false when the SQ is full even after a submit. The caller must retry: with no multishot in
///   flight no completion re-arms it, so giving up here leaves the worker deaf for good.
fn armMultishotRecv(ring: *IoUring, msg: *linux.msghdr, fd: std.posix.socket_t) bool {
    const sqe = uringGetSqe(ring) orelse return false;
    sqe.prep_recvmsg_multishot(fd, msg, 0);
    sqe.flags |= linux.IOSQE_BUFFER_SELECT;
    sqe.buf_index = uring_buf_group;
    sqe.user_data = uring_mshot_tag;

    return true;
}

/// Parse a completed multishot recvmsg buffer: the io_uring_recvmsg_out header, then the reserved peer
/// address, then the payload. The header and peer are copied out into aligned locals so the parse does
/// not depend on the buffer's alignment. Returns null when the buffer is too short or the peer address
/// was truncated (a datagram the caller drops). `buf` is already sliced to the CQE byte count.
///
/// Param:
/// buf - []const u8 (the selected buffer, sliced to the completion's byte count)
/// name_reserve - usize (bytes reserved for the peer address, the msghdr namelen)
/// controllen - usize (bytes reserved for control data, the msghdr controllen)
/// max_payload - usize (cap on the returned payload length, config.max_recv_buf)
///
/// Return:
/// - ?struct { peer, payload }
fn parseMultishotBuf(buf: []const u8, name_reserve: usize, controllen: usize, max_payload: usize) ?struct { peer: std.posix.sockaddr.in6, payload: []const u8 } {
    if (buf.len < recvmsg_out_hdr) return null;

    var out: linux.io_uring_recvmsg_out = undefined;
    @memcpy(std.mem.asBytes(&out), buf[0..recvmsg_out_hdr]);
    if (out.namelen < mshot_name_reserve) return null; // need the full dual-stack peer address

    const payload_off = recvmsg_out_hdr + name_reserve + controllen;
    const plen = @min(@as(usize, out.payloadlen), max_payload);
    if (payload_off + plen > buf.len) return null;

    var peer: std.posix.sockaddr.in6 = undefined;
    @memcpy(std.mem.asBytes(&peer), buf[recvmsg_out_hdr..][0..mshot_name_reserve]);

    return .{ .peer = peer, .payload = buf[payload_off..][0..plen] };
}

/// One HTTP/3 io_uring worker: bind a per-core SO_REUSEPORT UDP socket, own a CID table + SendBatch, and
/// drive an io_uring completion loop. Prefers multishot recvmsg on a provided buffer ring, falling
/// back to the one-shot recvmsg slot pool (still io_uring) when the buffer ring cannot be set up. If
/// io_uring is unavailable entirely (old kernel, seccomp, RLIMIT_MEMLOCK), the worker folds to the epoll
/// loop so .URING never strands a core (a capability fold, not model-mixing). Shared-nothing: its own
/// ring, socket, CID table, and batches, no lock on the hot path.
fn workerLoopUring(comptime handler: core.HandlerFn, config: Http3ServerConfig, worker_id: usize, steering: ?reuseport.Steering, report: *listen_report.Report) void {
    common.pinToCpu(worker_id);

    var ring = initUringRing() catch |err| {
        common.logSystem(config, .WARN, "io_uring unavailable ({s}): worker {d} folds to epoll", .{ @errorName(err), worker_id });

        return epoll.workerLoopEpoll(handler, config, worker_id, steering, report);
    };
    defer ring.deinit();

    // Skew report at worker exit: requests this worker served (common.tl_requests_served).
    // Placed after the ring probe so the epoll fold reports through its own line only.
    defer common.logSystem(config, .INFO, "uring worker {d}: {d} requests served", .{ worker_id, common.tl_requests_served });

    // Bind under the order gate: REUSEPORT group index i = worker i,
    // so the cpu-mod-N steering lands on the worker pinned to that slot.
    var bind_turn = reuseport.BindTurn.begin(steering, worker_id);
    defer bind_turn.release();

    // Every exit between here and the receive loop has to reach the group, or the workers that
    // did bind wait on one that is already gone.
    var slot = report.slot(config.io, error.ZixHttp3WorkerSetupFailed);
    defer slot.close();

    const fd = datagram.open(config.ip, config.port, true) catch |err| {
        slot.fail(err);

        return;
    };
    defer datagram.close(fd);

    if (steering) |steer| _ = reuseport.attachCpuSteering(fd, steer.group_size);
    bind_turn.release();

    // Serve only once every worker is up, so a group where one bind failed serves on none of them.
    slot.ok();
    if (report.awaitGroup(config.io) != null) return;

    common.setBusyPoll(fd, config.busy_poll_us);
    datagram.setSocketBuffers(fd, config.socket_rcvbuf, config.socket_sndbuf);

    const table = config.allocator.create(common.ConnTable) catch return;
    defer config.allocator.destroy(table);
    table.* = .{};

    var pool = common.openReassemblyPool(config) catch return;
    defer pool.deinit(config.allocator);

    var wt_pool_handle = common.openWebtransportPool(config);
    defer if (wt_pool_handle) |*opened| opened.deinit(config.allocator);

    var tx = UringTx.init(config.allocator, config.send_batch, common.sendBufBytes(config)) catch return;
    defer tx.deinit();

    tx.setGso(config.gso_enabled and datagram.probeGso(fd));

    runRecvLoop(handler, &ring, fd, table, &pool, if (wt_pool_handle) |*opened| opened else null, &tx, config, worker_id);
}

/// Drive receives on the ring: set up the multishot provided buffer ring and run the multishot loop, or
/// fall back to the one-shot recvmsg slot pool when the buffer ring cannot be registered (older kernel).
fn runRecvLoop(comptime handler: core.HandlerFn, ring: *IoUring, fd: std.posix.socket_t, table: *common.ConnTable, pool: *reassembly.Pool, wt_pool_ptr: ?*wt_pool.Pool, tx: *UringTx, config: Http3ServerConfig, worker_id: usize) void {
    const buf_size = std.mem.alignForward(usize, recvmsg_out_hdr + mshot_name_reserve + config.max_recv_buf, 16);

    const br = IoUring.setup_buf_ring(ring.fd, uring_ring_bufs, uring_buf_group, .{ .inc = false }) catch
        return runOneShotLoop(handler, ring, fd, table, pool, wt_pool_ptr, tx, config, worker_id);
    defer IoUring.free_buf_ring(ring.fd, br, uring_ring_bufs, uring_buf_group);
    IoUring.buf_ring_init(br);

    const backing = config.allocator.alloc(u8, uring_ring_bufs * buf_size) catch
        return runOneShotLoop(handler, ring, fd, table, pool, wt_pool_ptr, tx, config, worker_id);
    defer config.allocator.free(backing);

    const mask = IoUring.buf_ring_mask(uring_ring_bufs);
    for (0..uring_ring_bufs) |i| {
        IoUring.buf_ring_add(br, backing[i * buf_size ..][0..buf_size], @intCast(i), mask, @intCast(i));
    }
    IoUring.buf_ring_advance(br, uring_ring_bufs);

    // The msghdr only reserves name / control space per selected buffer, iov is unused (the kernel picks
    // the buffer). It must outlive the multishot, so it lives here for the worker's life.
    var msg = std.mem.zeroes(linux.msghdr);
    msg.namelen = @intCast(mshot_name_reserve);

    // Sticky: true while the multishot needs (re-)arming and the arm has not landed. A full SQ fails
    // the arm, and with no multishot in flight no CQE would ever request the re-arm again, so the
    // flag carries it across passes and the loop retries once a submit frees SQ space.
    var recv_unarmed = !armMultishotRecv(ring, &msg, fd);

    common.logSystem(config, .INFO, "io_uring worker {d} up (multishot recvmsg, {d} buffers)", .{ worker_id, uring_ring_bufs });

    var stats = common.WorkerStats{ .worker_id = worker_id };
    common.registerWorkerStats(&stats);
    var cqes: [uring_cqe_batch]linux.io_uring_cqe = undefined;
    var last_sweep_us: u64 = recovery.nowUs();
    var timeout_armed = false;
    const maintenance_ts = linux.kernel_timespec{ .sec = 0, .nsec = @intCast(common.maintenance_interval_us * 1000) };

    while (true) {
        // Retry a multishot arm lost to a full SQ, so the queued SQE rides this pass's submit.
        if (recv_unarmed) recv_unarmed = !armMultishotRecv(ring, &msg, fd);

        // Arm one maintenance timeout while the worker owns connections, so submit_and_wait returns after
        // the interval even with no I/O and the sweep (loss recovery, idle eviction) still runs during a
        // lull. Only one is ever in flight, re-armed after it fires (its CQE below).
        if (!timeout_armed and table.count > 0) {
            if (ring.timeout(uring_timeout_tag, &maintenance_ts, 0, 0)) |_| {
                timeout_armed = true;
            } else |_| {}
        }

        if (comptime common.diag_enabled) stats.wait_enter_us = recovery.nowUs();
        const wait_result = ring.submit_and_wait(1);
        if (comptime common.diag_enabled) {
            stats.block_us += recovery.nowUs() -| stats.wait_enter_us;
            stats.wait_enter_us = 0;
        }
        _ = wait_result catch continue;
        stats.wakes += 1;

        const reaped = ring.copy_cqes(&cqes, 0) catch continue;
        var rearm = false;
        for (cqes[0..reaped]) |cqe| {
            if (cqe.user_data == uring_timeout_tag) {
                timeout_armed = false; // the maintenance timer fired (or was cancelled): re-arm next loop
                continue;
            }
            if (tx.reap(cqe.user_data)) continue; // a send SQE landed, bookkeeping only

            if (cqe.flags & linux.IORING_CQE_F_BUFFER != 0) {
                const bid = cqe.buffer_id() catch {
                    if (cqe.flags & linux.IORING_CQE_F_MORE == 0) rearm = true;
                    continue;
                };
                const buf = backing[@as(usize, bid) * buf_size ..][0..buf_size];

                // Serve before recycling: the payload slice points into this buffer, and serveDatagram
                // reads it (and copies the peer into the SendBatch) before returning.
                if (cqe.res > 0) {
                    const used = @min(@as(usize, @intCast(cqe.res)), buf_size);
                    if (parseMultishotBuf(buf[0..used], mshot_name_reserve, msg.controllen, config.max_recv_buf)) |parsed| {
                        stats.datagrams += 1;
                        common.serveDatagram(handler, table, pool, wt_pool_ptr, .{ .data = parsed.payload, .from = parsed.peer }, tx.active(), fd, config, &stats);
                    }
                }

                IoUring.buf_ring_add(br, buf, bid, mask, 0);
                IoUring.buf_ring_advance(br, 1);
            }

            // The multishot ended (buffer exhaustion or error): re-arm so receives stay in flight.
            if (cqe.flags & linux.IORING_CQE_F_MORE == 0) rearm = true;
        }
        if (rearm) recv_unarmed = !armMultishotRecv(ring, &msg, fd);

        // Time-driven maintenance before the send submit, so a retransmit it queues rides this wake's
        // sends. At most once per interval however often a completion wakes the worker.
        const now_us = recovery.nowUs();
        if (now_us -| last_sweep_us >= common.maintenance_interval_us) {
            common.sweepMaintenance(handler, table, wt_pool_ptr, tx.active(), fd, config, now_us, &stats);
            last_sweep_us = now_us;
        }

        // Submit this wake's replies as sendmsg SQEs on the same ring instead of a blocking sendmmsg
        // syscall, then swap to the other tx buffer once it is clear of its own prior sends. The
        // submit rides the next submit_and_wait below, so this never blocks the loop.
        stats.packets += tx.active().count;
        const submitted = tx.submitAndSwap(ring, fd);
        if (submitted > 0) stats.flushes += 1;

        stats.maybeDump();
    }
}

/// The one-shot recvmsg fallback (still io_uring): a pool of recvmsg submissions stays in flight, one
/// buffer + sockaddr + msghdr per slot, and each completion hands back the bytes and peer address by slot
/// index, re-armed per datagram. Used when the provided buffer ring cannot be registered.
fn runOneShotLoop(comptime handler: core.HandlerFn, ring: *IoUring, fd: std.posix.socket_t, table: *common.ConnTable, pool: *reassembly.Pool, wt_pool_ptr: ?*wt_pool.Pool, tx: *UringTx, config: Http3ServerConfig, worker_id: usize) void {
    const bufs = config.allocator.alloc(u8, uring_recv_slots * config.max_recv_buf) catch return;
    defer config.allocator.free(bufs);
    const names = config.allocator.alloc(std.posix.sockaddr.in6, uring_recv_slots) catch return;
    defer config.allocator.free(names);
    const iovs = config.allocator.alloc(std.posix.iovec, uring_recv_slots) catch return;
    defer config.allocator.free(iovs);
    const msgs = config.allocator.alloc(linux.msghdr, uring_recv_slots) catch return;
    defer config.allocator.free(msgs);

    // Slots whose recvmsg re-arm was lost to a full SQ, retried at the top of the loop. Each slot
    // appears at most once (a slot re-arms only after its own completion), so the array bounds it.
    var pending_slots: [uring_recv_slots]usize = undefined;
    var pending_count: usize = 0;

    for (0..uring_recv_slots) |slot| {
        iovs[slot] = .{ .base = bufs.ptr + slot * config.max_recv_buf, .len = config.max_recv_buf };
        msgs[slot] = .{
            .name = @ptrCast(&names[slot]),
            .namelen = sockaddr_in6_len,
            .iov = @ptrCast(&iovs[slot]),
            .iovlen = 1,
            .control = null,
            .controllen = 0,
            .flags = 0,
        };

        if (!armUringRecv(ring, &msgs[slot], slot, fd)) {
            pending_slots[pending_count] = slot;
            pending_count += 1;
        }
    }

    common.logSystem(config, .INFO, "io_uring worker {d} up ({d} recv slots, one-shot)", .{ worker_id, uring_recv_slots });

    var stats = common.WorkerStats{ .worker_id = worker_id };
    common.registerWorkerStats(&stats);
    var cqes: [uring_cqe_batch]linux.io_uring_cqe = undefined;
    var last_sweep_us: u64 = recovery.nowUs();
    var timeout_armed = false;
    const maintenance_ts = linux.kernel_timespec{ .sec = 0, .nsec = @intCast(common.maintenance_interval_us * 1000) };

    while (true) {
        // Retry receive slots whose re-arm was lost to a full SQ, so a slot is delayed, never leaked.
        while (pending_count > 0) {
            const slot = pending_slots[pending_count - 1];
            if (!armUringRecv(ring, &msgs[slot], slot, fd)) break;

            pending_count -= 1;
        }

        // Arm one maintenance timeout while the worker owns connections, so the wait returns after the
        // interval even with no I/O and the sweep still runs during a lull. Re-armed after it fires.
        if (!timeout_armed and table.count > 0) {
            if (ring.timeout(uring_timeout_tag, &maintenance_ts, 0, 0)) |_| {
                timeout_armed = true;
            } else |_| {}
        }

        if (comptime common.diag_enabled) stats.wait_enter_us = recovery.nowUs();
        const wait_result = ring.submit_and_wait(1);
        if (comptime common.diag_enabled) {
            stats.block_us += recovery.nowUs() -| stats.wait_enter_us;
            stats.wait_enter_us = 0;
        }
        _ = wait_result catch continue;
        stats.wakes += 1;

        const reaped = ring.copy_cqes(&cqes, 0) catch continue;
        for (cqes[0..reaped]) |cqe| {
            if (cqe.user_data == uring_timeout_tag) {
                timeout_armed = false; // the maintenance timer fired (or was cancelled): re-arm next loop
                continue;
            }
            if (tx.reap(cqe.user_data)) continue; // a send SQE landed, bookkeeping only

            const slot: usize = @intCast(cqe.user_data);

            // res > 0 is the datagram length, res <= 0 is an empty datagram or a recvmsg error. Re-arm the
            // slot either way so the receive stays in flight.
            if (cqe.res > 0) {
                const len: usize = @min(@as(usize, @intCast(cqe.res)), config.max_recv_buf);
                stats.datagrams += 1;
                common.serveDatagram(handler, table, pool, wt_pool_ptr, .{ .data = bufs[slot * config.max_recv_buf ..][0..len], .from = names[slot] }, tx.active(), fd, config, &stats);
            }

            if (!armUringRecv(ring, &msgs[slot], slot, fd)) {
                pending_slots[pending_count] = slot;
                pending_count += 1;
            }
        }

        // Time-driven maintenance before the send submit, so a retransmit it queues rides this wake's
        // sends. At most once per interval however often a completion wakes the worker.
        const now_us = recovery.nowUs();
        if (now_us -| last_sweep_us >= common.maintenance_interval_us) {
            common.sweepMaintenance(handler, table, wt_pool_ptr, tx.active(), fd, config, now_us, &stats);
            last_sweep_us = now_us;
        }

        // Submit this wake's replies as sendmsg SQEs on the same ring instead of a blocking sendmmsg
        // syscall, then swap to the other tx buffer once it is clear of its own prior sends.
        stats.packets += tx.active().count;
        const submitted = tx.submitAndSwap(ring, fd);
        if (submitted > 0) stats.flushes += 1;

        stats.maybeDump();
    }
}

/// Run the HTTP/3 server with one SO_REUSEPORT io_uring worker per core. Mirrors runEpoll but with a real
/// io_uring recv backend, so .URING is a genuine io_uring path, not the recvmmsg fold.
pub fn runUring(comptime handler: core.HandlerFn, config: Http3ServerConfig) !void {
    if (!datagram.is_linux) {
        common.logSystem(config, .ERROR, "HTTP/3 requires the Linux datagram path", .{});
        return;
    }

    const want = common.effectiveWorkers(config);

    common.installDiagnosticDump();

    const threads = try config.allocator.alloc(std.Thread, want);
    defer config.allocator.free(threads);

    // CBPF steering: one shared bind-order gate, alive until join().
    var bind_gate = reuseport.BindOrderGate{};
    const steering: ?reuseport.Steering = if (config.reuseport_cbpf) .{ .gate = &bind_gate, .group_size = want } else null;

    // What every worker says about its own socket, so a bind that fails inside a worker thread
    // reaches this frame instead of ending that thread and nothing else.
    var report = listen_report.Report.init(want);

    var spawned: usize = 0;
    for (0..want) |i| {
        threads[i] = std.Thread.spawn(.{ .stack_size = config.worker_stack_size_bytes }, workerLoopUring, .{ handler, config, i, steering, &report }) catch |err| {
            common.logSystem(config, .ERROR, "could not spawn worker {d} of {d} ({s})", .{ i, want, @errorName(err) });
            report.abandon(config.io, want - i, err);

            break;
        };
        spawned += 1;
    }

    if (report.awaitGroup(config.io)) |err| {
        common.logSystem(config, .ERROR, "not listening on {s}:{d}: {d} of {d} workers could not bind ({s})", .{ config.ip, config.port, report.failures(), want, @errorName(err) });

        for (threads[0..spawned]) |thread| thread.join();

        return error.ZixHttp3ListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is nothing
    // to announce: the old line claimed a socket that may never have been bound.
    common.logSystem(config, .INFO, "listening on {s}:{d} ({d} workers, SO_REUSEPORT + io_uring)", .{ config.ip, config.port, want });

    for (threads[0..spawned]) |thread| thread.join();
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix http3: parseMultishotBuf recovers the peer and payload at the recvmsg_out offsets" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    const name_reserve = mshot_name_reserve;
    var buf: [256]u8 = @splat(0);

    // Lay out a completion buffer exactly as the kernel does: recvmsg_out header, then the peer address,
    // then the payload.
    const out = linux.io_uring_recvmsg_out{ .namelen = @intCast(name_reserve), .controllen = 0, .payloadlen = 5, .flags = 0 };
    @memcpy(buf[0..recvmsg_out_hdr], std.mem.asBytes(&out));

    var peer = std.mem.zeroes(std.posix.sockaddr.in6);
    peer.family = linux.AF.INET6;
    peer.port = std.mem.nativeToBig(u16, 4242);
    @memcpy(buf[recvmsg_out_hdr..][0..name_reserve], std.mem.asBytes(&peer));

    const payload_off = recvmsg_out_hdr + name_reserve;
    @memcpy(buf[payload_off..][0..5], "world");

    const parsed = parseMultishotBuf(buf[0 .. payload_off + 5], name_reserve, 0, 1500).?;
    try std.testing.expectEqualStrings("world", parsed.payload);
    try std.testing.expectEqual(@as(u16, 4242), std.mem.bigToNative(u16, parsed.peer.port));

    // A buffer shorter than the recvmsg_out header is rejected.
    try std.testing.expect(parseMultishotBuf(buf[0..8], name_reserve, 0, 1500) == null);

    // A truncated peer address (namelen below a full sockaddr_in6) is rejected.
    const short = linux.io_uring_recvmsg_out{ .namelen = 4, .controllen = 0, .payloadlen = 5, .flags = 0 };
    @memcpy(buf[0..recvmsg_out_hdr], std.mem.asBytes(&short));
    try std.testing.expect(parseMultishotBuf(buf[0 .. payload_off + 5], name_reserve, 0, 1500) == null);
}

test "zix http3: http3 run shapes compile (monomorphize without running)" {
    // The run shapes never return, so they cannot be run in a test. if (false) still type-checks the
    // whole call chain at comptime, so a compile error in any generic body (including the parameterized
    // workerLoop that runSingle drives) surfaces here rather than only when an example runs it.
    const noop = struct {
        fn handle(_: *const core.Request, _: *core.Response) void {}
    }.handle;

    if (false) {
        runUring(noop, undefined) catch {};
        epoll.runEpoll(noop, undefined) catch {};
        common.runSingle(noop, undefined) catch {};
    }
}

test "zix http3: io_uring recvmsg delivers a datagram and its peer address by slot" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    if (comptime !datagram.is_linux) return;

    var ring = initUringRing() catch return; // skip where io_uring is unavailable (sandbox / old kernel)
    defer ring.deinit();

    const r_fd = datagram.open("127.0.0.1", 19073, false) catch return; // skip if the port is busy
    defer datagram.close(r_fd);

    // Arm a single recvmsg on slot 7, then send one datagram to the receiver.
    var name: std.posix.sockaddr.in6 = undefined;
    var buf: [1500]u8 = undefined;
    var iov = std.posix.iovec{ .base = &buf, .len = buf.len };
    var msg = linux.msghdr{
        .name = @ptrCast(&name),
        .namelen = sockaddr_in6_len,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    try std.testing.expect(armUringRecv(&ring, &msg, 7, r_fd));
    _ = ring.submit() catch return;

    const s_fd = datagram.open("127.0.0.1", 19074, false) catch return;
    defer datagram.close(s_fd);

    const dest = datagram.ipToSockaddr6(try std.Io.net.IpAddress.parse("127.0.0.1", 19073));
    var tx = try datagram.SendBatch.init(std.testing.allocator, 1, 64);
    defer tx.deinit();
    try std.testing.expect(tx.queue(dest, "ping"));
    try tx.flush(s_fd);

    // The completion carries the slot in user_data, the byte count in res, and the bytes in the buffer.
    _ = ring.submit_and_wait(1) catch return;
    var cqes: [4]linux.io_uring_cqe = undefined;
    const n = ring.copy_cqes(&cqes, 0) catch return;
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(u64, 7), cqes[0].user_data);
    try std.testing.expect(cqes[0].res >= 4);
    try std.testing.expectEqualStrings("ping", buf[0..4]);
}

test "zix http3: UringTx.activeTailPending gates the swap on a fully submitted buffer" {
    var tx = UringTx.init(std.testing.allocator, 4, 64) catch return;
    defer tx.deinit();

    // An empty active buffer has no tail.
    try std.testing.expect(!tx.activeTailPending());

    // A queued reply not yet on the ring is a pending tail: submitAndSwap must not rotate the
    // buffer out, or the swap-back reset() would discard the reply.
    const dest = datagram.ipToSockaddr6(try std.Io.net.IpAddress.parse("127.0.0.1", 19080));
    try std.testing.expect(tx.active().queue(dest, "tail"));
    try std.testing.expect(tx.activeTailPending());

    // Once the ring took it (as submitUring records via ring_sent), the buffer may rotate.
    tx.bufs[tx.cur].ring_sent = tx.bufs[tx.cur].count;
    try std.testing.expect(!tx.activeTailPending());
}

test "zix http3: armUringRecv and armMultishotRecv report the arm result" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    if (comptime !datagram.is_linux) return;

    var ring = initUringRing() catch return; // skip where io_uring is unavailable
    defer ring.deinit();

    const fd = datagram.open("127.0.0.1", 19081, false) catch return; // skip if the port is busy
    defer datagram.close(fd);

    var name: std.posix.sockaddr.in6 = undefined;
    var buf: [64]u8 = undefined;
    var iov = std.posix.iovec{ .base = &buf, .len = buf.len };
    var msg = linux.msghdr{
        .name = @ptrCast(&name),
        .namelen = sockaddr_in6_len,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };

    // Fill the whole SQ with no-ops, so the next arm exercises the submit-then-retry path in
    // uringGetSqe and still lands (true), instead of silently dropping the receive.
    for (0..uring_entries) |_| {
        const sqe = ring.get_sqe() catch break;
        sqe.prep_nop();
        sqe.user_data = 0;
    }
    try std.testing.expect(armUringRecv(&ring, &msg, 3, fd));

    // The multishot arm reports its result the same way (no buffer ring is registered here, so the
    // SQE will complete with ENOBUFS later, but queuing it must succeed).
    var mshot_msg = std.mem.zeroes(linux.msghdr);
    mshot_msg.namelen = @intCast(mshot_name_reserve);
    try std.testing.expect(armMultishotRecv(&ring, &mshot_msg, fd));
}

test "zix http3: UringTx.reap matches only its own two tags" {
    var tx = UringTx.init(std.testing.allocator, 4, 64) catch return;
    defer tx.deinit();

    // An unrelated tag (a recv slot index or the multishot sentinel) is not a send completion.
    try std.testing.expect(!tx.reap(999));

    tx.inflight[1] = 2;
    try std.testing.expect(tx.reap(UringTx.tags[1]));
    try std.testing.expectEqual(@as(usize, 1), tx.inflight[1]);

    // Saturating: reaping past zero never underflows.
    try std.testing.expect(tx.reap(UringTx.tags[0]));
    try std.testing.expectEqual(@as(usize, 0), tx.inflight[0]);
}

test "zix http3: UringTx.submitAndSwap defers the swap while the other buffer still has sends in flight" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    if (comptime !datagram.is_linux) return;

    var ring = initUringRing() catch return; // skip where io_uring is unavailable
    defer ring.deinit();

    const fd = datagram.open("127.0.0.1", 19079, false) catch return; // skip if the port is busy
    defer datagram.close(fd);

    var tx = UringTx.init(std.testing.allocator, 4, 64) catch return;
    defer tx.deinit();

    const dest = datagram.ipToSockaddr6(try std.Io.net.IpAddress.parse("127.0.0.1", 19079));

    // Buffer 0 queues one reply and submits: buffer 1 was clear, so it swaps in for the next wake.
    try std.testing.expect(tx.active().queue(dest, "one"));
    _ = tx.submitAndSwap(&ring, fd);
    try std.testing.expectEqual(@as(usize, 1), tx.cur);
    try std.testing.expectEqual(@as(usize, 1), tx.inflight[0]);

    // Buffer 1 submits (nothing queued): buffer 0's send is still unreaped, so the swap back is
    // deferred and the worker keeps queuing into buffer 1 for the next wake too.
    _ = tx.submitAndSwap(&ring, fd);
    try std.testing.expectEqual(@as(usize, 1), tx.cur);

    // Reaping buffer 0's completion, as the real worker loop's own CQE drain would, clears the way.
    _ = try ring.submit_and_wait(1);
    var cqes: [4]linux.io_uring_cqe = undefined;
    const reaped = try ring.copy_cqes(&cqes, 0);
    for (cqes[0..reaped]) |cqe| _ = tx.reap(cqe.user_data);
    try std.testing.expectEqual(@as(usize, 0), tx.inflight[0]);

    _ = tx.submitAndSwap(&ring, fd);
    try std.testing.expectEqual(@as(usize, 0), tx.cur); // swapped back now that buffer 0 is clear
}
