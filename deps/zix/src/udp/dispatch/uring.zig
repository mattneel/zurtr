//! zix udp raw-bytes URING dispatch (ADR-049 / ADR-050): one SO_REUSEPORT worker per CPU, each driving a
//! real io_uring completion loop. Prefers multishot recvmsg on a provided buffer ring (one SQE yields a
//! CQE per datagram, no per-datagram re-arm), falling back to the one-shot recvmsg slot pool when the
//! buffer ring cannot be registered (older kernel), and to the epoll loop when io_uring is unavailable
//! entirely (old kernel, seccomp, RLIMIT_MEMLOCK), so selecting .URING never strands a core. The
//! per-datagram serve and the worker helpers live in the common module (common.zig).

const std = @import("std");
const linux = std.os.linux;
const IoUring = std.os.linux.IoUring;

const Config = @import("../config.zig");
const UdpServerConfig = Config.UdpServerConfig;
const core = @import("../core.zig");
const datagram = @import("../datagram.zig");
const common = @import("common.zig");
const reuseport = @import("../../multiplexers/reuseport.zig");
const listen_report = @import("../../multiplexers/listen_report.zig");
const epoll = @import("epoll.zig");

/// io_uring submission-queue depth for a raw-UDP .URING worker. The ring carries only recvmsg SQEs
/// (replies go out through the sendmmsg SendBatch), so this bounds the outstanding receives. A power of
/// two, at least uring_recv_slots.
const uring_entries: u16 = 256;

/// In-flight recvmsg submissions per worker: how many datagrams the kernel can fill at once, at
/// slots * max_recv_buf bytes of receive buffer per worker. Kept at or below uring_entries.
const uring_recv_slots: usize = 192;

/// Completions reaped per copy_cqes call.
const uring_cqe_batch: usize = 256;

/// One dual-stack sockaddr_in6 length, for a recvmsg msghdr name field.
const sockaddr_in6_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in6);

/// Multishot recv. A provided buffer ring lets one multishot recvmsg SQE deliver a CQE per datagram
/// without re-arming per datagram (the one-shot re-arm churn): the kernel selects a buffer from the ring
/// for each completion and writes an io_uring_recvmsg_out header, the peer address, then the payload into
/// it. When the kernel ends the multishot (buffer exhaustion or error, no IORING_CQE_F_MORE), the worker
/// re-arms. Buffer-ring entries must be a power of two.
const uring_ring_bufs: u16 = 256;

/// The provided-buffer group id for the worker ring (one group per worker).
const uring_buf_group: u16 = 1;

/// user_data tag on the multishot recvmsg SQE, distinct from the one-shot slot indices
/// (0..uring_recv_slots) so a completion is never mistaken for a slot.
const uring_mshot_tag: u64 = std.math.maxInt(u64);

/// Bytes the kernel prefixes to each selected buffer: the io_uring_recvmsg_out header.
const recvmsg_out_hdr: usize = @sizeOf(linux.io_uring_recvmsg_out);

/// Bytes reserved for the peer address in each selected buffer (a dual-stack sockaddr_in6).
const mshot_name_reserve: usize = @sizeOf(std.posix.sockaddr.in6);

/// Initialize one io_uring for a raw-UDP worker. Each per-core worker is shared-nothing: one thread owns
/// the ring, submits, and reaps, so SINGLE_ISSUER (only this thread submits, kernel skips submitter
/// locking) + DEFER_TASKRUN (completion task work runs at submit_and_wait, not on every IRQ) apply. They
/// pair (DEFER_TASKRUN requires SINGLE_ISSUER) and need a recent kernel, so the init steps down to
/// COOP_TASKRUN then to plain flags. A kernel without io_uring errors out and the caller falls back to
/// the epoll worker. No SQPOLL: it needs privilege and a dedicated kernel poll thread per ring.
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
fn armUringRecv(ring: *IoUring, msg: *linux.msghdr, slot: usize, fd: std.posix.socket_t) void {
    msg.namelen = sockaddr_in6_len;

    const sqe = uringGetSqe(ring) orelse return;
    sqe.prep_recvmsg(fd, msg, 0);
    sqe.user_data = @intCast(slot);
}

/// Arm (or re-arm) the multishot recvmsg on the provided buffer group: one SQE yields a CQE per datagram
/// (each carrying a selected buffer id) until the kernel ends the multishot, when the caller re-arms. The
/// msghdr only reserves the name / control space. The kernel writes the recvmsg_out header, the peer
/// address, then the payload into each selected buffer.
fn armMultishotRecv(ring: *IoUring, msg: *linux.msghdr, fd: std.posix.socket_t) void {
    const sqe = uringGetSqe(ring) orelse return;
    sqe.prep_recvmsg_multishot(fd, msg, 0);
    sqe.flags |= linux.IOSQE_BUFFER_SELECT;
    sqe.buf_index = uring_buf_group;
    sqe.user_data = uring_mshot_tag;
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
    const payload_len = @min(@as(usize, out.payloadlen), max_payload);
    if (payload_off + payload_len > buf.len) return null;

    var peer: std.posix.sockaddr.in6 = undefined;
    @memcpy(std.mem.asBytes(&peer), buf[recvmsg_out_hdr..][0..mshot_name_reserve]);

    return .{ .peer = peer, .payload = buf[payload_off..][0..payload_len] };
}

/// One raw-UDP io_uring worker: bind a per-core SO_REUSEPORT socket and drive a real io_uring completion
/// loop. A pool of recvmsg submissions stays in flight (one buffer + sockaddr + msghdr per slot), so the
/// kernel fills many datagrams in parallel and each completion hands back the bytes and peer address by
/// slot index. Replies go out through the same coalescing SendBatch, flushed once per completion batch.
/// Shared-nothing: its own ring, socket, and batches, no lock on the hot path. Falls back to the epoll
/// loop when io_uring is unavailable.
fn workerLoopUring(comptime handler: core.HandlerFn, config: UdpServerConfig, worker_id: usize, steering: ?reuseport.Steering, report: *listen_report.Report) void {
    common.pinToCpu(worker_id);

    var ring = initUringRing() catch |err| {
        common.logSystem(config, .WARN, "io_uring unavailable ({s}): raw worker {d} falls back to epoll", .{ @errorName(err), worker_id });

        return epoll.workerLoopEpoll(handler, config, worker_id, steering, report);
    };
    defer ring.deinit();

    // Datagrams served by this worker (skew counter). Single-owner plain increment
    // (no contention), reported through the system logger at worker exit so
    // REUSEPORT skew across workers is measurable. Placed after the ring probe so
    // the epoll fallback reports through its own counter only.
    var datagrams_served: u64 = 0;
    defer common.logSystem(config, .INFO, "uring worker {d}: {d} datagrams served", .{ worker_id, datagrams_served });

    // Bind under the order gate: REUSEPORT group index i = worker i,
    // so the cpu-mod-N steering lands on the worker pinned to that slot.
    var bind_turn = reuseport.BindTurn.begin(steering, worker_id);
    defer bind_turn.release();

    // Every exit between here and the ring loop has to reach the group, or the workers that did
    // bind wait on one that is already gone.
    var slot = report.slot(config.io, error.ZixUdpWorkerSetupFailed);
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

    var tx = datagram.SendBatch.init(config.allocator, config.send_batch, config.send_batch * config.max_recv_buf) catch return;
    defer tx.deinit();

    tx.gso = config.gso_enabled and datagram.probeGso(fd);

    runRecvLoop(handler, &ring, fd, &tx, config, worker_id, &datagrams_served);
}

/// Drive receives on the ring: set up the multishot provided buffer ring and run the multishot loop, or
/// fall back to the one-shot recvmsg slot pool when the buffer ring cannot be registered (older kernel).
fn runRecvLoop(comptime handler: core.HandlerFn, ring: *IoUring, fd: std.posix.socket_t, tx: *datagram.SendBatch, config: UdpServerConfig, worker_id: usize, datagrams_served: *u64) void {
    const buf_size = std.mem.alignForward(usize, recvmsg_out_hdr + mshot_name_reserve + config.max_recv_buf, 16);

    const br = IoUring.setup_buf_ring(ring.fd, uring_ring_bufs, uring_buf_group, .{ .inc = false }) catch
        return runOneShotLoop(handler, ring, fd, tx, config, worker_id, datagrams_served);
    defer IoUring.free_buf_ring(ring.fd, br, uring_ring_bufs, uring_buf_group);
    IoUring.buf_ring_init(br);

    const backing = config.allocator.alloc(u8, uring_ring_bufs * buf_size) catch
        return runOneShotLoop(handler, ring, fd, tx, config, worker_id, datagrams_served);
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
    armMultishotRecv(ring, &msg, fd);

    common.logSystem(config, .INFO, "raw io_uring worker {d} up (multishot recvmsg, {d} buffers)", .{ worker_id, uring_ring_bufs });

    var cqes: [uring_cqe_batch]linux.io_uring_cqe = undefined;
    while (true) {
        _ = ring.submit_and_wait(1) catch continue;

        const reaped = ring.copy_cqes(&cqes, 0) catch continue;
        var rearm = false;
        for (cqes[0..reaped]) |cqe| {
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
                        datagrams_served.* += 1;
                        common.serveDatagram(handler, .{ .data = parsed.payload, .from = parsed.peer }, tx, fd);
                    }
                }

                IoUring.buf_ring_add(br, buf, bid, mask, 0);
                IoUring.buf_ring_advance(br, 1);
            }

            // The multishot ended (buffer exhaustion or error): re-arm so receives stay in flight.
            if (cqe.flags & linux.IORING_CQE_F_MORE == 0) rearm = true;
        }
        if (rearm) armMultishotRecv(ring, &msg, fd);

        tx.flush(fd) catch tx.reset();
    }
}

/// The one-shot recvmsg fallback (still io_uring): a pool of recvmsg submissions stays in flight, one
/// buffer + sockaddr + iovec + msghdr per slot, and each completion hands back the bytes and peer address
/// by slot index, re-armed per datagram. Used when the provided buffer ring cannot be registered.
fn runOneShotLoop(comptime handler: core.HandlerFn, ring: *IoUring, fd: std.posix.socket_t, tx: *datagram.SendBatch, config: UdpServerConfig, worker_id: usize, datagrams_served: *u64) void {
    // Receive-slot pool: one buffer + sockaddr + iovec + msghdr per in-flight recvmsg. Each msghdr points
    // at its slot's sockaddr and iovec (heap slices, stable for the worker's life), so the kernel writes
    // the datagram into the buffer and the peer address into the sockaddr, recovered by the CQE slot index.
    const bufs = config.allocator.alloc(u8, uring_recv_slots * config.max_recv_buf) catch return;
    defer config.allocator.free(bufs);
    const names = config.allocator.alloc(std.posix.sockaddr.in6, uring_recv_slots) catch return;
    defer config.allocator.free(names);
    const iovs = config.allocator.alloc(std.posix.iovec, uring_recv_slots) catch return;
    defer config.allocator.free(iovs);
    const msgs = config.allocator.alloc(linux.msghdr, uring_recv_slots) catch return;
    defer config.allocator.free(msgs);

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
        armUringRecv(ring, &msgs[slot], slot, fd);
    }

    common.logSystem(config, .INFO, "raw io_uring worker {d} up ({d} recv slots, one-shot)", .{ worker_id, uring_recv_slots });

    var cqes: [uring_cqe_batch]linux.io_uring_cqe = undefined;
    while (true) {
        _ = ring.submit_and_wait(1) catch continue;

        const reaped = ring.copy_cqes(&cqes, 0) catch continue;
        for (cqes[0..reaped]) |cqe| {
            const slot: usize = @intCast(cqe.user_data);

            // res > 0 is the datagram length, res <= 0 is an empty datagram or a recvmsg error. Re-arm the
            // slot either way so the receive stays in flight.
            if (cqe.res > 0) {
                const len: usize = @min(@as(usize, @intCast(cqe.res)), config.max_recv_buf);
                datagrams_served.* += 1;
                common.serveDatagram(handler, .{ .data = bufs[slot * config.max_recv_buf ..][0..len], .from = names[slot] }, tx, fd);
            }

            armUringRecv(ring, &msgs[slot], slot, fd);
        }

        tx.flush(fd) catch tx.reset();
    }
}

/// Run the raw server with one SO_REUSEPORT io_uring worker per CPU. Linux-only: off Linux this returns
/// error.ZixDispatchModelUnsupported instead of downgrading (ADR-065), the caller picks .ASYNC there.
pub fn runUring(comptime handler: core.HandlerFn, config: UdpServerConfig) !void {
    if (!datagram.is_linux) return error.ZixDispatchModelUnsupported;

    const want = common.effectiveWorkers(config);

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
        common.logSystem(config, .ERROR, "raw not listening on {s}:{d}: {d} of {d} workers could not bind ({s})", .{ config.ip, config.port, report.failures(), want, @errorName(err) });

        for (threads[0..spawned]) |thread| thread.join();

        return error.ZixUdpListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is nothing
    // to announce: the old line claimed a socket that may never have been bound.
    common.logSystem(config, .INFO, "raw listening on {s}:{d} ({d} workers, SO_REUSEPORT + io_uring)", .{ config.ip, config.port, want });

    for (threads[0..spawned]) |thread| thread.join();
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix udp: raw udp epoll and uring run shapes compile (monomorphize without running)" {
    // The per-core loops never return, so they cannot be run in a test. if (false) still type-checks the
    // whole call chain at comptime: runUring -> workerLoopUring, runEpoll -> workerLoopEpoll, so a compile
    // error in either generic body surfaces here rather than only when an example instantiates it.
    const noop = struct {
        fn handle(_: []const u8, _: *const std.Io.net.IpAddress, _: *core.Sink) void {}
    }.handle;

    if (false) {
        runUring(noop, undefined) catch {};
        epoll.runEpoll(noop, undefined) catch {};
        common.runSingle(noop, undefined) catch {};
    }
}

test "zix udp: raw udp parseMultishotBuf recovers the peer and payload at the recvmsg_out offsets" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var buf: [256]u8 = @splat(0);

    // Lay out a completion buffer exactly as the kernel does: recvmsg_out header, then the peer
    // address, then the payload.
    var out = std.mem.zeroes(linux.io_uring_recvmsg_out);
    out.namelen = @intCast(mshot_name_reserve);
    out.payloadlen = 4;
    @memcpy(buf[0..recvmsg_out_hdr], std.mem.asBytes(&out));

    var peer = std.mem.zeroes(std.posix.sockaddr.in6);
    peer.family = std.posix.AF.INET6;
    peer.port = std.mem.nativeToBig(u16, 9100);
    @memcpy(buf[recvmsg_out_hdr..][0..mshot_name_reserve], std.mem.asBytes(&peer));

    const payload_off = recvmsg_out_hdr + mshot_name_reserve;
    @memcpy(buf[payload_off..][0..4], "ping");

    const parsed = parseMultishotBuf(buf[0 .. payload_off + 4], mshot_name_reserve, 0, 1500) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(peer.port, parsed.peer.port);
    try std.testing.expectEqualStrings("ping", parsed.payload);

    // A truncated peer address (namelen too small) drops the datagram.
    out.namelen = 4;
    @memcpy(buf[0..recvmsg_out_hdr], std.mem.asBytes(&out));
    try std.testing.expect(parseMultishotBuf(buf[0 .. payload_off + 4], mshot_name_reserve, 0, 1500) == null);
}

test "zix udp: raw udp io_uring recvmsg delivers a datagram and its peer address by slot" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    if (comptime !datagram.is_linux) return;

    var ring = initUringRing() catch return; // skip where io_uring is unavailable (sandbox / old kernel)
    defer ring.deinit();

    const r_fd = datagram.open("127.0.0.1", 19081, false) catch return; // skip if the port is busy
    defer datagram.close(r_fd);

    // Arm a single recvmsg on slot 5, then send one datagram to the receiver.
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
    armUringRecv(&ring, &msg, 5, r_fd);
    _ = ring.submit() catch return;

    const s_fd = datagram.open("127.0.0.1", 19082, false) catch return;
    defer datagram.close(s_fd);

    const dest = datagram.ipToSockaddr6(try std.Io.net.IpAddress.parse("127.0.0.1", 19081));
    var tx = try datagram.SendBatch.init(std.testing.allocator, 1, 64);
    defer tx.deinit();
    try std.testing.expect(tx.queue(dest, "ping"));
    try tx.flush(s_fd);

    // The completion carries the slot in user_data, the byte count in res, and the bytes in the buffer.
    _ = ring.submit_and_wait(1) catch return;
    var cqes: [4]linux.io_uring_cqe = undefined;
    const n = ring.copy_cqes(&cqes, 0) catch return;
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(u64, 5), cqes[0].user_data);
    try std.testing.expect(cqes[0].res >= 4);
    try std.testing.expectEqualStrings("ping", buf[0..4]);
}
