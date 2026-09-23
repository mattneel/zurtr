//! zix WebRTC URING dispatch: one SO_REUSEPORT worker per core, each driving a real io_uring
//! completion loop (multicore, Linux).
//!
//! What:
//! - A pool of recvmsg submissions stays in flight, and the kernel hands each datagram back as a
//!   completion carrying the peer address. One timeout submission rides alongside them, so the wait
//!   ends on a deadline as readily as on a datagram.
//! - A worker whose host has no usable ring folds to the epoll loop, so asking for .URING never
//!   strands a core.
//!
//! Note:
//! - Receives go through the ring, replies go out with one sendmmsg per wake. The double-buffered
//!   send ring the HTTP/3 worker carries exists to keep a throughput engine's send queue full, and
//!   a WebRTC wake answers a handful of peers rather than thousands of requests. It is a refinement
//!   this engine has no measurement asking for yet, and the ring is a real ring without it.
//! - One-shot recvmsg rather than multishot on a provided buffer ring, for the same reason: the
//!   re-arm per datagram costs one submission, and there is no datagram flood here to amortise it
//!   against. Both are worth revisiting when this engine has a baseline to defend.
//! - The timeout is armed once and re-armed after it fires, so a deadline that becomes sooner while
//!   a longer timeout is in flight is answered late. The budget is capped by tick_interval_ms, so
//!   that lateness is too.
//! - No CBPF CPU steering, for the reason epoll.zig gives: a WebRTC peer is its 4-tuple, and the
//!   default hash is what keeps one peer's datagrams on one worker.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const IoUring = std.os.linux.IoUring;

const Config = @import("../config.zig");
const WebrtcServerConfig = Config.WebrtcServerConfig;
const common = @import("common.zig");
const listen_report = @import("../../../multiplexers/listen_report.zig");
const core = @import("../core.zig");
const datagram = @import("../../datagram.zig");
const epoll = @import("epoll.zig");
const worker = @import("worker.zig");

/// Submission queue depth. Holds the receive slots, their re-arms, and the timeout with room to
/// spare. A power of two, as the ring requires.
const URING_ENTRIES: u16 = 128;

/// Receives in flight per worker: how many datagrams the kernel can fill at once. Each costs one
/// max_recv_buf slot, and a WebRTC worker holds tens of peers rather than thousands.
const URING_RECV_SLOTS: usize = 64;

/// Completions taken in one copy_cqes call.
const URING_CQE_BATCH: usize = 128;

/// The tag on the deadline timeout, kept clear of every slot index so a fired timer is never
/// mistaken for a receive.
const URING_TIMEOUT_TAG: u64 = std.math.maxInt(u64);

/// One dual-stack sockaddr_in6 length, for a recvmsg msghdr name field.
const SOCKADDR_IN6_LEN: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in6);

/// One URING worker: its socket, its ring, the receive slots, and the peers it holds.
const Ring = struct {
    config: WebrtcServerConfig,
    fd: std.posix.socket_t,
    ring: IoUring,
    worker: worker.Worker,

    /// One receive slot each: the bytes, the peer address the kernel fills in, and the msghdr
    /// wiring them together.
    bufs: []u8,
    names: []std.posix.sockaddr.in6,
    iovs: []std.posix.iovec,
    msgs: []linux.msghdr,

    /// Slots whose re-arm was refused by a full submission queue, retried at the top of the next
    /// pass. A slot re-arms only after its own completion, so it can appear here at most once.
    pending: [URING_RECV_SLOTS]usize,
    pending_count: usize,

    timeout_armed: bool,
    /// Read by the kernel while the timeout is in flight, so it lives as long as the worker.
    timeout_ts: linux.kernel_timespec,

    cqes: [URING_CQE_BATCH]linux.io_uring_cqe,

    /// Bind, open the ring, and wire the receive slots. Nothing is submitted yet.
    ///
    /// Note:
    /// - The kernel is handed pointers into this struct once prime() runs, so the value has to be
    ///   in its final place by then. That is why arming is not done here.
    ///
    /// Return:
    /// - Ring
    /// - whatever the bind, the ring, or the allocations raised
    fn init(config: WebrtcServerConfig) !Ring {
        const fd = try common.openWorkerSocket(config);
        errdefer datagram.close(fd);

        var ring = try openRing();
        errdefer ring.deinit();

        const bufs = try config.allocator.alloc(u8, URING_RECV_SLOTS * config.max_recv_buf);
        errdefer config.allocator.free(bufs);

        const names = try config.allocator.alloc(std.posix.sockaddr.in6, URING_RECV_SLOTS);
        errdefer config.allocator.free(names);

        const iovs = try config.allocator.alloc(std.posix.iovec, URING_RECV_SLOTS);
        errdefer config.allocator.free(iovs);

        const msgs = try config.allocator.alloc(linux.msghdr, URING_RECV_SLOTS);
        errdefer config.allocator.free(msgs);

        for (0..URING_RECV_SLOTS) |slot| {
            iovs[slot] = .{ .base = bufs.ptr + slot * config.max_recv_buf, .len = config.max_recv_buf };
            msgs[slot] = .{
                .name = @ptrCast(&names[slot]),
                .namelen = SOCKADDR_IN6_LEN,
                .iov = @ptrCast(&iovs[slot]),
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            };
        }

        return .{
            .config = config,
            .fd = fd,
            .ring = ring,
            .worker = try worker.Worker.initDescriptor(config, fd),
            .bufs = bufs,
            .names = names,
            .iovs = iovs,
            .msgs = msgs,
            .pending = undefined,
            .pending_count = 0,
            .timeout_armed = false,
            .timeout_ts = .{ .sec = 0, .nsec = 0 },
            .cqes = undefined,
        };
    }

    fn deinit(self: *Ring) void {
        // The ring goes first: the kernel holds pointers into the slot buffers until it does.
        self.ring.deinit();

        self.worker.deinit();
        self.config.allocator.free(self.msgs);
        self.config.allocator.free(self.iovs);
        self.config.allocator.free(self.names);
        self.config.allocator.free(self.bufs);

        datagram.close(self.fd);
    }

    /// Put every receive slot in flight. Called once the value is where it will stay.
    fn prime(self: *Ring) void {
        for (0..self.msgs.len) |slot| {
            if (!self.armRecv(slot)) self.holdSlot(slot);
        }
    }

    /// One trip round the loop: submit, wait, then act on every completion that came back.
    ///
    /// Note:
    /// - Separated from the loop so a test can drive single passes against a real socket. The loop
    ///   itself is still this file's own (ADR-043), it just has nothing left in it but the repeat.
    ///
    /// Param:
    /// handler - comptime core.HandlerFn
    ///
    /// Return:
    /// - void
    fn pass(self: *Ring, comptime handler: core.HandlerFn) void {
        self.rearmPending();
        self.armTimeout();

        _ = self.ring.submit_and_wait(1) catch return;

        const reaped = self.ring.copy_cqes(&self.cqes, 0) catch return;
        const now_ms = common.monotonicMs();

        var index: usize = 0;
        while (index < reaped) : (index += 1) {
            const completion = self.cqes[index];

            self.reap(handler, completion, now_ms);
        }

        self.worker.flush();

        if (self.worker.sweepDue(now_ms)) {
            self.worker.sweep(handler, now_ms);
            self.worker.flush();
        }
    }

    /// Act on one completion: the fired timeout, or a receive slot with a datagram in it.
    fn reap(self: *Ring, comptime handler: core.HandlerFn, completion: linux.io_uring_cqe, now_ms: u64) void {
        if (completion.user_data == URING_TIMEOUT_TAG) {
            self.timeout_armed = false;

            return;
        }

        if (completion.user_data >= self.msgs.len) return;

        const slot: usize = @intCast(completion.user_data);

        // res > 0 is the datagram length. Anything else is an empty datagram or a failed receive,
        // and the slot is re-armed either way so the pool never shrinks.
        if (completion.res > 0) self.deliver(handler, slot, @intCast(completion.res), now_ms);

        if (!self.armRecv(slot)) self.holdSlot(slot);
    }

    /// Give one slot's datagram to the peer it came from.
    fn deliver(self: *Ring, comptime handler: core.HandlerFn, slot: usize, bytes: usize, now_ms: u64) void {
        // A datagram the slot could not hold is one no layer below can parse, and every layer here
        // is authenticated, so guessing at the missing bytes is not an option.
        if (self.msgs[slot].flags & linux.MSG.TRUNC != 0) {
            common.logSystem(self.config, .WARN, "dropped a datagram larger than max_recv_buf ({d})", .{self.config.max_recv_buf});

            return;
        }

        const length = @min(bytes, self.config.max_recv_buf);
        const payload = self.bufs[slot * self.config.max_recv_buf ..][0..length];

        self.worker.serve(handler, datagram.sockaddr6ToIp(self.names[slot]), payload, now_ms);
    }

    /// Queue a recvmsg on one slot.
    ///
    /// Return:
    /// - true when the submission was queued
    /// - false when the submission queue is full even after a submit, and the caller must hold the
    ///   slot for the next pass
    fn armRecv(self: *Ring, slot: usize) bool {
        // recvmsg shrinks namelen to the address it actually wrote, and reports the receive's own
        // flags, so both are reset before the slot goes back in flight.
        self.msgs[slot].namelen = SOCKADDR_IN6_LEN;
        self.msgs[slot].flags = 0;

        const sqe = self.nextSqe() orelse return false;

        sqe.prep_recvmsg(self.fd, &self.msgs[slot], 0);
        sqe.user_data = @intCast(slot);

        return true;
    }

    /// Queue the deadline timeout when none is in flight.
    ///
    /// Note:
    /// - A budget of zero is a deadline already due, and a zero timeout fires at once, which is the
    ///   wake that answers it.
    fn armTimeout(self: *Ring) void {
        if (self.timeout_armed) return;

        const budget_ms = self.worker.waitMs(common.monotonicMs());

        self.timeout_ts = .{
            .sec = @intCast(budget_ms / std.time.ms_per_s),
            .nsec = @intCast((budget_ms % std.time.ms_per_s) * std.time.ns_per_ms),
        };

        if (self.ring.timeout(URING_TIMEOUT_TAG, &self.timeout_ts, 0, 0)) |_| {
            self.timeout_armed = true;
        } else |_| {}
    }

    /// Retry the slots a full submission queue refused, so a slot is delayed rather than lost.
    fn rearmPending(self: *Ring) void {
        while (self.pending_count > 0) {
            const slot = self.pending[self.pending_count - 1];

            if (!self.armRecv(slot)) return;

            self.pending_count -= 1;
        }
    }

    /// Remember a slot whose re-arm did not land.
    fn holdSlot(self: *Ring, slot: usize) void {
        if (self.pending_count >= self.pending.len) return;

        self.pending[self.pending_count] = slot;
        self.pending_count += 1;
    }

    /// A submission entry, submitting the backlog and retrying once when the queue is momentarily
    /// full. Null when the ring cannot take a submission at all right now.
    fn nextSqe(self: *Ring) ?*linux.io_uring_sqe {
        return self.ring.get_sqe() catch {
            _ = self.ring.submit() catch return null;

            return self.ring.get_sqe() catch null;
        };
    }
};

/// Open one io_uring, stepping down through the setup flags an older kernel may not have.
///
/// Note:
/// - SINGLE_ISSUER and DEFER_TASKRUN pair, and both hold here: one thread owns this ring, submits
///   on it, and reaps it. A kernel without them still gets a ring, one step down at a time.
/// - No SQPOLL. It wants privilege and a kernel poll thread per ring, which is the wrong trade for
///   a worker that spends most of its time waiting on a deadline.
///
/// Return:
/// - IoUring
/// - whatever the last attempt raised, on a host with no io_uring at all
fn openRing() !IoUring {
    const single_defer = linux.IORING_SETUP_SINGLE_ISSUER | linux.IORING_SETUP_DEFER_TASKRUN;

    if (IoUring.init(URING_ENTRIES, single_defer)) |ring| return ring else |_| {}

    if (IoUring.init(URING_ENTRIES, linux.IORING_SETUP_COOP_TASKRUN)) |ring| return ring else |_| {}

    return IoUring.init(URING_ENTRIES, 0);
}

/// One URING worker for its whole life: pin, open the ring, then answer peers until the process
/// ends. A host with no usable ring folds to the epoll worker instead.
///
/// Param:
/// handler - comptime core.HandlerFn
/// config - WebrtcServerConfig (already validated by the server)
/// worker_id - usize (its slot in the SO_REUSEPORT group)
///
/// Return:
/// - void, returning only when the worker could not start
fn workerLoopUring(comptime handler: core.HandlerFn, config: WebrtcServerConfig, worker_id: usize, report: *listen_report.Report) void {
    common.pinToCpu(worker_id);

    var ring = Ring.init(config) catch |err| {
        common.logSystem(config, .WARN, "uring worker {d} could not start ({s}), folding to epoll", .{ worker_id, @errorName(err) });

        return epoll.workerLoopEpoll(handler, config, worker_id, report);
    };
    defer ring.deinit();

    ring.prime();

    // The ring is up, which for this engine is the socket too. Serve once the group agrees.
    report.bound(config.io);
    if (report.awaitGroup(config.io) != null) return;

    while (true) ring.pass(handler);
}

/// Run the WebRTC server with one SO_REUSEPORT io_uring worker per core.
///
/// Param:
/// handler - comptime core.HandlerFn
/// config - WebrtcServerConfig (already validated by the server)
///
/// Return:
/// - !void, blocking until every worker has gone
/// - error.ZixDispatchModelUnsupported off Linux (ADR-065), where the caller picks .ASYNC
pub fn runUring(comptime handler: core.HandlerFn, config: WebrtcServerConfig) !void {
    if (comptime !datagram.is_linux) return error.ZixDispatchModelUnsupported;

    const want = common.effectiveWorkers(config);

    const threads = try config.allocator.alloc(std.Thread, want);
    defer config.allocator.free(threads);

    // What every worker says about its own socket, so a bind that fails inside a worker thread
    // reaches this frame instead of ending that thread and nothing else.
    var report = listen_report.Report.init(want);

    var spawned: usize = 0;
    for (0..want) |i| {
        threads[i] = std.Thread.spawn(.{ .stack_size = config.worker_stack_size_bytes }, workerLoopUring, .{ handler, config, i, &report }) catch |err| {
            common.logSystem(config, .ERROR, "could not spawn worker {d} of {d} ({s})", .{ i, want, @errorName(err) });
            report.abandon(config.io, want - i, err);

            break;
        };
        spawned += 1;
    }

    if (report.awaitGroup(config.io)) |err| {
        common.logSystem(config, .ERROR, "not listening on {s}:{d}: {d} of {d} workers could not start ({s})", .{ config.ip, config.port, report.failures(), want, @errorName(err) });

        for (threads[0..spawned]) |thread| thread.join();

        return error.ZixWebrtcListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is nothing
    // to announce: the old line claimed a socket that may never have been bound.
    common.logSystem(config, .INFO, "listening on {s}:{d} ({d} workers, SO_REUSEPORT + io_uring)", .{ config.ip, config.port, want });

    for (threads[0..spawned]) |thread| thread.join();
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const session = @import("test_session.zig");

/// This model's own ports, so the epoll and io_uring session tests never collide.
const TEST_SERVER_PORT: u16 = 19097;
const TEST_DIALER_PORT: u16 = 19098;

test "zix webrtc: uring, run is refused off linux and every slot arms on it" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try session.testContext(std.testing.allocator);
    const config = session.testConfig(threaded.io(), std.testing.allocator, &tls, TEST_SERVER_PORT);

    if (comptime builtin.target.os.tag != .linux) {
        try std.testing.expectError(error.ZixDispatchModelUnsupported, runUring(session.echoHandler, config));

        return;
    }

    // Skip where io_uring is unavailable (old kernel, seccomp, a locked memory cap) or the port is
    // taken. The fold to epoll covers that case in the running server.
    var ring = Ring.init(config) catch {
        std.log.info("io_uring is unavailable on this kernel or the test port is taken, test skipped", .{});
        return;
    };
    defer ring.deinit();

    ring.prime();

    // Every slot found a submission entry, so none was left waiting for the next pass.
    try std.testing.expectEqual(@as(usize, 0), ring.pending_count);
    try std.testing.expectEqual(@as(usize, 0), ring.worker.peers.live);
}

test "zix webrtc: uring, a worker carries one whole session over a real socket" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const io = threaded.io();

    var tls = try session.testContext(std.testing.allocator);
    var config = session.testConfig(io, std.testing.allocator, &tls, TEST_SERVER_PORT);
    config.dispatch_model = .URING;

    var ring = Ring.init(config) catch {
        std.log.info("io_uring is unavailable on this kernel or the test port is taken, test skipped", .{});
        return;
    };
    defer ring.deinit();

    ring.prime();

    var driver = session.Driver.init(io, TEST_SERVER_PORT, TEST_DIALER_PORT) catch {
        std.log.info("the webrtc test driver could not open its socket, test skipped", .{});
        return;
    };
    defer driver.deinit();

    // Every pass is one submit_and_wait plus whatever it brought, so the session is driven a pass
    // at a time with the dialer answering in between.
    var rounds: usize = 0;
    while (rounds < session.MAX_ROUNDS and !driver.done()) : (rounds += 1) {
        try driver.send();

        ring.pass(session.echoHandler);

        try driver.receive();
    }

    try std.testing.expectEqualStrings(session.MESSAGE, driver.echo());
    try std.testing.expectEqual(@as(usize, 1), ring.worker.peers.live);
}

test "zix webrtc: uring, a pass with nothing to read ends on the timeout and drops nobody" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try session.testContext(std.testing.allocator);
    var config = session.testConfig(threaded.io(), std.testing.allocator, &tls, TEST_SERVER_PORT);
    config.tick_interval_ms = 10;

    var ring = Ring.init(config) catch {
        std.log.info("io_uring is unavailable on this kernel or the test port is taken, test skipped", .{});
        return;
    };
    defer ring.deinit();

    ring.prime();

    // Nobody has written to the socket, so the only completion this can get is the timeout.
    ring.pass(session.echoHandler);

    try std.testing.expect(!ring.timeout_armed);
    try std.testing.expectEqual(@as(usize, 0), ring.worker.peers.live);
}
