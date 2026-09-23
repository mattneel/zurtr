//! zix HTTP/3 EPOLL dispatch: one SO_REUSEPORT worker per core, the kernel load-balancing connections
//! by 4-tuple (multicore). Each worker waits in epoll_wait and drains the socket to EAGAIN on every
//! readiness wake, so a datagram is never left queued for the next cycle (the per-request latency tax
//! under load) and an idle worker stays off the CPU. Shared-nothing: its own socket, epoll fd, CID
//! table, and batches, so the hot path takes no lock. The recv / demux / respond code it drives lives in
//! the common module (common.zig), which the io_uring worker (uring.zig) imports too.

const std = @import("std");
const linux = std.os.linux;

const Config = @import("../config.zig");
const Http3ServerConfig = Config.Http3ServerConfig;
const core = @import("../core.zig");
const datagram = @import("../../datagram.zig");
const recovery = @import("../recovery.zig");
const common = @import("common.zig");
const reuseport = @import("../../../multiplexers/reuseport.zig");
const listen_report = @import("../../../multiplexers/listen_report.zig");

/// Max datagrams drained from the socket per epoll wake before returning to epoll_wait (the cap on one
/// drain-to-EAGAIN pass). A worker owns one UDP socket, so the only reason to leave a non-empty drain is
/// to re-enter epoll_wait for future timer work (idle eviction): EAGAIN normally ends the drain first.
/// Sized to absorb a large burst in a single wake.
const max_drain_per_wake: usize = 4096;

/// One HTTP/3 EPOLL worker: bind a per-core SO_REUSEPORT UDP socket, watch it with epoll, and on each
/// readiness wake drain the kernel receive queue to EAGAIN before sleeping again. Draining fully each
/// wake keeps a datagram from waiting a whole cycle (the per-request latency tax under load), and the
/// epoll_wait block keeps an idle worker off the CPU, so utilization tracks real load with no spin.
/// Shared-nothing: its own socket, epoll fd, CID table, and batches, so the hot path takes no lock. Pub
/// so the io_uring worker can fall back to it when io_uring is unavailable.
pub fn workerLoopEpoll(comptime handler: core.HandlerFn, config: Http3ServerConfig, worker_id: usize, steering: ?reuseport.Steering, report: *listen_report.Report) void {
    common.pinToCpu(worker_id);

    // Skew report at worker exit: requests this worker served (common.tl_requests_served).
    defer common.logSystem(config, .INFO, "epoll worker {d}: {d} requests served", .{ worker_id, common.tl_requests_served });

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

    const epfd_rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    if (std.posix.errno(epfd_rc) != .SUCCESS) {
        common.logSystem(config, .ERROR, "epoll_create1 failed", .{});
        return;
    }
    const epfd: i32 = @intCast(epfd_rc);
    defer _ = linux.close(epfd);

    var watch = linux.epoll_event{ .events = linux.EPOLL.IN, .data = .{ .fd = fd } };
    if (std.posix.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, fd, &watch)) != .SUCCESS) {
        common.logSystem(config, .ERROR, "epoll_ctl ADD failed", .{});
        return;
    }

    const table = config.allocator.create(common.ConnTable) catch return;
    defer config.allocator.destroy(table);
    table.* = .{};

    var pool = common.openReassemblyPool(config) catch return;
    defer pool.deinit(config.allocator);

    var wt_pool_handle = common.openWebtransportPool(config);
    defer if (wt_pool_handle) |*opened| opened.deinit(config.allocator);

    var rx = datagram.RecvBatch.init(config.allocator, config.recv_batch, config.max_recv_buf) catch return;
    defer rx.deinit();

    var tx = datagram.SendBatch.init(config.allocator, config.send_batch, common.sendBufBytes(config)) catch return;
    defer tx.deinit();

    tx.gso = config.gso_enabled and datagram.probeGso(fd);

    var stats = common.WorkerStats{ .worker_id = worker_id };
    common.registerWorkerStats(&stats);
    var events: [1]linux.epoll_event = undefined;
    var last_sweep_us: u64 = recovery.nowUs();

    while (true) {
        // Wake on readiness, or after the maintenance interval so loss recovery and idle eviction still
        // run during a lull with no inbound datagrams. With no connections there is no timed work, so
        // park indefinitely and stay off the CPU (an idle worker must not spin on a timer).
        const timeout_ms: i32 = if (table.count > 0) @intCast(common.maintenance_interval_us / 1000) else -1;

        if (comptime common.diag_enabled) stats.wait_enter_us = recovery.nowUs();
        const ready = linux.epoll_wait(epfd, &events, 1, timeout_ms);
        if (comptime common.diag_enabled) {
            stats.block_us += recovery.nowUs() -| stats.wait_enter_us;
            stats.wait_enter_us = 0;
        }
        if (std.posix.errno(ready) != .SUCCESS) continue; // EINTR and friends: re-arm the wait

        stats.wakes += 1;

        // Drain the receive queue to EAGAIN: handle every datagram queued this wake, not just one
        // recvmmsg batch, so nothing waits a whole cycle. recvNow is the non-blocking recvmmsg, 0 means
        // the queue is empty. The cap bounds one drain so a sustained flood still re-enters epoll_wait.
        var drained: usize = 0;
        while (drained < max_drain_per_wake) {
            const count = rx.recvNow(fd) catch break;
            if (count == 0) break;

            drained += count;
            stats.datagrams += count;
            for (0..count) |i| {
                const dg = rx.get(i);
                common.serveDatagram(handler, table, &pool, if (wt_pool_handle) |*opened| opened else null, dg, &tx, fd, config, &stats);
            }

            stats.packets += tx.count;
            if (tx.count > 0) stats.flushes += 1;
            tx.flush(fd) catch {};
        }

        // Time-driven maintenance: retransmit a timed-out (tail-lost) flight and evict a gone peer, at
        // most once per interval however often readiness wakes the worker. Flush what the resend queued.
        const now_us = recovery.nowUs();
        if (now_us -| last_sweep_us >= common.maintenance_interval_us) {
            common.sweepMaintenance(handler, table, if (wt_pool_handle) |*opened| opened else null, &tx, fd, config, now_us, &stats);
            tx.flush(fd) catch {};
            last_sweep_us = now_us;
        }

        stats.maybeDump();
    }
}

/// Run the HTTP/3 server with one SO_REUSEPORT epoll worker per core: each waits in epoll_wait and drains
/// the socket to EAGAIN per wake. The .URING sibling (uring.zig) runs the io_uring completion loop instead.
pub fn runEpoll(comptime handler: core.HandlerFn, config: Http3ServerConfig) !void {
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
        threads[i] = std.Thread.spawn(.{ .stack_size = config.worker_stack_size_bytes }, workerLoopEpoll, .{ handler, config, i, steering, &report }) catch |err| {
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
    common.logSystem(config, .INFO, "listening on {s}:{d} ({d} workers, SO_REUSEPORT + epoll)", .{ config.ip, config.port, want });

    for (threads[0..spawned]) |thread| thread.join();
}
