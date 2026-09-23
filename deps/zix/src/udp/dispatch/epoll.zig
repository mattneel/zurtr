//! zix udp raw-bytes EPOLL dispatch (ADR-049 / ADR-050): one SO_REUSEPORT worker per CPU, each waiting
//! in epoll_wait and draining the socket to EAGAIN on every readiness wake before sleeping again.
//! Shared-nothing: its own socket, epoll fd, and send / recv batches, so the hot path takes no lock. The
//! per-datagram serve and the worker helpers live in the common module (common.zig).

const std = @import("std");
const linux = std.os.linux;

const Config = @import("../config.zig");
const UdpServerConfig = Config.UdpServerConfig;
const core = @import("../core.zig");
const datagram = @import("../datagram.zig");
const common = @import("common.zig");
const reuseport = @import("../../multiplexers/reuseport.zig");
const listen_report = @import("../../multiplexers/listen_report.zig");

/// Max datagrams drained per epoll wake before returning to epoll_wait, bounding one drain-to-EAGAIN
/// pass so a sustained flood still re-enters the wait. EAGAIN normally ends the drain first.
const max_drain_per_wake: usize = 4096;

/// One raw-UDP EPOLL worker: bind a per-core SO_REUSEPORT socket, watch it with epoll, and drain the
/// receive queue to EAGAIN on each readiness wake. Pub so the io_uring worker can fall back to it when
/// io_uring is unavailable.
pub fn workerLoopEpoll(comptime handler: core.HandlerFn, config: UdpServerConfig, worker_id: usize, steering: ?reuseport.Steering, report: *listen_report.Report) void {
    common.pinToCpu(worker_id);

    // Datagrams served by this worker (skew counter). Single-owner plain increment
    // (no contention), reported through the system logger at worker exit so
    // REUSEPORT skew across workers is measurable.
    var datagrams_served: u64 = 0;
    defer common.logSystem(config, .INFO, "epoll worker {d}: {d} datagrams served", .{ worker_id, datagrams_served });

    // Bind under the order gate: REUSEPORT group index i = worker i,
    // so the cpu-mod-N steering lands on the worker pinned to that slot.
    var bind_turn = reuseport.BindTurn.begin(steering, worker_id);
    defer bind_turn.release();

    // Every exit between here and the event loop has to reach the group, or the workers that did
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

    const epfd_rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    if (std.posix.errno(epfd_rc) != .SUCCESS) {
        common.logSystem(config, .ERROR, "raw epoll_create1 failed", .{});
        return;
    }
    const epfd: i32 = @intCast(epfd_rc);
    defer _ = linux.close(epfd);

    var watch = linux.epoll_event{ .events = linux.EPOLL.IN, .data = .{ .fd = fd } };
    if (std.posix.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, fd, &watch)) != .SUCCESS) {
        common.logSystem(config, .ERROR, "raw epoll_ctl ADD failed", .{});
        return;
    }

    var rx = datagram.RecvBatch.init(config.allocator, config.recv_batch, config.max_recv_buf) catch return;
    defer rx.deinit();

    var tx = datagram.SendBatch.init(config.allocator, config.send_batch, config.send_batch * config.max_recv_buf) catch return;
    defer tx.deinit();

    tx.gso = config.gso_enabled and datagram.probeGso(fd);

    var events: [1]linux.epoll_event = undefined;

    while (true) {
        const ready = linux.epoll_wait(epfd, &events, 1, -1);
        if (std.posix.errno(ready) != .SUCCESS) continue; // EINTR and friends: re-arm the wait

        // Drain the receive queue to EAGAIN so nothing waits a whole cycle. recvNow is the non-blocking
        // recvmmsg, 0 means empty. The cap bounds one drain so a sustained flood still re-enters the wait.
        var drained: usize = 0;
        while (drained < max_drain_per_wake) {
            const count = rx.recvNow(fd) catch break;
            if (count == 0) break;

            drained += count;
            datagrams_served += count;
            for (0..count) |i| common.serveDatagram(handler, rx.get(i), &tx, fd);

            tx.flush(fd) catch tx.reset();
        }
    }
}

/// Run the raw server with one SO_REUSEPORT epoll worker per CPU. Linux-only: off Linux this returns
/// error.ZixDispatchModelUnsupported instead of downgrading (ADR-065), the caller picks .ASYNC there.
pub fn runEpoll(comptime handler: core.HandlerFn, config: UdpServerConfig) !void {
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
        threads[i] = std.Thread.spawn(.{ .stack_size = config.worker_stack_size_bytes }, workerLoopEpoll, .{ handler, config, i, steering, &report }) catch |err| {
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
    common.logSystem(config, .INFO, "raw listening on {s}:{d} ({d} workers, SO_REUSEPORT + epoll)", .{ config.ip, config.port, want });

    for (threads[0..spawned]) |thread| thread.join();
}
