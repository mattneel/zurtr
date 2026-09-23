//! zix tcp .EPOLL dispatch model (Linux-only): shared-nothing epoll workers.
//! The per-connection .URING model folds here too: a blocking per-connection
//! handler cannot run on the single-threaded ring, so it is served by this
//! shared-nothing loop (the framed callback path runs natively on the ring).

const std = @import("std");
const Config = @import("../config.zig");
const TcpServerConfig = Config.TcpServerConfig;
const Logger = @import("../../logger/logger.zig").Logger;
const common = @import("common.zig");
const logSystem = common.logSystem;
const HandlerFn = common.HandlerFn;
const ConnTask = common.ConnTask;
const dispatchConn = common.dispatchConn;
const applyConnTimeout = common.applyConnTimeout;
const reuseport = @import("../../multiplexers/reuseport.zig");
const listen_report = @import("../../multiplexers/listen_report.zig");

/// Max epoll events drained per epoll_wait call. 512 lets a worker clear its
/// ready-fd set in one syscall at high connection counts.
const EPOLL_MAX_EVENTS: usize = 512;

// --------------------------------------------------------- //

const EpollWorkerCtx = struct {
    io: std.Io,
    ip: []const u8,
    port: u16,
    kernel_backlog: u31,
    recv_timeout_ms: u32,
    send_timeout_ms: u32,
    handler: HandlerFn,
    logger: ?*Logger,
    worker_id: usize,
    /// CBPF steering wiring (config.reuseport_cbpf). Null = steering off.
    steering: ?reuseport.Steering = null,
    /// Where this worker says whether its listener came up, shared with the whole group.
    report: *listen_report.Report,
};

/// EPOLL worker: owns one SO_REUSEPORT listener and one epoll instance.
/// The kernel load-balances connections across per-worker listeners with no
/// shared queue and no cross-thread fd handoff. Each accepted connection is
/// dispatched via io.async so the worker returns to epoll_wait immediately
/// and is not parked on the connection lifetime.
fn epollWorkerEntry(ctx: EpollWorkerCtx) void {
    const linux = std.os.linux;
    common.pinToCpu(ctx.worker_id);

    // Connections accepted by this worker (skew counter): the accept loop's unit
    // of work (each connection is then served by its own io.async task). Reported
    // through the system logger at worker exit so REUSEPORT skew is measurable.
    var conns_served: u64 = 0;
    defer if (ctx.logger) |lg| lg.system(.INFO, "tcp", "epoll worker {d}: {d} conns accepted", .{ ctx.worker_id, conns_served });

    // Bind under the order gate: REUSEPORT group index i = worker i,
    // so the cpu-mod-N steering lands on the worker pinned to that slot.
    var bind_turn = reuseport.BindTurn.begin(ctx.steering, ctx.worker_id);
    defer bind_turn.release();

    // Every exit between here and the event loop has to reach the group, or the workers that
    // did bind wait on one that is already gone.
    var slot = ctx.report.slot(ctx.io, error.ZixTcpWorkerSetupFailed);
    defer slot.close();

    const addr = std.Io.net.IpAddress.resolve(ctx.io, ctx.ip, ctx.port) catch |err| {
        slot.fail(err);

        return;
    };
    var srv = addr.listen(ctx.io, .{
        .mode = .stream,
        .protocol = .tcp,
        .reuse_address = true, // SO_REUSEADDR + SO_REUSEPORT on POSIX: each worker binds the same port
        .kernel_backlog = ctx.kernel_backlog,
    }) catch |err| {
        slot.fail(err);

        return;
    };
    defer srv.deinit(ctx.io);
    const listener_fd = srv.socket.handle;

    if (ctx.steering) |steer| _ = reuseport.attachCpuSteering(listener_fd, steer.group_size);
    bind_turn.release();

    // Serve only once every worker is up, so a group where one bind failed serves on none of them.
    slot.ok();
    if (ctx.report.awaitGroup(ctx.io) != null) return;

    const cur_flags = linux.fcntl(listener_fd, std.posix.F.GETFL, 0);
    const nonblock_bit: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
    _ = linux.fcntl(listener_fd, std.posix.F.SETFL, cur_flags | @as(usize, nonblock_bit));

    const epfd_rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    if (std.posix.errno(epfd_rc) != .SUCCESS) return;
    const epfd: std.posix.fd_t = @intCast(epfd_rc);
    defer _ = linux.close(epfd);

    var listener_event = linux.epoll_event{
        .events = linux.EPOLL.IN,
        .data = .{ .fd = listener_fd },
    };
    if (std.posix.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, listener_fd, &listener_event)) != .SUCCESS) return;

    var events: [EPOLL_MAX_EVENTS]linux.epoll_event = undefined;
    var epoll_timeout: i32 = -1;
    while (true) {
        const wait_result = linux.epoll_wait(epfd, &events, EPOLL_MAX_EVENTS, epoll_timeout);
        switch (std.posix.errno(wait_result)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return,
        }

        const n: usize = @intCast(wait_result);
        if (n == 0) {
            epoll_timeout = -1;
            continue;
        }

        for (events[0..n]) |ev| {
            if (ev.data.fd != listener_fd) continue;

            while (true) {
                const accept_result = linux.accept4(listener_fd, null, null, std.posix.SOCK.CLOEXEC);
                switch (std.posix.errno(accept_result)) {
                    .SUCCESS => {},
                    .AGAIN => break,
                    .INTR, .CONNABORTED => continue,
                    else => break,
                }

                const conn_fd: std.posix.fd_t = @intCast(accept_result);
                conns_served += 1;
                applyConnTimeout(conn_fd, ctx.recv_timeout_ms, ctx.send_timeout_ms);
                const stream: std.Io.net.Stream = .{ .socket = .{
                    .handle = conn_fd,
                    .address = .{ .ip4 = .unspecified(0) },
                } };

                _ = ctx.io.async(dispatchConn, .{ConnTask{
                    .stream = stream,
                    .io = ctx.io,
                    .handler = ctx.handler,
                    .logger = ctx.logger,
                }});
            }
        }

        epoll_timeout = 0;
    }
}

// --------------------------------------------------------- //
// EPOLL model

/// EPOLL dispatch: spawns shared-nothing workers, each with its own
/// SO_REUSEPORT listener and epoll instance. Linux-only.
///
/// Note:
/// - The kernel distributes connections across per-worker listeners with no
///   shared queue and no cross-thread fd handoff.
/// - Each accepted connection is dispatched via io.async: the worker returns
///   to epoll_wait immediately and is not parked on the connection lifetime.
/// - workers = 0 (default): one worker per available CPU (cgroup-allowed mask),
///   each pinned to its own CPU slot.
pub fn runEpoll(cfg: TcpServerConfig, handler: HandlerFn) !void {
    const cpu = common.getAvailableCpuCount();
    const worker_count = if (cfg.workers == 0) cpu else cfg.workers;

    const workers = try std.heap.smp_allocator.alloc(std.Thread, worker_count);
    defer std.heap.smp_allocator.free(workers);

    // CBPF steering: one shared bind-order gate, alive until join().
    var bind_gate = reuseport.BindOrderGate{};
    const steering: ?reuseport.Steering = if (cfg.reuseport_cbpf) .{ .gate = &bind_gate, .group_size = worker_count } else null;

    // What every worker says about its own listener, so a bind that fails inside a worker
    // thread reaches this frame instead of ending that thread and nothing else.
    var report = listen_report.Report.init(worker_count);

    for (workers, 0..) |*thread, worker_id|
        thread.* = std.Thread.spawn(
            .{ .stack_size = cfg.worker_stack_size_bytes },
            epollWorkerEntry,
            .{EpollWorkerCtx{
                .io = cfg.io,
                .ip = cfg.ip,
                .port = cfg.port,
                .kernel_backlog = cfg.kernel_backlog,
                .recv_timeout_ms = cfg.recv_timeout_ms,
                .send_timeout_ms = cfg.send_timeout_ms,
                .handler = handler,
                .logger = cfg.logger,
                .worker_id = worker_id,
                .steering = steering,
                .report = &report,
            }},
        ) catch |err| {
            logSystem(cfg, .ERROR, "could not spawn worker {d} of {d} ({s})", .{ worker_id, worker_count, @errorName(err) });
            report.abandon(cfg.io, worker_count - worker_id, err);

            for (workers[0..worker_id]) |spawned| spawned.join();

            return error.ZixTcpListenFailed;
        };

    if (report.awaitGroup(cfg.io)) |err| {
        logSystem(cfg, .ERROR, "not listening on {s}:{d}: {d} of {d} workers could not bind ({s})", .{ cfg.ip, cfg.port, report.failures(), worker_count, @errorName(err) });

        for (workers) |thread| thread.join();

        return error.ZixTcpListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is nothing
    // to announce: the old line claimed a listener that may never have come up.
    logSystem(cfg, .INFO, "listening on {s}:{d} (epoll/{d}, shared-nothing)", .{ cfg.ip, cfg.port, worker_count });

    for (workers) |thread| thread.join();
}
