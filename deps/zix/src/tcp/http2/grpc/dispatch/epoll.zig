//! zix grpc .EPOLL dispatch model (Linux-only): multiplexed shared-nothing, one
//! SO_REUSEPORT listener + epoll + ConnTable per worker. The kernel load-balances
//! new connections across the per-worker listeners, so a connection is accepted
//! and driven to completion by a single worker with no cross-thread state.

const std = @import("std");
const core = @import("../core.zig");
const mux = @import("../mux.zig");
const GrpcServerConfig = @import("../config.zig").GrpcServerConfig;
const common = @import("common.zig");
const logSystem = common.logSystem;
const effectiveCacheEntries = common.effectiveCacheEntries;
const setNoDelay = common.setNoDelay;
const MAX_FD = common.MAX_FD;
const rcache = @import("../../../../utils/response_cache.zig");
const slab = @import("../../../../multiplexers/slab.zig");
const tls_mux = @import("../tls_mux.zig");
const tls_conn = @import("../../../../multiplexers/tls_conn.zig");
const Tls = @import("../../../../tls/Tls.zig");
const reuseport = @import("../../../../multiplexers/reuseport.zig");
const listen_report = @import("../../../../multiplexers/listen_report.zig");

/// Max epoll events drained per epoll_wait call. 512 lets a worker clear its
/// ready-fd set in one syscall at high connection counts.
const EPOLL_MAX_EVENTS: usize = 512;

/// Private per-worker fd to GrpcMuxConn map. Not shared between workers.
const GrpcConnTable = struct {
    slots: []?*mux.GrpcMuxConn,

    fn init() !GrpcConnTable {
        // mmap'd pointer slots: kernel-zeroed (zero == null) and demand-paged, so
        // they cost no physical memory until used. See multiplexers/slab.
        const slots = try slab.mapZeroedSlots(?*mux.GrpcMuxConn, MAX_FD);

        return .{ .slots = slots };
    }

    fn deinit(self: *GrpcConnTable) void {
        for (self.slots) |maybe_conn| {
            if (maybe_conn) |conn| conn.deinit();
        }

        slab.unmapSlots(self.slots);
    }

    fn get(self: *GrpcConnTable, fd: std.posix.fd_t) ?*mux.GrpcMuxConn {
        const idx: usize = @intCast(fd);
        if (idx >= self.slots.len) return null;

        return self.slots[idx];
    }

    fn alloc(self: *GrpcConnTable, fd: std.posix.fd_t, opts: core.GrpcServeOpts, io: std.Io) ?*mux.GrpcMuxConn {
        const idx: usize = @intCast(fd);
        if (idx >= self.slots.len) return null;

        const conn = mux.GrpcMuxConn.init(fd, opts, io) orelse return null;
        self.slots[idx] = conn;

        return conn;
    }

    fn free(self: *GrpcConnTable, fd: std.posix.fd_t) void {
        const idx: usize = @intCast(fd);
        if (idx >= self.slots.len) return;

        if (self.slots[idx]) |conn| {
            conn.deinit();
            self.slots[idx] = null;
        }
    }
};

/// Accept every pending connection on listener_fd and register each in epfd. Level-triggered,
/// so draining to EAGAIN guarantees no accept is missed.
fn acceptAll(table: *GrpcConnTable, epfd: std.posix.fd_t, listener_fd: std.posix.fd_t, opts: core.GrpcServeOpts, busy_poll_us: u32, io: std.Io) void {
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
        common.setBusyPoll(conn_fd, busy_poll_us);
        if (table.alloc(conn_fd, opts, io) == null) {
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

// --------------------------------------------------------- //

const MuxWorkerCtx = struct {
    io: std.Io,
    ip: []const u8,
    port: u16,
    kernel_backlog: u31,
    opts: core.GrpcServeOpts,
    worker_id: usize,
    busy_poll_us: u32,
    /// Dual-listener TLS side (config.tls + config.tls_port). Inactive when null / 0.
    tls_ctx: ?*Tls.Context = null,
    tls_port: u16 = 0,
    /// CBPF steering wiring (config.reuseport_cbpf). Null = steering off.
    steering: ?reuseport.Steering = null,
    /// Where this worker says whether its listeners came up, shared with the whole group.
    report: *listen_report.Report,
};

/// Build a concrete epoll mux worker entry with the Router type baked in at compile
/// time. One multiplexed worker: a private SO_REUSEPORT listener + epoll instance
/// driving many non-blocking connections through the resumable h2 state machine.
fn epollMuxWorkerFn(comptime RouterType: type) fn (MuxWorkerCtx) void {
    return struct {
        /// One event on a dual-listener TLS connection: mirrors the tls_mux worker loop body
        /// (flush staged ciphertext on EPOLLOUT, feed decrypted bytes on EPOLLIN, re-arm or reap).
        fn serveTlsEvent(tls_conns: *tls_mux.ConnTable, epfd: std.posix.fd_t, ev: std.os.linux.epoll_event) void {
            const linux = std.os.linux;
            const fd: std.posix.fd_t = @intCast(ev.data.u64 & (tls_conn.tls_event_tag - 1));

            const conn = tls_conns.get(fd) orelse return;
            var keep = true;

            if ((ev.events & (linux.EPOLL.HUP | linux.EPOLL.ERR)) != 0) {
                keep = false;
            } else {
                if ((ev.events & linux.EPOLL.OUT) != 0) keep = conn.transport.onWritable(epfd);
                if (keep and (ev.events & linux.EPOLL.IN) != 0) keep = tls_mux.onReadable(RouterType, conn);
                if (keep and conn.transport.want_out) tls_conn.armOut(epfd, fd, conn.transport.ep_data, true);
                if (keep and conn.transport.wclose and !conn.transport.want_out) keep = false;
            }

            if (!keep) {
                _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_DEL, fd, null);
                tls_conns.drop(fd);
                _ = linux.close(fd);
            }
        }

        fn run(ctx: MuxWorkerCtx) void {
            const linux = std.os.linux;

            // Pin to one cgroup-allowed CPU so workers never oversubscribe a core under a limited cpuset.
            common.pinToCpu(ctx.worker_id);

            // Bind under the order gate: REUSEPORT group index i = worker i,
            // so the cpu-mod-N steering lands on the worker pinned to that slot.
            var bind_turn = reuseport.BindTurn.begin(ctx.steering, ctx.worker_id);
            defer bind_turn.release();

            // Every exit between here and the event loop has to reach the group, or the
            // workers that did bind wait on one that is already gone.
            var slot = ctx.report.slot(ctx.io, error.ZixGrpcWorkerSetupFailed);
            defer slot.close();

            const addr = std.Io.net.IpAddress.resolve(ctx.io, ctx.ip, ctx.port) catch |err| {
                slot.fail(err);

                return;
            };
            var srv = addr.listen(ctx.io, .{
                .reuse_address = true, // SO_REUSEADDR + SO_REUSEPORT: the kernel balances accepts across workers
                .kernel_backlog = ctx.kernel_backlog,
            }) catch |err| {
                slot.fail(err);

                return;
            };
            defer srv.deinit(ctx.io);
            const listener_fd = srv.socket.handle;

            common.setNonBlock(listener_fd);
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

            var table = GrpcConnTable.init() catch return;
            defer table.deinit();

            // Dual-listener TLS side (config.tls + config.tls_port): a second listen fd whose
            // connections terminate TLS in this same loop via the tls_mux connection machinery.
            // Everything below is mapped only when active, so a cleartext-only worker sees zero
            // layout change on its hot structures.
            const tls_ctx: ?*Tls.Context = if (ctx.tls_port != 0) ctx.tls_ctx else null;
            var tls_listener_fd: std.posix.fd_t = -1;
            var tls_srv: std.Io.net.Server = undefined;
            var tls_table: ?tls_mux.ConnTable = null;
            defer if (tls_table) |*tls_conns| tls_conns.deinit();
            defer if (tls_ctx != null and tls_listener_fd != -1) tls_srv.deinit(ctx.io);

            if (tls_ctx != null) {
                const tls_addr = std.Io.net.IpAddress.resolve(ctx.io, ctx.ip, ctx.tls_port) catch |err| {
                    slot.fail(err);

                    return;
                };
                tls_srv = tls_addr.listen(ctx.io, .{
                    .reuse_address = true,
                    .kernel_backlog = ctx.kernel_backlog,
                }) catch |err| {
                    slot.fail(err);

                    return;
                };
                tls_listener_fd = tls_srv.socket.handle;
                common.setNonBlock(tls_listener_fd);
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

            // Serve only once every worker is up, so a group where one bind failed serves on none
            // of them and the caller gets one honest failure.
            slot.ok();
            if (ctx.report.awaitGroup(ctx.io) != null) return;

            // Per-worker unary response cache: lock-free by ownership, never shared.
            var response_cache: rcache.ResponseCache = undefined;
            var cache_on = false;
            if (ctx.opts.response_cache) {
                if (rcache.ResponseCache.init(std.heap.smp_allocator, .{
                    .max_entries = effectiveCacheEntries(ctx.opts),
                    .max_value_bytes = ctx.opts.cache_max_value_bytes,
                })) |built| {
                    response_cache = built;
                    cache_on = true;
                    core.setCache(&response_cache, ctx.opts.cache_ttl_ms);
                } else |_| {
                    cache_on = false;
                }
            }
            defer if (cache_on) {
                core.setCache(null, 0);
                response_cache.deinit();
            };

            var events: [EPOLL_MAX_EVENTS]linux.epoll_event = undefined;
            var epoll_timeout: i32 = -1;
            while (true) {
                const wait_rc = linux.epoll_wait(epfd, &events, EPOLL_MAX_EVENTS, epoll_timeout);
                switch (std.posix.errno(wait_rc)) {
                    .SUCCESS => {},
                    .INTR => continue,
                    else => return,
                }

                const n: usize = @intCast(wait_rc);
                if (n == 0) {
                    epoll_timeout = -1;
                    continue;
                }

                for (events[0..n]) |ev| {
                    if (ev.data.fd == listener_fd) {
                        acceptAll(&table, epfd, listener_fd, ctx.opts, ctx.busy_poll_us, ctx.io);
                        continue;
                    }

                    if (tls_ctx) |tls_context| {
                        if (ev.data.fd == tls_listener_fd) {
                            tls_mux.acceptAll(&tls_table.?, epfd, tls_listener_fd, tls_context, ctx.opts, tls_conn.tls_event_tag, ctx.io);
                            continue;
                        }
                        if (ev.data.u64 & tls_conn.tls_event_tag != 0) {
                            serveTlsEvent(&tls_table.?, epfd, ev);
                            continue;
                        }
                    }

                    const conn = table.get(ev.data.fd) orelse continue;
                    const outcome = if ((ev.events & (linux.EPOLL.HUP | linux.EPOLL.ERR)) != 0)
                        mux.GrpcConnOutcome.close
                    else
                        mux.grpcMuxOnReadable(RouterType, conn);

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

// --------------------------------------------------------- //
// EPOLL model

/// EPOLL dispatch (Linux-only): shared-nothing, one SO_REUSEPORT listener + epoll per
/// worker. Each worker multiplexes many non-blocking connections through a resumable h2
/// state machine, dispatches inline, and flushes one coalesced write per readable event.
///
/// Note:
/// - worker_count = workers (0 = cpu count). A streaming handler runs on the event
///   loop, so it must stay bounded (it blocks the worker's other connections while running).
pub fn runEpoll(comptime RouterType: type, cfg: GrpcServerConfig) !void {
    const io = cfg.io;
    // cgroup-aware so a limited cpuset defaults to one worker per available CPU, not one per machine core.
    const cpu = common.getAvailableCpuCount();
    const worker_count = if (cfg.workers == 0) cpu else cfg.workers;
    const opts = common.serveOptsWithCache(cfg);

    const workers = try std.heap.smp_allocator.alloc(std.Thread, worker_count);
    defer std.heap.smp_allocator.free(workers);

    // CBPF steering: one shared bind-order gate, alive until join().
    var bind_gate = reuseport.BindOrderGate{};
    const steering: ?reuseport.Steering = if (cfg.reuseport_cbpf) .{ .gate = &bind_gate, .group_size = worker_count } else null;

    // What every worker says about its own listeners, so a bind that fails inside a worker
    // thread reaches this frame instead of ending that thread and nothing else.
    var report = listen_report.Report.init(worker_count);

    const worker_fn = epollMuxWorkerFn(RouterType);
    for (workers, 0..) |*thread, idx|
        thread.* = std.Thread.spawn(
            .{ .stack_size = cfg.worker_stack_size_bytes },
            worker_fn,
            .{MuxWorkerCtx{
                .io = io,
                .ip = cfg.ip,
                .port = cfg.port,
                .kernel_backlog = cfg.kernel_backlog,
                .opts = opts,
                .worker_id = idx,
                .busy_poll_us = cfg.busy_poll_us,
                .tls_ctx = cfg.tls,
                .tls_port = cfg.tls_port,
                .steering = steering,
                .report = &report,
            }},
        ) catch |err| {
            logSystem(cfg, .ERROR, "could not spawn worker {d} of {d} ({s})", .{ idx, worker_count, @errorName(err) });
            report.abandon(io, worker_count - idx, err);

            for (workers[0..idx]) |spawned| spawned.join();

            return error.ZixGrpcListenFailed;
        };

    if (report.awaitGroup(io)) |err| {
        logSystem(cfg, .ERROR, "not listening on {s}:{d}: {d} of {d} workers could not bind ({s})", .{ cfg.ip, cfg.port, report.failures(), worker_count, @errorName(err) });

        for (workers) |thread| thread.join();

        return error.ZixGrpcListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is
    // nothing to announce: the old line claimed a listener that may never have come up.
    logSystem(cfg, .INFO, "listening on {s}:{d} (epoll-mux/{d})", .{ cfg.ip, cfg.port, worker_count });
    if (cfg.tls != null and cfg.tls_port != 0)
        logSystem(cfg, .INFO, "dual listener: grpc TLS on {s}:{d} (same workers)", .{ cfg.ip, cfg.tls_port });

    for (workers) |thread| thread.join();
}
