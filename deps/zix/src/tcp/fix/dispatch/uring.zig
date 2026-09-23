//! zix fix .URING dispatch model (Linux-only): shared-nothing io_uring ring per
//! worker (ADR-037 Phase 4 extension). recv into the connection buffer, run the
//! resumable FIX session processor (core.processFixRing) with replies staged
//! through the sink, and submit one coalesced send per readable batch.
//! Half-duplex per connection.

const std = @import("std");
const core = @import("../core.zig");
const FixServerConfig = @import("../config.zig").FixServerConfig;
const FixServeOpts = core.FixServeOpts;
const common = @import("common.zig");
const reuseport = @import("../../../multiplexers/reuseport.zig");
const listen_report = @import("../../../multiplexers/listen_report.zig");
const epoll_model = @import("epoll.zig");
const logSystem = common.logSystem;
const uring = @import("../../../multiplexers/ring.zig");
const slab = @import("../../../multiplexers/slab.zig");
const IoUring = std.os.linux.IoUring;

// --------------------------------------------------------- //

/// Per-connection recv accumulator. FIX messages are small, so 64 KiB holds a
/// deep batch of pipelined messages with headroom.
const FIX_RING_RECV_BUF: usize = 64 * 1024;
/// SQ entries per worker ring.
const URING_ENTRIES: u16 = 4096;
/// CQ entries per worker ring (multishot completion headroom).
const URING_CQ_ENTRIES: u32 = 16 * 1024;
/// Max CQEs drained per loop pass.
const URING_CQE_BATCH: usize = 512;
/// Per-connection staged-response buffer.
const URING_SEND_BUF_SIZE: usize = 64 * 1024;

/// io_uring SQPOLL kernel-thread idle before it sleeps, in milliseconds. Inert
/// unless IORING_SETUP_SQPOLL is set (it is not here), kept for when it is.
const URING_SQ_THREAD_IDLE_MS: u32 = 1000;

/// Initialize a worker ring with the single-issuer fast-path flags, falling back
/// to a flagless ring when the kernel does not support them.
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

fn ringSetNoDelay(fd: std.posix.fd_t) void {
    std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&@as(c_int, 1))) catch {};
}

/// Per-connection ring state. buf accumulates FIX bytes until whole messages are
/// present, send_buf holds the coalesced reply while a send is in flight, gen
/// guards against fd reuse, fix_state is the resumable FIX session.
const UringFixConn = struct {
    fd: std.posix.fd_t,
    gen: u24,
    buf: []u8,
    filled: usize,
    send_buf: []u8,
    staged: usize,
    inflight: usize,
    closing: bool,
    fix_state: core.FixRingState = .{},
};

const UringFixCtx = struct {
    io: std.Io,
    ip: []const u8,
    port: u16,
    kernel_backlog: u31,
    comp_id: []const u8,
    opts: FixServeOpts,
    send_buf_size: usize,
    max_conns: usize,
    worker_id: usize,
    /// CBPF steering wiring (config.reuseport_cbpf). Null = steering off.
    steering: ?reuseport.Steering = null,
    /// Where this worker says whether its listener came up, shared with the whole group.
    report: *listen_report.Report,
};

fn uringFixWorker(ctx: UringFixCtx) void {
    const Worker = struct {
        ring: IoUring,
        slots: []?*UringFixConn,
        listener_fd: std.posix.fd_t,
        gen_counter: u24,
        comp_id: []const u8,
        opts: FixServeOpts,
        hb_ms: u32,
        hb_timespec: lx.kernel_timespec,
        send_buf_size: usize = URING_SEND_BUF_SIZE,
        /// Io backend, carried for the FixContext built at each processFixRing dispatch.
        io: std.Io,

        const W = @This();
        const allocator = std.heap.smp_allocator;
        const lx = std.os.linux;

        fn deinit(worker: *W) void {
            for (worker.slots) |maybe_conn| {
                if (maybe_conn) |conn| {
                    _ = lx.close(conn.fd);
                    allocator.free(conn.buf);
                    allocator.free(conn.send_buf);
                    allocator.destroy(conn);
                }
            }

            slab.unmapSlots(worker.slots);
            worker.ring.deinit();
        }

        fn getSqe(worker: *W) ?*lx.io_uring_sqe {
            return worker.ring.get_sqe() catch {
                _ = worker.ring.submit() catch return null;

                return worker.ring.get_sqe() catch null;
            };
        }

        fn lookup(worker: *W, decoded: uring.Decoded) ?*UringFixConn {
            const idx: usize = @intCast(decoded.fd);
            if (idx >= worker.slots.len) return null;

            const conn = worker.slots[idx] orelse return null;
            if (conn.gen != decoded.gen) return null;

            return conn;
        }

        fn destroyConn(worker: *W, conn: *UringFixConn) void {
            worker.slots[@intCast(conn.fd)] = null;

            allocator.free(conn.buf);
            allocator.free(conn.send_buf);
            allocator.destroy(conn);
        }

        fn finishClose(worker: *W, conn: *UringFixConn) void {
            _ = lx.close(conn.fd);
            worker.destroyConn(conn);
        }

        fn beginClose(worker: *W, conn: *UringFixConn) void {
            conn.closing = true;
            if (conn.inflight > 0) return;

            if (conn.staged > 0) {
                worker.submitSend(conn);
                return;
            }

            worker.finishClose(conn);
        }

        fn armAccept(worker: *W) void {
            const sqe = worker.getSqe() orelse return;
            sqe.prep_multishot_accept(worker.listener_fd, null, null, 0);
            sqe.user_data = uring.packUserData(.accept, 0, worker.listener_fd);
        }

        fn armRecv(worker: *W, conn: *UringFixConn) void {
            if (conn.filled >= conn.buf.len) {
                worker.beginClose(conn);
                return;
            }

            const sqe = worker.getSqe() orelse {
                worker.beginClose(conn);
                return;
            };
            sqe.prep_recv(conn.fd, conn.buf[conn.filled..], 0);
            sqe.user_data = uring.packUserData(.recv, conn.gen, conn.fd);
        }

        fn submitSend(worker: *W, conn: *UringFixConn) void {
            const sqe = worker.getSqe() orelse {
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

            ringSetNoDelay(conn_fd);

            const conn = allocator.create(UringFixConn) catch {
                _ = lx.close(conn_fd);
                return;
            };
            const buf = allocator.alloc(u8, FIX_RING_RECV_BUF) catch {
                allocator.destroy(conn);
                _ = lx.close(conn_fd);
                return;
            };
            const send_buf = allocator.alloc(u8, worker.send_buf_size) catch {
                allocator.free(buf);
                allocator.destroy(conn);
                _ = lx.close(conn_fd);
                return;
            };

            worker.gen_counter +%= 1;
            conn.* = .{
                .fd = conn_fd,
                .gen = worker.gen_counter,
                .buf = buf,
                .filled = 0,
                .send_buf = send_buf,
                .staged = 0,
                .inflight = 0,
                .closing = false,
                .fix_state = .{},
            };
            worker.slots[idx] = conn;

            worker.armRecv(conn);
        }

        fn handleRecv(worker: *W, cqe: lx.io_uring_cqe, decoded: uring.Decoded) void {
            const conn = worker.lookup(decoded) orelse return;

            if (cqe.res <= 0) {
                worker.beginClose(conn);
                return;
            }

            conn.filled += @intCast(cqe.res);
            conn.fix_state.last_activity_ms = core.monotonicMs();
            conn.fix_state.sent_test_request = false;

            const close = worker.dispatch(conn);

            if (conn.staged > 0) {
                worker.submitSend(conn);
                if (close) conn.closing = true;

                return;
            }

            if (close) {
                worker.beginClose(conn);
                return;
            }

            worker.armRecv(conn);
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

        /// Install the sink, run the resumable FIX processor over conn.buf, then
        /// compact the unconsumed tail. Returns true when the session must close.
        fn dispatch(worker: *W, conn: *UringFixConn) bool {
            const fd = conn.fd;

            var sink = core.RespSink{ .fd = fd, .buf = conn.send_buf };
            core.tl_resp_sink = &sink;
            defer core.tl_resp_sink = null;

            const result = core.processFixRing(&conn.fix_state, worker.comp_id, worker.opts, conn.buf[0..conn.filled], fd, worker.io);

            if (result.consumed >= conn.filled) {
                conn.filled = 0;
            } else if (result.consumed > 0) {
                std.mem.copyForwards(u8, conn.buf[0 .. conn.filled - result.consumed], conn.buf[result.consumed..conn.filled]);
                conn.filled -= result.consumed;
            }

            conn.staged = sink.len;

            return result.close or sink.failed;
        }

        fn armTimeout(worker: *W) void {
            if (worker.hb_ms == 0) return;

            const sqe = worker.getSqe() orelse return;
            sqe.prep_timeout(&worker.hb_timespec, 0, 0);
            sqe.user_data = uring.packUserData(.timeout, 0, worker.listener_fd);
        }

        /// Periodic heartbeat tick: send a TestRequest to every idle logged-in
        /// session, reap one that stayed silent through a Logout, then re-arm. The
        /// reaped connection has only an idle recv in flight (no buffered data), so
        /// closing it is safe: the stale recv completion is dropped by the gen tag.
        fn handleTimeout(worker: *W, cqe: lx.io_uring_cqe) void {
            _ = cqe;

            const now = core.monotonicMs();
            for (worker.slots) |maybe_conn| {
                if (maybe_conn) |conn| {
                    if (core.fixHeartbeatTick(&conn.fix_state, worker.comp_id, conn.fd, now, worker.hb_ms)) {
                        worker.finishClose(conn);
                    }
                }
            }

            worker.armTimeout();
        }

        fn run(worker: *W) void {
            worker.armAccept();
            worker.armTimeout();

            var cqes: [URING_CQE_BATCH]lx.io_uring_cqe = undefined;
            while (true) {
                _ = worker.ring.submit_and_wait(1) catch |err| switch (err) {
                    error.SignalInterrupt => continue,
                    else => return,
                };

                const count = worker.ring.copy_cqes(&cqes, 0) catch return;
                for (cqes[0..count]) |cqe| {
                    const decoded = uring.unpackUserData(cqe.user_data);
                    switch (decoded.op) {
                        .accept => worker.handleAccept(cqe),
                        .recv => worker.handleRecv(cqe, decoded),
                        .send => worker.handleSend(cqe, decoded),
                        .timeout => worker.handleTimeout(cqe),
                        .close => {},
                        .tls_accept, .tls_recv, .tls_send, .external => {},
                    }
                }
            }
        }
    };

    common.pinToCpu(ctx.worker_id);

    // Bind under the order gate: REUSEPORT group index i = worker i,
    // so the cpu-mod-N steering lands on the worker pinned to that slot.
    var bind_turn = reuseport.BindTurn.begin(ctx.steering, ctx.worker_id);
    defer bind_turn.release();

    // Every exit between here and the ring loop has to reach the group, or the workers that did
    // bind wait on one that is already gone.
    var slot = ctx.report.slot(ctx.io, error.ZixFixWorkerSetupFailed);
    defer slot.close();

    const addr = std.Io.net.IpAddress.resolve(ctx.io, ctx.ip, ctx.port) catch |err| {
        slot.fail(err);

        return;
    };
    var net_server = addr.listen(ctx.io, .{
        .mode = .stream,
        .reuse_address = true,
        .kernel_backlog = ctx.kernel_backlog,
    }) catch |err| {
        slot.fail(err);

        return;
    };
    defer net_server.deinit(ctx.io);
    const listener_fd = net_server.socket.handle;

    if (ctx.steering) |steer| _ = reuseport.attachCpuSteering(listener_fd, steer.group_size);
    bind_turn.release();

    // Serve only once every worker is up, so a group where one bind failed serves on none of them
    // and the caller gets one honest failure.
    slot.ok();
    if (ctx.report.awaitGroup(ctx.io) != null) return;

    const slots = slab.mapZeroedSlots(?*UringFixConn, ctx.max_conns) catch return;

    const hb_ms = ctx.opts.heartbeat_timeout_ms;
    var worker = Worker{
        .ring = undefined,
        .slots = slots,
        .listener_fd = listener_fd,
        .gen_counter = 0,
        .comp_id = ctx.comp_id,
        .opts = ctx.opts,
        .hb_ms = hb_ms,
        .hb_timespec = .{ .sec = @intCast(hb_ms / 1000), .nsec = @intCast((hb_ms % 1000) * 1_000_000) },
        .send_buf_size = ctx.send_buf_size,
        .io = ctx.io,
    };
    worker.ring = initUringRing() catch return;
    defer worker.deinit();

    worker.run();

    if (ctx.opts.logger) |lg| lg.system(.INFO, "fix", "uring worker {d}: {d} messages served", .{ ctx.worker_id, core.tl_messages_served });
}

// --------------------------------------------------------- //
// URING model

pub fn runUring(cfg: FixServerConfig, conn_opts: FixServeOpts) !void {
    // Runtime probe: io_uring can be unavailable on this host (seccomp/sandbox,
    // RLIMIT_MEMLOCK, or an old kernel). Without this, every worker would fail
    // setup, return, and the server would vanish right after binding (a confusing
    // ServerStartTimeout downstream). Fall back to the EPOLL shared-nothing loop.
    var probe = initUringRing() catch |err| {
        logSystem(cfg, .WARN, "io_uring unavailable ({s}): not suited to this environment (commonly RLIMIT_MEMLOCK, the ulimit -l cap, too low for the ring size). Falling back to EPOLL.", .{@errorName(err)});

        return epoll_model.runEpoll(cfg, conn_opts);
    };
    probe.deinit();

    const cpu = common.getAvailableCpuCount();
    const worker_count = if (cfg.workers == 0) cpu else cfg.workers;

    const workers = try std.heap.smp_allocator.alloc(std.Thread, worker_count);
    defer std.heap.smp_allocator.free(workers);

    // CBPF steering: one shared bind-order gate, alive until join().
    var bind_gate = reuseport.BindOrderGate{};
    const steering: ?reuseport.Steering = if (cfg.reuseport_cbpf) .{ .gate = &bind_gate, .group_size = worker_count } else null;

    // What every worker says about its own listener, so a bind that fails inside a worker thread
    // reaches this frame instead of ending that thread and nothing else.
    var report = listen_report.Report.init(worker_count);

    for (workers, 0..) |*thread, worker_id|
        thread.* = std.Thread.spawn(
            .{ .stack_size = cfg.worker_stack_size_bytes },
            uringFixWorker,
            .{UringFixCtx{
                .io = cfg.io,
                .ip = cfg.ip,
                .port = cfg.port,
                .kernel_backlog = cfg.kernel_backlog,
                .comp_id = cfg.comp_id,
                .opts = conn_opts,
                .send_buf_size = cfg.uring_send_buf_size,
                .max_conns = cfg.uring_max_conns_per_worker,
                .worker_id = worker_id,
                .steering = steering,
                .report = &report,
            }},
        ) catch |err| {
            logSystem(cfg, .ERROR, "could not spawn worker {d} of {d} ({s})", .{ worker_id, worker_count, @errorName(err) });
            report.abandon(cfg.io, worker_count - worker_id, err);

            for (workers[0..worker_id]) |spawned| spawned.join();

            return error.ZixFixListenFailed;
        };

    if (report.awaitGroup(cfg.io)) |err| {
        logSystem(cfg, .ERROR, "not listening on {s}:{d}: {d} of {d} workers could not bind ({s})", .{ cfg.ip, cfg.port, report.failures(), worker_count, @errorName(err) });

        for (workers) |thread| thread.join();

        return error.ZixFixListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is nothing
    // to announce: the old line claimed a listener that may never have come up.
    logSystem(cfg, .INFO, "listening on {s}:{d} (io_uring/{d}, shared-nothing)", .{ cfg.ip, cfg.port, worker_count });

    for (workers) |thread| thread.join();
}
