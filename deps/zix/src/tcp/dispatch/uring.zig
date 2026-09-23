//! zix tcp framed io_uring ring (ADR-037 Phase 4 extension): shared-nothing, one
//! ring + listener per worker. recv into the connection buffer, parse
//! length-prefixed frames, call frame_fn per frame (the reply stages through
//! tl_resp_sink), and submit one coalesced send per readable batch. Half-duplex
//! per connection. Mirrors the zix.Http1 ring core with frame parsing in place
//! of HTTP parsing.
//!
//! Only the framed callback engine (Server.initFramed) runs natively on the
//! ring. The per-connection blocking handler cannot, so its .URING model folds
//! to the .EPOLL shared-nothing loop (see dispatch/epoll.zig).

const std = @import("std");
const Config = @import("../config.zig");
const TcpServerConfig = Config.TcpServerConfig;
const uring = @import("../../multiplexers/ring.zig");
const slab = @import("../../multiplexers/slab.zig");
const Logger = @import("../../logger/logger.zig").Logger;
const reuseport = @import("../../multiplexers/reuseport.zig");
const listen_report = @import("../../multiplexers/listen_report.zig");
const common = @import("common.zig");
const logSystem = common.logSystem;
const FrameFn = common.FrameFn;
const RespSink = common.RespSink;
const FRAME_LEN_PREFIX = common.FRAME_LEN_PREFIX;
const FRAME_MAX_PAYLOAD = common.FRAME_MAX_PAYLOAD;
const IoUring = std.os.linux.IoUring;

// --------------------------------------------------------- //

const FrameOutcome = enum { keep_alive, close };

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

/// Runtime probe: null when an io_uring ring can be created on this host,
/// otherwise the error name explaining why it cannot. io_uring can be
/// unavailable (seccomp/sandbox, RLIMIT_MEMLOCK too low for the ring size, old
/// kernel), in which case the framed server falls back to the blocking frame
/// adapter served over EPOLL instead of vanishing right after binding.
pub fn uringUnavailableReason() ?[]const u8 {
    var ring = initUringRing() catch |err| return @errorName(err);
    ring.deinit();

    return null;
}

fn ringSetNoDelay(fd: std.posix.fd_t) void {
    std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&@as(c_int, 1))) catch {};
}

/// Per-connection ring state. buf accumulates frame bytes until whole frames are
/// present, send_buf holds the coalesced reply while a send is in flight, gen
/// guards against fd reuse.
const UringConn = struct {
    fd: std.posix.fd_t,
    gen: u24,
    buf: []u8,
    filled: usize,
    send_buf: []u8,
    staged: usize,
    inflight: usize,
    closing: bool,
};

const UringFrameCtx = struct {
    io: std.Io,
    ip: []const u8,
    port: u16,
    kernel_backlog: u31,
    recv_buf_size: usize,
    send_buf_size: usize,
    max_conns: usize,
    worker_id: usize,
    /// Config logger, for the per-worker skew report at exit.
    logger: ?*Logger = null,
    /// CBPF steering wiring (config.reuseport_cbpf). Null = steering off.
    steering: ?reuseport.Steering = null,
    /// Where this worker says whether its listener came up, shared with the whole group.
    report: *listen_report.Report,
};

/// Build a concrete framed io_uring worker entry with frame_fn baked in at
/// compile time, mirroring the zix.Http1 ring worker.
fn uringFrameWorkerFn(comptime frame_fn: FrameFn) fn (UringFrameCtx) void {
    return struct {
        const Worker = struct {
            ring: IoUring,
            slots: []?*UringConn,
            listener_fd: std.posix.fd_t,
            gen_counter: u24,
            recv_buf_size: usize,
            send_buf_size: usize = URING_SEND_BUF_SIZE,
            /// Frames served by this worker (skew counter). Single-owner plain
            /// increment (no contention), reported through the system logger at
            /// worker exit so REUSEPORT skew across workers is measurable.
            frames_served: u64 = 0,

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

            fn lookup(worker: *W, decoded: uring.Decoded) ?*UringConn {
                const idx: usize = @intCast(decoded.fd);
                if (idx >= worker.slots.len) return null;

                const conn = worker.slots[idx] orelse return null;
                if (conn.gen != decoded.gen) return null;

                return conn;
            }

            fn destroyConn(worker: *W, conn: *UringConn) void {
                worker.slots[@intCast(conn.fd)] = null;

                allocator.free(conn.buf);
                allocator.free(conn.send_buf);
                allocator.destroy(conn);
            }

            fn finishClose(worker: *W, conn: *UringConn) void {
                _ = lx.close(conn.fd);
                worker.destroyConn(conn);
            }

            fn beginClose(worker: *W, conn: *UringConn) void {
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

            fn armRecv(worker: *W, conn: *UringConn) void {
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

            fn submitSend(worker: *W, conn: *UringConn) void {
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

                const conn = allocator.create(UringConn) catch {
                    _ = lx.close(conn_fd);
                    return;
                };
                const buf = allocator.alloc(u8, worker.recv_buf_size) catch {
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

                const outcome = worker.dispatch(conn);

                if (conn.staged > 0) {
                    worker.submitSend(conn);
                    if (outcome == .close) conn.closing = true;

                    return;
                }

                if (outcome == .close) {
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

            /// Parse every complete length-prefixed frame in conn.buf and call
            /// frame_fn for each (reply staged through the sink into send_buf),
            /// then compact the trailing partial frame to the front.
            fn dispatch(worker: *W, conn: *UringConn) FrameOutcome {
                const fd = conn.fd;

                var sink = RespSink{ .fd = fd, .buf = conn.send_buf };
                common.tl_resp_sink = &sink;
                defer common.tl_resp_sink = null;

                var consumed: usize = 0;
                var keep_alive = true;
                while (conn.filled - consumed >= FRAME_LEN_PREFIX) {
                    const rem = conn.buf[consumed..conn.filled];
                    const len = std.mem.readInt(u32, rem[0..FRAME_LEN_PREFIX], .big);
                    if (len == 0 or len > FRAME_MAX_PAYLOAD or FRAME_LEN_PREFIX + len > conn.buf.len) {
                        keep_alive = false;
                        break;
                    }

                    const need = FRAME_LEN_PREFIX + len;
                    if (rem.len < need) break;

                    frame_fn(rem[FRAME_LEN_PREFIX..need], fd);
                    consumed += need;
                    worker.frames_served += 1;
                }

                if (consumed >= conn.filled) {
                    conn.filled = 0;
                } else if (consumed > 0) {
                    std.mem.copyForwards(u8, conn.buf[0 .. conn.filled - consumed], conn.buf[consumed..conn.filled]);
                    conn.filled -= consumed;
                }

                conn.staged = sink.len;
                if (sink.failed) return .close;

                return if (keep_alive) .keep_alive else .close;
            }

            fn run(worker: *W) void {
                worker.armAccept();

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
                            .timeout => {},
                            .close => {},
                            .tls_accept, .tls_recv, .tls_send, .external => {},
                        }
                    }
                }
            }
        };

        fn run(ctx: UringFrameCtx) void {
            common.pinToCpu(ctx.worker_id);

            // Bind under the order gate: REUSEPORT group index i = worker i,
            // so the cpu-mod-N steering lands on the worker pinned to that slot.
            var bind_turn = reuseport.BindTurn.begin(ctx.steering, ctx.worker_id);
            defer bind_turn.release();

            // Every exit between here and the ring loop has to reach the group, or the workers
            // that did bind wait on one that is already gone.
            var slot = ctx.report.slot(ctx.io, error.ZixTcpWorkerSetupFailed);
            defer slot.close();

            const addr = std.Io.net.IpAddress.resolve(ctx.io, ctx.ip, ctx.port) catch |err| {
                slot.fail(err);

                return;
            };
            var net_server = addr.listen(ctx.io, .{
                .mode = .stream,
                .protocol = .tcp,
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

            // Serve only once every worker is up, so a group where one bind failed serves on none
            // of them and the caller gets one honest failure.
            slot.ok();
            if (ctx.report.awaitGroup(ctx.io) != null) return;

            const slots = slab.mapZeroedSlots(?*UringConn, ctx.max_conns) catch return;

            var worker = Worker{
                .ring = undefined,
                .slots = slots,
                .listener_fd = listener_fd,
                .gen_counter = 0,
                .recv_buf_size = ctx.recv_buf_size,
                .send_buf_size = ctx.send_buf_size,
            };
            worker.ring = initUringRing() catch return;
            defer worker.deinit();

            worker.run();

            if (ctx.logger) |lg| lg.system(.INFO, "tcp", "uring worker {d}: {d} frames served", .{ ctx.worker_id, worker.frames_served });
        }
    }.run;
}

// --------------------------------------------------------- //
// URING framed model

pub fn runFramedUring(cfg: TcpServerConfig, io: std.Io, comptime frame_fn: FrameFn) !void {
    const worker_count = if (cfg.workers == 0) common.getAvailableCpuCount() else cfg.workers;

    const threads = try std.heap.smp_allocator.alloc(std.Thread, worker_count);
    defer std.heap.smp_allocator.free(threads);

    // CBPF steering: one shared bind-order gate, alive until join().
    var bind_gate = reuseport.BindOrderGate{};
    const steering: ?reuseport.Steering = if (cfg.reuseport_cbpf) .{ .gate = &bind_gate, .group_size = worker_count } else null;

    // What every worker says about its own listener, so a bind that fails inside a worker thread
    // reaches this frame instead of ending that thread and nothing else.
    var report = listen_report.Report.init(worker_count);

    const worker_fn = uringFrameWorkerFn(frame_fn);
    for (threads, 0..) |*thread, worker_id|
        thread.* = std.Thread.spawn(
            .{ .stack_size = cfg.worker_stack_size_bytes },
            worker_fn,
            .{UringFrameCtx{
                .io = io,
                .ip = cfg.ip,
                .port = cfg.port,
                .kernel_backlog = cfg.kernel_backlog,
                .recv_buf_size = cfg.max_recv_buf,
                .send_buf_size = cfg.uring_send_buf_size,
                .max_conns = cfg.uring_max_conns_per_worker,
                .worker_id = worker_id,
                .logger = cfg.logger,
                .steering = steering,
                .report = &report,
            }},
        ) catch |err| {
            logSystem(cfg, .ERROR, "could not spawn worker {d} of {d} ({s})", .{ worker_id, worker_count, @errorName(err) });
            report.abandon(io, worker_count - worker_id, err);

            for (threads[0..worker_id]) |spawned| spawned.join();

            return error.ZixTcpListenFailed;
        };

    if (report.awaitGroup(io)) |err| {
        logSystem(cfg, .ERROR, "not listening on {s}:{d}: {d} of {d} workers could not bind ({s})", .{ cfg.ip, cfg.port, report.failures(), worker_count, @errorName(err) });

        for (threads) |thread| thread.join();

        return error.ZixTcpListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is nothing
    // to announce: the old line claimed a listener that may never have come up.
    logSystem(cfg, .INFO, "listening on {s}:{d} (io_uring framed/{d}, shared-nothing)", .{ cfg.ip, cfg.port, worker_count });

    for (threads) |thread| thread.join();
}
