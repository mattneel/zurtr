//! zix http2 .URING dispatch model (Linux): shared-nothing io_uring, one ring + SO_REUSEPORT
//! listener per worker (ADR-037 Phase 4). Mirrors the gRPC URING model: multishot accept, an
//! fd-indexed slot table with a generation-tagged user_data against fd reuse, and a plain recv
//! into each connection's read accumulator that drives the resumable h2 state machine in `mux.zig`.
//!
//! Note:
//! - Unlike the gRPC ring, zix.Http2's handler writes the reply straight to the fd (via
//!   `frame.sendResponseFD`), so there is no reply cork to ring-send: the ring owns accept and recv,
//!   responses go direct-to-fd. The accepted fd is set non-blocking so `frame.writeAllFD` polls on
//!   EAGAIN under backpressure instead of blocking the worker. One recv is in flight per connection.
//! - Falls back to the .EPOLL shared-nothing loop when io_uring is unavailable (old kernel, seccomp
//!   sandbox, or an RLIMIT_MEMLOCK cap too low for the ring), so selecting .URING never strands the
//!   server right after binding.

const std = @import("std");
const core = @import("../core.zig");
const mux = @import("../mux.zig");
const Http2ServerConfig = @import("../config.zig").Http2ServerConfig;
const common = @import("common.zig");
const epoll_model = @import("epoll.zig");
const logSystem = common.logSystem;
const setNoDelay = common.setNoDelay;
const MAX_FD = common.MAX_FD;
const effectiveCacheEntries = common.effectiveCacheEntries;
const uring = @import("../../../multiplexers/ring.zig");
const slab = @import("../../../multiplexers/slab.zig");
const rcache = @import("../../../utils/response_cache.zig");
const tls_mux = @import("../tls_mux.zig");
const tls_conn = @import("../../../multiplexers/tls_conn.zig");
const reuseport = @import("../../../multiplexers/reuseport.zig");
const listen_report = @import("../../../multiplexers/listen_report.zig");
const Tls = @import("../../../tls/Tls.zig");
const IoUring = std.os.linux.IoUring;

/// SQ entries per worker ring.
const URING_ENTRIES: u16 = 4096;
/// CQ entries per worker ring (larger than the default for multishot headroom).
const URING_CQ_ENTRIES: u32 = 16 * 1024;
/// Max CQEs drained per loop pass.
const URING_CQE_BATCH: usize = 512;

/// io_uring SQPOLL kernel-thread idle before it sleeps, in milliseconds. Inert
/// unless IORING_SETUP_SQPOLL is set (it is not here), kept for when it is.
const URING_SQ_THREAD_IDLE_MS: u32 = 1000;

/// Initialize a worker ring with the single-issuer fast-path flags, falling back to a flagless ring
/// when the kernel does not support them. Mirrors the zix.Http1 and gRPC ring init.
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

/// Per-connection ring wrapper. conn holds the h2 state (the rbuf read accumulator). gen guards
/// against fd reuse: a stale recv CQE for a closed fd must not touch a freshly accepted connection.
const UringConn = struct {
    conn: *mux.MuxConn,
    gen: u24,
};

/// Ring-hosted TLS connection (dual listener, config.tls_port): the shared TLS connection
/// (tls_mux) plus ring bookkeeping. The ciphertext recv buffer is per connection because the
/// kernel fills it asynchronously (the .EPOLL paths read into per-event stack staging instead).
const UringTlsConn = struct {
    conn: tls_mux.TlsConn,
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

const UringMuxCtx = struct {
    io: std.Io,
    ip: []const u8,
    port: u16,
    kernel_backlog: u31,
    opts: core.ServeOpts,
    handler: core.HandlerFn,
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

const Worker = struct {
    ring: IoUring,
    slots: []?*UringConn,
    listener_fd: std.posix.fd_t,
    gen_counter: u24,
    opts: core.ServeOpts,
    handler: core.HandlerFn,
    io: std.Io,
    busy_poll_us: u32,
    /// Dual-listener TLS side (config.tls + config.tls_port). Inactive by default
    /// (-1 / null), so a cleartext-only worker sees zero layout change.
    tls_listener_fd: std.posix.fd_t = -1,
    tls_ctx: ?*Tls.Context = null,
    tls_conns: ?TlsConnTable = null,
    tls_gen_counter: u24 = 0,
    /// The multishot accept re-arm was lost to a full SQ. Retried at the
    /// top of the next loop pass, mirroring the Http1 URING worker.
    /// Without this a full SQ at re-arm time stopped the worker from
    /// ever accepting again while the kernel backlog filled.
    accept_pending: bool = false,
    /// Same lost-re-arm guard for the dual-listener TLS accept.
    tls_accept_pending: bool = false,

    const Self = @This();
    const allocator = std.heap.smp_allocator;
    const linux = std.os.linux;

    fn deinit(self: *Self) void {
        for (self.slots) |maybe_conn| {
            if (maybe_conn) |uc| {
                _ = linux.close(uc.conn.fd);
                uc.conn.deinit();
                allocator.destroy(uc);
            }
        }

        slab.unmapSlots(self.slots);
        if (self.tls_conns) |*tls_table| tls_table.deinit();
        self.ring.deinit();
    }

    fn getSqe(self: *Self) ?*linux.io_uring_sqe {
        return self.ring.get_sqe() catch {
            _ = self.ring.submit() catch return null;

            return self.ring.get_sqe() catch null;
        };
    }

    fn lookup(self: *Self, decoded: uring.Decoded) ?*UringConn {
        const idx: usize = @intCast(decoded.fd);
        if (idx >= self.slots.len) return null;

        const uc = self.slots[idx] orelse return null;
        if (uc.gen != decoded.gen) return null;

        return uc;
    }

    fn closeConn(self: *Self, uc: *UringConn) void {
        self.slots[@intCast(uc.conn.fd)] = null;

        _ = linux.close(uc.conn.fd);
        uc.conn.deinit();
        allocator.destroy(uc);
    }

    fn armAccept(self: *Self) void {
        const sqe = self.getSqe() orelse {
            self.accept_pending = true;
            return;
        };

        sqe.prep_multishot_accept(self.listener_fd, null, null, 0);
        sqe.user_data = uring.packUserData(.accept, 0, self.listener_fd);
    }

    fn armRecv(self: *Self, uc: *UringConn) void {
        const c = uc.conn;

        // Compact the read accumulator before the next recv, mirroring onReadable's loop-top
        // compaction in mux.zig.
        if (c.rstart == c.rend) {
            c.rstart = 0;
            c.rend = 0;
        } else if (c.rend == c.rbuf.len) {
            const n = c.rend - c.rstart;
            std.mem.copyForwards(u8, c.rbuf[0..n], c.rbuf[c.rstart..c.rend]);
            c.rstart = 0;
            c.rend = n;
        }

        if (c.rend == c.rbuf.len) {
            self.closeConn(uc);
            return;
        }

        const sqe = self.getSqe() orelse {
            self.closeConn(uc);
            return;
        };
        sqe.prep_recv(c.fd, c.rbuf[c.rend..], 0);
        sqe.user_data = uring.packUserData(.recv, uc.gen, c.fd);
    }

    fn handleAccept(self: *Self, cqe: linux.io_uring_cqe) void {
        const rearm = (cqe.flags & linux.IORING_CQE_F_MORE) == 0;
        defer if (rearm) self.armAccept();

        if (cqe.res < 0) return;

        const conn_fd: std.posix.fd_t = cqe.res;
        const idx: usize = @intCast(conn_fd);
        if (idx >= self.slots.len) {
            _ = linux.close(conn_fd);
            return;
        }

        setNoDelay(conn_fd);
        // non-blocking so a direct frame.writeAllFD reply polls on EAGAIN under
        // backpressure rather than blocking the worker thread.
        common.setNonBlock(conn_fd);
        common.setBusyPoll(conn_fd, self.busy_poll_us);

        const c = mux.MuxConn.init(conn_fd, self.opts, self.io) orelse {
            _ = linux.close(conn_fd);
            return;
        };
        const uc = allocator.create(UringConn) catch {
            c.deinit();
            _ = linux.close(conn_fd);
            return;
        };

        self.gen_counter +%= 1;
        uc.* = .{ .conn = c, .gen = self.gen_counter };
        self.slots[idx] = uc;

        self.armRecv(uc);
    }

    fn handleRecv(self: *Self, cqe: linux.io_uring_cqe, decoded: uring.Decoded) void {
        const uc = self.lookup(decoded) orelse return;

        // res == 0 is a peer hangup, res < 0 a receive error: both close. A clean hangup part way
        // through a request is answered with GOAWAY first, so the peer is not left reading a bare
        // close. A receive error says nothing: the connection is already broken.
        if (cqe.res <= 0) {
            if (cqe.res == 0) _ = mux.hangupGoaway(uc.conn);
            self.closeConn(uc);

            return;
        }

        uc.conn.rend += @intCast(cqe.res);

        // Coalesce every frame this batch writes into one send instead of one write per frame
        // (HEADERS + DATA per stream, times the streams in the batch). The handler still writes
        // its reply during processing, but the frames stage into the per-worker sink and leave
        // as a single write when the batch ends.
        common.beginCoalesce(uc.conn.fd);
        const outcome = mux.processRing(self.handler, uc.conn);
        const write_failed = common.endCoalesce();
        if (outcome == .close or write_failed) {
            self.closeConn(uc);
            return;
        }

        self.armRecv(uc);
    }

    // ------------------------------------------- //
    // Dual-listener TLS side (config.tls_port): ciphertext recv and the staged-ciphertext
    // flush ride the ring (tls_recv / tls_send ops), the TLS connection logic is
    // tls_mux's (shared with the .EPOLL paths). Half-duplex per connection: while a
    // flush send is in flight no recv is armed, so the transport's staging buffer is
    // never compacted while the kernel reads it.

    fn lookupTls(self: *Self, decoded: uring.Decoded) ?*UringTlsConn {
        const table = if (self.tls_conns) |*tls_table| tls_table else return null;

        const ring_conn = table.get(decoded.fd) orelse return null;
        if (ring_conn.gen != decoded.gen) return null;

        return ring_conn;
    }

    fn armTlsAccept(self: *Self) void {
        const sqe = self.getSqe() orelse {
            self.tls_accept_pending = true;
            return;
        };

        sqe.prep_multishot_accept(self.tls_listener_fd, null, null, 0);
        sqe.user_data = uring.packUserData(.tls_accept, 0, self.tls_listener_fd);
    }

    fn handleTlsAccept(self: *Self, cqe: linux.io_uring_cqe) void {
        const rearm = (cqe.flags & linux.IORING_CQE_F_MORE) == 0;
        defer if (rearm) self.armTlsAccept();

        if (cqe.res < 0) return;

        const conn_fd: std.posix.fd_t = cqe.res;
        const table = if (self.tls_conns) |*tls_table| tls_table else {
            _ = linux.close(conn_fd);
            return;
        };
        const idx: usize = @intCast(conn_fd);
        if (idx >= table.slots.len) {
            _ = linux.close(conn_fd);
            return;
        }

        setNoDelay(conn_fd);
        // The transport writes records directly (staging on EAGAIN), so the fd must be
        // non-blocking.
        common.setNonBlock(conn_fd);

        const ring_conn = allocator.create(UringTlsConn) catch {
            _ = linux.close(conn_fd);
            return;
        };
        const cipher_buf = allocator.alloc(u8, tls_conn.read_staging_size) catch {
            allocator.destroy(ring_conn);
            _ = linux.close(conn_fd);
            return;
        };

        self.tls_gen_counter +%= 1;
        ring_conn.* = .{
            .conn = .{
                .transport = tls_conn.Transport.init(conn_fd, self.tls_ctx.?),
                .opts = self.opts,
                .io = self.io,
            },
            .gen = self.tls_gen_counter,
            .cipher_buf = cipher_buf,
        };
        ring_conn.conn.transport.wbuf_initial = self.opts.tls_write_buf_initial;
        table.put(conn_fd, ring_conn);

        self.armTlsRecv(ring_conn);
    }

    /// Tear a TLS connection down: drop it from the table (frees the conn object) and
    /// hand the fd close to the ring.
    fn closeTls(self: *Self, ring_conn: *UringTlsConn) void {
        const fd = ring_conn.conn.transport.fd;
        if (self.tls_conns) |*tls_table| tls_table.drop(fd);

        const sqe = self.getSqe() orelse {
            _ = linux.close(fd);
            return;
        };
        sqe.prep_close(fd);
        sqe.user_data = uring.packUserData(.close, 0, fd);
    }

    fn armTlsRecv(self: *Self, ring_conn: *UringTlsConn) void {
        // Sized by what the session can take, not by the staging buffer. The staging buffer is wider
        // than one TLS record, so a busy socket (a large request in flight) would otherwise hand the
        // session two records at once, which it refuses by closing the connection.
        const room = ring_conn.conn.transport.tls.readRoom();
        if (room == 0) {
            self.closeTls(ring_conn);
            return;
        }

        const sqe = self.getSqe() orelse {
            self.closeTls(ring_conn);
            return;
        };
        sqe.prep_recv(ring_conn.conn.transport.fd, ring_conn.cipher_buf[0..@min(ring_conn.cipher_buf.len, room)], 0);
        sqe.user_data = uring.packUserData(.tls_recv, ring_conn.gen, ring_conn.conn.transport.fd);
    }

    /// Flush the transport's staged ciphertext (wbuf[woff..wlen]) with an on-ring send.
    fn submitTlsSend(self: *Self, ring_conn: *UringTlsConn) void {
        const transport = &ring_conn.conn.transport;

        const sqe = self.getSqe() orelse {
            self.closeTls(ring_conn);
            return;
        };
        sqe.prep_send(transport.fd, transport.wbuf[transport.woff..transport.wlen], linux.MSG.NOSIGNAL);
        sqe.user_data = uring.packUserData(.tls_send, ring_conn.gen, transport.fd);
    }

    fn handleTlsRecv(self: *Self, cqe: linux.io_uring_cqe, decoded: uring.Decoded) void {
        const ring_conn = self.lookupTls(decoded) orelse return;

        if (cqe.res <= 0) {
            // A clean hangup part way through a request seals a GOAWAY, which rides the ring before
            // the close (handleTlsSend closes on wclose once it drains). A receive error says
            // nothing: the connection is already broken.
            if (cqe.res == 0 and tls_mux.hangupGoaway(&ring_conn.conn)) {
                self.submitTlsSend(ring_conn);

                return;
            }

            self.closeTls(ring_conn);
            return;
        }

        const keep = tls_mux.onCiphertext(self.handler, &ring_conn.conn, ring_conn.cipher_buf[0..@intCast(cqe.res)]);
        const transport = &ring_conn.conn.transport;

        if (!keep) {
            self.closeTls(ring_conn);
            return;
        }

        // Backpressure-staged ciphertext: flush it on the ring before the next recv.
        if (transport.wlen > transport.woff) {
            self.submitTlsSend(ring_conn);
            return;
        }

        if (transport.wclose) {
            self.closeTls(ring_conn);
            return;
        }

        self.armTlsRecv(ring_conn);
    }

    fn handleTlsSend(self: *Self, cqe: linux.io_uring_cqe, decoded: uring.Decoded) void {
        const ring_conn = self.lookupTls(decoded) orelse return;
        const transport = &ring_conn.conn.transport;

        if (cqe.res <= 0) {
            self.closeTls(ring_conn);
            return;
        }

        transport.woff += @intCast(cqe.res);
        if (transport.woff < transport.wlen) {
            self.submitTlsSend(ring_conn);
            return;
        }

        // Drained. Keep the buffer for reuse (freed at close), mirroring the EPOLL flush.
        transport.woff = 0;
        transport.wlen = 0;
        transport.want_out = false;

        if (transport.wclose) {
            self.closeTls(ring_conn);
            return;
        }

        self.armTlsRecv(ring_conn);
    }

    // ------------------------------------------- //

    fn run(self: *Self) void {
        self.armAccept();
        if (self.tls_listener_fd != -1) self.armTlsAccept();

        var cqes: [URING_CQE_BATCH]linux.io_uring_cqe = undefined;
        while (true) {
            _ = self.ring.submit_and_wait(1) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => return,
            };

            // The submit above freed SQ space: retry an accept re-arm
            // lost to a full SQ, so the worker never stops accepting.
            if (self.accept_pending) {
                self.accept_pending = false;
                self.armAccept();
            }
            if (self.tls_accept_pending) {
                self.tls_accept_pending = false;
                self.armTlsAccept();
            }

            const count = self.ring.copy_cqes(&cqes, 0) catch return;
            for (cqes[0..count]) |cqe| {
                const decoded = uring.unpackUserData(cqe.user_data);
                switch (decoded.op) {
                    .accept => self.handleAccept(cqe),
                    .recv => self.handleRecv(cqe, decoded),
                    .send => {},
                    .timeout => {},
                    .close => {},
                    .tls_accept => self.handleTlsAccept(cqe),
                    .tls_recv => self.handleTlsRecv(cqe, decoded),
                    .tls_send => self.handleTlsSend(cqe, decoded),
                    .external => {},
                }
            }
        }
    }
};

fn uringMuxWorker(ctx: UringMuxCtx) void {
    // Pin to one cgroup-allowed CPU so workers never oversubscribe a core under a limited cpuset.
    common.pinToCpu(ctx.worker_id);

    // Bind under the order gate: REUSEPORT group index i = worker i,
    // so the cpu-mod-N steering lands on the worker pinned to that slot.
    var bind_turn = reuseport.BindTurn.begin(ctx.steering, ctx.worker_id);
    defer bind_turn.release();

    // Every exit between here and the ring loop has to reach the group, or the workers that did
    // bind wait on one that is already gone.
    var slot = ctx.report.slot(ctx.io, error.ZixHttp2WorkerSetupFailed);
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

    if (ctx.steering) |steer| _ = reuseport.attachCpuSteering(listener_fd, steer.group_size);

    // Dual-listener TLS side: a second listener on tls_port whose connections terminate
    // TLS in this same ring loop (no separate epoll fleet).
    const tls_active = ctx.tls_ctx != null and ctx.tls_port != 0;
    var tls_srv: std.Io.net.Server = undefined;
    var tls_listener_fd: std.posix.fd_t = -1;
    if (tls_active) {
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
        if (ctx.steering) |steer| _ = reuseport.attachCpuSteering(tls_listener_fd, steer.group_size);
    }
    defer if (tls_active) tls_srv.deinit(ctx.io);

    // Both groups joined: release the bind turn to the next worker.
    bind_turn.release();

    // Serve only once every worker is up, so a group where one bind failed serves on none of them
    // and the caller gets one honest failure.
    slot.ok();
    if (ctx.report.awaitGroup(ctx.io) != null) return;

    const slots = slab.mapZeroedSlots(?*UringConn, MAX_FD) catch return;

    var worker = Worker{
        .ring = undefined,
        .slots = slots,
        .listener_fd = listener_fd,
        .gen_counter = 0,
        .opts = ctx.opts,
        .handler = ctx.handler,
        .io = ctx.io,
        .busy_poll_us = ctx.busy_poll_us,
        .tls_listener_fd = tls_listener_fd,
        .tls_ctx = if (tls_active) ctx.tls_ctx else null,
    };
    worker.ring = initUringRing() catch return;
    if (tls_active) worker.tls_conns = TlsConnTable.init() catch return;
    defer worker.deinit();

    // Per-worker access logger: installed once for the worker's whole life, like the cache below.
    core.setAccessLogger(ctx.opts.logger);

    // Per-worker response cache: lock-free by ownership, never shared, like the EPOLL worker.
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

    worker.run();
}

// --------------------------------------------------------- //

/// URING dispatch (Linux-only): shared-nothing, one SO_REUSEPORT listener plus io_uring ring per
/// worker. Each worker multiplexes many connections through the resumable h2 state machine on a
/// completion loop (ADR-037 Phase 4).
///
/// Note:
/// - worker_count = workers (0 = cpu count). A handler runs on the completion loop, so it must
///   stay bounded (it blocks the worker's other connections while running).
pub fn runUring(handler: core.HandlerFn, cfg: Http2ServerConfig) !void {
    // Runtime probe: io_uring can be unavailable on this host (seccomp/sandbox, RLIMIT_MEMLOCK, or
    // an old kernel). Without this, every worker would fail setup, return, and the server would
    // vanish right after binding (a confusing ServerStartTimeout downstream). Fall back to the EPOLL
    // shared-nothing loop.
    var probe = initUringRing() catch |err| {
        logSystem(cfg, .WARN, "io_uring unavailable ({s}): not suited to this environment (commonly RLIMIT_MEMLOCK, the ulimit -l cap, too low for the ring size). Falling back to EPOLL.", .{@errorName(err)});

        return epoll_model.runEpoll(handler, cfg);
    };
    probe.deinit();

    const io = cfg.io;
    // cgroup-aware so a limited cpuset defaults to one worker per available CPU, not one per machine core.
    const cpu = common.getAvailableCpuCount();
    const worker_count = if (cfg.workers == 0) cpu else cfg.workers;
    const opts = common.serveOpts(cfg);

    const workers = try std.heap.smp_allocator.alloc(std.Thread, worker_count);
    defer std.heap.smp_allocator.free(workers);

    // CBPF steering: one shared bind-order gate, alive until join().
    var bind_gate = reuseport.BindOrderGate{};
    const steering: ?reuseport.Steering = if (cfg.reuseport_cbpf) .{ .gate = &bind_gate, .group_size = worker_count } else null;

    // What every worker says about its own listeners, so a bind that fails inside a worker
    // thread reaches this frame instead of ending that thread and nothing else.
    var report = listen_report.Report.init(worker_count);

    for (workers, 0..) |*thread, idx|
        thread.* = std.Thread.spawn(
            .{ .stack_size = cfg.worker_stack_size_bytes },
            uringMuxWorker,
            .{UringMuxCtx{
                .io = io,
                .ip = cfg.ip,
                .port = cfg.port,
                .kernel_backlog = cfg.kernel_backlog,
                .opts = opts,
                .handler = handler,
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

            return error.ZixHttp2ListenFailed;
        };

    if (report.awaitGroup(io)) |err| {
        logSystem(cfg, .ERROR, "not listening on {s}:{d}: {d} of {d} workers could not bind ({s})", .{ cfg.ip, cfg.port, report.failures(), worker_count, @errorName(err) });

        for (workers) |thread| thread.join();

        return error.ZixHttp2ListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is
    // nothing to announce: the old line claimed a listener that may never have come up.
    logSystem(cfg, .INFO, "listening on {s}:{d} (io_uring-mux/{d})", .{ cfg.ip, cfg.port, worker_count });
    if (cfg.tls != null and cfg.tls_port != 0)
        logSystem(cfg, .INFO, "dual listener: h2 TLS on {s}:{d} (same workers, on-ring)", .{ cfg.ip, cfg.tls_port });

    for (workers) |thread| thread.join();
}
