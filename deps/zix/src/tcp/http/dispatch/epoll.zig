//! zix http .EPOLL dispatch model (Linux-only): shared-nothing event-loop
//! workers, each with its own SO_REUSEPORT listener and epoll instance. The
//! kernel load-balances new connections across all per-worker listeners, so
//! there is no shared queue and no cross-thread fd handoff.

const std = @import("std");
const common = @import("common.zig");
const logSystem = common.logSystem;
const processRequest = common.processRequest;
const pinToCpu = common.pinToCpu;
const getAvailableCpuCount = common.getAvailableCpuCount;
const effectiveCacheEntries = common.effectiveCacheEntries;
const EpollConnTable = common.EpollConnTable;
const epollAcceptAll = common.epollAcceptAll;
const EPOLL_OUT_BUF_SIZE = common.EPOLL_OUT_BUF_SIZE;
const parser = @import("../parser.zig");
const rcache = @import("../../../utils/response_cache.zig");
const reuseport = @import("../../../multiplexers/reuseport.zig");
const listen_report = @import("../../../multiplexers/listen_report.zig");
const resp_mod = @import("../response.zig");
const tls_mux = @import("../tls_mux.zig");
const tls_conn = @import("../../../multiplexers/tls_conn.zig");
const Tls = @import("../../../tls/Tls.zig");
const setCache = resp_mod.setCache;
const setCompression = resp_mod.setCompression;
const RespSink = resp_mod.RespSink;
const writeAllFD = resp_mod.writeAllFD;

/// Max epoll events drained per epoll_wait call. 1024 lets a worker clear its
/// ready-fd set in one syscall at high connection counts.
const EPOLL_MAX_EVENTS: usize = 1024;

// --------------------------------------------------------- //

/// EPOLL worker: owns one SO_REUSEPORT listener and one epoll instance.
/// The kernel load-balances new connections across all per-worker listeners so
/// there is no shared queue and no cross-thread fd handoff.
///
/// Note:
/// - EpollConnTable holds per-connection recv state. Each accept assigns a
///   slab slice with no heap call, filled tracks accumulated bytes across events.
/// - Accepted fds are NONBLOCK: the recv loop reads until EAGAIN, allowing
///   headers that arrive in multiple TCP segments without blocking the worker.
/// - Connections are level-triggered: the fd stays registered after each request
///   and re-fires when new data arrives (keep-alive without re-arm syscalls).
/// - Arena and slab are allocated once per worker and reused across all connections.
///
/// Param:
/// server - anytype (pointer to the Server instance)
/// io - std.Io
/// worker_id - usize (used for pinToCpu)
/// One event on a dual-listener TLS connection: mirrors the tls_mux worker loop body (flush
/// staged ciphertext on EPOLLOUT, feed decrypted bytes on EPOLLIN, re-arm or reap). Generic over
/// the tls_mux Worker instantiation, since the TLS connection type carries the server type.
fn serveTlsEvent(comptime TlsWorker: type, tls_conns: *TlsWorker.ConnTable, epfd: std.posix.fd_t, ev: std.os.linux.epoll_event, io: std.Io, arena: *std.heap.ArenaAllocator) void {
    const linux = std.os.linux;
    const fd: std.posix.fd_t = @intCast(ev.data.u64 & (tls_conn.tls_event_tag - 1));

    const conn = tls_conns.get(fd) orelse return;
    var keep = true;

    if ((ev.events & (linux.EPOLL.HUP | linux.EPOLL.ERR)) != 0) {
        keep = false;
    } else {
        if ((ev.events & linux.EPOLL.OUT) != 0) keep = conn.transport.onWritable(epfd);
        if (keep and (ev.events & linux.EPOLL.IN) != 0) keep = TlsWorker.onReadable(conn, io, arena);
        if (keep and conn.transport.want_out) tls_conn.armOut(epfd, fd, conn.transport.ep_data, true);
        if (keep and conn.transport.wclose and !conn.transport.want_out) keep = false;
    }

    if (!keep) {
        _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_DEL, fd, null);
        tls_conns.drop(fd);
        _ = linux.close(fd);
    }
}

fn epollWorker(server: anytype, io: std.Io, worker_id: usize, steering: ?reuseport.Steering, report: *listen_report.Report) void {
    const linux = std.os.linux;
    const cfg = server.config;

    pinToCpu(worker_id);

    // Requests served by this worker (cleartext dispatch). Single-owner plain
    // increment (no contention), reported through the system logger at worker
    // exit so REUSEPORT skew across workers is measurable.
    var requests_served: u64 = 0;
    defer logSystem(cfg, .INFO, "epoll worker {d}: {d} requests served", .{ worker_id, requests_served });

    // Bind under the order gate: REUSEPORT group index i = worker i,
    // so the cpu-mod-N steering lands on the worker pinned to that slot.
    var bind_turn = reuseport.BindTurn.begin(steering, worker_id);
    defer bind_turn.release();

    // Every exit between here and the event loop has to reach the group, or the workers that
    // did bind wait on one that is already gone.
    var slot = report.slot(io, error.ZixHttpWorkerSetupFailed);
    defer slot.close();

    const addr = std.Io.net.IpAddress.resolve(io, cfg.ip, cfg.port) catch |err| {
        slot.fail(err);

        return;
    };
    var net_server = addr.listen(io, .{
        .mode = .stream,
        .kernel_backlog = @intCast(cfg.kernel_backlog),
        .reuse_address = true, // SO_REUSEADDR + SO_REUSEPORT: each worker binds the same port
    }) catch |err| {
        slot.fail(err);

        return;
    };
    defer net_server.deinit(io);
    const listener_fd = net_server.socket.handle;

    if (steering) |steer| _ = reuseport.attachCpuSteering(listener_fd, steer.group_size);

    // Non-blocking listener so epollAcceptAll drains to EAGAIN without blocking.
    const cur_flags = linux.fcntl(listener_fd, std.posix.F.GETFL, 0);
    const nonblock_bit: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
    _ = linux.fcntl(listener_fd, std.posix.F.SETFL, cur_flags | @as(usize, nonblock_bit));

    const epfd_rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    if (std.posix.errno(epfd_rc) != .SUCCESS) return;
    const epfd: std.posix.fd_t = @intCast(epfd_rc);
    defer _ = linux.close(epfd);

    var listener_event = linux.epoll_event{
        .events = linux.EPOLL.IN,
        .data = .{ .u64 = @intCast(listener_fd) },
    };
    if (std.posix.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, listener_fd, &listener_event)) != .SUCCESS) return;

    var table = EpollConnTable.init(cfg.max_recv_buf) catch return;
    defer table.deinit();

    // Dual-listener TLS side (config.tls + config.tls_port): a second listen fd whose connections
    // terminate TLS in this same loop via the tls_mux Worker machinery. Everything below is mapped
    // only when active, so a cleartext-only worker sees zero layout change on its hot structures.
    const TlsWorker = tls_mux.Worker(@TypeOf(server));
    const tls_ctx: ?*Tls.Context = if (cfg.tls_port != 0) cfg.tls else null;
    var tls_listener_fd: std.posix.fd_t = -1;
    var tls_srv: std.Io.net.Server = undefined;
    var tls_table: ?TlsWorker.ConnTable = null;
    defer if (tls_table) |*tls_conns| tls_conns.deinit();
    defer if (tls_ctx != null and tls_listener_fd != -1) tls_srv.deinit(io);

    if (tls_ctx != null) {
        const tls_addr = std.Io.net.IpAddress.resolve(io, cfg.ip, cfg.tls_port) catch |err| {
            slot.fail(err);

            return;
        };
        tls_srv = tls_addr.listen(io, .{
            .mode = .stream,
            .kernel_backlog = @intCast(cfg.kernel_backlog),
            .reuse_address = true,
        }) catch |err| {
            slot.fail(err);

            return;
        };
        tls_listener_fd = tls_srv.socket.handle;
        if (steering) |steer| _ = reuseport.attachCpuSteering(tls_listener_fd, steer.group_size);

        const tls_cur_flags = linux.fcntl(tls_listener_fd, std.posix.F.GETFL, 0);
        _ = linux.fcntl(tls_listener_fd, std.posix.F.SETFL, tls_cur_flags | @as(usize, nonblock_bit));

        var tls_lev = linux.epoll_event{
            .events = linux.EPOLL.IN,
            .data = .{ .u64 = @intCast(tls_listener_fd) },
        };
        if (std.posix.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, tls_listener_fd, &tls_lev)) != .SUCCESS) return;

        tls_table = TlsWorker.ConnTable.init() catch return;
    }

    // Both groups joined: release the bind turn to the next worker.
    bind_turn.release();

    // Serve only once every worker is up, so a group where one bind failed serves on none of them
    // and the caller gets one honest failure.
    slot.ok();
    if (report.awaitGroup(io) != null) return;

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    _ = arena.allocator().alloc(u8, cfg.max_allocator_size) catch {};
    _ = arena.reset(.retain_capacity);

    // Per-worker response cache: lock-free by ownership, never shared.
    var response_cache: rcache.ResponseCache = undefined;
    var cache_on = false;
    if (cfg.response_cache) {
        if (rcache.ResponseCache.init(std.heap.smp_allocator, .{
            .max_entries = effectiveCacheEntries(cfg),
            .max_value_bytes = cfg.cache_max_value_bytes,
        })) |built| {
            response_cache = built;
            cache_on = true;
            setCache(&response_cache, cfg.cache_ttl_ms);
        } else |_| {
            cache_on = false;
        }
    }
    defer if (cache_on) {
        setCache(null, 0);
        response_cache.deinit();
    };

    // Response compression, stateless per worker. Active under .EPOLL and .URING,
    // like the cache.
    if (cfg.compress) setCompression(cfg.compress, cfg.compression_min_size, cfg.compression_max_out);
    defer setCompression(false, 0, 0);

    // Per-worker response staging buffer: the handler's writes coalesce
    // into this sink, then the worker flushes it once per request.
    const out_buf = std.heap.smp_allocator.alloc(u8, EPOLL_OUT_BUF_SIZE) catch return;
    defer std.heap.smp_allocator.free(out_buf);

    var events: [EPOLL_MAX_EVENTS]linux.epoll_event = undefined;
    var epoll_timeout: i32 = -1;
    while (true) {
        const wait_result = linux.epoll_wait(epfd, &events, EPOLL_MAX_EVENTS, epoll_timeout);
        switch (std.posix.errno(wait_result)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return,
        }

        const event_count: usize = @intCast(wait_result);
        if (event_count == 0) {
            epoll_timeout = -1;
            continue;
        }

        for (events[0..event_count]) |ev| {
            if (ev.data.fd == listener_fd) {
                epollAcceptAll(&table, epfd, listener_fd, cfg.busy_poll_us);
                continue;
            }

            if (tls_ctx) |tls_context| {
                if (ev.data.fd == tls_listener_fd) {
                    TlsWorker.acceptAll(&tls_table.?, epfd, tls_listener_fd, server, tls_context, tls_conn.tls_event_tag);
                    continue;
                }
                if (ev.data.u64 & tls_conn.tls_event_tag != 0) {
                    serveTlsEvent(TlsWorker, &tls_table.?, epfd, ev, io, &arena);
                    continue;
                }
            }

            const conn_fd = ev.data.fd;

            if ((ev.events & (linux.EPOLL.HUP | linux.EPOLL.ERR | linux.EPOLL.RDHUP)) != 0) {
                if (table.get(conn_fd)) |_| table.free(conn_fd);
                _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_DEL, conn_fd, null);
                _ = linux.close(conn_fd);
                continue;
            }

            const conn = table.get(conn_fd) orelse continue;

            // Drain a staged response before anything else: never start a
            // new request while a prior response is still flushing, so the
            // response order is preserved under pipelining (the connection
            // is EPOLLOUT-armed only while write_pending holds bytes).
            if (conn.write_pending.len > conn.write_pending_off) {
                const pending = conn.write_pending[conn.write_pending_off..];
                const written = resp_mod.writeNonBlockFD(conn_fd, pending) orelse {
                    table.free(conn_fd);
                    _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_DEL, conn_fd, null);
                    _ = linux.close(conn_fd);
                    continue;
                };

                conn.write_pending_off += written;
                if (conn.write_pending_off < conn.write_pending.len) continue;

                const drained_close = conn.write_pending_close;
                std.heap.smp_allocator.free(conn.write_pending);
                conn.write_pending = &.{};
                conn.write_pending_off = 0;
                conn.write_pending_close = false;
                conn.filled = 0;

                if (drained_close) {
                    table.free(conn_fd);
                    _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_DEL, conn_fd, null);
                    _ = linux.close(conn_fd);
                    continue;
                }

                var disarm_ev = linux.epoll_event{
                    .events = linux.EPOLL.IN | linux.EPOLL.RDHUP,
                    .data = .{ .u64 = @intCast(conn_fd) },
                };
                _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_MOD, conn_fd, &disarm_ev);

                continue;
            }

            // Recv into conn.buf[conn.filled..]. NONBLOCK fd: read() returns
            // EAGAIN when no more data is buffered in the kernel, so we break
            // and wait for the next IN event (partial headers across segments).
            var should_close = false;
            var found_headers = false;
            while (conn.filled < conn.buf.len) {
                const n = std.posix.read(conn_fd, conn.buf[conn.filled..]) catch |err| {
                    if (err != error.WouldBlock) should_close = true;
                    break;
                };
                if (n == 0) {
                    should_close = true;
                    break;
                }
                const prev = conn.filled;
                conn.filled += n;
                const search_from = if (prev > 3) prev - 3 else 0;
                if (parser.findHeaderEnd(conn.buf[0..conn.filled], search_from)) |_| {
                    found_headers = true;
                    break;
                }
            }

            if (!should_close and !found_headers and conn.filled >= conn.buf.len) {
                writeAllFD(conn_fd, "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n") catch {};
                should_close = true;
            }

            if (should_close) {
                table.free(conn_fd);
                _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_DEL, conn_fd, null);
                _ = linux.close(conn_fd);
                continue;
            }

            if (!found_headers) continue;

            const stream = std.Io.net.Stream{ .socket = .{ .handle = conn_fd, .address = undefined } };
            _ = arena.reset(.retain_capacity);

            var sink = RespSink{ .fd = conn_fd, .buf = out_buf };
            resp_mod.tl_resp_sink = &sink;
            const outcome = processRequest(server, stream, conn_fd, io, conn.buf[0..conn.filled], &arena);
            resp_mod.tl_resp_sink = null;
            requests_served += 1;

            var close_conn = (outcome != .keep_alive) or sink.failed;

            // Flush the coalesced response. A partial write (EAGAIN) stages
            // the unwritten tail and arms EPOLLOUT instead of dropping it.
            if (!sink.failed and sink.len > 0) {
                if (resp_mod.writeNonBlockFD(conn_fd, sink.buf[0..sink.len])) |written| {
                    if (written < sink.len) {
                        const remaining = sink.buf[written..sink.len];
                        if (std.heap.smp_allocator.alloc(u8, remaining.len)) |staged| {
                            @memcpy(staged, remaining);
                            conn.write_pending = staged;
                            conn.write_pending_off = 0;
                            conn.write_pending_close = (outcome != .keep_alive);
                            conn.filled = 0;

                            var arm_ev = linux.epoll_event{
                                .events = linux.EPOLL.IN | linux.EPOLL.OUT | linux.EPOLL.RDHUP,
                                .data = .{ .u64 = @intCast(conn_fd) },
                            };
                            _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_MOD, conn_fd, &arm_ev);

                            continue;
                        } else |_| {
                            close_conn = true;
                        }
                    }
                } else {
                    close_conn = true;
                }
            }

            if (close_conn) {
                table.free(conn_fd);
                _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_DEL, conn_fd, null);
                _ = linux.close(conn_fd);
            } else {
                conn.filled = 0;
            }
        }

        epoll_timeout = 0;
    }
}

// --------------------------------------------------------- //
// EPOLL model

/// EPOLL dispatch: spawns shared-nothing event loop workers, each with its own
/// SO_REUSEPORT listener and epoll instance. Linux-only.
///
/// Note:
/// - The kernel distributes connections across per-worker listeners with no shared
///   accept queue and no cross-thread fd handoffs.
/// - workers = 0 (default): one worker per available CPU (respects cgroup mask).
/// - workers = N: exactly N workers.
///
/// Param:
/// server - anytype (pointer to the Server instance)
/// io - std.Io
///
/// Return:
/// - !void (exits only on setup failure, otherwise runs forever)
pub fn runEpoll(server: anytype, io: std.Io) !void {
    const cfg = server.config;
    const worker_count = if (cfg.workers == 0) getAvailableCpuCount() else cfg.workers;

    const threads = try std.heap.smp_allocator.alloc(std.Thread, worker_count);
    defer std.heap.smp_allocator.free(threads);

    // std.compress.flate.Compress is about 230 KB and is built on the handler's stack
    // frame, so a compressing handler (sendNegotiated) needs more than the default
    // 512 KB worker stack. Thread stacks are demand-paged, so the larger limit costs
    // almost no RSS, and the bump applies only when compression is enabled.
    const worker_stack: usize = if (cfg.compress) @max(cfg.worker_stack_size_bytes, cfg.worker_stack_compress_bytes) else cfg.worker_stack_size_bytes;

    // CBPF steering: one shared bind-order gate, alive until join().
    var bind_gate = reuseport.BindOrderGate{};
    const steering: ?reuseport.Steering = if (cfg.reuseport_cbpf) .{ .gate = &bind_gate, .group_size = worker_count } else null;

    // What every worker says about its own listeners, so a bind that fails inside a worker thread
    // reaches this frame instead of ending that thread and nothing else.
    var report = listen_report.Report.init(worker_count);

    for (threads, 0..) |*thread, idx| {
        thread.* = std.Thread.spawn(.{ .stack_size = worker_stack }, epollWorker, .{ server, io, idx, steering, &report }) catch |err| {
            logSystem(cfg, .ERROR, "could not spawn worker {d} of {d} ({s})", .{ idx, worker_count, @errorName(err) });
            report.abandon(io, worker_count - idx, err);

            for (threads[0..idx]) |spawned| spawned.join();

            return error.ZixHttpListenFailed;
        };
    }

    if (report.awaitGroup(io)) |err| {
        logSystem(cfg, .ERROR, "not listening on {s}:{d}: {d} of {d} workers could not bind ({s})", .{ cfg.ip, cfg.port, report.failures(), worker_count, @errorName(err) });

        for (threads) |thread| thread.join();

        return error.ZixHttpListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is nothing
    // to announce: the old line claimed a listener that may never have come up.
    logSystem(cfg, .INFO, "listening on {s}:{d} (epoll, {d} workers, shared-nothing)", .{
        cfg.ip, cfg.port, worker_count,
    });
    if (cfg.tls != null and cfg.tls_port != 0)
        logSystem(cfg, .INFO, "dual listener: https/1.1 TLS on {s}:{d} (same workers)", .{ cfg.ip, cfg.tls_port });

    for (threads) |thread| thread.join();
}
