//! zix http https serve path, event-driven (https/1.1 over TLS 1.3, RFC 8446 + 9112).
//!
//! What:
//! - One SO_REUSEPORT listener + epoll instance per worker, like the cleartext .EPOLL model, but each
//!   connection terminates TLS in place via the shared transport (multiplexers/tls_conn.zig), no
//!   thread per connection. recv ciphertext -> transport decrypts -> plaintext feeds the request loop
//!   -> the router response is captured (the existing response sink, reused via
//!   tls_serve.processRequestToBuffer) -> encrypted back into TLS records -> sent. A worker
//!   multiplexes thousands of TLS connections.
//! - Keep-alive: a connection serves requests in a loop over the established session. Writes are
//!   non-blocking: on EAGAIN the unsent ciphertext is staged per connection and EPOLLOUT is armed.
//! - Cpuset-aware worker count + per-core pin (common.getAvailableCpuCount / common.pinToCpu), so a
//!   cgroup-pinned cpuset does not oversubscribe a core under a handshake storm (matches http1).
//! - Streaming (res.stream, SSE) is hosted via the per-connection stream sink: each write seals
//!   records through the transport, staging on backpressure. WebSocket stays on the
//!   thread-per-connection path (the cleartext mux loop does not host WS either).
//! - The Worker machinery (TlsConn, ConnTable, onReadable, acceptAll) is pub: the dual-listener
//!   loops (dispatch/epoll.zig, dispatch/uring.zig, config.tls_port) host the same connections in
//!   the cleartext worker instead of a second fleet.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const common = @import("dispatch/common.zig");
const listen_report = @import("../../multiplexers/listen_report.zig");
const parser = @import("parser.zig");
const ws = @import("websocket.zig");
const resp = @import("response.zig");
const tls_serve = @import("tls_serve.zig");
const Tls = @import("../../tls/Tls.zig");
const tls_conn = @import("../../multiplexers/tls_conn.zig");
const record = @import("../../tls/record.zig");

const MAX_FD = common.MAX_FD;
const EPOLL_MAX_EVENTS: usize = 4096;
const allocator = std.heap.smp_allocator;

const TLS_READ_STAGING_SIZE: usize = tls_conn.read_staging_size;
/// Sealed response staging: room for every record a full-size response takes, since a response past
/// one record's worth of plaintext is split across several and each pays its own header and tag.
const TLS_SEALED_OUT_SIZE: usize = record.sealedLen(RESPONSE_BUF_SIZE);
const TLS_PLAIN_STAGING_SIZE: usize = 32 * 1024;
const REQUEST_BUF_SIZE: usize = 17 * 1024;
const RESPONSE_BUF_SIZE: usize = 64 * 1024;

/// Listen and serve https/1.1 over TLS, multiplexed across one epoll worker per core. Generic over the
/// server type (the comptime-baked router), so the worker machinery is instantiated per server.
pub fn runTlsMux(server: anytype, io: std.Io) !void {
    return Worker(@TypeOf(server)).run(server, io);
}

pub fn Worker(comptime Server: type) type {
    return struct {
        /// One TLS connection: the shared byte transport (session + outbound backpressure buffer),
        /// the request accumulator, and the server pointer (for the router).
        pub const TlsConn = struct {
            transport: tls_conn.Transport,
            server: Server,
            ctx: *const Tls.Context,

            rbuf: [REQUEST_BUF_SIZE]u8 = undefined,
            rlen: usize = 0,
        };

        pub const ConnTable = tls_conn.ConnTable(TlsConn, MAX_FD, freeConn);

        fn freeConn(conn: *TlsConn) void {
            conn.transport.deinit();
            allocator.destroy(conn);
        }

        /// Encrypt response plaintext into TLS records and send (staging on backpressure).
        fn sendPlain(conn: *TlsConn, plaintext: []const u8) bool {
            var sealed: [TLS_SEALED_OUT_SIZE]u8 = undefined;

            return conn.transport.sendPlain(plaintext, &sealed);
        }

        /// Stream-sink write (res.stream, SSE): seal the plaintext into records and send through
        /// the transport, staging on backpressure. Chunked, so one oversized write never
        /// overflows the sealed staging buffer.
        fn streamWrite(ctx_ptr: *anyopaque, plaintext: []const u8) bool {
            const transport: *tls_conn.Transport = @ptrCast(@alignCast(ctx_ptr));

            var rest = plaintext;
            while (rest.len > 0) {
                const n = @min(rest.len, RESPONSE_BUF_SIZE);
                var sealed: [TLS_SEALED_OUT_SIZE]u8 = undefined;
                if (!transport.sendPlain(rest[0..n], &sealed)) return false;
                rest = rest[n..];
            }

            return true;
        }

        /// Handle a readable TLS connection: decrypt records, drive the handshake, feed plaintext to the
        /// request loop, seal replies. Returns false when the connection must close.
        pub fn onReadable(conn: *TlsConn, io: std.Io, arena: *std.heap.ArenaAllocator) bool {
            var cipher: [TLS_READ_STAGING_SIZE]u8 = undefined;

            while (true) {
                const rc = linux.read(conn.transport.fd, &cipher, cipher.len);
                switch (posix.errno(rc)) {
                    .SUCCESS => {
                        if (rc == 0) return false;
                    },
                    .INTR => continue,
                    .AGAIN => return true,
                    else => return false,
                }

                if (!onCiphertext(conn, cipher[0..@intCast(rc)], io, arena)) return false;
                if (conn.transport.wclose) return conn.transport.want_out; // flush, then close
            }
        }

        /// Feed one received ciphertext chunk through the session and the request loop. The
        /// recv-model-agnostic core of onReadable: the .EPOLL paths call it under their own read
        /// loop, the .URING path calls it per recv completion. Returns false when the connection
        /// must close now. transport.wclose set with staged bytes means flush, then close.
        pub fn onCiphertext(conn: *TlsConn, cipher: []const u8, io: std.Io, arena: *std.heap.ArenaAllocator) bool {
            var to_send: [TLS_SEALED_OUT_SIZE]u8 = undefined;
            var plain_in: [TLS_PLAIN_STAGING_SIZE]u8 = undefined;

            const r = conn.transport.tls.feed(cipher, &to_send, &plain_in);

            if (r.to_send.len > 0 and !conn.transport.sendRaw(r.to_send)) return false;

            if (r.outcome == .close) {
                conn.transport.wclose = true; // keep the conn only to flush a final alert
                return true;
            }

            if (r.plaintext.len > 0) {
                if (!feedRequests(conn, r.plaintext, io, arena)) return false;
            }

            return true;
        }

        /// Accumulate decrypted plaintext and dispatch every complete request now buffered (pipelined
        /// requests drain in one pass). Returns false on a fatal write, sets transport.wclose otherwise.
        fn feedRequests(conn: *TlsConn, plaintext: []const u8, io: std.Io, arena: *std.heap.ArenaAllocator) bool {
            const cfg = conn.server.config;

            if (plaintext.len > conn.rbuf.len - conn.rlen) {
                conn.transport.wclose = true;
                return true;
            }

            @memcpy(conn.rbuf[conn.rlen..][0..plaintext.len], plaintext);
            conn.rlen += plaintext.len;

            // The per-connection stream sink (ADR-054): a handler that calls res.stream (SSE)
            // detaches the buffered capture, and every subsequent write seals records through the
            // transport, staging on backpressure instead of parking the worker.
            var stream_sink = resp.TlsStreamSink{ .ctx = &conn.transport, .writeFn = streamWrite };
            resp.tl_tls_stream = &stream_sink;
            defer resp.tl_tls_stream = null;

            var response_buf: [RESPONSE_BUF_SIZE]u8 = undefined;

            while (conn.rlen > 0) {
                // Answer before closing, the same way the 421 branch below does. A
                // silent drop leaves the client unable to tell a refused method from
                // a dead connection, and the session is established, so the status
                // can be sent.
                const maybe_head = parser.parse(conn.rbuf[0..conn.rlen], cfg.max_request_headers.value()) catch |err| {
                    _ = sendPlain(conn, resp.parseErrorResponse(err));
                    conn.transport.wclose = true;
                    return true;
                };
                const head = maybe_head orelse return true; // incomplete head: wait for more
                if (head.chunked) {
                    conn.transport.wclose = true; // chunked bodies are out of scope for the TLS cut
                    return true;
                }
                const total = head.body_offset + head.content_length;
                if (conn.rlen < total) return true; // wait for the full body

                // RFC 9110 7.4: a request for an authority this cert does not serve is misdirected (421).
                if (tls_serve.hostFromHead(conn.rbuf[0..head.body_offset])) |host_raw| {
                    const host = tls_serve.stripPort(host_raw);
                    Tls.verifyCertIdentity(conn.ctx.cert_der, host) catch {
                        const misdirected = "HTTP/1.1 421 Misdirected Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                        _ = sendPlain(conn, misdirected);
                        conn.transport.wclose = true;
                        return true;
                    };
                }

                const cap = tls_serve.processRequestToBuffer(conn.server, io, conn.rbuf[0..total], &response_buf, arena) catch {
                    _ = ws.takeWebSocket(); // the multiplexed path does not host WS (ADR-055), drop any handoff
                    conn.transport.wclose = true; // ResponseTooLarge: close
                    return true;
                };
                _ = ws.takeWebSocket(); // WS stays on the thread path: drop any handoff

                // A streamed response (res.stream) already left through the stream sink.
                if (stream_sink.failed) return false;
                if (!cap.streamed and !sendPlain(conn, cap.bytes)) return false;

                const remaining = conn.rlen - total;
                if (remaining > 0) std.mem.copyForwards(u8, conn.rbuf[0..remaining], conn.rbuf[total..conn.rlen]);
                conn.rlen = remaining;

                if (cap.outcome == .close) {
                    var close_buf: [64]u8 = undefined;
                    _ = conn.transport.sendRaw(conn.transport.tls.closeNotify(&close_buf));
                    conn.transport.wclose = true;
                    return true;
                }
            }

            return true;
        }

        /// Accept every pending TLS connection on listener_fd and register each in epfd with
        /// `ev_tag | fd` as the event data. The TLS-only worker passes 0 (plain fd), the
        /// dual-listener .EPOLL loop passes tls_conn.tls_event_tag so its one loop can route
        /// TLS events.
        pub fn acceptAll(table: *ConnTable, epfd: posix.fd_t, listener_fd: posix.fd_t, server: Server, ctx: *const Tls.Context, ev_tag: u64) void {
            while (true) {
                const rc = linux.accept4(listener_fd, null, null, posix.SOCK.NONBLOCK | posix.SOCK.CLOEXEC);
                switch (posix.errno(rc)) {
                    .SUCCESS => {},
                    .AGAIN => return,
                    .INTR, .CONNABORTED => continue,
                    else => return,
                }

                const fd: posix.fd_t = @intCast(rc);
                common.setNoDelay(fd);

                const idx: usize = @intCast(fd);
                if (idx >= table.slots.len) {
                    _ = linux.close(fd);
                    continue;
                }

                const conn = allocator.create(TlsConn) catch {
                    _ = linux.close(fd);
                    continue;
                };
                conn.* = .{
                    .transport = tls_conn.Transport.init(fd, ctx),
                    .server = server,
                    .ctx = ctx,
                };
                conn.transport.ep_data = ev_tag | @as(u64, @intCast(fd));
                table.put(fd, conn);

                var ev = linux.epoll_event{ .events = linux.EPOLL.IN | linux.EPOLL.RDHUP, .data = .{ .u64 = conn.transport.ep_data } };
                if (posix.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, fd, &ev)) != .SUCCESS) {
                    table.drop(fd);
                    _ = linux.close(fd);
                }
            }
        }

        const WorkerCtx = struct {
            io: std.Io,
            ip: []const u8,
            port: u16,
            kernel_backlog: u31,
            max_allocator_size: usize,
            worker_id: usize,
            server: Server,
            ctx: *const Tls.Context,
            /// Where this worker says whether its listener came up, shared with the whole group.
            report: *listen_report.Report,
        };

        fn workerRun(worker: WorkerCtx) void {
            common.pinToCpu(worker.worker_id);

            // Every exit between here and the event loop has to reach the group, or the
            // workers that did bind wait on one that is already gone.
            var slot = worker.report.slot(worker.io, error.ZixHttpTlsWorkerSetupFailed);
            defer slot.close();

            const addr = std.Io.net.IpAddress.resolve(worker.io, worker.ip, worker.port) catch |err| {
                slot.fail(err);

                return;
            };
            var srv = addr.listen(worker.io, .{ .reuse_address = true, .kernel_backlog = worker.kernel_backlog }) catch |err| {
                slot.fail(err);

                return;
            };
            defer srv.deinit(worker.io);
            const listener_fd = srv.socket.handle;
            common.setNonBlock(listener_fd);

            const epfd_rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
            if (posix.errno(epfd_rc) != .SUCCESS) return;
            const epfd: posix.fd_t = @intCast(epfd_rc);
            defer _ = linux.close(epfd);

            var lev = linux.epoll_event{ .events = linux.EPOLL.IN, .data = .{ .fd = listener_fd } };
            if (posix.errno(linux.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, listener_fd, &lev)) != .SUCCESS) return;

            var table = ConnTable.init() catch return;
            defer table.deinit();

            // One per-worker arena, reset per request inside processRequestToBuffer (shared-nothing,
            // one request processed at a time on this thread).
            var arena = std.heap.ArenaAllocator.init(allocator);
            defer arena.deinit();
            _ = arena.allocator().alloc(u8, worker.max_allocator_size) catch {};
            _ = arena.reset(.retain_capacity);

            // Serve only once every worker is up, so a group where one bind failed serves on none
            // of them and the caller gets one honest failure.
            slot.ok();
            if (worker.report.awaitGroup(worker.io) != null) return;

            var events: [EPOLL_MAX_EVENTS]linux.epoll_event = undefined;
            while (true) {
                const wait_rc = linux.epoll_wait(epfd, &events, EPOLL_MAX_EVENTS, -1);
                switch (posix.errno(wait_rc)) {
                    .SUCCESS => {},
                    .INTR => continue,
                    else => return,
                }

                for (events[0..@intCast(wait_rc)]) |ev| {
                    if (ev.data.fd == listener_fd) {
                        acceptAll(&table, epfd, listener_fd, worker.server, worker.ctx, 0);
                        continue;
                    }

                    const conn = table.get(ev.data.fd) orelse continue;
                    var keep = true;

                    if ((ev.events & (linux.EPOLL.HUP | linux.EPOLL.ERR)) != 0) {
                        keep = false;
                    } else {
                        if ((ev.events & linux.EPOLL.OUT) != 0) keep = conn.transport.onWritable(epfd);
                        if (keep and (ev.events & linux.EPOLL.IN) != 0) keep = onReadable(conn, worker.io, &arena);
                        if (keep and conn.transport.want_out) tls_conn.armOut(epfd, conn.transport.fd, conn.transport.ep_data, true);
                        if (keep and conn.transport.wclose and !conn.transport.want_out) keep = false;
                    }

                    if (!keep) {
                        _ = linux.epoll_ctl(epfd, linux.EPOLL.CTL_DEL, ev.data.fd, null);
                        table.drop(ev.data.fd);
                        _ = linux.close(ev.data.fd);
                    }
                }
            }
        }

        fn run(server: Server, io: std.Io) !void {
            const cfg = server.config;
            const ctx = cfg.tls.?;
            // Cpuset-aware count, NOT the host CPU count, so a cgroup-pinned server does not spawn
            // host-many workers onto a few cores (matches the cleartext .EPOLL model and http1).
            const cpu = common.getAvailableCpuCount();
            const worker_count = if (cfg.workers == 0) cpu else cfg.workers;

            const threads = try allocator.alloc(std.Thread, worker_count);
            defer allocator.free(threads);

            // What every worker says about its own listener, so a bind that fails inside a
            // worker thread reaches this frame instead of ending that thread and nothing else.
            var report = listen_report.Report.init(worker_count);

            for (threads, 0..) |*t, i|
                t.* = std.Thread.spawn(.{ .stack_size = cfg.worker_stack_size_bytes }, workerRun, .{WorkerCtx{
                    .io = io,
                    .ip = cfg.ip,
                    .port = cfg.port,
                    .kernel_backlog = cfg.kernel_backlog,
                    .max_allocator_size = cfg.max_allocator_size,
                    .worker_id = i,
                    .server = server,
                    .ctx = ctx,
                    .report = &report,
                }}) catch |err| {
                    common.logSystem(cfg, .ERROR, "could not spawn tls worker {d} of {d} ({s})", .{ i, worker_count, @errorName(err) });
                    report.abandon(io, worker_count - i, err);

                    for (threads[0..i]) |spawned| spawned.join();

                    return error.ZixHttpTlsListenFailed;
                };

            if (report.awaitGroup(io)) |err| {
                common.logSystem(cfg, .ERROR, "tls not listening on {s}:{d}: {d} of {d} workers could not bind ({s})", .{ cfg.ip, cfg.port, report.failures(), worker_count, @errorName(err) });

                for (threads) |t| t.join();

                return error.ZixHttpTlsListenFailed;
            }

            // Announced here rather than above the spawn, because until the group reports there is
            // nothing to announce: the old line claimed a listener that may never have come up.
            common.logSystem(cfg, .INFO, "listening on {s}:{d} (https/1.1 TLS, epoll-mux/{d})", .{ cfg.ip, cfg.port, worker_count });

            for (threads) |t| t.join();
        }
    };
}
