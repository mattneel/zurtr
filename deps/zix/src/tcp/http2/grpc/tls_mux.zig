//! zix grpc https serve path, multiplexed (gRPC over TLS 1.3, RFC 8446 + 7540).
//!
//! What:
//! - The gRPC twin of ../tls_mux.zig: one SO_REUSEPORT listener + epoll instance per worker, each
//!   connection terminating TLS in place via the shared transport (multiplexers/tls_conn.zig), no
//!   socketpair, no thread per connection. recv ciphertext -> transport decrypts -> the resumable gRPC
//!   h2 mux (grpcMuxProcessRing) consumes plaintext -> its staged reply is encrypted back into TLS
//!   records through the frame write hook -> sent. A worker multiplexes thousands of TLS connections,
//!   so high concurrency no longer spawns a thread per connection (the thread-per-conn TLS path
//!   thrashes).

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const core = @import("core.zig");
const mux = @import("mux.zig");
const GrpcServerConfig = @import("config.zig").GrpcServerConfig;
const common = @import("dispatch/common.zig");
const listen_report = @import("../../../multiplexers/listen_report.zig");
const frame = @import("../frame.zig");
const Tls = @import("../../../tls/Tls.zig");
const record = @import("../../../tls/record.zig");
const tls_conn = @import("../../../multiplexers/tls_conn.zig");

const MAX_FD = common.MAX_FD;
const EPOLL_MAX_EVENTS: usize = 4096;

/// One sealed TLS record staging buffer: max record plaintext plus AEAD overhead.
const TLS_SEALED_RECORD_SIZE: usize = 18 * 1024;

/// Inbound ciphertext read staging (may hold several records per read).
const TLS_READ_STAGING_SIZE: usize = tls_conn.read_staging_size;

const allocator = std.heap.smp_allocator;

/// One multiplexed TLS connection: the shared byte transport (session + outbound backpressure
/// buffer), the gRPC h2 mux (allocated once the handshake establishes), and the plaintext record
/// accumulator.
/// One multiplexed TLS connection. Pub with ConnTable / onCiphertext / acceptAll: the
/// dual-listener loops (dispatch/epoll.zig, dispatch/uring.zig, config.tls_port) host the same
/// connections in the cleartext worker instead of a second fleet.
pub const TlsConn = struct {
    transport: tls_conn.Transport,
    grpc: ?*mux.GrpcMuxConn = null,
    opts: core.GrpcServeOpts,
    /// Io backend, carried for the GrpcMuxConn built at handshake. Worker-wide.
    io: std.Io,

    // Plaintext the mux emitted this pass, accumulated then sealed in record-sized chunks.
    plain: [record.max_plaintext]u8 = undefined,
    plain_len: usize = 0,
};

/// Per-worker fd -> TlsConn map (shared-nothing, one worker owns a connection for its lifetime).
pub const ConnTable = tls_conn.ConnTable(TlsConn, MAX_FD, freeConn);

fn freeConn(conn: *TlsConn) void {
    if (conn.grpc) |grpc_conn| grpc_conn.deinit();
    conn.transport.deinit();
    allocator.destroy(conn);
}

/// Seal the connection's accumulated plaintext into TLS records and send (staging on backpressure).
fn flushPlain(conn: *TlsConn) void {
    if (conn.plain_len == 0) return;

    var sealed: [TLS_SEALED_RECORD_SIZE]u8 = undefined;
    const plain_len = conn.plain_len;
    conn.plain_len = 0;
    if (!conn.transport.sendPlain(conn.plain[0..plain_len], &sealed)) conn.transport.wclose = true;
}

/// The frame write hook: the mux writes plaintext h2 frames here. The plaintext accumulates into
/// `plain` and seals in record-sized chunks. `ctx` is the *TlsConn the worker set before driving
/// the mux.
fn hookWrite(ctx: *anyopaque, bytes: []const u8) void {
    const conn: *TlsConn = @ptrCast(@alignCast(ctx));
    var rest = bytes;
    while (rest.len > 0) {
        if (conn.plain_len == conn.plain.len) flushPlain(conn);

        const n = @min(rest.len, conn.plain.len - conn.plain_len);
        @memcpy(conn.plain[conn.plain_len..][0..n], rest[0..n]);
        conn.plain_len += n;
        rest = rest[n..];
    }
}

/// What a peer gets when it hangs up part way through a request, over TLS: the same GOAWAY the
/// cleartext models send, sealed into a record first.
///
/// Note:
/// - Nothing is written for a connection with no request in flight, or for one that never finished
///   its handshake. Both close as ordinarily as they would in the clear.
/// - The connection is marked for close either way. The return value only says whether ciphertext is
///   still staged, so a caller that has to flush before closing knows to.
///
/// Param:
/// conn - *TlsConn (the connection whose peer just hung up)
///
/// Return:
/// - bool (true when staged ciphertext must be flushed before the close)
pub fn hangupGoaway(conn: *TlsConn) bool {
    const grpc_conn = conn.grpc orelse return false;
    if (!mux.requestInFlight(grpc_conn)) return false;

    frame.write_hook = hookWrite;
    frame.write_hook_ctx = conn;
    _ = mux.stageHangupGoaway(grpc_conn);
    grpc_conn.flushStage();
    flushPlain(conn);
    frame.write_hook = null;
    frame.write_hook_ctx = null;

    conn.transport.wclose = true;

    return conn.transport.wlen > conn.transport.woff;
}

/// Handle a readable TLS connection: decrypt available records, drive the handshake, then feed the
/// plaintext to the gRPC h2 mux and seal its reply. Returns false when the connection must close.
pub fn onReadable(comptime RouterType: type, conn: *TlsConn) bool {
    var cipher: [TLS_READ_STAGING_SIZE]u8 = undefined;

    while (true) {
        // Sized by what the session can take, not by the staging buffer. The staging buffer is wider
        // than one TLS record, so a busy socket (a large request in flight) would otherwise hand feed
        // two records at once, which it refuses by closing the connection.
        const room = conn.transport.tls.readRoom();
        if (room == 0) return false;

        const rc = linux.read(conn.transport.fd, &cipher, @min(cipher.len, room));
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return hangupGoaway(conn);
            },
            .INTR => continue,
            .AGAIN => return true,
            else => return false,
        }

        if (!onCiphertext(RouterType, conn, cipher[0..@intCast(rc)])) return false;
        if (conn.transport.wclose) return conn.transport.want_out; // flush, then close
    }
}

/// Feed one received ciphertext chunk through the session and the gRPC h2 mux. The
/// recv-model-agnostic core of onReadable: the .EPOLL paths call it under their own read loop, the
/// .URING path calls it per recv completion. Returns false when the connection must close now.
/// transport.wclose set with staged bytes means flush, then close.
pub fn onCiphertext(comptime RouterType: type, conn: *TlsConn, cipher: []const u8) bool {
    var to_send: [TLS_SEALED_RECORD_SIZE]u8 = undefined;
    var plain_in: [TLS_SEALED_RECORD_SIZE]u8 = undefined;

    const r = conn.transport.tls.feed(cipher, &to_send, &plain_in);

    if (r.to_send.len > 0 and !conn.transport.sendRaw(r.to_send)) return false;

    if (r.outcome == .established) {
        if (!conn.transport.tls.alpnIsH2()) return false;
        conn.grpc = mux.GrpcMuxConn.init(conn.transport.fd, conn.opts, conn.io) orelse return false;
    }

    if (r.outcome == .close) {
        conn.transport.wclose = true; // keep the conn only to flush a final alert
        return true;
    }

    if (r.plaintext.len > 0) {
        const grpc_conn = conn.grpc orelse return false;
        if (!feedMux(RouterType, conn, grpc_conn, r.plaintext)) return false;
    }

    return true;
}

/// Append decrypted plaintext to the mux read accumulator and drive one processing pass, sealing the
/// reply through the write hook. Returns false when the mux asks to close.
fn feedMux(comptime RouterType: type, conn: *TlsConn, grpc_conn: *mux.GrpcMuxConn, plaintext: []const u8) bool {
    if (grpc_conn.rstart == grpc_conn.rend) {
        grpc_conn.rstart = 0;
        grpc_conn.rend = 0;
    } else if (grpc_conn.rend == grpc_conn.rbuf.len) {
        const keep = grpc_conn.rend - grpc_conn.rstart;
        std.mem.copyForwards(u8, grpc_conn.rbuf[0..keep], grpc_conn.rbuf[grpc_conn.rstart..grpc_conn.rend]);
        grpc_conn.rstart = 0;
        grpc_conn.rend = keep;
    }

    if (plaintext.len > grpc_conn.rbuf.len - grpc_conn.rend) return false;
    @memcpy(grpc_conn.rbuf[grpc_conn.rend..][0..plaintext.len], plaintext);
    grpc_conn.rend += plaintext.len;

    frame.write_hook = hookWrite;
    frame.write_hook_ctx = conn;
    const outcome = mux.grpcMuxProcessRing(RouterType, grpc_conn);
    grpc_conn.flushStage(); // staged reply -> frame.writeAllFD -> hook -> encrypt
    flushPlain(conn);
    frame.write_hook = null;
    frame.write_hook_ctx = null;

    return outcome != .close;
}

/// Accept every pending TLS connection on listener_fd and register each in epfd with
/// `ev_tag | fd` as the event data. The TLS-only worker passes 0 (plain fd), the dual-listener
/// .EPOLL loop passes tls_conn.tls_event_tag so its one loop can route TLS events.
pub fn acceptAll(table: *ConnTable, epfd: posix.fd_t, listener_fd: posix.fd_t, ctx: *const Tls.Context, opts: core.GrpcServeOpts, ev_tag: u64, io: std.Io) void {
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
        conn.* = .{ .transport = tls_conn.Transport.init(fd, ctx), .opts = opts, .io = io };
        conn.transport.wbuf_initial = opts.tls_write_buf_initial;
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
    ctx: *const Tls.Context,
    opts: core.GrpcServeOpts,
    worker_id: usize,
    /// Where this worker says whether its listener came up, shared with the whole group.
    report: *listen_report.Report,
};

fn workerFn(comptime RouterType: type) fn (WorkerCtx) void {
    return struct {
        fn run(worker: WorkerCtx) void {
            // Pin to the worker's CPU slot (cgroup-mask aware) so a pinned cpuset does not
            // oversubscribe one core under a handshake storm (mirrors http1's tls_mux).
            common.pinToCpu(worker.worker_id);

            // Every exit between here and the event loop has to reach the group, or the
            // workers that did bind wait on one that is already gone.
            var slot = worker.report.slot(worker.io, error.ZixGrpcTlsWorkerSetupFailed);
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
                        acceptAll(&table, epfd, listener_fd, worker.ctx, worker.opts, 0, worker.io);
                        continue;
                    }

                    const conn = table.get(ev.data.fd) orelse continue;
                    var keep = true;

                    if ((ev.events & (linux.EPOLL.HUP | linux.EPOLL.ERR)) != 0) {
                        keep = false;
                    } else {
                        if ((ev.events & linux.EPOLL.OUT) != 0) keep = conn.transport.onWritable(epfd);
                        if (keep and (ev.events & linux.EPOLL.IN) != 0) keep = onReadable(RouterType, conn);
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
    }.run;
}

/// Listen and serve gRPC over TLS, multiplexed across one epoll worker per core.
pub fn runTlsMux(comptime RouterType: type, config: GrpcServerConfig) !void {
    const ctx = config.tls.?;
    const cpu = common.getAvailableCpuCount();
    const worker_count = if (config.workers == 0) cpu else config.workers;
    const opts = common.serveOpts(config);

    const workers = try allocator.alloc(std.Thread, worker_count);
    defer allocator.free(workers);

    // What every worker says about its own listener, so a bind that fails inside a worker thread
    // reaches this frame instead of ending that thread and nothing else.
    var report = listen_report.Report.init(worker_count);

    const wf = workerFn(RouterType);
    for (workers, 0..) |*t, i|
        t.* = std.Thread.spawn(.{ .stack_size = config.worker_stack_size_bytes }, wf, .{WorkerCtx{
            .io = config.io,
            .ip = config.ip,
            .port = config.port,
            .kernel_backlog = config.kernel_backlog,
            .ctx = ctx,
            .opts = opts,
            .worker_id = i,
            .report = &report,
        }}) catch |err| {
            common.logSystem(config, .ERROR, "could not spawn tls worker {d} of {d} ({s})", .{ i, worker_count, @errorName(err) });
            report.abandon(config.io, worker_count - i, err);

            for (workers[0..i]) |spawned| spawned.join();

            return error.ZixGrpcTlsListenFailed;
        };

    if (report.awaitGroup(config.io)) |err| {
        common.logSystem(config, .ERROR, "tls not listening on {s}:{d}: {d} of {d} workers could not bind ({s})", .{ config.ip, config.port, report.failures(), worker_count, @errorName(err) });

        for (workers) |t| t.join();

        return error.ZixGrpcTlsListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is nothing
    // to announce: the old line claimed a listener that may never have come up.
    common.logSystem(config, .INFO, "listening on {s}:{d} (grpc TLS, epoll-mux/{d})", .{ config.ip, config.port, worker_count });

    for (workers) |t| t.join();
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix grpc: a TLS connection that never handshook closes without a GOAWAY" {
    if (@import("builtin").os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var pair: [2]posix.fd_t = undefined;
    try std.testing.expect(posix.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const ctx = Tls.Context{
        .allocator = std.testing.allocator,
        .cert_der = &.{},
        .signing_key = .{ .ecdsa_p256 = try EcdsaP256.KeyPair.generateDeterministic(@splat(0x7)) },
        .alpn = &.{.H2},
        .curves = @import("../../../tls/context.zig").default_curves,
        .ciphers = @import("../../../tls/context.zig").default_ciphers,
        .min_version = .TLS_1_2,
        .max_version = .TLS_1_3,
        .prefer_server_ciphers = true,
        .hsts_max_age_s = 0,
    };

    var conn = TlsConn{ .transport = tls_conn.Transport.init(pair[1], &ctx), .opts = .{}, .io = undefined };
    defer conn.transport.deinit();

    // A peer that connects and drops before ALPN never opened a stream, so there is no request to
    // answer for and nothing to seal. This is the scanner case, and it must stay silent.
    try std.testing.expect(conn.grpc == null);
    try std.testing.expect(!hangupGoaway(&conn));
    try std.testing.expect(!conn.transport.wclose);
}

const tls_client = @import("../../../tls/client.zig");
const h2 = @import("../Http2.zig");

// Fixture leaf cert (ECDSA P-256, CN=localhost) and its signing key, shared with the tls client tests.
const fixture_cert_hex = "308201d43082017ba00302010202147a26ee491f091ac7c914f4a810c1ece713402574300a06082a8648ce3d040302302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f63301e170d3236303632323132353432305a170d3336303631393132353432305a302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f633059301306072a8648ce3d020106082a8648ce3d03010703420004c2a0121b298ac9cd389200e78d94e7bde1cc7cd8074795fab4f919799d40fdc231c5a90990ac8c6166ae472f33f74fced097f2edb7b8a1974be66a4ab07f253ba37f307d301d0603551d0e04160414c34e1d0a36a43947709b539e16dd0213aa4196aa301f0603551d23041830168014c34e1d0a36a43947709b539e16dd0213aa4196aa300f0603551d130101ff040530030101ff301a0603551d110413301182096c6f63616c686f737487047f000001300e0603551d0f0101ff040403020780300a06082a8648ce3d040302034700304402200b012f119db9b95d990bc482cb63e8f81e337a08634904e4caf513dc10c8aa8302202fdfe79ff6d5403e753ddf2aa52671923b8a2c28126bcbf196bd6fb7ecbcb14e";
const fixture_key_hex = "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c";

var tls_call_dispatches: usize = 0;
var tls_call_body_len: usize = 0;

fn tlsCallHandler(req: *core.GrpcRequest, _: *core.GrpcResponse, _: *core.GrpcContext) anyerror!void {
    tls_call_dispatches += 1;
    tls_call_body_len = if (req.recvMessage()) |msg| msg.len else 0;
}

const tls_call_router = core.Router(&[_]core.Route{.{ .path = "/svc.Svc/Method", .handler = tlsCallHandler }});

fn readExactBlocking(fd: posix.fd_t, buf: []u8) !void {
    var got: usize = 0;
    while (got < buf.len) {
        const rc = linux.read(fd, buf[got..].ptr, buf.len - got);
        if (posix.errno(rc) != .SUCCESS) return error.ReadFailed;
        if (rc == 0) return error.ZixEof;
        got += rc;
    }
}

/// Read one full TLS record (5-byte header + fragment) with blocking reads. Used only for the
/// handshake flight, where every byte is already buffered by the time the client reads.
fn readRecordBlocking(fd: posix.fd_t, buf: []u8) ![]const u8 {
    try readExactBlocking(fd, buf[0..5]);
    const len = std.mem.readInt(u16, buf[3..5], .big);
    try readExactBlocking(fd, buf[5 .. 5 + len]);

    return buf[0 .. 5 + len];
}

fn writeAllBlocking(fd: posix.fd_t, bytes: []const u8) !void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = linux.write(fd, bytes[sent..].ptr, bytes.len - sent);
        if (posix.errno(rc) != .SUCCESS) return error.WriteFailed;
        sent += rc;
    }
}

/// Drain whatever is readable now (non-blocking) onto the tail of `buf`, returning the new length.
fn drainNonblock(fd: posix.fd_t, buf: []u8, len: usize) usize {
    var total = len;
    while (total < buf.len) {
        const rc = linux.read(fd, buf[total..].ptr, buf.len - total);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) break;
                total += rc;
            },
            .INTR => continue,
            else => break, // AGAIN (drained) or a real error: stop here
        }
    }

    return total;
}

/// Build the fixture TLS context into caller-owned storage, so the context outlives no buffer it
/// points at. Only the certificate slice borrows, the signing key is held by value.
fn testTlsContext(cert_buf: *[512]u8) !Tls.Context {
    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

    var skey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&skey, fixture_key_hex);
    const server_key = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(skey));
    const cert_der = try std.fmt.hexToBytes(cert_buf, fixture_cert_hex);

    return .{
        .allocator = std.testing.allocator,
        .cert_der = cert_der,
        .signing_key = .{ .ecdsa_p256 = server_key },
        .alpn = &.{.H2},
        .curves = @import("../../../tls/context.zig").default_curves,
        .ciphers = @import("../../../tls/context.zig").default_ciphers,
        .min_version = .TLS_1_2,
        .max_version = .TLS_1_3,
        .prefer_server_ciphers = true,
        .hsts_max_age_s = 0,
    };
}

/// Run the TLS handshake against a server connection driven through onReadable, leaving both ends
/// established and ALPN-negotiated to h2. Returns the client session that speaks to it.
fn handshakeTlsConn(server_conn: *TlsConn, client_fd: posix.fd_t) !tls_client.ClientConnection {
    var ch_buf: [512]u8 = undefined;
    const started = try tls_client.start(.{ .client_random = @splat(0x11), .ephemeral_secret = @splat(0x42), .alpn = &.{.H2} }, &ch_buf);
    var state = started.state;

    var ch_rec: [600]u8 = undefined;
    ch_rec[0] = 22;
    std.mem.writeInt(u16, ch_rec[1..3], 0x0303, .big);
    std.mem.writeInt(u16, ch_rec[3..5], @intCast(started.client_hello.len), .big);
    @memcpy(ch_rec[5 .. 5 + started.client_hello.len], started.client_hello);
    try writeAllBlocking(client_fd, ch_rec[0 .. 5 + started.client_hello.len]);

    _ = onReadable(tls_call_router, server_conn);

    var flight_buf: [4096]u8 = undefined;
    var flen: usize = 0;
    for (0..3) |_| {
        const rec = try readRecordBlocking(client_fd, flight_buf[flen..]);
        flen += rec.len;
    }

    var fin_buf: [256]u8 = undefined;
    const finished = try tls_client.finish(&state, flight_buf[0..flen], &fin_buf);
    try writeAllBlocking(client_fd, finished.client_finished);

    _ = onReadable(tls_call_router, server_conn);
    _ = server_conn.grpc orelse return error.ZixHandshakeIncomplete;

    return finished.connection;
}

/// Encrypt and send the h2 connection preface plus an empty SETTINGS frame, which is what takes the
/// server's mux out of its await_preface phase and into h2 proper.
fn sendClientPreface(cc: *tls_client.ClientConnection, fd: posix.fd_t) !void {
    var plain: [64]u8 = undefined;
    @memcpy(plain[0..h2.PREFACE.len], h2.PREFACE);
    h2.encodeFrameHeader(plain[h2.PREFACE.len..][0..9], .{ .length = 0, .frame_type = h2.FRAME_TYPE_SETTINGS, .flags = 0, .stream_id = 0 });

    var enc: [256]u8 = undefined;
    try writeAllBlocking(fd, cc.writeAppData(plain[0 .. h2.PREFACE.len + 9], &enc));
}

/// Encrypt and send one h2 frame as its own TLS record, from caller-owned scratch so the frame may be
/// larger than a small header block.
fn sendClientFrame(cc: *tls_client.ClientConnection, fd: posix.fd_t, ftype: u8, flags: u8, sid: u31, payload: []const u8, plain: []u8, enc: []u8) !void {
    h2.encodeFrameHeader(plain[0..9], .{ .length = @intCast(payload.len), .frame_type = ftype, .flags = flags, .stream_id = sid });
    @memcpy(plain[9..][0..payload.len], payload);

    try writeAllBlocking(fd, cc.writeAppData(plain[0 .. 9 + payload.len], enc));
}

/// What the server answered with, decrypted from every record readable right now.
const TlsTally = struct {
    rst_protocol_error: usize = 0,
    goaway_protocol_error: usize = 0,
    header_frames: usize = 0,
};

fn tallyTlsWire(cc: *tls_client.ClientConnection, client_fd: posix.fd_t) TlsTally {
    var cipher: [64 * 1024]u8 = undefined;
    const cipher_len = drainNonblock(client_fd, &cipher, 0);

    var plain: [64 * 1024]u8 = undefined;
    var plain_len: usize = 0;
    var off: usize = 0;
    while (cipher_len - off >= 5) {
        const rec_len = std.mem.readInt(u16, cipher[off + 3 ..][0..2], .big);
        if (cipher_len - off < 5 + rec_len) break;

        const dec = cc.readAppData(cipher[off .. off + 5 + rec_len], plain[plain_len..]) catch break;
        plain_len += dec.len;
        off += 5 + rec_len;
    }

    var tally = TlsTally{};
    var foff: usize = 0;
    while (foff + 9 <= plain_len) {
        const fh = h2.parseFrameHeader(plain[foff..][0..9]);
        foff += 9;
        if (foff + fh.length > plain_len) break;

        switch (fh.frame_type) {
            h2.FRAME_TYPE_RST_STREAM => {
                if (std.mem.readInt(u32, plain[foff..][0..4], .big) == h2.ERR_PROTOCOL_ERROR) tally.rst_protocol_error += 1;
            },
            h2.FRAME_TYPE_GOAWAY => {
                if (std.mem.readInt(u32, plain[foff + 4 ..][0..4], .big) == h2.ERR_PROTOCOL_ERROR) tally.goaway_protocol_error += 1;
            },
            h2.FRAME_TYPE_HEADERS => tally.header_frames += 1,
            else => {},
        }
        foff += fh.length;
    }

    return tally;
}

/// Encode a call head declaring `content_length`, ending the headers but not the stream.
fn encodeTlsCallHead(block: []u8, content_length: []const u8) ![]const u8 {
    var enc = h2.HpackEncoder.init(block);
    try enc.writeHeader(":method", "POST");
    try enc.writeHeader(":path", "/svc.Svc/Method");
    try enc.writeHeader("content-length", content_length);

    return enc.encoded();
}

/// Stand up a handshaken, prefaced gRPC-over-TLS connection on a socketpair.
fn openTlsCall(server_conn: *TlsConn, pair: [2]posix.fd_t) !tls_client.ClientConnection {
    var client = try handshakeTlsConn(server_conn, pair[0]);
    common.setNonBlock(pair[0]);
    _ = tallyTlsWire(&client, pair[0]);

    try sendClientPreface(&client, pair[0]);
    _ = onReadable(tls_call_router, server_conn);
    _ = tallyTlsWire(&client, pair[0]);

    return client;
}

test "zix grpc: gRPC over TLS resets a stream whose body is short of its content-length" {
    if (@import("builtin").os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var cert_buf: [512]u8 = undefined;
    const ctx = try testTlsContext(&cert_buf);

    var pair: [2]posix.fd_t = undefined;
    try std.testing.expect(posix.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    common.setNonBlock(pair[1]);

    var server_conn = TlsConn{ .transport = tls_conn.Transport.init(pair[1], &ctx), .opts = .{ .max_streams = 16, .max_body = 65536 }, .io = undefined };
    defer if (server_conn.grpc) |grpc_conn| grpc_conn.deinit();
    defer server_conn.transport.deinit();

    var client = try openTlsCall(&server_conn, pair);

    var scratch: [1024]u8 = undefined;
    var enc: [2048]u8 = undefined;
    var block: [256]u8 = undefined;

    // 100 bytes promised, 40 delivered, then END_STREAM: the message never finished arriving
    const head = try encodeTlsCallHead(&block, "100");
    try sendClientFrame(&client, pair[0], h2.FRAME_TYPE_HEADERS, h2.FLAG_END_HEADERS, 1, head, &scratch, &enc);

    const short: [40]u8 = @splat('x');
    try sendClientFrame(&client, pair[0], h2.FRAME_TYPE_DATA, h2.FLAG_END_STREAM, 1, &short, &scratch, &enc);

    tls_call_dispatches = 0;
    _ = onReadable(tls_call_router, &server_conn);

    // the guard runs inside the same mux the cleartext models drive, and its answer seals into a
    // record like any other frame
    try std.testing.expectEqual(@as(usize, 0), tls_call_dispatches);

    const tally = tallyTlsWire(&client, pair[0]);

    try std.testing.expectEqual(@as(usize, 1), tally.rst_protocol_error);
    try std.testing.expectEqual(@as(usize, 0), tally.header_frames);
}

test "zix grpc: gRPC over TLS answers a peer that hangs up with a request unfinished" {
    if (@import("builtin").os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var cert_buf: [512]u8 = undefined;
    const ctx = try testTlsContext(&cert_buf);

    var pair: [2]posix.fd_t = undefined;
    try std.testing.expect(posix.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    common.setNonBlock(pair[1]);

    var server_conn = TlsConn{ .transport = tls_conn.Transport.init(pair[1], &ctx), .opts = .{ .max_streams = 16, .max_body = 65536 }, .io = undefined };
    defer if (server_conn.grpc) |grpc_conn| grpc_conn.deinit();
    defer server_conn.transport.deinit();

    var client = try openTlsCall(&server_conn, pair);

    var scratch: [1024]u8 = undefined;
    var enc: [2048]u8 = undefined;
    var block: [256]u8 = undefined;

    // a call that opens its stream and never ends it: the message is still on its way
    const head = try encodeTlsCallHead(&block, "100");
    try sendClientFrame(&client, pair[0], h2.FRAME_TYPE_HEADERS, h2.FLAG_END_HEADERS, 1, head, &scratch, &enc);

    _ = onReadable(tls_call_router, &server_conn);
    _ = tallyTlsWire(&client, pair[0]);

    try std.testing.expect(mux.requestInFlight(server_conn.grpc.?));
    _ = hangupGoaway(&server_conn);

    const tally = tallyTlsWire(&client, pair[0]);

    try std.testing.expectEqual(@as(usize, 1), tally.goaway_protocol_error);
    try std.testing.expect(server_conn.transport.wclose);
}

test "zix grpc: gRPC over TLS serves a request body spanning several TLS records" {
    if (@import("builtin").os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var cert_buf: [512]u8 = undefined;
    const ctx = try testTlsContext(&cert_buf);

    var pair: [2]posix.fd_t = undefined;
    try std.testing.expect(posix.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = linux.close(pair[0]);
    defer _ = linux.close(pair[1]);

    common.setNonBlock(pair[1]);

    var server_conn = TlsConn{ .transport = tls_conn.Transport.init(pair[1], &ctx), .opts = .{ .max_streams = 16, .max_body = 65536 }, .io = undefined };
    defer if (server_conn.grpc) |grpc_conn| grpc_conn.deinit();
    defer server_conn.transport.deinit();

    var client = try openTlsCall(&server_conn, pair);

    const chunk_len: usize = 13000;
    const chunks: usize = 3;
    const body_len = chunk_len * chunks;

    const scratch = try std.testing.allocator.alloc(u8, chunk_len + 64);
    defer std.testing.allocator.free(scratch);
    const enc = try std.testing.allocator.alloc(u8, chunk_len + 512);
    defer std.testing.allocator.free(enc);

    var block: [256]u8 = undefined;
    const head = try encodeTlsCallHead(&block, "39000");
    try sendClientFrame(&client, pair[0], h2.FRAME_TYPE_HEADERS, h2.FLAG_END_HEADERS, 1, head, scratch, enc);

    // Three DATA frames, one TLS record each, all sitting in the socket before the server reads.
    // That is the condition the session's single-record reassembly buffer could not survive: a read
    // wide enough to scoop up more than one record and hand them over together. The first frame
    // carries the 5-byte gRPC length prefix so the message the handler reads is whole too.
    const payload = try std.testing.allocator.alloc(u8, chunk_len);
    defer std.testing.allocator.free(payload);
    @memset(payload, 'u');
    std.mem.writeInt(u32, payload[1..5], @intCast(body_len - 5), .big);
    payload[0] = 0;

    for (0..chunks) |idx| {
        const flags: u8 = if (idx == chunks - 1) h2.FLAG_END_STREAM else 0;
        try sendClientFrame(&client, pair[0], h2.FRAME_TYPE_DATA, flags, 1, payload, scratch, enc);
    }

    tls_call_dispatches = 0;
    tls_call_body_len = 0;
    _ = onReadable(tls_call_router, &server_conn);

    // the whole body reached the handler, and the connection is still alive to answer
    try std.testing.expectEqual(@as(usize, 1), tls_call_dispatches);
    try std.testing.expectEqual(body_len - 5, tls_call_body_len);

    const tally = tallyTlsWire(&client, pair[0]);

    try std.testing.expectEqual(@as(usize, 0), tally.rst_protocol_error);
}
