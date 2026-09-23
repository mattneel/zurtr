//! zix http2 https serve path, multiplexed (h2 over TLS 1.3, RFC 8446 + 7540).
//!
//! What:
//! - One SO_REUSEPORT listener + epoll instance per worker, like the cleartext .EPOLL model, but each
//!   connection terminates TLS in place via the shared transport (multiplexers/tls_conn.zig), no
//!   socketpair, no thread per connection. recv ciphertext -> transport decrypts -> the resumable h2
//!   mux (mux.zig) consumes plaintext -> the mux's reply frames are encrypted back into TLS records
//!   through the frame write hook -> sent. A worker multiplexes thousands of TLS connections, so high
//!   concurrency no longer spawns thousands of threads (the thread-per-conn TLS path thrashes there).
//! - Writes are non-blocking: on EAGAIN the unsent ciphertext is staged per connection and EPOLLOUT is
//!   armed, so a slow client never parks the worker.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const core = @import("core.zig");
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Context = @import("context.zig").Context;
const Http2ServerConfig = @import("config.zig").Http2ServerConfig;
const common = @import("dispatch/common.zig");
const listen_report = @import("../../multiplexers/listen_report.zig");
const mux = @import("mux.zig");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");
const Tls = @import("../../tls/Tls.zig");
const record = @import("../../tls/record.zig");
const tls_conn = @import("../../multiplexers/tls_conn.zig");

const MAX_FD = common.MAX_FD;
const EPOLL_MAX_EVENTS: usize = 4096;

/// One sealed TLS record staging buffer: max record plaintext plus AEAD overhead.
const TLS_SEALED_RECORD_SIZE: usize = 18 * 1024;

/// Inbound ciphertext read staging (may hold several records per read).
const TLS_READ_STAGING_SIZE: usize = tls_conn.read_staging_size;
const allocator = std.heap.smp_allocator;

/// One multiplexed TLS connection: the shared byte transport (session + outbound backpressure
/// buffer), the h2 mux (allocated once the handshake establishes), and the plaintext record
/// accumulator. Pub with ConnTable / onCiphertext / acceptAll: the dual-listener loops
/// (dispatch/epoll.zig, dispatch/uring.zig, config.tls_port) host the same connections in the
/// cleartext worker instead of a second fleet.
pub const TlsConn = struct {
    transport: tls_conn.Transport,
    h2: ?*mux.MuxConn = null,
    opts: core.ServeOpts,
    /// Io backend, carried for the h2 mux Context built at each dispatch. Worker-wide.
    io: std.Io,

    // Plaintext the mux emitted this pass, accumulated then sealed in record-sized chunks.
    plain: [record.max_plaintext]u8 = undefined,
    plain_len: usize = 0,
};

/// Per-worker fd -> TlsConn map (shared-nothing, one worker owns a connection for its lifetime).
pub const ConnTable = tls_conn.ConnTable(TlsConn, MAX_FD, freeConn);

fn freeConn(conn: *TlsConn) void {
    if (conn.h2) |h2| h2.deinit();
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

/// Seal-in-place toggle. true: seal a full record straight from source via the gather encrypt, so a
/// large DATA payload is not copied into `plain` first. false: accumulate into `plain` and seal there
/// (the pre-seal-in-place path). Comptime, so the effect can be A/B'd against an otherwise identical
/// build without changing any other behavior.
const seal_in_place = true;

/// Seal one full record (the staged prefix gathered with a slice of the source) and send. Avoids
/// copying the source slice into `plain` first. prefix.len + tail.len == plain.len (a full record).
/// Ordering matches flushPlain: records leave in sequence order through the transport.
fn sealGather(conn: *TlsConn, prefix: []const u8, tail: []const u8) void {
    var sealed: [TLS_SEALED_RECORD_SIZE]u8 = undefined;
    if (!conn.transport.sendPlainGather(prefix, tail, &sealed)) conn.transport.wclose = true;
}

/// The frame write hook: the mux writes plaintext h2 frames here. With seal_in_place a full record (the
/// staged prefix plus this write) is sealed straight from source, so a large DATA payload is not copied
/// into `plain` first, only the sub-record remainder is staged. Otherwise the plaintext accumulates
/// into `plain` and seals when it fills. `ctx` is the *TlsConn the worker set before driving the mux.
fn hookWrite(ctx: *anyopaque, bytes: []const u8) void {
    const conn: *TlsConn = @ptrCast(@alignCast(ctx));
    var rest = bytes;

    if (seal_in_place) {
        // Seal every full record that the staged prefix plus `rest` completes, gathering the staged
        // bytes with a slice of `rest` straight from source (no bulk copy of the payload into `plain`).
        while (conn.plain_len + rest.len >= conn.plain.len) {
            const take = conn.plain.len - conn.plain_len;
            sealGather(conn, conn.plain[0..conn.plain_len], rest[0..take]);
            conn.plain_len = 0;
            rest = rest[take..];
        }

        @memcpy(conn.plain[conn.plain_len..][0..rest.len], rest[0..rest.len]);
        conn.plain_len += rest.len;

        return;
    }

    // Accumulate-then-seal: stage into `plain`, flushing a full record when it fills.
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
    const h2 = conn.h2 orelse return false;
    if (!mux.requestInFlight(h2)) return false;

    frame.write_hook = hookWrite;
    frame.write_hook_ctx = conn;
    _ = mux.hangupGoaway(h2);
    flushPlain(conn);
    frame.write_hook = null;
    frame.write_hook_ctx = null;

    conn.transport.wclose = true;

    return conn.transport.wlen > conn.transport.woff;
}

/// Handle a readable TLS connection: decrypt available records, drive the handshake, then feed the
/// plaintext to the h2 mux and seal its reply. Returns false when the connection must close.
pub fn onReadable(handler: core.HandlerFn, conn: *TlsConn) bool {
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
                if (rc == 0) return hangupGoaway(conn); // peer closed
            },
            .INTR => continue,
            .AGAIN => return true, // drained
            else => return false,
        }

        if (!onCiphertext(handler, conn, cipher[0..@intCast(rc)])) return false;
        if (conn.transport.wclose) return conn.transport.want_out; // flush, then close
    }
}

/// Feed one received ciphertext chunk through the session and the h2 mux. The recv-model-agnostic
/// core of onReadable: the .EPOLL paths call it under their own read loop, the .URING path calls
/// it per recv completion. Returns false when the connection must close now. transport.wclose set
/// with staged bytes means flush, then close.
pub fn onCiphertext(handler: core.HandlerFn, conn: *TlsConn, cipher: []const u8) bool {
    var to_send: [TLS_SEALED_RECORD_SIZE]u8 = undefined;
    var plain_in: [TLS_SEALED_RECORD_SIZE]u8 = undefined;

    const r = conn.transport.tls.feed(cipher, &to_send, &plain_in);

    if (r.to_send.len > 0 and !conn.transport.sendRaw(r.to_send)) return false;

    if (r.outcome == .established) {
        if (!conn.transport.tls.alpnIsH2()) return false;
        conn.h2 = mux.MuxConn.init(conn.transport.fd, conn.opts, conn.io) orelse return false;
    }

    if (r.outcome == .close) {
        conn.transport.wclose = true; // keep the conn only to flush a final alert
        return true;
    }

    if (r.plaintext.len > 0) {
        const h2 = conn.h2 orelse return false;
        if (!feedMux(handler, conn, h2, r.plaintext)) return false;
    }

    return true;
}

/// Append decrypted plaintext to the mux read accumulator and drive one processing pass, sealing the
/// reply through the write hook. Returns false when the mux asks to close.
fn feedMux(handler: core.HandlerFn, conn: *TlsConn, h2: *mux.MuxConn, plaintext: []const u8) bool {
    // Compact, then append (a record is <= 16 KiB, the mux rbuf is >= 32 KiB).
    if (h2.rstart == h2.rend) {
        h2.rstart = 0;
        h2.rend = 0;
    } else if (h2.rend == h2.rbuf.len) {
        const keep = h2.rend - h2.rstart;
        std.mem.copyForwards(u8, h2.rbuf[0..keep], h2.rbuf[h2.rstart..h2.rend]);
        h2.rstart = 0;
        h2.rend = keep;
    }

    if (plaintext.len > h2.rbuf.len - h2.rend) return false;
    @memcpy(h2.rbuf[h2.rend..][0..plaintext.len], plaintext);
    h2.rend += plaintext.len;

    frame.write_hook = hookWrite;
    frame.write_hook_ctx = conn;
    const outcome = mux.processRing(handler, h2);
    flushPlain(conn);
    frame.write_hook = null;
    frame.write_hook_ctx = null;

    return outcome != .close;
}

/// Accept every pending TLS connection on listener_fd and register each in epfd with
/// `ev_tag | fd` as the event data. The TLS-only worker passes 0 (plain fd), the dual-listener
/// .EPOLL loop passes tls_conn.tls_event_tag so its one loop can route TLS events.
pub fn acceptAll(table: *ConnTable, epfd: posix.fd_t, listener_fd: posix.fd_t, ctx: *const Tls.Context, opts: core.ServeOpts, ev_tag: u64, io: std.Io) void {
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
    opts: core.ServeOpts,
    handler: core.HandlerFn,
    worker_id: usize,
    /// Where this worker says whether its listener came up, shared with the whole group.
    report: *listen_report.Report,
};

fn tlsMuxWorker(worker: WorkerCtx) void {
    // Pin to the worker's CPU slot (cgroup-mask aware) so a pinned cpuset does not
    // oversubscribe one core under a handshake storm (mirrors http1's tls_mux).
    common.pinToCpu(worker.worker_id);

    // Every exit between here and the event loop has to reach the group, or the workers that
    // did bind wait on one that is already gone.
    var slot = worker.report.slot(worker.io, error.ZixHttp2TlsWorkerSetupFailed);
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

    // Serve only once every worker is up, so a group where one bind failed serves on none of them
    // and the caller gets one honest failure.
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
                if (keep and (ev.events & linux.EPOLL.IN) != 0) keep = onReadable(worker.handler, conn);
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

/// Listen and serve h2 over TLS, multiplexed across one epoll worker per core.
pub fn runTlsMux(handler: core.HandlerFn, config: Http2ServerConfig) !void {
    const ctx = config.tls.?;
    const cpu = common.getAvailableCpuCount();
    const worker_count = if (config.workers == 0) cpu else config.workers;
    const opts = common.serveOpts(config);

    const workers = try allocator.alloc(std.Thread, worker_count);
    defer allocator.free(workers);

    // What every worker says about its own listener, so a bind that fails inside a worker thread
    // reaches this frame instead of ending that thread and nothing else.
    var report = listen_report.Report.init(worker_count);

    for (workers, 0..) |*t, i|
        t.* = std.Thread.spawn(.{ .stack_size = config.worker_stack_size_bytes }, tlsMuxWorker, .{WorkerCtx{
            .io = config.io,
            .ip = config.ip,
            .port = config.port,
            .kernel_backlog = config.kernel_backlog,
            .ctx = ctx,
            .opts = opts,
            .handler = handler,
            .worker_id = i,
            .report = &report,
        }}) catch |err| {
            common.logSystem(config, .ERROR, "could not spawn tls worker {d} of {d} ({s})", .{ i, worker_count, @errorName(err) });
            report.abandon(config.io, worker_count - i, err);

            for (workers[0..i]) |spawned| spawned.join();

            return error.ZixHttp2TlsListenFailed;
        };

    if (report.awaitGroup(config.io)) |err| {
        common.logSystem(config, .ERROR, "tls not listening on {s}:{d}: {d} of {d} workers could not bind ({s})", .{ config.ip, config.port, report.failures(), worker_count, @errorName(err) });

        for (workers) |t| t.join();

        return error.ZixHttp2TlsListenFailed;
    }

    // Announced here rather than above the spawn, because until the group reports there is nothing
    // to announce: the old line claimed a listener that may never have come up.
    common.logSystem(config, .INFO, "listening on {s}:{d} (h2 TLS, epoll-mux/{d})", .{ config.ip, config.port, worker_count });

    for (workers) |t| t.join();
}

// --------------------------------------------------------- //

// End-to-end reproduction for the static-h2 stall: a real TLS 1.3 handshake (the zix client against
// this file's server path) then h2 GETs whose bodies exceed a small connection window, so the server
// parks them and must resume each as the client grants connection-level WINDOW_UPDATE. The plaintext
// mux proves this drains (mux.zig tests), this proves it drains through the TLS record + write-hook
// path too. A stall (parked bodies that never resume over TLS) trips the deadlock guard below.

const tls_client = @import("../../tls/client.zig");

// Fixture leaf cert (ECDSA P-256, CN=localhost) and its signing key, shared with the tls client tests.
const repro_cert_hex = "308201d43082017ba00302010202147a26ee491f091ac7c914f4a810c1ece713402574300a06082a8648ce3d040302302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f63301e170d3236303632323132353432305a170d3336303631393132353432305a302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f633059301306072a8648ce3d020106082a8648ce3d03010703420004c2a0121b298ac9cd389200e78d94e7bde1cc7cd8074795fab4f919799d40fdc231c5a90990ac8c6166ae472f33f74fced097f2edb7b8a1974be66a4ab07f253ba37f307d301d0603551d0e04160414c34e1d0a36a43947709b539e16dd0213aa4196aa301f0603551d23041830168014c34e1d0a36a43947709b539e16dd0213aa4196aa300f0603551d130101ff040530030101ff301a0603551d110413301182096c6f63616c686f737487047f000001300e0603551d0f0101ff040403020780300a06082a8648ce3d040302034700304402200b012f119db9b95d990bc482cb63e8f81e337a08634904e4caf513dc10c8aa8302202fdfe79ff6d5403e753ddf2aa52671923b8a2c28126bcbf196bd6fb7ecbcb14e";
const repro_key_hex = "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c";

// Larger than the default 65535 window (mirrors the largest static fixture, vendor.js.br ~67 KiB), so
// each stream exhausts its own send window and the shared connection window, needing both a stream and
// a connection WINDOW_UPDATE to fully drain.
var repro_body: [70000]u8 = undefined;

fn reproHandler(_: *Request, res: *Response, _: *Context) anyerror!void {
    mux.sendResponseStreamFD(res.fd, res.sid, 200, "text/plain", "", &repro_body);
}

const repro_router = core.Router(&[_]core.Route{.{ .path = "/", .handler = reproHandler }});

/// Read one full TLS record (5-byte header + fragment) with blocking reads. Used only for the
/// handshake flight, where every byte is already buffered by the time the client reads.
fn readRecordBlocking(fd: posix.fd_t, buf: []u8) ![]const u8 {
    try readExactBlocking(fd, buf[0..5]);
    const len = std.mem.readInt(u16, buf[3..5], .big);
    try readExactBlocking(fd, buf[5 .. 5 + len]);

    return buf[0 .. 5 + len];
}

fn readExactBlocking(fd: posix.fd_t, buf: []u8) !void {
    var got: usize = 0;
    while (got < buf.len) {
        const rc = linux.read(fd, buf[got..].ptr, buf.len - got);
        if (posix.errno(rc) != .SUCCESS) return error.ReadFailed;
        if (rc == 0) return error.ZixEof;
        got += rc;
    }
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

/// Encrypt and send one h2 WINDOW_UPDATE (stream 0 = connection level) granting `inc` bytes.
fn sendWindowUpdate(cc: *tls_client.ClientConnection, fd: posix.fd_t, sid: u31, inc: u32) !void {
    var wu: [13]u8 = undefined;
    frame.encodeFrameHeader(wu[0..9], .{ .length = 4, .frame_type = frame.FRAME_TYPE_WINDOW_UPDATE, .flags = 0, .stream_id = sid });
    std.mem.writeInt(u32, wu[9..13], inc, .big);

    var enc: [128]u8 = undefined;
    try writeAllBlocking(fd, cc.writeAppData(&wu, &enc));
}

test "zix http2: h2 over TLS resumes flow-control-parked streams (static-h2 stall repro)" {
    if (@import("builtin").os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    @memset(&repro_body, 'z');

    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var skey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&skey, repro_key_hex);
    const server_key = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(skey));
    var cert_buf: [512]u8 = undefined;
    const cert_der = try std.fmt.hexToBytes(&cert_buf, repro_cert_hex);

    const ctx = Tls.Context{
        .allocator = std.testing.allocator,
        .cert_der = cert_der,
        .signing_key = .{ .ecdsa_p256 = server_key },
        .alpn = &.{.H2},
        .curves = @import("../../tls/context.zig").default_curves,
        .ciphers = @import("../../tls/context.zig").default_ciphers,
        .min_version = .TLS_1_2,
        .max_version = .TLS_1_3,
        .prefer_server_ciphers = true,
        .hsts_max_age_s = 0,
    };

    var pair: [2]posix.fd_t = undefined;
    try std.testing.expect(posix.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);
    defer _ = linux.close(server_fd);

    // The server drives through onReadable, which reads until EAGAIN, so its fd must be non-blocking.
    common.setNonBlock(server_fd);

    var server_conn = TlsConn{ .transport = tls_conn.Transport.init(server_fd, &ctx), .opts = .{ .max_streams = 16 }, .io = undefined };
    defer if (server_conn.h2) |h2| h2.deinit();
    defer server_conn.transport.deinit();

    const epfd_rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
    try std.testing.expect(posix.errno(epfd_rc) == .SUCCESS);
    const epfd: posix.fd_t = @intCast(epfd_rc);
    defer _ = linux.close(epfd);

    // handshake: client ClientHello -> server flight -> client Finished -> established
    var ch_buf: [512]u8 = undefined;
    const started = try tls_client.start(.{ .client_random = @splat(0x11), .ephemeral_secret = @splat(0x42), .alpn = &.{.H2} }, &ch_buf);
    var state = started.state;

    var ch_rec: [600]u8 = undefined;
    ch_rec[0] = 22;
    std.mem.writeInt(u16, ch_rec[1..3], 0x0303, .big);
    std.mem.writeInt(u16, ch_rec[3..5], @intCast(started.client_hello.len), .big);
    @memcpy(ch_rec[5 .. 5 + started.client_hello.len], started.client_hello);
    try writeAllBlocking(client_fd, ch_rec[0 .. 5 + started.client_hello.len]);

    _ = onReadable(repro_router.dispatch, &server_conn);

    var flight_buf: [4096]u8 = undefined;
    var flen: usize = 0;
    for (0..3) |_| {
        const rec = try readRecordBlocking(client_fd, flight_buf[flen..]);
        flen += rec.len;
    }

    var fin_buf: [256]u8 = undefined;
    var finished = try tls_client.finish(&state, flight_buf[0..flen], &fin_buf);
    try writeAllBlocking(client_fd, finished.client_finished);
    try std.testing.expectEqual(Tls.Alpn.H2, finished.alpn.?);

    _ = onReadable(repro_router.dispatch, &server_conn);
    _ = server_conn.h2 orelse return error.ZixHandshakeIncomplete;

    // Default 65535 connection and per-stream windows (the client advertised none), matching the bench:
    // each 70 KB body overruns both, so the server parks and must resume on stream AND connection
    // WINDOW_UPDATE. No poke here, the defaults ARE the reproduction condition.

    // Client is non-blocking for the request/response phase so the drain stops at EAGAIN each round.
    common.setNonBlock(client_fd);

    const sids = [_]u31{ 1, 3 };

    // First client flight: connection preface + empty SETTINGS + three GET / requests.
    var req_plain: [512]u8 = undefined;
    var rp: usize = 0;
    @memcpy(req_plain[rp..][0..frame.PREFACE.len], frame.PREFACE);
    rp += frame.PREFACE.len;
    frame.encodeFrameHeader(req_plain[rp..][0..9], .{ .length = 0, .frame_type = frame.FRAME_TYPE_SETTINGS, .flags = 0, .stream_id = 0 });
    rp += 9;
    for (sids) |sid| {
        var hblk: [64]u8 = undefined;
        var enc = hpack.HpackEncoder.init(&hblk);
        try enc.writeHeader(":method", "GET");
        try enc.writeHeader(":path", "/");
        const block = enc.encoded();
        frame.encodeFrameHeader(req_plain[rp..][0..9], .{ .length = @intCast(block.len), .frame_type = frame.FRAME_TYPE_HEADERS, .flags = frame.FLAG_END_HEADERS | frame.FLAG_END_STREAM, .stream_id = sid });
        rp += 9;
        @memcpy(req_plain[rp..][0..block.len], block);
        rp += block.len;
    }

    var enc_out: [4096]u8 = undefined;
    try writeAllBlocking(client_fd, finished.connection.writeAppData(req_plain[0..rp], &enc_out));

    // Client receive state: accumulated ciphertext, accumulated plaintext h2, per-stream tallies.
    var cipher_acc: [128 * 1024]u8 = undefined;
    var cipher_len: usize = 0;
    var h2_acc: [128 * 1024]u8 = undefined;
    var h2_len: usize = 0;

    var received: [sids.len]usize = @splat(0);
    var ended: [sids.len]bool = @splat(false);
    var granted_conn: usize = 0;
    var granted_stream: [sids.len]usize = @splat(0);

    var stall_rounds: usize = 0;
    var round: usize = 0;
    while (round < 128) : (round += 1) {
        // Model a well-behaved client: grant back both the connection window and each stream's window
        // as their DATA is consumed, exactly what drives the server to resume its parked bodies.
        var consumed: usize = 0;
        for (received) |got| consumed += got;

        if (consumed > granted_conn) {
            try sendWindowUpdate(&finished.connection, client_fd, 0, @intCast(consumed - granted_conn));
            granted_conn = consumed;
        }
        for (sids, 0..) |sid, idx| {
            if (received[idx] > granted_stream[idx]) {
                try sendWindowUpdate(&finished.connection, client_fd, sid, @intCast(received[idx] - granted_stream[idx]));
                granted_stream[idx] = received[idx];
            }
        }

        _ = onReadable(repro_router.dispatch, &server_conn);
        if (server_conn.transport.want_out) _ = server_conn.transport.onWritable(epfd);

        // Drain and decrypt every complete TLS record now available, appending plaintext to h2_acc.
        cipher_len = drainNonblock(client_fd, &cipher_acc, cipher_len);
        var off: usize = 0;
        while (cipher_len - off >= 5) {
            const rec_len = std.mem.readInt(u16, cipher_acc[off + 3 ..][0..2], .big);
            if (cipher_len - off < 5 + rec_len) break;

            var plain: [18 * 1024]u8 = undefined;
            const dec = try finished.connection.readAppData(cipher_acc[off .. off + 5 + rec_len], &plain);
            @memcpy(h2_acc[h2_len..][0..dec.len], dec);
            h2_len += dec.len;
            off += 5 + rec_len;
        }
        if (off > 0) {
            std.mem.copyForwards(u8, cipher_acc[0 .. cipher_len - off], cipher_acc[off..cipher_len]);
            cipher_len -= off;
        }

        // Parse every complete h2 frame, tallying DATA payload and END_STREAM per stream.
        var before: usize = 0;
        for (received) |got| before += got;
        var hoff: usize = 0;
        while (h2_len - hoff >= 9) {
            const fh = frame.parseFrameHeader(h2_acc[hoff..][0..9]);
            if (h2_len - hoff < 9 + fh.length) break;

            if (fh.frame_type == frame.FRAME_TYPE_DATA and fh.stream_id != 0) {
                const idx = (fh.stream_id - 1) / 2;
                if (idx < sids.len) {
                    received[idx] += fh.length;
                    if ((fh.flags & frame.FLAG_END_STREAM) != 0) ended[idx] = true;
                }
            }
            hoff += 9 + fh.length;
        }
        if (hoff > 0) {
            std.mem.copyForwards(u8, h2_acc[0 .. h2_len - hoff], h2_acc[hoff..h2_len]);
            h2_len -= hoff;
        }

        var all_done = true;
        for (ended) |done_flag| all_done = all_done and done_flag;
        if (all_done) break;

        // No new bytes delivered and the client has already granted back everything it consumed: the
        // connection is wedged (parked bodies the server never resumed).
        var after: usize = 0;
        for (received) |got| after += got;
        if (after == before and after == granted_conn) {
            stall_rounds += 1;
            if (stall_rounds >= 3) break;
        } else {
            stall_rounds = 0;
        }
    }

    // Every stream must have delivered its whole body and closed. A stall (parked-but-never-resumed
    // over TLS) leaves some received[] short of repro_body.len with ended[] false.
    for (sids, 0..) |_, idx| {
        try std.testing.expectEqual(repro_body.len, received[idx]);
        try std.testing.expect(ended[idx]);
    }
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

/// Build the fixture TLS context into caller-owned storage, so the context outlives no buffer it
/// points at. Only the certificate slice borrows, the signing key is held by value.
fn testTlsContext(cert_buf: *[512]u8) !Tls.Context {
    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

    var skey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&skey, repro_key_hex);
    const server_key = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(skey));
    const cert_der = try std.fmt.hexToBytes(cert_buf, repro_cert_hex);

    return .{
        .allocator = std.testing.allocator,
        .cert_der = cert_der,
        .signing_key = .{ .ecdsa_p256 = server_key },
        .alpn = &.{.H2},
        .curves = @import("../../tls/context.zig").default_curves,
        .ciphers = @import("../../tls/context.zig").default_ciphers,
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

    _ = onReadable(repro_router.dispatch, server_conn);

    var flight_buf: [4096]u8 = undefined;
    var flen: usize = 0;
    for (0..3) |_| {
        const rec = try readRecordBlocking(client_fd, flight_buf[flen..]);
        flen += rec.len;
    }

    var fin_buf: [256]u8 = undefined;
    const finished = try tls_client.finish(&state, flight_buf[0..flen], &fin_buf);
    try writeAllBlocking(client_fd, finished.client_finished);

    _ = onReadable(repro_router.dispatch, server_conn);
    _ = server_conn.h2 orelse return error.ZixHandshakeIncomplete;

    return finished.connection;
}

/// Encrypt and send the h2 connection preface plus an empty SETTINGS frame, which is what takes the
/// server's mux out of its await_preface phase and into h2 proper.
fn sendClientPreface(cc: *tls_client.ClientConnection, fd: posix.fd_t) !void {
    var plain: [64]u8 = undefined;
    @memcpy(plain[0..frame.PREFACE.len], frame.PREFACE);
    frame.encodeFrameHeader(plain[frame.PREFACE.len..][0..9], .{ .length = 0, .frame_type = frame.FRAME_TYPE_SETTINGS, .flags = 0, .stream_id = 0 });

    var enc: [256]u8 = undefined;
    try writeAllBlocking(fd, cc.writeAppData(plain[0 .. frame.PREFACE.len + 9], &enc));
}

/// Encrypt and send one h2 frame the way a client would.
fn sendClientFrame(cc: *tls_client.ClientConnection, fd: posix.fd_t, ftype: u8, flags: u8, sid: u31, payload: []const u8) !void {
    var plain: [1024]u8 = undefined;
    frame.encodeFrameHeader(plain[0..9], .{ .length = @intCast(payload.len), .frame_type = ftype, .flags = flags, .stream_id = sid });
    @memcpy(plain[9..][0..payload.len], payload);

    var enc: [2048]u8 = undefined;
    try writeAllBlocking(fd, cc.writeAppData(plain[0 .. 9 + payload.len], &enc));
}

/// What the server answered with, decrypted from every record readable right now.
const TlsTally = struct {
    rst_protocol_error: usize = 0,
    goaway_protocol_error: usize = 0,
    statuses: usize = 0,
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
        const fh = frame.parseFrameHeader(plain[foff..][0..9]);
        foff += 9;
        if (foff + fh.length > plain_len) break;

        switch (fh.frame_type) {
            frame.FRAME_TYPE_RST_STREAM => {
                if (std.mem.readInt(u32, plain[foff..][0..4], .big) == frame.ERR_PROTOCOL_ERROR) tally.rst_protocol_error += 1;
            },
            frame.FRAME_TYPE_GOAWAY => {
                if (std.mem.readInt(u32, plain[foff + 4 ..][0..4], .big) == frame.ERR_PROTOCOL_ERROR) tally.goaway_protocol_error += 1;
            },
            frame.FRAME_TYPE_HEADERS => tally.statuses += 1,
            else => {},
        }
        foff += fh.length;
    }

    return tally;
}

/// Encode a POST head declaring `content_length`, ending the headers but not the stream.
fn encodeTlsPostHead(block: []u8, content_length: []const u8) ![]const u8 {
    var enc = hpack.HpackEncoder.init(block);
    try enc.writeHeader(":method", "POST");
    try enc.writeHeader(":path", "/");
    try enc.writeHeader("content-length", content_length);

    return enc.encoded();
}

test "zix http2: h2 over TLS resets a stream whose body is short of its content-length" {
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

    var server_conn = TlsConn{ .transport = tls_conn.Transport.init(pair[1], &ctx), .opts = .{ .max_streams = 16 }, .io = undefined };
    defer if (server_conn.h2) |h2| h2.deinit();
    defer server_conn.transport.deinit();

    var client = try handshakeTlsConn(&server_conn, pair[0]);
    common.setNonBlock(pair[0]);
    _ = tallyTlsWire(&client, pair[0]);

    try sendClientPreface(&client, pair[0]);
    _ = onReadable(repro_router.dispatch, &server_conn);
    _ = tallyTlsWire(&client, pair[0]);

    // 100 bytes promised, 40 delivered, then END_STREAM: the request never finished arriving
    var block: [128]u8 = undefined;
    const head = try encodeTlsPostHead(&block, "100");
    try sendClientFrame(&client, pair[0], frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS, 1, head);

    const short: [40]u8 = @splat('x');
    try sendClientFrame(&client, pair[0], frame.FRAME_TYPE_DATA, frame.FLAG_END_STREAM, 1, &short);

    _ = onReadable(repro_router.dispatch, &server_conn);

    // the guard runs inside the same mux the cleartext models drive, and its answer seals into a
    // record like any other frame: a reset, and no response headers from a handler that never ran
    const tally = tallyTlsWire(&client, pair[0]);

    try std.testing.expectEqual(@as(usize, 1), tally.rst_protocol_error);
    try std.testing.expectEqual(@as(usize, 0), tally.statuses);
}

test "zix http2: h2 over TLS answers a peer that hangs up with a request unfinished" {
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

    var server_conn = TlsConn{ .transport = tls_conn.Transport.init(pair[1], &ctx), .opts = .{ .max_streams = 16 }, .io = undefined };
    defer if (server_conn.h2) |h2| h2.deinit();
    defer server_conn.transport.deinit();

    var client = try handshakeTlsConn(&server_conn, pair[0]);
    common.setNonBlock(pair[0]);
    _ = tallyTlsWire(&client, pair[0]);

    try sendClientPreface(&client, pair[0]);
    _ = onReadable(repro_router.dispatch, &server_conn);
    _ = tallyTlsWire(&client, pair[0]);

    // a POST that opens its stream and never ends it: the body is still on its way
    var block: [128]u8 = undefined;
    const head = try encodeTlsPostHead(&block, "100");
    try sendClientFrame(&client, pair[0], frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS, 1, head);

    _ = onReadable(repro_router.dispatch, &server_conn);
    _ = tallyTlsWire(&client, pair[0]);

    // the peer goes away, and the GOAWAY that says so is sealed like any other frame
    try std.testing.expect(mux.requestInFlight(server_conn.h2.?));
    _ = hangupGoaway(&server_conn);

    const tally = tallyTlsWire(&client, pair[0]);

    try std.testing.expectEqual(@as(usize, 1), tally.goaway_protocol_error);
    try std.testing.expect(server_conn.transport.wclose);
}

test "zix http2: h2 over TLS closes an idle connection without a GOAWAY" {
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

    var server_conn = TlsConn{ .transport = tls_conn.Transport.init(pair[1], &ctx), .opts = .{ .max_streams = 16 }, .io = undefined };
    defer if (server_conn.h2) |h2| h2.deinit();
    defer server_conn.transport.deinit();

    var client = try handshakeTlsConn(&server_conn, pair[0]);
    common.setNonBlock(pair[0]);
    _ = tallyTlsWire(&client, pair[0]);

    try sendClientPreface(&client, pair[0]);
    _ = onReadable(repro_router.dispatch, &server_conn);
    _ = tallyTlsWire(&client, pair[0]);

    // nothing was ever opened, so the peer leaving is the ordinary end of a connection
    try std.testing.expect(!mux.requestInFlight(server_conn.h2.?));
    try std.testing.expect(!hangupGoaway(&server_conn));

    const tally = tallyTlsWire(&client, pair[0]);

    try std.testing.expectEqual(@as(usize, 0), tally.goaway_protocol_error);
}

var tls_body_seen: usize = 0;
var tls_body_dispatches: usize = 0;

fn tlsBodyHandler(req: *Request, res: *Response, _: *Context) anyerror!void {
    tls_body_dispatches += 1;
    tls_body_seen = req.body.len;

    try res.sendText("ok");
}

const tls_body_router = core.Router(&[_]core.Route{.{ .path = "/", .handler = tlsBodyHandler }});

/// Encrypt and send one h2 DATA frame as its own TLS record, from caller-owned scratch so the frame
/// may be larger than the small-frame helper allows.
fn sendClientData(cc: *tls_client.ClientConnection, fd: posix.fd_t, sid: u31, payload: []const u8, plain: []u8, enc: []u8, end_stream: bool) !void {
    frame.encodeFrameHeader(plain[0..9], .{
        .length = @intCast(payload.len),
        .frame_type = frame.FRAME_TYPE_DATA,
        .flags = if (end_stream) frame.FLAG_END_STREAM else 0,
        .stream_id = sid,
    });
    @memcpy(plain[9..][0..payload.len], payload);

    try writeAllBlocking(fd, cc.writeAppData(plain[0 .. 9 + payload.len], enc));
}

test "zix http2: h2 over TLS serves a request body spanning several TLS records" {
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
    defer if (server_conn.h2) |h2| h2.deinit();
    defer server_conn.transport.deinit();

    var client = try handshakeTlsConn(&server_conn, pair[0]);
    common.setNonBlock(pair[0]);
    _ = tallyTlsWire(&client, pair[0]);

    try sendClientPreface(&client, pair[0]);
    _ = onReadable(tls_body_router.dispatch, &server_conn);
    _ = tallyTlsWire(&client, pair[0]);

    const chunk_len: usize = 13000;
    const chunks: usize = 3;
    const body_len = chunk_len * chunks;

    var head_block: [128]u8 = undefined;
    const head = try encodeTlsPostHead(&head_block, "39000");
    try sendClientFrame(&client, pair[0], frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS, 1, head);

    // Three DATA frames, one TLS record each, all sitting in the socket before the server reads.
    // That is the condition the session's single-record reassembly buffer could not survive: a read
    // wide enough to scoop up more than one record and hand them over together.
    const payload = try std.testing.allocator.alloc(u8, chunk_len);
    defer std.testing.allocator.free(payload);
    @memset(payload, 'u');

    const plain = try std.testing.allocator.alloc(u8, chunk_len + 64);
    defer std.testing.allocator.free(plain);
    const enc = try std.testing.allocator.alloc(u8, chunk_len + 512);
    defer std.testing.allocator.free(enc);

    for (0..chunks) |idx| try sendClientData(&client, pair[0], 1, payload, plain, enc, idx == chunks - 1);

    tls_body_dispatches = 0;
    tls_body_seen = 0;
    _ = onReadable(tls_body_router.dispatch, &server_conn);

    // The whole body reached the handler, and the connection is still alive to answer
    try std.testing.expectEqual(@as(usize, 1), tls_body_dispatches);
    try std.testing.expectEqual(body_len, tls_body_seen);

    const tally = tallyTlsWire(&client, pair[0]);

    try std.testing.expectEqual(@as(usize, 0), tally.rst_protocol_error);
    try std.testing.expect(tally.statuses >= 1);
}
