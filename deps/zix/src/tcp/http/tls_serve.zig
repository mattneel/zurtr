//! zix http https serve path (RFC 8446 + 9112), the thread-per-connection models.
//!
//! Note:
//! - Gated on config.tls (a *Tls.Context). The accept loop hands each connection to its own worker
//!   thread (.ASYNC), so a slow handshake or a keep-alive client never serializes
//!   the others. The worker reads the ClientHello, branches on the version policy (TLS 1.3 via
//!   zix.Tls, a 1.2-only client via tls12_connection), then per request decrypts the record(s),
//!   accumulates a full request, runs the router through processRequest with the response captured
//!   into a buffer (the existing response sink), encrypts that plaintext, and sends it.
//! - The cleartext path is untouched: this file is reached only when config.tls is set (gated in
//!   server.zig before the dispatch switch). .EPOLL / .URING terminate TLS in the event-driven
//!   tls_mux worker instead. https is its own perf band (not the cleartext 1% gate).
//! - Buffered responses by default. A streaming handler (res.stream / SSE) is served over TLS via
//!   the per-connection stream sink (ADR-054): res.stream detaches the buffered capture, then each
//!   event encrypts one record and sends it. A WebSocket upgrade (bidirectional) is still out of
//!   scope here (ADR-055 adds the TLS read path on top of this stream sink).

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const fd_io = @import("../../utils/fd_io.zig");
const common = @import("dispatch/common.zig");
const resp = @import("response.zig");
const parser = @import("parser.zig");
const ws = @import("websocket.zig");
const Tls = @import("../../tls/Tls.zig");
const tls12 = @import("../../tls/tls12_connection.zig");
const record = @import("../../tls/record.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// Record traffic runs over the bare accepted descriptor, so it goes through the shared
/// fd helpers rather than a per-platform branch in this file.
const readAll = fd_io.readAll;
const writeAllFD = fd_io.writeAll;

const content_type_change_cipher_spec: u8 = 20;
const content_type_alert: u8 = 21;
const content_type_handshake: u8 = 22;
const content_type_application_data: u8 = 23;

/// Server handshake flight output staging (TLS 1.3 and TLS 1.2 server flights).
const server_flight_out_size: usize = 8 * 1024;

/// HelloRetryRequest output staging (RFC 8446 4.1.4).
const hello_retry_out_size: usize = 1024;

/// Incoming ClientKeyExchange body copy (TLS 1.2 path).
const client_key_exchange_size: usize = 256;

/// Outgoing server Finished output (TLS 1.2 path).
const server_finished_out_size: usize = 256;

/// Application-data encrypt output: one response record plus AEAD and framing overhead.
const app_data_encrypt_out_size: usize = 70 * 1024;

/// One encrypted alert record (close_notify or a fatal alert after keys exist).
const encrypted_alert_size: usize = 64;

/// One decrypted record's plaintext (a TLS record carries up to ~16 KiB).
const record_plain_size: usize = 17 * 1024;

/// Accumulated request plaintext: the effective max request size (head + body) over TLS.
const request_plain_size: usize = 17 * 1024;

/// Captured response buffer: the effective max response size over TLS.
const response_buf_size: usize = 64 * 1024;

/// WebSocket-over-TLS frame loop buffers (ADR-055): accumulated client frame bytes, one decrypted
/// record, the largest unmasked payload, and the coalesced outbound frames staged before encryption.
const ws_acc_size: usize = 17 * 1024;
const ws_record_plain_size: usize = 17 * 1024;
const ws_payload_size: usize = 16 * 1024;
const ws_out_size: usize = 32 * 1024;

/// The sentinel fd handed to processRequest while a response sink is installed: every writeAllFD and
/// the Response fast path target this fd, so nothing escapes to a real descriptor (no plaintext leak).
const sink_fd: posix.fd_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;

/// One captured response: the plaintext bytes the router wrote, plus the keep-alive outcome.
/// `streamed` is true when the handler took the streaming path (res.stream / SSE) over TLS: the
/// response was already encrypted and sent through the stream sink, so `bytes` is empty and the
/// caller closes the connection instead of encrypting a buffer.
pub const Captured = struct {
    bytes: []const u8,
    outcome: common.ReqOutcome,
    streamed: bool = false,
};

/// Per-connection streaming state behind the type-erased resp.TlsStreamSink (ADR-054). Generic over
/// the connection so the TLS 1.3 and 1.2 paths share one implementation: write encrypts one record
/// from `plaintext` and sends it straight to the socket, the streaming counterpart of writeAppData.
fn StreamSinkFor(comptime Conn: type) type {
    return struct {
        conn: Conn,
        fd: posix.fd_t,
        enc: []u8,

        fn write(ctx_ptr: *anyopaque, plaintext: []const u8) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx_ptr));

            const encrypted = self.conn.writeAppData(plaintext, self.enc);
            writeAllFD(self.fd, encrypted) catch return false;

            return true;
        }
    };
}

/// Run the router for one fully-buffered request with a response sink installed, returning the
/// plaintext it wrote into `out`. processRequest serializes the Response into the sink (matched by
/// the sentinel fd) instead of any socket, so there is no pipe per request, just an in-memory copy.
///
/// Note:
/// - `request` MUST hold the complete request (head + Content-Length body): with fd = -1 the body
///   reader cannot pull more off a socket, so a partial body would silently truncate.
/// - A streaming handler nulls the sink (res.stream). Detect that and reject (StreamingNotSupported).
///   An overflowing response flushes to the sentinel fd, which fails, surfacing as ResponseTooLarge.
pub fn processRequestToBuffer(server: anytype, io: std.Io, request: []u8, out: []u8, arena: *std.heap.ArenaAllocator) !Captured {
    _ = arena.reset(.retain_capacity);

    var sink = resp.RespSink{ .fd = sink_fd, .buf = out };
    const prev = resp.tl_resp_sink;
    resp.tl_resp_sink = &sink;
    defer resp.tl_resp_sink = prev;

    const stream = std.Io.net.Stream{ .socket = .{ .handle = sink_fd, .address = undefined } };
    const outcome = common.processRequest(server, stream, sink_fd, io, request, arena);

    if (resp.tl_resp_sink != &sink) {
        // the handler detached the capture sink via res.sendStream(). With the stream sink armed it
        // already streamed the response over TLS (ADR-054). Without it, streaming has no TLS path.
        if (resp.tl_tls_stream != null) return .{ .bytes = &.{}, .outcome = .close, .streamed = true };

        return error.ZixStreamingNotSupported;
    }
    if (sink.failed) return error.ZixResponseTooLarge;

    return .{ .bytes = out[0..sink.len], .outcome = outcome };
}

/// Listen and serve https/1.1, one worker thread per connection (the .ASYNC path,
/// .EPOLL / .URING use the event-driven tls_mux). The cert / key / policy are already loaded and
/// validated in the context (config.tls), so this only accepts and drives per-connection handshakes.
pub fn runTls(server: anytype, io: std.Io) !void {
    const cfg = server.config;
    const ctx = cfg.tls.?;

    const addr = try std.Io.net.IpAddress.resolve(io, cfg.ip, cfg.port);
    var srv = try addr.listen(io, .{ .reuse_address = true, .kernel_backlog = cfg.kernel_backlog });

    common.logSystem(cfg, .INFO, "listening on {s}:{d} (https/1.1)", .{ cfg.ip, cfg.port });

    // io.async / std.Thread.spawn need a concrete function: wrap the generic serve in a closure where
    // the server pointer type is fixed (same pattern as the cleartext async dispatch).
    const Spawn = struct {
        fn handle(srv_ptr: @TypeOf(server), conn_fd: posix.fd_t, tls_ctx: *const Tls.Context, h_io: std.Io) void {
            // A failed handshake used to close the socket with nothing said. It files at DEBUG
            // rather than WARN because one remote peer drives it, and a scanner would flood.
            serveConnTls(srv_ptr, h_io, conn_fd, tls_ctx) catch |err| {
                common.logSystem(srv_ptr.config, .DEBUG, "tls connection ended: {s}", .{@errorName(err)});
            };

            fd_io.close(conn_fd);
        }
    };

    while (true) {
        const stream = srv.accept(io) catch continue;
        const conn_fd = stream.socket.handle;

        const worker = std.Thread.spawn(.{ .stack_size = cfg.worker_stack_size_bytes }, Spawn.handle, .{ server, conn_fd, ctx, io }) catch {
            // Spawn failed (thread / pid limit): drop this connection and keep accepting. Serving
            // inline would block the accept loop for the connection's whole lifetime.
            fd_io.close(conn_fd);

            continue;
        };

        worker.detach();
    }
}

fn serveConnTls(server: anytype, io: std.Io, fd: posix.fd_t, ctx: *const Tls.Context) !void {
    var record_buf: [record.max_record_wire]u8 = undefined;

    const client_hello_rec = try readRecord(fd, &record_buf);
    if (client_hello_rec.content_type != content_type_handshake) return error.ZixUnexpectedRecord;

    var ephemeral_secret: [32]u8 = undefined;
    var server_random: [32]u8 = undefined;
    var pss_salt: [32]u8 = undefined;
    // std.Io carries the platform's CSPRNG, so the handshake secrets need no syscall branch.
    try io.randomSecure(&ephemeral_secret);
    try io.randomSecure(&server_random);
    try io.randomSecure(&pss_salt);

    const opts = ctx.handshakeOptions(ephemeral_secret, server_random, pss_salt);

    // Version policy: a TLS 1.2 ceiling never takes the 1.3 path. The 1.2 ServerKeyExchange is
    // ECDSA-signed, so an Ed25519 / RSA context cannot serve 1.2.
    if (!ctx.allowsTls13()) {
        const ecdsa_key = switch (ctx.signing_key) {
            .ecdsa_p256 => |kp| kp,
            else => return error.ZixTls12RequiresEcdsa,
        };

        return serveConnTls12(server, io, fd, ctx, ecdsa_key, client_hello_rec.body, ephemeral_secret, server_random);
    }

    // HelloRetryRequest (RFC 8446 4.1.4): a 1.3 client that picked a group it gave no key_share for.
    var handshake_out: [server_flight_out_size]u8 = undefined;
    var hrr_out: [hello_retry_out_size]u8 = undefined;
    var retry_state: ?Tls.RetryState = null;
    var second_hello: []const u8 = &.{};
    if (Tls.serverHelloRetry(opts, client_hello_rec.body, &hrr_out)) |maybe_retry| {
        if (maybe_retry) |retry| {
            try writeAllFD(fd, retry.to_send);

            const ch2_rec = try readRecord(fd, &record_buf);
            if (ch2_rec.content_type != content_type_handshake) return error.ZixUnexpectedRecord;

            retry_state = retry.state;
            second_hello = ch2_rec.body;
        }
    } else |err| {
        if (err != error.ZixUnsupportedTlsVersion) {
            var alert_buf: [Tls.fatal_record_len]u8 = undefined;
            if (Tls.alertRecordForError(&alert_buf, err)) |rec| writeAllFD(fd, rec) catch {};

            return err;
        }
    }

    const result = if (retry_state) |state|
        try Tls.serverHandshakeAfterRetry(state, second_hello, &handshake_out)
    else
        Tls.serverHandshake(opts, client_hello_rec.body, &handshake_out) catch |err| {
            // no 1.3 offer -> a TLS 1.2 only client. Honor the floor: refuse at a 1.3 min_version,
            // else take the ECDSA-signed 1.2 path.
            if (err == error.ZixUnsupportedTlsVersion) {
                if (!ctx.allowsTls12()) {
                    var ver_alert: [Tls.fatal_record_len]u8 = undefined;
                    if (Tls.alertRecordForError(&ver_alert, err)) |rec| writeAllFD(fd, rec) catch {};

                    return err;
                }

                const ecdsa_key = switch (ctx.signing_key) {
                    .ecdsa_p256 => |kp| kp,
                    else => return error.ZixTls12RequiresEcdsa,
                };

                return serveConnTls12(server, io, fd, ctx, ecdsa_key, client_hello_rec.body, ephemeral_secret, server_random);
            }

            var alert_buf: [Tls.fatal_record_len]u8 = undefined;
            if (Tls.alertRecordForError(&alert_buf, err)) |rec| writeAllFD(fd, rec) catch {};

            return err;
        };
    try writeAllFD(fd, result.to_send);
    var conn = result.connection;

    // client ChangeCipherSpec (skipped) + Finished. A plaintext alert here means the peer aborted.
    while (true) {
        const rec = try readRecord(fd, &record_buf);
        if (rec.content_type == content_type_change_cipher_spec) continue;
        if (rec.content_type == content_type_alert) return peerAlert(rec.body);
        if (rec.content_type != content_type_application_data) return error.ZixUnexpectedRecord;

        try conn.verifyClientFinished(rec.full);
        break;
    }

    try serveRequests(server, io, fd, ctx, &conn, &record_buf);
}

/// TLS 1.2 path (RFC 5246 + 5288, ECDHE-ECDSA): the two-phase handshake via tls12_connection, then
/// the keep-alive request loop. Reached only when the client did not offer 1.3.
fn serveConnTls12(server: anytype, io: std.Io, fd: posix.fd_t, ctx: *const Tls.Context, key_pair: EcdsaP256.KeyPair, client_hello: []const u8, ephemeral_secret: [32]u8, server_random: [32]u8) !void {
    var flight_out: [server_flight_out_size]u8 = undefined;
    const flight = try tls12.serverFlight1(.{
        .certificate_der = ctx.cert_der,
        .signing_key = key_pair,
        .server_eph_secret = ephemeral_secret,
        .server_random = server_random,
        .alpn_prefs = ctx.alpn,
    }, client_hello, &flight_out);
    try writeAllFD(fd, flight.to_send);
    var state = flight.state;

    var record_buf: [record.max_record_wire]u8 = undefined;

    const cke_rec = try readRecord(fd, &record_buf);
    if (cke_rec.content_type != content_type_handshake) return error.ZixUnexpectedRecord;
    var cke_buf: [client_key_exchange_size]u8 = undefined;
    if (cke_rec.body.len > cke_buf.len) return error.ZixRecordTooLarge;
    @memcpy(cke_buf[0..cke_rec.body.len], cke_rec.body);
    const client_key_exchange = cke_buf[0..cke_rec.body.len];

    const finished_rec = while (true) {
        const rec = try readRecord(fd, &record_buf);
        if (rec.content_type == content_type_change_cipher_spec) continue;
        if (rec.content_type == content_type_alert) return peerAlert(rec.body);
        if (rec.content_type != content_type_handshake) return error.ZixUnexpectedRecord;

        break rec;
    };

    var finish_out: [server_finished_out_size]u8 = undefined;
    const finish = try tls12.serverFinish(&state, client_key_exchange, finished_rec.full, &finish_out);
    try writeAllFD(fd, finish.to_send);
    var conn = finish.connection;

    try serveRequests(server, io, fd, ctx, &conn, &record_buf);
}

/// Serve application requests over an established TLS session until the client signals close. Each
/// request: decrypt record(s), accumulate a full request (head + body), route it with the response
/// captured into a buffer, encrypt, write. Generic over the connection type so the 1.3 and 1.2 paths
/// share one loop (both expose readAppData / writeAppData / closeNotify).
fn serveRequests(server: anytype, io: std.Io, fd: posix.fd_t, ctx: *const Tls.Context, conn: anytype, record_buf: []u8) !void {
    const cfg = server.config;
    var rbuf: [request_plain_size]u8 = undefined;
    var rlen: usize = 0;
    var plain_temp: [record_plain_size]u8 = undefined;
    var response_buf: [response_buf_size]u8 = undefined;
    var encrypt_buf: [app_data_encrypt_out_size]u8 = undefined;
    var close_buf: [encrypted_alert_size]u8 = undefined;

    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    _ = arena.allocator().alloc(u8, cfg.max_allocator_size) catch {};
    _ = arena.reset(.retain_capacity);

    // arm the streaming sink for this connection (ADR-054): a streaming handler (res.stream / SSE)
    // writes each event through it, encrypting one record per write, instead of buffering. A normal
    // buffered handler never touches it (the capture sink wins in writeAllFD).
    const Stream = StreamSinkFor(@TypeOf(conn));
    var stream_state = Stream{ .conn = conn, .fd = fd, .enc = &encrypt_buf };
    const prev_stream = resp.tl_tls_stream;
    var stream_sink = resp.TlsStreamSink{ .ctx = &stream_state, .writeFn = Stream.write };
    resp.tl_tls_stream = &stream_sink;
    defer resp.tl_tls_stream = prev_stream;

    while (true) {
        // Is a complete request already buffered? parse what we have. A null / IncompleteHeader means
        // we need more bytes.
        // Answer before closing, the same way the 421 branch below does. A silent
        // drop leaves the client unable to tell a refused method from a dead
        // connection, and the session is established, so the status can be sent.
        const maybe_head = parser.parse(rbuf[0..rlen], cfg.max_request_headers.value()) catch |err| {
            writeAllFD(fd, conn.writeAppData(resp.parseErrorResponse(err), &encrypt_buf)) catch {};
            writeAllFD(fd, conn.closeNotify(&close_buf)) catch {};

            return error.ZixBadRequest;
        };
        const complete = if (maybe_head) |h| blk: {
            if (h.chunked) break :blk false; // chunked bodies are out of scope for the TLS cut
            break :blk rlen >= h.body_offset + h.content_length;
        } else false;

        if (!complete) {
            // need another record: read ciphertext, decrypt, append plaintext to rbuf.
            const request_rec = readRecord(fd, record_buf) catch |err| {
                if (err == error.ZixConnectionClosed and rlen == 0) return; // clean keep-alive end
                return err;
            };
            if (request_rec.content_type == content_type_alert) return; // peer close_notify / alert
            if (request_rec.content_type != content_type_application_data) return error.ZixUnexpectedRecord;

            const plain = conn.readAppData(request_rec.full, &plain_temp) catch |err| {
                if (err == error.ZixPeerClosed) return; // client close_notify
                return err;
            };
            if (rlen + plain.len > rbuf.len) return error.ZixRequestTooLarge;
            @memcpy(rbuf[rlen..][0..plain.len], plain);
            rlen += plain.len;

            continue;
        }

        const head = maybe_head.?;
        const total = head.body_offset + head.content_length;

        // RFC 9110 7.4: a request for an authority this cert does not serve is misdirected (421).
        if (hostFromHead(rbuf[0..head.body_offset])) |host_raw| {
            const host = stripPort(host_raw);
            Tls.verifyCertIdentity(ctx.cert_der, host) catch {
                const misdirected = "HTTP/1.1 421 Misdirected Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                writeAllFD(fd, conn.writeAppData(misdirected, &encrypt_buf)) catch {};
                writeAllFD(fd, conn.closeNotify(&close_buf)) catch {};

                return;
            };
        }

        const cap = processRequestToBuffer(server, io, rbuf[0..total], &response_buf, &arena) catch {
            // ResponseTooLarge / StreamingNotSupported: close the connection cleanly.
            writeAllFD(fd, conn.closeNotify(&close_buf)) catch {};

            return;
        };

        if (ws.takeWebSocket()) |handoff| {
            // WebSocket upgrade over TLS (ADR-055): the 101 was already sent through the stream sink.
            // Run the inline frame loop over this TLS session, then close.
            serveWsTls(conn, fd, handoff.on_frame, record_buf) catch {};
            writeAllFD(fd, conn.closeNotify(&close_buf)) catch {};

            return;
        }

        if (cap.streamed) {
            // the handler streamed the whole response over TLS (already encrypted + sent through the
            // stream sink). The stream owns the rest of the connection, so close after it returns.
            writeAllFD(fd, conn.closeNotify(&close_buf)) catch {};

            return;
        }

        try writeAllFD(fd, conn.writeAppData(cap.bytes, &encrypt_buf));

        // slide any pipelined bytes down for the next request.
        const remaining = rlen - total;
        if (remaining > 0) std.mem.copyForwards(u8, rbuf[0..remaining], rbuf[total..rlen]);
        rlen = remaining;

        if (cap.outcome == .close) {
            writeAllFD(fd, conn.closeNotify(&close_buf)) catch {};

            return;
        }
    }
}

/// Drive a WebSocket session over the established TLS connection (ADR-055). Each iteration reads one
/// ciphertext record, decrypts it, accumulates the plaintext, and pumps every complete frame: a
/// text / binary frame invokes on_frame, ping is auto-ponged, close is auto-echoed. Outbound frames
/// flow through the ADR-054 stream sink (resp.writeAllFD -> conn.writeAppData), so each pump pass
/// encrypts its coalesced frames as one record. Ends on a peer hangup, a close frame, or close_notify.
fn serveWsTls(conn: anytype, fd: posix.fd_t, on_frame: ws.WsFrameFn, record_buf: []u8) !void {
    var acc: [ws_acc_size]u8 = undefined;
    var acc_len: usize = 0;
    var plain_temp: [ws_record_plain_size]u8 = undefined;
    var payload_buf: [ws_payload_size]u8 = undefined;
    var out_buf: [ws_out_size]u8 = undefined;

    while (true) {
        const rec = readRecord(fd, record_buf) catch |err| {
            if (err == error.ZixConnectionClosed) return; // peer hung up

            return err;
        };
        if (rec.content_type == content_type_alert) return; // peer close_notify
        if (rec.content_type != content_type_application_data) return error.ZixUnexpectedRecord;

        const plain = conn.readAppData(rec.full, &plain_temp) catch |err| {
            if (err == error.ZixPeerClosed) return; // client close_notify

            return err;
        };
        if (acc_len + plain.len > acc.len) return error.ZixWsFrameTooLarge;
        @memcpy(acc[acc_len..][0..plain.len], plain);
        acc_len += plain.len;

        const result = ws.pump(fd, acc[0..acc_len], &payload_buf, &out_buf, on_frame);

        // slide any trailing partial frame down for the next record.
        const remaining = acc_len - result.consumed;
        if (remaining > 0) std.mem.copyForwards(u8, acc[0..remaining], acc[result.consumed..acc_len]);
        acc_len = remaining;

        if (result.close) return;
    }
}

// --------------------------------------------------------------- //

/// A plaintext alert arriving mid-handshake (the peer aborted): parse it and signal a clean teardown.
fn peerAlert(body: []const u8) anyerror {
    _ = Tls.parseInboundAlert(body) catch {};

    return error.ZixPeerAlert;
}

/// The Host header value (RFC 9112 3.2) from a request head, or null when absent.
pub fn hostFromHead(head: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next(); // request line
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " \t"), "host")) {
            return std.mem.trim(u8, line[colon + 1 ..], " \t");
        }
    }

    return null;
}

/// Strip the ":port" suffix from a Host value, leaving the authority host.
pub fn stripPort(host: []const u8) []const u8 {
    if (host.len == 0) return host;

    if (host[0] == '[') {
        if (std.mem.indexOfScalar(u8, host, ']')) |close| return host[1..close];

        return host;
    }

    if (std.mem.indexOfScalar(u8, host, ':')) |first| {
        if (std.mem.lastIndexOfScalar(u8, host, ':').? == first) return host[0..first];
    }

    return host;
}

const Record = struct {
    content_type: u8,
    full: []const u8,
    body: []const u8,
};

fn readRecord(fd: posix.fd_t, buf: []u8) !Record {
    try readAll(fd, buf[0..5]);

    const length = std.mem.readInt(u16, buf[3..5], .big);
    if (5 + length > buf.len) return error.ZixRecordTooLarge;

    try readAll(fd, buf[5 .. 5 + length]);

    return .{ .content_type = buf[0], .full = buf[0 .. 5 + length], .body = buf[5 .. 5 + length] };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix http: tls_serve, stripPort strips host:port and bracketed ipv6" {
    try std.testing.expectEqualStrings("localhost", stripPort("localhost:9071"));
    try std.testing.expectEqualStrings("localhost", stripPort("localhost"));
    try std.testing.expectEqualStrings("127.0.0.1", stripPort("127.0.0.1:443"));
    try std.testing.expectEqualStrings("::1", stripPort("[::1]:443"));
    try std.testing.expectEqualStrings("::1", stripPort("::1"));
}

test "zix http: tls_serve, hostFromHead extracts the Host header" {
    const head = "GET / HTTP/1.1\r\nUser-Agent: x\r\nHost: localhost:9071\r\nAccept: */*\r\n\r\n";
    try std.testing.expectEqualStrings("localhost:9071", hostFromHead(head).?);

    const no_host = "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
    try std.testing.expect(hostFromHead(no_host) == null);
}

const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Context = @import("context.zig").Context;
const Route = @import("router.zig").Route;
const Router = @import("router.zig").Router;

fn tlsTestHandler(req: *Request, res: *Response, ctx: *Context) anyerror!void {
    _ = req;
    _ = ctx;

    try res.send("ok");
}

fn tlsStreamHandler(req: *Request, res: *Response, ctx: *Context) anyerror!void {
    _ = req;
    _ = ctx;

    _ = res.sendStream() catch {};
}

test "zix http: tls_serve, processRequestToBuffer captures the router response" {
    const HttpServerImpl = @import("server.zig").Server;

    const routes = [_]Route{
        .{ .path = "/", .handler = tlsTestHandler },
        .{ .path = "/sse", .handler = tlsStreamHandler },
    };
    const router = Router(&routes);
    var server = HttpServerImpl.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var out: [4096]u8 = undefined;

    // a buffered route serializes into the capture buffer instead of any socket, no plaintext escapes.
    var req_ok = "GET / HTTP/1.1\r\nHost: x\r\n\r\n".*;
    const cap = try processRequestToBuffer(&server, undefined, req_ok[0..], &out, &arena);
    try std.testing.expect(std.mem.indexOf(u8, cap.bytes, "200 Ok") != null);
    try std.testing.expect(std.mem.indexOf(u8, cap.bytes, "ok") != null);
    try std.testing.expectEqual(common.ReqOutcome.keep_alive, cap.outcome);

    // a streaming route with no stream sink armed has no TLS path, surfaced as StreamingNotSupported.
    var req_sse = "GET /sse HTTP/1.1\r\nHost: x\r\n\r\n".*;
    try std.testing.expectError(error.ZixStreamingNotSupported, processRequestToBuffer(&server, undefined, req_sse[0..], &out, &arena));
}

/// Capture stream sink for the test: a streaming handler's writes land in `buf` instead of a socket.
const CaptureStream = struct {
    buf: [1024]u8 = undefined,
    len: usize = 0,

    fn write(ctx_ptr: *anyopaque, plaintext: []const u8) bool {
        const self: *CaptureStream = @ptrCast(@alignCast(ctx_ptr));

        @memcpy(self.buf[self.len..][0..plaintext.len], plaintext);
        self.len += plaintext.len;

        return true;
    }
};

test "zix http: tls_serve, processRequestToBuffer streams over TLS when the stream sink is armed" {
    const HttpServerImpl = @import("server.zig").Server;

    const routes = [_]Route{
        .{ .path = "/sse", .handler = tlsStreamHandler },
    };
    const router = Router(&routes);
    var server = HttpServerImpl.init(router.dispatch, .{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC });
    defer server.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var out: [4096]u8 = undefined;

    var capture = CaptureStream{};
    var stream_sink = resp.TlsStreamSink{ .ctx = &capture, .writeFn = CaptureStream.write };
    const prev = resp.tl_tls_stream;
    resp.tl_tls_stream = &stream_sink;
    defer resp.tl_tls_stream = prev;

    // res.sendStream() detaches the capture sink and writes the SSE headers through the stream sink.
    var req_sse = "GET /sse HTTP/1.1\r\nHost: x\r\n\r\n".*;
    const cap = try processRequestToBuffer(&server, undefined, req_sse[0..], &out, &arena);
    try std.testing.expect(cap.streamed);
    try std.testing.expectEqual(common.ReqOutcome.close, cap.outcome);
    try std.testing.expect(std.mem.indexOf(u8, capture.buf[0..capture.len], "text/event-stream") != null);
}

fn wsNoopFrame(fd: posix.fd_t, opcode: u8, payload: []const u8) void {
    _ = fd;
    _ = opcode;
    _ = payload;
}

test "zix http: tls_serve, WebSocket.serveTls encrypts the 101 through the stream sink and registers the handoff" {
    var capture = CaptureStream{};
    var stream_sink = resp.TlsStreamSink{ .ctx = &capture, .writeFn = CaptureStream.write };
    const prev = resp.tl_tls_stream;
    resp.tl_tls_stream = &stream_sink;
    defer resp.tl_tls_stream = prev;

    // the 101 routes through the stream sink (encrypted over TLS in production), the handoff is set.
    const sink_only_fd: std.posix.fd_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;
    try ws.serveTls(sink_only_fd, "dGhlIHNhbXBsZSBub25jZQ==", wsNoopFrame);
    try std.testing.expect(std.mem.indexOf(u8, capture.buf[0..capture.len], "101 Switching Protocols") != null);
    try std.testing.expect(std.mem.indexOf(u8, capture.buf[0..capture.len], "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=") != null);

    const handoff = ws.takeWebSocket();
    try std.testing.expect(handoff != null);
}
