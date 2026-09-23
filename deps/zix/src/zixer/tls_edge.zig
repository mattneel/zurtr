//! zixer tls edge: terminate TLS on one edge connection over the zix tls engine

const std = @import("std");
const zix = @import("zix");

const client_lease = @import("client_lease.zig");
const conn_buffer = @import("conn_buffer.zig");
const http1_proxy = @import("http1_proxy.zig");
const grpc_edge = @import("grpc_edge.zig");
const http2_edge = @import("http2_edge.zig");
const site_cfg = @import("site_cfg.zig");

const socket_cut_reader = zix.utils.socket_cut_reader;
const socket_cut_writer = zix.utils.socket_cut_writer;

const Tls = zix.Tls;

/// Handshake flight staging (server flight fits well under this).
const FLIGHT_OUT_SIZE: usize = 8 * 1024;

/// HelloRetryRequest staging (one small record).
const RETRY_OUT_SIZE: usize = 1024;

/// TLS 1.2 ClientKeyExchange copy (one P-256 key share).
const KEY_EXCHANGE_SIZE: usize = 256;

/// TLS 1.2 server Finished staging (ChangeCipherSpec + Finished records).
const FINISHED_OUT_SIZE: usize = 256;

/// One sealed alert record (close_notify or a fatal alert).
const ALERT_OUT_SIZE: usize = 64;

/// Plaintext staging the reader hands to the request loop: one full record
/// wire (deprotect wants ciphertext-length out space) plus the largest
/// contiguous ask (a request head), so a decrypt always fits behind
/// partially buffered plaintext.
const READ_PLAIN_SIZE: usize = Tls.max_record_wire + 16 * 1024;

/// Sealed staging for one full-size application record.
const SEAL_OUT_SIZE: usize = Tls.sealedLen(Tls.max_plaintext);

/// Plaintext staging the writer collects before sealing.
const WRITE_STAGE_SIZE: usize = 8 * 1024;

const content_type_change_cipher_spec: u8 = 20;
const content_type_alert: u8 = 21;
const content_type_handshake: u8 = 22;
const content_type_application_data: u8 = 23;

/// ALPN preference list per site engine: an http2 site offers h2 first
/// with the http/1.1 fallback, a grpc site is h2 only, everything else
/// pins http/1.1.
pub fn alpnPrefs(engine: site_cfg.Engine) []const Tls.Alpn {
    return switch (engine) {
        .HTTP2 => &.{ .H2, .HTTP_1_1 },
        .GRPC => &.{.H2},
        else => &.{.HTTP_1_1},
    };
}

/// Build the live TLS context for one site from its cert / key paths.
///
/// Param:
/// alpn - []const Tls.Alpn (protocol preferences, borrowed for the
/// context lifetime, see alpnPrefs)
///
/// Return:
/// - Tls.Context (release with deinit)
/// - the Tls.Context.init errors (missing file, bad PEM, unsupported key)
pub fn buildContext(allocator: std.mem.Allocator, io: std.Io, cert_path: []const u8, key_path: []const u8, alpn: []const Tls.Alpn) !Tls.Context {
    return Tls.Context.init(allocator, io, .{
        .cert_path = cert_path,
        .key_path = key_path,
        .alpn = alpn,
    });
}

/// The established connection state, TLS 1.3 or 1.2. Both expose the same
/// sans-I/O record calls, only the error sets differ.
const Conn = union(enum) {
    tls13: Tls.Connection,
    tls12: Tls.Server12.Connection,

    fn readAppData(conn: *Conn, rec: []const u8, out: []u8) ![]const u8 {
        return switch (conn.*) {
            .tls13 => |*inner| inner.readAppData(rec, out),
            .tls12 => |*inner| inner.readAppData(rec, out),
        };
    }

    fn writeAppData(conn: *Conn, plaintext: []const u8, out: []u8) []const u8 {
        return switch (conn.*) {
            .tls13 => |*inner| inner.writeAppData(plaintext, out),
            .tls12 => |*inner| inner.writeAppData(plaintext, out),
        };
    }

    fn closeNotify(conn: *Conn, out: []u8) []const u8 {
        return switch (conn.*) {
            .tls13 => |*inner| inner.closeNotify(out),
            .tls12 => |*inner| inner.closeNotify(out),
        };
    }
};

/// One record read off the wire: 5-byte header plus body.
const RecordView = struct {
    content_type: u8,
    full: []const u8,
    body: []const u8,
};

/// One terminated edge connection: the established session plus the
/// plaintext reader / writer interfaces the request loop runs over.
///
/// Note:
/// - Pinned once bound: the interfaces point into the struct's own buffers,
///   so a Session never moves after bind (heap or a stable stack frame).
pub const Session = struct {
    conn: Conn,
    /// The protocol the handshake negotiated, null when the client
    /// offered no ALPN. The serve dispatch branches on it.
    alpn: ?Tls.Alpn,
    stream_r: *std.Io.Reader,
    stream_w: *std.Io.Writer,
    reader: std.Io.Reader,
    writer: std.Io.Writer,
    record_buf: [Tls.max_record_wire]u8,
    read_plain: [READ_PLAIN_SIZE]u8,
    write_stage: [WRITE_STAGE_SIZE]u8,

    /// Wire the interfaces onto an established connection. The handshake
    /// path calls this, tests bind a hand-established pair directly.
    pub fn bind(session: *Session, conn: Conn, stream_r: *std.Io.Reader, stream_w: *std.Io.Writer) void {
        session.conn = conn;
        session.alpn = null;
        session.stream_r = stream_r;
        session.stream_w = stream_w;
        session.reader = .{
            .vtable = &reader_vtable,
            .buffer = &session.read_plain,
            .seek = 0,
            .end = 0,
        };
        session.writer = .{
            .vtable = &writer_vtable,
            .buffer = &session.write_stage,
            .end = 0,
        };
    }

    /// Best-effort clean closure: seal a close_notify and flush it out.
    pub fn sendCloseNotify(session: *Session) void {
        var out: [ALERT_OUT_SIZE]u8 = undefined;
        const rec = session.conn.closeNotify(&out);

        session.stream_w.writeAll(rec) catch return;
        session.stream_w.flush() catch return;
    }
};

const reader_vtable = std.Io.Reader.VTable{ .stream = streamDecrypt };
const writer_vtable = std.Io.Writer.VTable{ .drain = drainSeal, .flush = flushSeal };

/// Reader vtable: pull ciphertext records off the stream, decrypt into the
/// interface buffer. A close_notify or a clean hangup is end of stream.
fn streamDecrypt(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    _ = w;
    _ = limit;
    const session: *Session = @alignCast(@fieldParentPtr("reader", r));

    while (true) {
        const rec = recordView(readRecord(session.stream_r, &session.record_buf) catch |err| {
            if (err == error.EndOfStream) return error.EndOfStream;

            return error.ReadFailed;
        });

        switch (rec.content_type) {
            content_type_change_cipher_spec => continue,
            content_type_alert => return error.EndOfStream,
            content_type_application_data => {},
            else => return error.ReadFailed,
        }

        dropConsumedPrefix(r);

        // deprotect needs ciphertext-length out space behind the buffered
        // plaintext. The buffer sizing guarantees it, this guard keeps a
        // shortfall an error instead of an overflow.
        if (r.buffer.len - r.end < rec.full.len) return error.ReadFailed;

        const plain = session.conn.readAppData(rec.full, r.buffer[r.end..]) catch |err| {
            if (err == error.ZixPeerClosed) return error.EndOfStream;

            return error.ReadFailed;
        };
        if (plain.len == 0) continue;

        r.end += plain.len;

        return 0;
    }
}

/// Move the still-unread bytes to the front of the reader buffer so the
/// free tail can hold the next record.
///
/// Note:
/// - Without this the buffer only ever grows forward: end walks to the far
///   wall and the connection then fails on the space guard, whatever the
///   request rate. On a keep-alive TLS connection that lands after roughly
///   one buffer of cumulative request bytes.
/// - The common case costs no copy: a request loop consumes its head and
///   body before asking for more, so seek equals end and both reset to 0.
/// - std.Io.Reader.rebase cannot stand in here. It measures free space from
///   seek, this needs it from end, so rebase returns early on exactly the
///   buffer state that is about to fail.
fn dropConsumedPrefix(r: *std.Io.Reader) void {
    if (r.seek == 0) return;

    const pending = r.buffer[r.seek..r.end];
    @memmove(r.buffer[0..pending.len], pending);

    r.seek = 0;
    r.end = pending.len;
}

/// Writer vtable: seal the staged plaintext plus the incoming slices as
/// application records, one record per max_plaintext chunk.
fn drainSeal(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    const session: *Session = @alignCast(@fieldParentPtr("writer", w));

    try sealChunks(session, w.buffer[0..w.end]);
    w.end = 0;

    var consumed: usize = 0;
    for (data[0 .. data.len - 1]) |slice| {
        try sealChunks(session, slice);
        consumed += slice.len;
    }

    const last = data[data.len - 1];
    for (0..splat) |_| {
        try sealChunks(session, last);
        consumed += last.len;
    }

    return consumed;
}

fn flushSeal(w: *std.Io.Writer) std.Io.Writer.Error!void {
    const session: *Session = @alignCast(@fieldParentPtr("writer", w));

    while (w.end != 0) _ = try drainSeal(w, &.{""}, 1);
    try session.stream_w.flush();
}

/// Seal one plaintext run as however many records it takes.
fn sealChunks(session: *Session, plaintext: []const u8) std.Io.Writer.Error!void {
    var rest = plaintext;
    while (rest.len > 0) {
        const take = @min(rest.len, Tls.max_plaintext);

        var sealed: [SEAL_OUT_SIZE]u8 = undefined;
        const rec = session.conn.writeAppData(rest[0..take], &sealed);
        if (rec.len == 0) return error.WriteFailed;

        try session.stream_w.writeAll(rec);
        rest = rest[take..];
    }
}

/// Read one TLS record (5-byte header plus body) into buf.
fn readRecord(stream_r: *std.Io.Reader, buf: []u8) ![]const u8 {
    try stream_r.readSliceAll(buf[0..5]);

    const length = std.mem.readInt(u16, buf[3..5], .big);
    if (5 + @as(usize, length) > buf.len) return error.ZixerRecordTooLarge;
    try stream_r.readSliceAll(buf[5 .. 5 + length]);

    return buf[0 .. 5 + length];
}

fn recordView(bytes: []const u8) RecordView {
    return .{ .content_type = bytes[0], .full = bytes, .body = bytes[5..] };
}

/// Drive the server handshake over the stream and bind the session.
///
/// Note:
/// - Mirrors the zix engine's blocking serve path: HelloRetryRequest when
///   the 1.3 client's group has no key_share, 1.2 fallback when the client
///   never offered 1.3 (ECDSA contexts only), fatal alert on a rejected
///   ClientHello.
///
/// Param:
/// session - *Session (bound on success, pinned from here on)
/// io - std.Io (handshake randoms)
/// ctx - *const Tls.Context (the site's loaded cert / key / policy)
/// stream_r - *std.Io.Reader (ciphertext in, stays the session's inner leg)
/// stream_w - *std.Io.Writer (ciphertext out, same)
///
/// Return:
/// - void, session bound
/// - the handshake errors (bad ClientHello, version refused, peer abort)
pub fn handshake(session: *Session, io: std.Io, ctx: *const Tls.Context, stream_r: *std.Io.Reader, stream_w: *std.Io.Writer) !void {
    const hello_rec = recordView(try readRecord(stream_r, &session.record_buf));
    if (hello_rec.content_type != content_type_handshake) return error.ZixerUnexpectedRecord;

    var ephemeral_secret: [32]u8 = undefined;
    var server_random: [32]u8 = undefined;
    var pss_salt: [32]u8 = undefined;
    try io.randomSecure(&ephemeral_secret);
    try io.randomSecure(&server_random);
    try io.randomSecure(&pss_salt);

    const opts = ctx.handshakeOptions(ephemeral_secret, server_random, pss_salt);

    if (!ctx.allowsTls13()) {
        return handshake12(session, ctx, opts, hello_rec.body, stream_r, stream_w);
    }

    // HelloRetryRequest (RFC 8446 4.1.4): the client picked a group it gave
    // no key_share for, ask again. A 1.2-only client surfaces as
    // UnsupportedTlsVersion and falls through to the version check below.
    var handshake_out: [FLIGHT_OUT_SIZE]u8 = undefined;
    var hrr_out: [RETRY_OUT_SIZE]u8 = undefined;
    var retry_state: ?Tls.RetryState = null;
    var second_hello: []const u8 = &.{};
    if (Tls.serverHelloRetry(opts, hello_rec.body, &hrr_out)) |maybe_retry| {
        if (maybe_retry) |retry| {
            try stream_w.writeAll(retry.to_send);
            try stream_w.flush();

            const second_rec = recordView(try readRecord(stream_r, &session.record_buf));
            if (second_rec.content_type != content_type_handshake) return error.ZixerUnexpectedRecord;

            retry_state = retry.state;
            second_hello = second_rec.body;
        }
    } else |err| {
        if (err != error.ZixUnsupportedTlsVersion) {
            sendAlertFor(stream_w, err);
            return err;
        }
    }

    const result = if (retry_state) |state|
        try Tls.serverHandshakeAfterRetry(state, second_hello, &handshake_out)
    else
        Tls.serverHandshake(opts, hello_rec.body, &handshake_out) catch |err| {
            if (err == error.ZixUnsupportedTlsVersion and ctx.allowsTls12()) {
                return handshake12(session, ctx, opts, hello_rec.body, stream_r, stream_w);
            }

            sendAlertFor(stream_w, err);
            return err;
        };
    try stream_w.writeAll(result.to_send);
    try stream_w.flush();
    var conn = result.connection;

    // client ChangeCipherSpec (skipped) + Finished. A plaintext alert here
    // means the peer aborted.
    while (true) {
        const rec = recordView(try readRecord(stream_r, &session.record_buf));
        if (rec.content_type == content_type_change_cipher_spec) continue;
        if (rec.content_type == content_type_alert) return error.ZixerPeerAborted;
        if (rec.content_type != content_type_application_data) return error.ZixerUnexpectedRecord;

        try conn.verifyClientFinished(rec.full);
        break;
    }

    session.bind(.{ .tls13 = conn }, stream_r, stream_w);
    session.alpn = result.alpn;
}

/// TLS 1.2 fallback (RFC 5246, ECDHE-ECDSA): two-phase handshake, then the
/// same session interfaces. Reached when the client never offered 1.3.
fn handshake12(session: *Session, ctx: *const Tls.Context, opts: Tls.HandshakeOptions, client_hello: []const u8, stream_r: *std.Io.Reader, stream_w: *std.Io.Writer) !void {
    const ecdsa_key = switch (ctx.signing_key) {
        .ecdsa_p256 => |key_pair| key_pair,
        else => return error.ZixerTls12RequiresEcdsa,
    };

    var flight_out: [FLIGHT_OUT_SIZE]u8 = undefined;
    const flight = try Tls.Server12.serverFlight1(.{
        .certificate_der = ctx.cert_der,
        .signing_key = ecdsa_key,
        .server_eph_secret = opts.ephemeral_secret,
        .server_random = opts.server_random,
        .alpn_prefs = ctx.alpn,
    }, client_hello, &flight_out);
    try stream_w.writeAll(flight.to_send);
    try stream_w.flush();
    var state = flight.state;

    // ClientKeyExchange (plaintext handshake record), copied out before the
    // record buffer is reused.
    const cke_rec = recordView(try readRecord(stream_r, &session.record_buf));
    if (cke_rec.content_type != content_type_handshake) return error.ZixerUnexpectedRecord;
    if (cke_rec.body.len > KEY_EXCHANGE_SIZE) return error.ZixerRecordTooLarge;
    var cke_buf: [KEY_EXCHANGE_SIZE]u8 = undefined;
    @memcpy(cke_buf[0..cke_rec.body.len], cke_rec.body);
    const client_key_exchange = cke_buf[0..cke_rec.body.len];

    // skip ChangeCipherSpec, then the encrypted client Finished.
    const finished_rec = while (true) {
        const rec = recordView(try readRecord(stream_r, &session.record_buf));
        if (rec.content_type == content_type_change_cipher_spec) continue;
        if (rec.content_type == content_type_alert) return error.ZixerPeerAborted;
        if (rec.content_type != content_type_handshake) return error.ZixerUnexpectedRecord;

        break rec;
    };

    var finish_out: [FINISHED_OUT_SIZE]u8 = undefined;
    const finish = try Tls.Server12.serverFinish(&state, client_key_exchange, finished_rec.full, &finish_out);
    try stream_w.writeAll(finish.to_send);
    try stream_w.flush();

    session.bind(.{ .tls12 = finish.connection }, stream_r, stream_w);
    session.alpn = state.alpn;
}

/// Best-effort fatal alert in the clear (no keys yet) for a rejected hello.
fn sendAlertFor(stream_w: *std.Io.Writer, err: anyerror) void {
    var alert_buf: [Tls.fatal_record_len]u8 = undefined;
    const rec = Tls.alertRecordForError(&alert_buf, err) orelse return;

    stream_w.writeAll(rec) catch return;
    stream_w.flush() catch return;
}

/// Serve one accepted edge connection with TLS terminated here: handshake,
/// then the request loop the negotiated protocol picks, over the
/// decrypted interfaces.
///
/// Note:
/// - An http2 site serves h2 when ALPN settled on it, and still sniffs
///   the prior-knowledge preface when the client offered no ALPN.
/// - A grpc site always runs the grpc relay: only h2 was offered, and the
///   relay itself requires the preface. Everything else runs the h1 loop.
/// - The site's client bound is taken ahead of the handshake, and a site with
///   no slot left closes the connection unanswered. Nothing has been
///   negotiated at that point, so there is no session to write a status over,
///   and a key exchange is the last thing to spend on a connection that is
///   already being refused.
pub fn serveConn(proxy: *const http1_proxy.Proxy, ctx: *const Tls.Context, client_stream: std.Io.net.Stream, engine: site_cfg.Engine) void {
    const io = proxy.io;
    defer client_stream.close(io);

    var lease = client_lease.Lease.open(proxy.client_table, io, client_stream.socket.handle, proxy.client_timeout_ms) orelse return;
    defer lease.release();

    // The wire pair only carries ciphertext to and from the socket. The
    // plaintext side is the Session's own buffers, which stay fixed: a
    // whole TLS record has to fit whatever the site configured.
    const buffers = conn_buffer.Set.init(proxy.allocator, proxy.stream_buf_bytes, .{ .client = true, .upstream = false }) catch return;
    defer buffers.deinit(proxy.allocator);

    // The sweep cuts this socket from another thread when the bound runs out, the first tick on
    // the read side and the next on both, so the ciphertext leg goes over the pair that ends on a
    // cut rather than the std pair that panics on it.
    var stream_reader = socket_cut_reader.init(client_stream, io, buffers.client_read);
    var stream_writer = socket_cut_writer.init(client_stream, io, buffers.client_write);

    var session: Session = undefined;
    handshake(&session, io, ctx, &stream_reader.interface, &stream_writer.interface) catch return;

    const wants_h2 = engine == .HTTP2 and
        (session.alpn == .H2 or (session.alpn == null and http2_edge.prefersH2(&session.reader)));
    if (engine == .GRPC) {
        grpc_edge.serveSession(proxy, &session.reader, &session.writer, client_stream.socket.address, client_stream, &lease);
    } else if (wants_h2) {
        http2_edge.serveSession(proxy, &session.reader, &session.writer, client_stream.socket.address, client_stream, &lease);
    } else {
        http1_proxy.serveLoop(proxy, &session.reader, &session.writer, client_stream.socket.address, client_stream, null, &lease);
    }
    session.sendCloseNotify();
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// Ciphertext leg size the rigs below bind with. The serving path takes
/// its size from the site instead, see conn_buffer.
const STREAM_BUF_SIZE: usize = 8 * 1024;

const FIXTURE_CERT = "examples/certs/ecdsa_p256_cert.pem";
const FIXTURE_KEY = "examples/certs/ecdsa_p256_key.pem";

/// Established TLS 1.3 pair for pure record tests: the server connection
/// the session runs plus its mirror client, no sockets involved.
const TestPair = struct {
    ctx: Tls.Context,
    server: Tls.Connection,
    client: Tls.Client.ClientConnection,

    fn deinit(pair: *TestPair) void {
        pair.ctx.deinit();
    }
};

fn establishPair(io: std.Io) !TestPair {
    var ctx = try buildContext(testing.allocator, io, FIXTURE_CERT, FIXTURE_KEY, &.{.HTTP_1_1});
    errdefer ctx.deinit();

    var hello_buf: [512]u8 = undefined;
    const started = try Tls.Client.start(.{
        .client_random = @splat(0x11),
        .ephemeral_secret = @splat(0x42),
        .alpn = &.{.HTTP_1_1},
    }, &hello_buf);
    var state = started.state;

    var flight_buf: [FLIGHT_OUT_SIZE]u8 = undefined;
    const opts = ctx.handshakeOptions(@splat(0x24), @splat(0x35), @splat(0x46));
    const result = try Tls.serverHandshake(opts, started.client_hello, &flight_buf);
    var server_conn = result.connection;

    var finish_buf: [256]u8 = undefined;
    const finished = try Tls.Client.finish(&state, result.to_send, &finish_buf);
    try server_conn.verifyClientFinished(finished.client_finished);

    return .{ .ctx = ctx, .server = server_conn, .client = finished.connection };
}

/// Split a byte run of sealed records and decrypt each on the client side.
fn clientDecryptAll(client: *Tls.Client.ClientConnection, wire: []const u8, out: []u8) !usize {
    var scratch: [Tls.max_record_wire]u8 = undefined;
    var offset: usize = 0;
    var total: usize = 0;
    while (offset < wire.len) {
        const body_len = std.mem.readInt(u16, wire[offset + 3 ..][0..2], .big);
        const rec = wire[offset .. offset + 5 + body_len];
        offset += rec.len;

        const plain = try client.readAppData(rec, &scratch);
        @memcpy(out[total..][0..plain.len], plain);
        total += plain.len;
    }

    return total;
}

test "zix zixer: tls edge, alpn preferences follow the site engine" {
    try testing.expectEqualSlices(Tls.Alpn, &.{ .H2, .HTTP_1_1 }, alpnPrefs(.HTTP2));
    try testing.expectEqualSlices(Tls.Alpn, &.{.H2}, alpnPrefs(.GRPC));
    try testing.expectEqualSlices(Tls.Alpn, &.{.HTTP_1_1}, alpnPrefs(.HTTP1));
}

test "zix zixer: tls edge, context builds from the shared cert fixtures" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var ctx = try buildContext(testing.allocator, io, FIXTURE_CERT, FIXTURE_KEY, &.{.HTTP_1_1});
    defer ctx.deinit();

    try testing.expect(ctx.cert_der.len > 0);
    try testing.expectEqual(@as(usize, 1), ctx.alpn.len);

    try testing.expectError(error.ZixTlsCertFileNotFound, buildContext(testing.allocator, io, "examples/certs/absent.pem", FIXTURE_KEY, &.{.HTTP_1_1}));
}

test "zix zixer: tls edge, reader decrypts across records and ends on close notify" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try establishPair(io);
    defer pair.deinit();

    var wire: [1024]u8 = undefined;
    var wire_len: usize = 0;
    for ([_][]const u8{ "hello ", "world" }) |piece| {
        const rec = pair.client.writeAppData(piece, wire[wire_len..]);
        wire_len += rec.len;
    }
    const close_rec = pair.client.closeNotify(wire[wire_len..]);
    wire_len += close_rec.len;

    var src = std.Io.Reader.fixed(wire[0..wire_len]);
    var sink_buf: [64]u8 = undefined;
    var sink = std.Io.Writer.fixed(&sink_buf);
    var session: Session = undefined;
    session.bind(.{ .tls13 = pair.server }, &src, &sink);

    var out: [11]u8 = undefined;
    try session.reader.readSliceAll(&out);
    try testing.expectEqualStrings("hello world", &out);

    try testing.expectError(error.EndOfStream, session.reader.readSliceAll(out[0..1]));
}

test "zix zixer: tls edge, drop consumed prefix reclaims the read buffer" {
    var buf: [16]u8 = undefined;
    @memcpy(buf[0..8], "abcdefgh");

    // Partly consumed: the unread tail moves to the front.
    var reader = std.Io.Reader{ .vtable = &reader_vtable, .buffer = &buf, .seek = 5, .end = 8 };
    dropConsumedPrefix(&reader);
    try testing.expectEqual(@as(usize, 0), reader.seek);
    try testing.expectEqual(@as(usize, 3), reader.end);
    try testing.expectEqualStrings("fgh", reader.buffer[0..reader.end]);

    // Fully consumed is the common case: both indices reset, no bytes move.
    reader.seek = 3;
    reader.end = 3;
    dropConsumedPrefix(&reader);
    try testing.expectEqual(@as(usize, 0), reader.seek);
    try testing.expectEqual(@as(usize, 0), reader.end);

    // Nothing consumed yet: the buffer is left exactly as it was.
    @memcpy(buf[0..4], "wxyz");
    reader.seek = 0;
    reader.end = 4;
    dropConsumedPrefix(&reader);
    try testing.expectEqual(@as(usize, 0), reader.seek);
    try testing.expectEqual(@as(usize, 4), reader.end);
    try testing.expectEqualStrings("wxyz", reader.buffer[0..reader.end]);
}

test "zix zixer: tls edge, one session reads past a full read buffer of records" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try establishPair(io);
    defer pair.deinit();

    // Two buffers' worth of client bytes on one connection, which is what a
    // keep-alive client sends over a few hundred requests. The reader has to
    // reclaim what the caller already took or it walks into the far wall and
    // the connection dies on the space guard.
    const CHUNK: usize = 1024;
    const rounds: usize = 2 * READ_PLAIN_SIZE / CHUNK;

    const wire = try testing.allocator.alloc(u8, rounds * Tls.sealedLen(CHUNK));
    defer testing.allocator.free(wire);

    var payload: [CHUNK]u8 = undefined;
    var wire_len: usize = 0;
    for (0..rounds) |round| {
        @memset(&payload, @intCast('a' + round % 26));
        const rec = pair.client.writeAppData(&payload, wire[wire_len..]);
        wire_len += rec.len;
    }

    var src = std.Io.Reader.fixed(wire[0..wire_len]);
    var sink_buf: [64]u8 = undefined;
    var sink = std.Io.Writer.fixed(&sink_buf);
    var session: Session = undefined;
    session.bind(.{ .tls13 = pair.server }, &src, &sink);

    var out: [CHUNK]u8 = undefined;
    for (0..rounds) |round| {
        try session.reader.readSliceAll(&out);

        const want: u8 = @intCast('a' + round % 26);
        try testing.expect(std.mem.allEqual(u8, &out, want));
    }
}

test "zix zixer: tls edge, a partly read record survives the next decrypt" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try establishPair(io);
    defer pair.deinit();

    // Reading fewer bytes than a record carries leaves a pending tail. The
    // reclaim has to move that tail, not drop it.
    var wire: [2048]u8 = undefined;
    var wire_len: usize = 0;
    for ([_][]const u8{ "first-record", "second-record" }) |piece| {
        const rec = pair.client.writeAppData(piece, wire[wire_len..]);
        wire_len += rec.len;
    }

    var src = std.Io.Reader.fixed(wire[0..wire_len]);
    var sink_buf: [64]u8 = undefined;
    var sink = std.Io.Writer.fixed(&sink_buf);
    var session: Session = undefined;
    session.bind(.{ .tls13 = pair.server }, &src, &sink);

    var head: [5]u8 = undefined;
    try session.reader.readSliceAll(&head);
    try testing.expectEqualStrings("first", &head);

    var rest: [20]u8 = undefined;
    try session.reader.readSliceAll(&rest);
    try testing.expectEqualStrings("-recordsecond-record", &rest);
}

test "zix zixer: tls edge, writer seals oversize writes as split records" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try establishPair(io);
    defer pair.deinit();

    var src = std.Io.Reader.fixed("");
    const sink_buf = try testing.allocator.alloc(u8, 2 * SEAL_OUT_SIZE);
    defer testing.allocator.free(sink_buf);
    var sink = std.Io.Writer.fixed(sink_buf);
    var session: Session = undefined;
    session.bind(.{ .tls13 = pair.server }, &src, &sink);

    const payload = try testing.allocator.alloc(u8, Tls.max_plaintext + 4096);
    defer testing.allocator.free(payload);
    for (payload, 0..) |*byte, i| byte.* = @intCast(i % 251);

    try session.writer.writeAll(payload);
    try session.writer.flush();

    const plain_out = try testing.allocator.alloc(u8, payload.len);
    defer testing.allocator.free(plain_out);
    const got = try clientDecryptAll(&pair.client, sink.buffered(), plain_out);

    try testing.expectEqual(payload.len, got);
    try testing.expectEqualSlices(u8, payload, plain_out[0..got]);
}

test "zix zixer: tls edge, tls12 session pumps the same interfaces" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var ctx = try buildContext(testing.allocator, io, FIXTURE_CERT, FIXTURE_KEY, &.{.HTTP_1_1});
    defer ctx.deinit();
    const ecdsa_key = switch (ctx.signing_key) {
        .ecdsa_p256 => |key_pair| key_pair,
        else => return error.TestUnexpectedResult,
    };

    // pure lockstep 1.2 handshake: every step is a sans-I/O call.
    var hello_buf: [512]u8 = undefined;
    const started = Tls.Client12.start(.{ .client_random = @splat(0x21), .ephemeral_secret = @splat(0x52) }, &hello_buf);
    var client_state = started.state;

    var flight_buf: [FLIGHT_OUT_SIZE]u8 = undefined;
    const flight = try Tls.Server12.serverFlight1(.{
        .certificate_der = ctx.cert_der,
        .signing_key = ecdsa_key,
        .server_eph_secret = @splat(0x63),
        .server_random = @splat(0x74),
        .alpn_prefs = ctx.alpn,
    }, started.client_hello, &flight_buf);
    var server_state = flight.state;

    var finish_buf: [512]u8 = undefined;
    const client_finish = try Tls.Client12.finish(&client_state, flight.to_send, &finish_buf);
    var client_conn = client_finish.connection;

    // the client's to_send carries CKE + CCS + Finished as three records.
    const cke_end = 5 + std.mem.readInt(u16, client_finish.to_send[3..5], .big);
    const ccs_end = cke_end + 5 + std.mem.readInt(u16, client_finish.to_send[cke_end + 3 ..][0..2], .big);
    var server_out: [FINISHED_OUT_SIZE]u8 = undefined;
    const server_finish = try Tls.Server12.serverFinish(
        &server_state,
        client_finish.to_send[5..cke_end],
        client_finish.to_send[ccs_end..],
        &server_out,
    );

    var wire: [256]u8 = undefined;
    var wire_len: usize = 0;
    const request_rec = client_conn.writeAppData("ping", &wire);
    wire_len += request_rec.len;

    var src = std.Io.Reader.fixed(wire[0..wire_len]);
    var sink_buf: [256]u8 = undefined;
    var sink = std.Io.Writer.fixed(&sink_buf);
    var session: Session = undefined;
    session.bind(.{ .tls12 = server_finish.connection }, &src, &sink);

    var out: [4]u8 = undefined;
    try session.reader.readSliceAll(&out);
    try testing.expectEqualStrings("ping", &out);

    try session.writer.writeAll("pong");
    try session.writer.flush();

    var plain: [64]u8 = undefined;
    const reply = try client_conn.readAppData(sink.buffered(), &plain);
    try testing.expectEqualStrings("pong", reply);
}

/// Loopback server side: accept one conn, handshake, answer one 4-byte
/// request with "pong", close cleanly.
fn loopbackServer(io: std.Io, server: *std.Io.net.Server, ctx: *const Tls.Context) void {
    const stream = server.accept(io) catch return;
    defer stream.close(io);

    var read_buf: [STREAM_BUF_SIZE]u8 = undefined;
    var write_buf: [STREAM_BUF_SIZE]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    var stream_writer = stream.writer(io, &write_buf);

    var session: Session = undefined;
    handshake(&session, io, ctx, &stream_reader.interface, &stream_writer.interface) catch return;

    var line: [4]u8 = undefined;
    session.reader.readSliceAll(&line) catch return;
    if (!std.mem.eql(u8, &line, "ping")) return;

    session.writer.writeAll("pong") catch return;
    session.writer.flush() catch return;
    session.sendCloseNotify();
}

test "zix zixer: tls edge, handshake terminates a tls13 client over loopback" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var ctx = try buildContext(testing.allocator, io, FIXTURE_CERT, FIXTURE_KEY, &.{.HTTP_1_1});
    defer ctx.deinit();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18890);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const server_thread = try std.Thread.spawn(.{}, loopbackServer, .{ io, &server, &ctx });
    defer server_thread.join();

    const stream = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);
    var read_buf: [STREAM_BUF_SIZE]u8 = undefined;
    var write_buf: [STREAM_BUF_SIZE]u8 = undefined;
    var client_reader = stream.reader(io, &read_buf);
    var client_writer = stream.writer(io, &write_buf);

    // ClientHello wrapped in a plaintext handshake record.
    var hello_buf: [512]u8 = undefined;
    const started = try Tls.Client.start(.{
        .client_random = @splat(0x11),
        .ephemeral_secret = @splat(0x42),
        .alpn = &.{.HTTP_1_1},
    }, &hello_buf);
    var state = started.state;

    var hello_rec: [600]u8 = undefined;
    hello_rec[0] = content_type_handshake;
    std.mem.writeInt(u16, hello_rec[1..3], 0x0303, .big);
    std.mem.writeInt(u16, hello_rec[3..5], @intCast(started.client_hello.len), .big);
    @memcpy(hello_rec[5 .. 5 + started.client_hello.len], started.client_hello);
    try client_writer.interface.writeAll(hello_rec[0 .. 5 + started.client_hello.len]);
    try client_writer.interface.flush();

    // the server flight arrives as three records.
    var flight_buf: [FLIGHT_OUT_SIZE]u8 = undefined;
    var flight_len: usize = 0;
    for (0..3) |_| {
        const rec = try readRecord(&client_reader.interface, flight_buf[flight_len..]);
        flight_len += rec.len;
    }

    var finish_buf: [256]u8 = undefined;
    const finished = try Tls.Client.finish(&state, flight_buf[0..flight_len], &finish_buf);
    var client_conn = finished.connection;
    try client_writer.interface.writeAll(finished.client_finished);
    try client_writer.interface.flush();

    var request_out: [64]u8 = undefined;
    try client_writer.interface.writeAll(client_conn.writeAppData("ping", &request_out));
    try client_writer.interface.flush();

    var reply_rec_buf: [256]u8 = undefined;
    const reply_rec = try readRecord(&client_reader.interface, &reply_rec_buf);
    var reply_plain: [64]u8 = undefined;
    const reply = try client_conn.readAppData(reply_rec, &reply_plain);
    try testing.expectEqualStrings("pong", reply);
}

// --------------------------------------------------------- //

const deadline_table = @import("deadline_table.zig");

const socket_poll = zix.utils.socket_poll;

/// Serve one TLS connection on its own thread, flagging the way out, so a test
/// can tell the edge let go instead of waiting on a join that may hang.
const TlsServeProbe = struct {
    proxy: *const http1_proxy.Proxy,
    ctx: *const Tls.Context,
    stream: std.Io.net.Stream,
    done: std.atomic.Value(bool) = .init(false),

    fn run(probe: *TlsServeProbe) void {
        serveConn(probe.proxy, probe.ctx, probe.stream, .HTTP1);
        probe.done.store(true, .release);
    }
};

test "zix zixer: tls edge, a site at its connection limit closes before the handshake" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var ctx = try buildContext(testing.allocator, io, FIXTURE_CERT, FIXTURE_KEY, &.{.HTTP_1_1});
    defer ctx.deinit();

    var table = try deadline_table.Table.init(testing.allocator, 1);
    defer table.deinit(testing.allocator);

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18901);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);
    const accepted = try server.accept(io);

    // The site's only slot is already spoken for, so the connection under test
    // arrives at a full table.
    try testing.expect(table.claim(client.socket.handle, deadline_table.NEVER_MS) == .TAKEN);

    const proxy = http1_proxy.Proxy{ .io = io, .client_table = &table, .client_timeout_ms = 60_000 };
    var probe = TlsServeProbe{ .proxy = &proxy, .ctx = &ctx, .stream = accepted };
    const thread = try std.Thread.spawn(.{}, TlsServeProbe.run, .{&probe});

    // A refused connection is closed, so the socket becomes readable at once.
    // An edge that went into the handshake instead would leave it silent, and
    // the wait is what turns that into a failure rather than a hang.
    try testing.expect(socket_poll.readableWithin(client.socket.handle, 5_000));

    // Nothing was written at all: there is no session to carry a status over
    // before a handshake, so the close is the whole answer.
    var read_buf: [64]u8 = undefined;
    var reader = client.reader(io, &read_buf);
    var byte: [1]u8 = undefined;
    try testing.expectError(error.EndOfStream, reader.interface.readSliceAll(&byte));

    thread.join();
    try testing.expect(probe.done.load(.acquire));

    // The refused connection never took a slot of its own.
    try testing.expectEqual(@as(usize, 1), table.liveCount());
}
