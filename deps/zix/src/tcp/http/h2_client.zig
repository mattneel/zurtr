//! Native HTTP/2 over TLS 1.3 client transport: the ALPN-h2 backend for zix.Http.Client.
//!
//! What:
//!   std.http.Client is HTTP/1-only and cannot offer ALPN, so it cannot speak h2. This module is
//!   the path zix.Http.Client.request() takes when config.version is HTTP_2 and the URL is https.
//!   It connects TCP, runs the TLS 1.3 handshake through zix.Tls.Client offering ALPN h2, trusts
//!   the server cert (chain RFC 5280 + hostname RFC 6125, the task-1 step), then performs one
//!   request / response over a single h2 stream and returns the parsed pieces.
//!
//! Note:
//! - One request per connection (no pooling). Sufficient for a request() call, the connection is
//!   torn down after the response.
//! - Trust anchor: the native client validates against ONE anchor (config.tls_ca_path), the same
//!   one-link scope as cert_verify. Public-CA system roots (a multi-link chain against the system
//!   bundle) come later, so tls_verify with no tls_ca_path is rejected up front rather than
//!   silently trusting nothing.
//! - Response headers must fit in one HEADERS frame (END_HEADERS). CONTINUATION is not handled.

const std = @import("std");
const builtin = @import("builtin");
const win_io = @import("../../utils/windows_io.zig");
const fd_io = @import("../../utils/fd_io.zig");
const socket_poll = @import("../../utils/socket_poll.zig");
const Config = @import("client_config.zig");
const HttpClientConfig = Config.HttpClientConfig;
const Method = @import("method.zig");
const Tls = @import("../../tls/Tls.zig");
const record = @import("../../tls/record.zig");
const Http2 = @import("../http2/Http2.zig");

/// TLS ClientHello scratch buffer.
const CLIENT_HELLO_BUF: usize = 600;
/// TLS handshake flight buffer.
const HANDSHAKE_FLIGHT_BUF: usize = 8192;
/// TLS Finished (client) message output buffer.
const FINISHED_BUF: usize = 256;
/// Scratch buffer for lowercasing one request header name before HPACK encoding.
const HEADER_NAME_BUF: usize = 256;
/// CA certificate PEM read buffer and read limit.
const CA_PEM_BUF: usize = 8192;
/// HPACK header block buffer.
const HPACK_BLOCK_BUF: usize = 4096;
/// h2 frame-out buffer.
const FRAME_OUT_BUF: usize = 8192;
/// h2 send buffer.
const H2_SEND_BUF: usize = 9 * 1024;
/// Per-frame scratch buffer.
const FRAME_SCRATCH: usize = 16 * 1024;
/// h2 response accumulator (hard caps the received body size).
const H2_RESPONSE_ACC: usize = 64 * 1024;

const posix = std.posix;

// the response flow-control window opened so the server can stream a large body without stalling.
// initial window is 65535, this increment keeps the connection + stream windows well above
// max_response_body without crossing the 2^31-1 ceiling.
const WINDOW_INCREMENT: u31 = 1 << 30;

// --------------------------------------------------------- //

/// The parsed response pieces, owned by config.allocator. The caller wraps these in ClientResponse.
pub const Parts = struct {
    status_code: u16,
    /// synthesized HTTP-style head ("HTTP/2 <status>\r\n" + regular headers + "\r\n").
    head_bytes: []u8,
    body_data: []u8,
};

// --------------------------------------------------------- //

/// Perform one HTTP/2 request over TLS 1.3 and return the parsed response.
///
/// Param:
/// config - HttpClientConfig (allocator, io, tls_verify, tls_ca_path, max_response_body, user_agent)
/// method - Method.Code
/// host - std.Io.net.HostName (authority host, resolved for connect + matched against the cert)
/// port - u16
/// path - []const u8 (the :path pseudo-header, including any query)
/// headers - []const std.http.Header (extra request headers, lowercased on the wire)
/// body - ?[]const u8 (request body, null for none)
///
/// Return:
/// - Parts (owned by config.allocator)
/// - error.ZixTlsNoTrustAnchor (tls_verify is on but tls_ca_path is null)
/// - error.ZixAlpnNotH2 (server did not select h2)
/// - error.ZixUnsupportedH2 (response headers spanned CONTINUATION frames)
/// - error.ZixBodyTooLarge / error.ZixNoStatus / error.ZixStreamReset / error.ZixGoaway
pub fn fetch(
    config: HttpClientConfig,
    method: Method.Code,
    host: std.Io.net.HostName,
    port: u16,
    path: []const u8,
    headers: []const std.http.Header,
    body: ?[]const u8,
) !Parts {
    const io = config.io;
    const gpa = config.allocator;

    // HostName.connect resolves the name (reads /etc/hosts, then DNS), unlike IpAddress.resolve
    // which only parses an IP literal.
    const stream = try host.connect(io, port, .{ .mode = .stream });
    defer stream.close(io);
    const fd = stream.socket.handle;

    var conn = try handshake(config, fd, host.bytes);

    try sendRequestFD(fd, &conn, method, host.bytes, path, headers, body, config.user_agent);

    return readResponse(gpa, fd, &conn, config.max_response_body, config.h2_max_read_rounds, config.read_timeout_ms);
}

// --------------------------------------------------------- //
// TLS handshake + cert trust (task-1 verifyServerCert).

fn handshake(config: HttpClientConfig, fd: posix.fd_t, host: []const u8) !Tls.Client.ClientConnection {
    var seed: [64]u8 = undefined;
    secureRandom(&seed);

    var ch_buf: [CLIENT_HELLO_BUF]u8 = undefined;
    const started = try Tls.Client.start(.{ .client_random = seed[0..32].*, .ephemeral_secret = seed[32..64].*, .alpn = &.{.H2} }, &ch_buf);
    var state = started.state;

    try writeRecordFD(fd, 22, started.client_hello);

    // server flight: ServerHello + ChangeCipherSpec + the encrypted flight (3 records).
    var flight_buf: [HANDSHAKE_FLIGHT_BUF]u8 = undefined;
    var flen: usize = 0;
    // A peer that accepts and then never speaks parks this read with no end, so the flight is
    // bounded by the same budget the HTTP_1 path uses for its first response byte.
    for (0..3) |_| flen += readRecordInto(fd, flight_buf[flen..], config.response_timeout_ms) catch |err| switch (err) {
        error.ZixReadTimeout => return error.ZixResponseTimeout,
        else => return err,
    };

    var fin_buf: [FINISHED_BUF]u8 = undefined;
    const finished = try Tls.Client.finish(&state, flight_buf[0..flen], &fin_buf);
    if (finished.alpn != Tls.Alpn.H2) return error.ZixAlpnNotH2;

    // trust the server cert: chain to the configured anchor (RFC 5280) + match the host (RFC 6125).
    if (config.tls_verify) {
        const anchor_path = config.tls_ca_path orelse return error.ZixTlsNoTrustAnchor;

        var pem_buf: [CA_PEM_BUF]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&pem_buf);
        const cert_pem = try std.Io.Dir.cwd().readFileAlloc(config.io, anchor_path, fba.allocator(), .limited(CA_PEM_BUF));

        var der_buf: [Tls.Client.max_server_cert_der]u8 = undefined;
        const anchor_der = try Tls.pemToDer(&der_buf, cert_pem);

        try finished.verifyServerCert(anchor_der, host, nowSec());
    }

    try fd_io.writeAll(fd, finished.client_finished);

    return finished.connection;
}

// --------------------------------------------------------- //
// request: preface + SETTINGS + connection WINDOW_UPDATE + HEADERS [+ stream WINDOW_UPDATE] [+ DATA].

fn sendRequestFD(
    fd: posix.fd_t,
    conn: *Tls.Client.ClientConnection,
    method: Method.Code,
    host: []const u8,
    path: []const u8,
    headers: []const std.http.Header,
    body: ?[]const u8,
    user_agent: []const u8,
) !void {
    const has_body = methodHasBody(method) and body != null;

    var hbuf: [HPACK_BLOCK_BUF]u8 = undefined;
    var enc = Http2.HpackEncoder.init(&hbuf);
    try enc.writeHeader(":method", Method.stringFromEnum(method));
    try enc.writeHeader(":path", path);
    try enc.writeHeader(":scheme", "https");
    try enc.writeHeader(":authority", host);
    if (user_agent.len > 0) try enc.writeHeader("user-agent", user_agent);

    var name_buf: [HEADER_NAME_BUF]u8 = undefined;
    for (headers) |hdr| {
        if (skipRequestHeader(hdr.name)) continue;
        if (hdr.name.len > name_buf.len) continue;

        const lowered = std.ascii.lowerString(name_buf[0..hdr.name.len], hdr.name);
        try enc.writeHeader(lowered, hdr.value);
    }

    var cl_buf: [20]u8 = undefined;
    if (has_body) {
        const cl = try std.fmt.bufPrint(&cl_buf, "{d}", .{body.?.len});
        try enc.writeHeader("content-length", cl);
    }

    const hblock = enc.encoded();

    var out: [FRAME_OUT_BUF]u8 = undefined;
    var n: usize = 0;

    @memcpy(out[n..][0..Http2.PREFACE.len], Http2.PREFACE);
    n += Http2.PREFACE.len;
    n += putFrame(out[n..], Http2.FRAME_TYPE_SETTINGS, 0, 0, &.{});
    n += putWindowUpdate(out[n..], 0, WINDOW_INCREMENT);

    const headers_flags: u8 = Http2.FLAG_END_HEADERS | (if (has_body) @as(u8, 0) else Http2.FLAG_END_STREAM);
    n += putFrame(out[n..], Http2.FRAME_TYPE_HEADERS, headers_flags, 1, hblock);
    n += putWindowUpdate(out[n..], 1, WINDOW_INCREMENT);

    var send_buf: [H2_SEND_BUF]u8 = undefined;
    try fd_io.writeAll(fd, conn.writeAppData(out[0..n], &send_buf));

    if (has_body) try sendBodyFD(fd, conn, body.?);
}

fn sendBodyFD(fd: posix.fd_t, conn: *Tls.Client.ClientConnection, body: []const u8) !void {
    const chunk_max = 8 * 1024; // keep each DATA frame within one comfortable TLS record.
    var sent: usize = 0;
    while (sent < body.len) {
        const end = @min(sent + chunk_max, body.len);
        const is_last = end == body.len;
        const flags: u8 = if (is_last) Http2.FLAG_END_STREAM else 0;

        var frame: [chunk_max + Http2.FRAME_HEADER_LEN]u8 = undefined;
        const len = putFrame(&frame, Http2.FRAME_TYPE_DATA, flags, 1, body[sent..end]);

        var enc_buf: [chunk_max + 128]u8 = undefined;
        try fd_io.writeAll(fd, conn.writeAppData(frame[0..len], &enc_buf));

        sent = end;
    }
}

// --------------------------------------------------------- //
// response: decrypt records, parse frames on stream 1, honor SETTINGS / PING, stop at END_STREAM.

fn readResponse(gpa: std.mem.Allocator, fd: posix.fd_t, conn: *Tls.Client.ClientConnection, max_body: usize, max_read_rounds: usize, idle_ms: u32) !Parts {
    var hdec = Http2.HpackDecoder.init();

    var head: std.ArrayList(u8) = .empty;
    errdefer head.deinit(gpa);
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(gpa);

    var status_code: u16 = 0;
    var have_status = false;
    var stream_done = false;

    var acc: [H2_RESPONSE_ACC]u8 = undefined;
    var acc_len: usize = 0;
    var rounds: usize = 0;
    while (!stream_done and rounds < max_read_rounds) : (rounds += 1) {
        var rec_buf: [record.max_record_wire]u8 = undefined;
        const rec_len = try readRecordInto(fd, &rec_buf, idle_ms);
        if (rec_buf[0] != 23) continue; // application_data only

        var dec: [record.max_record_wire]u8 = undefined;
        const plain = try conn.readAppData(rec_buf[0..rec_len], &dec);
        if (acc_len + plain.len > acc.len) return error.ZixBodyTooLarge;
        @memcpy(acc[acc_len..][0..plain.len], plain);
        acc_len += plain.len;

        var off: usize = 0;
        while (off + Http2.FRAME_HEADER_LEN <= acc_len) {
            const frame = Http2.parseFrameHeader(acc[off..][0..Http2.FRAME_HEADER_LEN]);
            const total = Http2.FRAME_HEADER_LEN + @as(usize, frame.length);
            if (off + total > acc_len) break; // frame not fully arrived yet

            const payload = acc[off + Http2.FRAME_HEADER_LEN .. off + total];
            try handleFrame(gpa, fd, conn, &hdec, frame, payload, &head, &body, &status_code, &have_status, &stream_done, max_body);
            off += total;

            if (stream_done) break;
        }

        if (off > 0 and off < acc_len) {
            std.mem.copyForwards(u8, acc[0 .. acc_len - off], acc[off..acc_len]);
            acc_len -= off;
        } else if (off >= acc_len) {
            acc_len = 0;
        }
    }

    if (!have_status) return error.ZixNoStatus;

    try head.appendSlice(gpa, "\r\n");

    return .{
        .status_code = status_code,
        .head_bytes = try head.toOwnedSlice(gpa),
        .body_data = try body.toOwnedSlice(gpa),
    };
}

fn handleFrame(
    gpa: std.mem.Allocator,
    fd: posix.fd_t,
    conn: *Tls.Client.ClientConnection,
    hdec: *Http2.HpackDecoder,
    frame: Http2.FrameHeader,
    payload: []const u8,
    head: *std.ArrayList(u8),
    body: *std.ArrayList(u8),
    status_code: *u16,
    have_status: *bool,
    stream_done: *bool,
    max_body: usize,
) !void {
    switch (frame.frame_type) {
        Http2.FRAME_TYPE_HEADERS => {
            if (frame.flags & Http2.FLAG_END_HEADERS == 0) return error.ZixUnsupportedH2;

            const block = try headerBlock(frame, payload);
            var hdrs: [Http2.MAX_HEADERS]Http2.Header = undefined;
            var scratch: [FRAME_SCRATCH]u8 = undefined;
            const cnt = try hdec.decode(block, &hdrs, &scratch);
            for (hdrs[0..cnt]) |h| {
                if (std.mem.eql(u8, h.name, ":status")) {
                    status_code.* = std.fmt.parseInt(u16, h.value, 10) catch 0;
                    have_status.* = true;

                    try head.appendSlice(gpa, "HTTP/2 ");
                    try head.appendSlice(gpa, h.value);
                    try head.appendSlice(gpa, "\r\n");
                } else if (h.name.len > 0 and h.name[0] != ':') {
                    try head.appendSlice(gpa, h.name);
                    try head.appendSlice(gpa, ": ");
                    try head.appendSlice(gpa, h.value);
                    try head.appendSlice(gpa, "\r\n");
                }
            }

            if (frame.flags & Http2.FLAG_END_STREAM != 0) stream_done.* = true;
        },
        Http2.FRAME_TYPE_DATA => {
            const data = try dataPayload(frame, payload);
            if (body.items.len + data.len > max_body) return error.ZixBodyTooLarge;
            try body.appendSlice(gpa, data);

            if (frame.flags & Http2.FLAG_END_STREAM != 0) stream_done.* = true;
        },
        Http2.FRAME_TYPE_SETTINGS => {
            if (frame.flags & Http2.FLAG_ACK == 0) try sendControlFD(fd, conn, Http2.FRAME_TYPE_SETTINGS, Http2.FLAG_ACK, 0, &.{});
        },
        Http2.FRAME_TYPE_PING => {
            if (frame.flags & Http2.FLAG_ACK == 0) try sendControlFD(fd, conn, Http2.FRAME_TYPE_PING, Http2.FLAG_ACK, 0, payload);
        },
        Http2.FRAME_TYPE_RST_STREAM => {
            if (frame.stream_id == 1) return error.ZixStreamReset;
        },
        Http2.FRAME_TYPE_GOAWAY => {
            if (!have_status.*) return error.ZixGoaway;
            stream_done.* = true;
        },
        else => {}, // WINDOW_UPDATE, PRIORITY, PUSH_PROMISE, etc.: nothing to do for a single GET/POST.
    }
}

/// The HPACK block inside a HEADERS frame, stripping PADDED + PRIORITY prefixes when present.
fn headerBlock(frame: Http2.FrameHeader, payload: []const u8) ![]const u8 {
    var start: usize = 0;
    var end: usize = payload.len;
    if (frame.flags & Http2.FLAG_PADDED != 0) {
        if (payload.len < 1) return error.ZixUnsupportedH2;
        const pad_len = payload[0];
        start = 1;
        if (@as(usize, pad_len) > end - start) return error.ZixUnsupportedH2;
        end -= pad_len;
    }
    if (frame.flags & Http2.FLAG_PRIORITY != 0) {
        if (end - start < 5) return error.ZixUnsupportedH2;
        start += 5; // stream dependency (4) + weight (1)
    }

    return payload[start..end];
}

/// The application data inside a DATA frame, stripping the PADDED prefix when present.
fn dataPayload(frame: Http2.FrameHeader, payload: []const u8) ![]const u8 {
    if (frame.flags & Http2.FLAG_PADDED == 0) return payload;
    if (payload.len < 1) return error.ZixUnsupportedH2;

    const pad_len = payload[0];
    if (@as(usize, pad_len) > payload.len - 1) return error.ZixUnsupportedH2;

    return payload[1 .. payload.len - pad_len];
}

// --------------------------------------------------------- //
// frame builders (plaintext, encrypted by the caller) + an encrypted single-frame control send.

fn putFrame(out: []u8, frame_type: u8, flags: u8, stream_id: u31, payload: []const u8) usize {
    var fh: [Http2.FRAME_HEADER_LEN]u8 = undefined;
    Http2.encodeFrameHeader(&fh, .{ .length = @intCast(payload.len), .frame_type = frame_type, .flags = flags, .stream_id = stream_id });
    @memcpy(out[0..fh.len], &fh);
    @memcpy(out[fh.len..][0..payload.len], payload);

    return fh.len + payload.len;
}

fn putWindowUpdate(out: []u8, stream_id: u31, increment: u31) usize {
    var inc: [4]u8 = undefined;
    std.mem.writeInt(u32, &inc, increment, .big);

    return putFrame(out, Http2.FRAME_TYPE_WINDOW_UPDATE, 0, stream_id, &inc);
}

fn sendControlFD(fd: posix.fd_t, conn: *Tls.Client.ClientConnection, frame_type: u8, flags: u8, stream_id: u31, payload: []const u8) !void {
    var frame: [Http2.FRAME_HEADER_LEN + 64]u8 = undefined;
    const len = putFrame(&frame, frame_type, flags, stream_id, payload);

    var enc_buf: [Http2.FRAME_HEADER_LEN + 128]u8 = undefined;
    try fd_io.writeAll(fd, conn.writeAppData(frame[0..len], &enc_buf));
}

// --------------------------------------------------------- //
// request header helpers.

/// Methods that carry a request body (mirrors the HTTP/1 path: POST / PUT / PATCH send a body, the
/// rest do not, RFC 9110). QUERY joins them because its content is the request (RFC 10008 section 2),
/// so dropping it would send a question with nothing asked. Combined with a non-null body to decide
/// whether to send a DATA frame.
fn methodHasBody(method: Method.Code) bool {
    return switch (method) {
        .POST, .PUT, .PATCH, .QUERY => true,
        else => false,
    };
}

/// Headers HTTP/2 forbids or that the pseudo-headers already carry (RFC 9113 8.2.2): drop them so
/// the caller cannot smuggle a connection-specific header into the h2 request.
fn skipRequestHeader(name: []const u8) bool {
    const banned = [_][]const u8{ "host", "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "user-agent", "content-length" };
    for (banned) |b| {
        if (std.ascii.eqlIgnoreCase(name, b)) return true;
    }

    return false;
}

fn nowSec() i64 {
    if (comptime builtin.target.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);

        return ts.sec;
    }

    if (comptime builtin.target.os.tag == .windows) return @intCast(win_io.wallClockNs() / std.time.ns_per_s);

    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &ts);

    return ts.sec;
}

/// Fill buf with cryptographically secure random bytes.
fn secureRandom(buf: []u8) void {
    if (comptime builtin.target.os.tag == .linux) {
        _ = std.os.linux.getrandom(buf.ptr, buf.len, 0);
        return;
    }

    if (comptime builtin.target.os.tag == .windows) {
        win_io.secureRandom(buf) catch {};
        return;
    }

    std.c.arc4random_buf(buf.ptr, buf.len);
}

// --------------------------------------------------------- //
// raw fd record framing (the TLS record layer is driven over the connected socket directly).

fn writeRecordFD(fd: posix.fd_t, content_type: u8, msg: []const u8) !void {
    var header: [5]u8 = undefined;
    header[0] = content_type;
    header[1] = 0x03;
    header[2] = 0x03;
    std.mem.writeInt(u16, header[3..5], @intCast(msg.len), .big);

    try fd_io.writeAll(fd, &header);
    try fd_io.writeAll(fd, msg);
}

/// Read one TLS record: the 5-byte header, then the body it declares. Both reads carry the caller's
/// idle budget, since either can be the one a silent peer parks on.
fn readRecordInto(fd: posix.fd_t, buf: []u8, idle_ms: u32) !usize {
    try readAll(fd, buf[0..5], idle_ms);
    const len = std.mem.readInt(u16, buf[3..5], .big);
    try readAll(fd, buf[5 .. 5 + len], idle_ms);

    return 5 + len;
}

/// Fill buf, bounding each read so a peer that stops speaking cannot park the caller forever.
///
/// Note:
/// - Raw descriptor with no buffered reader above it, so the readiness gate sits directly in front
///   of the read. See socket_poll.readableWithin for why that placement matters.
/// - h2_max_read_rounds does not cover this. It caps how many records a chatty peer may send before
///   the stream completes, and a silent peer never advances that counter at all.
/// - An idle_ms of 0 keeps the original blocking read, so an unconfigured caller is unaffected.
fn readAll(fd: posix.fd_t, buf: []u8, idle_ms: u32) !void {
    var read: usize = 0;

    while (read < buf.len) {
        // Inside the loop, not above it: a peer that sends one byte and then stops would clear a
        // single gate at the top and park on the next read with nothing left to bound it.
        if (!socket_poll.readableWithin(fd, idle_ms)) return error.ZixReadTimeout;

        const n = fd_io.readOnce(fd, buf[read..]) catch return error.ReadFailed;
        if (n == 0) return error.ZixConnectionClosed;

        read += n;
    }
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix http: h2 client, methodHasBody and skipRequestHeader" {
    try std.testing.expect(methodHasBody(.POST));
    try std.testing.expect(methodHasBody(.PUT));
    try std.testing.expect(methodHasBody(.PATCH));
    try std.testing.expect(!methodHasBody(.GET));
    try std.testing.expect(!methodHasBody(.HEAD));
    try std.testing.expect(!methodHasBody(.DELETE));

    // pseudo-header-carried + connection-specific names are dropped (case-insensitive).
    try std.testing.expect(skipRequestHeader("Host"));
    try std.testing.expect(skipRequestHeader("connection"));
    try std.testing.expect(skipRequestHeader("Content-Length"));
    try std.testing.expect(skipRequestHeader("User-Agent"));
    try std.testing.expect(!skipRequestHeader("accept"));
    try std.testing.expect(!skipRequestHeader("x-custom"));
}

test "zix http: h2 client, QUERY carries a body and names itself in the method pseudo-header" {
    // The content is the request for QUERY (RFC 10008 section 2). Treating it as
    // bodyless would send the pseudo-headers and no DATA frame, asking nothing.
    try std.testing.expect(methodHasBody(.QUERY));
    try std.testing.expectEqualStrings("QUERY", Method.stringFromEnum(.QUERY));
}

test "zix http: h2 client, putFrame round-trips through the frame parser" {
    var buf: [64]u8 = undefined;
    const payload = "hello";
    const len = putFrame(&buf, Http2.FRAME_TYPE_DATA, Http2.FLAG_END_STREAM, 1, payload);
    try std.testing.expectEqual(@as(usize, Http2.FRAME_HEADER_LEN + payload.len), len);

    const fh = Http2.parseFrameHeader(buf[0..Http2.FRAME_HEADER_LEN]);
    try std.testing.expectEqual(Http2.FRAME_TYPE_DATA, fh.frame_type);
    try std.testing.expectEqual(Http2.FLAG_END_STREAM, fh.flags);
    try std.testing.expectEqual(@as(u31, 1), fh.stream_id);
    try std.testing.expectEqual(@as(u24, payload.len), fh.length);
    try std.testing.expectEqualSlices(u8, payload, buf[Http2.FRAME_HEADER_LEN..len]);
}

test "zix http: h2 client, putWindowUpdate encodes the increment big-endian" {
    var buf: [16]u8 = undefined;
    _ = putWindowUpdate(&buf, 0, WINDOW_INCREMENT);

    const fh = Http2.parseFrameHeader(buf[0..Http2.FRAME_HEADER_LEN]);
    try std.testing.expectEqual(Http2.FRAME_TYPE_WINDOW_UPDATE, fh.frame_type);
    try std.testing.expectEqual(@as(u24, 4), fh.length);

    const inc = std.mem.readInt(u32, buf[Http2.FRAME_HEADER_LEN..][0..4], .big);
    try std.testing.expectEqual(@as(u32, WINDOW_INCREMENT), inc);
}

test "zix http: h2 client, headerBlock strips PADDED and PRIORITY prefixes" {
    // plain block, no flags.
    const plain = Http2.FrameHeader{ .length = 3, .frame_type = Http2.FRAME_TYPE_HEADERS, .flags = Http2.FLAG_END_HEADERS, .stream_id = 1 };
    try std.testing.expectEqualSlices(u8, "abc", try headerBlock(plain, "abc"));

    // PADDED: first byte is pad length, that many trailing bytes are padding.
    const padded = Http2.FrameHeader{ .length = 6, .frame_type = Http2.FRAME_TYPE_HEADERS, .flags = Http2.FLAG_PADDED, .stream_id = 1 };
    try std.testing.expectEqualSlices(u8, "abc", try headerBlock(padded, &[_]u8{ 2, 'a', 'b', 'c', 0, 0 }));

    // PRIORITY: a 5-byte prefix (stream dependency + weight) precedes the block.
    const prio = Http2.FrameHeader{ .length = 8, .frame_type = Http2.FRAME_TYPE_HEADERS, .flags = Http2.FLAG_PRIORITY, .stream_id = 1 };
    try std.testing.expectEqualSlices(u8, "abc", try headerBlock(prio, &[_]u8{ 0, 0, 0, 0, 0, 'a', 'b', 'c' }));
}

test "zix http: h2 client, dataPayload strips DATA padding" {
    const plain = Http2.FrameHeader{ .length = 3, .frame_type = Http2.FRAME_TYPE_DATA, .flags = 0, .stream_id = 1 };
    try std.testing.expectEqualSlices(u8, "abc", try dataPayload(plain, "abc"));

    const padded = Http2.FrameHeader{ .length = 6, .frame_type = Http2.FRAME_TYPE_DATA, .flags = Http2.FLAG_PADDED, .stream_id = 1 };
    try std.testing.expectEqualSlices(u8, "abc", try dataPayload(padded, &[_]u8{ 2, 'a', 'b', 'c', 0, 0 }));
}

test "zix http: h2 client, a peer that accepts and never speaks yields ResponseTimeout" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The handshake writes a ClientHello and then reads the server flight. A peer that accepts and
    // answers nothing parks that read, and h2_max_read_rounds cannot help: the round counter only
    // advances once a record has been read.
    const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 9404);
    var silent = try addr.listen(io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 8, .reuse_address = true });
    defer silent.deinit(io);

    const host = try std.Io.net.HostName.init("127.0.0.1");
    const outcome = fetch(.{
        .allocator = std.testing.allocator,
        .io = io,
        .version = .HTTP_2,
        .tls_verify = false,
        .response_timeout_ms = 150,
    }, .GET, host, 9404, "/", &.{}, null);

    try std.testing.expectError(error.ZixResponseTimeout, outcome);
}
