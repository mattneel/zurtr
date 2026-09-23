//! zixer http2 edge: h2 client connections re-originated as http1 to the
//! pool, one stream served at a time with a bounded queue for the rest

const std = @import("std");
const zix = @import("zix");

const cfg_headers = @import("cfg_headers.zig");
const client_lease = @import("client_lease.zig");
const conn_buffer = @import("conn_buffer.zig");
const http1_head = @import("http1_head.zig");
const http1_proxy = @import("http1_proxy.zig");
const http2_frames = @import("http2_frames.zig");
const http2_translate = @import("http2_translate.zig");
const http2_ws_bridge = @import("http2_ws_bridge.zig");
const process_wait = @import("process_wait.zig");
const proxy_headers = @import("proxy_headers.zig");
const static_cached = @import("static_cached.zig");
const static_files = @import("static_files.zig");
const upstream_conn = @import("upstream_conn.zig");
const upstream_deadline = @import("upstream_deadline.zig");
const upstream_pool = @import("upstream_pool.zig");
const upstream_status = @import("upstream_status.zig");

const monotonic_clock = zix.utils.monotonic_clock;
const socket_cut_reader = zix.utils.socket_cut_reader;
const socket_cut_writer = zix.utils.socket_cut_writer;

const Http2 = zix.Http2;

/// Streams the edge holds while one is being served, advertised as
/// SETTINGS_MAX_CONCURRENT_STREAMS. Overflow answers REFUSED_STREAM, the
/// safe retry signal.
const QUEUE_CAP: usize = 8;

/// Interim (1xx) responses relayed per exchange (parity with the h1 edge).
const MAX_INTERIM = 4;

/// The rfc 6455 accept-key suffix for validating the upstream handshake.
const WS_ACCEPT_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// How one stream serve ended: the stream closed but the connection
/// lives, or the client connection itself is gone.
const Outcome = enum {
    DONE,
    CONN_DEAD,
};

/// Result of handling one client frame.
const ProcessResult = enum {
    OK,
    CLOSED,
};

/// One queued stream: everything needed to serve it after the current
/// one finishes. The h1 head is prebuilt at HEADERS time (the hpack
/// decode scratch does not survive), static requests also carry the
/// target and accept-encoding for the file plane.
const Pending = struct {
    id: u31,
    dead: bool,
    kind: enum { STATIC, POOL },
    send_window: i64,
    is_head: bool,
    needs_body: bool,
    expects_continue: bool,
    content_length: ?u64,
    head_len: usize,
    head: [http1_head.MAX_HEAD_BYTES]u8,
    target_len: usize,
    target: [static_files.PUBLIC_PATH_MAX]u8,
    accept_len: usize,
    has_accept: bool,
    accept: [256]u8,
    authority_len: usize,
    authority: [AUTHORITY_MAX]u8,
};

/// Longest authority a stream carries into the $host token: a hostname at its
/// rfc 1035 ceiling plus a port.
const AUTHORITY_MAX: usize = 264;

/// The stream currently being served. send_window spends against the
/// client's grants, the pump reads request DATA through took_data.
const ActiveStream = struct {
    id: u31,
    send_window: i64,
    recv_done: bool = false,
    reset: bool = false,
    took_data: []const u8 = "",
    took_wire: u32 = 0,
};

/// One h2 edge connection. Sized for the stack of its own connection
/// task: the queue dominates, everything is fixed.
const Conn = struct {
    proxy: *const http1_proxy.Proxy,
    io: std.Io,
    client_r: *std.Io.Reader,
    client_w: *std.Io.Writer,
    client_addr: std.Io.net.IpAddress,
    client_stream: ?std.Io.net.Stream,
    /// This connection's slot in the site's client bound, taken by whoever
    /// accepted it.
    lease: *client_lease.Lease,
    /// The upstream leg's buffers. One stream is served at a time, so the
    /// whole connection shares one pair.
    buffers: conn_buffer.Set,
    decoder: Http2.HpackDecoder,
    write_lock: std.atomic.Value(bool) = .init(false),
    saw_settings: bool = false,
    goaway_received: bool = false,
    highest_stream: u31 = 0,
    peer_initial_window: i64 = Http2.DEFAULT_INITIAL_WINDOW,
    peer_max_frame: u32 = Http2.DEFAULT_MAX_FRAME_SIZE,
    conn_send_window: i64 = Http2.DEFAULT_INITIAL_WINDOW,
    queue: [QUEUE_CAP]Pending = undefined,
    queue_head: usize = 0,
    queue_len: usize = 0,
    connect_pending: bool = false,
    connect_id: u31 = 0,
    connect_key: [24]u8 = undefined,
    connect_head_len: usize = 0,
    connect_head: [http1_head.MAX_HEAD_BYTES]u8 = undefined,
    payload_buf: [http2_frames.MAX_PAYLOAD]u8 = undefined,
    block_buf: [http1_head.MAX_HEAD_BYTES]u8 = undefined,
    resp_block_buf: [http1_head.MAX_HEAD_BYTES]u8 = undefined,
    decoded: [Http2.MAX_HEADERS]Http2.Header = undefined,
    decode_scratch: [http1_head.MAX_HEAD_BYTES]u8 = undefined,
    /// The peer address as the $client_ip token writes it, formatted once
    /// because it never changes over the connection.
    client_ip_len: usize = 0,
    client_ip: [proxy_headers.CLIENT_IP_MAX]u8 = undefined,
    /// The authority of the stream being answered right now. Set the moment a
    /// request's headers are read and again when a queued one is picked up,
    /// so every answer names the authority its own request carried.
    host_len: usize = 0,
    host: [AUTHORITY_MAX]u8 = undefined,

    /// The authority of the request being answered, empty when none is known.
    fn currentHost(conn: *const Conn) []const u8 {
        return conn.host[0..conn.host_len];
    }

    /// Remember this request's authority for the answers it produces.
    fn takeHost(conn: *Conn, authority: []const u8) void {
        conn.host_len = @min(authority.len, AUTHORITY_MAX);
        @memcpy(conn.host[0..conn.host_len], authority[0..conn.host_len]);
    }

    /// The site's answer headers with this stream's token values filled in.
    fn clientBlock(conn: *const Conn) cfg_headers.Block {
        return .{
            .table = conn.proxy.response_headers,
            .values = .{
                .client_ip = conn.client_ip[0..conn.client_ip_len],
                .scheme = conn.proxy.client_scheme.token(),
                .host = conn.currentHost(),
            },
        };
    }

    /// The same, for the leg out to the upstream.
    fn upstreamBlock(conn: *const Conn) cfg_headers.Block {
        return .{
            .table = conn.proxy.request_headers,
            .values = .{
                .client_ip = conn.client_ip[0..conn.client_ip_len],
                .scheme = conn.proxy.client_scheme.token(),
                .host = conn.currentHost(),
            },
        };
    }
};

/// True when the buffered stream opens with the h2 client preface. Peeks
/// without consuming, so the h1 fallback parses the same bytes.
pub fn prefersH2(client_r: *std.Io.Reader) bool {
    const first = client_r.peek(Http2.PREFACE.len) catch return false;

    return std.mem.eql(u8, first[0..Http2.PREFACE.len], Http2.PREFACE);
}

/// Serve one accepted cleartext connection of an http2 site: the h2
/// preface picks the h2 loop, anything else falls back to the h1 edge
/// (rfc 9113 3.3, prior knowledge only, the h1 Upgrade path is gone).
///
/// Note:
/// - The site's client bound is taken before anything is read, so a refused
///   connection never parks a thread waiting for a preface that may never
///   arrive. That leaves the refusal with no way to know which dialect the
///   client speaks, so it answers h2, the one this site exists for.
pub fn serveConn(proxy: *const http1_proxy.Proxy, client_stream: std.Io.net.Stream) void {
    const io = proxy.io;
    defer client_stream.close(io);

    var lease = client_lease.Lease.open(proxy.client_table, io, client_stream.socket.handle, proxy.client_timeout_ms) orelse {
        refuseFull(io, client_stream);

        return;
    };
    defer lease.release();

    const buffers = conn_buffer.Set.init(proxy.allocator, proxy.stream_buf_bytes, .{ .client = true, .upstream = false }) catch return;
    defer buffers.deinit(proxy.allocator);

    // The sweep cuts this socket from another thread when the bound runs out, the first tick on
    // the read side and the next on both, so the client leg goes over the pair that ends on a cut
    // rather than the std pair that panics on it.
    var client_reader = socket_cut_reader.init(client_stream, io, buffers.client_read);
    var client_writer = socket_cut_writer.init(client_stream, io, buffers.client_write);

    if (prefersH2(&client_reader.interface)) {
        serveSession(proxy, &client_reader.interface, &client_writer.interface, client_stream.socket.address, client_stream, &lease);
        return;
    }

    http1_proxy.serveLoop(proxy, &client_reader.interface, &client_writer.interface, client_stream.socket.address, client_stream, client_stream.socket.handle, &lease);
}

/// Answer a connection the site had no slot for: the h2 way to say a connection
/// is over before a single stream opens on it.
///
/// Note:
/// - Written off the stack, and every failure is swallowed: the site is at its
///   ceiling, so a refusal that cannot be delivered is not worth a retry.
fn refuseFull(io: std.Io, client_stream: std.Io.net.Stream) void {
    var refusal_buf: [64]u8 = undefined;
    var refusal_writer = client_stream.writer(io, &refusal_buf);

    http2_frames.writeImmediateGoaway(&refusal_writer.interface, Http2.ERR_ENHANCE_YOUR_CALM) catch return;
    refusal_writer.interface.flush() catch {};
}

/// The h2 request loop over reader / writer interfaces (plain stream or a
/// terminated TLS session).
///
/// Note:
/// - Every stream is re-originated as its own h1 exchange against the
///   pool, so the pick granularity is per client stream.
/// - One stream serves at a time. Bodyless streams arriving meanwhile
///   queue (up to QUEUE_CAP), bodied ones answer REFUSED_STREAM: their
///   DATA cannot wait, and the client retries safely.
/// - client_stream is the raw socket behind the interfaces, the rfc 8441
///   tunnel needs it to unblock a waiting frame read.
/// - lease is the connection's slot in the site's client bound, already taken
///   by whoever accepted the connection. A caller with no bound to enforce
///   passes a lease over nothing.
pub fn serveSession(proxy: *const http1_proxy.Proxy, client_r: *std.Io.Reader, client_w: *std.Io.Writer, client_addr: std.Io.net.IpAddress, client_stream: ?std.Io.net.Stream, lease: *client_lease.Lease) void {
    var preface: [Http2.PREFACE.len]u8 = undefined;
    client_r.readSliceAll(&preface) catch return;
    if (!std.mem.eql(u8, &preface, Http2.PREFACE)) return;

    http2_frames.writeSettings(client_w, &.{
        .{ Http2.SETTINGS_MAX_CONCURRENT_STREAMS, QUEUE_CAP },
        .{ http2_frames.SETTINGS_ENABLE_CONNECT_PROTOCOL, 1 },
    }) catch return;
    client_w.flush() catch return;

    const buffers = conn_buffer.Set.init(proxy.allocator, proxy.stream_buf_bytes, .{ .client = false, .upstream = proxy.pool != null }) catch return;
    defer buffers.deinit(proxy.allocator);

    var conn = Conn{
        .proxy = proxy,
        .io = proxy.io,
        .client_r = client_r,
        .client_w = client_w,
        .client_addr = client_addr,
        .client_stream = client_stream,
        .lease = lease,
        .buffers = buffers,
        .decoder = Http2.HpackDecoder.init(),
    };
    conn.client_ip_len = proxy_headers.clientIp(&conn.client_ip, client_addr).len;

    mainLoop(&conn);
}

/// The connection frame loop.
///
/// Note:
/// - The client bound means something different here than on an h1 connection:
///   one budget cannot cover several streams at once, so it covers the quiet
///   instead. The connection is held while it has work and armed again only
///   while it waits for the next client frame, which is the shape a connection
///   opened and then left idle takes.
fn mainLoop(conn: *Conn) void {
    while (true) {
        conn.lease.holdStream();

        while (conn.queue_len != 0) {
            const entry = &conn.queue[conn.queue_head];
            conn.takeHost(entry.authority[0..entry.authority_len]);

            const outcome = if (entry.dead) Outcome.DONE else serveEntry(conn, entry);

            conn.queue_head = (conn.queue_head + 1) % QUEUE_CAP;
            conn.queue_len -= 1;
            if (outcome == .CONN_DEAD) return;
        }

        if (conn.connect_pending) {
            conn.connect_pending = false;
            if (serveConnect(conn) == .CONN_DEAD) return;
            continue;
        }

        if (conn.goaway_received) {
            lockWrite(conn);
            http2_frames.writeGoaway(conn.client_w, conn.highest_stream, Http2.ERR_NO_ERROR) catch {};
            conn.client_w.flush() catch {};
            unlockWrite(conn);

            return;
        }

        conn.lease.armRequest();
        if (processFrame(conn, null) == .CLOSED) return;
    }
}

// --------------------------------------------------------- //
// frame processing

/// Read and handle one client frame. active is the stream being served
/// when the call is nested inside a body pump or a window wait.
fn processFrame(conn: *Conn, active: ?*ActiveStream) ProcessResult {
    const frame = http2_frames.readFrame(conn.client_r, &conn.payload_buf) catch |err| {
        if (err == error.ZixerFrameTooLarge) return connError(conn, Http2.ERR_FRAME_SIZE_ERROR);

        return .CLOSED;
    };

    // rfc 9113 3.4: the client preface ends with a SETTINGS frame.
    if (!conn.saw_settings and frame.head.frame_type != Http2.FRAME_TYPE_SETTINGS) {
        return connError(conn, Http2.ERR_PROTOCOL_ERROR);
    }

    switch (frame.head.frame_type) {
        Http2.FRAME_TYPE_DATA => return processData(conn, active, &frame),
        Http2.FRAME_TYPE_HEADERS => return processHeaders(conn, active, &frame),
        Http2.FRAME_TYPE_PRIORITY => return .OK,
        Http2.FRAME_TYPE_RST_STREAM => {
            if (frame.payload.len != 4) return connError(conn, Http2.ERR_FRAME_SIZE_ERROR);
            if (frame.head.stream_id == 0) return connError(conn, Http2.ERR_PROTOCOL_ERROR);

            if (active) |act| {
                if (frame.head.stream_id == act.id) {
                    act.reset = true;
                    return .OK;
                }
            }
            markQueueDead(conn, frame.head.stream_id);

            return .OK;
        },
        Http2.FRAME_TYPE_SETTINGS => return processSettings(conn, active, &frame),
        Http2.FRAME_TYPE_PUSH_PROMISE => return connError(conn, Http2.ERR_PROTOCOL_ERROR),
        Http2.FRAME_TYPE_PING => {
            if ((frame.head.flags & Http2.FLAG_ACK) != 0) return .OK;
            if (frame.payload.len != 8) return connError(conn, Http2.ERR_FRAME_SIZE_ERROR);

            lockWrite(conn);
            defer unlockWrite(conn);
            http2_frames.writePingAck(conn.client_w, frame.payload) catch return .CLOSED;
            conn.client_w.flush() catch return .CLOSED;

            return .OK;
        },
        Http2.FRAME_TYPE_GOAWAY => {
            conn.goaway_received = true;

            return .OK;
        },
        Http2.FRAME_TYPE_WINDOW_UPDATE => return processWindowUpdate(conn, active, &frame),
        Http2.FRAME_TYPE_CONTINUATION => return connError(conn, Http2.ERR_PROTOCOL_ERROR),
        else => return .OK,
    }
}

fn processData(conn: *Conn, active: ?*ActiveStream, frame: *const http2_frames.Frame) ProcessResult {
    if (frame.head.stream_id == 0) return connError(conn, Http2.ERR_PROTOCOL_ERROR);
    const data = http2_frames.dataPayload(frame) catch return connError(conn, Http2.ERR_PROTOCOL_ERROR);

    if (active) |act| {
        if (frame.head.stream_id == act.id and !act.recv_done) {
            act.took_data = data;
            act.took_wire = frame.head.length;
            if ((frame.head.flags & Http2.FLAG_END_STREAM) != 0) act.recv_done = true;

            return .OK;
        }
    }

    // Unclaimed DATA (a refused, reset, or finished stream): dropped, the
    // connection credit goes straight back so the client never stalls.
    if (frame.head.length > 0) {
        lockWrite(conn);
        defer unlockWrite(conn);
        http2_frames.writeWindowUpdate(conn.client_w, 0, @intCast(frame.head.length)) catch return .CLOSED;
        conn.client_w.flush() catch return .CLOSED;
    }

    return .OK;
}

fn processHeaders(conn: *Conn, active: ?*ActiveStream, first: *const http2_frames.Frame) ProcessResult {
    const id = first.head.stream_id;
    if (id == 0) return connError(conn, Http2.ERR_PROTOCOL_ERROR);

    const fragment = http2_frames.headersFragment(first) catch return connError(conn, Http2.ERR_PROTOCOL_ERROR);
    if (fragment.len > conn.block_buf.len) return connError(conn, Http2.ERR_ENHANCE_YOUR_CALM);
    @memcpy(conn.block_buf[0..fragment.len], fragment);
    var block_len: usize = fragment.len;
    const end_stream = (first.head.flags & Http2.FLAG_END_STREAM) != 0;

    // CONTINUATION frames extend the block until END_HEADERS. A block the
    // buffer cannot hold kills the connection: skipping it would desync
    // the shared hpack state.
    var end_headers = (first.head.flags & Http2.FLAG_END_HEADERS) != 0;
    while (!end_headers) {
        const next = http2_frames.readFrame(conn.client_r, &conn.payload_buf) catch return .CLOSED;
        if (next.head.frame_type != Http2.FRAME_TYPE_CONTINUATION or next.head.stream_id != id) {
            return connError(conn, Http2.ERR_PROTOCOL_ERROR);
        }
        if (block_len + next.payload.len > conn.block_buf.len) return connError(conn, Http2.ERR_ENHANCE_YOUR_CALM);

        @memcpy(conn.block_buf[block_len..][0..next.payload.len], next.payload);
        block_len += next.payload.len;
        end_headers = (next.head.flags & Http2.FLAG_END_HEADERS) != 0;
    }

    const count = conn.decoder.decode(conn.block_buf[0..block_len], &conn.decoded, &conn.decode_scratch) catch {
        return connError(conn, Http2.ERR_COMPRESSION_ERROR);
    };
    const headers = conn.decoded[0..count];

    // Trailers of the stream being served: the h1 leg has no place for
    // them once the head is on the wire, decoded (hpack stays synced) and
    // dropped, they only end the request body.
    if (active) |act| {
        if (id == act.id) {
            if (!end_stream) return connError(conn, Http2.ERR_PROTOCOL_ERROR);
            act.recv_done = true;

            return .OK;
        }
    }

    if (id % 2 == 0) return connError(conn, Http2.ERR_PROTOCOL_ERROR);
    if (id <= conn.highest_stream) return streamError(conn, id, Http2.ERR_STREAM_CLOSED);
    conn.highest_stream = id;

    if (conn.goaway_received) return streamError(conn, id, Http2.ERR_REFUSED_STREAM);

    const request = http2_translate.assemble(headers, end_stream) catch |err| switch (err) {
        error.ZixerMalformed => return streamError(conn, id, Http2.ERR_PROTOCOL_ERROR),
        error.ZixerUnsupportedConnect => return localAnswer(conn, id, 501, null),
    };

    // rfc 9110 7.4: under TLS, an authority this certificate does not
    // serve is a misdirected request.
    if (misdirected(conn, &request)) return localAnswer(conn, id, 421, null);

    if (request.is_connect) return acceptConnect(conn, active, id, &request, headers);

    return acceptStream(conn, active, id, &request, headers);
}

/// Queue a plain stream for serving, or answer it locally right away.
fn acceptStream(conn: *Conn, active: ?*ActiveStream, id: u31, request: *const http2_translate.Request, headers: []const Http2.Header) ProcessResult {
    const has_pool = conn.proxy.pool != null;

    // The static plane decision mirrors the h1 answer order: a handled
    // target tries the file plane first, a static-only site answers
    // everything else locally.
    var wants_static = false;
    if (conn.proxy.static) |*site| {
        wants_static = static_files.handles(site, request.method, request.target) and
            request.target.len <= static_files.PUBLIC_PATH_MAX;
    }
    if (!wants_static and !has_pool) {
        if (!static_files.fileMethod(request.method)) return localAnswer(conn, id, 405, null);

        return localAnswer(conn, id, 404, null);
    }

    if (request.has_body and active != null) return streamError(conn, id, Http2.ERR_REFUSED_STREAM);
    if (conn.queue_len == QUEUE_CAP) return streamError(conn, id, Http2.ERR_REFUSED_STREAM);

    const entry = &conn.queue[(conn.queue_head + conn.queue_len) % QUEUE_CAP];
    entry.* = .{
        .id = id,
        .dead = false,
        .kind = if (wants_static) .STATIC else .POOL,
        .send_window = conn.peer_initial_window,
        .is_head = request.is_head,
        .needs_body = request.has_body,
        .expects_continue = request.expects_continue,
        .content_length = request.content_length,
        .head_len = 0,
        .head = undefined,
        .target_len = 0,
        .target = undefined,
        .accept_len = 0,
        .has_accept = false,
        .accept = undefined,
        .authority_len = @min(request.authority.len, AUTHORITY_MAX),
        .authority = undefined,
    };
    @memcpy(entry.authority[0..entry.authority_len], request.authority[0..entry.authority_len]);

    if (wants_static) {
        @memcpy(entry.target[0..request.target.len], request.target);
        entry.target_len = request.target.len;

        for (headers) |header| {
            if (!std.mem.eql(u8, header.name, "accept-encoding")) continue;

            const take = @min(header.value.len, entry.accept.len);
            @memcpy(entry.accept[0..take], header.value[0..take]);
            entry.accept_len = take;
            entry.has_accept = true;
            break;
        }
    }

    if (has_pool) {
        const head = http2_translate.buildUpstreamHead(&entry.head, request, headers, conn.client_addr, conn.proxy.client_scheme, conn.upstreamBlock()) catch {
            return localAnswer(conn, id, 400, "http_request_error");
        };
        entry.head_len = head.len;
    }

    conn.queue_len += 1;

    return .OK;
}

/// Stage an rfc 8441 extended CONNECT: the main loop runs the tunnel once
/// the edge is idle, a busy edge refuses so the client retries fresh.
fn acceptConnect(conn: *Conn, active: ?*ActiveStream, id: u31, request: *const http2_translate.Request, headers: []const Http2.Header) ProcessResult {
    if (active != null or conn.queue_len != 0) return streamError(conn, id, Http2.ERR_REFUSED_STREAM);
    if (conn.proxy.pool == null) return localAnswer(conn, id, 503, "destination_unavailable");

    // The h1 leg needs the Sec-WebSocket-Key the h2 handshake never
    // carries, zixer generates its own and validates the accept answer.
    var key_raw: [16]u8 = undefined;
    conn.io.randomSecure(&key_raw) catch return streamError(conn, id, Http2.ERR_INTERNAL_ERROR);
    _ = std.base64.standard.Encoder.encode(&conn.connect_key, &key_raw);

    const head = http2_translate.buildConnectHead(&conn.connect_head, request, headers, conn.client_addr, &conn.connect_key, conn.proxy.client_scheme, conn.upstreamBlock()) catch {
        return localAnswer(conn, id, 400, "http_request_error");
    };
    conn.connect_head_len = head.len;
    conn.connect_id = id;
    conn.connect_pending = true;

    return .OK;
}

fn processSettings(conn: *Conn, active: ?*ActiveStream, frame: *const http2_frames.Frame) ProcessResult {
    if ((frame.head.flags & Http2.FLAG_ACK) != 0) return .OK;
    if (frame.payload.len % 6 != 0) return connError(conn, Http2.ERR_FRAME_SIZE_ERROR);

    var params = http2_frames.SettingsIterator.init(frame.payload);
    while (params.next()) |param| {
        switch (param[0]) {
            Http2.SETTINGS_INITIAL_WINDOW_SIZE => {
                if (param[1] > 0x7FFF_FFFF) return connError(conn, Http2.ERR_FLOW_CONTROL_ERROR);

                // rfc 9113 6.9.2: the delta applies to every open stream.
                const delta = @as(i64, param[1]) - conn.peer_initial_window;
                conn.peer_initial_window = param[1];
                if (active) |act| act.send_window += delta;
                var offset: usize = 0;
                while (offset < conn.queue_len) : (offset += 1) {
                    conn.queue[(conn.queue_head + offset) % QUEUE_CAP].send_window += delta;
                }
            },
            Http2.SETTINGS_MAX_FRAME_SIZE => {
                if (param[1] < Http2.DEFAULT_MAX_FRAME_SIZE or param[1] > 0xFF_FFFF) {
                    return connError(conn, Http2.ERR_PROTOCOL_ERROR);
                }
                conn.peer_max_frame = param[1];
            },
            Http2.SETTINGS_ENABLE_PUSH => {
                if (param[1] > 1) return connError(conn, Http2.ERR_PROTOCOL_ERROR);
            },
            else => {},
        }
    }
    conn.saw_settings = true;

    lockWrite(conn);
    defer unlockWrite(conn);
    http2_frames.writeSettingsAck(conn.client_w) catch return .CLOSED;
    conn.client_w.flush() catch return .CLOSED;

    return .OK;
}

fn processWindowUpdate(conn: *Conn, active: ?*ActiveStream, frame: *const http2_frames.Frame) ProcessResult {
    const increment = http2_frames.windowIncrement(frame.payload) catch {
        return connError(conn, Http2.ERR_FRAME_SIZE_ERROR);
    };

    if (frame.head.stream_id == 0) {
        if (increment == 0) return connError(conn, Http2.ERR_PROTOCOL_ERROR);

        conn.conn_send_window += increment;
        if (conn.conn_send_window > 0x7FFF_FFFF) return connError(conn, Http2.ERR_FLOW_CONTROL_ERROR);

        return .OK;
    }

    if (increment == 0) return streamError(conn, frame.head.stream_id, Http2.ERR_PROTOCOL_ERROR);

    if (active) |act| {
        if (frame.head.stream_id == act.id) {
            act.send_window += increment;

            return .OK;
        }
    }

    var offset: usize = 0;
    while (offset < conn.queue_len) : (offset += 1) {
        const entry = &conn.queue[(conn.queue_head + offset) % QUEUE_CAP];
        if (entry.id == frame.head.stream_id) {
            entry.send_window += increment;

            return .OK;
        }
    }

    return .OK;
}

fn markQueueDead(conn: *Conn, id: u31) void {
    var offset: usize = 0;
    while (offset < conn.queue_len) : (offset += 1) {
        const entry = &conn.queue[(conn.queue_head + offset) % QUEUE_CAP];
        if (entry.id == id) entry.dead = true;
    }
}

/// Whether a TLS-terminated request names an authority the site's
/// certificate does not serve. Cleartext edges never arm this.
fn misdirected(conn: *Conn, request: *const http2_translate.Request) bool {
    const cert_der = conn.proxy.tls_cert_der orelse return false;
    if (request.authority.len == 0) return false;

    const host = proxy_headers.stripHostPort(request.authority);
    zix.Tls.verifyCertIdentity(cert_der, host) catch return true;

    return false;
}

// --------------------------------------------------------- //
// stream serving

fn serveEntry(conn: *Conn, entry: *Pending) Outcome {
    var active = ActiveStream{
        .id = entry.id,
        .send_window = entry.send_window,
        .recv_done = !entry.needs_body,
    };

    if (entry.kind == .STATIC) {
        const site = &conn.proxy.static.?;
        const accept: ?[]const u8 = if (entry.has_accept) entry.accept[0..entry.accept_len] else null;
        const target = entry.target[0..entry.target_len];

        const ttl_ms = conn.proxy.public_dir_cache_ttl_ms;

        if (static_cached.acquireResident(conn.io, site.public_dir, target, accept, ttl_ms)) |hit| {
            defer static_cached.release(hit);

            return serveStaticFile(conn, &active, resolvedFromHit(hit), entry.is_head, hit.bytes);
        }

        if (static_files.open(conn.io, site.public_dir, target, accept)) |resolved| {
            defer resolved.file.close(conn.io);

            return serveStaticFile(conn, &active, resolved, entry.is_head, null);
        }

        // File miss: the fallback page of a client-side routed app, then
        // the pool on a mixed site, a local 404 otherwise.
        if (site.spa_fallback) |fallback| {
            var target_buf: [static_files.PUBLIC_PATH_MAX]u8 = undefined;
            if (std.fmt.bufPrint(&target_buf, "/{s}", .{fallback}) catch null) |fallback_target| {
                if (static_cached.acquireResident(conn.io, site.public_dir, fallback_target, accept, ttl_ms)) |hit| {
                    defer static_cached.release(hit);

                    return serveStaticFile(conn, &active, resolvedFromHit(hit), entry.is_head, hit.bytes);
                }

                if (static_files.open(conn.io, site.public_dir, fallback_target, accept)) |resolved| {
                    defer resolved.file.close(conn.io);

                    return serveStaticFile(conn, &active, resolved, entry.is_head, null);
                }
            }
        }

        if (conn.proxy.pool == null) {
            return if (localAnswer(conn, entry.id, 404, null) == .CLOSED) .CONN_DEAD else .DONE;
        }
    }

    return servePool(conn, &active, entry);
}

/// One exchange against the pool: pick, forward, relay, bounded retry.
/// Mirrors the h1 exchange, with the client leg speaking frames.
fn servePool(conn: *Conn, active: *ActiveStream, entry: *const Pending) Outcome {
    const io = conn.io;
    const pool = conn.proxy.pool.?;
    const idle = conn.proxy.idle.?;
    const upstream_head = entry.head[0..entry.head_len];
    var continue_sent = false;

    // One place in the site's gate per stream, not per connection: an h2
    // client multiplexes many requests over one socket, and each of them
    // spends a backend on its own.
    const admission = process_wait.admit(conn.proxy.process_gate, io);
    if (admission != .ADMITTED) {
        return if (localAnswer(conn, active.id, 504, process_wait.PROXY_ERROR) == .CLOSED) .CONN_DEAD else .DONE;
    }

    var slot = process_wait.hold(conn.proxy.process_gate);
    defer slot.release();

    var attempts: usize = pool.slots.len + 1;
    var failed_here = false;
    var connect_timed_out = false;
    while (attempts > 0) : (attempts -= 1) {
        const picked = pool.pick(monotonic_clock.nowMs(io)) orelse {
            if (failed_here) break;

            return if (localAnswer(conn, active.id, 503, "destination_unavailable") == .CLOSED) .CONN_DEAD else .DONE;
        };

        const conn_up = idle.acquire(io, picked.index, monotonic_clock.nowMs(io)) orelse
            upstream_conn.connect(io, picked.host, picked.port, picked.index, conn.proxy.upstream_connect_timeout_ms) catch |err| {
            if (upstream_status.ranOutOfTime(err)) connect_timed_out = true;

            pool.markDown(picked.index, monotonic_clock.nowMs(io));
            failed_here = true;
            continue;
        };
        const gate = upstreamGate(conn, conn_up);

        var up_reader = conn_up.stream.reader(io, conn.buffers.upstream_read);
        var up_writer = conn_up.stream.writer(io, conn.buffers.upstream_write);

        up_writer.interface.writeAll(upstream_head) catch {
            conn_up.stream.close(io);
            if (!conn_up.reused) pool.markDown(picked.index, monotonic_clock.nowMs(io));
            failed_here = true;
            continue;
        };

        if (entry.needs_body) {
            // The client may hold the body for a 100 (rfc 9113 8.5 allows
            // the interim HEADERS), answered here once, the h1 leg
            // dropped the Expect header.
            if (entry.expects_continue and !continue_sent) {
                if (sendLocalHead(conn, active.id, 100, null, false) == .CLOSED) {
                    conn_up.stream.close(io);
                    return .CONN_DEAD;
                }
                continue_sent = true;
            }

            pumpBodyToUpstream(conn, active, &up_writer.interface, entry.content_length) catch |err| {
                conn_up.stream.close(io);
                switch (err) {
                    error.ZixerClientDead => return .CONN_DEAD,
                    error.ZixerReset => return .DONE,
                    error.ZixerBadBody => return if (streamError(conn, active.id, Http2.ERR_PROTOCOL_ERROR) == .CLOSED) .CONN_DEAD else .DONE,
                    error.ZixerUpstreamDead => return if (localAnswer(conn, active.id, 502, "connection_terminated") == .CLOSED) .CONN_DEAD else .DONE,
                }
            };
        }

        up_writer.interface.flush() catch {
            conn_up.stream.close(io);
            if (!entry.needs_body) {
                if (!conn_up.reused) pool.markDown(picked.index, monotonic_clock.nowMs(io));
                failed_here = true;
                continue;
            }

            return if (localAnswer(conn, active.id, 502, "connection_terminated") == .CLOSED) .CONN_DEAD else .DONE;
        };

        var resp_head_buf: [http1_head.MAX_HEAD_BYTES]u8 = undefined;
        const method: []const u8 = if (entry.is_head) "HEAD" else "GET";
        const response = readUpstreamHead(conn, active, &up_reader.interface, &resp_head_buf, method, gate) catch |err| {
            conn_up.stream.close(io);
            switch (err) {
                error.ZixerClientDead => return .CONN_DEAD,

                // A silent upstream is not a dead one: the request was
                // already delivered, so it is neither replayed elsewhere
                // nor is the slot taken out of rotation.
                error.ZixerUpstreamTimeout => return if (localAnswer(conn, active.id, 504, "http_response_timeout") == .CLOSED) .CONN_DEAD else .DONE,
                else => {},
            }
            if (!entry.needs_body) {
                if (!conn_up.reused) pool.markDown(picked.index, monotonic_clock.nowMs(io));
                failed_here = true;
                continue;
            }

            return if (localAnswer(conn, active.id, 502, "connection_terminated") == .CLOSED) .CONN_DEAD else .DONE;
        };

        return relayResponse(conn, active, &response, conn_up, &up_reader.interface);
    }

    const answer = upstream_status.afterAttempts(connect_timed_out);

    return if (localAnswer(conn, active.id, answer.status, answer.proxy_error) == .CLOSED) .CONN_DEAD else .DONE;
}

/// Read the upstream response head, relaying interim 1xx heads as h2
/// informational HEADERS. A 101 was never asked for on a plain exchange
/// and counts as an upstream failure.
fn readUpstreamHead(conn: *Conn, active: *ActiveStream, up_r: *std.Io.Reader, head_buf: []u8, method: []const u8, gate: upstream_deadline.Gate) !http1_head.ResponseHead {
    var interim: usize = 0;
    while (interim <= MAX_INTERIM) : (interim += 1) {
        if (!gate.ready(up_r)) return error.ZixerUpstreamTimeout;

        const bytes = http1_head.readHead(up_r, head_buf) catch return error.ZixerUpstreamDead;
        const response = http1_head.parseResponse(bytes, method) catch return error.ZixerUpstreamDead;

        if (response.status == 101) return error.ZixerUpstreamDead;
        if (response.status / 100 != 1) return response;

        const block = http2_translate.encodeResponseBlock(&conn.resp_block_buf, &response, null, conn.clientBlock()) catch return error.ZixerUpstreamDead;
        if (writeBlock(conn, active.id, block, false) == .CLOSED) return error.ZixerClientDead;
    }

    return error.ZixerUpstreamDead;
}

/// Relay one upstream response onto the stream: head as a header block,
/// body as flow-controlled DATA, chunked trailers as a trailing block.
fn relayResponse(conn: *Conn, active: *ActiveStream, response: *const http1_head.ResponseHead, conn_up: upstream_conn.UpstreamConn, up_r: *std.Io.Reader) Outcome {
    const io = conn.io;

    const block_length: ?u64 = switch (response.framing) {
        .content_length => |len| len,
        .none => if (response.status == 204 or response.status == 304 or response.status / 100 == 1) null else 0,
        else => null,
    };
    const head_only = response.framing == .none;

    const block = http2_translate.encodeResponseBlock(&conn.resp_block_buf, response, block_length, conn.clientBlock()) catch {
        conn_up.stream.close(io);
        return if (streamError(conn, active.id, Http2.ERR_INTERNAL_ERROR) == .CLOSED) .CONN_DEAD else .DONE;
    };
    // A Content-Length body is a finished answer being read right now, so
    // the head stays staged and the first DATA frame rides the same write.
    // A chunked or close-delimited body may be a live stream whose first
    // byte is seconds out, and that head cannot wait on it.
    const stage_head = response.framing == .content_length;
    const head_written = if (stage_head)
        stageBlock(conn, active.id, block, false)
    else
        writeBlock(conn, active.id, block, head_only);
    if (head_written == .CLOSED) {
        conn_up.stream.close(io);
        return .CONN_DEAD;
    }

    var relay_failed = false;
    var relay_result: Outcome = .DONE;
    if (!head_only) {
        const relayed: RelayError!void = switch (response.framing) {
            .content_length => |len| relayExact(conn, active, up_r, len, upstreamGate(conn, conn_up)),
            .chunked => relayChunked(conn, active, up_r),
            .until_close => relayUntilClose(conn, active, up_r),
            .none => unreachable,
        };

        relayed catch |err| switch (err) {
            error.ZixerClientDead => {
                conn_up.stream.close(io);
                return .CONN_DEAD;
            },
            error.ZixerReset => relay_failed = true,
            error.ZixerUpstreamDead, error.ZixerBadBody => {
                relay_failed = true;
                relay_result = if (streamError(conn, active.id, Http2.ERR_INTERNAL_ERROR) == .CLOSED) .CONN_DEAD else .DONE;
            },
        };
    }

    // Nothing may stay staged past here. A relay that ended early still
    // owes the client the head, and an already-drained buffer costs
    // nothing to flush again.
    conn.client_w.flush() catch {
        conn_up.stream.close(io);
        return .CONN_DEAD;
    };

    const reusable = !relay_failed and !response.connection_close and response.framing != .until_close;
    if (reusable) conn.proxy.idle.?.release(io, conn_up, monotonic_clock.nowMs(io)) else conn_up.stream.close(io);

    return relay_result;
}

// --------------------------------------------------------- //
// body relays

const RelayError = error{
    ZixerClientDead,
    ZixerReset,
    ZixerUpstreamDead,
    ZixerBadBody,
};

/// Pump the request DATA frames onto the upstream leg, granting the flow
/// credit back as each frame lands. content_length null re-frames as
/// chunked (the h1 leg always carries explicit framing).
fn pumpBodyToUpstream(conn: *Conn, active: *ActiveStream, up_w: *std.Io.Writer, content_length: ?u64) RelayError!void {
    var remaining: u64 = content_length orelse 0;
    const chunked = content_length == null;

    while (!active.recv_done) {
        active.took_data = "";
        active.took_wire = 0;
        if (processFrame(conn, active) == .CLOSED) return error.ZixerClientDead;
        if (active.reset) return error.ZixerReset;

        if (active.took_data.len > 0) {
            const data = active.took_data;
            if (chunked) {
                up_w.print("{x}\r\n", .{data.len}) catch return error.ZixerUpstreamDead;
                up_w.writeAll(data) catch return error.ZixerUpstreamDead;
                up_w.writeAll("\r\n") catch return error.ZixerUpstreamDead;
            } else {
                if (data.len > remaining) return error.ZixerBadBody;
                up_w.writeAll(data) catch return error.ZixerUpstreamDead;
                remaining -= data.len;
            }
        }

        if (active.took_wire > 0) grantCredit(conn, active.id, active.took_wire) catch return error.ZixerClientDead;
    }

    if (!chunked and remaining != 0) return error.ZixerBadBody;
    if (chunked) up_w.writeAll("0\r\n\r\n") catch return error.ZixerUpstreamDead;
}

/// Hand consumed request-body credit back on the connection and stream.
fn grantCredit(conn: *Conn, stream_id: u31, consumed: u32) !void {
    lockWrite(conn);
    defer unlockWrite(conn);
    try http2_frames.writeWindowUpdate(conn.client_w, 0, @intCast(consumed));
    try http2_frames.writeWindowUpdate(conn.client_w, stream_id, @intCast(consumed));
    try conn.client_w.flush();
}

/// Send one run of response bytes as DATA frames inside the send windows,
/// reading client frames whenever credit runs dry.
fn sendData(conn: *Conn, active: *ActiveStream, bytes: []const u8, end_stream: bool) RelayError!void {
    if (bytes.len == 0) {
        if (!end_stream) return;

        lockWrite(conn);
        defer unlockWrite(conn);
        http2_frames.writeFrame(conn.client_w, Http2.FRAME_TYPE_DATA, Http2.FLAG_END_STREAM, active.id, "") catch return error.ZixerClientDead;
        conn.client_w.flush() catch return error.ZixerClientDead;

        return;
    }

    var offset: usize = 0;
    while (offset < bytes.len) {
        const window = @min(conn.conn_send_window, active.send_window);
        if (window <= 0) {
            // Everything staged must reach the client before blocking on
            // its next grant, an unflushed frame cannot be acknowledged.
            conn.client_w.flush() catch return error.ZixerClientDead;
            if (processFrame(conn, active) == .CLOSED) return error.ZixerClientDead;
            if (active.reset) return error.ZixerReset;
            continue;
        }

        const take = @min(bytes.len - offset, @min(@as(usize, @intCast(window)), effectiveMaxFrame(conn)));
        const last = offset + take == bytes.len;
        const flags: u8 = if (last and end_stream) Http2.FLAG_END_STREAM else 0;

        lockWrite(conn);
        http2_frames.writeFrame(conn.client_w, Http2.FRAME_TYPE_DATA, flags, active.id, bytes[offset..][0..take]) catch {
            unlockWrite(conn);
            return error.ZixerClientDead;
        };
        unlockWrite(conn);

        conn.conn_send_window -= @intCast(take);
        active.send_window -= @intCast(take);
        offset += take;
    }
}

/// Relay exactly len upstream bytes as DATA, END_STREAM on the last run.
fn relayExact(conn: *Conn, active: *ActiveStream, up_r: *std.Io.Reader, len: u64, gate: upstream_deadline.Gate) RelayError!void {
    var chunk: [http2_frames.MAX_PAYLOAD]u8 = undefined;
    var remaining = len;
    while (remaining > 0) {
        // The head is already on the wire, so a stall here can only end the
        // stream. The client sees a reset rather than a body that never ends.
        if (!gate.ready(up_r)) return error.ZixerUpstreamDead;

        const want: usize = @intCast(@min(remaining, chunk.len));
        const got = up_r.readSliceShort(chunk[0..want]) catch return error.ZixerUpstreamDead;
        if (got == 0) return error.ZixerUpstreamDead;

        remaining -= got;
        try sendData(conn, active, chunk[0..got], remaining == 0);
    }

    conn.client_w.flush() catch return error.ZixerClientDead;
}

/// Relay a chunked upstream body: each chunk flushes as its own DATA so
/// stream semantics survive the hop, the trailer section becomes the
/// trailing header block.
fn relayChunked(conn: *Conn, active: *ActiveStream, up_r: *std.Io.Reader) RelayError!void {
    while (true) {
        var line_buf: [256]u8 = undefined;
        const size_line = readLine(up_r, &line_buf) catch return error.ZixerUpstreamDead;

        const semicolon = std.mem.indexOfScalar(u8, size_line, ';');
        const size_text = std.mem.trim(u8, if (semicolon) |pos| size_line[0..pos] else size_line, " \t");
        const size = std.fmt.parseInt(u64, size_text, 16) catch return error.ZixerBadBody;

        if (size == 0) return relayTrailers(conn, active, up_r);

        var remaining = size;
        var chunk: [http2_frames.MAX_PAYLOAD]u8 = undefined;
        while (remaining > 0) {
            const want: usize = @intCast(@min(remaining, chunk.len));
            const got = up_r.readSliceShort(chunk[0..want]) catch return error.ZixerUpstreamDead;
            if (got == 0) return error.ZixerUpstreamDead;

            remaining -= got;
            try sendData(conn, active, chunk[0..got], false);
        }

        const after = readLine(up_r, &line_buf) catch return error.ZixerUpstreamDead;
        if (after.len != 0) return error.ZixerBadBody;

        conn.client_w.flush() catch return error.ZixerClientDead;
    }
}

/// Consume the trailer section and end the stream: named trailers ride a
/// trailing header block, an empty section ends with bare END_STREAM.
fn relayTrailers(conn: *Conn, active: *ActiveStream, up_r: *std.Io.Reader) RelayError!void {
    var trailers: [16]http1_head.Header = undefined;
    var trailer_count: usize = 0;
    var text_buf: [2048]u8 = undefined;
    var text_len: usize = 0;

    while (true) {
        var line_buf: [512]u8 = undefined;
        const line = readLine(up_r, &line_buf) catch return error.ZixerUpstreamDead;
        if (line.len == 0) break;
        if (trailer_count == trailers.len) continue;
        if (text_len + line.len > text_buf.len) continue;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        @memcpy(text_buf[text_len..][0..line.len], line);
        const stored = text_buf[text_len..][0..line.len];
        text_len += line.len;

        trailers[trailer_count] = .{
            .name = stored[0..colon],
            .value = std.mem.trim(u8, stored[colon + 1 ..], " \t"),
        };
        trailer_count += 1;
    }

    if (trailer_count > 0) {
        const block = http2_translate.encodeTrailerBlock(&conn.resp_block_buf, trailers[0..trailer_count]) catch {
            return try sendData(conn, active, "", true);
        };
        if (block.len > 0) {
            if (writeBlock(conn, active.id, block, true) == .CLOSED) return error.ZixerClientDead;

            return;
        }
    }

    try sendData(conn, active, "", true);
}

/// Relay until the upstream closes, each burst flushed as it arrives (a
/// filling read would hold streamed events until the buffer topped up),
/// then END_STREAM.
fn relayUntilClose(conn: *Conn, active: *ActiveStream, up_r: *std.Io.Reader) RelayError!void {
    while (true) {
        const burst = up_r.peekGreedy(1) catch break;

        try sendData(conn, active, burst, false);
        conn.client_w.flush() catch return error.ZixerClientDead;
        up_r.toss(burst.len);
    }

    try sendData(conn, active, "", true);
}

/// One CRLF-terminated line, returned without its terminator.
fn readLine(src: *std.Io.Reader, buf: []u8) ![]const u8 {
    var len: usize = 0;
    while (len < buf.len) {
        const got = src.readSliceShort(buf[len .. len + 1]) catch return error.ZixerConnectionClosed;
        if (got == 0) return error.ZixerConnectionClosed;

        len += 1;
        if (len >= 2 and buf[len - 2] == '\r' and buf[len - 1] == '\n') return buf[0 .. len - 2];
    }

    return error.ZixerBadChunk;
}

// --------------------------------------------------------- //
// static plane

/// Serve one resolved file on the stream, mirroring the h1 static plane.
fn resolvedFromHit(hit: static_cached.Hit) static_files.Resolved {
    return .{
        .file = hit.file,
        .size = hit.size,
        .content_type = hit.content_type,
        .encoding = hit.encoding,
    };
}

/// Write one static file as a HEADERS block and its DATA frames.
///
/// Note:
/// - The caller owns the descriptor. An uncached answer closes it after, a
///   cached one leaves it to the table.
/// - bytes is the resident copy of a cached entry, non-null only when the
///   table could snapshot it. Every DATA frame then comes from memory instead
///   of reading the same range out of the page cache once per frame. This edge
///   coalesces its frames, which rules out handing the descriptor to sendfile,
///   so the snapshot is what replaces it.
fn serveStaticFile(conn: *Conn, active: *ActiveStream, resolved: static_files.Resolved, is_head: bool, bytes: ?[]const u8) Outcome {
    const io = conn.io;

    var block_buf: [1024]u8 = undefined;
    const block = http2_translate.encodeStaticBlock(&block_buf, resolved.content_type, resolved.size, resolved.encoding.contentEncoding(), conn.clientBlock()) catch {
        return if (streamError(conn, active.id, Http2.ERR_INTERNAL_ERROR) == .CLOSED) .CONN_DEAD else .DONE;
    };

    // Same staging as the proxied path: the file's first DATA frame
    // leaves with the head.
    const head_only = is_head or resolved.size == 0;
    const head_written = if (head_only)
        writeBlock(conn, active.id, block, true)
    else
        stageBlock(conn, active.id, block, false);
    if (head_written == .CLOSED) return .CONN_DEAD;
    if (head_only) return .DONE;

    var chunk: [http2_frames.MAX_PAYLOAD]u8 = undefined;
    var offset: u64 = 0;
    while (offset < resolved.size) {
        const want: usize = @intCast(@min(resolved.size - offset, chunk.len));

        const frame: []const u8 = if (bytes) |resident|
            resident[@intCast(offset)..][0..want]
        else read: {
            const got = resolved.file.readPositionalAll(io, chunk[0..want], offset) catch {
                return if (streamError(conn, active.id, Http2.ERR_INTERNAL_ERROR) == .CLOSED) .CONN_DEAD else .DONE;
            };
            if (got == 0) {
                return if (streamError(conn, active.id, Http2.ERR_INTERNAL_ERROR) == .CLOSED) .CONN_DEAD else .DONE;
            }

            break :read chunk[0..got];
        };

        offset += frame.len;
        sendData(conn, active, frame, offset == resolved.size) catch |err| switch (err) {
            error.ZixerClientDead => return .CONN_DEAD,

            // The stream ended under us, the staged head still leaves.
            else => {
                conn.client_w.flush() catch return .CONN_DEAD;

                return .DONE;
            },
        };
    }
    conn.client_w.flush() catch return .CONN_DEAD;

    return .DONE;
}

// --------------------------------------------------------- //
// rfc 8441 tunnel

/// Run the staged extended CONNECT: the pool pick pins for the tunnel
/// life and the edge connection always closes with it. A refused upgrade
/// relays the upstream's plain response instead.
fn serveConnect(conn: *Conn) Outcome {
    const io = conn.io;
    const pool = conn.proxy.pool.?;
    const idle = conn.proxy.idle.?;
    const upstream_head = conn.connect_head[0..conn.connect_head_len];
    var active = ActiveStream{ .id = conn.connect_id, .send_window = conn.peer_initial_window, .recv_done = true };

    // The tunnel setup is gated, the tunnel itself is not: it lives as long
    // as its client, so the slot goes back once the 101 is relayed.
    const admission = process_wait.admit(conn.proxy.process_gate, io);
    if (admission != .ADMITTED) {
        return if (localAnswer(conn, active.id, 504, process_wait.PROXY_ERROR) == .CLOSED) .CONN_DEAD else .DONE;
    }

    var slot = process_wait.hold(conn.proxy.process_gate);
    defer slot.release();

    var attempts: usize = pool.slots.len + 1;
    var failed_here = false;
    var connect_timed_out = false;
    while (attempts > 0) : (attempts -= 1) {
        const picked = pool.pick(monotonic_clock.nowMs(io)) orelse {
            if (failed_here) break;

            return if (localAnswer(conn, active.id, 503, "destination_unavailable") == .CLOSED) .CONN_DEAD else .DONE;
        };

        const conn_up = idle.acquire(io, picked.index, monotonic_clock.nowMs(io)) orelse
            upstream_conn.connect(io, picked.host, picked.port, picked.index, conn.proxy.upstream_connect_timeout_ms) catch |err| {
            if (upstream_status.ranOutOfTime(err)) connect_timed_out = true;

            pool.markDown(picked.index, monotonic_clock.nowMs(io));
            failed_here = true;
            continue;
        };

        var up_reader = conn_up.stream.reader(io, conn.buffers.upstream_read);
        var up_writer = conn_up.stream.writer(io, conn.buffers.upstream_write);

        const sent = blk: {
            up_writer.interface.writeAll(upstream_head) catch break :blk false;
            up_writer.interface.flush() catch break :blk false;
            break :blk true;
        };
        if (!sent) {
            conn_up.stream.close(io);
            if (!conn_up.reused) pool.markDown(picked.index, monotonic_clock.nowMs(io));
            failed_here = true;
            continue;
        }

        var resp_head_buf: [http1_head.MAX_HEAD_BYTES]u8 = undefined;
        if (!upstreamGate(conn, conn_up).ready(&up_reader.interface)) {
            conn_up.stream.close(io);

            return if (localAnswer(conn, active.id, 504, "http_response_timeout") == .CLOSED) .CONN_DEAD else .DONE;
        }

        const head_bytes = http1_head.readHead(&up_reader.interface, &resp_head_buf) catch {
            conn_up.stream.close(io);
            if (!conn_up.reused) pool.markDown(picked.index, monotonic_clock.nowMs(io));
            failed_here = true;
            continue;
        };
        const response = http1_head.parseResponse(head_bytes, "GET") catch {
            conn_up.stream.close(io);
            failed_here = true;
            continue;
        };

        // The upstream refused the upgrade: its plain response relays on
        // the CONNECT stream, the edge keeps serving.
        if (response.status != 101) {
            return relayResponse(conn, &active, &response, conn_up, &up_reader.interface);
        }

        if (!acceptMatches(&response, &conn.connect_key)) {
            conn_up.stream.close(io);
            return if (localAnswer(conn, active.id, 502, "connection_terminated") == .CLOSED) .CONN_DEAD else .DONE;
        }

        const block = http2_translate.encodeConnectResponseBlock(&conn.resp_block_buf, &response, conn.clientBlock()) catch {
            conn_up.stream.close(io);
            return if (streamError(conn, active.id, Http2.ERR_INTERNAL_ERROR) == .CLOSED) .CONN_DEAD else .DONE;
        };
        if (writeBlock(conn, active.id, block, false) == .CLOSED) {
            conn_up.stream.close(io);
            return .CONN_DEAD;
        }

        // The upgrade is live from here, so the next request may have the
        // slot. A handful of open tunnels must not pin the site's capacity.
        slot.release();

        var conn_window = std.atomic.Value(i64).init(conn.conn_send_window);
        var stream_window = std.atomic.Value(i64).init(active.send_window);
        var stop = std.atomic.Value(bool).init(false);
        http2_ws_bridge.run(.{
            .io = io,
            .client_r = conn.client_r,
            .client_w = conn.client_w,
            .write_lock = &conn.write_lock,
            .client_stream = conn.client_stream,
            .stream_id = active.id,
            .up_stream = conn_up.stream,
            .up_r = &up_reader.interface,
            .up_w = &up_writer.interface,
            .conn_window = &conn_window,
            .stream_window = &stream_window,
            .max_frame = effectiveMaxFrame(conn),
            .stop = &stop,
        });
        conn_up.stream.close(io);

        lockWrite(conn);
        http2_frames.writeGoaway(conn.client_w, conn.highest_stream, Http2.ERR_NO_ERROR) catch {};
        conn.client_w.flush() catch {};
        unlockWrite(conn);

        return .CONN_DEAD;
    }

    const answer = upstream_status.afterAttempts(connect_timed_out);

    return if (localAnswer(conn, active.id, answer.status, answer.proxy_error) == .CLOSED) .CONN_DEAD else .DONE;
}

/// Validate the upstream's Sec-WebSocket-Accept against zixer's own key
/// (rfc 6455 4.2.2).
fn acceptMatches(response: *const http1_head.ResponseHead, key_b64: []const u8) bool {
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(key_b64);
    sha.update(WS_ACCEPT_GUID);
    var digest: [20]u8 = undefined;
    sha.final(&digest);

    var expected: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&expected, &digest);

    for (response.headerSlice()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "sec-websocket-accept")) {
            return std.mem.eql(u8, std.mem.trim(u8, header.value, " \t"), &expected);
        }
    }

    return false;
}

// --------------------------------------------------------- //
// local answers and small helpers

/// Answer a stream locally with a bodyless head, END_STREAM set.
fn localAnswer(conn: *Conn, stream_id: u31, status: u16, proxy_error: ?[]const u8) ProcessResult {
    return sendLocalHead(conn, stream_id, status, proxy_error, true);
}

fn sendLocalHead(conn: *Conn, stream_id: u31, status: u16, proxy_error: ?[]const u8, end_stream: bool) ProcessResult {
    var block_buf: [256]u8 = undefined;
    const block = http2_translate.encodeLocalBlock(&block_buf, status, proxy_error, conn.clientBlock()) catch return .OK;

    return writeBlock(conn, stream_id, block, end_stream);
}

/// Write one header block and flush it, under the shared write lock.
fn writeBlock(conn: *Conn, stream_id: u31, block: []const u8, end_stream: bool) ProcessResult {
    lockWrite(conn);
    defer unlockWrite(conn);
    http2_frames.writeHeaderBlock(conn.client_w, stream_id, block, end_stream, effectiveMaxFrame(conn)) catch return .CLOSED;
    conn.client_w.flush() catch return .CLOSED;

    return .OK;
}

/// Write one header block and leave it staged, under the shared write lock.
///
/// Note:
/// - Only for a head whose body is already in hand or a local file read:
///   the first DATA frame then leaves in the same write, so a small
///   response costs one segment instead of two, and one TLS record
///   instead of two. A body that may stall (chunked, close-delimited)
///   uses writeBlock, its head cannot wait on a stream's first event.
/// - The caller owes the flush. Every relay path ends in one, and
///   relayResponse flushes again on the way out so an early end still
///   delivers the head.
fn stageBlock(conn: *Conn, stream_id: u31, block: []const u8, end_stream: bool) ProcessResult {
    lockWrite(conn);
    defer unlockWrite(conn);
    http2_frames.writeHeaderBlock(conn.client_w, stream_id, block, end_stream, effectiveMaxFrame(conn)) catch return .CLOSED;

    return .OK;
}

/// Reset one stream, the connection keeps serving.
fn streamError(conn: *Conn, stream_id: u31, code: u32) ProcessResult {
    lockWrite(conn);
    defer unlockWrite(conn);
    http2_frames.writeRstStream(conn.client_w, stream_id, code) catch return .CLOSED;
    conn.client_w.flush() catch return .CLOSED;

    return .OK;
}

/// Fatal connection error: best-effort GOAWAY, then the caller closes.
fn connError(conn: *Conn, code: u32) ProcessResult {
    lockWrite(conn);
    defer unlockWrite(conn);
    http2_frames.writeGoaway(conn.client_w, conn.highest_stream, code) catch return .CLOSED;
    conn.client_w.flush() catch return .CLOSED;

    return .CLOSED;
}

/// Largest DATA payload one send may carry: the peer's advertised frame
/// size, capped by zixer's own staging.
fn effectiveMaxFrame(conn: *const Conn) usize {
    return @min(conn.peer_max_frame, http2_frames.MAX_PAYLOAD);
}

fn lockWrite(conn: *Conn) void {
    while (conn.write_lock.swap(true, .acquire)) std.atomic.spinLoopHint();
}

fn unlockWrite(conn: *Conn) void {
    conn.write_lock.store(false, .release);
}

/// The read bound for one upstream leg of this site.
fn upstreamGate(conn: *Conn, conn_up: upstream_conn.UpstreamConn) upstream_deadline.Gate {
    return .{ .stream = conn_up.stream, .budget_ms = conn.proxy.upstream_timeout_ms };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Attempts a fake backend makes at its fixed port, one per BIND_RETRY_MS.
/// These ports sit below the ephemeral range, so the kernel never hands one
/// out as an outbound source port. What is left is a foreign process holding
/// the port, and retrying rides a brief hold out instead of failing the run.
const BIND_TRIES: usize = 50;
const BIND_RETRY_MS: u64 = 10;

fn bindWithRetry(io: std.Io, addr: std.Io.net.IpAddress) ?std.Io.net.Server {
    var tries: usize = 0;
    while (tries < BIND_TRIES) : (tries += 1) {
        if (addr.listen(io, .{ .reuse_address = true, .kernel_backlog = 8 })) |server| return server else |_| {}

        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(BIND_RETRY_MS), .awake) catch {};
    }

    return null;
}

const testing = std.testing;

/// Socket leg size the rigs below bind with. The serving path takes its
/// size from the site instead, see conn_buffer.
const STREAM_BUF_SIZE: usize = 8 * 1024;
const site_cfg = @import("site_cfg.zig");

fn edgeStream(handle: std.posix.fd_t) std.Io.net.Stream {
    return .{ .socket = .{ .handle = handle, .address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 40012 } } } };
}

fn spawnServeConn(proxy: *const http1_proxy.Proxy, stream: std.Io.net.Stream) !std.Thread {
    return std.Thread.spawn(.{}, serveConnThread, .{ proxy, stream });
}

fn serveConnThread(proxy: *const http1_proxy.Proxy, stream: std.Io.net.Stream) void {
    serveConn(proxy, stream);
}

/// h2 test client over one socketpair end: buffered stream interfaces
/// plus its own frame and hpack state.
const TestClient = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    read_buf: [16 * 1024]u8 = undefined,
    write_buf: [8 * 1024]u8 = undefined,
    reader: std.Io.net.Stream.Reader = undefined,
    writer: std.Io.net.Stream.Writer = undefined,
    payload_buf: [http2_frames.MAX_PAYLOAD]u8 = undefined,
    decoder: Http2.HpackDecoder = undefined,
    decoded: [32]Http2.Header = undefined,
    scratch: [8 * 1024]u8 = undefined,
    head_end_stream: bool = false,

    /// Bind the interfaces, run the connection preface both ways.
    fn start(client: *TestClient) !void {
        client.reader = client.stream.reader(client.io, &client.read_buf);
        client.writer = client.stream.writer(client.io, &client.write_buf);
        client.decoder = Http2.HpackDecoder.init();

        try client.writer.interface.writeAll(Http2.PREFACE);
        try http2_frames.writeSettings(&client.writer.interface, &.{});
        try client.writer.interface.flush();

        const server_settings = try client.nextFrame();
        try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_SETTINGS), server_settings.head.frame_type);
        try testing.expectEqual(@as(u8, 0), server_settings.head.flags & Http2.FLAG_ACK);

        try http2_frames.writeSettingsAck(&client.writer.interface);
        try client.writer.interface.flush();

        const settings_ack = try client.nextFrame();
        try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_SETTINGS), settings_ack.head.frame_type);
        try testing.expectEqual(Http2.FLAG_ACK, settings_ack.head.flags & Http2.FLAG_ACK);
    }

    fn nextFrame(client: *TestClient) !http2_frames.Frame {
        return http2_frames.readFrame(&client.reader.interface, &client.payload_buf);
    }

    fn sendHeaders(client: *TestClient, stream_id: u31, headers: []const Http2.Header, end_stream: bool) !void {
        var block_buf: [2048]u8 = undefined;
        var encoder = Http2.HpackEncoder.init(&block_buf);
        for (headers) |entry| try encoder.writeHeader(entry.name, entry.value);

        try http2_frames.writeHeaderBlock(&client.writer.interface, stream_id, encoder.encoded(), end_stream, http2_frames.MAX_PAYLOAD);
        try client.writer.interface.flush();
    }

    fn sendData(client: *TestClient, stream_id: u31, bytes: []const u8, end_stream: bool) !void {
        const flags: u8 = if (end_stream) Http2.FLAG_END_STREAM else 0;
        try http2_frames.writeFrame(&client.writer.interface, Http2.FRAME_TYPE_DATA, flags, stream_id, bytes);
        try client.writer.interface.flush();
    }

    fn sendPing(client: *TestClient) !void {
        try http2_frames.writeFrame(&client.writer.interface, Http2.FRAME_TYPE_PING, 0, 0, "pingpong");
        try client.writer.interface.flush();
    }

    /// Read frames until this stream's response head arrives, decode it
    /// into client.decoded. Grants and acks on the way are skipped.
    fn readHead(client: *TestClient, stream_id: u31) !usize {
        while (true) {
            const frame = try client.nextFrame();
            if (frame.head.frame_type != Http2.FRAME_TYPE_HEADERS or frame.head.stream_id != stream_id) {
                if (frame.head.frame_type == Http2.FRAME_TYPE_RST_STREAM or
                    frame.head.frame_type == Http2.FRAME_TYPE_GOAWAY) return error.TestUnexpectedResult;
                continue;
            }

            try testing.expect((frame.head.flags & Http2.FLAG_END_HEADERS) != 0);
            client.head_end_stream = (frame.head.flags & Http2.FLAG_END_STREAM) != 0;
            const fragment = try http2_frames.headersFragment(&frame);

            return try client.decoder.decode(fragment, &client.decoded, &client.scratch);
        }
    }

    fn headerValue(client: *TestClient, count: usize, name: []const u8) ?[]const u8 {
        for (client.decoded[0..count]) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.value;
        }

        return null;
    }

    /// Collect DATA for one stream until END_STREAM, granting the flow
    /// credit back as a well-behaved peer.
    fn collectBody(client: *TestClient, stream_id: u31, out: []u8) !usize {
        var total: usize = 0;
        while (true) {
            const frame = try client.nextFrame();
            if (frame.head.frame_type != Http2.FRAME_TYPE_DATA or frame.head.stream_id != stream_id) {
                if (frame.head.frame_type == Http2.FRAME_TYPE_RST_STREAM or
                    frame.head.frame_type == Http2.FRAME_TYPE_GOAWAY) return error.TestUnexpectedResult;
                continue;
            }

            const data = try http2_frames.dataPayload(&frame);
            if (total + data.len > out.len) return error.TestUnexpectedResult;
            @memcpy(out[total..][0..data.len], data);
            total += data.len;

            if (frame.head.length > 0) {
                try http2_frames.writeWindowUpdate(&client.writer.interface, 0, @intCast(frame.head.length));
                try http2_frames.writeWindowUpdate(&client.writer.interface, stream_id, @intCast(frame.head.length));
                try client.writer.interface.flush();
            }

            if ((frame.head.flags & Http2.FLAG_END_STREAM) != 0) return total;
        }
    }
};

/// h1 upstream fake for the edge tests: accepts loopback conns, answers
/// per mode, records the first head and body it saw.
const FakeBackend = struct {
    io: std.Io,
    port: u16,
    request_quota: usize,
    mode: enum { ECHO, BIG, WS, PLAIN_403 },
    seen_head: [8192]u8 = undefined,
    seen_len: usize = 0,
    seen_body: [4096]u8 = undefined,
    seen_body_len: usize = 0,
    conns_accepted: usize = 0,
    ready: std.atomic.Value(bool) = .init(false),

    fn serve(fake: *FakeBackend) void {
        const io = fake.io;

        const addr = std.Io.net.IpAddress.parse("127.0.0.1", fake.port) catch return;
        var server = bindWithRetry(io, addr) orelse return;
        defer server.deinit(io);
        fake.ready.store(true, .release);

        var answered: usize = 0;
        while (answered < fake.request_quota) {
            const stream = server.accept(io) catch return;
            fake.conns_accepted += 1;

            var read_buf: [8192]u8 = undefined;
            var write_buf: [8192]u8 = undefined;
            var reader = stream.reader(io, &read_buf);
            var writer = stream.writer(io, &write_buf);

            conn: while (answered < fake.request_quota) {
                var head_buf: [8192]u8 = undefined;
                const head = http1_head.readHead(&reader.interface, &head_buf) catch break :conn;
                const request = http1_head.parseRequest(head) catch break :conn;

                if (fake.seen_len == 0) {
                    @memcpy(fake.seen_head[0..head.len], head);
                    fake.seen_len = head.len;
                }
                fake.readBody(&reader.interface, &request) catch break :conn;

                fake.answer(&writer.interface, &reader.interface) catch break :conn;
                answered += 1;
                if (fake.mode == .WS) break :conn;
            }

            stream.close(io);
        }
    }

    fn readBody(fake: *FakeBackend, src: *std.Io.Reader, request: *const http1_head.RequestHead) !void {
        switch (request.framing) {
            .none, .until_close => {},
            .content_length => |len| {
                const want: usize = @intCast(len);
                var got: usize = 0;
                while (got < want) {
                    const step = try src.readSliceShort(fake.seen_body[got..want]);
                    if (step == 0) return error.EndOfStream;
                    got += step;
                }
                fake.seen_body_len = want;
            },
            .chunked => {
                var line_buf: [64]u8 = undefined;
                while (true) {
                    const size_line = try readLine(src, &line_buf);
                    const size = try std.fmt.parseInt(usize, size_line, 16);
                    if (size == 0) {
                        _ = try readLine(src, &line_buf);
                        return;
                    }

                    var got: usize = 0;
                    while (got < size) {
                        const step = try src.readSliceShort(fake.seen_body[fake.seen_body_len + got ..][0 .. size - got]);
                        if (step == 0) return error.EndOfStream;
                        got += step;
                    }
                    fake.seen_body_len += size;
                    _ = try readLine(src, &line_buf);
                }
            },
        }
    }

    fn answer(fake: *FakeBackend, out: *std.Io.Writer, src: *std.Io.Reader) !void {
        switch (fake.mode) {
            .ECHO => {
                try out.print(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nKeep-Alive: timeout=5\r\nContent-Length: {d}\r\n\r\necho:{s}",
                    .{ fake.seen_body_len + 5, fake.seen_body[0..fake.seen_body_len] },
                );
                try out.flush();
            },
            .BIG => {
                try out.print("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {d}\r\n\r\n", .{BIG_BODY_LEN});
                var block: [4096]u8 = undefined;
                @memset(&block, 'b');
                var sent: usize = 0;
                while (sent < BIG_BODY_LEN) {
                    const take = @min(BIG_BODY_LEN - sent, block.len);
                    try out.writeAll(block[0..take]);
                    sent += take;
                }
                try out.flush();
            },
            .WS => {
                const key = headOf(fake, "sec-websocket-key") orelse return error.TestUnexpectedResult;
                var accept: [28]u8 = undefined;
                wsAccept(key, &accept);
                try out.print(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n",
                    .{&accept},
                );
                try out.flush();

                // raw echo until the tunnel half-closes.
                while (true) {
                    const burst = src.peekGreedy(1) catch return;
                    try out.writeAll(burst);
                    try out.flush();
                    src.toss(burst.len);
                }
            },
            .PLAIN_403 => {
                try out.writeAll("HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno");
                try out.flush();
            },
        }
    }

    /// The value of one header in the recorded head, null when absent.
    fn headOf(fake: *FakeBackend, name: []const u8) ?[]const u8 {
        const request = http1_head.parseRequest(fake.seen_head[0..fake.seen_len]) catch return null;
        for (request.headers[0..request.header_count]) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) return entry.value;
        }

        return null;
    }
};

const BIG_BODY_LEN: usize = 100000;

/// rfc 6455 4.2.2 accept answer for a handshake key.
fn wsAccept(key: []const u8, out: *[28]u8) void {
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(key);
    sha.update(WS_ACCEPT_GUID);
    var digest: [20]u8 = undefined;
    sha.final(&digest);

    _ = std.base64.standard.Encoder.encode(out, &digest);
}

fn waitBackend(io: std.Io, fake: *FakeBackend) !void {
    var tries: usize = 0;
    while (tries < 100 and !fake.ready.load(.acquire)) : (tries += 1) {
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }

    try testing.expect(tries < 100);
}

fn openEdgePair(fds: *[2]std.posix.fd_t) !void {
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, fds));
}

/// Client-leg writer that records the wire as segments: one entry per
/// drain or flush that moved bytes, which is one send on a real socket.
/// A call that moved nothing is no send at all, so it records nothing.
const SegmentProbe = struct {
    writer: std.Io.Writer,
    stage: [STREAM_BUF_SIZE]u8 = undefined,
    wire: [16 * 1024]u8 = undefined,
    wire_len: usize = 0,
    segment_start: [32]usize = undefined,
    segment_len: [32]usize = undefined,
    segment_count: usize = 0,

    const vtable = std.Io.Writer.VTable{ .drain = drain, .flush = flushSegment };

    fn bind(probe: *SegmentProbe) void {
        probe.writer = .{ .vtable = &vtable, .buffer = &probe.stage, .end = 0 };
    }

    fn segment(probe: *const SegmentProbe, index: usize) []const u8 {
        return probe.wire[probe.segment_start[index]..][0..probe.segment_len[index]];
    }

    fn append(probe: *SegmentProbe, bytes: []const u8) void {
        @memcpy(probe.wire[probe.wire_len..][0..bytes.len], bytes);
        probe.wire_len += bytes.len;
    }

    fn closeSegment(probe: *SegmentProbe, start: usize) void {
        if (probe.wire_len == start) return;

        probe.segment_start[probe.segment_count] = start;
        probe.segment_len[probe.segment_count] = probe.wire_len - start;
        probe.segment_count += 1;
    }

    fn drain(interface: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const probe: *SegmentProbe = @alignCast(@fieldParentPtr("writer", interface));
        const start = probe.wire_len;

        probe.append(interface.buffer[0..interface.end]);
        interface.end = 0;

        var consumed: usize = 0;
        for (data[0 .. data.len - 1]) |slice| {
            probe.append(slice);
            consumed += slice.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            probe.append(last);
            consumed += last.len;
        }

        probe.closeSegment(start);

        return consumed;
    }

    fn flushSegment(interface: *std.Io.Writer) std.Io.Writer.Error!void {
        const probe: *SegmentProbe = @alignCast(@fieldParentPtr("writer", interface));
        const start = probe.wire_len;

        probe.append(interface.buffer[0..interface.end]);
        interface.end = 0;

        probe.closeSegment(start);
    }
};

/// Build one h2 client leg: preface, SETTINGS, the ack, then one request.
fn buildClientWire(buf: []u8, headers: []const Http2.Header) ![]const u8 {
    var out = std.Io.Writer.fixed(buf);
    try out.writeAll(Http2.PREFACE);
    try http2_frames.writeSettings(&out, &.{});
    try http2_frames.writeSettingsAck(&out);

    var block_buf: [1024]u8 = undefined;
    var encoder = Http2.HpackEncoder.init(&block_buf);
    for (headers) |entry| try encoder.writeHeader(entry.name, entry.value);

    try http2_frames.writeHeaderBlock(&out, 1, encoder.encoded(), true, http2_frames.MAX_PAYLOAD);

    return out.buffered();
}

test "zix zixer: http2 edge, preface sniff serves h2 and falls back to h1" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const proxy = http1_proxy.Proxy{ .io = io };

    // an h1 request on the http2 site runs the h1 loop.
    var h1_fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&h1_fds);
    const h1_thread = try spawnServeConn(&proxy, edgeStream(h1_fds[0]));
    const h1_client = edgeStream(h1_fds[1]);

    var h1_write_buf: [256]u8 = undefined;
    var h1_writer = h1_client.writer(io, &h1_write_buf);
    try h1_writer.interface.writeAll("GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    try h1_writer.interface.flush();

    var h1_reply: [512]u8 = undefined;
    var h1_read_buf: [512]u8 = undefined;
    var h1_reader = h1_client.reader(io, &h1_read_buf);
    var h1_len: usize = 0;
    while (h1_len < h1_reply.len) {
        const got = h1_reader.interface.readSliceShort(h1_reply[h1_len .. h1_len + 1]) catch break;
        if (got == 0) break;
        h1_len += got;
    }
    try testing.expect(std.mem.startsWith(u8, h1_reply[0..h1_len], "HTTP/1.1 404 "));
    h1_client.close(io);
    h1_thread.join();

    // the h2 preface reaches the frame loop: settings come back.
    var h2_fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&h2_fds);
    const h2_thread = try spawnServeConn(&proxy, edgeStream(h2_fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(h2_fds[1]) };
    try client.start();

    client.stream.close(io);
    h2_thread.join();
}

test "zix zixer: http2 edge, get proxies end to end and reuses the upstream conn" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeBackend{ .io = io, .port = 18857, .request_quota = 2, .mode = .ECHO };
    const fake_thread = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake});
    try waitBackend(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18857 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    var idle = try upstream_conn.IdleCache.init(testing.allocator, 1);
    defer idle.deinit(testing.allocator, io);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool, .idle = &idle };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    const get_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/api/one" },
        .{ .name = ":authority", .value = "app.example" },
        .{ .name = "accept", .value = "*/*" },
    };
    try client.sendHeaders(1, &get_headers, true);

    const count = try client.readHead(1);
    try testing.expectEqualStrings("200", client.headerValue(count, ":status").?);
    try testing.expectEqualStrings("1.1 zixer", client.headerValue(count, "via").?);
    try testing.expectEqualStrings("5", client.headerValue(count, "content-length").?);
    try testing.expect(client.headerValue(count, "keep-alive") == null);
    try testing.expect(!client.head_end_stream);

    var body: [64]u8 = undefined;
    try testing.expectEqualStrings("echo:", body[0..try client.collectBody(1, &body)]);

    // a ping between exchanges answers.
    try client.sendPing();
    const pong = try client.nextFrame();
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_PING), pong.head.frame_type);
    try testing.expectEqual(Http2.FLAG_ACK, pong.head.flags & Http2.FLAG_ACK);
    try testing.expectEqualStrings("pingpong", pong.payload);

    // the second stream reuses the idle upstream conn.
    try client.sendHeaders(3, &get_headers, true);
    const second_count = try client.readHead(3);
    try testing.expectEqualStrings("200", client.headerValue(second_count, ":status").?);
    _ = try client.collectBody(3, &body);

    // the rebuilt upstream head carried the intermediary fields.
    const seen = fake.seen_head[0..fake.seen_len];
    try testing.expect(std.mem.startsWith(u8, seen, "GET /api/one HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, seen, "Host: app.example\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, seen, "Via: 1.1 zixer\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, seen, "Forwarded: for=") != null);

    try testing.expectEqual(@as(usize, 1), fake.conns_accepted);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: http2 edge, post with content length reaches the upstream intact" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeBackend{ .io = io, .port = 18858, .request_quota = 1, .mode = .ECHO };
    const fake_thread = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake});
    try waitBackend(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18858 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    var idle = try upstream_conn.IdleCache.init(testing.allocator, 1);
    defer idle.deinit(testing.allocator, io);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool, .idle = &idle };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    const post_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/submit" },
        .{ .name = ":authority", .value = "app.example" },
        .{ .name = "content-length", .value = "9" },
    };
    try client.sendHeaders(1, &post_headers, false);
    try client.sendData(1, "ping-", false);
    try client.sendData(1, "body", true);

    const count = try client.readHead(1);
    try testing.expectEqualStrings("200", client.headerValue(count, ":status").?);

    var body: [64]u8 = undefined;
    try testing.expectEqualStrings("echo:ping-body", body[0..try client.collectBody(1, &body)]);

    try testing.expectEqualStrings("ping-body", fake.seen_body[0..fake.seen_body_len]);
    const seen = fake.seen_head[0..fake.seen_len];
    try testing.expect(std.mem.indexOf(u8, seen, "Content-Length: 9\r\n") != null);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: http2 edge, post without length re-frames as chunked" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeBackend{ .io = io, .port = 18868, .request_quota = 1, .mode = .ECHO };
    const fake_thread = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake});
    try waitBackend(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18868 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    var idle = try upstream_conn.IdleCache.init(testing.allocator, 1);
    defer idle.deinit(testing.allocator, io);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool, .idle = &idle };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    const post_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/stream" },
        .{ .name = ":authority", .value = "app.example" },
    };
    try client.sendHeaders(1, &post_headers, false);
    try client.sendData(1, "part-one", false);
    try client.sendData(1, "two", true);

    const count = try client.readHead(1);
    try testing.expectEqualStrings("200", client.headerValue(count, ":status").?);

    var body: [64]u8 = undefined;
    _ = try client.collectBody(1, &body);

    try testing.expectEqualStrings("part-onetwo", fake.seen_body[0..fake.seen_body_len]);
    const seen = fake.seen_head[0..fake.seen_len];
    try testing.expect(std.mem.indexOf(u8, seen, "Transfer-Encoding: chunked\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, seen, "Content-Length") == null);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: http2 edge, queued streams answer in order and pick per stream" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake_a = FakeBackend{ .io = io, .port = 18850, .request_quota = 1, .mode = .ECHO };
    var fake_b = FakeBackend{ .io = io, .port = 18851, .request_quota = 1, .mode = .ECHO };
    const thread_a = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake_a});
    const thread_b = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake_b});
    try waitBackend(io, &fake_a);
    try waitBackend(io, &fake_b);

    const upstreams = [_]site_cfg.Upstream{
        .{ .host = "127.0.0.1", .port = 18850 },
        .{ .host = "127.0.0.1", .port = 18851 },
    };
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    var idle = try upstream_conn.IdleCache.init(testing.allocator, 2);
    defer idle.deinit(testing.allocator, io);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool, .idle = &idle };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    // both streams land before either response is read: the second one
    // queues while the first serves.
    const get_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/burst" },
        .{ .name = ":authority", .value = "app.example" },
    };
    try client.sendHeaders(1, &get_headers, true);
    try client.sendHeaders(3, &get_headers, true);

    var body: [64]u8 = undefined;
    const first_count = try client.readHead(1);
    try testing.expectEqualStrings("200", client.headerValue(first_count, ":status").?);
    _ = try client.collectBody(1, &body);

    const second_count = try client.readHead(3);
    try testing.expectEqualStrings("200", client.headerValue(second_count, ":status").?);
    _ = try client.collectBody(3, &body);

    // per-stream pick: round-robin sent one exchange to each upstream.
    try testing.expectEqual(@as(usize, 1), fake_a.conns_accepted);
    try testing.expectEqual(@as(usize, 1), fake_b.conns_accepted);

    client.stream.close(io);
    edge_thread.join();
    thread_a.join();
    thread_b.join();
}

test "zix zixer: http2 edge, big body crosses the flow windows complete" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeBackend{ .io = io, .port = 18856, .request_quota = 1, .mode = .BIG };
    const fake_thread = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake});
    try waitBackend(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18856 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    var idle = try upstream_conn.IdleCache.init(testing.allocator, 1);
    defer idle.deinit(testing.allocator, io);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool, .idle = &idle };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    const get_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/big" },
        .{ .name = ":authority", .value = "app.example" },
    };
    try client.sendHeaders(1, &get_headers, true);

    const count = try client.readHead(1);
    try testing.expectEqualStrings("200", client.headerValue(count, ":status").?);

    // The body outsizes both 65535 windows: it only completes because
    // collectBody grants credit back, and every frame stays inside the
    // default max frame size.
    var total: usize = 0;
    var frames: usize = 0;
    while (true) {
        const frame = try client.nextFrame();
        if (frame.head.frame_type != Http2.FRAME_TYPE_DATA or frame.head.stream_id != 1) continue;

        try testing.expect(frame.head.length <= Http2.DEFAULT_MAX_FRAME_SIZE);
        const data = try http2_frames.dataPayload(&frame);
        for (data) |byte| try testing.expectEqual(@as(u8, 'b'), byte);
        total += data.len;
        frames += 1;

        if (frame.head.length > 0) {
            try http2_frames.writeWindowUpdate(&client.writer.interface, 0, @intCast(frame.head.length));
            try http2_frames.writeWindowUpdate(&client.writer.interface, 1, @intCast(frame.head.length));
            try client.writer.interface.flush();
        }

        if ((frame.head.flags & Http2.FLAG_END_STREAM) != 0) break;
    }
    try testing.expectEqual(BIG_BODY_LEN, total);
    try testing.expect(frames >= BIG_BODY_LEN / Http2.DEFAULT_MAX_FRAME_SIZE);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: http2 edge, extended connect tunnels through the h1 upgrade" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeBackend{ .io = io, .port = 18852, .request_quota = 1, .mode = .WS };
    const fake_thread = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake});
    try waitBackend(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18852 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    var idle = try upstream_conn.IdleCache.init(testing.allocator, 1);
    defer idle.deinit(testing.allocator, io);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool, .idle = &idle };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    const connect_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "app.example" },
        .{ .name = "sec-websocket-version", .value = "13" },
    };
    try client.sendHeaders(1, &connect_headers, false);

    const count = try client.readHead(1);
    try testing.expectEqualStrings("200", client.headerValue(count, ":status").?);
    try testing.expectEqualStrings("1.1 zixer", client.headerValue(count, "via").?);
    try testing.expect(client.headerValue(count, "sec-websocket-accept") == null);
    try testing.expect(!client.head_end_stream);

    // raw websocket bytes echo through the pinned tunnel.
    try client.sendData(1, "frame-one", false);
    var echoed: [9]u8 = undefined;
    var echo_len: usize = 0;
    while (echo_len < echoed.len) {
        const frame = try client.nextFrame();
        if (frame.head.frame_type != Http2.FRAME_TYPE_DATA or frame.head.stream_id != 1) continue;

        const data = try http2_frames.dataPayload(&frame);
        @memcpy(echoed[echo_len..][0..data.len], data);
        echo_len += data.len;
    }
    try testing.expectEqualStrings("frame-one", &echoed);

    // the h1 leg carried zixer's own generated key and the upgrade pair.
    const seen = fake.seen_head[0..fake.seen_len];
    try testing.expect(std.mem.startsWith(u8, seen, "GET /chat HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, seen, "Sec-WebSocket-Key: ") != null);
    try testing.expect(std.mem.indexOf(u8, seen, "Connection: Upgrade\r\nUpgrade: websocket\r\n") != null);

    // client end: the edge closes with the tunnel, a goaway on the way out.
    try client.sendData(1, "", true);
    var saw_goaway = false;
    while (client.nextFrame()) |frame| {
        if (frame.head.frame_type == Http2.FRAME_TYPE_GOAWAY) saw_goaway = true;
    } else |_| {}
    try testing.expect(saw_goaway);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: http2 edge, refused upgrade relays the plain response" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeBackend{ .io = io, .port = 18853, .request_quota = 1, .mode = .PLAIN_403 };
    const fake_thread = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake});
    try waitBackend(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18853 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    var idle = try upstream_conn.IdleCache.init(testing.allocator, 1);
    defer idle.deinit(testing.allocator, io);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool, .idle = &idle };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    const connect_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":authority", .value = "app.example" },
        .{ .name = "sec-websocket-version", .value = "13" },
    };
    try client.sendHeaders(1, &connect_headers, false);

    const count = try client.readHead(1);
    try testing.expectEqualStrings("403", client.headerValue(count, ":status").?);

    var body: [16]u8 = undefined;
    try testing.expectEqualStrings("no", body[0..try client.collectBody(1, &body)]);

    // the connection lives on after the refusal.
    try client.sendPing();
    const pong = try client.nextFrame();
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_PING), pong.head.frame_type);
    try testing.expectEqual(Http2.FLAG_ACK, pong.head.flags & Http2.FLAG_ACK);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: http2 edge, static plane serves files head and misses" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    tmp.dir.writeFile(testing.io, .{ .sub_path = "page.html", .data = "<h1>h2 static</h1>" }) catch @panic("fixture write failed");

    var root_buf: [128]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    const proxy = http1_proxy.Proxy{ .io = io, .static = .{
        .public_dir = root,
        .public_prefix = null,
        .spa_fallback = null,
    } };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    const get_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/page.html" },
        .{ .name = ":authority", .value = "site.test" },
    };
    try client.sendHeaders(1, &get_headers, true);

    const count = try client.readHead(1);
    try testing.expectEqualStrings("200", client.headerValue(count, ":status").?);
    try testing.expectEqualStrings("text/html", client.headerValue(count, "content-type").?);
    try testing.expectEqualStrings("18", client.headerValue(count, "content-length").?);
    try testing.expectEqualStrings("Accept-Encoding", client.headerValue(count, "vary").?);

    var body: [64]u8 = undefined;
    try testing.expectEqualStrings("<h1>h2 static</h1>", body[0..try client.collectBody(1, &body)]);

    // HEAD answers the same head bodyless, END_STREAM on the headers.
    const head_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "HEAD" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/page.html" },
        .{ .name = ":authority", .value = "site.test" },
    };
    try client.sendHeaders(3, &head_headers, true);
    const head_count = try client.readHead(3);
    try testing.expectEqualStrings("200", client.headerValue(head_count, ":status").?);
    try testing.expect(client.head_end_stream);

    // a miss on the static-only site answers a local 404.
    const miss_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/absent.html" },
        .{ .name = ":authority", .value = "site.test" },
    };
    try client.sendHeaders(5, &miss_headers, true);
    const miss_count = try client.readHead(5);
    try testing.expectEqualStrings("404", client.headerValue(miss_count, ":status").?);
    try testing.expect(client.head_end_stream);

    client.stream.close(io);
    edge_thread.join();
}

test "zix zixer: http2 edge, tls certificate gate answers 421 on a foreign authority" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const cert_pem = try std.Io.Dir.cwd().readFileAlloc(io, "examples/certs/ecdsa_p256_cert.pem", testing.allocator, .limited(1 << 20));
    defer testing.allocator.free(cert_pem);
    var der_buf: [4096]u8 = undefined;
    const cert_der = try zix.Tls.pemToDer(&der_buf, cert_pem);

    const proxy = http1_proxy.Proxy{ .io = io, .tls_cert_der = cert_der };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    const foreign_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "evil.example" },
    };
    try client.sendHeaders(1, &foreign_headers, true);
    const foreign_count = try client.readHead(1);
    try testing.expectEqualStrings("421", client.headerValue(foreign_count, ":status").?);
    try testing.expect(client.head_end_stream);

    // the certificate's own SAN passes the gate and reaches the next
    // plane (here: the local 404 of a site with no planes).
    const own_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "localhost:443" },
    };
    try client.sendHeaders(3, &own_headers, true);
    const own_count = try client.readHead(3);
    try testing.expectEqualStrings("404", client.headerValue(own_count, ":status").?);

    client.stream.close(io);
    edge_thread.join();
}

test "zix zixer: http2 edge, malformed stream resets and the connection survives" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const proxy = http1_proxy.Proxy{ .io = io };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    // an uppercase field name is malformed in h2 (rfc 9113 8.2).
    const malformed_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "t" },
        .{ .name = "X-Bad", .value = "1" },
    };
    try client.sendHeaders(1, &malformed_headers, true);

    const reset = try client.nextFrame();
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_RST_STREAM), reset.head.frame_type);
    try testing.expectEqual(@as(u31, 1), reset.head.stream_id);
    try testing.expectEqual(Http2.ERR_PROTOCOL_ERROR, std.mem.readInt(u32, reset.payload[0..4], .big));

    // the stream died, the connection did not.
    try client.sendPing();
    const pong = try client.nextFrame();
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_PING), pong.head.frame_type);
    try testing.expectEqual(Http2.FLAG_ACK, pong.head.flags & Http2.FLAG_ACK);

    client.stream.close(io);
    edge_thread.join();
}

test "zix zixer: http2 edge, client goaway drains and closes the connection" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const proxy = http1_proxy.Proxy{ .io = io };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    try http2_frames.writeGoaway(&client.writer.interface, 0, Http2.ERR_NO_ERROR);
    try client.writer.interface.flush();

    const answer_frame = try client.nextFrame();
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_GOAWAY), answer_frame.head.frame_type);
    try testing.expectError(error.ZixerConnectionClosed, client.nextFrame());

    client.stream.close(io);
    edge_thread.join();
}

/// Test upstream that accepts and then says nothing, the stall an upstream
/// read deadline exists for.
const SilentBackend = struct {
    io: std.Io,
    port: u16,
    ready: std.atomic.Value(bool) = .init(false),
    release: std.atomic.Value(bool) = .init(false),

    fn serve(fake: *SilentBackend) void {
        const io = fake.io;

        const addr = std.Io.net.IpAddress.parse("127.0.0.1", fake.port) catch return;
        var server = bindWithRetry(io, addr) orelse return;
        defer server.deinit(io);
        fake.ready.store(true, .release);

        const stream = server.accept(io) catch return;
        defer stream.close(io);

        while (!fake.release.load(.acquire)) {
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch break;
        }
    }
};

test "zix zixer: http2 edge, a silent upstream answers 504 with proxy status" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = SilentBackend{ .io = io, .port = 18950 };
    const fake_thread = try std.Thread.spawn(.{}, SilentBackend.serve, .{&fake});
    var tries: usize = 0;
    while (tries < 100 and !fake.ready.load(.acquire)) : (tries += 1) {
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    try testing.expect(tries < 100);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18950 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    var idle = try upstream_conn.IdleCache.init(testing.allocator, 1);
    defer idle.deinit(testing.allocator, io);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool, .idle = &idle, .upstream_timeout_ms = 200 };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    const get_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/stalled" },
        .{ .name = ":authority", .value = "app.example" },
    };
    try client.sendHeaders(1, &get_headers, true);

    const count = try client.readHead(1);
    try testing.expectEqualStrings("504", client.headerValue(count, ":status").?);
    try testing.expectEqualStrings("zixer; error=\"http_response_timeout\"", client.headerValue(count, "proxy-status").?);

    // A slow backend is still a serving one, so the slot stays in rotation.
    try testing.expectEqual(@as(usize, 1), pool.upCount());

    client.stream.close(io);
    edge_thread.join();
    fake.release.store(true, .release);
    fake_thread.join();
}

test "zix zixer: http2 edge, the proxied head and body leave in one write" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeBackend{ .io = io, .port = 18956, .request_quota = 1, .mode = .ECHO };
    const fake_thread = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake});
    try waitBackend(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18956 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    var idle = try upstream_conn.IdleCache.init(testing.allocator, 1);
    defer idle.deinit(testing.allocator, io);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool, .idle = &idle };

    const get_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/one" },
        .{ .name = ":authority", .value = "app.example" },
    };
    var wire_buf: [1024]u8 = undefined;
    const wire = try buildClientWire(&wire_buf, &get_headers);

    // The client leg is a fixed reader, so the edge serves the one request
    // and then reads end of stream, and every byte it wrote is on record.
    var client_r = std.Io.Reader.fixed(wire);
    var probe: SegmentProbe = .{ .writer = undefined };
    probe.bind();
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18956);
    var lease = client_lease.Lease.none;
    serveSession(&proxy, &client_r, &probe.writer, addr, null, &lease);

    fake_thread.join();

    // Server SETTINGS, the SETTINGS ack, then the whole response. Four
    // would mean the head went out on its own and the body chased it.
    try testing.expectEqual(@as(usize, 3), probe.segment_count);

    var response = std.Io.Reader.fixed(probe.segment(2));
    var payload_buf: [http2_frames.MAX_PAYLOAD]u8 = undefined;

    const head = try http2_frames.readFrame(&response, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_HEADERS), head.head.frame_type);
    try testing.expectEqual(@as(u31, 1), head.head.stream_id);
    try testing.expectEqual(Http2.FLAG_END_HEADERS, head.head.flags & Http2.FLAG_END_HEADERS);
    try testing.expectEqual(@as(u8, 0), head.head.flags & Http2.FLAG_END_STREAM);

    const data = try http2_frames.readFrame(&response, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_DATA), data.head.frame_type);
    try testing.expectEqual(@as(u31, 1), data.head.stream_id);
    try testing.expectEqual(Http2.FLAG_END_STREAM, data.head.flags & Http2.FLAG_END_STREAM);
    try testing.expectEqualStrings("echo:", data.payload);

    try testing.expectEqual(@as(usize, 0), response.bufferedLen());
}

test "zix zixer: http2 edge, the static head and body leave in one write" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    tmp.dir.writeFile(testing.io, .{ .sub_path = "page.html", .data = "<h1>one write</h1>" }) catch @panic("fixture write failed");

    var root_buf: [128]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    const proxy = http1_proxy.Proxy{ .io = io, .static = .{
        .public_dir = root,
        .public_prefix = null,
        .spa_fallback = null,
    } };

    const get_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/page.html" },
        .{ .name = ":authority", .value = "site.test" },
    };
    var wire_buf: [1024]u8 = undefined;
    const wire = try buildClientWire(&wire_buf, &get_headers);

    var client_r = std.Io.Reader.fixed(wire);
    var probe: SegmentProbe = .{ .writer = undefined };
    probe.bind();
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18957);
    var lease = client_lease.Lease.none;
    serveSession(&proxy, &client_r, &probe.writer, addr, null, &lease);

    try testing.expectEqual(@as(usize, 3), probe.segment_count);

    var response = std.Io.Reader.fixed(probe.segment(2));
    var payload_buf: [http2_frames.MAX_PAYLOAD]u8 = undefined;

    const head = try http2_frames.readFrame(&response, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_HEADERS), head.head.frame_type);
    try testing.expectEqual(@as(u8, 0), head.head.flags & Http2.FLAG_END_STREAM);

    const data = try http2_frames.readFrame(&response, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_DATA), data.head.frame_type);
    try testing.expectEqual(Http2.FLAG_END_STREAM, data.head.flags & Http2.FLAG_END_STREAM);
    try testing.expectEqualStrings("<h1>one write</h1>", data.payload);
}

test "zix zixer: http2 edge, a bodyless answer still leaves on its own" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // No pool and no static plane, so the edge answers 503 locally: a head
    // with nothing behind it must not sit staged waiting for a body.
    const proxy = http1_proxy.Proxy{ .io = io };

    const get_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/gone" },
        .{ .name = ":authority", .value = "app.example" },
    };
    var wire_buf: [1024]u8 = undefined;
    const wire = try buildClientWire(&wire_buf, &get_headers);

    var client_r = std.Io.Reader.fixed(wire);
    var probe: SegmentProbe = .{ .writer = undefined };
    probe.bind();
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18958);
    var lease = client_lease.Lease.none;
    serveSession(&proxy, &client_r, &probe.writer, addr, null, &lease);

    try testing.expectEqual(@as(usize, 3), probe.segment_count);

    var response = std.Io.Reader.fixed(probe.segment(2));
    var payload_buf: [http2_frames.MAX_PAYLOAD]u8 = undefined;

    const head = try http2_frames.readFrame(&response, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_HEADERS), head.head.frame_type);
    try testing.expectEqual(Http2.FLAG_END_STREAM, head.head.flags & Http2.FLAG_END_STREAM);
    try testing.expectEqual(@as(usize, 0), response.bufferedLen());
}

/// Upstream that answers a chunked head, holds, then sends one chunk. The
/// hold is what a live stream looks like between events.
const PausingBackend = struct {
    io: std.Io,
    port: u16,
    pause_ms: u32,
    ready: std.atomic.Value(bool) = .init(false),

    fn serve(fake: *PausingBackend) void {
        const io = fake.io;

        const addr = std.Io.net.IpAddress.parse("127.0.0.1", fake.port) catch return;
        var server = bindWithRetry(io, addr) orelse return;
        defer server.deinit(io);
        fake.ready.store(true, .release);

        const stream = server.accept(io) catch return;
        defer stream.close(io);

        var read_buf: [4096]u8 = undefined;
        var write_buf: [4096]u8 = undefined;
        var reader = stream.reader(io, &read_buf);
        var writer = stream.writer(io, &write_buf);

        var head_buf: [4096]u8 = undefined;
        _ = http1_head.readHead(&reader.interface, &head_buf) catch return;

        writer.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n") catch return;
        writer.interface.flush() catch return;

        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(fake.pause_ms), .awake) catch {};

        writer.interface.writeAll("5\r\nfirst\r\n0\r\n\r\n") catch return;
        writer.interface.flush() catch return;
    }
};

test "zix zixer: http2 edge, a streaming head leaves before its first chunk" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = PausingBackend{ .io = io, .port = 18959, .pause_ms = 150 };
    const fake_thread = try std.Thread.spawn(.{}, PausingBackend.serve, .{&fake});
    var tries: usize = 0;
    while (tries < 100 and !fake.ready.load(.acquire)) : (tries += 1) {
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    try testing.expect(tries < 100);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18959 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    var idle = try upstream_conn.IdleCache.init(testing.allocator, 1);
    defer idle.deinit(testing.allocator, io);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool, .idle = &idle };

    const get_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/events" },
        .{ .name = ":authority", .value = "app.example" },
    };
    var wire_buf: [1024]u8 = undefined;
    const wire = try buildClientWire(&wire_buf, &get_headers);

    var client_r = std.Io.Reader.fixed(wire);
    var probe: SegmentProbe = .{ .writer = undefined };
    probe.bind();
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18959);
    var lease = client_lease.Lease.none;
    serveSession(&proxy, &client_r, &probe.writer, addr, null, &lease);

    fake_thread.join();

    // The head must not have waited on the pause, so it is its own write
    // and the chunk follows in the next one.
    try testing.expect(probe.segment_count >= 4);

    var head_segment = std.Io.Reader.fixed(probe.segment(2));
    var payload_buf: [http2_frames.MAX_PAYLOAD]u8 = undefined;
    const head = try http2_frames.readFrame(&head_segment, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_HEADERS), head.head.frame_type);
    try testing.expectEqual(@as(u8, 0), head.head.flags & Http2.FLAG_END_STREAM);
    try testing.expectEqual(@as(usize, 0), head_segment.bufferedLen());

    var data_segment = std.Io.Reader.fixed(probe.segment(3));
    const data = try http2_frames.readFrame(&data_segment, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_DATA), data.head.frame_type);
    try testing.expectEqualStrings("first", data.payload);
}

test "zix zixer: http2 edge, a cached entry answers after the file leaves disk" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("http2 edge cache test needs the linux socketpair harness", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    tmp.dir.writeFile(testing.io, .{ .sub_path = "page.html", .data = "<h1>cached</h1>" }) catch @panic("fixture write failed");

    var root_buf: [128]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    static_cached.install(60_000, 16);
    defer static_cached.shutdown(testing.io);

    const proxy = http1_proxy.Proxy{
        .io = io,
        .static = .{ .public_dir = root, .public_prefix = null, .spa_fallback = null },
        .public_dir_cache_ttl_ms = 60_000,
    };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    const headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/page.html" },
        .{ .name = ":authority", .value = "site.test" },
    };

    try client.sendHeaders(1, &headers, true);
    const first = try client.readHead(1);
    try testing.expectEqualStrings("200", client.headerValue(first, ":status").?);

    var first_body: [64]u8 = undefined;
    try testing.expectEqualStrings("<h1>cached</h1>", first_body[0..try client.collectBody(1, &first_body)]);

    // The entry holds the descriptor, so unlinking the name cannot reach it.
    tmp.dir.deleteFile(testing.io, "page.html") catch @panic("fixture delete failed");

    try client.sendHeaders(3, &headers, true);
    const second = try client.readHead(3);
    try testing.expectEqualStrings("200", client.headerValue(second, ":status").?);
    try testing.expectEqualStrings("15", client.headerValue(second, "content-length").?);

    var second_body: [64]u8 = undefined;
    try testing.expectEqualStrings("<h1>cached</h1>", second_body[0..try client.collectBody(3, &second_body)]);

    client.stream.close(io);
    edge_thread.join();
}

test "zix zixer: http2 edge, a resident entry frames a body larger than one payload" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("http2 edge cache test needs the linux socketpair harness", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Longer than one DATA payload, so the send loop has to walk the resident
    // bytes by offset rather than hand over one slice.
    var payload: [http2_frames.MAX_PAYLOAD + 500]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast('a' + index % 26);

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    tmp.dir.writeFile(testing.io, .{ .sub_path = "vendor.js", .data = &payload }) catch @panic("fixture write failed");

    var root_buf: [128]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    static_cached.install(60_000, 16);
    defer static_cached.shutdown(testing.io);

    const proxy = http1_proxy.Proxy{
        .io = io,
        .static = .{ .public_dir = root, .public_prefix = null, .spa_fallback = null },
        .public_dir_cache_ttl_ms = 60_000,
    };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    const headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/vendor.js" },
        .{ .name = ":authority", .value = "site.test" },
    };
    try client.sendHeaders(1, &headers, true);

    const count = try client.readHead(1);
    try testing.expectEqualStrings("200", client.headerValue(count, ":status").?);

    var body: [http2_frames.MAX_PAYLOAD + 1024]u8 = undefined;
    const got = try client.collectBody(1, &body);
    try testing.expectEqualSlices(u8, &payload, body[0..got]);

    client.stream.close(io);
    edge_thread.join();
}

// --------------------------------------------------------- //

const deadline_sweep = @import("deadline_sweep.zig");
const deadline_table = @import("deadline_table.zig");

/// One served h2 connection plus a flag its thread sets on the way out, so a
/// test can tell the edge let go instead of waiting on a join that may hang.
const ServeProbe = struct {
    proxy: *const http1_proxy.Proxy,
    stream: std.Io.net.Stream,
    done: std.atomic.Value(bool) = .init(false),

    fn run(probe: *ServeProbe) void {
        serveConn(probe.proxy, probe.stream);
        probe.done.store(true, .release);
    }
};

test "zix zixer: http2 edge, a site at its connection limit goes away at once" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var table = try deadline_table.Table.init(testing.allocator, 1);
    defer table.deinit(testing.allocator);

    const proxy = http1_proxy.Proxy{ .io = io, .client_table = &table, .client_timeout_ms = 60_000 };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const holder = edgeStream(fds[0]);

    // The site's only slot is already spoken for, so the connection under test
    // arrives at a full table.
    try testing.expect(table.claim(holder.socket.handle, deadline_table.NEVER_MS) == .TAKEN);

    var refused_fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&refused_fds);
    var probe = ServeProbe{ .proxy = &proxy, .stream = edgeStream(refused_fds[0]) };
    const thread = try std.Thread.spawn(.{}, ServeProbe.run, .{&probe});
    const client = edgeStream(refused_fds[1]);

    // The answer is h2 even though the client has not said a word: reading the
    // preface first is what a refused connection must never be made to wait
    // for.
    var read_buf: [512]u8 = undefined;
    var reader = client.reader(io, &read_buf);
    var payload_buf: [64]u8 = undefined;

    const settings = try http2_frames.readFrame(&reader.interface, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_SETTINGS), settings.head.frame_type);

    const goaway = try http2_frames.readFrame(&reader.interface, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_GOAWAY), goaway.head.frame_type);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, goaway.payload[0..4], .big));
    try testing.expectEqual(Http2.ERR_ENHANCE_YOUR_CALM, std.mem.readInt(u32, goaway.payload[4..8], .big));

    thread.join();
    try testing.expect(probe.done.load(.acquire));
    client.close(io);
    holder.close(io);
    edgeStream(fds[1]).close(io);

    // The refused connection never took a slot of its own.
    try testing.expectEqual(@as(usize, 1), table.liveCount());
}

test "zix zixer: http2 edge, a quiet connection re-arms per frame and is cut in the end" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var table = try deadline_table.Table.init(testing.allocator, 1);
    defer table.deinit(testing.allocator);

    const proxy = http1_proxy.Proxy{ .io = io, .client_table = &table, .client_timeout_ms = 60_000 };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);

    // Stamped before the connection exists, so the deadline the accept armed
    // is at most a few milliseconds past base plus the budget.
    const base = monotonic_clock.nowMs(io);
    var probe = ServeProbe{ .proxy = &proxy, .stream = edgeStream(fds[0]) };
    const thread = try std.Thread.spawn(.{}, ServeProbe.run, .{&probe});

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    // Far enough after the accept that a connection still carrying the accept
    // deadline reads as past due at the stamp swept below.
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(400), .awake) catch {};

    try client.sendPing();
    const ack = try client.nextFrame();
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_PING), ack.head.frame_type);
    try testing.expectEqual(Http2.FLAG_ACK, ack.head.flags & Http2.FLAG_ACK);

    // The frame the client just sent was read under a budget armed after the
    // sleep, so this stamp is still inside it. A loop that armed once at
    // accept would be cut here instead.
    const early = deadline_sweep.sweepOnce(&table, base + 60_200);
    try testing.expectEqual(@as(usize, 0), early.cut);
    try testing.expectEqual(@as(usize, 0), early.dropped);

    // Past every budget: the client asked for nothing more, which is the shape
    // the bound over a multiplexed connection exists to reach.
    var cut: usize = 0;
    var rounds: usize = 0;
    while (rounds < 500 and !probe.done.load(.acquire)) : (rounds += 1) {
        cut += deadline_sweep.sweepOnce(&table, std.math.maxInt(i64)).cut;
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }

    try testing.expect(probe.done.load(.acquire));
    try testing.expect(cut > 0);

    thread.join();
    client.stream.close(io);

    try testing.expectEqual(@as(usize, 0), table.liveCount());
}

test "zix zixer: http2 edge, a stream in flight is never cut" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = PausingBackend{ .io = io, .port = 18917, .pause_ms = 700 };
    const fake_thread = try std.Thread.spawn(.{}, PausingBackend.serve, .{&fake});
    var tries: usize = 0;
    while (tries < 100 and !fake.ready.load(.acquire)) : (tries += 1) {
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    try testing.expect(tries < 100);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18917 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    var idle = try upstream_conn.IdleCache.init(testing.allocator, 1);
    defer idle.deinit(testing.allocator, io);

    var table = try deadline_table.Table.init(testing.allocator, 1);
    defer table.deinit(testing.allocator);

    // One millisecond of budget, so a connection still alive a moment later is
    // held rather than merely lucky.
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool, .idle = &idle, .client_table = &table, .client_timeout_ms = 1 };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    var probe = ServeProbe{ .proxy = &proxy, .stream = edgeStream(fds[0]) };
    const edge_thread = try std.Thread.spawn(.{}, ServeProbe.run, .{&probe});

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    const get_headers = [_]Http2.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/events" },
        .{ .name = ":authority", .value = "app.example" },
    };
    try client.sendHeaders(1, &get_headers, true);

    // The head arriving means the relay is running and the upstream is inside
    // its pause, which is what a live stream looks like between events.
    const count = try client.readHead(1);
    try testing.expectEqualStrings("200", client.headerValue(count, ":status").?);

    const swept = deadline_sweep.sweepOnce(&table, std.math.maxInt(i64));
    try testing.expectEqual(@as(usize, 0), swept.cut);
    try testing.expectEqual(@as(usize, 0), swept.dropped);
    try testing.expectEqual(@as(usize, 1), table.liveCount());

    // The stream ends on its own terms, and its last chunk still reaches the
    // client the sweep did not cut.
    var body: [64]u8 = undefined;
    const got = try client.collectBody(1, &body);
    try testing.expectEqualStrings("first", body[0..got]);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}
