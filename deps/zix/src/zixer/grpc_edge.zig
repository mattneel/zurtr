//! zixer grpc edge: h2 client streams relayed h2 end-to-end to the pool,
//! multiplexed both ways so grpc trailers survive the hop

const std = @import("std");
const zix = @import("zix");

const cfg_headers = @import("cfg_headers.zig");
const client_lease = @import("client_lease.zig");
const conn_buffer = @import("conn_buffer.zig");
const grpc_relay = @import("grpc_relay.zig");
const grpc_upstream = @import("grpc_upstream.zig");
const http1_proxy = @import("http1_proxy.zig");
const proxy_headers = @import("proxy_headers.zig");
const http2_frames = @import("http2_frames.zig");
const process_wait = @import("process_wait.zig");

const monotonic_clock = zix.utils.monotonic_clock;
const socket_cut_reader = zix.utils.socket_cut_reader;
const socket_cut_writer = zix.utils.socket_cut_writer;

const Http2 = zix.Http2;

/// Concurrent client streams one edge connection relays, advertised as
/// SETTINGS_MAX_CONCURRENT_STREAMS. Overflow answers REFUSED_STREAM, the
/// safe retry signal.
const MAX_STREAMS: usize = 8;

/// Upstream h2 connections one edge connection holds. Streams multiplex
/// onto them, a pick landing on a further distinct upstream reuses an
/// already open connection instead.
const UP_CONN_CAP: usize = 4;

/// Largest header block either direction carries.
const BLOCK_MAX: usize = 16 * 1024;

/// Poll gap while a relay waits for send-window credit. Credit only moves
/// when the receiving peer grants it, so the wait is peer-paced anyway.
const WINDOW_POLL_MS: i64 = 1;

/// Result of handling one client frame.
const ProcessResult = enum {
    OK,
    CLOSED,
};

/// One relayed stream: the client id, its route, and both send windows.
/// All fields are guarded by the session state lock.
const StreamEntry = struct {
    active: bool = false,
    client_id: u31 = 0,
    up_index: usize = 0,
    up_id: u31 = 0,
    /// The response head crossed already: the next HEADERS is trailers.
    saw_head: bool = false,
    /// The client half closed (END_STREAM seen), late client frames on
    /// the stream are a protocol fault.
    client_done: bool = false,
    /// Our send credit toward the client on this stream.
    client_window: i64 = 0,
    /// Our send credit toward the upstream on this stream.
    up_window: i64 = 0,
    /// The authority this stream named, for the $host token. Streams run
    /// concurrently here, so it is kept per stream rather than per session.
    authority_len: usize = 0,
    authority: [AUTHORITY_MAX]u8 = undefined,

    /// The authority this stream named, empty when it named none.
    fn authorityText(entry: *const StreamEntry) []const u8 {
        return entry.authority[0..entry.authority_len];
    }
};

/// Longest authority a stream carries into the $host token: a hostname at its
/// rfc 1035 ceiling plus a port.
const AUTHORITY_MAX: usize = 264;

/// The site's answer headers with one stream's token values filled in.
///
/// Param:
/// host - []const u8 (the stream's authority, empty when none is known)
///
/// Return:
/// - cfg_headers.Block, empty when the site configured no section
fn clientBlock(session: *const Session, host: []const u8) cfg_headers.Block {
    return .{
        .table = session.proxy.response_headers,
        .values = .{
            .client_ip = session.client_ip[0..session.client_ip_len],
            .scheme = session.proxy.client_scheme.token(),
            .host = host,
        },
    };
}

/// The same, for the leg out to the upstream.
fn upstreamBlock(session: *const Session, host: []const u8) cfg_headers.Block {
    return .{
        .table = session.proxy.request_headers,
        .values = .{
            .client_ip = session.client_ip[0..session.client_ip_len],
            .scheme = session.proxy.client_scheme.token(),
            .host = host,
        },
    };
}

/// One grpc edge connection: the client frame loop (up pump) plus one
/// down pump per upstream connection, sharing the stream table.
///
/// Note:
/// - state_lock guards the table, every window, and the upstream conn
///   bookkeeping. Critical sections stay short and never touch a socket.
/// - write_lock serializes all client-bound frames (both pumps write).
/// - A stalled peer window head-of-line blocks the pump that serves it,
///   the price of the buffer-free relay.
const Session = struct {
    proxy: *const http1_proxy.Proxy,
    io: std.Io,
    client_r: *std.Io.Reader,
    client_w: *std.Io.Writer,
    client_addr: std.Io.net.IpAddress,
    client_stream: ?std.Io.net.Stream,
    /// This connection's slot in the site's client bound, taken by whoever
    /// accepted it.
    lease: *client_lease.Lease,
    decoder: Http2.HpackDecoder,
    write_lock: std.atomic.Value(bool) = .init(false),
    state_lock: std.atomic.Value(bool) = .init(false),
    entries: [MAX_STREAMS]StreamEntry = @splat(.{}),
    saw_settings: bool = false,
    goaway_received: bool = false,
    goaway_sent: bool = false,
    stopping: bool = false,
    highest_stream: u31 = 0,
    client_conn_window: i64 = Http2.DEFAULT_INITIAL_WINDOW,
    client_initial_window: i64 = Http2.DEFAULT_INITIAL_WINDOW,
    client_max_frame: u32 = Http2.DEFAULT_MAX_FRAME_SIZE,
    /// The peer address as the $client_ip token writes it, formatted once
    /// because it never changes over the connection.
    client_ip_len: usize = 0,
    client_ip: [proxy_headers.CLIENT_IP_MAX]u8 = undefined,
    up_conns: [UP_CONN_CAP]grpc_upstream.UpConn = undefined,
    up_used: [UP_CONN_CAP]bool = @splat(false),
    up_done: [UP_CONN_CAP]std.atomic.Value(bool) = @splat(.init(false)),
    up_cursor: usize = 0,
    pumps: std.Io.Group = .init,
    payload_buf: [http2_frames.MAX_PAYLOAD]u8 = undefined,
    block_buf: [BLOCK_MAX]u8 = undefined,
    out_block_buf: [BLOCK_MAX]u8 = undefined,
    decoded: [Http2.MAX_HEADERS]Http2.Header = undefined,
    decode_scratch: [BLOCK_MAX]u8 = undefined,
};

/// Serve one accepted cleartext connection of a grpc site. grpc clients
/// speak h2 with prior knowledge, so the preface is required: anything
/// else closes without an answer (no h1 fallback on a grpc site).
///
/// Note:
/// - The site's client bound is taken before anything is read, so a refused
///   connection never parks a thread waiting for a preface. Every client here
///   speaks h2, so the refusal is an h2 one.
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

    serveSession(proxy, &client_reader.interface, &client_writer.interface, client_stream.socket.address, client_stream, &lease);
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

/// The grpc relay loop over reader / writer interfaces (plain stream or a
/// terminated TLS session).
///
/// Note:
/// - Every stream relays h2 end-to-end: the response trailer block a grpc
///   status rides in reaches the client intact, which an h1 hop loses.
/// - The pick is per client stream, streams multiplex onto the open
///   upstream connections.
/// - An upstream END_STREAM finishes the relay entry: late client DATA
///   for that stream drops with its credit refunded (a grpc client stops
///   sending once the status arrives).
/// - lease is the connection's slot in the site's client bound, already taken
///   by whoever accepted the connection. A caller with no bound to enforce
///   passes a lease over nothing.
pub fn serveSession(proxy: *const http1_proxy.Proxy, client_r: *std.Io.Reader, client_w: *std.Io.Writer, client_addr: std.Io.net.IpAddress, client_stream: ?std.Io.net.Stream, lease: *client_lease.Lease) void {
    var preface: [Http2.PREFACE.len]u8 = undefined;
    client_r.readSliceAll(&preface) catch return;
    if (!std.mem.eql(u8, &preface, Http2.PREFACE)) return;

    http2_frames.writeSettings(client_w, &.{
        .{ Http2.SETTINGS_MAX_CONCURRENT_STREAMS, MAX_STREAMS },
    }) catch return;
    client_w.flush() catch return;

    var session = Session{
        .proxy = proxy,
        .io = proxy.io,
        .client_r = client_r,
        .client_w = client_w,
        .client_addr = client_addr,
        .client_stream = client_stream,
        .lease = lease,
        .decoder = Http2.HpackDecoder.init(),
    };
    session.client_ip_len = proxy_headers.clientIp(&session.client_ip, client_addr).len;

    mainLoop(&session);

    // Teardown: stop the pumps, unblock their reads, join, then close.
    lockState(&session);
    session.stopping = true;
    unlockState(&session);

    for (session.up_used, 0..) |used, index| {
        if (used) session.up_conns[index].stream.shutdown(session.io, .both) catch {};
    }
    session.pumps.cancel(session.io);

    for (session.up_used, 0..) |used, index| {
        if (used) grpc_upstream.close(&session.up_conns[index], session.io, session.proxy.allocator);
    }
}

fn mainLoop(session: *Session) void {
    while (true) {
        maybeCloseAfterDrain(session);
        boundWhenQuiet(session);

        if (processFrame(session) == .CLOSED) return;
    }
}

/// Put the client bound back over the connection while it relays nothing, and
/// take it off while it does.
///
/// Note:
/// - An RPC stays open for as long as its own exchange runs, and a server
///   -streaming one is silent between messages by design, so one client budget
///   here can only mean the wait between RPCs. A connection opened and then
///   left idle is exactly what it reaches.
/// - The slot stays taken either way, so a held connection still counts
///   against the site's connection limit.
fn boundWhenQuiet(session: *Session) void {
    lockState(session);
    const relaying = activeCountLocked(session) != 0;
    unlockState(session);

    if (relaying) session.lease.holdStream() else session.lease.armRequest();
}

/// After the client's GOAWAY, once no stream is active: answer GOAWAY and
/// unblock the client frame read. Both pumps call this, goaway_sent keeps
/// it single-shot.
fn maybeCloseAfterDrain(session: *Session) void {
    lockState(session);
    const should = session.goaway_received and !session.goaway_sent and !session.stopping and activeCountLocked(session) == 0;
    if (should) session.goaway_sent = true;
    const highest = session.highest_stream;
    unlockState(session);

    if (!should) return;

    lockClient(session);
    http2_frames.writeGoaway(session.client_w, highest, Http2.ERR_NO_ERROR) catch {};
    session.client_w.flush() catch {};
    unlockClient(session);

    if (session.client_stream) |stream| stream.shutdown(session.io, .recv) catch {};
}

// --------------------------------------------------------- //
// client frames (up pump)

fn processFrame(session: *Session) ProcessResult {
    const frame = http2_frames.readFrame(session.client_r, &session.payload_buf) catch |err| {
        if (err == error.ZixerFrameTooLarge) return connError(session, Http2.ERR_FRAME_SIZE_ERROR);

        return .CLOSED;
    };

    // rfc 9113 3.4: the client preface ends with a SETTINGS frame.
    if (!session.saw_settings and frame.head.frame_type != Http2.FRAME_TYPE_SETTINGS) {
        return connError(session, Http2.ERR_PROTOCOL_ERROR);
    }

    switch (frame.head.frame_type) {
        Http2.FRAME_TYPE_DATA => return processClientData(session, &frame),
        Http2.FRAME_TYPE_HEADERS => return processClientHeaders(session, &frame),
        Http2.FRAME_TYPE_PRIORITY => return .OK,
        Http2.FRAME_TYPE_RST_STREAM => return processClientRst(session, &frame),
        Http2.FRAME_TYPE_SETTINGS => return processClientSettings(session, &frame),
        Http2.FRAME_TYPE_PUSH_PROMISE => return connError(session, Http2.ERR_PROTOCOL_ERROR),
        Http2.FRAME_TYPE_PING => {
            if ((frame.head.flags & Http2.FLAG_ACK) != 0) return .OK;
            if (frame.payload.len != 8) return connError(session, Http2.ERR_FRAME_SIZE_ERROR);

            lockClient(session);
            defer unlockClient(session);
            http2_frames.writePingAck(session.client_w, frame.payload) catch return .CLOSED;
            session.client_w.flush() catch return .CLOSED;

            return .OK;
        },
        Http2.FRAME_TYPE_GOAWAY => {
            lockState(session);
            session.goaway_received = true;
            unlockState(session);

            return .OK;
        },
        Http2.FRAME_TYPE_WINDOW_UPDATE => return processClientWindowUpdate(session, &frame),
        Http2.FRAME_TYPE_CONTINUATION => return connError(session, Http2.ERR_PROTOCOL_ERROR),
        else => return .OK,
    }
}

fn processClientHeaders(session: *Session, first: *const http2_frames.Frame) ProcessResult {
    const id = first.head.stream_id;
    if (id == 0 or id % 2 == 0) return connError(session, Http2.ERR_PROTOCOL_ERROR);

    const fragment = http2_frames.headersFragment(first) catch return connError(session, Http2.ERR_PROTOCOL_ERROR);
    if (fragment.len > session.block_buf.len) return connError(session, Http2.ERR_ENHANCE_YOUR_CALM);
    @memcpy(session.block_buf[0..fragment.len], fragment);
    var block_len: usize = fragment.len;
    const end_stream = (first.head.flags & Http2.FLAG_END_STREAM) != 0;

    // CONTINUATION frames extend the block until END_HEADERS. A block the
    // buffer cannot hold kills the connection: skipping it would desync
    // the shared hpack state.
    var end_headers = (first.head.flags & Http2.FLAG_END_HEADERS) != 0;
    while (!end_headers) {
        const next = http2_frames.readFrame(session.client_r, &session.payload_buf) catch return .CLOSED;
        if (next.head.frame_type != Http2.FRAME_TYPE_CONTINUATION or next.head.stream_id != id) {
            return connError(session, Http2.ERR_PROTOCOL_ERROR);
        }
        if (block_len + next.payload.len > session.block_buf.len) return connError(session, Http2.ERR_ENHANCE_YOUR_CALM);

        @memcpy(session.block_buf[block_len..][0..next.payload.len], next.payload);
        block_len += next.payload.len;
        end_headers = (next.head.flags & Http2.FLAG_END_HEADERS) != 0;
    }

    const count = session.decoder.decode(session.block_buf[0..block_len], &session.decoded, &session.decode_scratch) catch {
        return connError(session, Http2.ERR_COMPRESSION_ERROR);
    };
    const headers = session.decoded[0..count];

    // A second HEADERS on a known stream is the request trailer block,
    // relayed as-is: the h2 upstream leg has a place for it.
    lockState(session);
    const known = findEntryByClientLocked(session, id);
    const route: ?struct { up_index: usize, up_id: u31, done: bool } = if (known) |entry|
        .{ .up_index = entry.up_index, .up_id = entry.up_id, .done = entry.client_done }
    else
        null;
    unlockState(session);

    if (route) |target| {
        if (!end_stream or target.done) return connError(session, Http2.ERR_PROTOCOL_ERROR);

        return relayRequestTrailers(session, id, target.up_index, target.up_id, headers);
    }

    lockState(session);
    const reused_id = id <= session.highest_stream;
    if (!reused_id) session.highest_stream = id;
    unlockState(session);

    if (reused_id) return connError(session, Http2.ERR_PROTOCOL_ERROR);

    return acceptStream(session, id, headers, end_stream);
}

fn relayRequestTrailers(session: *Session, id: u31, up_index: usize, up_id: u31, headers: []const Http2.Header) ProcessResult {
    const up_conn = &session.up_conns[up_index];

    var trailer_buf: [BLOCK_MAX]u8 = undefined;
    const block = grpc_relay.encodeTrailerBlock(&trailer_buf, headers) catch {
        clearEntryByClient(session, id);
        grpc_upstream.writeRst(up_conn, up_id, Http2.ERR_PROTOCOL_ERROR) catch {};

        return streamError(session, id, Http2.ERR_PROTOCOL_ERROR);
    };

    lockState(session);
    if (findEntryByClientLocked(session, id)) |entry| entry.client_done = true;
    const max_frame = upstreamMaxFrameLocked(up_conn);
    unlockState(session);

    grpc_upstream.writeHeaders(up_conn, up_id, block, true, max_frame) catch {
        failUpstreamWrite(session, up_index, id);
    };

    return .OK;
}

/// A new client stream: validate, pick an upstream, claim a table entry,
/// and put the request block on the upstream wire.
fn acceptStream(session: *Session, id: u31, headers: []const Http2.Header, end_stream: bool) ProcessResult {
    const info = grpc_relay.validateRequest(headers) catch {
        return streamError(session, id, Http2.ERR_PROTOCOL_ERROR);
    };

    lockState(session);
    const refused = session.goaway_received;
    const slot: ?*StreamEntry = if (refused) null else findFreeEntryLocked(session);
    unlockState(session);

    if (slot == null) return streamError(session, id, Http2.ERR_REFUSED_STREAM);
    const entry = slot.?;

    // The gate sheds here instead of parking: this runs on the frame loop
    // that pumps every live stream on the connection, so waiting would
    // stall streams already admitted. A trailers-only UNAVAILABLE is what
    // a grpc client retries on.
    if (process_wait.admitNow(session.proxy.process_gate) != .ADMITTED) {
        var busy_buf: [256]u8 = undefined;
        const busy_block = grpc_relay.encodeUnavailableBlock(&busy_buf, clientBlock(session, "")) catch return .OK;

        return writeBlockToClient(session, id, busy_block, true);
    }

    // Released once the request block is on the upstream wire. A grpc
    // stream lives as long as its client, so holding the slot for the whole
    // exchange would let a few long calls pin the site's capacity.
    var stream_slot = process_wait.hold(session.proxy.process_gate);
    defer stream_slot.release();

    const up_index = findOrOpenUpstream(session) orelse {
        var local_buf: [256]u8 = undefined;
        const block = grpc_relay.encodeUnavailableBlock(&local_buf, clientBlock(session, info.authority)) catch return .OK;

        return writeBlockToClient(session, id, block, true);
    };
    const up_conn = &session.up_conns[up_index];

    const block = grpc_relay.encodeRequestBlock(&session.out_block_buf, headers, &info, session.client_addr, session.proxy.client_scheme, upstreamBlock(session, info.authority)) catch {
        return streamError(session, id, Http2.ERR_INTERNAL_ERROR);
    };

    lockState(session);
    const up_id = grpc_upstream.allocStreamId(up_conn);
    entry.* = .{
        .active = true,
        .client_id = id,
        .up_index = up_index,
        .up_id = up_id,
        .client_done = end_stream,
        .client_window = session.client_initial_window,
        .up_window = up_conn.initial_window,
        .authority_len = @min(info.authority.len, AUTHORITY_MAX),
    };
    @memcpy(entry.authority[0..entry.authority_len], info.authority[0..entry.authority_len]);
    const max_frame = upstreamMaxFrameLocked(up_conn);
    unlockState(session);

    grpc_upstream.writeHeaders(up_conn, up_id, block, end_stream, max_frame) catch {
        lockState(session);
        up_conn.alive = false;
        entry.active = false;
        unlockState(session);

        return streamError(session, id, Http2.ERR_REFUSED_STREAM);
    };

    return .OK;
}

fn processClientData(session: *Session, frame: *const http2_frames.Frame) ProcessResult {
    const id = frame.head.stream_id;
    if (id == 0) return connError(session, Http2.ERR_PROTOCOL_ERROR);
    const data = http2_frames.dataPayload(frame) catch return connError(session, Http2.ERR_PROTOCOL_ERROR);
    const end_stream = (frame.head.flags & Http2.FLAG_END_STREAM) != 0;

    lockState(session);
    const found = findEntryByClientLocked(session, id);
    const route: ?struct { up_index: usize, up_id: u31 } = if (found) |entry| blk: {
        if (entry.client_done) break :blk null;

        break :blk .{ .up_index = entry.up_index, .up_id = entry.up_id };
    } else null;
    unlockState(session);

    const target = route orelse {
        // Unclaimed DATA (a refused, reset, or finished stream): dropped,
        // the connection credit goes straight back so the client never
        // stalls.
        if (frame.head.length > 0) {
            lockClient(session);
            defer unlockClient(session);
            http2_frames.writeWindowUpdate(session.client_w, 0, @intCast(frame.head.length)) catch return .CLOSED;
            session.client_w.flush() catch return .CLOSED;
        }

        return .OK;
    };

    forwardDataToUpstream(session, target.up_index, target.up_id, id, data, end_stream);

    if (end_stream) {
        lockState(session);
        if (findEntryByClientLocked(session, id)) |entry| entry.client_done = true;
        unlockState(session);
    }

    // The relay holds nothing, so the credit goes back per frame.
    if (frame.head.length > 0) {
        lockClient(session);
        defer unlockClient(session);
        http2_frames.writeWindowUpdate(session.client_w, 0, @intCast(frame.head.length)) catch return .CLOSED;
        http2_frames.writeWindowUpdate(session.client_w, id, @intCast(frame.head.length)) catch return .CLOSED;
        session.client_w.flush() catch return .CLOSED;
    }

    return .OK;
}

/// Push one client DATA payload to the upstream inside its send windows.
/// A vanished entry or dead upstream drops the rest silently: the stream
/// was already reset by the other pump.
fn forwardDataToUpstream(session: *Session, up_index: usize, up_id: u31, client_id: u31, data: []const u8, end_stream: bool) void {
    const up_conn = &session.up_conns[up_index];

    if (data.len == 0) {
        if (end_stream) grpc_upstream.writeData(up_conn, up_id, "", true) catch failUpstreamWrite(session, up_index, client_id);

        return;
    }

    var offset: usize = 0;
    while (offset < data.len) {
        lockState(session);
        const entry = findEntryByUpLocked(session, up_index, up_id);
        const gone = entry == null or !up_conn.alive;
        const window: i64 = if (entry) |found| @min(up_conn.send_window, found.up_window) else 0;
        const max_frame = upstreamMaxFrameLocked(up_conn);
        const stopping = session.stopping;
        unlockState(session);

        if (gone or stopping) return;
        if (window <= 0) {
            std.Io.sleep(session.io, std.Io.Duration.fromMilliseconds(WINDOW_POLL_MS), .awake) catch {};
            continue;
        }

        const usable: usize = @intCast(@min(window, 0x7FFF_FFFF));
        const take: usize = @min(data.len - offset, @min(usable, max_frame));
        const last = offset + take == data.len;

        grpc_upstream.writeData(up_conn, up_id, data[offset..][0..take], end_stream and last) catch {
            failUpstreamWrite(session, up_index, client_id);
            return;
        };

        lockState(session);
        up_conn.send_window -= @intCast(take);
        if (findEntryByUpLocked(session, up_index, up_id)) |spent| spent.up_window -= @intCast(take);
        unlockState(session);

        offset += take;
    }
}

fn processClientRst(session: *Session, frame: *const http2_frames.Frame) ProcessResult {
    if (frame.payload.len != 4) return connError(session, Http2.ERR_FRAME_SIZE_ERROR);
    if (frame.head.stream_id == 0) return connError(session, Http2.ERR_PROTOCOL_ERROR);

    const code = std.mem.readInt(u32, frame.payload[0..4], .big);

    lockState(session);
    const found = findEntryByClientLocked(session, frame.head.stream_id);
    const route: ?struct { up_index: usize, up_id: u31 } = if (found) |entry| blk: {
        entry.active = false;

        break :blk .{ .up_index = entry.up_index, .up_id = entry.up_id };
    } else null;
    unlockState(session);

    if (route) |target| {
        grpc_upstream.writeRst(&session.up_conns[target.up_index], target.up_id, code) catch {};
    }

    return .OK;
}

fn processClientSettings(session: *Session, frame: *const http2_frames.Frame) ProcessResult {
    if ((frame.head.flags & Http2.FLAG_ACK) != 0) return .OK;
    if (frame.payload.len % 6 != 0) return connError(session, Http2.ERR_FRAME_SIZE_ERROR);

    var params = http2_frames.SettingsIterator.init(frame.payload);
    while (params.next()) |param| {
        switch (param[0]) {
            Http2.SETTINGS_INITIAL_WINDOW_SIZE => {
                if (param[1] > 0x7FFF_FFFF) return connError(session, Http2.ERR_FLOW_CONTROL_ERROR);

                // rfc 9113 6.9.2: the delta applies to every open stream.
                lockState(session);
                const delta = @as(i64, param[1]) - session.client_initial_window;
                session.client_initial_window = param[1];
                for (&session.entries) |*entry| {
                    if (entry.active) entry.client_window += delta;
                }
                unlockState(session);
            },
            Http2.SETTINGS_MAX_FRAME_SIZE => {
                if (param[1] < Http2.DEFAULT_MAX_FRAME_SIZE or param[1] > 0xFF_FFFF) {
                    return connError(session, Http2.ERR_PROTOCOL_ERROR);
                }

                lockState(session);
                session.client_max_frame = param[1];
                unlockState(session);
            },
            Http2.SETTINGS_ENABLE_PUSH => {
                if (param[1] > 1) return connError(session, Http2.ERR_PROTOCOL_ERROR);
            },
            else => {},
        }
    }
    session.saw_settings = true;

    lockClient(session);
    defer unlockClient(session);
    http2_frames.writeSettingsAck(session.client_w) catch return .CLOSED;
    session.client_w.flush() catch return .CLOSED;

    return .OK;
}

fn processClientWindowUpdate(session: *Session, frame: *const http2_frames.Frame) ProcessResult {
    const increment = http2_frames.windowIncrement(frame.payload) catch {
        return connError(session, Http2.ERR_FRAME_SIZE_ERROR);
    };

    if (frame.head.stream_id == 0) {
        if (increment == 0) return connError(session, Http2.ERR_PROTOCOL_ERROR);

        lockState(session);
        session.client_conn_window += increment;
        const overflow = session.client_conn_window > 0x7FFF_FFFF;
        unlockState(session);

        if (overflow) return connError(session, Http2.ERR_FLOW_CONTROL_ERROR);

        return .OK;
    }

    if (increment == 0) return streamError(session, frame.head.stream_id, Http2.ERR_PROTOCOL_ERROR);

    lockState(session);
    if (findEntryByClientLocked(session, frame.head.stream_id)) |entry| entry.client_window += increment;
    unlockState(session);

    return .OK;
}

// --------------------------------------------------------- //
// the upstream pick

/// Route one new stream: an already open upstream conn for the picked
/// slot wins, else a fresh conn in a free lifetime slot, else any open
/// conn. Connect failures mark the slot down and re-pick, bounded.
fn findOrOpenUpstream(session: *Session) ?usize {
    const pool = session.proxy.pool orelse return null;
    const io = session.io;

    var attempts: usize = pool.slots.len + 1;
    while (attempts > 0) : (attempts -= 1) {
        const picked = pool.pick(monotonic_clock.nowMs(io)) orelse return anyOpenUpstream(session);

        lockState(session);
        var existing: ?usize = null;
        for (0..UP_CONN_CAP) |index| {
            if (session.up_used[index] and session.up_conns[index].alive and session.up_conns[index].slot_index == picked.index) {
                existing = index;
                break;
            }
        }
        const free_index = findFreeUpSlotLocked(session);
        unlockState(session);

        if (existing) |index| return index;
        const open_index = free_index orelse return anyOpenUpstream(session);

        grpc_upstream.openInto(&session.up_conns[open_index], io, session.proxy.allocator, session.proxy.stream_buf_bytes, picked.host, picked.port, picked.index, session.proxy.upstream_connect_timeout_ms) catch {
            pool.markDown(picked.index, monotonic_clock.nowMs(io));
            continue;
        };

        lockState(session);
        session.up_used[open_index] = true;
        session.up_done[open_index].store(false, .release);
        unlockState(session);

        session.pumps.concurrent(io, downPumpTask, .{ session, open_index }) catch {
            grpc_upstream.close(&session.up_conns[open_index], io, session.proxy.allocator);
            lockState(session);
            session.up_conns[open_index].alive = false;
            unlockState(session);
            session.up_done[open_index].store(true, .release);
            continue;
        };

        return open_index;
    }

    return null;
}

/// Round-robin over the open upstream conns, for when the picked slot
/// cannot get its own connection.
fn anyOpenUpstream(session: *Session) ?usize {
    lockState(session);
    defer unlockState(session);

    for (0..UP_CONN_CAP) |scanned| {
        const index = (session.up_cursor + scanned) % UP_CONN_CAP;
        if (session.up_used[index] and session.up_conns[index].alive) {
            session.up_cursor = index + 1;

            return index;
        }
    }

    return null;
}

/// A lifetime slot for a fresh upstream conn: never used, or used by a
/// conn whose pump already finished.
fn findFreeUpSlotLocked(session: *Session) ?usize {
    for (0..UP_CONN_CAP) |index| {
        if (!session.up_used[index]) return index;
    }
    for (0..UP_CONN_CAP) |index| {
        if (session.up_done[index].load(.acquire) and !session.up_conns[index].alive) return index;
    }

    return null;
}

/// An upstream write failed mid-relay: the conn is gone, reset the client
/// stream so the client retries elsewhere.
fn failUpstreamWrite(session: *Session, up_index: usize, client_id: u31) void {
    lockState(session);
    session.up_conns[up_index].alive = false;
    if (findEntryByClientLocked(session, client_id)) |entry| entry.active = false;
    unlockState(session);

    _ = streamError(session, client_id, Http2.ERR_REFUSED_STREAM);
}

// --------------------------------------------------------- //
// upstream frames (down pump, one per upstream conn)

fn downPumpTask(session: *Session, up_index: usize) void {
    downPump(session, up_index);
    session.up_done[up_index].store(true, .release);
}

fn downPump(session: *Session, up_index: usize) void {
    const up_conn = &session.up_conns[up_index];

    var decoder = Http2.HpackDecoder.init();
    var payload_buf: [http2_frames.MAX_PAYLOAD]u8 = undefined;
    var block_buf: [BLOCK_MAX]u8 = undefined;
    var out_block_buf: [BLOCK_MAX]u8 = undefined;
    var decoded: [Http2.MAX_HEADERS]Http2.Header = undefined;
    var decode_scratch: [BLOCK_MAX]u8 = undefined;

    while (true) {
        const frame = http2_frames.readFrame(&up_conn.reader.interface, &payload_buf) catch break;

        switch (frame.head.frame_type) {
            Http2.FRAME_TYPE_DATA => {
                if (!relayUpstreamData(session, up_index, &frame)) break;
            },
            Http2.FRAME_TYPE_HEADERS => {
                if (!relayUpstreamHeaders(session, up_index, &frame, &decoder, &block_buf, &out_block_buf, &decoded, &decode_scratch, &payload_buf)) break;
            },
            Http2.FRAME_TYPE_RST_STREAM => {
                if (frame.payload.len != 4) break;

                const code = std.mem.readInt(u32, frame.payload[0..4], .big);
                relayUpstreamRst(session, up_index, frame.head.stream_id, code);
            },
            Http2.FRAME_TYPE_SETTINGS => {
                if ((frame.head.flags & Http2.FLAG_ACK) != 0) continue;

                applyUpstreamSettings(session, up_conn, &frame);
                grpc_upstream.writeSettingsAck(up_conn) catch break;
            },
            Http2.FRAME_TYPE_PING => {
                if ((frame.head.flags & Http2.FLAG_ACK) != 0) continue;
                if (frame.payload.len != 8) break;

                grpc_upstream.writePingAck(up_conn, frame.payload) catch break;
            },
            Http2.FRAME_TYPE_WINDOW_UPDATE => {
                const increment = http2_frames.windowIncrement(frame.payload) catch break;

                lockState(session);
                if (frame.head.stream_id == 0) {
                    up_conn.send_window += increment;
                } else if (findEntryByUpLocked(session, up_index, frame.head.stream_id)) |entry| {
                    entry.up_window += increment;
                }
                unlockState(session);
            },
            Http2.FRAME_TYPE_GOAWAY => {
                // No new streams route here, the running ones finish.
                lockState(session);
                up_conn.alive = false;
                unlockState(session);
            },
            else => {},
        }
    }

    markUpstreamDead(session, up_index);
}

fn applyUpstreamSettings(session: *Session, up_conn: *grpc_upstream.UpConn, frame: *const http2_frames.Frame) void {
    var params = http2_frames.SettingsIterator.init(frame.payload);
    while (params.next()) |param| {
        switch (param[0]) {
            Http2.SETTINGS_INITIAL_WINDOW_SIZE => {
                if (param[1] > 0x7FFF_FFFF) continue;

                lockState(session);
                const delta = @as(i64, param[1]) - up_conn.initial_window;
                up_conn.initial_window = param[1];
                for (&session.entries) |*entry| {
                    if (entry.active and &session.up_conns[entry.up_index] == up_conn) entry.up_window += delta;
                }
                unlockState(session);
            },
            Http2.SETTINGS_MAX_FRAME_SIZE => {
                if (param[1] < Http2.DEFAULT_MAX_FRAME_SIZE or param[1] > 0xFF_FFFF) continue;

                lockState(session);
                up_conn.max_frame = param[1];
                unlockState(session);
            },
            else => {},
        }
    }
}

/// Relay one upstream header block: the response head gets via appended,
/// a later block is the trailer block that must survive. False ends the
/// pump (the client side is gone).
fn relayUpstreamHeaders(session: *Session, up_index: usize, first: *const http2_frames.Frame, decoder: *Http2.HpackDecoder, block_buf: []u8, out_block_buf: []u8, decoded: []Http2.Header, decode_scratch: []u8, payload_buf: []u8) bool {
    const up_conn = &session.up_conns[up_index];
    const up_id = first.head.stream_id;

    const fragment = http2_frames.headersFragment(first) catch return false;
    if (fragment.len > block_buf.len) return false;
    @memcpy(block_buf[0..fragment.len], fragment);
    var block_len: usize = fragment.len;
    const end_stream = (first.head.flags & Http2.FLAG_END_STREAM) != 0;

    var end_headers = (first.head.flags & Http2.FLAG_END_HEADERS) != 0;
    while (!end_headers) {
        const next = http2_frames.readFrame(&up_conn.reader.interface, payload_buf) catch return false;
        if (next.head.frame_type != Http2.FRAME_TYPE_CONTINUATION or next.head.stream_id != up_id) return false;
        if (block_len + next.payload.len > block_buf.len) return false;

        @memcpy(block_buf[block_len..][0..next.payload.len], next.payload);
        block_len += next.payload.len;
        end_headers = (next.head.flags & Http2.FLAG_END_HEADERS) != 0;
    }

    const count = decoder.decode(block_buf[0..block_len], decoded, decode_scratch) catch return false;
    const headers = decoded[0..count];

    // The authority is copied out under the same lock as the rest of the
    // snapshot: the entry can be cleared the moment the lock is dropped.
    var host_buf: [AUTHORITY_MAX]u8 = undefined;

    lockState(session);
    const found = findEntryByUpLocked(session, up_index, up_id);
    const route: ?struct { client_id: u31, saw_head: bool, host_len: usize } = if (found) |entry| taken: {
        @memcpy(host_buf[0..entry.authority_len], entry.authority[0..entry.authority_len]);

        break :taken .{ .client_id = entry.client_id, .saw_head = entry.saw_head, .host_len = entry.authority_len };
    } else null;
    unlockState(session);

    // Decoded for hpack sync, but nobody claims it: the stream was reset.
    const target = route orelse return true;

    if (!target.saw_head) {
        const block = grpc_relay.encodeResponseBlock(out_block_buf, headers, clientBlock(session, host_buf[0..target.host_len])) catch {
            clearEntryByUp(session, up_index, up_id);
            grpc_upstream.writeRst(up_conn, up_id, Http2.ERR_PROTOCOL_ERROR) catch {};
            _ = streamError(session, target.client_id, Http2.ERR_PROTOCOL_ERROR);

            return true;
        };

        if (writeBlockToClient(session, target.client_id, block, end_stream) == .CLOSED) return false;

        if (end_stream) {
            clearEntryByUp(session, up_index, up_id);
            maybeCloseAfterDrain(session);
        } else {
            lockState(session);
            if (findEntryByUpLocked(session, up_index, up_id)) |entry| entry.saw_head = true;
            unlockState(session);
        }

        return true;
    }

    // rfc 9113 8.1: a trailer block ends the stream, anything else from
    // the upstream is broken framing.
    if (!end_stream) {
        clearEntryByUp(session, up_index, up_id);
        grpc_upstream.writeRst(up_conn, up_id, Http2.ERR_PROTOCOL_ERROR) catch {};
        _ = streamError(session, target.client_id, Http2.ERR_PROTOCOL_ERROR);

        return true;
    }

    const block = grpc_relay.encodeTrailerBlock(out_block_buf, headers) catch {
        clearEntryByUp(session, up_index, up_id);
        _ = streamError(session, target.client_id, Http2.ERR_PROTOCOL_ERROR);

        return true;
    };

    if (writeBlockToClient(session, target.client_id, block, true) == .CLOSED) return false;

    clearEntryByUp(session, up_index, up_id);
    maybeCloseAfterDrain(session);

    return true;
}

/// Relay one upstream DATA frame inside the client's send windows. False
/// ends the pump (the client side is gone).
fn relayUpstreamData(session: *Session, up_index: usize, frame: *const http2_frames.Frame) bool {
    const up_conn = &session.up_conns[up_index];
    const up_id = frame.head.stream_id;
    if (up_id == 0) return false;
    const data = http2_frames.dataPayload(frame) catch return false;
    const end_stream = (frame.head.flags & Http2.FLAG_END_STREAM) != 0;

    lockState(session);
    const claimed = findEntryByUpLocked(session, up_index, up_id);
    const client_id: ?u31 = if (claimed) |entry| entry.client_id else null;
    unlockState(session);

    const target = client_id orelse {
        // Reset stream: drop the payload, refund the upstream credit.
        grpc_upstream.writeConnGrant(up_conn, frame.head.length) catch return false;

        return true;
    };

    var offset: usize = 0;
    var delivered = true;
    while (offset < data.len) {
        lockState(session);
        const entry = findEntryByUpLocked(session, up_index, up_id);
        const gone = entry == null;
        const window: i64 = if (entry) |found| @min(session.client_conn_window, found.client_window) else 0;
        const max_frame: usize = @min(session.client_max_frame, http2_frames.MAX_PAYLOAD);
        const stopping = session.stopping;
        unlockState(session);

        if (stopping) return false;
        if (gone) {
            delivered = false;
            break;
        }
        if (window <= 0) {
            std.Io.sleep(session.io, std.Io.Duration.fromMilliseconds(WINDOW_POLL_MS), .awake) catch {};
            continue;
        }

        const usable: usize = @intCast(@min(window, 0x7FFF_FFFF));
        const take: usize = @min(data.len - offset, @min(usable, max_frame));
        const last = offset + take == data.len;
        const flags: u8 = if (end_stream and last) Http2.FLAG_END_STREAM else 0;

        {
            lockClient(session);
            defer unlockClient(session);
            http2_frames.writeFrame(session.client_w, Http2.FRAME_TYPE_DATA, flags, target, data[offset..][0..take]) catch return false;
            session.client_w.flush() catch return false;
        }

        lockState(session);
        session.client_conn_window -= @intCast(take);
        if (findEntryByUpLocked(session, up_index, up_id)) |spent| spent.client_window -= @intCast(take);
        unlockState(session);

        offset += take;
    }

    if (data.len == 0 and end_stream and delivered) {
        lockClient(session);
        http2_frames.writeFrame(session.client_w, Http2.FRAME_TYPE_DATA, Http2.FLAG_END_STREAM, target, "") catch {
            unlockClient(session);
            return false;
        };
        session.client_w.flush() catch {
            unlockClient(session);
            return false;
        };
        unlockClient(session);
    }

    if (delivered) {
        grpc_upstream.writeGrant(up_conn, up_id, frame.head.length) catch return false;
    } else {
        grpc_upstream.writeConnGrant(up_conn, frame.head.length) catch return false;
    }

    if (end_stream and delivered) {
        clearEntryByUp(session, up_index, up_id);
        maybeCloseAfterDrain(session);
    }

    return true;
}

fn relayUpstreamRst(session: *Session, up_index: usize, up_id: u31, code: u32) void {
    lockState(session);
    const found = findEntryByUpLocked(session, up_index, up_id);
    const client_id: ?u31 = if (found) |entry| blk: {
        entry.active = false;

        break :blk entry.client_id;
    } else null;
    unlockState(session);

    if (client_id) |id| {
        _ = streamError(session, id, code);
        maybeCloseAfterDrain(session);
    }
}

/// The pump is over: reset every client stream that was routed here and
/// take the conn out of routing.
fn markUpstreamDead(session: *Session, up_index: usize) void {
    var affected: [MAX_STREAMS]struct { id: u31, saw_head: bool } = undefined;
    var affected_len: usize = 0;

    lockState(session);
    session.up_conns[up_index].alive = false;
    for (&session.entries) |*entry| {
        if (entry.active and entry.up_index == up_index) {
            affected[affected_len] = .{ .id = entry.client_id, .saw_head = entry.saw_head };
            affected_len += 1;
            entry.active = false;
        }
    }
    const stopping = session.stopping;
    unlockState(session);

    if (stopping) return;

    for (affected[0..affected_len]) |lost| {
        // A stream the upstream never answered is safe to retry.
        const code: u32 = if (lost.saw_head) Http2.ERR_INTERNAL_ERROR else Http2.ERR_REFUSED_STREAM;
        _ = streamError(session, lost.id, code);
    }

    maybeCloseAfterDrain(session);
}

// --------------------------------------------------------- //
// shared state and client write helpers

fn findEntryByClientLocked(session: *Session, client_id: u31) ?*StreamEntry {
    for (&session.entries) |*entry| {
        if (entry.active and entry.client_id == client_id) return entry;
    }

    return null;
}

fn findEntryByUpLocked(session: *Session, up_index: usize, up_id: u31) ?*StreamEntry {
    for (&session.entries) |*entry| {
        if (entry.active and entry.up_index == up_index and entry.up_id == up_id) return entry;
    }

    return null;
}

fn findFreeEntryLocked(session: *Session) ?*StreamEntry {
    for (&session.entries) |*entry| {
        if (!entry.active) return entry;
    }

    return null;
}

fn activeCountLocked(session: *Session) usize {
    var count: usize = 0;
    for (&session.entries) |*entry| {
        if (entry.active) count += 1;
    }

    return count;
}

fn clearEntryByClient(session: *Session, client_id: u31) void {
    lockState(session);
    defer unlockState(session);

    if (findEntryByClientLocked(session, client_id)) |entry| entry.active = false;
}

fn clearEntryByUp(session: *Session, up_index: usize, up_id: u31) void {
    lockState(session);
    defer unlockState(session);

    if (findEntryByUpLocked(session, up_index, up_id)) |entry| entry.active = false;
}

/// Largest DATA payload one upstream send may carry. Caller holds the
/// state lock.
fn upstreamMaxFrameLocked(up_conn: *const grpc_upstream.UpConn) usize {
    return @min(up_conn.max_frame, http2_frames.MAX_PAYLOAD);
}

/// Write one header block to the client and flush it.
fn writeBlockToClient(session: *Session, stream_id: u31, block: []const u8, end_stream: bool) ProcessResult {
    lockState(session);
    const max_frame: usize = @min(session.client_max_frame, http2_frames.MAX_PAYLOAD);
    unlockState(session);

    lockClient(session);
    defer unlockClient(session);
    http2_frames.writeHeaderBlock(session.client_w, stream_id, block, end_stream, max_frame) catch return .CLOSED;
    session.client_w.flush() catch return .CLOSED;

    return .OK;
}

/// Reset one client stream, the connection keeps serving.
fn streamError(session: *Session, stream_id: u31, code: u32) ProcessResult {
    lockClient(session);
    defer unlockClient(session);
    http2_frames.writeRstStream(session.client_w, stream_id, code) catch return .CLOSED;
    session.client_w.flush() catch return .CLOSED;

    return .OK;
}

/// Fatal connection error: best-effort GOAWAY, then the caller closes.
fn connError(session: *Session, code: u32) ProcessResult {
    lockClient(session);
    defer unlockClient(session);
    http2_frames.writeGoaway(session.client_w, session.highest_stream, code) catch return .CLOSED;
    session.client_w.flush() catch return .CLOSED;

    return .CLOSED;
}

fn lockClient(session: *Session) void {
    while (session.write_lock.swap(true, .acquire)) std.atomic.spinLoopHint();
}

fn unlockClient(session: *Session) void {
    session.write_lock.store(false, .release);
}

fn lockState(session: *Session) void {
    while (session.state_lock.swap(true, .acquire)) std.atomic.spinLoopHint();
}

fn unlockState(session: *Session) void {
    session.state_lock.store(false, .release);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;
const site_cfg = @import("site_cfg.zig");
const upstream_pool = @import("upstream_pool.zig");

fn edgeStream(handle: std.posix.fd_t) std.Io.net.Stream {
    return .{ .socket = .{ .handle = handle, .address = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 40013 } } } };
}

fn openEdgePair(fds: *[2]std.posix.fd_t) !void {
    try testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, fds));
}

fn spawnServeConn(proxy: *const http1_proxy.Proxy, stream: std.Io.net.Stream) !std.Thread {
    return std.Thread.spawn(.{}, serveConnThread, .{ proxy, stream });
}

fn serveConnThread(proxy: *const http1_proxy.Proxy, stream: std.Io.net.Stream) void {
    serveConn(proxy, stream);
}

/// grpc test client over one socketpair end: buffered stream interfaces
/// plus its own frame and hpack state, reading edge frames as events.
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
    event_data: [16 * 1024]u8 = undefined,

    const Event = struct {
        kind: enum { HEADERS, DATA, RST, GOAWAY, WINDOW_UPDATE, PING_ACK },
        stream_id: u31 = 0,
        end_stream: bool = false,
        count: usize = 0,
        data_len: usize = 0,
        code: u32 = 0,
    };

    fn start(client: *TestClient) !void {
        try client.startWith(&.{});
    }

    /// Bind the interfaces, run the connection preface both ways with the
    /// given client SETTINGS parameters.
    fn startWith(client: *TestClient, params: []const [2]u32) !void {
        client.reader = client.stream.reader(client.io, &client.read_buf);
        client.writer = client.stream.writer(client.io, &client.write_buf);
        client.decoder = Http2.HpackDecoder.init();

        try client.writer.interface.writeAll(Http2.PREFACE);
        try http2_frames.writeSettings(&client.writer.interface, params);
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

    fn sendRst(client: *TestClient, stream_id: u31, code: u32) !void {
        try http2_frames.writeRstStream(&client.writer.interface, stream_id, code);
        try client.writer.interface.flush();
    }

    fn sendGoaway(client: *TestClient) !void {
        try http2_frames.writeGoaway(&client.writer.interface, 0, Http2.ERR_NO_ERROR);
        try client.writer.interface.flush();
    }

    /// Read the next frame as an event. HEADERS decode into decoded, DATA
    /// copies into event_data and grants the credit back like a
    /// well-behaved peer.
    fn nextEvent(client: *TestClient) !Event {
        while (true) {
            const frame = try client.nextFrame();
            switch (frame.head.frame_type) {
                Http2.FRAME_TYPE_HEADERS => {
                    try testing.expect((frame.head.flags & Http2.FLAG_END_HEADERS) != 0);
                    const fragment = try http2_frames.headersFragment(&frame);
                    const count = try client.decoder.decode(fragment, &client.decoded, &client.scratch);

                    return .{
                        .kind = .HEADERS,
                        .stream_id = frame.head.stream_id,
                        .end_stream = (frame.head.flags & Http2.FLAG_END_STREAM) != 0,
                        .count = count,
                    };
                },
                Http2.FRAME_TYPE_DATA => {
                    const data = try http2_frames.dataPayload(&frame);
                    @memcpy(client.event_data[0..data.len], data);

                    if (frame.head.length > 0) {
                        try http2_frames.writeWindowUpdate(&client.writer.interface, 0, @intCast(frame.head.length));
                        try http2_frames.writeWindowUpdate(&client.writer.interface, frame.head.stream_id, @intCast(frame.head.length));
                        try client.writer.interface.flush();
                    }

                    return .{
                        .kind = .DATA,
                        .stream_id = frame.head.stream_id,
                        .end_stream = (frame.head.flags & Http2.FLAG_END_STREAM) != 0,
                        .data_len = data.len,
                    };
                },
                Http2.FRAME_TYPE_RST_STREAM => {
                    return .{
                        .kind = .RST,
                        .stream_id = frame.head.stream_id,
                        .code = std.mem.readInt(u32, frame.payload[0..4], .big),
                    };
                },
                Http2.FRAME_TYPE_GOAWAY => return .{ .kind = .GOAWAY },
                Http2.FRAME_TYPE_WINDOW_UPDATE => {
                    return .{
                        .kind = .WINDOW_UPDATE,
                        .stream_id = frame.head.stream_id,
                        .code = try http2_frames.windowIncrement(frame.payload),
                    };
                },
                Http2.FRAME_TYPE_PING => {
                    if ((frame.head.flags & Http2.FLAG_ACK) != 0) return .{ .kind = .PING_ACK };
                },
                else => {},
            }
        }
    }

    /// Read events until this stream's HEADERS arrives, skipping grants.
    fn awaitHeaders(client: *TestClient, stream_id: u31) !Event {
        while (true) {
            const event = try client.nextEvent();
            if (event.kind == .RST or event.kind == .GOAWAY) return error.TestUnexpectedResult;
            if (event.kind == .HEADERS and event.stream_id == stream_id) return event;
        }
    }

    /// Collect DATA for one stream until its trailer block, which decodes
    /// into decoded for the caller to inspect.
    const Collected = struct {
        body_len: usize,
        data_frames: usize,
        trailer_count: usize,
    };

    fn collectUntilTrailers(client: *TestClient, stream_id: u31, out: []u8) !Collected {
        var body_len: usize = 0;
        var data_frames: usize = 0;
        while (true) {
            const event = try client.nextEvent();
            if (event.kind == .RST or event.kind == .GOAWAY) return error.TestUnexpectedResult;
            if (event.stream_id != stream_id) continue;

            if (event.kind == .DATA) {
                if (body_len + event.data_len > out.len) return error.TestUnexpectedResult;
                @memcpy(out[body_len..][0..event.data_len], client.event_data[0..event.data_len]);
                body_len += event.data_len;
                data_frames += 1;
                continue;
            }
            if (event.kind == .HEADERS) {
                try testing.expect(event.end_stream);

                return .{ .body_len = body_len, .data_frames = data_frames, .trailer_count = event.count };
            }
        }
    }

    fn headerValue(client: *TestClient, count: usize, name: []const u8) ?[]const u8 {
        for (client.decoded[0..count]) |entry| {
            if (std.mem.eql(u8, entry.name, name)) return entry.value;
        }

        return null;
    }
};

/// h2 grpc upstream fake: accepts conns, multiplexes streams, answers per
/// mode, and records what crossed the relay.
const FakeGrpcUpstream = struct {
    io: std.Io,
    port: u16,
    mode: enum { ECHO, TRAILERS_ONLY, STREAM3, HOLD },
    conn_quota: usize = 1,
    /// The first conn answers a head plus one DATA frame, then drops the
    /// whole connection (upstream death mid-stream).
    die_first_conn: bool = false,
    ready: std.atomic.Value(bool) = .init(false),
    /// Set when every bind attempt lost, so the waiter fails with the
    /// reason instead of spinning out its whole budget on a dead thread.
    bind_failed: std.atomic.Value(bool) = .init(false),
    conns_accepted: usize = 0,
    streams_served: std.atomic.Value(usize) = .init(0),
    rst_seen: std.atomic.Value(usize) = .init(0),
    seen_head: [4096]u8 = undefined,
    seen_head_len: usize = 0,
    seen_trailer: [1024]u8 = undefined,
    seen_trailer_len: usize = 0,

    const FakeStream = struct {
        used: bool = false,
        id: u31 = 0,
        body_len: usize = 0,
        body: [8192]u8 = undefined,
    };

    fn serve(fake: *FakeGrpcUpstream) void {
        const io = fake.io;

        const addr = std.Io.net.IpAddress.parse("127.0.0.1", fake.port) catch {
            fake.bind_failed.store(true, .release);
            return;
        };

        var server = bindWithRetry(io, addr) orelse {
            fake.bind_failed.store(true, .release);
            return;
        };
        defer server.deinit(io);
        fake.ready.store(true, .release);

        var conns: usize = 0;
        while (conns < fake.conn_quota) : (conns += 1) {
            const stream = server.accept(io) catch return;
            fake.conns_accepted += 1;

            fake.handleConn(stream, fake.die_first_conn and conns == 0);
            stream.close(io);
        }
    }

    fn handleConn(fake: *FakeGrpcUpstream, stream: std.Io.net.Stream, die_after_head: bool) void {
        const io = fake.io;

        var read_buf: [16 * 1024]u8 = undefined;
        var write_buf: [16 * 1024]u8 = undefined;
        var reader = stream.reader(io, &read_buf);
        var writer = stream.writer(io, &write_buf);
        const out = &writer.interface;

        var preface: [Http2.PREFACE.len]u8 = undefined;
        reader.interface.readSliceAll(&preface) catch return;
        if (!std.mem.eql(u8, &preface, Http2.PREFACE)) return;

        http2_frames.writeSettings(out, &.{}) catch return;
        out.flush() catch return;

        var decoder = Http2.HpackDecoder.init();
        var decoded: [Http2.MAX_HEADERS]Http2.Header = undefined;
        var decode_scratch: [8192]u8 = undefined;
        var payload_buf: [http2_frames.MAX_PAYLOAD]u8 = undefined;
        var streams: [10]FakeStream = @splat(.{});

        while (true) {
            const frame = http2_frames.readFrame(&reader.interface, &payload_buf) catch return;

            switch (frame.head.frame_type) {
                Http2.FRAME_TYPE_SETTINGS => {
                    if ((frame.head.flags & Http2.FLAG_ACK) != 0) continue;

                    http2_frames.writeSettingsAck(out) catch return;
                    out.flush() catch return;
                },
                Http2.FRAME_TYPE_PING => {
                    if ((frame.head.flags & Http2.FLAG_ACK) != 0) continue;

                    http2_frames.writePingAck(out, frame.payload) catch return;
                    out.flush() catch return;
                },
                Http2.FRAME_TYPE_HEADERS => {
                    const fragment = http2_frames.headersFragment(&frame) catch return;
                    const count = decoder.decode(fragment, &decoded, &decode_scratch) catch return;
                    const end_stream = (frame.head.flags & Http2.FLAG_END_STREAM) != 0;
                    const id = frame.head.stream_id;

                    if (findFakeStream(&streams, id)) |slot| {
                        fake.record(&fake.seen_trailer, &fake.seen_trailer_len, decoded[0..count]);
                        if (end_stream) {
                            fake.respond(out, id, slot, die_after_head) catch return;
                            if (die_after_head) return;
                        }
                        continue;
                    }

                    const slot = claimFakeStream(&streams, id) orelse return;
                    if (fake.seen_head_len == 0) fake.record(&fake.seen_head, &fake.seen_head_len, decoded[0..count]);
                    if (end_stream) {
                        fake.respond(out, id, slot, die_after_head) catch return;
                        if (die_after_head) return;
                    }
                },
                Http2.FRAME_TYPE_DATA => {
                    const data = http2_frames.dataPayload(&frame) catch return;
                    const id = frame.head.stream_id;
                    const slot = findFakeStream(&streams, id) orelse continue;

                    @memcpy(slot.body[slot.body_len..][0..data.len], data);
                    slot.body_len += data.len;

                    if (frame.head.length > 0) {
                        http2_frames.writeWindowUpdate(out, 0, @intCast(frame.head.length)) catch return;
                        http2_frames.writeWindowUpdate(out, id, @intCast(frame.head.length)) catch return;
                        out.flush() catch return;
                    }

                    if ((frame.head.flags & Http2.FLAG_END_STREAM) != 0) {
                        fake.respond(out, id, slot, die_after_head) catch return;
                        if (die_after_head) return;
                    }
                },
                Http2.FRAME_TYPE_RST_STREAM => {
                    _ = fake.rst_seen.fetchAdd(1, .acq_rel);
                },
                else => {},
            }
        }
    }

    fn respond(fake: *FakeGrpcUpstream, out: *std.Io.Writer, id: u31, slot: *FakeStream, die_after_head: bool) !void {
        var block_buf: [1024]u8 = undefined;

        if (die_after_head) {
            const head = try encodeFakeBlock(&block_buf, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-type", .value = "application/grpc" },
            });
            try http2_frames.writeHeaderBlock(out, id, head, false, http2_frames.MAX_PAYLOAD);
            try http2_frames.writeFrame(out, Http2.FRAME_TYPE_DATA, 0, id, "partial");
            try out.flush();

            return;
        }

        switch (fake.mode) {
            .ECHO => {
                const head = try encodeFakeBlock(&block_buf, &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "content-type", .value = "application/grpc" },
                });
                try http2_frames.writeHeaderBlock(out, id, head, false, http2_frames.MAX_PAYLOAD);
                try out.flush();

                if (slot.body_len > 0) {
                    try http2_frames.writeFrame(out, Http2.FRAME_TYPE_DATA, 0, id, slot.body[0..slot.body_len]);
                    try out.flush();
                }

                var len_text: [24]u8 = undefined;
                const len_value = std.fmt.bufPrint(&len_text, "{d}", .{slot.body_len}) catch unreachable;
                const trailers = try encodeFakeBlock(&block_buf, &.{
                    .{ .name = "grpc-status", .value = "0" },
                    .{ .name = "x-echo-len", .value = len_value },
                });
                try http2_frames.writeHeaderBlock(out, id, trailers, true, http2_frames.MAX_PAYLOAD);
                try out.flush();
            },
            .TRAILERS_ONLY => {
                const block = try encodeFakeBlock(&block_buf, &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "content-type", .value = "application/grpc" },
                    .{ .name = "grpc-status", .value = "0" },
                    .{ .name = "grpc-message", .value = "empty ok" },
                });
                try http2_frames.writeHeaderBlock(out, id, block, true, http2_frames.MAX_PAYLOAD);
                try out.flush();
            },
            .STREAM3 => {
                const head = try encodeFakeBlock(&block_buf, &.{
                    .{ .name = ":status", .value = "200" },
                    .{ .name = "content-type", .value = "application/grpc" },
                });
                try http2_frames.writeHeaderBlock(out, id, head, false, http2_frames.MAX_PAYLOAD);
                try out.flush();

                const messages = [_][]const u8{ "msg0", "msg1", "msg2" };
                for (messages) |message| {
                    try http2_frames.writeFrame(out, Http2.FRAME_TYPE_DATA, 0, id, message);
                    try out.flush();
                }

                const trailers = try encodeFakeBlock(&block_buf, &.{
                    .{ .name = "grpc-status", .value = "0" },
                });
                try http2_frames.writeHeaderBlock(out, id, trailers, true, http2_frames.MAX_PAYLOAD);
                try out.flush();
            },
            .HOLD => return,
        }

        slot.* = .{};
        _ = fake.streams_served.fetchAdd(1, .acq_rel);
    }

    /// Flatten headers as name=value lines into one record buffer.
    fn record(fake: *FakeGrpcUpstream, buf: []u8, len: *usize, headers: []const Http2.Header) void {
        _ = fake;

        for (headers) |header| {
            const need = header.name.len + header.value.len + 2;
            if (len.* + need > buf.len) return;

            @memcpy(buf[len.*..][0..header.name.len], header.name);
            len.* += header.name.len;
            buf[len.*] = '=';
            len.* += 1;
            @memcpy(buf[len.*..][0..header.value.len], header.value);
            len.* += header.value.len;
            buf[len.*] = '\n';
            len.* += 1;
        }
    }

    fn findFakeStream(streams: []FakeStream, id: u31) ?*FakeStream {
        for (streams) |*slot| {
            if (slot.used and slot.id == id) return slot;
        }

        return null;
    }

    fn claimFakeStream(streams: []FakeStream, id: u31) ?*FakeStream {
        for (streams) |*slot| {
            if (!slot.used) {
                slot.* = .{ .used = true, .id = id };

                return slot;
            }
        }

        return null;
    }

    fn encodeFakeBlock(block_buf: []u8, headers: []const Http2.Header) ![]const u8 {
        var encoder = Http2.HpackEncoder.init(block_buf);
        for (headers) |header| try encoder.writeHeader(header.name, header.value);

        return encoder.encoded();
    }
};

/// Attempts the fake upstream makes at its fixed port, one per BIND_RETRY_MS.
/// These ports sit below the ephemeral range, so the kernel never hands one
/// out as an outbound source port. What is left is a foreign process holding
/// the port, and retrying rides a brief hold out instead of failing the run.
const BIND_TRIES: usize = 50;
const BIND_RETRY_MS: u64 = 10;

fn bindWithRetry(io: std.Io, addr: std.Io.net.IpAddress) ?std.Io.net.Server {
    var tries: usize = 0;
    while (tries < BIND_TRIES) : (tries += 1) {
        if (addr.listen(io, .{ .reuse_address = true, .kernel_backlog = 4 })) |server| return server else |_| {}

        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(BIND_RETRY_MS), .awake) catch {};
    }

    return null;
}

fn waitReady(io: std.Io, fake: *FakeGrpcUpstream) !void {
    var spins: usize = 0;
    while (!fake.ready.load(.acquire)) : (spins += 1) {
        // Told apart on purpose: a lost port is an environment problem, a
        // quiet thread is a real one, and the old bound reported both alike.
        if (fake.bind_failed.load(.acquire)) {
            std.log.err("zix zixer: grpc edge, the fake upstream could not take port {d} in {d} tries", .{ fake.port, BIND_TRIES });

            return error.ZixerFakeBindFailed;
        }

        if (spins > 5000) return error.ZixerFakeNeverReady;

        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }
}

const REQUEST_HEAD = [_]Http2.Header{
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":path", .value = "/test.Svc/Echo" },
    .{ .name = ":authority", .value = "zixer-grpc" },
    .{ .name = "content-type", .value = "application/grpc" },
    .{ .name = "te", .value = "trailers" },
};

test "zix zixer: grpc edge, unary echo end-to-end with trailers and via" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeGrpcUpstream{ .io = io, .port = 18841, .mode = .ECHO };
    const fake_thread = try std.Thread.spawn(.{}, FakeGrpcUpstream.serve, .{&fake});
    try waitReady(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18841 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    try client.sendHeaders(1, &REQUEST_HEAD, false);
    try client.sendData(1, "abc", true);

    const head = try client.awaitHeaders(1);
    try testing.expect(!head.end_stream);
    try testing.expectEqualStrings("200", client.headerValue(head.count, ":status").?);
    try testing.expectEqualStrings("application/grpc", client.headerValue(head.count, "content-type").?);
    try testing.expectEqualStrings(grpc_relay.VIA_H2, client.headerValue(head.count, "via").?);

    var body: [64]u8 = undefined;
    const result = try client.collectUntilTrailers(1, &body);
    try testing.expectEqualStrings("abc", body[0..result.body_len]);
    try testing.expectEqualStrings("0", client.headerValue(result.trailer_count, "grpc-status").?);
    try testing.expectEqualStrings("3", client.headerValue(result.trailer_count, "x-echo-len").?);

    // The upstream leg carried the relay marks and kept te intact.
    const seen = fake.seen_head[0..fake.seen_head_len];
    try testing.expect(std.mem.indexOf(u8, seen, "via=2 zixer\n") != null);
    try testing.expect(std.mem.indexOf(u8, seen, "forwarded=for=\"127.0.0.1:40013\";proto=http;host=\"zixer-grpc\"\n") != null);
    try testing.expect(std.mem.indexOf(u8, seen, "te=trailers\n") != null);
    try testing.expect(std.mem.indexOf(u8, seen, ":path=/test.Svc/Echo\n") != null);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: grpc edge, request trailers relay to the upstream" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeGrpcUpstream{ .io = io, .port = 18842, .mode = .ECHO };
    const fake_thread = try std.Thread.spawn(.{}, FakeGrpcUpstream.serve, .{&fake});
    try waitReady(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18842 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    try client.sendHeaders(1, &REQUEST_HEAD, false);
    try client.sendData(1, "abc", false);
    const request_trailers = [_]Http2.Header{.{ .name = "x-client-trailer", .value = "yes" }};
    try client.sendHeaders(1, &request_trailers, true);

    _ = try client.awaitHeaders(1);
    var body: [64]u8 = undefined;
    const result = try client.collectUntilTrailers(1, &body);
    try testing.expectEqualStrings("abc", body[0..result.body_len]);

    const seen = fake.seen_trailer[0..fake.seen_trailer_len];
    try testing.expect(std.mem.indexOf(u8, seen, "x-client-trailer=yes\n") != null);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: grpc edge, trailers-only answer and sequential streams reuse one conn" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeGrpcUpstream{ .io = io, .port = 18843, .mode = .TRAILERS_ONLY };
    const fake_thread = try std.Thread.spawn(.{}, FakeGrpcUpstream.serve, .{&fake});
    try waitReady(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18843 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    try client.sendHeaders(1, &REQUEST_HEAD, true);
    const first = try client.awaitHeaders(1);
    try testing.expect(first.end_stream);
    try testing.expectEqualStrings("200", client.headerValue(first.count, ":status").?);
    try testing.expectEqualStrings("0", client.headerValue(first.count, "grpc-status").?);
    try testing.expectEqualStrings("empty ok", client.headerValue(first.count, "grpc-message").?);

    try client.sendHeaders(3, &REQUEST_HEAD, true);
    const second = try client.awaitHeaders(3);
    try testing.expect(second.end_stream);
    try testing.expectEqualStrings("0", client.headerValue(second.count, "grpc-status").?);

    try testing.expectEqual(@as(usize, 1), fake.conns_accepted);
    try testing.expectEqual(@as(usize, 2), fake.streams_served.load(.acquire));

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: grpc edge, two in-flight streams multiplex one upstream conn" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeGrpcUpstream{ .io = io, .port = 18844, .mode = .ECHO };
    const fake_thread = try std.Thread.spawn(.{}, FakeGrpcUpstream.serve, .{&fake});
    try waitReady(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18844 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    // Stream 1 stays open while stream 3 completes: two live entries on
    // one upstream conn.
    try client.sendHeaders(1, &REQUEST_HEAD, false);
    try client.sendHeaders(3, &REQUEST_HEAD, true);

    const other_head = try client.awaitHeaders(3);
    try testing.expect(!other_head.end_stream);
    var other_body: [64]u8 = undefined;
    const other = try client.collectUntilTrailers(3, &other_body);
    try testing.expectEqual(@as(usize, 0), other.body_len);
    try testing.expectEqualStrings("0", client.headerValue(other.trailer_count, "grpc-status").?);

    try client.sendData(1, "abc", true);
    _ = try client.awaitHeaders(1);
    var body: [64]u8 = undefined;
    const result = try client.collectUntilTrailers(1, &body);
    try testing.expectEqualStrings("abc", body[0..result.body_len]);

    try testing.expectEqual(@as(usize, 1), fake.conns_accepted);
    try testing.expectEqual(@as(usize, 2), fake.streams_served.load(.acquire));

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: grpc edge, pick per stream lands on both upstreams" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake_a = FakeGrpcUpstream{ .io = io, .port = 18845, .mode = .TRAILERS_ONLY };
    var fake_b = FakeGrpcUpstream{ .io = io, .port = 18846, .mode = .TRAILERS_ONLY };
    const thread_a = try std.Thread.spawn(.{}, FakeGrpcUpstream.serve, .{&fake_a});
    const thread_b = try std.Thread.spawn(.{}, FakeGrpcUpstream.serve, .{&fake_b});
    try waitReady(io, &fake_a);
    try waitReady(io, &fake_b);

    const upstreams = [_]site_cfg.Upstream{
        .{ .host = "127.0.0.1", .port = 18845 },
        .{ .host = "127.0.0.1", .port = 18846 },
    };
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    try client.sendHeaders(1, &REQUEST_HEAD, true);
    _ = try client.awaitHeaders(1);
    try client.sendHeaders(3, &REQUEST_HEAD, true);
    _ = try client.awaitHeaders(3);

    try testing.expectEqual(@as(usize, 1), fake_a.conns_accepted);
    try testing.expectEqual(@as(usize, 1), fake_b.conns_accepted);
    try testing.expectEqual(@as(usize, 1), fake_a.streams_served.load(.acquire));
    try testing.expectEqual(@as(usize, 1), fake_b.streams_served.load(.acquire));

    client.stream.close(io);
    edge_thread.join();
    thread_a.join();
    thread_b.join();
}

test "zix zixer: grpc edge, server streaming keeps messages as separate frames" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeGrpcUpstream{ .io = io, .port = 18848, .mode = .STREAM3 };
    const fake_thread = try std.Thread.spawn(.{}, FakeGrpcUpstream.serve, .{&fake});
    try waitReady(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18848 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    try client.sendHeaders(1, &REQUEST_HEAD, true);

    _ = try client.awaitHeaders(1);
    var body: [64]u8 = undefined;
    const result = try client.collectUntilTrailers(1, &body);

    // One relayed frame per upstream frame: the streamed messages arrive
    // as the upstream sent them.
    try testing.expectEqual(@as(usize, 3), result.data_frames);
    try testing.expectEqualStrings("msg0msg1msg2", body[0..result.body_len]);
    try testing.expectEqualStrings("0", client.headerValue(result.trailer_count, "grpc-status").?);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: grpc edge, response data respects the client stream window" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeGrpcUpstream{ .io = io, .port = 18854, .mode = .ECHO };
    const fake_thread = try std.Thread.spawn(.{}, FakeGrpcUpstream.serve, .{&fake});
    try waitReady(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18854 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.startWith(&.{.{ Http2.SETTINGS_INITIAL_WINDOW_SIZE, 4 }});

    try client.sendHeaders(1, &REQUEST_HEAD, false);
    try client.sendData(1, "0123456789", true);

    _ = try client.awaitHeaders(1);
    var body: [64]u8 = undefined;
    var body_len: usize = 0;
    var frames: usize = 0;
    while (true) {
        const event = try client.nextEvent();
        if (event.kind == .WINDOW_UPDATE) continue;
        if (event.kind == .HEADERS) {
            try testing.expect(event.end_stream);
            break;
        }

        try testing.expectEqual(.DATA, event.kind);
        try testing.expect(event.data_len <= 4);
        @memcpy(body[body_len..][0..event.data_len], client.event_data[0..event.data_len]);
        body_len += event.data_len;
        frames += 1;
    }

    try testing.expectEqualStrings("0123456789", body[0..body_len]);
    try testing.expect(frames >= 3);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: grpc edge, request data credit comes back per frame" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeGrpcUpstream{ .io = io, .port = 18832, .mode = .HOLD };
    const fake_thread = try std.Thread.spawn(.{}, FakeGrpcUpstream.serve, .{&fake});
    try waitReady(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18832 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    try client.sendHeaders(1, &REQUEST_HEAD, false);
    try client.sendData(1, "abcd", false);

    const conn_grant = try client.nextEvent();
    try testing.expectEqual(.WINDOW_UPDATE, conn_grant.kind);
    try testing.expectEqual(@as(u31, 0), conn_grant.stream_id);
    try testing.expectEqual(@as(u32, 4), conn_grant.code);

    const stream_grant = try client.nextEvent();
    try testing.expectEqual(.WINDOW_UPDATE, stream_grant.kind);
    try testing.expectEqual(@as(u31, 1), stream_grant.stream_id);
    try testing.expectEqual(@as(u32, 4), stream_grant.code);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: grpc edge, no reachable upstream answers grpc unavailable" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Nothing listens on the upstream port.
    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18847 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    try client.sendHeaders(1, &REQUEST_HEAD, true);
    const answer = try client.awaitHeaders(1);
    try testing.expect(answer.end_stream);
    try testing.expectEqualStrings("200", client.headerValue(answer.count, ":status").?);
    try testing.expectEqualStrings(grpc_relay.GRPC_STATUS_UNAVAILABLE, client.headerValue(answer.count, "grpc-status").?);

    try client.sendPing();
    const pong = try client.nextEvent();
    try testing.expectEqual(.PING_ACK, pong.kind);

    client.stream.close(io);
    edge_thread.join();
}

test "zix zixer: grpc edge, ninth concurrent stream is refused" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeGrpcUpstream{ .io = io, .port = 18830, .mode = .HOLD };
    const fake_thread = try std.Thread.spawn(.{}, FakeGrpcUpstream.serve, .{&fake});
    try waitReady(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18830 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    var id: u31 = 1;
    while (id <= 15) : (id += 2) {
        try client.sendHeaders(id, &REQUEST_HEAD, true);
    }
    try client.sendHeaders(17, &REQUEST_HEAD, true);

    const refused = try client.nextEvent();
    try testing.expectEqual(.RST, refused.kind);
    try testing.expectEqual(@as(u31, 17), refused.stream_id);
    try testing.expectEqual(Http2.ERR_REFUSED_STREAM, refused.code);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: grpc edge, client reset forwards to the upstream stream" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeGrpcUpstream{ .io = io, .port = 18831, .mode = .HOLD };
    const fake_thread = try std.Thread.spawn(.{}, FakeGrpcUpstream.serve, .{&fake});
    try waitReady(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18831 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    try client.sendHeaders(1, &REQUEST_HEAD, false);
    try client.sendRst(1, Http2.ERR_CANCEL);

    var spins: usize = 0;
    while (fake.rst_seen.load(.acquire) == 0) : (spins += 1) {
        if (spins > 5000) return error.ZixerRstNeverForwarded;

        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(1), .awake) catch {};
    }

    try client.sendPing();
    const pong = try client.nextEvent();
    try testing.expectEqual(.PING_ACK, pong.kind);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: grpc edge, upstream death resets the stream and the next one reconnects" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeGrpcUpstream{ .io = io, .port = 18849, .mode = .ECHO, .conn_quota = 2, .die_first_conn = true };
    const fake_thread = try std.Thread.spawn(.{}, FakeGrpcUpstream.serve, .{&fake});
    try waitReady(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18849 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    try client.sendHeaders(1, &REQUEST_HEAD, true);
    _ = try client.awaitHeaders(1);
    const partial = try client.nextEvent();
    try testing.expectEqual(.DATA, partial.kind);
    try testing.expectEqualStrings("partial", client.event_data[0..partial.data_len]);

    const reset = try client.nextEvent();
    try testing.expectEqual(.RST, reset.kind);
    try testing.expectEqual(@as(u31, 1), reset.stream_id);
    try testing.expectEqual(Http2.ERR_INTERNAL_ERROR, reset.code);

    // The next stream opens a fresh upstream conn and completes.
    try client.sendHeaders(3, &REQUEST_HEAD, true);
    _ = try client.awaitHeaders(3);
    var body: [64]u8 = undefined;
    const result = try client.collectUntilTrailers(3, &body);
    try testing.expectEqualStrings("0", client.headerValue(result.trailer_count, "grpc-status").?);

    try testing.expectEqual(@as(usize, 2), fake.conns_accepted);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

test "zix zixer: grpc edge, connection specific header resets the stream only" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18847 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    const bad = [_]Http2.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/x" },
        .{ .name = ":authority", .value = "zixer-grpc" },
        .{ .name = "connection", .value = "keep-alive" },
    };
    try client.sendHeaders(1, &bad, true);

    const reset = try client.nextEvent();
    try testing.expectEqual(.RST, reset.kind);
    try testing.expectEqual(@as(u31, 1), reset.stream_id);
    try testing.expectEqual(Http2.ERR_PROTOCOL_ERROR, reset.code);

    try client.sendPing();
    const pong = try client.nextEvent();
    try testing.expectEqual(.PING_ACK, pong.kind);

    client.stream.close(io);
    edge_thread.join();
}

test "zix zixer: grpc edge, non-preface bytes close without an answer" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18847 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    const peer = edgeStream(fds[1]);
    var write_buf: [256]u8 = undefined;
    var writer = peer.writer(io, &write_buf);
    try writer.interface.writeAll("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    try writer.interface.flush();

    var read_buf: [64]u8 = undefined;
    var reader = peer.reader(io, &read_buf);
    var probe: [1]u8 = undefined;
    const got = reader.interface.readSliceShort(&probe) catch 0;
    try testing.expectEqual(@as(usize, 0), got);

    peer.close(io);
    edge_thread.join();
}

test "zix zixer: grpc edge, client goaway drains and the edge answers goaway" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeGrpcUpstream{ .io = io, .port = 18855, .mode = .TRAILERS_ONLY };
    const fake_thread = try std.Thread.spawn(.{}, FakeGrpcUpstream.serve, .{&fake});
    try waitReady(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18855 }};
    var pool = try upstream_pool.Pool.init(testing.allocator, &upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
    defer pool.deinit(testing.allocator);
    const proxy = http1_proxy.Proxy{ .io = io, .pool = &pool };

    var fds: [2]std.posix.fd_t = undefined;
    try openEdgePair(&fds);
    const edge_thread = try spawnServeConn(&proxy, edgeStream(fds[0]));

    var client = TestClient{ .io = io, .stream = edgeStream(fds[1]) };
    try client.start();

    try client.sendHeaders(1, &REQUEST_HEAD, true);
    _ = try client.awaitHeaders(1);

    try client.sendGoaway();
    const answer = try client.nextEvent();
    try testing.expectEqual(.GOAWAY, answer.kind);

    var probe: [1]u8 = undefined;
    const got = client.reader.interface.readSliceShort(&probe) catch 0;
    try testing.expectEqual(@as(usize, 0), got);

    client.stream.close(io);
    edge_thread.join();
    fake_thread.join();
}

// --------------------------------------------------------- //

const deadline_sweep = @import("deadline_sweep.zig");
const deadline_table = @import("deadline_table.zig");

/// A stand-in socket for the table tests below. The table stores the handle and
/// never acts on it there, so no real socket has to exist.
fn testHandle(seed: usize) std.posix.socket_t {
    if (comptime @typeInfo(std.posix.socket_t) == .pointer) return @ptrFromInt(seed + 1);

    return @intCast(seed + 1);
}

/// One served grpc connection plus a flag its thread sets on the way out, so a
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

test "zix zixer: grpc edge, a site at its connection limit goes away at once" {
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

    // Answered before the preface is read: a refused connection must never be
    // made to wait on a client that may send nothing.
    var read_buf: [512]u8 = undefined;
    var reader = client.reader(io, &read_buf);
    var payload_buf: [64]u8 = undefined;

    const settings = try http2_frames.readFrame(&reader.interface, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_SETTINGS), settings.head.frame_type);

    const goaway = try http2_frames.readFrame(&reader.interface, &payload_buf);
    try testing.expectEqual(@as(u8, Http2.FRAME_TYPE_GOAWAY), goaway.head.frame_type);
    try testing.expectEqual(Http2.ERR_ENHANCE_YOUR_CALM, std.mem.readInt(u32, goaway.payload[4..8], .big));

    thread.join();
    try testing.expect(probe.done.load(.acquire));
    client.close(io);
    holder.close(io);
    edgeStream(fds[1]).close(io);

    try testing.expectEqual(@as(usize, 1), table.liveCount());
}

test "zix zixer: grpc edge, a quiet connection re-arms per frame and is cut in the end" {
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
    const ack = try client.nextEvent();
    try testing.expectEqual(.PING_ACK, ack.kind);

    // The frame the client just sent was read under a budget armed after the
    // sleep, so this stamp is still inside it. A loop that armed once at
    // accept would be cut here instead.
    const early = deadline_sweep.sweepOnce(&table, base + 60_200);
    try testing.expectEqual(@as(usize, 0), early.cut);
    try testing.expectEqual(@as(usize, 0), early.dropped);

    // Past every budget, and nothing is relaying, so nothing holds the bound
    // off this connection.
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

test "zix zixer: grpc edge, the bound comes off a connection that is relaying" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var table = try deadline_table.Table.init(testing.allocator, 1);
    defer table.deinit(testing.allocator);

    var src = std.Io.Reader.fixed("");
    var sink_buf: [64]u8 = undefined;
    var sink = std.Io.Writer.fixed(&sink_buf);
    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 40013 } };
    const proxy = http1_proxy.Proxy{ .io = io };

    var lease = client_lease.Lease.open(&table, io, testHandle(1), 1).?;
    defer lease.release();

    var session = Session{
        .proxy = &proxy,
        .io = io,
        .client_r = &src,
        .client_w = &sink,
        .client_addr = addr,
        .client_stream = null,
        .lease = &lease,
        .decoder = Http2.HpackDecoder.init(),
    };

    // Nothing relaying: the connection goes back under its budget, and a one
    // millisecond one is already spent.
    boundWhenQuiet(&session);

    var quiet: u32 = 0;
    const past_due = table.borrowExpired(std.math.maxInt(i64), &quiet).?;
    table.endBorrow(past_due.ticket);

    // One live RPC: the budget comes off, because an RPC ends when its own
    // exchange does and no client budget can name that.
    session.entries[0] = .{ .active = true, .client_id = 1 };
    boundWhenQuiet(&session);

    var relaying: u32 = 0;
    try testing.expect(table.borrowExpired(std.math.maxInt(i64), &relaying) == null);
    try testing.expectEqual(@as(usize, 1), table.liveCount());

    // The RPC finished, so the next quiet pass puts the bound back.
    session.entries[0] = .{};
    boundWhenQuiet(&session);

    var after: u32 = 0;
    const cut_again = table.borrowExpired(std.math.maxInt(i64), &after).?;
    table.endBorrow(cut_again.ticket);
}
