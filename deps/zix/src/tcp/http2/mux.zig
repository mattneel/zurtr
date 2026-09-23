//! HTTP/2 multiplexed connection state machine for the .EPOLL / .URING dispatch models.
//!
//! What:
//! - Resumable, non-blocking h2c. One `MuxConn` per fd. The read accumulator `rbuf` persists across
//!   readable events and holds a partial frame until the rest arrives, so a worker can drive many
//!   connections from one thread. Mirrors the gRPC mux loop (`grpc/core.zig`), adapted to the plain
//!   h2c handler model.
//!
//! Note:
//! - Connection-management frames and responses write straight to the fd via the `frame.*` helpers,
//!   which poll on EAGAIN for a non-blocking socket (see `frame.writeAllFD`). Wire order is preserved
//!   with no reply cork, and the existing `core` dispatch is reused unchanged. A handler runs inline
//!   on the worker, so like the gRPC mux model it must stay bounded.
//! - The h2c upgrade path (HTTP/1.1 `Upgrade: h2c`) is served minimally on the mux path: 101 then the
//!   connection preface, the request carried on stream 1 is not served (prior-knowledge clients, the
//!   common h2c case, are unaffected). The blocking ASYNC model serves it.

const std = @import("std");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");
const stream_body = @import("stream_body.zig");
const core = @import("core.zig");
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Context = @import("context.zig").Context;
const wallClockNs = @import("context.zig").wallClockNs;

/// The connection whose handler is running on this worker thread, set around each dispatch so the
/// flow-controlled send (`sendResponseStreamFD`) can reach the connection's send windows. Null on the
/// blocking non-mux serve paths, where the send falls back to an immediate, unmetered write.
pub threadlocal var active_conn: ?*MuxConn = null;

// --------------------------------------------------------- //

pub const ConnOutcome = enum { keep_alive, close };

const MuxPhase = enum { await_preface, await_upgrade, await_preface2, h2 };

const StreamState = enum { IDLE, OPEN, HALF_CLOSED_REMOTE, CLOSED };

/// One stream within a multiplexed connection, borrowed from the per-worker pool while open. `body` /
/// `header_scratch` are the pooled stream's own buffers, sized by the serve options and reused across
/// borrows. `next_free` links the stream into the pool freelist while it is idle.
const MuxStream = struct {
    id: u31 = 0,
    state: StreamState = .IDLE,
    headers: [frame.MAX_HEADERS]hpack.Header = undefined,
    header_count: usize = 0,
    header_scratch: []u8 = &.{},
    body: []u8 = &.{},
    body_len: usize = 0,
    end_headers: bool = false,
    end_stream: bool = false,

    /// Send-side flow control (RFC 7540 6.9). send_window is the peer's remaining receive window for
    /// this stream. pending_body is the still-unsent tail of a response body whose send was capped by
    /// a window. It points into caller-owned memory that must outlive the stream (the static cache),
    /// the slot stays borrowed until pending_body drains, and a WINDOW_UPDATE resumes it.
    send_window: i64 = 65535,
    pending_body: []const u8 = &.{},
    pending_end: bool = false,

    /// Freelist link, valid only while this stream sits idle in the per-worker pool.
    next_free: ?*MuxStream = null,
};

/// Per-connection h2 state for the multiplexed models. Heap-owned, one per fd, private to the
/// owning worker thread.
pub const MuxConn = struct {
    fd: std.posix.fd_t,
    opts: core.ServeOpts,
    /// Io backend, carried for the Context built at each muxDispatch. Worker-wide (the same value
    /// for every connection on this worker), not per-connection.
    io: std.Io,

    rbuf: []u8,
    rstart: usize,
    rend: usize,

    hpack_dec: hpack.HpackDecoder,

    /// Per-connection slot table. `streams[i]` is a stream borrowed from the per-worker pool, valid only
    /// while `slots[i]` is set. The array holds pointers (not inline stream state), so an idle
    /// connection reserves `max_streams` pointers, not `max_streams` full stream buffers.
    streams: []*MuxStream,
    slots: []bool,

    last_stream_id: u31,
    phase: MuxPhase,

    /// Connection-level send window (the peer's remaining receive window for all our DATA), and the
    /// peer's advertised SETTINGS_INITIAL_WINDOW_SIZE, the starting per-stream send window. Both
    /// govern how much response body we may send before a WINDOW_UPDATE.
    send_window: i64 = 65535,
    peer_init_window: i64 = 65535,

    /// The peer's SETTINGS_MAX_FRAME_SIZE (RFC 7540 6.5.2): the largest DATA frame it will accept.
    /// Defaults to 16384 until the peer advertises a larger value. Outbound DATA is sized by this,
    /// never by our own receive-side max_frame_size, which the peer may reject as FRAME_SIZE_ERROR.
    peer_max_frame_size: u32 = frame.DEFAULT_MAX_FRAME_SIZE,

    /// Allocate and initialize a connection. Returns null on allocation failure (caller closes fd).
    pub fn init(fd: std.posix.fd_t, opts: core.ServeOpts, io: std.Io) ?*MuxConn {
        const a = std.heap.smp_allocator;
        const conn = a.create(MuxConn) catch return null;

        const max_payload = opts.max_frame_size + frame.FRAME_PAYLOAD_SLACK;
        const rcap = @max(opts.conn_read_buf_min, max_payload + 9);
        const rbuf = a.alloc(u8, rcap) catch {
            a.destroy(conn);
            return null;
        };
        const streams = a.alloc(*MuxStream, opts.max_streams) catch {
            a.free(rbuf);
            a.destroy(conn);
            return null;
        };
        const slots = a.alloc(bool, opts.max_streams) catch {
            a.free(streams);
            a.free(rbuf);
            a.destroy(conn);
            return null;
        };

        // Slots start free. The heavy per-stream state (header table plus body / scratch buffers) is not
        // reserved here, it is borrowed from the per-worker pool on stream open. `streams[i]` is only
        // read while `slots[i]` is set, so the pointers stay unset until a slot is claimed.
        @memset(slots, false);

        conn.* = .{
            .fd = fd,
            .opts = opts,
            .io = io,
            .rbuf = rbuf,
            .rstart = 0,
            .rend = 0,
            .hpack_dec = hpack.HpackDecoder.init(),
            .streams = streams,
            .slots = slots,
            .last_stream_id = 0,
            .phase = .await_preface,
        };

        return conn;
    }

    pub fn deinit(self: *MuxConn) void {
        const a = std.heap.smp_allocator;

        // Return any still-open stream to the per-worker pool before freeing the connection's own arrays.
        for (self.slots, 0..) |in_use, slot| {
            if (in_use) releaseStream(self.streams[slot]);
        }

        a.free(self.slots);
        a.free(self.streams);
        a.free(self.rbuf);
        a.destroy(self);
    }
};

// --------------------------------------------------------- //
// Per-worker stream-slot pool. A worker drives many connections from one thread, and each connection
// borrows a MuxStream (its inline header table plus body / header-scratch buffers) only while a stream
// is open, returning it on close. The freelist is threadlocal (shared-nothing per worker, no atomics),
// so resident stream memory tracks concurrent streams on the worker, not connections times max_streams.
// Buffers are allocated once per pooled stream and reused across borrows, so the steady state does no
// per-stream allocation.

threadlocal var stream_pool: ?*MuxStream = null;

/// Borrow a stream from the per-worker pool, growing the pool with a fresh allocation when the freelist
/// is empty. The returned stream is reset to defaults (a pooled stream was cleared on release) with its
/// body / header-scratch buffers sized to at least the serve options.
///
/// Return:
/// - *MuxStream (clean, buffers ready)
/// - null when a growth allocation failed (the caller refuses the stream)
fn acquireStream(opts: core.ServeOpts) ?*MuxStream {
    const a = std.heap.smp_allocator;

    if (stream_pool) |st| {
        stream_pool = st.next_free;
        if (st.body.len >= opts.max_body and st.header_scratch.len >= opts.max_header_scratch) return st;

        // A borrower asking for a larger cap than this slot was sized to (non-uniform serve options on
        // one worker, never in normal use) drops the slot and falls through to a fresh allocation.
        a.free(st.body);
        a.free(st.header_scratch);
        a.destroy(st);
    }

    const st = a.create(MuxStream) catch return null;
    const body = a.alloc(u8, opts.max_body) catch {
        a.destroy(st);
        return null;
    };
    const scratch = a.alloc(u8, opts.max_header_scratch) catch {
        a.free(body);
        a.destroy(st);
        return null;
    };

    st.* = .{};
    st.body = body;
    st.header_scratch = scratch;

    return st;
}

/// Return a stream to the per-worker pool, resetting its state to defaults while keeping its buffers so
/// the next borrower reuses them. LIFO, so a hot stream is reused first.
fn releaseStream(st: *MuxStream) void {
    const body = st.body;
    const scratch = st.header_scratch;

    st.* = .{};
    st.body = body;
    st.header_scratch = scratch;
    st.next_free = stream_pool;

    stream_pool = st;
}

/// Free a connection slot: mark it unused and return its borrowed stream to the pool.
fn releaseSlot(conn: *MuxConn, slot: usize) void {
    conn.slots[slot] = false;
    releaseStream(conn.streams[slot]);
}

/// Claim a free slot for a new stream, borrowing a stream from the pool. Returns the slot index, or
/// null when the connection is at max_streams or a pool allocation failed (the caller refuses the
/// stream).
fn slotFor(conn: *MuxConn, stream_id: u31) ?usize {
    for (conn.slots, 0..) |slot_in_use, i| {
        if (!slot_in_use) {
            const st = acquireStream(conn.opts) orelse return null;
            st.id = stream_id;

            conn.streams[i] = st;
            conn.slots[i] = true;

            return i;
        }
    }

    return null;
}

fn findSlot(stream_id: u31, streams: []*MuxStream, used: []bool) ?usize {
    for (used, 0..) |slot_in_use, i| {
        if (slot_in_use and streams[i].id == stream_id) return i;
    }

    return null;
}

/// Send the server SETTINGS frame (the connection preface reply).
fn sendServerSettings(conn: *MuxConn) void {
    frame.sendSettingsFD(conn.fd, &.{
        .{ frame.SETTINGS_MAX_CONCURRENT_STREAMS, @as(u32, @intCast(conn.opts.max_streams)) },
        .{ frame.SETTINGS_INITIAL_WINDOW_SIZE, 65535 },
        .{ frame.SETTINGS_MAX_FRAME_SIZE, conn.opts.max_frame_size },
        .{ frame.SETTINGS_ENABLE_PUSH, 0 },
    }) catch {};
}

/// Extract method / path from the decoded pseudo-headers and dispatch the stream. The reply is
/// written straight to the fd by the handler (via `frame.sendResponseFD`).
fn muxDispatch(handler: core.HandlerFn, conn: *MuxConn, slot: usize) void {
    const s = conn.streams[slot];
    var method: []const u8 = "GET";
    var raw_path: []const u8 = "/";
    for (s.headers[0..s.header_count]) |h| {
        switch (h.name.len) {
            5 => if (std.mem.eql(u8, h.name, ":path")) {
                raw_path = h.value;
            },
            7 => if (std.mem.eql(u8, h.name, ":method")) {
                method = h.value;
            },
            else => {},
        }
    }

    const split = Request.splitPath(raw_path);

    active_conn = conn;
    // Record the request key inputs for the response-cache API only when a cache is installed, so the
    // default (cache off) hot path pays no extra threadlocal writes. serveCached returns false without
    // a cache, so it never reads these when they go unset, and the next dispatch overwrites them.
    if (core.tl_cache != null) {
        core.tl_req_path = split.path;
        core.tl_req_body = s.body[0..s.body_len];
    }

    var req = Request{
        .method = method,
        .path = split.path,
        .query = split.query,
        .headers = s.headers[0..s.header_count],
        .body = s.body[0..s.body_len],
    };
    const deadline_ns: ?u64 = if (conn.opts.handler_timeout_ms > 0)
        wallClockNs() + @as(u64, conn.opts.handler_timeout_ms) * std.time.ns_per_ms
    else
        null;
    core.invokeHandler(handler, &req, conn.fd, s.id, conn.io, deadline_ns, conn.opts, conn.peer_max_frame_size);
    active_conn = null;

    // Free the slot unless the response body is parked on a window, then a WINDOW_UPDATE resumes it.
    if (s.pending_body.len == 0) releaseSlot(conn, slot);
}

/// Dispatch a stream whose END_STREAM has arrived, unless its body is short of (or past) the
/// content-length its own headers declared.
///
/// Note:
/// - RFC 9113 8.1.1 makes that request malformed, a stream error of type PROTOCOL_ERROR, so the
///   stream is reset and its slot freed instead. A handler is therefore never handed a body that is
///   not whole, which is the same promise the truncated-body answer makes on http1.
/// - A body past `max_body` is a different case, answered upstream with 413: that request is valid
///   h2 the engine will not carry, where this one is not valid h2 at all.
///
/// Param:
/// handler - core.HandlerFn (the router entry point)
/// conn - *MuxConn (the connection owning the stream)
/// slot - usize (the stream's slot index)
///
/// Return:
/// - void
fn dispatchWhole(handler: core.HandlerFn, conn: *MuxConn, slot: usize) void {
    const s = conn.streams[slot];
    if (!stream_body.isWhole(s.headers[0..s.header_count], s.body_len)) {
        frame.sendRstStreamFD(conn.fd, s.id, frame.ERR_PROTOCOL_ERROR) catch {};
        releaseSlot(conn, slot);

        return;
    }

    muxDispatch(handler, conn, slot);
}

/// Whether any stream is still waiting for the rest of its request. A slot held only by a parked
/// response body does not count: that request arrived whole and the debt is ours, not the peer's.
///
/// Param:
/// conn - *const MuxConn (the connection to inspect)
///
/// Return:
/// - bool (true when a request was in flight)
pub fn requestInFlight(conn: *const MuxConn) bool {
    for (conn.slots, 0..) |in_use, slot| {
        if (in_use and !conn.streams[slot].end_stream) return true;
    }

    return false;
}

/// What a peer gets when it hangs up part way through a request.
///
/// Note:
/// - A stream the peer opened and never ended is a request that never finished arriving. GOAWAY says
///   the connection ended by decision, where a bare close reads the same to the peer as a crash, a
///   timeout, or a dropped connection. h2 gives a client RST_STREAM and GOAWAY to abandon work, so
///   dropping the transport mid-stream is a protocol error rather than an ordinary end.
/// - A connection with no request in flight closes without a byte, which is the ordinary end of a
///   connection and not an error.
/// - Nothing is dispatched either way: the partial request is dropped, never served.
///
/// Param:
/// conn - *MuxConn (the connection whose peer just hung up)
///
/// Return:
/// - bool (true when a GOAWAY was written)
pub fn hangupGoaway(conn: *MuxConn) bool {
    if (!requestInFlight(conn)) return false;

    frame.sendGoawayFD(conn.fd, conn.last_stream_id, frame.ERR_PROTOCOL_ERROR) catch {};

    return true;
}

/// Send DATA for `body` up to the connection and stream send windows and the max frame size. What
/// does not fit is parked on the stream (`pending_body`) for a later WINDOW_UPDATE. END_STREAM rides
/// the final frame only once the whole body has gone out.
fn pumpBody(conn: *MuxConn, stream: *MuxStream, body: []const u8, end: bool) void {
    var off: usize = 0;
    while (off < body.len) {
        const room = @min(conn.send_window, stream.send_window);
        if (room <= 0) break;

        const cap = @min(@as(i64, conn.peer_max_frame_size), room);
        const chunk = @min(body.len - off, @as(usize, @intCast(cap)));
        const is_last = end and (off + chunk == body.len);

        frame.writeFrameHeaderFD(conn.fd, .{
            .length = @intCast(chunk),
            .frame_type = frame.FRAME_TYPE_DATA,
            .flags = if (is_last) frame.FLAG_END_STREAM else 0,
            .stream_id = stream.id,
        }) catch break;
        frame.writeAllFD(conn.fd, body[off..][0..chunk]) catch break;

        conn.send_window -= @intCast(chunk);
        stream.send_window -= @intCast(chunk);
        off += chunk;
    }

    if (off < body.len) {
        stream.pending_body = body[off..];
        stream.pending_end = end;
    } else {
        stream.pending_body = &.{};
        stream.pending_end = false;
    }
}

/// Resume one parked stream after its window grew. Frees the slot once the body fully drains.
fn resumeStream(conn: *MuxConn, slot: usize) void {
    const stream = conn.streams[slot];
    if (stream.pending_body.len == 0) return;

    pumpBody(conn, stream, stream.pending_body, stream.pending_end);
    if (stream.pending_body.len == 0) releaseSlot(conn, slot);
}

/// Resume every parked stream after the connection window grew.
fn resumeAll(conn: *MuxConn) void {
    for (conn.slots, 0..) |in_use, slot| {
        if (in_use and conn.streams[slot].pending_body.len > 0) resumeStream(conn, slot);
    }
}

/// Write the response HEADERS frame (status, content-type, optional content-encoding, content-length).
fn sendRespHeadersFD(fd: std.posix.fd_t, sid: u31, status: u16, content_type: []const u8, content_encoding: []const u8, content_length: usize, end_stream: bool) void {
    var hdr_buf: [frame.HPACK_ENCODE_SCRATCH]u8 = undefined;

    // The [:status, content-type, content-encoding] prefix is served from a per-triple cache, only
    // content-length (which varies) is encoded per call. This path always carries content-length.
    const hblock = hdr_buf[0..hpack.respHeaderBlock(&hdr_buf, status, content_type, content_encoding, content_length)];
    const flags: u8 = if (end_stream) frame.FLAG_END_HEADERS | frame.FLAG_END_STREAM else frame.FLAG_END_HEADERS;

    frame.writeFrameHeaderFD(fd, .{ .length = @intCast(hblock.len), .frame_type = frame.FRAME_TYPE_HEADERS, .flags = flags, .stream_id = sid }) catch return;
    frame.writeAllFD(fd, hblock) catch return;
}

/// Send a response with HTTP/2 send-side flow control: HEADERS, then the body in DATA frames capped
/// by the peer's connection and stream windows, the remainder parked and resumed by WINDOW_UPDATE.
///
/// Note:
/// - The body is referenced, not copied, so it must outlive the stream (a process-lifetime cache, not
///   a per-request scratch buffer). For small transient bodies use frame.sendResponseFD instead.
/// - With no active connection context (the blocking non-mux serve paths) it falls back to an
///   immediate, unmetered send.
pub fn sendResponseStreamFD(fd: std.posix.fd_t, sid: u31, status: u16, content_type: []const u8, content_encoding: []const u8, body: []const u8) void {
    const conn = active_conn orelse {
        frame.sendResponseEncodedFD(fd, sid, status, content_type, content_encoding, body) catch {};
        return;
    };
    const slot = if (conn.fd == fd) findSlot(sid, conn.streams, conn.slots) else null;
    const s = if (slot) |sl| conn.streams[sl] else {
        frame.sendResponseEncodedFD(fd, sid, status, content_type, content_encoding, body) catch {};
        return;
    };

    sendRespHeadersFD(fd, sid, status, content_type, content_encoding, body.len, body.len == 0);
    if (body.len == 0) return;

    pumpBody(conn, s, body, true);
}

/// Handle the HTTP/1.1 h2c upgrade request. Minimal: 101 then await the preface. The carried
/// stream-1 request is not served on the mux path.
fn muxHandleUpgrade(conn: *MuxConn) ConnOutcome {
    const buf = conn.rbuf[conn.rstart..conn.rend];
    const marker = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse {
        if (conn.rend == conn.rbuf.len) return .close;
        return .keep_alive;
    };
    const hdr_end = marker + 4;

    const upgrade_val = getHttp1Header(buf[0..hdr_end], "upgrade");
    const is_h2c = upgrade_val != null and std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade_val.?, " "), "h2c");
    if (!is_h2c) {
        frame.writeAllFD(conn.fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n") catch {};
        return .close;
    }

    frame.writeAllFD(conn.fd, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n") catch {};
    conn.rstart += hdr_end;
    conn.phase = .await_preface2;

    return .keep_alive;
}

fn getHttp1Header(buf: []const u8, name: []const u8) ?[]const u8 {
    const first_crlf = std.mem.indexOf(u8, buf, "\r\n") orelse return null;
    var pos = first_crlf + 2;
    while (pos < buf.len) {
        const line_end = std.mem.indexOfPos(u8, buf, pos, "\r\n") orelse break;
        const line = buf[pos..line_end];
        if (line.len == 0) break;
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            if (std.ascii.eqlIgnoreCase(line[0..colon], name)) {
                var val_start: usize = colon + 1;
                while (val_start < line.len and line[val_start] == ' ') val_start += 1;
                return line[val_start..];
            }
        }
        pos = line_end + 2;
    }

    return null;
}

/// Advance the connection through the preface phases, then process buffered frames.
fn muxProcess(handler: core.HandlerFn, conn: *MuxConn) ConnOutcome {
    switch (conn.phase) {
        .await_preface => {
            const avail = conn.rend - conn.rstart;
            if (avail < 3) return .keep_alive;

            if (!std.mem.eql(u8, conn.rbuf[conn.rstart..][0..3], "PRI")) {
                conn.phase = .await_upgrade;
                return muxHandleUpgrade(conn);
            }
            if (avail < frame.PREFACE.len) return .keep_alive;
            if (!std.mem.eql(u8, conn.rbuf[conn.rstart..][0..frame.PREFACE.len], frame.PREFACE)) {
                frame.sendGoawayFD(conn.fd, 0, frame.ERR_PROTOCOL_ERROR) catch {};
                return .close;
            }

            conn.rstart += frame.PREFACE.len;
            sendServerSettings(conn);
            conn.phase = .h2;
        },

        .await_upgrade => return muxHandleUpgrade(conn),

        .await_preface2 => {
            const avail = conn.rend - conn.rstart;
            if (avail < frame.PREFACE.len) return .keep_alive;
            if (!std.mem.eql(u8, conn.rbuf[conn.rstart..][0..frame.PREFACE.len], frame.PREFACE)) {
                frame.sendGoawayFD(conn.fd, 0, frame.ERR_PROTOCOL_ERROR) catch {};
                return .close;
            }

            conn.rstart += frame.PREFACE.len;
            sendServerSettings(conn);
            conn.phase = .h2;
        },

        .h2 => {},
    }

    return muxFrameLoop(handler, conn);
}

/// The h2 frame loop over buffered bytes for a connection in the .h2 phase.
fn muxFrameLoop(handler: core.HandlerFn, conn: *MuxConn) ConnOutcome {
    const max_payload = conn.opts.max_frame_size + frame.FRAME_PAYLOAD_SLACK;

    while (true) {
        const avail = conn.rend - conn.rstart;
        if (avail < 9) return .keep_alive;

        const fh = frame.parseFrameHeader(conn.rbuf[conn.rstart..][0..9]);
        if (fh.length > max_payload) {
            frame.sendGoawayFD(conn.fd, conn.last_stream_id, frame.ERR_FRAME_SIZE_ERROR) catch {};
            return .close;
        }
        if (avail < 9 + fh.length) return .keep_alive;

        conn.rstart += 9;
        const payload = conn.rbuf[conn.rstart..][0..fh.length];
        conn.rstart += fh.length;

        switch (fh.frame_type) {
            frame.FRAME_TYPE_SETTINGS => {
                if ((fh.flags & frame.FLAG_ACK) != 0) continue;
                var i: usize = 0;
                while (i + 6 <= payload.len) : (i += 6) {
                    const id: u16 = (@as(u16, payload[i]) << 8) | payload[i + 1];
                    const val: u32 = (@as(u32, payload[i + 2]) << 24) | (@as(u32, payload[i + 3]) << 16) |
                        (@as(u32, payload[i + 4]) << 8) | payload[i + 5];
                    if (id == frame.SETTINGS_HEADER_TABLE_SIZE) {
                        conn.hpack_dec.max_size = val;
                        conn.hpack_dec.evictTo(val);
                    }
                    if (id == frame.SETTINGS_INITIAL_WINDOW_SIZE) {
                        // RFC 7540 6.9.2: a new initial window adjusts every open stream's send
                        // window by the delta.
                        const new_init: i64 = val;
                        const delta = new_init - conn.peer_init_window;
                        conn.peer_init_window = new_init;
                        for (conn.slots, 0..) |in_use, slot| {
                            if (in_use) conn.streams[slot].send_window += delta;
                        }
                    }
                    if (id == frame.SETTINGS_MAX_FRAME_SIZE) {
                        // RFC 7540 6.5.2: the peer's largest acceptable frame, valid range
                        // 16384..16777215. Cap outbound DATA to it so we never emit a frame the peer
                        // rejects with FRAME_SIZE_ERROR. An out-of-range value keeps the last good one.
                        if (val >= frame.DEFAULT_MAX_FRAME_SIZE and val <= 16_777_215) conn.peer_max_frame_size = val;
                    }
                }
                frame.sendSettingsAckFD(conn.fd) catch {};
                frame.sendWindowUpdateFD(conn.fd, 0, frame.DEFAULT_WINDOW_SIZE) catch {};
            },

            frame.FRAME_TYPE_WINDOW_UPDATE => {
                if (payload.len != 4) {
                    frame.sendGoawayFD(conn.fd, conn.last_stream_id, frame.ERR_FRAME_SIZE_ERROR) catch {};
                    return .close;
                }
                const raw: u32 = (@as(u32, payload[0]) << 24) | (@as(u32, payload[1]) << 16) |
                    (@as(u32, payload[2]) << 8) | payload[3];
                const inc: i64 = @intCast(raw & 0x7fffffff);

                if (fh.stream_id == 0) {
                    conn.send_window += inc;
                    resumeAll(conn);
                } else if (findSlot(fh.stream_id, conn.streams, conn.slots)) |slot| {
                    conn.streams[slot].send_window += inc;
                    resumeStream(conn, slot);
                }
            },

            frame.FRAME_TYPE_PING => {
                if ((fh.flags & frame.FLAG_ACK) != 0) continue;
                if (payload.len != 8) {
                    frame.sendGoawayFD(conn.fd, conn.last_stream_id, frame.ERR_FRAME_SIZE_ERROR) catch {};
                    return .close;
                }
                var p8: [8]u8 = undefined;
                @memcpy(&p8, payload[0..8]);
                frame.sendPingAckFD(conn.fd, p8) catch {};
            },

            frame.FRAME_TYPE_HEADERS => {
                const sid = fh.stream_id;
                if (sid == 0) {
                    frame.sendGoawayFD(conn.fd, conn.last_stream_id, frame.ERR_PROTOCOL_ERROR) catch {};
                    return .close;
                }
                if (sid <= conn.last_stream_id and sid % 2 == 1) {
                    frame.sendRstStreamFD(conn.fd, sid, frame.ERR_STREAM_CLOSED) catch {};
                    continue;
                }
                conn.last_stream_id = @max(conn.last_stream_id, sid);

                const slot = slotFor(conn, sid) orelse {
                    frame.sendRstStreamFD(conn.fd, sid, frame.ERR_REFUSED_STREAM) catch {};
                    continue;
                };
                const s = conn.streams[slot];
                s.id = sid;
                s.state = .OPEN;
                s.header_count = 0;
                s.body_len = 0;
                s.end_headers = false;
                s.end_stream = false;
                s.send_window = conn.peer_init_window;
                s.pending_body = &.{};
                s.pending_end = false;

                var block = payload;
                var offset: usize = 0;
                var pad_len: usize = 0;
                if ((fh.flags & frame.FLAG_PADDED) != 0 and block.len > 0) {
                    pad_len = block[0];
                    offset = 1;
                }
                if ((fh.flags & frame.FLAG_PRIORITY) != 0 and offset + 5 <= block.len) {
                    offset += 5;
                }
                if (pad_len + offset > block.len) {
                    frame.sendGoawayFD(conn.fd, conn.last_stream_id, frame.ERR_PROTOCOL_ERROR) catch {};
                    return .close;
                }
                block = block[offset .. block.len - pad_len];

                s.header_count = conn.hpack_dec.decode(block, &s.headers, s.header_scratch) catch {
                    frame.sendRstStreamFD(conn.fd, sid, frame.ERR_COMPRESSION_ERROR) catch {};
                    releaseSlot(conn, slot);
                    continue;
                };
                s.end_headers = (fh.flags & frame.FLAG_END_HEADERS) != 0;
                s.end_stream = (fh.flags & frame.FLAG_END_STREAM) != 0;

                if (s.end_headers and s.end_stream) {
                    dispatchWhole(handler, conn, slot);
                }
            },

            frame.FRAME_TYPE_CONTINUATION => {
                const sid = fh.stream_id;
                const slot = findSlot(sid, conn.streams, conn.slots) orelse {
                    frame.sendGoawayFD(conn.fd, conn.last_stream_id, frame.ERR_PROTOCOL_ERROR) catch {};
                    return .close;
                };
                const s = conn.streams[slot];
                const count = conn.hpack_dec.decode(payload, s.headers[s.header_count..], s.header_scratch) catch {
                    frame.sendRstStreamFD(conn.fd, sid, frame.ERR_COMPRESSION_ERROR) catch {};
                    releaseSlot(conn, slot);
                    continue;
                };
                s.header_count += count;
                s.end_headers = (fh.flags & frame.FLAG_END_HEADERS) != 0;
                if (s.end_headers and s.end_stream) {
                    dispatchWhole(handler, conn, slot);
                }
            },

            frame.FRAME_TYPE_DATA => {
                const sid = fh.stream_id;
                if (sid == 0) {
                    frame.sendGoawayFD(conn.fd, conn.last_stream_id, frame.ERR_PROTOCOL_ERROR) catch {};
                    return .close;
                }
                const slot = findSlot(sid, conn.streams, conn.slots) orelse {
                    frame.sendRstStreamFD(conn.fd, sid, frame.ERR_STREAM_CLOSED) catch {};
                    continue;
                };
                const stream = conn.streams[slot];

                var data = payload;
                var pad_len: usize = 0;
                if ((fh.flags & frame.FLAG_PADDED) != 0 and data.len > 0) {
                    pad_len = data[0];
                    data = data[1..];
                }
                if (pad_len > data.len) {
                    frame.sendGoawayFD(conn.fd, conn.last_stream_id, frame.ERR_PROTOCOL_ERROR) catch {};
                    return .close;
                }
                data = data[0 .. data.len - pad_len];

                // A body past max_body sheds the stream instead of truncating it: 413 with
                // END_STREAM, slot released, so a corrupt body never dispatches. A follow-up
                // DATA frame finds no slot and is answered with RST_STREAM above. Only the
                // connection window is credited for the discarded bytes (the stream is done,
                // the connection must stay usable for its other streams).
                if (data.len > stream.body.len - stream.body_len) {
                    if (data.len > 0) frame.sendWindowUpdateFD(conn.fd, 0, @intCast(data.len)) catch {};
                    sendRespHeadersFD(conn.fd, sid, 413, "text/plain", "", 0, true);
                    releaseSlot(conn, slot);
                    continue;
                }

                if (data.len > 0) {
                    frame.sendWindowUpdateFD(conn.fd, 0, @intCast(data.len)) catch {};
                    frame.sendWindowUpdateFD(conn.fd, sid, @intCast(data.len)) catch {};
                }

                @memcpy(stream.body[stream.body_len..][0..data.len], data);
                stream.body_len += data.len;

                stream.end_stream = (fh.flags & frame.FLAG_END_STREAM) != 0;
                if (stream.end_stream) {
                    dispatchWhole(handler, conn, slot);
                }
            },

            frame.FRAME_TYPE_RST_STREAM => {
                if (findSlot(fh.stream_id, conn.streams, conn.slots)) |slot| releaseSlot(conn, slot);
            },

            frame.FRAME_TYPE_GOAWAY => return .close,
            frame.FRAME_TYPE_PRIORITY => {},
            else => {},
        }
    }
}

/// Process the bytes already in `rbuf` for a connection whose read accumulator a ring recv has just
/// filled. Unlike `onReadable` there is no read loop and no fd flush at the end: the .URING worker
/// owns the recv and re-arms it after this returns. Responses and connection frames are written
/// straight to the fd during processing, exactly as on the .EPOLL path.
///
/// Return:
/// - .close when a protocol error occurred or the handshake was rejected
pub fn processRing(handler: core.HandlerFn, conn: *MuxConn) ConnOutcome {
    return muxProcess(handler, conn);
}

/// Drive one readable event: read available bytes (non-blocking), then process complete frames.
/// Responses and connection frames are written straight to the fd during processing.
///
/// Return:
/// - .close when the peer closed, a protocol error occurred, or the handshake was rejected
pub fn onReadable(handler: core.HandlerFn, conn: *MuxConn) ConnOutcome {
    while (true) {
        if (conn.rstart == conn.rend) {
            conn.rstart = 0;
            conn.rend = 0;
        } else if (conn.rend == conn.rbuf.len) {
            const n = conn.rend - conn.rstart;
            std.mem.copyForwards(u8, conn.rbuf[0..n], conn.rbuf[conn.rstart..conn.rend]);
            conn.rstart = 0;
            conn.rend = n;
        }

        if (conn.rend == conn.rbuf.len) return .close;

        const got = std.posix.read(conn.fd, conn.rbuf[conn.rend..]) catch |err| switch (err) {
            error.WouldBlock => return .keep_alive,
            else => return .close,
        };
        if (got == 0) {
            _ = hangupGoaway(conn);

            return .close;
        }
        conn.rend += got;

        if (muxProcess(handler, conn) == .close) return .close;
    }
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix http2: mux sendResponseStreamFD paces a large body by the send window" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    const fds = try std.Io.Threaded.pipe2(.{});
    defer _ = std.posix.system.close(fds[0]);
    // the write end is closed explicitly below to signal EOF, so it is not deferred.

    const opts = core.ServeOpts{ .max_streams = 4, .max_body = 1024, .max_header_scratch = 1024 };
    const conn = MuxConn.init(fds[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();

    // tiny windows so a modest body must be paced across several WINDOW_UPDATEs
    conn.send_window = 100;
    conn.peer_init_window = 100;

    const slot = slotFor(conn, 1).?;
    const s = conn.streams[slot];
    s.id = 1;
    s.state = .OPEN;
    s.send_window = 100;
    s.pending_body = &.{};

    var body: [250]u8 = undefined;
    @memset(&body, 'z');

    active_conn = conn;
    sendResponseStreamFD(fds[1], 1, 200, "text/plain", "", &body);
    active_conn = null;

    // 100 of 250 went out, 150 parked, slot retained, connection window drained to 0
    try std.testing.expectEqual(@as(usize, 150), s.pending_body.len);
    try std.testing.expect(conn.slots[slot]);
    try std.testing.expectEqual(@as(i64, 0), conn.send_window);

    // grow the windows and resume: 100 more out, 50 parked, slot still held
    conn.send_window += 100;
    s.send_window += 100;
    resumeStream(conn, slot);
    try std.testing.expectEqual(@as(usize, 50), s.pending_body.len);
    try std.testing.expect(conn.slots[slot]);

    // grow again and resume: the last 50 go out with END_STREAM, the slot is freed
    conn.send_window += 100;
    s.send_window += 100;
    resumeStream(conn, slot);
    try std.testing.expectEqual(@as(usize, 0), s.pending_body.len);
    try std.testing.expect(!conn.slots[slot]);

    // drain the pipe: total DATA bytes equal the body, the final DATA frame carries END_STREAM, and
    // no single DATA frame exceeded the 100-byte window slice.
    _ = std.posix.system.close(fds[1]);
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const got = std.posix.read(fds[0], buf[total..]) catch break;
        if (got == 0) break;
        total += got;
    }

    var off: usize = 0;
    var data_bytes: usize = 0;
    var last_data_flags: u8 = 0;
    while (off + 9 <= total) {
        const fh = frame.parseFrameHeader(buf[off..][0..9]);
        off += 9;
        if (fh.frame_type == frame.FRAME_TYPE_DATA) {
            try std.testing.expect(fh.length <= 100);
            data_bytes += fh.length;
            last_data_flags = fh.flags;
        }
        off += fh.length;
    }

    try std.testing.expectEqual(@as(usize, 250), data_bytes);
    try std.testing.expect((last_data_flags & frame.FLAG_END_STREAM) != 0);
}

var fc_test_body: [5000]u8 = undefined;

fn fcTestHandler(_: *Request, res: *Response, _: *Context) anyerror!void {
    sendResponseStreamFD(res.fd, res.sid, 200, "text/plain", "", &fc_test_body);
}

const fc_test_router = core.Router(&[_]core.Route{.{ .path = "/", .handler = fcTestHandler }});

fn feedFrame(conn: *MuxConn, ftype: u8, flags: u8, sid: u31, payload: []const u8) void {
    var fh: [9]u8 = undefined;
    frame.encodeFrameHeader(&fh, .{ .length = @intCast(payload.len), .frame_type = ftype, .flags = flags, .stream_id = sid });
    @memcpy(conn.rbuf[conn.rend..][0..9], &fh);
    conn.rend += 9;
    @memcpy(conn.rbuf[conn.rend..][0..payload.len], payload);
    conn.rend += payload.len;
}

test "zix http2: mux parks a body then resumes it across WINDOW_UPDATE in the frame loop" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    @memset(&fc_test_body, 'q');

    const fds = try std.Io.Threaded.pipe2(.{});
    defer _ = std.posix.system.close(fds[0]);
    defer _ = std.posix.system.close(fds[1]);

    const opts = core.ServeOpts{ .max_streams = 4, .max_body = 256, .max_header_scratch = 1024 };
    const conn = MuxConn.init(fds[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;
    conn.send_window = 100;
    conn.peer_init_window = 100;

    // request: HEADERS GET / on stream 1, END_HEADERS | END_STREAM, which dispatches the handler
    var hblk: [128]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&hblk);
    try enc.writeHeader(":method", "GET");
    try enc.writeHeader(":path", "/");
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS | frame.FLAG_END_STREAM, 1, enc.encoded());

    _ = muxFrameLoop(fc_test_router.dispatch, conn);

    // the handler sent 100 of 5000 (the window) and parked the rest, the slot stays held
    const slot = findSlot(1, conn.streams, conn.slots).?;
    try std.testing.expectEqual(@as(usize, 4900), conn.streams[slot].pending_body.len);
    try std.testing.expectEqual(@as(i64, 0), conn.send_window);

    // grow the connection then the stream window by 1000, the frame loop resumes the parked body
    const inc = [4]u8{ 0, 0, 0x03, 0xE8 }; // +1000
    feedFrame(conn, frame.FRAME_TYPE_WINDOW_UPDATE, 0, 0, &inc);
    feedFrame(conn, frame.FRAME_TYPE_WINDOW_UPDATE, 0, 1, &inc);
    _ = muxFrameLoop(fc_test_router.dispatch, conn);

    // 1000 more went out (the min of the two windows), 3900 remains parked
    try std.testing.expectEqual(@as(usize, 3900), conn.streams[slot].pending_body.len);
}

var ae_seen_buf: [128]u8 = undefined;
var ae_seen_len: usize = 0;

fn aeCheckHandler(req: *Request, res: *Response, _: *Context) anyerror!void {
    ae_seen_len = 0;
    for (req.headers) |h| {
        if (std.mem.eql(u8, h.name, "accept-encoding")) {
            @memcpy(ae_seen_buf[0..h.value.len], h.value);
            ae_seen_len = h.value.len;
        }
    }

    try res.sendText("ok");
}

const ae_router = core.Router(&[_]core.Route{.{ .path = "/static/x", .handler = aeCheckHandler }});

test "zix http2: mux passes the accept-encoding request header to the handler" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    const fds = try std.Io.Threaded.pipe2(.{});
    defer _ = std.posix.system.close(fds[0]);
    defer _ = std.posix.system.close(fds[1]);

    const opts = core.ServeOpts{ .max_streams = 4, .max_body = 256, .max_header_scratch = 1024 };
    const conn = MuxConn.init(fds[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    var hblk: [256]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&hblk);
    try enc.writeHeader(":method", "GET");
    try enc.writeHeader(":path", "/static/x");
    try enc.writeHeader("accept-encoding", "br;q=1, gzip;q=0.8");
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS | frame.FLAG_END_STREAM, 1, enc.encoded());

    ae_seen_len = 0;
    _ = muxFrameLoop(ae_router.dispatch, conn);

    try std.testing.expectEqualStrings("br;q=1, gzip;q=0.8", ae_seen_buf[0..ae_seen_len]);
}

test "zix http2: mux pooled stream is reused and reset clean on release" {
    const opts = core.ServeOpts{ .max_streams = 4, .max_body = 128, .max_header_scratch = 64 };

    // a fresh borrow carries buffers sized to at least the serve options
    const first = acquireStream(opts) orelse return error.OutOfMemory;
    try std.testing.expect(first.body.len >= 128);
    try std.testing.expect(first.header_scratch.len >= 64);

    // dirty every field a request would touch, then return the stream to the pool
    first.id = 7;
    first.state = .OPEN;
    first.header_count = 3;
    first.body_len = 99;
    first.pending_body = "parked";
    first.send_window = 12;
    releaseStream(first);

    // the next borrow is LIFO, so it is the same object, now reset to defaults with buffers retained
    const again = acquireStream(opts) orelse return error.OutOfMemory;
    try std.testing.expectEqual(first, again);
    try std.testing.expectEqual(@as(u31, 0), again.id);
    try std.testing.expectEqual(StreamState.IDLE, again.state);
    try std.testing.expectEqual(@as(usize, 0), again.header_count);
    try std.testing.expectEqual(@as(usize, 0), again.body_len);
    try std.testing.expectEqual(@as(usize, 0), again.pending_body.len);
    try std.testing.expectEqual(@as(i64, 65535), again.send_window);
    try std.testing.expect(again.body.len >= 128);

    releaseStream(again);
}

test "zix http2: mux DATA past max_body sheds the stream with 413 instead of truncating" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    const fds = try std.Io.Threaded.pipe2(.{});
    defer _ = std.posix.system.close(fds[0]);
    // the write end is closed explicitly below to signal EOF, so it is not deferred.

    const opts = core.ServeOpts{ .max_streams = 4, .max_body = 16, .max_header_scratch = 1024 };
    const conn = MuxConn.init(fds[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    // request: HEADERS POST / on stream 1 (no END_STREAM), which opens the slot
    var hblk: [128]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&hblk);
    try enc.writeHeader(":method", "POST");
    try enc.writeHeader(":path", "/");
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS, 1, enc.encoded());
    try std.testing.expectEqual(ConnOutcome.keep_alive, muxFrameLoop(fc_test_router.dispatch, conn));

    // fill the body to 8 bytes short of its buffer (a pooled stream's buffer may exceed
    // max_body, the overflow boundary is the buffer itself), then send a 32-byte DATA
    const open_slot = findSlot(1, conn.streams, conn.slots).?;
    conn.streams[open_slot].body_len = conn.streams[open_slot].body.len - 8;

    const oversized: [32]u8 = @splat(0xaa);
    feedFrame(conn, frame.FRAME_TYPE_DATA, frame.FLAG_END_STREAM, 1, &oversized);
    try std.testing.expectEqual(ConnOutcome.keep_alive, muxFrameLoop(fc_test_router.dispatch, conn));

    // the stream is shed: slot freed, so a follow-up DATA frame finds no slot and is RST
    try std.testing.expect(findSlot(1, conn.streams, conn.slots) == null);
    feedFrame(conn, frame.FRAME_TYPE_DATA, 0, 1, oversized[0..8]);
    try std.testing.expectEqual(ConnOutcome.keep_alive, muxFrameLoop(fc_test_router.dispatch, conn));

    _ = std.posix.system.close(fds[1]);
    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const got = std.posix.read(fds[0], buf[total..]) catch break;
        if (got == 0) break;
        total += got;
    }

    // wire: connection window credited for the discarded bytes (stream window not),
    // a 413 HEADERS with END_HEADERS | END_STREAM, then RST_STREAM(STREAM_CLOSED)
    var saw_conn_credit = false;
    var saw_stream_credit = false;
    var saw_413 = false;
    var saw_rst_closed = false;
    var dec = hpack.HpackDecoder.init();
    var off: usize = 0;
    while (off + 9 <= total) {
        const fh = frame.parseFrameHeader(buf[off..][0..9]);
        off += 9;
        const payload = buf[off..][0..fh.length];
        off += fh.length;

        switch (fh.frame_type) {
            frame.FRAME_TYPE_WINDOW_UPDATE => {
                if (fh.stream_id == 0) saw_conn_credit = true;
                if (fh.stream_id == 1) saw_stream_credit = true;
            },
            frame.FRAME_TYPE_HEADERS => {
                try std.testing.expect((fh.flags & frame.FLAG_END_STREAM) != 0);
                try std.testing.expect((fh.flags & frame.FLAG_END_HEADERS) != 0);

                var hdrs: [frame.MAX_HEADERS]hpack.Header = undefined;
                var scratch: [256]u8 = undefined;
                const count = try dec.decode(payload, &hdrs, &scratch);
                for (hdrs[0..count]) |hdr| {
                    if (std.mem.eql(u8, hdr.name, ":status") and std.mem.eql(u8, hdr.value, "413")) saw_413 = true;
                }
            },
            frame.FRAME_TYPE_RST_STREAM => {
                const code: u32 = (@as(u32, payload[0]) << 24) | (@as(u32, payload[1]) << 16) |
                    (@as(u32, payload[2]) << 8) | payload[3];
                if (fh.stream_id == 1 and code == frame.ERR_STREAM_CLOSED) saw_rst_closed = true;
            },
            else => {},
        }
    }

    try std.testing.expect(saw_conn_credit);
    try std.testing.expect(!saw_stream_credit);
    try std.testing.expect(saw_413);
    try std.testing.expect(saw_rst_closed);
}

var exact_body_seen: usize = 0;

fn exactBodyHandler(req: *Request, res: *Response, _: *Context) anyerror!void {
    exact_body_seen = req.body.len;

    try res.sendText("ok");
}

const exact_body_router = core.Router(&[_]core.Route{.{ .path = "/", .handler = exactBodyHandler }});

test "zix http2: mux DATA exactly filling max_body still dispatches the full body" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    const fds = try std.Io.Threaded.pipe2(.{});
    defer _ = std.posix.system.close(fds[0]);
    defer _ = std.posix.system.close(fds[1]);

    const opts = core.ServeOpts{ .max_streams = 4, .max_body = 16, .max_header_scratch = 1024 };
    const conn = MuxConn.init(fds[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    var hblk: [128]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&hblk);
    try enc.writeHeader(":method", "POST");
    try enc.writeHeader(":path", "/");
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS, 1, enc.encoded());
    _ = muxFrameLoop(exact_body_router.dispatch, conn);

    // fill the body to exactly 16 bytes short of its buffer, then a 16-byte DATA lands
    // flush on the boundary: it must copy and dispatch, not shed
    const open_slot = findSlot(1, conn.streams, conn.slots).?;
    const full_len = conn.streams[open_slot].body.len;
    conn.streams[open_slot].body_len = full_len - 16;

    const exact: [16]u8 = @splat(0xbb);
    feedFrame(conn, frame.FRAME_TYPE_DATA, frame.FLAG_END_STREAM, 1, &exact);

    exact_body_seen = 0;
    _ = muxFrameLoop(exact_body_router.dispatch, conn);

    try std.testing.expectEqual(full_len, exact_body_seen);
    try std.testing.expect(findSlot(1, conn.streams, conn.slots) == null);
}

test "zix http2: mux HEADERS past max_streams is refused, the open stream keeps its slot" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    const fds = try std.Io.Threaded.pipe2(.{});
    defer _ = std.posix.system.close(fds[0]);
    // the write end is closed explicitly below to signal EOF, so it is not deferred.

    const opts = core.ServeOpts{ .max_streams = 1, .max_body = 64, .max_header_scratch = 1024 };
    const conn = MuxConn.init(fds[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    // stream 1 opens and holds the single slot (no END_STREAM, body pending)
    var hblk: [128]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&hblk);
    try enc.writeHeader(":method", "POST");
    try enc.writeHeader(":path", "/");
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS, 1, enc.encoded());

    // stream 3 finds no free slot and must be refused, retry-safe for the client
    var hblk2: [128]u8 = undefined;
    var enc2 = hpack.HpackEncoder.init(&hblk2);
    try enc2.writeHeader(":method", "POST");
    try enc2.writeHeader(":path", "/");
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS, 3, enc2.encoded());

    try std.testing.expectEqual(ConnOutcome.keep_alive, muxFrameLoop(fc_test_router.dispatch, conn));
    try std.testing.expect(findSlot(1, conn.streams, conn.slots) != null);
    try std.testing.expect(findSlot(3, conn.streams, conn.slots) == null);

    _ = std.posix.system.close(fds[1]);
    var buf: [1024]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const got = std.posix.read(fds[0], buf[total..]) catch break;
        if (got == 0) break;
        total += got;
    }

    var saw_refused = false;
    var off: usize = 0;
    while (off + 9 <= total) {
        const fh = frame.parseFrameHeader(buf[off..][0..9]);
        off += 9;
        const payload = buf[off..][0..fh.length];
        off += fh.length;

        if (fh.frame_type == frame.FRAME_TYPE_RST_STREAM and fh.stream_id == 3) {
            const code: u32 = (@as(u32, payload[0]) << 24) | (@as(u32, payload[1]) << 16) |
                (@as(u32, payload[2]) << 8) | payload[3];
            if (code == frame.ERR_REFUSED_STREAM) saw_refused = true;
        }
    }

    try std.testing.expect(saw_refused);
}

test "zix http2: mux RST_STREAM reaps a slot parked on pending_body" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    @memset(&fc_test_body, 'r');

    const fds = try std.Io.Threaded.pipe2(.{});
    defer _ = std.posix.system.close(fds[0]);
    defer _ = std.posix.system.close(fds[1]);

    const opts = core.ServeOpts{ .max_streams = 4, .max_body = 256, .max_header_scratch = 1024 };
    const conn = MuxConn.init(fds[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;
    conn.send_window = 100;
    conn.peer_init_window = 100;

    // dispatch parks 4900 of the 5000-byte response on the tiny window, holding the slot
    var hblk: [128]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&hblk);
    try enc.writeHeader(":method", "GET");
    try enc.writeHeader(":path", "/");
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS | frame.FLAG_END_STREAM, 1, enc.encoded());
    _ = muxFrameLoop(fc_test_router.dispatch, conn);

    const slot = findSlot(1, conn.streams, conn.slots).?;
    try std.testing.expectEqual(@as(usize, 4900), conn.streams[slot].pending_body.len);

    // the peer cancels: the parked slot is released, nothing left to resume
    const cancel = [4]u8{ 0, 0, 0, 8 };
    feedFrame(conn, frame.FRAME_TYPE_RST_STREAM, 0, 1, &cancel);
    _ = muxFrameLoop(fc_test_router.dispatch, conn);

    try std.testing.expect(findSlot(1, conn.streams, conn.slots) == null);
}

test "zix http2: mux stream slots are pooled across connections" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    const opts = core.ServeOpts{ .max_streams = 4, .max_body = 128, .max_header_scratch = 64 };

    const fds = try std.Io.Threaded.pipe2(.{});
    defer _ = std.posix.system.close(fds[0]);
    defer _ = std.posix.system.close(fds[1]);

    // connection A borrows a slot, then releases it back to the per-worker pool
    const conn_a = MuxConn.init(fds[1], opts, undefined) orelse return error.OutOfMemory;
    const slot_a = slotFor(conn_a, 1).?;
    const stream_a = conn_a.streams[slot_a];
    try std.testing.expect(conn_a.slots[slot_a]);

    releaseSlot(conn_a, slot_a);
    try std.testing.expect(!conn_a.slots[slot_a]);
    conn_a.deinit();

    // a second connection reuses the same pooled stream (LIFO), so stream memory is shared per worker
    // and does not scale with the connection count
    const conn_b = MuxConn.init(fds[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn_b.deinit();

    const slot_b = slotFor(conn_b, 3).?;
    try std.testing.expectEqual(stream_a, conn_b.streams[slot_b]);
    try std.testing.expectEqual(@as(u31, 3), conn_b.streams[slot_b].id);

    releaseSlot(conn_b, slot_b);
}

// The static-h2 bench stalls when several large-body streams share one connection window: the first
// stream drains the window, the rest park, and every parked stream must resume as connection-level
// WINDOW_UPDATE credit arrives. The single-stream tests above never exercise more than one parked
// body at a time, so they miss a resumeAll that fails to drain the full parked set.
var multi_body: [4000]u8 = undefined;

fn multiBodyHandler(_: *Request, res: *Response, _: *Context) anyerror!void {
    sendResponseStreamFD(res.fd, res.sid, 200, "text/plain", "", &multi_body);
}

const multi_body_router = core.Router(&[_]core.Route{.{ .path = "/", .handler = multiBodyHandler }});

/// Read every byte currently in the pipe (non-blocking), tallying DATA payload and END_STREAM flags per
/// stream. Used by the flow-control drain tests to prove the whole body reached the wire.
const DrainTally = struct {
    data_bytes: usize = 0,
    end_streams: usize = 0,
};

fn drainDataTally(read_fd: std.posix.fd_t, write_fd: std.posix.fd_t, buf: []u8) DrainTally {
    // Half-close the writer so the drain read sees EOF once the buffered frames are consumed (the fd
    // itself stays open for the test's deferred close).
    _ = std.os.linux.shutdown(write_fd, std.os.linux.SHUT.WR);

    var total: usize = 0;
    while (total < buf.len) {
        const got = std.posix.read(read_fd, buf[total..]) catch break;
        if (got == 0) break;
        total += got;
    }

    var tally = DrainTally{};
    var off: usize = 0;
    while (off + 9 <= total) {
        const fh = frame.parseFrameHeader(buf[off..][0..9]);
        off += 9;
        if (fh.frame_type == frame.FRAME_TYPE_DATA) {
            tally.data_bytes += fh.length;
            if ((fh.flags & frame.FLAG_END_STREAM) != 0) tally.end_streams += 1;
        }
        off += fh.length;
    }

    return tally;
}

test "zix http2: mux resumes every parked stream sharing one connection window" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    @memset(&multi_body, 'm');

    // A socketpair's default buffer holds the whole reply set without blocking the writer, so a single
    // thread can drive the frame loop and read the wire back afterwards.
    var pair: [2]i32 = undefined;
    try std.testing.expect(std.posix.errno(std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = std.posix.system.close(pair[0]);
    defer _ = std.posix.system.close(pair[1]);

    const opts = core.ServeOpts{ .max_streams = 8, .max_body = 256, .max_header_scratch = 1024 };
    const conn = MuxConn.init(pair[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    // Large per-stream windows so the shared connection window (small here) is the sole bottleneck, the
    // same shape as a client that advertises a big stream window but grants the connection window in
    // steps.
    conn.send_window = 1000;
    conn.peer_init_window = 1 << 20;

    // four concurrent GETs (streams 1, 3, 5, 7), each dispatching the 4000-byte body
    const sids = [_]u31{ 1, 3, 5, 7 };
    for (sids) |sid| {
        var hblk: [64]u8 = undefined;
        var enc = hpack.HpackEncoder.init(&hblk);
        try enc.writeHeader(":method", "GET");
        try enc.writeHeader(":path", "/");
        feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS | frame.FLAG_END_STREAM, sid, enc.encoded());
    }
    _ = muxFrameLoop(multi_body_router.dispatch, conn);

    // stream 1 sent the 1000-byte window, the other three could not start: four slots still parked
    var parked: usize = 0;
    for (sids) |sid| {
        if (findSlot(sid, conn.streams, conn.slots)) |slot| {
            if (conn.streams[slot].pending_body.len > 0) parked += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 4), parked);
    try std.testing.expectEqual(@as(i64, 0), conn.send_window);

    // grant the connection window the full remaining credit (3000 + 3 * 4000), which must resume and
    // fully drain every parked stream
    const remaining: u32 = 3000 + 3 * 4000;
    const inc = [4]u8{
        @intCast((remaining >> 24) & 0x7f),
        @intCast((remaining >> 16) & 0xff),
        @intCast((remaining >> 8) & 0xff),
        @intCast(remaining & 0xff),
    };
    feedFrame(conn, frame.FRAME_TYPE_WINDOW_UPDATE, 0, 0, &inc);
    _ = muxFrameLoop(multi_body_router.dispatch, conn);

    // every slot is freed and every body reached the wire, each ending with END_STREAM
    for (sids) |sid| {
        try std.testing.expect(findSlot(sid, conn.streams, conn.slots) == null);
    }

    var buf: [64 * 1024]u8 = undefined;
    const tally = drainDataTally(pair[0], pair[1], &buf);
    try std.testing.expectEqual(@as(usize, 4 * multi_body.len), tally.data_bytes);
    try std.testing.expectEqual(@as(usize, 4), tally.end_streams);
}

test "zix http2: mux parks on an exhausted stream window until a stream WINDOW_UPDATE arrives" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    @memset(&multi_body, 'm');

    var pair: [2]i32 = undefined;
    try std.testing.expect(std.posix.errno(std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = std.posix.system.close(pair[0]);
    defer _ = std.posix.system.close(pair[1]);

    const opts = core.ServeOpts{ .max_streams = 4, .max_body = 256, .max_header_scratch = 1024 };
    const conn = MuxConn.init(pair[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    // Roomy connection window, tiny per-stream window: the stream window is the limit, so only a
    // stream-level WINDOW_UPDATE may resume the parked tail. A connection-level grant must not.
    conn.send_window = 1 << 20;
    conn.peer_init_window = 500;

    var hblk: [64]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&hblk);
    try enc.writeHeader(":method", "GET");
    try enc.writeHeader(":path", "/");
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS | frame.FLAG_END_STREAM, 1, enc.encoded());
    _ = muxFrameLoop(multi_body_router.dispatch, conn);

    const slot = findSlot(1, conn.streams, conn.slots).?;
    try std.testing.expectEqual(@as(usize, multi_body.len - 500), conn.streams[slot].pending_body.len);

    // a connection-level grant alone leaves the body parked (the stream window is still zero)
    const conn_inc = [4]u8{ 0, 0, 0x27, 0x10 }; // +10000
    feedFrame(conn, frame.FRAME_TYPE_WINDOW_UPDATE, 0, 0, &conn_inc);
    _ = muxFrameLoop(multi_body_router.dispatch, conn);
    try std.testing.expectEqual(@as(usize, multi_body.len - 500), conn.streams[slot].pending_body.len);

    // the stream-level grant resumes and fully drains the tail, freeing the slot
    const stream_inc = [4]u8{ 0, 0, 0x0f, 0xa0 }; // +4000
    feedFrame(conn, frame.FRAME_TYPE_WINDOW_UPDATE, 0, 1, &stream_inc);
    _ = muxFrameLoop(multi_body_router.dispatch, conn);
    try std.testing.expect(findSlot(1, conn.streams, conn.slots) == null);

    var buf: [8 * 1024]u8 = undefined;
    const tally = drainDataTally(pair[0], pair[1], &buf);
    try std.testing.expectEqual(@as(usize, multi_body.len), tally.data_bytes);
    try std.testing.expectEqual(@as(usize, 1), tally.end_streams);
}

// A body streamed to a peer that never advertised SETTINGS_MAX_FRAME_SIZE must be framed in <= 16384
// (the RFC 7540 default) DATA chunks, NOT the server's own larger max_frame_size: a peer rejects an
// over-sized frame with FRAME_SIZE_ERROR and tears the connection down (the static-h2 regression, where
// every file past 16 KiB failed while small files passed).
var mfs_body: [40000]u8 = undefined;

fn mfsHandler(_: *Request, res: *Response, _: *Context) anyerror!void {
    sendResponseStreamFD(res.fd, res.sid, 200, "application/octet-stream", "", &mfs_body);
}

const mfs_router = core.Router(&[_]core.Route{.{ .path = "/", .handler = mfsHandler }});

test "zix http2: outbound DATA frames respect the peer default max frame size, not the server's" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    @memset(&mfs_body, 'f');

    var pair: [2]i32 = undefined;
    try std.testing.expect(std.posix.errno(std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = std.posix.system.close(pair[0]);
    defer _ = std.posix.system.close(pair[1]);

    // Server configured with a 24 KiB max_frame_size (its own receive-side limit), larger than the
    // 16384 the peer will accept by default: outbound DATA must still cap at 16384.
    const opts = core.ServeOpts{ .max_streams = 4, .max_body = 256, .max_header_scratch = 1024, .max_frame_size = 24 * 1024 };
    const conn = MuxConn.init(pair[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    // The peer never sent SETTINGS_MAX_FRAME_SIZE, so its limit is the RFC default.
    try std.testing.expectEqual(@as(u32, frame.DEFAULT_MAX_FRAME_SIZE), conn.peer_max_frame_size);

    var hblk: [64]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&hblk);
    try enc.writeHeader(":method", "GET");
    try enc.writeHeader(":path", "/");
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS | frame.FLAG_END_STREAM, 1, enc.encoded());
    _ = muxFrameLoop(mfs_router.dispatch, conn);

    // Every DATA frame on the wire must be <= 16384, and together they must carry the whole body.
    var body_buf: [64 * 1024]u8 = undefined;
    _ = std.os.linux.shutdown(pair[1], std.os.linux.SHUT.WR);
    var total: usize = 0;
    while (total < body_buf.len) {
        const got = std.posix.read(pair[0], body_buf[total..]) catch break;
        if (got == 0) break;
        total += got;
    }

    var data_bytes: usize = 0;
    var frames: usize = 0;
    var off: usize = 0;
    while (off + 9 <= total) {
        const fh = frame.parseFrameHeader(body_buf[off..][0..9]);
        off += 9;
        if (fh.frame_type == frame.FRAME_TYPE_DATA) {
            try std.testing.expect(fh.length <= frame.DEFAULT_MAX_FRAME_SIZE);
            data_bytes += fh.length;
            frames += 1;
        }
        off += fh.length;
    }

    try std.testing.expectEqual(@as(usize, mfs_body.len), data_bytes);
    try std.testing.expect(frames >= 3); // 40000 / 16384 -> at least three frames

    // Once the peer advertises a larger max frame size, the mux records it for subsequent sends.
    const settings_mfs = [_]u8{ 0x00, 0x05, 0x00, 0x00, 0x60, 0x00 }; // SETTINGS_MAX_FRAME_SIZE = 24576
    feedFrame(conn, frame.FRAME_TYPE_SETTINGS, 0, 0, &settings_mfs);
    _ = muxFrameLoop(mfs_router.dispatch, conn);
    try std.testing.expectEqual(@as(u32, 24 * 1024), conn.peer_max_frame_size);
}

// The static public_dir fallback must obey the SAME rule as the streamed handler path above: DATA is
// capped by what the PEER advertised, never by the server's own receive-side max_frame_size. The
// static path reads its cap from Context, so this covers the plumbing that fills it.
const sfs_router = core.Router(&[_]core.Route{.{ .path = "/", .handler = mfsHandler }});

test "zix http2: static DATA frames respect the peer max frame size, not the server's" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Comfortably past 16384, so an unchecked cap would emit an oversized frame.
    var payload: [40000]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast('a' + index % 26);
    tmp.dir.writeFile(std.testing.io, .{ .sub_path = "big.bin", .data = &payload }) catch @panic("fixture write failed");

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var pair: [2]i32 = undefined;
    try std.testing.expect(std.posix.errno(std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = std.posix.system.close(pair[0]);
    defer _ = std.posix.system.close(pair[1]);

    // Server configured with a 24 KiB receive-side limit while the peer never advertised one, so its
    // ceiling is the RFC default. Reading the server's value here is the bug this guards.
    const opts = core.ServeOpts{
        .max_streams = 4,
        .max_body = 256,
        .max_header_scratch = 1024,
        .max_frame_size = 24 * 1024,
        .public_dir = root,
    };
    const conn = MuxConn.init(pair[1], opts, std.testing.io) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    try std.testing.expectEqual(@as(u32, frame.DEFAULT_MAX_FRAME_SIZE), conn.peer_max_frame_size);

    var hblk: [64]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&hblk);
    try enc.writeHeader(":method", "GET");
    try enc.writeHeader(":path", "/big.bin");
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS | frame.FLAG_END_STREAM, 1, enc.encoded());
    _ = muxFrameLoop(sfs_router.dispatch, conn);

    var wire: [64 * 1024]u8 = undefined;
    _ = std.os.linux.shutdown(pair[1], std.os.linux.SHUT.WR);
    var total: usize = 0;
    while (total < wire.len) {
        const got = std.posix.read(pair[0], wire[total..]) catch break;
        if (got == 0) break;
        total += got;
    }

    var data_bytes: usize = 0;
    var off: usize = 0;
    while (off + 9 <= total) {
        const fh = frame.parseFrameHeader(wire[off..][0..9]);
        off += 9;
        if (fh.frame_type == frame.FRAME_TYPE_DATA) {
            try std.testing.expect(fh.length <= frame.DEFAULT_MAX_FRAME_SIZE);
            data_bytes += fh.length;
        }
        off += fh.length;
    }

    try std.testing.expectEqual(@as(usize, payload.len), data_bytes);
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

var cl_dispatches: usize = 0;
var cl_body_len: usize = 0;

fn clHandler(req: *Request, res: *Response, _: *Context) anyerror!void {
    cl_dispatches += 1;
    cl_body_len = req.body.len;

    try res.sendText("ok");
}

const cl_router = core.Router(&[_]core.Route{.{ .path = "/", .handler = clHandler }});

/// Read every byte the connection wrote, tallying the reset codes and the statuses it answered with.
/// The write end is shut down first so the read ends at EOF rather than blocking.
const WireTally = struct {
    rst_protocol_error: usize = 0,
    goaway_protocol_error: usize = 0,
    status_200: usize = 0,
};

fn tallyWire(read_fd: std.posix.fd_t, write_fd: std.posix.fd_t, buf: []u8) WireTally {
    _ = std.os.linux.shutdown(write_fd, std.os.linux.SHUT.WR);

    var total: usize = 0;
    while (total < buf.len) {
        const got = std.posix.read(read_fd, buf[total..]) catch break;
        if (got == 0) break;
        total += got;
    }

    var tally = WireTally{};
    var dec = hpack.HpackDecoder.init();
    var off: usize = 0;
    while (off + 9 <= total) {
        const fh = frame.parseFrameHeader(buf[off..][0..9]);
        off += 9;
        if (off + fh.length > total) break;

        const payload = buf[off..][0..fh.length];
        off += fh.length;

        switch (fh.frame_type) {
            frame.FRAME_TYPE_RST_STREAM => {
                const code = std.mem.readInt(u32, payload[0..4], .big);
                if (code == frame.ERR_PROTOCOL_ERROR) tally.rst_protocol_error += 1;
            },
            frame.FRAME_TYPE_GOAWAY => {
                const code = std.mem.readInt(u32, payload[4..8], .big);
                if (code == frame.ERR_PROTOCOL_ERROR) tally.goaway_protocol_error += 1;
            },
            frame.FRAME_TYPE_HEADERS => {
                var hdrs: [frame.MAX_HEADERS]hpack.Header = undefined;
                var scratch: [256]u8 = undefined;
                const count = dec.decode(payload, &hdrs, &scratch) catch continue;
                for (hdrs[0..count]) |hdr| {
                    if (std.mem.eql(u8, hdr.name, ":status") and std.mem.eql(u8, hdr.value, "200")) tally.status_200 += 1;
                }
            },
            else => {},
        }
    }

    return tally;
}

/// Open a connection in the .h2 phase over a socketpair, ready to be fed frames.
fn openTestConn(fd: std.posix.fd_t, opts: core.ServeOpts) !*MuxConn {
    const conn = MuxConn.init(fd, opts, undefined) orelse return error.OutOfMemory;
    conn.phase = .h2;

    return conn;
}

/// Feed a POST whose headers declare `content_length` and whose DATA carries `body`, ending the
/// stream. The two disagree exactly when a truncated (or overlong) body is being modelled.
fn feedDeclaredPost(conn: *MuxConn, content_length: []const u8, body: []const u8) !void {
    var hblk: [128]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&hblk);
    try enc.writeHeader(":method", "POST");
    try enc.writeHeader(":path", "/");
    try enc.writeHeader("content-length", content_length);
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS, 1, enc.encoded());
    feedFrame(conn, frame.FRAME_TYPE_DATA, frame.FLAG_END_STREAM, 1, body);
}

test "zix http2: mux resets a stream whose body is short of its content-length" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var pair: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.posix.errno(std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = std.posix.system.close(pair[0]);

    const conn = try openTestConn(pair[1], .{ .max_streams = 4, .max_body = 1024, .max_header_scratch = 1024 });
    defer conn.deinit();

    // 100 bytes promised, 40 delivered, then END_STREAM: the request never finished arriving
    const short: [40]u8 = @splat('x');
    cl_dispatches = 0;
    try feedDeclaredPost(conn, "100", &short);
    try std.testing.expectEqual(ConnOutcome.keep_alive, muxFrameLoop(cl_router.dispatch, conn));

    // the handler never ran, so no truncated body was ever served
    try std.testing.expectEqual(@as(usize, 0), cl_dispatches);

    // the slot is freed, so the connection stays usable for its other streams
    try std.testing.expect(findSlot(1, conn.streams, conn.slots) == null);

    var buf: [4096]u8 = undefined;
    const tally = tallyWire(pair[0], pair[1], &buf);

    try std.testing.expectEqual(@as(usize, 1), tally.rst_protocol_error);
    try std.testing.expectEqual(@as(usize, 0), tally.status_200);
}

test "zix http2: mux serves a stream whose body matches its content-length" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var pair: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.posix.errno(std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = std.posix.system.close(pair[0]);

    const conn = try openTestConn(pair[1], .{ .max_streams = 4, .max_body = 1024, .max_header_scratch = 1024 });
    defer conn.deinit();

    const whole: [40]u8 = @splat('x');
    cl_dispatches = 0;
    cl_body_len = 0;
    try feedDeclaredPost(conn, "40", &whole);
    try std.testing.expectEqual(ConnOutcome.keep_alive, muxFrameLoop(cl_router.dispatch, conn));

    // the guard only sheds a body that disagrees with its own headers, an honest one still serves
    try std.testing.expectEqual(@as(usize, 1), cl_dispatches);
    try std.testing.expectEqual(@as(usize, 40), cl_body_len);

    var buf: [4096]u8 = undefined;
    const tally = tallyWire(pair[0], pair[1], &buf);

    try std.testing.expectEqual(@as(usize, 0), tally.rst_protocol_error);
    try std.testing.expectEqual(@as(usize, 1), tally.status_200);
}

test "zix http2: mux resets a stream whose body runs past its content-length" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var pair: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.posix.errno(std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = std.posix.system.close(pair[0]);

    const conn = try openTestConn(pair[1], .{ .max_streams = 4, .max_body = 1024, .max_header_scratch = 1024 });
    defer conn.deinit();

    const overlong: [40]u8 = @splat('x');
    cl_dispatches = 0;
    try feedDeclaredPost(conn, "10", &overlong);
    try std.testing.expectEqual(ConnOutcome.keep_alive, muxFrameLoop(cl_router.dispatch, conn));

    try std.testing.expectEqual(@as(usize, 0), cl_dispatches);

    var buf: [4096]u8 = undefined;
    const tally = tallyWire(pair[0], pair[1], &buf);

    try std.testing.expectEqual(@as(usize, 1), tally.rst_protocol_error);
}

test "zix http2: mux resets a stream that declares a body then ends with none" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var pair: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.posix.errno(std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = std.posix.system.close(pair[0]);

    const conn = try openTestConn(pair[1], .{ .max_streams = 4, .max_body = 1024, .max_header_scratch = 1024 });
    defer conn.deinit();

    // END_STREAM rides the HEADERS, so no DATA frame ever arrives for a promised 5 bytes
    var hblk: [128]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&hblk);
    try enc.writeHeader(":method", "POST");
    try enc.writeHeader(":path", "/");
    try enc.writeHeader("content-length", "5");
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS | frame.FLAG_END_STREAM, 1, enc.encoded());

    cl_dispatches = 0;
    try std.testing.expectEqual(ConnOutcome.keep_alive, muxFrameLoop(cl_router.dispatch, conn));

    try std.testing.expectEqual(@as(usize, 0), cl_dispatches);

    var buf: [4096]u8 = undefined;
    const tally = tallyWire(pair[0], pair[1], &buf);

    try std.testing.expectEqual(@as(usize, 1), tally.rst_protocol_error);
}

test "zix http2: mux answers a peer that hangs up with a request unfinished" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var pair: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.posix.errno(std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = std.posix.system.close(pair[0]);

    const conn = try openTestConn(pair[1], .{ .max_streams = 4, .max_body = 1024, .max_header_scratch = 1024 });
    defer conn.deinit();

    // a POST that opens its stream and never ends it: the body is still on its way
    var hblk: [128]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&hblk);
    try enc.writeHeader(":method", "POST");
    try enc.writeHeader(":path", "/");
    try enc.writeHeader("content-length", "100");
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS, 1, enc.encoded());
    try std.testing.expectEqual(ConnOutcome.keep_alive, muxFrameLoop(cl_router.dispatch, conn));

    try std.testing.expect(requestInFlight(conn));
    try std.testing.expect(hangupGoaway(conn));

    var buf: [4096]u8 = undefined;
    const tally = tallyWire(pair[0], pair[1], &buf);

    try std.testing.expectEqual(@as(usize, 1), tally.goaway_protocol_error);
}

test "zix http2: mux closes an idle connection without a GOAWAY" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var pair: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.posix.errno(std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = std.posix.system.close(pair[0]);

    const conn = try openTestConn(pair[1], .{ .max_streams = 4, .max_body = 1024, .max_header_scratch = 1024 });
    defer conn.deinit();

    // a whole request, served, its slot given back: nothing is owed when the peer leaves
    const whole: [8]u8 = @splat('x');
    try feedDeclaredPost(conn, "8", &whole);
    try std.testing.expectEqual(ConnOutcome.keep_alive, muxFrameLoop(cl_router.dispatch, conn));

    try std.testing.expect(!requestInFlight(conn));
    try std.testing.expect(!hangupGoaway(conn));

    var buf: [4096]u8 = undefined;
    const tally = tallyWire(pair[0], pair[1], &buf);

    try std.testing.expectEqual(@as(usize, 0), tally.goaway_protocol_error);
}

test "zix http2: a stream parked on a send window is not a request in flight" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var pair: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.posix.errno(std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    defer _ = std.posix.system.close(pair[0]);
    defer _ = std.posix.system.close(pair[1]);

    const conn = try openTestConn(pair[1], .{ .max_streams = 4, .max_body = 1024, .max_header_scratch = 1024 });
    defer conn.deinit();

    // tiny windows, so the handler's reply parks and the slot stays held after END_STREAM
    @memset(&fc_test_body, 'q');
    conn.send_window = 100;
    conn.peer_init_window = 100;

    var hblk: [64]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&hblk);
    try enc.writeHeader(":method", "GET");
    try enc.writeHeader(":path", "/");
    feedFrame(conn, frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS | frame.FLAG_END_STREAM, 1, enc.encoded());
    _ = muxFrameLoop(fc_test_router.dispatch, conn);

    const slot = findSlot(1, conn.streams, conn.slots).?;
    try std.testing.expect(conn.streams[slot].pending_body.len > 0);

    // the slot is held by a reply we still owe, not by a request that never arrived, so a peer
    // leaving now gets the ordinary silent close
    try std.testing.expect(!requestInFlight(conn));
    try std.testing.expect(!hangupGoaway(conn));
}
