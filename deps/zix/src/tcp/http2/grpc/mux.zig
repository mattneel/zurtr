//! gRPC multiplexed h2/h2c connection state machine for the .EPOLL / .URING dispatch models.
//!
//! What:
//! - Resumable, non-blocking h2c. One GrpcMuxConn per fd. The read accumulator rbuf persists
//!   across readable events and holds a partial frame until the rest arrives, so one worker
//!   thread drives many connections. Each connection is owned by a single worker, so dispatch is
//!   inline (no per-stream threads, no connection write mutex) and every frame produced in one
//!   readable event coalesces into the connection's ReplyStage and flushes in one write().
//!
//! Note:
//! - EPOLL / URING only, so Linux-only. The handler dispatch, router, context, and the shared
//!   helpers (Stream, ReplyStage, maybeDecompressBody, computeDeadline) live in core.zig and are
//!   reused unchanged from here.

const std = @import("std");
const socket_pair = @import("../../../utils/socket_pair.zig");
const builtin = @import("builtin");
const h2 = @import("../Http2.zig");
const stream_body = @import("../stream_body.zig");
const frame = @import("frame.zig");
const core = @import("core.zig");

const GrpcServeOpts = core.GrpcServeOpts;
const Route = core.Route;
const Router = core.Router;
const GrpcContext = core.GrpcContext;
const GrpcRequest = core.GrpcRequest;
const GrpcResponse = core.GrpcResponse;
const GrpcStatus = core.GrpcStatus;
const Stream = core.Stream;
const StreamState = core.StreamState;
const ReplyStage = core.ReplyStage;
const maybeDecompressBody = core.maybeDecompressBody;
const computeDeadline = core.computeDeadline;
const headerPath = core.headerPath;
const routeIsStreaming = core.routeIsStreaming;
const peerStr = core.peerStr;
const monotonicNs = core.monotonicNs;
const headersAcceptGzip = core.headersAcceptGzip;
const getHttp1Header = core.getHttp1Header;
const STREAM_WINDOW_SIZE = core.STREAM_WINDOW_SIZE;
const CONN_WINDOW_BUMP = core.CONN_WINDOW_BUMP;
const CONN_REPLENISH_THRESHOLD = core.CONN_REPLENISH_THRESHOLD;
const grpc_stream_coalesce_cap = core.grpc_stream_coalesce_cap;
const CTX_ARENA_BYTES = core.CTX_ARENA_BYTES;

/// gRPC mux reply staging buffer per connection.
const mux_stage_buf: usize = 65536;

/// Secondary mux per-connection read buffer floor (the mux conn path).
const mux_read_buf_min: usize = 32 * 1024;

pub const GrpcConnOutcome = enum { keep_alive, close };

const MuxPhase = enum { await_preface, await_upgrade, await_preface2, h2 };

/// Per-connection h2/gRPC state for the multiplexed .EPOLL / .URING models. Heap-owned, one per fd.
/// rbuf is the read accumulator: it persists across readable events and holds any partial
/// frame until the rest arrives. The stream table, hpack decoder and reply cork are all
/// private to the owning worker thread.
pub const GrpcMuxConn = struct {
    fd: std.posix.fd_t,
    opts: GrpcServeOpts,
    /// Io backend, carried for the Context built at each muxDispatch. Worker-wide.
    io: std.Io,

    rbuf: []u8,
    rstart: usize,
    rend: usize,

    hpack_dec: h2.HpackDecoder,

    /// Per-connection slot table. `streams[i]` is a Stream borrowed from the per-worker pool, valid only
    /// while `slots[i]` is set. The array holds pointers, not inline stream state, so an idle connection
    /// reserves `max_streams` pointers, not `max_streams` full body / scratch buffers.
    streams: []*Stream,
    slots: []bool,

    last_stream_id: u31,
    conn_window_consumed: usize,
    phase: MuxPhase,

    /// Precomputed 33-byte server SETTINGS frame (9-byte header + 4 params x 6 bytes).
    /// Built once in init from opts and appended as-is on every new h2 connection.
    settings_frame: [33]u8,
    /// 64 KB backing store for the per-event reply stage.
    /// Large enough to hold a full 5000-message streaming call (~85 KB peak) in 2 flushes
    /// and to coalesce 100 concurrent unary replies (~6 KB) in a single write().
    stage_buf: [mux_stage_buf]u8,
    stage: ReplyStage,

    /// Allocate and initialize a connection.
    ///
    /// Return:
    /// - null on allocation failure (caller closes fd)
    pub fn init(fd: std.posix.fd_t, opts: GrpcServeOpts, io: std.Io) ?*GrpcMuxConn {
        const conn = std.heap.smp_allocator.create(GrpcMuxConn) catch return null;

        const max_payload = opts.max_frame_size + h2.FRAME_PAYLOAD_SLACK;
        const rcap = @max(mux_read_buf_min, max_payload + 9);
        const rbuf = std.heap.smp_allocator.alloc(u8, rcap) catch {
            std.heap.smp_allocator.destroy(conn);
            return null;
        };
        const streams = std.heap.smp_allocator.alloc(*Stream, opts.max_streams) catch {
            std.heap.smp_allocator.free(rbuf);
            std.heap.smp_allocator.destroy(conn);
            return null;
        };
        const slots = std.heap.smp_allocator.alloc(bool, opts.max_streams) catch {
            std.heap.smp_allocator.free(streams);
            std.heap.smp_allocator.free(rbuf);
            std.heap.smp_allocator.destroy(conn);
            return null;
        };

        // Slots start free. The heavy per-stream state (body / header-scratch buffers) is not reserved
        // here, it is borrowed from the per-worker pool on stream open. `streams[i]` is only read while
        // `slots[i]` is set, so the pointers stay unset until a slot is claimed.
        @memset(slots, false);

        conn.* = .{
            .fd = fd,
            .opts = opts,
            .io = io,
            .rbuf = rbuf,
            .rstart = 0,
            .rend = 0,
            .hpack_dec = h2.HpackDecoder.init(),
            .streams = streams,
            .slots = slots,
            .last_stream_id = 0,
            .conn_window_consumed = 0,
            .phase = .await_preface,
            .settings_frame = undefined,
            .stage_buf = undefined,
            .stage = undefined,
        };
        buildSettingsFrame(&conn.settings_frame, opts);
        conn.stage = .{ .fd = fd, .buf = &conn.stage_buf, .len = 0 };

        return conn;
    }

    pub fn deinit(self: *GrpcMuxConn) void {
        // Return any still-open stream to the per-worker pool before freeing the connection's own arrays.
        for (self.slots, 0..) |in_use, slot| {
            if (in_use) releaseGrpcStream(self.streams[slot]);
        }

        std.heap.smp_allocator.free(self.slots);
        std.heap.smp_allocator.free(self.streams);
        std.heap.smp_allocator.free(self.rbuf);
        std.heap.smp_allocator.destroy(self);
    }

    /// Flush the staged reply through `h2.writeAllFD` (the URING / EPOLL loops send `stage.buf`
    /// directly, but the inline TLS path drains it through the frame write hook to be encrypted).
    pub fn flushStage(self: *GrpcMuxConn) void {
        self.stage.flush();
    }
};

// --------------------------------------------------------- //
// Per-worker stream-slot pool for the multiplexed (.EPOLL / .URING) path. A worker drives many
// connections from one thread, and each connection borrows a Stream (its body / header-scratch buffers)
// only while a stream is open, returning it on close. The freelist is threadlocal (shared-nothing per
// worker, no atomics), so resident stream memory tracks concurrent streams on the worker, not
// connections times max_streams. Buffers are allocated once per pooled stream and reused across borrows,
// so the steady state does no per-stream allocation.

threadlocal var grpc_stream_pool: ?*Stream = null;

/// Borrow a stream from the per-worker pool, growing it with a fresh allocation when the freelist is
/// empty. The returned stream is reset to defaults (a pooled stream was cleared on release) with its
/// body / header-scratch buffers sized to at least the serve options.
///
/// Return:
/// - *Stream (clean, buffers ready)
/// - null when a growth allocation failed (the caller refuses the stream)
fn acquireGrpcStream(opts: GrpcServeOpts) ?*Stream {
    const a = std.heap.smp_allocator;

    if (grpc_stream_pool) |st| {
        grpc_stream_pool = st.next_free;
        if (st.body.len >= opts.max_body and st.header_scratch.len >= opts.max_header_scratch) return st;

        // A borrower asking for a larger cap than this slot was sized to (non-uniform serve options on
        // one worker, never in normal use) drops the slot and falls through to a fresh allocation.
        a.free(st.body);
        a.free(st.header_scratch);
        a.destroy(st);
    }

    const st = a.create(Stream) catch return null;
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
fn releaseGrpcStream(st: *Stream) void {
    const body = st.body;
    const scratch = st.header_scratch;

    st.* = .{};
    st.body = body;
    st.header_scratch = scratch;
    st.next_free = grpc_stream_pool;

    grpc_stream_pool = st;
}

/// Free a connection slot: mark it unused and return its borrowed stream to the pool.
fn muxReleaseSlot(conn: *GrpcMuxConn, slot: usize) void {
    conn.slots[slot] = false;
    releaseGrpcStream(conn.streams[slot]);
}

/// Claim a free slot for a new stream, borrowing a stream from the pool. Returns the slot index, or null
/// when the connection is at max_streams or a pool allocation failed (the caller refuses the stream).
fn muxSlotFor(conn: *GrpcMuxConn, stream_id: u31) ?usize {
    for (conn.slots, 0..) |slot_in_use, i| {
        if (!slot_in_use) {
            const st = acquireGrpcStream(conn.opts) orelse return null;
            st.id = stream_id;

            conn.streams[i] = st;
            conn.slots[i] = true;

            return i;
        }
    }

    return null;
}

fn muxFindSlot(stream_id: u31, streams: []*Stream, used: []bool) ?usize {
    for (used, 0..) |slot_in_use, i| {
        if (slot_in_use and streams[i].id == stream_id) return i;
    }

    return null;
}

/// Append a complete frame (9-byte header + payload) to the connection reply cork.
fn muxStageFrame(conn: *GrpcMuxConn, frame_type: u8, flags: u8, stream_id: u31, payload: []const u8) void {
    var hdr: [9]u8 = undefined;
    h2.encodeFrameHeader(&hdr, .{
        .length = @intCast(payload.len),
        .frame_type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    });
    conn.stage.append(&hdr);
    if (payload.len > 0) conn.stage.append(payload);
}

fn muxStageWindowUpdate(conn: *GrpcMuxConn, stream_id: u31, increment: u31) void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, @as(u32, increment), .big);
    muxStageFrame(conn, h2.FRAME_TYPE_WINDOW_UPDATE, 0, stream_id, &payload);
}

fn muxStageGoaway(conn: *GrpcMuxConn, last_stream: u31, error_code: u32) void {
    var payload: [8]u8 = undefined;
    std.mem.writeInt(u32, payload[0..4], @as(u32, last_stream), .big);
    std.mem.writeInt(u32, payload[4..8], error_code, .big);
    muxStageFrame(conn, h2.FRAME_TYPE_GOAWAY, 0, 0, &payload);
}

fn muxStageRst(conn: *GrpcMuxConn, stream_id: u31, error_code: u32) void {
    var payload: [4]u8 = undefined;
    std.mem.writeInt(u32, &payload, error_code, .big);
    muxStageFrame(conn, h2.FRAME_TYPE_RST_STREAM, 0, stream_id, &payload);
}

/// Build the 33-byte server SETTINGS frame into out. Called once per connection in
/// GrpcMuxConn.init so subsequent handshakes append a precomputed blob, not a loop.
fn buildSettingsFrame(out: *[33]u8, opts: GrpcServeOpts) void {
    const params = [_][2]u32{
        .{ h2.SETTINGS_MAX_CONCURRENT_STREAMS, @as(u32, @intCast(opts.max_streams)) },
        .{ h2.SETTINGS_INITIAL_WINDOW_SIZE, STREAM_WINDOW_SIZE },
        .{ h2.SETTINGS_MAX_FRAME_SIZE, opts.max_frame_size },
        .{ h2.SETTINGS_ENABLE_PUSH, 0 },
    };

    var fh_buf: [9]u8 = undefined;
    h2.encodeFrameHeader(&fh_buf, .{
        .length = 24,
        .frame_type = h2.FRAME_TYPE_SETTINGS,
        .flags = 0,
        .stream_id = 0,
    });
    @memcpy(out[0..9], &fh_buf);

    for (params, 0..) |param, i| {
        std.mem.writeInt(u16, out[9 + i * 6 ..][0..2], @as(u16, @intCast(param[0])), .big);
        std.mem.writeInt(u32, out[9 + i * 6 + 2 ..][0..4], param[1], .big);
    }
}

/// Stage the precomputed server SETTINGS frame (built once in GrpcMuxConn.init).
fn muxStageServerSettings(conn: *GrpcMuxConn) void {
    conn.stage.append(&conn.settings_frame);
}

/// Enable or disable TCP_CORK on a Linux TCP socket.
/// When enabled, the kernel holds output segments until the MSS is full or CORK is cleared,
/// coalescing the multiple intermediate stage flushes a streaming handler produces into
/// fewer TCP segments. No-op on non-Linux targets.
fn setTcpCork(fd: std.posix.fd_t, enable: bool) void {
    if (comptime @import("builtin").target.os.tag != .linux) return;
    const val: c_int = if (enable) 1 else 0;
    std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, 3, std.mem.asBytes(&val)) catch {};
}

/// Dispatch a stream whose END_STREAM has arrived, unless its body is short of (or past) the
/// content-length its own headers declared.
///
/// Note:
/// - RFC 9113 8.1.1 makes that request malformed, a stream error of type PROTOCOL_ERROR, so the
///   stream is reset and never dispatched. A handler is therefore never handed a message that is not
///   whole, which is what a short body would produce: a length prefix promising bytes that never came.
/// - A body past max_body is a different case, answered upstream with RESOURCE_EXHAUSTED trailers:
///   that request is valid h2 the engine will not carry, where this one is not valid h2 at all.
/// - The caller frees the slot either way, so nothing is left holding it.
///
/// Param:
/// RouterType - type (the comptime router, carrying the route table)
/// conn - *GrpcMuxConn (the connection owning the stream)
/// stream - *Stream (the stream whose request side just closed)
///
/// Return:
/// - void
fn muxDispatchWhole(comptime RouterType: type, conn: *GrpcMuxConn, stream: *Stream) void {
    if (!stream_body.isWhole(stream.headers[0..stream.header_count], stream.body_len)) {
        muxStageRst(conn, stream.id, h2.ERR_PROTOCOL_ERROR);

        return;
    }

    muxDispatch(RouterType, conn, stream);
}

/// Whether any stream is still waiting for the rest of its request.
///
/// Param:
/// conn - *const GrpcMuxConn (the connection to inspect)
///
/// Return:
/// - bool (true when a request was in flight)
pub fn requestInFlight(conn: *const GrpcMuxConn) bool {
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
/// - The GOAWAY is staged, not written: the caller flushes the cork before closing, exactly as it
///   does for every other frame this state machine produces.
///
/// Param:
/// conn - *GrpcMuxConn (the connection whose peer just hung up)
///
/// Return:
/// - bool (true when a GOAWAY was staged)
pub fn stageHangupGoaway(conn: *GrpcMuxConn) bool {
    if (!requestInFlight(conn)) return false;

    muxStageGoaway(conn, conn.last_stream_id, h2.ERR_PROTOCOL_ERROR);

    return true;
}

/// Dispatch one fully-received stream inline, staging the reply into the connection cork.
/// Unlike the blocking path this never spawns a thread or takes a connection mutex: the worker
/// owns the connection, so a streaming handler runs on the event loop and must stay bounded.
fn muxDispatch(comptime RouterType: type, conn: *GrpcMuxConn, stream: *Stream) void {
    const path = headerPath(stream.headers[0..stream.header_count]);
    const is_streaming = routeIsStreaming(RouterType.route_slice, path);

    var time_start: u64 = undefined;
    if (conn.opts.logger != null) time_start = monotonicNs();

    var decomp_buf: ?[]u8 = null;
    defer if (decomp_buf) |buf| std.heap.smp_allocator.free(buf);
    const effective_body = maybeDecompressBody(
        stream.body[0..stream.body_len],
        stream.headers[0..stream.header_count],
        conn.opts.max_body,
        &decomp_buf,
    );

    const resp_gzip = conn.opts.compress and headersAcceptGzip(stream.headers[0..stream.header_count]);

    // Server-streaming replies pack many messages per DATA frame through this buffer (see
    // _sendDataFrame). Unary keeps one frame per message, so it gets no coalesce buffer.
    var coal_buf: [grpc_stream_coalesce_cap]u8 = undefined;

    var arena_buf: [CTX_ARENA_BYTES]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);

    var ctx = GrpcContext{
        .fd = conn.fd,
        .stream_id = stream.id,
        .path = path,
        ._body = effective_body,
        ._pos = 0,
        ._hdr_sent = false,
        ._sent_bytes = 0,
        ._grpc_status = 0,
        .deadline_ns = computeDeadline(conn.opts.handler_timeout_ms, stream.headers[0..stream.header_count]),
        ._write_mutex = null,
        ._out = &conn.stage,
        ._resp_gzip = resp_gzip,
        ._coal = if (is_streaming) &coal_buf else null,
        .io = conn.io,
        .allocator = fba.allocator(),
    };
    var req = GrpcRequest{ .path = path, .headers = stream.headers[0..stream.header_count], ._ctx = &ctx };
    var res = GrpcResponse{ ._ctx = &ctx };

    if (is_streaming) setTcpCork(conn.fd, true);
    RouterType.dispatch(&req, &res, &ctx) catch {};
    if (is_streaming) setTcpCork(conn.fd, false);

    if (conn.opts.logger) |logger| {
        const dur_ms: u64 = (monotonicNs() -| time_start) / 1_000_000;
        var peer_buf: [64]u8 = undefined;
        const peer = peerStr(conn.fd, &peer_buf);
        logger.rpc(peer, path, ctx._grpc_status, stream.body_len, ctx._sent_bytes, dur_ms);
    }
}

/// Handle the HTTP/1.1 h2c upgrade request for a non-prior-knowledge client.
/// Minimal by design: any client without "Upgrade: h2c" gets 400 (this is the validate probe
/// path). A valid h2c upgrade gets 101 and then expects the connection preface, but the initial
/// request carried on stream 1 by the upgrade is not served (prior-knowledge clients do not use
/// this path).
///
/// Return:
/// - .close when the request is complete and rejected
fn muxHandleUpgrade(conn: *GrpcMuxConn) GrpcConnOutcome {
    const buf = conn.rbuf[conn.rstart..conn.rend];
    const marker = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse {
        if (conn.rend == conn.rbuf.len) return .close;
        return .keep_alive;
    };
    const hdr_end = marker + 4;

    const upgrade_val = getHttp1Header(buf[0..hdr_end], "upgrade");
    const is_h2c = upgrade_val != null and std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade_val.?, " "), "h2c");
    if (!is_h2c) {
        conn.stage.append("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        return .close;
    }

    conn.stage.append("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n");
    conn.rstart += hdr_end;
    conn.phase = .await_preface2;

    return .keep_alive;
}

/// Process as many complete frames as are currently buffered.
///
/// Return:
/// - .keep_alive when the buffer is drained or holds only a partial frame (wait for more bytes)
/// - .close on a protocol error or GOAWAY (a GOAWAY/close reply is staged first)
fn muxProcess(comptime RouterType: type, conn: *GrpcMuxConn) GrpcConnOutcome {
    switch (conn.phase) {
        .await_preface => {
            const avail = conn.rend - conn.rstart;
            if (avail < 3) return .keep_alive;

            if (!std.mem.eql(u8, conn.rbuf[conn.rstart..][0..3], "PRI")) {
                conn.phase = .await_upgrade;
                return muxHandleUpgrade(conn);
            }
            if (avail < h2.PREFACE.len) return .keep_alive;
            if (!std.mem.eql(u8, conn.rbuf[conn.rstart..][0..h2.PREFACE.len], h2.PREFACE)) {
                muxStageGoaway(conn, 0, h2.ERR_PROTOCOL_ERROR);
                return .close;
            }

            conn.rstart += h2.PREFACE.len;
            muxStageServerSettings(conn);
            conn.phase = .h2;
        },

        .await_upgrade => return muxHandleUpgrade(conn),

        .await_preface2 => {
            const avail = conn.rend - conn.rstart;
            if (avail < h2.PREFACE.len) return .keep_alive;
            if (!std.mem.eql(u8, conn.rbuf[conn.rstart..][0..h2.PREFACE.len], h2.PREFACE)) {
                muxStageGoaway(conn, 0, h2.ERR_PROTOCOL_ERROR);
                return .close;
            }

            conn.rstart += h2.PREFACE.len;
            muxStageServerSettings(conn);
            conn.phase = .h2;
        },

        .h2 => {},
    }

    return muxFrameLoop(RouterType, conn);
}

/// The h2 frame loop over buffered bytes for a connection in the .h2 phase.
fn muxFrameLoop(comptime RouterType: type, conn: *GrpcMuxConn) GrpcConnOutcome {
    const max_payload = conn.opts.max_frame_size + h2.FRAME_PAYLOAD_SLACK;

    while (true) {
        const avail = conn.rend - conn.rstart;
        if (avail < 9) return .keep_alive;

        const fh = h2.parseFrameHeader(conn.rbuf[conn.rstart..][0..9]);
        if (fh.length > max_payload) {
            muxStageGoaway(conn, conn.last_stream_id, h2.ERR_FRAME_SIZE_ERROR);
            return .close;
        }
        if (avail < 9 + fh.length) return .keep_alive;

        conn.rstart += 9;
        const payload = conn.rbuf[conn.rstart..][0..fh.length];
        conn.rstart += fh.length;

        switch (fh.frame_type) {
            h2.FRAME_TYPE_SETTINGS => {
                if ((fh.flags & h2.FLAG_ACK) != 0) continue;
                var i: usize = 0;
                while (i + 6 <= payload.len) : (i += 6) {
                    const id: u16 = (@as(u16, payload[i]) << 8) | payload[i + 1];
                    const val: u32 = (@as(u32, payload[i + 2]) << 24) | (@as(u32, payload[i + 3]) << 16) |
                        (@as(u32, payload[i + 4]) << 8) | payload[i + 5];
                    if (id == h2.SETTINGS_HEADER_TABLE_SIZE) {
                        conn.hpack_dec.max_size = val;
                        conn.hpack_dec.evictTo(val);
                    }
                }

                muxStageFrame(conn, h2.FRAME_TYPE_SETTINGS, h2.FLAG_ACK, 0, &.{});
                muxStageWindowUpdate(conn, 0, CONN_WINDOW_BUMP);
            },

            h2.FRAME_TYPE_WINDOW_UPDATE => {},

            h2.FRAME_TYPE_PING => {
                if ((fh.flags & h2.FLAG_ACK) != 0) continue;
                if (payload.len != 8) {
                    muxStageGoaway(conn, conn.last_stream_id, h2.ERR_FRAME_SIZE_ERROR);
                    return .close;
                }

                muxStageFrame(conn, h2.FRAME_TYPE_PING, h2.FLAG_ACK, 0, payload);
            },

            h2.FRAME_TYPE_HEADERS => {
                const stream_id = fh.stream_id;
                if (stream_id == 0) {
                    muxStageGoaway(conn, conn.last_stream_id, h2.ERR_PROTOCOL_ERROR);
                    return .close;
                }
                if (stream_id <= conn.last_stream_id and stream_id % 2 == 1) {
                    muxStageRst(conn, stream_id, h2.ERR_STREAM_CLOSED);
                    continue;
                }
                conn.last_stream_id = @max(conn.last_stream_id, stream_id);

                const slot = muxSlotFor(conn, stream_id) orelse {
                    muxStageRst(conn, stream_id, h2.ERR_REFUSED_STREAM);
                    continue;
                };
                const stream = conn.streams[slot];
                stream.id = stream_id;
                stream.state = .OPEN;
                stream.body_len = 0;

                var block = payload;
                var offset: usize = 0;
                var pad_len: usize = 0;
                if ((fh.flags & h2.FLAG_PADDED) != 0 and block.len > 0) {
                    pad_len = block[0];
                    offset = 1;
                }
                if ((fh.flags & h2.FLAG_PRIORITY) != 0 and offset + 5 <= block.len) {
                    offset += 5;
                }
                if (pad_len + offset > block.len) {
                    muxStageGoaway(conn, conn.last_stream_id, h2.ERR_PROTOCOL_ERROR);
                    return .close;
                }
                block = block[offset .. block.len - pad_len];

                stream.header_count = conn.hpack_dec.decode(block, &stream.headers, stream.header_scratch) catch {
                    muxStageRst(conn, stream_id, h2.ERR_COMPRESSION_ERROR);
                    muxReleaseSlot(conn, slot);
                    continue;
                };
                stream.end_headers = (fh.flags & h2.FLAG_END_HEADERS) != 0;
                stream.end_stream = (fh.flags & h2.FLAG_END_STREAM) != 0;

                if (stream.end_headers and stream.end_stream) {
                    muxDispatchWhole(RouterType, conn, stream);
                    muxReleaseSlot(conn, slot);
                }
            },

            h2.FRAME_TYPE_CONTINUATION => {
                const stream_id = fh.stream_id;
                const slot = muxFindSlot(stream_id, conn.streams, conn.slots) orelse {
                    muxStageGoaway(conn, conn.last_stream_id, h2.ERR_PROTOCOL_ERROR);
                    return .close;
                };
                const stream = conn.streams[slot];
                const count = conn.hpack_dec.decode(payload, stream.headers[stream.header_count..], stream.header_scratch) catch {
                    muxStageRst(conn, stream_id, h2.ERR_COMPRESSION_ERROR);
                    muxReleaseSlot(conn, slot);
                    continue;
                };
                stream.header_count += count;
                stream.end_headers = (fh.flags & h2.FLAG_END_HEADERS) != 0;
                if (stream.end_headers and stream.end_stream) {
                    muxDispatchWhole(RouterType, conn, stream);
                    muxReleaseSlot(conn, slot);
                }
            },

            h2.FRAME_TYPE_DATA => {
                const stream_id = fh.stream_id;
                if (stream_id == 0) {
                    muxStageGoaway(conn, conn.last_stream_id, h2.ERR_PROTOCOL_ERROR);
                    return .close;
                }
                const slot = muxFindSlot(stream_id, conn.streams, conn.slots) orelse {
                    muxStageRst(conn, stream_id, h2.ERR_STREAM_CLOSED);
                    continue;
                };
                const stream = conn.streams[slot];

                var data = payload;
                var pad_len: usize = 0;
                if ((fh.flags & h2.FLAG_PADDED) != 0 and data.len > 0) {
                    pad_len = data[0];
                    data = data[1..];
                }
                if (pad_len > data.len) {
                    muxStageGoaway(conn, conn.last_stream_id, h2.ERR_PROTOCOL_ERROR);
                    return .close;
                }
                data = data[0 .. data.len - pad_len];

                if (data.len > 0) {
                    conn.conn_window_consumed += data.len;
                    if (conn.conn_window_consumed >= CONN_REPLENISH_THRESHOLD) {
                        muxStageWindowUpdate(conn, 0, @intCast(conn.conn_window_consumed));
                        conn.conn_window_consumed = 0;
                    }
                }

                // A payload past the body cap can not be served truncated (the
                // dispatched message would be corrupt). Shed the started stream
                // with RESOURCE_EXHAUSTED trailers and free the slot. Any later
                // DATA for it lands on the findSlot miss above and gets
                // RST(STREAM_CLOSED), other streams on the connection continue.
                if (data.len > stream.body.len - stream.body_len) {
                    var err_buf: [frame.headers_frame_scratch]u8 = undefined;
                    const err_len = frame.buildGrpcError(&err_buf, stream_id, @intFromEnum(GrpcStatus.RESOURCE_EXHAUSTED), "request message exceeds max_body");
                    conn.stage.append(err_buf[0..err_len]);
                    muxReleaseSlot(conn, slot);
                    continue;
                }

                @memcpy(stream.body[stream.body_len..][0..data.len], data);
                stream.body_len += data.len;
                stream.end_stream = (fh.flags & h2.FLAG_END_STREAM) != 0;

                if (stream.end_stream) {
                    muxDispatchWhole(RouterType, conn, stream);
                    muxReleaseSlot(conn, slot);
                }
            },

            h2.FRAME_TYPE_RST_STREAM => {
                if (muxFindSlot(fh.stream_id, conn.streams, conn.slots)) |slot| muxReleaseSlot(conn, slot);
            },

            h2.FRAME_TYPE_GOAWAY => return .close,
            h2.FRAME_TYPE_PRIORITY => {},
            else => {},
        }
    }
}

/// Drive one readable event for a multiplexed connection: read available bytes (non-blocking),
/// process complete frames, and flush the staged reply in one write().
///
/// Return:
/// - .close when the peer closed, a protocol error occurred, or the handshake was rejected
pub fn grpcMuxOnReadable(comptime RouterType: type, conn: *GrpcMuxConn) GrpcConnOutcome {
    conn.stage.len = 0;

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

        if (conn.rend == conn.rbuf.len) {
            conn.stage.flush();
            return .close;
        }

        const got = std.posix.read(conn.fd, conn.rbuf[conn.rend..]) catch |err| switch (err) {
            error.WouldBlock => {
                conn.stage.flush();
                return .keep_alive;
            },
            else => {
                conn.stage.flush();
                return .close;
            },
        };
        if (got == 0) {
            _ = stageHangupGoaway(conn);
            conn.stage.flush();

            return .close;
        }
        conn.rend += got;

        if (muxProcess(RouterType, conn) == .close) {
            conn.stage.flush();
            return .close;
        }
    }
}

/// Process buffered frames for the .URING ring path (ADR-037 Phase 4 step 3).
/// Like grpcMuxOnReadable but without the blocking read loop and without the
/// final fd flush: the ring worker has already filled conn.rbuf (advancing
/// conn.rend), and it submits conn.stage.buf[0..conn.stage.len] as one ring send
/// afterwards. rbuf compaction before each recv is the caller's responsibility.
/// A large reply that overflows the cork still flushes straight to the fd inside
/// muxProcess, which is safe under the ring's half-duplex guarantee.
///
/// Return:
/// - .keep_alive when the buffer is drained or holds only a partial frame
/// - .close on a protocol error or peer close (a GOAWAY/close reply is staged first)
pub fn grpcMuxProcessRing(comptime RouterType: type, conn: *GrpcMuxConn) GrpcConnOutcome {
    conn.stage.len = 0;

    return muxProcess(RouterType, conn);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix grpc: buildSettingsFrame produces valid SETTINGS frame header" {
    const opts = GrpcServeOpts{};
    var frm: [33]u8 = undefined;
    buildSettingsFrame(&frm, opts);

    const fh = h2.parseFrameHeader(frm[0..9]);
    try std.testing.expectEqual(h2.FRAME_TYPE_SETTINGS, fh.frame_type);
    try std.testing.expectEqual(@as(u8, 0), fh.flags);
    try std.testing.expectEqual(@as(u31, 0), fh.stream_id);
    try std.testing.expectEqual(@as(u24, 24), fh.length);
}

test "zix grpc: buildSettingsFrame encodes MAX_CONCURRENT_STREAMS correctly" {
    const opts = GrpcServeOpts{ .max_streams = 64 };
    var frm: [33]u8 = undefined;
    buildSettingsFrame(&frm, opts);

    const id = std.mem.readInt(u16, frm[9..11], .big);
    const val = std.mem.readInt(u32, frm[11..15], .big);
    try std.testing.expectEqual(@as(u16, h2.SETTINGS_MAX_CONCURRENT_STREAMS), id);
    try std.testing.expectEqual(@as(u32, 64), val);
}

test "zix grpc: pooled stream is reused and reset clean on release" {
    const opts = GrpcServeOpts{ .max_streams = 4, .max_body = 128, .max_header_scratch = 64 };

    // A fresh borrow carries buffers sized to at least the serve options.
    const first = acquireGrpcStream(opts) orelse return error.OutOfMemory;
    try std.testing.expect(first.body.len >= 128);
    try std.testing.expect(first.header_scratch.len >= 64);

    // Dirty every field a request would touch, then return the stream to the pool.
    first.id = 7;
    first.state = .OPEN;
    first.header_count = 3;
    first.body_len = 99;
    first.end_headers = true;
    first.end_stream = true;
    releaseGrpcStream(first);

    // The next borrow is LIFO, so it is the same object, now reset to defaults with buffers retained.
    const again = acquireGrpcStream(opts) orelse return error.OutOfMemory;
    try std.testing.expectEqual(first, again);
    try std.testing.expectEqual(@as(u31, 0), again.id);
    try std.testing.expectEqual(StreamState.IDLE, again.state);
    try std.testing.expectEqual(@as(usize, 0), again.header_count);
    try std.testing.expectEqual(@as(usize, 0), again.body_len);
    try std.testing.expect(!again.end_headers);
    try std.testing.expect(!again.end_stream);
    try std.testing.expect(again.body.len >= 128);

    releaseGrpcStream(again);
}

test "zix grpc: stream slots are pooled across connections" {
    const opts = GrpcServeOpts{ .max_streams = 4, .max_body = 128, .max_header_scratch = 64 };

    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();
    const fds = pair.fds;

    // Connection A borrows a slot, then releases it back to the per-worker pool.
    const conn_a = GrpcMuxConn.init(fds[1], opts, undefined) orelse return error.OutOfMemory;
    const slot_a = muxSlotFor(conn_a, 1).?;
    const stream_a = conn_a.streams[slot_a];
    try std.testing.expect(conn_a.slots[slot_a]);

    muxReleaseSlot(conn_a, slot_a);
    try std.testing.expect(!conn_a.slots[slot_a]);
    conn_a.deinit();

    // A second connection reuses the same pooled stream (LIFO), so stream memory is shared per worker
    // and does not scale with the connection count.
    const conn_b = GrpcMuxConn.init(fds[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn_b.deinit();

    const slot_b = muxSlotFor(conn_b, 3).?;
    try std.testing.expectEqual(stream_a, conn_b.streams[slot_b]);
    try std.testing.expectEqual(@as(u31, 3), conn_b.streams[slot_b].id);

    muxReleaseSlot(conn_b, slot_b);
}

test "zix grpc: mux DATA past max_body sheds the stream with RESOURCE_EXHAUSTED trailers" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    const opts = GrpcServeOpts{ .max_streams = 4, .max_body = 16, .max_header_scratch = 256 };

    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();
    const fds = pair.fds;

    const conn = GrpcMuxConn.init(fds[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    // HEADERS for stream 1 (END_HEADERS, no END_STREAM): claims a slot and waits for DATA.
    var enc_scratch: [256]u8 = undefined;
    var enc = h2.HpackEncoder.init(&enc_scratch);
    try enc.writeHeader(":method", "POST");
    try enc.writeHeader(":path", "/svc.Svc/Method");
    const hblock = enc.encoded();

    var off: usize = 0;
    h2.encodeFrameHeader(conn.rbuf[off..][0..9], .{ .length = @intCast(hblock.len), .frame_type = h2.FRAME_TYPE_HEADERS, .flags = h2.FLAG_END_HEADERS, .stream_id = 1 });
    @memcpy(conn.rbuf[off + 9 ..][0..hblock.len], hblock);
    off += 9 + hblock.len;

    // DATA with twice the body cap: the stream must be shed, not truncated.
    const big: [32]u8 = @splat(0xaa);
    h2.encodeFrameHeader(conn.rbuf[off..][0..9], .{ .length = big.len, .frame_type = h2.FRAME_TYPE_DATA, .flags = 0, .stream_id = 1 });
    @memcpy(conn.rbuf[off + 9 ..][0..big.len], &big);
    off += 9 + big.len;

    // A second DATA for the shed stream must land on the freed-slot path
    // (RST STREAM_CLOSED), proving a stale stream reference after the shed
    // never touches recycled slot memory.
    h2.encodeFrameHeader(conn.rbuf[off..][0..9], .{ .length = 4, .frame_type = h2.FRAME_TYPE_DATA, .flags = 0, .stream_id = 1 });
    @memcpy(conn.rbuf[off + 9 ..][0..4], big[0..4]);
    off += 9 + 4;
    conn.rend = off;

    const outcome = muxFrameLoop(Router(&[_]Route{}), conn);

    try std.testing.expectEqual(GrpcConnOutcome.keep_alive, outcome);
    for (conn.slots) |in_use| try std.testing.expect(!in_use);

    // First staged frame: trailers-only HEADERS carrying grpc-status 8 (RESOURCE_EXHAUSTED).
    const staged = conn.stage.buf[0..conn.stage.len];
    const fh_err = h2.parseFrameHeader(staged[0..9]);
    try std.testing.expectEqual(h2.FRAME_TYPE_HEADERS, fh_err.frame_type);
    try std.testing.expectEqual(h2.FLAG_END_HEADERS | h2.FLAG_END_STREAM, fh_err.flags);
    try std.testing.expectEqual(@as(u31, 1), fh_err.stream_id);

    var decoder = h2.HpackDecoder.init();
    var headers: [8]h2.Header = undefined;
    var scratch: [512]u8 = undefined;
    const count = try decoder.decode(staged[9..][0..fh_err.length], &headers, &scratch);

    var saw_status = false;
    for (headers[0..count]) |hdr| {
        if (std.mem.eql(u8, hdr.name, "grpc-status") and std.mem.eql(u8, hdr.value, "8")) saw_status = true;
    }
    try std.testing.expect(saw_status);

    // Second staged frame: RST_STREAM(STREAM_CLOSED) answering the stale DATA.
    const rst_off = 9 + @as(usize, fh_err.length);
    const fh_rst = h2.parseFrameHeader(staged[rst_off..][0..9]);
    try std.testing.expectEqual(h2.FRAME_TYPE_RST_STREAM, fh_rst.frame_type);
    try std.testing.expectEqual(@as(u31, 1), fh_rst.stream_id);

    const rst_code: u32 = (@as(u32, staged[rst_off + 9]) << 24) | (@as(u32, staged[rst_off + 10]) << 16) |
        (@as(u32, staged[rst_off + 11]) << 8) | staged[rst_off + 12];
    try std.testing.expectEqual(h2.ERR_STREAM_CLOSED, rst_code);
}

test "zix grpc: mux HEADERS past max_streams is refused with REFUSED_STREAM" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    const opts = GrpcServeOpts{ .max_streams = 1, .max_body = 64, .max_header_scratch = 256 };

    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();
    const fds = pair.fds;

    const conn = GrpcMuxConn.init(fds[1], opts, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    var enc_scratch: [256]u8 = undefined;
    var enc = h2.HpackEncoder.init(&enc_scratch);
    try enc.writeHeader(":method", "POST");
    try enc.writeHeader(":path", "/svc.Svc/Method");
    const hblock = enc.encoded();

    // Stream 1 claims the only slot (no END_STREAM, so it stays open).
    var off: usize = 0;
    h2.encodeFrameHeader(conn.rbuf[off..][0..9], .{ .length = @intCast(hblock.len), .frame_type = h2.FRAME_TYPE_HEADERS, .flags = h2.FLAG_END_HEADERS, .stream_id = 1 });
    @memcpy(conn.rbuf[off + 9 ..][0..hblock.len], hblock);
    off += 9 + hblock.len;

    // Stream 3 finds no free slot and must be refused, not queued and not served.
    var enc_scratch2: [256]u8 = undefined;
    var enc2 = h2.HpackEncoder.init(&enc_scratch2);
    try enc2.writeHeader(":method", "POST");
    try enc2.writeHeader(":path", "/svc.Svc/Method");
    const hblock2 = enc2.encoded();

    h2.encodeFrameHeader(conn.rbuf[off..][0..9], .{ .length = @intCast(hblock2.len), .frame_type = h2.FRAME_TYPE_HEADERS, .flags = h2.FLAG_END_HEADERS, .stream_id = 3 });
    @memcpy(conn.rbuf[off + 9 ..][0..hblock2.len], hblock2);
    off += 9 + hblock2.len;
    conn.rend = off;

    const outcome = muxFrameLoop(Router(&[_]Route{}), conn);

    try std.testing.expectEqual(GrpcConnOutcome.keep_alive, outcome);

    // Stream 1 keeps its slot, the refusal never disturbs an accepted stream.
    try std.testing.expect(conn.slots[0]);
    try std.testing.expectEqual(@as(u31, 1), conn.streams[0].id);

    // The staged reply is RST_STREAM(REFUSED_STREAM) for stream 3: guaranteed
    // unprocessed, safe for the client to retry.
    const staged = conn.stage.buf[0..conn.stage.len];
    const fh_rst = h2.parseFrameHeader(staged[0..9]);
    try std.testing.expectEqual(h2.FRAME_TYPE_RST_STREAM, fh_rst.frame_type);
    try std.testing.expectEqual(@as(u31, 3), fh_rst.stream_id);

    const rst_code: u32 = (@as(u32, staged[9]) << 24) | (@as(u32, staged[10]) << 16) |
        (@as(u32, staged[11]) << 8) | staged[12];
    try std.testing.expectEqual(h2.ERR_REFUSED_STREAM, rst_code);
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

var grpc_cl_dispatches: usize = 0;
var grpc_cl_body_len: usize = 0;

fn grpcClHandler(req: *GrpcRequest, _: *GrpcResponse, _: *GrpcContext) anyerror!void {
    grpc_cl_dispatches += 1;
    grpc_cl_body_len = if (req.recvMessage()) |msg| msg.len else 0;
}

const grpc_cl_router = Router(&[_]Route{.{ .path = "/svc.Svc/Method", .handler = grpcClHandler }});

/// Fill the connection's read accumulator with a POST whose headers declare `content_length` and
/// whose DATA carries `body`, ending the stream. The two disagree exactly when a truncated (or
/// overlong) body is being modelled.
fn feedDeclaredCall(conn: *GrpcMuxConn, content_length: []const u8, body: []const u8, end_stream: bool) !void {
    var enc_scratch: [256]u8 = undefined;
    var enc = h2.HpackEncoder.init(&enc_scratch);
    try enc.writeHeader(":method", "POST");
    try enc.writeHeader(":path", "/svc.Svc/Method");
    try enc.writeHeader("content-length", content_length);
    const hblock = enc.encoded();

    var off: usize = 0;
    h2.encodeFrameHeader(conn.rbuf[off..][0..9], .{ .length = @intCast(hblock.len), .frame_type = h2.FRAME_TYPE_HEADERS, .flags = h2.FLAG_END_HEADERS, .stream_id = 1 });
    @memcpy(conn.rbuf[off + 9 ..][0..hblock.len], hblock);
    off += 9 + hblock.len;

    if (end_stream) {
        h2.encodeFrameHeader(conn.rbuf[off..][0..9], .{ .length = @intCast(body.len), .frame_type = h2.FRAME_TYPE_DATA, .flags = h2.FLAG_END_STREAM, .stream_id = 1 });
        @memcpy(conn.rbuf[off + 9 ..][0..body.len], body);
        off += 9 + body.len;
    }

    conn.rend = off;
}

/// How many RST_STREAM(PROTOCOL_ERROR) frames the connection staged this pass.
fn stagedProtocolResets(conn: *const GrpcMuxConn) usize {
    const staged = conn.stage.buf[0..conn.stage.len];

    var seen: usize = 0;
    var off: usize = 0;
    while (off + 9 <= staged.len) {
        const fh = h2.parseFrameHeader(staged[off..][0..9]);
        off += 9;
        if (off + fh.length > staged.len) break;

        if (fh.frame_type == h2.FRAME_TYPE_RST_STREAM and std.mem.readInt(u32, staged[off..][0..4], .big) == h2.ERR_PROTOCOL_ERROR) seen += 1;
        off += fh.length;
    }

    return seen;
}

/// How many GOAWAY(PROTOCOL_ERROR) frames the connection staged this pass.
fn stagedProtocolGoaways(conn: *const GrpcMuxConn) usize {
    const staged = conn.stage.buf[0..conn.stage.len];

    var seen: usize = 0;
    var off: usize = 0;
    while (off + 9 <= staged.len) {
        const fh = h2.parseFrameHeader(staged[off..][0..9]);
        off += 9;
        if (off + fh.length > staged.len) break;

        if (fh.frame_type == h2.FRAME_TYPE_GOAWAY and std.mem.readInt(u32, staged[off + 4 ..][0..4], .big) == h2.ERR_PROTOCOL_ERROR) seen += 1;
        off += fh.length;
    }

    return seen;
}

test "zix grpc: mux resets a stream whose body is short of its content-length" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();

    const conn = GrpcMuxConn.init(pair.fds[1], .{ .max_streams = 4, .max_body = 1024, .max_header_scratch = 256 }, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    // 100 bytes promised, 40 delivered, then END_STREAM: the message never finished arriving
    const short: [40]u8 = @splat('x');
    grpc_cl_dispatches = 0;
    try feedDeclaredCall(conn, "100", &short, true);

    try std.testing.expectEqual(GrpcConnOutcome.keep_alive, muxFrameLoop(grpc_cl_router, conn));

    // the handler never ran, so no truncated message was ever served
    try std.testing.expectEqual(@as(usize, 0), grpc_cl_dispatches);
    try std.testing.expectEqual(@as(usize, 1), stagedProtocolResets(conn));

    // the slot is freed, so the connection stays usable for its other streams
    for (conn.slots) |in_use| try std.testing.expect(!in_use);
}

test "zix grpc: mux serves a stream whose body matches its content-length" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();

    const conn = GrpcMuxConn.init(pair.fds[1], .{ .max_streams = 4, .max_body = 1024, .max_header_scratch = 256 }, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    // a 5-byte gRPC length prefix and its 4 payload bytes, so the message is whole as well
    const whole = [_]u8{ 0, 0, 0, 0, 4, 'p', 'i', 'n', 'g' };
    grpc_cl_dispatches = 0;
    grpc_cl_body_len = 0;
    try feedDeclaredCall(conn, "9", &whole, true);

    try std.testing.expectEqual(GrpcConnOutcome.keep_alive, muxFrameLoop(grpc_cl_router, conn));

    // the guard only sheds a body that disagrees with its own headers, an honest one still serves
    try std.testing.expectEqual(@as(usize, 1), grpc_cl_dispatches);
    try std.testing.expectEqual(@as(usize, 4), grpc_cl_body_len);
    try std.testing.expectEqual(@as(usize, 0), stagedProtocolResets(conn));
}

test "zix grpc: mux resets a stream whose body runs past its content-length" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();

    const conn = GrpcMuxConn.init(pair.fds[1], .{ .max_streams = 4, .max_body = 1024, .max_header_scratch = 256 }, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    const overlong: [40]u8 = @splat('x');
    grpc_cl_dispatches = 0;
    try feedDeclaredCall(conn, "10", &overlong, true);

    try std.testing.expectEqual(GrpcConnOutcome.keep_alive, muxFrameLoop(grpc_cl_router, conn));

    try std.testing.expectEqual(@as(usize, 0), grpc_cl_dispatches);
    try std.testing.expectEqual(@as(usize, 1), stagedProtocolResets(conn));
}

test "zix grpc: mux stages a GOAWAY for a peer that hangs up with a request unfinished" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();

    const conn = GrpcMuxConn.init(pair.fds[1], .{ .max_streams = 4, .max_body = 1024, .max_header_scratch = 256 }, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    // a call that opens its stream and never ends it: the message is still on its way
    try feedDeclaredCall(conn, "100", &.{}, false);
    try std.testing.expectEqual(GrpcConnOutcome.keep_alive, muxFrameLoop(grpc_cl_router, conn));

    conn.stage.len = 0;
    try std.testing.expect(requestInFlight(conn));
    try std.testing.expect(stageHangupGoaway(conn));
    try std.testing.expectEqual(@as(usize, 1), stagedProtocolGoaways(conn));
}

test "zix grpc: mux closes an idle connection without a GOAWAY" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();

    const conn = GrpcMuxConn.init(pair.fds[1], .{ .max_streams = 4, .max_body = 1024, .max_header_scratch = 256 }, undefined) orelse return error.OutOfMemory;
    defer conn.deinit();
    conn.phase = .h2;

    // a whole call, served, its slot given back: nothing is owed when the peer leaves
    const whole = [_]u8{ 0, 0, 0, 0, 0 };
    try feedDeclaredCall(conn, "5", &whole, true);
    try std.testing.expectEqual(GrpcConnOutcome.keep_alive, muxFrameLoop(grpc_cl_router, conn));

    conn.stage.len = 0;
    try std.testing.expect(!requestInFlight(conn));
    try std.testing.expect(!stageHangupGoaway(conn));
    try std.testing.expectEqual(@as(usize, 0), stagedProtocolGoaways(conn));
}
