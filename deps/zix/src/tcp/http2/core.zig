//! HTTP/2 connection loop: h2c direct (PRI preface) and h2c upgrade (HTTP/1.1 Upgrade: h2c).

const std = @import("std");
const socket_pair = @import("../../utils/socket_pair.zig");
const win_io = @import("../../utils/windows_io.zig");
const frame = @import("frame.zig");
const hpack = @import("hpack.zig");
const stream_body = @import("stream_body.zig");
const rc = @import("../../utils/response_cache.zig");
const peer_addr = @import("../../utils/peer_addr.zig");
const Logger = @import("../../logger/logger.zig").Logger;
const router_mod = @import("router.zig");
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Context = @import("context.zig").Context;
const wallClockNs = @import("context.zig").wallClockNs;
const CTX_ARENA_BYTES = @import("context.zig").CTX_ARENA_BYTES;

/// Base64 decode scratch for the HTTP2-Settings header on an h2c upgrade.
const SETTINGS_DECODE_SCRATCH: usize = 256;

/// Request line and header read bound for an h2c upgrade (HeaderTooLarge over this).
const UPGRADE_HEAD_BUF: usize = 8192;

// --------------------------------------------------------- //
// Per-worker response cache (ADR-036), opt-in via config.response_cache. Mirrors the zix.Grpc and
// zix.Http1 response caches: the worker installs a cache, muxDispatch records the request key, and a
// handler serves or stores an unframed response body that is re-framed per stream-id on a hit.

/// Per-worker response cache installed by the EPOLL / URING mux worker. Null on workers without a
/// cache, so the serveCached / sendCachedFD API degrades to a plain send.
pub threadlocal var tl_cache: ?*rc.ResponseCache = null;

/// Default freshness in milliseconds for a stored response, set alongside tl_cache.
pub threadlocal var tl_cache_ttl_ms: u32 = 1000;

/// Path and body of the request currently dispatching on this worker, set by muxDispatch around each
/// handler call so the free-function cache API can compute the request key. The handler does not
/// receive the path, so it is threaded here rather than through HandlerFn.
pub threadlocal var tl_req_path: []const u8 = "";
pub threadlocal var tl_req_body: []const u8 = "";

/// Install the per-worker response cache and its default TTL.
pub fn setCache(cache: ?*rc.ResponseCache, default_ttl_ms: u32) void {
    tl_cache = cache;
    tl_cache_ttl_ms = default_ttl_ms;
}

/// Worker default cache TTL in milliseconds, exposed to handlers.
pub fn cacheTtl() u32 {
    return tl_cache_ttl_ms;
}

/// Hash a request into a cache key from its path and body. A zero digest is bumped to 1 so 0 stays
/// reserved for an empty cache slot.
fn requestKey(path: []const u8, body: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(path);
    hasher.update(body);

    const digest = hasher.final();
    return if (digest == 0) 1 else digest;
}

/// Serve the current request from the per-worker cache when present. On a hit the cached (unframed)
/// body is re-framed for this stream and sent, and the handler should return.
///
/// Usage:
/// ```zig
/// fn handler(req: *zix.Http2.Request, res: *zix.Http2.Response, ctx: *zix.Http2.Context) anyerror!void {
///     _ = res;
///     if (zix.Http2.serveCached(ctx.fd, ctx.sid, "application/json")) return;
///     const reply = buildExpensive();
///     zix.Http2.sendCachedFD(ctx.fd, ctx.sid, "application/json", reply);
/// }
/// ```
///
/// Return:
/// - bool (true when served from cache, the handler should return)
pub fn serveCached(fd: std.posix.fd_t, sid: u31, content_type: []const u8) bool {
    const cache = tl_cache orelse return false;
    if (tl_req_path.len == 0) return false;

    const bytes = cache.lookup(requestKey(tl_req_path, tl_req_body), rc.nowMillis()) orelse return false;

    frame.sendResponseFD(fd, sid, 200, content_type, bytes) catch {};

    return true;
}

/// Send a response body and store it under the current request key for later serveCached hits.
/// Storing is skipped when no cache is installed or the path is empty. The body is sent regardless.
pub fn sendCachedFD(fd: std.posix.fd_t, sid: u31, content_type: []const u8, data: []const u8) void {
    frame.sendResponseFD(fd, sid, 200, content_type, data) catch {};

    const cache = tl_cache orelse return;
    if (tl_req_path.len == 0) return;

    _ = cache.store(requestKey(tl_req_path, tl_req_body), data, tl_cache_ttl_ms, rc.nowMillis());
}

// --------------------------------------------------------- //

/// HTTP/2 handler function type. Called once per completed h2 stream via invokeHandler,
/// which builds the trio (Request, Response, Context). Route matching happens in the router the
/// caller builds (Router(routes).dispatch is itself a HandlerFn), not in the engine.
pub const HandlerFn = router_mod.HandlerFn;
pub const RouteKind = router_mod.RouteKind;
pub const Route = router_mod.Route;
pub const Router = router_mod.Router;

/// Build the trio and invoke the handler, mirroring Http1's core.invokeHandler (ADR-062). A handler
/// error is completed as one auto-500, but only when the handler wrote nothing, so a partially sent
/// response is not corrupted.
///
/// Note:
/// - "Wrote nothing" covers both answer styles: the Response builder (`Response.sent`) and the fd
///   writers (`frame.respondedFD`). A handler that answers with `sendResponseFD` or `writeAllFD`
///   holds no Response, so checking `Response.sent` alone read it as unanswered and put a second
///   HEADERS frame on a stream the peer already saw closed.
/// - An error the handler swallows itself is the handler's own business. The engine completes an
///   error the handler RETURNS, nothing else.
///
/// Param:
/// handler - HandlerFn (built via Router(&[_]Route{...}).dispatch)
/// req - Request (already built by the caller: method, path, query, headers, body)
/// fd - std.posix.fd_t (connection fd for sending responses)
/// sid - u31 (HTTP/2 stream id)
/// io - std.Io (carried on Context for symmetry with the other engines)
/// deadline_ns - ?u64 (seeded from opts.handler_timeout_ms by the caller)
/// opts - ServeOpts (read for public_dir)
/// peer_max_frame_size - u32 (the peer's advertised SETTINGS_MAX_FRAME_SIZE, NOT opts.max_frame_size,
///   which is this server's own receive-side limit and says nothing about what the peer accepts)
pub inline fn invokeHandler(handler: HandlerFn, req: *Request, fd: std.posix.fd_t, sid: u31, io: std.Io, deadline_ns: ?u64, opts: ServeOpts, peer_max_frame_size: u32) void {
    var res = Response{ .fd = fd, .sid = sid };
    var arena_buf: [CTX_ARENA_BYTES]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    var ctx = Context{ .fd = fd, .sid = sid, .deadline_ns = deadline_ns, .io = io, .allocator = fba.allocator(), .public_dir = opts.public_dir, .max_frame_size = peer_max_frame_size };

    // Cleared here rather than per connection: SETTINGS and the WINDOW_UPDATE frames that paced
    // this request's body were written before dispatch, and neither is the handler answering.
    frame.tl_responded = false;

    handler(req, &res, &ctx) catch {
        if (!res.sent and !frame.respondedFD()) {
            frame.sendResponseFD(fd, sid, 500, "text/plain", "Internal Server Error") catch {};
            res.status = 500;
        }
    };

    writeAccessRecord(req, &res, fd);
}

/// The logger this worker writes access records to, or null when none is attached.
///
/// Note:
/// - A threadlocal rather than a parameter because the multiplexed models install their per-worker
///   state once for the worker's whole life, and threading a logger through every dispatch call
///   would put that setup on the per-stream path instead.
pub threadlocal var tl_access_logger: ?*Logger = null;

/// Attach the access logger for this worker (or, under .ASYNC, for this connection).
pub fn setAccessLogger(logger: ?*Logger) void {
    tl_access_logger = logger;
}

/// Log one served stream, when a logger is attached.
///
/// Note:
/// - The whole call costs one threadlocal load and one branch when no logger is attached, which is
///   what keeps a raw engine paying nothing for a feature it did not ask for.
/// - The client address falls back to the socket when no proxy header names one, so a direct
///   request is logged with a real address rather than "-".
fn writeAccessRecord(req: *const Request, res: *const Response, fd: std.posix.fd_t) void {
    const logger = tl_access_logger orelse return;

    var peer_buf: [peer_addr.MAX_LEN]u8 = undefined;
    const client_ip = peer_addr.clientIp(
        req.header("x-forwarded-for") orelse "",
        req.header("x-real-ip") orelse "",
        fd,
        &peer_buf,
    );

    logger.access(
        "http2",
        req.method,
        req.path,
        res.status,
        res.bytes_written,
        client_ip,
        req.header("user-agent") orelse "",
        req.header("origin") orelse "",
    );
}

pub const ServeOpts = struct {
    /// Maximum concurrent streams per connection (advertised SETTINGS_MAX_CONCURRENT_STREAMS). Each
    /// stream's slot is borrowed from a per-worker pool, so this is not reserved per connection.
    max_streams: usize = 128,
    /// MAX_FRAME_SIZE sent in server SETTINGS.
    max_frame_size: u32 = frame.DEFAULT_MAX_FRAME_SIZE,
    /// HPACK scratch buffer size per connection (header string storage).
    max_header_scratch: usize = 4096,
    /// Maximum request body buffered per stream in bytes. A body past what a stream can hold is shed
    /// with 413 rather than truncated, so a handler never receives a partial one. The multiplexed
    /// models size a pooled stream's buffer by this, the blocking model uses its own fixed per-stream
    /// buffer and sheds at that.
    max_body: usize = 16384,
    /// Where served streams are recorded, from config.logger. Null logs nothing.
    logger: ?*Logger = null,
    /// Per-connection read buffer floor in bytes. The reader is sized to the larger of this and
    /// one max frame, so a larger floor cuts read() and compaction for big frames.
    conn_read_buf_min: usize = 32 * 1024,
    /// Initial capacity in bytes of the per-connection TLS pending-write buffer (it grows on demand).
    /// A larger initial avoids early reallocation under big responses on the TLS path.
    tls_write_buf_initial: usize = 16 * 1024,
    /// Enable the per-worker response cache (ADR-036). When off, serveCached / sendCachedFD degrade to
    /// a plain send. Active under every dispatch model (shared-nothing: one owner per multiplexed
    /// worker, one per io pool thread under .ASYNC).
    response_cache: bool = false,
    /// Response cache slot count, rounded down to a power of two by ResponseCache.init.
    cache_max_entries: u32 = 256,
    /// Per-slot response cap in bytes. A response larger than this bypasses the cache.
    cache_max_value_bytes: u32 = 16 * 1024,
    /// Default freshness in milliseconds, exposed to handlers via cacheTtl().
    cache_ttl_ms: u32 = 1000,
    /// Optional ceiling on per-worker cache memory in bytes. 0 disables the ceiling. When set, the
    /// effective entry count is reduced so entries * value_bytes fits (see effectiveCacheEntries).
    cache_max_total_bytes: usize = 0,
    /// Server-wide default handler processing timeout in milliseconds. 0 = disabled.
    /// Seeds Context.deadline_ns at dispatch. The handler may extend or override via setTimeout/withTimeout.
    handler_timeout_ms: u32 = 0,
    /// Root directory for static file serving, carried onto Context so the router can reach it
    /// without a threadlocal. Empty disables static serving.
    public_dir: []const u8 = "",
};

// --------------------------------------------------------- //

const StreamState = enum { IDLE, OPEN, HALF_CLOSED_REMOTE, CLOSED };

/// Per-stream request body buffer size (bytes a single stream can accumulate).
const STREAM_BODY_BUF_SIZE: usize = 64 * 1024;
/// Per-stream scratch buffer for building the HPACK-decoded header block.
const STREAM_HEADER_SCRATCH_SIZE: usize = 4096;

const Stream = struct {
    id: u31,
    state: StreamState,
    headers: [frame.MAX_HEADERS]hpack.Header,
    header_count: usize,
    body: [STREAM_BODY_BUF_SIZE]u8,
    body_len: usize,
    header_scratch: [STREAM_HEADER_SCRATCH_SIZE]u8,
    end_headers: bool,
    end_stream: bool,
};

// --------------------------------------------------------- //

/// Read some bytes from fd: the ntdll shim on Windows, std.posix.read elsewhere.
fn readOnceFD(fd: std.posix.fd_t, buf: []u8) !usize {
    if (comptime @import("builtin").target.os.tag == .windows) return win_io.readOnce(fd, buf);

    return std.posix.read(fd, buf);
}

/// Serve one h2c connection. Takes raw fd extracted by the server dispatch layer.
/// Caller owns the fd and must close it after this exits.
pub fn serveConn(handler: HandlerFn, fd: std.posix.fd_t, opts: ServeOpts, io: std.Io) void {
    if (comptime @import("builtin").target.os.tag != .windows) {
        // std.posix.TCP is void on the BSDs in Zig 0.16: TCP_NODELAY is 1 there.
        const nodelay: u32 = if (comptime std.posix.TCP != void) std.posix.TCP.NODELAY else 1;

        std.posix.setsockopt(
            fd,
            std.posix.IPPROTO.TCP,
            nodelay,
            std.mem.asBytes(&@as(c_int, 1)),
        ) catch {};
    }
    serveConnInner(handler, fd, opts, io) catch {};
}

fn serveConnInner(handler: HandlerFn, fd: std.posix.fd_t, opts: ServeOpts, io: std.Io) !void {
    var peek: [3]u8 = undefined;
    try frame.recvExact(fd, &peek);

    if (std.mem.eql(u8, &peek, "PRI")) {
        var rest: [21]u8 = undefined;
        try frame.recvExact(fd, &rest);
        var preface: [24]u8 = undefined;
        @memcpy(preface[0..3], &peek);
        @memcpy(preface[3..], &rest);
        if (!std.mem.eql(u8, &preface, frame.PREFACE)) {
            frame.sendGoawayFD(fd, 0, frame.ERR_PROTOCOL_ERROR) catch {};
            return error.ZixBadPreface;
        }
        try frame.sendSettingsFD(fd, &.{
            .{ frame.SETTINGS_MAX_CONCURRENT_STREAMS, @as(u32, @intCast(opts.max_streams)) },
            .{ frame.SETTINGS_INITIAL_WINDOW_SIZE, 65535 },
            .{ frame.SETTINGS_MAX_FRAME_SIZE, opts.max_frame_size },
            .{ frame.SETTINGS_ENABLE_PUSH, 0 },
        });
        var hpack_dec = hpack.HpackDecoder.init();
        try serveH2cLoop(handler, fd, &hpack_dec, opts, 0, io, frame.DEFAULT_MAX_FRAME_SIZE);
    } else {
        try serveH2cUpgrade(handler, fd, opts, &peek, io);
    }
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

fn serveH2cUpgrade(handler: HandlerFn, fd: std.posix.fd_t, opts: ServeOpts, prefix: *const [3]u8, io: std.Io) !void {
    var head_buf: [UPGRADE_HEAD_BUF]u8 = undefined;
    var filled: usize = 3;
    @memcpy(head_buf[0..3], prefix);
    while (std.mem.indexOf(u8, head_buf[0..filled], "\r\n\r\n") == null) {
        if (filled >= head_buf.len) return error.ZixHeaderTooLarge;
        const n = readOnceFD(fd, head_buf[filled..]) catch return error.ZixClosed;
        if (n == 0) return error.ZixClosed;
        filled += n;
    }
    const hdr_end = std.mem.indexOf(u8, head_buf[0..filled], "\r\n\r\n").? + 4;

    const upgrade = getHttp1Header(head_buf[0..hdr_end], "upgrade") orelse {
        frame.writeAllFD(fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n") catch {};
        return error.ZixBadRequest;
    };
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade, " "), "h2c")) {
        frame.writeAllFD(fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n") catch {};
        return error.ZixBadRequest;
    }

    var method: []const u8 = "GET";
    var path: []const u8 = "/";
    if (std.mem.indexOfScalar(u8, head_buf[0..hdr_end], ' ')) |sp1| {
        method = head_buf[0..sp1];
        const after = head_buf[sp1 + 1 .. hdr_end];
        if (std.mem.indexOfScalar(u8, after, ' ')) |sp2| path = after[0..sp2];
    }

    try frame.writeAllFD(
        fd,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Connection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
    );

    var preface: [24]u8 = undefined;
    try frame.recvExact(fd, &preface);
    if (!std.mem.eql(u8, &preface, frame.PREFACE)) {
        frame.sendGoawayFD(fd, 0, frame.ERR_PROTOCOL_ERROR) catch {};
        return error.ZixBadPreface;
    }

    var hpack_dec = hpack.HpackDecoder.init();
    var peer_max_frame_size: u32 = frame.DEFAULT_MAX_FRAME_SIZE;
    if (getHttp1Header(head_buf[0..hdr_end], "http2-settings")) |b64| {
        const trimmed = std.mem.trim(u8, b64, " ");
        var decoded: [SETTINGS_DECODE_SCRATCH]u8 = undefined;
        const dlen = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(trimmed) catch 0;
        if (dlen > 0 and dlen <= decoded.len) {
            std.base64.url_safe_no_pad.Decoder.decode(decoded[0..dlen], trimmed) catch {};
            var i: usize = 0;
            while (i + 6 <= dlen) : (i += 6) {
                const id: u16 = (@as(u16, decoded[i]) << 8) | decoded[i + 1];
                const val: u32 = (@as(u32, decoded[i + 2]) << 24) | (@as(u32, decoded[i + 3]) << 16) |
                    (@as(u32, decoded[i + 4]) << 8) | decoded[i + 5];
                if (id == frame.SETTINGS_HEADER_TABLE_SIZE) {
                    hpack_dec.max_size = val;
                    hpack_dec.evictTo(val);
                }
                // The upgrade header carries the client's SETTINGS, so the frame ceiling for the
                // carried stream-1 response is known before a single frame is exchanged.
                if (id == frame.SETTINGS_MAX_FRAME_SIZE and val >= frame.DEFAULT_MAX_FRAME_SIZE and val <= 16_777_215) {
                    peer_max_frame_size = val;
                }
            }
        }
    }

    try frame.sendSettingsFD(fd, &.{
        .{ frame.SETTINGS_MAX_CONCURRENT_STREAMS, @as(u32, @intCast(opts.max_streams)) },
        .{ frame.SETTINGS_INITIAL_WINDOW_SIZE, 65535 },
        .{ frame.SETTINGS_MAX_FRAME_SIZE, opts.max_frame_size },
        .{ frame.SETTINGS_ENABLE_PUSH, 0 },
    });

    var s1_hdrs = [3]hpack.Header{
        .{ .name = ":method", .value = method },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = "http" },
    };
    const split = Request.splitPath(path);
    var req = Request{ .method = method, .path = split.path, .query = split.query, .headers = &s1_hdrs, .body = &.{} };
    const deadline_ns: ?u64 = if (opts.handler_timeout_ms > 0) wallClockNs() + @as(u64, opts.handler_timeout_ms) * std.time.ns_per_ms else null;
    invokeHandler(handler, &req, fd, 1, io, deadline_ns, opts, peer_max_frame_size);

    try serveH2cLoop(handler, fd, &hpack_dec, opts, 1, io, peer_max_frame_size);
}

fn serveH2cLoop(
    handler: HandlerFn,
    fd: std.posix.fd_t,
    hpack_dec: *hpack.HpackDecoder,
    opts: ServeOpts,
    initial_last_stream: u31,
    io: std.Io,
    initial_peer_max_frame_size: u32,
) !void {
    // Tracks the peer's SETTINGS_MAX_FRAME_SIZE for the life of the connection. A peer may raise it
    // mid-connection, so this is a running value rather than a constant read once at the preface.
    var peer_max_frame_size: u32 = initial_peer_max_frame_size;

    const max_payload = opts.max_frame_size + frame.FRAME_PAYLOAD_SLACK;
    const payload_buf = try std.heap.smp_allocator.alloc(u8, max_payload);
    defer std.heap.smp_allocator.free(payload_buf);

    const streams = try std.heap.smp_allocator.alloc(Stream, opts.max_streams);
    defer std.heap.smp_allocator.free(streams);
    const stream_slots = try std.heap.smp_allocator.alloc(bool, opts.max_streams);
    defer std.heap.smp_allocator.free(stream_slots);
    @memset(stream_slots, false);

    var last_stream_id: u31 = initial_last_stream;

    while (true) {
        const fh = frame.readFrameHeader(fd) catch |err| {
            hangupGoaway(fd, streams, stream_slots, last_stream_id);

            return err;
        };

        if (fh.length > max_payload) {
            frame.sendGoawayFD(fd, last_stream_id, frame.ERR_FRAME_SIZE_ERROR) catch {};
            return error.ZixFrameTooLarge;
        }

        const payload = payload_buf[0..fh.length];
        if (fh.length > 0) try frame.recvExact(fd, payload);

        switch (fh.frame_type) {
            frame.FRAME_TYPE_SETTINGS => {
                if ((fh.flags & frame.FLAG_ACK) != 0) continue;
                var i: usize = 0;
                while (i + 6 <= payload.len) : (i += 6) {
                    const id: u16 = (@as(u16, payload[i]) << 8) | payload[i + 1];
                    const val: u32 = (@as(u32, payload[i + 2]) << 24) | (@as(u32, payload[i + 3]) << 16) |
                        (@as(u32, payload[i + 4]) << 8) | payload[i + 5];
                    if (id == frame.SETTINGS_HEADER_TABLE_SIZE) {
                        hpack_dec.max_size = val;
                        hpack_dec.evictTo(val);
                    }
                    // RFC 7540 6.5.2: a valid SETTINGS_MAX_FRAME_SIZE is 16384..16777215. Outbound
                    // DATA is capped to it so no frame the peer would reject with FRAME_SIZE_ERROR
                    // is ever emitted. An out-of-range value keeps the last good one.
                    if (id == frame.SETTINGS_MAX_FRAME_SIZE and val >= frame.DEFAULT_MAX_FRAME_SIZE and val <= 16_777_215) {
                        peer_max_frame_size = val;
                    }
                }
                try frame.sendSettingsAckFD(fd);
                try frame.sendWindowUpdateFD(fd, 0, frame.DEFAULT_WINDOW_SIZE);
            },

            frame.FRAME_TYPE_WINDOW_UPDATE => {},

            frame.FRAME_TYPE_PING => {
                if ((fh.flags & frame.FLAG_ACK) != 0) continue;
                if (payload.len != 8) {
                    frame.sendGoawayFD(fd, last_stream_id, frame.ERR_FRAME_SIZE_ERROR) catch {};
                    return error.ZixProtocolError;
                }
                var p8: [8]u8 = undefined;
                @memcpy(&p8, payload[0..8]);
                try frame.sendPingAckFD(fd, p8);
            },

            frame.FRAME_TYPE_HEADERS => {
                const sid = fh.stream_id;
                if (sid == 0) {
                    frame.sendGoawayFD(fd, last_stream_id, frame.ERR_PROTOCOL_ERROR) catch {};
                    return error.ZixProtocolError;
                }
                if (sid <= last_stream_id and sid % 2 == 1) {
                    frame.sendRstStreamFD(fd, sid, frame.ERR_STREAM_CLOSED) catch {};
                    continue;
                }
                last_stream_id = @max(last_stream_id, sid);

                const slot = slotFor(sid, streams, stream_slots) orelse {
                    frame.sendRstStreamFD(fd, sid, frame.ERR_REFUSED_STREAM) catch {};
                    continue;
                };
                const s = &streams[slot];
                s.* = std.mem.zeroes(Stream);
                s.id = sid;
                s.state = .OPEN;

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
                    frame.sendGoawayFD(fd, last_stream_id, frame.ERR_PROTOCOL_ERROR) catch {};
                    return error.ZixProtocolError;
                }
                block = block[offset .. block.len - pad_len];

                s.header_count = hpack_dec.decode(block, &s.headers, &s.header_scratch) catch {
                    frame.sendRstStreamFD(fd, sid, frame.ERR_COMPRESSION_ERROR) catch {};
                    stream_slots[slot] = false;
                    continue;
                };
                s.end_headers = (fh.flags & frame.FLAG_END_HEADERS) != 0;
                s.end_stream = (fh.flags & frame.FLAG_END_STREAM) != 0;

                if (s.end_headers and s.end_stream) {
                    dispatchWhole(handler, s, fd, opts, io, peer_max_frame_size);
                    stream_slots[slot] = false;
                }
            },

            frame.FRAME_TYPE_CONTINUATION => {
                const sid = fh.stream_id;
                const slot = findSlot(sid, streams, stream_slots) orelse {
                    frame.sendGoawayFD(fd, last_stream_id, frame.ERR_PROTOCOL_ERROR) catch {};
                    return error.ZixProtocolError;
                };
                const s = &streams[slot];
                const count = hpack_dec.decode(payload, s.headers[s.header_count..], &s.header_scratch) catch {
                    frame.sendRstStreamFD(fd, sid, frame.ERR_COMPRESSION_ERROR) catch {};
                    stream_slots[slot] = false;
                    continue;
                };
                s.header_count += count;
                s.end_headers = (fh.flags & frame.FLAG_END_HEADERS) != 0;
                if (s.end_headers and s.end_stream) {
                    dispatchWhole(handler, s, fd, opts, io, peer_max_frame_size);
                    stream_slots[slot] = false;
                }
            },

            frame.FRAME_TYPE_DATA => {
                const sid = fh.stream_id;
                if (sid == 0) {
                    frame.sendGoawayFD(fd, last_stream_id, frame.ERR_PROTOCOL_ERROR) catch {};
                    return error.ZixProtocolError;
                }
                const slot = findSlot(sid, streams, stream_slots) orelse {
                    frame.sendRstStreamFD(fd, sid, frame.ERR_STREAM_CLOSED) catch {};
                    continue;
                };
                const s = &streams[slot];

                var data = payload;
                var pad_len: usize = 0;
                if ((fh.flags & frame.FLAG_PADDED) != 0 and data.len > 0) {
                    pad_len = data[0];
                    data = data[1..];
                }
                if (pad_len > data.len) {
                    frame.sendGoawayFD(fd, last_stream_id, frame.ERR_PROTOCOL_ERROR) catch {};
                    return error.ZixProtocolError;
                }
                data = data[0 .. data.len - pad_len];

                // A body past max_body sheds the stream instead of truncating it: 413 with
                // END_STREAM, slot freed, so a corrupt body never dispatches. A follow-up DATA frame
                // finds no slot and is answered with RST_STREAM above. Only the connection window is
                // credited for the discarded bytes (the stream is done, the connection must stay
                // usable for its other streams). Same shed as the multiplexed models.
                if (data.len > s.body.len - s.body_len) {
                    if (data.len > 0) frame.sendWindowUpdateFD(fd, 0, @intCast(data.len)) catch {};
                    frame.sendResponseFD(fd, sid, 413, "text/plain", "") catch {};
                    stream_slots[slot] = false;

                    continue;
                }

                if (data.len > 0) {
                    frame.sendWindowUpdateFD(fd, 0, @intCast(data.len)) catch {};
                    frame.sendWindowUpdateFD(fd, sid, @intCast(data.len)) catch {};
                }

                @memcpy(s.body[s.body_len..][0..data.len], data);
                s.body_len += data.len;

                s.end_stream = (fh.flags & frame.FLAG_END_STREAM) != 0;
                if (s.end_stream) {
                    dispatchWhole(handler, s, fd, opts, io, peer_max_frame_size);
                    stream_slots[slot] = false;
                }
            },

            frame.FRAME_TYPE_RST_STREAM => {
                const sid = fh.stream_id;
                if (findSlot(sid, streams, stream_slots)) |slot| {
                    stream_slots[slot] = false;
                }
            },

            frame.FRAME_TYPE_GOAWAY => return,

            frame.FRAME_TYPE_PRIORITY => {},

            else => {},
        }
    }
}

/// Dispatch a stream whose END_STREAM has arrived, unless its body is short of (or past) the
/// content-length its own headers declared.
///
/// Note:
/// - RFC 9113 8.1.1 makes that request malformed, a stream error of type PROTOCOL_ERROR, so the
///   stream is reset instead. A handler is therefore never handed a body that is not whole, which is
///   the same promise the multiplexed models make.
/// - The caller frees the slot either way, so nothing is left holding it.
///
/// Param:
/// handler - HandlerFn (the router entry point)
/// stream - *Stream (the stream whose request side just closed)
/// fd - std.posix.fd_t (connection fd)
/// opts - ServeOpts (serve limits carried to the handler trio)
/// io - std.Io (backend carried on Context)
/// peer_max_frame_size - u32 (largest DATA frame the peer accepts)
///
/// Return:
/// - void
fn dispatchWhole(handler: HandlerFn, stream: *Stream, fd: std.posix.fd_t, opts: ServeOpts, io: std.Io, peer_max_frame_size: u32) void {
    if (!stream_body.isWhole(stream.headers[0..stream.header_count], stream.body_len)) {
        frame.sendRstStreamFD(fd, stream.id, frame.ERR_PROTOCOL_ERROR) catch {};

        return;
    }

    dispatchStream(handler, stream, fd, opts, io, peer_max_frame_size);
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
/// fd - std.posix.fd_t (connection fd)
/// streams - []const Stream (the connection's stream table)
/// used - []const bool (which entries of the table are live)
/// last_stream_id - u31 (highest stream id seen, carried on the GOAWAY)
///
/// Return:
/// - void
fn hangupGoaway(fd: std.posix.fd_t, streams: []const Stream, used: []const bool, last_stream_id: u31) void {
    if (!requestInFlight(streams, used)) return;

    frame.sendGoawayFD(fd, last_stream_id, frame.ERR_PROTOCOL_ERROR) catch {};
}

/// Whether any stream is still waiting for the rest of its request.
///
/// Param:
/// streams - []const Stream (the connection's stream table)
/// used - []const bool (which entries of the table are live)
///
/// Return:
/// - bool (true when a request was in flight)
fn requestInFlight(streams: []const Stream, used: []const bool) bool {
    for (used, 0..) |in_use, slot| {
        if (in_use and !streams[slot].end_stream) return true;
    }

    return false;
}

fn slotFor(sid: u31, streams: []Stream, used: []bool) ?usize {
    for (used, 0..) |u, i| {
        if (!u) {
            used[i] = true;
            streams[i].id = sid;
            return i;
        }
    }
    return null;
}

fn findSlot(sid: u31, streams: []Stream, used: []bool) ?usize {
    for (used, 0..) |u, i| {
        if (u and streams[i].id == sid) return i;
    }
    return null;
}

fn dispatchStream(handler: HandlerFn, stream: *Stream, fd: std.posix.fd_t, opts: ServeOpts, io: std.Io, peer_max_frame_size: u32) void {
    var method: []const u8 = "GET";
    var raw_path: []const u8 = "/";
    for (stream.headers[0..stream.header_count]) |h| {
        // The two pseudo-headers have distinct lengths (":path" 5, ":method" 7),
        // so dispatch on length first and do at most one compare per header.
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
    var req = Request{
        .method = method,
        .path = split.path,
        .query = split.query,
        .headers = stream.headers[0..stream.header_count],
        .body = stream.body[0..stream.body_len],
    };
    const deadline_ns: ?u64 = if (opts.handler_timeout_ms > 0) wallClockNs() + @as(u64, opts.handler_timeout_ms) * std.time.ns_per_ms else null;
    invokeHandler(handler, &req, fd, stream.id, io, deadline_ns, opts, peer_max_frame_size);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http2: ServeOpts defaults" {
    const opts = ServeOpts{};
    try std.testing.expectEqual(@as(usize, 128), opts.max_streams);
    try std.testing.expectEqual(frame.DEFAULT_MAX_FRAME_SIZE, opts.max_frame_size);
}

test "zix http2: response cache round-trips via sendCachedFD then serveCached" {
    var cache = try rc.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 1024 });
    defer cache.deinit();
    setCache(&cache, 1000);
    defer setCache(null, 0);

    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();
    const fds = pair.fds;

    tl_req_path = "/cached";
    tl_req_body = "";
    defer {
        tl_req_path = "";
        tl_req_body = "";
    }

    // a miss before anything is stored: the handler should build the response itself
    try std.testing.expect(!serveCached(fds[1], 1, "text/plain"));

    // store under the current request key, then a later request with the same key hits and is
    // re-framed for its own stream id
    sendCachedFD(fds[1], 1, "text/plain", "hello-cached");
    try std.testing.expect(serveCached(fds[1], 3, "text/plain"));

    // a different request key still misses
    tl_req_path = "/other";
    try std.testing.expect(!serveCached(fds[1], 5, "text/plain"));
}

test "zix http2: a served stream writes one access record naming the engine" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    setAccessLogger(&logger);
    defer setAccessLogger(null);

    const headers = [_]hpack.Header{
        .{ .name = "x-real-ip", .value = "198.51.100.9" },
        .{ .name = "user-agent", .value = "h2load/1.0" },
    };
    var req = Request{
        .method = "POST",
        .path = "/rpc/submit",
        .query = "",
        .headers = &headers,
        .body = "",
    };

    invokeHandler(accessProbeHandler, &req, fds[1], 1, std.testing.io, null, .{}, frame.DEFAULT_MAX_FRAME_SIZE);
    logger.flush();

    const line = try readAccessLine(tmp.dir, std.testing.allocator);
    defer std.testing.allocator.free(line);

    std.log.info(".ACCESS: {s}", .{std.mem.trimEnd(u8, line, "\n")});

    try std.testing.expect(std.mem.indexOf(u8, line, "[http2:access] POST /rpc/submit 202 7 \"198.51.100.9\" \"h2load/1.0\" \"-\"") != null);
}

test "zix http2: a served stream writes no access record when no logger is attached" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    setAccessLogger(null);

    var req = Request{ .method = "GET", .path = "/", .query = "", .headers = &.{}, .body = "" };

    // The point is that it does not reach for a logger it does not have.
    invokeHandler(accessProbeHandler, &req, fds[1], 1, std.testing.io, null, .{}, frame.DEFAULT_MAX_FRAME_SIZE);
}

fn accessProbeHandler(req: *Request, res: *Response, ctx: *Context) !void {
    _ = req;
    _ = ctx;

    res.setStatus(202);
    try res.send("queued!");
}

// --------------------------------------------------------- //
// Handler-error completion: one answer per stream, whichever way the handler answered

/// Answers through the fd writers, then returns an error. The engine must leave the stream alone.
fn fdThenErrorHandler(req: *Request, res: *Response, ctx: *Context) !void {
    _ = req;
    _ = res;

    try frame.sendResponseFD(ctx.fd, ctx.sid, 200, "text/plain", "fd answered");

    return error.ZixProbeFailure;
}

/// Answers through the Response builder, then returns an error. The engine must leave it alone.
fn responseThenErrorHandler(req: *Request, res: *Response, ctx: *Context) !void {
    _ = req;
    _ = ctx;

    try res.send("res answered");

    return error.ZixProbeFailure;
}

/// Returns an error having answered nothing. The engine owes this stream a 500.
fn errorBeforeAnswerHandler(req: *Request, res: *Response, ctx: *Context) !void {
    _ = req;
    _ = res;
    _ = ctx;

    return error.ZixProbeFailure;
}

/// Swallows its own failure and returns cleanly. The engine adds nothing, the handler owns it.
fn swallowedErrorHandler(req: *Request, res: *Response, ctx: *Context) !void {
    _ = req;
    _ = ctx;

    res.send("swallowed") catch {
        // The send is against a live socketpair here, so reaching this block at all means the
        // wire broke and the frame count below would be reading a truncated stream.
        return error.ZixProbeFailure;
    };
}

/// Drive one handler over a socketpair and hand back every byte the peer end received.
fn h2WireOf(handler: HandlerFn, buf: []u8) ![]u8 {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);

    var req = Request{
        .method = "GET",
        .path = "/probe",
        .query = "",
        .headers = &[_]hpack.Header{},
        .body = "",
    };

    invokeHandler(handler, &req, fds[1], 1, std.testing.io, null, .{}, frame.DEFAULT_MAX_FRAME_SIZE);

    // Closed before the read so the peer sees EOF rather than blocking on a live socket.
    _ = std.os.linux.close(fds[1]);

    const n = std.posix.read(fds[0], buf) catch 0;

    return buf[0..n];
}

/// Count HEADERS frames addressed to stream 1 in a raw h2 byte stream. Two of them for one
/// request is the defect this guards: a response the peer already read, then a second one.
fn countHeadersFrames(wire: []const u8) usize {
    var pos: usize = 0;
    var found: usize = 0;

    while (pos + frame.FRAME_HEADER_LEN <= wire.len) {
        const length = (@as(usize, wire[pos]) << 16) | (@as(usize, wire[pos + 1]) << 8) | wire[pos + 2];
        if (wire[pos + 3] == frame.FRAME_TYPE_HEADERS) found += 1;

        pos += frame.FRAME_HEADER_LEN + length;
    }

    return found;
}

test "zix http2: an fd answer followed by a handler error is not answered a second time" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socketpair, test skipped", .{});
        return;
    }

    var buf: [4096]u8 = undefined;
    const wire = try h2WireOf(fdThenErrorHandler, &buf);

    std.log.info(".WIRE: {d} bytes, {d} HEADERS frames", .{ wire.len, countHeadersFrames(wire) });

    try std.testing.expectEqual(@as(usize, 1), countHeadersFrames(wire));
    try std.testing.expect(std.mem.indexOf(u8, wire, "fd answered") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire, "Internal Server Error") == null);
}

test "zix http2: a Response answer followed by a handler error is not answered a second time" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socketpair, test skipped", .{});
        return;
    }

    var buf: [4096]u8 = undefined;
    const wire = try h2WireOf(responseThenErrorHandler, &buf);

    try std.testing.expectEqual(@as(usize, 1), countHeadersFrames(wire));
    try std.testing.expect(std.mem.indexOf(u8, wire, "res answered") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire, "Internal Server Error") == null);
}

test "zix http2: a handler error with nothing answered is completed as one 500" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socketpair, test skipped", .{});
        return;
    }

    var buf: [4096]u8 = undefined;
    const wire = try h2WireOf(errorBeforeAnswerHandler, &buf);

    try std.testing.expectEqual(@as(usize, 1), countHeadersFrames(wire));
    try std.testing.expect(std.mem.indexOf(u8, wire, "Internal Server Error") != null);
}

test "zix http2: an error the handler swallows itself gets nothing from the engine" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socketpair, test skipped", .{});
        return;
    }

    var buf: [4096]u8 = undefined;
    const wire = try h2WireOf(swallowedErrorHandler, &buf);

    try std.testing.expectEqual(@as(usize, 1), countHeadersFrames(wire));
    try std.testing.expect(std.mem.indexOf(u8, wire, "swallowed") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire, "Internal Server Error") == null);
}

/// Read back the one log file written under a temp root, for the access tests above.
fn readAccessLine(root: std.Io.Dir, allocator: std.mem.Allocator) ![]u8 {
    var days = root.iterate();

    while (try days.next(std.testing.io)) |entry| {
        if (entry.kind != .directory) continue;

        var day = try root.openDir(std.testing.io, entry.name, .{});
        defer day.close(std.testing.io);

        const bytes = day.readFileAlloc(std.testing.io, "log-000000.log", allocator, .limited(64 * 1024)) catch continue;
        if (bytes.len > 0) return bytes;

        allocator.free(bytes);
    }

    return error.ZixNoLogLine;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

var async_dispatches: usize = 0;
var async_body_len: usize = 0;

fn asyncBodyHandler(req: *Request, res: *Response, _: *Context) anyerror!void {
    async_dispatches += 1;
    async_body_len = req.body.len;

    try res.sendText("ok");
}

const async_body_router = Router(&[_]Route{.{ .path = "/", .handler = asyncBodyHandler }});

/// Write one complete frame (9-byte header + payload) to a fd, the way a client would.
fn writeFrameTo(fd: std.posix.fd_t, ftype: u8, flags: u8, sid: u31, payload: []const u8) !void {
    var fh: [9]u8 = undefined;
    frame.encodeFrameHeader(&fh, .{ .length = @intCast(payload.len), .frame_type = ftype, .flags = flags, .stream_id = sid });

    try frame.writeAllFD(fd, &fh);
    if (payload.len > 0) try frame.writeAllFD(fd, payload);
}

/// What the blocking loop answered with, read back after it returned.
const AsyncWireTally = struct {
    rst_protocol_error: usize = 0,
    goaway_protocol_error: usize = 0,
    status_200: usize = 0,
    status_413: usize = 0,
};

fn tallyAsyncWire(read_fd: std.posix.fd_t, server_fd: std.posix.fd_t, buf: []u8) AsyncWireTally {
    // The server end still holds the socket open, so without this the read below waits on bytes that
    // are never coming rather than ending at EOF.
    _ = std.os.linux.shutdown(server_fd, std.os.linux.SHUT.WR);

    var total: usize = 0;
    while (total < buf.len) {
        const got = std.posix.read(read_fd, buf[total..]) catch break;
        if (got == 0) break;
        total += got;
    }

    var tally = AsyncWireTally{};
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
                if (std.mem.readInt(u32, payload[0..4], .big) == frame.ERR_PROTOCOL_ERROR) tally.rst_protocol_error += 1;
            },
            frame.FRAME_TYPE_GOAWAY => {
                if (std.mem.readInt(u32, payload[4..8], .big) == frame.ERR_PROTOCOL_ERROR) tally.goaway_protocol_error += 1;
            },
            frame.FRAME_TYPE_HEADERS => {
                var hdrs: [frame.MAX_HEADERS]hpack.Header = undefined;
                var scratch: [256]u8 = undefined;
                const count = dec.decode(payload, &hdrs, &scratch) catch continue;
                for (hdrs[0..count]) |hdr| {
                    if (!std.mem.eql(u8, hdr.name, ":status")) continue;
                    if (std.mem.eql(u8, hdr.value, "200")) tally.status_200 += 1;
                    if (std.mem.eql(u8, hdr.value, "413")) tally.status_413 += 1;
                }
            },
            else => {},
        }
    }

    return tally;
}

/// Encode a POST request head declaring `content_length`, ending the headers but not the stream.
fn encodeDeclaredPostHead(block: []u8, content_length: []const u8) ![]const u8 {
    var enc = hpack.HpackEncoder.init(block);
    try enc.writeHeader(":method", "POST");
    try enc.writeHeader(":path", "/");
    try enc.writeHeader("content-length", content_length);

    return enc.encoded();
}

/// Run the blocking frame loop over everything already written to the connection. The client end is
/// shut down for writing first, so the loop reaches EOF and returns instead of parking on a read.
fn runAsyncLoopToEof(client_fd: std.posix.fd_t, server_fd: std.posix.fd_t, opts: ServeOpts) void {
    _ = std.os.linux.shutdown(client_fd, std.os.linux.SHUT.WR);

    var dec = hpack.HpackDecoder.init();
    serveH2cLoop(async_body_router.dispatch, server_fd, &dec, opts, 0, std.testing.io, frame.DEFAULT_MAX_FRAME_SIZE) catch {};
}

test "zix http2: the blocking loop resets a stream whose body is short of its content-length" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    // 100 bytes promised, 40 delivered, then END_STREAM: the request never finished arriving
    var block: [128]u8 = undefined;
    const head = try encodeDeclaredPostHead(&block, "100");
    try writeFrameTo(fds[0], frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS, 1, head);

    const short: [40]u8 = @splat('x');
    try writeFrameTo(fds[0], frame.FRAME_TYPE_DATA, frame.FLAG_END_STREAM, 1, &short);

    async_dispatches = 0;
    runAsyncLoopToEof(fds[0], fds[1], .{});

    // the handler never ran, so no truncated body was ever served
    try std.testing.expectEqual(@as(usize, 0), async_dispatches);

    var buf: [8192]u8 = undefined;
    const tally = tallyAsyncWire(fds[0], fds[1], &buf);

    try std.testing.expectEqual(@as(usize, 1), tally.rst_protocol_error);
    try std.testing.expectEqual(@as(usize, 0), tally.status_200);
}

test "zix http2: the blocking loop serves a stream whose body matches its content-length" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var block: [128]u8 = undefined;
    const head = try encodeDeclaredPostHead(&block, "40");
    try writeFrameTo(fds[0], frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS, 1, head);

    const whole: [40]u8 = @splat('x');
    try writeFrameTo(fds[0], frame.FRAME_TYPE_DATA, frame.FLAG_END_STREAM, 1, &whole);

    async_dispatches = 0;
    async_body_len = 0;
    runAsyncLoopToEof(fds[0], fds[1], .{});

    // the guard only sheds a body that disagrees with its own headers, an honest one still serves
    try std.testing.expectEqual(@as(usize, 1), async_dispatches);
    try std.testing.expectEqual(@as(usize, 40), async_body_len);

    var buf: [8192]u8 = undefined;
    const tally = tallyAsyncWire(fds[0], fds[1], &buf);

    try std.testing.expectEqual(@as(usize, 0), tally.rst_protocol_error);
    try std.testing.expectEqual(@as(usize, 1), tally.status_200);
}

test "zix http2: the blocking loop sheds a body past the stream buffer with 413" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var block: [128]u8 = undefined;
    const head = try encodeDeclaredPostHead(&block, "70000");
    try writeFrameTo(fds[0], frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS, 1, head);

    // fill the per-stream buffer exactly, then one byte more: the stream is shed, not truncated
    const chunk = try std.testing.allocator.alloc(u8, frame.DEFAULT_MAX_FRAME_SIZE);
    defer std.testing.allocator.free(chunk);
    @memset(chunk, 'y');

    const frames = STREAM_BODY_BUF_SIZE / frame.DEFAULT_MAX_FRAME_SIZE;
    for (0..frames) |_| try writeFrameTo(fds[0], frame.FRAME_TYPE_DATA, 0, 1, chunk);
    try writeFrameTo(fds[0], frame.FRAME_TYPE_DATA, frame.FLAG_END_STREAM, 1, chunk[0..1]);

    async_dispatches = 0;
    runAsyncLoopToEof(fds[0], fds[1], .{});

    // no handler saw the first 64 KiB as though it were the whole 70000-byte body
    try std.testing.expectEqual(@as(usize, 0), async_dispatches);

    var buf: [32 * 1024]u8 = undefined;
    const tally = tallyAsyncWire(fds[0], fds[1], &buf);

    try std.testing.expectEqual(@as(usize, 1), tally.status_413);
    try std.testing.expectEqual(@as(usize, 0), tally.status_200);
}

test "zix http2: the blocking loop answers a peer that hangs up with a request unfinished" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    // a POST that opens its stream and never ends it, then the peer simply goes away
    var block: [128]u8 = undefined;
    const head = try encodeDeclaredPostHead(&block, "100");
    try writeFrameTo(fds[0], frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS, 1, head);

    async_dispatches = 0;
    runAsyncLoopToEof(fds[0], fds[1], .{});

    try std.testing.expectEqual(@as(usize, 0), async_dispatches);

    var buf: [8192]u8 = undefined;
    const tally = tallyAsyncWire(fds[0], fds[1], &buf);

    try std.testing.expectEqual(@as(usize, 1), tally.goaway_protocol_error);
}

test "zix http2: the blocking loop closes an idle connection without a GOAWAY" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    // one whole request, served and its slot given back: nothing is owed when the peer leaves
    var block: [128]u8 = undefined;
    var enc = hpack.HpackEncoder.init(&block);
    try enc.writeHeader(":method", "GET");
    try enc.writeHeader(":path", "/");
    try writeFrameTo(fds[0], frame.FRAME_TYPE_HEADERS, frame.FLAG_END_HEADERS | frame.FLAG_END_STREAM, 1, enc.encoded());

    async_dispatches = 0;
    runAsyncLoopToEof(fds[0], fds[1], .{});

    try std.testing.expectEqual(@as(usize, 1), async_dispatches);

    var buf: [8192]u8 = undefined;
    const tally = tallyAsyncWire(fds[0], fds[1], &buf);

    try std.testing.expectEqual(@as(usize, 0), tally.goaway_protocol_error);
    try std.testing.expectEqual(@as(usize, 1), tally.status_200);
}
