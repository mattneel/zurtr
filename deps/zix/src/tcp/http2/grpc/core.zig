//! gRPC h2c thread-per-connection loop, handler context, and path/content-type utilities.
//! The multiplexed .EPOLL / .URING connection state machine lives in mux.zig.

const std = @import("std");
const socket_pair = @import("../../../utils/socket_pair.zig");
const fd_io = @import("../../../utils/fd_io.zig");
const win_io = @import("../../../utils/windows_io.zig");
const peer_addr = @import("../../../utils/peer_addr.zig");
const h2 = @import("../Http2.zig");
const stream_body = @import("../stream_body.zig");
const frame = @import("frame.zig");
const status = @import("status.zig");
const Logger = @import("../../../logger/logger.zig").Logger;
const parseTimeout = @import("timeout.zig").parseTimeout;
const rc = @import("../../../utils/response_cache.zig");

/// Reply HPACK and frame staging buffer for one streamed response pass.
const reply_stage_scratch: usize = 4096;

/// Base64 decode scratch for the HTTP2-Settings header on an h2c upgrade.
const settings_decode_scratch: usize = 256;

/// Request line and header read bound for an h2c upgrade (HeaderTooLarge over this).
const upgrade_head_buf: usize = 8192;

/// Backing size of the per-request stack arena on Context.allocator. Stack-based
/// (std.heap.FixedBufferAllocator), no heap call, mirrors Fix/Http2's Context parity.
pub const CTX_ARENA_BYTES: usize = 4096;

pub const GrpcStatus = status.GrpcStatus;

/// Return the current wall-clock time in nanoseconds (CLOCK_REALTIME basis).
/// Use this when overriding ctx.deadline_ns at runtime inside a handler.
pub fn wallClockNs() u64 {
    if (comptime @import("builtin").target.os.tag == .linux) {
        var timespec: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &timespec);
        return @as(u64, @intCast(timespec.sec)) * std.time.ns_per_s + @as(u64, @intCast(timespec.nsec));
    }

    if (comptime @import("builtin").target.os.tag == .windows) return win_io.wallClockNs();

    var timespec: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &timespec);
    return @as(u64, @intCast(timespec.sec)) * std.time.ns_per_s + @as(u64, @intCast(timespec.nsec));
}

/// Return the current monotonic time in nanoseconds (CLOCK_MONOTONIC basis).
/// Use this for elapsed-duration measurements (request timing).
pub fn monotonicNs() u64 {
    if (comptime @import("builtin").target.os.tag == .linux) {
        var timespec: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &timespec);
        return @as(u64, @intCast(timespec.sec)) * std.time.ns_per_s + @as(u64, @intCast(timespec.nsec));
    }

    if (comptime @import("builtin").target.os.tag == .windows) return win_io.monotonicUs() * std.time.ns_per_us;

    var timespec: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &timespec);
    return @as(u64, @intCast(timespec.sec)) * std.time.ns_per_s + @as(u64, @intCast(timespec.nsec));
}

// --------------------------------------------------------- //

pub const GrpcContentType = enum { PROTO, JSON, UNKNOWN };

/// Detect gRPC content-type from request headers.
pub fn detectContentType(headers: []const h2.Header) GrpcContentType {
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "content-type")) continue;
        if (std.mem.startsWith(u8, header.value, "application/grpc+json")) return .JSON;
        if (std.mem.startsWith(u8, header.value, "application/grpc")) return .PROTO;
    }
    return .UNKNOWN;
}

/// gRPC path components from /<package.Service>/<Method>.
pub const GrpcPath = struct {
    package_service: []const u8,
    method: []const u8,
};

/// Parse /<package.Service>/<Method> path.
///
/// Return:
/// - ?GrpcPath (null for invalid paths)
pub fn parsePath(path: []const u8) ?GrpcPath {
    if (path.len < 2 or path[0] != '/') return null;
    const rest = path[1..];
    const slash = std.mem.lastIndexOfScalar(u8, rest, '/') orelse return null;
    if (slash == 0 or slash + 1 >= rest.len) return null;
    return .{ .package_service = rest[0..slash], .method = rest[slash + 1 ..] };
}

// --------------------------------------------------------- //

/// Per-stream context passed to HandlerFn.
/// Buffers all inbound gRPC messages. Handler calls recvMessage() to iterate
/// and sendMessage()/finish() to respond.
pub const GrpcContext = struct {
    fd: std.posix.fd_t,
    stream_id: u31,
    /// Full gRPC path of this call (e.g. "/pkg.Svc/Method"). Set at dispatch.
    /// Used as part of the response cache key. Empty when unset.
    path: []const u8 = "",
    _body: []const u8,
    _pos: usize,
    _hdr_sent: bool,
    _sent_bytes: usize,
    _grpc_status: u8,
    /// Whether the handler closed this call with `finish`. Read by the engine on a handler error,
    /// so a call the handler already answered is not answered a second time with a status the
    /// handler did not choose.
    _finished: bool = false,
    /// Absolute deadline in nanoseconds (CLOCK_REALTIME basis). Null = no deadline.
    /// Set at dispatch from tighter_of(Route.timeout_ms, config.handler_timeout_ms, grpc-timeout header).
    /// Handler may read and overwrite. Use isExpired() to check.
    deadline_ns: ?u64 = null,
    /// Shared connection-level write spinlock. Null when no concurrent writes are possible.
    /// Held for the entire duration of each frame write to prevent interleaving across streams.
    _write_mutex: ?*ConnMutex = null,
    /// Optional corked output buffer. When set (inline unary path), HEADERS, DATA and the
    /// trailer are staged here and flushed in a single write() after the handler returns.
    /// Null on the streaming path, which writes each frame directly under _write_mutex.
    _out: ?*ReplyStage = null,
    /// When true, sendMessage compresses DATA payloads with gzip and emits grpc-encoding: gzip
    /// in the initial HEADERS frame. Set at dispatch when opts.compress is enabled and
    /// the client advertised grpc-accept-encoding: gzip.
    _resp_gzip: bool = false,
    /// Server-streaming DATA-frame coalescing buffer. When set (the mux streaming path), sendMessage
    /// packs gRPC-framed messages here and emits them as one h2 DATA frame per grpc_stream_coalesce_cap
    /// worth of payload, instead of one tiny DATA frame per message. Null on the unary and thread
    /// paths, which keep one frame per message. _coal_len is the bytes currently packed.
    _coal: ?[]u8 = null,
    _coal_len: usize = 0,
    /// Io backend for the connection. Carried for symmetry with the other engines' Context.
    io: std.Io,
    /// Per-request scratch allocator, backed by a stack buffer (no heap call).
    allocator: std.mem.Allocator,

    /// Return a copy with the deadline set to now + ms.
    pub fn withTimeout(self: GrpcContext, ms: u64) GrpcContext {
        var ctx = self;
        ctx.deadline_ns = wallClockNs() + ms * std.time.ns_per_ms;

        return ctx;
    }

    /// Set the deadline to now + ms in place.
    pub fn setTimeout(self: *GrpcContext, ms: u64) void {
        self.deadline_ns = wallClockNs() + ms * std.time.ns_per_ms;
    }

    /// Return a copy with an explicit absolute deadline (wall-clock nanoseconds).
    pub fn withDeadline(self: GrpcContext, deadline_ns: u64) GrpcContext {
        var ctx = self;
        ctx.deadline_ns = deadline_ns;

        return ctx;
    }

    /// Whether the deadline has passed. False when no deadline is set. The
    /// handler must check this explicitly, it does not interrupt anything.
    pub fn timedOut(self: *const GrpcContext) bool {
        return self.isExpired();
    }

    /// Read the next gRPC message from the buffered request stream.
    /// Slices point into the body buffer. Valid for the duration of the handler call.
    ///
    /// Return:
    /// - ?[]const u8 (null when all client messages are consumed)
    pub fn recvMessage(self: *GrpcContext) ?[]const u8 {
        const remaining = self._body[self._pos..];
        if (remaining.len < frame.grpc_prefix_len) return null;
        const msg_len = std.mem.readInt(u32, remaining[1..frame.grpc_prefix_len], .big);
        const total = frame.grpc_prefix_len + @as(usize, msg_len);
        if (total > remaining.len) return null;
        const message = remaining[frame.grpc_prefix_len..total];
        self._pos += total;
        return message;
    }

    /// Write initial HEADERS if not already sent. No lock acquired, caller must hold _write_mutex.
    ///
    /// Return:
    /// - void
    /// - error.BrokenPipe when the write failed, or the staged reply already failed one
    fn _flushHeaders(self: *GrpcContext, content_type: []const u8) error{BrokenPipe}!void {
        if (self._hdr_sent) return;

        if (self._out) |out| {
            if (out.failed) return error.BrokenPipe;

            var buf: [frame.headers_frame_scratch]u8 = undefined;
            const n = if (self._resp_gzip)
                frame.buildGrpcHeadersGzip(&buf, self.stream_id, content_type)
            else
                frame.buildGrpcHeaders(&buf, self.stream_id, content_type);
            out.append(buf[0..n]);

            self._hdr_sent = true;

            return if (out.failed) error.BrokenPipe else {};
        }

        if (self._resp_gzip) {
            var buf: [frame.headers_frame_scratch]u8 = undefined;
            const n = frame.buildGrpcHeadersGzip(&buf, self.stream_id, content_type);
            h2.writeAllFD(self.fd, buf[0..n]) catch return error.BrokenPipe;
        } else {
            frame.sendGrpcHeadersFD(self.fd, self.stream_id, content_type) catch return error.BrokenPipe;
        }

        self._hdr_sent = true;
    }

    /// Send the initial response HEADERS (:status 200, content-type). No-op if already sent.
    ///
    /// Return:
    /// - void
    /// - error.BrokenPipe when the peer is gone. `try` hands it to the engine, which answers the
    ///   call with a gRPC status. Handle it yourself to answer differently.
    pub fn sendHeaders(self: *GrpcContext, content_type: []const u8) error{BrokenPipe}!void {
        if (self._out != null) {
            return self._flushHeaders(content_type);
        }

        if (self._write_mutex) |mutex| mutex.lock();
        defer {
            if (self._write_mutex) |mutex| mutex.unlock();
        }

        return self._flushHeaders(content_type);
    }

    /// Send one gRPC response message DATA frame.
    /// Sends initial headers first if not yet sent.
    /// When _resp_gzip is true, the payload is gzip-compressed before sending and the
    /// compress flag in the 5-byte gRPC prefix is set to 1.
    /// Falls back to uncompressed on allocation or compression failure.
    /// On the staged (inline unary) path the frame is appended to the cork buffer.
    /// On the streaming path headers and data are written under a single lock to prevent interleaving.
    ///
    /// Return:
    /// - void
    /// - error.BrokenPipe when the peer is gone. `try` hands it to the engine, which answers the
    ///   call with a gRPC status. Handle it yourself to answer differently.
    pub fn sendMessage(self: *GrpcContext, content_type: []const u8, data: []const u8) error{BrokenPipe}!void {
        if (self._resp_gzip and data.len > 0) {
            const max_comp = data.len + frame.gzip_framing_headroom;
            if (std.heap.smp_allocator.alloc(u8, max_comp)) |comp_buf| {
                defer std.heap.smp_allocator.free(comp_buf);

                // A compression failure is not the caller's problem: the message still goes out,
                // uncompressed, through the fall-through below.
                if (frame.compressGrpcMessage(data, comp_buf)) |comp_len| {
                    return self._sendDataFrame(content_type, comp_buf[0..comp_len], true);
                } else |_| {}
            } else |_| {}
        }

        return self._sendDataFrame(content_type, data, false);
    }

    /// Emit the packed coalesce buffer as one h2 DATA frame into the cork, then reset it. No-op when
    /// nothing is packed. The frame length is known up front, so no back-patch is needed and the cork
    /// may flush freely between frames.
    fn _emitCoalesced(self: *GrpcContext, out: *ReplyStage) void {
        if (self._coal_len == 0) return;

        const coal = self._coal.?;
        var hdr: [h2.FRAME_HEADER_LEN]u8 = undefined;
        h2.encodeFrameHeader(&hdr, .{
            .length = @intCast(self._coal_len),
            .frame_type = h2.FRAME_TYPE_DATA,
            .flags = 0,
            .stream_id = self.stream_id,
        });
        out.append(&hdr);
        out.append(coal[0..self._coal_len]);

        self._coal_len = 0;
    }

    /// Return:
    /// - void
    /// - error.BrokenPipe when the write failed, or the staged reply already failed one
    fn _sendDataFrame(self: *GrpcContext, content_type: []const u8, payload: []const u8, compress: bool) error{BrokenPipe}!void {
        if (self._out) |out| {
            try self._flushHeaders(content_type);

            // Streaming path: pack the gRPC-framed message (5-byte prefix + payload) into the
            // coalesce buffer, flushing it to a DATA frame first when this message would overflow.
            // Messages that fit the buffer ride out under one shared frame header.
            if (self._coal) |coal| {
                const framed = frame.grpc_prefix_len + payload.len;
                if (framed <= coal.len) {
                    if (self._coal_len + framed > coal.len) self._emitCoalesced(out);

                    frame.writeGrpcPrefix(coal[self._coal_len..][0..frame.grpc_prefix_len], compress, @intCast(payload.len));
                    @memcpy(coal[self._coal_len + frame.grpc_prefix_len ..][0..payload.len], payload);
                    self._coal_len += framed;
                    self._sent_bytes += payload.len;

                    return if (out.failed) error.BrokenPipe else {};
                }

                // A single message larger than the coalesce buffer: flush what is packed, then let it
                // ride out as its own DATA frame below (preserving wire order).
                self._emitCoalesced(out);
            }

            var head: [14]u8 = undefined;
            _ = frame.buildGrpcDataHeader(&head, self.stream_id, payload.len, compress);
            out.append(&head);
            out.append(payload);
            self._sent_bytes += payload.len;

            return if (out.failed) error.BrokenPipe else {};
        }

        if (self._write_mutex) |mutex| mutex.lock();
        defer {
            if (self._write_mutex) |mutex| mutex.unlock();
        }

        try self._flushHeaders(content_type);

        var head: [14]u8 = undefined;
        const head_len = frame.buildGrpcDataHeader(&head, self.stream_id, payload.len, compress);

        // Small message (the common server-streaming case): coalesce the DATA header and
        // payload into one write, so each message costs one syscall instead of two and one
        // TLS record instead of two under the stream sink hook. A larger payload keeps the
        // two-write path so it is never copied through the stack buffer.
        if (head_len + payload.len <= grpc_stream_inline_cap) {
            var one: [grpc_stream_inline_cap]u8 = undefined;
            @memcpy(one[0..head_len], head[0..head_len]);
            @memcpy(one[head_len..][0..payload.len], payload);
            h2.writeAllFD(self.fd, one[0 .. head_len + payload.len]) catch return error.BrokenPipe;
        } else {
            h2.writeAllFD(self.fd, head[0..head_len]) catch return error.BrokenPipe;
            h2.writeAllFD(self.fd, payload) catch return error.BrokenPipe;
        }

        self._sent_bytes += payload.len;
    }

    /// Close the stream with a gRPC status. Must be called exactly once per handler.
    /// If no response messages were sent, sends a trailers-only (error) response.
    ///
    /// Return:
    /// - void
    /// - error.BrokenPipe when the peer is gone. The call still counts as closed, so the engine
    ///   does not answer it a second time on the way out.
    pub fn finish(self: *GrpcContext, stat: GrpcStatus, grpc_message: []const u8) error{BrokenPipe}!void {
        self._grpc_status = @intFromEnum(stat);
        self._finished = true;
        const status_code = self._grpc_status;

        if (self._out) |out| {
            if (self._coal != null) self._emitCoalesced(out);

            var buf: [frame.headers_frame_scratch]u8 = undefined;
            const n = if (self._hdr_sent)
                frame.buildGrpcTrailer(&buf, self.stream_id, status_code, grpc_message)
            else
                frame.buildGrpcError(&buf, self.stream_id, status_code, grpc_message);
            out.append(buf[0..n]);

            return if (out.failed) error.BrokenPipe else {};
        }

        if (self._write_mutex) |mutex| mutex.lock();
        defer {
            if (self._write_mutex) |mutex| mutex.unlock();
        }

        if (self._hdr_sent) {
            frame.sendGrpcTrailerFD(self.fd, self.stream_id, status_code, grpc_message) catch return error.BrokenPipe;
        } else {
            frame.sendGrpcErrorFD(self.fd, self.stream_id, status_code, grpc_message) catch return error.BrokenPipe;
        }
    }

    /// Answer a call the handler left open, and report whether anything was written.
    ///
    /// Note:
    /// - Called by the engine on a handler error, never by a handler. A call the handler already
    ///   closed with `finish` is left alone, so a status the handler chose is never overwritten.
    ///   A call that got as far as HEADERS is closed with a trailer, one that got nothing is
    ///   closed with a trailers-only response.
    ///
    /// Param:
    /// stat - GrpcStatus (the status to close an unfinished call with)
    /// grpc_message - []const u8 (the grpc-message text to carry with it)
    ///
    /// Return:
    /// - bool, true when this closed the call, false when the handler had already closed it
    pub fn finishIfOpen(self: *GrpcContext, stat: GrpcStatus, grpc_message: []const u8) bool {
        if (self._finished) return false;

        self.finish(stat, grpc_message) catch {};

        return true;
    }

    /// Return true when deadline_ns has passed. False when deadline_ns is null.
    /// Does not cancel or interrupt anything, handler must check explicitly.
    pub fn isExpired(self: *const GrpcContext) bool {
        const deadline = self.deadline_ns orelse return false;
        return wallClockNs() >= deadline;
    }

    /// Serve a cached unary response when one is present and fresh. The key is
    /// the path plus the raw request body, so an identical call replays the
    /// stored response message with no handler work. On a hit the message is
    /// sent and the stream is finished with OK, and the handler should return.
    /// The cache stores the logical message, so per-stream framing and optional
    /// gzip are reapplied by sendMessage on every hit.
    ///
    /// Note:
    /// - A miss, no cache installed on this worker, or an empty path returns
    ///   false so the handler builds the response as usual.
    ///
    /// Usage:
    /// ```zig
    /// fn handler(req: *zix.Grpc.Request, res: *zix.Grpc.Response, _: *zix.Grpc.Context) anyerror!void {
    ///     if (try res.serveCached("application/grpc")) return;
    ///     const reply = buildExpensiveReply(req.recvMessage());
    ///     try res.sendCached("application/grpc", reply, 0);
    ///     try res.finish(.OK, "");
    /// }
    /// ```
    ///
    /// Return:
    /// - bool (true when served from cache, the handler should return)
    /// - error.BrokenPipe when the peer went away mid-replay
    pub fn serveCached(self: *GrpcContext, content_type: []const u8) error{BrokenPipe}!bool {
        const cache = tl_cache orelse return false;
        if (self.path.len == 0) return false;

        const bytes = cache.lookup(requestKey(self.path, self._body), rc.nowMillis()) orelse return false;

        try self.sendMessage(content_type, bytes);
        try self.finish(.OK, "");

        return true;
    }

    /// Send a unary response message and store it under the call key for later
    /// serveCached hits. ttl_ms of 0 uses the worker default (cacheTtl). Storing
    /// is skipped when no cache is installed, the path is empty, or the message
    /// exceeds the per-slot cap. The handler still calls finish() as usual.
    ///
    /// Param:
    /// content_type - []const u8 (response content type, e.g. "application/grpc")
    /// data - []const u8 (the uncompressed response message)
    /// ttl_ms - u32 (freshness in milliseconds, 0 means the worker default)
    ///
    /// Return:
    /// - void
    /// - error.BrokenPipe when the peer is gone. Nothing is stored in that case, a response the
    ///   peer never received is not worth replaying.
    pub fn sendCached(self: *GrpcContext, content_type: []const u8, data: []const u8, ttl_ms: u32) error{BrokenPipe}!void {
        try self.sendMessage(content_type, data);

        const cache = tl_cache orelse return;
        if (self.path.len == 0) return;

        const ttl = if (ttl_ms == 0) tl_cache_ttl_ms else ttl_ms;
        _ = cache.store(requestKey(self.path, self._body), data, ttl, rc.nowMillis());
    }
};

// --------------------------------------------------------- //

/// Per-worker response cache installed by the EPOLL / URING mux worker. Null on workers
/// without a cache, so the GrpcContext cache API degrades to a plain send.
pub threadlocal var tl_cache: ?*rc.ResponseCache = null;

/// Default cache freshness for this worker, used when a handler passes ttl 0.
pub threadlocal var tl_cache_ttl_ms: u32 = 1000;

/// Install (or clear) the per-worker response cache and its default TTL.
pub fn setCache(cache: ?*rc.ResponseCache, default_ttl_ms: u32) void {
    tl_cache = cache;
    tl_cache_ttl_ms = default_ttl_ms;
}

/// Worker default cache freshness in milliseconds.
pub fn cacheTtl() u32 {
    return tl_cache_ttl_ms;
}

/// Cache key for a unary call: the gRPC path and the raw request body. Returns
/// a non-zero u64 (0 is the cache empty sentinel).
fn requestKey(path: []const u8, body: []const u8) u64 {
    var hasher = std.hash.Wyhash.init(0);
    hasher.update(path);
    hasher.update(body);

    const digest = hasher.final();
    return if (digest == 0) 1 else digest;
}

// --------------------------------------------------------- //

/// Zero-copy view over one inbound gRPC call's path and headers. Message access forwards to
/// the Context that owns the actual receive buffer (recvMessage), so this stays a thin view
/// with no state of its own.
pub const GrpcRequest = struct {
    /// Full gRPC path of this call (e.g. "/pkg.Svc/Method").
    path: []const u8,
    headers: []const h2.Header,
    _ctx: *GrpcContext,

    /// One request header value by name (case-insensitive).
    pub fn header(self: GrpcRequest, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }

        return null;
    }

    /// Read the next gRPC message from the buffered request stream. Forwards to
    /// Context.recvMessage, the actual message buffer and cursor live there.
    pub fn recvMessage(self: GrpcRequest) ?[]const u8 {
        return self._ctx.recvMessage();
    }
};

/// Thin builder over the Context's existing send verbs (sendHeaders, sendMessage, finish,
/// serveCached, sendCached). Delegates rather than duplicates: Context already owns the
/// gzip / coalescing / cork-buffer machinery, none of that moves.
pub const GrpcResponse = struct {
    _ctx: *GrpcContext,

    /// Send the initial response HEADERS (:status 200, content-type). No-op if already sent.
    ///
    /// Return:
    /// - void
    /// - error.BrokenPipe when the peer is gone
    pub fn sendHeaders(self: GrpcResponse, content_type: []const u8) error{BrokenPipe}!void {
        return self._ctx.sendHeaders(content_type);
    }

    /// Send one gRPC response message DATA frame.
    ///
    /// Return:
    /// - void
    /// - error.BrokenPipe when the peer is gone
    pub fn sendMessage(self: GrpcResponse, content_type: []const u8, data: []const u8) error{BrokenPipe}!void {
        return self._ctx.sendMessage(content_type, data);
    }

    /// Close the stream with a gRPC status. Must be called exactly once per handler.
    ///
    /// Return:
    /// - void
    /// - error.BrokenPipe when the peer is gone
    pub fn finish(self: GrpcResponse, stat: GrpcStatus, grpc_message: []const u8) error{BrokenPipe}!void {
        return self._ctx.finish(stat, grpc_message);
    }

    /// Serve a cached unary response when one is present and fresh. See Context.serveCached.
    ///
    /// Return:
    /// - bool (true when served from cache, the handler should return)
    /// - error.BrokenPipe when the peer went away mid-replay
    pub fn serveCached(self: GrpcResponse, content_type: []const u8) error{BrokenPipe}!bool {
        return self._ctx.serveCached(content_type);
    }

    /// Send a unary response message and store it for later serveCached hits. See Context.sendCached.
    ///
    /// Return:
    /// - void
    /// - error.BrokenPipe when the peer is gone
    pub fn sendCached(self: GrpcResponse, content_type: []const u8, data: []const u8, ttl_ms: u32) error{BrokenPipe}!void {
        return self._ctx.sendCached(content_type, data, ttl_ms);
    }
};

/// gRPC handler function type. Called once per inbound gRPC call (h2 stream).
/// Handler must call res.finish() before returning. Errors pass through silently
/// (the wire carries whatever the handler already sent, or nothing).
///
/// Param:
/// req - *GrpcRequest (path, headers, recvMessage)
/// res - *GrpcResponse (sendMessage, finish)
/// ctx - *GrpcContext (deadline, io, per-request arena)
pub const HandlerFn = *const fn (
    req: *GrpcRequest,
    res: *GrpcResponse,
    ctx: *GrpcContext,
) anyerror!void;

/// gRPC route: exact full path to handler mapping.
///
/// Param:
/// path - []const u8 (full gRPC path, e.g. "/package.Service/Method")
/// handler - HandlerFn
/// timeout_ms - u32 (per-route timeout in milliseconds. 0 = use GrpcServerConfig.handler_timeout_ms)
/// is_server_streaming - bool (true for server-streaming RouterType that send multiple DATA frames)
pub const Route = struct {
    path: []const u8,
    handler: HandlerFn,
    /// Per-route handler timeout (milliseconds). 0 = use GrpcServerConfig.handler_timeout_ms.
    /// When non-zero, tightens ctx.deadline_ns if shorter than the global cap.
    timeout_ms: u32 = 0,
    /// Set to true for server-streaming RouterType (handler calls sendMessage in a loop or
    /// requires client flow-control window updates while writing). When false (default),
    /// the handler runs synchronously on the connection thread: no task alloc, no 4KB
    /// header copy, no mutex. Synchronous dispatch blocks the read loop for the handler
    /// duration, only safe for short unary handlers.
    ///
    /// Note:
    /// - The engine reads this BEFORE any handler runs (dispatchStream / muxDispatch), to pick
    ///   sync-inline vs task-spawn dispatch. Measured: sync-inline is ~185x more RPS/core than
    ///   task-spawn for a trivial unary handler (44.8M vs ~242K effective RPS/core, this box,
    ///   2026-07-26 PoC). This is why Server.init takes the RouterType TYPE (comptime route
    ///   visibility), not a bare handler pointer like the other four zix engines.
    is_server_streaming: bool = false,
};

/// Comptime path router. Dispatches by exact match on path. Sends UNIMPLEMENTED if no route matches.
/// Usable as a HandlerFn (matches its signature exactly).
///
/// Note:
/// - Tightens ctx.deadline_ns with Route.timeout_ms when non-zero and shorter than current deadline.
/// - route_slice exposes the comptime route table so the engine's own dispatch-strategy check
///   (routeIsStreaming) can read Route.is_server_streaming before invoking the handler.
///
/// Return:
/// - type (zero-size, with a dispatch function)
pub fn Router(comptime routes: []const Route) type {
    return struct {
        /// Runtime-accessible slice of the comptime route table.
        pub const route_slice: []const Route = routes;

        pub fn dispatch(req: *GrpcRequest, res: *GrpcResponse, ctx: *GrpcContext) anyerror!void {
            inline for (routes) |route| {
                if (std.mem.eql(u8, route.path, req.path)) {
                    if (route.timeout_ms > 0) {
                        const route_deadline: u64 = wallClockNs() + @as(u64, route.timeout_ms) * std.time.ns_per_ms;
                        if (ctx.deadline_ns) |current_deadline| {
                            if (route_deadline < current_deadline) ctx.deadline_ns = route_deadline;
                        } else {
                            ctx.deadline_ns = route_deadline;
                        }
                    }

                    return route.handler(req, res, ctx);
                }
            }

            return res.finish(.UNIMPLEMENTED, "unknown method");
        }
    };
}

// --------------------------------------------------------- //

pub const GrpcServeOpts = struct {
    /// Maximum concurrent streams per connection.
    max_streams: usize = 128,
    /// MAX_FRAME_SIZE sent in server SETTINGS.
    max_frame_size: u32 = h2.DEFAULT_MAX_FRAME_SIZE,
    /// HPACK scratch buffer size per connection (header string storage).
    max_header_scratch: usize = 4096,
    /// Maximum body buffer per stream in bytes.
    max_body: usize = 16384,
    /// Per-connection read buffer floor in bytes. The reader is sized to the larger of this and
    /// one max frame, so a larger floor cuts read() and compaction for big frames.
    conn_read_buf_min: usize = 64 * 1024,
    /// Initial capacity in bytes of the per-connection TLS pending-write buffer (it grows on demand).
    tls_write_buf_initial: usize = 16 * 1024,
    logger: ?*Logger = null,
    /// Global handler timeout cap (milliseconds). Passed from GrpcServerConfig.handler_timeout_ms.
    /// 0 = disabled. Combined with Route.timeout_ms and grpc-timeout header at dispatch.
    handler_timeout_ms: u32 = 0,
    /// When set, spawnGrpcStream uses io.async (work-stealing pool) instead of std.Thread.spawn.
    /// Avoids per-request clone() syscall cost (~20-50us per stream) under concurrent load.
    /// Null falls back to std.Thread.spawn for compatibility with standalone serveConn callers.
    io: ?std.Io = null,
    /// Enable gzip response compression. When true, compresses DATA frames for clients
    /// that advertise grpc-accept-encoding: gzip. Passed from GrpcServerConfig.compress.
    compress: bool = false,
    /// Enable the per-worker unary response cache (ADR-036). Passed from
    /// GrpcServerConfig.response_cache. Active under every dispatch model.
    response_cache: bool = false,
    /// Response cache slot count, rounded down to a power of two.
    cache_max_entries: u32 = 256,
    /// Per-slot response-message cap. A larger message bypasses the cache.
    cache_max_value_bytes: u32 = 16 * 1024,
    /// Default cache freshness in milliseconds, exposed to handlers via cacheTtl().
    cache_ttl_ms: u32 = 1000,
    /// Optional ceiling on per-worker cache memory. 0 disables the ceiling.
    cache_max_total_bytes: usize = 0,
};

// --------------------------------------------------------- //

/// Stream-level receive window advertised in SETTINGS. Large enough that small unary and
/// streaming request bodies never need a per-DATA WINDOW_UPDATE. Inbound bodies above this
/// on a single stream would stall (not a benchmark or typical gRPC shape).
pub const STREAM_WINDOW_SIZE: u32 = 16 * 1024 * 1024;

/// One-time connection-level window bump sent after the SETTINGS handshake. Lifts the fixed
/// 65535 connection receive window so the read loop does not WINDOW_UPDATE per DATA frame.
pub const CONN_WINDOW_BUMP: u31 = 1 << 30;

/// Replenish the connection window once cumulative inbound DATA crosses this. Keeps long-lived
/// connections that move more than CONN_WINDOW_BUMP bytes from stalling, while staying ~0
/// updates per request for the small-body case.
pub const CONN_REPLENISH_THRESHOLD: usize = 1 << 29;

/// Streaming-path coalescing cap. A server-streaming DATA frame whose 14-byte header plus
/// payload fits under this is written in one syscall (one TLS record under the stream sink
/// hook) instead of a separate header write and payload write. Server-streaming messages are
/// small (events, rows), so this halves the per-message syscall count on the streaming hot
/// path. A larger payload keeps the two-write path so it is never copied through the stack
/// buffer. The unary path already coalesces through the cork buffer, so this is streaming only.
const grpc_stream_inline_cap: usize = 4096;

/// grpc-message text the engine closes a call with when the handler returned an error without
/// closing it. Deliberately says nothing about what failed: the caller is not the audience for a
/// server-side fault, and the handler that knows the detail can send its own status instead.
const HANDLER_ERROR_MESSAGE: []const u8 = "handler error";

/// Answer a call whose handler returned an error, so the caller is never left waiting on a stream
/// that will never carry a status.
///
/// Note:
/// - The one place all three dispatch paths (blocking, mux, tls) complete a failed handler, so the
///   three cannot drift into answering the same failure three different ways.
/// - A call the handler already closed with `finish` is left exactly as the handler left it, and
///   an error the handler swallowed itself never reaches here at all.
///
/// Param:
/// ctx - *GrpcContext (the call the handler was invoked with)
///
/// Return:
/// - void
pub fn completeHandlerError(ctx: *GrpcContext) void {
    _ = ctx.finishIfOpen(.INTERNAL, HANDLER_ERROR_MESSAGE);
}

/// Server-streaming DATA-frame coalescing cap (mux cork path). A server-streaming reply is many
/// tiny gRPC messages. Emitting one h2 DATA frame per message spends a 9-byte frame header (and a
/// client-side frame parse) on every 2-to-a-few-byte payload. Instead, consecutive messages are
/// packed into one DATA frame up to this many payload bytes, cutting frame headers and client
/// parses by the pack factor. Kept at the HTTP/2 default SETTINGS_MAX_FRAME_SIZE (16 KiB) so the
/// coalesced frame never exceeds what a client that did not raise its max frame size will accept.
pub const grpc_stream_coalesce_cap: usize = 16384;

pub const StreamState = enum { IDLE, OPEN, HALF_CLOSED_REMOTE, CLOSED };

/// Per-stream parse state. `body` and `header_scratch` are buffers sized to the serve options
/// (opts.max_body / opts.max_header_scratch), not inline arrays, so the fixed part of a Stream stays
/// small regardless of the configured body limit. On the multiplexed (.EPOLL / .URING) path a Stream is
/// borrowed from the per-worker pool while open (its buffers reused across borrows) and `next_free` links
/// it into the pool freelist while idle. On the blocking path the array is inline and `body` /
/// `header_scratch` are slices into per-connection backing buffers.
pub const Stream = struct {
    id: u31 = 0,
    state: StreamState = .IDLE,
    headers: [h2.MAX_HEADERS]h2.Header = undefined,
    header_count: usize = 0,
    body: []u8 = &.{},
    body_len: usize = 0,
    header_scratch: []u8 = &.{},
    end_headers: bool = false,
    end_stream: bool = false,

    /// Freelist link, valid only while this stream sits idle in the per-worker pool.
    next_free: ?*Stream = null,
};

// --------------------------------------------------------- //

/// Corked output buffer for one inline (unary) reply. Stages HEADERS + DATA + trailer
/// and flushes them to the fd in a single write(). Frames larger than the buffer are
/// passed through directly after flushing the staged prefix, preserving wire order.
/// Callers supply `buf` - the backing storage for staging. Use a small stack array for
/// the blocking path. Use the per-connection `stage_buf` in GrpcMuxConn for the mux path.
pub const ReplyStage = struct {
    fd: std.posix.fd_t,
    buf: []u8,
    len: usize = 0,
    /// Set once a write for this reply failed. Staged bytes are written after the handler has
    /// returned, so the failure cannot be handed back at the call that staged them. It is read by
    /// the next send instead, which reports error.BrokenPipe rather than staging onto a dead
    /// connection.
    failed: bool = false,

    pub fn append(self: *ReplyStage, bytes: []const u8) void {
        if (bytes.len > self.buf.len - self.len) {
            self.flush();
            if (bytes.len > self.buf.len) {
                h2.writeAllFD(self.fd, bytes) catch {
                    self.failed = true;
                };

                return;
            }
        }

        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    pub fn flush(self: *ReplyStage) void {
        if (self.len == 0) return;

        h2.writeAllFD(self.fd, self.buf[0..self.len]) catch {
            self.failed = true;
        };

        self.len = 0;
    }
};

/// Buffered frame reader for one connection. Reads in chunks and serves frame headers and
/// payloads from the buffer, so a batch of small frames (the common HEADERS + DATA pair of a
/// unary call) costs one read() instead of two per frame. Payload slices point into buf and
/// are valid only until the next ensure() call.
const ConnReader = struct {
    fd: std.posix.fd_t,
    buf: []u8,
    start: usize = 0,
    end: usize = 0,

    fn fillSome(self: *ConnReader) !void {
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        } else if (self.end == self.buf.len) {
            const n = self.end - self.start;
            std.mem.copyForwards(u8, self.buf[0..n], self.buf[self.start..self.end]);
            self.start = 0;
            self.end = n;
        }

        const got = readOnceFD(self.fd, self.buf[self.end..]) catch return error.ZixClosed;
        if (got == 0) return error.ZixClosed;
        self.end += got;
    }

    /// Block until at least `need` bytes are buffered. `need` must be <= buf.len.
    fn ensure(self: *ConnReader, need: usize) !void {
        while (self.end - self.start < need) try self.fillSome();
    }

    /// Return the next `n` buffered bytes and advance. Caller must ensure(n) first.
    fn take(self: *ConnReader, n: usize) []u8 {
        const slice = self.buf[self.start..][0..n];
        self.start += n;
        return slice;
    }
};

/// Heap-allocated ref-counted write spinlock for one h2 connection.
/// Shared between the read loop and all per-stream handler threads.
/// Ensures H2 frames from concurrent streams are not interleaved on the fd.
const ConnMutex = struct {
    locked: std.atomic.Value(bool) = .init(false),
    refs: std.atomic.Value(u32) = .init(1),
    /// Count of server-streaming tasks currently writing on this connection.
    /// Read by the inline unary fast-path to decide whether the write mutex is needed.
    active_streaming: std.atomic.Value(u32) = .init(0),

    fn lock(self: *ConnMutex) void {
        while (self.locked.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {
            std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *ConnMutex) void {
        self.locked.store(false, .release);
    }

    fn retain(self: *ConnMutex) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    fn release(self: *ConnMutex) void {
        if (self.refs.fetchSub(1, .acq_rel) == 1) {
            std.heap.smp_allocator.destroy(self);
        }
    }
};

/// Per-task scratch buffer for building the HPACK-decoded header block.
const TASK_HEADER_SCRATCH_SIZE: usize = 4096;
/// Per-task request body buffer size (bytes a single call can accumulate).
const TASK_BODY_BUF_SIZE: usize = 64 * 1024;

/// Heap-allocated per-stream dispatch task. Owns a deep copy of the stream's headers
/// and body so the read loop can immediately reuse the stream slot after spawning.
fn DispatchTask(comptime RouterType: type) type {
    return struct {
        const Self = @This();

        fd: std.posix.fd_t,
        stream_id: u31,
        header_count: usize,
        headers: [h2.MAX_HEADERS]h2.Header,
        header_scratch: [TASK_HEADER_SCRATCH_SIZE]u8,
        body_len: usize,
        body: [TASK_BODY_BUF_SIZE]u8,
        opts: GrpcServeOpts,
        conn_mutex: *ConnMutex,
        io: std.Io,

        fn run(self: *Self) void {
            const conn_mutex_ptr = self.conn_mutex;
            defer {
                _ = conn_mutex_ptr.active_streaming.fetchSub(1, .acq_rel);
                std.heap.smp_allocator.destroy(self);
                conn_mutex_ptr.release();
            }

            var path: []const u8 = "/";
            for (self.headers[0..self.header_count]) |header| {
                if (header.name.len == 5 and std.mem.eql(u8, header.name, ":path")) path = header.value;
            }

            var time_start: u64 = undefined;
            if (self.opts.logger != null) time_start = monotonicNs();

            var arena_buf: [CTX_ARENA_BYTES]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&arena_buf);

            var ctx = GrpcContext{
                .fd = self.fd,
                .stream_id = self.stream_id,
                ._body = self.body[0..self.body_len],
                ._pos = 0,
                ._hdr_sent = false,
                ._sent_bytes = 0,
                ._grpc_status = 0,
                .deadline_ns = computeDeadline(self.opts.handler_timeout_ms, self.headers[0..self.header_count]),
                ._write_mutex = conn_mutex_ptr,
                ._resp_gzip = self.opts.compress and headersAcceptGzip(self.headers[0..self.header_count]),
                .io = self.io,
                .allocator = fba.allocator(),
            };
            var req = GrpcRequest{ .path = path, .headers = self.headers[0..self.header_count], ._ctx = &ctx };
            var res = GrpcResponse{ ._ctx = &ctx };
            RouterType.dispatch(&req, &res, &ctx) catch completeHandlerError(&ctx);

            if (self.opts.logger) |logger| {
                const dur_ms: u64 = (monotonicNs() -| time_start) / 1_000_000;
                var peer_buf: [64]u8 = undefined;
                const peer = peerStr(self.fd, &peer_buf);
                logger.rpc(peer, path, ctx._grpc_status, self.body_len, ctx._sent_bytes, dur_ms);
            }
        }
    };
}

/// Spawn a detached handler thread for one gRPC stream.
/// Deep-copies stream data so the slot can be freed immediately.
/// Rebases header slice pointers from the stream's scratch buffer into the task's copy.
/// Falls back to an inline INTERNAL error if allocation or spawn fails.
fn spawnGrpcStream(
    comptime RouterType: type,
    stream: *Stream,
    fd: std.posix.fd_t,
    opts: GrpcServeOpts,
    conn_mutex: *ConnMutex,
    io: std.Io,
) void {
    const Task = DispatchTask(RouterType);
    const task = std.heap.smp_allocator.create(Task) catch {
        var ctx = GrpcContext{
            .fd = fd,
            .stream_id = stream.id,
            ._body = &.{},
            ._pos = 0,
            ._hdr_sent = false,
            ._sent_bytes = 0,
            ._grpc_status = 0,
            ._write_mutex = conn_mutex,
            .io = io,
            .allocator = std.heap.smp_allocator,
        };
        ctx.finish(.INTERNAL, "server overloaded") catch {};

        return;
    };

    task.fd = fd;
    task.stream_id = stream.id;
    task.header_count = stream.header_count;
    task.headers = stream.headers;

    // stream.header_scratch is a slice into the connection backing buffer. Copy its used range
    // into the task's own array so header name/value pointers can be rebased below.
    // Requires opts.max_header_scratch <= task.header_scratch.len (4096).
    const scratch_n = @min(task.header_scratch.len, stream.header_scratch.len);
    @memcpy(task.header_scratch[0..scratch_n], stream.header_scratch[0..scratch_n]);

    if (headersHaveGzipEncoding(stream.headers[0..stream.header_count])) {
        var decomp_buf: ?[]u8 = null;
        const eff = maybeDecompressBody(stream.body[0..stream.body_len], stream.headers[0..stream.header_count], opts.max_body, &decomp_buf);
        defer if (decomp_buf) |buf| std.heap.smp_allocator.free(buf);
        task.body_len = @min(eff.len, task.body.len);
        @memcpy(task.body[0..task.body_len], eff[0..task.body_len]);
    } else {
        task.body_len = stream.body_len;
        @memcpy(task.body[0..stream.body_len], stream.body[0..stream.body_len]);
    }

    task.opts = opts;
    task.io = io;

    const old_base = @intFromPtr(&stream.header_scratch[0]);
    const old_end = old_base + stream.header_scratch.len;
    for (task.headers[0..task.header_count]) |*hdr| {
        const name_ptr = @intFromPtr(hdr.name.ptr);
        if (name_ptr >= old_base and name_ptr < old_end) {
            hdr.name = task.header_scratch[name_ptr - old_base ..][0..hdr.name.len];
        }
        const val_ptr = @intFromPtr(hdr.value.ptr);
        if (val_ptr >= old_base and val_ptr < old_end) {
            hdr.value = task.header_scratch[val_ptr - old_base ..][0..hdr.value.len];
        }
    }

    _ = conn_mutex.active_streaming.fetchAdd(1, .monotonic);
    conn_mutex.retain();
    task.conn_mutex = conn_mutex;

    if (opts.io) |spawn_io| {
        // Use the work-stealing thread pool: no per-request clone() syscall.
        _ = spawn_io.async(Task.run, .{task});
    } else {
        const thread = std.Thread.spawn(.{}, Task.run, .{task}) catch {
            _ = conn_mutex.active_streaming.fetchSub(1, .acq_rel);
            conn_mutex.release();
            std.heap.smp_allocator.destroy(task);
            var ctx = GrpcContext{
                .fd = fd,
                .stream_id = stream.id,
                ._body = &.{},
                ._pos = 0,
                ._hdr_sent = false,
                ._sent_bytes = 0,
                ._grpc_status = 0,
                ._write_mutex = conn_mutex,
                .io = io,
                .allocator = std.heap.smp_allocator,
            };
            ctx.finish(.INTERNAL, "spawn failed") catch {};

            return;
        };
        thread.detach();
    }
}

pub fn headerPath(headers: []const h2.Header) []const u8 {
    for (headers) |header| {
        if (header.name.len == 5 and std.mem.eql(u8, header.name, ":path")) return header.value;
    }
    return "/";
}

pub fn routeIsStreaming(comptime routes: []const Route, path: []const u8) bool {
    inline for (routes) |route| {
        if (std.mem.eql(u8, route.path, path)) return route.is_server_streaming;
    }
    return false;
}

fn dispatchGrpcInline(
    comptime RouterType: type,
    stream: *const Stream,
    fd: std.posix.fd_t,
    opts: GrpcServeOpts,
    conn_mutex: *ConnMutex,
    path: []const u8,
    io: std.Io,
) void {
    var time_start: u64 = undefined;
    if (opts.logger != null) time_start = monotonicNs();

    var decomp_buf: ?[]u8 = null;
    defer if (decomp_buf) |buf| std.heap.smp_allocator.free(buf);
    const effective_body = maybeDecompressBody(
        stream.body[0..stream.body_len],
        stream.headers[0..stream.header_count],
        opts.max_body,
        &decomp_buf,
    );

    const resp_gzip = opts.compress and headersAcceptGzip(stream.headers[0..stream.header_count]);

    // The reply (HEADERS + DATA + trailer) is staged and flushed in one write().
    // Hold the connection write lock across the whole reply only when a streaming
    // task may be writing concurrently, so frames are not interleaved.
    const need_mutex = conn_mutex.active_streaming.load(.acquire) > 0;
    var stage_buf: [reply_stage_scratch]u8 = undefined;
    var stage = ReplyStage{ .fd = fd, .buf = &stage_buf };

    var arena_buf: [CTX_ARENA_BYTES]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);

    var ctx = GrpcContext{
        .fd = fd,
        .stream_id = stream.id,
        ._body = effective_body,
        ._pos = 0,
        ._hdr_sent = false,
        ._sent_bytes = 0,
        ._grpc_status = 0,
        .deadline_ns = computeDeadline(opts.handler_timeout_ms, stream.headers[0..stream.header_count]),
        ._write_mutex = null,
        ._out = &stage,
        ._resp_gzip = resp_gzip,
        .io = io,
        .allocator = fba.allocator(),
    };
    var req = GrpcRequest{ .path = path, .headers = stream.headers[0..stream.header_count], ._ctx = &ctx };
    var res = GrpcResponse{ ._ctx = &ctx };

    if (need_mutex) conn_mutex.lock();
    RouterType.dispatch(&req, &res, &ctx) catch completeHandlerError(&ctx);
    stage.flush();
    if (need_mutex) conn_mutex.unlock();

    if (opts.logger) |logger| {
        const dur_ms: u64 = (monotonicNs() -| time_start) / 1_000_000;
        var peer_buf: [64]u8 = undefined;
        const peer = peerStr(fd, &peer_buf);
        logger.rpc(peer, path, ctx._grpc_status, stream.body_len, ctx._sent_bytes, dur_ms);
    }
}

fn dispatchStream(
    comptime RouterType: type,
    stream: *Stream,
    fd: std.posix.fd_t,
    opts: GrpcServeOpts,
    conn_mutex: *ConnMutex,
    io: std.Io,
) void {
    const path = headerPath(stream.headers[0..stream.header_count]);

    if (routeIsStreaming(RouterType.route_slice, path)) {
        spawnGrpcStream(RouterType, stream, fd, opts, conn_mutex, io);
    } else {
        dispatchGrpcInline(RouterType, stream, fd, opts, conn_mutex, path, io);
    }
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
/// stream - *Stream (the stream whose request side just closed)
/// fd - std.posix.fd_t (connection fd)
/// opts - GrpcServeOpts (serve limits carried to the handler trio)
/// conn_mutex - *ConnMutex (guards every write on a connection shared with spawned stream threads)
/// io - std.Io (backend carried on Context)
///
/// Return:
/// - void
fn dispatchWhole(
    comptime RouterType: type,
    stream: *Stream,
    fd: std.posix.fd_t,
    opts: GrpcServeOpts,
    conn_mutex: *ConnMutex,
    io: std.Io,
) void {
    if (!stream_body.isWhole(stream.headers[0..stream.header_count], stream.body_len)) {
        {
            conn_mutex.lock();
            defer conn_mutex.unlock();
            h2.sendRstStreamFD(fd, stream.id, h2.ERR_PROTOCOL_ERROR) catch {};
        }

        return;
    }

    dispatchStream(RouterType, stream, fd, opts, conn_mutex, io);
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
/// conn_mutex - *ConnMutex (guards every write on a connection shared with spawned stream threads)
///
/// Return:
/// - void
fn hangupGoaway(fd: std.posix.fd_t, streams: []const Stream, used: []const bool, last_stream_id: u31, conn_mutex: *ConnMutex) void {
    if (!requestInFlight(streams, used)) return;

    conn_mutex.lock();
    defer conn_mutex.unlock();

    h2.sendGoawayFD(fd, last_stream_id, h2.ERR_PROTOCOL_ERROR) catch {};
}

// --------------------------------------------------------- //

/// Read some bytes from fd: the ntdll shim on Windows, std.posix.read elsewhere.
fn readOnceFD(fd: std.posix.fd_t, buf: []u8) !usize {
    if (comptime @import("builtin").target.os.tag == .windows) return win_io.readOnce(fd, buf);

    return std.posix.read(fd, buf);
}

/// Serve one gRPC h2c connection (h2c direct or h2c upgrade).
/// Caller owns fd and must close it after this exits.
pub fn serveGrpcConn(comptime RouterType: type, fd: std.posix.fd_t, opts: GrpcServeOpts, io: std.Io) void {
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
    serveGrpcConnInner(RouterType, fd, opts, io) catch {};
}

fn serveGrpcConnInner(comptime RouterType: type, fd: std.posix.fd_t, opts: GrpcServeOpts, io: std.Io) !void {
    var peek: [3]u8 = undefined;
    try h2.recvExact(fd, &peek);

    if (std.mem.eql(u8, &peek, "PRI")) {
        var rest: [21]u8 = undefined;
        try h2.recvExact(fd, &rest);
        var preface: [24]u8 = undefined;
        @memcpy(preface[0..3], &peek);
        @memcpy(preface[3..], &rest);
        if (!std.mem.eql(u8, &preface, h2.PREFACE)) {
            h2.sendGoawayFD(fd, 0, h2.ERR_PROTOCOL_ERROR) catch {};
            return error.ZixBadPreface;
        }
        try h2.sendSettingsFD(fd, &.{
            .{ h2.SETTINGS_MAX_CONCURRENT_STREAMS, @as(u32, @intCast(opts.max_streams)) },
            .{ h2.SETTINGS_INITIAL_WINDOW_SIZE, STREAM_WINDOW_SIZE },
            .{ h2.SETTINGS_MAX_FRAME_SIZE, opts.max_frame_size },
            .{ h2.SETTINGS_ENABLE_PUSH, 0 },
        });
        var hpack_dec = h2.HpackDecoder.init();
        try serveGrpcLoop(RouterType, fd, &hpack_dec, opts, 0, io);
    } else {
        try serveGrpcUpgrade(RouterType, fd, opts, &peek, io);
    }
}

pub fn getHttp1Header(buf: []const u8, name: []const u8) ?[]const u8 {
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

fn serveGrpcUpgrade(comptime RouterType: type, fd: std.posix.fd_t, opts: GrpcServeOpts, prefix: *const [3]u8, io: std.Io) !void {
    var head_buf: [upgrade_head_buf]u8 = undefined;
    var filled: usize = 3;
    @memcpy(head_buf[0..3], prefix);
    while (std.mem.indexOf(u8, head_buf[0..filled], "\r\n\r\n") == null) {
        if (filled >= head_buf.len) return error.ZixHeaderTooLarge;
        const n = readOnceFD(fd, head_buf[filled..]) catch return error.ZixClosed;
        if (n == 0) return error.ZixClosed;
        filled += n;
    }
    const hdr_end = std.mem.indexOf(u8, head_buf[0..filled], "\r\n\r\n").? + 4;

    const upgrade_val = getHttp1Header(head_buf[0..hdr_end], "upgrade") orelse {
        h2.writeAllFD(fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n") catch {};
        return error.ZixBadRequest;
    };
    if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade_val, " "), "h2c")) {
        h2.writeAllFD(fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n") catch {};
        return error.ZixBadRequest;
    }

    var path: []const u8 = "/";
    if (std.mem.indexOfScalar(u8, head_buf[0..hdr_end], ' ')) |first_space| {
        const after = head_buf[first_space + 1 .. hdr_end];
        if (std.mem.indexOfScalar(u8, after, ' ')) |second_space| path = after[0..second_space];
    }

    try h2.writeAllFD(
        fd,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Connection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
    );

    var preface: [24]u8 = undefined;
    try h2.recvExact(fd, &preface);
    if (!std.mem.eql(u8, &preface, h2.PREFACE)) {
        h2.sendGoawayFD(fd, 0, h2.ERR_PROTOCOL_ERROR) catch {};
        return error.ZixBadPreface;
    }

    var hpack_dec = h2.HpackDecoder.init();
    if (getHttp1Header(head_buf[0..hdr_end], "http2-settings")) |settings_encoded| {
        const trimmed = std.mem.trim(u8, settings_encoded, " ");
        var decoded: [settings_decode_scratch]u8 = undefined;
        const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(trimmed) catch 0;
        if (decoded_len > 0 and decoded_len <= decoded.len) {
            std.base64.url_safe_no_pad.Decoder.decode(decoded[0..decoded_len], trimmed) catch {};
            var i: usize = 0;
            while (i + 6 <= decoded_len) : (i += 6) {
                const id: u16 = (@as(u16, decoded[i]) << 8) | decoded[i + 1];
                const val: u32 = (@as(u32, decoded[i + 2]) << 24) | (@as(u32, decoded[i + 3]) << 16) |
                    (@as(u32, decoded[i + 4]) << 8) | decoded[i + 5];
                if (id == h2.SETTINGS_HEADER_TABLE_SIZE) {
                    hpack_dec.max_size = val;
                    hpack_dec.evictTo(val);
                }
            }
        }
    }

    try h2.sendSettingsFD(fd, &.{
        .{ h2.SETTINGS_MAX_CONCURRENT_STREAMS, @as(u32, @intCast(opts.max_streams)) },
        .{ h2.SETTINGS_INITIAL_WINDOW_SIZE, STREAM_WINDOW_SIZE },
        .{ h2.SETTINGS_MAX_FRAME_SIZE, opts.max_frame_size },
        .{ h2.SETTINGS_ENABLE_PUSH, 0 },
    });

    var stream1_headers = [2]h2.Header{
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = "http" },
    };

    var time_start: u64 = undefined;
    if (opts.logger != null) time_start = monotonicNs();

    // Note:
    // Stream 1 (h2c upgrade) is dispatched synchronously before the read loop starts.
    // A long-running streaming handler here will delay the loop. This is a known limitation
    // of the upgrade path, h2c direct does not have this issue.
    var arena_buf: [CTX_ARENA_BYTES]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);

    var ctx = GrpcContext{
        .fd = fd,
        .stream_id = 1,
        ._body = &.{},
        ._pos = 0,
        ._hdr_sent = false,
        ._sent_bytes = 0,
        ._grpc_status = 0,
        .deadline_ns = if (opts.handler_timeout_ms > 0)
            wallClockNs() + @as(u64, opts.handler_timeout_ms) * std.time.ns_per_ms
        else
            null,
        .io = io,
        .allocator = fba.allocator(),
    };
    var req = GrpcRequest{ .path = path, .headers = &stream1_headers, ._ctx = &ctx };
    var res = GrpcResponse{ ._ctx = &ctx };
    RouterType.dispatch(&req, &res, &ctx) catch completeHandlerError(&ctx);

    if (opts.logger) |logger| {
        const dur_ms: u64 = (monotonicNs() -| time_start) / 1_000_000;
        var peer_buf: [64]u8 = undefined;
        const peer = peerStr(fd, &peer_buf);
        logger.rpc(peer, path, ctx._grpc_status, ctx._body.len, ctx._sent_bytes, dur_ms);
    }

    try serveGrpcLoop(RouterType, fd, &hpack_dec, opts, 1, io);
}

fn serveGrpcLoop(
    comptime RouterType: type,
    fd: std.posix.fd_t,
    hpack_dec: *h2.HpackDecoder,
    opts: GrpcServeOpts,
    initial_last_stream: u31,
    io: std.Io,
) !void {
    const max_payload = opts.max_frame_size + h2.FRAME_PAYLOAD_SLACK;
    // Read buffer holds at least one full frame (header + max payload) and is large enough
    // to batch several small frames per read().
    const reader_cap = @max(opts.conn_read_buf_min, max_payload + 9);
    const reader_buf = try std.heap.smp_allocator.alloc(u8, reader_cap);
    defer std.heap.smp_allocator.free(reader_buf);
    var reader = ConnReader{ .fd = fd, .buf = reader_buf };

    const streams = try std.heap.smp_allocator.alloc(Stream, opts.max_streams);
    defer std.heap.smp_allocator.free(streams);
    const stream_slots = try std.heap.smp_allocator.alloc(bool, opts.max_streams);
    defer std.heap.smp_allocator.free(stream_slots);
    @memset(stream_slots, false);

    const bodies = try std.heap.smp_allocator.alloc(u8, opts.max_body * opts.max_streams);
    defer std.heap.smp_allocator.free(bodies);
    const scratches = try std.heap.smp_allocator.alloc(u8, opts.max_header_scratch * opts.max_streams);
    defer std.heap.smp_allocator.free(scratches);
    for (streams, 0..) |*s, i| {
        s.body = bodies[i * opts.max_body ..][0..opts.max_body];
        s.header_scratch = scratches[i * opts.max_header_scratch ..][0..opts.max_header_scratch];
    }

    var last_stream_id: u31 = initial_last_stream;
    var conn_window_consumed: usize = 0;

    const conn_mutex = try std.heap.smp_allocator.create(ConnMutex);
    conn_mutex.* = .{};
    defer conn_mutex.release();

    while (true) {
        reader.ensure(9) catch |err| {
            hangupGoaway(fd, streams, stream_slots, last_stream_id, conn_mutex);

            return err;
        };
        const frame_header = h2.parseFrameHeader(reader.take(9));

        if (frame_header.length > max_payload) {
            {
                conn_mutex.lock();
                defer conn_mutex.unlock();
                h2.sendGoawayFD(fd, last_stream_id, h2.ERR_FRAME_SIZE_ERROR) catch {};
            }
            return error.ZixFrameTooLarge;
        }

        try reader.ensure(frame_header.length);
        const payload = reader.take(frame_header.length);

        switch (frame_header.frame_type) {
            h2.FRAME_TYPE_SETTINGS => {
                if ((frame_header.flags & h2.FLAG_ACK) != 0) continue;
                var i: usize = 0;
                while (i + 6 <= payload.len) : (i += 6) {
                    const id: u16 = (@as(u16, payload[i]) << 8) | payload[i + 1];
                    const val: u32 = (@as(u32, payload[i + 2]) << 24) | (@as(u32, payload[i + 3]) << 16) |
                        (@as(u32, payload[i + 4]) << 8) | payload[i + 5];
                    if (id == h2.SETTINGS_HEADER_TABLE_SIZE) {
                        hpack_dec.max_size = val;
                        hpack_dec.evictTo(val);
                    }
                }
                {
                    conn_mutex.lock();
                    defer conn_mutex.unlock();
                    try h2.sendSettingsAckFD(fd);
                    try h2.sendWindowUpdateFD(fd, 0, CONN_WINDOW_BUMP);
                }
            },

            h2.FRAME_TYPE_WINDOW_UPDATE => {},

            h2.FRAME_TYPE_PING => {
                if ((frame_header.flags & h2.FLAG_ACK) != 0) continue;
                if (payload.len != 8) {
                    {
                        conn_mutex.lock();
                        defer conn_mutex.unlock();
                        h2.sendGoawayFD(fd, last_stream_id, h2.ERR_FRAME_SIZE_ERROR) catch {};
                    }
                    return error.ZixProtocolError;
                }
                var ping_payload: [8]u8 = undefined;
                @memcpy(&ping_payload, payload[0..8]);
                {
                    conn_mutex.lock();
                    defer conn_mutex.unlock();
                    try h2.sendPingAckFD(fd, ping_payload);
                }
            },

            h2.FRAME_TYPE_HEADERS => {
                const stream_id = frame_header.stream_id;
                if (stream_id == 0) {
                    {
                        conn_mutex.lock();
                        defer conn_mutex.unlock();
                        h2.sendGoawayFD(fd, last_stream_id, h2.ERR_PROTOCOL_ERROR) catch {};
                    }
                    return error.ZixProtocolError;
                }
                if (stream_id <= last_stream_id and stream_id % 2 == 1) {
                    {
                        conn_mutex.lock();
                        defer conn_mutex.unlock();
                        h2.sendRstStreamFD(fd, stream_id, h2.ERR_STREAM_CLOSED) catch {};
                    }
                    continue;
                }
                last_stream_id = @max(last_stream_id, stream_id);

                const slot = slotFor(stream_id, streams, stream_slots) orelse {
                    {
                        conn_mutex.lock();
                        defer conn_mutex.unlock();
                        h2.sendRstStreamFD(fd, stream_id, h2.ERR_REFUSED_STREAM) catch {};
                    }
                    continue;
                };
                const stream = &streams[slot];
                stream.id = stream_id;
                stream.state = .OPEN;
                stream.body_len = 0;

                var block = payload;
                var offset: usize = 0;
                var pad_len: usize = 0;
                if ((frame_header.flags & h2.FLAG_PADDED) != 0 and block.len > 0) {
                    pad_len = block[0];
                    offset = 1;
                }
                if ((frame_header.flags & h2.FLAG_PRIORITY) != 0 and offset + 5 <= block.len) {
                    offset += 5;
                }
                if (pad_len + offset > block.len) {
                    {
                        conn_mutex.lock();
                        defer conn_mutex.unlock();
                        h2.sendGoawayFD(fd, last_stream_id, h2.ERR_PROTOCOL_ERROR) catch {};
                    }
                    return error.ZixProtocolError;
                }
                block = block[offset .. block.len - pad_len];

                stream.header_count = hpack_dec.decode(block, &stream.headers, stream.header_scratch) catch {
                    {
                        conn_mutex.lock();
                        defer conn_mutex.unlock();
                        h2.sendRstStreamFD(fd, stream_id, h2.ERR_COMPRESSION_ERROR) catch {};
                    }
                    stream_slots[slot] = false;
                    continue;
                };
                stream.end_headers = (frame_header.flags & h2.FLAG_END_HEADERS) != 0;
                stream.end_stream = (frame_header.flags & h2.FLAG_END_STREAM) != 0;

                if (stream.end_headers and stream.end_stream) {
                    dispatchWhole(RouterType, stream, fd, opts, conn_mutex, io);
                    stream_slots[slot] = false;
                }
            },

            h2.FRAME_TYPE_CONTINUATION => {
                const stream_id = frame_header.stream_id;
                const slot = findSlot(stream_id, streams, stream_slots) orelse {
                    {
                        conn_mutex.lock();
                        defer conn_mutex.unlock();
                        h2.sendGoawayFD(fd, last_stream_id, h2.ERR_PROTOCOL_ERROR) catch {};
                    }
                    return error.ZixProtocolError;
                };
                const stream = &streams[slot];
                const count = hpack_dec.decode(payload, stream.headers[stream.header_count..], stream.header_scratch) catch {
                    {
                        conn_mutex.lock();
                        defer conn_mutex.unlock();
                        h2.sendRstStreamFD(fd, stream_id, h2.ERR_COMPRESSION_ERROR) catch {};
                    }
                    stream_slots[slot] = false;
                    continue;
                };
                stream.header_count += count;
                stream.end_headers = (frame_header.flags & h2.FLAG_END_HEADERS) != 0;
                if (stream.end_headers and stream.end_stream) {
                    dispatchWhole(RouterType, stream, fd, opts, conn_mutex, io);
                    stream_slots[slot] = false;
                }
            },

            h2.FRAME_TYPE_DATA => {
                const stream_id = frame_header.stream_id;
                if (stream_id == 0) {
                    {
                        conn_mutex.lock();
                        defer conn_mutex.unlock();
                        h2.sendGoawayFD(fd, last_stream_id, h2.ERR_PROTOCOL_ERROR) catch {};
                    }
                    return error.ZixProtocolError;
                }
                const slot = findSlot(stream_id, streams, stream_slots) orelse {
                    {
                        conn_mutex.lock();
                        defer conn_mutex.unlock();
                        h2.sendRstStreamFD(fd, stream_id, h2.ERR_STREAM_CLOSED) catch {};
                    }
                    continue;
                };
                const stream = &streams[slot];

                var data = payload;
                var pad_len: usize = 0;
                if ((frame_header.flags & h2.FLAG_PADDED) != 0 and data.len > 0) {
                    pad_len = data[0];
                    data = data[1..];
                }
                if (pad_len > data.len) {
                    {
                        conn_mutex.lock();
                        defer conn_mutex.unlock();
                        h2.sendGoawayFD(fd, last_stream_id, h2.ERR_PROTOCOL_ERROR) catch {};
                    }
                    return error.ZixProtocolError;
                }
                data = data[0 .. data.len - pad_len];

                // Stream-level flow control is covered by the large STREAM_WINDOW_SIZE in
                // SETTINGS, so no per-frame stream WINDOW_UPDATE is needed. The connection
                // window is bumped once at handshake and only replenished in bulk here.
                if (data.len > 0) {
                    conn_window_consumed += data.len;
                    if (conn_window_consumed >= CONN_REPLENISH_THRESHOLD) {
                        conn_mutex.lock();
                        defer conn_mutex.unlock();
                        h2.sendWindowUpdateFD(fd, 0, @intCast(conn_window_consumed)) catch {};
                        conn_window_consumed = 0;
                    }
                }

                // Same shed as the mux path: a payload past the body cap ends
                // the stream with RESOURCE_EXHAUSTED trailers instead of a
                // silent truncate that would dispatch a corrupt message.
                if (data.len > stream.body.len - stream.body_len) {
                    {
                        conn_mutex.lock();
                        defer conn_mutex.unlock();
                        frame.sendGrpcErrorFD(fd, stream_id, @intFromEnum(GrpcStatus.RESOURCE_EXHAUSTED), "request message exceeds max_body") catch {};
                    }

                    stream_slots[slot] = false;
                    continue;
                }

                @memcpy(stream.body[stream.body_len..][0..data.len], data);
                stream.body_len += data.len;
                stream.end_stream = (frame_header.flags & h2.FLAG_END_STREAM) != 0;

                if (stream.end_stream) {
                    dispatchWhole(RouterType, stream, fd, opts, conn_mutex, io);
                    stream_slots[slot] = false;
                }
            },

            h2.FRAME_TYPE_RST_STREAM => {
                const stream_id = frame_header.stream_id;
                if (findSlot(stream_id, streams, stream_slots)) |slot| stream_slots[slot] = false;
            },

            h2.FRAME_TYPE_GOAWAY => return,
            h2.FRAME_TYPE_PRIORITY => {},
            else => {},
        }
    }
}

/// The peer of a connected socket as "1.2.3.4:5678", or "-" when it cannot be read.
///
/// Note:
/// - One line over the shared helper, which is also what the TCP connection records and the HTTP
///   access records use, so every engine names a peer the same way.
pub fn peerStr(fd: std.posix.fd_t, buf: *[64]u8) []const u8 {
    return peer_addr.endpoint(fd, buf);
}

fn slotFor(stream_id: u31, streams: []Stream, used: []bool) ?usize {
    for (used, 0..) |slot_in_use, i| {
        if (!slot_in_use) {
            used[i] = true;
            streams[i].id = stream_id;
            return i;
        }
    }
    return null;
}

fn findSlot(stream_id: u31, streams: []Stream, used: []bool) ?usize {
    for (used, 0..) |slot_in_use, i| {
        if (slot_in_use and streams[i].id == stream_id) return i;
    }
    return null;
}

/// Return true when the client sent grpc-encoding: gzip (inbound messages are compressed).
fn headersHaveGzipEncoding(headers: []const h2.Header) bool {
    for (headers) |hdr| {
        if (!std.ascii.eqlIgnoreCase(hdr.name, "grpc-encoding")) continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, hdr.value, " "), "gzip")) return true;
    }
    return false;
}

/// Return true when the client advertised grpc-accept-encoding containing "gzip".
pub fn headersAcceptGzip(headers: []const h2.Header) bool {
    for (headers) |hdr| {
        if (!std.ascii.eqlIgnoreCase(hdr.name, "grpc-accept-encoding")) continue;
        var it = std.mem.splitScalar(u8, hdr.value, ',');
        while (it.next()) |part| {
            if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, part, " "), "gzip")) return true;
        }
    }
    return false;
}

/// Decompress body via smp_allocator if grpc-encoding: gzip is present.
/// Returns the effective body slice and sets decomp_out to the allocated buffer (caller frees).
pub fn maybeDecompressBody(
    body: []const u8,
    headers: []const h2.Header,
    max_body: usize,
    decomp_out: *?[]u8,
) []const u8 {
    decomp_out.* = null;
    if (!headersHaveGzipEncoding(headers)) return body;

    const buf = std.heap.smp_allocator.alloc(u8, max_body) catch return body;
    const n = frame.decompressGrpcBody(body, buf) catch {
        std.heap.smp_allocator.free(buf);
        return body;
    };
    decomp_out.* = buf;
    return buf[0..n];
}

pub fn computeDeadline(handler_timeout_ms: u32, headers: []const h2.Header) ?u64 {
    var best: ?u64 = null;
    const now = wallClockNs();

    if (handler_timeout_ms > 0) {
        best = now + @as(u64, handler_timeout_ms) * std.time.ns_per_ms;
    }

    for (headers) |header| {
        if (!std.mem.eql(u8, header.name, "grpc-timeout")) continue;
        if (parseTimeout(header.value)) |t_ns| {
            const candidate = now + t_ns;
            if (best) |current_deadline| {
                if (candidate < current_deadline) best = candidate;
            } else {
                best = candidate;
            }
        }
    }

    return best;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Test fd sentinel: Windows descriptors are opaque pointers, POSIX are ints.
const TEST_FD: std.posix.fd_t = if (@import("builtin").target.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;

test "zix grpc: GrpcContext recvMessage empty body returns null" {
    var ctx = GrpcContext{ .fd = TEST_FD, .stream_id = 1, ._body = &.{}, ._pos = 0, ._hdr_sent = false, ._sent_bytes = 0, ._grpc_status = 0, .io = undefined, .allocator = std.testing.allocator };
    try std.testing.expect(ctx.recvMessage() == null);
}

test "zix grpc: GrpcContext recvMessage parses one message" {
    const frm_mod = @import("frame.zig");
    var body: [10]u8 = undefined;
    frm_mod.writeGrpcPrefix(body[0..5], false, 5);
    @memcpy(body[5..], "hello");
    var ctx = GrpcContext{ .fd = TEST_FD, .stream_id = 1, ._body = &body, ._pos = 0, ._hdr_sent = false, ._sent_bytes = 0, ._grpc_status = 0, .io = undefined, .allocator = std.testing.allocator };
    const message = ctx.recvMessage().?;
    try std.testing.expectEqualStrings("hello", message);
    try std.testing.expect(ctx.recvMessage() == null);
}

test "zix grpc: GrpcContext recvMessage two messages" {
    const frm_mod = @import("frame.zig");
    var body: [20]u8 = undefined;
    frm_mod.writeGrpcPrefix(body[0..5], false, 3);
    @memcpy(body[5..8], "foo");
    frm_mod.writeGrpcPrefix(body[8..13], false, 3);
    @memcpy(body[13..16], "bar");
    var ctx = GrpcContext{ .fd = TEST_FD, .stream_id = 1, ._body = body[0..16], ._pos = 0, ._hdr_sent = false, ._sent_bytes = 0, ._grpc_status = 0, .io = undefined, .allocator = std.testing.allocator };
    try std.testing.expectEqualStrings("foo", ctx.recvMessage().?);
    try std.testing.expectEqualStrings("bar", ctx.recvMessage().?);
    try std.testing.expect(ctx.recvMessage() == null);
}

test "zix grpc: parsePath valid" {
    const grpc_path = parsePath("/helloworld.Greeter/SayHello").?;
    try std.testing.expectEqualStrings("helloworld.Greeter", grpc_path.package_service);
    try std.testing.expectEqualStrings("SayHello", grpc_path.method);
}

test "zix grpc: parsePath no package returns null" {
    try std.testing.expect(parsePath("/SayHello") == null);
}

test "zix grpc: parsePath trailing slash returns null" {
    try std.testing.expect(parsePath("/pkg.Svc/") == null);
}

test "zix grpc: detectContentType proto" {
    const headers = [_]h2.Header{.{ .name = "content-type", .value = "application/grpc+proto" }};
    try std.testing.expectEqual(GrpcContentType.PROTO, detectContentType(&headers));
}

test "zix grpc: detectContentType json" {
    const headers = [_]h2.Header{.{ .name = "content-type", .value = "application/grpc+json" }};
    try std.testing.expectEqual(GrpcContentType.JSON, detectContentType(&headers));
}

test "zix grpc: detectContentType grpc no subtype is PROTO" {
    const headers = [_]h2.Header{.{ .name = "content-type", .value = "application/grpc" }};
    try std.testing.expectEqual(GrpcContentType.PROTO, detectContentType(&headers));
}

test "zix grpc: GrpcServeOpts defaults" {
    const opts = GrpcServeOpts{};
    try std.testing.expectEqual(@as(usize, 128), opts.max_streams);
    try std.testing.expectEqual(h2.DEFAULT_MAX_FRAME_SIZE, opts.max_frame_size);
    try std.testing.expectEqual(@as(usize, 16384), opts.max_body);
    try std.testing.expectEqual(@as(u32, 0), opts.handler_timeout_ms);
    try std.testing.expect(opts.io == null);
}

test "zix grpc: Route timeout_ms defaults to zero" {
    const r = Route{ .path = "/svc.Svc/Method", .handler = struct {
        fn handle(_: *GrpcRequest, _: *GrpcResponse, _: *GrpcContext) anyerror!void {}
    }.handle };
    try std.testing.expectEqual(@as(u32, 0), r.timeout_ms);
}

test "zix grpc: Route is_server_streaming defaults to false" {
    const r = Route{ .path = "/svc.Svc/Method", .handler = struct {
        fn handle(_: *GrpcRequest, _: *GrpcResponse, _: *GrpcContext) anyerror!void {}
    }.handle };
    try std.testing.expect(!r.is_server_streaming);
}

test "zix grpc: GrpcContext.isExpired null deadline returns false" {
    var ctx = GrpcContext{ .fd = TEST_FD, .stream_id = 1, ._body = &.{}, ._pos = 0, ._hdr_sent = false, ._sent_bytes = 0, ._grpc_status = 0, .io = undefined, .allocator = std.testing.allocator };
    try std.testing.expect(!ctx.isExpired());
}

test "zix grpc: GrpcContext.isExpired past deadline returns true" {
    var ctx = GrpcContext{ .fd = TEST_FD, .stream_id = 1, ._body = &.{}, ._pos = 0, ._hdr_sent = false, ._sent_bytes = 0, ._grpc_status = 0, .deadline_ns = 1, .io = undefined, .allocator = std.testing.allocator };
    try std.testing.expect(ctx.isExpired());
}

test "zix grpc: GrpcContext.isExpired future deadline returns false" {
    const far_future: u64 = wallClockNs() + 1000 * std.time.ns_per_s;
    var ctx = GrpcContext{ .fd = TEST_FD, .stream_id = 1, ._body = &.{}, ._pos = 0, ._hdr_sent = false, ._sent_bytes = 0, ._grpc_status = 0, .deadline_ns = far_future, .io = undefined, .allocator = std.testing.allocator };
    try std.testing.expect(!ctx.isExpired());
}

test "zix grpc: RouterType dispatches to matching handler" {
    const called = struct {
        var count: u32 = 0;
        fn handle(_: *GrpcRequest, _: *GrpcResponse, _: *GrpcContext) anyerror!void {
            count += 1;
        }
    };

    const router = Router(&[_]Route{.{ .path = "/svc.Svc/Method", .handler = called.handle }});

    var ctx = GrpcContext{
        .fd = TEST_FD,
        .stream_id = 1,
        ._body = &.{},
        ._pos = 0,
        ._hdr_sent = false,
        ._sent_bytes = 0,
        ._grpc_status = 0,
        .io = undefined,
        .allocator = std.testing.allocator,
    };
    var req = GrpcRequest{ .path = "/svc.Svc/Method", .headers = &.{}, ._ctx = &ctx };
    var res = GrpcResponse{ ._ctx = &ctx };

    try router.dispatch(&req, &res, &ctx);
    try std.testing.expectEqual(@as(u32, 1), called.count);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix grpc: ReplyStage append and flush via pipe" {
    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();
    const fds = pair.fds;

    var backing: [64]u8 = undefined;
    var stage = ReplyStage{ .fd = fds[1], .buf = &backing };
    stage.append("hello");
    stage.append(" world");
    stage.flush();

    var out: [16]u8 = undefined;
    const n = try fd_io.readOnce(fds[0], &out);
    try std.testing.expectEqualStrings("hello world", out[0..n]);
}

test "zix grpc: ReplyStage overflow triggers flush and continues buffering" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();
    const fds = pair.fds;

    var backing: [4]u8 = undefined;
    var stage = ReplyStage{ .fd = fds[1], .buf = &backing };

    stage.append("abcd");
    stage.append("ef");
    stage.flush();

    var out: [16]u8 = undefined;
    const n = try fd_io.readOnce(fds[0], &out);
    try std.testing.expectEqualStrings("abcdef", out[0..n]);
}

test "zix grpc: ReplyStage payload larger than buf writes directly" {
    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();
    const fds = pair.fds;

    var backing: [4]u8 = undefined;
    var stage = ReplyStage{ .fd = fds[1], .buf = &backing };

    stage.append("hello world");
    stage.flush();

    var out: [16]u8 = undefined;
    const n = try fd_io.readOnce(fds[0], &out);
    try std.testing.expectEqualStrings("hello world", out[0..n]);
}

// Walk staged h2 frames, counting DATA frames and the gRPC messages packed inside them, and the
// largest DATA payload seen. Used by the coalescing tests below.
const StagedFrames = struct { data_frames: usize, messages: usize, max_data_payload: usize };

fn walkStagedDataFrames(buf: []const u8) StagedFrames {
    var out = StagedFrames{ .data_frames = 0, .messages = 0, .max_data_payload = 0 };
    var pos: usize = 0;
    while (pos + h2.FRAME_HEADER_LEN <= buf.len) {
        const flen = (@as(usize, buf[pos]) << 16) | (@as(usize, buf[pos + 1]) << 8) | buf[pos + 2];
        const ftype = buf[pos + 3];
        const payload = buf[pos + h2.FRAME_HEADER_LEN ..][0..flen];
        pos += h2.FRAME_HEADER_LEN + flen;

        if (ftype != h2.FRAME_TYPE_DATA) continue;

        out.data_frames += 1;
        if (flen > out.max_data_payload) out.max_data_payload = flen;

        var mp: usize = 0;
        while (mp + frame.grpc_prefix_len <= payload.len) {
            const mlen = std.mem.readInt(u32, payload[mp + 1 ..][0..4], .big);
            mp += frame.grpc_prefix_len + mlen;
            out.messages += 1;
        }
    }
    return out;
}

// --------------------------------------------------------- //
// Handler-error completion: the caller is answered once, and only when the handler left it open

/// A context staging into `stage`, with the call still open and no HEADERS written yet.
fn openCallCtx(stage: *ReplyStage) GrpcContext {
    return .{
        .fd = TEST_FD,
        .stream_id = 1,
        ._body = &.{},
        ._pos = 0,
        ._hdr_sent = false,
        ._sent_bytes = 0,
        ._grpc_status = 0,
        ._out = stage,
        .io = undefined,
        .allocator = std.testing.allocator,
    };
}

test "zix grpc: a handler error with the call still open closes it with INTERNAL" {
    var backing: [1024]u8 = undefined;
    var stage = ReplyStage{ .fd = TEST_FD, .buf = &backing };
    var ctx = openCallCtx(&stage);

    try std.testing.expect(ctx.finishIfOpen(.INTERNAL, HANDLER_ERROR_MESSAGE));

    var expected: [frame.headers_frame_scratch]u8 = undefined;
    const n = frame.buildGrpcError(&expected, 1, @intFromEnum(GrpcStatus.INTERNAL), HANDLER_ERROR_MESSAGE);

    std.log.info(".STAGED: {d} bytes, expected {d}", .{ stage.len, n });

    try std.testing.expectEqualSlices(u8, expected[0..n], stage.buf[0..stage.len]);
}

test "zix grpc: a call the handler already finished is left as the handler left it" {
    var backing: [1024]u8 = undefined;
    var stage = ReplyStage{ .fd = TEST_FD, .buf = &backing };
    var ctx = openCallCtx(&stage);

    try ctx.finish(.OK, "");
    const closed_len = stage.len;

    try std.testing.expect(!ctx.finishIfOpen(.INTERNAL, HANDLER_ERROR_MESSAGE));
    try std.testing.expectEqual(closed_len, stage.len);
    try std.testing.expectEqual(@as(u8, @intFromEnum(GrpcStatus.OK)), ctx._grpc_status);
}

test "zix grpc: sendMessage reports a dead peer instead of swallowing it" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socketpair, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer _ = linux.close(fds[1]);

    // The peer end goes first, so the send below has nowhere to land.
    _ = linux.close(fds[0]);

    var ctx = GrpcContext{
        .fd = fds[1],
        .stream_id = 1,
        ._body = &.{},
        ._pos = 0,
        ._hdr_sent = true,
        ._sent_bytes = 0,
        ._grpc_status = 0,
        .io = undefined,
        .allocator = std.testing.allocator,
    };

    const result = ctx.sendMessage("application/grpc", "payload");

    try std.testing.expectError(error.BrokenPipe, result);
}

test "zix grpc: server-streaming packs many messages into one DATA frame" {
    var backing: [4096]u8 = undefined;
    var stage = ReplyStage{ .fd = TEST_FD, .buf = &backing };
    var coal: [grpc_stream_coalesce_cap]u8 = undefined;

    var ctx = GrpcContext{
        .fd = TEST_FD,
        .stream_id = 1,
        ._body = &.{},
        ._pos = 0,
        ._hdr_sent = true, // skip HEADERS so the stage holds only DATA frames and the trailer
        ._sent_bytes = 0,
        ._grpc_status = 0,
        ._out = &stage,
        ._coal = &coal,
        .io = undefined,
        .allocator = std.testing.allocator,
    };

    try ctx.sendMessage("application/grpc", "aa");
    try ctx.sendMessage("application/grpc", "bb");
    try ctx.sendMessage("application/grpc", "cc");
    try ctx.finish(.OK, "");

    const walked = walkStagedDataFrames(stage.buf[0..stage.len]);
    try std.testing.expectEqual(@as(usize, 1), walked.data_frames);
    try std.testing.expectEqual(@as(usize, 3), walked.messages);
}

test "zix grpc: server-streaming DATA coalescing respects the frame cap" {
    var backing: [4096]u8 = undefined;
    var stage = ReplyStage{ .fd = TEST_FD, .buf = &backing };
    var coal: [16]u8 = undefined; // holds two framed 2-byte messages (7 bytes each), then must flush

    var ctx = GrpcContext{
        .fd = TEST_FD,
        .stream_id = 1,
        ._body = &.{},
        ._pos = 0,
        ._hdr_sent = true,
        ._sent_bytes = 0,
        ._grpc_status = 0,
        ._out = &stage,
        ._coal = &coal,
        .io = undefined,
        .allocator = std.testing.allocator,
    };

    var sent: usize = 0;
    while (sent < 5) : (sent += 1) try ctx.sendMessage("application/grpc", "xy");
    try ctx.finish(.OK, "");

    // Five 7-byte messages under a 16-byte cap pack two-per-frame: 3 DATA frames, none over the cap.
    const walked = walkStagedDataFrames(stage.buf[0..stage.len]);
    try std.testing.expectEqual(@as(usize, 3), walked.data_frames);
    try std.testing.expectEqual(@as(usize, 5), walked.messages);
    try std.testing.expect(walked.max_data_payload <= coal.len);
}

test "zix grpc: serveCached is a no-op without a cache or with an empty path" {
    setCache(null, 0);

    var ctx = GrpcContext{
        .fd = TEST_FD,
        .stream_id = 1,
        .path = "/svc.Svc/Method",
        ._body = "req",
        ._pos = 0,
        ._hdr_sent = false,
        ._sent_bytes = 0,
        ._grpc_status = 0,
        .io = undefined,
        .allocator = std.testing.allocator,
    };
    try std.testing.expect(!try ctx.serveCached("application/grpc"));

    // even with a cache installed, an empty path is never cached
    var cache = try rc.ResponseCache.init(std.testing.allocator, .{ .max_entries = 8, .max_value_bytes = 64 });
    defer cache.deinit();

    setCache(&cache, 1000);
    defer setCache(null, 0);

    var no_path = ctx;
    no_path.path = "";
    try std.testing.expect(!try no_path.serveCached("application/grpc"));
}

test "zix grpc: sendCached stores the unary reply and serveCached replays it" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var cache = try rc.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 256 });
    defer cache.deinit();

    setCache(&cache, 1000);
    defer setCache(null, 0);

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const path = "/svc.Svc/Method";
    const body = "request-body";
    const reply = "unary-reply-payload";

    // first call: miss, handler builds and stores the reply
    var ctx = GrpcContext{
        .fd = fds[1],
        .stream_id = 1,
        .path = path,
        ._body = body,
        ._pos = 0,
        ._hdr_sent = false,
        ._sent_bytes = 0,
        ._grpc_status = 0,
        .io = undefined,
        .allocator = std.testing.allocator,
    };
    try std.testing.expect(!try ctx.serveCached("application/grpc"));
    try ctx.sendCached("application/grpc", reply, 0);
    try ctx.finish(.OK, "");

    var first: [512]u8 = undefined;
    const n1 = try fd_io.readOnce(fds[0], &first);
    try std.testing.expect(std.mem.indexOf(u8, first[0..n1], reply) != null);

    // the message is now stored under the call key
    try std.testing.expect(cache.lookup(requestKey(path, body), rc.nowMillis()) != null);

    // second call: same path and body, served from cache with no handler
    var ctx2 = GrpcContext{
        .fd = fds[1],
        .stream_id = 3,
        .path = path,
        ._body = body,
        ._pos = 0,
        ._hdr_sent = false,
        ._sent_bytes = 0,
        ._grpc_status = 0,
        .io = undefined,
        .allocator = std.testing.allocator,
    };
    try std.testing.expect(try ctx2.serveCached("application/grpc"));

    var second: [512]u8 = undefined;
    const n2 = try fd_io.readOnce(fds[0], &second);
    try std.testing.expect(std.mem.indexOf(u8, second[0..n2], reply) != null);
}

test "zix grpc: response cache keys separate distinct paths and bodies" {
    const key_a = requestKey("/svc.Svc/A", "body");
    const key_b = requestKey("/svc.Svc/B", "body");
    const key_c = requestKey("/svc.Svc/A", "other");

    try std.testing.expect(key_a != key_b);
    try std.testing.expect(key_a != key_c);
    try std.testing.expect(key_b != key_c);
}

// Counts writes routed through the frame write hook and captures the bytes (up to
// its buffer) so a test can assert the streaming DATA frame is coalesced and well
// formed. Used by the streaming-coalesce tests below.
const WriteHookProbe = struct {
    count: usize = 0,
    buf: [256]u8 = undefined,
    len: usize = 0,
};

fn writeHookProbe(ctx: *anyopaque, bytes: []const u8) void {
    const probe: *WriteHookProbe = @ptrCast(@alignCast(ctx));
    probe.count += 1;

    if (probe.len + bytes.len <= probe.buf.len) {
        @memcpy(probe.buf[probe.len..][0..bytes.len], bytes);
        probe.len += bytes.len;
    }
}

test "zix grpc: streaming sendMessage coalesces a small DATA frame into one write" {
    const h2_frame = @import("../frame.zig");

    var probe = WriteHookProbe{};
    h2_frame.write_hook = writeHookProbe;
    h2_frame.write_hook_ctx = &probe;
    defer {
        h2_frame.write_hook = null;
        h2_frame.write_hook_ctx = null;
    }

    // Streaming path: no cork (_out null) and no write mutex, so sendMessage writes
    // directly. Headers pre-marked sent so only the DATA frame goes through the hook.
    var ctx = GrpcContext{ .fd = TEST_FD, .stream_id = 1, ._body = &.{}, ._pos = 0, ._hdr_sent = true, ._sent_bytes = 0, ._grpc_status = 0, .io = undefined, .allocator = std.testing.allocator };

    try ctx.sendMessage("application/grpc", "pong");

    // One write: the 14-byte header and the 4-byte payload were coalesced.
    try std.testing.expectEqual(@as(usize, 1), probe.count);
    try std.testing.expectEqual(@as(usize, 14 + 4), probe.len);

    // The single write is a valid DATA frame on stream 1 carrying the payload.
    const fh = h2_frame.parseFrameHeader(probe.buf[0..9]);
    try std.testing.expectEqual(@as(u8, h2_frame.FRAME_TYPE_DATA), fh.frame_type);
    try std.testing.expectEqual(@as(u31, 1), fh.stream_id);
    try std.testing.expectEqualStrings("pong", probe.buf[14..18]);
}

test "zix grpc: streaming sendMessage past the inline cap keeps the two-write path" {
    const h2_frame = @import("../frame.zig");

    var probe = WriteHookProbe{};
    h2_frame.write_hook = writeHookProbe;
    h2_frame.write_hook_ctx = &probe;
    defer {
        h2_frame.write_hook = null;
        h2_frame.write_hook_ctx = null;
    }

    var ctx = GrpcContext{ .fd = TEST_FD, .stream_id = 3, ._body = &.{}, ._pos = 0, ._hdr_sent = true, ._sent_bytes = 0, ._grpc_status = 0, .io = undefined, .allocator = std.testing.allocator };

    // A payload larger than the inline cap is written as header then payload (two
    // writes), so it is never copied through the stack buffer.
    var big: [grpc_stream_inline_cap + 1]u8 = undefined;
    @memset(&big, 'x');
    try ctx.sendMessage("application/grpc", &big);

    try std.testing.expectEqual(@as(usize, 2), probe.count);
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

var grpc_async_dispatches: usize = 0;
var grpc_async_body_len: usize = 0;

fn grpcAsyncHandler(req: *GrpcRequest, _: *GrpcResponse, _: *GrpcContext) anyerror!void {
    grpc_async_dispatches += 1;
    grpc_async_body_len = if (req.recvMessage()) |msg| msg.len else 0;
}

const grpc_async_router = Router(&[_]Route{.{ .path = "/svc.Svc/Method", .handler = grpcAsyncHandler }});

/// Write one complete frame (9-byte header + payload) to a fd, the way a client would.
fn writeGrpcFrameTo(fd: std.posix.fd_t, ftype: u8, flags: u8, sid: u31, payload: []const u8) !void {
    var fh: [9]u8 = undefined;
    h2.encodeFrameHeader(&fh, .{ .length = @intCast(payload.len), .frame_type = ftype, .flags = flags, .stream_id = sid });

    try h2.writeAllFD(fd, &fh);
    if (payload.len > 0) try h2.writeAllFD(fd, payload);
}

/// Write a call head declaring `content_length`, ending the headers but not the stream.
fn writeDeclaredCallHead(fd: std.posix.fd_t, content_length: []const u8) !void {
    var block: [256]u8 = undefined;
    var enc = h2.HpackEncoder.init(&block);
    try enc.writeHeader(":method", "POST");
    try enc.writeHeader(":path", "/svc.Svc/Method");
    try enc.writeHeader("content-length", content_length);

    try writeGrpcFrameTo(fd, h2.FRAME_TYPE_HEADERS, h2.FLAG_END_HEADERS, 1, enc.encoded());
}

/// Run the blocking frame loop over everything already written to the connection. The client end is
/// shut down for writing first, so the loop reaches EOF and returns instead of parking on a read.
fn runGrpcLoopToEof(client_fd: std.posix.fd_t, server_fd: std.posix.fd_t) void {
    _ = std.os.linux.shutdown(client_fd, std.os.linux.SHUT.WR);

    var dec = h2.HpackDecoder.init();
    serveGrpcLoop(grpc_async_router, server_fd, &dec, .{}, 0, std.testing.io) catch {};
}

/// What the blocking loop answered with, read back after it returned.
const GrpcAsyncTally = struct {
    rst_protocol_error: usize = 0,
    goaway_protocol_error: usize = 0,
};

fn tallyGrpcAsyncWire(read_fd: std.posix.fd_t, server_fd: std.posix.fd_t, buf: []u8) GrpcAsyncTally {
    // The server end still holds the socket open, so without this the read below waits on bytes that
    // are never coming rather than ending at EOF.
    _ = std.os.linux.shutdown(server_fd, std.os.linux.SHUT.WR);

    var total: usize = 0;
    while (total < buf.len) {
        const got = std.posix.read(read_fd, buf[total..]) catch break;
        if (got == 0) break;
        total += got;
    }

    var tally = GrpcAsyncTally{};
    var off: usize = 0;
    while (off + 9 <= total) {
        const fh = h2.parseFrameHeader(buf[off..][0..9]);
        off += 9;
        if (off + fh.length > total) break;

        if (fh.frame_type == h2.FRAME_TYPE_RST_STREAM and std.mem.readInt(u32, buf[off..][0..4], .big) == h2.ERR_PROTOCOL_ERROR) tally.rst_protocol_error += 1;
        if (fh.frame_type == h2.FRAME_TYPE_GOAWAY and std.mem.readInt(u32, buf[off + 4 ..][0..4], .big) == h2.ERR_PROTOCOL_ERROR) tally.goaway_protocol_error += 1;
        off += fh.length;
    }

    return tally;
}

test "zix grpc: the blocking loop resets a stream whose body is short of its content-length" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    // 100 bytes promised, 40 delivered, then END_STREAM: the message never finished arriving
    try writeDeclaredCallHead(fds[0], "100");
    const short: [40]u8 = @splat('x');
    try writeGrpcFrameTo(fds[0], h2.FRAME_TYPE_DATA, h2.FLAG_END_STREAM, 1, &short);

    grpc_async_dispatches = 0;
    runGrpcLoopToEof(fds[0], fds[1]);

    // the handler never ran, so no truncated message was ever served
    try std.testing.expectEqual(@as(usize, 0), grpc_async_dispatches);

    var buf: [8192]u8 = undefined;
    const tally = tallyGrpcAsyncWire(fds[0], fds[1], &buf);

    try std.testing.expectEqual(@as(usize, 1), tally.rst_protocol_error);
}

test "zix grpc: the blocking loop serves a stream whose body matches its content-length" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    // a 5-byte gRPC length prefix and its 4 payload bytes, so the message is whole as well
    try writeDeclaredCallHead(fds[0], "9");
    const whole = [_]u8{ 0, 0, 0, 0, 4, 'p', 'i', 'n', 'g' };
    try writeGrpcFrameTo(fds[0], h2.FRAME_TYPE_DATA, h2.FLAG_END_STREAM, 1, &whole);

    grpc_async_dispatches = 0;
    grpc_async_body_len = 0;
    runGrpcLoopToEof(fds[0], fds[1]);

    // the guard only sheds a body that disagrees with its own headers, an honest one still serves
    try std.testing.expectEqual(@as(usize, 1), grpc_async_dispatches);
    try std.testing.expectEqual(@as(usize, 4), grpc_async_body_len);

    var buf: [8192]u8 = undefined;
    const tally = tallyGrpcAsyncWire(fds[0], fds[1], &buf);

    try std.testing.expectEqual(@as(usize, 0), tally.rst_protocol_error);
}

test "zix grpc: the blocking loop answers a peer that hangs up with a request unfinished" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    // a call that opens its stream and never ends it, then the peer simply goes away
    try writeDeclaredCallHead(fds[0], "100");

    grpc_async_dispatches = 0;
    runGrpcLoopToEof(fds[0], fds[1]);

    try std.testing.expectEqual(@as(usize, 0), grpc_async_dispatches);

    var buf: [8192]u8 = undefined;
    const tally = tallyGrpcAsyncWire(fds[0], fds[1], &buf);

    try std.testing.expectEqual(@as(usize, 1), tally.goaway_protocol_error);
}

test "zix grpc: the blocking loop closes an idle connection without a GOAWAY" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    // one whole call, served and its slot given back: nothing is owed when the peer leaves
    try writeDeclaredCallHead(fds[0], "5");
    const whole = [_]u8{ 0, 0, 0, 0, 0 };
    try writeGrpcFrameTo(fds[0], h2.FRAME_TYPE_DATA, h2.FLAG_END_STREAM, 1, &whole);

    grpc_async_dispatches = 0;
    runGrpcLoopToEof(fds[0], fds[1]);

    try std.testing.expectEqual(@as(usize, 1), grpc_async_dispatches);

    var buf: [8192]u8 = undefined;
    const tally = tallyGrpcAsyncWire(fds[0], fds[1], &buf);

    try std.testing.expectEqual(@as(usize, 0), tally.goaway_protocol_error);
}
