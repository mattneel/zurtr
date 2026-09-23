//! zix http1 core: zero-alloc HTTP/1.x request parsing and response writing.
//! All parsing operates on caller-owned buffers. No std.http dependency.

const std = @import("std");
const win_io = @import("../../utils/windows_io.zig");
const cache = @import("../../utils/response_cache.zig");
const compression = @import("../../utils/compression/compression.zig");
const slab_mem = @import("../../multiplexers/slab.zig");
const parser = @import("parser.zig");
const websocket = @import("websocket.zig");
const peer_addr = @import("../../utils/peer_addr.zig");
const Method = @import("method.zig");
const Logger = @import("../../logger/logger.zig").Logger;
const ZIG_SEMVER = @import("../../lib.zig").ZIG_SEMVER;
pub const Request = @import("request.zig").Request;
pub const Response = @import("response.zig").Response;
pub const Context = @import("context.zig").Context;

/// Shared per-connection scratch size: the blocking-loop receive buffer, the
/// chunked-body reader, and the TLS payload buffers all use it.
pub const BUF_SIZE: usize = 16 * 1024;
const GZIP_OUT_SIZE: usize = 256 * 1024;

/// Scratch buffer for building one HTTP status line plus its headers.
pub const HEADER_BUF_SIZE: usize = 256;

/// Inline write fast-path buffer. A response whose status line, headers, and
/// body all fit here is sent in one direct write, skipping the iovec scatter
/// path. The body threshold is this minus HEADER_BUF_SIZE.
const SMALL_BODY_INLINE_BUF: usize = 4096;

/// Staging buffer for one blocking WebSocket pump pass, matching what the .EPOLL worker gives
/// its own pump so a pipelined burst costs one write on either model.
const WS_OUT_SIZE: usize = 4 * 1024;

// Head parsing lives in parser.zig, re-exported here so every dispatch loop
// and call site keeps the same core.* names.
pub const ParseResult = parser.ParseResult;
pub const ParsedHead = parser.ParsedHead;
pub const Range = parser.Range;
pub const HeaderSpan = parser.HeaderSpan;
pub const SPAN_UNSCANNED = parser.SPAN_UNSCANNED;
pub const SPAN_ABSENT = parser.SPAN_ABSENT;
pub const parseHeadAt = parser.parseHeadAt;
pub const parseHead = parser.parseHead;
pub const getHeader = parser.getHeader;
pub const acceptEncoding = parser.acceptEncoding;
pub const queryParam = parser.queryParam;
pub const percentDecode = parser.percentDecode;
pub const parseRange = parser.parseRange;

/// Handler signature: the ergonomic request, response, context trio. All slices
/// the request exposes are valid only for the duration of the call. A returned
/// error is completed by the engine as a 500 when the handler wrote nothing.
pub const HandlerFn = *const fn (
    req: *Request,
    res: *Response,
    ctx: *Context,
) anyerror!void;

/// Build the request, response, and context trio over a parsed request and hand
/// it to the handler. One place builds the trio, so every dispatch model invokes
/// a handler the same way. On an error return the response is completed with a
/// 500, but only when the handler wrote nothing, so a handler that already sent a
/// response and then failed does not corrupt the stream.
///
/// Note:
/// - "Wrote nothing" covers both answer styles: the Response builder (`Response.sent`) and the fd
///   writers (`respondedFD`). A handler that answers with `sendSimpleFD` or `writeAllFD` holds no
///   Response, so checking `Response.sent` alone read it as unanswered and appended a second
///   status line to a response the peer was already reading.
/// - An error the handler swallows itself is the handler's own business. The engine completes an
///   error the handler RETURNS, nothing else.
///
/// Param:
/// handler_fn - HandlerFn (the route or top-level handler)
/// head - *const ParsedHead (borrows the receive buffer)
/// body - []const u8 (already drained by the engine)
/// fd - std.posix.fd_t (the connection)
/// io - std.Io (the worker io, carried for ctx and an inline driver call)
/// allocator - std.mem.Allocator (per-request scratch, reset by the engine)
///
/// Return:
/// - void
pub inline fn invokeHandler(
    handler_fn: HandlerFn,
    head: *const ParsedHead,
    body: []const u8,
    fd: std.posix.fd_t,
    io: std.Io,
    allocator: std.mem.Allocator,
) void {
    var req = Request.init(head, body, fd);
    var res = Response.init(fd, io, allocator);
    var ctx = Context.init(io, allocator, fd);

    if (tl_body_info) |info| {
        req.body_received = info.received;
        req.body_complete = info.complete;
        tl_body_info = null;
    }

    // Cleared here rather than at connection setup: the 100-continue an Expect request gets is
    // written by the engine before this point, and that interim write is not the handler answering.
    tl_responded = false;

    handler_fn(&req, &res, &ctx) catch {
        if (!res.sent and !respondedFD()) {
            sendSimpleFD(fd, 500, "text/plain", "Internal Server Error") catch {};
            res.status = .INTERNAL_SERVER_ERROR;
        }
    };

    writeAccessRecord(&req, &res, fd);
}

/// The logger this worker writes access records to, or null when none is attached.
///
/// Note:
/// - A threadlocal rather than a parameter because the multiplexed models install their per-worker
///   state once for the worker's whole life, and threading a logger through every dispatch call
///   would put that setup on the per-request path instead.
pub threadlocal var tl_access_logger: ?*Logger = null;

/// Attach the access logger for this worker (or, under .ASYNC, for this connection).
pub fn setAccessLogger(logger: ?*Logger) void {
    tl_access_logger = logger;
}

/// Log one served request, when a logger is attached.
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
        "http1",
        Method.stringFromEnum(req.method()),
        req.path(),
        @intFromEnum(res.status),
        res.bytes_written,
        client_ip,
        req.header("user-agent") orelse "",
        req.header("origin") orelse "",
    );
}

/// What a dispatch model measured about the body it just read, for the request
/// it is about to invoke.
///
/// Note:
/// - Only set when the delivered slice does not tell the whole story: a body the
///   engine consumed past what it could hand over, or one the peer cut short.
///   A body that arrived whole and fits the buffer needs no entry, Request.init
///   already derives both answers from the slice.
pub const BodyInfo = struct {
    /// Body bytes taken off the socket, counted from the reads that took them
    /// and never from the Content-Length header.
    received: u64,
    /// Whether those reads reached the end of the body: the declared length, or
    /// the chunked terminator.
    complete: bool,
};

/// Body measurements for the request about to be invoked. Null is the common
/// case and the one the bodyless hot path takes, so the check costs one load and
/// one branch. Consumed and cleared by invokeHandler, so it never leaks into a
/// later request on the same thread.
pub threadlocal var tl_body_info: ?BodyInfo = null;

/// Whether response bytes for the request in flight have already reached the wire.
///
/// Note:
/// - The `Response` builder tracks the same thing in `Response.sent`, but a handler may answer
///   through the fd writers instead, which hold no `Response`. Without this the engine reads such
///   a handler as never having answered and completes it a second time, gluing a status line onto
///   a response the peer is already reading.
/// - A threadlocal because the fd writers take an fd and nothing else. Cleared by invokeHandler,
///   so it never carries into the next request on this thread.
pub threadlocal var tl_responded: bool = false;

/// Record that response bytes for the request in flight reached the wire.
///
/// Note:
/// - Called by the fd writers, never by a handler. `Response.send*` reaches it through the same
///   writers, so both answer styles set it.
///
/// Return:
/// - void
pub fn markResponded() void {
    tl_responded = true;
}

/// Whether the request in flight has been answered through the fd writers.
///
/// Return:
/// - bool
pub fn respondedFD() bool {
    return tl_responded;
}

/// Options for serveConn.
pub const ServeOpts = struct {
    nodelay: bool = true,
    /// Per-handler execution budget in milliseconds. 0 = no deadline armed.
    handler_timeout_ms: u32 = 0,
    /// SO_RCVBUF applied on the large-body path only (a body larger than the read buffer). 0 leaves
    /// the kernel default. Widens the receive window so a large upload drains in fewer cycles.
    large_body_rcvbuf: usize = 0,
    /// Per-connection receive size in bytes, from config.max_recv_buf. Bounds the
    /// request head and the body slice a handler is given, the same knob the
    /// .EPOLL and .URING slots are cut from. Defaults to BUF_SIZE so a direct
    /// serveConn caller that does not care keeps the historical size.
    max_recv_buf: usize = BUF_SIZE,
    /// Largest request body in bytes, from config.max_request_body. A declared
    /// Content-Length past this is refused with 413 before the body is read or
    /// discarded. 0 removes the check.
    max_request_body: usize = 0,
};

/// This pool thread's receive and body buffers for the thread model (.ASYNC).
///
/// io.async hands each connection to whichever pool thread is free, so a thread
/// keeps one pair and every connection it serves reuses them. That is the same
/// shape a .EPOLL or .URING worker already has, one body scratch shared by every
/// connection the worker owns, rather than a fresh reservation per connection.
threadlocal var tl_recv_buf: []u8 = &.{};
threadlocal var tl_body_buf: []u8 = &.{};

/// The pair of buffers this pool thread serves connections with, allocated on
/// first use and grown only when a later connection asks for more.
///
/// Note:
/// - They live for the thread's lifetime rather than the connection's. That is
///   the trade the event-loop models already make, and it is what keeps a
///   request allocation-free.
/// - Resident is bounded by pool threads, not by connection count.
///
/// Param:
/// size - usize (bytes each buffer must hold, from config.max_recv_buf)
///
/// Return:
/// - the two buffers, each exactly size bytes
/// - null when the allocation failed, the caller drops the connection
fn threadConnBufs(size: usize) ?struct { recv: []u8, body: []u8 } {
    if (tl_recv_buf.len < size) {
        const grown = std.heap.smp_allocator.realloc(tl_recv_buf, size) catch return null;
        tl_recv_buf = grown;
    }

    if (tl_body_buf.len < size) {
        const grown = std.heap.smp_allocator.realloc(tl_body_buf, size) catch return null;
        tl_body_buf = grown;
    }

    return .{ .recv = tl_recv_buf[0..size], .body = tl_body_buf[0..size] };
}

/// SO_RCVBUF for the large-body path under the event-loop models (.EPOLL / .URING), set once per
/// worker from config.large_body_rcvbuf. The blocking model (.ASYNC) carries it on ServeOpts instead. The
/// event-loop request functions do not thread config through, so a threadlocal is the carrier. 0
/// leaves the kernel default.
pub threadlocal var tl_large_body_rcvbuf: usize = 0;

/// Install the large-body SO_RCVBUF for this worker (event-loop models).
pub fn setLargeBodyRcvbuf(bytes: usize) void {
    tl_large_body_rcvbuf = bytes;
}

/// Largest request body accepted under the event-loop models (.EPOLL / .URING), set once per worker
/// from config.max_request_body. The blocking model (.ASYNC) carries it on ServeOpts instead. 0
/// removes the check.
pub threadlocal var tl_max_request_body: usize = 0;

/// Install the request body limit for this worker.
pub fn setMaxRequestBody(bytes: usize) void {
    tl_max_request_body = bytes;
}

/// External fd watch (.URING): a caller-registered callback for foreign fds
/// (driver sockets) living on the engine worker's own ring. The callback runs
/// on the worker thread when the fd turns readable. The watch is multishot
/// and the engine sustains it, arm once per fd via uringWatchFd.
pub const ExternalFn = *const fn (fd: std.posix.fd_t) void;

/// Per-worker external-readable callback, set once per worker by the caller.
pub threadlocal var tl_external_cb: ?ExternalFn = null;

/// Ring-arm trampoline installed by the .URING worker loop for this thread.
pub threadlocal var tl_uring_watch: ?*const fn (ctx: *anyopaque, fd: std.posix.fd_t) bool = null;
pub threadlocal var tl_uring_watch_ctx: ?*anyopaque = null;

/// Register the external-readable callback for this worker thread.
pub fn setExternalHandler(cb: ExternalFn) void {
    tl_external_cb = cb;
}

/// Arm a multishot readable watch for fd on this worker's ring.
///
/// Return:
/// - true when armed or parked (the callback fires on each readable)
/// - false when this thread is not a .URING worker or the ring cannot take it
pub fn uringWatchFd(fd: std.posix.fd_t) bool {
    const watch = tl_uring_watch orelse return false;

    return watch(tl_uring_watch_ctx.?, fd);
}

/// Widen the socket receive buffer (SO_RCVBUF) so a large request body drains in fewer cycles.
/// Applied only on the large-body path (a body bigger than the read buffer), so ordinary small
/// requests keep the kernel default and its autotuning. bytes = 0 leaves the socket untouched.
/// Note: an explicit SO_RCVBUF disables receive autotuning for that socket, which is why it is set
/// only when a large body is actually detected, not at accept.
pub fn setRecvBuf(fd: std.posix.fd_t, bytes: usize) void {
    if (bytes == 0) return;
    if (comptime @import("builtin").target.os.tag == .windows) return;

    const val: c_int = @intCast(@min(bytes, std.math.maxInt(c_int)));
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&val)) catch {};
}

/// Read some bytes from fd: the ntdll shim on Windows, std.posix.read elsewhere.
///
/// Return:
/// - usize (bytes read, 0 when the peer closed)
/// - read error otherwise
fn readOnceFD(fd: std.posix.fd_t, buf: []u8) !usize {
    if (comptime @import("builtin").target.os.tag == .windows) return win_io.readOnce(fd, buf);

    return std.posix.read(fd, buf);
}

// --------------------------------------------------------- //

/// Wall-clock nanoseconds since the epoch (CLOCK_REALTIME).
fn wallClockNs() u64 {
    if (comptime @import("builtin").target.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);

        return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
    }

    if (comptime @import("builtin").target.os.tag == .windows) return win_io.wallClockNs();

    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &ts);

    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// Per-handler deadline, thread-local so each worker tracks its own request.
/// 0 means no deadline is active.
threadlocal var tl_deadline_ns: u64 = 0;

/// Arm or clear the per-handler deadline for the current thread.
/// The server calls this before each dispatch with config.handler_timeout_ms.
/// Handlers may call it to shorten their own budget. ms = 0 clears the deadline.
pub fn setTimeout(ms: u32) void {
    tl_deadline_ns = if (ms == 0)
        0
    else
        wallClockNs() + @as(u64, ms) * std.time.ns_per_ms;
}

/// Whether the current handler's deadline has passed.
/// Always false when no deadline is armed.
pub fn isExpired() bool {
    if (tl_deadline_ns == 0) return false;

    return wallClockNs() >= tl_deadline_ns;
}

// --------------------------------------------------------- //

/// Per-frame callback for an engine-owned WebSocket connection.
/// The engine parses each complete client frame and invokes this for text and
/// binary opcodes. opcode is the raw RFC 6455 opcode value (use the
/// WebSocket.Opcode enum to interpret it). Ping is auto-ponged and close is
/// auto-echoed by the engine, so the callback only ever sees data frames.
///
/// Param:
/// fd - std.posix.fd_t (the connection, write replies with WebSocket.send)
/// opcode - u8 (RFC 6455 opcode, .text or .binary in practice)
/// payload - []const u8 (unmasked frame payload, valid only for this call)
pub const WsFrameFn = *const fn (fd: std.posix.fd_t, opcode: u8, payload: []const u8) void;

const WsPending = struct {
    fd: std.posix.fd_t,
    on_frame: WsFrameFn,
};

/// Set by WebSocket.serve during a handler, read right after the handler returns by whichever
/// loop owns the connection. Thread-local, so a thread only ever hands off its own connection.
/// Honored under every dispatch model: the event loops drive their own frame pump, .ASYNC drives
/// the blocking one in websocket.serveBlocking.
threadlocal var tl_ws_pending: ?WsPending = null;

/// Request that the connection on fd be promoted to an engine-owned WebSocket
/// after the current handler returns. WebSocket.serve calls this for you.
pub fn requestWebSocket(fd: std.posix.fd_t, on_frame: WsFrameFn) void {
    tl_ws_pending = .{ .fd = fd, .on_frame = on_frame };
}

/// Take and clear any pending WebSocket promotion for the current thread.
/// The engine calls this after every dispatch.
pub fn takeWebSocket() ?WsPending {
    const pending = tl_ws_pending;
    tl_ws_pending = null;

    return pending;
}

// --------------------------------------------------------- //
// Response cache: per-worker, per-key precomputed response (ADR-036).

/// The calling thread's response cache when config.response_cache is on, null otherwise. The
/// multiplexed workers set it once per worker, .ASYNC once per io pool thread (utils/async_cache).
/// When null every cache call below degrades to a no-op, so a handler that uses the cache API
/// still works on a server with caching disabled.
pub threadlocal var tl_cache: ?*cache.ResponseCache = null;

/// Configured default TTL in milliseconds, installed alongside tl_cache. A
/// handler may pass its own TTL or this default via cacheTtl().
pub threadlocal var tl_cache_ttl_ms: u32 = 1000;

/// Install or clear the response cache and its default TTL for this worker.
pub fn setCache(resp_cache: ?*cache.ResponseCache, default_ttl_ms: u32) void {
    tl_cache = resp_cache;
    tl_cache_ttl_ms = default_ttl_ms;
}

/// The configured default cache TTL for this worker, for handlers that want it.
pub fn cacheTtl() u32 {
    return tl_cache_ttl_ms;
}

/// Whether response compression is enabled for this worker. Off unless the server
/// installs it from config.compress. When off, sendNegotiateCachedFD always writes
/// uncompressed.
pub threadlocal var tl_compression: bool = false;

/// Body size floor for compression, installed from config.compression_min_size.
pub threadlocal var tl_compression_min_size: usize = compression.min_size_default;

/// Compressed-output cap, installed from config.compression_max_out. A compressed
/// result above this is discarded and the response is sent uncompressed.
pub threadlocal var tl_compression_max_out: usize = GZIP_OUT_SIZE;

/// Install or clear the compression policy for this worker.
pub fn setCompression(enabled: bool, min_size: usize, max_out: usize) void {
    tl_compression = enabled;
    tl_compression_min_size = min_size;
    tl_compression_max_out = max_out;
}

/// Look up a full cached response for this request. Returns the cached bytes
/// when caching is enabled and a fresh entry exists, else null. The key is
/// hash(method, path, query). Write the returned bytes with writeAllFD.
pub fn cacheLookup(head: *const ParsedHead) ?[]const u8 {
    const c = tl_cache orelse return null;
    const key = cache.hashKey(head.method, head.path, head.query);

    return c.lookup(key, cache.nowMillis());
}

/// Response to answer a failed request-line parse with
///
/// Note:
/// - A method the engine does not implement is 501, not 400: the request line
///   was well formed and only the method is unsupported (RFC 9110 section
///   15.6.2). QUERY reached this path before RFC 10008 support, and answering
///   400 told a client the request was broken when it was merely unhandled
/// - Every other parse failure is a malformed request line, which stays 400
/// - Reached only on the error path, so no request that parses pays for it
///
/// Param:
/// err - anyerror (from parseHead or parseHeadAt)
///
/// Return:
/// - []const u8 (a complete response, ready to write)
pub fn parseErrorResponse(err: anyerror) []const u8 {
    return switch (err) {
        error.ZixUnknownMethod => "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n",
        else => "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
    };
}

/// Whether a response to this request may be stored under its request key
///
/// Note:
/// - The key is hash(method, path, query) and carries no request content. Two
///   QUERY requests to one path with different bodies would therefore share a
///   key, and one query's answer could be served for another
/// - RFC 10008 section 2.7 requires a cache key that incorporates the request
///   content, and makes caching a QUERY response a MAY. Refusing to store is
///   the conformant answer for a key this shape
/// - Only the store path checks this. Nothing is ever written under a QUERY
///   key, so the lookup path stays untouched and keeps its cost
///
/// Param:
/// head - *const ParsedHead
///
/// Return:
/// - bool
fn storableUnderRequestKey(head: *const ParsedHead) bool {
    return !std.mem.eql(u8, head.method, "QUERY");
}

/// Store full response bytes as this request's cached response for ttl_ms.
/// No-op when caching is disabled, the request is a QUERY, the bytes exceed the
/// per-slot cap, or the table is full. The bytes must be a complete HTTP response.
pub fn cacheStore(head: *const ParsedHead, bytes: []const u8, ttl_ms: u32) void {
    const c = tl_cache orelse return;
    if (!storableUnderRequestKey(head)) return;

    const key = cache.hashKey(head.method, head.path, head.query);

    _ = c.store(key, bytes, ttl_ms, cache.nowMillis());
}

/// Look up a cached response for this request under a specific content-encoding (the per-(key,
/// encoding) cache). The compressed and identity representations live in distinct slots, so a gzip
/// request never replays the identity body. Returns the full response bytes, or null.
pub fn cacheLookupEncoded(head: *const ParsedHead, encoding: []const u8) ?[]const u8 {
    const c = tl_cache orelse return null;
    const key = cache.hashKeyEncoded(head.method, head.path, head.query, encoding);

    return c.lookup(key, cache.nowMillis());
}

/// Store full response bytes for this request under a specific content-encoding. The bytes must be a
/// complete HTTP response (status line + headers + the encoded body).
pub fn cacheStoreEncoded(head: *const ParsedHead, encoding: []const u8, bytes: []const u8, ttl_ms: u32) void {
    const c = tl_cache orelse return;
    if (!storableUnderRequestKey(head)) return;

    const key = cache.hashKeyEncoded(head.method, head.path, head.query, encoding);

    _ = c.store(key, bytes, ttl_ms, cache.nowMillis());
}

/// Store bytes under this request's key (when cacheable) then write them to fd.
///
/// Note:
/// - Cache the full response only for idempotent methods (GET, HEAD). Dynamic
///   per-request bodies either set a short ttl_ms or skip the cache and write
///   directly.
///
/// Usage:
/// ```zig
/// fn handler(req: *zix.Http1.Request, res: *zix.Http1.Response, ctx: *zix.Http1.Context) !void {
///     if (zix.Http1.cacheLookup(req.head)) |bytes| {
///         try res.sendRaw(bytes);
///         return;
///     }
///
///     const resp = buildResponse(req.head, try req.body());
///     zix.Http1.sendWithCacheFD(req.fd, req.head, resp, zix.Http1.cacheTtl()) catch {};
/// }
/// ```
pub fn sendWithCacheFD(fd: std.posix.fd_t, head: *const ParsedHead, bytes: []const u8, ttl_ms: u32) error{BrokenPipe}!void {
    cacheStore(head, bytes, ttl_ms);

    return writeAllFD(fd, bytes);
}

// --------------------------------------------------------- //

fn statusPhrase(code: u16) []const u8 {
    return switch (code) {
        100 => "Continue",
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        408 => "Request Timeout",
        416 => "Range Not Satisfiable",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        else => "Unknown",
    };
}

/// Comptime-baked "HTTP/1.1 <code> <phrase>\r\n" status line for the known codes,
/// so the response builder emits the whole line in one copy instead of
/// assembling it from five pieces per request. Returns "" for an unknown code,
/// where the caller falls back to the piecewise build. Byte-identical to that
/// build for every known code.
fn statusLine(code: u16) []const u8 {
    return switch (code) {
        100 => "HTTP/1.1 100 Continue\r\n",
        200 => "HTTP/1.1 200 OK\r\n",
        201 => "HTTP/1.1 201 Created\r\n",
        204 => "HTTP/1.1 204 No Content\r\n",
        206 => "HTTP/1.1 206 Partial Content\r\n",
        301 => "HTTP/1.1 301 Moved Permanently\r\n",
        302 => "HTTP/1.1 302 Found\r\n",
        304 => "HTTP/1.1 304 Not Modified\r\n",
        400 => "HTTP/1.1 400 Bad Request\r\n",
        401 => "HTTP/1.1 401 Unauthorized\r\n",
        403 => "HTTP/1.1 403 Forbidden\r\n",
        404 => "HTTP/1.1 404 Not Found\r\n",
        405 => "HTTP/1.1 405 Method Not Allowed\r\n",
        408 => "HTTP/1.1 408 Request Timeout\r\n",
        416 => "HTTP/1.1 416 Range Not Satisfiable\r\n",
        431 => "HTTP/1.1 431 Request Header Fields Too Large\r\n",
        500 => "HTTP/1.1 500 Internal Server Error\r\n",
        501 => "HTTP/1.1 501 Not Implemented\r\n",
        503 => "HTTP/1.1 503 Service Unavailable\r\n",
        else => "",
    };
}

fn formatHttpDate(secs: u64, buf: []u8) []u8 {
    const ep = std.time.epoch;
    const es = ep.EpochSeconds{ .secs = secs };
    const epoch_day = es.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = es.getDaySeconds();
    const day_names = [_][]const u8{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    const dow = (@as(u64, epoch_day.day) % 7 + 4) % 7;

    return std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        day_names[dow],
        @as(u32, month_day.day_index) + 1,
        month_names[@intFromEnum(month_day.month) - 1],
        year_day.year,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
    }) catch buf[0..0];
}

const DateCache = struct {
    secs: u64,
    buf: [40]u8,
    len: usize,
};

threadlocal var tl_date: DateCache = .{ .secs = 0, .buf = undefined, .len = 0 };
threadlocal var tl_date_tick: u8 = 0;
threadlocal var tl_send_date: bool = true;

/// Set whether responses include the Date header. Called once per worker thread at startup.
pub fn setDateHeader(enabled: bool) void {
    tl_send_date = enabled;
}

/// Configured static-serve root for the unmatched-route fallback. Empty disables it. The router
/// reads these because the static fallback runs before any handler, so the public_dir and io are
/// threaded down per worker the same way the date / cache / compression switches are.
pub threadlocal var tl_static_dir: []const u8 = "";
pub threadlocal var tl_static_io: ?std.Io = null;

/// Install the static-serve root and io for this worker thread. Called once per worker at startup.
/// An empty public_dir leaves static serving off (the router falls straight through to 404).
pub fn setStatic(public_dir: []const u8, io: std.Io) void {
    tl_static_dir = public_dir;
    tl_static_io = io;
}

/// Response extra-header capacity (Response.addHeader) for this worker, from
/// config.max_response_headers. The backing buffer is allocated lazily per
/// request on the first addHeader call, so requests that add none pay nothing.
pub threadlocal var tl_max_response_headers: usize = 16;

/// Install the Response extra-header capacity for this worker thread. Called once per worker at startup.
pub fn setMaxResponseHeaders(count: usize) void {
    tl_max_response_headers = count;
}

fn cachedDate() []const u8 {
    tl_date_tick +%= 1;
    if (tl_date_tick == 0 or tl_date.len == 0) {
        const secs: u64 = wallClockNs() / std.time.ns_per_s;
        if (secs != tl_date.secs or tl_date.len == 0) {
            const d = formatHttpDate(secs, &tl_date.buf);
            tl_date.secs = secs;
            tl_date.len = d.len;
        }
    }

    return tl_date.buf[0..tl_date.len];
}

// --------------------------------------------------------- //

fn appendStatusCode(buf: []u8, pos: usize, code: u16) usize {
    buf[pos] = '0' + @as(u8, @intCast(code / 100));
    buf[pos + 1] = '0' + @as(u8, @intCast((code / 10) % 10));
    buf[pos + 2] = '0' + @as(u8, @intCast(code % 10));
    return pos + 3;
}

fn appendDec(buf: []u8, pos: usize, val: usize) usize {
    if (val == 0) {
        buf[pos] = '0';
        return pos + 1;
    }
    var tmp: [20]u8 = undefined;
    var tmp_len: usize = 0;
    var v = val;
    while (v > 0) {
        tmp[tmp_len] = '0' + @as(u8, @intCast(v % 10));
        tmp_len += 1;
        v /= 10;
    }

    var i: usize = 0;
    while (i < tmp_len) : (i += 1) {
        buf[pos + i] = tmp[tmp_len - 1 - i];
    }

    return pos + tmp_len;
}

fn appendBytes(buf: []u8, pos: usize, str: []const u8) usize {
    @memcpy(buf[pos..][0..str.len], str);
    return pos + str.len;
}

/// Write a simple response header into buf starting at offset 0.
/// buf must be at least 256 bytes. Returns the number of bytes written.
/// The block ends with the final \r\n\r\n, so a caller inserting extra
/// headers (Response.addHeader) splices them in before the last two bytes.
pub fn buildSimpleHeaderInto(buf: []u8, status: u16, content_type: []const u8, body_len: usize) usize {
    var pos: usize = 0;

    const line = statusLine(status);
    if (line.len > 0) {
        pos = appendBytes(buf, pos, line);
    } else {
        pos = appendBytes(buf, pos, "HTTP/1.1 ");
        pos = appendStatusCode(buf, pos, status);
        buf[pos] = ' ';
        pos += 1;
        pos = appendBytes(buf, pos, statusPhrase(status));
        pos = appendBytes(buf, pos, "\r\n");
    }

    if (content_type.len > 0) {
        pos = appendBytes(buf, pos, "Content-Type: ");
        pos = appendBytes(buf, pos, content_type);
        pos = appendBytes(buf, pos, "\r\n");
    }
    pos = appendBytes(buf, pos, "Content-Length: ");
    pos = appendDec(buf, pos, body_len);
    pos = appendBytes(buf, pos, "\r\n");
    if (tl_send_date) {
        pos = appendBytes(buf, pos, "Date: ");
        pos = appendBytes(buf, pos, cachedDate());
        pos = appendBytes(buf, pos, "\r\n");
    }
    pos = appendBytes(buf, pos, "\r\n");

    return pos;
}

fn buildSimpleHeader(buf: *[HEADER_BUF_SIZE]u8, status: u16, content_type: []const u8, body_len: usize) []u8 {
    return buf[0..buildSimpleHeaderInto(buf, status, content_type, body_len)];
}

// --------------------------------------------------------- //

/// Coalescing sink for pipelined responses. While installed (tl_resp_sink),
/// writeAllFD appends to buf instead of hitting the socket, so a pipelined
/// burst of N responses costs one write() instead of N. Same pattern as the
/// WebSocket SendSink. Installed by the .EPOLL / .URING request loops
/// (dispatch/) and the TLS capture path (tls_serve.runHandlerToBuffer).
pub const RespSink = struct {
    fd: std.posix.fd_t,
    buf: []u8,
    len: usize = 0,
    failed: bool = false,
    /// Where bytes past the staging buffer go when there is no descriptor to write them to. The
    /// https paths install the connection's TLS stream sink here, so a response larger than buf
    /// leaves as TLS records while it is still being rendered instead of failing at the buffer's
    /// edge. null (cleartext) keeps the write-to-fd behavior.
    spill: ?*TlsStreamSink = null,
    /// When set, an overflowing append grows buf (realloc up to grow_cap)
    /// instead of flushing to the socket. The URING dispatch installs this over
    /// the per-connection send buffer so a response larger than the staged
    /// buffer still goes out as one on-ring send instead of stalling the whole
    /// worker on a blocking off-ring write. null (the EPOLL path) keeps the
    /// flush-on-overflow behavior.
    grow_allocator: ?std.mem.Allocator = null,
    /// Hard ceiling for grow_allocator growth. Past this an oversized response
    /// falls back to a single direct flush rather than unbounded buffering.
    grow_cap: usize = 0,
    /// Whether buf is owned by grow_allocator (realloc-able). false when buf is
    /// a slice of the per-connection slab, which cannot be realloc'd: the first
    /// grow then switches to a fresh heap buffer (copying the staged bytes) and
    /// flips this to true, so the connection's close path knows to free it.
    buf_owned: bool = true,
    /// Zero-copy cache replay (URING only): a whole-response cache hit written
    /// while the sink is empty is borrowed into direct with its slot pinned,
    /// instead of memcpy'd into buf. The ring then sends the slab bytes and
    /// unpins on completion. Off (false) on every other path.
    allow_direct: bool = false,
    direct: []const u8 = &.{},
    direct_slot: u32 = 0,
    /// Dead prefix before the staged bytes. A reserve-committed response
    /// renders its body at HEADER_BUF_SIZE and right-aligns the header before
    /// it, so the staged region starts here instead of 0. Always 0 outside
    /// that path, and reset to 0 by flush.
    off: usize = 0,

    /// Fold a captured zero-copy replay back into the staged batch: a later
    /// response in the same batch means the send must carry both in order, so
    /// the borrowed bytes are copied after all and the pin drops. The copy
    /// happens before unpin could matter: this worker owns the cache, so
    /// nothing can overwrite the region between the unpin and the memcpy.
    pub fn materializeDirect(self: *RespSink) void {
        if (self.direct.len == 0) return;

        const bytes = self.direct;
        self.direct = &.{};
        if (tl_cache) |c| c.unpin(self.direct_slot);

        self.append(bytes);
    }

    /// Send bytes that are not staying in buf: through the spill sink when one is installed (https,
    /// where the fd is a sentinel and every write has to become a TLS record), straight to the
    /// descriptor otherwise. A write that does not land marks the sink failed, which the caller
    /// reads as a broken peer.
    fn writeOut(self: *RespSink, bytes: []const u8) void {
        if (self.spill) |sink| {
            if (!sink.write(bytes)) self.failed = true;

            return;
        }

        writeAllDirectFD(self.fd, bytes) catch {
            self.failed = true;
        };
    }

    pub fn append(self: *RespSink, bytes: []const u8) void {
        // Single response larger than the whole buffer: grow to hold it when
        // backed by an allocator, otherwise flush the staged batch and write
        // this payload straight through.
        if (bytes.len > self.buf.len) {
            if (self.grow(self.len + bytes.len)) {
                @memcpy(self.buf[self.len..][0..bytes.len], bytes);
                self.len += bytes.len;

                return;
            }

            self.flush();
            self.writeOut(bytes);

            return;
        }

        // Cumulative overflow: the staged batch plus these bytes exceed the
        // buffer. Grow to keep the batch on the ring, otherwise flush it first.
        if (self.len + bytes.len > self.buf.len) {
            if (!self.grow(self.len + bytes.len)) self.flush();
        }

        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    pub fn flush(self: *RespSink) void {
        if (self.len == 0) return;

        self.writeOut(self.buf[self.off..self.len]);
        self.len = 0;
        self.off = 0;
    }

    /// Reserve an in-place body region for a response rendered directly into
    /// the sink buffer, so the body bytes are written exactly once (no
    /// handler-side scratch buffer, no append copy). The region starts at
    /// HEADER_BUF_SIZE: commitSimple builds the header right-aligned so it
    /// ends exactly where the body starts.
    ///
    /// Note:
    /// - Returns null when the sink already stages bytes (a pipelined batch),
    ///   a zero-copy replay is captured, or max_body does not fit. The caller
    ///   falls back to rendering its own buffer and writeAllFD.
    /// - Between reserve and commitSimple the caller must not stage any other
    ///   response bytes for this sink.
    ///
    /// Return:
    /// - []u8 body region of max_body bytes
    /// - null when unavailable, the caller uses the writeAllFD path
    pub fn reserve(self: *RespSink, max_body: usize) ?[]u8 {
        if (self.len != 0 or self.direct.len != 0 or self.failed) return null;
        if (HEADER_BUF_SIZE + max_body > self.buf.len) {
            if (!self.grow(HEADER_BUF_SIZE + max_body)) return null;
        }

        return self.buf[HEADER_BUF_SIZE..][0..max_body];
    }

    /// Commit a reserved render: build the simple header right-aligned so it
    /// ends exactly where the body starts, and stage header + body as one
    /// contiguous region (off marks the dead prefix before the header).
    pub fn commitSimple(self: *RespSink, status: u16, content_type: []const u8, body_len: usize) void {
        std.debug.assert(self.len == 0 and self.direct.len == 0);

        var hdr_buf: [HEADER_BUF_SIZE]u8 = undefined;
        const hdr = buildSimpleHeader(&hdr_buf, status, content_type, body_len);
        const start = HEADER_BUF_SIZE - hdr.len;
        @memcpy(self.buf[start..HEADER_BUF_SIZE], hdr);

        self.off = start;
        self.len = HEADER_BUF_SIZE + body_len;
    }

    /// Grow buf to hold at least need bytes when backed by a growable allocator.
    /// Returns false when growth is unavailable (no allocator) or would exceed
    /// grow_cap, so the caller falls back to a direct flush. Never shrinks, so a
    /// grown per-connection buffer is reused by later requests on that fd.
    fn grow(self: *RespSink, need: usize) bool {
        const gpa = self.grow_allocator orelse return false;
        if (need <= self.buf.len) return true;
        if (need > self.grow_cap) return false;

        var new_len = @max(self.buf.len, 1) * 2;
        while (new_len < need) new_len *= 2;
        if (new_len > self.grow_cap) new_len = self.grow_cap;

        if (!self.buf_owned) {
            const grown = gpa.alloc(u8, new_len) catch return false;
            @memcpy(grown[0..self.len], self.buf[0..self.len]);
            self.buf = grown;
            self.buf_owned = true;

            return true;
        }

        const grown = gpa.realloc(self.buf, new_len) catch return false;
        self.buf = grown;

        return true;
    }
};

/// Coalescing sink for the current worker. null sends every write straight to the fd.
pub threadlocal var tl_resp_sink: ?*RespSink = null;

/// Streaming sink for the thread-per-connection https path (ADR-054). While installed
/// (tl_tls_stream) and the buffered capture sink is detached, writeAllFD encrypts each write as one
/// TLS record and sends it straight to the socket, so an SSE handler streams over TLS instead of
/// buffering a whole response. Type-erased over the live connection (the 1.3 and 1.2 paths share
/// it): writeFn casts ctx back to the concrete per-connection state and encrypts + writes.
pub const TlsStreamSink = struct {
    ctx: *anyopaque,
    writeFn: *const fn (ctx: *anyopaque, plaintext: []const u8) bool,
    failed: bool = false,
    /// Whether any plaintext has already left through this sink for the request being served. Once
    /// bytes are on the wire the response is committed: a later failure can only close the
    /// connection, because a status line appended to a half-sent body is not a response.
    wrote: bool = false,

    pub fn write(self: *TlsStreamSink, bytes: []const u8) bool {
        if (self.failed) return false;

        if (!self.writeFn(self.ctx, bytes)) {
            self.failed = true;

            return false;
        }

        self.wrote = true;

        return true;
    }
};

/// Active streaming sink for the current worker thread (the thread-per-conn https path). null for
/// cleartext and the buffered https path, so writeAllFD never routes through it there.
pub threadlocal var tl_tls_stream: ?*TlsStreamSink = null;

/// Begin a streaming response (SSE) from a handler, so one handler serves cleartext and TLS.
///
/// Detaches any buffered capture / coalescing sink, so each subsequent writeAllFD flushes
/// immediately: over TLS it hands writes to the live-session stream sink (one record per write), in
/// cleartext it writes straight to the socket. An SSE handler never returns, so a buffered sink
/// would never flush. A no-op when no sink is installed (the cleartext .ASYNC SSE path).
///
/// Usage:
/// ```zig
/// fn eventsHandler(req: *zix.Http1.Request, res: *zix.Http1.Response, ctx: *zix.Http1.Context) !void {
///     zix.Http1.beginStream();
///     try res.sendRaw(sse_headers);
///     // ... emit events with res.sendRaw(...) ...
/// }
/// ```
pub fn beginStream() void {
    if (tl_resp_sink) |sink| {
        sink.materializeDirect();
        sink.flush();
        tl_resp_sink = null;
    }
}

/// Flush any response bytes still staged for fd. Handlers that write to the
/// fd directly (sendfile, raw send) must call this first so the wire order
/// matches the request order under pipelining. No-op when nothing is staged.
pub fn flushPending(fd: std.posix.fd_t) void {
    if (tl_resp_sink) |sink| {
        if (sink.fd == fd) {
            sink.materializeDirect();
            sink.flush();
        }
    }
}

/// Write as much of data to fd as possible without blocking.
/// On EAGAIN returns the byte count written so far (caller stages the rest).
/// On a permanent error returns null.
pub fn writeNonBlockFD(fd: std.posix.fd_t, data: []const u8) ?usize {
    if (comptime @import("builtin").target.os.tag == .windows) {
        // Windows path is blocking (ntdll wait-on-handle): a full send buffer
        // stalls the write instead of staging, no partial count to report.
        win_io.writeAll(fd, data) catch return null;
        return data.len;
    }

    var written: usize = 0;
    while (written < data.len) {
        const rc = std.posix.system.write(fd, data[written..].ptr, data.len - written);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return null;
                written += n;
            },
            .INTR => continue,
            .AGAIN => return written,
            else => return null,
        }
    }
    return written;
}

/// Write response bytes to fd, the canonical write behind every send helper.
/// Routes through the coalescing sink (tl_resp_sink) or the TLS stream sink
/// when one is installed for this worker, otherwise writes directly.
///
/// Note:
/// - Marks the request in flight as answered, so a handler that writes here directly is not
///   completed a second time by invokeHandler. Every send helper lands here, the SSE prologue
///   and the WebSocket 101 upgrade included.
pub fn writeAllFD(fd: std.posix.fd_t, data: []const u8) error{BrokenPipe}!void {
    markResponded();

    if (tl_resp_sink) |sink| {
        if (sink.fd == fd) {
            // Zero-copy cache replay: a whole-response hit written while the
            // batch is empty is borrowed (slot pinned) instead of copied. Only
            // the exact slice the cache lookup returned qualifies.
            if (sink.allow_direct and sink.len == 0 and sink.direct.len == 0) {
                if (tl_cache) |c| {
                    if (c.hitSlot(data)) |slot| {
                        c.pin(slot);
                        sink.direct = data;
                        sink.direct_slot = slot;

                        return;
                    }
                }
            }

            sink.materializeDirect();
            sink.append(data);
            if (sink.failed) return error.BrokenPipe;

            return;
        }
    }

    // Streaming https path (ADR-054): the capture sink was detached by beginStream(), so each write
    // encrypts one TLS record and sends it. null in cleartext, where writes go straight to the fd.
    if (tl_tls_stream) |strm| {
        return if (strm.write(data)) {} else error.BrokenPipe;
    }

    return writeAllDirectFD(fd, data);
}

fn writeAllDirectFD(fd: std.posix.fd_t, data: []const u8) error{BrokenPipe}!void {
    if (comptime @import("builtin").target.os.tag == .windows) return win_io.writeAll(fd, data);

    var rem = data;
    while (rem.len > 0) {
        const rc = std.posix.system.write(fd, rem.ptr, rem.len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.BrokenPipe;
                rem = rem[n..];
            },
            .INTR => continue,
            // Non-blocking socket with a full send buffer: wait for the peer
            // to drain it, then retry. Blocking sockets never hit this branch.
            .AGAIN => {
                var pfd = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 }};
                _ = std.posix.poll(&pfd, -1) catch return error.BrokenPipe;
            },
            else => return error.BrokenPipe,
        }
    }
}

/// Reserve an in-place render region on the worker's response sink for fd.
/// A handler that builds its body dynamically renders straight into the
/// returned region and seals it with responseCommit, so the body bytes are
/// written exactly once, into the buffer the response sends from.
///
/// Note:
/// - null when no sink is installed for fd, bytes are already staged, or
///   max_body does not fit. The caller falls back to rendering its own
///   buffer and writeAllFD, which is always correct.
///
/// Usage:
/// ```zig
/// if (zix.Http1.responseReserve(req.fd, MAX_BODY)) |region| {
///     const body_len = render(region);
///     try zix.Http1.responseCommit(req.fd, 200, "application/json", body_len);
///     return;
/// }
/// // writeAllFD fallback path
/// ```
///
/// Return:
/// - []u8 body region of max_body bytes
/// - null when unavailable
pub fn responseReserve(fd: std.posix.fd_t, max_body: usize) ?[]u8 {
    const sink = tl_resp_sink orelse return null;
    if (sink.fd != fd) return null;

    return sink.reserve(max_body);
}

/// Seal a responseReserve render as a complete response: the simple header
/// (status, content_type, Content-Length) is built by the engine directly in
/// front of the rendered body. Only valid right after a successful
/// responseReserve for the same fd, with body_len <= the reserved size.
///
/// Return:
/// - void
/// - error.BrokenPipe when the sink already failed for this connection
pub fn responseCommit(fd: std.posix.fd_t, status: u16, content_type: []const u8, body_len: usize) error{BrokenPipe}!void {
    markResponded();

    const sink = tl_resp_sink orelse return error.BrokenPipe;
    if (sink.fd != fd) return error.BrokenPipe;

    sink.commitSimple(status, content_type, body_len);

    return if (sink.failed) error.BrokenPipe else {};
}

/// Response with Content-Length body.
///
/// Note:
/// - Marks the request in flight as answered. The sink fast path below builds straight into the
///   batch and never reaches writeAllFD, so the mark cannot be left to that writer alone.
pub fn sendSimpleFD(
    fd: std.posix.fd_t,
    status: u16,
    content_type: []const u8,
    body: []const u8,
) !void {
    markResponded();

    if (tl_resp_sink) |sink| {
        if (sink.fd == fd) {
            // A pending zero-copy replay must land in the batch before this
            // response so the wire order matches the request order.
            sink.materializeDirect();

            // Fast path: build header directly into sink.buf at sink.len, then
            // append body. Eliminates the hdr_buf[256] stack allocation and the
            // hdr_buf-to-sink memcpy on the pipelined hot path.
            if (sink.len + HEADER_BUF_SIZE + body.len <= sink.buf.len) {
                const hdr_len = buildSimpleHeaderInto(sink.buf[sink.len..], status, content_type, body.len);
                sink.len += hdr_len;
                @memcpy(sink.buf[sink.len..][0..body.len], body);
                sink.len += body.len;
            } else {
                var hdr_buf: [HEADER_BUF_SIZE]u8 = undefined;
                const hdr = buildSimpleHeader(&hdr_buf, status, content_type, body.len);
                sink.append(hdr);
                if (!sink.failed) sink.append(body);
            }

            return if (sink.failed) error.BrokenPipe else {};
        }
    }

    var hdr_buf: [HEADER_BUF_SIZE]u8 = undefined;
    const hdr = buildSimpleHeader(&hdr_buf, status, content_type, body.len);

    if (body.len <= SMALL_BODY_INLINE_BUF - HEADER_BUF_SIZE) {
        var buf: [SMALL_BODY_INLINE_BUF]u8 = undefined;
        @memcpy(buf[0..hdr.len], hdr);
        @memcpy(buf[hdr.len..][0..body.len], body);

        // Skips that sink check entirely instead,
        // and write straight to the fd since code only reaches this line.
        return writeAllDirectFD(fd, buf[0 .. hdr.len + body.len]);
    }

    if (comptime @import("builtin").target.os.tag == .windows) {
        // No writev over ntdll: two blocking writes keep the same wire bytes.
        try win_io.writeAll(fd, hdr);
        return win_io.writeAll(fd, body);
    }

    var sent: usize = 0;
    const total = hdr.len + body.len;
    while (sent < total) {
        var iovs: [2]std.posix.iovec_const = undefined;
        var nvec: usize = 0;
        if (sent < hdr.len) {
            iovs[0] = .{ .base = hdr[sent..].ptr, .len = hdr.len - sent };
            iovs[1] = .{ .base = body.ptr, .len = body.len };
            nvec = 2;
        } else {
            const body_sent = sent - hdr.len;
            iovs[0] = .{ .base = body[body_sent..].ptr, .len = body.len - body_sent };
            nvec = 1;
        }
        const rc = std.os.linux.writev(fd, &iovs, nvec);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.BrokenPipe;
                sent += n;
            },
            .INTR => continue,
            .AGAIN => {
                var pfd = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 }};
                _ = std.posix.poll(&pfd, -1) catch return error.BrokenPipe;
            },
            else => return error.BrokenPipe,
        }
    }
}

/// Headers-only response (no body). Used for HEAD method responses.
pub fn sendSimpleNoBodyFD(
    fd: std.posix.fd_t,
    status: u16,
    content_type: []const u8,
    content_length: usize,
) !void {
    var hdr_buf: [HEADER_BUF_SIZE]u8 = undefined;
    const hdr = buildSimpleHeader(&hdr_buf, status, content_type, content_length);

    return writeAllFD(fd, hdr);
}

/// JSON response. Shorthand for sendSimpleFD with "application/json".
pub fn sendJsonFD(fd: std.posix.fd_t, status: u16, body: []const u8) !void {
    return sendSimpleFD(fd, status, "application/json", body);
}

/// Send 100 Continue before reading a large body.
pub fn send100ContinueFD(fd: std.posix.fd_t) !void {
    try writeAllFD(fd, "HTTP/1.1 100 Continue\r\n\r\n");
}

/// Per-worker compression scratch, one lazily mapped block per worker thread instead of ~1 MiB of
/// cold threadlocal (.tbss) buffers. The flate state is about 225 KB, its window 64 KB, plus the
/// two response assembly buffers. A per-request heap alloc of these would overflow SmpAllocator's
/// 32 KB size class and fall to mmap / munmap, whose process mmap_lock + TLB-shootdown serializes
/// every worker (the json-comp low-CPU stall). One mapping per worker keeps the hot path free of
/// allocation syscalls, keeps the hot threadlocals (sink, cache, date) packed instead of spread
/// across cold TLS blobs, and gives the scratch its own mapping so a non-compressing worker pays
/// nothing. The compressor is held as an error-union slot and built in place (sret), never as a
/// 225 KB stack temporary.
const EncodeScratch = struct {
    /// flate history window.
    window: [std.compress.flate.max_window_len]u8,
    /// flate state, built in place per response.
    comp: std.Io.Writer.Error!std.compress.flate.Compress,
    /// Full gzip response: the body compresses straight into [HEADER_BUF_SIZE..]
    /// and the header renders right-aligned before it (reserve-prefix assembly),
    /// so header and body are contiguous with zero body copies.
    resp: [HEADER_BUF_SIZE + GZIP_OUT_SIZE]u8,
    /// Same reserve-prefix assembly buffer for the negotiated
    /// (gzip / deflate / brotli) response path.
    neg_resp: [HEADER_BUF_SIZE + GZIP_OUT_SIZE]u8,
};

threadlocal var tl_encode_scratch: ?*EncodeScratch = null;

/// The worker's compression scratch, mapped on the first compressed response.
fn encodeScratch() !*EncodeScratch {
    if (tl_encode_scratch == null) {
        const raw = try slab_mem.mapZeroedSlots(u8, @sizeOf(EncodeScratch));
        tl_encode_scratch = @ptrCast(@alignCast(raw.ptr));
    }

    return tl_encode_scratch.?;
}

/// Build a complete gzip HTTP response (header + compressed body) into the per-worker buffer and
/// return the slice. A body inside the fast encoder's cap compresses via compression.flate_fast
/// (in-tree greedy fixed-Huffman gzip, no per-stream state init), larger bodies reuse the per-worker
/// std compressor. Either way the body compresses directly into the response buffer past the header
/// reserve, then the header renders right-aligned so it ends exactly where the body starts: no pass
/// over the compressed bytes, no allocation. Shared by sendGzipFD and sendGzipCachedFD.
fn buildGzipResponse(status: u16, content_type: []const u8, body: []const u8) ![]const u8 {
    const scratch = try encodeScratch();

    // Fast path: a body inside the fast encoder's cap compresses via the
    // in-tree greedy fixed-Huffman encoder (flate_fast), several times
    // faster than the std matcher on dynamic-response bodies. Larger bodies
    // keep the std path below.
    if (compression.flate_fast.fitsFast(body.len, GZIP_OUT_SIZE)) {
        const compressed_len = compression.flate_fast.gzipFastInto(body, scratch.resp[HEADER_BUF_SIZE..]);

        var hdr_buf: [HEADER_BUF_SIZE]u8 = undefined;
        const header = try std.fmt.bufPrint(
            &hdr_buf,
            "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Encoding: gzip\r\nContent-Length: {d}\r\n\r\n",
            .{ status, statusPhrase(status), content_type, compressed_len },
        );
        const start = HEADER_BUF_SIZE - header.len;
        @memcpy(scratch.resp[start..HEADER_BUF_SIZE], header);

        return scratch.resp[start .. HEADER_BUF_SIZE + compressed_len];
    }

    var out_w: std.Io.Writer = .fixed(scratch.resp[HEADER_BUF_SIZE..]);
    scratch.comp = std.compress.flate.Compress.init(
        &out_w,
        &scratch.window,
        .gzip,
        std.compress.flate.Compress.Options.default,
    );

    const comp: *std.compress.flate.Compress = if (scratch.comp) |*payload| payload else |_| return error.ZixCompressFailed;
    try comp.writer.writeAll(body);
    try comp.finish();

    const compressed = out_w.buffered();
    var hdr_buf: [HEADER_BUF_SIZE]u8 = undefined;
    const header = try std.fmt.bufPrint(
        &hdr_buf,
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Encoding: gzip\r\nContent-Length: {d}\r\n\r\n",
        .{ status, statusPhrase(status), content_type, compressed.len },
    );
    const start = HEADER_BUF_SIZE - header.len;

    @memcpy(scratch.resp[start..HEADER_BUF_SIZE], header);

    return scratch.resp[start .. HEADER_BUF_SIZE + compressed.len];
}

/// gzip-compressed response: flate_fast for bodies inside its cap, std.compress.flate above it.
pub fn sendGzipFD(fd: std.posix.fd_t, status: u16, content_type: []const u8, body: []const u8) !void {
    try writeAllFD(fd, try buildGzipResponse(status, content_type, body));
}

/// gzip response with the per-(key, encoding) cache: on a hit replay the cached compressed response
/// with zero compression work, on a miss compress once, store, and write. For a deterministic body
/// every request after the first becomes a replay.
pub fn sendGzipCachedFD(fd: std.posix.fd_t, head: *const ParsedHead, status: u16, content_type: []const u8, body: []const u8, ttl_ms: u32) !void {
    if (cacheLookupEncoded(head, "gzip")) |cached| return writeAllFD(fd, cached);

    const resp = try buildGzipResponse(status, content_type, body);
    cacheStoreEncoded(head, "gzip", resp, ttl_ms);

    try writeAllFD(fd, resp);
}

/// Build a complete brotli HTTP response (header + brotli body) into the per-worker negotiated buffer
/// and return the slice. Brotli's encoder needs heap scratch (input-sized hash and Huffman tables),
/// so it routes through the shared compression facade on the per-worker encode arena rather than the
/// flate-style compressor. The encoded body lands past the header reserve and the header renders
/// right-aligned before it (reserve-prefix assembly). Shared by sendBrotliFD and sendBrotliCachedFD.
fn buildBrotliResponse(status: u16, content_type: []const u8, body: []const u8) ![]const u8 {
    const scratch = try encodeScratch();
    const arena = encodeArena();
    defer _ = arena.reset(.retain_capacity);

    const encoded_len = try compression.encodeInto(arena.allocator(), .BR, body, scratch.neg_resp[HEADER_BUF_SIZE..], .DEFAULT);

    var hdr_buf: [HEADER_BUF_SIZE]u8 = undefined;
    const header = try std.fmt.bufPrint(
        &hdr_buf,
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Encoding: br\r\nContent-Length: {d}\r\n\r\n",
        .{ status, statusPhrase(status), content_type, encoded_len },
    );
    const start = HEADER_BUF_SIZE - header.len;

    @memcpy(scratch.neg_resp[start..HEADER_BUF_SIZE], header);

    return scratch.neg_resp[start .. HEADER_BUF_SIZE + encoded_len];
}

/// brotli-compressed response via the shared compression facade on the per-worker encode arena. The
/// forced-brotli sibling of sendGzipFD, for a caller that has already decided on brotli.
pub fn sendBrotliFD(fd: std.posix.fd_t, status: u16, content_type: []const u8, body: []const u8) !void {
    try writeAllFD(fd, try buildBrotliResponse(status, content_type, body));
}

/// brotli response with the per-(key, encoding) cache: a hit replays the cached compressed response
/// with zero compression work, a miss compresses once, stores, and writes. The forced-brotli sibling
/// of sendGzipCachedFD.
pub fn sendBrotliCachedFD(fd: std.posix.fd_t, head: *const ParsedHead, status: u16, content_type: []const u8, body: []const u8, ttl_ms: u32) !void {
    if (cacheLookupEncoded(head, "br")) |cached| return writeAllFD(fd, cached);

    const resp = try buildBrotliResponse(status, content_type, body);
    cacheStoreEncoded(head, "br", resp, ttl_ms);

    try writeAllFD(fd, resp);
}

/// Per-worker arena for negotiated-compression codec scratch (gzip / deflate / brotli), reset with
/// retained capacity after each response so the codecs reuse one backing allocation per worker
/// instead of allocating per request. Lazily initialized on first use.
threadlocal var tl_encode_arena: ?std.heap.ArenaAllocator = null;

fn encodeArena() *std.heap.ArenaAllocator {
    if (tl_encode_arena == null) {
        tl_encode_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    }

    return &tl_encode_arena.?;
}

/// Response with Accept-Encoding negotiation: the body is compressed only when the
/// worker has compression enabled, the client accepts a producible coding, the body
/// clears the size floor and is not an already-compressed media type, and the
/// compressed result is both smaller than the original and within the cap. In every
/// other case the body is sent uncompressed, byte-identical to sendSimpleFD.
///
/// Note:
/// - This is the negotiating replacement for a hand-called sendGzipFD. It uses the per-(key,
///   encoding) response cache: a hit replays the full compressed response with no compression
///   work, a miss compresses once then stores the assembled response under (key, encoding).
/// - The compressed response sets Content-Encoding and Vary: Accept-Encoding.
///
/// Param:
/// fd - std.posix.fd_t (connection)
/// head - *const ParsedHead (for the Accept-Encoding header)
/// status - u16 (response status)
/// content_type - []const u8 (response Content-Type)
/// body - []const u8 (uncompressed body)
///
/// Return:
/// - void
/// - error.BrokenPipe on a failed write
pub fn sendNegotiateCachedFD(
    fd: std.posix.fd_t,
    head: *const ParsedHead,
    status: u16,
    content_type: []const u8,
    body: []const u8,
) !void {
    if (!tl_compression) return sendSimpleFD(fd, status, content_type, body);

    const accept = acceptEncoding(head);
    const encoding = compression.negotiate(accept, &compression.supported_default) orelse {
        return sendSimpleNoBodyFD(fd, 406, content_type, 0);
    };

    if (encoding == .IDENTITY or !compression.shouldCompress(body.len, content_type, tl_compression_min_size)) {
        return sendSimpleFD(fd, status, content_type, body);
    }

    const token = encoding.contentEncoding().?;

    // Per-(key, encoding) cache hit: replay the full compressed response, no compression work.
    if (cacheLookupEncoded(head, token)) |cached| return writeAllFD(fd, cached);

    const scratch = encodeScratch() catch {
        return sendSimpleFD(fd, status, content_type, body);
    };

    // Per-worker arena for the codec scratch. gzip / deflate / brotli each allocate transient
    // buffers (brotli especially: input-sized hash tables, Huffman tables, command lists). A
    // per-request smp_allocator would mmap the larger ones over the 32 KiB size class and serialize
    // workers in the kernel. The arena is retained across requests, so after warmup the codec path
    // issues no allocation syscalls. The reset(.retain_capacity) call reclaims every codec buffer
    // after the response is written.
    const arena = encodeArena();
    defer _ = arena.reset(.retain_capacity);

    // Reserve-prefix assembly: the body encodes straight into the assembly buffer past the header
    // reserve, so the response never repeats a pass over the encoded bytes. An encoded result too
    // large for the buffer streams in two parts instead (the rare oversized path).
    const encoded_len = compression.encodeInto(arena.allocator(), encoding, body, scratch.neg_resp[HEADER_BUF_SIZE..], .DEFAULT) catch |err| switch (err) {
        error.ZixBufferTooSmall => return sendNegotiateOversized(fd, head, encoding, token, status, content_type, body),
        else => return sendSimpleFD(fd, status, content_type, body),
    };

    if (encoded_len > tl_compression_max_out or encoded_len >= body.len) {
        return sendSimpleFD(fd, status, content_type, body);
    }

    // The header renders right-aligned so it ends exactly where the encoded body starts, then the
    // contiguous response is cached and replayed on later requests with the same (key, encoding).
    var hdr_buf: [HEADER_BUF_SIZE]u8 = undefined;
    const header = try std.fmt.bufPrint(
        &hdr_buf,
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Encoding: {s}\r\nVary: Accept-Encoding\r\nContent-Length: {d}\r\n\r\n",
        .{ status, statusPhrase(status), content_type, token, encoded_len },
    );
    const start = HEADER_BUF_SIZE - header.len;

    @memcpy(scratch.neg_resp[start..HEADER_BUF_SIZE], header);
    const full = scratch.neg_resp[start .. HEADER_BUF_SIZE + encoded_len];
    cacheStoreEncoded(head, token, full, cacheTtl());

    return writeAllFD(fd, full);
}

/// Negotiated response for a body too large for the into-buffer bound check: compress through the
/// arena, then assemble + cache when the result fits the per-worker buffer (the copy is paid only
/// on this oversized-input branch), else stream in two parts and skip the cache. Off the hot path.
fn sendNegotiateOversized(
    fd: std.posix.fd_t,
    head: *const ParsedHead,
    encoding: compression.Encoding,
    token: []const u8,
    status: u16,
    content_type: []const u8,
    body: []const u8,
) !void {
    const arena = encodeArena();
    defer _ = arena.reset(.retain_capacity);

    const encoded = compression.encode(arena.allocator(), encoding, body, .DEFAULT) catch {
        return sendSimpleFD(fd, status, content_type, body);
    };

    if (encoded.len > tl_compression_max_out or encoded.len >= body.len) {
        return sendSimpleFD(fd, status, content_type, body);
    }

    var hdr_buf: [HEADER_BUF_SIZE]u8 = undefined;
    const header = try std.fmt.bufPrint(
        &hdr_buf,
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Encoding: {s}\r\nVary: Accept-Encoding\r\nContent-Length: {d}\r\n\r\n",
        .{ status, statusPhrase(status), content_type, token, encoded.len },
    );

    if (encodeScratch()) |scratch| {
        const total = header.len + encoded.len;
        if (total <= scratch.neg_resp.len) {
            @memcpy(scratch.neg_resp[0..header.len], header);
            @memcpy(scratch.neg_resp[header.len..total], encoded);
            const full = scratch.neg_resp[0..total];
            cacheStoreEncoded(head, token, full, cacheTtl());

            return writeAllFD(fd, full);
        }
    } else |_| {}

    try writeAllFD(fd, header);
    try writeAllFD(fd, encoded);
}

/// Response with Accept-Encoding negotiation, uncached sibling of sendNegotiateCachedFD: it compresses
/// on every request and never stores or replays. Suits a body that is not deterministic (a per-(key,
/// encoding) cache would only grow memory with no replay hit) or a lean, cache-free memory profile.
/// Same negotiation, size floor, and identity fall-through as the cached variant.
///
/// Note:
/// - The compressed response sets Content-Encoding and Vary: Accept-Encoding.
/// - No response cache: each call runs the codec on the per-worker encode arena, then reclaims it.
///
/// Param:
/// fd - std.posix.fd_t (connection)
/// head - *const ParsedHead (for the Accept-Encoding header)
/// status - u16 (response status)
/// content_type - []const u8 (response Content-Type)
/// body - []const u8 (uncompressed body)
///
/// Return:
/// - void
/// - error.BrokenPipe on a failed write
pub fn sendNegotiateFD(
    fd: std.posix.fd_t,
    head: *const ParsedHead,
    status: u16,
    content_type: []const u8,
    body: []const u8,
) !void {
    if (!tl_compression) return sendSimpleFD(fd, status, content_type, body);

    const accept = acceptEncoding(head);
    const encoding = compression.negotiate(accept, &compression.supported_default) orelse {
        return sendSimpleNoBodyFD(fd, 406, content_type, 0);
    };

    if (encoding == .IDENTITY or !compression.shouldCompress(body.len, content_type, tl_compression_min_size)) {
        return sendSimpleFD(fd, status, content_type, body);
    }

    const token = encoding.contentEncoding().?;

    const arena = encodeArena();
    defer _ = arena.reset(.retain_capacity);

    const encoded = compression.encode(arena.allocator(), encoding, body, .DEFAULT) catch {
        return sendSimpleFD(fd, status, content_type, body);
    };

    if (encoded.len > tl_compression_max_out or encoded.len >= body.len) {
        return sendSimpleFD(fd, status, content_type, body);
    }

    var hdr_buf: [HEADER_BUF_SIZE]u8 = undefined;
    const header = try std.fmt.bufPrint(
        &hdr_buf,
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Encoding: {s}\r\nVary: Accept-Encoding\r\nContent-Length: {d}\r\n\r\n",
        .{ status, statusPhrase(status), content_type, token, encoded.len },
    );

    try writeAllFD(fd, header);
    try writeAllFD(fd, encoded);
}

/// Start a chunked response. Call sendChunkFD for each chunk, then sendChunkedEndFD.
pub fn sendChunkedStartFD(fd: std.posix.fd_t, status: u16, content_type: []const u8) !void {
    var hdr: [HEADER_BUF_SIZE]u8 = undefined;
    const s = try std.fmt.bufPrint(
        &hdr,
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nTransfer-Encoding: chunked\r\n\r\n",
        .{ status, statusPhrase(status), content_type },
    );
    try writeAllFD(fd, s);
}

/// Write one chunk: hex_len CRLF data CRLF.
pub fn sendChunkFD(fd: std.posix.fd_t, data: []const u8) !void {
    if (data.len == 0) return;
    var sz: [32]u8 = undefined;
    const s = try std.fmt.bufPrint(&sz, "{x}\r\n", .{data.len});
    try writeAllFD(fd, s);
    try writeAllFD(fd, data);
    try writeAllFD(fd, "\r\n");
}

/// Terminate the chunked body with the final zero-length chunk.
pub fn sendChunkedEndFD(fd: std.posix.fd_t) !void {
    try writeAllFD(fd, "0\r\n\r\n");
}

/// 206 Partial Content or 416 Range Not Satisfiable based on parseRange result.
pub fn sendRangeFD(
    fd: std.posix.fd_t,
    content_type: []const u8,
    full_body: []const u8,
    range_val: []const u8,
) !void {
    const total: u64 = full_body.len;
    const range = parseRange(range_val, total) orelse {
        var hdr: [HEADER_BUF_SIZE]u8 = undefined;
        const s = try std.fmt.bufPrint(
            &hdr,
            "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{d}\r\nContent-Length: 0\r\n\r\n",
            .{total},
        );
        return writeAllFD(fd, s);
    };

    const slice = full_body[range.start .. range.end + 1];
    var hdr: [HEADER_BUF_SIZE]u8 = undefined;
    const s = try std.fmt.bufPrint(
        &hdr,
        "HTTP/1.1 206 Partial Content\r\nContent-Type: {s}\r\nContent-Range: bytes {d}-{d}/{d}\r\nContent-Length: {d}\r\n\r\n",
        .{ content_type, range.start, range.end, total, slice.len },
    );
    try writeAllFD(fd, s);
    try writeAllFD(fd, slice);
}

// --------------------------------------------------------- //

const RecvHeadResult = struct {
    body_offset: usize,
    filled: usize,
};

/// Bulk-read into buf until \r\n\r\n is found.
/// pre_filled bytes are already in buf from a previous iteration (keep-alive leftover).
///
/// Return:
/// - !RecvHeadResult
fn recvHead(fd: std.posix.fd_t, buf: []u8, pre_filled: usize) !RecvHeadResult {
    var filled = pre_filled;

    if (filled >= 4) {
        if (std.mem.indexOf(u8, buf[0..filled], "\r\n\r\n")) |pos| {
            return .{ .body_offset = pos + 4, .filled = filled };
        }
    }

    while (true) {
        if (filled >= buf.len) return error.ZixHeaderTooLarge;
        const n = readOnceFD(fd, buf[filled..]) catch return error.ZixClosed;
        if (n == 0) return error.ZixClosed;
        const search_from = if (filled > 3) filled - 3 else 0;
        filled += n;
        if (std.mem.indexOfPos(u8, buf[0..filled], search_from, "\r\n\r\n")) |pos| {
            return .{ .body_offset = pos + 4, .filled = filled };
        }
    }
}

/// Why a chunked body read or decode stopped.
pub const ChunkedStop = enum {
    /// The terminal chunk arrived, the body is whole.
    COMPLETE,
    /// The bytes in hand end mid-body. Read more and try again.
    NEED_MORE,
    /// The body does not fit the buffer the engine can hand a handler.
    TOO_LARGE,
    /// A chunk size line is not valid hex.
    MALFORMED,
};

/// What a walk of the chunk framing found.
pub const ChunkedFrame = struct {
    /// Decoded body size, valid once stop is COMPLETE.
    len: usize = 0,
    /// Wire bytes the body occupies, chunk framing and trailers included. Bytes
    /// past this belong to whatever follows the request.
    consumed: usize = 0,
    stop: ChunkedStop,
};

/// Walk the chunk framing in src without moving a byte.
///
/// Note:
/// - Steps over chunk data by its declared size, so the cost is one step per
///   chunk rather than one per byte, and data that happens to spell the terminal
///   chunk cannot be mistaken for it.
/// - The stop reason separates "not arrived yet" from "broken" from "too big".
///   One null for all three left every caller unable to answer, which is how a
///   malformed body used to stall a connection instead of drawing a 400.
///
/// Param:
/// src - []const u8 (chunked bytes received so far, framing included)
/// out_cap - usize (bytes the caller can hold, decides TOO_LARGE)
///
/// Return:
/// - ChunkedFrame
pub fn chunkedFrame(src: []const u8, out_cap: usize) ChunkedFrame {
    var pos: usize = 0;
    var decoded: usize = 0;

    while (true) {
        const line_end = std.mem.indexOfPos(u8, src, pos, "\r\n") orelse return .{ .stop = .NEED_MORE };
        const size_field = src[pos..line_end];
        const hex = if (std.mem.indexOfScalar(u8, size_field, ';')) |semi| size_field[0..semi] else size_field;

        const chunk_size = std.fmt.parseInt(usize, std.mem.trim(u8, hex, " "), 16) catch
            return .{ .stop = .MALFORMED };
        pos = line_end + 2;

        if (chunk_size == 0) {
            const trailer_end = std.mem.indexOfPos(u8, src, pos, "\r\n") orelse return .{ .stop = .NEED_MORE };

            return .{ .len = decoded, .consumed = trailer_end + 2, .stop = .COMPLETE };
        }

        if (decoded + chunk_size > out_cap) return .{ .stop = .TOO_LARGE };
        if (pos + chunk_size + 2 > src.len) return .{ .stop = .NEED_MORE };

        decoded += chunk_size;
        pos += chunk_size + 2;
    }
}

/// Decode a chunked request body that is fully present in src (RFC 9112 7.1).
///
/// Note:
/// - Every dispatch model decodes here, so a chunked body means the same thing
///   on all three.
/// - out may be src itself. Decoding only removes framing, so every byte moves
///   left and a forward copy is correct even where the ranges overlap. @memcpy
///   is not usable for that, it requires disjoint ranges.
/// - Nothing is copied until the framing walk says the body is whole, so a
///   partial body leaves src untouched and the caller can read more into it.
///
/// Param:
/// src - []const u8 (chunked bytes received so far, framing included)
/// out - []u8 (decode destination, may alias src)
///
/// Return:
/// - ChunkedFrame (len and consumed are set only when stop is COMPLETE)
pub fn decodeChunkedInBuf(src: []const u8, out: []u8) ChunkedFrame {
    const frame = chunkedFrame(src, out.len);
    if (frame.stop != .COMPLETE) return frame;

    var pos: usize = 0;
    var out_pos: usize = 0;

    while (out_pos < frame.len) {
        const line_end = std.mem.indexOfPos(u8, src, pos, "\r\n").?;
        const size_field = src[pos..line_end];
        const hex = if (std.mem.indexOfScalar(u8, size_field, ';')) |semi| size_field[0..semi] else size_field;
        const chunk_size = std.fmt.parseInt(usize, std.mem.trim(u8, hex, " "), 16) catch unreachable;
        pos = line_end + 2;

        std.mem.copyForwards(u8, out[out_pos..][0..chunk_size], src[pos..][0..chunk_size]);
        out_pos += chunk_size;
        pos += chunk_size + 2;
    }

    return frame;
}

/// Result of pulling a chunked body off a blocking socket.
pub const ChunkedRead = struct {
    /// Decoded body bytes, living at buf[0..len].
    len: usize = 0,
    /// Wire bytes of the body taken off the socket, framing included.
    received: u64 = 0,
    /// Bytes read past the end of the body, sitting at buf[leftover_off..][0..leftover].
    /// A pipelined request lands here, and dropping it would leave that client
    /// waiting on a response to a request the server already read.
    leftover_off: usize = 0,
    leftover: usize = 0,
    stop: ChunkedStop,
};

/// Read a chunked request body off a blocking socket and decode it in place.
///
/// Note:
/// - buf is both the read buffer and the decode destination. The caller seeds it
///   with the body bytes that arrived alongside the head, and the body is decoded
///   over those same bytes, so there is no second buffer and no full-body copy.
/// - A body that outgrows buf stops with TOO_LARGE rather than being cut to what
///   fits, because a handler cannot tell a cut body from a whole one.
/// - Whatever follows the body is reported, not discarded. The reader this
///   replaced kept a private buffer and dropped its tail, losing a pipelined
///   request the server had already taken off the socket.
///
/// Param:
/// fd - std.posix.fd_t
/// buf - []u8 (read buffer and decode destination, seeded bytes already at the front)
/// seeded - usize (how many body bytes the caller placed at the front of buf)
///
/// Return:
/// - ChunkedRead
pub fn readChunkedBody(fd: std.posix.fd_t, buf: []u8, seeded: usize) ChunkedRead {
    var filled = seeded;

    while (true) {
        const frame = chunkedFrame(buf[0..filled], buf.len);
        switch (frame.stop) {
            .COMPLETE => {
                _ = decodeChunkedInBuf(buf[0..filled], buf);

                return .{
                    .len = frame.len,
                    .received = frame.consumed,
                    .leftover_off = frame.consumed,
                    .leftover = filled - frame.consumed,
                    .stop = .COMPLETE,
                };
            },
            .MALFORMED, .TOO_LARGE => return .{ .received = filled, .stop = frame.stop },
            .NEED_MORE => {},
        }

        if (filled == buf.len) return .{ .received = filled, .stop = .TOO_LARGE };

        const n = readOnceFD(fd, buf[filled..]) catch return .{ .received = filled, .stop = .NEED_MORE };
        if (n == 0) return .{ .received = filled, .stop = .NEED_MORE };

        filled += n;
    }
}

/// Per-request verdict from a dispatch: keep the connection open or close it.
pub const ConnOutcome = enum { keep_alive, close };

/// Bytes requested per drain read on the portable arm of drainBody. The Linux arm
/// asks for the whole remainder in one call, because MSG.TRUNC never writes a buffer.
const DRAIN_SCRATCH: usize = 4096;

/// Upper clamp on bytes requested in a single MSG.TRUNC drain recv. The kernel
/// never writes the buffer there, so a length past it is safe. Mirrors the clamp
/// the multiplexed models use.
const MAX_DRAIN_RECV: usize = 1 << 30;

/// Discard request-body bytes still sitting on the socket.
///
/// Note:
/// - Never writes into the buffer the handler is about to read. The drained
///   bytes are not part of the delivered body, so sharing one buffer hands the
///   handler the tail of the drain in place of the start of its request.
/// - Stops early on a peer that hangs up, which the caller sees as a returned
///   count short of what it asked for.
///
/// Param:
/// fd - std.posix.fd_t (the connection)
/// owed - usize (body bytes still to consume)
///
/// Return:
/// - usize (bytes actually consumed off the socket)
fn drainBody(fd: std.posix.fd_t, owed: usize) usize {
    var remaining = owed;
    var consumed: usize = 0;
    var scratch: [DRAIN_SCRATCH]u8 = undefined;

    if (comptime @import("builtin").target.os.tag == .linux) {
        // MSG.TRUNC drops the bytes inside the kernel: nothing is copied to
        // userspace and one call may ask for far more than scratch holds.
        const linux = std.os.linux;

        while (remaining > 0) {
            const want = @min(remaining, MAX_DRAIN_RECV);
            const rc = linux.recvfrom(fd, &scratch, want, linux.MSG.TRUNC, null, null);
            switch (std.posix.errno(rc)) {
                .SUCCESS => {
                    const n: usize = @intCast(rc);
                    if (n == 0) return consumed;

                    consumed += n;
                    remaining -= n;
                },
                .INTR => continue,
                else => return consumed,
            }
        }

        return consumed;
    }

    // Portable arm: a dedicated scratch buffer, never the handler's body buffer.
    while (remaining > 0) {
        const want = @min(remaining, scratch.len);
        const n = readOnceFD(fd, scratch[0..want]) catch return consumed;
        if (n == 0) return consumed;

        consumed += n;
        remaining -= n;
    }

    return consumed;
}

/// Keep-alive connection loop. The caller owns closing the fd. Pass raw fd extracted
/// from the accepted stream.
pub fn serveConn(fd: std.posix.fd_t, handler: HandlerFn, opts: ServeOpts, io: std.Io) void {
    if (opts.nodelay) {
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
    }

    // Per-connection scratch for the handler trio, reset before each request so a
    // long keep-alive connection never grows without bound.
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();

    // Both buffers are cut from config.max_recv_buf, the same knob the .EPOLL
    // and .URING connection slots use, so the body a handler is given has one
    // size across every dispatch model.
    const recv_size = if (opts.max_recv_buf == 0) BUF_SIZE else opts.max_recv_buf;

    const bufs = threadConnBufs(recv_size) orelse return;
    const recv_buf = bufs.recv;
    const body_buf = bufs.body;

    var leftover: usize = 0;

    while (true) {
        const hdr = recvHead(fd, recv_buf, leftover) catch |err| {
            if (err == error.ZixHeaderTooLarge) {
                writeAllFD(fd, "HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\n\r\n") catch {};
            }
            return;
        };

        const result = parseHead(recv_buf[0..hdr.filled]) catch |err| {
            writeAllFD(fd, parseErrorResponse(err)) catch {};
            return;
        };
        const head = result.head;

        if (head.expect_continue and (head.content_length > 0 or head.chunked_request)) {
            send100ContinueFD(fd) catch return;
        }

        var body_len: usize = 0;
        var received: u64 = 0;
        var drained_large = false;
        // Whether this request declared a body at all, and whether reading it
        // reached the end. A request with no body skips the handoff below
        // entirely, so the bodyless path pays one compare and no store.
        var has_body = false;
        var body_complete = true;
        var chunked_leftover: usize = 0;
        var chunked_leftover_off: usize = 0;
        if (head.chunked_request) {
            // The body reads into body_buf and is decoded over itself there. recv_buf
            // cannot be used as that scratch: head still points into it, and the
            // handler is about to be given those slices.
            const peeked = hdr.filled - hdr.body_offset;
            if (peeked > 0) @memcpy(body_buf[0..peeked], recv_buf[hdr.body_offset..hdr.filled]);

            const chunked = readChunkedBody(fd, body_buf, peeked);
            switch (chunked.stop) {
                .COMPLETE => {},
                .MALFORMED => {
                    // The rest of the body cannot be framed, so there is no way to
                    // find where the next request would start. Answer and close.
                    writeAllFD(fd, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};

                    return;
                },
                .TOO_LARGE => {
                    writeAllFD(fd, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};

                    return;
                },
                .NEED_MORE => return,
            }

            has_body = true;
            body_len = chunked.len;
            received = chunked.received;
            chunked_leftover_off = chunked.leftover_off;
            chunked_leftover = chunked.leftover;
        } else if (head.content_length > 0) {
            // Refused before a byte of it is read or discarded, so a declared
            // length cannot make this thread consume an arbitrary body.
            if (opts.max_request_body != 0 and head.content_length > opts.max_request_body) {
                writeAllFD(fd, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n") catch {};

                return;
            }

            has_body = true;

            const content_length: usize = @intCast(head.content_length);
            const to_read: usize = @min(content_length, body_buf.len);
            const peeked = hdr.filled - hdr.body_offset;
            const from_peek = @min(peeked, to_read);
            if (from_peek > 0) {
                @memcpy(body_buf[0..from_peek], recv_buf[hdr.body_offset..][0..from_peek]);
            }
            body_len = from_peek;
            while (body_len < to_read) {
                const n = readOnceFD(fd, body_buf[body_len..to_read]) catch break;
                if (n == 0) break;
                body_len += n;
            }

            // Body bytes already off the socket: the ones that arrived with the head, plus the
            // ones the fill loop pulled. Counting only the head-side bytes here would make the
            // drain below ask for the fill loop's bytes a second time, taking them from the next
            // request on the connection.
            received = @min(peeked, content_length) + (body_len - from_peek);

            // Body larger than the handler buffer: consume the rest off the socket so the
            // connection stays usable for keep-alive (the leftover would otherwise be misparsed as
            // the next request). drainBody never touches body_buf, so the slice handed to the
            // handler stays the start of the request instead of the tail of the drain. A wider
            // SO_RCVBUF (opts.large_body_rcvbuf) speeds this on uploads.
            if (received < content_length) {
                setRecvBuf(fd, opts.large_body_rcvbuf);

                received += drainBody(fd, content_length - received);
                drained_large = true;
            }

            // A peer that stopped early leaves the drain short of the declared
            // length. The handler still runs, so it needs a way to tell that
            // upload apart from one that finished.
            body_complete = received >= content_length;
        }

        setTimeout(opts.handler_timeout_ms);
        _ = arena.reset(.retain_capacity);

        // The delivered slice is capped by body_buf, the count is everything the socket gave up,
        // so a handler comparing the two can tell a truncated body from a complete one.
        if (has_body) tl_body_info = .{ .received = received, .complete = body_complete };
        invokeHandler(handler, &head, body_buf[0..body_len], fd, io, arena.allocator());

        // Engine-owned WebSocket promotion: the event loops hand the connection to their own
        // frame pump, this path runs the blocking one. Either way the connection stops being
        // an HTTP request stream from here, so the serve loop ends when the pump returns.
        if (takeWebSocket()) |pending| {
            var ws_out_buf: [WS_OUT_SIZE]u8 = undefined;

            websocket.serveBlocking(pending.fd, pending.on_frame, recv_buf, body_buf, &ws_out_buf);

            return;
        }

        if (!head.keep_alive) return;

        if (head.chunked_request) {
            // Bytes the chunked read pulled past the end of the body: a pipelined
            // request, carried to the front of recv_buf for the next pass. The
            // handler has returned, so overwriting the head bytes is safe now.
            leftover = chunked_leftover;
            if (leftover > 0) {
                @memcpy(recv_buf[0..leftover], body_buf[chunked_leftover_off..][0..leftover]);
            }
        } else if (drained_large) {
            // The whole body was consumed off the socket, and a large body has no
            // pipelined request after it, so nothing is left to carry.
            leftover = 0;
        } else {
            const body_consumed: usize = @intCast(@min(head.content_length, @as(u64, body_buf.len)));
            const request_end = hdr.body_offset + body_consumed;
            if (hdr.filled > request_end) {
                leftover = hdr.filled - request_end;
                std.mem.copyForwards(u8, recv_buf[0..leftover], recv_buf[request_end..hdr.filled]);
            } else {
                leftover = 0;
            }
        }
    }
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http1: buildSimpleHeaderInto writes status, content-type, content-length" {
    var buf: [HEADER_BUF_SIZE]u8 = undefined;
    const len = buildSimpleHeaderInto(&buf, 200, "text/plain", 3);
    const hdr = buf[0..len];
    try std.testing.expect(std.mem.startsWith(u8, hdr, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, hdr, "Content-Length: 3\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, hdr, "\r\n\r\n"));
}

test "zix http1: buildSimpleHeaderInto omits Content-Type when empty" {
    var buf: [HEADER_BUF_SIZE]u8 = undefined;
    const len = buildSimpleHeaderInto(&buf, 204, "", 0);
    const hdr = buf[0..len];
    try std.testing.expect(std.mem.indexOf(u8, hdr, "Content-Type") == null);
    try std.testing.expect(std.mem.indexOf(u8, hdr, "Content-Length: 0\r\n") != null);
}

test "zix http1: buildSimpleHeaderInto baked status line is byte-identical across paths" {
    const saved = tl_send_date;
    tl_send_date = false;
    defer tl_send_date = saved;

    var buf: [HEADER_BUF_SIZE]u8 = undefined;

    // Known code: baked one-copy status line.
    const a = buildSimpleHeaderInto(&buf, 200, "text/plain", 2);
    try std.testing.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n", buf[0..a]);

    // Another known code, non-200.
    const b = buildSimpleHeaderInto(&buf, 404, "text/plain", 9);
    try std.testing.expectEqualStrings("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\n", buf[0..b]);

    // Unknown code: piecewise fallback must match the legacy bytes exactly.
    const c = buildSimpleHeaderInto(&buf, 599, "text/plain", 0);
    try std.testing.expectEqualStrings("HTTP/1.1 599 Unknown\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n", buf[0..c]);
}

test "zix http1: sendSimpleFD builds header directly into active sink without hdr_buf bounce" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var stage: [4096]u8 = undefined;
    var sink = RespSink{ .fd = fds[1], .buf = &stage };
    tl_resp_sink = &sink;
    defer tl_resp_sink = null;

    const before = sink.len;
    try sendSimpleFD(fds[1], 200, "text/plain", "hi");

    // Header was written directly into the sink: len advanced, nothing flushed yet.
    try std.testing.expect(sink.len > before);
    try std.testing.expect(!sink.failed);

    sink.flush();

    var recv: [512]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    const resp = recv[0..n];
    try std.testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, resp, "\r\n\r\nhi"));
}

test "zix http1: RespSink stages writeAllFD bytes until flush" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var stage: [64]u8 = undefined;
    var sink = RespSink{ .fd = fds[1], .buf = &stage };
    tl_resp_sink = &sink;
    defer tl_resp_sink = null;

    try writeAllFD(fds[1], "alpha");
    try writeAllFD(fds[1], "beta");

    // Both writes are staged, nothing has hit the socket yet.
    try std.testing.expectEqual(@as(usize, 9), sink.len);

    sink.flush();
    try std.testing.expect(!sink.failed);

    var recv: [64]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    try std.testing.expectEqualStrings("alphabeta", recv[0..n]);
}

test "zix http1: responseReserve renders in place and responseCommit stages header + body" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var stage: [HEADER_BUF_SIZE + 64]u8 = undefined;
    var sink = RespSink{ .fd = fds[1], .buf = &stage };
    tl_resp_sink = &sink;
    defer tl_resp_sink = null;

    const region = responseReserve(fds[1], 32) orelse return error.ZixReserveUnavailable;
    const body = "{\"ok\":true}";
    @memcpy(region[0..body.len], body);
    try responseCommit(fds[1], 200, "application/json", body.len);

    // The staged region starts at the right-aligned header, ends after the body.
    try std.testing.expect(sink.off > 0);
    try std.testing.expectEqual(HEADER_BUF_SIZE + body.len, sink.len);

    sink.flush();
    try std.testing.expect(!sink.failed);
    try std.testing.expectEqual(@as(usize, 0), sink.off);

    var recv: [512]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    var expect_buf: [HEADER_BUF_SIZE]u8 = undefined;
    const expect_hdr = buildSimpleHeader(&expect_buf, 200, "application/json", body.len);
    try std.testing.expectEqualStrings(expect_hdr, recv[0..expect_hdr.len]);
    try std.testing.expectEqualStrings(body, recv[expect_hdr.len..n]);
}

test "zix http1: responseReserve refuses a sink with staged bytes or a foreign fd" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var stage: [HEADER_BUF_SIZE + 64]u8 = undefined;
    var sink = RespSink{ .fd = 7, .buf = &stage };
    tl_resp_sink = &sink;
    defer tl_resp_sink = null;

    try std.testing.expect(responseReserve(8, 32) == null);

    sink.append("pipelined-first-response");
    try std.testing.expect(responseReserve(7, 32) == null);

    // Oversized reservation on a non-growable sink refuses too.
    sink.len = 0;
    try std.testing.expect(responseReserve(7, stage.len) == null);
}

test "zix http1: sendSimpleFD writes directly into active sink without buf[4096] bounce" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var stage: [4096]u8 = undefined;
    var sink = RespSink{ .fd = fds[1], .buf = &stage };
    tl_resp_sink = &sink;
    defer tl_resp_sink = null;

    try sendSimpleFD(fds[1], 200, "text/plain", "ok");

    // Bytes are staged in the sink, nothing sent to the socket yet.
    try std.testing.expect(sink.len > 0);
    try std.testing.expect(!sink.failed);

    sink.flush();

    var recv: [512]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    const resp = recv[0..n];
    try std.testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, resp, "\r\n\r\nok"));
}

test "zix http1: sendSimpleFD with no active sink writes directly to fd" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    try sendSimpleFD(fds[1], 404, "text/plain", "not found");

    var recv: [512]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    const resp = recv[0..n];
    try std.testing.expect(std.mem.startsWith(u8, resp, "HTTP/1.1 404 Not Found\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, resp, "\r\n\r\nnot found"));
}

test "zix http1: cache API is a no-op when no cache is installed" {
    setCache(null, 0);

    const parsed = try parseHead("GET /x HTTP/1.1\r\n\r\n");

    try std.testing.expect(cacheLookup(&parsed.head) == null);

    // store with no cache installed must not crash
    cacheStore(&parsed.head, "whatever", 1000);
    try std.testing.expect(cacheLookup(&parsed.head) == null);
}

test "zix http1: sendWithCacheFD stores then a later lookup hits with identical bytes" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var rc = try cache.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 256 });
    defer rc.deinit();

    setCache(&rc, 1000);
    defer setCache(null, 0);

    const parsed = try parseHead("GET /thing HTTP/1.1\r\nHost: x\r\n\r\n");
    const head = parsed.head;

    // first request: miss
    try std.testing.expect(cacheLookup(&head) == null);

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    const resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
    try sendWithCacheFD(fds[1], &head, resp, cacheTtl());

    var recv: [128]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    try std.testing.expectEqualStrings(resp, recv[0..n]);

    // second request: hit returns the identical cached bytes
    try std.testing.expectEqualStrings(resp, cacheLookup(&head).?);
}

fn negotiatedRoundtrip(req: []const u8, content_type: []const u8, body: []const u8, out: []u8) !usize {
    const parsed = try parseHead(req);

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    try sendNegotiateCachedFD(fds[1], &parsed.head, 200, content_type, body);

    return std.posix.read(fds[0], out);
}

test "zix http1: sendNegotiateCachedFD compresses when gzip is accepted" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    setCompression(true, 256, GZIP_OUT_SIZE);
    defer setCompression(false, 0, 0);

    var body: [512]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @intCast('a' + (index % 16));

    var recv: [1024]u8 = undefined;
    const n = try negotiatedRoundtrip("GET /x HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n", "text/plain", &body, &recv);
    const resp = recv[0..n];

    try std.testing.expect(std.mem.indexOf(u8, resp, "Content-Encoding: gzip") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "Vary: Accept-Encoding") != null);

    const sep = std.mem.indexOf(u8, resp, "\r\n\r\n").?;
    const restored = try compression.flate.decompressGzipAlloc(std.testing.allocator, resp[sep + 4 ..], 2048);
    defer std.testing.allocator.free(restored);

    try std.testing.expectEqualSlices(u8, &body, restored);
}

test "zix http1: sendNegotiateCachedFD sends uncompressed when compression is off" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    setCompression(false, 0, 0);

    var body: [512]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @intCast('a' + (index % 16));

    var recv: [1024]u8 = undefined;
    const n = try negotiatedRoundtrip("GET /x HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n", "text/plain", &body, &recv);
    const resp = recv[0..n];

    try std.testing.expect(std.mem.indexOf(u8, resp, "Content-Encoding") == null);

    const sep = std.mem.indexOf(u8, resp, "\r\n\r\n").?;
    try std.testing.expectEqualSlices(u8, &body, resp[sep + 4 ..]);
}

test "zix http1: sendNegotiateCachedFD does not compress without Accept-Encoding" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    setCompression(true, 256, GZIP_OUT_SIZE);
    defer setCompression(false, 0, 0);

    var body: [512]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @intCast('a' + (index % 16));

    var recv: [1024]u8 = undefined;
    const n = try negotiatedRoundtrip("GET /x HTTP/1.1\r\n\r\n", "text/plain", &body, &recv);
    const resp = recv[0..n];

    try std.testing.expect(std.mem.indexOf(u8, resp, "Content-Encoding") == null);
}

test "zix http1: sendNegotiateCachedFD skips bodies under the size floor" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    setCompression(true, 256, GZIP_OUT_SIZE);
    defer setCompression(false, 0, 0);

    var recv: [256]u8 = undefined;
    const n = try negotiatedRoundtrip("GET /x HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n", "text/plain", "hi", &recv);
    const resp = recv[0..n];

    try std.testing.expect(std.mem.indexOf(u8, resp, "Content-Encoding") == null);
    try std.testing.expect(std.mem.endsWith(u8, resp, "hi"));
}

test "zix http1: sendNegotiateCachedFD skips already-compressed media types" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    setCompression(true, 256, GZIP_OUT_SIZE);
    defer setCompression(false, 0, 0);

    var body: [512]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @intCast('a' + (index % 16));

    var recv: [1024]u8 = undefined;
    const n = try negotiatedRoundtrip("GET /x HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n", "image/jpeg", &body, &recv);
    const resp = recv[0..n];

    try std.testing.expect(std.mem.indexOf(u8, resp, "Content-Encoding") == null);
}

test "zix http1: cache keys separate distinct paths and queries" {
    var rc = try cache.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 64 });
    defer rc.deinit();

    setCache(&rc, 1000);
    defer setCache(null, 0);

    const a = try parseHead("GET /a HTTP/1.1\r\n\r\n");
    const b = try parseHead("GET /b HTTP/1.1\r\n\r\n");
    const q = try parseHead("GET /a?v=2 HTTP/1.1\r\n\r\n");

    cacheStore(&a.head, "alpha-resp", 1000);

    // a different path and a different query are both misses
    try std.testing.expect(cacheLookup(&b.head) == null);
    try std.testing.expect(cacheLookup(&q.head) == null);
    try std.testing.expectEqualStrings("alpha-resp", cacheLookup(&a.head).?);
}

test "zix http1: RespSink oversized payload writes through in order" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var stage: [8]u8 = undefined;
    var sink = RespSink{ .fd = fds[1], .buf = &stage };
    tl_resp_sink = &sink;
    defer tl_resp_sink = null;

    // "abc" stages, the oversized payload flushes it first then writes
    // through directly, so wire order matches call order.
    try writeAllFD(fds[1], "abc");
    try writeAllFD(fds[1], "0123456789");
    sink.flush();
    try std.testing.expect(!sink.failed);

    var recv: [64]u8 = undefined;
    const n = try std.posix.read(fds[0], &recv);
    try std.testing.expectEqualStrings("abc0123456789", recv[0..n]);
}

test "zix http1: RespSink grows in place instead of flushing when backed by an allocator" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const gpa = std.testing.allocator;

    // 8-byte initial buffer, fd -1 so any accidental flush would error and trip
    // failed: the grow path must never touch the socket.
    const buf = try gpa.alloc(u8, 8);
    var sink = RespSink{ .fd = -1, .buf = buf, .grow_allocator = gpa, .grow_cap = 1024 };
    defer gpa.free(sink.buf);

    sink.append("0123456789ABCDEF");

    // Buffer grew to fit, the bytes are staged, nothing was flushed.
    try std.testing.expect(!sink.failed);
    try std.testing.expect(sink.buf.len >= 16);
    try std.testing.expectEqual(@as(usize, 16), sink.len);
    try std.testing.expectEqualStrings("0123456789ABCDEF", sink.buf[0..sink.len]);
}

test "zix http1: RespSink grow refuses past grow_cap" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const gpa = std.testing.allocator;

    const buf = try gpa.alloc(u8, 8);
    var sink = RespSink{ .fd = -1, .buf = buf, .grow_allocator = gpa, .grow_cap = 32 };
    defer gpa.free(sink.buf);

    // Past the cap: refuses and leaves buf untouched.
    try std.testing.expect(!sink.grow(64));
    try std.testing.expectEqual(@as(usize, 8), sink.buf.len);

    // Within the cap: grows to a power-of-two that covers need, clamped to cap.
    try std.testing.expect(sink.grow(20));
    try std.testing.expect(sink.buf.len >= 20 and sink.buf.len <= 32);
}

test "zix http1: RespSink grow switches a slab-backed buf to a heap buffer" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const gpa = std.testing.allocator;

    // A borrowed (slab-slice) buffer must never be realloc'd: the first grow
    // allocates fresh, copies the staged bytes, and marks the buffer owned.
    var slab_slice: [8]u8 = undefined;
    var sink = RespSink{ .fd = -1, .buf = &slab_slice, .grow_allocator = gpa, .grow_cap = 1024, .buf_owned = false };
    defer if (sink.buf_owned) gpa.free(sink.buf);

    sink.append("01234");
    sink.append("56789ABCDEF");

    try std.testing.expect(!sink.failed);
    try std.testing.expect(sink.buf_owned);
    try std.testing.expect(sink.buf.ptr != @as([*]u8, &slab_slice));
    try std.testing.expectEqualStrings("0123456789ABCDEF", sink.buf[0..sink.len]);
}

test "zix http1: RespSink captures a cache-hit replay zero-copy and materializes it for a batch" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var rc = try cache.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 256 });
    defer rc.deinit();
    setCache(&rc, 60_000);
    defer setCache(null, 1000);

    const key = cache.hashKey("GET", "/hit", "");
    const stored = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expect(rc.store(key, stored, 60_000, 100));
    const cached = rc.lookup(key, 200).?;
    const slot = rc.hitSlot(cached).?;

    var stage: [256]u8 = undefined;
    var sink = RespSink{ .fd = -1, .buf = &stage, .allow_direct = true };
    tl_resp_sink = &sink;
    defer tl_resp_sink = null;

    // First response of the batch is the exact cached slice: borrowed with the
    // slot pinned, nothing copied into the stage buffer.
    try writeAllFD(-1, cached);
    try std.testing.expectEqual(@as(usize, 0), sink.len);
    try std.testing.expectEqual(@intFromPtr(cached.ptr), @intFromPtr(sink.direct.ptr));
    try std.testing.expectEqual(@as(u32, 1), rc.pins[slot]);

    // A second response joins the batch: the borrowed bytes fold back into the
    // stage in request order and the pin drops.
    try writeAllFD(-1, "SECOND");
    try std.testing.expectEqual(@as(usize, 0), sink.direct.len);
    try std.testing.expectEqual(@as(u32, 0), rc.pins[slot]);
    try std.testing.expectEqualStrings(stored ++ "SECOND", sink.buf[0..sink.len]);

    // A plain (non-cache) first write on an empty batch never captures.
    sink.len = 0;
    try writeAllFD(-1, "plain");
    try std.testing.expectEqual(@as(usize, 0), sink.direct.len);
    try std.testing.expectEqualStrings("plain", sink.buf[0..sink.len]);
}

test "zix http1: RespSink without a grow allocator does not grow" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var stage: [8]u8 = undefined;
    var sink = RespSink{ .fd = -1, .buf = &stage };

    // EPOLL path (null allocator): grow is a no-op, so a stack or static buffer
    // is never reallocated and overflow stays on the flush path.
    try std.testing.expect(!sink.grow(64));
    try std.testing.expectEqual(@as(usize, 8), sink.buf.len);
}

/// The sentinel descriptor the https capture path installs: no write ever reaches it, so the spill
/// tests below can run on every target instead of skipping where a descriptor is not an int.
const spill_test_fd: std.posix.fd_t = if (@import("builtin").os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;

/// Test-only spill target standing in for a TLS connection: it records every write it is handed, in
/// order, and can be made to refuse one so the failure path is reachable without a live session.
const SpillCollector = struct {
    buf: [1024]u8 = undefined,
    len: usize = 0,
    writes: usize = 0,
    refuse: bool = false,

    fn write(ctx_ptr: *anyopaque, plaintext: []const u8) bool {
        const self: *SpillCollector = @ptrCast(@alignCast(ctx_ptr));
        self.writes += 1;

        if (self.refuse or self.len + plaintext.len > self.buf.len) return false;

        @memcpy(self.buf[self.len..][0..plaintext.len], plaintext);
        self.len += plaintext.len;

        return true;
    }

    fn collected(self: *const SpillCollector) []const u8 {
        return self.buf[0..self.len];
    }
};

test "zix http1: RespSink spills the staged batch when the next write overflows" {
    var collector = SpillCollector{};
    var stream = TlsStreamSink{ .ctx = &collector, .writeFn = SpillCollector.write };

    var stage: [8]u8 = undefined;
    var sink = RespSink{ .fd = spill_test_fd, .buf = &stage, .spill = &stream };

    sink.append("HEAD");
    try std.testing.expectEqual(@as(usize, 0), collector.writes); // still fits, nothing left yet

    // Cumulative overflow with no grow allocator: the staged batch goes out through the spill and
    // the new bytes take the emptied buffer, instead of the write failing at the buffer's edge.
    sink.append("BODY!");
    try std.testing.expect(!sink.failed);
    try std.testing.expectEqualStrings("HEAD", collector.collected());
    try std.testing.expectEqualStrings("BODY!", stage[sink.off..sink.len]);
}

test "zix http1: RespSink hands the spill sink a payload larger than the whole buffer" {
    var collector = SpillCollector{};
    var stream = TlsStreamSink{ .ctx = &collector, .writeFn = SpillCollector.write };

    var stage: [8]u8 = undefined;
    var sink = RespSink{ .fd = spill_test_fd, .buf = &stage, .spill = &stream };

    // A single write past the buffer can never be staged, so it goes straight through the spill
    // rather than being refused. This is the shape a static file body arrives in.
    sink.append("0123456789ABCDEFGHIJ");

    try std.testing.expect(!sink.failed);
    try std.testing.expectEqual(@as(usize, 0), sink.len);
    try std.testing.expectEqualStrings("0123456789ABCDEFGHIJ", collector.collected());
    try std.testing.expect(stream.wrote);
}

test "zix http1: RespSink spill keeps a response byte-exact and in order across many writes" {
    var collector = SpillCollector{};
    var stream = TlsStreamSink{ .ctx = &collector, .writeFn = SpillCollector.write };

    var stage: [16]u8 = undefined;
    var sink = RespSink{ .fd = spill_test_fd, .buf = &stage, .spill = &stream };

    // Mixed small and oversized writes: what the peer sees is the spilled bytes followed by
    // whatever is still staged, so the two together must rebuild the response exactly.
    const parts = [_][]const u8{ "HTTP/1.1 200 OK\r\n", "Content-Length: 40\r\n", "\r\n", "0123456789", "abcdefghijklmnopqrstuvwxyz", "!!!!" };
    var want: [128]u8 = undefined;
    var want_len: usize = 0;
    for (parts) |part| {
        sink.append(part);
        @memcpy(want[want_len..][0..part.len], part);
        want_len += part.len;
    }

    var seen: [128]u8 = undefined;
    @memcpy(seen[0..collector.len], collector.collected());
    const staged = stage[sink.off..sink.len];
    @memcpy(seen[collector.len..][0..staged.len], staged);

    try std.testing.expect(!sink.failed);
    try std.testing.expectEqualStrings(want[0..want_len], seen[0 .. collector.len + staged.len]);
}

test "zix http1: RespSink leaves the spill untouched for a response that exactly fills the buffer" {
    var collector = SpillCollector{};
    var stream = TlsStreamSink{ .ctx = &collector, .writeFn = SpillCollector.write };

    var stage: [8]u8 = undefined;
    var sink = RespSink{ .fd = spill_test_fd, .buf = &stage, .spill = &stream };

    // Exactly buf.len is the last size that still fits: one byte more is the first that spills.
    sink.append("01234567");

    try std.testing.expectEqual(@as(usize, 0), collector.writes);
    try std.testing.expectEqual(@as(usize, 8), sink.len);
    try std.testing.expect(!stream.wrote);
}

test "zix http1: RespSink flush with nothing staged never calls the spill sink" {
    var collector = SpillCollector{};
    var stream = TlsStreamSink{ .ctx = &collector, .writeFn = SpillCollector.write };

    var stage: [8]u8 = undefined;
    var sink = RespSink{ .fd = spill_test_fd, .buf = &stage, .spill = &stream };

    // An empty flush must not put a record on the wire: a TLS record carrying no bytes still costs
    // a header, a tag, and a sequence number.
    sink.flush();

    try std.testing.expectEqual(@as(usize, 0), collector.writes);
    try std.testing.expect(!sink.failed);
}

test "zix http1: RespSink spill sends the committed header, not the dead prefix before it" {
    var collector = SpillCollector{};
    var stream = TlsStreamSink{ .ctx = &collector, .writeFn = SpillCollector.write };

    var stage: [512]u8 = undefined;
    var sink = RespSink{ .fd = spill_test_fd, .buf = &stage, .spill = &stream };

    // A reserve-committed render right-aligns its header, so the staged region starts at off. The
    // spill must honor that: sending from 0 would put uninitialized bytes on the wire.
    const region = sink.reserve(4).?;
    @memcpy(region, "body");
    sink.commitSimple(200, "text/plain", 4);
    sink.flush();

    try std.testing.expect(!sink.failed);
    try std.testing.expect(std.mem.startsWith(u8, collector.collected(), "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, collector.collected(), "\r\n\r\nbody"));
}

test "zix http1: RespSink spill failure marks the sink failed" {
    var collector = SpillCollector{ .refuse = true };
    var stream = TlsStreamSink{ .ctx = &collector, .writeFn = SpillCollector.write };

    var stage: [8]u8 = undefined;
    var sink = RespSink{ .fd = spill_test_fd, .buf = &stage, .spill = &stream };

    // A dead connection has to surface: writeAllFD turns failed into BrokenPipe, which the serve
    // loop reads as a peer that is gone rather than a response it may keep rendering.
    sink.append("0123456789ABCDEFGHIJ");

    try std.testing.expect(sink.failed);
    try std.testing.expect(stream.failed);
    try std.testing.expect(!stream.wrote);
}

test "zix http1: TlsStreamSink reports whether bytes reached the wire" {
    var collector = SpillCollector{};
    var stream = TlsStreamSink{ .ctx = &collector, .writeFn = SpillCollector.write };

    try std.testing.expect(!stream.wrote);
    try std.testing.expect(stream.write("event: ping\n"));
    try std.testing.expect(stream.wrote);

    // A sink that fails on its first write never wrote, so the caller may still answer a status.
    var refusing = SpillCollector{ .refuse = true };
    var dead = TlsStreamSink{ .ctx = &refusing, .writeFn = SpillCollector.write };

    try std.testing.expect(!dead.write("event: ping\n"));
    try std.testing.expect(!dead.wrote);
    try std.testing.expect(dead.failed);

    // Once failed the sink refuses without calling through, so a broken connection is written to
    // exactly once.
    try std.testing.expect(!dead.write("more"));
    try std.testing.expectEqual(@as(usize, 1), refusing.writes);
}

test "zix http1: sendGzipFD reuses the threadlocal compressor across calls, valid gzip, no leak" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const flate = @import("../../utils/compression/flate.zig");
    const linux = std.os.linux;

    var pipe_fds: [2]i32 = undefined;
    try std.testing.expect(std.posix.errno(linux.pipe2(&pipe_fds, .{})) == .SUCCESS);
    defer _ = linux.close(pipe_fds[0]);
    defer _ = linux.close(pipe_fds[1]);

    // two different bodies back to back: the second must NOT carry state from the first.
    const bodies = [_][]const u8{
        "{\"a\":1,\"b\":2,\"msg\":\"world world world world world\"}",
        "{\"different\":true,\"xs\":[1,2,3,4,5,6,7,8,9,10,11,12]}",
    };

    for (bodies) |body| {
        try sendGzipFD(pipe_fds[1], 200, "application/json", body);

        var resp: [4096]u8 = undefined;
        const n = try std.posix.read(pipe_fds[0], &resp);
        const sep = std.mem.indexOf(u8, resp[0..n], "\r\n\r\n").?;
        const gz = resp[sep + 4 .. n];

        var out: [4096]u8 = undefined;
        const dlen = try flate.decompressGzip(gz, &out);
        try std.testing.expectEqualStrings(body, out[0..dlen]);
    }
}

test "zix http1: buildGzipResponse reserve-prefix bytes equal header plus the facade gzip stream" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    var pipe_fds: [2]i32 = undefined;
    try std.testing.expect(std.posix.errno(linux.pipe2(&pipe_fds, .{})) == .SUCCESS);
    defer _ = linux.close(pipe_fds[0]);
    defer _ = linux.close(pipe_fds[1]);

    const body = "{\"identity\":\"check check check check check check check\"}";

    try sendGzipFD(pipe_fds[1], 200, "application/json", body);

    var resp: [4096]u8 = undefined;
    const n = try std.posix.read(pipe_fds[0], &resp);

    // The reserve-prefix assembly (compress in place, header right-aligned)
    // must be byte-identical to the plain header + gzip-stream concatenation.
    const stream = try compression.encode(std.testing.allocator, .GZIP, body, .DEFAULT);
    defer std.testing.allocator.free(stream);

    var expect_buf: [4096]u8 = undefined;
    const expect_hdr = try std.fmt.bufPrint(
        &expect_buf,
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: {d}\r\n\r\n",
        .{stream.len},
    );
    @memcpy(expect_buf[expect_hdr.len..][0..stream.len], stream);

    try std.testing.expectEqualSlices(u8, expect_buf[0 .. expect_hdr.len + stream.len], resp[0..n]);
}

test "zix http1: sendGzipCachedFD stores per-(key,encoding) and replays the same bytes on a hit" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const flate = @import("../../utils/compression/flate.zig");
    const linux = std.os.linux;

    var rc = try cache.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 4096 });
    defer rc.deinit();
    setCache(&rc, 60_000);
    defer setCache(null, 1000);

    var pipe_fds: [2]i32 = undefined;
    try std.testing.expect(std.posix.errno(linux.pipe2(&pipe_fds, .{})) == .SUCCESS);
    defer _ = linux.close(pipe_fds[0]);
    defer _ = linux.close(pipe_fds[1]);

    const parsed = try parseHead("GET /json HTTP/1.1\r\nHost: x\r\n\r\n");
    const head = parsed.head;
    const body = "{\"msg\":\"hello hello hello hello hello hello hello\"}";

    // miss: compress + store, the response decompresses back to the body.
    try std.testing.expect(cacheLookupEncoded(&head, "gzip") == null);
    try sendGzipCachedFD(pipe_fds[1], &head, 200, "application/json", body, 60_000);
    try std.testing.expect(cacheLookupEncoded(&head, "gzip") != null);

    var resp1: [4096]u8 = undefined;
    const n1 = try std.posix.read(pipe_fds[0], &resp1);
    const sep1 = std.mem.indexOf(u8, resp1[0..n1], "\r\n\r\n").?;
    var out1: [4096]u8 = undefined;
    const d1 = try flate.decompressGzip(resp1[sep1 + 4 .. n1], &out1);
    try std.testing.expectEqualStrings(body, out1[0..d1]);

    // hit: replay the cached response, byte-identical to the first.
    try sendGzipCachedFD(pipe_fds[1], &head, 200, "application/json", body, 60_000);
    var resp2: [4096]u8 = undefined;
    const n2 = try std.posix.read(pipe_fds[0], &resp2);
    try std.testing.expectEqualSlices(u8, resp1[0..n1], resp2[0..n2]);
}

test "zix http1: sendBrotliFD emits Content-Encoding br and decodes back to the body, no leak" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    var pipe_fds: [2]i32 = undefined;
    try std.testing.expect(std.posix.errno(linux.pipe2(&pipe_fds, .{})) == .SUCCESS);
    defer _ = linux.close(pipe_fds[0]);
    defer _ = linux.close(pipe_fds[1]);

    // two different bodies back to back: the arena reset must clear codec state between calls.
    const bodies = [_][]const u8{
        "{\"a\":1,\"b\":2,\"msg\":\"world world world world world\"}",
        "{\"different\":true,\"xs\":[1,2,3,4,5,6,7,8,9,10,11,12]}",
    };

    for (bodies) |body| {
        try sendBrotliFD(pipe_fds[1], 200, "application/json", body);

        var resp: [4096]u8 = undefined;
        const n = try std.posix.read(pipe_fds[0], &resp);
        try std.testing.expect(std.mem.indexOf(u8, resp[0..n], "Content-Encoding: br") != null);

        const sep = std.mem.indexOf(u8, resp[0..n], "\r\n\r\n").?;
        const restored = try compression.decode(std.testing.allocator, .BR, resp[sep + 4 .. n], 4096);
        defer std.testing.allocator.free(restored);

        try std.testing.expectEqualStrings(body, restored);
    }
}

test "zix http1: sendBrotliCachedFD stores under br and replays the same bytes on a hit" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    var rc = try cache.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 4096 });
    defer rc.deinit();
    setCache(&rc, 60_000);
    defer setCache(null, 1000);

    var pipe_fds: [2]i32 = undefined;
    try std.testing.expect(std.posix.errno(linux.pipe2(&pipe_fds, .{})) == .SUCCESS);
    defer _ = linux.close(pipe_fds[0]);
    defer _ = linux.close(pipe_fds[1]);

    const parsed = try parseHead("GET /json HTTP/1.1\r\nHost: x\r\n\r\n");
    const head = parsed.head;
    const body = "{\"msg\":\"hello hello hello hello hello hello hello\"}";

    // miss: compress + store under the br key, the response decodes back to the body.
    try std.testing.expect(cacheLookupEncoded(&head, "br") == null);
    try sendBrotliCachedFD(pipe_fds[1], &head, 200, "application/json", body, 60_000);
    try std.testing.expect(cacheLookupEncoded(&head, "br") != null);

    var resp1: [4096]u8 = undefined;
    const n1 = try std.posix.read(pipe_fds[0], &resp1);
    const sep1 = std.mem.indexOf(u8, resp1[0..n1], "\r\n\r\n").?;
    const restored = try compression.decode(std.testing.allocator, .BR, resp1[sep1 + 4 .. n1], 4096);
    defer std.testing.allocator.free(restored);
    try std.testing.expectEqualStrings(body, restored);

    // hit: replay the cached response, byte-identical to the first.
    try sendBrotliCachedFD(pipe_fds[1], &head, 200, "application/json", body, 60_000);
    var resp2: [4096]u8 = undefined;
    const n2 = try std.posix.read(pipe_fds[0], &resp2);
    try std.testing.expectEqualSlices(u8, resp1[0..n1], resp2[0..n2]);
}

test "zix http1: sendNegotiateFD compresses without touching the cache" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    setCompression(true, 256, GZIP_OUT_SIZE);
    defer setCompression(false, 0, 0);

    var rc = try cache.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 4096 });
    defer rc.deinit();
    setCache(&rc, 60_000);
    defer setCache(null, 1000);

    const linux = std.os.linux;
    var pipe_fds: [2]i32 = undefined;
    try std.testing.expect(std.posix.errno(linux.pipe2(&pipe_fds, .{})) == .SUCCESS);
    defer _ = linux.close(pipe_fds[0]);
    defer _ = linux.close(pipe_fds[1]);

    const parsed = try parseHead("GET /x HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n");
    const head = parsed.head;

    var body: [512]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @intCast('a' + (index % 16));

    try sendNegotiateFD(pipe_fds[1], &head, 200, "text/plain", &body);

    var resp: [1024]u8 = undefined;
    const n = try std.posix.read(pipe_fds[0], &resp);
    try std.testing.expect(std.mem.indexOf(u8, resp[0..n], "Content-Encoding: gzip") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp[0..n], "Vary: Accept-Encoding") != null);

    // uncached: nothing was stored under the negotiated encoding.
    try std.testing.expect(cacheLookupEncoded(&head, "gzip") == null);

    const sep = std.mem.indexOf(u8, resp[0..n], "\r\n\r\n").?;
    const restored = try compression.decode(std.testing.allocator, .GZIP, resp[sep + 4 .. n], 2048);
    defer std.testing.allocator.free(restored);
    try std.testing.expectEqualSlices(u8, &body, restored);
}

test "zix http1: sendNegotiateFD sends uncompressed when no coding is accepted" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    setCompression(true, 256, GZIP_OUT_SIZE);
    defer setCompression(false, 0, 0);

    const linux = std.os.linux;
    var pipe_fds: [2]i32 = undefined;
    try std.testing.expect(std.posix.errno(linux.pipe2(&pipe_fds, .{})) == .SUCCESS);
    defer _ = linux.close(pipe_fds[0]);
    defer _ = linux.close(pipe_fds[1]);

    const parsed = try parseHead("GET /x HTTP/1.1\r\n\r\n");
    const head = parsed.head;

    var body: [512]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @intCast('a' + (index % 16));

    try sendNegotiateFD(pipe_fds[1], &head, 200, "text/plain", &body);

    var resp: [1024]u8 = undefined;
    const n = try std.posix.read(pipe_fds[0], &resp);
    try std.testing.expect(std.mem.indexOf(u8, resp[0..n], "Content-Encoding") == null);

    const sep = std.mem.indexOf(u8, resp[0..n], "\r\n\r\n").?;
    try std.testing.expectEqualSlices(u8, &body, resp[sep + 4 .. n]);
}

test "zix http1: serveConn drains an over-large body so the keep-alive connection survives" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    const Handler = struct {
        fn handle(_: *Request, res: *Response, _: *Context) anyerror!void {
            try res.sendRaw("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    };
    const Srv = struct {
        fn run(fd: std.posix.fd_t) void {
            serveConn(fd, Handler.handle, .{ .large_body_rcvbuf = 1 << 20, .max_recv_buf = 8 * 1024 }, undefined);

            _ = linux.close(fd);
        }
    };
    const t = try std.Thread.spawn(.{}, Srv.run, .{server_fd});
    defer t.join();

    // request 1: a 64 KiB body, well past the 8 KiB receive buffer, so the engine must drain the rest.
    const big: usize = 64 * 1024;
    var head_buf: [128]u8 = undefined;
    const h1 = try std.fmt.bufPrint(&head_buf, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {d}\r\n\r\n", .{big});
    try writeAllFD(client_fd, h1);

    var chunk: [4096]u8 = @splat(0xAB);
    var body_sent: usize = 0;
    while (body_sent < big) {
        const n = @min(chunk.len, big - body_sent);
        try writeAllFD(client_fd, chunk[0..n]);
        body_sent += n;
    }

    var resp1: [256]u8 = undefined;
    const n1 = try std.posix.read(client_fd, &resp1);
    try std.testing.expect(std.mem.indexOf(u8, resp1[0..n1], "200 OK") != null);

    // request 2 on the SAME connection (Connection: close so the server returns after it): served
    // cleanly only if the first body was fully drained, else the leftover bytes misparse as this one.
    try writeAllFD(client_fd, "GET /ping HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");

    var resp2: [256]u8 = undefined;
    const n2 = try std.posix.read(client_fd, &resp2);
    try std.testing.expect(std.mem.indexOf(u8, resp2[0..n2], "200 OK") != null);
}

/// Echo the engine-counted received body size, so a test reads the value the
/// upload contract is built on rather than the Content-Length header.
fn testEchoReceivedHandler(req: *Request, res: *Response, _: *Context) anyerror!void {
    var buf: [24]u8 = undefined;
    const out = std.fmt.bufPrint(&buf, "{d}", .{req.bodyReceived()}) catch return;

    res.setContentType(.TEXT_PLAIN);

    try res.send(out);
}

/// Echo "<received>:<delivered>", the counted body size beside the slice the
/// handler actually got. A handler can only tell a body was cut short when
/// these two disagree.
fn testEchoBodyStatsHandler(req: *Request, res: *Response, _: *Context) anyerror!void {
    const delivered = try req.body();

    var buf: [48]u8 = undefined;
    const out = std.fmt.bufPrint(&buf, "{d}:{d}", .{ req.bodyReceived(), delivered.len }) catch return;

    res.setContentType(.TEXT_PLAIN);

    try res.send(out);
}

/// Echo "<received>:<complete>", so a test can tell an upload that finished from
/// one the peer cut short at the same byte count.
fn testEchoBodyCompleteHandler(req: *Request, res: *Response, _: *Context) anyerror!void {
    var buf: [48]u8 = undefined;
    const out = std.fmt.bufPrint(&buf, "{d}:{s}", .{ req.bodyReceived(), if (req.bodyComplete()) "whole" else "cut" }) catch return;

    res.setContentType(.TEXT_PLAIN);

    try res.send(out);
}

/// Echo the first and last byte of the delivered body, so a test can tell which
/// part of the request the handler was actually handed.
fn testEchoBodyEndsHandler(req: *Request, res: *Response, _: *Context) anyerror!void {
    const delivered = try req.body();
    if (delivered.len == 0) return res.send("empty");

    var buf: [2]u8 = .{ delivered[0], delivered[delivered.len - 1] };

    res.setContentType(.TEXT_PLAIN);

    try res.send(&buf);
}

/// Run serveConn on one end of a socketpair until it returns, then close that
/// end so the client side sees EOF and its read loop terminates.
const TestServeArgs = struct {
    fd: std.posix.fd_t,
    handler: HandlerFn,
    max_recv_buf: usize = 8 * 1024,
    max_request_body: usize = 0,
};

fn testServeConnThread(args: TestServeArgs) void {
    serveConn(args.fd, args.handler, .{ .large_body_rcvbuf = 1 << 20, .max_recv_buf = args.max_recv_buf, .max_request_body = args.max_request_body }, undefined);

    _ = std.os.linux.close(args.fd);
}

fn testTcpSocket() !std.posix.fd_t {
    const rc = std.os.linux.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    if (std.posix.errno(rc) != .SUCCESS) return error.ZixSocketFailed;

    return @intCast(rc);
}

/// Connected loopback TCP pair, returned as {client, server}.
///
/// Note:
/// - The drain discards with MSG.TRUNC, which the kernel honours on a TCP
///   socket only. An AF.UNIX socketpair ignores it and copies instead, and the
///   drain asks for far more than any scratch buffer holds, so every drain test
///   needs a real TCP pair.
/// - The guard below is what keeps the body off every other target: a comptime
///   true early return makes the rest of the function dead, so the std.os.linux
///   calls are never analyzed there. It names a real error rather than a skip,
///   because a helper that returns a pair cannot report a skip without handing
///   the caller two descriptors it never opened. Every caller guards the
///   platform first, so the error is unreachable at runtime.
pub fn testTcpPair() ![2]std.posix.fd_t {
    if (comptime @import("builtin").target.os.tag != .linux) return error.ZixTcpPairNeedsLinux;

    const linux = std.os.linux;

    const listener = try testTcpSocket();
    defer _ = linux.close(listener);

    var addr = std.posix.sockaddr.in{
        .port = 0,
        .addr = std.mem.nativeToBig(u32, 0x7F000001),
    };
    var addr_len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.in);
    if (std.posix.errno(linux.bind(listener, @ptrCast(&addr), addr_len)) != .SUCCESS) return error.ZixBindFailed;
    if (std.posix.errno(linux.listen(listener, 1)) != .SUCCESS) return error.ZixListenFailed;
    if (std.posix.errno(linux.getsockname(listener, @ptrCast(&addr), &addr_len)) != .SUCCESS) return error.ZixSockNameFailed;

    const client = try testTcpSocket();
    errdefer _ = linux.close(client);
    if (std.posix.errno(linux.connect(client, @ptrCast(&addr), addr_len)) != .SUCCESS) return error.ZixConnectFailed;

    const accepted = linux.accept4(listener, null, null, 0);
    if (std.posix.errno(accepted) != .SUCCESS) return error.ZixAcceptFailed;

    return .{ client, @intCast(accepted) };
}

/// Drain one socketpair end to EOF. The peer half-closed before the server
/// thread started, so the server always reaches the end of its serve loop and
/// closes, which bounds this read without a timeout.
fn testReadToEof(fd: std.posix.fd_t, buf: []u8) usize {
    var len: usize = 0;
    while (len < buf.len) {
        const n = std.posix.read(fd, buf[len..]) catch break;
        if (n == 0) break;
        len += n;
    }

    return len;
}

test "zix http1: ASYNC serveConn reports a fitting body through bodyReceived" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    var pair: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.posix.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    const body_len: usize = 64;
    var head_buf: [128]u8 = undefined;
    const head = try std.fmt.bufPrint(&head_buf, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {d}\r\n\r\n", .{body_len});
    try writeAllFD(client_fd, head);
    var body: [body_len]u8 = @splat('x');
    try writeAllFD(client_fd, &body);

    // Half-close before the server starts: every request byte is already
    // buffered, so the serve loop runs to completion and then sees EOF.
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoReceivedHandler }});
    defer thread.join();

    var resp: [512]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, resp[0..len], "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, resp[0..len], "\r\n\r\n64"));
}

test "zix http1: ASYNC serveConn reports the full received size when the body outgrows the async chunk" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    // A 64 KiB body against an 8 KiB receive buffer. The delivered slice is
    // capped by design, but the count must stay the bytes the engine consumed,
    // the way .URING reports it. When both read 8192 the handler has no way to
    // tell a 64 KiB upload from an 8 KiB one.
    const big: usize = 64 * 1024;
    var head_buf: [128]u8 = undefined;
    const head = try std.fmt.bufPrint(&head_buf, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {d}\r\n\r\n", .{big});
    try writeAllFD(client_fd, head);

    var chunk: [4096]u8 = @splat('A');
    var sent: usize = 0;
    while (sent < big) {
        const n = @min(chunk.len, big - sent);
        try writeAllFD(client_fd, chunk[0..n]);
        sent += n;
    }
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoBodyStatsHandler }});
    defer thread.join();

    var resp: [512]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expect(std.mem.endsWith(u8, resp[0..len], "\r\n\r\n65536:8192"));
}

test "zix http1: ASYNC serveConn delivers the start of an over-large body, not drain leftovers" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    // First 8 KiB of the body is 'A', the rest is 'B'. The delivered slice is
    // capped at the receive buffer, so it must be the 'A' region. The drain loop
    // reuses the same body_buf, so anything else means the handler is reading
    // bytes the drain wrote over the body after it was collected.
    const head_bytes: usize = 8 * 1024;
    const tail_bytes: usize = 56 * 1024;
    const big = head_bytes + tail_bytes;

    var head_buf: [128]u8 = undefined;
    const head = try std.fmt.bufPrint(&head_buf, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {d}\r\n\r\n", .{big});
    try writeAllFD(client_fd, head);

    var a_chunk: [4096]u8 = @splat('A');
    var sent: usize = 0;
    while (sent < head_bytes) {
        const n = @min(a_chunk.len, head_bytes - sent);
        try writeAllFD(client_fd, a_chunk[0..n]);
        sent += n;
    }

    var b_chunk: [4096]u8 = @splat('B');
    sent = 0;
    while (sent < tail_bytes) {
        const n = @min(b_chunk.len, tail_bytes - sent);
        try writeAllFD(client_fd, b_chunk[0..n]);
        sent += n;
    }
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoBodyEndsHandler }});
    defer thread.join();

    var resp: [512]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expect(std.mem.endsWith(u8, resp[0..len], "\r\n\r\nAA"));
}

test "zix http1: ASYNC serveConn drains an over-large body so the pipelined request survives" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    // A 64 KiB body against an 8 KiB receive buffer: the handler sees the
    // capped count, and the remainder has to leave the socket so the pipelined
    // GET behind it still parses as a request.
    const big: usize = 64 * 1024;
    var head_buf: [128]u8 = undefined;
    const head = try std.fmt.bufPrint(&head_buf, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {d}\r\n\r\n", .{big});
    try writeAllFD(client_fd, head);

    var chunk: [4096]u8 = @splat('A');
    var sent: usize = 0;
    while (sent < big) {
        const n = @min(chunk.len, big - sent);
        try writeAllFD(client_fd, chunk[0..n]);
        sent += n;
    }
    try writeAllFD(client_fd, "GET /ping HTTP/1.1\r\nHost: x\r\n\r\n");
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoReceivedHandler }});
    defer thread.join();

    var resp: [1024]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, resp[0..len], "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, resp[0..len], "\r\n\r\n0"));
}

test "zix http1: ASYNC serveConn drain stops at the body end when the head fills the receive buffer" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    // A padded head leaves under a full buffer of body in the receive
    // buffer, so the body-fill loop must read the shortfall off the socket.
    // Those bytes are already consumed, so the drain that follows owes only
    // what is left. Reading the full content_length minus the peek instead
    // over-consumes and eats the pipelined GET.
    const pad_len: usize = 12 * 1024;
    var pad: [pad_len]u8 = @splat('P');

    const big: usize = 64 * 1024;
    var head_buf: [128]u8 = undefined;
    const head_start = try std.fmt.bufPrint(&head_buf, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Length: {d}\r\nX-Pad: ", .{big});
    try writeAllFD(client_fd, head_start);
    try writeAllFD(client_fd, &pad);
    try writeAllFD(client_fd, "\r\n\r\n");

    var chunk: [4096]u8 = @splat('A');
    var sent: usize = 0;
    while (sent < big) {
        const n = @min(chunk.len, big - sent);
        try writeAllFD(client_fd, chunk[0..n]);
        sent += n;
    }
    try writeAllFD(client_fd, "GET /ping HTTP/1.1\r\nHost: x\r\n\r\n");
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoReceivedHandler, .max_recv_buf = BUF_SIZE }});
    defer thread.join();

    var resp: [1024]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, resp[0..len], "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, resp[0..len], "\r\n\r\n0"));
}

test "zix http1: chunkedFrame reports the body length once the terminator arrived" {
    const raw = "5\r\nhello\r\n0\r\n\r\n";
    const frame = chunkedFrame(raw, 64);
    try std.testing.expectEqual(ChunkedStop.COMPLETE, frame.stop);
    try std.testing.expectEqual(@as(usize, 5), frame.len);
    try std.testing.expectEqual(raw.len, frame.consumed);
}

test "zix http1: chunkedFrame asks for more while the body is still arriving" {
    try std.testing.expectEqual(ChunkedStop.NEED_MORE, chunkedFrame("5\r\nhel", 64).stop);
    try std.testing.expectEqual(ChunkedStop.NEED_MORE, chunkedFrame("5\r\nhello\r\n", 64).stop);
    try std.testing.expectEqual(ChunkedStop.NEED_MORE, chunkedFrame("5\r\nhello\r\n0\r\n", 64).stop);
}

test "zix http1: chunkedFrame separates malformed and too-large from unfinished" {
    // All three used to answer null, so a caller could only wait. Only the first
    // of these can ever be resolved by waiting.
    try std.testing.expectEqual(ChunkedStop.NEED_MORE, chunkedFrame("5\r\nhel", 64).stop);
    try std.testing.expectEqual(ChunkedStop.MALFORMED, chunkedFrame("zz\r\nabc\r\n0\r\n\r\n", 64).stop);
    const oversized: [64]u8 = @splat('A');
    const raw = "40\r\n".* ++ oversized ++ "\r\n0\r\n\r\n".*;
    try std.testing.expectEqual(ChunkedStop.TOO_LARGE, chunkedFrame(raw[0..], 8).stop);
}

test "zix http1: chunkedFrame steps over data that spells the terminator" {
    const raw = "5\r\n0\r\n\r\n\r\n0\r\n\r\n";
    const frame = chunkedFrame(raw, 64);
    try std.testing.expectEqual(ChunkedStop.COMPLETE, frame.stop);
    try std.testing.expectEqual(raw.len, frame.consumed);
}

test "zix http1: chunkedFrame stops at the request pipelined behind the terminator" {
    const body = "3\r\nabc\r\n0\r\n\r\n";
    const frame = chunkedFrame(body ++ "GET /next HTTP/1.1\r\n\r\n", 64);
    try std.testing.expectEqual(ChunkedStop.COMPLETE, frame.stop);
    try std.testing.expectEqual(body.len, frame.consumed);
}

test "zix http1: decodeChunkedInBuf decodes over its own source buffer" {
    // Source and destination overlap here, which is what @memcpy may not do.
    const filler: [32]u8 = @splat('A');
    var raw = "20\r\n".* ++ filler ++ "\r\n0\r\n\r\n".*;

    const decoded = decodeChunkedInBuf(&raw, &raw);
    try std.testing.expectEqual(ChunkedStop.COMPLETE, decoded.stop);
    try std.testing.expectEqualStrings(&filler, raw[0..decoded.len]);
}

test "zix http1: decodeChunkedInBuf leaves the source untouched when the body is unfinished" {
    const source = "5\r\nhello\r\n3\r\nab";
    var raw = source.*;
    var out: [64]u8 = undefined;
    const decoded = decodeChunkedInBuf(&raw, &out);
    try std.testing.expectEqual(ChunkedStop.NEED_MORE, decoded.stop);
    try std.testing.expectEqualStrings(source, &raw);
}

test "zix http1: ASYNC serveConn answers 413 for a chunked body past the receive buffer" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    // The decoded body is far past what the engine can hand a handler. Cutting it
    // down would give the handler a fragment it cannot tell from a whole body, so
    // the request is refused instead.
    const chunk: usize = 16 * 1024;
    var head_buf: [128]u8 = undefined;
    const head = try std.fmt.bufPrint(&head_buf, "POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n{x}\r\n", .{chunk});
    try writeAllFD(client_fd, head);
    var payload: [chunk]u8 = @splat('A');
    try writeAllFD(client_fd, &payload);
    try writeAllFD(client_fd, "\r\n0\r\n\r\n");
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoBodyStatsHandler, .max_recv_buf = 4096 }});
    defer thread.join();

    var resp: [1024]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expect(std.mem.startsWith(u8, resp[0..len], "HTTP/1.1 413 "));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, resp[0..len], "HTTP/1.1 200 OK\r\n"));
}

test "zix http1: ASYNC serveConn answers the request pipelined behind a chunked body" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    // The GET arrives in the same segment as the chunked body. The chunked read
    // takes it off the socket, so it has to be carried forward. Dropping it left
    // the client waiting on a response to a request the server had already read.
    const request = "POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n" ++
        "GET /ping HTTP/1.1\r\nHost: x\r\n\r\n";
    try writeAllFD(client_fd, request);
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoBodyStatsHandler, .max_recv_buf = 4096 }});
    defer thread.join();

    var resp: [1024]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, resp[0..len], "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, resp[0..len], "\r\n\r\n15:5") != null);
    try std.testing.expect(std.mem.endsWith(u8, resp[0..len], "\r\n\r\n0:0"));
}

test "zix http1: ASYNC serveConn answers 400 and closes on a malformed chunked body" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    // A chunk size that is not hex. The body can no longer be framed, so where
    // the next request starts is unknowable. Serving the connection on would
    // parse the undecodable remainder as a request.
    const request = "POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nhello\r\n0\r\n\r\n" ++
        "GET /ping HTTP/1.1\r\nHost: x\r\n\r\n";
    try writeAllFD(client_fd, request);
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoBodyStatsHandler, .max_recv_buf = 4096 }});
    defer thread.join();

    var resp: [1024]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expect(std.mem.startsWith(u8, resp[0..len], "HTTP/1.1 400 "));
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, resp[0..len], "HTTP/1.1 200 OK\r\n"));
}

test "zix http1: ASYNC serveConn delivers a chunked body that arrives after the head" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    const head = "POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
    try writeAllFD(client_fd, head);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoBodyStatsHandler, .max_recv_buf = 4096 }});
    defer thread.join();

    // The body follows in its own segments, the shape a streaming client sends.
    try writeAllFD(client_fd, "5\r\nhello\r\n");
    try writeAllFD(client_fd, "6\r\n world\r\n");
    try writeAllFD(client_fd, "0\r\n\r\n");
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    var resp: [1024]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, resp[0..len], "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, resp[0..len], "\r\n\r\n26:11"));
}

test "zix http1: ASYNC serveConn refuses a declared body past the limit with 413" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    // The declared length alone is enough to refuse. Without a limit the engine
    // reads or discards every byte a client cares to claim, which costs a worker
    // for as long as the client keeps sending.
    const head = "POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 65536\r\n\r\n";
    try writeAllFD(client_fd, head);
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoReceivedHandler, .max_request_body = 1024 }});
    defer thread.join();

    var resp: [512]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expectStringStartsWith(resp[0..len], "HTTP/1.1 413 ");
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, resp[0..len], "HTTP/1.1 200 OK\r\n"));
}

test "zix http1: ASYNC serveConn serves a declared body inside the limit" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    const request = "POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nabcd";
    try writeAllFD(client_fd, request);
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoReceivedHandler, .max_request_body = 1024 }});
    defer thread.join();

    var resp: [512]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, resp[0..len], "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, resp[0..len], "\r\n\r\n4"));
}

test "zix http1: ASYNC serveConn sends 100 Continue before a body that expects it" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    var pair: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.posix.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    const request = "POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\nabcd";
    try writeAllFD(client_fd, request);
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoReceivedHandler }});
    defer thread.join();

    var resp: [512]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    // The interim response comes first, then the real one on the same connection.
    try std.testing.expect(std.mem.startsWith(u8, resp[0..len], "HTTP/1.1 100 Continue\r\n\r\n"));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, resp[0..len], "HTTP/1.1 200 OK\r\n"));
}

test "zix http1: ASYNC serveConn marks a body the peer cut short as incomplete" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    // 64 declared, 10 sent, then the peer goes away. The handler still runs, and
    // without this flag a 10-byte upload and a 64-byte upload that died at byte
    // 10 look identical to it.
    const head = "POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 64\r\n\r\n";
    try writeAllFD(client_fd, head);
    try writeAllFD(client_fd, "0123456789");
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoBodyCompleteHandler }});
    defer thread.join();

    var resp: [512]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expect(std.mem.endsWith(u8, resp[0..len], "\r\n\r\n10:cut"));
}

test "zix http1: ASYNC serveConn marks a body that arrived in full as complete" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    const request = "POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n0123456789";
    try writeAllFD(client_fd, request);
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoBodyCompleteHandler }});
    defer thread.join();

    var resp: [512]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expect(std.mem.endsWith(u8, resp[0..len], "\r\n\r\n10:whole"));
}

test "zix http1: ASYNC serveConn marks a drained over-large body as complete" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    const pair = try testTcpPair();
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    // Past the receive buffer, so the handler is given a short slice. That is a
    // delivery cap, not a truncated upload, and the two must not read the same.
    const big: usize = 64 * 1024;
    var head_buf: [128]u8 = undefined;
    const head = try std.fmt.bufPrint(&head_buf, "POST /u HTTP/1.1\r\nHost: x\r\nContent-Length: {d}\r\n\r\n", .{big});
    try writeAllFD(client_fd, head);
    var body: [big]u8 = @splat('A');
    try writeAllFD(client_fd, &body);
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoBodyCompleteHandler }});
    defer thread.join();

    var resp: [4096]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    try std.testing.expect(std.mem.endsWith(u8, resp[0..len], "\r\n\r\n65536:whole"));
}

test "zix http1: ASYNC serveConn marks a bodyless request as complete" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    var pair: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.posix.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    try writeAllFD(client_fd, "GET /ping HTTP/1.1\r\nHost: x\r\n\r\n");
    _ = linux.shutdown(client_fd, linux.SHUT.WR);

    const thread = try std.Thread.spawn(.{}, testServeConnThread, .{TestServeArgs{ .fd = server_fd, .handler = testEchoBodyCompleteHandler }});
    defer thread.join();

    var resp: [512]u8 = undefined;
    const len = testReadToEof(client_fd, &resp);

    // Nothing to fall short of, so there is no measurement to hand over and the
    // request keeps the defaults.
    try std.testing.expect(std.mem.endsWith(u8, resp[0..len], "\r\n\r\n0:whole"));
}

test "zix http1: uringWatchFd routes through the installed trampoline" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    try std.testing.expect(!uringWatchFd(7));

    const Fake = struct {
        var seen: std.posix.fd_t = -1;
        fn watch(ctx: *anyopaque, fd: std.posix.fd_t) bool {
            _ = ctx;
            seen = fd;

            return true;
        }
    };

    var ctx_dummy: u8 = 0;
    tl_uring_watch = &Fake.watch;
    tl_uring_watch_ctx = &ctx_dummy;
    defer {
        tl_uring_watch = null;
        tl_uring_watch_ctx = null;
    }

    try std.testing.expect(uringWatchFd(7));
    try std.testing.expectEqual(@as(std.posix.fd_t, 7), Fake.seen);
}

test "zix http1: a served request writes one access record naming the engine" {
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

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const head = parser.ParsedHead{
        .method = "GET",
        .path = "/orders/42",
        .query = "",
        .raw_headers = "x-forwarded-for: 203.0.113.7\r\nuser-agent: curl/8.5.0\r\n",
        .version_minor = 1,
        .keep_alive = true,
        .content_length = 0,
        .chunked_request = false,
        .expect_continue = false,
    };

    invokeHandler(accessProbeHandler, &head, "", fds[1], std.testing.io, arena.allocator());
    logger.flush();

    const line = try readLoggedLine(tmp.dir, std.testing.allocator);
    defer std.testing.allocator.free(line);

    std.log.info(".ACCESS: {s}", .{std.mem.trimEnd(u8, line, "\n")});

    try std.testing.expect(std.mem.indexOf(u8, line, "[http1:access] GET /orders/42 201 5 \"203.0.113.7\" \"curl/8.5.0\" \"-\"") != null);
}

test "zix http1: a served request writes no access record when no logger is attached" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    setAccessLogger(null);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const head = parser.ParsedHead{
        .method = "GET",
        .path = "/",
        .query = "",
        .raw_headers = "",
        .version_minor = 1,
        .keep_alive = true,
        .content_length = 0,
        .chunked_request = false,
        .expect_continue = false,
    };

    // The point is that it does not reach for a logger it does not have.
    invokeHandler(accessProbeHandler, &head, "", fds[1], std.testing.io, arena.allocator());
}

fn accessProbeHandler(req: *Request, res: *Response, ctx: *Context) !void {
    _ = req;
    _ = ctx;

    res.setStatus(.CREATED);
    try res.send("hello");
}

// --------------------------------------------------------- //
// Handler-error completion: one answer per request, whichever way the handler answered

/// Answers through the fd writers, then returns an error. The engine must leave it alone.
fn fdThenErrorHandler(req: *Request, res: *Response, ctx: *Context) !void {
    _ = res;
    _ = ctx;

    try sendSimpleFD(req.fd, 200, "text/plain", "fd answered");

    return error.ZixProbeFailure;
}

/// Answers through the Response builder, then returns an error. The engine must leave it alone.
fn responseThenErrorHandler(req: *Request, res: *Response, ctx: *Context) !void {
    _ = req;
    _ = ctx;

    try res.send("res answered");

    return error.ZixProbeFailure;
}

/// Returns an error having answered nothing. The engine owes this request a 500.
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
        // wire broke and the assertion below would be reading a truncated response.
        return error.ZixProbeFailure;
    };
}

/// Drive one handler over a socketpair and hand back everything the peer end received.
fn wireOf(handler_fn: HandlerFn, buf: []u8) ![]u8 {
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const head = parser.ParsedHead{
        .method = "GET",
        .path = "/probe",
        .query = "",
        .raw_headers = "",
        .version_minor = 1,
        .keep_alive = true,
        .content_length = 0,
        .chunked_request = false,
        .expect_continue = false,
    };

    invokeHandler(handler_fn, &head, "", fds[1], std.testing.io, arena.allocator());

    // Closed before the read so the peer sees EOF rather than blocking on a live socket.
    _ = std.os.linux.close(fds[1]);

    const n = std.posix.read(fds[0], buf) catch 0;

    return buf[0..n];
}

test "zix http1: an fd answer followed by a handler error is not answered a second time" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socketpair, test skipped", .{});
        return;
    }

    var buf: [1024]u8 = undefined;
    const wire = try wireOf(fdThenErrorHandler, &buf);

    std.log.info(".WIRE: {d} bytes, {d} status lines", .{ wire.len, std.mem.count(u8, wire, "HTTP/1.1 ") });

    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire, "HTTP/1.1 "));
    try std.testing.expect(std.mem.indexOf(u8, wire, "HTTP/1.1 200 OK") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire, "500") == null);
}

test "zix http1: a Response answer followed by a handler error is not answered a second time" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socketpair, test skipped", .{});
        return;
    }

    var buf: [1024]u8 = undefined;
    const wire = try wireOf(responseThenErrorHandler, &buf);

    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire, "HTTP/1.1 "));
    try std.testing.expect(std.mem.indexOf(u8, wire, "res answered") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire, "500") == null);
}

test "zix http1: a handler error with nothing answered is completed as one 500" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socketpair, test skipped", .{});
        return;
    }

    var buf: [1024]u8 = undefined;
    const wire = try wireOf(errorBeforeAnswerHandler, &buf);

    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire, "HTTP/1.1 "));
    try std.testing.expect(std.mem.indexOf(u8, wire, "HTTP/1.1 500 Internal Server Error") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire, "Internal Server Error") != null);
}

test "zix http1: an error the handler swallows itself gets nothing from the engine" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socketpair, test skipped", .{});
        return;
    }

    var buf: [1024]u8 = undefined;
    const wire = try wireOf(swallowedErrorHandler, &buf);

    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, wire, "HTTP/1.1 "));
    try std.testing.expect(std.mem.indexOf(u8, wire, "swallowed") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire, "500") == null);
}

/// Read back the one log file written under a temp root, for the access tests above.
fn readLoggedLine(root: std.Io.Dir, allocator: std.mem.Allocator) ![]u8 {
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
