//! zix http response

const std = @import("std");
const socket_pair = @import("../../utils/socket_pair.zig");
const fd_io = @import("../../utils/fd_io.zig");
const builtin = @import("builtin");
const win_io = @import("../../utils/windows_io.zig");
const Status = @import("status.zig");
const Content = @import("content.zig");
const Request = @import("request.zig").Request;
const rc = @import("../../utils/response_cache.zig");
const compression = @import("../../utils/compression/compression.zig");

/// Fast-path fixed response-header staging buffer. The 454 overhead estimate uses the same size.
const FIXED_HEADER_BUF: usize = 512;
/// SSE response header staging buffer.
const SSE_HEADER_BUF: usize = 256;
/// Per extra-header staging buffer.
const EXTRA_HEADER_BUF: usize = 256;
/// Slow-path response-header staging buffer (caps total fixed plus extra header bytes).
const SLOW_HEADER_BUF: usize = 2048;

// --------------------------------------------------------- //

pub const HttpHeader = struct {
    name: []const u8,
    value: []const u8,
};

/// Controls how many custom response headers addHeader() will accept per request.
///
/// max_response_headers in HttpServerConfig sets the cap. The backing buffer is
/// arena-allocated lazily on the first addHeader() call, requests that add no
/// custom headers pay zero allocation cost.
/// Any addHeader() call beyond the cap yields error.ZixTooManyHeaders.
///
/// - MINIMAL (16): simple APIs, constrained environments
/// - COMMON (32): most web applications, single proxy/load balancer (default)
/// - LARGE (64): behind load balancers, CDN + proxy
/// - EXTRA_LARGE (128): k8s, service mesh, many CORS/caching/forwarding headers
/// - CUSTOM (N): explicit non-standard cap
///
/// See docs/headers.md for security guidance and tier selection.
pub const HeaderSize = union(enum) {
    MINIMAL,
    COMMON,
    LARGE,
    EXTRA_LARGE,
    CUSTOM: usize,

    pub fn value(self: HeaderSize) usize {
        return switch (self) {
            .MINIMAL => 16,
            .COMMON => 32,
            .LARGE => 64,
            .EXTRA_LARGE => 128,
            .CUSTOM => |n| n,
        };
    }
};

/// Writer handle returned by Response.sendStream() for SSE (Server-Sent Events).
/// Writes directly to the raw socket fd, no buffering, no flush needed.
pub const SseWriter = struct {
    fd: std.posix.fd_t,

    /// Sends: data: <data>\n\n
    pub fn writeEvent(self: SseWriter, data: []const u8) !void {
        try writeAllFD(self.fd, "data: ");
        try writeAllFD(self.fd, data);
        try writeAllFD(self.fd, "\n\n");
    }

    /// Sends: event: <event>\ndata: <data>\n\n
    pub fn writeNamedEvent(self: SseWriter, event: []const u8, data: []const u8) !void {
        try writeAllFD(self.fd, "event: ");
        try writeAllFD(self.fd, event);
        try writeAllFD(self.fd, "\ndata: ");
        try writeAllFD(self.fd, data);
        try writeAllFD(self.fd, "\n\n");
    }

    /// Sends: : <text>\n  (comment / keepalive heartbeat)
    pub fn comment(self: SseWriter, text: []const u8) !void {
        try writeAllFD(self.fd, ": ");
        try writeAllFD(self.fd, text);
        try writeAllFD(self.fd, "\n");
    }
};

pub const Response = struct {
    /// Raw socket fd: all writes go here directly via posix.write().
    fd: std.posix.fd_t,
    /// keep_alive from the parsed request head (Connection: close = false).
    req_keep_alive: bool,
    io: std.Io,
    allocator: std.mem.Allocator,
    status: Status.Code = .OK,
    content_type: ?Content.Type = null,
    keep_alive: ?bool = null,
    extra_buf: ?[]HttpHeader = null,
    extra_len: usize = 0,
    max_headers: usize,
    date_cache: ?[]const u8 = null,
    /// Set to true by sendStream() so handleConnection breaks the keep-alive loop after the handler exits.
    streaming: bool = false,
    /// Body bytes set by send(). Read by the server to populate the access log.
    bytes_written: usize = 0,
    /// Set once any send lands, so the engine writes a 500 only when a failed
    /// handler produced no response at all.
    sent: bool = false,

    pub fn init(fd: std.posix.fd_t, req_keep_alive: bool, io: std.Io, allocator: std.mem.Allocator, max_headers: usize) Response {
        return .{
            .fd = fd,
            .req_keep_alive = req_keep_alive,
            .io = io,
            .allocator = allocator,
            .max_headers = max_headers,
        };
    }

    pub fn setStatus(self: *Response, status: Status.Code) void {
        self.status = status;
    }

    pub fn setContentType(self: *Response, ct: Content.Type) void {
        self.content_type = ct;
    }

    pub fn setKeepAlive(self: *Response, keep_alive: bool) void {
        self.keep_alive = keep_alive;
    }

    /// Append a custom header to the response.
    /// Allocates the full header buffer on the first call (lazy, capacity = max_headers).
    ///
    /// Return:
    /// - error.ZixTooManyHeaders if the header cap is exceeded
    /// - error.ZixInvalidHeaderName or error.ZixInvalidHeaderValue on CR/LF injection
    pub fn addHeader(self: *Response, name: []const u8, value: []const u8) !void {
        for (name) |c| if (c == '\r' or c == '\n') return error.ZixInvalidHeaderName;
        for (value) |c| if (c == '\r' or c == '\n') return error.ZixInvalidHeaderValue;
        if (self.extra_buf == null) {
            if (self.max_headers == 0) return error.ZixTooManyHeaders;
            self.extra_buf = try self.allocator.alloc(HttpHeader, self.max_headers);
        }
        if (self.extra_len >= self.extra_buf.?.len) return error.ZixTooManyHeaders;
        self.extra_buf.?[self.extra_len] = .{ .name = name, .value = value };
        self.extra_len += 1;
    }

    /// Write and flush the HTTP response with the given body.
    /// Sink path (.EPOLL/.URING): serialize straight into the sink's free space, no copy.
    /// Fast path (no extra headers, body fits in staging buffer): one posix.write() syscall.
    /// Slow path (extra headers or large body): fixed headers + extra headers + body.
    pub fn send(self: *Response, body_data: []const u8) !void {
        self.bytes_written = body_data.len;
        self.sent = true;

        // Sink path: when a coalescing sink is installed (.EPOLL/.URING), serialize
        // the response directly into the sink's free space. This is byte-identical to
        // the staging-buffer path (buildResponse is what the cache serializes too) and
        // skips the stack buffer plus the copy that writeAllFD -> RespSink.append makes.
        if (tl_resp_sink) |sink| {
            if (sink.fd == self.fd and !sink.failed) {
                if (self.buildResponse(body_data, sink.buf[sink.len..])) |written| {
                    sink.len += written;

                    return;
                }
            }
        }

        const fd = self.fd;
        const date_value = self.date_cache orelse "";

        // Stage fixed headers into a 512-byte stack buffer.
        var fixed: [FIXED_HEADER_BUF]u8 = undefined;
        var offset: usize = 0;

        const status_line = Status.statusLine(self.status);
        if (status_line.len > 0) {
            @memcpy(fixed[offset..][0..status_line.len], status_line);
            offset += status_line.len;
        } else {
            const status_str = Status.stringFromEnum(self.status);
            const s = try std.fmt.bufPrint(fixed[offset..], "HTTP/1.1 {d} {s}\r\n", .{ @intFromEnum(self.status), status_str });
            offset += s.len;
        }

        const skip_body_headers = self.status == .NO_CONTENT;
        if (!skip_body_headers) {
            if (self.content_type) |ct| {
                const ct_str = ct.asString();
                const ct_prefix = "Content-Type: ";
                if (offset + ct_prefix.len + ct_str.len + 2 > fixed.len) return error.ZixBufferTooSmall;

                @memcpy(fixed[offset..][0..ct_prefix.len], ct_prefix);
                offset += ct_prefix.len;
                @memcpy(fixed[offset..][0..ct_str.len], ct_str);
                offset += ct_str.len;
                fixed[offset] = '\r';
                fixed[offset + 1] = '\n';
                offset += 2;
            }
            const cl_prefix = "Content-Length: ";
            if (offset + cl_prefix.len + 22 > fixed.len) return error.ZixBufferTooSmall;
            @memcpy(fixed[offset..][0..cl_prefix.len], cl_prefix);
            offset += cl_prefix.len;
            offset += writeDecimal(fixed[offset..], body_data.len);
            fixed[offset] = '\r';
            fixed[offset + 1] = '\n';
            offset += 2;
        }
        if (self.keep_alive) |keep_alive| {
            const conn: []const u8 = if (keep_alive and self.req_keep_alive)
                "Connection: keep-alive\r\n"
            else
                "Connection: close\r\n";
            if (offset + conn.len > fixed.len) return error.ZixBufferTooSmall;
            @memcpy(fixed[offset..][0..conn.len], conn);
            offset += conn.len;
        }
        if (date_value.len > 0) {
            const date_prefix = "Date: ";
            if (offset + date_prefix.len + date_value.len + 2 > fixed.len) return error.ZixBufferTooSmall;

            @memcpy(fixed[offset..][0..date_prefix.len], date_prefix);
            offset += date_prefix.len;
            @memcpy(fixed[offset..][0..date_value.len], date_value);
            offset += date_value.len;
            fixed[offset] = '\r';
            fixed[offset + 1] = '\n';
            offset += 2;
        }

        // Fast path: no extra headers AND body fits in the remaining buffer, one write().
        if (self.extra_len == 0 and offset + 2 + body_data.len <= fixed.len) {
            fixed[offset] = '\r';
            fixed[offset + 1] = '\n';
            offset += 2;
            if (body_data.len > 0) {
                @memcpy(fixed[offset..][0..body_data.len], body_data);
                offset += body_data.len;
            }
            writeAllFD(fd, fixed[0..offset]) catch return;
            return;
        }

        // Slow path: extra headers present or body too large for the stack buffer.
        // Stage fixed headers + extra headers into a secondary buffer, then write body.
        var slow: [SLOW_HEADER_BUF]u8 = undefined;
        var slow_off: usize = 0;
        @memcpy(slow[0..offset], fixed[0..offset]);
        slow_off = offset;

        if (self.extra_buf) |extra| {
            for (extra[0..self.extra_len]) |h| {
                const s = std.fmt.bufPrint(slow[slow_off..], "{s}: {s}\r\n", .{ h.name, h.value }) catch {
                    // Extra header too large for staging buffer, write what we have and continue.
                    writeAllFD(fd, slow[0..slow_off]) catch return;
                    slow_off = 0;
                    const header_str = std.fmt.bufPrint(&slow, "{s}: {s}\r\n", .{ h.name, h.value }) catch continue;
                    writeAllFD(fd, header_str) catch return;
                    continue;
                };
                slow_off += s.len;
            }
        }
        slow[slow_off] = '\r';
        slow[slow_off + 1] = '\n';
        slow_off += 2;

        if (slow_off + body_data.len <= slow.len) {
            // Body fits in the staging buffer, one write().
            @memcpy(slow[slow_off..][0..body_data.len], body_data);
            slow_off += body_data.len;
            writeAllFD(fd, slow[0..slow_off]) catch return;
        } else {
            writeAllFD(fd, slow[0..slow_off]) catch return;
            if (body_data.len > 0) writeAllFD(fd, body_data) catch return;
        }
    }

    pub fn sendJson(self: *Response, body_data: []const u8) !void {
        self.content_type = .APPLICATION_JSON;
        return self.send(body_data);
    }

    /// Send body as text/plain.
    pub fn sendText(self: *Response, body_data: []const u8) !void {
        self.content_type = .TEXT_PLAIN;
        return self.send(body_data);
    }

    /// Write caller-owned bytes verbatim, a full response the handler built
    /// itself. Routes through the coalescing sink and the TLS stream sink like
    /// every other write.
    ///
    /// Param:
    /// bytes - []const u8 (the exact wire bytes to send)
    ///
    /// Return:
    /// - !void (propagates the writer error, e.g. error.BrokenPipe)
    pub fn sendRaw(self: *Response, bytes: []const u8) !void {
        self.bytes_written = bytes.len;
        self.sent = true;

        return writeAllFD(self.fd, bytes);
    }

    /// Begin an SSE (Server-Sent Events) stream and return an SseWriter.
    /// Sends HTTP 200 with Content-Type: text/event-stream (no Content-Length).
    /// Sets res.streaming = true so handleConnection closes after the handler exits.
    /// Requires workers = 1 (Model 1). Long-lived SSE connections exhaust a blocking pool (Model 2).
    pub fn sendStream(self: *Response) !SseWriter {
        // SSE draining is handler-side: a blocking write parks the handler itself,
        // so detach any coalescing sink. Each event must flush to the fd directly
        // rather than buffer into the .EPOLL/.URING response sink (which only
        // flushes after the handler returns, but an SSE handler never returns).
        //
        // Over TLS (ADR-054) the live-session stream sink is armed: drop the buffered capture (its
        // bytes are replaced by the stream, so it is discarded not flushed to the -1 sentinel) and
        // let writeAllFD route each event through the stream sink, encrypting one record per write.
        if (tl_tls_stream != null) {
            tl_resp_sink = null;
        } else if (tl_resp_sink) |sink| {
            sink.flush();
            tl_resp_sink = null;
        }

        const fd = self.fd;
        const date_value = self.date_cache orelse "";

        var fixed: [SSE_HEADER_BUF]u8 = undefined;
        var offset: usize = 0;
        const sse_hdr = "HTTP/1.1 200 Ok\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n";
        @memcpy(fixed[0..sse_hdr.len], sse_hdr);
        offset += sse_hdr.len;
        if (date_value.len > 0) {
            if (std.fmt.bufPrint(fixed[offset..], "Date: {s}\r\n", .{date_value})) |written| {
                offset += written.len;
            } else |_| {}
        }
        writeAllFD(fd, fixed[0..offset]) catch return error.BrokenPipe;

        if (self.extra_buf) |extra| {
            for (extra[0..self.extra_len]) |h| {
                var hbuf: [EXTRA_HEADER_BUF]u8 = undefined;
                const s = std.fmt.bufPrint(&hbuf, "{s}: {s}\r\n", .{ h.name, h.value }) catch continue;
                writeAllFD(fd, s) catch return error.BrokenPipe;
            }
        }
        writeAllFD(fd, "\r\n") catch return error.BrokenPipe;

        self.streaming = true;
        self.sent = true;
        return SseWriter{ .fd = fd };
    }

    /// Send a 204 No Content response with an empty body.
    pub fn sendNoContent(self: *Response) !void {
        self.status = .NO_CONTENT;
        return self.send("");
    }

    /// Serialize the full HTTP response (status line, headers, body) into out,
    /// in the same byte order as send(). The result is suitable for both writing
    /// and caching verbatim.
    ///
    /// Return:
    /// - ?usize (total bytes written into out, null when out is too small)
    fn buildResponse(self: *Response, body_data: []const u8, out: []u8) ?usize {
        const date_value = self.date_cache orelse "";
        var offset: usize = 0;

        const status_line = Status.statusLine(self.status);
        if (status_line.len > 0) {
            if (offset + status_line.len > out.len) return null;
            @memcpy(out[offset..][0..status_line.len], status_line);
            offset += status_line.len;
        } else {
            const status_str = Status.stringFromEnum(self.status);
            const s = std.fmt.bufPrint(out[offset..], "HTTP/1.1 {d} {s}\r\n", .{ @intFromEnum(self.status), status_str }) catch return null;
            offset += s.len;
        }

        const skip_body_headers = self.status == .NO_CONTENT;
        if (!skip_body_headers) {
            if (self.content_type) |ct| {
                const ct_str = ct.asString();
                const ct_prefix = "Content-Type: ";
                if (offset + ct_prefix.len + ct_str.len + 2 > out.len) return null;

                @memcpy(out[offset..][0..ct_prefix.len], ct_prefix);
                offset += ct_prefix.len;
                @memcpy(out[offset..][0..ct_str.len], ct_str);
                offset += ct_str.len;
                out[offset] = '\r';
                out[offset + 1] = '\n';
                offset += 2;
            }

            const cl_prefix = "Content-Length: ";
            if (offset + cl_prefix.len + 22 > out.len) return null;
            @memcpy(out[offset..][0..cl_prefix.len], cl_prefix);
            offset += cl_prefix.len;
            offset += writeDecimal(out[offset..], body_data.len);
            out[offset] = '\r';
            out[offset + 1] = '\n';
            offset += 2;
        }

        if (self.keep_alive) |keep_alive| {
            const conn: []const u8 = if (keep_alive and self.req_keep_alive)
                "Connection: keep-alive\r\n"
            else
                "Connection: close\r\n";
            if (offset + conn.len > out.len) return null;
            @memcpy(out[offset..][0..conn.len], conn);
            offset += conn.len;
        }

        if (date_value.len > 0) {
            const date_prefix = "Date: ";
            if (offset + date_prefix.len + date_value.len + 2 > out.len) return null;

            @memcpy(out[offset..][0..date_prefix.len], date_prefix);
            offset += date_prefix.len;
            @memcpy(out[offset..][0..date_value.len], date_value);
            offset += date_value.len;
            out[offset] = '\r';
            out[offset + 1] = '\n';
            offset += 2;
        }

        if (self.extra_buf) |extra| {
            for (extra[0..self.extra_len]) |h| {
                const s = std.fmt.bufPrint(out[offset..], "{s}: {s}\r\n", .{ h.name, h.value }) catch return null;
                offset += s.len;
            }
        }

        if (offset + 2 + body_data.len > out.len) return null;
        out[offset] = '\r';
        out[offset + 1] = '\n';
        offset += 2;

        if (body_data.len > 0) {
            @memcpy(out[offset..][0..body_data.len], body_data);
            offset += body_data.len;
        }

        return offset;
    }

    /// Look up a cached full response for req and, on a fresh hit, write it
    /// verbatim with no re-serialization. A miss, an expired entry, or no cache
    /// installed on this worker returns false.
    ///
    /// Usage:
    /// ```zig
    /// if (res.sendFromCache(&req)) return;
    /// const body = buildExpensiveBody(...);
    /// try res.sendCached(&req, body, 0);
    /// ```
    ///
    /// Return:
    /// - bool (true when served from cache, the handler should return)
    pub fn sendFromCache(self: *Response, req: *const Request) bool {
        const cache = tl_cache orelse return false;
        const bytes = cache.lookup(requestKey(req), rc.nowMillis()) orelse return false;

        self.bytes_written = bytes.len;
        self.sent = true;
        writeAllFD(self.fd, bytes) catch return true;

        return true;
    }

    /// Serialize the response once, write it, and store it under the request key
    /// for later sendFromCache hits. ttl_ms of 0 uses the worker default (cacheTtl).
    /// Falls back to a plain send when no cache is installed, the request is a
    /// QUERY, or the serialized response exceeds the per-slot cap.
    ///
    /// Param:
    /// req - *const Request (source of the cache key: method, path, query)
    /// body_data - []const u8 (response body)
    /// ttl_ms - u32 (freshness in milliseconds, 0 means the worker default)
    ///
    /// Return:
    /// - !void
    pub fn sendCached(self: *Response, req: *const Request, body_data: []const u8, ttl_ms: u32) !void {
        const cache = tl_cache orelse return self.send(body_data);
        if (!storableUnderRequestKey(req)) return self.send(body_data);

        var extra_bytes: usize = 0;
        if (self.extra_buf) |extra| {
            for (extra[0..self.extra_len]) |h| extra_bytes += h.name.len + h.value.len + 4;
        }

        const total = FIXED_HEADER_BUF + extra_bytes + body_data.len;
        const buf = self.allocator.alloc(u8, total) catch return self.send(body_data);

        const len = self.buildResponse(body_data, buf) orelse return self.send(body_data);
        self.bytes_written = body_data.len;
        self.sent = true;

        const ttl = if (ttl_ms == 0) tl_cache_ttl_ms else ttl_ms;
        _ = cache.store(requestKey(req), buf[0..len], ttl, rc.nowMillis());

        return writeAllFD(self.fd, buf[0..len]);
    }

    /// Send body_data with Accept-Encoding negotiation. Compresses only when the
    /// worker has compression enabled, the client accepts a producible coding, the
    /// body clears the size floor and is not an already-compressed media type, and the
    /// compressed result is both smaller than the original and within the cap. In every
    /// other case the body is sent uncompressed, identical to send().
    ///
    /// Note:
    /// - Opt-in like sendCached: the handler passes the request for its Accept-Encoding.
    /// - The compressed path sets Content-Encoding and Vary: Accept-Encoding, then
    ///   reuses send() so Content-Length and the rest of the header block stay correct.
    /// - Does not touch the cache. Caching the compressed bytes per (key, encoding) is
    ///   a separate slice, since the cache key does not yet include the coding.
    ///
    /// Param:
    /// req - *const Request (for the Accept-Encoding header)
    /// body_data - []const u8 (uncompressed body)
    ///
    /// Return:
    /// - void
    /// - propagates send() and addHeader errors
    pub fn sendNegotiated(self: *Response, req: *const Request, body_data: []const u8) !void {
        if (!tl_compression) return self.send(body_data);

        const accept = req.header("accept-encoding");
        const encoding = compression.negotiate(accept, &compression.supported_default) orelse {
            self.setStatus(.NOT_ACCEPTABLE);

            return self.send("");
        };

        const content_type = if (self.content_type) |ct| ct.asString() else "";
        if (encoding == .IDENTITY or !compression.shouldCompress(body_data.len, content_type, tl_compression_min_size)) {
            return self.send(body_data);
        }

        const encoded = compression.encode(std.heap.smp_allocator, encoding, body_data, .DEFAULT) catch {
            return self.send(body_data);
        };
        defer std.heap.smp_allocator.free(encoded);

        if (encoded.len > tl_compression_max_out or encoded.len >= body_data.len) {
            return self.send(body_data);
        }

        try self.addHeader("Content-Encoding", encoding.contentEncoding().?);
        try self.addHeader("Vary", "Accept-Encoding");

        return self.send(encoded);
    }
};

// --------------------------------------------------------- //

/// Per-worker response cache installed by the EPOLL / URING worker. Null on workers
/// without a cache, so the Response cache API degrades to a plain send.
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

/// Whether response compression is enabled for this worker. Off unless the server
/// installs it from config.compress, in which case sendNegotiated sends uncompressed.
pub threadlocal var tl_compression: bool = false;

/// Body size floor for compression, installed from config.compression_min_size.
pub threadlocal var tl_compression_min_size: usize = compression.min_size_default;

/// Compressed-output cap, installed from config.compression_max_out. A compressed
/// result above this is discarded and the response is sent uncompressed.
pub threadlocal var tl_compression_max_out: usize = 256 * 1024;

/// Install (or clear) the compression policy for this worker.
pub fn setCompression(enabled: bool, min_size: usize, max_out: usize) void {
    tl_compression = enabled;
    tl_compression_min_size = min_size;
    tl_compression_max_out = max_out;
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
/// err - anyerror (from parser.parse)
///
/// Return:
/// - []const u8 (a complete response, ready to write)
pub fn parseErrorResponse(err: anyerror) []const u8 {
    return switch (err) {
        error.ZixUnknownMethod => "HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\n\r\n",
        else => "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n",
    };
}

/// Cache key for a request: method name, path, and query string.
fn requestKey(req: *const Request) u64 {
    return rc.hashKey(@tagName(req.method()), req.path(), req.query());
}

/// Whether a response to this request may be stored under its request key
///
/// Note:
/// - requestKey carries no request content. Two QUERY requests to one path with
///   different bodies would therefore share a key, and one query's answer could
///   be served for another
/// - RFC 10008 section 2.7 requires a cache key that incorporates the request
///   content, and makes caching a QUERY response a MAY. Refusing to store is
///   the conformant answer for a key this shape
/// - Only the store path checks this. Nothing is ever written under a QUERY
///   key, so sendFromCache cannot hit one and stays untouched
///
/// Param:
/// req - *const Request
///
/// Return:
/// - bool
fn storableUnderRequestKey(req: *const Request) bool {
    return req.method() != .QUERY;
}

// --------------------------------------------------------- //

/// Raw write: loops until all bytes are written or an error occurs.
/// Uses posix.system.write directly, no std.Io.Writer dispatch on the hot path.
///
/// Return:
/// - error.BrokenPipe on any write failure (caller ignores or propagates)
pub fn writeAllFD(fd: std.posix.fd_t, data: []const u8) error{BrokenPipe}!void {
    if (tl_resp_sink) |sink| {
        sink.append(data);

        return if (sink.failed) error.BrokenPipe else {};
    }

    // Streaming https path (ADR-054): no buffered capture is installed, so each write encrypts one
    // TLS record and sends it. Reached only after res.sendStream() detaches the capture sink over TLS.
    if (tl_tls_stream) |strm| {
        return if (strm.write(data)) {} else error.BrokenPipe;
    }

    return rawFdWrite(fd, data);
}

/// Flush response bytes still staged for fd. A caller that writes the socket directly (sendfile)
/// must call this first, so the wire order matches the order the responses were produced. No-op
/// when no sink is installed or nothing is staged.
pub fn flushPending(fd: std.posix.fd_t) void {
    if (tl_resp_sink) |sink| {
        if (sink.fd == fd) sink.flush();
    }
}

/// Direct socket write, bypassing the .URING coalescing sink. Used by the sink
/// itself (to avoid recursion) and by every non-ring dispatch model.
fn rawFdWrite(fd: std.posix.fd_t, data: []const u8) error{BrokenPipe}!void {
    if (comptime builtin.os.tag == .windows) return win_io.writeAll(fd, data);

    var remaining = data;
    while (remaining.len > 0) {
        const write_result = std.posix.system.write(fd, remaining.ptr, remaining.len);
        switch (std.posix.errno(write_result)) {
            .SUCCESS => {
                const n: usize = @intCast(write_result);
                if (n == 0) return error.BrokenPipe;
                remaining = remaining[n..];
            },
            .INTR => continue,
            else => return error.BrokenPipe,
        }
    }
}

/// Write as much of data to fd as possible without parking the worker.
/// Used by the .EPOLL response flush: a partial write (send buffer full) returns
/// the byte count written so far, and the worker stages the unwritten tail to
/// drain on the next EPOLLOUT event instead of dropping the connection.
///
/// Return:
/// - usize (bytes written so far, may be less than data.len on EAGAIN)
/// - null on a permanent write error
pub fn writeNonBlockFD(fd: std.posix.fd_t, data: []const u8) ?usize {
    if (comptime builtin.os.tag == .windows) {
        // Windows path is blocking (ntdll wait-on-handle): a full send buffer
        // stalls the write instead of staging, no partial count to report.
        win_io.writeAll(fd, data) catch return null;
        return data.len;
    }

    var written: usize = 0;
    while (written < data.len) {
        const write_result = std.posix.system.write(fd, data[written..].ptr, data.len - written);
        switch (std.posix.errno(write_result)) {
            .SUCCESS => {
                const n: usize = @intCast(write_result);
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

/// Coalescing sink for the .URING ring path (ADR-037 Phase 4 step 4). While
/// installed (tl_resp_sink), writeAllFD stages into buf instead of writing to the
/// fd, so a whole response coalesces into one ring send. An oversize write flushes
/// straight to the fd, which is safe under the ring's half-duplex guarantee (no
/// send is in flight while a handler runs).
pub const RespSink = struct {
    fd: std.posix.fd_t,
    buf: []u8,
    len: usize = 0,
    failed: bool = false,

    pub fn append(self: *RespSink, bytes: []const u8) void {
        if (bytes.len > self.buf.len) {
            self.flush();
            rawFdWrite(self.fd, bytes) catch {
                self.failed = true;
            };

            return;
        }

        if (self.len + bytes.len > self.buf.len) self.flush();

        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    pub fn flush(self: *RespSink) void {
        if (self.len == 0) return;

        rawFdWrite(self.fd, self.buf[0..self.len]) catch {
            self.failed = true;
        };
        self.len = 0;
    }
};

/// Active response sink for the current worker thread (the .URING ring path).
/// null for every other dispatch model, so writeAllFD writes straight to the fd.
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

    pub fn write(self: *TlsStreamSink, bytes: []const u8) bool {
        if (self.failed) return false;

        if (!self.writeFn(self.ctx, bytes)) {
            self.failed = true;

            return false;
        }

        return true;
    }
};

/// Active streaming sink for the current worker thread (the thread-per-conn https path). null for
/// cleartext and the buffered https path, so writeAllFD never routes through it there.
pub threadlocal var tl_tls_stream: ?*TlsStreamSink = null;

// --------------------------------------------------------- //

/// Hand-rolled usize -> decimal writer for Content-Length in the hot path.
fn writeDecimal(buf: []u8, n: usize) usize {
    if (n == 0) {
        buf[0] = '0';
        return 1;
    }
    var tmp: [20]u8 = undefined;
    var i: usize = 0;
    var x = n;
    while (x > 0) : (x /= 10) {
        tmp[i] = @intCast('0' + (x % 10));
        i += 1;
    }
    var j: usize = 0;
    while (i > 0) {
        i -= 1;
        buf[j] = tmp[i];
        j += 1;
    }
    return j;
}

// --------------------------------------------------------- //

pub fn formatHttpDate(secs: u64, buf: []u8) []u8 {
    const epoch = std.time.epoch;
    const epoch_sec = epoch.EpochSeconds{ .secs = secs };
    const epoch_day = epoch_sec.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch_sec.getDaySeconds();

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

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// A connected pair for the tests below, portable across every supported platform.
fn socketPair(fds: *[2]std.posix.fd_t) !void {
    const pair = try socket_pair.Pair.open(std.testing.allocator);
    fds.* = pair.fds;
}

/// Test fd sentinel: Windows descriptors are opaque pointers, POSIX are ints.
const TEST_FD: std.posix.fd_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;

test "zix http: response setters" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var res = Response.init(TEST_FD, true, undefined, arena.allocator(), 32);

    res.setStatus(.CREATED);
    try std.testing.expectEqual(Status.Code.CREATED, res.status);

    res.setContentType(.APPLICATION_JSON);
    try std.testing.expectEqual(Content.Type.APPLICATION_JSON, res.content_type.?);

    res.setKeepAlive(false);
    try std.testing.expectEqual(@as(?bool, false), res.keep_alive);

    try res.addHeader("X-Test", "Value");
    try std.testing.expectEqual(@as(usize, 1), res.extra_len);
    try std.testing.expectEqualStrings("X-Test", res.extra_buf.?[0].name);
    try std.testing.expectEqualStrings("Value", res.extra_buf.?[0].value);
}

test "zix http: HeaderSize value()" {
    const minimal: HeaderSize = .MINIMAL;
    const common: HeaderSize = .COMMON;
    const large: HeaderSize = .LARGE;
    const xl: HeaderSize = .EXTRA_LARGE;
    try std.testing.expectEqual(@as(usize, 16), minimal.value());
    try std.testing.expectEqual(@as(usize, 32), common.value());
    try std.testing.expectEqual(@as(usize, 64), large.value());
    try std.testing.expectEqual(@as(usize, 128), xl.value());
    try std.testing.expectEqual(@as(usize, 48), (HeaderSize{ .CUSTOM = 48 }).value());
}

test "zix http: addHeader injection guard" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var res = Response.init(TEST_FD, true, undefined, arena.allocator(), 32);
    try std.testing.expectError(error.ZixInvalidHeaderName, res.addHeader("X-Bad\r\nInject", "val"));
    try std.testing.expectError(error.ZixInvalidHeaderValue, res.addHeader("X-Good", "val\r\nInject"));
}

test "zix http: addHeader TooManyHeaders" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var res = Response.init(TEST_FD, true, undefined, arena.allocator(), 2);
    try res.addHeader("X-A", "1");
    try res.addHeader("X-B", "2");
    try std.testing.expectError(error.ZixTooManyHeaders, res.addHeader("X-C", "3"));
}

test "zix http: Response.streaming defaults to false" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const res = Response.init(TEST_FD, true, undefined, arena.allocator(), 32);
    try std.testing.expect(!res.streaming);
}

test "zix http: writeDecimal" {
    var buf: [24]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 1), writeDecimal(&buf, 0));
    try std.testing.expectEqualStrings("0", buf[0..1]);
    try std.testing.expectEqual(@as(usize, 1), writeDecimal(&buf, 7));
    try std.testing.expectEqualStrings("7", buf[0..1]);
    try std.testing.expectEqual(@as(usize, 3), writeDecimal(&buf, 456));
    try std.testing.expectEqualStrings("456", buf[0..3]);
    try std.testing.expectEqual(@as(usize, 4), writeDecimal(&buf, 1024));
    try std.testing.expectEqualStrings("1024", buf[0..4]);
    try std.testing.expectEqual(@as(usize, 10), writeDecimal(&buf, 4294967295));
    try std.testing.expectEqualStrings("4294967295", buf[0..10]);
}

test "zix http: formatHttpDate known timestamps" {
    var buf: [40]u8 = undefined;
    try std.testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", formatHttpDate(0, &buf));
    try std.testing.expectEqualStrings("Sat, 03 Jan 1970 00:00:00 GMT", formatHttpDate(2 * 86400, &buf));
    try std.testing.expectEqualStrings("Thu, 01 Jan 1970 01:01:01 GMT", formatHttpDate(3661, &buf));
    try std.testing.expectEqualStrings("Mon, 28 Feb 2000 12:30:45 GMT", formatHttpDate(951_741_045, &buf));
}

test "zix http response cache: sendFromCache is a no-op when no cache is installed" {
    setCache(null, 0);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var req = try Request.fromRaw("GET /x HTTP/1.1\r\nHost: x\r\n\r\n", arena.allocator());
    var res = Response.init(TEST_FD, true, undefined, arena.allocator(), 16);

    try std.testing.expect(!res.sendFromCache(&req));
}

test "zix http response cache: sendCached stores then sendFromCache writes identical bytes" {
    var cache = try rc.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 512 });
    defer cache.deinit();

    setCache(&cache, 1000);
    defer setCache(null, 0);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var req = try Request.fromRaw("GET /thing HTTP/1.1\r\nHost: x\r\n\r\n", arena.allocator());

    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    // first request: miss, then build + store + write
    var res = Response.init(fds[1], true, undefined, arena.allocator(), 16);
    try std.testing.expect(!res.sendFromCache(&req));
    try res.sendCached(&req, "hello", 0);

    var first: [256]u8 = undefined;
    const n1 = try fd_io.readOnce(fds[0], &first);
    try std.testing.expect(std.mem.endsWith(u8, first[0..n1], "\r\n\r\nhello"));

    // second request: hit returns the identical cached bytes
    var res2 = Response.init(fds[1], true, undefined, arena.allocator(), 16);
    try std.testing.expect(res2.sendFromCache(&req));

    var second: [256]u8 = undefined;
    const n2 = try fd_io.readOnce(fds[0], &second);
    try std.testing.expectEqualStrings(first[0..n1], second[0..n2]);
}

test "zix http response cache: a QUERY response is never stored under the request key" {
    var cache = try rc.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 512 });
    defer cache.deinit();

    setCache(&cache, 1000);
    defer setCache(null, 0);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // The request key is hash(method, path, query) and carries no content. Storing
    // this would let its answer serve a later QUERY to /search asking something else.
    var req = try Request.fromRaw(
        "QUERY /search HTTP/1.1\r\nHost: x\r\nContent-Type: application/sql\r\nContent-Length: 14\r\n\r\nSELECT 1 AS a;",
        arena.allocator(),
    );

    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var res = Response.init(fds[1], true, undefined, arena.allocator(), 16);
    try std.testing.expect(!res.sendFromCache(&req));
    try res.sendCached(&req, "one", 0);

    // The body still reaches the peer, the store is what was skipped.
    var first: [256]u8 = undefined;
    const n1 = try fd_io.readOnce(fds[0], &first);
    try std.testing.expect(std.mem.endsWith(u8, first[0..n1], "\r\n\r\none"));

    var res2 = Response.init(fds[1], true, undefined, arena.allocator(), 16);
    try std.testing.expect(!res2.sendFromCache(&req));
}

test "zix http response cache: refusing QUERY leaves GET on the same path cacheable" {
    var cache = try rc.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 512 });
    defer cache.deinit();

    setCache(&cache, 1000);
    defer setCache(null, 0);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var query_req = try Request.fromRaw("QUERY /search HTTP/1.1\r\nHost: x\r\n\r\n", arena.allocator());
    var get_req = try Request.fromRaw("GET /search HTTP/1.1\r\nHost: x\r\n\r\n", arena.allocator());

    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var query_res = Response.init(fds[1], true, undefined, arena.allocator(), 16);
    try query_res.sendCached(&query_req, "from-query", 0);

    var drain: [256]u8 = undefined;
    _ = try fd_io.readOnce(fds[0], &drain);

    // The GET stores and hits as it always did, so the refusal is scoped to QUERY
    // rather than disabling the cache for the path.
    var get_res = Response.init(fds[1], true, undefined, arena.allocator(), 16);
    try std.testing.expect(!get_res.sendFromCache(&get_req));
    try get_res.sendCached(&get_req, "from-get", 0);
    _ = try fd_io.readOnce(fds[0], &drain);

    var get_res2 = Response.init(fds[1], true, undefined, arena.allocator(), 16);
    try std.testing.expect(get_res2.sendFromCache(&get_req));

    var hit: [256]u8 = undefined;
    const hit_len = try fd_io.readOnce(fds[0], &hit);
    try std.testing.expect(std.mem.endsWith(u8, hit[0..hit_len], "\r\n\r\nfrom-get"));
}

fn negotiatedHttpRoundtrip(raw_req: []const u8, ct: Content.Type, body: []const u8, arena: std.mem.Allocator, out: []u8) !usize {
    var req = try Request.fromRaw(raw_req, arena);

    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var res = Response.init(fds[1], true, undefined, arena, 16);
    res.setContentType(ct);
    try res.sendNegotiated(&req, body);

    return fd_io.readOnce(fds[0], out);
}

test "zix http response: sendNegotiated compresses when gzip is accepted" {
    setCompression(true, 256, 256 * 1024);
    defer setCompression(false, 0, 0);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var body: [512]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @intCast('a' + (index % 16));

    var recv: [1024]u8 = undefined;
    const n = try negotiatedHttpRoundtrip("GET /x HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n", .TEXT_PLAIN, &body, arena.allocator(), &recv);
    const resp = recv[0..n];

    try std.testing.expect(std.mem.indexOf(u8, resp, "Content-Encoding: gzip") != null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "Vary: Accept-Encoding") != null);

    const sep = std.mem.indexOf(u8, resp, "\r\n\r\n").?;
    const restored = try compression.flate.decompressGzipAlloc(std.testing.allocator, resp[sep + 4 ..], 2048);
    defer std.testing.allocator.free(restored);

    try std.testing.expectEqualSlices(u8, &body, restored);
}

test "zix http response: sendNegotiated sends uncompressed when compression is off" {
    setCompression(false, 0, 0);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var body: [512]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @intCast('a' + (index % 16));

    var recv: [1024]u8 = undefined;
    const n = try negotiatedHttpRoundtrip("GET /x HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n", .TEXT_PLAIN, &body, arena.allocator(), &recv);

    try std.testing.expect(std.mem.indexOf(u8, recv[0..n], "Content-Encoding") == null);
}

test "zix http response: sendNegotiated skips bodies under the floor" {
    setCompression(true, 256, 256 * 1024);
    defer setCompression(false, 0, 0);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var recv: [256]u8 = undefined;
    const n = try negotiatedHttpRoundtrip("GET /x HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n", .TEXT_PLAIN, "hi", arena.allocator(), &recv);

    try std.testing.expect(std.mem.indexOf(u8, recv[0..n], "Content-Encoding") == null);
}

test "zix http response: sendNegotiated skips already-compressed media types" {
    setCompression(true, 256, 256 * 1024);
    defer setCompression(false, 0, 0);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var body: [512]u8 = undefined;
    for (&body, 0..) |*byte, index| byte.* = @intCast('a' + (index % 16));

    var recv: [1024]u8 = undefined;
    const n = try negotiatedHttpRoundtrip("GET /x HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n", .IMAGE_JPEG, &body, arena.allocator(), &recv);

    try std.testing.expect(std.mem.indexOf(u8, recv[0..n], "Content-Encoding") == null);
}

test "zix http response cache: cached bytes match a plain send" {
    var cache = try rc.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 512 });
    defer cache.deinit();

    setCache(&cache, 1000);
    defer setCache(null, 0);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var req = try Request.fromRaw("GET /thing HTTP/1.1\r\nHost: x\r\n\r\n", arena.allocator());

    var pair_a: [2]std.posix.fd_t = undefined;
    var pair_b: [2]std.posix.fd_t = undefined;
    try socketPair(&pair_a);
    try socketPair(&pair_b);
    defer for ([_]std.posix.fd_t{ pair_a[0], pair_a[1], pair_b[0], pair_b[1] }) |fd| {
        fd_io.close(fd);
    };

    // plain send
    var res_plain = Response.init(pair_a[1], true, undefined, arena.allocator(), 16);
    res_plain.setContentType(.APPLICATION_JSON);
    try res_plain.send("{\"ok\":true}");

    var plain: [256]u8 = undefined;
    const np = try fd_io.readOnce(pair_a[0], &plain);

    // cached send with the same response shape
    var res_cached = Response.init(pair_b[1], true, undefined, arena.allocator(), 16);
    res_cached.setContentType(.APPLICATION_JSON);
    try res_cached.sendCached(&req, "{\"ok\":true}", 0);

    var cached: [256]u8 = undefined;
    const nc = try fd_io.readOnce(pair_b[0], &cached);

    try std.testing.expectEqualStrings(plain[0..np], cached[0..nc]);
}

test "zix http response cache: sendCached without a cache falls back to a plain send" {
    setCache(null, 0);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var req = try Request.fromRaw("GET /x HTTP/1.1\r\nHost: x\r\n\r\n", arena.allocator());

    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var res = Response.init(fds[1], true, undefined, arena.allocator(), 16);
    try res.sendCached(&req, "data", 0);

    var recv: [128]u8 = undefined;
    const n = try fd_io.readOnce(fds[0], &recv);
    try std.testing.expect(std.mem.startsWith(u8, recv[0..n], "HTTP/1.1 200 Ok"));
    try std.testing.expect(std.mem.endsWith(u8, recv[0..n], "\r\n\r\ndata"));
}

test "zix http response cache: distinct paths and queries are separate keys" {
    var cache = try rc.ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 256 });
    defer cache.deinit();

    setCache(&cache, 1000);
    defer setCache(null, 0);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var req_a = try Request.fromRaw("GET /a HTTP/1.1\r\n\r\n", allocator);
    var req_b = try Request.fromRaw("GET /b HTTP/1.1\r\n\r\n", allocator);
    var req_q = try Request.fromRaw("GET /a?v=2 HTTP/1.1\r\n\r\n", allocator);

    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var res_a = Response.init(fds[1], true, undefined, allocator, 16);
    try res_a.sendCached(&req_a, "alpha", 0);

    var drain: [128]u8 = undefined;
    _ = try fd_io.readOnce(fds[0], &drain);

    // a different path and a different query are both misses
    var res_b = Response.init(fds[1], true, undefined, allocator, 16);
    var res_q = Response.init(fds[1], true, undefined, allocator, 16);
    try std.testing.expect(!res_b.sendFromCache(&req_b));
    try std.testing.expect(!res_q.sendFromCache(&req_q));

    // the original path and query hits
    var res_a2 = Response.init(fds[1], true, undefined, allocator, 16);
    try std.testing.expect(res_a2.sendFromCache(&req_a));
}

test "zix http: writeNonBlockFD stages a partial write then resumes after drain" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    const linux = std.os.linux;

    // Nonblocking AF_UNIX stream pair with a tiny send/recv budget, so a large
    // write fills the kernel buffer and returns a partial count (the .EPOLL
    // backpressure path) instead of blocking the worker.
    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.NONBLOCK, 0, &fds));
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    const small: c_int = 2048;
    std.posix.setsockopt(fds[0], std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&small)) catch {};
    std.posix.setsockopt(fds[1], std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&small)) catch {};

    const payload = try std.testing.allocator.alloc(u8, 1024 * 1024);
    defer std.testing.allocator.free(payload);
    @memset(payload, 'x');

    // First write makes progress but cannot drain the whole payload: a partial.
    const first = writeNonBlockFD(fds[0], payload) orelse return error.ZixUnexpectedWriteError;
    try std.testing.expect(first > 0);
    try std.testing.expect(first < payload.len);

    // Reading on the peer frees buffer space for the staged tail.
    const read_buf = try std.testing.allocator.alloc(u8, 1024 * 1024);
    defer std.testing.allocator.free(read_buf);
    var consumed: usize = 0;
    while (consumed < first) {
        const n = fd_io.readOnce(fds[1], read_buf) catch break;
        if (n == 0) break;
        consumed += n;
    }

    // The previously-blocked tail now makes forward progress.
    const second = writeNonBlockFD(fds[0], payload[first..]) orelse return error.ZixUnexpectedWriteError;
    try std.testing.expect(second > 0);
}

test "zix http: Response.stream detaches the coalescing sink for direct SSE writes" {
    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    // Install a sink as the .EPOLL/.URING worker would before a handler runs.
    var out_buf: [4096]u8 = undefined;
    var sink = RespSink{ .fd = fds[1], .buf = &out_buf };
    tl_resp_sink = &sink;
    defer tl_resp_sink = null;

    var res = Response.init(fds[1], true, undefined, arena.allocator(), 8);
    const writer = try res.sendStream();

    // stream() must detach the sink so SSE events write straight to the fd.
    try std.testing.expect(tl_resp_sink == null);
    try std.testing.expect(res.streaming);

    try writer.writeEvent("hello");

    // The header and event landed on the socket directly, not staged in the sink.
    var buf: [256]u8 = undefined;
    const n = try fd_io.readOnce(fds[0], &buf);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "text/event-stream") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf[0..n], "data: hello") != null);
}

test "zix http: send() into an installed sink is byte-identical to a direct send" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    // Direct send (no sink): build via the staging buffer, capture off the socket.
    tl_resp_sink = null;
    var res_direct = Response.init(fds[1], true, undefined, allocator, 8);
    res_direct.setContentType(.APPLICATION_JSON);
    try res_direct.addHeader("X-Test", "1");
    try res_direct.send("{\"ok\":true}");
    var direct: [512]u8 = undefined;
    const nd = try fd_io.readOnce(fds[0], &direct);

    // Sink send: serialize straight into the sink buffer (the optimized path).
    var out_buf: [512]u8 = undefined;
    var sink = RespSink{ .fd = fds[1], .buf = &out_buf };
    tl_resp_sink = &sink;
    defer tl_resp_sink = null;
    var res_sink = Response.init(fds[1], true, undefined, allocator, 8);
    res_sink.setContentType(.APPLICATION_JSON);
    try res_sink.addHeader("X-Test", "1");
    try res_sink.send("{\"ok\":true}");

    try std.testing.expectEqualStrings(direct[0..nd], sink.buf[0..sink.len]);
}

test "zix http: buildResponse emits Content-Type and Date without bufPrint, byte-exact" {
    var res = Response.init(TEST_FD, true, undefined, std.testing.allocator, 0);
    res.status = .OK;
    res.content_type = .TEXT_PLAIN;
    res.date_cache = "Mon, 01 Jan 2026 00:00:00 GMT";

    var out: [512]u8 = undefined;
    const n = res.buildResponse("ok", &out).?;
    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 Ok\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nDate: Mon, 01 Jan 2026 00:00:00 GMT\r\n\r\nok",
        out[0..n],
    );

    // No content-type and no date: both branches skip cleanly.
    var bare = Response.init(TEST_FD, true, undefined, std.testing.allocator, 0);
    bare.status = .OK;
    const m = bare.buildResponse("hi", &out).?;
    try std.testing.expectEqualStrings("HTTP/1.1 200 Ok\r\nContent-Length: 2\r\n\r\nhi", out[0..m]);
}

test "zix http response: sendText sends text/plain and marks sent" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var res = Response.init(fds[1], true, undefined, arena.allocator(), 16);
    try std.testing.expect(!res.sent);
    try res.sendText("plain words");

    var buf: [512]u8 = undefined;
    const n = try fd_io.readOnce(fds[0], &buf);
    const wire = buf[0..n];

    try std.testing.expect(std.mem.indexOf(u8, wire, "Content-Type: text/plain\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\nplain words"));
    try std.testing.expect(res.sent);
    try std.testing.expect(res.content_type.? == .TEXT_PLAIN);
}

test "zix http response: sendRaw writes caller bytes verbatim and marks sent" {
    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var res = Response.init(fds[1], true, undefined, std.testing.allocator, 16);
    const wire = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    try res.sendRaw(wire);

    var buf: [128]u8 = undefined;
    const n = try fd_io.readOnce(fds[0], &buf);

    try std.testing.expectEqualStrings(wire, buf[0..n]);
    try std.testing.expectEqual(wire.len, res.bytes_written);
    try std.testing.expect(res.sent);
}
