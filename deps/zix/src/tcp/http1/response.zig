//! zix http1 response: the write path for the ergonomic req, res, ctx handler
//! shape. A thin builder over the connection fd. Every send delegates to the
//! core FD writers (sendSimpleFD, sendJsonFD, writeAllFD), so the wire bytes are
//! identical to a handler that calls those directly, and the coalescing sink the
//! .EPOLL and .URING workers install (tl_resp_sink, checked inside core) is
//! inherited for free. No engine change, no second header path.
//!
//! Status and Content-Type are the typed enums (status.zig, content.zig), the
//! same caller surface as zix.Http. The engine decides connection lifetime from
//! the parsed head, setKeepAlive only shapes the Connection header bytes.

const std = @import("std");
const fd_io = @import("../../utils/fd_io.zig");
const socket_pair = @import("../../utils/socket_pair.zig");
const core = @import("core.zig");
const Status = @import("status.zig");
const Content = @import("content.zig");
const compression = @import("../../utils/compression/compression.zig");
const Request = @import("request.zig").Request;

/// Scratch for one extra header line during a streamed header write.
const EXTRA_HEADER_BUF: usize = 256;

pub const HttpHeader = struct {
    name: []const u8,
    value: []const u8,
};

/// Controls how many custom response headers addHeader() will accept per request.
///
/// max_response_headers in Http1ServerConfig sets the cap. The backing buffer is
/// arena-allocated lazily on the first addHeader() call, requests that add no
/// custom headers pay zero allocation cost.
/// Any addHeader() call beyond the cap yields error.ZixTooManyHeaders.
///
/// - MINIMAL (16): simple APIs, constrained environments
/// - COMMON (32): most web applications, single proxy/load balancer
/// - LARGE (64): behind load balancers, CDN + proxy
/// - EXTRA_LARGE (128): k8s, service mesh, many CORS/caching/forwarding headers
/// - CUSTOM (N): explicit non-standard cap
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
        try core.writeAllFD(self.fd, "data: ");
        try core.writeAllFD(self.fd, data);
        try core.writeAllFD(self.fd, "\n\n");
    }

    /// Sends: event: <event>\ndata: <data>\n\n
    pub fn writeNamedEvent(self: SseWriter, event: []const u8, data: []const u8) !void {
        try core.writeAllFD(self.fd, "event: ");
        try core.writeAllFD(self.fd, event);
        try core.writeAllFD(self.fd, "\ndata: ");
        try core.writeAllFD(self.fd, data);
        try core.writeAllFD(self.fd, "\n\n");
    }

    /// Sends: : <text>\n  (comment / keepalive heartbeat)
    pub fn comment(self: SseWriter, text: []const u8) !void {
        try core.writeAllFD(self.fd, ": ");
        try core.writeAllFD(self.fd, text);
        try core.writeAllFD(self.fd, "\n");
    }
};

fn appendBytes(buf: []u8, pos: usize, bytes: []const u8) usize {
    @memcpy(buf[pos..][0..bytes.len], bytes);
    return pos + bytes.len;
}

pub const Response = struct {
    /// Connection fd. Every write lands here, through the core sink when one is
    /// installed on this worker.
    fd: std.posix.fd_t,
    /// The io the request runs on. Carried for symmetry with Context. The plain
    /// send path does not use it.
    io: std.Io,
    /// Per-request allocator. Used only by the extra-header, cached, and
    /// negotiated paths. The plain send path allocates nothing.
    allocator: std.mem.Allocator,
    /// Response status code. Default 200.
    status: Status.Code = .OK,
    /// Content-Type. Null omits the header, matching core.sendSimpleFD with "".
    content_type: ?Content.Type = null,
    /// Handler override for the Connection header. Null emits nothing (the
    /// engine default). The engine's connection lifetime still follows the
    /// request head: false emits Connection: close so the client closes and the
    /// engine reaps the socket.
    keep_alive: ?bool = null,
    /// Custom headers appended by addHeader, allocated lazily.
    extra_buf: ?[]HttpHeader = null,
    extra_len: usize = 0,
    /// Body bytes written by the last send, for a caller access log.
    bytes_written: usize = 0,
    /// Set once any send lands, so the engine does not emit a 500 over a
    /// response the handler already wrote when the handler then returns an error.
    sent: bool = false,

    /// Build a response over a connection fd.
    ///
    /// Param:
    /// fd - std.posix.fd_t (the connection)
    /// io - std.Io (the worker io, carried for symmetry with Context)
    /// allocator - std.mem.Allocator (per-request scratch)
    ///
    /// Return:
    /// - Response
    pub fn init(fd: std.posix.fd_t, io: std.Io, allocator: std.mem.Allocator) Response {
        return .{ .fd = fd, .io = io, .allocator = allocator };
    }

    /// Set the response status code.
    pub fn setStatus(self: *Response, status: Status.Code) void {
        self.status = status;
    }

    /// Set the Content-Type.
    pub fn setContentType(self: *Response, content_type: Content.Type) void {
        self.content_type = content_type;
    }

    /// Set the Connection header for this response. The engine's connection
    /// lifetime still follows the request head: false emits Connection: close
    /// (the client closes, the engine then reaps the socket), true emits
    /// Connection: keep-alive (e.g. for an HTTP/1.0 client).
    pub fn setKeepAlive(self: *Response, keep_alive: bool) void {
        self.keep_alive = keep_alive;
    }

    /// Append a custom header to the response.
    /// Allocates the full header buffer on the first call (lazy, capacity =
    /// config.max_response_headers via the worker install).
    ///
    /// Return:
    /// - error.ZixTooManyHeaders if the header cap is exceeded
    /// - error.ZixInvalidHeaderName or error.ZixInvalidHeaderValue on CR/LF injection
    pub fn addHeader(self: *Response, name: []const u8, value: []const u8) !void {
        for (name) |byte| if (byte == '\r' or byte == '\n') return error.ZixInvalidHeaderName;
        for (value) |byte| if (byte == '\r' or byte == '\n') return error.ZixInvalidHeaderValue;

        if (self.extra_buf == null) {
            if (core.tl_max_response_headers == 0) return error.ZixTooManyHeaders;
            self.extra_buf = try self.allocator.alloc(HttpHeader, core.tl_max_response_headers);
        }
        if (self.extra_len >= self.extra_buf.?.len) return error.ZixTooManyHeaders;

        self.extra_buf.?[self.extra_len] = .{ .name = name, .value = value };
        self.extra_len += 1;
    }

    fn contentTypeString(self: *const Response) []const u8 {
        return if (self.content_type) |content_type| content_type.asString() else "";
    }

    /// Serialize the full response (base headers, extra headers, Connection
    /// override, body) into one arena buffer. Same byte layout as the fast path
    /// with the extra lines spliced in before the final CRLF.
    fn buildFull(self: *Response, body: []const u8) ![]u8 {
        var extra_bytes: usize = 0;
        if (self.extra_buf) |extra| {
            for (extra[0..self.extra_len]) |hdr| extra_bytes += hdr.name.len + hdr.value.len + 4;
        }
        if (self.keep_alive != null) extra_bytes += "Connection: keep-alive\r\n".len;

        const buf = try self.allocator.alloc(u8, core.HEADER_BUF_SIZE + extra_bytes + body.len);
        const base_len = core.buildSimpleHeaderInto(buf, @intFromEnum(self.status), self.contentTypeString(), body.len);

        var pos = base_len - 2;
        if (self.extra_buf) |extra| {
            for (extra[0..self.extra_len]) |hdr| {
                pos = appendBytes(buf, pos, hdr.name);
                pos = appendBytes(buf, pos, ": ");
                pos = appendBytes(buf, pos, hdr.value);
                pos = appendBytes(buf, pos, "\r\n");
            }
        }
        if (self.keep_alive) |keep_alive| {
            pos = appendBytes(buf, pos, if (keep_alive) "Connection: keep-alive\r\n" else "Connection: close\r\n");
        }
        pos = appendBytes(buf, pos, "\r\n");
        pos = appendBytes(buf, pos, body);

        return buf[0..pos];
    }

    /// Send body with the current status and Content-Type. With no extra
    /// headers this is byte-identical to a direct core.sendSimpleFD and routes
    /// through the coalescing sink when the .EPOLL or .URING worker has one
    /// installed. With extra headers (or a Connection override) the same header
    /// block is built once with the extra lines spliced in, then written whole.
    ///
    /// Param:
    /// body - []const u8 (response body)
    ///
    /// Return:
    /// - !void (propagates the core writer error, e.g. error.BrokenPipe)
    pub fn send(self: *Response, body: []const u8) !void {
        self.bytes_written = body.len;
        self.sent = true;

        if (self.extra_len == 0 and self.keep_alive == null) {
            return core.sendSimpleFD(self.fd, @intFromEnum(self.status), self.contentTypeString(), body);
        }

        const full = try self.buildFull(body);

        return core.writeAllFD(self.fd, full);
    }

    /// Send body as application/json. Byte-identical to core.sendJsonFD.
    pub fn sendJson(self: *Response, body: []const u8) !void {
        self.content_type = .APPLICATION_JSON;

        return self.send(body);
    }

    /// Send body as text/plain.
    pub fn sendText(self: *Response, body: []const u8) !void {
        self.content_type = .TEXT_PLAIN;

        return self.send(body);
    }

    /// Write caller-owned bytes verbatim, a full response the handler built
    /// itself. Routes through the coalescing sink like every other write.
    ///
    /// Param:
    /// bytes - []const u8 (the exact wire bytes to send)
    ///
    /// Return:
    /// - !void (propagates the core writer error, e.g. error.BrokenPipe)
    pub fn sendRaw(self: *Response, bytes: []const u8) !void {
        self.bytes_written = bytes.len;
        self.sent = true;

        return core.writeAllFD(self.fd, bytes);
    }

    /// Send a 204 No Content response with an empty body.
    pub fn sendNoContent(self: *Response) !void {
        self.status = .NO_CONTENT;

        return self.send("");
    }

    /// Serve this request from the per-worker response cache when it holds a
    /// fresh entry. A no-op returning false on workers without a cache.
    ///
    /// Usage:
    /// ```zig
    /// if (res.sendFromCache(req)) return;
    /// const body = buildExpensiveBody(...);
    /// try res.sendCached(req, body, 0);
    /// ```
    ///
    /// Return:
    /// - bool (true when served from cache, the handler should return)
    pub fn sendFromCache(self: *Response, req: *const Request) bool {
        const bytes = core.cacheLookup(req.head) orelse return false;

        self.bytes_written = bytes.len;
        self.sent = true;
        core.writeAllFD(self.fd, bytes) catch return true;

        return true;
    }

    /// Serialize the response once, write it, and store it under the request
    /// key for later sendFromCache hits. ttl_ms of 0 uses the worker default
    /// (core.cacheTtl). Falls back to a plain send when no cache is installed
    /// or the serialization allocation fails.
    ///
    /// Param:
    /// req - *const Request (source of the cache key: method, path, query)
    /// body - []const u8 (response body)
    /// ttl_ms - u32 (freshness in milliseconds, 0 means the worker default)
    ///
    /// Return:
    /// - !void
    pub fn sendCached(self: *Response, req: *const Request, body: []const u8, ttl_ms: u32) !void {
        if (core.tl_cache == null) return self.send(body);

        const full = self.buildFull(body) catch return self.send(body);
        self.bytes_written = body.len;
        self.sent = true;

        const ttl = if (ttl_ms == 0) core.cacheTtl() else ttl_ms;
        core.cacheStore(req.head, full, ttl);

        return core.writeAllFD(self.fd, full);
    }

    /// Send body with Accept-Encoding negotiation. Compresses only when the
    /// worker has compression enabled, the client accepts a producible coding,
    /// the body clears the size floor and is not an already-compressed media
    /// type, and the compressed result is both smaller than the original and
    /// within the cap. In every other case the body is sent uncompressed,
    /// identical to send().
    ///
    /// Note:
    /// - Opt-in like sendCached: the handler passes the request for its
    ///   Accept-Encoding.
    /// - The compressed path sets Content-Encoding and Vary: Accept-Encoding,
    ///   then reuses send() so Content-Length and the header block stay correct.
    /// - Does not touch the cache.
    ///
    /// Param:
    /// req - *const Request (for the Accept-Encoding header)
    /// body - []const u8 (uncompressed body)
    ///
    /// Return:
    /// - !void (propagates send() and addHeader errors)
    pub fn sendNegotiated(self: *Response, req: *const Request, body: []const u8) !void {
        if (!core.tl_compression) return self.send(body);

        const accept = core.acceptEncoding(req.head);
        const encoding = compression.negotiate(accept, &compression.supported_default) orelse {
            self.setStatus(.NOT_ACCEPTABLE);

            return self.send("");
        };

        if (encoding == .IDENTITY or !compression.shouldCompress(body.len, self.contentTypeString(), core.tl_compression_min_size)) {
            return self.send(body);
        }

        const encoded = compression.encode(self.allocator, encoding, body, .DEFAULT) catch {
            return self.send(body);
        };

        if (encoded.len > core.tl_compression_max_out or encoded.len >= body.len) {
            return self.send(body);
        }

        try self.addHeader("Content-Encoding", encoding.contentEncoding().?);
        try self.addHeader("Vary", "Accept-Encoding");

        return self.send(encoded);
    }

    /// Begin an SSE (Server-Sent Events) stream and return an SseWriter.
    /// Sends HTTP 200 with Content-Type: text/event-stream (no Content-Length)
    /// plus any headers added via addHeader. Detaches the coalescing sink first
    /// (core.beginStream), so each event flushes to the socket immediately, in
    /// cleartext and over TLS. An SSE handler never returns.
    pub fn sendStream(self: *Response) !SseWriter {
        core.beginStream();

        const fixed = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n";
        core.writeAllFD(self.fd, fixed) catch return error.BrokenPipe;

        if (self.extra_buf) |extra| {
            for (extra[0..self.extra_len]) |hdr| {
                var hdr_buf: [EXTRA_HEADER_BUF]u8 = undefined;
                const line = std.fmt.bufPrint(&hdr_buf, "{s}: {s}\r\n", .{ hdr.name, hdr.value }) catch continue;
                core.writeAllFD(self.fd, line) catch return error.BrokenPipe;
            }
        }
        core.writeAllFD(self.fd, "\r\n") catch return error.BrokenPipe;

        self.sent = true;
        return SseWriter{ .fd = self.fd };
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Sentinel descriptor for tests that never write: Windows handles are opaque pointers,
/// POSIX descriptors are ints.
const TEST_FD: std.posix.fd_t = if (@import("builtin").os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;

/// A connected pair for the tests below, portable across every supported platform.
fn socketPair(fds: *[2]std.posix.fd_t) !void {
    const pair = try socket_pair.Pair.open(std.testing.allocator);
    fds.* = pair.fds;
}

test "zix http1: Response setters mutate status, content type, keep alive" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var res = Response.init(TEST_FD, undefined, std.testing.allocator);

    try std.testing.expect(res.status == .OK);
    res.setStatus(.NOT_FOUND);
    try std.testing.expect(res.status == .NOT_FOUND);

    res.setContentType(.TEXT_HTML);
    try std.testing.expect(res.content_type.? == .TEXT_HTML);

    try std.testing.expect(res.keep_alive == null);
    res.setKeepAlive(false);
    try std.testing.expect(res.keep_alive.? == false);
}

test "zix http1: Response.send is byte-identical to core.sendSimpleFD" {
    var pair_res: [2]std.posix.fd_t = undefined;
    var pair_core: [2]std.posix.fd_t = undefined;
    try socketPair(&pair_res);
    try socketPair(&pair_core);
    defer for ([_]std.posix.fd_t{ pair_res[0], pair_res[1], pair_core[0], pair_core[1] }) |fd| {
        fd_io.close(fd);
    };

    var res = Response.init(pair_res[1], undefined, std.testing.allocator);
    res.setStatus(.CREATED);
    res.setContentType(.TEXT_PLAIN);
    try res.send("hello");

    var via_res: [256]u8 = undefined;
    const n_res = try fd_io.readOnce(pair_res[0], &via_res);

    try core.sendSimpleFD(pair_core[1], 201, "text/plain", "hello");

    var via_core: [256]u8 = undefined;
    const n_core = try fd_io.readOnce(pair_core[0], &via_core);

    try std.testing.expectEqualStrings(via_core[0..n_core], via_res[0..n_res]);
    try std.testing.expectEqual(@as(usize, 5), res.bytes_written);
    try std.testing.expect(res.sent);
}

test "zix http1: Response.sendJson is byte-identical to core.sendJsonFD" {
    var pair_res: [2]std.posix.fd_t = undefined;
    var pair_core: [2]std.posix.fd_t = undefined;
    try socketPair(&pair_res);
    try socketPair(&pair_core);
    defer for ([_]std.posix.fd_t{ pair_res[0], pair_res[1], pair_core[0], pair_core[1] }) |fd| {
        fd_io.close(fd);
    };

    var res = Response.init(pair_res[1], undefined, std.testing.allocator);
    try res.sendJson("{\"ok\":true}");

    var via_res: [256]u8 = undefined;
    const n_res = try fd_io.readOnce(pair_res[0], &via_res);

    try core.sendJsonFD(pair_core[1], 200, "{\"ok\":true}");

    var via_core: [256]u8 = undefined;
    const n_core = try fd_io.readOnce(pair_core[0], &via_core);

    try std.testing.expectEqualStrings(via_core[0..n_core], via_res[0..n_res]);
    try std.testing.expect(res.content_type.? == .APPLICATION_JSON);
}

test "zix http1: Response.sendText is byte-identical to core.sendSimpleFD text/plain" {
    var pair_res: [2]std.posix.fd_t = undefined;
    var pair_core: [2]std.posix.fd_t = undefined;
    try socketPair(&pair_res);
    try socketPair(&pair_core);
    defer for ([_]std.posix.fd_t{ pair_res[0], pair_res[1], pair_core[0], pair_core[1] }) |fd| {
        fd_io.close(fd);
    };

    var res = Response.init(pair_res[1], undefined, std.testing.allocator);
    try res.sendText("plain words");

    var via_res: [256]u8 = undefined;
    const n_res = try fd_io.readOnce(pair_res[0], &via_res);

    try core.sendSimpleFD(pair_core[1], 200, "text/plain", "plain words");

    var via_core: [256]u8 = undefined;
    const n_core = try fd_io.readOnce(pair_core[0], &via_core);

    try std.testing.expectEqualStrings(via_core[0..n_core], via_res[0..n_res]);
}

test "zix http1: Response.sendRaw writes caller bytes verbatim" {
    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var res = Response.init(fds[1], undefined, std.testing.allocator);
    const wire = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    try res.sendRaw(wire);

    var buf: [128]u8 = undefined;
    const n = try fd_io.readOnce(fds[0], &buf);

    try std.testing.expectEqualStrings(wire, buf[0..n]);
    try std.testing.expectEqual(wire.len, res.bytes_written);
}

test "zix http1: Response.sendNoContent is byte-identical to a 204 empty send" {
    var pair_res: [2]std.posix.fd_t = undefined;
    var pair_core: [2]std.posix.fd_t = undefined;
    try socketPair(&pair_res);
    try socketPair(&pair_core);
    defer for ([_]std.posix.fd_t{ pair_res[0], pair_res[1], pair_core[0], pair_core[1] }) |fd| {
        fd_io.close(fd);
    };

    var res = Response.init(pair_res[1], undefined, std.testing.allocator);
    try res.sendNoContent();

    var via_res: [256]u8 = undefined;
    const n_res = try fd_io.readOnce(pair_res[0], &via_res);

    try core.sendSimpleFD(pair_core[1], 204, "", "");

    var via_core: [256]u8 = undefined;
    const n_core = try fd_io.readOnce(pair_core[0], &via_core);

    try std.testing.expectEqualStrings(via_core[0..n_core], via_res[0..n_res]);
    try std.testing.expect(res.status == .NO_CONTENT);
}

test "zix http1: Response.addHeader splices extra lines before the final CRLF" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var res = Response.init(fds[1], undefined, arena.allocator());
    res.setContentType(.TEXT_PLAIN);
    try res.addHeader("X-Custom", "yes");
    try res.addHeader("X-Trace", "abc123");
    try res.send("body");

    var buf: [512]u8 = undefined;
    const n = try fd_io.readOnce(fds[0], &buf);
    const wire = buf[0..n];

    try std.testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, wire, "Content-Length: 4\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire, "X-Custom: yes\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire, "X-Trace: abc123\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\nbody"));
}

test "zix http1: Response.addHeader rejects CR LF injection and enforces the cap" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var res = Response.init(TEST_FD, undefined, arena.allocator());
    try std.testing.expectError(error.ZixInvalidHeaderName, res.addHeader("X\r\nBad", "v"));
    try std.testing.expectError(error.ZixInvalidHeaderValue, res.addHeader("X-Ok", "v\r\ninjected"));

    core.setMaxResponseHeaders(1);
    defer core.setMaxResponseHeaders(16);

    try res.addHeader("X-One", "1");
    try std.testing.expectError(error.ZixTooManyHeaders, res.addHeader("X-Two", "2"));
}

test "zix http1: Response.setKeepAlive false emits Connection close" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var res = Response.init(fds[1], undefined, arena.allocator());
    res.setKeepAlive(false);
    try res.send("bye");

    var buf: [256]u8 = undefined;
    const n = try fd_io.readOnce(fds[0], &buf);
    const wire = buf[0..n];

    try std.testing.expect(std.mem.indexOf(u8, wire, "Connection: close\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\nbye"));
}

test "zix http1: Response.sendFromCache is false without a cache, hits after sendCached" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parsed = try core.parseHead("GET /cacheme HTTP/1.1\r\nHost: x\r\n\r\n");
    var req = Request.init(&parsed.head, "", TEST_FD);

    core.setCache(null, 0);
    var miss_res = Response.init(TEST_FD, undefined, arena.allocator());
    try std.testing.expect(!miss_res.sendFromCache(&req));

    var resp_cache = try @import("../../utils/response_cache.zig").ResponseCache.init(std.testing.allocator, .{ .max_entries = 16, .max_value_bytes = 256 });
    defer resp_cache.deinit();

    core.setCache(&resp_cache, 1000);
    defer core.setCache(null, 0);

    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var res = Response.init(fds[1], undefined, arena.allocator());
    res.setContentType(.TEXT_PLAIN);
    try res.sendCached(&req, "fresh", 0);

    var first: [256]u8 = undefined;
    const n_first = try fd_io.readOnce(fds[0], &first);

    var hit_res = Response.init(fds[1], undefined, arena.allocator());
    try std.testing.expect(hit_res.sendFromCache(&req));

    var second: [256]u8 = undefined;
    const n_second = try fd_io.readOnce(fds[0], &second);

    try std.testing.expectEqualStrings(first[0..n_first], second[0..n_second]);
    try std.testing.expect(std.mem.endsWith(u8, first[0..n_first], "\r\n\r\nfresh"));
}

test "zix http1: Response.sendNegotiated equals plain send when compression is off" {
    var pair_res: [2]std.posix.fd_t = undefined;
    var pair_plain: [2]std.posix.fd_t = undefined;
    try socketPair(&pair_res);
    try socketPair(&pair_plain);
    defer for ([_]std.posix.fd_t{ pair_res[0], pair_res[1], pair_plain[0], pair_plain[1] }) |fd| {
        fd_io.close(fd);
    };

    const parsed = try core.parseHead("GET /n HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n");
    var req = Request.init(&parsed.head, "", TEST_FD);

    var res = Response.init(pair_res[1], undefined, std.testing.allocator);
    res.setContentType(.TEXT_PLAIN);
    try res.sendNegotiated(&req, "uncompressed body");

    var via_res: [256]u8 = undefined;
    const n_res = try fd_io.readOnce(pair_res[0], &via_res);

    var plain = Response.init(pair_plain[1], undefined, std.testing.allocator);
    plain.setContentType(.TEXT_PLAIN);
    try plain.send("uncompressed body");

    var via_plain: [256]u8 = undefined;
    const n_plain = try fd_io.readOnce(pair_plain[0], &via_plain);

    try std.testing.expectEqualStrings(via_plain[0..n_plain], via_res[0..n_res]);
}

test "zix http1: Response.sendStream writes the SSE header block then events" {
    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var res = Response.init(fds[1], undefined, std.testing.allocator);
    const writer = try res.sendStream();
    try writer.writeEvent("tick 1");

    var buf: [512]u8 = undefined;
    const n = try fd_io.readOnce(fds[0], &buf);
    const wire = buf[0..n];

    try std.testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, wire, "\r\n\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, wire, "data: tick 1\n\n"));
    try std.testing.expect(res.sent);
}
