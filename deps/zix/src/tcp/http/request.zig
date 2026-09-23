//! zix http request

const std = @import("std");
const builtin = @import("builtin");
const win_io = @import("../../utils/windows_io.zig");
const fd_io = @import("../../utils/fd_io.zig");
const Method = @import("method.zig");
const parser = @import("parser.zig");

/// First size of the raw buffer a chunked body reads into. It doubles from here as bytes
/// arrive, so a small chunked request pays one allocation of this size and a large one pays
/// a handful of grows instead of reserving the ceiling up front.
const CHUNKED_RAW_START: usize = 8 * 1024;

/// Ceiling for a chunked body when config.max_request_body is 0. Chunked declares no length,
/// so the read loop has nothing to check a limit against and needs a stop of its own. A
/// configured max_request_body replaces this.
const CHUNKED_RAW_MAX: usize = 64 * 1024 * 1024;

/// SO_RCVBUF (bytes) applied while reading a large request body. Installed per worker from
/// config.large_body_rcvbuf. 0 leaves the kernel default. Threadlocal because body() runs on the
/// worker without a config handle.
pub threadlocal var tl_large_body_rcvbuf: usize = 0;

/// Install the large-body SO_RCVBUF for this worker.
pub fn setLargeBodyRcvbuf(bytes: usize) void {
    tl_large_body_rcvbuf = bytes;
}

/// Widen the socket receive buffer for a large-body read. bytes = 0 leaves the socket untouched.
fn setRecvBuf(fd: std.posix.fd_t, bytes: usize) void {
    if (bytes == 0) return;
    if (comptime @import("builtin").target.os.tag == .windows) return;

    const val: c_int = @intCast(@min(bytes, std.math.maxInt(c_int)));
    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&val)) catch {};
}

/// Max time body() waits for the next segment of a Content-Length or chunked body before giving up.
/// Threadlocal so the EPOLL / URING worker can tune it without a config handle. The default covers a
/// slow upload while keeping a stalled client bounded rather than blocking the worker forever.
pub threadlocal var tl_body_read_timeout_ms: i32 = 30_000;

/// Install the body read timeout for this worker.
pub fn setBodyReadTimeout(ms: i32) void {
    tl_body_read_timeout_ms = ms;
}

/// Read some bytes from fd: the ntdll shim on Windows, std.posix.read elsewhere.
fn readOnceFD(fd: std.posix.fd_t, buf: []u8) !usize {
    if (comptime builtin.os.tag == .windows) return win_io.readOnce(fd, buf);

    return std.posix.read(fd, buf);
}

/// Block until fd is readable or the timeout elapses.
///
/// The accepted fd is non-blocking under the EPOLL / URING models, so a body split across TCP
/// segments returns EAGAIN between segments. body() waits here for the next segment instead of
/// truncating at the first EAGAIN. Upload path only: a request with no body never reaches this.
///
/// Return:
/// - true when the fd became readable
/// - false on timeout or a poll error
fn waitReadable(fd: std.posix.fd_t, timeout_ms: i32) bool {
    return fd_io.waitReadable(fd, timeout_ms);
}

pub const PathParam = struct {
    name: []const u8,
    value: []const u8,
};

pub const Request = struct {
    /// Read buffer slice for this connection. All path/query/header slices point into it.
    buf: []const u8,
    /// Parsed offsets into buf. No data was copied during parsing.
    head: parser.ParsedHead,
    /// Raw socket fd: used by body() for any bytes not yet in buf.
    fd: std.posix.fd_t,
    /// How many bytes in buf are valid (filled by the recv loop in handleConnection).
    buf_filled: usize,
    allocator: std.mem.Allocator,
    body_cache: ?[]const u8 = null,
    /// Largest body this request may take off the socket, from config.max_request_body.
    /// 0 removes the limit.
    body_limit: usize = 0,
    /// Body bytes taken off the socket for this request, counted by the read loops
    /// in body(). Never taken from the Content-Length header. Read it through
    /// bodyReceived().
    body_received: u64 = 0,
    /// Whether the body read reached the end of the body: the declared
    /// Content-Length, or the chunked terminator. Read it through bodyComplete().
    body_complete: bool = false,
    /// Set when the body crossed body_limit, so the caller can answer 413.
    body_too_large: bool = false,
    /// Set when the chunked framing could not be parsed, so the caller can answer 400.
    body_malformed: bool = false,
    path_params: []const PathParam = &.{},

    /// Get HTTP method.
    pub fn method(self: Request) Method.Code {
        return self.head.method;
    }

    /// Get the URL path without query string.
    pub fn path(self: Request) []const u8 {
        return self.buf[self.head.path_start..][0..self.head.path_len];
    }

    /// Get the raw query string (after '?'), or empty string if none.
    pub fn query(self: Request) []const u8 {
        if (self.head.query_len == 0) return "";
        return self.buf[self.head.query_start..][0..self.head.query_len];
    }

    /// Get a request header value by name (case-insensitive).
    pub fn header(self: Request, name: []const u8) ?[]const u8 {
        return parser.getHeader(self.head, self.buf, name);
    }

    /// Read and return the request body bytes.
    ///
    /// Note:
    /// - Lazy, unlike zix.Http1 where the engine drains before the handler
    ///   runs. The first call is what pulls the body off the socket, so a
    ///   handler that never calls this leaves the body unread.
    /// - Cached after the first call, so calling it twice costs nothing.
    /// - Handles both Content-Length and Transfer-Encoding: chunked. Bytes
    ///   already in the read buffer are used directly, the rest are recv'd.
    /// - The returned length is what was actually read, which can be short of
    ///   the declared Content-Length when the peer stops early.
    ///
    /// Return:
    /// - []const u8 (the body bytes)
    /// - empty when Content-Length is absent or zero and the request is not chunked
    pub fn body(self: *Request) ![]const u8 {
        if (self.body_cache) |cached| return cached;

        if (self.head.chunked) return self.readChunkedBody();

        const declared = self.head.content_length;
        if (declared == 0) {
            self.body_cache = "";
            self.body_complete = true;
            return "";
        }

        // The declared length decides the allocation, so it is checked against the
        // limit before anything is reserved. A client cannot make the server
        // allocate by claiming a size it never sends.
        const content_len = std.math.cast(usize, declared) orelse {
            self.body_too_large = true;
            return error.ZixRequestBodyTooLarge;
        };
        if (self.body_limit != 0 and content_len > self.body_limit) {
            self.body_too_large = true;
            return error.ZixRequestBodyTooLarge;
        }

        // Bytes already pulled into buf during the header read loop.
        const in_buf_end = @min(self.buf_filled, self.buf.len);
        const already_slice = self.buf[@min(self.head.body_offset, in_buf_end)..in_buf_end];
        const already_len = @min(already_slice.len, content_len);

        const out = try self.allocator.alloc(u8, content_len);
        @memcpy(out[0..already_len], already_slice[0..already_len]);

        // Large body still to come off the socket: widen the receive window so it ingests in fewer
        // cycles (the upload path). Small bodies already buffered skip this.
        if (content_len > already_len) setRecvBuf(self.fd, tl_large_body_rcvbuf);

        var total: usize = already_len;
        while (total < content_len) {
            const n = readOnceFD(self.fd, out[total..content_len]) catch |err| {
                // Non-blocking fd between segments: wait for the next one instead of truncating.
                if (err == error.WouldBlock and waitReadable(self.fd, tl_body_read_timeout_ms)) continue;

                break;
            };
            if (n == 0) break;
            total += n;
        }

        // Counted from the reads, so a peer that stops early leaves the two
        // disagreeing and bodyComplete() false. The caller closes on that.
        self.body_received = total;
        self.body_complete = total == content_len;
        self.body_cache = out[0..total];

        return self.body_cache.?;
    }

    /// Read a chunked body off the socket, decoded in place.
    ///
    /// Note:
    /// - The raw buffer is sized from what still has to be read, not from the
    ///   bytes that happened to arrive with the head. It starts at one window and
    ///   doubles, so a body spanning many segments costs a few grows.
    /// - Completion is decided by walking the chunk framing, not by searching for
    ///   the terminator bytes, which chunk data can spell by accident.
    /// - Decoding runs over the raw buffer itself, so the second buffer and the
    ///   full-body copy the old path paid are both gone.
    fn readChunkedBody(self: *Request) ![]const u8 {
        const in_buf_end = @min(self.buf_filled, self.buf.len);
        const already_slice = self.buf[@min(self.head.body_offset, in_buf_end)..in_buf_end];

        // Chunked declares no length, so the ceiling is the configured limit and
        // the buffer grows toward it only as bytes actually arrive.
        const cap_limit = @max(if (self.body_limit == 0) CHUNKED_RAW_MAX else self.body_limit, already_slice.len);
        var cap = @max(already_slice.len, @min(CHUNKED_RAW_START, cap_limit));

        var raw = try self.allocator.alloc(u8, cap);
        @memcpy(raw[0..already_slice.len], already_slice);
        var raw_total = already_slice.len;

        if (raw_total < cap) setRecvBuf(self.fd, tl_large_body_rcvbuf);

        var scan_from: usize = 0;
        var body_end: ?usize = null;
        while (true) {
            body_end = parser.chunkedEnd(raw[0..raw_total], &scan_from) catch {
                self.body_malformed = true;
                self.body_received = raw_total;
                self.body_cache = "";

                return error.ZixInvalidChunkedBody;
            };
            if (body_end != null) break;

            if (raw_total == cap) {
                if (cap >= cap_limit) {
                    self.body_too_large = true;
                    self.body_received = raw_total;
                    self.body_cache = "";

                    return error.ZixRequestBodyTooLarge;
                }

                cap = @min(cap * 2, cap_limit);
                raw = try self.allocator.realloc(raw, cap);
            }

            const n = readOnceFD(self.fd, raw[raw_total..cap]) catch |err| {
                // Non-blocking fd between chunks: wait for the next one instead of truncating.
                if (err == error.WouldBlock and waitReadable(self.fd, tl_body_read_timeout_ms)) continue;

                break;
            };
            if (n == 0) break;
            raw_total += n;
        }

        // A body that never terminated still decodes what arrived, and leaves
        // bodyComplete() false so the caller closes instead of reusing the socket.
        const end = body_end orelse raw_total;
        const decoded_len = parser.dechunkInPlace(raw[0..end]) catch 0;

        self.body_received = end;
        self.body_complete = body_end != null;
        self.body_cache = raw[0..decoded_len];

        return self.body_cache.?;
    }

    /// How many body bytes this request took off the socket, counted by the read
    /// loops in body() and never read from the Content-Length header.
    ///
    /// Note:
    /// - This is the COUNT. body() is the DATA. A handler that only needs the
    ///   size reads this and skips the bytes.
    /// - Zero until body() is called, because zix.Http reads the body lazily.
    /// - For a chunked body this counts the wire bytes, framing included, so it
    ///   is larger than body().len by the size of that framing.
    ///
    /// Return:
    /// - u64 (counted received body bytes)
    pub fn bodyReceived(self: Request) u64 {
        return self.body_received;
    }

    /// Whether the body was read all the way to its end: the declared
    /// Content-Length, or the chunked terminator.
    ///
    /// Note:
    /// - False when body() was never called, when the peer stopped early, and
    ///   when the body crossed the configured limit.
    /// - The engine closes the connection rather than reuse it whenever this is
    ///   false for a request that declared a body, because the unread remainder
    ///   would otherwise be parsed as the next request.
    ///
    /// Return:
    /// - bool
    pub fn bodyComplete(self: Request) bool {
        return self.body_complete;
    }

    /// Whether the connection is keep-alive.
    pub fn keepAlive(self: Request) bool {
        return self.head.keep_alive;
    }

    /// Get a single named query parameter value.
    pub fn queryParam(self: Request, key: []const u8) ?[]const u8 {
        const q = self.query();
        if (q.len == 0) return null;
        var pos: usize = 0;
        while (pos < q.len) {
            const amp = std.mem.indexOfScalarPos(u8, q, pos, '&') orelse q.len;
            const pair = q[pos..amp];
            if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
                if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
            }
            pos = amp + 1;
        }
        return null;
    }

    /// Split the request path into non-empty segments.
    pub fn pathSegments(self: Request, allocator: std.mem.Allocator) ![][]const u8 {
        var list: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, self.path(), '/');
        while (it.next()) |seg| {
            if (seg.len > 0) try list.append(allocator, seg);
        }
        return list.items;
    }

    /// Parse a complete raw HTTP/1.1 head buffer into a Request.
    /// Useful for tests and offline parsing. buf must contain a full head (\r\n\r\n).
    pub fn fromRaw(buf: []const u8, allocator: std.mem.Allocator) !Request {
        const head = (try parser.parse(buf, parser.MAX_HEADERS_U8)) orelse return error.ZixIncomplete;
        return .{
            .buf = buf,
            .head = head,
            .fd = undefined,
            .buf_filled = buf.len,
            .allocator = allocator,
        };
    }

    /// Get a named path parameter captured from a parameterized route.
    pub fn pathParam(self: Request, name: []const u8) ?[]const u8 {
        for (self.path_params) |p| {
            if (std.mem.eql(u8, p.name, name)) return p.value;
        }
        return null;
    }

    pub const QueryParam = struct {
        key: []const u8,
        value: ?[]const u8,
    };

    /// Get all query parameters as a slice of QueryParam.
    pub fn queryParams(self: Request, allocator: std.mem.Allocator) ![]QueryParam {
        const q = self.query();
        if (q.len == 0) return &.{};
        var list: std.ArrayList(QueryParam) = .empty;
        var pos: usize = 0;
        while (pos < q.len) {
            const amp = std.mem.indexOfScalarPos(u8, q, pos, '&') orelse q.len;
            const pair = q[pos..amp];
            if (pair.len > 0) {
                if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
                    const val = pair[eq + 1 ..];
                    try list.append(allocator, .{
                        .key = pair[0..eq],
                        .value = if (val.len > 0) val else null,
                    });
                } else {
                    try list.append(allocator, .{ .key = pair, .value = null });
                }
            }
            if (amp >= q.len) break;
            pos = amp + 1;
        }
        return list.items;
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http: request path and query" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const raw = "GET /api/users/123?name=alice&flag HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const head = (try parser.parse(raw, parser.MAX_HEADERS_U8)).?;
    var req = Request{
        .buf = raw,
        .head = head,
        .fd = undefined,
        .buf_filled = raw.len,
        .allocator = allocator,
    };

    try std.testing.expectEqual(Method.Code.GET, req.method());
    try std.testing.expectEqualStrings("/api/users/123", req.path());
    try std.testing.expectEqualStrings("name=alice&flag", req.query());

    try std.testing.expectEqualStrings("alice", req.queryParam("name").?);
    try std.testing.expect(req.queryParam("flag") == null);
    try std.testing.expect(req.queryParam("missing") == null);

    const segs = try req.pathSegments(allocator);
    try std.testing.expectEqual(@as(usize, 3), segs.len);
    try std.testing.expectEqualStrings("api", segs[0]);
    try std.testing.expectEqualStrings("users", segs[1]);
    try std.testing.expectEqualStrings("123", segs[2]);

    const params = try req.queryParams(allocator);
    try std.testing.expectEqual(@as(usize, 2), params.len);
    try std.testing.expectEqualStrings("name", params[0].key);
    try std.testing.expectEqualStrings("alice", params[0].value.?);
    try std.testing.expectEqualStrings("flag", params[1].key);
    try std.testing.expect(params[1].value == null);
}

test "zix http: request header lookup" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const raw = "GET / HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n";
    const head = (try parser.parse(raw, parser.MAX_HEADERS_U8)).?;
    var req = Request{
        .buf = raw,
        .head = head,
        .fd = undefined,
        .buf_filled = raw.len,
        .allocator = arena.allocator(),
    };
    try std.testing.expectEqualStrings("example.com", req.header("host").?);
    try std.testing.expectEqualStrings("example.com", req.header("Host").?);
    try std.testing.expectEqualStrings("application/json", req.header("content-type").?);
    try std.testing.expect(req.header("x-missing") == null);
}

test "zix http: request body must not truncate when a Content-Length body arrives in segments over a non-blocking fd" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // Repro for the EPOLL / URING body gap. The accepted fd is non-blocking, but body() reads the
    // remaining body with a posix.read loop that `catch break`s on the first EAGAIN. When the body is
    // split across TCP segments (only the first has arrived), the loop bails with a TRUNCATED body.
    // A writer thread delivers the first segment up front, then the rest a moment later, so a correct
    // read collects all 10 bytes while the current code returns only the first 3.
    const linux = std.os.linux;

    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer _ = linux.close(fds[0]);

    // server read end is non-blocking, matching the EPOLL / URING accept path
    const cur_flags = linux.fcntl(fds[0], std.posix.F.GETFL, 0);
    const nonblock_bit: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
    _ = linux.fcntl(fds[0], std.posix.F.SETFL, cur_flags | @as(usize, nonblock_bit));

    // first segment is already on the socket. The remaining bytes follow after a short delay
    try std.testing.expectEqual(@as(usize, 3), linux.write(fds[1], "abc", 3));

    const Writer = struct {
        fn run(w_fd: std.posix.fd_t) void {
            var delay = std.os.linux.timespec{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
            _ = std.os.linux.nanosleep(&delay, null);
            _ = std.os.linux.write(w_fd, "defghij", 7);
            _ = std.os.linux.close(w_fd);
        }
    };
    var writer = try std.Thread.spawn(.{}, Writer.run, .{fds[1]});
    defer writer.join();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const raw = "POST /post HTTP/1.1\r\nContent-Length: 10\r\n\r\n";
    const head = (try parser.parse(raw, parser.MAX_HEADERS_U8)).?;
    var req = Request{
        .buf = raw,
        .head = head,
        .fd = fds[0],
        .buf_filled = raw.len,
        .allocator = arena.allocator(),
    };

    const body = try req.body();

    try std.testing.expectEqualStrings("abcdefghij", body);
}

test "zix http: request chunked body must not truncate when chunks arrive in segments over a non-blocking fd" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // Same EPOLL / URING gap on the chunked path: readChunkedBody() reads until the terminal
    // "0\r\n\r\n" chunk, and must wait across segment boundaries instead of bailing at the first
    // EAGAIN. The writer delivers the terminator only in the second segment.
    const linux = std.os.linux;

    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer _ = linux.close(fds[0]);

    const cur_flags = linux.fcntl(fds[0], std.posix.F.GETFL, 0);
    const nonblock_bit: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
    _ = linux.fcntl(fds[0], std.posix.F.SETFL, cur_flags | @as(usize, nonblock_bit));

    // first segment: chunk size line + part of the payload, no terminator yet
    const seg1 = "a\r\nabcdef";
    try std.testing.expectEqual(@as(usize, seg1.len), linux.write(fds[1], seg1, seg1.len));

    const Writer = struct {
        fn run(w_fd: std.posix.fd_t) void {
            var delay = std.os.linux.timespec{ .sec = 0, .nsec = 50 * std.time.ns_per_ms };
            _ = std.os.linux.nanosleep(&delay, null);
            // rest of the payload + terminal zero chunk
            const seg2 = "ghij\r\n0\r\n\r\n";
            _ = std.os.linux.write(w_fd, seg2, seg2.len);
            _ = std.os.linux.close(w_fd);
        }
    };
    var writer = try std.Thread.spawn(.{}, Writer.run, .{fds[1]});
    defer writer.join();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const raw = "POST /post HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    const head = (try parser.parse(raw, parser.MAX_HEADERS_U8)).?;
    var req = Request{
        .buf = raw,
        .head = head,
        .fd = fds[0],
        .buf_filled = raw.len,
        .allocator = arena.allocator(),
    };

    const body = try req.body();

    try std.testing.expectEqualStrings("abcdefghij", body);
}

test "zix http: request body delivers a body far larger than the read buffer" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // zix.Http sizes the body allocation from Content-Length and reads until it
    // is filled, so the read buffer never caps what the handler sees. The .ASYNC
    // path of zix.Http1 truncates the delivered slice at its body chunk instead,
    // and the multiplexed models drop the body entirely, so this is the contract
    // that separates the two engines.
    const linux = std.os.linux;

    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const body_len: usize = 64 * 1024;
    const payload = try arena.allocator().alloc(u8, body_len);
    @memset(payload, 'A');
    try std.testing.expectEqual(body_len, linux.write(fds[1], payload.ptr, body_len));

    const raw = "POST /upload HTTP/1.1\r\nContent-Length: 65536\r\n\r\n";
    const head = (try parser.parse(raw, parser.MAX_HEADERS_U8)).?;
    var req = Request{
        .buf = raw,
        .head = head,
        .fd = fds[0],
        .buf_filled = raw.len,
        .allocator = arena.allocator(),
    };

    const body = try req.body();

    try std.testing.expectEqual(body_len, body.len);
    try std.testing.expectEqual(@as(usize, body_len), std.mem.count(u8, body, "A"));
}

test "zix http: request body reports a short read when the peer closes before Content-Length" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    // The returned slice is what the keep-alive decision reads: a body shorter
    // than Content-Length still comes back as a successful read, so a caller
    // that trusts the length alone cannot tell the request was cut off.
    const linux = std.os.linux;

    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer _ = linux.close(fds[0]);

    try std.testing.expectEqual(@as(usize, 3), linux.write(fds[1], "abc", 3));
    _ = linux.close(fds[1]);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const raw = "POST /upload HTTP/1.1\r\nContent-Length: 10\r\n\r\n";
    const head = (try parser.parse(raw, parser.MAX_HEADERS_U8)).?;
    var req = Request{
        .buf = raw,
        .head = head,
        .fd = fds[0],
        .buf_filled = raw.len,
        .allocator = arena.allocator(),
    };

    const body = try req.body();

    try std.testing.expectEqualStrings("abc", body);
    try std.testing.expect(body.len < head.content_length);
}

test "zix http: request keepAlive reflects the parsed head" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    var req = try Request.fromRaw("GET / HTTP/1.1\r\nHost: x\r\n\r\n", arena.allocator());
    try std.testing.expect(req.keepAlive());

    var req_close = try Request.fromRaw("GET / HTTP/1.1\r\nConnection: close\r\n\r\n", arena.allocator());
    try std.testing.expect(!req_close.keepAlive());
}
