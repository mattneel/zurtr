//! zix http1 request: a zero-copy view over the connection receive buffer for
//! the ergonomic req, res, ctx handler shape. Every slice it returns borrows
//! the receive buffer and is valid only for the handler call. The body is
//! already drained by the engine before the handler runs, so body() returns a
//! slice without touching the socket.

const std = @import("std");
const core = @import("core.zig");
const router = @import("router.zig");
const Method = @import("method.zig");

pub const Request = struct {
    /// Parsed request head. Every slice in it borrows the receive buffer.
    head: *const core.ParsedHead,
    /// Request body bytes, already drained by the engine. Empty when there is
    /// none. Handlers read it through body().
    body_bytes: []const u8,
    /// Connection fd, the raw escape hatch.
    fd: std.posix.fd_t,
    /// Path parameters captured by a PARAM route. The async lane copies them in
    /// at handoff, because the router threadlocal is not valid once a fiber
    /// resumes. The sync path leaves this empty and pathParam() reads the router
    /// threadlocal directly.
    path_params: []const router.PathParam = &.{},
    /// Body bytes consumed off the socket for this request, counted by the
    /// engine from the reads that took them. Equals body().len when the body fit
    /// the receive buffer. Past that every dispatch model counts the drained
    /// remainder here too. Handlers read it through bodyReceived().
    body_received: u64 = 0,
    /// Whether the engine read the body to its end. True for a request that
    /// declared no body, since there was nothing to fall short of. Handlers read
    /// it through bodyComplete().
    body_complete: bool = true,

    /// Build a request view over a parsed head, body, and fd.
    ///
    /// Note:
    /// - The defaults describe a body that arrived whole and fits the delivered
    ///   slice, which is every request the engine did not have to measure. A
    ///   dispatch model that drained or cut a body overrides both fields through
    ///   core.tl_body_info.
    ///
    /// Param:
    /// head - *const core.ParsedHead (borrows the receive buffer)
    /// body_data - []const u8 (already drained by the engine, empty when none)
    /// fd - std.posix.fd_t (the connection)
    ///
    /// Return:
    /// - Request
    pub fn init(head: *const core.ParsedHead, body_data: []const u8, fd: std.posix.fd_t) Request {
        return .{ .head = head, .body_bytes = body_data, .fd = fd, .body_received = body_data.len };
    }

    /// The HTTP method as the typed code. An unknown or oversized method token
    /// maps to GET (the Method.enumFromString contract).
    pub fn method(self: Request) Method.Code {
        if (self.head.method.len > 8) return .GET;

        return Method.enumFromString(self.head.method);
    }

    /// The path without the query string.
    pub fn path(self: Request) []const u8 {
        return self.head.path;
    }

    /// The raw query string after the "?", or empty.
    pub fn query(self: Request) []const u8 {
        return self.head.query;
    }

    /// One query parameter value, or null.
    pub fn queryParam(self: Request, name: []const u8) ?[]const u8 {
        return core.queryParam(self.head, name);
    }

    /// One request header value by name (case-insensitive), or null.
    pub fn header(self: Request, name: []const u8) ?[]const u8 {
        return core.getHeader(self.head, name);
    }

    /// A path parameter captured by a PARAM route, or null. Reads the request's
    /// own captured set first (async lane), then falls back to the router
    /// threadlocal (sync path).
    pub fn pathParam(self: Request, name: []const u8) ?[]const u8 {
        for (self.path_params) |path_param| {
            if (std.mem.eql(u8, path_param.name, name)) return path_param.value;
        }

        return router.pathParam(name);
    }

    /// The body bytes handed to this handler. Identical call shape to zix.Http.
    /// The engine already took the body off the socket before the handler ran,
    /// so this never reads the socket and never blocks.
    ///
    /// Note:
    /// - This is the DATA. bodyReceived() is the COUNT of what came off the
    ///   socket. They answer different questions, see bodyReceived().
    /// - The slice borrows the connection receive buffer and is only valid for
    ///   the duration of the handler call. Copy it to keep it.
    /// - Empty when the request declared no body, and also when the engine
    ///   could not deliver one (a body past the receive buffer is discarded).
    ///
    /// Return:
    /// - []const u8 (the engine-delivered body slice, empty when none)
    pub fn body(self: *Request) ![]const u8 {
        return self.body_bytes;
    }

    /// How many body bytes the engine took off the socket for this request.
    /// Counted from the reads that received them, never read from the
    /// Content-Length header, so a lying header cannot inflate it.
    ///
    /// Note:
    /// - This is the COUNT. body() is the DATA. A handler that only needs the
    ///   size (an upload receipt, a metric) reads this and skips the bytes.
    /// - bodyReceived() == body().len means the handler was given everything.
    ///   A larger count means bytes arrived that body() does not contain, so
    ///   any parse of body() is working on a fragment.
    /// - The two are equal whenever the body fit the receive buffer.
    /// - Past the receive buffer every dispatch model counts the drained
    ///   remainder as well, so the same request reports the same number on all
    ///   three and one handler can be written against any of them. That holds
    ///   for a body that arrived whole. One the peer cut short never reaches a
    ///   handler on .EPOLL or .URING, see bodyComplete().
    /// - For a chunked body this counts the wire bytes, framing included, so it
    ///   is larger than body().len by the size of that framing.
    ///
    /// Return:
    /// - u64 (counted received body bytes)
    pub fn bodyReceived(self: Request) u64 {
        return self.body_received;
    }

    /// Whether the engine read this request's body all the way to its end: the
    /// declared Content-Length, or the chunked terminator.
    ///
    /// Note:
    /// - False means the peer stopped sending part way. The bytes in body() are
    ///   real, there are just fewer of them than the request promised, so an
    ///   upload that looks small may be a large one that was cut off.
    /// - Only .ASYNC ever reports false. It reads the body inline and runs the
    ///   handler with whatever arrived. .EPOLL and .URING hold the request until
    ///   its body is whole, so a peer that quits part way never reaches a
    ///   handler there: the engine answers 400 with Connection: close itself and
    ///   drops the request. This reads true on both by construction.
    /// - True for a request that declared no body, since there was nothing to
    ///   fall short of.
    /// - True does not mean the handler was given every byte. A body past the
    ///   receive buffer arrives complete and is delivered short, which is what
    ///   bodyReceived() against body().len tells apart.
    /// - Connection safety does not depend on this. A body only falls short when
    ///   the peer stopped sending, and the serve loop ends on the next read.
    ///   This is for the handler's own decision: reject the upload, log it, bill
    ///   the bytes that did arrive.
    /// - zix.Http answers the same question with the same name, with one extra
    ///   case: there the body is read lazily, so a handler that never calls
    ///   body() leaves it unread and this reads false.
    ///
    /// Usage:
    /// ```zig
    /// // The guard runs on .ASYNC. On .EPOLL and .URING the engine already
    /// // refused the cut-short upload, so the handler only sees whole ones and
    /// // the branch is never taken.
    /// fn uploadHandler(req: *Request, res: *Response, _: *Context) !void {
    ///     if (!req.bodyComplete()) {
    ///         res.setStatus(.BAD_REQUEST);
    ///         try res.send("incomplete body");
    ///
    ///         return;
    ///     }
    ///
    ///     var buf: [32]u8 = undefined;
    ///     try res.send(try std.fmt.bufPrint(&buf, "{d}", .{req.bodyReceived()}));
    /// }
    /// ```
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

    /// Split the request path into non-empty segments.
    pub fn pathSegments(self: Request, allocator: std.mem.Allocator) ![][]const u8 {
        var list: std.ArrayList([]const u8) = .empty;

        var iter = std.mem.splitScalar(u8, self.path(), '/');
        while (iter.next()) |segment| {
            if (segment.len > 0) try list.append(allocator, segment);
        }

        return list.items;
    }

    pub const QueryParam = struct {
        key: []const u8,
        value: ?[]const u8,
    };

    /// Get all query parameters as a slice of QueryParam.
    pub fn queryParams(self: Request, allocator: std.mem.Allocator) ![]QueryParam {
        const query_str = self.query();
        if (query_str.len == 0) return &.{};

        var list: std.ArrayList(QueryParam) = .empty;
        var pos: usize = 0;
        while (pos < query_str.len) {
            const amp_pos = std.mem.indexOfScalarPos(u8, query_str, pos, '&') orelse query_str.len;
            const pair = query_str[pos..amp_pos];
            if (pair.len > 0) {
                if (std.mem.indexOfScalar(u8, pair, '=')) |eq_pos| {
                    const value = pair[eq_pos + 1 ..];
                    try list.append(allocator, .{
                        .key = pair[0..eq_pos],
                        .value = if (value.len > 0) value else null,
                    });
                } else {
                    try list.append(allocator, .{ .key = pair, .value = null });
                }
            }
            if (amp_pos >= query_str.len) break;
            pos = amp_pos + 1;
        }

        return list.items;
    }

    /// Parse a complete raw HTTP/1.x head buffer into a Request.
    /// Useful for tests and offline parsing. buf must contain a full head
    /// (\r\n\r\n) and must outlive the Request (every slice borrows it). The
    /// parsed head is one small allocation from allocator.
    pub fn fromRaw(buf: []const u8, allocator: std.mem.Allocator) !Request {
        const result = try core.parseHead(buf);

        const head = try allocator.create(core.ParsedHead);
        head.* = result.head;

        const body_start = @min(result.body_offset, buf.len);
        return .{ .head = head, .body_bytes = buf[body_start..], .fd = if (@import("builtin").target.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1, .body_received = buf.len - body_start };
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http1: Request view exposes method, path, query" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const parsed = try core.parseHead("GET /users?active=1 HTTP/1.1\r\nHost: x\r\n\r\n");
    const req = Request.init(&parsed.head, "", 3);

    try std.testing.expect(req.method() == .GET);
    try std.testing.expectEqualStrings("/users", req.path());
    try std.testing.expectEqualStrings("active=1", req.query());
    try std.testing.expectEqual(@as(std.posix.fd_t, 3), req.fd);
    try std.testing.expect(req.keepAlive());
}

test "zix http1: an unimplemented method never reaches a Request" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    // The parser refuses these now, so no handler ever sees one mislabelled as a
    // GET. The caller answers 501 from the error instead.
    try std.testing.expectError(error.ZixUnknownMethod, core.parseHead("BREW /pot HTTP/1.1\r\n\r\n"));
    try std.testing.expectError(error.ZixUnknownMethod, core.parseHead("VERYLONGMETHOD /x HTTP/1.1\r\n\r\n"));

    const post = try core.parseHead("POST /x HTTP/1.1\r\n\r\n");
    const post_req = Request.init(&post.head, "", -1);
    try std.testing.expect(post_req.method() == .POST);
}

test "zix http1: Request method keeps its GET fallback for a hand-built head" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    // A Request built directly rather than parsed can still hold any token, so
    // the accessor keeps a total answer instead of a null a handler must unwrap.
    const parsed = try core.parseHead("GET /pot HTTP/1.1\r\n\r\n");
    var head = parsed.head;
    head.method = "BREW";

    const req = Request.init(&head, "", -1);
    try std.testing.expect(req.method() == .GET);
}

test "zix http1: Request queryParam and header lookups" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const parsed = try core.parseHead("GET /p?name=alice&age=30 HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n");
    const req = Request.init(&parsed.head, "", -1);

    try std.testing.expectEqualStrings("alice", req.queryParam("name").?);
    try std.testing.expectEqualStrings("30", req.queryParam("age").?);
    try std.testing.expect(req.queryParam("missing") == null);
    try std.testing.expectEqualStrings("text/plain", req.header("content-type").?);
}

test "zix http1: Request pathParam reads its own captured set first" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const parsed = try core.parseHead("GET /users/alice HTTP/1.1\r\n\r\n");
    const captured = [_]router.PathParam{.{ .name = "id", .value = "alice" }};
    const req = Request{ .head = &parsed.head, .body_bytes = "", .fd = -1, .path_params = &captured };

    try std.testing.expectEqualStrings("alice", req.pathParam("id").?);
    try std.testing.expect(req.pathParam("missing") == null);
}

test "zix http1: Request body returns the engine-delivered slice" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const parsed = try core.parseHead("POST /submit HTTP/1.1\r\nContent-Length: 5\r\n\r\n");
    var req = Request.init(&parsed.head, "hello", -1);

    try std.testing.expectEqualStrings("hello", try req.body());
    try std.testing.expect(req.method() == .POST);
}

test "zix http1: Request bodyReceived defaults to the body length and takes an engine override" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const parsed = try core.parseHead("POST /u HTTP/1.1\r\nContent-Length: 5\r\n\r\n");

    var req = Request.init(&parsed.head, "hello", -1);
    try std.testing.expectEqual(@as(u64, 5), req.bodyReceived());

    // A dispatch path that drained a larger body overrides the count.
    req.body_received = 100000;
    try std.testing.expectEqual(@as(u64, 100000), req.bodyReceived());

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const raw = try Request.fromRaw("POST /u HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc", arena.allocator());
    try std.testing.expectEqual(@as(u64, 3), raw.bodyReceived());
}

test "zix http1: Request bodyComplete defaults true and takes an engine override" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    const parsed = try core.parseHead("POST /u HTTP/1.1\r\nContent-Length: 5\r\n\r\n");

    // The default describes a body that arrived whole, which is every request
    // the engine had no reason to measure.
    var req = Request.init(&parsed.head, "hello", -1);
    try std.testing.expect(req.bodyComplete());

    // A peer that stopped part way is the only thing that clears it.
    req.body_complete = false;
    try std.testing.expect(!req.bodyComplete());

    // A delivered slice shorter than the count is a delivery cap, not a cut
    // upload, so the two answers stay independent.
    req.body_complete = true;
    req.body_received = 100000;
    try std.testing.expect(req.bodyComplete());
    try std.testing.expect(req.bodyReceived() != (try req.body()).len);
}

test "zix http1: Request pathSegments splits non-empty segments" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parsed = try core.parseHead("GET /api//users/42/ HTTP/1.1\r\n\r\n");
    const req = Request.init(&parsed.head, "", -1);

    const segments = try req.pathSegments(arena.allocator());
    try std.testing.expectEqual(@as(usize, 3), segments.len);
    try std.testing.expectEqualStrings("api", segments[0]);
    try std.testing.expectEqualStrings("users", segments[1]);
    try std.testing.expectEqualStrings("42", segments[2]);
}

test "zix http1: Request queryParams returns every pair, valueless keys null" {
    if (comptime @import("builtin").target.os.tag == .windows) {
        std.log.info("this test drives a POSIX descriptor, Windows handles are opaque, test skipped", .{});
        return;
    }

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const parsed = try core.parseHead("GET /q?name=alice&flag&empty= HTTP/1.1\r\n\r\n");
    const req = Request.init(&parsed.head, "", -1);

    const params = try req.queryParams(arena.allocator());
    try std.testing.expectEqual(@as(usize, 3), params.len);
    try std.testing.expectEqualStrings("name", params[0].key);
    try std.testing.expectEqualStrings("alice", params[0].value.?);
    try std.testing.expectEqualStrings("flag", params[1].key);
    try std.testing.expect(params[1].value == null);
    try std.testing.expectEqualStrings("empty", params[2].key);
    try std.testing.expect(params[2].value == null);
}

test "zix http1: Request fromRaw parses a raw buffer with body" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const raw = "POST /submit?src=test HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    var req = try Request.fromRaw(raw, arena.allocator());

    try std.testing.expect(req.method() == .POST);
    try std.testing.expectEqualStrings("/submit", req.path());
    try std.testing.expectEqualStrings("test", req.queryParam("src").?);
    try std.testing.expectEqualStrings("hello", try req.body());
}
