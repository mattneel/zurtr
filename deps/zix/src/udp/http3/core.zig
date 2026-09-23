//! zix HTTP/3 application handler surface.
//!
//! What:
//! - The request / response shapes the application handler sees, and the `HandlerFn` type the server
//!   facade bakes at comptime. The QUIC / packet machinery is internal: the handler works at the HTTP
//!   request level, the same altitude as the other zix engines.

const std = @import("std");
const builtin = @import("builtin");
const win_io = @import("../../utils/windows_io.zig");

const response = @import("response.zig");

/// The content coding a handler may set on its response body (`res.content_encoding`). Re-exported from
/// the wire layer so a handler names it as `zix.Http3.ContentEncoding` without reaching into internals.
pub const ContentEncoding = response.ContentEncoding;

/// Backing size of the per-request stack arena on Context.allocator. Stack-based
/// (std.heap.FixedBufferAllocator), no heap call.
pub const CTX_ARENA_BYTES: usize = 4096;

/// A decoded HTTP/3 request handed to the application handler. The slices point into the engine's
/// per-connection decode buffer and are valid only for the duration of the handler call.
pub const Request = struct {
    method: []const u8,
    path: []const u8,
    authority: []const u8 = "",
    /// The request body bytes handed to this handler, empty when the request carried none. This is the
    /// DATA, `bodyReceived()` is the COUNT, and `bodyComplete()` says whether the two agree.
    ///
    /// Note:
    /// - The slice borrows the connection decode buffer, like `path`, so copy it to keep it past the
    ///   handler call. Handing it straight to `res.send` is only safe for a response that fits one
    ///   packet, since a larger one is sent from the buffer after the next datagram has overwritten it.
    body: []const u8 = "",
    /// Body bytes the engine decoded off the wire for this request. Read through `bodyReceived()`.
    body_received: u64 = 0,
    /// Whether the client finished sending this request and `body` holds all of it. Read through
    /// `bodyComplete()`.
    body_complete: bool = true,
    /// The client's `accept-encoding` value, or empty when it sent none. A handler negotiates a
    /// pre-compressed body against it (for example serving a `.br` variant when it contains `br`) and
    /// sets `res.content_encoding` to match.
    accept_encoding: []const u8 = "",

    /// How many body bytes the engine decoded off the wire for this request, HTTP/3 framing excluded.
    /// Counted from the DATA frames that carried them, never from a `content-length` field, so a lying
    /// header cannot inflate it.
    ///
    /// Note:
    /// - This is the COUNT, `body` is the DATA. A handler that only needs the size (an upload receipt,
    ///   a metric) reads this and skips the bytes.
    /// - Equal to `body.len` means the handler was given every byte that arrived. A larger count means
    ///   bytes arrived that `body` does not hold, so any parse of `body` is working on a fragment.
    /// - zix.Http1 and zix.Http answer the same question under the same name.
    ///
    /// Return:
    /// - u64 (counted received body bytes)
    pub fn bodyReceived(self: Request) u64 {
        return self.body_received;
    }

    /// Whether the client finished sending this request and every byte it sent is in `body`.
    ///
    /// Note:
    /// - False means the bytes in `body` are real but the request promised more: the client had not
    ///   ended the QUIC stream, or it split the body across DATA frames or datagrams and only the
    ///   first part is delivered. Check this before parsing a body as a whole document.
    /// - This engine decodes one datagram at a time, so a body larger than a datagram reads false.
    ///   Rejecting the request (413) or answering from what arrived is the handler's call.
    /// - True for a request that carried no body, since a conforming client ends the stream with its
    ///   HEADERS (RFC 9114 4.1) and there is nothing to fall short of.
    /// - zix.Http1 answers the same question under the same name.
    ///
    /// Usage:
    /// ```zig
    /// fn uploadHandler(req: *const Request, res: *Response, _: *Context) !void {
    ///     if (!req.bodyComplete()) {
    ///         res.setStatus(400);
    ///         res.send("incomplete body");
    ///
    ///         return;
    ///     }
    ///
    ///     res.send(req.body);
    /// }
    /// ```
    ///
    /// Return:
    /// - bool
    pub fn bodyComplete(self: Request) bool {
        return self.body_complete;
    }
};

/// The response the handler fills. The body is copied into the engine's send path after the handler
/// returns, so it may point at handler-owned or static memory.
pub const Response = struct {
    status: u16 = 200,
    body: []const u8 = "",
    /// Content type. A handler may set it, but the v1 HTTP/3 response path does not emit it on the
    /// wire yet (only `:status` and `content-encoding` are QPACK-encoded). Kept for the handler API
    /// and for when it is wired.
    content_type: []const u8 = "text/plain",

    /// The content coding of `body`. When not identity the serve path emits a `content-encoding`
    /// response header (RFC 9114 4.1). The handler owns the coding: `body` must already be encoded
    /// with it (the engine never compresses on the send path).
    content_encoding: ContentEncoding = .identity,

    /// Whether `send` has been called. Read by `invokeHandler` to decide whether a handler error still
    /// gets an auto-500, so an intentionally sent response is never overwritten.
    sent: bool = false,

    /// Set the HTTP status code.
    pub fn setStatus(self: *Response, status: u16) void {
        self.status = status;
    }

    /// Set the response body.
    pub fn send(self: *Response, body: []const u8) void {
        self.body = body;
        self.sent = true;
    }

    /// Set the content coding of the body (the handler must have encoded `body` accordingly).
    pub fn setContentEncoding(self: *Response, encoding: ContentEncoding) void {
        self.content_encoding = encoding;
    }
};

/// The per-request env: deadline and the io/allocator carried for symmetry with the other engines'
/// Context. HTTP/3 has no per-request fd (QUIC multiplexes many requests per connection), so
/// `stream_id` is the raw escape hatch.
pub const Context = struct {
    /// QUIC request stream id this call was decoded from.
    stream_id: u64,
    /// Absolute deadline in nanoseconds (wall clock). Null = no deadline.
    /// Set at dispatch from the server-wide handler_timeout_ms. Handler may read and overwrite.
    deadline_ns: ?u64 = null,
    /// Io backend for the connection. Carried for symmetry with the other engines' Context.
    io: std.Io,
    /// Per-request scratch allocator, backed by a stack buffer (no heap call).
    allocator: std.mem.Allocator,
    /// Static file directory set by the server from config.public_dir. Empty disables the router's
    /// static fallback, so an unmatched route goes straight to 404.
    public_dir: []const u8 = "",
    /// Cache slot backing the response body, when the router served a static file. The pin is held
    /// past the handler because the body has to outlive it, so the engine releases it when the send
    /// stream retires (or immediately, when the whole response fitted one packet).
    static_slot: ?u32 = null,

    /// Return a copy with the deadline set to now + ms.
    pub fn withTimeout(self: Context, ms: u64) Context {
        var ctx = self;
        ctx.deadline_ns = wallClockNs() + ms * std.time.ns_per_ms;

        return ctx;
    }

    /// Set the deadline to now + ms in place.
    pub fn setTimeout(self: *Context, ms: u64) void {
        self.deadline_ns = wallClockNs() + ms * std.time.ns_per_ms;
    }

    /// Return a copy with an explicit absolute deadline (wall-clock nanoseconds).
    pub fn withDeadline(self: Context, deadline_ns: u64) Context {
        var ctx = self;
        ctx.deadline_ns = deadline_ns;

        return ctx;
    }

    /// Whether the deadline has passed. False when no deadline is set.
    pub fn isExpired(self: *const Context) bool {
        return self.timedOut();
    }

    /// Whether the deadline has passed. False when no deadline is set. The
    /// handler must check this explicitly, it does not interrupt anything.
    pub fn timedOut(self: *const Context) bool {
        const deadline = self.deadline_ns orelse return false;

        return wallClockNs() >= deadline;
    }
};

/// Return the current wall-clock time in nanoseconds (Unix epoch basis).
pub fn wallClockNs() u64 {
    if (comptime builtin.target.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
        return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
    }

    if (comptime builtin.target.os.tag == .windows) return win_io.wallClockNs();

    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

/// The application request handler, baked into the server type at comptime.
pub const HandlerFn = *const fn (req: *const Request, res: *Response, ctx: *Context) anyerror!void;

/// Build the Context and invoke the handler. A handler error is completed as one auto-500, but only
/// when the handler wrote nothing, so an intentionally sent response is never overwritten.
///
/// Param:
/// handler - HandlerFn (built via Router(&[_]Route{...}).dispatch or a bare handler)
/// req - Request (already decoded by the caller)
/// res - Response (defaults, filled by the handler)
/// stream_id - u64 (QUIC request stream id, carried on Context as the raw escape hatch)
/// io - std.Io (carried on Context for symmetry with the other engines)
/// deadline_ns - ?u64 (seeded from config.handler_timeout_ms by the caller)
/// public_dir - []const u8 (static root, carried onto Context so the router can reach it)
///
/// Return:
/// - ?u32 (static cache slot still pinned for this response, which the caller MUST release once the
///   body has been sent. null when the response did not come from a static file)
pub inline fn invokeHandler(handler: HandlerFn, req: *const Request, res: *Response, stream_id: u64, io: std.Io, deadline_ns: ?u64, public_dir: []const u8) ?u32 {
    var arena_buf: [CTX_ARENA_BYTES]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
    var ctx = Context{ .stream_id = stream_id, .deadline_ns = deadline_ns, .io = io, .allocator = fba.allocator(), .public_dir = public_dir };

    handler(req, res, &ctx) catch {
        if (!res.sent) {
            res.status = 500;
            res.body = "";
        }
    };

    return ctx.static_slot;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn echoHandler(req: *const Request, res: *Response, ctx: *Context) !void {
    _ = ctx;
    res.setStatus(200);
    res.send(req.path);
}

// A handler that serves a pre-compressed brotli variant when the client accepts br, else identity: the
// content-negotiation shape the static routes use.
fn negotiateHandler(req: *const Request, res: *Response, ctx: *Context) !void {
    _ = ctx;
    if (std.mem.indexOf(u8, req.accept_encoding, "br") != null) {
        res.setContentEncoding(.br);
        res.send("<brotli-bytes>");
    } else {
        res.send("<identity-bytes>");
    }
}

// Scratch the body handler formats its answer into, so the slice it sends outlives the handler call
// the way a real handler's does.
threadlocal var body_reply_buf: [64]u8 = undefined;

// A handler that answers from the request body and reports how many bytes of it arrived: the POST
// shape that used to read empty on this engine, whatever the client sent.
fn bodyEchoHandler(req: *const Request, res: *Response, ctx: *Context) !void {
    _ = ctx;
    res.send(std.fmt.bufPrint(&body_reply_buf, "{d}:{s}", .{ req.bodyReceived(), req.body }) catch "0:");
}

fn erroringHandler(req: *const Request, res: *Response, ctx: *Context) !void {
    _ = req;
    _ = res;
    _ = ctx;
    return error.ZixBoom;
}

fn erroringAfterSendHandler(req: *const Request, res: *Response, ctx: *Context) !void {
    _ = req;
    _ = ctx;
    res.send("partial");
    return error.ZixBoom;
}

test "zix http3: Response setters and handler shape" {
    const req = Request{ .method = "GET", .path = "/hello", .authority = "example.com" };
    var res = Response{};
    var ctx = Context{ .stream_id = 0, .io = undefined, .allocator = std.testing.allocator };
    try echoHandler(&req, &res, &ctx);

    try std.testing.expectEqual(@as(u16, 200), res.status);
    try std.testing.expectEqualSlices(u8, "/hello", res.body);
    try std.testing.expectEqualSlices(u8, "text/plain", res.content_type);
    try std.testing.expectEqual(ContentEncoding.identity, res.content_encoding);
    try std.testing.expect(res.sent);
}

test "zix http3: a handler negotiates content-encoding off the request accept-encoding" {
    var ctx = Context{ .stream_id = 0, .io = undefined, .allocator = std.testing.allocator };

    var br_res = Response{};
    try negotiateHandler(&.{ .method = "GET", .path = "/x", .accept_encoding = "gzip, deflate, br" }, &br_res, &ctx);
    try std.testing.expectEqual(ContentEncoding.br, br_res.content_encoding);
    try std.testing.expectEqualSlices(u8, "<brotli-bytes>", br_res.body);

    var plain_res = Response{};
    try negotiateHandler(&.{ .method = "GET", .path = "/x" }, &plain_res, &ctx);
    try std.testing.expectEqual(ContentEncoding.identity, plain_res.content_encoding);
}

test "zix http3: a handler answers from the request body and the count that came with it" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const req = Request{ .method = "POST", .path = "/upload", .body = "20", .body_received = 2 };
    var res = Response{};
    _ = invokeHandler(bodyEchoHandler, &req, &res, 0, io, null, "");

    // The body reached the handler, which is the whole point: an empty one here is the defect this
    // pins, a 200 computed as if the client had sent nothing.
    try std.testing.expectEqualSlices(u8, "2:20", res.body);
    try std.testing.expectEqual(@as(u16, 200), res.status);
}

test "zix http3: a Request with no body reports nothing received and nothing missing" {
    const req = Request{ .method = "GET", .path = "/" };

    try std.testing.expectEqual(@as(usize, 0), req.body.len);
    try std.testing.expectEqual(@as(u64, 0), req.bodyReceived());
    try std.testing.expect(req.bodyComplete());
}

test "zix http3: a Request delivered short reports more received than it hands over" {
    // What the engine builds when the client split its body: the first DATA frame is delivered, the
    // count covers every frame, and the pair is what tells a handler it is holding a fragment.
    const req = Request{ .method = "POST", .path = "/upload", .body = "20", .body_received = 4, .body_complete = false };

    try std.testing.expectEqual(@as(u64, 4), req.bodyReceived());
    try std.testing.expect(req.bodyReceived() != req.body.len);
    try std.testing.expect(!req.bodyComplete());
}

test "zix http3: invokeHandler auto-500s when the handler errors and sent nothing" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const req = Request{ .method = "GET", .path = "/boom" };
    var res = Response{};
    _ = invokeHandler(erroringHandler, &req, &res, 0, io, null, "");

    try std.testing.expectEqual(@as(u16, 500), res.status);
    try std.testing.expectEqualSlices(u8, "", res.body);
}

test "zix http3: invokeHandler keeps a partially sent response on handler error" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const req = Request{ .method = "GET", .path = "/partial" };
    var res = Response{};
    _ = invokeHandler(erroringAfterSendHandler, &req, &res, 0, io, null, "");

    try std.testing.expectEqual(@as(u16, 200), res.status);
    try std.testing.expectEqualSlices(u8, "partial", res.body);
}

test "zix http3: Context.withTimeout, withDeadline, and timedOut" {
    const base = Context{ .stream_id = 0, .io = undefined, .allocator = std.testing.allocator };

    try std.testing.expect(!base.isExpired());
    try std.testing.expect(!base.timedOut());

    const future = base.withTimeout(60_000);
    try std.testing.expect(future.deadline_ns != null);
    try std.testing.expect(!future.timedOut());

    const past = base.withDeadline(1);
    try std.testing.expect(past.timedOut());
    try std.testing.expect(past.isExpired());
}

test "zix http3: Context.setTimeout mutates the deadline in place" {
    var ctx = Context{ .stream_id = 0, .io = undefined, .allocator = std.testing.allocator };

    try std.testing.expect(ctx.deadline_ns == null);

    ctx.setTimeout(60_000);

    try std.testing.expect(ctx.deadline_ns != null);
    try std.testing.expect(!ctx.timedOut());
}
