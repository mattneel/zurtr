//! zix http2 router: comptime EXACT + PREFIX path dispatch. No PARAM route kind this pass
//! (Http2 had none before ADR-063 either, added only if a later pass needs it).

const std = @import("std");
const builtin = @import("builtin");
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Context = @import("context.zig").Context;
const static = @import("static.zig");

// --------------------------------------------------------- //

pub const HandlerFn = *const fn (req: *Request, res: *Response, ctx: *Context) anyerror!void;

pub const RouteKind = enum(u8) { EXACT, PREFIX };

pub const Route = struct {
    path: []const u8,
    handler: HandlerFn,
    kind: RouteKind = .EXACT,
};

/// Build a router type whose dispatch table is fixed at compile time.
///
/// Note:
/// - EXACT routes go into a StaticStringMap for O(1) lookup, PREFIX routes into a comptime
///   array iterated with inline for at each dispatch call (longest match wins).
/// - The returned type exposes a single `dispatch` usable as a HandlerFn.
///
/// Param:
/// routes - []const Route (comptime-known route table)
///
/// Usage:
/// ```zig
/// const router = zix.Http2.Router(&[_]zix.Http2.Route{
///     .{ .path = "/", .handler = homeHandler },
///     .{ .path = "/static", .handler = staticHandler, .kind = .PREFIX },
/// });
/// var server = zix.Http2.Server.init(router.dispatch, .{ .io = io, .ip = "0.0.0.0", .port = 8082, .dispatch_model = .ASYNC });
/// try server.run();
/// ```
pub fn Router(comptime routes: []const Route) type {
    const exact_count = blk: {
        var n: usize = 0;
        for (routes) |r| if (r.kind == .EXACT) {
            n += 1;
        };
        break :blk n;
    };
    const prefix_count = blk: {
        var n: usize = 0;
        for (routes) |r| if (r.kind == .PREFIX) {
            n += 1;
        };
        break :blk n;
    };

    const exact_pairs: [exact_count]struct { []const u8, HandlerFn } = blk: {
        var arr: [exact_count]struct { []const u8, HandlerFn } = undefined;
        var i: usize = 0;
        for (routes) |r| {
            if (r.kind == .EXACT) {
                arr[i] = .{ r.path, r.handler };
                i += 1;
            }
        }
        break :blk arr;
    };

    const prefix_routes: [prefix_count]Route = blk: {
        var arr: [prefix_count]Route = undefined;
        var i: usize = 0;
        for (routes) |r| {
            if (r.kind == .PREFIX) {
                arr[i] = r;
                i += 1;
            }
        }
        break :blk arr;
    };

    const exact_map = std.StaticStringMap(HandlerFn).initComptime(exact_pairs);

    return struct {
        /// Dispatch the request to the best matching route. Usable as a HandlerFn.
        ///
        /// Note:
        /// - Pass 1 exact: O(1) comptime-built hash lookup
        /// - Pass 2 prefix: longest matching prefix wins
        /// - Unknown paths get 404 text/plain.
        pub fn dispatch(req: *Request, res: *Response, ctx: *Context) anyerror!void {
            const p = req.path;

            // Pass 1: exact, O(1) hash lookup
            if (exact_map.get(p)) |handler| {
                return handler(req, res, ctx);
            }

            // Pass 2: prefix (longest match wins)
            var best_len: usize = 0;
            var best_handler: ?HandlerFn = null;
            inline for (prefix_routes) |route| {
                if (std.mem.startsWith(u8, p, route.path)) {
                    const at_boundary = p.len == route.path.len or p[route.path.len] == '/';
                    if (at_boundary and route.path.len > best_len) {
                        best_len = route.path.len;
                        best_handler = route.handler;
                    }
                }
            }

            if (best_handler) |handler| {
                return handler(req, res, ctx);
            }

            // Static file fallback: when public_dir is configured, try to serve the request path
            // as a file before returning 404. Disabled when public_dir is empty.
            if (ctx.public_dir.len > 0) {
                const stripped = if (p.len > 0 and p[0] == '/') p[1..] else p;
                if (stripped.len > 0 and static.serve(req, ctx, stripped, ctx.max_frame_size)) {
                    res.sent = true;

                    return;
                }
            }

            res.setStatus(404);

            try res.sendText("Not Found");
        }
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

fn mockHandler(req: *Request, res: *Response, ctx: *Context) anyerror!void {
    _ = req;
    _ = res;
    _ = ctx;
}

/// Test fd sentinel: Windows descriptors are opaque pointers, POSIX are ints.
const TEST_FD: std.posix.fd_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;

test "zix http2: router comptime" {
    const TestRouter = Router(&[_]Route{
        .{ .path = "/about", .handler = mockHandler },
        .{ .path = "/api", .handler = mockHandler, .kind = .PREFIX },
    });
    _ = TestRouter;
}

test "zix http2: dispatch, exact match routes to handler" {
    const called = struct {
        var count: u32 = 0;
        fn handler(_: *Request, _: *Response, _: *Context) anyerror!void {
            count += 1;
        }
    };

    const router = Router(&[_]Route{
        .{ .path = "/about", .handler = called.handler },
    });

    var req = Request{ .method = "GET", .path = "/about", .query = "", .headers = &.{}, .body = "" };
    var res = Response{ .fd = TEST_FD, .sid = 1 };
    var ctx = Context{ .fd = TEST_FD, .sid = 1, .io = undefined, .allocator = std.testing.allocator };

    try router.dispatch(&req, &res, &ctx);
    try std.testing.expectEqual(@as(u32, 1), called.count);
}

test "zix http2: dispatch, EXACT wins over PREFIX and longest prefix wins" {
    const hit = struct {
        var id: u8 = 0;
    };
    const Handlers = struct {
        fn make(comptime route_id: u8) HandlerFn {
            return struct {
                fn handle(_: *Request, _: *Response, _: *Context) anyerror!void {
                    hit.id = route_id;
                }
            }.handle;
        }
    };

    const router = Router(&[_]Route{
        .{ .path = "/json", .handler = Handlers.make(1) },
        .{ .path = "/json", .handler = Handlers.make(2), .kind = .PREFIX },
        .{ .path = "/json/special", .handler = Handlers.make(3), .kind = .PREFIX },
    });

    var res = Response{ .fd = TEST_FD, .sid = 1 };
    var ctx = Context{ .fd = TEST_FD, .sid = 1, .io = undefined, .allocator = std.testing.allocator };

    // EXACT "/json" beats the "/json" PREFIX for the bare path.
    hit.id = 0;
    var req_exact = Request{ .method = "GET", .path = "/json", .query = "", .headers = &.{}, .body = "" };
    try router.dispatch(&req_exact, &res, &ctx);
    try std.testing.expectEqual(@as(u8, 1), hit.id);

    // Longest matching prefix wins for a deeper path.
    hit.id = 0;
    var req_deep = Request{ .method = "GET", .path = "/json/special/x", .query = "", .headers = &.{}, .body = "" };
    try router.dispatch(&req_deep, &res, &ctx);
    try std.testing.expectEqual(@as(u8, 3), hit.id);
}

test "zix http2: dispatch, prefix does not match a path that merely starts with the same bytes" {
    const called = struct {
        var count: u32 = 0;
        fn handler(_: *Request, _: *Response, _: *Context) anyerror!void {
            count += 1;
        }
    };
    called.count = 0;

    const router = Router(&[_]Route{
        .{ .path = "/api", .handler = called.handler, .kind = .PREFIX },
    });

    var req = Request{ .method = "GET", .path = "/apiv2", .query = "", .headers = &.{}, .body = "" };
    var res = Response{ .fd = TEST_FD, .sid = 1 };
    var ctx = Context{ .fd = TEST_FD, .sid = 1, .io = undefined, .allocator = std.testing.allocator };

    // No route matches, so dispatch falls through to the 404 send: needs a real fd.
    if (comptime @import("builtin").target.os.tag == .linux) {
        var fds: [2]i32 = undefined;
        try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
        defer _ = std.os.linux.close(fds[0]);
        defer _ = std.os.linux.close(fds[1]);
        res.fd = fds[1];

        try router.dispatch(&req, &res, &ctx);
        try std.testing.expectEqual(@as(u32, 0), called.count);
        try std.testing.expectEqual(@as(u16, 404), res.status);
    }
}
