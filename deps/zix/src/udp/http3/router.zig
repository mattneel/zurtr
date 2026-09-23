//! zix HTTP/3 comptime router: EXACT, PREFIX, and PARAM matching over the request path, mirroring the
//! Http1 / Http2 routers but on the HTTP/3 request / response handler shape (this layer dispatches a
//! decoded request to a `fn(req, res)` handler, not an fd).
//!
//! Note:
//! - Matching is on the path before the query string, so a route `/baseline2` matches a request to
//!   `/baseline2?a=1&b=1` (the handler reads the query from `req.path`).

const std = @import("std");

const core = @import("core.zig");
const static = @import("static.zig");

pub const RouteKind = enum(u8) { EXACT, PREFIX, PARAM };

pub const Route = struct {
    path: []const u8,
    handler: core.HandlerFn,
    kind: RouteKind = .EXACT,
};

/// One matched path parameter (e.g. `:id` -> "alice"). File-private: `pathParam` returns the value
/// slice, this struct is only the internal `tl_params` element type.
const PathParam = struct {
    name: []const u8,
    value: []const u8,
};

/// Upper bound on `:params` captured from a single PARAM route.
const MAX_PATH_PARAMS: usize = 8;

/// Per-request param store. Thread-local because each worker serves one request at a time. Values
/// are slices into the request path and stay valid only for the dispatch call.
threadlocal var tl_params: [MAX_PATH_PARAMS]PathParam = undefined;
threadlocal var tl_param_count: usize = 0;

/// Look up a path parameter captured by the matched PARAM route. Only valid inside a handler reached
/// via a PARAM route, the returned slice borrows the request path and dies with the call.
pub fn pathParam(name: []const u8) ?[]const u8 {
    for (tl_params[0..tl_param_count]) |p| {
        if (std.mem.eql(u8, p.name, name)) return p.value;
    }

    return null;
}

/// Build a router type whose dispatch table is fixed at compile time.
///
/// Note:
/// - EXACT routes go into a StaticStringMap for O(1) lookup, PARAM and PREFIX routes into comptime
///   arrays iterated with inline for at each dispatch call.
/// - Dispatch priority: EXACT > PARAM (first-registered wins) > PREFIX (longest wins).
/// - The returned type exposes a single `dispatch` usable as a HandlerFn.
///
/// Usage:
/// ```zig
/// const R = zix.Http3.Router(&[_]zix.Http3.Route{
///     .{ .path = "/", .handler = homeHandler },
///     .{ .path = "/static", .handler = staticHandler, .kind = .PREFIX },
///     .{ .path = "/users/:id", .handler = userHandler, .kind = .PARAM },
/// });
///
/// fn homeHandler(req: *const zix.Http3.Request, res: *zix.Http3.Response, ctx: *zix.Http3.Context) !void {
///     res.send("home");
/// }
///
/// var server = zix.Http3.Server.init(R.dispatch, config);
/// ```
///
/// Return:
/// - type
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
    const param_count = blk: {
        var n: usize = 0;
        for (routes) |r| if (r.kind == .PARAM) {
            n += 1;
        };
        break :blk n;
    };

    const exact_pairs: [exact_count]struct { []const u8, core.HandlerFn } = blk: {
        var arr: [exact_count]struct { []const u8, core.HandlerFn } = undefined;
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

    const param_routes: [param_count]Route = blk: {
        var arr: [param_count]Route = undefined;
        var i: usize = 0;
        for (routes) |r| {
            if (r.kind == .PARAM) {
                arr[i] = r;
                i += 1;
            }
        }
        break :blk arr;
    };

    const exact_map = std.StaticStringMap(core.HandlerFn).initComptime(exact_pairs);

    return struct {
        /// Dispatch the request to the best matching route. Usable as a HandlerFn. Unknown paths get
        /// a 404 text/plain response.
        pub fn dispatch(req: *const core.Request, res: *core.Response, ctx: *core.Context) !void {
            tl_param_count = 0;

            // Match on the path before the query string.
            const query_at = std.mem.indexOfScalar(u8, req.path, '?');
            const p = if (query_at) |i| req.path[0..i] else req.path;

            // Pass 1: exact, O(1) hash lookup.
            if (exact_map.get(p)) |handler| {
                return handler(req, res, ctx);
            }

            // Pass 2: parameterized (first match wins).
            inline for (param_routes) |route| {
                if (matchParam(route.path, p)) {
                    return route.handler(req, res, ctx);
                }
            }

            // Pass 3: prefix (longest match wins).
            var best_len: usize = 0;
            var best_handler: ?core.HandlerFn = null;
            inline for (prefix_routes) |route| {
                if (std.mem.startsWith(u8, p, route.path)) {
                    const at_boundary = p.len == route.path.len or p[route.path.len] == '/';
                    if (at_boundary and route.path.len > best_len) {
                        best_len = route.path.len;
                        best_handler = route.handler;
                    }
                }
            }

            if (best_handler) |h| {
                return h(req, res, ctx);
            }

            // Static file fallback: when public_dir is configured, try to serve the request path as
            // a file before returning 404. Disabled when public_dir is empty.
            if (ctx.public_dir.len > 0) {
                const stripped = if (p.len > 0 and p[0] == '/') p[1..] else p;
                if (stripped.len > 0 and static.serve(req, res, ctx, stripped)) return;
            }

            res.setStatus(404);
            res.send("Not Found");
        }
    };
}

/// Match a parameterized pattern against a concrete path. On success, fills the thread-local param
/// store and returns true.
fn matchParam(pattern: []const u8, path: []const u8) bool {
    var pat_it = std.mem.splitScalar(u8, pattern, '/');
    var path_it = std.mem.splitScalar(u8, path, '/');
    var count: usize = 0;

    while (true) {
        const pat_seg = pat_it.next();
        const path_seg = path_it.next();
        if (pat_seg == null and path_seg == null) break;
        if (pat_seg == null or path_seg == null) return false;

        const pat_token = pat_seg.?;
        const path_token = path_seg.?;
        if (std.mem.startsWith(u8, pat_token, ":")) {
            if (path_token.len == 0) return false;
            if (count >= MAX_PATH_PARAMS) return false;

            tl_params[count] = .{ .name = pat_token[1..], .value = path_token };
            count += 1;
        } else {
            if (!std.mem.eql(u8, pat_token, path_token)) return false;
        }
    }

    tl_param_count = count;
    return true;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn homeHandler(_: *const core.Request, res: *core.Response, _: *core.Context) !void {
    res.send("home");
}

fn usersHandler(_: *const core.Request, res: *core.Response, _: *core.Context) !void {
    res.send(pathParam("id") orelse "none");
}

fn staticHandler(_: *const core.Request, res: *core.Response, _: *core.Context) !void {
    res.send("static");
}

test "zix http3: http3 router matchParam captures params" {
    try std.testing.expect(matchParam("/users/:id", "/users/alice"));
    try std.testing.expectEqualStrings("alice", pathParam("id").?);
    try std.testing.expect(!matchParam("/users/:id", "/users"));
    try std.testing.expect(!matchParam("/users/:id", "/users/alice/posts"));
}

test "zix http3: http3 router dispatch by exact, param, prefix, query, and 404" {
    const R = Router(&[_]Route{
        .{ .path = "/", .handler = homeHandler },
        .{ .path = "/users/:id", .handler = usersHandler, .kind = .PARAM },
        .{ .path = "/static", .handler = staticHandler, .kind = .PREFIX },
    });

    var res = core.Response{};
    var ctx = core.Context{ .stream_id = 0, .io = undefined, .allocator = std.testing.allocator };

    var home = core.Request{ .method = "GET", .path = "/" };
    try R.dispatch(&home, &res, &ctx);
    try std.testing.expectEqualSlices(u8, "home", res.body);

    // The query string is ignored for matching (baseline-style request).
    var home_q = core.Request{ .method = "GET", .path = "/?a=1&b=1" };
    res = .{};
    try R.dispatch(&home_q, &res, &ctx);
    try std.testing.expectEqualSlices(u8, "home", res.body);

    var user = core.Request{ .method = "GET", .path = "/users/bob" };
    res = .{};
    try R.dispatch(&user, &res, &ctx);
    try std.testing.expectEqualSlices(u8, "bob", res.body);

    var asset = core.Request{ .method = "GET", .path = "/static/app.js" };
    res = .{};
    try R.dispatch(&asset, &res, &ctx);
    try std.testing.expectEqualSlices(u8, "static", res.body);

    var missing = core.Request{ .method = "GET", .path = "/nope" };
    res = .{};
    try R.dispatch(&missing, &res, &ctx);
    try std.testing.expectEqual(@as(u16, 404), res.status);
}
