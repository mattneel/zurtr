//! zix http1 comptime router: EXACT, PREFIX, and PARAM matching, zero runtime alloc.

const std = @import("std");
const core = @import("core.zig");
const static = @import("static.zig");
const Request = @import("request.zig").Request;
const Response = @import("response.zig").Response;
const Context = @import("context.zig").Context;

// --------------------------------------------------------- //

pub const RouteKind = enum(u8) { EXACT, PREFIX, PARAM };

pub const Route = struct {
    path: []const u8,
    handler: core.HandlerFn,
    kind: RouteKind = .EXACT,
};

/// One matched path parameter (e.g. `:id` -> "alice").
pub const PathParam = struct {
    name: []const u8,
    value: []const u8,
};

/// Upper bound on `:params` captured from a single PARAM route.
const MAX_PATH_PARAMS: usize = 8;

/// Per-request param store. Thread-local because each worker serves one request
/// at a time, the same model as core.zig's per-handler deadline. Values are
/// slices into the request path and stay valid only for the dispatch call.
threadlocal var tl_params: [MAX_PATH_PARAMS]PathParam = undefined;
threadlocal var tl_param_count: usize = 0;

/// Look up a path parameter captured by the matched PARAM route.
///
/// Note:
/// - Only valid inside a handler reached via a PARAM route.
/// - The returned slice borrows the request path and dies with the call.
///
/// Param:
/// name - []const u8 (param name without the leading ":")
///
/// Return:
/// - ?[]const u8 (value slice, or null if no such param)
pub fn pathParam(name: []const u8) ?[]const u8 {
    for (tl_params[0..tl_param_count]) |p| {
        if (std.mem.eql(u8, p.name, name)) return p.value;
    }

    return null;
}

/// Build a router type whose dispatch table is fixed at compile time.
///
/// Note:
/// - Routes are partitioned by kind at comptime: EXACT routes go into a
///   StaticStringMap for O(1) lookup, PARAM and PREFIX routes into comptime
///   arrays iterated with inline for at each dispatch call.
/// - Dispatch priority: EXACT > PARAM (first-registered wins) > PREFIX (longest wins).
/// - Registration order matters only within the PARAM tier.
/// - The returned type exposes a single `dispatch` usable as a HandlerFn.
///
/// Param:
/// routes - []const Route (comptime-known route table)
///
/// Usage:
/// ```zig
/// const R = zix.Http1.Router(&[_]zix.Http1.Route{
///     .{ .path = "/", .handler = homeHandler },
///     .{ .path = "/secret", .handler = secretHandler, .kind = .PREFIX },
///     .{ .path = "/users/:id", .handler = userHandler, .kind = .PARAM },
/// });
///
/// var server = zix.Http1.Server.init(R.dispatch, .{ .ip = "0.0.0.0", .port = 8080 });
/// try server.run();
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
        /// Dispatch the request to the best matching route. Usable as a HandlerFn.
        ///
        /// Note:
        /// - Pass 1 exact: O(1) comptime-built hash lookup
        /// - Pass 2 param: first parameterized pattern that matches wins
        /// - Pass 3 prefix: longest matching prefix wins
        /// - Unknown paths get 404 text/plain.
        pub fn dispatch(req: *Request, res: *Response, ctx: *Context) anyerror!void {
            tl_param_count = 0;

            const path = req.head.path;

            // Pass 1: exact, O(1) hash lookup
            if (exact_map.get(path)) |handler| {
                return handler(req, res, ctx);
            }

            // Pass 2: parameterized (first match wins)
            inline for (param_routes) |route| {
                if (matchParam(route.path, path)) {
                    return route.handler(req, res, ctx);
                }
            }

            // Pass 3: prefix (longest match wins)
            var best_len: usize = 0;
            var best_handler: ?core.HandlerFn = null;
            inline for (prefix_routes) |route| {
                if (std.mem.startsWith(u8, path, route.path)) {
                    const at_boundary = path.len == route.path.len or path[route.path.len] == '/';
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
            // as a file before returning 404. Disabled when public_dir is empty (tl_static_dir = "").
            if (core.tl_static_dir.len > 0) {
                if (core.tl_static_io) |io| {
                    const stripped = if (path.len > 0 and path[0] == '/') path[1..] else path;
                    if (stripped.len > 0) {
                        const served = static.serve(req.head, req.fd, stripped, core.tl_static_dir, io) catch false;
                        if (served) return;
                    }
                }
            }

            res.setStatus(.NOT_FOUND);

            try res.sendText("Not Found");
        }
    };
}

// Match a parameterized pattern against a concrete path. On success, fills the
// thread-local param store and returns true. On failure the store is left
// untouched (tl_param_count is only committed at the end), so a later match
// always overwrites from index 0.
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

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http1: router matchParam" {
    try std.testing.expect(matchParam("/users/:id", "/users/alice"));
    try std.testing.expectEqualStrings("id", tl_params[0].name);
    try std.testing.expectEqualStrings("alice", tl_params[0].value);
    try std.testing.expectEqualStrings("alice", pathParam("id").?);

    try std.testing.expect(matchParam("/:tenant/:branch", "/acme/main"));
    try std.testing.expectEqualStrings("acme", pathParam("tenant").?);
    try std.testing.expectEqualStrings("main", pathParam("branch").?);

    try std.testing.expect(!matchParam("/users/:id", "/users"));
    try std.testing.expect(!matchParam("/users/:id", "/users/alice/posts"));
}

fn mockHandler(req: *Request, res: *Response, ctx: *Context) anyerror!void {
    _ = req;
    _ = res;
    _ = ctx;
}

test "zix http1: router comptime" {
    const TestRouter = Router(&[_]Route{
        .{ .path = "/about", .handler = mockHandler },
        .{ .path = "/api", .handler = mockHandler, .kind = .PREFIX },
        .{ .path = "/users/:id", .handler = mockHandler, .kind = .PARAM },
    });
    _ = TestRouter;
}
