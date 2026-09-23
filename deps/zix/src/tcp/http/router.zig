//! zix http router

const std = @import("std");
const Request = @import("request.zig").Request;
const PathParam = @import("request.zig").PathParam;
const Response = @import("response.zig").Response;
const Context = @import("context.zig").Context;
const static = @import("static.zig");

// --------------------------------------------------------- //

pub const HandlerFn = *const fn (req: *Request, res: *Response, ctx: *Context) anyerror!void;

pub const RouteKind = enum(u8) { EXACT, PREFIX, PARAM };

pub const Route = struct {
    path: []const u8,
    handler: HandlerFn,
    kind: RouteKind = .EXACT,
};

/// Build a router type whose dispatch table is fixed at compile time
///
/// Note:
/// - Routes are partitioned by kind at comptime: EXACT routes go into
///   a StaticStringMap for O(1) lookup, PARAM and PREFIX routes into
///   comptime arrays iterated with inline for at each dispatch call.
/// - Dispatch priority: EXACT > PARAM (first-registered wins) > PREFIX (longest wins).
/// - Registration order matters only within the PARAM tier.
/// - The returned type is zero-size: embed it as a field or call dispatch on it.
///
/// Param:
/// routes - []const Route (comptime-known route table)
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

    const exact_map = std.StaticStringMap(HandlerFn).initComptime(exact_pairs);

    return struct {
        /// Dispatch the request to the best matching route. Usable as a HandlerFn.
        ///
        /// Note:
        /// - Pass 1 exact: O(1) comptime-built hash lookup
        /// - Pass 2 param: first parameterized pattern that matches wins, path_params written to req
        /// - Pass 3 prefix: longest matching prefix wins
        /// - Priority is independent of registration order
        /// - Static file fallback: when ctx.public_dir is set, try to serve the request
        ///   path as a file before returning 404
        ///
        /// Param:
        /// req - *Request
        /// res - *Response
        /// ctx - *Context
        pub fn dispatch(req: *Request, res: *Response, ctx: *Context) anyerror!void {
            const p = req.path();

            // Pass 1: exact, O(1) hash lookup
            if (exact_map.get(p)) |handler| {
                return handler(req, res, ctx);
            }

            // Pass 2: parameterized (first match wins)
            inline for (param_routes) |route| {
                if (try matchParam(route.path, p, req)) {
                    return route.handler(req, res, ctx);
                }
            }

            // Pass 3: prefix (longest match wins)
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

            if (best_handler) |h| {
                return h(req, res, ctx);
            }

            if (ctx.public_dir.len > 0) {
                const stripped = if (p.len > 0 and p[0] == '/') p[1..] else p;
                if (stripped.len > 0) {
                    const served = static.serve(req, req.fd, stripped, ctx.public_dir, ctx.io) catch false;
                    if (served) return;
                }
            }

            res.setStatus(.NOT_FOUND);

            try res.send("Not Found");
        }
    };
}

// Match a parameterized pattern against a concrete path.
// On success, populates req.path_params (allocated from req.allocator) and returns true.
fn matchParam(pattern: []const u8, path: []const u8, req: *Request) !bool {
    var pat_it = std.mem.splitScalar(u8, pattern, '/');
    var path_it = std.mem.splitScalar(u8, path, '/');
    var params: std.ArrayList(PathParam) = .empty;

    while (true) {
        const pat_seg = pat_it.next();
        const path_seg = path_it.next();
        if (pat_seg == null and path_seg == null) break;
        if (pat_seg == null or path_seg == null) return false;
        const pat_token = pat_seg.?;
        const path_token = path_seg.?;
        if (std.mem.startsWith(u8, pat_token, ":")) {
            if (path_token.len == 0) return false;
            try params.append(req.allocator, .{ .name = pat_token[1..], .value = path_token });
        } else {
            if (!std.mem.eql(u8, pat_token, path_token)) return false;
        }
    }

    req.path_params = params.items;
    return true;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http: router matchParam" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var req = Request{
        .buf = "",
        .head = std.mem.zeroes(@import("parser.zig").ParsedHead),
        .fd = undefined,
        .buf_filled = 0,
        .allocator = allocator,
    };

    try std.testing.expect(try matchParam("/users/:id", "/users/alice", &req));
    try std.testing.expectEqualStrings("id", req.path_params[0].name);
    try std.testing.expectEqualStrings("alice", req.path_params[0].value);

    try std.testing.expect(try matchParam("/:tenant/:branch", "/acme/main", &req));
    try std.testing.expectEqualStrings("tenant", req.path_params[0].name);
    try std.testing.expectEqualStrings("acme", req.path_params[0].value);
    try std.testing.expectEqualStrings("branch", req.path_params[1].name);
    try std.testing.expectEqualStrings("main", req.path_params[1].value);

    try std.testing.expect(!try matchParam("/users/:id", "/users", &req));
    try std.testing.expect(!try matchParam("/users/:id", "/users/alice/posts", &req));
}

fn mockHandler(req: *Request, res: *Response, ctx: *Context) !void {
    _ = req;
    _ = res;
    _ = ctx;
}

test "zix http: router comptime" {
    const TestRouter = Router(&[_]Route{
        .{ .path = "/about", .handler = mockHandler },
        .{ .path = "/api", .handler = mockHandler, .kind = .PREFIX },
        .{ .path = "/users/:id", .handler = mockHandler, .kind = .PARAM },
    });
    const r: TestRouter = .{};
    _ = r;
}
