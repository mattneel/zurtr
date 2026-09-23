//! zix http2 request: a zero-copy view over one h2 stream's decoded headers and body for the
//! ergonomic req, res, ctx handler shape. Every slice it returns borrows the stream's own buffers
//! (Stream.headers / Stream.body in core.zig, or the mux's stream slot) and is valid only for the
//! handler call.

const std = @import("std");
const hpack = @import("hpack.zig");

pub const Request = struct {
    method: []const u8,
    /// Path without the query string.
    path: []const u8,
    /// Raw query string after the "?", or empty.
    query: []const u8,
    headers: []const hpack.Header,
    body: []const u8,

    /// Split a raw ":path" pseudo-header value (which carries the query string attached, e.g.
    /// "/json/5?m=7") into path and query. Used at dispatch to build a Request.
    pub fn splitPath(raw_path: []const u8) struct { path: []const u8, query: []const u8 } {
        const q = std.mem.indexOfScalar(u8, raw_path, '?') orelse return .{ .path = raw_path, .query = "" };

        return .{ .path = raw_path[0..q], .query = raw_path[q + 1 ..] };
    }

    /// One request header value by name (case-insensitive). Includes pseudo-headers
    /// (":method", ":path", ":scheme", ":authority"), h2 carries them as regular header entries.
    pub fn header(self: Request, name: []const u8) ?[]const u8 {
        for (self.headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }

        return null;
    }

    /// One query parameter value, or null. A valueless key (e.g. "?flag") returns "".
    pub fn queryParam(self: Request, name: []const u8) ?[]const u8 {
        var pos: usize = 0;
        while (pos < self.query.len) {
            const amp_pos = std.mem.indexOfScalarPos(u8, self.query, pos, '&') orelse self.query.len;
            const pair = self.query[pos..amp_pos];
            if (std.mem.indexOfScalar(u8, pair, '=')) |eq_pos| {
                if (std.mem.eql(u8, pair[0..eq_pos], name)) return pair[eq_pos + 1 ..];
            } else if (std.mem.eql(u8, pair, name)) {
                return "";
            }

            if (amp_pos >= self.query.len) break;
            pos = amp_pos + 1;
        }

        return null;
    }

    pub const QueryParam = struct {
        key: []const u8,
        value: ?[]const u8,
    };

    /// Get all query parameters as a slice of QueryParam. Valueless keys get a null value.
    pub fn queryParams(self: Request, allocator: std.mem.Allocator) ![]QueryParam {
        if (self.query.len == 0) return &.{};

        var list: std.ArrayList(QueryParam) = .empty;
        var pos: usize = 0;
        while (pos < self.query.len) {
            const amp_pos = std.mem.indexOfScalarPos(u8, self.query, pos, '&') orelse self.query.len;
            const pair = self.query[pos..amp_pos];
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

            if (amp_pos >= self.query.len) break;
            pos = amp_pos + 1;
        }

        return list.items;
    }

    /// Split the request path into non-empty segments.
    pub fn pathSegments(self: Request, allocator: std.mem.Allocator) ![][]const u8 {
        var list: std.ArrayList([]const u8) = .empty;

        var iter = std.mem.splitScalar(u8, self.path, '/');
        while (iter.next()) |segment| {
            if (segment.len > 0) try list.append(allocator, segment);
        }

        return list.items;
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http2: Request.splitPath separates path and query" {
    const split = Request.splitPath("/users/5?role=admin");
    try std.testing.expectEqualStrings("/users/5", split.path);
    try std.testing.expectEqualStrings("role=admin", split.query);

    const no_query = Request.splitPath("/about");
    try std.testing.expectEqualStrings("/about", no_query.path);
    try std.testing.expectEqualStrings("", no_query.query);
}

test "zix http2: Request.header is case-insensitive and includes pseudo-headers" {
    const headers = [_]hpack.Header{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "content-type", .value = "application/json" },
    };
    const req = Request{ .method = "GET", .path = "/", .query = "", .headers = &headers, .body = "" };

    try std.testing.expectEqualStrings("GET", req.header(":method").?);
    try std.testing.expectEqualStrings("application/json", req.header("Content-Type").?);
    try std.testing.expect(req.header("missing") == null);
}

test "zix http2: Request.queryParam finds a value and a valueless key" {
    const req = Request{ .method = "GET", .path = "/p", .query = "name=alice&flag&empty=", .headers = &.{}, .body = "" };

    try std.testing.expectEqualStrings("alice", req.queryParam("name").?);
    try std.testing.expectEqualStrings("", req.queryParam("flag").?);
    try std.testing.expectEqualStrings("", req.queryParam("empty").?);
    try std.testing.expect(req.queryParam("missing") == null);
}

test "zix http2: Request.queryParams returns every pair, valueless keys null" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const req = Request{ .method = "GET", .path = "/q", .query = "name=alice&flag&empty=", .headers = &.{}, .body = "" };
    const params = try req.queryParams(arena.allocator());

    try std.testing.expectEqual(@as(usize, 3), params.len);
    try std.testing.expectEqualStrings("name", params[0].key);
    try std.testing.expectEqualStrings("alice", params[0].value.?);
    try std.testing.expectEqualStrings("flag", params[1].key);
    try std.testing.expect(params[1].value == null);
    try std.testing.expectEqualStrings("empty", params[2].key);
    try std.testing.expect(params[2].value == null);
}

test "zix http2: Request.pathSegments splits non-empty segments" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const req = Request{ .method = "GET", .path = "/api//users/42/", .query = "", .headers = &.{}, .body = "" };
    const segments = try req.pathSegments(arena.allocator());

    try std.testing.expectEqual(@as(usize, 3), segments.len);
    try std.testing.expectEqualStrings("api", segments[0]);
    try std.testing.expectEqualStrings("users", segments[1]);
    try std.testing.expectEqualStrings("42", segments[2]);
}
