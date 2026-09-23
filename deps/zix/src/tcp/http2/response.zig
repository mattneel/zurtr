//! zix http2 response: the write path for the ergonomic req, res, ctx handler shape. A thin
//! builder over frame.sendResponseFD / sendResponseEncodedFD, so the wire bytes are byte-identical
//! to a handler that calls those directly.

const std = @import("std");
const fd_io = @import("../../utils/fd_io.zig");
const socket_pair = @import("../../utils/socket_pair.zig");
const builtin = @import("builtin");
const frame = @import("frame.zig");

pub const Response = struct {
    /// Connection fd. Every write lands here.
    fd: std.posix.fd_t,
    /// HTTP/2 stream id this response belongs to.
    sid: u31,
    /// Response status code. Default 200.
    status: u16 = 200,
    /// Content-Type. Empty omits the header, matching frame.sendResponseFD("").
    content_type: []const u8 = "",
    /// Set once any send lands, so the engine does not emit a 500 over a response the handler
    /// already wrote when the handler then returns an error.
    sent: bool = false,
    /// Body bytes handed to the last send, for the engine's access record.
    ///
    /// Note:
    /// - Counts what went through this Response. A handler that frames its own bytes through
    ///   frame.sendResponseFD, or serves a static file directly, is not counted here.
    bytes_written: usize = 0,

    /// Set the response status code.
    pub fn setStatus(self: *Response, status: u16) void {
        self.status = status;
    }

    /// Set the Content-Type.
    pub fn setContentType(self: *Response, content_type: []const u8) void {
        self.content_type = content_type;
    }

    /// Send body with the current status and Content-Type. Byte-identical to a direct
    /// frame.sendResponseFD call.
    ///
    /// Param:
    /// body - []const u8 (response body)
    ///
    /// Return:
    /// - !void (propagates the frame writer error)
    pub fn send(self: *Response, body: []const u8) !void {
        self.sent = true;
        self.bytes_written = body.len;

        return frame.sendResponseFD(self.fd, self.sid, self.status, self.content_type, body);
    }

    /// Send body as application/json. Byte-identical to frame.sendResponseFD with that content type.
    pub fn sendJson(self: *Response, body: []const u8) !void {
        self.content_type = "application/json";

        return self.send(body);
    }

    /// Send body as text/plain.
    pub fn sendText(self: *Response, body: []const u8) !void {
        self.content_type = "text/plain";

        return self.send(body);
    }

    /// Send a 204 No Content response with an empty body.
    pub fn sendNoContent(self: *Response) !void {
        self.status = 204;

        return self.send("");
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// A connected pair for the tests below, portable across every supported platform.
fn socketPair(fds: *[2]std.posix.fd_t) !void {
    const pair = try socket_pair.Pair.open(std.testing.allocator);
    fds.* = pair.fds;
}

/// Test fd sentinel: Windows descriptors are opaque pointers, POSIX are ints.
const TEST_FD: std.posix.fd_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;

test "zix http2: Response setters mutate status and content type" {
    var res = Response{ .fd = TEST_FD, .sid = 1 };

    try std.testing.expectEqual(@as(u16, 200), res.status);
    res.setStatus(404);
    try std.testing.expectEqual(@as(u16, 404), res.status);

    res.setContentType("text/html");
    try std.testing.expectEqualStrings("text/html", res.content_type);
}

test "zix http2: Response.send is byte-identical to frame.sendResponseFD" {
    var pair_res: [2]std.posix.fd_t = undefined;
    var pair_frame: [2]std.posix.fd_t = undefined;
    try socketPair(&pair_res);
    try socketPair(&pair_frame);
    defer for ([_]std.posix.fd_t{ pair_res[0], pair_res[1], pair_frame[0], pair_frame[1] }) |fd| {
        fd_io.close(fd);
    };

    var res = Response{ .fd = pair_res[1], .sid = 1, .status = 201, .content_type = "text/plain" };
    try res.send("hello");

    var via_res: [256]u8 = undefined;
    const n_res = try fd_io.readOnce(pair_res[0], &via_res);

    try frame.sendResponseFD(pair_frame[1], 1, 201, "text/plain", "hello");

    var via_frame: [256]u8 = undefined;
    const n_frame = try fd_io.readOnce(pair_frame[0], &via_frame);

    try std.testing.expectEqualStrings(via_frame[0..n_frame], via_res[0..n_res]);
    try std.testing.expect(res.sent);
}

test "zix http2: Response.sendJson sets application/json" {
    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var res = Response{ .fd = fds[1], .sid = 1 };
    try res.sendJson("{\"ok\":true}");

    try std.testing.expectEqualStrings("application/json", res.content_type);

    var buf: [256]u8 = undefined;
    _ = try fd_io.readOnce(fds[0], &buf);
}

test "zix http2: Response.sendNoContent sets 204" {
    var fds: [2]std.posix.fd_t = undefined;
    try socketPair(&fds);
    defer fd_io.close(fds[0]);
    defer fd_io.close(fds[1]);

    var res = Response{ .fd = fds[1], .sid = 1 };
    try res.sendNoContent();

    try std.testing.expectEqual(@as(u16, 204), res.status);

    var buf: [256]u8 = undefined;
    _ = try fd_io.readOnce(fds[0], &buf);
}
