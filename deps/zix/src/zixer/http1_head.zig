//! zixer http1 head parsing for the proxy edge: request line, status line,
//! headers, and the body framing decision (rfc 9112)

const std = @import("std");

/// Hard ceiling for one message head (request or status line plus headers).
pub const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Most headers one message may carry through the proxy.
pub const MAX_HEADERS: usize = 64;

pub const Error = error{
    ZixerHeadTooLarge,
    /// The peer went away between messages, before a single byte of the next
    /// head. Nothing was asked, so nothing is owed.
    ZixerConnectionClosed,
    /// The peer went away part way through a head. A request was started and
    /// never finished, which is the one end the sender is owed a status for.
    PartialHead,
    ZixerBadHead,
    ZixerTooManyHeaders,
    ZixerBadContentLength,
    /// Content-Length next to Transfer-Encoding: rejected outright, the
    /// classic rfc 9112 smuggling vector.
    ZixerAmbiguousFraming,
    /// A Transfer-Encoding zixer cannot re-frame (only chunked is supported).
    ZixerUnsupportedTransferEncoding,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// How the body after this head is delimited.
pub const Framing = union(enum) {
    none,
    content_length: u64,
    chunked,
    until_close,
};

/// Parsed request head. All slices point into the caller's head buffer.
pub const RequestHead = struct {
    method: []const u8,
    target: []const u8,
    headers: [MAX_HEADERS]Header,
    header_count: usize,
    framing: Framing,
    host: []const u8,
    connection_value: []const u8,
    connection_close: bool,

    pub fn headerSlice(head: *const RequestHead) []const Header {
        return head.headers[0..head.header_count];
    }
};

/// Parsed response head. All slices point into the caller's head buffer.
pub const ResponseHead = struct {
    status: u16,
    reason: []const u8,
    headers: [MAX_HEADERS]Header,
    header_count: usize,
    framing: Framing,
    connection_value: []const u8,
    connection_close: bool,

    pub fn headerSlice(head: *const ResponseHead) []const Header {
        return head.headers[0..head.header_count];
    }
};

/// Read one message head (through the blank line) into buf.
///
/// Param:
/// reader - *std.Io.Reader (stream reader interface, body bytes stay unread)
/// buf - []u8 (MAX_HEAD_BYTES covers any accepted head)
///
/// Return:
/// - []const u8 the head bytes including the final CRLFCRLF
/// - error.ZixerConnectionClosed when the peer closes with no head started
/// - error.PartialHead when the peer closes part way through one
/// - error.ZixerHeadTooLarge when buf fills without a blank line
pub fn readHead(reader: *std.Io.Reader, buf: []u8) Error![]const u8 {
    var len: usize = 0;
    while (len < buf.len) {
        const got = reader.readSliceShort(buf[len .. len + 1]) catch return endedAt(len);
        if (got == 0) return endedAt(len);

        len += 1;
        if (len >= 4 and std.mem.eql(u8, buf[len - 4 .. len], "\r\n\r\n")) return buf[0..len];
    }

    return error.ZixerHeadTooLarge;
}

/// Which end a stopped read was, told by how much of the head had arrived.
fn endedAt(len: usize) Error {
    return if (len == 0) error.ZixerConnectionClosed else error.PartialHead;
}

/// Parse one request head as read by readHead.
pub fn parseRequest(head_bytes: []const u8) Error!RequestHead {
    var lines = std.mem.splitSequence(u8, head_bytes, "\r\n");
    const request_line = lines.next() orelse return error.ZixerBadHead;

    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return error.ZixerBadHead;
    const target = parts.next() orelse return error.ZixerBadHead;
    const version = parts.next() orelse return error.ZixerBadHead;
    if (method.len == 0 or target.len == 0) return error.ZixerBadHead;
    if (!std.mem.eql(u8, version, "HTTP/1.1") and !std.mem.eql(u8, version, "HTTP/1.0")) return error.ZixerBadHead;

    var head = RequestHead{
        .method = method,
        .target = target,
        .headers = undefined,
        .header_count = 0,
        .framing = .none,
        .host = "",
        .connection_value = "",
        .connection_close = std.mem.eql(u8, version, "HTTP/1.0"),
    };

    var content_length: ?u64 = null;
    var chunked = false;
    try parseHeaderLines(&lines, &head.headers, &head.header_count, &content_length, &chunked, &head.connection_value, &head.host);

    head.framing = try resolveFraming(content_length, chunked, .none);
    head.connection_close = connectionCloses(head.connection_value, head.connection_close);

    return head;
}

/// Parse one response head as read by readHead. request_method matters for
/// framing: a HEAD response has no body whatever its headers claim.
pub fn parseResponse(head_bytes: []const u8, request_method: []const u8) Error!ResponseHead {
    var lines = std.mem.splitSequence(u8, head_bytes, "\r\n");
    const status_line = lines.next() orelse return error.ZixerBadHead;

    if (!std.mem.startsWith(u8, status_line, "HTTP/1.")) return error.ZixerBadHead;
    var parts = std.mem.splitScalar(u8, status_line, ' ');
    _ = parts.next();
    const status_text = parts.next() orelse return error.ZixerBadHead;
    const status = std.fmt.parseInt(u16, status_text, 10) catch return error.ZixerBadHead;
    const reason = parts.rest();

    var head = ResponseHead{
        .status = status,
        .reason = reason,
        .headers = undefined,
        .header_count = 0,
        .framing = .none,
        .connection_value = "",
        .connection_close = false,
    };

    var content_length: ?u64 = null;
    var chunked = false;
    var host_sink: []const u8 = "";
    try parseHeaderLines(&lines, &head.headers, &head.header_count, &content_length, &chunked, &head.connection_value, &host_sink);

    const bodyless = std.ascii.eqlIgnoreCase(request_method, "HEAD") or
        status / 100 == 1 or status == 204 or status == 304;
    head.framing = if (bodyless) .none else try resolveFraming(content_length, chunked, .until_close);
    head.connection_close = connectionCloses(head.connection_value, false);

    return head;
}

fn parseHeaderLines(
    lines: *std.mem.SplitIterator(u8, .sequence),
    headers: *[MAX_HEADERS]Header,
    header_count: *usize,
    content_length: *?u64,
    chunked: *bool,
    connection_value: *[]const u8,
    host: *[]const u8,
) Error!void {
    while (lines.next()) |line| {
        if (line.len == 0) break;
        if (header_count.* == MAX_HEADERS) return error.ZixerTooManyHeaders;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.ZixerBadHead;
        const name = line[0..colon];
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (name.len == 0) return error.ZixerBadHead;

        headers[header_count.*] = .{ .name = name, .value = value };
        header_count.* += 1;

        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            // A repeated Content-Length with a different value is the same
            // smuggling vector as CL next to TE.
            const parsed = std.fmt.parseInt(u64, value, 10) catch return error.ZixerBadContentLength;
            if (content_length.*) |seen| {
                if (seen != parsed) return error.ZixerAmbiguousFraming;
            }
            content_length.* = parsed;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            if (!std.ascii.eqlIgnoreCase(value, "chunked")) return error.ZixerUnsupportedTransferEncoding;
            chunked.* = true;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            connection_value.* = value;
        } else if (std.ascii.eqlIgnoreCase(name, "host")) {
            host.* = value;
        }
    }
}

fn resolveFraming(content_length: ?u64, chunked: bool, neither: Framing) Error!Framing {
    if (chunked and content_length != null) return error.ZixerAmbiguousFraming;
    if (chunked) return .chunked;
    if (content_length) |len| return if (len == 0) .none else .{ .content_length = len };

    return neither;
}

fn connectionCloses(connection_value: []const u8, default_close: bool) bool {
    var tokens = std.mem.splitScalar(u8, connection_value, ',');
    while (tokens.next()) |token| {
        const trimmed = std.mem.trim(u8, token, " \t");
        if (std.ascii.eqlIgnoreCase(trimmed, "close")) return true;
        if (std.ascii.eqlIgnoreCase(trimmed, "keep-alive")) return false;
    }

    return default_close;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: http1 head, plain get parses with no body framing" {
    const head = try parseRequest("GET /api/x HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n");

    try std.testing.expectEqualStrings("GET", head.method);
    try std.testing.expectEqualStrings("/api/x", head.target);
    try std.testing.expectEqualStrings("example.com", head.host);
    try std.testing.expectEqual(@as(usize, 2), head.header_count);
    try std.testing.expect(head.framing == .none);
    try std.testing.expect(!head.connection_close);
}

test "zix zixer: http1 head, content-length and chunked each resolve framing" {
    const sized = try parseRequest("POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\n\r\n");
    try std.testing.expectEqual(@as(u64, 12), sized.framing.content_length);

    const chunked = try parseRequest("POST /u HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n");
    try std.testing.expect(chunked.framing == .chunked);

    const empty = try parseRequest("POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: 0\r\n\r\n");
    try std.testing.expect(empty.framing == .none);
}

test "zix zixer: http1 head, smuggling shapes are rejected" {
    try std.testing.expectError(
        error.ZixerAmbiguousFraming,
        parseRequest("POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n"),
    );
    try std.testing.expectError(
        error.ZixerAmbiguousFraming,
        parseRequest("POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"),
    );
    try std.testing.expectError(
        error.ZixerUnsupportedTransferEncoding,
        parseRequest("POST /u HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"),
    );
    try std.testing.expectError(
        error.ZixerBadContentLength,
        parseRequest("POST /u HTTP/1.1\r\nHost: a\r\nContent-Length: nope\r\n\r\n"),
    );
}

test "zix zixer: http1 head, connection close and http/1.0 default" {
    const closing = try parseRequest("GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n");
    try std.testing.expect(closing.connection_close);

    const old = try parseRequest("GET / HTTP/1.0\r\nHost: a\r\n\r\n");
    try std.testing.expect(old.connection_close);

    const old_keep = try parseRequest("GET / HTTP/1.0\r\nHost: a\r\nConnection: keep-alive\r\n\r\n");
    try std.testing.expect(!old_keep.connection_close);
}

test "zix zixer: http1 head, bad request lines are rejected" {
    try std.testing.expectError(error.ZixerBadHead, parseRequest("GET /\r\n\r\n"));
    try std.testing.expectError(error.ZixerBadHead, parseRequest("GET / HTTP/2.0\r\n\r\n"));
    try std.testing.expectError(error.ZixerBadHead, parseRequest("\r\n\r\n"));
    try std.testing.expectError(error.ZixerBadHead, parseRequest("GET / HTTP/1.1\r\nNoColonHere\r\n\r\n"));
}

test "zix zixer: http1 head, response framing follows status and method" {
    const sized = try parseResponse("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", "GET");
    try std.testing.expectEqual(@as(u16, 200), sized.status);
    try std.testing.expectEqualStrings("OK", sized.reason);
    try std.testing.expectEqual(@as(u64, 5), sized.framing.content_length);

    const chunked = try parseResponse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", "GET");
    try std.testing.expect(chunked.framing == .chunked);

    const eof_delimited = try parseResponse("HTTP/1.1 200 OK\r\n\r\n", "GET");
    try std.testing.expect(eof_delimited.framing == .until_close);

    const no_content = try parseResponse("HTTP/1.1 204 No Content\r\n\r\n", "GET");
    try std.testing.expect(no_content.framing == .none);

    const not_modified = try parseResponse("HTTP/1.1 304 Not Modified\r\nContent-Length: 90\r\n\r\n", "GET");
    try std.testing.expect(not_modified.framing == .none);

    const head_reply = try parseResponse("HTTP/1.1 200 OK\r\nContent-Length: 90\r\n\r\n", "HEAD");
    try std.testing.expect(head_reply.framing == .none);
}

test "zix zixer: http1 head, readHead stops at the blank line and bounds the head" {
    var fixed = std.Io.Reader.fixed("GET / HTTP/1.1\r\nHost: a\r\n\r\nBODYBYTES");
    var head_buf: [128]u8 = undefined;

    const head_bytes = try readHead(&fixed, &head_buf);
    try std.testing.expectEqualStrings("GET / HTTP/1.1\r\nHost: a\r\n\r\n", head_bytes);

    var rest_buf: [16]u8 = undefined;
    const rest_len = try fixed.readSliceShort(&rest_buf);
    try std.testing.expectEqualStrings("BODYBYTES", rest_buf[0..rest_len]);

    var tiny_buf: [8]u8 = undefined;
    var again = std.Io.Reader.fixed("GET / HTTP/1.1\r\n\r\n");
    try std.testing.expectError(error.ZixerHeadTooLarge, readHead(&again, &tiny_buf));

    var cut = std.Io.Reader.fixed("GET / HT");
    var cut_buf: [128]u8 = undefined;
    try std.testing.expectError(error.PartialHead, readHead(&cut, &cut_buf));
}

test "zix zixer: http1 head, a started head and a silent connection end apart" {
    // Nothing was ever asked, which is what a kept-alive connection looks like
    // when the client is finished with it.
    var silent = std.Io.Reader.fixed("");
    var silent_buf: [128]u8 = undefined;
    try std.testing.expectError(error.ZixerConnectionClosed, readHead(&silent, &silent_buf));

    // One byte is enough to be a request in progress.
    var started = std.Io.Reader.fixed("G");
    var started_buf: [128]u8 = undefined;
    try std.testing.expectError(error.PartialHead, readHead(&started, &started_buf));

    // A head three bytes short of its blank line is the shape a dribbling
    // client leaves behind.
    var nearly = std.Io.Reader.fixed("GET / HTTP/1.1\r\nHost: a\r\n\r");
    var nearly_buf: [128]u8 = undefined;
    try std.testing.expectError(error.PartialHead, readHead(&nearly, &nearly_buf));
}
