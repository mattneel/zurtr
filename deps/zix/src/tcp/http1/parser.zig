//! zix http1 parser: zero-alloc HTTP/1.x request-head parsing.
//! All parsing operates on caller-owned buffers, every ParsedHead slice
//! points into the caller's buffer (zero copy).

const std = @import("std");
const ZIG_SEMVER = @import("../../lib.zig").ZIG_SEMVER;
const Method = @import("method.zig");

pub const ParseResult = struct {
    head: ParsedHead,
    body_offset: usize,
};

/// HeaderSpan offset marking a span the producing parse pass never scanned
/// for: readers fall back to a getHeader scan.
pub const SPAN_UNSCANNED: u32 = std.math.maxInt(u32);

/// HeaderSpan offset marking a header the parse pass scanned for and did not
/// find (a definitive absence, no fallback scan needed).
pub const SPAN_ABSENT: u32 = std.math.maxInt(u32) - 1;

/// Byte range of a captured header value inside raw_headers, so a hot header
/// read is O(1) instead of a per-request rescan of the header block.
pub const HeaderSpan = struct {
    off: u32 = SPAN_UNSCANNED,
    len: u32 = 0,
};

pub const ParsedHead = struct {
    method: []const u8,
    path: []const u8,
    query: []const u8,
    /// Raw header block from the byte after the request line CRLF up to and
    /// including the final header CRLF. Empty when the request has no headers.
    /// Use getHeader to look up individual headers on demand.
    raw_headers: []const u8,
    version_minor: u8,
    keep_alive: bool,
    content_length: u64,
    chunked_request: bool,
    expect_continue: bool,
    /// Accept-Encoding value span, captured during the one existing header
    /// walk. Read it through acceptEncoding, which handles the unscanned and
    /// absent sentinels.
    accept_encoding: HeaderSpan = .{},
};

/// Byte range from a Range request header (parseRange), inclusive on both ends.
pub const Range = struct { start: u64, end: u64 };

/// Whether the request-line method token names a method this engine implements
///
/// Note:
/// - Method.codeFromString is the single table. Keeping a second copy here is
///   what let the two HTTP/1 engines disagree on method case, so the check
///   defers to the table it publishes
/// - The match is exact, per RFC 9110 section 9.1, so a normal request costs
///   one length switch and one compare, with no copy
/// - A keep-alive GET never reaches here at all: the EPOLL and URING loops
///   resolve it in parseGetFastPath before parseHeadAt is called
///
/// Param:
/// method - []const u8 (the raw token from the request line)
///
/// Return:
/// - bool
fn methodImplemented(method: []const u8) bool {
    return Method.codeFromString(method) != null;
}

/// Parse a complete HTTP/1.x request from buf where header_end (the index of
/// \r\n\r\n in buf) is already known. Avoids the redundant indexOf scan when
/// the caller has already located the terminator. buf may extend beyond
/// header_end + 4 (body bytes are ignored).
///
/// Note:
/// - Framing pass: a header line is tokenized only when its first letter is
///   c, t, e, or a (the letters that start a captured header: content-length,
///   connection, transfer-encoding, expect, accept-encoding). All other lines
///   skip with one indexOfPos plus one masked compare.
///
/// Return:
/// - !struct{ head: ParsedHead, body_offset: usize }
/// - error.ZixInvalidRequest on a malformed request line
/// - error.ZixUnknownMethod when the request line is well formed but names a
///   method this engine does not implement (the caller answers 501)
pub fn parseHeadAt(buf: []const u8, header_end: usize) !ParseResult {
    const body_offset = header_end + 4;

    const first_crlf = std.mem.indexOf(u8, buf[0..header_end], "\r\n") orelse header_end;
    const req_line = buf[0..first_crlf];

    const sp1 = std.mem.indexOfScalar(u8, req_line, ' ') orelse return error.ZixInvalidRequest;
    if (sp1 == 0) return error.ZixInvalidRequest;
    const method = req_line[0..sp1];

    const rest = req_line[sp1 + 1 ..];
    const sp2 = std.mem.lastIndexOfScalar(u8, rest, ' ') orelse return error.ZixInvalidRequest;
    const target = rest[0..sp2];
    const version_str = rest[sp2 + 1 ..];

    const version_minor: u8 = if (std.mem.eql(u8, version_str, "HTTP/1.1"))
        1
    else if (std.mem.eql(u8, version_str, "HTTP/1.0"))
        0
    else
        return error.ZixInvalidRequest;

    // Checked after the version so a mangled request line still reads as
    // malformed (400) rather than as an unimplemented method (501).
    if (!methodImplemented(method)) return error.ZixUnknownMethod;

    var path = target;
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, target, '?')) |question_mark| {
        path = target[0..question_mark];
        query = target[question_mark + 1 ..];
    }

    const raw_headers: []const u8 = if (first_crlf >= header_end)
        buf[0..0]
    else
        buf[first_crlf + 2 .. header_end + 2];

    var keep_alive = (version_minor == 1);
    var content_length: u64 = 0;
    var chunked_request = false;
    var expect_continue = false;
    var accept_encoding: HeaderSpan = .{ .off = SPAN_ABSENT };

    var pos: usize = 0;
    while (pos < raw_headers.len) {
        const line_start = pos;
        const line_end = std.mem.indexOfPos(u8, raw_headers, pos, "\r\n") orelse raw_headers.len;
        const line = raw_headers[pos..line_end];
        pos = line_end + 2;
        if (line.len == 0) break;

        const first_lower = line[0] | 0x20;
        if (first_lower != 'c' and first_lower != 't' and first_lower != 'e' and first_lower != 'a') continue;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        var value_off: usize = colon + 1;
        while (value_off < line.len and line[value_off] == ' ') value_off += 1;
        const value = line[value_off..];

        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            content_length = std.fmt.parseInt(u64, value, 10) catch 0;
        } else if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (std.ascii.eqlIgnoreCase(value, "close")) keep_alive = false;
            if (std.ascii.eqlIgnoreCase(value, "keep-alive")) keep_alive = true;
        } else if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
            const chunked_pos = if (comptime ZIG_SEMVER.MINOR == 16)
                std.ascii.indexOfIgnoreCase(value, "chunked")
            else
                std.ascii.findIgnoreCase(value, "chunked");

            if (chunked_pos != null) chunked_request = true;
        } else if (std.ascii.eqlIgnoreCase(name, "expect")) {
            if (std.ascii.eqlIgnoreCase(value, "100-continue")) expect_continue = true;
        } else if (std.ascii.eqlIgnoreCase(name, "accept-encoding")) {
            accept_encoding = .{ .off = @intCast(line_start + value_off), .len = @intCast(value.len) };
        }
    }

    return .{ .head = .{
        .method = method,
        .path = path,
        .query = query,
        .raw_headers = raw_headers,
        .version_minor = version_minor,
        .keep_alive = keep_alive,
        .content_length = content_length,
        .chunked_request = chunked_request,
        .expect_continue = expect_continue,
        .accept_encoding = accept_encoding,
    }, .body_offset = body_offset };
}

/// Parse a complete HTTP/1.x request from buf.
/// buf must contain the full header block ending with \r\n\r\n.
/// All slices in ParsedHead point into buf (zero copy).
///
/// Return:
/// - !struct{ head: ParsedHead, body_offset: usize }
/// - error.ZixIncompleteHeader when \r\n\r\n has not arrived yet
/// - error.ZixInvalidRequest on a malformed request line
/// - error.ZixUnknownMethod when the method is not one this engine implements
pub fn parseHead(buf: []const u8) !ParseResult {
    const header_end = std.mem.indexOf(u8, buf, "\r\n\r\n") orelse return error.ZixIncompleteHeader;
    return parseHeadAt(buf, header_end);
}

/// Case-insensitive header lookup, scanning raw_headers on demand.
/// Cost is paid only by handlers that actually read a header.
pub fn getHeader(head: *const ParsedHead, name: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos < head.raw_headers.len) {
        const line_end = std.mem.indexOfPos(u8, head.raw_headers, pos, "\r\n") orelse head.raw_headers.len;
        const line = head.raw_headers[pos..line_end];
        pos = line_end + 2;
        if (line.len == 0) break;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], name)) continue;

        var value_off: usize = colon + 1;
        while (value_off < line.len and line[value_off] == ' ') value_off += 1;

        return line[value_off..];
    }

    return null;
}

/// The Accept-Encoding value for this request. O(1) when the producing parse
/// pass captured (or ruled out) the header, one getHeader scan otherwise.
///
/// Return:
/// - ?[]const u8 (the raw field value, or null when the header is absent)
pub fn acceptEncoding(head: *const ParsedHead) ?[]const u8 {
    return switch (head.accept_encoding.off) {
        SPAN_UNSCANNED => getHeader(head, "accept-encoding"),
        SPAN_ABSENT => null,
        else => head.raw_headers[head.accept_encoding.off..][0..head.accept_encoding.len],
    };
}

/// Linear scan for a single query parameter by exact name.
/// Does not percent-decode keys or values.
///
/// Return:
/// - ?[]const u8 (raw value slice, or null if not found)
pub fn queryParam(head: *const ParsedHead, name: []const u8) ?[]const u8 {
    if (head.query.len == 0) return null;

    var it = std.mem.splitScalar(u8, head.query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], name)) return pair[eq + 1 ..];
    }

    return null;
}

/// Percent-decode buf in place.
///
/// Return:
/// - []u8 (decoded slice, shorter or equal length)
pub fn percentDecode(buf: []u8) []u8 {
    return std.Uri.percentDecodeInPlace(buf);
}

/// Parse "bytes=start-end" or "bytes=start-" (open-ended).
///
/// Return:
/// - ?Range (null for invalid or unsatisfiable range)
pub fn parseRange(val: []const u8, total: u64) ?Range {
    if (!std.mem.startsWith(u8, val, "bytes=")) return null;
    const spec = val[6..];
    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return null;
    if (total == 0) return null;

    const start_str = spec[0..dash];
    const end_str = spec[dash + 1 ..];

    const start = std.fmt.parseInt(u64, start_str, 10) catch return null;
    if (start >= total) return null;

    const end: u64 = if (end_str.len == 0)
        total - 1
    else blk: {
        const e = std.fmt.parseInt(u64, end_str, 10) catch return null;
        break :blk if (e >= total) total - 1 else e;
    };

    if (start > end) return null;
    return .{ .start = start, .end = end };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http1: parseHead, GET request fields" {
    const result = try parseHead("GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n");
    try std.testing.expectEqualStrings("GET", result.head.method);
    try std.testing.expectEqualStrings("/ping", result.head.path);
    try std.testing.expectEqualStrings("", result.head.query);
    try std.testing.expectEqual(@as(u8, 1), result.head.version_minor);
    try std.testing.expect(result.head.keep_alive);
}

test "zix http1: parseHead, query string split from path" {
    const result = try parseHead("GET /search?q=zig&page=2 HTTP/1.1\r\n\r\n");
    try std.testing.expectEqualStrings("/search", result.head.path);
    try std.testing.expectEqualStrings("q=zig&page=2", result.head.query);
}

test "zix http1: parseHead, POST with Content-Length" {
    const result = try parseHead("POST /api HTTP/1.1\r\nContent-Length: 13\r\n\r\n");
    try std.testing.expectEqualStrings("POST", result.head.method);
    try std.testing.expectEqual(@as(u64, 13), result.head.content_length);
}

test "zix http1: parseHead, HTTP/1.0 defaults keep_alive to false" {
    const result = try parseHead("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n");
    try std.testing.expectEqual(@as(u8, 0), result.head.version_minor);
    try std.testing.expect(!result.head.keep_alive);
}

test "zix http1: parseHead, Connection keep-alive overrides HTTP/1.0 default" {
    const result = try parseHead("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n");
    try std.testing.expect(result.head.keep_alive);
}

test "zix http1: parseHead, Expect: 100-continue sets flag" {
    const result = try parseHead("POST /up HTTP/1.1\r\nContent-Length: 512\r\nExpect: 100-continue\r\n\r\n");
    try std.testing.expect(result.head.expect_continue);
}

test "zix http1: getHeader, case-insensitive lookup" {
    const result = try parseHead("GET / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n");
    try std.testing.expectEqualStrings("text/plain", getHeader(&result.head, "content-type").?);
    try std.testing.expectEqualStrings("text/plain", getHeader(&result.head, "CONTENT-TYPE").?);
    try std.testing.expect(getHeader(&result.head, "x-missing") == null);
}

test "zix http1: acceptEncoding, captured in the parse pass" {
    const result = try parseHead("GET /json HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip, br\r\n\r\n");

    // Captured span: O(1) read, no rescan of the header block.
    try std.testing.expect(result.head.accept_encoding.off != SPAN_UNSCANNED);
    try std.testing.expect(result.head.accept_encoding.off != SPAN_ABSENT);
    try std.testing.expectEqualStrings("gzip, br", acceptEncoding(&result.head).?);

    // Case-insensitive header name, same capture.
    const upper = try parseHead("GET / HTTP/1.1\r\nACCEPT-ENCODING: deflate\r\n\r\n");
    try std.testing.expectEqualStrings("deflate", acceptEncoding(&upper.head).?);
}

test "zix http1: acceptEncoding, definitive absence needs no fallback scan" {
    const result = try parseHead("GET / HTTP/1.1\r\nHost: x\r\n\r\n");

    try std.testing.expectEqual(SPAN_ABSENT, result.head.accept_encoding.off);
    try std.testing.expect(acceptEncoding(&result.head) == null);
}

test "zix http1: acceptEncoding, unscanned head falls back to getHeader" {
    // A head built without a capturing parse pass (span defaulted): the reader
    // falls back to the on-demand scan, so correctness never depends on the
    // producing path.
    var head = (try parseHead("GET / HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n")).head;
    head.accept_encoding = .{};

    try std.testing.expectEqual(SPAN_UNSCANNED, head.accept_encoding.off);
    try std.testing.expectEqualStrings("gzip", acceptEncoding(&head).?);
}

test "zix http1: queryParam, single and multiple params" {
    const result = try parseHead("GET /p?name=alice&age=30 HTTP/1.1\r\n\r\n");
    try std.testing.expectEqualStrings("alice", queryParam(&result.head, "name").?);
    try std.testing.expectEqualStrings("30", queryParam(&result.head, "age").?);
    try std.testing.expect(queryParam(&result.head, "missing") == null);
}

test "zix http1: parseRange, valid and boundary cases" {
    try std.testing.expectEqual(Range{ .start = 0, .end = 99 }, parseRange("bytes=0-99", 200).?);
    try std.testing.expectEqual(Range{ .start = 100, .end = 199 }, parseRange("bytes=100-", 200).?);
    try std.testing.expectEqual(Range{ .start = 0, .end = 199 }, parseRange("bytes=0-999", 200).?);
    try std.testing.expect(parseRange("bytes=200-", 200) == null);
    try std.testing.expect(parseRange("notbytes=0-99", 200) == null);
}

test "zix http1: percentDecode, encoded chars decoded in place" {
    var buf = [_]u8{ 'a', '%', '2', '0', 'b' };
    const decoded = percentDecode(&buf);
    try std.testing.expectEqualStrings("a b", decoded);
}
