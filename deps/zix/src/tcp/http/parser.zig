//! zix http parser
//!
//! Pure zero-copy HTTP/1.1 request parser.
//! No I/O, no allocation. All output fields are byte offsets into the caller's buffer.
//! parse() yields null when the buffer does not yet contain a complete header block.

const std = @import("std");
const Method = @import("method.zig");
const ZIG_SEMVER = @import("../../lib.zig").ZIG_SEMVER;

pub const MAX_HEADERS: usize = 64;
pub const MAX_HEADERS_U8: u8 = MAX_HEADERS;

// --------------------------------------------------------- //

/// Request header cap tier. Controls how many headers the server accepts before rejecting with 431.
/// Mirrors HeaderSize for response headers. CUSTOM values above 64 are silently capped at 64.
pub const RequestHeaderSize = union(enum) {
    MINIMAL, // 16
    COMMON, // 32
    LARGE, // 64 (parser storage limit)
    CUSTOM: u8,

    pub fn value(self: RequestHeaderSize) u8 {
        return switch (self) {
            .MINIMAL => 16,
            .COMMON => 32,
            .LARGE => MAX_HEADERS,
            .CUSTOM => |n| @min(n, MAX_HEADERS),
        };
    }
};

/// Fully parsed HTTP/1.1 request head, encoded as offsets into the read buffer.
/// Pre-parses method, keep_alive, and content_length to avoid re-scanning on the hot path.
pub const ParsedHead = struct {
    method: Method.Code,
    path_start: u16,
    path_len: u16,
    query_start: u16, // 0 when no query string. Check query_len instead.
    query_len: u16,
    /// Raw header block: the header lines after the request line, up to but not
    /// including the terminating CRLF. Scanned on demand by getHeader. Lazy: no
    /// per-request header array is built, only the framing headers are pre-parsed.
    headers_start: u16,
    headers_len: u16,
    body_offset: u16, // byte index of first body byte (header_end + 4)
    keep_alive: bool, // false when Connection: close was sent, true otherwise (HTTP/1.1 default)
    content_length: u64,
    chunked: bool, // true when Transfer-Encoding: chunked
    /// True when the client sent Expect: 100-continue and is waiting for the
    /// interim response before it sends the body.
    expect_continue: bool,
};

pub const ParseError = error{
    ZixInvalidRequest,
    ZixTooManyHeaders,
    /// Well-formed request line naming a method this engine does not implement.
    /// Distinct from ZixInvalidRequest so the caller can answer 501 rather than 400.
    ZixUnknownMethod,
};

const DechunkError = error{
    ZixInvalidChunkSize,
};

/// Find the start index of the end-of-headers marker "\r\n\r\n".
/// Scans for '\n' with a vectorized scalar search and verifies the three
/// preceding bytes, avoiding the per-window byte compare that a multi-byte
/// indexOf incurs (mem.eql at every position).
///
/// Param:
/// buf - []const u8 (bytes to search)
/// start - usize (byte index to begin scanning, clamped so a 3-byte look-back is valid)
///
/// Return:
/// - index of the first '\r' of "\r\n\r\n", or null when not present
pub fn findHeaderEnd(buf: []const u8, start: usize) ?usize {
    var i = @max(start, 3);
    while (std.mem.indexOfScalarPos(u8, buf, i, '\n')) |nl| {
        if (buf[nl - 1] == '\r' and buf[nl - 2] == '\n' and buf[nl - 3] == '\r') {
            return nl - 3;
        }
        i = nl + 1;
    }
    return null;
}

/// Fast path for the common GET request: extract method, path, and query with direct integer
/// compares and a single header-region scan, skipping the per-line header loop that the full parse
/// runs. Returns null (falling back to the full parse) unless the request is a plain keep-alive GET
/// with no framing headers, so correctness is never traded for speed.
///
/// Note:
/// - The header region is bailed to the full parse when it carries a Connection header (keep-alive
///   needs the per-line value), Content-Length (a body), or Transfer-Encoding (chunked). The bail
///   probes are case-robust: the first letter is skipped so "Content-" and "content-" both match.
/// - Mirrors zix.Http1's parseGetFastPath, hardened so a GET carrying a body or an explicit
///   Connection header is never mis-framed.
fn parseGetFast(buf: []const u8, header_end: usize) ?ParsedHead {
    if (buf.len < 16) return null;
    if (std.mem.readInt(u32, buf[0..4], .little) != comptime std.mem.readInt(u32, "GET ", .little)) return null;

    const line_end = std.mem.indexOfScalarPos(u8, buf, 4, '\r') orelse return null;

    // Minimum for "GET / HTTP/1.1": line_end >= 14, the last 9 bytes of the line are " HTTP/1.1".
    if (line_end < 14) return null;
    if (buf[line_end - 9] != ' ') return null;
    if (std.mem.readInt(u64, buf[line_end - 8 ..][0..8], .little) != comptime std.mem.readInt(u64, "HTTP/1.1", .little)) return null;

    const target = buf[4 .. line_end - 9];
    var path_len: u16 = @intCast(target.len);
    var query_start: u16 = 0;
    var query_len: u16 = 0;
    if (std.mem.indexOfScalar(u8, target, '?')) |q| {
        path_len = @intCast(q);
        query_start = @intCast(4 + q + 1);
        query_len = @intCast(target.len - q - 1);
    }

    const headers_start = line_end + 2;
    const header_region = if (headers_start < header_end) buf[headers_start..header_end] else buf[0..0];

    if (std.mem.indexOf(u8, header_region, "onnection") != null) return null; // any Connection header
    if (std.mem.indexOf(u8, header_region, "ontent-") != null) return null; // Content-Length (body)
    if (std.mem.indexOf(u8, header_region, "ransfer-") != null) return null; // Transfer-Encoding (chunked)

    return ParsedHead{
        .method = .GET,
        .path_start = 4,
        .path_len = path_len,
        .query_start = query_start,
        .query_len = query_len,
        .headers_start = @intCast(headers_start),
        .headers_len = @intCast(if (headers_start < header_end) header_end - headers_start else 0),
        .body_offset = @intCast(header_end + 4),
        .keep_alive = true,
        .content_length = 0,
        .chunked = false,
        .expect_continue = false,
    };
}

/// Parse an HTTP/1.1 request from buf.
/// On success the returned ParsedHead contains only offsets into buf, no data is copied.
///
/// Return:
/// - null when the buffer does not contain a complete header block (\r\n\r\n not found)
/// - ParseError on malformed input
pub fn parse(buf: []const u8, max_headers: u8) ParseError!?ParsedHead {
    // Scan for the end-of-headers marker. Search stops as soon as it is found.
    const header_end = findHeaderEnd(buf, 0) orelse return null;

    // Fast path for the common keep-alive GET: skips the per-line header scan. Bails to the full
    // parse below for anything with framing or Connection headers.
    if (parseGetFast(buf, header_end)) |fast| return fast;
    const head_buf = buf[0..header_end];

    // Parse request line: "METHOD TARGET HTTP/1.1"
    // When there are no additional headers, head_buf IS the request line (no \r\n inside it).
    // Scan for '\n' (vectorized) and step back over the '\r' to locate the CRLF.
    const first_nl = std.mem.indexOfScalar(u8, head_buf, '\n') orelse head_buf.len;
    const first_crlf = if (first_nl > 0 and head_buf[first_nl - 1] == '\r') first_nl - 1 else first_nl;
    const req_line = head_buf[0..first_crlf];

    const first_space = std.mem.indexOfScalar(u8, req_line, ' ') orelse return error.ZixInvalidRequest;
    // The line tokenized, so an unmatched token is an unimplemented method rather
    // than a malformed request. The caller turns this into a 501.
    const method_code = Method.codeFromString(req_line[0..first_space]) orelse return error.ZixUnknownMethod;

    const after_method = req_line[first_space + 1 ..];
    const second_space = std.mem.indexOfScalar(u8, after_method, ' ') orelse return error.ZixInvalidRequest;
    const target = after_method[0..second_space];

    // Absolute offsets of path and query into buf.
    const path_abs: u16 = @intCast(first_space + 1);
    var path_len: u16 = undefined;
    var query_start: u16 = 0;
    var query_len: u16 = 0;
    if (std.mem.indexOfScalar(u8, target, '?')) |q| {
        path_len = @intCast(q);
        query_start = @intCast(first_space + 1 + q + 1);
        const qlen = target.len - q - 1;
        query_len = @intCast(qlen);
    } else {
        path_len = @intCast(target.len);
    }

    // Scan header lines once to pre-parse the framing headers and enforce the
    // header-count limit. Individual headers are NOT stored: getHeader rescans the
    // raw block on demand (lazy parseHead), which keeps ParsedHead small and skips
    // the per-request header-array fill on the hot path.
    const headers_start: usize = first_nl + 1;
    var header_count: u8 = 0;
    var keep_alive = true; // HTTP/1.1 default
    var content_length: u64 = 0;
    var chunked = false;
    var expect_continue = false;

    var pos: usize = headers_start;
    while (pos < head_buf.len) {
        // Vectorized scan for the line's '\n', then step back over the '\r'.
        const nl = std.mem.indexOfScalarPos(u8, head_buf, pos, '\n') orelse head_buf.len;
        const line_end = if (nl > pos and head_buf[nl - 1] == '\r') nl - 1 else nl;
        const line = head_buf[pos..line_end];
        if (line.len == 0) break;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse {
            pos = nl + 1;
            continue;
        };

        if (header_count >= max_headers) return error.ZixTooManyHeaders;
        header_count += 1;

        // Skip colon + leading whitespace for value.
        var val_off = colon + 1;
        while (val_off < line.len and line[val_off] == ' ') val_off += 1;

        // Pre-parse the framing headers to avoid rescanning them on the hot
        // path. Dispatch on name length first: the three framing names have
        // distinct lengths (10, 14, 17), so most header lines do no string
        // compare at all, and a length match does at most one.
        const name = line[0..colon];
        const value = line[val_off..];
        switch (name.len) {
            6 => if (std.ascii.eqlIgnoreCase(name, "expect")) {
                if (std.ascii.eqlIgnoreCase(value, "100-continue")) expect_continue = true;
            },
            10 => if (std.ascii.eqlIgnoreCase(name, "connection")) {
                if (std.ascii.eqlIgnoreCase(value, "close")) keep_alive = false;
            },
            14 => if (std.ascii.eqlIgnoreCase(name, "content-length")) {
                content_length = std.fmt.parseInt(u64, value, 10) catch 0;
            },
            17 => if (std.ascii.eqlIgnoreCase(name, "transfer-encoding")) {
                // RFC 9112 allows a coding list, so "gzip, chunked" is a chunked
                // request. An exact compare framed it as bodyless and let the
                // body become the next request. Same search zix.Http1 uses, one
                // pass over one header value inside this walk.
                const chunked_pos = if (comptime ZIG_SEMVER.MINOR == 16)
                    std.ascii.indexOfIgnoreCase(value, "chunked")
                else
                    std.ascii.findIgnoreCase(value, "chunked");

                if (chunked_pos != null) chunked = true;
            },
            else => {},
        }

        pos = nl + 1;
    }

    return ParsedHead{
        .method = method_code,
        .path_start = path_abs,
        .path_len = path_len,
        .query_start = query_start,
        .query_len = query_len,
        .headers_start = @intCast(headers_start),
        .headers_len = @intCast(if (headers_start < head_buf.len) head_buf.len - headers_start else 0),
        .body_offset = @intCast(header_end + 4),
        .keep_alive = keep_alive,
        .content_length = content_length,
        .chunked = chunked,
        .expect_continue = expect_continue,
    };
}

/// Look up a request header value by name (case-insensitive), scanning the raw
/// header block on demand. The lazy counterpart to the old per-request header
/// array: nothing is stored at parse time, the block is rescanned per lookup.
///
/// Param:
/// head - ParsedHead
/// buf - []const u8 (the read buffer the offsets point into)
/// name - []const u8 (header name, case-insensitive)
///
/// Return:
/// - the header value with leading optional whitespace trimmed, or null when absent
pub fn getHeader(head: ParsedHead, buf: []const u8, name: []const u8) ?[]const u8 {
    if (head.headers_len == 0) return null;

    const block = buf[head.headers_start..][0..head.headers_len];
    var pos: usize = 0;
    while (pos < block.len) {
        const nl = std.mem.indexOfScalarPos(u8, block, pos, '\n') orelse block.len;
        const line_end = if (nl > pos and block[nl - 1] == '\r') nl - 1 else nl;
        const line = block[pos..line_end];
        pos = nl + 1;
        if (line.len == 0) continue;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(line[0..colon], name)) continue;

        var val_off = colon + 1;
        while (val_off < line.len and line[val_off] == ' ') val_off += 1;

        return line[val_off..];
    }

    return null;
}

/// Walk the chunk framing in raw and report where the body ends.
///
/// Note:
/// - Steps over chunk data by its declared size, so the cost is one step per
///   chunk rather than one per byte. Data that happens to spell the terminal
///   chunk cannot be mistaken for it, which a byte search cannot promise.
/// - The reader calls this after each read to decide whether to read again, and
///   carries scan_from between calls so each chunk is walked once no matter how
///   many segments the body arrives in.
///
/// Param:
/// raw - []const u8 (chunked bytes received so far, framing included)
/// scan_from - *usize (last verified chunk boundary, start at 0 and reuse the same variable)
///
/// Return:
/// - usize (bytes of raw the body occupies, terminal chunk and trailers included)
/// - null when the body has not fully arrived
/// - error.ZixInvalidChunkSize when a size line is not hex
pub fn chunkedEnd(raw: []const u8, scan_from: *usize) DechunkError!?usize {
    var pos: usize = scan_from.*;

    while (true) {
        scan_from.* = pos;

        const crlf = std.mem.indexOfPos(u8, raw, pos, "\r\n") orelse return null;
        const size_line = raw[pos..crlf];

        const ext_pos = std.mem.indexOfScalar(u8, size_line, ';') orelse size_line.len;
        const size_hex = std.mem.trim(u8, size_line[0..ext_pos], " \t");
        if (size_hex.len == 0) return error.ZixInvalidChunkSize;

        const chunk_size = std.fmt.parseInt(usize, size_hex, 16) catch return error.ZixInvalidChunkSize;

        if (chunk_size == 0) {
            // Terminal chunk. The trailer section runs to the first blank line.
            var trailer_pos = crlf + 2;
            while (true) {
                const trailer_end = std.mem.indexOfPos(u8, raw, trailer_pos, "\r\n") orelse return null;
                if (trailer_end == trailer_pos) return trailer_end + 2;

                trailer_pos = trailer_end + 2;
            }
        }

        const data_end = crlf + 2 + chunk_size;
        if (data_end + 2 > raw.len) return null;

        pos = data_end + 2;
    }
}

/// Decode chunked bytes over themselves, no second buffer.
///
/// Note:
/// - Decoding only ever removes framing, so the output is never longer than the
///   input and every byte moves left. That makes the destination a prefix of the
///   source, and a forward copy correct even where the two ranges overlap.
///   @memcpy cannot be used here, it requires disjoint ranges.
/// - Saves the allocation and the full-body copy a separate output buffer costs.
///
/// Param:
/// raw - []u8 (chunked bytes, overwritten with the decoded body)
///
/// Return:
/// - usize (decoded bytes, living at raw[0..returned])
/// - error.ZixInvalidChunkSize when a size line is not hex
pub fn dechunkInPlace(raw: []u8) DechunkError!usize {
    var pos: usize = 0;
    var written: usize = 0;

    while (pos < raw.len) {
        const crlf = std.mem.indexOfPos(u8, raw, pos, "\r\n") orelse break;
        const size_line = raw[pos..crlf];

        const ext_pos = std.mem.indexOfScalar(u8, size_line, ';') orelse size_line.len;
        const size_hex = std.mem.trim(u8, size_line[0..ext_pos], " \t");
        if (size_hex.len == 0) return error.ZixInvalidChunkSize;

        const chunk_size = std.fmt.parseInt(usize, size_hex, 16) catch return error.ZixInvalidChunkSize;
        if (chunk_size == 0) break;

        const data_start = crlf + 2;
        const data_end = data_start + chunk_size;
        if (data_end > raw.len) break;

        std.mem.copyForwards(u8, raw[written..][0..chunk_size], raw[data_start..data_end]);
        written += chunk_size;

        pos = data_end + 2;
    }

    return written;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http: parser incomplete returns null" {
    try std.testing.expect(try parse("GET / HTTP/1.1\r\n", 64) == null);
    try std.testing.expect(try parse("GET / HTTP/1.1\r\nHost: x\r\n", 64) == null);
    try std.testing.expect(try parse("", 64) == null);
}

test "zix http: parser minimal GET" {
    const raw = "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const h = (try parse(raw, 64)).?;
    try std.testing.expectEqual(Method.Code.GET, h.method);
    try std.testing.expectEqualStrings("/", raw[h.path_start..][0..h.path_len]);
    try std.testing.expectEqual(@as(u16, 0), h.query_len);
    try std.testing.expectEqualStrings("localhost", getHeader(h, raw, "host").?);
    try std.testing.expect(h.keep_alive);
    try std.testing.expectEqual(@as(u64, 0), h.content_length);
}

test "zix http: parser path and query" {
    const raw = "GET /api/users/123?name=alice&flag HTTP/1.1\r\n\r\n";
    const h = (try parse(raw, 64)).?;
    try std.testing.expectEqualStrings("/api/users/123", raw[h.path_start..][0..h.path_len]);
    try std.testing.expectEqualStrings("name=alice&flag", raw[h.query_start..][0..h.query_len]);
}

test "zix http: parser header offsets" {
    const raw = "POST /data HTTP/1.1\r\nContent-Length: 5\r\nX-Foo: bar\r\n\r\nhello";
    const h = (try parse(raw, 64)).?;
    try std.testing.expectEqual(Method.Code.POST, h.method);
    try std.testing.expectEqual(@as(u64, 5), h.content_length);
    // Headers are scanned on demand from the raw block (case-insensitive).
    try std.testing.expectEqualStrings("5", getHeader(h, raw, "content-length").?);
    try std.testing.expectEqualStrings("bar", getHeader(h, raw, "X-Foo").?);
    try std.testing.expect(getHeader(h, raw, "missing") == null);
    // Body offset points right after \r\n\r\n
    try std.testing.expectEqualStrings("hello", raw[h.body_offset..]);
}

test "zix http: parser keep_alive false on Connection: close" {
    const raw = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    const h = (try parse(raw, 64)).?;
    try std.testing.expect(!h.keep_alive);
}

test "zix http: parser all methods" {
    const cases = [_]struct { raw: []const u8, code: Method.Code }{
        .{ .raw = "GET / HTTP/1.1\r\n\r\n", .code = .GET },
        .{ .raw = "HEAD / HTTP/1.1\r\n\r\n", .code = .HEAD },
        .{ .raw = "POST / HTTP/1.1\r\n\r\n", .code = .POST },
        .{ .raw = "PUT / HTTP/1.1\r\n\r\n", .code = .PUT },
        .{ .raw = "DELETE / HTTP/1.1\r\n\r\n", .code = .DELETE },
        .{ .raw = "PATCH / HTTP/1.1\r\n\r\n", .code = .PATCH },
        .{ .raw = "OPTIONS / HTTP/1.1\r\n\r\n", .code = .OPTIONS },
    };
    for (cases) |c| {
        const h = (try parse(c.raw, 64)).?;
        try std.testing.expectEqual(c.code, h.method);
    }
}

test "zix http: parser an unimplemented method is UnknownMethod, not InvalidRequest" {
    // The request line tokenized fine, so the caller owes a 501 rather than a 400.
    try std.testing.expectError(error.ZixUnknownMethod, parse("BREW / HTTP/1.1\r\n\r\n", 64));
    try std.testing.expectError(error.ZixUnknownMethod, parse("QUERX / HTTP/1.1\r\n\r\n", 64));
}

test "zix http: parser a malformed request line stays InvalidRequest" {
    // No space at all, then only one space. Neither tokenizes, so neither is a
    // statement about the method.
    try std.testing.expectError(error.ZixInvalidRequest, parse("GET\r\n\r\n", 64));
    try std.testing.expectError(error.ZixInvalidRequest, parse("GET /x\r\n\r\n", 64));
}

test "zix http: parser chunked flag set when Transfer-Encoding: chunked" {
    const raw = "POST /upload HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    const h = (try parse(raw, 64)).?;
    try std.testing.expect(h.chunked);
}

test "zix http: parser length-switch rejects same-length non-framing headers" {
    // Names that collide in length with the framing headers must still be
    // rejected by the eqlIgnoreCase guard inside each switch arm: "User-Agent"
    // (10) vs "connection", "Accept-Charset" (14) vs "content-length".
    const raw = "GET / HTTP/1.1\r\nUser-Agent: ua\r\nAccept-Charset: utf-8\r\n\r\n";
    const h = (try parse(raw, 16)).?;
    try std.testing.expect(h.keep_alive);
    try std.testing.expectEqual(@as(u64, 0), h.content_length);
    try std.testing.expect(!h.chunked);
}

test "zix http: parser chunked flag set when chunked is the last transfer coding" {
    // RFC 9112 lets Transfer-Encoding carry a coding list as long as chunked is
    // last. Missing it frames the request as bodyless, so the chunked body that
    // follows is read as the next request on the connection.
    const raw = "POST /upload HTTP/1.1\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
    const h = (try parse(raw, 64)).?;
    try std.testing.expect(h.chunked);
}

test "zix http: parser non-numeric Content-Length falls back to zero" {
    const raw = "POST /upload HTTP/1.1\r\nContent-Length: abc\r\n\r\n";
    const h = (try parse(raw, 64)).?;
    try std.testing.expectEqual(@as(u64, 0), h.content_length);
}

test "zix http: parser Content-Length past u64 falls back to zero" {
    const raw = "POST /upload HTTP/1.1\r\nContent-Length: 99999999999999999999999\r\n\r\n";
    const h = (try parse(raw, 64)).?;
    try std.testing.expectEqual(@as(u64, 0), h.content_length);
}

test "zix http: parser reads Content-Length case-insensitively on the full parse" {
    const raw = "POST /upload HTTP/1.1\r\ncOnTeNt-LeNgTh: 20971520\r\n\r\n";
    const h = (try parse(raw, 64)).?;
    try std.testing.expectEqual(@as(u64, 20971520), h.content_length);
}

test "zix http: parser chunked flag false when Transfer-Encoding absent" {
    const raw = "POST /upload HTTP/1.1\r\nContent-Length: 5\r\n\r\n";
    const h = (try parse(raw, 64)).?;
    try std.testing.expect(!h.chunked);
}

test "zix http: parseGetFast serves a plain keep-alive GET with query and headers" {
    // No Connection / Content-Length / Transfer-Encoding header, so the fast path applies.
    const raw = "GET /search?q=zig HTTP/1.1\r\nHost: x\r\nAccept: */*\r\n\r\n";
    const h = (try parse(raw, 64)).?;
    try std.testing.expectEqual(Method.Code.GET, h.method);
    try std.testing.expectEqualStrings("/search", raw[h.path_start..][0..h.path_len]);
    try std.testing.expectEqualStrings("q=zig", raw[h.query_start..][0..h.query_len]);
    try std.testing.expect(h.keep_alive);
    try std.testing.expectEqual(@as(u64, 0), h.content_length);
    try std.testing.expect(!h.chunked);
    try std.testing.expectEqualStrings("x", getHeader(h, raw, "host").?);
}

test "zix http: parseGetFast bails on a Connection header so keep-alive stays correct" {
    const raw = "GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
    const h = (try parse(raw, 64)).?;
    try std.testing.expectEqual(Method.Code.GET, h.method);
    try std.testing.expect(!h.keep_alive); // the full parse read Connection: close
}

test "zix http: parseGetFast bails on a GET body so Content-Length is framed" {
    const raw = "GET /x HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    const h = (try parse(raw, 64)).?;
    try std.testing.expectEqualStrings("/x", raw[h.path_start..][0..h.path_len]);
    try std.testing.expectEqual(@as(u64, 5), h.content_length);
}

test "zix http: parseGetFast bail probe is case-robust for a lowercase content-length" {
    const raw = "GET / HTTP/1.1\r\ncontent-length: 3\r\n\r\nabc";
    const h = (try parse(raw, 64)).?;
    try std.testing.expectEqual(@as(u64, 3), h.content_length);
}

test "zix http: parseGetFast bails on Transfer-Encoding chunked" {
    const raw = "GET / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    const h = (try parse(raw, 64)).?;
    try std.testing.expect(h.chunked);
}

test "zix http: parseGetFast declines non-GET and HTTP/1.0 (full parse handles them)" {
    const post = "POST /data HTTP/1.1\r\nContent-Length: 2\r\n\r\nhi";
    const hp = (try parse(post, 64)).?;
    try std.testing.expectEqual(Method.Code.POST, hp.method);

    const v10 = "GET / HTTP/1.0\r\nHost: x\r\n\r\n";
    const h10 = (try parse(v10, 64)).?;
    try std.testing.expectEqual(Method.Code.GET, h10.method);
    try std.testing.expectEqualStrings("/", v10[h10.path_start..][0..h10.path_len]);
}

test "zix http: chunkedEnd reports the body length once the terminator arrived" {
    const raw = "5\r\nhello\r\n0\r\n\r\n";
    var scan_from: usize = 0;
    try std.testing.expectEqual(@as(?usize, raw.len), try chunkedEnd(raw, &scan_from));
}

test "zix http: chunkedEnd is null while the body is still arriving" {
    var scan_from: usize = 0;
    try std.testing.expectEqual(@as(?usize, null), try chunkedEnd("5\r\nhel", &scan_from));

    scan_from = 0;
    try std.testing.expectEqual(@as(?usize, null), try chunkedEnd("5\r\nhello\r\n", &scan_from));

    scan_from = 0;
    try std.testing.expectEqual(@as(?usize, null), try chunkedEnd("5\r\nhello\r\n0\r\n", &scan_from));
}

test "zix http: chunkedEnd resumes from the watermark across segments" {
    const raw = "3\r\nabc\r\n3\r\ndef\r\n0\r\n\r\n";
    var scan_from: usize = 0;

    // One chunk in hand: the walk stops at the second chunk's size line.
    try std.testing.expectEqual(@as(?usize, null), try chunkedEnd(raw[0..8], &scan_from));
    try std.testing.expectEqual(@as(usize, 8), scan_from);

    // The rest arrives and the walk carries on from there, not from byte zero.
    try std.testing.expectEqual(@as(?usize, raw.len), try chunkedEnd(raw, &scan_from));
}

test "zix http: chunkedEnd steps over data that spells the terminator" {
    // The chunk data is the terminator byte-for-byte. A byte search would stop
    // inside it and cut the body short, the framing walk steps past it.
    const raw = "5\r\n0\r\n\r\n\r\n0\r\n\r\n";
    var scan_from: usize = 0;
    try std.testing.expectEqual(@as(?usize, raw.len), try chunkedEnd(raw, &scan_from));
}

test "zix http: chunkedEnd counts the trailer section into the body length" {
    const raw = "3\r\nabc\r\n0\r\nX-Sum: 1\r\n\r\n";
    var scan_from: usize = 0;
    try std.testing.expectEqual(@as(?usize, raw.len), try chunkedEnd(raw, &scan_from));
}

test "zix http: chunkedEnd stops at the pipelined request behind the terminator" {
    const body = "3\r\nabc\r\n0\r\n\r\n";
    const raw = body ++ "GET /next HTTP/1.1\r\n\r\n";
    var scan_from: usize = 0;
    try std.testing.expectEqual(@as(?usize, body.len), try chunkedEnd(raw, &scan_from));
}

test "zix http: chunkedEnd rejects a size line that is not hex" {
    var scan_from: usize = 0;
    try std.testing.expectError(error.ZixInvalidChunkSize, chunkedEnd("zz\r\nabc\r\n0\r\n\r\n", &scan_from));
}

test "zix http: dechunkInPlace decodes over the source buffer" {
    var raw = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n".*;
    const len = try dechunkInPlace(&raw);
    try std.testing.expectEqualStrings("hello world", raw[0..len]);
}

test "zix http: dechunkInPlace moves a chunk longer than its own framing" {
    // Source and destination ranges overlap here (the chunk is far longer than
    // the framing it replaces), which is exactly what @memcpy may not do.
    const filler: [32]u8 = @splat('A');
    var raw = "20\r\n".* ++ filler ++ "\r\n0\r\n\r\n".*;

    const len = try dechunkInPlace(&raw);
    try std.testing.expectEqual(@as(usize, 32), len);
    try std.testing.expectEqualStrings(&filler, raw[0..len]);
}

test "zix http: dechunkInPlace joins every chunk in order" {
    var raw = "4\r\nzero\r\n3\r\nsix\r\n0\r\n\r\n".*;
    const got = try dechunkInPlace(&raw);
    try std.testing.expectEqualStrings("zerosix", raw[0..got]);
}
