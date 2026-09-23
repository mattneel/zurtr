//! zixer http2 translate: h2 header lists to h1 messages and back (rfc 9113 8)

const std = @import("std");
const zix = @import("zix");

const cfg_headers = @import("cfg_headers.zig");
const cfg_scanner = @import("cfg_scanner.zig");
const fault = @import("fault.zig");
const http1_head = @import("http1_head.zig");
const proxy_headers = @import("proxy_headers.zig");
const request_scheme = @import("request_scheme.zig");
const ws_tunnel = @import("ws_tunnel.zig");

const Http2 = zix.Http2;

/// Longest response header name the encoder lowercases. Longer names drop.
const NAME_LOWER_MAX: usize = 128;

pub const Error = error{
    /// The request breaks an rfc 9113 8.2 or 8.3 rule: the stream answers
    /// a protocol error, never the pool.
    ZixerMalformed,
    /// CONNECT without the rfc 8441 websocket extension. zixer only
    /// tunnels websocket.
    ZixerUnsupportedConnect,
};

/// One h2 request after pseudo-header validation. Slices borrow the decode
/// scratch of the header block, copy before the next decode.
pub const Request = struct {
    method: []const u8,
    target: []const u8,
    authority: []const u8,
    /// rfc 8441 extended CONNECT with :protocol websocket.
    is_connect: bool,
    is_head: bool,
    /// True when DATA frames follow (HEADERS came without END_STREAM).
    has_body: bool,
    content_length: ?u64,
    expects_continue: bool,
};

/// Validate the decoded header list of one HEADERS block and assemble the
/// request view (rfc 9113 8.2 and 8.3, rfc 8441 for extended CONNECT).
pub fn assemble(headers: []const Http2.Header, end_stream: bool) Error!Request {
    var method: ?[]const u8 = null;
    var target: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var authority: ?[]const u8 = null;
    var protocol: ?[]const u8 = null;
    var host_value: []const u8 = "";
    var content_length: ?u64 = null;
    var expects_continue = false;
    var seen_regular = false;

    for (headers) |header| {
        if (header.name.len == 0) return error.ZixerMalformed;

        if (header.name[0] == ':') {
            if (seen_regular) return error.ZixerMalformed;

            if (std.mem.eql(u8, header.name, ":method")) {
                if (method != null) return error.ZixerMalformed;
                method = header.value;
            } else if (std.mem.eql(u8, header.name, ":path")) {
                if (target != null) return error.ZixerMalformed;
                target = header.value;
            } else if (std.mem.eql(u8, header.name, ":scheme")) {
                if (scheme != null) return error.ZixerMalformed;
                scheme = header.value;
            } else if (std.mem.eql(u8, header.name, ":authority")) {
                if (authority != null) return error.ZixerMalformed;
                authority = header.value;
            } else if (std.mem.eql(u8, header.name, ":protocol")) {
                if (protocol != null) return error.ZixerMalformed;
                protocol = header.value;
            } else {
                return error.ZixerMalformed;
            }
            continue;
        }

        seen_regular = true;
        try validateRegularName(header.name);

        if (std.mem.eql(u8, header.name, "te")) {
            if (!std.ascii.eqlIgnoreCase(header.value, "trailers")) return error.ZixerMalformed;
        } else if (std.mem.eql(u8, header.name, "content-length")) {
            const parsed = std.fmt.parseInt(u64, header.value, 10) catch return error.ZixerMalformed;
            if (content_length) |seen| {
                if (seen != parsed) return error.ZixerMalformed;
            }
            content_length = parsed;
        } else if (std.mem.eql(u8, header.name, "host")) {
            host_value = header.value;
        } else if (std.mem.eql(u8, header.name, "expect")) {
            if (std.ascii.eqlIgnoreCase(header.value, "100-continue")) expects_continue = true;
        }
    }

    const method_value = method orelse return error.ZixerMalformed;
    if (method_value.len == 0) return error.ZixerMalformed;

    const final_authority = authority orelse host_value;

    if (std.mem.eql(u8, method_value, "CONNECT")) {
        // rfc 8441 5: extended CONNECT carries :protocol plus the full
        // :scheme / :path / :authority set. Plain CONNECT stays unsupported.
        const protocol_value = protocol orelse return error.ZixerUnsupportedConnect;
        if (!std.mem.eql(u8, protocol_value, "websocket")) return error.ZixerUnsupportedConnect;
        if (scheme == null) return error.ZixerMalformed;
        const connect_target = target orelse return error.ZixerMalformed;
        if (connect_target.len == 0) return error.ZixerMalformed;
        if (final_authority.len == 0) return error.ZixerMalformed;

        return .{
            .method = method_value,
            .target = connect_target,
            .authority = final_authority,
            .is_connect = true,
            .is_head = false,
            .has_body = false,
            .content_length = null,
            .expects_continue = false,
        };
    }

    if (protocol != null) return error.ZixerMalformed;
    if (scheme == null) return error.ZixerMalformed;
    const target_value = target orelse return error.ZixerMalformed;
    if (target_value.len == 0) return error.ZixerMalformed;
    if (final_authority.len == 0) return error.ZixerMalformed;

    // A body promised by content-length cannot ride a closed stream.
    if (end_stream and (content_length orelse 0) != 0) return error.ZixerMalformed;

    return .{
        .method = method_value,
        .target = target_value,
        .authority = final_authority,
        .is_connect = false,
        .is_head = std.mem.eql(u8, method_value, "HEAD"),
        .has_body = !end_stream,
        .content_length = content_length,
        .expects_continue = expects_continue,
    };
}

/// rfc 9113 8.2: field names travel lowercase, and connection-specific
/// headers make the whole request malformed.
fn validateRegularName(name: []const u8) Error!void {
    for (name) |char| {
        if (char >= 'A' and char <= 'Z') return error.ZixerMalformed;
    }

    const forbidden = [_][]const u8{ "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade" };
    for (forbidden) |bad| {
        if (std.mem.eql(u8, name, bad)) return error.ZixerMalformed;
    }
}

/// Build the h1 upstream head for a plain (non CONNECT) h2 request:
/// filtered headers plus Host, Via, Forwarded, and zixer's own framing.
pub fn buildUpstreamHead(buf: []u8, request: *const Request, headers: []const Http2.Header, client_addr: std.Io.net.IpAddress, scheme: request_scheme.Scheme, extra: cfg_headers.Block) ![]const u8 {
    var fixed = std.Io.Writer.fixed(buf);

    try fixed.print("{s} {s} HTTP/1.1\r\n", .{ request.method, request.target });
    try fixed.print("Host: {s}\r\n", .{request.authority});
    try writeFilteredHeaders(&fixed, headers, false, extra);
    try fixed.print("Via: {s}\r\n", .{proxy_headers.VIA});
    try proxy_headers.writeForwarded(&fixed, client_addr, request.authority, scheme);

    if (request.has_body) {
        if (request.content_length) |len| {
            try fixed.print("Content-Length: {d}\r\n", .{len});
        } else {
            try fixed.writeAll("Transfer-Encoding: chunked\r\n");
        }
    }

    try extra.write(&fixed);
    try fixed.writeAll("\r\n");

    return fixed.buffered();
}

/// Build the h1 upgrade head that bridges an extended CONNECT to a
/// websocket upstream (rfc 8441 to rfc 6455): the h1 leg needs the
/// Sec-WebSocket-Key the h2 leg never carries, key_b64 is zixer's own.
pub fn buildConnectHead(buf: []u8, request: *const Request, headers: []const Http2.Header, client_addr: std.Io.net.IpAddress, key_b64: []const u8, scheme: request_scheme.Scheme, extra: cfg_headers.Block) ![]const u8 {
    var fixed = std.Io.Writer.fixed(buf);

    try fixed.print("GET {s} HTTP/1.1\r\n", .{request.target});
    try fixed.print("Host: {s}\r\n", .{request.authority});
    try writeFilteredHeaders(&fixed, headers, true, extra);
    if (!hasName(headers, "sec-websocket-version")) try fixed.writeAll("Sec-WebSocket-Version: 13\r\n");
    try fixed.print("Sec-WebSocket-Key: {s}\r\n", .{key_b64});
    try fixed.print("Via: {s}\r\n", .{proxy_headers.VIA});
    try proxy_headers.writeForwarded(&fixed, client_addr, request.authority, scheme);
    try ws_tunnel.writeUpgradeHeaders(&fixed);

    try extra.write(&fixed);
    try fixed.writeAll("\r\n");

    return fixed.buffered();
}

/// Write the end-to-end request headers: pseudo, host, expect, and the
/// hop-by-hop set drop, cookie fields coalesce into one h1 line
/// (rfc 9113 8.2.3). for_connect also drops a stray sec-websocket-key,
/// the bridge writes its own.
fn writeFilteredHeaders(out: *std.Io.Writer, headers: []const Http2.Header, for_connect: bool, extra: cfg_headers.Block) !void {
    for (headers) |header| {
        if (header.name.len == 0 or header.name[0] == ':') continue;
        if (std.mem.eql(u8, header.name, "host")) continue;
        if (std.mem.eql(u8, header.name, "expect")) continue;
        if (std.mem.eql(u8, header.name, "cookie")) continue;
        if (for_connect and std.mem.eql(u8, header.name, "sec-websocket-key")) continue;
        if (proxy_headers.isStripped(header.name)) continue;

        // The site's own line replaces the client's rather than joining it.
        if (extra.owns(header.name)) continue;

        try out.print("{s}: {s}\r\n", .{ header.name, header.value });
    }

    var cookie_open = false;
    for (headers) |header| {
        if (!std.mem.eql(u8, header.name, "cookie")) continue;

        try out.writeAll(if (cookie_open) "; " else "Cookie: ");
        try out.writeAll(header.value);
        cookie_open = true;
    }
    if (cookie_open) try out.writeAll("\r\n");
}

fn hasName(headers: []const Http2.Header, name: []const u8) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name)) return true;
    }

    return false;
}

/// Encode an upstream h1 response head as an h2 header block: names
/// lowercase, hop-by-hop dropped, via appended, content-length re-emitted
/// from zixer's own framing when known.
pub fn encodeResponseBlock(block_buf: []u8, response: *const http1_head.ResponseHead, content_length: ?u64, extra: cfg_headers.Block) ![]const u8 {
    var encoder = Http2.HpackEncoder.init(block_buf);

    var status_text: [8]u8 = undefined;
    try encoder.writeHeader(":status", std.fmt.bufPrint(&status_text, "{d}", .{response.status}) catch unreachable);

    for (response.headerSlice()) |header| {
        if (proxy_headers.isStripped(header.name)) continue;
        if (proxy_headers.namedInConnection(header.name, response.connection_value)) continue;
        if (extra.owns(header.name)) continue;

        try writeLowerHeader(&encoder, header.name, header.value);
    }

    try encoder.writeHeader("via", proxy_headers.VIA);
    if (content_length) |len| {
        var len_text: [24]u8 = undefined;
        try encoder.writeHeader("content-length", std.fmt.bufPrint(&len_text, "{d}", .{len}) catch unreachable);
    }

    try writeExtraHeaders(&encoder, extra);

    return encoder.encoded();
}

/// Encode the h2 answer to an extended CONNECT from the upstream's h1 101:
/// :status 200, end-to-end headers minus the Sec-WebSocket-Accept the h2
/// leg has no key for (rfc 8441 5).
pub fn encodeConnectResponseBlock(block_buf: []u8, response: *const http1_head.ResponseHead, extra: cfg_headers.Block) ![]const u8 {
    var encoder = Http2.HpackEncoder.init(block_buf);

    try encoder.writeHeader(":status", "200");
    for (response.headerSlice()) |header| {
        if (proxy_headers.isStripped(header.name)) continue;
        if (proxy_headers.namedInConnection(header.name, response.connection_value)) continue;
        if (std.ascii.eqlIgnoreCase(header.name, "sec-websocket-accept")) continue;
        if (extra.owns(header.name)) continue;

        try writeLowerHeader(&encoder, header.name, header.value);
    }
    try encoder.writeHeader("via", proxy_headers.VIA);

    try writeExtraHeaders(&encoder, extra);

    return encoder.encoded();
}

/// Encode a local edge answer: bodyless, optional rfc 9209 Proxy-Status.
pub fn encodeLocalBlock(block_buf: []u8, status: u16, proxy_error: ?[]const u8, extra: cfg_headers.Block) ![]const u8 {
    var encoder = Http2.HpackEncoder.init(block_buf);

    var status_text: [8]u8 = undefined;
    try encoder.writeHeader(":status", std.fmt.bufPrint(&status_text, "{d}", .{status}) catch unreachable);

    if (proxy_error) |token| {
        var value_buf: [96]u8 = undefined;
        const value = std.fmt.bufPrint(&value_buf, "zixer; error=\"{s}\"", .{token}) catch return error.ZixerBufferFull;
        try encoder.writeHeader("proxy-status", value);
    }

    try writeExtraHeaders(&encoder, extra);

    return encoder.encoded();
}

/// Encode the head for a resolved static file, mirroring the h1 static
/// plane: content type from the identity name, Vary always, the
/// content-encoding of a negotiated sibling.
pub fn encodeStaticBlock(block_buf: []u8, content_type: []const u8, size: u64, content_encoding: ?[]const u8, extra: cfg_headers.Block) ![]const u8 {
    var encoder = Http2.HpackEncoder.init(block_buf);

    try encoder.writeHeader(":status", "200");
    if (!extra.owns("content-type")) try encoder.writeHeader("content-type", content_type);

    var len_text: [24]u8 = undefined;
    try encoder.writeHeader("content-length", std.fmt.bufPrint(&len_text, "{d}", .{size}) catch unreachable);
    if (content_encoding) |token| {
        if (!extra.owns("content-encoding")) try encoder.writeHeader("content-encoding", token);
    }

    if (!extra.owns("vary")) try encoder.writeHeader("vary", "Accept-Encoding");

    try writeExtraHeaders(&encoder, extra);

    return encoder.encoded();
}

/// Encode h1 chunked trailers as the h2 trailing header block.
pub fn encodeTrailerBlock(block_buf: []u8, trailers: []const http1_head.Header) ![]const u8 {
    var encoder = Http2.HpackEncoder.init(block_buf);

    for (trailers) |trailer| {
        if (proxy_headers.isStripped(trailer.name)) continue;

        try writeLowerHeader(&encoder, trailer.name, trailer.value);
    }

    return encoder.encoded();
}

/// Encode the site's [response_headers] into this block, one field each with
/// its tokens filled in.
///
/// Note:
/// - h2 carries every field on its own, so the compiled block's h1 byte view
///   is unusable here and the per-line view is walked instead.
///
/// Param:
/// encoder - *Http2.HpackEncoder (the block in progress)
/// extra - cfg_headers.Block (the site's table, empty when it configured none)
///
/// Return:
/// - void
fn writeExtraHeaders(encoder: *Http2.HpackEncoder, extra: cfg_headers.Block) !void {
    if (extra.isEmpty()) return;

    var value_buf: [cfg_headers.MAX_VALUE_BYTES]u8 = undefined;
    for (extra.lines()) |line| {
        try writeLowerHeader(encoder, line.name, try line.renderValue(&value_buf, extra.values));
    }
}

/// h2 field names travel lowercase (rfc 9113 8.2). Names past the bound
/// drop rather than truncate.
fn writeLowerHeader(encoder: *Http2.HpackEncoder, name: []const u8, value: []const u8) !void {
    if (name.len > NAME_LOWER_MAX) return;

    var lower_buf: [NAME_LOWER_MAX]u8 = undefined;
    for (name, 0..) |char, index| lower_buf[index] = std.ascii.toLower(char);

    try encoder.writeHeader(lower_buf[0..name.len], value);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

fn makeHeader(name: []const u8, value: []const u8) Http2.Header {
    return .{ .name = name, .value = value };
}

fn decodeBlock(block: []const u8, out: []Http2.Header, scratch: []u8) !usize {
    var decoder = Http2.HpackDecoder.init();

    return decoder.decode(block, out, scratch);
}

fn findValue(headers: []const Http2.Header, count: usize, name: []const u8) ?[]const u8 {
    for (headers[0..count]) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.value;
    }

    return null;
}

test "zix zixer: http2 translate, plain get assembles from pseudo headers" {
    const list = [_]Http2.Header{
        makeHeader(":method", "GET"),
        makeHeader(":scheme", "https"),
        makeHeader(":path", "/api/items?page=2"),
        makeHeader(":authority", "app.example"),
        makeHeader("accept", "*/*"),
    };

    const request = try assemble(&list, true);
    try testing.expectEqualStrings("GET", request.method);
    try testing.expectEqualStrings("/api/items?page=2", request.target);
    try testing.expectEqualStrings("app.example", request.authority);
    try testing.expect(!request.has_body);
    try testing.expect(!request.is_connect);
    try testing.expect(!request.is_head);
    try testing.expectEqual(@as(?u64, null), request.content_length);
}

test "zix zixer: http2 translate, host header stands in for a missing authority" {
    const list = [_]Http2.Header{
        makeHeader(":method", "GET"),
        makeHeader(":scheme", "http"),
        makeHeader(":path", "/"),
        makeHeader("host", "fallback.example"),
    };

    const request = try assemble(&list, true);
    try testing.expectEqualStrings("fallback.example", request.authority);
}

test "zix zixer: http2 translate, body flags follow end stream and content length" {
    const posted = [_]Http2.Header{
        makeHeader(":method", "POST"),
        makeHeader(":scheme", "http"),
        makeHeader(":path", "/submit"),
        makeHeader(":authority", "app.example"),
        makeHeader("content-length", "12"),
    };

    const with_body = try assemble(&posted, false);
    try testing.expect(with_body.has_body);
    try testing.expectEqual(@as(?u64, 12), with_body.content_length);

    // A promised body on a closed stream is malformed.
    try testing.expectError(error.ZixerMalformed, assemble(&posted, true));

    const head_request = [_]Http2.Header{
        makeHeader(":method", "HEAD"),
        makeHeader(":scheme", "http"),
        makeHeader(":path", "/"),
        makeHeader(":authority", "app.example"),
    };
    try testing.expect((try assemble(&head_request, true)).is_head);
}

test "zix zixer: http2 translate, rfc 9113 malformed shapes are refused" {
    const no_path = [_]Http2.Header{ makeHeader(":method", "GET"), makeHeader(":scheme", "http"), makeHeader(":authority", "a") };
    try testing.expectError(error.ZixerMalformed, assemble(&no_path, true));

    const no_scheme = [_]Http2.Header{ makeHeader(":method", "GET"), makeHeader(":path", "/"), makeHeader(":authority", "a") };
    try testing.expectError(error.ZixerMalformed, assemble(&no_scheme, true));

    const no_authority = [_]Http2.Header{ makeHeader(":method", "GET"), makeHeader(":scheme", "http"), makeHeader(":path", "/") };
    try testing.expectError(error.ZixerMalformed, assemble(&no_authority, true));

    const connection_header = [_]Http2.Header{
        makeHeader(":method", "GET"),           makeHeader(":scheme", "http"), makeHeader(":path", "/"), makeHeader(":authority", "a"),
        makeHeader("connection", "keep-alive"),
    };
    try testing.expectError(error.ZixerMalformed, assemble(&connection_header, true));

    const te_gzip = [_]Http2.Header{
        makeHeader(":method", "GET"), makeHeader(":scheme", "http"), makeHeader(":path", "/"), makeHeader(":authority", "a"),
        makeHeader("te", "gzip"),
    };
    try testing.expectError(error.ZixerMalformed, assemble(&te_gzip, true));

    const uppercase_name = [_]Http2.Header{
        makeHeader(":method", "GET"), makeHeader(":scheme", "http"), makeHeader(":path", "/"), makeHeader(":authority", "a"),
        makeHeader("X-Custom", "1"),
    };
    try testing.expectError(error.ZixerMalformed, assemble(&uppercase_name, true));

    const pseudo_after_regular = [_]Http2.Header{
        makeHeader(":method", "GET"),  makeHeader(":scheme", "http"), makeHeader("accept", "*/*"), makeHeader(":path", "/"),
        makeHeader(":authority", "a"),
    };
    try testing.expectError(error.ZixerMalformed, assemble(&pseudo_after_regular, true));

    const duplicate_method = [_]Http2.Header{
        makeHeader(":method", "GET"),  makeHeader(":method", "POST"), makeHeader(":scheme", "http"), makeHeader(":path", "/"),
        makeHeader(":authority", "a"),
    };
    try testing.expectError(error.ZixerMalformed, assemble(&duplicate_method, true));

    const protocol_on_get = [_]Http2.Header{
        makeHeader(":method", "GET"),         makeHeader(":scheme", "http"), makeHeader(":path", "/"), makeHeader(":authority", "a"),
        makeHeader(":protocol", "websocket"),
    };
    try testing.expectError(error.ZixerMalformed, assemble(&protocol_on_get, true));

    const conflicting_lengths = [_]Http2.Header{
        makeHeader(":method", "POST"),     makeHeader(":scheme", "http"),     makeHeader(":path", "/"), makeHeader(":authority", "a"),
        makeHeader("content-length", "4"), makeHeader("content-length", "9"),
    };
    try testing.expectError(error.ZixerMalformed, assemble(&conflicting_lengths, false));
}

test "zix zixer: http2 translate, extended connect takes websocket only" {
    const websocket = [_]Http2.Header{
        makeHeader(":method", "CONNECT"),
        makeHeader(":protocol", "websocket"),
        makeHeader(":scheme", "https"),
        makeHeader(":path", "/chat"),
        makeHeader(":authority", "app.example"),
        makeHeader("sec-websocket-version", "13"),
    };

    const request = try assemble(&websocket, false);
    try testing.expect(request.is_connect);
    try testing.expectEqualStrings("/chat", request.target);

    const plain_connect = [_]Http2.Header{ makeHeader(":method", "CONNECT"), makeHeader(":authority", "app.example:443") };
    try testing.expectError(error.ZixerUnsupportedConnect, assemble(&plain_connect, false));

    const other_protocol = [_]Http2.Header{
        makeHeader(":method", "CONNECT"), makeHeader(":protocol", "webtransport"), makeHeader(":scheme", "https"),
        makeHeader(":path", "/wt"),       makeHeader(":authority", "app.example"),
    };
    try testing.expectError(error.ZixerUnsupportedConnect, assemble(&other_protocol, false));

    const missing_path = [_]Http2.Header{
        makeHeader(":method", "CONNECT"),        makeHeader(":protocol", "websocket"), makeHeader(":scheme", "https"),
        makeHeader(":authority", "app.example"),
    };
    try testing.expectError(error.ZixerMalformed, assemble(&missing_path, false));
}

test "zix zixer: http2 translate, upstream head carries host via forwarded and framing" {
    const list = [_]Http2.Header{
        makeHeader(":method", "POST"),
        makeHeader(":scheme", "http"),
        makeHeader(":path", "/api"),
        makeHeader(":authority", "app.example"),
        makeHeader("accept", "*/*"),
        makeHeader("cookie", "a=1"),
        makeHeader("cookie", "b=2"),
        makeHeader("te", "trailers"),
        makeHeader("expect", "100-continue"),
        makeHeader("content-length", "4"),
    };
    const request = try assemble(&list, false);

    var build_buf: [http1_head.MAX_HEAD_BYTES + 512]u8 = undefined;
    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 7 }, .port = 55000 } };
    const head = try buildUpstreamHead(&build_buf, &request, &list, addr, .HTTP, .{});

    try testing.expect(std.mem.startsWith(u8, head, "POST /api HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, head, "Host: app.example\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "accept: */*\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Cookie: a=1; b=2\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Via: 1.1 zixer\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Forwarded: for=\"192.0.2.7:55000\";proto=http;host=\"app.example\"\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Content-Length: 4\r\n") != null);

    try testing.expect(std.mem.indexOf(u8, head, ":method") == null);
    try testing.expect(std.mem.indexOf(u8, head, "te:") == null);
    try testing.expect(std.mem.indexOf(u8, head, "expect") == null);
    try testing.expect(std.mem.indexOf(u8, head, "cookie:") == null);
    try testing.expect(std.mem.endsWith(u8, head, "\r\n\r\n"));
}

test "zix zixer: http2 translate, bodied request without length re-frames chunked" {
    const list = [_]Http2.Header{
        makeHeader(":method", "POST"),
        makeHeader(":scheme", "http"),
        makeHeader(":path", "/stream"),
        makeHeader(":authority", "app.example"),
    };
    const request = try assemble(&list, false);

    var build_buf: [1024]u8 = undefined;
    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 4000 } };
    const head = try buildUpstreamHead(&build_buf, &request, &list, addr, .HTTP, .{});

    try testing.expect(std.mem.indexOf(u8, head, "Transfer-Encoding: chunked\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Content-Length") == null);
}

test "zix zixer: http2 translate, connect head bridges to an h1 upgrade" {
    const list = [_]Http2.Header{
        makeHeader(":method", "CONNECT"),
        makeHeader(":protocol", "websocket"),
        makeHeader(":scheme", "https"),
        makeHeader(":path", "/chat"),
        makeHeader(":authority", "app.example"),
        makeHeader("sec-websocket-version", "13"),
        makeHeader("sec-websocket-protocol", "chat.v2"),
        makeHeader("sec-websocket-key", "client-key-must-drop"),
    };
    const request = try assemble(&list, false);

    var build_buf: [2048]u8 = undefined;
    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 4200 } };
    const head = try buildConnectHead(&build_buf, &request, &list, addr, "zixer-generated-key==", .HTTP, .{});

    try testing.expect(std.mem.startsWith(u8, head, "GET /chat HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, head, "Host: app.example\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Sec-WebSocket-Key: zixer-generated-key==\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "client-key-must-drop") == null);
    try testing.expect(std.mem.indexOf(u8, head, "sec-websocket-version: 13\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "sec-websocket-protocol: chat.v2\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Connection: Upgrade\r\nUpgrade: websocket\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Via: 1.1 zixer\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, head, "\r\n\r\n"));
}

test "zix zixer: http2 translate, connect head adds a missing version" {
    const list = [_]Http2.Header{
        makeHeader(":method", "CONNECT"),
        makeHeader(":protocol", "websocket"),
        makeHeader(":scheme", "https"),
        makeHeader(":path", "/chat"),
        makeHeader(":authority", "app.example"),
    };
    const request = try assemble(&list, false);

    var build_buf: [1024]u8 = undefined;
    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 4200 } };
    const head = try buildConnectHead(&build_buf, &request, &list, addr, "key==", .HTTP, .{});

    try testing.expect(std.mem.indexOf(u8, head, "Sec-WebSocket-Version: 13\r\n") != null);
}

test "zix zixer: http2 translate, response block lowercases and strips hop by hop" {
    const response = try http1_head.parseResponse(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: keep-alive, X-Hop\r\nX-Hop: secret\r\nKeep-Alive: timeout=5\r\nX-Custom: yes\r\nContent-Length: 4\r\n\r\n",
        "GET",
    );

    var block_buf: [1024]u8 = undefined;
    const block = try encodeResponseBlock(&block_buf, &response, 4, .{});

    var decoded: [32]Http2.Header = undefined;
    var scratch: [2048]u8 = undefined;
    const count = try decodeBlock(block, &decoded, &scratch);

    try testing.expectEqualStrings(":status", decoded[0].name);
    try testing.expectEqualStrings("200", decoded[0].value);
    try testing.expectEqualStrings("text/plain", findValue(&decoded, count, "content-type").?);
    try testing.expectEqualStrings("yes", findValue(&decoded, count, "x-custom").?);
    try testing.expectEqualStrings("1.1 zixer", findValue(&decoded, count, "via").?);
    try testing.expectEqualStrings("4", findValue(&decoded, count, "content-length").?);

    try testing.expectEqual(@as(?[]const u8, null), findValue(&decoded, count, "connection"));
    try testing.expectEqual(@as(?[]const u8, null), findValue(&decoded, count, "keep-alive"));
    try testing.expectEqual(@as(?[]const u8, null), findValue(&decoded, count, "x-hop"));
}

test "zix zixer: http2 translate, connect response drops the accept answer" {
    const response = try http1_head.parseResponse(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: chat.v2\r\n\r\n",
        "GET",
    );

    var block_buf: [1024]u8 = undefined;
    const block = try encodeConnectResponseBlock(&block_buf, &response, .{});

    var decoded: [32]Http2.Header = undefined;
    var scratch: [2048]u8 = undefined;
    const count = try decodeBlock(block, &decoded, &scratch);

    try testing.expectEqualStrings(":status", decoded[0].name);
    try testing.expectEqualStrings("200", decoded[0].value);
    try testing.expectEqualStrings("chat.v2", findValue(&decoded, count, "sec-websocket-protocol").?);
    try testing.expectEqualStrings("1.1 zixer", findValue(&decoded, count, "via").?);

    try testing.expectEqual(@as(?[]const u8, null), findValue(&decoded, count, "sec-websocket-accept"));
    try testing.expectEqual(@as(?[]const u8, null), findValue(&decoded, count, "upgrade"));
    try testing.expectEqual(@as(?[]const u8, null), findValue(&decoded, count, "connection"));
}

test "zix zixer: http2 translate, local block carries proxy status" {
    var block_buf: [256]u8 = undefined;
    const block = try encodeLocalBlock(&block_buf, 502, "connection_refused", .{});

    var decoded: [8]Http2.Header = undefined;
    var scratch: [512]u8 = undefined;
    const count = try decodeBlock(block, &decoded, &scratch);

    try testing.expectEqualStrings(":status", decoded[0].name);
    try testing.expectEqualStrings("502", decoded[0].value);
    try testing.expectEqualStrings("zixer; error=\"connection_refused\"", findValue(&decoded, count, "proxy-status").?);

    const plain = try encodeLocalBlock(&block_buf, 404, null, .{});
    const plain_count = try decodeBlock(plain, &decoded, &scratch);
    try testing.expectEqual(@as(usize, 1), plain_count);
    try testing.expectEqualStrings("404", decoded[0].value);
}

test "zix zixer: http2 translate, static block mirrors the h1 static head" {
    var block_buf: [512]u8 = undefined;
    const block = try encodeStaticBlock(&block_buf, "text/html", 120, "br", .{});

    var decoded: [8]Http2.Header = undefined;
    var scratch: [1024]u8 = undefined;
    const count = try decodeBlock(block, &decoded, &scratch);

    try testing.expectEqualStrings("200", decoded[0].value);
    try testing.expectEqualStrings("text/html", findValue(&decoded, count, "content-type").?);
    try testing.expectEqualStrings("120", findValue(&decoded, count, "content-length").?);
    try testing.expectEqualStrings("br", findValue(&decoded, count, "content-encoding").?);
    try testing.expectEqualStrings("Accept-Encoding", findValue(&decoded, count, "vary").?);

    const identity = try encodeStaticBlock(&block_buf, "text/plain", 5, null, .{});
    const identity_count = try decodeBlock(identity, &decoded, &scratch);
    try testing.expectEqual(@as(?[]const u8, null), findValue(&decoded, identity_count, "content-encoding"));
}

test "zix zixer: http2 translate, trailer block keeps end to end fields only" {
    const trailers = [_]http1_head.Header{
        .{ .name = "X-Sum", .value = "ok" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
    };

    var block_buf: [256]u8 = undefined;
    const block = try encodeTrailerBlock(&block_buf, &trailers);

    var decoded: [8]Http2.Header = undefined;
    var scratch: [512]u8 = undefined;
    const count = try decodeBlock(block, &decoded, &scratch);

    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("x-sum", decoded[0].name);
    try testing.expectEqualStrings("ok", decoded[0].value);
}

/// Compile one header section the way a site cfg would, for the translate
/// tests.
fn testTable(arena: std.mem.Allocator, direction: cfg_headers.Direction, lines: []const cfg_scanner.Entry) !cfg_headers.Table {
    var faults = fault.FaultList.init(arena);
    const table = try cfg_headers.compile(arena, lines, direction, true, &faults);

    try testing.expectEqual(@as(usize, 0), faults.slice().len);

    return table;
}

test "zix zixer: http2 translate, the response block carries the site's headers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const table = try testTable(arena.allocator(), .RESPONSE, &.{
        .{ .key = "strict-transport-security", .value = "max-age=31536000", .line_no = 2 },
        .{ .key = "X-Origin", .value = "$scheme://$host", .line_no = 3 },
        .{ .key = "x-custom", .value = "site-wins", .line_no = 4 },
    });
    const extra = cfg_headers.Block{
        .table = table,
        .values = .{ .client_ip = "192.0.2.7", .scheme = "https", .host = "app.example" },
    };

    const response = try http1_head.parseResponse(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Custom: origin-value\r\nContent-Length: 4\r\n\r\n",
        "GET",
    );

    var block_buf: [1024]u8 = undefined;
    const block = try encodeResponseBlock(&block_buf, &response, 4, extra);

    var decoded: [32]Http2.Header = undefined;
    var scratch: [2048]u8 = undefined;
    const count = try decodeBlock(block, &decoded, &scratch);

    // Each field is encoded on its own here, and the name travels lowercase
    // whatever the operator typed (rfc 9113 8.2).
    try testing.expectEqualStrings("max-age=31536000", findValue(&decoded, count, "strict-transport-security").?);
    try testing.expectEqualStrings("https://app.example", findValue(&decoded, count, "x-origin").?);
    try testing.expectEqual(@as(?[]const u8, null), findValue(&decoded, count, "X-Origin"));

    // One x-custom, and it is the site's.
    try testing.expectEqualStrings("site-wins", findValue(&decoded, count, "x-custom").?);
    var customs: usize = 0;
    for (decoded[0..count]) |header| {
        if (std.mem.eql(u8, header.name, "x-custom")) customs += 1;
    }
    try testing.expectEqual(@as(usize, 1), customs);
}

test "zix zixer: http2 translate, a local block and a static block carry them too" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const table = try testTable(arena.allocator(), .RESPONSE, &.{
        .{ .key = "x-frame-options", .value = "DENY", .line_no = 2 },
    });
    const extra = cfg_headers.Block{ .table = table };

    var block_buf: [512]u8 = undefined;
    var decoded: [16]Http2.Header = undefined;
    var scratch: [1024]u8 = undefined;

    const local = try encodeLocalBlock(&block_buf, 504, "http_response_timeout", extra);
    const local_count = try decodeBlock(local, &decoded, &scratch);
    try testing.expectEqualStrings("DENY", findValue(&decoded, local_count, "x-frame-options").?);

    const static = try encodeStaticBlock(&block_buf, "text/html", 12, null, extra);
    const static_count = try decodeBlock(static, &decoded, &scratch);
    try testing.expectEqualStrings("DENY", findValue(&decoded, static_count, "x-frame-options").?);
    try testing.expectEqualStrings("text/html", findValue(&decoded, static_count, "content-type").?);
}

test "zix zixer: http2 translate, the upstream head carries the site's request headers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const table = try testTable(arena.allocator(), .REQUEST, &.{
        .{ .key = "x-real-ip", .value = "$client_ip", .line_no = 2 },
        .{ .key = "x-tenant", .value = "acme", .line_no = 3 },
    });
    const extra = cfg_headers.Block{
        .table = table,
        .values = .{ .client_ip = "192.0.2.7", .scheme = "https", .host = "app.example" },
    };

    const headers = [_]Http2.Header{
        makeHeader(":method", "GET"),
        makeHeader(":scheme", "https"),
        makeHeader(":authority", "app.example"),
        makeHeader(":path", "/api"),
        makeHeader("x-tenant", "spoofed"),
    };
    const request = try assemble(&headers, true);

    var head_buf: [http1_head.MAX_HEAD_BYTES + 512 + cfg_headers.MAX_BLOCK_BYTES]u8 = undefined;
    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 7 }, .port = 55000 } };
    const head = try buildUpstreamHead(&head_buf, &request, &headers, addr, .HTTPS, extra);

    try testing.expect(std.mem.indexOf(u8, head, "x-real-ip: 192.0.2.7\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "x-tenant: acme\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "spoofed") == null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, head, "\r\n\r\n"));
}
