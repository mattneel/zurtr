//! zixer h3 translate: h3 field sections to h1 messages and back (rfc 9114 4)

const std = @import("std");

const cfg_headers = @import("cfg_headers.zig");
const cfg_scanner = @import("cfg_scanner.zig");
const fault = @import("fault.zig");
const h3_qpack = @import("h3_qpack.zig");
const http1_head = @import("http1_head.zig");
const proxy_headers = @import("proxy_headers.zig");
const request_scheme = @import("request_scheme.zig");

/// The via element an h3 hop adds (rfc 9110 7.6.3): protocol version then the
/// pseudonym, matching the h1 "1.1 zixer" and grpc "2 zixer" forms.
pub const VIA_H3: []const u8 = "3 zixer";

/// Longest response header name the encoder lowercases. Longer names drop.
const NAME_LOWER_MAX: usize = 128;

pub const Error = error{
    /// The request breaks an rfc 9114 4.1.2 or 4.2 rule: the stream answers a
    /// message error, never the pool.
    ZixerMalformed,
    /// CONNECT over h3. The edge tunnels nothing on h3 yet.
    ZixerUnsupportedConnect,
    /// The head or block buffer ran out.
    ZixerBufferFull,
    WriteFailed,
};

/// One h3 request after pseudo-header validation. Slices borrow the decoded
/// field section, so they live as long as its block and scratch.
pub const Request = struct {
    method: []const u8,
    target: []const u8,
    authority: []const u8,
    is_head: bool,
    /// True when DATA frames follow (the HEADERS frame did not end the stream).
    has_body: bool,
    content_length: ?u64,
    expects_continue: bool,
};

/// Validate a decoded request field section and assemble the request view
/// (rfc 9114 4.1.2 pseudo-header rules, 4.2 field rules).
pub fn assemble(fields: []const h3_qpack.Field, end_stream: bool) Error!Request {
    var method: ?[]const u8 = null;
    var target: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var authority: ?[]const u8 = null;
    var protocol: ?[]const u8 = null;
    var host_value: []const u8 = "";
    var content_length: ?u64 = null;
    var expects_continue = false;
    var seen_regular = false;

    for (fields) |field| {
        if (field.name.len == 0) return error.ZixerMalformed;

        if (field.name[0] == ':') {
            if (seen_regular) return error.ZixerMalformed;

            if (std.mem.eql(u8, field.name, ":method")) {
                if (method != null) return error.ZixerMalformed;
                method = field.value;
            } else if (std.mem.eql(u8, field.name, ":path")) {
                if (target != null) return error.ZixerMalformed;
                target = field.value;
            } else if (std.mem.eql(u8, field.name, ":scheme")) {
                if (scheme != null) return error.ZixerMalformed;
                scheme = field.value;
            } else if (std.mem.eql(u8, field.name, ":authority")) {
                if (authority != null) return error.ZixerMalformed;
                authority = field.value;
            } else if (std.mem.eql(u8, field.name, ":protocol")) {
                if (protocol != null) return error.ZixerMalformed;
                protocol = field.value;
            } else {
                return error.ZixerMalformed;
            }
            continue;
        }

        seen_regular = true;
        try validateRegularName(field.name);

        if (std.mem.eql(u8, field.name, "te")) {
            if (!std.ascii.eqlIgnoreCase(field.value, "trailers")) return error.ZixerMalformed;
        } else if (std.mem.eql(u8, field.name, "content-length")) {
            const parsed = std.fmt.parseInt(u64, field.value, 10) catch return error.ZixerMalformed;
            if (content_length) |seen| {
                if (seen != parsed) return error.ZixerMalformed;
            }
            content_length = parsed;
        } else if (std.mem.eql(u8, field.name, "host")) {
            host_value = field.value;
        } else if (std.mem.eql(u8, field.name, "expect")) {
            if (std.ascii.eqlIgnoreCase(field.value, "100-continue")) expects_continue = true;
        }
    }

    const method_value = method orelse return error.ZixerMalformed;
    if (method_value.len == 0) return error.ZixerMalformed;

    // The edge terminates h3 and re-originates h1, and an h1 hop cannot carry
    // a tunnel opened over h3 (rfc 9114 4.4, rfc 9220 for extended CONNECT).
    if (std.mem.eql(u8, method_value, "CONNECT")) return error.ZixerUnsupportedConnect;
    if (protocol != null) return error.ZixerUnsupportedConnect;

    if (scheme == null) return error.ZixerMalformed;
    const target_value = target orelse return error.ZixerMalformed;
    if (target_value.len == 0) return error.ZixerMalformed;

    const final_authority = authority orelse host_value;
    if (final_authority.len == 0) return error.ZixerMalformed;

    // A body promised by content-length cannot ride a stream that already ended.
    if (end_stream and (content_length orelse 0) != 0) return error.ZixerMalformed;

    return .{
        .method = method_value,
        .target = target_value,
        .authority = final_authority,
        .is_head = std.mem.eql(u8, method_value, "HEAD"),
        .has_body = !end_stream,
        .content_length = content_length,
        .expects_continue = expects_continue,
    };
}

/// rfc 9114 4.2: field names travel lowercase, and a connection-specific
/// header makes the whole message malformed.
fn validateRegularName(name: []const u8) Error!void {
    for (name) |char| {
        if (char >= 'A' and char <= 'Z') return error.ZixerMalformed;
    }

    const forbidden = [_][]const u8{ "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade" };
    for (forbidden) |bad| {
        if (std.mem.eql(u8, name, bad)) return error.ZixerMalformed;
    }
}

/// Build the h1 upstream head for one h3 request: filtered fields plus Host,
/// Via, Forwarded, and zixer's own framing.
pub fn buildUpstreamHead(buf: []u8, request: *const Request, fields: []const h3_qpack.Field, client_addr: std.Io.net.IpAddress, scheme: request_scheme.Scheme, extra: cfg_headers.Block) Error![]const u8 {
    var fixed = std.Io.Writer.fixed(buf);

    fixed.print("{s} {s} HTTP/1.1\r\n", .{ request.method, request.target }) catch return error.ZixerBufferFull;
    fixed.print("Host: {s}\r\n", .{request.authority}) catch return error.ZixerBufferFull;
    writeFilteredFields(&fixed, fields, extra) catch return error.ZixerBufferFull;
    fixed.print("Via: {s}\r\n", .{VIA_H3}) catch return error.ZixerBufferFull;
    proxy_headers.writeForwarded(&fixed, client_addr, request.authority, scheme) catch return error.ZixerBufferFull;

    if (request.has_body) {
        if (request.content_length) |len| {
            fixed.print("Content-Length: {d}\r\n", .{len}) catch return error.ZixerBufferFull;
        } else {
            fixed.writeAll("Transfer-Encoding: chunked\r\n") catch return error.ZixerBufferFull;
        }
    }

    extra.write(&fixed) catch return error.ZixerBufferFull;
    fixed.writeAll("\r\n") catch return error.ZixerBufferFull;

    return fixed.buffered();
}

/// Write the end-to-end request headers: pseudo, host, and expect are zixer's
/// own, the hop-by-hop set drops, and cookie fields coalesce into one h1 line
/// (rfc 9114 4.2.1).
fn writeFilteredFields(out: *std.Io.Writer, fields: []const h3_qpack.Field, extra: cfg_headers.Block) !void {
    for (fields) |field| {
        if (field.name.len == 0 or field.name[0] == ':') continue;
        if (std.mem.eql(u8, field.name, "host")) continue;
        if (std.mem.eql(u8, field.name, "expect")) continue;
        if (std.mem.eql(u8, field.name, "cookie")) continue;
        if (proxy_headers.isStripped(field.name)) continue;

        // The site's own line replaces the client's rather than joining it.
        if (extra.owns(field.name)) continue;

        try out.print("{s}: {s}\r\n", .{ field.name, field.value });
    }

    var cookie_open = false;
    for (fields) |field| {
        if (!std.mem.eql(u8, field.name, "cookie")) continue;

        try out.writeAll(if (cookie_open) "; " else "Cookie: ");
        try out.writeAll(field.value);
        cookie_open = true;
    }
    if (cookie_open) try out.writeAll("\r\n");
}

/// Encode an upstream h1 response head as an h3 field section: names
/// lowercase, hop-by-hop dropped, via appended, content-length re-emitted from
/// zixer's own framing when it knows the length.
pub fn encodeResponseBlock(block_buf: []u8, response: *const http1_head.ResponseHead, content_length: ?u64, extra: cfg_headers.Block) Error![]const u8 {
    var encoder = h3_qpack.Encoder.init(block_buf);

    var status_text: [8]u8 = undefined;
    try encoder.field(":status", std.fmt.bufPrint(&status_text, "{d}", .{response.status}) catch unreachable);

    for (response.headerSlice()) |header| {
        if (proxy_headers.isStripped(header.name)) continue;
        if (proxy_headers.namedInConnection(header.name, response.connection_value)) continue;
        if (content_length != null and std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
        if (extra.owns(header.name)) continue;

        try writeLowerField(&encoder, header.name, header.value);
    }

    try encoder.field("via", VIA_H3);
    if (content_length) |len| {
        var len_text: [24]u8 = undefined;
        try encoder.field("content-length", std.fmt.bufPrint(&len_text, "{d}", .{len}) catch unreachable);
    }

    try writeExtraFields(&encoder, extra);

    return encoder.encoded();
}

/// Encode a local edge answer: bodyless, optional rfc 9209 Proxy-Status.
pub fn encodeLocalBlock(block_buf: []u8, status: u16, proxy_error: ?[]const u8, extra: cfg_headers.Block) Error![]const u8 {
    var encoder = h3_qpack.Encoder.init(block_buf);

    var status_text: [8]u8 = undefined;
    try encoder.field(":status", std.fmt.bufPrint(&status_text, "{d}", .{status}) catch unreachable);
    try encoder.field("content-length", "0");

    if (proxy_error) |token| {
        var value_buf: [96]u8 = undefined;
        const value = std.fmt.bufPrint(&value_buf, "zixer; error=\"{s}\"", .{token}) catch return error.ZixerBufferFull;
        try encoder.field("proxy-status", value);
    }

    try encoder.field("via", VIA_H3);

    try writeExtraFields(&encoder, extra);

    return encoder.encoded();
}

/// Encode the head for a resolved static file, mirroring the h1 static plane:
/// content type from the identity name, Vary always, the content-encoding of a
/// negotiated sibling.
pub fn encodeStaticBlock(block_buf: []u8, content_type: []const u8, size: u64, content_encoding: ?[]const u8, extra: cfg_headers.Block) Error![]const u8 {
    var encoder = h3_qpack.Encoder.init(block_buf);

    try encoder.field(":status", "200");
    if (!extra.owns("content-type")) try encoder.field("content-type", content_type);

    var len_text: [24]u8 = undefined;
    try encoder.field("content-length", std.fmt.bufPrint(&len_text, "{d}", .{size}) catch unreachable);
    if (content_encoding) |token| {
        if (!extra.owns("content-encoding")) try encoder.field("content-encoding", token);
    }

    if (!extra.owns("vary")) try encoder.field("vary", "Accept-Encoding");
    try encoder.field("via", VIA_H3);

    try writeExtraFields(&encoder, extra);

    return encoder.encoded();
}

/// Encode h1 chunked trailers as the h3 trailing field section.
pub fn encodeTrailerBlock(block_buf: []u8, trailers: []const http1_head.Header) Error![]const u8 {
    var encoder = h3_qpack.Encoder.init(block_buf);

    for (trailers) |trailer| {
        if (proxy_headers.isStripped(trailer.name)) continue;

        try writeLowerField(&encoder, trailer.name, trailer.value);
    }

    return encoder.encoded();
}

/// Encode the site's [response_headers] into this section, one field each with
/// its tokens filled in.
///
/// Note:
/// - h3 carries every field on its own, so the compiled block's h1 byte view
///   is unusable here and the per-line view is walked instead.
fn writeExtraFields(encoder: *h3_qpack.Encoder, extra: cfg_headers.Block) Error!void {
    if (extra.isEmpty()) return;

    var value_buf: [cfg_headers.MAX_VALUE_BYTES]u8 = undefined;
    for (extra.lines()) |line| {
        const value = line.renderValue(&value_buf, extra.values) catch return error.ZixerBufferFull;

        try writeLowerField(encoder, line.name, value);
    }
}

/// h3 field names travel lowercase (rfc 9114 4.2). Names past the bound drop
/// rather than truncate.
fn writeLowerField(encoder: *h3_qpack.Encoder, name: []const u8, value: []const u8) Error!void {
    if (name.len > NAME_LOWER_MAX) return;

    var lower_buf: [NAME_LOWER_MAX]u8 = undefined;
    const lower = std.ascii.lowerString(lower_buf[0..name.len], name);

    try encoder.field(lower, value);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

fn testAddress() std.Io.net.IpAddress {
    return std.Io.net.IpAddress.parse("203.0.113.9", 51234) catch unreachable;
}

test "zix zixer: h3 translate, a plain request assembles from its pseudo headers" {
    const fields = [_]h3_qpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "pages.test" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = "user-agent", .value = "probe/1" },
    };

    const request = try assemble(&fields, true);
    try testing.expectEqualStrings("GET", request.method);
    try testing.expectEqualStrings("/index.html", request.target);
    try testing.expectEqualStrings("pages.test", request.authority);
    try testing.expect(!request.has_body);
    try testing.expect(!request.is_head);
}

test "zix zixer: h3 translate, missing and duplicate pseudo headers are malformed" {
    const no_path = [_]h3_qpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "a.test" },
    };
    try testing.expectError(error.ZixerMalformed, assemble(&no_path, true));

    const twice = [_]h3_qpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "a.test" },
        .{ .name = ":path", .value = "/" },
    };
    try testing.expectError(error.ZixerMalformed, assemble(&twice, true));

    const after_regular = [_]h3_qpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":path", .value = "/" },
    };
    try testing.expectError(error.ZixerMalformed, assemble(&after_regular, true));

    const unknown_pseudo = [_]h3_qpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "a.test" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":made-up", .value = "x" },
    };
    try testing.expectError(error.ZixerMalformed, assemble(&unknown_pseudo, true));
}

test "zix zixer: h3 translate, connection specific fields are malformed" {
    const base = [_]h3_qpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "a.test" },
        .{ .name = ":path", .value = "/" },
    };

    inline for (.{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" }) |name| {
        const fields = base ++ [_]h3_qpack.Field{.{ .name = name, .value = "x" }};
        try testing.expectError(error.ZixerMalformed, assemble(&fields, true));
    }

    const upper = base ++ [_]h3_qpack.Field{.{ .name = "Accept", .value = "*/*" }};
    try testing.expectError(error.ZixerMalformed, assemble(&upper, true));

    const bad_te = base ++ [_]h3_qpack.Field{.{ .name = "te", .value = "gzip" }};
    try testing.expectError(error.ZixerMalformed, assemble(&bad_te, true));

    const good_te = base ++ [_]h3_qpack.Field{.{ .name = "te", .value = "trailers" }};
    _ = try assemble(&good_te, true);
}

test "zix zixer: h3 translate, connect is refused on the h3 edge" {
    const connect = [_]h3_qpack.Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "a.test" },
        .{ .name = ":path", .value = "/chat" },
        .{ .name = ":protocol", .value = "websocket" },
    };

    try testing.expectError(error.ZixerUnsupportedConnect, assemble(&connect, true));
}

test "zix zixer: h3 translate, a body without content length frames as chunked" {
    const fields = [_]h3_qpack.Field{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "a.test" },
        .{ .name = ":path", .value = "/submit" },
    };

    const request = try assemble(&fields, false);
    try testing.expect(request.has_body);
    try testing.expect(request.content_length == null);

    var buf: [512]u8 = undefined;
    const head = try buildUpstreamHead(&buf, &request, &fields, testAddress(), .HTTPS, .{});
    try testing.expect(std.mem.indexOf(u8, head, "Transfer-Encoding: chunked\r\n") != null);

    const sized = [_]h3_qpack.Field{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "a.test" },
        .{ .name = ":path", .value = "/submit" },
        .{ .name = "content-length", .value = "7" },
    };
    const sized_request = try assemble(&sized, false);
    const sized_head = try buildUpstreamHead(&buf, &sized_request, &sized, testAddress(), .HTTPS, .{});
    try testing.expect(std.mem.indexOf(u8, sized_head, "Content-Length: 7\r\n") != null);

    // A promised body on an already ended stream is malformed.
    try testing.expectError(error.ZixerMalformed, assemble(&sized, true));
}

test "zix zixer: h3 translate, the upstream head carries via, forwarded, and coalesced cookies" {
    const fields = [_]h3_qpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "shop.test" },
        .{ .name = ":path", .value = "/cart" },
        .{ .name = "cookie", .value = "a=1" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = "cookie", .value = "b=2" },
    };

    const request = try assemble(&fields, true);
    var buf: [512]u8 = undefined;
    const head = try buildUpstreamHead(&buf, &request, &fields, testAddress(), .HTTPS, .{});

    try testing.expect(std.mem.startsWith(u8, head, "GET /cart HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, head, "Host: shop.test\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Via: 3 zixer\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "for=\"203.0.113.9:51234\"") != null);
    try testing.expect(std.mem.indexOf(u8, head, "Cookie: a=1; b=2\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "accept: */*\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, head, "\r\n\r\n"));
}

test "zix zixer: h3 translate, a response head encodes back as a field section" {
    const raw = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nConnection: keep-alive\r\nX-Trace: abc\r\nContent-Length: 99\r\n\r\n";
    const response = try http1_head.parseResponse(raw, "POST");

    var block_buf: [512]u8 = undefined;
    const block = try encodeResponseBlock(&block_buf, &response, 17, .{});

    var scratch: [512]u8 = undefined;
    const section = try h3_qpack.decodeSection(block, &scratch);

    try testing.expectEqualStrings("201", section.get(":status").?);
    try testing.expectEqualStrings("application/json", section.get("content-type").?);
    try testing.expectEqualStrings("abc", section.get("x-trace").?);
    try testing.expectEqualStrings(VIA_H3, section.get("via").?);
    try testing.expectEqualStrings("17", section.get("content-length").?);
    try testing.expect(section.get("connection") == null);
}

test "zix zixer: h3 translate, a local answer carries proxy status" {
    var block_buf: [256]u8 = undefined;
    const block = try encodeLocalBlock(&block_buf, 502, "connection_refused", .{});

    var scratch: [256]u8 = undefined;
    const section = try h3_qpack.decodeSection(block, &scratch);

    try testing.expectEqualStrings("502", section.get(":status").?);
    try testing.expectEqualStrings("0", section.get("content-length").?);
    try testing.expectEqualStrings("zixer; error=\"connection_refused\"", section.get("proxy-status").?);

    const plain = try encodeLocalBlock(&block_buf, 404, null, .{});
    const plain_section = try h3_qpack.decodeSection(plain, &scratch);
    try testing.expectEqualStrings("404", plain_section.get(":status").?);
    try testing.expect(plain_section.get("proxy-status") == null);
}

test "zix zixer: h3 translate, a static answer carries type, length, and vary" {
    var block_buf: [256]u8 = undefined;
    const block = try encodeStaticBlock(&block_buf, "text/css", 240, "br", .{});

    var scratch: [256]u8 = undefined;
    const section = try h3_qpack.decodeSection(block, &scratch);

    try testing.expectEqualStrings("200", section.get(":status").?);
    try testing.expectEqualStrings("text/css", section.get("content-type").?);
    try testing.expectEqualStrings("240", section.get("content-length").?);
    try testing.expectEqualStrings("br", section.get("content-encoding").?);
    try testing.expectEqualStrings("Accept-Encoding", section.get("vary").?);
}

test "zix zixer: h3 translate, trailers encode lowercase and drop hop by hop" {
    const trailers = [_]http1_head.Header{
        .{ .name = "Grpc-Status", .value = "0" },
        .{ .name = "Connection", .value = "close" },
    };

    var block_buf: [256]u8 = undefined;
    const block = try encodeTrailerBlock(&block_buf, &trailers);

    var scratch: [256]u8 = undefined;
    const section = try h3_qpack.decodeSection(block, &scratch);

    try testing.expectEqual(@as(usize, 1), section.len);
    try testing.expectEqualStrings("grpc-status", section.entries[0].name);
    try testing.expectEqualStrings("0", section.entries[0].value);
}

/// Compile one header section the way a site cfg would, for the h3 tests.
fn testTable(arena: std.mem.Allocator, direction: cfg_headers.Direction, lines: []const cfg_scanner.Entry) !cfg_headers.Table {
    var faults = fault.FaultList.init(arena);
    const table = try cfg_headers.compile(arena, lines, direction, true, &faults);

    try testing.expectEqual(@as(usize, 0), faults.slice().len);

    return table;
}

test "zix zixer: h3 translate, the field sections carry the site's response headers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const table = try testTable(arena.allocator(), .RESPONSE, &.{
        .{ .key = "strict-transport-security", .value = "max-age=31536000", .line_no = 2 },
        .{ .key = "X-Origin", .value = "$scheme://$host", .line_no = 3 },
        .{ .key = "x-custom", .value = "site-wins", .line_no = 4 },
    });
    const extra = cfg_headers.Block{
        .table = table,
        .values = .{ .client_ip = "203.0.113.9", .scheme = "https", .host = "app.example" },
    };

    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;
    var block_buf: [2048]u8 = undefined;

    const response = try http1_head.parseResponse(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Custom: origin-value\r\n\r\n",
        "GET",
    );
    const head = try encodeResponseBlock(&block_buf, &response, 4, extra);
    const head_section = try h3_qpack.decodeSection(head, &scratch);

    try testing.expectEqualStrings("max-age=31536000", head_section.get("strict-transport-security").?);

    // The name travels lowercase whatever the operator typed (rfc 9114 4.2).
    try testing.expectEqualStrings("https://app.example", head_section.get("x-origin").?);
    try testing.expectEqualStrings("site-wins", head_section.get("x-custom").?);

    const local = try encodeLocalBlock(&block_buf, 504, "http_response_timeout", extra);
    const local_section = try h3_qpack.decodeSection(local, &scratch);
    try testing.expectEqualStrings("max-age=31536000", local_section.get("strict-transport-security").?);

    const static = try encodeStaticBlock(&block_buf, "text/html", 12, null, extra);
    const static_section = try h3_qpack.decodeSection(static, &scratch);
    try testing.expectEqualStrings("max-age=31536000", static_section.get("strict-transport-security").?);
    try testing.expectEqualStrings("text/html", static_section.get("content-type").?);
}

test "zix zixer: h3 translate, the upstream head carries the site's request headers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const table = try testTable(arena.allocator(), .REQUEST, &.{
        .{ .key = "x-real-ip", .value = "$client_ip", .line_no = 2 },
        .{ .key = "x-tenant", .value = "acme", .line_no = 3 },
    });
    const extra = cfg_headers.Block{
        .table = table,
        .values = .{ .client_ip = "203.0.113.9", .scheme = "https", .host = "app.example" },
    };

    const fields = [_]h3_qpack.Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "app.example" },
        .{ .name = ":path", .value = "/api" },
        .{ .name = "x-tenant", .value = "spoofed" },
    };
    const request = try assemble(&fields, true);

    var head_buf: [http1_head.MAX_HEAD_BYTES + 512 + cfg_headers.MAX_BLOCK_BYTES]u8 = undefined;
    const head = try buildUpstreamHead(&head_buf, &request, &fields, testAddress(), .HTTPS, extra);

    try testing.expect(std.mem.indexOf(u8, head, "x-real-ip: 203.0.113.9\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "x-tenant: acme\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, head, "spoofed") == null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, head, "\r\n\r\n"));
}
