//! prometheuz http_client: a minimal HTTP/1.1 client, std only.
//!
//! Note:
//! - Standalone package, no zix dependency (see the plan doc's "Transport"
//!   section for why zix.Http.Client cannot be reused here).
//! - GET and POST only, cleartext only, Content-Length bodies only: no
//!   chunked transfer-encoding, no TLS, no redirects.
//! - Same idea as zix.Http.Client's own requestUds path: connect, write the
//!   request bytes raw, read the response head up to "\r\n\r\n", parse the
//!   status line plus Content-Length, then read exactly that many body
//!   bytes (or read to EOF when Content-Length is absent).

const std = @import("std");

const REQUEST_BUILD_BUF: usize = 4096;
const HEAD_SCAN_BUF: usize = 8192;
const BODY_READ_CHUNK: usize = 4096;

// --------------------------------------------------------- //

/// A request header, name/value.
pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

/// Options for a single request. All fields optional.
pub const RequestOpts = struct {
    /// Additional request headers, sent after the built-in Host/Connection lines.
    headers: []const Header = &.{},
    /// Request body bytes. null sends no body (Content-Length: 0 on POST).
    body: ?[]const u8 = null,
    /// TCP connect timeout in milliseconds, 0 disables the bound.
    connect_timeout_ms: u32 = 5_000,
    /// Caps the response body in bytes.
    max_response_body: usize = 1024 * 1024 * 4,
};

/// Parsed HTTP response. Caller must call deinit() to release owned memory.
pub const ClientResponse = struct {
    status_code: u16,
    body_data: []u8,
    head_bytes: []u8,
    allocator: std.mem.Allocator,

    /// HTTP status code (e.g. 200, 404).
    pub fn status(self: ClientResponse) u16 {
        return self.status_code;
    }

    /// First value of the named response header (case-insensitive). null when absent.
    pub fn header(self: ClientResponse, name: []const u8) ?[]const u8 {
        return findHeader(self.head_bytes, name);
    }

    /// Response body bytes. Empty slice when the server sent no body.
    pub fn body(self: ClientResponse) []const u8 {
        return self.body_data;
    }

    /// Release body and head memory.
    pub fn deinit(self: *ClientResponse) void {
        if (self.body_data.len > 0) self.allocator.free(self.body_data);
        if (self.head_bytes.len > 0) self.allocator.free(self.head_bytes);
    }
};

// --------------------------------------------------------- //

/// GET request. See request() for the shared implementation.
pub fn get(allocator: std.mem.Allocator, io: std.Io, ip: []const u8, port: u16, path: []const u8, opts: RequestOpts) !ClientResponse {
    return request(allocator, io, "GET", ip, port, path, opts);
}

/// POST request. See request() for the shared implementation.
pub fn post(allocator: std.mem.Allocator, io: std.Io, ip: []const u8, port: u16, path: []const u8, opts: RequestOpts) !ClientResponse {
    return request(allocator, io, "POST", ip, port, path, opts);
}

/// Make an HTTP/1.1 request and return the parsed response.
///
/// Return:
/// - ClientResponse
/// - error.PrometheuzConnectionClosed (peer closed before a full head/body arrived)
/// - error.PrometheuzInvalidResponse (no "\r\n\r\n" found within HEAD_SCAN_BUF)
/// - error.PrometheuzBodyTooLarge (response body exceeded opts.max_response_body)
pub fn request(allocator: std.mem.Allocator, io: std.Io, method: []const u8, ip: []const u8, port: u16, path: []const u8, opts: RequestOpts) !ClientResponse {
    const stream = try connectTcp(io, ip, port, opts.connect_timeout_ms);
    defer stream.close(io);

    const fd = stream.socket.handle;

    try sendRequest(fd, method, ip, port, path, opts);

    return readResponse(allocator, fd, opts.max_response_body);
}

// --------------------------------------------------------- //

/// TCP connect to an IP literal or a hostname.
///
/// Note:
/// - connect_timeout_ms is accepted for API shape parity (RequestOpts,
///   ScrapeConfig/WriteConfig/QueryConfig) but not yet enforced here:
///   std.Io.Threaded's netConnectIpPosix has no timeout support on this Zig
///   version (`@panic("TODO implement netConnectIpPosix with timeout")`), so
///   passing one through would crash instead of erroring. Same "stored, not
///   yet applied" shape as zix.Http.Client's own response_timeout_ms.
fn connectTcp(io: std.Io, host: []const u8, port: u16, connect_timeout_ms: u32) !std.Io.net.Stream {
    _ = connect_timeout_ms;

    if (std.Io.net.IpAddress.resolve(io, host, port)) |addr| {
        return addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    } else |_| {
        const host_name = try std.Io.net.HostName.init(host);

        return host_name.connect(io, port, .{ .mode = .stream, .protocol = .tcp });
    }
}

/// Build and write the request line, headers, and body over a connected fd.
fn sendRequest(fd: std.posix.fd_t, method: []const u8, ip: []const u8, port: u16, path: []const u8, opts: RequestOpts) !void {
    var request_buf: [REQUEST_BUILD_BUF]u8 = undefined;
    var request_len: usize = 0;

    const status_line = std.fmt.bufPrint(
        request_buf[request_len..],
        "{s} {s} HTTP/1.1\r\nHost: {s}:{d}\r\nConnection: close\r\n",
        .{ method, path, ip, port },
    ) catch return error.PrometheuzRequestTooLarge;
    request_len += status_line.len;

    for (opts.headers) |field| {
        const header_line = std.fmt.bufPrint(
            request_buf[request_len..],
            "{s}: {s}\r\n",
            .{ field.name, field.value },
        ) catch return error.PrometheuzRequestTooLarge;
        request_len += header_line.len;
    }

    const body = opts.body orelse &.{};
    const content_length_line = std.fmt.bufPrint(
        request_buf[request_len..],
        "Content-Length: {d}\r\n\r\n",
        .{body.len},
    ) catch return error.PrometheuzRequestTooLarge;
    request_len += content_length_line.len;

    try writeAll(fd, request_buf[0..request_len]);
    if (body.len > 0) try writeAll(fd, body);
}

/// Read the response head (up to "\r\n\r\n"), parse status plus
/// Content-Length, then read the body.
fn readResponse(allocator: std.mem.Allocator, fd: std.posix.fd_t, max_response_body: usize) !ClientResponse {
    var head_scan_buf: [HEAD_SCAN_BUF]u8 = undefined;
    var head_scan_len: usize = 0;
    var header_end: usize = 0;

    while (head_scan_len < head_scan_buf.len) {
        const n = readOnceFD(fd, head_scan_buf[head_scan_len..]) catch return error.PrometheuzConnectionClosed;
        if (n == 0) return error.PrometheuzConnectionClosed;
        head_scan_len += n;
        if (std.mem.indexOf(u8, head_scan_buf[0..head_scan_len], "\r\n\r\n")) |pos| {
            header_end = pos + 4;
            break;
        }
    }

    if (header_end == 0) return error.PrometheuzInvalidResponse;

    const head_raw = head_scan_buf[0..header_end];
    const status_code = parseStatusCode(head_raw);

    const head_copy = try allocator.dupe(u8, head_raw);
    errdefer allocator.free(head_copy);

    const content_length: ?usize = blk: {
        const raw_value = findHeader(head_raw, "content-length") orelse break :blk null;
        break :blk std.fmt.parseInt(usize, std.mem.trim(u8, raw_value, " \t"), 10) catch null;
    };
    const is_chunked = if (findHeader(head_raw, "transfer-encoding")) |raw_value|
        std.ascii.eqlIgnoreCase(std.mem.trim(u8, raw_value, " \t"), "chunked")
    else
        false;

    const already_read = head_scan_len - header_end;

    var body_list: std.ArrayList(u8) = .empty;
    errdefer body_list.deinit(allocator);

    if (is_chunked) {
        try readChunkedBody(allocator, fd, head_scan_buf[header_end..][0..already_read], max_response_body, &body_list);
    } else if (content_length) |body_len| {
        if (body_len > max_response_body) return error.PrometheuzBodyTooLarge;
        try body_list.resize(allocator, body_len);
        // Explicit usize annotation matters here: @min over comptime-bounded
        // operands can otherwise infer a narrower integer type than usize,
        // wrapping body_received below once a real (multi-KB) body exceeds
        // that narrower range.
        const initial: usize = @min(already_read, body_len);
        @memcpy(body_list.items[0..initial], head_scan_buf[header_end..][0..initial]);
        var body_received = initial;
        while (body_received < body_len) {
            const n = readOnceFD(fd, body_list.items[body_received..]) catch break;
            if (n == 0) break;
            body_received += n;
        }
    } else {
        if (already_read > 0) try body_list.appendSlice(allocator, head_scan_buf[header_end..][0..already_read]);
        var read_chunk: [BODY_READ_CHUNK]u8 = undefined;
        while (true) {
            const n = readOnceFD(fd, &read_chunk) catch break;
            if (n == 0) break;
            if (body_list.items.len + n > max_response_body) return error.PrometheuzBodyTooLarge;
            try body_list.appendSlice(allocator, read_chunk[0..n]);
        }
    }

    const body_bytes = try body_list.toOwnedSlice(allocator);

    return .{
        .status_code = status_code,
        .body_data = body_bytes,
        .head_bytes = head_copy,
        .allocator = allocator,
    };
}

/// Decode an HTTP/1.1 chunked body (RFC 9112 7.1) into `body_list`. `seed`
/// is whatever body bytes were already read into the head-scan buffer
/// before framing was known to be chunked. Further bytes come from `fd`.
/// Chunk extensions (after `;` on a size line) and trailer headers (after
/// the terminating 0-size chunk) are read but ignored: the socket closes
/// right after this call regardless, so there is nothing to preserve them
/// for.
fn readChunkedBody(allocator: std.mem.Allocator, fd: std.posix.fd_t, seed: []const u8, max_response_body: usize, body_list: *std.ArrayList(u8)) !void {
    var carry: std.ArrayList(u8) = .empty;
    defer carry.deinit(allocator);
    try carry.appendSlice(allocator, seed);

    while (true) {
        const size_line = try takeLine(&carry, allocator, fd);
        defer allocator.free(size_line);

        const size_text = if (std.mem.indexOfScalar(u8, size_line, ';')) |semicolon_pos| size_line[0..semicolon_pos] else size_line;
        const chunk_size = std.fmt.parseInt(usize, std.mem.trim(u8, size_text, " \t"), 16) catch return error.PrometheuzInvalidResponse;

        if (chunk_size == 0) return;
        if (body_list.items.len + chunk_size > max_response_body) return error.PrometheuzBodyTooLarge;

        const chunk_data = try takeExact(&carry, allocator, fd, chunk_size);
        defer allocator.free(chunk_data);
        try body_list.appendSlice(allocator, chunk_data);

        const trailing_crlf = try takeExact(&carry, allocator, fd, 2);
        allocator.free(trailing_crlf);
    }
}

fn fillMore(carry: *std.ArrayList(u8), allocator: std.mem.Allocator, fd: std.posix.fd_t) !bool {
    var read_chunk: [BODY_READ_CHUNK]u8 = undefined;
    const n = readOnceFD(fd, &read_chunk) catch return error.PrometheuzConnectionClosed;
    if (n == 0) return false;
    try carry.appendSlice(allocator, read_chunk[0..n]);

    return true;
}

/// Read and remove one CRLF-terminated line (without the CRLF), reading
/// more from `fd` as needed.
fn takeLine(carry: *std.ArrayList(u8), allocator: std.mem.Allocator, fd: std.posix.fd_t) ![]u8 {
    while (true) {
        if (std.mem.indexOf(u8, carry.items, "\r\n")) |pos| {
            const line = try allocator.dupe(u8, carry.items[0..pos]);
            consume(carry, pos + 2);

            return line;
        }
        if (!try fillMore(carry, allocator, fd)) return error.PrometheuzInvalidResponse;
    }
}

/// Read and remove exactly `count` bytes, reading more from `fd` as
/// needed.
fn takeExact(carry: *std.ArrayList(u8), allocator: std.mem.Allocator, fd: std.posix.fd_t, count: usize) ![]u8 {
    while (carry.items.len < count) {
        if (!try fillMore(carry, allocator, fd)) return error.PrometheuzConnectionClosed;
    }

    const taken = try allocator.dupe(u8, carry.items[0..count]);
    consume(carry, count);

    return taken;
}

fn consume(carry: *std.ArrayList(u8), count: usize) void {
    std.mem.copyForwards(u8, carry.items[0 .. carry.items.len - count], carry.items[count..]);
    carry.shrinkRetainingCapacity(carry.items.len - count);
}

// --------------------------------------------------------- //

// --------------------------------------------------------- //
// Windows socket I/O over ntdll. Zig 0.16 std drives sockets through AFD, and
// std.posix read plus the libc write are POSIX-only, so the raw-fd paths above
// branch here on Windows. The helpers issue the AFD send and receive ioctls
// (the requests std itself uses: the plain NtReadFile / NtWriteFile path
// fails on raw AFD endpoints) and each call completes through its own event,
// so the status block is never read before the operation finished.

/// Per-call completion event for the ntdll socket I/O below.
fn windowsIoEvent() error{BrokenPipe}!std.os.windows.HANDLE {
    const windows = std.os.windows;
    var event: windows.HANDLE = undefined;
    const status = windows.ntdll.NtCreateEvent(
        &event,
        windows.ACCESS_MASK.Specific.Event.ALL_ACCESS,
        null,
        .Notification,
        .FALSE,
    );
    if (status != .SUCCESS) return error.BrokenPipe;

    return event;
}

/// One AFD receive ioctl, waiting on a per-call event when the operation goes
/// async. A graceful peer close completes with SUCCESS and 0 bytes.
fn windowsReadOnce(handle: std.os.windows.HANDLE, buf: []u8) error{BrokenPipe}!usize {
    const windows = std.os.windows;
    const event = try windowsIoEvent();
    defer _ = windows.ntdll.NtClose(event);

    const iovecs = [1]windows.AFD.WSABUF(.@"var"){.{
        .len = std.math.lossyCast(windows.ULONG, buf.len),
        .buf = buf.ptr,
    }};
    const info = windows.AFD.RECV_INFO{
        .BufferArray = &iovecs,
        .BufferCount = 1,
        .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
        .TdiFlags = .{ .NORMAL = true },
    };

    var iosb: windows.IO_STATUS_BLOCK = undefined;
    var status = windows.ntdll.NtDeviceIoControlFile(
        handle,
        event,
        null,
        null,
        &iosb,
        windows.IOCTL.AFD.RECEIVE,
        @ptrCast(&info),
        @sizeOf(windows.AFD.RECV_INFO),
        null,
        0,
    );
    if (status == .PENDING) {
        _ = windows.ntdll.NtWaitForSingleObject(event, .FALSE, null);
        status = iosb.u.Status;
    }
    if (status == .END_OF_FILE) return 0;
    if (status != .SUCCESS) return error.BrokenPipe;

    return iosb.Information;
}

/// Write all of data via AFD send ioctls, waiting on a per-call event when async.
fn windowsWriteAll(handle: std.os.windows.HANDLE, data: []const u8) error{BrokenPipe}!void {
    const windows = std.os.windows;
    var rem = data;
    while (rem.len > 0) {
        const event = try windowsIoEvent();
        defer _ = windows.ntdll.NtClose(event);

        const iovecs = [1]windows.AFD.WSABUF(.@"const"){.{
            .len = std.math.lossyCast(windows.ULONG, rem.len),
            .buf = rem.ptr,
        }};
        const info = windows.AFD.SEND_INFO{
            .BufferArray = &iovecs,
            .BufferCount = 1,
            .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
            .TdiFlags = .{},
        };

        var iosb: windows.IO_STATUS_BLOCK = undefined;
        var status = windows.ntdll.NtDeviceIoControlFile(
            handle,
            event,
            null,
            null,
            &iosb,
            windows.IOCTL.AFD.SEND,
            @ptrCast(&info),
            @sizeOf(windows.AFD.SEND_INFO),
            null,
            0,
        );
        if (status == .PENDING) {
            _ = windows.ntdll.NtWaitForSingleObject(event, .FALSE, null);
            status = iosb.u.Status;
        }
        if (status != .SUCCESS) return error.BrokenPipe;
        if (iosb.Information == 0) return error.BrokenPipe;

        rem = rem[iosb.Information..];
    }
}

/// Read some bytes from fd: the ntdll path on Windows, std.posix.read elsewhere.
fn readOnceFD(fd: std.posix.fd_t, buf: []u8) !usize {
    if (comptime @import("builtin").target.os.tag == .windows) return windowsReadOnce(fd, buf);

    return std.posix.read(fd, buf);
}

fn writeAll(fd: std.posix.fd_t, data: []const u8) !void {
    if (comptime @import("builtin").target.os.tag == .windows) return windowsWriteAll(fd, data);

    var written: usize = 0;
    while (written < data.len) {
        const rc = std.posix.system.write(fd, data[written..].ptr, data.len - written);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.BrokenPipe;
                written += n;
            },
            .INTR => continue,
            else => return error.BrokenPipe,
        }
    }
}

fn parseStatusCode(head: []const u8) u16 {
    const first_line_end = std.mem.indexOfScalar(u8, head, '\r') orelse return 0;
    const first_line = head[0..first_line_end];
    const space1 = std.mem.indexOfScalar(u8, first_line, ' ') orelse return 0;
    const after_space = first_line[space1 + 1 ..];
    const space2 = std.mem.indexOfScalar(u8, after_space, ' ') orelse after_space.len;

    return std.fmt.parseInt(u16, after_space[0..space2], 10) catch 0;
}

fn findHeader(head: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, head, "\r\n");
    _ = it.next();
    while (it.next()) |line| {
        const colon_pos = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const header_name = std.mem.trim(u8, line[0..colon_pos], " \t");
        if (std.ascii.eqlIgnoreCase(header_name, name)) {
            return std.mem.trim(u8, line[colon_pos + 1 ..], " \t");
        }
    }

    return null;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const testing = std.testing;

/// A scripted mock server: server bytes pre-written into one end of a
/// loopback TCP pair before the client ever reads. The client's own writes
/// land in the peer's read buffer, so a test can also assert on the exact
/// request bytes sent.
///
/// Note:
/// - This file works on raw fds throughout (readResponse/sendRequest take a
///   plain fd_t), so init/deinit each spin up a short-lived std.Io.Threaded
///   just to set up or tear down the loopback pair, not shared with callers.
const MOCK_SERVER_PORT: u16 = 19300;

fn loopbackStream(fd: std.posix.fd_t) std.Io.net.Stream {
    return .{ .socket = .{ .handle = fd, .address = .{ .ip4 = .loopback(0) } } };
}

fn closeLoopbackFd(fd: std.posix.fd_t) void {
    var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer threaded.deinit();

    loopbackStream(fd).close(threaded.io());
}

const MockServer = struct {
    client_fd: std.posix.fd_t,
    script_fd: std.posix.fd_t,

    fn init(script: []const u8) !MockServer {
        var threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
        defer threaded.deinit();
        const io = threaded.io();

        const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", MOCK_SERVER_PORT);
        var listener = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });
        defer listener.deinit(io);

        const Accepted = struct {
            listener: *std.Io.net.Server,
            io: std.Io,
            stream: std.Io.net.Stream = undefined,
            err: ?anyerror = null,

            fn run(self: *@This()) void {
                self.stream = self.listener.accept(self.io) catch |e| {
                    self.err = e;
                    return;
                };
            }
        };

        var accepted = Accepted{ .listener = &listener, .io = io };
        const t = try std.Thread.spawn(.{}, Accepted.run, .{&accepted});

        const client_stream = try addr.connect(io, .{ .mode = .stream });
        t.join();
        if (accepted.err) |e| return e;

        var write_buf: [8192]u8 = undefined;
        var writer = accepted.stream.writer(io, &write_buf);
        try writer.interface.writeAll(script);
        try writer.interface.flush();

        return .{ .client_fd = client_stream.socket.handle, .script_fd = accepted.stream.socket.handle };
    }

    fn deinit(self: *const MockServer) void {
        closeLoopbackFd(self.client_fd);
        closeLoopbackFd(self.script_fd);
    }

    /// Read the client's request bytes, looping until the full request has
    /// arrived (headers plus the Content-Length body), so a request split
    /// across TCP segments cannot truncate the capture.
    fn readSent(self: *const MockServer, buf: []u8) []u8 {
        var filled: usize = 0;

        while (filled < buf.len) {
            const n = readOnceFD(self.script_fd, buf[filled..]) catch break;
            if (n == 0) break;

            filled += n;
            if (requestComplete(buf[0..filled])) break;
        }

        return buf[0..filled];
    }

    /// A sendRequest wire request is complete once the header block ends and
    /// the Content-Length body bytes follow (sendRequest always writes the field).
    fn requestComplete(data: []const u8) bool {
        const label = "Content-Length: ";

        const header_end = (std.mem.indexOf(u8, data, "\r\n\r\n") orelse return false) + 4;

        const label_pos = std.mem.indexOf(u8, data[0..header_end], label) orelse return true;
        const digits_start = label_pos + label.len;
        const digits_end = std.mem.indexOfScalarPos(u8, data, digits_start, '\r') orelse return true;
        const content_len = std.fmt.parseInt(usize, data[digits_start..digits_end], 10) catch return true;

        return data.len >= header_end + content_len;
    }
};

test "prometheuz: http_client parses a Content-Length response" {
    const mock = try MockServer.init(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello",
    );
    defer mock.deinit();

    var resp = try readResponse(testing.allocator, mock.client_fd, 1024 * 1024);
    defer resp.deinit();

    try testing.expectEqual(@as(u16, 200), resp.status());
    try testing.expectEqualStrings("hello", resp.body());
    try testing.expectEqualStrings("text/plain", resp.header("content-type").?);
}

test "prometheuz: http_client reads to EOF when Content-Length is absent" {
    const mock = try MockServer.init("HTTP/1.1 200 OK\r\n\r\nno-length-body");
    defer closeLoopbackFd(mock.client_fd);

    // Peer goes away right after the script: the client must read to EOF
    // since there is no Content-Length to bound the body.
    closeLoopbackFd(mock.script_fd);

    var resp = try readResponse(testing.allocator, mock.client_fd, 1024 * 1024);
    defer resp.deinit();

    try testing.expectEqual(@as(u16, 200), resp.status());
    try testing.expectEqualStrings("no-length-body", resp.body());
}

test "prometheuz: http_client surfaces a 404 status" {
    const mock = try MockServer.init("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    defer mock.deinit();

    var resp = try readResponse(testing.allocator, mock.client_fd, 1024 * 1024);
    defer resp.deinit();

    try testing.expectEqual(@as(u16, 404), resp.status());
    try testing.expectEqualStrings("", resp.body());
}

test "prometheuz: http_client rejects a body over max_response_body" {
    const mock = try MockServer.init("HTTP/1.1 200 OK\r\nContent-Length: 999999\r\n\r\n");
    defer mock.deinit();

    try testing.expectError(error.PrometheuzBodyTooLarge, readResponse(testing.allocator, mock.client_fd, 16));
}

test "prometheuz: http_client sendRequest writes a well-formed GET" {
    const mock = try MockServer.init("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n");
    defer mock.deinit();

    try sendRequest(mock.client_fd, "GET", "127.0.0.1", 9100, "/metrics", .{});

    var sent_buf: [512]u8 = undefined;
    const sent = mock.readSent(&sent_buf);

    try testing.expect(std.mem.startsWith(u8, sent, "GET /metrics HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, sent, "Host: 127.0.0.1:9100\r\n") != null);
    try testing.expect(std.mem.indexOf(u8, sent, "Content-Length: 0\r\n") != null);
}

test "prometheuz: http_client sendRequest carries a POST body" {
    const mock = try MockServer.init("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    defer mock.deinit();

    try sendRequest(mock.client_fd, "POST", "10.0.0.5", 9090, "/api/v1/write", .{ .body = "payload" });

    var sent_buf: [512]u8 = undefined;
    const sent = mock.readSent(&sent_buf);

    try testing.expect(std.mem.startsWith(u8, sent, "POST /api/v1/write HTTP/1.1\r\n"));
    try testing.expect(std.mem.indexOf(u8, sent, "Content-Length: 7\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, sent, "\r\n\r\npayload"));
}

test "prometheuz: http_client decodes a chunked response" {
    // Same shape node-exporter actually sends: no Content-Length, chunked
    // body, a word split across a chunk boundary.
    const mock = try MockServer.init(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" ++
            "5\r\nhello\r\n" ++
            "1\r\n \r\n" ++
            "5\r\nworld\r\n" ++
            "0\r\n\r\n",
    );
    defer mock.deinit();

    var resp = try readResponse(testing.allocator, mock.client_fd, 1024 * 1024);
    defer resp.deinit();

    try testing.expectEqual(@as(u16, 200), resp.status());
    try testing.expectEqualStrings("hello world", resp.body());
}

test "prometheuz: http_client chunked response spanning multiple reads" {
    // A body larger than one BODY_READ_CHUNK (4096), forcing fillMore() to
    // run more than once and a chunk boundary to land mid-read.
    var large: [10_000]u8 = undefined;
    for (&large, 0..) |*byte, index| byte.* = 'a' + @as(u8, @intCast(index % 26));

    var script: std.ArrayList(u8) = .empty;
    defer script.deinit(testing.allocator);
    try script.appendSlice(testing.allocator, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");

    var offset: usize = 0;
    while (offset < large.len) {
        const chunk_len: usize = @min(large.len - offset, 777);
        var size_line_buf: [16]u8 = undefined;
        const size_line = try std.fmt.bufPrint(&size_line_buf, "{x}\r\n", .{chunk_len});
        try script.appendSlice(testing.allocator, size_line);
        try script.appendSlice(testing.allocator, large[offset..][0..chunk_len]);
        try script.appendSlice(testing.allocator, "\r\n");
        offset += chunk_len;
    }
    try script.appendSlice(testing.allocator, "0\r\n\r\n");

    const mock = try MockServer.init(script.items);
    defer mock.deinit();

    var resp = try readResponse(testing.allocator, mock.client_fd, 1024 * 1024);
    defer resp.deinit();

    try testing.expectEqualSlices(u8, &large, resp.body());
}

test "prometheuz: http_client sendRequest carries custom headers" {
    const mock = try MockServer.init("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    defer mock.deinit();

    try sendRequest(mock.client_fd, "POST", "10.0.0.5", 9090, "/api/v1/write", .{
        .headers = &.{.{ .name = "Content-Encoding", .value = "snappy" }},
        .body = "x",
    });

    var sent_buf: [512]u8 = undefined;
    const sent = mock.readSent(&sent_buf);

    try testing.expect(std.mem.indexOf(u8, sent, "Content-Encoding: snappy\r\n") != null);
}

test "prometheuz: http_client requestComplete detects a split request" {
    const full = "POST /w HTTP/1.1\r\nContent-Length: 7\r\n\r\npayload";

    try testing.expect(!MockServer.requestComplete(full[0..10]));
    try testing.expect(!MockServer.requestComplete(full[0 .. full.len - 3]));
    try testing.expect(MockServer.requestComplete(full));
    try testing.expect(MockServer.requestComplete("GET /m HTTP/1.1\r\n\r\n"));
}
