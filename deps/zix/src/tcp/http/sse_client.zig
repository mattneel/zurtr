//! zix http SSE client
//! Consumes a Server-Sent Events stream: HTTP GET + line-by-line event parsing.

const std = @import("std");
const builtin = @import("builtin");
const win_io = @import("../../utils/windows_io.zig");
const socket_poll = @import("../../utils/socket_poll.zig");

/// SSE stream read buffer.
const SSE_READ_BUF: usize = 4096;
/// SSE event-name scratch buffer.
const EVENT_NAME_SCRATCH: usize = 256;
/// SSE event-id scratch buffer.
const EVENT_ID_SCRATCH: usize = 256;
/// SSE line scratch buffer.
const LINE_SCRATCH: usize = 1024;
/// SSE request build buffer.
const REQUEST_BUILD_BUF: usize = 1024;
/// SSE response head buffer.
const RESPONSE_HEAD_BUF: usize = 4096;

// --------------------------------------------------------- //

/// A single Server-Sent Event.
/// All slice fields point into the buf passed to SseStream.next().
pub const SseEvent = struct {
    /// Event type field. null when the stream omitted the event: line (default type "message").
    event: ?[]const u8,
    /// Accumulated data (multiple data: lines joined with '\n').
    data: []const u8,
    /// Last-event-ID field. null when the stream omitted the id: line.
    id: ?[]const u8,
    /// Reconnect time hint in milliseconds. null when the stream omitted the retry: line.
    retry: ?u32,
};

// --------------------------------------------------------- //

/// Configuration for an SSE client connection.
pub const SseClientConfig = struct {
    /// Event-loop backend. Caller owns and must outlive the client.
    io: std.Io,
    /// TCP connect timeout in milliseconds. 0 = no timeout.
    connect_timeout_ms: u32 = 0,
    /// Time allowed to receive the response head after the request is sent, in milliseconds.
    /// 0 = no timeout. Yields error.ZixResponseTimeout when a server accepts and then never answers.
    response_timeout_ms: u32 = 0,
    /// Idle bound between events, in milliseconds. The budget restarts on every event.
    /// 0 = no timeout. Yields error.ZixReadTimeout when the stream goes quiet.
    ///
    /// Note:
    /// - Defaults to no bound on purpose. A live SSE stream is expected to sit idle between
    ///   events, so only a caller that knows its stream is chatty (a test, a health probe) should
    ///   set this.
    read_timeout_ms: u32 = 0,
};

// --------------------------------------------------------- //

/// Live SSE stream. Yields parsed events via next().
/// Call deinit() when done.
pub const SseStream = struct {
    const Self = @This();

    fd: std.posix.fd_t,
    read_buf: [SSE_READ_BUF]u8,
    read_len: usize,
    read_pos: usize,
    /// Idle bound carried over from SseClientConfig, applied per socket read in readLine.
    /// Defaults to no bound so a hand-built stream reads exactly as it did before the field existed.
    read_timeout_ms: u32 = 0,

    // --------------------------------------------------------- //

    /// Read and parse one event from the stream.
    ///
    /// Note:
    /// - All returned slices point into buf. Do not call next() again until
    ///   you have finished using the previous SseEvent's fields.
    /// - buf layout after return: [0..data_end] = data, then event type, then id.
    ///   Caller must size buf generously (4096 B recommended).
    /// - null when the server closes the stream cleanly.
    ///
    /// Param:
    /// buf - []u8 (workspace, must be large enough for data + event + id combined)
    ///
    /// Return:
    /// - ?SseEvent
    pub fn next(self: *Self, buf: []u8) !?SseEvent {
        var data_len: usize = 0;
        var event_scratch: [EVENT_NAME_SCRATCH]u8 = undefined;
        var event_scratch_len: usize = 0;
        var id_scratch: [EVENT_ID_SCRATCH]u8 = undefined;
        var id_scratch_len: usize = 0;
        var retry: ?u32 = null;
        var has_data = false;

        var line_scratch: [LINE_SCRATCH]u8 = undefined;

        while (true) {
            const maybe_line = try self.readLine(&line_scratch);

            if (maybe_line == null) {
                if (has_data) break;
                return null;
            }

            const line = maybe_line.?;

            if (line.len == 0) {
                if (has_data) break;
                event_scratch_len = 0;
                id_scratch_len = 0;
                retry = null;
                continue;
            }

            if (line[0] == ':') continue;

            if (splitField(line, "data")) |value| {
                if (has_data and data_len < buf.len) {
                    buf[data_len] = '\n';
                    data_len += 1;
                }
                const copy_len = @min(value.len, buf.len - data_len);
                @memcpy(buf[data_len..][0..copy_len], value[0..copy_len]);
                data_len += copy_len;
                has_data = true;
            } else if (splitField(line, "event")) |value| {
                event_scratch_len = @min(value.len, event_scratch.len);
                @memcpy(event_scratch[0..event_scratch_len], value[0..event_scratch_len]);
            } else if (splitField(line, "id")) |value| {
                id_scratch_len = @min(value.len, id_scratch.len);
                @memcpy(id_scratch[0..id_scratch_len], value[0..id_scratch_len]);
            } else if (splitField(line, "retry")) |value| {
                retry = std.fmt.parseInt(u32, value, 10) catch null;
            }
        }

        const data_slice = buf[0..data_len];
        var write_pos = data_len;

        const event_slice: ?[]const u8 = if (event_scratch_len > 0) event_blk: {
            const copy_len = @min(event_scratch_len, buf.len - write_pos);
            if (copy_len == 0) break :event_blk null;
            @memcpy(buf[write_pos..][0..copy_len], event_scratch[0..copy_len]);
            const s = buf[write_pos..][0..copy_len];
            write_pos += copy_len;
            break :event_blk s;
        } else null;

        const id_slice: ?[]const u8 = if (id_scratch_len > 0) id_blk: {
            const copy_len = @min(id_scratch_len, buf.len - write_pos);
            if (copy_len == 0) break :id_blk null;
            @memcpy(buf[write_pos..][0..copy_len], id_scratch[0..copy_len]);
            const s = buf[write_pos..][0..copy_len];
            break :id_blk s;
        } else null;

        return SseEvent{
            .event = event_slice,
            .data = data_slice,
            .id = id_slice,
            .retry = retry,
        };
    }

    /// Close the underlying TCP connection.
    pub fn deinit(self: Self) void {
        closeFD(self.fd);
    }

    // --------------------------------------------------------- //

    fn readLine(self: *Self, out: []u8) !?[]const u8 {
        var line_len: usize = 0;

        while (true) {
            while (self.read_pos < self.read_len) {
                const byte = self.read_buf[self.read_pos];
                self.read_pos += 1;

                if (byte == '\n') {
                    if (line_len > 0 and out[line_len - 1] == '\r') line_len -= 1;
                    return out[0..line_len];
                }

                if (line_len < out.len) {
                    out[line_len] = byte;
                    line_len += 1;
                }
            }

            // A quiet stream is an error, never a clean close: null here would surface as "no
            // event" and hide a server that accepted and then stopped answering.
            if (!socket_poll.readableWithin(self.fd, self.read_timeout_ms)) return error.ZixReadTimeout;

            const n = readOnceFD(self.fd, &self.read_buf) catch return null;
            if (n == 0) return if (line_len > 0) out[0..line_len] else null;
            self.read_pos = 0;
            self.read_len = n;
        }
    }
};

// --------------------------------------------------------- //

/// SSE client. Connects to an SSE endpoint and returns a live SseStream.
///
/// Usage:
/// ```zig
/// var sse_client = zix.Http.SseClient.init(.{ .io = process.io });
/// var stream = try sse_client.open("http://127.0.0.1:9010/events");
/// defer stream.deinit();
/// var buf: [4096]u8 = undefined;
/// while (try stream.next(&buf)) |ev| {
///     std.debug.print("data: {s}\n", .{ev.data});
/// }
/// ```
pub const SseClient = struct {
    const Self = @This();

    config: SseClientConfig,

    // --------------------------------------------------------- //

    /// Initialise the client. No connection is opened until open() is called.
    pub fn init(config: SseClientConfig) Self {
        return .{ .config = config };
    }

    /// Connect to an SSE endpoint and return a live stream.
    ///
    /// Note:
    /// - https:// is not yet supported.
    /// - Caller owns the returned SseStream and must call deinit() on it.
    ///
    /// Param:
    /// url - []const u8 (http://host:port/path)
    ///
    /// Return:
    /// - SseStream
    /// - error.ZixUrlMalformed (the URL does not parse)
    /// - error.ZixUrlSchemeUnsupported (the scheme is not http)
    /// - error.ZixUrlHostMissing (the URL carries no host)
    /// - error.ZixUrlPortInvalid (the port is not a number in range)
    /// - error.ZixUrlPathTooLong (the request line does not fit the buffer)
    /// - error.ZixTlsNotSupported (https:// scheme)
    /// - error.ZixConnectionFailed (TCP error or server closed early)
    /// - error.ZixNotEventStream (server did not respond with text/event-stream)
    /// - error.ZixUnexpectedStatus (server did not respond 200)
    pub fn open(self: Self, url: []const u8) !SseStream {
        const parsed = try parseHttpUrl(url);

        const addr = try std.Io.net.IpAddress.resolve(self.config.io, parsed.host, parsed.port);
        const tcp_stream = try addr.connect(self.config.io, .{ .mode = .stream, .protocol = .tcp });
        const fd = tcp_stream.socket.handle;
        errdefer closeFD(fd);

        var req_buf: [REQUEST_BUILD_BUF]u8 = undefined;
        const req = std.fmt.bufPrint(
            &req_buf,
            "GET {s} HTTP/1.1\r\n" ++
                "Host: {s}:{d}\r\n" ++
                "Accept: text/event-stream\r\n" ++
                "Cache-Control: no-cache\r\n" ++
                "Connection: keep-alive\r\n" ++
                "\r\n",
            .{ parsed.path, parsed.host, parsed.port },
        ) catch return error.ZixUrlPathTooLong;

        writeAllFD(fd, req) catch return error.ZixConnectionFailed;

        var head_buf: [RESPONSE_HEAD_BUF]u8 = undefined;
        var head_len: usize = 0;
        var header_end: usize = 0;

        while (head_len < head_buf.len) {
            if (!socket_poll.readableWithin(fd, self.config.response_timeout_ms)) return error.ZixResponseTimeout;

            const n = readOnceFD(fd, head_buf[head_len..]) catch return error.ZixConnectionFailed;
            if (n == 0) return error.ZixConnectionFailed;
            head_len += n;
            if (std.mem.indexOf(u8, head_buf[0..head_len], "\r\n\r\n")) |pos| {
                header_end = pos + 4;
                break;
            }
        }

        if (header_end == 0) return error.ZixConnectionFailed;
        if (!std.mem.startsWith(u8, head_buf[0..header_end], "HTTP/1.1 200")) return error.ZixUnexpectedStatus;

        const content_type = findHeader(head_buf[0..header_end], "content-type") orelse return error.ZixNotEventStream;
        if (std.mem.indexOf(u8, content_type, "text/event-stream") == null) return error.ZixNotEventStream;

        var result = SseStream{
            .fd = fd,
            .read_buf = undefined,
            .read_len = 0,
            .read_pos = 0,
            .read_timeout_ms = self.config.read_timeout_ms,
        };

        const already_read = head_len - header_end;
        if (already_read > 0) {
            const copy_len = @min(already_read, result.read_buf.len);
            @memcpy(result.read_buf[0..copy_len], head_buf[header_end..][0..copy_len]);
            result.read_len = copy_len;
        }

        return result;
    }
};

// --------------------------------------------------------- //

const HttpUrlParsed = struct { host: []const u8, port: u16, path: []const u8 };

fn parseHttpUrl(url: []const u8) !HttpUrlParsed {
    if (std.mem.startsWith(u8, url, "https://")) return error.ZixTlsNotSupported;
    if (!std.mem.startsWith(u8, url, "http://")) return error.ZixUrlSchemeUnsupported;

    const authority_start: usize = "http://".len;
    const path_start = std.mem.indexOfScalarPos(u8, url, authority_start, '/') orelse url.len;
    const authority = url[authority_start..path_start];
    const path_str: []const u8 = if (path_start < url.len) url[path_start..] else "/";

    if (authority.len == 0) return error.ZixUrlHostMissing;

    const colon_pos = std.mem.lastIndexOfScalar(u8, authority, ':');
    const host: []const u8 = if (colon_pos) |cp| authority[0..cp] else authority;
    const port: u16 = if (colon_pos) |cp|
        (std.fmt.parseInt(u16, authority[cp + 1 ..], 10) catch return error.ZixUrlPortInvalid)
    else
        80;

    if (host.len == 0) return error.ZixUrlHostMissing;

    return HttpUrlParsed{ .host = host, .port = port, .path = path_str };
}

fn splitField(line: []const u8, name: []const u8) ?[]const u8 {
    const colon_pos = std.mem.indexOfScalar(u8, line, ':');
    if (colon_pos == null) {
        if (std.mem.eql(u8, line, name)) return "";
        return null;
    }
    const cp = colon_pos.?;
    if (!std.mem.eql(u8, line[0..cp], name)) return null;
    const value = line[cp + 1 ..];
    if (value.len > 0 and value[0] == ' ') return value[1..];
    return value;
}

/// Close fd: the ntdll shim on Windows, the libc close elsewhere.
fn closeFD(fd: std.posix.fd_t) void {
    if (comptime builtin.os.tag == .windows) {
        win_io.close(fd);
        return;
    }

    _ = std.posix.system.close(fd);
}

/// Read some bytes from fd: the ntdll shim on Windows, std.posix.read elsewhere.
fn readOnceFD(fd: std.posix.fd_t, buf: []u8) !usize {
    if (comptime builtin.os.tag == .windows) return win_io.readOnce(fd, buf);

    return std.posix.read(fd, buf);
}

fn writeAllFD(fd: std.posix.fd_t, data: []const u8) !void {
    if (comptime builtin.os.tag == .windows) return win_io.writeAll(fd, data) catch error.BrokenPipe;

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

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http sse client: splitField data line" {
    const value = splitField("data: hello", "data");
    try std.testing.expectEqualStrings("hello", value.?);
}

test "zix http sse client: splitField event line" {
    const value = splitField("event: update", "event");
    try std.testing.expectEqualStrings("update", value.?);
}

test "zix http sse client: splitField retry line" {
    const value = splitField("retry: 3000", "retry");
    try std.testing.expectEqualStrings("3000", value.?);
}

test "zix http sse client: splitField no colon, bare field name" {
    const value = splitField("data", "data");
    try std.testing.expectEqualStrings("", value.?);
}

test "zix http sse client: splitField name mismatch returns null" {
    const value = splitField("event: update", "data");
    try std.testing.expectEqual(null, value);
}

test "zix http sse client: splitField no leading space preserved" {
    const value = splitField("data:noSpace", "data");
    try std.testing.expectEqualStrings("noSpace", value.?);
}

test "zix http sse client: parseHttpUrl basic" {
    const parsed = try parseHttpUrl("http://127.0.0.1:9010/events");
    try std.testing.expectEqualStrings("127.0.0.1", parsed.host);
    try std.testing.expectEqual(@as(u16, 9010), parsed.port);
    try std.testing.expectEqualStrings("/events", parsed.path);
}

test "zix http sse client: parseHttpUrl default port 80" {
    const parsed = try parseHttpUrl("http://example.com/events");
    try std.testing.expectEqual(@as(u16, 80), parsed.port);
}

test "zix http sse client: parseHttpUrl https returns TlsNotSupported" {
    try std.testing.expectError(error.ZixTlsNotSupported, parseHttpUrl("https://example.com/events"));
}

test "zix http sse client: a server that never answers yields ResponseTimeout" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Never accepted on purpose. The kernel completes the handshake into the backlog, so the client
    // connects and sends fine and then waits on a head that never comes.
    const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 9079);
    var silent = try addr.listen(io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 8, .reuse_address = true });
    defer silent.deinit(io);

    const client = SseClient.init(.{
        .io = io,
        .connect_timeout_ms = 3000,
        .response_timeout_ms = 150,
    });

    try std.testing.expectError(error.ZixResponseTimeout, client.open("http://127.0.0.1:9079/events"));
}

test "zix http sse client: a stream that goes quiet yields ReadTimeout, not a clean close" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 9080);
    var listener = try addr.listen(io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 8, .reuse_address = true });
    defer listener.deinit(io);

    // Sends a valid event-stream head and then no events at all. Held open until released, because
    // closing would be the clean end of stream this test is trying NOT to produce.
    const Quiet = struct {
        fn serve(listen_srv: *std.Io.net.Server, srv_io: std.Io, release: *std.atomic.Value(bool)) void {
            const stream = listen_srv.accept(srv_io) catch return;
            defer stream.close(srv_io);

            var scratch: [1024]u8 = undefined;
            var reader = stream.reader(srv_io, &scratch);
            while (reader.interface.takeDelimiterInclusive('\n') catch null) |line| {
                if (line.len <= 2) break;
            }

            var sink: [256]u8 = undefined;
            var writer = stream.writer(srv_io, &sink);
            writer.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n") catch return;
            writer.interface.flush() catch return;

            var rounds: usize = 0;
            while (!release.load(.acquire) and rounds < 5000) : (rounds += 1) {
                std.Io.sleep(srv_io, std.Io.Duration.fromMilliseconds(1), .awake) catch break;
            }
        }
    };

    var release: std.atomic.Value(bool) = .init(false);
    const serve_thread = try std.Thread.spawn(.{}, Quiet.serve, .{ &listener, io, &release });
    defer serve_thread.join();

    const client = SseClient.init(.{
        .io = io,
        .connect_timeout_ms = 3000,
        .response_timeout_ms = 3000,
        .read_timeout_ms = 150,
    });

    var stream = client.open("http://127.0.0.1:9080/events") catch |err| {
        release.store(true, .release);
        return err;
    };
    defer stream.deinit();

    var buf: [1024]u8 = undefined;
    const outcome = stream.next(&buf);
    release.store(true, .release);

    try std.testing.expectError(error.ZixReadTimeout, outcome);
}
