//! The in-process endpoint: an in-process HTTP server standing in for the exporter,
//! the remote-write receiver and the query API at once.
//!
//! Note:
//! - Binds port 0 and reports the port the kernel picked, so several servers can
//!   run at once and nothing collides with a fixed test port.
//! - One thread per connection, and one request per connection: the driver
//!   opens a fresh connection per call, so keep-alive would be answering a
//!   question nobody asks.
//! - Every request is recorded, which is how a suite checks what the driver
//!   actually sent: the target it built, the encoding it declared, the bytes
//!   it posted.
//! - Stop is deterministic: the flag goes up, a throwaway self-connect wakes
//!   the parked accept, then every thread is joined.
//!
//! Usage:
//! ```zig
//! const server = try Server.start(allocator, io, .{});
//! defer server.stop();
//!
//! const config = prometheuz.ScrapeConfig{ .ip = inproc.IP, .port = server.port };
//! ```

const std = @import("std");

pub const responses = @import("responses.zig");

/// Loopback only: the server never wants to be reachable off the machine.
pub const IP = "127.0.0.1";

/// Largest request the server accepts, headers and body together. A remote
/// write of a few hundred samples is well inside this.
const MAX_REQUEST = 1024 * 1024;

const READ_BUF_SIZE = 16 * 1024;
const WRITE_BUF_SIZE = 16 * 1024;

pub const Routes = responses.Routes;
pub const Reply = responses.Reply;
pub const Recorded = responses.Recorded;

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    routes: responses.Routes,
    listener: std.Io.net.Server,
    /// The port the kernel assigned, what a suite points its config at.
    port: u16,

    recorded: std.ArrayList(responses.Recorded),
    recorded_arena: std.heap.ArenaAllocator,
    recorded_lock: std.atomic.Value(bool),

    stopping: std.atomic.Value(bool),
    accept_thread: ?std.Thread,
    handlers: std.ArrayList(std.Thread),
    handlers_lock: std.atomic.Value(bool),

    const Self = @This();

    /// Bind, start accepting, and return once the port is known.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (owns the server and its recordings)
    /// io - std.Io (must outlive the server)
    /// routes - responses.Routes (what each path answers)
    ///
    /// Return:
    /// - *Server, stop it to release the port and every thread
    pub fn start(allocator: std.mem.Allocator, io: std.Io, routes: responses.Routes) !*Self {
        const addr = try std.Io.net.IpAddress.resolve(io, IP, 0);
        const listener = try addr.listen(io, .{ .mode = .stream, .reuse_address = true });

        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .io = io,
            .routes = routes,
            .listener = listener,
            .port = listener.socket.address.getPort(),
            .recorded = .empty,
            .recorded_arena = std.heap.ArenaAllocator.init(allocator),
            .recorded_lock = .init(false),
            .stopping = .init(false),
            .accept_thread = null,
            .handlers = .empty,
            .handlers_lock = .init(false),
        };

        self.accept_thread = try std.Thread.spawn(.{}, acceptLoop, .{self});

        return self;
    }

    /// Stop accepting, drop every connection, release everything.
    pub fn stop(self: *Self) void {
        self.stopping.store(true, .release);
        self.wakeAccept();

        if (self.accept_thread) |thread| thread.join();

        self.acquireHandlers();
        const pending = self.handlers.toOwnedSlice(self.allocator) catch &.{};
        self.releaseHandlers();

        for (pending) |thread| thread.join();
        self.allocator.free(pending);

        self.listener.deinit(self.io);
        self.recorded.deinit(self.allocator);
        self.recorded_arena.deinit();

        const allocator = self.allocator;
        allocator.destroy(self);
    }

    /// How many requests the server has served.
    pub fn requestCount(self: *Self) usize {
        self.acquireRecorded();
        defer self.releaseRecorded();

        return self.recorded.items.len;
    }

    /// The request at `index`, or null when fewer have arrived.
    ///
    /// Note:
    /// - The slices live as long as the server, so a suite may hold them
    ///   until it stops it.
    pub fn request(self: *Self, index: usize) ?responses.Recorded {
        self.acquireRecorded();
        defer self.releaseRecorded();

        if (index >= self.recorded.items.len) return null;

        return self.recorded.items[index];
    }

    /// The most recent request, or null when none have arrived.
    pub fn lastRequest(self: *Self) ?responses.Recorded {
        const count = self.requestCount();
        if (count == 0) return null;

        return self.request(count - 1);
    }

    // --------------------------------------------------------- //

    fn acquireRecorded(self: *Self) void {
        while (self.recorded_lock.cmpxchgWeak(false, true, .acq_rel, .acquire) != null) std.atomic.spinLoopHint();
    }

    fn releaseRecorded(self: *Self) void {
        self.recorded_lock.store(false, .release);
    }

    fn acquireHandlers(self: *Self) void {
        while (self.handlers_lock.cmpxchgWeak(false, true, .acq_rel, .acquire) != null) std.atomic.spinLoopHint();
    }

    fn releaseHandlers(self: *Self) void {
        self.handlers_lock.store(false, .release);
    }

    /// A throwaway connection so the parked accept returns and sees the flag.
    fn wakeAccept(self: *Self) void {
        var addr = std.Io.net.IpAddress.resolve(self.io, IP, self.port) catch return;
        const stream = addr.connect(self.io, .{ .mode = .stream }) catch return;
        stream.close(self.io);
    }

    fn acceptLoop(self: *Self) void {
        while (true) {
            const stream = self.listener.accept(self.io) catch return;
            if (self.stopping.load(.acquire)) {
                stream.close(self.io);

                return;
            }

            const thread = std.Thread.spawn(.{}, handleConnection, .{ self, stream }) catch {
                stream.close(self.io);

                continue;
            };

            self.acquireHandlers();
            self.handlers.append(self.allocator, thread) catch thread.detach();
            self.releaseHandlers();
        }
    }

    fn handleConnection(self: *Self, stream: std.Io.net.Stream) void {
        defer stream.close(self.io);

        var read_buf: [READ_BUF_SIZE]u8 = undefined;
        var write_buf: [WRITE_BUF_SIZE]u8 = undefined;
        var reader = stream.reader(self.io, &read_buf);
        var writer = stream.writer(self.io, &write_buf);

        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();

        const parsed = readRequest(&reader.interface, arena.allocator()) catch return;
        self.record(parsed);

        const reply = self.routes.pick(parsed.target);
        writeReply(&writer.interface, reply) catch return;
    }

    /// Copy the request into the recording arena, so it outlives the handler.
    fn record(self: *Self, parsed: responses.Recorded) void {
        self.acquireRecorded();
        defer self.releaseRecorded();

        const arena = self.recorded_arena.allocator();
        const copy = responses.Recorded{
            .method = arena.dupe(u8, parsed.method) catch return,
            .path = arena.dupe(u8, parsed.path) catch return,
            .target = arena.dupe(u8, parsed.target) catch return,
            .body = arena.dupe(u8, parsed.body) catch return,
            .content_encoding = arena.dupe(u8, parsed.content_encoding) catch return,
        };

        self.recorded.append(self.allocator, copy) catch {};
    }
};

// --------------------------------------------------------- //

const RequestError = error{
    PrometheuzConnectionClosed,
    PrometheuzMalformedRequest,
    PrometheuzRequestTooLarge,
    OutOfMemory,
};

/// Read one request: the line, the headers, then a Content-Length body.
fn readRequest(reader: *std.Io.Reader, arena: std.mem.Allocator) RequestError!responses.Recorded {
    const request_line = try readLine(reader, arena);

    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return error.PrometheuzMalformedRequest;
    const target = parts.next() orelse return error.PrometheuzMalformedRequest;

    var content_length: usize = 0;
    var content_encoding: []const u8 = "";

    while (true) {
        const header = try readLine(reader, arena);
        if (header.len == 0) break;

        const colon = std.mem.indexOfScalar(u8, header, ':') orelse continue;
        const name = std.mem.trim(u8, header[0..colon], " ");
        const value = std.mem.trim(u8, header[colon + 1 ..], " ");

        if (std.ascii.eqlIgnoreCase(name, "content-length")) {
            content_length = std.fmt.parseInt(usize, value, 10) catch return error.PrometheuzMalformedRequest;
            if (content_length > MAX_REQUEST) return error.PrometheuzRequestTooLarge;
        }
        if (std.ascii.eqlIgnoreCase(name, "content-encoding")) content_encoding = value;
    }

    const body = try arena.alloc(u8, content_length);
    if (content_length > 0) reader.readSliceAll(body) catch return error.PrometheuzConnectionClosed;

    return .{
        .method = method,
        .path = responses.pathOf(target),
        .target = target,
        .body = body,
        .content_encoding = content_encoding,
    };
}

/// One CRLF-terminated line, the terminator stripped.
fn readLine(reader: *std.Io.Reader, arena: std.mem.Allocator) RequestError![]const u8 {
    const raw = reader.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.EndOfStream, error.ReadFailed => return error.PrometheuzConnectionClosed,
        error.StreamTooLong => return error.PrometheuzRequestTooLarge,
    };

    var line = raw[0 .. raw.len - 1];
    if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];

    // the reader buffer moves on, so the line has to be copied out
    return arena.dupe(u8, line);
}

fn writeReply(writer: *std.Io.Writer, reply: responses.Reply) !void {
    try writer.print("HTTP/1.1 {d} {s}\r\n", .{ reply.status, reasonPhrase(reply.status) });
    if (reply.content_type.len > 0) try writer.print("Content-Type: {s}\r\n", .{reply.content_type});

    if (reply.close_without_length) {
        try writer.writeAll("Connection: close\r\n\r\n");
        try writer.writeAll(reply.body);
        try writer.flush();

        return;
    }

    try writer.print("Content-Length: {d}\r\n\r\n", .{reply.body.len});
    try writer.writeAll(reply.body);
    try writer.flush();
}

fn reasonPhrase(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        else => "Unknown",
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

const Harness = struct {
    threaded: std.Io.Threaded,
    server: *Server,

    fn start(self: *Harness, routes: responses.Routes) !void {
        self.threaded = std.Io.Threaded.init(std.heap.smp_allocator, .{});
        errdefer self.threaded.deinit();

        self.server = try Server.start(std.heap.smp_allocator, self.threaded.io(), routes);
    }

    fn stop(self: *Harness) void {
        self.server.stop();
        self.threaded.deinit();
    }

    /// Send a raw request and return the whole answer.
    fn roundTrip(self: *Harness, request_text: []const u8, out: []u8) ![]const u8 {
        const io = self.threaded.io();
        var addr = try std.Io.net.IpAddress.resolve(io, IP, self.server.port);
        const stream = try addr.connect(io, .{ .mode = .stream });
        defer stream.close(io);

        var write_buf: [4096]u8 = undefined;
        var writer = stream.writer(io, &write_buf);
        try writer.interface.writeAll(request_text);
        try writer.interface.flush();

        var read_buf: [8192]u8 = undefined;
        var reader = stream.reader(io, &read_buf);

        var filled: usize = 0;
        while (filled < out.len) {
            const got = reader.interface.readSliceShort(out[filled..]) catch break;
            if (got == 0) break;

            filled += got;
        }

        return out[0..filled];
    }
};

test "prometheuz inproc: server reports the port the kernel assigned" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    try testing.expect(harness.server.port != 0);
}

test "prometheuz inproc: server serves the metrics body on a get" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    var out: [8192]u8 = undefined;
    const answer = try harness.roundTrip("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", &out);

    try testing.expect(std.mem.startsWith(u8, answer, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.indexOf(u8, answer, "zix_requests_total") != null);
}

test "prometheuz inproc: server answers an unknown path with 404" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    var out: [4096]u8 = undefined;
    const answer = try harness.roundTrip("GET /nope HTTP/1.1\r\nHost: x\r\n\r\n", &out);

    try testing.expect(std.mem.startsWith(u8, answer, "HTTP/1.1 404 Not Found\r\n"));
}

test "prometheuz inproc: server records the target a request carried" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    var out: [8192]u8 = undefined;
    _ = try harness.roundTrip("GET /api/v1/query?query=up HTTP/1.1\r\nHost: x\r\n\r\n", &out);

    const recorded = harness.server.lastRequest().?;
    try testing.expectEqualStrings("GET", recorded.method);
    try testing.expectEqualStrings("/api/v1/query", recorded.path);
    try testing.expectEqualStrings("/api/v1/query?query=up", recorded.target);
}

test "prometheuz inproc: server records a posted body and its encoding" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    var out: [4096]u8 = undefined;
    _ = try harness.roundTrip(
        "POST /api/v1/write HTTP/1.1\r\nHost: x\r\nContent-Encoding: snappy\r\nContent-Length: 5\r\n\r\nhello",
        &out,
    );

    const recorded = harness.server.lastRequest().?;
    try testing.expectEqualStrings("POST", recorded.method);
    try testing.expectEqualStrings("snappy", recorded.content_encoding);
    try testing.expectEqualStrings("hello", recorded.body);
}

test "prometheuz inproc: server counts every request it served" {
    var harness: Harness = undefined;
    try harness.start(.{});
    defer harness.stop();

    var out: [8192]u8 = undefined;
    _ = try harness.roundTrip("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", &out);
    _ = try harness.roundTrip("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", &out);

    try testing.expectEqual(@as(usize, 2), harness.server.requestCount());
    try testing.expectEqual(@as(?responses.Recorded, null), harness.server.request(2));
}

test "prometheuz inproc: server can answer without a content length" {
    var harness: Harness = undefined;
    try harness.start(.{ .metrics = .{ .body = "bare-body", .close_without_length = true } });
    defer harness.stop();

    var out: [4096]u8 = undefined;
    const answer = try harness.roundTrip("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n", &out);

    try testing.expect(std.mem.indexOf(u8, answer, "Content-Length") == null);
    try testing.expect(std.mem.endsWith(u8, answer, "bare-body"));
}

test "prometheuz inproc: server serves several servers at once on distinct ports" {
    var first: Harness = undefined;
    try first.start(.{});
    defer first.stop();

    var second: Harness = undefined;
    try second.start(.{});
    defer second.stop();

    try testing.expect(first.server.port != second.server.port);
}
