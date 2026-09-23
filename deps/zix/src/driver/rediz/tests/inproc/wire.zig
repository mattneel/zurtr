//! RESP framing for the in-process server side: inbound command arrays in, replies out.
//!
//! Note:
//! - The driver always sends a command as a RESP array of bulk strings, so the
//!   inline command form a real server also accepts is not implemented here.
//! - RESP2 and RESP3 disagree on null, map, boolean and double. ReplyWriter
//!   carries the negotiated version and picks the matching form.

const std = @import("std");

/// Longest protocol line the server accepts, matching the driver's own bound.
pub const MAX_LINE_LEN = 4096;

/// Largest bulk argument the server accepts, generous for a test keyspace.
pub const MAX_BULK_LEN = 1024 * 1024;

/// Most arguments one command may carry.
pub const MAX_ARGS = 512;

pub const ReadError = error{
    RedizConnectionClosed,
    RedizProtocolViolation,
    OutOfMemory,
};

/// One command off the wire, as an argv of bulk strings.
///
/// Note:
/// - Generic over the source so the same framing serves a cleartext socket and
///   a TLS session, which is the same shape the driver uses on its own side.
///   The source must provide `readLine(buf) ![]const u8` (one line, CRLF
///   stripped) and `readExact(buf) !void`.
/// - Every slice is allocated in arena, so the caller may keep them after the
///   source buffer moves on.
///
/// Param:
/// source - anytype (the connection byte source, see transport.zig)
/// arena - std.mem.Allocator (owns the returned argv and every argument)
///
/// Return:
/// - []const []const u8 with at least one element
/// - error.RedizConnectionClosed when the peer hung up between commands
/// - error.RedizProtocolViolation on a malformed frame
pub fn readCommand(source: anytype, arena: std.mem.Allocator) ReadError![]const []const u8 {
    var line_buf: [MAX_LINE_LEN]u8 = undefined;
    const header = try source.readLine(&line_buf);
    if (header.len < 2 or header[0] != '*') return error.RedizProtocolViolation;

    const count = std.fmt.parseInt(usize, header[1..], 10) catch return error.RedizProtocolViolation;
    if (count == 0 or count > MAX_ARGS) return error.RedizProtocolViolation;

    const argv = try arena.alloc([]const u8, count);
    for (argv) |*arg| arg.* = try readBulk(source, arena);

    return argv;
}

fn readBulk(source: anytype, arena: std.mem.Allocator) ReadError![]const u8 {
    var line_buf: [MAX_LINE_LEN]u8 = undefined;
    const header = try source.readLine(&line_buf);
    if (header.len < 2 or header[0] != '$') return error.RedizProtocolViolation;

    const len = std.fmt.parseInt(usize, header[1..], 10) catch return error.RedizProtocolViolation;
    if (len > MAX_BULK_LEN) return error.RedizProtocolViolation;

    const body = try arena.alloc(u8, len);
    try source.readExact(body);

    var crlf: [2]u8 = undefined;
    try source.readExact(&crlf);
    if (crlf[0] != '\r' or crlf[1] != '\n') return error.RedizProtocolViolation;

    return body;
}

// --------------------------------------------------------- //

pub const WriteError = error{WriteFailed};

/// Reply emitter bound to one connection's negotiated protocol version.
///
/// Note:
/// - Writes into a buffer, not to the socket. The transport sends what
///   accumulated, so one command's reply leaves in one write and the TLS path
///   needs no special case here.
///
/// Usage:
/// ```zig
/// var buffer = std.Io.Writer.fixed(&reply_buf);
/// var out = ReplyWriter{ .writer = &buffer, .resp3 = true };
/// try out.simple("OK");
/// try transport.send(buffer.buffered());
/// ```
pub const ReplyWriter = struct {
    writer: *std.Io.Writer,
    resp3: bool,

    const Self = @This();

    /// Simple status string, `+OK`.
    pub fn simple(self: *Self, text: []const u8) WriteError!void {
        self.writer.print("+{s}\r\n", .{text}) catch return error.WriteFailed;
    }

    /// Error reply. The prefix is part of text, e.g. `WRONGTYPE Operation ...`.
    pub fn err(self: *Self, text: []const u8) WriteError!void {
        self.writer.print("-{s}\r\n", .{text}) catch return error.WriteFailed;
    }

    pub fn integer(self: *Self, value: i64) WriteError!void {
        self.writer.print(":{d}\r\n", .{value}) catch return error.WriteFailed;
    }

    pub fn bulk(self: *Self, body: []const u8) WriteError!void {
        self.writer.print("${d}\r\n", .{body.len}) catch return error.WriteFailed;
        self.writer.writeAll(body) catch return error.WriteFailed;
        self.writer.writeAll("\r\n") catch return error.WriteFailed;
    }

    /// Absent value: `_` on RESP3, the null bulk `$-1` on RESP2.
    pub fn nil(self: *Self) WriteError!void {
        const frame = if (self.resp3) "_\r\n" else "$-1\r\n";
        self.writer.writeAll(frame) catch return error.WriteFailed;
    }

    /// Boolean: `#t` on RESP3, an integer on RESP2 where booleans do not exist.
    pub fn boolean(self: *Self, value: bool) WriteError!void {
        if (!self.resp3) return self.integer(if (value) 1 else 0);

        self.writer.writeAll(if (value) "#t\r\n" else "#f\r\n") catch return error.WriteFailed;
    }

    /// Double: `,` on RESP3, a bulk string on RESP2.
    pub fn double(self: *Self, value: f64) WriteError!void {
        if (!self.resp3) {
            var buf: [64]u8 = undefined;
            const text = std.fmt.bufPrint(&buf, "{d}", .{value}) catch return error.WriteFailed;

            return self.bulk(text);
        }

        self.writer.print(",{d}\r\n", .{value}) catch return error.WriteFailed;
    }

    /// Array header, followed by `count` replies written by the caller.
    pub fn arrayHeader(self: *Self, count: usize) WriteError!void {
        self.writer.print("*{d}\r\n", .{count}) catch return error.WriteFailed;
    }

    /// Map header, followed by `count` key/value reply pairs written by the
    /// caller. RESP2 has no map type, so it degrades to a flat array of
    /// 2 * count elements, which is what a real server does.
    pub fn mapHeader(self: *Self, count: usize) WriteError!void {
        if (!self.resp3) return self.arrayHeader(count * 2);

        self.writer.print("%{d}\r\n", .{count}) catch return error.WriteFailed;
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// A source over a fixed byte slice, the same shape transport.zig provides for
/// a real connection.
const FixedSource = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn readLine(self: *FixedSource, buf: []u8) ReadError![]const u8 {
        const start = self.pos;
        while (self.pos < self.bytes.len) {
            if (self.bytes[self.pos] != '\n') {
                self.pos += 1;

                continue;
            }

            const line_end = self.pos;
            self.pos += 1;
            if (line_end == start or self.bytes[line_end - 1] != '\r') return error.RedizProtocolViolation;

            const body = self.bytes[start .. line_end - 1];
            if (body.len > buf.len) return error.RedizProtocolViolation;
            @memcpy(buf[0..body.len], body);

            return buf[0..body.len];
        }

        return error.RedizConnectionClosed;
    }

    fn readExact(self: *FixedSource, buf: []u8) ReadError!void {
        if (self.pos + buf.len > self.bytes.len) return error.RedizConnectionClosed;

        @memcpy(buf, self.bytes[self.pos..][0..buf.len]);
        self.pos += buf.len;
    }
};

fn sourceOver(bytes: []const u8) FixedSource {
    return .{ .bytes = bytes };
}

test "rediz inproc: wire readCommand parses an argv of bulk strings" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var reader = sourceOver("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n");
    const argv = try readCommand(&reader, arena.allocator());

    try testing.expectEqual(@as(usize, 3), argv.len);
    try testing.expectEqualStrings("SET", argv[0]);
    try testing.expectEqualStrings("key", argv[1]);
    try testing.expectEqualStrings("value", argv[2]);
}

test "rediz inproc: wire readCommand accepts an empty bulk argument" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var reader = sourceOver("*2\r\n$3\r\nSET\r\n$0\r\n\r\n");
    const argv = try readCommand(&reader, arena.allocator());

    try testing.expectEqual(@as(usize, 2), argv.len);
    try testing.expectEqualStrings("", argv[1]);
}

test "rediz inproc: wire readCommand reports a closed peer, not a violation" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var reader = sourceOver("");
    try testing.expectError(error.RedizConnectionClosed, readCommand(&reader, arena.allocator()));
}

test "rediz inproc: wire readCommand rejects a non-array frame" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var reader = sourceOver("+PING\r\n");
    try testing.expectError(error.RedizProtocolViolation, readCommand(&reader, arena.allocator()));
}

test "rediz inproc: wire readCommand rejects a truncated bulk body" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var reader = sourceOver("*1\r\n$10\r\nshort\r\n");
    try testing.expectError(error.RedizConnectionClosed, readCommand(&reader, arena.allocator()));
}

test "rediz inproc: wire nil and boolean differ between resp2 and resp3" {
    var buf: [64]u8 = undefined;

    var resp3_writer = std.Io.Writer.fixed(&buf);
    var resp3 = ReplyWriter{ .writer = &resp3_writer, .resp3 = true };
    try resp3.nil();
    try resp3.boolean(true);
    try testing.expectEqualStrings("_\r\n#t\r\n", resp3_writer.buffered());

    var resp2_writer = std.Io.Writer.fixed(&buf);
    var resp2 = ReplyWriter{ .writer = &resp2_writer, .resp3 = false };
    try resp2.nil();
    try resp2.boolean(true);
    try testing.expectEqualStrings("$-1\r\n:1\r\n", resp2_writer.buffered());
}

test "rediz inproc: wire map degrades to a flat array on resp2" {
    var buf: [64]u8 = undefined;

    var resp3_writer = std.Io.Writer.fixed(&buf);
    var resp3 = ReplyWriter{ .writer = &resp3_writer, .resp3 = true };
    try resp3.mapHeader(2);
    try testing.expectEqualStrings("%2\r\n", resp3_writer.buffered());

    var resp2_writer = std.Io.Writer.fixed(&buf);
    var resp2 = ReplyWriter{ .writer = &resp2_writer, .resp3 = false };
    try resp2.mapHeader(2);
    try testing.expectEqualStrings("*4\r\n", resp2_writer.buffered());
}

test "rediz inproc: wire emits bulk, integer and error frames" {
    var buf: [128]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buf);
    var out = ReplyWriter{ .writer = &writer, .resp3 = true };

    try out.bulk("hello");
    try out.integer(-7);
    try out.err("WRONGTYPE Operation against a key holding the wrong kind of value");

    try testing.expectEqualStrings(
        "$5\r\nhello\r\n" ++
            ":-7\r\n" ++
            "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n",
        writer.buffered(),
    );
}
