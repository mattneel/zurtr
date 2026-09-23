//! RESP codec: command encoding and reply decoding for RESP2 and RESP3.
//!
//! Note:
//! - Commands always encode as an array of bulk strings, the only frame a
//!   server accepts.
//! - decode() is transport-independent: it pulls bytes from any source that
//!   provides readLine (one protocol line, CRLF stripped) and readExact
//!   (a known-length bulk body plus its trailing CRLF).
//! - Aggregate replies allocate from the arena the caller passes in, so one
//!   reset frees a whole reply tree.

const std = @import("std");

/// Longest accepted protocol line (type marker + digits or a simple string).
pub const MAX_LINE_LEN = 4096;
/// Longest accepted bulk payload. The server-side protocol cap is larger,
/// this bounds driver memory per reply.
pub const MAX_BULK_LEN = 64 * 1024 * 1024;
/// Deepest accepted aggregate nesting, guards the recursive decoder.
pub const MAX_DEPTH = 32;

/// RESP3 verbatim string: a 3-char format tag ("txt", "mkd") plus the text.
pub const Verbatim = struct {
    format: [3]u8,
    data: []const u8,
};

/// One RESP3 map pair.
pub const MapEntry = struct {
    key: Reply,
    value: Reply,
};

/// One decoded reply. Slices borrow the decode arena: valid until that
/// arena resets.
pub const Reply = union(enum) {
    simple: []const u8,
    err: []const u8,
    integer: i64,
    bulk: []const u8,
    array: []Reply,
    null,
    boolean: bool,
    double: f64,
    big_number: []const u8,
    bulk_err: []const u8,
    verbatim: Verbatim,
    map: []MapEntry,
    set: []Reply,
    push: []Reply,

    /// Whether this is the simple string "OK".
    pub fn isOk(self: Reply) bool {
        return switch (self) {
            .simple => |line| std.mem.eql(u8, line, "OK"),
            else => false,
        };
    }

    /// Whether this is an error reply (RESP2 err or RESP3 bulk_err).
    pub fn isErr(self: Reply) bool {
        return switch (self) {
            .err, .bulk_err => true,
            else => false,
        };
    }

    /// The raw error line when isErr(), null otherwise.
    pub fn errLine(self: Reply) ?[]const u8 {
        return switch (self) {
            .err => |line| line,
            .bulk_err => |line| line,
            else => null,
        };
    }
};

// --------------------------------------------------------- //

/// Encode one command as a RESP array of bulk strings.
///
/// Param:
/// out - *std.ArrayList(u8) (appended, caller batches and flushes)
/// args - []const []const u8 (command name first, then its arguments)
pub fn encodeCommand(allocator: std.mem.Allocator, out: *std.ArrayList(u8), args: []const []const u8) !void {
    if (args.len == 0) return error.RedizEmptyCommand;

    var header_buf: [32]u8 = undefined;
    const header = try std.fmt.bufPrint(&header_buf, "*{d}\r\n", .{args.len});
    try out.appendSlice(allocator, header);

    for (args) |arg| {
        const arg_header = try std.fmt.bufPrint(&header_buf, "${d}\r\n", .{arg.len});
        try out.appendSlice(allocator, arg_header);
        try out.appendSlice(allocator, arg);
        try out.appendSlice(allocator, "\r\n");
    }
}

// --------------------------------------------------------- //

/// Decode one full reply from a byte source.
///
/// Note:
/// - The source must provide `readLine(buf: []u8) ![]const u8` (one line,
///   CRLF stripped, error.RedizLineTooLong when buf overflows) and
///   `readExact(buf: []u8) !void`.
///
/// Param:
/// arena - std.mem.Allocator (owns every slice and aggregate in the reply)
///
/// Return:
/// - Reply on success (error replies decode as .err / .bulk_err, they are
///   data here, the connection maps them)
/// - error.RedizProtocolViolation on an unknown marker or malformed frame
pub fn decode(arena: std.mem.Allocator, source: anytype) anyerror!Reply {
    return decodeDepth(arena, source, 0);
}

fn decodeDepth(arena: std.mem.Allocator, source: anytype, depth: usize) anyerror!Reply {
    if (depth >= MAX_DEPTH) return error.RedizProtocolViolation;

    var line_buf: [MAX_LINE_LEN]u8 = undefined;
    const line = try source.readLine(&line_buf);
    if (line.len == 0) return error.RedizProtocolViolation;

    const marker = line[0];
    const rest = line[1..];

    switch (marker) {
        '+' => return .{ .simple = try arena.dupe(u8, rest) },
        '-' => return .{ .err = try arena.dupe(u8, rest) },
        ':' => return .{ .integer = try parseInteger(rest) },
        '#' => {
            if (rest.len != 1) return error.RedizProtocolViolation;

            return switch (rest[0]) {
                't' => .{ .boolean = true },
                'f' => .{ .boolean = false },
                else => error.RedizProtocolViolation,
            };
        },
        ',' => return .{ .double = try parseDouble(rest) },
        '(' => return .{ .big_number = try arena.dupe(u8, rest) },
        '_' => {
            if (rest.len != 0) return error.RedizProtocolViolation;

            return .null;
        },
        '$' => {
            const body = try readBulkBody(arena, source, rest) orelse return .null;

            return .{ .bulk = body };
        },
        '!' => {
            const body = try readBulkBody(arena, source, rest) orelse return error.RedizProtocolViolation;

            return .{ .bulk_err = body };
        },
        '=' => {
            const body = try readBulkBody(arena, source, rest) orelse return error.RedizProtocolViolation;
            if (body.len < 4 or body[3] != ':') return error.RedizProtocolViolation;

            return .{ .verbatim = .{
                .format = body[0..3].*,
                .data = body[4..],
            } };
        },
        '*', '~', '>' => {
            const count = try parseAggregateLen(rest) orelse {
                if (marker != '*') return error.RedizProtocolViolation;

                return .null;
            };

            const items = try arena.alloc(Reply, count);
            for (items) |*item| item.* = try decodeDepth(arena, source, depth + 1);

            return switch (marker) {
                '*' => .{ .array = items },
                '~' => .{ .set = items },
                else => .{ .push = items },
            };
        },
        '%' => {
            const count = try parseAggregateLen(rest) orelse return error.RedizProtocolViolation;

            const entries = try arena.alloc(MapEntry, count);
            for (entries) |*entry| {
                entry.key = try decodeDepth(arena, source, depth + 1);
                entry.value = try decodeDepth(arena, source, depth + 1);
            }

            return .{ .map = entries };
        },
        else => return error.RedizProtocolViolation,
    }
}

/// Bulk body for $, ! and =: reads `len` bytes plus the trailing CRLF.
///
/// Return:
/// - []u8 arena copy of the body
/// - null on the RESP2 null bulk ($-1)
fn readBulkBody(arena: std.mem.Allocator, source: anytype, len_text: []const u8) !?[]u8 {
    const len = try parseAggregateLen(len_text) orelse return null;
    if (len > MAX_BULK_LEN) return error.RedizProtocolViolation;

    const body = try arena.alloc(u8, len);
    try source.readExact(body);

    var crlf: [2]u8 = undefined;
    try source.readExact(&crlf);
    if (crlf[0] != '\r' or crlf[1] != '\n') return error.RedizProtocolViolation;

    return body;
}

fn parseInteger(text: []const u8) !i64 {
    return std.fmt.parseInt(i64, text, 10) catch error.RedizProtocolViolation;
}

/// Aggregate and bulk length field: a non-negative count, or -1 for null.
fn parseAggregateLen(text: []const u8) !?usize {
    if (std.mem.eql(u8, text, "-1")) return null;

    const value = std.fmt.parseInt(i64, text, 10) catch return error.RedizProtocolViolation;
    if (value < 0) return error.RedizProtocolViolation;

    return @intCast(value);
}

fn parseDouble(text: []const u8) !f64 {
    if (std.mem.eql(u8, text, "inf")) return std.math.inf(f64);
    if (std.mem.eql(u8, text, "-inf")) return -std.math.inf(f64);
    if (std.mem.eql(u8, text, "nan")) return std.math.nan(f64);

    return std.fmt.parseFloat(f64, text) catch error.RedizProtocolViolation;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// Test source over a fixed byte slice.
const FixedSource = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn readLine(self: *FixedSource, buf: []u8) ![]const u8 {
        const start = self.pos;
        while (self.pos < self.bytes.len) : (self.pos += 1) {
            if (self.bytes[self.pos] == '\n') {
                if (self.pos == start or self.bytes[self.pos - 1] != '\r') return error.RedizProtocolViolation;

                const line = self.bytes[start .. self.pos - 1];
                if (line.len > buf.len) return error.RedizLineTooLong;
                self.pos += 1;

                return line;
            }
        }

        return error.RedizConnectionClosed;
    }

    fn readExact(self: *FixedSource, buf: []u8) !void {
        if (self.pos + buf.len > self.bytes.len) return error.RedizConnectionClosed;

        @memcpy(buf, self.bytes[self.pos..][0..buf.len]);
        self.pos += buf.len;
    }
};

fn decodeFixed(arena: std.mem.Allocator, bytes: []const u8) !Reply {
    var source = FixedSource{ .bytes = bytes };

    return decode(arena, &source);
}

test "rediz protocol: encode command frames array of bulk strings" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try encodeCommand(testing.allocator, &out, &.{ "SET", "key", "value" });
    try testing.expectEqualStrings("*3\r\n$3\r\nSET\r\n$3\r\nkey\r\n$5\r\nvalue\r\n", out.items);
}

test "rediz protocol: encode command rejects empty" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try testing.expectError(error.RedizEmptyCommand, encodeCommand(testing.allocator, &out, &.{}));
}

test "rediz protocol: decode simple string, error and integer" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const ok = try decodeFixed(allocator, "+OK\r\n");
    try testing.expect(ok.isOk());
    try testing.expectEqualStrings("OK", ok.simple);

    const err_reply = try decodeFixed(allocator, "-ERR unknown command\r\n");
    try testing.expect(err_reply.isErr());
    try testing.expectEqualStrings("ERR unknown command", err_reply.errLine().?);

    const number = try decodeFixed(allocator, ":42\r\n");
    try testing.expectEqual(@as(i64, 42), number.integer);

    const negative = try decodeFixed(allocator, ":-7\r\n");
    try testing.expectEqual(@as(i64, -7), negative.integer);
}

test "rediz protocol: decode bulk string and null bulk" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const bulk = try decodeFixed(allocator, "$5\r\nhello\r\n");
    try testing.expectEqualStrings("hello", bulk.bulk);

    const empty = try decodeFixed(allocator, "$0\r\n\r\n");
    try testing.expectEqualStrings("", empty.bulk);

    const null_bulk = try decodeFixed(allocator, "$-1\r\n");
    try testing.expectEqual(Reply.null, null_bulk);
}

test "rediz protocol: decode array, null array and nesting" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const list = try decodeFixed(allocator, "*3\r\n$1\r\na\r\n:2\r\n*1\r\n+deep\r\n");
    try testing.expectEqual(@as(usize, 3), list.array.len);
    try testing.expectEqualStrings("a", list.array[0].bulk);
    try testing.expectEqual(@as(i64, 2), list.array[1].integer);
    try testing.expectEqualStrings("deep", list.array[2].array[0].simple);

    const null_array = try decodeFixed(allocator, "*-1\r\n");
    try testing.expectEqual(Reply.null, null_array);
}

test "rediz protocol: decode resp3 null boolean double and big number" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try testing.expectEqual(Reply.null, try decodeFixed(allocator, "_\r\n"));
    try testing.expectEqual(true, (try decodeFixed(allocator, "#t\r\n")).boolean);
    try testing.expectEqual(false, (try decodeFixed(allocator, "#f\r\n")).boolean);

    const pi = try decodeFixed(allocator, ",3.14\r\n");
    try testing.expectApproxEqAbs(@as(f64, 3.14), pi.double, 0.0001);

    const inf = try decodeFixed(allocator, ",inf\r\n");
    try testing.expect(std.math.isInf(inf.double));

    const big = try decodeFixed(allocator, "(3492890328409238509324850943850943825024385\r\n");
    try testing.expectEqualStrings("3492890328409238509324850943850943825024385", big.big_number);
}

test "rediz protocol: decode resp3 map set push verbatim and bulk error" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const map = try decodeFixed(allocator, "%2\r\n+first\r\n:1\r\n+second\r\n:2\r\n");
    try testing.expectEqual(@as(usize, 2), map.map.len);
    try testing.expectEqualStrings("first", map.map[0].key.simple);
    try testing.expectEqual(@as(i64, 2), map.map[1].value.integer);

    const set = try decodeFixed(allocator, "~2\r\n+a\r\n+b\r\n");
    try testing.expectEqual(@as(usize, 2), set.set.len);

    const push = try decodeFixed(allocator, ">2\r\n+pubsub\r\n+message\r\n");
    try testing.expectEqual(@as(usize, 2), push.push.len);
    try testing.expectEqualStrings("pubsub", push.push[0].simple);

    const verbatim = try decodeFixed(allocator, "=15\r\ntxt:Some string\r\n");
    try testing.expectEqualStrings("txt", &verbatim.verbatim.format);
    try testing.expectEqualStrings("Some string", verbatim.verbatim.data);

    const bulk_err = try decodeFixed(allocator, "!21\r\nSYNTAX invalid syntax\r\n");
    try testing.expect(bulk_err.isErr());
    try testing.expectEqualStrings("SYNTAX invalid syntax", bulk_err.errLine().?);
}

test "rediz protocol: decode rejects malformed frames" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try testing.expectError(error.RedizProtocolViolation, decodeFixed(allocator, "?\r\n"));
    try testing.expectError(error.RedizProtocolViolation, decodeFixed(allocator, ":abc\r\n"));
    try testing.expectError(error.RedizProtocolViolation, decodeFixed(allocator, "#x\r\n"));
    try testing.expectError(error.RedizProtocolViolation, decodeFixed(allocator, "$5\r\nhelloXX"));
    try testing.expectError(error.RedizProtocolViolation, decodeFixed(allocator, "*-2\r\n"));
    try testing.expectError(error.RedizConnectionClosed, decodeFixed(allocator, "*2\r\n+only-one\r\n"));
}

test "rediz protocol: decode guards nesting depth" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(testing.allocator);
    var level: usize = 0;
    while (level < MAX_DEPTH + 1) : (level += 1) {
        try bytes.appendSlice(testing.allocator, "*1\r\n");
    }
    try bytes.appendSlice(testing.allocator, ":1\r\n");

    try testing.expectError(error.RedizProtocolViolation, decodeFixed(allocator, bytes.items));
}
