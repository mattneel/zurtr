//! What the driver sends, as the in-process backend reads it.
//!
//! Note:
//! - The mirror of src/protocol/frontend.zig, which builds these same
//!   messages. Only the ones the driver actually emits are decoded, an
//!   unrecognised tag is surfaced rather than guessed at.
//! - The startup packet is untagged and comes first, so it is read by its own
//!   entry point. Everything after it is tagged.
//! - Reading needs only `readExact` from the source, since every message is
//!   length prefixed. That is what lets the same parser serve cleartext and
//!   TLS connections.

const std = @import("std");

const message = @import("message.zig");

/// A single message may not exceed this. The driver's largest is a COPY data
/// chunk, well inside it.
pub const MAX_MESSAGE_LEN = 1024 * 1024;

pub const Error = error{
    PostgrezConnectionClosed,
    PostgrezMalformedMessage,
    PostgrezMessageTooLarge,
    OutOfMemory,
};

/// The first packet a client sends.
pub const Startup = union(enum) {
    /// The client is asking whether the server speaks TLS.
    ssl_request,
    cancel_request: CancelRequest,
    hello: Hello,
};

pub const CancelRequest = struct {
    pid: i32,
    key: []const u8,
};

pub const Hello = struct {
    protocol_code: i32,
    user: []const u8,
    database: []const u8,
    /// Every key/value pair as sent, so a test can assert on the ones the
    /// driver chose to include.
    parameters: []const Parameter,
};

pub const Parameter = struct {
    name: []const u8,
    value: []const u8,
};

pub const Parse = struct {
    statement_name: []const u8,
    sql: []const u8,
    param_oids: []const u32,
};

/// One bound parameter. The format matters: a four-byte text value and a
/// binary int4 are indistinguishable by length alone.
pub const BoundParameter = struct {
    /// null for a SQL NULL.
    value: ?[]const u8,
    binary: bool,
};

pub const Bind = struct {
    portal_name: []const u8,
    statement_name: []const u8,
    parameters: []const BoundParameter,
    /// Result formats the client asked for: text when empty or all zero.
    binary_results: bool,
};

/// Describe and Close share a shape: a kind ('S' statement, 'P' portal) and a name.
pub const Target = struct {
    kind: u8,
    name: []const u8,
};

pub const Execute = struct {
    portal_name: []const u8,
    max_rows: u32,
};

pub const Message = union(enum) {
    /// Tag 'p': a cleartext password, a SASLInitialResponse or a SASLResponse.
    /// Which one it is depends on where the handshake has got to, so the
    /// payload is handed over raw.
    password: []const u8,
    query: []const u8,
    parse: Parse,
    bind: Bind,
    describe: Target,
    close: Target,
    execute: Execute,
    sync,
    flush,
    terminate,
    copy_data: []const u8,
    copy_done,
    copy_fail: []const u8,
    unknown: u8,
};

/// Read the untagged first packet.
///
/// Param:
/// source - anytype (needs readExact(buf), see transport.zig)
/// arena - std.mem.Allocator (owns every slice in the result)
pub fn readStartup(source: anytype, arena: std.mem.Allocator) Error!Startup {
    var length_bytes: [4]u8 = undefined;
    source.readExact(&length_bytes) catch return error.PostgrezConnectionClosed;

    const total = std.mem.readInt(i32, &length_bytes, .big);
    if (total < 8 or total > MAX_MESSAGE_LEN) return error.PostgrezMessageTooLarge;

    const payload = try arena.alloc(u8, @as(usize, @intCast(total)) - 4);
    source.readExact(payload) catch return error.PostgrezConnectionClosed;

    var reader = message.Reader{ .buf = payload };
    const code = reader.int32() catch return error.PostgrezMalformedMessage;

    // an SSL request is exactly the code and nothing else
    if (code == 80877103) return .ssl_request;

    if (code == 80877102) {
        const pid = reader.int32() catch return error.PostgrezMalformedMessage;

        return .{ .cancel_request = .{ .pid = pid, .key = reader.rest() } };
    }

    var parameters: std.ArrayList(Parameter) = .empty;
    var user: []const u8 = "";
    var database: []const u8 = "";

    while (reader.remaining() > 1) {
        const name = reader.cstring() catch return error.PostgrezMalformedMessage;
        if (name.len == 0) break;

        const value = reader.cstring() catch return error.PostgrezMalformedMessage;
        try parameters.append(arena, .{ .name = name, .value = value });

        if (std.mem.eql(u8, name, "user")) user = value;
        if (std.mem.eql(u8, name, "database")) database = value;
    }

    return .{ .hello = .{
        .protocol_code = code,
        .user = user,
        .database = database,
        .parameters = try parameters.toOwnedSlice(arena),
    } };
}

/// Read one tagged message.
pub fn readMessage(source: anytype, arena: std.mem.Allocator) Error!Message {
    var header: [5]u8 = undefined;
    source.readExact(&header) catch return error.PostgrezConnectionClosed;

    const tag = header[0];
    const total = std.mem.readInt(i32, header[1..5], .big);
    if (total < 4 or total > MAX_MESSAGE_LEN) return error.PostgrezMessageTooLarge;

    const payload = try arena.alloc(u8, @as(usize, @intCast(total)) - 4);
    source.readExact(payload) catch return error.PostgrezConnectionClosed;

    return decode(tag, payload, arena);
}

/// Turn one tag and payload into a Message. Split out so it can be tested
/// without a socket.
pub fn decode(tag: u8, payload: []const u8, arena: std.mem.Allocator) Error!Message {
    var reader = message.Reader{ .buf = payload };

    return switch (tag) {
        'p' => .{ .password = payload },
        'Q' => .{ .query = reader.cstring() catch return error.PostgrezMalformedMessage },
        'P' => .{ .parse = try decodeParse(&reader, arena) },
        'B' => .{ .bind = try decodeBind(&reader, arena) },
        'D' => .{ .describe = try decodeTarget(&reader) },
        'C' => .{ .close = try decodeTarget(&reader) },
        'E' => .{ .execute = try decodeExecute(&reader) },
        'S' => .sync,
        'H' => .flush,
        'X' => .terminate,
        'd' => .{ .copy_data = payload },
        'c' => .copy_done,
        'f' => .{ .copy_fail = reader.cstring() catch return error.PostgrezMalformedMessage },
        else => .{ .unknown = tag },
    };
}

fn decodeParse(reader: *message.Reader, arena: std.mem.Allocator) Error!Parse {
    const statement_name = reader.cstring() catch return error.PostgrezMalformedMessage;
    const sql = reader.cstring() catch return error.PostgrezMalformedMessage;
    const count = reader.int16() catch return error.PostgrezMalformedMessage;
    if (count < 0) return error.PostgrezMalformedMessage;

    const oids = try arena.alloc(u32, @intCast(count));
    for (oids) |*entry| {
        entry.* = @bitCast(reader.int32() catch return error.PostgrezMalformedMessage);
    }

    return .{ .statement_name = statement_name, .sql = sql, .param_oids = oids };
}

fn decodeBind(reader: *message.Reader, arena: std.mem.Allocator) Error!Bind {
    const portal_name = reader.cstring() catch return error.PostgrezMalformedMessage;
    const statement_name = reader.cstring() catch return error.PostgrezMalformedMessage;

    // Parameter formats. The protocol allows none (all text), exactly one
    // (that format for every parameter), or one each.
    const format_count = reader.int16() catch return error.PostgrezMalformedMessage;
    if (format_count < 0) return error.PostgrezMalformedMessage;

    const formats = try arena.alloc(bool, @intCast(format_count));
    for (formats) |*binary| {
        binary.* = (reader.int16() catch return error.PostgrezMalformedMessage) == 1;
    }

    const param_count = reader.int16() catch return error.PostgrezMalformedMessage;
    if (param_count < 0) return error.PostgrezMalformedMessage;

    const parameters = try arena.alloc(BoundParameter, @intCast(param_count));
    for (parameters, 0..) |*parameter, index| {
        const binary = if (formats.len == 0)
            false
        else if (formats.len == 1)
            formats[0]
        else if (index < formats.len)
            formats[index]
        else
            return error.PostgrezMalformedMessage;

        const length = reader.int32() catch return error.PostgrezMalformedMessage;
        if (length < 0) {
            parameter.* = .{ .value = null, .binary = binary };

            continue;
        }

        parameter.* = .{
            .value = reader.bytes(@intCast(length)) catch return error.PostgrezMalformedMessage,
            .binary = binary,
        };
    }

    const result_format_count = reader.int16() catch return error.PostgrezMalformedMessage;
    if (result_format_count < 0) return error.PostgrezMalformedMessage;

    // any binary result format asks the whole row set to come back binary,
    // which is what the driver's binary-first mapper relies on
    var binary_results = false;
    for (0..@intCast(result_format_count)) |_| {
        const format = reader.int16() catch return error.PostgrezMalformedMessage;
        if (format == 1) binary_results = true;
    }

    return .{
        .portal_name = portal_name,
        .statement_name = statement_name,
        .parameters = parameters,
        .binary_results = binary_results,
    };
}

fn decodeTarget(reader: *message.Reader) Error!Target {
    const kind = reader.byte() catch return error.PostgrezMalformedMessage;
    const name = reader.cstring() catch return error.PostgrezMalformedMessage;

    return .{ .kind = kind, .name = name };
}

fn decodeExecute(reader: *message.Reader) Error!Execute {
    const portal_name = reader.cstring() catch return error.PostgrezMalformedMessage;
    const max_rows = reader.int32() catch return error.PostgrezMalformedMessage;
    if (max_rows < 0) return error.PostgrezMalformedMessage;

    return .{ .portal_name = portal_name, .max_rows = @intCast(max_rows) };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

const postgrez = @import("postgrez");

/// A source over a fixed byte slice, the shape transport.zig provides for a
/// real connection.
const FixedSource = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn readExact(self: *FixedSource, buf: []u8) !void {
        if (self.pos + buf.len > self.bytes.len) return error.PostgrezConnectionClosed;

        @memcpy(buf, self.bytes[self.pos..][0..buf.len]);
        self.pos += buf.len;
    }
};

/// Build a client message with the driver's own encoder, so these tests prove
/// the two sides agree rather than proving the server agrees with itself.
fn encoded(arena: std.mem.Allocator, comptime build: anytype, args: anytype) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try @call(.auto, build, .{ arena, &out } ++ args);

    return out.items;
}

test "postgrez inproc: frontend reads the startup packet the driver builds" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const bytes = try encoded(arena.allocator(), postgrez.frontend.startup, .{
        postgrez.frontend.PROTOCOL_V3_2,
        postgrez.frontend.StartupOptions{ .user = "tester", .database = "testdb" },
    });

    var source = FixedSource{ .bytes = bytes };
    const startup = try readStartup(&source, arena.allocator());

    try testing.expectEqual(postgrez.frontend.PROTOCOL_V3_2, startup.hello.protocol_code);
    try testing.expectEqualStrings("tester", startup.hello.user);
    try testing.expectEqualStrings("testdb", startup.hello.database);
}

test "postgrez inproc: frontend recognises an ssl request" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const bytes = try encoded(arena.allocator(), postgrez.frontend.sslRequest, .{});

    var source = FixedSource{ .bytes = bytes };
    const startup = try readStartup(&source, arena.allocator());

    try testing.expectEqual(Startup.ssl_request, startup);
}

test "postgrez inproc: frontend recognises a cancel request" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const bytes = try encoded(arena.allocator(), postgrez.frontend.cancelRequest, .{ @as(i32, 4242), "keydata" });

    var source = FixedSource{ .bytes = bytes };
    const startup = try readStartup(&source, arena.allocator());

    try testing.expectEqual(@as(i32, 4242), startup.cancel_request.pid);
}

test "postgrez inproc: frontend reads a simple query" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const bytes = try encoded(arena.allocator(), postgrez.frontend.query, .{"SELECT 1"});

    var source = FixedSource{ .bytes = bytes };
    const msg = try readMessage(&source, arena.allocator());

    try testing.expectEqualStrings("SELECT 1", msg.query);
}

test "postgrez inproc: frontend reads a parse with its parameter oids" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const oids = [_]u32{ 23, 25 };
    const bytes = try encoded(arena.allocator(), postgrez.frontend.parse, .{ "stmt1", "SELECT $1, $2", @as([]const u32, &oids) });

    var source = FixedSource{ .bytes = bytes };
    const msg = try readMessage(&source, arena.allocator());

    try testing.expectEqualStrings("stmt1", msg.parse.statement_name);
    try testing.expectEqualStrings("SELECT $1, $2", msg.parse.sql);
    try testing.expectEqualSlices(u32, &oids, msg.parse.param_oids);
}

test "postgrez inproc: frontend reads bind parameters including a null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const values = [_]?[]const u8{ "abc", null };
    const param_formats = [_]postgrez.frontend.Format{ .TEXT, .TEXT };
    const result_formats = [_]postgrez.frontend.Format{.BINARY};
    const bytes = try encoded(arena.allocator(), postgrez.frontend.bind, .{
        "",
        "stmt1",
        @as([]const postgrez.frontend.Format, &param_formats),
        @as([]const ?[]const u8, &values),
        @as([]const postgrez.frontend.Format, &result_formats),
    });

    var source = FixedSource{ .bytes = bytes };
    const msg = try readMessage(&source, arena.allocator());

    try testing.expectEqualStrings("stmt1", msg.bind.statement_name);
    try testing.expectEqual(@as(usize, 2), msg.bind.parameters.len);
    try testing.expectEqualStrings("abc", msg.bind.parameters[0].value.?);
    try testing.expect(!msg.bind.parameters[0].binary);
    try testing.expectEqual(@as(?[]const u8, null), msg.bind.parameters[1].value);
    try testing.expect(msg.bind.binary_results);
}

test "postgrez inproc: frontend keeps the binary flag a parameter was bound with" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // a four-byte text value and a binary int4 are the same length, so the
    // format is the only thing that tells them apart
    const values = [_]?[]const u8{"4242"};
    const text_formats = [_]postgrez.frontend.Format{.TEXT};
    const binary_formats = [_]postgrez.frontend.Format{.BINARY};

    const as_text = try encoded(arena.allocator(), postgrez.frontend.bind, .{
        "",
        "stmt1",
        @as([]const postgrez.frontend.Format, &text_formats),
        @as([]const ?[]const u8, &values),
        @as([]const postgrez.frontend.Format, &.{}),
    });
    var text_source = FixedSource{ .bytes = as_text };
    const text_msg = try readMessage(&text_source, arena.allocator());
    try testing.expect(!text_msg.bind.parameters[0].binary);

    const as_binary = try encoded(arena.allocator(), postgrez.frontend.bind, .{
        "",
        "stmt1",
        @as([]const postgrez.frontend.Format, &binary_formats),
        @as([]const ?[]const u8, &values),
        @as([]const postgrez.frontend.Format, &.{}),
    });
    var binary_source = FixedSource{ .bytes = as_binary };
    const binary_msg = try readMessage(&binary_source, arena.allocator());
    try testing.expect(binary_msg.bind.parameters[0].binary);
}

test "postgrez inproc: frontend reads describe, execute and sync" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var out: std.ArrayList(u8) = .empty;
    try postgrez.frontend.describeStatement(allocator, &out, "stmt1");
    try postgrez.frontend.execute(allocator, &out, "", 0);
    try postgrez.frontend.sync(allocator, &out);

    var source = FixedSource{ .bytes = out.items };

    const describe = try readMessage(&source, allocator);
    try testing.expectEqual(@as(u8, 'S'), describe.describe.kind);
    try testing.expectEqualStrings("stmt1", describe.describe.name);

    const execute_msg = try readMessage(&source, allocator);
    try testing.expectEqual(@as(u32, 0), execute_msg.execute.max_rows);

    const sync_msg = try readMessage(&source, allocator);
    try testing.expectEqual(Message.sync, sync_msg);
}

test "postgrez inproc: frontend reads copy data and copy done" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var out: std.ArrayList(u8) = .empty;
    try postgrez.frontend.copyData(allocator, &out, "1\tone\n");
    try postgrez.frontend.copyDone(allocator, &out);

    var source = FixedSource{ .bytes = out.items };

    const data = try readMessage(&source, allocator);
    try testing.expectEqualStrings("1\tone\n", data.copy_data);

    const done = try readMessage(&source, allocator);
    try testing.expectEqual(Message.copy_done, done);
}

test "postgrez inproc: frontend surfaces an unknown tag rather than guessing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const msg = try decode('Z', "", arena.allocator());

    try testing.expectEqual(@as(u8, 'Z'), msg.unknown);
}

test "postgrez inproc: frontend reports a closed peer mid-message" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // a header that promises more payload than the stream holds
    var source = FixedSource{ .bytes = &[_]u8{ 'Q', 0, 0, 0, 20 } };

    try testing.expectError(error.PostgrezConnectionClosed, readMessage(&source, arena.allocator()));
}

test "postgrez inproc: frontend rejects an implausible message length" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    var source = FixedSource{ .bytes = &[_]u8{ 'Q', 0x7f, 0xff, 0xff, 0xff } };

    try testing.expectError(error.PostgrezMessageTooLarge, readMessage(&source, arena.allocator()));
}
