//! postgrez frontend messages: driver to server encode.
//!
//! Note:
//! - Every builder appends one complete wire message to `out`, so callers can
//!   batch several messages into a single send (pipelining).
//! - Framing: 1-byte type tag, then an i32 length that counts itself but not
//!   the tag. The startup family (StartupMessage, SSLRequest, CancelRequest)
//!   has no tag byte.
//! - All integers are big-endian on the wire.

const std = @import("std");

/// Protocol 3.0 wire code (major 3 in the high 16 bits, minor 0 in the low).
pub const PROTOCOL_V3_0: i32 = 0x0003_0000;

/// Protocol 3.2 wire code. New in PostgreSQL 18, main change is the
/// variable-length cancellation key.
pub const PROTOCOL_V3_2: i32 = 0x0003_0002;

/// Magic code sent in place of a protocol version to request a TLS upgrade.
pub const SSL_REQUEST_CODE: i32 = 80877103;

/// Magic code sent in place of a protocol version to cancel a running query.
pub const CANCEL_REQUEST_CODE: i32 = 80877102;

/// Wire format of a parameter or result column.
pub const Format = enum(i16) {
    TEXT = 0,
    BINARY = 1,
};

/// Startup parameters sent in the StartupMessage.
///
/// Note:
/// - `client_encoding` is always sent as UTF8, the only encoding the driver
///   decodes.
pub const StartupOptions = struct {
    user: []const u8,
    database: ?[]const u8 = null,
    application_name: ?[]const u8 = null,
};

// --------------------------------------------------------- //

/// Append `value` big-endian to `out`.
fn appendInt(comptime T: type, allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: T) !void {
    var buf: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &buf, value, .big);

    try out.appendSlice(allocator, &buf);
}

/// Append `text` as a NUL-terminated string to `out`.
fn appendCstr(allocator: std.mem.Allocator, out: *std.ArrayList(u8), text: []const u8) !void {
    try out.appendSlice(allocator, text);
    try out.append(allocator, 0);
}

/// Reserve the 4-byte length field and return its offset for patchLen.
fn reserveLen(allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !usize {
    const len_pos = out.items.len;
    try out.appendSlice(allocator, &.{ 0, 0, 0, 0 });

    return len_pos;
}

/// Patch the length field at `len_pos` to cover everything appended since,
/// itself included (wire rule).
fn patchLen(out: *std.ArrayList(u8), len_pos: usize) void {
    const len: i32 = @intCast(out.items.len - len_pos);
    std.mem.writeInt(i32, out.items[len_pos..][0..4], len, .big);
}

// --------------------------------------------------------- //

/// StartupMessage: first message on a cleartext connection, no tag byte.
///
/// Param:
/// protocol_code - i32 (PROTOCOL_V3_2 or PROTOCOL_V3_0)
pub fn startup(allocator: std.mem.Allocator, out: *std.ArrayList(u8), protocol_code: i32, options: StartupOptions) !void {
    const len_pos = try reserveLen(allocator, out);

    try appendInt(i32, allocator, out, protocol_code);
    try appendCstr(allocator, out, "user");
    try appendCstr(allocator, out, options.user);
    if (options.database) |database| {
        try appendCstr(allocator, out, "database");
        try appendCstr(allocator, out, database);
    }
    if (options.application_name) |application_name| {
        try appendCstr(allocator, out, "application_name");
        try appendCstr(allocator, out, application_name);
    }
    try appendCstr(allocator, out, "client_encoding");
    try appendCstr(allocator, out, "UTF8");
    try out.append(allocator, 0);

    patchLen(out, len_pos);
}

/// SSLRequest: asks the server to upgrade this connection to TLS. The server
/// answers a single byte, 'S' (proceed with TLS) or 'N' (refused).
pub fn sslRequest(allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
    const len_pos = try reserveLen(allocator, out);

    try appendInt(i32, allocator, out, SSL_REQUEST_CODE);

    patchLen(out, len_pos);
}

/// CancelRequest: sent on a NEW connection to cancel a query on another one.
///
/// Param:
/// key - []const u8 (4 bytes under protocol 3.0, variable length under 3.2)
pub fn cancelRequest(allocator: std.mem.Allocator, out: *std.ArrayList(u8), pid: i32, key: []const u8) !void {
    const len_pos = try reserveLen(allocator, out);

    try appendInt(i32, allocator, out, CANCEL_REQUEST_CODE);
    try appendInt(i32, allocator, out, pid);
    try out.appendSlice(allocator, key);

    patchLen(out, len_pos);
}

// --------------------------------------------------------- //

/// PasswordMessage: cleartext password reply to AuthenticationCleartextPassword.
pub fn passwordCleartext(allocator: std.mem.Allocator, out: *std.ArrayList(u8), password: []const u8) !void {
    try out.append(allocator, 'p');
    const len_pos = try reserveLen(allocator, out);

    try appendCstr(allocator, out, password);

    patchLen(out, len_pos);
}

/// SASLInitialResponse: selects the SASL mechanism and carries the
/// client-first message.
pub fn saslInitialResponse(allocator: std.mem.Allocator, out: *std.ArrayList(u8), mechanism: []const u8, initial: []const u8) !void {
    try out.append(allocator, 'p');
    const len_pos = try reserveLen(allocator, out);

    try appendCstr(allocator, out, mechanism);
    try appendInt(i32, allocator, out, @intCast(initial.len));
    try out.appendSlice(allocator, initial);

    patchLen(out, len_pos);
}

/// SASLResponse: carries the client-final message of the SASL exchange.
pub fn saslResponse(allocator: std.mem.Allocator, out: *std.ArrayList(u8), data: []const u8) !void {
    try out.append(allocator, 'p');
    const len_pos = try reserveLen(allocator, out);

    try out.appendSlice(allocator, data);

    patchLen(out, len_pos);
}

// --------------------------------------------------------- //

/// Query: simple query protocol, one round trip, text results.
pub fn query(allocator: std.mem.Allocator, out: *std.ArrayList(u8), sql: []const u8) !void {
    try out.append(allocator, 'Q');
    const len_pos = try reserveLen(allocator, out);

    try appendCstr(allocator, out, sql);

    patchLen(out, len_pos);
}

/// Parse: create a prepared statement (extended query protocol).
///
/// Param:
/// statement_name - []const u8 (empty selects the unnamed statement)
/// param_oids - []const u32 (0 lets the server infer the parameter type)
pub fn parse(allocator: std.mem.Allocator, out: *std.ArrayList(u8), statement_name: []const u8, sql: []const u8, param_oids: []const u32) !void {
    try out.append(allocator, 'P');
    const len_pos = try reserveLen(allocator, out);

    try appendCstr(allocator, out, statement_name);
    try appendCstr(allocator, out, sql);
    try appendInt(i16, allocator, out, @intCast(param_oids.len));
    for (param_oids) |oid| try appendInt(u32, allocator, out, oid);

    patchLen(out, len_pos);
}

/// Bind: bind parameter values to a prepared statement, producing a portal.
///
/// Note:
/// - `params` values are already wire-encoded, null means SQL NULL.
/// - A single-element format list applies to every parameter or column
///   (wire rule), so passing `&.{.BINARY}` binds everything binary.
pub fn bind(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    portal_name: []const u8,
    statement_name: []const u8,
    param_formats: []const Format,
    params: []const ?[]const u8,
    result_formats: []const Format,
) !void {
    try out.append(allocator, 'B');
    const len_pos = try reserveLen(allocator, out);

    try appendCstr(allocator, out, portal_name);
    try appendCstr(allocator, out, statement_name);
    try appendInt(i16, allocator, out, @intCast(param_formats.len));
    for (param_formats) |format| try appendInt(i16, allocator, out, @intFromEnum(format));
    try appendInt(i16, allocator, out, @intCast(params.len));
    for (params) |maybe_value| {
        if (maybe_value) |value| {
            try appendInt(i32, allocator, out, @intCast(value.len));
            try out.appendSlice(allocator, value);
        } else {
            try appendInt(i32, allocator, out, -1);
        }
    }
    try appendInt(i16, allocator, out, @intCast(result_formats.len));
    for (result_formats) |format| try appendInt(i16, allocator, out, @intFromEnum(format));

    patchLen(out, len_pos);
}

/// Describe a prepared statement: server replies ParameterDescription then
/// RowDescription (or NoData).
pub fn describeStatement(allocator: std.mem.Allocator, out: *std.ArrayList(u8), statement_name: []const u8) !void {
    try out.append(allocator, 'D');
    const len_pos = try reserveLen(allocator, out);

    try out.append(allocator, 'S');
    try appendCstr(allocator, out, statement_name);

    patchLen(out, len_pos);
}

/// Describe a portal: server replies RowDescription (or NoData).
pub fn describePortal(allocator: std.mem.Allocator, out: *std.ArrayList(u8), portal_name: []const u8) !void {
    try out.append(allocator, 'D');
    const len_pos = try reserveLen(allocator, out);

    try out.append(allocator, 'P');
    try appendCstr(allocator, out, portal_name);

    patchLen(out, len_pos);
}

/// Execute a portal.
///
/// Param:
/// max_rows - u32 (0 fetches all rows, otherwise the portal suspends)
pub fn execute(allocator: std.mem.Allocator, out: *std.ArrayList(u8), portal_name: []const u8, max_rows: u32) !void {
    try out.append(allocator, 'E');
    const len_pos = try reserveLen(allocator, out);

    try appendCstr(allocator, out, portal_name);
    try appendInt(u32, allocator, out, max_rows);

    patchLen(out, len_pos);
}

/// Close a prepared statement on the server.
pub fn closeStatement(allocator: std.mem.Allocator, out: *std.ArrayList(u8), statement_name: []const u8) !void {
    try out.append(allocator, 'C');
    const len_pos = try reserveLen(allocator, out);

    try out.append(allocator, 'S');
    try appendCstr(allocator, out, statement_name);

    patchLen(out, len_pos);
}

/// Close a portal on the server.
pub fn closePortal(allocator: std.mem.Allocator, out: *std.ArrayList(u8), portal_name: []const u8) !void {
    try out.append(allocator, 'C');
    const len_pos = try reserveLen(allocator, out);

    try out.append(allocator, 'P');
    try appendCstr(allocator, out, portal_name);

    patchLen(out, len_pos);
}

/// Flush: ask the server to deliver pending responses without ending the
/// extended-query batch.
pub fn flush(allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
    try out.appendSlice(allocator, &.{ 'H', 0, 0, 0, 4 });
}

/// Sync: close the current extended-query batch, server answers
/// ReadyForQuery. Also the pipeline barrier.
pub fn sync(allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
    try out.appendSlice(allocator, &.{ 'S', 0, 0, 0, 4 });
}

/// Terminate: orderly connection shutdown, no reply.
pub fn terminate(allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
    try out.appendSlice(allocator, &.{ 'X', 0, 0, 0, 4 });
}

// --------------------------------------------------------- //

/// CopyData: one chunk of COPY payload (either direction).
pub fn copyData(allocator: std.mem.Allocator, out: *std.ArrayList(u8), data: []const u8) !void {
    try out.append(allocator, 'd');
    const len_pos = try reserveLen(allocator, out);

    try out.appendSlice(allocator, data);

    patchLen(out, len_pos);
}

/// CopyDone: ends a COPY FROM STDIN stream.
pub fn copyDone(allocator: std.mem.Allocator, out: *std.ArrayList(u8)) !void {
    try out.appendSlice(allocator, &.{ 'c', 0, 0, 0, 4 });
}

/// CopyFail: aborts a COPY FROM STDIN stream with a reason.
pub fn copyFail(allocator: std.mem.Allocator, out: *std.ArrayList(u8), message: []const u8) !void {
    try out.append(allocator, 'f');
    const len_pos = try reserveLen(allocator, out);

    try appendCstr(allocator, out, message);

    patchLen(out, len_pos);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez protocol: startup encodes protocol code and params" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try startup(testing.allocator, &out, PROTOCOL_V3_2, .{ .user = "u", .database = "d" });

    const expected = [_]u8{
        0, 0, 0, 48, // length
        0, 0x03, 0, 0x02, // protocol 3.2
    } ++ "user\x00u\x00database\x00d\x00client_encoding\x00UTF8\x00\x00".*;
    try testing.expectEqualSlices(u8, &expected, out.items);
}

test "postgrez protocol: sslRequest is the fixed 8-byte magic" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try sslRequest(testing.allocator, &out);

    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f }, out.items);
}

test "postgrez protocol: cancelRequest carries a variable-length key" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try cancelRequest(testing.allocator, &out, 7, &.{ 1, 2, 3, 4, 5, 6 });

    try testing.expectEqualSlices(u8, &.{
        0, 0, 0, 18, // 4 len + 4 code + 4 pid + 6 key
        0x04, 0xd2, 0x16, 0x2e, // 80877102
        0, 0, 0, 7, // pid
        1, 2, 3, 4, 5, 6, // key
    }, out.items);
}

test "postgrez protocol: passwordCleartext frames the password as cstr" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try passwordCleartext(testing.allocator, &out, "pw");

    try testing.expectEqualSlices(u8, &.{ 'p', 0, 0, 0, 7, 'p', 'w', 0 }, out.items);
}

test "postgrez protocol: saslInitialResponse frames mechanism and payload" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try saslInitialResponse(testing.allocator, &out, "SCRAM-SHA-256", "abc");

    const expected = [_]u8{ 'p', 0, 0, 0, 25 } ++ "SCRAM-SHA-256\x00".* ++ [_]u8{ 0, 0, 0, 3 } ++ "abc".*;
    try testing.expectEqualSlices(u8, &expected, out.items);
}

test "postgrez protocol: saslResponse is raw payload" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try saslResponse(testing.allocator, &out, "xyz");

    try testing.expectEqualSlices(u8, &.{ 'p', 0, 0, 0, 7, 'x', 'y', 'z' }, out.items);
}

test "postgrez protocol: query frames sql as cstr" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try query(testing.allocator, &out, "SELECT 1");

    const expected = [_]u8{ 'Q', 0, 0, 0, 13 } ++ "SELECT 1\x00".*;
    try testing.expectEqualSlices(u8, &expected, out.items);
}

test "postgrez protocol: parse encodes names, sql, and oids" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try parse(testing.allocator, &out, "s1", "SELECT $1", &.{23});

    const expected = [_]u8{ 'P', 0, 0, 0, 23 } ++ "s1\x00SELECT $1\x00".* ++ [_]u8{ 0, 1, 0, 0, 0, 23 };
    try testing.expectEqualSlices(u8, &expected, out.items);
}

test "postgrez protocol: bind encodes formats, params, and null" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try bind(testing.allocator, &out, "", "s1", &.{.BINARY}, &.{ "ab", null }, &.{.BINARY});

    const expected = [_]u8{ 'B', 0, 0, 0, 28 } ++ "\x00s1\x00".* ++ [_]u8{
        0, 1, 0, 1, // one param format, BINARY
        0, 2, // two params
        0, 0, 0, 2, 'a', 'b', // first value
        0xff, 0xff, 0xff, 0xff, // null
        0, 1, 0, 1, // one result format, BINARY
    };
    try testing.expectEqualSlices(u8, &expected, out.items);
}

test "postgrez protocol: describe, execute, and close target the right object" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try describeStatement(testing.allocator, &out, "s1");
    try describePortal(testing.allocator, &out, "p1");
    try execute(testing.allocator, &out, "p1", 0);
    try closeStatement(testing.allocator, &out, "s1");
    try closePortal(testing.allocator, &out, "p1");

    const expected = [_]u8{ 'D', 0, 0, 0, 8, 'S' } ++ "s1\x00".* ++
        [_]u8{ 'D', 0, 0, 0, 8, 'P' } ++ "p1\x00".* ++
        [_]u8{ 'E', 0, 0, 0, 11 } ++ "p1\x00".* ++ [_]u8{ 0, 0, 0, 0 } ++
        [_]u8{ 'C', 0, 0, 0, 8, 'S' } ++ "s1\x00".* ++
        [_]u8{ 'C', 0, 0, 0, 8, 'P' } ++ "p1\x00".*;
    try testing.expectEqualSlices(u8, &expected, out.items);
}

test "postgrez protocol: flush, sync, terminate are fixed empty messages" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try flush(testing.allocator, &out);
    try sync(testing.allocator, &out);
    try terminate(testing.allocator, &out);

    try testing.expectEqualSlices(u8, &.{
        'H', 0, 0, 0, 4,
        'S', 0, 0, 0, 4,
        'X', 0, 0, 0, 4,
    }, out.items);
}

test "postgrez protocol: copy messages frame data, done, and fail" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try copyData(testing.allocator, &out, "row\n");
    try copyDone(testing.allocator, &out);
    try copyFail(testing.allocator, &out, "no");

    const expected = [_]u8{ 'd', 0, 0, 0, 8 } ++ "row\n".* ++
        [_]u8{ 'c', 0, 0, 0, 4 } ++
        [_]u8{ 'f', 0, 0, 0, 7 } ++ "no\x00".*;
    try testing.expectEqualSlices(u8, &expected, out.items);
}
