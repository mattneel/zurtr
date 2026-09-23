//! What the in-process backend sends, built the way the driver expects to read it.
//!
//! Note:
//! - The mirror of src/protocol/backend.zig, which parses these same
//!   messages. Only what the driver reads is emitted.
//! - Every builder appends to a caller-owned message.Writer, so one reply
//!   flight (say BindComplete, DataRow, CommandComplete, ReadyForQuery)
//!   accumulates and leaves the socket in a single write.

const std = @import("std");

const message = @import("message.zig");

/// Transaction status carried by ReadyForQuery.
pub const TransactionStatus = enum(u8) {
    /// Not in a transaction.
    IDLE = 'I',
    /// In a transaction block.
    IN_TRANSACTION = 'T',
    /// In a transaction block that has already failed.
    IN_FAILED_TRANSACTION = 'E',
};

/// One column of a RowDescription.
pub const Column = struct {
    name: []const u8,
    type_oid: u32,
    /// Negative means variable width, which is right for text and numeric.
    type_len: i16 = -1,
    type_mod: i32 = -1,
    /// 0 text, 1 binary. Must match how the values in each DataRow are encoded.
    format: i16 = 0,
};

/// An error or notice, as the driver's sqlstate layer reads it.
pub const Notice = struct {
    severity: []const u8 = "ERROR",
    /// Five-character SQLSTATE, for example 23505 for a unique violation.
    code: []const u8,
    message: []const u8,
    detail: ?[]const u8 = null,
    constraint: ?[]const u8 = null,
};

// --------------------------------------------------------- //

pub fn authenticationOk(writer: *message.Writer) void {
    const marker = writer.beginMessage('R');
    writer.int32(0);
    writer.endMessage(marker);
}

pub fn authenticationCleartextPassword(writer: *message.Writer) void {
    const marker = writer.beginMessage('R');
    writer.int32(3);
    writer.endMessage(marker);
}

/// AuthenticationSASL: the mechanism list, NUL terminated and then empty.
pub fn authenticationSasl(writer: *message.Writer, mechanisms: []const []const u8) void {
    const marker = writer.beginMessage('R');
    writer.int32(10);
    for (mechanisms) |mechanism| writer.cstring(mechanism);
    writer.byte(0);
    writer.endMessage(marker);
}

pub fn authenticationSaslContinue(writer: *message.Writer, data: []const u8) void {
    const marker = writer.beginMessage('R');
    writer.int32(11);
    writer.bytes(data);
    writer.endMessage(marker);
}

pub fn authenticationSaslFinal(writer: *message.Writer, data: []const u8) void {
    const marker = writer.beginMessage('R');
    writer.int32(12);
    writer.bytes(data);
    writer.endMessage(marker);
}

pub fn parameterStatus(writer: *message.Writer, name: []const u8, value: []const u8) void {
    const marker = writer.beginMessage('S');
    writer.cstring(name);
    writer.cstring(value);
    writer.endMessage(marker);
}

pub fn backendKeyData(writer: *message.Writer, pid: i32, key: []const u8) void {
    const marker = writer.beginMessage('K');
    writer.int32(pid);
    writer.bytes(key);
    writer.endMessage(marker);
}

pub fn readyForQuery(writer: *message.Writer, status: TransactionStatus) void {
    const marker = writer.beginMessage('Z');
    writer.byte(@intFromEnum(status));
    writer.endMessage(marker);
}

/// NegotiateProtocolVersion: the server offers a lower minor than requested.
pub fn negotiateProtocolVersion(writer: *message.Writer, newest_code: i32, unsupported: []const []const u8) void {
    const marker = writer.beginMessage('v');
    writer.int32(newest_code);
    writer.int32(@intCast(unsupported.len));
    for (unsupported) |option| writer.cstring(option);
    writer.endMessage(marker);
}

pub fn rowDescription(writer: *message.Writer, columns: []const Column) void {
    const marker = writer.beginMessage('T');
    writer.int16(@intCast(columns.len));
    for (columns) |column| {
        writer.cstring(column.name);
        // table oid and column attribute number: zero means the column is not
        // a plain reference to a table column, which is true of everything
        // this backend serves
        writer.int32(0);
        writer.int16(0);
        writer.int32(@bitCast(column.type_oid));
        writer.int16(column.type_len);
        writer.int32(column.type_mod);
        writer.int16(column.format);
    }
    writer.endMessage(marker);
}

/// One row. A null element is the SQL NULL, encoded as a length of -1.
pub fn dataRow(writer: *message.Writer, values: []const ?[]const u8) void {
    const marker = writer.beginMessage('D');
    writer.int16(@intCast(values.len));
    for (values) |value| {
        if (value) |bytes| {
            writer.int32(@intCast(bytes.len));
            writer.bytes(bytes);

            continue;
        }

        writer.int32(-1);
    }
    writer.endMessage(marker);
}

/// CommandComplete, carrying a tag such as `SELECT 2` or `INSERT 0 1`.
pub fn commandComplete(writer: *message.Writer, tag: []const u8) void {
    const marker = writer.beginMessage('C');
    writer.cstring(tag);
    writer.endMessage(marker);
}

pub fn emptyQueryResponse(writer: *message.Writer) void {
    const marker = writer.beginMessage('I');
    writer.endMessage(marker);
}

pub fn errorResponse(writer: *message.Writer, notice: Notice) void {
    appendNotice(writer, 'E', notice);
}

pub fn noticeResponse(writer: *message.Writer, notice: Notice) void {
    appendNotice(writer, 'N', notice);
}

fn appendNotice(writer: *message.Writer, tag: u8, notice: Notice) void {
    const marker = writer.beginMessage(tag);

    writer.byte('S');
    writer.cstring(notice.severity);
    writer.byte('V');
    writer.cstring(notice.severity);
    writer.byte('C');
    writer.cstring(notice.code);
    writer.byte('M');
    writer.cstring(notice.message);
    if (notice.detail) |detail| {
        writer.byte('D');
        writer.cstring(detail);
    }
    if (notice.constraint) |constraint| {
        writer.byte('n');
        writer.cstring(constraint);
    }

    // the field list ends with a lone NUL
    writer.byte(0);
    writer.endMessage(marker);
}

pub fn parseComplete(writer: *message.Writer) void {
    emptyMessage(writer, '1');
}

pub fn bindComplete(writer: *message.Writer) void {
    emptyMessage(writer, '2');
}

pub fn closeComplete(writer: *message.Writer) void {
    emptyMessage(writer, '3');
}

pub fn noData(writer: *message.Writer) void {
    emptyMessage(writer, 'n');
}

pub fn portalSuspended(writer: *message.Writer) void {
    emptyMessage(writer, 's');
}

pub fn copyDone(writer: *message.Writer) void {
    emptyMessage(writer, 'c');
}

fn emptyMessage(writer: *message.Writer, tag: u8) void {
    const marker = writer.beginMessage(tag);
    writer.endMessage(marker);
}

pub fn parameterDescription(writer: *message.Writer, oids: []const u32) void {
    const marker = writer.beginMessage('t');
    writer.int16(@intCast(oids.len));
    for (oids) |type_oid| writer.int32(@bitCast(type_oid));
    writer.endMessage(marker);
}

pub fn copyInResponse(writer: *message.Writer, column_count: u16) void {
    copyResponse(writer, 'G', column_count);
}

pub fn copyOutResponse(writer: *message.Writer, column_count: u16) void {
    copyResponse(writer, 'H', column_count);
}

/// CopyInResponse and CopyOutResponse share a body: the overall format, then
/// one format per column. This backend only ever copies in text mode.
fn copyResponse(writer: *message.Writer, tag: u8, column_count: u16) void {
    const marker = writer.beginMessage(tag);
    writer.byte(0);
    writer.int16(@intCast(column_count));
    for (0..column_count) |_| writer.int16(0);
    writer.endMessage(marker);
}

pub fn copyData(writer: *message.Writer, data: []const u8) void {
    const marker = writer.beginMessage('d');
    writer.bytes(data);
    writer.endMessage(marker);
}

pub fn notificationResponse(writer: *message.Writer, pid: i32, channel: []const u8, payload: []const u8) void {
    const marker = writer.beginMessage('A');
    writer.int32(pid);
    writer.cstring(channel);
    writer.cstring(payload);
    writer.endMessage(marker);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

const postgrez = @import("postgrez");

/// Parse back what was built, using the driver's own decoder. These tests
/// prove the two sides agree, not that the server agrees with itself.
fn parseOne(bytes: []const u8) !postgrez.backend.BackendMessage {
    const header = try postgrez.backend.parseHeader(bytes[0..5].*);
    const payload = bytes[5 .. 5 + header.payload_len];

    return postgrez.backend.decode(header.tag, payload);
}

test "postgrez inproc: backend authentication ok decodes as ok" {
    var buf: [64]u8 = undefined;
    var writer = message.Writer{ .buf = &buf };
    authenticationOk(&writer);

    const parsed = try parseOne(try writer.finish());

    try testing.expectEqual(postgrez.backend.Auth.ok, parsed.auth);
}

test "postgrez inproc: backend sasl mechanism list decodes" {
    var buf: [128]u8 = undefined;
    var writer = message.Writer{ .buf = &buf };
    authenticationSasl(&writer, &.{ "SCRAM-SHA-256-PLUS", "SCRAM-SHA-256" });

    const parsed = try parseOne(try writer.finish());

    try testing.expect(parsed.auth.sasl.has("SCRAM-SHA-256"));
    try testing.expect(parsed.auth.sasl.has("SCRAM-SHA-256-PLUS"));
}

test "postgrez inproc: backend parameter status and key data decode" {
    var buf: [128]u8 = undefined;

    var status_writer = message.Writer{ .buf = &buf };
    parameterStatus(&status_writer, "server_version", "18.0");
    const status = try parseOne(try status_writer.finish());
    try testing.expectEqualStrings("server_version", status.parameter_status.name);
    try testing.expectEqualStrings("18.0", status.parameter_status.value);

    var key_writer = message.Writer{ .buf = &buf };
    backendKeyData(&key_writer, 4242, &[_]u8{ 0xca, 0xfe, 0xba, 0xbe });
    const key = try parseOne(try key_writer.finish());
    try testing.expectEqual(@as(i32, 4242), key.backend_key_data.pid);
}

test "postgrez inproc: backend ready for query carries the transaction status" {
    var buf: [16]u8 = undefined;
    var writer = message.Writer{ .buf = &buf };
    readyForQuery(&writer, .IN_TRANSACTION);

    const parsed = try parseOne(try writer.finish());

    try testing.expectEqual(postgrez.backend.TransactionStatus.IN_TRANSACTION, parsed.ready_for_query);
}

test "postgrez inproc: backend row description decodes column by column" {
    var buf: [256]u8 = undefined;
    var writer = message.Writer{ .buf = &buf };
    rowDescription(&writer, &.{
        .{ .name = "id", .type_oid = 23, .type_len = 4, .format = 1 },
        .{ .name = "name", .type_oid = 25 },
    });

    const parsed = try parseOne(try writer.finish());
    try testing.expectEqual(@as(u16, 2), parsed.row_description.column_count);

    var it = parsed.row_description.iterator();

    const first = (try it.next()).?;
    try testing.expectEqualStrings("id", first.name);
    try testing.expectEqual(@as(u32, 23), first.type_oid);
    try testing.expectEqual(postgrez.backend.Format.BINARY, first.format);

    const second = (try it.next()).?;
    try testing.expectEqualStrings("name", second.name);
    try testing.expectEqual(@as(u32, 25), second.type_oid);
    try testing.expectEqual(postgrez.backend.Format.TEXT, second.format);
}

test "postgrez inproc: backend data row carries a null as a negative length" {
    var buf: [128]u8 = undefined;
    var writer = message.Writer{ .buf = &buf };
    dataRow(&writer, &.{ "one", null, "" });

    const parsed = try parseOne(try writer.finish());
    try testing.expectEqual(@as(u16, 3), parsed.data_row.column_count);

    var it = parsed.data_row.iterator();
    try testing.expectEqualStrings("one", (try it.next()).?.?);
    try testing.expectEqual(@as(?[]const u8, null), (try it.next()).?);
    try testing.expectEqualStrings("", (try it.next()).?.?);
}

test "postgrez inproc: backend error response carries the sqlstate the driver maps" {
    var buf: [256]u8 = undefined;
    var writer = message.Writer{ .buf = &buf };
    errorResponse(&writer, .{
        .code = "23505",
        .message = "duplicate key value violates unique constraint",
        .constraint = "users_email_key",
    });

    const parsed = try parseOne(try writer.finish());

    try testing.expectEqualStrings("23505", parsed.error_response.get('C').?);
    try testing.expectEqualStrings("users_email_key", parsed.error_response.get('n').?);
}

test "postgrez inproc: backend command complete carries its tag" {
    var buf: [64]u8 = undefined;
    var writer = message.Writer{ .buf = &buf };
    commandComplete(&writer, "INSERT 0 1");

    const parsed = try parseOne(try writer.finish());

    try testing.expectEqualStrings("INSERT 0 1", parsed.command_complete);
}

test "postgrez inproc: backend notification carries channel and payload" {
    var buf: [128]u8 = undefined;
    var writer = message.Writer{ .buf = &buf };
    notificationResponse(&writer, 77, "chan", "hello");

    const parsed = try parseOne(try writer.finish());

    try testing.expectEqual(@as(i32, 77), parsed.notification.pid);
    try testing.expectEqualStrings("chan", parsed.notification.channel);
    try testing.expectEqualStrings("hello", parsed.notification.payload);
}

test "postgrez inproc: backend copy in response announces its columns" {
    var buf: [64]u8 = undefined;
    var writer = message.Writer{ .buf = &buf };
    copyInResponse(&writer, 2);

    const parsed = try parseOne(try writer.finish());

    try testing.expectEqual(@as(u16, 2), parsed.copy_in_response.column_count);
    try testing.expectEqual(postgrez.backend.Format.TEXT, parsed.copy_in_response.overall_format);
}

test "postgrez inproc: backend flight accumulates in one buffer" {
    var buf: [256]u8 = undefined;
    var writer = message.Writer{ .buf = &buf };

    bindComplete(&writer);
    dataRow(&writer, &.{"1"});
    commandComplete(&writer, "SELECT 1");
    readyForQuery(&writer, .IDLE);

    const flight = try writer.finish();

    // four messages back to back, each readable in turn
    var offset: usize = 0;
    const tags = [_]u8{ '2', 'D', 'C', 'Z' };
    for (tags) |want| {
        const header = try postgrez.backend.parseHeader(flight[offset..][0..5].*);
        try testing.expectEqual(want, header.tag);
        offset += 5 + header.payload_len;
    }

    try testing.expectEqual(flight.len, offset);
}
