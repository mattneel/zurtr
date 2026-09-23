//! postgrez backend messages: server to driver decode.
//!
//! Note:
//! - decode() takes one complete message payload (framing already stripped)
//!   and returns a tagged union view over it. Decoded slices point INTO the
//!   payload buffer, zero copy, so they live only as long as that buffer.
//! - Framing: 1-byte tag, then an i32 length that counts itself but not the
//!   tag. parseHeader() decodes those first 5 bytes.

const std = @import("std");
const frontend = @import("frontend.zig");

pub const Format = frontend.Format;

pub const DecodeError = error{
    PostgrezTruncated,
    PostgrezBadMessage,
};

/// Wire framing: tag + length. `payload_len` already excludes the length
/// field itself, it is the number of bytes to read after the header.
pub const Header = struct {
    tag: u8,
    payload_len: u32,
};

/// Decode the 5 framing bytes of a backend message.
///
/// Return:
/// - Header on success
/// - error.PostgrezBadMessage when the length field is below its own 4 bytes
pub fn parseHeader(bytes: [5]u8) DecodeError!Header {
    const wire_len = std.mem.readInt(u32, bytes[1..5], .big);
    if (wire_len < 4) return error.PostgrezBadMessage;

    return .{ .tag = bytes[0], .payload_len = wire_len - 4 };
}

// --------------------------------------------------------- //

/// Bounds-checked read cursor over one message payload.
const Cursor = struct {
    buf: []const u8,
    pos: usize = 0,

    fn readInt(self: *Cursor, comptime T: type) DecodeError!T {
        if (self.pos + @sizeOf(T) > self.buf.len) return error.PostgrezTruncated;

        const value = std.mem.readInt(T, self.buf[self.pos..][0..@sizeOf(T)], .big);
        self.pos += @sizeOf(T);

        return value;
    }

    fn readCstr(self: *Cursor) DecodeError![]const u8 {
        const end = std.mem.indexOfScalarPos(u8, self.buf, self.pos, 0) orelse return error.PostgrezTruncated;

        const text = self.buf[self.pos..end];
        self.pos = end + 1;

        return text;
    }

    fn take(self: *Cursor, n: usize) DecodeError![]const u8 {
        if (self.pos + n > self.buf.len) return error.PostgrezTruncated;

        const bytes = self.buf[self.pos..][0..n];
        self.pos += n;

        return bytes;
    }

    fn rest(self: *Cursor) []const u8 {
        return self.buf[self.pos..];
    }
};

// --------------------------------------------------------- //

/// Authentication ('R') variants the driver understands. MD5 is decoded so
/// the connection can reject it with a precise error, not supported.
pub const Auth = union(enum) {
    ok,
    cleartext_password,
    md5_password: [4]u8,
    sasl: SaslMechanisms,
    sasl_continue: []const u8,
    sasl_final: []const u8,
    unsupported: i32,
};

/// The SASL mechanism list from AuthenticationSASL, iterated as cstrs.
pub const SaslMechanisms = struct {
    payload: []const u8,

    pub const Iterator = struct {
        cursor: Cursor,

        /// Next mechanism name, null at the terminating empty string.
        pub fn next(self: *Iterator) DecodeError!?[]const u8 {
            if (self.cursor.pos >= self.cursor.buf.len) return null;

            const name = try self.cursor.readCstr();
            if (name.len == 0) return null;

            return name;
        }
    };

    pub fn iterator(self: SaslMechanisms) Iterator {
        return .{ .cursor = .{ .buf = self.payload } };
    }

    /// Whether `mechanism` is offered by the server.
    pub fn has(self: SaslMechanisms, mechanism: []const u8) bool {
        var it = self.iterator();

        while (it.next() catch return false) |name| {
            if (std.mem.eql(u8, name, mechanism)) return true;
        }

        return false;
    }
};

/// BackendKeyData ('K'): cancellation credentials. The key is 4 bytes under
/// protocol 3.0 and variable length (up to 256) under 3.2, so it stays a slice.
pub const BackendKeyData = struct {
    pid: i32,
    key: []const u8,
};

/// ParameterStatus ('S'): a run-time parameter report, e.g. server_version.
pub const ParameterStatus = struct {
    name: []const u8,
    value: []const u8,
};

/// ReadyForQuery ('Z') transaction status.
pub const TransactionStatus = enum(u8) {
    IDLE = 'I',
    IN_TRANSACTION = 'T',
    IN_FAILED_TRANSACTION = 'E',
};

/// ErrorResponse ('E') and NoticeResponse ('N') field list.
///
/// Note:
/// - Field codes are single bytes from the protocol error-fields table:
///   'S' severity, 'C' sqlstate, 'M' message, 'D' detail, 'H' hint, and so on.
pub const Fields = struct {
    payload: []const u8,

    pub const Field = struct {
        code: u8,
        value: []const u8,
    };

    pub const Iterator = struct {
        cursor: Cursor,

        pub fn next(self: *Iterator) DecodeError!?Field {
            if (self.cursor.pos >= self.cursor.buf.len) return null;

            const code = (try self.cursor.take(1))[0];
            if (code == 0) return null;

            const value = try self.cursor.readCstr();

            return .{ .code = code, .value = value };
        }
    };

    pub fn iterator(self: Fields) Iterator {
        return .{ .cursor = .{ .buf = self.payload } };
    }

    /// First field with `code`, null when absent or malformed.
    pub fn get(self: Fields, code: u8) ?[]const u8 {
        var it = self.iterator();

        while (it.next() catch return null) |field| {
            if (field.code == code) return field.value;
        }

        return null;
    }

    /// Severity field ('S'), e.g. ERROR, FATAL, WARNING.
    pub fn severity(self: Fields) []const u8 {
        return self.get('S') orelse "";
    }

    /// Raw 5-char SQLSTATE code ('C').
    pub fn sqlstateCode(self: Fields) []const u8 {
        return self.get('C') orelse "";
    }

    /// Primary message ('M').
    pub fn message(self: Fields) []const u8 {
        return self.get('M') orelse "";
    }
};

/// One column descriptor from RowDescription.
pub const Column = struct {
    name: []const u8,
    table_oid: u32,
    column_attr: i16,
    type_oid: u32,
    type_len: i16,
    type_mod: i32,
    format: Format,
};

/// RowDescription ('T'): column metadata for the rows that follow.
pub const RowDescription = struct {
    column_count: u16,
    payload: []const u8,

    pub const Iterator = struct {
        cursor: Cursor,
        remaining: u16,

        pub fn next(self: *Iterator) DecodeError!?Column {
            if (self.remaining == 0) return null;
            self.remaining -= 1;

            const name = try self.cursor.readCstr();
            const table_oid = try self.cursor.readInt(u32);
            const column_attr = try self.cursor.readInt(i16);
            const type_oid = try self.cursor.readInt(u32);
            const type_len = try self.cursor.readInt(i16);
            const type_mod = try self.cursor.readInt(i32);
            const format_code = try self.cursor.readInt(i16);
            if (format_code != 0 and format_code != 1) return error.PostgrezBadMessage;

            return .{
                .name = name,
                .table_oid = table_oid,
                .column_attr = column_attr,
                .type_oid = type_oid,
                .type_len = type_len,
                .type_mod = type_mod,
                .format = @enumFromInt(format_code),
            };
        }
    };

    pub fn iterator(self: RowDescription) Iterator {
        return .{ .cursor = .{ .buf = self.payload }, .remaining = self.column_count };
    }
};

/// DataRow ('D'): one result row, cells in RowDescription order.
pub const DataRow = struct {
    column_count: u16,
    payload: []const u8,

    pub const Iterator = struct {
        cursor: Cursor,
        remaining: u16,

        /// Next cell. The outer optional ends iteration, the inner optional
        /// is SQL NULL.
        pub fn next(self: *Iterator) DecodeError!??[]const u8 {
            if (self.remaining == 0) return null;
            self.remaining -= 1;

            const cell_len = try self.cursor.readInt(i32);
            if (cell_len == -1) return @as(?[]const u8, null);
            if (cell_len < 0) return error.PostgrezBadMessage;

            return try self.cursor.take(@intCast(cell_len));
        }
    };

    pub fn iterator(self: DataRow) Iterator {
        return .{ .cursor = .{ .buf = self.payload }, .remaining = self.column_count };
    }
};

/// ParameterDescription ('t'): parameter type OIDs of a described statement.
pub const ParameterDescription = struct {
    count: u16,
    payload: []const u8,

    pub const Iterator = struct {
        cursor: Cursor,
        remaining: u16,

        pub fn next(self: *Iterator) DecodeError!?u32 {
            if (self.remaining == 0) return null;
            self.remaining -= 1;

            return try self.cursor.readInt(u32);
        }
    };

    pub fn iterator(self: ParameterDescription) Iterator {
        return .{ .cursor = .{ .buf = self.payload }, .remaining = self.count };
    }
};

/// CopyInResponse ('G') and CopyOutResponse ('H').
pub const CopyResponse = struct {
    overall_format: Format,
    column_count: u16,
    formats_payload: []const u8,
};

/// NotificationResponse ('A'): a NOTIFY delivered to a LISTEN subscriber.
pub const Notification = struct {
    pid: i32,
    channel: []const u8,
    payload: []const u8,
};

/// NegotiateProtocolVersion ('v'): the server declined the requested minor
/// protocol version and reports the newest one it supports.
pub const NegotiateProtocolVersion = struct {
    newest_code: i32,
    unsupported_count: i32,
    options_payload: []const u8,
};

/// A message tag the driver does not know, kept for forward compatibility.
pub const Unknown = struct {
    tag: u8,
    payload: []const u8,
};

// --------------------------------------------------------- //

pub const BackendMessage = union(enum) {
    auth: Auth,
    backend_key_data: BackendKeyData,
    parameter_status: ParameterStatus,
    ready_for_query: TransactionStatus,
    error_response: Fields,
    notice_response: Fields,
    row_description: RowDescription,
    data_row: DataRow,
    command_complete: []const u8,
    empty_query_response,
    parse_complete,
    bind_complete,
    close_complete,
    no_data,
    portal_suspended,
    parameter_description: ParameterDescription,
    copy_in_response: CopyResponse,
    copy_out_response: CopyResponse,
    copy_data: []const u8,
    copy_done,
    notification: Notification,
    negotiate_protocol_version: NegotiateProtocolVersion,
    unknown: Unknown,
};

/// Decode one backend message payload.
///
/// Param:
/// tag - u8 (message type byte from the header)
/// payload - []const u8 (message body, length field already consumed)
///
/// Return:
/// - BackendMessage view over `payload` (zero copy)
/// - error.PostgrezTruncated / error.PostgrezBadMessage on malformed input
pub fn decode(tag: u8, payload: []const u8) DecodeError!BackendMessage {
    var cursor = Cursor{ .buf = payload };

    switch (tag) {
        'R' => {
            const subtype = try cursor.readInt(i32);

            switch (subtype) {
                0 => return .{ .auth = .ok },
                3 => return .{ .auth = .cleartext_password },
                5 => {
                    const salt = try cursor.take(4);

                    return .{ .auth = .{ .md5_password = salt[0..4].* } };
                },
                10 => return .{ .auth = .{ .sasl = .{ .payload = cursor.rest() } } },
                11 => return .{ .auth = .{ .sasl_continue = cursor.rest() } },
                12 => return .{ .auth = .{ .sasl_final = cursor.rest() } },
                else => return .{ .auth = .{ .unsupported = subtype } },
            }
        },
        'K' => {
            const pid = try cursor.readInt(i32);

            return .{ .backend_key_data = .{ .pid = pid, .key = cursor.rest() } };
        },
        'S' => {
            const name = try cursor.readCstr();
            const value = try cursor.readCstr();

            return .{ .parameter_status = .{ .name = name, .value = value } };
        },
        'Z' => {
            const status = (try cursor.take(1))[0];
            if (status != 'I' and status != 'T' and status != 'E') return error.PostgrezBadMessage;

            return .{ .ready_for_query = @enumFromInt(status) };
        },
        'E' => return .{ .error_response = .{ .payload = payload } },
        'N' => return .{ .notice_response = .{ .payload = payload } },
        'T' => {
            const column_count = try cursor.readInt(u16);

            return .{ .row_description = .{ .column_count = column_count, .payload = cursor.rest() } };
        },
        'D' => {
            const column_count = try cursor.readInt(u16);

            return .{ .data_row = .{ .column_count = column_count, .payload = cursor.rest() } };
        },
        'C' => return .{ .command_complete = try cursor.readCstr() },
        'I' => return .empty_query_response,
        '1' => return .parse_complete,
        '2' => return .bind_complete,
        '3' => return .close_complete,
        'n' => return .no_data,
        's' => return .portal_suspended,
        't' => {
            const count = try cursor.readInt(u16);

            return .{ .parameter_description = .{ .count = count, .payload = cursor.rest() } };
        },
        'G', 'H' => {
            const overall = try cursor.readInt(i8);
            if (overall != 0 and overall != 1) return error.PostgrezBadMessage;
            const column_count = try cursor.readInt(u16);

            const response = CopyResponse{
                .overall_format = @enumFromInt(overall),
                .column_count = column_count,
                .formats_payload = cursor.rest(),
            };

            if (tag == 'G') return .{ .copy_in_response = response };
            return .{ .copy_out_response = response };
        },
        'd' => return .{ .copy_data = payload },
        'c' => return .copy_done,
        'A' => {
            const pid = try cursor.readInt(i32);
            const channel = try cursor.readCstr();
            const notify_payload = try cursor.readCstr();

            return .{ .notification = .{ .pid = pid, .channel = channel, .payload = notify_payload } };
        },
        'v' => {
            const newest_code = try cursor.readInt(i32);
            const unsupported_count = try cursor.readInt(i32);

            return .{ .negotiate_protocol_version = .{
                .newest_code = newest_code,
                .unsupported_count = unsupported_count,
                .options_payload = cursor.rest(),
            } };
        },
        else => return .{ .unknown = .{ .tag = tag, .payload = payload } },
    }
}

/// Rows affected from a CommandComplete tag, e.g. "UPDATE 3" is 3 and
/// "INSERT 0 5" is 5. Tags without a count, e.g. "BEGIN", report 0.
pub fn commandCompleteRows(tag: []const u8) u64 {
    var it = std.mem.splitScalar(u8, tag, ' ');
    var last: []const u8 = "";
    while (it.next()) |part| last = part;

    return std.fmt.parseInt(u64, last, 10) catch 0;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez protocol: parseHeader splits tag and payload length" {
    const header = try parseHeader(.{ 'Z', 0, 0, 0, 5 });

    try testing.expectEqual(@as(u8, 'Z'), header.tag);
    try testing.expectEqual(@as(u32, 1), header.payload_len);
}

test "postgrez protocol: parseHeader rejects a length below 4" {
    try testing.expectError(error.PostgrezBadMessage, parseHeader(.{ 'Z', 0, 0, 0, 3 }));
}

test "postgrez protocol: auth ok, cleartext, md5 decode" {
    const ok = try decode('R', &.{ 0, 0, 0, 0 });
    try testing.expect(ok.auth == .ok);

    const cleartext = try decode('R', &.{ 0, 0, 0, 3 });
    try testing.expect(cleartext.auth == .cleartext_password);

    const md5 = try decode('R', &.{ 0, 0, 0, 5, 1, 2, 3, 4 });
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, &md5.auth.md5_password);
}

test "postgrez protocol: auth sasl lists mechanisms" {
    const payload = [_]u8{ 0, 0, 0, 10 } ++ "SCRAM-SHA-256-PLUS\x00SCRAM-SHA-256\x00\x00".*;
    const msg = try decode('R', &payload);

    try testing.expect(msg.auth.sasl.has("SCRAM-SHA-256"));
    try testing.expect(msg.auth.sasl.has("SCRAM-SHA-256-PLUS"));
    try testing.expect(!msg.auth.sasl.has("PLAIN"));
}

test "postgrez protocol: auth sasl continue and final carry raw data" {
    const cont = try decode('R', &([_]u8{ 0, 0, 0, 11 } ++ "r=abc".*));
    try testing.expectEqualStrings("r=abc", cont.auth.sasl_continue);

    const final = try decode('R', &([_]u8{ 0, 0, 0, 12 } ++ "v=xyz".*));
    try testing.expectEqualStrings("v=xyz", final.auth.sasl_final);
}

test "postgrez protocol: auth unknown subtype maps to unsupported" {
    const msg = try decode('R', &.{ 0, 0, 0, 7 });

    try testing.expectEqual(@as(i32, 7), msg.auth.unsupported);
}

test "postgrez protocol: backend_key_data keeps variable-length key" {
    const msg = try decode('K', &.{ 0, 0, 0, 9, 1, 2, 3, 4, 5, 6 });

    try testing.expectEqual(@as(i32, 9), msg.backend_key_data.pid);
    try testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6 }, msg.backend_key_data.key);
}

test "postgrez protocol: parameter_status decodes name and value" {
    const msg = try decode('S', "server_version\x0018.0\x00");

    try testing.expectEqualStrings("server_version", msg.parameter_status.name);
    try testing.expectEqualStrings("18.0", msg.parameter_status.value);
}

test "postgrez protocol: ready_for_query maps transaction status" {
    const idle = try decode('Z', "I");
    try testing.expectEqual(TransactionStatus.IDLE, idle.ready_for_query);

    const in_transaction = try decode('Z', "T");
    try testing.expectEqual(TransactionStatus.IN_TRANSACTION, in_transaction.ready_for_query);

    try testing.expectError(error.PostgrezBadMessage, decode('Z', "X"));
}

test "postgrez protocol: error_response fields are reachable by code" {
    const payload = "SERROR\x00C23505\x00Mduplicate key\x00\x00";
    const msg = try decode('E', payload);

    try testing.expectEqualStrings("ERROR", msg.error_response.severity());
    try testing.expectEqualStrings("23505", msg.error_response.sqlstateCode());
    try testing.expectEqualStrings("duplicate key", msg.error_response.message());
    try testing.expectEqual(@as(?[]const u8, null), msg.error_response.get('H'));
}

test "postgrez protocol: row_description iterates columns" {
    const payload = [_]u8{ 0, 2 } ++
        "id\x00".* ++ [_]u8{ 0, 0, 0, 1, 0, 1, 0, 0, 0, 20, 0, 8, 0xff, 0xff, 0xff, 0xff, 0, 1 } ++
        "name\x00".* ++ [_]u8{ 0, 0, 0, 1, 0, 2, 0, 0, 0, 25, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0 };
    const msg = try decode('T', &payload);

    try testing.expectEqual(@as(u16, 2), msg.row_description.column_count);

    var it = msg.row_description.iterator();

    const first = (try it.next()).?;
    try testing.expectEqualStrings("id", first.name);
    try testing.expectEqual(@as(u32, 20), first.type_oid);
    try testing.expectEqual(Format.BINARY, first.format);

    const second = (try it.next()).?;
    try testing.expectEqualStrings("name", second.name);
    try testing.expectEqual(@as(u32, 25), second.type_oid);
    try testing.expectEqual(Format.TEXT, second.format);

    try testing.expectEqual(@as(?Column, null), try it.next());
}

test "postgrez protocol: data_row iterates cells including null" {
    const payload = [_]u8{ 0, 3 } ++
        [_]u8{ 0, 0, 0, 2, 'a', 'b' } ++
        [_]u8{ 0xff, 0xff, 0xff, 0xff } ++
        [_]u8{ 0, 0, 0, 0 };
    const msg = try decode('D', &payload);

    var it = msg.data_row.iterator();

    const first = (try it.next()).?;
    try testing.expectEqualStrings("ab", first.?);

    const second = (try it.next()).?;
    try testing.expectEqual(@as(?[]const u8, null), second);

    const third = (try it.next()).?;
    try testing.expectEqualStrings("", third.?);

    try testing.expectEqual(@as(??[]const u8, null), try it.next());
}

test "postgrez protocol: command_complete and row counts" {
    const msg = try decode('C', "UPDATE 3\x00");

    try testing.expectEqualStrings("UPDATE 3", msg.command_complete);
    try testing.expectEqual(@as(u64, 3), commandCompleteRows(msg.command_complete));
    try testing.expectEqual(@as(u64, 5), commandCompleteRows("INSERT 0 5"));
    try testing.expectEqual(@as(u64, 0), commandCompleteRows("BEGIN"));
}

test "postgrez protocol: bare acks decode to their variants" {
    try testing.expect((try decode('I', "")) == .empty_query_response);
    try testing.expect((try decode('1', "")) == .parse_complete);
    try testing.expect((try decode('2', "")) == .bind_complete);
    try testing.expect((try decode('3', "")) == .close_complete);
    try testing.expect((try decode('n', "")) == .no_data);
    try testing.expect((try decode('s', "")) == .portal_suspended);
    try testing.expect((try decode('c', "")) == .copy_done);
}

test "postgrez protocol: parameter_description lists oids" {
    const msg = try decode('t', &.{ 0, 2, 0, 0, 0, 23, 0, 0, 0, 25 });

    var it = msg.parameter_description.iterator();
    try testing.expectEqual(@as(u32, 23), (try it.next()).?);
    try testing.expectEqual(@as(u32, 25), (try it.next()).?);
    try testing.expectEqual(@as(?u32, null), try it.next());
}

test "postgrez protocol: copy responses decode overall format" {
    const copy_in = try decode('G', &.{ 0, 0, 2, 0, 0, 0, 0 });
    try testing.expectEqual(Format.TEXT, copy_in.copy_in_response.overall_format);
    try testing.expectEqual(@as(u16, 2), copy_in.copy_in_response.column_count);

    const copy_out = try decode('H', &.{ 1, 0, 1, 0, 1 });
    try testing.expectEqual(Format.BINARY, copy_out.copy_out_response.overall_format);
}

test "postgrez protocol: copy_data is the raw chunk" {
    const msg = try decode('d', "line\n");

    try testing.expectEqualStrings("line\n", msg.copy_data);
}

test "postgrez protocol: notification decodes pid, channel, payload" {
    const payload = [_]u8{ 0, 0, 0, 42 } ++ "jobs\x00job-42\x00".*;
    const msg = try decode('A', &payload);

    try testing.expectEqual(@as(i32, 42), msg.notification.pid);
    try testing.expectEqualStrings("jobs", msg.notification.channel);
    try testing.expectEqualStrings("job-42", msg.notification.payload);
}

test "postgrez protocol: negotiate_protocol_version decodes newest code" {
    const msg = try decode('v', &.{ 0, 0x03, 0, 0, 0, 0, 0, 0 });

    try testing.expectEqual(@as(i32, frontend.PROTOCOL_V3_0), msg.negotiate_protocol_version.newest_code);
    try testing.expectEqual(@as(i32, 0), msg.negotiate_protocol_version.unsupported_count);
}

test "postgrez protocol: unknown tag is preserved" {
    const msg = try decode('!', "??");

    try testing.expectEqual(@as(u8, '!'), msg.unknown.tag);
    try testing.expectEqualStrings("??", msg.unknown.payload);
}

test "postgrez protocol: truncated payloads error instead of overread" {
    try testing.expectError(error.PostgrezTruncated, decode('R', &.{ 0, 0 }));
    try testing.expectError(error.PostgrezTruncated, decode('S', "no_terminator"));
    try testing.expectError(error.PostgrezTruncated, decode('A', &.{ 0, 0, 0, 1 }));
}
