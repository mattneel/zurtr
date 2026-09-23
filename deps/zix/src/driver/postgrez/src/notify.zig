//! LISTEN and NOTIFY.
//!
//! Note:
//! - Notifications arriving while other queries pump messages are captured
//!   into the connection's pending list, next() serves those first and only
//!   then blocks on the wire.
//! - The notification returned by next() stays valid until the following
//!   next() call on the same connection.

const std = @import("std");
const conn_mod = @import("conn.zig");
const frontend = @import("protocol/frontend.zig");

const Conn = conn_mod.Conn;

/// PostgreSQL identifiers cap at 63 bytes, quoting can double that.
const MAX_CHANNEL_LEN = 63;

/// LISTEN on a channel. The channel is quoted as an identifier, embedded
/// quotes escaped.
pub fn listen(conn: *Conn, channel: []const u8) !void {
    var sql_buf: [16 + MAX_CHANNEL_LEN * 2]u8 = undefined;
    const sql = try buildChannelSql(&sql_buf, "LISTEN", channel);

    _ = try conn.exec(sql, .{});
}

/// UNLISTEN a channel.
pub fn unlisten(conn: *Conn, channel: []const u8) !void {
    var sql_buf: [16 + MAX_CHANNEL_LEN * 2]u8 = undefined;
    const sql = try buildChannelSql(&sql_buf, "UNLISTEN", channel);

    _ = try conn.exec(sql, .{});
}

/// NOTIFY through pg_notify, payload fully parameterized.
pub fn send(conn: *Conn, channel: []const u8, payload: []const u8) !void {
    _ = try conn.exec("SELECT pg_notify($1, $2)", .{ channel, payload });
}

/// Deliver the next notification: pending first, then block on the wire.
///
/// Return:
/// - the notification, slices valid until the following call
/// - error.PostgrezServerError / error.PostgrezConnectionClosed
pub fn next(conn: *Conn) !?conn_mod.OwnedNotification {
    conn.freeCurrentNotification();

    if (conn.pending_notifications.items.len > 0) {
        const note = conn.pending_notifications.orderedRemove(0);
        conn.current_notification = note;

        return note;
    }

    // readMessage (not nextMessage): the transparent capture would swallow
    // the notification and keep blocking for a non-notification message
    while (true) {
        const msg = try conn.readMessage();

        switch (msg) {
            .notification => |raw_note| {
                const channel = try conn.allocator.dupe(u8, raw_note.channel);
                errdefer conn.allocator.free(channel);
                const payload = try conn.allocator.dupe(u8, raw_note.payload);

                const note = conn_mod.OwnedNotification{
                    .pid = raw_note.pid,
                    .channel = channel,
                    .payload = payload,
                };
                conn.current_notification = note;

                return note;
            },
            .notice_response, .parameter_status => {},
            .error_response => |fields| {
                conn.last_server_error.capture(fields);

                return error.PostgrezServerError;
            },
            else => return error.PostgrezProtocolViolation,
        }
    }
}

/// "<verb> \"<channel>\"" with identifier quoting.
fn buildChannelSql(buf: []u8, verb: []const u8, channel: []const u8) ![]const u8 {
    if (channel.len == 0 or channel.len > MAX_CHANNEL_LEN) return error.PostgrezBadChannelName;

    var writer = std.Io.Writer.fixed(buf);
    writer.writeAll(verb) catch return error.PostgrezBadChannelName;
    writer.writeAll(" \"") catch return error.PostgrezBadChannelName;
    for (channel) |char| {
        if (char == 0) return error.PostgrezBadChannelName;
        if (char == '"') writer.writeByte('"') catch return error.PostgrezBadChannelName;
        writer.writeByte(char) catch return error.PostgrezBadChannelName;
    }
    writer.writeAll("\"") catch return error.PostgrezBadChannelName;

    return writer.buffered();
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez: buildChannelSql quotes and escapes" {
    var buf: [16 + MAX_CHANNEL_LEN * 2]u8 = undefined;

    try testing.expectEqualStrings("LISTEN \"jobs\"", try buildChannelSql(&buf, "LISTEN", "jobs"));
    try testing.expectEqualStrings("UNLISTEN \"a\"\"b\"", try buildChannelSql(&buf, "UNLISTEN", "a\"b"));

    const long_channel: [64]u8 = @splat('x');

    try testing.expectError(error.PostgrezBadChannelName, buildChannelSql(&buf, "LISTEN", ""));
    try testing.expectError(error.PostgrezBadChannelName, buildChannelSql(&buf, "LISTEN", &long_channel));
    try testing.expectError(error.PostgrezBadChannelName, buildChannelSql(&buf, "LISTEN", "a\x00b"));
}
