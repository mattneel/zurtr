//! COPY IN (FROM STDIN) and COPY OUT (TO STDOUT) over the simple query
//! protocol.
//!
//! Note:
//! - CopyIn buffers writes and flushes in chunks: call finish() (or
//!   abort()) to end the stream, only then is the connection reusable.
//! - CopyOut.next() returns raw chunks as the server framed them (one
//!   text-format row per chunk in practice). The slice points into the
//!   receive buffer: valid until the next call.

const std = @import("std");
const conn_mod = @import("conn.zig");
const frontend = @import("protocol/frontend.zig");
const backend = @import("protocol/backend.zig");

const Conn = conn_mod.Conn;

/// Flush threshold for buffered CopyData chunks.
const COPY_FLUSH_LEN = 8 * 1024;

pub const CopyIn = struct {
    conn: *Conn,

    /// Issue the COPY ... FROM STDIN statement.
    pub fn begin(conn: *Conn, sql: []const u8) !CopyIn {
        try startCopy(conn, sql);

        while (true) {
            const msg = try conn.nextMessage();

            switch (msg) {
                .copy_in_response => return .{ .conn = conn },
                .notice_response => {},
                .error_response => |fields| {
                    conn.last_server_error.capture(fields);
                    try drainToReady(conn);

                    return error.PostgrezServerError;
                },
                else => return error.PostgrezProtocolViolation,
            }
        }
    }

    /// Queue one chunk of COPY payload (text format: rows end with \n).
    pub fn write(self: *CopyIn, data: []const u8) !void {
        const conn = self.conn;

        try frontend.copyData(conn.allocator, &conn.send_buf, data);

        if (conn.send_buf.items.len >= COPY_FLUSH_LEN) try conn.flushSend();
    }

    /// End the stream.
    ///
    /// Return:
    /// - rows copied (CommandComplete tag)
    /// - error.PostgrezServerError when the server rejected the data
    pub fn finish(self: *CopyIn) !u64 {
        const conn = self.conn;

        try frontend.copyDone(conn.allocator, &conn.send_buf);
        try conn.flushSend();

        var affected: u64 = 0;
        var failed = false;
        while (true) {
            const msg = try conn.nextMessage();

            switch (msg) {
                .notice_response => {},
                .command_complete => |tag| affected = backend.commandCompleteRows(tag),
                .error_response => |fields| {
                    conn.last_server_error.capture(fields);
                    failed = true;
                },
                .ready_for_query => |status| {
                    conn.transaction_status = status;
                    if (failed) return error.PostgrezServerError;

                    return affected;
                },
                else => return error.PostgrezProtocolViolation,
            }
        }
    }

    /// Abort the stream with a reason, the server answers with an error
    /// that is swallowed here (aborting was the intent).
    pub fn abort(self: *CopyIn, reason: []const u8) !void {
        const conn = self.conn;

        try frontend.copyFail(conn.allocator, &conn.send_buf, reason);
        try conn.flushSend();

        while (true) {
            const msg = try conn.nextMessage();

            switch (msg) {
                .notice_response => {},
                .error_response => |fields| conn.last_server_error.capture(fields),
                .ready_for_query => |status| {
                    conn.transaction_status = status;

                    return;
                },
                else => return error.PostgrezProtocolViolation,
            }
        }
    }
};

// --------------------------------------------------------- //

pub const CopyOut = struct {
    conn: *Conn,
    done: bool = false,
    failed: bool = false,

    /// Issue the COPY ... TO STDOUT statement.
    pub fn begin(conn: *Conn, sql: []const u8) !CopyOut {
        try startCopy(conn, sql);

        while (true) {
            const msg = try conn.nextMessage();

            switch (msg) {
                .copy_out_response => return .{ .conn = conn },
                .notice_response => {},
                .error_response => |fields| {
                    conn.last_server_error.capture(fields);
                    try drainToReady(conn);

                    return error.PostgrezServerError;
                },
                else => return error.PostgrezProtocolViolation,
            }
        }
    }

    /// Next chunk, null when the copy ended. Must be driven to null (or
    /// deinit() called) before the connection is reusable.
    pub fn next(self: *CopyOut) !?[]const u8 {
        if (self.done) return null;

        while (true) {
            const msg = try self.conn.nextMessage();

            switch (msg) {
                .copy_data => |chunk| return chunk,
                .copy_done, .command_complete, .notice_response => {},
                .error_response => |fields| {
                    self.conn.last_server_error.capture(fields);
                    self.failed = true;
                },
                .ready_for_query => |status| {
                    self.conn.transaction_status = status;
                    self.done = true;
                    if (self.failed) return error.PostgrezServerError;

                    return null;
                },
                else => return error.PostgrezProtocolViolation,
            }
        }
    }

    /// Drain the remaining chunks so the connection is reusable.
    pub fn deinit(self: *CopyOut) void {
        while (true) {
            const maybe_chunk = self.next() catch return;
            if (maybe_chunk == null) return;
        }
    }
};

// --------------------------------------------------------- //

fn startCopy(conn: *Conn, sql: []const u8) !void {
    conn.send_buf.clearRetainingCapacity();
    try frontend.query(conn.allocator, &conn.send_buf, sql);
    try conn.flushSend();
}

fn drainToReady(conn: *Conn) !void {
    while (true) {
        const msg = try conn.nextMessage();

        switch (msg) {
            .ready_for_query => |status| {
                conn.transaction_status = status;

                return;
            },
            else => {},
        }
    }
}
