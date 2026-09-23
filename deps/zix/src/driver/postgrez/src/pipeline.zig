//! Query pipelining: batch several statements into one send, one Sync
//! barrier, one round trip.
//!
//! Note:
//! - add() only appends to the connection send buffer, nothing hits the
//!   wire before sync().
//! - config.max_pending_replies bounds the queued statements (0 = no
//!   bound). Beyond the bound add() sheds with error.PostgrezQueueFull instead of
//!   growing memory.
//! - After a failed statement the server discards the rest of the batch
//!   until Sync: those results come back ABORTED.
//! - No other queries on the connection between begin and sync.

const std = @import("std");
const conn_mod = @import("conn.zig");
const frontend = @import("protocol/frontend.zig");
const backend = @import("protocol/backend.zig");

const Conn = conn_mod.Conn;

pub const PipelineStatus = enum {
    OK,
    FAILED,
    ABORTED,
};

pub const PipelineResult = struct {
    affected: u64 = 0,
    status: PipelineStatus = .ABORTED,
};

pub const Pipeline = struct {
    conn: *Conn,
    statement_count: usize = 0,

    /// Open a pipeline. Resets the per-query arena: results of a previous
    /// query on this connection become invalid.
    pub fn begin(conn: *Conn) !Pipeline {
        _ = conn.query_arena.reset(.retain_capacity);
        conn.send_buf.clearRetainingCapacity();

        return .{ .conn = conn };
    }

    /// Queue one statement.
    ///
    /// Return:
    /// - void on success
    /// - error.PostgrezQueueFull when max_pending_replies is set and reached
    pub fn add(self: *Pipeline, sql: []const u8, args: anytype) !void {
        const bound = self.conn.config.max_pending_replies;
        if (bound != 0 and self.statement_count >= bound) return error.PostgrezQueueFull;

        const conn = self.conn;
        const arena = conn.query_arena.allocator();
        const params = try conn_mod.encodeParams(arena, args);

        try frontend.parse(conn.allocator, &conn.send_buf, "", sql, &params.oids);
        try frontend.bind(conn.allocator, &conn.send_buf, "", "", &params.formats, &params.values, &.{});
        try frontend.execute(conn.allocator, &conn.send_buf, "", 0);

        self.statement_count += 1;
    }

    /// Send the batch and collect one result per queued statement, in add()
    /// order. The slice lives in the per-query arena: valid until the next
    /// query on this connection.
    pub fn sync(self: *Pipeline) ![]PipelineResult {
        const conn = self.conn;

        try frontend.sync(conn.allocator, &conn.send_buf);
        try conn.flushSend();

        const results = try conn.query_arena.allocator().alloc(PipelineResult, self.statement_count);
        for (results) |*result| result.* = .{};

        var index: usize = 0;
        while (true) {
            const msg = try conn.nextMessage();

            switch (msg) {
                .parse_complete, .bind_complete, .no_data, .row_description, .data_row, .notice_response => {},
                .command_complete => |tag| {
                    if (index < results.len) {
                        results[index] = .{ .affected = backend.commandCompleteRows(tag), .status = .OK };
                        index += 1;
                    }
                },
                .empty_query_response => {
                    if (index < results.len) {
                        results[index] = .{ .status = .OK };
                        index += 1;
                    }
                },
                .error_response => |fields| {
                    conn.last_server_error.capture(fields);
                    if (index < results.len) {
                        results[index] = .{ .status = .FAILED };
                        index += 1;
                    }
                },
                .ready_for_query => |status| {
                    conn.transaction_status = status;

                    return results;
                },
                else => return error.PostgrezProtocolViolation,
            }
        }
    }
};
