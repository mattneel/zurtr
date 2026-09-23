//! Prepared statements: a named server-side statement plus cached result
//! metadata, so repeated executions skip the parse and describe rounds.
//!
//! Note:
//! - prepare() describes the statement once: parameter OIDs and result
//!   columns (with their binary-first formats) live in the statement arena.
//! - At execution the encoded parameter OID is checked against the
//!   described one: match sends binary, mismatch falls back to the text
//!   wire form (PostgreSQL casts text into any parameter type).

const std = @import("std");
const conn_mod = @import("conn.zig");
const frontend = @import("protocol/frontend.zig");
const row_mod = @import("types/row.zig");
const binary_mod = @import("types/binary.zig");
const text_mod = @import("types/text.zig");

const Conn = conn_mod.Conn;

pub const Statement = struct {
    conn: *Conn,
    arena: std.heap.ArenaAllocator,
    name_buf: [24]u8 = undefined,
    name_len: usize = 0,
    param_oids: []u32 = &.{},
    columns: []row_mod.ColumnInfo = &.{},
    result_formats: []frontend.Format = &.{},

    /// Parse + describe `sql` under a fresh server-side name.
    ///
    /// Return:
    /// - Statement ready for exec/query/rows, deinit() closes it
    /// - error.PostgrezServerError when parsing fails (see conn.lastServerError)
    pub fn prepare(conn: *Conn, sql: []const u8) !Statement {
        conn.statement_seq += 1;

        var self = Statement{
            .conn = conn,
            .arena = std.heap.ArenaAllocator.init(conn.allocator),
        };
        errdefer self.arena.deinit();

        const written_name = std.fmt.bufPrint(&self.name_buf, "postgrez_{d}", .{conn.statement_seq}) catch unreachable;
        self.name_len = written_name.len;

        conn.send_buf.clearRetainingCapacity();
        try frontend.parse(conn.allocator, &conn.send_buf, self.name(), sql, &.{});
        try frontend.describeStatement(conn.allocator, &conn.send_buf, self.name());
        try frontend.sync(conn.allocator, &conn.send_buf);
        try conn.flushSend();

        var failed = false;
        while (true) {
            const msg = try conn.nextMessage();

            switch (msg) {
                .parse_complete, .notice_response, .no_data => {},
                .parameter_description => |desc| {
                    const oids = try self.arena.allocator().alloc(u32, desc.count);

                    var oid_it = desc.iterator();
                    var index: usize = 0;
                    while (try oid_it.next()) |param_oid| : (index += 1) oids[index] = param_oid;

                    self.param_oids = oids;
                },
                .row_description => |desc| {
                    self.columns = try conn_mod.materializeColumns(self.arena.allocator(), desc);

                    const formats = try self.arena.allocator().alloc(frontend.Format, self.columns.len);
                    for (formats, self.columns) |*format, column| format.* = column.format;
                    self.result_formats = formats;
                },
                .error_response => |fields| {
                    conn.last_server_error.capture(fields);
                    failed = true;
                },
                .ready_for_query => |status| {
                    conn.transaction_status = status;
                    if (failed) return error.PostgrezServerError;

                    return self;
                },
                else => return error.PostgrezProtocolViolation,
            }
        }
    }

    /// Close the server-side statement (best effort) and free the metadata.
    pub fn deinit(self: *Statement) void {
        const conn = self.conn;

        conn.send_buf.clearRetainingCapacity();
        blk: {
            frontend.closeStatement(conn.allocator, &conn.send_buf, self.name()) catch break :blk;
            frontend.sync(conn.allocator, &conn.send_buf) catch break :blk;
            conn.flushSend() catch break :blk;
            _ = conn.readCommandCompletion() catch {};
        }

        self.arena.deinit();
    }

    pub fn name(self: *const Statement) []const u8 {
        return self.name_buf[0..self.name_len];
    }

    // --------------------------------------------------------- //

    /// Execute with no interest in rows, like conn.exec.
    pub fn exec(self: *Statement, args: anytype) !u64 {
        const conn = self.conn;

        _ = conn.query_arena.reset(.retain_capacity);
        const arena = conn.query_arena.allocator();
        const params = try encodeParamsForOids(arena, self.param_oids, args);

        conn.send_buf.clearRetainingCapacity();
        try frontend.bind(conn.allocator, &conn.send_buf, "", self.name(), &params.formats, &params.values, &.{});
        try frontend.execute(conn.allocator, &conn.send_buf, "", 0);
        try frontend.sync(conn.allocator, &conn.send_buf);
        try conn.flushSend();

        return conn.readCommandCompletion();
    }

    /// Stream the result set, like conn.rows but without the describe round.
    pub fn rows(self: *Statement, args: anytype) !conn_mod.Result {
        const conn = self.conn;

        _ = conn.query_arena.reset(.retain_capacity);
        const arena = conn.query_arena.allocator();
        const params = try encodeParamsForOids(arena, self.param_oids, args);

        conn.send_buf.clearRetainingCapacity();
        try frontend.bind(conn.allocator, &conn.send_buf, "", self.name(), &params.formats, &params.values, self.result_formats);
        try frontend.execute(conn.allocator, &conn.send_buf, "", 0);
        try frontend.sync(conn.allocator, &conn.send_buf);
        try conn.flushSend();

        return .{
            .conn = conn,
            .columns = self.columns,
            .cells = try arena.alloc(?[]const u8, self.columns.len),
        };
    }

    /// Queue one execution without touching the wire: several sendRows
    /// (across statements of the same connection) share one round trip.
    ///
    /// Note:
    /// - config.max_pending_replies bounds the queued executions (0 = no
    ///   bound), at the bound sendRows sheds with error.PostgrezQueueFull: await
    ///   the queued results first.
    /// - No other queries on the connection until every queued result was
    ///   consumed by awaitRows.
    ///
    /// Usage:
    /// ```zig
    /// try statement_a.sendRows(.{1});
    /// try statement_b.sendRows(.{2});
    /// var result_a = try statement_a.awaitRows(); // Sync + flush happen here
    /// // drive result_a to the end before the next awaitRows
    /// var result_b = try statement_b.awaitRows();
    /// ```
    ///
    /// Return:
    /// - void on success (awaitRows sends the batch and reads the result)
    /// - error.PostgrezQueueFull when max_pending_replies is set and reached
    pub fn sendRows(self: *Statement, args: anytype) !void {
        const conn = self.conn;
        const bound = conn.config.max_pending_replies;
        if (bound != 0 and conn.batch_pending >= bound) return error.PostgrezQueueFull;

        if (conn.batch_pending == 0) {
            _ = conn.query_arena.reset(.retain_capacity);
            conn.send_buf.clearRetainingCapacity();
            conn.batch_flushed = false;
            conn.batch_aborted = false;
        }

        const arena = conn.query_arena.allocator();
        const params = try encodeParamsForOids(arena, self.param_oids, args);

        try frontend.bind(conn.allocator, &conn.send_buf, "", self.name(), &params.formats, &params.values, self.result_formats);
        try frontend.execute(conn.allocator, &conn.send_buf, "", 0);

        conn.batch_pending += 1;
    }

    /// Take the next queued result, in sendRows order (call it on the
    /// statement that queued that execution). The first awaitRows of a
    /// batch appends the Sync and flushes: one send, one receive burst for
    /// the whole batch.
    ///
    /// Note:
    /// - Drive each Result to the end (next() until null, or deinit) before
    ///   the next awaitRows.
    /// - Results share the per-query arena: all stay valid until the next
    ///   batch or query on this connection.
    ///
    /// Return:
    /// - conn.Result for the oldest queued execution
    /// - error.PostgrezBatchEmpty when nothing was queued
    /// - error.PostgrezBatchAborted when an earlier statement of the batch failed
    ///   (the server discarded this one until Sync)
    pub fn awaitRows(self: *Statement) !conn_mod.Result {
        const conn = self.conn;
        if (conn.batch_pending == 0) return error.PostgrezBatchEmpty;

        if (conn.batch_aborted) {
            conn.batch_pending -= 1;
            if (conn.batch_pending == 0) conn.batch_aborted = false;

            return error.PostgrezBatchAborted;
        }

        if (!conn.batch_flushed) {
            try frontend.sync(conn.allocator, &conn.send_buf);
            try conn.flushSend();
            conn.batch_flushed = true;
        }

        conn.batch_pending -= 1;

        return .{
            .conn = conn,
            .columns = self.columns,
            .cells = try conn.query_arena.allocator().alloc(?[]const u8, self.columns.len),
            .batched = true,
        };
    }

    /// All rows mapped into []T, like conn.query.
    pub fn query(self: *Statement, comptime T: type, args: anytype) ![]T {
        var result = try self.rows(args);
        defer result.deinit();

        var list: std.ArrayList(T) = .empty;
        errdefer list.deinit(self.conn.allocator);

        while (try result.next()) |row_view| {
            const item = try row_mod.parseRow(T, self.conn.allocator, result.columns, row_view.cells, .{});
            try list.append(self.conn.allocator, item);
        }

        return list.toOwnedSlice(self.conn.allocator);
    }

    /// First row mapped into T, null on an empty result.
    pub fn queryRow(self: *Statement, comptime T: type, args: anytype) !?T {
        var result = try self.rows(args);
        defer result.deinit();

        const first = (try result.next()) orelse return null;

        return try row_mod.parseRow(T, self.conn.allocator, result.columns, first.cells, .{});
    }
};

// --------------------------------------------------------- //

/// Encode args against the described parameter OIDs: binary when the
/// type-picked OID matches (or was left to inference), text otherwise.
///
/// Return:
/// - the parallel Bind arrays
/// - error.PostgrezParamCountMismatch when args and the statement disagree
pub fn encodeParamsForOids(arena: std.mem.Allocator, param_oids: []const u32, args: anytype) !conn_mod.Params(row_mod.fieldCount(@TypeOf(args))) {
    const count = comptime row_mod.fieldCount(@TypeOf(args));
    if (count != param_oids.len) return error.PostgrezParamCountMismatch;

    var out: conn_mod.Params(count) = undefined;
    inline for (0..count) |index| {
        const encoded = try binary_mod.encode(arena, args[index]);

        if (encoded.bytes == null or encoded.oid == 0 or encoded.oid == param_oids[index]) {
            out.oids[index] = encoded.oid;
            out.formats[index] = encoded.format;
            out.values[index] = encoded.bytes;
        } else {
            out.oids[index] = param_oids[index];
            out.formats[index] = .TEXT;
            out.values[index] = try text_mod.encode(arena, args[index]);
        }
    }

    return out;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez: encodeParamsForOids binary on match, text on mismatch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // int8 arg against described int8: stays binary
    const matched = try encodeParamsForOids(allocator, &.{20}, .{@as(i64, 7)});
    try testing.expectEqual(frontend.Format.BINARY, matched.formats[0]);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 7 }, matched.values[0].?);

    // i64 arg against described int4: falls back to text "7"
    const fallback = try encodeParamsForOids(allocator, &.{23}, .{@as(i64, 7)});
    try testing.expectEqual(frontend.Format.TEXT, fallback.formats[0]);
    try testing.expectEqualStrings("7", fallback.values[0].?);

    // string arg (oid 0, inference) passes through against anything
    const inferred = try encodeParamsForOids(allocator, &.{25}, .{"hello"});
    try testing.expectEqualStrings("hello", inferred.values[0].?);

    // null passes through
    const with_null = try encodeParamsForOids(allocator, &.{23}, .{@as(?i32, null)});
    try testing.expectEqual(@as(?[]const u8, null), with_null.values[0]);
}

test "postgrez: encodeParamsForOids rejects a count mismatch" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expectError(error.PostgrezParamCountMismatch, encodeParamsForOids(arena.allocator(), &.{ 20, 23 }, .{@as(i64, 7)}));
}
