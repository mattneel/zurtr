//! The query protocol for one connection, from the first ReadyForQuery to the
//! client hanging up.
//!
//! Note:
//! - Both query forms are served: the simple 'Q' path and the extended
//!   Parse / Bind / Describe / Execute cycle. The driver uses the extended one
//!   for everything except a bare exec of literal SQL, so both must work.
//! - Flush and Sync are not the same thing and the difference matters. The
//!   driver's row path sends Parse, Describe, Flush and then waits, so a
//!   backend that only answered on Sync would hang it.
//! - After an error the extended protocol skips everything until Sync, which
//!   is what lets a failed statement inside a pipeline not corrupt the ones
//!   behind it. That skip is modelled here.
//! - Statements whose answer depends on connection state (BEGIN, LISTEN,
//!   pg_backend_pid) are handled before the catalog is consulted, because
//!   their result is not a property of the text.

const std = @import("std");

const backend = @import("backend.zig");
const catalog_mod = @import("catalog.zig");
const clients = @import("clients.zig");
const frontend = @import("frontend.zig");
const message = @import("message.zig");
const options_mod = @import("options.zig");
const transport_mod = @import("transport.zig");
const value_mod = @import("value.zig");

/// Ceiling for one reply flight. A COPY out of the default catalog is the
/// largest the shipped suites produce, well inside this.
const REPLY_BUF_SIZE = 256 * 1024;

/// SQLSTATE for a statement the backend refused outright.
const SYNTAX_ERROR = "42601";

pub const Error = error{
    PostgrezConnectionClosed,
    PostgrezMalformedMessage,
    PostgrezMessageTooLarge,
    PostgrezTruncated,
    WriteFailed,
    OutOfMemory,
    /// The client sent Terminate, or the connection is finished for any other
    /// orderly reason.
    PostgrezDone,
};

/// A parsed statement: its text plus whatever parameter types the client
/// declared. A Describe hands those back, which is what a real backend does
/// when the client specified them.
const Prepared = struct {
    sql: []const u8,
    param_oids: []const u32,
};

/// A bound portal: the statement it came from plus how the client wants the
/// rows back.
const Portal = struct {
    sql: []const u8,
    /// Bind asked for at least one binary result column. The driver picks
    /// formats from the column OIDs, so in practice this is all or nothing.
    binary_results: bool,
    parameters: []const frontend.BoundParameter,
};

pub const Session = struct {
    allocator: std.mem.Allocator,
    options: options_mod.Options,
    client: *clients.Client,
    registry: *clients.Registry,
    transport: *transport_mod.Transport,

    /// Lives as long as the connection: statement and portal names, their SQL,
    /// and the channels this session listens on.
    state_arena: std.heap.ArenaAllocator,
    /// Reset before every message.
    message_arena: std.heap.ArenaAllocator,

    transaction: backend.TransactionStatus = .IDLE,
    statements: std.StringHashMapUnmanaged(Prepared) = .empty,
    portals: std.StringHashMapUnmanaged(Portal) = .empty,
    listening: std.ArrayList([]const u8) = .empty,

    /// An error is outstanding, so everything until Sync is skipped.
    failed: bool = false,

    reply_buf: []u8,
    reply: message.Writer = undefined,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        options: options_mod.Options,
        client: *clients.Client,
        registry: *clients.Registry,
        transport: *transport_mod.Transport,
    ) !Self {
        const reply_buf = try allocator.alloc(u8, REPLY_BUF_SIZE);

        return .{
            .allocator = allocator,
            .options = options,
            .client = client,
            .registry = registry,
            .transport = transport,
            .state_arena = std.heap.ArenaAllocator.init(allocator),
            .message_arena = std.heap.ArenaAllocator.init(allocator),
            .reply_buf = reply_buf,
        };
    }

    pub fn deinit(self: *Self) void {
        self.message_arena.deinit();
        self.state_arena.deinit();
        self.allocator.free(self.reply_buf);
    }

    /// Serve until the client hangs up or the connection breaks.
    pub fn run(self: *Self) void {
        self.reply = .{ .buf = self.reply_buf };

        while (!self.client.killed.load(.acquire)) {
            _ = self.message_arena.reset(.retain_capacity);

            const msg = frontend.readMessage(self.transport, self.message_arena.allocator()) catch return;
            self.handle(msg) catch return;
        }
    }

    // --------------------------------------------------------- //

    fn handle(self: *Self, msg: frontend.Message) Error!void {
        // Sync always lands, even mid-failure: it is what ends the skip.
        if (msg == .sync) {
            self.failed = false;
            backend.readyForQuery(&self.reply, self.transaction);

            return self.flushReply();
        }

        if (msg == .flush) return self.flushReply();
        if (msg == .terminate) return error.PostgrezDone;

        if (self.failed) return;

        switch (msg) {
            .query => |sql| try self.simpleQuery(sql),
            .parse => |parse| try self.handleParse(parse),
            .bind => |bind| try self.handleBind(bind),
            .describe => |target| try self.handleDescribe(target),
            .execute => |execute| try self.handleExecute(execute),
            .close => backend.closeComplete(&self.reply),
            // a stray COPY message outside a copy is simply ignored, which is
            // what a backend that already finished the copy does
            .copy_data, .copy_done, .copy_fail => {},
            .password => try self.fail("unexpected password message", SYNTAX_ERROR),
            .unknown => try self.fail("unrecognised message", SYNTAX_ERROR),
            .sync, .flush, .terminate => unreachable,
        }
    }

    fn flushReply(self: *Self) Error!void {
        const bytes = self.reply.finish() catch return error.PostgrezTruncated;
        try self.transport.send(bytes);
        self.reply.reset();
    }

    /// Record an error and enter the skip-until-Sync state.
    fn fail(self: *Self, text: []const u8, code: []const u8) Error!void {
        self.failed = true;
        if (self.transaction == .IN_TRANSACTION) self.transaction = .IN_FAILED_TRANSACTION;

        backend.errorResponse(&self.reply, .{ .code = code, .message = text });
    }

    fn failWith(self: *Self, notice: backend.Notice) Error!void {
        self.failed = true;
        if (self.transaction == .IN_TRANSACTION) self.transaction = .IN_FAILED_TRANSACTION;

        backend.errorResponse(&self.reply, notice);
    }

    // --------------------------------------------------------- //

    /// The simple 'Q' path: run it and finish with ReadyForQuery.
    fn simpleQuery(self: *Self, sql: []const u8) Error!void {
        if (catalog_mod.normalize(sql).len == 0) {
            backend.emptyQueryResponse(&self.reply);
        } else {
            try self.runStatement(sql, &.{}, false, true);
        }

        self.failed = false;
        backend.readyForQuery(&self.reply, self.transaction);

        return self.flushReply();
    }

    fn handleParse(self: *Self, parse: frontend.Parse) Error!void {
        const arena = self.state_arena.allocator();
        const name = try arena.dupe(u8, parse.statement_name);

        try self.statements.put(arena, name, .{
            .sql = try arena.dupe(u8, parse.sql),
            .param_oids = try arena.dupe(u32, parse.param_oids),
        });
        backend.parseComplete(&self.reply);
    }

    fn handleBind(self: *Self, bind: frontend.Bind) Error!void {
        const prepared = self.statements.get(bind.statement_name) orelse {
            return self.fail("prepared statement does not exist", "26000");
        };

        const arena = self.state_arena.allocator();
        const name = try arena.dupe(u8, bind.portal_name);

        // the parameter bytes live in the message arena, which is reset before
        // the Execute that reads them, so they have to be copied out
        const parameters = try arena.alloc(frontend.BoundParameter, bind.parameters.len);
        for (bind.parameters, parameters) |source, *target| {
            target.* = .{
                .value = if (source.value) |bytes| try arena.dupe(u8, bytes) else null,
                .binary = source.binary,
            };
        }

        try self.portals.put(arena, name, .{
            .sql = prepared.sql,
            .binary_results = bind.binary_results,
            .parameters = parameters,
        });
        backend.bindComplete(&self.reply);
    }

    fn handleDescribe(self: *Self, target: frontend.Target) Error!void {
        var sql: []const u8 = "";

        switch (target.kind) {
            'S' => {
                const prepared = self.statements.get(target.name) orelse {
                    return self.fail("prepared statement does not exist", "26000");
                };
                sql = prepared.sql;

                // A statement describe reports its parameters first. Echo the
                // types the client declared, and where it declared none, say
                // how many placeholders there are with the type unspecified,
                // which is what a backend that cannot infer them does.
                try self.describeParameters(prepared);
            },
            'P' => {
                const portal = self.portals.get(target.name) orelse {
                    return self.fail("portal does not exist", "34000");
                };
                sql = portal.sql;
            },
            else => return self.fail("invalid describe target", SYNTAX_ERROR),
        }

        const shape = self.resultShape(sql);
        if (shape) |columns| {
            // a describe happens before Bind, so the format is not settled and
            // a real backend reports text here
            try self.writeRowDescription(columns, false);

            return;
        }

        backend.noData(&self.reply);
    }

    /// ParameterDescription for a parsed statement.
    fn describeParameters(self: *Self, prepared: Prepared) Error!void {
        if (prepared.param_oids.len > 0) {
            return backend.parameterDescription(&self.reply, prepared.param_oids);
        }

        const count = countPlaceholders(prepared.sql);
        const unspecified = try self.message_arena.allocator().alloc(u32, count);
        @memset(unspecified, 0);

        backend.parameterDescription(&self.reply, unspecified);
    }

    fn handleExecute(self: *Self, execute: frontend.Execute) Error!void {
        const portal = self.portals.get(execute.portal_name) orelse {
            return self.fail("portal does not exist", "34000");
        };

        // the row description already went out with the describe, so the
        // execute contributes rows only
        try self.runStatement(portal.sql, portal.parameters, portal.binary_results, false);
    }

    // --------------------------------------------------------- //

    /// The column shape a statement produces, or null when it produces none.
    fn resultShape(self: *Self, sql: []const u8) ?[]const catalog_mod.ColumnSpec {
        if (self.builtinShape(sql)) |columns| return columns;

        const response = self.options.catalog.lookup(sql);

        return switch (response) {
            .rows => |set| set.columns,
            else => null,
        };
    }

    /// Run a statement and append its reply.
    ///
    /// Param:
    /// describe_rows - bool (also emit the RowDescription, true on the simple
    ///   path where no Describe preceded it)
    fn runStatement(
        self: *Self,
        sql: []const u8,
        parameters: []const frontend.BoundParameter,
        binary: bool,
        describe_rows: bool,
    ) Error!void {
        if (self.options.drop_on_statement) |marker| {
            const trimmed = catalog_mod.normalize(sql);
            if (std.mem.startsWith(u8, trimmed, marker)) return error.PostgrezConnectionClosed;
        }

        if (try self.runBuiltin(sql, parameters, binary, describe_rows)) return;

        switch (self.options.catalog.lookup(sql)) {
            .rows => |set| try self.writeResultSet(set, binary, describe_rows),
            .command => |tag| backend.commandComplete(&self.reply, tag),
            .failure => |notice| try self.failWith(notice),
            .copy_in => |copy| try self.runCopyIn(copy),
            .copy_out => |copy| try self.runCopyOut(copy),
        }
    }

    fn writeResultSet(
        self: *Self,
        set: catalog_mod.ResultSet,
        binary: bool,
        describe_rows: bool,
    ) Error!void {
        if (describe_rows) try self.writeRowDescription(set.columns, binary);

        const arena = self.message_arena.allocator();
        const cells = try arena.alloc(?[]const u8, set.columns.len);

        for (set.rows) |row| {
            for (row, cells) |cell, *encoded| encoded.* = try cell.encode(arena, binary);
            backend.dataRow(&self.reply, cells);
        }

        const tag = try std.fmt.allocPrint(arena, "{s} {d}", .{ set.tag, set.rows.len });
        backend.commandComplete(&self.reply, tag);
    }

    fn writeRowDescription(self: *Self, columns: []const catalog_mod.ColumnSpec, binary: bool) Error!void {
        const arena = self.message_arena.allocator();
        const described = try arena.alloc(backend.Column, columns.len);

        for (columns, described) |column, *entry| {
            entry.* = .{
                .name = column.name,
                .type_oid = column.type.oid(),
                .type_len = column.type.wireLength(),
                .format = if (binary) 1 else 0,
            };
        }

        backend.rowDescription(&self.reply, described);
    }

    /// COPY ... FROM STDIN: announce, then drain the client's stream.
    fn runCopyIn(self: *Self, copy: catalog_mod.CopyIn) Error!void {
        backend.copyInResponse(&self.reply, copy.column_count);
        try self.flushReply();

        var rows_seen: usize = 0;
        while (true) {
            _ = self.message_arena.reset(.retain_capacity);
            const msg = try frontend.readMessage(self.transport, self.message_arena.allocator());

            switch (msg) {
                .copy_data => |chunk| rows_seen += std.mem.count(u8, chunk, "\n"),
                .copy_done => break,
                .copy_fail => |text| return self.fail(text, "57014"),
                .terminate => return error.PostgrezDone,
                else => return self.fail("unexpected message during copy", SYNTAX_ERROR),
            }
        }

        const tag = try std.fmt.allocPrint(self.message_arena.allocator(), "{s} {d}", .{ copy.tag, rows_seen });
        backend.commandComplete(&self.reply, tag);
    }

    /// COPY ... TO STDOUT: announce, stream the chunks, finish.
    fn runCopyOut(self: *Self, copy: catalog_mod.CopyOut) Error!void {
        backend.copyOutResponse(&self.reply, copy.column_count);
        for (copy.chunks) |chunk| backend.copyData(&self.reply, chunk);
        backend.copyDone(&self.reply);

        const tag = try std.fmt.allocPrint(
            self.message_arena.allocator(),
            "{s} {d}",
            .{ copy.tag, copy.chunks.len },
        );
        backend.commandComplete(&self.reply, tag);
    }

    // --------------------------------------------------------- //

    /// The shape of a built-in that returns rows, or null.
    fn builtinShape(self: *Self, sql: []const u8) ?[]const catalog_mod.ColumnSpec {
        _ = self;
        const trimmed = catalog_mod.normalize(sql);

        if (std.ascii.eqlIgnoreCase(trimmed, "SELECT pg_backend_pid()")) return &BACKEND_PID_COLUMNS;
        if (startsWithIgnoreCase(trimmed, "SELECT pg_terminate_backend")) return &TERMINATE_COLUMNS;
        if (startsWithIgnoreCase(trimmed, "SELECT pg_notify")) return &NOTIFY_COLUMNS;

        return null;
    }

    /// Statements whose answer depends on this connection rather than on the
    /// statement text.
    ///
    /// Return:
    /// - true when the statement was handled here
    fn runBuiltin(
        self: *Self,
        sql: []const u8,
        parameters: []const frontend.BoundParameter,
        binary: bool,
        describe_rows: bool,
    ) Error!bool {
        const trimmed = catalog_mod.normalize(sql);

        if (matchesAny(trimmed, &.{ "BEGIN", "START TRANSACTION" })) {
            self.transaction = .IN_TRANSACTION;
            backend.commandComplete(&self.reply, "BEGIN");

            return true;
        }

        if (matchesAny(trimmed, &.{ "COMMIT", "END" })) {
            self.transaction = .IDLE;
            backend.commandComplete(&self.reply, "COMMIT");

            return true;
        }

        if (matchesAny(trimmed, &.{ "ROLLBACK", "ABORT" })) {
            self.transaction = .IDLE;
            backend.commandComplete(&self.reply, "ROLLBACK");

            return true;
        }

        if (startsWithIgnoreCase(trimmed, "LISTEN ")) {
            const arena = self.state_arena.allocator();
            const channel = try unquoteIdentifier(arena, trimmed["LISTEN ".len..]);

            try self.listening.append(arena, channel);
            backend.commandComplete(&self.reply, "LISTEN");

            return true;
        }

        if (startsWithIgnoreCase(trimmed, "UNLISTEN ")) {
            const channel = try unquoteIdentifier(self.message_arena.allocator(), trimmed["UNLISTEN ".len..]);

            self.dropChannel(channel);
            backend.commandComplete(&self.reply, "UNLISTEN");

            return true;
        }

        if (std.ascii.eqlIgnoreCase(trimmed, "SELECT pg_backend_pid()")) {
            try self.writeSingleRow(&BACKEND_PID_COLUMNS, &.{.{ .int4 = self.client.pid }}, binary, describe_rows);

            return true;
        }

        if (startsWithIgnoreCase(trimmed, "SELECT pg_terminate_backend")) {
            const victim = firstParameterAsInt(parameters) orelse 0;
            const terminated = self.registry.terminate(victim);
            try self.writeSingleRow(&TERMINATE_COLUMNS, &.{.{ .boolean = terminated }}, binary, describe_rows);

            return true;
        }

        if (startsWithIgnoreCase(trimmed, "SELECT pg_notify")) {
            try self.deliverNotify(parameters);
            try self.writeSingleRow(&NOTIFY_COLUMNS, &.{.null}, binary, describe_rows);

            return true;
        }

        return false;
    }

    fn writeSingleRow(
        self: *Self,
        columns: []const catalog_mod.ColumnSpec,
        row: []const value_mod.Value,
        binary: bool,
        describe_rows: bool,
    ) Error!void {
        const set = catalog_mod.ResultSet{
            .columns = columns,
            .rows = &.{row},
        };

        return self.writeResultSet(set, binary, describe_rows);
    }

    /// NOTIFY reaches a session that is listening on the channel. Only this
    /// session is considered, which is what a suite on one connection needs
    /// and what a real backend also does for a self-notify.
    fn deliverNotify(self: *Self, parameters: []const frontend.BoundParameter) Error!void {
        if (parameters.len < 1) return;

        const channel = parameters[0].value orelse return;
        const payload = if (parameters.len > 1) (parameters[1].value orelse "") else "";

        for (self.listening.items) |listened| {
            if (!std.mem.eql(u8, listened, channel)) continue;

            backend.notificationResponse(&self.reply, self.client.pid, channel, payload);

            return;
        }
    }

    fn dropChannel(self: *Self, channel: []const u8) void {
        for (self.listening.items, 0..) |listened, index| {
            if (!std.mem.eql(u8, listened, channel)) continue;

            _ = self.listening.orderedRemove(index);

            return;
        }
    }
};

const BACKEND_PID_COLUMNS = [_]catalog_mod.ColumnSpec{.{ .name = "pg_backend_pid", .type = .INT4 }};
const TERMINATE_COLUMNS = [_]catalog_mod.ColumnSpec{.{ .name = "pg_terminate_backend", .type = .BOOL }};
const NOTIFY_COLUMNS = [_]catalog_mod.ColumnSpec{.{ .name = "pg_notify", .type = .TEXT }};

/// Undo the identifier quoting LISTEN and UNLISTEN apply: surrounding double
/// quotes removed, doubled inner quotes collapsed back to one.
fn unquoteIdentifier(arena: std.mem.Allocator, raw: []const u8) error{OutOfMemory}![]const u8 {
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return arena.dupe(u8, raw);

    const inner = raw[1 .. raw.len - 1];
    var out: std.ArrayList(u8) = .empty;

    var index: usize = 0;
    while (index < inner.len) : (index += 1) {
        try out.append(arena, inner[index]);
        if (inner[index] == '"' and index + 1 < inner.len and inner[index + 1] == '"') index += 1;
    }

    return out.toOwnedSlice(arena);
}

/// How many distinct $N placeholders a statement carries, by the highest N.
fn countPlaceholders(sql: []const u8) usize {
    var highest: usize = 0;
    var index: usize = 0;

    while (index < sql.len) : (index += 1) {
        if (sql[index] != '$') continue;

        var end = index + 1;
        while (end < sql.len and std.ascii.isDigit(sql[end])) end += 1;
        if (end == index + 1) continue;

        const number = std.fmt.parseInt(usize, sql[index + 1 .. end], 10) catch continue;
        if (number > highest) highest = number;
        index = end - 1;
    }

    return highest;
}

fn startsWithIgnoreCase(text: []const u8, prefix: []const u8) bool {
    if (text.len < prefix.len) return false;

    return std.ascii.eqlIgnoreCase(text[0..prefix.len], prefix);
}

fn matchesAny(text: []const u8, candidates: []const []const u8) bool {
    for (candidates) |candidate| {
        if (std.ascii.eqlIgnoreCase(text, candidate)) return true;
    }

    return false;
}

/// The first bound parameter read as an integer.
///
/// Note:
/// - The format decides, not the length: a four-byte text value and a binary
///   int4 are the same size on the wire.
fn firstParameterAsInt(parameters: []const frontend.BoundParameter) ?i32 {
    if (parameters.len == 0) return null;

    const parameter = parameters[0];
    const raw = parameter.value orelse return null;

    if (parameter.binary) {
        if (raw.len != 4) return null;

        return std.mem.readInt(i32, raw[0..4], .big);
    }

    return std.fmt.parseInt(i32, raw, 10) catch null;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez inproc: session recognises the transaction control words" {
    try testing.expect(matchesAny("BEGIN", &.{ "BEGIN", "START TRANSACTION" }));
    try testing.expect(matchesAny("begin", &.{ "BEGIN", "START TRANSACTION" }));
    try testing.expect(matchesAny("START TRANSACTION", &.{ "BEGIN", "START TRANSACTION" }));
    try testing.expect(!matchesAny("BEGINNING", &.{"BEGIN"}));
}

test "postgrez inproc: session prefix match ignores case" {
    try testing.expect(startsWithIgnoreCase("SELECT pg_notify($1, $2)", "SELECT pg_notify"));
    try testing.expect(startsWithIgnoreCase("select PG_NOTIFY($1)", "SELECT pg_notify"));
    try testing.expect(!startsWithIgnoreCase("SELECT", "SELECT pg_notify"));
}

test "postgrez inproc: session reads a bound integer by its declared format" {
    const binary = [_]u8{ 0, 0, 0x10, 0x92 };

    try testing.expectEqual(@as(i32, 4242), firstParameterAsInt(&.{
        .{ .value = &binary, .binary = true },
    }).?);

    // the same four bytes as text are a different number entirely, which is
    // why the format has to be carried rather than guessed
    try testing.expectEqual(@as(i32, 4242), firstParameterAsInt(&.{
        .{ .value = "4242", .binary = false },
    }).?);

    try testing.expectEqual(@as(?i32, null), firstParameterAsInt(&.{
        .{ .value = null, .binary = true },
    }));
    try testing.expectEqual(@as(?i32, null), firstParameterAsInt(&.{}));
}
