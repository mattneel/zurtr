//! What the in-process backend answers for a given statement.
//!
//! Note:
//! - The backend runs no SQL. A statement is looked up by its text and answered
//!   with a canned result, which is enough to drive every wire path the driver
//!   has: parse, bind, describe, execute, row decode, error mapping, COPY.
//!   What it deliberately does not test is whether a query means what its
//!   author intended, and that is what the container suite is still for.
//! - A suite that needs its own statements passes its own entries. The default
//!   set below covers the shapes the shipped suites use.
//! - Statements the session handles itself (BEGIN, LISTEN, pg_backend_pid and
//!   friends) never reach here, because their answers depend on connection
//!   state rather than on the text alone.

const std = @import("std");

const backend = @import("backend.zig");
const value_mod = @import("value.zig");

pub const Value = value_mod.Value;

pub const ColumnSpec = struct {
    name: []const u8,
    type: value_mod.ValueType,
};

pub const ResultSet = struct {
    columns: []const ColumnSpec,
    rows: []const []const Value,
    /// Completion tag stem. The row count is appended, giving `SELECT 2`.
    tag: []const u8 = "SELECT",
};

pub const CopyIn = struct {
    column_count: u16 = 1,
    /// Sent once the client finishes the stream, with the row count appended.
    tag: []const u8 = "COPY",
};

pub const CopyOut = struct {
    column_count: u16 = 1,
    /// One CopyData message per chunk.
    chunks: []const []const u8,
    tag: []const u8 = "COPY",
};

pub const Response = union(enum) {
    rows: ResultSet,
    /// A statement with no result set, carrying its whole completion tag.
    command: []const u8,
    /// An ErrorResponse, which also puts the session's transaction into the
    /// failed state when one is open.
    failure: backend.Notice,
    copy_in: CopyIn,
    copy_out: CopyOut,
};

pub const Entry = struct {
    /// Matched against the statement text, case insensitively, after leading
    /// and trailing space and any trailing semicolon are trimmed.
    sql: []const u8,
    /// Match `sql` as a prefix instead of the whole statement.
    prefix: bool = false,
    response: Response,
};

pub const Catalog = struct {
    entries: []const Entry = &DEFAULT_ENTRIES,
    /// Answer for a statement no entry matched. A command tag by default, so
    /// an unplanned statement is quietly harmless rather than a failure that
    /// looks like a driver bug.
    fallback: Response = .{ .command = "SELECT 0" },

    /// The response for one statement.
    pub fn lookup(self: Catalog, sql: []const u8) Response {
        const trimmed = normalize(sql);

        for (self.entries) |entry| {
            const candidate = normalize(entry.sql);
            const hit = if (entry.prefix)
                trimmed.len >= candidate.len and std.ascii.eqlIgnoreCase(trimmed[0..candidate.len], candidate)
            else
                std.ascii.eqlIgnoreCase(trimmed, candidate);

            if (hit) return entry.response;
        }

        return self.fallback;
    }
};

/// Trim surrounding space and a trailing semicolon, so `SELECT 1;` and
/// ` select 1 ` both find the same entry.
pub fn normalize(sql: []const u8) []const u8 {
    var trimmed = std.mem.trim(u8, sql, " \t\r\n");
    while (trimmed.len > 0 and trimmed[trimmed.len - 1] == ';') {
        trimmed = std.mem.trim(u8, trimmed[0 .. trimmed.len - 1], " \t\r\n");
    }

    return trimmed;
}

// --------------------------------------------------------- //

const USER_COLUMNS = [_]ColumnSpec{
    .{ .name = "id", .type = .INT4 },
    .{ .name = "email", .type = .TEXT },
    .{ .name = "active", .type = .BOOL },
};

const USER_ROWS = [_][]const Value{
    &.{ .{ .int4 = 1 }, .{ .text = "ada@example.com" }, .{ .boolean = true } },
    &.{ .{ .int4 = 2 }, .{ .text = "grace@example.com" }, .{ .boolean = false } },
};

const TYPED_COLUMNS = [_]ColumnSpec{
    .{ .name = "small", .type = .INT2 },
    .{ .name = "whole", .type = .INT4 },
    .{ .name = "big", .type = .INT8 },
    .{ .name = "ratio", .type = .FLOAT8 },
    .{ .name = "label", .type = .TEXT },
    .{ .name = "flag", .type = .BOOL },
    .{ .name = "document", .type = .JSONB },
};

const TYPED_ROWS = [_][]const Value{
    &.{
        .{ .int2 = -300 },
        .{ .int4 = 70000 },
        .{ .int8 = -9_000_000_000 },
        .{ .float8 = 9.5 },
        .{ .text = "widget" },
        .{ .boolean = true },
        .{ .jsonb = "{\"kind\":\"tool\"}" },
    },
};

const NULLABLE_COLUMNS = [_]ColumnSpec{
    .{ .name = "id", .type = .INT4 },
    .{ .name = "note", .type = .TEXT },
};

const NULLABLE_ROWS = [_][]const Value{
    &.{ .{ .int4 = 1 }, .{ .text = "present" } },
    &.{ .{ .int4 = 2 }, .null },
};

const LEDGER_CHUNKS = [_][]const u8{
    "1\tone\n",
    "2\ttwo\n",
    "3\tthree\n",
};

/// The statements the shipped suites use. A suite with other needs passes its
/// own entries rather than growing this list.
pub const DEFAULT_ENTRIES = [_]Entry{
    .{
        .sql = "SELECT 1",
        .response = .{ .rows = .{
            .columns = &.{.{ .name = "?column?", .type = .INT4 }},
            .rows = &.{&.{.{ .int4 = 1 }}},
        } },
    },
    .{
        .sql = "SELECT * FROM users",
        .prefix = true,
        .response = .{ .rows = .{ .columns = &USER_COLUMNS, .rows = &USER_ROWS } },
    },
    .{
        .sql = "SELECT * FROM typed",
        .prefix = true,
        .response = .{ .rows = .{ .columns = &TYPED_COLUMNS, .rows = &TYPED_ROWS } },
    },
    .{
        .sql = "SELECT * FROM nullable",
        .prefix = true,
        .response = .{ .rows = .{ .columns = &NULLABLE_COLUMNS, .rows = &NULLABLE_ROWS } },
    },
    .{
        .sql = "SELECT * FROM empty",
        .prefix = true,
        .response = .{ .rows = .{ .columns = &USER_COLUMNS, .rows = &.{} } },
    },
    .{
        .sql = "INSERT INTO users",
        .prefix = true,
        .response = .{ .command = "INSERT 0 1" },
    },
    .{
        .sql = "UPDATE users",
        .prefix = true,
        .response = .{ .command = "UPDATE 2" },
    },
    .{
        .sql = "DELETE FROM users",
        .prefix = true,
        .response = .{ .command = "DELETE 1" },
    },
    .{
        .sql = "INSERT INTO duplicated",
        .prefix = true,
        .response = .{ .failure = .{
            .code = "23505",
            .message = "duplicate key value violates unique constraint \"users_email_key\"",
            .constraint = "users_email_key",
        } },
    },
    .{
        .sql = "SELECT undefined_column",
        .prefix = true,
        .response = .{ .failure = .{
            .code = "42703",
            .message = "column \"undefined_column\" does not exist",
        } },
    },
    .{
        .sql = "TRUNCATE",
        .prefix = true,
        .response = .{ .command = "TRUNCATE TABLE" },
    },
    .{
        .sql = "COPY ledger FROM STDIN",
        .prefix = true,
        .response = .{ .copy_in = .{ .column_count = 2 } },
    },
    .{
        .sql = "COPY ledger TO STDOUT",
        .prefix = true,
        .response = .{ .copy_out = .{ .column_count = 2, .chunks = &LEDGER_CHUNKS } },
    },
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez inproc: catalog normalizes space and a trailing semicolon" {
    try testing.expectEqualStrings("SELECT 1", normalize("  SELECT 1;  "));
    try testing.expectEqualStrings("SELECT 1", normalize("SELECT 1"));
    try testing.expectEqualStrings("SELECT 1", normalize("\nSELECT 1 ;\n"));
    try testing.expectEqualStrings("", normalize("  ;  "));
}

test "postgrez inproc: catalog finds an exact statement regardless of case" {
    const catalog = Catalog{};

    const upper = catalog.lookup("SELECT 1");
    const lower = catalog.lookup("select 1;");

    try testing.expectEqual(@as(usize, 1), upper.rows.rows.len);
    try testing.expectEqual(@as(usize, 1), lower.rows.rows.len);
}

test "postgrez inproc: catalog matches a prefix entry" {
    const catalog = Catalog{};

    const response = catalog.lookup("SELECT * FROM users WHERE active = true ORDER BY id");

    try testing.expectEqual(@as(usize, 3), response.rows.columns.len);
    try testing.expectEqual(@as(usize, 2), response.rows.rows.len);
}

test "postgrez inproc: catalog answers an unplanned statement with the fallback" {
    const catalog = Catalog{};

    const response = catalog.lookup("SELECT something_nobody_planned");

    try testing.expectEqualStrings("SELECT 0", response.command);
}

test "postgrez inproc: catalog carries a sqlstate for a failing statement" {
    const catalog = Catalog{};

    const response = catalog.lookup("INSERT INTO duplicated (email) VALUES ('a')");

    try testing.expectEqualStrings("23505", response.failure.code);
    try testing.expectEqualStrings("users_email_key", response.failure.constraint.?);
}

test "postgrez inproc: catalog describes the copy directions apart" {
    const catalog = Catalog{};

    const in_response = catalog.lookup("COPY ledger FROM STDIN");
    const out_response = catalog.lookup("COPY ledger TO STDOUT");

    try testing.expectEqual(@as(u16, 2), in_response.copy_in.column_count);
    try testing.expectEqual(@as(usize, 3), out_response.copy_out.chunks.len);
}

test "postgrez inproc: catalog can be replaced wholesale by a suite" {
    const entries = [_]Entry{.{
        .sql = "SELECT answer",
        .response = .{ .rows = .{
            .columns = &.{.{ .name = "answer", .type = .INT4 }},
            .rows = &.{&.{.{ .int4 = 42 }}},
        } },
    }};
    const catalog = Catalog{ .entries = &entries, .fallback = .{ .command = "NOTHING" } };

    try testing.expectEqual(@as(i32, 42), catalog.lookup("SELECT answer").rows.rows[0][0].int4);
    try testing.expectEqualStrings("NOTHING", catalog.lookup("SELECT 1").command);
}

test "postgrez inproc: catalog empty result keeps its column shape" {
    const catalog = Catalog{};

    const response = catalog.lookup("SELECT * FROM empty");

    try testing.expectEqual(@as(usize, 3), response.rows.columns.len);
    try testing.expectEqual(@as(usize, 0), response.rows.rows.len);
}

test "postgrez inproc: catalog nullable rows carry a null cell" {
    const catalog = Catalog{};

    const response = catalog.lookup("SELECT * FROM nullable");

    try testing.expectEqual(Value.null, response.rows.rows[1][1]);
}
