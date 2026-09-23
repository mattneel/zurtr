//! Comptime row to struct mapper, mirroring the std.json.parseFromSlice
//! idiom (typed struct target + options struct).
//!
//! Note:
//! - Columns bind by NAME (RowDescription) to field names, order
//!   independent.
//! - NULL is only legal into an optional field, otherwise
//!   error.PostgrezNullIntoNonOptional.
//! - Unknown result columns are an error unless ignore_unknown_columns.
//! - A field the result set does not cover falls back to its default value,
//!   no default is error.PostgrezMissingColumn.
//! - A struct or union field on a json/jsonb column goes through std.json
//!   with ignore_unknown_fields.
//! - String results are duplicated from `allocator` (arena intended), so
//!   mapped rows outlive the receive buffer.

const std = @import("std");
const oid_mod = @import("oid.zig");
const binary = @import("binary.zig");
const text = @import("text.zig");
const frontend = @import("../protocol/frontend.zig");
const ZIG_SEMVER = @import("../lib.zig").ZIG_SEMVER;

const Oid = oid_mod.Oid;
const Format = frontend.Format;

// Struct field introspection moved between Zig versions: 0.16 exposes
// info.fields (name/type/defaultValue), 0.17 exposes parallel field_names /
// field_types / field_attrs slices. These helpers are the single branch.

/// Field count of a struct or tuple type. Public because the connection
/// layer uses it to size parameter arrays from an args tuple.
pub fn fieldCount(comptime T: type) usize {
    const info = structInfo(T);

    if (comptime ZIG_SEMVER.MINOR == 16) return info.fields.len;

    return info.field_names.len;
}

fn fieldName(comptime T: type, comptime index: usize) [:0]const u8 {
    const info = structInfo(T);

    if (comptime ZIG_SEMVER.MINOR == 16) return info.fields[index].name;

    return info.field_names[index];
}

fn FieldType(comptime T: type, comptime index: usize) type {
    const info = structInfo(T);

    if (comptime ZIG_SEMVER.MINOR == 16) return info.fields[index].type;

    return info.field_types[index];
}

fn fieldDefault(comptime T: type, comptime index: usize) ?FieldType(T, index) {
    const info = structInfo(T);

    if (comptime ZIG_SEMVER.MINOR == 16) return info.fields[index].defaultValue();

    return info.field_attrs[index].defaultValue(info.field_types[index]);
}

fn structInfo(comptime T: type) @TypeOf(@typeInfo(T).@"struct") {
    return switch (@typeInfo(T)) {
        .@"struct" => |info| info,
        else => @compileError("postgrez parseRow: target must be a struct, got " ++ @typeName(T)),
    };
}

/// Column metadata the mapper needs, materialized from RowDescription.
pub const ColumnInfo = struct {
    name: []const u8,
    type_oid: u32,
    format: Format,
};

pub const ParseRowOptions = struct {
    ignore_unknown_columns: bool = false,
};

// --------------------------------------------------------- //

/// Map one row (cells in `columns` order) into a `T` value.
///
/// Param:
/// columns - []const ColumnInfo (result columns from RowDescription)
/// cells - []const ?[]const u8 (cell bytes, null is SQL NULL)
///
/// Return:
/// - T on success
/// - error.PostgrezUnknownColumn / error.PostgrezMissingColumn / error.PostgrezNullIntoNonOptional
/// - decode errors (TypeMismatch, ValueOutOfRange, BadCell) per cell
pub fn parseRow(comptime T: type, allocator: std.mem.Allocator, columns: []const ColumnInfo, cells: []const ?[]const u8, options: ParseRowOptions) !T {
    const field_count = comptime fieldCount(T);

    if (columns.len != cells.len) return error.PostgrezBadCell;

    var result: T = undefined;
    var seen: [field_count]bool = @splat(false);

    for (columns, cells) |column, cell| {
        var matched = false;

        inline for (0..field_count) |field_index| {
            const name = comptime fieldName(T, field_index);

            if (!matched and std.mem.eql(u8, name, column.name)) {
                matched = true;
                seen[field_index] = true;
                @field(result, name) = try decodeField(FieldType(T, field_index), allocator, column, cell);
            }
        }

        if (!matched and !options.ignore_unknown_columns) return error.PostgrezUnknownColumn;
    }

    inline for (0..field_count) |field_index| {
        if (!seen[field_index]) {
            if (comptime fieldDefault(T, field_index)) |default_value| {
                @field(result, fieldName(T, field_index)) = default_value;
            } else {
                return error.PostgrezMissingColumn;
            }
        }
    }

    return result;
}

/// Decode one cell into a field type, handling SQL NULL against optionals.
pub fn decodeField(comptime FieldT: type, allocator: std.mem.Allocator, column: ColumnInfo, cell: ?[]const u8) !FieldT {
    switch (@typeInfo(FieldT)) {
        .optional => |optional_info| {
            const bytes = cell orelse return null;

            return try decodeValue(optional_info.child, allocator, column, bytes);
        },
        else => {
            const bytes = cell orelse return error.PostgrezNullIntoNonOptional;

            return try decodeValue(FieldT, allocator, column, bytes);
        },
    }
}

/// Decode non-null cell bytes into a value type, allocating copies so the
/// value outlives the receive buffer.
fn decodeValue(comptime ValueT: type, allocator: std.mem.Allocator, column: ColumnInfo, bytes: []const u8) !ValueT {
    const oid: Oid = @enumFromInt(column.type_oid);

    switch (@typeInfo(ValueT)) {
        .bool, .int, .float => return try rawDecode(ValueT, oid, column.format, bytes),
        .array => return try rawDecode(ValueT, oid, column.format, bytes),
        .pointer => {
            if (ValueT != []const u8) @compileError("postgrez parseRow: unsupported slice field " ++ @typeName(ValueT) ++ ", use []const u8");

            const raw = try rawDecode([]const u8, oid, column.format, bytes);

            return try allocator.dupe(u8, raw);
        },
        .@"enum" => {
            const raw = try rawDecode([]const u8, oid, column.format, bytes);

            return std.meta.stringToEnum(ValueT, raw) orelse error.PostgrezBadCell;
        },
        .@"struct", .@"union" => {
            if (!oid_mod.isJson(oid)) return error.PostgrezTypeMismatch;

            const raw = try rawDecode([]const u8, oid, column.format, bytes);

            return std.json.parseFromSliceLeaky(ValueT, allocator, raw, .{
                .ignore_unknown_fields = true,
                .allocate = .alloc_always,
            }) catch error.PostgrezBadCell;
        },
        else => @compileError("postgrez parseRow: unsupported field type " ++ @typeName(ValueT)),
    }
}

/// Format dispatch: binary first, text fallback. No allocation, slices
/// point into `bytes`.
pub fn rawDecode(comptime ValueT: type, oid: Oid, format: Format, bytes: []const u8) binary.DecodeValueError!ValueT {
    return switch (format) {
        .BINARY => binary.decode(ValueT, oid, bytes),
        .TEXT => text.decode(ValueT, oid, bytes),
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

const SAMPLE_COLUMNS = [_]ColumnInfo{
    .{ .name = "id", .type_oid = @intFromEnum(Oid.INT8), .format = .BINARY },
    .{ .name = "name", .type_oid = @intFromEnum(Oid.TEXT), .format = .BINARY },
    .{ .name = "age", .type_oid = @intFromEnum(Oid.INT2), .format = .BINARY },
    .{ .name = "bio", .type_oid = @intFromEnum(Oid.TEXT), .format = .BINARY },
};

test "postgrez types: parseRow binds by name, order-independent" {
    const User = struct {
        name: []const u8,
        id: i64,
        age: u16,
        bio: ?[]const u8,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cells = [_]?[]const u8{
        &.{ 0, 0, 0, 0, 0, 0, 0, 7 },
        "Alice",
        &.{ 0, 30 },
        null,
    };

    const user = try parseRow(User, arena.allocator(), &SAMPLE_COLUMNS, &cells, .{});

    try testing.expectEqual(@as(i64, 7), user.id);
    try testing.expectEqualStrings("Alice", user.name);
    try testing.expectEqual(@as(u16, 30), user.age);
    try testing.expectEqual(@as(?[]const u8, null), user.bio);
}

test "postgrez types: parseRow null into non-optional errors" {
    const User = struct {
        id: i64,
        name: []const u8,
        age: u16,
        bio: []const u8,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cells = [_]?[]const u8{
        &.{ 0, 0, 0, 0, 0, 0, 0, 7 },
        "Alice",
        &.{ 0, 30 },
        null,
    };

    try testing.expectError(error.PostgrezNullIntoNonOptional, parseRow(User, arena.allocator(), &SAMPLE_COLUMNS, &cells, .{}));
}

test "postgrez types: parseRow unknown column errors unless opted out" {
    const Narrow = struct {
        id: i64,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const cells = [_]?[]const u8{
        &.{ 0, 0, 0, 0, 0, 0, 0, 7 },
        "Alice",
        &.{ 0, 30 },
        null,
    };

    try testing.expectError(error.PostgrezUnknownColumn, parseRow(Narrow, arena.allocator(), &SAMPLE_COLUMNS, &cells, .{}));

    const narrow = try parseRow(Narrow, arena.allocator(), &SAMPLE_COLUMNS, &cells, .{ .ignore_unknown_columns = true });
    try testing.expectEqual(@as(i64, 7), narrow.id);
}

test "postgrez types: parseRow missing column falls back to default" {
    const WithDefault = struct {
        id: i64,
        score: f64 = 0.5,
    };
    const WithoutDefault = struct {
        id: i64,
        score: f64,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const columns = [_]ColumnInfo{
        .{ .name = "id", .type_oid = @intFromEnum(Oid.INT8), .format = .BINARY },
    };
    const cells = [_]?[]const u8{
        &.{ 0, 0, 0, 0, 0, 0, 0, 7 },
    };

    const with_default = try parseRow(WithDefault, arena.allocator(), &columns, &cells, .{});
    try testing.expectEqual(@as(f64, 0.5), with_default.score);

    try testing.expectError(error.PostgrezMissingColumn, parseRow(WithoutDefault, arena.allocator(), &columns, &cells, .{}));
}

test "postgrez types: parseRow struct field parses json and jsonb" {
    const Profile = struct {
        theme: []const u8,
        notifications: bool,
    };
    const User = struct {
        id: i64,
        profile: Profile,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const columns = [_]ColumnInfo{
        .{ .name = "id", .type_oid = @intFromEnum(Oid.INT8), .format = .BINARY },
        .{ .name = "profile", .type_oid = @intFromEnum(Oid.JSONB), .format = .BINARY },
    };
    const jsonb_cell = [_]u8{1} ++ "{\"theme\":\"dark\",\"notifications\":true,\"extra\":1}".*;
    const cells = [_]?[]const u8{
        &.{ 0, 0, 0, 0, 0, 0, 0, 7 },
        &jsonb_cell,
    };

    const user = try parseRow(User, arena.allocator(), &columns, &cells, .{});
    try testing.expectEqualStrings("dark", user.profile.theme);
    try testing.expectEqual(true, user.profile.notifications);
}

test "postgrez types: parseRow struct field on a non-json column errors" {
    const Profile = struct { theme: []const u8 };
    const User = struct { profile: Profile };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const columns = [_]ColumnInfo{
        .{ .name = "profile", .type_oid = @intFromEnum(Oid.TEXT), .format = .BINARY },
    };
    const cells = [_]?[]const u8{"{\"theme\":\"dark\"}"};

    try testing.expectError(error.PostgrezTypeMismatch, parseRow(User, arena.allocator(), &columns, &cells, .{}));
}

test "postgrez types: parseRow enum field from text content" {
    const Kind = enum { deploy, rollback };
    const Event = struct { kind: Kind };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const columns = [_]ColumnInfo{
        .{ .name = "kind", .type_oid = @intFromEnum(Oid.TEXT), .format = .BINARY },
    };

    const cells = [_]?[]const u8{"rollback"};
    const event = try parseRow(Event, arena.allocator(), &columns, &cells, .{});
    try testing.expectEqual(Kind.rollback, event.kind);

    const bad_cells = [_]?[]const u8{"unknown_kind"};
    try testing.expectError(error.PostgrezBadCell, parseRow(Event, arena.allocator(), &columns, &bad_cells, .{}));
}

test "postgrez types: parseRow duplicates strings off the receive buffer" {
    const Named = struct { name: []const u8 };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const columns = [_]ColumnInfo{
        .{ .name = "name", .type_oid = @intFromEnum(Oid.TEXT), .format = .BINARY },
    };

    var recv_buf: [5]u8 = "Alice".*;
    const cells = [_]?[]const u8{&recv_buf};

    const named = try parseRow(Named, arena.allocator(), &columns, &cells, .{});
    @memset(&recv_buf, 'X');

    try testing.expectEqualStrings("Alice", named.name);
}

test "postgrez types: parseRow text format cells decode via fallback" {
    const User = struct {
        id: i64,
        active: bool,
    };

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const columns = [_]ColumnInfo{
        .{ .name = "id", .type_oid = @intFromEnum(Oid.INT8), .format = .TEXT },
        .{ .name = "active", .type_oid = @intFromEnum(Oid.BOOL), .format = .TEXT },
    };
    const cells = [_]?[]const u8{ "42", "t" };

    const user = try parseRow(User, arena.allocator(), &columns, &cells, .{});
    try testing.expectEqual(@as(i64, 42), user.id);
    try testing.expectEqual(true, user.active);
}
