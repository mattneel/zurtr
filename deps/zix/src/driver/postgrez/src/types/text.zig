//! Text wire format fallback: decode cells for types without a binary
//! decoder (numeric, interval, custom types) and for simple-query results.
//!
//! Note:
//! - Bytes are the printable form PostgreSQL sends, e.g. "42", "t"/"f",
//!   "1.5", "550e8400-e29b-41d4-a716-446655440000".
//! - `[]const u8` targets return the raw text as-is (bytea stays in its
//!   "\x..." hex form, callers wanting decoded bytea should use the
//!   extended protocol where bytea arrives binary).

const std = @import("std");
const oid_mod = @import("oid.zig");
const binary = @import("binary.zig");

const Oid = oid_mod.Oid;

pub const DecodeValueError = binary.DecodeValueError;

/// Decode one text-format cell into `T`.
///
/// Return:
/// - T on success
/// - error.PostgrezValueOutOfRange when the number does not fit T
/// - error.PostgrezBadCell when the text does not parse as T
pub fn decode(comptime T: type, oid: Oid, bytes: []const u8) DecodeValueError!T {
    _ = oid;

    switch (@typeInfo(T)) {
        .bool => {
            if (bytes.len == 1 and bytes[0] == 't') return true;
            if (bytes.len == 1 and bytes[0] == 'f') return false;

            return error.PostgrezBadCell;
        },
        .int => {
            return std.fmt.parseInt(T, bytes, 10) catch |err| switch (err) {
                error.Overflow => error.PostgrezValueOutOfRange,
                error.InvalidCharacter => error.PostgrezBadCell,
            };
        },
        .float => {
            return std.fmt.parseFloat(T, bytes) catch error.PostgrezBadCell;
        },
        .pointer => {
            if (T != []const u8) @compileError("postgrez text.decode: unsupported slice type " ++ @typeName(T) ++ ", use []const u8");

            return bytes;
        },
        .array => |array_info| {
            if (array_info.child != u8 or array_info.len != 16) {
                @compileError("postgrez text.decode: unsupported array type " ++ @typeName(T) ++ ", use [16]u8 for uuid");
            }

            return parseUuid(bytes);
        },
        else => @compileError("postgrez text.decode: unsupported target type " ++ @typeName(T)),
    }
}

/// Parse the canonical uuid text form (8-4-4-4-12 hex) into 16 bytes.
fn parseUuid(text: []const u8) DecodeValueError![16]u8 {
    if (text.len != 36) return error.PostgrezBadCell;
    if (text[8] != '-' or text[13] != '-' or text[18] != '-' or text[23] != '-') return error.PostgrezBadCell;

    var out: [16]u8 = undefined;
    var out_index: usize = 0;
    var pos: usize = 0;
    while (pos < text.len) {
        if (text[pos] == '-') {
            pos += 1;
            continue;
        }

        const high = hexNibble(text[pos]) orelse return error.PostgrezBadCell;
        const low = hexNibble(text[pos + 1]) orelse return error.PostgrezBadCell;
        out[out_index] = (high << 4) | low;
        out_index += 1;
        pos += 2;
    }
    if (out_index != 16) return error.PostgrezBadCell;

    return out;
}

fn hexNibble(char: u8) ?u8 {
    return switch (char) {
        '0'...'9' => char - '0',
        'a'...'f' => char - 'a' + 10,
        'A'...'F' => char - 'A' + 10,
        else => null,
    };
}

// --------------------------------------------------------- //

/// Encode one Zig value into its text wire form (the fallback when a
/// prepared statement's described parameter OID does not match the binary
/// encoding the value's type would pick).
///
/// Return:
/// - text bytes (arena-allocated or referencing the value), null = SQL NULL
pub fn encode(arena: std.mem.Allocator, value: anytype) !?[]const u8 {
    const T = @TypeOf(value);

    switch (@typeInfo(T)) {
        .null => return null,
        .optional => {
            if (value) |inner| return encode(arena, inner);

            return null;
        },
        .comptime_int, .int => return try std.fmt.allocPrint(arena, "{d}", .{value}),
        .comptime_float, .float => return try std.fmt.allocPrint(arena, "{d}", .{value}),
        .bool => return if (value) "t" else "f",
        .pointer => |pointer_info| {
            if (T == []const u8 or T == []u8) return value;
            if (pointer_info.size == .one) {
                switch (@typeInfo(pointer_info.child)) {
                    .array => |array_info| {
                        if (array_info.child == u8) return value;
                    },
                    else => {},
                }
            }

            @compileError("postgrez text.encode: unsupported pointer type " ++ @typeName(T));
        },
        .array => |array_info| {
            if (array_info.child != u8) @compileError("postgrez text.encode: unsupported array type " ++ @typeName(T));

            return try arena.dupe(u8, &value);
        },
        .@"enum" => return @tagName(value),
        .@"struct", .@"union" => return try std.json.Stringify.valueAlloc(arena, value, .{}),
        else => @compileError("postgrez text.encode: unsupported parameter type " ++ @typeName(T)),
    }
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez types: text decode bool" {
    try testing.expectEqual(true, try decode(bool, .BOOL, "t"));
    try testing.expectEqual(false, try decode(bool, .BOOL, "f"));

    try testing.expectError(error.PostgrezBadCell, decode(bool, .BOOL, "true"));
}

test "postgrez types: text decode integers" {
    try testing.expectEqual(@as(i64, -42), try decode(i64, .INT8, "-42"));
    try testing.expectEqual(@as(u16, 300), try decode(u16, .INT4, "300"));

    try testing.expectError(error.PostgrezValueOutOfRange, decode(u8, .INT4, "300"));
    try testing.expectError(error.PostgrezBadCell, decode(i32, .INT4, "4x2"));
}

test "postgrez types: text decode floats and numeric fallback" {
    try testing.expectEqual(@as(f64, 1.5), try decode(f64, .FLOAT8, "1.5"));
    // numeric has no binary decoder, its text form parses into a float
    try testing.expectEqual(@as(f64, 12345.678), try decode(f64, .NUMERIC, "12345.678"));

    try testing.expectError(error.PostgrezBadCell, decode(f64, .NUMERIC, "abc"));
}

test "postgrez types: text decode raw slice passthrough" {
    try testing.expectEqualStrings("hello", try decode([]const u8, .TEXT, "hello"));
    try testing.expectEqualStrings("\\xdead", try decode([]const u8, .BYTEA, "\\xdead"));
}

test "postgrez types: text encode covers the parameter types" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try std.testing.expectEqualStrings("42", (try encode(allocator, @as(i64, 42))).?);
    try std.testing.expectEqualStrings("-7", (try encode(allocator, @as(i16, -7))).?);
    try std.testing.expectEqualStrings("1.5", (try encode(allocator, @as(f64, 1.5))).?);
    try std.testing.expectEqualStrings("t", (try encode(allocator, true)).?);
    try std.testing.expectEqualStrings("f", (try encode(allocator, false)).?);
    try std.testing.expectEqualStrings("hello", (try encode(allocator, @as([]const u8, "hello"))).?);
    try std.testing.expectEqualStrings("hi", (try encode(allocator, "hi")).?);

    const Kind = enum { deploy };
    try std.testing.expectEqualStrings("deploy", (try encode(allocator, Kind.deploy)).?);

    try std.testing.expectEqual(@as(?[]const u8, null), try encode(allocator, @as(?i32, null)));
    try std.testing.expectEqualStrings("5", (try encode(allocator, @as(?i32, 5))).?);
}

test "postgrez types: text decode uuid" {
    const parsed = try decode([16]u8, .UUID, "550e8400-e29b-41d4-a716-446655440000");

    try testing.expectEqualSlices(u8, &.{
        0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4,
        0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00, 0x00,
    }, &parsed);

    try testing.expectError(error.PostgrezBadCell, decode([16]u8, .UUID, "550e8400"));
    try testing.expectError(error.PostgrezBadCell, decode([16]u8, .UUID, "550e8400-e29b-41d4-a716-44665544000z"));
}
