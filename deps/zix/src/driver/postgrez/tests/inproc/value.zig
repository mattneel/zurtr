//! Typed cell values the in-process backend serves, and their two wire forms.
//!
//! Note:
//! - Rows are written as Zig values rather than pre-encoded bytes, and the
//!   backend encodes them in whatever format the client asked for at Bind time.
//!   That is what lets one catalog entry exercise both the driver's text
//!   fallback and its binary-first decoders.
//! - Only the types the driver has binary decoders for are modelled. Anything
//!   else would be answering a question the driver cannot ask.

const std = @import("std");

/// The column types the server can serve, with the OID PostgreSQL uses.
pub const ValueType = enum(u32) {
    BOOL = 16,
    INT2 = 21,
    INT4 = 23,
    INT8 = 20,
    FLOAT8 = 701,
    TEXT = 25,
    JSON = 114,
    JSONB = 3802,
    UUID = 2950,

    pub fn oid(self: ValueType) u32 {
        return @intFromEnum(self);
    }

    /// Fixed width on the wire, or -1 when the type is variable length.
    pub fn wireLength(self: ValueType) i16 {
        return switch (self) {
            .BOOL => 1,
            .INT2 => 2,
            .INT4 => 4,
            .INT8 => 8,
            .FLOAT8 => 8,
            .UUID => 16,
            .TEXT, .JSON, .JSONB => -1,
        };
    }
};

pub const Value = union(enum) {
    /// SQL NULL, which is a length of -1 on the wire in either format.
    null,
    boolean: bool,
    int2: i16,
    int4: i32,
    int8: i64,
    float8: f64,
    text: []const u8,
    json: []const u8,
    jsonb: []const u8,
    uuid: [16]u8,

    const Self = @This();

    /// The column type this value belongs under.
    pub fn valueType(self: Self) ?ValueType {
        return switch (self) {
            .null => null,
            .boolean => .BOOL,
            .int2 => .INT2,
            .int4 => .INT4,
            .int8 => .INT8,
            .float8 => .FLOAT8,
            .text => .TEXT,
            .json => .JSON,
            .jsonb => .JSONB,
            .uuid => .UUID,
        };
    }

    /// Encode for the wire.
    ///
    /// Param:
    /// arena - std.mem.Allocator (owns the returned bytes)
    /// binary - bool (true for the binary format, false for text)
    ///
    /// Return:
    /// - ?[]const u8, null for SQL NULL
    pub fn encode(self: Self, arena: std.mem.Allocator, binary: bool) !?[]const u8 {
        if (self == .null) return null;

        if (binary) return try self.encodeBinary(arena);

        return try self.encodeText(arena);
    }

    fn encodeBinary(self: Self, arena: std.mem.Allocator) ![]const u8 {
        return switch (self) {
            .null => unreachable,
            .boolean => |value| try arena.dupe(u8, if (value) &[_]u8{1} else &[_]u8{0}),
            .int2 => |value| try bigEndian(arena, i16, value),
            .int4 => |value| try bigEndian(arena, i32, value),
            .int8 => |value| try bigEndian(arena, i64, value),
            .float8 => |value| try bigEndian(arena, u64, @bitCast(value)),
            .text, .json => |value| try arena.dupe(u8, value),
            // jsonb binary carries a leading format version, always 1
            .jsonb => |value| try std.mem.concat(arena, u8, &.{ &[_]u8{1}, value }),
            .uuid => |value| try arena.dupe(u8, &value),
        };
    }

    fn encodeText(self: Self, arena: std.mem.Allocator) ![]const u8 {
        return switch (self) {
            .null => unreachable,
            .boolean => |value| try arena.dupe(u8, if (value) "t" else "f"),
            .int2 => |value| try std.fmt.allocPrint(arena, "{d}", .{value}),
            .int4 => |value| try std.fmt.allocPrint(arena, "{d}", .{value}),
            .int8 => |value| try std.fmt.allocPrint(arena, "{d}", .{value}),
            .float8 => |value| try std.fmt.allocPrint(arena, "{d}", .{value}),
            .text, .json, .jsonb => |value| try arena.dupe(u8, value),
            .uuid => |value| try formatUuid(arena, value),
        };
    }
};

fn bigEndian(arena: std.mem.Allocator, comptime T: type, value: T) ![]const u8 {
    const out = try arena.alloc(u8, @divExact(@typeInfo(T).int.bits, 8));
    std.mem.writeInt(T, out[0..@divExact(@typeInfo(T).int.bits, 8)], value, .big);

    return out;
}

/// The canonical 8-4-4-4-12 hyphenated form.
fn formatUuid(arena: std.mem.Allocator, raw: [16]u8) ![]const u8 {
    return std.fmt.allocPrint(
        arena,
        "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-" ++
            "{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
        .{
            raw[0], raw[1], raw[2],  raw[3],  raw[4],  raw[5],  raw[6],  raw[7],
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        },
    );
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

const postgrez = @import("postgrez");

/// Decode with the driver's own binary decoder, so these tests prove the two
/// sides agree rather than proving the server agrees with itself.
fn decodeBinary(comptime T: type, value: Value, arena: std.mem.Allocator) !T {
    const bytes = (try value.encode(arena, true)).?;
    const type_oid: postgrez.oid.Oid = @enumFromInt(value.valueType().?.oid());

    return postgrez.binary.decode(T, type_oid, bytes);
}

test "postgrez inproc: value null encodes as null in either format" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expectEqual(@as(?[]const u8, null), try (Value{ .null = {} }).encode(arena.allocator(), true));
    try testing.expectEqual(@as(?[]const u8, null), try (Value{ .null = {} }).encode(arena.allocator(), false));
    try testing.expectEqual(@as(?ValueType, null), (Value{ .null = {} }).valueType());
}

test "postgrez inproc: value integers round trip through the driver binary decoder" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try testing.expectEqual(@as(i16, -300), try decodeBinary(i16, .{ .int2 = -300 }, allocator));
    try testing.expectEqual(@as(i32, 70000), try decodeBinary(i32, .{ .int4 = 70000 }, allocator));
    try testing.expectEqual(@as(i64, -9_000_000_000), try decodeBinary(i64, .{ .int8 = -9_000_000_000 }, allocator));
}

test "postgrez inproc: value bool and float round trip through the driver" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try testing.expectEqual(true, try decodeBinary(bool, .{ .boolean = true }, allocator));
    try testing.expectEqual(false, try decodeBinary(bool, .{ .boolean = false }, allocator));
    try testing.expectEqual(@as(f64, 9.5), try decodeBinary(f64, .{ .float8 = 9.5 }, allocator));
}

test "postgrez inproc: value text and uuid round trip through the driver" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try testing.expectEqualStrings("widget", try decodeBinary([]const u8, .{ .text = "widget" }, allocator));

    const raw = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ++ @as([8]u8, @splat(0xff));
    try testing.expectEqualSlices(u8, &raw, &try decodeBinary([16]u8, .{ .uuid = raw }, allocator));
}

test "postgrez inproc: value jsonb binary carries the version byte the driver strips" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const document = "{\"id\":1}";
    const encoded = (try (Value{ .jsonb = document }).encode(allocator, true)).?;

    try testing.expectEqual(@as(u8, 1), encoded[0]);
    try testing.expectEqualStrings(document, try decodeBinary([]const u8, .{ .jsonb = document }, allocator));
}

test "postgrez inproc: value text format matches what postgres prints" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try testing.expectEqualStrings("t", (try (Value{ .boolean = true }).encode(allocator, false)).?);
    try testing.expectEqualStrings("f", (try (Value{ .boolean = false }).encode(allocator, false)).?);
    try testing.expectEqualStrings("-42", (try (Value{ .int4 = -42 }).encode(allocator, false)).?);
    try testing.expectEqualStrings("9.5", (try (Value{ .float8 = 9.5 }).encode(allocator, false)).?);
}

test "postgrez inproc: value uuid text takes the hyphenated form" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const raw = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef } ++ @as([8]u8, @splat(0xff));
    const text = (try (Value{ .uuid = raw }).encode(arena.allocator(), false)).?;

    try testing.expectEqualStrings("01234567-89ab-cdef-ffff-ffffffffffff", text);
}

test "postgrez inproc: value type reports the oid and wire width" {
    try testing.expectEqual(@as(u32, 23), ValueType.INT4.oid());
    try testing.expectEqual(@as(i16, 4), ValueType.INT4.wireLength());
    try testing.expectEqual(@as(i16, -1), ValueType.TEXT.wireLength());
    try testing.expectEqual(ValueType.INT8, (Value{ .int8 = 1 }).valueType().?);
}
