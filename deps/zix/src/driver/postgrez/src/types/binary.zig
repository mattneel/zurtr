//! Binary wire format: decode result cells into Zig values and encode
//! query parameters (binary first, text fallback lives in text.zig).
//!
//! Note:
//! - Wire forms (all big-endian): bool 1 byte, int2/4/8 fixed width, float4/8
//!   IEEE bits, date i32 days since 2000-01-01, time i64 micros since
//!   midnight, timestamp/timestamptz i64 micros since 2000-01-01, uuid 16
//!   raw bytes, jsonb a 1-byte version prefix then the JSON text, text-like
//!   types the raw content.

const std = @import("std");
const oid_mod = @import("oid.zig");
const frontend = @import("../protocol/frontend.zig");

const Oid = oid_mod.Oid;
const Format = frontend.Format;

pub const DecodeValueError = error{
    PostgrezTypeMismatch,
    PostgrezValueOutOfRange,
    PostgrezBadCell,
};

// --------------------------------------------------------- //

/// Decode one binary-format cell into `T`.
///
/// Note:
/// - Integer targets accept any integer wire type that fits, checked at
///   runtime (int2 into u8 works for 0..255, 300 errors).
/// - `[]const u8` targets accept any OID and return the raw content
///   (jsonb has its version byte stripped). Slices point INTO `bytes`.
/// - `[16]u8` targets accept uuid.
///
/// Return:
/// - T on success
/// - error.PostgrezTypeMismatch when the OID cannot decode into T
/// - error.PostgrezValueOutOfRange when the value does not fit T
/// - error.PostgrezBadCell on a malformed cell
pub fn decode(comptime T: type, oid: Oid, bytes: []const u8) DecodeValueError!T {
    switch (@typeInfo(T)) {
        .bool => {
            if (oid != .BOOL) return error.PostgrezTypeMismatch;
            if (bytes.len != 1) return error.PostgrezBadCell;

            return bytes[0] != 0;
        },
        .int => {
            const wide = try decodeIntWide(oid, bytes);

            return std.math.cast(T, wide) orelse error.PostgrezValueOutOfRange;
        },
        .float => |float_info| {
            switch (oid) {
                .FLOAT4 => {
                    if (bytes.len != 4) return error.PostgrezBadCell;

                    const value: f32 = @bitCast(std.mem.readInt(u32, bytes[0..4], .big));

                    return @floatCast(value);
                },
                .FLOAT8 => {
                    if (float_info.bits < 64) return error.PostgrezTypeMismatch;
                    if (bytes.len != 8) return error.PostgrezBadCell;

                    const value: f64 = @bitCast(std.mem.readInt(u64, bytes[0..8], .big));

                    return @floatCast(value);
                },
                else => return error.PostgrezTypeMismatch,
            }
        },
        .pointer => {
            if (T != []const u8) @compileError("postgrez binary.decode: unsupported slice type " ++ @typeName(T) ++ ", use []const u8");

            if (oid == .JSONB) {
                if (bytes.len < 1 or bytes[0] != 1) return error.PostgrezBadCell;

                return bytes[1..];
            }

            return bytes;
        },
        .array => |array_info| {
            if (array_info.child != u8 or array_info.len != 16) {
                @compileError("postgrez binary.decode: unsupported array type " ++ @typeName(T) ++ ", use [16]u8 for uuid");
            }
            if (oid != .UUID) return error.PostgrezTypeMismatch;
            if (bytes.len != 16) return error.PostgrezBadCell;

            return bytes[0..16].*;
        },
        else => @compileError("postgrez binary.decode: unsupported target type " ++ @typeName(T)),
    }
}

/// The widest integer read for an integer-bearing OID.
fn decodeIntWide(oid: Oid, bytes: []const u8) DecodeValueError!i64 {
    switch (oid) {
        .INT2 => {
            if (bytes.len != 2) return error.PostgrezBadCell;

            return std.mem.readInt(i16, bytes[0..2], .big);
        },
        .INT4, .DATE => {
            if (bytes.len != 4) return error.PostgrezBadCell;

            return std.mem.readInt(i32, bytes[0..4], .big);
        },
        .INT8, .TIME, .TIMESTAMP, .TIMESTAMPTZ => {
            if (bytes.len != 8) return error.PostgrezBadCell;

            return std.mem.readInt(i64, bytes[0..8], .big);
        },
        .OID => {
            if (bytes.len != 4) return error.PostgrezBadCell;

            return std.mem.readInt(u32, bytes[0..4], .big);
        },
        .CHAR => {
            if (bytes.len != 1) return error.PostgrezBadCell;

            return bytes[0];
        },
        else => return error.PostgrezTypeMismatch,
    }
}

// --------------------------------------------------------- //

/// One encoded query parameter, ready for frontend.bind.
pub const EncodedParam = struct {
    oid: u32,
    format: Format,
    bytes: ?[]const u8,
};

/// Encode one Zig value as a query parameter, binary first.
///
/// Note:
/// - Integers go as typed binary (int2/int4/int8 by needed width), floats as
///   float4/float8, bool as bool. Strings and enums go as TEXT with OID 0 so
///   the server infers the type from context. Structs and unions are
///   serialized to JSON text. Optionals unwrap, null becomes SQL NULL.
/// - Returned bytes may be allocated from `allocator` (arena intended) or
///   reference the value directly, both live long enough for the bind call.
pub fn encode(allocator: std.mem.Allocator, value: anytype) !EncodedParam {
    const T = @TypeOf(value);

    switch (@typeInfo(T)) {
        .null => return .{ .oid = 0, .format = .TEXT, .bytes = null },
        .optional => {
            if (value) |inner| return encode(allocator, inner);

            return .{ .oid = 0, .format = .TEXT, .bytes = null };
        },
        .comptime_int => return encodeInt(allocator, @as(i64, value)),
        .int => return encodeInt(allocator, value),
        .comptime_float => return encodeFloat(allocator, @as(f64, value)),
        .float => return encodeFloat(allocator, value),
        .bool => {
            const bytes = try allocator.alloc(u8, 1);
            bytes[0] = @intFromBool(value);

            return .{ .oid = @intFromEnum(Oid.BOOL), .format = .BINARY, .bytes = bytes };
        },
        .pointer => |pointer_info| {
            if (T == []const u8 or T == []u8) {
                return .{ .oid = 0, .format = .TEXT, .bytes = value };
            }
            if (pointer_info.size == .one) {
                switch (@typeInfo(pointer_info.child)) {
                    .array => |array_info| {
                        if (array_info.child == u8) {
                            return .{ .oid = 0, .format = .TEXT, .bytes = value };
                        }
                    },
                    else => {},
                }
            }

            @compileError("postgrez binary.encode: unsupported pointer type " ++ @typeName(T));
        },
        .array => |array_info| {
            if (array_info.child != u8) @compileError("postgrez binary.encode: unsupported array type " ++ @typeName(T));

            const bytes = try allocator.dupe(u8, &value);

            return .{ .oid = 0, .format = .TEXT, .bytes = bytes };
        },
        .@"enum" => return .{ .oid = 0, .format = .TEXT, .bytes = @tagName(value) },
        .@"struct", .@"union" => {
            const bytes = try std.json.Stringify.valueAlloc(allocator, value, .{});

            return .{ .oid = 0, .format = .TEXT, .bytes = bytes };
        },
        else => @compileError("postgrez binary.encode: unsupported parameter type " ++ @typeName(T)),
    }
}

fn encodeInt(allocator: std.mem.Allocator, value: anytype) !EncodedParam {
    const T = @TypeOf(value);
    const info = @typeInfo(T).int;

    // pick the narrowest wire integer the TYPE always fits (stable OID per
    // Zig type, so prepared statements see one parameter type)
    if ((info.signedness == .signed and info.bits <= 16) or (info.signedness == .unsigned and info.bits <= 8)) {
        return intParam(i16, Oid.INT2, allocator, @intCast(value));
    }
    if ((info.signedness == .signed and info.bits <= 32) or (info.signedness == .unsigned and info.bits <= 16)) {
        return intParam(i32, Oid.INT4, allocator, @intCast(value));
    }
    if ((info.signedness == .signed and info.bits <= 64) or (info.signedness == .unsigned and info.bits <= 32)) {
        return intParam(i64, Oid.INT8, allocator, @intCast(value));
    }

    // u64/usize and wider: must fit int8
    const wide = std.math.cast(i64, value) orelse return error.PostgrezValueOutOfRange;

    return intParam(i64, Oid.INT8, allocator, wide);
}

fn intParam(comptime Wire: type, oid: Oid, allocator: std.mem.Allocator, value: Wire) !EncodedParam {
    const bytes = try allocator.alloc(u8, @sizeOf(Wire));
    std.mem.writeInt(Wire, bytes[0..@sizeOf(Wire)], value, .big);

    return .{ .oid = @intFromEnum(oid), .format = .BINARY, .bytes = bytes };
}

fn encodeFloat(allocator: std.mem.Allocator, value: anytype) !EncodedParam {
    const T = @TypeOf(value);

    if (@typeInfo(T).float.bits <= 32) {
        const bytes = try allocator.alloc(u8, 4);
        std.mem.writeInt(u32, bytes[0..4], @bitCast(@as(f32, value)), .big);

        return .{ .oid = @intFromEnum(Oid.FLOAT4), .format = .BINARY, .bytes = bytes };
    }

    const bytes = try allocator.alloc(u8, 8);
    std.mem.writeInt(u64, bytes[0..8], @bitCast(@as(f64, value)), .big);

    return .{ .oid = @intFromEnum(Oid.FLOAT8), .format = .BINARY, .bytes = bytes };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez types: binary decode integers with checked narrowing" {
    try testing.expectEqual(@as(i16, -7), try decode(i16, .INT2, &.{ 0xff, 0xf9 }));
    try testing.expectEqual(@as(i64, 1), try decode(i64, .INT8, &.{ 0, 0, 0, 0, 0, 0, 0, 1 }));
    try testing.expectEqual(@as(u8, 255), try decode(u8, .INT2, &.{ 0, 255 }));
    try testing.expectEqual(@as(i32, 42), try decode(i32, .INT4, &.{ 0, 0, 0, 42 }));

    try testing.expectError(error.PostgrezValueOutOfRange, decode(u8, .INT2, &.{ 1, 44 }));
    try testing.expectError(error.PostgrezBadCell, decode(i32, .INT4, &.{ 0, 0, 42 }));
    try testing.expectError(error.PostgrezTypeMismatch, decode(i32, .TEXT, "42"));
}

test "postgrez types: binary decode date, time, timestamp as integers" {
    // date: i32 days since 2000-01-01
    try testing.expectEqual(@as(i32, 9690), try decode(i32, .DATE, &.{ 0, 0, 0x25, 0xda }));
    // timestamp: i64 micros since 2000-01-01
    try testing.expectEqual(@as(i64, 1_000_000), try decode(i64, .TIMESTAMP, &.{ 0, 0, 0, 0, 0, 0x0f, 0x42, 0x40 }));
}

test "postgrez types: binary decode floats" {
    var float4_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &float4_bytes, @bitCast(@as(f32, 1.5)), .big);
    try testing.expectEqual(@as(f32, 1.5), try decode(f32, .FLOAT4, &float4_bytes));
    try testing.expectEqual(@as(f64, 1.5), try decode(f64, .FLOAT4, &float4_bytes));

    var float8_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &float8_bytes, @bitCast(@as(f64, -2.25)), .big);
    try testing.expectEqual(@as(f64, -2.25), try decode(f64, .FLOAT8, &float8_bytes));

    try testing.expectError(error.PostgrezTypeMismatch, decode(f32, .FLOAT8, &float8_bytes));
}

test "postgrez types: binary decode bool" {
    try testing.expectEqual(true, try decode(bool, .BOOL, &.{1}));
    try testing.expectEqual(false, try decode(bool, .BOOL, &.{0}));

    try testing.expectError(error.PostgrezTypeMismatch, decode(bool, .INT2, &.{1}));
    try testing.expectError(error.PostgrezBadCell, decode(bool, .BOOL, &.{ 1, 1 }));
}

test "postgrez types: binary decode text-like, bytea, and jsonb strip" {
    try testing.expectEqualStrings("hi", try decode([]const u8, .TEXT, "hi"));
    try testing.expectEqualSlices(u8, &.{ 0xde, 0xad }, try decode([]const u8, .BYTEA, &.{ 0xde, 0xad }));

    const jsonb = [_]u8{1} ++ "{\"a\":1}".*;
    try testing.expectEqualStrings("{\"a\":1}", try decode([]const u8, .JSONB, &jsonb));

    try testing.expectError(error.PostgrezBadCell, decode([]const u8, .JSONB, &.{2}));
}

test "postgrez types: binary decode uuid into [16]u8" {
    var uuid_bytes: [16]u8 = undefined;
    for (&uuid_bytes, 0..) |*byte, index| byte.* = @intCast(index);

    const decoded = try decode([16]u8, .UUID, &uuid_bytes);
    try testing.expectEqualSlices(u8, &uuid_bytes, &decoded);

    try testing.expectError(error.PostgrezBadCell, decode([16]u8, .UUID, uuid_bytes[0..8]));
    try testing.expectError(error.PostgrezTypeMismatch, decode([16]u8, .BYTEA, &uuid_bytes));
}

test "postgrez types: encode integers picks stable wire width by type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const int2 = try encode(allocator, @as(i16, -3));
    try testing.expectEqual(@as(u32, @intFromEnum(Oid.INT2)), int2.oid);
    try testing.expectEqualSlices(u8, &.{ 0xff, 0xfd }, int2.bytes.?);

    const int4 = try encode(allocator, @as(u16, 65535));
    try testing.expectEqual(@as(u32, @intFromEnum(Oid.INT4)), int4.oid);

    const int8 = try encode(allocator, @as(u32, 4_000_000_000));
    try testing.expectEqual(@as(u32, @intFromEnum(Oid.INT8)), int8.oid);

    const literal = try encode(allocator, 7);
    try testing.expectEqual(@as(u32, @intFromEnum(Oid.INT8)), literal.oid);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 7 }, literal.bytes.?);

    try testing.expectError(error.PostgrezValueOutOfRange, encode(allocator, @as(u64, std.math.maxInt(u64))));
}

test "postgrez types: encode floats, bool, strings, null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const float8 = try encode(allocator, @as(f64, 1.5));
    try testing.expectEqual(@as(u32, @intFromEnum(Oid.FLOAT8)), float8.oid);
    try testing.expectEqual(frontend.Format.BINARY, float8.format);

    const flag = try encode(allocator, true);
    try testing.expectEqualSlices(u8, &.{1}, flag.bytes.?);

    const text = try encode(allocator, @as([]const u8, "hello"));
    try testing.expectEqual(@as(u32, 0), text.oid);
    try testing.expectEqual(frontend.Format.TEXT, text.format);
    try testing.expectEqualStrings("hello", text.bytes.?);

    const literal = try encode(allocator, "hi");
    try testing.expectEqualStrings("hi", literal.bytes.?);

    const nothing = try encode(allocator, @as(?i32, null));
    try testing.expectEqual(@as(?[]const u8, null), nothing.bytes);

    const some = try encode(allocator, @as(?i32, 5));
    try testing.expectEqual(@as(u32, @intFromEnum(Oid.INT4)), some.oid);
}

test "postgrez types: encode enum and struct as text" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const Kind = enum { deploy, rollback };
    const tag = try encode(allocator, Kind.deploy);
    try testing.expectEqualStrings("deploy", tag.bytes.?);

    const Payload = struct { id: i64, note: []const u8 };
    const json = try encode(allocator, Payload{ .id = 4, .note = "ok" });
    try testing.expectEqualStrings("{\"id\":4,\"note\":\"ok\"}", json.bytes.?);
}
