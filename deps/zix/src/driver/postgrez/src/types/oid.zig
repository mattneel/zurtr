//! OID table and type registry: which built-in types the driver knows and
//! which of them it can decode in binary format (binary first, text
//! fallback for the rest).

const std = @import("std");

/// Built-in type OIDs the driver has dedicated handling for. Non-exhaustive:
/// any other OID still flows through as raw text.
pub const Oid = enum(u32) {
    BOOL = 16,
    BYTEA = 17,
    CHAR = 18,
    NAME = 19,
    INT8 = 20,
    INT2 = 21,
    INT4 = 23,
    TEXT = 25,
    OID = 26,
    JSON = 114,
    XML = 142,
    FLOAT4 = 700,
    FLOAT8 = 701,
    UNKNOWN = 705,
    BPCHAR = 1042,
    VARCHAR = 1043,
    DATE = 1082,
    TIME = 1083,
    TIMESTAMP = 1114,
    TIMESTAMPTZ = 1184,
    INTERVAL = 1186,
    NUMERIC = 1700,
    UUID = 2950,
    JSONB = 3802,
    _,
};

/// Whether the driver has a binary decoder for `oid`. Types outside this
/// set are requested in text format (fallback).
pub fn hasBinaryDecode(oid: Oid) bool {
    return switch (oid) {
        .BOOL,
        .BYTEA,
        .CHAR,
        .NAME,
        .INT8,
        .INT2,
        .INT4,
        .TEXT,
        .OID,
        .JSON,
        .FLOAT4,
        .FLOAT8,
        .BPCHAR,
        .VARCHAR,
        .DATE,
        .TIME,
        .TIMESTAMP,
        .TIMESTAMPTZ,
        .UUID,
        .JSONB,
        => true,
        else => false,
    };
}

/// Whether `oid` is a text-like type whose binary and text wire forms are
/// both the raw byte content.
pub fn isTextLike(oid: Oid) bool {
    return switch (oid) {
        .TEXT, .VARCHAR, .BPCHAR, .NAME, .CHAR, .XML, .UNKNOWN => true,
        else => false,
    };
}

/// Whether `oid` carries JSON content (json or jsonb).
pub fn isJson(oid: Oid) bool {
    return oid == .JSON or oid == .JSONB;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez types: oid values match the catalog" {
    try testing.expectEqual(@as(u32, 16), @intFromEnum(Oid.BOOL));
    try testing.expectEqual(@as(u32, 20), @intFromEnum(Oid.INT8));
    try testing.expectEqual(@as(u32, 23), @intFromEnum(Oid.INT4));
    try testing.expectEqual(@as(u32, 25), @intFromEnum(Oid.TEXT));
    try testing.expectEqual(@as(u32, 1700), @intFromEnum(Oid.NUMERIC));
    try testing.expectEqual(@as(u32, 2950), @intFromEnum(Oid.UUID));
    try testing.expectEqual(@as(u32, 3802), @intFromEnum(Oid.JSONB));
}

test "postgrez types: binary registry is binary-first with text fallback" {
    try testing.expect(hasBinaryDecode(.INT8));
    try testing.expect(hasBinaryDecode(.UUID));
    try testing.expect(hasBinaryDecode(.JSONB));

    // numeric and interval fall back to text
    try testing.expect(!hasBinaryDecode(.NUMERIC));
    try testing.expect(!hasBinaryDecode(.INTERVAL));
    // unregistered OID (custom type) falls back to text
    try testing.expect(!hasBinaryDecode(@enumFromInt(99999)));
}

test "postgrez types: text-like and json classification" {
    try testing.expect(isTextLike(.TEXT));
    try testing.expect(isTextLike(.VARCHAR));
    try testing.expect(!isTextLike(.INT4));

    try testing.expect(isJson(.JSON));
    try testing.expect(isJson(.JSONB));
    try testing.expect(!isJson(.TEXT));
}
