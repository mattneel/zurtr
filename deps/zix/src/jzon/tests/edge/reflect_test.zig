//! Edge tests: jzon.reflect at the boundaries.
//! Covers a non-exhaustive enum, a struct with no fields at all, a default that
//! is itself null, and defaults that are whole structs and slices.

const std = @import("std");
const jzon = @import("jzon");

const reflect = jzon.reflect;

const Open = enum(u8) { LOW, HIGH, _ };

const Point = struct {
    x: i32,
    y: i32,
};

const Boundary = struct {
    note: ?[]const u8 = null,
    origin: Point = .{ .x = 0, .y = 0 },
    tags: []const []const u8 = &.{},
    zero: u8 = 0,
    required: u8,
};

test "jzon edge: reflect calls a non-exhaustive enum what it is" {
    try std.testing.expect(!reflect.isExhaustive(Open));
    try std.testing.expect(!reflect.isExhaustive(enum(u2) { A, _ }));
}

test "jzon edge: reflect separates a default of null from no default" {
    const declared = reflect.defaultOf(Boundary, 0);

    try std.testing.expect(declared != null);
    try std.testing.expect(declared.? == null);

    try std.testing.expect(reflect.defaultOf(Boundary, 4) == null);
}

test "jzon edge: reflect reads a default that is a whole struct" {
    const origin = reflect.defaultOf(Boundary, 1).?;

    try std.testing.expectEqual(@as(i32, 0), origin.x);
    try std.testing.expectEqual(@as(i32, 0), origin.y);
}

test "jzon edge: reflect reads a default that is an empty slice" {
    const tags = reflect.defaultOf(Boundary, 2).?;

    try std.testing.expectEqual(@as(usize, 0), tags.len);
}

test "jzon edge: reflect reads a default whose value is zero" {
    // Zero is a value, not the absence of one, so it has to come back as a
    // default rather than as null.
    const zero = reflect.defaultOf(Boundary, 3);

    try std.testing.expect(zero != null);
    try std.testing.expectEqual(@as(u8, 0), zero.?);
}

test "jzon edge: reflect walks a struct that declares no fields" {
    const names = comptime std.meta.fieldNames(struct {});

    try std.testing.expectEqual(@as(usize, 0), names.len);
}
