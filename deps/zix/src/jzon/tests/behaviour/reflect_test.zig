//! Behaviour tests: jzon.reflect, the questions a type is asked.
//! Verifies which enums cover every value they carry, and that a field's declared
//! default is read back as the field's own type.

const std = @import("std");
const jzon = @import("jzon");

const reflect = jzon.reflect;

const Status = enum { PENDING, SHIPPED, CANCELLED };

const Settings = struct {
    retries: u8 = 3,
    label: []const u8 = "none",
    ratio: f64 = 0.5,
    status: Status = .PENDING,
    id: u64,
};

test "jzon behaviour: reflect calls an ordinary enum exhaustive" {
    try std.testing.expect(reflect.isExhaustive(Status));
    try std.testing.expect(reflect.isExhaustive(enum { ONLY }));
    try std.testing.expect(reflect.isExhaustive(enum(u16) { LOW = 1, HIGH = 900 }));
}

test "jzon behaviour: reflect reads a default of every field type" {
    try std.testing.expectEqual(@as(u8, 3), reflect.defaultOf(Settings, 0).?);
    try std.testing.expectEqualStrings("none", reflect.defaultOf(Settings, 1).?);
    try std.testing.expectEqual(@as(f64, 0.5), reflect.defaultOf(Settings, 2).?);
    try std.testing.expectEqual(Status.PENDING, reflect.defaultOf(Settings, 3).?);
}

test "jzon behaviour: reflect reports no default for a field that declares none" {
    try std.testing.expect(reflect.defaultOf(Settings, 4) == null);
}

test "jzon behaviour: reflect walks fields in declaration order" {
    const names = comptime std.meta.fieldNames(Settings);

    try std.testing.expectEqual(@as(usize, 5), names.len);
    try std.testing.expectEqualStrings("retries", names[0]);
    try std.testing.expectEqualStrings("id", names[4]);
}
