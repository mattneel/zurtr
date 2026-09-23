//! jzon type reflection.
//!
//! What:
//! - The few questions jzon asks a type that the two supported Zig versions
//!   answer differently. Asking them here keeps every version check in one file
//!   instead of one per caller.
//!
//! Note:
//! - Zig 0.16 holds a struct's fields in `@typeInfo(T).@"struct".fields` and an
//!   enum's exhaustiveness in `is_exhaustive`. Zig 0.17 splits the fields into
//!   `field_names` and `field_attrs`, and renames the enum flag to `mode`. The
//!   branch reading the field that is not there never reaches the compiler,
//!   because the condition choosing it is known at compile time.
//! - `std.meta.fieldNames` and `@FieldType` answer the same on both versions, so
//!   a caller walking fields uses those directly rather than through here.

const std = @import("std");

/// Whether every value of an enum type has a tag name.
///
/// Note:
/// - A non-exhaustive enum carries values no name covers, which is why both
///   directions refuse one: there is no name to write, and no value to read a
///   name into.
///
/// Param:
/// T - type (comptime, the enum type to ask about)
///
/// Return:
/// - bool (true when every value the type carries has a name)
pub inline fn isExhaustive(comptime T: type) bool {
    const info = @typeInfo(T).@"enum";

    if (@hasField(@TypeOf(info), "is_exhaustive")) return info.is_exhaustive;

    return info.mode == .exhaustive;
}

/// The default value a struct field declares, when it declares one.
///
/// Note:
/// - An optional field spelled `note: ?[]const u8 = null` has a default, and that
///   default is `null`. The result is one optional deeper than the field, so
///   "declares no default" and "defaults to null" stay apart.
///
/// Param:
/// T - type (comptime, the struct declaring the field)
/// index - usize (comptime, the field's place in declaration order)
///
/// Return:
/// - The field's type wrapped in an optional, null when the field declares no
///   default
pub inline fn defaultOf(comptime T: type, comptime index: usize) ?@FieldType(T, std.meta.fieldNames(T)[index]) {
    const Field = @FieldType(T, std.meta.fieldNames(T)[index]);
    const info = @typeInfo(T).@"struct";

    if (@hasField(@TypeOf(info), "fields")) {
        const declared = info.fields[index].default_value_ptr orelse return null;

        return @as(*const Field, @ptrCast(@alignCast(declared))).*;
    }

    const declared = info.field_attrs[index].default_value_ptr orelse return null;

    return @as(*const Field, @ptrCast(@alignCast(declared))).*;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const Closed = enum { PENDING, SHIPPED };
const Open = enum(u8) { PENDING, SHIPPED, _ };

const Record = struct {
    id: u32,
    name: []const u8,
    note: ?[]const u8 = null,
    retries: u8 = 3,
};

test "jzon: reflect answers which enums cover every value they carry" {
    try std.testing.expect(isExhaustive(Closed));
    try std.testing.expect(!isExhaustive(Open));
}

test "jzon: reflect reads the default a field declares" {
    try std.testing.expectEqual(@as(?u8, 3), defaultOf(Record, 3));
}

test "jzon: reflect separates no default from a default of null" {
    try std.testing.expect(defaultOf(Record, 0) == null);
    try std.testing.expect(defaultOf(Record, 1) == null);

    const note = defaultOf(Record, 2);
    try std.testing.expect(note != null);
    try std.testing.expect(note.? == null);
}
