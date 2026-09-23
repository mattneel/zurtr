//! jzon deserialize field bookkeeping.
//!
//! What:
//! - Which of a target struct's fields a document has filled in, and what
//!   happens to the ones it left out.
//! - Every generated parser needs the same two answers, so they live here rather
//!   than once per parser.

const std = @import("std");
const diagnostic = @import("diagnostic.zig");

const reflect = @import("../reflect.zig");

/// How the bookkeeping can fail: the same key twice, or a field the document
/// never carried and the type gives no default for.
pub const Error = @import("options.zig").Error;

/// Tracks which of `T`'s fields have been read.
///
/// Note:
/// - One bool per field, sized at compile time, so nothing is allocated to track
///   a parse.
///
/// Usage:
/// ```zig
/// var seen: fields.Seen(Order) = .{};
///
/// try seen.mark(index);
/// try seen.fill(&result);
/// ```
pub fn Seen(comptime T: type) type {
    return struct {
        const Self = @This();

        /// How many fields the target declares.
        pub const COUNT = std.meta.fieldNames(T).len;

        marked: [COUNT]bool = @splat(false),

        /// Record that the field at `index` has been read.
        ///
        /// Note:
        /// - A field read twice means the document carried the same key twice,
        ///   which no JSON object should. Reporting it here keeps the check in
        ///   one place for every parser.
        ///
        /// Param:
        /// index - usize (the field's place in declaration order)
        ///
        /// Return:
        /// - void
        /// - error.JzonUnexpected when that field was already read
        pub fn mark(self: *Self, index: usize) Error!void {
            if (self.marked[index]) return error.JzonUnexpected;

            self.marked[index] = true;
        }

        /// Whether the field at `index` has been read.
        pub fn isMarked(self: Self, index: usize) bool {
            return self.marked[index];
        }

        /// Give every field the document left out the default its type declares.
        ///
        /// Note:
        /// - A field with no declared default has nothing to fall back to, so an
        ///   absent one fails. An optional field is no exception: spell it
        ///   `note: ?[]const u8 = null` to make the document's silence mean null.
        ///   That is the rule std.json holds to, and both paths keep to it.
        ///
        /// Param:
        /// target - *T (the value being built, whose unread fields are still
        ///   undefined)
        ///
        /// Return:
        /// - void
        /// - error.JzonMissingField when an unread field declares no default
        pub fn fill(self: Self, target: *T) Error!void {
            inline for (comptime std.meta.fieldNames(T), 0..) |name, index| {
                if (!self.marked[index]) {
                    const declared = reflect.defaultOf(T, index) orelse {
                        diagnostic.noteField(name);

                        return error.JzonMissingField;
                    };

                    @field(target, name) = declared;
                }
            }
        }
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const Record = struct {
    id: u32,
    name: []const u8,
    note: ?[]const u8 = null,
    retries: u8 = 3,
};

test "jzon: seen starts with nothing read and counts the target's fields" {
    const Tracker = Seen(Record);
    var seen: Tracker = .{};

    try std.testing.expectEqual(@as(usize, 4), Tracker.COUNT);

    for (0..Tracker.COUNT) |index| {
        try std.testing.expect(!seen.isMarked(index));
    }

    try seen.mark(1);
    try std.testing.expect(seen.isMarked(1));
}

test "jzon: seen refuses the same field twice" {
    var seen: Seen(Record) = .{};

    try seen.mark(0);
    try std.testing.expectError(error.JzonUnexpected, seen.mark(0));
}

test "jzon: seen fills the fields a document left out" {
    var seen: Seen(Record) = .{};
    try seen.mark(0);
    try seen.mark(1);

    var record: Record = undefined;
    record.id = 7;
    record.name = "x";

    try seen.fill(&record);

    try std.testing.expectEqual(@as(u32, 7), record.id);
    try std.testing.expectEqualStrings("x", record.name);
    try std.testing.expect(record.note == null);
    try std.testing.expectEqual(@as(u8, 3), record.retries);
}

test "jzon: seen reports a field the document owed and the type does not default" {
    var seen: Seen(Record) = .{};
    try seen.mark(0);

    var record: Record = undefined;
    record.id = 7;

    try std.testing.expectError(error.JzonMissingField, seen.fill(&record));
}
