//! Edge tests: jzon.fields at the boundaries.
//! Covers the same field twice, a target with no fields, an optional that has to
//! be spelled with a default, and a fill that stops at the first field it cannot
//! answer for.

const std = @import("std");
const jzon = @import("jzon");

const fields = jzon.fields;

const Pair = struct {
    left: u8,
    right: u8 = 2,
};

/// An optional with no default is still a field the document owes, which is the
/// rule std.json holds to.
const Bare = struct {
    note: ?[]const u8,
};

/// The same field with a default of null, which is how a field is made optional
/// in the document.
const Defaulted = struct {
    note: ?[]const u8 = null,
};

test "jzon edge: seen refuses the same field twice" {
    var seen: fields.Seen(Pair) = .{};

    try seen.mark(1);
    try std.testing.expectError(error.JzonUnexpected, seen.mark(1));

    // The first mark still stands after the second was refused.
    try std.testing.expect(seen.isMarked(1));
}

test "jzon edge: seen over a target with no fields fills nothing and fails at nothing" {
    const Empty = struct {};

    var seen: fields.Seen(Empty) = .{};
    var empty: Empty = .{};

    try seen.fill(&empty);
    try std.testing.expectEqual(@as(usize, 0), fields.Seen(Empty).COUNT);
}

test "jzon edge: seen owes an optional that declares no default" {
    var seen: fields.Seen(Bare) = .{};
    var bare: Bare = undefined;

    try std.testing.expectError(error.JzonMissingField, seen.fill(&bare));
}

test "jzon edge: seen gives an optional with a default its null" {
    var seen: fields.Seen(Defaulted) = .{};
    var defaulted: Defaulted = undefined;

    try seen.fill(&defaulted);

    try std.testing.expect(defaulted.note == null);
}

test "jzon edge: seen fills the fields ahead of the one it cannot answer for" {
    // `right` has a default and comes second, `left` has none and comes first, so
    // the walk fails before it reaches the one it could have filled.
    var seen: fields.Seen(Pair) = .{};
    var pair: Pair = undefined;

    try std.testing.expectError(error.JzonMissingField, seen.fill(&pair));

    var marked: fields.Seen(Pair) = .{};
    try marked.mark(0);

    pair.left = 1;
    try marked.fill(&pair);

    try std.testing.expectEqual(@as(u8, 1), pair.left);
    try std.testing.expectEqual(@as(u8, 2), pair.right);
}

test "jzon edge: two trackers over the same target do not share their marks" {
    var first: fields.Seen(Pair) = .{};
    var second: fields.Seen(Pair) = .{};

    try first.mark(0);

    try std.testing.expect(first.isMarked(0));
    try std.testing.expect(!second.isMarked(0));
}
