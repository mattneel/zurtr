//! jzon deserialize, stepping over a value.
//!
//! What:
//! - Walks past one whole JSON value without building anything out of it,
//!   however deep it nests. This is what `unknown = .SKIP` runs when a document
//!   carries a key the target type does not declare.
//! - Nothing is allocated and no string is decoded. A token is bounded, checked
//!   against the grammar, and left behind.
//!
//! Note:
//! - The walk validates rather than merely bounds, so a malformed value fails
//!   whether the parse wanted it or not. A document that the std-backed path
//!   refuses is refused here too.
//! - A document is untrusted, so the nesting a walk will follow is capped.
//!   Anything deeper is refused instead of being allowed to grow the stack.

const cursor_mod = @import("../cursor.zig");
const float = @import("../float.zig");
const scan = @import("scan.zig");

const Cursor = cursor_mod.Cursor;

/// How a walk can fail.
pub const Error = @import("options.zig").Error;

/// The width the walk scans at.
pub const Shape = scan.Shape;

/// How deep a stepped-over value may nest.
///
/// Note:
/// - Held well above what a request body ever nests to, and well below what
///   would trouble the stack. std.json caps its own nesting the same way.
pub const MAX_DEPTH = 256;

/// Step over one whole value, whatever shape it is.
///
/// Param:
/// cursor - *Cursor (positioned at the value, leading whitespace allowed)
/// shape - Shape (comptime, which width to scan at)
///
/// Return:
/// - void
/// - error.JzonTruncated when the document ends inside the value
/// - error.JzonUnexpected when the value is malformed, or nests past MAX_DEPTH
pub fn value(cursor: *Cursor, comptime shape: Shape) Error!void {
    return valueAt(cursor, shape, 0);
}

/// Step over one value sitting `depth` containers deep.
fn valueAt(cursor: *Cursor, comptime shape: Shape, depth: usize) Error!void {
    if (depth > MAX_DEPTH) return error.JzonUnexpected;

    scan.skipSpace(cursor, shape);

    switch (try cursor.peek()) {
        '{' => return object(cursor, shape, depth),
        '[' => return array(cursor, shape, depth),
        '"' => {
            _ = try scan.stringSpan(cursor, shape);
        },
        't' => try cursor.literal("true"),
        'f' => try cursor.literal("false"),
        'n' => try cursor.literal("null"),
        '-', '0'...'9' => {
            if (!float.isNumber(try cursor.numberSpan())) return error.JzonUnexpected;
        },

        else => return error.JzonUnexpected,
    }
}

/// Step over an object, keys and values alike.
fn object(cursor: *Cursor, comptime shape: Shape, depth: usize) Error!void {
    try cursor.expect('{');
    scan.skipSpace(cursor, shape);

    if (cursor.accept('}')) return;

    while (true) {
        scan.skipSpace(cursor, shape);
        _ = try scan.stringSpan(cursor, shape);

        scan.skipSpace(cursor, shape);
        try cursor.expect(':');

        try valueAt(cursor, shape, depth + 1);

        scan.skipSpace(cursor, shape);
        if (cursor.accept(',')) continue;

        return cursor.expect('}');
    }
}

/// Step over an array, one element at a time.
fn array(cursor: *Cursor, comptime shape: Shape, depth: usize) Error!void {
    try cursor.expect('[');
    scan.skipSpace(cursor, shape);

    if (cursor.accept(']')) return;

    while (true) {
        try valueAt(cursor, shape, depth + 1);

        scan.skipSpace(cursor, shape);
        if (cursor.accept(',')) continue;

        return cursor.expect(']');
    }
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const std = @import("std");

/// Both widths, so every case asserts the pair agrees.
const SHAPES = [_]Shape{
    .{ .scan = .SCALAR },
    .{ .scan = .VECTOR },
};

/// Step over the value at the head of `document` and assert what is left.
fn expectLeaves(document: []const u8, rest: []const u8) !void {
    inline for (SHAPES) |shape| {
        var cursor: Cursor = .init(document);
        try value(&cursor, shape);

        try std.testing.expectEqualStrings(rest, cursor.src[cursor.pos..]);
    }
}

/// Assert the value at the head of `document` is refused, at both widths.
fn expectRefused(document: []const u8, failure: anyerror) !void {
    inline for (SHAPES) |shape| {
        var cursor: Cursor = .init(document);

        try std.testing.expectError(failure, value(&cursor, shape));
    }
}

test "jzon: skip steps over each scalar form" {
    try expectLeaves("true,rest", ",rest");
    try expectLeaves("false,rest", ",rest");
    try expectLeaves("null,rest", ",rest");
    try expectLeaves("42,rest", ",rest");
    try expectLeaves("-1.5e10,rest", ",rest");
    try expectLeaves("\"a string\",rest", ",rest");
}

test "jzon: skip steps over a whole nested value" {
    try expectLeaves("{\"deep\":[1,2,{\"a\":null}],\"b\":\"x\"},rest", ",rest");
    try expectLeaves("[[[[]]]],rest", ",rest");
    try expectLeaves("{},rest", ",rest");
    try expectLeaves("[],rest", ",rest");
}

test "jzon: skip steps over a value laid out with whitespace" {
    try expectLeaves("  { \"deep\" : [ 1 , 2 ] , \"b\" : true }  ,rest", "  ,rest");
    try expectLeaves("  \"padded\"  ,rest", "  ,rest");
}

test "jzon: skip refuses a value it cannot walk to the end of" {
    try expectRefused("{\"a\":1", error.JzonTruncated);
    try expectRefused("[1,2", error.JzonTruncated);
    try expectRefused("\"unterminated", error.JzonTruncated);
    try expectRefused("tru", error.JzonTruncated);
}

test "jzon: skip refuses a malformed value the way the read paths do" {
    try expectRefused("{,}", error.JzonUnexpected);
    try expectRefused("[1,,2]", error.JzonUnexpected);
    try expectRefused("{\"a\" 1}", error.JzonUnexpected);
    try expectRefused("{1:2}", error.JzonUnexpected);
    try expectRefused("1.2.3", error.JzonUnexpected);
    try expectRefused("trve", error.JzonUnexpected);
}

test "jzon: skip refuses nesting past the cap" {
    var document: [MAX_DEPTH * 2 + 4]u8 = undefined;
    @memset(document[0 .. MAX_DEPTH + 2], '[');
    @memset(document[MAX_DEPTH + 2 ..], ']');

    try expectRefused(&document, error.JzonUnexpected);
}
