//! Edge tests: jzon.skip at the boundaries.
//! Covers values that end early, values the grammar does not allow, and nesting
//! past the cap, so a document a parse does not want cannot slip past on a
//! shape a parse would have refused.

const std = @import("std");
const jzon = @import("jzon");

const Cursor = jzon.Cursor;
const skip = jzon.skip;
const std_parser = jzon.std_parser;

const Shape = jzon.scan.Shape;

/// Both widths, so every case asserts the pair agrees.
const SHAPES = [_]Shape{
    .{ .scan = .SCALAR },
    .{ .scan = .VECTOR },
};

/// Assert the value at the head of `document` is refused, at both widths.
fn expectRefused(document: []const u8, failure: anyerror) !void {
    inline for (SHAPES) |shape| {
        var cursor: Cursor = .init(document);

        try std.testing.expectError(failure, skip.value(&cursor, shape));
    }
}

test "jzon edge: skip reports a value the document ends inside" {
    try expectRefused("", error.JzonTruncated);
    try expectRefused("{", error.JzonTruncated);
    try expectRefused("{\"a\"", error.JzonTruncated);
    try expectRefused("{\"a\":", error.JzonTruncated);
    try expectRefused("{\"a\":1", error.JzonTruncated);
    try expectRefused("[", error.JzonTruncated);
    try expectRefused("[1,2", error.JzonTruncated);
    try expectRefused("\"unterminated", error.JzonTruncated);
    try expectRefused("tru", error.JzonTruncated);
    try expectRefused("nul", error.JzonTruncated);
}

test "jzon edge: skip reports a value the grammar does not allow" {
    try expectRefused("}", error.JzonUnexpected);
    try expectRefused("]", error.JzonUnexpected);
    try expectRefused(",", error.JzonUnexpected);
    try expectRefused("{,}", error.JzonUnexpected);
    try expectRefused("{\"a\":1,}", error.JzonUnexpected);
    try expectRefused("{\"a\" 1}", error.JzonUnexpected);
    try expectRefused("{a:1}", error.JzonUnexpected);
    try expectRefused("[1,,2]", error.JzonUnexpected);
    try expectRefused("[1,]", error.JzonUnexpected);
    try expectRefused("trve", error.JzonUnexpected);
    try expectRefused("NULL", error.JzonUnexpected);
}

test "jzon edge: skip reports a number the grammar does not allow" {
    // The cursor bounds a number token without validating it, so the check has
    // to happen here or a document std refuses would be stepped over.
    try expectRefused("1.2.3", error.JzonUnexpected);
    try expectRefused("01", error.JzonUnexpected);
    try expectRefused("1e", error.JzonUnexpected);
    try expectRefused("1.", error.JzonUnexpected);
    try expectRefused("-", error.JzonUnexpected);
}

test "jzon edge: a value skip refuses is a value the std path refuses too" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const malformed = [_][]const u8{
        "{\"a\":1,}",
        "[1,]",
        "1.2.3",
        "01",
        "trve",
    };

    for (malformed) |document| {
        try expectRefused(document, error.JzonUnexpected);
        try std.testing.expect(std.meta.isError(std_parser.parse(std.json.Value, allocator, document, .{})));
    }
}

test "jzon edge: skip refuses nesting past the cap" {
    const depth = skip.MAX_DEPTH + 2;

    var document: [depth * 2]u8 = undefined;
    @memset(document[0..depth], '[');
    @memset(document[depth..], ']');

    try expectRefused(&document, error.JzonUnexpected);
}

test "jzon edge: skip walks nesting right up to the cap" {
    const depth = skip.MAX_DEPTH;

    var document: [depth * 2]u8 = undefined;
    @memset(document[0..depth], '[');
    @memset(document[depth..], ']');

    inline for (SHAPES) |shape| {
        var cursor: Cursor = .init(&document);
        try skip.value(&cursor, shape);

        try std.testing.expect(cursor.atEnd());
    }
}

test "jzon edge: skip steps over an empty container inside a deep one" {
    inline for (SHAPES) |shape| {
        var cursor: Cursor = .init("{\"a\":{},\"b\":[],\"c\":{\"d\":[]}}|rest");
        try skip.value(&cursor, shape);

        try std.testing.expectEqualStrings("|rest", cursor.src[cursor.pos..]);
    }
}
