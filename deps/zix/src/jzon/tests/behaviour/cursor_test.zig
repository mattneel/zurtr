//! Behaviour tests: jzon.Cursor, the contract a parser reads against.
//! Verifies token bounding over a whole document, the whitespace set RFC 8259
//! allows, and the escaped flag a borrowing parser decides on.

const std = @import("std");
const jzon = @import("jzon");

const Cursor = jzon.Cursor;

// --------------------------------------------------------- //

test "jzon behaviour: cursor walks a pretty printed object end to end" {
    const document =
        \\{
        \\  "id": 42,
        \\  "name": "zix"
        \\}
    ;

    var cursor: Cursor = .init(document);

    cursor.skipSpace();
    try cursor.expect('{');

    cursor.skipSpace();
    const first_key = try cursor.stringSpan();
    try std.testing.expectEqualStrings("id", first_key.raw);

    cursor.skipSpace();
    try cursor.expect(':');
    cursor.skipSpace();
    try std.testing.expectEqualStrings("42", try cursor.numberSpan());

    cursor.skipSpace();
    try std.testing.expect(cursor.accept(','));

    cursor.skipSpace();
    const second_key = try cursor.stringSpan();
    try std.testing.expectEqualStrings("name", second_key.raw);

    cursor.skipSpace();
    try cursor.expect(':');
    cursor.skipSpace();
    const value = try cursor.stringSpan();
    try std.testing.expectEqualStrings("zix", value.raw);

    cursor.skipSpace();
    try cursor.expect('}');
    try std.testing.expect(cursor.atEnd());
}

test "jzon behaviour: cursor skips every whitespace byte RFC 8259 allows" {
    var cursor: Cursor = .init(" \t\n\r \t\n\rx");

    cursor.skipSpace();

    try std.testing.expectEqual(@as(u8, 'x'), try cursor.peek());
    try std.testing.expectEqual(@as(usize, 1), cursor.remaining());
}

test "jzon behaviour: cursor skipSpace on a non-space byte moves nothing" {
    var cursor: Cursor = .init("abc");

    cursor.skipSpace();
    cursor.skipSpace();

    try std.testing.expectEqual(@as(usize, 3), cursor.remaining());
}

test "jzon behaviour: cursor reports a clean string as unescaped" {
    var cursor: Cursor = .init("\"plain value\"");

    const span = try cursor.stringSpan();

    try std.testing.expectEqualStrings("plain value", span.raw);
    try std.testing.expect(!span.escaped);
}

test "jzon behaviour: cursor reports a string carrying any escape as escaped" {
    const documents = [_][]const u8{
        "\"a\\nb\"",
        "\"a\\\"b\"",
        "\"a\\\\b\"",
        "\"a\\u0041b\"",
    };

    for (documents) |document| {
        var cursor: Cursor = .init(document);
        const span = try cursor.stringSpan();

        try std.testing.expect(span.escaped);
        try std.testing.expect(cursor.atEnd());
    }
}

test "jzon behaviour: cursor bounds a number token at the first byte no number holds" {
    const cases = [_]struct { document: []const u8, token: []const u8 }{
        .{ .document = "0,", .token = "0" },
        .{ .document = "42}", .token = "42" },
        .{ .document = "-7]", .token = "-7" },
        .{ .document = "1.5 ", .token = "1.5" },
        .{ .document = "2e10\t", .token = "2e10" },
        .{ .document = "-3.25e-4,", .token = "-3.25e-4" },
    };

    for (cases) |case| {
        var cursor: Cursor = .init(case.document);

        try std.testing.expectEqualStrings(case.token, try cursor.numberSpan());
    }
}

test "jzon behaviour: cursor reads the three literal words" {
    var yes: Cursor = .init("true");
    try yes.literal("true");
    try std.testing.expect(yes.atEnd());

    var no: Cursor = .init("false");
    try no.literal("false");
    try std.testing.expect(no.atEnd());

    var nothing: Cursor = .init("null");
    try nothing.literal("null");
    try std.testing.expect(nothing.atEnd());
}

test "jzon behaviour: cursor accept consumes only on a match" {
    var cursor: Cursor = .init("[]");

    try std.testing.expect(!cursor.accept(','));
    try std.testing.expectEqual(@as(usize, 2), cursor.remaining());

    try std.testing.expect(cursor.accept('['));
    try std.testing.expectEqual(@as(usize, 1), cursor.remaining());
}
