//! Edge tests: jzon.Cursor at its bounds.
//! Verifies the empty document, tokens that never close, the byte a string may
//! not carry raw, and the difference between a document that ran out and one
//! that holds the wrong byte.

const std = @import("std");
const jzon = @import("jzon");

const Cursor = jzon.Cursor;

// --------------------------------------------------------- //

test "jzon edge: cursor over an empty document has nothing to give" {
    var cursor: Cursor = .init("");

    try std.testing.expect(cursor.atEnd());
    try std.testing.expectEqual(@as(usize, 0), cursor.remaining());
    try std.testing.expectError(error.JzonTruncated, cursor.peek());
    try std.testing.expectError(error.JzonTruncated, cursor.take());
    try std.testing.expectError(error.JzonTruncated, cursor.expect('{'));
    try std.testing.expectError(error.JzonTruncated, cursor.stringSpan());
    try std.testing.expectError(error.JzonTruncated, cursor.numberSpan());
    try std.testing.expect(!cursor.accept('{'));

    cursor.skipSpace();
    try std.testing.expect(cursor.atEnd());
}

test "jzon edge: cursor over an all-whitespace document lands at the end" {
    var cursor: Cursor = .init(" \t\n\r");

    cursor.skipSpace();

    try std.testing.expect(cursor.atEnd());
}

test "jzon edge: cursor on a string that never closes reports truncation" {
    var open: Cursor = .init("\"unterminated");
    try std.testing.expectError(error.JzonTruncated, open.stringSpan());

    var trailing_backslash: Cursor = .init("\"broken\\");
    try std.testing.expectError(error.JzonTruncated, trailing_backslash.stringSpan());

    var escaped_close: Cursor = .init("\"never done\\\"");
    try std.testing.expectError(error.JzonTruncated, escaped_close.stringSpan());
}

test "jzon edge: cursor rejects a raw control byte inside a string" {
    var newline: Cursor = .init("\"line\nbreak\"");
    try std.testing.expectError(error.JzonUnexpected, newline.stringSpan());

    var nul: Cursor = .init("\"has\x00nul\"");
    try std.testing.expectError(error.JzonUnexpected, nul.stringSpan());

    var unit_separator: Cursor = .init("\"has\x1fseparator\"");
    try std.testing.expectError(error.JzonUnexpected, unit_separator.stringSpan());
}

test "jzon edge: cursor accepts the boundary bytes a string may carry raw" {
    var space: Cursor = .init("\" \"");
    try std.testing.expectEqualStrings(" ", (try space.stringSpan()).raw);

    var delete: Cursor = .init("\"\x7f\"");
    try std.testing.expectEqualStrings("\x7f", (try delete.stringSpan()).raw);

    var high: Cursor = .init("\"\xff\"");
    try std.testing.expectEqualStrings("\xff", (try high.stringSpan()).raw);
}

test "jzon edge: cursor on an empty string token gives an empty span" {
    var cursor: Cursor = .init("\"\"");

    const span = try cursor.stringSpan();

    try std.testing.expectEqual(@as(usize, 0), span.raw.len);
    try std.testing.expect(!span.escaped);
    try std.testing.expect(cursor.atEnd());
}

test "jzon edge: cursor tells a wrong byte apart from a spent document" {
    var wrong: Cursor = .init("}");
    try std.testing.expectError(error.JzonUnexpected, wrong.expect('{'));

    var spent: Cursor = .init("");
    try std.testing.expectError(error.JzonTruncated, spent.expect('{'));

    var not_a_string: Cursor = .init("42");
    try std.testing.expectError(error.JzonUnexpected, not_a_string.stringSpan());

    var not_a_number: Cursor = .init("\"42\"");
    try std.testing.expectError(error.JzonUnexpected, not_a_number.numberSpan());
}

test "jzon edge: cursor number span runs to the end of the document" {
    var cursor: Cursor = .init("12345");

    try std.testing.expectEqualStrings("12345", try cursor.numberSpan());
    try std.testing.expect(cursor.atEnd());
}

test "jzon edge: cursor number span holds a token no number can be read from" {
    var cursor: Cursor = .init("1.2.3,");

    // Bounding a token and validating it are separate jobs. The malformed run
    // comes back whole and is rejected by whatever converts it.
    try std.testing.expectEqualStrings("1.2.3", try cursor.numberSpan());
    try std.testing.expect(cursor.accept(','));
}

test "jzon edge: cursor literal at the very end of the document" {
    var exact: Cursor = .init("null");
    try exact.literal("null");
    try std.testing.expect(exact.atEnd());

    var one_short: Cursor = .init("fals");
    try std.testing.expectError(error.JzonTruncated, one_short.literal("false"));
    try std.testing.expectEqual(@as(usize, 4), one_short.remaining());
}
