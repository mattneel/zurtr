//! Edge tests: jzon.cursor_vector at the boundaries.
//! Covers a token that ends exactly on a lane boundary, an escape split across
//! one, a document shorter than a single lane, and the bytes a string may not
//! carry raw.

const std = @import("std");
const jzon = @import("jzon");

const Cursor = jzon.Cursor;
const cursor_vector = jzon.cursor_vector;

const LANES = jzon.escape_vector.LANES;

test "jzon edge: the lane scan reads a token whose quote lands on a lane boundary" {
    // The opening quote takes one byte, so a body of LANES - 1 puts the closing
    // quote at the last byte of the first lane, and a body of LANES puts it at
    // the first byte of the second.
    for ([_]usize{ LANES - 2, LANES - 1, LANES, LANES + 1 }) |body| {
        var document: [LANES * 2 + 2]u8 = @splat('x');
        document[0] = '"';
        document[body + 1] = '"';

        const src = document[0 .. body + 2];

        var ours: Cursor = .init(src);
        const got = try cursor_vector.stringSpan(&ours);

        var theirs: Cursor = .init(src);
        const wanted = try theirs.stringSpan();

        try std.testing.expectEqualStrings(wanted.raw, got.raw);
        try std.testing.expectEqual(theirs.pos, ours.pos);
    }
}

test "jzon edge: the lane scan reads an escape split across a lane boundary" {
    // Walk a two-byte escape through every position, so its backslash sits in
    // one lane and its spelling in the next.
    for (1..LANES * 2) |at| {
        var document: [LANES * 2 + 4]u8 = @splat('x');
        document[0] = '"';
        document[at] = '\\';
        document[at + 1] = 't';
        document[document.len - 1] = '"';

        var ours: Cursor = .init(&document);
        const got = try cursor_vector.stringSpan(&ours);

        var theirs: Cursor = .init(&document);
        const wanted = try theirs.stringSpan();

        try std.testing.expectEqualStrings(wanted.raw, got.raw);
        try std.testing.expectEqual(wanted.escaped, got.escaped);
        try std.testing.expectEqual(theirs.pos, ours.pos);
    }
}

test "jzon edge: the lane scan reports a token the document ends inside" {
    var unterminated: Cursor = .init("\"a body long enough to fill a whole lane but never closed");
    try std.testing.expectError(error.JzonTruncated, cursor_vector.stringSpan(&unterminated));

    var trailing_backslash: Cursor = .init("\"a body long enough to fill a whole lane ending on \\");
    try std.testing.expectError(error.JzonTruncated, cursor_vector.stringSpan(&trailing_backslash));

    var empty: Cursor = .init("");
    try std.testing.expectError(error.JzonTruncated, cursor_vector.stringSpan(&empty));
}

test "jzon edge: the lane scan refuses a raw control byte inside a token" {
    var short: Cursor = .init("\"a\x01b\"");
    try std.testing.expectError(error.JzonUnexpected, cursor_vector.stringSpan(&short));

    // Past the first lane, so the byte is found by the lane scan rather than by
    // the tail that follows it.
    var long: Cursor = .init("\"a body long enough to fill a whole lane\x01 and then some\"");
    try std.testing.expectError(error.JzonUnexpected, cursor_vector.stringSpan(&long));
}

test "jzon edge: the lane scan refuses a token that does not open with a quote" {
    var cursor: Cursor = .init("not a string at all, though long enough for a lane");

    try std.testing.expectError(error.JzonUnexpected, cursor_vector.stringSpan(&cursor));
    try std.testing.expectEqual(@as(usize, 0), cursor.pos);
}

test "jzon edge: the lane scan skips whitespace on a document shorter than a lane" {
    var cursor: Cursor = .init("  x");
    cursor_vector.skipSpace(&cursor);

    try std.testing.expectEqual(@as(usize, 2), cursor.pos);

    // Nothing but whitespace, and less of it than one lane.
    var all_space: Cursor = .init("   ");
    cursor_vector.skipSpace(&all_space);

    try std.testing.expect(all_space.atEnd());
}

test "jzon edge: the lane scan skips a document that is whitespace to its end" {
    var document: [LANES * 3]u8 = @splat('\n');

    var cursor: Cursor = .init(&document);
    cursor_vector.skipSpace(&cursor);

    try std.testing.expect(cursor.atEnd());
}

test "jzon edge: the lane scan stops on a byte the whitespace set does not hold" {
    // 0x0b and 0x0c are control bytes that JSON does not count as whitespace, so
    // the skip has to leave them for the token that follows to report.
    for ([_]u8{ 0x00, 0x0b, 0x0c, 0x1f }) |byte| {
        var document: [LANES + 2]u8 = @splat(' ');
        document[LANES + 1] = byte;

        var cursor: Cursor = .init(&document);
        cursor_vector.skipSpace(&cursor);

        try std.testing.expectEqual(@as(usize, LANES + 1), cursor.pos);
    }
}
