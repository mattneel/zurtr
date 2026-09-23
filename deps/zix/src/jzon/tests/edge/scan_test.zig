//! Edge tests: jzon.scan at the boundaries.
//! Covers an empty document, a document that is nothing but whitespace, a token
//! that ends on the last byte, and the widths agreeing on all of them.

const std = @import("std");
const jzon = @import("jzon");

const Cursor = jzon.Cursor;
const scan = jzon.scan;

const LANES = jzon.escape_vector.LANES;
const Shape = scan.Shape;

/// Both widths, so every case asserts the pair agrees.
const SHAPES = [_]Shape{
    .{ .scan = .SCALAR },
    .{ .scan = .VECTOR },
};

test "jzon edge: both widths leave an empty document alone" {
    inline for (SHAPES) |shape| {
        var cursor: Cursor = .init("");
        scan.skipSpace(&cursor, shape);

        try std.testing.expect(cursor.atEnd());
        try std.testing.expectError(error.JzonTruncated, scan.stringSpan(&cursor, shape));
    }
}

test "jzon edge: both widths run a whitespace-only document to its end" {
    for ([_]usize{ 1, LANES - 1, LANES, LANES + 1, LANES * 3 }) |len| {
        var document: [LANES * 3]u8 = @splat('\t');

        inline for (SHAPES) |shape| {
            var cursor: Cursor = .init(document[0..len]);
            scan.skipSpace(&cursor, shape);

            try std.testing.expect(cursor.atEnd());
        }
    }
}

test "jzon edge: both widths read a token ending on the document's last byte" {
    for ([_]usize{ 0, 1, LANES - 2, LANES - 1, LANES, LANES + 1 }) |body| {
        var document: [LANES * 2 + 2]u8 = @splat('x');
        document[0] = '"';
        document[body + 1] = '"';

        const src = document[0 .. body + 2];

        inline for (SHAPES) |shape| {
            var cursor: Cursor = .init(src);
            const span = try scan.stringSpan(&cursor, shape);

            try std.testing.expectEqual(body, span.raw.len);
            try std.testing.expect(cursor.atEnd());
        }
    }
}

test "jzon edge: both widths refuse a token opening on the last byte" {
    inline for (SHAPES) |shape| {
        var cursor: Cursor = .init("\"");

        try std.testing.expectError(error.JzonTruncated, scan.stringSpan(&cursor, shape));
    }
}

test "jzon edge: both widths report an escape the document ends on" {
    // The backslash takes the byte after it, and there is no byte after it.
    const documents = [_][]const u8{
        "\"\\",
        "\"a body long enough to cross one whole lane boundary \\",
    };

    for (documents) |document| {
        inline for (SHAPES) |shape| {
            var cursor: Cursor = .init(document);

            try std.testing.expectError(error.JzonTruncated, scan.stringSpan(&cursor, shape));
        }
    }
}

test "jzon edge: both widths keep an escaped quote inside the token" {
    const document = "\"a body with an escaped quote \\\" that does not end it here\"";

    inline for (SHAPES) |shape| {
        var cursor: Cursor = .init(document);
        const span = try scan.stringSpan(&cursor, shape);

        try std.testing.expect(span.escaped);
        try std.testing.expectEqualStrings(document[1 .. document.len - 1], span.raw);
        try std.testing.expect(cursor.atEnd());
    }
}
