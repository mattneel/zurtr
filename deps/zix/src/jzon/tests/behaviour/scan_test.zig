//! Behaviour tests: jzon.scan, the choice between the two read widths.
//! Verifies both widths answer the same two questions the same way, so a parse
//! that swaps one for the other reads the same documents.

const std = @import("std");
const jzon = @import("jzon");

const Cursor = jzon.Cursor;
const scan = jzon.scan;

const Shape = scan.Shape;

/// Both widths, so every case asserts the pair agrees.
const SHAPES = [_]Shape{
    .{ .scan = .SCALAR },
    .{ .scan = .VECTOR },
};

test "jzon behaviour: the scan width defaults to the byte at a time one" {
    const shape: Shape = .{};

    try std.testing.expectEqual(scan.ScanPath.SCALAR, shape.scan);
}

test "jzon behaviour: both widths leave the cursor on the same byte" {
    const documents = [_][]const u8{
        "",
        "x",
        "   x",
        "\t\n\r\t x",
        "                                            x",
        "                                             ",
    };

    for (documents) |document| {
        var reached: [SHAPES.len]usize = undefined;

        inline for (SHAPES, 0..) |shape, index| {
            var cursor: Cursor = .init(document);
            scan.skipSpace(&cursor, shape);

            reached[index] = cursor.pos;
        }

        try std.testing.expectEqual(reached[0], reached[1]);
    }
}

test "jzon behaviour: both widths bound the same string token" {
    const documents = [_][]const u8{
        "\"\"",
        "\"plain\"",
        "\"a body that runs well past one whole lane of bytes\"",
        "\"with \\\" an escape in it\"",
        "\"\\u00e9\"",
    };

    for (documents) |document| {
        var raws: [SHAPES.len][]const u8 = undefined;
        var flags: [SHAPES.len]bool = undefined;
        var reached: [SHAPES.len]usize = undefined;

        inline for (SHAPES, 0..) |shape, index| {
            var cursor: Cursor = .init(document);
            const span = try scan.stringSpan(&cursor, shape);

            raws[index] = span.raw;
            flags[index] = span.escaped;
            reached[index] = cursor.pos;
        }

        try std.testing.expectEqualStrings(raws[0], raws[1]);
        try std.testing.expectEqual(flags[0], flags[1]);
        try std.testing.expectEqual(reached[0], reached[1]);
    }
}

test "jzon behaviour: both widths report the same failure" {
    const Case = struct {
        document: []const u8,
        failure: anyerror,
    };

    const cases = [_]Case{
        .{ .document = "", .failure = error.JzonTruncated },
        .{ .document = "\"never closed", .failure = error.JzonTruncated },
        .{ .document = "not a string", .failure = error.JzonUnexpected },
        .{ .document = "\"a raw \x01 control byte\"", .failure = error.JzonUnexpected },
    };

    for (cases) |case| {
        inline for (SHAPES) |shape| {
            var cursor: Cursor = .init(case.document);

            try std.testing.expectError(case.failure, scan.stringSpan(&cursor, shape));
        }
    }
}

test "jzon behaviour: a walk over one document reaches the same place at both widths" {
    const document = "  { \"key\" : \"a value long enough to fill one whole lane\" }  ";

    var reached: [SHAPES.len]usize = undefined;

    inline for (SHAPES, 0..) |shape, index| {
        var cursor: Cursor = .init(document);

        scan.skipSpace(&cursor, shape);
        try cursor.expect('{');

        scan.skipSpace(&cursor, shape);
        const key = try scan.stringSpan(&cursor, shape);
        try std.testing.expectEqualStrings("key", key.raw);

        scan.skipSpace(&cursor, shape);
        try cursor.expect(':');

        scan.skipSpace(&cursor, shape);
        _ = try scan.stringSpan(&cursor, shape);

        scan.skipSpace(&cursor, shape);
        try cursor.expect('}');

        scan.skipSpace(&cursor, shape);
        reached[index] = cursor.pos;
    }

    try std.testing.expectEqual(document.len, reached[0]);
    try std.testing.expectEqual(reached[0], reached[1]);
}
