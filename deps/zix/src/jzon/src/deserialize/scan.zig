//! jzon deserialize scan width.
//!
//! What:
//! - Which of the two read scans a parse runs, and the two questions that
//!   differ between them. Everything else a parse asks the document costs the
//!   same either way, so it goes straight to the cursor.
//! - Both widths land the cursor in the same place on the same document and
//!   report the same failures, which is what makes the width a cost decision and
//!   nothing else.

const cursor_mod = @import("../cursor.zig");
const cursor_vector = @import("../cursor_vector.zig");

const Cursor = cursor_mod.Cursor;
const StringSpan = cursor_mod.StringSpan;

/// How a read can fail. The same set the cursor reports.
pub const Error = cursor_mod.Error;

/// How many bytes a scan classifies at once.
pub const ScanPath = enum {
    /// One byte at a time.
    SCALAR,
    /// One vector lane at a time, which pays on whitespace and long strings.
    VECTOR,
};

/// The width a parse runs with.
///
/// Note:
/// - One axis today, held on a struct so a second one can arrive without every
///   call site changing shape. The generated emitter carries its pairing the
///   same way.
pub const Shape = struct {
    scan: ScanPath = .SCALAR,
};

/// Step over the insignificant whitespace between tokens.
///
/// Param:
/// cursor - *Cursor (the cursor to advance)
/// shape - Shape (comptime, which width to scan at)
///
/// Return:
/// - void
pub inline fn skipSpace(cursor: *Cursor, comptime shape: Shape) void {
    switch (shape.scan) {
        .SCALAR => cursor.skipSpace(),
        .VECTOR => cursor_vector.skipSpace(cursor),
    }
}

/// Read a string token and return the bytes between its quotes undecoded.
///
/// Param:
/// cursor - *Cursor (positioned at the opening quote)
/// shape - Shape (comptime, which width to scan at)
///
/// Return:
/// - StringSpan (the undecoded body, plus whether it holds an escape)
/// - error.JzonTruncated when the closing quote never arrives
/// - error.JzonUnexpected when the token does not open with a quote, or carries a
///   raw control byte
pub inline fn stringSpan(cursor: *Cursor, comptime shape: Shape) Error!StringSpan {
    return switch (shape.scan) {
        .SCALAR => cursor.stringSpan(),
        .VECTOR => cursor_vector.stringSpan(cursor),
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const std = @import("std");

/// Both widths, so a case can assert the pair agrees.
const SHAPES = [_]Shape{
    .{ .scan = .SCALAR },
    .{ .scan = .VECTOR },
};

test "jzon: both scan widths step over the same whitespace" {
    const documents = [_][]const u8{
        "",
        "x",
        "  x",
        "\t\n\r x",
        "                                   x",
    };

    for (documents) |document| {
        var reached: [SHAPES.len]usize = undefined;

        inline for (SHAPES, 0..) |shape, index| {
            var cursor: Cursor = .init(document);
            skipSpace(&cursor, shape);

            reached[index] = cursor.pos;
        }

        try std.testing.expectEqual(reached[0], reached[1]);
    }
}

test "jzon: both scan widths bound the same string token" {
    const documents = [_][]const u8{
        "\"\"",
        "\"plain\"",
        "\"a body that runs well past one whole lane of bytes\"",
        "\"with \\\" an escape in it\"",
    };

    for (documents) |document| {
        var raws: [SHAPES.len][]const u8 = undefined;
        var flags: [SHAPES.len]bool = undefined;

        inline for (SHAPES, 0..) |shape, index| {
            var cursor: Cursor = .init(document);
            const span = try stringSpan(&cursor, shape);

            raws[index] = span.raw;
            flags[index] = span.escaped;
        }

        try std.testing.expectEqualStrings(raws[0], raws[1]);
        try std.testing.expectEqual(flags[0], flags[1]);
    }
}

test "jzon: the scan width defaults to the scalar one" {
    const shape: Shape = .{};

    try std.testing.expectEqual(ScanPath.SCALAR, shape.scan);
}
