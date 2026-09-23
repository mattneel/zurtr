//! jzon read cursor, scanned a vector lane at a time.
//!
//! What:
//! - The two scans a parse repeats most: stepping over the whitespace between
//!   tokens, and finding where a string token ends. A whole lane of bytes is
//!   classified in one comparison instead of one per byte.
//! - The cursor still owns the position and the bounds. This file owns the scan
//!   and nothing else, so both widths leave the cursor in the same place on the
//!   same document.
//!
//! Note:
//! - This pays on documents that arrive pretty printed or carry long strings. On
//!   minified traffic with short fields there is no whitespace to step over and
//!   no string long enough to fill a lane, so the lane setup is cost with
//!   nothing to show for it. That is why the width is a call-site choice.
//! - The whitespace skip asks the byte already under the cursor before it loads
//!   anything. A minified document answers there and never reaches the lane
//!   loop, which is the case that would otherwise pay the most for nothing.

const std = @import("std");

const cursor_mod = @import("cursor.zig");
const escape_vector = @import("escape_vector.zig");

const Chunk = escape_vector.Chunk;
const Cursor = cursor_mod.Cursor;
const LANES = escape_vector.LANES;
const StringSpan = cursor_mod.StringSpan;

/// How a read can fail. The same set the scalar cursor reports.
pub const Error = cursor_mod.Error;

/// Step over the insignificant whitespace between tokens.
///
/// Note:
/// - A lane of whitespace advances the cursor by the whole lane. The first lane
///   that holds anything else lands the cursor exactly on it.
///
/// Param:
/// cursor - *Cursor (the cursor to advance)
///
/// Return:
/// - void
pub fn skipSpace(cursor: *Cursor) void {
    if (cursor.pos == cursor.src.len or !cursor_mod.isSpace(cursor.src[cursor.pos])) return;

    while (cursor.pos + LANES <= cursor.src.len) {
        const chunk: Chunk = cursor.src[cursor.pos..][0..LANES].*;

        if (firstOther(chunk)) |offset| {
            cursor.pos += offset;

            return;
        }

        cursor.pos += LANES;
    }

    cursor.skipSpace();
}

/// Read a string token, both quotes included, and return the bytes between them
/// undecoded.
///
/// Note:
/// - A lane with nothing of interest in it advances the cursor whole. Otherwise
///   the cursor lands on the first byte that matters and that one byte is read,
///   which is what lets a backslash take the byte after it even when the two sit
///   in different lanes.
/// - The result is what the scalar `Cursor.stringSpan` returns for the same
///   document, failures included.
///
/// Param:
/// cursor - *Cursor (positioned at the opening quote)
///
/// Return:
/// - StringSpan (the undecoded body, plus whether it holds an escape)
/// - error.JzonTruncated when the closing quote never arrives
/// - error.JzonUnexpected when the token does not open with a quote, or carries a
///   raw control byte
pub fn stringSpan(cursor: *Cursor) Error!StringSpan {
    try cursor.expect('"');

    const start = cursor.pos;
    var escaped = false;

    while (true) {
        if (cursor.pos + LANES <= cursor.src.len) {
            const chunk: Chunk = cursor.src[cursor.pos..][0..LANES].*;

            if (escape_vector.firstEscaped(chunk)) |offset| {
                cursor.pos += offset;
            } else {
                cursor.pos += LANES;

                continue;
            }
        }

        if (cursor.pos == cursor.src.len) return error.JzonTruncated;

        const byte = cursor.src[cursor.pos];

        if (byte == '"') {
            const raw = cursor.src[start..cursor.pos];
            cursor.pos += 1;

            return .{ .raw = raw, .escaped = escaped };
        }

        if (byte < 0x20) return error.JzonUnexpected;

        if (byte == '\\') {
            if (cursor.pos + 1 == cursor.src.len) return error.JzonTruncated;

            escaped = true;
            cursor.pos += 2;

            continue;
        }

        cursor.pos += 1;
    }
}

/// Where the first byte that is not whitespace sits inside one lane.
///
/// Note:
/// - The comparisons are built from `cursor.WHITESPACE`, so the set is the one
///   the scalar rule answers for and the two cannot drift apart.
///
/// Param:
/// chunk - Chunk (one lane of the document)
///
/// Return:
/// - usize (the offset inside the lane of the first byte to stop on)
/// - null when the whole lane is whitespace
inline fn firstOther(chunk: Chunk) ?usize {
    var spaces: @Vector(LANES, bool) = @splat(false);

    inline for (cursor_mod.WHITESPACE) |allowed| {
        const wanted: Chunk = @splat(allowed);
        spaces = spaces | (chunk == wanted);
    }

    // The lane index comes back at its own narrow width, which the caller wants
    // as an offset it can add to a position.
    const at = std.simd.firstTrue(~spaces) orelse return null;

    return at;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Every document the cases below run over, chosen so each one crosses the lane
/// boundary somewhere different.
const DOCUMENTS = [_][]const u8{
    "",
    " ",
    "   \t\n\r  x",
    "                                   deep past two whole lanes",
    "\"\"",
    "\"short\"",
    "\"a string body that runs well past one whole lane of bytes\"",
    "\"escape \\\" in a lane that is otherwise clean and rather long\"",
    "\"a lane boundary landing right on an escape \\\\ here\"",
    "\"\\u00e9\\ud83d\\udca9 back to back escapes with nothing plain between\"",
};

test "jzon: vector skipSpace stops where the scalar skip stops" {
    for (DOCUMENTS) |document| {
        var ours: Cursor = .init(document);
        skipSpace(&ours);

        var theirs: Cursor = .init(document);
        theirs.skipSpace();

        try std.testing.expectEqual(theirs.pos, ours.pos);
    }
}

test "jzon: vector skipSpace steps over runs longer than one lane" {
    // Two whole lanes of whitespace and one byte more, so the lane loop runs
    // twice and the scalar tail finishes the job.
    var document: [LANES * 2 + 1 + 3]u8 = @splat(' ');
    document[LANES * 2 + 1] = 'a';

    var cursor: Cursor = .init(&document);
    skipSpace(&cursor);

    try std.testing.expectEqual(@as(usize, LANES * 2 + 1), cursor.pos);
}

test "jzon: vector stringSpan reads what the scalar span reads" {
    for (DOCUMENTS) |document| {
        var ours: Cursor = .init(document);
        const our_span = stringSpan(&ours);

        var theirs: Cursor = .init(document);
        const their_span = theirs.stringSpan();

        if (their_span) |wanted| {
            const got = try our_span;

            try std.testing.expectEqualStrings(wanted.raw, got.raw);
            try std.testing.expectEqual(wanted.escaped, got.escaped);
            try std.testing.expectEqual(theirs.pos, ours.pos);
        } else |failure| {
            try std.testing.expectError(failure, our_span);
        }
    }
}

test "jzon: vector stringSpan agrees with the scalar one at every position" {
    // One escape walked through every position of a body long enough to cross
    // two lane boundaries, so the hit lands in a leading lane, a trailing lane
    // and the scalar tail in turn.
    var document: [40]u8 = undefined;

    for (1..document.len - 3) |at| {
        @memset(&document, 'x');
        document[0] = '"';
        document[at] = '\\';
        document[at + 1] = 't';
        document[document.len - 1] = '"';

        var ours: Cursor = .init(&document);
        const got = try stringSpan(&ours);

        var theirs: Cursor = .init(&document);
        const wanted = try theirs.stringSpan();

        try std.testing.expectEqualStrings(wanted.raw, got.raw);
        try std.testing.expectEqual(wanted.escaped, got.escaped);
        try std.testing.expectEqual(theirs.pos, ours.pos);
    }
}

test "jzon: vector stringSpan leaves the bytes after the token unread" {
    var cursor: Cursor = .init("\"a body long enough to fill a whole lane and more\",rest");

    const span = try stringSpan(&cursor);

    try std.testing.expect(!span.escaped);
    try std.testing.expectEqualStrings(",rest", cursor.src[cursor.pos..]);
}
