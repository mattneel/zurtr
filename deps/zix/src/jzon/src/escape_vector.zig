//! jzon string escape, scanned a vector lane at a time.
//!
//! What:
//! - The same output as `escape.encodeBody`, byte for byte. What differs is only
//!   how the bytes that need escaping are found: a lane of them is classified in
//!   one comparison instead of one per byte.
//! - The rules stay in escape.zig. This file owns the scan and nothing else, so
//!   the two spellings can never drift apart.
//!
//! Note:
//! - This pays on long strings and costs on short ones. A string shorter than one
//!   lane never enters the vector loop at all, and one just over a lane pays the
//!   vector setup for a single comparison. Pick it for text, not for identifiers.

const std = @import("std");

const escape = @import("escape.zig");
const Sink = @import("sink.zig").Sink;

/// How encoding can fail. Encoding never allocates, so a full buffer is all of it.
pub const EncodeError = escape.EncodeError;

/// Bytes classified per comparison.
///
/// Note:
/// - Held at 16 because that is the width the measurement was taken at, and it is
///   the widest vector every supported target can lower without splitting.
pub const LANES = 16;

/// One lane of text.
pub const Chunk = @Vector(LANES, u8);

/// Write `text` as a complete JSON string, quotes included.
///
/// Param:
/// sink - *Sink (where the string goes)
/// text - []const u8 (the bytes to escape and write)
///
/// Return:
/// - void
/// - error.NoSpaceLeft when the escaped form does not fit
pub fn encode(sink: *Sink, text: []const u8) EncodeError!void {
    try sink.byte('"');
    try encodeBody(sink, text);
    try sink.byte('"');
}

/// Write `text` escaped, without the surrounding quotes.
///
/// Note:
/// - A clean lane advances the scan and writes nothing. The run of clean bytes
///   is only copied when an escape interrupts it or the text ends, so a string
///   with no escape costs one copy however long it is.
///
/// Param:
/// sink - *Sink (where the bytes go)
/// text - []const u8 (the bytes to escape and write)
///
/// Return:
/// - void
/// - error.NoSpaceLeft when the escaped form does not fit
pub fn encodeBody(sink: *Sink, text: []const u8) EncodeError!void {
    var clean_from: usize = 0;
    var index: usize = 0;

    while (index + LANES <= text.len) : (index += LANES) {
        const chunk: Chunk = text[index..][0..LANES].*;
        if (!anyEscaped(chunk)) continue;

        var offset = index;
        while (offset < index + LANES) : (offset += 1) {
            const byte = text[offset];
            if (!escape.isEscaped(byte)) continue;

            try sink.bytes(text[clean_from..offset]);
            try escape.spell(sink, byte);

            clean_from = offset + 1;
        }
    }

    while (index < text.len) : (index += 1) {
        const byte = text[index];
        if (!escape.isEscaped(byte)) continue;

        try sink.bytes(text[clean_from..index]);
        try escape.spell(sink, byte);

        clean_from = index + 1;
    }

    try sink.bytes(text[clean_from..]);
}

/// Where the first byte that cannot go out raw sits inside one lane.
///
/// Note:
/// - Three comparisons, all lane parallel, over the same set `escape.isEscaped`
///   answers for one byte. A clean lane costs the comparisons and nothing more,
///   because finding the position only runs once a lane has a hit in it.
/// - Both directions ask this. On the way out these are the bytes that have to
///   be spelled differently. On the way back in they are the bytes that end a
///   string token, open an escape, or may not appear raw at all.
///
/// Param:
/// chunk - Chunk (one lane of the text)
///
/// Return:
/// - usize (the offset inside the lane of the first such byte)
/// - null when every byte in the lane may stand as itself
pub inline fn firstEscaped(chunk: Chunk) ?usize {
    const quote: Chunk = @splat('"');
    const backslash: Chunk = @splat('\\');
    const first_printable: Chunk = @splat(0x20);

    const hits = (chunk == quote) | (chunk == backslash) | (chunk < first_printable);

    // The lane index comes back at its own narrow width, which every caller
    // wants as an offset it can add to a position.
    const at = std.simd.firstTrue(hits) orelse return null;

    return at;
}

/// Whether any byte in one lane has to be escaped.
inline fn anyEscaped(chunk: Chunk) bool {
    return firstEscaped(chunk) != null;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Every sample the cases below run over, chosen so each one crosses the lane
/// boundary somewhere different.
const SAMPLES = [_][]const u8{
    "",
    "short",
    "exactly sixteen!",
    "a string that runs well past one whole lane of bytes",
    "\"",
    "escape \" at the head of a lane that is otherwise clean",
    "a lane ending on an escape \\",
    "control \x00 in the middle of a long enough run to vectorize",
    "\n\r\t\x08\x0c back to back with nothing clean between them at all",
    "utf8 \xc3\xa9 \xe2\x82\xac \xf0\x9f\x92\xa9 past a lane boundary for sure",
};

test "jzon: vector escape writes what the scalar escape writes" {
    for (SAMPLES) |sample| {
        var vector_buf: [512]u8 = undefined;
        var vector_sink: Sink = .init(&vector_buf);
        try encode(&vector_sink, sample);

        var scalar_buf: [512]u8 = undefined;
        var scalar_sink: Sink = .init(&scalar_buf);
        try escape.encode(&scalar_sink, sample);

        try std.testing.expectEqualStrings(scalar_sink.filled(), vector_sink.filled());
    }
}

test "jzon: vector escape bodies match the scalar bodies" {
    for (SAMPLES) |sample| {
        var vector_buf: [512]u8 = undefined;
        var vector_sink: Sink = .init(&vector_buf);
        try encodeBody(&vector_sink, sample);

        var scalar_buf: [512]u8 = undefined;
        var scalar_sink: Sink = .init(&scalar_buf);
        try escape.encodeBody(&scalar_sink, sample);

        try std.testing.expectEqualStrings(scalar_sink.filled(), vector_sink.filled());
    }
}

test "jzon: vector escape agrees with the scalar one at every length" {
    // One escape walked through every position of a string long enough to cross
    // two lane boundaries, so the hit lands in a leading lane, a trailing lane
    // and the scalar remainder in turn.
    var text: [40]u8 = undefined;

    for (0..text.len) |at| {
        @memset(&text, 'x');
        text[at] = '\n';

        var vector_buf: [256]u8 = undefined;
        var vector_sink: Sink = .init(&vector_buf);
        try encodeBody(&vector_sink, &text);

        var scalar_buf: [256]u8 = undefined;
        var scalar_sink: Sink = .init(&scalar_buf);
        try escape.encodeBody(&scalar_sink, &text);

        try std.testing.expectEqualStrings(scalar_sink.filled(), vector_sink.filled());
    }
}

test "jzon: firstEscaped finds the same byte the scalar rule names" {
    var lane: [LANES]u8 = @splat('x');

    try std.testing.expect(firstEscaped(lane) == null);

    for (0..LANES) |at| {
        lane = @splat('x');
        lane[at] = '"';
        try std.testing.expectEqual(@as(?usize, at), firstEscaped(lane));

        lane[at] = '\\';
        try std.testing.expectEqual(@as(?usize, at), firstEscaped(lane));

        lane[at] = '\n';
        try std.testing.expectEqual(@as(?usize, at), firstEscaped(lane));
    }
}

test "jzon: firstEscaped reports the earliest hit in a lane" {
    var lane: [LANES]u8 = @splat('x');
    lane[3] = '\\';
    lane[9] = '"';

    try std.testing.expectEqual(@as(?usize, 3), firstEscaped(lane));
}

test "jzon: vector escape reports a buffer that cannot hold the result" {
    var buf: [4]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std.testing.expectError(
        error.NoSpaceLeft,
        encode(&sink, "a string far longer than four bytes"),
    );
}
