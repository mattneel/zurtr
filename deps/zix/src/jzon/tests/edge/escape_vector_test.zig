//! Edge tests: jzon.escape_vector at the boundaries.
//! Covers every length around the lane width, an escape at each position in a
//! string, strings that are nothing but escapes, and buffers that fit exactly or
//! one byte short.

const std = @import("std");
const jzon = @import("jzon");

const Sink = jzon.Sink;
const escape = jzon.escape;
const escape_vector = jzon.escape_vector;

/// The lane width the vector scan reads at. The cases walk across it in both
/// directions rather than assume where the boundary falls.
const LANES = 16;

test "jzon edge: vector escape matches the scalar scan at every length up to three lanes" {
    var text: [LANES * 3]u8 = undefined;
    @memset(&text, 'x');

    for (0..text.len + 1) |len| {
        var vector_buf: [512]u8 = undefined;
        var vector_sink: Sink = .init(&vector_buf);
        try escape_vector.encodeBody(&vector_sink, text[0..len]);

        var scalar_buf: [512]u8 = undefined;
        var scalar_sink: Sink = .init(&scalar_buf);
        try escape.encodeBody(&scalar_sink, text[0..len]);

        try std.testing.expectEqualStrings(scalar_sink.filled(), vector_sink.filled());
    }
}

test "jzon edge: vector escape matches the scalar scan with one escape at every position" {
    var text: [LANES * 3]u8 = undefined;

    for (0..text.len) |at| {
        @memset(&text, 'x');
        text[at] = '"';

        var vector_buf: [512]u8 = undefined;
        var vector_sink: Sink = .init(&vector_buf);
        try escape_vector.encodeBody(&vector_sink, &text);

        var scalar_buf: [512]u8 = undefined;
        var scalar_sink: Sink = .init(&scalar_buf);
        try escape.encodeBody(&scalar_sink, &text);

        try std.testing.expectEqualStrings(scalar_sink.filled(), vector_sink.filled());
    }
}

test "jzon edge: vector escape matches the scalar scan on a string of nothing but escapes" {
    var text: [LANES * 2]u8 = undefined;

    for (&text, 0..) |*byte, index| {
        byte.* = @intCast(index % 0x20);
    }

    var vector_buf: [1024]u8 = undefined;
    var vector_sink: Sink = .init(&vector_buf);
    try escape_vector.encodeBody(&vector_sink, &text);

    var scalar_buf: [1024]u8 = undefined;
    var scalar_sink: Sink = .init(&scalar_buf);
    try escape.encodeBody(&scalar_sink, &text);

    try std.testing.expectEqualStrings(scalar_sink.filled(), vector_sink.filled());
}

test "jzon edge: vector escape matches the scalar scan over every single byte" {
    for (0..256) |value| {
        const byte: u8 = @intCast(value);
        const text = [_]u8{byte};

        var vector_buf: [16]u8 = undefined;
        var vector_sink: Sink = .init(&vector_buf);
        try escape_vector.encodeBody(&vector_sink, &text);

        var scalar_buf: [16]u8 = undefined;
        var scalar_sink: Sink = .init(&scalar_buf);
        try escape.encodeBody(&scalar_sink, &text);

        try std.testing.expectEqualStrings(scalar_sink.filled(), vector_sink.filled());
    }
}

test "jzon edge: vector escape leaves every byte at 0x20 and above raw, except quote and backslash" {
    // 0x20 through 0x5f, the run that holds both bytes above 0x1f that still have
    // to be escaped.
    var text: [LANES * 4]u8 = undefined;

    for (&text, 0..) |*byte, index| {
        byte.* = @intCast(0x20 + index);
    }

    var buf: [512]u8 = undefined;
    var sink: Sink = .init(&buf);
    try escape_vector.encodeBody(&sink, &text);

    // Only the quote and the backslash are in this run, and each costs one extra
    // byte, so the body is two longer than the input.
    try std.testing.expectEqual(text.len + 2, sink.written());
}

test "jzon edge: vector escape on an empty string writes only the quotes" {
    var buf: [8]u8 = undefined;
    var sink: Sink = .init(&buf);

    try escape_vector.encode(&sink, "");

    try std.testing.expectEqualStrings("\"\"", sink.filled());
}

test "jzon edge: vector escape fills an exact-fit buffer and refuses one byte short" {
    // "a\nbcde" is nine bytes once escaped and quoted.
    const sample = "a\nbcde";

    var fits: [9]u8 = undefined;
    var exact: Sink = .init(&fits);
    try escape_vector.encode(&exact, sample);
    try std.testing.expectEqualStrings("\"a\\nbcde\"", exact.filled());
    try std.testing.expectEqual(@as(usize, 0), exact.remaining());

    var cramped: [8]u8 = undefined;
    var short: Sink = .init(&cramped);
    try std.testing.expectError(error.NoSpaceLeft, escape_vector.encode(&short, sample));
}

test "jzon edge: vector escape refuses a buffer that runs out inside a lane" {
    // The clean run ahead of the escape is copied first, so the room it takes is
    // gone before the escape's own spelling is attempted.
    var buf: [20]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std.testing.expectError(
        error.NoSpaceLeft,
        escape_vector.encode(&sink, "a long clean run of bytes then a \" quote"),
    );
}

test "jzon edge: vector escape refuses an empty buffer" {
    var buf: [0]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std.testing.expectError(error.NoSpaceLeft, escape_vector.encode(&sink, ""));
}
