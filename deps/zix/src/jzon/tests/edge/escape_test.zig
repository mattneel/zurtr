//! Edge tests: jzon.escape at its bounds.
//! Verifies every control byte against std.json.Stringify, the exact-fit buffer
//! on both directions, and each way a `\u` escape can be malformed.

const std = @import("std");
const jzon = @import("jzon");

const Sink = jzon.Sink;
const escape = jzon.escape;

/// The same string through std.json.Stringify, which jzon's output must match.
fn stdEncoded(buf: []u8, text: []const u8) []const u8 {
    var writer = std.Io.Writer.fixed(buf);
    std.json.Stringify.value(text, .{}, &writer) catch unreachable;

    return writer.buffered();
}

// --------------------------------------------------------- //

test "jzon edge: escape encodes every control byte the way std does" {
    for (0..0x20) |code| {
        const sample = [_]u8{@intCast(code)};

        var ours: [16]u8 = undefined;
        var sink: Sink = .init(&ours);
        try escape.encode(&sink, &sample);

        var theirs: [16]u8 = undefined;
        try std.testing.expectEqualStrings(stdEncoded(&theirs, &sample), sink.filled());
    }
}

test "jzon edge: escape leaves every byte at 0x20 and above raw, except quote and backslash" {
    for (0x20..0x100) |code| {
        const byte: u8 = @intCast(code);
        if (byte == '"' or byte == '\\') continue;

        const sample = [_]u8{byte};

        var buf: [16]u8 = undefined;
        var sink: Sink = .init(&buf);
        try escape.encodeBody(&sink, &sample);

        try std.testing.expectEqualStrings(&sample, sink.filled());
    }
}

test "jzon edge: escape encode on an empty string writes only the quotes" {
    var buf: [8]u8 = undefined;
    var sink: Sink = .init(&buf);

    try escape.encode(&sink, "");

    try std.testing.expectEqualStrings("\"\"", sink.filled());
}

test "jzon edge: escape encode fills an exact-fit buffer and refuses one byte short" {
    var exact: [9]u8 = undefined;
    var fits: Sink = .init(&exact);
    try escape.encode(&fits, "a\nbcde");
    try std.testing.expectEqualStrings("\"a\\nbcde\"", fits.filled());
    try std.testing.expectEqual(@as(usize, 0), fits.remaining());

    var tight: [8]u8 = undefined;
    var overflows: Sink = .init(&tight);
    try std.testing.expectError(error.NoSpaceLeft, escape.encode(&overflows, "a\nbcde"));
}

test "jzon edge: escape decode refuses an escape that never completes" {
    var buf: [16]u8 = undefined;

    var lone_backslash: Sink = .init(&buf);
    try std.testing.expectError(error.JzonBadEscape, escape.decode(&lone_backslash, "ab\\"));

    var unknown_spelling: Sink = .init(&buf);
    try std.testing.expectError(error.JzonBadEscape, escape.decode(&unknown_spelling, "a\\qb"));

    var short_unicode: Sink = .init(&buf);
    try std.testing.expectError(error.JzonBadEscape, escape.decode(&short_unicode, "\\u12"));

    var bad_hex: Sink = .init(&buf);
    try std.testing.expectError(error.JzonBadEscape, escape.decode(&bad_hex, "\\u12g4"));
}

test "jzon edge: escape decode reads hex digits in either case" {
    var lower_buf: [8]u8 = undefined;
    var lower: Sink = .init(&lower_buf);
    try escape.decode(&lower, "\\u00e9");

    var upper_buf: [8]u8 = undefined;
    var upper: Sink = .init(&upper_buf);
    try escape.decode(&upper, "\\u00E9");

    try std.testing.expectEqualStrings("\xc3\xa9", lower.filled());
    try std.testing.expectEqualStrings(lower.filled(), upper.filled());
}

test "jzon edge: escape decode refuses every unpaired surrogate half" {
    var buf: [16]u8 = undefined;

    var high_alone: Sink = .init(&buf);
    try std.testing.expectError(error.JzonBadEscape, escape.decode(&high_alone, "\\ud800"));

    var low_alone: Sink = .init(&buf);
    try std.testing.expectError(error.JzonBadEscape, escape.decode(&low_alone, "\\udc00"));

    var high_then_text: Sink = .init(&buf);
    try std.testing.expectError(error.JzonBadEscape, escape.decode(&high_then_text, "\\ud800abc"));

    var high_then_high: Sink = .init(&buf);
    try std.testing.expectError(error.JzonBadEscape, escape.decode(&high_then_high, "\\ud800\\ud800"));

    var high_then_plain: Sink = .init(&buf);
    try std.testing.expectError(error.JzonBadEscape, escape.decode(&high_then_plain, "\\ud800\\u0041"));
}

test "jzon edge: escape decode carries the surrogate range boundaries" {
    var lowest_buf: [8]u8 = undefined;
    var lowest: Sink = .init(&lowest_buf);
    try escape.decode(&lowest, "\\ud800\\udc00");

    var highest_buf: [8]u8 = undefined;
    var highest: Sink = .init(&highest_buf);
    try escape.decode(&highest, "\\udbff\\udfff");

    try std.testing.expectEqualStrings("\xf0\x90\x80\x80", lowest.filled());
    try std.testing.expectEqualStrings("\xf4\x8f\xbf\xbf", highest.filled());
}

test "jzon edge: escape decode of \\u0000 yields the nul byte" {
    var buf: [8]u8 = undefined;
    var sink: Sink = .init(&buf);

    try escape.decode(&sink, "a\\u0000b");

    try std.testing.expectEqualStrings("a\x00b", sink.filled());
}

test "jzon edge: escape decode refuses to overrun the buffer" {
    var tight: [3]u8 = undefined;
    var sink: Sink = .init(&tight);

    try std.testing.expectError(error.NoSpaceLeft, escape.decode(&sink, "abcd"));

    var one_short: [3]u8 = undefined;
    var unicode: Sink = .init(&one_short);
    try std.testing.expectError(error.NoSpaceLeft, escape.decode(&unicode, "\\ud83d\\udca9"));
}

test "jzon edge: needsEscape on an empty string is false" {
    try std.testing.expect(!escape.needsEscape(""));
}
