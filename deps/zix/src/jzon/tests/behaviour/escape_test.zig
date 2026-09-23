//! Behaviour tests: jzon.escape, the string rules both directions share.
//! Verifies the encoded form against std.json.Stringify, the round trip back
//! through decode, and that needsEscape answers for the same byte set encode acts on.

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

/// Every sample the cases below run over: clean runs, each escape family, and
/// multi-byte UTF-8.
const SAMPLES = [_][]const u8{
    "",
    "plain",
    "a longer run with spaces and digits 0123456789",
    "quote \" here",
    "backslash \\ here",
    "newline \n carriage \r tab \t backspace \x08 formfeed \x0c",
    "unnamed \x00 \x01 \x0b \x0e \x1f controls",
    "utf8 \xc3\xa9 \xe2\x82\xac \xf0\x9f\x92\xa9",
    "delete \x7f and high \xc2\xa0 bytes",
    "\"leading quote and trailing backslash\\\\",
};

// --------------------------------------------------------- //

test "jzon behaviour: escape encode matches std.json.Stringify byte for byte" {
    for (SAMPLES) |sample| {
        var ours: [256]u8 = undefined;
        var sink: Sink = .init(&ours);
        try escape.encode(&sink, sample);

        var theirs: [256]u8 = undefined;
        try std.testing.expectEqualStrings(stdEncoded(&theirs, sample), sink.filled());
    }
}

test "jzon behaviour: escape encode wraps the body in quotes" {
    var quoted_buf: [64]u8 = undefined;
    var quoted: Sink = .init(&quoted_buf);
    try escape.encode(&quoted, "value");

    var body_buf: [64]u8 = undefined;
    var body: Sink = .init(&body_buf);
    try escape.encodeBody(&body, "value");

    try std.testing.expectEqualStrings("\"value\"", quoted.filled());
    try std.testing.expectEqualStrings("value", body.filled());
}

test "jzon behaviour: escape decode returns every sample unchanged" {
    for (SAMPLES) |sample| {
        var encoded_buf: [256]u8 = undefined;
        var encoded: Sink = .init(&encoded_buf);
        try escape.encodeBody(&encoded, sample);

        var decoded_buf: [256]u8 = undefined;
        var decoded: Sink = .init(&decoded_buf);
        try escape.decode(&decoded, encoded.filled());

        try std.testing.expectEqualStrings(sample, decoded.filled());
    }
}

test "jzon behaviour: escape decode agrees with what std.json parses" {
    for (SAMPLES) |sample| {
        var encoded_buf: [256]u8 = undefined;
        const document = stdEncoded(&encoded_buf, sample);

        const parsed = try std.json.parseFromSlice([]const u8, std.testing.allocator, document, .{});
        defer parsed.deinit();

        var decoded_buf: [256]u8 = undefined;
        var decoded: Sink = .init(&decoded_buf);
        try escape.decode(&decoded, document[1 .. document.len - 1]);

        try std.testing.expectEqualStrings(parsed.value, decoded.filled());
    }
}

test "jzon behaviour: needsEscape answers true for exactly what encode rewrites" {
    for (SAMPLES) |sample| {
        var encoded_buf: [256]u8 = undefined;
        var encoded: Sink = .init(&encoded_buf);
        try escape.encodeBody(&encoded, sample);

        const rewritten = !std.mem.eql(u8, sample, encoded.filled());

        try std.testing.expectEqual(rewritten, escape.needsEscape(sample));
    }
}

test "jzon behaviour: escape decode reads the solidus form encode never writes" {
    var buf: [32]u8 = undefined;
    var sink: Sink = .init(&buf);

    try escape.decode(&sink, "path\\/to\\/thing");

    try std.testing.expectEqualStrings("path/to/thing", sink.filled());
}

test "jzon behaviour: escape decode turns a surrogate pair into one code point" {
    var buf: [32]u8 = undefined;
    var sink: Sink = .init(&buf);

    try escape.decode(&sink, "before \\ud83d\\udca9 after");

    try std.testing.expectEqualStrings("before \xf0\x9f\x92\xa9 after", sink.filled());
}
