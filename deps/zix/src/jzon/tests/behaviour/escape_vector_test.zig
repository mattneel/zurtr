//! Behaviour tests: jzon.escape_vector, the lane-at-a-time escape scan.
//! Verifies it writes exactly what the scalar scan writes, that both agree with
//! std.json.Stringify, and that the result decodes back to the input.

const std = @import("std");
const jzon = @import("jzon");

const Sink = jzon.Sink;
const escape = jzon.escape;
const escape_vector = jzon.escape_vector;

/// The same string through std.json.Stringify, which both scans must match.
fn stdEncoded(buf: []u8, text: []const u8) []const u8 {
    var writer = std.Io.Writer.fixed(buf);
    std.json.Stringify.value(text, .{}, &writer) catch unreachable;

    return writer.buffered();
}

/// Strings a record realistically carries, long enough that most of them cross
/// at least one lane boundary.
const SAMPLES = [_][]const u8{
    "",
    "id",
    "a product name that runs comfortably past a single lane of bytes",
    "quoted \"value\" inside a sentence long enough to be scanned in lanes",
    "a windows path C:\\Users\\someone\\Documents\\report.txt written out",
    "line one\nline two\nline three\nand a fourth to push it well past a lane",
    "tab\tseparated\tfields\tacross\tenough\tcolumns\tto\tfill\tseveral\tlanes",
    "utf8 text with \xc3\xa9 and \xe2\x82\xac and \xf0\x9f\x92\xa9 spread through it",
};

test "jzon behaviour: vector escape writes what the scalar escape writes" {
    for (SAMPLES) |sample| {
        var vector_buf: [512]u8 = undefined;
        var vector_sink: Sink = .init(&vector_buf);
        try escape_vector.encode(&vector_sink, sample);

        var scalar_buf: [512]u8 = undefined;
        var scalar_sink: Sink = .init(&scalar_buf);
        try escape.encode(&scalar_sink, sample);

        try std.testing.expectEqualStrings(scalar_sink.filled(), vector_sink.filled());
    }
}

test "jzon behaviour: vector escape matches std.json.Stringify byte for byte" {
    for (SAMPLES) |sample| {
        var ours: [512]u8 = undefined;
        var sink: Sink = .init(&ours);
        try escape_vector.encode(&sink, sample);

        var theirs: [512]u8 = undefined;
        try std.testing.expectEqualStrings(stdEncoded(&theirs, sample), sink.filled());
    }
}

test "jzon behaviour: vector escape output decodes back to the input" {
    for (SAMPLES) |sample| {
        var encoded: [512]u8 = undefined;
        var writer: Sink = .init(&encoded);
        try escape_vector.encodeBody(&writer, sample);

        var decoded: [512]u8 = undefined;
        var reader: Sink = .init(&decoded);
        try escape.decode(&reader, writer.filled());

        try std.testing.expectEqualStrings(sample, reader.filled());
    }
}

test "jzon behaviour: vector escape body leaves out the quotes encode adds" {
    const sample = "a body long enough to take the lane path, with a \" in it";

    var body_buf: [256]u8 = undefined;
    var body: Sink = .init(&body_buf);
    try escape_vector.encodeBody(&body, sample);

    var whole_buf: [256]u8 = undefined;
    var whole: Sink = .init(&whole_buf);
    try escape_vector.encode(&whole, sample);

    try std.testing.expectEqual(body.written() + 2, whole.written());
    try std.testing.expectEqualStrings(body.filled(), whole.filled()[1 .. whole.written() - 1]);
}

test "jzon behaviour: vector escape writes after what the sink already holds" {
    var buf: [256]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.literal("{\"name\":");
    try escape_vector.encode(&sink, "a value long enough to be scanned a lane at a time");
    try sink.byte('}');

    try std.testing.expectEqualStrings(
        "{\"name\":\"a value long enough to be scanned a lane at a time\"}",
        sink.filled(),
    );
}
