//! Edge tests: jzon.std_emitter at the boundaries.
//! Covers buffers that fit exactly or one byte short, what a failed render leaves
//! behind, and the shapes with nothing in them.

const std = @import("std");
const jzon = @import("jzon");

const Sink = jzon.Sink;
const std_emitter = jzon.std_emitter;

const Pair = struct {
    left: u8,
    right: u8,
};

const PAIR: Pair = .{ .left = 1, .right = 2 };

/// What PAIR renders to, so a case can size a buffer against it.
const PAIR_TEXT = "{\"left\":1,\"right\":2}";

test "jzon edge: std emitter fills an exact-fit buffer" {
    var buf: [PAIR_TEXT.len]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std_emitter.emit(&sink, PAIR);

    try std.testing.expectEqualStrings(PAIR_TEXT, sink.filled());
    try std.testing.expectEqual(@as(usize, 0), sink.remaining());
}

test "jzon edge: std emitter refuses a buffer one byte short and writes nothing" {
    var buf: [PAIR_TEXT.len - 1]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std.testing.expectError(error.NoSpaceLeft, std_emitter.emit(&sink, PAIR));
    try std.testing.expectEqual(@as(usize, 0), sink.written());
}

test "jzon edge: std emitter leaves an earlier write in place when its own render fails" {
    var buf: [8]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.literal("[");
    try std.testing.expectError(error.NoSpaceLeft, std_emitter.emit(&sink, PAIR));

    try std.testing.expectEqualStrings("[", sink.filled());
    try std.testing.expectEqual(@as(usize, 1), sink.written());
}

test "jzon edge: std emitter refuses an empty buffer" {
    var buf: [0]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std.testing.expectError(error.NoSpaceLeft, std_emitter.emit(&sink, PAIR));
}

test "jzon edge: std emitter renders the shapes with nothing in them" {
    const Empty = struct {};

    var buf: [64]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std_emitter.emit(&sink, Empty{});
    try std_emitter.emit(&sink, @as([]const u8, ""));
    try std_emitter.emit(&sink, @as([]const u32, &.{}));
    try std_emitter.emit(&sink, @as(?u8, null));

    try std.testing.expectEqualStrings("{}\"\"[]null", sink.filled());
}

test "jzon edge: std emitter renders the extremes of the integer widths" {
    const Extremes = struct {
        unsigned_high: u64,
        signed_high: i64,
        signed_low: i64,
        narrow: u8,
    };

    var buf: [256]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std_emitter.emit(&sink, Extremes{
        .unsigned_high = std.math.maxInt(u64),
        .signed_high = std.math.maxInt(i64),
        .signed_low = std.math.minInt(i64),
        .narrow = 255,
    });

    try std.testing.expectEqualStrings(
        "{\"unsigned_high\":18446744073709551615," ++
            "\"signed_high\":9223372036854775807," ++
            "\"signed_low\":-9223372036854775808," ++
            "\"narrow\":255}",
        sink.filled(),
    );
}

test "jzon edge: std emitter renders a value nested several levels deep" {
    const Leaf = struct { value: u8 };
    const Middle = struct { leaf: Leaf };
    const Root = struct { middle: Middle };

    var buf: [128]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std_emitter.emit(&sink, Root{ .middle = .{ .leaf = .{ .value = 9 } } });

    try std.testing.expectEqualStrings("{\"middle\":{\"leaf\":{\"value\":9}}}", sink.filled());
}
