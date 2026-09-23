//! Edge tests: jzon.generated_emitter at the boundaries.
//! Covers a buffer that runs out at every point in a render, a field name that
//! needs escaping, the extremes of each width, deep nesting, and the shapes with
//! nothing in them.

const std = @import("std");
const jzon = @import("jzon");

const Sink = jzon.Sink;
const generated_emitter = jzon.generated_emitter;
const std_emitter = jzon.std_emitter;

const Shape = generated_emitter.Shape;

const SHAPES = [_]Shape{
    .{ .numbers = .FMT, .escapes = .SCALAR },
    .{ .numbers = .FMT, .escapes = .VECTOR },
    .{ .numbers = .TABLE, .escapes = .SCALAR },
    .{ .numbers = .TABLE, .escapes = .VECTOR },
};

const Pair = struct {
    left: u8,
    right: u8,
};

const PAIR: Pair = .{ .left = 1, .right = 2 };

/// What PAIR renders to, so a case can size a buffer against it.
const PAIR_TEXT = "{\"left\":1,\"right\":2}";

/// Render one value under every pairing and assert all of them agree with what
/// the std-backed path writes.
fn expectEveryShapeAgreesWithStd(value: anytype) !void {
    var expected_buf: [4096]u8 = undefined;
    var expected: Sink = .init(&expected_buf);
    try std_emitter.emit(&expected, value);

    inline for (SHAPES) |shape| {
        var ours: [4096]u8 = undefined;
        var sink: Sink = .init(&ours);
        try generated_emitter.emit(&sink, value, shape);

        try std.testing.expectEqualStrings(expected.filled(), sink.filled());
    }
}

test "jzon edge: generated emitter fills an exact-fit buffer under every pairing" {
    inline for (SHAPES) |shape| {
        var buf: [PAIR_TEXT.len]u8 = undefined;
        var sink: Sink = .init(&buf);

        try generated_emitter.emit(&sink, PAIR, shape);

        try std.testing.expectEqualStrings(PAIR_TEXT, sink.filled());
        try std.testing.expectEqual(@as(usize, 0), sink.remaining());
    }
}

test "jzon edge: generated emitter refuses every buffer shorter than the render" {
    inline for (SHAPES) |shape| {
        for (0..PAIR_TEXT.len) |len| {
            var buf: [PAIR_TEXT.len]u8 = undefined;
            var sink: Sink = .init(buf[0..len]);

            try std.testing.expectError(
                error.NoSpaceLeft,
                generated_emitter.emit(&sink, PAIR, shape),
            );

            // Whatever landed is a prefix of the whole render, never bytes the
            // full buffer would not have produced.
            try std.testing.expect(std.mem.startsWith(u8, PAIR_TEXT, sink.filled()));
        }
    }
}

test "jzon edge: generated emitter escapes a field name that needs it" {
    const Odd = struct {
        @"a\"b": u8,
        @"tab\there": u8,
    };

    try expectEveryShapeAgreesWithStd(Odd{ .@"a\"b" = 1, .@"tab\there" = 2 });

    var buf: [128]u8 = undefined;
    var sink: Sink = .init(&buf);
    try generated_emitter.emit(&sink, Odd{ .@"a\"b" = 1, .@"tab\there" = 2 }, .{});

    try std.testing.expectEqualStrings("{\"a\\\"b\":1,\"tab\\there\":2}", sink.filled());
}

test "jzon edge: generated emitter renders the extremes of the integer widths" {
    const Extremes = struct {
        unsigned_high: u64,
        signed_high: i64,
        signed_low: i64,
        narrow: u8,
        one_bit: u1,
    };

    try expectEveryShapeAgreesWithStd(Extremes{
        .unsigned_high = std.math.maxInt(u64),
        .signed_high = std.math.maxInt(i64),
        .signed_low = std.math.minInt(i64),
        .narrow = 255,
        .one_bit = 1,
    });
}

test "jzon edge: generated emitter renders the float widths the way std does" {
    const Widths = struct {
        half: f16,
        single: f32,
        double: f64,
    };

    try expectEveryShapeAgreesWithStd(Widths{ .half = 1.5, .single = 0.1, .double = 0.1 });
}

test "jzon edge: generated emitter renders the shapes with nothing in them" {
    const Empty = struct {};

    inline for (SHAPES) |shape| {
        var buf: [64]u8 = undefined;
        var sink: Sink = .init(&buf);

        try generated_emitter.emit(&sink, Empty{}, shape);
        try generated_emitter.emit(&sink, @as([]const u8, ""), shape);
        try generated_emitter.emit(&sink, @as([]const u32, &.{}), shape);
        try generated_emitter.emit(&sink, @as(?u8, null), shape);

        try std.testing.expectEqualStrings("{}\"\"[]null", sink.filled());
    }
}

test "jzon edge: generated emitter renders a nested optional both ways" {
    const Held = struct { value: u8 };
    const Wrapper = struct { held: ?Held };

    try expectEveryShapeAgreesWithStd(Wrapper{ .held = null });
    try expectEveryShapeAgreesWithStd(Wrapper{ .held = .{ .value = 7 } });
}

test "jzon edge: generated emitter renders a value nested several levels deep" {
    const Leaf = struct { value: u8 };
    const Middle = struct { leaf: Leaf, siblings: []const Leaf };
    const Root = struct { middle: Middle };

    try expectEveryShapeAgreesWithStd(Root{
        .middle = .{
            .leaf = .{ .value = 9 },
            .siblings = &.{ .{ .value = 1 }, .{ .value = 2 } },
        },
    });
}

test "jzon edge: generated emitter renders a slice of slices" {
    const Grid = struct { rows: []const []const u8 };

    try expectEveryShapeAgreesWithStd(Grid{ .rows = &.{ "one", "", "three" } });
}

test "jzon edge: generated emitter renders a string long enough to fill several lanes" {
    const Long = struct { text: []const u8 };

    try expectEveryShapeAgreesWithStd(Long{
        .text = "a string of well over sixteen bytes, carrying a \" and a \\ and a \n " ++
            "so both scans have to break their clean run more than once",
    });
}

test "jzon edge: generated emitter refuses an empty buffer" {
    inline for (SHAPES) |shape| {
        var buf: [0]u8 = undefined;
        var sink: Sink = .init(&buf);

        try std.testing.expectError(
            error.NoSpaceLeft,
            generated_emitter.emit(&sink, PAIR, shape),
        );
    }
}
