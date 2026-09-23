//! Edge tests: jzon.float at the boundaries.
//! Covers the extremes of the width, denormals, the two values with no JSON form,
//! a value f64 cannot hold, buffers that fit the digits exactly or one short, and
//! the text a read refuses even though std.fmt would take it.

const std = @import("std");
const jzon = @import("jzon");

const Sink = jzon.Sink;
const float = jzon.float;

/// The same value through std.json.Stringify, which jzon's output must match.
fn stdRendered(buf: []u8, value: anytype) []const u8 {
    var writer = std.Io.Writer.fixed(buf);
    std.json.Stringify.value(value, .{}, &writer) catch unreachable;

    return writer.buffered();
}

test "jzon edge: float writes the extremes of f64 the way std does" {
    const samples = [_]f64{
        std.math.floatMax(f64),
        -std.math.floatMax(f64),
        std.math.floatMin(f64),
        std.math.floatTrueMin(f64),
        std.math.floatEps(f64),
        1e308,
        1e-308,
    };

    for (samples) |sample| {
        var ours: [512]u8 = undefined;
        var sink: Sink = .init(&ours);
        try float.append(&sink, sample);

        var theirs: [512]u8 = undefined;
        try std.testing.expectEqualStrings(stdRendered(&theirs, sample), sink.filled());
    }
}

test "jzon edge: float writes both zeroes as std writes them" {
    var positive_buf: [64]u8 = undefined;
    var positive: Sink = .init(&positive_buf);
    try float.append(&positive, @as(f64, 0.0));

    var negative_buf: [64]u8 = undefined;
    var negative: Sink = .init(&negative_buf);
    try float.append(&negative, @as(f64, -0.0));

    var std_positive: [64]u8 = undefined;
    try std.testing.expectEqualStrings(stdRendered(&std_positive, @as(f64, 0.0)), positive.filled());

    var std_negative: [64]u8 = undefined;
    try std.testing.expectEqualStrings(stdRendered(&std_negative, @as(f64, -0.0)), negative.filled());
}

test "jzon edge: float spells NaN as a string, the way std does" {
    var buf: [64]u8 = undefined;
    var sink: Sink = .init(&buf);
    try float.append(&sink, std.math.nan(f64));

    try std.testing.expectEqualStrings("\"nan\"", sink.filled());

    var theirs: [64]u8 = undefined;
    try std.testing.expectEqualStrings(stdRendered(&theirs, std.math.nan(f64)), sink.filled());
}

test "jzon edge: float spells infinity as std does, which is not valid JSON" {
    var positive_buf: [64]u8 = undefined;
    var positive: Sink = .init(&positive_buf);
    try float.append(&positive, std.math.inf(f64));
    try std.testing.expectEqualStrings("inf", positive.filled());

    var negative_buf: [64]u8 = undefined;
    var negative: Sink = .init(&negative_buf);
    try float.append(&negative, -std.math.inf(f64));
    try std.testing.expectEqualStrings("-inf", negative.filled());

    var std_positive: [64]u8 = undefined;
    try std.testing.expectEqualStrings(
        stdRendered(&std_positive, std.math.inf(f64)),
        positive.filled(),
    );

    // Saying it out loud: no JSON parser takes this, jzon writes it only so the
    // two serialize paths never disagree.
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    if (std.json.parseFromSliceLeaky(f64, arena.allocator(), positive.filled(), .{})) |_| {
        return error.TestExpectedError;
    } else |_| {}
}

test "jzon edge: float quotes a value f64 cannot hold" {
    const wide: f128 = 0.1;

    var buf: [512]u8 = undefined;
    var sink: Sink = .init(&buf);
    try float.append(&sink, wide);

    try std.testing.expectEqualStrings("\"0.1\"", sink.filled());

    var theirs: [512]u8 = undefined;
    try std.testing.expectEqualStrings(stdRendered(&theirs, wide), sink.filled());
}

test "jzon edge: float writes a value f64 can hold as a bare number, even at f128" {
    const exact: f128 = 0.5;

    var buf: [512]u8 = undefined;
    var sink: Sink = .init(&buf);
    try float.append(&sink, exact);

    try std.testing.expectEqualStrings("0.5", sink.filled());
}

test "jzon edge: float fills an exact-fit buffer and refuses one byte short" {
    var fits: [10]u8 = undefined;
    var exact: Sink = .init(&fits);
    try float.append(&exact, @as(f64, 12345.6789));
    try std.testing.expectEqualStrings("12345.6789", exact.filled());
    try std.testing.expectEqual(@as(usize, 0), exact.remaining());

    var cramped: [9]u8 = undefined;
    var short: Sink = .init(&cramped);
    try std.testing.expectError(error.NoSpaceLeft, float.append(&short, @as(f64, 12345.6789)));
    try std.testing.expectEqual(@as(usize, 0), short.written());
}

test "jzon edge: float refuses a quoted value when the closing quote does not fit" {
    // "0.1" is five bytes with its quotes, so four is one short of the whole
    // spelling and the digits that did land stay put.
    var buf: [4]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std.testing.expectError(error.NoSpaceLeft, float.append(&sink, @as(f128, 0.1)));
    try std.testing.expectEqualStrings("\"0.1", sink.filled());
}

test "jzon edge: float refuses an empty buffer" {
    var buf: [0]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std.testing.expectError(error.NoSpaceLeft, float.append(&sink, @as(f64, 1.0)));
}

test "jzon edge: float writes every width it is handed" {
    var buf: [512]u8 = undefined;

    inline for (.{ f16, f32, f64, f80, f128 }) |Width| {
        var sink: Sink = .init(&buf);
        try float.append(&sink, @as(Width, 1.25));

        try std.testing.expectEqualStrings("1.25", sink.filled());
    }
}

test "jzon edge: float refuses the words std.fmt would read as numbers" {
    // std.fmt.parseFloat takes all four of these. None of them is JSON, and a
    // read cursor bounds a token without checking its grammar, so the refusal has
    // to happen on this side.
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "inf"));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "-inf"));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "nan"));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "0x1p3"));
}

test "jzon edge: float refuses a number missing a part the grammar needs" {
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, ""));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "-"));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "."));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, ".5"));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "1."));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "1e"));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "1e-"));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "--1"));
}

test "jzon edge: float refuses a leading zero that is not the whole integer part" {
    try std.testing.expectEqual(@as(f64, 0), try float.parse(f64, "0"));
    try std.testing.expectEqual(@as(f64, 0.5), try float.parse(f64, "0.5"));
    try std.testing.expectEqual(@as(f64, -0.5), try float.parse(f64, "-0.5"));

    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "01"));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "-01"));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "007"));
}

test "jzon edge: float refuses anything trailing the number" {
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "1 "));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "1,"));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "1.5x"));
    try std.testing.expectError(error.JzonBadNumber, float.parse(f64, "+1"));
}

test "jzon edge: float reads a value past a width as an infinity, the way std.json does" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const ours = try float.parse(f32, "1e300");
    const theirs = try std.json.parseFromSliceLeaky(f32, arena.allocator(), "1e300", .{});

    try std.testing.expectEqual(std.math.inf(f32), ours);
    try std.testing.expectEqual(theirs, ours);
}

test "jzon edge: float reads the extremes of f64 back from its own output" {
    const samples = [_]f64{
        std.math.floatMax(f64),
        -std.math.floatMax(f64),
        std.math.floatMin(f64),
        std.math.floatTrueMin(f64),
        std.math.floatEps(f64),
    };

    for (samples) |sample| {
        var buf: [512]u8 = undefined;
        var sink: Sink = .init(&buf);
        try float.append(&sink, sample);

        try std.testing.expectEqual(sample, try float.parse(f64, sink.filled()));
    }
}
