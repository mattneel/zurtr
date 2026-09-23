//! Edge tests: jzon.deserialize at the boundaries.
//! Covers documents that end early, carry more than one value, or hold a value
//! the field cannot take, all read through every strategy, plus the three places
//! the generated strategies deliberately answer differently from the default.

const std = @import("std");
const jzon = @import("jzon");

const Strategy = jzon.DeserializeStrategy;

/// Every strategy, so a case can assert all of them at once.
const STRATEGIES = [_]Strategy{ .STD, .SCANNER, .GENERATED, .GENERATED_VECTOR };

/// Every strategy generated from the type, which is where the three deliberate
/// differences from the default live.
const GENERATED = [_]Strategy{ .SCANNER, .GENERATED, .GENERATED_VECTOR };

const Status = enum { PENDING, SHIPPED };

const Pair = struct {
    id: u8,
    name: []const u8,
};

/// Assert a document is refused the same way by every strategy.
fn expectRefused(comptime T: type, src: []const u8, failure: anyerror) !void {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    inline for (STRATEGIES) |strategy| {
        try std.testing.expectError(
            failure,
            jzon.deserialize(T, arena.allocator(), src, .{ .strategy = strategy }),
        );
    }
}

test "jzon edge: every deserialize strategy reports a document that ends early" {
    try expectRefused(Pair, "{", error.JzonTruncated);
    try expectRefused(Pair, "{\"id\":", error.JzonTruncated);
    try expectRefused(Pair, "{\"id\":1,", error.JzonTruncated);
    try expectRefused([]const u32, "[1,2", error.JzonTruncated);
    try expectRefused([]const u8, "\"unterminated", error.JzonTruncated);
}

test "jzon edge: every deserialize strategy reports a document carrying more than one value" {
    try expectRefused(u8, "1 2", error.JzonUnexpected);
    try expectRefused(Pair, "{\"id\":1,\"name\":\"x\"}{}", error.JzonUnexpected);
    try expectRefused([]const u32, "[1][2]", error.JzonUnexpected);
}

test "jzon edge: every deserialize strategy reports a value the field cannot take" {
    try expectRefused(Pair, "{\"id\":300,\"name\":\"x\"}", error.JzonBadNumber);
    try expectRefused(Pair, "{\"id\":null,\"name\":\"x\"}", error.JzonUnexpected);
    try expectRefused(Pair, "{\"id\":1,\"name\":7}", error.JzonUnexpected);
    try expectRefused([]const u32, "{}", error.JzonUnexpected);
}

test "jzon edge: every deserialize strategy reports an object owing a field" {
    try expectRefused(Pair, "{}", error.JzonMissingField);
    try expectRefused(Pair, "{\"id\":1}", error.JzonMissingField);
}

test "jzon edge: every deserialize strategy reports a key the type does not declare" {
    try expectRefused(Pair, "{\"id\":1,\"name\":\"x\",\"gone\":2}", error.JzonUnknownField);
}

test "jzon edge: every deserialize strategy reports a name no enum tag carries" {
    try expectRefused(Status, "\"GONE\"", error.JzonUnknownEnumValue);
    try expectRefused(Status, "\"pending\"", error.JzonUnknownEnumValue);
}

test "jzon edge: every deserialize strategy reads the empty string, object and array" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const Holder = struct {
        text: []const u8,
        items: []const u32,
    };

    inline for (STRATEGIES) |strategy| {
        const empty = try jzon.deserialize(Holder, allocator, "{\"text\":\"\",\"items\":[]}", .{
            .strategy = strategy,
        });

        try std.testing.expectEqual(@as(usize, 0), empty.text.len);
        try std.testing.expectEqual(@as(usize, 0), empty.items.len);

        // A type that declares no fields is owed nothing, so an empty object is
        // a whole value for it.
        _ = try jzon.deserialize(struct {}, allocator, "{}", .{ .strategy = strategy });
    }
}

test "jzon edge: every deserialize strategy reads the extremes of a width" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    inline for (STRATEGIES) |strategy| {
        const options: jzon.DeserializeOptions = .{ .strategy = strategy };

        try std.testing.expectEqual(
            @as(u64, std.math.maxInt(u64)),
            try jzon.deserialize(u64, allocator, "18446744073709551615", options),
        );
        try std.testing.expectEqual(
            @as(i64, std.math.minInt(i64)),
            try jzon.deserialize(i64, allocator, "-9223372036854775808", options),
        );
    }
}

test "jzon edge: a generated strategy refuses an array of bytes as a string" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    // In jzon a slice of bytes is a string and nothing else. std also fills one
    // from an array of numbers, which is why the same document reads under the
    // default strategy and fails under a generated one.
    inline for (GENERATED) |strategy| {
        try std.testing.expectError(
            error.JzonUnexpected,
            jzon.deserialize([]const u8, allocator, "[104,105]", .{ .strategy = strategy }),
        );
    }

    try std.testing.expectEqualStrings("hi", try jzon.deserialize([]const u8, allocator, "[104,105]", .{}));
}

test "jzon edge: a generated strategy refuses a signed zero in an unsigned field" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const src = "{\"id\":-0,\"name\":\"x\"}";

    // A sign against an unsigned field is a type error whatever the digits after
    // it are. std reads the digits and lands on zero. No serialize strategy ever
    // writes this, so no round trip crosses the difference.
    inline for (GENERATED) |strategy| {
        try std.testing.expectError(
            error.JzonBadNumber,
            jzon.deserialize(Pair, allocator, src, .{ .strategy = strategy }),
        );
    }

    const theirs = try jzon.deserialize(Pair, allocator, src, .{});
    try std.testing.expectEqual(@as(u8, 0), theirs.id);
}

test "jzon edge: only the strategy that decodes an escape itself can name a bad one" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const src = "\"\\q\"";

    // The generated parser decodes escapes itself, so it can say which of the
    // two went wrong. The other paths leave that to std, which calls a broken
    // escape a syntax error.
    inline for ([_]Strategy{ .GENERATED, .GENERATED_VECTOR }) |strategy| {
        try std.testing.expectError(
            error.JzonBadEscape,
            jzon.deserialize([]const u8, allocator, src, .{ .strategy = strategy }),
        );
    }

    inline for ([_]Strategy{ .STD, .SCANNER }) |strategy| {
        try std.testing.expectError(
            error.JzonUnexpected,
            jzon.deserialize([]const u8, allocator, src, .{ .strategy = strategy }),
        );
    }
}

test "jzon edge: an omitted optional without a declared default is still owed" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // Spelling a field `?T` says what it can hold, not that a document may leave
    // it out. `= null` is what makes it optional, on every strategy including
    // the default one.
    const Owed = struct {
        id: u8,
        note: ?[]const u8,
    };

    inline for (STRATEGIES) |strategy| {
        try std.testing.expectError(
            error.JzonMissingField,
            jzon.deserialize(Owed, arena.allocator(), "{\"id\":1}", .{ .strategy = strategy }),
        );
    }
}

test "jzon edge: every deserialize strategy reports an allocator with nothing left" {
    var failing: std.testing.FailingAllocator = .init(std.testing.allocator, .{ .fail_index = 0 });

    inline for (STRATEGIES) |strategy| {
        try std.testing.expectError(
            error.OutOfMemory,
            jzon.deserialize(Pair, failing.allocator(), "{\"id\":1,\"name\":\"x\"}", .{ .strategy = strategy }),
        );
    }
}
