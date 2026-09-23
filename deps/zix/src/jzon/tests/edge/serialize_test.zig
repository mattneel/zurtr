//! Edge tests: jzon.serialize at the boundaries.
//! Covers buffers that are exactly big enough, one byte short, and empty, plus
//! what each strategy leaves behind when a value does not fit.

const std = @import("std");
const jzon = @import("jzon");

const Strategy = jzon.SerializeStrategy;

/// Every strategy, so a case can assert all of them at once.
const STRATEGIES = [_]Strategy{ .STD, .GENERATED_FMT, .GENERATED, .GENERATED_VECTOR };

/// Every strategy generated from the type, which write as they go.
const GENERATED = [_]Strategy{ .GENERATED_FMT, .GENERATED, .GENERATED_VECTOR };

const Nested = struct {
    alpha: i32,
    beta: []const u8,
};

const NESTED: Nested = .{ .alpha = -3, .beta = "x" };

const NESTED_RENDERED = "{\"alpha\":-3,\"beta\":\"x\"}";

test "jzon edge: serialize fills a buffer that is exactly big enough" {
    inline for (STRATEGIES) |strategy| {
        var buf: [NESTED_RENDERED.len]u8 = undefined;
        const len = try jzon.serialize(&buf, NESTED, .{ .strategy = strategy });

        try std.testing.expectEqual(buf.len, len);
        try std.testing.expectEqualStrings(NESTED_RENDERED, buf[0..len]);
    }
}

test "jzon edge: serialize reports a buffer one byte short" {
    inline for (STRATEGIES) |strategy| {
        var buf: [NESTED_RENDERED.len - 1]u8 = undefined;

        try std.testing.expectError(
            error.NoSpaceLeft,
            jzon.serialize(&buf, NESTED, .{ .strategy = strategy }),
        );
    }
}

test "jzon edge: serialize reports a buffer with no room at all" {
    inline for (STRATEGIES) |strategy| {
        var buf: [0]u8 = undefined;

        try std.testing.expectError(
            error.NoSpaceLeft,
            jzon.serialize(&buf, true, .{ .strategy = strategy }),
        );
        try std.testing.expectError(
            error.NoSpaceLeft,
            jzon.serialize(&buf, @as([]const u32, &.{}), .{ .strategy = strategy }),
        );
    }
}

test "jzon edge: a generated strategy leaves the prefix that fit behind" {
    // Writes land as they are produced, so a failed render is not a rollback. No
    // length comes back either way, so the prefix is not a value a caller can
    // read, only bytes it is free to overwrite.
    inline for (GENERATED) |strategy| {
        var buf: [10]u8 = @splat('#');

        try std.testing.expectError(
            error.NoSpaceLeft,
            jzon.serialize(&buf, NESTED, .{ .strategy = strategy }),
        );

        // The brace and the whole first key literal fit, the integer after them
        // does not. How much of that integer landed differs by path, so only
        // what every one of them wrote is asserted here. A caller gets no
        // length, so none of it is readable as a value either way.
        try std.testing.expect(std.mem.startsWith(u8, &buf, "{\"alpha\":"));
    }
}

test "jzon edge: serialize renders the extremes of the number widths" {
    inline for (STRATEGIES) |strategy| {
        var buf: [64]u8 = undefined;

        const widest = try jzon.serialize(&buf, @as(u64, std.math.maxInt(u64)), .{ .strategy = strategy });
        try std.testing.expectEqualStrings("18446744073709551615", buf[0..widest]);

        const lowest = try jzon.serialize(&buf, @as(i64, std.math.minInt(i64)), .{ .strategy = strategy });
        try std.testing.expectEqualStrings("-9223372036854775808", buf[0..lowest]);

        const narrow = try jzon.serialize(&buf, @as(u1, 1), .{ .strategy = strategy });
        try std.testing.expectEqualStrings("1", buf[0..narrow]);
    }
}

test "jzon edge: serialize renders a field name that needs escaping" {
    const Awkward = struct {
        @"a\"b": u8,
        @"tab\there": u8,
    };

    inline for (STRATEGIES) |strategy| {
        var buf: [64]u8 = undefined;
        const len = try jzon.serialize(&buf, Awkward{ .@"a\"b" = 1, .@"tab\there" = 2 }, .{
            .strategy = strategy,
        });

        try std.testing.expectEqualStrings("{\"a\\\"b\":1,\"tab\\there\":2}", buf[0..len]);
    }
}

test "jzon edge: serialize renders a deeply nested value" {
    const Leaf = struct { value: u8 };
    const Middle = struct { leaf: Leaf };
    const Outer = struct { middle: Middle };

    inline for (STRATEGIES) |strategy| {
        var buf: [64]u8 = undefined;
        const len = try jzon.serialize(&buf, Outer{ .middle = .{ .leaf = .{ .value = 7 } } }, .{
            .strategy = strategy,
        });

        try std.testing.expectEqualStrings("{\"middle\":{\"leaf\":{\"value\":7}}}", buf[0..len]);
    }
}
