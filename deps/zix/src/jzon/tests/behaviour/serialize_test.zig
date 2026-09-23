//! Behaviour tests: jzon.serialize, the call a caller makes to render.
//! Verifies every strategy writes the same bytes for the same value, that the
//! returned length is the whole of what landed, and that the default strategy
//! still takes a shape the generated ones refuse at compile time.

const std = @import("std");
const jzon = @import("jzon");

const Strategy = jzon.SerializeStrategy;

/// Every strategy, so a case can assert all of them at once.
const STRATEGIES = [_]Strategy{ .STD, .GENERATED_FMT, .GENERATED, .GENERATED_VECTOR };

const Status = enum { PENDING, SHIPPED, CANCELLED };

const Totals = struct {
    net_cents: i64,
    tax_cents: i64,
};

const Line = struct {
    sku: []const u8,
    qty: u32,
    price_cents: i64,
};

const Order = struct {
    id: u64,
    customer: []const u8,
    status: Status,
    note: ?[]const u8,
    tags: []const []const u8,
    lines: []const Line,
    totals: Totals,
};

const ORDER: Order = .{
    .id = 4815162342,
    .customer = "Rekha Nair",
    .status = .SHIPPED,
    .note = "leave at the door",
    .tags = &.{ "priority", "gift" },
    .lines = &.{
        .{ .sku = "AB-1", .qty = 2, .price_cents = 1299 },
        .{ .sku = "CD-2", .qty = 1, .price_cents = 4500 },
    },
    .totals = .{ .net_cents = 7098, .tax_cents = 710 },
};

const RENDERED =
    "{\"id\":4815162342,\"customer\":\"Rekha Nair\",\"status\":\"SHIPPED\"," ++
    "\"note\":\"leave at the door\",\"tags\":[\"priority\",\"gift\"]," ++
    "\"lines\":[{\"sku\":\"AB-1\",\"qty\":2,\"price_cents\":1299}," ++
    "{\"sku\":\"CD-2\",\"qty\":1,\"price_cents\":4500}]," ++
    "\"totals\":{\"net_cents\":7098,\"tax_cents\":710}}";

/// Render one value under every strategy and assert all four agree.
fn expectEveryStrategyRenders(expected: []const u8, value: anytype) !void {
    inline for (STRATEGIES) |strategy| {
        var buf: [2048]u8 = undefined;
        const len = try jzon.serialize(&buf, value, .{ .strategy = strategy });

        try std.testing.expectEqualStrings(expected, buf[0..len]);
    }
}

test "jzon behaviour: every serialize strategy renders the same order" {
    try expectEveryStrategyRenders(RENDERED, ORDER);
}

test "jzon behaviour: every serialize strategy renders each shape on its own" {
    try expectEveryStrategyRenders("true", true);
    try expectEveryStrategyRenders("false", false);
    try expectEveryStrategyRenders("255", @as(u8, 255));
    try expectEveryStrategyRenders("-9223372036854775808", @as(i64, std.math.minInt(i64)));
    try expectEveryStrategyRenders("18446744073709551615", @as(u64, std.math.maxInt(u64)));
    try expectEveryStrategyRenders("2.5", @as(f64, 2.5));
    try expectEveryStrategyRenders("\"text\"", @as([]const u8, "text"));
    try expectEveryStrategyRenders("[1,2,3]", @as([]const u32, &.{ 1, 2, 3 }));
    try expectEveryStrategyRenders("null", @as(?u8, null));
    try expectEveryStrategyRenders("9", @as(?u8, 9));
    try expectEveryStrategyRenders("\"CANCELLED\"", Status.CANCELLED);
}

test "jzon behaviour: every serialize strategy escapes a string the same way" {
    const text: []const u8 = "quote \" backslash \\ newline \n tab \t and a run long enough to fill a lane";

    try expectEveryStrategyRenders(
        "\"quote \\\" backslash \\\\ newline \\n tab \\t and a run long enough to fill a lane\"",
        text,
    );
}

test "jzon behaviour: serialize returns the length of what landed and leaves the tail alone" {
    inline for (STRATEGIES) |strategy| {
        var buf: [64]u8 = @splat('#');
        const len = try jzon.serialize(&buf, @as([]const u32, &.{ 10, 20 }), .{ .strategy = strategy });

        try std.testing.expectEqual(@as(usize, 7), len);
        try std.testing.expectEqualStrings("[10,20]", buf[0..len]);

        // Nothing past the reported length was touched, so a caller can keep
        // building after the value.
        for (buf[len..]) |byte| try std.testing.expectEqual(@as(u8, '#'), byte);
    }
}

test "jzon behaviour: serialize renders an empty string, object and array" {
    const Empty = struct {};

    try expectEveryStrategyRenders("\"\"", @as([]const u8, ""));
    try expectEveryStrategyRenders("[]", @as([]const u32, &.{}));
    try expectEveryStrategyRenders("{}", Empty{});
}

test "jzon behaviour: serialize renders a shape only the default strategy has a form for" {
    var buf: [64]u8 = undefined;

    // A tuple has no object form and a non-exhaustive enum may carry a value no
    // tag names, so the generated strategies refuse both at compile time. The
    // default one is the reason a caller is never stuck.
    const tuple_len = try jzon.serialize(&buf, .{ @as(u8, 1), true, "x" }, .{});
    try std.testing.expectEqualStrings("[1,true,\"x\"]", buf[0..tuple_len]);

    const Loose = enum(u8) { FIRST = 1, _ };
    const loose_len = try jzon.serialize(&buf, @as(Loose, @enumFromInt(9)), .{});
    try std.testing.expectEqualStrings("9", buf[0..loose_len]);
}
