//! Behaviour tests: every jzon strategy pair, through the public surface.
//! One order is rendered by all four serialize strategies and each rendering is
//! read back by all four deserialize strategies, in both string modes. This is
//! the gate that keeps a strategy a cost decision: a caller may pick any pair
//! and get the same value back.

const std = @import("std");
const jzon = @import("jzon");

const DeserializeStrategy = jzon.DeserializeStrategy;
const SerializeStrategy = jzon.SerializeStrategy;
const Strings = jzon.Strings;

/// Every write strategy.
const WRITE = [_]SerializeStrategy{ .STD, .GENERATED_FMT, .GENERATED, .GENERATED_VECTOR };

/// Every read strategy.
const READ = [_]DeserializeStrategy{ .STD, .SCANNER, .GENERATED, .GENERATED_VECTOR };

/// Both places a parsed string's bytes can live.
const MODES = [_]Strings{ .COPY, .BORROW };

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
    note: ?[]const u8 = null,
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

test "jzon behaviour: every strategy pair round trips an order" {
    try expectEveryPair(ORDER);
}

test "jzon behaviour: every strategy pair round trips an order with an unset optional" {
    var order = ORDER;
    order.note = null;

    try expectEveryPair(order);
}

test "jzon behaviour: every strategy pair round trips an order carrying escapes" {
    var order = ORDER;
    order.customer = "quote \" backslash \\ newline \n tab \t";
    order.note = "a note long enough for the lane scan to take its vector path";

    try expectEveryPair(order);
}

test "jzon behaviour: every strategy pair round trips an order with empty slices" {
    var order = ORDER;
    order.tags = &.{};
    order.lines = &.{};

    try expectEveryPair(order);
}

test "jzon behaviour: every strategy pair round trips the extremes of the number widths" {
    var order = ORDER;
    order.id = std.math.maxInt(u64);
    order.totals = .{ .net_cents = std.math.minInt(i64), .tax_cents = std.math.maxInt(i64) };

    try expectEveryPair(order);
}

test "jzon behaviour: every serialize strategy renders the same bytes" {
    var expected_buf: [2048]u8 = undefined;
    const expected_len = try jzon.serialize(&expected_buf, ORDER, .{});

    inline for (WRITE) |strategy| {
        var buf: [2048]u8 = undefined;
        const len = try jzon.serialize(&buf, ORDER, .{ .strategy = strategy });

        try std.testing.expectEqualStrings(expected_buf[0..expected_len], buf[0..len]);
    }
}

/// Render `order` through every write strategy and read each rendering back
/// through every read strategy in both string modes.
fn expectEveryPair(order: Order) !void {
    inline for (WRITE) |strategy| {
        var buf: [2048]u8 = undefined;
        const len = try jzon.serialize(&buf, order, .{ .strategy = strategy });

        try expectEveryReadStrategy(order, buf[0..len]);
    }
}

/// Read one rendering back through every read strategy in both string modes.
fn expectEveryReadStrategy(expected: Order, rendered: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    inline for (READ) |strategy| {
        inline for (MODES) |mode| {
            const actual = try jzon.deserialize(Order, arena.allocator(), rendered, .{
                .strategy = strategy,
                .strings = mode,
            });

            try expectSameOrder(expected, actual);
        }
    }
}

/// Assert two orders carry the same value in every field.
fn expectSameOrder(expected: Order, actual: Order) !void {
    try std.testing.expectEqual(expected.id, actual.id);
    try std.testing.expectEqualStrings(expected.customer, actual.customer);
    try std.testing.expectEqual(expected.status, actual.status);

    if (expected.note) |note| {
        try std.testing.expectEqualStrings(note, actual.note.?);
    } else {
        try std.testing.expect(actual.note == null);
    }

    try std.testing.expectEqual(expected.tags.len, actual.tags.len);
    for (expected.tags, actual.tags) |want, got| {
        try std.testing.expectEqualStrings(want, got);
    }

    try std.testing.expectEqual(expected.lines.len, actual.lines.len);
    for (expected.lines, actual.lines) |want, got| {
        try std.testing.expectEqualStrings(want.sku, got.sku);
        try std.testing.expectEqual(want.qty, got.qty);
        try std.testing.expectEqual(want.price_cents, got.price_cents);
    }

    try std.testing.expectEqual(expected.totals.net_cents, actual.totals.net_cents);
    try std.testing.expectEqual(expected.totals.tax_cents, actual.totals.tax_cents);
}
