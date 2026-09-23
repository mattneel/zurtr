//! Behaviour tests: every jzon write path against every read path.
//! One order is rendered by the std-backed emitter and by the generated emitter
//! under all four pairings, then every rendering is read back by all three read
//! paths, the generated one at both scan widths, in both string modes. This is
//! the gate that keeps a strategy a cost decision.

const std = @import("std");
const jzon = @import("jzon");

const Sink = jzon.Sink;
const generated_emitter = jzon.generated_emitter;
const generated_parser = jzon.generated_parser;
const scanner_parser = jzon.scanner_parser;
const std_emitter = jzon.std_emitter;
const std_parser = jzon.std_parser;

const ReadShape = generated_parser.Shape;
const Shape = generated_emitter.Shape;

/// Every pairing the generated emitter runs with.
const SHAPES = [_]Shape{
    .{ .numbers = .FMT, .escapes = .SCALAR },
    .{ .numbers = .FMT, .escapes = .VECTOR },
    .{ .numbers = .TABLE, .escapes = .SCALAR },
    .{ .numbers = .TABLE, .escapes = .VECTOR },
};

/// Every width the generated parser runs at.
const READ_SHAPES = [_]ReadShape{
    .{ .scan = .SCALAR },
    .{ .scan = .VECTOR },
};

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

test "jzon behaviour: every write path renders an order every read path reads back" {
    try expectRoundTrips(ORDER);
}

test "jzon behaviour: every pair round trips an order with an unset optional" {
    var order = ORDER;
    order.note = null;

    try expectRoundTrips(order);
}

test "jzon behaviour: every pair round trips an order carrying escapes" {
    var order = ORDER;
    order.customer = "quote \" backslash \\ newline \n tab \t";
    order.note = "a note long enough for the lane scan to take its vector path";

    try expectRoundTrips(order);
}

test "jzon behaviour: every pair round trips an order with empty slices" {
    var order = ORDER;
    order.tags = &.{};
    order.lines = &.{};

    try expectRoundTrips(order);
}

test "jzon behaviour: every pair round trips the extremes of the number widths" {
    var order = ORDER;
    order.id = std.math.maxInt(u64);
    order.totals = .{ .net_cents = std.math.minInt(i64), .tax_cents = std.math.maxInt(i64) };

    try expectRoundTrips(order);
}

test "jzon behaviour: every write path renders the same bytes" {
    var expected_buf: [2048]u8 = undefined;
    var expected: Sink = .init(&expected_buf);
    try std_emitter.emit(&expected, ORDER);

    inline for (SHAPES) |shape| {
        var buf: [2048]u8 = undefined;
        var sink: Sink = .init(&buf);
        try generated_emitter.emit(&sink, ORDER, shape);

        try std.testing.expectEqualStrings(expected.filled(), sink.filled());
    }
}

/// Render `order` through every write path and read each rendering back through
/// every read path in every string mode.
fn expectRoundTrips(order: Order) !void {
    var std_buf: [2048]u8 = undefined;
    var std_sink: Sink = .init(&std_buf);
    try std_emitter.emit(&std_sink, order);

    try expectEveryReadPath(order, std_sink.filled());

    inline for (SHAPES) |shape| {
        var buf: [2048]u8 = undefined;
        var sink: Sink = .init(&buf);
        try generated_emitter.emit(&sink, order, shape);

        try expectEveryReadPath(order, sink.filled());
    }
}

/// Read one rendering back through every path in both string modes.
fn expectEveryReadPath(expected: Order, rendered: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try expectSameOrder(expected, try std_parser.parse(Order, allocator, rendered, .{ .strings = .COPY }));
    try expectSameOrder(expected, try std_parser.parse(Order, allocator, rendered, .{ .strings = .BORROW }));
    try expectSameOrder(expected, try scanner_parser.parse(Order, allocator, rendered, .{ .strings = .COPY }));
    try expectSameOrder(expected, try scanner_parser.parse(Order, allocator, rendered, .{ .strings = .BORROW }));

    inline for (READ_SHAPES) |shape| {
        try expectSameOrder(expected, try generated_parser.parse(Order, allocator, rendered, .{ .strings = .COPY }, shape));
        try expectSameOrder(expected, try generated_parser.parse(Order, allocator, rendered, .{ .strings = .BORROW }, shape));
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
