//! Behaviour tests: jzon.generated_emitter, the emitter built from the type.
//! Verifies every number and escape pairing writes the same bytes, that those
//! bytes are what the std-backed path writes, and that they parse back into the
//! same value.

const std = @import("std");
const jzon = @import("jzon");

const Sink = jzon.Sink;
const generated_emitter = jzon.generated_emitter;
const std_emitter = jzon.std_emitter;

const Shape = generated_emitter.Shape;

/// Every pairing of the two axes. The three named strategies sit among these:
/// integers through std.fmt, integers written directly, and the direct integers
/// with the lane-at-a-time escape scan.
const SHAPES = [_]Shape{
    .{ .numbers = .FMT, .escapes = .SCALAR },
    .{ .numbers = .FMT, .escapes = .VECTOR },
    .{ .numbers = .TABLE, .escapes = .SCALAR },
    .{ .numbers = .TABLE, .escapes = .VECTOR },
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

test "jzon behaviour: generated emitter renders a whole order" {
    var buf: [1024]u8 = undefined;
    var sink: Sink = .init(&buf);

    try generated_emitter.emit(&sink, ORDER, .{});

    try std.testing.expectEqualStrings(
        "{\"id\":4815162342,\"customer\":\"Rekha Nair\",\"status\":\"SHIPPED\"," ++
            "\"note\":\"leave at the door\",\"tags\":[\"priority\",\"gift\"]," ++
            "\"lines\":[{\"sku\":\"AB-1\",\"qty\":2,\"price_cents\":1299}," ++
            "{\"sku\":\"CD-2\",\"qty\":1,\"price_cents\":4500}]," ++
            "\"totals\":{\"net_cents\":7098,\"tax_cents\":710}}",
        sink.filled(),
    );
}

test "jzon behaviour: every pairing renders an order identically" {
    try expectEveryShapeAgreesWithStd(ORDER);
}

test "jzon behaviour: every pairing renders an unset optional as null" {
    var order = ORDER;
    order.note = null;

    try expectEveryShapeAgreesWithStd(order);
}

test "jzon behaviour: every pairing renders the empty slices as empty arrays" {
    var order = ORDER;
    order.tags = &.{};
    order.lines = &.{};

    try expectEveryShapeAgreesWithStd(order);

    var buf: [1024]u8 = undefined;
    var sink: Sink = .init(&buf);
    try generated_emitter.emit(&sink, order, .{});

    try std.testing.expect(std.mem.indexOf(u8, sink.filled(), "\"tags\":[]") != null);
    try std.testing.expect(std.mem.indexOf(u8, sink.filled(), "\"lines\":[]") != null);
}

test "jzon behaviour: every pairing escapes what a value carries" {
    var order = ORDER;
    order.customer = "quote \" and backslash \\ and a newline \n";
    order.note = "a note long enough for the lane scan to take its vector path";

    try expectEveryShapeAgreesWithStd(order);
}

test "jzon behaviour: every pairing renders each enum tag as its name" {
    inline for (.{ Status.PENDING, Status.SHIPPED, Status.CANCELLED }) |status| {
        var order = ORDER;
        order.status = status;

        try expectEveryShapeAgreesWithStd(order);
    }
}

test "jzon behaviour: generated emitter output parses back into the same order" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    inline for (SHAPES) |shape| {
        var buf: [1024]u8 = undefined;
        var sink: Sink = .init(&buf);
        try generated_emitter.emit(&sink, ORDER, shape);

        const parsed = try std.json.parseFromSliceLeaky(
            Order,
            arena.allocator(),
            sink.filled(),
            .{},
        );

        try std.testing.expectEqual(ORDER.id, parsed.id);
        try std.testing.expectEqualStrings(ORDER.customer, parsed.customer);
        try std.testing.expectEqual(ORDER.status, parsed.status);
        try std.testing.expectEqualStrings(ORDER.note.?, parsed.note.?);
        try std.testing.expectEqual(ORDER.tags.len, parsed.tags.len);
        try std.testing.expectEqualStrings(ORDER.lines[0].sku, parsed.lines[0].sku);
        try std.testing.expectEqual(ORDER.totals.net_cents, parsed.totals.net_cents);
    }
}

test "jzon behaviour: generated emitter writes after what the sink already holds" {
    var buf: [2048]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.literal("{\"order\":");
    try generated_emitter.emit(&sink, ORDER, .{});
    try sink.literal(",\"ok\":true}");

    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const Envelope = struct {
        order: Order,
        ok: bool,
    };

    const parsed = try std.json.parseFromSliceLeaky(
        Envelope,
        arena.allocator(),
        sink.filled(),
        .{},
    );

    try std.testing.expect(parsed.ok);
    try std.testing.expectEqual(ORDER.id, parsed.order.id);
}
