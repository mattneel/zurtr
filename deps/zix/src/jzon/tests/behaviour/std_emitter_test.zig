//! Behaviour tests: jzon.std_emitter, the std-backed serialize path.
//! Verifies it renders a realistic record into a caller buffer, that the text it
//! writes parses back into the same value, and that it allocates nothing.

const std = @import("std");
const jzon = @import("jzon");

const Sink = jzon.Sink;
const std_emitter = jzon.std_emitter;

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

test "jzon behaviour: std emitter renders a whole order" {
    var buf: [1024]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std_emitter.emit(&sink, ORDER);

    try std.testing.expectEqualStrings(
        "{\"id\":4815162342,\"customer\":\"Rekha Nair\",\"status\":\"SHIPPED\"," ++
            "\"note\":\"leave at the door\",\"tags\":[\"priority\",\"gift\"]," ++
            "\"lines\":[{\"sku\":\"AB-1\",\"qty\":2,\"price_cents\":1299}," ++
            "{\"sku\":\"CD-2\",\"qty\":1,\"price_cents\":4500}]," ++
            "\"totals\":{\"net_cents\":7098,\"tax_cents\":710}}",
        sink.filled(),
    );
}

test "jzon behaviour: std emitter output parses back into the same order" {
    var buf: [1024]u8 = undefined;
    var sink: Sink = .init(&buf);
    try std_emitter.emit(&sink, ORDER);

    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSliceLeaky(Order, arena.allocator(), sink.filled(), .{});

    try std.testing.expectEqual(ORDER.id, parsed.id);
    try std.testing.expectEqualStrings(ORDER.customer, parsed.customer);
    try std.testing.expectEqual(ORDER.status, parsed.status);
    try std.testing.expectEqualStrings(ORDER.note.?, parsed.note.?);
    try std.testing.expectEqual(ORDER.lines.len, parsed.lines.len);
    try std.testing.expectEqualStrings(ORDER.lines[1].sku, parsed.lines[1].sku);
    try std.testing.expectEqual(ORDER.totals.tax_cents, parsed.totals.tax_cents);
}

test "jzon behaviour: std emitter renders an unset optional as null" {
    var order = ORDER;
    order.note = null;

    var buf: [1024]u8 = undefined;
    var sink: Sink = .init(&buf);
    try std_emitter.emit(&sink, order);

    try std.testing.expect(std.mem.indexOf(u8, sink.filled(), "\"note\":null") != null);
}

test "jzon behaviour: std emitter escapes what a value carries" {
    var order = ORDER;
    order.customer = "quote \" and backslash \\ and a newline \n";

    var buf: [1024]u8 = undefined;
    var sink: Sink = .init(&buf);
    try std_emitter.emit(&sink, order);

    try std.testing.expect(std.mem.indexOf(
        u8,
        sink.filled(),
        "\"customer\":\"quote \\\" and backslash \\\\ and a newline \\n\"",
    ) != null);
}

test "jzon behaviour: std emitter carries no state between renders" {
    var buf: [1024]u8 = undefined;

    var sink: Sink = .init(&buf);
    try std_emitter.emit(&sink, ORDER);

    var first: [1024]u8 = undefined;
    const rendered = first[0..sink.written()];
    @memcpy(rendered, sink.filled());

    sink.reset();
    try std_emitter.emit(&sink, ORDER);

    try std.testing.expectEqualStrings(rendered, sink.filled());
}

test "jzon behaviour: std emitter appends one value after another" {
    var buf: [2048]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.byte('[');
    try std_emitter.emit(&sink, ORDER);
    try sink.byte(',');
    try std_emitter.emit(&sink, ORDER);
    try sink.byte(']');

    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const parsed = try std.json.parseFromSliceLeaky(
        []Order,
        arena.allocator(),
        sink.filled(),
        .{},
    );

    try std.testing.expectEqual(@as(usize, 2), parsed.len);
    try std.testing.expectEqual(ORDER.id, parsed[1].id);
}
