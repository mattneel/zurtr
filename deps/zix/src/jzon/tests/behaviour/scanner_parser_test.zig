//! Behaviour tests: jzon.scanner_parser, std's tokens with generated dispatch.
//! Verifies a whole order comes back field for field, that it agrees with the
//! std-backed path on the same document, and that both string modes and both
//! unknown-key modes do what they say.

const std = @import("std");
const jzon = @import("jzon");

const scanner_parser = jzon.scanner_parser;
const std_parser = jzon.std_parser;

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

const ORDER_JSON =
    "{\"id\":4815162342,\"customer\":\"Rekha Nair\",\"status\":\"SHIPPED\"," ++
    "\"note\":\"leave at the door\",\"tags\":[\"priority\",\"gift\"]," ++
    "\"lines\":[{\"sku\":\"AB-1\",\"qty\":2,\"price_cents\":1299}," ++
    "{\"sku\":\"CD-2\",\"qty\":1,\"price_cents\":4500}]," ++
    "\"totals\":{\"net_cents\":7098,\"tax_cents\":710}}";

test "jzon behaviour: scanner parser reads a whole order" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const order = try scanner_parser.parse(Order, arena.allocator(), ORDER_JSON, .{});

    try std.testing.expectEqual(@as(u64, 4815162342), order.id);
    try std.testing.expectEqualStrings("Rekha Nair", order.customer);
    try std.testing.expectEqual(Status.SHIPPED, order.status);
    try std.testing.expectEqualStrings("leave at the door", order.note.?);
    try std.testing.expectEqual(@as(usize, 2), order.tags.len);
    try std.testing.expectEqualStrings("gift", order.tags[1]);
    try std.testing.expectEqual(@as(usize, 2), order.lines.len);
    try std.testing.expectEqualStrings("CD-2", order.lines[1].sku);
    try std.testing.expectEqual(@as(i64, 4500), order.lines[1].price_cents);
    try std.testing.expectEqual(@as(i64, 710), order.totals.tax_cents);
}

test "jzon behaviour: scanner parser and the std path read the same order" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const ours = try scanner_parser.parse(Order, allocator, ORDER_JSON, .{});
    const theirs = try std_parser.parse(Order, allocator, ORDER_JSON, .{});

    try expectSameOrder(theirs, ours);
}

test "jzon behaviour: scanner parser reads a whitespace-heavy document the same way" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const spaced =
        "{\n  \"id\" : 4815162342 ,\n  \"customer\" : \"Rekha Nair\" ,\n" ++
        "  \"status\" : \"SHIPPED\" ,\n  \"note\" : \"leave at the door\" ,\n" ++
        "  \"tags\" : [ \"priority\" , \"gift\" ] ,\n" ++
        "  \"lines\" : [\n    { \"sku\" : \"AB-1\" , \"qty\" : 2 , \"price_cents\" : 1299 } ,\n" ++
        "    { \"sku\" : \"CD-2\" , \"qty\" : 1 , \"price_cents\" : 4500 }\n  ] ,\n" ++
        "  \"totals\" : { \"net_cents\" : 7098 , \"tax_cents\" : 710 }\n}\n";

    const spaced_order = try scanner_parser.parse(Order, allocator, spaced, .{});
    const tight_order = try scanner_parser.parse(Order, allocator, ORDER_JSON, .{});

    try expectSameOrder(tight_order, spaced_order);
}

test "jzon behaviour: scanner parser reads an unset optional as null" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const src = "{\"id\":1,\"customer\":\"x\",\"status\":\"PENDING\",\"note\":null," ++
        "\"tags\":[],\"lines\":[],\"totals\":{\"net_cents\":0,\"tax_cents\":0}}";

    const order = try scanner_parser.parse(Order, arena.allocator(), src, .{});

    try std.testing.expect(order.note == null);
    try std.testing.expectEqual(@as(usize, 0), order.tags.len);
    try std.testing.expectEqual(@as(usize, 0), order.lines.len);
}

test "jzon behaviour: scanner parser gives an absent field the default its type declares" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const src = "{\"id\":1,\"customer\":\"x\",\"status\":\"PENDING\"," ++
        "\"tags\":[],\"lines\":[],\"totals\":{\"net_cents\":0,\"tax_cents\":0}}";

    const order = try scanner_parser.parse(Order, arena.allocator(), src, .{});

    try std.testing.expect(order.note == null);
}

test "jzon behaviour: scanner parser borrows a clean string and copies an escaped one" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const Pair = struct {
        plain: []const u8,
        escaped: []const u8,
    };
    const src = "{\"plain\":\"borrowed\",\"escaped\":\"one\\ttwo\"}";

    const pair = try scanner_parser.parse(Pair, arena.allocator(), src, .{ .strings = .BORROW });

    try std.testing.expect(inside(src, pair.plain));
    try std.testing.expect(!inside(src, pair.escaped));
    try std.testing.expectEqualStrings("borrowed", pair.plain);
    try std.testing.expectEqualStrings("one\ttwo", pair.escaped);
}

test "jzon behaviour: scanner parser copies every string when asked to" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const Pair = struct {
        plain: []const u8,
        escaped: []const u8,
    };
    const src = "{\"plain\":\"copied\",\"escaped\":\"one\\ttwo\"}";

    const pair = try scanner_parser.parse(Pair, arena.allocator(), src, .{ .strings = .COPY });

    try std.testing.expect(!inside(src, pair.plain));
    try std.testing.expectEqualStrings("copied", pair.plain);
    try std.testing.expectEqualStrings("one\ttwo", pair.escaped);
}

test "jzon behaviour: scanner parser refuses a key the type does not declare" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const Pair = struct { id: u8, name: []const u8 };
    const src = "{\"id\":1,\"name\":\"x\",\"shipped_at\":\"today\"}";

    try std.testing.expectError(
        error.JzonUnknownField,
        scanner_parser.parse(Pair, arena.allocator(), src, .{}),
    );
}

test "jzon behaviour: scanner parser steps over a key the type does not declare when asked to" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const Pair = struct { id: u8, name: []const u8 };
    const src = "{\"id\":1,\"extra\":{\"deep\":[1,2,{\"deeper\":true}]},\"name\":\"x\"}";

    const pair = try scanner_parser.parse(Pair, arena.allocator(), src, .{ .unknown = .SKIP });

    try std.testing.expectEqual(@as(u8, 1), pair.id);
    try std.testing.expectEqualStrings("x", pair.name);
}

test "jzon behaviour: scanner parser reads a bare value as well as an object" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectEqual(@as(u32, 42), try scanner_parser.parse(u32, allocator, "42", .{}));
    try std.testing.expectEqual(@as(f64, 2.5), try scanner_parser.parse(f64, allocator, "2.5", .{}));
    try std.testing.expect(try scanner_parser.parse(bool, allocator, "true", .{}));
    try std.testing.expectEqual(Status.CANCELLED, try scanner_parser.parse(Status, allocator, "\"CANCELLED\"", .{}));
    try std.testing.expectEqualStrings("hi", try scanner_parser.parse([]const u8, allocator, "\"hi\"", .{}));
}

test "jzon behaviour: scanner parser reads a field the document puts out of order" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const Pair = struct { id: u8, name: []const u8 };

    const forward = try scanner_parser.parse(Pair, arena.allocator(), "{\"id\":1,\"name\":\"x\"}", .{});
    const backward = try scanner_parser.parse(Pair, arena.allocator(), "{\"name\":\"x\",\"id\":1}", .{});

    try std.testing.expectEqual(forward.id, backward.id);
    try std.testing.expectEqualStrings(forward.name, backward.name);
}

/// Assert two orders carry the same value in every field.
fn expectSameOrder(expected: Order, actual: Order) !void {
    try std.testing.expectEqual(expected.id, actual.id);
    try std.testing.expectEqualStrings(expected.customer, actual.customer);
    try std.testing.expectEqual(expected.status, actual.status);
    try std.testing.expectEqualStrings(expected.note.?, actual.note.?);

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

/// Whether `text` is a slice of `src` rather than a copy of it.
fn inside(src: []const u8, text: []const u8) bool {
    const start = @intFromPtr(src.ptr);
    const at = @intFromPtr(text.ptr);

    return at >= start and at < start + src.len;
}
