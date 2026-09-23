//! jzon example: JSON text back into a typed value, on an arena.
//!
//! A parse allocates only what the result points at, out of the allocator it was
//! handed. An arena is the natural fit for a server: parse a request body into it,
//! answer, reset it, and the whole parse is freed in one step with nothing to walk
//! and nothing to free field by field.
//!
//! The strategy names which read path runs. All four read back the same value and
//! report through the same error set, so picking one is a cost decision. It is a
//! comptime field, so only the path named is compiled into the binary.
//!
//! Note:
//! - The document holds one value and nothing after it. Trailing bytes are a
//!   failure rather than something left unread.
//! - Whitespace and line layout do not matter. The body below arrives laid out,
//!   which is the shape .GENERATED_VECTOR is quickest on.
//! - Build it from this package with `zig build example-deserialize`, then run
//!   ./zig-out/bin/jzon-example-deserialize-<arch>-<os>.

const std = @import("std");
const jzon = @import("jzon");

/// Every read path, so one document can be read through all of them.
const STRATEGIES = [_]jzon.DeserializeStrategy{ .STD, .SCANNER, .GENERATED, .GENERATED_VECTOR };

// --------------------------------------------------------- //

const Status = enum { PENDING, SHIPPED, CANCELLED };

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
};

/// One request body, laid out the way a client that pretty prints would send it.
const BODY =
    \\{
    \\  "id": 4815162342,
    \\  "customer": "Rekha Nair",
    \\  "status": "SHIPPED",
    \\  "note": "leave at the door",
    \\  "tags": ["priority", "gift"],
    \\  "lines": [
    \\    {"sku": "AB-1", "qty": 2, "price_cents": 1299},
    \\    {"sku": "CD-2", "qty": 1, "price_cents": 4500}
    \\  ]
    \\}
;

/// Three bodies in a row, which is what a worker sees between arena resets.
const BODIES = [_][]const u8{
    "{\"id\":1,\"customer\":\"Ada\",\"status\":\"PENDING\",\"tags\":[],\"lines\":[]}",
    "{\"id\":2,\"customer\":\"Budi\",\"status\":\"SHIPPED\",\"note\":\"ring twice\",\"tags\":[\"gift\"],\"lines\":[]}",
    "{\"id\":3,\"customer\":\"Chen\",\"status\":\"CANCELLED\",\"tags\":[],\"lines\":[{\"sku\":\"EF-3\",\"qty\":9,\"price_cents\":250}]}",
};

// --------------------------------------------------------- //

/// Print every field of a parsed order.
fn describe(order: Order) void {
    std.debug.print("  id: {d}\n", .{order.id});
    std.debug.print("  customer: {s}\n", .{order.customer});
    std.debug.print("  status: {s}\n", .{@tagName(order.status)});
    std.debug.print("  note: {s}\n", .{order.note orelse "(none)"});

    std.debug.print("  tags:", .{});
    for (order.tags) |tag| std.debug.print(" {s}", .{tag});
    std.debug.print("\n", .{});

    for (order.lines) |line| {
        std.debug.print("  line: {s} x{d} at {d} cents\n", .{ line.sku, line.qty, line.price_cents });
    }
}

/// Read the body the way a caller who has made no choice gets it.
fn readWithTheDefault(allocator: std.mem.Allocator) !void {
    const order = try jzon.deserialize(Order, allocator, BODY, .{});

    std.debug.print("default strategy:\n", .{});
    describe(order);
    std.debug.print("\n", .{});
}

/// Read the same body through every path, resetting the arena between parses.
fn readThroughEveryStrategy(arena: *std.heap.ArenaAllocator) !void {
    inline for (STRATEGIES) |strategy| {
        defer _ = arena.reset(.retain_capacity);

        const order = try jzon.deserialize(Order, arena.allocator(), BODY, .{ .strategy = strategy });

        std.debug.print("{s}: id {d}, customer {s}, {d} tags, {d} lines\n", .{
            @tagName(strategy),
            order.id,
            order.customer,
            order.tags.len,
            order.lines.len,
        });
    }

    std.debug.print("\n", .{});
}

/// Serve three bodies off one arena, which is the shape a worker holds to.
fn readManyBodiesOnOneArena(arena: *std.heap.ArenaAllocator) !void {
    for (BODIES) |body| {
        // The reset is what frees the parse. It keeps the pages the arena has
        // already taken, so the next body is served without asking the OS again.
        defer _ = arena.reset(.retain_capacity);

        const order = try jzon.deserialize(Order, arena.allocator(), body, .{
            .strategy = .GENERATED,
        });

        std.debug.print("body {d}: {s} is {s}\n", .{ order.id, order.customer, @tagName(order.status) });
    }

    std.debug.print("\n", .{});
}

/// Hand a parse a document the type cannot take.
fn readADocumentThatDoesNotFit(allocator: std.mem.Allocator) void {
    const cases = [_][]const u8{
        "{\"id\":1,\"customer\":\"Ada\"",
        "{\"id\":1,\"customer\":\"Ada\",\"status\":\"GONE\",\"tags\":[],\"lines\":[]}",
        "{\"id\":1,\"customer\":\"Ada\",\"status\":\"PENDING\",\"tags\":[]}",
    };

    for (cases) |src| {
        const outcome = jzon.deserialize(Order, allocator, src, .{ .strategy = .GENERATED });

        if (outcome) |order| {
            std.debug.print("unexpected: read order {d}\n", .{order.id});
        } else |failure| {
            std.debug.print("{}\n", .{failure});
        }
    }
}

// main takes no std.process.Init because a parse touches no IO. What it does need
// is an allocator, which is the one thing it asks the caller for.
pub fn main() !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.smp_allocator);
    defer arena.deinit();

    try readWithTheDefault(arena.allocator());
    _ = arena.reset(.retain_capacity);

    try readThroughEveryStrategy(&arena);
    try readManyBodiesOnOneArena(&arena);

    readADocumentThatDoesNotFit(arena.allocator());
}
