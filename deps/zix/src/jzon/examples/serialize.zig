//! jzon example: a typed value into JSON text, in a buffer the caller owns.
//!
//! A render allocates nothing. It is handed a buffer, writes into it, and returns
//! how many bytes it used. A value that does not fit is error.NoSpaceLeft, never a
//! bigger buffer, so a caller sizes the buffer once and knows what it costs.
//!
//! The strategy names which write path runs. All four render the same bytes for
//! the same value, so picking one is a cost decision and nothing else. It is a
//! comptime field, so only the path named is compiled into the binary.
//!
//! Note:
//! - .STD renders anything std renders, including shapes the generated paths have
//!   no JSON form for. Those are a compile error naming the type, never a runtime
//!   failure.
//! - .GENERATED_VECTOR scans strings one vector lane at a time. It pays on long
//!   strings and costs on short ones, which is why it is a call-site choice.
//! - Build it from this package with `zig build example-serialize`, then run
//!   ./zig-out/bin/jzon-example-serialize-<arch>-<os>.

const std = @import("std");
const jzon = @import("jzon");

/// Every write path, so one value can be rendered through all of them.
const STRATEGIES = [_]jzon.SerializeStrategy{ .STD, .GENERATED_FMT, .GENERATED, .GENERATED_VECTOR };

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
};

// --------------------------------------------------------- //

/// Render the order the way a caller who has made no choice gets it.
fn renderWithTheDefault() !void {
    var buf: [512]u8 = undefined;
    const len = try jzon.serialize(&buf, ORDER, .{});

    std.debug.print("default strategy, {d} bytes:\n{s}\n\n", .{ len, buf[0..len] });
}

/// Render the same order through every path and check the bytes agree.
fn renderThroughEveryStrategy() !void {
    var expected: [512]u8 = undefined;
    const expected_len = try jzon.serialize(&expected, ORDER, .{});

    inline for (STRATEGIES) |strategy| {
        var buf: [512]u8 = undefined;
        const len = try jzon.serialize(&buf, ORDER, .{ .strategy = strategy });

        std.debug.print("{s}: {d} bytes, same bytes as the default: {}\n", .{
            @tagName(strategy),
            len,
            std.mem.eql(u8, expected[0..expected_len], buf[0..len]),
        });
    }

    std.debug.print("\n", .{});
}

/// Render an unset optional, which is the one field the shape may leave out.
fn renderAnUnsetOptional() !void {
    var order = ORDER;
    order.note = null;

    var buf: [512]u8 = undefined;
    const len = try jzon.serialize(&buf, order, .{ .strategy = .GENERATED });

    std.debug.print("an unset optional is written as null:\n{s}\n\n", .{buf[0..len]});
}

/// Hand a render less room than the value needs.
fn renderIntoABufferTooSmall() void {
    var buf: [16]u8 = undefined;

    if (jzon.serialize(&buf, ORDER, .{})) |len| {
        std.debug.print("unexpected: {d} bytes rendered into {d}\n", .{ len, buf.len });
    } else |failure| {
        std.debug.print("a buffer of {d} bytes reports {}\n", .{ buf.len, failure });
        std.debug.print("no length comes back, so nothing left in the buffer is readable as a value\n", .{});
    }
}

// main takes no std.process.Init because a render touches no IO and no allocator.
// Everything it needs is the value and the buffer it was handed.
pub fn main() !void {
    try renderWithTheDefault();
    try renderThroughEveryStrategy();
    try renderAnUnsetOptional();

    renderIntoABufferTooSmall();
}
