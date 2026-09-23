//! jzon example: what each write path costs on one record.
//!
//! What:
//! - Renders the same value the same number of times through every write path,
//!   then prints ns per render, renders per second, and each path as a multiple
//!   of the default's rate.
//! - The first row is what `.{}` gives a caller who has made no choice, which is
//!   the std-backed path. Every row under it is a generated path.
//!
//! Note:
//! - Build this with `-Doptimize=ReleaseFast`. A Debug build measures the safety
//!   checks rather than the paths, and every row collapses onto the others.
//! - The quickest of ROUNDS is reported, not the mean. One round picks up
//!   whatever else the machine happened to be doing.
//! - The rendered length is taken once before any timing and the paths are
//!   checked against each other, so a path that stopped writing the whole value
//!   cannot look quick.
//! - The numbers move with the record. A shape carrying longer strings or more
//!   integers shifts which path costs least, so read this as a method to rerun on
//!   the shape actually being served, not as a verdict.
//! - Build it from this package with `zig build example-bench_serialize`, then run
//!   ./zig-out/bin/jzon-example-bench_serialize-<arch>-<os>.

const std = @import("std");
const jzon = @import("jzon");

/// Renders one round does.
const ITERATIONS: usize = 100_000;

/// Rounds run per path. The quickest is what gets reported.
const ROUNDS: usize = 5;

/// Every write path, the default first so the ratio column has a base.
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

/// Render the order ITERATIONS times, ROUNDS times over.
///
/// Return:
/// - Nanoseconds the quickest round took
/// - error.NoSpaceLeft when the buffer is too small for the record
fn timeStrategy(io: std.Io, comptime strategy: jzon.SerializeStrategy) !u64 {
    var buf: [512]u8 = undefined;

    // One render before the clock starts: it warms the code path and it is the
    // length every timed render is expected to produce.
    const expected_len = try jzon.serialize(&buf, ORDER, .{ .strategy = strategy });

    var best: u64 = std.math.maxInt(u64);

    for (0..ROUNDS) |_| {
        const started = std.Io.Timestamp.now(io, .awake);

        for (0..ITERATIONS) |_| {
            const len = try jzon.serialize(&buf, ORDER, .{ .strategy = strategy });
            std.mem.doNotOptimizeAway(len);
        }

        const ended = std.Io.Timestamp.now(io, .awake);
        const elapsed: u64 = @intCast(started.durationTo(ended).nanoseconds);

        best = @min(best, elapsed);
    }

    if (expected_len == 0) return error.JzonNothingRendered;

    return best;
}

/// Check every path renders the same bytes, so the table compares equal work.
fn assertPathsAgree() !void {
    var expected: [512]u8 = undefined;
    const expected_len = try jzon.serialize(&expected, ORDER, .{});

    inline for (STRATEGIES) |strategy| {
        var buf: [512]u8 = undefined;
        const len = try jzon.serialize(&buf, ORDER, .{ .strategy = strategy });

        if (!std.mem.eql(u8, expected[0..expected_len], buf[0..len])) return error.JzonPathsDisagree;
    }

    std.debug.print("every path renders the same {d} bytes\n\n", .{expected_len});
}

// main takes std.process.Init for one reason: the monotonic clock the timing reads
// comes from io. The renders themselves touch no IO and no allocator.
pub fn main(process: std.process.Init) !void {
    try assertPathsAgree();

    std.debug.print("serialize: {d} renders per round, quickest of {d} rounds\n\n", .{ ITERATIONS, ROUNDS });
    std.debug.print("{s: <18}{s: >12}{s: >14}{s: >12}\n", .{ "strategy", "ns/render", "renders/s", "vs default" });

    var default_rate: f64 = 0;

    inline for (STRATEGIES, 0..) |strategy, index| {
        const elapsed = try timeStrategy(process.io, strategy);
        const per_render = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(ITERATIONS));
        const rate = @as(f64, std.time.ns_per_s) / per_render;

        if (index == 0) default_rate = rate;

        std.debug.print("{s: <18}{d: >12.0}{d: >14.0}{d: >11.2}x\n", .{
            @tagName(strategy),
            per_render,
            rate,
            rate / default_rate,
        });
    }
}
