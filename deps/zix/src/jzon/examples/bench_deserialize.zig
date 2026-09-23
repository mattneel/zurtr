//! jzon example: what each read path costs on one document.
//!
//! What:
//! - Parses the same document the same number of times through every read path,
//!   then prints ns per parse, parses per second, and each path as a multiple of
//!   the default's rate.
//! - The first row is what `.{}` gives a caller who has made no choice, which is
//!   the std-backed path. Every row under it is a generated path.
//! - The table runs twice, once on a minified document and once on the same
//!   document laid out with whitespace. Whitespace is the one thing that moves
//!   the ranking, so a single shape would read as a verdict it is not.
//!
//! Note:
//! - Build this with `-Doptimize=ReleaseFast`. A Debug build measures the safety
//!   checks rather than the paths, and every row collapses onto the others.
//! - The quickest of ROUNDS is reported, not the mean. One round picks up
//!   whatever else the machine happened to be doing.
//! - The arena reset is inside the timed loop on purpose: it is what a worker
//!   pays per request, and every row pays it equally.
//! - Strings are copied here, which is the default. Borrowing them instead is a
//!   separate lever, shown in examples/strings.zig.
//! - Build it from this package with `zig build example-bench_deserialize`, then
//!   run ./zig-out/bin/jzon-example-bench_deserialize-<arch>-<os>.

const std = @import("std");
const jzon = @import("jzon");

/// Parses one round does.
const ITERATIONS: usize = 100_000;

/// Rounds run per path. The quickest is what gets reported.
const ROUNDS: usize = 5;

/// Every read path, the default first so the ratio column has a base.
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

/// A document and what to call it in the heading.
const Document = struct {
    what: []const u8,
    text: []const u8,
};

/// The shape that arrives off a wire: no whitespace anywhere.
const MINIFIED =
    "{\"id\":4815162342,\"customer\":\"Rekha Nair\",\"status\":\"SHIPPED\"," ++
    "\"note\":\"leave at the door\",\"tags\":[\"priority\",\"gift\"]," ++
    "\"lines\":[{\"sku\":\"AB-1\",\"qty\":2,\"price_cents\":1299}," ++
    "{\"sku\":\"CD-2\",\"qty\":1,\"price_cents\":4500}]}";

/// The same value, laid out the way a client that pretty prints sends it.
const LAID_OUT =
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

const DOCUMENTS = [_]Document{
    .{ .what = "minified", .text = MINIFIED },
    .{ .what = "laid out", .text = LAID_OUT },
};

/// What both documents hold, so a parse that read less cannot go untimed.
const EXPECTED_LINES: usize = 2;

// --------------------------------------------------------- //

/// Parse the document ITERATIONS times, ROUNDS times over.
///
/// Note:
/// - The arena is reset after every parse, so the run measures a steady worker
///   rather than an arena that keeps growing
///
/// Return:
/// - Nanoseconds the quickest round took
/// - error.JzonWrongShape when the parse did not read the whole document
fn timeStrategy(
    io: std.Io,
    arena: *std.heap.ArenaAllocator,
    src: []const u8,
    comptime strategy: jzon.DeserializeStrategy,
) !u64 {
    // One parse before the clock starts: it warms the code path and it is what
    // proves this path reads the same document as the others.
    {
        defer _ = arena.reset(.retain_capacity);

        const order = try jzon.deserialize(Order, arena.allocator(), src, .{ .strategy = strategy });
        if (order.lines.len != EXPECTED_LINES) return error.JzonWrongShape;
    }

    var best: u64 = std.math.maxInt(u64);

    for (0..ROUNDS) |_| {
        const started = std.Io.Timestamp.now(io, .awake);

        for (0..ITERATIONS) |_| {
            const order = try jzon.deserialize(Order, arena.allocator(), src, .{ .strategy = strategy });
            std.mem.doNotOptimizeAway(&order);

            _ = arena.reset(.retain_capacity);
        }

        const ended = std.Io.Timestamp.now(io, .awake);
        const elapsed: u64 = @intCast(started.durationTo(ended).nanoseconds);

        best = @min(best, elapsed);
    }

    return best;
}

/// Print one table: every read path over one document.
fn runDocument(io: std.Io, arena: *std.heap.ArenaAllocator, document: Document) !void {
    std.debug.print("deserialize, {s} ({d} bytes): {d} parses per round, quickest of {d} rounds\n\n", .{
        document.what,
        document.text.len,
        ITERATIONS,
        ROUNDS,
    });
    std.debug.print("{s: <18}{s: >12}{s: >14}{s: >12}\n", .{ "strategy", "ns/parse", "parses/s", "vs default" });

    var default_rate: f64 = 0;

    inline for (STRATEGIES, 0..) |strategy, index| {
        const elapsed = try timeStrategy(io, arena, document.text, strategy);
        const per_parse = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(ITERATIONS));
        const rate = @as(f64, std.time.ns_per_s) / per_parse;

        if (index == 0) default_rate = rate;

        std.debug.print("{s: <18}{d: >12.0}{d: >14.0}{d: >11.2}x\n", .{
            @tagName(strategy),
            per_parse,
            rate,
            rate / default_rate,
        });
    }

    std.debug.print("\n", .{});
}

// main takes std.process.Init for one reason: the monotonic clock the timing reads
// comes from io. The parses themselves touch no IO.
pub fn main(process: std.process.Init) !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.smp_allocator);
    defer arena.deinit();

    for (DOCUMENTS) |document| {
        try runDocument(process.io, &arena, document);
    }
}
