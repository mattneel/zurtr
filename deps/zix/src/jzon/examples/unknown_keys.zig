//! jzon example: a key the type does not declare.
//!
//! A document does not always match the type reading it. Another service adds a
//! field, a client runs ahead of this build, a payload carries more than this
//! handler cares about. The `unknown` option decides what that means.
//!
//! .REJECT calls the document wrong for this type and fails with
//! error.JzonUnknownField. .SKIP steps over the key and its whole value, however deep
//! it nests, and reads the rest.
//!
//! Note:
//! - .REJECT is the default. A document that says something the type never asked
//!   about is more often a version mismatch than a courtesy, and failing says so
//!   at the edge rather than dropping the field quietly.
//! - Skipping costs a walk over the value being stepped over, not a parse of it.
//!   Nothing inside an unknown key is built.
//! - A missing key is a different question. .SKIP forgives keys the type does not
//!   want, never keys it is owed, so error.JzonMissingField stands either way.
//! - Build it from this package with `zig build example-unknown_keys`, then run
//!   ./zig-out/bin/jzon-example-unknown_keys-<arch>-<os>.

const std = @import("std");
const jzon = @import("jzon");

/// Every read path, so both answers can be shown on all of them.
const STRATEGIES = [_]jzon.DeserializeStrategy{ .STD, .SCANNER, .GENERATED, .GENERATED_VECTOR };

// --------------------------------------------------------- //

const Status = enum { PENDING, SHIPPED, CANCELLED };

const Order = struct {
    id: u64,
    customer: []const u8,
    status: Status,
};

/// The document this build's type was written for.
const KNOWN = "{\"id\":7,\"customer\":\"Rekha Nair\",\"status\":\"SHIPPED\"}";

/// The same order from a sender that carries more: a flat extra field, a nested
/// object, and an array of objects. None of it is declared by `Order`.
const EXTENDED =
    "{\"id\":7,\"customer\":\"Rekha Nair\",\"channel\":\"mobile\"," ++
    "\"address\":{\"city\":\"Bandung\",\"geo\":{\"lat\":-6.9,\"lon\":107.6}}," ++
    "\"history\":[{\"at\":\"2026-01-01\",\"was\":\"PENDING\"}]," ++
    "\"status\":\"SHIPPED\"}";

/// The extended document with the field the type is owed taken out of it.
const OWED = "{\"id\":7,\"channel\":\"mobile\",\"status\":\"SHIPPED\"}";

// --------------------------------------------------------- //

/// Read one document under one answer and print how it went.
fn readAndReport(
    allocator: std.mem.Allocator,
    label: []const u8,
    src: []const u8,
    comptime unknown: jzon.Unknown,
) void {
    const outcome = jzon.deserialize(Order, allocator, src, .{ .unknown = unknown });

    if (outcome) |order| {
        std.debug.print("{s} under {s}: order {d} for {s}, {s}\n", .{
            label,
            @tagName(unknown),
            order.id,
            order.customer,
            @tagName(order.status),
        });
    } else |failure| {
        std.debug.print("{s} under {s}: {}\n", .{ label, @tagName(unknown), failure });
    }
}

/// Show that the answer holds whichever read path runs.
fn readEveryStrategy(arena: *std.heap.ArenaAllocator) !void {
    inline for (STRATEGIES) |strategy| {
        defer _ = arena.reset(.retain_capacity);

        const refused = jzon.deserialize(Order, arena.allocator(), EXTENDED, .{
            .strategy = strategy,
            .unknown = .REJECT,
        });
        const skipped = try jzon.deserialize(Order, arena.allocator(), EXTENDED, .{
            .strategy = strategy,
            .unknown = .SKIP,
        });

        if (refused) |order| {
            std.debug.print("{s}: unexpected, REJECT read order {d}\n", .{ @tagName(strategy), order.id });
        } else |failure| {
            std.debug.print("{s}: REJECT gives {}, SKIP reads order {d}\n", .{
                @tagName(strategy),
                failure,
                skipped.id,
            });
        }
    }

    std.debug.print("\n", .{});
}

// main takes no std.process.Init because a parse touches no IO. What it does need
// is an allocator, which is the one thing it asks the caller for.
pub fn main() !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.smp_allocator);
    defer arena.deinit();

    // A document the type was written for reads under both answers.
    readAndReport(arena.allocator(), "known", KNOWN, .REJECT);
    readAndReport(arena.allocator(), "known", KNOWN, .SKIP);

    // A document carrying more than the type declares is where they part.
    readAndReport(arena.allocator(), "extended", EXTENDED, .REJECT);
    readAndReport(arena.allocator(), "extended", EXTENDED, .SKIP);

    // Skipping forgives the extra key and still reports the missing one. REJECT
    // stops at whichever disagreement it reaches first, which here is the extra.
    readAndReport(arena.allocator(), "owed", OWED, .REJECT);
    readAndReport(arena.allocator(), "owed", OWED, .SKIP);
    std.debug.print("\n", .{});

    _ = arena.reset(.retain_capacity);

    try readEveryStrategy(&arena);
}
