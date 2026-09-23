//! jzon example: where a parsed string's bytes live.
//!
//! A parsed string either owns its bytes or points at the document it came from.
//! That is the whole of the `strings` option, and it decides two things: what the
//! parse costs, and how long the document has to stay alive.
//!
//! .COPY copies every string into the allocator, so the value outlives the
//! document. .BORROW points a string with no escape at the document itself, which
//! costs no copy and no allocation, and makes the document part of the value's
//! lifetime.
//!
//! Note:
//! - A string carrying an escape is copied under both modes. Its decoded bytes are
//!   not in the document anywhere: the document holds \t, the value holds a tab.
//! - Borrowing suits a request body held for the length of one handler. Copying
//!   suits a value that outlives the buffer it arrived in, such as one put on a
//!   queue or kept in a cache.
//! - Build it from this package with `zig build example-strings`, then run
//!   ./zig-out/bin/jzon-example-strings-<arch>-<os>.

const std = @import("std");
const jzon = @import("jzon");

/// Every read path, so both modes can be shown on all of them.
const STRATEGIES = [_]jzon.DeserializeStrategy{ .STD, .SCANNER, .GENERATED, .GENERATED_VECTOR };

// --------------------------------------------------------- //

const Note = struct {
    plain: []const u8,
    escaped: []const u8,
};

/// `plain` has no escape in it, `escaped` carries a tab written as \t.
const DOCUMENT = "{\"plain\":\"leave at the door\",\"escaped\":\"one\\ttwo\"}";

// --------------------------------------------------------- //

/// Whether `text` sits inside `document` rather than in memory of its own.
fn pointsIntoDocument(text: []const u8, document: []const u8) bool {
    const document_start = @intFromPtr(document.ptr);
    const text_start = @intFromPtr(text.ptr);

    return text_start >= document_start and text_start < document_start + document.len;
}

/// Read the document in one mode and report where each string ended up.
fn readInMode(allocator: std.mem.Allocator, comptime mode: jzon.Strings) !void {
    const note = try jzon.deserialize(Note, allocator, DOCUMENT, .{ .strings = mode });

    std.debug.print("{s}:\n", .{@tagName(mode)});
    std.debug.print("  plain   \"{s}\", in the document: {}\n", .{
        note.plain,
        pointsIntoDocument(note.plain, DOCUMENT),
    });
    std.debug.print("  escaped \"{s}\", in the document: {}\n", .{
        note.escaped,
        pointsIntoDocument(note.escaped, DOCUMENT),
    });
}

/// Show that the mode holds whichever read path runs.
fn readEveryStrategyInBothModes(arena: *std.heap.ArenaAllocator) !void {
    inline for (STRATEGIES) |strategy| {
        defer _ = arena.reset(.retain_capacity);

        const copied = try jzon.deserialize(Note, arena.allocator(), DOCUMENT, .{
            .strategy = strategy,
            .strings = .COPY,
        });
        const borrowed = try jzon.deserialize(Note, arena.allocator(), DOCUMENT, .{
            .strategy = strategy,
            .strings = .BORROW,
        });

        std.debug.print("{s}: copied plain is in the document: {}, borrowed plain is in the document: {}\n", .{
            @tagName(strategy),
            pointsIntoDocument(copied.plain, DOCUMENT),
            pointsIntoDocument(borrowed.plain, DOCUMENT),
        });
    }

    std.debug.print("\n", .{});
}

/// What a borrowed string is worth only while its document is alive.
fn showTheLifetimeRule(allocator: std.mem.Allocator) !void {
    // The document is built here rather than being a literal, so it is the kind
    // of buffer a server reuses: read into it, parse out of it, answer, read the
    // next request over the top of it.
    var body: [64]u8 = undefined;
    const src = try std.fmt.bufPrint(&body, "{{\"plain\":\"{s}\",\"escaped\":\"a\\tb\"}}", .{"first"});

    const note = try jzon.deserialize(Note, allocator, src, .{ .strings = .BORROW });
    std.debug.print("borrowed before the buffer is reused: \"{s}\"\n", .{note.plain});

    // Reusing the buffer rewrites what the borrowed string points at. Nothing
    // here is unsafe, the bytes are simply not the ones that were parsed. This is
    // what .COPY buys, and what .BORROW asks a caller to keep track of.
    _ = try std.fmt.bufPrint(&body, "{{\"plain\":\"{s}\",\"escaped\":\"a\\tb\"}}", .{"later"});
    std.debug.print("borrowed after the buffer is reused:  \"{s}\"\n", .{note.plain});
    std.debug.print("the escaped string was copied, so it is untouched: \"{s}\"\n\n", .{note.escaped});
}

// main takes no std.process.Init because a parse touches no IO. What it does need
// is an allocator, which is the one thing it asks the caller for.
pub fn main() !void {
    var arena: std.heap.ArenaAllocator = .init(std.heap.smp_allocator);
    defer arena.deinit();

    try readInMode(arena.allocator(), .COPY);
    try readInMode(arena.allocator(), .BORROW);
    std.debug.print("\n", .{});

    _ = arena.reset(.retain_capacity);

    try readEveryStrategyInBothModes(&arena);
    try showTheLifetimeRule(arena.allocator());
}
