//! jzon deserialize, the std-backed path.
//!
//! What:
//! - Reads a value through `std.json`, which reflects over the target type at
//!   runtime. This is the capable path: it takes every shape std takes,
//!   including the ones the generated parsers refuse at compile time.
//!
//! Note:
//! - Everything the result points at comes from the allocator handed in, so an
//!   arena reset frees a whole parse in one step.
//! - std has its own error set, wider than jzon's and shaped around std's
//!   internals. It is mapped onto the one jzon set here, so a caller sees the
//!   same failures whichever path ran.

const std = @import("std");

const Allocator = std.mem.Allocator;

/// How a parse can fail.
pub const Error = @import("options.zig").Error;

/// The options a parse runs with.
pub const Options = @import("options.zig").Options;

/// Everything std can report from a parse over a complete document.
const StdError = std.json.ParseError(std.json.Scanner);

/// Read a `T` out of a whole JSON document.
///
/// Param:
/// T - type (comptime, the type to build)
/// allocator - Allocator (owns everything the result points at)
/// src - []const u8 (the whole document)
/// options - Options (comptime, how strings are held and what an unknown key does)
///
/// Return:
/// - T (the parsed value)
/// - error.JzonUnknownField, error.JzonMissingField, error.JzonUnknownEnumValue when the
///   document and the type disagree
/// - error.JzonTruncated, error.JzonUnexpected, error.JzonBadNumber when the document is not
///   what it claims
/// - error.OutOfMemory when the allocator runs out
pub fn parse(
    comptime T: type,
    allocator: Allocator,
    src: []const u8,
    comptime options: Options,
) Error!T {
    return std.json.parseFromSliceLeaky(T, allocator, src, .{
        .ignore_unknown_fields = options.unknown == .SKIP,
        .allocate = switch (options.strings) {
            .COPY => .alloc_always,
            .BORROW => .alloc_if_needed,
        },
    }) catch |failure| translate(failure);
}

/// Map one of std's failures onto the set every jzon path shares.
///
/// Note:
/// - What is left over is the document disagreeing with the type: a syntax
///   error, a token where another was wanted, the same key twice, an array of
///   the wrong length, or a value past the length cap. All of them are
///   Unexpected, and an error a later std adds lands there too rather than
///   breaking the build.
fn translate(failure: StdError) Error {
    return switch (failure) {
        error.OutOfMemory => error.OutOfMemory,
        error.UnknownField => error.JzonUnknownField,
        error.MissingField => error.JzonMissingField,
        error.InvalidEnumTag => error.JzonUnknownEnumValue,
        error.UnexpectedEndOfInput, error.BufferUnderrun => error.JzonTruncated,
        error.Overflow, error.InvalidCharacter, error.InvalidNumber => error.JzonBadNumber,
        else => error.JzonUnexpected,
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const Nested = struct {
    alpha: i32,
    beta: []const u8,
};

const Status = enum { PENDING, SHIPPED };

const Record = struct {
    id: u64,
    name: []const u8,
    ratio: f64,
    active: bool,
    status: Status,
    note: ?[]const u8 = null,
    tags: []const []const u8,
    nested: Nested,
};

const DOCUMENT =
    "{\"id\":7,\"name\":\"a\\\"b\",\"ratio\":2.5,\"active\":true," ++
    "\"status\":\"SHIPPED\",\"note\":null,\"tags\":[\"one\",\"two\"]," ++
    "\"nested\":{\"alpha\":-3,\"beta\":\"x\"}}";

test "jzon: std parser reads a whole record" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const record = try parse(Record, arena.allocator(), DOCUMENT, .{});

    try std.testing.expectEqual(@as(u64, 7), record.id);
    try std.testing.expectEqualStrings("a\"b", record.name);
    try std.testing.expectEqual(@as(f64, 2.5), record.ratio);
    try std.testing.expect(record.active);
    try std.testing.expectEqual(Status.SHIPPED, record.status);
    try std.testing.expect(record.note == null);
    try std.testing.expectEqual(@as(usize, 2), record.tags.len);
    try std.testing.expectEqualStrings("two", record.tags[1]);
    try std.testing.expectEqual(@as(i32, -3), record.nested.alpha);
}

test "jzon: std parser borrows a clean string and copies an escaped one" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const src = "{\"plain\":\"borrowed\",\"escaped\":\"one\\ttwo\"}";
    const Pair = struct {
        plain: []const u8,
        escaped: []const u8,
    };

    const pair = try parse(Pair, arena.allocator(), src, .{ .strings = .BORROW });

    // A string with no escape is the document's own bytes, so it sits inside it.
    try std.testing.expect(@intFromPtr(pair.plain.ptr) >= @intFromPtr(src.ptr));
    try std.testing.expect(@intFromPtr(pair.plain.ptr) < @intFromPtr(src.ptr) + src.len);
    try std.testing.expectEqualStrings("one\ttwo", pair.escaped);
}

test "jzon: std parser maps std's failures onto the shared set" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const Pair = struct { id: u8, name: []const u8 };

    try std.testing.expectError(error.JzonUnknownField, parse(Pair, allocator, "{\"id\":1,\"name\":\"x\",\"other\":2}", .{}));
    try std.testing.expectError(error.JzonMissingField, parse(Pair, allocator, "{\"id\":1}", .{}));
    try std.testing.expectError(error.JzonBadNumber, parse(Pair, allocator, "{\"id\":300,\"name\":\"x\"}", .{}));
    try std.testing.expectError(error.JzonTruncated, parse(Pair, allocator, "{\"id\":1,", .{}));
    try std.testing.expectError(error.JzonUnexpected, parse(Pair, allocator, "{\"id\":true,\"name\":\"x\"}", .{}));
    try std.testing.expectError(error.JzonUnknownEnumValue, parse(Status, allocator, "\"GONE\"", .{}));
}

test "jzon: std parser steps over an unknown key when asked to" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const Pair = struct { id: u8, name: []const u8 };
    const src = "{\"id\":1,\"other\":{\"deep\":[1,2,3]},\"name\":\"x\"}";

    const pair = try parse(Pair, arena.allocator(), src, .{ .unknown = .SKIP });

    try std.testing.expectEqual(@as(u8, 1), pair.id);
    try std.testing.expectEqualStrings("x", pair.name);
}
