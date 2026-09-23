//! jzon deserialize.
//!
//! What:
//! - The one call that turns JSON text into a typed value. It runs the read path
//!   the options name over the caller's document and builds the target type out
//!   of it.
//! - Everything the result points at comes from the allocator handed in, so an
//!   arena reset between requests frees a whole parse in one step.
//!
//! Note:
//! - Every strategy reports through the same error set and reads back what every
//!   serialize strategy writes, so swapping one for another changes what it
//!   costs and not what a caller has to handle.
//! - The generated strategies differ from the std-backed one in three places,
//!   each of them a shape neither serialize path ever writes: a slice of bytes
//!   is a string and never an array of numbers, a sign against an unsigned field
//!   is a type error rather than a value, and a broken escape is BadEscape
//!   rather than a syntax error.

const std = @import("std");

const generated_parser = @import("generated_parser.zig");
const options_mod = @import("options.zig");
const scanner_parser = @import("scanner_parser.zig");
const std_parser = @import("std_parser.zig");

const Allocator = std.mem.Allocator;

/// Which read path a parse runs.
pub const Strategy = options_mod.Strategy;

/// The options a parse runs with.
pub const Options = options_mod.Options;

/// How a parse can fail.
pub const Error = options_mod.Error;

/// Read a `T` out of a whole JSON document.
///
/// Note:
/// - The strategy is comptime, so only the path it names is compiled in. A shape
///   the generated paths refuse still parses under the default one.
/// - The document has to hold one value and nothing after it, so trailing bytes
///   are a failure rather than something left unread.
///
/// Param:
/// T - type (comptime, the type to build)
/// allocator - Allocator (owns everything the result points at)
/// src - []const u8 (the whole document)
/// options - Options (comptime, which read path runs, how strings are held, and
///   what an unknown key does)
///
/// Usage:
/// ```zig
/// const order = try jzon.deserialize(Order, arena, body, .{});
///
/// const faster = try jzon.deserialize(Order, arena, body, .{
///     .strategy = .GENERATED,
///     .strings = .BORROW,
///     .unknown = .SKIP,
/// });
/// ```
///
/// Return:
/// - T (the parsed value)
/// - error.JzonUnknownField, error.JzonMissingField, error.JzonUnknownEnumValue when the
///   document and the type disagree
/// - error.JzonTruncated, error.JzonUnexpected, error.JzonBadNumber, error.JzonBadEscape when
///   the document is not what it claims
/// - error.OutOfMemory when the allocator runs out
pub fn deserialize(
    comptime T: type,
    allocator: Allocator,
    src: []const u8,
    comptime options: Options,
) Error!T {
    return switch (options.strategy) {
        .STD => std_parser.parse(T, allocator, src, options),
        .SCANNER => scanner_parser.parse(T, allocator, src, options),
        .GENERATED => generated_parser.parse(T, allocator, src, options, .{ .scan = .SCALAR }),
        .GENERATED_VECTOR => generated_parser.parse(T, allocator, src, options, .{ .scan = .VECTOR }),
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Every strategy, so a case can assert all of them at once.
const STRATEGIES = [_]Strategy{ .STD, .SCANNER, .GENERATED, .GENERATED_VECTOR };

const Status = enum { PENDING, SHIPPED };

const Nested = struct {
    alpha: i32,
    beta: []const u8,
};

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

test "jzon: deserialize reads a record through every strategy" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    inline for (STRATEGIES) |strategy| {
        const record = try deserialize(Record, arena.allocator(), DOCUMENT, .{ .strategy = strategy });

        try std.testing.expectEqual(@as(u64, 7), record.id);
        try std.testing.expectEqualStrings("a\"b", record.name);
        try std.testing.expectEqual(@as(f64, 2.5), record.ratio);
        try std.testing.expect(record.active);
        try std.testing.expectEqual(Status.SHIPPED, record.status);
        try std.testing.expect(record.note == null);
        try std.testing.expectEqualStrings("two", record.tags[1]);
        try std.testing.expectEqual(@as(i32, -3), record.nested.alpha);
    }
}

test "jzon: deserialize carries the string mode down to the path it picked" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const src = "{\"alpha\":1,\"beta\":\"borrowed\"}";

    inline for (STRATEGIES) |strategy| {
        const borrowed = try deserialize(Nested, arena.allocator(), src, .{
            .strategy = strategy,
            .strings = .BORROW,
        });

        try std.testing.expect(@intFromPtr(borrowed.beta.ptr) >= @intFromPtr(src.ptr));
        try std.testing.expect(@intFromPtr(borrowed.beta.ptr) < @intFromPtr(src.ptr) + src.len);

        const copied = try deserialize(Nested, arena.allocator(), src, .{
            .strategy = strategy,
            .strings = .COPY,
        });

        try std.testing.expect(@intFromPtr(copied.beta.ptr) < @intFromPtr(src.ptr) or
            @intFromPtr(copied.beta.ptr) >= @intFromPtr(src.ptr) + src.len);
        try std.testing.expectEqualStrings("borrowed", copied.beta);
    }
}

test "jzon: deserialize carries the unknown key rule down to the path it picked" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const src = "{\"alpha\":1,\"extra\":[1,{\"deep\":null}],\"beta\":\"x\"}";

    inline for (STRATEGIES) |strategy| {
        const skipped = try deserialize(Nested, arena.allocator(), src, .{
            .strategy = strategy,
            .unknown = .SKIP,
        });

        try std.testing.expectEqual(@as(i32, 1), skipped.alpha);
        try std.testing.expectEqualStrings("x", skipped.beta);

        try std.testing.expectError(error.JzonUnknownField, deserialize(Nested, arena.allocator(), src, .{
            .strategy = strategy,
            .unknown = .REJECT,
        }));
    }
}

test "jzon: deserialize reports every strategy's failure through one error set" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    inline for (STRATEGIES) |strategy| {
        const options: Options = .{ .strategy = strategy };

        try std.testing.expectError(error.JzonTruncated, deserialize(Nested, arena.allocator(), "{\"alpha\":", options));
        try std.testing.expectError(error.JzonUnexpected, deserialize(Nested, arena.allocator(), "[]", options));
        try std.testing.expectError(error.JzonMissingField, deserialize(Nested, arena.allocator(), "{\"alpha\":1}", options));
        try std.testing.expectError(error.JzonUnknownField, deserialize(Nested, arena.allocator(), "{\"gone\":1}", options));
    }
}

test "jzon: deserialize reads a shape the generated paths refuse" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // std fills a byte slice from an array of numbers, which the generated paths
    // refuse. The default path is the one that stays correct for it.
    const text = try deserialize([]const u8, arena.allocator(), "[104,105]", .{});

    try std.testing.expectEqualStrings("hi", text);
}
