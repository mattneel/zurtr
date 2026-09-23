//! Edge tests: jzon.scanner_parser at the boundaries.
//! Covers documents that end early, carry more than one value, repeat a key, or
//! hold a number the field cannot take, and the one number the two read paths
//! deliberately disagree about.

const std = @import("std");
const jzon = @import("jzon");

const scanner_parser = jzon.scanner_parser;
const std_parser = jzon.std_parser;

const Status = enum { PENDING, SHIPPED };

const Pair = struct {
    id: u8,
    name: []const u8,
};

test "jzon edge: scanner parser reports a document that ends early" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectError(error.JzonTruncated, scanner_parser.parse(u8, allocator, "", .{}));
    try std.testing.expectError(error.JzonTruncated, scanner_parser.parse(Pair, allocator, "{", .{}));
    try std.testing.expectError(error.JzonTruncated, scanner_parser.parse(Pair, allocator, "{\"id\":1,", .{}));
}

test "jzon edge: scanner parser reports a document carrying more than one value" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectError(error.JzonUnexpected, scanner_parser.parse(u8, allocator, "1 2", .{}));
    try std.testing.expectError(
        error.JzonUnexpected,
        scanner_parser.parse(Pair, allocator, "{\"id\":1,\"name\":\"x\"}{}", .{}),
    );
}

test "jzon edge: scanner parser reports the same key twice" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(
        error.JzonUnexpected,
        scanner_parser.parse(Pair, arena.allocator(), "{\"id\":1,\"id\":2,\"name\":\"x\"}", .{}),
    );
}

test "jzon edge: scanner parser reports a number the field cannot take" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectError(error.JzonBadNumber, scanner_parser.parse(Pair, allocator, "{\"id\":300,\"name\":\"x\"}", .{}));
    try std.testing.expectError(error.JzonBadNumber, scanner_parser.parse(Pair, allocator, "{\"id\":1.5,\"name\":\"x\"}", .{}));
    try std.testing.expectError(error.JzonBadNumber, scanner_parser.parse(Pair, allocator, "{\"id\":-1,\"name\":\"x\"}", .{}));
}

test "jzon edge: the two read paths disagree about a signed zero in an unsigned field" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const src = "{\"id\":-0,\"name\":\"x\"}";

    // jzon treats a sign against an unsigned field as a type error, whatever the
    // digits after it are. std reads the digits and lands on zero. Neither
    // serialize path ever writes this, so no round trip crosses the difference.
    try std.testing.expectError(error.JzonBadNumber, scanner_parser.parse(Pair, allocator, src, .{}));

    const theirs = try std_parser.parse(Pair, allocator, src, .{});
    try std.testing.expectEqual(@as(u8, 0), theirs.id);
}

test "jzon edge: scanner parser reports a value of the wrong shape" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectError(error.JzonUnexpected, scanner_parser.parse(Pair, allocator, "{\"id\":null,\"name\":\"x\"}", .{}));
    try std.testing.expectError(error.JzonUnexpected, scanner_parser.parse(Pair, allocator, "{\"id\":1,\"name\":7}", .{}));
    try std.testing.expectError(error.JzonUnexpected, scanner_parser.parse(Pair, allocator, "[1,2]", .{}));
}

test "jzon edge: scanner parser reports an object owing every field" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.JzonMissingField, scanner_parser.parse(Pair, arena.allocator(), "{}", .{}));
}

test "jzon edge: scanner parser reports a name no enum tag carries" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectError(error.JzonUnknownEnumValue, scanner_parser.parse(Status, allocator, "\"GONE\"", .{}));
    try std.testing.expectError(error.JzonUnknownEnumValue, scanner_parser.parse(Status, allocator, "\"pending\"", .{}));
}

test "jzon edge: scanner parser decodes a surrogate pair and refuses a lone half" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const paired = try scanner_parser.parse([]const u8, allocator, "\"\\ud83d\\udca9\"", .{});
    try std.testing.expectEqualStrings("\xf0\x9f\x92\xa9", paired);

    // The scanner decides what an escape is, and it calls a broken one a syntax
    // error, so this path never reports BadEscape.
    try std.testing.expectError(error.JzonUnexpected, scanner_parser.parse([]const u8, allocator, "\"\\ud83d\"", .{}));
    try std.testing.expectError(error.JzonUnexpected, scanner_parser.parse([]const u8, allocator, "\"\\q\"", .{}));
}

test "jzon edge: scanner parser reads the empty string, object and array" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const Holder = struct {
        text: []const u8,
        items: []const u32,
    };

    const empty = try scanner_parser.parse(Holder, allocator, "{\"text\":\"\",\"items\":[]}", .{});

    try std.testing.expectEqual(@as(usize, 0), empty.text.len);
    try std.testing.expectEqual(@as(usize, 0), empty.items.len);

    // A type that declares no fields is owed nothing, so an empty object is a
    // whole value for it.
    _ = try scanner_parser.parse(struct {}, allocator, "{}", .{});
}

test "jzon edge: scanner parser steps over a deeply nested unknown value" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const src = "{\"id\":1,\"deep\":[[[{\"a\":{\"b\":[null,true,\"x\"]}}]]],\"name\":\"y\"}";

    const pair = try scanner_parser.parse(Pair, arena.allocator(), src, .{ .unknown = .SKIP });

    try std.testing.expectEqual(@as(u8, 1), pair.id);
    try std.testing.expectEqualStrings("y", pair.name);
}

test "jzon edge: scanner parser reads the extremes of a width" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), try scanner_parser.parse(u64, allocator, "18446744073709551615", .{}));
    try std.testing.expectEqual(@as(i64, std.math.minInt(i64)), try scanner_parser.parse(i64, allocator, "-9223372036854775808", .{}));
    try std.testing.expectError(error.JzonBadNumber, scanner_parser.parse(u64, allocator, "18446744073709551616", .{}));
}

test "jzon edge: the two read paths disagree about an array of bytes" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    // In jzon a slice of bytes is a string and nothing else. std also fills one
    // from an array of numbers, which is why the same type reads here and fails
    // there.
    try std.testing.expectError(error.JzonUnexpected, scanner_parser.parse([]const u8, allocator, "[104,105]", .{}));

    const theirs = try std_parser.parse([]const u8, allocator, "[104,105]", .{});
    try std.testing.expectEqualStrings("hi", theirs);
}

test "jzon edge: scanner parser reads a nested slice of slices" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const grid = try scanner_parser.parse(
        []const []const u32,
        arena.allocator(),
        "[[1,2],[],[3]]",
        .{},
    );

    try std.testing.expectEqual(@as(usize, 3), grid.len);
    try std.testing.expectEqual(@as(u32, 2), grid[0][1]);
    try std.testing.expectEqual(@as(usize, 0), grid[1].len);
    try std.testing.expectEqual(@as(u32, 3), grid[2][0]);
}
