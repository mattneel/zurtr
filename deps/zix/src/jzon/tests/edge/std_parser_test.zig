//! Edge tests: jzon.std_parser at the boundaries.
//! Covers documents that end early, carry more than one value, repeat a key, or
//! hold a number the field cannot take, and checks each one lands on the shared
//! error set rather than on std's own.

const std = @import("std");
const jzon = @import("jzon");

const std_parser = jzon.std_parser;

const Status = enum { PENDING, SHIPPED };

const Pair = struct {
    id: u8,
    name: []const u8,
};

test "jzon edge: std parser reports a document that ends early" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectError(error.JzonTruncated, std_parser.parse(u8, allocator, "", .{}));
    try std.testing.expectError(error.JzonTruncated, std_parser.parse(Pair, allocator, "{", .{}));
    try std.testing.expectError(error.JzonTruncated, std_parser.parse(Pair, allocator, "{\"id\":1,", .{}));
}

test "jzon edge: std parser reports a document carrying more than one value" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectError(error.JzonUnexpected, std_parser.parse(u8, allocator, "1 2", .{}));
    try std.testing.expectError(
        error.JzonUnexpected,
        std_parser.parse(Pair, allocator, "{\"id\":1,\"name\":\"x\"}{}", .{}),
    );
}

test "jzon edge: std parser reports the same key twice" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(
        error.JzonUnexpected,
        std_parser.parse(Pair, arena.allocator(), "{\"id\":1,\"id\":2,\"name\":\"x\"}", .{}),
    );
}

test "jzon edge: std parser reports a number the field cannot take" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectError(error.JzonBadNumber, std_parser.parse(Pair, allocator, "{\"id\":300,\"name\":\"x\"}", .{}));
    try std.testing.expectError(error.JzonBadNumber, std_parser.parse(Pair, allocator, "{\"id\":1.5,\"name\":\"x\"}", .{}));
    try std.testing.expectError(error.JzonBadNumber, std_parser.parse(Pair, allocator, "{\"id\":-1,\"name\":\"x\"}", .{}));
}

test "jzon edge: std parser reports a value of the wrong shape" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectError(error.JzonUnexpected, std_parser.parse(Pair, allocator, "{\"id\":null,\"name\":\"x\"}", .{}));
    try std.testing.expectError(error.JzonUnexpected, std_parser.parse(Pair, allocator, "{\"id\":1,\"name\":7}", .{}));
    try std.testing.expectError(error.JzonUnexpected, std_parser.parse(Pair, allocator, "[1,2]", .{}));
}

test "jzon edge: std parser reports an object owing every field" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.JzonMissingField, std_parser.parse(Pair, arena.allocator(), "{}", .{}));
}

test "jzon edge: std parser reports a name no enum tag carries" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectError(error.JzonUnknownEnumValue, std_parser.parse(Status, allocator, "\"GONE\"", .{}));
    try std.testing.expectError(error.JzonUnknownEnumValue, std_parser.parse(Status, allocator, "\"pending\"", .{}));
}

test "jzon edge: std parser decodes a surrogate pair and refuses a lone half" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const paired = try std_parser.parse([]const u8, allocator, "\"\\ud83d\\udca9\"", .{});
    try std.testing.expectEqualStrings("\xf0\x9f\x92\xa9", paired);

    // std reports a broken escape as a syntax error rather than as its own kind,
    // so it lands on Unexpected here.
    try std.testing.expectError(error.JzonUnexpected, std_parser.parse([]const u8, allocator, "\"\\ud83d\"", .{}));
    try std.testing.expectError(error.JzonUnexpected, std_parser.parse([]const u8, allocator, "\"\\q\"", .{}));
}

test "jzon edge: std parser reads the empty string, object and array" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const Holder = struct {
        text: []const u8,
        items: []const u32,
    };

    const empty = try std_parser.parse(Holder, allocator, "{\"text\":\"\",\"items\":[]}", .{});

    try std.testing.expectEqual(@as(usize, 0), empty.text.len);
    try std.testing.expectEqual(@as(usize, 0), empty.items.len);

    // A type that declares no fields is owed nothing, so an empty object is a
    // whole value for it.
    _ = try std_parser.parse(struct {}, allocator, "{}", .{});
}

test "jzon edge: std parser steps over a deeply nested unknown value" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const src = "{\"id\":1,\"deep\":[[[{\"a\":{\"b\":[null,true,\"x\"]}}]]],\"name\":\"y\"}";

    const pair = try std_parser.parse(Pair, arena.allocator(), src, .{ .unknown = .SKIP });

    try std.testing.expectEqual(@as(u8, 1), pair.id);
    try std.testing.expectEqualStrings("y", pair.name);
}

test "jzon edge: std parser reads the extremes of a width" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectEqual(@as(u64, std.math.maxInt(u64)), try std_parser.parse(u64, allocator, "18446744073709551615", .{}));
    try std.testing.expectEqual(@as(i64, std.math.minInt(i64)), try std_parser.parse(i64, allocator, "-9223372036854775808", .{}));
    try std.testing.expectError(error.JzonBadNumber, std_parser.parse(u64, allocator, "18446744073709551616", .{}));
}
