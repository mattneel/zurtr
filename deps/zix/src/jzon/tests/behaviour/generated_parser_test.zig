//! Behaviour tests: jzon.generated_parser, the read path built from the
//! target type. Verifies both scan widths read every shape the generated
//! emitter writes, and read it the same way the other two paths do.

const std = @import("std");
const jzon = @import("jzon");

const generated_parser = jzon.generated_parser;
const scanner_parser = jzon.scanner_parser;
const std_parser = jzon.std_parser;

const Shape = generated_parser.Shape;

/// Both widths, so every case asserts the pair agrees.
const SHAPES = [_]Shape{
    .{ .scan = .SCALAR },
    .{ .scan = .VECTOR },
};

const Status = enum { PENDING, SHIPPED, CANCELLED };

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

test "jzon behaviour: the generated parser reads a whole record at both widths" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    inline for (SHAPES) |shape| {
        const record = try generated_parser.parse(Record, arena.allocator(), DOCUMENT, .{}, shape);

        try std.testing.expectEqual(@as(u64, 7), record.id);
        try std.testing.expectEqualStrings("a\"b", record.name);
        try std.testing.expectEqual(@as(f64, 2.5), record.ratio);
        try std.testing.expect(record.active);
        try std.testing.expectEqual(Status.SHIPPED, record.status);
        try std.testing.expect(record.note == null);
        try std.testing.expectEqual(@as(usize, 2), record.tags.len);
        try std.testing.expectEqualStrings("one", record.tags[0]);
        try std.testing.expectEqualStrings("two", record.tags[1]);
        try std.testing.expectEqual(@as(i32, -3), record.nested.alpha);
        try std.testing.expectEqualStrings("x", record.nested.beta);
    }
}

test "jzon behaviour: the generated parser reads what the other two paths read" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const from_std = try std_parser.parse(Record, allocator, DOCUMENT, .{});
    const from_scanner = try scanner_parser.parse(Record, allocator, DOCUMENT, .{});

    inline for (SHAPES) |shape| {
        const ours = try generated_parser.parse(Record, allocator, DOCUMENT, .{}, shape);

        try std.testing.expectEqual(from_std.id, ours.id);
        try std.testing.expectEqualStrings(from_std.name, ours.name);
        try std.testing.expectEqual(from_std.ratio, ours.ratio);
        try std.testing.expectEqual(from_std.status, ours.status);
        try std.testing.expectEqualStrings(from_scanner.tags[1], ours.tags[1]);
        try std.testing.expectEqual(from_scanner.nested.alpha, ours.nested.alpha);
        try std.testing.expectEqualStrings(from_scanner.nested.beta, ours.nested.beta);
    }
}

test "jzon behaviour: the generated parser reads each shape on its own" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    inline for (SHAPES) |shape| {
        try std.testing.expect(try generated_parser.parse(bool, allocator, "true", .{}, shape));
        try std.testing.expect(!(try generated_parser.parse(bool, allocator, "false", .{}, shape)));
        try std.testing.expectEqual(@as(u8, 255), try generated_parser.parse(u8, allocator, "255", .{}, shape));
        try std.testing.expectEqual(@as(i64, -9), try generated_parser.parse(i64, allocator, "-9", .{}, shape));
        try std.testing.expectEqual(@as(f64, 0.5), try generated_parser.parse(f64, allocator, "0.5", .{}, shape));
        try std.testing.expectEqual(Status.CANCELLED, try generated_parser.parse(Status, allocator, "\"CANCELLED\"", .{}, shape));
        try std.testing.expectEqualStrings("text", try generated_parser.parse([]const u8, allocator, "\"text\"", .{}, shape));

        const numbers = try generated_parser.parse([]const u32, allocator, "[1,2,3]", .{}, shape);
        try std.testing.expectEqual(@as(usize, 3), numbers.len);
        try std.testing.expectEqual(@as(u32, 3), numbers[2]);

        try std.testing.expect((try generated_parser.parse(?u8, allocator, "null", .{}, shape)) == null);
        try std.testing.expectEqual(@as(?u8, 9), try generated_parser.parse(?u8, allocator, "9", .{}, shape));
    }
}

test "jzon behaviour: the generated parser reads a document laid out with whitespace" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\  {
        \\    "alpha" : -3 ,
        \\    "beta"  : "a value long enough to fill one whole lane of bytes"
        \\  }
        \\
    ;

    inline for (SHAPES) |shape| {
        const nested = try generated_parser.parse(Nested, arena.allocator(), src, .{}, shape);

        try std.testing.expectEqual(@as(i32, -3), nested.alpha);
        try std.testing.expectEqualStrings("a value long enough to fill one whole lane of bytes", nested.beta);
    }
}

test "jzon behaviour: the generated parser gives an absent field its declared default" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const Defaults = struct {
        id: u32,
        status: Status = .PENDING,
        note: ?[]const u8 = null,
        retries: u8 = 3,
    };

    inline for (SHAPES) |shape| {
        const value = try generated_parser.parse(Defaults, arena.allocator(), "{\"id\":1}", .{}, shape);

        try std.testing.expectEqual(@as(u32, 1), value.id);
        try std.testing.expectEqual(Status.PENDING, value.status);
        try std.testing.expect(value.note == null);
        try std.testing.expectEqual(@as(u8, 3), value.retries);
    }
}

test "jzon behaviour: the generated parser borrows a clean string and copies an escaped one" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const src = "{\"alpha\":1,\"beta\":\"borrowed\"}";
    const escaped_src = "{\"alpha\":1,\"beta\":\"one\\ttwo\"}";

    inline for (SHAPES) |shape| {
        const borrowed = try generated_parser.parse(Nested, arena.allocator(), src, .{ .strings = .BORROW }, shape);

        try std.testing.expect(@intFromPtr(borrowed.beta.ptr) >= @intFromPtr(src.ptr));
        try std.testing.expect(@intFromPtr(borrowed.beta.ptr) < @intFromPtr(src.ptr) + src.len);

        const copied = try generated_parser.parse(Nested, arena.allocator(), src, .{ .strings = .COPY }, shape);

        try std.testing.expect(@intFromPtr(copied.beta.ptr) < @intFromPtr(src.ptr) or
            @intFromPtr(copied.beta.ptr) >= @intFromPtr(src.ptr) + src.len);
        try std.testing.expectEqualStrings("borrowed", copied.beta);

        // An escape has no undecoded home in the document, so it is copied even
        // when the caller asked to borrow.
        const decoded = try generated_parser.parse(Nested, arena.allocator(), escaped_src, .{ .strings = .BORROW }, shape);

        try std.testing.expectEqualStrings("one\ttwo", decoded.beta);
    }
}

test "jzon behaviour: the generated parser steps over an unknown key when asked to" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const src = "{\"alpha\":1,\"extra\":{\"deep\":[1,2,{\"a\":null}]},\"beta\":\"x\"}";

    inline for (SHAPES) |shape| {
        const nested = try generated_parser.parse(Nested, arena.allocator(), src, .{ .unknown = .SKIP }, shape);

        try std.testing.expectEqual(@as(i32, 1), nested.alpha);
        try std.testing.expectEqualStrings("x", nested.beta);
    }
}

test "jzon behaviour: the generated parser matches a key spelled with an escape" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    // A key is compared by its value, not by how the document spelled it, which
    // is what the other two paths do as well.
    const src = "{\"\\u0061lpha\":5,\"beta\":\"x\"}";

    inline for (SHAPES) |shape| {
        const ours = try generated_parser.parse(Nested, allocator, src, .{}, shape);

        try std.testing.expectEqual(@as(i32, 5), ours.alpha);
    }

    const theirs = try std_parser.parse(Nested, allocator, src, .{});
    try std.testing.expectEqual(@as(i32, 5), theirs.alpha);
}
