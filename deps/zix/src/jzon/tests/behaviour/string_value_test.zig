//! Behaviour tests: jzon.string_value, the bytes a parse hands back for one
//! string token. Verifies the borrow and copy modes differ only in where the
//! bytes live, and that an escaped token is decoded in both.

const std = @import("std");
const jzon = @import("jzon");

const StringSpan = jzon.StringSpan;
const string_value = jzon.string_value;

/// Whether `text` points inside `document`.
fn pointsInto(text: []const u8, document: []const u8) bool {
    return @intFromPtr(text.ptr) >= @intFromPtr(document.ptr) and
        @intFromPtr(text.ptr) < @intFromPtr(document.ptr) + document.len;
}

test "jzon behaviour: a borrowed clean token is the document's own bytes" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const document = "no escape in here";
    const span: StringSpan = .{ .raw = document, .escaped = false };

    const taken = try string_value.take(arena.allocator(), span, .{ .strings = .BORROW });

    try std.testing.expectEqualStrings(document, taken);
    try std.testing.expect(pointsInto(taken, document));
}

test "jzon behaviour: a copied clean token stops depending on the document" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const document = "no escape in here";
    const span: StringSpan = .{ .raw = document, .escaped = false };

    const taken = try string_value.take(arena.allocator(), span, .{ .strings = .COPY });

    try std.testing.expectEqualStrings(document, taken);
    try std.testing.expect(!pointsInto(taken, document));
}

test "jzon behaviour: copy is what a parse does unless it is told otherwise" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const document = "left alone";
    const span: StringSpan = .{ .raw = document, .escaped = false };

    const taken = try string_value.take(arena.allocator(), span, .{});

    try std.testing.expect(!pointsInto(taken, document));
}

test "jzon behaviour: an escaped token is decoded whichever mode is asked for" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const document = "line\\nbreak\\ttab";
    const span: StringSpan = .{ .raw = document, .escaped = true };

    const borrowed = try string_value.take(arena.allocator(), span, .{ .strings = .BORROW });
    const copied = try string_value.take(arena.allocator(), span, .{ .strings = .COPY });

    try std.testing.expectEqualStrings("line\nbreak\ttab", borrowed);
    try std.testing.expectEqualStrings("line\nbreak\ttab", copied);
    try std.testing.expect(!pointsInto(borrowed, document));
}

test "jzon behaviour: every escape the rules spell is read back" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const Case = struct {
        raw: []const u8,
        value: []const u8,
    };

    const cases = [_]Case{
        .{ .raw = "\\\"", .value = "\"" },
        .{ .raw = "\\\\", .value = "\\" },
        .{ .raw = "\\/", .value = "/" },
        .{ .raw = "\\b", .value = "\x08" },
        .{ .raw = "\\f", .value = "\x0c" },
        .{ .raw = "\\n", .value = "\n" },
        .{ .raw = "\\r", .value = "\r" },
        .{ .raw = "\\t", .value = "\t" },
        .{ .raw = "\\u0041", .value = "A" },
        .{ .raw = "\\u00e9", .value = "\xc3\xa9" },
        .{ .raw = "\\ud83d\\udca9", .value = "\xf0\x9f\x92\xa9" },
    };

    for (cases) |case| {
        const taken = try string_value.take(allocator, .{ .raw = case.raw, .escaped = true }, .{});

        try std.testing.expectEqualStrings(case.value, taken);
    }
}

test "jzon behaviour: a decoded token is exactly as long as its value" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const taken = try string_value.take(
        arena.allocator(),
        .{ .raw = "\\n\\n\\n", .escaped = true },
        .{},
    );

    try std.testing.expectEqual(@as(usize, 3), taken.len);
    try std.testing.expectEqualStrings("\n\n\n", taken);
}
