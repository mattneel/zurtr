//! Edge tests: jzon.string_value at the boundaries.
//! Covers the empty token, a token that is nothing but escapes, escapes the
//! rules do not spell, and an allocator that has nothing left to give.

const std = @import("std");
const jzon = @import("jzon");

const StringSpan = jzon.StringSpan;
const string_value = jzon.string_value;

test "jzon edge: an empty token comes back empty in either mode" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const span: StringSpan = .{ .raw = "", .escaped = false };

    const borrowed = try string_value.take(allocator, span, .{ .strings = .BORROW });
    const copied = try string_value.take(allocator, span, .{ .strings = .COPY });

    try std.testing.expectEqual(@as(usize, 0), borrowed.len);
    try std.testing.expectEqual(@as(usize, 0), copied.len);
}

test "jzon edge: a token that is nothing but escapes decodes to its value alone" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const taken = try string_value.take(
        arena.allocator(),
        .{ .raw = "\\u0000\\u001f\\u007f", .escaped = true },
        .{},
    );

    try std.testing.expectEqualStrings("\x00\x1f\x7f", taken);
}

test "jzon edge: an escape the rules do not spell is refused" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const broken = [_][]const u8{
        "\\",
        "\\q",
        "\\u",
        "\\u00",
        "\\u00zz",
        "\\ud83d",
        "\\udca9",
        "\\ud83d\\u0041",
    };

    for (broken) |raw| {
        try std.testing.expectError(
            error.JzonBadEscape,
            string_value.take(allocator, .{ .raw = raw, .escaped = true }, .{}),
        );
    }
}

test "jzon edge: a token flagged escaped that holds none comes back unchanged" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // A read cursor never produces this pairing, but decoding a clean body has
    // to be the body itself rather than a failure.
    const taken = try string_value.take(
        arena.allocator(),
        .{ .raw = "plain", .escaped = true },
        .{ .strings = .BORROW },
    );

    try std.testing.expectEqualStrings("plain", taken);
}

test "jzon edge: a copy reports an allocator with nothing left" {
    var failing: std.testing.FailingAllocator = .init(std.testing.allocator, .{ .fail_index = 0 });

    const allocator = failing.allocator();

    try std.testing.expectError(
        error.OutOfMemory,
        string_value.take(allocator, .{ .raw = "copied", .escaped = false }, .{ .strings = .COPY }),
    );

    try std.testing.expectError(
        error.OutOfMemory,
        string_value.take(allocator, .{ .raw = "one\\ttwo", .escaped = true }, .{}),
    );
}

test "jzon edge: a borrow of a clean token asks the allocator for nothing" {
    var failing: std.testing.FailingAllocator = .init(std.testing.allocator, .{ .fail_index = 0 });

    const document = "borrowed";

    const taken = try string_value.take(
        failing.allocator(),
        .{ .raw = document, .escaped = false },
        .{ .strings = .BORROW },
    );

    try std.testing.expectEqualStrings(document, taken);
    try std.testing.expectEqual(@as(usize, 0), failing.allocations);
}

test "jzon edge: a token as long as its decoded value keeps every byte" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    // Four hex digits become up to three UTF-8 bytes, so the escape is always
    // the longer spelling and the room taken always holds the result.
    const taken = try string_value.take(
        arena.allocator(),
        .{ .raw = "\\uffff", .escaped = true },
        .{},
    );

    try std.testing.expectEqualStrings("\xef\xbf\xbf", taken);
}
