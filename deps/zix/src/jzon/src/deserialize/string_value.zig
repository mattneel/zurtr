//! jzon deserialize strings.
//!
//! What:
//! - Turns a bounded string token into the bytes a parse hands back: a slice of
//!   the document itself when it may be borrowed, bytes in the allocator
//!   otherwise.
//! - Every generated parser makes the same decision about every string it
//!   reads, so it is made here once rather than once per parser.
//!
//! Note:
//! - A token carrying an escape is decoded into the allocator whichever string
//!   mode was asked for, because its decoded bytes appear nowhere in the
//!   document to point at.
//! - The decoded form is never longer than the undecoded one: every escape
//!   spells more bytes than the character it stands for. So the room taken is
//!   the undecoded length and the slack is handed straight back.

const std = @import("std");

const cursor_mod = @import("../cursor.zig");
const escape = @import("../escape.zig");
const Sink = @import("../sink.zig").Sink;

const Allocator = std.mem.Allocator;
const StringSpan = cursor_mod.StringSpan;

/// How taking a string can fail.
pub const Error = @import("options.zig").Error;

/// The options a parse runs with.
pub const Options = @import("options.zig").Options;

/// The value of one string token.
///
/// Param:
/// allocator - Allocator (owns any bytes that are not the document's own)
/// span - StringSpan (the token's undecoded body, as a read cursor bounds it)
/// options - Options (comptime, which string mode the parse runs in)
///
/// Return:
/// - []const u8 (the string's value, pointing into the document only under
///   `strings = .BORROW` and only when the token carried no escape)
/// - error.JzonBadEscape when the token holds an escape the rules do not spell
/// - error.OutOfMemory when the allocator runs out
pub fn take(allocator: Allocator, span: StringSpan, comptime options: Options) Error![]const u8 {
    if (span.escaped) return decode(allocator, span.raw);

    if (options.strings == .BORROW) return span.raw;

    return allocator.dupe(u8, span.raw);
}

/// Write a token's decoded bytes into the allocator.
///
/// Note:
/// - Room for the undecoded length always holds the decoded form, so the sink
///   cannot run out. The branch is still mapped rather than asserted, so a
///   future escape form that grew could never write past the room it was given.
fn decode(allocator: Allocator, raw: []const u8) Error![]const u8 {
    const room = try allocator.alloc(u8, raw.len);
    var sink: Sink = .init(room);

    escape.decode(&sink, raw) catch |failure| return switch (failure) {
        error.JzonBadEscape => error.JzonBadEscape,
        error.NoSpaceLeft => error.JzonUnexpected,
    };

    const decoded = sink.written();
    _ = allocator.resize(room, decoded);

    return room[0..decoded];
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Whether `text` points inside `document`.
fn pointsInto(text: []const u8, document: []const u8) bool {
    return @intFromPtr(text.ptr) >= @intFromPtr(document.ptr) and
        @intFromPtr(text.ptr) < @intFromPtr(document.ptr) + document.len;
}

test "jzon: a borrowed clean string is the document's own bytes" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const document = "borrowed";
    const span: StringSpan = .{ .raw = document, .escaped = false };

    const taken = try take(arena.allocator(), span, .{ .strings = .BORROW });

    try std.testing.expectEqualStrings("borrowed", taken);
    try std.testing.expect(pointsInto(taken, document));
}

test "jzon: a copied clean string leaves the document behind" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const document = "copied";
    const span: StringSpan = .{ .raw = document, .escaped = false };

    const taken = try take(arena.allocator(), span, .{ .strings = .COPY });

    try std.testing.expectEqualStrings("copied", taken);
    try std.testing.expect(!pointsInto(taken, document));
}

test "jzon: an escaped string is decoded in either mode" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const document = "one\\ttwo";
    const span: StringSpan = .{ .raw = document, .escaped = true };

    const borrowed = try take(arena.allocator(), span, .{ .strings = .BORROW });
    const copied = try take(arena.allocator(), span, .{ .strings = .COPY });

    try std.testing.expectEqualStrings("one\ttwo", borrowed);
    try std.testing.expectEqualStrings("one\ttwo", copied);
    try std.testing.expect(!pointsInto(borrowed, document));
}

test "jzon: a decoded string is exactly as long as its value" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const span: StringSpan = .{ .raw = "\\ud83d\\udca9", .escaped = true };

    const taken = try take(arena.allocator(), span, .{});

    try std.testing.expectEqualStrings("\xf0\x9f\x92\xa9", taken);
    try std.testing.expectEqual(@as(usize, 4), taken.len);
}

test "jzon: a string carrying an escape the rules do not spell is refused" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    try std.testing.expectError(error.JzonBadEscape, take(allocator, .{ .raw = "\\q", .escaped = true }, .{}));
    try std.testing.expectError(error.JzonBadEscape, take(allocator, .{ .raw = "\\ud83d", .escaped = true }, .{}));
    try std.testing.expectError(error.JzonBadEscape, take(allocator, .{ .raw = "\\u00zz", .escaped = true }, .{}));
}
