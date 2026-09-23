//! jzon deserialize diagnostic: which field and which byte the last parse stopped on

const std = @import("std");

/// What the last failed parse on this thread was about.
///
/// Note:
/// - An error value has nowhere to put a field name or an offset, so a caller who receives
///   JzonUnknownField learns that a field was wrong and not which one. This is where that goes.
/// - It is a side channel, so a caller who reads only the error value still learns nothing. Every
///   error it can explain names it in its own doc comment.
pub const Failure = struct {
    /// The field the failure is about, empty when the failure is not about a field.
    field: []const u8 = "",
    /// Byte offset into the source where the parse stopped, or 0 when the path cannot report one.
    /// The std-backed path never reports an offset, because std does not surface its scanner's.
    offset: usize = 0,
    /// False until a parse has failed on this thread.
    filled: bool = false,
};

/// Per-thread, because a parse never crosses threads: it is one call over one buffer. The next
/// failure on the same thread replaces it, which is what makes it safe to read only right after a
/// parse returned an error.
threadlocal var last: Failure = .{};

/// What the last failed parse on this thread was about.
///
/// Note:
/// - Read it immediately after a parse returned an error. A later parse overwrites it, and a
///   successful parse leaves whatever the previous failure wrote.
///
/// Usage:
/// ```zig
/// const record = jzon.deserialize(Order, allocator, body, .{}) catch |err| {
///     const why = jzon.lastFailure();
///     std.log.err("{s} at byte {d}: {s}", .{ @errorName(err), why.offset, why.field });
///
///     return err;
/// };
/// ```
///
/// Return:
/// - Failure, with filled false when nothing has failed on this thread yet
pub fn lastFailure() Failure {
    return last;
}

/// Record that the failure about to be returned is about this field.
///
/// Param:
/// field - []const u8 (the field name, borrowed from the source or from reflection)
pub fn noteField(field: []const u8) void {
    last = .{ .field = field, .offset = 0, .filled = true };
}

/// Record that the failure about to be returned stopped at this byte.
///
/// Param:
/// offset - usize (byte offset into the source)
pub fn noteOffset(offset: usize) void {
    last = .{ .field = "", .offset = offset, .filled = true };
}

/// Record both, for a failure that knows the field and where it was reading.
pub fn noteFieldAt(field: []const u8, offset: usize) void {
    last = .{ .field = field, .offset = offset, .filled = true };
}

/// Forget the last failure, so a test or a long-lived worker does not read a stale one.
pub fn reset() void {
    last = .{};
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "jzon: diagnostic starts unfilled" {
    reset();

    const why = lastFailure();
    try std.testing.expect(!why.filled);
    try std.testing.expectEqual(@as(usize, 0), why.offset);
    try std.testing.expectEqualStrings("", why.field);
}

test "jzon: diagnostic carries the field a failure was about" {
    reset();
    noteField("customer");

    const why = lastFailure();
    try std.testing.expect(why.filled);
    try std.testing.expectEqualStrings("customer", why.field);
}

test "jzon: diagnostic carries the byte a failure stopped on" {
    reset();
    noteOffset(42);

    const why = lastFailure();
    try std.testing.expect(why.filled);
    try std.testing.expectEqual(@as(usize, 42), why.offset);
    try std.testing.expectEqualStrings("", why.field);
}

test "jzon: diagnostic carries both when the path knows both" {
    reset();
    noteFieldAt("status", 17);

    const why = lastFailure();
    try std.testing.expectEqualStrings("status", why.field);
    try std.testing.expectEqual(@as(usize, 17), why.offset);
}

test "jzon: the newest failure replaces the one before it" {
    reset();
    noteField("first");
    noteOffset(9);

    const why = lastFailure();
    try std.testing.expectEqualStrings("", why.field);
    try std.testing.expectEqual(@as(usize, 9), why.offset);
}
