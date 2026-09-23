//! Edge tests: jzon.Sink at its bounds.
//! Verifies the exact-fit and one-byte-short cases for every write form, the
//! zero-length buffer, and that a rejected write leaves the cursor where it was.

const std = @import("std");
const jzon = @import("jzon");

const Sink = jzon.Sink;

// --------------------------------------------------------- //

test "jzon edge: sink accepts a write that fits exactly" {
    var buf: [5]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.bytes("hello");

    try std.testing.expectEqualStrings("hello", sink.filled());
    try std.testing.expectEqual(@as(usize, 0), sink.remaining());
}

test "jzon edge: sink refuses a write one byte past the end" {
    var buf: [4]u8 = undefined;

    var by_bytes: Sink = .init(&buf);
    try std.testing.expectError(error.NoSpaceLeft, by_bytes.bytes("hello"));

    var by_literal: Sink = .init(&buf);
    try std.testing.expectError(error.NoSpaceLeft, by_literal.literal("hello"));

    var by_byte: Sink = .init(&buf);
    try by_byte.bytes("abcd");
    try std.testing.expectError(error.NoSpaceLeft, by_byte.byte('e'));
}

test "jzon edge: sink over a zero-length buffer takes nothing but an empty run" {
    var buf: [0]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.bytes("");
    try sink.literal("");

    try std.testing.expectError(error.NoSpaceLeft, sink.byte('x'));
    try std.testing.expectEqual(@as(usize, 0), sink.written());
    try std.testing.expectEqual(@as(usize, 0), sink.filled().len);
}

test "jzon edge: sink leaves the position untouched when a write is refused" {
    var buf: [8]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.bytes("abcdef");
    const before = sink.written();

    try std.testing.expectError(error.NoSpaceLeft, sink.bytes("ghi"));
    try std.testing.expectEqual(before, sink.written());

    try sink.bytes("gh");
    try std.testing.expectEqualStrings("abcdefgh", sink.filled());
}

test "jzon edge: sink reserve at the bounds" {
    var buf: [4]u8 = undefined;

    var empty: Sink = .init(&buf);
    const nothing = try empty.reserve(0);
    try std.testing.expectEqual(@as(usize, 0), nothing.len);
    try std.testing.expectEqual(@as(usize, 0), empty.written());

    var exact: Sink = .init(&buf);
    const whole = try exact.reserve(4);
    try std.testing.expectEqual(@as(usize, 4), whole.len);
    try std.testing.expectEqual(@as(usize, 0), exact.remaining());

    var past: Sink = .init(&buf);
    try std.testing.expectError(error.NoSpaceLeft, past.reserve(5));
    try std.testing.expectEqual(@as(usize, 0), past.written());
}

test "jzon edge: sink commit past the end is refused" {
    var buf: [4]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.byte('a');

    try std.testing.expectError(error.NoSpaceLeft, sink.commit(4));
    try std.testing.expectEqual(@as(usize, 1), sink.written());

    try sink.commit(3);
    try std.testing.expectEqual(@as(usize, 0), sink.remaining());
}

test "jzon edge: sink tail shrinks as the buffer fills and empties at the end" {
    var buf: [4]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std.testing.expectEqual(@as(usize, 4), sink.tail().len);

    try sink.bytes("ab");
    try std.testing.expectEqual(@as(usize, 2), sink.tail().len);

    try sink.bytes("cd");
    try std.testing.expectEqual(@as(usize, 0), sink.tail().len);
}
