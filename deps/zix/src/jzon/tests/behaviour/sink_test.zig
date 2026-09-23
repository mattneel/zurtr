//! Behaviour tests: jzon.Sink, the contract a caller writes against.
//! Verifies the write forms land the same bytes, that the three position
//! readings stay in agreement, and that a reserved region is the caller's to fill.

const std = @import("std");
const jzon = @import("jzon");

const Sink = jzon.Sink;

// --------------------------------------------------------- //

test "jzon behaviour: sink writes land in call order" {
    var buf: [64]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.byte('{');
    try sink.literal("\"name\":");
    try sink.byte('"');
    try sink.bytes("zix");
    try sink.byte('"');
    try sink.byte('}');

    try std.testing.expectEqualStrings("{\"name\":\"zix\"}", sink.filled());
}

test "jzon behaviour: sink literal and bytes produce the same run" {
    var literal_buf: [16]u8 = undefined;
    var literal_sink: Sink = .init(&literal_buf);
    try literal_sink.literal("\"total\":");

    var bytes_buf: [16]u8 = undefined;
    var bytes_sink: Sink = .init(&bytes_buf);
    try bytes_sink.bytes("\"total\":");

    try std.testing.expectEqualStrings(literal_sink.filled(), bytes_sink.filled());
}

test "jzon behaviour: sink written, remaining and filled agree at every step" {
    var buf: [10]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std.testing.expectEqual(@as(usize, 0), sink.written());
    try std.testing.expectEqual(@as(usize, 10), sink.remaining());
    try std.testing.expectEqual(@as(usize, 0), sink.filled().len);

    try sink.bytes("abcd");

    try std.testing.expectEqual(@as(usize, 4), sink.written());
    try std.testing.expectEqual(@as(usize, 6), sink.remaining());
    try std.testing.expectEqual(sink.written(), sink.filled().len);
    try std.testing.expectEqual(buf.len, sink.written() + sink.remaining());
}

test "jzon behaviour: sink reserve hands over exactly the room asked for" {
    var buf: [16]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.byte('[');

    const region = try sink.reserve(5);
    try std.testing.expectEqual(@as(usize, 5), region.len);
    @memcpy(region, "12345");

    try sink.byte(']');

    try std.testing.expectEqualStrings("[12345]", sink.filled());
}

test "jzon behaviour: sink tail and commit carry a foreign writer's output" {
    var buf: [32]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.literal("id=");

    const printed = try std.fmt.bufPrint(sink.tail(), "{d}", .{987654});
    try sink.commit(printed.len);

    try std.testing.expectEqualStrings("id=987654", sink.filled());
    try std.testing.expectEqual(@as(usize, 9), sink.written());
}

test "jzon behaviour: sink reset makes the buffer reusable" {
    var buf: [16]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.bytes("first pass");
    try std.testing.expectEqual(@as(usize, 10), sink.written());

    sink.reset();

    try std.testing.expectEqual(@as(usize, 0), sink.written());
    try std.testing.expectEqual(buf.len, sink.remaining());

    try sink.bytes("second");
    try std.testing.expectEqualStrings("second", sink.filled());
}
