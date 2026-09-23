//! jzon serialize, the std-backed path.
//!
//! What:
//! - Renders a value through `std.json.Stringify` into a caller-owned buffer.
//!   This is the capable path: it takes every shape std takes, including the
//!   ones the generated emitter refuses at compile time.
//!
//! Note:
//! - Nothing is allocated. std writes into the sink's unwritten tail through a
//!   fixed writer, and the sink only advances once the whole value has landed, so
//!   a value too large for the buffer leaves the sink exactly as it was. That is
//!   stricter than the generated emitter, which writes as it goes.

const std = @import("std");

const Sink = @import("../sink.zig").Sink;

/// How rendering can fail. Nothing is allocated, so a full buffer is all of it.
pub const Error = @import("../sink.zig").Error;

/// Render `value` as JSON.
///
/// Param:
/// sink - *Sink (where the JSON text goes)
/// value - anytype (any shape std.json.Stringify renders)
///
/// Return:
/// - void
/// - error.NoSpaceLeft when the rendered form does not fit
pub fn emit(sink: *Sink, value: anytype) Error!void {
    var writer = std.Io.Writer.fixed(sink.tail());

    std.json.Stringify.value(value, .{}, &writer) catch return error.NoSpaceLeft;

    try sink.commit(writer.buffered().len);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const Nested = struct {
    alpha: i32,
    beta: []const u8,
};

const Status = enum { PENDING, SHIPPED };

const Record = struct {
    id: u64,
    name: []const u8,
    ratio: f64,
    active: bool,
    status: Status,
    note: ?[]const u8,
    tags: []const []const u8,
    nested: Nested,
};

const RECORD: Record = .{
    .id = 7,
    .name = "a\"b",
    .ratio = 2.5,
    .active = true,
    .status = .SHIPPED,
    .note = null,
    .tags = &.{ "one", "two" },
    .nested = .{ .alpha = -3, .beta = "x" },
};

test "jzon: std emitter renders a whole record" {
    var buf: [512]u8 = undefined;
    var sink: Sink = .init(&buf);

    try emit(&sink, RECORD);

    try std.testing.expectEqualStrings(
        "{\"id\":7,\"name\":\"a\\\"b\",\"ratio\":2.5,\"active\":true," ++
            "\"status\":\"SHIPPED\",\"note\":null,\"tags\":[\"one\",\"two\"]," ++
            "\"nested\":{\"alpha\":-3,\"beta\":\"x\"}}",
        sink.filled(),
    );
}

test "jzon: std emitter writes after what the sink already holds" {
    var buf: [64]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.literal("{\"body\":");
    try emit(&sink, @as(u32, 42));
    try sink.byte('}');

    try std.testing.expectEqualStrings("{\"body\":42}", sink.filled());
}

test "jzon: std emitter leaves the sink untouched when the value does not fit" {
    var buf: [16]u8 = undefined;
    var sink: Sink = .init(&buf);

    try sink.literal("[");
    try std.testing.expectError(error.NoSpaceLeft, emit(&sink, RECORD));

    try std.testing.expectEqualStrings("[", sink.filled());
}
