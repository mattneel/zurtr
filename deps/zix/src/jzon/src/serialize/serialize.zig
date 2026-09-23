//! jzon serialize.
//!
//! What:
//! - The one call that turns a typed value into JSON text. It runs the write
//!   path the options name over the caller's buffer and reports how many bytes
//!   the value took.
//! - Nothing is allocated. The buffer belongs to the caller, so a handler can
//!   render straight into the send buffer an engine hands it.
//!
//! Note:
//! - Every strategy writes the same bytes for the same value, so swapping one
//!   for another changes what it costs and nothing else.
//! - A value that does not fit is `error.NoSpaceLeft` and no length. What the
//!   buffer holds afterwards differs by path, the std-backed one leaves it as it
//!   found it and a generated one leaves the prefix that fit, so neither result
//!   is a rendered value either way.

const std = @import("std");

const generated_emitter = @import("generated_emitter.zig");
const options_mod = @import("options.zig");
const std_emitter = @import("std_emitter.zig");
const Sink = @import("../sink.zig").Sink;

/// Which write path a render runs.
pub const Strategy = options_mod.Strategy;

/// The options a render runs with.
pub const Options = options_mod.Options;

/// How a render can fail.
pub const Error = options_mod.Error;

/// Render `value` as JSON into `buf`.
///
/// Note:
/// - The strategy is comptime, so only the path it names is compiled in. A shape
///   the generated paths refuse still renders under the default one.
///
/// Param:
/// buf - []u8 (where the JSON text goes, caller owned)
/// value - anytype (the value to render)
/// options - Options (comptime, which write path runs)
///
/// Usage:
/// ```zig
/// var buf: [64 * 1024]u8 = undefined;
///
/// const len = try jzon.serialize(&buf, order, .{});
/// const faster = try jzon.serialize(&buf, order, .{ .strategy = .GENERATED });
/// ```
///
/// Return:
/// - usize (how many bytes of `buf` the value took)
/// - error.NoSpaceLeft when the rendered form does not fit
pub fn serialize(buf: []u8, value: anytype, comptime options: Options) Error!usize {
    var sink: Sink = .init(buf);

    switch (options.strategy) {
        .STD => try std_emitter.emit(&sink, value),
        .GENERATED_FMT => try generated_emitter.emit(&sink, value, .{ .numbers = .FMT, .escapes = .SCALAR }),
        .GENERATED => try generated_emitter.emit(&sink, value, .{ .numbers = .TABLE, .escapes = .SCALAR }),
        .GENERATED_VECTOR => try generated_emitter.emit(&sink, value, .{ .numbers = .TABLE, .escapes = .VECTOR }),
    }

    return sink.written();
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Every strategy, so a case can assert all of them at once.
const STRATEGIES = [_]Strategy{ .STD, .GENERATED_FMT, .GENERATED, .GENERATED_VECTOR };

const Status = enum { PENDING, SHIPPED };

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

const RENDERED =
    "{\"id\":7,\"name\":\"a\\\"b\",\"ratio\":2.5,\"active\":true," ++
    "\"status\":\"SHIPPED\",\"note\":null,\"tags\":[\"one\",\"two\"]," ++
    "\"nested\":{\"alpha\":-3,\"beta\":\"x\"}}";

test "jzon: serialize renders a record through every strategy" {
    inline for (STRATEGIES) |strategy| {
        var buf: [512]u8 = undefined;
        const len = try serialize(&buf, RECORD, .{ .strategy = strategy });

        try std.testing.expectEqualStrings(RENDERED, buf[0..len]);
    }
}

test "jzon: serialize returns the length of what it wrote" {
    var buf: [64]u8 = undefined;

    try std.testing.expectEqual(@as(usize, 4), try serialize(&buf, true, .{}));
    try std.testing.expectEqual(@as(usize, 2), try serialize(&buf, @as([]const u8, ""), .{}));
    try std.testing.expectEqual(@as(usize, 7), try serialize(&buf, @as([]const u32, &.{ 1, 2, 3 }), .{}));
}

test "jzon: serialize reports a buffer the value does not fit in" {
    inline for (STRATEGIES) |strategy| {
        var buf: [8]u8 = undefined;

        try std.testing.expectError(error.NoSpaceLeft, serialize(&buf, RECORD, .{ .strategy = strategy }));
    }
}

test "jzon: serialize renders a shape the generated paths refuse" {
    // A tuple has no object form, so only the default path takes it. That is the
    // whole reason the default is the std-backed one.
    var buf: [32]u8 = undefined;
    const len = try serialize(&buf, .{ @as(u8, 1), true }, .{});

    try std.testing.expectEqualStrings("[1,true]", buf[0..len]);
}
