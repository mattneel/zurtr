//! jzon serialize, the emitter generated from the type.
//!
//! What:
//! - Turns a typed value into JSON with the shape of the type resolved at compile
//!   time. Every object key, its quotes, its colon and the comma before it are
//!   baked into one literal, so a field costs one fixed-size copy plus its value.
//! - Two axes are picked by the caller: how integers reach the buffer, and how
//!   strings are scanned for the bytes that need escaping. They are independent,
//!   so every pairing is available.
//!
//! Note:
//! - The output matches `std.json.Stringify` byte for byte, whichever pairing is
//!   chosen. That is what makes a strategy a cost decision and nothing else.
//! - A field type with no JSON form is a compile error naming the type. It is
//!   never a runtime failure, and the std-backed path stays available for it.
//! - Writes land as they are produced, so a value that runs out of room leaves
//!   what fit behind. A caller that needs all-or-nothing keeps its own mark.

const std = @import("std");

const escape = @import("../escape.zig");
const escape_vector = @import("../escape_vector.zig");
const float = @import("../float.zig");
const integer = @import("../integer.zig");
const reflect = @import("../reflect.zig");
const Sink = @import("../sink.zig").Sink;

/// How rendering can fail. Nothing is allocated, so a full buffer is all of it.
pub const Error = @import("../sink.zig").Error;

/// How an integer reaches the buffer.
pub const NumberPath = enum {
    /// Through `std.fmt`, which builds a writer per value.
    FMT,
    /// Digits written straight into the sink.
    TABLE,
};

/// How a string is scanned for the bytes that need escaping.
pub const EscapePath = enum {
    /// One byte at a time.
    SCALAR,
    /// One vector lane at a time, which pays on long strings only.
    VECTOR,
};

/// The pairing an emitter runs with.
pub const Shape = struct {
    numbers: NumberPath = .TABLE,
    escapes: EscapePath = .SCALAR,
};

/// Render `value` as JSON.
///
/// Note:
/// - Recursive over the type, not over any runtime shape, so a nested struct or a
///   slice of them costs nothing at runtime beyond its own bytes.
///
/// Param:
/// sink - *Sink (where the JSON text goes)
/// value - anytype (bool, any integer or float width, a string, a slice, an
///   optional, an exhaustive enum, or a struct of those)
/// shape - Shape (comptime, which integer path and which escape scan to run)
///
/// Return:
/// - void
/// - error.NoSpaceLeft when the rendered form does not fit
pub fn emit(sink: *Sink, value: anytype, comptime shape: Shape) Error!void {
    const Value = @TypeOf(value);

    switch (@typeInfo(Value)) {
        .bool => {
            if (value) return sink.literal("true");

            return sink.literal("false");
        },

        .int => switch (shape.numbers) {
            .FMT => try integer.appendFmt(sink, value),
            .TABLE => try integer.appendTable(sink, value),
        },

        .float => try float.append(sink, value),

        .optional => {
            if (value) |payload| return emit(sink, payload, shape);

            try sink.literal("null");
        },

        .@"enum" => {
            if (!reflect.isExhaustive(Value)) @compileError(
                "jzon emitter: " ++ @typeName(Value) ++
                    " is non-exhaustive, so a value it carries may have no tag name",
            );

            try emitString(sink, @tagName(value), shape);
        },

        .@"struct" => |info| {
            if (info.is_tuple) @compileError(
                "jzon emitter: " ++ @typeName(Value) ++ " is a tuple, which has no object form",
            );

            try emitStruct(sink, value, shape);
        },

        .pointer => |info| {
            if (info.size != .slice) @compileError(
                "jzon emitter: " ++ @typeName(Value) ++ " is not a slice, so it has no JSON form",
            );

            if (info.child == u8) return emitString(sink, value, shape);

            try emitSlice(sink, value, shape);
        },

        else => @compileError("jzon emitter: " ++ @typeName(Value) ++ " has no JSON form"),
    }
}

/// Render a struct as a JSON object, fields in declaration order.
fn emitStruct(sink: *Sink, value: anytype, comptime shape: Shape) Error!void {
    try sink.byte('{');

    inline for (comptime std.meta.fieldNames(@TypeOf(value)), 0..) |name, index| {
        try sink.literal(comptime fieldKey(name, index == 0));
        try emit(sink, @field(value, name), shape);
    }

    try sink.byte('}');
}

/// Render a slice as a JSON array.
fn emitSlice(sink: *Sink, values: anytype, comptime shape: Shape) Error!void {
    try sink.byte('[');

    for (values, 0..) |element, index| {
        if (index != 0) try sink.byte(',');

        try emit(sink, element, shape);
    }

    try sink.byte(']');
}

/// Render a string through whichever escape scan the shape asked for.
fn emitString(sink: *Sink, text: []const u8, comptime shape: Shape) Error!void {
    switch (shape.escapes) {
        .SCALAR => try escape.encode(sink, text),
        .VECTOR => try escape_vector.encode(sink, text),
    }
}

/// The whole punctuation of one object key, as one literal.
///
/// Note:
/// - Everything a field name costs at runtime is this one copy: the comma when it
///   is not the first field, the quotes, the escaped name and the colon.
/// - The name is escaped here, at compile time, so a field spelled with a quote
///   or a control byte still matches what std would write for it. An ordinary
///   name escapes to itself and the escape costs nothing at runtime.
///
/// Param:
/// name - []const u8 (comptime, the field name)
/// first - bool (comptime, whether this is the object's first field)
///
/// Return:
/// - []const u8 (the literal to copy in ahead of the value)
fn fieldKey(comptime name: []const u8, comptime first: bool) []const u8 {
    comptime {
        // Six is the longest escape any one byte takes, plus room for the comma,
        // both quotes and the colon.
        var buf: [name.len * 6 + 4]u8 = undefined;
        var sink: Sink = .init(&buf);

        sink.literal(if (first) "\"" else ",\"") catch unreachable;
        escape.encodeBody(&sink, name) catch unreachable;
        sink.literal("\":") catch unreachable;

        const final = buf[0..sink.written()].*;

        return &final;
    }
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const std_emitter = @import("std_emitter.zig");

/// Every pairing of the two axes, so a case can assert all of them at once.
const SHAPES = [_]Shape{
    .{ .numbers = .FMT, .escapes = .SCALAR },
    .{ .numbers = .FMT, .escapes = .VECTOR },
    .{ .numbers = .TABLE, .escapes = .SCALAR },
    .{ .numbers = .TABLE, .escapes = .VECTOR },
};

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

/// Render one value under every pairing and assert all four agree with std.
fn expectAgreesWithStd(value: anytype) !void {
    var expected_buf: [4096]u8 = undefined;
    var expected: Sink = .init(&expected_buf);
    try std_emitter.emit(&expected, value);

    inline for (SHAPES) |shape| {
        var ours: [4096]u8 = undefined;
        var sink: Sink = .init(&ours);
        try emit(&sink, value, shape);

        try std.testing.expectEqualStrings(expected.filled(), sink.filled());
    }
}

test "jzon: generated emitter renders a whole record" {
    var buf: [512]u8 = undefined;
    var sink: Sink = .init(&buf);

    try emit(&sink, RECORD, .{});

    try std.testing.expectEqualStrings(
        "{\"id\":7,\"name\":\"a\\\"b\",\"ratio\":2.5,\"active\":true," ++
            "\"status\":\"SHIPPED\",\"note\":null,\"tags\":[\"one\",\"two\"]," ++
            "\"nested\":{\"alpha\":-3,\"beta\":\"x\"}}",
        sink.filled(),
    );
}

test "jzon: every number and escape pairing renders the same bytes" {
    try expectAgreesWithStd(RECORD);
}

test "jzon: generated emitter agrees with std on each shape on its own" {
    try expectAgreesWithStd(true);
    try expectAgreesWithStd(false);
    try expectAgreesWithStd(@as(u8, 255));
    try expectAgreesWithStd(@as(i64, -9223372036854775808));
    try expectAgreesWithStd(@as(f64, 0.1));
    try expectAgreesWithStd(@as([]const u8, "text \" with \n escapes"));
    try expectAgreesWithStd(@as([]const u32, &.{ 1, 2, 3 }));
    try expectAgreesWithStd(@as(?u8, null));
    try expectAgreesWithStd(@as(?u8, 9));
    try expectAgreesWithStd(Status.PENDING);
    try expectAgreesWithStd(Nested{ .alpha = 0, .beta = "" });
}

test "jzon: generated emitter renders an empty slice and an empty struct" {
    const Empty = struct {};

    var buf: [64]u8 = undefined;
    var sink: Sink = .init(&buf);

    try emit(&sink, Empty{}, .{});
    try emit(&sink, @as([]const u8, ""), .{});
    try emit(&sink, @as([]const u32, &.{}), .{});

    try std.testing.expectEqualStrings("{}\"\"[]", sink.filled());
}

test "jzon: generated emitter reports a buffer the value does not fit in" {
    var buf: [8]u8 = undefined;
    var sink: Sink = .init(&buf);

    try std.testing.expectError(error.NoSpaceLeft, emit(&sink, RECORD, .{}));

    // Writes land as they are produced, so the prefix that fit is still there.
    // The next key literal is one whole write, so none of it landed.
    try std.testing.expectEqualStrings("{\"id\":7", sink.filled());
}
