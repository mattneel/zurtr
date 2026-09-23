//! jzon deserialize, the parser generated from the type.
//!
//! What:
//! - Reads a document straight off jzon's own read cursor, with the shape of the
//!   target type resolved at compile time. Nothing reflects over the type while
//!   the parse runs, and no token is built that the type has no field for.
//! - One axis is picked by the caller: how many bytes a scan classifies at once.
//!   Both widths read the same documents and report the same failures.
//!
//! Note:
//! - Reads what the generated emitter writes, and refuses at compile time what
//!   the emitter refuses at compile time. A field type outside that set names
//!   itself in the error, and the std-backed path stays available for it.
//! - A slice of bytes is a string here and nothing else. std also fills a
//!   `[]const u8` from an array of numbers, which this path refuses, so the one
//!   spelling always means the one JSON form.
//! - Under `strings = .BORROW` a string with no escape in it is a slice of the
//!   document, so the document has to outlive the value. An escaped one is
//!   decoded into the allocator either way.
//! - Everything the result points at comes from the allocator handed in, so an
//!   arena reset frees a whole parse in one step.

const std = @import("std");
const diagnostic = @import("diagnostic.zig");

const cursor_mod = @import("../cursor.zig");
const fields = @import("fields.zig");
const float = @import("../float.zig");
const integer = @import("../integer.zig");
const reflect = @import("../reflect.zig");
const scan = @import("scan.zig");
const skip = @import("skip.zig");
const string_value = @import("string_value.zig");

const Allocator = std.mem.Allocator;
const Cursor = cursor_mod.Cursor;

/// How a parse can fail.
pub const Error = @import("options.zig").Error;

/// The options a parse runs with.
pub const Options = @import("options.zig").Options;

/// How many bytes a scan classifies at once.
pub const ScanPath = scan.ScanPath;

/// The width a parse runs with.
pub const Shape = scan.Shape;

/// The cursor, plus what turning a token into a value needs.
const Source = struct {
    allocator: Allocator,
    cursor: *Cursor,
};

/// The string mode a name is read under.
///
/// Note:
/// - A field name and an enum tag name are compared and then dropped, never
///   kept, so borrowing them costs nothing and saves a copy per key. What the
///   caller asked for governs the strings that end up in the result.
const NAME_OPTIONS: Options = .{ .strings = .BORROW };

/// Read a `T` out of a whole JSON document.
///
/// Note:
/// - The document has to hold one value and nothing after it, so trailing bytes
///   are a failure rather than something left unread.
///
/// Param:
/// T - type (comptime, the type to build)
/// allocator - Allocator (owns everything the result points at)
/// src - []const u8 (the whole document)
/// options - Options (comptime, how strings are held and what an unknown key does)
/// shape - Shape (comptime, which width to scan at)
///
/// Return:
/// - T (the parsed value)
/// - error.JzonUnknownField, error.JzonMissingField, error.JzonUnknownEnumValue when the
///   document and the type disagree
/// - error.JzonTruncated, error.JzonUnexpected, error.JzonBadNumber, error.JzonBadEscape when
///   the document is not what it claims
/// - error.OutOfMemory when the allocator runs out
pub fn parse(
    comptime T: type,
    allocator: Allocator,
    src: []const u8,
    comptime options: Options,
    comptime shape: Shape,
) Error!T {
    var cursor: Cursor = .init(src);

    const source: Source = .{ .allocator = allocator, .cursor = &cursor };

    const value = try readValue(T, source, options, shape);

    scan.skipSpace(&cursor, shape);
    if (!cursor.atEnd()) return error.JzonUnexpected;

    return value;
}

/// Read one value of `T`, whatever shape the type is.
fn readValue(comptime T: type, source: Source, comptime options: Options, comptime shape: Shape) Error!T {
    switch (@typeInfo(T)) {
        .bool => return readBool(source.cursor, shape),

        .int => {
            scan.skipSpace(source.cursor, shape);

            return integer.parse(T, try source.cursor.numberSpan());
        },

        .float => {
            scan.skipSpace(source.cursor, shape);

            return float.parse(T, try source.cursor.numberSpan());
        },

        .optional => |info| {
            scan.skipSpace(source.cursor, shape);

            if ((try source.cursor.peek()) == 'n') {
                try source.cursor.literal("null");

                return null;
            }

            return try readValue(info.child, source, options, shape);
        },

        .@"enum" => {
            if (!reflect.isExhaustive(T)) @compileError(
                "jzon generated parser: " ++ @typeName(T) ++
                    " is non-exhaustive, so a name cannot cover every value it carries",
            );

            return readEnum(T, source, shape);
        },

        .@"struct" => |info| {
            if (info.is_tuple) @compileError(
                "jzon generated parser: " ++ @typeName(T) ++ " is a tuple, which has no object form",
            );

            return readStruct(T, source, options, shape);
        },

        .pointer => |info| {
            if (info.size != .slice) @compileError(
                "jzon generated parser: " ++ @typeName(T) ++ " is not a slice, so it has no JSON form",
            );

            if (info.child == u8) return readString(T, source, options, shape);

            return readSlice(T, source, options, shape);
        },

        else => @compileError("jzon generated parser: " ++ @typeName(T) ++ " has no JSON form"),
    }
}

/// Read one of the two boolean words.
fn readBool(cursor: *Cursor, comptime shape: Shape) Error!bool {
    scan.skipSpace(cursor, shape);

    switch (try cursor.peek()) {
        't' => {
            try cursor.literal("true");

            return true;
        },

        'f' => {
            try cursor.literal("false");

            return false;
        },

        else => return error.JzonUnexpected,
    }
}

/// Read a string holding one of an enum's tag names.
fn readEnum(comptime T: type, source: Source, comptime shape: Shape) Error!T {
    scan.skipSpace(source.cursor, shape);

    const span = try scan.stringSpan(source.cursor, shape);
    const name = try string_value.take(source.allocator, span, NAME_OPTIONS);

    return std.meta.stringToEnum(T, name) orelse {
        diagnostic.noteField(name);

        return error.JzonUnknownEnumValue;
    };
}

/// Read a struct as a JSON object, matching each key against a field name.
fn readStruct(comptime T: type, source: Source, comptime options: Options, comptime shape: Shape) Error!T {
    const cursor = source.cursor;

    scan.skipSpace(cursor, shape);
    try cursor.expect('{');

    var result: T = undefined;
    var seen: fields.Seen(T) = .{};

    scan.skipSpace(cursor, shape);

    if (!cursor.accept('}')) {
        while (true) {
            scan.skipSpace(cursor, shape);

            const span = try scan.stringSpan(cursor, shape);
            const key = try string_value.take(source.allocator, span, NAME_OPTIONS);

            scan.skipSpace(cursor, shape);
            try cursor.expect(':');

            try readField(T, &result, &seen, key, source, options, shape);

            scan.skipSpace(cursor, shape);
            if (cursor.accept(',')) continue;

            try cursor.expect('}');
            break;
        }
    }

    try seen.fill(&result);

    return result;
}

/// Read the value behind one object key into the field that key names.
///
/// Note:
/// - The match is unrolled over the field names at compile time, so a key costs
///   one comparison per field and no lookup structure is built for it.
fn readField(
    comptime T: type,
    result: *T,
    seen: *fields.Seen(T),
    key: []const u8,
    source: Source,
    comptime options: Options,
    comptime shape: Shape,
) Error!void {
    inline for (comptime std.meta.fieldNames(T), 0..) |name, index| {
        if (std.mem.eql(u8, name, key)) {
            try seen.mark(index);

            @field(result, name) = try readValue(@FieldType(T, name), source, options, shape);

            return;
        }
    }

    switch (options.unknown) {
        .REJECT => {
            diagnostic.noteFieldAt(key, source.cursor.pos);

            return error.JzonUnknownField;
        },
        .SKIP => try skip.value(source.cursor, shape),
    }
}

/// Read a slice as a JSON array, one element at a time.
fn readSlice(comptime T: type, source: Source, comptime options: Options, comptime shape: Shape) Error!T {
    const Element = @typeInfo(T).pointer.child;

    if (T != []const Element and T != []Element) @compileError(
        "jzon generated parser: " ++ @typeName(T) ++ " is not a plain slice, so a parse cannot produce it",
    );

    const cursor = source.cursor;

    scan.skipSpace(cursor, shape);
    try cursor.expect('[');

    var elements: std.ArrayList(Element) = .empty;

    scan.skipSpace(cursor, shape);

    if (!cursor.accept(']')) {
        while (true) {
            const element = try readValue(Element, source, options, shape);
            try elements.append(source.allocator, element);

            scan.skipSpace(cursor, shape);
            if (cursor.accept(',')) continue;

            try cursor.expect(']');
            break;
        }
    }

    return try elements.toOwnedSlice(source.allocator);
}

/// Read a string into the one slice type a parse can produce.
fn readString(comptime T: type, source: Source, comptime options: Options, comptime shape: Shape) Error!T {
    if (T != []const u8) @compileError(
        "jzon generated parser: " ++ @typeName(T) ++ " is not []const u8, the only string form a parse produces",
    );

    scan.skipSpace(source.cursor, shape);

    const span = try scan.stringSpan(source.cursor, shape);

    return string_value.take(source.allocator, span, options);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const scanner_parser = @import("scanner_parser.zig");

/// Both widths, so a case can assert the pair agrees.
const SHAPES = [_]Shape{
    .{ .scan = .SCALAR },
    .{ .scan = .VECTOR },
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
    note: ?[]const u8 = null,
    tags: []const []const u8,
    nested: Nested,
};

const DOCUMENT =
    "{\"id\":7,\"name\":\"a\\\"b\",\"ratio\":2.5,\"active\":true," ++
    "\"status\":\"SHIPPED\",\"note\":null,\"tags\":[\"one\",\"two\"]," ++
    "\"nested\":{\"alpha\":-3,\"beta\":\"x\"}}";

test "jzon: generated parser reads a whole record at both widths" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    inline for (SHAPES) |shape| {
        const record = try parse(Record, arena.allocator(), DOCUMENT, .{}, shape);

        try std.testing.expectEqual(@as(u64, 7), record.id);
        try std.testing.expectEqualStrings("a\"b", record.name);
        try std.testing.expectEqual(@as(f64, 2.5), record.ratio);
        try std.testing.expect(record.active);
        try std.testing.expectEqual(Status.SHIPPED, record.status);
        try std.testing.expect(record.note == null);
        try std.testing.expectEqual(@as(usize, 2), record.tags.len);
        try std.testing.expectEqualStrings("one", record.tags[0]);
        try std.testing.expectEqualStrings("x", record.nested.beta);
    }
}

test "jzon: generated parser reads the same record the scanner path reads" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const theirs = try scanner_parser.parse(Record, allocator, DOCUMENT, .{});

    inline for (SHAPES) |shape| {
        const ours = try parse(Record, allocator, DOCUMENT, .{}, shape);

        try std.testing.expectEqual(theirs.id, ours.id);
        try std.testing.expectEqualStrings(theirs.name, ours.name);
        try std.testing.expectEqual(theirs.ratio, ours.ratio);
        try std.testing.expectEqual(theirs.status, ours.status);
        try std.testing.expectEqualStrings(theirs.tags[1], ours.tags[1]);
        try std.testing.expectEqual(theirs.nested.alpha, ours.nested.alpha);
    }
}

test "jzon: generated parser reports the same failures the other paths report" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const Pair = struct { id: u8, name: []const u8 };

    inline for (SHAPES) |shape| {
        try std.testing.expectError(error.JzonUnknownField, parse(Pair, allocator, "{\"id\":1,\"name\":\"x\",\"other\":2}", .{}, shape));
        try std.testing.expectError(error.JzonMissingField, parse(Pair, allocator, "{\"id\":1}", .{}, shape));
        try std.testing.expectError(error.JzonBadNumber, parse(Pair, allocator, "{\"id\":300,\"name\":\"x\"}", .{}, shape));
        try std.testing.expectError(error.JzonTruncated, parse(Pair, allocator, "{\"id\":1,", .{}, shape));
        try std.testing.expectError(error.JzonUnexpected, parse(Pair, allocator, "{\"id\":true,\"name\":\"x\"}", .{}, shape));
        try std.testing.expectError(error.JzonUnknownEnumValue, parse(Status, allocator, "\"GONE\"", .{}, shape));
    }
}

test "jzon: generated parser steps over an unknown key when asked to" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const Pair = struct { id: u8, name: []const u8 };
    const src = "{\"id\":1,\"other\":{\"deep\":[1,2,3]},\"name\":\"x\"}";

    inline for (SHAPES) |shape| {
        const pair = try parse(Pair, arena.allocator(), src, .{ .unknown = .SKIP }, shape);

        try std.testing.expectEqual(@as(u8, 1), pair.id);
        try std.testing.expectEqualStrings("x", pair.name);
    }
}

test "jzon: generated parser borrows a clean string and copies an escaped one" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const src = "{\"plain\":\"borrowed\",\"escaped\":\"one\\ttwo\"}";
    const Pair = struct {
        plain: []const u8,
        escaped: []const u8,
    };

    inline for (SHAPES) |shape| {
        const borrowed = try parse(Pair, arena.allocator(), src, .{ .strings = .BORROW }, shape);

        try std.testing.expect(@intFromPtr(borrowed.plain.ptr) >= @intFromPtr(src.ptr));
        try std.testing.expect(@intFromPtr(borrowed.plain.ptr) < @intFromPtr(src.ptr) + src.len);
        try std.testing.expectEqualStrings("one\ttwo", borrowed.escaped);

        const copied = try parse(Pair, arena.allocator(), src, .{ .strings = .COPY }, shape);

        try std.testing.expect(@intFromPtr(copied.plain.ptr) < @intFromPtr(src.ptr) or
            @intFromPtr(copied.plain.ptr) >= @intFromPtr(src.ptr) + src.len);
        try std.testing.expectEqualStrings("borrowed", copied.plain);
    }
}

test "jzon: generated parser reads a document laid out with whitespace" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const src =
        \\  {
        \\    "id"   : 9 ,
        \\    "name" : "spaced out"
        \\  }
    ;
    const Pair = struct { id: u8, name: []const u8 };

    inline for (SHAPES) |shape| {
        const pair = try parse(Pair, arena.allocator(), src, .{}, shape);

        try std.testing.expectEqual(@as(u8, 9), pair.id);
        try std.testing.expectEqualStrings("spaced out", pair.name);
    }
}

test "jzon: generated parser refuses a document with anything after the value" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    inline for (SHAPES) |shape| {
        try std.testing.expectError(error.JzonUnexpected, parse(u8, arena.allocator(), "1 2", .{}, shape));
    }
}
