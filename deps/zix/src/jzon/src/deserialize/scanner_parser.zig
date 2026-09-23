//! jzon deserialize, tokens from std's scanner.
//!
//! What:
//! - Pulls whole tokens off `std.json.Scanner`, so std still decides what a valid
//!   document is, and hands each one to code built from the target type at
//!   compile time. Nothing reflects over the type while the parse runs.
//!
//! Note:
//! - Reads the shapes the generated emitter writes. A field type outside that set
//!   is a compile error naming the type, never a runtime failure, and the
//!   std-backed path stays available for it.
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

const fields = @import("fields.zig");
const float = @import("../float.zig");
const integer = @import("../integer.zig");
const reflect = @import("../reflect.zig");

const Allocator = std.mem.Allocator;

/// How a parse can fail.
pub const Error = @import("options.zig").Error;

/// The options a parse runs with.
pub const Options = @import("options.zig").Options;

/// Everything the scanner can report, whichever way a token is asked for.
const ScannerError = std.json.Scanner.NextError ||
    std.json.Scanner.PeekError ||
    std.json.Scanner.AllocError ||
    std.json.Scanner.SkipError;

/// The scanner, plus what taking a token off it needs.
const Source = struct {
    allocator: Allocator,
    scanner: *std.json.Scanner,

    /// The longest a single token can be, which is the document itself. std uses
    /// the same bound, so `error.ValueTooLong` can never come up.
    value_cap: usize,

    /// Take the next whole token.
    fn next(self: Source, when: std.json.AllocWhen) Error!std.json.Token {
        return self.scanner.nextAllocMax(self.allocator, when, self.value_cap) catch |failure|
            translate(failure);
    }

    /// What the next token is, without taking it.
    fn peek(self: Source) Error!std.json.TokenType {
        return self.scanner.peekNextTokenType() catch |failure| translate(failure);
    }

    /// Step over the next whole value, however deep it nests.
    fn skip(self: Source) Error!void {
        return self.scanner.skipValue() catch |failure| translate(failure);
    }
};

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
///
/// Return:
/// - T (the parsed value)
/// - error.JzonUnknownField, error.JzonMissingField, error.JzonUnknownEnumValue when the
///   document and the type disagree
/// - error.JzonTruncated, error.JzonUnexpected, error.JzonBadNumber when the document is not
///   what it claims
/// - error.OutOfMemory when the allocator runs out
pub fn parse(
    comptime T: type,
    allocator: Allocator,
    src: []const u8,
    comptime options: Options,
) Error!T {
    var scanner = std.json.Scanner.initCompleteInput(allocator, src);
    defer scanner.deinit();

    const source: Source = .{ .allocator = allocator, .scanner = &scanner, .value_cap = src.len };

    const value = try readValue(T, source, options);

    if ((try source.next(.alloc_if_needed)) != .end_of_document) return error.JzonUnexpected;

    return value;
}

/// Read one value of `T`, whatever shape the type is.
fn readValue(comptime T: type, source: Source, comptime options: Options) Error!T {
    switch (@typeInfo(T)) {
        .bool => return readBool(source),

        .int => return integer.parse(T, try numberText(source)),

        .float => return float.parse(T, try numberText(source)),

        .optional => |info| {
            if ((try source.peek()) == .null) {
                _ = try source.next(.alloc_if_needed);

                return null;
            }

            return try readValue(info.child, source, options);
        },

        .@"enum" => {
            if (!reflect.isExhaustive(T)) @compileError(
                "jzon parser: " ++ @typeName(T) ++
                    " is non-exhaustive, so a name cannot cover every value it carries",
            );

            const name = try stringText(source, .alloc_if_needed);

            return std.meta.stringToEnum(T, name) orelse {
                diagnostic.noteField(name);

                return error.JzonUnknownEnumValue;
            };
        },

        .@"struct" => |info| {
            if (info.is_tuple) @compileError(
                "jzon parser: " ++ @typeName(T) ++ " is a tuple, which has no object form",
            );

            return readStruct(T, source, options);
        },

        .pointer => |info| {
            if (info.size != .slice) @compileError(
                "jzon parser: " ++ @typeName(T) ++ " is not a slice, so it has no JSON form",
            );

            if (info.child == u8) return readString(T, source, options);

            return readSlice(T, source, options);
        },

        else => @compileError("jzon parser: " ++ @typeName(T) ++ " has no JSON form"),
    }
}

/// Read one of the two boolean words.
fn readBool(source: Source) Error!bool {
    return switch (try source.next(.alloc_if_needed)) {
        .true => true,
        .false => false,
        else => error.JzonUnexpected,
    };
}

/// Read a struct as a JSON object, matching each key against a field name.
///
/// Note:
/// - The key match is unrolled over the field names at compile time, so a key
///   costs one comparison per field and no lookup structure is built.
fn readStruct(comptime T: type, source: Source, comptime options: Options) Error!T {
    if ((try source.next(.alloc_if_needed)) != .object_begin) return error.JzonUnexpected;

    var result: T = undefined;
    var seen: fields.Seen(T) = .{};

    while (true) {
        const key = switch (try source.next(.alloc_if_needed)) {
            .object_end => break,
            .string => |text| text,
            .allocated_string => |text| text,
            else => return error.JzonUnexpected,
        };

        var matched = false;

        inline for (comptime std.meta.fieldNames(T), 0..) |name, index| {
            if (!matched and std.mem.eql(u8, name, key)) {
                try seen.mark(index);

                @field(result, name) = try readValue(@FieldType(T, name), source, options);
                matched = true;
            }
        }

        if (matched) continue;

        switch (options.unknown) {
            .REJECT => {
                diagnostic.noteField(key);

                return error.JzonUnknownField;
            },
            .SKIP => try source.skip(),
        }
    }

    try seen.fill(&result);

    return result;
}

/// Read a slice as a JSON array, one element at a time.
fn readSlice(comptime T: type, source: Source, comptime options: Options) Error!T {
    const Element = @typeInfo(T).pointer.child;

    if (T != []const Element and T != []Element) @compileError(
        "jzon parser: " ++ @typeName(T) ++ " is not a plain slice, so a parse cannot produce it",
    );

    if ((try source.next(.alloc_if_needed)) != .array_begin) return error.JzonUnexpected;

    var elements: std.ArrayList(Element) = .empty;

    while ((try source.peek()) != .array_end) {
        const element = try readValue(Element, source, options);

        try elements.append(source.allocator, element);
    }

    _ = try source.next(.alloc_if_needed);

    return try elements.toOwnedSlice(source.allocator);
}

/// Read a string into the one slice type a parse can produce.
fn readString(comptime T: type, source: Source, comptime options: Options) Error!T {
    if (T != []const u8) @compileError(
        "jzon parser: " ++ @typeName(T) ++ " is not []const u8, the only string form a parse produces",
    );

    const when: std.json.AllocWhen = switch (options.strings) {
        .COPY => .alloc_always,
        .BORROW => .alloc_if_needed,
    };

    return stringText(source, when);
}

/// The bytes of a string token, decoded and whole.
fn stringText(source: Source, when: std.json.AllocWhen) Error![]const u8 {
    return switch (try source.next(when)) {
        .string => |text| text,
        .allocated_string => |text| text,
        else => error.JzonUnexpected,
    };
}

/// The bytes of a number token, which never need decoding.
fn numberText(source: Source) Error![]const u8 {
    return switch (try source.next(.alloc_if_needed)) {
        .number => |text| text,
        .allocated_number => |text| text,
        else => error.JzonUnexpected,
    };
}

/// Map one of the scanner's failures onto the set every jzon path shares.
///
/// Note:
/// - A syntax error and a value past the length cap are both the document not
///   being what it claims, so both are Unexpected. Running out of input part way
///   through a token is Truncated.
fn translate(failure: ScannerError) Error {
    return switch (failure) {
        error.OutOfMemory => error.OutOfMemory,
        error.UnexpectedEndOfInput, error.BufferUnderrun => error.JzonTruncated,
        else => error.JzonUnexpected,
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const std_parser = @import("std_parser.zig");

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

test "jzon: scanner parser reads a whole record" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const record = try parse(Record, arena.allocator(), DOCUMENT, .{});

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

test "jzon: scanner parser reads the same record the std path reads" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

    const ours = try parse(Record, allocator, DOCUMENT, .{});
    const theirs = try std_parser.parse(Record, allocator, DOCUMENT, .{});

    try std.testing.expectEqual(theirs.id, ours.id);
    try std.testing.expectEqualStrings(theirs.name, ours.name);
    try std.testing.expectEqual(theirs.ratio, ours.ratio);
    try std.testing.expectEqual(theirs.status, ours.status);
    try std.testing.expectEqualStrings(theirs.tags[1], ours.tags[1]);
    try std.testing.expectEqual(theirs.nested.alpha, ours.nested.alpha);
}

test "jzon: scanner parser reports the same failures the std path reports" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const Pair = struct { id: u8, name: []const u8 };

    try std.testing.expectError(error.JzonUnknownField, parse(Pair, allocator, "{\"id\":1,\"name\":\"x\",\"other\":2}", .{}));
    try std.testing.expectError(error.JzonMissingField, parse(Pair, allocator, "{\"id\":1}", .{}));
    try std.testing.expectError(error.JzonBadNumber, parse(Pair, allocator, "{\"id\":300,\"name\":\"x\"}", .{}));
    try std.testing.expectError(error.JzonTruncated, parse(Pair, allocator, "{\"id\":1,", .{}));
    try std.testing.expectError(error.JzonUnexpected, parse(Pair, allocator, "{\"id\":true,\"name\":\"x\"}", .{}));
    try std.testing.expectError(error.JzonUnknownEnumValue, parse(Status, allocator, "\"GONE\"", .{}));
}

test "jzon: scanner parser steps over an unknown key when asked to" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const Pair = struct { id: u8, name: []const u8 };
    const src = "{\"id\":1,\"other\":{\"deep\":[1,2,3]},\"name\":\"x\"}";

    const pair = try parse(Pair, arena.allocator(), src, .{ .unknown = .SKIP });

    try std.testing.expectEqual(@as(u8, 1), pair.id);
    try std.testing.expectEqualStrings("x", pair.name);
}

test "jzon: scanner parser borrows a clean string and copies an escaped one" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    const src = "{\"plain\":\"borrowed\",\"escaped\":\"one\\ttwo\"}";
    const Pair = struct {
        plain: []const u8,
        escaped: []const u8,
    };

    const borrowed = try parse(Pair, arena.allocator(), src, .{ .strings = .BORROW });

    try std.testing.expect(@intFromPtr(borrowed.plain.ptr) >= @intFromPtr(src.ptr));
    try std.testing.expect(@intFromPtr(borrowed.plain.ptr) < @intFromPtr(src.ptr) + src.len);
    try std.testing.expectEqualStrings("one\ttwo", borrowed.escaped);

    const copied = try parse(Pair, arena.allocator(), src, .{ .strings = .COPY });

    try std.testing.expect(@intFromPtr(copied.plain.ptr) < @intFromPtr(src.ptr) or
        @intFromPtr(copied.plain.ptr) >= @intFromPtr(src.ptr) + src.len);
    try std.testing.expectEqualStrings("borrowed", copied.plain);
}

test "jzon: scanner parser refuses a document with anything after the value" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.JzonUnexpected, parse(u8, arena.allocator(), "1 2", .{}));
}
