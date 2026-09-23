//! zurtr live-UI wire protocol: the client/server frame codec
//! (`docs/modules/live.md` §Protocol).
//!
//! Envelope only. This file knows the framing of a frame and the limits the
//! protocol puts on it; it knows nothing about patch op internals, event
//! payload shapes, or session semantics (what an `ack` means, how `rev`
//! advances). Payload and patch JSON travel as opaque text produced and
//! consumed by other components.
//!
//! Pure: no I/O, no session state, no swerver dependency. Decoding is
//! deliberately coarse — a frame is either one of the four client messages or
//! it is rejected with one of four reasons.
//!
//! Wire shapes (text frames, JSON):
//!
//!     {"t":"hello","token":"...","rev":<n>,"pending":[<event-ids>]}
//!     {"t":"events","batch":[{"id":<u64>,"ev":"<name>","payload":{...}}]}
//!     {"t":"ack","rev":<n>}
//!     {"t":"resync_req"}
//!
//!     {"t":"ready","rev":<n>,"resume":<bool>}
//!     {"t":"patch","rev":<n>,"acks":[...],"ops":[...],"forms":{...},"focus":{...},"nav":{...}}
//!     {"t":"resync","rev":<n>,"html":"<full page>"}
//!     {"t":"error","event":<id>,"kind":"...","fields":{...},"message":"..."}
//!     {"t":"redirect","to":"..."}
//!
//! Decode rules:
//!   * Object field order is not significant; JSON whitespace between tokens
//!     is allowed; exactly one JSON document must fill the frame (trailing
//!     non-whitespace is `Malformed`).
//!   * Unknown object fields are ignored (forward compatibility); a repeated
//!     known field name is `Malformed`. `std.json.Scanner` emits duplicate
//!     keys, so every field loop here tracks "already seen" explicitly.
//!   * Missing required field -> `MissingField`; unknown `t` -> `UnknownType`;
//!     grammar failure, wrong JSON type for a field, non-integer number, or
//!     repeated field -> `Malformed`; any protocol limit exceeded -> `TooLarge`.
//!   * Limits are enforced where the quantity becomes known: the total frame
//!     size before parsing starts, the batch/pending element counts as each
//!     element arrives, and token/name/payload sizes as each is read.
//!   * The frozen `DecodeError` set has no allocation variant. Every
//!     allocation below is bounded by one of these limits, so a failed
//!     allocation is reported as `TooLarge`. Decode may leave arena
//!     allocations behind on error; slices are owned by `alloc`.
//!
//! Encode rules:
//!   * Compact JSON, no trailing whitespace, fixed field order per message.
//!   * String fields are JSON-escaped; `ops`/`forms`/`focus`/`nav`/`fields`
//!     are inserted verbatim as JSON values (already-serialized by the render
//!     and patch layers) and are not re-encoded or validated.
//!   * `null` optionals are omitted from the object, never emitted as `null`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const json = std.json;

/// Largest client frame accepted, in bytes.
pub const max_message_bytes: usize = 64 * 1024;
/// Largest number of events in one `events` batch.
pub const max_events_per_batch: usize = 256;
/// Longest event name (`ev`), in bytes.
pub const max_event_name_bytes: usize = 128;
/// Longest session token, in bytes.
pub const max_token_bytes: usize = 256;
/// Largest number of unacknowledged event ids a `hello` may present.
pub const max_pending_ids: usize = 1024;
/// Largest raw JSON text of one event payload, in bytes.
pub const max_payload_bytes: usize = 16 * 1024;

/// Client -> server messages.
pub const ClientMsg = union(enum) {
    hello: struct { token: []const u8, rev: u64, pending: []const u64 },
    events: struct { batch: []const Event },
    ack: struct { rev: u64 },
    resync_req: void,
};

/// One client event: a client-generated monotonic id, the view's wire event
/// name, and the payload as raw JSON text.
pub const Event = struct { id: u64, name: []const u8, payload_json: []const u8 };

/// Reason a server error reply was produced; names match the wire strings.
pub const ErrKind = enum { validation, authz, conflict, unavailable, internal };

/// Server -> client messages.
pub const ServerMsg = union(enum) {
    ready: struct { rev: u64, @"resume": bool },
    patch: struct {
        rev: u64,
        acks: []const u64,
        ops_json: []const u8,
        forms_json: ?[]const u8,
        focus_json: ?[]const u8,
        nav_json: ?[]const u8,
    },
    resync: struct { rev: u64, html: []const u8 },
    err: struct {
        event: ?u64,
        kind: ErrKind,
        fields_json: ?[]const u8,
        message: []const u8,
    },
    redirect: struct { to: []const u8 },
};

/// Why a client frame was rejected.
pub const DecodeError = error{ Malformed, UnknownType, TooLarge, MissingField };

// ---------------------------------------------------------------- decoding

/// Decodes one client text frame. Every returned slice is allocated from
/// `alloc` (typically an event arena; nothing here is freed individually).
pub fn decodeClientMsg(alloc: Allocator, bytes: []const u8) DecodeError!ClientMsg {
    if (bytes.len > max_message_bytes) return error.TooLarge;

    var sc: json.Scanner = .initCompleteInput(alloc, bytes);
    defer sc.deinit();

    switch (try nextToken(&sc)) {
        .object_begin => {},
        else => return error.Malformed, // non-object root (or empty input)
    }

    // Fields of every client message: `t` plus the union of the shapes above.
    // Collected first, validated against the shape selected by `t` after.
    var msg_type: ?[]const u8 = null;
    var token: ?[]const u8 = null;
    var rev: ?u64 = null;
    var pending: ?[]const u64 = null;
    var batch: ?[]const Event = null;

    while (true) {
        const key = switch (try nextToken(&sc)) {
            .object_end => break,
            else => |tok| stringValue(tok) orelse return error.Malformed,
        };
        if (std.mem.eql(u8, key, "t")) {
            if (msg_type != null) return error.Malformed;
            msg_type = try readString(&sc, alloc, max_message_bytes, .alloc_if_needed);
        } else if (std.mem.eql(u8, key, "token")) {
            if (token != null) return error.Malformed;
            token = try readString(&sc, alloc, max_token_bytes, .alloc_always);
        } else if (std.mem.eql(u8, key, "rev")) {
            if (rev != null) return error.Malformed;
            rev = try readU64(&sc);
        } else if (std.mem.eql(u8, key, "pending")) {
            if (pending != null) return error.Malformed;
            pending = try readPendingIds(&sc, alloc);
        } else if (std.mem.eql(u8, key, "batch")) {
            if (batch != null) return error.Malformed;
            batch = try readBatch(&sc, alloc);
        } else {
            sc.skipValue() catch |err| return mapError(err);
        }
    }

    // One frame is exactly one JSON document.
    switch (try nextToken(&sc)) {
        .end_of_document => {},
        else => return error.Malformed,
    }

    const type_name = msg_type orelse return error.MissingField;
    if (std.mem.eql(u8, type_name, "hello")) {
        const hello_token = token orelse return error.MissingField;
        const hello_rev = rev orelse return error.MissingField;
        const hello_pending = pending orelse return error.MissingField;
        return .{ .hello = .{
            .token = hello_token,
            .rev = hello_rev,
            .pending = hello_pending,
        } };
    }
    if (std.mem.eql(u8, type_name, "events")) {
        const event_batch = batch orelse return error.MissingField;
        return .{ .events = .{ .batch = event_batch } };
    }
    if (std.mem.eql(u8, type_name, "ack")) {
        const ack_rev = rev orelse return error.MissingField;
        return .{ .ack = .{ .rev = ack_rev } };
    }
    if (std.mem.eql(u8, type_name, "resync_req")) return .{ .resync_req = {} };
    return error.UnknownType;
}

/// `[<event-ids>]`, at most `max_pending_ids` entries.
fn readPendingIds(sc: *json.Scanner, alloc: Allocator) DecodeError![]const u64 {
    switch (try nextToken(sc)) {
        .array_begin => {},
        else => return error.Malformed,
    }
    var ids: std.ArrayList(u64) = .empty;
    while (true) {
        switch (try nextToken(sc)) {
            .array_end => break,
            .number, .allocated_number => |text| {
                if (ids.items.len >= max_pending_ids) return error.TooLarge;
                ids.append(alloc, try parseIntegerText(text)) catch |err| return mapError(err);
            },
            // Strings, floats, booleans, null, and nested containers.
            else => return error.Malformed,
        }
    }
    return ids.toOwnedSlice(alloc) catch |err| return mapError(err);
}

/// `[{...},...]`, at most `max_events_per_batch` events.
fn readBatch(sc: *json.Scanner, alloc: Allocator) DecodeError![]const Event {
    switch (try nextToken(sc)) {
        .array_begin => {},
        else => return error.Malformed,
    }
    var events: std.ArrayList(Event) = .empty;
    while (true) {
        switch (try nextToken(sc)) {
            .array_end => break,
            .object_begin => {
                if (events.items.len >= max_events_per_batch) return error.TooLarge;
                events.append(alloc, try readEvent(sc, alloc)) catch |err| return mapError(err);
            },
            else => return error.Malformed,
        }
    }
    return events.toOwnedSlice(alloc) catch |err| return mapError(err);
}

/// `{"id":<u64>,"ev":"<name>","payload":{...}}`.
fn readEvent(sc: *json.Scanner, alloc: Allocator) DecodeError!Event {
    var id: ?u64 = null;
    var name: ?[]const u8 = null;
    var payload: ?[]const u8 = null;

    while (true) {
        const key = switch (try nextToken(sc)) {
            .object_end => break,
            else => |tok| stringValue(tok) orelse return error.Malformed,
        };
        if (std.mem.eql(u8, key, "id")) {
            if (id != null) return error.Malformed;
            id = try readU64(sc);
        } else if (std.mem.eql(u8, key, "ev")) {
            if (name != null) return error.Malformed;
            name = try readString(sc, alloc, max_event_name_bytes, .alloc_always);
        } else if (std.mem.eql(u8, key, "payload")) {
            if (payload != null) return error.Malformed;
            payload = try readPayload(sc, alloc);
        } else {
            sc.skipValue() catch |err| return mapError(err);
        }
    }

    const event_id = id orelse return error.MissingField;
    const event_name = name orelse return error.MissingField;
    const event_payload = payload orelse return error.MissingField;
    return .{ .id = event_id, .name = event_name, .payload_json = event_payload };
}

/// One event payload: a JSON object, returned as its raw source text so the
/// typed event decoder sees exactly what the client sent (numbers keep their
/// spelling, escape sequences stay escaped).
fn readPayload(sc: *json.Scanner, alloc: Allocator) DecodeError![]const u8 {
    // `peekNextTokenType` consumes the ':' left pending by the key read and
    // skips whitespace, so the scanner lands on the value's first byte.
    switch (sc.peekNextTokenType() catch |err| return mapError(err)) {
        .object_begin => {},
        else => return error.Malformed,
    }
    const input = sc.input;
    const start = firstNonWhitespace(input, sc.cursor);
    if (start >= input.len) return error.Malformed;
    sc.skipValue() catch |err| return mapError(err);

    var end = sc.cursor;
    while (end > start and isJsonWhitespace(input[end - 1])) end -= 1;
    const raw = input[start..end];
    if (raw.len > max_payload_bytes) return error.TooLarge;
    return alloc.dupe(u8, raw) catch |err| return mapError(err);
}

/// A JSON number token holding an unsigned integer.
fn readU64(sc: *json.Scanner) DecodeError!u64 {
    return switch (try nextToken(sc)) {
        .number, .allocated_number => |text| try parseIntegerText(text),
        else => error.Malformed, // string, float, bool, null, container
    };
}

fn parseIntegerText(text: []const u8) DecodeError!u64 {
    if (!json.isNumberFormattedLikeAnInteger(text)) return error.Malformed;
    return std.fmt.parseInt(u64, text, 10) catch return error.Malformed;
}

/// The next value as a string; `limit` is enforced by the scanner while it
/// unescapes, so an over-long token or name fails as `TooLarge`.
fn readString(
    sc: *json.Scanner,
    alloc: Allocator,
    limit: usize,
    when: json.AllocWhen,
) DecodeError![]const u8 {
    const tok = sc.nextAllocMax(alloc, when, limit) catch |err| return mapError(err);
    return switch (tok) {
        .string, .allocated_string => |s| s,
        else => error.Malformed,
    };
}

fn nextToken(sc: *json.Scanner) DecodeError!json.Token {
    return sc.next() catch |err| mapError(err);
}

/// The decoded text of a string token, or `null` for any other token.
fn stringValue(tok: json.Token) ?[]const u8 {
    return switch (tok) {
        .string, .allocated_string => |s| s,
        else => null,
    };
}

fn firstNonWhitespace(input: []const u8, from: usize) usize {
    var i = from;
    while (i < input.len and isJsonWhitespace(input[i])) i += 1;
    return i;
}

fn isJsonWhitespace(c: u8) bool {
    return switch (c) {
        ' ', '\t', '\r', '\n' => true,
        else => false,
    };
}

/// Scanner and allocation failures collapsed onto `DecodeError`: grammar
/// problems (`SyntaxError`, `UnexpectedEndOfInput`) are `Malformed`, and
/// `ValueTooLong`/`OutOfMemory` — both bounded by a protocol limit — are
/// `TooLarge`. `BufferUnderrun` cannot occur on complete input.
fn mapError(err: anyerror) DecodeError {
    return switch (err) {
        error.OutOfMemory, error.ValueTooLong => error.TooLarge,
        else => error.Malformed,
    };
}

// ---------------------------------------------------------------- encoding

/// Encodes one server message as a compact JSON text frame.
pub fn encodeServerMsg(w: *Writer, msg: ServerMsg) !void {
    var js: json.Stringify = .{ .writer = w };
    try js.beginObject();
    try js.objectField("t");
    switch (msg) {
        .ready => |m| {
            try writeStringValue(&js, "ready");
            try js.objectField("rev");
            try js.write(m.rev);
            try js.objectField("resume");
            try js.write(m.@"resume");
        },
        .patch => |m| {
            try writeStringValue(&js, "patch");
            try js.objectField("rev");
            try js.write(m.rev);
            try js.objectField("acks");
            try js.write(m.acks);
            try js.objectField("ops");
            try writeRawValue(&js, m.ops_json);
            if (m.forms_json) |text| {
                try js.objectField("forms");
                try writeRawValue(&js, text);
            }
            if (m.focus_json) |text| {
                try js.objectField("focus");
                try writeRawValue(&js, text);
            }
            if (m.nav_json) |text| {
                try js.objectField("nav");
                try writeRawValue(&js, text);
            }
        },
        .resync => |m| {
            try writeStringValue(&js, "resync");
            try js.objectField("rev");
            try js.write(m.rev);
            try js.objectField("html");
            try writeStringValue(&js, m.html);
        },
        .err => |m| {
            try writeStringValue(&js, "error");
            if (m.event) |id| {
                try js.objectField("event");
                try js.write(id);
            }
            try js.objectField("kind");
            try writeStringValue(&js, @tagName(m.kind));
            if (m.fields_json) |text| {
                try js.objectField("fields");
                try writeRawValue(&js, text);
            }
            try js.objectField("message");
            try writeStringValue(&js, m.message);
        },
        .redirect => |m| {
            try writeStringValue(&js, "redirect");
            try js.objectField("to");
            try writeStringValue(&js, m.to);
        },
    }
    try js.endObject();
}

/// Writes a string field, always as a JSON string (escaped) — including for
/// bytes that are not valid UTF-8, which `Stringify.write` would emit as a
/// number array.
fn writeStringValue(js: *json.Stringify, s: []const u8) !void {
    try js.beginWriteRaw();
    try json.Stringify.encodeJsonString(s, .{}, js.writer);
    js.endWriteRaw();
}

/// Inserts already-serialized JSON text as a value, verbatim.
fn writeRawValue(js: *json.Stringify, text: []const u8) !void {
    try js.beginWriteRaw();
    try js.writer.writeAll(text);
    js.endWriteRaw();
}

// ------------------------------------------------------------------- tests

const testing = std.testing;

/// Decodes with decoding errors mapped to `expectError`.
fn expectDecodeError(expected: DecodeError, bytes: []const u8) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(expected, decodeClientMsg(arena.allocator(), bytes));
}

fn expectEncode(expected: []const u8, msg: ServerMsg) !void {
    var out: Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    try encodeServerMsg(&out.writer, msg);
    try testing.expectEqualStrings(expected, out.written());
}

/// `{"t":"hello","token":"<token>","rev":1,"pending":[1,1,...]}`.
fn helloFrame(alloc: Allocator, token: []const u8, pending_count: usize) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(alloc);
    try buf.appendSlice(alloc, "{\"t\":\"hello\",\"token\":\"");
    try buf.appendSlice(alloc, token);
    try buf.appendSlice(alloc, "\",\"rev\":1,\"pending\":[");
    for (0..pending_count) |i| {
        if (i != 0) try buf.append(alloc, ',');
        try buf.append(alloc, '1');
    }
    try buf.appendSlice(alloc, "]}");
    return buf.toOwnedSlice(alloc);
}

/// `{"t":"events","batch":[<event>,<event>,...]}` with `count` copies.
fn eventsFrame(alloc: Allocator, event: []const u8, count: usize) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(alloc);
    try buf.appendSlice(alloc, "{\"t\":\"events\",\"batch\":[");
    for (0..count) |i| {
        if (i != 0) try buf.append(alloc, ',');
        try buf.appendSlice(alloc, event);
    }
    try buf.appendSlice(alloc, "]}");
    return buf.toOwnedSlice(alloc);
}

/// `{"t":"events","batch":[{"id":1,"ev":"x","payload":{"s":"xxx..."}}]}`;
/// the raw payload text is `content_len + 8` bytes.
fn payloadFrame(alloc: Allocator, content_len: usize) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(alloc);
    try buf.appendSlice(
        alloc,
        "{\"t\":\"events\",\"batch\":[{\"id\":1,\"ev\":\"x\",\"payload\":{\"s\":\"",
    );
    try buf.ensureTotalCapacity(alloc, buf.items.len + content_len + 8);
    for (0..content_len) |_| try buf.append(alloc, 'x');
    try buf.appendSlice(alloc, "\"}}]}");
    return buf.toOwnedSlice(alloc);
}

fn repeated(alloc: Allocator, byte: u8, len: usize) ![]u8 {
    const buf = try alloc.alloc(u8, len);
    @memset(buf, byte);
    return buf;
}

test "decode hello" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const msg = try decodeClientMsg(
        arena.allocator(),
        "{\"t\":\"hello\",\"token\":\"tok-1\",\"rev\":7,\"pending\":[3,5,8]}",
    );
    switch (msg) {
        .hello => |h| {
            try testing.expectEqualStrings("tok-1", h.token);
            try testing.expectEqual(@as(u64, 7), h.rev);
            try testing.expectEqualSlices(u64, &[_]u64{ 3, 5, 8 }, h.pending);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "decode hello accepts field reordering, whitespace, escapes, empty pending" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();

    const msg = try decodeClientMsg(arena.allocator(),
        \\  {  "rev" : 0 , "pending" : [ ] ,
        \\"t":"hello","token":"a\u0041\u00dfb" }
    );
    switch (msg) {
        .hello => |h| {
            try testing.expectEqualStrings("aA\xc3\x9fb", h.token);
            try testing.expectEqual(@as(u64, 0), h.rev);
            try testing.expectEqual(@as(usize, 0), h.pending.len);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "decode events keeps payload JSON verbatim" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    const src = "{\"t\":\"events\",\"batch\":[" ++
        "{\"id\":1,\"ev\":\"save\",\"payload\":{ \"n\" : 2.50, \"s\":\"a\\nb\" }}" ++
        ",{\"ev\":\"del\",\"payload\":{},\"id\":2}" ++
        "]}";
    const frame = try alloc.dupe(u8, src);
    const msg = try decodeClientMsg(alloc, frame);
    @memset(frame, 'x'); // decoded text must not alias the frame

    switch (msg) {
        .events => |e| {
            try testing.expectEqual(@as(usize, 2), e.batch.len);

            try testing.expectEqual(@as(u64, 1), e.batch[0].id);
            try testing.expectEqualStrings("save", e.batch[0].name);
            try testing.expectEqualStrings("{ \"n\" : 2.50, \"s\":\"a\\nb\" }", e.batch[0].payload_json);

            try testing.expectEqual(@as(u64, 2), e.batch[1].id);
            try testing.expectEqualStrings("del", e.batch[1].name);
            try testing.expectEqualStrings("{}", e.batch[1].payload_json);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "decode ack, resync_req, and ignored fields" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    switch (try decodeClientMsg(alloc, "{\"t\":\"ack\",\"rev\":18446744073709551615}")) {
        .ack => |a| try testing.expectEqual(@as(u64, std.math.maxInt(u64)), a.rev),
        else => return error.TestUnexpectedResult,
    }
    switch (try decodeClientMsg(alloc, "{\"rev\":3,\"t\":\"ack\"}")) {
        .ack => |a| try testing.expectEqual(@as(u64, 3), a.rev),
        else => return error.TestUnexpectedResult,
    }
    switch (try decodeClientMsg(alloc, "{\"t\":\"resync_req\"}")) {
        .resync_req => {},
        else => return error.TestUnexpectedResult,
    }
    // Unknown fields (nested, in any position) are skipped.
    switch (try decodeClientMsg(alloc, "{\"x\":{\"deep\":[1,2,{\"n\":null}]},\"t\":\"resync_req\",\"y\":[]}")) {
        .resync_req => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try decodeClientMsg(alloc, "{\"t\":\"events\",\"batch\":[],\"x\":1,\"t2\":\"hello\"}")) {
        .events => |e| try testing.expectEqual(@as(usize, 0), e.batch.len),
        else => return error.TestUnexpectedResult,
    }
}

test "decode rejects non-object roots" {
    try expectDecodeError(error.Malformed, "");
    try expectDecodeError(error.Malformed, "   ");
    try expectDecodeError(error.Malformed, "[]");
    try expectDecodeError(error.Malformed, "\"hello\"");
    try expectDecodeError(error.Malformed, "42");
    try expectDecodeError(error.Malformed, "true");
    try expectDecodeError(error.Malformed, "null");
}

test "decode rejects missing required fields" {
    try expectDecodeError(error.MissingField, "{}");
    try expectDecodeError(error.MissingField, "{\"token\":\"a\",\"rev\":1,\"pending\":[]}");
    try expectDecodeError(error.MissingField, "{\"t\":\"hello\",\"rev\":1,\"pending\":[]}");
    try expectDecodeError(error.MissingField, "{\"t\":\"hello\",\"token\":\"a\",\"pending\":[]}");
    try expectDecodeError(error.MissingField, "{\"t\":\"hello\",\"token\":\"a\",\"rev\":1}");
    try expectDecodeError(error.MissingField, "{\"t\":\"events\"}");
    try expectDecodeError(error.MissingField, "{\"t\":\"ack\"}");
    try expectDecodeError(error.MissingField, "{\"t\":\"events\",\"batch\":[{}]}");
    try expectDecodeError(error.MissingField, "{\"t\":\"events\",\"batch\":[{\"ev\":\"a\",\"payload\":{}}]}");
    try expectDecodeError(error.MissingField, "{\"t\":\"events\",\"batch\":[{\"id\":1,\"payload\":{}}]}");
    try expectDecodeError(error.MissingField, "{\"t\":\"events\",\"batch\":[{\"id\":1,\"ev\":\"a\"}]}");
}

test "decode rejects unknown message types" {
    try expectDecodeError(error.UnknownType, "{\"t\":\"nope\"}");
    try expectDecodeError(error.UnknownType, "{\"t\":\"Hello\"}");
    try expectDecodeError(error.UnknownType, "{\"t\":\"ack2\",\"rev\":1}");
    try expectDecodeError(error.UnknownType, "{\"t\":\"nope\",\"batch\":[{\"id\":1,\"ev\":\"a\",\"payload\":{}}]}");
}

test "decode rejects wrong types and out-of-range integers" {
    try expectDecodeError(error.Malformed, "{\"t\":5}");
    try expectDecodeError(error.Malformed, "{\"t\":null}");
    try expectDecodeError(error.Malformed, "{\"t\":{}}");

    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":\"1\"}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":1.5}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":1.0}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":1e3}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":true}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":null}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":[1]}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":{\"n\":1}}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":-1}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":-0}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":18446744073709551616}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":01}");

    try expectDecodeError(error.Malformed, "{\"t\":\"hello\",\"token\":5,\"rev\":1,\"pending\":[]}");
    try expectDecodeError(error.Malformed, "{\"t\":\"hello\",\"token\":\"a\",\"rev\":1,\"pending\":5}");
    try expectDecodeError(error.Malformed, "{\"t\":\"events\",\"batch\":{}}");
    try expectDecodeError(error.Malformed, "{\"t\":\"events\",\"batch\":[5]}");
    try expectDecodeError(error.Malformed, "{\"t\":\"events\",\"batch\":[{\"id\":\"1\",\"ev\":\"a\",\"payload\":{}}]}");
    try expectDecodeError(error.Malformed, "{\"t\":\"events\",\"batch\":[{\"id\":1,\"ev\":5,\"payload\":{}}]}");
}

test "decode rejects payloads that are not objects" {
    try expectDecodeError(error.Malformed, "{\"t\":\"events\",\"batch\":[{\"id\":1,\"ev\":\"a\",\"payload\":5}]}");
    try expectDecodeError(error.Malformed, "{\"t\":\"events\",\"batch\":[{\"id\":1,\"ev\":\"a\",\"payload\":null}]}");
    try expectDecodeError(error.Malformed, "{\"t\":\"events\",\"batch\":[{\"id\":1,\"ev\":\"a\",\"payload\":[]}]}");
    try expectDecodeError(error.Malformed, "{\"t\":\"events\",\"batch\":[{\"id\":1,\"ev\":\"a\",\"payload\":\"x\"}]}");
}

test "decode rejects pending with non-integers" {
    const prefix = "{\"t\":\"hello\",\"token\":\"a\",\"rev\":1,\"pending\":";
    const cases = [_][]const u8{
        "[\"1\"]",
        "[1.5]",
        "[1.0]",
        "[1e4]",
        "[-1]",
        "[null]",
        "[true]",
        "[{}]",
        "[[1]]",
        "[18446744073709551616]",
        "[\"abc\"",
        "[",
    };
    for (cases) |case| {
        const frame = try std.testing.allocator.alloc(u8, prefix.len + case.len + 1);
        defer std.testing.allocator.free(frame);
        @memcpy(frame[0..prefix.len], prefix);
        @memcpy(frame[prefix.len..][0..case.len], case);
        frame[frame.len - 1] = '}';
        try expectDecodeError(error.Malformed, frame);
    }
}

test "decode rejects duplicate field names" {
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":1,\"rev\":2}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"t\":\"ack\",\"rev\":1}");
    try expectDecodeError(error.Malformed, "{\"t\":\"hello\",\"token\":\"a\",\"token\":\"b\",\"rev\":1,\"pending\":[]}");
    try expectDecodeError(error.Malformed, "{\"t\":\"hello\",\"token\":\"a\",\"rev\":1,\"pending\":[1],\"pending\":[]}");
    try expectDecodeError(error.Malformed, "{\"t\":\"events\",\"batch\":[],\"batch\":[]}");
    try expectDecodeError(error.Malformed, "{\"t\":\"events\",\"batch\":[{\"id\":1,\"id\":2,\"ev\":\"a\",\"payload\":{}}]}");
    try expectDecodeError(error.Malformed, "{\"t\":\"events\",\"batch\":[{\"id\":1,\"ev\":\"a\",\"ev\":\"b\",\"payload\":{}}]}");
    try expectDecodeError(error.Malformed, "{\"t\":\"events\",\"batch\":[{\"id\":1,\"ev\":\"a\",\"payload\":{},\"payload\":{}}]}");
}

test "decode rejects truncated frames" {
    try expectDecodeError(error.Malformed, "{");
    try expectDecodeError(error.Malformed, "{\"t\"");
    try expectDecodeError(error.Malformed, "{\"t\":");
    try expectDecodeError(error.Malformed, "{\"t\":\"hel");
    try expectDecodeError(error.Malformed, "{\"t\":\"hello\"");
    try expectDecodeError(error.Malformed, "{\"t\":\"hello\",\"token\":\"a\",");
    try expectDecodeError(error.Malformed, "{\"t\":\"hello\",\"token\":\"a\"");
    try expectDecodeError(error.Malformed, "{\"t\":\"hello\",\"token\":\"a\",\"rev\":");
    try expectDecodeError(error.Malformed, "{\"t\":\"hello\",\"token\":\"a\",\"rev\":1,\"pending\":[1");
    try expectDecodeError(error.Malformed, "{\"t\":\"events\",\"batch\":[{\"id\":1,\"ev\":\"a\",\"payload\":{}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":1");
}

test "decode rejects trailing content" {
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":1}x");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":1} {\"t\":\"ack\",\"rev\":2}");
    try expectDecodeError(error.Malformed, "{\"t\":\"ack\",\"rev\":1},{}");
}

test "decode enforces limits" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // Total frame size, checked before parsing: this frame is only whitespace
    // past the limit, so it would otherwise be `Malformed`.
    const oversize = try repeated(alloc, ' ', max_message_bytes + 1);
    try expectDecodeError(error.TooLarge, oversize);

    // Exactly the limit is fine (trailing whitespace is part of the frame).
    const at_limit = try repeated(alloc, ' ', max_message_bytes);
    @memcpy(at_limit[0.."{\"t\":\"ack\",\"rev\":1}".len], "{\"t\":\"ack\",\"rev\":1}");
    switch (try decodeClientMsg(alloc, at_limit)) {
        .ack => |a| try testing.expectEqual(@as(u64, 1), a.rev),
        else => return error.TestUnexpectedResult,
    }

    // Batch size.
    const event = "{\"id\":1,\"ev\":\"x\",\"payload\":{}}";
    const max_batch = try eventsFrame(alloc, event, max_events_per_batch);
    switch (try decodeClientMsg(alloc, max_batch)) {
        .events => |e| try testing.expectEqual(max_events_per_batch, e.batch.len),
        else => return error.TestUnexpectedResult,
    }
    try expectDecodeError(error.TooLarge, try eventsFrame(alloc, event, max_events_per_batch + 1));

    // Pending ids.
    const full_pending = try helloFrame(alloc, "tok", max_pending_ids);
    switch (try decodeClientMsg(alloc, full_pending)) {
        .hello => |h| try testing.expectEqual(max_pending_ids, h.pending.len),
        else => return error.TestUnexpectedResult,
    }
    try expectDecodeError(error.TooLarge, try helloFrame(alloc, "tok", max_pending_ids + 1));

    // Event name.
    const ok_name = try repeated(alloc, 'a', max_event_name_bytes);
    const ok_name_frame = try std.fmt.allocPrint(
        alloc,
        "{{\"t\":\"events\",\"batch\":[{{\"id\":1,\"ev\":\"{s}\",\"payload\":{{}}}}]}}",
        .{ok_name},
    );
    switch (try decodeClientMsg(alloc, ok_name_frame)) {
        .events => |e| try testing.expectEqual(max_event_name_bytes, e.batch[0].name.len),
        else => return error.TestUnexpectedResult,
    }
    const long_name = try repeated(alloc, 'a', max_event_name_bytes + 1);
    try expectDecodeError(error.TooLarge, try std.fmt.allocPrint(
        alloc,
        "{{\"t\":\"events\",\"batch\":[{{\"id\":1,\"ev\":\"{s}\",\"payload\":{{}}}}]}}",
        .{long_name},
    ));

    // Token.
    const ok_token = try repeated(alloc, 't', max_token_bytes);
    switch (try decodeClientMsg(alloc, try helloFrame(alloc, ok_token, 0))) {
        .hello => |h| try testing.expectEqual(max_token_bytes, h.token.len),
        else => return error.TestUnexpectedResult,
    }
    const long_token = try repeated(alloc, 't', max_token_bytes + 1);
    try expectDecodeError(error.TooLarge, try helloFrame(alloc, long_token, 0));

    // Payload, measured on the raw JSON text: `{"s":"..."}` is 8 bytes of
    // framing around the string content.
    switch (try decodeClientMsg(alloc, try payloadFrame(alloc, max_payload_bytes - 8))) {
        .events => |e| try testing.expectEqual(max_payload_bytes, e.batch[0].payload_json.len),
        else => return error.TestUnexpectedResult,
    }
    try expectDecodeError(error.TooLarge, try payloadFrame(alloc, max_payload_bytes - 7));
}

test "encode ready" {
    try expectEncode("{\"t\":\"ready\",\"rev\":7,\"resume\":true}", .{ .ready = .{ .rev = 7, .@"resume" = true } });
    try expectEncode("{\"t\":\"ready\",\"rev\":0,\"resume\":false}", .{ .ready = .{ .rev = 0, .@"resume" = false } });
}

test "encode patch omits absent optional fields" {
    try expectEncode("{\"t\":\"patch\",\"rev\":9,\"acks\":[],\"ops\":[]}", .{ .patch = .{
        .rev = 9,
        .acks = &.{},
        .ops_json = "[]",
        .forms_json = null,
        .focus_json = null,
        .nav_json = null,
    } });
}

test "encode patch with acks and every optional field" {
    try expectEncode(
        "{\"t\":\"patch\",\"rev\":10,\"acks\":[1,2,3]," ++
            "\"ops\":[{\"op\":\"text\",\"id\":4,\"value\":\"hi\"}]," ++
            "\"forms\":{\"email\":\"a@b\"},\"focus\":{\"id\":4},\"nav\":{\"to\":\"/inbox\"}}",
        .{ .patch = .{
            .rev = 10,
            .acks = &[_]u64{ 1, 2, 3 },
            .ops_json = "[{\"op\":\"text\",\"id\":4,\"value\":\"hi\"}]",
            .forms_json = "{\"email\":\"a@b\"}",
            .focus_json = "{\"id\":4}",
            .nav_json = "{\"to\":\"/inbox\"}",
        } },
    );
}

test "encode resync escapes quotes, backslashes, and control characters" {
    const html = "a\"b\\c\nd\te\rf\x01g\x08h\x0ci\x7fj\u{00e9}k";
    try expectEncode(
        "{\"t\":\"resync\",\"rev\":3,\"html\":\"a\\\"b\\\\c\\nd\\te\\rf\\u0001g\\bh\\fi\x7fj\u{00e9}k\"}",
        .{ .resync = .{ .rev = 3, .html = html } },
    );
}

test "encode err omits event and fields when absent" {
    try expectEncode("{\"t\":\"error\",\"kind\":\"unavailable\",\"message\":\"try later\"}", .{ .err = .{
        .event = null,
        .kind = .unavailable,
        .fields_json = null,
        .message = "try later",
    } });
}

test "encode err with event and fields, message escaped" {
    try expectEncode(
        "{\"t\":\"error\",\"event\":4,\"kind\":\"conflict\",\"fields\":{\"rev\":3},\"message\":\"stale \\\"rev\\\"\\nretry\"}",
        .{ .err = .{
            .event = 4,
            .kind = .conflict,
            .fields_json = "{\"rev\":3}",
            .message = "stale \"rev\"\nretry",
        } },
    );
}

test "encode err kind wire names" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    inline for (@typeInfo(ErrKind).@"enum".field_names) |name| {
        const expected = try std.fmt.allocPrint(
            alloc,
            "{{\"t\":\"error\",\"kind\":\"{s}\",\"message\":\"x\"}}",
            .{name},
        );
        try expectEncode(expected, .{ .err = .{
            .event = null,
            .kind = @field(ErrKind, name),
            .fields_json = null,
            .message = "x",
        } });
    }
}

test "encode redirect escapes the target" {
    try expectEncode("{\"t\":\"redirect\",\"to\":\"/login?next=%2Finbox\"}", .{ .redirect = .{
        .to = "/login?next=%2Finbox",
    } });
}
