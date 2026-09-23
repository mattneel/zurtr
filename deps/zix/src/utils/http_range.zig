//! zix http range: the Range request header (RFC 7233), parsed once for every engine that serves
//! byte ranges.
//!
//! Split in two on purpose. `parseSpec` reads the header text and knows nothing about the file, so
//! a caller can tell a malformed header (which RFC 7233 section 3.1 says to IGNORE, serving the whole
//! representation) from a well-formed one that asks for bytes the file does not have (which is a 416
//! with a Content-Range of `bytes *\/length`). Collapsing both into one null makes that distinction
//! impossible, and answering 200 where 416 is required is the bug that shape invites.
//!
//! Only a single byte range is understood. A multi-range request parses as its first range, which is
//! allowed: a server may answer any subset, and multipart/byteranges is its own change.

const std = @import("std");

// --------------------------------------------------------- //

/// A range as the client wrote it, before the file size is known. A null end means "to the end".
pub const Spec = struct {
    start: u64,
    end: ?u64,
};

/// A range resolved against a known length, inclusive on both ends, always satisfiable.
pub const Range = struct {
    start: u64,
    end: u64,

    /// Bytes the range covers.
    pub fn length(self: Range) u64 {
        return self.end - self.start + 1;
    }
};

// --------------------------------------------------------- //

/// Read a `Range: bytes=start-end` header value.
///
/// Note:
/// - A suffix range (`bytes=-500`, meaning the LAST 500 bytes) is deliberately not supported and
///   parses as null, so the caller ignores the header and serves the whole file. Answering it would
///   need the length here, which is what keeps this function independent of the file.
///
/// Param:
/// value - []const u8 (raw header value, `bytes=` prefix included)
///
/// Return:
/// - Spec (syntactically valid, not yet checked against any length)
/// - null when the header is malformed, which the caller must treat as "no range at all"
pub fn parseSpec(value: []const u8) ?Spec {
    const trimmed = std.mem.trim(u8, value, " \t");
    if (!std.mem.startsWith(u8, trimmed, "bytes=")) return null;

    const spec = trimmed["bytes=".len..];
    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return null;

    // Only the first range of a multi-range request is read.
    const first_end = std.mem.indexOfScalar(u8, spec, ',') orelse spec.len;
    if (dash > first_end) return null;

    const start_text = spec[0..dash];
    const end_text = spec[dash + 1 .. first_end];
    if (start_text.len == 0) return null;

    const start = std.fmt.parseInt(u64, start_text, 10) catch return null;
    if (end_text.len == 0) return .{ .start = start, .end = null };

    const end = std.fmt.parseInt(u64, end_text, 10) catch return null;
    if (end < start) return null;

    return .{ .start = start, .end = end };
}

/// Clamp a spec to a known length.
///
/// Note:
/// - An end past the last byte is clamped rather than refused, which is what RFC 7233 section 2.1
///   requires: `bytes=0-999` against a 200-byte file is the whole file, not an error.
///
/// Return:
/// - Range (satisfiable, inclusive)
/// - null when the range cannot be satisfied, which is a 416 and NOT a 200
pub fn resolve(spec: Spec, total: u64) ?Range {
    if (total == 0) return null;
    if (spec.start >= total) return null;

    const end = if (spec.end) |asked| @min(asked, total - 1) else total - 1;

    return .{ .start = spec.start, .end = end };
}

/// Read and clamp in one step, for a caller that treats malformed and unsatisfiable the same way.
///
/// Return:
/// - Range (satisfiable, inclusive)
/// - null when the header is malformed OR the range is unsatisfiable
pub fn parse(value: []const u8, total: u64) ?Range {
    return resolve(parseSpec(value) orelse return null, total);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "zix http_range: parseSpec reads a closed range" {
    const spec = parseSpec("bytes=0-499").?;

    try testing.expectEqual(@as(u64, 0), spec.start);
    try testing.expectEqual(@as(u64, 499), spec.end.?);
}

test "zix http_range: parseSpec reads an open-ended range" {
    const spec = parseSpec("bytes=500-").?;

    try testing.expectEqual(@as(u64, 500), spec.start);
    try testing.expect(spec.end == null);
}

test "zix http_range: parseSpec tolerates surrounding whitespace" {
    const spec = parseSpec("  bytes=2-5 ").?;

    try testing.expectEqual(@as(u64, 2), spec.start);
    try testing.expectEqual(@as(u64, 5), spec.end.?);
}

test "zix http_range: parseSpec takes the first range of a multi-range request" {
    const spec = parseSpec("bytes=0-49,100-149").?;

    try testing.expectEqual(@as(u64, 0), spec.start);
    try testing.expectEqual(@as(u64, 49), spec.end.?);
}

test "zix http_range: parseSpec rejects what the caller must ignore" {
    // Wrong unit, no dash, no start, reversed, and non-numeric all mean "serve the whole file".
    try testing.expect(parseSpec("items=0-10") == null);
    try testing.expect(parseSpec("bytes=0") == null);
    try testing.expect(parseSpec("bytes=-500") == null);
    try testing.expect(parseSpec("bytes=10-5") == null);
    try testing.expect(parseSpec("bytes=a-b") == null);
    try testing.expect(parseSpec("") == null);
}

test "zix http_range: resolve clamps an end past the last byte" {
    const range = resolve(.{ .start = 0, .end = 999 }, 200).?;

    try testing.expectEqual(@as(u64, 0), range.start);
    try testing.expectEqual(@as(u64, 199), range.end);
    try testing.expectEqual(@as(u64, 200), range.length());
}

test "zix http_range: resolve fills an open end from the length" {
    const range = resolve(.{ .start = 100, .end = null }, 200).?;

    try testing.expectEqual(@as(u64, 100), range.start);
    try testing.expectEqual(@as(u64, 199), range.end);
    try testing.expectEqual(@as(u64, 100), range.length());
}

test "zix http_range: resolve refuses a start at or past the end" {
    // These are the 416 cases, distinct from a malformed header.
    try testing.expect(resolve(.{ .start = 200, .end = null }, 200) == null);
    try testing.expect(resolve(.{ .start = 201, .end = 300 }, 200) == null);
    try testing.expect(resolve(.{ .start = 0, .end = null }, 0) == null);
}

test "zix http_range: a single byte is a valid range" {
    const range = resolve(.{ .start = 5, .end = 5 }, 10).?;

    try testing.expectEqual(@as(u64, 1), range.length());
}

test "zix http_range: parse combines both steps" {
    const range = parse("bytes=2-5", 10).?;

    try testing.expectEqual(@as(u64, 2), range.start);
    try testing.expectEqual(@as(u64, 5), range.end);

    try testing.expect(parse("bytes=99-", 10) == null);
    try testing.expect(parse("garbage", 10) == null);
}
