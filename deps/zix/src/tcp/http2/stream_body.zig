//! Whether an HTTP/2 request body is whole: the content-length a stream declared against the DATA
//! payload bytes that actually arrived.
//!
//! What:
//! - A request carrying `content-length` promises exactly that many DATA payload bytes. RFC 9113
//!   8.1.1 makes the request malformed when that promise is broken, and a malformed request is a
//!   stream error of type PROTOCOL_ERROR. Without the check, a peer that declares 100 bytes, sends
//!   40, and sets END_STREAM has its short body served as though it were whole.
//!
//! Note:
//! - The count compared here is the DATA payload accumulated for the stream, before any
//!   content-encoding is undone: content-length describes the bytes on the wire, not what they
//!   decompress to.
//! - A request with no content-length is whole at END_STREAM by definition. That is the ordinary h2
//!   shape: a streaming client declares nothing and ends the stream instead.
//! - Shared by every h2 and gRPC state machine (blocking and multiplexed, cleartext and TLS), so one
//!   rule answers for all of the dispatch models.

const std = @import("std");
const hpack = @import("hpack.zig");

/// Longest decimal a u64 byte count can occupy, so an absurd run of digits is rejected on length
/// before any arithmetic runs.
const MAX_DIGITS: usize = 20;

/// Length of the header name this module looks for, checked before the compare so a request's other
/// headers cost one integer test each.
const CONTENT_LENGTH_NAME_LEN: usize = "content-length".len;

/// What a request's headers promise about its body length.
pub const Declared = union(enum) {
    /// No content-length header. The body ends where END_STREAM says it does.
    ABSENT,
    /// The exact DATA payload byte count the peer promised.
    LENGTH: u64,
    /// A content-length that can not be honoured: not a plain decimal number, or two of them
    /// disagreeing. No arriving body satisfies it.
    BROKEN,
};

/// Parse a header value as a plain decimal byte count. Strict on purpose: an HTTP field value here is
/// digits and nothing else, where a general-purpose integer parser also accepts a sign and digit
/// separators, which would let `+40` or `1_0` pass as a length.
///
/// Param:
/// value - []const u8 (the raw header value)
///
/// Return:
/// - ?u64 (the count, or null when the value is not a bare decimal number or overflows u64)
fn parseDecimal(value: []const u8) ?u64 {
    if (value.len == 0 or value.len > MAX_DIGITS) return null;

    var total: u64 = 0;
    for (value) |digit| {
        if (digit < '0' or digit > '9') return null;

        total = std.math.mul(u64, total, 10) catch return null;
        total = std.math.add(u64, total, digit - '0') catch return null;
    }

    return total;
}

/// Read the content-length a request declared.
///
/// Note:
/// - Repeats of the same value count as one declaration, which is what a proxy that re-emits the
///   header produces. Two different values are unresolvable and report BROKEN.
///
/// Param:
/// headers - []const hpack.Header (the stream's decoded request headers)
///
/// Return:
/// - Declared.ABSENT when no content-length header is present
/// - Declared.LENGTH when one usable value was declared
/// - Declared.BROKEN when a value is not a bare decimal number, or two declared values disagree
pub fn declared(headers: []const hpack.Header) Declared {
    var found: ?u64 = null;

    for (headers) |header| {
        if (header.name.len != CONTENT_LENGTH_NAME_LEN) continue;
        if (!std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;

        const value = parseDecimal(header.value) orelse return .BROKEN;
        if (found) |first| {
            if (first != value) return .BROKEN;
        } else {
            found = value;
        }
    }

    if (found) |value| return .{ .LENGTH = value };

    return .ABSENT;
}

/// Whether the DATA bytes that arrived complete the body the request declared. Asked once, at the
/// moment END_STREAM closes the request side of a stream, so a handler is never handed a body that
/// is short of (or past) what its own headers promised.
///
/// Usage:
/// ```zig
/// if (!stream_body.isWhole(stream.headers[0..stream.header_count], stream.body_len)) {
///     frame.sendRstStreamFD(fd, stream.id, frame.ERR_PROTOCOL_ERROR) catch {};
///     return;
/// }
/// ```
///
/// Param:
/// headers - []const hpack.Header (the stream's decoded request headers)
/// received - usize (DATA payload bytes accumulated for the stream, before any decompression)
///
/// Return:
/// - bool (true when the request may be served, false when it is malformed and its stream must be reset)
pub fn isWhole(headers: []const hpack.Header, received: usize) bool {
    return switch (declared(headers)) {
        .ABSENT => true,
        .LENGTH => |promised| promised == received,
        .BROKEN => false,
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix http2: a request without content-length is whole at any received count" {
    const headers = [_]hpack.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/upload" },
    };

    try std.testing.expectEqual(Declared.ABSENT, declared(&headers));
    try std.testing.expect(isWhole(&headers, 0));
    try std.testing.expect(isWhole(&headers, 4096));
}

test "zix http2: a declared content-length is whole only at the exact received count" {
    const headers = [_]hpack.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = "content-length", .value = "100" },
    };

    try std.testing.expectEqual(@as(u64, 100), declared(&headers).LENGTH);
    try std.testing.expect(isWhole(&headers, 100));

    // short of the promise (the truncated body) and past it are both malformed
    try std.testing.expect(!isWhole(&headers, 99));
    try std.testing.expect(!isWhole(&headers, 0));
    try std.testing.expect(!isWhole(&headers, 101));
}

test "zix http2: content-length zero is whole with no body and malformed with one" {
    const headers = [_]hpack.Header{
        .{ .name = "content-length", .value = "0" },
    };

    try std.testing.expectEqual(@as(u64, 0), declared(&headers).LENGTH);
    try std.testing.expect(isWhole(&headers, 0));
    try std.testing.expect(!isWhole(&headers, 1));
}

test "zix http2: a content-length that is not a bare decimal is broken" {
    // a sign, a digit separator, whitespace, a unit suffix, and an empty value are all rejected:
    // each would otherwise let a length through that the wire never meant
    const rejected = [_][]const u8{ "+40", "-40", "1_0", " 40", "40 ", "40b", "0x28", "", "abc" };

    for (rejected) |value| {
        const headers = [_]hpack.Header{.{ .name = "content-length", .value = value }};

        try std.testing.expectEqual(Declared.BROKEN, declared(&headers));
        try std.testing.expect(!isWhole(&headers, 40));
    }
}

test "zix http2: a content-length past u64 is broken rather than wrapping" {
    const headers = [_]hpack.Header{
        .{ .name = "content-length", .value = "99999999999999999999" },
    };

    try std.testing.expectEqual(Declared.BROKEN, declared(&headers));
    try std.testing.expect(!isWhole(&headers, 0));
}

test "zix http2: repeated content-length agrees once and is broken when the values differ" {
    const agreeing = [_]hpack.Header{
        .{ .name = "content-length", .value = "12" },
        .{ .name = "content-length", .value = "12" },
    };
    try std.testing.expectEqual(@as(u64, 12), declared(&agreeing).LENGTH);
    try std.testing.expect(isWhole(&agreeing, 12));

    const disagreeing = [_]hpack.Header{
        .{ .name = "content-length", .value = "12" },
        .{ .name = "content-length", .value = "13" },
    };
    try std.testing.expectEqual(Declared.BROKEN, declared(&disagreeing));
    try std.testing.expect(!isWhole(&disagreeing, 12));
    try std.testing.expect(!isWhole(&disagreeing, 13));
}

test "zix http2: the content-length name is matched without regard to case" {
    const headers = [_]hpack.Header{
        .{ .name = "Content-Length", .value = "7" },
    };

    try std.testing.expectEqual(@as(u64, 7), declared(&headers).LENGTH);
    try std.testing.expect(isWhole(&headers, 7));
}

test "zix http2: a header whose name is the same length as content-length is not mistaken for it" {
    const headers = [_]hpack.Header{
        .{ .name = "content-lengthx", .value = "9" },
        .{ .name = "if-none-match!", .value = "9" },
    };

    try std.testing.expectEqual(Declared.ABSENT, declared(&headers));
    try std.testing.expect(isWhole(&headers, 0));
}

test "zix http2: an empty header list declares nothing" {
    const headers = [_]hpack.Header{};

    try std.testing.expectEqual(Declared.ABSENT, declared(&headers));
    try std.testing.expect(isWhole(&headers, 0));
}
