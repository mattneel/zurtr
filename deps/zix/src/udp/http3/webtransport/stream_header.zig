//! zix WebTransport stream headers (draft-ietf-webtrans-http3-16 4.2 / 4.3).
//!
//! What:
//! - The bytes that open a WebTransport data stream: a unidirectional stream starts with the stream
//!   type 0x54, a bidirectional stream starts with the signal value 0x41, and each is followed by the
//!   session id (the CONNECT stream id the stream belongs to) as a variable-length integer. Everything
//!   after the header is application bytes, not HTTP/3 frames.
//! - The reader side of that contract, including the two rules that make the header trustworthy: the
//!   session id MUST name a client-initiated bidirectional stream (4.1), and the signal value is only
//!   legal as the first bytes of a stream (4.3).
//! - The header size, which a reliable reset has to deliver even when the payload is discarded (4.4).
//! - Pure buffer arithmetic, no io, no allocation. Proven against the layout and the validation rules
//!   in the tests below.

const std = @import("std");

const varint = @import("../varint.zig");
const wt = @import("draft.zig");

/// Which half of the stream space a WebTransport data stream belongs to (4.2 / 4.3).
pub const Kind = enum {
    /// A unidirectional stream: type 0x54, then the session id, then the application bytes. Both
    /// endpoints may open one.
    uni,
    /// A bidirectional stream: signal value 0x41, then the session id, then the application bytes.
    bidi,
};

/// A parsed stream header: how many bytes it took, and which session the stream belongs to.
pub const Header = struct {
    /// The session (CONNECT stream) id the stream is bound to.
    session_id: u64,
    /// Bytes the header occupied, so the caller knows where the application bytes start.
    len: usize,
};

/// The errors parsing a stream header raises.
pub const HeaderError = error{
    /// The header is not complete yet: more stream bytes are needed.
    ZixTruncated,
    /// The first value is not this kind's header (0x54 for a unidirectional stream, 0x41 for a
    /// bidirectional one). The stream belongs to another user of the QUIC stream space.
    ZixNotWebtransport,
    /// The session id does not name a client-initiated bidirectional stream: H3_ID_ERROR (4.1).
    ZixIdError,
};

/// Whether `id` may be a WebTransport session id (4.1): it MUST always correspond to a
/// client-initiated bidirectional stream id. The largest legal QUIC stream id is 2^62 - 1, so the
/// largest session id is 2^62 - 4.
pub fn isValidSessionId(id: u64) bool {
    return id % 4 == 0 and id <= max_session_id;
}

/// The largest legal session id: the largest stream id divisible by four.
pub const max_session_id: u64 = (1 << 62) - 4;

/// The stream type / signal value that opens a stream of `kind` (0x54 / 0x41).
pub fn openValue(kind: Kind) u64 {
    return switch (kind) {
        .uni => wt.uni_stream_type,
        .bidi => wt.wt_stream,
    };
}

/// The bytes a header of `kind` for `session_id` occupies on the wire.
pub fn headerLen(kind: Kind, session_id: u64) usize {
    return varint.encodedLen(openValue(kind)) + varint.encodedLen(session_id);
}

/// The reliable size a reset of a `kind` stream must deliver so the receiver can still associate the
/// stream with its session (4.4). A RESET_STREAM_AT with a smaller Reliable Size would drop the session
/// id with the rest of the discarded bytes.
pub fn reliableResetSize(kind: Kind, session_id: u64) u64 {
    return headerLen(kind, session_id);
}

/// Parse the header at the start of a WebTransport data stream (4.2 / 4.3).
///
/// Param:
/// kind - Kind (which stream space the caller is reading, decided by the stream id's two low bits)
/// buf - []const u8 (the stream bytes from offset 0)
///
/// Return:
/// - Header (the session id and the bytes the header took)
/// - error.ZixTruncated when the header is still arriving
/// - error.ZixNotWebtransport when the stream does not open with this kind's header
/// - error.ZixIdError when the session id is not a client-initiated bidirectional stream id
pub fn parse(kind: Kind, buf: []const u8) HeaderError!Header {
    const value_vi = varint.read(buf) catch return error.ZixTruncated;
    if (value_vi.value != openValue(kind)) return error.ZixNotWebtransport;

    const session_vi = varint.read(buf[value_vi.len..]) catch return error.ZixTruncated;
    if (!isValidSessionId(session_vi.value)) return error.ZixIdError;

    return .{
        .session_id = session_vi.value,
        .len = value_vi.len + session_vi.len,
    };
}

/// Write a header of `kind` for `session_id`. Returns the bytes written, or null when the session id
/// is not a legal one or the header does not fit.
pub fn write(kind: Kind, out: []u8, session_id: u64) ?usize {
    if (!isValidSessionId(session_id)) return null;

    const needed = headerLen(kind, session_id);
    if (needed > out.len) return null;

    var pos: usize = 0;
    pos += varint.write(out[pos..], openValue(kind));
    pos += varint.write(out[pos..], session_id);

    return pos;
}

/// Whether a stream id belongs to a WebTransport data stream of `kind`, given that the endpoint already
/// knows which session opened it.
///
/// Note:
/// - A server opens bidirectional ids 1, 5, 9 (1 mod 4) and unidirectional ids 3, 7, 11 (3 mod 4), the
///   client opens 0, 4, 8 (0 mod 4) and 2, 6, 10 (2 mod 4) (RFC 9000 2.1). A client's WebTransport
///   bidirectional streams are those client-initiated request streams the client converted with the
///   0x41 signal, so the id alone cannot tell a data stream from a request stream: the header does.
pub fn idMatchesKind(kind: Kind, id: u64) bool {
    return switch (kind) {
        .uni => id & 0x02 != 0,
        .bidi => id & 0x02 == 0,
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix webtransport: 4.2 / 4.3 the stream header layout" {
    var buf: [16]u8 = undefined;

    // Both type values are past 63, so each takes the 2-byte QUIC varint form (RFC 9000 16): the type
    // or signal value, then the session id.
    const bidi_len = write(.bidi, &buf, 0).?;
    try std.testing.expectEqualSlices(u8, &hexBytes("4041" ++ "00"), buf[0..bidi_len]);
    const uni_len = write(.uni, &buf, 0).?;
    try std.testing.expectEqualSlices(u8, &hexBytes("4054" ++ "00"), buf[0..uni_len]);

    // Session 4 (quarter 1) and a session id that needs a 2-byte varint of its own.
    const session4 = write(.uni, &buf, 4).?;
    try std.testing.expectEqualSlices(u8, &hexBytes("4054" ++ "04"), buf[0..session4]);
    const big = write(.bidi, &buf, 64).?;
    try std.testing.expectEqualSlices(u8, &hexBytes("4041" ++ "4040"), buf[0..big]);

    // The parsed header reports the session and where the application bytes start.
    const parsed = try parse(.bidi, buf[0..big]);
    try std.testing.expectEqual(@as(u64, 64), parsed.session_id);
    try std.testing.expectEqual(big, parsed.len);
    try std.testing.expectEqual(@as(usize, 4), headerLen(.bidi, 64));

    // A peer is free to encode the same values on more bytes than the minimum (RFC 9000 16), so the
    // reader takes the non-minimal form too.
    const non_minimal = hexBytes("80000041" ++ "80000000");
    const wide = try parse(.bidi, &non_minimal);
    try std.testing.expectEqual(@as(u64, 0), wide.session_id);
    try std.testing.expectEqual(@as(usize, 8), wide.len);
}

test "zix webtransport: a stream that opens with another protocol is not a WebTransport stream" {
    // An ordinary HTTP/3 request stream opens with a HEADERS frame (0x01): it is not a WT data stream.
    try std.testing.expectError(error.ZixNotWebtransport, parse(.bidi, &hexBytes("01")));

    // The two kinds are not interchangeable: the unidirectional type on a bidirectional stream is not
    // a bidirectional header.
    try std.testing.expectError(error.ZixNotWebtransport, parse(.bidi, &hexBytes("4054" ++ "00")));
    try std.testing.expectError(error.ZixNotWebtransport, parse(.uni, &hexBytes("4041" ++ "00")));

    // A header still arriving is not a wrong protocol, it is a request for more bytes.
    try std.testing.expectError(error.ZixTruncated, parse(.bidi, ""));
    try std.testing.expectError(error.ZixTruncated, parse(.uni, &hexBytes("54")));
    try std.testing.expectError(error.ZixTruncated, parse(.uni, &hexBytes("4054")));
    try std.testing.expectError(error.ZixTruncated, parse(.bidi, &hexBytes("4041" ++ "40")));
}

test "zix webtransport: 4.1 the session id must be a client-initiated bidirectional stream id" {
    // 0, 4, 8 are session ids; 1, 2, 3, 5, 6, 7 are stream ids of another kind.
    try std.testing.expect(isValidSessionId(0));
    try std.testing.expect(isValidSessionId(4));
    try std.testing.expect(isValidSessionId(8));
    try std.testing.expect(!isValidSessionId(1));
    try std.testing.expect(!isValidSessionId(2));
    try std.testing.expect(!isValidSessionId(3));
    try std.testing.expect(!isValidSessionId(6));

    // The ceiling is the largest stream id a QUIC varint can carry, less its low two bits.
    try std.testing.expect(isValidSessionId(max_session_id));
    try std.testing.expect(!isValidSessionId(max_session_id + 4));
    try std.testing.expect(!isValidSessionId(std.math.maxInt(u64)));

    // A stream header naming a server-initiated or unidirectional stream is H3_ID_ERROR (4.1).
    var buf: [16]u8 = undefined;
    const bad_len = write(.bidi, &buf, 4).?;
    buf[bad_len - 1] = 0x01; // session id 1: a server-initiated bidirectional id
    try std.testing.expectError(error.ZixIdError, parse(.bidi, buf[0..bad_len]));

    // Writing refuses an illegal session id rather than putting it on the wire.
    try std.testing.expect(write(.uni, &buf, 7) == null);
}

test "zix webtransport: 4.4 a reliable reset covers at least the header" {
    // The reset has to deliver the header, or the receiver cannot tell which session the stream
    // belonged to (4.4).
    // Two bytes of type or signal value, then the session id varint.
    try std.testing.expectEqual(@as(u64, 3), reliableResetSize(.bidi, 0));
    try std.testing.expectEqual(@as(u64, 3), reliableResetSize(.uni, 0));
    try std.testing.expectEqual(@as(u64, 4), reliableResetSize(.bidi, 64));
    try std.testing.expectEqual(@as(u64, 6), reliableResetSize(.uni, 16384));

    // The reported size is exactly what the encoder writes for that header.
    var buf: [16]u8 = undefined;
    for ([_]u64{ 0, 4, 64, 16384, max_session_id }) |session_id| {
        for ([_]Kind{ .bidi, .uni }) |kind| {
            const written = write(kind, &buf, session_id).?;
            try std.testing.expectEqual(@as(u64, written), reliableResetSize(kind, session_id));
            try std.testing.expectEqual(written, (try parse(kind, buf[0..written])).len);
        }
    }
}

test "zix webtransport: the stream id space a data stream can live in" {
    // Bidirectional data streams: both endpoints open them (0 mod 4 for the client, 1 mod 4 for the
    // server). Unidirectional data streams: 2 mod 4 and 3 mod 4.
    try std.testing.expect(idMatchesKind(.bidi, 0));
    try std.testing.expect(idMatchesKind(.bidi, 4));
    try std.testing.expect(idMatchesKind(.bidi, 1));
    try std.testing.expect(!idMatchesKind(.bidi, 2));
    try std.testing.expect(!idMatchesKind(.bidi, 3));

    try std.testing.expect(idMatchesKind(.uni, 2));
    try std.testing.expect(idMatchesKind(.uni, 3));
    try std.testing.expect(!idMatchesKind(.uni, 0));
    try std.testing.expect(!idMatchesKind(.uni, 1));
}
