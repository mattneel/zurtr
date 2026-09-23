//! zix WebTransport over HTTP/3 wire vocabulary: the draft-16 codepoints, the deployed draft-07 alias
//! set, and the mapping between WebTransport application errors and the HTTP/3 error range that
//! carries them.
//!
//! What:
//! - The negotiation surface (3.1 / 3.2 / 9.1 / 9.2): the extended CONNECT upgrade tokens, the
//!   SETTINGS identifiers a WebTransport-capable connection exchanges, and the stream / frame / capsule
//!   / error codepoints the binding uses.
//! - The settings a peer must have sent before a session is legal, as a table per dialect.
//! - The WebTransport application error mapping (4.4): the app error space is an unsigned 32-bit
//!   integer, carried on the wire as a codepoint inside the reserved WT_APPLICATION_ERROR range with
//!   the HTTP/3 grease codepoints (0x1f * N + 0x21) skipped.
//! - Pure constants and pure functions, no io, no allocation. Proven against the spec in the tests below.
//!
//! Note:
//! - Two dialects are live on the wire. draft-16 (the current revision) renamed both the upgrade token
//!   (`webtransport-h3`) and the server's support setting (SETTINGS_WT_ENABLED 0x2c7cf000); the deployed
//!   dialect shipped in browsers and in the aioquic client still sends `webtransport` with
//!   SETTINGS_ENABLE_WEBTRANSPORT (0x2b603742). The token in the CONNECT request is what picks the
//!   dialect, so one server can speak both: the server advertises both settings codepoints, and a peer
//!   ignores the one it does not know (RFC 9114 7.2.4.1).

const std = @import("std");

/// Which revision of the binding a session speaks. The upgrade token in the CONNECT request selects it.
pub const Dialect = enum {
    /// draft-ietf-webtrans-http3-16: token `webtransport-h3`, SETTINGS_WT_ENABLED, session-level flow
    /// control, RESET_STREAM_AT on data stream resets.
    draft16,
    /// draft-ietf-webtrans-http3-02..07: token `webtransport`, SETTINGS_ENABLE_WEBTRANSPORT, no
    /// session-level flow control, plain RESET_STREAM.
    draft07,
};

/// The HTTP/3 settings this binding reads and writes (RFC 9114 7.2.4.1). Values outside the reserved
/// grep range are ignored by a peer that does not know them, which is what lets one SETTINGS frame
/// carry both dialects' codepoints.
pub const setting = struct {
    /// RFC 9220: the peer accepts extended CONNECT (a CONNECT request carrying `:protocol`).
    pub const enable_connect_protocol: u64 = 0x08;
    /// RFC 9297 2.1.1: the peer accepts HTTP datagrams, and so QUIC DATAGRAM frames.
    pub const h3_datagram: u64 = 0x33;
    /// draft-16: the peer is WebTransport-capable. Value 1 for this revision. A client that sends this
    /// also identifies its draft version (7.1), because each revision owns a distinct codepoint.
    pub const wt_enabled: u64 = 0x2c7cf000;
    /// draft-16 5.5.1: initial per-session unidirectional stream limit, replacing the WT_MAX_STREAMS
    /// capsule for the connection's first sessions.
    pub const wt_initial_max_streams_uni: u64 = 0x2b64;
    /// draft-16 5.5.2: initial per-session bidirectional stream limit.
    pub const wt_initial_max_streams_bidi: u64 = 0x2b65;
    /// draft-16 5.5.3: initial per-session data limit, replacing the WT_MAX_DATA capsule until one is sent.
    pub const wt_initial_max_data: u64 = 0x2b61;
    /// draft-02: the peer is WebTransport-capable. Superseded by the draft-07 setting below, still sent
    /// by the deployed clients.
    pub const enable_webtransport: u64 = 0x2b603742;
    /// draft-07 3.4: WebTransport-capable, and the number of concurrent sessions the server accepts.
    /// Still the codepoint a browser-built server advertises.
    pub const webtransport_max_sessions: u64 = 0xc671706a;
};

/// The upgrade tokens an extended CONNECT carries in `:protocol` (9.1).
pub const upgrade_token = struct {
    pub const draft16: []const u8 = "webtransport-h3";
    pub const draft07: []const u8 = "webtransport";
};

/// The dialect a `:protocol` value selects, or null for a protocol this server does not implement
/// (an unknown token is answered 501, RFC 9220 3).
pub fn dialectForToken(protocol: []const u8) ?Dialect {
    if (std.mem.eql(u8, protocol, upgrade_token.draft16)) return .draft16;
    if (std.mem.eql(u8, protocol, upgrade_token.draft07)) return .draft07;

    return null;
}

/// The token that selects `dialect`, for a server-initiated CONNECT (an intermediary) or a test.
pub fn tokenFor(dialect: Dialect) []const u8 {
    return switch (dialect) {
        .draft16 => upgrade_token.draft16,
        .draft07 => upgrade_token.draft07,
    };
}

// --------------------------------------------------------------- //

/// The unidirectional stream type that carries a WebTransport stream (4.2): the type, then the session
/// id, then the application bytes.
pub const uni_stream_type: u64 = 0x54;

/// The bidirectional stream signal value (4.3), registered as frame type WT_STREAM. It is not a proper
/// HTTP/3 frame: it has no length, and the rest of the stream after it is application bytes. A request
/// stream that opens with it stops being an HTTP/3 request stream.
pub const wt_stream: u64 = 0x41;

/// The HTTP/3 error codes this binding adds (draft-16 9.5). draft-07 registered the first two under
/// WEBTRANSPORT_* names with the same values.
pub const error_code = struct {
    /// A data stream arrived with no session to attach it to and the buffer was full.
    pub const wt_buffered_stream_rejected: u64 = 0x3994bd84;
    /// A data stream was aborted because its session ended. Also the codea peer uses on the CONNECT
    /// stream to say it has stopped reading.
    pub const wt_session_gone: u64 = 0x170d7b68;
    /// A session-level flow control rule was broken (5.6.2 / 5.6.4).
    pub const wt_flow_control_error: u64 = 0x045d4487;
    /// Application protocol negotiation failed (3.3).
    pub const wt_alpn_error: u64 = 0x0817b3dd;
    /// The connection lacks a setting or transport parameter WebTransport requires (3.1).
    pub const wt_requirements_not_met: u64 = 0x212c0d48;
};

/// The capsule types this binding uses (9.6). The flow control capsules only exist in draft-16.
pub const capsule = struct {
    /// draft-16 WT_CLOSE_SESSION / draft-07 CLOSE_WEBTRANSPORT_SESSION (6).
    pub const close_session: u64 = 0x2843;
    /// draft-16 WT_DRAIN_SESSION / draft-07 DRAIN_WEBTRANSPORT_SESSION (4.7).
    pub const drain_session: u64 = 0x78ae;
    /// draft-16 WT_MAX_DATA (5.6.4).
    pub const max_data: u64 = 0x190B4D3D;
    /// draft-16 WT_DATA_BLOCKED (5.6.5).
    pub const data_blocked: u64 = 0x190B4D41;
    /// draft-16 WT_MAX_STREAMS, bidirectional (5.6.2).
    pub const max_streams_bidi: u64 = 0x190B4D3F;
    /// draft-16 WT_MAX_STREAMS, unidirectional (5.6.2).
    pub const max_streams_uni: u64 = 0x190B4D40;
    /// draft-16 WT_STREAMS_BLOCKED, bidirectional (5.6.3).
    pub const streams_blocked_bidi: u64 = 0x190B4D43;
    /// draft-16 WT_STREAMS_BLOCKED, unidirectional (5.6.3).
    pub const streams_blocked_uni: u64 = 0x190B4D44;
};

/// The most streams a WT_MAX_STREAMS / WT_STREAMS_BLOCKED capsule may carry: a larger value cannot
/// correspond to any encodable stream id, so it is a session flow control error (5.6.2).
pub const max_stream_count: u64 = 1 << 60;

/// The largest Application Error Message a WT_CLOSE_SESSION capsule may carry (6, 8192 bits).
pub const max_close_message: usize = 1024;

/// Whether a capsule type is one of the draft-16 flow control capsules (5.6). An endpoint that has not
/// enabled flow control MUST ignore them, and an intermediary MUST consume them.
pub fn isFlowControlCapsule(capsule_type: u64) bool {
    return switch (capsule_type) {
        capsule.max_data,
        capsule.data_blocked,
        capsule.max_streams_bidi,
        capsule.max_streams_uni,
        capsule.streams_blocked_bidi,
        capsule.streams_blocked_uni,
        => true,
        else => false,
    };
}

/// Whether a capsule carries stream limits rather than a data limit, and which direction it limits.
pub const StreamKind = enum { bidi, uni };

/// The stream kind a WT_MAX_STREAMS or WT_STREAMS_BLOCKED capsule speaks about, or null for a capsule
/// that is not one of the two.
pub fn streamKindOf(capsule_type: u64) ?StreamKind {
    return switch (capsule_type) {
        capsule.max_streams_bidi, capsule.streams_blocked_bidi => .bidi,
        capsule.max_streams_uni, capsule.streams_blocked_uni => .uni,
        else => null,
    };
}

// --------------------------------------------------------------- //
// Application error mapping (4.4).
// --------------------------------------------------------------- //

/// The first codepoint of the WT_APPLICATION_ERROR range (9.5).
pub const app_error_first: u64 = 0x52e4a40fa8db;

/// The last codepoint of the WT_APPLICATION_ERROR range (9.5).
pub const app_error_last: u64 = 0x52e5ac983162;

/// The gap between two application error codepoints: the mapping skips one codepoint every 30 steps so
/// it never lands on an HTTP/3 grease codepoint (0x1f * N + 0x21).
const app_error_gap: u64 = 0x1e;

/// Map a WebTransport application error code (an unsigned 32-bit integer) into the HTTP/3 error range
/// the wire carries it in (4.4).
///
/// Note:
/// - The result never lands on a reserved grease codepoint, which is what the division by 0x1e buys:
///   the HTTP/3 codepoints of shape 0x1f * N + 0x21 are skipped rather than used as carriers.
///
/// Param:
/// code - u32 (the application error code, the whole unsigned 32-bit space is legal)
///
/// Return:
/// - u64 (the HTTP/3 error code to put on the wire, inside WT_APPLICATION_ERROR)
pub fn encodeAppError(code: u32) u64 {
    const n: u64 = code;

    return app_error_first + n + n / app_error_gap;
}

/// Map an HTTP/3 error code back to a WebTransport application error code (4.4). Null when the code is
/// outside the WT_APPLICATION_ERROR range or is one of the reserved grease codepoints inside it, which
/// the spec excludes from the mapping.
///
/// Note:
/// - A stream reset carries an error code the peer chose. A code outside the range is still a reset, so
///   the caller delivers the reset without an application code rather than treating it as an error.
///
/// Param:
/// http_code - u64 (the error code from a RESET_STREAM / RESET_STREAM_AT / STOP_SENDING frame)
///
/// Return:
/// - ?u32 (the application error code, or null when the code carries none)
pub fn decodeAppError(http_code: u64) ?u32 {
    if (http_code < app_error_first or http_code > app_error_last) return null;

    // The reserved codepoints inside the range are not part of the mapping (4.4).
    if (isReservedErrorCode(http_code)) return null;

    const shifted = http_code - app_error_first;
    const app = shifted - shifted / (app_error_gap + 1);

    return std.math.cast(u32, app);
}

/// Whether an HTTP/3 error code is in the reserved (grease) range 0x1f * N + 0x21, which a receiver
/// MUST treat as equivalent to H3_NO_ERROR (RFC 9114 8.1).
pub fn isReservedErrorCode(code: u64) bool {
    if (code < 0x21) return false;

    return (code - 0x21) % 0x1f == 0;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix webtransport: the upgrade tokens select the dialect" {
    try std.testing.expectEqual(Dialect.draft16, dialectForToken("webtransport-h3").?);
    try std.testing.expectEqual(Dialect.draft07, dialectForToken("webtransport").?);

    // An unknown token is not this server's protocol: the caller answers 501 (RFC 9220 3).
    try std.testing.expect(dialectForToken("websocket") == null);
    try std.testing.expect(dialectForToken("") == null);

    // The deployed token must not be a prefix match for the new one (or the reverse).
    try std.testing.expect(dialectForToken("webtransport-h3x") == null);
    try std.testing.expectEqualStrings("webtransport-h3", tokenFor(.draft16));
    try std.testing.expectEqualStrings("webtransport", tokenFor(.draft07));
}

test "zix webtransport: draft-16 codepoints match the IANA registrations" {
    // 9.2 settings, 9.3 frame type, 9.4 stream type, 9.5 error codes, 9.6 capsule types.
    try std.testing.expectEqual(@as(u64, 0x2c7cf000), setting.wt_enabled);
    try std.testing.expectEqual(@as(u64, 0x2b64), setting.wt_initial_max_streams_uni);
    try std.testing.expectEqual(@as(u64, 0x2b65), setting.wt_initial_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 0x2b61), setting.wt_initial_max_data);
    try std.testing.expectEqual(@as(u64, 0x08), setting.enable_connect_protocol);
    try std.testing.expectEqual(@as(u64, 0x33), setting.h3_datagram);

    try std.testing.expectEqual(@as(u64, 0x41), wt_stream);
    try std.testing.expectEqual(@as(u64, 0x54), uni_stream_type);

    try std.testing.expectEqual(@as(u64, 0x3994bd84), error_code.wt_buffered_stream_rejected);
    try std.testing.expectEqual(@as(u64, 0x170d7b68), error_code.wt_session_gone);
    try std.testing.expectEqual(@as(u64, 0x045d4487), error_code.wt_flow_control_error);
    try std.testing.expectEqual(@as(u64, 0x0817b3dd), error_code.wt_alpn_error);
    try std.testing.expectEqual(@as(u64, 0x212c0d48), error_code.wt_requirements_not_met);

    try std.testing.expectEqual(@as(u64, 0x2843), capsule.close_session);
    try std.testing.expectEqual(@as(u64, 0x78ae), capsule.drain_session);
    try std.testing.expectEqual(@as(u64, 0x190B4D3F), capsule.max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 0x190B4D40), capsule.max_streams_uni);
    try std.testing.expectEqual(@as(u64, 0x190B4D3D), capsule.max_data);
    try std.testing.expectEqual(@as(u64, 0x190B4D41), capsule.data_blocked);
    try std.testing.expectEqual(@as(u64, 0x190B4D43), capsule.streams_blocked_bidi);
    try std.testing.expectEqual(@as(u64, 0x190B4D44), capsule.streams_blocked_uni);
}

test "zix webtransport: the deployed draft-07 codepoints stay accepted" {
    try std.testing.expectEqual(@as(u64, 0x2b603742), setting.enable_webtransport);
    try std.testing.expectEqual(@as(u64, 0xc671706a), setting.webtransport_max_sessions);

    // The two dialects share the stream types, the close capsule, and the application error range, so
    // only the token and the support setting differ on the wire.
    try std.testing.expectEqual(@as(u64, 0x54), uni_stream_type);
    try std.testing.expectEqual(@as(u64, 0x41), wt_stream);
    try std.testing.expectEqual(@as(u64, 0x2843), capsule.close_session);
}

test "zix webtransport: 4.4 application errors map to non-reserved HTTP/3 codes and back" {
    // The ends of the application range are pinned by the spec's own pseudocode.
    try std.testing.expectEqual(app_error_first, encodeAppError(0));
    try std.testing.expectEqual(app_error_last, encodeAppError(0xffffffff));
    try std.testing.expectEqual(@as(u32, 0), decodeAppError(encodeAppError(0)).?);
    try std.testing.expectEqual(@as(u32, 0xffffffff), decodeAppError(encodeAppError(0xffffffff)).?);

    // The two framing codes a browser uses most must survive the round trip.
    try std.testing.expectEqual(@as(u32, 0), decodeAppError(encodeAppError(0)).?);
    try std.testing.expectEqual(@as(u32, 42), decodeAppError(encodeAppError(42)).?);

    // A code outside the range is not an application error, including the HTTP/3 codes themselves.
    try std.testing.expect(decodeAppError(0x0100) == null);
    try std.testing.expect(decodeAppError(error_code.wt_session_gone) == null);
    try std.testing.expect(decodeAppError(app_error_first - 1) == null);
    try std.testing.expect(decodeAppError(app_error_last + 1) == null);
}

test "zix webtransport: the application mapping skips every grease codepoint" {
    // Exhaustive over the small codes, then a sweep of the space: no encoded code may be a reserved
    // codepoint, and every encoded code must decode back to what it came from.
    var code: u32 = 0;
    while (code < 4096) : (code += 1) {
        const encoded = encodeAppError(code);
        try std.testing.expect(!isReservedErrorCode(encoded));
        try std.testing.expectEqual(code, decodeAppError(encoded).?);
    }

    // Including the 32-bit ends and the neighbourhood of each grease codepoint inside the range.
    const probes = [_]u32{ 0, 1, 29, 30, 31, 32, 59, 60, 61, 0x7fffffff, 0xfffffffe, 0xffffffff };
    for (probes) |probe| {
        const encoded = encodeAppError(probe);
        try std.testing.expect(!isReservedErrorCode(encoded));
        try std.testing.expectEqual(probe, decodeAppError(encoded).?);
    }
}

test "zix webtransport: a reserved codepoint inside the range carries no application error" {
    // 0x1f * 1 + 0x21 = 0x40 sits far below the range, so build one inside it: the first grease
    // codepoint at or past app_error_first.
    var found: ?u64 = null;
    var n: u64 = 0;
    while (found == null and n < 1 << 20) : (n += 1) {
        const candidate = app_error_first + n;
        if (isReservedErrorCode(candidate)) found = candidate;
    }

    const reserved = found.?;
    try std.testing.expect(decodeAppError(reserved) == null);

    // The codepoint just before it is a legal carrier, so the skip is a gap and not an off-by-one.
    try std.testing.expect(decodeAppError(reserved - 1) != null);
}

test "zix webtransport: the flow control capsules are classified" {
    try std.testing.expect(isFlowControlCapsule(capsule.max_data));
    try std.testing.expect(isFlowControlCapsule(capsule.data_blocked));
    try std.testing.expect(isFlowControlCapsule(capsule.max_streams_bidi));
    try std.testing.expect(isFlowControlCapsule(capsule.streams_blocked_uni));

    // CLOSE / DRAIN are session signals, not flow control: an intermediary forwards them.
    try std.testing.expect(!isFlowControlCapsule(capsule.close_session));
    try std.testing.expect(!isFlowControlCapsule(capsule.drain_session));

    try std.testing.expectEqual(StreamKind.bidi, streamKindOf(capsule.max_streams_bidi).?);
    try std.testing.expectEqual(StreamKind.uni, streamKindOf(capsule.max_streams_uni).?);
    try std.testing.expectEqual(StreamKind.bidi, streamKindOf(capsule.streams_blocked_bidi).?);
    try std.testing.expectEqual(StreamKind.uni, streamKindOf(capsule.streams_blocked_uni).?);
    try std.testing.expect(streamKindOf(capsule.close_session) == null);
    try std.testing.expect(streamKindOf(capsule.max_data) == null);
}
