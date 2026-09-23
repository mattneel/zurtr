//! zix HTTP/3 application framing and semantics (RFC 9114, Layer H).
//!
//! What:
//! - The stream and frame structure (6.2 / 7.2): the control stream type, the SETTINGS-first rule,
//!   the frame-per-stream permission matrix, and the legal frame order within a request.
//! - Message validation (4.1.2 / 4.2 / 4.3): lowercase field names, mandatory and prohibited
//!   pseudo-headers, pseudo-before-regular ordering, and Content-Length vs the DATA sum.
//! - The WebTransport binding's surface over the same framing (RFC 9220 3, RFC 8441 4, RFC 9297
//!   2.1.1, draft-ietf-webtrans-http3-16 3.1 / 3.2 / 5.5): the extended CONNECT rules that ride on
//!   `:protocol`, the SETTINGS a server writes and a client's SETTINGS are read back from, and which
//!   stream types already belong to HTTP/3.
//! - Connection lifecycle and the error vocabulary (5.2 / 7.2.7 / 8.1): GOAWAY monotonicity,
//!   MAX_PUSH_ID / PUSH_PROMISE direction, and the seventeen error codes plus the grease range.
//! - Pure framing and validation logic, no crypto. Proven against the RFC rules in the tests below.
//!
//! Note:
//! - Implemented and unit-tested, but not wired into the serve path yet (deferred). The live request
//!   path handles the minimal HTTP/3 framing inline in dispatch/common.zig. Wiring the control
//!   stream, GOAWAY, and message validation is v2 work.

const std = @import("std");

const varint = @import("varint.zig");
const draft = @import("webtransport/draft.zig");

/// The HTTP/3 frame types (RFC 9114 7.2). The values are sparse: 0x02 and 0x06 are reserved or used
/// elsewhere, so the set is explicit.
pub const FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0d,
};

/// The HTTP/3 unidirectional stream types (RFC 9114 6.2, QPACK 4.2).
pub const control_stream: u64 = 0x00;
pub const push_stream: u64 = 0x01;
pub const qpack_encoder_stream: u64 = 0x02;
pub const qpack_decoder_stream: u64 = 0x03;

/// Whether a unidirectional stream type is one HTTP/3 already owns (control, push, QPACK), so the
/// WebTransport binding must leave it alone (RFC 9114 6.2, RFC 9204 4.2).
///
/// Note:
/// - The WebTransport stream type (draft-ietf-webtrans-http3-16 4.2) is deliberately not builtin: the
///   binding owns that one, and a reader that skipped it as HTTP/3's would lose the session id it
///   carries ahead of the application bytes.
pub fn isBuiltinStreamType(stream_type: u64) bool {
    return switch (stream_type) {
        control_stream, push_stream, qpack_encoder_stream, qpack_decoder_stream => true,
        else => false,
    };
}

/// Whether a frame type may appear on the control stream (RFC 9114 7.2). DATA / HEADERS /
/// PUSH_PROMISE on the control stream are H3_FRAME_UNEXPECTED.
pub fn frameAllowedOnControl(frame: FrameType) bool {
    return switch (frame) {
        .settings, .goaway, .max_push_id, .cancel_push => true,
        .data, .headers, .push_promise => false,
    };
}

/// Whether a frame type may appear on a request stream (RFC 9114 7.2). SETTINGS / GOAWAY /
/// MAX_PUSH_ID / CANCEL_PUSH on a request stream are H3_FRAME_UNEXPECTED.
pub fn frameAllowedOnRequest(frame: FrameType) bool {
    return switch (frame) {
        .headers, .data, .push_promise => true,
        .settings, .goaway, .max_push_id, .cancel_push => false,
    };
}

// --------------------------------------------------------------- //

/// The control-stream errors (RFC 9114 6.2.1).
pub const ControlError = error{
    /// The first frame on the control stream was not SETTINGS: H3_MISSING_SETTINGS.
    ZixMissingSettings,
    /// A second control stream was opened: H3_STREAM_CREATION_ERROR.
    ZixStreamCreationError,
};

/// Tracks the control-stream invariants (RFC 9114 6.2.1): exactly one control stream, SETTINGS first.
pub const ControlStream = struct {
    open: bool = false,
    settings_seen: bool = false,

    /// Open the single control stream. A second one is H3_STREAM_CREATION_ERROR.
    pub fn openStream(self: *ControlStream) ControlError!void {
        if (self.open) return error.ZixStreamCreationError;
        self.open = true;
    }

    /// Process a frame on the control stream. The first frame MUST be SETTINGS.
    pub fn onFrame(self: *ControlStream, frame: FrameType) ControlError!void {
        if (!self.settings_seen and frame != .settings) return error.ZixMissingSettings;
        self.settings_seen = true;
    }
};

/// The position within a request's frame sequence (RFC 9114 4.1): a HEADERS, then optional DATA, then
/// an optional trailing HEADERS, and nothing after.
pub const RequestState = enum { initial, header_seen, trailer_seen };

/// Advance the request frame sequence (RFC 9114 4.1). A null result is an invalid sequence,
/// H3_FRAME_UNEXPECTED: DATA before HEADERS, or any frame after the trailing HEADERS.
pub fn requestFrameTransition(state: RequestState, frame: FrameType) ?RequestState {
    return switch (state) {
        .initial => switch (frame) {
            .headers => .header_seen,
            else => null,
        },
        .header_seen => switch (frame) {
            .data => .header_seen,
            .headers => .trailer_seen,
            else => null,
        },
        .trailer_seen => null,
    };
}

// --------------------------------------------------------------- //

/// A decompressed field line (the output of QPACK decode).
pub const Field = struct { name: []const u8, value: []const u8 };

/// Whether the message is a request or a response (RFC 9114 4.3).
pub const MessageKind = enum { request, response };

/// The message-validation error (RFC 9114 4.1.2): a malformed message is H3_MESSAGE_ERROR.
pub const MessageError = error{ZixMessageError};

/// Whether a field name is connection-specific and therefore prohibited in HTTP/3 (RFC 9114 4.2).
pub fn connectionSpecific(name: []const u8) bool {
    const prohibited = [_][]const u8{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" };
    for (prohibited) |bad| {
        if (std.mem.eql(u8, name, bad)) return true;
    }

    return false;
}

/// Validate a decompressed HTTP/3 message (RFC 9114 4.1.2 / 4.2 / 4.3). Returns H3_MESSAGE_ERROR on
/// any malformed condition.
///
/// Note:
/// - A CONNECT carrying `:protocol` is the extended CONNECT of RFC 9220 3 (the HTTP/3 form of the
///   RFC 8441 4 upgrade): it is the one request that names a target, so `:authority`, `:scheme` and
///   `:path` are all mandatory and a plain tunnel with none of them is not what it means. A CONNECT
///   without `:protocol` stays the tunnel of RFC 9114 4.3.1 and MUST NOT carry `:scheme` or `:path`.
/// - The `:protocol` value is not judged here: which tokens this server speaks is the binding's
///   decision (RFC 9220 3 answers an unknown one with 501), not a property of a well-formed request.
///
/// Param:
/// kind - MessageKind (request or response)
/// fields - []const Field (the decompressed field list, in order)
/// content_length - ?u64 (the Content-Length value if the message declared one)
/// data_total - u64 (the summed length of the DATA frames received)
///
/// Return:
/// - void
/// - error.ZixMessageError on any malformed condition
pub fn validateMessage(kind: MessageKind, fields: []const Field, content_length: ?u64, data_total: u64) MessageError!void {
    var seen_regular = false;
    var method: ?[]const u8 = null;
    var protocol: ?[]const u8 = null;
    var has_scheme = false;
    var has_path = false;
    var has_authority = false;
    var has_status = false;

    for (fields) |entry| {
        for (entry.name) |c| {
            if (c >= 'A' and c <= 'Z') return error.ZixMessageError;
        }

        if (entry.name.len > 0 and entry.name[0] == ':') {
            if (seen_regular) return error.ZixMessageError;

            if (std.mem.eql(u8, entry.name, ":method")) {
                method = entry.value;
            } else if (std.mem.eql(u8, entry.name, ":protocol")) {
                // Single valued: a second one would let a peer put two upgrade tokens in one request
                // and pick whichever dialect the server happens to match first (RFC 8441 4).
                if (protocol != null) return error.ZixMessageError;

                protocol = entry.value;
            } else if (std.mem.eql(u8, entry.name, ":scheme")) {
                has_scheme = true;
            } else if (std.mem.eql(u8, entry.name, ":path")) {
                has_path = true;
            } else if (std.mem.eql(u8, entry.name, ":authority")) {
                has_authority = true;
            } else if (std.mem.eql(u8, entry.name, ":status")) {
                has_status = true;
            } else {
                return error.ZixMessageError;
            }
        } else {
            seen_regular = true;
            if (connectionSpecific(entry.name)) return error.ZixMessageError;
        }
    }

    switch (kind) {
        .request => {
            if (has_status) return error.ZixMessageError;

            if (method) |verb| {
                if (std.mem.eql(u8, verb, "CONNECT")) {
                    if (protocol != null) {
                        // Extended CONNECT: the request still names a resource, so the target fields
                        // are mandatory rather than forbidden (RFC 8441 4).
                        if (!has_authority or !has_scheme or !has_path) return error.ZixMessageError;
                    } else {
                        // A plain CONNECT is a tunnel to `:authority` and nothing else.
                        if (!has_authority or has_scheme or has_path) return error.ZixMessageError;
                    }
                } else {
                    if (!has_scheme or !has_path) return error.ZixMessageError;

                    // `:protocol` extends CONNECT alone (RFC 8441 4).
                    if (protocol != null) return error.ZixMessageError;
                }
            } else {
                return error.ZixMessageError;
            }
        },
        .response => {
            if (!has_status) return error.ZixMessageError;
            if (method != null or protocol != null or has_scheme or has_path or has_authority) return error.ZixMessageError;
        },
    }

    if (content_length) |declared| {
        if (declared != data_total) return error.ZixMessageError;
    }
}

/// Whether validating the message raised H3_MESSAGE_ERROR.
pub fn isMalformed(kind: MessageKind, fields: []const Field, content_length: ?u64, data_total: u64) bool {
    return std.meta.isError(validateMessage(kind, fields, content_length, data_total));
}

/// The HTTP/3 settings a WebTransport-capable server sends (RFC 9114 7.2.4.1, RFC 9220, RFC 9297,
/// draft-ietf-webtrans-http3-16 3.1 / 5.5, plus the deployed draft-07 aliases).
pub const ServerSettings = struct {
    /// RFC 9220: advertise extended CONNECT.
    enable_connect_protocol: bool = false,
    /// RFC 9297 2.1.1: advertise HTTP/3 datagrams.
    h3_datagram: bool = false,
    /// draft-16: advertise WebTransport over HTTP/3 (SETTINGS_WT_ENABLED) and the session limits.
    webtransport: bool = false,
    /// draft-16 5.5.1: the unidirectional stream limit a session starts with, in place of a
    /// WT_MAX_STREAMS capsule. Zero leaves the session at the capsule-negotiated zero.
    wt_initial_max_streams_uni: u64 = 0,
    /// draft-16 5.5.2: the bidirectional stream limit a session starts with.
    wt_initial_max_streams_bidi: u64 = 0,
    /// draft-16 5.5.3: the data limit a session starts with, in place of a WT_MAX_DATA capsule.
    wt_initial_max_data: u64 = 0,
    /// The deployed dialect also sends SETTINGS_ENABLE_WEBTRANSPORT so shipping clients see support.
    legacy_webtransport: bool = false,
};

/// The value a flag-like setting carries when it is on: RFC 9220 3 and RFC 9297 2.1.1 both spell the
/// support flag as 1, and draft-ietf-webtrans-http3-16 3.1 spells SETTINGS_WT_ENABLED the same way.
/// The legacy session count below rides the same value for the same reason.
const setting_on: u64 = 1;

/// The widest a SETTINGS entry can be: its identifier and its value at eight varint bytes each
/// (RFC 9000 16).
const widest_setting_entry: usize = 16;

/// The most entries `writeServerControlStream` can write: the three support flags, the three session
/// limits, and the two legacy aliases.
const max_server_settings: usize = 8;

/// One SETTINGS entry: the identifier and the value, the pair a SETTINGS payload interleaves
/// (RFC 9114 7.2.4.1).
const Setting = struct { identifier: u64, value: u64 };

/// The entry for a boolean setting: `setting_on` when the flag is set, and the 0 that
/// `writeServerControlStream` reads as "leave this entry out" when it is not.
fn flagEntry(identifier: u64, flag: bool) Setting {
    return .{ .identifier = identifier, .value = if (flag) setting_on else 0 };
}

/// Write the server control stream's opening bytes: the control stream type 0x00, then a SETTINGS
/// frame (0x04) whose payload carries `settings` in a stable order. Returns the bytes written, or
/// null when `out` is too small.
///
/// Note:
/// - Only the settings that are on are written, and each one carries the value a peer reads as its
///   default instead of the entry, which is what makes an omitted flag and a zero limit say the same
///   thing in fewer bytes. The order is `enable_connect_protocol`, `h3_datagram`, SETTINGS_WT_ENABLED,
///   the three WT initial limits, then the legacy pair, so equal settings always produce equal bytes.
/// - The legacy pair goes out together, because SETTINGS_ENABLE_WEBTRANSPORT only says the endpoint
///   is WebTransport-capable while the deployed dialect reads support out of the session count
///   (draft-ietf-webtrans-http3-07 3.1, where 0 means the server accepts no sessions at all and the
///   count is not configurable through `ServerSettings`).
///
/// Param:
/// out - []u8 (destination for the control stream bytes)
/// settings - ServerSettings (the settings to advertise)
///
/// Return:
/// - usize (the bytes written: the stream type, the frame type, the payload length, the payload)
/// - null when `out` cannot hold them
pub fn writeServerControlStream(out: []u8, settings: ServerSettings) ?usize {
    // The entries in wire order, with a zero value meaning "off, leave it out": every setting here is
    // either a flag or a limit whose default is zero, so 0 is the one value that is never advertised.
    const entries = [_]Setting{
        flagEntry(draft.setting.enable_connect_protocol, settings.enable_connect_protocol),
        flagEntry(draft.setting.h3_datagram, settings.h3_datagram),
        flagEntry(draft.setting.wt_enabled, settings.webtransport),
        .{ .identifier = draft.setting.wt_initial_max_streams_uni, .value = settings.wt_initial_max_streams_uni },
        .{ .identifier = draft.setting.wt_initial_max_streams_bidi, .value = settings.wt_initial_max_streams_bidi },
        .{ .identifier = draft.setting.wt_initial_max_data, .value = settings.wt_initial_max_data },
        flagEntry(draft.setting.enable_webtransport, settings.legacy_webtransport),
        flagEntry(draft.setting.webtransport_max_sessions, settings.legacy_webtransport),
    };

    // Sized for every entry at its widest, so a partial write is the only failure the entries can
    // hit and the caller's buffer is the one that decides whether the frame fits.
    var payload: [max_server_settings * widest_setting_entry]u8 = undefined;
    var len: usize = 0;
    for (entries) |entry| {
        if (entry.value == 0) continue;

        len += writeSetting(payload[len..], entry);
    }

    // The control stream type, the frame type, and the length of everything that follows, all as
    // varints (RFC 9114 6.2.1 / 7.2.4.1).
    const frame_type = @intFromEnum(FrameType.settings);
    if (out.len < varint.encodedLen(control_stream) + varint.encodedLen(frame_type) + varint.encodedLen(len) + len) return null;

    var pos: usize = 0;
    pos += varint.write(out[pos..], control_stream);
    pos += varint.write(out[pos..], frame_type);
    pos += varint.write(out[pos..], len);
    @memcpy(out[pos..][0..len], payload[0..len]);
    pos += len;

    return pos;
}

/// Append one setting's two varints and return the bytes written. The caller sizes `out` for the
/// widest entry (RFC 9000 16).
fn writeSetting(out: []u8, entry: Setting) usize {
    var pos = varint.write(out, entry.identifier);
    pos += varint.write(out[pos..], entry.value);

    return pos;
}

/// What a client's SETTINGS frame said, reduced to what the WebTransport binding reads. Unknown
/// settings are ignored (RFC 9114 7.2.4.1), so this only reports the ones that matter here.
pub const ClientSettings = struct {
    enable_connect_protocol: bool = false,
    h3_datagram: bool = false,
    wt_enabled: u64 = 0,
    wt_initial_max_streams_uni: u64 = 0,
    wt_initial_max_streams_bidi: u64 = 0,
    wt_initial_max_data: u64 = 0,
    enable_webtransport: u64 = 0,
    webtransport_max_sessions: u64 = 0,
    /// The SETTINGS payload broke a MUST: the peer is answered with H3_SETTINGS_ERROR.
    malformed: bool = false,
};

/// Parse the payload of a client SETTINGS frame (the bytes after the frame type and length). Sets
/// `malformed` when an identifier repeats, when an identifier is in the reserved range 0x02..0x05,
/// when SETTINGS_H3_DATAGRAM (0x33) carries a value other than 0 or 1 (RFC 9297 2.1.1), or when
/// SETTINGS_WT_ENABLED (0x2c7cf000) carries a value greater than 1 (draft-16 3.1). A malformed
/// payload reports `malformed` and stops early; the values parsed before that point stay.
///
/// Note:
/// - H3_SETTINGS_ERROR is a connection error (RFC 9114 7.2.4.1), so a caller that sees `malformed`
///   ends the connection rather than acting on the values beside it. They are left in place because
///   a resumed connection's limits and a logging path both want them.
/// - A payload that ends inside a varint is malformed as well: the frame is at least that broken, and
///   there is no setting to read past the cut.
/// - A flag is read as on when its value is 1, which is the only value that advertises support; a
///   setting this binding does not read is skipped whatever it carries.
///
/// Param:
/// payload - []const u8 (the SETTINGS frame payload, read from offset 0)
///
/// Return:
/// - ClientSettings (what the binding reads, with `malformed` set on a MUST violation)
pub fn parseClientSettings(payload: []const u8) ClientSettings {
    var out = ClientSettings{};
    var pos: usize = 0;

    while (pos < payload.len) {
        // The identifier, then its value (RFC 9114 7.2.4.1). The start of the entry is kept for the
        // duplicate check below, which compares against the entries already walked.
        const entry_start = pos;
        const identifier = varint.read(payload[pos..]) catch {
            out.malformed = true;
            return out;
        };
        pos += identifier.len;

        const value = varint.read(payload[pos..]) catch {
            out.malformed = true;
            return out;
        };
        pos += value.len;

        // 0x02..0x05 were HTTP/2's without an HTTP/3 equivalent, so a peer sending one is
        // H3_SETTINGS_ERROR no matter what it names (RFC 9114 7.2.4.1).
        if (identifier.value >= 0x02 and identifier.value <= 0x05) {
            out.malformed = true;
            return out;
        }

        // An identifier must appear once: a peer could otherwise send two values for one setting and
        // leave the receiver to guess which one its limits came from.
        if (settingSeenBefore(payload, entry_start, identifier.value)) {
            out.malformed = true;
            return out;
        }

        switch (identifier.value) {
            draft.setting.enable_connect_protocol => out.enable_connect_protocol = value.value == 1,
            draft.setting.h3_datagram => {
                // A value outside 0 and 1 is H3_SETTINGS_ERROR (RFC 9297 2.1.1), and the datagrams
                // stay off either way.
                if (value.value > 1) {
                    out.malformed = true;
                    return out;
                }

                out.h3_datagram = value.value == 1;
            },
            draft.setting.wt_enabled => {
                // Greater than 1 is a revision this build does not speak (draft-16 3.1), so the
                // client is told H3_SETTINGS_ERROR rather than silently downgraded.
                if (value.value > 1) {
                    out.malformed = true;
                    return out;
                }

                out.wt_enabled = value.value;
            },
            draft.setting.wt_initial_max_streams_uni => out.wt_initial_max_streams_uni = value.value,
            draft.setting.wt_initial_max_streams_bidi => out.wt_initial_max_streams_bidi = value.value,
            draft.setting.wt_initial_max_data => out.wt_initial_max_data = value.value,
            draft.setting.enable_webtransport => out.enable_webtransport = value.value,
            draft.setting.webtransport_max_sessions => out.webtransport_max_sessions = value.value,
            else => {}, // A setting this binding does not read: RFC 9114 7.2.4.1 says ignore it.
        }
    }

    return out;
}

/// Whether the entries before `end` in a SETTINGS payload already carry `identifier`, which makes the
/// payload H3_SETTINGS_ERROR (RFC 9114 7.2.4.1).
///
/// Note:
/// - The walk re-reads the entries before the current one instead of holding a table of identifiers,
///   so the rule holds for a payload of any size. A payload of n entries therefore costs n walks of
///   at most n entries each, and n is a handful for every SETTINGS frame a peer has a reason to send
///   (RFC 9114 7.2.4.1 registers a small fixed set). A caller that buffers a whole control stream
///   before parsing should still bound the frame length it accepts, which is what keeps any frame
///   walk over peer-chosen bytes tame.
///
/// Param:
/// payload - []const u8 (the whole SETTINGS payload)
/// end - usize (where the current entry starts)
/// identifier - u64 (the identifier to look for)
///
/// Return:
/// - bool (whether an earlier entry named it)
fn settingSeenBefore(payload: []const u8, end: usize, identifier: u64) bool {
    var pos: usize = 0;
    while (pos < end) {
        // The entries before `end` were read to get this far, so the walk cannot run off the front of
        // the payload; the catches keep a caller that hands over a half-parsed prefix from trapping.
        const other = varint.read(payload[pos..]) catch return false;
        pos += other.len;

        const value = varint.read(payload[pos..]) catch return false;
        pos += value.len;

        if (other.value == identifier) return true;
    }

    return false;
}

// --------------------------------------------------------------- //

/// Which side of the connection an endpoint is (RFC 9114 7.2.7).
pub const Role = enum { client, server };

/// Whether a frame type may be SENT by the given role (RFC 9114 7.2.5 / 7.2.7). MAX_PUSH_ID is
/// client-only and PUSH_PROMISE is server-only, a frame from the wrong side is H3_FRAME_UNEXPECTED
/// at the receiver.
pub fn frameSendableBy(frame: FrameType, sender: Role) bool {
    return switch (frame) {
        .max_push_id => sender == .client,
        .push_promise => sender == .server,
        else => true,
    };
}

/// The identifier-ordering error (RFC 9114 5.2 / 7.2.7): H3_ID_ERROR.
pub const IdError = error{ZixIdError};

/// Tracks received GOAWAY identifiers (RFC 9114 5.2): each MUST NOT exceed any previous one. A larger
/// identifier is H3_ID_ERROR.
pub const GoawayTracker = struct {
    last: ?u64 = null,

    pub fn receive(self: *GoawayTracker, id: u64) IdError!void {
        if (self.last) |prev| {
            if (id > prev) return error.ZixIdError;
        }
        self.last = id;
    }
};

/// Tracks the push limit set by MAX_PUSH_ID (RFC 9114 7.2.7): the value only increases. A smaller
/// value is H3_ID_ERROR.
pub const MaxPushIdTracker = struct {
    current: ?u64 = null,

    pub fn update(self: *MaxPushIdTracker, id: u64) IdError!void {
        if (self.current) |prev| {
            if (id < prev) return error.ZixIdError;
        }
        self.current = id;
    }
};

/// The HTTP/3 error codes (RFC 9114 8.1).
pub const Http3Error = enum(u64) {
    no_error = 0x0100,
    general_protocol_error = 0x0101,
    internal_error = 0x0102,
    stream_creation_error = 0x0103,
    closed_critical_stream = 0x0104,
    frame_unexpected = 0x0105,
    frame_error = 0x0106,
    excessive_load = 0x0107,
    id_error = 0x0108,
    settings_error = 0x0109,
    missing_settings = 0x010a,
    request_rejected = 0x010b,
    request_cancelled = 0x010c,
    request_incomplete = 0x010d,
    message_error = 0x010e,
    connect_error = 0x010f,
    version_fallback = 0x0110,
};

/// Whether an error code is in the reserved (grease) range 0x1f * N + 0x21 (RFC 9114 8.1), which a
/// receiver MUST treat as equivalent to H3_NO_ERROR.
pub fn isReservedErrorCode(code: u64) bool {
    if (code < 0x21) return false;

    return (code - 0x21) % 0x1f == 0;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

/// Bytes from a hex string, for the fixtures that are easier to read the way the wire spells them.
fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

/// The payload of the SETTINGS frame a control stream opens with: skip the control stream type, the
/// frame type, and the length varint (RFC 9114 6.2.1 / 7.2.4.1).
fn controlStreamPayload(bytes: []const u8) []const u8 {
    var pos: usize = 0;
    for (0..3) |_| {
        const field = varint.read(bytes[pos..]) catch unreachable;
        pos += field.len;
    }

    return bytes[pos..];
}

test "zix http3: RFC 9114 7.2 / 6.2 frame and stream type values" {
    try std.testing.expectEqual(@as(u64, 0x00), @intFromEnum(FrameType.data));
    try std.testing.expectEqual(@as(u64, 0x01), @intFromEnum(FrameType.headers));
    try std.testing.expectEqual(@as(u64, 0x04), @intFromEnum(FrameType.settings));
    try std.testing.expectEqual(@as(u64, 0x07), @intFromEnum(FrameType.goaway));
    try std.testing.expectEqual(@as(u64, 0x0d), @intFromEnum(FrameType.max_push_id));

    try std.testing.expect(control_stream == 0x00 and push_stream == 0x01);
    try std.testing.expect(qpack_encoder_stream == 0x02 and qpack_decoder_stream == 0x03);
}

test "zix http3: RFC 9114 6.2.1 control stream and SETTINGS first" {
    var control = ControlStream{};
    try control.openStream();
    try control.onFrame(.settings);
    try control.onFrame(.goaway);
    try std.testing.expectError(error.ZixStreamCreationError, control.openStream());

    var bad_control = ControlStream{};
    try bad_control.openStream();
    try std.testing.expectError(error.ZixMissingSettings, bad_control.onFrame(.goaway));
}

test "zix http3: RFC 9114 7.2 frame-per-stream matrix and 4.1 request sequence" {
    try std.testing.expect(frameAllowedOnControl(.settings) and !frameAllowedOnRequest(.settings));
    try std.testing.expect(frameAllowedOnRequest(.headers) and !frameAllowedOnControl(.headers));
    try std.testing.expect(frameAllowedOnControl(.goaway) and !frameAllowedOnRequest(.goaway));

    try std.testing.expectEqual(RequestState.header_seen, requestFrameTransition(.initial, .headers).?);
    try std.testing.expect(requestFrameTransition(.header_seen, .data) != null);
    try std.testing.expectEqual(RequestState.trailer_seen, requestFrameTransition(.header_seen, .headers).?);
    try std.testing.expect(requestFrameTransition(.trailer_seen, .data) == null);
    try std.testing.expect(requestFrameTransition(.initial, .data) == null);
}

test "zix http3: RFC 9114 4.3 message validation" {
    const request = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "user-agent", .value = "zix" },
    };
    try std.testing.expect(!isMalformed(.request, &request, null, 0));

    const connect = [_]Field{ .{ .name = ":method", .value = "CONNECT" }, .{ .name = ":authority", .value = "example.com:443" } };
    try std.testing.expect(!isMalformed(.request, &connect, null, 0));

    const response = [_]Field{ .{ .name = ":status", .value = "200" }, .{ .name = "content-type", .value = "text/plain" } };
    try std.testing.expect(!isMalformed(.response, &response, null, 0));

    const no_method = [_]Field{ .{ .name = ":scheme", .value = "https" }, .{ .name = ":path", .value = "/" } };
    try std.testing.expect(isMalformed(.request, &no_method, null, 0));

    const uppercase = [_]Field{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":path", .value = "/" }, .{ .name = "User-Agent", .value = "zix" } };
    try std.testing.expect(isMalformed(.request, &uppercase, null, 0));

    const pseudo_after = [_]Field{ .{ .name = ":method", .value = "GET" }, .{ .name = "user-agent", .value = "zix" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":path", .value = "/" } };
    try std.testing.expect(isMalformed(.request, &pseudo_after, null, 0));

    const conn_specific = [_]Field{ .{ .name = ":status", .value = "200" }, .{ .name = "connection", .value = "keep-alive" } };
    try std.testing.expect(isMalformed(.response, &conn_specific, null, 0));

    try std.testing.expect(!isMalformed(.response, &response, 5, 5));
    try std.testing.expect(isMalformed(.response, &response, 5, 3));
}

test "zix http3: RFC 9114 5.2 / 7.2.7 GOAWAY, direction, and 8.1 error codes" {
    var goaway = GoawayTracker{};
    try goaway.receive(100);
    try goaway.receive(60);
    try goaway.receive(60);
    try std.testing.expectError(error.ZixIdError, goaway.receive(80));

    try std.testing.expect(frameSendableBy(.max_push_id, .client) and !frameSendableBy(.max_push_id, .server));
    try std.testing.expect(frameSendableBy(.push_promise, .server) and !frameSendableBy(.push_promise, .client));

    var max_push = MaxPushIdTracker{};
    try max_push.update(10);
    try max_push.update(20);
    try std.testing.expectError(error.ZixIdError, max_push.update(5));

    try std.testing.expectEqual(@as(u64, 0x0100), @intFromEnum(Http3Error.no_error));
    try std.testing.expectEqual(@as(u64, 0x0105), @intFromEnum(Http3Error.frame_unexpected));
    try std.testing.expectEqual(@as(u64, 0x0110), @intFromEnum(Http3Error.version_fallback));

    try std.testing.expect(isReservedErrorCode(0x21));
    try std.testing.expect(isReservedErrorCode(0x40));
    try std.testing.expect(!isReservedErrorCode(0x0105));
}

test "zix webtransport: extended CONNECT validates :protocol and the fields it makes mandatory" {
    const extended = [_]Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = draft.upgrade_token.draft16 },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/wt" },
    };
    try std.testing.expect(!isMalformed(.request, &extended, null, 0));

    // RFC 8441 4: naming a target is what makes the request an upgrade rather than a tunnel, so all
    // three of the target fields are mandatory once :protocol is there.
    const no_path = [_]Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = draft.upgrade_token.draft16 },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };
    try std.testing.expect(isMalformed(.request, &no_path, null, 0));

    const no_scheme = [_]Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = draft.upgrade_token.draft07 },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/wt" },
    };
    try std.testing.expect(isMalformed(.request, &no_scheme, null, 0));

    const no_authority = [_]Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = draft.upgrade_token.draft07 },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/wt" },
    };
    try std.testing.expect(isMalformed(.request, &no_authority, null, 0));

    // Without :protocol a CONNECT is still the tunnel to `:authority` of RFC 9114 4.3.1.
    const tunnel = [_]Field{ .{ .name = ":method", .value = "CONNECT" }, .{ .name = ":authority", .value = "example.com:443" } };
    try std.testing.expect(!isMalformed(.request, &tunnel, null, 0));

    const tunnel_with_target = [_]Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.com:443" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    try std.testing.expect(isMalformed(.request, &tunnel_with_target, null, 0));

    // :protocol extends CONNECT alone, whatever else the request carries.
    const get = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":protocol", .value = draft.upgrade_token.draft16 },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/wt" },
    };
    try std.testing.expect(isMalformed(.request, &get, null, 0));

    // Two :protocol values would let one request offer two dialects to match against.
    const twice = [_]Field{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = draft.upgrade_token.draft16 },
        .{ .name = ":protocol", .value = draft.upgrade_token.draft07 },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/wt" },
    };
    try std.testing.expect(isMalformed(.request, &twice, null, 0));

    // A response carries none of the request pseudo-headers, :protocol included.
    const response = [_]Field{ .{ .name = ":status", .value = "200" }, .{ .name = ":protocol", .value = draft.upgrade_token.draft16 } };
    try std.testing.expect(isMalformed(.response, &response, null, 0));

    // The rules the message already lived under still hold for the extended shape.
    try std.testing.expect(isMalformed(.request, &extended, 4, 0));
}

test "zix webtransport: the server control stream opens with SETTINGS in a stable order" {
    var out: [64]u8 = undefined;

    const full = ServerSettings{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .webtransport = true,
        .wt_initial_max_streams_uni = 100,
        .wt_initial_max_streams_bidi = 100,
        .wt_initial_max_data = 1024,
        .legacy_webtransport = true,
    };

    // The control stream type 0x00, the SETTINGS frame 0x04, the payload length 0x23, then
    // enable_connect_protocol (0x08) and h3_datagram (0x33), SETTINGS_WT_ENABLED (0x2c7cf000) with
    // the value 1, the three initial limits (0x2b64 / 0x2b65 / 0x2b61), and the deployed pair
    // (0x2b603742, and 0xc671706a whose value needs the eight-byte varint form) counting one session.
    const full_len = writeServerControlStream(&out, full).?;
    try std.testing.expectEqual(@as(usize, 38), full_len);
    try std.testing.expectEqualSlices(u8, &hexBytes("00042308013301ac7cf000016b6440646b6540646b614400ab60374201c0000000c671706a01"), out[0..full_len]);

    // Nothing on is still a legal opening: the empty SETTINGS frame the serve path writes today
    // (dispatch/common.zig), which is what an HTTP/3-only server sends.
    const empty_len = writeServerControlStream(&out, .{}).?;
    try std.testing.expectEqual(@as(usize, 3), empty_len);
    try std.testing.expectEqualSlices(u8, &hexBytes("000400"), out[0..empty_len]);

    // One flag: the length covers the entry that follows and nothing else.
    const minimal_len = writeServerControlStream(&out, .{ .enable_connect_protocol = true }).?;
    try std.testing.expectEqual(@as(usize, 5), minimal_len);
    try std.testing.expectEqualSlices(u8, &hexBytes("0004020801"), out[0..minimal_len]);

    // A limit alone: every setting is independent of the flags around it.
    const limit_len = writeServerControlStream(&out, .{ .wt_initial_max_data = 1 }).?;
    try std.testing.expectEqualSlices(u8, &hexBytes("0004036b6101"), out[0..limit_len]);

    // The legacy pair alone: both aliases go out together, in that order, with the draft-16 settings
    // and every flag absent.
    const legacy_len = writeServerControlStream(&out, .{ .legacy_webtransport = true }).?;
    try std.testing.expectEqualSlices(u8, &hexBytes("00040eab60374201c0000000c671706a01"), out[0..legacy_len]);
}

test "zix webtransport: the server control stream needs the whole frame in the buffer" {
    var out: [64]u8 = undefined;
    const advertised = ServerSettings{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .webtransport = true,
        .wt_initial_max_streams_uni = 100,
        .wt_initial_max_streams_bidi = 100,
        .wt_initial_max_data = 1024,
        .legacy_webtransport = true,
    };
    const len = writeServerControlStream(&out, advertised).?;
    try std.testing.expectEqual(@as(usize, 38), len);

    // A buffer that holds exactly the frame is enough, and one byte less is not: the encoder decides
    // on the length before it writes, so a caller never sees half a control stream.
    var exact: [38]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 38), writeServerControlStream(&exact, advertised).?);
    try std.testing.expectEqualSlices(u8, out[0..len], &exact);

    var one_short: [37]u8 = undefined;
    try std.testing.expect(writeServerControlStream(&one_short, advertised) == null);

    // Even the empty frame needs its three bytes.
    var none: [0]u8 = undefined;
    try std.testing.expect(writeServerControlStream(&none, .{}) == null);
}

test "zix webtransport: the client SETTINGS decode reports what the peer advertised" {
    var out: [64]u8 = undefined;
    const advertised = ServerSettings{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .webtransport = true,
        .wt_initial_max_streams_uni = 4,
        .wt_initial_max_streams_bidi = 8,
        .wt_initial_max_data = 65536,
        .legacy_webtransport = true,
    };
    const len = writeServerControlStream(&out, advertised).?;

    // What this server writes is what its own decode reads back, field for field.
    const client = parseClientSettings(controlStreamPayload(out[0..len]));
    try std.testing.expect(!client.malformed);
    try std.testing.expect(client.enable_connect_protocol);
    try std.testing.expect(client.h3_datagram);
    try std.testing.expectEqual(@as(u64, 1), client.wt_enabled);
    try std.testing.expectEqual(@as(u64, 4), client.wt_initial_max_streams_uni);
    try std.testing.expectEqual(@as(u64, 8), client.wt_initial_max_streams_bidi);
    try std.testing.expectEqual(@as(u64, 65536), client.wt_initial_max_data);
    try std.testing.expectEqual(@as(u64, 1), client.enable_webtransport);
    try std.testing.expectEqual(@as(u64, 1), client.webtransport_max_sessions);

    // A client that speaks only the deployed dialect sends its own shape and no draft-16 flag.
    var fixture: [32]u8 = undefined;
    var pos: usize = 0;
    pos += varint.write(fixture[pos..], draft.setting.webtransport_max_sessions);
    pos += varint.write(fixture[pos..], 16);
    pos += varint.write(fixture[pos..], draft.setting.enable_webtransport);
    pos += varint.write(fixture[pos..], 1);

    const legacy = parseClientSettings(fixture[0..pos]);
    try std.testing.expect(!legacy.malformed);
    try std.testing.expectEqual(@as(u64, 16), legacy.webtransport_max_sessions);
    try std.testing.expectEqual(@as(u64, 1), legacy.enable_webtransport);
    try std.testing.expectEqual(@as(u64, 0), legacy.wt_enabled);

    // A setting this binding does not read (the grease form 0x1f * N + 0x21) is skipped rather than
    // reported, and the settings around it still arrive.
    var greased: [32]u8 = undefined;
    var at: usize = 0;
    at += varint.write(greased[at..], 0x1f * 4 + 0x21);
    at += varint.write(greased[at..], 1234);
    at += varint.write(greased[at..], draft.setting.h3_datagram);
    at += varint.write(greased[at..], 1);

    const skipped = parseClientSettings(greased[0..at]);
    try std.testing.expect(!skipped.malformed);
    try std.testing.expect(skipped.h3_datagram);

    // A client that sent no settings at all is a client that said nothing, not a broken frame.
    const silent = parseClientSettings(&[_]u8{});
    try std.testing.expect(!silent.malformed);
    try std.testing.expectEqual(@as(u64, 0), silent.wt_initial_max_data);

    // Both flags spelled as an explicit 0 stay off instead of tripping the value rules.
    const off = parseClientSettings(&hexBytes("3300ac7cf00000"));
    try std.testing.expect(!off.malformed);
    try std.testing.expect(!off.h3_datagram);
    try std.testing.expectEqual(@as(u64, 0), off.wt_enabled);
}

test "zix webtransport: a malformed client SETTINGS payload is flagged" {
    // The same identifier twice (RFC 9114 7.2.4.1), whatever values it carries.
    try std.testing.expect(parseClientSettings(&hexBytes("08010800")).malformed);
    try std.testing.expect(parseClientSettings(&hexBytes("33013301")).malformed);

    // The reserved range 0x02..0x05, which includes 0x04: the SETTINGS frame type is not a setting
    // identifier even though the frame wears it.
    for ([_]u8{ 0x02, 0x03, 0x04, 0x05 }) |identifier| {
        const reserved = [_]u8{ identifier, 0x00 };
        try std.testing.expect(parseClientSettings(&reserved).malformed);
    }

    // SETTINGS_H3_DATAGRAM is 0 or 1 (RFC 9297 2.1.1).
    try std.testing.expect(parseClientSettings(&hexBytes("3302")).malformed);

    // SETTINGS_WT_ENABLED above 1 names a revision this build does not speak (draft-16 3.1).
    try std.testing.expect(parseClientSettings(&hexBytes("ac7cf00002")).malformed);

    // A payload cut inside an entry: an identifier with no value, and one that is itself truncated.
    try std.testing.expect(parseClientSettings(&hexBytes("08")).malformed);
    try std.testing.expect(parseClientSettings(&hexBytes("ac7c")).malformed);

    // The entries read before the bad one stay, and the value that broke the rule never turns its
    // flag on. H3_SETTINGS_ERROR is a connection error, so nothing downstream uses either.
    const partial = parseClientSettings(&hexBytes("08013302"));
    try std.testing.expect(partial.malformed);
    try std.testing.expect(partial.enable_connect_protocol);
    try std.testing.expect(!partial.h3_datagram);

    // The same values spelled legally are not flagged, so the rule is not a blanket reject.
    try std.testing.expect(!parseClientSettings(&hexBytes("08013301")).malformed);
}

test "zix webtransport: HTTP/3's own stream types are not the binding's" {
    try std.testing.expect(isBuiltinStreamType(control_stream));
    try std.testing.expect(isBuiltinStreamType(push_stream));
    try std.testing.expect(isBuiltinStreamType(qpack_encoder_stream));
    try std.testing.expect(isBuiltinStreamType(qpack_decoder_stream));

    // The types the binding has to route itself: the WebTransport stream that carries a session id
    // and then application bytes, and an unassigned type, which is nobody's stream.
    try std.testing.expect(!isBuiltinStreamType(draft.uni_stream_type));
    try std.testing.expect(!isBuiltinStreamType(draft.wt_stream));
    try std.testing.expect(!isBuiltinStreamType(0x40)); // the grease form 0x1f * N + 0x21 (RFC 9114 6.2.3)
}
