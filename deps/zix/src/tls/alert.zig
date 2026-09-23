//! TLS 1.3 alerts (RFC 8446 section 6).
//!
//! Note:
//! - The fatal alert descriptions raised by the handshake and extension layers, plus the plaintext
//!   alert record builder for the pre-handshake-key failures. In TLS 1.3 the level byte is legacy
//!   (these are all fatal), so only the description is modeled here.

const std = @import("std");

/// AlertLevel (RFC 8446 6): legacy in 1.3 (all these are fatal), kept for the wire byte.
const level_warning: u8 = 1;
pub const level_fatal: u8 = 2;

const content_type_alert: u8 = 21;

/// A fatal alert as a plaintext record is 7 bytes: the 5-byte record header + a 2-byte body.
pub const fatal_record_len: usize = 7;

/// AlertDescription (RFC 8446 6.2), the subset zix raises.
pub const Alert = enum(u8) {
    UNEXPECTED_MESSAGE = 10,
    BAD_RECORD_MAC = 20,
    RECORD_OVERFLOW = 22,
    HANDSHAKE_FAILURE = 40,
    BAD_CERTIFICATE = 42,
    ILLEGAL_PARAMETER = 47,
    DECODE_ERROR = 50,
    DECRYPT_ERROR = 51,
    PROTOCOL_VERSION = 70,
    MISSING_EXTENSION = 109,
    UNRECOGNIZED_NAME = 112,
    NO_APPLICATION_PROTOCOL = 120,
};

// --------------------------------------------------------------- //

/// Build a fatal alert as a plaintext TLS record: content_type alert(21), legacy_record_version
/// 0x0303, a 2-byte body [level fatal(2), description]. This is the form for the pre-handshake-key
/// failures (a ClientHello rejected before the handshake keys exist), where the alert goes on the
/// wire in the clear. Post-handshake fatal alerts are encrypted through the record layer instead.
pub fn fatalRecord(buf: *[fatal_record_len]u8, desc: Alert) []const u8 {
    buf[0] = content_type_alert;
    buf[1] = 0x03;
    buf[2] = 0x03;
    buf[3] = 0x00;
    buf[4] = 0x02;
    buf[5] = level_fatal;
    buf[6] = @intFromEnum(desc);

    return buf[0..fatal_record_len];
}

// --------------------------------------------------------------- //

/// Inbound alert descriptions that need their own handling but are not in the outbound subset.
/// close_notify (0) is a clean closure, user_canceled (90) is a warning the peer may send before it.
pub const desc_close_notify: u8 = 0;
pub const desc_user_canceled: u8 = 90;

/// A parsed inbound alert (RFC 8446 6): the legacy level byte plus the description. In TLS 1.3 the
/// level is advisory (the description decides the action), so classification keys on the description.
pub const Inbound = struct {
    level: u8,
    description: u8,

    /// close_notify (RFC 8446 6.1): the peer closed its write side. No more data follows from it,
    /// the receiver MUST stop reading application data and tear the connection down.
    pub fn isCloseNotify(self: Inbound) bool {
        return self.description == desc_close_notify;
    }

    /// Every alert except close_notify / user_canceled is fatal in TLS 1.3, the connection MUST be
    /// closed and its keys dropped (RFC 8446 6). user_canceled is a warning that precedes close_notify.
    pub fn isFatal(self: Inbound) bool {
        return self.description != desc_close_notify and self.description != desc_user_canceled;
    }
};

/// Parse an inbound alert body: the 2 bytes [level, description] that follow a plaintext alert
/// record header, or the decrypted inner content of a post-handshake alert (RFC 8446 6).
///
/// Param:
/// body - []const u8 (exactly the 2 alert bytes, level then description)
///
/// Return:
/// - Inbound
/// - error.ZixDecodeError (the body is not exactly 2 bytes, RFC 8446 6 malformed alert)
pub fn parseInbound(body: []const u8) error{ZixDecodeError}!Inbound {
    if (body.len != 2) return error.ZixDecodeError;

    return .{ .level = body[0], .description = body[1] };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix tls: Alert, wire values" {
    try std.testing.expectEqual(@as(u8, 47), @intFromEnum(Alert.ILLEGAL_PARAMETER));
    try std.testing.expectEqual(@as(u8, 109), @intFromEnum(Alert.MISSING_EXTENSION));
    try std.testing.expectEqual(@as(u8, 120), @intFromEnum(Alert.NO_APPLICATION_PROTOCOL));
}

test "zix tls: Alert, fatalRecord plaintext bytes" {
    var buf: [fatal_record_len]u8 = undefined;
    const rec = fatalRecord(&buf, .NO_APPLICATION_PROTOCOL);

    // 15 03 03 00 02 02 78: alert(21), 0x0303, len 2, fatal(2), no_application_protocol(120).
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x78 }, rec);
}

test "zix tls: Alert, parseInbound classifies close_notify vs fatal" {
    // close_notify (warning level 1, desc 0): clean closure, not fatal.
    const cn = try parseInbound(&[_]u8{ level_warning, desc_close_notify });
    try std.testing.expect(cn.isCloseNotify());
    try std.testing.expect(!cn.isFatal());

    // handshake_failure (fatal level 2, desc 40): fatal, not a clean closure.
    const hf = try parseInbound(&[_]u8{ level_fatal, @intFromEnum(Alert.HANDSHAKE_FAILURE) });
    try std.testing.expect(!hf.isCloseNotify());
    try std.testing.expect(hf.isFatal());

    // user_canceled (warning, desc 90): a warning that precedes close_notify, not fatal.
    const uc = try parseInbound(&[_]u8{ level_warning, desc_user_canceled });
    try std.testing.expect(!uc.isFatal());

    // a malformed alert body (not 2 bytes) -> decode_error.
    try std.testing.expectError(error.ZixDecodeError, parseInbound(&[_]u8{0x01}));
    try std.testing.expectError(error.ZixDecodeError, parseInbound(&[_]u8{ 1, 2, 3 }));
}
