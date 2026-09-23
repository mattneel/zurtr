//! zix HTTP/3 QUIC connection close, stateless reset, and anti-amplification (RFC 9000 19.19 / 10.2
//! / 10.3 / 8.1, Layer Q).
//!
//! What:
//! - How a connection ends and how it is protected from abuse before the peer address is validated:
//!   the CONNECTION_CLOSE field layout (only the 0x1c QUIC variant carries a Frame Type), the closing
//!   / draining states, stateless-reset detection by the trailing 16 bytes, and the server-side 3x
//!   anti-amplification cap plus the 1200-byte client Initial floor.
//! - Proven against crafted frames, byte counts, and datagrams in the tests below.

const std = @import("std");

const varint = @import("varint.zig");

/// A parsed CONNECTION_CLOSE frame (RFC 9000 19.19). The QUIC variant (0x1c) carries a Frame Type
/// field, the application variant (0x1d) does not.
pub const ConnClose = struct {
    is_application: bool,
    error_code: u64,
    frame_type: u64,
    reason: []const u8,
};

/// Parse a CONNECTION_CLOSE frame including its type byte (RFC 9000 19.19). Only the 0x1c variant
/// has the Frame Type field.
pub fn parseConnectionClose(data: []const u8) error{ ZixTruncated, ZixProtocolViolation }!ConnClose {
    var pos: usize = 0;

    const type_vi = varint.read(data) catch return error.ZixTruncated;
    pos += type_vi.len;
    if (type_vi.value != 0x1c and type_vi.value != 0x1d) return error.ZixProtocolViolation;

    const is_application = type_vi.value == 0x1d;

    const error_code = readField(data, &pos) catch return error.ZixTruncated;

    var frame_type: u64 = 0;
    if (!is_application) frame_type = readField(data, &pos) catch return error.ZixTruncated;

    const reason_len = readField(data, &pos) catch return error.ZixTruncated;
    if (data.len < pos + reason_len) return error.ZixTruncated;

    return .{ .is_application = is_application, .error_code = error_code, .frame_type = frame_type, .reason = data[pos .. pos + reason_len] };
}

/// Read one variable-length field, advancing the cursor (helper for parseConnectionClose).
fn readField(data: []const u8, pos: *usize) error{ZixTruncated}!u64 {
    const vi = try varint.read(data[pos.*..]);
    pos.* += vi.len;

    return vi.value;
}

// --------------------------------------------------------------- //

/// The connection-termination states (RFC 9000 10.2): an endpoint that sends CONNECTION_CLOSE enters
/// closing, one that receives it enters draining, and both end in the terminal closed state.
pub const CloseState = enum { open, closing, draining, closed };

/// Events that drive connection termination (RFC 9000 10.2).
pub const CloseEvent = enum { send_close, recv_close, timeout };

/// Apply a termination event (RFC 9000 10.2.1 / 10.2.2). A null result means the event is not legal
/// in that state.
pub fn closeTransition(state: CloseState, event: CloseEvent) ?CloseState {
    return switch (state) {
        .open => switch (event) {
            .send_close => .closing,
            .recv_close => .draining,
            else => null,
        },
        .closing => switch (event) {
            .recv_close => .draining,
            .timeout => .closed,
            else => null,
        },
        .draining => switch (event) {
            .timeout => .closed,
            else => null,
        },
        .closed => null,
    };
}

/// Whether an endpoint may still send packets in a termination state (RFC 9000 10.2.2): the draining
/// state sends nothing.
pub fn maySendInState(state: CloseState) bool {
    return state == .open or state == .closing;
}

// --------------------------------------------------------------- //

/// Detect a Stateless Reset by the trailing 16 bytes of the datagram (RFC 9000 10.3.1). A short
/// header packet smaller than 21 bytes is never a valid QUIC packet, so it cannot be a reset.
pub fn isStatelessReset(datagram: []const u8, token: [16]u8) bool {
    if (datagram.len < 21) return false;

    return std.mem.eql(u8, datagram[datagram.len - 16 ..], &token);
}

/// Whether a Stateless Reset of `reset_len` bytes is allowed in response to a `received_len`-byte
/// packet (RFC 9000 10.3): it MUST NOT be three times or more larger, to avoid amplification.
pub fn resetSizeAllowed(received_len: usize, reset_len: usize) bool {
    return reset_len < 3 * received_len;
}

// --------------------------------------------------------------- //

/// The server-side anti-amplification budget before the client address is validated (RFC 9000 8.1):
/// the server MUST NOT send more than three times the bytes it has received.
pub const AntiAmplification = struct {
    received: u64 = 0,
    sent: u64 = 0,
    validated: bool = false,

    /// Count payload bytes received on the connection (RFC 9000 8.1).
    pub fn onReceive(self: *AntiAmplification, bytes: u64) void {
        self.received += bytes;
    }

    /// Count payload bytes sent on the connection (RFC 9000 8.1).
    pub fn onSend(self: *AntiAmplification, bytes: u64) void {
        self.sent += bytes;
    }

    /// Whether sending `bytes` more is within the 3x cap (or address validation has lifted it).
    pub fn maySend(self: AntiAmplification, bytes: u64) bool {
        return self.validated or self.sent + bytes <= 3 * self.received;
    }
};

/// Whether a datagram carrying a client Initial meets the 1200-byte floor (RFC 9000 8.1 / 14.1).
pub fn initialDatagramValid(size: usize) bool {
    return size >= 1200;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix http3: RFC 9000 19.19 CONNECTION_CLOSE frame variants" {
    const close_quic = try parseConnectionClose(&hexBytes("1c07000" ++ "26f6b"));
    try std.testing.expect(!close_quic.is_application);
    try std.testing.expectEqual(@as(u64, 7), close_quic.error_code);
    try std.testing.expectEqual(@as(u64, 0), close_quic.frame_type);
    try std.testing.expectEqualSlices(u8, "ok", close_quic.reason);

    const close_app = try parseConnectionClose(&hexBytes("1d0100"));
    try std.testing.expect(close_app.is_application);
    try std.testing.expectEqual(@as(u64, 1), close_app.error_code);
    try std.testing.expectEqual(@as(usize, 0), close_app.reason.len);
}

test "zix http3: RFC 9000 10.2 closing and draining states" {
    try std.testing.expectEqual(CloseState.closing, closeTransition(.open, .send_close).?);
    try std.testing.expectEqual(CloseState.draining, closeTransition(.open, .recv_close).?);
    try std.testing.expectEqual(CloseState.draining, closeTransition(.closing, .recv_close).?);
    try std.testing.expectEqual(CloseState.closed, closeTransition(.closing, .timeout).?);
    try std.testing.expectEqual(CloseState.closed, closeTransition(.draining, .timeout).?);
    try std.testing.expect(!maySendInState(.draining));
    try std.testing.expect(maySendInState(.closing));
}

test "zix http3: RFC 9000 10.3 stateless reset detection and size" {
    const token: [16]u8 = .{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf };

    try std.testing.expect(isStatelessReset(&hexBytes("4111223344556677" ++ "88" ++ "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"), token));
    try std.testing.expect(!isStatelessReset(&hexBytes("4111223344556677" ++ "88" ++ "ffffffffffffffffffffffffffffffff"), token));
    try std.testing.expect(!isStatelessReset(&hexBytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf11223344"), token));

    try std.testing.expect(!resetSizeAllowed(20, 60));
    try std.testing.expect(resetSizeAllowed(20, 59));
}

test "zix http3: RFC 9000 8.1 anti-amplification and Initial floor" {
    var anti = AntiAmplification{};
    anti.onReceive(1200);
    try std.testing.expect(anti.maySend(3600));
    try std.testing.expect(!anti.maySend(3601));

    var anti_validated = AntiAmplification{ .validated = true };
    anti_validated.onReceive(100);
    try std.testing.expect(anti_validated.maySend(1_000_000));

    try std.testing.expect(initialDatagramValid(1200));
    try std.testing.expect(!initialDatagramValid(1199));
}
