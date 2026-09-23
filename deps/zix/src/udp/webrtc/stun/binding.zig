//! zix STUN binding transaction (RFC 8489 6.3.1 / 12).
//!
//! What:
//! - The server half of the Binding method: read a datagram, and if it is a binding request,
//!   answer with the address it arrived from in an XOR-MAPPED-ADDRESS attribute. That reflected
//!   address is the whole point of STUN, it is what a peer behind a NAT learns about itself.
//! - `respond` is a pure function over bytes, which keeps the transaction rules testable without
//!   a socket and lets any dispatch model call it from a datagram handler.
//!
//! Note:
//! - Binding is idempotent (RFC 8489 6.3.1), so a retransmitted request is recomputed rather than
//!   remembered. The server holds no per-transaction state.
//! - No authentication. A plain binding server needs none, and a request carrying credentials is
//!   answered all the same, because known-but-unexpected attributes are ignored (RFC 8489 6.3).
//!   ICE connectivity checks do require credentials, and those rules belong with ICE.
//! - Every response carries FINGERPRINT. It costs 8 bytes, it is what lets a peer tell a STUN
//!   response from another protocol on a shared port, and ICE requires it later anyway.
//!
//! Usage:
//! ```zig
//! fn handler(datagram: []const u8, peer: *const std.Io.net.IpAddress, sink: *zix.Udp.Sink) void {
//!     var buf: [binding.MAX_RESPONSE_BYTES]u8 = undefined;
//!
//!     if (binding.respond(datagram, peer, &buf)) |reply| sink.replyTo(peer, reply);
//! }
//! ```

const std = @import("std");

const message = @import("message.zig");

const IpAddress = std.Io.net.IpAddress;

/// Largest response this file can produce. A caller that sizes its buffer to this never loses a
/// reply to a short buffer.
///
/// Note:
/// - Worst case is the 420 response: 20 header, 28 ERROR-CODE, 20 UNKNOWN-ATTRIBUTES, 8
///   FINGERPRINT. A success response is 52 bytes at most, on an IPv6 peer.
pub const MAX_RESPONSE_BYTES: usize = 128;

/// Error code for a request holding an attribute the server must understand and does not
/// (RFC 8489 6.3.1).
pub const ERROR_UNKNOWN_ATTRIBUTE: u16 = 420;

/// Most unknown attribute types listed in one 420 response. A request that trips more than this
/// is malformed or hostile, and the list is diagnostic, so truncating it costs nothing.
const MAX_UNKNOWN_LISTED: usize = 8;

/// Recommended reason phrase for 420 (RFC 8489 14.8). Diagnostic text, never machine-read.
const REASON_UNKNOWN_ATTRIBUTE: []const u8 = "Unknown Attribute";

/// Answer a datagram that may be a STUN binding request.
///
/// Note:
/// - null means send nothing. That covers every silent-discard case in RFC 8489 6.3 (not STUN,
///   malformed, wrong method, a class a server does not answer, a broken FINGERPRINT) and also
///   an `out` too small to hold the reply, so size it to MAX_RESPONSE_BYTES.
/// - A request holding an unknown comprehension-required attribute gets a 420 error response
///   rather than silence, because the sender needs to know why it failed.
///
/// Param:
/// datagram - []const u8 (one received datagram)
/// peer - *const std.Io.net.IpAddress (where it came from, the address being reflected back)
/// out - []u8 (destination for the reply, MAX_RESPONSE_BYTES is always enough)
///
/// Return:
/// - []const u8 (the reply, borrowing out)
/// - null when nothing should be sent
pub fn respond(datagram: []const u8, peer: *const IpAddress, out: []u8) ?[]const u8 {
    const request = message.parse(datagram) catch return null;

    if (request.class != .REQUEST) return null;
    if (request.method != .BINDING) return null;
    if (request.fingerprint() == .INVALID) return null;

    var unknown: [MAX_UNKNOWN_LISTED]message.AttributeType = undefined;
    const unknown_kinds = message.collectUnknownRequired(request, &unknown);

    if (unknown_kinds.len > 0) return unknownAttributeResponse(request, unknown_kinds, out);

    return successResponse(request, peer, out);
}

/// Success response: the reflected transport address, nothing else (RFC 8489 12).
fn successResponse(request: message.Message, peer: *const IpAddress, out: []u8) ?[]const u8 {
    var writer = message.Writer.init(out, .SUCCESS_RESPONSE, .BINDING, request.transaction_id) catch return null;

    writer.addXorMappedAddress(peer.*) catch return null;
    writer.addFingerprint() catch return null;

    return writer.finish();
}

/// 420 error response naming the attributes that could not be understood (RFC 8489 6.3.1).
fn unknownAttributeResponse(request: message.Message, kinds: []const message.AttributeType, out: []u8) ?[]const u8 {
    var writer = message.Writer.init(out, .ERROR_RESPONSE, .BINDING, request.transaction_id) catch return null;

    writer.addErrorCode(ERROR_UNKNOWN_ATTRIBUTE, REASON_UNKNOWN_ATTRIBUTE) catch return null;
    writer.addUnknownAttributes(kinds) catch return null;
    writer.addFingerprint() catch return null;

    return writer.finish();
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const TEST_TRANSACTION_ID: [message.TRANSACTION_ID_LEN]u8 = .{ 0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34, 0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE };

const TEST_PEER: IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 32853 } };

fn testRequest(buf: []u8, class: message.Class, method: message.Method) message.Writer {
    return message.Writer.init(buf, class, method, TEST_TRANSACTION_ID) catch unreachable;
}

test "zix stun: binding respond, a request is answered with the reflected address" {
    var request_buf: [64]u8 = undefined;
    var request = testRequest(&request_buf, .REQUEST, .BINDING);

    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const reply = respond(request.finish(), &TEST_PEER, &out).?;

    const response = try message.parse(reply);
    try std.testing.expectEqual(message.Class.SUCCESS_RESPONSE, response.class);
    try std.testing.expectEqual(message.Method.BINDING, response.method);
    try std.testing.expectEqualSlices(u8, &TEST_TRANSACTION_ID, &response.transaction_id);

    const attr = response.find(.XOR_MAPPED_ADDRESS).?;
    const reflected = try message.decodeXorMappedAddress(attr.value, &response.transaction_id);
    try std.testing.expectEqualSlices(u8, &TEST_PEER.ip4.bytes, &reflected.ip4.bytes);
    try std.testing.expectEqual(TEST_PEER.ip4.port, reflected.ip4.port);
}

test "zix stun: binding respond, every reply carries a valid fingerprint" {
    var request_buf: [64]u8 = undefined;
    var request = testRequest(&request_buf, .REQUEST, .BINDING);

    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const reply = respond(request.finish(), &TEST_PEER, &out).?;

    const response = try message.parse(reply);
    try std.testing.expectEqual(message.FingerprintState.VALID, response.fingerprint());

    // FINGERPRINT must be the last attribute (RFC 8489 14.7).
    try std.testing.expectEqual(reply.len, response.find(.FINGERPRINT).?.offset + message.FINGERPRINT_LEN);
}

test "zix stun: binding respond, an ipv6 peer is reflected as ipv6" {
    const peer: IpAddress = .{ .ip6 = .{
        .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 },
        .port = 41000,
    } };

    var request_buf: [64]u8 = undefined;
    var request = testRequest(&request_buf, .REQUEST, .BINDING);

    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const reply = respond(request.finish(), &peer, &out).?;

    const response = try message.parse(reply);
    const attr = response.find(.XOR_MAPPED_ADDRESS).?;
    const reflected = try message.decodeXorMappedAddress(attr.value, &response.transaction_id);

    try std.testing.expectEqualSlices(u8, &peer.ip6.bytes, &reflected.ip6.bytes);
    try std.testing.expectEqual(peer.ip6.port, reflected.ip6.port);
}

test "zix stun: binding respond, a retransmission gets a byte-identical answer" {
    var request_buf: [64]u8 = undefined;
    var request = testRequest(&request_buf, .REQUEST, .BINDING);
    const datagram = request.finish();

    var first_out: [MAX_RESPONSE_BYTES]u8 = undefined;
    var second_out: [MAX_RESPONSE_BYTES]u8 = undefined;

    const first = respond(datagram, &TEST_PEER, &first_out).?;
    const second = respond(datagram, &TEST_PEER, &second_out).?;

    try std.testing.expectEqualSlices(u8, first, second);
}

test "zix stun: binding respond, traffic that is not a binding request is ignored" {
    var out: [MAX_RESPONSE_BYTES]u8 = undefined;

    // Another protocol sharing the port (RFC 7983): a DTLS record and a plain SCTP-looking blob.
    var dtls_record: [40]u8 = @splat(0);
    dtls_record[0] = 0x16;
    dtls_record[1] = 0xfe;
    dtls_record[2] = 0xfd;

    try std.testing.expectEqual(@as(?[]const u8, null), respond(&dtls_record, &TEST_PEER, &out));
    try std.testing.expectEqual(@as(?[]const u8, null), respond(&[_]u8{}, &TEST_PEER, &out));
    try std.testing.expectEqual(@as(?[]const u8, null), respond("not stun at all", &TEST_PEER, &out));

    // A truncated request: the header claims attributes the datagram does not carry.
    var short_buf: [64]u8 = undefined;
    var short = testRequest(&short_buf, .REQUEST, .BINDING);
    var truncated: [message.HEADER_LEN]u8 = short.finish()[0..message.HEADER_LEN].*;
    std.mem.writeInt(u16, truncated[2..4], 8, .big);

    try std.testing.expectEqual(@as(?[]const u8, null), respond(&truncated, &TEST_PEER, &out));
}

test "zix stun: binding respond, only the request class of the binding method is answered" {
    var out: [MAX_RESPONSE_BYTES]u8 = undefined;

    const ignored_classes = [_]message.Class{ .INDICATION, .SUCCESS_RESPONSE, .ERROR_RESPONSE };
    for (ignored_classes) |class| {
        var buf: [64]u8 = undefined;
        var writer = testRequest(&buf, class, .BINDING);

        try std.testing.expectEqual(@as(?[]const u8, null), respond(writer.finish(), &TEST_PEER, &out));
    }

    // A request for a method this server does not implement, TURN Allocate for one.
    var allocate_buf: [64]u8 = undefined;
    var allocate = testRequest(&allocate_buf, .REQUEST, @enumFromInt(0x003));

    try std.testing.expectEqual(@as(?[]const u8, null), respond(allocate.finish(), &TEST_PEER, &out));
}

test "zix stun: binding respond, a wrong fingerprint on the request is discarded" {
    var request_buf: [64]u8 = undefined;
    var request = testRequest(&request_buf, .REQUEST, .BINDING);
    try request.addFingerprint();

    const datagram = request.finish();
    var out: [MAX_RESPONSE_BYTES]u8 = undefined;

    // A correct fingerprint is answered.
    try std.testing.expect(respond(datagram, &TEST_PEER, &out) != null);

    // One flipped bit in the CRC is not.
    var tampered: [64]u8 = undefined;
    @memcpy(tampered[0..datagram.len], datagram);
    tampered[datagram.len - 1] ^= 0x01;

    try std.testing.expectEqual(@as(?[]const u8, null), respond(tampered[0..datagram.len], &TEST_PEER, &out));
}

test "zix stun: binding respond, an unknown comprehension-required attribute gets 420" {
    const unknown_kind: message.AttributeType = @enumFromInt(0x0042);

    var request_buf: [64]u8 = undefined;
    var request = testRequest(&request_buf, .REQUEST, .BINDING);
    try request.addAttribute(unknown_kind, "xy");

    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const reply = respond(request.finish(), &TEST_PEER, &out).?;

    const response = try message.parse(reply);
    try std.testing.expectEqual(message.Class.ERROR_RESPONSE, response.class);
    try std.testing.expectEqualSlices(u8, &TEST_TRANSACTION_ID, &response.transaction_id);
    try std.testing.expectEqual(@as(?message.Attribute, null), response.find(.XOR_MAPPED_ADDRESS));

    const error_code = response.find(.ERROR_CODE).?;
    try std.testing.expectEqual(@as(u8, 4), error_code.value[2]);
    try std.testing.expectEqual(@as(u8, 20), error_code.value[3]);
    try std.testing.expectEqualStrings(REASON_UNKNOWN_ATTRIBUTE, error_code.value[4..]);

    const listed_kinds = response.find(.UNKNOWN_ATTRIBUTES).?;
    try std.testing.expectEqual(@as(usize, 2), listed_kinds.value.len);
    try std.testing.expectEqual(@intFromEnum(unknown_kind), std.mem.readInt(u16, listed_kinds.value[0..2], .big));
}

test "zix stun: binding respond, a repeated unknown attribute is named once" {
    const unknown_kind: message.AttributeType = @enumFromInt(0x0042);

    var request_buf: [64]u8 = undefined;
    var request = testRequest(&request_buf, .REQUEST, .BINDING);
    try request.addAttribute(unknown_kind, "xy");
    try request.addAttribute(unknown_kind, "xy");

    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const response = try message.parse(respond(request.finish(), &TEST_PEER, &out).?);

    try std.testing.expectEqual(@as(usize, 2), response.find(.UNKNOWN_ATTRIBUTES).?.value.len);
}

test "zix stun: binding respond, an unknown comprehension-optional attribute is ignored" {
    var request_buf: [64]u8 = undefined;
    var request = testRequest(&request_buf, .REQUEST, .BINDING);
    try request.addAttribute(@enumFromInt(0x8042), "ignore me");

    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const response = try message.parse(respond(request.finish(), &TEST_PEER, &out).?);

    try std.testing.expectEqual(message.Class.SUCCESS_RESPONSE, response.class);
    try std.testing.expect(response.find(.XOR_MAPPED_ADDRESS) != null);
}

test "zix stun: binding respond, a known attribute the server does not expect is ignored" {
    var request_buf: [64]u8 = undefined;
    var request = testRequest(&request_buf, .REQUEST, .BINDING);
    try request.addAttribute(.USERNAME, "zix:peer");
    try request.addAttribute(.SOFTWARE, "some client");

    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const response = try message.parse(respond(request.finish(), &TEST_PEER, &out).?);

    try std.testing.expectEqual(message.Class.SUCCESS_RESPONSE, response.class);
    try std.testing.expect(response.find(.XOR_MAPPED_ADDRESS) != null);
}

test "zix stun: binding respond, the worst case reply fits MAX_RESPONSE_BYTES" {
    var request_buf: [256]u8 = undefined;
    var request = testRequest(&request_buf, .REQUEST, .BINDING);

    // More unknown comprehension-required attributes than a 420 response lists.
    for (0..MAX_UNKNOWN_LISTED + 4) |i| {
        try request.addAttribute(@enumFromInt(@as(u16, 0x0040) + @as(u16, @intCast(i))), "");
    }

    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const reply = respond(request.finish(), &TEST_PEER, &out).?;

    const response = try message.parse(reply);
    try std.testing.expectEqual(message.Class.ERROR_RESPONSE, response.class);
    try std.testing.expectEqual(MAX_UNKNOWN_LISTED * 2, response.find(.UNKNOWN_ATTRIBUTES).?.value.len);
    try std.testing.expectEqual(message.FingerprintState.VALID, response.fingerprint());
    try std.testing.expect(reply.len <= MAX_RESPONSE_BYTES);
}

test "zix stun: binding respond, a buffer too small drops the reply instead of writing past it" {
    var request_buf: [64]u8 = undefined;
    var request = testRequest(&request_buf, .REQUEST, .BINDING);
    const datagram = request.finish();

    var exact: [message.HEADER_LEN + 12 + message.FINGERPRINT_LEN]u8 = undefined;
    try std.testing.expect(respond(datagram, &TEST_PEER, &exact) != null);

    var one_short: [message.HEADER_LEN + 12 + message.FINGERPRINT_LEN - 1]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), respond(datagram, &TEST_PEER, &one_short));

    var header_only: [message.HEADER_LEN]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), respond(datagram, &TEST_PEER, &header_only));
}
