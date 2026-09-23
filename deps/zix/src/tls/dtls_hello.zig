//! DTLS ClientHello and HelloVerifyRequest codec (RFC 6347 4.2.1).
//!
//! What:
//! - The one handshake message DTLS changes the body of, plus the message that exists only in
//!   DTLS. Everything else on the wire is TLS 1.2 unchanged.
//! - A DTLS ClientHello carries a `cookie` vector between session_id and cipher_suites. That one
//!   field is the whole reason the TLS parser cannot be reused: it would read the cookie length
//!   as the top half of the cipher suite list length and misparse everything after it.
//!
//! Note:
//! - Parsing borrows, it copies nothing but the fixed-size random. The bytes stay in the caller's
//!   receive buffer.
//! - `paramsForCookie` returns the span a cookie is computed over. The client MUST repeat those
//!   fields verbatim in the second ClientHello (RFC 6347 4.2.1), which is what makes a cookie
//!   verifiable without storing anything.
//! - The version in a HelloVerifyRequest is DTLS 1.0 by convention, even from a 1.2 server
//!   (RFC 6347 4.2.1). It is not version negotiation, and a client must not read it as such.

const std = @import("std");

const wire = @import("wire.zig");
const dtls_handshake = @import("dtls_handshake.zig");
const dtls_record = @import("dtls_record.zig");

/// Longest cookie a server may issue (RFC 6347 4.2.1).
pub const MAX_COOKIE_LEN: usize = 255;

/// Longest session id in a ClientHello (RFC 5246 7.4.1.2).
pub const MAX_SESSION_ID_LEN: usize = 32;

pub const Error = error{
    /// The bytes ran out mid-field.
    ZixTruncated,
    /// A field is present but outside its allowed size.
    ZixBadHello,
};

/// A parsed DTLS ClientHello body, borrowing the caller's bytes.
pub const ClientHello = struct {
    client_version: u16,
    random: [32]u8,
    session_id: []const u8,
    /// Empty on the first ClientHello, filled on the one that answers a HelloVerifyRequest.
    cookie: []const u8,
    cipher_suites: []const u8,
    compression_methods: []const u8,
    /// Raw extensions block, empty when the hello carried none.
    extensions: []const u8,
    /// Everything the cookie is computed over, see paramsForCookie.
    body: []const u8,

    /// The bytes a cookie binds: every field the client must repeat verbatim.
    ///
    /// Note:
    /// - The cookie itself is cut out, since the second hello carries a cookie the first did not
    ///   and binding it would make the check circular.
    ///
    /// Return:
    /// - []const u8 (version, random, and session_id, in wire order)
    pub fn paramsForCookie(self: *const ClientHello) []const u8 {
        return self.body[0 .. 2 + 32 + 1 + self.session_id.len];
    }

    /// Whether this hello answers a HelloVerifyRequest.
    pub fn hasCookie(self: *const ClientHello) bool {
        return self.cookie.len > 0;
    }

    /// Whether a cipher suite was offered. The suite list is a flat run of 2-byte values.
    pub fn offersCipherSuite(self: *const ClientHello, suite: u16) bool {
        var pos: usize = 0;
        while (pos + 2 <= self.cipher_suites.len) : (pos += 2) {
            if (std.mem.readInt(u16, self.cipher_suites[pos..][0..2], .big) == suite) return true;
        }

        return false;
    }
};

/// Parse a DTLS ClientHello body (RFC 6347 4.2.1), the bytes after the handshake header.
///
/// Param:
/// body - []const u8 (handshake message body, header already stripped)
///
/// Return:
/// - ClientHello borrowing body
/// - error.ZixTruncated, error.ZixBadHello
pub fn parseClientHello(body: []const u8) Error!ClientHello {
    var reader = wire.Reader{ .buf = body };

    const client_version = reader.readU16() catch return error.ZixTruncated;
    const random = reader.readBytes(32) catch return error.ZixTruncated;

    const session_id_len = reader.readU8() catch return error.ZixTruncated;
    if (session_id_len > MAX_SESSION_ID_LEN) return error.ZixBadHello;
    const session_id = reader.readBytes(session_id_len) catch return error.ZixTruncated;

    const cookie_len = reader.readU8() catch return error.ZixTruncated;
    const cookie = reader.readBytes(cookie_len) catch return error.ZixTruncated;

    const suites_len = reader.readU16() catch return error.ZixTruncated;
    if (suites_len == 0 or suites_len % 2 != 0) return error.ZixBadHello;
    const cipher_suites = reader.readBytes(suites_len) catch return error.ZixTruncated;

    const compression_len = reader.readU8() catch return error.ZixTruncated;
    if (compression_len == 0) return error.ZixBadHello;
    const compression_methods = reader.readBytes(compression_len) catch return error.ZixTruncated;

    // Extensions are optional in DTLS 1.2, a hello may simply end after compression methods.
    var extensions: []const u8 = &.{};
    if (reader.remaining() >= 2) {
        const extensions_len = reader.readU16() catch return error.ZixTruncated;
        extensions = reader.readBytes(extensions_len) catch return error.ZixTruncated;
    }

    return .{
        .client_version = client_version,
        .random = random[0..32].*,
        .session_id = session_id,
        .cookie = cookie,
        .cipher_suites = cipher_suites,
        .compression_methods = compression_methods,
        .extensions = extensions,
        .body = body,
    };
}

/// Write a HelloVerifyRequest body: server_version and the cookie (RFC 6347 4.2.1).
///
/// Return:
/// - []const u8 (the body, borrowing out)
/// - error.ZixBadHello when the cookie is over MAX_COOKIE_LEN
pub fn writeHelloVerifyRequestBody(out: []u8, cookie: []const u8) Error![]const u8 {
    if (cookie.len > MAX_COOKIE_LEN) return error.ZixBadHello;

    var writer = wire.Writer{ .buf = out };
    writer.writeU16(dtls_record.VERSION_DTLS_1_0);
    writer.writeU8(@intCast(cookie.len));
    writer.writeBytes(cookie);

    return writer.slice();
}

/// Read the cookie out of a HelloVerifyRequest body, which is what a client needs from it.
pub fn parseHelloVerifyRequestBody(body: []const u8) Error![]const u8 {
    var reader = wire.Reader{ .buf = body };

    _ = reader.readU16() catch return error.ZixTruncated;

    const cookie_len = reader.readU8() catch return error.ZixTruncated;

    return reader.readBytes(cookie_len) catch error.ZixTruncated;
}

/// Write a DTLS ClientHello body (RFC 6347 4.2.1). Used by the client half and by tests.
///
/// Param:
/// out - []u8 (destination)
/// client_version - u16 (0xFEFD for DTLS 1.2)
/// random - [32]u8
/// session_id - []const u8 (empty for a fresh handshake)
/// cookie - []const u8 (empty on the first hello, echoed on the second)
/// cipher_suites - []const u16
///
/// Return:
/// - []const u8 (the body, borrowing out)
/// - error.ZixBadHello when the cookie or session id is over its limit
pub fn writeClientHelloBody(
    out: []u8,
    client_version: u16,
    random: [32]u8,
    session_id: []const u8,
    cookie: []const u8,
    cipher_suites: []const u16,
) Error![]const u8 {
    if (cookie.len > MAX_COOKIE_LEN) return error.ZixBadHello;
    if (session_id.len > MAX_SESSION_ID_LEN) return error.ZixBadHello;

    var writer = wire.Writer{ .buf = out };
    writer.writeU16(client_version);
    writer.writeBytes(&random);
    writer.writeU8(@intCast(session_id.len));
    writer.writeBytes(session_id);
    writer.writeU8(@intCast(cookie.len));
    writer.writeBytes(cookie);

    writer.writeU16(@intCast(cipher_suites.len * 2));
    for (cipher_suites) |suite| writer.writeU16(suite);

    writer.writeU8(1);
    writer.writeU8(0); // null compression

    return writer.slice();
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const TEST_RANDOM: [32]u8 = @splat(0x11);
const TEST_SUITE: u16 = 0xC02B;

test "zix dtls: hello parse, a first client hello carries no cookie" {
    var buf: [256]u8 = undefined;
    const body = try writeClientHelloBody(&buf, dtls_record.VERSION_DTLS_1_2, TEST_RANDOM, "", "", &.{TEST_SUITE});

    const hello = try parseClientHello(body);
    try std.testing.expectEqual(@as(u16, dtls_record.VERSION_DTLS_1_2), hello.client_version);
    try std.testing.expectEqualSlices(u8, &TEST_RANDOM, &hello.random);
    try std.testing.expectEqual(@as(usize, 0), hello.session_id.len);
    try std.testing.expect(!hello.hasCookie());
    try std.testing.expect(hello.offersCipherSuite(TEST_SUITE));
    try std.testing.expect(!hello.offersCipherSuite(0x1301));
}

test "zix dtls: hello parse, the cookie field is what breaks a tls parser" {
    var buf: [256]u8 = undefined;
    const cookie: [1]u8 = @splat(0xAB);
    const body = try writeClientHelloBody(&buf, dtls_record.VERSION_DTLS_1_2, TEST_RANDOM, "", &cookie, &.{ TEST_SUITE, 0x009C });

    const hello = try parseClientHello(body);
    try std.testing.expect(hello.hasCookie());
    try std.testing.expectEqualSlices(u8, &cookie, hello.cookie);

    // Both offered suites survive, which is the part a cookie-blind parser gets wrong.
    try std.testing.expectEqual(@as(usize, 4), hello.cipher_suites.len);
    try std.testing.expect(hello.offersCipherSuite(TEST_SUITE));
    try std.testing.expect(hello.offersCipherSuite(0x009C));
}

test "zix dtls: hello parse, the cookie span is stable across the two hellos" {
    var first_buf: [256]u8 = undefined;
    var second_buf: [256]u8 = undefined;

    const session_id = [_]u8{ 1, 2, 3, 4 };
    const first = try parseClientHello(try writeClientHelloBody(
        &first_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_RANDOM,
        &session_id,
        "",
        &.{TEST_SUITE},
    ));

    const cookie: [32]u8 = @splat(0xCD);
    const second = try parseClientHello(try writeClientHelloBody(
        &second_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_RANDOM,
        &session_id,
        &cookie,
        &.{TEST_SUITE},
    ));

    // The second hello adds a cookie and repeats everything else, so the signed span matches
    // byte for byte. Without that, no cookie could ever verify.
    try std.testing.expectEqualSlices(u8, first.paramsForCookie(), second.paramsForCookie());
    try std.testing.expectEqual(@as(usize, 2 + 32 + 1 + 4), first.paramsForCookie().len);

    // A changed random moves the span, so a cookie farmed for one hello does not fit another.
    var third_buf: [256]u8 = undefined;
    const third = try parseClientHello(try writeClientHelloBody(
        &third_buf,
        dtls_record.VERSION_DTLS_1_2,
        @splat(0x22),
        &session_id,
        &cookie,
        &.{TEST_SUITE},
    ));
    try std.testing.expect(!std.mem.eql(u8, first.paramsForCookie(), third.paramsForCookie()));
}

test "zix dtls: hello parse, extensions are optional and pass through whole" {
    var buf: [256]u8 = undefined;
    const body = try writeClientHelloBody(&buf, dtls_record.VERSION_DTLS_1_2, TEST_RANDOM, "", "", &.{TEST_SUITE});

    // Written without an extensions block at all, which is legal.
    const no_extensions = try parseClientHello(body);
    try std.testing.expectEqual(@as(usize, 0), no_extensions.extensions.len);

    // Append an extensions block by hand and it comes back untouched.
    var with_buf: [256]u8 = undefined;
    @memcpy(with_buf[0..body.len], body);
    var writer = wire.Writer{ .buf = with_buf[body.len..] };
    const block = writer.placeU16();
    writer.writeU16(0x000d); // signature_algorithms
    writer.writeU16(2);
    writer.writeU16(0x0403);
    writer.patchU16(block);

    const with_extensions = try parseClientHello(with_buf[0 .. body.len + writer.len]);
    try std.testing.expectEqual(@as(usize, 6), with_extensions.extensions.len);
    try std.testing.expectEqual(@as(u16, 0x000d), std.mem.readInt(u16, with_extensions.extensions[0..2], .big));
}

test "zix dtls: hello parse, malformed bodies are refused" {
    var buf: [256]u8 = undefined;
    const body = try writeClientHelloBody(&buf, dtls_record.VERSION_DTLS_1_2, TEST_RANDOM, "", "", &.{TEST_SUITE});

    try std.testing.expectError(error.ZixTruncated, parseClientHello(body[0 .. body.len - 1]));
    try std.testing.expectError(error.ZixTruncated, parseClientHello(body[0..10]));
    try std.testing.expectError(error.ZixTruncated, parseClientHello(""));

    // A session id longer than the field allows.
    var bad_session: [256]u8 = undefined;
    @memcpy(bad_session[0..body.len], body);
    bad_session[34] = 33;
    try std.testing.expectError(error.ZixBadHello, parseClientHello(bad_session[0..body.len]));

    // An odd cipher suite list length cannot hold whole suites.
    var bad_suites: [256]u8 = undefined;
    @memcpy(bad_suites[0..body.len], body);
    bad_suites[37] = 3;
    try std.testing.expectError(error.ZixBadHello, parseClientHello(bad_suites[0..body.len]));
}

test "zix dtls: hello verify request, round trips the cookie at dtls 1.0" {
    const cookie: [32]u8 = @splat(0x5A);

    var buf: [64]u8 = undefined;
    const body = try writeHelloVerifyRequestBody(&buf, &cookie);

    // The version is 1.0 even from a 1.2 server, and it is not a negotiation signal.
    try std.testing.expectEqual(@as(u16, dtls_record.VERSION_DTLS_1_0), std.mem.readInt(u16, body[0..2], .big));
    try std.testing.expectEqual(@as(usize, 2 + 1 + 32), body.len);

    try std.testing.expectEqualSlices(u8, &cookie, try parseHelloVerifyRequestBody(body));

    try std.testing.expectError(error.ZixTruncated, parseHelloVerifyRequestBody(body[0 .. body.len - 1]));
    try std.testing.expectError(error.ZixTruncated, parseHelloVerifyRequestBody(""));

    const too_long: [MAX_COOKIE_LEN + 1]u8 = @splat(0);
    var big_buf: [512]u8 = undefined;
    try std.testing.expectError(error.ZixBadHello, writeHelloVerifyRequestBody(&big_buf, &too_long));
}

test "zix dtls: hello, a whole message round trips through the handshake header" {
    var body_buf: [256]u8 = undefined;
    const body = try writeClientHelloBody(&body_buf, dtls_record.VERSION_DTLS_1_2, TEST_RANDOM, "", "", &.{TEST_SUITE});

    var message: [512]u8 = undefined;
    var fragmenter: dtls_handshake.Fragmenter = .{
        .msg_type = .CLIENT_HELLO,
        .message_seq = 0,
        .body = body,
        .max_fragment_len = 1000,
    };
    const piece = fragmenter.next(&message).?;

    var iterator: dtls_handshake.FragmentIterator = .{ .body = piece };
    const fragment = (try iterator.next()).?;

    try std.testing.expectEqual(dtls_handshake.MessageType.CLIENT_HELLO, fragment.header.msg_type);

    const hello = try parseClientHello(fragment.data);
    try std.testing.expectEqualSlices(u8, &TEST_RANDOM, &hello.random);
}
