//! zix ICE-lite connectivity check responder (RFC 8445 4.2 / 7.3).
//!
//! What:
//! - The whole of an ice-lite agent. It never gathers candidates, never sends a check, and never
//!   nominates. It answers the checks the other peer sends, and it accepts the pair that peer
//!   nominates. That is the entire protocol for a peer that already sits on a reachable address.
//! - `respond` is a pure function over bytes apart from remembering the nominated address, so the
//!   rules stay testable without a socket and any dispatch model can call it from a datagram
//!   handler.
//!
//! Note:
//! - A lite agent is always the controlled one (RFC 8445 6.1.1). It cannot take the controlling
//!   role, so a peer that also claims to be controlled is an unresolvable conflict and gets 487
//!   every time. A full agent would compare tiebreakers and one side would switch, which is why
//!   there is no tiebreaker in this file at all.
//! - Every check is authenticated. Unlike plain STUN binding, a check without USERNAME and
//!   MESSAGE-INTEGRITY is answered with an error, and one whose MAC does not verify never reaches
//!   the response path.
//! - FINGERPRINT is required, not optional. It is what separates a check from the DTLS and media
//!   traffic sharing the port, and RFC 8445 7.1.1 has the sender include it on every check.
//! - Consent freshness (RFC 7675) is a full agent's job. A lite agent sends nothing, so it has no
//!   consent timer, which is what keeps this file free of any clock.
//!
//! Usage:
//! ```zig
//! var responder: lite.Responder = .{
//!     .local = .{ .ufrag = local_ufrag, .password = local_password },
//!     .remote_ufrag = remote_ufrag,
//! };
//!
//! fn handler(datagram: []const u8, peer: *const std.Io.net.IpAddress, sink: *zix.Udp.Sink) void {
//!     var buf: [lite.MAX_RESPONSE_BYTES]u8 = undefined;
//!     const outcome = responder.respond(datagram, peer, &buf);
//!
//!     if (outcome.reply) |reply| sink.replyTo(peer, reply);
//!     if (outcome.nominated) startDtls(peer);
//! }
//! ```

const std = @import("std");

const candidate = @import("candidate.zig");
const check = @import("check.zig");
const credentials = @import("credentials.zig");
const message = @import("../stun/message.zig");

const IpAddress = std.Io.net.IpAddress;

/// Largest response this file can produce. A caller that sizes its buffer to this never loses a
/// reply to a short buffer.
///
/// Note:
/// - Worst case is the 420 response: 20 header, 28 ERROR-CODE, 20 UNKNOWN-ATTRIBUTES, 24
///   MESSAGE-INTEGRITY, 8 FINGERPRINT. A success response is 76 bytes at most, on an IPv6 peer.
pub const MAX_RESPONSE_BYTES: usize = 128;

/// The request was missing the attributes every check must carry (RFC 8489 9.1.3).
pub const ERROR_BAD_REQUEST: u16 = 400;

/// The credentials did not match (RFC 8489 9.1.3).
pub const ERROR_UNAUTHORIZED: u16 = 401;

/// The request held a comprehension-required attribute this responder does not know
/// (RFC 8489 6.3.1).
pub const ERROR_UNKNOWN_ATTRIBUTE: u16 = 420;

/// Both peers claimed the same ICE role (RFC 8445 7.3.1.1).
pub const ERROR_ROLE_CONFLICT: u16 = 487;

/// Most unknown attribute types listed in one 420 response. The list is diagnostic, so truncating
/// it costs nothing.
const MAX_UNKNOWN_LISTED: usize = 8;

/// Recommended reason phrases (RFC 8489 14.8). Diagnostic text, never machine-read.
const REASON_BAD_REQUEST: []const u8 = "Bad Request";
const REASON_UNAUTHORIZED: []const u8 = "Unauthorized";
const REASON_UNKNOWN_ATTRIBUTE: []const u8 = "Unknown Attribute";
const REASON_ROLE_CONFLICT: []const u8 = "Role Conflict";

/// What one datagram did.
///
/// Note:
/// - reply null means send nothing, which covers every silent-discard case: not STUN, malformed,
///   a class or method this agent does not answer, a missing or broken FINGERPRINT, and an `out`
///   too small to hold the response.
/// - authenticated says the check carried credentials that verified, which is the first moment
///   the peer's address is worth acting on. nominated says that check also carried USE-CANDIDATE.
pub const Outcome = struct {
    reply: ?[]const u8 = null,
    authenticated: bool = false,
    nominated: bool = false,
};

/// One ice-lite agent, for one session.
///
/// Note:
/// - Borrows all three strings, it copies nothing. They have to outlive the responder, and they
///   are replaced together on an ICE restart.
/// - A named remote_ufrag has to be known before checks arrive. A peer starts sending checks as
///   soon as it has the answer, so a caller that has not read the peer's ufrag yet will reject
///   those early checks with 401 and wait for the retransmissions.
/// - A null remote_ufrag takes whatever the peer calls itself, and the local password stays the
///   gate. That is the case where the peer picks its own ufrag per session (a browser does) and
///   this agent has one set of credentials for everybody: the password is in the answer that peer
///   was handed, so proving it is what proves the session, and the ufrag adds nothing on top.
pub const Responder = struct {
    /// This agent's own ufrag and password, the credentials a check is verified against.
    local: credentials.Credentials,
    /// The other peer's ufrag, the second half of the USERNAME every check carries. Null takes any.
    remote_ufrag: ?[]const u8,
    /// Address the peer nominated with USE-CANDIDATE, once one has. This is the pair DTLS runs
    /// over.
    selected: ?IpAddress = null,

    /// Answer a datagram that may be an ICE connectivity check.
    ///
    /// Note:
    /// - The checks run in the order RFC 8489 6.3 sets out: authentication first, then unknown
    ///   attributes, then the rules specific to ICE. An error response only carries
    ///   MESSAGE-INTEGRITY once the credentials have verified, since before that there is no key
    ///   to sign it with.
    /// - A retransmitted check is recomputed rather than remembered, so no per-transaction state
    ///   is kept. Nominating twice from the same address is therefore harmless.
    ///
    /// Param:
    /// datagram - []const u8 (one received datagram)
    /// peer - *const std.Io.net.IpAddress (where it came from, the address reflected back)
    /// out - []u8 (destination for the response, MAX_RESPONSE_BYTES is always enough)
    ///
    /// Return:
    /// - Outcome
    pub fn respond(self: *Responder, datagram: []const u8, peer: *const IpAddress, out: []u8) Outcome {
        const request = message.parse(datagram) catch return .{};

        if (request.class != .REQUEST) return .{};
        if (request.method != .BINDING) return .{};
        if (request.fingerprint() != .VALID) return .{};

        const username = request.find(.USERNAME) orelse return badRequest(request, out);

        if (request.find(.MESSAGE_INTEGRITY) == null) return badRequest(request, out);

        const parts = credentials.splitUsername(username.value) catch return badRequest(request, out);

        if (!std.mem.eql(u8, parts.destination_ufrag, self.local.ufrag)) return unauthorized(request, out);

        if (self.remote_ufrag) |expected| {
            if (!std.mem.eql(u8, parts.source_ufrag, expected)) return unauthorized(request, out);
        }

        if (request.messageIntegrity(self.local.password) != .VALID) return unauthorized(request, out);

        var unknown: [MAX_UNKNOWN_LISTED]message.AttributeType = undefined;
        const unknown_kinds = message.collectUnknownRequired(request, &unknown);

        if (unknown_kinds.len > 0) {
            return .{
                .reply = unknownAttributeResponse(request, unknown_kinds, self.local.password, out),
                .authenticated = true,
            };
        }

        const fields = check.read(request) catch return .{
            .reply = errorResponse(request, ERROR_BAD_REQUEST, REASON_BAD_REQUEST, self.local.password, out),
            .authenticated = true,
        };

        // A lite agent cannot switch to controlling, so a peer that also calls itself controlled
        // is a conflict neither side can resolve.
        if (fields.role == .CONTROLLED) {
            return .{
                .reply = errorResponse(request, ERROR_ROLE_CONFLICT, REASON_ROLE_CONFLICT, self.local.password, out),
                .authenticated = true,
            };
        }

        const reply = successResponse(request, peer, self.local.password, out);

        if (reply != null and fields.use_candidate) {
            self.selected = peer.*;

            return .{ .reply = reply, .authenticated = true, .nominated = true };
        }

        return .{ .reply = reply, .authenticated = true };
    }

    /// The one candidate a lite agent has to offer, for the session description to publish.
    ///
    /// Note:
    /// - A lite agent has exactly one address per component, so the local preference is the
    ///   single-address value and there is nothing to choose between.
    ///
    /// Param:
    /// address - std.Io.net.IpAddress (the address this agent listens on)
    ///
    /// Return:
    /// - candidate.Candidate
    pub fn hostCandidate(address: IpAddress) candidate.Candidate {
        return candidate.Candidate.host(address, .RTP, candidate.SINGLE_ADDRESS_PREFERENCE);
    }
};

/// 400 for a check missing the attributes authentication needs. It cannot be signed, because the
/// key to sign it with is what the request failed to prove (RFC 8489 9.1.3).
fn badRequest(request: message.Message, out: []u8) Outcome {
    return .{ .reply = errorResponse(request, ERROR_BAD_REQUEST, REASON_BAD_REQUEST, null, out) };
}

/// 401 for credentials that did not match. Also unsigned, for the same reason.
fn unauthorized(request: message.Message, out: []u8) Outcome {
    return .{ .reply = errorResponse(request, ERROR_UNAUTHORIZED, REASON_UNAUTHORIZED, null, out) };
}

/// Success response: the reflected transport address, signed (RFC 8445 7.3).
fn successResponse(request: message.Message, peer: *const IpAddress, key: []const u8, out: []u8) ?[]const u8 {
    var writer = message.Writer.init(out, .SUCCESS_RESPONSE, .BINDING, request.transaction_id) catch return null;

    writer.addXorMappedAddress(peer.*) catch return null;
    writer.addMessageIntegrity(key) catch return null;
    writer.addFingerprint() catch return null;

    return writer.finish();
}

/// Error response, signed only when the caller has a verified key to sign it with.
fn errorResponse(request: message.Message, code: u16, reason: []const u8, key: ?[]const u8, out: []u8) ?[]const u8 {
    var writer = message.Writer.init(out, .ERROR_RESPONSE, .BINDING, request.transaction_id) catch return null;

    writer.addErrorCode(code, reason) catch return null;

    if (key) |verified| writer.addMessageIntegrity(verified) catch return null;

    writer.addFingerprint() catch return null;

    return writer.finish();
}

/// 420 error response naming the attributes that could not be understood (RFC 8489 6.3.1).
fn unknownAttributeResponse(request: message.Message, kinds: []const message.AttributeType, key: []const u8, out: []u8) ?[]const u8 {
    var writer = message.Writer.init(out, .ERROR_RESPONSE, .BINDING, request.transaction_id) catch return null;

    writer.addErrorCode(ERROR_UNKNOWN_ATTRIBUTE, REASON_UNKNOWN_ATTRIBUTE) catch return null;
    writer.addUnknownAttributes(kinds) catch return null;
    writer.addMessageIntegrity(key) catch return null;
    writer.addFingerprint() catch return null;

    return writer.finish();
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const TEST_TRANSACTION_ID: [message.TRANSACTION_ID_LEN]u8 = .{ 0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34, 0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE };

const TEST_LOCAL_UFRAG: []const u8 = "8hhY";
const TEST_LOCAL_PASSWORD: []const u8 = "asd88fgpdd777uzjYhagZg";
const TEST_REMOTE_UFRAG: []const u8 = "9uB6";
const TEST_REMOTE_PASSWORD: []const u8 = "YH75Fviy6338Vbrhrlp8Yh";

const TEST_PEER: IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 32853 } };

const TEST_PRIORITY: u32 = 1845494271;
const TEST_TIEBREAKER: u64 = 0x932FF9B151263B36;

fn testResponder() Responder {
    return .{
        .local = .{ .ufrag = TEST_LOCAL_UFRAG, .password = TEST_LOCAL_PASSWORD },
        .remote_ufrag = TEST_REMOTE_UFRAG,
    };
}

/// A check the responder should accept, unless a field is overridden.
const TestCheck = struct {
    destination_ufrag: []const u8 = TEST_LOCAL_UFRAG,
    source_ufrag: []const u8 = TEST_REMOTE_UFRAG,
    password: []const u8 = TEST_LOCAL_PASSWORD,
    role: check.Role = .CONTROLLING,
    use_candidate: bool = false,
};

fn writeTestCheck(out: []u8, params: TestCheck) []const u8 {
    var username_buf: [credentials.MAX_USERNAME_LEN]u8 = undefined;
    const username = credentials.writeUsername(&username_buf, params.destination_ufrag, params.source_ufrag) catch unreachable;

    return check.writeRequest(out, .{
        .transaction_id = TEST_TRANSACTION_ID,
        .username = username,
        .password = params.password,
        .priority = TEST_PRIORITY,
        .role = params.role,
        .tiebreaker = TEST_TIEBREAKER,
        .use_candidate = params.use_candidate,
    }) catch unreachable;
}

fn errorCodeOf(response: message.Message) u16 {
    const value = response.find(.ERROR_CODE).?.value;

    return @as(u16, value[2]) * 100 + value[3];
}

test "zix ice: lite respond, a valid check is answered with the reflected address" {
    var responder = testResponder();

    var request_buf: [256]u8 = undefined;
    const datagram = writeTestCheck(&request_buf, .{});

    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const outcome = responder.respond(datagram, &TEST_PEER, &out);

    try std.testing.expect(outcome.authenticated);
    try std.testing.expect(!outcome.nominated);
    try std.testing.expectEqual(@as(?IpAddress, null), responder.selected);

    const response = try message.parse(outcome.reply.?);
    try std.testing.expectEqual(message.Class.SUCCESS_RESPONSE, response.class);
    try std.testing.expectEqualSlices(u8, &TEST_TRANSACTION_ID, &response.transaction_id);

    const reflected = try message.decodeXorMappedAddress(
        response.find(.XOR_MAPPED_ADDRESS).?.value,
        &response.transaction_id,
    );
    try std.testing.expectEqualSlices(u8, &TEST_PEER.ip4.bytes, &reflected.ip4.bytes);
    try std.testing.expectEqual(TEST_PEER.ip4.port, reflected.ip4.port);
}

test "zix ice: lite respond, the response is signed with the local password" {
    var responder = testResponder();

    var request_buf: [256]u8 = undefined;
    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const outcome = responder.respond(writeTestCheck(&request_buf, .{}), &TEST_PEER, &out);

    const response = try message.parse(outcome.reply.?);
    try std.testing.expectEqual(message.IntegrityState.VALID, response.messageIntegrity(TEST_LOCAL_PASSWORD));
    try std.testing.expectEqual(message.FingerprintState.VALID, response.fingerprint());

    // The peer verifies with the password it was given, which is this agent's own, not its.
    try std.testing.expectEqual(message.IntegrityState.INVALID, response.messageIntegrity(TEST_REMOTE_PASSWORD));

    // FINGERPRINT last, integrity before it.
    try std.testing.expect(response.find(.MESSAGE_INTEGRITY).?.offset < response.find(.FINGERPRINT).?.offset);
    try std.testing.expectEqual(outcome.reply.?.len, response.find(.FINGERPRINT).?.offset + message.FINGERPRINT_LEN);
}

test "zix ice: lite respond, use-candidate nominates the address it came from" {
    var responder = testResponder();

    var request_buf: [256]u8 = undefined;
    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const outcome = responder.respond(writeTestCheck(&request_buf, .{ .use_candidate = true }), &TEST_PEER, &out);

    try std.testing.expect(outcome.nominated);
    try std.testing.expectEqualSlices(u8, &TEST_PEER.ip4.bytes, &responder.selected.?.ip4.bytes);
    try std.testing.expectEqual(TEST_PEER.ip4.port, responder.selected.?.ip4.port);

    // Nomination is still answered like any other check.
    try std.testing.expectEqual(message.Class.SUCCESS_RESPONSE, (try message.parse(outcome.reply.?)).class);
}

test "zix ice: lite respond, a failed check never nominates" {
    var responder = testResponder();

    var request_buf: [256]u8 = undefined;
    var out: [MAX_RESPONSE_BYTES]u8 = undefined;

    // Right attributes, wrong password: the nomination must not be taken on the way to the 401.
    const outcome = responder.respond(
        writeTestCheck(&request_buf, .{ .password = TEST_REMOTE_PASSWORD, .use_candidate = true }),
        &TEST_PEER,
        &out,
    );

    try std.testing.expect(!outcome.authenticated);
    try std.testing.expect(!outcome.nominated);
    try std.testing.expectEqual(@as(?IpAddress, null), responder.selected);
    try std.testing.expectEqual(ERROR_UNAUTHORIZED, errorCodeOf(try message.parse(outcome.reply.?)));
}

test "zix ice: lite respond, a wrong ufrag on either half is 401" {
    var responder = testResponder();

    const cases = [_]TestCheck{
        .{ .destination_ufrag = "0000" },
        .{ .source_ufrag = "0000" },
        .{ .password = TEST_REMOTE_PASSWORD },
    };

    for (cases) |params| {
        var request_buf: [256]u8 = undefined;
        var out: [MAX_RESPONSE_BYTES]u8 = undefined;
        const outcome = responder.respond(writeTestCheck(&request_buf, params), &TEST_PEER, &out);

        const response = try message.parse(outcome.reply.?);
        try std.testing.expectEqual(message.Class.ERROR_RESPONSE, response.class);
        try std.testing.expectEqual(ERROR_UNAUTHORIZED, errorCodeOf(response));

        // Nothing to sign an unauthenticated rejection with, so it goes out unsigned.
        try std.testing.expectEqual(message.IntegrityState.ABSENT, response.messageIntegrity(TEST_LOCAL_PASSWORD));
        try std.testing.expectEqual(message.FingerprintState.VALID, response.fingerprint());
    }
}

test "zix ice: lite respond, a null remote ufrag takes whatever the peer calls itself" {
    // What a browser needs: it draws its own ufrag per session, and this agent has one set of
    // credentials for every peer, so there is nothing to compare that half against.
    var responder = testResponder();
    responder.remote_ufrag = null;

    const names = [_][]const u8{ "9uB6", "aB3x", "someverylongufragvalue" };

    for (names) |name| {
        var request_buf: [256]u8 = undefined;
        var out: [MAX_RESPONSE_BYTES]u8 = undefined;
        const outcome = responder.respond(writeTestCheck(&request_buf, .{ .source_ufrag = name }), &TEST_PEER, &out);

        try std.testing.expect(outcome.authenticated);
        try std.testing.expectEqual(message.Class.SUCCESS_RESPONSE, (try message.parse(outcome.reply.?)).class);
    }
}

test "zix ice: lite respond, a null remote ufrag still holds a check to the local credentials" {
    var responder = testResponder();
    responder.remote_ufrag = null;

    // The half that names this agent is still compared, and the password is still the gate. Taking
    // any source ufrag lets a peer name itself, it does not let a stranger in.
    const cases = [_]TestCheck{
        .{ .destination_ufrag = "0000" },
        .{ .password = TEST_REMOTE_PASSWORD },
    };

    for (cases) |params| {
        var request_buf: [256]u8 = undefined;
        var out: [MAX_RESPONSE_BYTES]u8 = undefined;
        const outcome = responder.respond(writeTestCheck(&request_buf, params), &TEST_PEER, &out);

        try std.testing.expect(!outcome.authenticated);
        try std.testing.expectEqual(ERROR_UNAUTHORIZED, errorCodeOf(try message.parse(outcome.reply.?)));
    }
}

test "zix ice: lite respond, a check missing credentials is 400" {
    var responder = testResponder();
    var out: [MAX_RESPONSE_BYTES]u8 = undefined;

    // No USERNAME and no MESSAGE-INTEGRITY at all, a plain binding request.
    var plain_buf: [128]u8 = undefined;
    var plain = try message.Writer.init(&plain_buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try plain.addFingerprint();

    const no_credentials = responder.respond(plain.finish(), &TEST_PEER, &out);
    try std.testing.expectEqual(ERROR_BAD_REQUEST, errorCodeOf(try message.parse(no_credentials.reply.?)));

    // USERNAME present, MESSAGE-INTEGRITY missing.
    var half_buf: [128]u8 = undefined;
    var half = try message.Writer.init(&half_buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try half.addAttribute(.USERNAME, "8hhY:9uB6");
    try half.addFingerprint();

    const no_integrity = responder.respond(half.finish(), &TEST_PEER, &out);
    try std.testing.expectEqual(ERROR_BAD_REQUEST, errorCodeOf(try message.parse(no_integrity.reply.?)));

    // A USERNAME that does not hold two ufrags cannot be checked against anything.
    var malformed_buf: [128]u8 = undefined;
    var malformed = try message.Writer.init(&malformed_buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try malformed.addAttribute(.USERNAME, "noseparator");
    try malformed.addMessageIntegrity(TEST_LOCAL_PASSWORD);
    try malformed.addFingerprint();

    const bad_username = responder.respond(malformed.finish(), &TEST_PEER, &out);
    try std.testing.expectEqual(ERROR_BAD_REQUEST, errorCodeOf(try message.parse(bad_username.reply.?)));
}

test "zix ice: lite respond, a peer claiming the controlled role gets 487" {
    var responder = testResponder();

    var request_buf: [256]u8 = undefined;
    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const outcome = responder.respond(writeTestCheck(&request_buf, .{ .role = .CONTROLLED }), &TEST_PEER, &out);

    try std.testing.expect(outcome.authenticated);
    try std.testing.expect(!outcome.nominated);

    const response = try message.parse(outcome.reply.?);
    try std.testing.expectEqual(message.Class.ERROR_RESPONSE, response.class);
    try std.testing.expectEqual(ERROR_ROLE_CONFLICT, errorCodeOf(response));

    // The credentials verified before the conflict was found, so this one is signed.
    try std.testing.expectEqual(message.IntegrityState.VALID, response.messageIntegrity(TEST_LOCAL_PASSWORD));
}

test "zix ice: lite respond, a role conflict is decided without a tiebreaker" {
    var responder = testResponder();

    // A full agent would compare tiebreakers and one side would switch. A lite agent answers 487
    // for every value, because it has no role to switch to.
    const tiebreakers = [_]u64{ 0, 1, std.math.maxInt(u64) };
    for (tiebreakers) |tiebreaker| {
        var username_buf: [credentials.MAX_USERNAME_LEN]u8 = undefined;
        const username = try credentials.writeUsername(&username_buf, TEST_LOCAL_UFRAG, TEST_REMOTE_UFRAG);

        var request_buf: [256]u8 = undefined;
        const datagram = try check.writeRequest(&request_buf, .{
            .transaction_id = TEST_TRANSACTION_ID,
            .username = username,
            .password = TEST_LOCAL_PASSWORD,
            .priority = TEST_PRIORITY,
            .role = .CONTROLLED,
            .tiebreaker = tiebreaker,
        });

        var out: [MAX_RESPONSE_BYTES]u8 = undefined;
        const outcome = responder.respond(datagram, &TEST_PEER, &out);

        try std.testing.expectEqual(ERROR_ROLE_CONFLICT, errorCodeOf(try message.parse(outcome.reply.?)));
    }
}

test "zix ice: lite respond, an unknown comprehension-required attribute gets a signed 420" {
    var responder = testResponder();

    var username_buf: [credentials.MAX_USERNAME_LEN]u8 = undefined;
    const username = try credentials.writeUsername(&username_buf, TEST_LOCAL_UFRAG, TEST_REMOTE_UFRAG);

    var request_buf: [256]u8 = undefined;
    var writer = try message.Writer.init(&request_buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try writer.addAttribute(.USERNAME, username);
    try check.addPriority(&writer, TEST_PRIORITY);
    try check.addRole(&writer, .CONTROLLING, TEST_TIEBREAKER);
    try writer.addAttribute(@enumFromInt(0x0042), "extension");
    try writer.addMessageIntegrity(TEST_LOCAL_PASSWORD);
    try writer.addFingerprint();

    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const outcome = responder.respond(writer.finish(), &TEST_PEER, &out);

    const response = try message.parse(outcome.reply.?);
    try std.testing.expectEqual(ERROR_UNKNOWN_ATTRIBUTE, errorCodeOf(response));
    try std.testing.expectEqual(message.IntegrityState.VALID, response.messageIntegrity(TEST_LOCAL_PASSWORD));

    const listed = response.find(.UNKNOWN_ATTRIBUTES).?;
    try std.testing.expectEqual(@as(u16, 0x0042), std.mem.readInt(u16, listed.value[0..2], .big));
    try std.testing.expect(outcome.reply.?.len <= MAX_RESPONSE_BYTES);
}

test "zix ice: lite respond, a malformed ice attribute is 400 after authentication" {
    var responder = testResponder();

    var username_buf: [credentials.MAX_USERNAME_LEN]u8 = undefined;
    const username = try credentials.writeUsername(&username_buf, TEST_LOCAL_UFRAG, TEST_REMOTE_UFRAG);

    var request_buf: [256]u8 = undefined;
    var writer = try message.Writer.init(&request_buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try writer.addAttribute(.USERNAME, username);
    try writer.addAttribute(.PRIORITY, "three");
    try writer.addMessageIntegrity(TEST_LOCAL_PASSWORD);
    try writer.addFingerprint();

    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const outcome = responder.respond(writer.finish(), &TEST_PEER, &out);

    const response = try message.parse(outcome.reply.?);
    try std.testing.expect(outcome.authenticated);
    try std.testing.expectEqual(ERROR_BAD_REQUEST, errorCodeOf(response));
    try std.testing.expectEqual(message.IntegrityState.VALID, response.messageIntegrity(TEST_LOCAL_PASSWORD));
}

test "zix ice: lite respond, traffic that is not a check is ignored" {
    var responder = testResponder();
    var out: [MAX_RESPONSE_BYTES]u8 = undefined;

    // Another protocol sharing the port (RFC 7983).
    var dtls_record: [40]u8 = @splat(0);
    dtls_record[0] = 0x16;
    dtls_record[1] = 0xfe;
    dtls_record[2] = 0xfd;

    try std.testing.expectEqual(@as(?[]const u8, null), responder.respond(&dtls_record, &TEST_PEER, &out).reply);
    try std.testing.expectEqual(@as(?[]const u8, null), responder.respond(&[_]u8{}, &TEST_PEER, &out).reply);

    // A response, not a request: a lite agent sends no checks, so nothing can be answering it.
    var response_buf: [128]u8 = undefined;
    var response = try message.Writer.init(&response_buf, .SUCCESS_RESPONSE, .BINDING, TEST_TRANSACTION_ID);
    try response.addFingerprint();

    try std.testing.expectEqual(@as(?[]const u8, null), responder.respond(response.finish(), &TEST_PEER, &out).reply);
}

test "zix ice: lite respond, a check without a valid fingerprint is discarded" {
    var responder = testResponder();
    var out: [MAX_RESPONSE_BYTES]u8 = undefined;

    var request_buf: [256]u8 = undefined;
    const datagram = writeTestCheck(&request_buf, .{});

    // One flipped bit in the CRC, everything else intact.
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..datagram.len], datagram);
    tampered[datagram.len - 1] ^= 0x01;

    try std.testing.expectEqual(@as(?[]const u8, null), responder.respond(tampered[0..datagram.len], &TEST_PEER, &out).reply);

    // No FINGERPRINT at all is discarded too, even with credentials that would have verified.
    var username_buf: [credentials.MAX_USERNAME_LEN]u8 = undefined;
    const username = try credentials.writeUsername(&username_buf, TEST_LOCAL_UFRAG, TEST_REMOTE_UFRAG);

    var plain_buf: [256]u8 = undefined;
    var plain = try message.Writer.init(&plain_buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try plain.addAttribute(.USERNAME, username);
    try plain.addMessageIntegrity(TEST_LOCAL_PASSWORD);

    try std.testing.expectEqual(@as(?[]const u8, null), responder.respond(plain.finish(), &TEST_PEER, &out).reply);
}

test "zix ice: lite respond, a retransmitted check gets a byte-identical answer" {
    var responder = testResponder();

    var request_buf: [256]u8 = undefined;
    const datagram = writeTestCheck(&request_buf, .{ .use_candidate = true });

    var first_out: [MAX_RESPONSE_BYTES]u8 = undefined;
    var second_out: [MAX_RESPONSE_BYTES]u8 = undefined;

    const first = responder.respond(datagram, &TEST_PEER, &first_out);
    const second = responder.respond(datagram, &TEST_PEER, &second_out);

    try std.testing.expectEqualSlices(u8, first.reply.?, second.reply.?);
    try std.testing.expect(second.nominated);
}

test "zix ice: lite respond, an ipv6 peer is reflected and the reply still fits" {
    var responder = testResponder();

    const peer: IpAddress = .{ .ip6 = .{
        .bytes = .{ 0x20, 0x01, 0x0d, 0xb8, 0x12, 0x34, 0x56, 0x78, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 },
        .port = 41000,
    } };

    var request_buf: [256]u8 = undefined;
    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const outcome = responder.respond(writeTestCheck(&request_buf, .{}), &peer, &out);

    const response = try message.parse(outcome.reply.?);
    const reflected = try message.decodeXorMappedAddress(
        response.find(.XOR_MAPPED_ADDRESS).?.value,
        &response.transaction_id,
    );

    try std.testing.expectEqualSlices(u8, &peer.ip6.bytes, &reflected.ip6.bytes);
    try std.testing.expect(outcome.reply.?.len <= MAX_RESPONSE_BYTES);
}

test "zix ice: lite respond, a buffer too small drops the reply instead of writing past it" {
    var responder = testResponder();

    var request_buf: [256]u8 = undefined;
    const datagram = writeTestCheck(&request_buf, .{ .use_candidate = true });

    var out: [MAX_RESPONSE_BYTES]u8 = undefined;
    const full = responder.respond(datagram, &TEST_PEER, &out).reply.?;

    var starved = testResponder();

    var one_short: [MAX_RESPONSE_BYTES]u8 = undefined;
    const outcome = starved.respond(datagram, &TEST_PEER, one_short[0 .. full.len - 1]);

    try std.testing.expectEqual(@as(?[]const u8, null), outcome.reply);

    // The nomination is not claimed when the answer could not be sent, so the peer retransmits
    // and both sides stay in step.
    try std.testing.expect(!outcome.nominated);
    try std.testing.expectEqual(@as(?IpAddress, null), starved.selected);
}

test "zix ice: lite candidate, the agent publishes one host candidate" {
    const address: IpAddress = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 7 }, .port = 9083 } };
    const local = Responder.hostCandidate(address);

    try std.testing.expectEqual(candidate.Type.HOST, local.kind);
    try std.testing.expectEqual(candidate.Component.RTP, local.component);
    try std.testing.expectEqual(
        candidate.priorityOf(.HOST, candidate.SINGLE_ADDRESS_PREFERENCE, .RTP),
        local.priority,
    );
}
