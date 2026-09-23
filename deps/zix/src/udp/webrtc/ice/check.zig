//! zix ICE connectivity check message (RFC 8445 7.1.1 / 7.3, attributes 16.1).
//!
//! What:
//! - The four attributes that turn a plain STUN binding request into an ICE connectivity check:
//!   PRIORITY, USE-CANDIDATE, ICE-CONTROLLING, and ICE-CONTROLLED. This file encodes and decodes
//!   their values, and builds or reads a whole check.
//! - `read` pulls a request apart into the fields a responder decides on. `writeRequest` builds
//!   one, which is what the checking half of a pair sends and what the responder tests are
//!   written against.
//!
//! Note:
//! - The attribute type numbers live in stun/message.zig with the rest of the registry, because
//!   an unknown-attribute scan has to recognise them. What they mean is here.
//! - A check is authenticated, always. USERNAME plus MESSAGE-INTEGRITY are not optional the way
//!   they are in plain STUN, so `writeRequest` takes a password and there is no way to build one
//!   without it.
//! - PRIORITY carries the priority the sender would give a peer-reflexive candidate discovered
//!   through this check (RFC 8445 7.1.1), not the priority of the candidate it is sending from.
//!   A responder that is not doing candidate discovery reads it and does nothing with it.

const std = @import("std");

const credentials = @import("credentials.zig");
const message = @import("../stun/message.zig");

/// Which agent nominates. Exactly one of a pair holds each role (RFC 8445 6.1.1), and a lite
/// agent is always the controlled one.
pub const Role = enum { CONTROLLING, CONTROLLED };

/// Size of the ICE-CONTROLLING and ICE-CONTROLLED values, a 64-bit tiebreaker (RFC 8445 16.1).
pub const TIEBREAKER_LEN: usize = 8;

/// Size of the PRIORITY value (RFC 8445 16.1).
pub const PRIORITY_LEN: usize = 4;

/// An attribute value whose length does not match its type.
pub const Error = error{ZixBadAttribute};

/// What a responder needs out of a connectivity check.
///
/// Note:
/// - Borrows the request bytes, it copies nothing.
/// - tiebreaker is meaningless when role is null, and is left at 0 in that case.
pub const Check = struct {
    /// USERNAME, still joined. Split it with credentials.splitUsername.
    username: ?[]const u8 = null,
    priority: ?u32 = null,
    use_candidate: bool = false,
    role: ?Role = null,
    tiebreaker: u64 = 0,
    /// Whether MESSAGE-INTEGRITY is present. Whether it verifies is a separate question, asked
    /// with the key, and the two are separate because a missing attribute and a wrong MAC are
    /// answered with different error codes.
    has_integrity: bool = false,
};

/// Read the ICE fields out of a parsed binding request.
///
/// Note:
/// - An attribute of the wrong length is an error rather than a silently dropped field. Reading a
///   malformed ICE-CONTROLLED as "no role" would skip the role conflict check, which is the one
///   place a badly formed check has to change what the responder answers.
///
/// Param:
/// request - stun.message.Message (an already parsed request)
///
/// Return:
/// - Check (borrowing the request bytes)
/// - error.ZixBadAttribute when a value length does not match its type, or both role attributes are
///   present at once
pub fn read(request: message.Message) Error!Check {
    var check: Check = .{};

    if (request.find(.USERNAME)) |attr| check.username = attr.value;
    if (request.find(.MESSAGE_INTEGRITY)) |_| check.has_integrity = true;

    if (request.find(.PRIORITY)) |attr| {
        if (attr.value.len != PRIORITY_LEN) return error.ZixBadAttribute;

        check.priority = std.mem.readInt(u32, attr.value[0..4], .big);
    }

    if (request.find(.USE_CANDIDATE)) |attr| {
        if (attr.value.len != 0) return error.ZixBadAttribute;

        check.use_candidate = true;
    }

    const controlling = request.find(.ICE_CONTROLLING);
    const controlled = request.find(.ICE_CONTROLLED);

    if (controlling != null and controlled != null) return error.ZixBadAttribute;

    if (controlling orelse controlled) |attr| {
        if (attr.value.len != TIEBREAKER_LEN) return error.ZixBadAttribute;

        check.role = if (controlling != null) .CONTROLLING else .CONTROLLED;
        check.tiebreaker = std.mem.readInt(u64, attr.value[0..8], .big);
    }

    return check;
}

/// Everything a connectivity check carries.
///
/// Note:
/// - username is the joined form, `<destination ufrag>:<source ufrag>`. Build it with
///   credentials.writeUsername.
/// - password is the destination peer's password, since that is the key the peer being asked will
///   verify the check with.
pub const Request = struct {
    transaction_id: [message.TRANSACTION_ID_LEN]u8,
    username: []const u8,
    password: []const u8,
    priority: u32,
    role: Role,
    tiebreaker: u64,
    use_candidate: bool = false,
};

/// Build a connectivity check (RFC 8445 7.1.1).
///
/// Note:
/// - MESSAGE-INTEGRITY and FINGERPRINT are appended last and in that order, which is the only
///   order in which both can be verified.
///
/// Param:
/// out - []u8 (destination, size it with requestLen)
/// request - Request
///
/// Return:
/// - []const u8 (the check, borrowing out)
/// - error.ZixNoSpace when out is too small
pub fn writeRequest(out: []u8, request: Request) message.Writer.Error![]const u8 {
    var writer = try message.Writer.init(out, .REQUEST, .BINDING, request.transaction_id);

    try writer.addAttribute(.USERNAME, request.username);
    try addPriority(&writer, request.priority);
    try addRole(&writer, request.role, request.tiebreaker);

    if (request.use_candidate) try addUseCandidate(&writer);

    try writer.addMessageIntegrity(request.password);
    try writer.addFingerprint();

    return writer.finish();
}

/// Bytes a check occupies on the wire, so a caller can size one buffer and stop guessing.
pub fn requestLen(username_len: usize, use_candidate: bool) usize {
    const username_bytes = message.ATTRIBUTE_HEADER_LEN + padTo4(username_len);
    const use_candidate_bytes: usize = if (use_candidate) message.ATTRIBUTE_HEADER_LEN else 0;

    return message.HEADER_LEN + username_bytes +
        (message.ATTRIBUTE_HEADER_LEN + PRIORITY_LEN) +
        (message.ATTRIBUTE_HEADER_LEN + TIEBREAKER_LEN) +
        use_candidate_bytes + message.MESSAGE_INTEGRITY_LEN + message.FINGERPRINT_LEN;
}

/// Append PRIORITY (RFC 8445 16.1).
pub fn addPriority(writer: *message.Writer, priority: u32) message.Writer.Error!void {
    var value: [PRIORITY_LEN]u8 = undefined;
    std.mem.writeInt(u32, &value, priority, .big);

    try writer.addAttribute(.PRIORITY, &value);
}

/// Append USE-CANDIDATE (RFC 8445 16.1), the flag that nominates a pair. It carries no value, its
/// presence is the whole signal.
pub fn addUseCandidate(writer: *message.Writer) message.Writer.Error!void {
    try writer.addAttribute(.USE_CANDIDATE, "");
}

/// Append ICE-CONTROLLING or ICE-CONTROLLED with the sender's tiebreaker (RFC 8445 16.1).
///
/// Note:
/// - The tiebreaker has to stay the same for the whole session, including across a role switch.
///   Regenerating it per check makes a role conflict unresolvable, because each side keeps
///   comparing against a number the other has already replaced.
pub fn addRole(writer: *message.Writer, role: Role, tiebreaker: u64) message.Writer.Error!void {
    var value: [TIEBREAKER_LEN]u8 = undefined;
    std.mem.writeInt(u64, &value, tiebreaker, .big);

    try writer.addAttribute(switch (role) {
        .CONTROLLING => .ICE_CONTROLLING,
        .CONTROLLED => .ICE_CONTROLLED,
    }, &value);
}

/// Round a value length up to the 4-byte boundary every attribute ends on (RFC 8489 14).
fn padTo4(value_len: usize) usize {
    return (value_len + 3) & ~@as(usize, 3);
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const TEST_TRANSACTION_ID: [message.TRANSACTION_ID_LEN]u8 = .{ 0xB7, 0xE7, 0xA7, 0x01, 0xBC, 0x34, 0xD6, 0x86, 0xFA, 0x87, 0xDF, 0xAE };

const TEST_PASSWORD: []const u8 = "asd88fgpdd777uzjYhagZg";

const TEST_TIEBREAKER: u64 = 0x932FF9B151263B36;

fn testRequest(use_candidate: bool) Request {
    return .{
        .transaction_id = TEST_TRANSACTION_ID,
        .username = "8hhY:9uB6",
        .password = TEST_PASSWORD,
        .priority = 1845494271,
        .role = .CONTROLLING,
        .tiebreaker = TEST_TIEBREAKER,
        .use_candidate = use_candidate,
    };
}

test "zix ice: check write, a built check reads back field for field" {
    var buf: [256]u8 = undefined;
    const datagram = try writeRequest(&buf, testRequest(false));

    const request = try message.parse(datagram);
    try std.testing.expectEqual(message.Class.REQUEST, request.class);
    try std.testing.expectEqual(message.Method.BINDING, request.method);

    const check = try read(request);
    try std.testing.expectEqualStrings("8hhY:9uB6", check.username.?);
    try std.testing.expectEqual(@as(u32, 1845494271), check.priority.?);
    try std.testing.expectEqual(Role.CONTROLLING, check.role.?);
    try std.testing.expectEqual(TEST_TIEBREAKER, check.tiebreaker);
    try std.testing.expect(!check.use_candidate);
    try std.testing.expect(check.has_integrity);
}

test "zix ice: check write, both credentials attributes verify on the built check" {
    var buf: [256]u8 = undefined;
    const request = try message.parse(try writeRequest(&buf, testRequest(false)));

    try std.testing.expectEqual(message.IntegrityState.VALID, request.messageIntegrity(TEST_PASSWORD));
    try std.testing.expectEqual(message.FingerprintState.VALID, request.fingerprint());

    // FINGERPRINT is last, which is what lets the integrity attribute before it still verify.
    try std.testing.expectEqual(
        (try writeRequest(&buf, testRequest(false))).len,
        request.find(.FINGERPRINT).?.offset + message.FINGERPRINT_LEN,
    );
}

test "zix ice: check write, use-candidate is a flag and carries no value" {
    var buf: [256]u8 = undefined;
    const request = try message.parse(try writeRequest(&buf, testRequest(true)));

    const attr = request.find(.USE_CANDIDATE).?;
    try std.testing.expectEqual(@as(usize, 0), attr.value.len);

    const check = try read(request);
    try std.testing.expect(check.use_candidate);
}

test "zix ice: check write, the controlled role picks the other attribute type" {
    var params = testRequest(false);
    params.role = .CONTROLLED;

    var buf: [256]u8 = undefined;
    const request = try message.parse(try writeRequest(&buf, params));

    try std.testing.expect(request.find(.ICE_CONTROLLED) != null);
    try std.testing.expectEqual(@as(?message.Attribute, null), request.find(.ICE_CONTROLLING));

    const check = try read(request);
    try std.testing.expectEqual(Role.CONTROLLED, check.role.?);
    try std.testing.expectEqual(TEST_TIEBREAKER, check.tiebreaker);
}

test "zix ice: check length, the published size matches the bytes written" {
    var buf: [256]u8 = undefined;

    const plain = try writeRequest(&buf, testRequest(false));
    try std.testing.expectEqual(plain.len, requestLen("8hhY:9uB6".len, false));

    const nominating = try writeRequest(&buf, testRequest(true));
    try std.testing.expectEqual(nominating.len, requestLen("8hhY:9uB6".len, true));

    // A buffer of exactly that size works, one byte less does not.
    var exact: [requestLen("8hhY:9uB6".len, false)]u8 = undefined;
    _ = try writeRequest(&exact, testRequest(false));

    var one_short: [requestLen("8hhY:9uB6".len, false) - 1]u8 = undefined;
    try std.testing.expectError(error.ZixNoSpace, writeRequest(&one_short, testRequest(false)));
}

test "zix ice: check read, a request with no ice attributes reads as empty" {
    var buf: [64]u8 = undefined;
    var writer = try message.Writer.init(&buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);

    const check = try read(try message.parse(writer.finish()));
    try std.testing.expectEqual(@as(?[]const u8, null), check.username);
    try std.testing.expectEqual(@as(?u32, null), check.priority);
    try std.testing.expectEqual(@as(?Role, null), check.role);
    try std.testing.expectEqual(@as(u64, 0), check.tiebreaker);
    try std.testing.expect(!check.use_candidate);
    try std.testing.expect(!check.has_integrity);
}

test "zix ice: check read, an attribute of the wrong length is an error" {
    const cases = [_]struct { kind: message.AttributeType, value: []const u8 }{
        .{ .kind = .PRIORITY, .value = "abc" },
        .{ .kind = .PRIORITY, .value = "abcde" },
        .{ .kind = .USE_CANDIDATE, .value = "x" },
        .{ .kind = .ICE_CONTROLLING, .value = "seven!!" },
        .{ .kind = .ICE_CONTROLLED, .value = "" },
    };

    for (cases) |case| {
        var buf: [64]u8 = undefined;
        var writer = try message.Writer.init(&buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
        try writer.addAttribute(case.kind, case.value);

        try std.testing.expectError(error.ZixBadAttribute, read(try message.parse(writer.finish())));
    }
}

test "zix ice: check read, claiming both roles at once is an error" {
    var buf: [128]u8 = undefined;
    var writer = try message.Writer.init(&buf, .REQUEST, .BINDING, TEST_TRANSACTION_ID);
    try addRole(&writer, .CONTROLLING, TEST_TIEBREAKER);
    try addRole(&writer, .CONTROLLED, TEST_TIEBREAKER);

    try std.testing.expectError(error.ZixBadAttribute, read(try message.parse(writer.finish())));
}

test "zix ice: check read, integrity presence and validity are separate answers" {
    var buf: [256]u8 = undefined;
    const request = try message.parse(try writeRequest(&buf, testRequest(false)));

    const check = try read(request);
    try std.testing.expect(check.has_integrity);
    try std.testing.expectEqual(message.IntegrityState.INVALID, request.messageIntegrity("another password"));
}

test "zix ice: check username, the built check splits into the two ufrags" {
    var username_buf: [credentials.MAX_USERNAME_LEN]u8 = undefined;
    const username = try credentials.writeUsername(&username_buf, "8hhY", "9uB6");

    var params = testRequest(false);
    params.username = username;

    var buf: [256]u8 = undefined;
    const check = try read(try message.parse(try writeRequest(&buf, params)));

    const parts = try credentials.splitUsername(check.username.?);
    try std.testing.expectEqualStrings("8hhY", parts.destination_ufrag);
    try std.testing.expectEqualStrings("9uB6", parts.source_ufrag);
}
