//! zix ICE short-term credentials (RFC 8445 5.3 / 7.1.2).
//!
//! What:
//! - The username fragment and password a peer publishes in its session description, and the
//!   USERNAME attribute a connectivity check carries. Every check is authenticated with these:
//!   the password is the STUN short-term key, and the ufrag pair says which two peers the check
//!   belongs to.
//! - Both halves of the USERNAME are handled here, so no caller has to remember which ufrag comes
//!   first.
//!
//! Note:
//! - The USERNAME on a check reads `<destination ufrag>:<source ufrag>` (RFC 8445 7.1.2), so the
//!   first half is the ufrag of the peer being asked and the second is the ufrag of the peer
//!   asking. Reading it the other way round rejects every legitimate check, and the two halves
//!   look alike, which is why they are named for direction rather than for local and remote.
//! - Credentials are per session, not per candidate. One ufrag and password cover every check on
//!   every pair in that session, and they change on an ICE restart.
//! - Generating them needs entropy, and sourcing entropy is the caller's job. `fillIceChars` maps
//!   caller-supplied bytes onto the allowed alphabet, which keeps this file free of any platform
//!   call and identical on every target.

const std = @import("std");

/// Shortest username fragment RFC 8445 5.3 allows. The floor exists because the ufrag has to
/// carry at least 24 bits of randomness.
pub const MIN_UFRAG_LEN: usize = 4;

/// Longest username fragment RFC 8445 5.3 allows.
pub const MAX_UFRAG_LEN: usize = 256;

/// Shortest password RFC 8445 5.3 allows, the length that carries 128 bits of randomness.
pub const MIN_PASSWORD_LEN: usize = 22;

/// Longest password RFC 8445 5.3 allows.
pub const MAX_PASSWORD_LEN: usize = 256;

/// Byte that separates the two ufrags inside a USERNAME attribute (RFC 8445 7.1.2).
pub const USERNAME_SEPARATOR: u8 = ':';

/// Longest USERNAME a check can carry: two ufrags at their maximum plus the separator.
pub const MAX_USERNAME_LEN: usize = MAX_UFRAG_LEN * 2 + 1;

/// The ice-char alphabet (RFC 8445 15.4). 64 characters, so a byte maps onto it with no bias.
const ICE_CHARS: []const u8 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Why a credential or a USERNAME is not usable.
pub const Error = error{
    ZixTooShort,
    ZixTooLong,
    ZixBadCharacter,
    ZixMissingSeparator,
    ZixNoSpace,
};

/// One peer's session credentials.
///
/// Note:
/// - Borrows both strings, it copies nothing. They have to outlive the responder that holds them.
pub const Credentials = struct {
    ufrag: []const u8,
    password: []const u8,

    /// Check both halves against the lengths and alphabet RFC 8445 5.3 requires.
    ///
    /// Note:
    /// - Worth calling once on credentials that arrived from a peer, before they are used as a
    ///   MAC key or compared against a USERNAME. A password that is too short is a weak key, and
    ///   the length rule is the only signal available that the peer is not doing ICE properly.
    ///
    /// Return:
    /// - void
    /// - Error when a length is out of range or a character is outside the alphabet
    pub fn validate(self: Credentials) Error!void {
        try validateIceString(self.ufrag, MIN_UFRAG_LEN, MAX_UFRAG_LEN);
        try validateIceString(self.password, MIN_PASSWORD_LEN, MAX_PASSWORD_LEN);
    }
};

/// The two halves of a USERNAME attribute, named for the direction the check travels.
pub const Username = struct {
    /// Ufrag of the peer the check was sent to.
    destination_ufrag: []const u8,
    /// Ufrag of the peer that sent it.
    source_ufrag: []const u8,
};

/// Split a USERNAME attribute value into its two ufrags (RFC 8445 7.1.2).
///
/// Note:
/// - Splits at the first separator. A ufrag cannot contain one, since `:` is not an ice-char, so
///   a second separator means the value is malformed and both halves are checked for it.
/// - The halves are only bounds-checked here, not compared. Which ufrags are expected is the
///   responder's business.
///
/// Param:
/// username - []const u8 (the USERNAME attribute value, padding excluded)
///
/// Return:
/// - Username (borrowing username)
/// - Error when the separator is missing, or either half is not a usable ufrag
pub fn splitUsername(username: []const u8) Error!Username {
    if (username.len > MAX_USERNAME_LEN) return error.ZixTooLong;

    const separator = std.mem.indexOfScalar(u8, username, USERNAME_SEPARATOR) orelse return error.ZixMissingSeparator;
    const parts: Username = .{
        .destination_ufrag = username[0..separator],
        .source_ufrag = username[separator + 1 ..],
    };

    try validateIceString(parts.destination_ufrag, MIN_UFRAG_LEN, MAX_UFRAG_LEN);
    try validateIceString(parts.source_ufrag, MIN_UFRAG_LEN, MAX_UFRAG_LEN);

    return parts;
}

/// Build the USERNAME attribute value for a check (RFC 8445 7.1.2).
///
/// Param:
/// out - []u8 (destination, MAX_USERNAME_LEN is always enough)
/// destination_ufrag - []const u8 (ufrag of the peer being asked)
/// source_ufrag - []const u8 (ufrag of the peer asking)
///
/// Return:
/// - []const u8 (the value, borrowing out)
/// - error.ZixNoSpace when out is too small
pub fn writeUsername(out: []u8, destination_ufrag: []const u8, source_ufrag: []const u8) Error![]const u8 {
    const total = destination_ufrag.len + 1 + source_ufrag.len;

    if (total > out.len) return error.ZixNoSpace;

    @memcpy(out[0..destination_ufrag.len], destination_ufrag);
    out[destination_ufrag.len] = USERNAME_SEPARATOR;
    @memcpy(out[destination_ufrag.len + 1 ..][0..source_ufrag.len], source_ufrag);

    return out[0..total];
}

/// Turn caller-supplied entropy into a ufrag or password (RFC 8445 15.4).
///
/// Note:
/// - One byte of entropy per character, and the alphabet is 64 characters, so the mapping throws
///   away 2 bits per byte rather than biasing toward the first 16 characters the way a modulo of
///   a non-power-of-two alphabet would.
/// - The result is only as unpredictable as the entropy handed in. Passing a counter, a timestamp,
///   or anything else guessable produces a credential an attacker can reproduce.
///
/// Param:
/// dst - []u8 (filled completely, its length is the credential length)
/// entropy - []const u8 (at least dst.len unpredictable bytes)
///
/// Return:
/// - void
/// - error.ZixTooShort when entropy is smaller than dst
pub fn fillIceChars(dst: []u8, entropy: []const u8) error{ZixTooShort}!void {
    if (entropy.len < dst.len) return error.ZixTooShort;

    for (dst, entropy[0..dst.len]) |*char, byte| char.* = ICE_CHARS[byte % ICE_CHARS.len];
}

/// Whether a byte is an ice-char, the only characters a ufrag or password may contain.
pub fn isIceChar(byte: u8) bool {
    return switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '+', '/' => true,
        else => false,
    };
}

/// Length and alphabet check shared by the ufrag and the password.
fn validateIceString(text: []const u8, min_len: usize, max_len: usize) Error!void {
    if (text.len < min_len) return error.ZixTooShort;
    if (text.len > max_len) return error.ZixTooLong;

    for (text) |byte| {
        if (!isIceChar(byte)) return error.ZixBadCharacter;
    }
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const TEST_UFRAG: []const u8 = "8hhY";
const TEST_PASSWORD: []const u8 = "asd88fgpdd777uzjYhagZg";

test "zix ice: credentials validate, the RFC 8445 example passes" {
    const creds: Credentials = .{ .ufrag = TEST_UFRAG, .password = TEST_PASSWORD };
    try creds.validate();

    try std.testing.expectEqual(@as(usize, 4), TEST_UFRAG.len);
    try std.testing.expectEqual(@as(usize, 22), TEST_PASSWORD.len);
}

test "zix ice: credentials validate, a short ufrag or password is rejected" {
    const short_ufrag: Credentials = .{ .ufrag = "abc", .password = TEST_PASSWORD };
    try std.testing.expectError(error.ZixTooShort, short_ufrag.validate());

    // One character below the floor fails, so the boundary is the documented one and not off by
    // one in either direction.
    const at_floor: Credentials = .{ .ufrag = TEST_UFRAG, .password = TEST_PASSWORD[0..MIN_PASSWORD_LEN] };
    try at_floor.validate();

    const below_floor: Credentials = .{ .ufrag = TEST_UFRAG, .password = TEST_PASSWORD[0 .. MIN_PASSWORD_LEN - 1] };
    try std.testing.expectError(error.ZixTooShort, below_floor.validate());
}

test "zix ice: credentials validate, a character outside the alphabet is rejected" {
    // A password of the right length but carrying a byte no ice-char covers.
    var password: [MIN_PASSWORD_LEN]u8 = @splat('a');
    password[7] = '=';

    const creds: Credentials = .{ .ufrag = TEST_UFRAG, .password = &password };
    try std.testing.expectError(error.ZixBadCharacter, creds.validate());

    const spaced: Credentials = .{ .ufrag = "ab d", .password = TEST_PASSWORD };
    try std.testing.expectError(error.ZixBadCharacter, spaced.validate());

    // The separator is deliberately not an ice-char, which is what makes the split unambiguous.
    try std.testing.expect(!isIceChar(USERNAME_SEPARATOR));
    try std.testing.expect(isIceChar('+'));
    try std.testing.expect(isIceChar('/'));
}

test "zix ice: credentials validate, an over-long half is rejected" {
    var long: [MAX_UFRAG_LEN + 1]u8 = @splat('a');

    const creds: Credentials = .{ .ufrag = &long, .password = TEST_PASSWORD };
    try std.testing.expectError(error.ZixTooLong, creds.validate());
}

test "zix ice: username, a check names the destination first and the source second" {
    var buf: [MAX_USERNAME_LEN]u8 = undefined;
    const username = try writeUsername(&buf, "8hhY", "9uB6");

    try std.testing.expectEqualStrings("8hhY:9uB6", username);

    const parts = try splitUsername(username);
    try std.testing.expectEqualStrings("8hhY", parts.destination_ufrag);
    try std.testing.expectEqualStrings("9uB6", parts.source_ufrag);
}

test "zix ice: username split, a malformed value is rejected rather than half read" {
    try std.testing.expectError(error.ZixMissingSeparator, splitUsername("8hhY9uB6"));
    try std.testing.expectError(error.ZixTooShort, splitUsername(":9uB6"));
    try std.testing.expectError(error.ZixTooShort, splitUsername("8hhY:"));
    try std.testing.expectError(error.ZixTooShort, splitUsername("8hhY:ab"));
    try std.testing.expectError(error.ZixMissingSeparator, splitUsername(""));

    // A second separator lands inside the source half, where it is not an ice-char.
    try std.testing.expectError(error.ZixBadCharacter, splitUsername("8hhY:9uB6:extra"));
}

test "zix ice: username write, refuses to overflow the caller buffer" {
    var exact: [9]u8 = undefined;
    try std.testing.expectEqualStrings("8hhY:9uB6", try writeUsername(&exact, "8hhY", "9uB6"));

    var one_short: [8]u8 = undefined;
    try std.testing.expectError(error.ZixNoSpace, writeUsername(&one_short, "8hhY", "9uB6"));
}

test "zix ice: fill, entropy maps onto the alphabet and nothing else" {
    var entropy: [MIN_PASSWORD_LEN]u8 = undefined;
    for (&entropy, 0..) |*byte, i| byte.* = @intCast(i * 7 + 3);

    var password: [MIN_PASSWORD_LEN]u8 = undefined;
    try fillIceChars(&password, &entropy);

    const creds: Credentials = .{ .ufrag = TEST_UFRAG, .password = &password };
    try creds.validate();

    // Every one of the 256 byte values has to land on an ice-char, not just the ones tried above.
    var every_byte: [256]u8 = undefined;
    for (&every_byte, 0..) |*byte, i| byte.* = @intCast(i);

    var mapped: [256]u8 = undefined;
    try fillIceChars(&mapped, &every_byte);

    for (mapped) |char| try std.testing.expect(isIceChar(char));
}

test "zix ice: fill, too little entropy is an error and not a short credential" {
    var entropy: [4]u8 = @splat(0);

    var password: [MIN_PASSWORD_LEN]u8 = undefined;
    try std.testing.expectError(error.ZixTooShort, fillIceChars(&password, &entropy));
}
