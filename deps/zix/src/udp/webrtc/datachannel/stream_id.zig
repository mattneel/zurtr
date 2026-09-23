//! zix WebRTC data channel stream identifiers (RFC 8831 6.5, RFC 8832 6).
//!
//! What:
//! - Which stream identifiers each side is allowed to open a channel on, and how to walk to the
//!   next one it owns.
//!
//! Note:
//! - The two sides never agree on a stream identifier, they divide the space up front: the side
//!   that acted as the DTLS client opens on even identifiers, the side that acted as the DTLS
//!   server opens on odd ones. Two peers opening a channel at the same instant then cannot land
//!   on the same pair.
//! - The role comes from the DTLS handshake, not from who dialled first and not from anything in
//!   SCTP. An endpoint that guesses it wrong opens every channel on the identifiers the peer
//!   owns, and the peer must refuse every one of them.
//! - A data channel is a pair of streams sharing one identifier, one in each direction
//!   (RFC 8831 6.4), so an identifier that is busy is busy for both directions.
//! - Identifier 65535 does not exist. An INIT negotiates at most 65535 streams, which numbers
//!   them 0 to 65534 (RFC 8832 3).

const std = @import("std");

/// The identifier that cannot be used, because the stream count tops out one below it.
pub const RESERVED: u16 = 65535;

/// Highest identifier a data channel can sit on.
pub const MAX_IDENTIFIER: u16 = RESERVED - 1;

/// Which half of the identifier space this endpoint opens channels on.
pub const Role = enum {
    /// Acted as the DTLS client, so it opens on even identifiers.
    DTLS_CLIENT,
    /// Acted as the DTLS server, so it opens on odd identifiers.
    DTLS_SERVER,
};

/// The lowest identifier a role may open on.
///
/// Param:
/// role - Role
///
/// Return:
/// - u16
pub fn first(role: Role) u16 {
    return switch (role) {
        .DTLS_CLIENT => 0,
        .DTLS_SERVER => 1,
    };
}

/// The next identifier in the same half of the space.
///
/// Param:
/// stream_identifier - u16
///
/// Return:
/// - ?u16, null once the walk would pass the last usable identifier
pub fn next(stream_identifier: u16) ?u16 {
    // Widened first, because the last two identifiers step straight past what a u16 holds.
    const stepped: u32 = @as(u32, stream_identifier) + 2;

    if (stepped > MAX_IDENTIFIER) return null;

    return @intCast(stepped);
}

/// Whether a role may open a channel on an identifier.
///
/// Param:
/// role - Role
/// stream_identifier - u16
///
/// Return:
/// - bool
pub fn ownedBy(role: Role, stream_identifier: u16) bool {
    if (stream_identifier == RESERVED) return false;

    const even = stream_identifier % 2 == 0;

    return switch (role) {
        .DTLS_CLIENT => even,
        .DTLS_SERVER => !even,
    };
}

/// The role that owns an identifier.
///
/// Note:
/// - What an arriving DATA_CHANNEL_OPEN is checked against: it has to have come in on an
///   identifier the peer owns, never one this endpoint opens on (RFC 8832 6).
///
/// Param:
/// stream_identifier - u16
///
/// Return:
/// - Role
pub fn owner(stream_identifier: u16) Role {
    return if (stream_identifier % 2 == 0) .DTLS_CLIENT else .DTLS_SERVER;
}

/// The role on the other side of the association.
///
/// Param:
/// role - Role
///
/// Return:
/// - Role
pub fn peerRole(role: Role) Role {
    return switch (role) {
        .DTLS_CLIENT => .DTLS_SERVER,
        .DTLS_SERVER => .DTLS_CLIENT,
    };
}

/// Whether an identifier exists on an association that negotiated this many streams.
///
/// Param:
/// stream_identifier - u16
/// negotiated_streams - u16 (streams the handshake settled on)
///
/// Return:
/// - bool
pub fn usable(stream_identifier: u16, negotiated_streams: u16) bool {
    if (stream_identifier == RESERVED) return false;

    return stream_identifier < negotiated_streams;
}

// --------------------------------------------------------------------------------------- //
// test cases

test "zix datachannel: stream_id first, the client starts at zero and the server at one" {
    try std.testing.expectEqual(@as(u16, 0), first(.DTLS_CLIENT));
    try std.testing.expectEqual(@as(u16, 1), first(.DTLS_SERVER));
}

test "zix datachannel: stream_id next, the walk keeps the parity" {
    try std.testing.expectEqual(@as(?u16, 2), next(0));
    try std.testing.expectEqual(@as(?u16, 4), next(2));
    try std.testing.expectEqual(@as(?u16, 3), next(1));
    try std.testing.expectEqual(@as(?u16, 5), next(3));
}

test "zix datachannel: stream_id next, the walk stops before the reserved identifier" {
    try std.testing.expectEqual(@as(?u16, MAX_IDENTIFIER), next(MAX_IDENTIFIER - 2));
    try std.testing.expectEqual(@as(?u16, null), next(MAX_IDENTIFIER));
    try std.testing.expectEqual(@as(?u16, null), next(MAX_IDENTIFIER - 1));
}

test "zix datachannel: stream_id ownedBy, each role owns its own parity" {
    try std.testing.expect(ownedBy(.DTLS_CLIENT, 0));
    try std.testing.expect(ownedBy(.DTLS_CLIENT, 128));
    try std.testing.expect(!ownedBy(.DTLS_CLIENT, 1));
    try std.testing.expect(ownedBy(.DTLS_SERVER, 1));
    try std.testing.expect(ownedBy(.DTLS_SERVER, 129));
    try std.testing.expect(!ownedBy(.DTLS_SERVER, 0));
}

test "zix datachannel: stream_id ownedBy, the reserved identifier belongs to neither role" {
    try std.testing.expect(!ownedBy(.DTLS_CLIENT, RESERVED));
    try std.testing.expect(!ownedBy(.DTLS_SERVER, RESERVED));
}

test "zix datachannel: stream_id owner, the parity names the side that opens there" {
    try std.testing.expectEqual(Role.DTLS_CLIENT, owner(0));
    try std.testing.expectEqual(Role.DTLS_SERVER, owner(1));
    try std.testing.expectEqual(Role.DTLS_CLIENT, owner(1000));
    try std.testing.expectEqual(Role.DTLS_SERVER, owner(1001));
}

test "zix datachannel: stream_id peerRole, the roles are opposites" {
    try std.testing.expectEqual(Role.DTLS_SERVER, peerRole(.DTLS_CLIENT));
    try std.testing.expectEqual(Role.DTLS_CLIENT, peerRole(.DTLS_SERVER));
}

test "zix datachannel: stream_id usable, an identifier past what was negotiated does not exist" {
    try std.testing.expect(usable(0, 128));
    try std.testing.expect(usable(127, 128));
    try std.testing.expect(!usable(128, 128));
    try std.testing.expect(!usable(200, 128));
}

test "zix datachannel: stream_id usable, the reserved identifier never exists" {
    // Even an association that somehow claimed the whole space cannot reach it.
    try std.testing.expect(!usable(RESERVED, RESERVED));
}

test "zix datachannel: stream_id, an identifier one role owns is one the other must not open" {
    var identifier: ?u16 = first(.DTLS_CLIENT);

    var checked: usize = 0;
    while (identifier) |current| : (identifier = next(current)) {
        try std.testing.expect(ownedBy(.DTLS_CLIENT, current));
        try std.testing.expect(!ownedBy(.DTLS_SERVER, current));

        checked += 1;
        if (checked == 8) break;
    }

    try std.testing.expectEqual(@as(usize, 8), checked);
}
