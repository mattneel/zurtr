//! zix SDP setup role (RFC 4145 4, RFC 8842 5, RFC 5763 5).
//!
//! What:
//! - The `a=setup` attribute, which decides who sends the DTLS ClientHello, and what that means
//!   for which stream identifiers a data channel opens on.
//!
//! Note:
//! - "active" means the endpoint will start the handshake, so it becomes the DTLS client.
//!   "passive" means it will wait for one, so it becomes the DTLS server. "actpass" is an offer
//!   saying either is fine, and only an offer may say it (RFC 4145 4.1).
//! - zix answers "passive", always. It has a DTLS server and no DTLS client, so an offer that
//!   demands zix start the handshake is one zix cannot answer, and saying so here is better than
//!   agreeing to something no later layer can do.
//! - That single decision fixes the data channel identifier space: the DTLS server opens on odd
//!   identifiers (RFC 8832 6). It is the whole reason this file reaches across to the data
//!   channel side rather than stopping at the attribute.
//! - "holdconn" is refused. RFC 8842 5.1 forbids it outright for DTLS.

const std = @import("std");

const stream_id = @import("../datachannel/stream_id.zig");

/// The attribute name this lives under.
pub const ATTRIBUTE: []const u8 = "setup";

/// What stops a setup role from being read.
pub const Error = error{
    /// A value outside the four RFC 4145 4 defines.
    ZixUnknownRole,
};

/// What stops a role from being taken. Separate from `Error` because reading an offer and
/// answering it fail for different reasons, and a caller handles them at different points.
pub const RoleError = error{
    /// A role this endpoint cannot take.
    ZixUnsupportedRole,
};

/// Who starts the handshake (RFC 4145 4).
pub const Role = enum {
    /// Will start the handshake, so it becomes the DTLS client.
    ACTIVE,
    /// Will wait for a handshake, so it becomes the DTLS server.
    PASSIVE,
    /// Either, which only an offer may say.
    ACTPASS,
    /// Neither for now, which RFC 8842 5.1 forbids for DTLS.
    HOLDCONN,

    /// The value as it appears in a description.
    ///
    /// Return:
    /// - []const u8
    pub fn name(self: Role) []const u8 {
        return switch (self) {
            .ACTIVE => "active",
            .PASSIVE => "passive",
            .ACTPASS => "actpass",
            .HOLDCONN => "holdconn",
        };
    }
};

/// Read an `a=setup` attribute value.
///
/// Param:
/// value - []const u8 (everything after `setup:`)
///
/// Return:
/// - Role
/// - error.ZixUnknownRole
pub fn read(value: []const u8) Error!Role {
    if (std.mem.eql(u8, value, "active")) return .ACTIVE;
    if (std.mem.eql(u8, value, "passive")) return .PASSIVE;
    if (std.mem.eql(u8, value, "actpass")) return .ACTPASS;
    if (std.mem.eql(u8, value, "holdconn")) return .HOLDCONN;

    return error.ZixUnknownRole;
}

/// The role to answer an offer with.
///
/// Note:
/// - Always passive when an answer is possible at all. RFC 5763 5 recommends active for lower
///   latency, and zix has no DTLS client to be active with, so the recommendation is one this
///   endpoint cannot take.
///
/// Param:
/// offered - Role (what the offer said)
///
/// Return:
/// - Role, always PASSIVE
/// - error.ZixUnsupportedRole when the offer leaves this endpoint no role it can take
pub fn answerFor(offered: Role) RoleError!Role {
    return switch (offered) {
        // Either is allowed, so take the one there is an implementation for.
        .ACTPASS => .PASSIVE,
        // The offerer will start the handshake, which is exactly what a passive answer wants.
        .ACTIVE => .PASSIVE,
        // The offerer will wait, so answering means being the client, and there is none.
        .PASSIVE => error.ZixUnsupportedRole,
        .HOLDCONN => error.ZixUnsupportedRole,
    };
}

/// Which half of the data channel identifier space a role opens on (RFC 8832 6).
///
/// Param:
/// role - Role (this endpoint's own role, after answering)
///
/// Return:
/// - stream_id.Role
/// - error.ZixUnsupportedRole for a role that names no side of the handshake
pub fn streamRole(role: Role) RoleError!stream_id.Role {
    return switch (role) {
        .ACTIVE => .DTLS_CLIENT,
        .PASSIVE => .DTLS_SERVER,
        .ACTPASS, .HOLDCONN => error.ZixUnsupportedRole,
    };
}

// --------------------------------------------------------------------------------------- //
// test cases

test "zix sdp: setup read, the four values resolve" {
    try std.testing.expectEqual(Role.ACTIVE, try read("active"));
    try std.testing.expectEqual(Role.PASSIVE, try read("passive"));
    try std.testing.expectEqual(Role.ACTPASS, try read("actpass"));
    try std.testing.expectEqual(Role.HOLDCONN, try read("holdconn"));
}

test "zix sdp: setup read, anything else is refused" {
    try std.testing.expectError(error.ZixUnknownRole, read("ACTPASS"));
    try std.testing.expectError(error.ZixUnknownRole, read("act"));
    try std.testing.expectError(error.ZixUnknownRole, read(""));
}

test "zix sdp: setup name, what was read writes back the same" {
    try std.testing.expectEqualStrings("active", Role.ACTIVE.name());
    try std.testing.expectEqualStrings("passive", Role.PASSIVE.name());
    try std.testing.expectEqualStrings("actpass", Role.ACTPASS.name());
    try std.testing.expectEqualStrings("holdconn", Role.HOLDCONN.name());
    try std.testing.expectEqual(Role.PASSIVE, try read(Role.PASSIVE.name()));
}

test "zix sdp: setup answerFor, an actpass offer is answered passive" {
    // Every browser offers actpass, so this is the path that matters.
    try std.testing.expectEqual(Role.PASSIVE, try answerFor(.ACTPASS));
}

test "zix sdp: setup answerFor, an active offer is answered passive" {
    try std.testing.expectEqual(Role.PASSIVE, try answerFor(.ACTIVE));
}

test "zix sdp: setup answerFor, a passive offer cannot be answered" {
    // Answering would mean starting the handshake, and there is no DTLS client to start it.
    try std.testing.expectError(error.ZixUnsupportedRole, answerFor(.PASSIVE));
}

test "zix sdp: setup answerFor, holdconn cannot be answered" {
    try std.testing.expectError(error.ZixUnsupportedRole, answerFor(.HOLDCONN));
}

test "zix sdp: setup streamRole, passive opens on the odd identifiers" {
    try std.testing.expectEqual(stream_id.Role.DTLS_SERVER, try streamRole(.PASSIVE));
    try std.testing.expect(stream_id.ownedBy(try streamRole(.PASSIVE), 1));
    try std.testing.expect(!stream_id.ownedBy(try streamRole(.PASSIVE), 0));
}

test "zix sdp: setup streamRole, active opens on the even identifiers" {
    try std.testing.expectEqual(stream_id.Role.DTLS_CLIENT, try streamRole(.ACTIVE));
    try std.testing.expect(stream_id.ownedBy(try streamRole(.ACTIVE), 0));
}

test "zix sdp: setup streamRole, a role that names no side is refused" {
    try std.testing.expectError(error.ZixUnsupportedRole, streamRole(.ACTPASS));
    try std.testing.expectError(error.ZixUnsupportedRole, streamRole(.HOLDCONN));
}

test "zix sdp: setup, answering an offer settles which identifiers zix opens on" {
    // The one chain that matters: a browser offers actpass, zix answers passive, and from then
    // on every channel zix opens sits on an odd identifier.
    const answered = try answerFor(try read("actpass"));

    try std.testing.expectEqual(Role.PASSIVE, answered);
    try std.testing.expectEqual(stream_id.Role.DTLS_SERVER, try streamRole(answered));
    try std.testing.expectEqual(@as(u16, 1), stream_id.first(try streamRole(answered)));
}
