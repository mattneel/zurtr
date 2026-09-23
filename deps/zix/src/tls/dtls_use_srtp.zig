//! zix DTLS-SRTP use_srtp extension (RFC 5764 4.1).
//!
//! What:
//! - The one extension that turns a DTLS handshake into a DTLS-SRTP handshake. The client offers
//!   a list of protection profiles, the server picks exactly one and echoes it back, and the keys
//!   for that choice come out of dtls_exporter.zig.
//!
//! Note:
//! - zix is always the DTLS server (see udp/webrtc/sdp/setup.zig), so this file reads a list and
//!   writes a single choice. There is no offer writer, and the tests build client extensions by
//!   hand instead of round-tripping through one.
//! - An answer names exactly one profile (RFC 5764 4.1.1). Echoing the whole list back looks like
//!   agreement and leaves the peer with no single key schedule to derive from.
//! - The MKI is read and reported, never honoured. Using one would mean carrying a master key
//!   identifier in every SRTP packet, and the profiles zix answers do not need it.
//! - A hello without the extension is not an error. It says the peer wants plain DTLS, and the
//!   answer is to leave the extension out of the ServerHello as well.

const std = @import("std");

const exporter = @import("dtls_exporter.zig");

/// Extension number for use_srtp (RFC 5764 9).
pub const EXTENSION_TYPE: u16 = 14;

/// Bytes one profile takes on the wire.
pub const PROFILE_LEN: usize = 2;

/// Longest master key identifier the length byte can describe.
pub const MAX_MKI_LEN: usize = 255;

/// Bytes a server answer takes, extension header included.
pub const ANSWER_LEN: usize = 2 + 2 + 2 + PROFILE_LEN + 1;

/// What stops the extension from being read.
pub const Error = error{
    /// The bytes do not frame as an extensions block or as a UseSRTPData value.
    ZixMalformed,
};

/// What a client offered, borrowed from the hello it came in.
pub const Offered = struct {
    /// The profile list as it stands, two bytes per entry.
    profiles: []const u8,
    /// The master key identifier, empty when the client asked for none.
    mki: []const u8,

    /// How many profiles the client named.
    ///
    /// Return:
    /// - usize
    pub fn count(self: Offered) usize {
        return self.profiles.len / PROFILE_LEN;
    }

    /// One profile by position, in the client's own preference order.
    ///
    /// Param:
    /// index - usize
    ///
    /// Return:
    /// - ?exporter.SrtpProfile
    pub fn at(self: Offered, index: usize) ?exporter.SrtpProfile {
        if (index >= self.count()) return null;

        const at_byte = index * PROFILE_LEN;

        return @enumFromInt(std.mem.readInt(u16, self.profiles[at_byte..][0..2], .big));
    }

    /// Whether a profile is somewhere in the list.
    ///
    /// Param:
    /// wanted - exporter.SrtpProfile
    ///
    /// Return:
    /// - bool
    pub fn has(self: Offered, wanted: exporter.SrtpProfile) bool {
        var index: usize = 0;
        while (self.at(index)) |offered| : (index += 1) {
            if (offered == wanted) return true;
        }

        return false;
    }
};

/// Find the use_srtp extension inside a hello's extensions block.
///
/// Note:
/// - Returns null when the block is well formed and simply has no use_srtp in it, which is the
///   ordinary case for a data-channel-only peer.
/// - The whole block is walked even after a match, so a truncated entry behind the extension is
///   still refused. Stopping at the match would accept a hello the rest of the handshake cannot
///   read anyway.
/// - Two use_srtp extensions in one block is an error. TLS allows one of each type, and picking
///   either of two would be guessing which one the peer meant.
///
/// Param:
/// extensions - []const u8 (the whole block, as dtls_hello.zig hands it over)
///
/// Return:
/// - ?[]const u8, the extension_data alone, borrowing `extensions`
/// - error.ZixMalformed when an entry runs past the end of the block, or use_srtp appears twice
pub fn find(extensions: []const u8) Error!?[]const u8 {
    var found: ?[]const u8 = null;
    var at: usize = 0;

    while (at + 4 <= extensions.len) {
        const kind = std.mem.readInt(u16, extensions[at..][0..2], .big);
        const len = std.mem.readInt(u16, extensions[at + 2 ..][0..2], .big);
        const body_at = at + 4;

        if (body_at + len > extensions.len) return error.ZixMalformed;

        if (kind == EXTENSION_TYPE) {
            if (found != null) return error.ZixMalformed;

            found = extensions[body_at..][0..len];
        }

        at = body_at + len;
    }

    if (at != extensions.len) return error.ZixMalformed;

    return found;
}

/// Read a UseSRTPData value (RFC 5764 4.1.1).
///
/// Param:
/// extension_data - []const u8 (borrowed, must outlive the result)
///
/// Return:
/// - Offered borrowing `extension_data`
/// - error.ZixMalformed for a truncated value, an odd profile list, an empty list, or trailing bytes
pub fn read(extension_data: []const u8) Error!Offered {
    if (extension_data.len < 3) return error.ZixMalformed;

    const profiles_len = std.mem.readInt(u16, extension_data[0..2], .big);

    if (profiles_len == 0) return error.ZixMalformed;
    if (profiles_len % PROFILE_LEN != 0) return error.ZixMalformed;
    if (2 + @as(usize, profiles_len) >= extension_data.len) return error.ZixMalformed;

    const mki_at = 2 + @as(usize, profiles_len);
    const mki_len = extension_data[mki_at];

    if (mki_at + 1 + @as(usize, mki_len) != extension_data.len) return error.ZixMalformed;

    return .{
        .profiles = extension_data[2..mki_at],
        .mki = extension_data[mki_at + 1 ..],
    };
}

/// Pick the profile to answer with.
///
/// Note:
/// - The server's own order decides, not the client's. The client lists what it can do, and which
///   of those zix would rather use is zix's call.
///
/// Param:
/// offered - Offered
/// preferences - []const exporter.SrtpProfile (server order, most wanted first)
///
/// Return:
/// - ?exporter.SrtpProfile, null when nothing overlaps
pub fn select(offered: Offered, preferences: []const exporter.SrtpProfile) ?exporter.SrtpProfile {
    for (preferences) |wanted| {
        if (offered.has(wanted)) return wanted;
    }

    return null;
}

/// Write the server's use_srtp extension, header included.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// chosen - exporter.SrtpProfile (the one profile the server agreed to)
///
/// Return:
/// - []const u8 of exactly ANSWER_LEN bytes
/// - error.ZixNoSpace
pub fn writeAnswer(out: []u8, chosen: exporter.SrtpProfile) error{ZixNoSpace}![]const u8 {
    if (out.len < ANSWER_LEN) return error.ZixNoSpace;

    std.mem.writeInt(u16, out[0..2], EXTENSION_TYPE, .big);
    std.mem.writeInt(u16, out[2..4], PROFILE_LEN + 2 + 1, .big);
    std.mem.writeInt(u16, out[4..6], PROFILE_LEN, .big);
    std.mem.writeInt(u16, out[6..8], @intFromEnum(chosen), .big);
    out[8] = 0;

    return out[0..ANSWER_LEN];
}

// --------------------------------------------------------------------------------------- //
// test cases

/// One client extension_data naming `profiles`, with no MKI.
fn offerData(out: []u8, profiles: []const exporter.SrtpProfile) []const u8 {
    const list_len = profiles.len * PROFILE_LEN;
    std.mem.writeInt(u16, out[0..2], @intCast(list_len), .big);

    for (profiles, 0..) |profile, index| {
        std.mem.writeInt(u16, out[2 + index * PROFILE_LEN ..][0..2], @intFromEnum(profile), .big);
    }

    out[2 + list_len] = 0;

    return out[0 .. 2 + list_len + 1];
}

test "zix dtls: use_srtp read, the published offer shape reads field for field" {
    // Two profiles and no MKI, which is what a browser sends.
    const data = [_]u8{ 0x00, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00 };
    const offered = try read(&data);

    try std.testing.expectEqual(@as(usize, 2), offered.count());
    try std.testing.expectEqual(exporter.SrtpProfile.SRTP_AES128_CM_HMAC_SHA1_80, offered.at(0).?);
    try std.testing.expectEqual(exporter.SrtpProfile.SRTP_AES128_CM_HMAC_SHA1_32, offered.at(1).?);
    try std.testing.expectEqual(@as(usize, 0), offered.mki.len);
    try std.testing.expect(offered.at(2) == null);
}

test "zix dtls: use_srtp read, a master key identifier is reported and not dropped" {
    const data = [_]u8{ 0x00, 0x02, 0x00, 0x01, 0x03, 0xAA, 0xBB, 0xCC };
    const offered = try read(&data);

    try std.testing.expectEqual(@as(usize, 1), offered.count());
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC }, offered.mki);
}

test "zix dtls: use_srtp read, a bad value is refused" {
    // Too short to hold a list length and an MKI length.
    try std.testing.expectError(error.ZixMalformed, read(&[_]u8{ 0x00, 0x02 }));

    // An odd profile list, so one entry is half there.
    try std.testing.expectError(error.ZixMalformed, read(&[_]u8{ 0x00, 0x03, 0x00, 0x01, 0x00, 0x00 }));

    // An empty profile list, which offers nothing to agree on.
    try std.testing.expectError(error.ZixMalformed, read(&[_]u8{ 0x00, 0x00, 0x00 }));

    // The list runs past the value.
    try std.testing.expectError(error.ZixMalformed, read(&[_]u8{ 0x00, 0x08, 0x00, 0x01, 0x00 }));

    // The MKI length disagrees with what follows it.
    try std.testing.expectError(error.ZixMalformed, read(&[_]u8{ 0x00, 0x02, 0x00, 0x01, 0x04, 0xAA }));

    // Trailing bytes after the MKI.
    try std.testing.expectError(error.ZixMalformed, read(&[_]u8{ 0x00, 0x02, 0x00, 0x01, 0x00, 0xFF }));
}

test "zix dtls: use_srtp read, an unregistered profile number still reads" {
    // The enum is open on purpose. A number zix does not answer has to come back as itself, so
    // `select` can pass over it instead of the parse failing on the whole hello.
    const data = [_]u8{ 0x00, 0x04, 0xFF, 0xFF, 0x00, 0x01, 0x00 };
    const offered = try read(&data);

    try std.testing.expectEqual(@as(u16, 0xFFFF), @intFromEnum(offered.at(0).?));
    try std.testing.expect(offered.has(.SRTP_AES128_CM_HMAC_SHA1_80));
}

test "zix dtls: use_srtp find, the extension is picked out of a block" {
    // Two other extensions around it, so the walk has to step over lengths correctly.
    const extensions = [_]u8{
        0x00, 0x0D, 0x00, 0x02, 0x04, 0x03,
        0x00, 0x0E, 0x00, 0x05, 0x00, 0x02,
        0x00, 0x01, 0x00, 0x00, 0x17, 0x00,
        0x00,
    };

    const data = (try find(&extensions)) orelse return error.TestUnexpectedResult;
    const offered = try read(data);

    try std.testing.expectEqual(@as(usize, 1), offered.count());
    try std.testing.expectEqual(exporter.SrtpProfile.SRTP_AES128_CM_HMAC_SHA1_80, offered.at(0).?);
}

test "zix dtls: use_srtp find, a block without it gives null" {
    const extensions = [_]u8{ 0x00, 0x0D, 0x00, 0x02, 0x04, 0x03 };

    try std.testing.expect((try find(&extensions)) == null);
    try std.testing.expect((try find(&[_]u8{})) == null);
}

test "zix dtls: use_srtp find, an entry running past the block is refused" {
    try std.testing.expectError(error.ZixMalformed, find(&[_]u8{ 0x00, 0x0E, 0x00, 0x08, 0x00 }));

    // A trailing stub too short to be an entry is not a block this walk can trust, and the walk
    // reaches it only because a match does not end it.
    try std.testing.expectError(error.ZixMalformed, find(&[_]u8{ 0x00, 0x0E, 0x00, 0x00, 0x00 }));
}

test "zix dtls: use_srtp find, the extension appearing twice is refused" {
    const twice = [_]u8{
        0x00, 0x0E, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00,
        0x00, 0x0E, 0x00, 0x05, 0x00, 0x02, 0x00, 0x02, 0x00,
    };

    try std.testing.expectError(error.ZixMalformed, find(&twice));
}

test "zix dtls: use_srtp select, the server order decides" {
    var buf: [16]u8 = undefined;
    const data = offerData(&buf, &.{ .SRTP_AES128_CM_HMAC_SHA1_32, .SRTP_AES128_CM_HMAC_SHA1_80 });
    const offered = try read(data);

    // The client put the 32-bit tag first. The server wants the 80-bit one, and gets it.
    const chosen = select(offered, &.{ .SRTP_AES128_CM_HMAC_SHA1_80, .SRTP_AES128_CM_HMAC_SHA1_32 });
    try std.testing.expectEqual(exporter.SrtpProfile.SRTP_AES128_CM_HMAC_SHA1_80, chosen.?);
}

test "zix dtls: use_srtp select, nothing in common gives null" {
    var buf: [16]u8 = undefined;
    const data = offerData(&buf, &.{.SRTP_NULL_HMAC_SHA1_80});
    const offered = try read(data);

    try std.testing.expect(select(offered, &.{.SRTP_AES128_CM_HMAC_SHA1_80}) == null);
    try std.testing.expect(select(offered, &.{}) == null);
}

test "zix dtls: use_srtp writeAnswer, the answer names exactly one profile" {
    var buf: [ANSWER_LEN]u8 = undefined;
    const written = try writeAnswer(&buf, .SRTP_AES128_CM_HMAC_SHA1_80);

    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ 0x00, 0x0E, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00 },
        written,
    );

    // What was written is a block, so the reader finds it again and sees one profile.
    const data = (try find(written)) orelse return error.TestUnexpectedResult;
    const offered = try read(data);

    try std.testing.expectEqual(@as(usize, 1), offered.count());
    try std.testing.expectEqual(@as(usize, 0), offered.mki.len);
}

test "zix dtls: use_srtp writeAnswer, a short buffer errors" {
    var buf: [ANSWER_LEN - 1]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, writeAnswer(&buf, .SRTP_AES128_CM_HMAC_SHA1_80));
}

test "zix dtls: use_srtp, the chosen profile is the one keys derive from" {
    var buf: [16]u8 = undefined;
    const data = offerData(&buf, &.{ .SRTP_AES128_CM_HMAC_SHA1_80, .SRTP_NULL_HMAC_SHA1_80 });
    const offered = try read(data);

    const chosen = select(offered, &.{ .SRTP_AES128_CM_HMAC_SHA1_80, .SRTP_AES128_CM_HMAC_SHA1_32 }).?;

    // The whole point of the negotiation: the answer feeds the exporter, and a NULL profile the
    // client also offered would have had nothing to export.
    const master: [48]u8 = @splat(0x5A);
    const client_random: [32]u8 = @splat(0xAA);
    const server_random: [32]u8 = @splat(0xBB);

    const keys = try exporter.srtpKeys(chosen, master, client_random, server_random);
    try std.testing.expect(!std.mem.eql(u8, &keys.client_write_key, &keys.server_write_key));

    try std.testing.expectError(
        error.ZixUnsupportedProfile,
        exporter.srtpKeys(.SRTP_NULL_HMAC_SHA1_80, master, client_random, server_random),
    );
}
