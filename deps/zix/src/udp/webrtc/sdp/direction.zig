//! zix SDP media direction (RFC 8866 6.7, RFC 3264 6.1).
//!
//! What:
//! - Which way media flows on one section, and what an answer is allowed to say back.
//!
//! Note:
//! - All four are flag attributes, so they are written as `a=sendrecv` with no value. Looking for
//!   them the way a valued attribute is looked for finds nothing.
//! - A section with none of the four is sendrecv (RFC 8866 6.7). That default is not a guess, it
//!   is what the offerer meant, and treating a missing attribute as inactive silently mutes a
//!   stream the peer expected to carry media.
//! - The answer is constrained, not free. sendonly must be answered recvonly or inactive, and
//!   recvonly must be answered sendonly or inactive (RFC 3264 6.1). Only an offer of sendrecv
//!   leaves a real choice.
//! - The directions are written from the point of view of whoever wrote the line. The offerer's
//!   "sendonly" and the answerer's "recvonly" describe one flow, not two.

const std = @import("std");

const attribute = @import("attribute.zig");

/// What a section says when it says nothing (RFC 8866 6.7).
pub const DEFAULT: Direction = .SENDRECV;

/// What stops a direction from being answered.
pub const Error = error{
    /// The offer leaves this endpoint no direction it can take.
    UnsupportedDirection,
};

/// Which way media flows, from the point of view of whoever wrote the attribute.
pub const Direction = enum {
    /// Both ways.
    SENDRECV,
    /// The writer sends, and expects nothing back.
    SENDONLY,
    /// The writer receives, and sends nothing.
    RECVONLY,
    /// Neither way, with the section otherwise negotiated.
    INACTIVE,

    /// The attribute name this appears under.
    ///
    /// Return:
    /// - []const u8
    pub fn name(self: Direction) []const u8 {
        return switch (self) {
            .SENDRECV => "sendrecv",
            .SENDONLY => "sendonly",
            .RECVONLY => "recvonly",
            .INACTIVE => "inactive",
        };
    }

    /// Whether the writer will send media.
    ///
    /// Return:
    /// - bool
    pub fn sends(self: Direction) bool {
        return self == .SENDRECV or self == .SENDONLY;
    }

    /// Whether the writer will receive media.
    ///
    /// Return:
    /// - bool
    pub fn receives(self: Direction) bool {
        return self == .SENDRECV or self == .RECVONLY;
    }
};

/// Read a direction from an attribute name.
///
/// Param:
/// text - []const u8 (the name alone, with no `a=` and no value)
///
/// Return:
/// - ?Direction, null for a name that is not one of the four
pub fn read(text: []const u8) ?Direction {
    if (std.mem.eql(u8, text, "sendrecv")) return .SENDRECV;
    if (std.mem.eql(u8, text, "sendonly")) return .SENDONLY;
    if (std.mem.eql(u8, text, "recvonly")) return .RECVONLY;
    if (std.mem.eql(u8, text, "inactive")) return .INACTIVE;

    return null;
}

/// The direction a region declares.
///
/// Note:
/// - Returns null when the region names none, so a caller can fall back to the session level
///   before settling for the default. `of` does both steps.
///
/// Param:
/// region - []const u8 (a media section or the session level)
///
/// Return:
/// - ?Direction
pub fn find(region: []const u8) ?Direction {
    const ordered = [_]Direction{ .SENDRECV, .SENDONLY, .RECVONLY, .INACTIVE };

    for (ordered) |candidate| {
        if (attribute.has(region, candidate.name())) return candidate;
    }

    return null;
}

/// The direction that applies to a section (RFC 3264 6.1).
///
/// Param:
/// section - []const u8 (the media section, searched first)
/// session - []const u8 (the session level, searched second)
///
/// Return:
/// - Direction, DEFAULT when neither names one
pub fn of(section: []const u8, session: []const u8) Direction {
    if (find(section)) |found| return found;
    if (find(session)) |found| return found;

    return DEFAULT;
}

/// The direction to answer an offered one with (RFC 3264 6.1).
///
/// Note:
/// - zix forwards, so it both receives from whoever is sending and sends to whoever is listening.
///   That makes sendrecv the answer to sendrecv rather than a narrower choice.
///
/// Param:
/// offered - Direction (what the offer said)
///
/// Return:
/// - Direction
pub fn answerFor(offered: Direction) Direction {
    return switch (offered) {
        .SENDRECV => .SENDRECV,
        // The peer sends and wants nothing back, so this end only receives.
        .SENDONLY => .RECVONLY,
        // The peer receives, so this end is the one sending.
        .RECVONLY => .SENDONLY,
        .INACTIVE => .INACTIVE,
    };
}

/// Whether an answer is one RFC 3264 6.1 allows for an offer.
///
/// Param:
/// offered - Direction
/// answered - Direction
///
/// Return:
/// - bool
pub fn isAllowedAnswer(offered: Direction, answered: Direction) bool {
    return switch (offered) {
        .SENDRECV => true,
        .SENDONLY => answered == .RECVONLY or answered == .INACTIVE,
        .RECVONLY => answered == .SENDONLY or answered == .INACTIVE,
        .INACTIVE => answered == .INACTIVE,
    };
}

// --------------------------------------------------------------------------------------- //
// test cases

const audio_section: []const u8 =
    "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n" ++
    "a=mid:0\r\n" ++
    "a=sendonly\r\n" ++
    "a=rtcp-mux\r\n";

test "zix sdp: direction read, the four names resolve" {
    try std.testing.expectEqual(Direction.SENDRECV, read("sendrecv").?);
    try std.testing.expectEqual(Direction.SENDONLY, read("sendonly").?);
    try std.testing.expectEqual(Direction.RECVONLY, read("recvonly").?);
    try std.testing.expectEqual(Direction.INACTIVE, read("inactive").?);
}

test "zix sdp: direction read, anything else is not one" {
    try std.testing.expect(read("SENDRECV") == null);
    try std.testing.expect(read("send") == null);
    try std.testing.expect(read("") == null);
    try std.testing.expect(read("rtcp-mux") == null);
}

test "zix sdp: direction name, what was read writes back the same" {
    const all = [_]Direction{ .SENDRECV, .SENDONLY, .RECVONLY, .INACTIVE };

    for (all) |entry| {
        try std.testing.expectEqual(entry, read(entry.name()).?);
    }
}

test "zix sdp: direction find, a section names its own" {
    try std.testing.expectEqual(Direction.SENDONLY, find(audio_section).?);
}

test "zix sdp: direction find, a section naming none gives null" {
    const plain = "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\n";

    try std.testing.expect(find(plain) == null);
}

test "zix sdp: direction of, the section wins over the session level" {
    const session = "v=0\r\na=recvonly\r\n";

    try std.testing.expectEqual(Direction.SENDONLY, of(audio_section, session));
}

test "zix sdp: direction of, the session level applies when the section is silent" {
    const plain = "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\n";
    const session = "v=0\r\na=recvonly\r\n";

    try std.testing.expectEqual(Direction.RECVONLY, of(plain, session));
}

test "zix sdp: direction of, neither level naming one means sendrecv" {
    // The default that matters: a missing attribute carries media, it does not mute the stream.
    const plain = "m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:0\r\n";

    try std.testing.expectEqual(Direction.SENDRECV, of(plain, "v=0\r\n"));
    try std.testing.expectEqual(DEFAULT, of("", ""));
}

test "zix sdp: direction answerFor, a one-way offer is answered the other way" {
    try std.testing.expectEqual(Direction.RECVONLY, answerFor(.SENDONLY));
    try std.testing.expectEqual(Direction.SENDONLY, answerFor(.RECVONLY));
}

test "zix sdp: direction answerFor, both ways stays both ways" {
    // zix forwards, so it is receiving from this peer and sending other peers' media to it.
    try std.testing.expectEqual(Direction.SENDRECV, answerFor(.SENDRECV));
}

test "zix sdp: direction answerFor, inactive stays inactive" {
    try std.testing.expectEqual(Direction.INACTIVE, answerFor(.INACTIVE));
}

test "zix sdp: direction answerFor, every answer is one the rfc allows" {
    const all = [_]Direction{ .SENDRECV, .SENDONLY, .RECVONLY, .INACTIVE };

    for (all) |offered| {
        try std.testing.expect(isAllowedAnswer(offered, answerFor(offered)));
    }
}

test "zix sdp: direction isAllowedAnswer, the constrained cases are refused" {
    // Answering a sendonly offer with sendonly leaves two senders and no receiver.
    try std.testing.expect(!isAllowedAnswer(.SENDONLY, .SENDONLY));
    try std.testing.expect(!isAllowedAnswer(.SENDONLY, .SENDRECV));
    try std.testing.expect(!isAllowedAnswer(.RECVONLY, .RECVONLY));
    try std.testing.expect(!isAllowedAnswer(.RECVONLY, .SENDRECV));
    try std.testing.expect(!isAllowedAnswer(.INACTIVE, .SENDRECV));

    // And an offer of sendrecv really does allow all four.
    try std.testing.expect(isAllowedAnswer(.SENDRECV, .INACTIVE));
    try std.testing.expect(isAllowedAnswer(.SENDRECV, .SENDONLY));
}

test "zix sdp: direction sends and receives, they agree with the names" {
    try std.testing.expect(Direction.SENDRECV.sends() and Direction.SENDRECV.receives());
    try std.testing.expect(Direction.SENDONLY.sends() and !Direction.SENDONLY.receives());
    try std.testing.expect(!Direction.RECVONLY.sends() and Direction.RECVONLY.receives());
    try std.testing.expect(!Direction.INACTIVE.sends() and !Direction.INACTIVE.receives());
}

test "zix sdp: direction, an offered flow lines up with the answered one" {
    // The pairing that matters: what the peer sends is what this end receives.
    const offered = Direction.SENDONLY;
    const answered = answerFor(offered);

    try std.testing.expect(offered.sends());
    try std.testing.expect(answered.receives());
    try std.testing.expect(!answered.sends());
}
