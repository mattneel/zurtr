//! zix SCTP state cookie (RFC 9260 5.1.3).
//!
//! What:
//! - The blob an INIT ACK hands out and a COOKIE ECHO hands back. It carries everything the
//!   responder needs to build the association, signed so a peer cannot edit it.
//! - Why it exists: the responder must not allocate association state when an INIT arrives, or a
//!   flood of INITs from forged sources exhausts it. Verifying a cookie is recomputing its MAC,
//!   which costs one hash and no memory.
//!
//! Note:
//! - The COOKIE ECHO chunk value is exactly this blob, so `verify` takes that value directly.
//! - The MAC covers the ports as well as the parameters. Two associations can share one DTLS
//!   connection (RFC 8261 6.1), so a cookie minted for one port pair must not be echoed on
//!   another.
//! - Cookies expire. RFC 9260 16 sets Valid.Cookie.Life to 60 seconds, and a cookie past that is
//!   answered with a Stale Cookie error carrying how late it was, not silently dropped. That is
//!   why staleness comes back as a number rather than a bool.
//! - The clock is the caller's. Nothing here reads a timer, which keeps the file testable and
//!   matches how the DTLS retransmit timers already work.
//! - Rotating the secret keeps the previous one usable for one more period, so a handshake in
//!   flight across the change still completes.

const std = @import("std");

const initiation = @import("init.zig");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

/// Cookie signing secret width, one SHA-256 block.
pub const SECRET_LEN: usize = 32;

/// Width of the MAC that closes the cookie.
pub const MAC_LEN: usize = HmacSha256.mac_length;

/// Signed part of the cookie, everything before the MAC.
pub const BODY_LEN: usize = 48;

/// Total cookie width. Fixed, so a builder can size its buffer up front.
pub const COOKIE_LEN: usize = BODY_LEN + MAC_LEN;

/// How long a cookie stays usable (RFC 9260 16, Valid.Cookie.Life).
pub const DEFAULT_LIFETIME_MS: u64 = 60_000;

/// Layout marker, so a rotation of the fields cannot be mistaken for a valid old cookie.
pub const VERSION: u8 = 1;

const FLAG_FORWARD_TSN: u8 = 1 << 0;
const FLAG_RECONFIG: u8 = 1 << 1;

/// The output buffer cannot hold a cookie.
pub const Error = error{ZixNoSpace};

/// Everything the responder has to remember between the INIT and the COOKIE ECHO.
pub const Contents = struct {
    /// This endpoint's SCTP port.
    local_port: u16,
    /// The peer's SCTP port.
    peer_port: u16,
    /// What the peer asked for in its INIT.
    peer: initiation.Fixed,
    /// What this endpoint answered with in its INIT ACK.
    local: initiation.Fixed,
    /// Whether the peer announced partial reliability.
    peer_forward_tsn: bool = false,
    /// Whether the peer announced stream reset.
    peer_reconfig: bool = false,
    /// When the cookie was minted, on the caller's monotonic millisecond clock.
    issued_ms: u64,
};

/// What a COOKIE ECHO turned out to be.
pub const Outcome = union(enum) {
    /// The MAC verified and the cookie is inside its lifetime.
    VALID: Contents,
    /// The MAC verified but the cookie is too old, by this many milliseconds.
    STALE: u64,
    /// Malformed, or signed by a secret this endpoint does not hold.
    INVALID,
};

/// Signs and verifies cookies for one endpoint.
///
/// Usage:
/// ```zig
/// var signer = Signer.init(secret);
///
/// var buf: [cookie.COOKIE_LEN]u8 = undefined;
/// const blob = try signer.sign(contents, &buf);
///
/// switch (signer.verify(cookie_echo.value, now_ms)) {
///     .VALID => |contents| establish(contents),
///     .STALE => |late_ms| sendStaleCookie(late_ms),
///     .INVALID => {},
/// }
/// ```
pub const Signer = struct {
    current: [SECRET_LEN]u8,
    previous: ?[SECRET_LEN]u8 = null,
    lifetime_ms: u64 = DEFAULT_LIFETIME_MS,

    /// Start with one secret and no history.
    ///
    /// Param:
    /// secret - [SECRET_LEN]u8 (random, never derived from anything the peer sees)
    ///
    /// Return:
    /// - Signer
    pub fn init(secret: [SECRET_LEN]u8) Signer {
        return .{ .current = secret };
    }

    /// Take a new secret and keep the old one usable for one more period.
    ///
    /// Param:
    /// next - [SECRET_LEN]u8
    ///
    /// Return:
    /// - void
    pub fn rotate(self: *Signer, next: [SECRET_LEN]u8) void {
        self.previous = self.current;
        self.current = next;
    }

    /// Mint a cookie.
    ///
    /// Param:
    /// contents - Contents
    /// out - []u8 (at least COOKIE_LEN bytes)
    ///
    /// Return:
    /// - []const u8 of exactly COOKIE_LEN bytes
    /// - error.ZixNoSpace if the buffer is smaller than that
    pub fn sign(self: Signer, contents: Contents, out: []u8) Error![]const u8 {
        if (out.len < COOKIE_LEN) return error.ZixNoSpace;

        writeBody(out[0..BODY_LEN], contents);

        var mac: [MAC_LEN]u8 = undefined;
        HmacSha256.create(&mac, out[0..BODY_LEN], &self.current);
        @memcpy(out[BODY_LEN..COOKIE_LEN], &mac);

        return out[0..COOKIE_LEN];
    }

    /// Check a cookie handed back in a COOKIE ECHO.
    ///
    /// Note:
    /// - The MAC is checked before the clock, so a forged cookie never reports staleness. That
    ///   ordering matters: a Stale Cookie error tells the peer its blob was genuine.
    ///
    /// Param:
    /// blob - []const u8 (the COOKIE ECHO chunk value)
    /// now_ms - u64 (monotonic milliseconds, the caller's clock)
    ///
    /// Return:
    /// - Outcome
    pub fn verify(self: Signer, blob: []const u8, now_ms: u64) Outcome {
        if (blob.len != COOKIE_LEN) return .INVALID;
        if (blob[0] != VERSION) return .INVALID;

        const body = blob[0..BODY_LEN];
        const carried: [MAC_LEN]u8 = blob[BODY_LEN..COOKIE_LEN].*;

        if (!self.matches(body, carried)) return .INVALID;

        const contents = readBody(body);

        // A clock that went backwards leaves the cookie inside its lifetime rather than ahead of
        // it, which is the safe reading: the peer is not at fault for the local clock.
        const age_ms = now_ms -| contents.issued_ms;

        if (age_ms > self.lifetime_ms) return .{ .STALE = age_ms - self.lifetime_ms };

        return .{ .VALID = contents };
    }

    /// Whether either held secret produced this MAC.
    fn matches(self: Signer, body: []const u8, carried: [MAC_LEN]u8) bool {
        var expected: [MAC_LEN]u8 = undefined;
        HmacSha256.create(&expected, body, &self.current);

        // Constant time: a MAC check that leaks how many bytes matched can be forged byte by byte.
        if (std.crypto.timing_safe.eql([MAC_LEN]u8, expected, carried)) return true;

        const older = self.previous orelse return false;
        HmacSha256.create(&expected, body, &older);

        return std.crypto.timing_safe.eql([MAC_LEN]u8, expected, carried);
    }
};

/// Pack the signed part of a cookie.
fn writeBody(out: *[BODY_LEN]u8, contents: Contents) void {
    var flags: u8 = 0;
    if (contents.peer_forward_tsn) flags |= FLAG_FORWARD_TSN;
    if (contents.peer_reconfig) flags |= FLAG_RECONFIG;

    out[0] = VERSION;
    out[1] = flags;
    std.mem.writeInt(u16, out[2..4], contents.local_port, .big);
    std.mem.writeInt(u16, out[4..6], contents.peer_port, .big);
    std.mem.writeInt(u16, out[6..8], 0, .big);
    std.mem.writeInt(u64, out[8..16], contents.issued_ms, .big);
    std.mem.writeInt(u32, out[16..20], contents.peer.initiate_tag, .big);
    std.mem.writeInt(u32, out[20..24], contents.peer.advertised_rwnd, .big);
    std.mem.writeInt(u16, out[24..26], contents.peer.outbound_streams, .big);
    std.mem.writeInt(u16, out[26..28], contents.peer.inbound_streams, .big);
    std.mem.writeInt(u32, out[28..32], contents.peer.initial_tsn, .big);
    std.mem.writeInt(u32, out[32..36], contents.local.initiate_tag, .big);
    std.mem.writeInt(u32, out[36..40], contents.local.initial_tsn, .big);
    std.mem.writeInt(u16, out[40..42], contents.local.outbound_streams, .big);
    std.mem.writeInt(u16, out[42..44], contents.local.inbound_streams, .big);
    std.mem.writeInt(u32, out[44..48], contents.local.advertised_rwnd, .big);
}

/// Unpack the signed part of a cookie. Only call this once the MAC has verified.
fn readBody(body: []const u8) Contents {
    const flags = body[1];

    return .{
        .local_port = std.mem.readInt(u16, body[2..4], .big),
        .peer_port = std.mem.readInt(u16, body[4..6], .big),
        .issued_ms = std.mem.readInt(u64, body[8..16], .big),
        .peer = .{
            .initiate_tag = std.mem.readInt(u32, body[16..20], .big),
            .advertised_rwnd = std.mem.readInt(u32, body[20..24], .big),
            .outbound_streams = std.mem.readInt(u16, body[24..26], .big),
            .inbound_streams = std.mem.readInt(u16, body[26..28], .big),
            .initial_tsn = std.mem.readInt(u32, body[28..32], .big),
        },
        .local = .{
            .initiate_tag = std.mem.readInt(u32, body[32..36], .big),
            .advertised_rwnd = std.mem.readInt(u32, body[44..48], .big),
            .outbound_streams = std.mem.readInt(u16, body[40..42], .big),
            .inbound_streams = std.mem.readInt(u16, body[42..44], .big),
            .initial_tsn = std.mem.readInt(u32, body[36..40], .big),
        },
        .peer_forward_tsn = flags & FLAG_FORWARD_TSN != 0,
        .peer_reconfig = flags & FLAG_RECONFIG != 0,
    };
}

// --------------------------------------------------------------------------------------- //
// test cases

const test_secret: [SECRET_LEN]u8 = @splat(0xA5);
const other_secret: [SECRET_LEN]u8 = @splat(0x5A);

fn sampleContents() Contents {
    return .{
        .local_port = 5000,
        .peer_port = 5000,
        .peer = .{
            .initiate_tag = 0x11223344,
            .advertised_rwnd = 131072,
            .outbound_streams = 1024,
            .inbound_streams = 1024,
            .initial_tsn = 0x0000ABCD,
        },
        .local = .{
            .initiate_tag = 0x55667788,
            .advertised_rwnd = 65536,
            .outbound_streams = 128,
            .inbound_streams = 128,
            .initial_tsn = 0xFFFFFFF0,
        },
        .peer_forward_tsn = true,
        .peer_reconfig = true,
        .issued_ms = 10_000,
    };
}

test "zix sctp: cookie sign, the contents come back out of a fresh cookie" {
    const signer = Signer.init(test_secret);
    const contents = sampleContents();

    var buf: [COOKIE_LEN]u8 = undefined;
    const blob = try signer.sign(contents, &buf);

    try std.testing.expectEqual(COOKIE_LEN, blob.len);

    switch (signer.verify(blob, contents.issued_ms)) {
        .VALID => |back| try std.testing.expectEqual(contents, back),
        else => return error.TestUnexpectedResult,
    }
}

test "zix sctp: cookie sign, the extension flags survive the round trip" {
    const signer = Signer.init(test_secret);
    var contents = sampleContents();
    contents.peer_forward_tsn = false;
    contents.peer_reconfig = true;

    var buf: [COOKIE_LEN]u8 = undefined;
    const blob = try signer.sign(contents, &buf);

    switch (signer.verify(blob, contents.issued_ms)) {
        .VALID => |back| {
            try std.testing.expect(!back.peer_forward_tsn);
            try std.testing.expect(back.peer_reconfig);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "zix sctp: cookie verify, a cookie signed by another secret is invalid" {
    const signer = Signer.init(test_secret);
    const stranger = Signer.init(other_secret);

    var buf: [COOKIE_LEN]u8 = undefined;
    const blob = try stranger.sign(sampleContents(), &buf);

    try std.testing.expect(signer.verify(blob, 10_000) == .INVALID);
}

test "zix sctp: cookie verify, one flipped byte in the body is invalid" {
    const signer = Signer.init(test_secret);

    var buf: [COOKIE_LEN]u8 = undefined;
    const blob = try signer.sign(sampleContents(), &buf);
    buf[20] ^= 0x01;

    try std.testing.expect(signer.verify(blob, 10_000) == .INVALID);
}

test "zix sctp: cookie verify, an edited peer tag does not survive the MAC" {
    const signer = Signer.init(test_secret);

    var buf: [COOKIE_LEN]u8 = undefined;
    const blob = try signer.sign(sampleContents(), &buf);

    // A peer that could rewrite its own initiate tag here could hijack the association.
    std.mem.writeInt(u32, buf[16..20], 0xDEADBEEF, .big);

    try std.testing.expect(signer.verify(blob, 10_000) == .INVALID);
}

test "zix sctp: cookie verify, a cookie inside its lifetime is valid at the edge" {
    const signer = Signer.init(test_secret);
    const contents = sampleContents();

    var buf: [COOKIE_LEN]u8 = undefined;
    const blob = try signer.sign(contents, &buf);

    const at_edge = contents.issued_ms + DEFAULT_LIFETIME_MS;
    try std.testing.expect(signer.verify(blob, at_edge) == .VALID);
}

test "zix sctp: cookie verify, a cookie past its lifetime reports how late it is" {
    const signer = Signer.init(test_secret);
    const contents = sampleContents();

    var buf: [COOKIE_LEN]u8 = undefined;
    const blob = try signer.sign(contents, &buf);

    const late = contents.issued_ms + DEFAULT_LIFETIME_MS + 250;

    switch (signer.verify(blob, late)) {
        .STALE => |staleness_ms| try std.testing.expectEqual(@as(u64, 250), staleness_ms),
        else => return error.TestUnexpectedResult,
    }
}

test "zix sctp: cookie verify, a forged cookie is invalid rather than stale" {
    const signer = Signer.init(test_secret);
    const stranger = Signer.init(other_secret);

    var buf: [COOKIE_LEN]u8 = undefined;
    const blob = try stranger.sign(sampleContents(), &buf);

    // Reporting staleness would tell the sender its blob was genuine.
    try std.testing.expect(signer.verify(blob, 10_000_000) == .INVALID);
}

test "zix sctp: cookie verify, a clock that went backwards keeps the cookie valid" {
    const signer = Signer.init(test_secret);
    const contents = sampleContents();

    var buf: [COOKIE_LEN]u8 = undefined;
    const blob = try signer.sign(contents, &buf);

    try std.testing.expect(signer.verify(blob, contents.issued_ms - 5_000) == .VALID);
}

test "zix sctp: cookie verify, a short or long blob is invalid" {
    const signer = Signer.init(test_secret);

    var buf: [COOKIE_LEN + 1]u8 = undefined;
    const blob = try signer.sign(sampleContents(), &buf);

    try std.testing.expect(signer.verify(blob[0 .. COOKIE_LEN - 1], 10_000) == .INVALID);
    try std.testing.expect(signer.verify(buf[0 .. COOKIE_LEN + 1], 10_000) == .INVALID);
    try std.testing.expect(signer.verify(&.{}, 10_000) == .INVALID);
}

test "zix sctp: cookie verify, a wrong version marker is invalid" {
    const signer = Signer.init(test_secret);

    var buf: [COOKIE_LEN]u8 = undefined;
    const blob = try signer.sign(sampleContents(), &buf);
    buf[0] = VERSION + 1;

    try std.testing.expect(signer.verify(blob, 10_000) == .INVALID);
}

test "zix sctp: cookie rotate, a cookie from the previous secret still verifies" {
    var signer = Signer.init(test_secret);

    var buf: [COOKIE_LEN]u8 = undefined;
    const blob = try signer.sign(sampleContents(), &buf);

    signer.rotate(other_secret);

    try std.testing.expect(signer.verify(blob, 10_000) == .VALID);
}

test "zix sctp: cookie rotate, a cookie two secrets old no longer verifies" {
    var signer = Signer.init(test_secret);

    var buf: [COOKIE_LEN]u8 = undefined;
    const blob = try signer.sign(sampleContents(), &buf);

    signer.rotate(other_secret);
    signer.rotate(@splat(0x33));

    try std.testing.expect(signer.verify(blob, 10_000) == .INVALID);
}

test "zix sctp: cookie sign, a buffer smaller than one cookie errors" {
    const signer = Signer.init(test_secret);

    var buf: [COOKIE_LEN - 1]u8 = undefined;
    try std.testing.expectError(error.ZixNoSpace, signer.sign(sampleContents(), &buf));
}

test "zix sctp: cookie sign, two different port pairs give different cookies" {
    const signer = Signer.init(test_secret);

    var first_buf: [COOKIE_LEN]u8 = undefined;
    var second_buf: [COOKIE_LEN]u8 = undefined;

    var contents = sampleContents();
    const first = try signer.sign(contents, &first_buf);

    contents.peer_port = 5001;
    const second = try signer.sign(contents, &second_buf);

    try std.testing.expect(!std.mem.eql(u8, first, second));
}

test "zix sctp: cookie verify, a lifetime the caller shortened is honoured" {
    var signer = Signer.init(test_secret);
    signer.lifetime_ms = 1_000;

    const contents = sampleContents();

    var buf: [COOKIE_LEN]u8 = undefined;
    const blob = try signer.sign(contents, &buf);

    try std.testing.expect(signer.verify(blob, contents.issued_ms + 1_000) == .VALID);
    try std.testing.expect(signer.verify(blob, contents.issued_ms + 1_001) == .STALE);
}
