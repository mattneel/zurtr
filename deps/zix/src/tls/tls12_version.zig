//! TLS cross-version selection + downgrade sentinel (RFC 8446 4.1.3, 4.2.1). A 1.3-capable server
//! offering both 1.3 and 1.2 picks 1.3 when the client offers it, else falls back to 1.2, else
//! rejects (1.1 / 1.0 are never used). When it negotiates DOWN to 1.2 it plants the "DOWNGRD\x01"
//! sentinel in the last 8 bytes of ServerHello.random, so a 1.3-capable client detects a downgrade.

const std = @import("std");

const version_tls_1_2: u16 = 0x0303;

/// Last 8 bytes of ServerHello.random when a 1.3-capable server negotiates lower (RFC 8446 4.1.3).
pub const sentinel_tls_1_2 = [8]u8{ 'D', 'O', 'W', 'N', 'G', 'R', 'D', 0x01 };
pub const sentinel_below_1_2 = [8]u8{ 'D', 'O', 'W', 'N', 'G', 'R', 'D', 0x00 };

/// The negotiated version outcome. UPPER_CASE per the public-enum rule.
pub const Selected = enum { TLS_1_3, TLS_1_2, UNSUPPORTED };

/// Pick the version (RFC 8446 4.2.1): prefer 1.3 when offered via supported_versions, else 1.2 when
/// legacy_version is at least 0x0303, else unsupported.
fn selectVersion(offers_tls13: bool, legacy_version: u16) Selected {
    if (offers_tls13) return .TLS_1_3;
    if (legacy_version >= version_tls_1_2) return .TLS_1_2;

    return .UNSUPPORTED;
}

/// Plant the downgrade sentinel in the last 8 bytes of ServerHello.random when negotiating below
/// 1.3. No-op for 1.3. zix only negotiates 1.3 or 1.2, so in practice only the 1.2 sentinel is set.
pub fn applyDowngradeSentinel(server_random: *[32]u8, negotiated: Selected) void {
    switch (negotiated) {
        .TLS_1_3 => {},
        .TLS_1_2 => @memcpy(server_random[24..32], &sentinel_tls_1_2),
        .UNSUPPORTED => @memcpy(server_random[24..32], &sentinel_below_1_2),
    }
}

/// Client-side check: a client that offered 1.3 but got a lower version with the matching sentinel
/// MUST treat it as a downgrade attack and abort (RFC 8446 4.1.3).
fn downgradeDetected(server_random: [32]u8, negotiated: Selected, client_offered_1_3: bool) bool {
    if (!client_offered_1_3) return false;

    return switch (negotiated) {
        .TLS_1_3 => false,
        .TLS_1_2 => std.mem.eql(u8, server_random[24..32], &sentinel_tls_1_2),
        .UNSUPPORTED => std.mem.eql(u8, server_random[24..32], &sentinel_below_1_2),
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix tls: tls12 version, selection" {
    try std.testing.expectEqual(Selected.TLS_1_3, selectVersion(true, version_tls_1_2));
    try std.testing.expectEqual(Selected.TLS_1_2, selectVersion(false, version_tls_1_2));
    try std.testing.expectEqual(Selected.UNSUPPORTED, selectVersion(false, 0x0302));
}

test "zix tls: tls12 version, downgrade sentinel byte-exact + detect" {
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01 }, &sentinel_tls_1_2);

    var rnd: [32]u8 = @splat(0xAB);
    applyDowngradeSentinel(&rnd, .TLS_1_2);
    const head: [24]u8 = @splat(0xAB);
    try std.testing.expectEqualSlices(u8, &head, rnd[0..24]);
    try std.testing.expectEqualSlices(u8, &sentinel_tls_1_2, rnd[24..32]);

    try std.testing.expect(downgradeDetected(rnd, .TLS_1_2, true)); // 1.3 client + 1.2 + sentinel
    try std.testing.expect(!downgradeDetected(rnd, .TLS_1_3, true)); // server picked 1.3
    try std.testing.expect(!downgradeDetected(rnd, .TLS_1_2, false)); // genuine 1.2-only client
}
