//! TLS 1.2 PRF + key schedule (RFC 5246 sec 5, 6.3, 7.4.9). Distinct from the 1.3 HKDF schedule in
//! key_schedule.zig: 1.2 derives keys with the HMAC-based PRF (P_SHA256 for the SHA-256 suites).
//! The master_secret, the key_block, and the Finished verify_data all ride on it. Verified against
//! the canonical 100-byte PRF known-answer vector.

const std = @import("std");

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const mac_len = HmacSha256.mac_length;

/// P_SHA256(secret, seed) (RFC 5246 5): A(0)=seed, A(i)=HMAC(secret, A(i-1)),
/// output = HMAC(secret, A(1)+seed) || HMAC(secret, A(2)+seed) || ... Fills all of `out`.
fn pSha256(out: []u8, secret: []const u8, seed: []const u8) void {
    var a: [mac_len]u8 = undefined;
    HmacSha256.create(&a, seed, secret);

    var off: usize = 0;
    while (off < out.len) {
        var block: [mac_len]u8 = undefined;
        var ctx = HmacSha256.init(secret);
        ctx.update(&a);
        ctx.update(seed);
        ctx.final(&block);

        const take = @min(mac_len, out.len - off);
        @memcpy(out[off .. off + take], block[0..take]);
        off += take;

        if (off < out.len) {
            var next: [mac_len]u8 = undefined;
            HmacSha256.create(&next, &a, secret);
            a = next;
        }
    }
}

/// TLS 1.2 PRF for the SHA-256 suites (RFC 5246 5): PRF(secret, label, seed) = P_SHA256(secret,
/// label ++ seed). `label.len + seed.len` must fit 256 bytes (a short label + two 32-byte randoms).
pub fn prf(out: []u8, secret: []const u8, label: []const u8, seed: []const u8) void {
    var label_seed: [256]u8 = undefined;
    @memcpy(label_seed[0..label.len], label);
    @memcpy(label_seed[label.len .. label.len + seed.len], seed);

    pSha256(out, secret, label_seed[0 .. label.len + seed.len]);
}

/// master_secret = PRF(pre_master, "master secret", client_random ++ server_random) (RFC 5246 8.1).
///
/// Return:
/// - [48]u8
pub fn masterSecret(pre_master: []const u8, client_random: [32]u8, server_random: [32]u8) [48]u8 {
    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], &client_random);
    @memcpy(seed[32..64], &server_random);

    var out: [48]u8 = undefined;
    prf(&out, pre_master, "master secret", &seed);

    return out;
}

/// AES-128-GCM key material from key_block = PRF(master, "key expansion", server_random ++
/// client_random) (RFC 5246 6.3). GCM has no MAC keys, so the block is 2x16 write_key + 2x4
/// write_IV = 40 bytes (the IV is the 4-byte implicit salt, RFC 5288).
pub const KeyMaterial = struct {
    client_write_key: [16]u8,
    server_write_key: [16]u8,
    client_write_iv: [4]u8,
    server_write_iv: [4]u8,
};

pub fn keyMaterial(master: [48]u8, client_random: [32]u8, server_random: [32]u8) KeyMaterial {
    var seed: [64]u8 = undefined;
    @memcpy(seed[0..32], &server_random); // server_random FIRST for key expansion
    @memcpy(seed[32..64], &client_random);

    var block: [40]u8 = undefined;
    prf(&block, &master, "key expansion", &seed);

    var km: KeyMaterial = undefined;
    @memcpy(&km.client_write_key, block[0..16]);
    @memcpy(&km.server_write_key, block[16..32]);
    @memcpy(&km.client_write_iv, block[32..36]);
    @memcpy(&km.server_write_iv, block[36..40]);

    return km;
}

/// Finished verify_data from a precomputed transcript hash (RFC 5246 7.4.9): PRF(master, label,
/// hash)[0..12]. label is "server finished" or "client finished". Used by the connection, which
/// keeps a running hash rather than the raw transcript bytes.
pub fn finishedFromHash(master: [48]u8, label: []const u8, transcript_hash: [32]u8) [12]u8 {
    var out: [12]u8 = undefined;
    prf(&out, &master, label, &transcript_hash);

    return out;
}

/// Finished verify_data over the raw handshake-message bytes (hashes them first).
pub fn finished(master: [48]u8, label: []const u8, transcript: []const u8) [12]u8 {
    var hash: [32]u8 = undefined;
    Sha256.hash(transcript, &hash, .{});

    return finishedFromHash(master, label, hash);
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix tls: tls12 prf, 100-byte known-answer vector" {
    var secret: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "9bbe436ba940f017b17652849a71db35");
    var seed: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, "a0ba9f936cda311827a6f796ffd5198c");

    var expected: [100]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66");

    var out: [100]u8 = undefined;
    prf(&out, &secret, "test label", &seed);

    try std.testing.expectEqualSlices(u8, &expected, &out);
}

test "zix tls: tls12 prf, schedule shape (master 48, finished 12 deterministic)" {
    const pre_master: [32]u8 = @splat(0x5A);
    const cr: [32]u8 = @splat(0xAA);
    const sr: [32]u8 = @splat(0xBB);

    const master = masterSecret(&pre_master, cr, sr);
    try std.testing.expectEqual(@as(usize, 48), master.len);

    const km = keyMaterial(master, cr, sr);
    // client and server material differ (different halves of the key_block).
    try std.testing.expect(!std.mem.eql(u8, &km.client_write_key, &km.server_write_key));

    const sf1 = finished(master, "server finished", "transcript");
    const sf2 = finished(master, "server finished", "transcript");
    const cf = finished(master, "client finished", "transcript");
    try std.testing.expectEqual(@as(usize, 12), sf1.len);
    try std.testing.expectEqualSlices(u8, &sf1, &sf2); // deterministic
    try std.testing.expect(!std.mem.eql(u8, &sf1, &cf)); // label separates client/server
}
