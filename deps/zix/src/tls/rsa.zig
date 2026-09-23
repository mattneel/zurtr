//! RSA signing for TLS server authentication (RFC 8017, PKCS#1 v2.2).
//!
//! Note:
//! - std VERIFIES RSA but cannot sign with a private key. This module authors the two signature
//!   encodings, EMSA-PKCS1-v1_5 (TLS 1.2 RSA suites) and EMSA-PSS (TLS 1.3 CertificateVerify,
//!   rsa_pss_rsae_sha256), and drives the CRT modular exponentiation through the constant-time
//!   Montgomery modexp in montgomery.zig (std.crypto.ff.Modulus is the fallback for other widths).
//! - PrivateKey parses a two-prime RSAPrivateKey from PKCS#1 or PKCS#8 DER (the forms openssl emits)
//!   and copies the modulus + private exponent into owned fixed buffers, so it holds no external
//!   memory and is safe to store by value in a SigningKey.
//! - Randomness is injected: signPss takes the salt from the caller (the serve path sources it from
//!   getrandom), so the encoding is deterministic given its inputs and unit-testable without I/O.
//! - Verified against openssl in rnd/0.5.x/verify-rsa.sh and against std RSA verify in-file.

const std = @import("std");
const mont = @import("montgomery.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

const hash_len = Sha256.digest_length;

/// Salt length for rsa_pss_rsae_sha256 (equals the hash length).
pub const pss_salt_len = hash_len;

/// Largest modulus supported (RSA-4096). RSA-2048 keys use a subset of each buffer.
pub const max_modulus_bits = 4096;
pub const max_modulus_len = max_modulus_bits / 8;

/// Largest CRT factor (a prime, half the modulus width). p, q, dP, dQ, qInv all fit here.
pub const max_prime_len = max_modulus_len / 2;

const Modulus = std.crypto.ff.Modulus(max_modulus_bits);

pub const Error = error{ ZixInvalidKey, ZixMessageTooLong };

/// DigestInfo DER prefix for SHA-256 (RFC 8017 9.2, the T value is this prefix then the 32 hash bytes).
const sha256_digestinfo_prefix = [_]u8{
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
};

// --------------------------------------------------------------- //

/// A parsed RSA private key: the modulus and private exponent, plus the CRT factors when present,
/// each big-endian with leading zeros stripped, copied into owned fixed buffers.
pub const PrivateKey = struct {
    n_buf: [max_modulus_len]u8 = undefined,
    n_len: usize = 0,
    d_buf: [max_modulus_len]u8 = undefined,
    d_len: usize = 0,

    /// CRT factors (RFC 8017 3.2 second form): p, q, dP, dQ, qInv. Present for any two-prime
    /// RSAPrivateKey, which is every key openssl emits. has_crt gates the fast signing path. When
    /// false (a key form without them), signing falls back to the plain m ^ d mod n path.
    has_crt: bool = false,
    p_buf: [max_prime_len]u8 = undefined,
    p_len: usize = 0,
    q_buf: [max_prime_len]u8 = undefined,
    q_len: usize = 0,
    dp_buf: [max_prime_len]u8 = undefined,
    dp_len: usize = 0,
    dq_buf: [max_prime_len]u8 = undefined,
    dq_len: usize = 0,
    qinv_buf: [max_prime_len]u8 = undefined,
    qinv_len: usize = 0,

    /// The modulus n, big-endian.
    pub fn modulus(self: *const PrivateKey) []const u8 {
        return self.n_buf[0..self.n_len];
    }

    /// The private exponent d, big-endian.
    pub fn privateExponent(self: *const PrivateKey) []const u8 {
        return self.d_buf[0..self.d_len];
    }

    /// The CRT prime p, big-endian.
    pub fn primeP(self: *const PrivateKey) []const u8 {
        return self.p_buf[0..self.p_len];
    }

    /// The CRT prime q, big-endian.
    pub fn primeQ(self: *const PrivateKey) []const u8 {
        return self.q_buf[0..self.q_len];
    }

    /// The CRT exponent dP = d mod (p - 1), big-endian.
    pub fn expDp(self: *const PrivateKey) []const u8 {
        return self.dp_buf[0..self.dp_len];
    }

    /// The CRT exponent dQ = d mod (q - 1), big-endian.
    pub fn expDq(self: *const PrivateKey) []const u8 {
        return self.dq_buf[0..self.dq_len];
    }

    /// The CRT coefficient qInv = q^-1 mod p, big-endian.
    pub fn coeffQinv(self: *const PrivateKey) []const u8 {
        return self.qinv_buf[0..self.qinv_len];
    }

    /// The modulus byte length k, which is also the signature length.
    pub fn size(self: *const PrivateKey) usize {
        return self.n_len;
    }

    /// Parse a two-prime RSAPrivateKey, unwrapping the PKCS#8 PrivateKeyInfo first when `is_pkcs8`.
    ///
    /// Note:
    /// - PKCS#8 (RFC 5208): SEQUENCE { INTEGER version, SEQUENCE AlgorithmIdentifier, OCTET STRING }.
    ///   The OCTET STRING content is the inner RSAPrivateKey, then parsed as PKCS#1.
    /// - PKCS#1 (RFC 8017 A.1.2): SEQUENCE { version, n, e, d, p, q, dp, dq, qinv }. n and d are
    ///   retained, and the CRT factors p, q, dp, dq, qinv when present (they drive the fast signing
    ///   path). A key without them still parses and signs via the plain m ^ d mod n path.
    ///
    /// Param:
    /// der - []const u8 (the decoded key DER)
    /// is_pkcs8 - bool (true for a PKCS#8 PrivateKeyInfo, false for a bare PKCS#1 RSAPrivateKey)
    ///
    /// Return:
    /// - PrivateKey (owns its modulus + exponent bytes)
    /// - error.ZixInvalidKey if the DER is malformed or a field exceeds max_modulus_len
    pub fn fromDer(der: []const u8, is_pkcs8: bool) Error!PrivateKey {
        var inner = der;
        if (is_pkcs8) {
            var outer = DerReader{ .buf = der };

            try outer.expectTag(0x30); // SEQUENCE PrivateKeyInfo
            _ = try outer.readLen();
            try outer.expectTag(0x02); // INTEGER version
            try outer.skip(try outer.readLen());
            try outer.expectTag(0x30); // SEQUENCE AlgorithmIdentifier
            try outer.skip(try outer.readLen());
            try outer.expectTag(0x04); // OCTET STRING privateKey
            const inner_len = try outer.readLen();
            inner = try outer.read(inner_len);
        }

        var r = DerReader{ .buf = inner };

        try r.expectTag(0x30); // SEQUENCE RSAPrivateKey
        _ = try r.readLen();
        try r.expectTag(0x02); // INTEGER version (0 for two-prime)
        try r.skip(try r.readLen());

        const n = try r.readInteger();
        _ = try r.readInteger(); // publicExponent e (not needed to sign)
        const d = try r.readInteger();

        if (n.len > max_modulus_len or d.len > max_modulus_len) return error.ZixInvalidKey;

        var key = PrivateKey{ .n_len = n.len, .d_len = d.len };
        @memcpy(key.n_buf[0..n.len], n);
        @memcpy(key.d_buf[0..d.len], d);

        key.loadCrt(&r);

        return key;
    }

    /// Read the optional CRT factors (p, q, dp, dq, qinv) that follow d in a two-prime
    /// RSAPrivateKey. On any miss (absent, malformed, or wider than a supported prime) the key keeps
    /// has_crt false and signs via the plain m ^ d mod n path. The reader is at end-of-key after.
    fn loadCrt(self: *PrivateKey, r: *DerReader) void {
        const p = r.readInteger() catch return;
        const q = r.readInteger() catch return;
        const dp = r.readInteger() catch return;
        const dq = r.readInteger() catch return;
        const qinv = r.readInteger() catch return;

        if (p.len > max_prime_len or q.len > max_prime_len or dp.len > max_prime_len or
            dq.len > max_prime_len or qinv.len > max_prime_len) return;

        @memcpy(self.p_buf[0..p.len], p);
        self.p_len = p.len;
        @memcpy(self.q_buf[0..q.len], q);
        self.q_len = q.len;
        @memcpy(self.dp_buf[0..dp.len], dp);
        self.dp_len = dp.len;
        @memcpy(self.dq_buf[0..dq.len], dq);
        self.dq_len = dq.len;
        @memcpy(self.qinv_buf[0..qinv.len], qinv);
        self.qinv_len = qinv.len;

        self.has_crt = true;
    }

    /// Sign a message with EMSA-PKCS1-v1_5 over SHA-256 (RFC 8017 8.2.1). Deterministic.
    ///
    /// Param:
    /// message - []const u8 (the bytes to sign, hashed with SHA-256 internally)
    /// out - []u8 (buffer for the signature, must be at least size() bytes)
    ///
    /// Return:
    /// - []const u8 (the signature, size() bytes, a sub-slice of out)
    /// - error.ZixMessageTooLong if the modulus is too small for the padding plus DigestInfo
    pub fn signPkcs1v15(self: *const PrivateKey, message: []const u8, out: []u8) Error![]const u8 {
        const k = self.size();

        var digest: [hash_len]u8 = undefined;
        Sha256.hash(message, &digest, .{});

        var em_buf: [max_modulus_len]u8 = undefined;
        const em = em_buf[0..k];
        try emsaPkcs1V15(digest, em);

        if (self.has_crt) {
            const mod_n = Modulus.fromBytes(self.modulus(), .big) catch return error.ZixInvalidKey;
            return self.rsaspCrt(mod_n, em, out[0..k]);
        }

        return rsasp1(self.modulus(), self.privateExponent(), em, out[0..k]);
    }

    /// Sign a message with EMSA-PSS over SHA-256 and MGF1 (RFC 8017 8.1.1, rsa_pss_rsae_sha256).
    ///
    /// Note:
    /// - The salt is supplied by the caller (RFC 8017 allows any salt, the serve path uses 32 random
    ///   bytes). A fixed salt makes a given signature reproducible, which the unit tests rely on.
    ///
    /// Param:
    /// message - []const u8 (the bytes to sign, hashed with SHA-256 internally)
    /// salt - [pss_salt_len]u8 (the random salt, 32 bytes)
    /// out - []u8 (buffer for the signature, must be at least size() bytes)
    ///
    /// Return:
    /// - []const u8 (the signature, size() bytes, a sub-slice of out)
    /// - error.ZixMessageTooLong if the modulus is too small for the salt and hash
    pub fn signPss(self: *const PrivateKey, message: []const u8, salt: [pss_salt_len]u8, out: []u8) Error![]const u8 {
        const k = self.size();
        const parsed_modulus = Modulus.fromBytes(self.modulus(), .big) catch return error.ZixInvalidKey;
        const em_bits = parsed_modulus.bits() - 1;

        var em_buf: [max_modulus_len]u8 = undefined;
        const em_len = std.math.divCeil(usize, em_bits, 8) catch unreachable;
        const em = em_buf[0..em_len];
        try emsaPssEncode(message, salt, em_bits, em);

        if (self.has_crt) return self.rsaspCrt(parsed_modulus, em, out[0..k]);

        return rsasp1WithModulus(parsed_modulus, self.privateExponent(), em, out[0..k]);
    }

    /// RSASP1 via the Chinese Remainder Theorem (RFC 8017 5.1.2 second form, applied to the signing
    /// primitive). About 4x the plain m ^ d mod n path: two half-width modexps over p and q (whose
    /// runtime limb count is half the modulus) instead of one full-width modexp with the 2048-bit
    /// private exponent. Constant-time, the std.crypto.ff routines are constant-time per prime.
    ///
    /// Param:
    /// mod_n - Modulus (the already-parsed public modulus n, reused so it is not parsed twice)
    /// em - []const u8 (the encoded message, an integer below n)
    /// sig - []u8 (the signature buffer, exactly size() bytes)
    ///
    /// Return:
    /// - []const u8 (the signature, sig)
    /// - error.ZixInvalidKey if a factor is malformed
    fn rsaspCrt(self: *const PrivateKey, mod_n: Modulus, em: []const u8, sig: []u8) Error![]const u8 {
        const k = sig.len;
        const mod_p = Modulus.fromBytes(self.primeP(), .big) catch return error.ZixInvalidKey;
        const mod_q = Modulus.fromBytes(self.primeQ(), .big) catch return error.ZixInvalidKey;

        // m reduced into each prime field, then m1 = m^dP mod p, m2 = m^dQ mod q.
        const m_n = Modulus.Fe.fromBytes(mod_n, em, .big) catch return error.ZixInvalidKey;
        const m_p = mod_p.reduce(m_n.v);
        const m_q = mod_q.reduce(m_n.v);

        const s_p = try crtHalf(mod_p, self.primeP(), m_p, self.expDp());
        const s_q = try crtHalf(mod_q, self.primeQ(), m_q, self.expDq());

        // h = (s_p - s_q) * qInv mod p.
        const s_q_mod_p = mod_p.reduce(s_q.v);
        const diff = mod_p.sub(s_p, s_q_mod_p);
        const qinv = Modulus.Fe.fromBytes(mod_p, self.coeffQinv(), .big) catch return error.ZixInvalidKey;
        const h = mod_p.mul(diff, qinv);

        // s = s_q + q * h. Both q * h and s are below n, so the n-field arithmetic is exact.
        var h_buf: [max_modulus_len]u8 = undefined;
        h.toBytes(h_buf[0..k], .big) catch return error.ZixInvalidKey;
        var sq_buf: [max_modulus_len]u8 = undefined;
        s_q.toBytes(sq_buf[0..k], .big) catch return error.ZixInvalidKey;

        const h_n = Modulus.Fe.fromBytes(mod_n, h_buf[0..k], .big) catch return error.ZixInvalidKey;
        const s_q_n = Modulus.Fe.fromBytes(mod_n, sq_buf[0..k], .big) catch return error.ZixInvalidKey;
        const q_n = Modulus.Fe.fromBytes(mod_n, self.primeQ(), .big) catch return error.ZixInvalidKey;

        const qh = mod_n.mul(q_n, h_n);
        const s = mod_n.add(s_q_n, qh);
        s.toBytes(sig, .big) catch return error.ZixInvalidKey;

        return sig;
    }
};

// --------------------------------------------------------------- //

/// One CRT half-exponentiation: s = base^exp mod prime. Runs the constant-time Montgomery modexp
/// when the prime width is supported, otherwise the std.crypto.ff path. base_fe is already reduced
/// below the prime, so it serializes into the prime-width buffer without overflow.
///
/// Param:
/// mod - Modulus (the prime field, reused for the result Fe and the fallback)
/// prime_be - []const u8 (the prime p or q, big-endian, leading zeros stripped)
/// base_fe - Modulus.Fe (the base, already reduced mod prime)
/// exp_be - []const u8 (the CRT exponent dP or dQ, big-endian)
///
/// Return:
/// - Modulus.Fe (the half result s_p or s_q)
/// - error.ZixInvalidKey if serialization fails
fn crtHalf(mod: Modulus, prime_be: []const u8, base_fe: Modulus.Fe, exp_be: []const u8) Error!Modulus.Fe {
    const plen = prime_be.len;

    var base_buf: [max_prime_len]u8 = undefined;
    base_fe.toBytes(base_buf[0..plen], .big) catch return error.ZixInvalidKey;

    var out_buf: [max_prime_len]u8 = undefined;
    if (montModExp(prime_be, base_buf[0..plen], exp_be, out_buf[0..plen])) {
        return Modulus.Fe.fromBytes(mod, out_buf[0..plen], .big) catch error.ZixInvalidKey;
    }

    return mod.powWithEncodedExponent(base_fe, exp_be, .big) catch error.ZixInvalidKey;
}

/// Dispatch the modexp to a Montgomery instance sized to the prime width (the primes of
/// RSA-2048 / 3072 / 4096 are 128 / 192 / 256 bytes). Returns false for any other width so the
/// caller keeps the std.crypto.ff path.
fn montModExp(prime_be: []const u8, base_be: []const u8, exp_be: []const u8, out: []u8) bool {
    switch (prime_be.len) {
        128 => mont.Montgomery(16).modExp(prime_be, base_be, exp_be, out),
        192 => mont.Montgomery(24).modExp(prime_be, base_be, exp_be, out),
        256 => mont.Montgomery(32).modExp(prime_be, base_be, exp_be, out),
        else => return false,
    }

    return true;
}

// --------------------------------------------------------------- //

/// Encode the SHA-256 digest as an EMSA-PKCS1-v1_5 message (RFC 8017 9.2): EM = 0x00 || 0x01 || PS
/// || 0x00 || T, where PS is at least eight 0xff octets and T is the DigestInfo prefix then the hash.
fn emsaPkcs1V15(digest: [hash_len]u8, em: []u8) Error!void {
    const t_len = sha256_digestinfo_prefix.len + hash_len;
    if (em.len < t_len + 11) return error.ZixMessageTooLong;

    @memset(em, 0xff);
    em[0] = 0x00;
    em[1] = 0x01;
    em[em.len - t_len - 1] = 0x00;

    @memcpy(em[em.len - t_len ..][0..sha256_digestinfo_prefix.len], &sha256_digestinfo_prefix);
    @memcpy(em[em.len - hash_len ..][0..hash_len], &digest);
}

/// Encode a message as EMSA-PSS (RFC 8017 9.1.1): M' = (eight 0x00) || mHash || salt, H = Hash(M').
/// DB = PS || 0x01 || salt masked with MGF1(H), the top bits cleared, then EM = maskedDB || H || 0xbc.
fn emsaPssEncode(message: []const u8, salt: [pss_salt_len]u8, em_bits: usize, em: []u8) Error!void {
    var m_hash: [hash_len]u8 = undefined;
    Sha256.hash(message, &m_hash, .{});

    const em_len = em.len;
    if (em_len < hash_len + pss_salt_len + 2) return error.ZixMessageTooLong;

    var h_input: [8 + hash_len + pss_salt_len]u8 = undefined;
    @memset(h_input[0..8], 0x00);
    @memcpy(h_input[8..][0..hash_len], &m_hash);
    @memcpy(h_input[8 + hash_len ..][0..pss_salt_len], &salt);

    var h: [hash_len]u8 = undefined;
    Sha256.hash(&h_input, &h, .{});

    const db_len = em_len - hash_len - 1;
    const db = em[0..db_len];
    @memset(db, 0x00);
    db[db_len - pss_salt_len - 1] = 0x01;
    @memcpy(db[db_len - pss_salt_len ..][0..pss_salt_len], &salt);

    var db_mask: [max_modulus_len]u8 = undefined;
    mgf1(&h, db_mask[0..db_len]);
    for (db, 0..) |*byte, i| byte.* ^= db_mask[i];

    const clear_bits = 8 * em_len - em_bits;
    db[0] &= @as(u8, 0xff) >> @intCast(clear_bits);

    @memcpy(em[db_len..][0..hash_len], &h);
    em[em_len - 1] = 0xbc;
}

/// MGF1 mask generation function (RFC 8017 B.2.1) with SHA-256.
fn mgf1(seed: []const u8, out: []u8) void {
    var counter: u32 = 0;
    var pos: usize = 0;
    while (pos < out.len) : (counter += 1) {
        var c: [4]u8 = undefined;
        std.mem.writeInt(u32, &c, counter, .big);

        var digest: [hash_len]u8 = undefined;
        var hasher = Sha256.init(.{});
        hasher.update(seed);
        hasher.update(&c);
        hasher.final(&digest);

        const take = @min(hash_len, out.len - pos);
        @memcpy(out[pos..][0..take], digest[0..take]);
        pos += take;
    }
}

/// RSASP1 signature primitive (RFC 8017 5.2.1): s = m ^ d mod n, then I2OSP to k bytes.
fn rsasp1(n_bytes: []const u8, d_bytes: []const u8, em: []const u8, sig: []u8) Error![]const u8 {
    const modulus = Modulus.fromBytes(n_bytes, .big) catch return error.ZixInvalidKey;

    return rsasp1WithModulus(modulus, d_bytes, em, sig);
}

/// RSASP1 against an already-parsed modulus, so the PSS path does not parse n twice.
fn rsasp1WithModulus(modulus: Modulus, d_bytes: []const u8, em: []const u8, sig: []u8) Error![]const u8 {
    const m_fe = Modulus.Fe.fromBytes(modulus, em, .big) catch return error.ZixInvalidKey;

    const s_fe = modulus.powWithEncodedExponent(m_fe, d_bytes, .big) catch return error.ZixInvalidKey;
    s_fe.toBytes(sig, .big) catch return error.ZixInvalidKey;

    return sig;
}

// --------------------------------------------------------------- //

const DerReader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn byte(self: *DerReader) Error!u8 {
        if (self.pos >= self.buf.len) return error.ZixInvalidKey;

        const b = self.buf[self.pos];
        self.pos += 1;

        return b;
    }

    fn expectTag(self: *DerReader, tag: u8) Error!void {
        if (try self.byte() != tag) return error.ZixInvalidKey;
    }

    fn readLen(self: *DerReader) Error!usize {
        const first = try self.byte();
        if (first < 0x80) return first;

        const count = first & 0x7f;
        if (count == 0 or count > 2) return error.ZixInvalidKey;

        var len: usize = 0;
        var i: usize = 0;
        while (i < count) : (i += 1) len = (len << 8) | (try self.byte());

        return len;
    }

    fn skip(self: *DerReader, n: usize) Error!void {
        if (self.pos + n > self.buf.len) return error.ZixInvalidKey;
        self.pos += n;
    }

    fn read(self: *DerReader, n: usize) Error![]const u8 {
        if (self.pos + n > self.buf.len) return error.ZixInvalidKey;

        const s = self.buf[self.pos .. self.pos + n];
        self.pos += n;

        return s;
    }

    /// Read an INTEGER and return its big-endian magnitude (leading 0x00 padding stripped).
    fn readInteger(self: *DerReader) Error![]const u8 {
        try self.expectTag(0x02);

        const len = try self.readLen();
        var content = try self.read(len);
        while (content.len > 1 and content[0] == 0x00) content = content[1..];

        return content;
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const pem = @import("pem.zig");
const StdRsa = std.crypto.Certificate.rsa;
const std_rsa_verify = @import("std_rsa_verify.zig");

/// A deterministic RSA-2048 PKCS#8 key (openssl genpkey), with the matching message, modulus, and
/// the openssl PKCS#1 v1.5 signature over that message (deterministic, so byte-comparable).
const fixture_pkcs8_pem =
    \\-----BEGIN PRIVATE KEY-----
    \\MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDiK/ullhGBT/Mj
    \\s1cQ3b7xqIAtHwMjuTxnUne42qU3cUrEeH2/jWjXjEeBMBqt8TYp1FVpDg+u2DGU
    \\Jada+rtFsPVZkD/07HUGXYfya6hwdwOqwjm+fdI+jIIpM+N1t6Ln+eV75GIu8KEr
    \\uRQVTsR3Rz8uMcIN/apvXP1Tus2Y2ZIhAKX9vk2DvL6+7gCLzK0wJmdQ34aGEw89
    \\MRfQLVmTpFvZSJ2B81dxY+IdgbshiZbbn76pzdH4TvxIOwDpUxW16qY7VXZErMtR
    \\S9jnavMpIB1sTkZLKZyIkowWqeeVWIQG85RreOwiEYywRUYnhI44YBxf0Xmgr1x6
    \\CnJ3atxDAgMBAAECggEACaafz9KF/7MWKG1UJ0OXDL/IbGR44VLbqXsC4c/uod2D
    \\N7v+fah+k0gImxIe6VI0IffOBzQS5j6SawRqTj8Js7EX3xEBMaXPXoyqKuV+JAJo
    \\FSbBiQfca0/alACDUbgayvRGXxGBQQiCkBePLFOWnZJcN0/nPGqZFbRtmN+NO1rk
    \\zTD46uKfBAFMKZLbWrK8plECMfea5h+/ysnfhpZXv5nAXuPY6cvwgDTZvphQdB4l
    \\4mjAtuI6oEYUL4CVga1NE57vC02RxJBwylmxznJyJcRdLl52kSgOMU3xV9isrrZT
    \\88s9Ds5ZxtGqaWUmbF+pHW1wxzTmJhrCXxEGtsrmAQKBgQD5u1KiuTlPnnVgIRfT
    \\thzF5pBp6Ynwbw/Q0SMkF/E7yxkPDdLWMY43WIikRj9IyfDnIRxdGEBkprF7/Sm/
    \\ehGVGRDNNT3eRaZ04jLP/EbksO9hF49ro/FlHSaaVrDSAsW3F8HBp8NQC9Sgpdlf
    \\XwnxZsP35wpISF1hWV5be0yWAQKBgQDn2UYCjGCRFdBNdsqxbgGemPBu60/U0leE
    \\T8xg42jN6tO2j0vesKp83NFcAl71NYh7rl8G+WnFJ3DgrjrFAPbTa6VJdnNnpjV+
    \\3o2CSqSTAReFM2khRIZodCbQ3Ad/6P00RnahpciBemQsQKeyGRMrhrkBZbiPIWch
    \\LgBIniOaQwKBgGcmxsVL+K44Z4cjZDIgoNXlnHUC7+UOGtxH5ln8QbpO87TSIuoy
    \\YeneeeJQ2cb5EraFaK/TWpW4fMsYEOx0QVrylYwNl9Z9snnJDO/35liD9PyHvMfb
    \\WdRILC/H6xVz67Lq7y9MWlJv8I3Cs3y/Rt4dcoitOAQPT/Lr9RuYXFQBAoGBAM0U
    \\QXsrlJeBRhnfQ/eiKMiS28ohVyIXVNZyh4QEY8YRO2g2ZJP8jTGZWY8bgcdArRNJ
    \\8ECJCegctRnow49TBQGKLFBI+Ffsi1FHpsBjKiPmSVnHWezVYlaut07z8aZQ/vfo
    \\hDMEI9Fz43vJTQyaZXyQ1MDJq3DfyQtuV03ko/VlAoGBAJiRuT9T8EQO0gJoaS6g
    \\W/+g7A+JUZnqIrCiL9JAaWzOy4TdKtEgbDQsLH1NfVclcnti5C/6wlCqvPcSQtF/
    \\ZGgEuI4ajyq60Un5tOiB1rbJ5sahSLgpM21Ph6kkC6nxTuKfRPpu1+L92SFZBFrX
    \\sIWllpzoV5pFqYoMGir8MZfp
    \\-----END PRIVATE KEY-----
;

const fixture_message = "zix rsa fixture, rfc 8017";

const fixture_modulus_hex = "e22bfba59611814ff323b35710ddbef1a8802d1f0323b93c675277b8daa537714ac4787dbf8d68d78c4781301aadf13629d455690e0faed8319425a75afabb45b0f559903ff4ec75065d87f26ba8707703aac239be7dd23e8c822933e375b7a2e7f9e57be4622ef0a12bb914154ec477473f2e31c20dfdaa6f5cfd53bacd98d9922100a5fdbe4d83bcbebeee008bccad30266750df8686130f3d3117d02d5993a45bd9489d81f3577163e21d81bb218996db9fbea9cdd1f84efc483b00e95315b5eaa63b557644accb514bd8e76af329201d6c4e464b299c88928c16a9e795588406f3946b78ec22118cb0454627848e38601c5fd179a0af5c7a0a72776adc43";

const fixture_v15_sig_hex = "de026c6dec3aaec2bc96e8bc2a940d3bd3d9ad40f8118f463b9ee9d528a736e8abd5c2eee17737d52c097126849fe9f076971339a1412074afdc7dc47b6a2d76577fd9d300f82a55d80f74f6feb2f851b913a7d7b2c72de9183d868bbf1fd848d4283bcd6e6a1ca7c47e04d274b129249b96cc0b6557081fa0abb03b00cdd48c91ec57780d15921aaccd116cf7bde01a039412720702d3bb3c486d16cbccce4a3ac27d6a5d90779f3c57b5403a91e6235c5787bb814cde48cfc818ef005489a57035abd582ad96dae9e87c1f294ec68fd4dadd25395f90da7f35d096d3181e8c62303d12f51bb416df5d70c61bf5e41e6381f56910b5c03593cf5b2f55e064c9";

fn loadFixtureKey() !PrivateKey {
    var der_buf: [4096]u8 = undefined;
    const der = try pem.pemToDer(&der_buf, fixture_pkcs8_pem);

    return PrivateKey.fromDer(der, true);
}

fn fixturePublicKey() !StdRsa.PublicKey {
    var n_bytes: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&n_bytes, fixture_modulus_hex);

    const e_bytes = [_]u8{ 0x01, 0x00, 0x01 };

    return StdRsa.PublicKey.fromBytes(&e_bytes, &n_bytes);
}

test "zix tls: rsa, PKCS#8 parse yields the expected modulus (R3 in-tree)" {
    const key = try loadFixtureKey();

    var expected_n: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_n, fixture_modulus_hex);

    try std.testing.expectEqual(@as(usize, 256), key.size());
    try std.testing.expectEqualSlices(u8, &expected_n, key.modulus());
}

test "zix tls: rsa, PKCS#1 v1.5 sign is byte-exact with openssl (deterministic)" {
    const key = try loadFixtureKey();

    var sig_buf: [max_modulus_len]u8 = undefined;
    const sig = try key.signPkcs1v15(fixture_message, &sig_buf);

    var expected_sig: [256]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_sig, fixture_v15_sig_hex);

    try std.testing.expectEqualSlices(u8, &expected_sig, sig);
}

test "zix tls: rsa, PKCS#1 v1.5 signature verifies with std RSA verify" {
    const key = try loadFixtureKey();
    const public_key = try fixturePublicKey();

    var sig_buf: [max_modulus_len]u8 = undefined;
    const sig = try key.signPkcs1v15(fixture_message, &sig_buf);

    try std_rsa_verify.verifyPkcs1v15(256, sig[0..256], fixture_message, public_key, Sha256);
}

test "zix tls: rsa, PSS signature verifies with std RSA verify (rsa_pss_rsae_sha256)" {
    const key = try loadFixtureKey();
    const public_key = try fixturePublicKey();

    var salt: [pss_salt_len]u8 = undefined;
    @memset(&salt, 0x5a);

    var sig_buf: [max_modulus_len]u8 = undefined;
    const sig = try key.signPss(fixture_message, salt, &sig_buf);

    // Temporary, zig 0.17 only: std's PSS verifier panics, see std_rsa_verify.zig.
    if (!std_rsa_verify.PSS_USABLE) {
        std.log.info("zix tls: rsa, std PSS verify is broken on this zig, cross-check skipped", .{});

        return;
    }

    try std_rsa_verify.verifyPss(256, sig[0..256], fixture_message, public_key, Sha256);
}

test "zix tls: rsa, CRT sign equals the plain m^d path (and has_crt is set)" {
    const key = try loadFixtureKey();
    try std.testing.expect(key.has_crt);

    var salt: [pss_salt_len]u8 = undefined;
    @memset(&salt, 0x5a);

    // the CRT path (has_crt true)
    var crt_buf: [max_modulus_len]u8 = undefined;
    const crt_sig = try key.signPss(fixture_message, salt, &crt_buf);

    // the same key forced onto the plain m ^ d mod n path
    var plain_key = key;
    plain_key.has_crt = false;
    var plain_buf: [max_modulus_len]u8 = undefined;
    const plain_sig = try plain_key.signPss(fixture_message, salt, &plain_buf);

    try std.testing.expectEqualSlices(u8, plain_sig, crt_sig);

    // and the v1.5 path agrees too
    var crt_v15: [max_modulus_len]u8 = undefined;
    const crt_v15_sig = try key.signPkcs1v15(fixture_message, &crt_v15);
    var plain_v15: [max_modulus_len]u8 = undefined;
    const plain_v15_sig = try plain_key.signPkcs1v15(fixture_message, &plain_v15);

    try std.testing.expectEqualSlices(u8, plain_v15_sig, crt_v15_sig);
}

test "zix tls: rsa, a tampered message fails std verify" {
    const key = try loadFixtureKey();
    const public_key = try fixturePublicKey();

    var sig_buf: [max_modulus_len]u8 = undefined;
    const sig = try key.signPkcs1v15(fixture_message, &sig_buf);

    try std.testing.expectError(error.InvalidSignature, std_rsa_verify.verifyPkcs1v15(256, sig[0..256], "tampered message", public_key, Sha256));
}
