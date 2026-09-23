//! zix TLS 1.3 client handshake (RFC 8446): the mirror of connection.zig (server). Sans-I/O, two
//! phases: `start` builds the ClientHello (the caller sends it), `finish` consumes the server flight
//! (ServerHello + ChangeCipherSpec + the encrypted EE/Certificate/CertificateVerify/Finished),
//! derives the client-side keys with the SAME schedule the server runs, verifies the server
//! Finished, and produces the client Finished + a ClientConnection for application data.
//!
//! Note:
//! - It offers x25519 + the mandatory extensions, completes the handshake, and verifies the peer.
//!   finish() verifies the server CertificateVerify (the peer holds the cert key) and
//!   surfaces the server end-entity certificate so the caller can chain-validate it (RFC 5280) +
//!   match the hostname (RFC 6125) through FinishResult.verifyServerCert against its trust store.
//! - Reuses the shared layers (wire, key_schedule, record, certificate, cert_verify), so no crypto
//!   is re-implemented. The oracle in tests is connection.serverHandshake (byte-exact vs RFC 8448).

const std = @import("std");
const wire = @import("wire.zig");
const key_schedule = @import("key_schedule.zig");
const record = @import("record.zig");
const certificate = @import("certificate.zig");
const extensions = @import("extensions.zig");
const cert_verify = @import("cert_verify.zig");

const X25519 = std.crypto.dh.X25519;
const Secret = key_schedule.Secret;
const Alpn = extensions.Alpn;

const named_group_x25519: u16 = 0x001d;

/// Max DER size for the server end-entity cert copied out of the decrypted flight. A P-256 leaf is
/// ~470 bytes, 2 KiB covers larger SAN lists and RSA leaves. A bigger cert fails handshake.
pub const max_server_cert_der = 2048;

pub const HandshakeOptions = struct {
    client_random: [32]u8,
    /// x25519 ephemeral private (fresh per connection, a fixed value in tests).
    ephemeral_secret: [32]u8,
    /// ALPN protocols to offer (RFC 7301), e.g. &.{.H2}. Empty offers no ALPN.
    alpn: []const Alpn = &.{},
};

/// Carried from start into finish: the ephemeral secret and the running transcript (ClientHello so far).
pub const State = struct {
    ephemeral_secret: [32]u8,
    transcript: key_schedule.Transcript,
};

pub const StartResult = struct {
    client_hello: []const u8,
    state: State,
};

pub const FinishResult = struct {
    client_finished: []const u8,
    connection: ClientConnection,
    /// the ALPN protocol the server selected (from EncryptedExtensions), null when none.
    alpn: ?Alpn = null,
    /// the server end-entity certificate (DER), copied out of the decrypted flight so it outlives
    /// finish(). Read it through serverCertDer(), trust it through verifyServerCert().
    server_cert: [max_server_cert_der]u8 = undefined,
    server_cert_len: usize = 0,

    /// The server end-entity certificate DER. Empty when the server sent no Certificate.
    pub fn serverCertDer(self: *const FinishResult) []const u8 {
        return self.server_cert[0..self.server_cert_len];
    }

    /// Trust the server certificate: chain it to `anchor_der` within its validity window (RFC 5280)
    /// and match `hostname` against its SAN (RFC 6125). finish() already proved the peer holds the
    /// cert key (CertificateVerify), this is the remaining chain + identity step that the caller
    /// owns, since only the caller knows its trust anchor and the host it meant to reach.
    ///
    /// Note:
    /// - For a self-signed server, `anchor_der` is the server certificate itself (out-of-band).
    ///   Do NOT pass serverCertDer() as the anchor: that only checks the cert signed itself, not
    ///   that it is trusted.
    ///
    /// Param:
    /// anchor_der - []const u8 (trust anchor DER the cert must chain to)
    /// hostname - []const u8 (the host the client intended to reach)
    /// now_sec - i64 (current UNIX time in seconds, for the validity window)
    ///
    /// Return:
    /// - void on a trusted, hostname-matching certificate
    /// - error.ZixNoServerCertificate (the server sent no Certificate)
    /// - error.CertificateExpired / error.CertificateNotYetValid / error.CertificateIssuerMismatch
    /// - error.CertificateHostMismatch (no SAN/CN entry matches hostname)
    pub fn verifyServerCert(self: *const FinishResult, anchor_der: []const u8, hostname: []const u8, now_sec: i64) !void {
        const der = self.serverCertDer();
        if (der.len == 0) return error.ZixNoServerCertificate;

        try cert_verify.verifyCertChain(der, anchor_der, now_sec);
        try cert_verify.verifyCertHostname(der, hostname);
    }
};

/// Post-handshake client keys + per-direction sequence numbers. The client writes under the client
/// application key and reads under the server's (the opposite of the server's Connection).
pub const ClientConnection = struct {
    client_app_key: [record.key_length]u8,
    client_app_iv: [record.iv_length]u8,
    server_app_key: [record.key_length]u8,
    server_app_iv: [record.iv_length]u8,
    client_seq: u64 = 0,
    server_seq: u64 = 0,

    pub fn writeAppData(self: *ClientConnection, plaintext: []const u8, out: []u8) []const u8 {
        const rec = record.protect(out, plaintext, .APPLICATION_DATA, self.client_app_key, self.client_app_iv, self.client_seq);
        self.client_seq += 1;

        return rec;
    }

    pub fn readAppData(self: *ClientConnection, rec: []const u8, out: []u8) record.Error![]const u8 {
        const opened = try record.deprotect(out, rec, self.server_app_key, self.server_app_iv, self.server_seq);
        self.server_seq += 1;
        if (opened.inner_type != .APPLICATION_DATA) return error.ZixDecode;

        return opened.data;
    }

    pub fn closeNotify(self: *ClientConnection, out: []u8) []const u8 {
        const rec = record.protect(out, &[_]u8{ 1, 0 }, .ALERT, self.client_app_key, self.client_app_iv, self.client_seq);
        self.client_seq += 1;

        return rec;
    }
};

/// Phase 1: build the ClientHello (offering x25519 + the mandatory extensions) and start the
/// transcript. The caller sends `client_hello`, then feeds the server flight to `finish`.
pub fn start(opts: HandshakeOptions, out: []u8) !StartResult {
    const client_public = try X25519.recoverPublicKey(opts.ephemeral_secret);
    const client_hello = buildClientHello(out, opts.client_random, client_public, opts.alpn);

    var state = State{ .ephemeral_secret = opts.ephemeral_secret, .transcript = key_schedule.Transcript.init() };
    state.transcript.update(client_hello);

    return .{ .client_hello = client_hello, .state = state };
}

/// Phase 2: process the server flight, verify the server Finished, produce the client Finished and
/// the ClientConnection.
pub fn finish(state: *State, server_flight: []const u8, out: []u8) !FinishResult {
    var r = wire.Reader{ .buf = server_flight };

    // record 1: ServerHello (plaintext handshake).
    if (try r.readU8() != 22) return error.ZixUnexpectedRecord;
    _ = try r.readU16();
    const sh_len = try r.readU16();
    const sh_msg = try r.readBytes(sh_len);
    const sh = try parseServerHello(sh_msg);
    state.transcript.update(sh_msg);

    // record 2: ChangeCipherSpec (skipped).
    if (try r.readU8() != 20) return error.ZixUnexpectedRecord;
    _ = try r.readU16();
    const ccs_len = try r.readU16();
    _ = try r.readBytes(ccs_len);

    // record 3: the encrypted flight.
    const flight_pos = r.pos;
    if (try r.readU8() != 23) return error.ZixUnexpectedRecord;
    _ = try r.readU16();
    const flight_len = try r.readU16();
    const flight_record = server_flight[flight_pos .. flight_pos + 5 + flight_len];

    // handshake key schedule from the transcript through ServerHello (identical to the server).
    const ecdhe = try X25519.scalarmult(state.ephemeral_secret, sh.server_public);

    const zero = std.mem.zeroes(Secret);
    const empty_hash = key_schedule.Transcript.init().current();
    const early = key_schedule.HkdfSha256.extract(&zero, &zero);
    const derived = key_schedule.deriveSecret(early, "derived", empty_hash);
    const handshake_secret = key_schedule.HkdfSha256.extract(&derived, &ecdhe);

    const t_ch_sh = state.transcript.current();
    const server_hs_traffic = key_schedule.deriveSecret(handshake_secret, "s hs traffic", t_ch_sh);
    const client_hs_traffic = key_schedule.deriveSecret(handshake_secret, "c hs traffic", t_ch_sh);

    var server_hs_key: [record.key_length]u8 = undefined;
    var server_hs_iv: [record.iv_length]u8 = undefined;
    var client_hs_key: [record.key_length]u8 = undefined;
    var client_hs_iv: [record.iv_length]u8 = undefined;
    key_schedule.expandLabel(&server_hs_key, server_hs_traffic, "key", "");
    key_schedule.expandLabel(&server_hs_iv, server_hs_traffic, "iv", "");
    key_schedule.expandLabel(&client_hs_key, client_hs_traffic, "key", "");
    key_schedule.expandLabel(&client_hs_iv, client_hs_traffic, "iv", "");

    // decrypt the flight, fold each inner message (EE, Cert, CertVerify, Finished) into the transcript.
    var flight_plain: [4096]u8 = undefined;
    const opened = try record.deprotect(&flight_plain, flight_record, server_hs_key, server_hs_iv, 0);
    if (opened.inner_type != .HANDSHAKE) return error.ZixUnexpectedRecord;

    var fr = wire.Reader{ .buf = opened.data };
    var server_finished_vd: []const u8 = &.{};
    var transcript_before_finished = state.transcript;
    var ee_msg: []const u8 = &.{};
    var cert_msg: []const u8 = &.{};
    var certverify_msg: []const u8 = &.{};
    var t_after_cert: Secret = undefined;
    while (fr.remaining() >= 4) {
        const msg_type = try fr.readU8();
        const msg_len = try fr.readU24();
        const msg_start = fr.pos - 4;
        const msg_body = try fr.readBytes(msg_len);
        switch (msg_type) {
            8 => ee_msg = msg_body, // EncryptedExtensions
            11 => cert_msg = msg_body, // Certificate
            15 => certverify_msg = msg_body, // CertificateVerify
            20 => { // Finished: verify_data covers the transcript before it
                transcript_before_finished = state.transcript;
                server_finished_vd = msg_body;
            },
            else => {},
        }
        state.transcript.update(opened.data[msg_start..fr.pos]);
        if (msg_type == 11) t_after_cert = state.transcript.current(); // CertVerify content = hash(CH..Certificate)
    }

    // CertificateVerify (RFC 8446 4.4.3): the peer signed the transcript with the end-entity cert's
    // private key, proving it holds the cert. This is the authentication binding, the cert CHAIN +
    // hostname trust (RFC 5280 / 6125) is the caller's job (it owns the trust store).
    try verifyCertificateVerify(cert_msg, certverify_msg, t_after_cert);

    // verify the server Finished (RFC 8446 4.4.4).
    const server_finished_key = certificate.finishedKey(server_hs_traffic);
    const expected = certificate.finishedVerifyData(server_finished_key, transcript_before_finished.current());
    if (server_finished_vd.len != key_schedule.hash_length or !std.mem.eql(u8, server_finished_vd, &expected)) {
        return error.ZixServerFinishedMismatch;
    }

    // application key schedule from the transcript through the server Finished.
    const t_full = state.transcript.current();
    const derived_master = key_schedule.deriveSecret(handshake_secret, "derived", empty_hash);
    const master = key_schedule.HkdfSha256.extract(&derived_master, &zero);
    const server_ap = key_schedule.deriveSecret(master, "s ap traffic", t_full);
    const client_ap = key_schedule.deriveSecret(master, "c ap traffic", t_full);

    var conn: ClientConnection = .{ .client_app_key = undefined, .client_app_iv = undefined, .server_app_key = undefined, .server_app_iv = undefined };
    key_schedule.expandLabel(&conn.server_app_key, server_ap, "key", "");
    key_schedule.expandLabel(&conn.server_app_iv, server_ap, "iv", "");
    key_schedule.expandLabel(&conn.client_app_key, client_ap, "key", "");
    key_schedule.expandLabel(&conn.client_app_iv, client_ap, "iv", "");

    // build the client Finished, encrypted under the client handshake key (seq 0).
    const client_finished_key = certificate.finishedKey(client_hs_traffic);
    const client_vd = certificate.finishedVerifyData(client_finished_key, t_full);
    var fin_msg: [4 + key_schedule.hash_length]u8 = undefined;
    fin_msg[0] = 20;
    fin_msg[1] = 0;
    fin_msg[2] = 0;
    fin_msg[3] = key_schedule.hash_length;
    @memcpy(fin_msg[4..], &client_vd);

    const client_finished = record.protect(out, &fin_msg, .HANDSHAKE, client_hs_key, client_hs_iv, 0);

    // surface the server end-entity cert so the caller can chain + hostname validate it. Copy it
    // out of the decrypted flight (a stack buffer that dies with finish), the caller owns the trust.
    const leaf = try leafCertDer(cert_msg);
    if (leaf.len > max_server_cert_der) return error.ZixCertificateTooLarge;

    var result: FinishResult = .{ .client_finished = client_finished, .connection = conn, .alpn = parseSelectedAlpn(ee_msg) };
    @memcpy(result.server_cert[0..leaf.len], leaf);
    result.server_cert_len = leaf.len;

    return result;
}

/// Parse the end-entity (leaf) certificate DER out of a TLS 1.3 Certificate message (RFC 8446 4.4.2):
/// certificate_request_context, then the certificate_list whose first entry is the end-entity cert.
fn leafCertDer(cert_msg: []const u8) ![]const u8 {
    var cr = wire.Reader{ .buf = cert_msg };
    const ctx_len = try cr.readU8();
    _ = try cr.readBytes(ctx_len); // certificate_request_context (empty from the server)
    _ = try cr.readU24(); // certificate_list length
    const cert_len = try cr.readU24();

    return cr.readBytes(cert_len);
}

/// The single ALPN protocol the server selected in EncryptedExtensions (RFC 7301), null when none.
fn parseSelectedAlpn(ee_msg: []const u8) ?Alpn {
    var r = wire.Reader{ .buf = ee_msg };
    const exts_len = r.readU16() catch return null;
    const exts = r.readBytes(exts_len) catch return null;

    var er = wire.Reader{ .buf = exts };
    while (er.remaining() >= 4) {
        const ext_type = er.readU16() catch return null;
        const ext_len = er.readU16() catch return null;
        const ext_data = er.readBytes(ext_len) catch return null;
        if (ext_type != 0x0010) continue;

        var ar = wire.Reader{ .buf = ext_data };
        _ = ar.readU16() catch return null; // ProtocolNameList length
        const name_len = ar.readU8() catch return null;
        const name = ar.readBytes(name_len) catch return null;
        inline for (.{ Alpn.HTTP_1_1, Alpn.H2 }) |cand| {
            if (std.mem.eql(u8, name, cand.token())) return cand;
        }

        return null;
    }

    return null;
}

// --------------------------------------------------------------- //

fn buildClientHello(out: []u8, client_random: [32]u8, client_public: [32]u8, alpn: []const Alpn) []const u8 {
    var w = wire.Writer{ .buf = out };
    w.writeU8(1); // client_hello
    const header = w.placeU24();
    w.writeU16(0x0303); // legacy_version
    w.writeBytes(&client_random);
    w.writeU8(0); // empty legacy_session_id
    w.writeU16(2); // cipher_suites length
    w.writeU16(0x1301); // TLS_AES_128_GCM_SHA256
    w.writeU8(1); // compression methods length
    w.writeU8(0); // null

    const exts = w.placeU16();
    // supported_versions: [0x0304]
    w.writeU16(0x002b);
    w.writeU16(3);
    w.writeU8(2);
    w.writeU16(0x0304);
    // signature_algorithms: [ecdsa_secp256r1_sha256, ed25519]
    w.writeU16(0x000d);
    w.writeU16(6);
    w.writeU16(4);
    w.writeU16(0x0403);
    w.writeU16(0x0807);
    // supported_groups: [x25519]
    w.writeU16(0x000a);
    w.writeU16(4);
    w.writeU16(2);
    w.writeU16(named_group_x25519);
    // key_share: x25519 -> client_public
    w.writeU16(0x0033);
    const ks_ext = w.placeU16();
    const ks_list = w.placeU16();
    w.writeU16(named_group_x25519);
    const ke = w.placeU16();
    w.writeBytes(&client_public);
    w.patchU16(ke);
    w.patchU16(ks_list);
    w.patchU16(ks_ext);
    // ALPN (RFC 7301): offer the protocols, server picks one and echoes it in EncryptedExtensions.
    if (alpn.len > 0) {
        w.writeU16(0x0010);
        const a_ext = w.placeU16();
        const a_list = w.placeU16();
        for (alpn) |protocol| {
            const token = protocol.token();
            w.writeU8(@intCast(token.len));
            w.writeBytes(token);
        }
        w.patchU16(a_list);
        w.patchU16(a_ext);
    }
    w.patchU16(exts);
    w.patchU24(header);

    return w.slice();
}

/// Verify the server CertificateVerify (RFC 8446 4.4.3): the signature over the 4.4.3 content, made
/// with the end-entity certificate's private key. Supports ecdsa_secp256r1_sha256 (0x0403, DER sig)
/// and ed25519 (0x0807, 64-byte raw sig), matching the schemes the ClientHello offers. The cert is
/// parsed with std.crypto.Certificate to lift the public key.
fn verifyCertificateVerify(cert_msg: []const u8, certverify_msg: []const u8, transcript_hash: Secret) !void {
    // end-entity cert DER from the TLS 1.3 Certificate message (RFC 8446 4.4.2).
    const cert_der = try leafCertDer(cert_msg);

    // signature: SignatureScheme + opaque<0..2^16-1>.
    var vr = wire.Reader{ .buf = certverify_msg };
    const scheme = try vr.readU16();
    const sig_len = try vr.readU16();
    const sig_bytes = try vr.readBytes(sig_len);

    const cert = std.crypto.Certificate{ .buffer = cert_der, .index = 0 };
    const parsed = try cert.parse();

    var content_buf: [256]u8 = undefined;
    const content = certificate.certificateVerifyContent(&content_buf, transcript_hash);

    switch (scheme) {
        0x0403 => { // ecdsa_secp256r1_sha256
            const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
            const pub_key = try EcdsaP256.PublicKey.fromSec1(parsed.pubKey());
            const sig = try EcdsaP256.Signature.fromDer(sig_bytes);
            try sig.verify(content, pub_key);
        },
        0x0807 => { // ed25519
            const Ed25519 = std.crypto.sign.Ed25519;
            if (sig_bytes.len != Ed25519.Signature.encoded_length) return error.InvalidSignature;
            const pub_raw = parsed.pubKey();
            if (pub_raw.len != 32) return error.ZixUnsupportedSignatureScheme;

            const pub_key = try Ed25519.PublicKey.fromBytes(pub_raw[0..32].*);
            const sig = Ed25519.Signature.fromBytes(sig_bytes[0..64].*);
            try sig.verify(content, pub_key);
        },
        else => return error.ZixUnsupportedSignatureScheme,
    }
}

const ServerHelloParsed = struct { server_random: [32]u8, server_public: [32]u8 };

fn parseServerHello(sh_msg: []const u8) !ServerHelloParsed {
    var hr = wire.Reader{ .buf = sh_msg };
    if (try hr.readU8() != 2) return error.ZixNotServerHello;
    _ = try hr.readU24();
    _ = try hr.readU16(); // legacy_version
    var out: ServerHelloParsed = undefined;
    @memcpy(&out.server_random, try hr.readBytes(32));
    const sid_len = try hr.readU8();
    _ = try hr.readBytes(sid_len);
    _ = try hr.readU16(); // cipher
    _ = try hr.readU8(); // compression
    const ext_len = try hr.readU16();
    const exts = try hr.readBytes(ext_len);

    var er = wire.Reader{ .buf = exts };
    while (er.remaining() >= 4) {
        const ext_type = try er.readU16();
        const el = try er.readU16();
        const ed = try er.readBytes(el);
        if (ext_type == 0x0033) { // key_share
            var kr = wire.Reader{ .buf = ed };
            _ = try kr.readU16(); // group
            const ke_len = try kr.readU16();
            @memcpy(&out.server_public, try kr.readBytes(ke_len));

            return out;
        }
    }

    return error.ZixNoServerKeyShare;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

// the example ECDSA P-256 fixture (examples/certs/ecdsa_p256_cert.pem), self-signed,
// CN=localhost / SAN DNS:localhost, key scalar 0b76f7...d32c. Its public key matches that scalar,
// so the server's CertificateVerify verifies against it.
const fixture_cert_hex = "308201d43082017ba00302010202147a26ee491f091ac7c914f4a810c1ece713402574300a06082a8648ce3d040302302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f63301e170d3236303632323132353432305a170d3336303631393132353432305a302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f633059301306072a8648ce3d020106082a8648ce3d03010703420004c2a0121b298ac9cd389200e78d94e7bde1cc7cd8074795fab4f919799d40fdc231c5a90990ac8c6166ae472f33f74fced097f2edb7b8a1974be66a4ab07f253ba37f307d301d0603551d0e04160414c34e1d0a36a43947709b539e16dd0213aa4196aa301f0603551d23041830168014c34e1d0a36a43947709b539e16dd0213aa4196aa300f0603551d130101ff040530030101ff301a0603551d110413301182096c6f63616c686f737487047f000001300e0603551d0f0101ff040403020780300a06082a8648ce3d040302034700304402200b012f119db9b95d990bc482cb63e8f81e337a08634904e4caf513dc10c8aa8302202fdfe79ff6d5403e753ddf2aa52671923b8a2c28126bcbf196bd6fb7ecbcb14e";

test "zix tls: client, 1.3 handshake against the zix server (in-memory round trip)" {
    const connection = @import("connection.zig");
    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

    var skey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&skey, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const server_key = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(skey));
    var cert_buf: [512]u8 = undefined;
    const cert_der = try std.fmt.hexToBytes(&cert_buf, fixture_cert_hex);

    // client phase 1 (offering ALPN h2).
    var ch_buf: [512]u8 = undefined;
    const started = try start(.{ .client_random = @splat(0x11), .ephemeral_secret = @splat(0x42), .alpn = &.{.H2} }, &ch_buf);
    var state = started.state;

    // the zix server responds (the byte-exact RFC 8448 oracle), signing with the fixture key.
    var srv_out: [4096]u8 = undefined;
    var server = try connection.serverHandshake(.{
        .certificate_chain = &.{cert_der},
        .signing_key = .{ .ecdsa_p256 = server_key },
        .ephemeral_secret = @splat(0x99),
        .server_random = @splat(0x55),
        .alpn_prefs = &.{.H2},
    }, started.client_hello, &srv_out);

    // client phase 2: verifies the server Finished, parses the selected ALPN, produces its own.
    var fin_buf: [128]u8 = undefined;
    var finished = try finish(&state, server.to_send, &fin_buf);
    try std.testing.expectEqual(Alpn.H2, finished.alpn.?);

    // finish surfaces the server end-entity cert, and the caller trusts it (RFC 5280 / 6125).
    try std.testing.expectEqualSlices(u8, cert_der, finished.serverCertDer());
    const now_sec: i64 = 1_800_000_000; // ~2027-01, inside the fixture validity window
    try finished.verifyServerCert(cert_der, "localhost", now_sec); // self-signed: anchor is the leaf

    // the server must accept the client Finished.
    try server.connection.verifyClientFinished(finished.client_finished);

    // application data both directions.
    var c2s_buf: [256]u8 = undefined;
    const c2s = finished.connection.writeAppData("ping from client", &c2s_buf);
    var s_in: [256]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "ping from client", try server.connection.readAppData(c2s, &s_in));

    var s2c_buf: [256]u8 = undefined;
    const s2c = server.connection.writeAppData("pong from server", &s2c_buf);
    var c_in: [256]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "pong from server", try finished.connection.readAppData(s2c, &c_in));
}

test "zix tls: client, verifyServerCert trusts a good cert and rejects bad host / expiry / anchor" {
    // Drive the trust step through FinishResult.verifyServerCert, the API the request path uses.
    // The fixture is self-signed (CA:TRUE), so the anchor is the leaf itself, out-of-band.
    var cert_buf: [512]u8 = undefined;
    const cert_der = try std.fmt.hexToBytes(&cert_buf, fixture_cert_hex);

    var result: FinishResult = .{ .client_finished = &.{}, .connection = undefined };
    @memcpy(result.server_cert[0..cert_der.len], cert_der);
    result.server_cert_len = cert_der.len;

    const now_sec: i64 = 1_800_000_000; // ~2027-01, inside notBefore (Jun 2026) .. notAfter (Jun 2036)
    try result.verifyServerCert(cert_der, "localhost", now_sec); // trusted + SAN DNS:localhost

    // wrong hostname (RFC 6125), outside the validity window (RFC 5280), and an empty cert all reject.
    try std.testing.expectError(error.CertificateHostMismatch, result.verifyServerCert(cert_der, "evil.example", now_sec));
    try std.testing.expectError(error.CertificateNotYetValid, result.verifyServerCert(cert_der, "localhost", 1_700_000_000));

    var empty: FinishResult = .{ .client_finished = &.{}, .connection = undefined };
    try std.testing.expectError(error.ZixNoServerCertificate, empty.verifyServerCert(cert_der, "localhost", now_sec));
}

// --------------------------------------------------------------- //
// real-fd integration: the sans-I/O client driven over a socketpair against the zix server.

fn readRecordFd(fd: std.posix.fd_t, buf: []u8) ![]const u8 {
    try readExactFd(fd, buf[0..5]);
    const len = std.mem.readInt(u16, buf[3..5], .big);
    try readExactFd(fd, buf[5 .. 5 + len]);

    return buf[0 .. 5 + len];
}

fn readExactFd(fd: std.posix.fd_t, buf: []u8) !void {
    const linux = std.os.linux;
    var n: usize = 0;
    while (n < buf.len) {
        const rc = linux.read(fd, buf[n..].ptr, buf.len - n);
        if (std.posix.errno(rc) != .SUCCESS) return error.ReadFailed;
        if (rc == 0) return error.ZixEof;
        n += rc;
    }
}

fn writeAllFD(fd: std.posix.fd_t, bytes: []const u8) !void {
    const linux = std.os.linux;
    var n: usize = 0;
    while (n < bytes.len) {
        const rc = linux.write(fd, bytes[n..].ptr, bytes.len - n);
        if (std.posix.errno(rc) != .SUCCESS) return error.WriteFailed;
        n += rc;
    }
}

test "zix tls: client over a socketpair (real fds, full https/1.1 request)" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("this test drives a Linux socket wire, test skipped", .{});
        return;
    }

    const connection = @import("connection.zig");
    const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const linux = std.os.linux;

    var skey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&skey, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const server_key = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(skey));
    var cert_buf: [512]u8 = undefined;
    const cert_der = try std.fmt.hexToBytes(&cert_buf, fixture_cert_hex);

    var pair: [2]std.posix.fd_t = undefined;
    try std.testing.expect(std.posix.errno(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &pair)) == .SUCCESS);
    const client_fd = pair[0];
    const server_fd = pair[1];
    defer _ = linux.close(client_fd);

    const ServerCtx = struct { fd: std.posix.fd_t, key: EcdsaP256.KeyPair, cert: []const u8 };
    const Srv = struct {
        fn run(ctx: ServerCtx) void {
            serveOnce(ctx) catch {};
            _ = linux.close(ctx.fd);
        }
        fn serveOnce(ctx: ServerCtx) !void {
            var buf: [4096]u8 = undefined;
            const ch = try readRecordFd(ctx.fd, &buf);
            var out: [4096]u8 = undefined;
            var res = try connection.serverHandshake(.{
                .certificate_chain = &.{ctx.cert},
                .signing_key = .{ .ecdsa_p256 = ctx.key },
                .ephemeral_secret = @splat(0x99),
                .server_random = @splat(0x55),
            }, ch[5..], &out);
            try writeAllFD(ctx.fd, res.to_send);

            var cf_buf: [256]u8 = undefined;
            const cf = try readRecordFd(ctx.fd, &cf_buf);
            try res.connection.verifyClientFinished(cf);

            var req_buf: [4096]u8 = undefined;
            const req_rec = try readRecordFd(ctx.fd, &req_buf);
            var req_plain: [4096]u8 = undefined;
            _ = try res.connection.readAppData(req_rec, &req_plain);

            var enc: [4096]u8 = undefined;
            try writeAllFD(ctx.fd, res.connection.writeAppData("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi", &enc));
        }
    };
    const t = try std.Thread.spawn(.{}, Srv.run, .{ServerCtx{ .fd = server_fd, .key = server_key, .cert = cert_der }});
    defer t.join();

    // client: ClientHello wrapped in a plaintext handshake record.
    var ch_buf: [512]u8 = undefined;
    const started = try start(.{ .client_random = @splat(0x11), .ephemeral_secret = @splat(0x42) }, &ch_buf);
    var state = started.state;

    var ch_rec: [600]u8 = undefined;
    ch_rec[0] = 22;
    std.mem.writeInt(u16, ch_rec[1..3], 0x0303, .big);
    std.mem.writeInt(u16, ch_rec[3..5], @intCast(started.client_hello.len), .big);
    @memcpy(ch_rec[5 .. 5 + started.client_hello.len], started.client_hello);
    try writeAllFD(client_fd, ch_rec[0 .. 5 + started.client_hello.len]);

    // read the server flight: ServerHello + ChangeCipherSpec + the encrypted flight (3 records).
    var flight_buf: [4096]u8 = undefined;
    var flen: usize = 0;
    for (0..3) |_| {
        const rec = try readRecordFd(client_fd, flight_buf[flen..]);
        flen += rec.len;
    }

    var fin_buf: [256]u8 = undefined;
    var finished = try finish(&state, flight_buf[0..flen], &fin_buf);
    try writeAllFD(client_fd, finished.client_finished);

    // send the request, read the response.
    var req_enc: [256]u8 = undefined;
    try writeAllFD(client_fd, finished.connection.writeAppData("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", &req_enc));

    var resp_rec: [4096]u8 = undefined;
    const resp = try readRecordFd(client_fd, &resp_rec);
    var resp_plain: [4096]u8 = undefined;
    const response = try finished.connection.readAppData(resp, &resp_plain);
    try std.testing.expect(std.mem.indexOf(u8, response, "200 OK") != null);
}
