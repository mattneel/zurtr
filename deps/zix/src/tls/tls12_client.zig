//! zix TLS 1.2 client handshake (RFC 5246 + 5288, ECDHE-ECDSA): the mirror of tls12_connection
//! (server). Sans-I/O: `start` builds the ClientHello, `finish` consumes the server flight 1
//! (ServerHello + Certificate + ServerKeyExchange + ServerHelloDone), verifies the ServerKeyExchange
//! signature with the end-entity cert key, derives the keys, and produces the client flight
//! (ClientKeyExchange + ChangeCipherSpec + the encrypted client Finished) + the expected server
//! Finished verify_data + a ClientConnection. Reuses tls12_prf + tls12_record + std X.509.
//!
//! Note: `finish` does the handshake binding (the SKE signature) and surfaces the server end-entity
//! certificate, the caller chain + hostname validates it (RFC 5280 / 6125) through
//! FinishResult.verifyServerCert against its trust store, the same split as the 1.3 client.

const std = @import("std");
const wire = @import("wire.zig");
const prf = @import("tls12_prf.zig");
const record = @import("tls12_record.zig");
const cert_verify = @import("cert_verify.zig");
const max_server_cert_der = @import("client.zig").max_server_cert_der;

const P256 = std.crypto.ecc.P256;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

const cipher_ecdhe_ecdsa_aes128_gcm: u16 = 0xC02B;
const named_curve_secp256r1: u16 = 0x0017;
const sig_ecdsa_secp256r1_sha256: u16 = 0x0403;
const version_tls_1_2: u16 = 0x0303;

pub const HandshakeOptions = struct {
    client_random: [32]u8,
    /// secp256r1 ephemeral seed (reduced to a scalar internally).
    ephemeral_secret: [32]u8,
};

pub const State = struct {
    ephemeral_scalar: [32]u8,
    client_random: [32]u8,
    transcript: Sha256,
};

pub const StartResult = struct {
    client_hello: []const u8,
    state: State,
};

pub const FinishResult = struct {
    /// ClientKeyExchange + ChangeCipherSpec + the encrypted client Finished, to send to the server.
    to_send: []const u8,
    connection: ClientConnection,
    /// the server Finished verify_data the client expects, check it against the server's Finished.
    expected_server_finished: [12]u8,
    /// the server end-entity certificate (DER), copied out of the flight. Read it through
    /// serverCertDer(), trust it through verifyServerCert().
    server_cert: [max_server_cert_der]u8 = undefined,
    server_cert_len: usize = 0,

    /// The server end-entity certificate DER. Empty when the server sent no Certificate.
    pub fn serverCertDer(self: *const FinishResult) []const u8 {
        return self.server_cert[0..self.server_cert_len];
    }

    /// Trust the server certificate: chain it to `anchor_der` within its validity window (RFC 5280)
    /// and match `hostname` against its SAN (RFC 6125). finish() already proved the peer holds the
    /// cert key (the ServerKeyExchange signature), this is the remaining chain + identity step the
    /// caller owns. See the 1.3 client verifyServerCert for the self-signed anchor note.
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

/// Post-handshake keys + sequence numbers (both at 1, after the seq-0 Finished). The client writes
/// under the client key and reads under the server's.
pub const ClientConnection = struct {
    km: prf.KeyMaterial,
    client_seq: u64 = 1,
    server_seq: u64 = 1,

    pub fn writeAppData(self: *ClientConnection, plaintext: []const u8, out: []u8) []const u8 {
        const rec = record.protect(out, plaintext, 23, self.km.client_write_key, self.km.client_write_iv, self.client_seq);
        self.client_seq += 1;

        return rec;
    }

    pub fn readAppData(self: *ClientConnection, rec: []const u8, out: []u8) record.Error![]const u8 {
        const plain = try record.deprotect(out, rec, self.km.server_write_key, self.km.server_write_iv, self.server_seq);
        self.server_seq += 1;

        return plain;
    }

    /// Verify the server Finished record (encrypted under the server key, seq 0, before app data).
    pub fn verifyServerFinished(self: *const ClientConnection, finished_record: []const u8, expected: [12]u8) !void {
        var plain: [64]u8 = undefined;
        const msg = try record.deprotect(&plain, finished_record, self.km.server_write_key, self.km.server_write_iv, 0);
        if (msg.len < 16 or msg[0] != 20) return error.ZixUnexpectedMessage;
        if (!std.mem.eql(u8, msg[4..16], &expected)) return error.ZixServerFinishedMismatch;
    }
};

// --------------------------------------------------------------- //

fn p256Scalar(seed: [32]u8) [32]u8 {
    var wide: [48]u8 = std.mem.zeroes([48]u8);
    @memcpy(wide[16..48], &seed);

    return P256.scalar.Scalar.fromBytes48(wide, .big).toBytes(.big);
}

/// Phase 1: build the TLS 1.2 ClientHello (ECDHE-ECDSA-AES128-GCM, secp256r1) and start the transcript.
pub fn start(opts: HandshakeOptions, out: []u8) StartResult {
    var w = wire.Writer{ .buf = out };
    w.writeU8(1); // client_hello
    const header = w.placeU24();
    w.writeU16(version_tls_1_2);
    w.writeBytes(&opts.client_random);
    w.writeU8(0); // empty session_id
    w.writeU16(2); // cipher_suites length
    w.writeU16(cipher_ecdhe_ecdsa_aes128_gcm);
    w.writeU8(1); // compression methods length
    w.writeU8(0); // null

    const exts = w.placeU16();
    // signature_algorithms: [ecdsa_secp256r1_sha256]
    w.writeU16(0x000d);
    w.writeU16(4);
    w.writeU16(2);
    w.writeU16(sig_ecdsa_secp256r1_sha256);
    // supported_groups: [secp256r1]
    w.writeU16(0x000a);
    w.writeU16(4);
    w.writeU16(2);
    w.writeU16(named_curve_secp256r1);
    // ec_point_formats: uncompressed
    w.writeU16(0x000b);
    w.writeU16(2);
    w.writeU8(1);
    w.writeU8(0);
    w.patchU16(exts);
    w.patchU24(header);

    const client_hello = w.slice();

    var state = State{ .ephemeral_scalar = p256Scalar(opts.ephemeral_secret), .client_random = opts.client_random, .transcript = Sha256.init(.{}) };
    state.transcript.update(client_hello);

    return .{ .client_hello = client_hello, .state = state };
}

/// Phase 2: process the server flight, verify the ServerKeyExchange signature, and produce the
/// client flight + the expected server Finished.
pub fn finish(state: *State, server_flight1: []const u8, out: []u8) !FinishResult {
    // the flight is one handshake record carrying SH + Certificate + ServerKeyExchange + ServerHelloDone.
    var rr = wire.Reader{ .buf = server_flight1 };
    if (try rr.readU8() != 22) return error.ZixUnexpectedRecord;
    _ = try rr.readU16();
    const body_len = try rr.readU16();
    const body = try rr.readBytes(body_len);
    state.transcript.update(body);

    const parsed = try parseFlight1(body);
    try verifyServerKeyExchange(parsed.cert_der, state.client_random, parsed.server_random, parsed.ske_params, parsed.ske_sig);

    // ECDHE -> pre_master -> master_secret -> key material.
    const client_point = (try P256.basePoint.mul(state.ephemeral_scalar, .big)).toUncompressedSec1();
    const server_point = try P256.fromSec1(parsed.server_point);
    const pre_master = (try server_point.mul(state.ephemeral_scalar, .big)).affineCoordinates().x.toBytes(.big);
    const master = prf.masterSecret(&pre_master, state.client_random, parsed.server_random);
    const km = prf.keyMaterial(master, state.client_random, parsed.server_random);

    // ClientKeyExchange (handshake message), folded into the transcript.
    var cke_msg: [4 + 1 + 65]u8 = undefined;
    cke_msg[0] = 16;
    cke_msg[1] = 0;
    cke_msg[2] = 0;
    cke_msg[3] = 1 + 65;
    cke_msg[4] = 65;
    @memcpy(cke_msg[5..], &client_point);
    state.transcript.update(&cke_msg);

    // client Finished verify_data over CH..CKE.
    const client_vd = prf.finishedFromHash(master, "client finished", transcriptHash(state));
    var cf_msg: [16]u8 = undefined;
    cf_msg[0] = 20;
    cf_msg[1] = 0;
    cf_msg[2] = 0;
    cf_msg[3] = 12;
    @memcpy(cf_msg[4..16], &client_vd);
    state.transcript.update(&cf_msg);

    // the server Finished the client will expect, over CH..clientFinished.
    const expected_server = prf.finishedFromHash(master, "server finished", transcriptHash(state));

    // wire: ClientKeyExchange (plaintext) + ChangeCipherSpec + the encrypted client Finished.
    var w = wire.Writer{ .buf = out };
    w.writeU8(22);
    w.writeU16(version_tls_1_2);
    w.writeU16(cke_msg.len);
    w.writeBytes(&cke_msg);
    w.writeU8(20); // change_cipher_spec
    w.writeU16(version_tls_1_2);
    w.writeU16(1);
    w.writeU8(1);
    const fin_rec = record.protect(out[w.len..], &cf_msg, 22, km.client_write_key, km.client_write_iv, 0);
    const total = w.len + fin_rec.len;

    // surface the server end-entity cert so the caller can chain + hostname validate it (RFC 5280 / 6125).
    if (parsed.cert_der.len > max_server_cert_der) return error.ZixCertificateTooLarge;

    var result: FinishResult = .{ .to_send = out[0..total], .connection = .{ .km = km }, .expected_server_finished = expected_server };
    @memcpy(result.server_cert[0..parsed.cert_der.len], parsed.cert_der);
    result.server_cert_len = parsed.cert_der.len;

    return result;
}

fn transcriptHash(state: *const State) [32]u8 {
    var copy = state.transcript;
    var hash: [32]u8 = undefined;
    copy.final(&hash);

    return hash;
}

const Flight1 = struct {
    server_random: [32]u8,
    server_point: []const u8,
    cert_der: []const u8,
    ske_params: []const u8,
    ske_sig: []const u8,
};

fn parseFlight1(body: []const u8) !Flight1 {
    var out: Flight1 = undefined;
    var r = wire.Reader{ .buf = body };
    while (r.remaining() >= 4) {
        const msg_type = try r.readU8();
        const msg_len = try r.readU24();
        const msg = try r.readBytes(msg_len);
        switch (msg_type) {
            2 => @memcpy(&out.server_random, msg[2..34]), // ServerHello: skip version, take random
            11 => { // Certificate (1.2 has no certificate_request_context, unlike 1.3): end-entity DER
                var cr = wire.Reader{ .buf = msg };
                _ = try cr.readU24(); // certificate_list length
                const cert_len = try cr.readU24();
                out.cert_der = try cr.readBytes(cert_len);
            },
            12 => { // ServerKeyExchange: curve_type + named_curve + point + sig
                const point_len = msg[3];
                out.ske_params = msg[0 .. 4 + point_len];
                out.server_point = msg[4 .. 4 + point_len];
                var sr = wire.Reader{ .buf = msg[4 + point_len ..] };
                _ = try sr.readU16(); // signature scheme
                const sig_len = try sr.readU16();
                out.ske_sig = try sr.readBytes(sig_len);
            },
            else => {},
        }
    }

    return out;
}

/// Verify the ServerKeyExchange ECDSA signature over client_random ++ server_random ++ params,
/// made with the end-entity cert key (RFC 5246 7.4.3). The handshake binding for 1.2.
fn verifyServerKeyExchange(cert_der: []const u8, client_random: [32]u8, server_random: [32]u8, params: []const u8, sig_der: []const u8) !void {
    const cert = std.crypto.Certificate{ .buffer = cert_der, .index = 0 };
    const parsed = try cert.parse();
    const pub_key = try EcdsaP256.PublicKey.fromSec1(parsed.pubKey());

    var signed: [32 + 32 + 128]u8 = undefined;
    @memcpy(signed[0..32], &client_random);
    @memcpy(signed[32..64], &server_random);
    @memcpy(signed[64 .. 64 + params.len], params);
    const sig = try EcdsaP256.Signature.fromDer(sig_der);
    try sig.verify(signed[0 .. 64 + params.len], pub_key);
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

// the example ECDSA P-256 fixture (key scalar 0b76f7...d32c), self-signed CN=localhost.
const fixture_cert_hex = "308201d43082017ba00302010202147a26ee491f091ac7c914f4a810c1ece713402574300a06082a8648ce3d040302302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f63301e170d3236303632323132353432305a170d3336303631393132353432305a302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f633059301306072a8648ce3d020106082a8648ce3d03010703420004c2a0121b298ac9cd389200e78d94e7bde1cc7cd8074795fab4f919799d40fdc231c5a90990ac8c6166ae472f33f74fced097f2edb7b8a1974be66a4ab07f253ba37f307d301d0603551d0e04160414c34e1d0a36a43947709b539e16dd0213aa4196aa301f0603551d23041830168014c34e1d0a36a43947709b539e16dd0213aa4196aa300f0603551d130101ff040530030101ff301a0603551d110413301182096c6f63616c686f737487047f000001300e0603551d0f0101ff040403020780300a06082a8648ce3d040302034700304402200b012f119db9b95d990bc482cb63e8f81e337a08634904e4caf513dc10c8aa8302202fdfe79ff6d5403e753ddf2aa52671923b8a2c28126bcbf196bd6fb7ecbcb14e";

test "zix tls: tls12 client, ECDHE-ECDSA handshake against the zix 1.2 server (in-memory)" {
    const server = @import("tls12_connection.zig");

    var skey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&skey, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const server_key = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(skey));
    var cert_buf: [512]u8 = undefined;
    const cert_der = try std.fmt.hexToBytes(&cert_buf, fixture_cert_hex);

    // client phase 1.
    var ch_buf: [256]u8 = undefined;
    const started = start(.{ .client_random = @splat(0x11), .ephemeral_secret = @splat(0x42) }, &ch_buf);
    var cstate = started.state;

    // server flight 1.
    var s1_buf: [4096]u8 = undefined;
    const flight1 = try server.serverFlight1(.{
        .certificate_der = cert_der,
        .signing_key = server_key,
        .server_eph_secret = @splat(0x22),
        .server_random = @splat(0x33),
    }, started.client_hello, &s1_buf);
    var sstate = flight1.state;

    // client finish: verify SKE, produce CKE + CCS + client Finished.
    var cfin_buf: [512]u8 = undefined;
    const cfin = try finish(&cstate, flight1.to_send, &cfin_buf);

    // finish surfaces the server cert, and the caller trusts it (RFC 5280 / 6125).
    try std.testing.expectEqualSlices(u8, cert_der, cfin.serverCertDer());
    const now_sec: i64 = 1_800_000_000; // ~2027-01, inside the fixture validity window
    try cfin.verifyServerCert(cert_der, "localhost", now_sec); // self-signed: anchor is the leaf
    try std.testing.expectError(error.CertificateHostMismatch, cfin.verifyServerCert(cert_der, "evil.example", now_sec));

    // parse the client's wire output: CKE message + the client Finished record.
    var pr = wire.Reader{ .buf = cfin.to_send };
    _ = try pr.readU8(); // 22
    _ = try pr.readU16();
    const cke_len = try pr.readU16();
    const cke_msg = try pr.readBytes(cke_len);
    _ = try pr.readU8(); // CCS type
    _ = try pr.readU16();
    const ccs_len = try pr.readU16();
    _ = try pr.readBytes(ccs_len);
    const fin_record = cfin.to_send[pr.pos..];

    // server finish: consumes CKE + client Finished, produces CCS + server Finished.
    var s2_buf: [256]u8 = undefined;
    var sfin = try server.serverFinish(&sstate, cke_msg, fin_record, &s2_buf);

    // client verifies the server Finished (skip the 6-byte CCS).
    try cfin.connection.verifyServerFinished(sfin.to_send[6..], cfin.expected_server_finished);

    // application data round trip.
    var c2s_buf: [256]u8 = undefined;
    var conn = cfin.connection;
    const c2s = conn.writeAppData("ping over tls 1.2", &c2s_buf);
    var s_in: [256]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "ping over tls 1.2", try sfin.connection.readAppData(c2s, &s_in));

    var s2c_buf: [256]u8 = undefined;
    const s2c = sfin.connection.writeAppData("pong over tls 1.2", &s2c_buf);
    var c_in: [256]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "pong over tls 1.2", try conn.readAppData(s2c, &c_in));
}
