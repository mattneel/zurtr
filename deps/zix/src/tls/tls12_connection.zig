//! TLS 1.2 server handshake (RFC 5246 + 5288, ECDHE-ECDSA, AES-128-GCM). Sans-I/O, two phases:
//!   - serverFlight1: consume ClientHello, emit ServerHello + Certificate + ServerKeyExchange +
//!     ServerHelloDone (plaintext), and return the State (randoms, server ephemeral, running
//!     transcript) needed to finish.
//!   - serverFinish: consume ClientKeyExchange + the encrypted client Finished, derive the keys,
//!     verify the client Finished, emit ChangeCipherSpec + the encrypted server Finished, and
//!     return the post-handshake Connection.
//! Composes the verified blocks: tls12_prf (key schedule), tls12_record (AEAD), tls12_version
//! (downgrade sentinel), plus secp256r1 ECDHE and an ECDSA-signed ServerKeyExchange. The 1.3 path
//! (connection.zig) is untouched. Cross-version branch + serve-loop wiring land separately, and the
//! RFC wire-correctness is gated by an openssl -tls1_2 cross-check (verify-tls12.md), not this file.

const std = @import("std");
const wire = @import("wire.zig");
const handshake = @import("handshake.zig");
const prf = @import("tls12_prf.zig");
const record = @import("tls12_record.zig");
const version = @import("tls12_version.zig");
const extensions = @import("extensions.zig");

const Alpn = extensions.Alpn;

const P256 = std.crypto.ecc.P256;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

const cipher_ecdhe_ecdsa_aes128_gcm: u16 = 0xC02B;
const named_curve_secp256r1: u16 = 0x0017;
const sig_ecdsa_secp256r1_sha256: u16 = 0x0403;

const hs_server_hello: u8 = 2;
const hs_certificate: u8 = 11;
const hs_server_key_exchange: u8 = 12;
const hs_server_hello_done: u8 = 14;
const hs_client_key_exchange: u8 = 16;
const hs_finished: u8 = 20;

const content_handshake: u8 = 22;
const version_tls_1_2: u16 = 0x0303;

/// Caller-supplied identity + per-connection randomness (fresh in production, fixed in tests).
pub const HandshakeOptions = struct {
    certificate_der: []const u8,
    signing_key: EcdsaP256.KeyPair,
    server_eph_secret: [32]u8,
    server_random: [32]u8,
    /// Server ALPN prefs (RFC 7301). Empty = no ALPN. h2-over-TLS needs .H2 here (RFC 7540 3.3).
    alpn_prefs: []const Alpn = &.{},
};

/// Carried from flight 1 into finish: the randoms, the server ephemeral scalar, and the running
/// handshake transcript hash.
pub const State = struct {
    client_random: [32]u8,
    server_random: [32]u8,
    server_eph_scalar: [32]u8,
    transcript: Sha256,
    /// ALPN selected from the client offer + server prefs, null when ALPN was not used. The engine
    /// dispatches on this (h2 vs http/1.1).
    alpn: ?Alpn = null,
};

pub const Flight1 = struct {
    to_send: []const u8,
    state: State,
};

pub const FinishResult = struct {
    to_send: []const u8,
    connection: Connection,
};

/// Post-handshake keys + per-direction sequence numbers (both start at 1, after the seq-0 Finished).
pub const Connection = struct {
    km: prf.KeyMaterial,
    server_seq: u64 = 1,
    client_seq: u64 = 1,

    pub fn writeAppData(self: *Connection, plaintext: []const u8, out: []u8) []const u8 {
        const rec = record.protect(out, plaintext, 23, self.km.server_write_key, self.km.server_write_iv, self.server_seq);
        self.server_seq += 1;

        return rec;
    }

    pub fn readAppData(self: *Connection, rec: []const u8, out: []u8) record.Error![]const u8 {
        const plain = try record.deprotect(out, rec, self.km.client_write_key, self.km.client_write_iv, self.client_seq);
        self.client_seq += 1;

        return plain;
    }

    /// Emit an encrypted close_notify alert (level warning(1), close_notify(0)) under the server key
    /// so the peer sees a clean shutdown (RFC 5246 7.2.1), content_type alert(21).
    pub fn closeNotify(self: *Connection, out: []u8) []const u8 {
        const rec = record.protect(out, &[_]u8{ 1, 0 }, 21, self.km.server_write_key, self.km.server_write_iv, self.server_seq);
        self.server_seq += 1;

        return rec;
    }
};

// --------------------------------------------------------------- //

fn reduceP256Scalar(seed: [32]u8) [32]u8 {
    var wide: [48]u8 = std.mem.zeroes([48]u8);
    @memcpy(wide[16..48], &seed);

    return P256.scalar.Scalar.fromBytes48(wide, .big).toBytes(.big);
}

fn ecdheSharedX(my_scalar: [32]u8, peer_public: []const u8) ![32]u8 {
    const peer = try P256.fromSec1(peer_public);
    const shared = try peer.mul(my_scalar, .big);

    return shared.affineCoordinates().x.toBytes(.big);
}

/// Phase 1: ClientHello -> ServerHello + Certificate + ServerKeyExchange + ServerHelloDone, as one
/// plaintext handshake record. The downgrade sentinel is planted when the client was 1.3-capable.
pub fn serverFlight1(opts: HandshakeOptions, client_hello: []const u8, out: []u8) !Flight1 {
    const parsed = handshake.parseClientHello(client_hello);
    if (parsed != .ok) return error.ZixClientHelloInvalid;
    const hello = parsed.ok;

    var state: State = undefined;
    state.client_random = hello.random;
    state.server_random = opts.server_random;
    if (hello.offers_tls13) version.applyDowngradeSentinel(&state.server_random, .TLS_1_2);
    state.server_eph_scalar = reduceP256Scalar(opts.server_eph_secret);
    state.transcript = Sha256.init(.{});
    state.transcript.update(client_hello);

    // ALPN: select one protocol when the server has prefs and the client offered a list.
    state.alpn = null;
    if (opts.alpn_prefs.len > 0) {
        if (hello.alpn) |client_alpn| state.alpn = extensions.negotiateAlpn(client_alpn, opts.alpn_prefs);
    }

    const server_point = (try P256.basePoint.mul(state.server_eph_scalar, .big)).toUncompressedSec1();

    var w = wire.Writer{ .buf = out };
    w.writeU8(content_handshake);
    w.writeU16(version_tls_1_2);
    const rec_len = w.placeU16();
    const body_start = w.len;

    writeServerHello(&w, state.server_random, hello.session_id, state.alpn);
    writeCertificate(&w, opts.certificate_der);
    try writeServerKeyExchange(&w, opts.signing_key, state.client_random, state.server_random, &server_point);
    w.writeU8(hs_server_hello_done);
    w.writeU24(0);

    state.transcript.update(w.buf[body_start..w.len]);
    w.patchU16(rec_len);

    return .{ .to_send = w.slice(), .state = state };
}

fn writeServerHello(writer: *wire.Writer, server_random: [32]u8, session_id: []const u8, alpn: ?Alpn) void {
    writer.writeU8(hs_server_hello);
    const header = writer.placeU24();

    writer.writeU16(version_tls_1_2);
    writer.writeBytes(&server_random);
    writer.writeU8(@intCast(session_id.len));
    writer.writeBytes(session_id);
    writer.writeU16(cipher_ecdhe_ecdsa_aes128_gcm);
    writer.writeU8(0); // null compression

    // ServerHello extensions openssl expects for a 1.2 ECDHE handshake.
    const exts = writer.placeU16();
    // renegotiation_info (RFC 5746): empty renegotiated_connection on the initial handshake.
    writer.writeU16(0xff01);
    writer.writeU16(1);
    writer.writeU8(0);
    // ec_point_formats (RFC 8422 5.1.2): uncompressed only.
    writer.writeU16(0x000b);
    writer.writeU16(2);
    writer.writeU8(1);
    writer.writeU8(0);
    // ALPN (RFC 7301): the one selected protocol, when negotiated (h2 for HTTP/2 over TLS).
    if (alpn) |protocol| {
        writer.writeU16(0x0010);
        const ext = writer.placeU16();
        const list = writer.placeU16();
        const token = protocol.token();
        writer.writeU8(@intCast(token.len));
        writer.writeBytes(token);
        writer.patchU16(list);
        writer.patchU16(ext);
    }
    writer.patchU16(exts);

    writer.patchU24(header);
}

fn writeCertificate(writer: *wire.Writer, der: []const u8) void {
    writer.writeU8(hs_certificate);
    const header = writer.placeU24();
    const list = writer.placeU24();
    const cert = writer.placeU24();

    writer.writeBytes(der);

    writer.patchU24(cert);
    writer.patchU24(list);
    writer.patchU24(header);
}

fn writeServerKeyExchange(writer: *wire.Writer, key: EcdsaP256.KeyPair, client_random: [32]u8, server_random: [32]u8, point: []const u8) !void {
    writer.writeU8(hs_server_key_exchange);
    const header = writer.placeU24();
    const params_start = writer.len;

    writer.writeU8(3); // ECCurveType named_curve
    writer.writeU16(named_curve_secp256r1);
    writer.writeU8(@intCast(point.len));
    writer.writeBytes(point);
    const params = writer.buf[params_start..writer.len];

    // signature over client_random ++ server_random ++ params (RFC 5246 7.4.3).
    var signed: [32 + 32 + 70]u8 = undefined;
    @memcpy(signed[0..32], &client_random);
    @memcpy(signed[32..64], &server_random);
    @memcpy(signed[64 .. 64 + params.len], params);
    const sig = try key.sign(signed[0 .. 64 + params.len], null);

    var der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const der = sig.toDer(&der_buf);

    writer.writeU16(sig_ecdsa_secp256r1_sha256);
    const sig_len = writer.placeU16();
    writer.writeBytes(der);
    writer.patchU16(sig_len);

    writer.patchU24(header);
}

/// Phase 2: ClientKeyExchange + the encrypted client Finished -> derive keys, verify the client
/// Finished, emit ChangeCipherSpec + the encrypted server Finished, return the Connection.
pub fn serverFinish(state: *State, client_key_exchange: []const u8, client_finished_record: []const u8, out: []u8) !FinishResult {
    var r = wire.Reader{ .buf = client_key_exchange };
    if (try r.readU8() != hs_client_key_exchange) return error.ZixUnexpectedMessage;
    _ = try r.readU24();
    const point_len = try r.readU8();
    const client_point = try r.readBytes(point_len);

    state.transcript.update(client_key_exchange);

    const pre_master = try ecdheSharedX(state.server_eph_scalar, client_point);
    const master = prf.masterSecret(&pre_master, state.client_random, state.server_random);
    const km = prf.keyMaterial(master, state.client_random, state.server_random);

    // verify the client Finished (encrypted under the client key, seq 0), transcript = CH..CKE.
    const expected = prf.finishedFromHash(master, "client finished", transcriptHash(state));
    var cf_plain: [64]u8 = undefined;
    const cf = try record.deprotect(&cf_plain, client_finished_record, km.client_write_key, km.client_write_iv, 0);
    if (cf.len < 16 or cf[0] != hs_finished) return error.ZixUnexpectedMessage;
    if (!std.mem.eql(u8, cf[4..16], &expected)) return error.ZixClientFinishedMismatch;

    state.transcript.update(cf);

    // server Finished over CH..clientFinished.
    const server_vd = prf.finishedFromHash(master, "server finished", transcriptHash(state));
    var fin_msg: [16]u8 = undefined;
    fin_msg[0] = hs_finished;
    fin_msg[1] = 0;
    fin_msg[2] = 0;
    fin_msg[3] = 12;
    @memcpy(fin_msg[4..16], &server_vd);

    // ChangeCipherSpec record (plaintext) then the encrypted Finished record (outer type handshake).
    out[0] = 20; // change_cipher_spec
    out[1] = 0x03;
    out[2] = 0x03;
    out[3] = 0x00;
    out[4] = 0x01;
    out[5] = 0x01;
    const enc = record.protect(out[6..], &fin_msg, content_handshake, km.server_write_key, km.server_write_iv, 0);

    return .{ .to_send = out[0 .. 6 + enc.len], .connection = .{ .km = km } };
}

fn transcriptHash(state: *const State) [32]u8 {
    var copy = state.transcript;
    var hash: [32]u8 = undefined;
    copy.final(&hash);

    return hash;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix tls: tls12 connection, serverFlight1 negotiates + emits ALPN h2" {
    var skey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&skey, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const key = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(skey));
    const dummy_der = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };

    // ClientHello offering ALPN ["h2"].
    var ch_buf: [128]u8 = undefined;
    var cw = wire.Writer{ .buf = &ch_buf };
    cw.writeU8(1);
    const ch_hdr = cw.placeU24();
    cw.writeU16(version_tls_1_2);
    const client_random: [32]u8 = @splat(0x11);
    cw.writeBytes(&client_random);
    cw.writeU8(0);
    cw.writeU16(2);
    cw.writeU16(cipher_ecdhe_ecdsa_aes128_gcm);
    cw.writeU8(1);
    cw.writeU8(0);
    const exts = cw.placeU16();
    cw.writeU16(0x0010); // ALPN
    cw.writeU16(5);
    cw.writeU16(3); // ProtocolNameList length
    cw.writeU8(2);
    cw.writeBytes("h2");
    cw.patchU16(exts);
    cw.patchU24(ch_hdr);

    var out: [4096]u8 = undefined;
    const flight = try serverFlight1(.{
        .certificate_der = &dummy_der,
        .signing_key = key,
        .server_eph_secret = @splat(0x22),
        .server_random = @splat(0x33),
        .alpn_prefs = &.{.H2},
    }, cw.slice(), &out);

    try std.testing.expectEqual(Alpn.H2, flight.state.alpn.?);
    // the ServerHello carries the ALPN extension selecting h2 (00 10 00 05 00 03 02 68 32).
    try std.testing.expect(std.mem.indexOf(u8, flight.to_send, &[_]u8{ 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x32 }) != null);
}

test "zix tls: tls12 connection, in-memory ECDHE-ECDSA handshake round trip" {
    // server identity (fixed scalar for determinism).
    var skey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&skey, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const key = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(skey));
    const dummy_der = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };

    // a minimal TLS 1.2 ClientHello (1.2-only: no supported_versions, so no downgrade sentinel).
    var ch_buf: [128]u8 = undefined;
    var cw = wire.Writer{ .buf = &ch_buf };
    cw.writeU8(1); // client_hello
    const ch_hdr = cw.placeU24();
    cw.writeU16(version_tls_1_2);
    const client_random: [32]u8 = @splat(0x11);
    cw.writeBytes(&client_random);
    cw.writeU8(0); // session_id
    cw.writeU16(2); // cipher_suites len
    cw.writeU16(cipher_ecdhe_ecdsa_aes128_gcm);
    cw.writeU8(1); // compression len
    cw.writeU8(0);
    cw.writeU16(0); // no extensions
    cw.patchU24(ch_hdr);
    const client_hello = cw.slice();

    var flight_buf: [4096]u8 = undefined;
    const flight = try serverFlight1(.{
        .certificate_der = &dummy_der,
        .signing_key = key,
        .server_eph_secret = @splat(0x22),
        .server_random = @splat(0x33),
    }, client_hello, &flight_buf);
    var state = flight.state;

    // Parse the flight for the server ECDHE point + server_random
    const body = flight.to_send[5..];
    var br = wire.Reader{ .buf = body };
    var server_point: []const u8 = &.{};
    var server_random_seen: [32]u8 = undefined;
    while (br.remaining() >= 4) {
        const msg_type = try br.readU8();
        const msg_len = try br.readU24();
        const msg = try br.readBytes(msg_len);
        if (msg_type == hs_server_hello) {
            @memcpy(&server_random_seen, msg[2..34]); // skip version(2), take random(32)
        } else if (msg_type == hs_server_key_exchange) {
            // curve_type(1) + named_curve(2) + point_len(1) + point
            server_point = msg[4 .. 4 + msg[3]];
        }
    }
    try std.testing.expectEqual(@as(usize, 65), server_point.len);

    // client ECDHE + key schedule.
    const c_scalar = reduceP256Scalar(@splat(0x44));
    const c_point = (try P256.basePoint.mul(c_scalar, .big)).toUncompressedSec1();
    const pre = try ecdheSharedX(c_scalar, server_point);
    const master = prf.masterSecret(&pre, client_random, server_random_seen);
    const km = prf.keyMaterial(master, client_random, server_random_seen);

    // ClientKeyExchange.
    var cke: [4 + 1 + 65]u8 = undefined;
    cke[0] = hs_client_key_exchange;
    cke[1] = 0;
    cke[2] = 0;
    cke[3] = 1 + 65;
    cke[4] = 65;
    @memcpy(cke[5..], &c_point);

    // client transcript = CH ++ flight body ++ CKE -> client Finished verify_data.
    var ct = Sha256.init(.{});
    ct.update(client_hello);
    ct.update(body);
    ct.update(&cke);
    var ch_cke_hash: [32]u8 = undefined;
    {
        var copy = ct;
        copy.final(&ch_cke_hash);
    }
    const client_vd = prf.finishedFromHash(master, "client finished", ch_cke_hash);

    var cf_msg: [16]u8 = undefined;
    cf_msg[0] = hs_finished;
    cf_msg[1] = 0;
    cf_msg[2] = 0;
    cf_msg[3] = 12;
    @memcpy(cf_msg[4..16], &client_vd);

    var cf_rec_buf: [128]u8 = undefined;
    const cf_rec = record.protect(&cf_rec_buf, &cf_msg, content_handshake, km.client_write_key, km.client_write_iv, 0);

    // Server finishes
    var out_buf: [256]u8 = undefined;
    var fin = try serverFinish(&state, &cke, cf_rec, &out_buf);

    // client verifies the server Finished: skip the 6-byte CCS, decrypt the rest.
    const server_fin_rec = fin.to_send[6..];
    var sf_plain: [64]u8 = undefined;
    const sf = try record.deprotect(&sf_plain, server_fin_rec, km.server_write_key, km.server_write_iv, 0);
    try std.testing.expectEqual(hs_finished, sf[0]);

    ct.update(&cf_msg); // CH..clientFinished
    var ch_cf_hash: [32]u8 = undefined;
    ct.final(&ch_cf_hash);
    const expect_server_vd = prf.finishedFromHash(master, "server finished", ch_cf_hash);
    try std.testing.expectEqualSlices(u8, &expect_server_vd, sf[4..16]);

    // application-data round trip on the established Connection.
    var app_buf: [128]u8 = undefined;
    const app_rec = fin.connection.writeAppData("hello over tls 1.2", &app_buf);
    var app_plain: [128]u8 = undefined;
    const got = try record.deprotect(&app_plain, app_rec, km.server_write_key, km.server_write_iv, 1);
    try std.testing.expectEqualSlices(u8, "hello over tls 1.2", got);
}
