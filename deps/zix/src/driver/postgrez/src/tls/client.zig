//! TLS 1.3 client handshake (RFC 8446), adapted from the zix TLS client for
//! the postgrez SSLRequest upgrade.
//!
//! Note:
//! - Sans-IO, two phases: start() builds the ClientHello (the caller wraps
//!   it in a plaintext handshake record and sends it), finish() consumes the
//!   accumulated server records and produces the client Finished plus a
//!   ClientConnection for application data.
//! - Differences against the zix original: no ALPN (the SSLRequest upgrade
//!   never negotiates one), the ChangeCipherSpec record is optional, the
//!   encrypted server flight may span several records (real servers split
//!   it), and finish() reports error.PostgrezNeedMoreRecords when the Finished
//!   message has not arrived yet, so the caller reads record by record.
//! - Offers x25519, TLS_AES_128_GCM_SHA256, and the ecdsa_secp256r1_sha256 +
//!   ed25519 signature schemes: the server certificate must match (the
//!   postgrez test container uses ECDSA P-256).
//! - finish() proves the peer holds the certificate key (CertificateVerify)
//!   and surfaces the end-entity certificate DER for SCRAM channel binding.
//!   Chain and hostname trust are out of scope here.

const std = @import("std");
const wire = @import("wire.zig");
const key_schedule = @import("key_schedule.zig");
const record = @import("record.zig");

const X25519 = std.crypto.dh.X25519;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Secret = key_schedule.Secret;

const NAMED_GROUP_X25519: u16 = 0x001d;

/// Max DER size for the server end-entity cert copied out of the decrypted
/// flight. A P-256 leaf is ~470 bytes, 2 KiB covers larger SAN lists.
pub const MAX_SERVER_CERT_DER = 2048;

/// Decrypted handshake flight ceiling (EE + Certificate + CertificateVerify
/// + Finished across every encrypted record).
pub const MAX_FLIGHT_PLAIN = 16 * 1024;

pub const HandshakeOptions = struct {
    client_random: [32]u8,
    /// x25519 ephemeral private (fresh per connection).
    ephemeral_secret: [32]u8,
};

/// Carried from start into finish: the ephemeral secret and the running
/// transcript (ClientHello so far). Copyable, finish() works on a copy so
/// the caller can retry with more records.
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
    /// the server end-entity certificate (DER), copied out of the decrypted
    /// flight so it outlives finish(). Read it through serverCertDer().
    server_cert: [MAX_SERVER_CERT_DER]u8 = undefined,
    server_cert_len: usize = 0,

    /// The server end-entity certificate DER. Empty when the server sent no
    /// Certificate.
    pub fn serverCertDer(self: *const FinishResult) []const u8 {
        return self.server_cert[0..self.server_cert_len];
    }
};

/// Post-handshake client keys + per-direction sequence numbers. The client
/// writes under the client application key and reads under the server's.
pub const ClientConnection = struct {
    client_app_key: [record.KEY_LENGTH]u8,
    client_app_iv: [record.IV_LENGTH]u8,
    server_app_key: [record.KEY_LENGTH]u8,
    server_app_iv: [record.IV_LENGTH]u8,
    client_seq: u64 = 0,
    server_seq: u64 = 0,

    pub fn writeAppData(self: *ClientConnection, plaintext: []const u8, out: []u8) []const u8 {
        const rec = record.protect(out, plaintext, .APPLICATION_DATA, self.client_app_key, self.client_app_iv, self.client_seq);
        self.client_seq += 1;

        return rec;
    }

    /// Open one protected record of ANY inner type. The caller inspects
    /// inner_type: post-handshake HANDSHAKE records (NewSessionTicket) are
    /// skipped, ALERT ends the stream.
    pub fn readRecord(self: *ClientConnection, rec: []const u8, out: []u8) record.Error!record.Opened {
        const opened = try record.deprotect(out, rec, self.server_app_key, self.server_app_iv, self.server_seq);
        self.server_seq += 1;

        return opened;
    }

    pub fn closeNotify(self: *ClientConnection, out: []u8) []const u8 {
        const rec = record.protect(out, &[_]u8{ 1, 0 }, .ALERT, self.client_app_key, self.client_app_iv, self.client_seq);
        self.client_seq += 1;

        return rec;
    }
};

// --------------------------------------------------------- //

/// Phase 1: build the ClientHello and start the transcript. The caller
/// wraps `client_hello` in a plaintext handshake record and sends it.
pub fn start(opts: HandshakeOptions, out: []u8) !StartResult {
    const client_public = try X25519.recoverPublicKey(opts.ephemeral_secret);
    const client_hello = buildClientHello(out, opts.client_random, client_public);

    var state = State{ .ephemeral_secret = opts.ephemeral_secret, .transcript = key_schedule.Transcript.init() };
    state.transcript.update(client_hello);

    return .{ .client_hello = client_hello, .state = state };
}

/// Phase 2: process the accumulated server records (ServerHello, optional
/// ChangeCipherSpec, one or more encrypted flight records), verify the
/// server Finished, produce the client Finished and the ClientConnection.
///
/// Return:
/// - FinishResult on a complete flight
/// - error.PostgrezNeedMoreRecords when Finished has not arrived yet: append the
///   next record and call again on a fresh copy of the start() state
pub fn finish(state: *State, server_records: []const u8, out: []u8) !FinishResult {
    var reader = wire.Reader{ .buf = server_records };

    // record 1: ServerHello (plaintext handshake).
    if (try reader.readU8() != 22) return error.PostgrezUnexpectedRecord;
    _ = try reader.readU16();
    const sh_len = try reader.readU16();
    const sh_msg = try reader.readBytes(sh_len);
    const sh = try parseServerHello(sh_msg);
    state.transcript.update(sh_msg);

    // handshake key schedule from the transcript through ServerHello.
    const ecdhe = try X25519.scalarmult(state.ephemeral_secret, sh.server_public);

    const zero = std.mem.zeroes(Secret);
    const empty_hash = key_schedule.Transcript.init().current();
    const early = key_schedule.HkdfSha256.extract(&zero, &zero);
    const derived = key_schedule.deriveSecret(early, "derived", empty_hash);
    const handshake_secret = key_schedule.HkdfSha256.extract(&derived, &ecdhe);

    const t_ch_sh = state.transcript.current();
    const server_hs_traffic = key_schedule.deriveSecret(handshake_secret, "s hs traffic", t_ch_sh);
    const client_hs_traffic = key_schedule.deriveSecret(handshake_secret, "c hs traffic", t_ch_sh);

    var server_hs_key: [record.KEY_LENGTH]u8 = undefined;
    var server_hs_iv: [record.IV_LENGTH]u8 = undefined;
    var client_hs_key: [record.KEY_LENGTH]u8 = undefined;
    var client_hs_iv: [record.IV_LENGTH]u8 = undefined;
    key_schedule.expandLabel(&server_hs_key, server_hs_traffic, "key", "");
    key_schedule.expandLabel(&server_hs_iv, server_hs_traffic, "iv", "");
    key_schedule.expandLabel(&client_hs_key, client_hs_traffic, "key", "");
    key_schedule.expandLabel(&client_hs_iv, client_hs_traffic, "iv", "");

    // decrypt every remaining record: skip ChangeCipherSpec, concatenate the
    // decrypted handshake messages across encrypted records.
    var flight_plain: [MAX_FLIGHT_PLAIN]u8 = undefined;
    var flight_len: usize = 0;
    var hs_seq: u64 = 0;
    while (reader.remaining() > 0) {
        const rec_type = try reader.readU8();
        _ = try reader.readU16();
        const rec_len = try reader.readU16();
        const rec_start = reader.pos - 5;
        _ = try reader.readBytes(rec_len);
        const rec = server_records[rec_start .. rec_start + 5 + rec_len];

        switch (rec_type) {
            20 => continue, // ChangeCipherSpec, middlebox compat, ignored
            23 => {
                if (flight_len + rec_len > flight_plain.len) return error.PostgrezFlightTooLarge;

                const opened = try record.deprotect(flight_plain[flight_len..], rec, server_hs_key, server_hs_iv, hs_seq);
                hs_seq += 1;
                if (opened.inner_type == .ALERT) return error.PostgrezHandshakeAlert;
                if (opened.inner_type != .HANDSHAKE) return error.PostgrezUnexpectedRecord;

                flight_len += opened.data.len;
            },
            21 => return error.PostgrezHandshakeAlert,
            else => return error.PostgrezUnexpectedRecord,
        }
    }

    // fold each inner message (EE, Cert, CertVerify, Finished) into the transcript.
    var flight_reader = wire.Reader{ .buf = flight_plain[0..flight_len] };
    var server_finished_vd: []const u8 = &.{};
    var transcript_before_finished = state.transcript;
    var cert_msg: []const u8 = &.{};
    var certverify_msg: []const u8 = &.{};
    var t_after_cert: Secret = undefined;
    var finished_seen = false;
    while (flight_reader.remaining() >= 4) {
        const msg_type = try flight_reader.readU8();
        const msg_len = try flight_reader.readU24();
        const msg_start = flight_reader.pos - 4;
        const msg_body = flight_reader.readBytes(msg_len) catch return error.PostgrezNeedMoreRecords;
        switch (msg_type) {
            11 => cert_msg = msg_body, // Certificate
            15 => certverify_msg = msg_body, // CertificateVerify
            20 => { // Finished: verify_data covers the transcript before it
                transcript_before_finished = state.transcript;
                server_finished_vd = msg_body;
                finished_seen = true;
            },
            else => {},
        }
        state.transcript.update(flight_plain[msg_start..flight_reader.pos]);
        if (msg_type == 11) t_after_cert = state.transcript.current();
        if (finished_seen) break;
    }
    if (!finished_seen) return error.PostgrezNeedMoreRecords;

    // CertificateVerify (RFC 8446 4.4.3): the peer signed the transcript
    // with the end-entity cert's private key.
    try verifyCertificateVerify(cert_msg, certverify_msg, t_after_cert);

    // verify the server Finished (RFC 8446 4.4.4).
    const server_finished_key = finishedKey(server_hs_traffic);
    const expected = finishedVerifyData(server_finished_key, transcript_before_finished.current());
    if (server_finished_vd.len != key_schedule.HASH_LENGTH or !std.mem.eql(u8, server_finished_vd, &expected)) {
        return error.PostgrezServerFinishedMismatch;
    }

    // application key schedule from the transcript through the server Finished.
    const t_full = state.transcript.current();
    const derived_master = key_schedule.deriveSecret(handshake_secret, "derived", empty_hash);
    const master = key_schedule.HkdfSha256.extract(&derived_master, &zero);
    const server_ap = key_schedule.deriveSecret(master, "s ap traffic", t_full);
    const client_ap = key_schedule.deriveSecret(master, "c ap traffic", t_full);

    var connection: ClientConnection = .{ .client_app_key = undefined, .client_app_iv = undefined, .server_app_key = undefined, .server_app_iv = undefined };
    key_schedule.expandLabel(&connection.server_app_key, server_ap, "key", "");
    key_schedule.expandLabel(&connection.server_app_iv, server_ap, "iv", "");
    key_schedule.expandLabel(&connection.client_app_key, client_ap, "key", "");
    key_schedule.expandLabel(&connection.client_app_iv, client_ap, "iv", "");

    // build the client Finished, encrypted under the client handshake key (seq 0).
    const client_finished_key = finishedKey(client_hs_traffic);
    const client_vd = finishedVerifyData(client_finished_key, t_full);
    var fin_msg: [4 + key_schedule.HASH_LENGTH]u8 = undefined;
    fin_msg[0] = 20;
    fin_msg[1] = 0;
    fin_msg[2] = 0;
    fin_msg[3] = key_schedule.HASH_LENGTH;
    @memcpy(fin_msg[4..], &client_vd);

    const client_finished = record.protect(out, &fin_msg, .HANDSHAKE, client_hs_key, client_hs_iv, 0);

    // surface the server end-entity cert for channel binding.
    const leaf = try leafCertDer(cert_msg);
    if (leaf.len > MAX_SERVER_CERT_DER) return error.PostgrezCertificateTooLarge;

    var result: FinishResult = .{ .client_finished = client_finished, .connection = connection };
    @memcpy(result.server_cert[0..leaf.len], leaf);
    result.server_cert_len = leaf.len;

    return result;
}

// --------------------------------------------------------- //

/// End-entity (leaf) certificate DER out of a TLS 1.3 Certificate message
/// (RFC 8446 4.4.2).
fn leafCertDer(cert_msg: []const u8) ![]const u8 {
    var cert_reader = wire.Reader{ .buf = cert_msg };
    const ctx_len = try cert_reader.readU8();
    _ = try cert_reader.readBytes(ctx_len);
    _ = try cert_reader.readU24(); // certificate_list length
    const cert_len = try cert_reader.readU24();

    return cert_reader.readBytes(cert_len);
}

fn buildClientHello(out: []u8, client_random: [32]u8, client_public: [32]u8) []const u8 {
    var writer = wire.Writer{ .buf = out };
    writer.writeU8(1); // client_hello
    const header = writer.placeU24();
    writer.writeU16(0x0303); // legacy_version
    writer.writeBytes(&client_random);
    writer.writeU8(0); // empty legacy_session_id
    writer.writeU16(2); // cipher_suites length
    writer.writeU16(0x1301); // TLS_AES_128_GCM_SHA256
    writer.writeU8(1); // compression methods length
    writer.writeU8(0); // null

    const exts = writer.placeU16();
    // supported_versions: [0x0304]
    writer.writeU16(0x002b);
    writer.writeU16(3);
    writer.writeU8(2);
    writer.writeU16(0x0304);
    // signature_algorithms: [ecdsa_secp256r1_sha256, ed25519]
    writer.writeU16(0x000d);
    writer.writeU16(6);
    writer.writeU16(4);
    writer.writeU16(0x0403);
    writer.writeU16(0x0807);
    // supported_groups: [x25519]
    writer.writeU16(0x000a);
    writer.writeU16(4);
    writer.writeU16(2);
    writer.writeU16(NAMED_GROUP_X25519);
    // key_share: x25519 -> client_public
    writer.writeU16(0x0033);
    const ks_ext = writer.placeU16();
    const ks_list = writer.placeU16();
    writer.writeU16(NAMED_GROUP_X25519);
    writer.writeU16(32);
    writer.writeBytes(&client_public);
    writer.patchU16(ks_list);
    writer.patchU16(ks_ext);

    writer.patchU16(exts);
    writer.patchU24(header);

    return writer.slice();
}

/// Verify the server CertificateVerify. Supports ecdsa_secp256r1_sha256
/// (0x0403) and ed25519 (0x0807), the schemes the ClientHello offers.
fn verifyCertificateVerify(cert_msg: []const u8, certverify_msg: []const u8, transcript_hash: Secret) !void {
    const cert_der = try leafCertDer(cert_msg);

    var verify_reader = wire.Reader{ .buf = certverify_msg };
    const scheme = try verify_reader.readU16();
    const sig_len = try verify_reader.readU16();
    const sig_bytes = try verify_reader.readBytes(sig_len);

    const cert = std.crypto.Certificate{ .buffer = cert_der, .index = 0 };
    const parsed = try cert.parse();

    var content_buf: [256]u8 = undefined;
    const content = certificateVerifyContent(&content_buf, transcript_hash);

    switch (scheme) {
        0x0403 => { // ecdsa_secp256r1_sha256
            const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
            const pub_key = try EcdsaP256.PublicKey.fromSec1(parsed.pubKey());
            const sig = try EcdsaP256.Signature.fromDer(sig_bytes);
            try sig.verify(content, pub_key);
        },
        0x0807 => { // ed25519
            const Ed25519 = std.crypto.sign.Ed25519;
            if (sig_bytes.len != Ed25519.Signature.encoded_length) return error.PostgrezInvalidSignature;
            const pub_raw = parsed.pubKey();
            if (pub_raw.len != 32) return error.PostgrezUnsupportedSignatureScheme;

            const pub_key = try Ed25519.PublicKey.fromBytes(pub_raw[0..32].*);
            const sig = Ed25519.Signature.fromBytes(sig_bytes[0..64].*);
            try sig.verify(content, pub_key);
        },
        else => return error.PostgrezUnsupportedSignatureScheme,
    }
}

const ServerHelloParsed = struct {
    server_random: [32]u8,
    server_public: [32]u8,
};

fn parseServerHello(sh_msg: []const u8) !ServerHelloParsed {
    var hello_reader = wire.Reader{ .buf = sh_msg };
    if (try hello_reader.readU8() != 2) return error.PostgrezNotServerHello;
    _ = try hello_reader.readU24();
    _ = try hello_reader.readU16(); // legacy_version
    var out: ServerHelloParsed = undefined;
    @memcpy(&out.server_random, try hello_reader.readBytes(32));
    const sid_len = try hello_reader.readU8();
    _ = try hello_reader.readBytes(sid_len);
    _ = try hello_reader.readU16(); // cipher
    _ = try hello_reader.readU8(); // compression
    const ext_len = try hello_reader.readU16();
    const exts = try hello_reader.readBytes(ext_len);

    var ext_reader = wire.Reader{ .buf = exts };
    while (ext_reader.remaining() >= 4) {
        const ext_type = try ext_reader.readU16();
        const ext_data_len = try ext_reader.readU16();
        const ext_data = try ext_reader.readBytes(ext_data_len);
        if (ext_type == 0x0033) { // key_share
            var ks_reader = wire.Reader{ .buf = ext_data };
            _ = try ks_reader.readU16(); // group
            const key_len = try ks_reader.readU16();
            @memcpy(&out.server_public, try ks_reader.readBytes(key_len));

            return out;
        }
    }

    return error.PostgrezNoServerKeyShare;
}

// certificate helpers inlined from the zix certificate layer (the only
// three the client path needs)

const CERTIFICATE_VERIFY_CONTEXT = "TLS 1.3, server CertificateVerify";
const CERTIFICATE_VERIFY_CONTENT_LEN = 64 + CERTIFICATE_VERIFY_CONTEXT.len + 1 + key_schedule.HASH_LENGTH;

/// CertificateVerify content (RFC 8446 4.4.3): 64 spaces, the context
/// string, a NUL, the transcript hash.
fn certificateVerifyContent(buf: []u8, transcript_hash: Secret) []const u8 {
    @memset(buf[0..64], 0x20);
    @memcpy(buf[64 .. 64 + CERTIFICATE_VERIFY_CONTEXT.len], CERTIFICATE_VERIFY_CONTEXT);
    buf[64 + CERTIFICATE_VERIFY_CONTEXT.len] = 0x00;
    @memcpy(buf[64 + CERTIFICATE_VERIFY_CONTEXT.len + 1 ..][0..key_schedule.HASH_LENGTH], &transcript_hash);

    return buf[0..CERTIFICATE_VERIFY_CONTENT_LEN];
}

/// finished_key = HKDF-Expand-Label(traffic_secret, "finished", "") (RFC 8446 4.4.4).
fn finishedKey(traffic_secret: Secret) Secret {
    var out: Secret = undefined;
    key_schedule.expandLabel(&out, traffic_secret, "finished", "");

    return out;
}

/// Finished verify_data = HMAC(finished_key, Transcript-Hash(...)) (RFC 8446 4.4.4).
fn finishedVerifyData(finished_key: Secret, transcript_hash: Secret) Secret {
    var out: Secret = undefined;
    HmacSha256.create(&out, &transcript_hash, &finished_key);

    return out;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez tls: tls client hello offers 1.3, x25519, aes-128-gcm" {
    var hello_buf: [512]u8 = undefined;
    const started = try start(.{ .client_random = @splat(0x11), .ephemeral_secret = @splat(0x42) }, &hello_buf);
    const hello = started.client_hello;

    try testing.expectEqual(@as(u8, 1), hello[0]);

    // cipher suite TLS_AES_128_GCM_SHA256 present
    try testing.expect(std.mem.indexOf(u8, hello, &.{ 0x13, 0x01 }) != null);
    // supported_versions carries 0x0304
    try testing.expect(std.mem.indexOf(u8, hello, &.{ 0x03, 0x04 }) != null);
    // key_share carries the x25519 public of the fixed ephemeral
    const client_public = try X25519.recoverPublicKey(@splat(0x42));
    try testing.expect(std.mem.indexOf(u8, hello, &client_public) != null);
}

test "postgrez tls: tls client finish reports NeedMoreRecords on a bare ServerHello" {
    // A minimal ServerHello record with a key_share, no encrypted flight yet.
    const server_public = try X25519.recoverPublicKey(@splat(0x99));

    var sh_buf: [256]u8 = undefined;
    var writer = wire.Writer{ .buf = &sh_buf };
    writer.writeU8(2); // server_hello
    const header = writer.placeU24();
    writer.writeU16(0x0303);
    var random: [32]u8 = @splat(0x55);
    writer.writeBytes(&random);
    writer.writeU8(0); // empty session id
    writer.writeU16(0x1301);
    writer.writeU8(0);
    const exts = writer.placeU16();
    writer.writeU16(0x0033);
    const ks_ext = writer.placeU16();
    writer.writeU16(NAMED_GROUP_X25519);
    writer.writeU16(32);
    writer.writeBytes(&server_public);
    writer.patchU16(ks_ext);
    writer.patchU16(exts);
    writer.patchU24(header);
    const sh_msg = writer.slice();

    var records_buf: [512]u8 = undefined;
    records_buf[0] = 22;
    std.mem.writeInt(u16, records_buf[1..3], 0x0303, .big);
    std.mem.writeInt(u16, records_buf[3..5], @intCast(sh_msg.len), .big);
    @memcpy(records_buf[5 .. 5 + sh_msg.len], sh_msg);

    var hello_buf: [512]u8 = undefined;
    const started = try start(.{ .client_random = @splat(0x11), .ephemeral_secret = @splat(0x42) }, &hello_buf);

    var state = started.state;
    var fin_buf: [256]u8 = undefined;
    try testing.expectError(error.PostgrezNeedMoreRecords, finish(&state, records_buf[0 .. 5 + sh_msg.len], &fin_buf));
}

test "postgrez tls: tls ClientConnection round trip and readRecord types" {
    var alice = ClientConnection{
        .client_app_key = @splat(0x01),
        .client_app_iv = @splat(0x02),
        .server_app_key = @splat(0x03),
        .server_app_iv = @splat(0x04),
    };
    // the mirror side reads what alice writes: swap key roles
    var bob = ClientConnection{
        .client_app_key = @splat(0x03),
        .client_app_iv = @splat(0x04),
        .server_app_key = @splat(0x01),
        .server_app_iv = @splat(0x02),
    };

    var rec_buf: [256]u8 = undefined;
    const rec = alice.writeAppData("SELECT 1", &rec_buf);

    var plain_buf: [256]u8 = undefined;
    const opened = try bob.readRecord(rec, &plain_buf);
    try testing.expectEqual(record.ContentType.APPLICATION_DATA, opened.inner_type);
    try testing.expectEqualStrings("SELECT 1", opened.data);

    // a handshake record (NewSessionTicket shape) surfaces its inner type
    var ticket_buf: [256]u8 = undefined;
    const ticket = record.protect(&ticket_buf, &.{ 4, 0, 0, 0 }, .HANDSHAKE, alice.client_app_key, alice.client_app_iv, alice.client_seq);
    alice.client_seq += 1;

    const opened_ticket = try bob.readRecord(ticket, &plain_buf);
    try testing.expectEqual(record.ContentType.HANDSHAKE, opened_ticket.inner_type);
}
