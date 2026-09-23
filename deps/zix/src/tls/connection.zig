//! TLS 1.3 server connection: the sans-I/O handshake + record state machine (RFC 8446).
//!
//! Note:
//! - No socket calls. `serverHandshake` consumes a ClientHello and produces the bytes to send
//!   (ServerHello plaintext record, a legacy ChangeCipherSpec, then the encrypted flight) and a
//!   Connection holding the post-handshake keys. The caller (the engine or example) owns the fd
//!   read/write loop, so this fits blocking and non-blocking dispatch alike.
//! - Randomness (the ephemeral key and ServerHello random) is injected by the caller, so the
//!   handshake is deterministic and unit-testable against the RFC 8448 trace.
//! - Composes the verified layers: handshake (H), extensions (X), certificate (C), key_schedule
//!   + record (K).

const std = @import("std");
const wire = @import("wire.zig");
const key_schedule = @import("key_schedule.zig");
const record = @import("record.zig");
const handshake = @import("handshake.zig");
const extensions = @import("extensions.zig");
const certificate = @import("certificate.zig");
const cert_verify = @import("cert_verify.zig");
const alert = @import("alert.zig");
const rsa = @import("rsa.zig");

/// Client Certificate record decrypt buffer (split-framing mTLS): caps the client cert size.
const CLIENT_CERT_RECORD_BUF: usize = 4096;

/// Server handshake flight build buffer: caps the server cert chain plus the flight messages.
const SERVER_FLIGHT_BUF: usize = 4096;

const X25519 = std.crypto.dh.X25519;
const P256 = std.crypto.ecc.P256;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const NamedGroup = handshake.NamedGroup;
const Secret = key_schedule.Secret;

const ccs_record = [_]u8{ 20, 0x03, 0x03, 0x00, 0x01, 0x01 };

/// Inputs the caller supplies to drive one server handshake. The cert + key select the identity,
/// the ephemeral secret + random are freshly generated per connection (or trace values in tests).
pub const HandshakeOptions = struct {
    /// The certificates to present, end-entity first, then any intermediates.
    certificate_chain: []const []const u8,
    /// ECDSA P-256 or Ed25519 signing identity (certificate.SigningKey). Its scheme must be one the
    /// client offered in signature_algorithms, else serverHandshake aborts (Layer C selection).
    signing_key: certificate.SigningKey,
    ephemeral_secret: [32]u8,
    server_random: [32]u8,
    /// Random salt for an RSA PSS CertificateVerify (RFC 8017 9.1), supplied per connection like the
    /// other randoms. Unused by the ECDSA / Ed25519 paths, so it defaults to zero for them.
    pss_salt: [rsa.pss_salt_len]u8 = std.mem.zeroes([rsa.pss_salt_len]u8),
    /// Server ALPN preference order (RFC 7301). Empty disables ALPN (no extension emitted).
    /// The first entry that the client also offered is selected and echoed in EncryptedExtensions.
    alpn_prefs: []const extensions.Alpn = &.{},
    /// Server curve preference order (Tls.Context.curves). Defaults to the built-in order so callers
    /// that do not configure curves keep the prior behavior. negotiate picks the first the client
    /// also offered.
    group_prefs: []const handshake.NamedGroup = &handshake.server_group_prefs,
    /// mTLS: when true the server emits a CertificateRequest (RFC 8446 4.3.2) in its flight, then
    /// the caller drives verifyClientCertFlight before verifyClientFinished. Off by default.
    request_client_cert: bool = false,
};

/// Post-handshake connection state: the application + handshake keys and per-key sequence
/// numbers needed to read the client Finished and exchange application records.
pub const Connection = struct {
    server_app_key: [record.key_length]u8,
    server_app_iv: [record.iv_length]u8,
    client_app_key: [record.key_length]u8,
    client_app_iv: [record.iv_length]u8,
    client_hs_key: [record.key_length]u8,
    client_hs_iv: [record.iv_length]u8,
    client_finished_key: Secret,
    /// Running transcript captured at the server Finished. Without mTLS its current() is the hash
    /// the client Finished binds. mTLS folds the client Certificate + CertificateVerify into it
    /// (verifyClientCertFlight) before the client Finished is checked.
    handshake_transcript: key_schedule.Transcript,
    /// Sequence number for the client handshake key. The client Finished (and, under mTLS, the
    /// client Certificate + CertificateVerify ahead of it) advance it as records are consumed.
    client_hs_seq: u64 = 0,
    server_app_seq: u64 = 0,
    client_app_seq: u64 = 0,

    /// Encrypt application data into a record under the server application key.
    pub fn writeAppData(self: *Connection, plaintext: []const u8, out: []u8) []const u8 {
        const rec = record.protect(out, plaintext, .APPLICATION_DATA, self.server_app_key, self.server_app_iv, self.server_app_seq);
        self.server_app_seq += 1;

        return rec;
    }

    /// Encrypt two application-data slices as one record under the server application key. The gather
    /// form of writeAppData: the send path seals a staged frame-header prefix (a) with the source
    /// payload (b) without copying b into a contiguous buffer first.
    pub fn writeAppData2(self: *Connection, a: []const u8, b: []const u8, out: []u8) []const u8 {
        const rec = record.protect2(out, a, b, .APPLICATION_DATA, self.server_app_key, self.server_app_iv, self.server_app_seq);
        self.server_app_seq += 1;

        return rec;
    }

    /// readAppData error set: record-layer failures plus the two post-handshake inner-type
    /// conditions a TLS 1.3 server must distinguish (RFC 8446 6, 5.1).
    pub const ReadError = record.Error || error{ ZixPeerClosed, ZixUnexpectedMessage };

    /// Decrypt one client application record and classify its inner content type (RFC 8446 5.1):
    /// - application_data: the plaintext is returned.
    /// - alert: a post-handshake alert (close_notify or fatal) ends the connection -> PeerClosed.
    ///   The body is parsed for classification, then read stops (data after a closure is ignored).
    /// - handshake: post-handshake handshake (renegotiation / KeyUpdate, neither supported) is the
    ///   unexpected_message condition -> UnexpectedMessage, so the caller sends that alert.
    pub fn readAppData(self: *Connection, rec: []const u8, out: []u8) ReadError![]const u8 {
        const opened = try record.deprotect(out, rec, self.client_app_key, self.client_app_iv, self.client_app_seq);
        self.client_app_seq += 1;

        switch (opened.inner_type) {
            .APPLICATION_DATA => return opened.data,
            .ALERT => {
                _ = alert.parseInbound(opened.data) catch {};

                return error.ZixPeerClosed;
            },
            .HANDSHAKE => return error.ZixUnexpectedMessage,
            else => return error.ZixDecode,
        }
    }

    /// Emit an encrypted close_notify alert (level warning, description 0) under the server key.
    pub fn closeNotify(self: *Connection, out: []u8) []const u8 {
        const rec = record.protect(out, &[_]u8{ 1, 0 }, .ALERT, self.server_app_key, self.server_app_iv, self.server_app_seq);
        self.server_app_seq += 1;

        return rec;
    }

    /// Emit an encrypted FATAL alert under the server application key (RFC 8446 6), e.g. to reject a
    /// post-handshake renegotiation with unexpected_message. closeNotify is the clean-shutdown variant.
    pub fn encryptedAlert(self: *Connection, desc: alert.Alert, out: []u8) []const u8 {
        const body = [_]u8{ alert.level_fatal, @intFromEnum(desc) };
        const rec = record.protect(out, &body, .ALERT, self.server_app_key, self.server_app_iv, self.server_app_seq);
        self.server_app_seq += 1;

        return rec;
    }

    /// Deprotect + verify the client Finished record (RFC 8446 4.4.4) under the client handshake
    /// key at the current handshake sequence. Mismatch is the decrypt_error condition. The verify
    /// data binds handshake_transcript, which mTLS extends past the server Finished.
    pub fn verifyClientFinished(self: *Connection, rec: []const u8) !void {
        var plain: [512]u8 = undefined;
        const opened = try record.deprotect(&plain, rec, self.client_hs_key, self.client_hs_iv, self.client_hs_seq);
        self.client_hs_seq += 1;
        if (opened.inner_type != .HANDSHAKE or opened.data.len < 4 + key_schedule.hash_length) return error.ZixClientFinishedMismatch;

        const expected = certificate.finishedVerifyData(self.client_finished_key, self.handshake_transcript.current());
        if (!std.mem.eql(u8, opened.data[4 .. 4 + key_schedule.hash_length], &expected)) return error.ZixClientFinishedMismatch;
    }

    /// mTLS: process the client's Certificate then CertificateVerify (RFC 8446 4.4.2 / 4.4.3),
    /// each one encrypted handshake record under the client handshake key, in order, ahead of the
    /// client Finished. Verifies the CertificateVerify signature against the client cert's public
    /// key and folds both messages into handshake_transcript so the client Finished then binds
    /// them. The trust decision (path validation against a store) is the caller's: run
    /// cert_verify on the returned DER.
    ///
    /// Note:
    /// - Assumes one handshake message per record (the framing zix and common stacks emit for the
    ///   client auth flight). Coalesced messages in a single record are a separate concern.
    ///
    /// Param:
    /// cert_record - []const u8 (the encrypted client Certificate record)
    /// cert_verify_record - []const u8 (the encrypted client CertificateVerify record)
    /// out_der - []u8 (scratch the returned DER is copied into, sized for the client cert)
    ///
    /// Return:
    /// - []const u8 (the client end-entity DER, a sub-slice of out_der)
    /// - error.ZixClientCertificateMissing (the client sent an empty certificate_list)
    /// - error.ZixUnexpectedHandshakeMessage (a record was not the expected message)
    /// - propagates record / signature / key errors otherwise
    pub fn verifyClientCertFlight(self: *Connection, cert_record: []const u8, cert_verify_record: []const u8, out_der: []u8) ![]const u8 {
        var cert_plain: [CLIENT_CERT_RECORD_BUF]u8 = undefined;
        const cert_opened = try record.deprotect(&cert_plain, cert_record, self.client_hs_key, self.client_hs_iv, self.client_hs_seq);
        self.client_hs_seq += 1;
        if (cert_opened.inner_type != .HANDSHAKE or cert_opened.data.len < 4) return error.ZixUnexpectedHandshakeMessage;
        if (cert_opened.data[0] != @intFromEnum(handshake.HandshakeType.CERTIFICATE)) return error.ZixUnexpectedHandshakeMessage;

        const client_der = (try certificate.parseEndEntityCertificate(cert_opened.data[4..])) orelse return error.ZixClientCertificateMissing;
        @memcpy(out_der[0..client_der.len], client_der);
        const der = out_der[0..client_der.len];
        self.handshake_transcript.update(cert_opened.data);

        // the CertificateVerify signs the transcript through the client Certificate (above).
        const transcript_through_cert = self.handshake_transcript.current();

        var verify_plain: [2048]u8 = undefined;
        const verify_opened = try record.deprotect(&verify_plain, cert_verify_record, self.client_hs_key, self.client_hs_iv, self.client_hs_seq);
        self.client_hs_seq += 1;
        if (verify_opened.inner_type != .HANDSHAKE or verify_opened.data.len < 4) return error.ZixUnexpectedHandshakeMessage;
        if (verify_opened.data[0] != @intFromEnum(handshake.HandshakeType.CERTIFICATE_VERIFY)) return error.ZixUnexpectedHandshakeMessage;

        const public_key = try cert_verify.peerEcdsaP256PublicKey(der);
        try certificate.verifyClientCertificateVerify(verify_opened.data[4..], public_key, transcript_through_cert);
        self.handshake_transcript.update(verify_opened.data);

        return der;
    }

    /// mTLS, coalesced framing: the whole client auth flight (Certificate, CertificateVerify,
    /// Finished) arrives in ONE encrypted handshake record, which is what openssl / boringssl emit.
    /// Walks the three messages out of the single decrypted record, verifies the CertificateVerify
    /// signature and the Finished verify_data, and folds each into handshake_transcript. Returns the
    /// client end-entity DER for the caller to path-validate (cert_verify). The split-record framing
    /// is verifyClientCertFlight + verifyClientFinished instead.
    ///
    /// Param:
    /// flight_record - []const u8 (one encrypted record holding the three handshake messages)
    /// out_der - []u8 (scratch the returned DER is copied into)
    ///
    /// Return:
    /// - []const u8 (the client end-entity DER, a sub-slice of out_der)
    /// - error.ZixClientCertificateMissing / error.ZixUnexpectedHandshakeMessage / error.ZixClientFinishedMismatch
    /// - propagates record / signature / key errors otherwise
    pub fn verifyClientAuthFlight(self: *Connection, flight_record: []const u8, out_der: []u8) ![]const u8 {
        var plain: [4096]u8 = undefined;
        const opened = try record.deprotect(&plain, flight_record, self.client_hs_key, self.client_hs_iv, self.client_hs_seq);
        self.client_hs_seq += 1;
        if (opened.inner_type != .HANDSHAKE) return error.ZixUnexpectedHandshakeMessage;

        var reader = wire.Reader{ .buf = opened.data };

        const cert_msg = try readHandshakeMessage(&reader, .CERTIFICATE);
        const client_der = (try certificate.parseEndEntityCertificate(cert_msg.body)) orelse return error.ZixClientCertificateMissing;
        @memcpy(out_der[0..client_der.len], client_der);
        const der = out_der[0..client_der.len];
        self.handshake_transcript.update(cert_msg.full);

        // the CertificateVerify signs the transcript through the client Certificate (above).
        const transcript_through_cert = self.handshake_transcript.current();

        const cert_verify_msg = try readHandshakeMessage(&reader, .CERTIFICATE_VERIFY);
        const public_key = try cert_verify.peerEcdsaP256PublicKey(der);
        try certificate.verifyClientCertificateVerify(cert_verify_msg.body, public_key, transcript_through_cert);
        self.handshake_transcript.update(cert_verify_msg.full);

        // the Finished binds the transcript through the CertificateVerify (above).
        const finished_msg = try readHandshakeMessage(&reader, .FINISHED);
        if (finished_msg.body.len < key_schedule.hash_length) return error.ZixClientFinishedMismatch;

        const expected = certificate.finishedVerifyData(self.client_finished_key, self.handshake_transcript.current());
        if (!std.mem.eql(u8, finished_msg.body[0..key_schedule.hash_length], &expected)) return error.ZixClientFinishedMismatch;
        self.handshake_transcript.update(finished_msg.full);

        return der;
    }
};

/// One handshake message inside a decrypted record: the full bytes (type + length + body, what
/// the transcript hashes) and the body alone (what the message parsers consume).
const HandshakeMessage = struct {
    full: []const u8,
    body: []const u8,
};

/// Read one length-prefixed handshake message (RFC 8446 4) at the reader's cursor, asserting its
/// type. The cursor advances past the message.
fn readHandshakeMessage(reader: *wire.Reader, want: handshake.HandshakeType) !HandshakeMessage {
    const start = reader.pos;
    const message_type = try reader.readU8();
    if (message_type != @intFromEnum(want)) return error.ZixUnexpectedHandshakeMessage;

    const length = try reader.readU24();
    const body = try reader.readBytes(length);

    return .{ .full = reader.buf[start..reader.pos], .body = body };
}

pub const HandshakeResult = struct {
    connection: Connection,
    /// The bytes to send to the client (ServerHello record, ChangeCipherSpec, encrypted flight).
    to_send: []const u8,
    /// The ALPN protocol selected from the client offer and the server prefs, null when ALPN was
    /// not used (no server prefs, or the client offered none). The engine dispatches on this.
    alpn: ?extensions.Alpn = null,
};

/// Drive the server side of a TLS 1.3 handshake from a ClientHello, producing the server flight
/// and the post-handshake Connection. Sans-I/O: the caller transmits `to_send` and feeds back
/// the client Finished + application records.
pub fn serverHandshake(opts: HandshakeOptions, client_hello: []const u8, out: []u8) !HandshakeResult {
    const parsed = handshake.parseClientHello(client_hello);
    if (parsed != .ok) return alertToError(parsed.alert);
    const hello = parsed.ok;

    // Negotiate version, cipher, and group (RFC 8446 4.1.1, 9.1). The key_exchange material is
    // computed after the group is known, so pass an empty placeholder here.
    const negotiated = switch (handshake.negotiate(&hello, &.{}, opts.group_prefs)) {
        .server_hello => |params| params,
        // Single-flight only for now: emitting a HelloRetryRequest (RFC 8446 4.1.4) and sending
        // alert records (Layer A) are tracked separately. In practice clients offer an X25519 or
        // secp256r1 key_share, so HRR does not trigger.
        .hello_retry_request => return error.ZixHelloRetryRequestUnsupported,
        .legacy_version => return error.ZixUnsupportedTlsVersion,
        .alert => |a| return alertToError(a),
    };

    var transcript = key_schedule.Transcript.init();
    transcript.update(client_hello);

    return completeHandshake(opts, &hello, negotiated, &transcript, out);
}

// --------------------------------------------------------------- //
// HelloRetryRequest (RFC 8446 4.1.4): the two-round path for when the client's preferred group has
// no key_share. serverHelloRetry emits the HRR + resume state, serverHandshakeAfterRetry processes
// the second ClientHello. completeHandshake is the shared tail (ServerHello + flight + key schedule),
// fed a transcript already seeded with the ClientHello(s).

/// Build the server flight + post-handshake Connection from a transcript already seeded with the
/// ClientHello(s). Shared by serverHandshake (one ClientHello) and serverHandshakeAfterRetry
/// (synthetic ClientHello1 + HelloRetryRequest + ClientHello2).
fn completeHandshake(opts: HandshakeOptions, hello: *const handshake.ClientHello, negotiated: handshake.ServerHelloParams, transcript: *key_schedule.Transcript, out: []u8) !HandshakeResult {
    // The key schedule is SHA-256 / AES-128-GCM only (server_cipher_prefs). negotiate() cannot
    // pick another suite, this guards that invariant.
    if (negotiated.cipher != .AES_128_GCM_SHA256) return error.ZixUnsupportedCipher;

    // Layer C: the server can only sign CertificateVerify with its key's scheme (ECDSA P-256 or
    // Ed25519, no SHA-1). The client MUST have offered it, else there is no common scheme and the
    // handshake aborts (RFC 8446 4.4.2.2 / 4.4.3). The std signature_algorithms list never has
    // SHA-1 since our SignatureScheme enum carries only ecdsa_secp256r1_sha256 and ed25519.
    if (!hello.offersSignatureScheme(opts.signing_key.scheme())) return error.ZixNoCommonSignatureScheme;

    // ALPN: select one protocol when the server has prefs and the client offered a list.
    // A client offer with no overlap is the no_application_protocol condition (RFC 7301 3.2).
    var selected_alpn: ?extensions.Alpn = null;
    if (opts.alpn_prefs.len > 0) {
        if (hello.alpn) |client_alpn| {
            selected_alpn = extensions.negotiateAlpn(client_alpn, opts.alpn_prefs) orelse return error.ZixNoApplicationProtocol;
        }
    }

    const client_share = switch (negotiated.group) {
        .X25519 => hello.x25519_share orelse return error.ZixMissingKeyShare,
        .SECP256R1 => hello.secp256r1_share orelse return error.ZixMissingKeyShare,
        else => return error.ZixUnsupportedGroup,
    };
    const kex = try computeKeyExchange(negotiated.group, opts.ephemeral_secret, client_share);
    const ecdhe = kex.shared;

    var writer = wire.Writer{ .buf = out };

    // ServerHello as a plaintext handshake record.
    const server_hello = handshake.serializeServerHello(writer.buf[writer.len + 5 ..], &opts.server_random, hello.session_id, .{
        .cipher = negotiated.cipher,
        .group = negotiated.group,
        .key_exchange = kex.server_public[0..kex.server_public_len],
    });
    transcript.update(server_hello);
    writeRecordHeader(&writer, 22, server_hello.len);
    writer.len += server_hello.len;

    writer.writeBytes(&ccs_record);

    // handshake key schedule from the transcript through ServerHello.
    const zero = std.mem.zeroes(Secret);
    const empty_hash = key_schedule.Transcript.init().current();
    const early = key_schedule.HkdfSha256.extract(&zero, &zero);
    const derived = key_schedule.deriveSecret(early, "derived", empty_hash);
    const handshake_secret = key_schedule.HkdfSha256.extract(&derived, &ecdhe);

    const transcript_ch_sh = transcript.current();
    const server_hs_traffic = key_schedule.deriveSecret(handshake_secret, "s hs traffic", transcript_ch_sh);
    const client_hs_traffic = key_schedule.deriveSecret(handshake_secret, "c hs traffic", transcript_ch_sh);

    var server_hs_key: [16]u8 = undefined;
    var server_hs_iv: [12]u8 = undefined;
    var connection: Connection = undefined;
    key_schedule.expandLabel(&server_hs_key, server_hs_traffic, "key", "");
    key_schedule.expandLabel(&server_hs_iv, server_hs_traffic, "iv", "");
    key_schedule.expandLabel(&connection.client_hs_key, client_hs_traffic, "key", "");
    key_schedule.expandLabel(&connection.client_hs_iv, client_hs_traffic, "iv", "");
    connection.client_finished_key = certificate.finishedKey(client_hs_traffic);
    const server_finished_key = certificate.finishedKey(server_hs_traffic);

    // build the flight: EncryptedExtensions, Certificate, CertificateVerify, Finished.
    var flight_buf: [SERVER_FLIGHT_BUF]u8 = undefined;
    var flight = wire.Writer{ .buf = &flight_buf };

    const ee = extensions.buildEncryptedExtensions(flight.buf[flight.len..], .{ .alpn_selected = selected_alpn });
    flight.len += ee.len;
    transcript.update(ee);

    // mTLS: prompt the client for a certificate before sending the server's own (RFC 8446 4.3.2).
    if (opts.request_client_cert) {
        const cert_request = certificate.buildCertificateRequest(flight.buf[flight.len..]);
        flight.len += cert_request.len;
        transcript.update(cert_request);
    }

    const cert_msg = certificate.buildCertificate(flight.buf[flight.len..], opts.certificate_chain);
    flight.len += cert_msg.len;
    transcript.update(cert_msg);

    const server_cert_verify = try certificate.buildCertificateVerify(flight.buf[flight.len..], opts.signing_key, transcript.current(), opts.pss_salt);
    flight.len += server_cert_verify.len;
    transcript.update(server_cert_verify);

    const finished = certificate.buildFinished(flight.buf[flight.len..], server_finished_key, transcript.current());
    flight.len += finished.len;
    transcript.update(finished);

    const flight_record = record.protect(writer.buf[writer.len..], flight.slice(), .HANDSHAKE, server_hs_key, server_hs_iv, 0);
    writer.len += flight_record.len;

    // application key schedule from the transcript through the server Finished.
    connection.handshake_transcript = transcript.*;
    const transcript_through_server_finished = transcript.current();
    const derived_master = key_schedule.deriveSecret(handshake_secret, "derived", empty_hash);
    const master = key_schedule.HkdfSha256.extract(&derived_master, &zero);
    const server_ap_traffic = key_schedule.deriveSecret(master, "s ap traffic", transcript_through_server_finished);
    const client_ap_traffic = key_schedule.deriveSecret(master, "c ap traffic", transcript_through_server_finished);
    key_schedule.expandLabel(&connection.server_app_key, server_ap_traffic, "key", "");
    key_schedule.expandLabel(&connection.server_app_iv, server_ap_traffic, "iv", "");
    key_schedule.expandLabel(&connection.client_app_key, client_ap_traffic, "key", "");
    key_schedule.expandLabel(&connection.client_app_iv, client_ap_traffic, "iv", "");
    connection.client_hs_seq = 0;
    connection.server_app_seq = 0;
    connection.client_app_seq = 0;

    return .{ .connection = connection, .to_send = writer.slice(), .alpn = selected_alpn };
}

/// Resume state carried between a HelloRetryRequest and the client's second ClientHello.
pub const RetryState = struct {
    opts: HandshakeOptions,
    /// transcript seeded with the synthetic message_hash(ClientHello1) + the HelloRetryRequest.
    transcript: key_schedule.Transcript,
    /// the group the client must send a key_share for in its second ClientHello.
    group: handshake.NamedGroup,
};

/// A HelloRetryRequest flight plus the state to resume from.
pub const RetryFlight = struct {
    to_send: []const u8,
    state: RetryState,
};

/// Emit a HelloRetryRequest (RFC 8446 4.1.4) when the ClientHello selected a supported group it gave
/// no key_share for: returns the HRR record + ChangeCipherSpec to send, plus the resume state.
/// Returns null when no retry is needed (the client already sent a usable key_share, so the caller
/// runs serverHandshake instead).
///
/// Note:
/// - The transcript follows RFC 8446 4.4.1: with an HRR, ClientHello1 is replaced in the running
///   hash by a synthetic message_hash message wrapping Hash(ClientHello1).
pub fn serverHelloRetry(opts: HandshakeOptions, client_hello1: []const u8, out: []u8) !?RetryFlight {
    const parsed = handshake.parseClientHello(client_hello1);
    if (parsed != .ok) return alertToError(parsed.alert);
    const hello = parsed.ok;

    const group = switch (handshake.negotiate(&hello, &.{}, opts.group_prefs)) {
        .hello_retry_request => |g| g,
        .server_hello => return null,
        .legacy_version => return error.ZixUnsupportedTlsVersion,
        .alert => |a| return alertToError(a),
    };

    var hrr_buf: [256]u8 = undefined;
    const hrr = handshake.serializeHelloRetryRequest(&hrr_buf, hello.session_id, .AES_128_GCM_SHA256, group);

    var writer = wire.Writer{ .buf = out };
    writeRecordHeader(&writer, 22, hrr.len);
    writer.writeBytes(hrr);
    writer.writeBytes(&ccs_record);

    // synthetic message_hash(ClientHello1) (RFC 8446 4.4.1), then the HelloRetryRequest.
    var ch1 = key_schedule.Transcript.init();
    ch1.update(client_hello1);
    const ch1_hash = ch1.current();

    var synthetic: [4 + key_schedule.hash_length]u8 = undefined;
    synthetic[0] = 0xfe; // handshake type message_hash (254)
    synthetic[1] = 0;
    synthetic[2] = 0;
    synthetic[3] = @intCast(key_schedule.hash_length);
    @memcpy(synthetic[4..], &ch1_hash);

    var transcript = key_schedule.Transcript.init();
    transcript.update(&synthetic);
    transcript.update(hrr);

    return .{ .to_send = writer.slice(), .state = .{ .opts = opts, .transcript = transcript, .group = group } };
}

/// Resume the handshake on the client's second ClientHello after a HelloRetryRequest. The retry is
/// allowed only once (RFC 8446 4.1.4): if the second ClientHello still lacks the key_share, or uses
/// a different group than the one requested, the handshake aborts.
pub fn serverHandshakeAfterRetry(state: RetryState, client_hello2: []const u8, out: []u8) !HandshakeResult {
    const parsed = handshake.parseClientHello(client_hello2);
    if (parsed != .ok) return alertToError(parsed.alert);
    const hello = parsed.ok;

    const negotiated = switch (handshake.negotiate(&hello, &.{}, state.opts.group_prefs)) {
        .server_hello => |params| params,
        .hello_retry_request => return error.ZixHelloRetryRequestUnsupported, // one retry only
        .legacy_version => return error.ZixUnsupportedTlsVersion,
        .alert => |a| return alertToError(a),
    };
    if (negotiated.group != state.group) return error.ZixHelloRetryGroupMismatch;

    var transcript = state.transcript;
    transcript.update(client_hello2);

    return completeHandshake(state.opts, &hello, negotiated, &transcript, out);
}

fn writeRecordHeader(writer: *wire.Writer, content_type: u8, length: usize) void {
    writer.writeU8(content_type);
    writer.writeU16(0x0303);
    writer.writeU16(@intCast(length));
}

/// The ephemeral ECDHE result for one handshake: the server public to put in the ServerHello
/// key_share (32 bytes for X25519, 65 for secp256r1 uncompressed) and the 32-byte shared secret.
const KeyExchange = struct {
    server_public: [65]u8,
    server_public_len: usize,
    shared: [32]u8,
};

/// Run the server side of ECDHE for the negotiated group (RFC 8446 7.4, 8422). The ephemeral
/// secret is injected (fresh per connection in production, a trace value in tests). For secp256r1
/// the shared secret is the X coordinate of the shared point (RFC 8446 7.4.2).
fn computeKeyExchange(group: NamedGroup, ephemeral_secret: [32]u8, client_public: []const u8) !KeyExchange {
    switch (group) {
        .X25519 => {
            if (client_public.len != 32) return error.ZixBadKeyShare;

            var client_pub: [32]u8 = undefined;
            @memcpy(&client_pub, client_public);
            const server_public = try X25519.recoverPublicKey(ephemeral_secret);
            const shared = try X25519.scalarmult(ephemeral_secret, client_pub);

            var kex = KeyExchange{ .server_public = undefined, .server_public_len = 32, .shared = shared };
            @memcpy(kex.server_public[0..32], &server_public);

            return kex;
        },
        .SECP256R1 => {
            const scalar = reduceP256Scalar(ephemeral_secret);
            const server_point = try P256.basePoint.mul(scalar, .big);
            const client_point = try P256.fromSec1(client_public);
            const shared_point = try client_point.mul(scalar, .big);

            return .{
                .server_public = server_point.toUncompressedSec1(),
                .server_public_len = 65,
                .shared = shared_point.affineCoordinates().x.toBytes(.big),
            };
        },
        else => return error.ZixUnsupportedGroup,
    }
}

/// Reduce 32 random bytes to a valid (non-zero, in-range) P-256 scalar. fromBytes48 reduces mod n,
/// so a zero-extended 256-bit seed maps uniformly enough for an ephemeral key.
fn reduceP256Scalar(seed: [32]u8) [32]u8 {
    var wide: [48]u8 = std.mem.zeroes([48]u8);
    @memcpy(wide[16..48], &seed);

    return P256.scalar.Scalar.fromBytes48(wide, .big).toBytes(.big);
}

/// Map a negotiation / parse alert to the error the caller surfaces.
fn alertToError(alert_desc: alert.Alert) anyerror {
    return switch (alert_desc) {
        .MISSING_EXTENSION => error.MissingExtension,
        .HANDSHAKE_FAILURE => error.HandshakeFailure,
        .ILLEGAL_PARAMETER => error.ZixIllegalParameter,
        .DECODE_ERROR => error.ZixDecodeError,
        else => error.HandshakeFailure,
    };
}

/// The condition -> fatal-alert matrix (RFC 8446 sec 6): map a serverHandshake failure back to the
/// AlertDescription the server must send before closing. null = no alert defined (close silently).
pub fn alertForError(err: anyerror) ?alert.Alert {
    return switch (err) {
        error.ZixNoApplicationProtocol => .NO_APPLICATION_PROTOCOL,
        error.MissingExtension => .MISSING_EXTENSION,
        error.ZixDecodeError => .DECODE_ERROR,
        error.ZixUnsupportedTlsVersion => .PROTOCOL_VERSION,
        error.ZixIllegalParameter, error.ZixMissingKeyShare, error.ZixBadKeyShare => .ILLEGAL_PARAMETER,
        error.HandshakeFailure, error.ZixUnsupportedCipher, error.ZixUnsupportedGroup, error.ZixHelloRetryRequestUnsupported, error.ZixNoCommonSignatureScheme => .HANDSHAKE_FAILURE,
        else => null,
    };
}

/// Build the plaintext fatal alert record for a serverHandshake failure, or null when no alert is
/// defined. The serve path writes this before closing. These failures all occur at ClientHello
/// processing, before the handshake keys exist, so the alert is sent in the clear.
pub fn alertRecordForError(buf: *[alert.fatal_record_len]u8, err: anyerror) ?[]const u8 {
    const desc = alertForError(err) orelse return null;

    return alert.fatalRecord(buf, desc);
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix tls: connection, server flight from RFC 8448 ClientHello" {
    var client_hello: [196]u8 = undefined;
    _ = try std.fmt.hexToBytes(&client_hello, "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");

    var server_hello: [90]u8 = undefined;
    _ = try std.fmt.hexToBytes(&server_hello, "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304");

    var ephemeral_secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ephemeral_secret, "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e");
    var server_random: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&server_random, "a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928");
    var scalar: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&scalar, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const key_pair = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(scalar));

    const dummy_der = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };

    var out: [4096]u8 = undefined;
    const result = try serverHandshake(.{
        .certificate_chain = &.{&dummy_der},
        .signing_key = .{ .ecdsa_p256 = key_pair },
        .ephemeral_secret = ephemeral_secret,
        .server_random = server_random,
    }, &client_hello, &out);

    // record 1: ServerHello plaintext handshake record, byte-exact vs the trace.
    var r = wire.Reader{ .buf = result.to_send };
    try std.testing.expectEqual(@as(u8, 22), try r.readU8());
    _ = try r.readU16();
    const sh_len = try r.readU16();
    try std.testing.expectEqualSlices(u8, &server_hello, try r.readBytes(sh_len));

    // record 2: legacy ChangeCipherSpec.
    try std.testing.expectEqual(@as(u8, 20), try r.readU8());
    _ = try r.readU16();
    const ccs_len = try r.readU16();
    try std.testing.expectEqualSlices(u8, &[_]u8{0x01}, try r.readBytes(ccs_len));

    // record 3: encrypted flight. With trace inputs the server handshake key is the trace key, so
    // deprotect it and confirm the inner handshake messages are EE, Certificate, CertVerify, Finished.
    try std.testing.expectEqual(@as(u8, 23), try r.readU8());
    _ = try r.readU16();
    const flight_len = try r.readU16();
    const flight_record = result.to_send[r.pos - 5 .. r.pos + flight_len];

    var hs_key: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&hs_key, "3fce516009c21727d0f2e4e86ee403bc");
    var hs_iv: [12]u8 = undefined;
    _ = try std.fmt.hexToBytes(&hs_iv, "5d313eb2671276ee13000b30");

    var plain: [4096]u8 = undefined;
    const opened = try record.deprotect(&plain, flight_record, hs_key, hs_iv, 0);
    try std.testing.expectEqual(record.ContentType.HANDSHAKE, opened.inner_type);

    var fr = wire.Reader{ .buf = opened.data };
    const expected_types = [_]u8{ 8, 11, 15, 20 };
    for (expected_types) |want| {
        try std.testing.expectEqual(want, try fr.readU8());
        const len = try fr.readU24();
        _ = try fr.readBytes(len);
    }
    try std.testing.expectEqual(@as(usize, 0), fr.remaining());
}

test "zix tls: connection, secp256r1 ECDHE shared secret is symmetric" {
    var a_seed: [32]u8 = undefined;
    var b_seed: [32]u8 = undefined;
    @memset(&a_seed, 0x11);
    @memset(&b_seed, 0x22);

    // b's public, then a derives ECDH(a, b_pub), b derives ECDH(b, a_pub), and both must match.
    const b_point = try P256.basePoint.mul(reduceP256Scalar(b_seed), .big);
    const b_pub = b_point.toUncompressedSec1();
    const kex_a = try computeKeyExchange(.SECP256R1, a_seed, &b_pub);
    const kex_b = try computeKeyExchange(.SECP256R1, b_seed, kex_a.server_public[0..kex_a.server_public_len]);

    try std.testing.expectEqual(@as(usize, 65), kex_a.server_public_len);
    try std.testing.expectEqualSlices(u8, &kex_a.shared, &kex_b.shared);
}

test "zix tls: connection, serverHandshake negotiates secp256r1 from a P-256-only ClientHello" {
    // a valid client secp256r1 key_share (a real point on the curve).
    var client_seed: [32]u8 = undefined;
    @memset(&client_seed, 0x33);
    const client_point = try P256.basePoint.mul(reduceP256Scalar(client_seed), .big);
    const client_pub = client_point.toUncompressedSec1();

    // ClientHello offering ONLY secp256r1 (group + key_share), plus the mandatory extensions.
    var ch_buf: [512]u8 = undefined;
    var w = wire.Writer{ .buf = &ch_buf };
    w.writeU8(@intFromEnum(handshake.HandshakeType.CLIENT_HELLO));
    const ch_header = w.placeU24();
    w.writeU16(handshake.VERSION_TLS_1_2);
    w.writeBytes(&std.mem.zeroes([32]u8)); // random
    w.writeU8(0); // empty session_id
    w.writeU16(2); // cipher_suites length
    w.writeU16(@intFromEnum(handshake.CipherSuite.AES_128_GCM_SHA256));
    w.writeU8(1); // compression length
    w.writeU8(0); // null compression

    const exts = w.placeU16();
    // supported_versions: [0x0304]
    w.writeU16(@intFromEnum(handshake.ExtensionType.SUPPORTED_VERSIONS));
    w.writeU16(3);
    w.writeU8(2);
    w.writeU16(handshake.VERSION_TLS_1_3);
    // signature_algorithms: [ecdsa_secp256r1_sha256] (presence is what negotiate checks)
    w.writeU16(@intFromEnum(handshake.ExtensionType.SIGNATURE_ALGORITHMS));
    w.writeU16(4);
    w.writeU16(2);
    w.writeU16(@intFromEnum(handshake.SignatureScheme.ECDSA_SECP256R1_SHA256));
    // supported_groups: [secp256r1]
    w.writeU16(@intFromEnum(handshake.ExtensionType.SUPPORTED_GROUPS));
    w.writeU16(4);
    w.writeU16(2);
    w.writeU16(@intFromEnum(handshake.NamedGroup.SECP256R1));
    // key_share: secp256r1 -> the 65-byte uncompressed point
    w.writeU16(@intFromEnum(handshake.ExtensionType.KEY_SHARE));
    const ks_ext = w.placeU16();
    const ks_list = w.placeU16();
    w.writeU16(@intFromEnum(handshake.NamedGroup.SECP256R1));
    w.writeU16(@intCast(client_pub.len));
    w.writeBytes(&client_pub);
    w.patchU16(ks_list);
    w.patchU16(ks_ext);
    w.patchU16(exts);
    w.patchU24(ch_header);

    var ephemeral_secret: [32]u8 = undefined;
    @memset(&ephemeral_secret, 0x44);
    var server_random: [32]u8 = undefined;
    @memset(&server_random, 0x55);
    var scalar: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&scalar, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const key_pair = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(scalar));
    const dummy_der = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };

    var out: [4096]u8 = undefined;
    const result = try serverHandshake(.{
        .certificate_chain = &.{&dummy_der},
        .signing_key = .{ .ecdsa_p256 = key_pair },
        .ephemeral_secret = ephemeral_secret,
        .server_random = server_random,
    }, w.slice(), &out);

    // the ServerHello key_share must echo secp256r1 with a 65-byte uncompressed (0x04) point.
    var r = wire.Reader{ .buf = result.to_send };
    try std.testing.expectEqual(@as(u8, 22), try r.readU8());
    _ = try r.readU16();
    const sh_len = try r.readU16();
    const sh = try r.readBytes(sh_len);

    var hr = wire.Reader{ .buf = sh };
    _ = try hr.readU8(); // server_hello type
    _ = try hr.readU24();
    _ = try hr.readU16(); // legacy_version
    _ = try hr.readBytes(32); // random
    const sid_len = try hr.readU8();
    _ = try hr.readBytes(sid_len);
    _ = try hr.readU16(); // cipher
    _ = try hr.readU8(); // compression
    const sh_ext_len = try hr.readU16();
    const sh_exts = try hr.readBytes(sh_ext_len);

    var er = wire.Reader{ .buf = sh_exts };
    var found_key_share = false;
    while (er.remaining() >= 4) {
        const ext_type = try er.readU16();
        const ext_len = try er.readU16();
        const ext_data = try er.readBytes(ext_len);
        if (ext_type == @intFromEnum(handshake.ExtensionType.KEY_SHARE)) {
            var kr = wire.Reader{ .buf = ext_data };
            try std.testing.expectEqual(@intFromEnum(handshake.NamedGroup.SECP256R1), try kr.readU16());
            const ke_len = try kr.readU16();
            const ke = try kr.readBytes(ke_len);
            try std.testing.expectEqual(@as(usize, 65), ke.len);
            try std.testing.expectEqual(@as(u8, 0x04), ke[0]);
            found_key_share = true;
        }
    }
    try std.testing.expect(found_key_share);
}

test "zix tls: connection, condition -> fatal-alert matrix" {
    try std.testing.expectEqual(alert.Alert.NO_APPLICATION_PROTOCOL, alertForError(error.ZixNoApplicationProtocol).?);
    try std.testing.expectEqual(alert.Alert.MISSING_EXTENSION, alertForError(error.MissingExtension).?);
    try std.testing.expectEqual(alert.Alert.PROTOCOL_VERSION, alertForError(error.ZixUnsupportedTlsVersion).?);
    try std.testing.expectEqual(alert.Alert.HANDSHAKE_FAILURE, alertForError(error.HandshakeFailure).?);
    try std.testing.expectEqual(alert.Alert.ILLEGAL_PARAMETER, alertForError(error.ZixMissingKeyShare).?);
    try std.testing.expectEqual(alert.Alert.DECODE_ERROR, alertForError(error.ZixDecodeError).?);
    try std.testing.expectEqual(alert.Alert.HANDSHAKE_FAILURE, alertForError(error.ZixNoCommonSignatureScheme).?);
    try std.testing.expect(alertForError(error.OutOfMemory) == null);

    // the record builder wires through for a representative condition.
    var buf: [alert.fatal_record_len]u8 = undefined;
    const rec = alertRecordForError(&buf, error.MissingExtension).?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 109 }, rec);
}

// shared fixture: self-signed CN=localhost, SAN DNS:localhost + IP:127.0.0.1, the same cert and
// scalar the other tls tests use (here it plays both the server cert and the client cert).
const fixture_cert_hex = "308201d43082017ba00302010202147a26ee491f091ac7c914f4a810c1ece713402574300a06082a8648ce3d040302302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f63301e170d3236303632323132353432305a170d3336303631393132353432305a302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f633059301306072a8648ce3d020106082a8648ce3d03010703420004c2a0121b298ac9cd389200e78d94e7bde1cc7cd8074795fab4f919799d40fdc231c5a90990ac8c6166ae472f33f74fced097f2edb7b8a1974be66a4ab07f253ba37f307d301d0603551d0e04160414c34e1d0a36a43947709b539e16dd0213aa4196aa301f0603551d23041830168014c34e1d0a36a43947709b539e16dd0213aa4196aa300f0603551d130101ff040530030101ff301a0603551d110413301182096c6f63616c686f737487047f000001300e0603551d0f0101ff040403020780300a06082a8648ce3d040302034700304402200b012f119db9b95d990bc482cb63e8f81e337a08634904e4caf513dc10c8aa8302202fdfe79ff6d5403e753ddf2aa52671923b8a2c28126bcbf196bd6fb7ecbcb14e";

test "zix tls: connection, mTLS server requests + verifies a client certificate (RFC 8446 4.3.2)" {
    var client_hello: [196]u8 = undefined;
    _ = try std.fmt.hexToBytes(&client_hello, "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");

    var ephemeral_secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ephemeral_secret, "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e");
    var server_random: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&server_random, "a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928");
    var scalar: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&scalar, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const key_pair = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(scalar));

    var cert_buf: [512]u8 = undefined;
    const cert_der = try std.fmt.hexToBytes(&cert_buf, fixture_cert_hex);

    var out: [4096]u8 = undefined;
    var result = try serverHandshake(.{
        .certificate_chain = &.{cert_der},
        .signing_key = .{ .ecdsa_p256 = key_pair },
        .ephemeral_secret = ephemeral_secret,
        .server_random = server_random,
        .request_client_cert = true,
    }, &client_hello, &out);

    // play the client auth flight: Certificate, then CertificateVerify signed over the transcript
    // through that Certificate, both encrypted under the client handshake key (seq 0, 1).
    var transcript = result.connection.handshake_transcript;

    var client_cert_msg_buf: [600]u8 = undefined;
    const client_cert_msg = certificate.buildCertificate(&client_cert_msg_buf, &.{cert_der});
    transcript.update(client_cert_msg);
    const transcript_through_cert = transcript.current();

    var cv_content_buf: [160]u8 = undefined;
    const cv_content = certificate.clientCertificateVerifyContent(&cv_content_buf, transcript_through_cert);
    const cv_sig = try key_pair.sign(cv_content, null);
    var cv_der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const cv_der = cv_sig.toDer(&cv_der_buf);

    var cv_msg_buf: [256]u8 = undefined;
    var cv_writer = wire.Writer{ .buf = &cv_msg_buf };
    cv_writer.writeU8(@intFromEnum(handshake.HandshakeType.CERTIFICATE_VERIFY));
    const cv_header = cv_writer.placeU24();
    cv_writer.writeU16(@intFromEnum(handshake.SignatureScheme.ECDSA_SECP256R1_SHA256));
    const cv_sig_field = cv_writer.placeU16();
    cv_writer.writeBytes(cv_der);
    cv_writer.patchU16(cv_sig_field);
    cv_writer.patchU24(cv_header);
    const cv_msg = cv_writer.slice();

    var cert_rec_buf: [700]u8 = undefined;
    const cert_rec = record.protect(&cert_rec_buf, client_cert_msg, .HANDSHAKE, result.connection.client_hs_key, result.connection.client_hs_iv, 0);
    var cv_rec_buf: [320]u8 = undefined;
    const cv_rec = record.protect(&cv_rec_buf, cv_msg, .HANDSHAKE, result.connection.client_hs_key, result.connection.client_hs_iv, 1);

    var got_der_buf: [512]u8 = undefined;
    const got_der = try result.connection.verifyClientCertFlight(cert_rec, cv_rec, &got_der_buf);
    try std.testing.expectEqualSlices(u8, cert_der, got_der);

    // the trust step (Layer V) composes on the returned DER: self-signed chain + SAN.
    try cert_verify.verifyCertChain(got_der, got_der, 1_800_000_000);
    try cert_verify.verifyCertHostname(got_der, "localhost");

    // the client Finished now binds the transcript through the CertificateVerify (seq 2).
    transcript.update(cv_msg);
    var fin_msg_buf: [64]u8 = undefined;
    const fin_msg = certificate.buildFinished(&fin_msg_buf, result.connection.client_finished_key, transcript.current());
    var fin_rec_buf: [128]u8 = undefined;
    const fin_rec = record.protect(&fin_rec_buf, fin_msg, .HANDSHAKE, result.connection.client_hs_key, result.connection.client_hs_iv, 2);

    try result.connection.verifyClientFinished(fin_rec);
}

test "zix tls: connection, mTLS rejects a tampered client CertificateVerify" {
    var client_hello: [196]u8 = undefined;
    _ = try std.fmt.hexToBytes(&client_hello, "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");

    var ephemeral_secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ephemeral_secret, "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e");
    var server_random: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&server_random, "a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928");
    var scalar: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&scalar, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const key_pair = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(scalar));

    var cert_buf: [512]u8 = undefined;
    const cert_der = try std.fmt.hexToBytes(&cert_buf, fixture_cert_hex);

    var out: [4096]u8 = undefined;
    var result = try serverHandshake(.{
        .certificate_chain = &.{cert_der},
        .signing_key = .{ .ecdsa_p256 = key_pair },
        .ephemeral_secret = ephemeral_secret,
        .server_random = server_random,
        .request_client_cert = true,
    }, &client_hello, &out);

    var transcript = result.connection.handshake_transcript;
    var client_cert_msg_buf: [600]u8 = undefined;
    const client_cert_msg = certificate.buildCertificate(&client_cert_msg_buf, &.{cert_der});
    transcript.update(client_cert_msg);

    // sign the WRONG transcript (not folding the client Certificate) so the binding fails.
    var cv_content_buf: [160]u8 = undefined;
    const cv_content = certificate.clientCertificateVerifyContent(&cv_content_buf, result.connection.handshake_transcript.current());
    const cv_sig = try key_pair.sign(cv_content, null);
    var cv_der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const cv_der = cv_sig.toDer(&cv_der_buf);

    var cv_msg_buf: [256]u8 = undefined;
    var cv_writer = wire.Writer{ .buf = &cv_msg_buf };
    cv_writer.writeU8(@intFromEnum(handshake.HandshakeType.CERTIFICATE_VERIFY));
    const cv_header = cv_writer.placeU24();
    cv_writer.writeU16(@intFromEnum(handshake.SignatureScheme.ECDSA_SECP256R1_SHA256));
    const cv_sig_field = cv_writer.placeU16();
    cv_writer.writeBytes(cv_der);
    cv_writer.patchU16(cv_sig_field);
    cv_writer.patchU24(cv_header);
    const cv_msg = cv_writer.slice();

    var cert_rec_buf: [700]u8 = undefined;
    const cert_rec = record.protect(&cert_rec_buf, client_cert_msg, .HANDSHAKE, result.connection.client_hs_key, result.connection.client_hs_iv, 0);
    var cv_rec_buf: [320]u8 = undefined;
    const cv_rec = record.protect(&cv_rec_buf, cv_msg, .HANDSHAKE, result.connection.client_hs_key, result.connection.client_hs_iv, 1);

    var got_der_buf: [512]u8 = undefined;
    try std.testing.expectError(error.SignatureVerificationFailed, result.connection.verifyClientCertFlight(cert_rec, cv_rec, &got_der_buf));
}

test "zix tls: connection, mTLS verifies a coalesced client auth flight (one record)" {
    var client_hello: [196]u8 = undefined;
    _ = try std.fmt.hexToBytes(&client_hello, "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001");

    var ephemeral_secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&ephemeral_secret, "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e");
    var server_random: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&server_random, "a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928");
    var scalar: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&scalar, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const key_pair = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(scalar));

    var cert_buf: [512]u8 = undefined;
    const cert_der = try std.fmt.hexToBytes(&cert_buf, fixture_cert_hex);

    var out: [4096]u8 = undefined;
    var result = try serverHandshake(.{
        .certificate_chain = &.{cert_der},
        .signing_key = .{ .ecdsa_p256 = key_pair },
        .ephemeral_secret = ephemeral_secret,
        .server_random = server_random,
        .request_client_cert = true,
    }, &client_hello, &out);

    // pack Certificate, CertificateVerify, Finished into one plaintext buffer (the openssl framing).
    var transcript = result.connection.handshake_transcript;
    var flight_buf: [1024]u8 = undefined;
    var flight = wire.Writer{ .buf = &flight_buf };

    const client_cert_msg = certificate.buildCertificate(flight.buf[flight.len..], &.{cert_der});
    flight.len += client_cert_msg.len;
    transcript.update(client_cert_msg);
    const transcript_through_cert = transcript.current();

    var cv_content_buf: [160]u8 = undefined;
    const cv_content = certificate.clientCertificateVerifyContent(&cv_content_buf, transcript_through_cert);
    const cv_sig = try key_pair.sign(cv_content, null);
    var cv_der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const cv_der = cv_sig.toDer(&cv_der_buf);

    var cv_writer = wire.Writer{ .buf = flight.buf[flight.len..] };
    cv_writer.writeU8(@intFromEnum(handshake.HandshakeType.CERTIFICATE_VERIFY));
    const cv_header = cv_writer.placeU24();
    cv_writer.writeU16(@intFromEnum(handshake.SignatureScheme.ECDSA_SECP256R1_SHA256));
    const cv_sig_field = cv_writer.placeU16();
    cv_writer.writeBytes(cv_der);
    cv_writer.patchU16(cv_sig_field);
    cv_writer.patchU24(cv_header);
    const cv_msg = cv_writer.slice();
    flight.len += cv_msg.len;
    transcript.update(cv_msg);

    const fin_msg = certificate.buildFinished(flight.buf[flight.len..], result.connection.client_finished_key, transcript.current());
    flight.len += fin_msg.len;

    var flight_rec_buf: [1100]u8 = undefined;
    const flight_rec = record.protect(&flight_rec_buf, flight.slice(), .HANDSHAKE, result.connection.client_hs_key, result.connection.client_hs_iv, 0);

    var got_der_buf: [512]u8 = undefined;
    const got_der = try result.connection.verifyClientAuthFlight(flight_rec, &got_der_buf);
    try std.testing.expectEqualSlices(u8, cert_der, got_der);

    try cert_verify.verifyCertChain(got_der, got_der, 1_800_000_000);
}

test "zix tls: connection, readAppData classifies post-handshake inner types (RFC 8446 5.1)" {
    // Only the application-key fields matter here, set them to a known key and leave the rest undefined.
    var conn: Connection = undefined;
    conn.client_app_key = @splat(0xAB);
    conn.client_app_iv = @splat(0xCD);
    conn.client_app_seq = 0;

    const key: [record.key_length]u8 = @splat(0xAB);
    const iv: [record.iv_length]u8 = @splat(0xCD);

    // application_data inner type -> the plaintext is returned.
    var rec_buf: [256]u8 = undefined;
    const app_rec = record.protect(&rec_buf, "hello", .APPLICATION_DATA, key, iv, 0);
    var out: [256]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "hello", try conn.readAppData(app_rec, &out));

    // handshake inner type (post-handshake renegotiation / KeyUpdate) -> unexpected_message.
    conn.client_app_seq = 1;
    const hs_rec = record.protect(&rec_buf, &[_]u8{ 1, 0, 0, 0 }, .HANDSHAKE, key, iv, 1);
    try std.testing.expectError(error.ZixUnexpectedMessage, conn.readAppData(hs_rec, &out));

    // alert inner type (a post-handshake closure / fatal alert) -> peer closed.
    conn.client_app_seq = 2;
    const alert_rec = record.protect(&rec_buf, &[_]u8{ 1, 0 }, .ALERT, key, iv, 2);
    try std.testing.expectError(error.ZixPeerClosed, conn.readAppData(alert_rec, &out));
}

test "zix tls: connection, writeAppData2 gather round-trips through readAppData" {
    // Server encrypts a gathered (prefix, payload). A peer with the same app key decrypts prefix||payload.
    var server: Connection = undefined;
    server.server_app_key = @splat(0x24);
    server.server_app_iv = @splat(0x68);
    server.server_app_seq = 0;

    var client: Connection = undefined;
    client.client_app_key = @splat(0x24);
    client.client_app_iv = @splat(0x68);
    client.client_app_seq = 0;

    const prefix = "\x00\x00\x05\x00\x01\x00\x00\x00\x03";
    const payload = "abcde";

    var rec_buf: [256]u8 = undefined;
    const rec = server.writeAppData2(prefix, payload, &rec_buf);
    try std.testing.expectEqual(@as(u64, 1), server.server_app_seq);

    var expect: [64]u8 = undefined;
    @memcpy(expect[0..prefix.len], prefix);
    @memcpy(expect[prefix.len..][0..payload.len], payload);

    var out: [256]u8 = undefined;
    try std.testing.expectEqualSlices(u8, expect[0 .. prefix.len + payload.len], try client.readAppData(rec, &out));
}

test "zix tls: connection, encryptedAlert emits a fatal alert decryptable as an ALERT record" {
    var conn: Connection = undefined;
    conn.server_app_key = @splat(0x11);
    conn.server_app_iv = @splat(0x22);
    conn.server_app_seq = 0;

    var out: [64]u8 = undefined;
    const rec = conn.encryptedAlert(.UNEXPECTED_MESSAGE, &out);

    const key: [record.key_length]u8 = @splat(0x11);
    const iv: [record.iv_length]u8 = @splat(0x22);
    var plain: [64]u8 = undefined;
    const opened = try record.deprotect(&plain, rec, key, iv, 0);
    try std.testing.expectEqual(record.ContentType.ALERT, opened.inner_type);

    const parsed = try alert.parseInbound(opened.data);
    try std.testing.expect(parsed.isFatal());
    try std.testing.expectEqual(@as(u8, @intFromEnum(alert.Alert.UNEXPECTED_MESSAGE)), parsed.description);
}

/// Test helper: build a ClientHello offering x25519 + secp256r1 groups, with key_shares only for the
/// groups passed in (null = offered in supported_groups but no key_share, the HRR trigger).
fn buildHrrClientHello(buf: []u8, x25519_share: ?[]const u8, secp_share: ?[]const u8) []const u8 {
    var w = wire.Writer{ .buf = buf };
    w.writeU8(@intFromEnum(handshake.HandshakeType.CLIENT_HELLO));
    const header = w.placeU24();
    w.writeU16(0x0303); // legacy_version
    const zero_random: [32]u8 = @splat(0);
    w.writeBytes(&zero_random); // random
    w.writeU8(0); // empty session_id
    w.writeU16(2); // cipher_suites length
    w.writeU16(0x1301); // TLS_AES_128_GCM_SHA256
    w.writeU8(1); // compression methods length
    w.writeU8(0); // null

    const exts = w.placeU16();
    // supported_versions: 0x0304
    w.writeU16(0x002b);
    w.writeU16(3);
    w.writeU8(2);
    w.writeU16(0x0304);
    // signature_algorithms: ecdsa_secp256r1_sha256
    w.writeU16(0x000d);
    w.writeU16(4);
    w.writeU16(2);
    w.writeU16(0x0403);
    // supported_groups: x25519, secp256r1
    w.writeU16(0x000a);
    w.writeU16(6);
    w.writeU16(4);
    w.writeU16(0x001d);
    w.writeU16(0x0017);
    // key_share
    w.writeU16(0x0033);
    const ks_ext = w.placeU16();
    const ks_list = w.placeU16();
    if (x25519_share) |s| {
        w.writeU16(0x001d);
        w.writeU16(@intCast(s.len));
        w.writeBytes(s);
    }
    if (secp_share) |s| {
        w.writeU16(0x0017);
        w.writeU16(@intCast(s.len));
        w.writeBytes(s);
    }
    w.patchU16(ks_list);
    w.patchU16(ks_ext);
    w.patchU16(exts);
    w.patchU24(header);

    return w.slice();
}

test "zix tls: connection, HelloRetryRequest round trip (RFC 8446 4.1.4)" {
    var scalar: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&scalar, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const key_pair = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(scalar));
    const dummy_der = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };
    const opts = HandshakeOptions{
        .certificate_chain = &.{&dummy_der},
        .signing_key = .{ .ecdsa_p256 = key_pair },
        .ephemeral_secret = @splat(0x99),
        .server_random = @splat(0x55),
    };

    const client_x25519 = try X25519.recoverPublicKey(@splat(0x42));
    var dummy_secp: [65]u8 = @splat(0xAB); // 65-byte point, content unused (HRR precedes ECDHE)
    dummy_secp[0] = 0x04;

    // ClientHello 1: offers x25519 but only a secp256r1 key_share -> the server asks it to retry.
    var ch1_buf: [512]u8 = undefined;
    const ch1 = buildHrrClientHello(&ch1_buf, null, &dummy_secp);

    var out1: [1024]u8 = undefined;
    const retry = (try serverHelloRetry(opts, ch1, &out1)) orelse return error.ZixExpectedRetry;

    // the emitted record is a ServerHello carrying the HelloRetryRequest random sentinel.
    try std.testing.expectEqual(@as(u8, 22), retry.to_send[0]);
    try std.testing.expectEqual(@as(u8, 0x02), retry.to_send[5]);
    try std.testing.expectEqualSlices(u8, &handshake.hello_retry_request_random, retry.to_send[11..43]);

    // ClientHello 2: now carries the requested x25519 key_share -> the handshake completes.
    var ch2_buf: [512]u8 = undefined;
    const ch2 = buildHrrClientHello(&ch2_buf, &client_x25519, null);

    var out2: [4096]u8 = undefined;
    const result = try serverHandshakeAfterRetry(retry.state, ch2, &out2);
    try std.testing.expect(result.to_send.len > 0);
    try std.testing.expectEqual(@as(u8, 0x02), result.to_send[5]); // a real ServerHello
    try std.testing.expect(!std.mem.eql(u8, &handshake.hello_retry_request_random, result.to_send[11..43]));

    // a ClientHello that already has the x25519 key_share needs no retry.
    var ch3_buf: [512]u8 = undefined;
    const ch3 = buildHrrClientHello(&ch3_buf, &client_x25519, null);
    var out3: [1024]u8 = undefined;
    try std.testing.expect((try serverHelloRetry(opts, ch3, &out3)) == null);
}
