//! DTLS 1.2 server handshake (RFC 6347), ECDHE-ECDSA with AES-128-GCM.
//!
//! What:
//! - The sans-I/O driver that turns the DTLS building blocks into a finished association, in
//!   three steps: answer a ClientHello with a cookie, send the server flight, then derive keys
//!   and exchange Finished messages.
//! - Composes dtls_record, dtls_handshake, dtls_hello, dtls_cookie, and the TLS 1.2 key schedule
//!   in tls12_prf. It reuses the leaf primitives of the TLS 1.2 path and none of its framing.
//!
//! Note:
//! - This does NOT ride tls12_connection.zig, and the reason is the Finished MAC. RFC 6347 4.2.6
//!   computes the handshake transcript over the DTLS handshake headers, message_seq and fragment
//!   fields included, as if every message had been sent unfragmented, and it excludes the first
//!   ClientHello and the HelloVerifyRequest. tls12_connection.zig hashes TLS-framed bytes, so
//!   reusing it would produce a Finished no DTLS peer accepts. That path is left untouched.
//! - Server side only, matching the 1.2 path. A zix peer answers, it does not dial out.
//! - Every message this file emits is unfragmented when it fits the fragment limit, so the bytes
//!   written are already the canonical form the transcript hashes.
//! - Epoch 0 is the plaintext handshake, epoch 1 begins at ChangeCipherSpec. Record sequence
//!   numbers restart at 0 for the new epoch (RFC 6347 4.1).
//!
//! Usage:
//! ```zig
//! // First ClientHello: answer with a cookie and keep no state.
//! const verify = try serverHelloVerifyRequest(&signer, peer, hello, record_seq, &out);
//!
//! // Second ClientHello, cookie checked: send the server flight.
//! const flight = try serverFlight(opts, &signer, peer, hello_message, &out);
//!
//! // ClientKeyExchange and the client Finished: derive keys and finish.
//! var state = flight.state;
//! const done = try serverFinish(&state, cke_body, finished_record, &out);
//! ```

const std = @import("std");

const wire = @import("wire.zig");
const prf = @import("tls12_prf.zig");
const dtls_record = @import("dtls_record.zig");
const dtls_handshake = @import("dtls_handshake.zig");
const dtls_hello = @import("dtls_hello.zig");
const dtls_cookie = @import("dtls_cookie.zig");
const dtls_use_srtp = @import("dtls_use_srtp.zig");
const dtls_exporter = @import("dtls_exporter.zig");

const P256 = std.crypto.ecc.P256;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const IpAddress = std.Io.net.IpAddress;

/// The one suite this path implements, matching the TLS 1.2 server (RFC 5289).
pub const CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256: u16 = 0xC02B;

/// Epoch of the plaintext handshake.
pub const EPOCH_HANDSHAKE: u16 = 0;

/// Epoch that begins at ChangeCipherSpec.
pub const EPOCH_APPLICATION: u16 = 1;

/// Default ceiling on one handshake fragment body, sized so a record fits inside a 1200-byte
/// datagram with room for IP and UDP headers.
pub const DEFAULT_MAX_FRAGMENT: usize = 1024;

const NAMED_CURVE_SECP256R1: u16 = 0x0017;
const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const ECCURVE_TYPE_NAMED_CURVE: u8 = 3;
const VERIFY_DATA_LEN: usize = 12;

/// message_seq is per side and counts every handshake message that side sends, retransmissions
/// reusing the same value (RFC 6347 4.2.2). The server's HelloVerifyRequest is its message 0,
/// which is why its flight starts at 1.
const SEQ_HELLO_VERIFY_REQUEST: u16 = 0;
const SEQ_SERVER_HELLO: u16 = 1;
const SEQ_CERTIFICATE: u16 = 2;
const SEQ_SERVER_KEY_EXCHANGE: u16 = 3;
const SEQ_SERVER_HELLO_DONE: u16 = 4;
const SEQ_SERVER_FINISHED: u16 = 5;
const SEQ_CLIENT_KEY_EXCHANGE: u16 = 2;
const SEQ_CLIENT_FINISHED: u16 = 3;

pub const Error = error{
    /// The ClientHello did not parse, or offered nothing this server implements.
    ZixClientHelloInvalid,
    /// The client did not offer the one supported cipher suite.
    ZixNoSharedCipherSuite,
    /// A message arrived that does not belong at this point in the handshake.
    ZixUnexpectedMessage,
    /// The client Finished did not match the transcript. The handshake is over.
    ZixClientFinishedMismatch,
    /// The output buffer cannot hold the flight.
    ZixNoSpace,
};

/// What the server brings to a handshake.
pub const HandshakeOptions = struct {
    certificate_der: []const u8,
    signing_key: EcdsaP256.KeyPair,
    /// Seed for the ephemeral ECDHE scalar. Fresh per handshake, never reused.
    server_eph_secret: [32]u8,
    server_random: [32]u8,
    /// Largest handshake fragment body this server emits.
    max_fragment_len: usize = DEFAULT_MAX_FRAGMENT,
    /// Where this server's epoch 0 record numbering has already reached. A HelloVerifyRequest went
    /// out on that epoch before this flight, so starting over at zero gives two records the same
    /// (epoch, sequence) and a peer with an anti-replay window (RFC 6347 4.1.2.6) throws the second
    /// one away. The caller passes one past the sequence its HelloVerifyRequest used.
    first_record_seq: u48 = 0,
    /// SRTP profiles this server will carry, best first (RFC 5764 4.1). Empty declines media: the
    /// ServerHello echoes no use_srtp extension, and a peer that offered one still gets a plain
    /// DTLS association, just with no SRTP keys exported for it.
    srtp_profiles: []const dtls_exporter.SrtpProfile = &.{},
};

/// Carried from the server flight into the finish: the randoms, the ephemeral scalar, the running
/// transcript, and where the record sequence has reached.
pub const State = struct {
    client_random: [32]u8,
    server_random: [32]u8,
    server_eph_scalar: [32]u8,
    transcript: Sha256,
    /// Next record sequence number in epoch 0.
    next_record_seq: u48,
    /// What use_srtp settled on, or null when neither side asked for media. The finish exports
    /// keys for exactly this profile, and the SRTP layer above reads its tag lengths from it.
    srtp_profile: ?dtls_exporter.SrtpProfile = null,
};

pub const Flight = struct {
    /// One or more DTLS records, back to back. The caller packs them into datagrams, splitting
    /// only on record boundaries.
    to_send: []const u8,
    state: State,
};

pub const FinishResult = struct {
    to_send: []const u8,
    connection: Connection,
    /// The SRTP master keys and salts for the profile use_srtp agreed on, or null when no profile
    /// was agreed. Exported here because this is the only point where the master secret exists
    /// (RFC 5764 4.2), and it is deliberately not kept on Connection: a caller that wants media
    /// takes these keys once and builds its own SRTP sessions from them.
    srtp_keys: ?dtls_exporter.SrtpKeys = null,
    /// The profile those keys belong to. The two travel together, because a key with the wrong
    /// profile picks the wrong authentication tag length and every packet fails to open.
    srtp_profile: ?dtls_exporter.SrtpProfile = null,
};

/// An established association: the keys, the send sequence, and the receive replay window.
pub const Connection = struct {
    km: prf.KeyMaterial,
    /// Next record sequence number this server sends in epoch 1. Starts at 1, after the Finished
    /// that used 0.
    server_seq: u48 = 1,
    /// Replay window for epoch 1. Sequence 0 was the client Finished, already accepted.
    replay: dtls_record.AntiReplay = .{},

    /// Protect application data for the peer.
    pub fn writeAppData(self: *Connection, plaintext: []const u8, out: []u8) dtls_record.Error![]const u8 {
        const bytes = try dtls_record.protect(
            out,
            plaintext,
            .APPLICATION_DATA,
            EPOCH_APPLICATION,
            self.server_seq,
            self.km.server_write_key,
            self.km.server_write_iv,
        );
        self.server_seq += 1;

        return bytes;
    }

    /// Open an application-data record from the peer.
    ///
    /// Note:
    /// - The replay window is consulted BEFORE the AEAD and updated only after it, so a forged
    ///   record at a far-ahead sequence number cannot slide the window and lock out real traffic.
    /// - A record from another epoch is not an error, it is reordering. Drop it.
    ///
    /// Return:
    /// - []const u8 (the plaintext, borrowing out)
    /// - null when the record is a replay or belongs to another epoch, so discard it
    /// - error when the record is malformed or fails authentication, which is also a discard,
    ///   but one worth counting
    pub fn readAppData(self: *Connection, bytes: []const u8, out: []u8) dtls_record.Error!?[]const u8 {
        const header = try dtls_record.parseHeader(bytes);

        if (header.epoch != EPOCH_APPLICATION) return null;
        if (!self.replay.isNew(header.sequence_number)) return null;

        const opened = try dtls_record.deprotect(out, bytes, self.km.client_write_key, self.km.client_write_iv);
        self.replay.accept(header.sequence_number);

        return opened.data;
    }
};

/// Answer a first ClientHello with a HelloVerifyRequest (RFC 6347 4.2.1).
///
/// Note:
/// - No state is created here, which is the point. A source address that cannot receive the
///   cookie never gets any further.
/// - The reply reuses the ClientHello's own record sequence number, which RFC 6347 4.2.1
///   requires so repeated cookie exchanges cannot collide.
/// - Neither this message nor the ClientHello that triggered it enters the transcript
///   (RFC 6347 4.2.6).
///
/// Param:
/// signer - *const dtls_cookie.Signer
/// peer - std.Io.net.IpAddress (source of the ClientHello)
/// hello - dtls_hello.ClientHello (already parsed)
/// client_record_seq - u48 (record sequence the ClientHello arrived on)
/// out - []u8
///
/// Return:
/// - []const u8 (one DTLS record, borrowing out)
pub fn serverHelloVerifyRequest(
    signer: *const dtls_cookie.Signer,
    peer: IpAddress,
    hello: dtls_hello.ClientHello,
    client_record_seq: u48,
    out: []u8,
) Error![]const u8 {
    const cookie = signer.generate(peer, hello.paramsForCookie());

    var body_buf: [64]u8 = undefined;
    const body = dtls_hello.writeHelloVerifyRequestBody(&body_buf, &cookie) catch return error.ZixNoSpace;

    var message_buf: [96]u8 = undefined;
    var fragmenter: dtls_handshake.Fragmenter = .{
        .msg_type = .HELLO_VERIFY_REQUEST,
        .message_seq = SEQ_HELLO_VERIFY_REQUEST,
        .body = body,
        .max_fragment_len = body.len,
    };
    const message = fragmenter.next(&message_buf) orelse return error.ZixNoSpace;

    return dtls_record.writePlaintext(out, .HANDSHAKE, EPOCH_HANDSHAKE, client_record_seq, message) catch
        error.ZixNoSpace;
}

/// Whether a ClientHello carries a cookie this server issued to this peer.
///
/// Note:
/// - An invalid cookie is not an error, it reads exactly like no cookie at all (RFC 6347 4.2.1).
///   A client holding a cookie signed by a rotated-out secret must be able to try again rather
///   than deadlock.
pub fn cookieAccepted(signer: *const dtls_cookie.Signer, peer: IpAddress, hello: dtls_hello.ClientHello) bool {
    if (!hello.hasCookie()) return false;

    return signer.verify(peer, hello.paramsForCookie(), hello.cookie);
}

/// Send the server flight: ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
/// (RFC 6347 4.2.4 flight 4).
///
/// Note:
/// - `client_hello_body` must be the body of the ClientHello that CARRIED THE COOKIE. That one
///   enters the transcript, the first one never does.
/// - Each message goes in its own record, so a caller can drop them into datagrams on record
///   boundaries without re-fragmenting anything.
///
/// Param:
/// opts - HandshakeOptions
/// client_hello_body - []const u8 (handshake body, header stripped)
/// out - []u8 (destination for the whole flight)
///
/// Return:
/// - Flight (records to send plus the state the finish needs)
/// - Error
pub fn serverFlight(opts: HandshakeOptions, client_hello_body: []const u8, out: []u8) Error!Flight {
    const hello = dtls_hello.parseClientHello(client_hello_body) catch return error.ZixClientHelloInvalid;

    if (!hello.offersCipherSuite(CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256)) return error.ZixNoSharedCipherSuite;

    var state: State = .{
        .client_random = hello.random,
        .server_random = opts.server_random,
        .server_eph_scalar = reduceP256Scalar(opts.server_eph_secret),
        .transcript = Sha256.init(.{}),
        .next_record_seq = opts.first_record_seq,
        .srtp_profile = selectSrtpProfile(hello.extensions, opts.srtp_profiles),
    };

    // The cookie-bearing ClientHello opens the transcript (RFC 6347 4.2.6).
    updateTranscript(&state.transcript, .CLIENT_HELLO, hello_message_seq_with_cookie, client_hello_body);

    const server_point = (P256.basePoint.mul(state.server_eph_scalar, .big) catch
        return error.ZixClientHelloInvalid).toUncompressedSec1();

    var cursor: usize = 0;
    var body_buf: [2048]u8 = undefined;

    {
        var writer = wire.Writer{ .buf = &body_buf };
        writeServerHelloBody(&writer, state.server_random, hello.session_id, state.srtp_profile);
        cursor += try emitMessage(out[cursor..], &state, .SERVER_HELLO, SEQ_SERVER_HELLO, writer.slice(), opts.max_fragment_len);
    }

    {
        var writer = wire.Writer{ .buf = &body_buf };
        if (opts.certificate_der.len + 6 > body_buf.len) return error.ZixNoSpace;
        writeCertificateBody(&writer, opts.certificate_der);
        cursor += try emitMessage(out[cursor..], &state, .CERTIFICATE, SEQ_CERTIFICATE, writer.slice(), opts.max_fragment_len);
    }

    {
        var writer = wire.Writer{ .buf = &body_buf };
        writeServerKeyExchangeBody(&writer, opts.signing_key, state.client_random, state.server_random, &server_point) catch
            return error.ZixClientHelloInvalid;
        cursor += try emitMessage(out[cursor..], &state, .SERVER_KEY_EXCHANGE, SEQ_SERVER_KEY_EXCHANGE, writer.slice(), opts.max_fragment_len);
    }

    cursor += try emitMessage(out[cursor..], &state, .SERVER_HELLO_DONE, SEQ_SERVER_HELLO_DONE, "", opts.max_fragment_len);

    return .{ .to_send = out[0..cursor], .state = state };
}

/// Finish the handshake: derive keys from ClientKeyExchange, verify the client Finished, and send
/// ChangeCipherSpec plus the server Finished (RFC 6347 4.2.4 flight 6).
///
/// Note:
/// - The client Finished arrives protected under epoch 1 at record sequence 0, because a new
///   epoch restarts its sequence numbers.
/// - ChangeCipherSpec is not a handshake message. It takes no message_seq and never enters the
///   transcript (RFC 6347 4.2.5).
///
/// Param:
/// state - *State (from serverFlight, advanced in place)
/// client_key_exchange_body - []const u8 (reassembled body, header stripped)
/// client_finished_record - []const u8 (one complete protected record)
/// out - []u8
///
/// Return:
/// - FinishResult (records to send plus the established Connection)
/// - Error
pub fn serverFinish(
    state: *State,
    client_key_exchange_body: []const u8,
    client_finished_record: []const u8,
    out: []u8,
) Error!FinishResult {
    var reader = wire.Reader{ .buf = client_key_exchange_body };
    const point_len = reader.readU8() catch return error.ZixUnexpectedMessage;
    const client_point = reader.readBytes(point_len) catch return error.ZixUnexpectedMessage;

    updateTranscript(&state.transcript, .CLIENT_KEY_EXCHANGE, SEQ_CLIENT_KEY_EXCHANGE, client_key_exchange_body);

    const pre_master = ecdheSharedX(state.server_eph_scalar, client_point) catch return error.ZixUnexpectedMessage;
    const master = prf.masterSecret(&pre_master, state.client_random, state.server_random);
    const km = prf.keyMaterial(master, state.client_random, state.server_random);

    const expected = prf.finishedFromHash(master, "client finished", transcriptHash(state));

    var plain_buf: [128]u8 = undefined;
    const opened = dtls_record.deprotect(&plain_buf, client_finished_record, km.client_write_key, km.client_write_iv) catch
        return error.ZixUnexpectedMessage;

    if (opened.header.epoch != EPOCH_APPLICATION) return error.ZixUnexpectedMessage;

    const finished_header = dtls_handshake.parseHeader(opened.data) catch return error.ZixUnexpectedMessage;
    if (finished_header.msg_type != .FINISHED) return error.ZixUnexpectedMessage;

    const client_verify_data = opened.data[dtls_handshake.HEADER_LEN..];
    if (client_verify_data.len != VERIFY_DATA_LEN) return error.ZixUnexpectedMessage;
    if (!std.mem.eql(u8, client_verify_data, &expected)) return error.ZixClientFinishedMismatch;

    updateTranscript(&state.transcript, .FINISHED, SEQ_CLIENT_FINISHED, client_verify_data);

    const server_verify_data = prf.finishedFromHash(master, "server finished", transcriptHash(state));

    var finished_message: [dtls_handshake.HEADER_LEN + VERIFY_DATA_LEN]u8 = undefined;
    dtls_handshake.writeHeader(&finished_message, .{
        .msg_type = .FINISHED,
        .length = VERIFY_DATA_LEN,
        .message_seq = SEQ_SERVER_FINISHED,
        .fragment_offset = 0,
        .fragment_length = VERIFY_DATA_LEN,
    });
    @memcpy(finished_message[dtls_handshake.HEADER_LEN..], &server_verify_data);

    // ChangeCipherSpec closes epoch 0, the Finished that follows is the first record of epoch 1.
    const ccs = dtls_record.writePlaintext(out, .CHANGE_CIPHER_SPEC, EPOCH_HANDSHAKE, state.next_record_seq, &[_]u8{1}) catch
        return error.ZixNoSpace;
    state.next_record_seq += 1;

    const finished = dtls_record.protect(
        out[ccs.len..],
        &finished_message,
        .HANDSHAKE,
        EPOCH_APPLICATION,
        0,
        km.server_write_key,
        km.server_write_iv,
    ) catch return error.ZixNoSpace;

    // The master secret exists only inside this function, so the SRTP export happens here or not
    // at all (RFC 5764 4.2). A profile that carries no cipher key exports nothing and is reported
    // as no media rather than as a failure.
    var srtp_keys: ?dtls_exporter.SrtpKeys = null;

    if (state.srtp_profile) |profile| {
        srtp_keys = dtls_exporter.srtpKeys(profile, master, state.client_random, state.server_random) catch null;
    }

    return .{
        .to_send = out[0 .. ccs.len + finished.len],
        .connection = .{ .km = km },
        .srtp_keys = srtp_keys,
        .srtp_profile = if (srtp_keys == null) null else state.srtp_profile,
    };
}

/// message_seq of the ClientHello that carries a cookie. The first one is 0, and it is not part
/// of the handshake the transcript covers.
const hello_message_seq_with_cookie: u16 = 1;

/// Hash one handshake message the way RFC 6347 4.2.6 requires: the 12-byte header with the
/// fragment fields set as if the message had been sent whole, then the body.
///
/// Note:
/// - Hashing the bytes as they arrived would make the MAC depend on how the peer chose to
///   fragment, which is exactly what this rule exists to prevent.
fn updateTranscript(transcript: *Sha256, msg_type: dtls_handshake.MessageType, message_seq: u16, body: []const u8) void {
    var header: [dtls_handshake.HEADER_LEN]u8 = undefined;
    dtls_handshake.writeHeader(&header, .{
        .msg_type = msg_type,
        .length = @intCast(body.len),
        .message_seq = message_seq,
        .fragment_offset = 0,
        .fragment_length = @intCast(body.len),
    });

    transcript.update(&header);
    transcript.update(body);
}

/// Frame one handshake message, hash it, and write it as its own record.
///
/// Return:
/// - usize (bytes written to out)
fn emitMessage(
    out: []u8,
    state: *State,
    msg_type: dtls_handshake.MessageType,
    message_seq: u16,
    body: []const u8,
    max_fragment_len: usize,
) Error!usize {
    updateTranscript(&state.transcript, msg_type, message_seq, body);

    var message_buf: [2048]u8 = undefined;
    var fragmenter: dtls_handshake.Fragmenter = .{
        .msg_type = msg_type,
        .message_seq = message_seq,
        .body = body,
        .max_fragment_len = max_fragment_len,
    };

    var written: usize = 0;
    while (fragmenter.next(&message_buf)) |message| {
        if (written + dtls_record.HEADER_LEN + message.len > out.len) return error.ZixNoSpace;

        const bytes = dtls_record.writePlaintext(out[written..], .HANDSHAKE, EPOCH_HANDSHAKE, state.next_record_seq, message) catch
            return error.ZixNoSpace;

        state.next_record_seq += 1;
        written += bytes.len;
    }

    return written;
}

/// Which SRTP profile to answer with, given what the ClientHello offered and what this server
/// carries. Null means no media: either the peer offered none, or none of its offers is one this
/// server implements.
///
/// Note:
/// - A use_srtp extension this server cannot read is treated as no offer rather than as a fatal
///   alert. The data channel half of the association works either way, and refusing the whole
///   handshake over a media extension would cost a peer its data channels too.
///
/// Param:
/// extensions - []const u8 (the ClientHello extensions block, possibly empty)
/// preferences - []const dtls_exporter.SrtpProfile (this server's order, best first)
///
/// Return:
/// - ?dtls_exporter.SrtpProfile
fn selectSrtpProfile(
    extensions: []const u8,
    preferences: []const dtls_exporter.SrtpProfile,
) ?dtls_exporter.SrtpProfile {
    if (preferences.len == 0) return null;

    const extension_data = (dtls_use_srtp.find(extensions) catch return null) orelse return null;
    const offered = dtls_use_srtp.read(extension_data) catch return null;

    return dtls_use_srtp.select(offered, preferences);
}

fn writeServerHelloBody(
    writer: *wire.Writer,
    server_random: [32]u8,
    session_id: []const u8,
    srtp_profile: ?dtls_exporter.SrtpProfile,
) void {
    writer.writeU16(dtls_record.VERSION_DTLS_1_2);
    writer.writeBytes(&server_random);
    writer.writeU8(@intCast(session_id.len));
    writer.writeBytes(session_id);
    writer.writeU16(CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256);
    writer.writeU8(0); // null compression

    // renegotiation_info (RFC 5746) and ec_point_formats (RFC 8422 5.1.2), the two a 1.2 ECDHE
    // peer expects to see echoed.
    const extensions = writer.placeU16();
    writer.writeU16(0xff01);
    writer.writeU16(1);
    writer.writeU8(0);
    writer.writeU16(0x000b);
    writer.writeU16(2);
    writer.writeU8(1);
    writer.writeU8(0);

    // use_srtp names the one profile the two sides settled on (RFC 5764 4.1.1). Answering with a
    // list, or with a profile the peer did not offer, is what a peer refuses the handshake over.
    if (srtp_profile) |chosen| {
        var answer_buf: [dtls_use_srtp.ANSWER_LEN]u8 = undefined;
        const answer = dtls_use_srtp.writeAnswer(&answer_buf, chosen) catch unreachable;

        writer.writeBytes(answer);
    }

    writer.patchU16(extensions);
}

fn writeCertificateBody(writer: *wire.Writer, der: []const u8) void {
    const list = writer.placeU24();
    const cert = writer.placeU24();

    writer.writeBytes(der);

    writer.patchU24(cert);
    writer.patchU24(list);
}

fn writeServerKeyExchangeBody(
    writer: *wire.Writer,
    key: EcdsaP256.KeyPair,
    client_random: [32]u8,
    server_random: [32]u8,
    point: []const u8,
) !void {
    const params_start = writer.len;

    writer.writeU8(ECCURVE_TYPE_NAMED_CURVE);
    writer.writeU16(NAMED_CURVE_SECP256R1);
    writer.writeU8(@intCast(point.len));
    writer.writeBytes(point);

    const params = writer.buf[params_start..writer.len];

    // The signature covers client_random ++ server_random ++ params (RFC 5246 7.4.3), which is
    // what binds the ephemeral key to this handshake and to this server's certificate.
    var signed: [32 + 32 + 70]u8 = undefined;
    @memcpy(signed[0..32], &client_random);
    @memcpy(signed[32..64], &server_random);
    @memcpy(signed[64 .. 64 + params.len], params);

    const signature = try key.sign(signed[0 .. 64 + params.len], null);

    var der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const der = signature.toDer(&der_buf);

    writer.writeU16(SIG_ECDSA_SECP256R1_SHA256);
    const signature_len = writer.placeU16();
    writer.writeBytes(der);
    writer.patchU16(signature_len);
}

fn transcriptHash(state: *const State) [32]u8 {
    var copy = state.transcript;
    var hash: [32]u8 = undefined;
    copy.final(&hash);

    return hash;
}

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

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const TEST_PEER: IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 41000 } };
const TEST_COOKIE_SECRET: [dtls_cookie.SECRET_LEN]u8 = @splat(0x5A);
const TEST_CLIENT_RANDOM: [32]u8 = @splat(0x11);
const TEST_DER = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };

fn testSigningKey() !EcdsaP256.KeyPair {
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");

    return EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(secret));
}

fn testOptions(key: EcdsaP256.KeyPair) HandshakeOptions {
    return .{
        .certificate_der = &TEST_DER,
        .signing_key = key,
        .server_eph_secret = @splat(0x22),
        .server_random = @splat(0x33),
    };
}

/// Walk a flight's records, collecting the handshake messages they carry.
fn collectMessages(flight: []const u8, out: *[8]dtls_handshake.Fragment) !usize {
    var iterator: dtls_record.RecordIterator = .{ .datagram = flight };
    var count: usize = 0;

    while (try iterator.next()) |bytes| {
        const body = try dtls_record.plaintextFragment(bytes);
        var messages: dtls_handshake.FragmentIterator = .{ .body = body };

        while (try messages.next()) |fragment| {
            out[count] = fragment;
            count += 1;
        }
    }

    return count;
}

test "zix dtls: connection cookie, a first hello is answered without state" {
    const signer = dtls_cookie.Signer.init(TEST_COOKIE_SECRET);

    var hello_buf: [256]u8 = undefined;
    const body = try dtls_hello.writeClientHelloBody(
        &hello_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_CLIENT_RANDOM,
        "",
        "",
        &.{CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    );
    const hello = try dtls_hello.parseClientHello(body);

    try std.testing.expect(!cookieAccepted(&signer, TEST_PEER, hello));

    var out: [256]u8 = undefined;
    const reply = try serverHelloVerifyRequest(&signer, TEST_PEER, hello, 7, &out);

    // The reply reuses the ClientHello's record sequence number (RFC 6347 4.2.1).
    const record_header = try dtls_record.parseHeader(reply);
    try std.testing.expectEqual(@as(u48, 7), record_header.sequence_number);
    try std.testing.expectEqual(@as(u16, EPOCH_HANDSHAKE), record_header.epoch);

    var messages: [8]dtls_handshake.Fragment = undefined;
    try std.testing.expectEqual(@as(usize, 1), try collectMessages(reply, &messages));
    try std.testing.expectEqual(dtls_handshake.MessageType.HELLO_VERIFY_REQUEST, messages[0].header.msg_type);
    try std.testing.expectEqual(@as(u16, 0), messages[0].header.message_seq);

    // The cookie it carries is the one the second hello must echo.
    const cookie = try dtls_hello.parseHelloVerifyRequestBody(messages[0].data);
    var second_buf: [256]u8 = undefined;
    const second = try dtls_hello.parseClientHello(try dtls_hello.writeClientHelloBody(
        &second_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_CLIENT_RANDOM,
        "",
        cookie,
        &.{CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    ));

    try std.testing.expect(cookieAccepted(&signer, TEST_PEER, second));

    // From a different address, the same cookie proves nothing.
    const elsewhere: IpAddress = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 7 }, .port = 41000 } };
    try std.testing.expect(!cookieAccepted(&signer, elsewhere, second));
}

test "zix dtls: connection flight, four messages in message_seq order" {
    const key = try testSigningKey();

    var hello_buf: [256]u8 = undefined;
    const body = try dtls_hello.writeClientHelloBody(
        &hello_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_CLIENT_RANDOM,
        "",
        "cookie",
        &.{CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    );

    var out: [4096]u8 = undefined;
    const flight = try serverFlight(testOptions(key), body, &out);

    var messages: [8]dtls_handshake.Fragment = undefined;
    const count = try collectMessages(flight.to_send, &messages);

    try std.testing.expectEqual(@as(usize, 4), count);

    const expected = [_]struct { msg_type: dtls_handshake.MessageType, seq: u16 }{
        .{ .msg_type = .SERVER_HELLO, .seq = SEQ_SERVER_HELLO },
        .{ .msg_type = .CERTIFICATE, .seq = SEQ_CERTIFICATE },
        .{ .msg_type = .SERVER_KEY_EXCHANGE, .seq = SEQ_SERVER_KEY_EXCHANGE },
        .{ .msg_type = .SERVER_HELLO_DONE, .seq = SEQ_SERVER_HELLO_DONE },
    };

    for (expected, 0..) |want, i| {
        try std.testing.expectEqual(want.msg_type, messages[i].header.msg_type);
        try std.testing.expectEqual(want.seq, messages[i].header.message_seq);
        try std.testing.expect(messages[i].header.isWholeMessage());
    }

    // The ServerHello names the one suite this path implements, at the DTLS 1.2 version.
    try std.testing.expectEqual(@as(u16, dtls_record.VERSION_DTLS_1_2), std.mem.readInt(u16, messages[0].data[0..2], .big));
    try std.testing.expectEqual(@as(u16, CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256), std.mem.readInt(u16, messages[0].data[35..37], .big));

    // Record sequence numbers advance one per record, all in epoch 0.
    var iterator: dtls_record.RecordIterator = .{ .datagram = flight.to_send };
    var seq: u48 = 0;
    while (try iterator.next()) |bytes| : (seq += 1) {
        const header = try dtls_record.parseHeader(bytes);
        try std.testing.expectEqual(seq, header.sequence_number);
        try std.testing.expectEqual(@as(u16, EPOCH_HANDSHAKE), header.epoch);
    }
}

test "zix dtls: connection flight, the record numbering starts where the caller says" {
    // A HelloVerifyRequest has already gone out on epoch 0 by the time this flight is built, so a
    // flight that starts over at zero repeats a sequence number the peer has seen. Its anti-replay
    // window (RFC 6347 4.1.2.6) then throws the whole ServerHello away, which is a handshake that
    // stops dead against any peer that keeps such a window.
    const key = try testSigningKey();

    var hello_buf: [256]u8 = undefined;
    const body = try dtls_hello.writeClientHelloBody(
        &hello_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_CLIENT_RANDOM,
        "",
        "cookie",
        &.{CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    );

    var options = testOptions(key);
    options.first_record_seq = 8;

    var out: [4096]u8 = undefined;
    const flight = try serverFlight(options, body, &out);

    var iterator: dtls_record.RecordIterator = .{ .datagram = flight.to_send };
    var seq: u48 = 8;
    while (try iterator.next()) |bytes| : (seq += 1) {
        try std.testing.expectEqual(seq, (try dtls_record.parseHeader(bytes)).sequence_number);
    }

    // Four messages went out, and the state carries where to carry on from.
    try std.testing.expectEqual(@as(u48, 12), seq);
    try std.testing.expectEqual(@as(u48, 12), flight.state.next_record_seq);
}

/// One ClientHello body carrying a use_srtp extension that offers `profiles`, in that order.
fn testHelloOfferingSrtp(
    out: []u8,
    cookie: []const u8,
    profiles: []const dtls_exporter.SrtpProfile,
) ![]const u8 {
    var body_buf: [256]u8 = undefined;
    const body = try dtls_hello.writeClientHelloBody(
        &body_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_CLIENT_RANDOM,
        "",
        cookie,
        &.{CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    );

    @memcpy(out[0..body.len], body);

    var writer = wire.Writer{ .buf = out[body.len..] };
    const block = writer.placeU16();

    writer.writeU16(dtls_use_srtp.EXTENSION_TYPE);
    const extension = writer.placeU16();
    writer.writeU16(@intCast(profiles.len * dtls_use_srtp.PROFILE_LEN));

    for (profiles) |profile| writer.writeU16(@intFromEnum(profile));

    writer.writeU8(0); // no MKI
    writer.patchU16(extension);
    writer.patchU16(block);

    return out[0 .. body.len + writer.len];
}

/// The use_srtp profile a ServerHello body answers with, or null when it carries none.
fn serverHelloSrtpProfile(server_hello_body: []const u8) !?dtls_exporter.SrtpProfile {
    // 2 version, 32 random, 1 session id length, the id itself, 2 cipher suite, 1 compression.
    const session_id_len: usize = server_hello_body[34];
    const at = 35 + session_id_len + 3;

    const extensions_len = std.mem.readInt(u16, server_hello_body[at..][0..2], .big);
    const extensions = server_hello_body[at + 2 ..][0..extensions_len];

    const extension_data = (try dtls_use_srtp.find(extensions)) orelse return null;

    return (try dtls_use_srtp.read(extension_data)).at(0);
}

test "zix dtls: connection flight, use_srtp answers with the server's choice not the client's" {
    const key = try testSigningKey();

    var hello_buf: [512]u8 = undefined;
    const body = try testHelloOfferingSrtp(&hello_buf, "cookie", &.{
        .SRTP_AES128_CM_HMAC_SHA1_32,
        .SRTP_AES128_CM_HMAC_SHA1_80,
    });

    var opts = testOptions(key);
    opts.srtp_profiles = &.{ .SRTP_AES128_CM_HMAC_SHA1_80, .SRTP_AES128_CM_HMAC_SHA1_32 };

    var out: [4096]u8 = undefined;
    const flight = try serverFlight(opts, body, &out);

    // The client put the 32-bit tag first and the server prefers the 80-bit one. The server's
    // order decides (RFC 5764 4.1.1), and the answer names exactly one profile.
    try std.testing.expectEqual(dtls_exporter.SrtpProfile.SRTP_AES128_CM_HMAC_SHA1_80, flight.state.srtp_profile.?);

    var messages: [8]dtls_handshake.Fragment = undefined;
    _ = try collectMessages(flight.to_send, &messages);

    try std.testing.expectEqual(
        dtls_exporter.SrtpProfile.SRTP_AES128_CM_HMAC_SHA1_80,
        (try serverHelloSrtpProfile(messages[0].data)).?,
    );
}

test "zix dtls: connection flight, a hello with no use_srtp is answered without one" {
    const key = try testSigningKey();

    var hello_buf: [256]u8 = undefined;
    const body = try dtls_hello.writeClientHelloBody(
        &hello_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_CLIENT_RANDOM,
        "",
        "cookie",
        &.{CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    );

    var opts = testOptions(key);
    opts.srtp_profiles = &.{.SRTP_AES128_CM_HMAC_SHA1_80};

    var out: [4096]u8 = undefined;
    const flight = try serverFlight(opts, body, &out);

    try std.testing.expect(flight.state.srtp_profile == null);

    var messages: [8]dtls_handshake.Fragment = undefined;
    _ = try collectMessages(flight.to_send, &messages);

    // A server that offers media to a peer that asked for none is describing a stream that peer
    // will never send, and a data-channel-only browser refuses the extension it did not offer.
    try std.testing.expect((try serverHelloSrtpProfile(messages[0].data)) == null);
}

test "zix dtls: connection flight, a server carrying no profiles leaves an offer unanswered" {
    const key = try testSigningKey();

    var hello_buf: [512]u8 = undefined;
    const body = try testHelloOfferingSrtp(&hello_buf, "cookie", &.{.SRTP_AES128_CM_HMAC_SHA1_80});

    var out: [4096]u8 = undefined;
    const flight = try serverFlight(testOptions(key), body, &out);

    // The default is no media at all, so the offer is passed over and the data channels still work.
    try std.testing.expect(flight.state.srtp_profile == null);
}

test "zix dtls: connection flight, no profile in common leaves media unnegotiated" {
    const key = try testSigningKey();

    var hello_buf: [512]u8 = undefined;
    const body = try testHelloOfferingSrtp(&hello_buf, "cookie", &.{.SRTP_AES128_CM_HMAC_SHA1_32});

    var opts = testOptions(key);
    opts.srtp_profiles = &.{.SRTP_AES128_CM_HMAC_SHA1_80};

    var out: [4096]u8 = undefined;
    const flight = try serverFlight(opts, body, &out);

    try std.testing.expect(flight.state.srtp_profile == null);
}

test "zix dtls: connection flight, a hello without the supported suite is refused" {
    const key = try testSigningKey();

    var hello_buf: [256]u8 = undefined;
    const body = try dtls_hello.writeClientHelloBody(
        &hello_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_CLIENT_RANDOM,
        "",
        "cookie",
        &.{0x1301},
    );

    var out: [4096]u8 = undefined;
    try std.testing.expectError(error.ZixNoSharedCipherSuite, serverFlight(testOptions(key), body, &out));
    try std.testing.expectError(error.ZixClientHelloInvalid, serverFlight(testOptions(key), body[0..8], &out));
}

test "zix dtls: connection flight, a large certificate fragments across records" {
    const key = try testSigningKey();

    var big_der: [1400]u8 = undefined;
    for (&big_der, 0..) |*byte, i| byte.* = @intCast(i % 251);

    var hello_buf: [256]u8 = undefined;
    const body = try dtls_hello.writeClientHelloBody(
        &hello_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_CLIENT_RANDOM,
        "",
        "cookie",
        &.{CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    );

    var options = testOptions(key);
    options.certificate_der = &big_der;
    options.max_fragment_len = 400;

    var out: [8192]u8 = undefined;
    const flight = try serverFlight(options, body, &out);

    var messages: [8]dtls_handshake.Fragment = undefined;
    const count = try collectMessages(flight.to_send, &messages);

    // The certificate arrives in pieces, every one of them naming the same whole-message length.
    var certificate_fragments: usize = 0;
    var reassembler: dtls_handshake.Reassembler(4096) = .{};

    for (messages[0..count]) |fragment| {
        if (fragment.header.msg_type != .CERTIFICATE) continue;

        try std.testing.expect(fragment.header.fragment_length <= 400);
        try reassembler.accept(fragment);
        certificate_fragments += 1;
    }

    try std.testing.expect(certificate_fragments > 1);
    try std.testing.expect(reassembler.isComplete());
    try std.testing.expect(std.mem.indexOf(u8, reassembler.message().?, &big_der) != null);
}

test "zix dtls: connection handshake, a full in-memory exchange agrees on keys" {
    const key = try testSigningKey();
    const signer = dtls_cookie.Signer.init(TEST_COOKIE_SECRET);

    // Flight 1: the client says hello with no cookie.
    var first_buf: [256]u8 = undefined;
    const first_body = try dtls_hello.writeClientHelloBody(
        &first_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_CLIENT_RANDOM,
        "",
        "",
        &.{CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    );

    // Flight 2: the server answers with a cookie and keeps nothing.
    var verify_buf: [256]u8 = undefined;
    const verify = try serverHelloVerifyRequest(&signer, TEST_PEER, try dtls_hello.parseClientHello(first_body), 0, &verify_buf);

    var verify_messages: [8]dtls_handshake.Fragment = undefined;
    _ = try collectMessages(verify, &verify_messages);
    const cookie = try dtls_hello.parseHelloVerifyRequestBody(verify_messages[0].data);

    // Flight 3: the client repeats itself with the cookie. This hello opens the transcript.
    var second_buf: [256]u8 = undefined;
    const client_hello_body = try dtls_hello.writeClientHelloBody(
        &second_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_CLIENT_RANDOM,
        "",
        cookie,
        &.{CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    );
    try std.testing.expect(cookieAccepted(&signer, TEST_PEER, try dtls_hello.parseClientHello(client_hello_body)));

    // Flight 4: the server flight.
    var flight_buf: [4096]u8 = undefined;
    const flight = try serverFlight(testOptions(key), client_hello_body, &flight_buf);
    var state = flight.state;

    var messages: [8]dtls_handshake.Fragment = undefined;
    const count = try collectMessages(flight.to_send, &messages);
    try std.testing.expectEqual(@as(usize, 4), count);

    const server_random_seen: [32]u8 = messages[0].data[2..34].*;
    const server_key_exchange = messages[2].data;
    const point_len = server_key_exchange[3];
    const server_point = server_key_exchange[4 .. 4 + point_len];
    try std.testing.expectEqual(@as(usize, 65), server_point.len);

    // The client mirrors the schedule from its own side.
    const client_scalar = reduceP256Scalar(@splat(0x44));
    const client_point = (try P256.basePoint.mul(client_scalar, .big)).toUncompressedSec1();
    const pre_master = try ecdheSharedX(client_scalar, server_point);
    const master = prf.masterSecret(&pre_master, TEST_CLIENT_RANDOM, server_random_seen);
    const km = prf.keyMaterial(master, TEST_CLIENT_RANDOM, server_random_seen);

    var cke_body: [1 + 65]u8 = undefined;
    cke_body[0] = 65;
    @memcpy(cke_body[1..], &client_point);

    // The client transcript covers the same messages, each with its DTLS header.
    var client_transcript = Sha256.init(.{});
    updateTranscript(&client_transcript, .CLIENT_HELLO, hello_message_seq_with_cookie, client_hello_body);
    updateTranscript(&client_transcript, .SERVER_HELLO, SEQ_SERVER_HELLO, messages[0].data);
    updateTranscript(&client_transcript, .CERTIFICATE, SEQ_CERTIFICATE, messages[1].data);
    updateTranscript(&client_transcript, .SERVER_KEY_EXCHANGE, SEQ_SERVER_KEY_EXCHANGE, messages[2].data);
    updateTranscript(&client_transcript, .SERVER_HELLO_DONE, SEQ_SERVER_HELLO_DONE, messages[3].data);
    updateTranscript(&client_transcript, .CLIENT_KEY_EXCHANGE, SEQ_CLIENT_KEY_EXCHANGE, &cke_body);

    var hash: [32]u8 = undefined;
    {
        var copy = client_transcript;
        copy.final(&hash);
    }
    const client_verify_data = prf.finishedFromHash(master, "client finished", hash);

    // Flight 5: the client Finished, protected under epoch 1 at sequence 0.
    var finished_message: [dtls_handshake.HEADER_LEN + VERIFY_DATA_LEN]u8 = undefined;
    dtls_handshake.writeHeader(&finished_message, .{
        .msg_type = .FINISHED,
        .length = VERIFY_DATA_LEN,
        .message_seq = SEQ_CLIENT_FINISHED,
        .fragment_offset = 0,
        .fragment_length = VERIFY_DATA_LEN,
    });
    @memcpy(finished_message[dtls_handshake.HEADER_LEN..], &client_verify_data);

    var finished_record_buf: [128]u8 = undefined;
    const client_finished_record = try dtls_record.protect(
        &finished_record_buf,
        &finished_message,
        .HANDSHAKE,
        EPOCH_APPLICATION,
        0,
        km.client_write_key,
        km.client_write_iv,
    );

    // Flight 6: the server accepts it and answers.
    var finish_buf: [512]u8 = undefined;
    var finish = try serverFinish(&state, &cke_body, client_finished_record, &finish_buf);

    // ChangeCipherSpec in epoch 0, then the Finished as the first record of epoch 1.
    var finish_records: dtls_record.RecordIterator = .{ .datagram = finish.to_send };
    const ccs = (try finish_records.next()).?;
    const ccs_header = try dtls_record.parseHeader(ccs);
    try std.testing.expectEqual(dtls_record.ContentType.CHANGE_CIPHER_SPEC, ccs_header.content_type);
    try std.testing.expectEqual(@as(u16, EPOCH_HANDSHAKE), ccs_header.epoch);

    const server_finished_record = (try finish_records.next()).?;
    const server_finished_header = try dtls_record.parseHeader(server_finished_record);
    try std.testing.expectEqual(@as(u16, EPOCH_APPLICATION), server_finished_header.epoch);
    try std.testing.expectEqual(@as(u48, 0), server_finished_header.sequence_number);

    // The client checks the server Finished against its own transcript.
    var server_plain: [128]u8 = undefined;
    const opened = try dtls_record.deprotect(&server_plain, server_finished_record, km.server_write_key, km.server_write_iv);

    updateTranscript(&client_transcript, .FINISHED, SEQ_CLIENT_FINISHED, &client_verify_data);
    var final_hash: [32]u8 = undefined;
    client_transcript.final(&final_hash);
    const expected_server_verify_data = prf.finishedFromHash(master, "server finished", final_hash);

    try std.testing.expectEqualSlices(u8, &expected_server_verify_data, opened.data[dtls_handshake.HEADER_LEN..]);

    // Application data flows both ways on the established association.
    var app_buf: [128]u8 = undefined;
    const app_record = try finish.connection.writeAppData("hello over dtls 1.2", &app_buf);

    var app_plain: [128]u8 = undefined;
    const got = try dtls_record.deprotect(&app_plain, app_record, km.server_write_key, km.server_write_iv);
    try std.testing.expectEqualStrings("hello over dtls 1.2", got.data);
    try std.testing.expectEqual(@as(u16, EPOCH_APPLICATION), got.header.epoch);
    try std.testing.expectEqual(@as(u48, 1), got.header.sequence_number);

    var from_client_buf: [128]u8 = undefined;
    const from_client = try dtls_record.protect(
        &from_client_buf,
        "hello back",
        .APPLICATION_DATA,
        EPOCH_APPLICATION,
        1,
        km.client_write_key,
        km.client_write_iv,
    );

    var read_buf: [128]u8 = undefined;
    try std.testing.expectEqualStrings("hello back", (try finish.connection.readAppData(from_client, &read_buf)).?);

    // The same record again is a replay, and a record from the dead epoch is stale.
    try std.testing.expectEqual(@as(?[]const u8, null), try finish.connection.readAppData(from_client, &read_buf));

    var stale_buf: [128]u8 = undefined;
    const stale = try dtls_record.protect(
        &stale_buf,
        "old epoch",
        .APPLICATION_DATA,
        EPOCH_HANDSHAKE,
        9,
        km.client_write_key,
        km.client_write_iv,
    );
    try std.testing.expectEqual(@as(?[]const u8, null), try finish.connection.readAppData(stale, &read_buf));
}

/// Drive one whole handshake with a client written here, and hand back what the finish produced
/// plus the master secret that client derived. Both buffers must outlive the result.
fn runFullHandshake(
    opts: HandshakeOptions,
    client_hello_body: []const u8,
    flight_buf: []u8,
    finish_buf: []u8,
) !struct { finish: FinishResult, master: [48]u8, server_random: [32]u8 } {
    const flight = try serverFlight(opts, client_hello_body, flight_buf);
    var state = flight.state;

    var messages: [8]dtls_handshake.Fragment = undefined;
    _ = try collectMessages(flight.to_send, &messages);

    const server_random_seen: [32]u8 = messages[0].data[2..34].*;
    const server_key_exchange = messages[2].data;
    const point_len = server_key_exchange[3];
    const server_point = server_key_exchange[4 .. 4 + point_len];

    const client_scalar = reduceP256Scalar(@splat(0x44));
    const client_point = (try P256.basePoint.mul(client_scalar, .big)).toUncompressedSec1();
    const pre_master = try ecdheSharedX(client_scalar, server_point);
    const master = prf.masterSecret(&pre_master, TEST_CLIENT_RANDOM, server_random_seen);
    const km = prf.keyMaterial(master, TEST_CLIENT_RANDOM, server_random_seen);

    var cke_body: [1 + 65]u8 = undefined;
    cke_body[0] = 65;
    @memcpy(cke_body[1..], &client_point);

    var client_transcript = Sha256.init(.{});
    updateTranscript(&client_transcript, .CLIENT_HELLO, hello_message_seq_with_cookie, client_hello_body);
    updateTranscript(&client_transcript, .SERVER_HELLO, SEQ_SERVER_HELLO, messages[0].data);
    updateTranscript(&client_transcript, .CERTIFICATE, SEQ_CERTIFICATE, messages[1].data);
    updateTranscript(&client_transcript, .SERVER_KEY_EXCHANGE, SEQ_SERVER_KEY_EXCHANGE, messages[2].data);
    updateTranscript(&client_transcript, .SERVER_HELLO_DONE, SEQ_SERVER_HELLO_DONE, messages[3].data);
    updateTranscript(&client_transcript, .CLIENT_KEY_EXCHANGE, SEQ_CLIENT_KEY_EXCHANGE, &cke_body);

    var hash: [32]u8 = undefined;
    {
        var copy = client_transcript;
        copy.final(&hash);
    }

    const client_verify_data = prf.finishedFromHash(master, "client finished", hash);

    var finished_message: [dtls_handshake.HEADER_LEN + VERIFY_DATA_LEN]u8 = undefined;
    dtls_handshake.writeHeader(&finished_message, .{
        .msg_type = .FINISHED,
        .length = VERIFY_DATA_LEN,
        .message_seq = SEQ_CLIENT_FINISHED,
        .fragment_offset = 0,
        .fragment_length = VERIFY_DATA_LEN,
    });
    @memcpy(finished_message[dtls_handshake.HEADER_LEN..], &client_verify_data);

    var record_buf: [128]u8 = undefined;
    const client_finished_record = try dtls_record.protect(
        &record_buf,
        &finished_message,
        .HANDSHAKE,
        EPOCH_APPLICATION,
        0,
        km.client_write_key,
        km.client_write_iv,
    );

    return .{
        .finish = try serverFinish(&state, &cke_body, client_finished_record, finish_buf),
        .master = master,
        .server_random = server_random_seen,
    };
}

test "zix dtls: connection finish, the srtp keys match what the peer derives" {
    const key = try testSigningKey();

    var hello_buf: [512]u8 = undefined;
    const body = try testHelloOfferingSrtp(&hello_buf, "cookie", &.{.SRTP_AES128_CM_HMAC_SHA1_80});

    var opts = testOptions(key);
    opts.srtp_profiles = &.{.SRTP_AES128_CM_HMAC_SHA1_80};

    var flight_buf: [4096]u8 = undefined;
    var finish_buf: [512]u8 = undefined;
    const done = try runFullHandshake(opts, body, &flight_buf, &finish_buf);

    try std.testing.expectEqual(dtls_exporter.SrtpProfile.SRTP_AES128_CM_HMAC_SHA1_80, done.finish.srtp_profile.?);

    // The peer exports from the same master secret and the same randoms. All four values have to
    // agree byte for byte, because nothing on the media path reports a key that is merely close.
    const peer_keys = try dtls_exporter.srtpKeys(
        .SRTP_AES128_CM_HMAC_SHA1_80,
        done.master,
        TEST_CLIENT_RANDOM,
        done.server_random,
    );
    const server_keys = done.finish.srtp_keys.?;

    try std.testing.expectEqualSlices(u8, &peer_keys.client_write_key, &server_keys.client_write_key);
    try std.testing.expectEqualSlices(u8, &peer_keys.server_write_key, &server_keys.server_write_key);
    try std.testing.expectEqualSlices(u8, &peer_keys.client_write_salt, &server_keys.client_write_salt);
    try std.testing.expectEqualSlices(u8, &peer_keys.server_write_salt, &server_keys.server_write_salt);

    // The two directions never share a key, which is what stops one peer forging the other's
    // stream on a path where both keys are derived from one secret.
    try std.testing.expect(!std.mem.eql(u8, &server_keys.client_write_key, &server_keys.server_write_key));
}

test "zix dtls: connection finish, a handshake with no media exports nothing" {
    const key = try testSigningKey();

    var hello_buf: [256]u8 = undefined;
    const body = try dtls_hello.writeClientHelloBody(
        &hello_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_CLIENT_RANDOM,
        "",
        "cookie",
        &.{CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    );

    var flight_buf: [4096]u8 = undefined;
    var finish_buf: [512]u8 = undefined;
    const done = try runFullHandshake(testOptions(key), body, &flight_buf, &finish_buf);

    try std.testing.expect(done.finish.srtp_keys == null);
    try std.testing.expect(done.finish.srtp_profile == null);
}

test "zix dtls: connection finish, a wrong client finished is rejected" {
    const key = try testSigningKey();

    var hello_buf: [256]u8 = undefined;
    const client_hello_body = try dtls_hello.writeClientHelloBody(
        &hello_buf,
        dtls_record.VERSION_DTLS_1_2,
        TEST_CLIENT_RANDOM,
        "",
        "cookie",
        &.{CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    );

    var flight_buf: [4096]u8 = undefined;
    const flight = try serverFlight(testOptions(key), client_hello_body, &flight_buf);
    var state = flight.state;

    var messages: [8]dtls_handshake.Fragment = undefined;
    _ = try collectMessages(flight.to_send, &messages);

    const server_random_seen: [32]u8 = messages[0].data[2..34].*;
    const server_key_exchange = messages[2].data;
    const server_point = server_key_exchange[4 .. 4 + server_key_exchange[3]];

    const client_scalar = reduceP256Scalar(@splat(0x44));
    const client_point = (try P256.basePoint.mul(client_scalar, .big)).toUncompressedSec1();
    const pre_master = try ecdheSharedX(client_scalar, server_point);
    const master = prf.masterSecret(&pre_master, TEST_CLIENT_RANDOM, server_random_seen);
    const km = prf.keyMaterial(master, TEST_CLIENT_RANDOM, server_random_seen);

    var cke_body: [1 + 65]u8 = undefined;
    cke_body[0] = 65;
    @memcpy(cke_body[1..], &client_point);

    // Correctly protected, but the verify_data is not the transcript.
    var finished_message: [dtls_handshake.HEADER_LEN + VERIFY_DATA_LEN]u8 = undefined;
    dtls_handshake.writeHeader(&finished_message, .{
        .msg_type = .FINISHED,
        .length = VERIFY_DATA_LEN,
        .message_seq = SEQ_CLIENT_FINISHED,
        .fragment_offset = 0,
        .fragment_length = VERIFY_DATA_LEN,
    });
    @memset(finished_message[dtls_handshake.HEADER_LEN..], 0xEE);

    var record_buf: [128]u8 = undefined;
    const wrong_finished = try dtls_record.protect(
        &record_buf,
        &finished_message,
        .HANDSHAKE,
        EPOCH_APPLICATION,
        0,
        km.client_write_key,
        km.client_write_iv,
    );

    var out: [512]u8 = undefined;
    try std.testing.expectError(error.ZixClientFinishedMismatch, serverFinish(&state, &cke_body, wrong_finished, &out));

    // A Finished sent in the wrong epoch, or one that will not open at all, is unexpected rather
    // than a mismatch.
    var wrong_epoch_state = flight.state;
    const wrong_epoch = try dtls_record.protect(
        &record_buf,
        &finished_message,
        .HANDSHAKE,
        EPOCH_HANDSHAKE,
        0,
        km.client_write_key,
        km.client_write_iv,
    );
    try std.testing.expectError(error.ZixUnexpectedMessage, serverFinish(&wrong_epoch_state, &cke_body, wrong_epoch, &out));

    var short_state = flight.state;
    try std.testing.expectError(error.ZixUnexpectedMessage, serverFinish(&short_state, cke_body[0..1], wrong_finished, &out));
}
