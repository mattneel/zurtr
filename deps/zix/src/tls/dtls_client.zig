//! DTLS 1.2 client handshake (RFC 6347), ECDHE-ECDSA with AES-128-GCM: the mirror of
//! dtls_connection.zig, the same way tls12_client.zig mirrors tls12_connection.zig.
//!
//! What:
//! - The sans-I/O client half, in two steps: write a ClientHello (twice, the second carrying the
//!   cookie), then consume the server flight and answer it with ClientKeyExchange,
//!   ChangeCipherSpec, and the client Finished.
//! - Composes the same leaf primitives as the server half, so both sides agree on the transcript
//!   by construction rather than by convention.
//!
//! Note:
//! - This exists so a zix peer can dial another zix peer over a real socket, which is the cheapest
//!   way to find out where two independent instances disagree. It is not certificate validating:
//!   the ServerKeyExchange signature is not checked against the certificate, because the peer this
//!   dials is identified by a fingerprint carried out of band (RFC 8122), and that check belongs
//!   with whatever carried it.
//! - Every message this file emits is unfragmented when it fits the fragment limit, so the bytes
//!   written are already the canonical form the transcript hashes (RFC 6347 4.2.6).
//! - Epoch 0 is the plaintext handshake, epoch 1 begins at ChangeCipherSpec, and record sequence
//!   numbers restart at 0 for the new epoch (RFC 6347 4.1).
//!
//! Usage:
//! ```zig
//! var state = start(.{ .client_random = random, .client_eph_secret = secret });
//!
//! // Flight 1, then flight 3 once the HelloVerifyRequest brings a cookie back.
//! const first = try writeHello(&state, "", &out);
//! const second = try writeHello(&state, cookie, &out);
//!
//! // Flight 5, from the four messages the server sent.
//! const done = try finish(&state, server_flight, &out);
//! ```

const std = @import("std");

const wire = @import("wire.zig");
const prf = @import("tls12_prf.zig");
const dtls_record = @import("dtls_record.zig");
const dtls_handshake = @import("dtls_handshake.zig");
const dtls_hello = @import("dtls_hello.zig");
const dtls_connection = @import("dtls_connection.zig");

const P256 = std.crypto.ecc.P256;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// The one suite this path implements, matching the server half.
pub const CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256: u16 = dtls_connection.CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256;

/// Largest ClientHello body this client builds, which caps the cookie it can carry back.
pub const MAX_HELLO_BODY: usize = 512;

/// Bytes a Finished message carries (RFC 5246 7.4.9).
pub const VERIFY_DATA_LEN: usize = 12;

/// message_seq is per side and counts every handshake message that side sends. The first
/// ClientHello is 0, the one carrying the cookie is 1, and only the second enters the transcript.
const SEQ_CLIENT_HELLO_FIRST: u16 = 0;
const SEQ_CLIENT_HELLO_WITH_COOKIE: u16 = 1;
const SEQ_CLIENT_KEY_EXCHANGE: u16 = 2;
const SEQ_CLIENT_FINISHED: u16 = 3;
const SEQ_SERVER_HELLO: u16 = 1;
const SEQ_CERTIFICATE: u16 = 2;
const SEQ_SERVER_KEY_EXCHANGE: u16 = 3;
const SEQ_SERVER_HELLO_DONE: u16 = 4;

pub const Error = error{
    /// The output buffer cannot hold what had to go in it.
    ZixNoSpace,
    /// A message from the server did not parse, or said something this client cannot use.
    ZixServerFlightInvalid,
    /// The server's ephemeral point is not on the curve, or the scalar multiply failed.
    ZixBadKeyExchange,
    /// finish was called before a cookie-bearing ClientHello opened the transcript.
    ZixNoHandshakeInProgress,
};

/// What the client brings to a handshake.
///
/// Note:
/// - Both values belong to exactly one handshake and are never reused, so they are taken from the
///   caller rather than drawn here. That also lets a test pin them.
pub const Options = struct {
    client_random: [32]u8,
    /// Seed for the ephemeral ECDHE scalar.
    client_eph_secret: [32]u8,
    /// Largest handshake fragment body this client emits.
    max_fragment_len: usize = dtls_connection.DEFAULT_MAX_FRAGMENT,
};

/// The four messages the server sends in flight 4, bodies only with their headers stripped.
pub const ServerFlight = struct {
    server_hello: []const u8,
    certificate: []const u8,
    key_exchange: []const u8,
    hello_done: []const u8,
};

/// Carried between the two steps: the randoms, the ephemeral scalar, the running transcript, and
/// where the record sequence has reached.
pub const State = struct {
    client_random: [32]u8,
    client_eph_scalar: [32]u8,
    transcript: Sha256,
    /// Next record sequence number in epoch 0.
    next_record_seq: u48,
    max_fragment_len: usize,
    /// The cookie-bearing ClientHello body, kept because it opens the transcript.
    hello_body: [MAX_HELLO_BODY]u8,
    hello_len: usize,
};

/// An established association from the client's side: the keys, the send sequence, and the receive
/// replay window.
///
/// Note:
/// - The mirror of dtls_connection.Connection. This side writes with the client keys and reads with
///   the server keys, which is the only difference between the two.
pub const ClientConnection = struct {
    km: prf.KeyMaterial,
    /// Next record sequence number this client sends in epoch 1. Starts at 1, after the Finished
    /// that used 0.
    client_seq: u48 = 1,
    /// Replay window for epoch 1.
    replay: dtls_record.AntiReplay = .{},

    /// Protect application data for the peer.
    pub fn writeAppData(self: *ClientConnection, plaintext: []const u8, out: []u8) dtls_record.Error![]const u8 {
        const bytes = try dtls_record.protect(
            out,
            plaintext,
            .APPLICATION_DATA,
            dtls_connection.EPOCH_APPLICATION,
            self.client_seq,
            self.km.client_write_key,
            self.km.client_write_iv,
        );
        self.client_seq += 1;

        return bytes;
    }

    /// Open an epoch 1 record from the peer.
    ///
    /// Note:
    /// - The server Finished is an epoch 1 record too, at sequence 0, so this is also what opens
    ///   it. The caller tells them apart by the content type it asked for.
    ///
    /// Return:
    /// - []const u8 (the plaintext, borrowing out)
    /// - null when the record is a replay or belongs to another epoch, so discard it
    /// - error when the record is malformed or fails authentication
    pub fn readRecord(self: *ClientConnection, bytes: []const u8, out: []u8) dtls_record.Error!?[]const u8 {
        const header = try dtls_record.parseHeader(bytes);

        if (header.epoch != dtls_connection.EPOCH_APPLICATION) return null;
        if (!self.replay.isNew(header.sequence_number)) return null;

        const opened = try dtls_record.deprotect(out, bytes, self.km.server_write_key, self.km.server_write_iv);
        self.replay.accept(header.sequence_number);

        return opened.data;
    }
};

pub const FinishResult = struct {
    /// ClientKeyExchange, ChangeCipherSpec, and the protected client Finished, back to back. The
    /// caller packs them into datagrams, splitting only on record boundaries.
    to_send: []const u8,
    /// What the server's Finished has to carry for this handshake to be sound.
    server_verify_data: [VERIFY_DATA_LEN]u8,
    connection: ClientConnection,
};

/// Begin a handshake.
///
/// Param:
/// options - Options
///
/// Return:
/// - State with an empty transcript
pub fn start(options: Options) State {
    return .{
        .client_random = options.client_random,
        .client_eph_scalar = reduceP256Scalar(options.client_eph_secret),
        .transcript = Sha256.init(.{}),
        .next_record_seq = 0,
        .max_fragment_len = options.max_fragment_len,
        .hello_body = undefined,
        .hello_len = 0,
    };
}

/// Write a ClientHello as one record (RFC 6347 4.2.4 flights 1 and 3).
///
/// Note:
/// - An empty cookie is the first hello, which neither side hashes. A cookie-bearing hello is the
///   one that opens the transcript, and it is kept so `finish` can hash it.
///
/// Param:
/// state - *State (advanced in place)
/// cookie - []const u8 (empty for the first hello, the HelloVerifyRequest's cookie for the second)
/// out - []u8 (destination for the record)
///
/// Return:
/// - []const u8 (one DTLS record, borrowing out)
/// - error.ZixNoSpace
pub fn writeHello(state: *State, cookie: []const u8, out: []u8) Error![]const u8 {
    var body_buf: [MAX_HELLO_BODY]u8 = undefined;
    const body = dtls_hello.writeClientHelloBody(
        &body_buf,
        dtls_record.VERSION_DTLS_1_2,
        state.client_random,
        "",
        cookie,
        &.{CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    ) catch return error.ZixNoSpace;

    const message_seq: u16 = if (cookie.len == 0) SEQ_CLIENT_HELLO_FIRST else SEQ_CLIENT_HELLO_WITH_COOKIE;

    if (cookie.len > 0) {
        @memcpy(state.hello_body[0..body.len], body);
        state.hello_len = body.len;
    }

    var message_buf: [MAX_HELLO_BODY + dtls_handshake.HEADER_LEN]u8 = undefined;
    var fragmenter: dtls_handshake.Fragmenter = .{
        .msg_type = .CLIENT_HELLO,
        .message_seq = message_seq,
        .body = body,
        .max_fragment_len = body.len,
    };
    const message = fragmenter.next(&message_buf) orelse return error.ZixNoSpace;

    const record = dtls_record.writePlaintext(out, .HANDSHAKE, dtls_connection.EPOCH_HANDSHAKE, state.next_record_seq, message) catch
        return error.ZixNoSpace;
    state.next_record_seq += 1;

    return record;
}

/// Answer the server flight: derive the keys, send ClientKeyExchange, ChangeCipherSpec, and the
/// client Finished (RFC 6347 4.2.4 flight 5).
///
/// Note:
/// - The ServerKeyExchange signature is not verified here, see the file note.
/// - ChangeCipherSpec is not a handshake message. It takes no message_seq and never enters the
///   transcript (RFC 6347 4.2.5).
///
/// Param:
/// state - *State (from writeHello with a cookie, advanced in place)
/// flight - ServerFlight (the four bodies, headers stripped)
/// out - []u8
///
/// Return:
/// - FinishResult (records to send, the verify data to expect back, and the connection)
/// - Error
pub fn finish(state: *State, flight: ServerFlight, out: []u8) Error!FinishResult {
    if (state.hello_len == 0) return error.ZixNoHandshakeInProgress;

    const server_random = try readServerRandom(flight.server_hello);
    const server_point = try readServerPoint(flight.key_exchange);

    const client_point = (P256.basePoint.mul(state.client_eph_scalar, .big) catch
        return error.ZixBadKeyExchange).toUncompressedSec1();

    var key_exchange_body: [1 + 65]u8 = undefined;
    key_exchange_body[0] = @intCast(client_point.len);
    @memcpy(key_exchange_body[1..], &client_point);

    // Both sides hash the same six messages, each with the header it would have had unfragmented.
    updateTranscript(&state.transcript, .CLIENT_HELLO, SEQ_CLIENT_HELLO_WITH_COOKIE, state.hello_body[0..state.hello_len]);
    updateTranscript(&state.transcript, .SERVER_HELLO, SEQ_SERVER_HELLO, flight.server_hello);
    updateTranscript(&state.transcript, .CERTIFICATE, SEQ_CERTIFICATE, flight.certificate);
    updateTranscript(&state.transcript, .SERVER_KEY_EXCHANGE, SEQ_SERVER_KEY_EXCHANGE, flight.key_exchange);
    updateTranscript(&state.transcript, .SERVER_HELLO_DONE, SEQ_SERVER_HELLO_DONE, flight.hello_done);
    updateTranscript(&state.transcript, .CLIENT_KEY_EXCHANGE, SEQ_CLIENT_KEY_EXCHANGE, &key_exchange_body);

    const pre_master = ecdheSharedX(state.client_eph_scalar, server_point) catch return error.ZixBadKeyExchange;
    const master = prf.masterSecret(&pre_master, state.client_random, server_random);
    const km = prf.keyMaterial(master, state.client_random, server_random);

    const client_verify_data = prf.finishedFromHash(master, "client finished", transcriptHash(state));

    var finished_message: [dtls_handshake.HEADER_LEN + VERIFY_DATA_LEN]u8 = undefined;
    dtls_handshake.writeHeader(&finished_message, .{
        .msg_type = .FINISHED,
        .length = VERIFY_DATA_LEN,
        .message_seq = SEQ_CLIENT_FINISHED,
        .fragment_offset = 0,
        .fragment_length = VERIFY_DATA_LEN,
    });
    @memcpy(finished_message[dtls_handshake.HEADER_LEN..], &client_verify_data);

    var cursor: usize = 0;

    {
        var message_buf: [dtls_handshake.HEADER_LEN + 1 + 65]u8 = undefined;
        var fragmenter: dtls_handshake.Fragmenter = .{
            .msg_type = .CLIENT_KEY_EXCHANGE,
            .message_seq = SEQ_CLIENT_KEY_EXCHANGE,
            .body = &key_exchange_body,
            .max_fragment_len = key_exchange_body.len,
        };
        const message = fragmenter.next(&message_buf) orelse return error.ZixNoSpace;

        const record = dtls_record.writePlaintext(out, .HANDSHAKE, dtls_connection.EPOCH_HANDSHAKE, state.next_record_seq, message) catch
            return error.ZixNoSpace;
        state.next_record_seq += 1;
        cursor += record.len;
    }

    const change_cipher = dtls_record.writePlaintext(out[cursor..], .CHANGE_CIPHER_SPEC, dtls_connection.EPOCH_HANDSHAKE, state.next_record_seq, &[_]u8{1}) catch
        return error.ZixNoSpace;
    state.next_record_seq += 1;
    cursor += change_cipher.len;

    const finished = dtls_record.protect(
        out[cursor..],
        &finished_message,
        .HANDSHAKE,
        dtls_connection.EPOCH_APPLICATION,
        0,
        km.client_write_key,
        km.client_write_iv,
    ) catch return error.ZixNoSpace;
    cursor += finished.len;

    // The server hashes the client Finished before computing its own, so this side has to as well.
    updateTranscript(&state.transcript, .FINISHED, SEQ_CLIENT_FINISHED, &client_verify_data);

    return .{
        .to_send = out[0..cursor],
        .server_verify_data = prf.finishedFromHash(master, "server finished", transcriptHash(state)),
        .connection = .{ .km = km },
    };
}

/// The verify data inside a Finished message the server sent, or null when it is not one.
///
/// Param:
/// plaintext - []const u8 (an opened epoch 1 record's contents)
///
/// Return:
/// - ?[]const u8 (the verify data, borrowed)
pub fn serverFinishedVerifyData(plaintext: []const u8) ?[]const u8 {
    const header = dtls_handshake.parseHeader(plaintext) catch return null;

    if (header.msg_type != .FINISHED) return null;

    const verify_data = plaintext[dtls_handshake.HEADER_LEN..];
    if (verify_data.len != VERIFY_DATA_LEN) return null;

    return verify_data;
}

/// The 32 random bytes a ServerHello carries, at a fixed offset after the version.
fn readServerRandom(server_hello: []const u8) Error![32]u8 {
    if (server_hello.len < 2 + 32) return error.ZixServerFlightInvalid;

    return server_hello[2..34].*;
}

/// The server's ephemeral point out of a ServerKeyExchange body (RFC 8422 5.4).
fn readServerPoint(key_exchange: []const u8) Error![]const u8 {
    var reader = wire.Reader{ .buf = key_exchange };

    const curve_type = reader.readU8() catch return error.ZixServerFlightInvalid;
    if (curve_type != 3) return error.ZixServerFlightInvalid;

    _ = reader.readU16() catch return error.ZixServerFlightInvalid;

    const point_len = reader.readU8() catch return error.ZixServerFlightInvalid;

    return reader.readBytes(point_len) catch error.ZixServerFlightInvalid;
}

/// Hash one handshake message the way RFC 6347 4.2.6 requires: the 12-byte header with the
/// fragment fields set as if the message had been sent whole, then the body.
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

const dtls_cookie = @import("dtls_cookie.zig");
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const IpAddress = std.Io.net.IpAddress;

const TEST_PEER: IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 41000 } };
const TEST_DER = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };

fn testSigningKey() !EcdsaP256.KeyPair {
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");

    return EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(secret));
}

/// The bodies of the handshake messages packed into a flight, in the order they arrived.
fn collectBodies(flight: []const u8, out: *[8][]const u8) !usize {
    var records: dtls_record.RecordIterator = .{ .datagram = flight };
    var count: usize = 0;

    while (try records.next()) |record| {
        const body = try dtls_record.plaintextFragment(record);
        var fragments: dtls_handshake.FragmentIterator = .{ .body = body };

        while (try fragments.next()) |fragment| {
            out[count] = fragment.data;
            count += 1;
        }
    }

    return count;
}

test "zix dtls: client hello, the first one carries no cookie and does not open the transcript" {
    var state = start(.{ .client_random = @splat(0x11), .client_eph_secret = @splat(0x44) });

    var out: [512]u8 = undefined;
    const record = try writeHello(&state, "", &out);

    const header = try dtls_record.parseHeader(record);
    try std.testing.expectEqual(dtls_record.ContentType.HANDSHAKE, header.content_type);
    try std.testing.expectEqual(@as(u48, 0), header.sequence_number);

    const parsed = try dtls_handshake.parseHeader(try dtls_record.plaintextFragment(record));
    try std.testing.expectEqual(dtls_handshake.MessageType.CLIENT_HELLO, parsed.msg_type);
    try std.testing.expectEqual(@as(u16, 0), parsed.message_seq);

    try std.testing.expectEqual(@as(usize, 0), state.hello_len);
    try std.testing.expectEqual(@as(u48, 1), state.next_record_seq);
}

test "zix dtls: client hello, the cookie-bearing one is kept for the transcript" {
    var state = start(.{ .client_random = @splat(0x11), .client_eph_secret = @splat(0x44) });
    const cookie: [32]u8 = @splat(0xAB);

    var out: [512]u8 = undefined;
    _ = try writeHello(&state, "", &out);
    const record = try writeHello(&state, &cookie, &out);

    const parsed = try dtls_handshake.parseHeader(try dtls_record.plaintextFragment(record));
    try std.testing.expectEqual(@as(u16, 1), parsed.message_seq);
    try std.testing.expect(state.hello_len > 0);
}

test "zix dtls: client finish, answering before a cookie hello is refused" {
    var state = start(.{ .client_random = @splat(0x11), .client_eph_secret = @splat(0x44) });

    var out: [512]u8 = undefined;
    try std.testing.expectError(error.ZixNoHandshakeInProgress, finish(&state, .{
        .server_hello = "",
        .certificate = "",
        .key_exchange = "",
        .hello_done = "",
    }, &out));
}

test "zix dtls: client finish, a malformed server flight is refused rather than guessed at" {
    var state = start(.{ .client_random = @splat(0x11), .client_eph_secret = @splat(0x44) });

    const cookie: [32]u8 = @splat(0xAB);

    var out: [512]u8 = undefined;
    _ = try writeHello(&state, &cookie, &out);

    // A ServerHello too short to hold its own random.
    try std.testing.expectError(error.ZixServerFlightInvalid, finish(&state, .{
        .server_hello = &[_]u8{ 0xFE, 0xFD },
        .certificate = "",
        .key_exchange = &[_]u8{ 3, 0, 23, 1, 0 },
        .hello_done = "",
    }, &out));

    // A ServerKeyExchange whose curve type is not the named-curve form.
    var full_hello: [40]u8 = @splat(0);
    try std.testing.expectError(error.ZixServerFlightInvalid, finish(&state, .{
        .server_hello = &full_hello,
        .certificate = "",
        .key_exchange = &[_]u8{ 1, 0, 23, 1, 0 },
        .hello_done = "",
    }, &out));
}

test "zix dtls: client and server complete a handshake and carry data both ways" {
    const key = try testSigningKey();
    const signer = dtls_cookie.Signer.init(@splat(0x5A));

    var state = start(.{ .client_random = @splat(0x11), .client_eph_secret = @splat(0x44) });

    // Flight 1: the client says hello with no cookie.
    var first_buf: [512]u8 = undefined;
    const first = try writeHello(&state, "", &first_buf);
    const first_body = try dtls_handshake.parseHeader(try dtls_record.plaintextFragment(first));
    try std.testing.expectEqual(dtls_handshake.MessageType.CLIENT_HELLO, first_body.msg_type);

    // Flight 2: the server answers with a cookie and keeps nothing.
    var verify_buf: [256]u8 = undefined;
    const hello_bytes = (try dtls_record.plaintextFragment(first))[dtls_handshake.HEADER_LEN..];
    const verify = try dtls_connection.serverHelloVerifyRequest(
        &signer,
        TEST_PEER,
        try dtls_hello.parseClientHello(hello_bytes),
        0,
        &verify_buf,
    );
    const cookie = try dtls_hello.parseHelloVerifyRequestBody((try dtls_record.plaintextFragment(verify))[dtls_handshake.HEADER_LEN..]);

    // Flight 3: the client repeats itself with the cookie.
    var second_buf: [512]u8 = undefined;
    const second = try writeHello(&state, cookie, &second_buf);
    const second_hello = (try dtls_record.plaintextFragment(second))[dtls_handshake.HEADER_LEN..];
    try std.testing.expect(dtls_connection.cookieAccepted(&signer, TEST_PEER, try dtls_hello.parseClientHello(second_hello)));

    // Flight 4: the server flight.
    var flight_buf: [4096]u8 = undefined;
    const server_flight = try dtls_connection.serverFlight(.{
        .certificate_der = &TEST_DER,
        .signing_key = key,
        .server_eph_secret = @splat(0x22),
        .server_random = @splat(0x33),
    }, second_hello, &flight_buf);
    var server_state = server_flight.state;

    var bodies: [8][]const u8 = undefined;
    try std.testing.expectEqual(@as(usize, 4), try collectBodies(server_flight.to_send, &bodies));

    // Flight 5: the client answers it.
    var answer_buf: [1024]u8 = undefined;
    var answer = try finish(&state, .{
        .server_hello = bodies[0],
        .certificate = bodies[1],
        .key_exchange = bodies[2],
        .hello_done = bodies[3],
    }, &answer_buf);

    var answer_records: dtls_record.RecordIterator = .{ .datagram = answer.to_send };
    const key_exchange_record = (try answer_records.next()).?;
    const change_cipher_record = (try answer_records.next()).?;
    const client_finished_record = (try answer_records.next()).?;

    try std.testing.expectEqual(dtls_record.ContentType.CHANGE_CIPHER_SPEC, (try dtls_record.parseHeader(change_cipher_record)).content_type);

    const key_exchange_body = (try dtls_record.plaintextFragment(key_exchange_record))[dtls_handshake.HEADER_LEN..];

    // Flight 6: the server accepts it and answers, which is the whole point of the exchange.
    var finish_buf: [512]u8 = undefined;
    var server_done = try dtls_connection.serverFinish(&server_state, key_exchange_body, client_finished_record, &finish_buf);

    var finish_records: dtls_record.RecordIterator = .{ .datagram = server_done.to_send };
    _ = (try finish_records.next()).?;
    const server_finished_record = (try finish_records.next()).?;

    var plain: [128]u8 = undefined;
    const opened = (try answer.connection.readRecord(server_finished_record, &plain)).?;
    try std.testing.expectEqualSlices(u8, &answer.server_verify_data, serverFinishedVerifyData(opened).?);

    // Application data flows both ways on the association the two agreed on.
    var to_server_buf: [128]u8 = undefined;
    const to_server = try answer.connection.writeAppData("ping from the dialer", &to_server_buf);

    var server_read: [128]u8 = undefined;
    try std.testing.expectEqualStrings("ping from the dialer", (try server_done.connection.readAppData(to_server, &server_read)).?);

    var to_client_buf: [128]u8 = undefined;
    const to_client = try server_done.connection.writeAppData("pong from the answerer", &to_client_buf);

    var client_read: [128]u8 = undefined;
    try std.testing.expectEqualStrings("pong from the answerer", (try answer.connection.readRecord(to_client, &client_read)).?);
}

test "zix dtls: client connection, a replayed record is dropped rather than opened twice" {
    const key = try testSigningKey();
    const signer = dtls_cookie.Signer.init(@splat(0x5A));

    var state = start(.{ .client_random = @splat(0x11), .client_eph_secret = @splat(0x44) });

    var first_buf: [512]u8 = undefined;
    const first = try writeHello(&state, "", &first_buf);
    const hello_bytes = (try dtls_record.plaintextFragment(first))[dtls_handshake.HEADER_LEN..];

    var verify_buf: [256]u8 = undefined;
    const verify = try dtls_connection.serverHelloVerifyRequest(&signer, TEST_PEER, try dtls_hello.parseClientHello(hello_bytes), 0, &verify_buf);
    const cookie = try dtls_hello.parseHelloVerifyRequestBody((try dtls_record.plaintextFragment(verify))[dtls_handshake.HEADER_LEN..]);

    var second_buf: [512]u8 = undefined;
    const second = try writeHello(&state, cookie, &second_buf);
    const second_hello = (try dtls_record.plaintextFragment(second))[dtls_handshake.HEADER_LEN..];

    var flight_buf: [4096]u8 = undefined;
    const server_flight = try dtls_connection.serverFlight(.{
        .certificate_der = &TEST_DER,
        .signing_key = key,
        .server_eph_secret = @splat(0x22),
        .server_random = @splat(0x33),
    }, second_hello, &flight_buf);
    var server_state = server_flight.state;

    var bodies: [8][]const u8 = undefined;
    _ = try collectBodies(server_flight.to_send, &bodies);

    var answer_buf: [1024]u8 = undefined;
    var answer = try finish(&state, .{
        .server_hello = bodies[0],
        .certificate = bodies[1],
        .key_exchange = bodies[2],
        .hello_done = bodies[3],
    }, &answer_buf);

    var answer_records: dtls_record.RecordIterator = .{ .datagram = answer.to_send };
    const key_exchange_record = (try answer_records.next()).?;
    _ = (try answer_records.next()).?;
    const client_finished_record = (try answer_records.next()).?;

    var finish_buf: [512]u8 = undefined;
    var server_done = try dtls_connection.serverFinish(
        &server_state,
        (try dtls_record.plaintextFragment(key_exchange_record))[dtls_handshake.HEADER_LEN..],
        client_finished_record,
        &finish_buf,
    );

    var to_client_buf: [128]u8 = undefined;
    const to_client = try server_done.connection.writeAppData("once only", &to_client_buf);

    var plain: [128]u8 = undefined;
    try std.testing.expectEqualStrings("once only", (try answer.connection.readRecord(to_client, &plain)).?);
    try std.testing.expectEqual(@as(?[]const u8, null), try answer.connection.readRecord(to_client, &plain));
}
