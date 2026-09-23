//! The server half of the TLS 1.3 handshake (RFC 8446) for the in-process server.
//!
//! Note:
//! - The mirror image of src/tls/client.zig, and it reuses that side's wire,
//!   key_schedule and record modules: those are direction-neutral, only the
//!   role labels differ. They are reached through rediz.tls, which names
//!   them so both sides of the handshake can be built from one layer.
//! - Nothing here is reachable from the driver itself. It exists so the
//!   driver's real TLS path can be driven on every platform with no container.
//! - Matches exactly what the client offers, no more: x25519,
//!   TLS_AES_128_GCM_SHA256, and an ECDSA P-256 certificate signed under
//!   ecdsa_secp256r1_sha256. A client that offered something else would be
//!   answered with a handshake failure rather than a negotiation.
//! - No session resumption, no tickets, no client certificates, no key update.
//!   The client asks for none of them.
//! - The whole server flight leaves in a single encrypted record. The client
//!   accepts a split flight too, this is simply the simpler side to write.

const std = @import("std");

const certificate = @import("certificate.zig");
const rediz_tls = @import("rediz").tls;

const key_schedule = rediz_tls.key_schedule;
const record = rediz_tls.record;
const wire = rediz_tls.wire;

const X25519 = std.crypto.dh.X25519;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Secret = key_schedule.Secret;

const NAMED_GROUP_X25519: u16 = 0x001d;
const CIPHER_SUITE_AES_128_GCM_SHA256: u16 = 0x1301;
const SIGNATURE_SCHEME_ECDSA_P256_SHA256: u16 = 0x0403;

const HANDSHAKE_RECORD: u8 = 22;
const APPLICATION_DATA_RECORD: u8 = 23;
const ALERT_RECORD: u8 = 21;

const CERTIFICATE_VERIFY_CONTEXT = "TLS 1.3, server CertificateVerify";

/// The record the client sends first bounds this: a ClientHello with one
/// key share and four extensions.
const MAX_CLIENT_HELLO = 2048;

pub const Error = error{
    RedizConnectionClosed,
    RedizNotClientHello,
    RedizNoClientKeyShare,
    RedizUnsupportedCipherSuite,
    RedizUnexpectedRecord,
    RedizClientFinishedMismatch,
    RedizRecordTooLarge,
    RedizHandshakeAlert,
};

/// Post-handshake keys and the per-direction sequence numbers. The server
/// writes under the server application key and reads under the client's.
pub const Session = struct {
    server_app_key: [record.KEY_LENGTH]u8,
    server_app_iv: [record.IV_LENGTH]u8,
    client_app_key: [record.KEY_LENGTH]u8,
    client_app_iv: [record.IV_LENGTH]u8,
    write_seq: u64 = 0,
    read_seq: u64 = 0,

    /// Staging for one wire record in each direction.
    record_buf: [record.MAX_RECORD_WIRE]u8 = undefined,
    write_buf: [record.MAX_RECORD_WIRE]u8 = undefined,

    /// Decrypted bytes not yet consumed.
    plain_buf: [record.MAX_PLAINTEXT + 256]u8 = undefined,
    plain_len: usize = 0,
    plain_pos: usize = 0,

    const Self = @This();

    pub fn bufferedLen(self: *const Self) usize {
        return self.plain_len - self.plain_pos;
    }

    /// Encrypt and send bytes as application data. The caller flushes.
    pub fn writeAll(self: *Self, writer: *std.Io.Writer, bytes: []const u8) !void {
        var pos: usize = 0;
        while (pos < bytes.len) {
            const chunk_len = @min(bytes.len - pos, record.MAX_PLAINTEXT);
            const protected = record.protect(
                &self.write_buf,
                bytes[pos..][0..chunk_len],
                .APPLICATION_DATA,
                self.server_app_key,
                self.server_app_iv,
                self.write_seq,
            );
            self.write_seq += 1;

            writer.writeAll(protected) catch return error.RedizConnectionClosed;
            pos += chunk_len;
        }
    }

    /// Fill out with decrypted application data, reading records as needed.
    pub fn readAll(self: *Self, reader: *std.Io.Reader, out: []u8) !void {
        var pos: usize = 0;
        while (pos < out.len) {
            if (self.bufferedLen() == 0) try self.fillPlain(reader);

            const take = @min(out.len - pos, self.bufferedLen());
            @memcpy(out[pos..][0..take], self.plain_buf[self.plain_pos..][0..take]);
            self.plain_pos += take;
            pos += take;
        }
    }

    fn fillPlain(self: *Self, reader: *std.Io.Reader) !void {
        while (true) {
            const rec = try readWireRecord(reader, &self.record_buf);
            if (rec[0] == ALERT_RECORD) return error.RedizConnectionClosed;

            var opened_buf: [record.MAX_PLAINTEXT + 256]u8 = undefined;
            const opened = record.deprotect(
                &opened_buf,
                rec,
                self.client_app_key,
                self.client_app_iv,
                self.read_seq,
            ) catch return error.RedizConnectionClosed;
            self.read_seq += 1;

            switch (opened.inner_type) {
                .APPLICATION_DATA => {
                    @memcpy(self.plain_buf[0..opened.data.len], opened.data);
                    self.plain_len = opened.data.len;
                    self.plain_pos = 0;

                    return;
                },
                // a post-handshake message from the client, nothing to do
                .HANDSHAKE => continue,
                else => return error.RedizConnectionClosed,
            }
        }
    }
};

/// Run the server side of the handshake over an established stream.
///
/// Param:
/// io - std.Io (entropy for the ephemeral key)
/// reader - *std.Io.Reader (the accepted connection)
/// writer - *std.Io.Writer (the accepted connection, flushed here)
/// cert - *const certificate.SelfSigned (what to present, with its key)
///
/// Return:
/// - Session ready for application data
/// - error.RedizClientFinishedMismatch when the client proved a different transcript
/// - error.RedizUnsupportedCipherSuite when the client offered nothing usable
pub fn handshake(
    io: std.Io,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    cert: *const certificate.SelfSigned,
) !Session {
    var hello_buf: [MAX_CLIENT_HELLO]u8 = undefined;
    const hello_record = try readWireRecord(reader, &hello_buf);
    if (hello_record[0] != HANDSHAKE_RECORD) return error.RedizUnexpectedRecord;

    const client_hello_msg = hello_record[5..];
    const client_hello = try parseClientHello(client_hello_msg);

    var transcript = key_schedule.Transcript.init();
    transcript.update(client_hello_msg);

    // the server ephemeral share, fresh per connection
    var server_secret: [32]u8 = undefined;
    io.randomSecure(&server_secret) catch io.random(&server_secret);
    const server_public = try X25519.recoverPublicKey(server_secret);

    var server_random: [32]u8 = undefined;
    io.randomSecure(&server_random) catch io.random(&server_random);

    var server_hello_buf: [256]u8 = undefined;
    const server_hello_msg = buildServerHello(
        &server_hello_buf,
        server_random,
        client_hello.session_id,
        server_public,
    );
    transcript.update(server_hello_msg);

    // handshake key schedule, identical to the client's derivation
    const ecdhe = try X25519.scalarmult(server_secret, client_hello.client_public);
    const zero = std.mem.zeroes(Secret);
    const empty_hash = key_schedule.Transcript.init().current();
    const early = key_schedule.HkdfSha256.extract(&zero, &zero);
    const derived = key_schedule.deriveSecret(early, "derived", empty_hash);
    const handshake_secret = key_schedule.HkdfSha256.extract(&derived, &ecdhe);

    const t_ch_sh = transcript.current();
    const server_hs_traffic = key_schedule.deriveSecret(handshake_secret, "s hs traffic", t_ch_sh);
    const client_hs_traffic = key_schedule.deriveSecret(handshake_secret, "c hs traffic", t_ch_sh);

    const server_hs = trafficKeys(server_hs_traffic);
    const client_hs = trafficKeys(client_hs_traffic);

    // the encrypted flight: EncryptedExtensions, Certificate,
    // CertificateVerify, Finished
    var flight_buf: [4096]u8 = undefined;
    var flight = wire.Writer{ .buf = &flight_buf };

    appendEncryptedExtensions(&flight);
    transcript.update(flight.slice());

    const cert_start = flight.len;
    appendCertificate(&flight, cert.derBytes());
    transcript.update(flight.slice()[cert_start..]);
    const t_after_cert = transcript.current();

    const verify_start = flight.len;
    try appendCertificateVerify(&flight, cert, t_after_cert);
    transcript.update(flight.slice()[verify_start..]);

    // Finished proves the transcript through CertificateVerify
    const server_finished_vd = finishedVerifyData(finishedKey(server_hs_traffic), transcript.current());
    const finished_start = flight.len;
    appendFinished(&flight, server_finished_vd);
    transcript.update(flight.slice()[finished_start..]);

    var hello_wire_buf: [5 + 256]u8 = undefined;
    const hello_wire = frameHandshakeRecord(&hello_wire_buf, server_hello_msg);

    var flight_wire_buf: [record.MAX_RECORD_WIRE]u8 = undefined;
    const flight_wire = record.protect(
        &flight_wire_buf,
        flight.slice(),
        .HANDSHAKE,
        server_hs.key,
        server_hs.iv,
        0,
    );

    writer.writeAll(hello_wire) catch return error.RedizConnectionClosed;
    writer.writeAll(flight_wire) catch return error.RedizConnectionClosed;
    writer.flush() catch return error.RedizConnectionClosed;

    // application keys come from the transcript through the server Finished
    const t_full = transcript.current();
    const derived_master = key_schedule.deriveSecret(handshake_secret, "derived", empty_hash);
    const master = key_schedule.HkdfSha256.extract(&derived_master, &zero);
    const server_ap = key_schedule.deriveSecret(master, "s ap traffic", t_full);
    const client_ap = key_schedule.deriveSecret(master, "c ap traffic", t_full);

    // the client Finished, encrypted under its handshake key at sequence 0
    try readClientFinished(reader, client_hs, finishedKey(client_hs_traffic), t_full);

    const server_app = trafficKeys(server_ap);
    const client_app = trafficKeys(client_ap);

    return .{
        .server_app_key = server_app.key,
        .server_app_iv = server_app.iv,
        .client_app_key = client_app.key,
        .client_app_iv = client_app.iv,
    };
}

// --------------------------------------------------------- //

const TrafficKeys = struct {
    key: [record.KEY_LENGTH]u8,
    iv: [record.IV_LENGTH]u8,
};

fn trafficKeys(traffic_secret: Secret) TrafficKeys {
    var out: TrafficKeys = undefined;
    key_schedule.expandLabel(&out.key, traffic_secret, "key", "");
    key_schedule.expandLabel(&out.iv, traffic_secret, "iv", "");

    return out;
}

fn finishedKey(traffic_secret: Secret) Secret {
    var out: Secret = undefined;
    key_schedule.expandLabel(&out, traffic_secret, "finished", "");

    return out;
}

fn finishedVerifyData(key: Secret, transcript_hash: Secret) Secret {
    var out: Secret = undefined;
    HmacSha256.create(&out, &transcript_hash, &key);

    return out;
}

/// One TLS record off the wire: the 5-byte header, then the framed length.
fn readWireRecord(reader: *std.Io.Reader, buf: []u8) Error![]const u8 {
    if (buf.len < 5) return error.RedizRecordTooLarge;

    reader.readSliceAll(buf[0..5]) catch return error.RedizConnectionClosed;

    const body_len = std.mem.readInt(u16, buf[3..5], .big);
    if (body_len > record.MAX_CIPHERTEXT) return error.RedizRecordTooLarge;
    if (5 + @as(usize, body_len) > buf.len) return error.RedizRecordTooLarge;

    reader.readSliceAll(buf[5 .. 5 + body_len]) catch return error.RedizConnectionClosed;

    return buf[0 .. 5 + body_len];
}

fn frameHandshakeRecord(buf: []u8, message: []const u8) []const u8 {
    buf[0] = HANDSHAKE_RECORD;
    std.mem.writeInt(u16, buf[1..3], 0x0303, .big);
    std.mem.writeInt(u16, buf[3..5], @intCast(message.len), .big);
    @memcpy(buf[5..][0..message.len], message);

    return buf[0 .. 5 + message.len];
}

const ClientHelloParsed = struct {
    client_public: [32]u8,
    /// Echoed back in ServerHello for middlebox compatibility.
    session_id: []const u8,
};

fn parseClientHello(msg: []const u8) Error!ClientHelloParsed {
    var reader = wire.Reader{ .buf = msg };

    if ((reader.readU8() catch return error.RedizNotClientHello) != 1) return error.RedizNotClientHello;
    _ = reader.readU24() catch return error.RedizNotClientHello;
    _ = reader.readU16() catch return error.RedizNotClientHello; // legacy_version
    _ = reader.readBytes(32) catch return error.RedizNotClientHello; // client_random

    const session_id_len = reader.readU8() catch return error.RedizNotClientHello;
    const session_id = reader.readBytes(session_id_len) catch return error.RedizNotClientHello;

    const suites_len = reader.readU16() catch return error.RedizNotClientHello;
    const suites = reader.readBytes(suites_len) catch return error.RedizNotClientHello;
    if (!offersCipherSuite(suites, CIPHER_SUITE_AES_128_GCM_SHA256)) return error.RedizUnsupportedCipherSuite;

    const compression_len = reader.readU8() catch return error.RedizNotClientHello;
    _ = reader.readBytes(compression_len) catch return error.RedizNotClientHello;

    const ext_len = reader.readU16() catch return error.RedizNoClientKeyShare;
    const exts = reader.readBytes(ext_len) catch return error.RedizNoClientKeyShare;

    var ext_reader = wire.Reader{ .buf = exts };
    while (ext_reader.remaining() >= 4) {
        const ext_type = ext_reader.readU16() catch return error.RedizNoClientKeyShare;
        const ext_data_len = ext_reader.readU16() catch return error.RedizNoClientKeyShare;
        const ext_data = ext_reader.readBytes(ext_data_len) catch return error.RedizNoClientKeyShare;
        if (ext_type != 0x0033) continue;

        var share_reader = wire.Reader{ .buf = ext_data };
        _ = share_reader.readU16() catch return error.RedizNoClientKeyShare; // client_shares length
        while (share_reader.remaining() >= 4) {
            const group = share_reader.readU16() catch return error.RedizNoClientKeyShare;
            const key_len = share_reader.readU16() catch return error.RedizNoClientKeyShare;
            const key_bytes = share_reader.readBytes(key_len) catch return error.RedizNoClientKeyShare;
            if (group != NAMED_GROUP_X25519 or key_len != 32) continue;

            var out: ClientHelloParsed = .{ .client_public = undefined, .session_id = session_id };
            @memcpy(&out.client_public, key_bytes);

            return out;
        }
    }

    return error.RedizNoClientKeyShare;
}

fn offersCipherSuite(suites: []const u8, wanted: u16) bool {
    var index: usize = 0;
    while (index + 1 < suites.len) : (index += 2) {
        if (std.mem.readInt(u16, suites[index..][0..2], .big) == wanted) return true;
    }

    return false;
}

fn buildServerHello(
    out: []u8,
    server_random: [32]u8,
    session_id: []const u8,
    server_public: [32]u8,
) []const u8 {
    var writer = wire.Writer{ .buf = out };
    writer.writeU8(2); // server_hello
    const header = writer.placeU24();
    writer.writeU16(0x0303); // legacy_version
    writer.writeBytes(&server_random);

    // echo the client's legacy session id
    writer.writeU8(@intCast(session_id.len));
    writer.writeBytes(session_id);

    writer.writeU16(CIPHER_SUITE_AES_128_GCM_SHA256);
    writer.writeU8(0); // null compression

    const exts = writer.placeU16();
    // supported_versions: TLS 1.3
    writer.writeU16(0x002b);
    writer.writeU16(2);
    writer.writeU16(0x0304);
    // key_share: the server share
    writer.writeU16(0x0033);
    const share_ext = writer.placeU16();
    writer.writeU16(NAMED_GROUP_X25519);
    writer.writeU16(32);
    writer.writeBytes(&server_public);
    writer.patchU16(share_ext);
    writer.patchU16(exts);

    writer.patchU24(header);

    return writer.slice();
}

fn appendEncryptedExtensions(flight: *wire.Writer) void {
    flight.writeU8(8); // encrypted_extensions
    const header = flight.placeU24();
    const exts = flight.placeU16();
    flight.patchU16(exts);
    flight.patchU24(header);
}

fn appendCertificate(flight: *wire.Writer, cert_der: []const u8) void {
    flight.writeU8(11); // certificate
    const header = flight.placeU24();
    flight.writeU8(0); // empty certificate_request_context

    const list = flight.placeU24();
    flight.writeU24(@intCast(cert_der.len));
    flight.writeBytes(cert_der);
    flight.writeU16(0); // no per-certificate extensions
    flight.patchU24(list);

    flight.patchU24(header);
}

fn appendCertificateVerify(
    flight: *wire.Writer,
    cert: *const certificate.SelfSigned,
    transcript_hash: Secret,
) !void {
    var content_buf: [256]u8 = undefined;
    const content = certificateVerifyContent(&content_buf, transcript_hash);

    const signature = try cert.key_pair.sign(content, null);
    var signature_der_buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
    const signature_der = signature.toDer(&signature_der_buf);

    flight.writeU8(15); // certificate_verify
    const header = flight.placeU24();
    flight.writeU16(SIGNATURE_SCHEME_ECDSA_P256_SHA256);
    flight.writeU16(@intCast(signature_der.len));
    flight.writeBytes(signature_der);
    flight.patchU24(header);
}

fn appendFinished(flight: *wire.Writer, verify_data: Secret) void {
    flight.writeU8(20); // finished
    const header = flight.placeU24();
    flight.writeBytes(&verify_data);
    flight.patchU24(header);
}

/// CertificateVerify content (RFC 8446 4.4.3): 64 spaces, the context string,
/// a NUL, the transcript hash.
fn certificateVerifyContent(buf: []u8, transcript_hash: Secret) []const u8 {
    @memset(buf[0..64], 0x20);
    @memcpy(buf[64..][0..CERTIFICATE_VERIFY_CONTEXT.len], CERTIFICATE_VERIFY_CONTEXT);
    buf[64 + CERTIFICATE_VERIFY_CONTEXT.len] = 0x00;
    @memcpy(buf[64 + CERTIFICATE_VERIFY_CONTEXT.len + 1 ..][0..key_schedule.HASH_LENGTH], &transcript_hash);

    return buf[0 .. 64 + CERTIFICATE_VERIFY_CONTEXT.len + 1 + key_schedule.HASH_LENGTH];
}

/// Read and check the client Finished. A ChangeCipherSpec ahead of it is
/// accepted and ignored, which is what the middlebox-compatible form sends.
fn readClientFinished(
    reader: *std.Io.Reader,
    client_hs: TrafficKeys,
    client_finished_key: Secret,
    transcript_hash: Secret,
) !void {
    var record_buf: [record.MAX_RECORD_WIRE]u8 = undefined;

    while (true) {
        const rec = try readWireRecord(reader, &record_buf);
        switch (rec[0]) {
            20 => continue, // ChangeCipherSpec
            ALERT_RECORD => return error.RedizHandshakeAlert,
            APPLICATION_DATA_RECORD => {},
            else => return error.RedizUnexpectedRecord,
        }

        var opened_buf: [record.MAX_PLAINTEXT + 256]u8 = undefined;
        const opened = record.deprotect(&opened_buf, rec, client_hs.key, client_hs.iv, 0) catch {
            return error.RedizClientFinishedMismatch;
        };
        if (opened.inner_type != .HANDSHAKE) return error.RedizUnexpectedRecord;

        var flight_reader = wire.Reader{ .buf = opened.data };
        const msg_type = flight_reader.readU8() catch return error.RedizClientFinishedMismatch;
        const msg_len = flight_reader.readU24() catch return error.RedizClientFinishedMismatch;
        const body = flight_reader.readBytes(msg_len) catch return error.RedizClientFinishedMismatch;
        if (msg_type != 20) return error.RedizUnexpectedRecord;

        const expected = finishedVerifyData(client_finished_key, transcript_hash);
        if (body.len != expected.len or !std.mem.eql(u8, body, &expected)) {
            return error.RedizClientFinishedMismatch;
        }

        return;
    }
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "rediz inproc: tls server hello echoes the session id and carries a key share" {
    var buf: [256]u8 = undefined;
    const session_id: [32]u8 = @splat(0xab);
    const server_public: [32]u8 = @splat(0xcd);

    const msg = buildServerHello(&buf, @splat(0x11), &session_id, server_public);

    try testing.expectEqual(@as(u8, 2), msg[0]);

    // the message length field must match what follows it
    const declared = (@as(u32, msg[1]) << 16) | (@as(u32, msg[2]) << 8) | msg[3];
    try testing.expectEqual(@as(u32, @intCast(msg.len - 4)), declared);

    // the echoed session id sits right after the 32-byte server random
    try testing.expectEqual(@as(u8, 32), msg[4 + 2 + 32]);
    try testing.expectEqualSlices(u8, &session_id, msg[4 + 2 + 32 + 1 ..][0..32]);
}

test "rediz inproc: tls parses a client hello built by the driver" {
    const client = rediz_tls.client;

    var hello_buf: [512]u8 = undefined;
    const started = try client.start(.{
        .client_random = @splat(0x22),
        .ephemeral_secret = @splat(0x33),
    }, &hello_buf);

    const parsed = try parseClientHello(started.client_hello);

    const expected_public = try X25519.recoverPublicKey(@splat(0x33));
    try testing.expectEqualSlices(u8, &expected_public, &parsed.client_public);
}

test "rediz inproc: tls rejects a hello that offers no usable cipher suite" {
    // a well-formed hello up to the cipher suite list, which names only a
    // suite the server does not implement
    var msg_buf: [128]u8 = undefined;
    var writer = wire.Writer{ .buf = &msg_buf };
    writer.writeU8(1);
    const header = writer.placeU24();
    writer.writeU16(0x0303);
    writer.writeBytes(&@as([32]u8, @splat(0x00)));
    writer.writeU8(0);
    writer.writeU16(2);
    writer.writeU16(0x1302); // TLS_AES_256_GCM_SHA384
    writer.writeU8(1);
    writer.writeU8(0);
    const exts = writer.placeU16();
    writer.patchU16(exts);
    writer.patchU24(header);

    try testing.expectError(error.RedizUnsupportedCipherSuite, parseClientHello(writer.slice()));
}

test "rediz inproc: tls rejects a hello with no x25519 key share" {
    var msg_buf: [128]u8 = undefined;
    var writer = wire.Writer{ .buf = &msg_buf };
    writer.writeU8(1);
    const header = writer.placeU24();
    writer.writeU16(0x0303);
    writer.writeBytes(&@as([32]u8, @splat(0x00)));
    writer.writeU8(0);
    writer.writeU16(2);
    writer.writeU16(CIPHER_SUITE_AES_128_GCM_SHA256);
    writer.writeU8(1);
    writer.writeU8(0);
    const exts = writer.placeU16();
    writer.patchU16(exts);
    writer.patchU24(header);

    try testing.expectError(error.RedizNoClientKeyShare, parseClientHello(writer.slice()));
}

test "rediz inproc: tls certificate verify content follows the rfc layout" {
    var buf: [256]u8 = undefined;
    const transcript_hash: Secret = @splat(0x44);

    const content = certificateVerifyContent(&buf, transcript_hash);

    try testing.expectEqual(@as(usize, 64 + CERTIFICATE_VERIFY_CONTEXT.len + 1 + 32), content.len);
    for (content[0..64]) |byte| try testing.expectEqual(@as(u8, 0x20), byte);
    try testing.expectEqualStrings(CERTIFICATE_VERIFY_CONTEXT, content[64..][0..CERTIFICATE_VERIFY_CONTEXT.len]);
    try testing.expectEqual(@as(u8, 0x00), content[64 + CERTIFICATE_VERIFY_CONTEXT.len]);
    try testing.expectEqualSlices(u8, &transcript_hash, content[64 + CERTIFICATE_VERIFY_CONTEXT.len + 1 ..]);
}

test "rediz inproc: tls certificate message wraps the der in a certificate list" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    const cert = try certificate.SelfSigned.generate(threaded.io(), "rediz-inproc");

    var flight_buf: [2048]u8 = undefined;
    var flight = wire.Writer{ .buf = &flight_buf };
    appendCertificate(&flight, cert.derBytes());

    // the driver reads the leaf back out of exactly this shape
    const client = rediz_tls.client;
    _ = client;

    const msg = flight.slice();
    try testing.expectEqual(@as(u8, 11), msg[0]);

    var reader = wire.Reader{ .buf = msg[4..] };
    const context_len = try reader.readU8();
    try testing.expectEqual(@as(u8, 0), context_len);
    _ = try reader.readU24();
    const leaf_len = try reader.readU24();
    const leaf = try reader.readBytes(leaf_len);
    try testing.expectEqualSlices(u8, cert.derBytes(), leaf);
}
