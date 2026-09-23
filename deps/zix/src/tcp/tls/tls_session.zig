//! Resumable (sans-blocking-I/O) TLS 1.3 server session for the multiplexed TLS dispatch.
//!
//! What:
//! - The epoll / io_uring loop owns the socket: it recvs ciphertext and sends bytes. This session
//!   advances the TLS state machine in place. Feed it the ciphertext as it arrives (a record can span
//!   several recvs, or several records can arrive in one recv), and it drives the handshake, then
//!   decrypts application records. No socket calls here, so one worker thread multiplexes many TLS
//!   connections instead of one thread per connection (the thread-per-conn TLS path thrashes at high
//!   concurrency).
//!
//! Note:
//! - TLS 1.3 only for now (the benchmark clients all offer 1.3. RSA certs work in 1.3 via RSA-PSS).
//!   A 1.2-only ClientHello is refused with a fatal alert. The thread-per-conn runTls path keeps 1.2
//!   for the .ASYNC model.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const win_io = @import("../../utils/windows_io.zig");

const Tls = @import("../../tls/Tls.zig");
const record = @import("../../tls/record.zig");
const connection = @import("../../tls/connection.zig");
const certificate = @import("../../tls/certificate.zig");
const extensions = @import("../../tls/extensions.zig");

const content_type_change_cipher_spec: u8 = 20;
const content_type_handshake: u8 = 22;
const content_type_application_data: u8 = 23;

/// The most a single TLS record can be (RFC 8446 5.1: 2^14 plaintext + expansion + 5-byte header).
const max_record: usize = 17 * 1024;

/// Server handshake flight assembly buffer.
const server_flight_buf: usize = 12 * 1024;

/// Where the handshake / data state machine is.
pub const Phase = enum { hello, finished, established, closed };

/// What a `feed` produced, for the dispatch loop to act on.
pub const Outcome = enum {
    /// Records consumed, nothing special. Send `to_send`, hand `plaintext` to the engine.
    ok,
    /// The handshake just completed: the connection is now established (alpnIsH2 is valid).
    established,
    /// The session must close (alert, protocol error, or buffer overflow). Send `to_send`, then close.
    close,
};

pub const FeedResult = struct {
    to_send: []const u8 = "",
    plaintext: []const u8 = "",
    outcome: Outcome = .ok,
};

/// Fill buf with cryptographically secure random bytes.
fn secureRandom(buf: []u8) void {
    if (comptime builtin.target.os.tag == .linux) {
        _ = linux.getrandom(buf.ptr, buf.len, 0);
        return;
    }

    if (comptime builtin.target.os.tag == .windows) {
        win_io.secureRandom(buf) catch {};
        return;
    }

    std.c.arc4random_buf(buf.ptr, buf.len);
}

/// One TLS server connection's resumable state. The handshake inputs (cert / key / alpn) are borrowed
/// from the Tls.Context and must outlive the session.
/// The most certificates one session presents: an end-entity plus the intermediates a public authority
/// needs.
const max_chain = 4;

pub const Session = struct {
    /// The chain this session presents, held here rather than borrowed. A caller with a single certificate
    /// passes a one-element literal, which does not outlive the call it is made in; the entries point at the
    /// context's DER bytes, which do.
    chain_storage: [max_chain][]const u8 = @splat(&.{}),
    chain_len: usize = 0,
    signing_key: certificate.SigningKey,
    alpn_prefs: []const extensions.Alpn,

    phase: Phase = .hello,
    conn: connection.Connection = undefined, // valid once established
    alpn_h2: bool = false,

    // Per-connection handshake randoms (RFC 8446: fresh per connection).
    ephemeral: [32]u8 = undefined,
    server_random: [32]u8 = undefined,
    pss_salt: [32]u8 = undefined,

    // Record reassembly: ciphertext accumulates here until at least one whole record is present.
    rbuf: [max_record]u8 = undefined,
    rlen: usize = 0,

    /// Initialize a session for a freshly accepted connection. cert_chain / signing_key / alpn_prefs are
    /// borrowed (typically from the Tls.Context).
    pub fn init(cert_chain: []const []const u8, signing_key: certificate.SigningKey, alpn_prefs: []const extensions.Alpn) Session {
        var self = Session{ .signing_key = signing_key, .alpn_prefs = alpn_prefs };
        secureRandom(&self.ephemeral);
        secureRandom(&self.server_random);
        secureRandom(&self.pss_salt);

        self.chain_len = @min(cert_chain.len, self.chain_storage.len);
        @memcpy(self.chain_storage[0..self.chain_len], cert_chain[0..self.chain_len]);

        return self;
    }

    /// The chain to present, in the order it was given: end-entity first.
    pub fn chain(self: *const Session) []const []const u8 {
        return self.chain_storage[0..self.chain_len];
    }

    fn handshakeOptions(self: *const Session) Tls.HandshakeOptions {
        return .{
            .certificate_chain = self.chain(),
            .signing_key = self.signing_key,
            .ephemeral_secret = self.ephemeral,
            .server_random = self.server_random,
            .pss_salt = self.pss_salt,
            .alpn_prefs = self.alpn_prefs,
        };
    }

    /// Whether ALPN selected h2 (only meaningful once established).
    pub fn alpnIsH2(self: *const Session) bool {
        return self.alpn_h2;
    }

    /// Ciphertext bytes this session can take in one feed.
    ///
    /// Note:
    /// - The reassembly buffer holds one record, and feed refuses (and closes on) an input larger
    ///   than the room left. A caller that reads into a buffer wider than one record has to size its
    ///   read by this, or a busy socket hands over two records at once and the connection dies with
    ///   no explanation. That is what capped TLS uploads at one bufferful.
    /// - 0 means a record larger than the buffer is being reassembled, which cannot complete.
    ///
    /// Return:
    /// - usize (bytes feed will accept right now)
    pub fn readRoom(self: *const Session) usize {
        return self.rbuf.len - self.rlen;
    }

    /// Feed received ciphertext. Drains every complete record now buffered, advancing the handshake or
    /// decrypting application data. `to_send_buf` collects bytes to write (handshake flight, alerts),
    /// `plain_buf` collects decrypted application plaintext. The returned slices point into those.
    ///
    /// Note:
    /// - Never hand this more than readRoom() bytes. Past that the connection is terminated, because
    ///   the reassembly buffer cannot hold the input and dropping part of it would desynchronize the
    ///   record stream.
    pub fn feed(self: *Session, input: []const u8, to_send_buf: []u8, plain_buf: []u8) FeedResult {
        if (self.phase == .closed) return .{ .outcome = .close };

        if (input.len > self.rbuf.len - self.rlen) {
            // A record larger than the buffer, or a stuck reassembly: terminate the connection.
            self.phase = .closed;
            return .{ .outcome = .close };
        }
        @memcpy(self.rbuf[self.rlen..][0..input.len], input);
        self.rlen += input.len;

        var to_send_len: usize = 0;
        var plain_len: usize = 0;
        var outcome: Outcome = .ok;

        var off: usize = 0;
        while (recordLen(self.rbuf[off..self.rlen])) |rec_len| {
            const rec = self.rbuf[off .. off + rec_len];
            const ctype = rec[0];
            const body = rec[5..];

            switch (self.phase) {
                .hello => {
                    if (ctype != content_type_handshake) {
                        outcome = .close;
                        break;
                    }

                    var flight: [server_flight_buf]u8 = undefined;
                    const result = Tls.serverHandshake(self.handshakeOptions(), body, &flight) catch {
                        // No usable 1.3 offer or a rejected ClientHello: fatal alert + close.
                        var alert: [Tls.fatal_record_len]u8 = undefined;
                        if (Tls.alertRecordForError(&alert, error.HandshakeFailure)) |a| {
                            to_send_len += appendInto(to_send_buf, to_send_len, a);
                        }
                        outcome = .close;
                        break;
                    };

                    to_send_len += appendInto(to_send_buf, to_send_len, result.to_send);
                    self.conn = result.connection;
                    self.alpn_h2 = result.alpn == .H2;
                    self.phase = .finished;
                },

                .finished => {
                    if (ctype == content_type_change_cipher_spec) {
                        off += rec_len;
                        continue;
                    }
                    if (ctype != content_type_application_data) {
                        outcome = .close;
                        break;
                    }

                    self.conn.verifyClientFinished(rec) catch {
                        outcome = .close;
                        break;
                    };
                    self.phase = .established;
                    outcome = .established;
                },

                .established => {
                    if (ctype != content_type_application_data) {
                        outcome = .close;
                        break;
                    }

                    const plain = self.conn.readAppData(rec, plain_buf[plain_len..]) catch {
                        outcome = .close;
                        break;
                    };
                    plain_len += plain.len;
                },

                .closed => break,
            }

            off += rec_len;
        }

        // Drop the records we consumed, keep any partial-record tail for the next feed.
        if (off > 0 and off <= self.rlen) {
            std.mem.copyForwards(u8, self.rbuf[0 .. self.rlen - off], self.rbuf[off..self.rlen]);
            self.rlen -= off;
        }

        if (outcome == .close) self.phase = .closed;

        return .{ .to_send = to_send_buf[0..to_send_len], .plaintext = plain_buf[0..plain_len], .outcome = outcome };
    }

    /// Encrypt response plaintext into one or more application_data records (RFC 8446 5.2).
    ///
    /// Note:
    /// - A record carries at most record.max_plaintext bytes, so a longer response is split across
    ///   however many records it takes. Callers size `out` with record.sealedLen for the largest
    ///   response they stage, which is why that is more than the plaintext itself.
    /// - All or nothing: a partial response is worse than none, since the peer would read a truncated
    ///   body as a complete one. An `out` too small to hold every record seals nothing.
    ///
    /// Param:
    /// plaintext - []const u8 (whole response bytes, any length)
    /// out - []u8 (must hold record.sealedLen(plaintext.len) bytes)
    ///
    /// Return:
    /// - []const u8 (every sealed record, back to back, ready for the wire)
    /// - empty when out cannot hold them all
    pub fn encrypt(self: *Session, plaintext: []const u8, out: []u8) []const u8 {
        if (out.len < record.sealedLen(plaintext.len)) return out[0..0];

        var rest = plaintext;
        var written: usize = 0;

        while (true) {
            const take = @min(rest.len, record.max_plaintext);
            const sealed = self.conn.writeAppData(rest[0..take], out[written..]);
            if (sealed.len == 0) return out[0..0];

            written += sealed.len;
            rest = rest[take..];

            if (rest.len == 0) break;
        }

        return out[0..written];
    }

    /// Gather form of encrypt: seal a staged prefix (a) followed by source bytes (b) as one
    /// application_data record, so the send path need not copy b into a contiguous buffer first.
    ///
    /// Note:
    /// - ONE record, so a.len + b.len must be at most record.max_plaintext. The engines that use
    ///   this stage a record-sized buffer and gather only what completes it, so the sum is bounded
    ///   by construction. Use encrypt for a payload that has to be split.
    ///
    /// Return:
    /// - []const u8 (the sealed record)
    /// - empty when the two slices exceed one record or out cannot hold it
    pub fn encrypt2(self: *Session, a: []const u8, b: []const u8, out: []u8) []const u8 {
        return self.conn.writeAppData2(a, b, out);
    }

    /// The close_notify alert record, sent before closing a healthy connection.
    pub fn closeNotify(self: *Session, out: []u8) []const u8 {
        return self.conn.closeNotify(out);
    }
};

/// The full length (5-byte header + payload) of the record at the front of `buf`, or null when a whole
/// record is not yet buffered.
fn recordLen(buf: []const u8) ?usize {
    if (buf.len < 5) return null;

    const length = (@as(usize, buf[3]) << 8) | buf[4];
    if (buf.len < 5 + length) return null;

    return 5 + length;
}

/// Append `src` into `dst` at `at`, returning how many bytes were written (0 when it would overflow).
fn appendInto(dst: []u8, at: usize, src: []const u8) usize {
    if (at + src.len > dst.len) return 0;

    @memcpy(dst[at..][0..src.len], src);
    return src.len;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const client = @import("../../tls/client.zig");
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

// The self-signed P-256 fixture identity the connection.zig / client.zig round-trip tests use.
const fixture_cert_hex = "308201d43082017ba00302010202147a26ee491f091ac7c914f4a810c1ece713402574300a06082a8648ce3d040302302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f63301e170d3236303632323132353432305a170d3336303631393132353432305a302a3112301006035504030c096c6f63616c686f737431143012060355040a0c0b7a69782d746c732d706f633059301306072a8648ce3d020106082a8648ce3d03010703420004c2a0121b298ac9cd389200e78d94e7bde1cc7cd8074795fab4f919799d40fdc231c5a90990ac8c6166ae472f33f74fced097f2edb7b8a1974be66a4ab07f253ba37f307d301d0603551d0e04160414c34e1d0a36a43947709b539e16dd0213aa4196aa301f0603551d23041830168014c34e1d0a36a43947709b539e16dd0213aa4196aa300f0603551d130101ff040530030101ff301a0603551d110413301182096c6f63616c686f737487047f000001300e0603551d0f0101ff040403020780300a06082a8648ce3d040302034700304402200b012f119db9b95d990bc482cb63e8f81e337a08634904e4caf513dc10c8aa8302202fdfe79ff6d5403e753ddf2aa52671923b8a2c28126bcbf196bd6fb7ecbcb14e";

/// Wrap a TLS plaintext payload as a record of `ctype` into `out`, returning the record bytes.
fn wrapRecord(ctype: u8, payload: []const u8, out: []u8) []const u8 {
    out[0] = ctype;
    out[1] = 0x03;
    out[2] = 0x03;
    std.mem.writeInt(u16, out[3..5], @intCast(payload.len), .big);
    @memcpy(out[5..][0..payload.len], payload);

    return out[0 .. 5 + payload.len];
}

test "zix tls: resumable session drives a full 1.3 handshake + app data, sans I/O" {
    // The same fixture identity the connection.zig / client.zig round-trip tests use.
    var skey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&skey, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const server_key = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(skey));
    var cert_buf: [512]u8 = undefined;
    const cert_der = try std.fmt.hexToBytes(&cert_buf, fixture_cert_hex);

    var session = Session.init(&.{cert_der}, .{ .ecdsa_p256 = server_key }, &.{.H2});

    // Client phase 1: ClientHello (offering ALPN h2), wrapped as a handshake record on the wire.
    var ch_buf: [512]u8 = undefined;
    const started = try client.start(.{ .client_random = @splat(0x11), .ephemeral_secret = @splat(0x42), .alpn = &.{.H2} }, &ch_buf);
    var state = started.state;

    var ch_rec: [600]u8 = undefined;
    const ch_record = wrapRecord(content_type_handshake, started.client_hello, &ch_rec);

    // Feed the ClientHello record: the session emits the server flight and moves to .finished.
    var to_send: [16 * 1024]u8 = undefined;
    var plain: [4096]u8 = undefined;
    const r1 = session.feed(ch_record, &to_send, &plain);
    try std.testing.expect(r1.outcome == .ok);
    try std.testing.expect(r1.to_send.len > 0);
    try std.testing.expect(session.phase == .finished);

    // Client phase 2: consume the flight, produce the client Finished. ALPN must be h2.
    var fin_buf: [256]u8 = undefined;
    var finished = try client.finish(&state, r1.to_send, &fin_buf);
    try std.testing.expect(finished.alpn.? == .H2);

    // Feed the client Finished record: the session verifies it and becomes established.
    const r2 = session.feed(finished.client_finished, &to_send, &plain);
    try std.testing.expect(r2.outcome == .established);
    try std.testing.expect(session.phase == .established);
    try std.testing.expect(session.alpnIsH2());

    // Application data, client -> server: the session decrypts it.
    var c2s_buf: [256]u8 = undefined;
    const c2s = finished.connection.writeAppData("ping from client", &c2s_buf);
    const r3 = session.feed(c2s, &to_send, &plain);
    try std.testing.expect(r3.outcome == .ok);
    try std.testing.expectEqualStrings("ping from client", r3.plaintext);

    // Application data, server -> client: the session encrypts it, the client decrypts.
    var s2c_buf: [256]u8 = undefined;
    const s2c = session.encrypt("pong from server", &s2c_buf);
    var c_in: [256]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "pong from server", try finished.connection.readAppData(s2c, &c_in));
}

/// Drive a session to .established and hand back both ends, so a test can exchange application
/// data without repeating the whole handshake.
fn establishedPair() !struct { session: Session, client_conn: client.ClientConnection } {
    var skey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&skey, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const server_key = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(skey));
    var cert_buf: [512]u8 = undefined;
    const cert_der = try std.fmt.hexToBytes(&cert_buf, fixture_cert_hex);

    var session = Session.init(&.{cert_der}, .{ .ecdsa_p256 = server_key }, &.{.H2});

    var ch_buf: [512]u8 = undefined;
    const started = try client.start(.{ .client_random = @splat(0x11), .ephemeral_secret = @splat(0x42), .alpn = &.{.H2} }, &ch_buf);
    var state = started.state;

    var ch_rec: [600]u8 = undefined;
    const ch_record = wrapRecord(content_type_handshake, started.client_hello, &ch_rec);

    var to_send: [16 * 1024]u8 = undefined;
    var plain: [4096]u8 = undefined;

    const flight = session.feed(ch_record, &to_send, &plain);
    var fin_buf: [256]u8 = undefined;
    const finished = try client.finish(&state, flight.to_send, &fin_buf);
    _ = session.feed(finished.client_finished, &to_send, &plain);

    return .{ .session = session, .client_conn = finished.connection };
}

test "zix tls: session encrypt splits a response past one record and the client reads it whole" {
    var pair = try establishedPair();

    // Three records' worth plus a remainder, so the split has to carry a partial last record.
    const body_len = record.max_plaintext * 3 + 1234;
    const body = try std.testing.allocator.alloc(u8, body_len);
    defer std.testing.allocator.free(body);
    for (body, 0..) |*byte, index| byte.* = @intCast(index % 251);

    const sealed = try std.testing.allocator.alloc(u8, record.sealedLen(body_len));
    defer std.testing.allocator.free(sealed);

    const wire = pair.session.encrypt(body, sealed);
    try std.testing.expectEqual(record.sealedLen(body_len), wire.len);

    // Read it back one record at a time, exactly as a peer would, and reassemble.
    const reassembled = try std.testing.allocator.alloc(u8, body_len);
    defer std.testing.allocator.free(reassembled);

    var offset: usize = 0;
    var filled: usize = 0;
    var records: usize = 0;
    var plain_buf: [record.max_plaintext + 1]u8 = undefined;
    while (offset < wire.len) {
        const length = (@as(usize, wire[offset + 3]) << 8) | wire[offset + 4];
        const one = wire[offset .. offset + 5 + length];

        const opened = try pair.client_conn.readAppData(one, &plain_buf);
        @memcpy(reassembled[filled..][0..opened.len], opened);
        filled += opened.len;
        records += 1;

        offset += one.len;
    }

    try std.testing.expectEqual(@as(usize, 4), records);
    try std.testing.expectEqual(body_len, filled);
    try std.testing.expectEqualSlices(u8, body, reassembled);
}

test "zix tls: session encrypt seals nothing rather than a truncated response" {
    var pair = try establishedPair();

    const body_len = record.max_plaintext * 2;
    const body = try std.testing.allocator.alloc(u8, body_len);
    defer std.testing.allocator.free(body);
    @memset(body, 'z');

    // One byte short of what the records cost. A partial seal would reach the peer as a complete
    // but truncated body, which is worse than no response at all.
    const tight = try std.testing.allocator.alloc(u8, record.sealedLen(body_len) - 1);
    defer std.testing.allocator.free(tight);

    try std.testing.expectEqual(@as(usize, 0), pair.session.encrypt(body, tight).len);

    const exact = try std.testing.allocator.alloc(u8, record.sealedLen(body_len));
    defer std.testing.allocator.free(exact);

    try std.testing.expectEqual(exact.len, pair.session.encrypt(body, exact).len);
}

test "zix tls: session encrypt still emits one record for a small response" {
    var pair = try establishedPair();

    var sealed: [256]u8 = undefined;
    const wire = pair.session.encrypt("small", &sealed);

    try std.testing.expectEqual(record.sealedLen("small".len), wire.len);

    var plain_buf: [256]u8 = undefined;
    try std.testing.expectEqualStrings("small", try pair.client_conn.readAppData(wire, &plain_buf));
}

test "zix tls: a fragmented record is held until the whole record arrives" {
    var skey: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&skey, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");
    const server_key = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(skey));
    var cert_buf: [512]u8 = undefined;
    const cert_der = try std.fmt.hexToBytes(&cert_buf, fixture_cert_hex);

    var session = Session.init(&.{cert_der}, .{ .ecdsa_p256 = server_key }, &.{.H2});

    var ch_buf: [512]u8 = undefined;
    const started = try client.start(.{ .client_random = @splat(0x11), .ephemeral_secret = @splat(0x42), .alpn = &.{.H2} }, &ch_buf);
    var ch_rec: [600]u8 = undefined;
    const ch_record = wrapRecord(content_type_handshake, started.client_hello, &ch_rec);

    var to_send: [16 * 1024]u8 = undefined;
    var plain: [4096]u8 = undefined;

    // Feed the ClientHello one byte short: no complete record yet, nothing produced, still in .hello.
    const r_partial = session.feed(ch_record[0 .. ch_record.len - 1], &to_send, &plain);
    try std.testing.expect(r_partial.outcome == .ok);
    try std.testing.expect(r_partial.to_send.len == 0);
    try std.testing.expect(session.phase == .hello);

    // Feed the final byte: the record completes, the handshake advances.
    const r_rest = session.feed(ch_record[ch_record.len - 1 ..], &to_send, &plain);
    try std.testing.expect(r_rest.to_send.len > 0);
    try std.testing.expect(session.phase == .finished);
}
