//! zix WebRTC DTLS session: the per-peer sequencer around the DTLS 1.2 server handshake.
//!
//! What:
//! - src/tls/dtls_connection.zig holds the three handshake steps as pure functions. Nothing there
//!   knows what order they run in, which datagram a message arrived in, or when a flight that went
//!   unanswered has to go out again. This file is that part, for one peer.
//! - Driven entirely by the caller: datagrams in, datagrams out, and a clock the caller owns.
//!   Nothing here touches a socket.
//!
//! Note:
//! - The cookie exchange keeps no state, which is the point of it (RFC 6347 4.2.1). A
//!   HelloVerifyRequest is therefore queued but never retransmitted on a timer: the answer to a
//!   lost one is the client's own retransmitted ClientHello, which is recomputed into the same
//!   cookie.
//! - The last flight is kept buffered even after the handshake finishes. The side that sent it
//!   owes a retransmission for as long as it keeps the association, or a lost final flight leaves
//!   both ends waiting (RFC 6347 4.2.4).
//! - A flight is handed out in path-sized pieces split on record boundaries, never mid-record. A
//!   record split across two datagrams is one no peer can open.

const std = @import("std");

const dtls_connection = @import("../../tls/dtls_connection.zig");
const dtls_cookie = @import("../../tls/dtls_cookie.zig");
const dtls_flight = @import("../../tls/dtls_flight.zig");
const dtls_handshake = @import("../../tls/dtls_handshake.zig");
const dtls_hello = @import("../../tls/dtls_hello.zig");
const dtls_record = @import("../../tls/dtls_record.zig");
const dtls_exporter = @import("../../tls/dtls_exporter.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const IpAddress = std.Io.net.IpAddress;

/// Largest handshake message this session reassembles. A ClientHello carrying the extensions a
/// browser sends is a few hundred bytes, so this leaves generous room above it.
pub const MAX_HANDSHAKE_MESSAGE: usize = 2048;

/// Largest ClientKeyExchange body this session holds. A P-256 point is 65 bytes plus its length
/// byte.
pub const MAX_KEY_EXCHANGE: usize = 256;

/// How many application records this session takes out of one datagram.
///
/// Note:
/// - A peer that packs more than this into a single datagram has the rest left unread, and SCTP
///   retransmits what went unacknowledged. Costly rather than lossy, and no peer zix has to answer
///   packs anywhere near this many.
pub const MAX_APP_RECORDS: usize = 16;

/// Where the handshake has reached.
pub const State = enum {
    /// Waiting for a ClientHello. Also where a session sits after answering one with a cookie,
    /// because that answer left nothing behind.
    AWAITING_HELLO,
    /// The server flight is out, waiting on ClientKeyExchange and the client Finished.
    AWAITING_FINISH,
    /// Keys are agreed and application data flows.
    ESTABLISHED,
    /// The handshake is over and did not succeed. The session is dead.
    FAILED,
};

pub const Error = error{
    OutOfMemory,
    /// A buffer handed in is too small for what had to go in it.
    ZixNoSpace,
    /// Application data was asked for before the handshake finished.
    ZixNotEstablished,
};

/// What one datagram did to the session.
pub const Outcome = struct {
    /// The handshake completed on this datagram.
    established: bool = false,
    /// The session died on this datagram, or on the timeout that preceded it.
    failed: bool = false,
    /// Application records were taken out, see `nextAppData`.
    delivered: bool = false,
};

/// What the server brings to every handshake it answers.
///
/// Note:
/// - `server_random` and `server_eph_secret` are per handshake and never reused, so they are taken
///   from the caller rather than drawn here. That also lets a test pin them.
pub const Options = struct {
    /// Borrowed, and must outlive the session.
    certificate_der: []const u8,
    signing_key: EcdsaP256.KeyPair,
    cookie_secret: [dtls_cookie.SECRET_LEN]u8,
    server_random: [32]u8,
    server_eph_secret: [32]u8,
    /// Largest handshake fragment body this server emits.
    max_fragment_len: usize = dtls_connection.DEFAULT_MAX_FRAGMENT,
    /// Largest datagram a flight piece may fill.
    path_max_bytes: usize = 1200,
    /// How many times one flight goes out again before the session gives up.
    max_retransmits: usize = dtls_flight.DEFAULT_MAX_RETRANSMITS,
    /// SRTP profiles this peer will carry media under, best first (RFC 5764 4.1). Empty is the
    /// data-channel-only server: use_srtp is left unanswered and no media keys are exported.
    srtp_profiles: []const dtls_exporter.SrtpProfile = &.{},
};

/// One DTLS 1.2 server handshake, and the connection it becomes.
///
/// Usage:
/// ```zig
/// var session = try Session.init(allocator, peer_address, options);
/// defer session.deinit();
///
/// _ = try session.handle(datagram, now_ms);
///
/// var out: [1500]u8 = undefined;
/// while (session.nextOutbound(&out)) |piece| try socket.send(piece);
/// while (session.nextAppData()) |payload| feedSctp(payload);
/// ```
pub const Session = struct {
    allocator: std.mem.Allocator,
    options: Options,
    /// Where the peer sits. The cookie is bound to it, so a cookie cannot be replayed from
    /// elsewhere (RFC 6347 4.2.1).
    peer: IpAddress,
    signer: dtls_cookie.Signer,
    state: State,
    flight: dtls_flight.Flight,

    /// The last flight, kept whole so it can go out again.
    pending: []u8,
    pending_len: usize,
    /// How far through `pending` the outbound pump has walked.
    pending_cursor: usize,
    /// Whether the buffered flight is one a timer may resend. A HelloVerifyRequest is not.
    pending_retransmittable: bool,
    /// Where this server's epoch 0 record numbering has reached. A HelloVerifyRequest goes out on
    /// the sequence the ClientHello arrived with (RFC 6347 4.2.1), and the flight after it has to
    /// carry on from there rather than start again at zero. Two records with the same epoch and
    /// sequence look like a replay to the peer, and it drops the second one.
    next_record_seq: u48,

    handshake: ?dtls_connection.State,
    connection: ?dtls_connection.Connection,
    /// The SRTP master keys use_srtp agreed on, taken from the finish. Null when this peer
    /// negotiated no media, which is every data-channel-only session.
    srtp_keys: ?dtls_exporter.SrtpKeys,
    /// The profile those keys belong to. Read together with them or not at all: the profile fixes
    /// the authentication tag length, and the wrong one fails every packet.
    srtp_profile: ?dtls_exporter.SrtpProfile,

    reassembler: dtls_handshake.Reassembler(MAX_HANDSHAKE_MESSAGE),
    key_exchange: [MAX_KEY_EXCHANGE]u8,
    key_exchange_len: usize,

    /// Decrypted application payloads from the last datagram, packed back to back.
    plain: []u8,
    plain_len: usize,
    app: [MAX_APP_RECORDS][]const u8,
    app_count: usize,
    app_cursor: usize,

    /// Build a session for one peer, before anything has arrived from it.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (owns the flight and plaintext buffers)
    /// peer - IpAddress (where the peer sits, what the cookie is bound to)
    /// options - Options
    /// max_datagram_bytes - usize (largest datagram this session will be handed)
    ///
    /// Return:
    /// - Session in AWAITING_HELLO
    /// - error.OutOfMemory
    pub fn init(
        allocator: std.mem.Allocator,
        peer: IpAddress,
        options: Options,
        max_datagram_bytes: usize,
    ) Error!Session {
        // The server flight is the largest thing ever buffered: four messages, of which the
        // certificate dominates. The rest covers headers, the key exchange, and its signature.
        const flight_bytes = options.certificate_der.len + 2048;

        const pending = try allocator.alloc(u8, flight_bytes);
        errdefer allocator.free(pending);

        const plain = try allocator.alloc(u8, max_datagram_bytes);

        return .{
            .allocator = allocator,
            .options = options,
            .peer = peer,
            .signer = dtls_cookie.Signer.init(options.cookie_secret),
            .state = .AWAITING_HELLO,
            .flight = blk: {
                var started = dtls_flight.Flight.initServer();
                started.max_retransmits = options.max_retransmits;

                break :blk started;
            },
            .pending = pending,
            .pending_len = 0,
            .pending_cursor = 0,
            .pending_retransmittable = false,
            .next_record_seq = 0,
            .handshake = null,
            .connection = null,
            .srtp_keys = null,
            .srtp_profile = null,
            .reassembler = .{},
            .key_exchange = undefined,
            .key_exchange_len = 0,
            .plain = plain,
            .plain_len = 0,
            .app = undefined,
            .app_count = 0,
            .app_cursor = 0,
        };
    }

    /// Free the buffers the session holds.
    pub fn deinit(self: *Session) void {
        self.allocator.free(self.pending);
        self.allocator.free(self.plain);
    }

    /// Whether application data can flow.
    pub fn isEstablished(self: Session) bool {
        return self.state == .ESTABLISHED;
    }

    /// When the outstanding flight has to go out again, or null when none is outstanding.
    pub fn deadline(self: Session) ?u64 {
        return self.flight.timer.deadline_ms;
    }

    /// Handle one datagram that demux routed to DTLS.
    ///
    /// Note:
    /// - Walks every record in the datagram. A malformed length stops the walk rather than killing
    ///   the session, because a stray datagram from anywhere can carry one.
    ///
    /// Param:
    /// datagram - []const u8 (one received datagram)
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - Outcome
    /// - error.ZixNoSpace, error.OutOfMemory
    pub fn handle(self: *Session, datagram: []const u8, now_ms: u64) Error!Outcome {
        self.resetAppData();

        if (self.state == .FAILED) return .{ .failed = true };

        var outcome: Outcome = .{};
        var records: dtls_record.RecordIterator = .{ .datagram = datagram };

        while (records.next() catch null) |record| {
            const header = dtls_record.parseHeader(record) catch break;

            switch (header.content_type) {
                .HANDSHAKE => try self.onHandshakeRecord(record, header, now_ms, &outcome),
                .APPLICATION_DATA => self.onApplicationRecord(record, &outcome),
                // ChangeCipherSpec is not a handshake message and never enters the transcript
                // (RFC 6347 4.2.5). The finish step writes its own.
                else => {},
            }
        }

        return outcome;
    }

    /// The retransmission timer fired.
    ///
    /// Note:
    /// - Call only when `deadline` says the time has come. Calling early is harmless and does
    ///   nothing.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - true when the buffered flight was requeued, so the caller should pump `nextOutbound`
    /// - false when nothing was due, or the peer has had every chance and the session is now FAILED
    pub fn onTimeout(self: *Session, now_ms: u64) bool {
        const action = self.flight.onTick(now_ms) orelse return false;

        switch (action) {
            .RETRANSMIT => {
                self.pending_cursor = 0;
                self.flight.sent(now_ms, true);

                return self.pending_len > 0;
            },
            .GIVE_UP => {
                self.state = .FAILED;

                return false;
            },
        }
    }

    /// The next piece of the buffered flight, sized to the path.
    ///
    /// Note:
    /// - Splits only between records, so every piece is a datagram the peer can open on its own.
    ///   A single record larger than the path is handed out whole rather than cut, because cutting
    ///   it would make it unreadable. The fragment limit in Options is what keeps that from
    ///   happening.
    ///
    /// Param:
    /// out - []u8 (destination, at least one record wide)
    ///
    /// Return:
    /// - ?[]const u8 (a datagram to send, borrowing out)
    /// - null when the flight is fully handed out
    pub fn nextOutbound(self: *Session, out: []u8) ?[]const u8 {
        if (self.pending_cursor >= self.pending_len) return null;

        const flight = self.pending[self.pending_cursor..self.pending_len];
        var records: dtls_record.RecordIterator = .{ .datagram = flight };
        var take: usize = 0;

        while (records.next() catch null) |record| {
            const room = @min(out.len, self.options.path_max_bytes);

            if (take > 0 and take + record.len > room) break;

            take += record.len;

            if (take >= room) break;
        }

        // A first record wider than the room available still has to go: the alternative is an
        // empty datagram and a cursor that never advances.
        if (take == 0) take = flight.len;

        const size = @min(take, out.len);
        @memcpy(out[0..size], flight[0..size]);
        self.pending_cursor += size;

        return out[0..size];
    }

    /// The next application payload taken out of the last datagram.
    ///
    /// Note:
    /// - Valid until the next call to `handle`, which is where the plaintext buffer is reused.
    ///
    /// Return:
    /// - ?[]const u8 (one SCTP packet, borrowed)
    pub fn nextAppData(self: *Session) ?[]const u8 {
        if (self.app_cursor >= self.app_count) return null;

        const payload = self.app[self.app_cursor];
        self.app_cursor += 1;

        return payload;
    }

    /// Wrap application data in a DTLS record.
    ///
    /// Param:
    /// plaintext - []const u8 (one SCTP packet)
    /// out - []u8 (destination)
    ///
    /// Return:
    /// - []const u8 (one record, borrowing out)
    /// - error.ZixNotEstablished before the handshake finishes
    /// - error.ZixNoSpace when out cannot hold the record
    pub fn writeAppData(self: *Session, plaintext: []const u8, out: []u8) Error![]const u8 {
        if (self.connection) |*live| return live.writeAppData(plaintext, out) catch error.ZixNoSpace;

        return error.ZixNotEstablished;
    }

    /// Drop what the last datagram left behind, so the buffers can be filled again.
    fn resetAppData(self: *Session) void {
        self.plain_len = 0;
        self.app_count = 0;
        self.app_cursor = 0;
    }

    /// Take one handshake record: drive the state machine, and buffer whatever it produced.
    fn onHandshakeRecord(
        self: *Session,
        record: []const u8,
        header: dtls_record.Header,
        now_ms: u64,
        outcome: *Outcome,
    ) Error!void {
        // The client Finished is the only handshake message that arrives protected, and it is what
        // the finish step needs whole.
        if (header.epoch == dtls_connection.EPOCH_APPLICATION) {
            try self.onProtectedFinished(record, now_ms, outcome);

            return;
        }

        const body = dtls_record.plaintextFragment(record) catch return;

        var fragments: dtls_handshake.FragmentIterator = .{ .body = body };
        while (fragments.next() catch null) |fragment| {
            switch (fragment.header.msg_type) {
                .CLIENT_HELLO => try self.onClientHelloFragment(fragment, header.sequence_number, now_ms),
                .CLIENT_KEY_EXCHANGE => try self.onKeyExchangeFragment(fragment),
                else => {},
            }
        }
    }

    /// Take one fragment of a ClientHello, and answer once the whole message is in.
    fn onClientHelloFragment(
        self: *Session,
        fragment: dtls_handshake.Fragment,
        record_seq: u48,
        now_ms: u64,
    ) Error!void {
        // A hello that arrives after the flight went out is the peer saying it never got it.
        if (self.state != .AWAITING_HELLO) {
            if (self.flight.onPeerRetransmit()) {
                self.pending_cursor = 0;
                self.flight.sent(now_ms, self.state != .ESTABLISHED);
            }

            return;
        }

        const message = self.acceptFragment(fragment) orelse return;
        const hello = dtls_hello.parseClientHello(message) catch return;

        if (!dtls_connection.cookieAccepted(&self.signer, self.peer, hello)) {
            const verify = dtls_connection.serverHelloVerifyRequest(&self.signer, self.peer, hello, record_seq, self.pending) catch return;

            self.pending_len = verify.len;
            self.pending_cursor = 0;
            self.pending_retransmittable = false;
            self.next_record_seq = record_seq +% 1;

            return;
        }

        const options: dtls_connection.HandshakeOptions = .{
            .certificate_der = self.options.certificate_der,
            .signing_key = self.options.signing_key,
            .server_eph_secret = self.options.server_eph_secret,
            .server_random = self.options.server_random,
            .max_fragment_len = self.options.max_fragment_len,
            .first_record_seq = self.next_record_seq,
            .srtp_profiles = self.options.srtp_profiles,
        };

        const flight = dtls_connection.serverFlight(options, message, self.pending) catch {
            self.state = .FAILED;

            return;
        };

        self.handshake = flight.state;
        self.pending_len = flight.to_send.len;
        self.pending_cursor = 0;
        self.pending_retransmittable = true;
        self.state = .AWAITING_FINISH;

        self.flight.onPeerFlight(false);
        self.flight.sending();
        self.flight.sent(now_ms, true);
    }

    /// Take one fragment into the reassembler, and answer with the whole message once it is there.
    ///
    /// Note:
    /// - A handshake message larger than the path is split across records, and the pieces arrive in
    ///   separate datagrams (RFC 6347 4.2.3). They only add up if they accumulate, so the reset
    ///   belongs at the boundary between two messages and nowhere else. A browser's ClientHello is
    ///   around 1500 bytes and always arrives in two pieces, which is why this is not optional.
    /// - A fragment the message in progress cannot take starts a new one rather than poisoning it,
    ///   which is what a peer that gave up and began again looks like from here.
    fn acceptFragment(self: *Session, fragment: dtls_handshake.Fragment) ?[]const u8 {
        const header = fragment.header;
        const other_message = self.reassembler.message_seq != header.message_seq or
            self.reassembler.msg_type != header.msg_type;

        if (self.reassembler.started and other_message) self.reassembler.reset();

        self.reassembler.accept(fragment) catch {
            self.reassembler.reset();
            self.reassembler.accept(fragment) catch return null;
        };

        return self.reassembler.message();
    }

    /// Take one fragment of a ClientKeyExchange, holding the body until the Finished arrives.
    fn onKeyExchangeFragment(self: *Session, fragment: dtls_handshake.Fragment) Error!void {
        if (self.state != .AWAITING_FINISH) return;

        const message = self.acceptFragment(fragment) orelse return;

        if (message.len > MAX_KEY_EXCHANGE) return;

        @memcpy(self.key_exchange[0..message.len], message);
        self.key_exchange_len = message.len;
    }

    /// Take the protected client Finished, which is what completes the handshake.
    fn onProtectedFinished(self: *Session, record: []const u8, now_ms: u64, outcome: *Outcome) Error!void {
        // After the handshake, a Finished arriving again says the peer never saw the last flight.
        if (self.state == .ESTABLISHED) {
            if (self.flight.onPeerRetransmit()) {
                self.pending_cursor = 0;
                self.flight.sent(now_ms, false);
            }

            return;
        }

        if (self.state != .AWAITING_FINISH) return;
        if (self.key_exchange_len == 0) return;
        if (self.handshake == null) return;

        const finish = dtls_connection.serverFinish(
            &self.handshake.?,
            self.key_exchange[0..self.key_exchange_len],
            record,
            self.pending,
        ) catch |err| switch (err) {
            // A Finished that does not match is the end of the handshake, not a retry.
            error.ZixClientFinishedMismatch => {
                self.state = .FAILED;
                outcome.failed = true;

                return;
            },
            else => return,
        };

        self.connection = finish.connection;
        self.srtp_keys = finish.srtp_keys;
        self.srtp_profile = finish.srtp_profile;
        self.pending_len = finish.to_send.len;
        self.pending_cursor = 0;
        self.pending_retransmittable = true;
        self.state = .ESTABLISHED;

        self.flight.onPeerFlight(true);
        self.flight.sent(now_ms, false);

        outcome.established = true;
    }

    /// Take one application record, decrypting it into the plaintext buffer.
    fn onApplicationRecord(self: *Session, record: []const u8, outcome: *Outcome) void {
        if (self.connection == null) return;
        if (self.app_count >= MAX_APP_RECORDS) return;

        const opened = (self.connection.?.readAppData(record, self.plain[self.plain_len..]) catch return) orelse return;

        self.app[self.app_count] = opened;
        self.app_count += 1;
        self.plain_len += opened.len;

        outcome.delivered = true;
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const TEST_PEER: IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 41000 } };
const TEST_DER = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };

fn testSigningKey() !EcdsaP256.KeyPair {
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");

    return EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(secret));
}

fn testOptions() !Options {
    return .{
        .certificate_der = &TEST_DER,
        .signing_key = try testSigningKey(),
        .cookie_secret = @splat(0x5A),
        .server_random = @splat(0x33),
        .server_eph_secret = @splat(0x44),
    };
}

/// One plaintext ClientHello record, with or without a cookie.
fn clientHelloRecord(out: []u8, cookie: []const u8, record_seq: u48) ![]const u8 {
    var body_buf: [512]u8 = undefined;
    const body = try dtls_hello.writeClientHelloBody(
        &body_buf,
        dtls_record.VERSION_DTLS_1_2,
        @splat(0x11),
        "",
        cookie,
        &.{dtls_connection.CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    );

    var message_buf: [640]u8 = undefined;
    var fragmenter: dtls_handshake.Fragmenter = .{
        .msg_type = .CLIENT_HELLO,
        .message_seq = if (cookie.len == 0) 0 else 1,
        .body = body,
        .max_fragment_len = body.len,
    };
    const message = fragmenter.next(&message_buf).?;

    return try dtls_record.writePlaintext(out, .HANDSHAKE, dtls_connection.EPOCH_HANDSHAKE, record_seq, message);
}

/// One ClientHello record that also offers `profiles` through use_srtp.
///
/// Note:
/// - The extensions block is written by hand rather than through a writer, because dtls_hello only
///   builds the fixed part of a hello and this is the one place in the engine that needs more.
fn clientHelloRecordOfferingSrtp(
    out: []u8,
    cookie: []const u8,
    profiles: []const dtls_exporter.SrtpProfile,
) ![]const u8 {
    var body_buf: [512]u8 = undefined;
    const base = try dtls_hello.writeClientHelloBody(
        &body_buf,
        dtls_record.VERSION_DTLS_1_2,
        @splat(0x11),
        "",
        cookie,
        &.{dtls_connection.CIPHER_ECDHE_ECDSA_AES128_GCM_SHA256},
    );

    var hello_buf: [640]u8 = undefined;
    @memcpy(hello_buf[0..base.len], base);

    const list_len: u16 = @intCast(profiles.len * 2);
    var at = base.len;

    std.mem.writeInt(u16, hello_buf[at..][0..2], 7 + list_len, .big); // whole extensions block
    std.mem.writeInt(u16, hello_buf[at + 2 ..][0..2], 14, .big); // use_srtp
    std.mem.writeInt(u16, hello_buf[at + 4 ..][0..2], 3 + list_len, .big); // extension_data
    std.mem.writeInt(u16, hello_buf[at + 6 ..][0..2], list_len, .big); // profile list
    at += 8;

    for (profiles) |profile| {
        std.mem.writeInt(u16, hello_buf[at..][0..2], @intFromEnum(profile), .big);
        at += 2;
    }

    hello_buf[at] = 0; // no MKI
    at += 1;

    var message_buf: [768]u8 = undefined;
    var fragmenter: dtls_handshake.Fragmenter = .{
        .msg_type = .CLIENT_HELLO,
        .message_seq = if (cookie.len == 0) 0 else 1,
        .body = hello_buf[0..at],
        .max_fragment_len = at,
    };
    const message = fragmenter.next(&message_buf).?;

    return try dtls_record.writePlaintext(out, .HANDSHAKE, dtls_connection.EPOCH_HANDSHAKE, 1, message);
}

/// The cookie out of a HelloVerifyRequest record.
fn cookieFrom(record: []const u8) ![]const u8 {
    const body = try dtls_record.plaintextFragment(record);

    return try dtls_hello.parseHelloVerifyRequestBody(body[dtls_handshake.HEADER_LEN..]);
}

test "zix webrtc: dtls session, a peer offering media is answered with the profile the config names" {
    var options = try testOptions();
    options.srtp_profiles = &.{.SRTP_AES128_CM_HMAC_SHA1_80};

    var session = try Session.init(std.testing.allocator, TEST_PEER, options, 1500);
    defer session.deinit();

    var first_buf: [768]u8 = undefined;
    _ = try session.handle(try clientHelloRecord(&first_buf, "", 0), 1000);

    var verify_out: [1500]u8 = undefined;
    const cookie = try cookieFrom(session.nextOutbound(&verify_out).?);

    var second_buf: [900]u8 = undefined;
    const offering = try clientHelloRecordOfferingSrtp(&second_buf, cookie, &.{
        .SRTP_AES128_CM_HMAC_SHA1_80,
        .SRTP_AES128_CM_HMAC_SHA1_32,
    });

    _ = try session.handle(offering, 1100);

    try std.testing.expectEqual(State.AWAITING_FINISH, session.state);
    try std.testing.expectEqual(
        dtls_exporter.SrtpProfile.SRTP_AES128_CM_HMAC_SHA1_80,
        session.handshake.?.srtp_profile.?,
    );
}

test "zix webrtc: dtls session, a peer offering media to a data-only server gets none back" {
    // The default config carries no profiles, which is what every data channel example runs, and
    // a browser offering use_srtp there has to end up with a working association anyway.
    var session = try Session.init(std.testing.allocator, TEST_PEER, try testOptions(), 1500);
    defer session.deinit();

    var first_buf: [768]u8 = undefined;
    _ = try session.handle(try clientHelloRecord(&first_buf, "", 0), 1000);

    var verify_out: [1500]u8 = undefined;
    const cookie = try cookieFrom(session.nextOutbound(&verify_out).?);

    var second_buf: [900]u8 = undefined;
    const offering = try clientHelloRecordOfferingSrtp(&second_buf, cookie, &.{.SRTP_AES128_CM_HMAC_SHA1_80});

    _ = try session.handle(offering, 1100);

    try std.testing.expectEqual(State.AWAITING_FINISH, session.state);
    try std.testing.expect(session.handshake.?.srtp_profile == null);
}

test "zix webrtc: dtls session, a fresh session is waiting with nothing to send" {
    var session = try Session.init(std.testing.allocator, TEST_PEER, try testOptions(), 1500);
    defer session.deinit();

    try std.testing.expectEqual(State.AWAITING_HELLO, session.state);
    try std.testing.expect(!session.isEstablished());
    try std.testing.expectEqual(@as(?u64, null), session.deadline());

    var out: [1500]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), session.nextOutbound(&out));
    try std.testing.expectEqual(@as(?[]const u8, null), session.nextAppData());
}

test "zix webrtc: dtls session, a first hello is answered with a cookie and no timer" {
    var session = try Session.init(std.testing.allocator, TEST_PEER, try testOptions(), 1500);
    defer session.deinit();

    var hello_buf: [768]u8 = undefined;
    const hello = try clientHelloRecord(&hello_buf, "", 0);

    const outcome = try session.handle(hello, 1000);
    try std.testing.expect(!outcome.established);
    try std.testing.expectEqual(State.AWAITING_HELLO, session.state);

    var out: [1500]u8 = undefined;
    const reply = session.nextOutbound(&out).?;

    const header = try dtls_record.parseHeader(reply);
    try std.testing.expectEqual(dtls_record.ContentType.HANDSHAKE, header.content_type);

    const body = try dtls_record.plaintextFragment(reply);
    const parsed = try dtls_handshake.parseHeader(body);
    try std.testing.expectEqual(dtls_handshake.MessageType.HELLO_VERIFY_REQUEST, parsed.msg_type);

    // The cookie exchange keeps no state, so nothing is waiting on a timer.
    try std.testing.expectEqual(@as(?u64, null), session.deadline());
    try std.testing.expect(!session.pending_retransmittable);
    try std.testing.expectEqual(@as(?[]const u8, null), session.nextOutbound(&out));
}

test "zix webrtc: dtls session, a cookie-bearing hello brings the server flight and arms the timer" {
    var session = try Session.init(std.testing.allocator, TEST_PEER, try testOptions(), 1500);
    defer session.deinit();

    var first_buf: [768]u8 = undefined;
    _ = try session.handle(try clientHelloRecord(&first_buf, "", 0), 1000);

    var out: [1500]u8 = undefined;
    const verify_body = try dtls_record.plaintextFragment(session.nextOutbound(&out).?);
    const cookie = try dtls_hello.parseHelloVerifyRequestBody(verify_body[dtls_handshake.HEADER_LEN..]);

    var second_buf: [768]u8 = undefined;
    _ = try session.handle(try clientHelloRecord(&second_buf, cookie, 1), 1000);

    try std.testing.expectEqual(State.AWAITING_FINISH, session.state);
    try std.testing.expect(session.pending_retransmittable);
    try std.testing.expectEqual(@as(?u64, 1000 + dtls_flight.INITIAL_TIMEOUT_MS), session.deadline());

    var seen: usize = 0;
    var flight_out: [1500]u8 = undefined;
    while (session.nextOutbound(&flight_out)) |piece| {
        try std.testing.expect(piece.len > 0);
        seen += piece.len;
    }
    try std.testing.expect(seen > 0);
}

test "zix webrtc: dtls session, the server flight carries on from the sequence the cookie used" {
    // What this pins: the HelloVerifyRequest and the ServerHello both went out as epoch 0 record 0,
    // and a peer holding an anti-replay window (RFC 6347 4.1.2.6) drops the second of the two. Every
    // browser and OpenSSL hold one, so the handshake stopped there and nothing said why.
    var session = try Session.init(std.testing.allocator, TEST_PEER, try testOptions(), 1500);
    defer session.deinit();

    var first_buf: [768]u8 = undefined;
    _ = try session.handle(try clientHelloRecord(&first_buf, "", 7), 1000);

    var out: [1500]u8 = undefined;
    const verify = session.nextOutbound(&out).?;
    const verify_seq = (try dtls_record.parseHeader(verify)).sequence_number;

    // The HelloVerifyRequest answers on the sequence its ClientHello arrived with (RFC 6347 4.2.1),
    // which is what makes the cookie exchange keep no state.
    try std.testing.expectEqual(@as(u48, 7), verify_seq);

    const verify_body = try dtls_record.plaintextFragment(verify);
    const cookie = try dtls_hello.parseHelloVerifyRequestBody(verify_body[dtls_handshake.HEADER_LEN..]);

    var second_buf: [768]u8 = undefined;
    _ = try session.handle(try clientHelloRecord(&second_buf, cookie, 8), 1000);

    var expected: u48 = verify_seq + 1;
    var flight_out: [1500]u8 = undefined;

    while (session.nextOutbound(&flight_out)) |piece| {
        var records: dtls_record.RecordIterator = .{ .datagram = piece };

        while (try records.next()) |record| : (expected += 1) {
            const header = try dtls_record.parseHeader(record);

            try std.testing.expectEqual(expected, header.sequence_number);
            try std.testing.expectEqual(@as(u16, dtls_connection.EPOCH_HANDSHAKE), header.epoch);
        }
    }

    // Four messages, so the numbering moved by four and never repeated the cookie's.
    try std.testing.expectEqual(@as(u48, verify_seq + 5), expected);
}

test "zix webrtc: dtls session, a timeout resends the buffered flight" {
    var session = try Session.init(std.testing.allocator, TEST_PEER, try testOptions(), 1500);
    defer session.deinit();

    var first_buf: [768]u8 = undefined;
    _ = try session.handle(try clientHelloRecord(&first_buf, "", 0), 0);

    var out: [1500]u8 = undefined;
    const verify = session.nextOutbound(&out).?;
    const verify_body = try dtls_record.plaintextFragment(verify);
    const cookie = try dtls_hello.parseHelloVerifyRequestBody(verify_body[dtls_handshake.HEADER_LEN..]);

    var second_buf: [768]u8 = undefined;
    _ = try session.handle(try clientHelloRecord(&second_buf, cookie, 1), 0);

    var drained: usize = 0;
    while (session.nextOutbound(&out)) |_| drained += 1;
    try std.testing.expect(drained > 0);
    try std.testing.expectEqual(@as(?[]const u8, null), session.nextOutbound(&out));

    // Too early: nothing is due.
    try std.testing.expect(!session.onTimeout(dtls_flight.INITIAL_TIMEOUT_MS - 1));

    // On time: the same flight is queued again, and the next deadline has doubled.
    try std.testing.expect(session.onTimeout(dtls_flight.INITIAL_TIMEOUT_MS));
    try std.testing.expect(session.nextOutbound(&out) != null);
    try std.testing.expectEqual(@as(?u64, dtls_flight.INITIAL_TIMEOUT_MS + 2 * dtls_flight.INITIAL_TIMEOUT_MS), session.deadline());
}

test "zix webrtc: dtls session, a peer that never answers is given up on" {
    var options = try testOptions();
    options.max_retransmits = 2;

    var session = try Session.init(std.testing.allocator, TEST_PEER, options, 1500);
    defer session.deinit();

    var first_buf: [768]u8 = undefined;
    _ = try session.handle(try clientHelloRecord(&first_buf, "", 0), 0);

    var out: [1500]u8 = undefined;
    const verify_body = try dtls_record.plaintextFragment(session.nextOutbound(&out).?);
    const cookie = try dtls_hello.parseHelloVerifyRequestBody(verify_body[dtls_handshake.HEADER_LEN..]);

    var second_buf: [768]u8 = undefined;
    _ = try session.handle(try clientHelloRecord(&second_buf, cookie, 1), 0);

    var now_ms: u64 = 0;
    var resends: usize = 0;
    while (session.state != .FAILED) {
        now_ms = session.deadline() orelse break;

        if (session.onTimeout(now_ms)) resends += 1;
    }

    try std.testing.expectEqual(State.FAILED, session.state);
    try std.testing.expectEqual(@as(usize, 2), resends);
}

test "zix webrtc: dtls session, application data before the handshake is refused" {
    var session = try Session.init(std.testing.allocator, TEST_PEER, try testOptions(), 1500);
    defer session.deinit();

    var out: [128]u8 = undefined;
    try std.testing.expectError(error.ZixNotEstablished, session.writeAppData("too early", &out));
}

test "zix webrtc: dtls session, a datagram that is not a record at all is ignored" {
    var session = try Session.init(std.testing.allocator, TEST_PEER, try testOptions(), 1500);
    defer session.deinit();

    const outcome = try session.handle(&[_]u8{ 22, 0xff }, 500);

    try std.testing.expect(!outcome.established);
    try std.testing.expect(!outcome.failed);
    try std.testing.expectEqual(State.AWAITING_HELLO, session.state);
}

test "zix webrtc: dtls session, a failed session answers nothing further" {
    var session = try Session.init(std.testing.allocator, TEST_PEER, try testOptions(), 1500);
    defer session.deinit();

    session.state = .FAILED;

    const outcome = try session.handle(&[_]u8{ 22, 0xfe, 0xfd }, 500);
    try std.testing.expect(outcome.failed);
}
