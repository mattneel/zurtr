//! zix WebRTC dialer: the peer that starts the session, for talking to a zix answerer.
//!
//! What:
//! - The mirror of connection.zig. It sends the ICE checks instead of answering them, runs the
//!   DTLS client half instead of the server half, opens the SCTP association instead of accepting
//!   it, and opens the first data channel instead of waiting for one.
//! - Owns no socket and reads no clock, exactly like the answerer, so a whole session between the
//!   two runs in memory with no port and no sleep.
//!
//! Note:
//! - This is what makes a native pair possible: two independent instances that have to agree on
//!   every byte, where both halves are zix and both can be instrumented. A browser is the harder
//!   test and this is the cheaper one, so this comes first.
//! - It is not a browser and does not pretend to be one. There is no SDP, no trickle ICE, no
//!   candidate gathering, and no certificate validation. The two sides are told each other's
//!   credentials by the caller.
//! - It dials one peer. A dialer is one session, and a second session is a second dialer.

const std = @import("std");

const core = @import("core.zig");
const datachannel = @import("datachannel/peer.zig");
const demux = @import("demux.zig");
const dtls_client = @import("../../tls/dtls_client.zig");
const dtls_connection = @import("../../tls/dtls_connection.zig");
const dtls_flight = @import("../../tls/dtls_flight.zig");
const dtls_handshake = @import("../../tls/dtls_handshake.zig");
const dtls_hello = @import("../../tls/dtls_hello.zig");
const dtls_record = @import("../../tls/dtls_record.zig");
const ice_check = @import("ice/check.zig");
const ice_credentials = @import("ice/credentials.zig");
const association = @import("sctp/association.zig");
const sctp_cookie = @import("sctp/cookie.zig");
const stun_message = @import("stun/message.zig");
const timer = @import("timer.zig");

const IpAddress = std.Io.net.IpAddress;

/// What a DTLS record adds around one SCTP packet.
pub const DTLS_OVERHEAD: usize = 13 + 8 + 16;

/// How many datagrams the dialer holds ready to send at once.
pub const MAX_QUEUED: usize = 8;

/// Largest handshake message the dialer reassembles out of the server flight. The certificate is
/// what sizes it.
pub const MAX_HANDSHAKE_MESSAGE: usize = 4096;

/// Where the dialer has reached.
pub const State = enum {
    /// Connectivity checks are going out and none has been answered.
    CHECKING,
    /// A check was answered, the DTLS handshake is running.
    HANDSHAKING,
    /// DTLS is up and the SCTP association is opening.
    ASSOCIATING,
    /// The association is up and the first channel has been asked for.
    OPENING,
    /// A channel is open and messages can flow.
    READY,
    /// The session is over and did not get there.
    FAILED,
};

pub const Error = datachannel.Error || error{ZixNoSpace};

/// What one datagram, or one tick, did.
pub const Outcome = struct {
    /// The DTLS handshake completed on this datagram.
    secured: bool = false,
    /// A channel became usable.
    ready: bool = false,
    /// Messages may be waiting, see `nextEvent`.
    delivered: bool = false,
    /// The dialer gave up.
    dead: bool = false,
};

/// What the dialer is built with.
pub const Options = struct {
    /// This side's ICE credentials, which the answerer knows as the peer's. Borrowed.
    local_ufrag: []const u8,
    local_password: []const u8,
    /// The answerer's ICE credentials, which every check is addressed and signed to. Borrowed.
    peer_ufrag: []const u8,
    peer_password: []const u8,

    /// The transaction identifier every check carries. One per dialer.
    transaction_id: [stun_message.TRANSACTION_ID_LEN]u8,
    /// This side's ICE role. A lite answerer cannot be controlling, so this stays CONTROLLING.
    tiebreaker: u64 = 1,

    client_random: [32]u8,
    client_eph_secret: [32]u8,

    /// Signs the SCTP state cookie this side would issue.
    sctp_cookie: [sctp_cookie.SECRET_LEN]u8,
    /// The association's initiate tag. Never zero.
    sctp_tag: u32,
    sctp_initial_tsn: u32,

    path_max_bytes: usize = 1200,
    max_datagram_bytes: usize = 1500,
    outbound_streams: u16 = 128,
    inbound_streams: u16 = 128,

    /// The label the first channel is opened with.
    channel_label: []const u8 = "zix",

    /// How long between connectivity checks while none has been answered (RFC 8445 14.2 uses 50ms
    /// as the pacing floor, and this is a two-peer session rather than a candidate sweep).
    check_interval_ms: u32 = 200,
    /// How long the whole session may take to reach READY before the dialer gives up.
    setup_timeout_ms: u32 = 15000,
};

/// The peer that dials.
///
/// Usage:
/// ```zig
/// var dialer = try Dialer.init(allocator, options, now_ms);
/// defer dialer.deinit();
///
/// var out: [1500]u8 = undefined;
/// while (dialer.nextOutbound(&out)) |datagram| try socket.send(datagram);
///
/// _ = try dialer.handle(received, now_ms);
/// while (try dialer.nextEvent(now_ms)) |event| handle(event);
/// ```
pub const Dialer = struct {
    allocator: std.mem.Allocator,
    options: Options,
    state: State,
    deadlines: timer.Deadlines,

    /// The USERNAME every check carries, built once.
    username: [ice_credentials.MAX_USERNAME_LEN]u8,
    username_len: usize,

    handshake: dtls_client.State,
    connection: ?dtls_client.ClientConnection,
    server_verify_data: [dtls_client.VERIFY_DATA_LEN]u8,
    flight: dtls_flight.Flight,

    /// The server flight, collected message by message.
    reassembler: dtls_handshake.Reassembler(MAX_HANDSHAKE_MESSAGE),
    server_hello: []u8,
    server_hello_len: usize,
    certificate: []u8,
    certificate_len: usize,
    key_exchange: []u8,
    key_exchange_len: usize,
    hello_done: bool,

    sctp: ?*association.Association,
    channels: ?datachannel.Peer,
    channel: ?u16,

    /// Datagrams ready to send, packed back to back.
    queue: []u8,
    queue_len: [MAX_QUEUED]usize,
    queue_count: usize,
    queue_used: usize,
    queue_taken: usize,
    queue_offset: usize,

    /// The last DTLS flight, kept so a timeout can send it again.
    last_flight: []u8,
    last_flight_len: usize,

    /// Where one packet is built before it is wrapped or queued.
    scratch: []u8,
    /// Where an opened record's plaintext lands.
    plain: []u8,

    /// Build a dialer and queue its first connectivity check.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (owns every buffer and, later, the association)
    /// options - Options (borrows every slice in it, which must outlive the dialer)
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - Dialer in CHECKING, with a check already waiting in `nextOutbound`
    /// - error.OutOfMemory, error.ZixNoSpace
    pub fn init(allocator: std.mem.Allocator, options: Options, now_ms: u64) Error!Dialer {
        const queue = try allocator.alloc(u8, MAX_QUEUED * (options.max_datagram_bytes + DTLS_OVERHEAD));
        errdefer allocator.free(queue);

        const last_flight = try allocator.alloc(u8, MAX_HANDSHAKE_MESSAGE + 1024);
        errdefer allocator.free(last_flight);

        const scratch = try allocator.alloc(u8, options.max_datagram_bytes);
        errdefer allocator.free(scratch);

        const plain = try allocator.alloc(u8, options.max_datagram_bytes);
        errdefer allocator.free(plain);

        const server_hello = try allocator.alloc(u8, 512);
        errdefer allocator.free(server_hello);

        const certificate = try allocator.alloc(u8, MAX_HANDSHAKE_MESSAGE);
        errdefer allocator.free(certificate);

        const key_exchange = try allocator.alloc(u8, 512);

        var dialer: Dialer = .{
            .allocator = allocator,
            .options = options,
            .state = .CHECKING,
            .deadlines = .{},
            .username = undefined,
            .username_len = 0,
            .handshake = dtls_client.start(.{
                .client_random = options.client_random,
                .client_eph_secret = options.client_eph_secret,
            }),
            .connection = null,
            .server_verify_data = @splat(0),
            .flight = dtls_flight.Flight.initClient(),
            .reassembler = .{},
            .server_hello = server_hello,
            .server_hello_len = 0,
            .certificate = certificate,
            .certificate_len = 0,
            .key_exchange = key_exchange,
            .key_exchange_len = 0,
            .hello_done = false,
            .sctp = null,
            .channels = null,
            .channel = null,
            .queue = queue,
            .queue_len = @splat(0),
            .queue_count = 0,
            .queue_used = 0,
            .queue_taken = 0,
            .queue_offset = 0,
            .last_flight = last_flight,
            .last_flight_len = 0,
            .scratch = scratch,
            .plain = plain,
        };

        const username = ice_credentials.writeUsername(&dialer.username, options.peer_ufrag, options.local_ufrag) catch
            return error.ZixNoSpace;
        dialer.username_len = username.len;

        // The whole session gets one budget. Nothing below it is allowed to hang forever.
        dialer.deadlines.armIn(.IDLE, now_ms, options.setup_timeout_ms);
        try dialer.sendCheck(now_ms);

        return dialer;
    }

    /// Free everything the dialer holds.
    pub fn deinit(self: *Dialer) void {
        if (self.channels) |*channels| channels.deinit();

        if (self.sctp) |sctp| {
            sctp.deinit();
            self.allocator.destroy(sctp);
        }

        self.allocator.free(self.queue);
        self.allocator.free(self.last_flight);
        self.allocator.free(self.scratch);
        self.allocator.free(self.plain);
        self.allocator.free(self.server_hello);
        self.allocator.free(self.certificate);
        self.allocator.free(self.key_exchange);
    }

    /// Whether a channel is open and messages can flow.
    pub fn isReady(self: Dialer) bool {
        return self.state == .READY;
    }

    /// Whether the dialer gave up.
    pub fn isDead(self: Dialer) bool {
        return self.state == .FAILED;
    }

    /// The stream identifier of the channel this dialer opened, once it is usable.
    pub fn channelId(self: Dialer) ?u16 {
        return self.channel;
    }

    /// When the dialer next needs looking at, or null when it needs nothing.
    pub fn deadline(self: Dialer) ?u64 {
        return self.deadlines.earliest();
    }

    /// Handle one datagram from the answerer.
    ///
    /// Param:
    /// datagram - []const u8
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - Outcome
    pub fn handle(self: *Dialer, datagram: []const u8, now_ms: u64) Error!Outcome {
        if (self.state == .FAILED) return .{ .dead = true };

        var outcome: Outcome = .{};

        switch (demux.classify(datagram)) {
            .STUN => try self.onStun(datagram, now_ms),
            .DTLS => try self.onDtls(datagram, now_ms, &outcome),
            else => {},
        }

        outcome.dead = self.state == .FAILED;

        return outcome;
    }

    /// Act on every deadline that has passed.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - Outcome
    pub fn tick(self: *Dialer, now_ms: u64) Error!Outcome {
        if (self.state == .FAILED) return .{ .dead = true };

        while (self.deadlines.takeExpired(now_ms)) |kind| switch (kind) {
            .ICE_CONSENT => if (self.state == .CHECKING) try self.sendCheck(now_ms),
            .DTLS_RETRANSMIT => try self.resendFlight(now_ms),
            .SCTP_RETRANSMIT => {
                if (self.sctp) |sctp| sctp.onRetransmitTimeout(now_ms);
            },
            // The whole session ran out of time, whichever step it was on.
            .IDLE => self.state = .FAILED,
        };

        self.syncDeadlines(now_ms);

        return .{ .dead = self.state == .FAILED };
    }

    /// The next datagram to send.
    ///
    /// Note:
    /// - Call in a loop until it returns null.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    /// out - []u8
    ///
    /// Return:
    /// - ?[]const u8 (borrowing out)
    pub fn nextOutbound(self: *Dialer, now_ms: u64, out: []u8) Error!?[]const u8 {
        if (self.takeQueued()) |datagram| {
            if (out.len < datagram.len) return error.ZixNoSpace;

            @memcpy(out[0..datagram.len], datagram);

            return out[0..datagram.len];
        }

        if (self.channels) |*channels| {
            if (self.connection == null) return null;

            const packet = (try channels.nextOutbound(now_ms, self.scratch)) orelse return null;
            const wrapped = self.connection.?.writeAppData(packet, out) catch return error.ZixNoSpace;

            self.syncDeadlines(now_ms);

            return wrapped;
        }

        return null;
    }

    /// The next thing the application has to know about.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - ?core.Event
    pub fn nextEvent(self: *Dialer, now_ms: u64) Error!?core.Event {
        if (self.channels) |*channels| {
            const event = (try channels.nextEvent(now_ms)) orelse return null;

            return switch (event) {
                .CHANNEL_OPEN => |identifier| .{ .CHANNEL_OPEN = identifier },
                .CHANNEL_CLOSED => |identifier| .{ .CHANNEL_CLOSED = identifier },
                .MESSAGE => |incoming| .{ .MESSAGE = .{
                    .channel = incoming.stream_identifier,
                    .kind = incoming.kind,
                    .payload = incoming.payload,
                } },
            };
        }

        return null;
    }

    /// Send a message on the channel this dialer opened.
    ///
    /// Param:
    /// kind - core.Kind
    /// bytes - []const u8 (copied)
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSuchChannel before a channel is open
    pub fn send(self: *Dialer, kind: core.Kind, bytes: []const u8, now_ms: u64) Error!void {
        const identifier = self.channel orelse return error.ZixNoSuchChannel;

        if (self.channels) |*channels| return channels.sendMessage(identifier, kind, bytes, now_ms);

        return error.ZixNoSuchChannel;
    }

    /// Build and queue one connectivity check (RFC 8445 7.1.1).
    fn sendCheck(self: *Dialer, now_ms: u64) Error!void {
        const check = ice_check.writeRequest(self.scratch, .{
            .transaction_id = self.options.transaction_id,
            .username = self.username[0..self.username_len],
            .password = self.options.peer_password,
            .priority = 1,
            .role = .CONTROLLING,
            .tiebreaker = self.options.tiebreaker,
            .use_candidate = true,
        }) catch return error.ZixNoSpace;

        self.enqueue(check);
        self.deadlines.armIn(.ICE_CONSENT, now_ms, self.options.check_interval_ms);
    }

    /// Take one datagram that demux routed to STUN.
    fn onStun(self: *Dialer, datagram: []const u8, now_ms: u64) Error!void {
        if (self.state != .CHECKING) return;

        const response = stun_message.parse(datagram) catch return;

        if (response.class != .SUCCESS_RESPONSE) return;
        if (response.method != .BINDING) return;
        if (!std.mem.eql(u8, &response.transaction_id, &self.options.transaction_id)) return;
        if (response.messageIntegrity(self.options.peer_password) != .VALID) return;

        // The pair is usable, so the handshake can start over it.
        self.deadlines.disarm(.ICE_CONSENT);
        self.state = .HANDSHAKING;

        try self.sendHello("", now_ms);
    }

    /// Build and queue a ClientHello, keeping it for retransmission.
    fn sendHello(self: *Dialer, cookie: []const u8, now_ms: u64) Error!void {
        const record = dtls_client.writeHello(&self.handshake, cookie, self.scratch) catch return error.ZixNoSpace;

        self.keepFlight(record);
        self.enqueue(record);
        self.armFlight(now_ms);
    }

    /// Take one datagram that demux routed to DTLS.
    fn onDtls(self: *Dialer, datagram: []const u8, now_ms: u64, outcome: *Outcome) Error!void {
        var records: dtls_record.RecordIterator = .{ .datagram = datagram };

        while (records.next() catch null) |record| {
            const header = dtls_record.parseHeader(record) catch break;

            if (header.epoch == dtls_connection.EPOCH_APPLICATION) {
                try self.onProtectedRecord(record, now_ms, outcome);

                continue;
            }

            if (header.content_type != .HANDSHAKE) continue;

            const body = dtls_record.plaintextFragment(record) catch continue;
            var fragments: dtls_handshake.FragmentIterator = .{ .body = body };

            while (fragments.next() catch null) |fragment| try self.onHandshakeFragment(fragment, now_ms);
        }
    }

    /// Take one handshake fragment from the server.
    fn onHandshakeFragment(self: *Dialer, fragment: dtls_handshake.Fragment, now_ms: u64) Error!void {
        if (self.state != .HANDSHAKING) return;

        self.reassembler.reset();
        self.reassembler.accept(fragment) catch return;

        const message = self.reassembler.message() orelse return;

        switch (fragment.header.msg_type) {
            .HELLO_VERIFY_REQUEST => {
                const cookie = dtls_hello.parseHelloVerifyRequestBody(message) catch return;

                self.flight.onPeerFlight(false);
                try self.sendHello(cookie, now_ms);
            },
            .SERVER_HELLO => self.server_hello_len = copyInto(self.server_hello, message),
            .CERTIFICATE => self.certificate_len = copyInto(self.certificate, message),
            .SERVER_KEY_EXCHANGE => self.key_exchange_len = copyInto(self.key_exchange, message),
            .SERVER_HELLO_DONE => {
                self.hello_done = true;

                try self.answerServerFlight(now_ms);
            },
            else => {},
        }
    }

    /// Answer a complete server flight with ClientKeyExchange, ChangeCipherSpec, and Finished.
    fn answerServerFlight(self: *Dialer, now_ms: u64) Error!void {
        if (self.server_hello_len == 0 or self.key_exchange_len == 0) return;

        const answer = dtls_client.finish(&self.handshake, .{
            .server_hello = self.server_hello[0..self.server_hello_len],
            .certificate = self.certificate[0..self.certificate_len],
            .key_exchange = self.key_exchange[0..self.key_exchange_len],
            .hello_done = "",
        }, self.last_flight) catch {
            self.state = .FAILED;

            return;
        };

        self.last_flight_len = answer.to_send.len;
        self.server_verify_data = answer.server_verify_data;
        self.connection = answer.connection;

        self.flight.onPeerFlight(false);
        self.queueFlight();
        self.armFlight(now_ms);
    }

    /// Take one epoch 1 record: the server Finished, or application data once it is past.
    fn onProtectedRecord(self: *Dialer, record: []const u8, now_ms: u64, outcome: *Outcome) Error!void {
        if (self.connection == null) return;

        const opened = (self.connection.?.readRecord(record, self.plain) catch return) orelse return;

        if (self.state == .HANDSHAKING) {
            const verify_data = dtls_client.serverFinishedVerifyData(opened) orelse return;

            if (!std.mem.eql(u8, verify_data, &self.server_verify_data)) {
                self.state = .FAILED;

                return;
            }

            self.flight.onPeerFlight(true);
            self.deadlines.disarm(.DTLS_RETRANSMIT);
            outcome.secured = true;

            try self.openAssociation(now_ms);

            return;
        }

        try self.onSctpPacket(opened, now_ms, outcome);
    }

    /// Build the association and send the INIT that opens it.
    fn openAssociation(self: *Dialer, now_ms: u64) Error!void {
        const sctp = try self.allocator.create(association.Association);
        errdefer self.allocator.destroy(sctp);

        sctp.* = try association.Association.init(self.allocator, .{
            .outbound_streams = self.options.outbound_streams,
            .inbound_streams = self.options.inbound_streams,
            .path_max_bytes = self.options.path_max_bytes -| DTLS_OVERHEAD,
        }, self.options.sctp_cookie, .{
            .tag = self.options.sctp_tag,
            .initial_tsn = self.options.sctp_initial_tsn,
        });

        self.sctp = sctp;
        self.channels = datachannel.Peer.init(self.allocator, sctp, .{
            // This side took the DTLS client role, so it opens on even identifiers (RFC 8832 6).
            .role = .DTLS_CLIENT,
        });
        self.state = .ASSOCIATING;

        const init_packet = try sctp.connect(self.scratch);
        try self.queueWrapped(init_packet);
        self.syncDeadlines(now_ms);
    }

    /// Take one SCTP packet that came out of a DTLS record.
    fn onSctpPacket(self: *Dialer, packet: []const u8, now_ms: u64, outcome: *Outcome) Error!void {
        if (self.channels == null) return;

        const result = self.channels.?.handle(packet, now_ms, self.scratch) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return,
        };

        if (result.reply) |reply| try self.queueWrapped(reply);
        if (result.delivered) outcome.delivered = true;
        if (result.aborted) self.state = .FAILED;

        if (result.established and self.state == .ASSOCIATING) {
            self.channel = self.channels.?.openChannel(.{ .label = self.options.channel_label }, now_ms) catch {
                self.state = .FAILED;

                return;
            };
            self.state = .OPENING;
        }

        self.syncDeadlines(now_ms);
    }

    /// Move to READY once the channel this dialer opened is usable.
    ///
    /// Note:
    /// - Called by the caller's event loop through `nextEvent`, so the transition is reported to
    ///   the application and recorded here in the same pass.
    pub fn onChannelOpen(self: *Dialer, identifier: u16) void {
        if (self.channel) |opened| {
            if (opened != identifier) return;
        }

        self.channel = identifier;
        self.state = .READY;
        self.deadlines.disarm(.IDLE);
    }

    /// Send the last flight again, or give up if it has had every chance.
    fn resendFlight(self: *Dialer, now_ms: u64) Error!void {
        const action = self.flight.onTick(now_ms) orelse return;

        switch (action) {
            .RETRANSMIT => {
                self.queueFlight();
                self.armFlight(now_ms);
            },
            .GIVE_UP => self.state = .FAILED,
        }
    }

    /// Note that a flight went out and start waiting for its answer.
    fn armFlight(self: *Dialer, now_ms: u64) void {
        self.flight.sending();
        self.flight.sent(now_ms, true);
        self.syncDeadlines(now_ms);
    }

    /// Bring the deadline set in line with what the layers below are waiting on.
    fn syncDeadlines(self: *Dialer, now_ms: u64) void {
        if (self.flight.timer.deadline_ms) |at_ms| {
            self.deadlines.arm(.DTLS_RETRANSMIT, at_ms);
        } else {
            self.deadlines.disarm(.DTLS_RETRANSMIT);
        }

        const sctp = self.sctp orelse return;

        if (sctp.send.count() == 0) {
            self.deadlines.disarm(.SCTP_RETRANSMIT);

            return;
        }

        if (!self.deadlines.isArmed(.SCTP_RETRANSMIT)) {
            self.deadlines.armIn(.SCTP_RETRANSMIT, now_ms, sctp.timer.timeout_ms);
        }
    }

    /// Keep a flight so a timeout can send it again.
    fn keepFlight(self: *Dialer, bytes: []const u8) void {
        self.last_flight_len = copyInto(self.last_flight, bytes);
    }

    /// Queue the kept flight, split on record boundaries.
    fn queueFlight(self: *Dialer) void {
        if (self.last_flight_len == 0) return;

        const flight = self.last_flight[0..self.last_flight_len];
        var records: dtls_record.RecordIterator = .{ .datagram = flight };
        var start: usize = 0;
        var take: usize = 0;

        while (records.next() catch null) |record| {
            if (take > 0 and take + record.len > self.options.path_max_bytes) {
                self.enqueue(flight[start..][0..take]);
                start += take;
                take = 0;
            }

            take += record.len;
        }

        if (take > 0) self.enqueue(flight[start..][0..take]);
    }

    /// Wrap an SCTP packet in a DTLS record and queue it.
    fn queueWrapped(self: *Dialer, packet: []const u8) Error!void {
        if (self.connection == null) return;
        if (self.queue_count >= MAX_QUEUED) return;

        const wrapped = self.connection.?.writeAppData(packet, self.queue[self.queue_used..]) catch return error.ZixNoSpace;

        self.queue_len[self.queue_count] = wrapped.len;
        self.queue_count += 1;
        self.queue_used += wrapped.len;
    }

    /// Hold one datagram for sending.
    fn enqueue(self: *Dialer, datagram: []const u8) void {
        if (self.queue_count >= MAX_QUEUED) return;
        if (self.queue_used + datagram.len > self.queue.len) return;

        @memcpy(self.queue[self.queue_used..][0..datagram.len], datagram);
        self.queue_len[self.queue_count] = datagram.len;
        self.queue_count += 1;
        self.queue_used += datagram.len;
    }

    /// The next queued datagram, or null when the queue is spent.
    fn takeQueued(self: *Dialer) ?[]const u8 {
        if (self.queue_taken >= self.queue_count) {
            self.resetQueue();

            return null;
        }

        const len = self.queue_len[self.queue_taken];
        const datagram = self.queue[self.queue_offset..][0..len];

        self.queue_taken += 1;
        self.queue_offset += len;

        return datagram;
    }

    /// Start the queue over, which is what draining it leaves behind.
    fn resetQueue(self: *Dialer) void {
        self.queue_count = 0;
        self.queue_used = 0;
        self.queue_taken = 0;
        self.queue_offset = 0;
    }
};

/// Copy what fits into a buffer, answering how much went in.
fn copyInto(dst: []u8, src: []const u8) usize {
    const len = @min(dst.len, src.len);

    @memcpy(dst[0..len], src[0..len]);

    return len;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const connection = @import("connection.zig");
const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const TEST_DER = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };
const ANSWERER_ADDRESS: IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 9084 } };
const ANSWERER_UFRAG = "zixA";
const ANSWERER_PASSWORD = "answererpasswordaaaaaa";
const DIALER_UFRAG = "zixD";
const DIALER_PASSWORD = "dialerpasswordbbbbbbbb";

fn testSigningKey() !EcdsaP256.KeyPair {
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");

    return EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(secret));
}

fn testDialerOptions() Options {
    return .{
        .local_ufrag = DIALER_UFRAG,
        .local_password = DIALER_PASSWORD,
        .peer_ufrag = ANSWERER_UFRAG,
        .peer_password = ANSWERER_PASSWORD,
        .transaction_id = @splat(0x77),
        .client_random = @splat(0x11),
        .client_eph_secret = @splat(0x44),
        .sctp_cookie = @splat(0x9C),
        .sctp_tag = 0x55667788,
        .sctp_initial_tsn = 5000,
        .channel_label = "echo",
    };
}

fn testAnswererOptions() !connection.Options {
    return .{
        .ice_ufrag = ANSWERER_UFRAG,
        .ice_password = ANSWERER_PASSWORD,
        .peer_ice_ufrag = DIALER_UFRAG,
        .certificate_der = &TEST_DER,
        .signing_key = try testSigningKey(),
    };
}

fn testAnswererSecrets() connection.Secrets {
    return .{
        .dtls_cookie = @splat(0x5A),
        .sctp_cookie = @splat(0x6B),
        .server_random = @splat(0x33),
        .server_eph_secret = @splat(0x22),
        .sctp_tag = 0x11223344,
        .sctp_initial_tsn = 1000,
    };
}

test "zix webrtc: dialer, a fresh dialer has a connectivity check ready to go" {
    var dialer = try Dialer.init(std.testing.allocator, testDialerOptions(), 0);
    defer dialer.deinit();

    try std.testing.expectEqual(State.CHECKING, dialer.state);
    try std.testing.expect(!dialer.isReady());
    try std.testing.expect(!dialer.isDead());

    var out: [1500]u8 = undefined;
    const check = (try dialer.nextOutbound(0, &out)).?;

    const parsed = try stun_message.parse(check);
    try std.testing.expectEqual(stun_message.Class.REQUEST, parsed.class);
    try std.testing.expectEqual(stun_message.Method.BINDING, parsed.method);
    try std.testing.expectEqual(stun_message.IntegrityState.VALID, parsed.messageIntegrity(ANSWERER_PASSWORD));

    try std.testing.expectEqual(@as(?[]const u8, null), try dialer.nextOutbound(0, &out));
}

test "zix webrtc: dialer, an unanswered check goes out again on its interval" {
    var options = testDialerOptions();
    options.check_interval_ms = 200;

    var dialer = try Dialer.init(std.testing.allocator, options, 0);
    defer dialer.deinit();

    var out: [1500]u8 = undefined;
    _ = (try dialer.nextOutbound(0, &out)).?;

    _ = try dialer.tick(199);
    try std.testing.expectEqual(@as(?[]const u8, null), try dialer.nextOutbound(199, &out));

    _ = try dialer.tick(200);
    try std.testing.expect((try dialer.nextOutbound(200, &out)) != null);
}

test "zix webrtc: dialer, a session that never gets anywhere gives up on its budget" {
    var options = testDialerOptions();
    options.setup_timeout_ms = 1000;

    var dialer = try Dialer.init(std.testing.allocator, options, 0);
    defer dialer.deinit();

    try std.testing.expect(!(try dialer.tick(999)).dead);
    try std.testing.expect((try dialer.tick(1000)).dead);
    try std.testing.expectEqual(State.FAILED, dialer.state);
}

test "zix webrtc: dialer, a response signed with the wrong password is ignored" {
    var dialer = try Dialer.init(std.testing.allocator, testDialerOptions(), 0);
    defer dialer.deinit();

    var answerer = try connection.Connection.init(std.testing.allocator, ANSWERER_ADDRESS, try testAnswererOptions(), testAnswererSecrets(), 0);
    defer answerer.deinit();

    var out: [1500]u8 = undefined;
    const check = (try dialer.nextOutbound(0, &out)).?;

    var check_copy: [1500]u8 = undefined;
    @memcpy(check_copy[0..check.len], check);

    _ = try answerer.handle(check_copy[0..check.len], 0);

    var reply_buf: [1500]u8 = undefined;
    const reply = (try answerer.nextOutbound(0, &reply_buf)).?;

    // Flip a byte of the integrity attribute, which is what a forged response looks like.
    var forged: [1500]u8 = undefined;
    @memcpy(forged[0..reply.len], reply);
    forged[reply.len - 12] ^= 0xFF;

    _ = try dialer.handle(forged[0..reply.len], 0);
    try std.testing.expectEqual(State.CHECKING, dialer.state);
}
