//! zix WebRTC connection: one peer, and the four layers a datagram from it can belong to.
//!
//! What:
//! - The state machine that turns "a datagram arrived from this address" into "here is what goes
//!   back, and here is what the application has to know about". ICE answers checks, DTLS runs the
//!   handshake and then wraps everything, SCTP carries the association, and the channel layer turns
//!   it into messages.
//! - Owns no socket and reads no clock. Every entry point takes the time from the caller and hands
//!   back bytes, which is what makes a full exchange testable in memory with no port and no sleep.
//!
//! Note:
//! - One connection is one peer address. A peer that migrates to a new address is a new connection
//!   to this file, which is correct for ICE-lite: the address that answers checks is the pair, and
//!   a changed address is a new pair the peer has to nominate.
//! - The layers are built in the order the wire builds them. There is no SCTP association until
//!   the DTLS handshake finishes, because the keys that protect it do not exist before then.
//! - Errors from a peer are the peer's problem. A malformed SCTP packet, a check that fails
//!   authentication, and a handshake message out of order all leave the connection alive, because
//!   the alternative is letting anyone who can guess an address end someone else's session.

const std = @import("std");

const core = @import("core.zig");
const datachannel = @import("datachannel/peer.zig");
const demux = @import("demux.zig");
const dtls_cookie = @import("../../tls/dtls_cookie.zig");
const dtls_exporter = @import("../../tls/dtls_exporter.zig");
const dtls_session = @import("dtls_session.zig");
const feedback = @import("media/feedback.zig");
const mux = @import("media/mux.zig");
const peer_media = @import("media/peer_media.zig");
const rtcp = @import("media/rtcp.zig");
const rtp = @import("media/rtp.zig");
const ice_credentials = @import("ice/credentials.zig");
const ice_lite = @import("ice/lite.zig");
const association = @import("sctp/association.zig");
const sctp_cookie = @import("sctp/cookie.zig");
const timer = @import("timer.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const IpAddress = std.Io.net.IpAddress;

/// What a DTLS record adds around one SCTP packet: the header, the explicit nonce, and the tag.
pub const DTLS_OVERHEAD: usize = 13 + 8 + 16;

/// The identifier zix puts on the control packets it sends.
///
/// Note:
/// - A forwarder sends no media of its own, so it needs one identifier for the whole control path
///   rather than one per stream. What matters is only that it is not a stream identifier any peer
///   is sending under, and a browser draws those at random across the full range.
pub const FORWARDER_SSRC: u32 = 0x7A69_7800;

/// How many packets one received datagram may leave queued for sending.
///
/// Note:
/// - One datagram normally produces one, being the acknowledgement for the packet it carried.
///   Past this ceiling the rest are not built, and SCTP retransmits whatever went unacknowledged.
pub const MAX_QUEUED: usize = 8;

/// The random values one connection needs at birth.
///
/// Note:
/// - Taken from the caller rather than drawn here, so a test can pin them and the engine can draw
///   them from the one place that is allowed to reach for ambient state.
/// - `server_random` and `server_eph_secret` belong to exactly one handshake and are never reused
///   across connections.
pub const Secrets = struct {
    /// Signs the DTLS cookie that makes the first ClientHello stateless (RFC 6347 4.2.1).
    dtls_cookie: [dtls_cookie.SECRET_LEN]u8,
    /// Signs the SCTP state cookie, for the same reason one layer up (RFC 9260 5.1.3).
    sctp_cookie: [sctp_cookie.SECRET_LEN]u8,
    server_random: [32]u8,
    server_eph_secret: [32]u8,
    /// The association's initiate tag, which the peer echoes in every packet. Never zero.
    sctp_tag: u32,
    /// The first TSN the association will use.
    sctp_initial_tsn: u32,
};

/// What one connection is built with. Assembled by the engine from its config.
pub const Options = struct {
    /// This agent's ICE credentials, the pair every check is verified against. Borrowed.
    ice_ufrag: []const u8,
    ice_password: []const u8,
    /// The peer's ufrag, the second half of the USERNAME its checks carry. Borrowed. Null takes
    /// whatever the peer calls itself, which is what a peer that draws its own ufrag needs.
    peer_ice_ufrag: ?[]const u8,

    /// The certificate this server presents, DER encoded. Borrowed.
    certificate_der: []const u8,
    signing_key: EcdsaP256.KeyPair,
    max_handshake_fragment: usize = 1024,

    /// The SRTP profiles this endpoint offers in the use_srtp extension, best first. Borrowed.
    /// Empty answers no media: the handshake exports no keys, and RTP from the peer is dropped
    /// where it is routed, which is what a data-channel-only server wants.
    srtp_profiles: []const dtls_exporter.SrtpProfile = &.{},

    /// Largest datagram this connection sends.
    path_max_bytes: usize = 1200,
    /// Largest datagram this connection is handed.
    max_datagram_bytes: usize = 1500,

    outbound_streams: u16 = 128,
    inbound_streams: u16 = 128,
    max_channels: usize = 64,

    /// How long the peer may say nothing before the connection is dropped.
    peer_idle_ms: u32 = 30000,
    /// How long after the last authenticated check consent lapses (RFC 7675 5.1).
    consent_timeout_ms: u32 = 30000,
};

/// Everything driving one connection can raise.
pub const Error = datachannel.Error || dtls_session.Error;

/// What one datagram, or one tick, did.
pub const Outcome = struct {
    /// The DTLS handshake completed, so the association exists from here on.
    established: bool = false,
    /// Messages may be waiting, see `nextEvent`.
    delivered: bool = false,
    /// A media packet was opened and is waiting for whoever forwards it, see `openedMedia`.
    media: bool = false,
    /// A receiver asked for a keyframe, see `takeKeyframeRequest`.
    keyframe_requested: bool = false,
    /// The connection is finished and the engine should drop it.
    dead: bool = false,
};

/// One WebRTC peer.
///
/// Usage:
/// ```zig
/// var conn = try Connection.init(allocator, peer_address, options, secrets, now_ms);
/// defer conn.deinit();
///
/// _ = try conn.handle(datagram, now_ms);
///
/// var out: [1500]u8 = undefined;
/// while (try conn.nextOutbound(now_ms, &out)) |packet| try socket.send(packet);
/// while (try conn.nextEvent(now_ms)) |event| try handler(event, &conn.context(now_ms).?);
/// ```
pub const Connection = struct {
    allocator: std.mem.Allocator,
    /// Where this peer sits. One connection is one address.
    address: IpAddress,
    options: Options,
    secrets: Secrets,

    ice: ice_lite.Responder,
    dtls: dtls_session.Session,
    /// Heap-allocated so the channel layer's pointer into it survives this struct being moved.
    sctp: ?*association.Association,
    channels: ?datachannel.Peer,

    deadlines: timer.Deadlines,
    /// Outstanding SCTP chunks at the last look, for spotting an acknowledgement that took some
    /// off the list (RFC 9260 6.3.2 R3).
    outstanding: usize,

    /// The ICE response to the last check, waiting to go out.
    ice_reply: [ice_lite.MAX_RESPONSE_BYTES]u8,
    ice_reply_len: usize,

    /// Packets built while handling one datagram, already wrapped in DTLS, packed back to back.
    queue: []u8,
    queue_len: [MAX_QUEUED]usize,
    queue_count: usize,
    queue_used: usize,
    queue_taken: usize,
    queue_offset: usize,

    /// Where one SCTP packet is built before it is wrapped.
    scratch: []u8,

    /// This peer's SRTP keys and streams, once the handshake has agreed on a profile. Null on a
    /// peer that offered no use_srtp, and on every peer of a server that answers no media.
    media: ?peer_media.PeerMedia,
    /// Where one media datagram is opened, in place. Held until the next datagram arrives, which
    /// is what lets a forwarder seal it for everybody else in between.
    media_buf: []u8,
    /// The source's own header of the packet in `media_buf`, before any renumbering.
    media_header: rtp.Header,
    media_len: usize,
    media_ready: bool,
    /// The stream a receiver asked for a keyframe on, named as its SOURCE sends it. Cleared when
    /// the engine takes it.
    keyframe_for: ?u32,

    dead: bool,

    /// Build a connection for a peer that has just been heard from.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (owns the buffers and, later, the association)
    /// address - IpAddress (where the peer sits)
    /// options - Options (borrows every slice in it, which must outlive the connection)
    /// secrets - Secrets
    /// now_ms - u64 (monotonic milliseconds, when the idle deadline starts counting)
    ///
    /// Return:
    /// - Connection with nothing negotiated yet
    /// - error.OutOfMemory
    pub fn init(
        allocator: std.mem.Allocator,
        address: IpAddress,
        options: Options,
        secrets: Secrets,
        now_ms: u64,
    ) Error!Connection {
        var dtls = try dtls_session.Session.init(allocator, address, .{
            .certificate_der = options.certificate_der,
            .signing_key = options.signing_key,
            .cookie_secret = secrets.dtls_cookie,
            .server_random = secrets.server_random,
            .server_eph_secret = secrets.server_eph_secret,
            .max_fragment_len = options.max_handshake_fragment,
            .path_max_bytes = options.path_max_bytes,
            .srtp_profiles = options.srtp_profiles,
        }, options.max_datagram_bytes);
        errdefer dtls.deinit();

        const queue = try allocator.alloc(u8, MAX_QUEUED * (options.path_max_bytes + DTLS_OVERHEAD));
        errdefer allocator.free(queue);

        const scratch = try allocator.alloc(u8, options.path_max_bytes);
        errdefer allocator.free(scratch);

        // Only a server that answers media ever opens one, so a data-channel-only peer pays
        // nothing for this.
        const media_buf = if (options.srtp_profiles.len == 0)
            try allocator.alloc(u8, 0)
        else
            try allocator.alloc(u8, options.max_datagram_bytes);

        var deadlines: timer.Deadlines = .{};
        deadlines.armIn(.IDLE, now_ms, options.peer_idle_ms);

        return .{
            .allocator = allocator,
            .address = address,
            .options = options,
            .secrets = secrets,
            .ice = .{
                .local = .{ .ufrag = options.ice_ufrag, .password = options.ice_password },
                .remote_ufrag = options.peer_ice_ufrag,
            },
            .dtls = dtls,
            .sctp = null,
            .channels = null,
            .deadlines = deadlines,
            .outstanding = 0,
            .ice_reply = undefined,
            .ice_reply_len = 0,
            .queue = queue,
            .queue_len = @splat(0),
            .queue_count = 0,
            .queue_used = 0,
            .queue_taken = 0,
            .queue_offset = 0,
            .scratch = scratch,
            .media = null,
            .media_buf = media_buf,
            .media_header = undefined,
            .media_len = 0,
            .media_ready = false,
            .keyframe_for = null,
            .dead = false,
        };
    }

    /// Free everything the connection holds.
    pub fn deinit(self: *Connection) void {
        if (self.channels) |*channels| channels.deinit();

        if (self.sctp) |sctp| {
            sctp.deinit();
            self.allocator.destroy(sctp);
        }

        self.dtls.deinit();
        self.allocator.free(self.queue);
        self.allocator.free(self.scratch);
        self.allocator.free(self.media_buf);
    }

    /// Whether the engine should drop this peer.
    pub fn isDead(self: Connection) bool {
        return self.dead;
    }

    /// Whether the association is up and channels can carry messages.
    pub fn isEstablished(self: Connection) bool {
        return self.dtls.isEstablished();
    }

    /// When this connection next needs looking at, or null when it needs nothing.
    pub fn deadline(self: Connection) ?u64 {
        return self.deadlines.earliest();
    }

    /// Handle one datagram from this peer.
    ///
    /// Param:
    /// datagram - []const u8 (one received datagram)
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - Outcome
    /// - error.OutOfMemory, error.ZixNoSpace
    pub fn handle(self: *Connection, datagram: []const u8, now_ms: u64) Error!Outcome {
        if (self.dead) return .{ .dead = true };

        self.resetQueue();
        self.media_ready = false;
        self.deadlines.armIn(.IDLE, now_ms, self.options.peer_idle_ms);

        var outcome: Outcome = .{};

        switch (demux.classify(datagram)) {
            .STUN => self.onStun(datagram, now_ms),
            .DTLS => try self.onDtls(datagram, now_ms, &outcome),
            .RTP => self.onMedia(datagram, &outcome),
            else => {},
        }

        self.syncDeadlines(now_ms);
        outcome.dead = self.dead;

        return outcome;
    }

    /// Act on every deadline that has passed.
    ///
    /// Note:
    /// - Cheap to call on every loop pass. With nothing due it does nothing.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - Outcome
    pub fn tick(self: *Connection, now_ms: u64) Outcome {
        if (self.dead) return .{ .dead = true };

        while (self.deadlines.takeExpired(now_ms)) |kind| switch (kind) {
            .DTLS_RETRANSMIT => {
                _ = self.dtls.onTimeout(now_ms);

                if (self.dtls.state == .FAILED) self.dead = true;
            },
            .SCTP_RETRANSMIT => {
                if (self.sctp) |sctp| sctp.onRetransmitTimeout(now_ms);
            },
            // A peer that stopped proving it is there, or stopped speaking at all, is gone.
            .ICE_CONSENT, .IDLE => self.dead = true,
        };

        self.syncDeadlines(now_ms);

        return .{ .dead = self.dead };
    }

    /// The next datagram to send to this peer.
    ///
    /// Note:
    /// - Call in a loop until it returns null. The order is fixed: the ICE response first, then
    ///   the DTLS handshake, then what the association owes. Nothing later matters to a peer that
    ///   has not finished the step before it.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    /// out - []u8 (destination, at least path_max_bytes wide)
    ///
    /// Return:
    /// - ?[]const u8 (a datagram, borrowing out)
    /// - error.ZixNoSpace when out cannot hold what was ready
    pub fn nextOutbound(self: *Connection, now_ms: u64, out: []u8) Error!?[]const u8 {
        if (self.ice_reply_len > 0) {
            const reply = self.ice_reply[0..self.ice_reply_len];
            self.ice_reply_len = 0;

            return try copyOut(reply, out);
        }

        if (self.dtls.nextOutbound(out)) |piece| return piece;

        if (self.takeQueued()) |packet| return try copyOut(packet, out);

        if (!self.dtls.isEstablished()) return null;

        if (self.channels) |*channels| {
            const packet = (try channels.nextOutbound(now_ms, self.scratch)) orelse return null;
            const wrapped = try self.dtls.writeAppData(packet, out);

            self.syncDeadlines(now_ms);

            return wrapped;
        }

        return null;
    }

    /// The next thing the application has to know about.
    ///
    /// Note:
    /// - Call in a loop until it returns null. A message payload is valid until the next call.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - ?core.Event
    pub fn nextEvent(self: *Connection, now_ms: u64) Error!?core.Event {
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

    /// The handle a handler answers this peer through, or null before the association exists.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - ?core.Context
    pub fn context(self: *Connection, now_ms: u64) ?core.Context {
        if (self.channels) |*channels| return .{
            .channels = channels,
            .address = self.address,
            .now_ms = now_ms,
        };

        return null;
    }

    /// Whether this peer negotiated media, so packets can cross it.
    pub fn carriesMedia(self: Connection) bool {
        return self.media != null;
    }

    /// The media packet the last datagram carried, opened and waiting to be forwarded.
    ///
    /// Note:
    /// - Borrows this connection and is valid until its next datagram, which is as long as the
    ///   engine's fan-out for that datagram lasts.
    /// - The header is the SOURCE's own, before any renumbering, because each receiver renumbers
    ///   it differently.
    ///
    /// Return:
    /// - ?peer_media.Opened
    pub fn openedMedia(self: *Connection) ?peer_media.Opened {
        if (!self.media_ready) return null;

        return .{ .header = self.media_header, .plain = self.media_buf[0..self.media_len] };
    }

    /// Whether this peer is the one sending under a stream identifier.
    ///
    /// Param:
    /// ssrc - u32
    ///
    /// Return:
    /// - bool
    pub fn sendsStream(self: *Connection, ssrc: u32) bool {
        const held = if (self.media) |*media| media else return false;

        return held.inbound.find(ssrc) != null;
    }

    /// Whether this peer has never been given anything from a source.
    ///
    /// Note:
    /// - True for exactly one packet, since sealing the first one puts the route in the table.
    ///   That is the moment the source has to be asked for a keyframe: a stream joined partway
    ///   through is undecodable until one arrives.
    ///
    /// Param:
    /// ssrc - u32 (the source's own identifier)
    ///
    /// Return:
    /// - bool
    pub fn isNewSource(self: *Connection, ssrc: u32) bool {
        const held = if (self.media) |*media| media else return false;

        return held.routes.find(ssrc) == null;
    }

    /// Seal one opened packet for this peer.
    ///
    /// Note:
    /// - A peer that cannot take it is not an error. One member of a room past its stream ceiling,
    ///   or one that negotiated no media, costs everybody else nothing.
    ///
    /// Param:
    /// opened - peer_media.Opened (from the peer that sent it)
    /// out - []u8 (destination, needs the plain packet plus the outgoing tag)
    ///
    /// Return:
    /// - ?[]const u8 (a datagram borrowing `out`, or null when this peer cannot take it)
    pub fn sealMedia(self: *Connection, opened: peer_media.Opened, out: []u8) ?[]const u8 {
        const held = if (self.media) |*media| media else return null;

        if (out.len < opened.plain.len) return null;

        @memcpy(out[0..opened.plain.len], opened.plain);

        return held.sealFor(opened.header, out, opened.plain.len) catch null;
    }

    /// The stream a receiver asked a keyframe for, named as its source sends it.
    ///
    /// Note:
    /// - Taking it clears the request, so one ask produces one request forwarded.
    ///
    /// Return:
    /// - ?u32
    pub fn takeKeyframeRequest(self: *Connection) ?u32 {
        const asked = self.keyframe_for orelse return null;

        self.keyframe_for = null;

        return asked;
    }

    /// Build a keyframe request for this peer, about one of the streams it is sending.
    ///
    /// Param:
    /// source_ssrc - u32 (the stream to ask about, as this peer sends it)
    /// out - []u8 (destination, needs the request plus the outgoing index and tag)
    ///
    /// Return:
    /// - ?[]const u8 (a datagram borrowing `out`, or null when this peer carries no media)
    pub fn sealKeyframeRequest(self: *Connection, source_ssrc: u32, out: []u8) ?[]const u8 {
        const held = if (self.media) |*media| media else return null;

        const written = feedback.writePictureLoss(out, FORWARDER_SSRC, source_ssrc) catch return null;

        return held.sealControl(out, written.len) catch null;
    }

    /// Answer one datagram that demux routed to STUN.
    fn onStun(self: *Connection, datagram: []const u8, now_ms: u64) void {
        const outcome = self.ice.respond(datagram, &self.address, &self.ice_reply);

        self.ice_reply_len = if (outcome.reply) |reply| reply.len else 0;

        // A check that verified is the peer proving it is still there, which is the whole of
        // consent for a lite agent (RFC 7675 5.1).
        if (outcome.authenticated) self.deadlines.armIn(.ICE_CONSENT, now_ms, self.options.consent_timeout_ms);
    }

    /// Take one datagram that demux routed to DTLS, and everything it unwraps into.
    fn onDtls(self: *Connection, datagram: []const u8, now_ms: u64, outcome: *Outcome) Error!void {
        const result = try self.dtls.handle(datagram, now_ms);

        if (result.failed) {
            self.dead = true;

            return;
        }

        if (result.established) {
            try self.startAssociation();
            self.startMedia();

            outcome.established = true;
        }

        if (self.channels == null) return;

        while (self.dtls.nextAppData()) |packet| {
            const sctp_outcome = self.channels.?.handle(packet, now_ms, self.scratch) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                // Anything else is one malformed packet, and the association survives it.
                else => continue,
            };

            if (sctp_outcome.reply) |reply| try self.queueAppData(reply);
            if (sctp_outcome.delivered) outcome.delivered = true;
            if (sctp_outcome.aborted or sctp_outcome.closed) self.dead = true;
        }
    }

    /// Build the association and the channels over it, which the finished handshake now allows.
    fn startAssociation(self: *Connection) Error!void {
        const sctp = try self.allocator.create(association.Association);
        errdefer self.allocator.destroy(sctp);

        sctp.* = try association.Association.init(self.allocator, .{
            .outbound_streams = self.options.outbound_streams,
            .inbound_streams = self.options.inbound_streams,
            .path_max_bytes = self.options.path_max_bytes -| DTLS_OVERHEAD,
        }, self.secrets.sctp_cookie, .{
            .tag = self.secrets.sctp_tag,
            .initial_tsn = self.secrets.sctp_initial_tsn,
        });

        self.sctp = sctp;
        self.channels = datachannel.Peer.init(self.allocator, sctp, .{
            // zix answers the handshake, so it is always the DTLS server, and that is what decides
            // which identifiers it may open channels on (RFC 8832 6).
            .role = .DTLS_SERVER,
            .limits = .{ .max_channels = self.options.max_channels },
        });
    }

    /// Open this peer's SRTP streams, which the finished handshake has now keyed.
    ///
    /// Note:
    /// - Nothing to do when the peer offered no use_srtp or this endpoint answered none, and that
    ///   is not a failure: the connection carries data channels either way.
    fn startMedia(self: *Connection) void {
        const negotiated = self.dtls.srtp_profile orelse return;
        const keys = self.dtls.srtp_keys orelse return;

        self.media = peer_media.PeerMedia.init(negotiated, keys) catch null;
    }

    /// Take one datagram that demux routed to media: open it, or answer what it asked for.
    ///
    /// Note:
    /// - Nothing is forwarded here. The connection opens what its own peer sent and stops, because
    ///   who else wants it is the engine's business and this file holds one peer.
    /// - A packet that will not open is dropped in silence. Media arrives before the answer's
    ///   first keyframe request is out and after a peer has gone, and neither is worth a log line
    ///   at thirty of them a second.
    fn onMedia(self: *Connection, datagram: []const u8, outcome: *Outcome) void {
        const held = if (self.media) |*media| media else return;

        if (datagram.len > self.media_buf.len) return;

        const kind = mux.classify(datagram) orelse return;

        @memcpy(self.media_buf[0..datagram.len], datagram);

        switch (kind) {
            .RTP => {
                const opened = held.open(self.media_buf, datagram.len) catch return;

                self.media_header = opened.header;
                self.media_len = opened.plain.len;
                self.media_ready = true;

                outcome.media = true;
            },
            .RTCP => self.onControl(held, datagram.len, outcome),
        }
    }

    /// Read one control packet from this peer.
    ///
    /// Note:
    /// - A forwarder answers the control path rather than relaying it, because a report names
    ///   streams by the numbers they had before the rewrite. What is acted on here is the one
    ///   message that has to cross peers: a receiver asking the sender for a fresh keyframe.
    fn onControl(self: *Connection, media: *peer_media.PeerMedia, packet_len: usize, outcome: *Outcome) void {
        const compound = media.openControl(self.media_buf, packet_len) catch return;
        var walk = rtcp.begin(compound) catch return;

        while (walk.next()) |packet| {
            if (packet.packet_type != .PSFB) continue;
            if ((feedback.payloadFormat(packet) catch continue) != .PLI) continue;

            const asked = feedback.read(packet) catch continue;

            // The receiver names the identifier it was given, and the peer that has to answer is
            // whichever source is behind it.
            self.keyframe_for = media.routes.sourceOf(asked.media_ssrc) orelse asked.media_ssrc;
            outcome.keyframe_requested = true;
        }
    }

    /// Bring the deadline set in line with what the layers below are actually waiting on.
    fn syncDeadlines(self: *Connection, now_ms: u64) void {
        if (self.dtls.deadline()) |at_ms| {
            self.deadlines.arm(.DTLS_RETRANSMIT, at_ms);
        } else {
            self.deadlines.disarm(.DTLS_RETRANSMIT);
        }

        const sctp = self.sctp orelse return;
        const outstanding = sctp.send.count();

        // An acknowledgement that took chunks off the list restarts the timer rather than letting
        // the old deadline run out on data that already got through (RFC 9260 6.3.2 R3).
        if (outstanding < self.outstanding) self.deadlines.disarm(.SCTP_RETRANSMIT);
        self.outstanding = outstanding;

        if (outstanding == 0) {
            self.deadlines.disarm(.SCTP_RETRANSMIT);

            return;
        }

        if (!self.deadlines.isArmed(.SCTP_RETRANSMIT)) {
            self.deadlines.armIn(.SCTP_RETRANSMIT, now_ms, sctp.timer.timeout_ms);
        }
    }

    /// Wrap one SCTP packet and hold it until the outbound pump asks for it.
    fn queueAppData(self: *Connection, packet: []const u8) Error!void {
        if (self.queue_count >= MAX_QUEUED) return;

        const wrapped = try self.dtls.writeAppData(packet, self.queue[self.queue_used..]);

        self.queue_len[self.queue_count] = wrapped.len;
        self.queue_count += 1;
        self.queue_used += wrapped.len;
    }

    /// The next queued packet, or null when the batch is spent.
    fn takeQueued(self: *Connection) ?[]const u8 {
        if (self.queue_taken >= self.queue_count) return null;

        const len = self.queue_len[self.queue_taken];
        const packet = self.queue[self.queue_offset..][0..len];

        self.queue_taken += 1;
        self.queue_offset += len;

        return packet;
    }

    /// Start a fresh batch, because a new datagram is being handled.
    fn resetQueue(self: *Connection) void {
        self.queue_count = 0;
        self.queue_used = 0;
        self.queue_taken = 0;
        self.queue_offset = 0;
    }
};

/// Copy bytes the caller has to own into the caller's buffer.
fn copyOut(bytes: []const u8, out: []u8) error{ZixNoSpace}![]const u8 {
    if (out.len < bytes.len) return error.ZixNoSpace;

    @memcpy(out[0..bytes.len], bytes);

    return out[0..bytes.len];
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const ice_check = @import("ice/check.zig");
const stun_message = @import("stun/message.zig");

const TEST_ADDRESS: IpAddress = .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 41000 } };
const TEST_DER = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };
const LOCAL_UFRAG = "zixL";
const LOCAL_PASSWORD = "zixlocalpasswordaaaaaa";
const PEER_UFRAG = "peer";
const PEER_PASSWORD = "peerpasswordbbbbbbbbbb";

fn testSigningKey() !EcdsaP256.KeyPair {
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");

    return EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(secret));
}

fn testOptions() !Options {
    return .{
        .ice_ufrag = LOCAL_UFRAG,
        .ice_password = LOCAL_PASSWORD,
        .peer_ice_ufrag = PEER_UFRAG,
        .certificate_der = &TEST_DER,
        .signing_key = try testSigningKey(),
    };
}

fn testSecrets() Secrets {
    return .{
        .dtls_cookie = @splat(0x5A),
        .sctp_cookie = @splat(0x6B),
        .server_random = @splat(0x33),
        .server_eph_secret = @splat(0x44),
        .sctp_tag = 0x11223344,
        .sctp_initial_tsn = 1000,
    };
}

/// One ICE connectivity check, the shape a controlling full agent sends.
fn testCheck(out: []u8, use_candidate: bool) ![]const u8 {
    var username_buf: [ice_credentials.MAX_USERNAME_LEN]u8 = undefined;
    const username = try ice_credentials.writeUsername(&username_buf, LOCAL_UFRAG, PEER_UFRAG);

    return try ice_check.writeRequest(out, .{
        .transaction_id = @splat(0x77),
        .username = username,
        .password = LOCAL_PASSWORD,
        .priority = 100,
        .role = .CONTROLLING,
        .tiebreaker = 42,
        .use_candidate = use_candidate,
    });
}

test "zix webrtc: connection, a fresh peer has nothing negotiated and only an idle deadline" {
    var conn = try Connection.init(std.testing.allocator, TEST_ADDRESS, try testOptions(), testSecrets(), 1000);
    defer conn.deinit();

    try std.testing.expect(!conn.isDead());
    try std.testing.expect(!conn.isEstablished());
    try std.testing.expectEqual(@as(?u64, 1000 + 30000), conn.deadline());
    try std.testing.expect(conn.context(1000) == null);

    var out: [1500]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), try conn.nextOutbound(1000, &out));
    try std.testing.expectEqual(@as(?core.Event, null), try conn.nextEvent(1000));
}

test "zix webrtc: connection, an authenticated check is answered and refreshes consent" {
    var conn = try Connection.init(std.testing.allocator, TEST_ADDRESS, try testOptions(), testSecrets(), 0);
    defer conn.deinit();

    var check_buf: [256]u8 = undefined;
    const check = try testCheck(&check_buf, true);

    _ = try conn.handle(check, 5000);

    var out: [1500]u8 = undefined;
    const reply = (try conn.nextOutbound(5000, &out)).?;

    const parsed = try stun_message.parse(reply);
    try std.testing.expectEqual(stun_message.Class.SUCCESS_RESPONSE, parsed.class);
    try std.testing.expectEqual(stun_message.Method.BINDING, parsed.method);

    try std.testing.expectEqual(@as(?u64, 5000 + 30000), conn.deadlines.deadline(.ICE_CONSENT));
    try std.testing.expect(conn.ice.selected != null);

    // One response per check, and nothing else waiting behind it.
    try std.testing.expectEqual(@as(?[]const u8, null), try conn.nextOutbound(5000, &out));
}

test "zix webrtc: connection, a check with the wrong password is refused without consent" {
    var conn = try Connection.init(std.testing.allocator, TEST_ADDRESS, try testOptions(), testSecrets(), 0);
    defer conn.deinit();

    var username_buf: [ice_credentials.MAX_USERNAME_LEN]u8 = undefined;
    const username = try ice_credentials.writeUsername(&username_buf, LOCAL_UFRAG, PEER_UFRAG);

    var check_buf: [256]u8 = undefined;
    const check = try ice_check.writeRequest(&check_buf, .{
        .transaction_id = @splat(0x77),
        .username = username,
        .password = PEER_PASSWORD,
        .priority = 100,
        .role = .CONTROLLING,
        .tiebreaker = 42,
    });

    _ = try conn.handle(check, 5000);

    var out: [1500]u8 = undefined;
    const reply = (try conn.nextOutbound(5000, &out)).?;

    const parsed = try stun_message.parse(reply);
    try std.testing.expectEqual(stun_message.Class.ERROR_RESPONSE, parsed.class);
    try std.testing.expect(!conn.deadlines.isArmed(.ICE_CONSENT));
}

test "zix webrtc: connection, a first client hello brings a cookie back" {
    var conn = try Connection.init(std.testing.allocator, TEST_ADDRESS, try testOptions(), testSecrets(), 0);
    defer conn.deinit();

    var hello_buf: [768]u8 = undefined;
    const hello = try testClientHello(&hello_buf, "", 0);

    const outcome = try conn.handle(hello, 1000);
    try std.testing.expect(!outcome.established);
    try std.testing.expect(!outcome.dead);

    var out: [1500]u8 = undefined;
    try std.testing.expect((try conn.nextOutbound(1000, &out)) != null);

    // The cookie exchange keeps no state, so only the idle deadline is running.
    try std.testing.expect(!conn.deadlines.isArmed(.DTLS_RETRANSMIT));
}

test "zix webrtc: connection, an idle peer is dropped once its deadline passes" {
    var conn = try Connection.init(std.testing.allocator, TEST_ADDRESS, try testOptions(), testSecrets(), 0);
    defer conn.deinit();

    try std.testing.expect(!conn.tick(29_999).dead);
    try std.testing.expect(conn.tick(30_000).dead);
    try std.testing.expect(conn.isDead());

    // A dead connection answers nothing further.
    const outcome = try conn.handle(&[_]u8{ 0, 1, 0, 0 }, 30_001);
    try std.testing.expect(outcome.dead);
}

test "zix webrtc: connection, silence after a nominated check lapses consent" {
    var conn = try Connection.init(std.testing.allocator, TEST_ADDRESS, try testOptions(), testSecrets(), 0);
    defer conn.deinit();

    var check_buf: [256]u8 = undefined;
    _ = try conn.handle(try testCheck(&check_buf, true), 1000);

    try std.testing.expect(!conn.tick(30_999).dead);
    try std.testing.expect(conn.tick(31_000).dead);
}

test "zix webrtc: connection, media is dropped by a peer that negotiated none" {
    var conn = try Connection.init(std.testing.allocator, TEST_ADDRESS, try testOptions(), testSecrets(), 0);
    defer conn.deinit();

    const rtp_packet = [_]u8{ 0x80, 0x60, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0 };
    const outcome = try conn.handle(&rtp_packet, 1000);

    try std.testing.expect(!outcome.dead);
    try std.testing.expect(!outcome.delivered);
    try std.testing.expect(!outcome.media);
    try std.testing.expect(!conn.carriesMedia());
    try std.testing.expect(conn.openedMedia() == null);

    var out: [1500]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), try conn.nextOutbound(1000, &out));
}

test "zix webrtc: connection, a datagram outside every known range is dropped" {
    var conn = try Connection.init(std.testing.allocator, TEST_ADDRESS, try testOptions(), testSecrets(), 0);
    defer conn.deinit();

    const outcome = try conn.handle(&[_]u8{ 200, 200, 200 }, 1000);

    try std.testing.expect(!outcome.dead);
    try std.testing.expect(!outcome.established);
}

const dtls_handshake = @import("../../tls/dtls_handshake.zig");
const dtls_hello = @import("../../tls/dtls_hello.zig");
const dtls_record = @import("../../tls/dtls_record.zig");
const dtls_connection = @import("../../tls/dtls_connection.zig");
const srtcp = @import("media/srtcp.zig");
const stream_set = @import("media/stream_set.zig");

const TEST_PROFILE: dtls_exporter.SrtpProfile = .SRTP_AES128_CM_HMAC_SHA1_80;

const TEST_KEYS: dtls_exporter.SrtpKeys = .{
    .client_write_key = @splat(0x11),
    .server_write_key = @splat(0x22),
    .client_write_salt = @splat(0x33),
    .server_write_salt = @splat(0x44),
};

const OTHER_KEYS: dtls_exporter.SrtpKeys = .{
    .client_write_key = @splat(0x55),
    .server_write_key = @splat(0x66),
    .client_write_salt = @splat(0x77),
    .server_write_salt = @splat(0x88),
};

/// The browser half of one peer's media, which writes with the client key and reads with the
/// server key. The mirror of what a Connection holds.
const TestBrowser = struct {
    sending: stream_set.StreamSet,
    receiving: stream_set.StreamSet,
    control_sending: srtcp.Session,
    control_receiving: srtcp.Session,

    fn init(keys: dtls_exporter.SrtpKeys) !TestBrowser {
        return .{
            .sending = try stream_set.StreamSet.init(TEST_PROFILE, keys.client_write_key, keys.client_write_salt),
            .receiving = try stream_set.StreamSet.init(TEST_PROFILE, keys.server_write_key, keys.server_write_salt),
            .control_sending = try srtcp.Session.init(TEST_PROFILE, keys.client_write_key, keys.client_write_salt),
            .control_receiving = try srtcp.Session.init(TEST_PROFILE, keys.server_write_key, keys.server_write_salt),
        };
    }

    fn send(self: *TestBrowser, buffer: []u8, ssrc: u32, sequence: u16, payload: []const u8) ![]const u8 {
        const written = try rtp.write(buffer, .{
            .payload_type = 96,
            .sequence = sequence,
            .timestamp = 90 * @as(u32, sequence),
            .ssrc = ssrc,
        }, payload);

        return (try self.sending.sessionFor(ssrc)).protect(buffer, written.len);
    }

    fn receive(self: *TestBrowser, buffer: []u8, packet_len: usize) !rtp.Packet {
        const ssrc = (try rtp.read(buffer[0..packet_len])).header.ssrc;

        return rtp.read(try (try self.receiving.sessionFor(ssrc)).unprotect(buffer[0..packet_len]));
    }

    fn askForKeyframe(self: *TestBrowser, buffer: []u8, media_ssrc: u32) ![]const u8 {
        const written = try feedback.writePictureLoss(buffer, 0x9999_9999, media_ssrc);

        return self.control_sending.protect(buffer, written.len);
    }

    fn receiveControl(self: *TestBrowser, buffer: []u8, packet_len: usize) ![]const u8 {
        return self.control_receiving.unprotect(buffer[0..packet_len]);
    }
};

/// Options for a server that answers media, which is what allocates the media buffer.
fn testMediaOptions() !Options {
    var options = try testOptions();
    options.srtp_profiles = &.{TEST_PROFILE};

    return options;
}

/// One connection already keyed, standing in for a finished handshake. What the handshake itself
/// does with use_srtp is tested where it happens, in dtls_connection.zig and dtls_session.zig.
fn keyedConnection(keys: dtls_exporter.SrtpKeys) !Connection {
    var conn = try Connection.init(std.testing.allocator, TEST_ADDRESS, try testMediaOptions(), testSecrets(), 0);
    errdefer conn.deinit();

    conn.media = try peer_media.PeerMedia.init(TEST_PROFILE, keys);

    return conn;
}

test "zix webrtc: connection, a media packet from a keyed peer is opened and offered on" {
    var conn = try keyedConnection(TEST_KEYS);
    defer conn.deinit();

    var browser = try TestBrowser.init(TEST_KEYS);

    var buffer: [256]u8 = undefined;
    const protected = try browser.send(&buffer, 0x1111_1111, 100, "camera bytes");

    const outcome = try conn.handle(protected, 1000);

    try std.testing.expect(outcome.media);
    try std.testing.expect(conn.carriesMedia());

    const opened = conn.openedMedia().?;

    try std.testing.expectEqual(@as(u32, 0x1111_1111), opened.header.ssrc);
    try std.testing.expectEqual(@as(u16, 100), opened.header.sequence);
    try std.testing.expectEqualStrings("camera bytes", (try rtp.read(opened.plain)).payload);
    try std.testing.expect(conn.sendsStream(0x1111_1111));
    try std.testing.expect(!conn.sendsStream(0x2222_2222));

    // Media never goes out through the connection's own queue. It is not wrapped in DTLS, and who
    // else wants it is the engine's business.
    var out: [1500]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), try conn.nextOutbound(1000, &out));
}

test "zix webrtc: connection, a forged media packet leaves nothing for the engine to forward" {
    var conn = try keyedConnection(TEST_KEYS);
    defer conn.deinit();

    var stranger = try TestBrowser.init(OTHER_KEYS);

    var buffer: [256]u8 = undefined;
    const protected = try stranger.send(&buffer, 0x1111_1111, 1, "not from here");

    const outcome = try conn.handle(protected, 1000);

    try std.testing.expect(!outcome.media);
    try std.testing.expect(!outcome.dead);
    try std.testing.expect(conn.openedMedia() == null);
}

test "zix webrtc: connection, one peer's packet is sealed for another under its own key" {
    var sender = try keyedConnection(TEST_KEYS);
    defer sender.deinit();

    var receiver = try keyedConnection(OTHER_KEYS);
    defer receiver.deinit();

    var sending_browser = try TestBrowser.init(TEST_KEYS);
    var receiving_browser = try TestBrowser.init(OTHER_KEYS);

    var buffer: [256]u8 = undefined;
    const protected = try sending_browser.send(&buffer, 0x1111_1111, 100, "across the room");

    _ = try sender.handle(protected, 1000);

    var out: [1500]u8 = undefined;
    const sealed = receiver.sealMedia(sender.openedMedia().?, &out).?;
    const sealed_len = sealed.len;

    const arrived = try receiving_browser.receive(&out, sealed_len);

    try std.testing.expectEqual(@as(u32, 0x1111_1111), arrived.header.ssrc);
    try std.testing.expectEqual(@as(u16, 100), arrived.header.sequence);
    try std.testing.expectEqualStrings("across the room", arrived.payload);
}

test "zix webrtc: connection, a peer that negotiated no media takes nothing sealed for it" {
    var sender = try keyedConnection(TEST_KEYS);
    defer sender.deinit();

    var plain = try Connection.init(std.testing.allocator, TEST_ADDRESS, try testOptions(), testSecrets(), 0);
    defer plain.deinit();

    var browser = try TestBrowser.init(TEST_KEYS);

    var buffer: [256]u8 = undefined;
    _ = try sender.handle(try browser.send(&buffer, 0x1111_1111, 1, "nowhere to go"), 1000);

    var out: [1500]u8 = undefined;
    try std.testing.expect(plain.sealMedia(sender.openedMedia().?, &out) == null);
}

test "zix webrtc: connection, a keyframe request names the source behind what the receiver sees" {
    var receiver = try keyedConnection(TEST_KEYS);
    defer receiver.deinit();

    var browser = try TestBrowser.init(TEST_KEYS);

    // The receiver has to be carrying the stream before it can ask about it, which is what puts
    // the route in the table.
    var media = try peer_media.PeerMedia.init(TEST_PROFILE, TEST_KEYS);
    _ = try media.routes.admit(0x1111_1111);
    receiver.media = media;

    var buffer: [256]u8 = undefined;
    const asked = try browser.askForKeyframe(&buffer, 0x1111_1111);
    const outcome = try receiver.handle(asked, 1000);

    try std.testing.expect(outcome.keyframe_requested);
    try std.testing.expectEqual(@as(?u32, 0x1111_1111), receiver.takeKeyframeRequest());

    // Taking it clears it, so one ask produces one request forwarded.
    try std.testing.expectEqual(@as(?u32, null), receiver.takeKeyframeRequest());
}

test "zix webrtc: connection, a keyframe request is built for the peer that has to answer it" {
    var sender = try keyedConnection(TEST_KEYS);
    defer sender.deinit();

    var browser = try TestBrowser.init(TEST_KEYS);

    var out: [1500]u8 = undefined;
    const request = sender.sealKeyframeRequest(0x1111_1111, &out).?;
    const request_len = request.len;

    const compound = try browser.receiveControl(&out, request_len);
    var walk = try rtcp.begin(compound);
    const packet = walk.next().?;

    try std.testing.expectEqual(rtcp.PacketType.PSFB, packet.packet_type);
    try std.testing.expectEqual(feedback.PayloadFormat.PLI, try feedback.payloadFormat(packet));

    const read_back = try feedback.read(packet);

    try std.testing.expectEqual(@as(u32, 0x1111_1111), read_back.media_ssrc);
    try std.testing.expectEqual(FORWARDER_SSRC, read_back.sender_ssrc);
}

test "zix webrtc: connection, a media packet larger than the buffer is dropped" {
    var conn = try keyedConnection(TEST_KEYS);
    defer conn.deinit();

    var oversized: [2048]u8 = undefined;
    @memset(&oversized, 0);
    oversized[0] = 0x80;
    oversized[1] = 96;

    const outcome = try conn.handle(&oversized, 1000);

    try std.testing.expect(!outcome.media);
    try std.testing.expect(!outcome.dead);
}

/// One plaintext ClientHello record, with or without a cookie.
fn testClientHello(out: []u8, cookie: []const u8, record_seq: u48) ![]const u8 {
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
