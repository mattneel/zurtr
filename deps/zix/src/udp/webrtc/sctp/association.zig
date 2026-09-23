//! zix SCTP association (RFC 9260 4, 5, 9, over DTLS per RFC 8261).
//!
//! What:
//! - The state machine that ties the rest of this directory together: the four-way handshake,
//!   the data flow with its acknowledgements and retransmissions, and the graceful close.
//! - One object per association, driven entirely by the caller: packets in, packets out, and a
//!   clock the caller owns. Nothing here touches a socket or a timer.
//!
//! Note:
//! - The responder keeps NO state until a COOKIE ECHO comes back. Everything the INIT carried
//!   goes into the signed cookie, which is what makes a flood of INITs cost one hash each
//!   (RFC 9260 5.1.3).
//! - The verification tag is checked on every packet except the ones that cannot carry it yet.
//!   Getting this wrong is the difference between an association and an open port: a packet
//!   with the wrong tag is not from this peer (RFC 9260 8.5).
//! - Acknowledgements go out at once rather than being delayed. Always correct, and one packet
//!   per data packet rather than one per two. Delayed acknowledgement is a policy the layer
//!   above can add, and it needs a timer this file deliberately does not have.
//! - Stream sequence numbers are assigned here, one counter per outbound stream. TSNs are
//!   assigned by the send queue, which is the only thing that knows what is still outstanding.
//! - Fragmentation is by path maximum. A message larger than one packet becomes a run of chunks
//!   with the same stream sequence number, and RFC 9260 forbids interleaving another message
//!   into that run.

const std = @import("std");

const checksum = @import("checksum.zig");
const chunk = @import("chunk.zig");
const congestion = @import("congestion.zig");
const cookie = @import("cookie.zig");
const data = @import("data.zig");
const error_cause = @import("error_cause.zig");
const forward_tsn = @import("forward_tsn.zig");
const heartbeat = @import("heartbeat.zig");
const initiation = @import("init.zig");
const packet = @import("packet.zig");
const reassembly = @import("reassembly.zig");
const receive_queue = @import("receive_queue.zig");
const rto = @import("rto.zig");
const sack = @import("sack.zig");
const send_queue = @import("send_queue.zig");
const serial = @import("serial.zig");
const teardown = @import("teardown.zig");

/// The default SCTP port for a WebRTC data channel (RFC 8831 6.2).
pub const DATA_CHANNEL_PORT: u16 = 5000;

/// Largest reply this file ever builds, which is an INIT ACK carrying a cookie.
pub const MAX_REPLY_BYTES: usize = 256;

/// How many streams one FORWARD TSN names. A data channel abandons one stream at a time, so the
/// ceiling only exists to keep the list on the stack.
pub const MAX_FORWARD_STREAMS: usize = 16;

/// Setup for one association.
pub const Config = struct {
    local_port: u16 = DATA_CHANNEL_PORT,
    remote_port: u16 = DATA_CHANNEL_PORT,
    /// How many outbound streams to ask for.
    outbound_streams: u16 = 128,
    /// How many inbound streams to accept.
    inbound_streams: u16 = 128,
    /// Receive buffer this endpoint dedicates to the association.
    advertised_rwnd: u32 = 128 * 1024,
    /// Largest SCTP packet that fits the path, DTLS overhead already taken off.
    path_max_bytes: usize = 1200,
    rto: rto.Config = .{},
    reassembly_limits: reassembly.Limits = .{},
    send_limits: send_queue.Limits = .{},
};

/// The random numbers an association needs at birth.
///
/// Note:
/// - Taken from the caller rather than drawn here, so a test can pin them and a server can draw
///   them from one source it controls.
pub const Identity = struct {
    /// This endpoint's initiate tag, which the peer echoes in every packet. Never zero.
    tag: u32,
    /// The first TSN this endpoint will use.
    initial_tsn: u32,
};

/// Where the association is (RFC 9260 4).
pub const State = enum {
    CLOSED,
    /// An INIT went out and its answer has not come back.
    COOKIE_WAIT,
    /// A COOKIE ECHO went out and its answer has not come back.
    COOKIE_ECHOED,
    ESTABLISHED,
    /// A SHUTDOWN went out.
    SHUTDOWN_SENT,
    /// A SHUTDOWN arrived, and this endpoint is draining what it still has to send.
    SHUTDOWN_RECEIVED,
    /// A SHUTDOWN ACK went out.
    SHUTDOWN_ACK_SENT,
};

/// What handling one packet did.
pub const Outcome = struct {
    /// A packet to send back, borrowing the caller's output buffer.
    reply: ?[]const u8 = null,
    /// The handshake completed on this packet.
    established: bool = false,
    /// The peer aborted, or this endpoint did. The association is dead either way.
    aborted: bool = false,
    /// The graceful close finished.
    closed: bool = false,
    /// Messages may be waiting, see `nextMessage`.
    delivered: bool = false,
    /// A RE-CONFIG chunk arrived, and this is its value, borrowed from the datagram handed in.
    /// Stream reset is driven by the layer that owns the channels, so it is passed up untouched.
    reconfig: ?[]const u8 = null,
};

/// Everything that can go wrong driving an association.
pub const Error = error{
    OutOfMemory,
    /// The output buffer is too small for the reply that had to go out.
    ZixNoSpace,
    /// The peer did something the protocol does not allow.
    ZixProtocolViolation,
    /// A message grew past the reassembly limit.
    ZixMessageTooLarge,
    /// A DATA chunk must carry at least one byte.
    ZixNoUserData,
    /// Sending is not possible in the current state.
    ZixNotEstablished,
};

/// One SCTP association over one DTLS connection.
///
/// Usage:
/// ```zig
/// var peer = try Association.init(allocator, .{}, secret, identity);
/// defer peer.deinit();
///
/// var out: [1200]u8 = undefined;
/// const outcome = try peer.handle(datagram, now_ms, &out);
/// if (outcome.reply) |reply| try dtls.write(reply);
///
/// while (try peer.nextMessage()) |message| handle(message);
/// ```
pub const Association = struct {
    allocator: std.mem.Allocator,
    config: Config,
    state: State,
    signer: cookie.Signer,
    /// This endpoint's tag, which every packet from the peer must carry.
    local: Identity,
    /// The peer's tag, which every packet this endpoint sends carries.
    peer_tag: u32,
    /// Streams actually usable, being the lesser of what each side asked for.
    outbound_streams: u16,
    inbound_streams: u16,
    /// The peer's last advertised receive window.
    peer_rwnd: u32,
    /// The first TSN the peer said it would use. Kept because the RFC 6525 request sequence
    /// numbering starts there, and only the handshake ever sees it.
    peer_initial_tsn: u32,
    peer_forward_tsn: bool,
    peer_reconfig: bool,
    send: send_queue.SendQueue,
    receive: receive_queue.ReceiveQueue,
    reassembler: reassembly.Reassembler,
    window: congestion.Window,
    timer: rto.Estimator,
    /// Next stream sequence number per outbound stream.
    next_sequence: []u16,

    /// Build one association. Which side it plays is decided by whether `connect` is called.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (must reclaim, the queues free as they drain)
    /// config - Config
    /// secret - [cookie.SECRET_LEN]u8 (for signing state cookies)
    /// local - Identity
    ///
    /// Return:
    /// - Association in CLOSED, waiting
    /// - error.OutOfMemory
    pub fn init(
        allocator: std.mem.Allocator,
        config: Config,
        secret: [cookie.SECRET_LEN]u8,
        local: Identity,
    ) Error!Association {
        const sequences = try allocator.alloc(u16, config.outbound_streams);
        @memset(sequences, 0);

        return .{
            .allocator = allocator,
            .config = config,
            .state = .CLOSED,
            .signer = cookie.Signer.init(secret),
            .local = local,
            .peer_tag = 0,
            .outbound_streams = config.outbound_streams,
            .inbound_streams = config.inbound_streams,
            .peer_rwnd = initiation.MIN_ADVERTISED_RWND,
            .peer_initial_tsn = 0,
            .peer_forward_tsn = false,
            .peer_reconfig = false,
            .send = send_queue.SendQueue.init(allocator, config.send_limits, local.initial_tsn),
            .receive = receive_queue.ReceiveQueue.init(0),
            .reassembler = reassembly.Reassembler.init(allocator, config.reassembly_limits, 0),
            .window = congestion.Window.init(.{ .path_max_bytes = config.path_max_bytes }),
            .timer = rto.Estimator.init(config.rto),
            .next_sequence = sequences,
        };
    }

    /// Free everything the association holds.
    ///
    /// Return:
    /// - void
    pub fn deinit(self: *Association) void {
        self.send.deinit();
        self.reassembler.deinit();
        self.allocator.free(self.next_sequence);
    }

    /// Build and send the INIT that opens an association.
    ///
    /// Param:
    /// out - []u8 (at least MAX_REPLY_BYTES)
    ///
    /// Return:
    /// - []const u8, the packet to send
    /// - error.ZixNoSpace
    pub fn connect(self: *Association, out: []u8) Error![]const u8 {
        var body: [MAX_REPLY_BYTES]u8 = undefined;
        var builder = initiation.Builder.begin(&body, self.localFixed()) catch return error.ZixNoSpace;

        builder.addForwardTsnSupported() catch return error.ZixNoSpace;
        builder.addSupportedExtensions(&.{ .RE_CONFIG, .FORWARD_TSN }) catch return error.ZixNoSpace;

        // A packet carrying an INIT has a zero verification tag: the peer's tag is not known yet.
        const reply = try self.buildPacket(out, 0, .INIT, 0, builder.chunkValue());
        self.state = .COOKIE_WAIT;

        return reply;
    }

    /// Handle one SCTP packet.
    ///
    /// Note:
    /// - The reply borrows `out`, so copy it before the next call.
    ///
    /// Param:
    /// datagram - []const u8 (payload of one DTLS record)
    /// now_ms - u64 (monotonic milliseconds)
    /// out - []u8 (at least MAX_REPLY_BYTES for the handshake, the path maximum for data)
    ///
    /// Return:
    /// - Outcome
    /// - error.ZixProtocolViolation, error.ZixMessageTooLarge, error.ZixNoSpace, error.OutOfMemory
    pub fn handle(self: *Association, datagram: []const u8, now_ms: u64, out: []u8) Error!Outcome {
        const incoming = packet.parse(datagram) catch return .{};

        if (!self.tagAccepted(incoming)) return .{};

        var outcome: Outcome = .{};
        var iterator = incoming.chunks();

        while (iterator.next()) |item| {
            switch (item.kind) {
                .INIT => return self.onInit(item, now_ms, out),
                .INIT_ACK => return self.onInitAck(item, now_ms, out),
                .COOKIE_ECHO => return self.onCookieEcho(item, now_ms, out),
                .COOKIE_ACK => {
                    if (self.state == .COOKIE_ECHOED) {
                        self.state = .ESTABLISHED;
                        outcome.established = true;
                    }
                },
                .DATA => try self.onData(item, &outcome),
                .SACK => self.onSack(item, now_ms),
                .FORWARD_TSN => self.onForwardTsn(item, &outcome),
                .HEARTBEAT => return self.onHeartbeat(item, out),
                .HEARTBEAT_ACK => {},
                // Handed up rather than handled here, because what a stream reset means is a
                // data channel question (RFC 8831 6.7). Only the first one in a packet is taken,
                // and RFC 6525 3.1 never bundles two.
                .RE_CONFIG => {
                    if (outcome.reconfig == null) outcome.reconfig = item.value;
                },
                // Known, and nothing is done with them here. Congestion notification is not
                // implemented, padding exists only to make a probe the right size, and an ERROR
                // is not fatal on its own.
                .ECNE, .CWR, .PAD, .ERROR => {},
                .SHUTDOWN => return self.onShutdown(item, out),
                .SHUTDOWN_ACK => return self.onShutdownAck(out),
                .SHUTDOWN_COMPLETE => {
                    self.state = .CLOSED;
                    outcome.closed = true;
                },
                .ABORT => {
                    self.state = .CLOSED;
                    outcome.aborted = true;

                    return outcome;
                },
                else => {
                    // An unknown type says in its own number what to do with it, and both skip
                    // actions are handled by simply reading the next chunk.
                    switch (chunk.unknownAction(item.kind)) {
                        .STOP, .STOP_AND_REPORT => return outcome,
                        .SKIP, .SKIP_AND_REPORT => continue,
                    }
                },
            }
        }

        if (incoming.find(.DATA) != null) {
            outcome.reply = try self.buildSack(out);
        }

        return outcome;
    }

    /// The next message the peer has completed.
    ///
    /// Note:
    /// - Call in a loop until it returns null. The payload is valid until the next call.
    ///
    /// Return:
    /// - ?reassembly.Message
    /// - error.ZixProtocolViolation, error.ZixMessageTooLarge, error.OutOfMemory
    pub fn nextMessage(self: *Association) Error!?reassembly.Message {
        return self.reassembler.next();
    }

    /// Queue a message for sending, fragmenting it if it does not fit one packet.
    ///
    /// Param:
    /// stream_identifier - u16
    /// payload - []const u8 (copied, so the caller's buffer may be reused)
    /// options - SendOptions
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - void
    /// - error.ZixNotEstablished if the association is not up
    /// - error.ZixNoUserData if the payload is empty
    /// - error.ZixProtocolViolation if the stream is outside what was negotiated
    /// - error.ZixNoSpace, error.OutOfMemory
    pub fn sendMessage(
        self: *Association,
        stream_identifier: u16,
        payload: []const u8,
        options: SendOptions,
        now_ms: u64,
    ) Error!void {
        if (self.state != .ESTABLISHED) return error.ZixNotEstablished;
        if (payload.len == 0) return error.ZixNoUserData;
        if (stream_identifier >= self.outbound_streams) return error.ZixProtocolViolation;

        const sequence = self.next_sequence[stream_identifier];
        const piece = self.maxPayloadBytes();

        var at: usize = 0;
        while (at < payload.len) {
            const end = @min(at + piece, payload.len);

            _ = self.send.append(.{
                .stream_identifier = stream_identifier,
                .stream_sequence = sequence,
                .payload_protocol = options.payload_protocol,
                .unordered = options.unordered,
                .beginning = at == 0,
                .ending = end == payload.len,
                .payload = payload[at..end],
                .reliability = options.reliability,
            }, now_ms) catch |err| switch (err) {
                error.ZixNoSpace => return error.ZixNoSpace,
                error.OutOfMemory => return error.OutOfMemory,
                error.ZixNoUserData => return error.ZixNoUserData,
            };

            at = end;
        }

        if (!options.unordered) {
            self.next_sequence[stream_identifier] = serial.StreamSequence.next(sequence);
        }
    }

    /// Build the next outbound packet from the send queue.
    ///
    /// Note:
    /// - Bundles as many chunks as the congestion window, the peer's window, and the path
    ///   maximum allow. Returns null when there is nothing to send or no room to send it.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    /// out - []u8 (the path maximum)
    ///
    /// Return:
    /// - ?[]const u8, a packet to send
    /// - error.ZixNoSpace if the buffer cannot hold a common header
    pub fn flush(self: *Association, now_ms: u64, out: []u8) Error!?[]const u8 {
        var writer = packet.Writer.init(
            out[0..@min(out.len, self.config.path_max_bytes)],
            self.config.local_port,
            self.config.remote_port,
            self.peer_tag,
        ) catch return error.ZixNoSpace;

        while (self.send.nextToSend()) |item| {
            const cost = item.wireBytes();

            if (self.window.available(self.send.in_flight_bytes, self.peer_rwnd) < cost) break;
            if (writer.remaining() < cost) break;

            const outgoing = item.asData();
            const tsn = item.tsn;

            const body = writer.reserveChunk(.DATA, outgoing.flags(), outgoing.valueLen()) catch break;
            _ = data.write(body, outgoing) catch break;

            self.send.markSent(tsn, now_ms);
        }

        if (writer.isEmpty()) return null;

        return writer.finish() catch return error.ZixNoSpace;
    }

    /// The retransmission timer expired.
    ///
    /// Param:
    /// now_ms - u64 (monotonic milliseconds)
    ///
    /// Return:
    /// - void
    pub fn onRetransmitTimeout(self: *Association, now_ms: u64) void {
        self.send.onTimeout(now_ms);
        self.window.onTimeout();
        self.timer.backOff();
    }

    /// Start a graceful close.
    ///
    /// Param:
    /// out - []u8 (at least MAX_REPLY_BYTES)
    ///
    /// Return:
    /// - []const u8, the SHUTDOWN packet to send
    /// - error.ZixNotEstablished if the association was never up
    /// - error.ZixNoSpace
    pub fn shutdown(self: *Association, out: []u8) Error![]const u8 {
        if (self.state != .ESTABLISHED) return error.ZixNotEstablished;

        var body: [teardown.SHUTDOWN_VALUE_LEN]u8 = undefined;
        const value = teardown.writeShutdown(&body, self.receive.cumulative_tsn) catch return error.ZixNoSpace;

        const reply = try self.buildPacket(out, self.peer_tag, .SHUTDOWN, 0, value);
        self.state = .SHUTDOWN_SENT;

        return reply;
    }

    /// Tear the association down immediately.
    ///
    /// Param:
    /// out - []u8 (at least MAX_REPLY_BYTES)
    /// reason - []const u8 (goes out as a User-Initiated Abort cause, may be empty)
    ///
    /// Return:
    /// - []const u8, the ABORT packet to send
    /// - error.ZixNoSpace
    pub fn abort(self: *Association, out: []u8, reason: []const u8) Error![]const u8 {
        var body: [MAX_REPLY_BYTES]u8 = undefined;
        const causes = error_cause.writeUserInitiatedAbort(&body, reason) catch return error.ZixNoSpace;

        const reply = try self.buildPacket(out, self.peer_tag, .ABORT, teardown.teardownFlags(false), causes);
        self.state = .CLOSED;

        return reply;
    }

    /// Build a FORWARD TSN for chunks the sender has given up on.
    ///
    /// Note:
    /// - Returns null when nothing has been abandoned, or when the peer never announced partial
    ///   reliability, in which case sending one would be a protocol violation (RFC 3758 3.1).
    ///
    /// Param:
    /// out - []u8 (at least MAX_REPLY_BYTES)
    ///
    /// Return:
    /// - ?[]const u8, the packet to send
    /// - error.ZixNoSpace
    pub fn buildForwardTsn(self: *Association, out: []u8) Error!?[]const u8 {
        if (!self.peer_forward_tsn) return null;

        const point = self.send.forwardTsnPoint() orelse return null;

        var entries: [MAX_FORWARD_STREAMS]forward_tsn.StreamEntry = undefined;
        const listed = self.send.forwardTsnStreams(point, &entries);

        var body: [MAX_REPLY_BYTES]u8 = undefined;
        const value = forward_tsn.write(&body, point, listed) catch return error.ZixNoSpace;

        const reply = try self.buildPacket(out, self.peer_tag, .FORWARD_TSN, 0, value);
        self.send.markForwarded(point);

        return reply;
    }

    /// Send a RE-CONFIG chunk built by the layer that owns the channels.
    ///
    /// Note:
    /// - Both sides must have listed RE-CONFIG in SUPPORTED-EXTENSIONS, which only the handshake
    ///   saw, so the check lives here (RFC 6525 5.1.1).
    ///
    /// Param:
    /// value - []const u8 (the whole chunk value, one or two reconfiguration parameters)
    /// out - []u8 (at least MAX_REPLY_BYTES)
    ///
    /// Return:
    /// - []const u8, the packet to send
    /// - error.ZixNotEstablished if the association is not up
    /// - error.ZixProtocolViolation if the peer never announced the extension
    /// - error.ZixNoSpace
    pub fn sendReconfig(self: *Association, value: []const u8, out: []u8) Error![]const u8 {
        if (self.state != .ESTABLISHED) return error.ZixNotEstablished;
        if (!self.peer_reconfig) return error.ZixProtocolViolation;

        return self.buildPacket(out, self.peer_tag, .RE_CONFIG, 0, value);
    }

    /// Put one outgoing stream's sequence numbering back to zero (RFC 6525 5.2.2 E3).
    ///
    /// Note:
    /// - Only the numbering is touched. Anything already queued for the stream keeps the number
    ///   it was given, which is why a reset is asked for after the queue has drained.
    ///
    /// Param:
    /// stream_identifier - u16
    ///
    /// Return:
    /// - void
    pub fn resetOutboundStream(self: *Association, stream_identifier: u16) void {
        if (stream_identifier >= self.outbound_streams) return;

        self.next_sequence[stream_identifier] = 0;
    }

    /// The last TSN handed to a DATA chunk, which a reset request has to carry.
    ///
    /// Return:
    /// - u32
    pub fn lastAssignedTsn(self: Association) u32 {
        return serial.Tsn.previous(self.send.next_tsn);
    }

    /// The highest TSN with nothing missing below it.
    ///
    /// Return:
    /// - u32
    pub fn cumulativeTsn(self: Association) u32 {
        return self.receive.cumulative_tsn;
    }

    /// The first TSN the peer announced.
    ///
    /// Return:
    /// - u32, zero before the handshake completes
    pub fn peerInitialTsn(self: Association) u32 {
        return self.peer_initial_tsn;
    }

    /// Whether the peer announced RFC 6525 support during the handshake.
    ///
    /// Return:
    /// - bool
    pub fn supportsReconfig(self: Association) bool {
        return self.peer_reconfig;
    }

    /// Largest user payload one DATA chunk can carry on this path.
    ///
    /// Return:
    /// - usize
    pub fn maxPayloadBytes(self: Association) usize {
        return self.config.path_max_bytes - packet.COMMON_HEADER_LEN - chunk.HEADER_LEN - data.FIXED_LEN;
    }

    /// An INIT arrived, so answer with an INIT ACK and keep no state.
    fn onInit(self: *Association, item: chunk.Chunk, now_ms: u64, out: []u8) Error!Outcome {
        const request = initiation.read(item.value) catch return .{};

        var body: [MAX_REPLY_BYTES]u8 = undefined;
        var builder = initiation.Builder.begin(&body, self.localFixed()) catch return error.ZixNoSpace;

        builder.addForwardTsnSupported() catch return error.ZixNoSpace;
        builder.addSupportedExtensions(&.{ .RE_CONFIG, .FORWARD_TSN }) catch return error.ZixNoSpace;

        var blob: [cookie.COOKIE_LEN]u8 = undefined;
        const signed = self.signer.sign(.{
            .local_port = self.config.local_port,
            .peer_port = self.config.remote_port,
            .peer = request.fixed,
            .local = self.localFixed(),
            .peer_forward_tsn = request.supportsForwardTsn(),
            .peer_reconfig = request.supportsReconfig(),
            .issued_ms = now_ms,
        }, &blob) catch return error.ZixNoSpace;

        builder.addStateCookie(signed) catch return error.ZixNoSpace;

        // The answer carries the peer's tag even though nothing is remembered about it.
        return .{ .reply = try self.buildPacket(out, request.fixed.initiate_tag, .INIT_ACK, 0, builder.chunkValue()) };
    }

    /// An INIT ACK arrived, so echo its cookie back.
    fn onInitAck(self: *Association, item: chunk.Chunk, now_ms: u64, out: []u8) Error!Outcome {
        _ = now_ms;

        if (self.state != .COOKIE_WAIT) return .{};

        const answer = initiation.read(item.value) catch return .{};
        const blob = answer.stateCookie() orelse return .{};

        self.adopt(answer);
        self.state = .COOKIE_ECHOED;

        return .{ .reply = try self.buildPacket(out, self.peer_tag, .COOKIE_ECHO, 0, blob) };
    }

    /// A COOKIE ECHO arrived, so verify it and build the association from what it carried.
    fn onCookieEcho(self: *Association, item: chunk.Chunk, now_ms: u64, out: []u8) Error!Outcome {
        switch (self.signer.verify(item.value, now_ms)) {
            .VALID => |contents| {
                if (contents.local_port != self.config.local_port) return .{};
                if (contents.peer_port != self.config.remote_port) return .{};

                self.adoptCookie(contents);
                self.state = .ESTABLISHED;

                return .{
                    .reply = try self.buildPacket(out, self.peer_tag, .COOKIE_ACK, 0, &.{}),
                    .established = true,
                };
            },
            .STALE => |staleness_ms| {
                var body: [16]u8 = undefined;

                // The cause measures in microseconds while every timer here is in milliseconds.
                const causes = error_cause.writeStaleCookie(&body, @intCast(@min(
                    staleness_ms *| 1_000,
                    std.math.maxInt(u32),
                ))) catch return error.ZixNoSpace;

                return .{ .reply = try self.buildPacket(out, self.peer_tag, .ERROR, 0, causes) };
            },
            .INVALID => return .{},
        }
    }

    /// A DATA chunk arrived.
    fn onData(self: *Association, item: chunk.Chunk, outcome: *Outcome) Error!void {
        const arriving = data.read(item.flags, item.value) catch return;

        if (arriving.stream_identifier >= self.inbound_streams) return;

        switch (self.receive.record(arriving.tsn)) {
            .RECORDED => {},
            .DUPLICATE, .DROPPED => return,
        }

        self.reassembler.accept(arriving) catch |err| switch (err) {
            // Refused for space, so the TSN must not stay acknowledged or the peer will never
            // send it again.
            error.ZixNoSpace => return,
            else => return err,
        };

        outcome.delivered = true;
    }

    /// A SACK arrived.
    fn onSack(self: *Association, item: chunk.Chunk, now_ms: u64) void {
        const report = sack.read(item.value) catch return;
        const result = self.send.onSack(report, now_ms);

        self.peer_rwnd = report.advertised_rwnd;

        if (result.rtt_sample_ms) |sample| self.timer.measure(sample);
        if (result.newly_acked_bytes > 0) self.window.onAck(result.newly_acked_bytes, result.flight_before);
        if (result.fast_retransmit) self.window.onLoss();
        if (result.all_acked) self.window.onFullyAcked();
    }

    /// A FORWARD TSN arrived, so skip past what the peer gave up on.
    fn onForwardTsn(self: *Association, item: chunk.Chunk, outcome: *Outcome) void {
        const skip = forward_tsn.read(item.value) catch return;

        self.receive.skipTo(skip.new_cumulative_tsn);
        _ = self.reassembler.skipTo(skip.new_cumulative_tsn);

        outcome.delivered = true;
    }

    /// A HEARTBEAT arrived, so send its blob straight back.
    fn onHeartbeat(self: *Association, item: chunk.Chunk, out: []u8) Error!Outcome {
        const info = heartbeat.readInfo(item.value) catch return .{};

        var body: [MAX_REPLY_BYTES]u8 = undefined;
        const value = heartbeat.writeInfo(&body, info) catch return error.ZixNoSpace;

        return .{ .reply = try self.buildPacket(out, self.peer_tag, .HEARTBEAT_ACK, 0, value) };
    }

    /// A SHUTDOWN arrived.
    fn onShutdown(self: *Association, item: chunk.Chunk, out: []u8) Error!Outcome {
        _ = teardown.readShutdown(item.value) catch return .{};

        self.state = .SHUTDOWN_ACK_SENT;

        return .{ .reply = try self.buildPacket(out, self.peer_tag, .SHUTDOWN_ACK, 0, &.{}) };
    }

    /// A SHUTDOWN ACK arrived, so close and say so.
    fn onShutdownAck(self: *Association, out: []u8) Error!Outcome {
        self.state = .CLOSED;

        return .{
            .reply = try self.buildPacket(out, self.peer_tag, .SHUTDOWN_COMPLETE, teardown.teardownFlags(false), &.{}),
            .closed = true,
        };
    }

    /// This endpoint's own fixed initiation fields.
    fn localFixed(self: Association) initiation.Fixed {
        return .{
            .initiate_tag = self.local.tag,
            .advertised_rwnd = self.config.advertised_rwnd,
            .outbound_streams = self.config.outbound_streams,
            .inbound_streams = self.config.inbound_streams,
            .initial_tsn = self.local.initial_tsn,
        };
    }

    /// Take on what the peer announced in an INIT ACK.
    fn adopt(self: *Association, answer: initiation.Initiation) void {
        self.peer_tag = answer.fixed.initiate_tag;
        self.peer_rwnd = answer.fixed.advertised_rwnd;
        self.peer_initial_tsn = answer.fixed.initial_tsn;
        self.peer_forward_tsn = answer.supportsForwardTsn();
        self.peer_reconfig = answer.supportsReconfig();

        // RFC 9260 5.1.1: each side ends up with the lesser of what it asked for and what the
        // other offered, in each direction.
        self.outbound_streams = @min(self.config.outbound_streams, answer.fixed.inbound_streams);
        self.inbound_streams = @min(self.config.inbound_streams, answer.fixed.outbound_streams);

        self.receive = receive_queue.ReceiveQueue.init(answer.fixed.initial_tsn);
        self.reassembler.deinit();
        self.reassembler = reassembly.Reassembler.init(
            self.allocator,
            self.config.reassembly_limits,
            answer.fixed.initial_tsn,
        );
    }

    /// Take on what the state cookie carried.
    fn adoptCookie(self: *Association, contents: cookie.Contents) void {
        self.peer_tag = contents.peer.initiate_tag;
        self.peer_rwnd = contents.peer.advertised_rwnd;
        self.peer_initial_tsn = contents.peer.initial_tsn;
        self.peer_forward_tsn = contents.peer_forward_tsn;
        self.peer_reconfig = contents.peer_reconfig;

        self.outbound_streams = @min(self.config.outbound_streams, contents.peer.inbound_streams);
        self.inbound_streams = @min(self.config.inbound_streams, contents.peer.outbound_streams);

        self.receive = receive_queue.ReceiveQueue.init(contents.peer.initial_tsn);
        self.reassembler.deinit();
        self.reassembler = reassembly.Reassembler.init(
            self.allocator,
            self.config.reassembly_limits,
            contents.peer.initial_tsn,
        );
    }

    /// Whether a packet carries a verification tag this association accepts (RFC 9260 8.5).
    fn tagAccepted(self: Association, incoming: packet.Packet) bool {
        const first = incoming.firstChunkType();

        // An INIT cannot carry a tag, because its sender does not have one yet.
        if (first == .INIT) return incoming.verification_tag == 0;

        // Before the handshake completes there is no tag to check against for the answers that
        // carry the peer's own, so those are accepted on their content instead.
        if (self.state == .COOKIE_WAIT and first == .INIT_ACK) return true;

        return incoming.verification_tag == self.local.tag;
    }

    /// Wrap one chunk in a packet.
    fn buildPacket(
        self: Association,
        out: []u8,
        verification_tag: u32,
        kind: chunk.Type,
        flags: u8,
        value: []const u8,
    ) Error![]const u8 {
        var writer = packet.Writer.init(out, self.config.local_port, self.config.remote_port, verification_tag) catch
            return error.ZixNoSpace;

        writer.addChunk(kind, flags, value) catch return error.ZixNoSpace;

        return writer.finish() catch return error.ZixNoSpace;
    }

    /// Build the acknowledgement for what has arrived.
    fn buildSack(self: *Association, out: []u8) Error![]const u8 {
        var body: [receive_queue.MAX_SACK_VALUE_LEN]u8 = undefined;
        const value = self.receive.writeSack(&body, self.config.advertised_rwnd) catch return error.ZixNoSpace;

        return self.buildPacket(out, self.peer_tag, .SACK, 0, value);
    }
};

/// How one message is sent.
pub const SendOptions = struct {
    /// Chosen by the application. SCTP passes it through untouched.
    payload_protocol: u32 = 0,
    /// Deliver without waiting for earlier messages on the same stream.
    unordered: bool = false,
    /// How hard to try before giving up, for a partially reliable channel.
    reliability: send_queue.Reliability = .{},
};

// --------------------------------------------------------------------------------------- //
// test cases

const responder_secret: [cookie.SECRET_LEN]u8 = @splat(0x11);

const client_identity: Identity = .{ .tag = 0x11112222, .initial_tsn = 1000 };
const server_identity: Identity = .{ .tag = 0x33334444, .initial_tsn = 5000 };

fn testPair(allocator: std.mem.Allocator) !struct { client: Association, server: Association } {
    return .{
        .client = try Association.init(allocator, .{}, responder_secret, client_identity),
        .server = try Association.init(allocator, .{}, responder_secret, server_identity),
    };
}

/// Run the four-way handshake between two associations and leave both established.
fn handshake(client: *Association, server: *Association, now_ms: u64) !void {
    var client_out: [MAX_REPLY_BYTES]u8 = undefined;
    var server_out: [MAX_REPLY_BYTES]u8 = undefined;

    const init_packet = try client.connect(&client_out);
    const init_ack = (try server.handle(init_packet, now_ms, &server_out)).reply.?;
    const cookie_echo = (try client.handle(init_ack, now_ms, &client_out)).reply.?;
    const cookie_ack = (try server.handle(cookie_echo, now_ms, &server_out)).reply.?;

    _ = try client.handle(cookie_ack, now_ms, &client_out);
}

test "zix sctp: association handshake, four packets bring both sides up" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    try std.testing.expectEqual(State.ESTABLISHED, pair.client.state);
    try std.testing.expectEqual(State.ESTABLISHED, pair.server.state);
}

test "zix sctp: association handshake, each side ends up holding the other's tag" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    try std.testing.expectEqual(server_identity.tag, pair.client.peer_tag);
    try std.testing.expectEqual(client_identity.tag, pair.server.peer_tag);
}

test "zix sctp: association handshake, the INIT packet carries a zero verification tag" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    var out: [MAX_REPLY_BYTES]u8 = undefined;
    const parsed = try packet.parse(try pair.client.connect(&out));

    try std.testing.expectEqual(@as(u32, 0), parsed.verification_tag);
    try std.testing.expectEqual(chunk.Type.INIT, parsed.firstChunkType());
    try std.testing.expectEqual(State.COOKIE_WAIT, pair.client.state);
}

test "zix sctp: association handshake, the responder keeps no state until the cookie comes back" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    var client_out: [MAX_REPLY_BYTES]u8 = undefined;
    var server_out: [MAX_REPLY_BYTES]u8 = undefined;

    const init_packet = try pair.client.connect(&client_out);
    _ = try pair.server.handle(init_packet, 1_000, &server_out);

    // A flood of INITs must cost the responder one signature each and nothing else.
    try std.testing.expectEqual(State.CLOSED, pair.server.state);
    try std.testing.expectEqual(@as(u32, 0), pair.server.peer_tag);
}

test "zix sctp: association handshake, both extension flags are announced and taken up" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    try std.testing.expect(pair.client.peer_forward_tsn);
    try std.testing.expect(pair.client.peer_reconfig);
    try std.testing.expect(pair.server.peer_forward_tsn);
    try std.testing.expect(pair.server.peer_reconfig);
}

test "zix sctp: association handshake, the stream counts settle on the lesser of the two" {
    const narrow: Config = .{ .outbound_streams = 4, .inbound_streams = 4 };
    const wide: Config = .{ .outbound_streams = 64, .inbound_streams = 64 };

    var client = try Association.init(std.testing.allocator, narrow, responder_secret, client_identity);
    defer client.deinit();

    var server = try Association.init(std.testing.allocator, wide, responder_secret, server_identity);
    defer server.deinit();

    try handshake(&client, &server, 1_000);

    try std.testing.expectEqual(@as(u16, 4), client.outbound_streams);
    try std.testing.expectEqual(@as(u16, 4), server.outbound_streams);
}

test "zix sctp: association handshake, a stale cookie is answered with an error not an ack" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    var client_out: [MAX_REPLY_BYTES]u8 = undefined;
    var server_out: [MAX_REPLY_BYTES]u8 = undefined;

    const init_packet = try pair.client.connect(&client_out);
    const init_ack = (try pair.server.handle(init_packet, 1_000, &server_out)).reply.?;
    const cookie_echo = (try pair.client.handle(init_ack, 1_000, &client_out)).reply.?;

    const late = 1_000 + cookie.DEFAULT_LIFETIME_MS + 1;
    const answer = try packet.parse((try pair.server.handle(cookie_echo, late, &server_out)).reply.?);

    try std.testing.expectEqual(chunk.Type.ERROR, answer.firstChunkType());
    try std.testing.expectEqual(State.CLOSED, pair.server.state);

    const cause = error_cause.find(answer.find(.ERROR).?.value, .STALE_COOKIE).?;
    try std.testing.expectEqual(@as(u32, 1_000), cause.staleness().?);
}

test "zix sctp: association handshake, a cookie signed by nobody is dropped in silence" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    var out: [MAX_REPLY_BYTES]u8 = undefined;
    var forged: [cookie.COOKIE_LEN]u8 = @splat(0);
    forged[0] = cookie.VERSION;

    var writer = try packet.Writer.init(&out, 5000, 5000, 0x33334444);
    try writer.addChunk(.COOKIE_ECHO, 0, &forged);
    const bytes = try writer.finish();

    var reply_buf: [MAX_REPLY_BYTES]u8 = undefined;
    const outcome = try pair.server.handle(bytes, 1_000, &reply_buf);

    try std.testing.expect(outcome.reply == null);
    try std.testing.expectEqual(State.CLOSED, pair.server.state);
}

test "zix sctp: association data, a message crosses and is acknowledged" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);
    try pair.client.sendMessage(0, "hello data channel", .{ .payload_protocol = 53 }, 1_000);

    var wire: [1200]u8 = undefined;
    const outbound = (try pair.client.flush(1_000, &wire)).?;

    var server_out: [1200]u8 = undefined;
    const outcome = try pair.server.handle(outbound, 1_010, &server_out);

    try std.testing.expect(outcome.delivered);

    const message = (try pair.server.nextMessage()).?;
    try std.testing.expectEqualStrings("hello data channel", message.payload);
    try std.testing.expectEqual(@as(u32, 53), message.payload_protocol);

    const report = try packet.parse(outcome.reply.?);
    try std.testing.expectEqual(chunk.Type.SACK, report.firstChunkType());
}

test "zix sctp: association data, an acknowledgement clears what was outstanding" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);
    try pair.client.sendMessage(0, "round trip", .{}, 1_000);

    var wire: [1200]u8 = undefined;
    const outbound = (try pair.client.flush(1_000, &wire)).?;

    var server_out: [1200]u8 = undefined;
    const report = (try pair.server.handle(outbound, 1_010, &server_out)).reply.?;

    try std.testing.expect(pair.client.send.in_flight_bytes > 0);

    var client_out: [1200]u8 = undefined;
    _ = try pair.client.handle(report, 1_020, &client_out);

    try std.testing.expectEqual(@as(usize, 0), pair.client.send.in_flight_bytes);
    try std.testing.expectEqual(@as(usize, 0), pair.client.send.count());
    try std.testing.expectEqual(@as(u64, 20), pair.client.timer.smoothed_ms);
}

test "zix sctp: association data, a message larger than the path is fragmented and rejoined" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    const long: [3000]u8 = @splat('z');
    try pair.client.sendMessage(0, &long, .{}, 1_000);

    try std.testing.expect(pair.client.send.count() > 1);

    var wire: [1200]u8 = undefined;
    var server_out: [1200]u8 = undefined;

    while (try pair.client.flush(1_000, &wire)) |outbound| {
        _ = try pair.server.handle(outbound, 1_010, &server_out);
    }

    const message = (try pair.server.nextMessage()).?;

    try std.testing.expectEqual(@as(usize, 3000), message.payload.len);
    try std.testing.expectEqualSlices(u8, &long, message.payload);
}

test "zix sctp: association data, ordered messages come out in the order they were sent" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    for ([_][]const u8{ "one", "two", "three" }) |body| {
        try pair.client.sendMessage(0, body, .{}, 1_000);
    }

    var wire: [1200]u8 = undefined;
    var server_out: [1200]u8 = undefined;

    while (try pair.client.flush(1_000, &wire)) |outbound| {
        _ = try pair.server.handle(outbound, 1_010, &server_out);
    }

    for ([_][]const u8{ "one", "two", "three" }) |expected| {
        try std.testing.expectEqualStrings(expected, (try pair.server.nextMessage()).?.payload);
    }
}

test "zix sctp: association data, each ordered message on a stream gets the next sequence" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);
    try pair.client.sendMessage(0, "first", .{}, 1_000);
    try pair.client.sendMessage(0, "second", .{}, 1_000);

    try std.testing.expectEqual(@as(u16, 0), pair.client.send.chunks.items[0].stream_sequence);
    try std.testing.expectEqual(@as(u16, 1), pair.client.send.chunks.items[1].stream_sequence);
}

test "zix sctp: association data, an unordered message does not consume a sequence" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);
    try pair.client.sendMessage(0, "loose", .{ .unordered = true }, 1_000);

    // The unordered message left the counter alone, so the ordered one still gets sequence 0.
    try std.testing.expectEqual(@as(u16, 0), pair.client.next_sequence[0]);

    try pair.client.sendMessage(0, "ordered", .{}, 1_000);

    try std.testing.expectEqual(@as(u16, 1), pair.client.next_sequence[0]);
    try std.testing.expectEqual(@as(u16, 0), pair.client.send.chunks.items[1].stream_sequence);
}

test "zix sctp: association data, sending before the handshake is refused" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try std.testing.expectError(error.ZixNotEstablished, pair.client.sendMessage(0, "early", .{}, 1_000));
}

test "zix sctp: association data, a stream outside what was negotiated is refused" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    try std.testing.expectError(
        error.ZixProtocolViolation,
        pair.client.sendMessage(pair.client.outbound_streams, "nowhere", .{}, 1_000),
    );
}

test "zix sctp: association data, an empty message is refused" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    try std.testing.expectError(error.ZixNoUserData, pair.client.sendMessage(0, "", .{}, 1_000));
}

test "zix sctp: association tags, a packet with the wrong verification tag is dropped" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);
    try pair.client.sendMessage(0, "hello", .{}, 1_000);

    var wire: [1200]u8 = undefined;
    const outbound = (try pair.client.flush(1_000, &wire)).?;

    // Rewrite the tag and restamp the checksum, so only the tag check can catch it.
    var forged: [1200]u8 = undefined;
    @memcpy(forged[0..outbound.len], outbound);
    std.mem.writeInt(u32, forged[4..8], 0xBADBAD00, .big);
    try checksum.insert(forged[0..outbound.len]);

    var server_out: [1200]u8 = undefined;
    const outcome = try pair.server.handle(forged[0..outbound.len], 1_010, &server_out);

    try std.testing.expect(!outcome.delivered);
    try std.testing.expect(outcome.reply == null);
}

test "zix sctp: association heartbeat, a probe comes back with its blob unchanged" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    var body: [heartbeat.PROBE_VALUE_LEN]u8 = undefined;
    const value = try heartbeat.writeProbe(&body, .{ .nonce = 0xABCD, .sent_ms = 1_000 });

    var wire: [MAX_REPLY_BYTES]u8 = undefined;
    var writer = try packet.Writer.init(&wire, 5000, 5000, server_identity.tag);
    try writer.addChunk(.HEARTBEAT, 0, value);

    var server_out: [MAX_REPLY_BYTES]u8 = undefined;
    const answer = try packet.parse((try pair.server.handle(try writer.finish(), 1_050, &server_out)).reply.?);

    try std.testing.expectEqual(chunk.Type.HEARTBEAT_ACK, answer.firstChunkType());

    const probe = heartbeat.readProbe(answer.find(.HEARTBEAT_ACK).?.value).?;
    try std.testing.expectEqual(@as(u64, 0xABCD), probe.nonce);
    try std.testing.expectEqual(@as(u64, 50), probe.roundTripMs(1_050));
}

test "zix sctp: association shutdown, the three-step close ends with both sides closed" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    var client_out: [MAX_REPLY_BYTES]u8 = undefined;
    var server_out: [MAX_REPLY_BYTES]u8 = undefined;

    const shutdown_packet = try pair.client.shutdown(&client_out);
    try std.testing.expectEqual(State.SHUTDOWN_SENT, pair.client.state);

    const shutdown_ack = (try pair.server.handle(shutdown_packet, 2_000, &server_out)).reply.?;
    try std.testing.expectEqual(State.SHUTDOWN_ACK_SENT, pair.server.state);

    const complete_outcome = try pair.client.handle(shutdown_ack, 2_010, &client_out);
    try std.testing.expect(complete_outcome.closed);
    try std.testing.expectEqual(State.CLOSED, pair.client.state);

    const final_outcome = try pair.server.handle(complete_outcome.reply.?, 2_020, &server_out);
    try std.testing.expect(final_outcome.closed);
    try std.testing.expectEqual(State.CLOSED, pair.server.state);
}

test "zix sctp: association shutdown, closing before the handshake is refused" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    var out: [MAX_REPLY_BYTES]u8 = undefined;

    try std.testing.expectError(error.ZixNotEstablished, pair.client.shutdown(&out));
}

test "zix sctp: association abort, the peer sees it and never answers it" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    var client_out: [MAX_REPLY_BYTES]u8 = undefined;
    const abort_packet = try pair.client.abort(&client_out, "going away");

    var server_out: [MAX_REPLY_BYTES]u8 = undefined;
    const outcome = try pair.server.handle(abort_packet, 2_000, &server_out);

    try std.testing.expect(outcome.aborted);
    try std.testing.expectEqual(State.CLOSED, pair.server.state);

    // RFC 9260 3.3.7: an abort is never answered with an abort.
    try std.testing.expect(outcome.reply == null);
}

test "zix sctp: association timeout, everything outstanding is queued again" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);
    try pair.client.sendMessage(0, "lost", .{}, 1_000);

    var wire: [1200]u8 = undefined;
    _ = try pair.client.flush(1_000, &wire);

    const before = pair.client.window.cwnd;
    pair.client.onRetransmitTimeout(3_000);

    try std.testing.expectEqual(@as(usize, 0), pair.client.send.in_flight_bytes);
    try std.testing.expect(pair.client.send.hasQueued());
    try std.testing.expect(pair.client.window.cwnd < before);
    try std.testing.expectEqual(@as(u64, 2_000), pair.client.timer.timeout_ms);
}

test "zix sctp: association flush, nothing to send gives no packet" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    var wire: [1200]u8 = undefined;
    try std.testing.expect(try pair.client.flush(1_000, &wire) == null);
}

test "zix sctp: association flush, chunks are bundled up to the path maximum" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    for (0..4) |_| try pair.client.sendMessage(0, "small", .{}, 1_000);

    var wire: [1200]u8 = undefined;
    const outbound = (try pair.client.flush(1_000, &wire)).?;
    const parsed = try packet.parse(outbound);

    var count: usize = 0;
    var iterator = parsed.chunks();
    while (iterator.next()) |_| count += 1;

    try std.testing.expectEqual(@as(usize, 4), count);
}

test "zix sctp: association sendReconfig, the packet carries the value as a RE-CONFIG chunk" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    var wire: [MAX_REPLY_BYTES]u8 = undefined;
    const outbound = try pair.client.sendReconfig(&.{ 0x00, 0x0D, 0x00, 0x04 }, &wire);
    const parsed = try packet.parse(outbound);
    const item = parsed.find(.RE_CONFIG) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x0D, 0x00, 0x04 }, item.value);
}

test "zix sctp: association sendReconfig, an association that is not up refuses" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    var wire: [MAX_REPLY_BYTES]u8 = undefined;

    try std.testing.expectError(error.ZixNotEstablished, pair.client.sendReconfig(&.{ 0, 0, 0, 4 }, &wire));
}

test "zix sctp: association sendReconfig, a peer that never announced the extension refuses" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    pair.client.peer_reconfig = false;

    var wire: [MAX_REPLY_BYTES]u8 = undefined;

    try std.testing.expectError(error.ZixProtocolViolation, pair.client.sendReconfig(&.{ 0, 0, 0, 4 }, &wire));
}

test "zix sctp: association handle, a RE-CONFIG chunk is handed up rather than answered" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    var wire: [MAX_REPLY_BYTES]u8 = undefined;
    const outbound = try pair.client.sendReconfig(&.{ 0x00, 0x0D, 0x00, 0x04 }, &wire);

    var reply: [MAX_REPLY_BYTES]u8 = undefined;
    const outcome = try pair.server.handle(outbound, 1_000, &reply);

    try std.testing.expect(outcome.reply == null);
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x0D, 0x00, 0x04 }, outcome.reconfig.?);
}

test "zix sctp: association handle, a packet with no RE-CONFIG hands nothing up" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    try pair.client.sendMessage(0, "hello", .{}, 1_000);

    var wire: [1200]u8 = undefined;
    const outbound = (try pair.client.flush(1_000, &wire)).?;

    var reply: [1200]u8 = undefined;
    const outcome = try pair.server.handle(outbound, 1_000, &reply);

    try std.testing.expect(outcome.reconfig == null);
}

test "zix sctp: association resetOutboundStream, the sequence numbering goes back to zero" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    try pair.client.sendMessage(3, "one", .{}, 1_000);
    try pair.client.sendMessage(3, "two", .{}, 1_000);

    try std.testing.expectEqual(@as(u16, 2), pair.client.next_sequence[3]);

    pair.client.resetOutboundStream(3);

    try std.testing.expectEqual(@as(u16, 0), pair.client.next_sequence[3]);
}

test "zix sctp: association resetOutboundStream, a stream outside the negotiated set is ignored" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    // Nothing to assert but that it returns, which is the point: a peer naming a stream that
    // does not exist must not reach past the table.
    pair.client.resetOutboundStream(pair.client.outbound_streams);
    pair.client.resetOutboundStream(65_535);
}

test "zix sctp: association lastAssignedTsn, it trails the next TSN by one" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    try std.testing.expectEqual(client_identity.initial_tsn - 1, pair.client.lastAssignedTsn());

    try pair.client.sendMessage(0, "one", .{}, 1_000);

    try std.testing.expectEqual(client_identity.initial_tsn, pair.client.lastAssignedTsn());
}

test "zix sctp: association cumulativeTsn, it follows what has arrived" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try handshake(&pair.client, &pair.server, 1_000);

    try std.testing.expectEqual(client_identity.initial_tsn - 1, pair.server.cumulativeTsn());

    try pair.client.sendMessage(0, "one", .{}, 1_000);

    var wire: [1200]u8 = undefined;
    const outbound = (try pair.client.flush(1_000, &wire)).?;

    var reply: [1200]u8 = undefined;
    _ = try pair.server.handle(outbound, 1_000, &reply);

    try std.testing.expectEqual(client_identity.initial_tsn, pair.server.cumulativeTsn());
}

test "zix sctp: association peerInitialTsn, each side ends up holding the other's first TSN" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try std.testing.expectEqual(@as(u32, 0), pair.client.peerInitialTsn());

    try handshake(&pair.client, &pair.server, 1_000);

    try std.testing.expectEqual(server_identity.initial_tsn, pair.client.peerInitialTsn());
    try std.testing.expectEqual(client_identity.initial_tsn, pair.server.peerInitialTsn());
}

test "zix sctp: association supportsReconfig, both sides announce the extension" {
    var pair = try testPair(std.testing.allocator);
    defer pair.client.deinit();
    defer pair.server.deinit();

    try std.testing.expect(!pair.client.supportsReconfig());

    try handshake(&pair.client, &pair.server, 1_000);

    try std.testing.expect(pair.client.supportsReconfig());
    try std.testing.expect(pair.server.supportsReconfig());
}
