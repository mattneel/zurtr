//! zix HTTP/3 per-connection state.
//!
//! What:
//! - The state one QUIC connection owns, tying the deterministic layers together: the Initial packet
//!   keys (crypto.zig), the Initial-level CRYPTO reassembly stream (tls.zig), the RTT estimator and
//!   congestion controller (recovery.zig), the anti-amplification budget and close state (close.zig),
//!   and the HTTP/3 control stream (h3.zig).
//!
//! Note:
//! - `init` derives the Initial secrets and per-direction AES-128-GCM keys from the client's
//!   Destination Connection ID (RFC 9001 5.2), the entry point a new Initial packet takes. Driving
//!   the TLS 1.3 handshake over the CRYPTO stream (through src/tls) is the live-handshake step that
//!   the server loop wires on top.

const std = @import("std");

const crypto = @import("crypto.zig");
const tls = @import("tls.zig");
const recovery = @import("recovery.zig");
const flow = @import("flow.zig");
const close = @import("close.zig");
const h3 = @import("h3.zig");
const demux = @import("demux.zig");
const keyschedule = @import("keyschedule.zig");
const transport_params = @import("transport_params.zig");
const response = @import("response.zig");
const wt = @import("webtransport/session.zig");
const wt_api = @import("webtransport/Webtransport.zig");
const stream_header = @import("webtransport/stream_header.zig");
const wt_pool = @import("webtransport/pool.zig");
const varint = @import("varint.zig");
const static = @import("static.zig");
const ks = @import("../../tls/key_schedule.zig");

/// The most concurrent large (multi-packet) response streams one connection tracks for resumption.
/// A large body only needs a slot while it is mid-send (spanning packets), and how many can be
/// genuinely in flight at once is bounded by the connection's send capacity (a congestion window of
/// packets), not by the protocol-level bidi stream credit (config.max_streams, which is how many
/// request streams the client may open, most of them small single-packet responses that never take a
/// slot). 64 comfortably covers the concurrent large-body burst while halving the per-connection
/// footprint from matching the full stream credit: this array is embedded in every eagerly-allocated
/// Connection (max_connections per worker, one worker per core), so each slot is paid many times over.
pub const max_send_streams = 64;

/// Decrypted 1-RTT payload copy buffer per connection: caps multiplexed request bytes per datagram.
const DEFAULT_APP_PAYLOAD_BUF: usize = 2048;

/// The decrypted 1-RTT payload buffer size, for callers that must not exceed it: a whole DATAGRAM frame
/// has to fit here for the receive path to read it, which is what caps the advertised frame size.
pub const app_payload_buf_len: usize = DEFAULT_APP_PAYLOAD_BUF;

/// Huffman-decoded :path scratch buffer per connection: caps the decoded path length.
const DEFAULT_PATH_SCRATCH: usize = 1024;

/// A response body being sent across multiple packets, resumed as the client extends flow control
/// (RFC 9000 4.1). The body is a zero-copy slice into handler-owned memory that MUST outlive the
/// stream (the static file cache satisfies this): the engine never copies it. The HTTP/3 prefix
/// (HEADERS + DATA header) is rebuilt on demand from status + body length, so it is not stored.
pub const SendStream = struct {
    active: bool = false,
    stream_id: u64 = 0,
    status: u16 = 200,
    body: []const u8 = "",
    /// The content coding of `body`, emitted in the rebuilt HEADERS prefix so a resumed large body
    /// keeps its `content-encoding` across every packet (the prefix is not stored, so this is).
    content_encoding: response.ContentEncoding = .identity,
    /// Total HTTP/3 stream length: the prefix length plus the body length.
    content_len: usize = 0,
    /// Stream offset already sent. A loss retransmission (Connection.onAckFrame) may rewind this
    /// backward to resend a lost range, so it is not the same as the connection flow control charge
    /// (see high_water below).
    sent: usize = 0,
    /// The highest stream offset ever reached, independent of `sent` rewinding for a retransmission.
    /// Connection-wide flow control (RFC 9000 4.1) charges for distinct stream offset, not for bytes
    /// handed to sendmsg, so a retransmission of an already-charged range must not charge it twice.
    high_water: usize = 0,
    /// The client's current per-stream flow control limit, raised by MAX_STREAM_DATA.
    stream_limit: u64 = 0,
    /// Bytes of this stream sent but not yet acknowledged (and not yet dropped from loss tracking). The
    /// pump raises it per chunk, onAckFrame lowers it when a range is acknowledged or declared lost, and
    /// recordSentRange lowers it when the shared sent-range ring overwrites one of this stream's still-
    /// live entries (that range leaves loss tracking, so it must leave this tally too, or it would leak
    /// and the slot would never free). The slot is retired only once the whole body is sent AND unacked
    /// reaches 0, so a tail packet lost after the last byte went out is still found and retransmitted.
    unacked: usize = 0,

    /// Static cache slot backing `body`, when this response came from public_dir. The pin keeps the
    /// file mapped while the pump reads it, so it is released only when the slot is retired. null
    /// for a handler-produced body, which owns its own lifetime.
    static_slot: ?u32 = null,

    /// Whether every byte of the stream content has been sent (the FIN went out).
    pub fn complete(self: *const SendStream) bool {
        return self.sent >= self.content_len;
    }
};

/// The retransmittable content of one sent 1-RTT packet, enough to know what to resend on loss
/// (RFC 9002 6.1). Only a SendStream byte range is tracked in this v1: a coalesced small-response
/// packet is not, so a lost small response has no recovery yet. Caller-supplied when queuing a packet
/// (Connection.recordSentRange).
pub const SentRangeInfo = struct {
    stream_id: u64,
    offset: usize,
    length: u32,
    /// Whether this range is a DATAGRAM frame rather than stream bytes: ack-eliciting and congestion
    /// controlled, but never retransmitted (RFC 9221 5.2), so the recovery paths leave it alone.
    datagram: bool = false,
};

/// One entry in the per-connection sent-packet log (Connection.sent_ranges): a SentRangeInfo tagged
/// with the packet number and send time it went out on, and whether it is still awaiting
/// acknowledgment.
const SentRange = struct {
    packet_number: u64 = 0,
    send_time_us: u64 = 0,
    stream_id: u64 = 0,
    offset: usize = 0,
    length: u32 = 0,
    /// Whether this range was a DATAGRAM frame: ack-eliciting, congestion controlled, never retransmitted
    /// (RFC 9221 5.2), so the recovery paths leave it alone.
    datagram: bool = false,
    in_flight: bool = false,
};

/// The most in-flight (sent, not yet acknowledged) packet ranges one connection tracks for loss
/// detection. A ring buffer: once full, the oldest entry is overwritten, which only means a
/// pathologically deep backlog loses loss-detection coverage for its oldest packets, not a
/// correctness bug (RFC 9002 loss detection is best-effort by nature). This array is embedded in every
/// Connection and every Connection is allocated eagerly (max_connections per worker, one worker per
/// core), so each entry costs max_connections * worker_count copies. This is the compile-time ceiling
/// on the in-flight window: the pump caps the effective congestion window at
/// Http3ServerConfig.max_inflight_packets, clamped to this, so an in-flight range is never overwritten
/// while still awaiting acknowledgment. Sized at 128: at max_datagram_size 1200 that is 153.6 KiB in
/// flight, so a large static response (up to ~150 KiB) streams in one congestion-window round instead
/// of several, which is what moves static-h3 throughput (the window, not per-request compute).
/// A deployment tunes the runtime window down with max_inflight_packets. Raising it past 128 needs this
/// bumped and a rebuild. Full-body delivery under concurrency is checked by the local h3 gate (rnd note).
pub const max_sent_ranges = 128;

/// Cap on the Probe Timeout backoff shift (RFC 9002 6.2.1). Each unanswered probe doubles the PTO period
/// (ptoWithBackoff), and this bounds the shift so it cannot overflow and so repeated probes to an
/// unresponsive peer space out instead of hammering. It is deliberately NOT an eviction threshold: loss
/// is not the same as a gone peer (a lossy but live connection keeps sending ACKs), so a slot is
/// reclaimed only by an explicit CONNECTION_CLOSE or the idle timeout, never by the backoff count. 6 caps
/// the period at 64x the base Probe Timeout.
pub const max_pto_backoff: u6 = 6;

/// Tracks which client 1-RTT packet numbers were received so the server ACKs honest ranges
/// (RFC 9000 19.3) instead of a contiguous 0..largest. Bit i of the mask set means (largest_pn - i) was
/// received, bit 0 is largest_pn. The window is 64 packets: older numbers slide out, already acked.
/// Honest gaps let the client retransmit a lost request packet instead of stalling on it.
pub const AckTracker = struct {
    largest_pn: u64 = 0,
    have_largest: bool = false,
    received_mask: u64 = 0,

    /// Record a received packet number, sliding the window when it is the new largest.
    pub fn record(self: *AckTracker, pn: u64) void {
        if (!self.have_largest) {
            self.have_largest = true;
            self.largest_pn = pn;
            self.received_mask = 1;
            return;
        }

        if (pn > self.largest_pn) {
            const shift = pn - self.largest_pn;
            self.received_mask = if (shift >= 64) 1 else (self.received_mask << @intCast(shift)) | 1;
            self.largest_pn = pn;
            return;
        }

        const delta = self.largest_pn - pn;
        if (delta < 64) self.received_mask |= @as(u64, 1) << @intCast(delta);
    }
};

/// What the time-driven maintenance sweep (Connection.onMaintenance) found for one connection, so the
/// worker loop knows whether to retransmit it and whether to free its table slot.
pub const Maintenance = struct {
    /// A Probe Timeout fired: one or more send streams were rewound, so the caller must pump the
    /// connection to retransmit the lost flight.
    resend: bool = false,
    /// The peer is gone: it sent CONNECTION_CLOSE, or it fell silent past the idle limit. The caller may
    /// remove the connection from the table. Loss (however many failed probes) never sets this.
    idle: bool = false,
};

/// How many client unidirectional streams this connection remembers the type of. A client opens a
/// handful per connection (a control stream, two QPACK streams, then one per WebTransport unidirectional
/// stream), and the table is only needed to classify a stream whose type varint straddled a frame.
pub const wt_uni_stream_types_cap: usize = 8;

/// Bytes of the client's control stream this connection keeps. Its first frame is SETTINGS, which is small
/// and is the only thing the engine reads off the control stream.
pub const wt_control_stream_bytes: usize = 256;

/// Which stream id space a server-initiated stream comes from (RFC 9000 2.1).
pub const ServerStreamKind = enum { bidi, uni };

/// How many WebTransport CONNECT streams this connection holds while it waits for the client's SETTINGS.
/// A client sends its SETTINGS and its CONNECT in the same flight, so one or two are enough; past this
/// many the excess is refused rather than held.
pub const wt_pending_connects_cap: usize = 4;

/// The WebTransport state one QUIC connection holds.
///
/// What:
/// - The client's SETTINGS reduced to what the binding reads, the client transport parameters that gate
///   datagrams and reliable resets, the sessions live on this connection, and the data streams those
///   sessions own.
/// - The stream table exists for acknowledgement and loss recovery: a sent range names a stream id, and
///   those paths run on the connection with no access to the worker pool, so the connection keeps its own
///   view of the streams whose bytes are in flight.
///
/// Note:
/// - Both tables are fixed arrays of pointers, paid once per eagerly allocated connection. The pool owns
///   the storage behind them, and an entry is cleared when its session or stream ends, so a released
///   slot is never reachable from here.
/// - A WebTransport CONNECT may arrive before the client's SETTINGS; `settings_received` is what the
///   serve path checks before it processes one (draft-ietf-webtrans-http3-16 7.1).
pub const WebTransportState = struct {
    /// The client's SETTINGS frame, decoded when its control stream arrives.
    client_settings: h3.ClientSettings = .{},
    /// Whether the client's SETTINGS have arrived.
    settings_received: bool = false,
    /// The client's max_datagram_frame_size: the largest DATAGRAM frame it accepts, 0 for none
    /// (RFC 9221 3).
    peer_datagram_frame_size: u64 = 0,
    /// Whether the client advertised reset_stream_at, so a reliable reset may be sent to it
    /// (draft-ietf-quic-reliable-stream-reset-09 3).
    peer_reset_stream_at: bool = false,
    /// The worker pool the sessions and streams on this connection came from, so a session can be given
    /// back from a path that has only the connection (the pump reaping a closed session). Null until the
    /// first session is attached, and never cleared: the pool outlives every connection on the worker.
    pool: ?*wt_pool.Pool = null,
    /// Live sessions, keyed by their CONNECT stream id (the pool owns the storage).
    sessions: [wt_api.connection_session_cap]?*wt.Session = @splat(null),
    /// Live data streams across every session of this connection (the pool owns the storage).
    streams: [wt_api.connection_stream_cap]?*wt.Stream = @splat(null),
    /// Datagrams that arrived for a session this connection does not have, and were dropped (4.6).
    dropped_datagrams: u64 = 0,
    /// The type of each client unidirectional stream this connection classified (RFC 9114 6.2).
    uni_types: [wt_uni_stream_types_cap]UniStreamType = @splat(.{}),
    /// The first bytes of a client unidirectional stream whose type varint is still arriving.
    uni_partial: [wt_uni_stream_types_cap]UniStreamPartial = @splat(.{}),
    /// The client's control stream bytes so far, and how many are in use.
    control: [wt_control_stream_bytes]u8 = undefined,
    control_len: usize = 0,
    /// WebTransport CONNECT streams waiting for the client's SETTINGS (see `wtIncomingConnect`): a server
    /// MUST NOT process a WebTransport request before them (draft-16 7.1), and refusing the request
    /// instead would cost the session when the SETTINGS packet is merely late.
    pending_connects: [wt_pending_connects_cap]u64 = @splat(0),
    pending_len: u8 = 0,

    /// The session with this id, or null.
    pub fn findSession(self: *const WebTransportState, session_id: u64) ?*wt.Session {
        for (self.sessions) |entry| {
            if (entry) |live| {
                if (live.id == session_id) return live;
            }
        }

        return null;
    }

    /// Track a session. False when the connection already holds as many as it can, which the caller
    /// answers by refusing the CONNECT rather than by running a session it cannot rely on.
    pub fn attachSession(self: *WebTransportState, live: *wt.Session) bool {
        for (&self.sessions) |*entry| {
            if (entry.* == null) {
                entry.* = live;

                return true;
            }
        }

        return false;
    }

    /// Stop tracking a session. Every stream of the session must already be detached.
    pub fn detachSession(self: *WebTransportState, live: *wt.Session) void {
        for (&self.sessions) |*entry| {
            if (entry.* == live) entry.* = null;
        }
    }

    /// The number of sessions this connection currently holds.
    pub fn sessionCount(self: *const WebTransportState) usize {
        var count: usize = 0;
        for (self.sessions) |entry| {
            if (entry != null) count += 1;
        }

        return count;
    }

    /// The data stream with this QUIC stream id, or null.
    pub fn findStream(self: *const WebTransportState, stream_id: u64) ?*wt.Stream {
        for (self.streams) |entry| {
            if (entry) |live| {
                if (live.id == stream_id) return live;
            }
        }

        return null;
    }

    /// Track a data stream. False when the connection holds as many as it can.
    pub fn attachStream(self: *WebTransportState, live: *wt.Stream) bool {
        for (&self.streams) |*entry| {
            if (entry.* == null) {
                entry.* = live;

                return true;
            }
        }

        return false;
    }

    /// Stop tracking a data stream.
    pub fn detachStream(self: *WebTransportState, live: *wt.Stream) void {
        for (&self.streams) |*entry| {
            if (entry.* == live) entry.* = null;
        }
    }

    /// The type of a client unidirectional stream, from the first bytes of the stream. The type is a
    /// variable-length integer at offset 0 and can straddle two STREAM frames, so up to eight bytes are
    /// remembered per stream until it resolves.
    ///
    /// Param:
    /// stream_id - u64 (the client's unidirectional stream id)
    /// offset - u64 (where these bytes sit in the stream: the type is only at offset 0)
    /// data - []const u8 (the stream bytes just received)
    ///
    /// Return:
    /// - ?u64 (the stream type, or null while it is still arriving)
    pub fn uniStreamType(self: *WebTransportState, stream_id: u64, offset: u64, data: []const u8) ?u64 {
        if (offset == 0) {
            const type_vi = varint.read(data) catch {
                self.holdPartial(stream_id, offset, data);

                return null;
            };

            self.recordUniType(stream_id, type_vi.value);

            return type_vi.value;
        }

        // A later frame: either the type is already known, or the held bytes plus these complete it.
        for (self.uni_types) |entry| {
            if (entry.stream_id == stream_id) return entry.stream_type;
        }

        for (&self.uni_partial) |*partial| {
            if (partial.stream_id != stream_id) continue;

            const room = partial.bytes.len - partial.len;
            const copy = @min(room, data.len);
            @memcpy(partial.bytes[partial.len..][0..copy], data[0..copy]);
            partial.len += copy;

            const type_vi = varint.read(partial.bytes[0..partial.len]) catch return null;
            partial.len = 0;
            self.recordUniType(stream_id, type_vi.value);

            return type_vi.value;
        }

        return null;
    }

    /// Remember the first bytes of a stream whose type varint has not arrived whole.
    fn holdPartial(self: *WebTransportState, stream_id: u64, offset: u64, data: []const u8) void {
        for (&self.uni_partial) |*partial| {
            if (partial.stream_id != stream_id) continue;

            const room = partial.bytes.len - partial.len;
            const copy = @min(room, data.len);
            @memcpy(partial.bytes[partial.len..][0..copy], data[0..copy]);
            partial.len += copy;

            return;
        }

        for (&self.uni_partial) |*partial| {
            if (partial.len != 0) continue;

            partial.* = .{ .stream_id = stream_id, .offset = offset };
            const copy = @min(partial.bytes.len, data.len);
            @memcpy(partial.bytes[0..copy], data[0..copy]);
            partial.len = copy;

            return;
        }
    }

    /// Store a resolved stream type, replacing the stream's held bytes.
    fn recordUniType(self: *WebTransportState, stream_id: u64, stream_type: u64) void {
        for (self.uni_partial, 0..) |partial, index| {
            if (partial.stream_id == stream_id) self.uni_partial[index] = .{};
        }

        for (&self.uni_types) |*entry| {
            if (entry.stream_id == stream_id) {
                entry.stream_type = stream_type;

                return;
            }
        }

        for (&self.uni_types) |*entry| {
            if (entry.stream_id != 0) continue;

            entry.* = .{ .stream_id = stream_id, .stream_type = stream_type };

            return;
        }
    }

    /// Note a CONNECT stream that has to wait for the client's SETTINGS. False when the table is full,
    /// which the caller answers by refusing the request.
    pub fn notePendingConnect(self: *WebTransportState, stream_id: u64) bool {
        for (self.pending_connects[0..self.pending_len]) |id| {
            if (id == stream_id) return true;
        }

        if (self.pending_len == self.pending_connects.len) return false;

        self.pending_connects[self.pending_len] = stream_id;
        self.pending_len += 1;

        return true;
    }

    /// Hand every waiting CONNECT stream id to `visit`, and clear the table. Called once the client's
    /// SETTINGS arrive, which is the moment they can be processed.
    pub fn takePendingConnects(self: *WebTransportState, comptime visit: anytype, context: anytype) void {
        for (self.pending_connects[0..self.pending_len]) |id| visit(context, id);

        self.pending_len = 0;
    }

    /// Accumulate the client's control stream and decode its SETTINGS frame once it is complete, which is
    /// what tells this endpoint whether the client supports WebTransport and how much it allows
    /// (RFC 9114 6.2.1, draft-ietf-webtrans-http3-16 5.5).
    ///
    /// Return:
    /// - ?h3.ClientSettings (the settings, on the call that completed the frame; null otherwise)
    pub fn feedControlStream(self: *WebTransportState, data: []const u8) ?h3.ClientSettings {
        if (self.settings_received) return null;

        const room = self.control.len - self.control_len;
        const copy = @min(room, data.len);
        @memcpy(self.control[self.control_len..][0..copy], data[0..copy]);
        self.control_len += copy;

        const type_vi = varint.read(self.control[0..self.control_len]) catch return null;

        // RFC 9114 6.2.1 requires SETTINGS first. Any other frame means this endpoint never learns what the
        // client supports, which the WebTransport checks then read as "not supported".
        if (type_vi.value != @intFromEnum(h3.FrameType.settings)) {
            self.settings_received = true;

            return null;
        }

        var pos = type_vi.len;
        const len_vi = varint.read(self.control[pos..self.control_len]) catch return null;
        pos += len_vi.len;

        const payload_len = std.math.cast(usize, len_vi.value) orelse return null;
        if (pos + payload_len > self.control_len) return null;

        self.client_settings = h3.parseClientSettings(self.control[pos..][0..payload_len]);
        self.settings_received = true;

        return self.client_settings;
    }
};

/// One client unidirectional stream's resolved type.
pub const UniStreamType = struct {
    stream_id: u64 = 0,
    stream_type: u64 = 0,
};

/// The first bytes of a client unidirectional stream whose type varint is still arriving.
pub const UniStreamPartial = struct {
    stream_id: u64 = 0,
    offset: u64 = 0,
    len: usize = 0,
    bytes: [8]u8 = @splat(0),
};

/// One QUIC / HTTP-3 connection's state, keyed in the demux table by its Destination Connection ID.
pub const Connection = struct {
    dcid: demux.ConnId,
    initial_client: crypto.AesKeys,
    initial_server: crypto.AesKeys,
    initial_keys: tls.InitialKeys = .{ .role = .server },
    zero_rtt: tls.ZeroRttPolicy = tls.default_zero_rtt,
    rtt: recovery.RttEstimator = .{},
    cc: recovery.CongestionController,
    anti_amplification: close.AntiAmplification = .{},
    close_state: close.CloseState = .open,
    control: h3.ControlStream = .{},
    crypto_initial: tls.CryptoStream = .{},

    // Server-initiated stream ids (RFC 9000 2.1: bidirectional 1 mod 4, unidirectional 3 mod 4). One
    // allocator per connection, shared by everything the server opens: the HTTP/3 control stream takes
    // the first unidirectional id, the QPACK encoder and decoder streams the next two if this engine
    // opens them, and every WebTransport data stream comes after that.
    //
    // Note:
    // - Sharing the counter is the invariant, not a convenience. A private counter per feature is how two
    //   owners hand out the same id: the WebTransport binding used to start its own unidirectional
    //   counter at 3, which is the control stream, so a session's first stream appended its bytes to the
    //   control stream and broke it for the peer.
    next_server_bidi: u64 = 1,
    next_server_uni: u64 = 3,

    /// The reason a client gave in a CONNECTION_CLOSE, copied out of the decrypted packet because the
    /// packet's buffer does not outlive the call that decrypted it.
    close_reason: [256]u8 = @splat(0),
    close_reason_len: usize = 0,

    /// The client's Handshake-level CRYPTO bytes: its Finished. Verifying it against the transcript
    /// through the server Finished is what completes the TLS handshake on the server side (RFC 8446
    /// 4.4.4), and completing it is what lets the server confirm the handshake to the client.
    crypto_handshake: tls.CryptoStream = .{},
    /// The transcript hash through the server Finished: the input the client's verify_data covers. Set
    /// where the application keys are derived, because the flight that appends the server Finished is
    /// what leaves the transcript in exactly that state.
    transcript_through_finished: crypto.Secret = @splat(0),
    /// Whether the client's Finished verified. False keeps the handshake unconfirmed, so a peer that
    /// cannot prove key possession never gets a session.
    client_finished_verified: bool = false,

    // Handshake step 2 (server send path) state.
    server_hello_sent: bool = false,
    our_scid: demux.ConnId = .{},
    handshake_shared: [32]u8 = undefined,
    // Handshake-level keys + transcript, ready once ServerHello has been sent.
    handshake_ready: bool = false,
    hs_keys: keyschedule.HandshakeKeys = undefined,
    handshake_transcript: ks.Transcript = undefined,
    // 1-RTT application keys + the client's Source Connection ID, ready once the flight is sent.
    app_ready: bool = false,
    app_keys: keyschedule.AppKeys = undefined,
    peer_scid: demux.ConnId = .{},
    // 1-RTT request / response state.
    app_pn: u32 = 0,
    // Received client 1-RTT packet numbers, for honest ACK ranges (RFC 9000 19.3).
    ack: AckTracker = .{},
    // Whether the first 1-RTT response has been sent. The server control stream (SETTINGS) and
    // HANDSHAKE_DONE ride that first response only, later per-stream responses omit them.
    first_response_sent: bool = false,
    // The most recent decrypted 1-RTT payload, copied off the recv buffer so the response builder can
    // walk every request stream it carries (a connection multiplexes many) without a second decrypt.
    app_payload_buf: [DEFAULT_APP_PAYLOAD_BUF]u8 = undefined,
    app_payload_len: usize = 0,
    // Reusable scratch for a Huffman-encoded :path (curl / h2load encode it), expanded per request.
    path_scratch: [DEFAULT_PATH_SCRATCH]u8 = undefined,
    // Client-advertised flow control limits (RFC 9000 4.1), parsed from the ClientHello transport
    // parameters. The server must not send response stream data past these. Zero until the handshake
    // parses them (a minimal client that sends no transport parameters grants no large-body credit).
    client_max_stream_data: u64 = 0,
    client_max_data: u64 = 0,
    // The client's per-stream send credit for the streams the server opens (RFC 9000 18.2 params 0x06 /
    // 0x07), which is what bounds a WebTransport data stream the application opens until the client
    // raises it with MAX_STREAM_DATA.
    client_max_stream_data_bidi_remote: u64 = 0,
    client_max_stream_data_uni: u64 = 0,
    // The largest UDP payload the client will accept (RFC 9000 transport parameter 0x03, max_udp_payload_size).
    // The send path never emits a datagram larger than this, so the client never has to drop one. Starts at
    // the QUIC minimum and is raised to the client's advertised value once the handshake parses it, so a
    // response before the parse still uses a safe size.
    client_max_udp_payload: u64 = transport_params.min_udp_payload_size,
    // Running total of stream bytes the server has sent on this connection, against client_max_data.
    conn_data_sent: u64 = 0,
    // Client request-stream (bidirectional) credit. The handshake advertises an initial allowance
    // (config.max_streams), which is a ONE-TIME budget until the server raises it with MAX_STREAMS
    // (RFC 9000 4.6). bidi_streams_granted is the cumulative limit advertised so far (0 until the first
    // request seeds it from the window), bidi_stream_high_water is the most request streams the client
    // has opened. replenishBidiStreams keeps the grant ahead of the high water so the connection never
    // stalls once the initial allowance is spent.
    bidi_streams_granted: u64 = 0,
    bidi_stream_high_water: u64 = 0,
    // Client connection-wide byte credit, the twin of the stream-count credit above. The handshake
    // advertises a ONE-TIME initial_max_data budget for the bytes the client sends across all its
    // streams. data_granted is the cumulative limit advertised so far (0 until the first packet seeds
    // it from the window), data_consumed is the running total of client stream bytes received.
    // replenishMaxData keeps the grant ahead of consumption so the connection never deadlocks once
    // the initial budget is spent (~1 MiB of requests, however much stream credit remains).
    data_granted: u64 = 0,
    data_consumed: u64 = 0,
    // Large responses still being sent across packets, resumed as the client extends flow control.
    send_streams: [max_send_streams]SendStream = @splat(.{}),
    // WebTransport: the client's settings and transport parameters, the sessions live on this
    // connection, and the data streams whose bytes are in flight (see WebTransportState).
    wt: WebTransportState = .{},
    // Loss detection and retransmission (RFC 9002). The power-of-two divisor the client used to
    // encode its ACK Delay fields, parsed from the ClientHello transport parameters (default 3,
    // RFC 9000 18.2, when the client advertises none).
    ack_delay_exponent: u6 = 3,
    // Every 1-RTT packet sent that carried a SendStream byte range, so a loss reported by a later ACK
    // can be resent (onAckFrame). See SentRange's own doc comment for the ring-buffer overwrite policy.
    sent_ranges: [max_sent_ranges]SentRange = @splat(.{}),
    sent_ranges_cursor: usize = 0,
    // Stream bytes sent but not yet acknowledged, the quantity the congestion controller bounds against
    // cc.congestion_window (RFC 9002 7). Raised per recorded sent range, lowered when a range is
    // acknowledged or declared lost in onAckFrame. The pump (pumpStream) refuses to push it past the
    // window, so the server self-clocks to ACKs instead of dumping a whole multi-packet body at once.
    bytes_in_flight: u64 = 0,
    // Monotonic time (recovery.nowUs()) of the most recent datagram received on this connection, stamped
    // by the response path. The time-driven maintenance sweep (onMaintenance) evicts a connection silent
    // past the idle limit, so a dead connection's table slot is reclaimed instead of held for the
    // worker's life (the wedge that collapsed EPOLL static-h3 across bench runs).
    last_activity_us: u64 = 0,
    // The peer's socket address as of the last datagram. A Probe-Timeout retransmit (onMaintenance) fires
    // with no incoming datagram to carry the address, so the send path reads it from here instead.
    peer_addr: std.posix.sockaddr.in6 = std.mem.zeroes(std.posix.sockaddr.in6),
    // Consecutive Probe Timeouts with no acknowledgment (RFC 9002 6.2.1): each one doubles the PTO period
    // (ptoWithBackoff) and, once it reaches max_pto_backoff, marks the peer gone so the sweep evicts the
    // connection. Reset to 0 whenever an ACK newly acknowledges data.
    pto_backoff: u6 = 0,

    /// Initialize a server-side connection from the client's Destination Connection ID
    /// (RFC 9001 5.2): derive the Initial secrets and the per-direction AES-128-GCM packet keys, and
    /// start the congestion controller at the initial window.
    ///
    /// Param:
    /// dcid - []const u8 (the client's Destination Connection ID from the first Initial packet)
    /// max_datagram_size - u64 (the path MTU estimate, for the initial congestion window)
    /// initial_window_packets - usize (the initial congestion window in packets, config.initial_window_packets)
    ///
    /// Return:
    /// - Connection
    pub fn init(dcid: []const u8, max_datagram_size: u64, initial_window_packets: usize) Connection {
        const secrets = crypto.initialSecrets(dcid);
        const initial_window = @as(u64, @intCast(initial_window_packets)) * max_datagram_size;

        return .{
            .dcid = demux.ConnId.fromSlice(dcid),
            .initial_client = crypto.AesKeys.fromSecret(secrets.client),
            .initial_server = crypto.AesKeys.fromSecret(secrets.server),
            .cc = recovery.CongestionController.init(max_datagram_size, initial_window),
        };
    }

    /// The wire size the send path may use for a 1-RTT datagram to this client: the smallest of the
    /// caller's request (`config_max`), the client's advertised max_udp_payload_size, and the ceiling.
    /// A response is fragmented into packets of this size, so a larger value means fewer packets, less
    /// per-packet work on both ends. Never exceeds what the client will accept (RFC 9000 18.2).
    ///
    /// Param:
    /// config_max - u64 (the server's configured datagram size, config.max_datagram_size)
    /// ceiling - u64 (the compile-time send ceiling, common.max_send_datagram_size)
    ///
    /// Return:
    /// - u64 (the wire datagram size to use, at least the QUIC minimum)
    pub fn sendDatagramSize(self: *const Connection, config_max: u64, ceiling: u64) u64 {
        return @max(transport_params.min_udp_payload_size, @min(config_max, @min(self.client_max_udp_payload, ceiling)));
    }

    /// Whether the server may still send `bytes` more before the client address is validated
    /// (RFC 9000 8.1): the 3x anti-amplification cap.
    pub fn maySend(self: *const Connection, bytes: u64) bool {
        return self.anti_amplification.maySend(bytes);
    }

    /// The in-flight large-response send stream for `stream_id`, or null when none is tracked.
    pub fn findSendStream(self: *Connection, stream_id: u64) ?*SendStream {
        for (&self.send_streams) |*stream| {
            if (stream.active and stream.stream_id == stream_id) return stream;
        }

        return null;
    }

    /// Reserve a send-stream slot for `stream_id`: the existing slot if one is tracked, otherwise a
    /// free slot. Returns null when every slot is busy with another in-flight stream.
    /// Hand back the static cache pin a retired send stream was holding, so the entry can expire.
    ///
    /// Note:
    /// - Idempotent by clearing the slot, since a stream can be retired down more than one path
    ///   (acknowledged, or abandoned when the connection goes away).
    /// - Releasing while the pump could still read `body` would let the mapping be torn down under
    ///   it, so this is only called where the stream is provably finished with.
    pub fn releaseStaticPin(self: *Connection, stream: *SendStream) void {
        _ = self;

        const slot = stream.static_slot orelse return;
        stream.static_slot = null;

        static.releasePin(slot);
    }

    /// Retire every send stream this connection still holds, releasing any static cache pins with
    /// them. Called when the connection is dropped, so a body abandoned mid-flight does not keep its
    /// cache entry pinned for the life of the process.
    pub fn releaseAllStaticPins(self: *Connection) void {
        for (&self.send_streams) |*stream| {
            if (stream.static_slot != null) self.releaseStaticPin(stream);
        }
    }

    pub fn reserveSendStream(self: *Connection, stream_id: u64) ?*SendStream {
        if (self.findSendStream(stream_id)) |stream| return stream;

        for (&self.send_streams) |*stream| {
            if (!stream.active) return stream;
        }

        return null;
    }

    /// Record that a just-sent 1-RTT packet carried `info`, for loss detection (RFC 9002 6.1). Called
    /// once per sent packet that carries a SendStream byte range, right after the packet number is
    /// assigned.
    ///
    /// Param:
    /// packet_number - u64 (the 1-RTT packet number this range went out on)
    /// send_time_us - u64 (recovery.nowUs() at send time)
    /// info - SentRangeInfo (the stream byte range the packet carried)
    ///
    /// Return:
    /// - void
    pub fn recordSentRange(self: *Connection, packet_number: u64, send_time_us: u64, info: SentRangeInfo) void {
        const slot = &self.sent_ranges[self.sent_ranges_cursor % max_sent_ranges];

        // Overwriting a slot still in flight drops that range from loss detection, so its bytes must
        // leave both the connection-wide in-flight tally AND the owning stream's unacked tally. Skipping
        // the per-stream decrement is exactly the bug that leaked unacked, kept a completed stream's slot
        // busy forever, and truncated static-h3 under concurrency. The pump caps in-flight near the ring
        // capacity, so overwriting a live slot is the uncommon path (small chunks running the count past
        // the byte-capped window), not the norm.
        if (slot.in_flight) {
            self.bytes_in_flight -|= slot.length;
            if (self.findSendStream(slot.stream_id)) |stream| stream.unacked -|= slot.length;
        }

        slot.* = .{
            .packet_number = packet_number,
            .send_time_us = send_time_us,
            .stream_id = info.stream_id,
            .offset = info.offset,
            .length = info.length,
            .datagram = info.datagram,
            .in_flight = true,
        };
        self.sent_ranges_cursor += 1;
        self.bytes_in_flight += info.length;
    }

    /// Apply a decoded ACK frame from the client (RFC 9000 19.3) to this connection's sent-packet
    /// bookkeeping: feed an RTT sample, retire every acknowledged range, and rewind any SendStream
    /// whose still-outstanding range is now provably lost (RFC 9002 6.1) so the next pumpStream call
    /// resends it. `now_us` is caller-supplied (recovery.nowUs() in production) so this stays a pure,
    /// deterministically testable function.
    ///
    /// Param:
    /// ack - flow.Ack (the parsed ACK frame)
    /// now_us - u64 (the current time in the same timebase as the send_time_us given to recordSentRange)
    ///
    /// Return:
    /// - void
    pub fn onAckFrame(self: *Connection, ack: flow.Ack, now_us: u64) void {
        // An RTT sample from the packet at the newly-reported largest acknowledged, if it is still
        // tracked and was still in flight. A duplicate or older ACK reporting the same largest gives
        // no packet to sample from, which is correct: it carries no new information (RFC 9002 5.1).
        for (&self.sent_ranges) |*entry| {
            if (entry.in_flight and entry.packet_number == ack.largest) {
                const latest_rtt = now_us -| entry.send_time_us;
                self.rtt.onSample(latest_rtt, ack.delay_us, recovery.default_max_ack_delay_us, self.app_ready);
                break;
            }
        }

        // Retire every acknowledged range, crediting its bytes to the congestion controller (RFC 9002
        // 7.3.1, window growth) and removing them from the connection and per-stream in-flight tallies so
        // the pump regains room and the stream can eventually retire.
        var acked_bytes: u64 = 0;
        for (&self.sent_ranges) |*entry| {
            if (!entry.in_flight) continue;

            for (ack.ranges[0..ack.range_len]) |range| {
                if (entry.packet_number >= range.smallest and entry.packet_number <= range.largest) {
                    entry.in_flight = false;
                    acked_bytes += entry.length;
                    self.bytes_in_flight -|= entry.length;

                    // The range belongs to an HTTP response stream (which only tallies what is
                    // unacknowledged), a WebTransport data stream (which frees the confirmed prefix of its
                    // send buffer, so the application can write again), or a DATAGRAM frame (which has no
                    // stream to tell: it was never kept for a retransmission).
                    if (entry.datagram) {
                        // Nothing to retire beyond the in-flight tally above.
                    } else if (self.findSendStream(entry.stream_id)) |stream| {
                        stream.unacked -|= entry.length;
                    } else if (self.wt.findStream(entry.stream_id)) |stream| {
                        stream.onAcked(entry.offset, entry.length);
                    }

                    break;
                }
            }
        }
        if (acked_bytes > 0) self.cc.onAckedBytes(acked_bytes);

        // An ACK newly acknowledged data, so the probe timer is cleared: reset the backoff (RFC 9002
        // 6.2.1) or a connection that recovered from one loss would keep an inflated PTO forever.
        if (acked_bytes > 0) self.pto_backoff = 0;

        // Declare loss for still-outstanding ranges before the largest acked (RFC 9002 6.1): rewind the
        // stream so the next pump resends, drop the bytes from the connection and per-stream in-flight
        // tallies (the resend re-adds them), and react to the congestion once per ACK (halve the window)
        // rather than once per lost packet.
        const smoothed = if (self.rtt.has_sample) self.rtt.smoothed_rtt else recovery.initial_rtt_us;
        var lost_any = false;
        for (&self.sent_ranges) |*entry| {
            if (!entry.in_flight) continue;

            const time_since_sent = now_us -| entry.send_time_us;
            if (!recovery.packetLost(entry.packet_number, ack.largest, time_since_sent, smoothed, smoothed)) continue;

            entry.in_flight = false;
            self.bytes_in_flight -|= entry.length;
            lost_any = true;
            if (entry.datagram) {
                // A lost datagram is gone (RFC 9221 5.2): no stream is rewound, so it is never resent.
            } else if (self.findSendStream(entry.stream_id)) |stream| {
                stream.unacked -|= entry.length;
                if (entry.offset < stream.sent) stream.sent = entry.offset;
            } else if (self.wt.findStream(entry.stream_id)) |stream| {
                stream.onLost(entry.offset);
            }
        }
        if (lost_any) self.cc.onCongestionEvent();

        // Retire a send stream only once it is fully sent AND fully acknowledged (unacked back to 0), not
        // the moment its last byte was handed to sendmsg. Holding the slot until the acks land keeps a
        // lost tail packet on a completed stream retransmittable by the loss rewind above (a freed slot
        // is not found), which is the recovery this whole change adds. unacked can never leak past 0
        // because recordSentRange charges the overwrite path too, so the pool always drains.
        for (&self.send_streams) |*stream| {
            if (stream.active and stream.unacked == 0 and stream.sent >= stream.content_len and stream.content_len > 0) {
                stream.active = false;
                self.releaseStaticPin(stream);
            }
        }
    }

    /// Time-driven connection maintenance (RFC 9002 6.2), the counterpart to onAckFrame for when NO ACK
    /// arrives. Ack-clocked loss detection cannot recover a lost tail (the client has nothing past the
    /// last packet to acknowledge, so no ACK ever reveals the gap): only the Probe Timeout does. On a PTO
    /// this declares every still-outstanding range lost and rewinds its stream for the pump to resend
    /// (RFC 9002 6.2 sends a probe, and resending the unacked data is that probe), backing off the PTO
    /// each time it fires unanswered. It reports the connection idle once the peer has clearly gone, so
    /// the caller frees the slot. Pure (now_us and max_idle_us supplied), so the sweep is testable with
    /// no socket or clock.
    ///
    /// Param:
    /// now_us - u64 (current monotonic time, recovery.nowUs() in production)
    /// max_idle_us - u64 (idle limit before eviction, config.max_idle_ms as microseconds)
    ///
    /// Return:
    /// - Maintenance (resend - pump the connection to retransmit, idle - remove it from the table)
    pub fn onMaintenance(self: *Connection, now_us: u64, max_idle_us: u64) Maintenance {
        // Reclaim the slot only when the peer is genuinely finished: it sent CONNECTION_CLOSE (RFC 9000
        // 10.2, now draining), or it has gone silent past the idle limit (10.1). The idle check applies
        // even with bytes still in flight, because a live peer keeps sending ACKs that refresh
        // last_activity, so it only trips for a peer that truly stopped. Loss never evicts (see below):
        // on a lossy path a live connection's resends can also drop, and reading that as "gone" would
        // kill a connection the client still holds open and strand it (the flaw a first cut introduced).
        if (self.close_state == .draining or self.close_state == .closed) return .{ .idle = true };
        if (now_us -| self.last_activity_us >= max_idle_us) return .{ .idle = true };

        // The oldest still-outstanding send: if its Probe Timeout has elapsed with no ACK, its flight (a
        // lost tail, typically) has gone unacknowledged long enough to retransmit.
        var oldest_send: ?u64 = null;
        for (&self.sent_ranges) |*entry| {
            if (!entry.in_flight) continue;
            if (oldest_send == null or entry.send_time_us < oldest_send.?) oldest_send = entry.send_time_us;
        }

        if (oldest_send == null) return .{}; // nothing in flight and not idle: a healthy keep-alive at rest

        const smoothed = if (self.rtt.has_sample) self.rtt.smoothed_rtt else recovery.initial_rtt_us;
        const rttvar = if (self.rtt.has_sample) self.rtt.rttvar else recovery.initial_rtt_us / 2;
        const pto = recovery.ptoWithBackoff(recovery.computePto(smoothed, rttvar, recovery.default_max_ack_delay_us), self.pto_backoff);

        if (now_us -| oldest_send.? < pto) return .{}; // the probe timer has not elapsed yet

        // PTO fired with no ACK: declare every outstanding range lost and rewind its stream so the pump
        // resends the flight. Drop the bytes from both in-flight tallies exactly as onAckFrame's loss
        // branch does, so the resend re-adds them rather than double-counting and stranding the window.
        var resend = false;
        for (&self.sent_ranges) |*entry| {
            if (!entry.in_flight) continue;

            entry.in_flight = false;
            self.bytes_in_flight -|= entry.length;
            resend = true;
            if (entry.datagram) {
                // A Probe Timeout is not a retransmission request for a datagram (RFC 9221 5.2).
            } else if (self.findSendStream(entry.stream_id)) |stream| {
                stream.unacked -|= entry.length;
                if (entry.offset < stream.sent) stream.sent = entry.offset;
            } else if (self.wt.findStream(entry.stream_id)) |stream| {
                stream.onLost(entry.offset);
            }
        }

        // A Probe Timeout is NOT a congestion signal (RFC 9002 6.2): it retransmits to elicit an ACK but
        // MUST NOT reduce the congestion window. Halving cwnd on every PTO (an earlier mistake here)
        // collapsed the window under load and pinned connections congestion-window-blocked, which the
        // bench diagnostic showed as the dominant stall (fc=0, cwnd_blocked in the millions). Real loss
        // still shrinks cwnd via the ack-driven path in onAckFrame. Here we only space out repeated
        // unanswered probes through the backoff (capped so the shift cannot overflow).
        if (self.pto_backoff < max_pto_backoff) self.pto_backoff += 1;

        return .{ .resend = resend };
    }

    /// Track the client's highest request stream and extend its bidirectional stream credit when the
    /// one-time handshake allowance is running low (RFC 9000 4.6 / 19.11). Without this a connection
    /// stalls once the client has opened `window` request streams, which is the HTTP/3 throughput
    /// collapse on a long-lived connection. Call once per received packet with the highest client bidi
    /// stream id it carried.
    ///
    /// Param:
    /// highest_bidi_id - u64 (the largest client-initiated bidi stream id seen, id % 4 == 0)
    /// window - u64 (request streams to keep available ahead of the client, the config.max_streams allowance)
    ///
    /// Return:
    /// - ?u64 (the new cumulative MAX_STREAMS value to advertise, or null when the grant still has room)
    pub fn replenishBidiStreams(self: *Connection, highest_bidi_id: u64, window: u64) ?u64 {
        const opened = highest_bidi_id / 4 + 1;
        if (opened > self.bidi_stream_high_water) self.bidi_stream_high_water = opened;

        if (self.bidi_streams_granted == 0) self.bidi_streams_granted = window;

        if (self.bidi_stream_high_water + window / 2 < self.bidi_streams_granted) return null;

        self.bidi_streams_granted = self.bidi_stream_high_water + window;

        return self.bidi_streams_granted;
    }

    /// Track the client's connection-wide byte consumption and extend its MAX_DATA credit when the
    /// one-time handshake budget (initial_max_data) is running low (RFC 9000 4.1 / 19.9). Without
    /// this a connection deadlocks once the client has sent `window` bytes of stream data (~1 MiB of
    /// requests): the client blocks on flow control and its last in-flight requests are never
    /// answered. Call once per received packet with the stream bytes it carried. Retransmitted
    /// stream bytes may be counted twice, which only grants credit early, never late: a grant is a
    /// limit, so overshooting by a packet is harmless while undershooting stalls the peer.
    ///
    /// Param:
    /// bytes_received - u64 (stream-frame payload bytes carried by the packet, all streams)
    /// window - u64 (bytes of credit to keep available ahead of the client, flight.initial_max_data)
    ///
    /// Return:
    /// - ?u64 (the new cumulative MAX_DATA value to advertise, or null when the grant still has room)
    /// Take the next server-initiated stream id of `kind`, advancing this connection's counter for that
    /// id space. Every server-initiated stream takes its id here, so no two of them can collide.
    pub fn takeServerStreamId(self: *Connection, kind: ServerStreamKind) u64 {
        return switch (kind) {
            .bidi => blk: {
                const id = self.next_server_bidi;
                self.next_server_bidi += 4;

                break :blk id;
            },
            .uni => blk: {
                const id = self.next_server_uni;
                self.next_server_uni += 4;

                break :blk id;
            },
        };
    }

    pub fn replenishMaxData(self: *Connection, bytes_received: u64, window: u64) ?u64 {
        self.data_consumed += bytes_received;

        if (self.data_granted == 0) self.data_granted = window;

        if (self.data_consumed + window / 2 < self.data_granted) return null;

        self.data_granted = self.data_consumed + window;

        return self.data_granted;
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix http3: sendDatagramSize clamps to the smallest of config, client limit, and ceiling" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    // Before the handshake parses the client's params, the field holds the QUIC minimum, so the send
    // size never exceeds 1200 however large the config asks for.
    try std.testing.expectEqual(@as(u64, 1200), conn.sendDatagramSize(8192, 16 * 1024));

    // A client that accepts 8 KiB lets an 8 KiB config through, but the ceiling caps a larger config.
    conn.client_max_udp_payload = 8192;
    try std.testing.expectEqual(@as(u64, 8192), conn.sendDatagramSize(8192, 16 * 1024));
    try std.testing.expectEqual(@as(u64, 8192), conn.sendDatagramSize(65527, 16 * 1024));

    // The config is honored when it is the smallest of the three.
    conn.client_max_udp_payload = 65527;
    try std.testing.expectEqual(@as(u64, 4096), conn.sendDatagramSize(4096, 16 * 1024));

    // The ceiling caps everything when both config and client allow more.
    try std.testing.expectEqual(@as(u64, 16 * 1024), conn.sendDatagramSize(65527, 16 * 1024));
}

test "zix http3: every server-initiated stream id is unique, control stream included" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    // The control stream is the first unidirectional stream a server opens (RFC 9114 6.2.1), and it takes
    // its id from the same counter every other server-initiated stream uses.
    const control = conn.takeServerStreamId(.uni);
    try std.testing.expectEqual(@as(u64, 3), control);

    // WebTransport data streams follow it: 7 and 11 unidirectional, 1 and 5 bidirectional. Handing a
    // session stream the control stream's id is the bug this covers (the bytes would land on the control
    // stream and break it for the peer).
    const uni_a = conn.takeServerStreamId(.uni);
    const uni_b = conn.takeServerStreamId(.uni);
    const bidi_a = conn.takeServerStreamId(.bidi);
    const bidi_b = conn.takeServerStreamId(.bidi);
    try std.testing.expectEqual(@as(u64, 7), uni_a);
    try std.testing.expectEqual(@as(u64, 11), uni_b);
    try std.testing.expectEqual(@as(u64, 1), bidi_a);
    try std.testing.expectEqual(@as(u64, 5), bidi_b);

    // The id spaces stay disjoint even under interleaved allocation, and every id is server-initiated:
    // unidirectional ids are 3 mod 4, bidirectional ids 1 mod 4.
    var taken: [16]u64 = undefined;
    var count: usize = 0;
    taken[count] = control;
    count += 1;
    for ([_]u64{ uni_a, uni_b, bidi_a, bidi_b }) |id| {
        taken[count] = id;
        count += 1;
    }
    for (taken[0..count], 0..) |id, i| {
        try std.testing.expect(id % 4 == 1 or id % 4 == 3);
        for (taken[i + 1 .. count]) |other| try std.testing.expect(id != other);
    }
}

test "zix http3: Connection init derives Initial keys from DCID (RFC 9001 A.1)" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    // The client Initial key from the RFC 9001 Appendix A.1 worked example.
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d }, &conn.initial_client.key);
    try std.testing.expectEqualSlices(u8, dcid[0..], conn.dcid.slice());
    try std.testing.expectEqual(@as(u64, 12_000), conn.cc.congestion_window);
    try std.testing.expect(conn.close_state == .open);
    try std.testing.expect(conn.initial_keys.maySendInitial());

    // Before address validation the 3x cap applies once bytes have been received.
    conn.anti_amplification.onReceive(1200);
    try std.testing.expect(conn.maySend(3600) and !conn.maySend(3601));
}

test "zix http3: replenishBidiStreams raises the grant past the one-time allowance so a connection never stalls" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    const window: u64 = 128;

    // Early streams stay inside the seeded allowance (128), so no MAX_STREAMS is due. Stream id 0 is
    // the first request stream (1 opened), id 4 the second, and so on.
    try std.testing.expect(conn.replenishBidiStreams(0, window) == null);
    try std.testing.expectEqual(@as(u64, 128), conn.bidi_streams_granted);

    // Crossing half the window (64 streams opened, highest bidi id 4*63 = 252) raises the grant ahead
    // of the client: 64 + 128 = 192, already past the one-time 128 cap.
    try std.testing.expectEqual(@as(u64, 192), conn.replenishBidiStreams(4 * 63, window).?);

    // Continuing past the old 128 cap keeps replenishing, so the client can open well beyond 128
    // request streams on the one connection (the stall this fixes).
    try std.testing.expectEqual(@as(u64, 256), conn.replenishBidiStreams(4 * 127, window).?);
    try std.testing.expectEqual(@as(u64, 384), conn.replenishBidiStreams(4 * 255, window).?);
    try std.testing.expect(conn.bidi_stream_high_water > 128);

    // A packet that opens no new stream (a lower id, a retransmit) does not lower the grant.
    try std.testing.expect(conn.replenishBidiStreams(0, window) == null);
    try std.testing.expectEqual(@as(u64, 384), conn.bidi_streams_granted);
}

test "zix http3: replenishMaxData raises the byte grant past the one-time budget so a connection never deadlocks" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    const window: u64 = 1024;

    // Early bytes stay inside the seeded budget (1024), so no MAX_DATA is due.
    try std.testing.expect(conn.replenishMaxData(100, window) == null);
    try std.testing.expectEqual(@as(u64, 1024), conn.data_granted);
    try std.testing.expectEqual(@as(u64, 100), conn.data_consumed);

    // Crossing half the window (consumed 100 + 500 = 600 >= 1024 - 512) raises the grant ahead of the
    // client: 600 + 1024 = 1624, already past the one-time 1024 budget.
    try std.testing.expectEqual(@as(u64, 1624), conn.replenishMaxData(500, window).?);

    // Continuing past the old budget keeps replenishing, so the client can send well beyond the
    // handshake allowance on the one connection (the ~1 MiB request deadlock this fixes).
    try std.testing.expectEqual(@as(u64, 2624), conn.replenishMaxData(1000, window).?);
    try std.testing.expect(conn.data_consumed > window);

    // A packet with few stream bytes leaves the grant untouched while it still has half a window.
    try std.testing.expect(conn.replenishMaxData(1, window) == null);
    try std.testing.expectEqual(@as(u64, 2624), conn.data_granted);
}

test "zix http3: reserveSendStream tracks max_send_streams concurrent large bodies, then reports full" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    // Fill every slot with a distinct client bidi stream id (id % 4 == 0).
    for (0..max_send_streams) |entry| {
        const stream_id: u64 = @intCast(entry * 4);
        const slot = conn.reserveSendStream(stream_id) orelse return error.TestUnexpectedResult;
        slot.* = .{ .active = true, .stream_id = stream_id };
    }

    // A concurrency this deep matches the protocol-level credit (config.max_streams), so it must not
    // be truncated by an internal pool smaller than what the client was actually granted.
    try std.testing.expect(conn.reserveSendStream(max_send_streams * 4) == null);

    // The existing streams still resolve to their own slot, not evicted by the probe above.
    try std.testing.expect(conn.findSendStream(0) != null);
    try std.testing.expect(conn.findSendStream((max_send_streams - 1) * 4) != null);
}

test "zix http3: AckTracker records packet numbers, holds a hole, then fills it" {
    var ack = AckTracker{};
    try std.testing.expect(!ack.have_largest);

    ack.record(0);
    ack.record(1);
    ack.record(3); // packet 2 missing

    try std.testing.expect(ack.have_largest);
    try std.testing.expectEqual(@as(u64, 3), ack.largest_pn);
    // bit 0 = pkt 3, bit 2 = pkt 1, bit 3 = pkt 0, bit 1 (pkt 2) clear.
    try std.testing.expectEqual(@as(u64, 0b1101), ack.received_mask);

    // A late packet 2 fills the hole in the window.
    ack.record(2);
    try std.testing.expectEqual(@as(u64, 0b1111), ack.received_mask);
}

fn oneRangeAck(largest: u64, smallest: u64, delay_us: u64) flow.Ack {
    var ranges: [16]flow.Range = undefined;
    ranges[0] = .{ .smallest = smallest, .largest = largest };

    return .{ .largest = largest, .delay_us = delay_us, .ranges = ranges, .range_len = 1, .ecn = null, .consumed = 0 };
}

test "zix http3: onAckFrame samples RTT from the packet at the newly-acked largest" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    conn.recordSentRange(5, 1000, .{ .stream_id = 0, .offset = 0, .length = 100 });
    try std.testing.expect(!conn.rtt.has_sample);

    conn.onAckFrame(oneRangeAck(5, 5, 0), 1500);

    try std.testing.expect(conn.rtt.has_sample);
    try std.testing.expectEqual(@as(u64, 500), conn.rtt.smoothed_rtt);
    try std.testing.expect(!conn.sent_ranges[0].in_flight);
}

test "zix http3: onAckFrame rewinds a SendStream's sent offset when its packet is lost" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    const slot = conn.reserveSendStream(4).?;
    slot.* = .{ .active = true, .stream_id = 4, .content_len = 1000, .sent = 300, .stream_limit = 1000 };

    conn.recordSentRange(1, 1000, .{ .stream_id = 4, .offset = 0, .length = 100 });
    conn.recordSentRange(2, 1000, .{ .stream_id = 4, .offset = 100, .length = 100 });
    conn.recordSentRange(3, 1000, .{ .stream_id = 4, .offset = 200, .length = 100 });

    // Packet 4 (an unrelated packet, not tracked here) is acked. Packet 1 is 3 behind the largest
    // acknowledged (the RFC 9002 6.1.1 packet-reordering threshold), so it is declared lost even
    // though packets 2 and 3 are not old enough yet by either threshold.
    conn.onAckFrame(oneRangeAck(4, 4, 0), 1010);

    try std.testing.expectEqual(@as(usize, 0), slot.sent);
    try std.testing.expect(!conn.sent_ranges[0].in_flight);
    try std.testing.expect(conn.sent_ranges[1].in_flight);
    try std.testing.expect(conn.sent_ranges[2].in_flight);
}

test "zix http3: onAckFrame does not rewind past a later, still-unacked send" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    const slot = conn.reserveSendStream(4).?;
    slot.* = .{ .active = true, .stream_id = 4, .content_len = 1000, .sent = 300, .stream_limit = 1000 };

    conn.recordSentRange(1, 1000, .{ .stream_id = 4, .offset = 0, .length = 100 });

    // Packet 1 itself is the one acknowledged: nothing to retransmit, sent stays put.
    conn.onAckFrame(oneRangeAck(1, 1, 0), 1010);

    try std.testing.expectEqual(@as(usize, 300), slot.sent);
    try std.testing.expect(!conn.sent_ranges[0].in_flight);
}

test "zix http3: recordSentRange raises bytes_in_flight and onAckFrame drains it while growing the window" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    const start_window = conn.cc.congestion_window;

    conn.recordSentRange(1, 1000, .{ .stream_id = 4, .offset = 0, .length = 1200 });
    conn.recordSentRange(2, 1000, .{ .stream_id = 4, .offset = 1200, .length = 1200 });
    try std.testing.expectEqual(@as(u64, 2400), conn.bytes_in_flight);

    // Acknowledging both ranges drains the in-flight tally and grows the window by the acked bytes
    // (slow start, RFC 9002 7.3.1), so the next pump has more room.
    conn.onAckFrame(oneRangeAck(2, 1, 0), 1100);

    try std.testing.expectEqual(@as(u64, 0), conn.bytes_in_flight);
    try std.testing.expectEqual(start_window + 2400, conn.cc.congestion_window);
}

test "zix http3: onAckFrame reacts to a lost packet with one congestion event and drops its bytes from flight" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    const slot = conn.reserveSendStream(4).?;
    slot.* = .{ .active = true, .stream_id = 4, .content_len = 10_000, .sent = 400, .stream_limit = 10_000 };

    // Four packets in flight (offsets 0,100,200,300). Packet 4 acks, so packet 1 is three behind the
    // largest acknowledged: past the RFC 9002 6.1.1 reorder threshold and declared lost.
    conn.recordSentRange(1, 1000, .{ .stream_id = 4, .offset = 0, .length = 100 });
    conn.recordSentRange(2, 1000, .{ .stream_id = 4, .offset = 100, .length = 100 });
    conn.recordSentRange(3, 1000, .{ .stream_id = 4, .offset = 200, .length = 100 });
    conn.recordSentRange(4, 1000, .{ .stream_id = 4, .offset = 300, .length = 100 });
    try std.testing.expectEqual(@as(u64, 400), conn.bytes_in_flight);

    const before = conn.cc.congestion_window;
    conn.onAckFrame(oneRangeAck(4, 4, 0), 1010);

    // Packet 4 retired (100 bytes), packet 1 lost (rewind + 100 bytes dropped), packets 2 and 3 still
    // outstanding (200 bytes). The window halves once for the round, not once per lost packet.
    try std.testing.expectEqual(@as(usize, 0), slot.sent);
    try std.testing.expectEqual(@as(u64, 200), conn.bytes_in_flight);
    try std.testing.expect(conn.cc.congestion_window < before);
}

test "zix http3: recordSentRange reclaims in-flight bytes when the ring overwrites a still-live slot" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    // Fill every ring slot with a live (unacked) range, then record one more to force an overwrite.
    for (0..max_sent_ranges) |entry| {
        conn.recordSentRange(@intCast(entry), 1000, .{ .stream_id = 4, .offset = entry * 100, .length = 100 });
    }
    try std.testing.expectEqual(@as(u64, max_sent_ranges * 100), conn.bytes_in_flight);

    // The overwrite drops the oldest live range from tracking, so its bytes leave the tally (net zero:
    // minus the overwritten 100, plus the new 100) rather than leaking upward and stalling the window.
    conn.recordSentRange(@intCast(max_sent_ranges), 1000, .{ .stream_id = 4, .offset = max_sent_ranges * 100, .length = 100 });
    try std.testing.expectEqual(@as(u64, max_sent_ranges * 100), conn.bytes_in_flight);
}

test "zix http3: onAckFrame retires a send stream only once it is fully sent AND fully acked" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    // A fully-sent stream (sent == content_len) with two packets still in flight (unacked = 200).
    const slot = conn.reserveSendStream(4).?;
    slot.* = .{ .active = true, .stream_id = 4, .content_len = 200, .sent = 200, .stream_limit = 10_000, .unacked = 200 };
    conn.recordSentRange(1, 1000, .{ .stream_id = 4, .offset = 0, .length = 100 });
    conn.recordSentRange(2, 1000, .{ .stream_id = 4, .offset = 100, .length = 100 });

    // Acking only the first packet leaves the stream fully sent but not fully acked, so it stays active:
    // a lost second packet must still be found and resent, which a freed slot could not do.
    conn.onAckFrame(oneRangeAck(1, 1, 0), 1010);
    try std.testing.expect(conn.send_streams[0].active);
    try std.testing.expectEqual(@as(usize, 100), conn.send_streams[0].unacked);

    // Acking the second retires the last in-flight bytes: now fully sent AND acked, the slot frees.
    conn.onAckFrame(oneRangeAck(2, 2, 0), 1020);
    try std.testing.expect(!conn.send_streams[0].active);
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams[0].unacked);
}

test "zix http3: an overwritten live range still drains the owning stream's unacked so its slot frees" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    // A fully-sent stream whose in-flight bytes exactly fill the ring: unacked = ring * 100.
    const slot = conn.reserveSendStream(4).?;
    slot.* = .{ .active = true, .stream_id = 4, .content_len = max_sent_ranges * 100, .sent = max_sent_ranges * 100, .stream_limit = 10_000_000, .unacked = max_sent_ranges * 100 };
    for (0..max_sent_ranges) |entry| {
        conn.recordSentRange(@intCast(entry), 1000, .{ .stream_id = 4, .offset = entry * 100, .length = 100 });
    }
    try std.testing.expectEqual(@as(usize, max_sent_ranges * 100), conn.send_streams[0].unacked);

    // One more send overwrites the oldest still-live range, dropping it from loss tracking. The owning
    // stream's unacked must fall by that range's 100 bytes (recordSentRange only decrements on overwrite;
    // the matching increment for the NEW range is the pump's job, not modelled here). Without this drain
    // (the bug that truncated static-h3) unacked would never return to 0 and the slot would leak forever.
    // bytes_in_flight nets to unchanged: recordSentRange owns both sides of it (minus old, plus new).
    conn.recordSentRange(@intCast(max_sent_ranges), 1000, .{ .stream_id = 4, .offset = max_sent_ranges * 100, .length = 100 });
    try std.testing.expectEqual(@as(usize, max_sent_ranges * 100 - 100), conn.send_streams[0].unacked);
    try std.testing.expectEqual(@as(u64, max_sent_ranges * 100), conn.bytes_in_flight);
}

test "zix http3: a fully-sent stream whose tail is lost stays retransmittable, not freed" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    // Fully sent (sent == content_len == 300), three packets still in flight.
    const slot = conn.reserveSendStream(4).?;
    slot.* = .{ .active = true, .stream_id = 4, .content_len = 300, .sent = 300, .stream_limit = 10_000, .unacked = 300 };
    conn.recordSentRange(1, 1000, .{ .stream_id = 4, .offset = 0, .length = 100 });
    conn.recordSentRange(2, 1000, .{ .stream_id = 4, .offset = 100, .length = 100 });
    conn.recordSentRange(3, 1000, .{ .stream_id = 4, .offset = 200, .length = 100 });

    // Packet 4 (unrelated) acked, so packet 1 is three behind and declared lost. The stream was not
    // freed on send, so the loss rewind still finds it: sent rewinds to 0 and the pump resends the tail.
    conn.onAckFrame(oneRangeAck(4, 4, 0), 1010);

    try std.testing.expect(conn.send_streams[0].active);
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams[0].sent);
}

test "zix http3: onMaintenance recovers a lost tail via the Probe Timeout when no ACK ever arrives" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    // Fully sent (sent == content_len), three packets in flight, and no ACK will come (the whole tail is
    // lost). Ack-based detection can never see this gap: only the Probe Timeout can.
    const slot = conn.reserveSendStream(4).?;
    slot.* = .{ .active = true, .stream_id = 4, .content_len = 300, .sent = 300, .stream_limit = 10_000, .unacked = 300 };
    conn.recordSentRange(1, 1000, .{ .stream_id = 4, .offset = 0, .length = 100 });
    conn.recordSentRange(2, 1000, .{ .stream_id = 4, .offset = 100, .length = 100 });
    conn.recordSentRange(3, 1000, .{ .stream_id = 4, .offset = 200, .length = 100 });
    try std.testing.expectEqual(@as(u64, 300), conn.bytes_in_flight);

    // Within the base Probe Timeout (~1.024s with no RTT sample) nothing fires: the flight might still
    // be acknowledged, so a premature resend would be spurious.
    const early = conn.onMaintenance(1000 + 500_000, 30_000_000);
    try std.testing.expect(!early.resend and !early.idle);
    try std.testing.expectEqual(@as(usize, 300), conn.send_streams[0].sent);

    // Past the Probe Timeout the outstanding tail is declared lost and rewound, so the next pump resends
    // it. Both in-flight tallies drain and the backoff counter advances. The congestion window is left
    // UNCHANGED: a PTO is not a congestion signal (RFC 9002 6.2), only ack-detected loss reduces cwnd.
    // The slot stays active (sent rewound below content_len), so the pump finds it to resend.
    const before_window = conn.cc.congestion_window;
    const fired = conn.onMaintenance(1000 + 2_000_000, 30_000_000);
    try std.testing.expect(fired.resend and !fired.idle);
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams[0].sent);
    try std.testing.expectEqual(@as(u64, 0), conn.bytes_in_flight);
    try std.testing.expectEqual(@as(usize, 0), conn.send_streams[0].unacked);
    try std.testing.expectEqual(@as(u6, 1), conn.pto_backoff);
    try std.testing.expectEqual(before_window, conn.cc.congestion_window);
    try std.testing.expect(conn.send_streams[0].active);
}

test "zix http3: onMaintenance evicts a connection silent past the idle limit, keeps a live one" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);
    conn.last_activity_us = 1_000_000;

    // Recently active with nothing in flight: a keep-alive between requests, not evictable.
    try std.testing.expect(!conn.onMaintenance(1_000_000 + 5_000_000, 30_000_000).idle);

    // Silent past the idle limit (30s): the peer has gone, so the slot may be reclaimed.
    try std.testing.expect(conn.onMaintenance(1_000_000 + 30_000_000, 30_000_000).idle);
}

test "zix http3: onMaintenance keeps retransmitting a lossy but live connection, never evicts on loss" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    const slot = conn.reserveSendStream(4).?;
    slot.* = .{ .active = true, .stream_id = 4, .content_len = 300, .sent = 300, .stream_limit = 10_000, .unacked = 100 };
    conn.recordSentRange(1, 0, .{ .stream_id = 4, .offset = 0, .length = 100 });

    // A live peer (activity 1s ago, well inside the idle limit) already at the backoff ceiling from
    // earlier unanswered probes. Its probe times out again: retransmit and hold the backoff at the
    // ceiling. Loss must NEVER evict a live connection (the flaw that stranded lossy connections
    // mid-transfer): only an explicit close or true silence does.
    conn.last_activity_us = 99_000_000;
    conn.pto_backoff = max_pto_backoff;
    const result = conn.onMaintenance(100_000_000, 30_000_000);
    try std.testing.expect(result.resend);
    try std.testing.expect(!result.idle);
    try std.testing.expectEqual(max_pto_backoff, conn.pto_backoff);
}

test "zix http3: onMaintenance evicts an idle peer even with bytes still in flight" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    const slot = conn.reserveSendStream(4).?;
    slot.* = .{ .active = true, .stream_id = 4, .content_len = 300, .sent = 100, .stream_limit = 10_000, .unacked = 100 };
    conn.recordSentRange(1, 1_000_000, .{ .stream_id = 4, .offset = 0, .length = 100 });
    conn.last_activity_us = 1_000_000;

    // Silent for the whole idle period with data still outstanding: the peer is gone, so evict rather
    // than retransmit into a void forever (the idle check must win over the in-flight retransmit path).
    const m = conn.onMaintenance(1_000_000 + 30_000_000, 30_000_000);
    try std.testing.expect(m.idle);
}

test "zix http3: onMaintenance evicts a connection the peer closed, whatever its recent activity" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);
    conn.last_activity_us = 100_000_000; // just active

    // A received CONNECTION_CLOSE puts the connection into draining (RFC 9000 10.2): evict it promptly,
    // even though it was active a moment ago, and do not keep sending.
    conn.close_state = .draining;
    const m = conn.onMaintenance(100_000_000 + 100_000, 30_000_000);
    try std.testing.expect(m.idle);
    try std.testing.expect(!m.resend);
}

test "zix http3: onAckFrame resets the PTO backoff when it acknowledges new data" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);
    conn.pto_backoff = 3;

    conn.recordSentRange(5, 1000, .{ .stream_id = 0, .offset = 0, .length = 100 });
    conn.onAckFrame(oneRangeAck(5, 5, 0), 1500);

    // The ACK cleared the probe timer, so a later PTO starts from the base period again (RFC 9002 6.2.1).
    try std.testing.expectEqual(@as(u6, 0), conn.pto_backoff);
}
