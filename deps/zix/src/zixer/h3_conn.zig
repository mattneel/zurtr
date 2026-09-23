//! zixer h3 conn: one QUIC connection the edge terminates (rfc 9000, rfc 9001)

const std = @import("std");
const zix = @import("zix");

const h3_frames = @import("h3_frames.zig");
const h3_streams = @import("h3_streams.zig");

const Http3 = zix.Http3;
const crypto = Http3.crypto;
const protection = Http3.protection;
const keyschedule = Http3.keyschedule;
const packet = Http3.packet;
const varint = Http3.varint;
const quic_tls = Http3.quic_tls;
const serverhello = Http3.serverhello;
const flight = Http3.flight;
const transport_params = Http3.transport_params;
const flow = Http3.flow;
const recovery = Http3.recovery;
const demux = Http3.demux;
const wire = Http3.response;
const quic_request = Http3.request;
const tls_handshake = Http3.tls_handshake;
const Transcript = Http3.tls_key_schedule.Transcript;
const secure_random = zix.utils.secure_random;

/// Wire size of a 1-RTT datagram the edge sends. The rfc 9000 floor every path
/// carries, so a response never depends on path MTU discovery.
pub const SEND_DATAGRAM: usize = 1200;

/// Room kept in a send packet for its frame headers and the AEAD tag.
pub const PACKET_RESERVE: usize = 96;

/// Decrypt scratch for one received packet.
pub const RECV_PAYLOAD: usize = 2048;

/// Sent packets tracked for loss detection. Each carries one stream range.
pub const MAX_SENT_RANGES: usize = 128;

/// Packets the pump keeps in flight at once. Half the ring, so a range is never
/// overwritten while it is still awaiting an acknowledgment.
pub const MAX_INFLIGHT_PACKETS: usize = MAX_SENT_RANGES / 2;

/// Connection id length the edge issues.
pub const CID_LEN: usize = 8;

/// Idle timeout advertised in the handshake and enforced by the sweep.
pub const MAX_IDLE_MS: u64 = 30_000;

/// The per-stream receive window the handshake advertises (rfc 9000 18.2,
/// initial_max_stream_data_bidi_remote in the engine's flight builder).
pub const STREAM_WINDOW: u64 = 262_144;

/// The connection-wide receive window the handshake advertises.
pub const DATA_WINDOW: u64 = flight.initial_max_data;

/// Frames the receive path acts on by type (rfc 9000 19).
const FRAME_PADDING: u64 = 0x00;
const FRAME_PING: u64 = 0x01;
const FRAME_ACK: u64 = 0x02;
const FRAME_ACK_ECN: u64 = 0x03;
const FRAME_RESET_STREAM: u64 = 0x04;
const FRAME_STOP_SENDING: u64 = 0x05;
const FRAME_MAX_DATA: u64 = 0x10;
const FRAME_MAX_STREAM_DATA: u64 = 0x11;
const FRAME_CONNECTION_CLOSE: u64 = 0x1c;
const FRAME_APPLICATION_CLOSE: u64 = 0x1d;
const FRAME_HANDSHAKE_DONE: u64 = 0x1e;

/// Where a built datagram goes. The edge points this at its udp socket, a test
/// points it at a recorder, so the connection never touches io itself.
pub const Sink = struct {
    ctx: *anyopaque,
    sendFn: *const fn (ctx: *anyopaque, datagram: []const u8) void,

    pub fn send(sink: Sink, datagram: []const u8) void {
        sink.sendFn(sink.ctx, datagram);
    }
};

/// What one received datagram produced, for the edge to act on.
pub const Progress = struct {
    /// Client request streams whose readable bytes advanced.
    ready: [h3_streams.MAX_STREAMS]u64 = @splat(0),
    ready_len: usize = 0,
    /// The peer sent CONNECTION_CLOSE.
    peer_closed: bool = false,
    /// This datagram completed the handshake, so 1-RTT is open.
    handshake_done: bool = false,

    fn note(progress: *Progress, stream_id: u64) void {
        for (progress.ready[0..progress.ready_len]) |seen| {
            if (seen == stream_id) return;
        }

        if (progress.ready_len >= progress.ready.len) return;

        progress.ready[progress.ready_len] = stream_id;
        progress.ready_len += 1;
    }

    /// The request streams that advanced.
    pub fn slice(progress: *const Progress) []const u64 {
        return progress.ready[0..progress.ready_len];
    }
};

/// What the time-driven sweep found for one connection.
pub const Maintenance = struct {
    /// A probe timeout fired: streams were rewound, so pump again.
    resend: bool = false,
    /// The peer is gone (closed, or silent past the idle limit).
    idle: bool = false,
};

/// Which client packet numbers arrived, so the edge acknowledges honest ranges
/// (rfc 9000 19.3) and the peer retransmits only what was really lost.
pub const AckTracker = struct {
    largest: u64 = 0,
    have_largest: bool = false,
    mask: u64 = 0,

    /// Record one received packet number, sliding the 64-packet window.
    pub fn record(tracker: *AckTracker, pn: u64) void {
        if (!tracker.have_largest) {
            tracker.have_largest = true;
            tracker.largest = pn;
            tracker.mask = 1;
            return;
        }

        if (pn > tracker.largest) {
            const shift = pn - tracker.largest;
            tracker.mask = if (shift >= 64) 1 else (tracker.mask << @intCast(shift)) | 1;
            tracker.largest = pn;
            return;
        }

        const delta = tracker.largest - pn;
        if (delta < 64) tracker.mask |= @as(u64, 1) << @intCast(delta);
    }
};

/// One sent 1-RTT packet and the stream range it carried, so a loss reported by
/// a later ACK can be resent (rfc 9002 6.1).
const SentRange = struct {
    packet_number: u64 = 0,
    sent_us: u64 = 0,
    stream_id: u64 = 0,
    offset: u64 = 0,
    length: u32 = 0,
    in_flight: bool = false,
};

/// One QUIC connection: keys, streams, flow control, and loss recovery.
///
/// Note:
/// - Not synchronized. The edge holds one lock per connection around every
///   call, because the receive thread and the request tasks both reach in.
pub const Conn = struct {
    allocator: std.mem.Allocator,
    tls: *const zix.Tls.Context,

    /// The client's first Destination Connection ID, the table key.
    dcid: demux.ConnId,
    /// The Source Connection ID the edge issued, which the client then uses as
    /// its Destination CID.
    our_scid: demux.ConnId = .{},
    /// The client's Source Connection ID, our destination on the way back.
    peer_scid: demux.ConnId = .{},
    peer: std.Io.net.IpAddress,

    initial_client: crypto.AesKeys,
    initial_server: crypto.AesKeys,
    crypto_stream: quic_tls.CryptoStream = .{},

    server_hello_sent: bool = false,
    handshake_ready: bool = false,
    hs_keys: keyschedule.HandshakeKeys = undefined,
    transcript: Transcript = undefined,

    app_ready: bool = false,
    app_keys: keyschedule.AppKeys = undefined,
    app_pn: u32 = 0,

    ack: AckTracker = .{},
    ack_pending: bool = false,
    /// Until the client acknowledges something, every packet repeats the
    /// prologue (HANDSHAKE_DONE and the control stream SETTINGS), so losing the
    /// first packet cannot strand the connection.
    prologue_acked: bool = false,

    streams: h3_streams.Table = .{},

    // Limits the client advertised, which the send path must respect.
    client_max_data: u64 = 0,
    client_max_stream_data: u64 = 0,
    client_max_udp_payload: u64 = transport_params.min_udp_payload_size,
    ack_delay_exponent: u6 = 3,
    conn_data_sent: u64 = 0,

    // Credit the edge grants the client, kept ahead of what it consumes.
    data_granted: u64 = DATA_WINDOW,
    data_consumed: u64 = 0,
    streams_granted: u64 = h3_streams.MAX_STREAMS,
    /// Pending credit frames, each riding the next packet out.
    max_data_pending: ?u64 = null,
    max_streams_pending: ?u64 = null,
    max_stream_data_pending: ?struct { stream_id: u64, limit: u64 } = null,

    sent_ranges: [MAX_SENT_RANGES]SentRange = @splat(.{}),
    sent_cursor: usize = 0,
    bytes_in_flight: u64 = 0,
    rtt: recovery.RttEstimator = .{},
    cc: recovery.CongestionController,
    pto_backoff: u6 = 0,
    last_send_us: u64 = 0,
    last_activity_us: u64 = 0,
    closed: bool = false,

    /// Start a server-side connection from the client's first Initial.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (stream buffers, long-lived)
    /// tls - *const zix.Tls.Context (site certificate and key, must outlive the conn)
    /// dcid - []const u8 (the client's Destination Connection ID)
    /// peer - std.Io.net.IpAddress (where replies go)
    ///
    /// Return:
    /// - Conn ready to take datagrams
    pub fn init(allocator: std.mem.Allocator, tls: *const zix.Tls.Context, dcid: []const u8, peer: std.Io.net.IpAddress) Conn {
        const secrets = crypto.initialSecrets(dcid);

        return .{
            .allocator = allocator,
            .tls = tls,
            .dcid = demux.ConnId.fromSlice(dcid),
            .peer = peer,
            .initial_client = crypto.AesKeys.fromSecret(secrets.client),
            .initial_server = crypto.AesKeys.fromSecret(secrets.server),
            .cc = recovery.CongestionController.init(SEND_DATAGRAM, recovery.initialWindow(SEND_DATAGRAM)),
            .last_activity_us = recovery.nowUs(),
        };
    }

    /// Release every stream buffer.
    pub fn deinit(conn: *Conn) void {
        conn.streams.deinit(conn.allocator);
    }

    /// Feed one received datagram, answering the handshake when it completes.
    pub fn onDatagram(conn: *Conn, data: []const u8, sink: Sink) Progress {
        var progress = Progress{};
        if (data.len == 0) return progress;

        conn.last_activity_us = recovery.nowUs();

        if (data[0] & 0x80 != 0) {
            conn.onLongHeader(data, sink, &progress);
            return progress;
        }

        conn.onShortHeader(data, &progress);

        return progress;
    }

    /// Handshake-space packets: the client Initial carrying its ClientHello,
    /// and the client Handshake packet carrying its Finished.
    fn onLongHeader(conn: *Conn, data: []const u8, sink: Sink, progress: *Progress) void {
        const header = packet.parseLongHeader(data) catch return;

        if (header.packet_type == 0) {
            var buf: [RECV_PAYLOAD]u8 = undefined;
            const opened = protection.openInitial(data, conn.initial_client, &buf) catch return;

            conn.feedCryptoFrames(opened.payload);

            if (!conn.server_hello_sent) conn.answerHandshake(header.scid, sink, progress);
            return;
        }

        // The client Handshake packet carries its Finished. Opening it proves
        // the handshake secrets match on both sides, which is all the edge
        // needs: there is no client certificate to verify.
        if (header.packet_type == 2 and conn.handshake_ready) {
            var buf: [RECV_PAYLOAD]u8 = undefined;
            _ = protection.openHandshake(data, conn.hs_keys.client, &buf) catch return;
        }
    }

    /// Feed the CRYPTO frames of a decrypted Initial into the handshake stream.
    fn feedCryptoFrames(conn: *Conn, payload: []const u8) void {
        var pos: usize = 0;
        while (pos < payload.len) {
            const parsed = Http3.frame.parseFrame(payload[pos..]) catch break;
            switch (parsed.frame) {
                .crypto => |chunk| conn.crypto_stream.insert(@intCast(chunk.offset), chunk.data),
                else => {},
            }

            if (parsed.len == 0) break;
            pos += parsed.len;
        }
    }

    /// The complete ClientHello bytes, or null while fragments are missing.
    fn clientHello(conn: *const Conn) ?[]const u8 {
        const bytes = conn.crypto_stream.readable();
        if (bytes.len < 4 or bytes[0] != 0x01) return null;

        const declared = (@as(usize, bytes[1]) << 16) | (@as(usize, bytes[2]) << 8) | bytes[3];
        if (bytes.len < 4 + declared) return null;

        return bytes[0 .. 4 + declared];
    }

    /// Answer a complete ClientHello: ServerHello in an Initial, then the
    /// Handshake flight (ALPN h3, transport parameters, certificate).
    fn answerHandshake(conn: *Conn, client_scid: []const u8, sink: Sink, progress: *Progress) void {
        const hello_bytes = conn.clientHello() orelse return;
        const hello = switch (tls_handshake.parseClientHello(hello_bytes)) {
            .ok => |parsed| parsed,
            .alert => return,
        };

        // The client's own limits, which the response path must not overrun.
        if (transport_params.fromClientHello(hello_bytes)) |params| {
            conn.client_max_data = params.initial_max_data;
            conn.client_max_stream_data = params.initial_max_stream_data_bidi_local;
            conn.ack_delay_exponent = params.ack_delay_exponent;
            conn.client_max_udp_payload = params.max_udp_payload_size;
        }

        var scid_bytes: [CID_LEN]u8 = undefined;
        secure_random.fill(&scid_bytes);
        conn.our_scid = demux.ConnId.fromSlice(&scid_bytes);
        conn.peer_scid = demux.ConnId.fromSlice(client_scid);

        var server_random: [32]u8 = undefined;
        secure_random.fill(&server_random);
        var ephemeral: [32]u8 = undefined;
        secure_random.fill(&ephemeral);

        var initial_out: [1500]u8 = undefined;
        const built = serverhello.buildServerHelloInitial(
            &initial_out,
            &hello,
            hello_bytes,
            conn.initial_server,
            client_scid,
            conn.our_scid.slice(),
            server_random,
            ephemeral,
        ) orelse return;

        conn.hs_keys = built.keys;
        conn.transcript = built.transcript;
        conn.handshake_ready = true;
        conn.server_hello_sent = true;

        sink.send(built.packet);

        const opts = conn.tls.handshakeOptions(ephemeral, server_random, @splat(0));

        var flight_out: [1500]u8 = undefined;
        const flight_packet = flight.buildHandshakeFlight(
            &flight_out,
            conn.hs_keys.server,
            conn.hs_keys.server_traffic,
            client_scid,
            conn.our_scid.slice(),
            &conn.transcript,
            opts.certificate_der,
            opts.signing_key,
            conn.dcid.slice(),
            conn.our_scid.slice(),
            MAX_IDLE_MS,
            h3_streams.MAX_STREAMS,
            .{},
        ) orelse return;

        sink.send(flight_packet);

        // 1-RTT keys follow the transcript through the server Finished the
        // flight just appended.
        conn.app_keys = keyschedule.applicationKeys(conn.hs_keys.handshake_secret, conn.transcript.current());
        conn.app_ready = true;
        progress.handshake_done = true;
    }

    /// A 1-RTT packet: decrypt, acknowledge, and apply its frames.
    fn onShortHeader(conn: *Conn, data: []const u8, progress: *Progress) void {
        if (!conn.app_ready) return;

        var buf: [RECV_PAYLOAD]u8 = undefined;
        const largest: ?u64 = if (conn.ack.have_largest) conn.ack.largest else null;
        const opened = protection.openShort(data, conn.app_keys.client, conn.our_scid.len, largest, &buf) catch return;

        conn.ack.record(opened.packet_number);
        conn.applyFrames(opened.payload, progress);
    }

    /// Walk the frames of a decrypted 1-RTT payload.
    fn applyFrames(conn: *Conn, payload: []const u8, progress: *Progress) void {
        var pos: usize = 0;

        while (pos < payload.len) {
            const type_vi = varint.read(payload[pos..]) catch return;
            const kind = type_vi.value;

            if (quic_request.isStreamFrameType(kind)) {
                conn.ack_pending = true;
                const consumed = conn.onStreamFrame(payload[pos..], progress) orelse return;
                pos += consumed;
                continue;
            }

            switch (kind) {
                FRAME_ACK, FRAME_ACK_ECN => {
                    const parsed = flow.parseAck(payload[pos..], conn.ack_delay_exponent) catch return;
                    conn.onAck(parsed);
                    pos += parsed.consumed;
                },
                FRAME_MAX_DATA => {
                    conn.ack_pending = true;
                    var walk = pos + type_vi.len;
                    const limit = varint.read(payload[walk..]) catch return;
                    walk += limit.len;
                    if (limit.value > conn.client_max_data) conn.client_max_data = limit.value;
                    pos = walk;
                },
                FRAME_MAX_STREAM_DATA => {
                    conn.ack_pending = true;
                    var walk = pos + type_vi.len;
                    const stream_id = varint.read(payload[walk..]) catch return;
                    walk += stream_id.len;
                    const limit = varint.read(payload[walk..]) catch return;
                    walk += limit.len;
                    if (conn.streams.findSend(stream_id.value)) |send| {
                        if (limit.value > send.stream_limit) send.stream_limit = limit.value;
                    }
                    pos = walk;
                },
                FRAME_RESET_STREAM, FRAME_STOP_SENDING => {
                    conn.ack_pending = true;
                    const stream_id = varint.read(payload[pos + type_vi.len ..]) catch return;
                    conn.dropStream(stream_id.value);
                    pos += quic_request.skipFrame(payload[pos..]) orelse return;
                },
                FRAME_CONNECTION_CLOSE, FRAME_APPLICATION_CLOSE => {
                    conn.closed = true;
                    progress.peer_closed = true;
                    return;
                },
                FRAME_PADDING, FRAME_PING, FRAME_HANDSHAKE_DONE => {
                    if (kind == FRAME_PING) conn.ack_pending = true;
                    pos += type_vi.len;
                },
                else => {
                    conn.ack_pending = true;
                    pos += quic_request.skipFrame(payload[pos..]) orelse return;
                },
            }
        }
    }

    /// Route one STREAM frame. Client bidi streams carry requests, client uni
    /// streams are the control and QPACK planes: their bytes are accounted for
    /// flow control and dropped, because zixer advertises no dynamic table and
    /// acts on no client setting.
    fn onStreamFrame(conn: *Conn, buf: []const u8, progress: *Progress) ?usize {
        const kind = buf[0];
        var pos: usize = 1;

        const id = varint.read(buf[pos..]) catch return null;
        pos += id.len;

        var offset: u64 = 0;
        if (kind & 0x04 != 0) {
            const off = varint.read(buf[pos..]) catch return null;
            pos += off.len;
            offset = off.value;
        }

        var length: u64 = buf.len - pos;
        if (kind & 0x02 != 0) {
            const len = varint.read(buf[pos..]) catch return null;
            pos += len.len;
            length = len.value;
        }
        if (pos + length > buf.len) return null;

        const bytes = buf[pos..][0..@intCast(length)];
        const fin = kind & 0x01 != 0;
        const consumed = pos + @as(usize, @intCast(length));

        conn.creditData(length);

        // Client-initiated bidirectional (id mod 4 == 0) is a request stream.
        if (id.value % 4 != 0) return consumed;

        const recv = conn.streams.recvFor(id.value) orelse return consumed;
        if (recv.granted == 0) recv.granted = STREAM_WINDOW;

        recv.insert(conn.allocator, offset, bytes, fin) catch {
            conn.dropStream(id.value);
            return consumed;
        };

        conn.creditStream(recv);
        conn.creditStreamCount(id.value);
        progress.note(id.value);

        return consumed;
    }

    /// Charge received bytes against the connection window and queue MAX_DATA
    /// before the client runs out (rfc 9000 4.1).
    fn creditData(conn: *Conn, bytes: u64) void {
        conn.data_consumed += bytes;
        if (conn.data_consumed + DATA_WINDOW / 2 < conn.data_granted) return;

        conn.data_granted = conn.data_consumed + DATA_WINDOW;
        conn.max_data_pending = conn.data_granted;
    }

    /// Keep one request stream's window ahead of what the client has sent.
    fn creditStream(conn: *Conn, recv: *h3_streams.RecvStream) void {
        const received = recv.received();
        if (received + STREAM_WINDOW / 2 < recv.granted) return;

        recv.granted = received + STREAM_WINDOW;
        conn.max_stream_data_pending = .{ .stream_id = recv.stream_id, .limit = recv.granted };
    }

    /// Keep the client's request-stream allowance ahead of the streams it opens
    /// (rfc 9000 4.6), so the handshake's one-time budget never strands it.
    fn creditStreamCount(conn: *Conn, stream_id: u64) void {
        const opened = stream_id / 4 + 1;
        if (opened + h3_streams.MAX_STREAMS / 2 < conn.streams_granted) return;

        conn.streams_granted = opened + h3_streams.MAX_STREAMS;
        conn.max_streams_pending = conn.streams_granted;
    }

    /// Apply one ACK frame: retire ranges, sample RTT, grow the window, and
    /// rewind whatever it declares lost (rfc 9002 6.1, 7.3).
    fn onAck(conn: *Conn, ack: flow.Ack) void {
        conn.prologue_acked = true;

        const now = recovery.nowUs();
        var acked_bytes: u64 = 0;
        var newest_sent_us: ?u64 = null;

        for (&conn.sent_ranges) |*range| {
            if (!range.in_flight) continue;
            if (!ackCovers(ack, range.packet_number)) continue;

            range.in_flight = false;
            conn.bytes_in_flight -|= range.length;
            acked_bytes += range.length;
            if (range.packet_number == ack.largest) newest_sent_us = range.sent_us;

            if (conn.streams.findSend(range.stream_id)) |send| {
                send.unacked -|= range.length;
            }
        }

        if (newest_sent_us) |sent_us| {
            if (now > sent_us) conn.rtt.onSample(now - sent_us, ack.delay_us, recovery.default_max_ack_delay_us, true);
        }

        if (acked_bytes > 0) {
            conn.cc.onAckedBytes(acked_bytes);
            conn.pto_backoff = 0;
        }

        conn.detectLoss(ack.largest, now);
        conn.releaseAcknowledged();
        conn.retireFinished();
    }

    /// Declare packets lost by the rfc 9002 6.1 packet and time thresholds, and
    /// rewind their streams so the pump resends the bytes.
    fn detectLoss(conn: *Conn, largest_acked: u64, now_us: u64) void {
        var lost_any = false;

        for (&conn.sent_ranges) |*range| {
            if (!range.in_flight) continue;
            if (range.packet_number >= largest_acked) continue;

            const since = if (now_us > range.sent_us) now_us - range.sent_us else 0;
            if (!recovery.packetLost(range.packet_number, largest_acked, since, conn.rtt.smoothed_rtt, conn.rtt.smoothed_rtt)) continue;

            range.in_flight = false;
            conn.bytes_in_flight -|= range.length;
            lost_any = true;

            if (conn.streams.findSend(range.stream_id)) |send| {
                send.unacked -|= range.length;
                send.rewind(range.offset);
            }
        }

        if (lost_any) conn.cc.onCongestionEvent();
    }

    /// Drop buffered response bytes that can no longer be needed: everything
    /// below both the send cursor and the oldest range still in flight.
    fn releaseAcknowledged(conn: *Conn) void {
        for (&conn.streams.send) |*send| {
            if (!send.active) continue;

            var retain = send.sent;
            for (conn.sent_ranges) |range| {
                if (!range.in_flight or range.stream_id != send.stream_id) continue;
                retain = @min(retain, range.offset);
            }

            send.releaseTo(retain);
        }
    }

    /// Free the slot of every stream fully sent and fully acknowledged.
    fn retireFinished(conn: *Conn) void {
        for (&conn.streams.send) |*send| {
            if (send.active and send.retired()) send.deinit(conn.allocator);
        }
    }

    /// Forget a stream the client reset or asked us to stop sending on.
    fn dropStream(conn: *Conn, stream_id: u64) void {
        if (conn.streams.findRecv(stream_id)) |recv| recv.deinit(conn.allocator);
        if (conn.streams.findSend(stream_id)) |send| send.deinit(conn.allocator);
    }

    /// The readable request bytes of one stream, empty when it has none.
    pub fn readable(conn: *Conn, stream_id: u64) []const u8 {
        const recv = conn.streams.findRecv(stream_id) orelse return &.{};

        return recv.readable();
    }

    /// Mark request bytes as parsed.
    pub fn takeRequestBytes(conn: *Conn, stream_id: u64, count: usize) void {
        if (conn.streams.findRecv(stream_id)) |recv| recv.take(count);
    }

    /// Whether the client ended its side of the stream.
    pub fn requestEnded(conn: *Conn, stream_id: u64) bool {
        const recv = conn.streams.findRecv(stream_id) orelse return false;

        return recv.complete();
    }

    /// Append response bytes for one client stream.
    pub fn respond(conn: *Conn, stream_id: u64, bytes: []const u8) !void {
        const send = conn.streams.sendFor(stream_id) orelse return error.ZixerNoStreamSlot;
        if (send.stream_limit == 0) send.stream_limit = conn.client_max_stream_data;

        try send.append(conn.allocator, bytes);
    }

    /// End the response on one client stream.
    pub fn finishResponse(conn: *Conn, stream_id: u64) void {
        if (conn.streams.findSend(stream_id)) |send| send.finish();
    }

    /// Bytes buffered but not yet on the wire for one stream, the backpressure
    /// signal a relay watches before reading more from its upstream.
    pub fn queuedBytes(conn: *Conn, stream_id: u64) usize {
        const send = conn.streams.findSend(stream_id) orelse return 0;

        return @intCast(send.buffered() -| send.sent);
    }

    /// Release the request buffer of a stream whose response is finished, so a
    /// served request stops holding its head and body.
    pub fn releaseRequest(conn: *Conn, stream_id: u64) void {
        if (conn.streams.findRecv(stream_id)) |recv| recv.deinit(conn.allocator);
    }

    /// Send everything flow control and the congestion window now allow.
    ///
    /// Note:
    /// - One packet carries at most one stream range, so every packet the pump
    ///   builds is retransmittable on its own.
    pub fn pump(conn: *Conn, sink: Sink) void {
        if (!conn.app_ready or conn.closed) return;

        var sent_any = false;

        for (&conn.streams.send) |*send| {
            if (!send.active) continue;

            while (conn.sendChunk(send, sink)) sent_any = true;
        }

        // Nothing rode out, but the peer still needs an acknowledgment or a
        // credit grant, so send the bare prologue packet.
        if (!sent_any and (conn.ack_pending or conn.creditPending())) _ = conn.sendPrologueOnly(sink);

        conn.retireFinished();
    }

    fn creditPending(conn: *const Conn) bool {
        return conn.max_data_pending != null or conn.max_streams_pending != null or conn.max_stream_data_pending != null;
    }

    /// Send one packet of one stream, returning false when nothing more may go
    /// out for it this round.
    fn sendChunk(conn: *Conn, send: *h3_streams.SendStream, sink: Sink) bool {
        const limit = conn.sendLimit(send);
        const fin_at = send.fin_offset orelse std.math.maxInt(u64);

        // A fin with no bytes left to carry still has to reach the client.
        if (limit <= send.sent and !send.finPending()) return false;

        var payload: [SEND_DATAGRAM]u8 = undefined;
        var plen = conn.writePrologue(&payload);

        const room = payload.len - plen - PACKET_RESERVE;
        const want: usize = @intCast(limit -| send.sent);
        const chunk = send.chunk(send.sent, @min(room, want));
        const is_last = send.fin_offset != null and send.sent + chunk.len >= fin_at;

        if (chunk.len == 0 and !is_last) return false;

        // STREAM frame with explicit offset and length, fin on the last one.
        payload[plen] = 0x0e | @as(u8, if (is_last) 0x01 else 0x00);
        plen += 1;
        plen += varint.write(payload[plen..], send.stream_id);
        plen += varint.write(payload[plen..], send.sent);
        plen += varint.write(payload[plen..], chunk.len);
        @memcpy(payload[plen..][0..chunk.len], chunk);
        plen += chunk.len;

        const range = SentRange{
            .stream_id = send.stream_id,
            .offset = send.sent,
            .length = @intCast(chunk.len),
        };
        if (!conn.sealAndSend(payload[0..plen], range, sink)) return false;

        const after = send.sent + chunk.len;
        if (after > send.high_water) {
            conn.conn_data_sent += after - send.high_water;
            send.high_water = after;
        }
        send.sent = after;
        send.unacked += chunk.len;
        if (is_last) send.fin_sent = true;

        return !send.fullySent();
    }

    /// The stream offset the pump may reach now: the client's stream and
    /// connection credit, capped by the congestion window.
    fn sendLimit(conn: *const Conn, send: *const h3_streams.SendStream) u64 {
        const conn_room = conn.client_max_data -| conn.conn_data_sent;
        const flow_limit = @min(send.buffered(), @min(send.stream_limit, send.high_water + conn_room));

        const window = @min(conn.cc.congestion_window, MAX_INFLIGHT_PACKETS * SEND_DATAGRAM);
        const cwnd_room = window -| conn.bytes_in_flight;

        return @min(flow_limit, send.sent + cwnd_room);
    }

    /// Write the packet prologue: the acknowledgment, the one-time
    /// HANDSHAKE_DONE and control-stream SETTINGS, and any pending credit.
    fn writePrologue(conn: *Conn, payload: []u8) usize {
        var plen: usize = 0;

        if (conn.ack.have_largest and (conn.ack_pending or !conn.prologue_acked)) {
            plen += wire.buildAckRanges(payload[plen..], conn.ack.largest, conn.ack.mask);
            conn.ack_pending = false;
        }

        if (!conn.prologue_acked) {
            payload[plen] = FRAME_HANDSHAKE_DONE;
            plen += 1;

            // The server control stream (id 3): its type varint then SETTINGS.
            var control: [32]u8 = undefined;
            var control_len: usize = varint.write(&control, h3_frames.CONTROL_STREAM);
            control_len += h3_frames.writeSettings(control[control_len..], .{}) catch 0;
            _ = wire.writeStreamFrame(payload, &plen, 3, false, control[0..control_len]);
        }

        if (conn.max_streams_pending) |granted| {
            plen += wire.buildMaxStreams(payload[plen..], granted);
            conn.max_streams_pending = null;
        }

        if (conn.max_data_pending) |granted| {
            plen += wire.buildMaxData(payload[plen..], granted);
            conn.max_data_pending = null;
        }

        if (conn.max_stream_data_pending) |grant| {
            payload[plen] = FRAME_MAX_STREAM_DATA;
            plen += 1;
            plen += varint.write(payload[plen..], grant.stream_id);
            plen += varint.write(payload[plen..], grant.limit);
            conn.max_stream_data_pending = null;
        }

        return plen;
    }

    /// Send a packet that carries only the prologue (an acknowledgment, credit,
    /// or the one-time handshake frames).
    fn sendPrologueOnly(conn: *Conn, sink: Sink) bool {
        var payload: [SEND_DATAGRAM]u8 = undefined;
        const plen = conn.writePrologue(&payload);
        if (plen == 0) return false;

        return conn.sealAndSend(payload[0..plen], null, sink);
    }

    /// Seal one 1-RTT packet and hand it to the sink, recording the stream
    /// range it carried for loss detection.
    fn sealAndSend(conn: *Conn, payload: []const u8, range: ?SentRange, sink: Sink) bool {
        var out: [SEND_DATAGRAM + protection.short_seal_overhead_max]u8 = undefined;
        const sealed = protection.sealShort(&out, conn.app_keys.server, conn.peer_scid.slice(), conn.app_pn, payload) catch return false;

        const now = recovery.nowUs();
        if (range) |info| {
            var entry = info;
            entry.packet_number = conn.app_pn;
            entry.sent_us = now;
            entry.in_flight = true;

            // An overwritten entry leaves loss tracking, so its bytes leave the
            // in-flight tally with it, or the window would never reopen.
            const evicted = conn.sent_ranges[conn.sent_cursor];
            if (evicted.in_flight) {
                conn.bytes_in_flight -|= evicted.length;
                if (conn.streams.findSend(evicted.stream_id)) |send| send.unacked -|= evicted.length;
            }

            conn.sent_ranges[conn.sent_cursor] = entry;
            conn.sent_cursor = (conn.sent_cursor + 1) % MAX_SENT_RANGES;
            conn.bytes_in_flight += entry.length;
        }

        conn.app_pn += 1;
        conn.last_send_us = now;
        sink.send(sealed);

        return true;
    }

    /// One time-driven pass: retransmit a flight whose probe timeout fired, and
    /// report a peer that has gone away (rfc 9002 6.2, rfc 9000 10.1).
    pub fn maintenance(conn: *Conn, now_us: u64) Maintenance {
        if (conn.closed) return .{ .idle = true };
        if (now_us -| conn.last_activity_us > MAX_IDLE_MS * std.time.us_per_ms) return .{ .idle = true };

        if (conn.bytes_in_flight == 0) return .{};

        const base = recovery.computePto(
            if (conn.rtt.has_sample) conn.rtt.smoothed_rtt else recovery.initial_rtt_us,
            conn.rtt.rttvar,
            recovery.default_max_ack_delay_us,
        );
        if (now_us -| conn.last_send_us < recovery.ptoWithBackoff(base, conn.pto_backoff)) return .{};

        // Nothing has been acknowledged in a probe timeout: rewind every range
        // still in flight so the pump sends it again.
        var rewound = false;
        for (&conn.sent_ranges) |*range| {
            if (!range.in_flight) continue;

            range.in_flight = false;
            conn.bytes_in_flight -|= range.length;
            rewound = true;

            if (conn.streams.findSend(range.stream_id)) |send| {
                send.unacked -|= range.length;
                send.rewind(range.offset);
            }
        }

        if (rewound and conn.pto_backoff < 6) conn.pto_backoff += 1;

        return .{ .resend = rewound };
    }
};

/// Whether an ACK frame covers this packet number.
fn ackCovers(ack: flow.Ack, packet_number: u64) bool {
    for (ack.ranges[0..ack.range_len]) |range| {
        if (packet_number >= range.smallest and packet_number <= range.largest) return true;
    }

    return false;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// Records the datagrams a connection sends, so the send path is testable
/// without a socket.
const Recorder = struct {
    count: usize = 0,
    total: usize = 0,
    last: [2048]u8 = undefined,
    last_len: usize = 0,

    fn sink(recorder: *Recorder) Sink {
        return .{ .ctx = recorder, .sendFn = record };
    }

    fn record(ctx: *anyopaque, datagram: []const u8) void {
        const recorder: *Recorder = @ptrCast(@alignCast(ctx));
        recorder.count += 1;
        recorder.total += datagram.len;

        const copy = @min(datagram.len, recorder.last.len);
        @memcpy(recorder.last[0..copy], datagram[0..copy]);
        recorder.last_len = copy;
    }
};

/// A connection already past its handshake, with keys both sides agree on, so
/// the 1-RTT paths can be driven directly.
const Pair = struct {
    conn: Conn,
    client_keys: keyschedule.AppKeys,
    ctx: zix.Tls.Context,

    fn init(allocator: std.mem.Allocator, io: std.Io) !Pair {
        var ctx = try zix.Tls.Context.init(allocator, io, .{
            .cert_path = "examples/certs/ecdsa_p256_cert.pem",
            .key_path = "examples/certs/ecdsa_p256_key.pem",
        });
        errdefer ctx.deinit();

        var pair = Pair{
            .conn = undefined,
            .client_keys = undefined,
            .ctx = ctx,
        };
        pair.conn = Conn.init(allocator, &pair.ctx, "abcdefgh", try std.Io.net.IpAddress.parse("127.0.0.1", 4433));

        // Both sides share one application key set: this drives the 1-RTT
        // paths without replaying a whole handshake.
        const secret: crypto.Secret = @splat(0x5a);
        pair.conn.app_keys = keyschedule.applicationKeys(secret, @splat(0x17));
        pair.client_keys = pair.conn.app_keys;
        pair.conn.our_scid = demux.ConnId.fromSlice("srvcid00");
        pair.conn.peer_scid = demux.ConnId.fromSlice("clicid00");
        pair.conn.app_ready = true;
        pair.conn.client_max_data = 1 << 20;
        pair.conn.client_max_stream_data = 1 << 20;

        return pair;
    }

    fn deinit(pair: *Pair) void {
        pair.conn.deinit();
        pair.ctx.deinit();
    }

    /// Seal a client 1-RTT packet carrying `payload` and feed it in.
    fn clientPacket(pair: *Pair, packet_number: u32, payload: []const u8, sink: Sink) Progress {
        var out: [2048]u8 = undefined;
        const sealed = protection.sealShort(&out, pair.client_keys.client, pair.conn.our_scid.slice(), packet_number, payload) catch unreachable;

        return pair.conn.onDatagram(sealed, sink);
    }
};

/// Build a STREAM frame with an explicit offset and length.
fn streamFrame(out: []u8, stream_id: u64, offset: u64, data: []const u8, fin: bool) usize {
    out[0] = 0x0e | @as(u8, if (fin) 0x01 else 0x00);
    var pos: usize = 1;
    pos += varint.write(out[pos..], stream_id);
    pos += varint.write(out[pos..], offset);
    pos += varint.write(out[pos..], data.len);
    @memcpy(out[pos..][0..data.len], data);

    return pos + data.len;
}

test "zix zixer: h3 conn, an ack tracker keeps honest ranges" {
    var tracker = AckTracker{};
    tracker.record(0);
    try testing.expectEqual(@as(u64, 0), tracker.largest);
    try testing.expectEqual(@as(u64, 1), tracker.mask);

    tracker.record(2);
    try testing.expectEqual(@as(u64, 2), tracker.largest);
    try testing.expectEqual(@as(u64, 0b101), tracker.mask);

    tracker.record(1);
    try testing.expectEqual(@as(u64, 0b111), tracker.mask);

    // A number far below the window slides out and is simply not acknowledged.
    tracker.record(200);
    try testing.expectEqual(@as(u64, 200), tracker.largest);
    try testing.expectEqual(@as(u64, 1), tracker.mask);
}

test "zix zixer: h3 conn, a request stream arrives and reads back" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pair = try Pair.init(testing.allocator, threaded.io());
    defer pair.deinit();

    var recorder = Recorder{};

    var payload: [64]u8 = undefined;
    const len = streamFrame(&payload, 0, 0, "request-bytes", true);

    const progress = pair.clientPacket(0, payload[0..len], recorder.sink());
    try testing.expectEqual(@as(usize, 1), progress.ready_len);
    try testing.expectEqual(@as(u64, 0), progress.slice()[0]);
    try testing.expectEqualStrings("request-bytes", pair.conn.readable(0));
    try testing.expect(pair.conn.requestEnded(0));
}

test "zix zixer: h3 conn, out of order stream frames reassemble" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pair = try Pair.init(testing.allocator, threaded.io());
    defer pair.deinit();

    var recorder = Recorder{};

    var tail: [64]u8 = undefined;
    const tail_len = streamFrame(&tail, 0, 5, "-tail", true);
    _ = pair.clientPacket(0, tail[0..tail_len], recorder.sink());
    try testing.expectEqual(@as(usize, 0), pair.conn.readable(0).len);
    try testing.expect(!pair.conn.requestEnded(0));

    var head: [64]u8 = undefined;
    const head_len = streamFrame(&head, 0, 0, "head5", false);
    _ = pair.clientPacket(1, head[0..head_len], recorder.sink());

    try testing.expectEqualStrings("head5-tail", pair.conn.readable(0));
    try testing.expect(pair.conn.requestEnded(0));
}

test "zix zixer: h3 conn, a response leaves as sealed packets" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pair = try Pair.init(testing.allocator, threaded.io());
    defer pair.deinit();

    var recorder = Recorder{};

    var payload: [64]u8 = undefined;
    const len = streamFrame(&payload, 0, 0, "req", true);
    _ = pair.clientPacket(0, payload[0..len], recorder.sink());

    try pair.conn.respond(0, "response-body");
    pair.conn.finishResponse(0);
    pair.conn.pump(recorder.sink());

    try testing.expect(recorder.count >= 1);
    try testing.expect(pair.conn.streams.findSend(0).?.fullySent());
    try testing.expectEqual(@as(u64, 13), pair.conn.streams.findSend(0).?.sent);
}

test "zix zixer: h3 conn, a large response spans packets and paces on the window" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pair = try Pair.init(testing.allocator, threaded.io());
    defer pair.deinit();

    var recorder = Recorder{};

    var big: [40 * 1024]u8 = @splat('x');
    try pair.conn.respond(0, &big);
    pair.conn.finishResponse(0);
    pair.conn.pump(recorder.sink());

    const send = pair.conn.streams.findSend(0).?;
    try testing.expect(recorder.count > 1);
    try testing.expect(send.sent > 0);

    // The first round is bounded by the initial congestion window, not by the
    // body size, so the rest waits for acknowledgments.
    try testing.expect(send.sent < big.len);
    try testing.expect(pair.conn.bytes_in_flight > 0);
}

test "zix zixer: h3 conn, an acknowledgment frees the window and the buffer" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pair = try Pair.init(testing.allocator, threaded.io());
    defer pair.deinit();

    var recorder = Recorder{};

    var big: [40 * 1024]u8 = @splat('y');
    try pair.conn.respond(0, &big);
    pair.conn.finishResponse(0);
    pair.conn.pump(recorder.sink());

    const in_flight_before = pair.conn.bytes_in_flight;
    const sent_before = pair.conn.streams.findSend(0).?.sent;
    try testing.expect(in_flight_before > 0);

    // Acknowledge every packet sent so far.
    var ack_payload: [32]u8 = undefined;
    const ack_len = wire.buildAck(&ack_payload, pair.conn.app_pn - 1);
    _ = pair.clientPacket(1, ack_payload[0..ack_len], recorder.sink());

    try testing.expectEqual(@as(u64, 0), pair.conn.bytes_in_flight);
    try testing.expect(pair.conn.streams.findSend(0).?.base >= sent_before);

    // With the window free the pump continues where it stopped.
    pair.conn.pump(recorder.sink());
    try testing.expect(pair.conn.streams.findSend(0).?.sent > sent_before);
}

test "zix zixer: h3 conn, a probe timeout rewinds the unacknowledged flight" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pair = try Pair.init(testing.allocator, threaded.io());
    defer pair.deinit();

    var recorder = Recorder{};

    try pair.conn.respond(0, "needs-a-resend");
    pair.conn.finishResponse(0);
    pair.conn.pump(recorder.sink());

    const sent = pair.conn.streams.findSend(0).?.sent;
    try testing.expect(sent > 0);
    try testing.expect(pair.conn.bytes_in_flight > 0);

    // Past the probe timeout but well inside the idle limit.
    const result = pair.conn.maintenance(pair.conn.last_send_us + 2 * std.time.us_per_s);
    try testing.expect(result.resend);
    try testing.expect(!result.idle);
    try testing.expectEqual(@as(u64, 0), pair.conn.streams.findSend(0).?.sent);
    try testing.expectEqual(@as(u64, 0), pair.conn.bytes_in_flight);

    const before = recorder.count;
    pair.conn.pump(recorder.sink());
    try testing.expect(recorder.count > before);
    try testing.expectEqual(sent, pair.conn.streams.findSend(0).?.sent);
}

test "zix zixer: h3 conn, a silent peer goes idle and a close ends it" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pair = try Pair.init(testing.allocator, threaded.io());
    defer pair.deinit();

    try testing.expect(!pair.conn.maintenance(pair.conn.last_activity_us + 1000).idle);
    try testing.expect(pair.conn.maintenance(pair.conn.last_activity_us + (MAX_IDLE_MS + 1) * std.time.us_per_ms).idle);

    var recorder = Recorder{};
    const close_frame = [_]u8{ 0x1c, 0x00, 0x00, 0x00 };
    const progress = pair.clientPacket(0, &close_frame, recorder.sink());

    try testing.expect(progress.peer_closed);
    try testing.expect(pair.conn.closed);
    try testing.expect(pair.conn.maintenance(recovery.nowUs()).idle);
}

test "zix zixer: h3 conn, receive credit is replenished before the client runs out" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pair = try Pair.init(testing.allocator, threaded.io());
    defer pair.deinit();

    var recorder = Recorder{};

    // One stream frame past half the connection window queues a MAX_DATA.
    const bulk = try testing.allocator.alloc(u8, 700 * 1024);
    defer testing.allocator.free(bulk);
    @memset(bulk, 'z');

    var frame_buf = try testing.allocator.alloc(u8, bulk.len + 32);
    defer testing.allocator.free(frame_buf);
    const len = streamFrame(frame_buf, 0, 0, bulk, false);

    // The packet is larger than one datagram, so feed the frame directly.
    var progress = Progress{};
    pair.conn.applyFrames(frame_buf[0..len], &progress);

    try testing.expect(pair.conn.max_data_pending != null);
    try testing.expect(pair.conn.max_data_pending.? > DATA_WINDOW);
    try testing.expect(pair.conn.max_stream_data_pending != null);

    // The grant rides the next packet out and clears.
    pair.conn.pump(recorder.sink());
    try testing.expect(pair.conn.max_data_pending == null);
    try testing.expect(pair.conn.max_stream_data_pending == null);
}

test "zix zixer: h3 conn, a reset stream drops its buffers" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pair = try Pair.init(testing.allocator, threaded.io());
    defer pair.deinit();

    var recorder = Recorder{};

    var payload: [64]u8 = undefined;
    const len = streamFrame(&payload, 0, 0, "abandoned", false);
    _ = pair.clientPacket(0, payload[0..len], recorder.sink());
    try testing.expect(pair.conn.streams.findRecv(0) != null);

    // RESET_STREAM: id 0, error 0, final size 9.
    const reset = [_]u8{ 0x04, 0x00, 0x00, 0x09 };
    _ = pair.clientPacket(1, &reset, recorder.sink());

    try testing.expect(pair.conn.streams.findRecv(0) == null);
}

test "zix zixer: h3 conn, the client stream limit rides in from the handshake" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    var pair = try Pair.init(testing.allocator, threaded.io());
    defer pair.deinit();

    var recorder = Recorder{};

    pair.conn.client_max_stream_data = 4;
    try pair.conn.respond(0, "0123456789");
    pair.conn.finishResponse(0);
    pair.conn.pump(recorder.sink());

    // Only the credited prefix goes out.
    try testing.expectEqual(@as(u64, 4), pair.conn.streams.findSend(0).?.sent);

    // MAX_STREAM_DATA: stream 0, new limit 10.
    const grant = [_]u8{ 0x11, 0x00, 0x0a };
    _ = pair.clientPacket(0, &grant, recorder.sink());
    pair.conn.pump(recorder.sink());

    try testing.expectEqual(@as(u64, 10), pair.conn.streams.findSend(0).?.sent);
}
