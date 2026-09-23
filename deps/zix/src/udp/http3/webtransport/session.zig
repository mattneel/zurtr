//! zix WebTransport session and stream state (draft-ietf-webtrans-http3-16 3.2 / 4 / 5 / 6).
//!
//! What:
//! - One session per accepted extended CONNECT: its state, its close information, and the stream list
//!   it owns. A session lives until its CONNECT stream closes, a WT_CLOSE_SESSION capsule is sent or
//!   received, or the QUIC connection goes away (6).
//! - The two halves of a WebTransport data stream and what each tracks: the send half owns the bytes
//!   the application wrote until the peer acknowledges them (so a loss can be resent) plus the FIN and
//!   the reset, and the receive half owns what arrived, the FIN, and the reset.
//! - Session-level flow control (5): the stream and data limits a peer may consume, the limits the peer
//!   granted, the monotonic rules capsules must follow, and when an endpoint owes the peer a new limit.
//! - Pure state machines over caller-owned buffers: no io, no allocation, no clock. The worker pool
//!   (pool.zig) allocates the slots and the dispatch layer drives these transitions.
//!
//! Note:
//! - The data limit counts Stream Body bytes only: the stream header (type or signal plus session id)
//!   is excluded on both sides (5.4), which is why the engine hands payload lengths here and never
//!   framed lengths.
//! - Two dialects are live: draft-16 sessions have session-level flow control, draft-07 sessions do
//!   not (there the only limits are QUIC's own). Every rule that only exists in draft-16 is gated on
//!   the session's dialect.

const std = @import("std");

const varint = @import("../varint.zig");
const draft = @import("draft.zig");
const capsule = @import("capsule.zig");
const stream_header = @import("stream_header.zig");

/// Which endpoint opened a stream (RFC 9000 2.1).
pub const Role = enum { client, server };

/// The session lifecycle (6).
pub const State = enum {
    /// The CONNECT was accepted and its 2xx response sent: data streams and datagrams may flow.
    open,
    /// A WT_DRAIN_SESSION capsule was sent or received (4.7). The session still works: the signal is
    /// advice to the application, and new streams and datagrams may still be exchanged.
    draining,
    /// The session is over: its streams are being reset with WT_SESSION_GONE and no new ones may open.
    closed,
};

/// Why a session ended, so the application can tell a clean close from a failure (6).
pub const CloseReason = enum {
    /// The peer closed the CONNECT stream cleanly, which is equivalent to a close capsule with code 0.
    peer_fin,
    /// The peer reset the CONNECT stream.
    peer_reset,
    /// The peer sent a WT_CLOSE_SESSION capsule.
    peer_close,
    /// The application called close.
    local_close,
    /// A session-level flow control rule was broken: WT_FLOW_CONTROL_ERROR.
    flow_control_error,
    /// A capsule was malformed: the CONNECT stream is reset with H3_MESSAGE_ERROR.
    protocol_error,
    /// The QUIC connection ended under the session.
    connection_closed,
};

/// What a session reports when it ends.
pub const CloseInfo = struct {
    /// The application error code, zero for a clean close (6).
    code: u32 = 0,
    /// The application message, empty when the peer sent none. Borrows the session's own buffer, so it
    /// stays valid while the session slot is alive.
    message: []const u8 = "",
    /// Why the session ended.
    reason: CloseReason = .peer_fin,
};

/// Errors a session transition raises. Each maps to the HTTP/3 code the engine sends.
pub const SessionError = error{
    /// A session-level flow control rule was broken: close with WT_FLOW_CONTROL_ERROR (5.6.2 / 5.6.4).
    ZixFlowControlError,
    /// The session is closed: nothing more may open or be sent on it (6).
    ZixSessionClosed,
    /// The peer's limit for this stream kind is exhausted: report WT_STREAMS_BLOCKED (5.6.3) and do not
    /// open the stream.
    ZixStreamLimit,
    /// There is no room for the stream in the worker pool.
    ZixStreamPoolFull,
};

// --------------------------------------------------------------- //
// A stream's send half
// --------------------------------------------------------------- //

/// A pending reset of the send half: the application error code and the offset that must still be
/// delivered (4.4: a reliable reset).
pub const Reset = struct {
    /// The application error code, remapped into WT_APPLICATION_ERROR on the wire.
    code: u32,
    /// The offset the receiver must receive reliably: at least the stream header, so the receiver can
    /// still tell which session the stream belonged to.
    reliable_size: u64,
    /// Whether the RESET_STREAM_AT has been queued to the peer.
    sent: bool = false,
};

/// One sent range a data stream is still waiting on.
pub const OutstandingRange = struct { offset: u64 = 0, len: u64 = 0 };

/// The most sent ranges one data stream accounts for at once. A range is one packet's worth of stream
/// bytes, and contiguous sends merge, so a steady stream waits on a handful. The pump stops sending on a
/// stream whose list is full (see `Stream.sendable`), which is what keeps the bound a fact rather than a
/// hope: a stream whose acknowledgement never arrives stops filling the buffer instead of losing track of
/// what the peer has.
pub const max_outstanding_ranges: usize = 32;

/// The largest send buffer a stream slot may use. A stream frees its buffer only up to the lowest
/// outstanding range, so a buffer larger than the range list can describe would hold bytes the endpoint
/// could never prove acknowledged.
pub const max_stream_buffer_bytes: usize = 16 * 1024;

/// The sending half of a WebTransport data stream.
pub const SendSide = struct {
    /// Whether the application may still write.
    open: bool = false,
    /// The application finished writing: FIN once the queued bytes are sent.
    fin: bool = false,
    /// Whether the stream header went out. The header is stream offset 0, so it is part of the byte
    /// accounting below rather than a separate queue.
    header_sent: bool = false,
    /// The stream offset below which every byte is acknowledged. The buffer holds the bytes from here on.
    acked: u64 = 0,
    /// Bytes queued in the buffer from `acked` onward that the peer has not acknowledged (whether sent or
    /// still waiting for room).
    queued: u64 = 0,
    /// The highest offset handed to the packet pump. A loss rewinds this, which is why it is not the same
    /// as `high_water`.
    sent: u64 = 0,
    /// The highest offset ever reached: the distinct stream offset the session data limit is charged for
    /// (5.4).
    high_water: u64 = 0,
    /// The peer's per-stream limit (QUIC, raised by MAX_STREAM_DATA).
    limit: u64 = 0,
    /// A pending reliable reset, or null.
    reset: ?Reset = null,
    /// Sent ranges still awaiting acknowledgement, in stream order, so the lowest entry is always the
    /// oldest byte the peer has not confirmed.
    outstanding: [max_outstanding_ranges]OutstandingRange = @splat(.{}),
    /// Entries of `outstanding` in use.
    outstanding_len: u8 = 0,

    /// Bytes sent and not yet acknowledged.
    pub fn unacked(self: *const SendSide) u64 {
        var total: u64 = 0;
        for (self.outstanding[0..self.outstanding_len]) |range| total += range.len;

        return total;
    }

    /// Whether another range may be handed to the pump.
    pub fn rangeRoom(self: *const SendSide) bool {
        return self.outstanding_len < self.outstanding.len;
    }

    /// Note a range handed to the pump. A range contiguous with the previous one merges into it, so a
    /// steady stream waits on one entry however many packets it took.
    pub fn noteSent(self: *SendSide, offset: u64, len: u64) void {
        if (len == 0) return;

        if (self.outstanding_len != 0) {
            const last = &self.outstanding[self.outstanding_len - 1];
            if (last.offset + last.len == offset) {
                last.len += len;

                return;
            }
        }

        // The pump checks `rangeRoom` before it sends, so a full list is not reachable from there.
        if (self.outstanding_len == self.outstanding.len) return;

        self.outstanding[self.outstanding_len] = .{ .offset = offset, .len = len };
        self.outstanding_len += 1;
    }

    /// Note that the peer acknowledged `[offset, offset + len)`: drop every outstanding range the
    /// acknowledgement covers, trim the head of one it only partly covers, and return how many bytes are
    /// now free at the front of the buffer.
    ///
    /// Note:
    /// - Ranges merge on send (`noteSent` folds a contiguous send into the previous entry), while an
    ///   acknowledgement arrives per packet, so a merged range is almost never covered whole: without the
    ///   head trim below a stream whose bytes are all acknowledged would still report nothing freed, fill
    ///   its buffer, and stall with data the peer confirmed long ago.
    /// - An acknowledgement of a range's middle leaves it outstanding, which can only postpone a free,
    ///   never free a byte the peer has not confirmed.
    pub fn noteAcked(self: *SendSide, offset: u64, len: u64) u64 {
        const end = offset + len;
        var index: u8 = 0;
        while (index < self.outstanding_len) {
            const range = &self.outstanding[index];
            const range_end = range.offset + range.len;

            if (range.offset >= offset and range_end <= end) {
                var move = index;
                while (move + 1 < self.outstanding_len) : (move += 1) self.outstanding[move] = self.outstanding[move + 1];
                self.outstanding_len -= 1;
                self.outstanding[self.outstanding_len] = .{};
                continue;
            }

            // The acknowledgement reaches into this range from the front: keep only the unconfirmed tail.
            if (range.offset < end and range_end > end) {
                range.len = range_end - end;
                range.offset = end;
            }

            index += 1;
        }

        return self.advanceAcked();
    }

    /// Free the confirmed prefix: with every range below the lowest outstanding one acknowledged, that
    /// offset is where the buffer may start.
    fn advanceAcked(self: *SendSide) u64 {
        const lowest = if (self.outstanding_len == 0) self.high_water else self.outstanding[0].offset;
        if (lowest <= self.acked) return 0;

        const advance = @min(lowest, self.acked + self.queued) - self.acked;
        self.acked += advance;
        self.queued -= advance;

        return advance;
    }
};

// --------------------------------------------------------------- //
// A stream's receive half
// --------------------------------------------------------------- //

/// The receiving half of a WebTransport data stream.
pub const RecvSide = struct {
    /// The peer ended the stream cleanly.
    fin: bool = false,
    /// The highest offset plus length received so far.
    received: u64 = 0,
    /// The limit this endpoint advertised for the stream (QUIC level).
    limit: u64 = 0,
    /// The peer reset the stream, with this HTTP/3 error code (4.4).
    reset_code: ?u64 = null,
    /// The peer's final size for a reset stream, which is what the session data limit charges (5.4).
    final_size: u64 = 0,
    /// Whether this endpoint asked the peer to stop sending (STOP_SENDING).
    stopped: bool = false,
};

// --------------------------------------------------------------- //
// A stream
// --------------------------------------------------------------- //

/// One WebTransport data stream: its identity, its two halves, and the bytes it still owes the peer.
pub const Stream = struct {
    /// The QUIC stream id.
    id: u64 = 0,
    /// The session (CONNECT stream id) this stream belongs to.
    session_id: u64 = 0,
    /// Unidirectional or bidirectional (4.2 / 4.3).
    kind: stream_header.Kind = .bidi,
    /// Which endpoint opened it. A client-opened stream is delivered to the application; a server-opened
    /// one is created by `Session.openStream`.
    initiator: Role = .client,
    /// The send half (ours).
    send: SendSide = .{},
    /// The receive half (the peer's).
    recv: RecvSide = .{},
    /// The send buffer: `queued` bytes starting at stream offset `acked`. Pool-owned.
    buf: []u8 = &.{},
    /// The engine hooks, installed when the stream was opened or delivered, so an application that holds
    /// a stream handle can ask the engine to reset or stop it.
    driver: ?*const Driver = null,
    /// The next stream of this session (an intrusive list, so the pool needs no per-session array).
    next: ?*Stream = null,

    /// Bytes the stream still has to deliver before it is fully sent: the header, everything queued, and
    /// the FIN.
    pub fn totalBytes(self: *const Stream) u64 {
        if (self.send.reset) |reset| {
            // A reset stream delivers up to its reliable size and then stops.
            return @max(reset.reliable_size, self.send.acked);
        }

        return self.send.acked + self.send.queued;
    }

    /// Whether the send half is finished: every queued byte sent and acknowledged and the FIN delivered,
    /// or a reset acknowledged. The pool slot can then be released.
    pub fn sendFinished(self: *const Stream) bool {
        if (self.send.reset) |reset| return reset.sent and self.send.unacked() == 0;
        if (!self.send.fin) return false;

        return self.send.queued == 0 and self.send.outstanding_len == 0;
    }

    /// Whether the receive half is finished, so nothing more can arrive on the stream.
    pub fn recvFinished(self: *const Stream) bool {
        if (self.recv.reset_code != null) return true;

        return self.recv.fin and self.recv.received == self.recv.final_size;
    }

    /// Whether the whole stream is done and its slot may be recycled.
    pub fn finished(self: *const Stream) bool {
        return self.sendFinished() and (self.recvFinished() or self.recv.stopped);
    }

    // ------------------------------------------------------------- //
    // Send half
    // ------------------------------------------------------------- //

    /// The bytes the application may write right now: the free room in the send buffer.
    ///
    /// Note:
    /// - Zero is normal back pressure, not an error: the application retries from its next event once
    ///   the peer acknowledges what is already queued.
    pub fn writable(self: *const Stream) usize {
        if (!self.send.open or self.send.fin) return 0;

        // The header is charged to the buffer as its first bytes, so `queued` counts it.
        const used = self.send.queued;
        if (used >= self.buf.len) return 0;

        return self.buf.len - @as(usize, @intCast(used));
    }

    /// Copy application bytes into the send buffer, returning how many were accepted. A partial accept
    /// is normal: the caller writes the rest once the buffer drains.
    pub fn write(self: *Stream, bytes: []const u8) usize {
        const room = self.writable();
        const take = @min(room, bytes.len);
        if (take == 0) return 0;

        // The buffer is linear: acknowledgement compacts the queued region to the front, so a write
        // always lands right after it and can never wrap.
        const end = @as(usize, @intCast(self.send.queued));
        @memcpy(self.buf[end..][0..take], bytes[0..take]);
        self.send.queued += take;

        return take;
    }

    /// Queue the stream header at offset 0. Called once, by whoever opens the stream.
    pub fn openWithHeader(self: *Stream, header: []const u8) void {
        self.send.open = true;
        @memcpy(self.buf[0..header.len], header);
        self.send.queued = header.len;
    }

    /// The bytes ready to go on the wire: the queued window from `sent` onward, bounded by the peer's
    /// per-stream limit and by the outstanding-range list (a stream waits for an acknowledgement once it
    /// has as many unconfirmed ranges as it can account for).
    pub fn sendable(self: *const Stream) usize {
        if (!self.send.rangeRoom()) return 0;

        const end = self.send.acked + self.send.queued;
        if (self.send.sent >= end) return 0;

        const limit = @min(end, self.send.limit);
        if (self.send.sent >= limit) return 0;

        return @intCast(limit - self.send.sent);
    }

    /// Whether the FIN goes with the next send: everything queued is sent and the application finished.
    pub fn finPending(self: *const Stream) bool {
        if (!self.send.fin) return false;

        return self.send.sent == self.send.acked + self.send.queued;
    }

    /// Note `count` bytes handed to the packet pump, starting at the stream's current sent offset.
    pub fn onSent(self: *Stream, count: u64) void {
        self.send.noteSent(self.send.sent, count);
        self.send.sent += count;
        if (self.send.sent > self.send.high_water) self.send.high_water = self.send.sent;
    }

    /// Note an acknowledged range, then compact the buffer so the confirmed prefix is reusable. The range
    /// comes from the connection's sent-packet bookkeeping, which knows which packet carried it.
    pub fn onAcked(self: *Stream, offset: u64, len: u64) void {
        const freed = self.send.noteAcked(offset, len);

        // Drop the confirmed prefix, so a long-lived stream reuses one fixed buffer.
        const rest: usize = @intCast(self.send.queued);
        if (freed != 0 and rest != 0) std.mem.copyForwards(u8, self.buf[0..rest], self.buf[@intCast(freed)..][0..rest]);
    }

    /// Rewind `sent` to `offset` after a loss was reported for that range, so the pump resends it. The
    /// range stays outstanding: a lost range is still one the peer has not acknowledged.
    pub fn onLost(self: *Stream, offset: u64) void {
        if (offset < self.send.sent) self.send.sent = offset;
    }

    /// Ask for a reliable reset of the send half (4.4). `reliable_size` must cover the header.
    pub fn resetSend(self: *Stream, code: u32) void {
        const header = stream_header.reliableResetSize(self.kind, self.session_id);
        self.send.reset = .{ .code = code, .reliable_size = @max(header, self.send.acked + self.send.queued) };
    }

    /// Note the peer's new per-stream limit (QUIC MAX_STREAM_DATA).
    pub fn onStreamLimit(self: *Stream, limit: u64) void {
        if (limit > self.send.limit) self.send.limit = limit;
    }

    // ------------------------------------------------------------- //
    // Receive half
    // ------------------------------------------------------------- //

    /// Whether this endpoint owes the peer more stream credit: the receive window is more than half
    /// consumed. Returns the new limit to advertise with MAX_STREAM_DATA (RFC 9000 4.1), or null.
    ///
    /// Note:
    /// - A WebTransport data stream has no reassembly slot, so nothing else in the engine replenishes
    ///   its credit: without this a stream stalls at the handshake's one-time per-stream allowance.
    pub fn replenish(self: *Stream, window: u64) ?u64 {
        if (window == 0) return null;
        if (self.recv.limit -| self.recv.received > window - window / 2) return null;

        self.recv.limit = self.recv.received + window;

        return self.recv.limit;
    }

    /// Note bytes received on the stream, and whether the peer ended it.
    pub fn onReceived(self: *Stream, offset: u64, len: usize, fin: bool) void {
        const end = offset + len;
        if (end > self.recv.received) self.recv.received = end;
        if (end > self.recv.final_size) self.recv.final_size = end;
        if (fin) self.recv.fin = true;
    }

    /// Note that the peer reset the stream. `final_size` is the Final Size field of the reset frame,
    /// which is what the session data limit charges (5.4).
    pub fn onResetReceived(self: *Stream, code: u64, final_size: u64) void {
        self.recv.reset_code = code;
        if (final_size > self.recv.final_size) self.recv.final_size = final_size;
        self.recv.fin = true;
    }
};

// --------------------------------------------------------------- //
// Session-level flow control (5)
// --------------------------------------------------------------- //

/// The session-level flow control state of one session (5.3 to 5.6).
///
/// Note:
/// - The limits are hop-by-hop: this endpoint enforces its own advertised limits on what the peer may
///   send, and honours the peer's advertised limits on what it may send (5.6.1).
pub const FlowControl = struct {
    /// Whether both endpoints enabled flow control (5.1). False means no session limits apply and any
    /// flow control capsule is ignored.
    enabled: bool = false,
    /// Whether this endpoint declared intent (a non-zero initial limit of its own).
    local_declared: bool = false,
    /// Whether the peer declared intent.
    peer_declared: bool = false,

    /// What this endpoint advertised: the peer's allowance.
    local_max_data: u64 = 0,
    local_max_streams_bidi: u64 = 0,
    local_max_streams_uni: u64 = 0,
    /// What the peer advertised: this endpoint's allowance.
    peer_max_data: u64 = 0,
    peer_max_streams_bidi: u64 = 0,
    peer_max_streams_uni: u64 = 0,

    /// Consumed against the local limits.
    data_received: u64 = 0,
    streams_bidi_received: u64 = 0,
    streams_uni_received: u64 = 0,
    /// Sent against the peer's limits.
    data_sent: u64 = 0,
    streams_bidi_opened: u64 = 0,
    streams_uni_opened: u64 = 0,

    /// The last limit this endpoint put on the wire, so a capsule is only sent when the limit grows.
    advertised_max_data: u64 = 0,
    advertised_streams_bidi: u64 = 0,
    advertised_streams_uni: u64 = 0,
    /// The last limit the peer put on the wire, for the monotonic rule (5.6.2 / 5.6.4).
    received_max_data: u64 = 0,
    received_streams_bidi: u64 = 0,
    received_streams_uni: u64 = 0,

    /// Record this endpoint's initial limits, from its SETTINGS (`SETTINGS_WT_INITIAL_MAX_*`, 5.5).
    pub fn declareLocal(self: *FlowControl, max_data: u64, streams_bidi: u64, streams_uni: u64) void {
        self.local_max_data = max_data;
        self.local_max_streams_bidi = streams_bidi;
        self.local_max_streams_uni = streams_uni;
        self.local_declared = max_data != 0 or streams_bidi != 0 or streams_uni != 0;
        self.updateEnabled();
    }

    /// Record the peer's initial limits, from its SETTINGS (5.5).
    pub fn declarePeer(self: *FlowControl, max_data: u64, streams_bidi: u64, streams_uni: u64) void {
        self.peer_max_data = max_data;
        self.peer_max_streams_bidi = streams_bidi;
        self.peer_max_streams_uni = streams_uni;
        self.peer_declared = max_data != 0 or streams_bidi != 0 or streams_uni != 0;
        self.updateEnabled();
    }

    fn updateEnabled(self: *FlowControl) void {
        self.enabled = self.local_declared and self.peer_declared;
    }

    /// Charge Stream Body bytes the peer sent on this session (5.4). Past the advertised limit is
    /// WT_FLOW_CONTROL_ERROR.
    pub fn onSessionData(self: *FlowControl, len: u64) SessionError!void {
        if (!self.enabled) return;

        const next = self.data_received + len;
        if (next > self.local_max_data) return error.ZixFlowControlError;
        self.data_received = next;
    }

    /// Charge the final size of a stream that was reset: the limit counts the bytes the sender charged
    /// even when the receiver never saw them (5.4).
    pub fn onResetFinalSize(self: *FlowControl, final_size: u64) SessionError!void {
        if (!self.enabled) return;
        if (final_size > self.local_max_data) return error.ZixFlowControlError;
        if (final_size > self.data_received) self.data_received = final_size;
    }

    /// Charge one incoming stream of `kind` against the advertised stream limit (5.6.2). Past it is
    /// WT_FLOW_CONTROL_ERROR.
    pub fn onStreamOpened(self: *FlowControl, kind: stream_header.Kind) SessionError!void {
        if (!self.enabled) return;

        switch (kind) {
            .bidi => {
                const next = self.streams_bidi_received + 1;
                if (next > self.local_max_streams_bidi) return error.ZixFlowControlError;
                self.streams_bidi_received = next;
            },
            .uni => {
                const next = self.streams_uni_received + 1;
                if (next > self.local_max_streams_uni) return error.ZixFlowControlError;
                self.streams_uni_received = next;
            },
        }
    }

    /// Whether this endpoint may open another stream of `kind` within the peer's limit (5.3).
    pub fn canOpen(self: *const FlowControl, kind: stream_header.Kind) bool {
        if (!self.enabled) return true;

        return switch (kind) {
            .bidi => self.streams_bidi_opened < self.peer_max_streams_bidi,
            .uni => self.streams_uni_opened < self.peer_max_streams_uni,
        };
    }

    /// Note that this endpoint opened a stream of `kind`.
    pub fn onOpenedStream(self: *FlowControl, kind: stream_header.Kind) void {
        switch (kind) {
            .bidi => self.streams_bidi_opened += 1,
            .uni => self.streams_uni_opened += 1,
        }
    }

    /// Whether this endpoint may send `len` more Stream Body bytes within the peer's data limit (5.4).
    pub fn canSendData(self: *const FlowControl, len: u64) bool {
        if (!self.enabled) return true;

        return self.data_sent + len <= self.peer_max_data;
    }

    /// Note Stream Body bytes sent on this session.
    pub fn onDataSent(self: *FlowControl, len: u64) void {
        self.data_sent += len;
    }

    /// Apply a WT_MAX_DATA capsule (5.6.4). The value must strictly increase, or the session fails with
    /// WT_FLOW_CONTROL_ERROR.
    pub fn onMaxData(self: *FlowControl, value: u64) SessionError!void {
        if (!self.enabled) return;
        if (value <= self.received_max_data) return error.ZixFlowControlError;

        self.received_max_data = value;
        self.peer_max_data = value;
    }

    /// Apply a WT_MAX_STREAMS capsule (5.6.2). The value must strictly increase, and it cannot exceed
    /// what a stream id can express.
    pub fn onMaxStreams(self: *FlowControl, kind: stream_header.Kind, value: u64) SessionError!void {
        if (!self.enabled) return;
        if (value > draft.max_stream_count) return error.ZixFlowControlError;

        switch (kind) {
            .bidi => {
                if (value <= self.received_streams_bidi) return error.ZixFlowControlError;
                self.received_streams_bidi = value;
                self.peer_max_streams_bidi = value;
            },
            .uni => {
                if (value <= self.received_streams_uni) return error.ZixFlowControlError;
                self.received_streams_uni = value;
                self.peer_max_streams_uni = value;
            },
        }
    }

    /// The WT_MAX_DATA value this endpoint owes the peer, or null when the limit does not need raising.
    /// The caller extends the local limit to `data_received + window` and sends the capsule (5.6.4).
    pub fn dueMaxData(self: *FlowControl, window: u64) ?u64 {
        if (!self.enabled or window == 0) return null;

        const target = self.data_received + window;
        if (target <= self.local_max_data or target <= self.advertised_max_data) return null;

        self.local_max_data = target;
        self.advertised_max_data = target;

        return target;
    }

    /// The WT_MAX_STREAMS value this endpoint owes the peer for `kind`, or null. The caller extends its
    /// local limit by `window` streams and sends the capsule (5.6.2).
    pub fn dueMaxStreams(self: *FlowControl, kind: stream_header.Kind, window: u64) ?u64 {
        if (!self.enabled or window == 0) return null;

        switch (kind) {
            .bidi => {
                const target = self.streams_bidi_received + window;
                if (target <= self.local_max_streams_bidi or target <= self.advertised_streams_bidi) return null;

                self.local_max_streams_bidi = target;
                self.advertised_streams_bidi = target;

                return target;
            },
            .uni => {
                const target = self.streams_uni_received + window;
                if (target <= self.local_max_streams_uni or target <= self.advertised_streams_uni) return null;

                self.local_max_streams_uni = target;
                self.advertised_streams_uni = target;

                return target;
            },
        }
    }
};

// --------------------------------------------------------------- //
// Driver interface
// --------------------------------------------------------------- //

/// The engine hooks a session's application-facing operations call into.
///
/// What:
/// - The state machines in this file know nothing about packets, sockets, or the worker pool. When an
///   application asks for something that needs the wire (opening a stream, sending a datagram, closing
///   the session), the call is handed to the engine through this vtable.
/// - The dispatch layer (src/udp/http3/dispatch/common.zig) implements every hook against the current
///   datagram's send batch, and installs the driver on a session only for the duration of the callbacks
///   it is servicing. `context` is that call's own state, so a session never holds a stale packet path.
///
/// Note:
/// - `open_stream` returns the stream on success and null when nothing can be opened (no pool slot, or
///   the peer's stream limit is reached). The caller has already checked the session state and the
///   session-level flow control, so a refusal here is a resource limit, not a protocol error.
/// - `send_capsule` carries a whole encoded capsule value: the engine frames it on the CONNECT stream.
pub const Driver = struct {
    /// The engine's per-call context, opaque to this file.
    context: *anyopaque,
    /// Open a server-initiated data stream of `kind` for `session`, queueing its header.
    open_stream: *const fn (context: *anyopaque, session: *Session, kind: stream_header.Kind) ?*Stream,
    /// Queue one WebTransport payload as an HTTP/3 datagram on the session. False when it cannot be
    /// sent now (datagrams not negotiated, or the congestion window has no room): the caller drops it,
    /// since a datagram is unreliable by definition.
    send_datagram: *const fn (context: *anyopaque, session: *Session, payload: []const u8) bool,
    /// Queue a WT_CLOSE_SESSION (or draft-07 CLOSE_WEBTRANSPORT_SESSION) capsule and finish the CONNECT
    /// stream, which is what ends the session for the peer (6).
    close_session: *const fn (context: *anyopaque, session: *Session) void,
    /// Queue a WT_DRAIN_SESSION capsule (4.7).
    drain_session: *const fn (context: *anyopaque, session: *Session) void,
    /// Queue a STOP_SENDING for a stream the application no longer wants to read (4.4).
    stop_receiving: *const fn (context: *anyopaque, stream: *Stream, code: u32) void,
    /// Queue the reset of a stream's send half: RESET_STREAM_AT on a draft-16 session (so the header is
    /// still delivered, 4.4), plain RESET_STREAM on a draft-07 one.
    reset_stream: *const fn (context: *anyopaque, stream: *Stream) void,
};

// --------------------------------------------------------------- //
// Session
// --------------------------------------------------------------- //

/// The bytes one CONNECT stream's send side holds: the 2xx response head, a close capsule (4 + the
/// 1024-byte message limit), a drain capsule, and room for the flow control capsules a busy session
/// sends between them. One buffer, because every capsule this endpoint sends is small and a close is
/// final.
pub const connect_out_bytes: usize = 2048;

/// One WebTransport session: an accepted extended CONNECT and everything multiplexed on it.
pub const Session = struct {
    /// The session id: the CONNECT stream id (3.2).
    id: u64 = 0,
    /// Which revision of the binding this session speaks, from the CONNECT `:protocol` token.
    dialect: draft.Dialect = .draft16,
    /// Lifecycle state (6).
    state: State = .open,
    /// Session-level flow control (5).
    flow: FlowControl = .{},
    /// The capsule reader for the CONNECT stream body.
    capsules: capsule.Reader = .{},
    /// The CONNECT stream's send side: the 2xx response head, then every capsule this endpoint sends,
    /// then the FIN that ends the session (6). It is a `Stream` so the packet pump, the flow control
    /// accounting, and loss recovery treat a lost capsule like any other lost byte.
    connect: Stream = .{},
    /// Backing store for `connect.buf`, so a session carries its CONNECT stream without allocating.
    connect_buf: [connect_out_bytes]u8 = undefined,
    /// The session's data streams, newest first (pool-allocated).
    streams: ?*Stream = null,
    /// When ended, why and with which application code.
    close: CloseInfo = .{},
    /// Backing store for `close.message`.
    close_message: [draft.max_close_message]u8 = undefined,
    /// The engine hooks for this session's application-facing operations. Installed by the dispatch
    /// layer around each callback and cleared afterwards, so it never outlives the call it was built for.
    driver: ?*const Driver = null,
    /// Streams opened by the peer that were rejected because the pool had no room, for diagnostics.
    rejected_streams: u64 = 0,
    /// Datagrams dropped because they arrived before the session, for diagnostics.
    dropped_datagrams: u64 = 0,

    /// Whether the session accepts new streams and datagrams (6: a draining session still does, a
    /// closed one does not).
    pub fn isOpen(self: *const Session) bool {
        return self.state != .closed;
    }

    /// Mark the 2xx response as sent: the session is established from this endpoint's point of view
    /// (3.2), which is what makes it visible to stream and datagram routing.
    pub fn onResponded(self: *Session) void {
        self.state = .open;
    }

    /// Queue the 2xx response head on the CONNECT stream and set that stream's send side up, so capsules
    /// can be appended after it. The FIN is not sent here: it is what ends the session (6).
    ///
    /// Param:
    /// head - []const u8 (the HTTP/3 HEADERS frame bytes carrying the response status)
    pub fn openConnect(self: *Session, head: []const u8) void {
        const queued = @min(head.len, self.connect_buf.len);

        self.connect = .{
            .id = self.id,
            .session_id = self.id,
            .kind = .bidi,
            .initiator = .client,
            .buf = self.connect_buf[0..],
            .send = .{ .open = true, .header_sent = true, .limit = std.math.maxInt(u64) },
            .recv = .{ .fin = false },
        };
        @memcpy(self.connect.buf[0..queued], head[0..queued]);
        self.connect.send.queued = queued;
        self.state = .open;
    }

    /// Whether every byte of every stream this session owns is finished, so the session can be recycled
    /// without losing a retransmittable byte.
    pub fn streamsFinished(self: *const Session) bool {
        var cursor = self.streams;
        while (cursor) |stream| : (cursor = stream.next) {
            if (!stream.finished()) return false;
        }

        return self.connect.sendFinished();
    }

    /// Apply a WT_DRAIN_SESSION capsule (4.7), from either side.
    pub fn onDrain(self: *Session) void {
        if (self.state == .open) self.state = .draining;
    }

    /// End the session (6). The engine resets every stream with WT_SESSION_GONE and stops routing
    /// datagrams once this returns.
    pub fn close_(self: *Session, info: CloseInfo) void {
        self.state = .closed;
        self.close = info;

        const len = @min(info.message.len, self.close_message.len);
        @memcpy(self.close_message[0..len], info.message[0..len]);
        self.close = .{ .code = info.code, .message = self.close_message[0..len], .reason = info.reason };
    }

    /// End the session with an application close (6).
    pub fn closeWith(self: *Session, code: u32, message: []const u8) void {
        self.close_(.{ .code = code, .message = message, .reason = .local_close });
    }

    /// The session's stream with `id`, or null.
    pub fn findStream(self: *const Session, id: u64) ?*Stream {
        var cursor = self.streams;
        while (cursor) |stream| : (cursor = stream.next) {
            if (stream.id == id) return stream;
        }

        return null;
    }

    /// Add `stream` to the session's list.
    pub fn attachStream(self: *Session, stream: *Stream) void {
        stream.next = self.streams;
        self.streams = stream;
    }

    /// Remove `stream` from the session's list, returning whether it was there. The caller returns the
    /// slot to the pool.
    pub fn detachStream(self: *Session, stream: *Stream) bool {
        var link = &self.streams;
        while (link.*) |candidate| {
            if (candidate == stream) {
                link.* = candidate.next;
                candidate.next = null;

                return true;
            }

            link = &candidate.next;
        }

        return false;
    }

    /// The session data limit charge for one incoming stream chunk (5.4): the Stream Body bytes only,
    /// the header excluded by the caller.
    pub fn onStreamData(self: *Session, len: u64) SessionError!void {
        if (!self.isOpen()) return error.ZixSessionClosed;

        return self.flow.onSessionData(len);
    }

    /// What the peer's SETTINGS said this endpoint may send (5.5).
    pub fn applyPeerInitialLimits(self: *Session, max_data: u64, streams_bidi: u64, streams_uni: u64) void {
        self.flow.declarePeer(max_data, streams_bidi, streams_uni);
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

/// Build a stream with a header already queued, as `openStream` does on the wire.
fn openStreamForTest(session: *Session, stream: *Stream, buf: []u8, kind: stream_header.Kind, id: u64, initiator: Role) void {
    var header_buf: [16]u8 = undefined;
    const len = stream_header.write(kind, &header_buf, session.id).?;

    stream.* = .{ .id = id, .session_id = session.id, .kind = kind, .initiator = initiator, .buf = buf };
    stream.openWithHeader(header_buf[0..len]);
    stream.send.limit = 1024;
    stream.recv.limit = 1024;
    session.attachStream(stream);
}

test "zix webtransport: a stream buffer takes what it can and reports back pressure" {
    var session = Session{ .id = 0 };
    var buf: [32]u8 = undefined;
    var stream: Stream = undefined;
    openStreamForTest(&session, &stream, &buf, .bidi, 4, .client);

    // The header (a 2-byte signal value plus a 1-byte session id for session 0) occupies offset 0, so
    // the application gets the rest of the buffer.
    try std.testing.expectEqual(@as(u64, 3), stream.send.queued);
    try std.testing.expectEqual(@as(usize, 29), stream.writable());

    // A write larger than the room is partially accepted, which is the back-pressure contract.
    const big: [40]u8 = @splat(0xaa);
    try std.testing.expectEqual(@as(usize, 29), stream.write(&big));
    try std.testing.expectEqual(@as(usize, 0), stream.writable());
    try std.testing.expectEqual(@as(usize, 0), stream.write("more"));

    // Sending advances `sent` and the unacknowledged tally, and the FIN is only pending once the last
    // queued byte is out.
    try std.testing.expectEqual(@as(usize, 32), stream.sendable());
    stream.onSent(32);
    try std.testing.expectEqual(@as(u64, 32), stream.send.unacked());
    try std.testing.expectEqual(@as(u64, 32), stream.send.high_water);
    stream.send.fin = true;
    try std.testing.expect(stream.finPending());

    // Acknowledging reclaims the buffer from the front and can never double-count a byte. A stream that
    // was finished takes no more writes even once its buffer is empty, which is what stops an
    // application from appending after its FIN.
    stream.onAcked(0, 32);
    try std.testing.expectEqual(@as(u64, 0), stream.send.queued);
    try std.testing.expectEqual(@as(u64, 0), stream.send.unacked());
    try std.testing.expectEqual(@as(usize, 0), stream.writable());
    try std.testing.expect(stream.sendFinished());

    // An acknowledgement for a range the stream never sent frees nothing: the peer cannot talk the
    // endpoint into dropping bytes it still owes.
    try std.testing.expectEqual(@as(u64, 32), stream.send.acked);
    stream.onAcked(100, 30);
    try std.testing.expectEqual(@as(u64, 32), stream.send.acked);
}

test "zix webtransport: a long stream reuses one buffer across acknowledgements" {
    var session = Session{ .id = 0 };
    var buf: [16]u8 = undefined;
    var stream: Stream = undefined;
    openStreamForTest(&session, &stream, &buf, .uni, 2, .client);

    // Fill, send, acknowledge, repeat: the buffer never grows and the content stays correct because the
    // acknowledged prefix is compacted away.
    var round: usize = 0;
    while (round < 40) : (round += 1) {
        const byte: u8 = @intCast(round % 251);
        const payload: [8]u8 = @splat(byte);
        try std.testing.expectEqual(@as(usize, 8), stream.write(&payload));

        const ready = stream.sendable();
        try std.testing.expect(ready >= payload.len);

        // What the pump would hand the wire is the queued region from the sent offset, and the bytes
        // just written are its tail: the first round also carries the header, later rounds carry only
        // what the application queued.
        const window = stream.buf[@intCast(stream.send.sent - stream.send.acked)..][0..ready];
        try std.testing.expectEqualSlices(u8, &payload, window[ready - payload.len ..]);

        const at = stream.send.sent;
        stream.onSent(ready);
        stream.onAcked(at, ready);
    }

    // Forty rounds of eight payload bytes, plus the three-byte header sent once.
    try std.testing.expectEqual(@as(u64, 3 + 320), stream.send.acked);
    try std.testing.expectEqual(@as(u64, 3 + 320), stream.send.high_water);
}

test "zix webtransport: a loss rewinds the sent offset without disturbing the queue" {
    var session = Session{ .id = 4 };
    var buf: [64]u8 = undefined;
    var stream: Stream = undefined;
    openStreamForTest(&session, &stream, &buf, .bidi, 8, .client);

    try std.testing.expectEqual(@as(usize, 10), stream.write("0123456789"));
    stream.onSent(13); // the 3-byte header plus ten payload bytes
    try std.testing.expectEqual(@as(u64, 13), stream.send.sent);

    // The peer reports the range from offset 4 lost: `sent` rewinds there, so the next pump resends it,
    // and the still-queued bytes are untouched.
    stream.onLost(4);
    try std.testing.expectEqual(@as(u64, 4), stream.send.sent);
    try std.testing.expectEqual(@as(u64, 13), stream.send.queued);
    // A loss is not an acknowledgement: every byte the stream sent is still waiting on the peer, so the
    // outstanding range is unchanged and only `sent` moved back for the resend.
    try std.testing.expectEqual(@as(u64, 13), stream.send.unacked());
    try std.testing.expectEqual(@as(usize, 1), stream.send.outstanding_len);
    try std.testing.expectEqual(@as(u64, 0), stream.send.outstanding[0].offset);

    // A stale loss report for a range already resent must not move the offset forward.
    stream.onLost(100);
    try std.testing.expectEqual(@as(u64, 4), stream.send.sent);
}

test "zix webtransport: 4.4 a reset always covers the stream header" {
    var session = Session{ .id = 0 };
    var buf: [64]u8 = undefined;
    var stream: Stream = undefined;
    openStreamForTest(&session, &stream, &buf, .bidi, 4, .client);

    try std.testing.expectEqual(@as(usize, 7), stream.write("payload"));
    stream.resetSend(7);
    const reset = stream.send.reset.?;
    try std.testing.expectEqual(@as(u32, 7), reset.code);
    try std.testing.expectEqual(@as(u64, 10), reset.reliable_size); // the 3-byte header plus 7 payload bytes
    try std.testing.expectEqual(@as(u64, 10), stream.totalBytes());
    try std.testing.expect(!stream.sendFinished());

    // Once the reset is out and every outstanding range is acknowledged the stream is finished even
    // without a FIN: the reset is how this half ends.
    stream.send.reset.?.sent = true;
    stream.onAcked(0, stream.send.queued);
    try std.testing.expect(stream.sendFinished());
}

test "zix webtransport: 5.4 the receive side replenishes credit before it runs dry" {
    var session = Session{ .id = 0 };
    var buf: [64]u8 = undefined;
    var stream: Stream = undefined;
    openStreamForTest(&session, &stream, &buf, .uni, 2, .client);

    // A 1024-byte window: the first half is free, past it the endpoint owes the peer a new limit.
    try std.testing.expect(stream.replenish(1024) == null);
    stream.onReceived(0, 500, false);
    try std.testing.expect(stream.replenish(1024) == null);
    stream.onReceived(500, 100, false);
    try std.testing.expectEqual(@as(u64, 1624), stream.replenish(1024).?);
    try std.testing.expectEqual(@as(u64, 1624), stream.recv.limit);

    // The FIN plus the final size is what marks the receive half done.
    try std.testing.expect(!stream.recvFinished());
    stream.onReceived(600, 0, true);
    try std.testing.expect(stream.recvFinished());
}

test "zix webtransport: 5.1 flow control is only enabled when both endpoints declare it" {
    var flow = FlowControl{};

    // Neither side declared: nothing applies and capsules must be ignored.
    try std.testing.expect(!flow.enabled);
    try flow.onSessionData(1 << 20);
    try flow.onMaxData(4096);
    try std.testing.expectEqual(@as(u64, 0), flow.peer_max_data);

    // One side only: still off (5.1 requires both).
    flow.declareLocal(1024, 2, 2);
    try std.testing.expect(!flow.enabled);

    flow.declarePeer(4096, 4, 4);
    try std.testing.expect(flow.enabled);
    try std.testing.expectEqual(@as(u64, 4096), flow.peer_max_data);
    try std.testing.expectEqual(@as(u64, 4), flow.peer_max_streams_bidi);
}

test "zix webtransport: 5.4 the session data limit is enforced and charged" {
    var flow = FlowControl{};
    flow.declareLocal(100, 0, 0);
    flow.declarePeer(100, 0, 0);
    try std.testing.expect(flow.enabled);

    try flow.onSessionData(60);
    try flow.onSessionData(40);
    try std.testing.expectError(error.ZixFlowControlError, flow.onSessionData(1));

    // A reset stream charges its final size, which can be more than what arrived (5.4).
    var other = FlowControl{};
    other.declareLocal(100, 0, 0);
    other.declarePeer(100, 0, 0);
    try other.onSessionData(10);
    try other.onResetFinalSize(100);
    try std.testing.expectError(error.ZixFlowControlError, other.onSessionData(1));
}

test "zix webtransport: 5.6.2 the incoming stream count is limited per kind" {
    var flow = FlowControl{};
    flow.declareLocal(1 << 20, 2, 1);
    flow.declarePeer(1 << 20, 2, 1);

    try flow.onStreamOpened(.bidi);
    try flow.onStreamOpened(.bidi);
    try std.testing.expectError(error.ZixFlowControlError, flow.onStreamOpened(.bidi));

    try flow.onStreamOpened(.uni);
    try std.testing.expectError(error.ZixFlowControlError, flow.onStreamOpened(.uni));

    // The two kinds have separate limits: an exhausted bidirectional limit says nothing about unidirectional.
    try std.testing.expectEqual(@as(u64, 2), flow.streams_bidi_received);
    try std.testing.expectEqual(@as(u64, 1), flow.streams_uni_received);
}

test "zix webtransport: 4.1 a merged send range frees its prefix from per-packet acknowledgements" {
    var send = SendSide{ .open = true, .queued = 3000, .sent = 3000, .high_water = 3000, .limit = 1 << 20 };

    // Three sends that are contiguous merge into one outstanding range, which is what a steady stream does.
    send.noteSent(0, 1000);
    send.noteSent(1000, 1000);
    send.noteSent(2000, 1000);
    try std.testing.expectEqual(@as(u8, 1), send.outstanding_len);

    // The peer acknowledges one packet at a time: each one frees its own bytes, so the buffer drains as the
    // stream advances instead of waiting for an acknowledgement that covers the whole merged range.
    try std.testing.expectEqual(@as(u64, 1000), send.noteAcked(0, 1000));
    try std.testing.expectEqual(@as(u64, 1000), send.noteAcked(1000, 1000));
    try std.testing.expectEqual(@as(u64, 1000), send.noteAcked(2000, 1000));

    try std.testing.expectEqual(@as(u64, 3000), send.acked);
    try std.testing.expectEqual(@as(u64, 0), send.queued);
    try std.testing.expectEqual(@as(u8, 0), send.outstanding_len);
}

test "zix webtransport: 5.3 opening streams respects the peer limit" {
    var flow = FlowControl{};
    flow.declareLocal(1 << 20, 4, 4);
    flow.declarePeer(1 << 20, 1, 0);
    try std.testing.expect(flow.enabled);

    try std.testing.expect(flow.canOpen(.bidi));
    flow.onOpenedStream(.bidi);
    try std.testing.expect(!flow.canOpen(.bidi));

    // A zero limit means the peer granted nothing.
    try std.testing.expect(!flow.canOpen(.uni));

    // Without flow control there is no session limit to respect.
    var free = FlowControl{};
    try std.testing.expect(free.canOpen(.uni));
    try std.testing.expect(free.canSendData(1 << 40));
}

test "zix webtransport: 5.6.4 WT_MAX_DATA and WT_MAX_STREAMS must increase" {
    var flow = FlowControl{};
    flow.declareLocal(1 << 20, 4, 4);
    flow.declarePeer(1000, 1, 1);
    try std.testing.expect(flow.enabled);

    try flow.onMaxData(2000);
    try std.testing.expectEqual(@as(u64, 2000), flow.peer_max_data);
    try std.testing.expectError(error.ZixFlowControlError, flow.onMaxData(2000));
    try std.testing.expectError(error.ZixFlowControlError, flow.onMaxData(1500));

    try flow.onMaxStreams(.bidi, 3);
    try std.testing.expectEqual(@as(u64, 3), flow.peer_max_streams_bidi);
    try std.testing.expectError(error.ZixFlowControlError, flow.onMaxStreams(.bidi, 3));

    // A count past 2^60 cannot describe a stream id: WT_FLOW_CONTROL_ERROR (5.6.2).
    try std.testing.expectError(error.ZixFlowControlError, flow.onMaxStreams(.uni, draft.max_stream_count + 1));
}

test "zix webtransport: the endpoint raises its own limits as the peer consumes them" {
    var flow = FlowControl{};
    flow.declareLocal(100, 2, 2);
    flow.declarePeer(100, 2, 2);

    // Nothing consumed yet: no capsule is owed.
    try std.testing.expect(flow.dueMaxData(100) == null);
    try std.testing.expect(flow.dueMaxStreams(.bidi, 2) == null);

    try flow.onSessionData(80);
    try std.testing.expectEqual(@as(u64, 180), flow.dueMaxData(100).?);
    try std.testing.expectEqual(@as(u64, 180), flow.local_max_data);
    // The limit only moves when it grows: a second call with the same window owes nothing.
    try std.testing.expect(flow.dueMaxData(100) == null);

    try flow.onStreamOpened(.bidi);
    try std.testing.expectEqual(@as(u64, 3), flow.dueMaxStreams(.bidi, 2).?);
    try std.testing.expect(flow.dueMaxStreams(.bidi, 2) == null);
}

test "zix webtransport: 6 a session ends with the close information the peer sent" {
    var session = Session{ .id = 4, .dialect = .draft16 };

    session.onDrain();
    try std.testing.expectEqual(State.draining, session.state);
    try std.testing.expect(session.isOpen());

    session.close_(.{ .code = 42, .message = "done here", .reason = .peer_close });
    try std.testing.expectEqual(State.closed, session.state);
    try std.testing.expect(!session.isOpen());
    try std.testing.expectEqual(@as(u32, 42), session.close.code);
    try std.testing.expectEqualStrings("done here", session.close.message);
    try std.testing.expectEqual(CloseReason.peer_close, session.close.reason);

    // The message is copied, so it survives the caller's buffer going away.
    try std.testing.expect(session.close.message.ptr != "done here".ptr);

    // A message longer than the limit is clipped to the session's own buffer.
    const long: [draft.max_close_message + 100]u8 = @splat('x');
    session.close_(.{ .code = 1, .message = &long, .reason = .local_close });
    try std.testing.expectEqual(@as(usize, draft.max_close_message), session.close.message.len);
}

test "zix webtransport: the session survives its streams being attached and detached" {
    var session = Session{ .id = 0 };
    var bufs: [3][32]u8 = undefined;
    var streams: [3]Stream = undefined;

    openStreamForTest(&session, &streams[0], &bufs[0], .bidi, 4, .client);
    openStreamForTest(&session, &streams[1], &bufs[1], .uni, 2, .client);
    openStreamForTest(&session, &streams[2], &bufs[2], .bidi, 5, .server);

    try std.testing.expectEqual(@as(u64, 4), session.findStream(4).?.id);
    try std.testing.expectEqual(@as(u64, 2), session.findStream(2).?.id);
    try std.testing.expect(session.findStream(99) == null);

    // Detaching the middle stream leaves the list intact, so the others are still findable.
    try std.testing.expect(session.detachStream(&streams[1]));
    try std.testing.expect(session.findStream(2) == null);
    try std.testing.expectEqual(@as(u64, 4), session.findStream(4).?.id);
    try std.testing.expectEqual(@as(u64, 5), session.findStream(5).?.id);
    try std.testing.expect(!session.detachStream(&streams[1]));
}

test "zix webtransport: 4.1 / 3.2 a session's id is its CONNECT stream id" {
    // The ids a session may be keyed by are the client's bidirectional stream ids, which is exactly what
    // the datagram quarter stream id reconstructs.
    const session = Session{ .id = 12 };
    try std.testing.expectEqual(@as(u64, 12), session.id);
    try std.testing.expectEqual(@as(u64, 3), 12 / 4);
    try std.testing.expect(stream_header.isValidSessionId(session.id));
}
