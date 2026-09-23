//! zix.Webtransport: the application surface for WebTransport over HTTP/3.
//!
//! What:
//! - The feature is configured on the HTTP/3 server (`Http3ServerConfig.webtransport`): turn it on,
//!   size the session and stream limits, and register the callbacks an application answers.
//! - `Session` and `Stream` are the handles an application works with. They are views over the engine's
//!   per-session and per-stream state: `Session.openBidi`, `Stream.write`, `Session.sendDatagram` and
//!   the rest are the whole API, so an application never touches a packet, a stream id, or a frame.
//! - The callbacks arrive from the worker that owns the QUIC connection, on its own thread, one at a
//!   time: an application handler runs single-threaded per connection and never needs a lock.
//!
//! Note:
//! - Lifetime follows the rest of zix: every handle and every slice handed to a callback is valid only
//!   for that callback. `Stream.read` returns the chunk the engine just decoded, so an application that
//!   needs the bytes later copies them.
//! - Nothing is allocated per callback and nothing per session beyond the worker pool's slots, so an
//!   application cannot make the server allocate by opening streams.
//! - WebTransport over HTTP/3 speaks two dialects on the wire: draft-ietf-webtrans-http3-16 (the
//!   current revision) and the deployed draft-07 dialect that browsers and aioquic still send. The
//!   session's `dialect()` says which one a session uses; the application does not have to care unless
//!   it wants flow control, which only draft-16 sessions have.

const std = @import("std");

/// The wire vocabulary both dialects share, plus the application error mapping (4.4).
pub const draft = @import("draft.zig");
/// The session and stream state machines, and the flow control rules (3.2 / 4 / 5 / 6).
pub const session = @import("session.zig");
/// The worker pool a session's slots and send buffers come from (4.6).
pub const pool = @import("pool.zig");
/// The capsule protocol: framing and the capsules this binding defines (RFC 9297 3, draft-16 5.6 / 6).
pub const capsule = @import("capsule.zig");
/// The QUIC DATAGRAM frame and the HTTP/3 datagram inside it (RFC 9221 4, RFC 9297 2).
pub const datagram = @import("datagram.zig");
/// The bytes that open a WebTransport data stream (4.2 / 4.3).
pub const stream_header = @import("stream_header.zig");

const session_state = session;
const draft_module = draft;

/// The WebTransport stream kind an application asks for (4.2 / 4.3).
pub const Kind = stream_header.Kind;

/// The dialect a session speaks: which revision of the binding the client used.
pub const Dialect = draft.Dialect;

/// The session's lifecycle state, as far as the application is concerned.
pub const State = session_state.State;

/// Why a session ended (6).
pub const CloseReason = session_state.CloseReason;

/// The close information a session carries once it has ended (6).
pub const CloseInfo = session_state.CloseInfo;

/// The request that established a session, handed to `Handler.on_session`.
///
/// Note:
/// - The slices borrow the engine's decode buffer, so they are valid for the `on_session` call only: an
///   application that routes on the path or authorizes an origin and needs either later copies it.
pub const SessionRequest = struct {
    /// The CONNECT `:path`, which is the resource the session was requested from.
    path: []const u8 = "",
    /// The CONNECT `:authority`.
    authority: []const u8 = "",
    /// The `:protocol` token the client used (9.1).
    protocol: []const u8 = "",
    /// The `Origin` field, empty when the client sent none. A browser client always sends one (3.2), and
    /// the server is the one that decides whether the origin is allowed.
    origin: []const u8 = "",
    /// Which revision of the binding the client speaks, derived from the token above.
    dialect: Dialect = .draft16,
    /// Whether the client's transport parameters and settings allow HTTP/3 datagrams. False means
    /// `Session.sendDatagram` will always refuse, and the application should not offer the feature.
    datagram_capable: bool = false,
};

/// The application callbacks for WebTransport sessions. Every one is optional: a callback left null
/// means the engine keeps the session alive and drops what would have been delivered to it.
pub const Handler = struct {
    /// Decide a session: return null to accept it (the engine then answers 2xx and the session is
    /// established from that point, 3.2), or an HTTP status code to refuse it (403 for an origin the
    /// application does not allow, 404 for a path it does not serve, 429 for rate limiting, 3.2 / 5.2).
    on_session: ?*const fn (session: *Session) ?u16 = null,
    /// A session's data stream has bytes ready: read them with `Stream.read`, which returns the chunk
    /// that just arrived. Called once per chunk, with `Stream.finished` telling whether the peer ended
    /// the stream with this chunk.
    on_stream: ?*const fn (session: *Session, stream: *const Stream) void = null,
    /// A data stream ended without its bytes all arriving: the peer reset it, or this endpoint gave up
    /// on it. `Stream.resetCode` carries the application error code the peer sent, when it was one.
    on_stream_reset: ?*const fn (session: *Session, stream: *const Stream) void = null,
    /// One datagram arrived on the session. The slice is the application payload, with the session
    /// routing already stripped; it is valid for this call only.
    on_datagram: ?*const fn (session: *Session, datagram: []const u8) void = null,
    /// The session ended, for any reason: read `Session.closeInfo` to tell which. After this call the
    /// session's slot is recycled, so nothing about it may be kept.
    on_close: ?*const fn (session: *Session) void = null,
};

/// The WebTransport feature configuration, carried on the HTTP/3 server config.
pub const Config = struct {
    /// Offer WebTransport at all. False costs nothing: no settings are advertised, no pool is
    /// allocated, and a WebTransport CONNECT is answered like any other unsupported method.
    enabled: bool = false,

    /// Concurrent WebTransport sessions one HTTP/3 connection may have (advertised to the client and
    /// enforced). Draft-16 clients learn the server's willingness from SETTINGS_WT_ENABLED and the
    /// stream limits; draft-07 clients from SETTINGS_WEBTRANSPORT_MAX_SESSIONS.
    max_sessions_per_connection: u16 = 4,

    /// Streams one session may have open in each direction, per session. Advertised with
    /// SETTINGS_WT_INITIAL_MAX_STREAMS_* and the WT_MAX_STREAMS capsule, and grows as streams close.
    max_streams_bidi: u32 = 16,
    max_streams_uni: u32 = 16,

    /// Stream Body bytes one session may carry before the limit is extended, advertised with
    /// SETTINGS_WT_INITIAL_MAX_DATA and the WT_MAX_DATA capsule. This is the session-wide budget, not
    /// per stream: QUIC's own flow control limits each stream.
    max_session_data: u64 = 1 << 20,

    /// Bytes one data stream may queue before the peer acknowledges them: the application's write
    /// window, and the bytes a lost packet can still be resent from. A stream that fills it back-
    /// pressures the application (`Stream.write` returns a short count) instead of dropping bytes.
    stream_send_bytes: usize = 16 * 1024,

    /// Session slots one worker allocates. Allocating 0 disables sessions on that worker.
    pool_sessions: usize = 16,
    /// Data stream slots one worker allocates, each with its own send buffer.
    pool_streams: usize = 64,
    /// Data streams one worker buffers when they arrive before the CONNECT that establishes their
    /// session (4.6). Past this many, a stream is reset with WT_BUFFERED_STREAM_REJECTED.
    pool_orphan_streams: usize = 8,
    /// Bytes buffered per pre-session stream.
    pool_orphan_bytes: usize = 1024,

    /// The largest DATAGRAM frame this endpoint accepts, advertised as max_datagram_frame_size
    /// (RFC 9221 3). It bounds what a peer may send and what one datagram may carry back. The
    /// recommended value accepts any datagram that fits a QUIC packet.
    max_datagram_frame_size: u64 = 1200,

    /// Also accept the deployed draft-07 dialect: the `webtransport` token and
    /// SETTINGS_ENABLE_WEBTRANSPORT. Turn it off only when every client is known to speak the current
    /// revision, since every shipping browser still sends the deployed one.
    legacy_dialect: bool = true,

    /// The application callbacks.
    handler: Handler = .{},
};

/// A WebTransport session: an accepted extended CONNECT and everything multiplexed on it.
///
/// Note:
/// - A session is the handle an application keeps during a callback. It is a view over engine state, so
///   copying it is fine but a copy is only usable while the callback that produced it runs.
pub const Session = struct {
    /// The engine's session state. Applications read it through the methods below.
    inner: *session_state.Session,
    /// The engine hooks, installed for the callback that owns this view.
    driver: ?*const session_state.Driver = null,
    /// The establishing request, filled for `Handler.on_session` only.
    request: SessionRequest = .{},

    /// The session id: the CONNECT stream id that identifies this session on the connection (3.2).
    pub fn id(self: Session) u64 {
        return self.inner.id;
    }

    /// Which revision of the binding this session speaks (9.1 / 7.1).
    pub fn dialect(self: Session) Dialect {
        return self.inner.dialect;
    }

    /// The lifecycle state (6).
    pub fn state(self: Session) State {
        return self.inner.state;
    }

    /// Whether the session still accepts new streams and datagrams. A draining session does (4.7); a
    /// closed one does not.
    pub fn isOpen(self: Session) bool {
        return self.inner.isOpen();
    }

    /// The request that established this session. Valid during `Handler.on_session`; the slices are
    /// emptied afterwards.
    pub fn sessionRequest(self: Session) SessionRequest {
        return self.request;
    }

    /// Open a bidirectional data stream on this session (4.3). Null when the session is closed, the
    /// peer's stream limit is reached, or the worker has no stream slot left.
    ///
    /// Note:
    /// - The stream is ready to write when this returns: the engine queues the stream header, so the
    ///   peer learns which session the stream belongs to before it sees any payload.
    pub fn openBidi(self: Session) ?Stream {
        return self.open(.bidi);
    }

    /// Open a unidirectional data stream on this session (4.2). Null under the same conditions as
    /// `openBidi`.
    pub fn openUni(self: Session) ?Stream {
        return self.open(.uni);
    }

    fn open(self: Session, kind: Kind) ?Stream {
        if (!self.inner.isOpen()) return null;
        if (!self.inner.flow.canOpen(kind)) return null;

        const driver = self.driver orelse return null;
        const inner = driver.open_stream(driver.context, self.inner, kind) orelse return null;

        return .{ .inner = inner, .driver = driver };
    }

    /// Send one unreliable datagram on this session (4.5). False when it could not be sent: the client
    /// did not negotiate datagrams, the payload is larger than the peer accepts, or the congestion
    /// window has no room. A datagram is never queued for later and never retransmitted, so a caller
    /// that needs reliability uses a stream.
    pub fn sendDatagram(self: Session, payload: []const u8) bool {
        if (!self.inner.isOpen()) return false;

        const driver = self.driver orelse return false;

        return driver.send_datagram(driver.context, self.inner, payload);
    }

    /// Close the session with an application error code and message (6). The engine sends a
    /// WT_CLOSE_SESSION capsule and finishes the CONNECT stream, then resets every stream of the
    /// session; the application's `on_close` runs once that is done.
    pub fn close(self: Session, code: u32, message: []const u8) void {
        if (!self.inner.isOpen()) return;

        self.inner.closeWith(code, message);

        const driver = self.driver orelse return;
        driver.close_session(driver.context, self.inner);
    }

    /// Tell the peer this session is draining (4.7). The session keeps working: the signal is advice to
    /// the client application to finish up, and new streams and datagrams are still allowed.
    pub fn drain(self: Session) void {
        if (!self.inner.isOpen()) return;

        self.inner.onDrain();

        const driver = self.driver orelse return;
        driver.drain_session(driver.context, self.inner);
    }

    /// How many more streams of `kind` the peer allows on this session (5.3). Only meaningful on a
    /// draft-16 session with flow control enabled, where a zero means streams cannot be opened until
    /// the peer raises the limit.
    pub fn streamsAvailable(self: Session, kind: Kind) u64 {
        if (!self.inner.flow.enabled) return std.math.maxInt(u64);

        return switch (kind) {
            .bidi => self.inner.flow.peer_max_streams_bidi -| self.inner.flow.streams_bidi_opened,
            .uni => self.inner.flow.peer_max_streams_uni -| self.inner.flow.streams_uni_opened,
        };
    }

    /// The close information of an ended session (6): the application code, the message, and why it
    /// ended. Empty until the session ends.
    pub fn closeInfo(self: Session) CloseInfo {
        return self.inner.close;
    }
};

/// A WebTransport data stream: reliable, ordered bytes, one QUIC stream per stream (4.2 / 4.3).
pub const Stream = struct {
    /// The engine's stream state. Applications read it through the methods below.
    inner: *session_state.Stream,
    /// The engine hooks, installed when this view was produced.
    driver: ?*const session_state.Driver = null,
    /// The chunk this view was created for, valid for the callback that produced it.
    chunk: []const u8 = "",
    /// Where `chunk` starts in the stream. An application that wants to reassemble offsets itself reads
    /// this; the bytes are ordered, so most applications just append what arrives.
    chunk_offset: u64 = 0,

    /// The QUIC stream id, unique on the connection.
    pub fn id(self: Stream) u64 {
        return self.inner.id;
    }

    /// Unidirectional or bidirectional (4.2 / 4.3).
    pub fn kind(self: Stream) Kind {
        return self.inner.kind;
    }

    /// Which endpoint opened the stream, so an application can tell a peer stream from one it opened.
    pub fn initiator(self: Stream) session_state.Role {
        return self.inner.initiator;
    }

    /// The bytes that just arrived, valid for this callback only. Empty when the peer ended the stream
    /// without sending more (`finished` is then true), or when the stream was only just opened.
    pub fn read(self: Stream) []const u8 {
        return self.chunk;
    }

    /// Whether the peer has ended this stream, so nothing more will arrive on it.
    pub fn finished(self: Stream) bool {
        return self.inner.recv.fin;
    }

    /// The application error code the peer used when it reset this stream, or null when it did not
    /// reset it. A code outside the WebTransport application range reads as null, which is the spec's
    /// "reset with no application error code" case (4.4).
    pub fn resetCode(self: Stream) ?u32 {
        const raw = self.inner.recv.reset_code orelse return null;

        return draft_module.decodeAppError(raw);
    }

    /// How many bytes this stream may be given right now. Zero means the write window is full, so the
    /// application stops writing and waits for the next callback once the peer acknowledges.
    pub fn writable(self: Stream) usize {
        return self.inner.writable();
    }

    /// Queue application bytes for the peer, returning how many were accepted. A short count is normal
    /// back pressure: write the rest from a later callback.
    pub fn write(self: Stream, bytes: []const u8) usize {
        // A stream whose send half is closed (never opened, or finished) takes nothing: the engine cannot
        // send bytes after the FIN it already queued.
        if (!self.inner.send.open) return 0;

        return self.inner.write(bytes);
    }

    /// Finish the send half: the engine sends a FIN once the queued bytes are out. The receive half is
    /// unaffected, which matters on a bidirectional stream.
    pub fn finish(self: Stream) void {
        if (!self.inner.send.open) return;

        self.inner.send.fin = true;
    }

    /// Reset the send half with an application error code: the peer sees a stream reset and stops
    /// expecting the rest of the bytes. On a draft-16 session this is a reliable reset, so the stream
    /// header is still delivered and the peer can still tell which session the stream belonged to (4.4).
    pub fn reset(self: Stream, code: u32) void {
        if (self.inner.send.reset != null) return;

        self.inner.resetSend(code);

        const driver = self.driver orelse return;
        driver.reset_stream(driver.context, self.inner);
    }

    /// Ask the peer to stop sending on this stream, with an application error code (4.4). The bytes
    /// already queued by the peer may still arrive; `read` stops delivering them once the engine sees
    /// the peer's response.
    pub fn stop(self: Stream, code: u32) void {
        if (self.inner.recv.stopped) return;

        self.inner.recv.stopped = true;

        const driver = self.driver orelse return;
        driver.stop_receiving(driver.context, self.inner, code);
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

/// The pool sizing a config asks for, given the limits it advertises.
///
/// Note:
/// - The pool is per worker, while the limits are per connection, so the pool has to hold whatever the
///   busiest connection on that worker holds plus room for a second one coming up. Sizing the pool from
///   the limits with a small headroom is what keeps a configured limit meaningful instead of a promise
///   the pool cannot keep.
pub fn poolConfig(config: Config) pool.Config {
    return .{
        .sessions = config.pool_sessions,
        .streams = config.pool_streams,
        .stream_buffer_bytes = config.stream_send_bytes,
        .orphans = config.pool_orphan_streams,
        .orphan_bytes = config.pool_orphan_bytes,
    };
}

/// The pool capacities a config asks for, checked against the compile-time ceilings the connection-side
/// tables are sized from. Returns the offending field name when a value is too large, so a server can
/// refuse to start rather than silently truncate the feature.
pub fn capacityError(config: Config) ?[]const u8 {
    if (config.max_sessions_per_connection > connection_session_cap) return "max_sessions_per_connection";
    if (config.pool_sessions > pool.maxima.sessions) return "pool_sessions";
    if (config.pool_streams > pool.maxima.streams) return "pool_streams";
    if (config.pool_orphan_streams > pool.maxima.orphans) return "pool_orphan_streams";

    return null;
}

/// The largest number of concurrent sessions one connection may be configured for. The connection's
/// session table (see `Connection.wt`) is sized from it, and each entry is a pointer, so raising it
/// costs that many bytes in every eagerly allocated connection.
pub const connection_session_cap: usize = 8;

/// The largest number of data streams one connection may hold open across all its sessions. The
/// connection's stream table is sized from it for the acknowledgement and loss-recovery paths.
pub const connection_stream_cap: usize = 32;

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix webtransport: the default config offers nothing until it is enabled" {
    const config = Config{};
    try std.testing.expect(!config.enabled);
    try std.testing.expectEqual(@as(u16, 4), config.max_sessions_per_connection);
    try std.testing.expectEqual(@as(u32, 16), config.max_streams_bidi);
    try std.testing.expectEqual(@as(u32, 16), config.max_streams_uni);
    try std.testing.expectEqual(@as(u64, 1 << 20), config.max_session_data);
    try std.testing.expectEqual(@as(usize, 16 * 1024), config.stream_send_bytes);
    try std.testing.expectEqual(@as(u64, 1200), config.max_datagram_frame_size);
    try std.testing.expect(config.legacy_dialect);
    try std.testing.expect(config.handler.on_session == null);
    try std.testing.expect(capacityError(config) == null);
}

test "zix webtransport: a config that outgrows the connection tables is refused by name" {
    try std.testing.expectEqualStrings("max_sessions_per_connection", capacityError(.{ .max_sessions_per_connection = connection_session_cap + 1 }).?);
    try std.testing.expectEqualStrings("pool_sessions", capacityError(.{ .pool_sessions = pool.maxima.sessions + 1 }).?);
    try std.testing.expectEqualStrings("pool_streams", capacityError(.{ .pool_streams = pool.maxima.streams + 1 }).?);
    try std.testing.expectEqualStrings("pool_orphan_streams", capacityError(.{ .pool_orphan_streams = pool.maxima.orphans + 1 }).?);

    // The ceilings themselves are accepted, since the tables are sized from exactly them.
    try std.testing.expect(capacityError(.{
        .max_sessions_per_connection = connection_session_cap,
        .pool_sessions = pool.maxima.sessions,
        .pool_streams = pool.maxima.streams,
        .pool_orphan_streams = pool.maxima.orphans,
    }) == null);
}

test "zix webtransport: the pool sizing follows the advertised limits" {
    const config = Config{ .stream_send_bytes = 4096, .pool_streams = 8, .pool_orphan_streams = 2, .pool_orphan_bytes = 512 };
    const sizing = poolConfig(config);

    try std.testing.expectEqual(@as(usize, 8), sizing.streams);
    try std.testing.expectEqual(@as(usize, 2), sizing.orphans);
    try std.testing.expectEqual(@as(usize, 512), sizing.orphan_bytes);
    try std.testing.expectEqual(@as(usize, 4096), sizing.stream_buffer_bytes);
    try std.testing.expectEqual(config.pool_sessions, sizing.sessions);
}

test "zix webtransport: the stream kind and dialect vocabulary the application sees" {
    try std.testing.expectEqual(Kind.bidi, Kind.bidi);
    try std.testing.expectEqual(Dialect.draft16, Dialect.draft16);
    try std.testing.expectEqual(State.open, State.open);
    try std.testing.expectEqual(CloseReason.peer_fin, CloseReason.peer_fin);
    try std.testing.expectEqualStrings("webtransport-h3", draft_module.tokenFor(Dialect.draft16));
}
