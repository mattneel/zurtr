//! zix WebRTC server config.
//!
//! What:
//! - `WebrtcServerConfig`: the UDP substrate knobs restated flat (ADR-049 / ADR-050 contract) plus
//!   what the four protocol layers need to answer a peer: ICE credentials, the DTLS certificate and
//!   signing key, and the deadlines the engine runs on.
//!
//! Note:
//! - The TLS context is the sanctioned by-pointer exception, the same as every other zix engine
//!   that carries one: the caller owns it and it must outlive the server. WebRTC only reads its
//!   certificate and its signing key, and that key has to be ECDSA P-256, because the one DTLS 1.2
//!   suite this engine implements is ECDHE-ECDSA (RFC 5289).
//! - Every duration is milliseconds, because every layer below already counts in milliseconds.

const std = @import("std");

const Logger = @import("../../logger/logger.zig").Logger;
const Tls = @import("../../tls/Tls.zig");
const dtls_exporter = @import("../../tls/dtls_exporter.zig");

/// The dispatch model, shared with the TCP engines and the other UDP engines (ADR-050). `.ASYNC` is
/// the portable single-worker loop. `.EPOLL` / `.URING` run one worker per core and are Linux-only.
pub const DispatchModel = @import("../../tcp/config.zig").DispatchModel;

/// The SRTP profiles this engine offers when it carries media, best first (RFC 5764 4.1.2).
///
/// Note:
/// - The 80-bit tag comes first. The 32-bit one saves six bytes a packet and gives up
///   authentication strength for them, so it is answered only to a peer that offers nothing else.
/// - The NULL profiles are not here at all. They authenticate without encrypting, which is not
///   something to agree to on a path that was just given a certificate.
pub const SRTP_PROFILES: []const dtls_exporter.SrtpProfile = &.{
    .SRTP_AES128_CM_HMAC_SHA1_80,
    .SRTP_AES128_CM_HMAC_SHA1_32,
};

pub const WebrtcServerConfig = struct {
    /// Io backend for the server. Caller-provided, must outlive the server.
    io: std.Io,
    /// Backing allocator. Must be a general-purpose allocator (e.g. std.heap.smp_allocator).
    allocator: std.mem.Allocator,
    /// Bind address.
    ip: []const u8,
    /// Bind port. Must be non-zero.
    port: u16,

    // UDP substrate knobs (ADR-049), restated flat.

    /// Concurrency model. ASYNC runs a single worker on every platform, EPOLL and URING run one
    /// SO_REUSEPORT worker per core and are rejected off Linux with error.ZixDispatchModelUnsupported.
    /// Required: the caller must set it explicitly (no default).
    dispatch_model: DispatchModel,
    /// Worker count for the per-core models. 0 means one per usable CPU. Ignored by ASYNC.
    workers: usize = 0,
    /// Worker thread stack size in bytes for the per-core workers. Ignored by ASYNC.
    worker_stack_size_bytes: usize = 512 * 1024,
    /// Maximum datagram size, the receive buffer per slot. 1500 is the common Ethernet MTU.
    max_recv_buf: usize = 1500,
    /// Requested SO_RCVBUF in bytes. 0 keeps the kernel default.
    socket_rcvbuf: usize = 1024 * 1024,
    /// Requested SO_SNDBUF in bytes. 0 keeps the kernel default.
    socket_sndbuf: usize = 1024 * 1024,

    // ICE (RFC 8445, RFC 8489). zix answers checks as a lite agent, it never sends its own.

    /// This agent's ufrag, the first half of the USERNAME every check carries.
    /// Required: run() rejects an empty one.
    ice_ufrag: []const u8 = "",
    /// This agent's password, the key every check is verified against.
    /// Required: run() rejects an empty one.
    ice_password: []const u8 = "",
    /// The peer's ufrag, the second half of that USERNAME. Empty means checks are refused with 401
    /// until it is known, which is what a caller with no signalling channel yet has to live with.
    /// Ignored when accept_any_peer_ice_ufrag is set.
    peer_ice_ufrag: []const u8 = "",
    /// Take a check whatever the peer calls itself, and let ice_password be the only gate. A peer
    /// that draws its own ufrag per session needs this, which is every browser: it learns this
    /// server's password from the answer it was handed, and every check it sends is verified
    /// against that password, so the ufrag it picked adds nothing on top. Off by default, because a
    /// server that names one peer should keep refusing everybody else.
    accept_any_peer_ice_ufrag: bool = false,

    // DTLS (RFC 6347). Server side, the role a zix peer always takes.

    /// TLS context: the certificate and the key that signs the ServerKeyExchange. Caller owns, must
    /// outlive the server. Null is rejected at run (WebRTC has no cleartext mode), and so is a key
    /// that is not ECDSA P-256.
    tls: ?*Tls.Context = null,
    /// Largest handshake fragment body this server emits, sized so a record fits the path MTU.
    max_handshake_fragment: usize = 1024,

    // Media (RFC 5764, RFC 3711). Off by default: a data channel server carries none.

    /// Whether this server forwards audio and video between its peers. On, the handshake
    /// negotiates SRTP through use_srtp and every peer's media goes to the rest of the worker's
    /// room. Off, no keys are exported and RTP from a peer is dropped where it is routed.
    ///
    /// Note:
    /// - The answer has its own switch. This one keys the transport, and
    ///   `sdp/answer.zig Config.carry_media` is what tells the peer to send in the first place. A
    ///   server that turns on one and not the other either promises media it will not carry, or
    ///   keys a path nothing will use.
    carry_media: bool = false,

    // SCTP and data channels (RFC 9260, RFC 8831).

    /// Largest SCTP packet that fits the path, DTLS overhead already taken off.
    path_max_bytes: usize = 1200,
    /// How many outbound streams the association asks for.
    outbound_streams: u16 = 128,
    /// How many inbound streams the association accepts.
    inbound_streams: u16 = 128,
    /// How many channels one peer may have open at once, counted from both sides.
    max_channels: usize = 64,

    // Engine limits and deadlines.

    /// How many peers one worker holds at once. A datagram from a new peer past the ceiling is
    /// dropped, which reads to that peer as a check that went unanswered. The per-core models count
    /// this per worker, so a server with N workers holds up to N * max_peers.
    max_peers: usize = 64,
    /// How long a peer may go without a datagram before the engine drops it. Covers the case a
    /// browser closes its tab without a graceful shutdown.
    peer_idle_ms: u32 = 30000,
    /// How often the engine looks at its peers when no datagram is arriving. The floor on how late
    /// a retransmit or an idle drop can be, so it is also the cost of a fully silent server.
    tick_interval_ms: u32 = 250,

    /// Optional logger. When non-null, the server calls logger.system() for lifecycle events.
    logger: ?*Logger = null,
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix webrtc: config default field values" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const config = WebrtcServerConfig{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .ip = "127.0.0.1",
        .port = 9083,
        .dispatch_model = .ASYNC,
    };

    try std.testing.expectEqual(DispatchModel.ASYNC, config.dispatch_model);
    try std.testing.expectEqual(@as(usize, 1500), config.max_recv_buf);
    try std.testing.expectEqual(@as(usize, 1024 * 1024), config.socket_rcvbuf);
    try std.testing.expectEqual(@as(usize, 1024 * 1024), config.socket_sndbuf);
    try std.testing.expectEqual(@as(usize, 1024), config.max_handshake_fragment);
    try std.testing.expectEqual(@as(usize, 1200), config.path_max_bytes);
    try std.testing.expectEqual(@as(u16, 128), config.outbound_streams);
    try std.testing.expectEqual(@as(u16, 128), config.inbound_streams);
    try std.testing.expectEqual(@as(usize, 64), config.max_channels);
    try std.testing.expectEqual(@as(usize, 64), config.max_peers);
    try std.testing.expectEqual(@as(u32, 30000), config.peer_idle_ms);
    try std.testing.expectEqual(@as(u32, 250), config.tick_interval_ms);

    // A data channel server carries no media, so nothing keys the media path unless it is asked
    // for.
    try std.testing.expect(!config.carry_media);
}

test "zix webrtc: config srtp profiles, the strong tag is offered first" {
    try std.testing.expectEqual(@as(usize, 2), SRTP_PROFILES.len);
    try std.testing.expectEqual(dtls_exporter.SrtpProfile.SRTP_AES128_CM_HMAC_SHA1_80, SRTP_PROFILES[0]);
    try std.testing.expectEqual(dtls_exporter.SrtpProfile.SRTP_AES128_CM_HMAC_SHA1_32, SRTP_PROFILES[1]);
}

test "zix webrtc: config credentials are empty until the caller fills them" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const config = WebrtcServerConfig{
        .io = threaded.io(),
        .allocator = std.testing.allocator,
        .ip = "127.0.0.1",
        .port = 9083,
        .dispatch_model = .ASYNC,
    };

    try std.testing.expectEqual(@as(usize, 0), config.ice_ufrag.len);
    try std.testing.expectEqual(@as(usize, 0), config.ice_password.len);
    try std.testing.expectEqual(@as(usize, 0), config.peer_ice_ufrag.len);
    try std.testing.expect(config.tls == null);
    try std.testing.expect(config.logger == null);

    // A server nobody named a peer for refuses everybody, rather than taking the first arrival.
    try std.testing.expect(!config.accept_any_peer_ice_ufrag);
}
