//! zix.Webrtc namespace: a pure-Zig WebRTC data channel server on one UDP port.
//!
//! What:
//! - Re-exports the public surface: the Server type (Server.init(handler, config)), the event and
//!   message shapes, the context a handler replies through, the server config, and the shared
//!   DispatchModel. ICE, DTLS, SCTP, and DCEP are internal.
//! - One port carries all of it, demultiplexed by the first byte of each datagram (RFC 7983 7).
//!
//! Note:
//! - zix answers, it does not dial. The ICE agent is lite (RFC 8445 2.3) and the DTLS role is
//!   always server, which is what decides the stream identifiers a channel may open on
//!   (RFC 8832 6).
//! - Media is not carried yet. RTP and RTCP are routed to their own layer and dropped there, and
//!   answering them is a later pass.

const server = @import("server.zig");
const core = @import("core.zig");
const Config = @import("config.zig");
const connection = @import("connection.zig");
const dialer = @import("dialer.zig");

/// The WebRTC server: Server.init(handler, config), mirroring the rest of the family.
pub const Server = server.Server;
/// The application event handler type.
pub const HandlerFn = core.HandlerFn;
/// Something the application has to know about: a channel opened, a channel closed, or a message.
pub const Event = core.Event;
/// One message that arrived on a data channel.
pub const Message = core.Message;
/// Which of the two payload kinds a message travels as.
pub const Kind = core.Kind;
/// What a handler answers through.
pub const Context = core.Context;
/// What to open a channel with, when the server opens one rather than answering.
pub const OpenRequest = core.OpenRequest;
/// The WebRTC server config.
pub const ServerConfig = Config.WebrtcServerConfig;
/// The dispatch model, shared with the rest of the engine family (ADR-050).
pub const DispatchModel = Config.DispatchModel;

/// The peer that dials, for talking to a zix answerer without a browser in between.
pub const Dialer = dialer.Dialer;
/// What a dialer is built with.
pub const DialerOptions = dialer.Options;

/// One answering peer's state machine, driven by datagrams and a clock the caller owns. The server
/// loop is built on it, and a caller drives it directly to run a whole session with no socket.
pub const Connection = connection.Connection;
/// What one connection is built with.
pub const ConnectionOptions = connection.Options;
/// The random values one connection is born with.
pub const Secrets = connection.Secrets;

// Low-level primitives, exposed so a peer (a hand-rolled client, a test harness) can build the
// other side of the wire. This mirrors how zix.Http3 exposes its QUIC and QPACK primitives: the
// server is the product, these are the building blocks under it.
pub const demux = @import("demux.zig");
pub const stun = @import("stun/message.zig");
pub const stun_binding = @import("stun/binding.zig");
pub const ice_lite = @import("ice/lite.zig");
pub const ice_check = @import("ice/check.zig");
pub const ice_credentials = @import("ice/credentials.zig");
pub const ice_candidate = @import("ice/candidate.zig");
pub const sctp = @import("sctp/association.zig");
pub const sctp_chunk = @import("sctp/chunk.zig");
pub const sctp_packet = @import("sctp/packet.zig");
pub const dcep = @import("datachannel/dcep.zig");
pub const datachannel = @import("datachannel/peer.zig");
pub const payload = @import("datachannel/payload.zig");
pub const sdp_offer = @import("sdp/offer.zig");
pub const sdp_answer = @import("sdp/answer.zig");
/// The certificate hash an answer publishes, which a caller computes from the certificate its TLS
/// context holds.
pub const sdp_fingerprint = @import("sdp/fingerprint.zig");
pub const sdp_media_offer = @import("sdp/media_offer.zig");
pub const sdp_media_answer = @import("sdp/media_answer.zig");
pub const srtp = @import("media/srtp.zig");
pub const rtp = @import("media/rtp.zig");
pub const rtcp = @import("media/rtcp.zig");
/// The DTLS 1.2 handshake steps the session sequencer drives, for a peer building the client half.
pub const dtls = @import("../../tls/dtls_connection.zig");
pub const dtls_client = @import("../../tls/dtls_client.zig");
pub const dtls_record = @import("../../tls/dtls_record.zig");
pub const dtls_handshake = @import("../../tls/dtls_handshake.zig");
pub const dtls_hello = @import("../../tls/dtls_hello.zig");
