//! zix.Http3 namespace: a pure-Zig HTTP/3 (QUIC) server on the zix.Udp datagram substrate.
//!
//! What:
//! - Re-exports the public surface: the Server type (Server.init(handler, config)), the request /
//!   response shapes, the server config, and the shared DispatchModel. The QUIC / TLS / QPACK
//!   machinery is internal.

const server = @import("server.zig");
const core = @import("core.zig");
const Config = @import("config.zig");
const router = @import("router.zig");

/// The HTTP/3 server: Server.init(handler, config), mirroring zix.Http1 / zix.Http2.
pub const Server = server.Server;
/// The application request handler type.
pub const HandlerFn = core.HandlerFn;
/// A decoded HTTP/3 request.
pub const Request = core.Request;
/// The response the handler fills.
pub const Response = core.Response;
/// The per-request env: deadline, io, allocator.
pub const Context = core.Context;
/// The content coding a handler sets on its response body (`res.content_encoding`).
pub const ContentEncoding = core.ContentEncoding;
/// The HTTP/3 server config.
pub const ServerConfig = Config.Http3ServerConfig;
/// The dispatch model, shared with the rest of the engine family (ADR-050).
pub const DispatchModel = Config.DispatchModel;
/// WebTransport over HTTP/3: the application surface (config, callbacks, Session, Stream) and the
/// wire-level building blocks under it. Configured on Http3ServerConfig.webtransport.
pub const Webtransport = @import("webtransport/Webtransport.zig");
/// The comptime router, mirroring zix.Http1 / zix.Http2.
pub const Router = router.Router;
/// A single route entry for the router.
pub const Route = router.Route;
/// Look up a path parameter captured by a PARAM route.
pub const pathParam = router.pathParam;

// Low-level QUIC / TLS / QPACK primitives, exposed so a peer (a hand-rolled client, a test harness)
// or a gateway that terminates QUIC itself can build a wire side of its own. This mirrors how
// zix.Http2 exposes its frame / HPACK primitives: the server is the product, these are the building
// blocks under it.
pub const crypto = @import("crypto.zig");
pub const protection = @import("protection.zig");
pub const keyschedule = @import("keyschedule.zig");
pub const qpack = @import("qpack.zig");
pub const huffman = @import("huffman.zig");
pub const packet = @import("packet.zig");
pub const varint = @import("varint.zig");
pub const frame = @import("frame.zig");
/// TLS-over-QUIC glue: CRYPTO-stream reassembly and the Initial-key discard rules (RFC 9001 4).
pub const quic_tls = @import("tls.zig");
/// The server Initial carrying a ServerHello, built from a parsed ClientHello (RFC 9001 4).
pub const serverhello = @import("serverhello.zig");
/// The server Handshake flight: EncryptedExtensions (ALPN h3 + transport parameters), Certificate,
/// CertificateVerify, Finished.
pub const flight = @import("flight.zig");
/// The client transport parameters carried in the ClientHello (RFC 9000 18).
pub const transport_params = @import("transport_params.zig");
/// The HTTP/3 layer rules: frame types, control-stream state, message validation (RFC 9114).
pub const h3 = @import("h3.zig");
/// Flow control and ACK range arithmetic (RFC 9000 4, 19.3).
pub const flow = @import("flow.zig");
/// Connection close, stateless reset, and the anti-amplification limit (RFC 9000 10, 8.1).
pub const close = @import("close.zig");
/// Loss recovery timing: RTT estimation, probe timeout, congestion control (RFC 9002).
pub const recovery = @import("recovery.zig");
/// Connection-id keyed demux, for a server holding many QUIC connections on one socket.
pub const demux = @import("demux.zig");
/// The stream id namespace and the send / receive state machines (RFC 9000 2, 3).
pub const stream = @import("stream.zig");
/// Frame-level request decode helpers: STREAM frame parsing over a decrypted payload.
pub const request = @import("request.zig");
/// Request-stream reassembly: the buffers a worker holds a request in while its client is still
/// sending it, since a request with a body rarely arrives in one packet.
pub const reassembly = @import("reassembly.zig");
/// Frame builders for the send path: ACK, MAX_DATA, MAX_STREAMS, STREAM.
pub const response = @import("response.zig");
/// TLS 1.3 key schedule the QUIC handshake reuses (transcript hash, HKDF derive).
pub const tls_key_schedule = @import("../../tls/key_schedule.zig");
/// TLS 1.3 handshake messages the QUIC handshake reuses: ClientHello parse and negotiation.
pub const tls_handshake = @import("../../tls/handshake.zig");
