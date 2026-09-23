//! zix
//! Zero sIX; 06;
//! A network backend library written in zig

const std = @import("std");
const builtin = @import("builtin");

/// THE ONLY SOURCE OF TRUTH for Zig SEMVER for zix source code.
///
/// Note:
/// - Do not create in other place!
pub const ZIG_SEMVER = struct {
    pub const MAJOR: usize = builtin.zig_version.major;
    pub const MINOR: usize = builtin.zig_version.minor;
    pub const PATCH: usize = builtin.zig_version.patch;
};

/// THE ONLY SOURCE OF TRUTH for the zix package version, taken from
/// build.zig.zon at build time.
///
/// Note:
/// - Anything shipped from this repository reports this string, so a binary
///   never carries a version of its own to drift from the package.
pub const VERSION: []const u8 = @import("zon_options").version;

// --------------------------------------------------------- //

pub const Tcp = @import("tcp/Tcp.zig");
pub const Udp = @import("udp/Udp.zig");
pub const Http = @import("tcp/http/Http.zig");
pub const Http1 = @import("tcp/http1/Http1.zig");
pub const Http2 = @import("tcp/http2/Http2.zig");
pub const Http3 = @import("udp/http3/Http3.zig");
pub const Webrtc = @import("udp/webrtc/Webrtc.zig");
pub const Webtransport = @import("udp/http3/webtransport/Webtransport.zig");
pub const Grpc = @import("tcp/http2/grpc/Grpc.zig");
pub const Fix = @import("tcp/fix/Fix.zig");
pub const Uds = @import("uds/Uds.zig");
pub const Tls = @import("tls/Tls.zig");
pub const Channel = @import("channel/Channel.zig").Channel;
pub const Logger = @import("logger/logger.zig").Logger;

// --------------------------------------------------------- //

pub const Driver = struct {
    /// zix redis internal db driver
    pub const rediz = @import("driver/rediz/src/lib.zig");
    /// zix postgresql internal db driver
    pub const postgrez = @import("driver/postgrez/src/lib.zig");
    /// zix prometheus/node-exporter internal driver
    pub const prometheuz = @import("driver/prometheuz/src/lib.zig");
};

// --------------------------------------------------------- //

/// zix json serialize and deserialize, a standalone package under src/jzon
pub const jzon = @import("jzon/src/lib.zig");

// --------------------------------------------------------- //

pub const utils = struct {
    pub const file = @import("utils/file.zig");
    pub const multipart = @import("utils/multipart.zig");
    pub const media_type = @import("utils/media_type.zig");
    pub const response_cache = @import("utils/response_cache.zig");
    pub const static_cache = @import("utils/static_cache.zig");
    pub const static_send = @import("utils/static_send.zig");
    pub const http_range = @import("utils/http_range.zig");
    pub const dispatch_support = @import("utils/dispatch_support.zig");
    pub const fd_io = @import("utils/fd_io.zig");
    pub const ignore_sigpipe = @import("utils/ignore_sigpipe.zig");
    pub const socket_pair = @import("utils/socket_pair.zig");
    pub const socket_poll = @import("utils/socket_poll.zig");
    pub const socket_cut = @import("utils/socket_cut.zig");
    pub const socket_cut_reader = @import("utils/socket_cut_reader.zig");
    pub const socket_cut_writer = @import("utils/socket_cut_writer.zig");
    pub const socket_connect = @import("utils/socket_connect.zig");
    pub const monotonic_clock = @import("utils/monotonic_clock.zig");
    pub const portable_sleep = @import("utils/portable_sleep.zig");
    pub const peer_addr = @import("utils/peer_addr.zig");
    pub const secure_random = @import("utils/secure_random.zig");
    pub const async_cache = @import("utils/async_cache.zig");
    pub const socket_path = @import("utils/socket_path.zig");
    pub const charsets = @import("utils/charsets.zig");
    pub const generator = @import("utils/generator.zig");
    pub const check = @import("utils/Check.zig");
    pub const base32 = @import("utils/base32.zig");
    pub const base64 = @import("utils/base64.zig");

    pub const compression = @import("utils/compression/compression.zig");
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix version: the package version reaches every consumer of it" {
    try std.testing.expect(VERSION.len != 0);

    // A package version is one token. A space would mean the string came from
    // somewhere other than build.zig.zon.
    try std.testing.expect(std.mem.indexOfScalar(u8, VERSION, ' ') == null);

    // The http client user agent is built from the same zon entry, so the two
    // can never report different versions.
    try std.testing.expect(std.mem.endsWith(u8, Http.default_user_agent, VERSION));
}

test "zix tests: canonical trio surface resolves on both http namespaces" {
    // Namespace-level names shared by zix.Http and zix.Http1.
    const shared_names = .{
        "Server",     "ServerConfig", "DispatchModel",  "HandlerFn",     "Route",
        "RouteKind",  "Request",      "Response",       "Context",       "Method",
        "Status",     "Content",      "ContentType",    "SseWriter",     "Header",
        "HeaderSize", "Multipart",    "MultipartField", "ResponseCache", "setCache",
        "cacheTtl",
    };
    inline for (shared_names) |name| {
        _ = @field(Http, name);
        _ = @field(Http1, name);
    }

    // Canonical caller surface on the trio types, both engines.
    const response_fns = .{
        "setStatus",  "setContentType", "setKeepAlive", "addHeader",     "send",
        "sendJson",   "sendText",       "sendRaw",      "sendNoContent", "sendFromCache",
        "sendCached", "sendNegotiated", "sendStream",
    };
    inline for (response_fns) |name| {
        try std.testing.expect(@hasDecl(Http.Response, name));
        try std.testing.expect(@hasDecl(Http1.Response, name));
    }

    const request_fns = .{
        "method",  "path",      "query",        "queryParam", "queryParams",
        "header",  "pathParam", "pathSegments", "body",       "keepAlive",
        "fromRaw",
    };
    inline for (request_fns) |name| {
        try std.testing.expect(@hasDecl(Http.Request, name));
        try std.testing.expect(@hasDecl(Http1.Request, name));
    }

    const context_fns = .{ "withTimeout", "withDeadline", "setTimeout", "isExpired", "timedOut" };
    inline for (context_fns) |name| {
        try std.testing.expect(@hasDecl(Http.Context, name));
        try std.testing.expect(@hasDecl(Http1.Context, name));
    }
}

test "zix: unit test" {
    // # zix.Http
    std.testing.refAllDecls(@import("tcp/http/method.zig"));
    std.testing.refAllDecls(@import("tcp/http/status.zig"));
    std.testing.refAllDecls(@import("tcp/http/content.zig"));
    std.testing.refAllDecls(@import("tcp/http/parser.zig"));
    std.testing.refAllDecls(@import("tcp/http/context.zig"));
    std.testing.refAllDecls(@import("tcp/http/request.zig"));
    std.testing.refAllDecls(@import("tcp/http/response.zig"));
    std.testing.refAllDecls(@import("tcp/http/router.zig"));
    std.testing.refAllDecls(@import("tcp/http/static.zig"));
    std.testing.refAllDecls(@import("tcp/http/websocket.zig"));
    std.testing.refAllDecls(@import("tcp/http/client_config.zig"));
    std.testing.refAllDecls(@import("tcp/http/config.zig"));
    std.testing.refAllDecls(@import("tcp/http/client.zig"));
    std.testing.refAllDecls(@import("tcp/http/h2_client.zig"));
    std.testing.refAllDecls(@import("tcp/http/server.zig"));
    std.testing.refAllDecls(@import("tcp/http/dispatch/common.zig"));
    std.testing.refAllDecls(@import("tcp/http/dispatch/async.zig"));
    // EPOLL / URING modules are Linux-only, their decls stay out of
    // analysis elsewhere (their tests still collect and self-skip).
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("tcp/http/dispatch/epoll.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("tcp/http/dispatch/uring.zig"));
    std.testing.refAllDecls(@import("tcp/http/tls_serve.zig"));
    std.testing.refAllDecls(@import("tcp/http/sse_client.zig"));
    std.testing.refAllDecls(@import("tcp/http/ws_client.zig"));

    // # zix.Http1
    std.testing.refAllDecls(@import("tcp/http1/core.zig"));
    std.testing.refAllDecls(@import("tcp/http1/parser.zig"));
    std.testing.refAllDecls(@import("tcp/http1/method.zig"));
    std.testing.refAllDecls(@import("tcp/http1/status.zig"));
    std.testing.refAllDecls(@import("tcp/http1/content.zig"));
    std.testing.refAllDecls(@import("tcp/http1/config.zig"));
    std.testing.refAllDecls(@import("tcp/http1/server.zig"));
    std.testing.refAllDecls(@import("tcp/http1/dispatch/common.zig"));
    std.testing.refAllDecls(@import("tcp/http1/dispatch/async.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("tcp/http1/dispatch/epoll.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("tcp/http1/dispatch/uring.zig"));
    std.testing.refAllDecls(@import("tcp/http1/router.zig"));
    std.testing.refAllDecls(@import("tcp/http1/request.zig"));
    std.testing.refAllDecls(@import("tcp/http1/response.zig"));
    std.testing.refAllDecls(@import("tcp/http1/context.zig"));
    std.testing.refAllDecls(@import("tcp/http1/static.zig"));
    std.testing.refAllDecls(@import("tcp/http1/websocket.zig"));

    // # zix.Tls (TLS 1.3 layer)
    std.testing.refAllDecls(@import("tls/wire.zig"));
    std.testing.refAllDecls(@import("tls/key_schedule.zig"));
    std.testing.refAllDecls(@import("tls/record.zig"));
    std.testing.refAllDecls(@import("tls/alert.zig"));
    std.testing.refAllDecls(@import("tls/handshake.zig"));
    std.testing.refAllDecls(@import("tls/extensions.zig"));
    std.testing.refAllDecls(@import("tls/certificate.zig"));
    std.testing.refAllDecls(@import("tls/connection.zig"));
    std.testing.refAllDecls(@import("tls/pem.zig"));
    std.testing.refAllDecls(@import("tls/rsa.zig"));
    std.testing.refAllDecls(@import("tls/std_rsa_verify.zig"));
    std.testing.refAllDecls(@import("tls/montgomery.zig"));
    std.testing.refAllDecls(@import("tls/context.zig"));
    std.testing.refAllDecls(@import("tcp/tls/h2_terminator.zig"));
    std.testing.refAllDecls(@import("tcp/tls/tls_session.zig"));
    std.testing.refAllDecls(@import("tcp/http1/tls_feed.zig"));
    std.testing.refAllDecls(@import("tcp/http1/tls_serve.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("tcp/http1/tls_mux.zig"));

    // # zix.Tls (TLS 1.2 building blocks: PRF schedule, record, version select)
    std.testing.refAllDecls(@import("tls/tls12_prf.zig"));
    std.testing.refAllDecls(@import("tls/tls12_record.zig"));
    std.testing.refAllDecls(@import("tls/tls12_version.zig"));
    std.testing.refAllDecls(@import("tls/tls12_connection.zig"));
    std.testing.refAllDecls(@import("tls/client.zig"));
    std.testing.refAllDecls(@import("tls/tls12_client.zig"));
    std.testing.refAllDecls(@import("tls/dtls_client.zig"));
    std.testing.refAllDecls(@import("tls/cert_verify.zig"));

    // # DTLS 1.2
    std.testing.refAllDecls(@import("tls/dtls_record.zig"));
    std.testing.refAllDecls(@import("tls/dtls_handshake.zig"));
    std.testing.refAllDecls(@import("tls/dtls_hello.zig"));
    std.testing.refAllDecls(@import("tls/dtls_cookie.zig"));
    std.testing.refAllDecls(@import("tls/dtls_flight.zig"));
    std.testing.refAllDecls(@import("tls/dtls_exporter.zig"));
    std.testing.refAllDecls(@import("tls/dtls_use_srtp.zig"));
    std.testing.refAllDecls(@import("tls/dtls_connection.zig"));

    // # zix.io_uring (shared ring runtime, .URING dispatch model)
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("multiplexers/ring.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("multiplexers/ring_wait.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("multiplexers/reuseport.zig"));
    std.testing.refAllDecls(@import("multiplexers/listen_report.zig"));
    std.testing.refAllDecls(@import("multiplexers/slab.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("multiplexers/tls_conn.zig"));

    // # zix.Http2
    std.testing.refAllDecls(@import("tcp/http2/frame.zig"));
    std.testing.refAllDecls(@import("tcp/http2/hpack.zig"));
    std.testing.refAllDecls(@import("tcp/http2/stream_body.zig"));
    std.testing.refAllDecls(@import("tcp/http2/core.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("tcp/http2/mux.zig"));
    std.testing.refAllDecls(@import("tcp/http2/config.zig"));
    std.testing.refAllDecls(@import("tcp/http2/server.zig"));
    std.testing.refAllDecls(@import("tcp/http2/dispatch/common.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("tcp/http2/dispatch/epoll.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("tcp/http2/dispatch/uring.zig"));
    std.testing.refAllDecls(@import("tcp/http2/tls_serve.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("tcp/http2/tls_mux.zig"));

    // # zix.Grpc
    std.testing.refAllDecls(@import("tcp/http2/grpc/status.zig"));
    std.testing.refAllDecls(@import("tcp/http2/grpc/frame.zig"));
    std.testing.refAllDecls(@import("tcp/http2/grpc/proto.zig"));
    std.testing.refAllDecls(@import("tcp/http2/grpc/timeout.zig"));
    std.testing.refAllDecls(@import("tcp/http2/grpc/core.zig"));
    std.testing.refAllDecls(@import("tcp/http2/grpc/mux.zig"));
    std.testing.refAllDecls(@import("tcp/http2/grpc/config.zig"));
    std.testing.refAllDecls(@import("tcp/http2/grpc/server.zig"));
    std.testing.refAllDecls(@import("tcp/http2/grpc/dispatch/common.zig"));
    std.testing.refAllDecls(@import("tcp/http2/grpc/tls_serve.zig"));
    std.testing.refAllDecls(@import("tcp/http2/grpc/client.zig"));

    // # zix.Logger
    std.testing.refAllDecls(@import("logger/logger.zig"));
    std.testing.refAllDecls(@import("logger/sink.zig"));
    std.testing.refAllDecls(@import("logger/flush.zig"));

    // # zix.Utils
    std.testing.refAllDecls(@import("utils/file.zig"));
    std.testing.refAllDecls(@import("utils/multipart.zig"));
    std.testing.refAllDecls(@import("utils/media_type.zig"));
    std.testing.refAllDecls(@import("utils/response_cache.zig"));
    std.testing.refAllDecls(@import("utils/static_cache.zig"));
    std.testing.refAllDecls(@import("utils/static_send.zig"));
    std.testing.refAllDecls(@import("utils/http_range.zig"));
    std.testing.refAllDecls(@import("utils/ignore_sigpipe.zig"));
    std.testing.refAllDecls(@import("utils/dispatch_support.zig"));
    std.testing.refAllDecls(@import("utils/fd_io.zig"));
    std.testing.refAllDecls(@import("utils/socket_pair.zig"));
    std.testing.refAllDecls(@import("utils/socket_poll.zig"));
    std.testing.refAllDecls(@import("utils/socket_cut.zig"));
    std.testing.refAllDecls(@import("utils/socket_cut_reader.zig"));
    std.testing.refAllDecls(@import("utils/socket_cut_writer.zig"));
    std.testing.refAllDecls(@import("utils/socket_connect.zig"));
    std.testing.refAllDecls(@import("utils/monotonic_clock.zig"));
    std.testing.refAllDecls(@import("utils/portable_sleep.zig"));
    std.testing.refAllDecls(@import("utils/peer_addr.zig"));
    std.testing.refAllDecls(@import("utils/secure_random.zig"));
    std.testing.refAllDecls(@import("utils/async_cache.zig"));
    std.testing.refAllDecls(@import("utils/socket_path.zig"));
    std.testing.refAllDecls(@import("utils/counter_scale.zig"));
    std.testing.refAllDecls(@import("utils/compression/flate.zig"));
    std.testing.refAllDecls(@import("utils/compression/flate_fast.zig"));
    std.testing.refAllDecls(@import("utils/compression/brotli.zig"));
    std.testing.refAllDecls(@import("utils/compression/compression.zig"));
    std.testing.refAllDecls(@import("utils/charsets.zig"));
    std.testing.refAllDecls(@import("utils/generator.zig"));
    std.testing.refAllDecls(@import("utils/Check.zig"));
    std.testing.refAllDecls(@import("utils/check/string.zig"));
    std.testing.refAllDecls(@import("utils/base32.zig"));
    std.testing.refAllDecls(@import("utils/base64.zig"));

    // # zix.Udp
    std.testing.refAllDecls(@import("udp/config.zig"));
    std.testing.refAllDecls(@import("udp/packet.zig"));
    std.testing.refAllDecls(@import("udp/server.zig"));
    std.testing.refAllDecls(@import("udp/client.zig"));
    std.testing.refAllDecls(@import("udp/datagram.zig"));
    std.testing.refAllDecls(@import("udp/core.zig"));
    std.testing.refAllDecls(@import("udp/raw.zig"));
    std.testing.refAllDecls(@import("udp/dispatch/common.zig"));
    std.testing.refAllDecls(@import("udp/dispatch/async.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("udp/dispatch/epoll.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("udp/dispatch/uring.zig"));

    // # zix.Http3
    std.testing.refAllDecls(@import("udp/http3/crypto.zig"));
    std.testing.refAllDecls(@import("udp/http3/varint.zig"));
    std.testing.refAllDecls(@import("udp/http3/packet.zig"));
    std.testing.refAllDecls(@import("udp/http3/frame.zig"));
    std.testing.refAllDecls(@import("udp/http3/stream.zig"));
    std.testing.refAllDecls(@import("udp/http3/flow.zig"));
    std.testing.refAllDecls(@import("udp/http3/close.zig"));
    std.testing.refAllDecls(@import("udp/http3/recovery.zig"));
    std.testing.refAllDecls(@import("udp/http3/h3.zig"));
    std.testing.refAllDecls(@import("udp/http3/qpack.zig"));
    std.testing.refAllDecls(@import("udp/http3/qpack_dynamic.zig"));
    std.testing.refAllDecls(@import("udp/http3/tls.zig"));
    std.testing.refAllDecls(@import("udp/http3/protection.zig"));
    std.testing.refAllDecls(@import("udp/http3/serverhello.zig"));
    std.testing.refAllDecls(@import("udp/http3/keyschedule.zig"));
    std.testing.refAllDecls(@import("udp/http3/flight.zig"));
    std.testing.refAllDecls(@import("udp/http3/response.zig"));
    std.testing.refAllDecls(@import("udp/http3/router.zig"));
    std.testing.refAllDecls(@import("udp/http3/huffman.zig"));
    std.testing.refAllDecls(@import("udp/http3/request.zig"));
    std.testing.refAllDecls(@import("udp/http3/reassembly.zig"));
    std.testing.refAllDecls(@import("udp/http3/transport_params.zig"));
    std.testing.refAllDecls(@import("udp/http3/config.zig"));
    std.testing.refAllDecls(@import("udp/http3/core.zig"));
    std.testing.refAllDecls(@import("udp/http3/demux.zig"));
    std.testing.refAllDecls(@import("udp/http3/connection.zig"));
    std.testing.refAllDecls(@import("udp/http3/server.zig"));
    std.testing.refAllDecls(@import("udp/http3/dispatch/common.zig"));
    std.testing.refAllDecls(@import("udp/http3/dispatch/async.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("udp/http3/dispatch/epoll.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("udp/http3/dispatch/uring.zig"));
    std.testing.refAllDecls(@import("udp/http3/Http3.zig"));

    // # webrtc
    std.testing.refAllDecls(@import("udp/webrtc/stun/message.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/stun/binding.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/ice/candidate.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/ice/credentials.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/ice/check.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/ice/lite.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/checksum.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/chunk.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/parameter.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/packet.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/init.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/cookie.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/error_cause.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/teardown.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/heartbeat.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/serial.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/data.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/sack.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/reassembly.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/rto.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/congestion.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/receive_queue.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/forward_tsn.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/send_queue.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/reconfig.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sctp/association.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/datachannel/payload.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/datachannel/dcep.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/datachannel/stream_id.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/datachannel/channel.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/datachannel/registry.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/datachannel/reset.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/datachannel/peer.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/line.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/attribute.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/address.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/media.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/session.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/fingerprint.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/setup.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/candidate.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/offer.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/answer.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/builder.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/direction.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/rtpmap.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/fmtp.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/rtcp_feedback.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/format.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/media_offer.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/sdp/media_answer.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/profile.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/rtp.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/mux.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/rtcp.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/report.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/feedback.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/srtp_cipher.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/srtp_key.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/srtp_auth.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/srtp_index.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/srtp.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/srtcp.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/forward.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/stream_set.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/route.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/media/peer_media.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/demux.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/config.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/timer.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/dtls_session.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/fanout.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/core.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/connection.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/table.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/dialer.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/server.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/dispatch/common.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/dispatch/worker.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/dispatch/async.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("udp/webrtc/dispatch/epoll.zig"));
    if (comptime builtin.os.tag == .linux) std.testing.refAllDecls(@import("udp/webrtc/dispatch/uring.zig"));
    std.testing.refAllDecls(@import("udp/webrtc/Webrtc.zig"));

    // # zix.Tcp (raw)
    std.testing.refAllDecls(@import("tcp/config.zig"));
    std.testing.refAllDecls(@import("tcp/server.zig"));
    std.testing.refAllDecls(@import("tcp/dispatch/common.zig"));
    std.testing.refAllDecls(@import("tcp/client.zig"));

    // # zix.Fix
    std.testing.refAllDecls(@import("tcp/fix/core.zig"));
    std.testing.refAllDecls(@import("tcp/fix/config.zig"));
    std.testing.refAllDecls(@import("tcp/fix/dispatch/common.zig"));
    std.testing.refAllDecls(@import("tcp/fix/server.zig"));
    std.testing.refAllDecls(@import("tcp/fix/client.zig"));
    std.testing.refAllDecls(@import("tcp/fix/router.zig"));

    // # zix.Uds
    std.testing.refAllDecls(@import("uds/config.zig"));
    std.testing.refAllDecls(@import("uds/server.zig"));
    std.testing.refAllDecls(@import("uds/client.zig"));

    // # zix.Channel
    std.testing.refAllDecls(@import("channel/channel.zig"));

    // jzon is a standalone package under src/jzon with its own build files, so
    // its in-file tests belong to `jzon-test-unit` the way each driver's do.
}
