//! zix http client config

const std = @import("std");

const zon_options = @import("zon_options");
/// Default zix http client user agent
pub const user_agent: []const u8 = zon_options.user_agent;

// --------------------------------------------------------- //

/// HTTP protocol version selector for client requests.
///
/// Note:
/// - HTTP_1 is HTTP/1.1 over std.http.Client.
/// - HTTP_2 is h2 over TLS 1.3 via the native zix.Tls client (https only). It validates the server
///   cert against tls_ca_path when tls_verify is set, see the h2_client transport.
/// - HTTP_3 is reserved and returns error.ZixUnsupportedVersion until a backend is wired.
pub const Version = enum {
    HTTP_1,
    HTTP_2,
    HTTP_3,
};

// --------------------------------------------------------- //

/// Configuration for an HTTP client instance.
/// Pass to Http.Client.init(). Fields without defaults (allocator, io) are required.
pub const HttpClientConfig = struct {
    /// Backing allocator for response body and header copies. Caller owns and must outlive the client.
    allocator: std.mem.Allocator,
    /// Event-loop backend. Caller owns and must not deinit while the client is in use.
    io: std.Io,
    /// TCP connect timeout in milliseconds. 0 = no timeout (uses io backend default).
    connect_timeout_ms: u32 = 0,
    /// Time allowed to receive the first response byte after the request is sent, in milliseconds.
    /// 0 = no timeout. Yields error.ZixResponseTimeout when a server accepts the connection and then
    /// never answers, which without a bound parks the caller forever.
    response_timeout_ms: u32 = 0,
    /// Idle bound between response body reads, in milliseconds. The budget restarts on every chunk
    /// that arrives, so a large body is not cut off for being large, only for going quiet.
    /// 0 = no timeout. Yields error.ZixReadTimeout when the body stalls mid-transfer.
    ///
    /// Note:
    /// - Applies to replies that declare a Content-Length. A chunked or close-delimited body has no
    ///   byte count to stop on, so it stays on the unbounded read and only response_timeout_ms
    ///   covers it.
    read_timeout_ms: u32 = 0,
    /// Maximum response body size in bytes. Yields error.ZixBodyTooLarge when exceeded.
    max_response_body: usize = 1024 * 1024 * 4,
    /// Follow HTTP 3xx redirects automatically up to max_redirects hops.
    follow_redirects: bool = true,
    /// Maximum number of automatic redirect hops. Ignored when follow_redirects is false.
    max_redirects: u8 = 3,
    /// Safety bound on the HTTP/2 client read-loop: max frame-read rounds before giving up on a
    /// response. Guards against a stuck peer that never completes a stream.
    h2_max_read_rounds: usize = 4096,
    /// Value sent in the User-Agent request header. Empty string omits the header entirely.
    user_agent: []const u8 = zon_options.user_agent,
    /// HTTP protocol version to use for requests. Default: .HTTP_1.
    /// HTTP_2 = h2 over TLS 1.3 (https only). HTTP_3 yields error.ZixUnsupportedVersion.
    version: Version = .HTTP_1,
    /// PEM path to an extra CA certificate to trust for https requests, in addition to the
    /// system roots. null = system roots only. Use this to trust a self-signed or private-CA
    /// server (the https analogue of pointing curl at --cacert). Loaded once on the first https
    /// request, relative to the process working directory.
    ///
    /// Note:
    /// - For HTTP_2 the native client validates against this anchor ALONE (one-link, no system
    ///   roots yet), so tls_verify with a null tls_ca_path yields error.ZixTlsNoTrustAnchor.
    tls_ca_path: ?[]const u8 = null,
    /// Verify the server certificate (chain + hostname) on https requests. Default true.
    /// Set false to skip verification (insecure, e.g. a throwaway self-signed server in a test).
    /// Applies to the HTTP_2 native path. HTTP_1 (std.http.Client) always verifies.
    tls_verify: bool = true,
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http: HttpClientConfig defaults" {
    const cfg: HttpClientConfig = .{
        .allocator = std.testing.allocator,
        .io = undefined,
    };
    try std.testing.expectEqual(@as(u32, 0), cfg.connect_timeout_ms);
    try std.testing.expectEqual(@as(u32, 0), cfg.response_timeout_ms);
    try std.testing.expectEqual(@as(u32, 0), cfg.read_timeout_ms);
    try std.testing.expectEqual(@as(usize, 1024 * 1024 * 4), cfg.max_response_body);
    try std.testing.expect(cfg.follow_redirects);
    try std.testing.expectEqual(@as(u8, 3), cfg.max_redirects);
    try std.testing.expectEqual(@as(usize, 4096), cfg.h2_max_read_rounds);
    try std.testing.expectEqualStrings(user_agent, cfg.user_agent);
    try std.testing.expectEqual(Version.HTTP_1, cfg.version);
    try std.testing.expect(cfg.tls_verify);
    try std.testing.expectEqual(@as(?[]const u8, null), cfg.tls_ca_path);
}
