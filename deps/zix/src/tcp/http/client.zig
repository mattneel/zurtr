//! zix http client

const std = @import("std");
const builtin = @import("builtin");
const ZIG_SEMVER = @import("../../lib.zig").ZIG_SEMVER;
const win_io = @import("../../utils/windows_io.zig");
const socket_poll = @import("../../utils/socket_poll.zig");
const Config = @import("client_config.zig");
const HttpClientConfig = Config.HttpClientConfig;
const Method = @import("method.zig");
const h2_client = @import("h2_client.zig");

/// Request body write buffer.
const REQUEST_WRITE_BUF: usize = 8192;
/// Response body transfer buffer.
const BODY_TRANSFER_BUF: usize = 4096;
/// Request path build buffer.
const REQUEST_PATH_BUF: usize = 2048;
/// Request build buffer (request line plus headers).
const REQUEST_BUILD_BUF: usize = 4096;
/// Response head scan buffer.
const HEAD_SCAN_BUF: usize = 8192;
/// Body read chunk buffer.
const BODY_READ_CHUNK: usize = 4096;
/// Response head buffer for a redirect hop (caps the redirect response head size).
const REDIRECT_HEAD_BUF: usize = 8 * 1024;
/// AF_UNIX socket path limit (classic 108-byte sun_path). std caps the path
/// at the filesystem limit on Windows, so the socket limit is enforced here
/// for the same error on every platform.
const UDS_PATH_MAX: usize = 108;

// --------------------------------------------------------- //

/// Options for a single HTTP request. All fields that accept null use the client config value.
pub const RequestOpts = struct {
    /// Additional request headers. Slice must outlive the request call.
    headers: []const std.http.Header = &.{},
    /// Request body bytes. null means no body.
    /// For methods that require a body (POST, PUT, PATCH), null sends Content-Length: 0.
    /// For methods that disallow a body (GET, HEAD, DELETE, OPTIONS, TRACE), body is ignored.
    body: ?[]const u8 = null,
    /// Per-request connect timeout in milliseconds. null uses the client config value.
    connect_timeout_ms: ?u32 = null,
};

// --------------------------------------------------------- //

/// Parsed HTTP response. Caller must call deinit() to release owned memory.
pub const ClientResponse = struct {
    const Self = @This();

    status_code: u16,
    /// Owned body bytes. Released by deinit().
    body_data: []u8,
    /// Owned copy of the raw response head (status line and headers). Released by deinit().
    head_bytes: []u8,
    allocator: std.mem.Allocator,

    // --------------------------------------------------------- //

    /// HTTP status code (e.g. 200, 404).
    pub fn status(self: Self) u16 {
        return self.status_code;
    }

    /// First value of the named response header (case-insensitive). null when absent.
    pub fn header(self: Self, name: []const u8) ?[]const u8 {
        var it = std.http.HeaderIterator.init(self.head_bytes);
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        }
        return null;
    }

    /// Iterator over all response headers as name/value pairs.
    pub fn iterateHeaders(self: Self) std.http.HeaderIterator {
        return std.http.HeaderIterator.init(self.head_bytes);
    }

    /// Response body bytes. Empty slice when the server sent no body.
    pub fn body(self: Self) []const u8 {
        return self.body_data;
    }

    /// Release body and head memory.
    pub fn deinit(self: *Self) void {
        if (self.body_data.len > 0) self.allocator.free(self.body_data);
        if (self.head_bytes.len > 0) self.allocator.free(self.head_bytes);
    }
};

// --------------------------------------------------------- //

/// HTTP client. One instance can make many sequential requests, reusing connections via the pool.
///
/// Usage:
/// ```zig
/// var client = zix.Http.Client.init(config);
/// defer client.deinit();
/// var resp = try client.get("http://localhost:9000/", .{});
/// defer resp.deinit();
/// std.debug.print("{d}: {s}\n", .{ resp.status(), resp.body() });
/// ```
pub const HttpClient = struct {
    const Self = @This();

    config: HttpClientConfig,
    inner: std.http.Client,

    // --------------------------------------------------------- //

    /// Initialise the client. No connections are opened until the first request.
    pub fn init(config: HttpClientConfig) Self {
        return .{
            .config = config,
            .inner = .{ .allocator = config.allocator, .io = config.io },
        };
    }

    /// Close all pooled connections and free client memory.
    /// Must not be called while a request is in flight.
    pub fn deinit(self: *Self) void {
        self.inner.deinit();
    }

    // --------------------------------------------------------- //

    pub fn get(self: *Self, url: []const u8, opts: RequestOpts) !ClientResponse {
        return self.request(.GET, url, opts);
    }

    pub fn head(self: *Self, url: []const u8, opts: RequestOpts) !ClientResponse {
        return self.request(.HEAD, url, opts);
    }

    pub fn post(self: *Self, url: []const u8, opts: RequestOpts) !ClientResponse {
        return self.request(.POST, url, opts);
    }

    pub fn put(self: *Self, url: []const u8, opts: RequestOpts) !ClientResponse {
        return self.request(.PUT, url, opts);
    }

    pub fn delete(self: *Self, url: []const u8, opts: RequestOpts) !ClientResponse {
        return self.request(.DELETE, url, opts);
    }

    pub fn patch(self: *Self, url: []const u8, opts: RequestOpts) !ClientResponse {
        return self.request(.PATCH, url, opts);
    }

    // --------------------------------------------------------- //

    /// Make an HTTP request and return the parsed response.
    ///
    /// Note:
    /// - HTTP_2 (config.version) takes the native h2-over-TLS path (requestHttp2), https only.
    ///   HTTP_3 returns error.ZixUnsupportedVersion.
    ///
    /// Errors (named):
    /// error.ZixUrlMalformed        - the URL does not parse
    /// error.ZixUrlSchemeUnsupported - the scheme is not one this transport speaks
    /// error.ZixUrlHostMissing      - the URL carries no host
    /// error.ZixUrlPathTooLong      - the path and query do not fit the request buffer
    /// error.ZixBodyTooLarge        - response body exceeded config.max_response_body bytes
    /// error.ZixResponseTimeout     - no first response byte within config.response_timeout_ms
    /// error.ZixReadTimeout         - response body went quiet for config.read_timeout_ms
    /// error.ZixUnsupportedVersion  - config.version is HTTP_3
    /// error.ZixUnsupportedScheme   - HTTP_2 was requested for a non-https URL
    /// error.ZixTlsNoTrustAnchor    - HTTP_2 with tls_verify set but no tls_ca_path
    ///
    /// Other errors propagate from std.http.Client (network failures, protocol errors, OOM).
    pub fn request(self: *Self, method: Method.Code, url: []const u8, opts: RequestOpts) !ClientResponse {
        switch (self.config.version) {
            .HTTP_1 => {},
            .HTTP_2 => return self.requestHttp2(method, url, opts),
            .HTTP_3 => return error.ZixUnsupportedVersion,
        }

        // Settled before anything is opened, so a method this transport cannot put
        // on the wire costs no socket and no DNS lookup.
        const std_method = try methodToStd(method);

        const gpa = self.config.allocator;

        const uri = std.Uri.parse(url) catch return error.ZixUrlMalformed;
        const protocol = std.http.Client.Protocol.fromUri(uri) orelse return error.ZixUrlSchemeUnsupported;

        var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
        const host_name = (if (ZIG_SEMVER.MINOR == 16)
            uri.getHost(&host_buf)
        else
            std.Io.net.HostName.fromUri(uri, &host_buf)) catch return error.ZixUrlHostMissing;
        const port = uri.port orelse switch (protocol) {
            .plain => @as(u16, 80),
            .tls => @as(u16, 443),
        };

        const connect_ms = opts.connect_timeout_ms orelse self.config.connect_timeout_ms;
        const timeout: std.Io.Timeout = if (connect_ms > 0) .{
            .duration = .{
                .raw = std.Io.Duration.fromMilliseconds(@as(i64, connect_ms)),
                .clock = .real,
            },
        } else .none;

        // https needs the inner std.http.Client's realtime clock + CA bundle set before the
        // handshake (zix connects directly, so std's own lazy init in its request flow does not
        // run first). Use std's own clock choice (Io.Clock.real), load the system roots, then add
        // the configured extra CA (tls_ca_path). Done once.
        if (protocol == .tls and self.inner.now == null) {
            const now = std.Io.Clock.real.now(self.config.io);

            // A failed rescan is not fatal: a caller who named tls_ca_path may not want the system
            // roots at all. It is not nothing either, so it comes back as its own name rather than
            // being dropped, and the caller decides.
            var roots_loaded = true;
            self.inner.ca_bundle.rescan(gpa, self.config.io, now) catch {
                roots_loaded = false;
            };

            if (self.config.tls_ca_path) |ca_path| {
                self.inner.ca_bundle.addCertsFromFilePath(gpa, self.config.io, now, std.Io.Dir.cwd(), ca_path) catch |err| return switch (err) {
                    error.FileNotFound => error.ZixTlsCaFileNotFound,
                    error.IsDir => error.ZixTlsCaPathIsDirectory,
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.ZixTlsCaLoadFailed,
                };
            } else if (!roots_loaded) {
                // No configured anchor and no system roots, so every verification below would fail
                // for a reason that had already been thrown away.
                return error.ZixTlsSystemRootsUnavailable;
            }

            self.inner.now = now;
        }

        const conn = try self.inner.connectTcpOptions(.{
            .host = host_name,
            .port = port,
            .protocol = protocol,
            .timeout = timeout,
        });

        const redirect_behavior: std.http.Client.Request.RedirectBehavior = if (!self.config.follow_redirects)
            .unhandled
        else if (self.config.max_redirects == 0)
            .not_allowed
        else
            std.http.Client.Request.RedirectBehavior.init(@as(u16, self.config.max_redirects));

        var req = try self.inner.request(std_method, uri, .{
            .connection = conn,
            .redirect_behavior = redirect_behavior,
            .extra_headers = opts.headers,
            .headers = .{
                .user_agent = if (self.config.user_agent.len > 0)
                    .{ .override = self.config.user_agent }
                else
                    .omit,
            },
        });
        defer req.deinit();

        if (std_method.requestHasBody()) {
            const b = opts.body orelse &.{};
            req.transfer_encoding = .{ .content_length = b.len };
            var write_buf: [REQUEST_WRITE_BUF]u8 = undefined;
            var body_writer = try req.sendBodyUnflushed(&write_buf);
            if (b.len > 0) try body_writer.writer.writeAll(b);
            try body_writer.end();
        } else {
            try req.sendBodiless();
        }

        const conn_handle = conn.stream_reader.stream.socket.handle;

        // The request is out, so everything below waits on the peer. A server that accepts and then
        // never answers parks receiveHead forever without this gate.
        if (!readableWithin(conn_handle, self.config.response_timeout_ms)) return error.ZixResponseTimeout;

        var redirect_buf: [REDIRECT_HEAD_BUF]u8 = undefined;
        var response = try req.receiveHead(&redirect_buf);

        // Copy head bytes before response.reader() invalidates the pointer.
        const head_copy = try gpa.dupe(u8, response.head.bytes);
        errdefer gpa.free(head_copy);

        const status_code: u16 = @intFromEnum(response.head.status);

        var transfer_buf: [BODY_TRANSFER_BUF]u8 = undefined;
        const body_reader = response.reader(&transfer_buf);

        // Bounded only when the reply declares its length, since the bounded loop stops on the byte
        // count. A chunked or close-delimited body keeps std's own read, which ends on the stream.
        const declared: ?usize = if (self.config.read_timeout_ms == 0)
            null
        else if (response.head.content_length) |len|
            std.math.cast(usize, len) orelse return error.ZixBodyTooLarge
        else
            null;

        const body_bytes = if (declared) |expected| blk: {
            if (expected > self.config.max_response_body) return error.ZixBodyTooLarge;

            break :blk try readBodyBounded(gpa, body_reader, conn, self.config.read_timeout_ms, expected);
        } else body_reader.allocRemaining(gpa, .limited(self.config.max_response_body)) catch |err| switch (err) {
            error.StreamTooLong => return error.ZixBodyTooLarge,
            else => |e| return e,
        };

        return .{
            .status_code = status_code,
            .body_data = body_bytes,
            .head_bytes = head_copy,
            .allocator = gpa,
        };
    }

    // --------------------------------------------------------- //

    /// HTTP/2 over TLS 1.3 via the native zix.Tls client (the h2_client transport). https only,
    /// since h2 here is always ALPN-negotiated over TLS. Trust + cert verification follow the config
    /// (tls_verify / tls_ca_path), see h2_client.fetch.
    fn requestHttp2(self: *Self, method: Method.Code, url: []const u8, opts: RequestOpts) !ClientResponse {
        const gpa = self.config.allocator;

        const uri = std.Uri.parse(url) catch return error.ZixUrlMalformed;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) return error.ZixUnsupportedScheme;

        var host_buf: [std.Io.net.HostName.max_len]u8 = undefined;
        const host_name = (if (ZIG_SEMVER.MINOR == 16)
            uri.getHost(&host_buf)
        else
            std.Io.net.HostName.fromUri(uri, &host_buf)) catch return error.ZixUrlHostMissing;
        const port = uri.port orelse 443;

        // origin-form request target (:path), the path plus any query, e.g. "/echo?foo=bar".
        var path_buf: [REQUEST_PATH_BUF]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{f}", .{uri.fmt(.{ .path = true, .query = true })}) catch return error.ZixUrlPathTooLong;

        const parts = try h2_client.fetch(self.config, method, host_name, port, path, opts.headers, opts.body);

        return .{
            .status_code = parts.status_code,
            .body_data = parts.body_data,
            .head_bytes = parts.head_bytes,
            .allocator = gpa,
        };
    }

    // --------------------------------------------------------- //

    /// Make an HTTP/1.1 GET over a Unix domain socket.
    ///
    /// Param:
    /// socket_path - []const u8 (path to the Unix socket file)
    /// http_path   - []const u8 (HTTP path, e.g. "/api/v1/info")
    /// opts        - RequestOpts
    ///
    /// Return:
    /// - ClientResponse
    /// - error.ZixUdsNotSupported (non-Unix platform)
    /// - error.ZixInvalidPath (path rejected by the OS)
    pub fn getUds(self: *Self, socket_path: []const u8, http_path: []const u8, opts: RequestOpts) !ClientResponse {
        return self.requestUds(.GET, socket_path, http_path, opts);
    }

    /// Make an HTTP/1.1 POST over a Unix domain socket.
    ///
    /// Param:
    /// socket_path - []const u8 (path to the Unix socket file)
    /// http_path   - []const u8 (HTTP path)
    /// opts        - RequestOpts
    ///
    /// Return:
    /// - ClientResponse
    pub fn postUds(self: *Self, socket_path: []const u8, http_path: []const u8, opts: RequestOpts) !ClientResponse {
        return self.requestUds(.POST, socket_path, http_path, opts);
    }

    /// Make an HTTP/1.1 request over a Unix domain socket.
    ///
    /// Note:
    /// - Sends Connection: close so the server closes after the response.
    ///   Content-Length is read when present, otherwise body is read until EOF.
    /// - wss:// and TLS are not supported. Use the TCP-based request() for those.
    ///
    /// Param:
    /// method      - Method.Code
    /// socket_path - []const u8 (path to the Unix socket file)
    /// http_path   - []const u8 (HTTP path, e.g. "/v1/info")
    /// opts        - RequestOpts
    ///
    /// Return:
    /// - ClientResponse
    /// - error.ZixUdsNotSupported (non-Unix platform)
    /// - error.ZixInvalidPath (socket path longer than 108 bytes or rejected by OS)
    /// - error.ZixBodyTooLarge (response body exceeded config.max_response_body)
    pub fn requestUds(self: *Self, method: Method.Code, socket_path: []const u8, http_path: []const u8, opts: RequestOpts) !ClientResponse {
        if (comptime !std.Io.net.has_unix_sockets) return error.ZixUdsNotSupported;
        if (socket_path.len > UDS_PATH_MAX) return error.ZixInvalidPath;

        const gpa = self.config.allocator;

        const unix_addr = std.Io.net.UnixAddress.init(socket_path) catch return error.ZixInvalidPath;
        const uds_stream = try unix_addr.connect(self.config.io);
        defer uds_stream.close(self.config.io);
        const fd = uds_stream.socket.handle;

        const method_name = udsMethodStr(method);

        var req_buf: [REQUEST_BUILD_BUF]u8 = undefined;
        var req_len: usize = 0;

        const status_line = std.fmt.bufPrint(
            req_buf[req_len..],
            "{s} {s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n",
            .{ method_name, http_path },
        ) catch return error.ZixInvalidPath;
        req_len += status_line.len;

        for (opts.headers) |hdr| {
            const h = std.fmt.bufPrint(req_buf[req_len..], "{s}: {s}\r\n", .{ hdr.name, hdr.value }) catch break;
            req_len += h.len;
        }

        if (opts.body) |body| {
            const cl_line = std.fmt.bufPrint(req_buf[req_len..], "Content-Length: {d}\r\n\r\n", .{body.len}) catch return error.ZixInvalidPath;
            req_len += cl_line.len;
            try udsWriteAll(fd, req_buf[0..req_len]);
            try udsWriteAll(fd, body);
        } else {
            const end = std.fmt.bufPrint(req_buf[req_len..], "\r\n", .{}) catch return error.ZixInvalidPath;
            req_len += end.len;
            try udsWriteAll(fd, req_buf[0..req_len]);
        }

        var head_scan_buf: [HEAD_SCAN_BUF]u8 = undefined;
        var head_scan_len: usize = 0;
        var header_end: usize = 0;

        while (head_scan_len < head_scan_buf.len) {
            if (!readableWithin(fd, self.config.response_timeout_ms)) return error.ZixResponseTimeout;

            const n = readOnceFD(fd, head_scan_buf[head_scan_len..]) catch return error.ZixConnectionClosed;
            if (n == 0) return error.ZixConnectionClosed;
            head_scan_len += n;
            if (std.mem.indexOf(u8, head_scan_buf[0..head_scan_len], "\r\n\r\n")) |pos| {
                header_end = pos + 4;
                break;
            }
        }

        if (header_end == 0) return error.ZixInvalidResponse;

        const head_raw = head_scan_buf[0..header_end];

        const status_code: u16 = blk: {
            const first_line_end = std.mem.indexOfScalar(u8, head_raw, '\r') orelse break :blk 0;
            const first_line = head_raw[0..first_line_end];
            const space1 = std.mem.indexOfScalar(u8, first_line, ' ') orelse break :blk 0;
            const after_sp = first_line[space1 + 1 ..];
            const space2 = std.mem.indexOfScalar(u8, after_sp, ' ') orelse after_sp.len;
            break :blk std.fmt.parseInt(u16, after_sp[0..space2], 10) catch 0;
        };

        const head_copy = try gpa.dupe(u8, head_raw);
        errdefer gpa.free(head_copy);

        const content_length: ?usize = blk: {
            const cl_val = udsResponseHeader(head_raw, "content-length") orelse break :blk null;
            break :blk std.fmt.parseInt(usize, std.mem.trim(u8, cl_val, " \t"), 10) catch null;
        };

        const already_read = head_scan_len - header_end;

        var body_list: std.ArrayList(u8) = .empty;
        errdefer body_list.deinit(gpa);

        if (content_length) |cl| {
            if (cl > self.config.max_response_body) return error.ZixBodyTooLarge;
            try body_list.resize(gpa, cl);
            const initial = @min(already_read, cl);
            @memcpy(body_list.items[0..initial], head_scan_buf[header_end..][0..initial]);
            var body_received = initial;
            while (body_received < cl) {
                if (!readableWithin(fd, self.config.read_timeout_ms)) return error.ZixReadTimeout;

                const n = readOnceFD(fd, body_list.items[body_received..]) catch break;
                if (n == 0) break;
                body_received += n;
            }
        } else {
            if (already_read > 0) try body_list.appendSlice(gpa, head_scan_buf[header_end..][0..already_read]);
            var read_chunk: [BODY_READ_CHUNK]u8 = undefined;
            while (true) {
                if (!readableWithin(fd, self.config.read_timeout_ms)) return error.ZixReadTimeout;

                const n = readOnceFD(fd, &read_chunk) catch break;
                if (n == 0) break;
                if (body_list.items.len + n > self.config.max_response_body) return error.ZixBodyTooLarge;
                try body_list.appendSlice(gpa, read_chunk[0..n]);
            }
        }

        const body_bytes = try body_list.toOwnedSlice(gpa);

        return ClientResponse{
            .status_code = status_code,
            .body_data = body_bytes,
            .head_bytes = head_copy,
            .allocator = gpa,
        };
    }

    // --------------------------------------------------------- //

    /// Map a zix method onto the std.http method this transport takes
    ///
    /// Note:
    /// - std.http.Method is a closed set of the nine methods RFC 9110 defines.
    ///   QUERY (RFC 10008) has no member there, so this transport cannot put one
    ///   on the wire. It reports that rather than substituting a method with
    ///   different semantics and different body framing
    /// - requestUds writes the request line itself, so that path does carry QUERY
    ///
    /// Param:
    /// method - Method.Code
    ///
    /// Return:
    /// - std.http.Method
    /// - error.UnsupportedMethod when std names no equivalent
    fn methodToStd(method: Method.Code) error{UnsupportedMethod}!std.http.Method {
        return switch (method) {
            .GET => .GET,
            .HEAD => .HEAD,
            .POST => .POST,
            .PUT => .PUT,
            .DELETE => .DELETE,
            .PATCH => .PATCH,
            .OPTIONS => .OPTIONS,
            .TRACE => .TRACE,
            .CONNECT => .CONNECT,
            .QUERY => error.UnsupportedMethod,
        };
    }
};

// --------------------------------------------------------- //

fn udsMethodStr(method: Method.Code) []const u8 {
    return switch (method) {
        .GET => "GET",
        .HEAD => "HEAD",
        .POST => "POST",
        .PUT => "PUT",
        .DELETE => "DELETE",
        .PATCH => "PATCH",
        .OPTIONS => "OPTIONS",
        .TRACE => "TRACE",
        .CONNECT => "CONNECT",
        .QUERY => "QUERY",
    };
}

/// Readiness gate shared with the SSE and WebSocket clients. Under https it means bytes arrived on
/// the wire, not that a whole TLS record is there, so it bounds liveness rather than record framing.
const readableWithin = socket_poll.readableWithin;

/// Whether any byte of the response is already in userspace, anywhere along the reader chain.
///
/// Note:
/// - This is what makes a socket-readiness gate safe to compose with a buffered reader. receiveHead
///   reads the head and whatever body bytes rode the same packet into the connection buffer, so the
///   socket can be silent while the body is already in hand. Polling then would wait out the whole
///   budget and report a timeout on a response that already arrived.
/// - Three levels because the chain differs by scheme: the body reader decodes, and under https the
///   connection reader holds decrypted bytes while stream_reader holds the raw ones. On plain http
///   the middle and last are the same reader, which costs one redundant load.
///
/// Param:
/// body_reader - *std.Io.Reader (the decoded body reader)
/// conn - *std.http.Client.Connection (the live connection)
///
/// Return:
/// - true when a read can be served without touching the socket
fn anyBuffered(body_reader: *std.Io.Reader, conn: *std.http.Client.Connection) bool {
    return body_reader.bufferedLen() > 0 or
        conn.reader().bufferedLen() > 0 or
        conn.stream_reader.interface.bufferedLen() > 0;
}

/// Read a declared-length response body with an idle bound between socket reads.
///
/// Note:
/// - The loop ends on the byte count, never on end of stream. A finished body leaves the socket
///   quiet, so a gate placed after the last byte would wait out its full budget on a complete
///   response.
/// - The budget covers one quiet stretch, not the whole transfer, so a large body is never cut off
///   for being large.
/// - Needs the length up front, so it serves content-length replies only. A chunked or
///   close-delimited body has no count to stop on and stays on the caller's unbounded path.
///
/// Param:
/// gpa - std.mem.Allocator (owns the returned slice)
/// reader - *std.Io.Reader (the decoded body reader)
/// conn - *std.http.Client.Connection (polled between reads, and asked what it already holds)
/// idle_ms - u32 (budget for one read, restarted on every chunk that arrives)
/// expected - usize (declared body length, from the Content-Length header)
///
/// Return:
/// - the body bytes, owned by gpa
/// - error.ZixReadTimeout when no byte arrives inside idle_ms
fn readBodyBounded(
    gpa: std.mem.Allocator,
    reader: *std.Io.Reader,
    conn: *std.http.Client.Connection,
    idle_ms: u32,
    expected: usize,
) ![]u8 {
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(gpa);

    try body.ensureTotalCapacity(gpa, expected);

    while (body.items.len < expected) {
        if (!anyBuffered(reader, conn)) {
            if (!readableWithin(conn.stream_reader.stream.socket.handle, idle_ms)) return error.ZixReadTimeout;
        }

        // A peer that closes early ends the body short rather than hanging the caller. The status
        // and head are already parsed, so the caller still sees a usable response.
        reader.fill(1) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };

        const chunk = reader.buffered();
        const wanted = @min(chunk.len, expected - body.items.len);

        try body.appendSlice(gpa, chunk[0..wanted]);
        reader.toss(wanted);
    }

    return body.toOwnedSlice(gpa);
}

/// Read some bytes from fd: the ntdll shim on Windows, std.posix.read elsewhere.
fn readOnceFD(fd: std.posix.fd_t, buf: []u8) !usize {
    if (comptime builtin.os.tag == .windows) return win_io.readOnce(fd, buf);

    return std.posix.read(fd, buf);
}

fn udsWriteAll(fd: std.posix.fd_t, data: []const u8) !void {
    if (comptime builtin.os.tag == .windows) return win_io.writeAll(fd, data) catch error.BrokenPipe;

    var written: usize = 0;
    while (written < data.len) {
        const rc = std.posix.system.write(fd, data[written..].ptr, data.len - written);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.BrokenPipe;
                written += n;
            },
            .INTR => continue,
            else => return error.BrokenPipe,
        }
    }
}

fn udsResponseHeader(head: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, head, "\r\n");
    _ = it.next();
    while (it.next()) |line| {
        const colon_pos = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const header_name = std.mem.trim(u8, line[0..colon_pos], " \t");
        if (std.ascii.eqlIgnoreCase(header_name, name)) {
            return std.mem.trim(u8, line[colon_pos + 1 ..], " \t");
        }
    }
    return null;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix http: http client, HTTP_2 over a non-https URL is rejected before connecting" {
    // requestHttp2 checks the scheme up front, so io is never touched (undefined is safe here).
    var client = HttpClient.init(.{
        .allocator = std.testing.allocator,
        .io = undefined,
        .version = .HTTP_2,
    });
    defer client.deinit();

    try std.testing.expectError(error.ZixUnsupportedScheme, client.get("http://localhost:9061/", .{}));
}

test "zix http: http client, HTTP_3 still yields UnsupportedVersion" {
    var client = HttpClient.init(.{
        .allocator = std.testing.allocator,
        .io = undefined,
        .version = .HTTP_3,
    });
    defer client.deinit();

    try std.testing.expectError(error.ZixUnsupportedVersion, client.get("https://localhost:9061/", .{}));
}

test "zix http: http client, a server that never answers yields ResponseTimeout" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Never accepted on purpose. The kernel completes the handshake into the backlog either way, so
    // the client connects and sends fine and then waits on a reply that never comes. That is what a
    // parked server looks like from the client side, and with no bound the wait has no end.
    const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 9066);
    var silent = try addr.listen(io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 8, .reuse_address = true });
    defer silent.deinit(io);

    var client = HttpClient.init(.{
        .allocator = std.testing.allocator,
        .io = io,
        .connect_timeout_ms = 3000,
        .response_timeout_ms = 150,
    });
    defer client.deinit();

    try std.testing.expectError(error.ZixResponseTimeout, client.get("http://127.0.0.1:9066/", .{}));
}

test "zix http: http client, a complete reply is not cut short by an idle bound" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 9069);
    var listener = try addr.listen(io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 8, .reuse_address = true });
    defer listener.deinit(io);

    // Head and body land in one write, so both sit in the connection buffer while the socket goes
    // quiet. A gate that only asks the socket times out here on a response already in hand, which
    // is exactly what this guards.
    const Whole = struct {
        fn serve(listen_srv: *std.Io.net.Server, srv_io: std.Io, release: *std.atomic.Value(bool)) void {
            const stream = listen_srv.accept(srv_io) catch return;
            defer stream.close(srv_io);

            // Drain the request first. Closing a socket that still holds unread bytes is an
            // abortive close, and Windows then discards the reply this test just wrote and fails
            // the client's read with LOCAL_DISCONNECT instead of delivering it.
            var scratch: [1024]u8 = undefined;
            var reader = stream.reader(srv_io, &scratch);
            while (reader.interface.takeDelimiterInclusive('\n') catch null) |line| {
                if (line.len <= 2) break;
            }

            var sink: [256]u8 = undefined;
            var writer = stream.writer(srv_io, &sink);
            writer.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nwhole") catch return;
            writer.interface.flush() catch return;

            // Held open until the client is done, for the same reason: the close must not race the
            // read it is answering. The round cap is only a backstop against an unjoinable thread.
            var rounds: usize = 0;
            while (!release.load(.acquire) and rounds < 5000) : (rounds += 1) {
                std.Io.sleep(srv_io, std.Io.Duration.fromMilliseconds(1), .awake) catch break;
            }
        }
    };

    var release: std.atomic.Value(bool) = .init(false);
    const serve_thread = try std.Thread.spawn(.{}, Whole.serve, .{ &listener, io, &release });
    defer serve_thread.join();

    var client = HttpClient.init(.{
        .allocator = std.testing.allocator,
        .io = io,
        .connect_timeout_ms = 3000,
        .response_timeout_ms = 3000,
        .read_timeout_ms = 150,
    });
    defer client.deinit();

    const outcome = client.get("http://127.0.0.1:9069/", .{});
    release.store(true, .release);

    var resp = try outcome;
    defer resp.deinit();

    try std.testing.expectEqual(@as(u16, 200), resp.status());
    try std.testing.expectEqualStrings("whole", resp.body());
}

test "zix http: http client, a body that goes quiet mid-transfer yields ReadTimeout" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 9068);
    var listener = try addr.listen(io, .{ .mode = .stream, .protocol = .tcp, .kernel_backlog = 8, .reuse_address = true });
    defer listener.deinit(io);

    // Promises 100 body bytes, sends 5, then holds the connection open. Closing instead would hand
    // the client a clean end of stream, which is a different outcome than the stall under test.
    const Stall = struct {
        fn serve(listen_srv: *std.Io.net.Server, srv_io: std.Io, release: *std.atomic.Value(bool)) void {
            const stream = listen_srv.accept(srv_io) catch return;
            defer stream.close(srv_io);

            var sink: [256]u8 = undefined;
            var writer = stream.writer(srv_io, &sink);
            writer.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nfive!") catch return;
            writer.interface.flush() catch return;

            // Released the moment the client call returns. The round cap is only a backstop so a
            // broken expectation cannot leave this thread unjoinable.
            var rounds: usize = 0;
            while (!release.load(.acquire) and rounds < 5000) : (rounds += 1) {
                std.Io.sleep(srv_io, std.Io.Duration.fromMilliseconds(1), .awake) catch break;
            }
        }
    };

    var release: std.atomic.Value(bool) = .init(false);
    const stall_thread = try std.Thread.spawn(.{}, Stall.serve, .{ &listener, io, &release });
    defer stall_thread.join();

    var client = HttpClient.init(.{
        .allocator = std.testing.allocator,
        .io = io,
        .connect_timeout_ms = 3000,
        .response_timeout_ms = 3000,
        .read_timeout_ms = 150,
    });
    defer client.deinit();

    const outcome = client.get("http://127.0.0.1:9068/", .{});
    release.store(true, .release);

    try std.testing.expectError(error.ZixReadTimeout, outcome);
}

test "zix http: http client, QUERY is refused before a socket is opened" {
    // std.http.Method is a closed set that predates RFC 10008, so this transport
    // has no QUERY to map onto. The refusal happens before any connect, so io is
    // never touched (undefined is safe here).
    var client = HttpClient.init(.{
        .allocator = std.testing.allocator,
        .io = undefined,
    });
    defer client.deinit();

    try std.testing.expectError(
        error.UnsupportedMethod,
        client.request(.QUERY, "http://localhost:9061/search", .{}),
    );
}

test "zix http: http client, methodToStd maps the nine std names and refuses QUERY" {
    try std.testing.expectEqual(std.http.Method.GET, try HttpClient.methodToStd(.GET));
    try std.testing.expectEqual(std.http.Method.POST, try HttpClient.methodToStd(.POST));
    try std.testing.expectEqual(std.http.Method.PATCH, try HttpClient.methodToStd(.PATCH));

    try std.testing.expectError(error.UnsupportedMethod, HttpClient.methodToStd(.QUERY));
}

test "zix http: http client, the uds path does name QUERY on its request line" {
    // requestUds writes the request line itself rather than handing the method to
    // std, so it is the one client path that can put a QUERY on the wire.
    try std.testing.expectEqualStrings("QUERY", udsMethodStr(.QUERY));
}
