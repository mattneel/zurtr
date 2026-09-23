//! zixer h3 edge: the QUIC client edge for one http3 site (rfc 9114)

const std = @import("std");
const zix = @import("zix");

const h3_conn = @import("h3_conn.zig");
const h3_frames = @import("h3_frames.zig");
const h3_qpack = @import("h3_qpack.zig");
const h3_streams = @import("h3_streams.zig");
const h3_translate = @import("h3_translate.zig");
const bind_options = @import("bind_options.zig");
const http1_head = @import("http1_head.zig");
const process_gate = @import("process_gate.zig");
const process_wait = @import("process_wait.zig");
const cfg_headers = @import("cfg_headers.zig");
const fault = @import("fault.zig");
const proxy_headers = @import("proxy_headers.zig");
const request_scheme = @import("request_scheme.zig");
const site_cfg = @import("site_cfg.zig");
const static_cached = @import("static_cached.zig");
const static_files = @import("static_files.zig");
const tls_edge = @import("tls_edge.zig");
const site_sweep = @import("site_sweep.zig");
const upstream_conn = @import("upstream_conn.zig");
const upstream_deadline = @import("upstream_deadline.zig");
const upstream_pool = @import("upstream_pool.zig");
const upstream_status = @import("upstream_status.zig");

const monotonic_clock = zix.utils.monotonic_clock;
const socket_poll = zix.utils.socket_poll;

/// Connections one h3 site holds at once. A new client past this is ignored
/// until a slot frees, the same shape as the udp forward's flow table.
pub const MAX_CONNS: usize = 64;

/// Largest datagram the edge receives. Nothing a QUIC peer sends is bigger.
const MAX_DATAGRAM: usize = 2048;

/// Receive poll slice, which is also how often the maintenance sweep runs.
const POLL_MS: u32 = 25;

/// Consecutive receive failures before the loop gives up.
const MAX_RECEIVE_FAILURES: usize = 100;

/// Read buffer for one upstream leg.
const STREAM_BUF_SIZE: usize = 16 * 1024;

/// Body bytes moved per relay step.
const RELAY_CHUNK: usize = 8 * 1024;

/// Response bytes allowed to sit unsent on one stream before the relay waits
/// for the client to acknowledge. This is what keeps a slow client from
/// pulling a whole upstream body into memory.
const QUEUE_HIGH_WATER: usize = 256 * 1024;

/// Longest a relay waits for that queue to drain before giving the client up.
const QUEUE_WAIT_MS: usize = 30_000;

/// Interim 1xx heads relayed before an upstream is called broken.
const MAX_INTERIM: usize = 8;

/// Recently served streams remembered per connection, so a retransmitted
/// request is not proxied twice.
const SERVED_MEMORY: usize = 32;

/// One QUIC connection slot the site owns.
///
/// Note:
/// - `lock` guards the connection. The receive thread and every request task
///   take it, and no one holds it across an upstream call.
/// - Only the receive thread creates and frees slots. `tasks` counts the live
///   request tasks pointing here, so a slot is freed only once they are gone.
const ConnSlot = struct {
    conn: h3_conn.Conn,
    lock: std.atomic.Value(bool) = .init(false),
    tasks: usize = 0,
    gone: bool = false,
    served: [SERVED_MEMORY]u64 = @splat(std.math.maxInt(u64)),
    served_cursor: usize = 0,

    /// Whether this request stream was already handed to a task.
    fn alreadyServed(slot: *const ConnSlot, stream_id: u64) bool {
        for (slot.served) |seen| {
            if (seen == stream_id) return true;
        }

        return false;
    }

    fn markServed(slot: *ConnSlot, stream_id: u64) void {
        slot.served[slot.served_cursor] = stream_id;
        slot.served_cursor = (slot.served_cursor + 1) % SERVED_MEMORY;
    }
};

/// Everything one serving http3 site owns.
///
/// Note:
/// - pool and idle exist only when the site has upstreams, a static-only site
///   leaves both null.
/// - sweeper runs only on a site that has an idle cache, and hands aged
///   upstream connections back even while the site sits quiet. The client
///   bound is not on it: a quic connection is not a socket the table can
///   cut, so an h3 site carries no deadline table, and its site cfg refuses
///   both client keys rather than accepting a bound nothing would act on.
/// - The QUIC handshake takes its ALPN ("h3") and its transport parameters
///   from the engine's flight builder, so the TLS context here supplies only
///   the certificate and its signing key.
pub const EdgeState = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    socket: std.Io.net.Socket,
    pool: ?upstream_pool.Pool,
    idle: ?upstream_conn.IdleCache,
    sweeper: site_sweep.Sweeper = .{},
    upstream_timeout_ms: u32,
    /// How long a connect to an upstream may take before the request answers
    /// 504. Zero waits on whatever the operating system decides.
    upstream_connect_timeout_ms: u32,
    /// How many requests this site may run upstream at once. One gate for
    /// the whole edge, shared by every request task the receive loop spawns.
    process_gate: process_gate.Gate,
    /// How long a cached public_dir file stays fresh, already resolved from
    /// the site file and the main.cfg default. Zero serves every static
    /// request through the uncached open.
    public_dir_cache_ttl_ms: u32,
    public_dir: ?[]const u8,
    public_prefix: ?[]const u8,
    spa_fallback: ?[]const u8,
    /// Headers this site adds to every answer it sends a client, and to every
    /// request it sends an upstream. Copied out of the cfg arena, which does
    /// not outlive this state.
    response_headers: cfg_headers.Table,
    request_headers: cfg_headers.Table,
    tls_ctx: zix.Tls.Context,
    slots: []?*ConnSlot,
    table_lock: std.atomic.Value(bool) = .init(false),
    stop: std.atomic.Value(bool) = .init(false),
    thread: ?std.Thread = null,
    tasks: std.Io.Group = .init,
    wake_ip: []const u8,
    port: u16,

    /// Build the edge state and start its receive thread.
    ///
    /// Note:
    /// - socket is moved in here: the caller hands the bound datagram socket
    ///   over and must not touch it again, shutdown() closes it. On error the
    ///   caller still owns it.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (state, pool, and connections, long-lived)
    /// io - std.Io (must outlive the state)
    /// socket - std.Io.net.Socket (bound datagram socket for this site)
    /// cfg - *const site_cfg.SiteCfg (validated http3 site config, tls required)
    /// port - u16
    /// options - bind_options.BindOptions (the main.cfg values the site resolves against)
    ///
    /// Return:
    /// - *EdgeState with the receive thread running
    /// - error.ZixerTlsRequired when the cfg carries no certificate
    /// - the zix.Tls.Context.init errors (missing file, bad PEM, unsupported key)
    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        socket: std.Io.net.Socket,
        cfg: *const site_cfg.SiteCfg,
        port: u16,
        options: bind_options.BindOptions,
    ) !*EdgeState {
        if (!cfg.tls or cfg.tls_cert == null or cfg.tls_key == null) return error.ZixerTlsRequired;

        const state = try allocator.create(EdgeState);
        errdefer allocator.destroy(state);

        const idle_ttl_ms = upstream_conn.resolveIdleTtl(cfg.upstream_idle_ttl_ms, options.upstream_idle_ttl_ms);

        var pool: ?upstream_pool.Pool = null;
        errdefer if (pool) |*inner| inner.deinit(allocator);
        var idle: ?upstream_conn.IdleCache = null;
        errdefer if (idle) |*inner| inner.deinit(allocator, io);
        if (cfg.upstreams.len > 0) {
            pool = try upstream_pool.Pool.init(allocator, cfg.upstreams, upstream_pool.DEFAULT_COOLDOWN_MS);
            idle = try upstream_conn.IdleCache.initShare(allocator, cfg.upstreams.len, 1, idle_ttl_ms);
        }

        const wake_ip = try allocator.dupe(u8, cfg.ip);
        errdefer allocator.free(wake_ip);
        const public_dir = try dupeOptional(allocator, cfg.public_dir);
        errdefer freeOptional(allocator, public_dir);
        const public_prefix = try dupeOptional(allocator, cfg.public_prefix);
        errdefer freeOptional(allocator, public_prefix);
        const spa_fallback = try dupeOptional(allocator, cfg.spa_fallback);

        const response_headers = try cfg.response_headers.dupe(allocator);
        errdefer response_headers.deinit(allocator);
        const request_headers = try cfg.request_headers.dupe(allocator);
        errdefer request_headers.deinit(allocator);
        errdefer freeOptional(allocator, spa_fallback);

        const slots = try allocator.alloc(?*ConnSlot, MAX_CONNS);
        errdefer allocator.free(slots);
        @memset(slots, null);

        var tls_ctx = try tls_edge.buildContext(allocator, io, cfg.tls_cert.?, cfg.tls_key.?, tls_edge.alpnPrefs(.HTTP3));
        errdefer tls_ctx.deinit();

        var gate = try process_gate.Gate.init(allocator, process_gate.resolve(
            cfg.process_limit,
            cfg.process_queue_len,
            cfg.process_queue_timeout_ms,
            .{
                .limit = options.process_limit,
                .queue_len = options.process_queue_len,
                .timeout_ms = options.process_queue_timeout_ms,
            },
        ));
        errdefer gate.deinit(allocator);

        // The table is process-wide, so this builds one only when no site has
        // yet. A window of 0 builds none and every lookup falls through.
        const cache_ttl_ms = static_cached.resolveTtl(cfg.public_dir_cache_ttl_ms, options.public_dir_cache_ttl_ms);
        if (public_dir != null) static_cached.install(cache_ttl_ms, options.public_dir_cache_max_entries);

        state.* = .{
            .allocator = allocator,
            .io = io,
            .socket = socket,
            .pool = pool,
            .idle = idle,
            .upstream_timeout_ms = cfg.upstream_timeout_ms orelse upstream_deadline.DEFAULT_MS,
            .upstream_connect_timeout_ms = upstream_conn.resolveConnectTimeout(cfg.upstream_connect_timeout_ms, options.upstream_connect_timeout_ms),
            .process_gate = gate,
            .public_dir_cache_ttl_ms = if (public_dir == null) 0 else cache_ttl_ms,
            .public_dir = public_dir,
            .public_prefix = public_prefix,
            .spa_fallback = spa_fallback,
            .response_headers = response_headers,
            .request_headers = request_headers,
            .tls_ctx = tls_ctx,
            .slots = slots,
            .wake_ip = wake_ip,
            .port = port,
        };

        // One cache: a quic edge owns a single socket, so it has no workers
        // to divide the idle bound between.
        if (state.idle) |*cache| try state.sweeper.start(io, cache[0..1], null, idle_ttl_ms);
        errdefer state.sweeper.stop();

        state.thread = try std.Thread.spawn(.{}, receiveLoop, .{state});

        return state;
    }

    /// Stop the receive thread, close the socket, release everything.
    ///
    /// Note:
    /// - The wake datagram is what unblocks a receive portably: closing a
    ///   socket another thread is blocked on is not reliable cross-platform.
    pub fn shutdown(state: *EdgeState) void {
        const io = state.io;

        state.stop.store(true, .release);
        wakeDatagram(io, state.wake_ip, state.port);
        if (state.thread) |thread| thread.join();
        state.tasks.cancel(io);
        state.sweeper.stop();

        for (state.slots) |maybe_slot| {
            const slot = maybe_slot orelse continue;
            slot.conn.deinit();
            state.allocator.destroy(slot);
        }

        state.socket.close(io);
        state.allocator.free(state.slots);
        state.process_gate.deinit(state.allocator);
        if (state.idle) |*idle| idle.deinit(state.allocator, io);
        if (state.pool) |*pool| pool.deinit(state.allocator);
        state.tls_ctx.deinit();
        state.allocator.free(state.wake_ip);
        freeOptional(state.allocator, state.public_dir);
        freeOptional(state.allocator, state.public_prefix);
        freeOptional(state.allocator, state.spa_fallback);
        state.response_headers.deinit(state.allocator);
        state.request_headers.deinit(state.allocator);

        const allocator = state.allocator;
        allocator.destroy(state);
    }

    /// The static plane of this site, when it serves one.
    fn staticSite(state: *const EdgeState) ?static_files.StaticSite {
        const dir = state.public_dir orelse return null;

        return .{ .public_dir = dir, .public_prefix = state.public_prefix, .spa_fallback = state.spa_fallback };
    }
};

fn dupeOptional(allocator: std.mem.Allocator, value: ?[]const u8) !?[]const u8 {
    const inner = value orelse return null;

    return try allocator.dupe(u8, inner);
}

fn freeOptional(allocator: std.mem.Allocator, value: ?[]const u8) void {
    if (value) |inner| allocator.free(inner);
}

// --------------------------------------------------------- //
// receive side

/// Take datagrams until the site stops, running the maintenance sweep on every
/// quiet poll slice.
fn receiveLoop(state: *EdgeState) void {
    const io = state.io;

    var buf: [MAX_DATAGRAM]u8 = undefined;
    var failures: usize = 0;

    while (!state.stop.load(.acquire)) {
        const ready = socket_poll.waitReady(state.socket.handle, socket_poll.READABLE, POLL_MS) catch {
            failures += 1;
            if (failures >= MAX_RECEIVE_FAILURES) return;
            continue;
        };

        if (!ready) {
            sweep(state);
            continue;
        }

        const message = state.socket.receive(io, &buf) catch {
            if (state.stop.load(.acquire)) return;

            failures += 1;
            if (failures >= MAX_RECEIVE_FAILURES) return;
            continue;
        };
        failures = 0;

        if (state.stop.load(.acquire)) return;
        if (message.flags.trunc) continue;

        handleDatagram(state, message.from, message.data);
        sweep(state);
    }
}

/// One request handed to a task: the raw request stream bytes, copied so the
/// task never reads connection memory without the lock.
const RequestTask = struct {
    state: *EdgeState,
    slot: *ConnSlot,
    stream_id: u64,
    bytes: []u8,
    client: std.Io.net.IpAddress,
    /// The authority this request named, for the $host token. Empty until the
    /// field section has been read, which is the whole of what an answer to an
    /// unreadable request can know.
    host: []const u8 = "",
};

/// The site's answer headers with this request's token values filled in.
///
/// Note:
/// - Quic carries no cleartext transport, so an h3 site is https by
///   construction and the site cfg already refuses tls: false.
///
/// Param:
/// ip_buf - []u8 (scratch for the address text, must outlive the block)
///
/// Return:
/// - cfg_headers.Block, empty when the site configured no section
fn clientBlock(task: RequestTask, ip_buf: []u8) cfg_headers.Block {
    const table = task.state.response_headers;
    if (table.isEmpty()) return .{};

    return .{
        .table = table,
        .values = .{
            .client_ip = proxy_headers.clientIp(ip_buf, task.client),
            .scheme = request_scheme.Scheme.HTTPS.token(),
            .host = task.host,
        },
    };
}

/// The same, for the leg out to the upstream.
fn upstreamBlock(task: RequestTask, ip_buf: []u8) cfg_headers.Block {
    const table = task.state.request_headers;
    if (table.isEmpty()) return .{};

    return .{
        .table = table,
        .values = .{
            .client_ip = proxy_headers.clientIp(ip_buf, task.client),
            .scheme = request_scheme.Scheme.HTTPS.token(),
            .host = task.host,
        },
    };
}

/// Route one received datagram to its connection, then hand every request it
/// completed to a task.
fn handleDatagram(state: *EdgeState, from: std.Io.net.IpAddress, data: []const u8) void {
    const slot = resolveSlot(state, from, data) orelse return;

    var pending: [h3_streams.MAX_STREAMS]RequestTask = undefined;
    var pending_len: usize = 0;

    lockSlot(slot);
    slot.conn.peer = from;

    var sink_ctx = DatagramSink{ .io = state.io, .socket = state.socket, .peer = from };
    const progress = slot.conn.onDatagram(data, sink_ctx.sink());
    slot.conn.pump(sink_ctx.sink());

    for (progress.slice()) |stream_id| {
        const task = takeRequest(state, slot, stream_id, from) orelse continue;

        pending[pending_len] = task;
        pending_len += 1;
    }
    unlockSlot(slot);

    // Spawning happens with the lock released: the inline fallback would
    // otherwise serve the request while holding it.
    for (pending[0..pending_len]) |task| {
        state.tasks.concurrent(state.io, serveRequest, .{task}) catch serveRequest(task);
    }
}

/// The connection this datagram belongs to, opening one for a fresh Initial.
fn resolveSlot(state: *EdgeState, from: std.Io.net.IpAddress, data: []const u8) ?*ConnSlot {
    if (data.len == 0) return null;

    const long_header = data[0] & 0x80 != 0;

    var key_buf: [20]u8 = undefined;
    var key: []const u8 = &.{};
    var is_initial = false;

    if (long_header) {
        const header = zix.Http3.packet.parseLongHeader(data) catch return null;
        const copy = @min(header.dcid.len, key_buf.len);
        @memcpy(key_buf[0..copy], header.dcid[0..copy]);
        key = key_buf[0..copy];
        is_initial = header.packet_type == 0;
    } else {
        if (data.len < 1 + h3_conn.CID_LEN) return null;
        @memcpy(key_buf[0..h3_conn.CID_LEN], data[1 .. 1 + h3_conn.CID_LEN]);
        key = key_buf[0..h3_conn.CID_LEN];
    }

    lockTable(state);
    defer unlockTable(state);

    for (state.slots) |maybe_slot| {
        const slot = maybe_slot orelse continue;
        if (slot.gone) continue;

        if (std.mem.eql(u8, slot.conn.dcid.slice(), key)) return slot;
        if (slot.conn.our_scid.len != 0 and std.mem.eql(u8, slot.conn.our_scid.slice(), key)) return slot;
    }

    if (!is_initial) return null;

    for (state.slots) |*entry| {
        if (entry.* != null) continue;

        const slot = state.allocator.create(ConnSlot) catch return null;
        slot.* = .{ .conn = h3_conn.Conn.init(state.allocator, &state.tls_ctx, key, from) };
        entry.* = slot;

        return slot;
    }

    return null;
}

/// Pull one complete request off a stream, if it has all arrived and was not
/// already served. The caller holds the slot lock.
fn takeRequest(state: *EdgeState, slot: *ConnSlot, stream_id: u64, from: std.Io.net.IpAddress) ?RequestTask {
    if (!slot.conn.requestEnded(stream_id)) return null;
    if (slot.alreadyServed(stream_id)) return null;

    const bytes = slot.conn.readable(stream_id);
    const copy = state.allocator.alloc(u8, bytes.len) catch return null;
    @memcpy(copy, bytes);

    slot.markServed(stream_id);
    slot.conn.releaseRequest(stream_id);
    slot.tasks += 1;

    return .{ .state = state, .slot = slot, .stream_id = stream_id, .bytes = copy, .client = from };
}

/// One time-driven pass over every connection: retransmit what a probe timeout
/// rewound, and drop peers that closed or fell silent.
fn sweep(state: *EdgeState) void {
    const now = zix.Http3.recovery.nowUs();

    for (state.slots) |maybe_slot| {
        const slot = maybe_slot orelse continue;
        if (slot.gone) continue;

        lockSlot(slot);
        const result = slot.conn.maintenance(now);
        if (result.resend) {
            var sink_ctx = DatagramSink{ .io = state.io, .socket = state.socket, .peer = slot.conn.peer };
            slot.conn.pump(sink_ctx.sink());
        }
        if (result.idle) slot.gone = true;
        unlockSlot(slot);
    }

    reapGoneSlots(state);
}

/// Free every connection that is gone and has no task left pointing at it.
fn reapGoneSlots(state: *EdgeState) void {
    lockTable(state);
    defer unlockTable(state);

    for (state.slots) |*entry| {
        const slot = entry.* orelse continue;
        if (!slot.gone) continue;

        lockSlot(slot);
        const busy = slot.tasks != 0;
        unlockSlot(slot);
        if (busy) continue;

        slot.conn.deinit();
        state.allocator.destroy(slot);
        entry.* = null;
    }
}

/// Where a connection's packets go: the site socket, addressed to its peer.
const DatagramSink = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    peer: std.Io.net.IpAddress,

    fn sink(self: *DatagramSink) h3_conn.Sink {
        return .{ .ctx = self, .sendFn = sendDatagram };
    }
};

fn sendDatagram(ctx: *anyopaque, datagram: []const u8) void {
    const self: *DatagramSink = @ptrCast(@alignCast(ctx));

    self.socket.send(self.io, &self.peer, datagram) catch {};
}

/// Send one datagram at the site's own port so a blocked receive returns.
/// A wildcard bind ip is reached through loopback.
fn wakeDatagram(io: std.Io, ip: []const u8, port: u16) void {
    const target = if (std.mem.eql(u8, ip, "0.0.0.0"))
        "127.0.0.1"
    else if (std.mem.eql(u8, ip, "::"))
        "::1"
    else
        ip;

    const addr = std.Io.net.IpAddress.parse(target, port) catch return;
    const local = std.Io.net.IpAddress.parse(if (addr == .ip6) "::" else "0.0.0.0", 0) catch return;
    const socket = local.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch return;
    defer socket.close(io);

    socket.send(io, &addr, "z") catch {};
}

fn lockTable(state: *EdgeState) void {
    while (state.table_lock.swap(true, .acquire)) std.atomic.spinLoopHint();
}

fn unlockTable(state: *EdgeState) void {
    state.table_lock.store(false, .release);
}

fn lockSlot(slot: *ConnSlot) void {
    while (slot.lock.swap(true, .acquire)) std.atomic.spinLoopHint();
}

fn unlockSlot(slot: *ConnSlot) void {
    slot.lock.store(false, .release);
}

// --------------------------------------------------------- //
// request serving

/// Serve one request: decode it, answer from the static plane or the pool, and
/// close the stream behind it.
fn serveRequest(incoming: RequestTask) void {
    var task = incoming;

    defer {
        lockSlot(task.slot);
        task.slot.tasks -= 1;
        unlockSlot(task.slot);
        task.state.allocator.free(task.bytes);
    }

    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;
    var body_start: usize = 0;
    var body_len: usize = 0;

    const section = decodeRequest(task.bytes, &scratch, &body_start, &body_len) orelse {
        answerLocal(task, 400, null);
        return;
    };
    const body = task.bytes[body_start..][0..body_len];

    var request = h3_translate.assemble(section.slice(), body_len == 0) catch |err| {
        answerLocal(task, if (err == error.ZixerUnsupportedConnect) 501 else 400, null);
        return;
    };

    // The whole request is in hand, so the upstream leg always carries an
    // exact length, whatever framing the client used.
    if (request.content_length) |declared| {
        if (declared != body_len) {
            answerLocal(task, 400, null);
            return;
        }
    }
    request.has_body = body_len > 0;
    request.content_length = if (body_len > 0) body_len else null;

    // Every answer below this line names the authority the request carried.
    // The section lives on this frame, so the slice outlives every call here.
    task.host = request.authority;

    if (misdirected(task, &request)) {
        answerLocal(task, 421, null);
        return;
    }

    if (task.state.staticSite()) |site| {
        if (static_files.handles(&site, request.method, request.target)) {
            if (serveStatic(task, &site, &request, section.get("accept-encoding"))) return;
        }
    }

    if (task.state.pool == null) {
        answerLocal(task, 404, null);
        return;
    }

    servePool(task, &request, section.slice(), body);
}

/// Split a request stream into its field section and its body bytes.
///
/// Note:
/// - A body split across several DATA frames is joined in place: each
///   payload slides down over the frame headers between them, so the caller
///   gets one contiguous body without a second buffer. The field section is
///   decoded before the first DATA frame, so its slices are never disturbed.
fn decodeRequest(bytes: []u8, scratch: []u8, body_start: *usize, body_len: *usize) ?h3_qpack.Section {
    var pos: usize = 0;
    var section: ?h3_qpack.Section = null;
    var body_from: ?usize = null;
    var write: usize = 0;

    while (pos < bytes.len) {
        const frame = (h3_frames.nextFrame(bytes[pos..]) catch return null) orelse break;
        const payload_at = pos + (frame.consumed - frame.payload.len);
        const payload_len = frame.payload.len;

        if (!h3_frames.allowedOnRequest(frame.kind)) return null;

        switch (frame.kind) {
            h3_frames.HEADERS => {
                // A trailing field section after the body is legal and carries
                // nothing the h1 leg can use, so it is read and dropped.
                if (section == null) section = h3_qpack.decodeSection(frame.payload, scratch) catch return null;
            },
            h3_frames.DATA => {
                if (body_from == null) {
                    body_from = payload_at;
                    write = payload_at;
                }

                std.mem.copyForwards(u8, bytes[write..][0..payload_len], bytes[payload_at..][0..payload_len]);
                write += payload_len;
            },
            else => {},
        }

        pos += frame.consumed;
    }

    body_start.* = body_from orelse 0;
    body_len.* = write - (body_from orelse 0);

    return section;
}

/// Whether this request names a host the site's certificate does not cover
/// (rfc 9110 15.5.20). QUIC is always TLS, so the gate always applies.
fn misdirected(task: RequestTask, request: *const h3_translate.Request) bool {
    if (request.authority.len == 0) return false;

    const host = proxy_headers.stripHostPort(request.authority);
    zix.Tls.verifyCertIdentity(task.state.tls_ctx.cert_der, host) catch return true;

    return false;
}

/// Answer from public_dir. Returns false when the request must fall through to
/// the pool (file miss on a mixed site).
fn serveStatic(task: RequestTask, site: *const static_files.StaticSite, request: *const h3_translate.Request, accept_encoding: ?[]const u8) bool {
    const io = task.state.io;

    const ttl_ms = task.state.public_dir_cache_ttl_ms;

    if (static_cached.acquire(io, site.public_dir, request.target, accept_encoding, ttl_ms)) |hit| {
        defer static_cached.release(hit);

        sendFile(task, resolvedFromHit(hit), request.is_head);
        return true;
    }

    if (static_files.open(io, site.public_dir, request.target, accept_encoding)) |resolved| {
        defer resolved.file.close(io);

        sendFile(task, resolved, request.is_head);
        return true;
    }

    if (site.spa_fallback) |fallback| {
        var target_buf: [static_files.PUBLIC_PATH_MAX]u8 = undefined;
        if (std.fmt.bufPrint(&target_buf, "/{s}", .{fallback}) catch null) |fallback_target| {
            if (static_cached.acquire(io, site.public_dir, fallback_target, accept_encoding, ttl_ms)) |hit| {
                defer static_cached.release(hit);

                sendFile(task, resolvedFromHit(hit), request.is_head);
                return true;
            }

            if (static_files.open(io, site.public_dir, fallback_target, accept_encoding)) |resolved| {
                defer resolved.file.close(io);

                sendFile(task, resolved, request.is_head);
                return true;
            }
        }
    }

    return false;
}

/// A cache entry in the shape the file sender already takes.
fn resolvedFromHit(hit: static_cached.Hit) static_files.Resolved {
    return .{
        .file = hit.file,
        .size = hit.size,
        .content_type = hit.content_type,
        .encoding = hit.encoding,
    };
}

/// Write one resolved file as the response body.
///
/// Note:
/// - The caller owns the descriptor. An uncached answer closes it after, a
///   cached one leaves it to the table.
/// - The body is copied into this stream's send buffer as it goes, so nothing
///   here has to outlive the call and a plain hit is enough. Asking the table
///   for a resident snapshot would hold a second copy for no gain.
fn sendFile(task: RequestTask, resolved: static_files.Resolved, is_head: bool) void {
    const io = task.state.io;
    const file = resolved.file;

    var block_buf: [1024]u8 = undefined;
    var ip_buf: [proxy_headers.CLIENT_IP_MAX]u8 = undefined;
    const block = h3_translate.encodeStaticBlock(&block_buf, resolved.content_type, resolved.size, resolved.encoding.contentEncoding(), clientBlock(task, &ip_buf)) catch {
        answerLocal(task, 500, null);
        return;
    };

    if (!writeHeaders(task, block)) return;

    if (!is_head) {
        var read_buf: [RELAY_CHUNK]u8 = undefined;
        var offset: u64 = 0;
        while (offset < resolved.size) {
            const want: usize = @intCast(@min(resolved.size - offset, read_buf.len));
            const read = file.readPositionalAll(io, read_buf[0..want], offset) catch break;
            if (read == 0) break;

            offset += read;
            if (!writeBody(task, read_buf[0..read])) return;
        }
    }

    finishStream(task);
}

/// One exchange against the pool: pick, forward, relay, bounded retry. The h1
/// leg is the same one every other zixer engine re-originates onto.
fn servePool(task: RequestTask, request: *const h3_translate.Request, fields: []const h3_qpack.Field, body: []const u8) void {
    const state = task.state;
    const io = state.io;
    const pool = &state.pool.?;
    const idle = &state.idle.?;

    var head_buf: [http1_head.MAX_HEAD_BYTES]u8 = undefined;
    // Quic carries no cleartext transport, so an h3 site is https by
    // construction and the site cfg already refuses tls: false.
    var up_ip_buf: [proxy_headers.CLIENT_IP_MAX]u8 = undefined;
    const upstream_head = h3_translate.buildUpstreamHead(&head_buf, request, fields, task.client, .HTTPS, upstreamBlock(task, &up_ip_buf)) catch {
        answerLocal(task, 431, null);
        return;
    };

    // One place in the gate per request stream. A quic connection carries
    // many of them, and each spends a backend on its own.
    const admission = process_wait.admit(&state.process_gate, io);
    if (admission != .ADMITTED) {
        answerLocal(task, 504, process_wait.PROXY_ERROR);

        return;
    }

    var slot = process_wait.hold(&state.process_gate);
    defer slot.release();

    var attempts: usize = pool.slots.len + 1;
    var failed_here = false;
    var connect_timed_out = false;
    while (attempts > 0) : (attempts -= 1) {
        const picked = pool.pick(monotonic_clock.nowMs(io)) orelse {
            if (failed_here) break;

            answerLocal(task, 503, "destination_unavailable");
            return;
        };

        const conn_up = idle.acquire(io, picked.index, monotonic_clock.nowMs(io)) orelse
            upstream_conn.connect(io, picked.host, picked.port, picked.index, state.upstream_connect_timeout_ms) catch |err| {
            if (upstream_status.ranOutOfTime(err)) connect_timed_out = true;

            pool.markDown(picked.index, monotonic_clock.nowMs(io));
            failed_here = true;
            continue;
        };

        var up_read_buf: [STREAM_BUF_SIZE]u8 = undefined;
        var up_write_buf: [STREAM_BUF_SIZE]u8 = undefined;
        var up_reader = conn_up.stream.reader(io, &up_read_buf);
        var up_writer = conn_up.stream.writer(io, &up_write_buf);

        const wrote = blk: {
            up_writer.interface.writeAll(upstream_head) catch break :blk false;
            if (body.len > 0) up_writer.interface.writeAll(body) catch break :blk false;
            up_writer.interface.flush() catch break :blk false;

            break :blk true;
        };
        if (!wrote) {
            conn_up.stream.close(io);
            if (!conn_up.reused) pool.markDown(picked.index, monotonic_clock.nowMs(io));
            failed_here = true;
            continue;
        }

        const method: []const u8 = if (request.is_head) "HEAD" else "GET";
        const gate = upstreamGate(state, conn_up);
        const response = readUpstreamHead(task, &up_reader.interface, method, gate) catch |err| {
            conn_up.stream.close(io);

            // A silent upstream is not a dead one: the request was already
            // delivered, so it is neither replayed elsewhere nor is the
            // slot taken out of rotation.
            if (err == error.ZixerUpstreamTimeout) {
                answerLocal(task, 504, "http_response_timeout");
                return;
            }

            if (!conn_up.reused) pool.markDown(picked.index, monotonic_clock.nowMs(io));
            failed_here = true;
            continue;
        };

        relayResponse(task, &response, conn_up, &up_reader.interface);
        return;
    }

    const answer = upstream_status.afterAttempts(connect_timed_out);
    answerLocal(task, answer.status, answer.proxy_error);
}

/// Read the upstream response head, relaying interim 1xx heads as informational
/// field sections. A 101 was never asked for and counts as upstream failure.
fn readUpstreamHead(task: RequestTask, up_r: *std.Io.Reader, method: []const u8, gate: upstream_deadline.Gate) !http1_head.ResponseHead {
    var head_buf: [http1_head.MAX_HEAD_BYTES]u8 = undefined;

    var interim: usize = 0;
    while (interim <= MAX_INTERIM) : (interim += 1) {
        if (!gate.ready(up_r)) return error.ZixerUpstreamTimeout;

        const bytes = http1_head.readHead(up_r, &head_buf) catch return error.ZixerUpstreamDead;
        const response = http1_head.parseResponse(bytes, method) catch return error.ZixerUpstreamDead;

        if (response.status == 101) return error.ZixerUpstreamDead;
        if (response.status / 100 != 1) return response;

        var block_buf: [4096]u8 = undefined;
        var ip_buf: [proxy_headers.CLIENT_IP_MAX]u8 = undefined;
        const block = h3_translate.encodeResponseBlock(&block_buf, &response, null, clientBlock(task, &ip_buf)) catch return error.ZixerUpstreamDead;
        if (!writeHeaders(task, block)) return error.ZixerClientDead;
    }

    return error.ZixerUpstreamDead;
}

/// Relay one upstream response onto the client stream: head as a field
/// section, body as DATA frames, chunked trailers as a trailing section.
fn relayResponse(task: RequestTask, response: *const http1_head.ResponseHead, conn_up: upstream_conn.UpstreamConn, up_r: *std.Io.Reader) void {
    const io = task.state.io;

    const block_length: ?u64 = switch (response.framing) {
        .content_length => |len| len,
        .none => if (response.status == 204 or response.status == 304 or response.status / 100 == 1) null else 0,
        else => null,
    };
    const head_only = response.framing == .none;

    var block_buf: [8192]u8 = undefined;
    var ip_buf: [proxy_headers.CLIENT_IP_MAX]u8 = undefined;
    const block = h3_translate.encodeResponseBlock(&block_buf, response, block_length, clientBlock(task, &ip_buf)) catch {
        conn_up.stream.close(io);
        answerLocal(task, 500, null);
        return;
    };

    if (!writeHeaders(task, block)) {
        conn_up.stream.close(io);
        return;
    }

    var relay_failed = false;
    if (!head_only) {
        const relayed: RelayError!void = switch (response.framing) {
            .content_length => |len| relayExact(task, up_r, len, upstreamGate(task.state, conn_up)),
            .chunked => relayChunked(task, up_r),
            .until_close => relayUntilClose(task, up_r),
            .none => unreachable,
        };

        relayed catch {
            relay_failed = true;
        };
    }

    const reusable = !relay_failed and !response.connection_close and response.framing != .until_close;
    if (reusable) task.state.idle.?.release(io, conn_up, monotonic_clock.nowMs(io)) else conn_up.stream.close(io);

    finishStream(task);
}

const RelayError = error{ ZixerUpstreamDead, ZixerClientDead, ZixerBadBody };

/// Relay a body of known length.
fn relayExact(task: RequestTask, up_r: *std.Io.Reader, len: u64, gate: upstream_deadline.Gate) RelayError!void {
    var left = len;
    var buf: [RELAY_CHUNK]u8 = undefined;

    while (left > 0) {
        // The head is already on the wire, so a stall here can only end the
        // stream. The client sees it cut rather than a body that never ends.
        if (!gate.ready(up_r)) return error.ZixerUpstreamDead;

        const want: usize = @intCast(@min(left, buf.len));
        const read = up_r.readSliceShort(buf[0..want]) catch return error.ZixerUpstreamDead;
        if (read == 0) return error.ZixerUpstreamDead;

        if (!writeBody(task, buf[0..read])) return error.ZixerClientDead;
        left -= read;
    }
}

/// Relay a chunked body, then its trailers as the trailing field section.
fn relayChunked(task: RequestTask, up_r: *std.Io.Reader) RelayError!void {
    var line_buf: [128]u8 = undefined;

    while (true) {
        const line = readLine(up_r, &line_buf) catch return error.ZixerUpstreamDead;
        const size_text = std.mem.sliceTo(line, ';');
        const size = std.fmt.parseInt(u64, std.mem.trim(u8, size_text, " \t"), 16) catch return error.ZixerBadBody;

        if (size == 0) {
            try relayTrailers(task, up_r);
            return;
        }

        var left = size;
        var buf: [RELAY_CHUNK]u8 = undefined;
        while (left > 0) {
            const want: usize = @intCast(@min(left, buf.len));
            const read = up_r.readSliceShort(buf[0..want]) catch return error.ZixerUpstreamDead;
            if (read == 0) return error.ZixerUpstreamDead;

            if (!writeBody(task, buf[0..read])) return error.ZixerClientDead;
            left -= read;
        }

        const terminator = readLine(up_r, &line_buf) catch return error.ZixerUpstreamDead;
        if (terminator.len != 0) return error.ZixerBadBody;
    }
}

/// Read the trailer section that closes a chunked body and relay it.
fn relayTrailers(task: RequestTask, up_r: *std.Io.Reader) RelayError!void {
    var trailers: [http1_head.MAX_HEADERS]http1_head.Header = undefined;
    var count: usize = 0;
    var line_buf: [1024]u8 = undefined;

    while (true) {
        const line = readLine(up_r, &line_buf) catch return error.ZixerUpstreamDead;
        if (line.len == 0) break;
        if (count >= trailers.len) continue;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        trailers[count] = .{
            .name = std.mem.trim(u8, line[0..colon], " \t"),
            .value = std.mem.trim(u8, line[colon + 1 ..], " \t"),
        };
        count += 1;
    }

    if (count == 0) return;

    var block_buf: [4096]u8 = undefined;
    const block = h3_translate.encodeTrailerBlock(&block_buf, trailers[0..count]) catch return error.ZixerBadBody;
    if (!writeHeaders(task, block)) return error.ZixerClientDead;
}

/// Relay a body framed only by the upstream closing.
fn relayUntilClose(task: RequestTask, up_r: *std.Io.Reader) RelayError!void {
    var buf: [RELAY_CHUNK]u8 = undefined;

    while (true) {
        const read = up_r.readSliceShort(&buf) catch return;
        if (read == 0) return;

        if (!writeBody(task, buf[0..read])) return error.ZixerClientDead;
    }
}

/// Read one CRLF-terminated line, without its terminator.
fn readLine(src: *std.Io.Reader, buf: []u8) ![]const u8 {
    var len: usize = 0;
    while (len < buf.len) {
        const byte = try src.takeByte();
        if (byte == '\n') {
            if (len > 0 and buf[len - 1] == '\r') len -= 1;

            return buf[0..len];
        }

        buf[len] = byte;
        len += 1;
    }

    return error.ZixerHeadTooLarge;
}

// --------------------------------------------------------- //
// response writing

/// Write a field section as a HEADERS frame on the client stream.
fn writeHeaders(task: RequestTask, block: []const u8) bool {
    var header: [16]u8 = undefined;
    const header_len = h3_frames.writeHeader(&header, h3_frames.HEADERS, block.len) catch return false;

    if (!appendToStream(task, header[0..header_len])) return false;

    return appendToStream(task, block);
}

/// Write body bytes as a DATA frame on the client stream.
fn writeBody(task: RequestTask, bytes: []const u8) bool {
    if (bytes.len == 0) return true;
    if (!awaitQueueRoom(task)) return false;

    var header: [16]u8 = undefined;
    const header_len = h3_frames.writeHeader(&header, h3_frames.DATA, bytes.len) catch return false;

    if (!appendToStream(task, header[0..header_len])) return false;

    return appendToStream(task, bytes);
}

/// Append response bytes and push whatever the window allows.
fn appendToStream(task: RequestTask, bytes: []const u8) bool {
    lockSlot(task.slot);
    defer unlockSlot(task.slot);

    if (task.slot.conn.closed) return false;

    task.slot.conn.respond(task.stream_id, bytes) catch return false;

    var sink_ctx = DatagramSink{ .io = task.state.io, .socket = task.state.socket, .peer = task.slot.conn.peer };
    task.slot.conn.pump(sink_ctx.sink());

    return true;
}

/// End the client stream.
fn finishStream(task: RequestTask) void {
    lockSlot(task.slot);
    defer unlockSlot(task.slot);

    if (task.slot.conn.closed) return;

    task.slot.conn.finishResponse(task.stream_id);

    var sink_ctx = DatagramSink{ .io = task.state.io, .socket = task.state.socket, .peer = task.slot.conn.peer };
    task.slot.conn.pump(sink_ctx.sink());
}

/// Wait until the client has drained enough of this stream to take more.
fn awaitQueueRoom(task: RequestTask) bool {
    var waited: usize = 0;
    while (waited < QUEUE_WAIT_MS) : (waited += 1) {
        lockSlot(task.slot);
        const queued = task.slot.conn.queuedBytes(task.stream_id);
        const dead = task.slot.conn.closed;
        unlockSlot(task.slot);

        if (dead) return false;
        if (queued <= QUEUE_HIGH_WATER) return true;

        std.Io.sleep(task.state.io, std.Io.Duration.fromMilliseconds(1), .awake) catch return false;
    }

    return false;
}

/// Answer the client from the edge itself, with an optional rfc 9209 reason.
fn answerLocal(task: RequestTask, status: u16, proxy_error: ?[]const u8) void {
    var block_buf: [512]u8 = undefined;
    var ip_buf: [proxy_headers.CLIENT_IP_MAX]u8 = undefined;
    const block = h3_translate.encodeLocalBlock(&block_buf, status, proxy_error, clientBlock(task, &ip_buf)) catch return;

    if (!writeHeaders(task, block)) return;

    finishStream(task);
}

/// The read bound for one upstream leg of this site.
fn upstreamGate(state: *EdgeState, conn_up: upstream_conn.UpstreamConn) upstream_deadline.Gate {
    return .{ .stream = conn_up.stream, .budget_ms = state.upstream_timeout_ms };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

const crypto = zix.Http3.crypto;
const protection = zix.Http3.protection;
const keyschedule = zix.Http3.keyschedule;
const quic_packet = zix.Http3.packet;
const quic_request = zix.Http3.request;
const varint = zix.Http3.varint;
const qpack = zix.Http3.qpack;
const wire = zix.Http3.response;
const ks = zix.Http3.tls_key_schedule;
const X25519 = std.crypto.dh.X25519;

const FIXTURE_CERT = "examples/certs/ecdsa_p256_cert.pem";
const FIXTURE_KEY = "examples/certs/ecdsa_p256_key.pem";

/// Pad the client Initial payload so the packet clears the rfc 9000 floor.
const INITIAL_MIN: usize = 1162;

/// A tiny big-endian TLS writer, enough to serialize a ClientHello by hand.
const HelloWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn byte(self: *HelloWriter, value: u8) void {
        self.buf[self.pos] = value;
        self.pos += 1;
    }

    fn word(self: *HelloWriter, value: u16) void {
        std.mem.writeInt(u16, self.buf[self.pos..][0..2], value, .big);
        self.pos += 2;
    }

    fn bytes(self: *HelloWriter, data: []const u8) void {
        @memcpy(self.buf[self.pos..][0..data.len], data);
        self.pos += data.len;
    }

    fn placeWord(self: *HelloWriter) usize {
        const at = self.pos;
        self.pos += 2;

        return at;
    }

    fn patchWord(self: *HelloWriter, at: usize) void {
        std.mem.writeInt(u16, self.buf[at..][0..2], @intCast(self.pos - at - 2), .big);
    }

    fn placeTriple(self: *HelloWriter) usize {
        const at = self.pos;
        self.pos += 3;

        return at;
    }

    fn patchTriple(self: *HelloWriter, at: usize) void {
        const len: u24 = @intCast(self.pos - at - 3);
        self.buf[at] = @intCast(len >> 16);
        self.buf[at + 1] = @intCast((len >> 8) & 0xff);
        self.buf[at + 2] = @intCast(len & 0xff);
    }
};

/// One integer transport parameter (rfc 9000 18.1).
fn putParam(buf: []u8, pos: *usize, id: u64, value: u64) void {
    pos.* += varint.write(buf[pos.*..], id);
    pos.* += varint.write(buf[pos.*..], varint.encodedLen(value));
    pos.* += varint.write(buf[pos.*..], value);
}

/// Serialize a ClientHello offering AES_128_GCM_SHA256, X25519, ECDSA-P256,
/// ALPN h3, and the transport parameters the edge's send path reads.
fn buildClientHello(buf: []u8, client_random: [32]u8, x25519_pub: [32]u8, scid: []const u8) []const u8 {
    var writer = HelloWriter{ .buf = buf };

    writer.byte(0x01);
    const body = writer.placeTriple();

    writer.word(0x0303);
    writer.bytes(&client_random);
    writer.byte(0x00);

    writer.word(0x0002);
    writer.word(0x1301);

    writer.byte(0x01);
    writer.byte(0x00);

    const exts = writer.placeWord();

    writer.word(0x002b); // supported_versions
    const versions = writer.placeWord();
    writer.byte(0x02);
    writer.word(0x0304);
    writer.patchWord(versions);

    writer.word(0x000a); // supported_groups
    const groups = writer.placeWord();
    writer.word(0x0002);
    writer.word(0x001d);
    writer.patchWord(groups);

    writer.word(0x000d); // signature_algorithms
    const sigs = writer.placeWord();
    writer.word(0x0002);
    writer.word(0x0403);
    writer.patchWord(sigs);

    writer.word(0x0010); // application_layer_protocol_negotiation
    const alpn = writer.placeWord();
    writer.word(0x0003);
    writer.byte(0x02);
    writer.bytes("h3");
    writer.patchWord(alpn);

    writer.word(0x0033); // key_share
    const share = writer.placeWord();
    writer.word(0x0024);
    writer.word(0x001d);
    writer.word(0x0020);
    writer.bytes(&x25519_pub);
    writer.patchWord(share);

    writer.word(0x0039); // quic_transport_parameters
    const params = writer.placeWord();
    var param_buf: [128]u8 = undefined;
    var param_len: usize = 0;
    param_len += varint.write(param_buf[param_len..], 0x0f); // initial_source_connection_id
    param_len += varint.write(param_buf[param_len..], scid.len);
    @memcpy(param_buf[param_len..][0..scid.len], scid);
    param_len += scid.len;
    putParam(&param_buf, &param_len, 0x04, 1 << 20); // initial_max_data
    putParam(&param_buf, &param_len, 0x05, 1 << 18); // initial_max_stream_data_bidi_local
    putParam(&param_buf, &param_len, 0x07, 1 << 18); // initial_max_stream_data_uni
    putParam(&param_buf, &param_len, 0x08, 8); // initial_max_streams_bidi
    putParam(&param_buf, &param_len, 0x09, 8); // initial_max_streams_uni
    writer.bytes(param_buf[0..param_len]);
    writer.patchWord(params);

    writer.patchWord(exts);
    writer.patchTriple(body);

    return writer.buf[0..writer.pos];
}

/// The X25519 key share of a ServerHello.
fn serverKeyShare(server_hello: []const u8) ?[32]u8 {
    var pos: usize = 4 + 2 + 32;
    if (pos >= server_hello.len) return null;

    const session_id_len = server_hello[pos];
    pos += 1 + session_id_len;
    pos += 2 + 1;
    if (pos + 2 > server_hello.len) return null;

    pos += 2;
    while (pos + 4 <= server_hello.len) {
        const ext_type = std.mem.readInt(u16, server_hello[pos..][0..2], .big);
        const ext_len = std.mem.readInt(u16, server_hello[pos + 2 ..][0..2], .big);
        pos += 4;
        if (pos + ext_len > server_hello.len) return null;

        if (ext_type == 0x0033) {
            if (ext_len < 4) return null;
            const key_len = std.mem.readInt(u16, server_hello[pos + 2 ..][0..2], .big);
            if (key_len != 32 or pos + 4 + 32 > server_hello.len) return null;

            var out: [32]u8 = undefined;
            @memcpy(&out, server_hello[pos + 4 ..][0..32]);

            return out;
        }

        pos += ext_len;
    }

    return null;
}

/// The first CRYPTO frame payload of a decrypted handshake packet.
fn firstCryptoData(payload: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos < payload.len) {
        const kind = varint.read(payload[pos..]) catch return null;
        pos += kind.len;

        switch (kind.value) {
            0x00, 0x01 => {},
            0x06 => {
                const offset = varint.read(payload[pos..]) catch return null;
                pos += offset.len;
                const length = varint.read(payload[pos..]) catch return null;
                pos += length.len;

                const len: usize = @intCast(length.value);
                if (pos + len > payload.len) return null;

                return payload[pos .. pos + len];
            },
            else => return null,
        }
    }

    return null;
}

/// Response streams the test client reassembles at once.
const CLIENT_STREAMS: usize = 4;

/// Reassembly space per tracked stream.
const CLIENT_STREAM_BYTES: usize = 1024 * 1024;

/// The receive window the test client advertises per stream and keeps ahead of
/// what it has consumed, the same shape a real client uses.
const CLIENT_WINDOW: u64 = 1 << 18;

/// One response stream being reassembled by the test client.
const ClientStream = struct {
    active: bool = false,
    stream_id: u64 = 0,
    /// Offset of this stream's space inside the client's buffer.
    base: usize = 0,
    contiguous: usize = 0,
    fin_at: ?usize = null,
    /// The flow control limit granted to the server on this stream.
    granted: u64 = CLIENT_WINDOW,
};

/// One decoded response off the wire.
const ClientResponse = struct {
    section: h3_qpack.Section,
    body_len: usize,

    fn status(response: *const ClientResponse) []const u8 {
        return response.section.get(":status") orelse "";
    }
};

/// A hand-rolled HTTP/3 client, driving the peer side of the wire from the
/// exported zix.Http3 primitives. It speaks the parts the edge needs: a
/// ClientHello with transport parameters, a QPACK request with real fields,
/// acknowledgments so the server's window keeps moving, and stream
/// reassembly for a response that spans packets.
const H3Client = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    server: std.Io.net.IpAddress,
    app_keys: keyschedule.AppKeys = undefined,
    server_scid: [20]u8 = undefined,
    server_scid_len: usize = 0,
    client_pn: u32 = 0,
    largest_server_pn: ?u64 = null,
    /// Which server packets arrived, bit 0 being the largest. The client
    /// acknowledges honest ranges, so a packet the loopback dropped is
    /// retransmitted instead of silently lost.
    received_mask: u64 = 0,
    /// Connection-wide receive credit granted to the server, and what it has
    /// spent, so a response larger than one window keeps flowing.
    conn_granted: u64 = 1 << 20,
    conn_consumed: u64 = 0,
    /// Reassembly space, one slice per tracked stream. It outlives every
    /// decoded field section, whose names and values point into it.
    stream_buf: []u8,
    streams: [CLIENT_STREAMS]ClientStream = @splat(.{}),

    fn connect(io: std.Io, port: u16) !H3Client {
        var seed: [96]u8 = undefined;
        io.random(&seed);

        const dcid = seed[0..h3_conn.CID_LEN];
        const source_cid = seed[16 .. 16 + h3_conn.CID_LEN];
        const client_random: [32]u8 = seed[32..64].*;
        const ephemeral: [32]u8 = seed[64..96].*;

        const local = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        const socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp });
        errdefer socket.close(io);

        const stream_buf = try testing.allocator.alloc(u8, CLIENT_STREAMS * CLIENT_STREAM_BYTES);
        errdefer testing.allocator.free(stream_buf);

        var client = H3Client{
            .io = io,
            .socket = socket,
            .server = try std.Io.net.IpAddress.parse("127.0.0.1", port),
            .stream_buf = stream_buf,
        };
        try client.handshake(dcid, source_cid, client_random, ephemeral);

        return client;
    }

    fn close(client: *H3Client) void {
        client.socket.close(client.io);
        testing.allocator.free(client.stream_buf);
    }

    fn scid(client: *const H3Client) []const u8 {
        return client.server_scid[0..client.server_scid_len];
    }

    fn handshake(client: *H3Client, dcid: []const u8, scid_bytes: []const u8, client_random: [32]u8, ephemeral: [32]u8) !void {
        const public_key = try X25519.recoverPublicKey(ephemeral);

        const secrets = crypto.initialSecrets(dcid);
        const initial_client = crypto.AesKeys.fromSecret(secrets.client);
        const initial_server = crypto.AesKeys.fromSecret(secrets.server);

        var hello_buf: [1024]u8 = undefined;
        const client_hello = buildClientHello(&hello_buf, client_random, public_key, scid_bytes);

        var transcript = ks.Transcript.init();
        transcript.update(client_hello);

        var payload: [1500]u8 = undefined;
        var plen: usize = 0;
        payload[plen] = 0x06;
        plen += 1;
        plen += varint.write(payload[plen..], 0);
        plen += varint.write(payload[plen..], client_hello.len);
        @memcpy(payload[plen..][0..client_hello.len], client_hello);
        plen += client_hello.len;
        while (plen < INITIAL_MIN) : (plen += 1) payload[plen] = 0x00;

        var initial_pkt: [1600]u8 = undefined;
        const initial = try protection.sealInitial(&initial_pkt, initial_client, dcid, scid_bytes, 0, payload[0..plen]);
        client.socket.send(client.io, &client.server, initial) catch {};

        var hs_keys: keyschedule.HandshakeKeys = undefined;
        var have_hello = false;
        var have_app = false;
        var initial_pn: u32 = 0;
        var sends: usize = 1;

        while (!have_app) {
            var buf: [2048]u8 = undefined;
            const message = client.receiveWithin(&buf, 600) orelse {
                if (sends >= 25) break;
                sends += 1;
                initial_pn += 1;

                var retry_pkt: [1600]u8 = undefined;
                const retry = protection.sealInitial(&retry_pkt, initial_client, dcid, scid_bytes, initial_pn, payload[0..plen]) catch continue;
                client.socket.send(client.io, &client.server, retry) catch continue;
                continue;
            };

            const data = message.data;
            if (data.len == 0 or data[0] & 0x80 == 0) continue;

            const header = quic_packet.parseLongHeader(data) catch continue;

            if (header.packet_type == 0 and !have_hello) {
                var opened_buf: [2048]u8 = undefined;
                const opened = protection.openInitial(data, initial_server, &opened_buf) catch continue;
                const server_hello = firstCryptoData(opened.payload) orelse continue;

                transcript.update(server_hello);
                const server_public = serverKeyShare(server_hello) orelse return error.ZixerNoServerKeyShare;
                const shared = try X25519.scalarmult(ephemeral, server_public);
                hs_keys = keyschedule.handshakeKeys(shared, transcript.current());

                @memcpy(client.server_scid[0..header.scid.len], header.scid);
                client.server_scid_len = header.scid.len;
                have_hello = true;
                continue;
            }

            if (header.packet_type == 2 and have_hello) {
                var opened_buf: [2048]u8 = undefined;
                const opened = protection.openHandshake(data, hs_keys.server, &opened_buf) catch continue;
                const flight_bytes = firstCryptoData(opened.payload) orelse continue;

                transcript.update(flight_bytes);
                client.app_keys = keyschedule.applicationKeys(hs_keys.handshake_secret, transcript.current());
                have_app = true;
            }
        }

        if (!have_app) return error.ZixerHandshakeIncomplete;
    }

    /// Send one request: a QPACK field section as HEADERS, then the body as
    /// one DATA frame, with the fin on the last frame.
    fn request(client: *H3Client, stream_id: u64, fields: []const h3_qpack.Field, body: []const u8) !void {
        if (body.len == 0) return client.requestParts(stream_id, fields, &.{});

        const parts = [_][]const u8{body};

        return client.requestParts(stream_id, fields, &parts);
    }

    /// Send one request whose body arrives as several DATA frames, which is
    /// what a client streaming its body puts on the wire.
    fn requestParts(client: *H3Client, stream_id: u64, fields: []const h3_qpack.Field, parts: []const []const u8) !void {
        var block_buf: [1024]u8 = undefined;
        var encoder = h3_qpack.Encoder.init(&block_buf);
        for (fields) |field| try encoder.field(field.name, field.value);
        const block = encoder.encoded();

        var content: [2048]u8 = undefined;
        var content_len = try h3_frames.writeFrame(&content, h3_frames.HEADERS, block);
        for (parts) |part| content_len += try h3_frames.writeFrame(content[content_len..], h3_frames.DATA, part);

        var payload: [2048]u8 = undefined;
        payload[0] = 0x0f; // STREAM with offset, length, and fin
        var plen: usize = 1;
        plen += varint.write(payload[plen..], stream_id);
        plen += varint.write(payload[plen..], 0);
        plen += varint.write(payload[plen..], content_len);
        @memcpy(payload[plen..][0..content_len], content[0..content_len]);
        plen += content_len;

        var packet_buf: [2048]u8 = undefined;
        const sealed = try protection.sealShort(&packet_buf, client.app_keys.client, client.scid(), client.client_pn, payload[0..plen]);
        client.client_pn += 1;

        try client.socket.send(client.io, &client.server, sealed);
    }

    /// The reassembly slot for one response stream, claimed on first sight.
    fn slotFor(client: *H3Client, stream_id: u64) ?*ClientStream {
        for (&client.streams) |*slot| {
            if (slot.active and slot.stream_id == stream_id) return slot;
        }

        for (&client.streams, 0..) |*slot, index| {
            if (slot.active) continue;

            slot.* = .{ .active = true, .stream_id = stream_id, .base = index * CLIENT_STREAM_BYTES };
            return slot;
        }

        return null;
    }

    /// Collect one response: reassemble every stream in flight (a connection
    /// multiplexes them), acknowledge every packet so the server's window keeps
    /// moving, and decode the field section of the one asked for.
    fn readResponse(client: *H3Client, stream_id: u64, body_out: []u8, scratch: []u8) !ClientResponse {
        var attempts: usize = 0;

        while (attempts < 4096) : (attempts += 1) {
            if (client.slotFor(stream_id)) |slot| {
                if (slot.fin_at) |end| {
                    if (slot.contiguous >= end) {
                        return decodeResponse(client.stream_buf[slot.base..][0..end], body_out, scratch);
                    }
                }
            }

            var buf: [2048]u8 = undefined;
            const message = client.receiveWithin(&buf, 3000) orelse break;
            const data = message.data;
            if (data.len == 0 or data[0] & 0x80 != 0) continue;

            var opened_buf: [2048]u8 = undefined;
            const opened = protection.openShort(data, client.app_keys.server, h3_conn.CID_LEN, client.largest_server_pn, &opened_buf) catch continue;

            client.recordPacket(opened.packet_number);

            client.collectStreams(opened.payload);
            try client.acknowledge();
        }

        return error.ZixerNoResponse;
    }

    /// Walk a decrypted payload, copying every tracked stream's bytes into place.
    fn collectStreams(client: *H3Client, payload: []const u8) void {
        var pos: usize = 0;
        while (pos < payload.len) {
            const kind = varint.read(payload[pos..]) catch return;

            if (!quic_request.isStreamFrameType(kind.value)) {
                pos += quic_request.skipFrame(payload[pos..]) orelse return;
                continue;
            }

            const flags = payload[pos];
            var walk = pos + 1;

            const id = varint.read(payload[walk..]) catch return;
            walk += id.len;

            var offset: u64 = 0;
            if (flags & 0x04 != 0) {
                const off = varint.read(payload[walk..]) catch return;
                walk += off.len;
                offset = off.value;
            }

            var length: u64 = payload.len - walk;
            if (flags & 0x02 != 0) {
                const len = varint.read(payload[walk..]) catch return;
                walk += len.len;
                length = len.value;
            }
            if (walk + length > payload.len) return;

            const bytes = payload[walk..][0..@intCast(length)];

            // Server-initiated streams (the control plane) carry no response.
            client.conn_consumed += bytes.len;

            if (id.value % 4 == 0) {
                if (client.slotFor(id.value)) |slot| {
                    if (offset + bytes.len <= CLIENT_STREAM_BYTES) {
                        @memcpy(client.stream_buf[slot.base + @as(usize, @intCast(offset)) ..][0..bytes.len], bytes);
                        if (offset <= slot.contiguous) slot.contiguous = @max(slot.contiguous, @as(usize, @intCast(offset)) + bytes.len);
                        if (flags & 0x01 != 0) slot.fin_at = @intCast(offset + bytes.len);
                    }
                }
            }

            pos = walk + @as(usize, @intCast(length));
        }
    }

    /// Record one received packet number, sliding the acknowledgment window.
    fn recordPacket(client: *H3Client, packet_number: u64) void {
        const largest = client.largest_server_pn orelse {
            client.largest_server_pn = packet_number;
            client.received_mask = 1;
            return;
        };

        if (packet_number > largest) {
            const shift = packet_number - largest;
            client.received_mask = if (shift >= 64) 1 else (client.received_mask << @intCast(shift)) | 1;
            client.largest_server_pn = packet_number;
            return;
        }

        const delta = largest - packet_number;
        if (delta < 64) client.received_mask |= @as(u64, 1) << @intCast(delta);
    }

    /// Acknowledge what actually arrived, so the server's congestion window
    /// frees and anything the loopback dropped is retransmitted.
    fn acknowledge(client: *H3Client) !void {
        const largest = client.largest_server_pn orelse return;

        var payload: [256]u8 = undefined;
        var plen = wire.buildAckRanges(&payload, largest, client.received_mask);
        if (plen == 0) return;

        // Keep the server's credit ahead of what has been consumed, the way a
        // real client does, so a response past one window is not stalled.
        for (&client.streams) |*slot| {
            if (!slot.active) continue;
            if (slot.contiguous + CLIENT_WINDOW / 2 < slot.granted) continue;

            slot.granted = slot.contiguous + CLIENT_WINDOW;
            payload[plen] = 0x11; // MAX_STREAM_DATA
            plen += 1;
            plen += varint.write(payload[plen..], slot.stream_id);
            plen += varint.write(payload[plen..], slot.granted);
        }

        if (client.conn_consumed + (1 << 19) >= client.conn_granted) {
            client.conn_granted = client.conn_consumed + (1 << 20);
            plen += wire.buildMaxData(payload[plen..], client.conn_granted);
        }

        var packet_buf: [512]u8 = undefined;
        const sealed = try protection.sealShort(&packet_buf, client.app_keys.client, client.scid(), client.client_pn, payload[0..plen]);
        client.client_pn += 1;

        try client.socket.send(client.io, &client.server, sealed);
    }

    fn receiveWithin(client: *H3Client, buf: []u8, timeout_ms: u32) ?std.Io.net.IncomingMessage {
        const ready = socket_poll.waitReady(client.socket.handle, socket_poll.READABLE, timeout_ms) catch return null;
        if (!ready) return null;

        return client.socket.receive(client.io, buf) catch null;
    }
};

/// Split a served response stream into its field section and body.
fn decodeResponse(bytes: []const u8, body_out: []u8, scratch: []u8) !ClientResponse {
    var section: ?h3_qpack.Section = null;
    var body_len: usize = 0;
    var pos: usize = 0;

    while (pos < bytes.len) {
        const frame = (try h3_frames.nextFrame(bytes[pos..])) orelse break;

        if (frame.kind == h3_frames.HEADERS and section == null) {
            section = try h3_qpack.decodeSection(frame.payload, scratch);
        }
        if (frame.kind == h3_frames.DATA) {
            if (body_len + frame.payload.len > body_out.len) return error.ZixerBodyTooLarge;

            @memcpy(body_out[body_len..][0..frame.payload.len], frame.payload);
            body_len += frame.payload.len;
        }

        pos += frame.consumed;
    }

    return .{ .section = section orelse return error.ZixerNoHeaders, .body_len = body_len };
}

/// A one-shot h1 upstream the edge proxies to.
const FakeBackend = struct {
    io: std.Io,
    port: u16,
    request_quota: usize,
    mode: enum { ECHO, BIG, CHUNKED },
    seen_head: [8192]u8 = undefined,
    seen_len: usize = 0,
    seen_body: [4096]u8 = undefined,
    seen_body_len: usize = 0,
    ready: std.atomic.Value(bool) = .init(false),
    /// Set when every bind attempt lost, so the waiter fails with the
    /// reason instead of timing out on a thread that already gave up.
    bind_failed: std.atomic.Value(bool) = .init(false),
    answered: std.atomic.Value(usize) = .init(0),

    fn serve(fake: *FakeBackend) void {
        const io = fake.io;

        const addr = std.Io.net.IpAddress.parse("127.0.0.1", fake.port) catch {
            fake.bind_failed.store(true, .release);
            return;
        };

        var server = bindWithRetry(io, addr) orelse {
            fake.bind_failed.store(true, .release);
            return;
        };
        defer server.deinit(io);
        fake.ready.store(true, .release);

        // One thread per connection: the edge serves concurrent client streams
        // on their own upstream connections, so a serial accept loop would
        // leave the second request waiting behind the first. Accepts are polled
        // so the loop ends once the quota is met, however many connections the
        // edge opened to get there.
        var threads: [4]?std.Thread = @splat(null);
        var count: usize = 0;
        var quiet: usize = 0;

        while (count < threads.len and fake.answered.load(.acquire) < fake.request_quota and quiet < FAKE_IDLE_SLICES) {
            const waiting = socket_poll.waitReady(server.socket.handle, socket_poll.READABLE, FAKE_POLL_MS) catch break;
            if (!waiting) {
                quiet += 1;
                continue;
            }
            quiet = 0;

            const stream = server.accept(io) catch break;

            threads[count] = std.Thread.spawn(.{}, handleConn, .{ fake, stream }) catch {
                handleConn(fake, stream);
                break;
            };
            count += 1;
        }

        for (threads[0..count]) |maybe_thread| {
            if (maybe_thread) |thread| thread.join();
        }
    }

    fn handleConn(fake: *FakeBackend, stream: std.Io.net.Stream) void {
        const io = fake.io;
        defer stream.close(io);

        var read_buf: [8192]u8 = undefined;
        var write_buf: [8192]u8 = undefined;
        var reader = stream.reader(io, &read_buf);
        var writer = stream.writer(io, &write_buf);

        // Reads are polled for the same reason accepts are: the edge keeps a
        // served connection in its idle cache, so a blocking read would hold
        // this thread well past the last answer.
        var quiet: usize = 0;
        while (fake.answered.load(.acquire) < fake.request_quota and quiet < FAKE_IDLE_SLICES) {
            const waiting = socket_poll.waitReady(stream.socket.handle, socket_poll.READABLE, FAKE_POLL_MS) catch return;
            if (!waiting) {
                quiet += 1;
                continue;
            }
            quiet = 0;

            var head_buf: [8192]u8 = undefined;
            const head = http1_head.readHead(&reader.interface, &head_buf) catch return;
            const request = http1_head.parseRequest(head) catch return;

            if (fake.seen_len == 0) {
                @memcpy(fake.seen_head[0..head.len], head);
                fake.seen_len = head.len;
            }

            fake.readBody(&reader.interface, &request) catch return;
            fake.answer(&writer.interface) catch return;
            _ = fake.answered.fetchAdd(1, .acq_rel);
        }
    }

    fn readBody(fake: *FakeBackend, src: *std.Io.Reader, request: *const http1_head.RequestHead) !void {
        fake.seen_body_len = 0;

        switch (request.framing) {
            .none, .until_close, .chunked => {},
            .content_length => |len| {
                const want: usize = @intCast(len);
                var got: usize = 0;
                while (got < want) {
                    const step = try src.readSliceShort(fake.seen_body[got..want]);
                    if (step == 0) return error.EndOfStream;
                    got += step;
                }
                fake.seen_body_len = want;
            },
        }
    }

    fn answer(fake: *FakeBackend, out: *std.Io.Writer) !void {
        switch (fake.mode) {
            .ECHO => {
                try out.print(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Upstream: fake\r\nConnection: keep-alive\r\nContent-Length: {d}\r\n\r\necho:{s}",
                    .{ fake.seen_body_len + 5, fake.seen_body[0..fake.seen_body_len] },
                );
                try out.flush();
            },
            .BIG => {
                try out.print("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {d}\r\n\r\n", .{BIG_BODY_LEN});
                var block: [4096]u8 = @splat('b');
                var sent: usize = 0;
                while (sent < BIG_BODY_LEN) {
                    const take = @min(BIG_BODY_LEN - sent, block.len);
                    try out.writeAll(block[0..take]);
                    sent += take;
                }
                try out.flush();
            },
            .CHUNKED => {
                try out.writeAll("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n");
                try out.writeAll("5\r\nfirst\r\n6\r\nsecond\r\n0\r\nx-done: yes\r\n\r\n");
                try out.flush();
            },
        }
    }

    /// The value of one header in the recorded head, null when absent.
    fn headOf(fake: *FakeBackend, name: []const u8) ?[]const u8 {
        const request = http1_head.parseRequest(fake.seen_head[0..fake.seen_len]) catch return null;
        for (request.headers[0..request.header_count]) |entry| {
            if (std.ascii.eqlIgnoreCase(entry.name, name)) return entry.value;
        }

        return null;
    }
};

const BIG_BODY_LEN: usize = 300 * 1024;

/// Poll slice the fake backend waits on, and how many quiet ones end it.
const FAKE_POLL_MS: u32 = 50;
const FAKE_IDLE_SLICES: usize = 200;

/// Attempts the fake backend makes at its fixed port, one per BIND_RETRY_MS.
/// These ports sit below the ephemeral range, so the kernel never hands one
/// out as an outbound source port. What is left is a foreign process holding
/// the port, and retrying rides a brief hold out instead of failing the run.
const BIND_TRIES: usize = 50;
const BIND_RETRY_MS: u64 = 10;

fn bindWithRetry(io: std.Io, addr: std.Io.net.IpAddress) ?std.Io.net.Server {
    var tries: usize = 0;
    while (tries < BIND_TRIES) : (tries += 1) {
        if (addr.listen(io, .{ .reuse_address = true, .kernel_backlog = 8 })) |server| return server else |_| {}

        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(BIND_RETRY_MS), .awake) catch {};
    }

    return null;
}

fn waitBackend(io: std.Io, fake: *FakeBackend) !void {
    var tries: usize = 0;
    while (tries < 200 and !fake.ready.load(.acquire) and !fake.bind_failed.load(.acquire)) : (tries += 1) {
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }

    // Told apart on purpose: a lost port is an environment problem, a quiet
    // thread is a real one, and the old bare bound reported both the same.
    if (fake.bind_failed.load(.acquire)) {
        std.log.err("zix zixer: h3 edge, the fake backend could not take port {d} in {d} tries", .{ fake.port, BIND_TRIES });

        return error.ZixerFakeBindFailed;
    }

    try testing.expect(fake.ready.load(.acquire));
}

/// The request fields a plain GET carries.
fn getFields(authority: []const u8, path: []const u8) [4]h3_qpack.Field {
    return .{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = authority },
        .{ .name = ":path", .value = path },
    };
}

fn tlsCfg(port: u16, upstreams: []const site_cfg.Upstream) site_cfg.SiteCfg {
    return .{
        .engine = .HTTP3,
        .ip = "127.0.0.1",
        .port = port,
        .tls = true,
        .tls_cert = FIXTURE_CERT,
        .tls_key = FIXTURE_KEY,
        .upstreams = upstreams,
    };
}

fn bindSite(io: std.Io, port: u16) !std.Io.net.Socket {
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);

    return addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
}

test "zix zixer: h3 edge, create starts the receive thread and shutdown frees the port" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18903 }};
    const cfg = tlsCfg(18902, &upstreams);

    const socket = try bindSite(io, 18902);
    const state = try EdgeState.create(testing.allocator, io, socket, &cfg, 18902, .{});
    state.shutdown();

    // Udp binds strict, so a clean rebind proves the port came back.
    const again = try bindSite(io, 18902);
    again.close(io);
}

test "zix zixer: h3 edge, a cleartext cfg refuses to serve" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18903 }};
    var cfg = tlsCfg(18904, &upstreams);
    cfg.tls = false;
    cfg.tls_cert = null;
    cfg.tls_key = null;

    const socket = try bindSite(io, 18904);
    defer socket.close(io);

    try testing.expectError(error.ZixerTlsRequired, EdgeState.create(testing.allocator, io, socket, &cfg, 18904, .{}));
}

test "zix zixer: h3 edge, a request crosses quic to the http1 upstream and back" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeBackend{ .io = io, .port = 18906, .request_quota = 1, .mode = .ECHO };
    const fake_thread = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake});
    try waitBackend(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18906 }};
    const cfg = tlsCfg(18905, &upstreams);
    const socket = try bindSite(io, 18905);
    const state = try EdgeState.create(testing.allocator, io, socket, &cfg, 18905, .{});
    defer state.shutdown();

    var client = try H3Client.connect(io, 18905);
    defer client.close();

    const fields = getFields("localhost", "/hello");
    try client.request(0, &fields, "");

    var body_buf: [4096]u8 = undefined;
    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;
    const response = try client.readResponse(0, &body_buf, &scratch);

    try testing.expectEqualStrings("200", response.status());
    try testing.expectEqualStrings("text/plain", response.section.get("content-type").?);
    try testing.expectEqualStrings(h3_translate.VIA_H3, response.section.get("via").?);
    try testing.expectEqualStrings("echo:", body_buf[0..response.body_len]);

    // The upstream leg carries the h1 head zixer rebuilt.
    try testing.expect(std.mem.startsWith(u8, fake.seen_head[0..fake.seen_len], "GET /hello HTTP/1.1\r\n"));
    try testing.expectEqualStrings("localhost", fake.headOf("host").?);
    try testing.expectEqualStrings(h3_translate.VIA_H3, fake.headOf("via").?);
    try testing.expect(fake.headOf("forwarded") != null);

    fake_thread.join();
}

test "zix zixer: h3 edge, a request body reaches the upstream" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeBackend{ .io = io, .port = 18908, .request_quota = 1, .mode = .ECHO };
    const fake_thread = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake});
    try waitBackend(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18908 }};
    const cfg = tlsCfg(18907, &upstreams);
    const socket = try bindSite(io, 18907);
    const state = try EdgeState.create(testing.allocator, io, socket, &cfg, 18907, .{});
    defer state.shutdown();

    var client = try H3Client.connect(io, 18907);
    defer client.close();

    const fields = [_]h3_qpack.Field{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/submit" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    try client.request(0, &fields, "payload-bytes");

    var body_buf: [4096]u8 = undefined;
    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;
    const response = try client.readResponse(0, &body_buf, &scratch);

    try testing.expectEqualStrings("200", response.status());
    try testing.expectEqualStrings("echo:payload-bytes", body_buf[0..response.body_len]);
    try testing.expectEqualStrings("13", fake.headOf("content-length").?);
    try testing.expectEqualStrings("text/plain", fake.headOf("content-type").?);

    fake_thread.join();
}

test "zix zixer: h3 edge, a body split across data frames joins for the upstream" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeBackend{ .io = io, .port = 18922, .request_quota = 1, .mode = .ECHO };
    const fake_thread = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake});
    try waitBackend(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18922 }};
    const cfg = tlsCfg(18921, &upstreams);
    const socket = try bindSite(io, 18921);
    const state = try EdgeState.create(testing.allocator, io, socket, &cfg, 18921, .{});
    defer state.shutdown();

    var client = try H3Client.connect(io, 18921);
    defer client.close();

    const fields = [_]h3_qpack.Field{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = ":path", .value = "/parts" },
    };
    const parts = [_][]const u8{ "first-", "second-", "third" };
    try client.requestParts(0, &fields, &parts);

    var body_buf: [4096]u8 = undefined;
    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;
    const response = try client.readResponse(0, &body_buf, &scratch);

    try testing.expectEqualStrings("200", response.status());
    try testing.expectEqualStrings("echo:first-second-third", body_buf[0..response.body_len]);
    try testing.expectEqualStrings("18", fake.headOf("content-length").?);

    fake_thread.join();
}

test "zix zixer: h3 edge, a big response spans packets and arrives whole" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeBackend{ .io = io, .port = 18910, .request_quota = 1, .mode = .BIG };
    const fake_thread = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake});
    try waitBackend(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18910 }};
    const cfg = tlsCfg(18909, &upstreams);
    const socket = try bindSite(io, 18909);
    const state = try EdgeState.create(testing.allocator, io, socket, &cfg, 18909, .{});
    defer state.shutdown();

    var client = try H3Client.connect(io, 18909);
    defer client.close();

    const fields = getFields("localhost", "/big");
    try client.request(0, &fields, "");

    const body_buf = try testing.allocator.alloc(u8, BIG_BODY_LEN + 4096);
    defer testing.allocator.free(body_buf);
    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;
    const response = try client.readResponse(0, body_buf, &scratch);

    try testing.expectEqualStrings("200", response.status());
    try testing.expectEqual(BIG_BODY_LEN, response.body_len);
    try testing.expectEqualStrings("307200", response.section.get("content-length").?);
    for (body_buf[0..response.body_len]) |byte| try testing.expectEqual(@as(u8, 'b'), byte);

    fake_thread.join();
}

test "zix zixer: h3 edge, a chunked upstream body relays with its trailers" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeBackend{ .io = io, .port = 18912, .request_quota = 1, .mode = .CHUNKED };
    const fake_thread = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake});
    try waitBackend(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18912 }};
    const cfg = tlsCfg(18911, &upstreams);
    const socket = try bindSite(io, 18911);
    const state = try EdgeState.create(testing.allocator, io, socket, &cfg, 18911, .{});
    defer state.shutdown();

    var client = try H3Client.connect(io, 18911);
    defer client.close();

    const fields = getFields("localhost", "/stream");
    try client.request(0, &fields, "");

    var body_buf: [4096]u8 = undefined;
    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;
    const response = try client.readResponse(0, &body_buf, &scratch);

    try testing.expectEqualStrings("200", response.status());
    try testing.expectEqualStrings("firstsecond", body_buf[0..response.body_len]);

    fake_thread.join();
}

test "zix zixer: h3 edge, a dead upstream answers 502 with proxy status" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Nothing listens on the upstream port.
    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18914 }};
    const cfg = tlsCfg(18913, &upstreams);
    const socket = try bindSite(io, 18913);
    const state = try EdgeState.create(testing.allocator, io, socket, &cfg, 18913, .{});
    defer state.shutdown();

    var client = try H3Client.connect(io, 18913);
    defer client.close();

    const fields = getFields("localhost", "/gone");
    try client.request(0, &fields, "");

    var body_buf: [1024]u8 = undefined;
    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;
    const response = try client.readResponse(0, &body_buf, &scratch);

    try testing.expectEqualStrings("502", response.status());
    try testing.expect(std.mem.indexOf(u8, response.section.get("proxy-status").?, "zixer") != null);
}

test "zix zixer: h3 edge, the static plane serves a file and misses fall through" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    tmp.dir.writeFile(testing.io, .{ .sub_path = "page.html", .data = "<h1>h3 static</h1>" }) catch @panic("fixture write failed");

    var root_buf: [128]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var cfg = tlsCfg(18915, &.{});
    cfg.public_dir = root;

    const socket = try bindSite(io, 18915);
    const state = try EdgeState.create(testing.allocator, io, socket, &cfg, 18915, .{});
    defer state.shutdown();

    var client = try H3Client.connect(io, 18915);
    defer client.close();

    const fields = getFields("localhost", "/page.html");
    try client.request(0, &fields, "");

    var body_buf: [4096]u8 = undefined;
    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;
    const response = try client.readResponse(0, &body_buf, &scratch);

    try testing.expectEqualStrings("200", response.status());
    try testing.expectEqualStrings("text/html", response.section.get("content-type").?);
    try testing.expectEqualStrings("Accept-Encoding", response.section.get("vary").?);
    try testing.expectEqualStrings("<h1>h3 static</h1>", body_buf[0..response.body_len]);

    // A miss on a static-only site is a local 404, not a pool attempt.
    const miss = getFields("localhost", "/missing.html");
    try client.request(4, &miss, "");
    const miss_response = try client.readResponse(4, &body_buf, &scratch);
    try testing.expectEqualStrings("404", miss_response.status());
}

test "zix zixer: h3 edge, a foreign authority is refused with 421" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18918 }};
    const cfg = tlsCfg(18916, &upstreams);
    const socket = try bindSite(io, 18916);
    const state = try EdgeState.create(testing.allocator, io, socket, &cfg, 18916, .{});
    defer state.shutdown();

    var client = try H3Client.connect(io, 18916);
    defer client.close();

    const foreign = getFields("evil.example", "/");
    try client.request(0, &foreign, "");

    var body_buf: [1024]u8 = undefined;
    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;
    const response = try client.readResponse(0, &body_buf, &scratch);

    try testing.expectEqualStrings("421", response.status());
}

test "zix zixer: h3 edge, two requests multiplex on one connection" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = FakeBackend{ .io = io, .port = 18920, .request_quota = 2, .mode = .ECHO };
    const fake_thread = try std.Thread.spawn(.{}, FakeBackend.serve, .{&fake});
    try waitBackend(io, &fake);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18920 }};
    const cfg = tlsCfg(18919, &upstreams);
    const socket = try bindSite(io, 18919);
    const state = try EdgeState.create(testing.allocator, io, socket, &cfg, 18919, .{});
    defer state.shutdown();

    var client = try H3Client.connect(io, 18919);
    defer client.close();

    const first = getFields("localhost", "/one");
    const second = getFields("localhost", "/two");
    try client.request(0, &first, "");
    try client.request(4, &second, "");

    var body_buf: [4096]u8 = undefined;
    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;

    const first_response = try client.readResponse(0, &body_buf, &scratch);
    try testing.expectEqualStrings("200", first_response.status());

    const second_response = try client.readResponse(4, &body_buf, &scratch);
    try testing.expectEqualStrings("200", second_response.status());

    fake_thread.join();
}

/// Test upstream that accepts and then says nothing, the stall an upstream
/// read deadline exists for.
const SilentBackend = struct {
    io: std.Io,
    port: u16,
    ready: std.atomic.Value(bool) = .init(false),
    release: std.atomic.Value(bool) = .init(false),

    fn serve(fake: *SilentBackend) void {
        const io = fake.io;

        const addr = std.Io.net.IpAddress.parse("127.0.0.1", fake.port) catch return;
        var server = bindWithRetry(io, addr) orelse return;
        defer server.deinit(io);
        fake.ready.store(true, .release);

        const stream = server.accept(io) catch return;
        defer stream.close(io);

        while (!fake.release.load(.acquire)) {
            std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch break;
        }
    }
};

test "zix zixer: h3 edge, a silent upstream answers 504 with proxy status" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fake = SilentBackend{ .io = io, .port = 18952 };
    const fake_thread = try std.Thread.spawn(.{}, SilentBackend.serve, .{&fake});
    var tries: usize = 0;
    while (tries < 100 and !fake.ready.load(.acquire)) : (tries += 1) {
        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(10), .awake) catch {};
    }
    try testing.expect(tries < 100);

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18952 }};
    var cfg = tlsCfg(18951, &upstreams);
    cfg.upstream_timeout_ms = 200;

    const socket = try bindSite(io, 18951);
    const state = try EdgeState.create(testing.allocator, io, socket, &cfg, 18951, .{});
    defer state.shutdown();

    var client = try H3Client.connect(io, 18951);
    defer client.close();

    const fields = getFields("localhost", "/stalled");
    try client.request(0, &fields, "");

    var body_buf: [1024]u8 = undefined;
    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;
    const response = try client.readResponse(0, &body_buf, &scratch);

    try testing.expectEqualStrings("504", response.status());
    try testing.expectEqualStrings("zixer; error=\"http_response_timeout\"", response.section.get("proxy-status").?);

    // A slow backend is still a serving one, so the slot stays in rotation.
    try testing.expectEqual(@as(usize, 1), state.pool.?.upCount());

    fake.release.store(true, .release);
    fake_thread.join();
}

test "zix zixer: h3 edge, a cached entry answers after the file leaves disk" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    tmp.dir.writeFile(testing.io, .{ .sub_path = "page.html", .data = "<h1>h3 cached</h1>" }) catch @panic("fixture write failed");

    var root_buf: [128]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var cfg = tlsCfg(18923, &.{});
    cfg.public_dir = root;
    cfg.public_dir_cache_ttl_ms = 60_000;

    const socket = try bindSite(io, 18923);
    const state = try EdgeState.create(testing.allocator, io, socket, &cfg, 18923, .{});
    defer state.shutdown();
    defer static_cached.shutdown(io);

    try testing.expectEqual(@as(u32, 60_000), state.public_dir_cache_ttl_ms);

    var client = try H3Client.connect(io, 18923);
    defer client.close();

    var body_buf: [4096]u8 = undefined;
    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;

    const fields = getFields("localhost", "/page.html");
    try client.request(0, &fields, "");
    const first = try client.readResponse(0, &body_buf, &scratch);
    try testing.expectEqualStrings("200", first.status());
    try testing.expectEqualStrings("<h1>h3 cached</h1>", body_buf[0..first.body_len]);

    // The entry holds the descriptor, so unlinking the name cannot reach it.
    tmp.dir.deleteFile(testing.io, "page.html") catch @panic("fixture delete failed");

    try client.request(4, &fields, "");
    const second = try client.readResponse(4, &body_buf, &scratch);
    try testing.expectEqualStrings("200", second.status());
    try testing.expectEqualStrings("<h1>h3 cached</h1>", body_buf[0..second.body_len]);
}

test "zix zixer: h3 edge, a site with no public dir resolves the window to off" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const upstreams = [_]site_cfg.Upstream{.{ .host = "127.0.0.1", .port = 18925 }};
    const cfg = tlsCfg(18924, &upstreams);

    const socket = try bindSite(io, 18924);
    const state = try EdgeState.create(testing.allocator, io, socket, &cfg, 18924, .{ .public_dir_cache_ttl_ms = 5000 });
    defer state.shutdown();

    // The daemon asked for a window, but a proxy-only site has no files to
    // cache, so no table is built and every lookup is skipped outright.
    try testing.expectEqual(@as(u32, 0), state.public_dir_cache_ttl_ms);
    try testing.expect(zix.utils.static_cache.instance() == null);
}

test "zix zixer: h3 edge, a served request carries the site's headers end to end" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("zix zixer: h3 edge socket tests need linux, skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    tmp.dir.writeFile(testing.io, .{ .sub_path = "page.html", .data = "h3-static" }) catch @panic("fixture write failed");

    var root_buf: [128]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    const socket = try bindSite(io, 18988);
    const state = built: {
        // The cfg arena is released before a single request is served, which
        // is what the daemon does too.
        var cfg_arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer cfg_arena.deinit();

        var content_buf: [768]u8 = undefined;
        const content = try std.fmt.bufPrint(&content_buf,
            \\engine: http3
            \\ip: 127.0.0.1
            \\port: 18988
            \\tls: true
            \\tls_cert: {s}
            \\tls_key: {s}
            \\public_dir: {s}
            \\[response_headers]
            \\strict-transport-security: max-age=31536000
            \\x-served-to: $client_ip over $scheme
            \\
        , .{ FIXTURE_CERT, FIXTURE_KEY, root });

        var faults = fault.FaultList.init(cfg_arena.allocator());
        const cfg = try site_cfg.parse(cfg_arena.allocator(), content, &faults);
        try testing.expectEqual(@as(usize, 0), faults.slice().len);

        break :built try EdgeState.create(testing.allocator, io, socket, &cfg, 18988, .{});
    };
    defer state.shutdown();

    var client = try H3Client.connect(io, 18988);
    defer client.close();

    const fields = getFields("localhost", "/page.html");
    try client.request(0, &fields, "");

    var body_buf: [4096]u8 = undefined;
    var scratch: [h3_qpack.SCRATCH_BYTES]u8 = undefined;
    const response = try client.readResponse(0, &body_buf, &scratch);

    try testing.expectEqualStrings("200", response.status());
    try testing.expectEqualStrings("max-age=31536000", response.section.get("strict-transport-security").?);

    // The peer address reached the token, over a table the cfg arena no
    // longer backs.
    const served_to = response.section.get("x-served-to").?;
    try testing.expect(std.mem.startsWith(u8, served_to, "127.0.0.1 over https"));
}
