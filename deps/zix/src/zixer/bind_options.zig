//! zixer bind options: what the daemon already settled before a site binds

const zix = @import("zix");

const conn_buffer = @import("conn_buffer.zig");
const deadline_table = @import("deadline_table.zig");
const process_gate = @import("process_gate.zig");
const static_cached = @import("static_cached.zig");
const upstream_conn = @import("upstream_conn.zig");

/// The main.cfg values a site needs at bind time.
///
/// Note:
/// - workers is the resolved count, not the raw main.cfg value: the daemon
///   turns 0 into the thread count once, at start, see worker_count.zig.
/// - Only a serving tcp site spends workers. A bare bound listener has no
///   accept loop, and the quic edge and the udp forward each own one
///   socket whose connection state is keyed to it.
/// - max_recv_buf is the daemon default. A site file may name its own,
///   which is why the edge resolves the pair rather than reading this one
///   directly, see conn_buffer.resolve.
/// - The three process_ values are daemon defaults the same way, resolved
///   against the site file by process_gate.resolve. A limit of 0 is the
///   gate off, which is what a daemon that never asked for one carries.
/// - public_dir_cache_ttl_ms is a daemon default too, resolved against the
///   site file by static_cached.resolveTtl. The entry count has no site
///   override: the cache table is one per process, so only main.cfg sizes it.
/// - client_timeout_ms and client_conn_limit are the client leg's pair,
///   resolved against the site file by deadline_table.resolve. A timeout of
///   0 is the bound off, and then the limit means nothing.
/// - upstream_connect_timeout_ms and upstream_idle_ttl_ms are the upstream
///   leg's, resolved by upstream_conn.resolveConnectTimeout and
///   upstream_conn.resolveIdleTtl.
/// - logger is the daemon's, borrowed for the life of the site. Null is a
///   site bound outside a daemon, which is what a test does: those lines
///   fall through to std.log instead, see daemon_log.logSystem.
pub const BindOptions = struct {
    kernel_backlog: u31 = 1024,
    workers: usize = 1,
    max_recv_buf: usize = conn_buffer.DEFAULT_BYTES,
    client_timeout_ms: u32 = 0,
    client_conn_limit: usize = deadline_table.DEFAULT_CONN_LIMIT,
    upstream_connect_timeout_ms: u32 = upstream_conn.DEFAULT_CONNECT_TIMEOUT_MS,
    upstream_idle_ttl_ms: u32 = upstream_conn.DEFAULT_IDLE_TTL_MS,
    process_limit: usize = 0,
    process_queue_len: usize = 0,
    process_queue_timeout_ms: u32 = process_gate.DEFAULT_TIMEOUT_MS,
    public_dir_cache_ttl_ms: u32 = static_cached.DEFAULT_TTL_MS,
    public_dir_cache_max_entries: u32 = static_cached.DEFAULT_MAX_ENTRIES,
    logger: ?*zix.Logger = null,
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const std = @import("std");

test "zix zixer: bind options, the defaults are one worker and the buffer default" {
    const options = BindOptions{};

    try std.testing.expectEqual(@as(u31, 1024), options.kernel_backlog);
    try std.testing.expectEqual(@as(usize, 1), options.workers);
    try std.testing.expectEqual(conn_buffer.DEFAULT_BYTES, options.max_recv_buf);
}

test "zix zixer: bind options, the daemon default stays inside the buffer range" {
    const options = BindOptions{};

    try std.testing.expect(conn_buffer.inRange(options.max_recv_buf));
}

test "zix zixer: bind options, the process gate defaults to off" {
    const options = BindOptions{};

    try std.testing.expectEqual(@as(usize, 0), options.process_limit);
    try std.testing.expectEqual(@as(usize, 0), options.process_queue_len);
    try std.testing.expectEqual(process_gate.DEFAULT_TIMEOUT_MS, options.process_queue_timeout_ms);

    const settings = process_gate.Settings{
        .limit = options.process_limit,
        .queue_len = options.process_queue_len,
        .timeout_ms = options.process_queue_timeout_ms,
    };
    try std.testing.expect(!settings.armed());
}

test "zix zixer: bind options, the static cache defaults to off with room reserved" {
    const options = BindOptions{};

    try std.testing.expectEqual(@as(u32, 0), options.public_dir_cache_ttl_ms);
    try std.testing.expectEqual(static_cached.DEFAULT_MAX_ENTRIES, options.public_dir_cache_max_entries);

    // A daemon that never asked for caching resolves every site to off.
    try std.testing.expectEqual(@as(u32, 0), static_cached.resolveTtl(null, options.public_dir_cache_ttl_ms));
}

test "zix zixer: bind options, the client bound defaults to off with a limit reserved" {
    const options = BindOptions{};

    try std.testing.expectEqual(@as(u32, 0), options.client_timeout_ms);
    try std.testing.expectEqual(deadline_table.DEFAULT_CONN_LIMIT, options.client_conn_limit);

    // A daemon that never asked for a bound resolves every site to off, so
    // no site allocates a table or refuses a connection.
    const settings = deadline_table.resolve(null, null, .{
        .timeout_ms = options.client_timeout_ms,
        .conn_limit = options.client_conn_limit,
    });
    try std.testing.expect(!settings.armed());
    try std.testing.expectEqual(@as(usize, 0), settings.capacity());
}

test "zix zixer: bind options, the upstream leg carries the built-in bounds" {
    const options = BindOptions{};

    try std.testing.expectEqual(upstream_conn.DEFAULT_CONNECT_TIMEOUT_MS, options.upstream_connect_timeout_ms);
    try std.testing.expectEqual(upstream_conn.DEFAULT_IDLE_TTL_MS, options.upstream_idle_ttl_ms);

    try std.testing.expect(upstream_conn.connectTimeoutInRange(options.upstream_connect_timeout_ms));
    try std.testing.expect(upstream_conn.idleTtlInRange(options.upstream_idle_ttl_ms));
}

test "zix zixer: bind options, no logger is the default a test-bound site gets" {
    const options = BindOptions{};

    try std.testing.expectEqual(@as(?*zix.Logger, null), options.logger);
}
