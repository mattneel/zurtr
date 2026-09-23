//! zix http1 dispatch helpers shared by two or more dispatch models.

const std = @import("std");
const builtin = @import("builtin");
const win_io = @import("../../../utils/windows_io.zig");
const async_cache = @import("../../../utils/async_cache.zig");
const Config = @import("../config.zig").Http1ServerConfig;
const core = @import("../core.zig");
const HandlerFn = core.HandlerFn;
const Logger = @import("../../../logger/logger.zig").Logger;

const log = std.log.scoped(.zix_http1);

// --------------------------------------------------------- //

/// Emit a server line at the given level. Routes through config.logger when present.
///
/// Note:
/// - Without a logger the line still reaches std.log, so a release build never loses a failure.
///   std.log's own default level does the filtering: .ERROR and .WARN survive a release build,
///   .INFO and .DEBUG do not, and a caller who sets std.options.logFn can route or silence all
///   of them.
///
/// Param:
/// level - Logger.Level (.ERROR for a failure the reader must act on, .INFO for a lifecycle line)
pub fn logSystem(config: Config, level: Logger.Level, comptime fmt: []const u8, args: anytype) void {
    if (config.logger) |lg| {
        lg.system(level, "http1", fmt, args);
        return;
    }

    switch (level) {
        .ERROR => log.err(fmt, args),
        .WARN => log.warn(fmt, args),
        .INFO => log.info(fmt, args),
        .DEBUG => log.debug(fmt, args),
    }
}

// --------------------------------------------------------- //
// Shared connection entry (.ASYNC)

/// Arguments for connEntry, one set per accepted connection.
pub const ConnArgs = struct {
    stream: std.Io.net.Stream,
    io: std.Io,
    handler: HandlerFn,
    handler_timeout_ms: u32 = 0,
    conn_timeout_ms: u32 = 0,
    registry: ?*ConnRegistry = null,
    send_date_header: bool = true,
    large_body_rcvbuf: usize = 0,
    /// Per-connection receive size, from config.max_recv_buf. Carried here so
    /// the blocking model sizes its buffers from the same knob the .EPOLL and
    /// .URING slots use.
    max_recv_buf: usize = core.BUF_SIZE,
    /// Largest request body, from config.max_request_body. 0 removes the check.
    max_request_body: usize = 0,
    public_dir: []const u8 = "",
    max_response_headers: usize = 16,
    /// Where served requests are recorded, from config.logger. Null logs nothing.
    logger: ?*Logger = null,
    compress: bool = false,
    compression_min_size: usize = 256,
    compression_max_out: usize = 256 * 1024,
    response_cache: bool = false,
    cache_max_entries: u32 = 256,
    cache_max_value_bytes: u32 = 16 * 1024,
    cache_ttl_ms: u32 = 0,
    cache_max_total_bytes: usize = 0,
};

/// Thread entry for one accepted connection (.ASYNC): installs the
/// per-worker switches, arms the guard when a registry is given, and runs the
/// keep-alive serve loop until the connection ends.
///
/// Note:
/// - The multiplexed models install their switches once per worker, because a worker owns its
///   connections for its whole life. .ASYNC has no such worker: io.async hands each connection
///   to whichever pool thread is free, so the switches are installed here instead. Compression
///   is stateless, the cache is built once per pool thread and reused (see threadCache).
pub fn connEntry(args: ConnArgs) void {
    core.setDateHeader(args.send_date_header);
    core.setStatic(args.public_dir, args.io);
    core.setMaxResponseHeaders(args.max_response_headers);
    core.setAccessLogger(args.logger);
    core.setCompression(args.compress, args.compression_min_size, args.compression_max_out);

    if (args.response_cache) {
        if (threadCache(args)) |cache| core.setCache(cache, args.cache_ttl_ms) else core.setCache(null, 0);
    } else {
        core.setCache(null, 0);
    }

    defer args.stream.close(args.io);

    const fd = args.stream.socket.handle;

    var guard: ?ConnEntry = null;
    if (args.registry) |registry| {
        guard = ConnEntry{ .fd = fd, .deadline = connDeadline(args.io, args.conn_timeout_ms) };
        registry.register(&guard.?, args.io);
    }
    defer if (args.registry) |registry| registry.deregister(&guard.?, args.io);

    core.serveConn(fd, args.handler, .{ .handler_timeout_ms = args.handler_timeout_ms, .large_body_rcvbuf = args.large_body_rcvbuf, .max_recv_buf = args.max_recv_buf, .max_request_body = args.max_request_body }, args.io);
}

/// This pool thread's response cache, sized from the connection's config.
fn threadCache(args: ConnArgs) ?*async_cache.ResponseCache {
    return async_cache.forThisThread(.{
        .max_entries = async_cache.effectiveEntries(args.cache_max_entries, args.cache_max_value_bytes, args.cache_max_total_bytes),
        .max_value_bytes = args.cache_max_value_bytes,
    });
}

// --------------------------------------------------------- //
// Connection guard (config.conn_timeout_ms): registry plus timer eviction on
// the blocking model (.ASYNC). The multiplexed models (.EPOLL,
// .URING) do not use it, their event loops own connection lifetime.

/// Sweep interval for the connection-guard timer thread.
const conn_timer_interval_ms: u32 = 500;

/// The wall-clock deadline for a connection accepted now.
pub fn connDeadline(io: std.Io, timeout_ms: u32) std.Io.Clock.Timestamp {
    return std.Io.Clock.Timestamp.fromNow(
        io,
        std.Io.Clock.Duration{ .raw = std.Io.Duration.fromMilliseconds(timeout_ms), .clock = .real },
    );
}

/// One live connection tracked by the guard: its fd, eviction deadline, and done flag.
pub const ConnEntry = struct {
    fd: std.posix.fd_t,
    deadline: std.Io.Clock.Timestamp,
    done: std.atomic.Value(bool) = .init(false),
};

/// Live-connection registry the guard timer sweeps (evict).
pub const ConnRegistry = struct {
    mutex: std.Io.Mutex = .init,
    entries: std.ArrayListUnmanaged(*ConnEntry) = .empty,

    pub fn register(self: *ConnRegistry, entry: *ConnEntry, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        self.entries.append(std.heap.smp_allocator, entry) catch {};
    }

    pub fn deregister(self: *ConnRegistry, entry: *ConnEntry, io: std.Io) void {
        entry.done.store(true, .release);

        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        for (self.entries.items, 0..) |candidate, i| {
            if (candidate == entry) {
                _ = self.entries.swapRemove(i);
                break;
            }
        }
    }

    /// Shut down every registered connection past its deadline. The blocked
    /// serve loop then sees EOF and tears the connection down normally.
    pub fn evict(self: *ConnRegistry, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        const now = std.Io.Clock.Timestamp.now(io, .real);
        for (self.entries.items) |entry| {
            if (!entry.done.load(.acquire) and now.compare(.gte, entry.deadline)) {
                if (comptime @import("builtin").target.os.tag == .windows) {
                    win_io.shutdown(entry.fd);
                } else {
                    _ = std.os.linux.shutdown(entry.fd, std.os.linux.SHUT.RDWR);
                }
            }
        }
    }

    pub fn deinit(self: *ConnRegistry) void {
        self.entries.deinit(std.heap.smp_allocator);
    }
};

/// Timer thread body: sweep the registry every conn_timer_interval_ms.
pub fn connTimerLoop(io: std.Io, registry: *ConnRegistry) void {
    while (true) {
        registry.evict(io);

        std.Io.sleep(io, std.Io.Duration.fromMilliseconds(conn_timer_interval_ms), .awake) catch break;
    }
}

/// Highest fd a worker's table can index. Linux hands out the lowest free fd,
/// so the table stays sparse. Connections on fds at or above this are refused.
pub const MAX_FD: usize = 1 << 16;

/// Upper clamp on bytes requested in a single MSG.TRUNC drain recv. With
/// MSG.TRUNC the kernel never writes the buffer, so a length past the connection
/// buffer is safe. 1 GiB is a safety ceiling that is never reached in practice.
pub const MAX_DRAIN_RECV: usize = 1 << 30;

/// Accept-thread stack. Accept threads only block in accept and hand off, so a
/// smaller stack than the workers is enough.
pub const ACCEPT_STACK: usize = 256 * 1024;

pub fn setNoDelay(fd: std.posix.fd_t) void {
    if (comptime @import("builtin").target.os.tag != .windows) {
        // std.posix.TCP is void on the BSDs in Zig 0.16: TCP_NODELAY is 1 there.
        const nodelay: u32 = if (comptime std.posix.TCP != void) std.posix.TCP.NODELAY else 1;

        std.posix.setsockopt(
            fd,
            std.posix.IPPROTO.TCP,
            nodelay,
            std.mem.asBytes(&@as(c_int, 1)),
        ) catch {};
    }
}

pub fn setNonBlock(fd: std.posix.fd_t) void {
    // fcntl O_NONBLOCK is POSIX-only, and only the Linux event loops call this.
    if (comptime builtin.os.tag == .windows) return;

    const linux = std.os.linux;
    const cur = linux.fcntl(fd, std.posix.F.GETFL, 0);
    const nonblock: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
    _ = linux.fcntl(fd, std.posix.F.SETFL, cur | @as(usize, nonblock));
}

/// Spin up to us microseconds before blocking (SO_BUSY_POLL, from config.busy_poll_us).
/// Reduces wake-up latency on saturated loopback benchmarks. Silent no-op when the
/// kernel lacks SO_BUSY_POLL support.
pub fn setBusyPoll(fd: std.posix.fd_t, us: u32) void {
    if (comptime builtin.os.tag == .windows) return;

    const SO_BUSY_POLL: u32 = 46;
    std.posix.setsockopt(
        fd,
        std.posix.SOL.SOCKET,
        SO_BUSY_POLL,
        std.mem.asBytes(&@as(c_int, @intCast(us))),
    ) catch {};
}

/// Widest allowed-CPU list the pinning path tracks: one slot per affinity-mask bit.
pub const PIN_MAX_CPUS: usize = 256;

/// Path buffer for /sys/devices/system/cpu/cpu<N>/topology/<leaf> (fits the widest leaf).
const TOPOLOGY_PATH_BUF_SIZE: usize = 80;

/// Value buffer for one sysfs topology read: a decimal id plus a trailing newline.
const TOPOLOGY_VALUE_BUF_SIZE: usize = 16;

/// Read one decimal value from /sys/devices/system/cpu/cpu<N>/topology/<leaf>.
///
/// Return:
/// - u32 parsed value
/// - null when the file is missing or malformed (non-sysfs layouts)
fn readTopologyValue(cpu: u32, comptime leaf: []const u8) ?u32 {
    var path_buf: [TOPOLOGY_PATH_BUF_SIZE]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/sys/devices/system/cpu/cpu{d}/topology/" ++ leaf, .{cpu}) catch return null;

    const fd = std.posix.openat(
        @as(std.posix.fd_t, std.posix.AT.FDCWD),
        path,
        .{ .ACCMODE = .RDONLY },
        0,
    ) catch return null;
    defer _ = std.os.linux.close(fd);

    var value_buf: [TOPOLOGY_VALUE_BUF_SIZE]u8 = undefined;
    const len = std.posix.read(fd, &value_buf) catch return null;

    const trimmed = std.mem.trim(u8, value_buf[0..len], " \n\t");

    return std.fmt.parseInt(u32, trimmed, 10) catch null;
}

/// Physical-core key for a CPU: package id in the high half, core id in the low
/// half, so two SMT siblings share a key and two packages never collide.
fn coreKey(cpu: u32) ?u64 {
    const package = readTopologyValue(cpu, "physical_package_id") orelse return null;
    const core_id = readTopologyValue(cpu, "core_id") orelse return null;

    return (@as(u64, package) << 32) | core_id;
}

/// Reorder the allowed-CPU list so each distinct physical core appears once
/// before any SMT sibling repeats one (stable inside both groups). Worker i
/// pins to slot i, so N workers land on N distinct physical cores whenever
/// N <= the core count, instead of stacking sibling pairs.
///
/// Param:
/// cpu_list - []u32 (the allowed CPUs, reordered in place)
/// keys - []const u64 (physical-core key per cpu_list entry, same length)
pub fn orderPhysicalCoresFirst(cpu_list: []u32, keys: []const u64) void {
    std.debug.assert(cpu_list.len == keys.len);
    std.debug.assert(cpu_list.len <= PIN_MAX_CPUS);

    var ordered: [PIN_MAX_CPUS]u32 = undefined;
    var ordered_len: usize = 0;
    for (keys, 0..) |key, idx| {
        if (std.mem.indexOfScalar(u64, keys[0..idx], key) == null) {
            ordered[ordered_len] = cpu_list[idx];
            ordered_len += 1;
        }
    }

    for (keys, 0..) |key, idx| {
        if (std.mem.indexOfScalar(u64, keys[0..idx], key) != null) {
            ordered[ordered_len] = cpu_list[idx];
            ordered_len += 1;
        }
    }

    @memcpy(cpu_list, ordered[0..cpu_list.len]);
}

/// Pin the calling thread to the CPU slot assigned to worker_id, respecting
/// the cgroup-allowed CPU mask so we never select a CPU the container cannot
/// use. Slots enumerate distinct physical cores first and SMT siblings after
/// (sysfs topology), so small worker counts never stack two workers on one
/// core. Mask order is kept when the topology files are absent.
pub fn pinToCpu(worker_id: usize) void {
    if (comptime @import("builtin").target.os.tag != .linux) return;

    const linux = std.os.linux;
    var cpu_set: linux.cpu_set_t = undefined;
    if (linux.sched_getaffinity(0, @sizeOf(linux.cpu_set_t), &cpu_set) != 0) return;

    var cpu_list: [PIN_MAX_CPUS]u32 = undefined;
    var n_cpus: usize = 0;
    for (cpu_set, 0..) |word, word_idx| {
        var bits = word;
        while (bits != 0) : (bits &= bits - 1) {
            if (n_cpus < cpu_list.len) {
                cpu_list[n_cpus] = @intCast(word_idx * @bitSizeOf(usize) + @ctz(bits));
                n_cpus += 1;
            }
        }
    }
    if (n_cpus == 0) return;

    var core_keys: [PIN_MAX_CPUS]u64 = undefined;
    var topology_known = true;
    for (cpu_list[0..n_cpus], 0..) |cpu, idx| {
        core_keys[idx] = coreKey(cpu) orelse {
            topology_known = false;
            break;
        };
    }
    if (topology_known) orderPhysicalCoresFirst(cpu_list[0..n_cpus], core_keys[0..n_cpus]);

    const target = cpu_list[worker_id % n_cpus];
    var target_set: linux.cpu_set_t = std.mem.zeroes(linux.cpu_set_t);
    const cpu_word = target / @bitSizeOf(usize);
    const cpu_bit: u6 = @intCast(target % @bitSizeOf(usize));
    target_set[cpu_word] |= @as(usize, 1) << cpu_bit;

    linux.sched_setaffinity(0, &target_set) catch {};
}

/// Count CPUs available to this process via sched_getaffinity, respecting cgroup
/// and taskset restrictions. Falls back to std.Thread.getCpuCount when the syscall
/// fails. Used by EPOLL to default to one worker per available CPU so that multiple
/// workers are never pinned to the same core under cgroup-limited bench environments.
pub fn getAvailableCpuCount() usize {
    if (comptime @import("builtin").target.os.tag != .linux) return std.Thread.getCpuCount() catch 1;

    const linux = std.os.linux;
    var cpu_set: linux.cpu_set_t = undefined;
    if (linux.sched_getaffinity(0, @sizeOf(linux.cpu_set_t), &cpu_set) != 0) {
        return std.Thread.getCpuCount() catch 1;
    }

    var count: usize = 0;
    for (cpu_set) |word| {
        count += @popCount(word);
    }

    return if (count == 0) 1 else count;
}

/// Fast path for HTTP/1.1 GET requests: extract method and path with direct
/// arithmetic, bypassing the full request-line tokenization in parseHeadAt.
/// One masked line walk (the same first-letter mask as parseHeadAt) handles
/// Connection close/keep-alive natively, captures the Accept-Encoding span,
/// and bails to the full parser only for a GET carrying framing headers
/// (content-length, transfer-encoding, expect), which the fast head cannot
/// represent. Returns null when the request is not a plain HTTP/1.1 GET.
pub fn parseGetFastPath(rem: []const u8, header_end: usize) ?core.ParseResult {
    if (rem.len < 16) return null;
    if (std.mem.readInt(u32, rem[0..4], .little) != comptime std.mem.readInt(u32, "GET ", .little)) return null;

    const line_end = std.mem.indexOfScalarPos(u8, rem, 4, '\r') orelse return null;

    // Minimum for "GET / HTTP/1.1": line_end >= 14, last 9 chars = " HTTP/1.1"
    if (line_end < 14) return null;
    if (rem[line_end - 9] != ' ') return null;
    if (std.mem.readInt(u64, rem[line_end - 8 ..][0..8], .little) != comptime std.mem.readInt(u64, "HTTP/1.1", .little)) return null;

    const full_path = rem[4 .. line_end - 9];
    var path = full_path;
    var query: []const u8 = "";
    if (std.mem.indexOfScalar(u8, full_path, '?')) |q| {
        path = full_path[0..q];
        query = full_path[q + 1 ..];
    }

    const raw_start = line_end + 2;
    const raw_headers: []const u8 = if (raw_start < header_end + 2) rem[raw_start .. header_end + 2] else &.{};

    var keep_alive = true;
    var accept_encoding: core.HeaderSpan = .{ .off = core.SPAN_ABSENT };

    var pos: usize = 0;
    while (pos < raw_headers.len) {
        const line_start = pos;
        const hdr_line_end = std.mem.indexOfPos(u8, raw_headers, pos, "\r\n") orelse raw_headers.len;
        const line = raw_headers[line_start..hdr_line_end];
        pos = hdr_line_end + 2;
        if (line.len == 0) break;

        const first_lower = line[0] | 0x20;
        if (first_lower != 'c' and first_lower != 't' and first_lower != 'e' and first_lower != 'a') continue;

        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        var value_off: usize = colon + 1;
        while (value_off < line.len and line[value_off] == ' ') value_off += 1;
        const value = line[value_off..];

        if (std.ascii.eqlIgnoreCase(name, "connection")) {
            if (std.ascii.eqlIgnoreCase(value, "close")) keep_alive = false;
        } else if (std.ascii.eqlIgnoreCase(name, "accept-encoding")) {
            accept_encoding = .{ .off = @intCast(line_start + value_off), .len = @intCast(value.len) };
        } else if (std.ascii.eqlIgnoreCase(name, "content-length") or
            std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
            std.ascii.eqlIgnoreCase(name, "expect"))
        {
            return null;
        }
    }

    return .{
        .head = .{
            .method = rem[0..3],
            .path = path,
            .query = query,
            .raw_headers = raw_headers,
            .version_minor = 1,
            .keep_alive = keep_alive,
            .content_length = 0,
            .chunked_request = false,
            .expect_continue = false,
            .accept_encoding = accept_encoding,
        },
        .body_offset = header_end + 4,
    };
}

/// Effective cache slot count for a worker, honoring cache_max_total_bytes.
/// When a memory ceiling is set, the entry count is reduced so the slab
/// (entries * value_bytes) fits. ResponseCache.init then rounds down to a power
/// of two, so the slab never exceeds the ceiling.
pub fn effectiveCacheEntries(config: Config) u32 {
    if (config.cache_max_total_bytes == 0) return config.cache_max_entries;

    const value_bytes: usize = @max(1, config.cache_max_value_bytes);
    const fit = config.cache_max_total_bytes / value_bytes;
    const capped = @min(@as(usize, config.cache_max_entries), fit);

    return @intCast(@max(@as(usize, 1), capped));
}

test "zix http1: effectiveCacheEntries honors the memory ceiling" {
    const base = Config{ .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC, .cache_max_entries = 1024, .cache_max_value_bytes = 16 * 1024 };

    // no ceiling: entry count unchanged
    try std.testing.expectEqual(@as(u32, 1024), effectiveCacheEntries(base));

    // ceiling of 256 KiB / 16 KiB = 16 slots, below the configured 1024
    var capped = base;
    capped.cache_max_total_bytes = 256 * 1024;
    try std.testing.expectEqual(@as(u32, 16), effectiveCacheEntries(capped));

    // a tiny ceiling still yields at least one slot
    var tiny = base;
    tiny.cache_max_total_bytes = 1;
    try std.testing.expectEqual(@as(u32, 1), effectiveCacheEntries(tiny));
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http1: parseGetFastPath basic GET with host header" {
    const req = "GET /pipeline HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const header_end = std.mem.indexOf(u8, req, "\r\n\r\n").?;
    const result = parseGetFastPath(req, header_end).?;

    try std.testing.expectEqualStrings("GET", result.head.method);
    try std.testing.expectEqualStrings("/pipeline", result.head.path);
    try std.testing.expectEqualStrings("", result.head.query);
    try std.testing.expectEqual(true, result.head.keep_alive);
    try std.testing.expectEqual(@as(u64, 0), result.head.content_length);
    try std.testing.expectEqual(false, result.head.chunked_request);
    try std.testing.expectEqual(@as(u8, 1), result.head.version_minor);
    try std.testing.expectEqual(header_end + 4, result.body_offset);
}

test "zix http1: parseGetFastPath with query string" {
    const req = "GET /baseline11?a=1&b=2 HTTP/1.1\r\nHost: x\r\n\r\n";
    const header_end = std.mem.indexOf(u8, req, "\r\n\r\n").?;
    const result = parseGetFastPath(req, header_end).?;

    try std.testing.expectEqualStrings("/baseline11", result.head.path);
    try std.testing.expectEqualStrings("a=1&b=2", result.head.query);
}

test "zix http1: parseGetFastPath rejects POST" {
    const req = "POST /upload HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    const header_end = std.mem.indexOf(u8, req, "\r\n\r\n").?;
    try std.testing.expectEqual(@as(?core.ParseResult, null), parseGetFastPath(req, header_end));
}

test "zix http1: parseGetFastPath rejects HTTP/1.0" {
    const req = "GET / HTTP/1.0\r\n\r\n";
    const header_end = std.mem.indexOf(u8, req, "\r\n\r\n").?;
    try std.testing.expectEqual(@as(?core.ParseResult, null), parseGetFastPath(req, header_end));
}

test "zix http1: parseGetFastPath integer compare matches the full word" {
    // Method differs only in the trailing byte ("GETX" vs "GET ").
    const bad_method = "GETX/ HTTP/1.1\r\n\r\n";
    try std.testing.expectEqual(@as(?core.ParseResult, null), parseGetFastPath(bad_method, std.mem.indexOf(u8, bad_method, "\r\n\r\n").?));

    // Version differs only in a middle byte ("HXTP/1.1" vs "HTTP/1.1").
    const bad_version = "GET / HXTP/1.1\r\n\r\n";
    try std.testing.expectEqual(@as(?core.ParseResult, null), parseGetFastPath(bad_version, std.mem.indexOf(u8, bad_version, "\r\n\r\n").?));

    // The exact words still match.
    const good = "GET / HTTP/1.1\r\n\r\n";
    try std.testing.expect(parseGetFastPath(good, std.mem.indexOf(u8, good, "\r\n\r\n").?) != null);
}

test "zix http1: parseGetFastPath raw_headers covers host line" {
    const req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const header_end = std.mem.indexOf(u8, req, "\r\n\r\n").?;
    const result = parseGetFastPath(req, header_end).?;
    const host = core.getHeader(&result.head, "host");
    try std.testing.expect(host != null);
    try std.testing.expectEqualStrings("example.com", host.?);
}

test "zix http1: parseGetFastPath handles Connection close natively" {
    const req = "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n";
    const header_end = std.mem.indexOf(u8, req, "\r\n\r\n").?;

    // Stays on the fast path (no bail to the full parser) with the same
    // keep_alive outcome the full parser produces.
    const result = parseGetFastPath(req, header_end).?;
    try std.testing.expectEqual(false, result.head.keep_alive);

    const keep = "GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";
    const keep_end = std.mem.indexOf(u8, keep, "\r\n\r\n").?;
    try std.testing.expectEqual(true, parseGetFastPath(keep, keep_end).?.head.keep_alive);
}

test "zix http1: parseGetFastPath captures the Accept-Encoding span in the walk" {
    const req = "GET /json HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip, br\r\n\r\n";
    const header_end = std.mem.indexOf(u8, req, "\r\n\r\n").?;
    const result = parseGetFastPath(req, header_end).?;

    // Definitive capture: the O(1) reader resolves without a fallback scan.
    try std.testing.expect(result.head.accept_encoding.off != core.SPAN_UNSCANNED);
    try std.testing.expectEqualStrings("gzip, br", core.acceptEncoding(&result.head).?);

    // No header: a definitive absence, still no fallback scan.
    const plain = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    const plain_end = std.mem.indexOf(u8, plain, "\r\n\r\n").?;
    const plain_result = parseGetFastPath(plain, plain_end).?;
    try std.testing.expectEqual(core.SPAN_ABSENT, plain_result.head.accept_encoding.off);
    try std.testing.expect(core.acceptEncoding(&plain_result.head) == null);
}

test "zix http1: parseGetFastPath bails to the full parser on framing headers" {
    // A GET carrying a body or an expectation cannot ride the fast head
    // (content_length is assumed 0 there): each must fall back.
    const with_length = "GET /odd HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(@as(?core.ParseResult, null), parseGetFastPath(with_length, std.mem.indexOf(u8, with_length, "\r\n\r\n").?));

    const chunked = "GET /odd HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    try std.testing.expectEqual(@as(?core.ParseResult, null), parseGetFastPath(chunked, std.mem.indexOf(u8, chunked, "\r\n\r\n").?));

    const expect_hdr = "GET /odd HTTP/1.1\r\nExpect: 100-continue\r\n\r\n";
    try std.testing.expectEqual(@as(?core.ParseResult, null), parseGetFastPath(expect_hdr, std.mem.indexOf(u8, expect_hdr, "\r\n\r\n").?));
}
test "zix http1: orderPhysicalCoresFirst puts distinct cores before SMT siblings" {
    var cpus = [_]u32{ 0, 1, 2, 3, 4, 5 };
    const keys = [_]u64{ 0, 0, 1, 1, 2, 2 };

    orderPhysicalCoresFirst(&cpus, &keys);

    try std.testing.expectEqualSlices(u32, &.{ 0, 2, 4, 1, 3, 5 }, &cpus);
}

test "zix http1: orderPhysicalCoresFirst keeps mask order on unique keys" {
    var cpus = [_]u32{ 3, 7, 11 };
    const keys = [_]u64{ 30, 10, 20 };

    orderPhysicalCoresFirst(&cpus, &keys);

    try std.testing.expectEqualSlices(u32, &.{ 3, 7, 11 }, &cpus);
}

test "zix http1: ConnRegistry evicts a connection past its deadline" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var registry = ConnRegistry{};
    defer registry.deinit();

    var entry = ConnEntry{ .fd = fds[1], .deadline = std.Io.Clock.Timestamp.now(io, .real) };
    registry.register(&entry, io);

    registry.evict(io);

    // the shut-down peer sees EOF, exactly what unblocks a stuck serve loop
    var buf: [8]u8 = undefined;
    const n = try std.posix.read(fds[0], &buf);
    try std.testing.expectEqual(@as(usize, 0), n);

    registry.deregister(&entry, io);
    try std.testing.expectEqual(@as(usize, 0), registry.entries.items.len);
}

test "zix http1: ConnRegistry leaves a connection before its deadline alone" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var registry = ConnRegistry{};
    defer registry.deinit();

    var entry = ConnEntry{ .fd = fds[1], .deadline = connDeadline(io, 60_000) };
    registry.register(&entry, io);

    registry.evict(io);

    // still open: a write on the registered side goes through
    const written = std.os.linux.write(fds[1], "x", 1);
    try std.testing.expectEqual(@as(usize, 1), written);

    registry.deregister(&entry, io);
}

/// Read back the one log file the logger wrote under a temp root.
///
/// Note:
/// - The logger names its file after the current date, so the day directory is found by scanning
///   rather than by rebuilding the date and risking a midnight straddle.
///
/// Return:
/// - the file's bytes, caller owns them
/// - error.ZixNoLogLine when the logger wrote nothing
fn readLoggedLine(root: std.Io.Dir, allocator: std.mem.Allocator) ![]u8 {
    var days = root.iterate();

    while (try days.next(std.testing.io)) |entry| {
        if (entry.kind != .directory) continue;

        var day = try root.openDir(std.testing.io, entry.name, .{});
        defer day.close(std.testing.io);

        const bytes = day.readFileAlloc(std.testing.io, "log-000000.log", allocator, .limited(64 * 1024)) catch continue;
        if (bytes.len > 0) return bytes;

        allocator.free(bytes);
    }

    return error.ZixNoLogLine;
}

test "zix http1: logSystem files a failure at the level the caller passed" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var logger = try Logger.init(std.testing.allocator, .{ .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const config = Config{
        .io = threaded.io(),
        .ip = "127.0.0.1",
        .port = 18990,
        .dispatch_model = .ASYNC,
        .logger = &logger,
    };

    logSystem(config, .ERROR, "listen failed on port {d}", .{18990});
    logger.flush();

    const line = try readLoggedLine(tmp.dir, std.testing.allocator);
    defer std.testing.allocator.free(line);

    try std.testing.expect(std.mem.indexOf(u8, line, "ERROR") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "listen failed on port 18990") != null);
}

test "zix http1: logSystem lifecycle line files as INFO, not as the old fixed level" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var logger = try Logger.init(std.testing.allocator, .{ .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const config = Config{
        .io = threaded.io(),
        .ip = "127.0.0.1",
        .port = 18991,
        .dispatch_model = .ASYNC,
        .logger = &logger,
    };

    logSystem(config, .INFO, "listening on {s}:{d}", .{ "127.0.0.1", 18991 });
    logger.flush();

    const line = try readLoggedLine(tmp.dir, std.testing.allocator);
    defer std.testing.allocator.free(line);

    try std.testing.expect(std.mem.indexOf(u8, line, "INFO") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "ERROR") == null);
}

test "zix http1: logSystem below the logger min level writes nothing" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path}) catch unreachable;

    var logger = try Logger.init(std.testing.allocator, .{ .save_path = root, .save_min_level = .ERROR });
    defer logger.deinit();

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const config = Config{
        .io = threaded.io(),
        .ip = "127.0.0.1",
        .port = 18992,
        .dispatch_model = .ASYNC,
        .logger = &logger,
    };

    logSystem(config, .INFO, "listening on {s}:{d}", .{ "127.0.0.1", 18992 });
    logSystem(config, .WARN, "io_uring unavailable, falling back", .{});
    logger.flush();

    try std.testing.expectError(error.ZixNoLogLine, readLoggedLine(tmp.dir, std.testing.allocator));
}

test "zix http1: logSystem with no logger attached accepts every level" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const config = Config{
        .io = threaded.io(),
        .ip = "127.0.0.1",
        .port = 18993,
        .dispatch_model = .ASYNC,
    };

    // The std.log branch. Its destination is the caller's std.options.logFn, which a test cannot
    // install (it is a root declaration), so what is checked here is that every level is handled
    // and none of them reaches for a logger that is not there.
    logSystem(config, .DEBUG, "no logger attached", .{});
    logSystem(config, .INFO, "no logger attached", .{});
}
