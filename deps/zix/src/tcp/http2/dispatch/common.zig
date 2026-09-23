//! zix http2 dispatch: shared helpers across the dispatch models (ADR-043).
//! ConnTask carries a runtime handler: core.HandlerFn (built by the caller via
//! Router(routes).dispatch), so dispatchConn is a plain function, not a
//! comptime-routes-parameterized type.

const std = @import("std");
const builtin = @import("builtin");
const fd_io = @import("../../../utils/fd_io.zig");
const core = @import("../core.zig");
const async_cache = @import("../../../utils/async_cache.zig");
const frame = @import("../frame.zig");
const Http2ServerConfig = @import("../config.zig").Http2ServerConfig;
const Logger = @import("../../../logger/logger.zig").Logger;

const log = std.log.scoped(.zix_http2);

// --------------------------------------------------------- //

/// Emit a server line at the given level. Routes through cfg.logger when present.
///
/// Note:
/// - Without a logger the line still reaches std.log, so a release build never loses a failure.
///   std.log's own default level does the filtering: .ERROR and .WARN survive a release build,
///   .INFO and .DEBUG do not, and a caller who sets std.options.logFn can route or silence all
///   of them.
///
/// Param:
/// level - Logger.Level (.ERROR for a failure the reader must act on, .INFO for a lifecycle line)
pub fn logSystem(cfg: Http2ServerConfig, level: Logger.Level, comptime fmt: []const u8, args: anytype) void {
    if (cfg.logger) |lg| {
        lg.system(level, "http2", fmt, args);
        return;
    }

    switch (level) {
        .ERROR => log.err(fmt, args),
        .WARN => log.warn(fmt, args),
        .INFO => log.info(fmt, args),
        .DEBUG => log.debug(fmt, args),
    }
}

/// Build the per-connection serve options from the server config.
pub fn serveOpts(cfg: Http2ServerConfig) core.ServeOpts {
    return .{
        .max_streams = cfg.max_streams,
        .max_frame_size = cfg.max_frame_size,
        .max_header_scratch = cfg.max_header_scratch,
        .max_body = cfg.max_body,
        .logger = cfg.logger,
        .conn_read_buf_min = cfg.max_recv_buf,
        .tls_write_buf_initial = cfg.tls_write_buf_initial_bytes,
        .response_cache = cfg.response_cache,
        .cache_max_entries = cfg.cache_max_entries,
        .cache_max_value_bytes = cfg.cache_max_value_bytes,
        .cache_ttl_ms = cfg.cache_ttl_ms,
        .cache_max_total_bytes = cfg.cache_max_total_bytes,
        .handler_timeout_ms = cfg.handler_timeout_ms,
        .public_dir = cfg.public_dir,
    };
}

/// Effective cache slot count for a worker, honoring cache_max_total_bytes. When a memory ceiling is
/// set, the entry count is reduced so the slab (entries * value_bytes) fits. ResponseCache.init then
/// rounds down to a power of two, so the slab never exceeds the ceiling. Mirrors zix.Grpc.
pub fn effectiveCacheEntries(opts: core.ServeOpts) u32 {
    if (opts.cache_max_total_bytes == 0) return opts.cache_max_entries;

    const value_bytes: usize = @max(1, opts.cache_max_value_bytes);
    const fit = opts.cache_max_total_bytes / value_bytes;
    const capped = @min(@as(usize, opts.cache_max_entries), fit);

    return @intCast(@max(@as(usize, 1), capped));
}

/// Highest fd a worker's mux table can index (EPOLL / URING models). Linux hands out the lowest
/// free fd, so the table stays sparse. Connections on fds at or above this are refused.
pub const MAX_FD: usize = 1 << 16;

/// Disable Nagle on a TCP socket so small h2 frames leave promptly.
pub fn setNoDelay(fd: std.posix.fd_t) void {
    if (comptime builtin.target.os.tag != .windows) {
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

/// Close a connection fd.
///
/// Note:
/// - Delegates to the shared helper rather than branching here. It used to call the raw Linux close
///   on every platform but Windows, which off Linux aims a Linux syscall number at a kernel that
///   assigns it to something else, so the connection was never closed and something unrelated ran
///   in its place. fd_io owns the three-way branch (ntdll, raw syscall, libc) for every engine.
pub fn closeFD(fd: std.posix.fd_t) void {
    fd_io.close(fd);
}

/// Put a socket in non-blocking mode (listener and accepted fds in the event-driven paths).
pub fn setNonBlock(fd: std.posix.fd_t) void {
    // fcntl O_NONBLOCK is POSIX-only, and only the Linux event loops call this.
    if (comptime builtin.os.tag == .windows) return;

    const linux = std.os.linux;
    const cur = linux.fcntl(fd, std.posix.F.GETFL, 0);
    const nonblock: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
    _ = linux.fcntl(fd, std.posix.F.SETFL, cur | @as(usize, nonblock));
}

/// Spin up to `us` microseconds before the worker sleeps on a connection socket (SO_BUSY_POLL),
/// trading CPU for lower wake-up latency on saturated loopback benchmarks. us = 0 leaves it unset
/// (no syscall). Silent no-op when the kernel lacks SO_BUSY_POLL. Mirrors zix.Http1's setBusyPoll.
pub fn setBusyPoll(fd: std.posix.fd_t, us: u32) void {
    if (comptime builtin.os.tag == .windows) return;

    if (us == 0) return;

    const SO_BUSY_POLL: u32 = 46;
    std.posix.setsockopt(
        fd,
        std.posix.SOL.SOCKET,
        SO_BUSY_POLL,
        std.mem.asBytes(&@as(c_int, @intCast(us))),
    ) catch {};
}

// --------------------------------------------------------- //

/// Per-worker write-coalescing buffer for the cleartext h2 mux. Installed as the frame write hook
/// (`frame.write_hook`) around one readable batch, so every frame the mux writes (HEADERS, DATA,
/// SETTINGS, WINDOW_UPDATE) stages into one buffer and leaves as a single write per batch instead of
/// one write per frame. With TCP_NODELAY on, the unbatched path emitted a separate tiny TCP segment
/// per frame, so a 100-stream h2load batch cost about 200 segments and trailed the TLS mux (which
/// already coalesces into TLS records). The buffer flushes when full and writes an oversized frame
/// straight through, so correctness never depends on the buffer being large enough. One worker thread
/// owns it, so no synchronization is needed.
const MUX_COALESCE_BUF: usize = 64 * 1024;

const MuxCoalesceSink = struct {
    fd: std.posix.fd_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1,
    len: usize = 0,
    failed: bool = false,
    buf: [MUX_COALESCE_BUF]u8 = undefined,

    fn append(self: *MuxCoalesceSink, bytes: []const u8) void {
        if (bytes.len > self.buf.len) {
            self.flush();
            frame.writeAllRawFD(self.fd, bytes) catch {
                self.failed = true;
            };

            return;
        }

        if (self.len + bytes.len > self.buf.len) self.flush();

        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn flush(self: *MuxCoalesceSink) void {
        if (self.len == 0) return;

        frame.writeAllRawFD(self.fd, self.buf[0..self.len]) catch {
            self.failed = true;
        };
        self.len = 0;
    }
};

/// Per-worker coalescing sink. A threadlocal so each mux worker owns one, reused across the
/// connections it serves (only one connection's batch is in flight at a time on a worker).
threadlocal var tl_mux_sink: MuxCoalesceSink = .{};

fn muxCoalesceWrite(ctx: *anyopaque, bytes: []const u8) void {
    const sink: *MuxCoalesceSink = @ptrCast(@alignCast(ctx));
    sink.append(bytes);
}

/// Install the per-worker coalescing sink as the frame write hook for one readable batch. Pair every
/// call with endCoalesce (use defer). While installed, mux frame writes stage instead of hitting the
/// socket per frame.
pub fn beginCoalesce(fd: std.posix.fd_t) void {
    tl_mux_sink.fd = fd;
    tl_mux_sink.len = 0;
    tl_mux_sink.failed = false;
    frame.write_hook = muxCoalesceWrite;
    frame.write_hook_ctx = &tl_mux_sink;
}

/// Flush the staged batch and uninstall the hook.
///
/// Return:
/// - bool (true when a write failed during the batch, so the caller should close the connection)
pub fn endCoalesce() bool {
    tl_mux_sink.flush();
    frame.write_hook = null;
    frame.write_hook_ctx = null;

    return tl_mux_sink.failed;
}

// --------------------------------------------------------- //

pub const ConnTask = struct {
    fd: std.posix.fd_t,
    opts: core.ServeOpts,
    handler: core.HandlerFn,
    io: std.Io,
};

pub fn dispatchConn(task: ConnTask) void {
    defer closeFD(task.fd);

    // The multiplexed workers build one cache each and hold it for their whole life. .ASYNC has
    // no worker, so the cache is built once per io pool thread and reused by every connection
    // that lands on it. Reclaimed together when the accept loop ends.
    installThreadCache(task.opts);
    core.setAccessLogger(task.opts.logger);

    core.serveConn(task.handler, task.fd, task.opts, task.io);
}

/// Point this pool thread's response cache at the config, or clear it when caching is off.
pub fn installThreadCache(opts: core.ServeOpts) void {
    if (!opts.response_cache) {
        core.setCache(null, 0);

        return;
    }

    const cache = async_cache.forThisThread(.{
        .max_entries = effectiveCacheEntries(opts),
        .max_value_bytes = opts.cache_max_value_bytes,
    });

    core.setCache(cache, opts.cache_ttl_ms);
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
    defer closeFD(fd);

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

/// Count CPUs available to this process via sched_getaffinity, respecting cgroup and taskset
/// restrictions (falls back to std.Thread.getCpuCount on failure). The TLS epoll default of one
/// worker per available CPU so workers are never oversubscribed under a cgroup-limited cpuset.
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

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix http2: http2 effectiveCacheEntries honors the memory ceiling" {
    const base = core.ServeOpts{ .cache_max_entries = 1024, .cache_max_value_bytes = 16 * 1024 };

    // no ceiling: the configured entry count passes through
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

test "zix http2: http2 MuxCoalesceSink stages small writes and flushes them in order" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var sink = MuxCoalesceSink{ .fd = fds[1] };

    // Two small appends stay buffered (coalesced), nothing on the wire yet.
    sink.append("AAAA");
    sink.append("BBBB");
    try std.testing.expectEqual(@as(usize, 8), sink.len);
    try std.testing.expect(!sink.failed);

    // Flush sends both in one ordered write.
    sink.flush();
    var recv: [16]u8 = undefined;
    const n = try std.posix.read(fds[0], recv[0..]);
    try std.testing.expectEqual(@as(usize, 8), n);
    try std.testing.expectEqualStrings("AAAABBBB", recv[0..n]);
    try std.testing.expectEqual(@as(usize, 0), sink.len);
}

test "zix http2: http2 MuxCoalesceSink flushes the buffer then writes an oversized frame straight through" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var sink = MuxCoalesceSink{ .fd = fds[1] };

    // A staged prefix, then a frame larger than the whole buffer: the prefix flushes first to keep
    // wire order, then the oversized frame is written directly. The reader (a stream socket) sees the
    // prefix ahead of the large frame.
    sink.append("PFX");
    var big: [MUX_COALESCE_BUF + 16]u8 = undefined;
    @memset(&big, 'Z');
    sink.append(&big);
    try std.testing.expectEqual(@as(usize, 0), sink.len);
    try std.testing.expect(!sink.failed);

    var got: usize = 0;
    var first3: [3]u8 = undefined;
    var scratch: [4096]u8 = undefined;
    while (got < 3 + big.len) {
        const n = try std.posix.read(fds[0], scratch[0..]);
        if (n == 0) break;
        if (got < 3) {
            const take = @min(3 - got, n);
            @memcpy(first3[got..][0..take], scratch[0..take]);
        }
        got += n;
    }
    try std.testing.expectEqual(@as(usize, 3 + big.len), got);
    try std.testing.expectEqualStrings("PFX", first3[0..3]);
}
test "zix http2: orderPhysicalCoresFirst puts distinct cores before SMT siblings" {
    var cpus = [_]u32{ 0, 1, 2, 3, 4, 5 };
    const keys = [_]u64{ 0, 0, 1, 1, 2, 2 };

    orderPhysicalCoresFirst(&cpus, &keys);

    try std.testing.expectEqualSlices(u32, &.{ 0, 2, 4, 1, 3, 5 }, &cpus);
}

test "zix http2: orderPhysicalCoresFirst keeps mask order on unique keys" {
    var cpus = [_]u32{ 3, 7, 11 };
    const keys = [_]u64{ 30, 10, 20 };

    orderPhysicalCoresFirst(&cpus, &keys);

    try std.testing.expectEqualSlices(u32, &.{ 3, 7, 11 }, &cpus);
}
