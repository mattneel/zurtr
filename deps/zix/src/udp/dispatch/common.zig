//! zix udp raw-bytes dispatch helpers (ADR-049), shared by the per-model run files.
//!
//! What:
//! - Only what the per-model files share: the per-datagram serve (`serveDatagram`), the recvmmsg worker
//!   loop (`workerLoop`) plus its run shape (`runSingle` - one worker for .ASYNC, the portable
//!   SO_REUSEPORT worker per CPU for .EPOLL / .URING, which ADR-050 defines as multi-core), the worker
//!   helpers (`effectiveWorkers` / `pinToCpu` / `setBusyPoll`), and the non-Linux fallback. The per-core
//!   EPOLL and URING workers own their own loops in `epoll.zig` and `uring.zig` (ADR-050: each model is
//!   independently tunable, .URING is a real io_uring ring, not an alias of .EPOLL).

const std = @import("std");
const builtin = @import("builtin");

const Config = @import("../config.zig");
const UdpServerConfig = Config.UdpServerConfig;
const core = @import("../core.zig");
const datagram = @import("../datagram.zig");
const Logger = @import("../../logger/logger.zig").Logger;

const log = std.log.scoped(.zix_udp);

const posix = std.posix;
const IpAddress = std.Io.net.IpAddress;

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
pub fn logSystem(config: UdpServerConfig, level: Logger.Level, comptime fmt: []const u8, args: anytype) void {
    if (config.logger) |lg| {
        lg.system(level, "udp", fmt, args);
        return;
    }

    switch (level) {
        .ERROR => log.err(fmt, args),
        .WARN => log.warn(fmt, args),
        .INFO => log.info(fmt, args),
        .DEBUG => log.debug(fmt, args),
    }
}

/// Effective worker count: the configured value, or one per available CPU when 0. cgroup-aware so a
/// taskset / cpuset-limited environment never spawns more SO_REUSEPORT workers than usable cores.
pub fn effectiveWorkers(config: UdpServerConfig) usize {
    if (config.workers != 0) return config.workers;

    return getAvailableCpuCount();
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

/// Count CPUs available to this process via sched_getaffinity, respecting cgroup and taskset
/// restrictions (falls back to std.Thread.getCpuCount on failure). One worker per available CPU so
/// several SO_REUSEPORT workers are never pinned to the same core under a cgroup-limited cpuset.
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

/// Spin up to `us` microseconds before the worker sleeps on the UDP socket (SO_BUSY_POLL), trading
/// CPU for lower recvmmsg wake-up latency on saturated benchmarks. us = 0 leaves it unset (no
/// syscall). Silent no-op when the kernel lacks SO_BUSY_POLL. Mirrors zix.Http1's setBusyPoll.
pub fn setBusyPoll(fd: posix.socket_t, us: u32) void {
    if (comptime @import("builtin").target.os.tag == .windows) return;

    if (us == 0) return;

    const SO_BUSY_POLL: u32 = 46;
    posix.setsockopt(
        fd,
        posix.SOL.SOCKET,
        SO_BUSY_POLL,
        std.mem.asBytes(&@as(c_int, @intCast(us))),
    ) catch {};
}

/// Serve one received datagram to the raw handler: present the peer address and a Sink over the send
/// batch, then invoke the handler. Shared by the single-worker loop (workerLoop) and the per-core epoll
/// / io_uring workers (epoll.zig / uring.zig), so the handler-invocation shape lives in one place.
pub fn serveDatagram(comptime handler: core.HandlerFn, dg: datagram.Datagram, tx: *datagram.SendBatch, fd: posix.socket_t) void {
    const peer = datagram.sockaddr6ToIp(dg.from);
    var sink = core.Sink{ .batch = tx, .fd = fd, .sender = dg.from };
    handler(dg.data, &peer, &sink);
}

/// One worker: a recvmmsg batch in, handler per datagram, sendmmsg out. `reuse` sets SO_REUSEPORT
/// (required when several workers bind the same port). Per-core mode (reuse == true) pins this worker
/// to its assigned CPU. The single-worker mode (reuse == false) stays unpinned.
pub fn workerLoop(comptime handler: core.HandlerFn, config: UdpServerConfig, reuse: bool, worker_id: usize) void {
    if (reuse) pinToCpu(worker_id);

    const fd = datagram.open(config.ip, config.port, reuse) catch |err| {
        logSystem(config, .ERROR, "raw bind failed on {s}:{d} ({s})", .{ config.ip, config.port, @errorName(err) });

        return;
    };
    defer datagram.close(fd);

    // Announced below the bind, not above it: the caller's old line claimed a socket that may
    // never have been opened. Only the single-worker caller announces here, a REUSEPORT group
    // has its own line once the whole group reports.
    if (!reuse) logSystem(config, .INFO, "raw listening on {s}:{d} (single worker)", .{ config.ip, config.port });

    setBusyPoll(fd, config.busy_poll_us);

    var rx = datagram.RecvBatch.init(config.allocator, config.recv_batch, config.max_recv_buf) catch return;
    defer rx.deinit();

    var tx = datagram.SendBatch.init(config.allocator, config.send_batch, config.send_batch * config.max_recv_buf) catch return;
    defer tx.deinit();

    // GSO coalescing on the send path, only when requested and the kernel supports UDP_SEGMENT.
    tx.gso = config.gso_enabled and datagram.probeGso(fd);

    while (true) {
        const count = rx.recv(fd) catch |err| {
            if (config.logger) |lg| lg.system(.WARN, "udp", "raw recv error: {}", .{err});
            continue;
        };

        for (0..count) |i| serveDatagram(handler, rx.get(i), &tx, fd);

        tx.flush(fd) catch |err| {
            if (config.logger) |lg| lg.system(.WARN, "udp", "raw send error: {}", .{err});
            tx.reset();
        };
    }
}

/// Single worker on the calling thread. Used by the .ASYNC model, the only portable one.
pub fn runSingle(comptime handler: core.HandlerFn, config: UdpServerConfig) !void {
    if (!datagram.is_linux) return runFallback(handler, config);

    workerLoop(handler, config, config.reuse_address, 0);
}

/// The descriptor the portable loop hands the sink. Never opened and never sent on: the batch
/// carries a PortableSink, so the flush the sink can reach goes through std.Io.
const NO_SOCKET: posix.socket_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;

/// Portable single-socket fallback for non-Linux targets: one datagram per receive, replies sent
/// individually through std.Io.net (no recvmmsg / sendmmsg batching).
pub fn runFallback(comptime handler: core.HandlerFn, config: UdpServerConfig) !void {
    const io = config.io;

    const addr = try IpAddress.parse(config.ip, config.port);
    const socket = try addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    logSystem(config, .INFO, "raw listening on {s}:{d} (fallback)", .{ config.ip, config.port });

    const buf = try config.allocator.alloc(u8, config.max_recv_buf);
    defer config.allocator.free(buf);

    var tx = try datagram.SendBatch.init(config.allocator, config.send_batch, config.send_batch * config.max_recv_buf);
    defer tx.deinit();

    // A handler that replies more than the batch holds makes the sink flush mid-handler, and the
    // descriptor it has here was never opened. The batch carries the bound socket so that flush
    // sends through std.Io: without it the queued replies would be dropped and never reported.
    tx.portable = .{ .socket = socket, .io = io };

    while (true) {
        const msg = socket.receive(io, buf) catch continue;

        const sender = datagram.ipToSockaddr6(msg.from);
        const peer = msg.from;
        var sink = core.Sink{ .batch = &tx, .fd = NO_SOCKET, .sender = sender };
        handler(msg.data, &peer, &sink);

        for (0..tx.count) |i| {
            const dest = datagram.sockaddr6ToIp(tx.names[i]);
            socket.send(io, &dest, tx.iovs[i].base[0..tx.iovs[i].len]) catch {};
        }
        tx.reset();
    }
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix udp: udp effectiveWorkers honors an explicit count and defaults to the cpuset-aware count" {
    const base = UdpServerConfig{ .allocator = std.testing.allocator, .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC };

    // an explicit worker count passes through unchanged
    var explicit = base;
    explicit.workers = 3;
    try std.testing.expectEqual(@as(usize, 3), effectiveWorkers(explicit));

    // workers = 0 defaults to the cgroup-aware count, never zero
    try std.testing.expect(effectiveWorkers(base) >= 1);
    try std.testing.expectEqual(getAvailableCpuCount(), effectiveWorkers(base));
}

test "zix udp: udp pinToCpu is a no-op-safe call for any worker_id" {
    // The modulo keeps a derived slot inside the available set, so an out-of-range worker_id must
    // not crash and the process keeps a valid affinity mask.
    pinToCpu(0);
    pinToCpu(999);
}
test "zix udp: orderPhysicalCoresFirst puts distinct cores before SMT siblings" {
    var cpus = [_]u32{ 0, 1, 2, 3, 4, 5 };
    const keys = [_]u64{ 0, 0, 1, 1, 2, 2 };

    orderPhysicalCoresFirst(&cpus, &keys);

    try std.testing.expectEqualSlices(u32, &.{ 0, 2, 4, 1, 3, 5 }, &cpus);
}

test "zix udp: orderPhysicalCoresFirst keeps mask order on unique keys" {
    var cpus = [_]u32{ 3, 7, 11 };
    const keys = [_]u64{ 30, 10, 20 };

    orderPhysicalCoresFirst(&cpus, &keys);

    try std.testing.expectEqualSlices(u32, &.{ 3, 7, 11 }, &cpus);
}
