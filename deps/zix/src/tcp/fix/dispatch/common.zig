//! zix fix dispatch: helpers shared across the dispatch models (ADR-043).
//! dispatchConn / ConnTask are the route-agnostic per-connection primitive used
//! by every model (routes ride inside the runtime FixServeOpts).

const std = @import("std");
const core = @import("../core.zig");
const FixServerConfig = @import("../config.zig").FixServerConfig;
const Logger = @import("../../../logger/logger.zig").Logger;

const log = std.log.scoped(.zix_fix);
const FixServeOpts = core.FixServeOpts;

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
pub fn logSystem(cfg: FixServerConfig, level: Logger.Level, comptime fmt: []const u8, args: anytype) void {
    if (cfg.logger) |lg| {
        lg.system(level, "fix", fmt, args);
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
// CPU accounting + pinning for the per-core dispatch models (.EPOLL / .URING).

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
/// fails. The per-core models default to one worker per available CPU so that
/// multiple workers are never pinned to the same core under a cpuset.
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

pub const ConnTask = struct {
    stream: std.Io.net.Stream,
    io: std.Io,
    comp_id: []const u8,
    opts: FixServeOpts,
};

pub fn dispatchConn(task: ConnTask) void {
    core.serveConn(task.stream, task.io, task.comp_id, task.opts) catch {};
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix fix: orderPhysicalCoresFirst puts distinct cores before SMT siblings" {
    var cpus = [_]u32{ 0, 1, 2, 3, 4, 5 };
    const keys = [_]u64{ 0, 0, 1, 1, 2, 2 };

    orderPhysicalCoresFirst(&cpus, &keys);

    try std.testing.expectEqualSlices(u32, &.{ 0, 2, 4, 1, 3, 5 }, &cpus);
}

test "zix fix: orderPhysicalCoresFirst keeps mask order on unique keys" {
    var cpus = [_]u32{ 3, 7, 11 };
    const keys = [_]u64{ 30, 10, 20 };

    orderPhysicalCoresFirst(&cpus, &keys);

    try std.testing.expectEqualSlices(u32, &.{ 3, 7, 11 }, &cpus);
}

test "zix fix: getAvailableCpuCount is at least one" {
    try std.testing.expect(getAvailableCpuCount() >= 1);
}
