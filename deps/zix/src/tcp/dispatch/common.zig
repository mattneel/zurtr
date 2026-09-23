//! zix tcp dispatch: helpers shared across the dispatch models (ADR-043).
//! Holds the per-connection primitive (ConnTask / dispatchConn), the
//! framed-engine wire format plus coalescing sink, and the small socket
//! helpers used by every model. Routes are runtime: each model threads a
//! HandlerFn function pointer, the framed ring bakes a comptime FrameFn.

const std = @import("std");
const builtin = @import("builtin");
const Config = @import("../config.zig");
const TcpServerConfig = Config.TcpServerConfig;
const Logger = @import("../../logger/logger.zig").Logger;
const win_io = @import("../../utils/windows_io.zig");
const peer_addr = @import("../../utils/peer_addr.zig");

const log = std.log.scoped(.zix_tcp);

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
pub fn logSystem(cfg: TcpServerConfig, level: Logger.Level, comptime fmt: []const u8, args: anytype) void {
    if (cfg.logger) |lg| {
        lg.system(level, "tcp", fmt, args);
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

/// User-provided connection handler. Receives the accepted stream and io.
/// The handler owns the stream for its lifetime. It must call stream.close(io) when done.
pub const HandlerFn = *const fn (stream: std.Io.net.Stream, io: std.Io) void;

/// Per-frame callback for the framed engine (runFramed). Called once per
/// length-prefixed frame (the engine drives the read/write loop, the callback
/// just processes one payload and writes a reply via frameRespond / writeAllFD).
/// Unlike HandlerFn it does not own the connection and never blocks, so it can
/// run on the single-threaded .URING completion ring (ADR-037).
pub const FrameFn = *const fn (payload: []const u8, fd: std.posix.fd_t) void;

/// Frame wire format for the framed engine: a 4-byte big-endian length prefix
/// followed by that many payload bytes. Frames larger than this are rejected
/// (the connection is closed).
pub const FRAME_LEN_PREFIX: usize = 4;
pub const FRAME_MAX_PAYLOAD: usize = 1 << 20;

/// Scratch buffer size backing the stream reader on the framed-connection path.
const FRAME_READ_BUF_SIZE: usize = 4096;

// --------------------------------------------------------- //
// Framed-engine response sink + helpers. While a sink is installed
// (tl_resp_sink, the .URING ring path), writes stage into it and coalesce into
// one ring send, otherwise they go straight to the fd (the blocking adapter).

/// Direct socket write, bypassing the coalescing sink.
fn rawFrameWrite(fd: std.posix.fd_t, data: []const u8) error{BrokenPipe}!void {
    if (comptime builtin.target.os.tag == .windows) return win_io.writeAll(fd, data);

    var remaining = data;
    while (remaining.len > 0) {
        const rc = std.posix.system.write(fd, remaining.ptr, remaining.len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.BrokenPipe;

                remaining = remaining[n..];
            },
            .INTR => continue,
            else => return error.BrokenPipe,
        }
    }
}

/// Coalescing sink for the framed .URING path. Oversize writes flush straight to
/// the fd (safe under the ring's half-duplex guarantee).
pub const RespSink = struct {
    fd: std.posix.fd_t,
    buf: []u8,
    len: usize = 0,
    failed: bool = false,

    pub fn append(self: *RespSink, bytes: []const u8) void {
        if (bytes.len > self.buf.len) {
            self.flush();
            rawFrameWrite(self.fd, bytes) catch {
                self.failed = true;
            };

            return;
        }

        if (self.len + bytes.len > self.buf.len) self.flush();

        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    pub fn flush(self: *RespSink) void {
        if (self.len == 0) return;

        rawFrameWrite(self.fd, self.buf[0..self.len]) catch {
            self.failed = true;
        };
        self.len = 0;
    }
};

/// Active sink for the current worker thread (set by the framed ring worker).
pub threadlocal var tl_resp_sink: ?*RespSink = null;

/// Write raw bytes to the connection: into the sink when one is installed
/// (coalesced ring send), otherwise straight to the fd.
pub fn writeAllFD(fd: std.posix.fd_t, data: []const u8) error{BrokenPipe}!void {
    if (tl_resp_sink) |sink| {
        sink.append(data);

        return if (sink.failed) error.BrokenPipe else {};
    }

    return rawFrameWrite(fd, data);
}

/// Send a length-prefixed frame: a 4-byte big-endian length followed by payload.
/// The framed-engine reply helper for a FrameFn callback.
pub fn frameRespond(fd: std.posix.fd_t, payload: []const u8) error{BrokenPipe}!void {
    var hdr: [FRAME_LEN_PREFIX]u8 = undefined;
    std.mem.writeInt(u32, &hdr, @intCast(payload.len), .big);

    try writeAllFD(fd, &hdr);
    try writeAllFD(fd, payload);
}

// --------------------------------------------------------- //

/// The peer of a connected socket as "1.2.3.4:5678", or "-" when it cannot be read.
///
/// Note:
/// - One line over the shared helper, which is also what the access records and the gRPC stream
///   records use, so every engine names a peer the same way.
pub fn getPeerAddr(fd: std.posix.fd_t, buf: []u8) []const u8 {
    return peer_addr.endpoint(fd, buf);
}

pub fn getMonotonicMs() u64 {
    if (comptime builtin.target.os.tag == .linux) {
        var spec: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &spec);
        const s: u64 = if (spec.sec >= 0) @intCast(spec.sec) else 0;
        const millis: u64 = if (spec.nsec >= 0) @as(u64, @intCast(spec.nsec)) / 1_000_000 else 0;
        return s * 1000 + millis;
    }

    if (comptime builtin.target.os.tag == .windows) return win_io.monotonicUs() / std.time.us_per_ms;

    var spec: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &spec);
    const s: u64 = if (spec.sec >= 0) @intCast(spec.sec) else 0;
    const millis: u64 = if (spec.nsec >= 0) @as(u64, @intCast(spec.nsec)) / 1_000_000 else 0;
    return s * 1000 + millis;
}

pub fn applyConnTimeout(sock_fd: std.posix.fd_t, recv_ms: u32, send_ms: u32) void {
    // setsockopt is POSIX-only in Zig 0.16 std: no socket timeouts on Windows.
    if (comptime @import("builtin").target.os.tag == .windows) return;

    if (recv_ms == 0 and send_ms == 0) return;

    if (recv_ms > 0) {
        const recv_tv = std.posix.timeval{ .sec = @intCast(recv_ms / 1000), .usec = @intCast((recv_ms % 1000) * 1000) };
        std.posix.setsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&recv_tv)) catch {};
    }

    if (send_ms > 0) {
        const send_tv = std.posix.timeval{ .sec = @intCast(send_ms / 1000), .usec = @intCast((send_ms % 1000) * 1000) };
        std.posix.setsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&send_tv)) catch {};
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
    handler: HandlerFn,
    logger: ?*Logger,
};

pub fn dispatchConn(task: ConnTask) void {
    var peer_buf: [64]u8 = undefined;
    const peer = getPeerAddr(task.stream.socket.handle, &peer_buf);
    const start = getMonotonicMs();
    task.handler(task.stream, task.io);
    if (task.logger) |lg| lg.conn(peer, getMonotonicMs() - start, null);
}

// --------------------------------------------------------- //

/// Blocking adapter: wrap a FrameFn in a per-connection HandlerFn that reads
/// length-prefixed frames and dispatches each. Used for every dispatch model
/// other than .URING so runFramed works everywhere.
pub fn frameAdapter(comptime frame_fn: FrameFn) HandlerFn {
    return struct {
        fn handle(stream: std.Io.net.Stream, io: std.Io) void {
            defer stream.close(io);
            const fd = stream.socket.handle;

            const payload_buf = std.heap.smp_allocator.alloc(u8, FRAME_MAX_PAYLOAD) catch return;
            defer std.heap.smp_allocator.free(payload_buf);

            var read_buf: [FRAME_READ_BUF_SIZE]u8 = undefined;
            var reader = stream.reader(io, &read_buf);

            while (true) {
                const len = reader.interface.takeVarInt(u32, .big, FRAME_LEN_PREFIX) catch return;
                if (len == 0 or len > FRAME_MAX_PAYLOAD) return;

                reader.interface.readSliceAll(payload_buf[0..len]) catch return;

                frame_fn(payload_buf[0..len], fd);
            }
        }
    }.handle;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix tcp dispatch: orderPhysicalCoresFirst puts distinct cores before SMT siblings" {
    var cpus = [_]u32{ 0, 1, 2, 3, 4, 5 };
    const keys = [_]u64{ 0, 0, 1, 1, 2, 2 };

    orderPhysicalCoresFirst(&cpus, &keys);

    try std.testing.expectEqualSlices(u32, &.{ 0, 2, 4, 1, 3, 5 }, &cpus);
}

test "zix tcp dispatch: orderPhysicalCoresFirst keeps mask order on unique keys" {
    var cpus = [_]u32{ 3, 7, 11 };
    const keys = [_]u64{ 30, 10, 20 };

    orderPhysicalCoresFirst(&cpus, &keys);

    try std.testing.expectEqualSlices(u32, &.{ 3, 7, 11 }, &cpus);
}

test "zix tcp dispatch: orderPhysicalCoresFirst handles uneven sibling groups" {
    var cpus = [_]u32{ 0, 1, 2 };
    const keys = [_]u64{ 7, 7, 9 };

    orderPhysicalCoresFirst(&cpus, &keys);

    try std.testing.expectEqualSlices(u32, &.{ 0, 2, 1 }, &cpus);
}

test "zix tcp dispatch: getAvailableCpuCount is at least one" {
    try std.testing.expect(getAvailableCpuCount() >= 1);
}
