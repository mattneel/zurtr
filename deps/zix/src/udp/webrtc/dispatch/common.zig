//! zix WebRTC dispatch substrate: everything the loops share, and no loop of its own (ADR-043).
//!
//! What:
//! - The parts of running a WebRTC server that are neither the loop nor the peers: binding a socket,
//!   drawing the randomness a connection needs, reading a clock, and picking a worker's CPU.
//! - This is the only place in the engine that reaches for ambient state. Everything under
//!   connection.zig takes its clock and its randomness from the caller, which is what keeps a full
//!   exchange testable in memory.
//!
//! Note:
//! - The peers a worker holds, and the fixed order one of them is answered in, live in worker.zig.
//!   That split is what lets the three loops differ only in how they learn a datagram arrived.

const std = @import("std");
const builtin = @import("builtin");

const Config = @import("../config.zig");
const WebrtcServerConfig = Config.WebrtcServerConfig;
const connection = @import("../connection.zig");
const datagram = @import("../../datagram.zig");
const secure_random = @import("../../../utils/secure_random.zig");
const srtp = @import("../media/srtp.zig");

const Logger = @import("../../../logger/logger.zig").Logger;

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const log = std.log.scoped(.zix_webrtc);

/// Emit a server line at the given level. Routes through config.logger when present.
///
/// Note:
/// - A lifecycle line stays silent without a logger. A server that narrates on its own is one a
///   test cannot run quietly, and the caller who wants those lines is the caller who passed a
///   logger.
/// - A failure does not get that treatment. .ERROR and .WARN reach std.log even with no logger, so
///   a release build never loses one, and a caller who sets std.options.logFn can still route or
///   silence them.
///
/// Param:
/// level - Logger.Level (.ERROR for a failure the reader must act on, .INFO for a lifecycle line)
pub fn logSystem(config: WebrtcServerConfig, level: Logger.Level, comptime fmt: []const u8, args: anytype) void {
    if (config.logger) |lg| {
        lg.system(level, "webrtc", fmt, args);
        return;
    }

    switch (level) {
        .ERROR => log.err(fmt, args),
        .WARN => log.warn(fmt, args),
        .INFO, .DEBUG => {},
    }
}

/// Draw the random values one connection is born with.
///
/// Note:
/// - An SCTP initiate tag of zero is the value a packet carrying an INIT uses, so it can never be
///   an endpoint's own tag (RFC 9260 3.1). Drawing one is possible, so it is corrected here.
///
/// Return:
/// - connection.Secrets
pub fn drawSecrets() connection.Secrets {
    var secrets: connection.Secrets = undefined;

    secure_random.fill(&secrets.dtls_cookie);
    secure_random.fill(&secrets.sctp_cookie);
    secure_random.fill(&secrets.server_random);
    secure_random.fill(&secrets.server_eph_secret);

    const tag = secure_random.int(u32);
    secrets.sctp_tag = if (tag == 0) 1 else tag;
    secrets.sctp_initial_tsn = secure_random.int(u32);

    return secrets;
}

/// The P-256 key pair out of the TLS context, or null when there is no context or its key is a
/// kind the one DTLS 1.2 suite cannot sign with.
///
/// Param:
/// config - WebrtcServerConfig
///
/// Return:
/// - ?EcdsaP256.KeyPair
pub fn ecdsaKey(config: WebrtcServerConfig) ?EcdsaP256.KeyPair {
    const tls = config.tls orelse return null;

    return switch (tls.signing_key) {
        .ecdsa_p256 => |pair| pair,
        else => null,
    };
}

/// Build the per-connection options out of the server config.
///
/// Note:
/// - Every slice is borrowed from the config, so the config has to outlive the server. That is the
///   same contract every other zix engine holds its caller to.
/// - Call only after run() has checked the config. A context with no usable key is rejected there,
///   before the socket is bound.
///
/// Param:
/// config - WebrtcServerConfig
///
/// Return:
/// - connection.Options
pub fn optionsFrom(config: WebrtcServerConfig) connection.Options {
    return .{
        .ice_ufrag = config.ice_ufrag,
        .ice_password = config.ice_password,
        .peer_ice_ufrag = if (config.accept_any_peer_ice_ufrag) null else config.peer_ice_ufrag,
        .certificate_der = if (config.tls) |tls| tls.cert_der else "",
        .signing_key = ecdsaKey(config).?,
        .max_handshake_fragment = config.max_handshake_fragment,
        .srtp_profiles = if (config.carry_media) Config.SRTP_PROFILES else &.{},
        .path_max_bytes = config.path_max_bytes,
        .max_datagram_bytes = config.max_recv_buf,
        .outbound_streams = config.outbound_streams,
        .inbound_streams = config.inbound_streams,
        .max_channels = config.max_channels,
        .peer_idle_ms = config.peer_idle_ms,
    };
}

/// How wide the outbound scratch buffer has to be for one datagram.
///
/// Note:
/// - The received size plus the SRTP overhead, because a forwarded packet is sealed under the
///   receiving peer's key and that peer's tag is not always the length the sender's was. Without
///   the headroom a packet crossing two different profiles has nowhere to be written.
pub fn sendBufBytes(config: WebrtcServerConfig) usize {
    return @max(config.max_recv_buf + srtp.MAX_OVERHEAD, config.path_max_bytes + connection.DTLS_OVERHEAD + 64);
}

/// Milliseconds between two readings of the same clock, never negative.
///
/// Param:
/// start - std.Io.Clock.Timestamp (the loop's own zero point)
/// now - std.Io.Clock.Timestamp
///
/// Return:
/// - u64
pub fn elapsedMs(start: std.Io.Clock.Timestamp, now: std.Io.Clock.Timestamp) u64 {
    const raw = std.Io.Clock.Timestamp.durationTo(start, now).raw.toMilliseconds();

    if (raw <= 0) return 0;

    return @intCast(raw);
}

/// Bind the UDP socket every model receives on.
///
/// Param:
/// config - WebrtcServerConfig
///
/// Return:
/// - std.Io.net.Socket, bound and ready to receive
/// - whatever resolve or bind raised
pub fn bindSocket(config: WebrtcServerConfig) !std.Io.net.Socket {
    const address = try std.Io.net.IpAddress.resolve(config.io, config.ip, config.port);
    const socket = try address.bind(config.io, .{ .mode = .dgram, .protocol = .udp });

    setSocketBuffers(socket.handle, config.socket_rcvbuf, config.socket_sndbuf);

    return socket;
}

/// Ask the kernel for larger socket buffers.
///
/// Note:
/// - Best effort. A kernel that clamps the request or refuses it leaves the default in place,
///   which is a slower server rather than a broken one.
/// - Nothing is asked for on Windows. std.posix.setsockopt is a compile error there since the
///   std.Io migration, and std.Io exposes no equivalent, so a Windows server keeps the default
///   buffers. Same as the raw UDP path, which gates this the same way.
pub fn setSocketBuffers(handle: std.posix.socket_t, rcvbuf: usize, sndbuf: usize) void {
    if (comptime builtin.target.os.tag == .windows) return;

    if (rcvbuf > 0) {
        const want = std.mem.toBytes(@as(c_int, @intCast(@min(rcvbuf, std.math.maxInt(c_int)))));
        std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, &want) catch {};
    }

    if (sndbuf > 0) {
        const want = std.mem.toBytes(@as(c_int, @intCast(@min(sndbuf, std.math.maxInt(c_int)))));
        std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, &want) catch {};
    }
}

/// Open the raw descriptor one Linux worker receives and replies on.
///
/// Note:
/// - SO_REUSEPORT, so every worker binds the same port and the kernel picks one by 4-tuple hash. A
///   WebRTC peer is identified by its transport address, which is that same 4-tuple, so all of one
///   peer's datagrams land on the worker holding that peer.
///
/// Param:
/// config - WebrtcServerConfig
///
/// Return:
/// - std.posix.socket_t, bound and ready to receive
/// - whatever the bind raised
pub fn openWorkerSocket(config: WebrtcServerConfig) !std.posix.socket_t {
    const fd = try datagram.open(config.ip, config.port, true);

    setSocketBuffers(fd, config.socket_rcvbuf, config.socket_sndbuf);

    return fd;
}

/// Monotonic milliseconds straight from the kernel clock, for the two Linux models.
///
/// Note:
/// - The portable model reads its clock through std.Io (elapsedMs). These two hold a raw descriptor
///   and never touch the Io, so they read the kernel clock the way every other Linux worker in the
///   family does.
/// - Off Linux this is unreachable: only epoll.zig and uring.zig call it, and run() rejects both
///   models there before a socket is bound.
///
/// Return:
/// - u64 (milliseconds since an unspecified fixed point, only differences are meaningful)
pub fn monotonicMs() u64 {
    if (comptime builtin.target.os.tag != .linux) return 0;

    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);

    return @as(u64, @intCast(ts.sec)) * std.time.ms_per_s + @as(u64, @intCast(@divTrunc(ts.nsec, std.time.ns_per_ms)));
}

/// How many workers the per-core models spawn: the configured count, or one per usable CPU.
///
/// Note:
/// - max_peers is counted per worker, so a server with N workers holds up to N * max_peers.
///
/// Param:
/// config - WebrtcServerConfig
///
/// Return:
/// - usize (at least one)
pub fn effectiveWorkers(config: WebrtcServerConfig) usize {
    if (config.workers != 0) return config.workers;

    return availableCpuCount();
}

/// CPUs this process may actually run on, so a cpuset-limited container never spawns more workers
/// than it has cores to put them on.
///
/// Return:
/// - usize (at least one)
pub fn availableCpuCount() usize {
    if (comptime builtin.target.os.tag != .linux) return std.Thread.getCpuCount() catch 1;

    var allowed: std.os.linux.cpu_set_t = undefined;
    if (std.os.linux.sched_getaffinity(0, @sizeOf(std.os.linux.cpu_set_t), &allowed) != 0) {
        return std.Thread.getCpuCount() catch 1;
    }

    var count: usize = 0;
    for (allowed) |word| count += @popCount(word);

    return if (count == 0) 1 else count;
}

/// Pin the calling thread to one CPU out of the allowed set, so a worker stays on the core its peer
/// table is warm on.
///
/// Note:
/// - Allowed-mask order, not sysfs topology order. The engines that saturate a box order physical
///   cores ahead of their SMT siblings, which matters when every core is busy. A WebRTC worker
///   spends most of its life waiting on a deadline, so the simpler selection is enough here.
/// - Silent no-op off Linux, and whenever the mask cannot be read or set.
///
/// Param:
/// worker_id - usize (wraps when there are more workers than CPUs)
///
/// Return:
/// - void
pub fn pinToCpu(worker_id: usize) void {
    if (comptime builtin.target.os.tag != .linux) return;

    const linux = std.os.linux;
    const Shift = std.math.Log2Int(usize);

    var allowed: linux.cpu_set_t = undefined;
    if (linux.sched_getaffinity(0, @sizeOf(linux.cpu_set_t), &allowed) != 0) return;

    var usable: usize = 0;
    for (allowed) |word| usable += @popCount(word);

    if (usable == 0) return;

    // Walk the set bits to the worker's own slot.
    var remaining = worker_id % usable;
    var chosen: usize = 0;

    outer: for (allowed, 0..) |word, word_index| {
        var bits = word;

        while (bits != 0) : (bits &= bits - 1) {
            if (remaining == 0) {
                chosen = word_index * @bitSizeOf(usize) + @ctz(bits);

                break :outer;
            }

            remaining -= 1;
        }
    }

    var target: linux.cpu_set_t = std.mem.zeroes(linux.cpu_set_t);
    const bit: Shift = @intCast(chosen % @bitSizeOf(usize));
    target[chosen / @bitSizeOf(usize)] |= @as(usize, 1) << bit;

    linux.sched_setaffinity(0, &target) catch {};
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const Tls = @import("../../../tls/Tls.zig");

/// Mutable because Tls.Context owns its certificate bytes, so the field is not const.
var test_certificate_der = [_]u8{ 0x30, 0x03, 0x01, 0x02, 0x03 };

/// A context carrying just the two fields this engine reads, so a test needs no certificate file.
fn testContext(allocator: std.mem.Allocator) !Tls.Context {
    var secret: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&secret, "0b76f7f1c7bf6e20029ddb566795e58da5ba63ffbdb914bf699bfbed3147d32c");

    return .{
        .allocator = allocator,
        .cert_der = &test_certificate_der,
        .signing_key = .{ .ecdsa_p256 = try EcdsaP256.KeyPair.fromSecretKey(try EcdsaP256.SecretKey.fromBytes(secret)) },
        .alpn = &.{},
        .curves = &.{},
        .ciphers = &.{},
        .min_version = .TLS_1_3,
        .max_version = .TLS_1_3,
        .prefer_server_ciphers = false,
        .hsts_max_age_s = 0,
    };
}

/// A logger that writes nowhere: console off and no save_path, so nothing is opened and nothing is
/// printed. It gives the rejection and drop paths a destination, which keeps a test's expected
/// failure message out of the runner's logged-error count.
var quiet_logger = Logger{ .config = .{}, .allocator = std.testing.allocator };

fn testConfig(io: std.Io, allocator: std.mem.Allocator, tls: *Tls.Context) WebrtcServerConfig {
    return .{
        .io = io,
        .allocator = allocator,
        .ip = "127.0.0.1",
        .port = 9083,
        .dispatch_model = .ASYNC,
        .ice_ufrag = "zixL",
        .ice_password = "zixlocalpasswordaaaaaa",
        .peer_ice_ufrag = "peer",
        .tls = tls,
        .logger = &quiet_logger,
    };
}

test "zix webrtc: dispatch common, options carry the config through unchanged" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.path_max_bytes = 1100;
    config.max_channels = 8;
    config.peer_idle_ms = 12_000;

    const options = optionsFrom(config);

    try std.testing.expectEqualStrings("zixL", options.ice_ufrag);
    try std.testing.expectEqualStrings("peer", options.peer_ice_ufrag.?);
    try std.testing.expectEqual(@as(usize, 1100), options.path_max_bytes);
    try std.testing.expectEqual(@as(usize, 8), options.max_channels);
    try std.testing.expectEqual(@as(u32, 12_000), options.peer_idle_ms);
    try std.testing.expectEqual(config.max_recv_buf, options.max_datagram_bytes);

    // Media is off, so the handshake offers no use_srtp and exports no keys.
    try std.testing.expectEqual(@as(usize, 0), options.srtp_profiles.len);
}

test "zix webrtc: dispatch common, carrying media puts the profiles in front of the handshake" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.carry_media = true;

    const options = optionsFrom(config);

    try std.testing.expectEqual(Config.SRTP_PROFILES.len, options.srtp_profiles.len);
    try std.testing.expectEqual(Config.SRTP_PROFILES[0], options.srtp_profiles[0]);
}

test "zix webrtc: dispatch common, taking any peer ufrag drops the name the config held" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.accept_any_peer_ice_ufrag = true;

    // The name stays in the config and stops being read, so a caller that sets both gets the
    // behaviour it asked for last rather than a silent contradiction.
    try std.testing.expectEqual(@as(?[]const u8, null), optionsFrom(config).peer_ice_ufrag);
    try std.testing.expectEqualStrings("peer", config.peer_ice_ufrag);
}

test "zix webrtc: dispatch common, the send buffer always holds a wrapped path-sized packet" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.max_recv_buf = 512;
    config.path_max_bytes = 1200;

    try std.testing.expect(sendBufBytes(config) >= config.path_max_bytes + connection.DTLS_OVERHEAD);
}

test "zix webrtc: dispatch common, drawn secrets never carry a zero initiate tag" {
    for (0..64) |_| {
        const secrets = drawSecrets();

        try std.testing.expect(secrets.sctp_tag != 0);
    }
}

test "zix webrtc: dispatch common, drawn secrets differ between connections" {
    const first = drawSecrets();
    const second = drawSecrets();

    try std.testing.expect(!std.mem.eql(u8, &first.server_random, &second.server_random));
    try std.testing.expect(!std.mem.eql(u8, &first.dtls_cookie, &second.dtls_cookie));
}

test "zix webrtc: dispatch common, an unread clock reports no time passed" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    const start = std.Io.Clock.Timestamp.now(threaded.io(), .awake);

    try std.testing.expectEqual(@as(u64, 0), elapsedMs(start, start));
}

test "zix webrtc: dispatch common, the monotonic clock only moves forward" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const first = monotonicMs();
    const second = monotonicMs();

    try std.testing.expect(second >= first);
}

test "zix webrtc: dispatch common, the worker count follows the config and then the cpus" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();

    var tls = try testContext(std.testing.allocator);
    var config = testConfig(threaded.io(), std.testing.allocator, &tls);
    config.workers = 3;

    try std.testing.expectEqual(@as(usize, 3), effectiveWorkers(config));

    config.workers = 0;
    try std.testing.expect(effectiveWorkers(config) >= 1);
    try std.testing.expectEqual(availableCpuCount(), effectiveWorkers(config));
}

test "zix webrtc: dispatch common, pinning a worker to any slot is survivable" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    // The pin moves the calling thread, and here that thread is the test runner, so its own mask is
    // put back before anything else runs.
    var original: linux.cpu_set_t = undefined;
    if (linux.sched_getaffinity(0, @sizeOf(linux.cpu_set_t), &original) != 0) {
        std.log.info("the thread affinity mask could not be read, the pin cannot be checked, test skipped", .{});
        return;
    }

    defer linux.sched_setaffinity(0, &original) catch {};

    // Best effort by design: a mask it cannot read or set leaves the thread where it is. What this
    // pins down is that no worker index, including one past the CPU count, faults or lands nowhere.
    pinToCpu(0);
    pinToCpu(1);
    pinToCpu(1024);

    try std.testing.expect(availableCpuCount() >= 1);
}
