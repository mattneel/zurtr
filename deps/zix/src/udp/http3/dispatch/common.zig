//! zix HTTP/3 dispatch helpers, shared by the per-model run files.
//!
//! What:
//! - The v1 single-worker recv loop: bind one UDP socket, receive datagrams in recvmmsg batches,
//!   parse the QUIC header to extract the Destination Connection ID, and demux to a per-connection
//!   slot (creating one for a new Initial). One worker owns the whole CID table, so connection
//!   migration is just a new peer address on an existing CID, no cross-core routing (ADR-049 phase 3).
//!
//! Note:
//! - Driving the TLS-over-QUIC handshake on the demuxed connection (decrypt the Initial, run the
//!   src/tls handshake over the CRYPTO stream, install Handshake / 1-RTT keys, answer requests
//!   through `handler`) is the live-handshake step layered on this recv / demux substrate.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const ZIG_SEMVER = @import("../../../lib.zig").ZIG_SEMVER;
const win_io = @import("../../../utils/windows_io.zig");
const peer_addr = @import("../../../utils/peer_addr.zig");

const Config = @import("../config.zig");
const Http3ServerConfig = Config.Http3ServerConfig;
const core = @import("../core.zig");
const h3 = @import("../h3.zig");
const connection_module = @import("../connection.zig");
const datagram = @import("../../datagram.zig");
const packet = @import("../packet.zig");
const protection = @import("../protection.zig");
const frame = @import("../frame.zig");
const certificate = @import("../../../tls/certificate.zig");
const varint = @import("../varint.zig");
const serverhello = @import("../serverhello.zig");
const flight = @import("../flight.zig");
const response = @import("../response.zig");
const request = @import("../request.zig");
const reassembly = @import("../reassembly.zig");
const huffman = @import("../huffman.zig");
const transport_params = @import("../transport_params.zig");
const keyschedule = @import("../keyschedule.zig");
const demux = @import("../demux.zig");
const flow = @import("../flow.zig");
const close = @import("../close.zig");
const recovery = @import("../recovery.zig");
const Connection = @import("../connection.zig").Connection;
const static = @import("../static.zig");
const SendStream = @import("../connection.zig").SendStream;
const SentRangeInfo = @import("../connection.zig").SentRangeInfo;
const max_sent_ranges = @import("../connection.zig").max_sent_ranges;
const tls_handshake = @import("../../../tls/handshake.zig");
const Logger = @import("../../../logger/logger.zig").Logger;

const wt = @import("../webtransport/session.zig");
const wt_capsule = @import("../webtransport/capsule.zig");
const wt_datagram = @import("../webtransport/datagram.zig");
const wt_draft = @import("../webtransport/draft.zig");
const wt_pool = @import("../webtransport/pool.zig");
const wt_stream_header = @import("../webtransport/stream_header.zig");
const Webtransport = @import("../webtransport/Webtransport.zig");

const log = std.log.scoped(.zix_http3);

/// Fill buf with cryptographically secure random bytes.
fn secureRandom(buf: []u8) void {
    if (comptime builtin.target.os.tag == .linux) {
        _ = linux.getrandom(buf.ptr, buf.len, 0);
        return;
    }

    if (comptime builtin.target.os.tag == .windows) {
        win_io.secureRandom(buf) catch {};
        return;
    }

    std.c.arc4random_buf(buf.ptr, buf.len);
}

/// Maximum connections one v1 worker tracks. The table is heap-allocated, each Connection is large.
pub const max_connections = 256;

/// The CID-keyed connection table one worker owns.
pub const ConnTable = demux.Table(Connection, max_connections);

/// One coalesced 1-RTT response packet's payload budget. Several small responses pack into one packet
/// (one AEAD seal, one short header) up to this, instead of a packet per response. Kept under
/// max_datagram_size (1200) once the short header and the AEAD tag are added, so the packed packet is
/// still one unfragmented datagram.
const COALESCE_PAYLOAD_MAX: usize = 1100;

/// The largest 1-RTT datagram the response path will ever emit, a compile-time ceiling. It bounds the
/// pump's per-packet scratch buffer and the send-batch slot size, so the runtime datagram size (the
/// smaller of config.max_datagram_size and the client's advertised max_udp_payload_size) can never
/// outgrow the buffers. 16 KiB fragments a ~63 KiB static response into 4 datagrams instead of 53 at
/// the 1200 minimum, cutting the per-packet header / AEAD / ACK work that dominates a big-response run.
pub const max_send_datagram_size: usize = 16 * 1024;

/// Bytes held back inside a datagram for the short header, packet number, STREAM frame header, the AEAD
/// tag, and the small control frames the first response packet coalesces (HANDSHAKE_DONE, SETTINGS, an
/// ACK, MAX_STREAMS). The stream-data chunk per packet is the datagram size minus this, so a sealed
/// packet always fits its datagram with room to spare.
const per_packet_frame_reserve: usize = 160;

/// The send-batch slot size for the configured datagram size: one sealed 1-RTT packet at the datagram
/// size (clamped to the ceiling) plus the seal overhead. Reused by every send-batch allocation site so
/// the batch backing grows with config.max_datagram_size instead of the recv MTU (which stays small,
/// since inbound datagrams are requests and ACKs).
pub fn sendSlotSize(config: Http3ServerConfig) usize {
    return @min(@as(usize, @intCast(config.max_datagram_size)), max_send_datagram_size) + protection.short_seal_overhead_max;
}

/// The send-batch backing size for one worker: send_batch slots at the configured datagram size.
pub fn sendBufBytes(config: Http3ServerConfig) usize {
    return config.send_batch * sendSlotSize(config);
}

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
pub fn logSystem(config: Http3ServerConfig, level: Logger.Level, comptime fmt: []const u8, args: anytype) void {
    if (config.logger) |lg| {
        lg.system(level, "http3", fmt, args);
        return;
    }

    switch (level) {
        .ERROR => log.err(fmt, args),
        .WARN => log.warn(fmt, args),
        .INFO => log.info(fmt, args),
        .DEBUG => log.debug(fmt, args),
    }
}

/// What processing one datagram produced, for the recv loop to log.
pub const Event = union(enum) {
    /// Not a parseable QUIC packet, or the table was full.
    ignored,
    /// Demuxed to a connection (short header, or a long header that is not an Initial).
    demuxed,
    /// A long-header Initial that failed to decrypt under the Initial keys.
    decrypt_failed,
    /// An Initial decrypted: the recovered packet number, no complete ClientHello yet.
    initial_opened: u64,
    /// A complete ClientHello decoded from the reassembled CRYPTO stream: its byte length.
    client_hello: usize,
    /// An Initial decrypted but the ClientHello failed to parse (a TLS alert condition).
    parse_alert,
    /// A client Handshake-level packet decrypted with the derived Handshake keys (proves the
    /// handshake-secret derivation is correct against the client).
    handshake_opened,
    /// A client Handshake-level packet whose CRYPTO bytes carried the client's Finished, verified: the
    /// TLS handshake is complete, so the server owes the client its handshake confirmation.
    handshake_finished,
    /// A client Finished arrived and did not verify: the handshake stays unconfirmed.
    finished_mismatch,
    /// A CONNECTION_CLOSE arrived inside a Handshake-level packet, carrying the reason the client gave.
    handshake_close: close.ConnClose,
    /// A client 1-RTT packet decrypted with the derived application keys (proves the 1-RTT key
    /// derivation is correct against the client, the request is now readable).
    request_opened,
};

/// Process one received datagram: demux it to a connection and decrypt by encryption level. A new
/// Initial opens a connection (keyed by the client's chosen DCID), Handshake / 1-RTT packets address
/// the connection by the Source Connection ID we issued (our_scid).
pub fn processDatagram(table: *ConnTable, data: []const u8, cid_len: usize, max_datagram_size: u64, initial_window_packets: usize) Event {
    if (data.len == 0) return .ignored;

    if (data[0] & 0x80 != 0) {
        const hdr = packet.parseLongHeader(data) catch return .ignored;
        const dcid = demux.ConnId.fromSlice(hdr.dcid);

        const conn = findConn(table, &dcid) orelse blk: {
            if (hdr.packet_type != 0) return .demuxed;
            break :blk table.put(dcid, Connection.init(hdr.dcid, max_datagram_size, initial_window_packets)) orelse return .ignored;
        };
        conn.anti_amplification.onReceive(data.len);

        if (hdr.packet_type == 0) return openClientInitial(conn, data);

        // A client Handshake packet: decrypt with the derived client Handshake keys. Success proves
        // the handshake-secret derivation (transcript + ECDHE + key schedule) matches byte-exact, and the
        // packet carries the client's Finished: the CRYPTO bytes are fed and verified here, because a
        // verified Finished is what makes the handshake complete.
        if (hdr.packet_type == 2 and conn.handshake_ready) {
            var hbuf: [2048]u8 = undefined;
            if (protection.openHandshake(data, conn.hs_keys.client, &hbuf)) |opened| {
                // A client that gives up during the handshake says why here: a TLS alert (an
                // unverifiable certificate, an unacceptable parameter) arrives as a CONNECTION_CLOSE
                // carrying the alert code and the client's own description. It is worth surfacing,
                // because the connection otherwise just goes quiet.
                if (close.parseConnectionClose(opened.payload)) |cc| {
                    // The parsed reason points into `hbuf`, which dies with this call, and the event's
                    // reader is the caller that logs it: keep the reason on the connection instead.
                    conn.close_reason_len = @min(cc.reason.len, conn.close_reason.len);
                    @memcpy(conn.close_reason[0..conn.close_reason_len], cc.reason[0..conn.close_reason_len]);

                    return .{ .handshake_close = .{
                        .is_application = cc.is_application,
                        .error_code = cc.error_code,
                        .frame_type = cc.frame_type,
                        .reason = conn.close_reason[0..conn.close_reason_len],
                    } };
                } else |_| {}

                feedHandshakeFrames(conn, opened.payload);

                return switch (clientFinishedState(conn)) {
                    .verified => .handshake_finished,
                    .mismatch => .finished_mismatch,
                    .incomplete => .handshake_opened,
                };
            } else |_| {}
        }

        return .demuxed;
    }

    // Short header (1-RTT): the Destination CID is the connection id we issued (cid_len bytes).
    if (data.len < 1 + cid_len) return .ignored;
    const dcid = demux.ConnId.fromSlice(data[1 .. 1 + cid_len]);
    const conn = findConn(table, &dcid) orelse return .demuxed;
    conn.anti_amplification.onReceive(data.len);

    if (conn.app_ready) {
        var sbuf: [2048]u8 = undefined;
        // Reconstruct the truncated packet number against the largest 1-RTT number decoded so far
        // (null before the first), so decryption keeps working past packet 256 (RFC 9000 A.3).
        const largest_pn: ?u64 = if (conn.ack.have_largest) conn.ack.largest_pn else null;
        if (protection.openShort(data, conn.app_keys.client, conn.our_scid.len, largest_pn, &sbuf)) |opened| {
            conn.ack.record(opened.packet_number);

            // Copy the decrypted payload onto the connection so sendResponseFD walks every request stream
            // it carries without decrypting again. sbuf is stack-local to this call.
            const copied = @min(opened.payload.len, conn.app_payload_buf.len);
            @memcpy(conn.app_payload_buf[0..copied], opened.payload[0..copied]);
            conn.app_payload_len = copied;

            return .request_opened;
        } else |_| {}
    }

    return .demuxed;
}

/// Find a connection by the Destination Connection ID. After ServerHello the client addresses the
/// connection by the Source CID the server issued (our_scid), which sendServerHelloFD adds to the demux
/// index as an alias, so both the original client DCID and our_scid resolve here in O(1).
fn findConn(table: *ConnTable, dcid: *const demux.ConnId) ?*Connection {
    return table.find(dcid);
}

/// Decrypt a client Initial with the DCID-derived client keys, feed its CRYPTO frames into the
/// Initial-level reassembly stream, and parse the ClientHello once it is contiguous (it spans two
/// Initials, so the prefix is incomplete until the second CRYPTO fragment arrives).
fn openClientInitial(conn: *Connection, data: []const u8) Event {
    var buf: [2048]u8 = undefined;
    const opened = protection.openInitial(data, conn.initial_client, &buf) catch return .decrypt_failed;

    feedInitialFrames(conn, opened.payload);

    const handshake_bytes = conn.crypto_initial.readable();
    if (handshake_bytes.len >= 4 and handshake_bytes[0] == 0x01) {
        const declared = (@as(usize, handshake_bytes[1]) << 16) | (@as(usize, handshake_bytes[2]) << 8) | handshake_bytes[3];
        if (handshake_bytes.len >= 4 + declared) {
            const message = handshake_bytes[0 .. 4 + declared];
            return switch (tls_handshake.parseClientHello(message)) {
                .ok => .{ .client_hello = message.len },
                .alert => .parse_alert,
            };
        }
    }

    return .{ .initial_opened = opened.packet_number };
}

/// Parse the frames of a decrypted Initial payload, feeding CRYPTO frame data into the connection's
/// Initial-level reassembly stream. PADDING and other frames are skipped.
fn feedInitialFrames(conn: *Connection, payload: []const u8) void {
    var pos: usize = 0;
    while (pos < payload.len) {
        const parsed = frame.parseFrame(payload[pos..]) catch break;
        switch (parsed.frame) {
            .crypto => |c| conn.crypto_initial.insert(@intCast(c.offset), c.data),
            else => {},
        }

        if (parsed.len == 0) break;
        pos += parsed.len;
    }
}

/// Feed a Handshake-level packet's CRYPTO frames into the connection's Handshake reassembly stream.
///
/// Note:
/// - The walk is type-driven with an unknown-frame skip, the same shape the datagram and stream passes
///   use. A strict frame parser is no good here: a client's Handshake packet carries an ACK of the server
///   flight first, and stopping there would drop the Finished that follows it.
fn feedHandshakeFrames(conn: *Connection, payload: []const u8) void {
    var pos: usize = 0;
    while (pos < payload.len) {
        const type_vi = varint.read(payload[pos..]) catch break;

        switch (type_vi.value) {
            0x06 => { // CRYPTO: offset, length, body.
                const parsed = frame.parseFrame(payload[pos..]) catch break;
                conn.crypto_handshake.insert(@intCast(parsed.frame.crypto.offset), parsed.frame.crypto.data);
                pos += parsed.len;
            },
            else => {
                const skipped = request.skipFrame(payload[pos..]) orelse break;
                if (skipped == 0) break;
                pos += skipped;
            },
        }
    }
}

/// Whether the client's Finished has arrived and verifies (RFC 8446 4.4.4). Its verify_data covers the
/// transcript through the server Finished, which is the hash the application keys were derived from, so
/// no extra transcript bookkeeping is needed. A message split across Handshake packets is only checked
/// once the reassembly stream holds it whole.
///
/// Note:
/// - A Finished that does not verify leaves the handshake unconfirmed: the client gets no HANDSHAKE_DONE
///   and no session, and the connection idles out. That is deliberate. Confirming a handshake the client
///   never proved would let a peer reach the request path without the Finished, which is the one thing
///   the message exists to prevent.
fn clientFinishedState(conn: *Connection) enum { incomplete, verified, mismatch } {
    if (conn.client_finished_verified) return .verified;

    const bytes = conn.crypto_handshake.readable();
    if (bytes.len < 4 or bytes[0] != 0x14) return .incomplete;

    const declared = (@as(usize, bytes[1]) << 16) | (@as(usize, bytes[2]) << 8) | bytes[3];
    if (declared != 32 or bytes.len < 4 + declared) return .incomplete;

    const finished_key = certificate.finishedKey(conn.hs_keys.client_traffic);
    const expected = certificate.finishedVerifyData(finished_key, conn.transcript_through_finished);
    if (!std.mem.eql(u8, &expected, bytes[4 .. 4 + declared])) return .mismatch;

    conn.client_finished_verified = true;

    return .verified;
}

/// Effective worker count: the configured value, or one per available CPU when 0.
/// Uses the cgroup-allowed CPU mask (getAvailableCpuCount), so under a container or
/// taskset that pins the server to a core subset we never spawn more SO_REUSEPORT
/// workers than there are usable cores (which would oversubscribe and collapse).
pub fn effectiveWorkers(config: Http3ServerConfig) usize {
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
/// fails. Used to default to one worker per available CPU so several workers are
/// never pinned to the same core under cgroup-limited bench environments.
pub fn getAvailableCpuCount() usize {
    if (comptime @import("builtin").target.os.tag != .linux) return std.Thread.getCpuCount() catch 1;

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
pub fn setBusyPoll(fd: std.posix.socket_t, us: u32) void {
    if (comptime @import("builtin").target.os.tag == .windows) return;

    if (us == 0) return;

    const SO_BUSY_POLL: u32 = 46;
    std.posix.setsockopt(
        fd,
        std.posix.SOL.SOCKET,
        SO_BUSY_POLL,
        std.mem.asBytes(&@as(c_int, @intCast(us))),
    ) catch {};
}

/// Open one worker's request-stream reassembly pool from the server config. Every worker loop calls
/// this once and owns the result for its life, beside its connection table: a request with a body can
/// span datagrams, so the bytes have to outlive the datagram that carried the first of them.
///
/// Param:
/// config - Http3ServerConfig (max_pending_request_streams and max_request_stream_bytes size it)
///
/// Return:
/// - reassembly.Pool (the caller deinits it with config.allocator)
/// - error.OutOfMemory
pub fn openReassemblyPool(config: Http3ServerConfig) !reassembly.Pool {
    return reassembly.Pool.init(config.allocator, config.max_pending_request_streams, config.max_request_stream_bytes);
}

/// The single-worker HTTP/3 recv loop (.ASYNC): bind one UDP socket, own a CID table, and
/// run the blocking recvmmsg / demux / respond loop on the calling thread. `reuse` sets SO_REUSEPORT so
/// several per-core workers can bind the same port, and a per-core worker pins to its CPU.
/// The single-worker mode (reuse == false) stays unpinned. Shared-nothing, no lock.
pub fn workerLoop(comptime handler: core.HandlerFn, config: Http3ServerConfig, reuse: bool, worker_id: usize) void {
    if (reuse) pinToCpu(worker_id);

    const fd = datagram.open(config.ip, config.port, reuse) catch |err| {
        logSystem(config, .ERROR, "bind failed on {s}:{d} ({s})", .{ config.ip, config.port, @errorName(err) });

        return;
    };
    defer datagram.close(fd);

    // Announced below the bind, not above it: the caller's old line claimed a socket that may
    // never have been opened. Only the single-worker caller announces here, a REUSEPORT group
    // has its own line once the whole group reports.
    if (!reuse) logSystem(config, .INFO, "listening on {s}:{d} (single worker)", .{ config.ip, config.port });

    setBusyPoll(fd, config.busy_poll_us);
    datagram.setSocketBuffers(fd, config.socket_rcvbuf, config.socket_sndbuf);

    const table = config.allocator.create(ConnTable) catch return;
    defer config.allocator.destroy(table);
    table.* = .{};

    var pool = openReassemblyPool(config) catch return;
    defer pool.deinit(config.allocator);

    var wt_pool_handle = openWebtransportPool(config);
    defer if (wt_pool_handle) |*opened| opened.deinit(config.allocator);

    var rx = datagram.RecvBatch.init(config.allocator, config.recv_batch, config.max_recv_buf) catch return;
    defer rx.deinit();

    var tx = datagram.SendBatch.init(config.allocator, config.send_batch, sendBufBytes(config)) catch return;
    defer tx.deinit();

    tx.gso = config.gso_enabled and datagram.probeGso(fd);

    var last_sweep_us: u64 = recovery.nowUs();

    while (true) {
        const count = rx.recv(fd) catch continue;

        for (0..count) |i| {
            const dg = rx.get(i);
            serveDatagram(handler, table, &pool, if (wt_pool_handle) |*opened| opened else null, dg, &tx, fd, config, null);
        }

        // Flush once per recv batch: the SendBatch coalesces every reply in the batch into one flush.
        tx.flush(fd) catch {};

        // Time-driven maintenance (loss recovery + idle eviction), interval-gated. This blocking-recv
        // loop (.ASYNC) has no wait timeout, so the sweep advances while traffic keeps
        // arriving. A fully silent worker parks in recv until the next datagram, acceptable off the
        // benchmark path (the EPOLL / URING workers carry the timeout wake for a total lull).
        const now_us = recovery.nowUs();
        if (now_us -| last_sweep_us >= maintenance_interval_us) {
            sweepMaintenance(handler, table, if (wt_pool_handle) |*opened| opened else null, &tx, fd, config, now_us, null);
            tx.flush(fd) catch {};
            last_sweep_us = now_us;
        }
    }
}

/// The descriptor the portable loop hands to helpers that expect one. Never opened and never sent
/// on: the batch carries a PortableSink, so every flush those helpers reach goes through std.Io.
const NO_SOCKET: std.posix.socket_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;

/// The single-worker recv loop on the calling thread (.ASYNC).
pub fn runSingle(comptime handler: core.HandlerFn, config: Http3ServerConfig) !void {
    if (!datagram.is_linux) return runFallback(handler, config);

    workerLoop(handler, config, false, 0);
}

/// Portable single-socket recv loop for targets with no recvmmsg / sendmmsg.
///
/// What:
///   Same QUIC state machine as workerLoop, driven one datagram at a time over std.Io instead
///   of a Linux batch. Demux, handshake, response and maintenance all reuse the shared helpers,
///   so this differs from the Linux worker only in how bytes reach and leave the socket.
///
/// Note:
/// - One recv and one send per datagram, so throughput is below the batched Linux path. This is
///   the correctness path for other platforms, not the benchmark path.
/// - Receive blocks with no timeout, so the maintenance sweep advances on traffic. A fully idle
///   server parks in receive until the next datagram, matching the Linux single-worker loop.
pub fn runFallback(comptime handler: core.HandlerFn, config: Http3ServerConfig) !void {
    const io = config.io;

    const addr = try std.Io.net.IpAddress.resolve(io, config.ip, config.port);
    const socket = try addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    logSystem(config, .INFO, "listening on {s}:{d} (fallback)", .{ config.ip, config.port });

    const table = config.allocator.create(ConnTable) catch return error.OutOfMemory;
    defer config.allocator.destroy(table);
    table.* = .{};

    var pool = try openReassemblyPool(config);
    defer pool.deinit(config.allocator);

    var wt_pool_handle = openWebtransportPool(config);
    defer if (wt_pool_handle) |*opened| opened.deinit(config.allocator);

    const buf = try config.allocator.alloc(u8, config.max_recv_buf);
    defer config.allocator.free(buf);

    var tx = try datagram.SendBatch.init(config.allocator, config.send_batch, sendBufBytes(config));
    defer tx.deinit();

    // The send helpers below take a descriptor and flush on it whenever the batch fills mid-flight.
    // There is no such descriptor here, so the batch carries the bound socket and flush routes to
    // it. Without this the server flight is queued, dropped by a flush against a descriptor that
    // was never opened, and the peer keeps retransmitting into silence.
    tx.portable = .{ .socket = socket, .io = io };

    var last_sweep_us: u64 = recovery.nowUs();

    while (true) {
        const msg = socket.receive(io, buf) catch continue;

        const dg = datagram.Datagram{ .data = msg.data, .from = datagram.ipToSockaddr6(msg.from) };
        serveDatagram(handler, table, &pool, if (wt_pool_handle) |*opened| opened else null, dg, &tx, NO_SOCKET, config, null);

        tx.flushPortable(socket, io);

        const now_us = recovery.nowUs();
        if (now_us -| last_sweep_us >= maintenance_interval_us) {
            sweepMaintenance(handler, table, if (wt_pool_handle) |*opened| opened else null, &tx, NO_SOCKET, config, now_us, null);
            tx.flushPortable(socket, io);
            last_sweep_us = now_us;
        }
    }
}

/// Process one received datagram: demux + decrypt, then drive the matching handshake or response step.
/// Shared by the recvmmsg worker loop (workerLoop) and the EPOLL worker loop (workerLoopEpoll). When
/// `stats` is non-null its request counter is bumped on a decrypted 1-RTT request (the epoll loop passes
/// it, the recvmmsg loop passes null). `pool` is the worker's own request-stream reassembly pool,
/// owned beside its connection table because a request with a body can span datagrams.
pub fn serveDatagram(comptime handler: core.HandlerFn, table: *ConnTable, pool: *reassembly.Pool, wt_pool_ptr: ?*wt_pool.Pool, dg: datagram.Datagram, tx: *datagram.SendBatch, fd: std.posix.socket_t, config: Http3ServerConfig, stats: ?*WorkerStats) void {
    if (stats) |st| st.conns = table.count;

    var offset: usize = 0;
    while (offset < dg.data.len) {
        const bytes = dg.data[offset..];

        // One datagram carries one or more packets back to back (RFC 9000 12.2), and real clients
        // coalesce: a client acknowledging an Initial in the same datagram as its first 1-RTT data, or a
        // server flight followed by application data. A long header says where its own packet ends; a
        // short header has no length and therefore runs to the end of the datagram, so it is always the
        // last packet in one.
        var size = bytes.len;
        if (bytes[0] & 0x80 != 0) {
            const bounds = packet.longPacketBounds(bytes) orelse break;
            size = bounds.end;
        } else if (bytes.len < 1 + config.cid_len) {
            break;
        }

        servePacket(handler, table, pool, wt_pool_ptr, bytes, tx, fd, dg.from, config, stats);

        offset += size;

        // What follows must look like a packet (the Fixed Bit is set on every QUIC packet): a client that
        // pads its datagram past the last packet to reach the 1200-byte floor leaves bytes that do not,
        // and they are not a packet to parse.
        if (offset < dg.data.len and dg.data[offset] & 0x40 == 0) break;
    }
}

/// Process one QUIC packet inside a datagram: demux and decrypt it, then drive the matching handshake or
/// response step. `data` is the packet, not the whole datagram: a datagram may carry several.
fn servePacket(comptime handler: core.HandlerFn, table: *ConnTable, pool: *reassembly.Pool, wt_pool_ptr: ?*wt_pool.Pool, data: []const u8, tx: *datagram.SendBatch, fd: std.posix.socket_t, from: std.posix.sockaddr.in6, config: Http3ServerConfig, stats: ?*WorkerStats) void {
    switch (processDatagram(table, data, config.cid_len, config.max_datagram_size, config.initial_window_packets)) {
        .client_hello => |n| {
            logSystem(config, .INFO, "decrypted client Initial, parsed ClientHello ({d} bytes)", .{n});
            sendServerHelloFD(table, data, tx, fd, from, config);
        },
        .initial_opened => |pn| logSystem(config, .INFO, "decrypted client Initial, packet number {d} (ClientHello incomplete)", .{pn}),
        .parse_alert => logSystem(config, .INFO, "decrypted client Initial but ClientHello parse raised an alert", .{}),
        .decrypt_failed => logSystem(config, .INFO, "long-header Initial failed to decrypt under the Initial keys", .{}),
        .handshake_opened => logSystem(config, .INFO, "decrypted client Handshake packet (handshake keys correct, validated live)", .{}),
        .handshake_finished => {
            logSystem(config, .INFO, "client Finished verified: the handshake is complete, sending the confirmation", .{});
            sendHandshakeConfirmationFD(table, data, tx, fd, from, config);
        },
        .finished_mismatch => logSystem(config, .ERROR, "client Finished did not verify: the handshake stays unconfirmed", .{}),
        .handshake_close => |cc| logSystem(config, .WARN, "client closed during the handshake: code {d} frame {d} reason \"{s}\"", .{ cc.error_code, cc.frame_type, cc.reason }),
        .request_opened => {
            if (stats) |st| st.requests += 1;

            logSystem(config, .INFO, "decrypted client 1-RTT request (application keys correct, validated live)", .{});
            sendResponseFD(handler, table, pool, wt_pool_ptr, data, tx, fd, from, config.cid_len, config, stats);
        },
        else => {},
    }
}

/// Scale `num / den` to hundredths for a "{d}.{d:0>2}" fixed-point display. Zero when den is 0.
fn ratioParts(num: u64, den: u64) struct { whole: u64, frac: u64 } {
    if (den == 0) return .{ .whole = 0, .frac = 0 };

    const scaled = num * 100 / den;

    return .{ .whole = scaled / 100, .frac = scaled % 100 };
}

/// How often (in epoll wakes) a Debug build dumps the per-worker counters. Internal, not a knob: the
/// dump exists only to localize behavior during a local Debug probe and compiles out of Release.
const stats_dump_every_wakes: u64 = 512;

/// Per-worker recv / drain / send counters for the EPOLL loop. Debug builds dump them to stderr every
/// stats_dump_every_wakes wakes to localize a closed-loop run: datagrams-per-wake and requests-per-wake
/// show whether a worker drains real batches or ping-pongs one packet at a time (the closed-loop latency
/// signature), packets-per-flush shows the send coalescing factor. The dump compiles out of Release
/// entirely (comptime gate), so a benchmark pays nothing, prints nothing, and there is no field or env
/// knob to set. Worker-owned, so no atomics. packets / flushes undercount slightly when a sub-batch
/// auto-flushes mid-fill, enough for the ratio. Both the epoll worker (epoll.zig) and the io_uring
/// worker (uring.zig) own one and pass it to serveDatagram, so this module exposes it (pub).
pub const WorkerStats = struct {
    worker_id: usize,
    wakes: u64 = 0,
    datagrams: u64 = 0,
    requests: u64 = 0,
    packets: u64 = 0,
    flushes: u64 = 0,
    /// Microseconds this worker spent parked in submit_and_wait (blocked for a completion), summed over
    /// the run. wall - block_us approximates the worker's on-CPU time, so block_us / wall is how idle a
    /// worker was: a high value with few datagrams means the worker is waiting for work, not saturated.
    block_us: u64 = 0,
    /// recovery.nowUs() at loop entry, set by registerWorkerStats. The diagnostic dump computes wall
    /// time as now - start_us. Zero means the worker never registered (dump skips it).
    start_us: u64 = 0,
    /// recovery.nowUs() captured just before the current submit_and_wait / epoll_wait, or 0 when the
    /// worker is not currently parked. The dump adds the in-progress wait (now - wait_enter_us) to
    /// block_us so a snapshot taken while every worker is idle-blocked (e.g. SIGTERM after the load
    /// stops) does not misreport that still-uncounted parked time as on-CPU time.
    wait_enter_us: u64 = 0,
    /// Times pumpStream had more of a large body to send but the client's flow control (per-stream
    /// MAX_STREAM_DATA or the connection-wide MAX_DATA) left no room, so the response stalled until the
    /// client raised a limit. A high count relative to requests is the fingerprint of flow-control
    /// pacing: the server sits idle waiting for credit instead of being CPU or send bound.
    fc_blocked: u64 = 0,
    /// Times pumpStream had more body to send but the connection's congestion window (bytes already in
    /// flight) left no room, so the send waits for an ACK to free the window. This is the healthy
    /// self-clocking back-pressure (the counterpart to fc_blocked), the fingerprint that the RFC 9002
    /// congestion control is pacing the body rather than the client's flow control gating it.
    cwnd_blocked: u64 = 0,
    /// MAX_DATA frames (0x10, connection-wide send credit) received from clients.
    max_data_recv: u64 = 0,
    /// MAX_STREAM_DATA frames (0x11, per-stream send credit) received from clients.
    max_stream_data_recv: u64 = 0,
    /// This worker's ConnTable.count as of its last processed datagram: how many distinct connections
    /// this worker owns right now. Distinguishes an uneven-SO_REUSEPORT-distribution problem (a busy
    /// worker legitimately owns most connections) from a stall problem (an idle worker owns connections
    /// that stopped producing traffic): compare `conns` against `req` across workers in the same dump.
    conns: u64 = 0,

    /// A worker's derived timing at a given instant, the numbers the diagnostic dump reports.
    pub const Snapshot = struct {
        wall_us: u64,
        active_us: u64,
        active_pct: u64,
    };

    /// Derive wall / on-CPU time from the raw counters at `now_us` (a recovery.nowUs() reading). Pure,
    /// so the dump's arithmetic is testable without signals or file descriptors. Saturating subtraction
    /// throughout: a block_us that briefly exceeds wall (measured across a nowUs pair) reads as 0 active
    /// rather than underflowing.
    ///
    /// Param:
    /// now_us - u64 (the current monotonic time, same base as start_us / block_us)
    ///
    /// Return:
    /// - Snapshot (wall_us, active_us, and active_pct = active as a percent of wall, 0 when wall is 0)
    pub fn snapshot(self: *const WorkerStats, now_us: u64) Snapshot {
        const wall_us = now_us -| self.start_us;

        // Count an in-progress park: block_us is only committed after a wait returns, so a worker
        // currently parked has uncounted blocked time that would otherwise read as on-CPU.
        var block = self.block_us;
        if (self.wait_enter_us != 0) block +|= now_us -| self.wait_enter_us;

        const active_us = wall_us -| block;
        const active_pct = if (wall_us > 0) active_us * 100 / wall_us else 0;

        return .{ .wall_us = wall_us, .active_us = active_us, .active_pct = active_pct };
    }

    /// Dump the counters every stats_dump_every_wakes wakes, Debug builds only (a no-op in Release).
    pub fn maybeDump(self: *const WorkerStats) void {
        if (comptime !diag_enabled) return;
        if (self.wakes == 0 or self.wakes % stats_dump_every_wakes != 0) return;

        const dgw = ratioParts(self.datagrams, self.wakes);
        const reqw = ratioParts(self.requests, self.wakes);
        const pktf = ratioParts(self.packets, self.flushes);

        var buf: [320]u8 = undefined;
        const line = std.fmt.bufPrint(&buf, "zix h3 w{d}: wakes={d} dg={d} req={d} pkt={d} flush={d} | dg/wake={d}.{d:0>2} req/wake={d}.{d:0>2} pkt/flush={d}.{d:0>2}\n", .{
            self.worker_id, self.wakes, self.datagrams, self.requests, self.packets, self.flushes,
            dgw.whole,      dgw.frac,   reqw.whole,     reqw.frac,     pktf.whole,   pktf.frac,
        }) catch return;

        _ = linux.write(2, line.ptr, line.len);
    }
};

// --------------------------------------------------------------- //

/// The most workers the diagnostic registry tracks. One per core on any realistic host, so this is a
/// generous fixed cap that keeps the registry allocation-free.
const max_diag_workers = 512;

/// The per-worker diagnostic (counters, SIGUSR1 / SIGTERM / SIGINT dump) is compiled in only outside
/// ReleaseSafe / ReleaseFast, so a production build installs no signal handler and pays no dump cost.
pub const diag_enabled = if (ZIG_SEMVER.MINOR == 16)
    builtin.mode != .ReleaseSafe and builtin.mode != .ReleaseFast
else
    builtin.mode != .safe and builtin.mode != .fast;

/// Registry of live worker stats, so a signal handler can dump every worker's counters without the
/// workers cooperating (they may all be parked in submit_and_wait when the signal arrives). Each worker
/// publishes a pointer to its own stack-resident WorkerStats once, at loop entry. The pointer stays
/// valid for the process lifetime because a worker thread lives that long.
var g_diag_stats: [max_diag_workers]?*WorkerStats = @splat(null);
var g_diag_count: std.atomic.Value(usize) = .init(0);
var g_diag_installed: std.atomic.Value(bool) = .init(false);

/// Publish this worker's stats to the diagnostic registry and stamp its start time. Call once, at the
/// top of a worker loop, before the loop begins. Over the fixed cap the worker is simply not tracked
/// (the dump still covers every worker up to the cap).
///
/// Param:
/// stats - *WorkerStats (the worker's own counters, must outlive the process, i.e. loop-local)
///
/// Return:
/// - void
pub fn registerWorkerStats(stats: *WorkerStats) void {
    if (comptime !diag_enabled) return;

    stats.start_us = recovery.nowUs();

    const idx = g_diag_count.fetchAdd(1, .acq_rel);
    if (idx < max_diag_workers) g_diag_stats[idx] = stats;
}

/// Install the diagnostic-dump signal handlers once per process. SIGUSR1 dumps every worker's counters
/// and keeps running (sample mid-benchmark), SIGTERM / SIGINT dump then exit (the natural stop dumps
/// too). Idempotent: a second call is a no-op. Called from the run entry point before workers spawn.
///
/// Note:
/// - The dump reads worker counters without locking. u64 loads on the target are atomic, so a value is
///   never torn, only possibly one wake stale, which does not matter for a coarse per-worker snapshot.
pub fn installDiagnosticDump() void {
    if (comptime !diag_enabled) return;

    if (g_diag_installed.swap(true, .acq_rel)) return;

    const act = linux.Sigaction{
        .handler = .{ .handler = diagSignalHandler },
        .mask = linux.sigemptyset(),
        .flags = 0,
    };
    _ = linux.sigaction(linux.SIG.USR1, &act, null);
    _ = linux.sigaction(linux.SIG.TERM, &act, null);
    _ = linux.sigaction(linux.SIG.INT, &act, null);
}

/// The signal handler: dump all workers, then exit unless the signal was SIGUSR1 (dump and continue).
/// Uses only stack-buffer formatting and raw writes, so it is safe to run in signal context.
fn diagSignalHandler(sig: linux.SIG) callconv(.c) void {
    dumpAllWorkerStats();

    if (sig != linux.SIG.USR1) linux.exit_group(0);
}

/// Write every registered worker's counters to stderr as one line each, then a totals line. The header
/// line names the fields. active_us = wall - block_us is the on-CPU estimate, active_pct = active_us
/// as a percent of wall, which is the per-worker CPU utilization the drop across bench runs is about.
fn dumpAllWorkerStats() void {
    const count = @min(g_diag_count.load(.acquire), max_diag_workers);
    const now = recovery.nowUs();

    var buf: [384]u8 = undefined;
    const header = "zix h3 diag: per-worker (active_pct=on-CPU/wall, dg/wake=recv batch, fc=flow-control stalls, cwnd=congestion-window waits, md/msd=MAX_DATA/MAX_STREAM_DATA recv, conns=owned connections)\n";
    _ = linux.write(2, header.ptr, header.len);

    var total_active_us: u64 = 0;
    var total_datagrams: u64 = 0;
    var total_requests: u64 = 0;
    var total_fc_blocked: u64 = 0;
    var active_workers: usize = 0;

    for (g_diag_stats[0..count]) |maybe_stats| {
        const stats = maybe_stats orelse continue;
        if (stats.start_us == 0) continue;

        const snap = stats.snapshot(now);
        const dgw = ratioParts(stats.datagrams, stats.wakes);

        total_active_us += snap.active_us;
        total_datagrams += stats.datagrams;
        total_requests += stats.requests;
        total_fc_blocked += stats.fc_blocked;
        if (stats.datagrams > 0) active_workers += 1;

        const line = std.fmt.bufPrint(&buf, "  w{d}: active={d}ms({d}%) wall={d}ms wakes={d} dg={d} req={d} pkt={d} dg/wake={d}.{d:0>2} fc={d} cwnd={d} md={d} msd={d} conns={d}\n", .{
            stats.worker_id,  snap.active_us / 1000, snap.active_pct,     snap.wall_us / 1000,        stats.wakes,
            stats.datagrams,  stats.requests,        stats.packets,       dgw.whole,                  dgw.frac,
            stats.fc_blocked, stats.cwnd_blocked,    stats.max_data_recv, stats.max_stream_data_recv, stats.conns,
        }) catch continue;

        _ = linux.write(2, line.ptr, line.len);
    }

    const totals = std.fmt.bufPrint(&buf, "  TOTAL: active={d}ms across {d} workers with traffic, dg={d} req={d} fc_stalls={d}\n", .{
        total_active_us / 1000, active_workers, total_datagrams, total_requests, total_fc_blocked,
    }) catch return;

    _ = linux.write(2, totals.ptr, totals.len);
}

// --------------------------------------------------------------- //

/// Build and send the server's ServerHello Initial in reply to a decrypted ClientHello (handshake
/// step 2). Idempotent per connection: sent once, skipped on retransmits.
fn sendServerHelloFD(table: *ConnTable, data: []const u8, tx: *datagram.SendBatch, fd: std.posix.socket_t, peer: std.posix.sockaddr.in6, config: Http3ServerConfig) void {
    const hdr = packet.parseLongHeader(data) catch return;
    if (hdr.packet_type != 0) return;

    const dcid = demux.ConnId.fromSlice(hdr.dcid);
    const conn = table.find(&dcid) orelse return;

    // Stamp liveness even on a retransmitted Initial: the peer is alive, so the maintenance sweep must
    // not treat a still-handshaking connection as idle.
    conn.peer_addr = peer;
    conn.last_activity_us = recovery.nowUs();

    if (conn.server_hello_sent) return;

    const handshake_bytes = conn.crypto_initial.readable();
    if (handshake_bytes.len < 4 or handshake_bytes[0] != 0x01) return;

    const declared = (@as(usize, handshake_bytes[1]) << 16) | (@as(usize, handshake_bytes[2]) << 8) | handshake_bytes[3];
    if (handshake_bytes.len < 4 + declared) return;

    const client_hello = handshake_bytes[0 .. 4 + declared];
    const hello = switch (tls_handshake.parseClientHello(client_hello)) {
        .ok => |parsed| parsed,
        .alert => return,
    };

    // Record the client's flow control limits so the response path can serve bodies larger than one
    // packet without overrunning them (RFC 9000 4.1). Absent (a minimal client) leaves them at 0.
    if (transport_params.fromClientHello(client_hello)) |tp| {
        conn.client_max_data = tp.initial_max_data;
        conn.client_max_stream_data = tp.initial_max_stream_data_bidi_local;
        conn.ack_delay_exponent = tp.ack_delay_exponent;
        conn.client_max_udp_payload = tp.max_udp_payload_size;

        // The streams the server opens have their own credits (RFC 9000 18.2 params 0x06 / 0x07), and the
        // two extension parameters are what allow a DATAGRAM frame and a reliable stream reset at all
        // (RFC 9221 3, draft-ietf-quic-reliable-stream-reset-09 3).
        conn.client_max_stream_data_bidi_remote = tp.initial_max_stream_data_bidi_remote;
        conn.client_max_stream_data_uni = tp.initial_max_stream_data_uni;
        conn.wt.peer_datagram_frame_size = tp.max_datagram_frame_size;
        conn.wt.peer_reset_stream_at = tp.reset_stream_at;
    }

    // Choose our Source Connection ID (the client will use it as its Destination CID) and the fresh
    // per-connection randoms.
    const cid_len: usize = @min(config.cid_len, 20);
    var scid_bytes: [20]u8 = undefined;
    secureRandom(scid_bytes[0..cid_len]);
    conn.our_scid = demux.ConnId.fromSlice(scid_bytes[0..cid_len]);

    // Index the connection under the SCID we issued too: the client uses it as its Destination CID for
    // every 1-RTT packet, so this makes those resolve in O(1) instead of a per-packet linear scan.
    table.addAlias(conn.our_scid, conn);

    var server_random: [32]u8 = undefined;
    secureRandom(&server_random);
    var ephemeral: [32]u8 = undefined;
    secureRandom(&ephemeral);

    var out: [1500]u8 = undefined;
    const built = serverhello.buildServerHelloInitial(&out, &hello, client_hello, conn.initial_server, hdr.scid, conn.our_scid.slice(), server_random, ephemeral) orelse {
        logSystem(config, .WARN, "ServerHello not built (no X25519 share or negotiation declined)", .{});
        return;
    };

    conn.handshake_shared = built.shared;
    conn.hs_keys = built.keys;
    conn.handshake_transcript = built.transcript;
    conn.handshake_ready = true;
    conn.server_hello_sent = true;

    _ = tx.queue(peer, built.packet);
    tx.flush(fd) catch {};
    logSystem(config, .INFO, "sent ServerHello Initial ({d} bytes), Handshake keys derived", .{built.packet.len});

    // Handshake flight: EncryptedExtensions (ALPN h3 + transport params) + Certificate +
    // CertificateVerify + Finished, sealed into a Handshake packet with the server Handshake keys.
    const tls_ctx = config.tls orelse return;
    const opts = tls_ctx.handshakeOptions(ephemeral, server_random, @splat(0));

    var flight_out: [flight.max_flight_bytes]u8 = undefined;
    const built_flight = flight.buildHandshakeFlight(
        &flight_out,
        conn.hs_keys.server,
        conn.hs_keys.server_traffic,
        hdr.scid,
        conn.our_scid.slice(),
        &conn.handshake_transcript,
        opts.certificate_chain,
        opts.signing_key,
        conn.dcid.slice(),
        conn.our_scid.slice(),
        config.max_idle_ms,
        config.max_streams,
        webtransportTransportExtensions(config),
    ) orelse {
        logSystem(config, .WARN, "Handshake flight not built", .{});
        return;
    };

    var flight_bytes: usize = 0;
    for (built_flight.packets[0..built_flight.len]) |sealed| {
        _ = tx.queue(peer, sealed);
        flight_bytes += sealed.len;
    }
    tx.flush(fd) catch {};
    logSystem(config, .INFO, "sent Handshake flight ({d} bytes in {d} packets): EE + Cert + CertVerify + Finished", .{ flight_bytes, built_flight.len });

    // 1-RTT application keys, derived from the transcript through the server Finished (which the
    // flight just appended). The client addresses us by our_scid from here on.
    conn.app_keys = keyschedule.applicationKeys(conn.hs_keys.handshake_secret, conn.handshake_transcript.current());
    // The flight just appended the server Finished, so the transcript hash is now the exact input the
    // client's Finished covers: keep it for that verification.
    conn.transcript_through_finished = conn.handshake_transcript.current();
    conn.peer_scid = demux.ConnId.fromSlice(hdr.scid);
    conn.app_ready = true;
}

/// Leave as soon as the handshake is complete: the server's one-time 1-RTT prologue, a HANDSHAKE_DONE
/// frame followed by the control stream's SETTINGS (RFC 9000 17.2.1, RFC 9114 6.2.1).
///
/// Note:
/// - A client is entitled to wait for the handshake to be confirmed before it sends 1-RTT data, and
///   Chromium does: it holds its SETTINGS, its CONNECT and every request until the confirmation lands. A
///   server that only writes its prologue when a 1-RTT packet arrives therefore deadlocks against it, so
///   the confirmation is sent here, on the client's Finished, rather than waiting for traffic.
/// - The client's Handshake packets are not ACKed on this path; the handshake is complete either way, so
///   the client discards its Handshake state with the HANDSHAKE_DONE and the confirmation is idempotent
///   if a retransmitted Finished arrives first.
fn sendHandshakeConfirmationFD(table: *ConnTable, data: []const u8, tx: *datagram.SendBatch, fd: std.posix.socket_t, peer: std.posix.sockaddr.in6, config: Http3ServerConfig) void {
    const hdr = packet.parseLongHeader(data) catch return;
    if (hdr.packet_type != 2) return;

    const dcid = demux.ConnId.fromSlice(hdr.dcid);
    const conn = table.find(&dcid) orelse return;
    if (!conn.app_ready or conn.first_response_sent or !conn.client_finished_verified) return;

    conn.peer_addr = peer;
    conn.last_activity_us = recovery.nowUs();

    var pbuf: [COALESCE_PAYLOAD_MAX]u8 = undefined;
    const plen = buildConnectionPrologue(&pbuf, config, conn.takeServerStreamId(.uni));
    conn.first_response_sent = true;

    sealAndQueue(conn, tx, fd, peer, pbuf[0..plen], null);
    tx.flush(fd) catch {};
}

/// Expand a request :path into a stable slice: Huffman-decoded into the connection scratch when the
/// client encoded it (the common case, curl / h2load encode :path), otherwise the literal slice into
/// the captured payload. Returns an empty path on a malformed Huffman code.
fn decodePath(conn: *Connection, req: request.DecodedRequest) []const u8 {
    if (req.path_huffman) {
        const len = huffman.decode(&conn.path_scratch, req.path) orelse return "";

        return conn.path_scratch[0..len];
    }

    return req.path;
}

/// Expand a request `accept-encoding` into a plain slice: Huffman-decoded into `scratch` when a custom
/// literal value arrived Huffman-coded, otherwise the value as decoded (the common indexed form,
/// `gzip, deflate, br`, is already plain). The slice is only read during the handler call, so a
/// caller-owned stack scratch is enough. Returns empty on a malformed Huffman code, which the handler
/// then treats as no accept-encoding (identity).
fn decodeAcceptEncoding(scratch: []u8, req: request.DecodedRequest) []const u8 {
    if (req.accept_encoding_huffman) {
        const len = huffman.decode(scratch, req.accept_encoding) orelse return "";

        return scratch[0..len];
    }

    return req.accept_encoding;
}

/// What one request-stream frame means for the serve loop.
const Ready = union(enum) {
    /// Run the handler on this request.
    serve: request.DecodedRequest,
    /// Nothing to answer for this frame: the rest of the request is still on its way, or the frame
    /// carries no request of its own. Carries the slot holding the request when there is one, so the
    /// loop can extend the client's stream credit before the client blocks waiting for it.
    hold: ?*reassembly.PendingStream,
    /// The worker had no slot left to assemble this request in. The loop answers 503 rather than
    /// running a handler against a body the engine knows is missing. Carries the head that did
    /// arrive, so the refusal is still logged with the method and path it refused.
    overloaded: request.DecodedRequest,
};

/// Decide what one request-stream frame means: a request to serve now, bytes to hold, a held request
/// this frame completes, or a request the worker has no room to assemble.
///
/// Note:
/// - A request that arrived whole in one packet is served straight from the decrypted payload, with
///   no copy and no slot. That is every GET, and every POST small enough that the client wrote it in
///   one go, so the common path pays one branch.
/// - Anything else is held. A client with a body commonly sends its HEADERS frame and its DATA frame
///   in separate packets, and answering the first one would run the handler with an empty body and
///   leave the real body arriving after the response.
/// - A refused frame that carries the start of a request becomes a 503. A refused frame that carries
///   only body bytes is dropped instead: the engine has no request to answer on that stream, and the
///   frame is as likely to be a retransmit of one already answered as the tail of a refused one.
///
/// Param:
/// pool - *reassembly.Pool (the worker's own, sized from the server config)
/// now_us - u64 (monotonic microseconds, for reclaiming a slot nobody is finishing)
/// cid - *const demux.ConnId (the connection the stream belongs to)
/// piece - request.StreamPiece (one client request-stream frame out of this payload)
/// held - *?*reassembly.PendingStream (set to the slot the caller must release once it has served)
///
/// Return:
/// - Ready (serve with the decoded request, hold, or overloaded)
fn takeReadyRequest(pool: *reassembly.Pool, now_us: u64, cid: *const demux.ConnId, piece: request.StreamPiece, held: *?*reassembly.PendingStream) Ready {
    if (piece.request) |whole| {
        if (whole.body_complete) return .{ .serve = whole };
    }

    switch (pool.feed(now_us, cid, piece.stream_id, piece.offset, piece.data, piece.fin)) {
        .ready => |slot| {
            // The joining decode, not the read-only one: the slot is the worker's own buffer, so a
            // body the client wrote as several DATA frames is joined in place into one slice rather
            // than delivered as its first frame with the rest reported missing.
            var decoded = request.decodeAssembledRequest(slot.assembledMutable(), true) orelse {
                pool.release(slot);

                return .{ .hold = null };
            };

            // A body cut by the configured stream size is served, never as a whole one: the count
            // says more arrived than the handler is holding.
            if (slot.dropped != 0) {
                decoded.body_received += slot.dropped;
                decoded.body_complete = false;
            }

            held.* = slot;

            return .{ .serve = decoded };
        },
        .waiting => |slot| {
            // A CONNECT request is complete once its header block is: RFC 9114 4.4 keeps the stream open
            // after the headers, which is exactly what a WebTransport session needs (its CONNECT stream
            // carries capsules until the session ends). Waiting for FIN would hold every session request
            // forever, and the ones the packet-level pass could not decode on arrival - because the
            // client's QPACK encoder had state the decode needed - would never be dispatched at all.
            // The decode returns null until the header block is whole, so a genuinely partial request
            // still waits.
            if (request.decodeAssembledRequest(slot.assembledMutable(), true)) |decoded| {
                if (std.mem.eql(u8, decoded.method, "CONNECT")) {
                    held.* = slot;

                    return .{ .serve = decoded };
                }
            }

            return .{ .hold = slot };
        },
        .refused => return if (piece.request) |head| .{ .overloaded = head } else .{ .hold = null },
    }
}

/// Build the handler-facing Request from one decoded request stream.
///
/// Note:
/// - The body needs no expansion step: DATA frames are never Huffman-coded, so the slice the decoder
///   kept is handed straight through. It borrows the connection's decrypted payload, which outlives
///   the handler call, the same lifetime the method and a non-Huffman path already have.
/// - The two body facts travel with it. Without them a handler cannot tell a body the client never
///   sent from one this engine only received part of.
///
/// Param:
/// conn - *Connection (owns the Huffman scratch a path is expanded into)
/// ae_scratch - []u8 (caller-owned scratch for a Huffman-coded accept-encoding)
/// decoded - request.DecodedRequest (one request stream out of the payload)
///
/// Return:
/// - core.Request (every slice borrowing the connection, valid for the handler call)
fn buildRequest(conn: *Connection, ae_scratch: []u8, decoded: request.DecodedRequest) core.Request {
    return .{
        .method = decoded.method,
        .path = decodePath(conn, decoded),
        .body = decoded.body,
        .body_received = decoded.body_received,
        .body_complete = decoded.body_complete,
        .accept_encoding = decodeAcceptEncoding(ae_scratch, decoded),
    };
}

/// Copy `dst.len` bytes of the logical response stream (the HTTP/3 prefix followed by the body) into
/// `dst`, starting at stream offset `off`. The prefix and body stay separate, so a large body is
/// never concatenated into one buffer.
fn copyStreamSlice(prefix: []const u8, body: []const u8, off: usize, dst: []u8) void {
    var written: usize = 0;
    var pos = off;

    if (pos < prefix.len) {
        const n = @min(dst.len, prefix.len - pos);
        @memcpy(dst[0..n], prefix[pos..][0..n]);
        written += n;
        pos += n;
    }

    if (written < dst.len) {
        const body_pos = pos - prefix.len;
        @memcpy(dst[written..], body[body_pos..][0 .. dst.len - written]);
    }
}

/// The total HTTP/3 stream length for a response: the prefix (HEADERS + DATA header) plus the body. The
/// content coding is part of the prefix (one field line), so it must match the coding the pump emits or
/// the flow-control accounting would drift by a byte.
fn streamContentLen(status: u16, content_encoding: response.ContentEncoding, body: []const u8) usize {
    var buf: [32]u8 = undefined;
    const prefix_len = response.buildStreamPrefix(&buf, status, content_encoding, body.len) orelse 0;

    return prefix_len + body.len;
}

/// Take the pending ACK (consume it so only the first packet of a call carries it).
fn ackTake(ack_pending: *?u64) ?u64 {
    const value = ack_pending.*;
    ack_pending.* = null;

    return value;
}

/// Take the pending MAX_STREAMS credit (consume it so only one packet of a call carries it).
fn maxStreamsTake(max_streams_pending: *?u64) ?u64 {
    const value = max_streams_pending.*;
    max_streams_pending.* = null;

    return value;
}

/// Take the pending MAX_DATA credit (consume it so only one packet of a call carries it).
fn maxDataTake(max_data_pending: *?u64) ?u64 {
    const value = max_data_pending.*;
    max_data_pending.* = null;

    return value;
}

/// Apply the acknowledgment content of a decrypted 1-RTT payload: an ACK frame (0x02 / 0x03) drives RTT
/// sampling, range retirement, loss detection and retransmission, congestion control, and send-stream
/// retirement (RFC 9002, Connection.onAckFrame). Every other frame is walked past. Run BEFORE request
/// registration in sendResponseFD: a stream is now freed on ack (not on send), so an ACK that finishes an
/// earlier stream must free its slot here, in time for a request riding the same datagram to claim it,
/// or the pool (sized to the client's stream concurrency) could refuse it with a spurious 500.
fn applyAcks(conn: *Connection, payload: []const u8) void {
    var pos: usize = 0;
    while (pos < payload.len) {
        const type_vi = varint.read(payload[pos..]) catch break;
        const frame_type = type_vi.value;

        if (frame_type == 0x02 or frame_type == 0x03) {
            const parsed = flow.parseAck(payload[pos..], conn.ack_delay_exponent) catch break;
            conn.onAckFrame(parsed, recovery.nowUs());
            pos += parsed.consumed;
            continue;
        }

        if (request.isStreamFrameType(frame_type)) {
            const stream = request.parseStreamFrame(payload[pos..]) orelse break;
            pos += stream.consumed;
            continue;
        }

        if (frame_type == 0x1c or frame_type == 0x1d) {
            // The peer is closing (RFC 9000 10.2): move to draining so the maintenance sweep evicts the
            // connection promptly and frees its slot, instead of holding it to the idle timeout. No
            // frames after CONNECTION_CLOSE are processed.
            conn.close_state = close.closeTransition(conn.close_state, .recv_close) orelse conn.close_state;
            break;
        }

        const skipped = request.skipFrame(payload[pos..]) orelse break;
        pos += skipped;
    }
}

/// Apply the flow-control credit of a decrypted 1-RTT payload: MAX_DATA (0x10) raises the
/// connection-wide send limit, MAX_STREAM_DATA (0x11) raises a tracked stream's limit (a limit only ever
/// increases, RFC 9000 4.1, so a smaller value is ignored). An ACK frame is parsed only to walk past it
/// (applyAcks already handled it). Run AFTER request registration so a MAX_STREAM_DATA riding the same
/// packet as the request it unblocks lands on the just-registered stream.
fn applyStreamCredit(conn: *Connection, payload: []const u8, stats: ?*WorkerStats) void {
    var pos: usize = 0;
    while (pos < payload.len) {
        const type_vi = varint.read(payload[pos..]) catch break;
        const frame_type = type_vi.value;

        if (frame_type == 0x02 or frame_type == 0x03) {
            const parsed = flow.parseAck(payload[pos..], conn.ack_delay_exponent) catch break;
            pos += parsed.consumed;
            continue;
        }

        if (request.isStreamFrameType(frame_type)) {
            const stream = request.parseStreamFrame(payload[pos..]) orelse break;
            pos += stream.consumed;
            continue;
        }

        if (frame_type == 0x10) {
            var p = pos + type_vi.len;
            const max = varint.read(payload[p..]) catch break;
            p += max.len;
            if (max.value > conn.client_max_data) conn.client_max_data = max.value;
            if (stats) |st| st.max_data_recv += 1;
            pos = p;
            continue;
        }

        if (frame_type == 0x11) {
            var p = pos + type_vi.len;
            const sid = varint.read(payload[p..]) catch break;
            p += sid.len;
            const max = varint.read(payload[p..]) catch break;
            p += max.len;
            if (conn.findSendStream(sid.value)) |stream| {
                if (max.value > stream.stream_limit) stream.stream_limit = max.value;
            } else if (conn.wt.findStream(sid.value)) |stream| {
                // A WebTransport data stream has its own limit, seeded from the stream-credit transport
                // parameter of its kind; without this a stream stalls at the handshake allowance.
                stream.onStreamLimit(max.value);
            }
            if (stats) |st| st.max_stream_data_recv += 1;
            pos = p;
            continue;
        }

        const skipped = request.skipFrame(payload[pos..]) orelse break;
        pos += skipped;
    }
}

/// The stream offset the pump may reach this round: the flow-control ceiling (`fc_limit`), capped so the
/// connection never holds more than a congestion window of bytes in flight (RFC 9002 7) and never more
/// than `window_cap` (the in-flight ceiling in bytes, from config.max_inflight_packets clamped to the
/// sent-range ring capacity, so a range is never overwritten while still awaiting acknowledgment). Pure,
/// so the gate that stops the whole-body burst is testable without a socket.
///
/// Param:
/// fc_limit - usize (the flow-control reachable offset: stream / connection MAX_DATA, capped at content)
/// sent - usize (the stream offset already sent, the floor this round starts from)
/// congestion_window - u64 (conn.cc.congestion_window, the NewReno window in bytes)
/// bytes_in_flight - u64 (conn.bytes_in_flight, stream bytes sent but not yet acknowledged)
/// window_cap - u64 (the in-flight ceiling in bytes: in-flight packets allowed times max_datagram_size)
///
/// Return:
/// - usize (the offset the pump may send up to, never below `sent`)
fn pumpLimit(fc_limit: usize, sent: usize, congestion_window: u64, bytes_in_flight: u64, window_cap: u64) usize {
    const window = @min(congestion_window, window_cap);
    const cwnd_room = window -| bytes_in_flight;
    const ceiling = sent + @as(usize, @intCast(@min(cwnd_room, window_cap)));

    return @min(fc_limit, ceiling);
}

/// Send as much of a large response stream as flow control and the congestion window now permit,
/// fragmenting it into STREAM frames across 1-RTT packets (RFC 9000 19.8) and advancing the stream's
/// sent offset. The connection's first response packet carries HANDSHAKE_DONE + the server control
/// SETTINGS, and the first packet sent this call carries the pending ACK. A completed stream frees its
/// slot. Returns true when at least one packet was sent.
fn pumpStream(conn: *Connection, stream: *SendStream, tx: *datagram.SendBatch, fd: std.posix.socket_t, peer: std.posix.sockaddr.in6, ack_pending: *?u64, max_streams_pending: *?u64, max_data_pending: *?u64, config: Http3ServerConfig, stats: ?*WorkerStats) bool {
    var prefix_buf: [32]u8 = undefined;
    const prefix_len = response.buildStreamPrefix(&prefix_buf, stream.status, stream.content_encoding, stream.body.len) orelse {
        stream.active = false;
        return false;
    };
    const prefix = prefix_buf[0..prefix_len];

    // The reachable offset: the stream's own flow limit, capped by the connection-wide remaining
    // credit. Credit is charged against high_water (the highest offset ever reached), not `sent`
    // directly: a loss retransmission rewinds `sent` backward to resend an already-charged range, and
    // that resend must not charge the connection-wide budget a second time (RFC 9000 4.1 counts
    // distinct stream offset, not bytes handed to sendmsg).
    const conn_remaining = if (conn.client_max_data > conn.conn_data_sent) conn.client_max_data - conn.conn_data_sent else 0;
    const fc_limit = @min(stream.content_len, @min(stream.stream_limit, stream.high_water + conn_remaining));

    // Never hold more than a congestion window of stream bytes in flight, so a multi-packet body
    // self-clocks to the client's ACKs instead of dumping the whole body in one burst (which overruns
    // the client's socket buffer and strands the drops with no timely retransmit). The window ceiling is
    // config.max_inflight_packets, clamped to the sent-range ring capacity so an in-flight range is never
    // overwritten. bytes_in_flight already counts this stream's earlier sends plus any sibling stream
    // pumped before it this round, so the window is shared connection-wide, not per-stream.
    const window_cap = @min(config.max_inflight_packets, max_sent_ranges) * config.max_datagram_size;
    const limit = pumpLimit(fc_limit, stream.sent, conn.cc.congestion_window, conn.bytes_in_flight, window_cap);

    if (limit <= stream.sent) {
        // More body remains but no room this round. Separate the two back-pressure sources so a
        // diagnostic dump tells throttling by the client (flow control credit) from throttling by our
        // own pacing (congestion window). A finished stream (sent reached content_len) counts as
        // neither.
        if (stream.sent < stream.content_len) {
            if (stats) |st| {
                if (fc_limit <= stream.sent) st.fc_blocked += 1 else st.cwnd_blocked += 1;
            }
        }

        return false;
    }

    // The wire datagram size for this connection: the smaller of the configured size, what the client
    // will accept (RFC 9000 18.2), and the compile-time ceiling. A larger datagram carries more stream
    // bytes per packet, so a big response goes out as fewer packets, cutting the per-packet header /
    // AEAD / ACK work that dominates a big-response run. The chunk is that size minus the room a sealed
    // packet needs for its frames and tag, optionally capped by an explicit config.max_stream_chunk.
    const dgram: usize = @intCast(conn.sendDatagramSize(config.max_datagram_size, max_send_datagram_size));
    var chunk_budget = dgram - per_packet_frame_reserve;
    if (config.max_stream_chunk != 0) chunk_budget = @min(chunk_budget, config.max_stream_chunk);

    var payload: [max_send_datagram_size]u8 = undefined;
    var sent_any = false;
    while (stream.sent < limit) {
        const chunk = @min(chunk_budget, limit - stream.sent);
        const is_last = (stream.sent + chunk == stream.content_len); // FIN only when fully sent

        var pos: usize = 0;

        if (!conn.first_response_sent) {
            pos += buildConnectionPrologue(payload[pos..], config, conn.takeServerStreamId(.uni));
            conn.first_response_sent = true;
        }

        if (ackTake(ack_pending)) |largest| pos += response.buildAck(payload[pos..], largest);

        if (maxStreamsTake(max_streams_pending)) |granted| pos += response.buildMaxStreams(payload[pos..], granted);

        if (maxDataTake(max_data_pending)) |granted| pos += response.buildMaxData(payload[pos..], granted);

        // STREAM frame on the request stream: type OFF | LEN (| FIN), id, offset, length, then data.
        payload[pos] = 0x0e | @as(u8, if (is_last) 0x01 else 0x00);
        pos += 1;
        pos += varint.write(payload[pos..], stream.stream_id);
        pos += varint.write(payload[pos..], stream.sent);
        pos += varint.write(payload[pos..], chunk);
        copyStreamSlice(prefix, stream.body, stream.sent, payload[pos..][0..chunk]);
        pos += chunk;

        sealAndQueue(conn, tx, fd, peer, payload[0..pos], .{ .stream_id = stream.stream_id, .offset = stream.sent, .length = @intCast(chunk) });

        const offset_after = stream.sent + chunk;
        if (offset_after > stream.high_water) {
            conn.conn_data_sent += offset_after - stream.high_water;
            stream.high_water = offset_after;
        }
        stream.sent = offset_after;
        stream.unacked += chunk;
        sent_any = true;
    }

    // A fully-sent stream is not freed here: it stays active until its packets are acknowledged
    // (Connection.onAckFrame retires it once unacked reaches 0), so a tail packet lost after the last
    // byte went out is still found and retransmitted by the loss rewind.
    if (stream.complete()) logSystem(config, .INFO, "stream {d} fully sent ({d} bytes), awaiting ack", .{ stream.stream_id, stream.content_len });

    return sent_any;
}

/// Seal a 1-RTT payload into a short packet directly in the send batch's slot (no scratch buffer, no
/// copy: the AEAD writes the packet where sendmmsg / GSO will read it), flushing the batch first when
/// it has no room so the reply is never dropped. `retransmit` is the SendStream byte range this packet
/// carries, recorded for loss detection (Connection.recordSentRange), or null for a packet that
/// carries no SendStream data (a coalesced small response or a bare ACK): those have no retransmission
/// yet, a known gap.
fn sealAndQueue(conn: *Connection, tx: *datagram.SendBatch, fd: std.posix.socket_t, peer: std.posix.sockaddr.in6, payload: []const u8, retransmit: ?SentRangeInfo) void {
    const needed = payload.len + protection.short_seal_overhead_max;

    // Reserve the batch's free tail and seal into it. A full batch (no room for a packet this size)
    // flushes first, then reserves from the reset batch, which always has room for one packet.
    const slot = tx.reserve(needed) orelse blk: {
        tx.flush(fd) catch return;
        break :blk tx.reserve(needed) orelse return;
    };

    const reply = protection.sealShort(slot, conn.app_keys.server, conn.peer_scid.slice(), conn.app_pn, payload) catch return;
    const packet_number = conn.app_pn;
    conn.app_pn += 1;

    // Commit only after a successful seal: a seal error leaves the reserved tail uncommitted (used /
    // count unmoved), so the packet number is not consumed and nothing partial is ever sent.
    if (retransmit) |info| conn.recordSentRange(packet_number, recovery.nowUs(), info);

    tx.commit(peer, reply.len);
}

// --------------------------------------------------------------- //
// WebTransport over HTTP/3
// --------------------------------------------------------------- //

/// The decrypted 1-RTT payload one connection holds. A DATAGRAM frame has to fit it whole for the receive
/// path to read it, which is what caps the frame size the server advertises (Server.run rejects a larger
/// configured value rather than advertising something it cannot receive).
pub const max_app_payload_buf: usize = connection_module.app_payload_buf_len;

/// Open the worker's WebTransport pool, or null when the feature is off. A pool that cannot be allocated
/// disables the feature with one error line instead of failing the server: an HTTP/3 server without
/// WebTransport still serves every request.
///
/// Return:
/// - ?wt_pool.Pool (the worker owns it and deinits it on the way out)
pub fn openWebtransportPool(config: Http3ServerConfig) ?wt_pool.Pool {
    if (!config.webtransport.enabled) return null;

    return wt_pool.Pool.init(config.allocator, Webtransport.poolConfig(config.webtransport)) catch |err| {
        logSystem(config, .ERROR, "webtransport pool allocation failed ({s}), the feature stays off", .{@errorName(err)});

        return null;
    };
}

/// Write the connection's one-time prologue into `out`: HANDSHAKE_DONE, then the server control stream
/// (the id `takeServerStreamId(.uni)` hands out first) opening with its SETTINGS frame. Returns the bytes
/// written.
///
/// Note:
/// - The SETTINGS frame is where a WebTransport-capable server advertises support, so this is the one
///   place the feature becomes visible to the peer. The buffer it is built into is sized for the widest
///   settings set (eight entries), which is why the caller passes one big enough.
fn buildConnectionPrologue(out: []u8, config: Http3ServerConfig, control_stream_id: u64) usize {
    var pos: usize = 0;
    out[pos] = 0x1e; // HANDSHAKE_DONE
    pos += 1;

    var control_buf: [wt_settings_bytes]u8 = undefined;
    const advertised = webtransportSettings(config);
    logSystem(config, .INFO, "http3: advertising settings enabled={} connect_protocol={} datagram={} wt={} legacy={} uni={d} bidi={d} data={d}", .{ config.webtransport.enabled, advertised.enable_connect_protocol, advertised.h3_datagram, advertised.webtransport, advertised.legacy_webtransport, advertised.wt_initial_max_streams_uni, advertised.wt_initial_max_streams_bidi, advertised.wt_initial_max_data });
    const control_len = h3.writeServerControlStream(&control_buf, advertised) orelse {
        // The widest set could not fit: fall back to the empty SETTINGS the engine sent before the
        // feature existed, rather than leaving the control stream unopened (RFC 9114 6.2.1).
        logSystem(config, .WARN, "http3: the WebTransport settings did not fit {d} bytes, falling back to empty SETTINGS", .{wt_settings_bytes});
        control_buf[0] = 0x00;
        control_buf[1] = 0x04;
        control_buf[2] = 0x00;

        if (!response.writeStreamFrame(out, &pos, control_stream_id, false, control_buf[0..3])) return pos;

        return pos;
    };

    _ = response.writeStreamFrame(out, &pos, control_stream_id, false, control_buf[0..control_len]);

    return pos;
}

/// The room the server control stream needs: the control stream type, the SETTINGS frame type and
/// length, and eight entries at their widest encoding.
const wt_settings_bytes: usize = 160;

/// The HTTP/3 settings a WebTransport-capable server advertises. Every flag is off when the feature is
/// off, so a plain HTTP/3 connection carries the same empty SETTINGS it carried before the feature
/// existed.
fn webtransportSettings(config: Http3ServerConfig) h3.ServerSettings {
    const wt_config = config.webtransport;
    if (!wt_config.enabled) return .{};

    return .{
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .webtransport = true,
        .wt_initial_max_streams_uni = wt_config.max_streams_uni,
        .wt_initial_max_streams_bidi = wt_config.max_streams_bidi,
        .wt_initial_max_data = wt_config.max_session_data,
        .legacy_webtransport = wt_config.legacy_dialect,
    };
}

/// The transport parameter extensions the handshake advertises for the feature. Both are WebTransport
/// prerequisites: without them a client must not send a DATAGRAM frame, and a reliable reset is not
/// something it can expect.
fn webtransportTransportExtensions(config: Http3ServerConfig) flight.TransportExtensions {
    const wt_config = config.webtransport;
    if (!wt_config.enabled) return .{};

    return .{
        .max_datagram_frame_size = wt_config.max_datagram_frame_size,
        .reset_stream_at = true,
    };
}

/// The WebTransport streams one payload claimed, so the HTTP request loop leaves them alone: a
/// WebTransport data stream is a client request stream with a different meaning, and a session's CONNECT
/// stream is not an HTTP request to answer.
const WtClaims = struct {
    ids: [request.max_requests_per_packet]u64 = @splat(0),
    len: usize = 0,

    fn add(self: *WtClaims, stream_id: u64) void {
        if (self.len < self.ids.len) {
            self.ids[self.len] = stream_id;
            self.len += 1;
        }
    }

    fn has(self: *const WtClaims, stream_id: u64) bool {
        for (self.ids[0..self.len]) |id| {
            if (id == stream_id) return true;
        }

        return false;
    }
};

/// One WebTransport call's engine context: what the application-facing `Session` and `Stream` methods
/// reach when they need bytes on the wire, plus the connection state they read.
///
/// Note:
/// - One of these is built per datagram, for the duration of the callbacks that datagram triggers, and
///   the driver it hands out points at it. Nothing outlives the call: a session holds no pointer here.
const WtCall = struct {
    conn: *Connection,
    pool: *wt_pool.Pool,
    /// The worker's request pool, the same one an HTTP request with a body is assembled in: a CONNECT
    /// that arrives before the client's SETTINGS waits there.
    requests: *reassembly.Pool,
    tx: *datagram.SendBatch,
    fd: std.posix.socket_t,
    peer: std.posix.sockaddr.in6,
    config: Http3ServerConfig,
    /// The monotonic time this datagram was handled, for the pool operations that reclaim a stale slot.
    now_us: u64,

    /// The vtable the application calls into. It lives in this call's own frame (one WtCall per datagram,
    /// one datagram at a time per worker), so two workers never share a context pointer.
    driver: wt.Driver,

    /// The driver for this call, with `context` pointing back at it.
    fn driverPtr(self: *WtCall) *const wt.Driver {
        return &self.driver;
    }

    fn fromContext(context: *anyopaque) *WtCall {
        return @ptrCast(@alignCast(context));
    }

    /// Open a server-initiated data stream: take a pool slot, an id, and a place in both tables, then
    /// queue the header. The pump sends it at the end of this payload's processing.
    fn openStream(context: *anyopaque, session: *wt.Session, kind: wt_stream_header.Kind) ?*wt.Stream {
        const call = fromContext(context);
        const live = call.pool.acquireStream() orelse return null;

        var header_buf: [16]u8 = undefined;
        const header_len = wt_stream_header.write(kind, &header_buf, session.id) orelse {
            call.pool.releaseStream(live);

            return null;
        };

        live.* = .{
            .id = call.conn.takeServerStreamId(switch (kind) {
                .bidi => .bidi,
                .uni => .uni,
            }),
            .session_id = session.id,
            .kind = kind,
            .initiator = .server,
            .buf = live.buf,
            .driver = call.driverPtr(),
            .send = .{ .open = true, .limit = call.peerStreamLimit(kind) },
            .recv = .{ .limit = flight.initial_max_stream_data },
        };
        live.openWithHeader(header_buf[0..header_len]);

        if (!call.conn.wt.attachStream(live)) {
            call.pool.releaseStream(live);

            return null;
        }

        session.attachStream(live);
        session.flow.onOpenedStream(kind);

        return live;
    }

    /// The peer's per-stream send limit for a server-initiated stream of `kind` (RFC 9000 18.2): a
    /// bidirectional stream the server opens is the client's "remote" one, and its unidirectional limit
    /// is a parameter of its own.
    fn peerStreamLimit(self: *WtCall, kind: wt_stream_header.Kind) u64 {
        return switch (kind) {
            .bidi => self.conn.client_max_stream_data_bidi_remote,
            .uni => self.conn.client_max_stream_data_uni,
        };
    }

    /// Send one unreliable datagram. False when it cannot go now: the client did not negotiate
    /// datagrams, the payload does not fit what it accepts, or the congestion window has no room. A
    /// datagram is dropped rather than queued in that case, which is what "unreliable" means here
    /// (RFC 9221 5.4).
    fn sendDatagram(context: *anyopaque, session: *wt.Session, payload: []const u8) bool {
        const call = fromContext(context);

        if (call.conn.wt.peer_datagram_frame_size == 0) return false;
        if (payload.len > wt_datagram.maxPayloadBytes(call.conn.wt.peer_datagram_frame_size, session.id)) return false;

        var payload_buf: [max_app_payload_buf]u8 = undefined;
        const h3_len = wt_datagram.writeHttp3(&payload_buf, session.id, payload) orelse return false;

        var frame_buf: [max_app_payload_buf]u8 = undefined;
        const frame_len = wt_datagram.writeFrame(&frame_buf, payload_buf[0..h3_len]) orelse return false;

        // Congestion control applies to datagrams like any other frame (RFC 9221 5.4), so a full window
        // drops this one instead of overrunning the path.
        if (call.conn.bytes_in_flight + frame_len > call.conn.cc.congestion_window) return false;

        // The range is tagged as a datagram: it counts as in flight and retires on acknowledgement, but
        // the recovery paths never rewind it (RFC 9221 5.2).
        sealAndQueue(call.conn, call.tx, call.fd, call.peer, frame_buf[0..frame_len], .{
            .stream_id = session.id,
            .offset = 0,
            .length = @intCast(frame_len),
            .datagram = true,
        });

        return true;
    }

    fn closeSession(context: *anyopaque, session: *wt.Session) void {
        _ = fromContext(context);

        var buf: [wt_capsule.max_known_value + 8]u8 = undefined;
        const len = wt_capsule.writeCloseSession(&buf, session.close.code, session.close.message) orelse return;

        queueOnConnectStream(session, buf[0..len]);
        // A close finishes the CONNECT stream as well (6), which is what tells the peer the session is
        // over even if the capsule itself is lost.
        session.connect.send.fin = true;
    }

    fn drainSession(context: *anyopaque, session: *wt.Session) void {
        _ = fromContext(context);

        var buf: [8]u8 = undefined;
        const len = wt_capsule.writeDrainSession(&buf) orelse return;

        queueOnConnectStream(session, buf[0..len]);
    }

    /// Append capsule bytes to the CONNECT stream's send buffer. A capsule the buffer cannot hold is
    /// dropped: the buffer is sized for the largest legal close capsule, so only a second close could
    /// overflow it, and a second close is not a thing.
    fn queueOnConnectStream(session: *wt.Session, bytes: []const u8) void {
        _ = session.connect.write(bytes);
    }

    /// Ask the peer to stop sending on a stream (STOP_SENDING, RFC 9000 19.5).
    fn stopReceiving(context: *anyopaque, stream: *wt.Stream, code: u32) void {
        const call = fromContext(context);

        var buf: [24]u8 = undefined;
        var pos: usize = 0;
        buf[pos] = 0x05; // STOP_SENDING
        pos += 1;
        pos += varint.write(buf[pos..], stream.id);
        pos += varint.write(buf[pos..], wt_draft.encodeAppError(code));
        sendControlPacket(call, buf[0..pos]);
    }

    /// Queue the reset of a stream's send half (4.4) and mark it sent.
    fn resetStream(context: *anyopaque, stream: *wt.Stream) void {
        const call = fromContext(context);

        sendStreamReset(call, stream, wt_draft.encodeAppError(stream.send.reset.?.code));
        stream.send.reset.?.sent = true;
    }

    /// Seal one small control frame into a packet of its own and queue it. The frame is not retransmitted
    /// here: a reset is retried by the maintenance sweep while its stream is still tracked, and a
    /// STOP_SENDING rides the next stream packet, the same best-effort a connection close already has.
    fn sendControlPacket(call: *WtCall, frame_bytes: []const u8) void {
        sealAndQueue(call.conn, call.tx, call.fd, call.peer, frame_bytes, null);
    }
};

/// The WebTransport receive pass for one decrypted payload: datagrams and stream resets, then client
/// unidirectional streams (control and WebTransport), then client bidirectional streams (session
/// CONNECTs and WebTransport data streams). Runs before the HTTP request pass, which skips every stream
/// this pass claims.
fn webtransportIncoming(
    conn: *Connection,
    pool: *wt_pool.Pool,
    requests: *reassembly.Pool,
    payload: []const u8,
    tx: *datagram.SendBatch,
    fd: std.posix.socket_t,
    peer: std.posix.sockaddr.in6,
    config: Http3ServerConfig,
    claims: *WtClaims,
) void {
    var call = WtCall{
        .conn = conn,
        .pool = pool,
        .requests = requests,
        .tx = tx,
        .fd = fd,
        .peer = peer,
        .config = config,
        .now_us = recovery.nowUs(),
        .driver = .{
            .context = undefined,
            .open_stream = WtCall.openStream,
            .send_datagram = WtCall.sendDatagram,
            .close_session = WtCall.closeSession,
            .drain_session = WtCall.drainSession,
            .stop_receiving = WtCall.stopReceiving,
            .reset_stream = WtCall.resetStream,
        },
    };
    call.driver.context = &call;

    wtIncomingFrames(&call, payload);

    var uni_pieces: [request.max_requests_per_packet]request.UniPiece = undefined;
    const uni_count = request.parseUniPieces(payload, &uni_pieces);
    for (uni_pieces[0..uni_count]) |piece| wtIncomingUniStream(&call, piece, claims);

    var pieces: [request.max_requests_per_packet]request.StreamPiece = undefined;
    const count = request.parseStreamPieces(payload, &pieces);
    for (pieces[0..count]) |piece| wtIncomingBidiStream(&call, piece, claims);
}

/// Accept a WebTransport session request that the *HTTP request pass* assembled rather than the
/// packet-level pass above.
///
/// Why this exists: the packet-level pass only sees a CONNECT whose header block it can decode out of
/// the bytes of one packet (`piece.request`). A client that has already sent a request on the same
/// connection - fetching the page, for instance - leaves its QPACK encoder with state that a later
/// header block refers to, so the decode is not ready when the packet that opens the CONNECT stream
/// arrives. Left alone, that stream is claimed by nobody and the request path answers the CONNECT as an
/// ordinary HTTP request, and no session is ever created. The request pool has the bytes assembled by
/// then, so the accept path runs here with the decoded request instead.
fn webtransportAcceptAssembled(
    conn: *Connection,
    pool: *wt_pool.Pool,
    requests: *reassembly.Pool,
    tx: *datagram.SendBatch,
    fd: std.posix.socket_t,
    peer: std.posix.sockaddr.in6,
    config: Http3ServerConfig,
    piece: request.StreamPiece,
    decoded: request.DecodedRequest,
) void {
    var call = WtCall{
        .conn = conn,
        .pool = pool,
        .requests = requests,
        .tx = tx,
        .fd = fd,
        .peer = peer,
        .config = config,
        .now_us = recovery.nowUs(),
        .driver = .{
            .context = undefined,
            .open_stream = WtCall.openStream,
            .send_datagram = WtCall.sendDatagram,
            .close_session = WtCall.closeSession,
            .drain_session = WtCall.drainSession,
            .stop_receiving = WtCall.stopReceiving,
            .reset_stream = WtCall.resetStream,
        },
    };
    call.driver.context = &call;

    logSystem(config, .INFO, "webtransport: session request on stream {d} was assembled from the request pool", .{piece.stream_id});

    wtIncomingConnect(&call, piece, decoded);
}

/// Read the non-STREAM frames a WebTransport connection cares about: DATAGRAM frames, and the stream
/// resets a peer uses to end a data stream early.
fn wtIncomingFrames(call: *WtCall, payload: []const u8) void {
    var pos: usize = 0;
    while (pos < payload.len) {
        const type_vi = varint.read(payload[pos..]) catch break;

        switch (type_vi.value) {
            0x30, 0x31 => {
                const parsed = frame.parseFrame(payload[pos..]) catch break;
                wtIncomingDatagram(call, parsed.frame.datagram);
                pos += parsed.len;
            },
            0x04 => { // RESET_STREAM: stream id, application error code, final size.
                var p = pos + type_vi.len;
                const id = varint.read(payload[p..]) catch break;
                p += id.len;
                const code = varint.read(payload[p..]) catch break;
                p += code.len;
                const final_size = varint.read(payload[p..]) catch break;
                p += final_size.len;

                wtIncomingReset(call, id.value, code.value, final_size.value);
                pos = p;
            },
            0x24 => { // RESET_STREAM_AT: the same three fields, then the reliable size.
                var p = pos + type_vi.len;
                const id = varint.read(payload[p..]) catch break;
                p += id.len;
                const code = varint.read(payload[p..]) catch break;
                p += code.len;
                const final_size = varint.read(payload[p..]) catch break;
                p += final_size.len;
                const reliable = varint.read(payload[p..]) catch break;
                p += reliable.len;

                wtIncomingReset(call, id.value, code.value, final_size.value);
                pos = p;
            },
            0x05 => { // STOP_SENDING: stream id, application error code.
                var p = pos + type_vi.len;
                const id = varint.read(payload[p..]) catch break;
                p += id.len;
                const code = varint.read(payload[p..]) catch break;
                p += code.len;

                wtIncomingStopSending(call, id.value, code.value);
                pos = p;
            },
            else => {
                const skipped = request.skipFrame(payload[pos..]) orelse break;
                if (skipped == 0) break;
                pos += skipped;
            },
        }
    }
}

/// One DATAGRAM frame: route it to its session, or drop it (RFC 9297 2.1 allows dropping a datagram whose
/// session does not exist, and 4.6 requires a limit rather than unbounded buffering).
fn wtIncomingDatagram(call: *WtCall, data: []const u8) void {
    const parsed = wt_datagram.parseHttp3(data) catch return;
    const session = call.conn.wt.findSession(parsed.session_id) orelse {
        call.conn.wt.dropped_datagrams += 1;

        return;
    };
    if (!session.isOpen()) return;

    const on_datagram = call.config.webtransport.handler.on_datagram orelse return;
    var view = Webtransport.Session{ .inner = session, .driver = call.driverPtr() };
    on_datagram(&view, parsed.payload);
}

/// One stream reset from the peer: charge the session limit for the final size (5.4), mark the receive
/// half reset, tell the application, and retire the stream when nothing is left on it.
fn wtIncomingReset(call: *WtCall, stream_id: u64, code: u64, final_size: u64) void {
    // A reset of a session's CONNECT stream ends that session (6), and it is not a data stream, so it is
    // checked first: the session id is the CONNECT stream id.
    if (call.conn.wt.findSession(stream_id)) |session| {
        wtCloseSession(call, session, .{ .code = 0, .message = "", .reason = .peer_reset });

        return;
    }

    const live = call.conn.wt.findStream(stream_id) orelse return;
    const session = call.conn.wt.findSession(live.session_id) orelse return;

    live.onResetReceived(code, final_size);
    session.flow.onResetFinalSize(final_size) catch {
        wtFailSession(call, session, .flow_control_error, wt_draft.error_code.wt_flow_control_error);

        return;
    };

    if (call.config.webtransport.handler.on_stream_reset) |on_reset| {
        var view = Webtransport.Session{ .inner = session, .driver = call.driverPtr() };
        var stream_view = Webtransport.Stream{ .inner = live, .driver = call.driverPtr() };
        on_reset(&view, &stream_view);
    }

    wtRetireStream(call, session, live);
}

/// One STOP_SENDING from the peer: it will not read this stream, so the send half is reset with the same
/// code (RFC 9000 3.5) and the application's writes stop being accepted.
fn wtIncomingStopSending(call: *WtCall, stream_id: u64, code: u64) void {
    const live = call.conn.wt.findStream(stream_id) orelse return;
    if (live.send.reset != null) return;

    live.recv.stopped = true;
    live.resetSend(wt_draft.decodeAppError(code) orelse 0);

    sendStreamReset(call, live, code);
    live.send.reset.?.sent = true;
}

/// Queue the reset of a stream's send half. A peer that advertised reset_stream_at gets RESET_STREAM_AT
/// with a reliable size covering the header, so the association survives the discard even when the
/// payload does not (4.4); every other peer gets a plain RESET_STREAM.
///
/// Param:
/// call - *WtCall
/// live - *wt.Stream (its send.reset describes what is being reset)
/// code - u64 (the HTTP/3 error code to carry; a WebTransport application error is mapped through
///   wt_draft.encodeAppError first)
fn sendStreamReset(call: *WtCall, live: *wt.Stream, code: u64) void {
    queueStreamReset(call.conn, call.tx, call.fd, call.peer, live, code);
}

/// Build and queue one stream reset frame: RESET_STREAM_AT when the peer advertised the extension, so the
/// header survives the discard (4.4), and a plain RESET_STREAM otherwise.
fn queueStreamReset(conn: *Connection, tx: *datagram.SendBatch, fd: std.posix.socket_t, peer: std.posix.sockaddr.in6, live: *wt.Stream, code: u64) void {
    const reset = live.send.reset orelse return;

    var buf: [48]u8 = undefined;
    var pos: usize = 0;

    if (conn.wt.peer_reset_stream_at) {
        buf[pos] = 0x24; // RESET_STREAM_AT
        pos += 1;
        pos += varint.write(buf[pos..], live.id);
        pos += varint.write(buf[pos..], code);
        pos += varint.write(buf[pos..], reset.reliable_size);
        pos += varint.write(buf[pos..], reset.reliable_size);
    } else {
        buf[pos] = 0x04; // RESET_STREAM
        pos += 1;
        pos += varint.write(buf[pos..], live.id);
        pos += varint.write(buf[pos..], code);
        pos += varint.write(buf[pos..], live.totalBytes());
    }

    sealAndQueue(conn, tx, fd, peer, buf[0..pos], null);
}

/// Retry the stream resets this connection still owes. A reset frame is not tracked for acknowledgement,
/// so a Probe Timeout is its retry: every stream whose reset went out and whose send half is not yet
/// finished is reset again, which is the same best-effort the engine gives its other control frames.
fn pumpWebtransportResets(conn: *Connection, tx: *datagram.SendBatch, fd: std.posix.socket_t) void {
    for (conn.wt.streams) |entry| {
        const live = entry orelse continue;
        const reset = live.send.reset orelse continue;
        if (!reset.sent) continue;
        if (live.sendFinished()) continue;

        queueStreamReset(conn, tx, fd, conn.peer_addr, live, wt_draft.encodeAppError(reset.code));
    }

    for (conn.wt.sessions) |entry| {
        const session = entry orelse continue;
        const reset = session.connect.send.reset orelse continue;
        _ = reset;

        queueStreamReset(conn, tx, fd, conn.peer_addr, &session.connect, wt_draft.error_code.wt_session_gone);
    }
}

/// Release every WebTransport session a connection holds, telling the application each one ended because
/// its connection did.
///
/// Note:
/// - No per-stream reset is sent: the connection itself is gone, which is what the peer observes, so the
///   only thing left to do is give the slots back and report the close.
fn wtReleaseConnection(config: Http3ServerConfig, conn: *Connection, pool: *wt_pool.Pool) void {
    for (&conn.wt.sessions) |*entry| {
        const session = entry.* orelse continue;
        entry.* = null;

        while (session.streams) |live| {
            _ = session.detachStream(live);
            conn.wt.detachStream(live);
            pool.releaseStream(live);
        }

        session.close_(.{ .code = 0, .message = "", .reason = .connection_closed });

        if (config.webtransport.handler.on_close) |on_close| {
            var view = Webtransport.Session{ .inner = session, .driver = null };
            on_close(&view);
        }

        _ = pool.dropOrphans(session.id);
        pool.releaseSession(session);
    }

    // A data stream with no session left (its session was already released) still holds a slot.
    for (&conn.wt.streams) |*entry| {
        const live = entry.* orelse continue;
        entry.* = null;
        pool.releaseStream(live);
    }
}

/// One client unidirectional stream frame. The first byte(s) of the stream are its type (RFC 9114 6.2):
/// the control stream carries the client's SETTINGS, the QPACK streams are ignored because this engine
/// never uses the dynamic table, and 0x54 opens a WebTransport unidirectional data stream.
fn wtIncomingUniStream(call: *WtCall, piece: request.UniPiece, claims: *WtClaims) void {
    // The type is only on the wire once, at offset 0. A stream already classified needs no second look.
    const stream_type = call.conn.wt.uniStreamType(piece.stream_id, piece.offset, piece.data) orelse return;

    switch (stream_type) {
        h3.control_stream => wtIncomingControlStream(call, piece),
        h3.qpack_encoder_stream, h3.qpack_decoder_stream => {},
        wt_draft.uni_stream_type => wtIncomingWtUniStream(call, piece, claims),
        else => {},
    }
}

/// The client's control stream: exactly one, SETTINGS first, and the SETTINGS frame is what tells this
/// endpoint what the client supports (RFC 9114 6.2.1 / 6.2.3). The frames are small, so the parse works
/// on the bytes as they arrive and stops once the SETTINGS frame is read.
fn wtIncomingControlStream(call: *WtCall, piece: request.UniPiece) void {
    // The stream type occupies the head of the first frame; what follows on this stream is the SETTINGS
    // frame. The accumulator drops the type byte once it has seen it, because the parse below expects the
    // frame to start at offset 0 of what it is given.
    const type_len: usize = if (piece.offset == 0) 1 else 0;
    if (piece.data.len <= type_len) return;

    const settings = call.conn.wt.feedControlStream(piece.data[type_len..]) orelse return;

    // The client's SETTINGS just landed, so the CONNECT requests that were waiting on them can be
    // processed: their bytes are in the worker's request pool, and this is the moment the features they
    // need are known.
    wtProcessPendingConnects(call);

    if (settings.malformed) {
        logSystem(call.config, .WARN, "client SETTINGS are malformed, the connection is left to the peer's own error handling", .{});

        return;
    }

    logSystem(call.config, .INFO, "client SETTINGS received (h3_datagram={}, webtransport_enabled={d}, legacy_max_sessions={d})", .{
        settings.h3_datagram,
        settings.wt_enabled,
        settings.webtransport_max_sessions,
    });
}

/// One WebTransport unidirectional data stream (4.2): type 0x54, then the session id, then the bytes.
fn wtIncomingWtUniStream(call: *WtCall, piece: request.UniPiece, claims: *WtClaims) void {
    const header = wt_stream_header.parse(.uni, piece.data) catch |err| switch (err) {
        error.ZixTruncated => {
            // The header is still arriving: hold the bytes until it is complete (4.6 allows buffering,
            // and the pool bounds it).
            wtBufferOrphan(call, piece.stream_id, .uni, 0, piece.data, piece.fin);
            claims.add(piece.stream_id);

            return;
        },
        error.ZixNotWebtransport, error.ZixIdError => return,
    };

    claims.add(piece.stream_id);
    wtDeliverData(call, .uni, header.session_id, header.len, piece.stream_id, piece.offset, piece.fin, piece.data);
}

/// One client bidirectional stream frame: a session CONNECT, its capsules, a WebTransport data stream, or
/// an HTTP request (which this pass leaves alone).
fn wtIncomingBidiStream(call: *WtCall, piece: request.StreamPiece, claims: *WtClaims) void {
    // A stream that is already a live session is its CONNECT stream: its bytes are capsules (3.2).
    if (call.conn.wt.findSession(piece.stream_id)) |session| {
        claims.add(piece.stream_id);
        wtIncomingConnectStream(call, session, piece);

        return;
    }

    // A stream that is already a live data stream is a continuation of its payload.
    if (call.conn.wt.findStream(piece.stream_id)) |live| {
        claims.add(piece.stream_id);
        wtDeliverExisting(call, live, piece);

        return;
    }

    // A new stream: the 0x41 signal value converts it from a request stream into a WebTransport data
    // stream (4.3), and an extended CONNECT opens a session.
    if (piece.offset != 0) return;

    if (wt_stream_header.parse(.bidi, piece.data)) |header| {
        claims.add(piece.stream_id);
        wtDeliverData(call, .bidi, header.session_id, header.len, piece.stream_id, piece.offset, piece.fin, piece.data);

        return;
    } else |err| switch (err) {
        error.ZixTruncated => {
            wtBufferOrphan(call, piece.stream_id, .bidi, 0, piece.data, piece.fin);
            claims.add(piece.stream_id);

            return;
        },
        error.ZixNotWebtransport => {},
        error.ZixIdError => {
            // A session id that is not a client-initiated bidirectional stream id is H3_ID_ERROR (4.1).
            call.conn.close_state = .draining;
            claims.add(piece.stream_id);

            return;
        },
    }

    const decoded = piece.request orelse return;
    if (!wtIsWebtransportConnect(decoded)) {
        if (std.mem.eql(u8, decoded.method, "CONNECT")) {
            logSystem(call.config, .INFO, "webtransport: CONNECT on stream {d} is not a session request (protocol={s}, huffman={}, dialect={s})", .{ piece.stream_id, decoded.protocol, decoded.protocol_huffman, if (decoded.protocol_huffman) "(huffman)" else "plain" });
        }

        return;
    }

    claims.add(piece.stream_id);
    wtIncomingConnect(call, piece, decoded);
}

/// Expand one request field the application will read into a slice of `scratch`, or return an empty
/// slice when the field is absent or does not fit. A Huffman-coded field is decoded here; the scratch is
/// one buffer carved into fixed ranges, because the fields are read once, at session establishment.
fn wtExpandField(field: []const u8, is_huffman: bool, scratch: []u8, from: usize, to: usize) []const u8 {
    if (field.len == 0) return "";

    const room = scratch[from..to];
    if (!is_huffman) {
        if (field.len > room.len) return "";

        @memcpy(room[0..field.len], field);

        return room[0..field.len];
    }

    const decoded_len = huffman.decode(room, field) orelse return "";

    return room[0..decoded_len];
}

/// Process the WebTransport CONNECT requests that arrived before the client's SETTINGS. Each one is
/// already assembled in the worker's request pool (the same pool a request with a body uses), so this
/// reads the bytes back, decodes the request, and runs the normal accept path on it.
fn wtProcessPendingConnects(call: *WtCall) void {
    call.conn.wt.takePendingConnects(wtProcessPendingConnect, call);
}

fn wtProcessPendingConnect(call: *WtCall, stream_id: u64) void {
    for (call.requests.slots) |*slot| {
        if (!slot.active or slot.stream_id != stream_id) continue;
        if (!slot.cid.eql(&call.conn.dcid)) continue;

        const bytes = slot.assembledMutable();
        const decoded = request.decodeAssembledRequest(bytes, true) orelse {
            call.requests.release(slot);

            return;
        };

        // The pool slot is released only after the accept path has read what it needs: the response head
        // it queues comes from these same bytes.
        wtIncomingConnect(call, .{
            .stream_id = stream_id,
            .offset = 0,
            .fin = true,
            .data = bytes,
            .request = decoded,
        }, decoded);
        call.requests.release(slot);

        return;
    }
}

/// Whether a decoded request is a WebTransport session request: an extended CONNECT (RFC 9220) whose
/// `:protocol` token this endpoint accepts (draft-16 3.2 / 9.1).
fn wtIsWebtransportConnect(decoded: request.DecodedRequest) bool {
    if (!std.mem.eql(u8, decoded.method, "CONNECT")) return false;
    if (decoded.protocol.len == 0) return false;
    if (!decoded.protocol_huffman) return wt_draft.dialectForToken(decoded.protocol) != null;

    // A Huffman-coded token is expanded here: the values are short and this runs once per CONNECT.
    var scratch: [32]u8 = undefined;
    const decoded_len = huffman.decode(&scratch, decoded.protocol) orelse return false;

    return wt_draft.dialectForToken(scratch[0..decoded_len]) != null;
}

/// Establish (or refuse) a WebTransport session for one extended CONNECT request.
fn wtIncomingConnect(call: *WtCall, piece: request.StreamPiece, decoded: request.DecodedRequest) void {
    const config = call.config.webtransport;

    // The token, expanded if the client Huffman-coded it.
    var token_scratch: [32]u8 = undefined;
    const token = if (decoded.protocol_huffman)
        token_scratch[0 .. huffman.decode(&token_scratch, decoded.protocol) orelse
            {
                logSystem(call.config, .INFO, "webtransport: CONNECT on stream {d} has an undecodable :protocol", .{piece.stream_id});

                return;
            }]
    else
        decoded.protocol;

    const dialect = wt_draft.dialectForToken(token) orelse {
        logSystem(call.config, .INFO, "webtransport: CONNECT on stream {d} names an unknown dialect ({s})", .{ piece.stream_id, token });

        return;
    };
    if (dialect == .draft07 and !config.legacy_dialect) {
        logSystem(call.config, .INFO, "webtransport: CONNECT on stream {d} is draft-07 and legacy dialing is off", .{piece.stream_id});

        return;
    }

    // draft-16 7.1: the server MUST NOT process a WebTransport request before the client's SETTINGS
    // arrive, because the settings are what pin the version and the required features. The request is
    // held instead of refused: a client sends its SETTINGS and its CONNECT in one flight, and the two can
    // arrive in either order, so refusing would cost the session for a packet that is merely late. The
    // held stream is re-processed the moment the SETTINGS land (wtIncomingControlStream).
    if (!call.conn.wt.settings_received) {
        switch (call.requests.feed(call.now_us, &call.conn.dcid, piece.stream_id, piece.offset, piece.data, piece.fin)) {
            .ready, .waiting => {
                if (!call.conn.wt.notePendingConnect(piece.stream_id)) {
                    logSystem(call.config, .INFO, "webtransport: CONNECT on stream {d} held but the table is full", .{piece.stream_id});
                    wtResetRequestStream(call, piece.stream_id, h3.Http3Error.request_rejected);
                } else {
                    logSystem(call.config, .INFO, "webtransport: CONNECT on stream {d} held until the client's SETTINGS arrive", .{piece.stream_id});
                }
            },
            // The pool is full, so this request cannot be held: it is refused with the code for "not
            // processed in any way" (RFC 9114 8.1) rather than answered against half a request.
            .refused => {
                logSystem(call.config, .INFO, "webtransport: CONNECT on stream {d} could not be held (request pool full)", .{piece.stream_id});
                wtResetRequestStream(call, piece.stream_id, h3.Http3Error.request_rejected);
            },
        }

        return;
    }

    // 3.1: a WebTransport connection requires HTTP/3 datagrams on both sides. Without the client's
    // SETTINGS_H3_DATAGRAM=1 and a transport parameter granting datagrams, the request is malformed.
    if (!call.conn.wt.client_settings.h3_datagram or call.conn.wt.peer_datagram_frame_size == 0) {
        logSystem(call.config, .INFO, "webtransport: CONNECT on stream {d} refused: h3_datagram={} peer_datagram_frame_size={d}", .{ piece.stream_id, call.conn.wt.client_settings.h3_datagram, call.conn.wt.peer_datagram_frame_size });
        wtResetRequestStream(call, piece.stream_id, h3.Http3Error.message_error);

        return;
    }

    // 5.2: the server limits how many sessions a connection may have, and 5.1: without flow control only
    // one session at a time is allowed.
    if (call.conn.wt.sessionCount() >= config.max_sessions_per_connection) {
        logSystem(call.config, .INFO, "webtransport: CONNECT on stream {d} refused: {d} sessions already live", .{ piece.stream_id, call.conn.wt.sessionCount() });
        wtRejectConnect(call, piece.stream_id, decoded, 429);

        return;
    }

    const session = call.pool.acquireSession() orelse {
        logSystem(call.config, .INFO, "webtransport: CONNECT on stream {d} refused: no session slot in the pool", .{piece.stream_id});
        wtRejectConnect(call, piece.stream_id, decoded, 503);

        return;
    };

    session.* = .{ .id = piece.stream_id, .dialect = dialect };
    session.flow.declareLocal(config.max_session_data, config.max_streams_bidi, config.max_streams_uni);
    session.flow.declarePeer(
        call.conn.wt.client_settings.wt_initial_max_data,
        call.conn.wt.client_settings.wt_initial_max_streams_bidi,
        call.conn.wt.client_settings.wt_initial_max_streams_uni,
    );

    if (!call.conn.wt.attachSession(session)) {
        logSystem(call.config, .INFO, "webtransport: CONNECT on stream {d} refused: the connection holds no free session slot", .{piece.stream_id});
        call.pool.releaseSession(session);
        wtRejectConnect(call, piece.stream_id, decoded, 503);

        return;
    }
    call.conn.wt.pool = call.pool;

    // The application decides: a null return accepts, a status refuses. The request fields the
    // application routes on are expanded here, because a client is free to Huffman-code any of them and
    // the decode leaves those bytes compressed.
    var field_scratch: [512]u8 = undefined;
    var view = Webtransport.Session{
        .inner = session,
        .driver = call.driverPtr(),
        .request = .{
            .path = wtExpandField(decoded.path, decoded.path_huffman, &field_scratch, 0, 192),
            .authority = wtExpandField(decoded.authority, decoded.authority_huffman, &field_scratch, 192, 384),
            .protocol = token,
            .origin = wtExpandField(decoded.origin, decoded.origin_huffman, &field_scratch, 384, 512),
            .dialect = dialect,
            .datagram_capable = call.conn.wt.peer_datagram_frame_size != 0,
        },
    };

    if (config.handler.on_session) |on_session| {
        if (on_session(&view)) |status| {
            logSystem(call.config, .INFO, "webtransport: the application refused the session on stream {d} with {d}", .{ piece.stream_id, status });
            call.conn.wt.detachSession(session);
            call.pool.releaseSession(session);
            wtRejectConnect(call, piece.stream_id, decoded, status);

            return;
        }
    }

    // Accepted: queue the 2xx response head on the CONNECT stream, which stays open for capsules until
    // the session ends (6).
    var head_buf: [32]u8 = undefined;
    const head_len = response.buildRequestStreamContent(&head_buf, 200, .identity, "") orelse {
        call.conn.wt.detachSession(session);
        call.pool.releaseSession(session);
        wtRejectConnect(call, piece.stream_id, decoded, 500);

        return;
    };
    session.openConnect(head_buf[0..head_len]);

    // A client may open streams and send datagrams before it sees the response (4.6), so anything it
    // buffered against this session is delivered now.
    wtReplayOrphans(call, session);

    logSystem(call.config, .INFO, "webtransport session {d} open ({s})", .{ session.id, if (dialect == .draft16) "draft-16" else "draft-07" });
}

/// Refuse a session request with an HTTP status, on the request stream, as an ordinary HTTP response
/// (3.2 allows any status, including 405 for a resource that does not serve WebTransport and 403 for a
/// disallowed origin).
fn wtRejectConnect(call: *WtCall, stream_id: u64, decoded: request.DecodedRequest, status: u16) void {
    _ = decoded;

    sendSingleResponse(call, stream_id, status);
}

/// Send one small headers-only response on a request stream, with FIN: the shape a WebTransport CONNECT
/// that the server will not accept gets, and the shape the request path itself uses for a small answer
/// (RFC 9114 7.2.1 / 7.2.2).
fn sendSingleResponse(call: *WtCall, stream_id: u64, status: u16) void {
    var content: [160]u8 = undefined;
    const len = response.buildRequestStreamContent(&content, status, .identity, "") orelse return;

    var payload: [256]u8 = undefined;
    var pos: usize = 0;
    if (!response.writeStreamFrame(&payload, &pos, stream_id, true, content[0..len])) return;

    sealAndQueue(call.conn, call.tx, call.fd, call.peer, payload[0..pos], null);
}

/// Reset a request stream with an HTTP/3 error code: the request was not processed (RFC 9114 8.1).
fn wtResetRequestStream(call: *WtCall, stream_id: u64, code: h3.Http3Error) void {
    var buf: [24]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0x04; // RESET_STREAM
    pos += 1;
    pos += varint.write(buf[pos..], stream_id);
    pos += varint.write(buf[pos..], @intFromEnum(code));
    pos += varint.write(buf[pos..], 0);
    WtCall.sendControlPacket(call, buf[0..pos]);
}

/// Deliver the payload of a WebTransport data stream frame to a live stream, creating the stream when it
/// is new. The header bytes are already consumed by the caller.
fn wtDeliverData(call: *WtCall, kind: wt_stream_header.Kind, session_id: u64, header_len: usize, stream_id: u64, offset: u64, fin: bool, data: []const u8) void {
    const session = call.conn.wt.findSession(session_id) orelse {
        // The session does not exist yet: hold the bytes (4.6), or reject the stream when there is no
        // room to hold them.
        wtBufferOrphan(call, stream_id, kind, session_id, data, fin);

        return;
    };
    if (!session.isOpen()) {
        wtResetStreamForSession(call, stream_id, kind, session_id, wt_draft.error_code.wt_session_gone);

        return;
    }

    var live = call.conn.wt.findStream(stream_id) orelse blk: {
        const slot = call.pool.acquireStream() orelse {
            wtResetStreamForSession(call, stream_id, kind, session_id, wt_draft.error_code.wt_buffered_stream_rejected);

            return;
        };

        slot.* = .{
            .id = stream_id,
            .session_id = session_id,
            .kind = kind,
            .initiator = .client,
            .buf = slot.buf,
            .driver = call.driverPtr(),
            // A bidirectional stream the client opened is also this endpoint's to write on (RFC 9000 2.1),
            // so its send half is open from the start: that is what lets the application answer on it. The
            // credit is the client's initial_max_stream_data_bidi_local (0x05), the limit it granted for
            // streams this endpoint sends on locally. A client-opened unidirectional stream has no send
            // half here at all.
            .send = if (kind == .bidi)
                .{ .open = true, .limit = call.conn.client_max_stream_data }
            else
                .{},
            .recv = .{ .limit = flight.initial_max_stream_data },
        };

        if (!call.conn.wt.attachStream(slot)) {
            call.pool.releaseStream(slot);
            wtResetStreamForSession(call, stream_id, kind, session_id, wt_draft.error_code.wt_buffered_stream_rejected);

            return;
        }

        session.attachStream(slot);
        session.flow.onStreamOpened(kind) catch {
            wtFailSession(call, session, .flow_control_error, wt_draft.error_code.wt_flow_control_error);

            return;
        };

        break :blk slot;
    };

    const payload = data[header_len..];
    session.onStreamData(payload.len) catch {
        wtFailSession(call, session, .flow_control_error, wt_draft.error_code.wt_flow_control_error);

        return;
    };

    const payload_offset = offset + header_len;
    live.onReceived(payload_offset, payload.len, fin);

    if (call.config.webtransport.handler.on_stream) |on_stream| {
        var view = Webtransport.Session{ .inner = session, .driver = call.driverPtr() };
        var stream_view = Webtransport.Stream{
            .inner = live,
            .driver = call.driverPtr(),
            .chunk = payload,
            .chunk_offset = payload_offset - wt_stream_header.headerLen(kind, session_id),
        };
        on_stream(&view, &stream_view);
    }

    // The peer's limit is extended as it consumes the stream, so a stream longer than the handshake
    // allowance keeps flowing: a WebTransport data stream has no reassembly slot, so nothing else in the
    // engine replenishes its credit.
    if (live.replenish(flight.initial_max_stream_data)) |limit| {
        var buf: [24]u8 = undefined;
        var pos: usize = 0;
        buf[pos] = 0x11; // MAX_STREAM_DATA
        pos += 1;
        pos += varint.write(buf[pos..], live.id);
        pos += varint.write(buf[pos..], limit);
        WtCall.sendControlPacket(call, buf[0..pos]);
    }

    wtRetireIfDone(call, session, live);
}

/// Deliver a continuation frame of a stream this connection already tracks.
fn wtDeliverExisting(call: *WtCall, live: *wt.Stream, piece: request.StreamPiece) void {
    const session = call.conn.wt.findSession(live.session_id) orelse return;
    if (!session.isOpen()) return;

    session.onStreamData(piece.data.len) catch {
        wtFailSession(call, session, .flow_control_error, wt_draft.error_code.wt_flow_control_error);

        return;
    };

    live.onReceived(piece.offset, piece.data.len, piece.fin);

    if (call.config.webtransport.handler.on_stream) |on_stream| {
        var view = Webtransport.Session{ .inner = session, .driver = call.driverPtr() };
        var stream_view = Webtransport.Stream{
            .inner = live,
            .driver = call.driverPtr(),
            .chunk = piece.data,
            .chunk_offset = piece.offset - wt_stream_header.headerLen(live.kind, live.session_id),
        };
        on_stream(&view, &stream_view);
    }

    wtRetireIfDone(call, session, live);
}

/// One CONNECT stream frame: its DATA frames carry the session's capsules (RFC 9297 3), and its FIN or
/// reset ends the session (6).
fn wtIncomingConnectStream(call: *WtCall, session: *wt.Session, piece: request.StreamPiece) void {

    // The H3 frames on this stream: DATA frames hold capsules, and anything else on it is not something
    // this binding sends or expects.
    var pos: usize = 0;
    while (pos < piece.data.len) {
        const type_vi = varint.read(piece.data[pos..]) catch break;

        switch (type_vi.value) {
            0x00 => { // DATA: capsules (RFC 9297 3.1)
                const len_vi = varint.read(piece.data[pos + type_vi.len ..]) catch break;
                const header = pos + type_vi.len + len_vi.len;
                const payload_len: usize = std.math.cast(usize, len_vi.value) orelse break;
                if (header + payload_len > piece.data.len) break;

                wtIncomingCapsules(call, session, piece.data[header..][0..payload_len]);
                pos = header + payload_len;
            },
            0x01 => { // HEADERS: trailers close the request body, so the session is being finished.
                break;
            },
            else => break,
        }
    }

    if (piece.fin) {
        wtCloseSession(call, session, .{ .code = 0, .message = "", .reason = .peer_fin });
    }
}

/// Apply the capsules one CONNECT-stream DATA frame carried (4.7 / 5.6 / 6).
fn wtIncomingCapsules(call: *WtCall, session: *wt.Session, payload: []const u8) void {
    const outcome = session.capsules.feed(payload, WtCapsuleVisit.visit, WtCapsuleVisit{ .call = call, .session = session });

    if (outcome.refused) {
        wtFailSession(call, session, .flow_control_error, wt_draft.error_code.wt_flow_control_error);
    }
}

/// The capsule visitor's context: the call it belongs to, and the session the capsule applies to.
const WtCapsuleVisit = struct {
    call: *WtCall,
    session: *wt.Session,

    /// Apply one capsule this binding defines to its session. Returns false when the capsule broke a rule
    /// the session has to fail on (5.6.2 / 5.6.4).
    fn visit(self: WtCapsuleVisit, capsule_value: wt_capsule.Capsule) bool {
        const call = self.call;
        const session = self.session;

        switch (capsule_value.type) {
            wt_draft.capsule.close_session => {
                const closed = wt_capsule.parseCloseSession(capsule_value.value) catch {
                    wtFailSession(call, session, .protocol_error, @intFromEnum(h3.Http3Error.message_error));

                    return false;
                };
                wtCloseSession(call, session, .{ .code = closed.code, .message = closed.message, .reason = .peer_close });

                return false;
            },
            wt_draft.capsule.drain_session => {
                session.onDrain();

                return true;
            },
            wt_draft.capsule.max_data => {
                const value = wt_capsule.parseFlowControl(capsule_value.value) catch return false;
                session.flow.onMaxData(value) catch return false;

                return true;
            },
            wt_draft.capsule.max_streams_bidi => {
                const value = wt_capsule.parseStreamCount(capsule_value.value) catch return false;
                session.flow.onMaxStreams(.bidi, value) catch return false;

                return true;
            },
            wt_draft.capsule.max_streams_uni => {
                const value = wt_capsule.parseStreamCount(capsule_value.value) catch return false;
                session.flow.onMaxStreams(.uni, value) catch return false;

                return true;
            },
            // WT_DATA_BLOCKED and WT_STREAMS_BLOCKED are reports the peer is blocked: this endpoint answers
            // them by extending its own limits, which it does anyway as it consumes what arrives (5.6.3).
            wt_draft.capsule.data_blocked, wt_draft.capsule.streams_blocked_bidi, wt_draft.capsule.streams_blocked_uni => return true,
            else => return true,
        }
    }
};

/// Hold a data stream's first bytes until its session exists (4.6). Past the buffer limit the stream is
/// rejected with WT_BUFFERED_STREAM_REJECTED, which is what stops a peer from parking streams on a
/// connection that will never establish their session.
fn wtBufferOrphan(call: *WtCall, stream_id: u64, kind: wt_stream_header.Kind, session_id: u64, data: []const u8, fin: bool) void {
    _ = call.pool.bufferOrphan(session_id, stream_id, kind, data, fin) orelse {
        wtResetStreamForSession(call, stream_id, kind, session_id, wt_draft.error_code.wt_buffered_stream_rejected);
    };
}

/// Deliver everything buffered for a session that has just been established.
fn wtReplayOrphans(call: *WtCall, session: *wt.Session) void {
    call.pool.drainOrphans(session.id, wtReplayOrphan, WtReplay{ .call = call, .session = session });
}

/// The replay visitor: one buffered stream's bytes, delivered as if they had just arrived.
const WtReplay = struct {
    call: *WtCall,
    session: *wt.Session,

    fn visit(self: WtReplay, orphan: *wt_pool.Orphan) void {
        // The buffered bytes are the stream's own start, so the header is already in them and the payload
        // begins after it. A header that never completed cannot be replayed and is dropped.
        const header = wt_stream_header.parse(orphan.kind, orphan.buf[0..orphan.len]) catch return;

        wtDeliverData(self.call, orphan.kind, orphan.session_id, header.len, orphan.stream_id, 0, orphan.fin, orphan.buf[0..orphan.len]);
    }
};

fn wtReplayOrphan(context: WtReplay, orphan: *wt_pool.Orphan) void {
    context.visit(orphan);
}

/// End a session: report it to the application, reset every stream it owns with WT_SESSION_GONE (6), and
/// give the slots back to the pool.
fn wtCloseSession(call: *WtCall, session: *wt.Session, info: wt.CloseInfo) void {
    if (!session.isOpen()) return;

    session.close_(info);

    // A clean end of this endpoint's side of the CONNECT stream is a FIN, whatever ended the session: a
    // peer that reset the stream or sent a close capsule still sees this side finished, and the FIN is
    // what carries any close capsule this endpoint queued (6).
    session.connect.send.fin = true;

    // 6: every stream of the session is reset (both directions) with WT_SESSION_GONE, so the peer learns
    // the streams are gone rather than waiting on them.
    while (session.streams) |live| {
        _ = session.detachStream(live);
        call.conn.wt.detachStream(live);

        if (!live.recv.stopped) {
            live.recv.stopped = true;
            var stop_buf: [24]u8 = undefined;
            var stop_pos: usize = 0;
            stop_buf[stop_pos] = 0x05;
            stop_pos += 1;
            stop_pos += varint.write(stop_buf[stop_pos..], live.id);
            stop_pos += varint.write(stop_buf[stop_pos..], wt_draft.error_code.wt_session_gone);
            WtCall.sendControlPacket(call, stop_buf[0..stop_pos]);
        }

        if (live.send.open and live.send.reset == null) {
            live.resetSend(0);
            sendStreamReset(call, live, wt_draft.error_code.wt_session_gone);
            live.send.reset.?.sent = true;
        }

        call.pool.releaseStream(live);
    }

    if (call.config.webtransport.handler.on_close) |on_close| {
        var view = Webtransport.Session{ .inner = session, .driver = call.driverPtr() };
        on_close(&view);
    }

    _ = call.pool.dropOrphans(session.id);
    call.conn.wt.detachSession(session);
    call.pool.releaseSession(session);
}

/// Fail a session: close it with the error code the rule that was broken maps to (5.6.2 / 5.6.4), which
/// the CONNECT stream carries to the peer.
fn wtFailSession(call: *WtCall, session: *wt.Session, reason: wt.CloseReason, code: u64) void {
    if (!session.isOpen()) return;

    // A session error travels as a reset of the CONNECT stream carrying the error code: that is what ends
    // the session for the peer, and it is the code a client prints (5.6.2 / 5.6.4 / 6).
    var buf: [24]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0x04; // RESET_STREAM
    pos += 1;
    pos += varint.write(buf[pos..], session.id);
    pos += varint.write(buf[pos..], code);
    pos += varint.write(buf[pos..], session.connect.send.high_water);
    WtCall.sendControlPacket(call, buf[0..pos]);

    wtCloseSession(call, session, .{ .code = 0, .message = "", .reason = reason });
}

/// Retire a stream whose two halves are both finished: its slot goes back to the pool, so a long-lived
/// session does not leak a slot per stream it ever used.
fn wtRetireIfDone(call: *WtCall, session: *wt.Session, live: *wt.Stream) void {

    // A client-opened bidirectional stream the application never wrote to is finished on the send side as
    // soon as its receive side ends: without that FIN the stream would stay half-open forever.
    if (live.initiator == .client and live.send.open and live.send.queued == 0 and !live.send.fin and live.recv.fin) {
        live.send.fin = true;
    }

    if (!live.finished()) return;

    // The stream may still owe the peer bytes (a FIN or a reset not yet acknowledged), in which case the
    // pump keeps it and this waits: only a fully acknowledged stream is retired.
    if (!live.sendFinished() and live.send.open) return;

    wtRetireStream(call, session, live);
}

/// Give a stream's slot back: detached from both tables first, so nothing can reach a released slot.
fn wtRetireStream(call: *WtCall, session: *wt.Session, live: *wt.Stream) void {
    _ = session.detachStream(live);
    call.conn.wt.detachStream(live);
    call.pool.releaseStream(live);
}

/// Reset a stream that belongs to no session, or to a closed one: the code is the HTTP/3 error the peer
/// sees, and the stream is not tracked (there is nothing to track it against).
fn wtResetStreamForSession(call: *WtCall, stream_id: u64, kind: wt_stream_header.Kind, session_id: u64, code: u64) void {
    _ = kind;
    _ = session_id;

    var buf: [48]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0x04;
    pos += 1;
    pos += varint.write(buf[pos..], stream_id);
    pos += varint.write(buf[pos..], code);
    pos += varint.write(buf[pos..], 0);
    WtCall.sendControlPacket(call, buf[0..pos]);
}

/// Pump every WebTransport stream this connection holds: the CONNECT stream of each session, and every
/// data stream with bytes to send. Runs after the HTTP response pump, so a packet carries both.
fn pumpWebtransport(conn: *Connection, tx: *datagram.SendBatch, fd: std.posix.socket_t, peer: std.posix.sockaddr.in6, config: Http3ServerConfig) void {
    if (!config.webtransport.enabled) return;

    var ack_pending: ?u64 = null;
    var max_streams_pending: ?u64 = null;
    var max_data_pending: ?u64 = null;

    for (conn.wt.sessions) |entry| {
        const session = entry orelse continue;

        // The CONNECT stream: the response head, then capsules, then the FIN that ends the session. A
        // closed session still pumps this stream, because its close capsule and FIN are what the peer
        // reads as the end of the session (6).
        if (session.connect.send.queued != 0 or session.connect.send.fin or session.connect.send.outstanding_len != 0) {
            pumpWtStream(conn, &session.connect, tx, fd, peer, &ack_pending, &max_streams_pending, &max_data_pending, config);
        }
    }

    var index: usize = 0;
    while (index < conn.wt.streams.len) : (index += 1) {
        const live = conn.wt.streams[index] orelse continue;

        pumpWtStream(conn, live, tx, fd, peer, &ack_pending, &max_streams_pending, &max_data_pending, config);
    }

    // A session whose CONNECT stream is fully acknowledged has nothing left to say: its slot goes back to
    // the pool here, which is the one place a closed session is reaped after its close capsule went out.
    if (conn.wt.pool) |pool| {
        for (&conn.wt.sessions) |*entry| {
            const session = entry.* orelse continue;
            if (session.state != .closed) continue;
            if (!session.connect.sendFinished()) continue;
            if (session.streams != null) continue;

            entry.* = null;
            _ = pool.dropOrphans(session.id);
            pool.releaseSession(session);
        }
    }
}

/// Send as much of one WebTransport stream as flow control and the congestion window permit. The stream's
/// bytes are already in its own buffer (the header was queued when it opened), so this only frames them.
fn pumpWtStream(conn: *Connection, live: *wt.Stream, tx: *datagram.SendBatch, fd: std.posix.socket_t, peer: std.posix.sockaddr.in6, ack_pending: *?u64, max_streams_pending: *?u64, max_data_pending: *?u64, config: Http3ServerConfig) void {
    const session = conn.wt.findSession(live.session_id);
    const end = live.send.acked + live.send.queued;

    // The session data limit applies to Stream Body bytes only (5.4): a CONNECT stream's capsules are
    // excluded, and a data stream's header was charged by the opening write, so what is left is the
    // payload this stream still has to send.
    const is_connect_stream = if (session) |open_session| live.id == open_session.id else false;
    var limit = end;
    if (!is_connect_stream) {
        if (session) |open_session| {
            if (open_session.flow.enabled) {
                const remaining = open_session.flow.peer_max_data -| open_session.flow.data_sent;
                limit = @min(end, live.send.sent + remaining);
            }
        }
    }

    limit = @min(limit, live.send.limit);

    if (limit <= live.send.sent) return;

    const dgram: usize = @intCast(conn.sendDatagramSize(config.max_datagram_size, max_send_datagram_size));
    const chunk_budget = dgram - per_packet_frame_reserve;

    var payload: [max_send_datagram_size]u8 = undefined;
    while (live.send.sent < limit) {
        const ready = live.sendable();
        if (ready == 0) break;

        const chunk = @min(chunk_budget, ready);
        const is_last = live.send.fin and (live.send.sent + chunk == end);

        var pos: usize = 0;
        if (ackTake(ack_pending)) |largest| pos += response.buildAck(payload[pos..], largest);
        if (maxStreamsTake(max_streams_pending)) |granted| pos += response.buildMaxStreams(payload[pos..], granted);
        if (maxDataTake(max_data_pending)) |granted| pos += response.buildMaxData(payload[pos..], granted);

        // STREAM frame: type OFF | LEN (| FIN), id, offset, length, then the bytes.
        payload[pos] = 0x0e | @as(u8, if (is_last) 0x01 else 0x00);
        pos += 1;
        pos += varint.write(payload[pos..], live.id);
        pos += varint.write(payload[pos..], live.send.sent);
        pos += varint.write(payload[pos..], chunk);

        const from = @as(usize, @intCast(live.send.sent - live.send.acked));
        @memcpy(payload[pos..][0..chunk], live.buf[from..][0..chunk]);
        pos += chunk;

        sealAndQueue(conn, tx, fd, peer, payload[0..pos], .{
            .stream_id = live.id,
            .offset = @intCast(live.send.sent),
            .length = @intCast(chunk),
        });

        live.onSent(chunk);
        if (!is_connect_stream) {
            if (session) |open_session| open_session.flow.onDataSent(chunk);
        }
    }
}

/// Build and send the HTTP/3 responses for the 1-RTT payload captured on the connection. A connection
/// multiplexes many requests, each on its own client bidi stream, and one packet can coalesce several:
/// a small response goes out in one packet, a large one is registered as a send stream and fragmented
/// across packets within the client's flow control, resumed as MAX_STREAM_DATA / MAX_DATA arrive. A
/// packet carrying no work is acknowledged so the client stops retransmitting.
/// Requests served on this worker thread (skew counter). Owned by the worker
/// (threadlocal, plain increment, no contention), read and reported through the
/// system logger at worker exit so REUSEPORT skew across workers is measurable.
pub threadlocal var tl_requests_served: u64 = 0;

/// Record one served request, when a logger is attached.
///
/// Note:
/// - QUIC keeps its peer on the connection, so the client is named from there rather than from a
///   socket. This Request carries no proxy headers, so there is nothing to prefer over the real
///   peer, and no user agent or origin to report.
/// - Called where the status and the body length are both known, which is straight after the
///   handler returns and before the response is framed into packets.
fn writeAccessRecord(
    config: Http3ServerConfig,
    req: *const core.Request,
    res: *const core.Response,
    peer: std.posix.sockaddr.in6,
) void {
    const logger = config.logger orelse return;

    var peer_buf: [peer_addr.MAX_LEN]u8 = undefined;
    logger.access(
        "http3",
        req.method,
        req.path,
        res.status,
        res.body.len,
        peer_addr.hostFromIn6(peer, &peer_buf),
        "",
        "",
    );
}

fn sendResponseFD(handler: core.HandlerFn, table: *ConnTable, pool: *reassembly.Pool, wt_pool_ptr: ?*wt_pool.Pool, data: []const u8, tx: *datagram.SendBatch, fd: std.posix.socket_t, peer: std.posix.sockaddr.in6, cid_len: usize, config: Http3ServerConfig, stats: ?*WorkerStats) void {
    if (data.len < 1 + cid_len) return;

    const dcid = demux.ConnId.fromSlice(data[1 .. 1 + cid_len]);
    const conn = findConn(table, &dcid) orelse return;
    if (!conn.app_ready) return;

    // Stamp liveness for the maintenance sweep: the peer address so a timer-driven retransmit has a
    // destination, and the activity time so a live connection is never evicted as idle.
    conn.peer_addr = peer;
    conn.last_activity_us = recovery.nowUs();

    const payload_view = conn.app_payload_buf[0..conn.app_payload_len];

    // The honest ACK (with ranges) is built in the prologue below from conn.ack. The pump carries none.
    var ack_pending: ?u64 = null;

    var pieces: [request.max_requests_per_packet]request.StreamPiece = undefined;
    const count = request.parseStreamPieces(payload_view, &pieces);

    // Extend the client's request-stream credit before it runs out (RFC 9000 4.6): find the highest
    // bidi request stream this packet opened and decide whether a MAX_STREAMS must ride a reply. Without
    // it the connection stalls at the one-time handshake allowance. Rides the first reply, like the ACK.
    var highest_bidi_id: ?u64 = null;
    for (pieces[0..count]) |piece| {
        if (piece.stream_id % 4 != 0) continue;
        if (highest_bidi_id == null or piece.stream_id > highest_bidi_id.?) highest_bidi_id = piece.stream_id;
    }
    var max_streams_pending: ?u64 = if (highest_bidi_id) |hid| conn.replenishBidiStreams(hid, config.max_streams) else null;

    // Extend the client's connection-wide byte credit the same way (RFC 9000 4.1): charge the stream
    // bytes this packet carried and decide whether a MAX_DATA must ride a reply. Without it the
    // connection deadlocks at the one-time initial_max_data budget (~1 MiB of requests) with the
    // client's last in-flight requests never answered, whatever MAX_STREAMS still allows.
    const stream_bytes = request.streamBytes(payload_view);
    var max_data_pending: ?u64 = if (stream_bytes != 0) conn.replenishMaxData(stream_bytes, flight.initial_max_data) else null;

    // Apply the client's ACKs first: retire acknowledged ranges, grow the window, rewind any lost stream
    // for retransmit, and free the slot of any stream this ACK fully retires. Done before the
    // registration loop so a request riding the same datagram as the finishing ACK finds the freed slot
    // (stream credit, MAX_DATA / MAX_STREAM_DATA, is applied after registration).
    applyAcks(conn, payload_view);

    // Coalesce small responses into one 1-RTT packet: pack each response's STREAM frame back to back,
    // sealing once per packet instead of once per response. A recv datagram carries many requests, so
    // baseline collapses dozens of AEAD seals and short headers into one. Large bodies still register a
    // send stream the pump fragments below.
    var pbuf: [COALESCE_PAYLOAD_MAX]u8 = undefined;
    var plen: usize = 0;

    // Prologue on the first packet: the ACK, the connection's one-time HANDSHAKE_DONE and server
    // control SETTINGS, and a due MAX_STREAMS. Consumed here so the pump and the seal below do not
    // repeat them. If this datagram carried no request, the prologue alone is the bare-ACK packet.
    if (conn.ack.have_largest) plen += response.buildAckRanges(pbuf[plen..], conn.ack.largest_pn, conn.ack.received_mask);
    if (!conn.first_response_sent) {
        plen += buildConnectionPrologue(pbuf[plen..], config, conn.takeServerStreamId(.uni));
        conn.first_response_sent = true;
    }
    if (maxStreamsTake(&max_streams_pending)) |granted| plen += response.buildMaxStreams(pbuf[plen..], granted);
    if (maxDataTake(&max_data_pending)) |granted| plen += response.buildMaxData(pbuf[plen..], granted);

    // WebTransport first: the pass claims every stream whose bytes are not an HTTP request (a session's
    // CONNECT stream, a WebTransport data stream), and the loop below skips them. A stream it holds for a
    // session that does not exist yet is claimed too, so the request path never answers a stream that is
    // waiting for its session.
    var claims = WtClaims{};
    if (wt_pool_ptr) |wt_pool_handle| {
        if (config.webtransport.enabled) webtransportIncoming(conn, wt_pool_handle, pool, payload_view, tx, fd, peer, config, &claims);
    }

    for (pieces[0..count]) |piece| {
        if (claims.has(piece.stream_id)) continue;

        // A retransmit of a request already being streamed: leave its progress, the pump continues it.
        if (conn.findSendStream(piece.stream_id) != null) continue;

        // A request the client has not finished is held until it does, so the handler runs once and
        // runs with the whole body. `held` is the reassembly slot to give back once it is served.
        var held: ?*reassembly.PendingStream = null;
        defer if (held) |slot| pool.release(slot);

        var content: [1024]u8 = undefined;
        var ae_scratch: [128]u8 = undefined;

        const decoded = switch (takeReadyRequest(pool, conn.last_activity_us, &conn.dcid, piece, &held)) {
            .serve => |ready| ready,
            .hold => |pending| {
                // A held request has no reply to ride, so its client's stream credit has to be
                // extended here or not at all. Without it an upload larger than the handshake
                // allowance stops: the client waits for credit, the engine waits for the rest of the
                // request, and nothing times out short of the idle timeout.
                if (pending) |slot| {
                    if (slot.replenishStreamData(flight.initial_max_stream_data)) |granted| {
                        plen += response.buildMaxStreamData(pbuf[plen..], piece.stream_id, granted);
                    }
                }

                continue;
            },
            .overloaded => |head| {
                // Every slot is busy with a request still arriving, so this one cannot be assembled.
                // It is answered rather than left hanging, and answered 503 rather than run against a
                // body that is still on its way: a wrong number is the failure this whole path exists
                // to prevent. Raise max_pending_request_streams if this shows up under normal load.
                const overload_len = response.buildRequestStreamContent(&content, 503, .identity, "") orelse continue;

                const overload_req = buildRequest(conn, &ae_scratch, head);
                writeAccessRecord(config, &overload_req, &core.Response{ .status = 503 }, conn.peer_addr);
                tl_requests_served += 1;

                packStreamFrame(conn, tx, fd, peer, &pbuf, &plen, piece.stream_id, content[0..overload_len]);

                continue;
            },
        };

        // A WebTransport session request is not an HTTP request: an extended CONNECT opens a session
        // instead of being answered (RFC 9220, draft-ietf-webtrans-http3 3.2). The packet-level pass
        // handles the ones it can decode on arrival; this is the path for a CONNECT whose header block
        // had to be assembled first. Without it the request path answers the CONNECT and the session is
        // never created.
        if (config.webtransport.enabled) {
            if (wt_pool_ptr) |wt_pool_handle| {
                if (wtIsWebtransportConnect(decoded)) {
                    webtransportAcceptAssembled(conn, wt_pool_handle, pool, tx, fd, peer, config, piece, decoded);

                    continue;
                }
            }
        }

        var req = buildRequest(conn, &ae_scratch, decoded);
        var res = core.Response{};
        const deadline_ns: ?u64 = if (config.handler_timeout_ms == 0)
            null
        else
            core.wallClockNs() + @as(u64, config.handler_timeout_ms) * std.time.ns_per_ms;
        // A static response keeps its cache slot pinned past the handler, because its body has to
        // stay readable for every packet and every retransmission below. Whoever finishes with the
        // body releases it: the send stream when it retires, or this loop for a body that was
        // already copied into a packet.
        const static_slot = core.invokeHandler(handler, &req, &res, piece.stream_id, config.io, deadline_ns, config.public_dir);
        tl_requests_served += 1;

        writeAccessRecord(config, &req, &res, conn.peer_addr);

        const content_len = response.buildRequestStreamContent(&content, res.status, res.content_encoding, res.body) orelse {
            // A body too large for one packet: register a send stream the pump fragments within flow
            // control, or answer 500 (packed like a small response) when no slot is free.
            if (conn.reserveSendStream(piece.stream_id)) |slot| {
                slot.* = .{
                    .active = true,
                    .stream_id = piece.stream_id,
                    .status = res.status,
                    .body = res.body,
                    .content_encoding = res.content_encoding,
                    .content_len = streamContentLen(res.status, res.content_encoding, res.body),
                    .sent = 0,
                    .stream_limit = conn.client_max_stream_data,
                    .static_slot = static_slot,
                };
            } else {
                // No slot, so the body is never sent and nothing will retire it later.
                static.releasePin(static_slot);

                const five = response.buildRequestStreamContent(&content, 500, .identity, "") orelse continue;
                packStreamFrame(conn, tx, fd, peer, &pbuf, &plen, piece.stream_id, content[0..five]);
            }
            continue;
        };

        // The whole response fitted one packet, so the body is already copied into `content` and the
        // pin has done its job.
        static.releasePin(static_slot);

        packStreamFrame(conn, tx, fd, peer, &pbuf, &plen, piece.stream_id, content[0..content_len]);
    }

    // Apply this packet's flow-control credit after registering requests, so a MAX_STREAM_DATA that
    // rides the same packet as the request it unblocks lands on the just-registered stream. The ACKs in
    // this payload were already applied above (applyAcks), before the slots were reserved.
    applyStreamCredit(conn, payload_view, stats);

    // Seal the coalesced response packet (prologue plus packed small responses), before the pump so the
    // client sees the ACK and HANDSHAKE_DONE first.
    if (plen > 0) sealAndQueue(conn, tx, fd, peer, pbuf[0..plen], null);

    // Pump every active large stream. The ACK, MAX_STREAMS, and MAX_DATA were consumed into the
    // coalesced packet, so the pending slots are null here, the pump carries only stream data. The
    // worker loop flushes the SendBatch once per recv batch, so this call leaves replies queued, not
    // flushed.
    for (&conn.send_streams) |*stream| {
        if (stream.active) _ = pumpStream(conn, stream, tx, fd, peer, &ack_pending, &max_streams_pending, &max_data_pending, config, stats);
    }

    // WebTransport streams last: they are pumped from their own buffers, with the same congestion window,
    // loss ring, and flow control as the HTTP response streams above.
    pumpWebtransport(conn, tx, fd, peer, config);
}

/// Append a response STREAM frame (with FIN) to the coalesced packet, sealing the full packet and
/// starting a fresh one when the frame no longer fits. A single response always fits an empty packet
/// (its content is capped below the budget), so the retry cannot loop.
fn packStreamFrame(conn: *Connection, tx: *datagram.SendBatch, fd: std.posix.socket_t, peer: std.posix.sockaddr.in6, pbuf: []u8, plen: *usize, stream_id: u64, content: []const u8) void {
    if (response.writeStreamFrame(pbuf, plen, stream_id, true, content)) return;

    sealAndQueue(conn, tx, fd, peer, pbuf[0..plen.*], null);
    plen.* = 0;
    _ = response.writeStreamFrame(pbuf, plen, stream_id, true, content);
}

// --------------------------------------------------------------- //

/// How often a worker runs the maintenance sweep (RFC 9002 6.2 loss recovery when no ACK arrives, plus
/// RFC 9000 10.1 idle eviction), in microseconds. Coarse on purpose: a Probe Timeout is an RTT plus
/// backoff (many milliseconds) and idle eviction is on the order of seconds, so a sweep every few
/// milliseconds recovers a lost tail promptly while its cost (one scan of the per-worker connection
/// table) stays negligible against the datagram rate. A worker arms this wake only while it owns at
/// least one connection, so a fully idle worker still parks indefinitely and stays off the CPU.
pub const maintenance_interval_us: u64 = 5_000;

/// Resume every active send stream on `conn` after a Probe Timeout rewound them, queuing the packets into
/// `tx` for the caller to flush. A pure retransmit carries only stream data, so it takes no pending ACK,
/// MAX_STREAMS, or MAX_DATA (those ride a fresh request's reply). The peer address comes from the
/// connection (conn.peer_addr): a timer-driven resend has no incoming datagram to carry it.
fn resumeStreams(conn: *Connection, tx: *datagram.SendBatch, fd: std.posix.socket_t, config: Http3ServerConfig, stats: ?*WorkerStats) void {
    var ack_pending: ?u64 = null;
    var max_streams_pending: ?u64 = null;
    var max_data_pending: ?u64 = null;

    for (&conn.send_streams) |*stream| {
        if (stream.active) _ = pumpStream(conn, stream, tx, fd, conn.peer_addr, &ack_pending, &max_streams_pending, &max_data_pending, config, stats);
    }
}

/// Run one time-driven maintenance pass over every live connection this worker owns (shared by the epoll
/// and io_uring workers, each calling it at most once per maintenance_interval_us). For each connection:
/// retransmit a flight whose Probe Timeout fired (the tail-loss recovery an ack-clocked path cannot do on
/// its own, RFC 9002 6.2), and evict one whose peer has gone (RFC 9000 10.1) so its table slot is
/// reclaimed instead of pinned for the worker's life. Without this, a lost tail leaves a connection
/// wedged (bytes stuck in flight, window collapsed) and the slot never frees, which is what collapsed
/// EPOLL static-h3 across bench runs. Leaves retransmitted packets queued in `tx`, the caller flushes.
pub fn sweepMaintenance(comptime handler: core.HandlerFn, table: *ConnTable, wt_pool_ptr: ?*wt_pool.Pool, tx: *datagram.SendBatch, fd: std.posix.socket_t, config: Http3ServerConfig, now_us: u64, stats: ?*WorkerStats) void {
    // The handler is comptime here for the same reason serveDatagram takes it: the WebTransport sessions a
    // dying connection held are reported to the application, which is the only notice it gets.
    _ = handler;

    const max_idle_us: u64 = @as(u64, config.max_idle_ms) * 1000; // ms to us

    for (0..ConnTable.slot_capacity) |slot| {
        const conn = table.at(slot) orelse continue;

        // A WebTransport session can have bytes to send with no incoming packet to carry them (an
        // application that pushes to its client), so the sweep pumps first: the same flush the response
        // path gives an HTTP response, on a time basis instead of a packet basis.
        if (config.webtransport.enabled and conn.wt.sessionCount() != 0) {
            pumpWebtransport(conn, tx, fd, conn.peer_addr, config);
        }

        const result = conn.onMaintenance(now_us, max_idle_us);
        if (result.resend) {
            resumeStreams(conn, tx, fd, config, stats);
            // A Probe Timeout is also the retry for a stream reset that never arrived: the reset frame is
            // not tracked for acknowledgement, so a stream still holding a sent reset is resent here.
            if (config.webtransport.enabled) pumpWebtransportResets(conn, tx, fd);
        }
        if (result.idle) {
            // The connection is going away with whatever it was still sending, so any static cache
            // pin it has to come back now or the entry is pinned for the life of the process.
            conn.releaseAllStaticPins();

            // The WebTransport sessions on it end with it. Their slots go back to the worker pool and the
            // application is told, which is the only notice it gets for a connection that simply went away.
            if (wt_pool_ptr) |wt_pool_handle| {
                if (config.webtransport.enabled) wtReleaseConnection(config, conn, wt_pool_handle);
            }

            _ = table.remove(&conn.dcid);
        }
    }

    if (stats) |st| st.conns = table.count;
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix http3: a client Finished verifies against the client handshake secret and the server-Finished transcript" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

    var conn = Connection.init(&dcid, 1200, 10);
    conn.hs_keys.client_traffic = @splat(0x2b);
    conn.transcript_through_finished = @splat(0x11);

    // Neither nothing nor a prefix of the message counts as a Finished: the handshake must not be
    // confirmed on CRYPTO bytes that are still arriving.
    try std.testing.expectEqual(.incomplete, clientFinishedState(&conn));

    const finished_key = certificate.finishedKey(conn.hs_keys.client_traffic);
    var fin_buf: [64]u8 = undefined;
    const finished = certificate.buildFinished(&fin_buf, finished_key, conn.transcript_through_finished);

    conn.crypto_handshake.insert(0, finished[0 .. finished.len - 1]);
    try std.testing.expectEqual(.incomplete, clientFinishedState(&conn));

    // The whole message verifies, and a second packet does not undo it (a retransmitted Finished, or any
    // later Handshake packet, finds the handshake already complete).
    conn.crypto_handshake.insert(finished.len - 1, finished[finished.len - 1 ..]);
    try std.testing.expectEqual(.verified, clientFinishedState(&conn));
    try std.testing.expectEqual(.verified, clientFinishedState(&conn));

    // The same message against a different transcript does not verify: the check binds the client to the
    // handshake it actually saw, so a peer that holds the secrets but not the transcript cannot pass.
    var other = Connection.init(&dcid, 1200, 10);
    other.hs_keys.client_traffic = conn.hs_keys.client_traffic;
    other.transcript_through_finished = @splat(0x12);
    other.crypto_handshake.insert(0, finished);
    try std.testing.expectEqual(.mismatch, clientFinishedState(&other));
}

test "zix http3: processDatagram demuxes a long-header Initial by DCID" {
    // Heap like the worker loops: the 256-slot table is multi-MB and overflows
    // smaller default test-thread stacks.
    const table = try std.testing.allocator.create(ConnTable);
    defer std.testing.allocator.destroy(table);
    table.* = .{};

    // A crafted Initial long header: 0xc3, version 1, 8-byte DCID, 4-byte SCID, one payload byte.
    const initial = [_]u8{ 0xc3, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x04, 0x11, 0x22, 0x33, 0x44, 0x00 };
    _ = processDatagram(table, &initial, 8, 1200, 10);

    const dcid = demux.ConnId.fromSlice(&[_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 });
    try std.testing.expectEqual(@as(usize, 1), table.count);
    try std.testing.expect(table.find(&dcid) != null);

    // A second datagram for the same connection reuses the slot, not a new one.
    _ = processDatagram(table, &initial, 8, 1200, 10);
    try std.testing.expectEqual(@as(usize, 1), table.count);

    // The anti-amplification budget reflects both received datagrams.
    try std.testing.expectEqual(@as(u64, 40), table.find(&dcid).?.anti_amplification.received);
}

test "zix http3: copyStreamSlice spans the prefix and body boundary" {
    const prefix = "PRE"; // 3 bytes of HTTP/3 prefix
    const body = "0123456789";

    // A slice from offset 1 across the prefix end into the body: "RE0123".
    var dst: [6]u8 = undefined;
    copyStreamSlice(prefix, body, 1, &dst);
    try std.testing.expectEqualStrings("RE0123", &dst);

    // A slice fully inside the body (offset past the prefix).
    var dst2: [4]u8 = undefined;
    copyStreamSlice(prefix, body, 5, &dst2);
    try std.testing.expectEqualStrings("2345", &dst2);
}

test "zix http3: pumpLimit caps the send at the congestion window, the window cap, and flow control" {
    // window_cap here is 128 packets * 1200 = 153600 bytes (the default max_inflight_packets window).
    const cap = 153_600;

    // Nothing in flight, a huge flow-control ceiling: the initial 12000-byte congestion window is the
    // binding cap, so the pump sends the initial window, not the whole body.
    try std.testing.expectEqual(@as(usize, 12_000), pumpLimit(1_000_000, 0, 12_000, 0, cap));

    // Flow control tighter than the window: flow control wins (the client granted only 5000 bytes).
    try std.testing.expectEqual(@as(usize, 5_000), pumpLimit(5_000, 0, 12_000, 0, cap));

    // A congestion window larger than the window cap is clamped to the cap (153600), so an in-flight
    // packet is never overwritten before loss detection can see it.
    try std.testing.expectEqual(@as(usize, 153_600), pumpLimit(1_000_000, 0, 1_000_000, 0, cap));

    // The whole window is already outstanding: the ceiling collapses to the current offset (limit <=
    // sent), which the caller reads as the cwnd-blocked signal and stops until an ACK frees the window.
    try std.testing.expectEqual(@as(usize, 3_000), pumpLimit(1_000_000, 3_000, 12_000, 12_000, cap));

    // Partial room: 4000 of a 12000 window in flight leaves 8000, so from offset 3000 the pump may
    // reach 11000, still under the flow-control ceiling.
    try std.testing.expectEqual(@as(usize, 11_000), pumpLimit(1_000_000, 3_000, 12_000, 4_000, cap));
}

test "zix http3: applyStreamCredit raises the connection and stream limits" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);
    conn.send_streams[0] = .{ .active = true, .stream_id = 0, .stream_limit = 1000 };

    // MAX_DATA (0x10) = 5000 then MAX_STREAM_DATA (0x11) for stream 0 = 9000.
    var stats = WorkerStats{ .worker_id = 0 };
    const payload = [_]u8{ 0x10, 0x53, 0x88, 0x11, 0x00, 0x63, 0x28 };
    applyStreamCredit(&conn, &payload, &stats);

    try std.testing.expectEqual(@as(u64, 5000), conn.client_max_data);
    try std.testing.expectEqual(@as(u64, 9000), conn.send_streams[0].stream_limit);

    // Each credit update is counted for the diagnostic dump (one MAX_DATA, one MAX_STREAM_DATA).
    try std.testing.expectEqual(@as(u64, 1), stats.max_data_recv);
    try std.testing.expectEqual(@as(u64, 1), stats.max_stream_data_recv);

    // A smaller advertisement never lowers an existing limit (RFC 9000 4.1).
    const lower = [_]u8{ 0x11, 0x00, 0x40, 0x64 }; // MAX_STREAM_DATA stream 0 = 100
    applyStreamCredit(&conn, &lower, &stats);
    try std.testing.expectEqual(@as(u64, 9000), conn.send_streams[0].stream_limit);
    try std.testing.expectEqual(@as(u64, 2), stats.max_stream_data_recv);
}

test "zix http3: applyAcks feeds a real ACK frame into Connection.onAckFrame" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);
    conn.recordSentRange(10, recovery.nowUs(), .{ .stream_id = 0, .offset = 0, .length = 100 });

    // ACK (0x02): largest=10, delay=0, range_count=0, first_ack_range=3 -> acks [7, 10].
    const payload = [_]u8{ 0x02, 0x0a, 0x00, 0x00, 0x03 };
    applyAcks(&conn, &payload);

    try std.testing.expect(conn.rtt.has_sample);
    try std.testing.expect(!conn.sent_ranges[0].in_flight);
}

test "zix http3: getAvailableCpuCount returns at least 1" {
    try std.testing.expect(getAvailableCpuCount() >= 1);
}

test "zix http3: effectiveWorkers honors an explicit count and caps at available CPUs" {
    const base = Http3ServerConfig{ .allocator = std.testing.allocator, .io = undefined, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC };

    // an explicit worker count passes through unchanged
    var explicit = base;
    explicit.workers = 3;
    try std.testing.expectEqual(@as(usize, 3), effectiveWorkers(explicit));

    // workers = 0 defaults to the cpuset-aware count, never zero
    try std.testing.expect(effectiveWorkers(base) >= 1);
    try std.testing.expectEqual(getAvailableCpuCount(), effectiveWorkers(base));
}

test "zix http3: pinToCpu is a no-op-safe call for any worker_id" {
    // The process keeps its original affinity mask, so pinning to a derived slot must not crash
    // for an out-of-range worker_id (the modulo keeps it inside the available set).
    pinToCpu(0);
    pinToCpu(999);
}

test "zix http3: ratioParts scales num/den to hundredths and guards a zero denominator" {
    // 3/2 = 1.50, 64/32 = 2.00 (the datagrams-per-wake the stats line reports).
    try std.testing.expectEqual(@as(u64, 1), ratioParts(3, 2).whole);
    try std.testing.expectEqual(@as(u64, 50), ratioParts(3, 2).frac);
    try std.testing.expectEqual(@as(u64, 2), ratioParts(64, 32).whole);
    try std.testing.expectEqual(@as(u64, 0), ratioParts(64, 32).frac);

    // A zero denominator (no wakes yet) reports 0.00 instead of dividing by zero.
    try std.testing.expectEqual(@as(u64, 0), ratioParts(0, 0).whole);
    try std.testing.expectEqual(@as(u64, 0), ratioParts(5, 0).frac);
}

test "zix http3: WorkerStats.maybeDump only reads, never mutates the counters" {
    // A wake count that is not a dump multiple: maybeDump must leave every counter unchanged (it only
    // reads them to format the line). The dump itself is Debug-only and compiled out of Release.
    var stats = WorkerStats{ .worker_id = 0, .wakes = 100, .datagrams = 200 };
    stats.maybeDump();

    try std.testing.expectEqual(@as(u64, 100), stats.wakes);
    try std.testing.expectEqual(@as(u64, 200), stats.datagrams);
}

test "zix http3: WorkerStats.snapshot derives wall, on-CPU time, and utilization percent" {
    // start at 1_000us, sampled at 11_000us -> 10_000us wall, blocked 9_000us -> 1_000us on CPU = 10%.
    const busy = WorkerStats{ .worker_id = 0, .start_us = 1_000, .block_us = 9_000 };
    const snap = busy.snapshot(11_000);
    try std.testing.expectEqual(@as(u64, 10_000), snap.wall_us);
    try std.testing.expectEqual(@as(u64, 1_000), snap.active_us);
    try std.testing.expectEqual(@as(u64, 10), snap.active_pct);

    // Blocked longer than wall (a nowUs pair straddling the sample) saturates to 0 active, never underflows.
    const over = WorkerStats{ .worker_id = 1, .start_us = 1_000, .block_us = 50_000 };
    const snap_over = over.snapshot(11_000);
    try std.testing.expectEqual(@as(u64, 0), snap_over.active_us);
    try std.testing.expectEqual(@as(u64, 0), snap_over.active_pct);

    // Zero wall (never advanced) reports 0 percent instead of dividing by zero.
    const fresh = WorkerStats{ .worker_id = 2, .start_us = 5_000 };
    try std.testing.expectEqual(@as(u64, 0), fresh.snapshot(5_000).active_pct);

    // A worker currently parked (wait_enter_us set) has its in-progress park counted as blocked, not
    // on-CPU: without this a dump taken while every worker idles (SIGTERM after the load stops) would
    // misreport the still-uncommitted parked time as active. Here committed block is 0 but the worker
    // entered the wait at 2_000 and it is now 11_000, so all 9_000us of wall is blocked, 0 active.
    const parked = WorkerStats{ .worker_id = 3, .start_us = 2_000, .block_us = 0, .wait_enter_us = 2_000 };
    const snap_parked = parked.snapshot(11_000);
    try std.testing.expectEqual(@as(u64, 9_000), snap_parked.wall_us);
    try std.testing.expectEqual(@as(u64, 0), snap_parked.active_us);
    try std.testing.expectEqual(@as(u64, 0), snap_parked.active_pct);
}

test "zix http3: registerWorkerStats stamps a start time and adds the worker to the dump registry" {
    const before = g_diag_count.load(.acquire);

    var stats = WorkerStats{ .worker_id = 4242 };
    registerWorkerStats(&stats);

    // The worker now has a monotonic start time and is one more entry in the registry, so a later
    // signal-driven dump reaches it.
    try std.testing.expect(stats.start_us > 0);
    try std.testing.expectEqual(before + 1, g_diag_count.load(.acquire));
    try std.testing.expect(g_diag_stats[before].? == &stats);
}
test "zix http3: orderPhysicalCoresFirst puts distinct cores before SMT siblings" {
    var cpus = [_]u32{ 0, 1, 2, 3, 4, 5 };
    const keys = [_]u64{ 0, 0, 1, 1, 2, 2 };

    orderPhysicalCoresFirst(&cpus, &keys);

    try std.testing.expectEqualSlices(u32, &.{ 0, 2, 4, 1, 3, 5 }, &cpus);
}

test "zix http3: orderPhysicalCoresFirst keeps mask order on unique keys" {
    var cpus = [_]u32{ 3, 7, 11 };
    const keys = [_]u64{ 30, 10, 20 };

    orderPhysicalCoresFirst(&cpus, &keys);

    try std.testing.expectEqualSlices(u32, &.{ 3, 7, 11 }, &cpus);
}

/// One POST on client bidi stream 0, as it arrives in a decrypted 1-RTT payload: a STREAM frame with
/// LEN and FIN (0x0b) holding a 17-byte HEADERS frame (:method POST, :path /baseline2) then a 4-byte
/// DATA frame carrying "20". The body payload sits at offset 22.
const post_payload_hex = "0b0015" ++ "010f" ++ "0000" ++ "d4" ++ "510a" ++ "2f626173656c696e6532" ++ "0002" ++ "3230";

/// The same request with no DATA frame and no end-of-stream bit (0x0a): a bodyless GET the client has
/// not finished, which is what a body still on its way looks like at this layer.
const open_get_payload_hex = "0a0011" ++ "010f" ++ "0000" ++ "d1" ++ "510a" ++ "2f626173656c696e6532";

/// The head of the POST above with the stream left open (0x0a), the first of the two packets a client
/// sends when it writes its headers and its body separately.
const post_head_payload_hex = "0a0011" ++ "010f" ++ "0000" ++ "d4" ++ "510a" ++ "2f626173656c696e6532";

/// The body of that POST: a STREAM frame at offset 17 (0x0f is STREAM | OFF | LEN | FIN) carrying the
/// DATA frame and ending the stream.
const post_body_payload_hex = "0f001104" ++ "0002" ++ "3230";

/// Decode the one request-stream frame a test payload carries.
fn onlyPiece(payload: []const u8) request.StreamPiece {
    var pieces: [2]request.StreamPiece = undefined;

    std.debug.assert(request.parseStreamPieces(payload, &pieces) == 1);

    return pieces[0];
}

/// A pool sized as a worker's would be, for the policy tests below.
fn testPool(streams: usize) !reassembly.Pool {
    return reassembly.Pool.init(std.testing.allocator, streams, reassembly.default_stream_bytes);
}

test "zix http3: takeReadyRequest serves a request that arrived whole without holding it" {
    var payload: [post_payload_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&payload, post_payload_hex);

    var pool = try testPool(reassembly.default_pending_streams);
    defer pool.deinit(std.testing.allocator);

    const cid = demux.ConnId.fromSlice(&[_]u8{ 0x11, 2, 3, 4, 5, 6, 7, 8 });
    var held: ?*reassembly.PendingStream = null;

    const decoded = switch (takeReadyRequest(&pool, 1_000, &cid, onlyPiece(&payload), &held)) {
        .serve => |ready| ready,
        else => return error.TestUnexpectedResult,
    };

    // Served straight from the payload: the fast path takes no reassembly slot, which is what keeps a
    // GET (and a small POST written in one go) as cheap as it was.
    try std.testing.expect(held == null);
    try std.testing.expectEqualSlices(u8, "20", decoded.body);
    try std.testing.expect(decoded.body_complete);
}

test "zix http3: takeReadyRequest holds a request until the client ends its stream" {
    var head: [post_head_payload_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&head, post_head_payload_hex);
    var body: [post_body_payload_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&body, post_body_payload_hex);

    var pool = try testPool(reassembly.default_pending_streams);
    defer pool.deinit(std.testing.allocator);

    const cid = demux.ConnId.fromSlice(&[_]u8{ 0x22, 2, 3, 4, 5, 6, 7, 8 });

    // The head alone answers nothing. Answering it would run the handler with an empty body and leave
    // the real body arriving after the response, which is the defect this holds back.
    var first_held: ?*reassembly.PendingStream = null;
    switch (takeReadyRequest(&pool, 1_000, &cid, onlyPiece(&head), &first_held)) {
        .hold => {},
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(first_held == null);

    // The body completes it, and now the whole request is served in one handler call.
    var held: ?*reassembly.PendingStream = null;
    defer if (held) |slot| pool.release(slot);

    const decoded = switch (takeReadyRequest(&pool, 1_100, &cid, onlyPiece(&body), &held)) {
        .serve => |ready| ready,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expect(held != null);
    try std.testing.expectEqualSlices(u8, "POST", decoded.method);
    try std.testing.expectEqualSlices(u8, "/baseline2", decoded.path);
    try std.testing.expectEqualSlices(u8, "20", decoded.body);
    try std.testing.expectEqual(@as(u64, 2), decoded.body_received);
    try std.testing.expect(decoded.body_complete);
}

test "zix http3: a held request hands back the slot its client's credit is extended from" {
    // The serve loop has no reply to attach a MAX_STREAM_DATA to while a request is still arriving,
    // so the hold carries the slot it is arriving into. Without that the loop cannot grant credit and
    // an upload past the handshake allowance stops halfway, unanswered.
    var head: [post_head_payload_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&head, post_head_payload_hex);

    var pool = try testPool(reassembly.default_pending_streams);
    defer pool.deinit(std.testing.allocator);

    const cid = demux.ConnId.fromSlice(&[_]u8{ 0x77, 2, 3, 4, 5, 6, 7, 8 });
    var held: ?*reassembly.PendingStream = null;

    const pending = switch (takeReadyRequest(&pool, 1_000, &cid, onlyPiece(&head), &held)) {
        .hold => |slot| slot,
        else => return error.TestUnexpectedResult,
    };

    const slot = pending orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, head.len - 3), slot.reached); // the STREAM frame header is not stream data

    // A window this stream has already eaten into: the grant moves out past where it has reached.
    try std.testing.expect(slot.replenishStreamData(16).? > slot.reached);
}

test "zix http3: takeReadyRequest calls a request overloaded rather than running it half-arrived" {
    // A pool with no room at all, which is what a worker whose slots are all busy looks like to the
    // next request head. The old behaviour handed the handler what had arrived, so a POST answered
    // from an empty body: a wrong number, silently. The loop answers 503 on this instead.
    var head: [post_head_payload_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&head, post_head_payload_hex);

    var pool = try testPool(0);
    defer pool.deinit(std.testing.allocator);

    const cid = demux.ConnId.fromSlice(&[_]u8{ 0x33, 2, 3, 4, 5, 6, 7, 8 });
    var held: ?*reassembly.PendingStream = null;

    // The head it refused travels with the refusal, so the 503 is still logged as the request it was.
    switch (takeReadyRequest(&pool, 1_000, &cid, onlyPiece(&head), &held)) {
        .overloaded => |refused| try std.testing.expectEqualSlices(u8, "POST", refused.method),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(held == null);
}

test "zix http3: takeReadyRequest drops a refused frame that carries no request of its own" {
    // Body-only bytes for a stream the pool is not holding. There is no request here to answer, and
    // the frame is as likely to be a retransmit of one already answered, so a 503 would contradict a
    // 200 the client already has.
    var body: [post_body_payload_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&body, post_body_payload_hex);

    var pool = try testPool(0);
    defer pool.deinit(std.testing.allocator);

    const cid = demux.ConnId.fromSlice(&[_]u8{ 0x44, 2, 3, 4, 5, 6, 7, 8 });
    var held: ?*reassembly.PendingStream = null;

    switch (takeReadyRequest(&pool, 1_000, &cid, onlyPiece(&body), &held)) {
        .hold => {},
        else => return error.TestUnexpectedResult,
    }
}

test "zix http3: takeReadyRequest serves a whole request while the pool holds nothing" {
    // The GET fast path with reassembly configured off entirely: a request that arrived whole never
    // reaches the pool, so turning the pool off costs a bodyless request nothing.
    var payload: [post_payload_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&payload, post_payload_hex);

    var pool = try testPool(0);
    defer pool.deinit(std.testing.allocator);

    const cid = demux.ConnId.fromSlice(&[_]u8{ 0x55, 2, 3, 4, 5, 6, 7, 8 });
    var held: ?*reassembly.PendingStream = null;

    const decoded = switch (takeReadyRequest(&pool, 1_000, &cid, onlyPiece(&payload), &held)) {
        .serve => |ready| ready,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expect(held == null);
    try std.testing.expect(decoded.body_complete);
}

test "zix http3: takeReadyRequest carries a raised stream size into what a handler is given whole" {
    // The same two-packet request against a pool sized well past the body: what the config knob buys
    // is that the handler is handed the whole thing instead of the front of it.
    var head: [post_head_payload_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&head, post_head_payload_hex);
    var body: [post_body_payload_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&body, post_body_payload_hex);

    var pool = try reassembly.Pool.init(std.testing.allocator, 1, 64 * 1024);
    defer pool.deinit(std.testing.allocator);

    const cid = demux.ConnId.fromSlice(&[_]u8{ 0x66, 2, 3, 4, 5, 6, 7, 8 });

    var first_held: ?*reassembly.PendingStream = null;
    _ = takeReadyRequest(&pool, 1_000, &cid, onlyPiece(&head), &first_held);

    var held: ?*reassembly.PendingStream = null;
    defer if (held) |slot| pool.release(slot);

    const decoded = switch (takeReadyRequest(&pool, 1_100, &cid, onlyPiece(&body), &held)) {
        .serve => |ready| ready,
        else => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqualSlices(u8, "20", decoded.body);
    try std.testing.expect(decoded.body_complete);
}

test "zix http3: buildRequest hands the decoded body and its counts to the handler Request" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    var payload: [post_payload_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&payload, post_payload_hex);

    var reqs: [2]request.StreamRequest = undefined;
    try std.testing.expectEqual(@as(usize, 1), request.parseRequests(&payload, &reqs));

    var ae_scratch: [128]u8 = undefined;
    const req = buildRequest(&conn, &ae_scratch, reqs[0].request);

    try std.testing.expectEqualSlices(u8, "POST", req.method);
    try std.testing.expectEqualSlices(u8, "/baseline2", req.path);
    try std.testing.expectEqualSlices(u8, "20", req.body);
    try std.testing.expectEqual(@as(u64, 2), req.bodyReceived());
    try std.testing.expect(req.bodyComplete());

    // The body borrows the payload rather than being copied out of it, so it costs the engine nothing
    // and lives exactly as long as the method and the path do.
    try std.testing.expect(req.body.ptr == payload[22..].ptr);
}

test "zix http3: buildRequest reports a bodyless request the client has not ended as incomplete" {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    var conn = Connection.init(&dcid, 1200, 10);

    var payload: [open_get_payload_hex.len / 2]u8 = undefined;
    _ = try std.fmt.hexToBytes(&payload, open_get_payload_hex);

    var reqs: [2]request.StreamRequest = undefined;
    try std.testing.expectEqual(@as(usize, 1), request.parseRequests(&payload, &reqs));

    var ae_scratch: [128]u8 = undefined;
    const req = buildRequest(&conn, &ae_scratch, reqs[0].request);

    // Nothing arrived, and the stream is still open, so a handler must not read the emptiness as
    // "the client sent no body".
    try std.testing.expectEqual(@as(usize, 0), req.body.len);
    try std.testing.expectEqual(@as(u64, 0), req.bodyReceived());
    try std.testing.expect(!req.bodyComplete());
}

test "zix http3: a served request writes one access record naming the engine and the QUIC peer" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    const config = Http3ServerConfig{ .allocator = std.testing.allocator, .io = std.testing.io, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC, .logger = &logger };
    const req = core.Request{ .method = "GET", .path = "/assets/app.js" };
    const res = core.Response{ .status = 200, .body = "console.log(1)" };

    // An IPv4 client on the dual-stack QUIC socket, as the connection stores it.
    var peer = std.mem.zeroes(std.posix.sockaddr.in6);
    peer.addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 7 };

    writeAccessRecord(config, &req, &res, peer);
    logger.flush();

    const line = try readAccessLine(tmp.dir, std.testing.allocator);
    defer std.testing.allocator.free(line);

    std.log.info(".ACCESS: {s}", .{std.mem.trimEnd(u8, line, "\n")});

    try std.testing.expect(std.mem.indexOf(u8, line, "[http3:access] GET /assets/app.js 200 14 \"203.0.113.7\" \"-\" \"-\"") != null);
}

test "zix http3: an errored request records its status and empty body" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();

    var root_buf: [64]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buf, ".zig-cache/tmp/{s}", .{tmp.sub_path});

    var logger = try Logger.init(std.testing.allocator, .{ .console = .OFF, .save_path = root, .save_min_level = .DEBUG });
    defer logger.deinit();

    const config = Http3ServerConfig{ .allocator = std.testing.allocator, .io = std.testing.io, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC, .logger = &logger };
    const req = core.Request{ .method = "GET", .path = "/missing" };
    const res = core.Response{ .status = 404, .body = "" };

    var peer = std.mem.zeroes(std.posix.sockaddr.in6);
    peer.addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    writeAccessRecord(config, &req, &res, peer);
    logger.flush();

    const line = try readAccessLine(tmp.dir, std.testing.allocator);
    defer std.testing.allocator.free(line);

    // A 4xx files at WARN, and an IPv6 client keeps its own form.
    try std.testing.expect(std.mem.indexOf(u8, line, "WARN ") != null);
    try std.testing.expect(std.mem.indexOf(u8, line, "[http3:access] GET /missing 404 0 \"::1\" \"-\" \"-\"") != null);
}

test "zix http3: a served request writes no access record when no logger is attached" {
    const config = Http3ServerConfig{ .allocator = std.testing.allocator, .io = std.testing.io, .ip = "127.0.0.1", .port = 0, .dispatch_model = .ASYNC };
    const req = core.Request{ .method = "GET", .path = "/" };
    const res = core.Response{ .status = 200, .body = "" };

    // The point is that it does not reach for a logger it does not have.
    writeAccessRecord(config, &req, &res, std.mem.zeroes(std.posix.sockaddr.in6));
}

/// Read back the one log file written under a temp root, for the access tests above.
fn readAccessLine(root: std.Io.Dir, allocator: std.mem.Allocator) ![]u8 {
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
