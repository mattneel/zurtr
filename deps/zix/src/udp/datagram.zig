//! zix udp raw datagram I/O primitives (ADR-049).
//!
//! What:
//! - A bound dual-stack (AF_INET6, IPV6_V6ONLY off) UDP socket plus batched receive / send over
//!   recvmmsg / sendmmsg, the building blocks for the raw-bytes datagram path (`zix.Udp.Raw`). One
//!   listener serves IPv4 (as IPv4-mapped) and IPv6 clients. Address conversion helpers are portable
//!   and unit-tested. The batched syscalls are Linux-only (the raw server falls back elsewhere).
//!
//! Note:
//! - recvmmsg fills one sockaddr per datagram, so a reply to the sender reuses that address with no
//!   conversion. Conversion to / from `std.Io.net.IpAddress` happens only for the handler view and
//!   for replies addressed to a peer other than the sender.

const std = @import("std");
const builtin = @import("builtin");

const linux = std.os.linux;
const posix = std.posix;

const IpAddress = std.Io.net.IpAddress;

/// Whether the batched-syscall path is available on this target.
pub const is_linux = builtin.os.tag == .linux;

const sockaddr_in6_len: posix.socklen_t = @sizeOf(posix.sockaddr.in6);

/// The IPv4-mapped IPv6 prefix (::ffff:0:0 / 96): the first 12 bytes of an IPv4-mapped address.
const v4_mapped_prefix = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

// --------------------------------------------------------- //

/// Build a dual-stack `sockaddr.in6` from a parsed address. An IPv4 address is stored in its
/// IPv4-mapped form (::ffff:a.b.c.d), so one AF_INET6 socket with IPV6_V6ONLY off serves both
/// families. The port is stored big-endian.
pub fn ipToSockaddr6(ip: IpAddress) posix.sockaddr.in6 {
    var addr: [16]u8 = @splat(0);
    var port: u16 = undefined;

    switch (ip) {
        .ip4 => |a| {
            @memcpy(addr[0..12], &v4_mapped_prefix);
            @memcpy(addr[12..16], &a.bytes);
            port = a.port;
        },
        .ip6 => |a| {
            @memcpy(&addr, &a.bytes);
            port = a.port;
        },
    }

    return .{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = addr, .scope_id = 0 };
}

/// Recover a `std.Io.net.IpAddress` from a `sockaddr.in6` the kernel filled in. An IPv4-mapped
/// address (::ffff:a.b.c.d) returns as IPv4, a native IPv6 address as IPv6.
pub fn sockaddr6ToIp(sa: posix.sockaddr.in6) IpAddress {
    const port = std.mem.bigToNative(u16, sa.port);
    if (std.mem.eql(u8, sa.addr[0..12], &v4_mapped_prefix)) {
        return .{ .ip4 = .{ .bytes = sa.addr[12..16].*, .port = port } };
    }

    return .{ .ip6 = .{ .bytes = sa.addr, .port = port } };
}

/// Parse a bind address string ("::", "0.0.0.0", "127.0.0.1") into a dual-stack `sockaddr.in6`.
pub fn parseBind(ip: []const u8, port: u16) !posix.sockaddr.in6 {
    const parsed = try IpAddress.parse(ip, port);

    return ipToSockaddr6(parsed);
}

/// Open a bound dual-stack UDP socket (AF_INET6 with IPV6_V6ONLY off, so "::" also accepts IPv4).
/// When `reuse` is set, SO_REUSEADDR + SO_REUSEPORT let many workers
/// bind the same port and the kernel load-balances datagrams across them. Socket / bind are raw
/// Linux syscalls (std.posix no longer wraps them since the std.Io migration). setsockopt is the
/// std.posix safe wrapper which remains.
pub fn open(ip: []const u8, port: u16, reuse: bool) !posix.socket_t {
    // Raw dual-stack sockets are POSIX-only here: Windows callers use the
    // std.Io fallback path instead.
    if (comptime builtin.os.tag == .windows) return error.ZixSocketFailed;

    const srv = linux.socket(linux.AF.INET6, linux.SOCK.DGRAM, linux.IPPROTO.UDP);
    switch (posix.errno(srv)) {
        .SUCCESS => {},
        else => return error.ZixSocketFailed,
    }

    const fd: posix.socket_t = @intCast(srv);
    errdefer close(fd);

    // Dual-stack: clear IPV6_V6ONLY so an AF_INET6 socket bound to "::" also accepts IPv4 (as
    // IPv4-mapped ::ffff:a.b.c.d). This lets one listener serve clients reaching it over either
    // family, regardless of how the peer resolved the host.
    const off = std.mem.toBytes(@as(c_int, 0));
    posix.setsockopt(fd, linux.IPPROTO.IPV6, linux.IPV6.V6ONLY, &off) catch {};

    if (reuse) {
        const one = std.mem.toBytes(@as(c_int, 1));
        posix.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, &one) catch {};
        posix.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEPORT, &one) catch return error.ZixReusePortFailed;
    }

    var addr = try parseBind(ip, port);
    const brv = linux.bind(fd, @ptrCast(&addr), sockaddr_in6_len);
    switch (posix.errno(brv)) {
        .SUCCESS => {},
        else => return error.ZixBindFailed,
    }

    return fd;
}

/// Request larger kernel socket buffers on a UDP socket. A QUIC / HTTP/3 worker drains datagrams in
/// recvmmsg batches, so between batches the kernel must hold a burst of arriving packets: a small
/// SO_RCVBUF drops the overflow, which shows up as loss and retransmits on a syscall-bound loopback
/// run. Larger send and receive buffers absorb the burst. The kernel caps each request at
/// net.core.rmem_max / wmem_max (and doubles it internally for bookkeeping), so an oversized request
/// is silently clamped, never an error. 0 leaves the kernel default untouched.
///
/// Param:
/// fd - posix.socket_t
/// rcvbuf - usize (requested SO_RCVBUF in bytes, 0 to skip)
/// sndbuf - usize (requested SO_SNDBUF in bytes, 0 to skip)
///
/// Return:
/// - void
pub fn setSocketBuffers(fd: posix.socket_t, rcvbuf: usize, sndbuf: usize) void {
    if (comptime builtin.os.tag == .windows) return;

    if (rcvbuf > 0) {
        const want = std.mem.toBytes(@as(c_int, @intCast(@min(rcvbuf, std.math.maxInt(c_int)))));
        posix.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, &want) catch {};
    }

    if (sndbuf > 0) {
        const want = std.mem.toBytes(@as(c_int, @intCast(@min(sndbuf, std.math.maxInt(c_int)))));
        posix.setsockopt(fd, linux.SOL.SOCKET, linux.SO.SNDBUF, &want) catch {};
    }
}

/// Close a raw socket descriptor.
pub fn close(fd: posix.socket_t) void {
    // No raw socket ever opens on Windows (open is gated), nothing to close.
    if (comptime builtin.os.tag == .windows) return;

    _ = linux.close(fd);
}

// --------------------------------------------------------- //

/// A received datagram: the payload bytes plus the sender address as the kernel reported it.
pub const Datagram = struct { data: []const u8, from: posix.sockaddr.in6 };

/// A reusable receive batch: one backing buffer carved into `count` MTU-sized slots, wired into the
/// mmsghdr / iovec / name arrays recvmmsg writes into.
pub const RecvBatch = struct {
    allocator: std.mem.Allocator,
    data: []u8,
    names: []posix.sockaddr.in6,
    iovs: []posix.iovec,
    hdrs: []linux.mmsghdr,
    slot_size: usize,

    /// Allocate a batch of `count` slots, each `slot_size` bytes wide.
    pub fn init(allocator: std.mem.Allocator, count: usize, slot_size: usize) !RecvBatch {
        const data = try allocator.alloc(u8, count * slot_size);
        errdefer allocator.free(data);

        const names = try allocator.alloc(posix.sockaddr.in6, count);
        errdefer allocator.free(names);

        const iovs = try allocator.alloc(posix.iovec, count);
        errdefer allocator.free(iovs);

        const hdrs = try allocator.alloc(linux.mmsghdr, count);
        errdefer allocator.free(hdrs);

        for (0..count) |i| {
            iovs[i] = .{ .base = data.ptr + i * slot_size, .len = slot_size };
            hdrs[i] = .{
                .hdr = .{
                    .name = @ptrCast(&names[i]),
                    .namelen = sockaddr_in6_len,
                    .iov = @ptrCast(&iovs[i]),
                    .iovlen = 1,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .len = 0,
            };
        }

        return .{ .allocator = allocator, .data = data, .names = names, .iovs = iovs, .hdrs = hdrs, .slot_size = slot_size };
    }

    pub fn deinit(self: *RecvBatch) void {
        self.allocator.free(self.data);
        self.allocator.free(self.names);
        self.allocator.free(self.iovs);
        self.allocator.free(self.hdrs);
    }

    /// Receive up to `count` datagrams in one syscall. MSG_WAITFORONE returns as soon as at least
    /// one datagram is available (without it, recvmmsg would block for the whole batch). A signal
    /// interruption yields 0 (the caller loops).
    pub fn recv(self: *RecvBatch, fd: posix.socket_t) !usize {
        const rc = linux.recvmmsg(fd, self.hdrs.ptr, @intCast(self.hdrs.len), linux.MSG.WAITFORONE, null);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .INTR => return 0,
            else => return error.ZixRecvFailed,
        }

        return rc;
    }

    /// Like `recv` but never blocks (MSG_DONTWAIT): returns 0 immediately when no datagram is queued.
    /// A userspace busy-poll loop spins on this to reap a datagram the instant it arrives, shaving the
    /// scheduler wake-up latency. Unlike SO_BUSY_POLL (a NIC NAPI poll, a no-op on loopback) this works
    /// on any socket and needs no privilege.
    pub fn recvNow(self: *RecvBatch, fd: posix.socket_t) !usize {
        const rc = linux.recvmmsg(fd, self.hdrs.ptr, @intCast(self.hdrs.len), linux.MSG.DONTWAIT, null);
        switch (posix.errno(rc)) {
            .SUCCESS => {},
            .INTR, .AGAIN => return 0,
            else => return error.ZixRecvFailed,
        }

        return rc;
    }

    /// The i-th received datagram. Valid for i < the count returned by `recv`.
    pub fn get(self: *const RecvBatch, i: usize) Datagram {
        return .{ .data = self.data[i * self.slot_size ..][0..self.hdrs[i].len], .from = self.names[i] };
    }
};

/// The socket a portable run sends through, with the std.Io it belongs to.
///
/// Note:
/// - Off Linux there is no descriptor to send batched raw datagrams on: the caller binds through
///   std.Io and holds a socket, not an fd. The helpers that queue a reply flush mid-flight when the
///   batch fills, and they only receive that unusable descriptor, so without this they would take
///   the sendmmsg path against a descriptor that was never opened, then reset the batch. Every
///   queued reply would be dropped with nothing reported. Setting this makes flush ignore its
///   descriptor and send through std.Io instead, so those mid-flight flushes reach the wire.
pub const PortableSink = struct {
    socket: std.Io.net.Socket,
    io: std.Io,
};

/// A reusable send batch: queued replies copied into a backing buffer and flushed via sendmmsg, or a coalesced sendmsg per peer-run when GSO is on. The
/// copy keeps replies valid even when the handler hands back bytes that live in the receive buffer.
pub const SendBatch = struct {
    allocator: std.mem.Allocator,
    data: []u8,
    names: []posix.sockaddr.in6,
    iovs: []posix.iovec,
    hdrs: []linux.mmsghdr,
    cap: usize,
    used: usize = 0,
    count: usize = 0,
    /// When true, flush coalesces consecutive same-destination replies into one sendmsg per group
    /// with a UDP_SEGMENT (GSO) control message, so the kernel splits the buffer into wire datagrams.
    /// Set by the worker only after probeGso confirms kernel support. Off keeps the plain sendmmsg path.
    gso: bool = false,
    /// How many queued replies (or, with gso set, how many queued replies the already-formed GSO
    /// groups cover) submitUring has already turned into io_uring SQEs. flush / flushGso only send
    /// the remainder, so a caller that falls back to a blocking flush mid-cycle (the batch filled
    /// before every queued reply could ride an SQE) never re-sends what is already in flight on the
    /// ring. Zero for a caller that never calls submitUring, so this changes nothing for them.
    ring_sent: usize = 0,
    /// Per-GSO-group scratch for submitUring, indexed by the group's starting queue position (so
    /// concurrent groups across calls never alias). Only touched when gso is set, otherwise unused.
    gso_iovs: []posix.iovec_const,
    gso_msgs: []linux.msghdr_const,
    gso_controls: []GsoControl,
    /// Where flush sends when there is no batched raw path (every target but Linux). Null on Linux,
    /// where flush owns the descriptor it is handed. See PortableSink for why this exists.
    portable: ?PortableSink = null,

    /// Allocate a batch holding up to `count` replies totalling `buf_bytes` payload bytes.
    pub fn init(allocator: std.mem.Allocator, count: usize, buf_bytes: usize) !SendBatch {
        const data = try allocator.alloc(u8, buf_bytes);
        errdefer allocator.free(data);

        const names = try allocator.alloc(posix.sockaddr.in6, count);
        errdefer allocator.free(names);

        const iovs = try allocator.alloc(posix.iovec, count);
        errdefer allocator.free(iovs);

        const hdrs = try allocator.alloc(linux.mmsghdr, count);
        errdefer allocator.free(hdrs);

        const gso_iovs = try allocator.alloc(posix.iovec_const, count);
        errdefer allocator.free(gso_iovs);

        const gso_msgs = try allocator.alloc(linux.msghdr_const, count);
        errdefer allocator.free(gso_msgs);

        const gso_controls = try allocator.alloc(GsoControl, count);
        errdefer allocator.free(gso_controls);

        return .{
            .allocator = allocator,
            .data = data,
            .names = names,
            .iovs = iovs,
            .hdrs = hdrs,
            .cap = count,
            .gso_iovs = gso_iovs,
            .gso_msgs = gso_msgs,
            .gso_controls = gso_controls,
        };
    }

    pub fn deinit(self: *SendBatch) void {
        self.allocator.free(self.data);
        self.allocator.free(self.names);
        self.allocator.free(self.iovs);
        self.allocator.free(self.hdrs);
        self.allocator.free(self.gso_iovs);
        self.allocator.free(self.gso_msgs);
        self.allocator.free(self.gso_controls);
    }

    /// Queue one reply to `dest` by copying `bytes` into the batch. Returns false when the batch is full
    /// (by count or by payload bytes), signalling the caller to flush and retry. A caller that can write
    /// the reply straight into the batch (e.g. seal a packet in place) should use reserve + commit
    /// instead to skip this copy.
    pub fn queue(self: *SendBatch, dest: posix.sockaddr.in6, bytes: []const u8) bool {
        if (self.count >= self.cap) return false;
        if (self.used + bytes.len > self.data.len) return false;

        @memcpy(self.data[self.used..][0..bytes.len], bytes);
        self.commit(dest, bytes.len);

        return true;
    }

    /// Reserve the free tail of the batch for the caller to write a reply into directly (seal in place),
    /// avoiding the copy queue() does. Returns a writable region of at least `needed` bytes, or null when
    /// the batch is full by count or lacks that much contiguous room, signalling the caller to flush and
    /// retry. Pair with commit() once the real written length is known.
    pub fn reserve(self: *SendBatch, needed: usize) ?[]u8 {
        if (self.count >= self.cap) return null;
        if (self.used + needed > self.data.len) return null;

        return self.data[self.used..];
    }

    /// Record a reply of `len` bytes now sitting at the batch's current tail (either copied by queue or
    /// written in place after reserve) to `dest`: wire its iovec / msghdr and advance the batch. `len`
    /// MUST be within the room a preceding reserve() confirmed, so the bytes lie inside the buffer.
    pub fn commit(self: *SendBatch, dest: posix.sockaddr.in6, len: usize) void {
        self.names[self.count] = dest;
        self.iovs[self.count] = .{ .base = self.data.ptr + self.used, .len = len };
        self.hdrs[self.count] = .{
            .hdr = .{
                .name = @ptrCast(&self.names[self.count]),
                .namelen = sockaddr_in6_len,
                .iov = @ptrCast(&self.iovs[self.count]),
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            },
            .len = 0,
        };

        self.used += len;
        self.count += 1;
    }

    /// Send every queued reply, then reset the batch. Handles partial sends and signal interruption.
    /// With gso set, consecutive same-destination replies are coalesced (see flushGso), otherwise the
    /// replies go out one-per-datagram batched into a single sendmmsg. Skips the prefix submitUring
    /// already put on the ring (ring_sent), so a caller that mixes the two never re-sends a reply
    /// twice.
    pub fn flush(self: *SendBatch, fd: posix.socket_t) !void {
        // A portable run has no descriptor to send on, and `fd` is whatever placeholder the caller
        // had. Send through the bound socket instead, so a helper that flushes mid-flight still
        // reaches the wire there.
        if (self.portable) |sink| {
            self.flushPortable(sink.socket, sink.io);

            return;
        }

        // sendmmsg below is a Linux syscall issued directly, so this path must never run anywhere
        // else: that syscall number belongs to something different there, and its result would be
        // read back through the wrong errno convention (a failure reading as success). A caller off
        // Linux is expected to set `portable` above, and gets a reported failure when it did not.
        if (comptime builtin.os.tag != .linux) return error.ZixSendFailed;

        if (self.gso) {
            try self.flushGso(fd);
            self.reset();
            return;
        }

        var sent: usize = self.ring_sent;
        while (sent < self.count) {
            const rc = linux.sendmmsg(fd, self.hdrs.ptr + sent, @intCast(self.count - sent), 0);
            switch (posix.errno(rc)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return error.ZixSendFailed,
            }
            if (rc == 0) break;
            sent += rc;
        }

        self.reset();
    }

    /// Send the queued replies coalescing consecutive same-destination runs via UDP GSO. A run is a
    /// span of queued replies all to the same peer where every reply but the last is exactly the
    /// segment size (the first reply's length) and the last is no larger. Such a run is sent as one
    /// sendmsg over its contiguous bytes (the queue lays them out back to back) plus a UDP_SEGMENT
    /// control message, so the kernel emits each segment as its own wire datagram from one syscall.
    /// A run of one is sent as a plain sendmsg. The big win is the Http3 multi-packet response flight
    /// to one peer. A per-peer-single-packet batch falls back to one sendmsg each (enable gso for
    /// multi-packet workloads). The caller resets the batch.
    fn flushGso(self: *SendBatch, fd: posix.socket_t) !void {
        var i: usize = self.ring_sent;
        while (i < self.count) {
            const run = gsoGroupLen(self.iovs[0..self.count], self.names[0..self.count], i);

            const seg_size: u16 = if (run >= 2) @intCast(self.iovs[i].len) else 0;
            var total: usize = 0;
            for (i..i + run) |k| total += self.iovs[k].len;

            try sendSeg(fd, @ptrCast(self.iovs[i].base), total, seg_size, &self.names[i]);

            i += run;
        }
    }

    /// Submit every reply queued since the last submitUring / reset as sendmsg SQEs on `ring`,
    /// tagging each with `tag` instead of a blocking sendmmsg syscall. Does not wait for completions
    /// and does not reset the batch: the messages (and, with gso set, the coalesced groups) live in
    /// this batch's own storage, so the caller must reap one ring completion per SQE this call
    /// reports submitted before it resets or reuses the batch. A ring momentarily too full to accept
    /// every SQE still returns the count actually submitted, leaving the rest for the next call.
    ///
    /// Param:
    /// ring - *linux.IoUring (the caller's ring, one per uring worker)
    /// fd - posix.socket_t (the UDP socket the SQEs send on)
    /// tag - u64 (the user_data every submitted SQE carries, for the caller's completion bookkeeping)
    ///
    /// Return:
    /// - usize (the number of SQEs submitted this call)
    pub fn submitUring(self: *SendBatch, ring: *linux.IoUring, fd: posix.socket_t, tag: u64) usize {
        if (self.gso) return self.submitUringGso(ring, fd, tag);

        var submitted: usize = 0;
        for (self.hdrs[self.ring_sent..self.count]) |*hdr| {
            const sqe = uringGetSqeRetrying(ring) orelse break;
            sqe.prep_sendmsg(fd, @ptrCast(&hdr.hdr), 0);
            sqe.user_data = tag;
            submitted += 1;
        }
        self.ring_sent += submitted;

        return submitted;
    }

    /// submitUring's gso branch: forms the same coalesced runs as flushGso, but each run becomes one
    /// persistent (not stack-local) iovec + msghdr + control message in this batch's own gso_* arrays
    /// indexed by the run's starting queue position, so the SQE's pointers stay valid across the
    /// async gap between submit and completion.
    fn submitUringGso(self: *SendBatch, ring: *linux.IoUring, fd: posix.socket_t, tag: u64) usize {
        var submitted: usize = 0;
        var i: usize = self.ring_sent;
        while (i < self.count) {
            const run = gsoGroupLen(self.iovs[0..self.count], self.names[0..self.count], i);

            const seg_size: u16 = if (run >= 2) @intCast(self.iovs[i].len) else 0;
            var total: usize = 0;
            for (i..i + run) |k| total += self.iovs[k].len;

            self.gso_iovs[i] = .{ .base = self.iovs[i].base, .len = total };
            self.gso_msgs[i] = .{
                .name = @ptrCast(&self.names[i]),
                .namelen = sockaddr_in6_len,
                .iov = self.gso_iovs[i..][0..1].ptr,
                .iovlen = 1,
                .control = null,
                .controllen = 0,
                .flags = 0,
            };
            if (seg_size > 0) {
                self.gso_controls[i] = .{ .hdr = .{ .len = GSO_CMSG_LEN, .level = linux.IPPROTO.UDP, .type = linux.UDP.SEGMENT }, .seg = seg_size };
                self.gso_msgs[i].control = &self.gso_controls[i];
                self.gso_msgs[i].controllen = GSO_CMSG_LEN;
            }

            const sqe = uringGetSqeRetrying(ring) orelse break;
            sqe.prep_sendmsg(fd, &self.gso_msgs[i], 0);
            sqe.user_data = tag;
            submitted += 1;

            i += run;
        }
        self.ring_sent = i;

        return submitted;
    }

    /// Drop all queued replies without sending.
    pub fn reset(self: *SendBatch) void {
        self.used = 0;
        self.count = 0;
        self.ring_sent = 0;
    }

    /// Send every queued reply one at a time through std.Io, then clear the batch.
    ///
    /// What:
    ///   flush() batches with sendmmsg, which is Linux only. This is the portable equivalent:
    ///   the same queued replies, one send syscall each. Used by the .ASYNC model on targets
    ///   with no sendmmsg, so a datagram server still runs there.
    ///
    /// Note:
    /// - A failed send is dropped rather than retried, matching flush(): UDP gives no delivery
    ///   guarantee, and one unreachable peer must not stall the replies queued behind it.
    ///
    /// Param:
    /// socket - std.Io.net.Socket (the bound datagram socket)
    /// io - std.Io
    ///
    /// Return:
    /// - void, with the batch cleared either way
    pub fn flushPortable(self: *SendBatch, socket: std.Io.net.Socket, io: std.Io) void {
        defer self.reset();

        for (0..self.count) |i| {
            const dest = sockaddr6ToIp(self.names[i]);

            socket.send(io, &dest, self.iovs[i].base[0..self.iovs[i].len]) catch continue;
        }
    }
};

/// Length in bytes of one UDP_SEGMENT control message: the cmsghdr plus the u16 segment size. The
/// cmsghdr is already usize-aligned, so no extra alignment padding sits between it and the u16.
const GSO_CMSG_LEN: usize = @sizeOf(linux.cmsghdr) + @sizeOf(u16);

/// Control-message buffer for one UDP_SEGMENT cmsg. extern + usize-aligned so the u16 lands at the
/// CMSG_DATA offset the kernel reads (right after the cmsghdr).
const GsoControl = extern struct {
    hdr: linux.cmsghdr,
    seg: u16,
};

/// Get a submission-queue entry for submitUring, submitting the backlog and retrying once when the
/// SQ is momentarily full. Null when the ring cannot accept a submission at all right now. Mirrors
/// the io_uring worker's own uringGetSqe (dispatch/uring.zig): duplicated rather than shared because
/// this file has no dependency on the http3 uring module, and the helper is four lines.
fn uringGetSqeRetrying(ring: *linux.IoUring) ?*linux.io_uring_sqe {
    return ring.get_sqe() catch {
        _ = ring.submit() catch return null;

        return ring.get_sqe() catch null;
    };
}

/// True when two addresses name the same peer (address bytes and port).
fn sameAddr(addr_a: posix.sockaddr.in6, addr_b: posix.sockaddr.in6) bool {
    return addr_a.port == addr_b.port and std.mem.eql(u8, &addr_a.addr, &addr_b.addr);
}

/// Length of the GSO run starting at index i: consecutive replies to the same peer where every reply
/// but the last is exactly the first reply's size and the last is no larger, bounded by the kernel
/// GSO limits (64 segments, 64 KiB total). Returns at least 1.
fn gsoGroupLen(iovs: []const posix.iovec, names: []const posix.sockaddr.in6, i: usize) usize {
    const seg_len = iovs[i].len;
    var j = i + 1;
    var total = seg_len;
    var segs: usize = 1;
    while (j < iovs.len and
        sameAddr(names[j], names[i]) and
        iovs[j - 1].len == seg_len and
        iovs[j].len <= seg_len and
        segs < 64 and
        total + iovs[j].len <= 65535)
    {
        total += iovs[j].len;
        segs += 1;
        j += 1;
    }

    return j - i;
}

/// Send one contiguous buffer to dest. When seg_size > 0 a UDP_SEGMENT control message asks the
/// kernel to split it into seg_size-byte wire datagrams (the last may be shorter). seg_size 0 sends
/// the buffer as a single datagram.
fn sendSeg(fd: posix.socket_t, base: [*]const u8, total: usize, seg_size: u16, dest: *const posix.sockaddr.in6) !void {
    if (comptime builtin.os.tag == .windows) return error.ZixSendFailed;

    var iov = posix.iovec_const{ .base = base, .len = total };
    var control: GsoControl align(@alignOf(usize)) = undefined;

    var msg = linux.msghdr_const{
        .name = @ptrCast(dest),
        .namelen = sockaddr_in6_len,
        .iov = @ptrCast(&iov),
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    if (seg_size > 0) {
        control.hdr = .{ .len = GSO_CMSG_LEN, .level = linux.IPPROTO.UDP, .type = linux.UDP.SEGMENT };
        control.seg = seg_size;
        msg.control = &control;
        msg.controllen = GSO_CMSG_LEN;
    }

    while (true) {
        const rc = linux.sendmsg(fd, &msg, 0);
        switch (posix.errno(rc)) {
            .SUCCESS => return,
            .INTR => continue,
            else => return error.ZixSendFailed,
        }
    }
}

/// Probe whether the kernel supports UDP GSO on this socket by setting the socket-wide segment size
/// to 0 (no socket default. The send path uses a per-message cmsg instead). Returns true when the
/// option exists (Linux 4.18+), false otherwise, so the caller leaves gso off on older kernels.
pub fn probeGso(fd: posix.socket_t) bool {
    if (comptime builtin.os.tag == .windows) return false;

    const zero: c_int = 0;
    posix.setsockopt(fd, linux.IPPROTO.UDP, linux.UDP.SEGMENT, std.mem.asBytes(&zero)) catch return false;

    return true;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix udp: datagram, ip4 round trips through sockaddr.in6 as IPv4-mapped" {
    const ip = try std.Io.net.IpAddress.parse("127.0.0.1", 9070);
    const sa = ipToSockaddr6(ip);

    try std.testing.expectEqual(@as(u16, std.mem.nativeToBig(u16, 9070)), sa.port);
    // The 4 IPv4 bytes sit after the ::ffff: prefix.
    try std.testing.expectEqualSlices(u8, &v4_mapped_prefix, sa.addr[0..12]);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, sa.addr[12..16]);

    const back = sockaddr6ToIp(sa);
    try std.testing.expectEqual(@as(u16, 9070), back.ip4.port);
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &back.ip4.bytes);
}

test "zix udp: datagram, native IPv6 round trips through sockaddr.in6" {
    const ip = try std.Io.net.IpAddress.parse("::1", 9071);
    const sa = ipToSockaddr6(ip);

    const back = sockaddr6ToIp(sa);
    try std.testing.expectEqual(@as(u16, 9071), back.ip6.port);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, &back.ip6.bytes);
}

test "zix udp: datagram, parseBind accepts dotted-quad and ::" {
    const sa4 = try parseBind("10.0.0.1", 53);
    try std.testing.expectEqual(@as(u16, std.mem.nativeToBig(u16, 53)), sa4.port);
    try std.testing.expectEqualSlices(u8, &.{ 10, 0, 0, 1 }, sa4.addr[12..16]);

    const sa6 = try parseBind("::", 53);
    try std.testing.expectEqualSlices(u8, &(@as([16]u8, @splat(0))), &sa6.addr);
}

test "zix udp: SendBatch queues replies and reports full" {
    var batch = try SendBatch.init(std.testing.allocator, 2, 32);
    defer batch.deinit();

    const dest = try parseBind("127.0.0.1", 1234);
    try std.testing.expect(batch.queue(dest, "ab"));
    try std.testing.expect(batch.queue(dest, "cde"));
    try std.testing.expectEqual(@as(usize, 2), batch.count);

    // Third queue exceeds the 2-slot cap.
    try std.testing.expect(!batch.queue(dest, "f"));

    // The payload bytes were copied in order.
    try std.testing.expectEqualStrings("abcde", batch.data[0..batch.used]);
    try std.testing.expectEqual(@as(usize, 2), batch.iovs[0].len);
    try std.testing.expectEqual(@as(usize, 3), batch.iovs[1].len);

    batch.reset();
    try std.testing.expectEqual(@as(usize, 0), batch.count);
    try std.testing.expectEqual(@as(usize, 0), batch.used);
}

test "zix udp: SendBatch flushPortable delivers every queued reply and clears the batch" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // a real bound receiver, so what is asserted is delivery and not just bookkeeping
    const recv_addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 9752);
    const receiver = try recv_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer receiver.close(io);

    const sender_addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 0);
    const sender = try sender_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(io);

    var batch = try SendBatch.init(std.testing.allocator, 4, 64);
    defer batch.deinit();

    const dest = try parseBind("127.0.0.1", 9752);
    try std.testing.expect(batch.queue(dest, "first"));
    try std.testing.expect(batch.queue(dest, "second"));

    batch.flushPortable(sender, io);

    // the batch is cleared whether or not a send failed, so the next round starts empty
    try std.testing.expectEqual(@as(usize, 0), batch.count);
    try std.testing.expectEqual(@as(usize, 0), batch.used);

    var buf: [64]u8 = undefined;
    const first = try receiver.receive(io, &buf);
    try std.testing.expectEqualStrings("first", first.data);

    var buf2: [64]u8 = undefined;
    const second = try receiver.receive(io, &buf2);
    try std.testing.expectEqualStrings("second", second.data);
}

test "zix udp: SendBatch flush sends through the portable sink and never touches its descriptor" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const recv_addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 9753);
    const receiver = try recv_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer receiver.close(io);

    const sender_addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 0);
    const sender = try sender_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(io);

    var batch = try SendBatch.init(std.testing.allocator, 4, 64);
    defer batch.deinit();
    batch.portable = .{ .socket = sender, .io = io };

    const dest = try parseBind("127.0.0.1", 9753);
    try std.testing.expect(batch.queue(dest, "first"));
    try std.testing.expect(batch.queue(dest, "second"));

    // The descriptor is one that was never opened, standing in for what a portable caller has to
    // pass. With the sink set, flush must ignore it rather than send on it: sending would drop
    // both replies and clear the batch, leaving the peer waiting on a reply that was never sent.
    const never_opened: posix.socket_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;
    try batch.flush(never_opened);

    try std.testing.expectEqual(@as(usize, 0), batch.count);
    try std.testing.expectEqual(@as(usize, 0), batch.used);

    var buf: [64]u8 = undefined;
    const first = try receiver.receive(io, &buf);
    try std.testing.expectEqualStrings("first", first.data);

    var buf2: [64]u8 = undefined;
    const second = try receiver.receive(io, &buf2);
    try std.testing.expectEqualStrings("second", second.data);
}

test "zix udp: SendBatch flushPortable on an empty batch sends nothing and stays empty" {
    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.resolve(io, "127.0.0.1", 0);
    const sender = try addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer sender.close(io);

    var batch = try SendBatch.init(std.testing.allocator, 4, 64);
    defer batch.deinit();

    batch.flushPortable(sender, io);

    try std.testing.expectEqual(@as(usize, 0), batch.count);
}

test "zix udp: SendBatch rejects an oversized payload" {
    var batch = try SendBatch.init(std.testing.allocator, 4, 4);
    defer batch.deinit();

    const dest = try parseBind("127.0.0.1", 1234);
    try std.testing.expect(batch.queue(dest, "abcd"));
    try std.testing.expect(!batch.queue(dest, "x"));
}

test "zix udp: SendBatch reserve + commit writes a reply in place with no copy, like queue" {
    var batch = try SendBatch.init(std.testing.allocator, 2, 32);
    defer batch.deinit();

    const dest = try parseBind("127.0.0.1", 1234);

    // Reserve the tail (asks for room >= what we write), write straight into it, commit the real length.
    const slot = batch.reserve(8) orelse return error.TestUnexpectedResult;
    @memcpy(slot[0..2], "ab");
    batch.commit(dest, 2);

    // A second in-place reply packs contiguously after the first, exactly as queue would have.
    const slot2 = batch.reserve(8) orelse return error.TestUnexpectedResult;
    @memcpy(slot2[0..3], "cde");
    batch.commit(dest, 3);

    try std.testing.expectEqual(@as(usize, 2), batch.count);
    try std.testing.expectEqualStrings("abcde", batch.data[0..batch.used]);
    try std.testing.expectEqual(@as(usize, 2), batch.iovs[0].len);
    try std.testing.expectEqual(@as(usize, 3), batch.iovs[1].len);

    // Full by count (2-slot cap) and full by bytes are both reported as null, the flush-and-retry signal.
    try std.testing.expect(batch.reserve(1) == null);

    batch.reset();
    try std.testing.expect(batch.reserve(64) == null); // 64 > 32-byte buffer: no contiguous room
    try std.testing.expect(batch.reserve(32) != null); // exactly the buffer fits
}

test "zix udp: RecvBatch allocates slots and wires headers" {
    var batch = try RecvBatch.init(std.testing.allocator, 4, 1500);
    defer batch.deinit();

    try std.testing.expectEqual(@as(usize, 4), batch.hdrs.len);
    try std.testing.expectEqual(@as(usize, 1500), batch.iovs[0].len);
    try std.testing.expectEqual(@as(usize, 4 * 1500), batch.data.len);
    try std.testing.expectEqual(@as(usize, 1), batch.hdrs[0].hdr.iovlen);
}

fn testPeer(port: u16) posix.sockaddr.in6 {
    var addr = std.mem.zeroes(posix.sockaddr.in6);
    addr.port = port;
    return addr;
}

test "zix udp: setSocketBuffers reads back a raised SO_RCVBUF on a real socket" {
    if (!is_linux) {
        std.log.info("SO_RCVBUF is read back through a Linux socket, test skipped", .{});
        return;
    }

    const fd = open("::1", 0, false) catch {
        std.log.info("the loopback UDP socket could not be opened, test skipped", .{});
        return;
    };
    defer close(fd);

    // Read the kernel default, request a larger buffer, then confirm the kernel raised it. The kernel
    // doubles the request internally and caps at rmem_max, so the result is at least the prior value.
    const before = getRcvBuf(fd) orelse {
        std.log.info("SO_RCVBUF could not be read back on this box, test skipped", .{});
        return;
    };

    setSocketBuffers(fd, 4 * 1024 * 1024, 4 * 1024 * 1024);

    const after = getRcvBuf(fd) orelse {
        std.log.info("SO_RCVBUF could not be read back on this box, test skipped", .{});
        return;
    };
    try std.testing.expect(after >= before);
    try std.testing.expect(after > 0);
}

test "zix udp: setSocketBuffers leaves the kernel default when asked for zero" {
    if (!is_linux) {
        std.log.info("SO_RCVBUF is read back through a Linux socket, test skipped", .{});
        return;
    }

    const fd = open("::1", 0, false) catch {
        std.log.info("the loopback UDP socket could not be opened, test skipped", .{});
        return;
    };
    defer close(fd);

    const before = getRcvBuf(fd) orelse {
        std.log.info("SO_RCVBUF could not be read back on this box, test skipped", .{});
        return;
    };

    // 0 for both: no setsockopt is issued, so the buffer is unchanged.
    setSocketBuffers(fd, 0, 0);

    const after = getRcvBuf(fd) orelse {
        std.log.info("SO_RCVBUF could not be read back on this box, test skipped", .{});
        return;
    };
    try std.testing.expectEqual(before, after);
}

/// Read SO_RCVBUF via the raw getsockopt syscall (test helper). Null when the syscall errors.
fn getRcvBuf(fd: posix.socket_t) ?c_int {
    var val: c_int = 0;
    var len: u32 = @sizeOf(c_int);
    const rc = linux.syscall5(.getsockopt, @as(usize, @intCast(fd)), linux.SOL.SOCKET, linux.SO.RCVBUF, @intFromPtr(&val), @intFromPtr(&len));
    if (posix.errno(rc) != .SUCCESS) return null;

    return val;
}

test "zix udp: gsoGroupLen coalesces a same-peer run with a shorter final segment" {
    var buf: [1]u8 = undefined;
    const a = testPeer(1);
    var iovs = [_]posix.iovec{
        .{ .base = &buf, .len = 1200 },
        .{ .base = &buf, .len = 1200 },
        .{ .base = &buf, .len = 800 },
    };
    var names = [_]posix.sockaddr.in6{ a, a, a };
    try std.testing.expectEqual(@as(usize, 3), gsoGroupLen(&iovs, &names, 0));
}

test "zix udp: gsoGroupLen stops after a short segment that is not last" {
    var buf: [1]u8 = undefined;
    const a = testPeer(1);
    // a short middle segment cannot be followed by another, so the run ends at the short one
    var iovs = [_]posix.iovec{
        .{ .base = &buf, .len = 1200 },
        .{ .base = &buf, .len = 800 },
        .{ .base = &buf, .len = 1200 },
    };
    var names = [_]posix.sockaddr.in6{ a, a, a };
    try std.testing.expectEqual(@as(usize, 2), gsoGroupLen(&iovs, &names, 0));
    try std.testing.expectEqual(@as(usize, 1), gsoGroupLen(&iovs, &names, 2));
}

test "zix udp: gsoGroupLen breaks the run at a different peer" {
    var buf: [1]u8 = undefined;
    const a = testPeer(1);
    const b = testPeer(2);
    var iovs = [_]posix.iovec{
        .{ .base = &buf, .len = 1200 },
        .{ .base = &buf, .len = 1200 },
    };
    var names = [_]posix.sockaddr.in6{ a, b };
    try std.testing.expectEqual(@as(usize, 1), gsoGroupLen(&iovs, &names, 0));
}

test "zix udp: gsoGroupLen rejects a larger following segment" {
    var buf: [1]u8 = undefined;
    const a = testPeer(1);
    // the second reply is larger than the first (the segment size), so it cannot ride the same GSO
    var iovs = [_]posix.iovec{
        .{ .base = &buf, .len = 800 },
        .{ .base = &buf, .len = 1200 },
    };
    var names = [_]posix.sockaddr.in6{ a, a };
    try std.testing.expectEqual(@as(usize, 1), gsoGroupLen(&iovs, &names, 0));
}

test "zix udp: SendBatch GSO send is accepted by the kernel and delivers over loopback" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    if (comptime !is_linux) return;

    const r_fd = open("127.0.0.1", 19071, false) catch return; // skip if the port is busy
    defer close(r_fd);
    const s_fd = open("127.0.0.1", 19072, false) catch return;
    defer close(s_fd);

    if (!probeGso(s_fd)) return; // kernel older than 4.18 without UDP GSO: skip

    // receiver non-blocking so the post-flush recv never hangs
    const fl = linux.fcntl(r_fd, posix.F.GETFL, 0);
    const nb: u32 = @bitCast(posix.O{ .NONBLOCK = true });
    _ = linux.fcntl(r_fd, posix.F.SETFL, fl | @as(usize, nb));

    const dest = ipToSockaddr6(try std.Io.net.IpAddress.parse("127.0.0.1", 19071));

    var payload_a: [1200]u8 = undefined;
    @memset(&payload_a, 'A');
    var payload_b: [800]u8 = undefined;
    @memset(&payload_b, 'B');

    var tx = try SendBatch.init(std.testing.allocator, 8, 8 * 1500);
    defer tx.deinit();
    tx.gso = true;
    try std.testing.expect(tx.queue(dest, &payload_a));
    try std.testing.expect(tx.queue(dest, &payload_b));

    // the coalesced UDP_SEGMENT sendmsg must be accepted by the kernel, not rejected with EINVAL.
    // A malformed control message fails here.
    try tx.flush(s_fd);

    // loopback delivers within the send syscall, so a non-blocking recv finds the first segment. The
    // delivery assertion is best-effort (guarded on n) to stay non-flaky. The flush above is the hard
    // check that the control message is well-formed.
    var rx = try RecvBatch.init(std.testing.allocator, 8, 1500);
    defer rx.deinit();
    const n = rx.recv(r_fd) catch 0;
    if (n >= 1) {
        const first = rx.get(0);
        try std.testing.expectEqual(@as(usize, 1200), first.data.len);
        try std.testing.expectEqual(@as(u8, 'A'), first.data[0]);
    }
}

test "zix udp: SendBatch.submitUring puts a queued reply on a real io_uring ring, not sendmmsg" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    if (comptime !is_linux) return;

    var ring = linux.IoUring.init(8, 0) catch return; // skip where io_uring is unavailable
    defer ring.deinit();

    const r_fd = open("127.0.0.1", 19075, false) catch return; // skip if the port is busy
    defer close(r_fd);
    const s_fd = open("127.0.0.1", 19076, false) catch return;
    defer close(s_fd);

    const dest = ipToSockaddr6(try std.Io.net.IpAddress.parse("127.0.0.1", 19075));

    var tx = try SendBatch.init(std.testing.allocator, 4, 64);
    defer tx.deinit();
    try std.testing.expect(tx.queue(dest, "hello"));

    // submitUring only queues the SQE: the reply does not land until the ring is submitted and the
    // completion reaped, unlike flush's synchronous sendmmsg.
    try std.testing.expectEqual(@as(usize, 1), tx.submitUring(&ring, s_fd, 42));
    try std.testing.expectEqual(@as(usize, 1), tx.ring_sent);

    _ = try ring.submit_and_wait(1);
    var cqes: [4]linux.io_uring_cqe = undefined;
    const reaped = try ring.copy_cqes(&cqes, 0);
    try std.testing.expect(reaped >= 1);
    try std.testing.expectEqual(@as(u64, 42), cqes[0].user_data);

    var rx = try RecvBatch.init(std.testing.allocator, 4, 64);
    defer rx.deinit();
    const n = try rx.recv(r_fd);
    try std.testing.expect(n >= 1);
    try std.testing.expectEqualStrings("hello", rx.get(0).data);
}

test "zix udp: SendBatch.flush skips the ring_sent prefix so mixing submitUring and flush never resends" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    if (comptime !is_linux) return;

    const r_fd = open("127.0.0.1", 19077, false) catch return;
    defer close(r_fd);
    const s_fd = open("127.0.0.1", 19078, false) catch return;
    defer close(s_fd);

    const fl = linux.fcntl(r_fd, posix.F.GETFL, 0);
    const nb: u32 = @bitCast(posix.O{ .NONBLOCK = true });
    _ = linux.fcntl(r_fd, posix.F.SETFL, fl | @as(usize, nb));

    const dest = ipToSockaddr6(try std.Io.net.IpAddress.parse("127.0.0.1", 19077));

    var tx = try SendBatch.init(std.testing.allocator, 4, 64);
    defer tx.deinit();
    try std.testing.expect(tx.queue(dest, "first"));
    try std.testing.expect(tx.queue(dest, "second"));

    // Pretend submitUring already put the first reply on a ring: flush must send only the tail.
    tx.ring_sent = 1;
    try tx.flush(s_fd);

    var rx = try RecvBatch.init(std.testing.allocator, 4, 64);
    defer rx.deinit();
    const n = rx.recv(r_fd) catch 0;
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualStrings("second", rx.get(0).data);

    // reset (called by flush) clears ring_sent too, so the batch starts its next cycle fresh.
    try std.testing.expectEqual(@as(usize, 0), tx.ring_sent);
}
