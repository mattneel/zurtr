//! The peer address of a connected socket, as text.
//!
//! What:
//! - One place that answers "who is on the other end of this descriptor". The connection records
//!   want it with its port (`endpoint`), an access record wants the address alone (`host`), and an
//!   access record behind a proxy wants the proxy headers consulted first (`clientIp`).
//!
//! Note:
//! - Zig 0.16 std has no getpeername on Windows, so every answer there is "-". The console and
//!   file records still carry everything else, only the peer field is empty.
//! - An unreadable peer is never an error: a closed or reset socket answers "-" like any other
//!   address that cannot be read, because a log record must not fail the request it describes.

const std = @import("std");
const builtin = @import("builtin");
const socket_pair = @import("socket_pair.zig");

// --------------------------------------------------------- //

/// What every call answers when the address cannot be read.
pub const UNKNOWN = "-";

/// Bytes an endpoint string can need: an IPv6 address in brackets plus a port.
pub const MAX_LEN: usize = 64;

/// Read the peer address off a connected socket.
///
/// Note:
/// - The raw syscall is used rather than std.posix.getpeername, which answers `unreachable` for
///   EBADF on the grounds that a bad descriptor is always a race. That is a fair contract for a
///   caller that owns the socket, but not for a log record: the TLS path hands this a buffer-sink
///   sentinel rather than a socket, and a logger must never be the thing that aborts a server.
/// - A descriptor that is not a socket, has no peer, or is not an IP family all answer null, and
///   every one of those becomes "-" in the record.
///
/// Return:
/// - std.Io.net.IpAddress for an IPv4 or IPv6 peer
/// - null on Windows, and whenever no IP peer can be read
fn read(fd: std.posix.fd_t) ?std.Io.net.IpAddress {
    if (comptime builtin.target.os.tag == .windows) return null;

    // Sentinels the engines use in place of a socket, so the syscall is never even attempted.
    if (fd < 0) return null;

    var storage: std.posix.sockaddr.storage = undefined;
    var len: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);

    const rc = std.posix.system.getpeername(fd, @ptrCast(&storage), &len);
    if (std.posix.errno(rc) != .SUCCESS) return null;

    if (storage.family == std.posix.AF.INET) {
        const sock_in: *align(8) const std.posix.sockaddr.in = @ptrCast(&storage);

        return .{ .ip4 = .{
            .bytes = @bitCast(sock_in.addr),
            .port = std.mem.bigToNative(u16, sock_in.port),
        } };
    }

    if (storage.family == std.posix.AF.INET6) {
        const sock_in6: *align(8) const std.posix.sockaddr.in6 = @ptrCast(&storage);

        return .{ .ip6 = .{
            .bytes = sock_in6.addr,
            .port = std.mem.bigToNative(u16, sock_in6.port),
            .flow = sock_in6.flowinfo,
        } };
    }

    return null;
}

/// The peer as address and port: "1.2.3.4:5678", "[::1]:5678", or "-".
///
/// Param:
/// buf - []u8 (MAX_LEN is always enough)
///
/// Return:
/// - the formatted slice, borrowed from buf
/// - UNKNOWN when there is no readable IP peer
pub fn endpoint(fd: std.posix.fd_t, buf: []u8) []const u8 {
    const address = read(fd) orelse return UNKNOWN;

    return std.fmt.bufPrint(buf, "{f}", .{address}) catch UNKNOWN;
}

/// The peer address without its port: "1.2.3.4", "::1", or "-".
///
/// Note:
/// - An access record names who made the request, and the ephemeral source port is noise there.
///   It also has to match what a proxy would put in X-Forwarded-For, which carries no port.
///
/// Param:
/// buf - []u8 (MAX_LEN is always enough)
///
/// Return:
/// - the formatted slice, borrowed from buf
/// - UNKNOWN when there is no readable IP peer
pub fn host(fd: std.posix.fd_t, buf: []u8) []const u8 {
    const address = read(fd) orelse return UNKNOWN;

    return switch (address) {
        .ip4 => |ip4| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
            ip4.bytes[0],
            ip4.bytes[1],
            ip4.bytes[2],
            ip4.bytes[3],
        }) catch UNKNOWN,
        .ip6 => |ip6| blk: {
            const bare: std.Io.net.Ip6Address.Unresolved = .{ .bytes = ip6.bytes, .interface_name = null };

            break :blk std.fmt.bufPrint(buf, "{f}", .{bare}) catch UNKNOWN;
        },
    };
}

/// Whether these 16 bytes are an IPv4 address carried in IPv6 form (::ffff:a.b.c.d).
fn isIp4Mapped(bytes: [16]u8) bool {
    const zero_prefix: [10]u8 = @splat(0);

    return std.mem.eql(u8, bytes[0..10], &zero_prefix) and bytes[10] == 0xff and bytes[11] == 0xff;
}

/// Format an address the caller already holds, without its port.
///
/// Note:
/// - For engines that never see a socket descriptor. QUIC keeps its peer on the connection, so
///   HTTP/3 names its client from this rather than from getpeername.
/// - An IPv4 client on a dual-stack socket arrives as ::ffff:a.b.c.d, and is written as the plain
///   dotted quad, because that is the address an operator recognises and what a proxy would send.
///
/// Param:
/// sock_in6 - std.posix.sockaddr.in6 (the peer as the engine stored it)
/// buf - []u8 (MAX_LEN is always enough)
///
/// Return:
/// - the formatted slice, borrowed from buf
/// - UNKNOWN when the address is all zeroes, which is what an unset field holds
pub fn hostFromIn6(sock_in6: std.posix.sockaddr.in6, buf: []u8) []const u8 {
    const bytes = sock_in6.addr;
    const unset: [16]u8 = @splat(0);

    if (std.mem.eql(u8, &bytes, &unset)) return UNKNOWN;

    if (isIp4Mapped(bytes)) {
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15],
        }) catch UNKNOWN;
    }

    const bare: std.Io.net.Ip6Address.Unresolved = .{ .bytes = bytes, .interface_name = null };

    return std.fmt.bufPrint(buf, "{f}", .{bare}) catch UNKNOWN;
}

/// The first entry of an X-Forwarded-For value, trimmed.
///
/// Note:
/// - The header is a chain, "client, proxy1, proxy2", and the client is the first entry. Later
///   entries are the proxies themselves, so taking the last one would name the wrong machine.
///
/// Return:
/// - the first entry, or an empty slice when the value is empty
pub fn firstForwarded(forwarded_for: []const u8) []const u8 {
    const comma = std.mem.indexOfScalar(u8, forwarded_for, ',') orelse forwarded_for.len;

    return std.mem.trim(u8, forwarded_for[0..comma], " \t");
}

/// Who the client is, for an access record.
///
/// Note:
/// - Order is X-Forwarded-For, then X-Real-IP, then the socket peer. A proxy header wins because
///   behind a proxy the socket peer is the proxy, not the client. The socket peer is the fallback
///   that makes a direct request name a real address rather than "-".
/// - The caller passes empty strings for headers it does not have, so a plain engine with no
///   header parsing can call this with two empty slices and still get the peer.
///
/// Param:
/// forwarded_for - []const u8 (the X-Forwarded-For value, empty when absent)
/// real_ip - []const u8 (the X-Real-IP value, empty when absent)
/// fd - ?std.posix.fd_t (the client socket, null when the engine has no descriptor to hand)
/// buf - []u8 (MAX_LEN is always enough, only used for the socket fallback)
///
/// Return:
/// - the client address, borrowed from the header value or from buf
/// - UNKNOWN when no source could name one
pub fn clientIp(forwarded_for: []const u8, real_ip: []const u8, fd: ?std.posix.fd_t, buf: []u8) []const u8 {
    const forwarded = firstForwarded(forwarded_for);
    if (forwarded.len > 0) return forwarded;

    const real = std.mem.trim(u8, real_ip, " \t");
    if (real.len > 0) return real;

    const socket = fd orelse return UNKNOWN;

    return host(socket, buf);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix utils peer: hostFromIn6 writes a mapped IPv4 client as a dotted quad" {
    var sock_in6 = std.mem.zeroes(std.posix.sockaddr.in6);
    sock_in6.addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 7 };

    var buf: [MAX_LEN]u8 = undefined;
    try std.testing.expectEqualStrings("203.0.113.7", hostFromIn6(sock_in6, &buf));
}

test "zix utils peer: hostFromIn6 writes a real IPv6 client in its own form" {
    var sock_in6 = std.mem.zeroes(std.posix.sockaddr.in6);
    sock_in6.addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    var buf: [MAX_LEN]u8 = undefined;
    const named = hostFromIn6(sock_in6, &buf);

    std.log.info(".PEER: an IPv6 loopback client is named {s}", .{named});
    try std.testing.expectEqualStrings("::1", named);
}

test "zix utils peer: hostFromIn6 answers UNKNOWN for an address that was never set" {
    const sock_in6 = std.mem.zeroes(std.posix.sockaddr.in6);

    var buf: [MAX_LEN]u8 = undefined;
    try std.testing.expectEqualStrings(UNKNOWN, hostFromIn6(sock_in6, &buf));
}

test "zix utils peer: firstForwarded takes the client and leaves the proxies" {
    try std.testing.expectEqualStrings("203.0.113.7", firstForwarded("203.0.113.7, 198.51.100.2, 198.51.100.3"));
    try std.testing.expectEqualStrings("203.0.113.7", firstForwarded("  203.0.113.7  ,198.51.100.2"));
    try std.testing.expectEqualStrings("203.0.113.7", firstForwarded("203.0.113.7"));
    try std.testing.expectEqualStrings("", firstForwarded(""));
}

test "zix utils peer: clientIp prefers the forwarded header over everything else" {
    var buf: [MAX_LEN]u8 = undefined;

    try std.testing.expectEqualStrings(
        "203.0.113.7",
        clientIp("203.0.113.7, 198.51.100.2", "198.51.100.9", null, &buf),
    );
}

test "zix utils peer: clientIp falls back to the real-ip header when there is no forwarded chain" {
    var buf: [MAX_LEN]u8 = undefined;

    try std.testing.expectEqualStrings("198.51.100.9", clientIp("", "198.51.100.9", null, &buf));
    try std.testing.expectEqualStrings("198.51.100.9", clientIp("   ", " 198.51.100.9 ", null, &buf));
}

test "zix utils peer: clientIp answers UNKNOWN when nothing can name the client" {
    var buf: [MAX_LEN]u8 = undefined;

    try std.testing.expectEqualStrings(UNKNOWN, clientIp("", "", null, &buf));
}

test "zix utils peer: a socket with no IP peer answers UNKNOWN rather than failing" {
    if (comptime builtin.target.os.tag == .windows) {
        std.log.info(".PEER: zig 0.16 std has no getpeername on windows, the answer is always UNKNOWN", .{});
        return;
    }

    // A unix socketpair is connected but has no IP family, which is the non-IP branch. The helper
    // reaches the same syscall through libc off linux, so this runs on every POSIX target.
    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();

    var buf: [MAX_LEN]u8 = undefined;
    try std.testing.expectEqualStrings(UNKNOWN, host(pair.fds[0], &buf));
    try std.testing.expectEqualStrings(UNKNOWN, endpoint(pair.fds[0], &buf));
    try std.testing.expectEqualStrings(UNKNOWN, clientIp("", "", pair.fds[0], &buf));
}

test "zix utils peer: a socket with no peer answers UNKNOWN rather than failing" {
    if (comptime builtin.target.os.tag == .windows) {
        std.log.info(".PEER: zig 0.16 std has no getpeername on windows, the answer is always UNKNOWN", .{});
        return;
    }

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A listening socket is a real socket that was never connected. getpeername answers ENOTCONN,
    // which is the branch a record hits when the connection went away before it was written. Port
    // 0 takes whatever the kernel hands out, so this fixture can never collide with another test.
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{ .kernel_backlog = 1 });
    defer server.deinit(io);

    var buf: [MAX_LEN]u8 = undefined;
    try std.testing.expectEqualStrings(UNKNOWN, host(server.socket.handle, &buf));
    try std.testing.expectEqualStrings(UNKNOWN, endpoint(server.socket.handle, &buf));
    try std.testing.expectEqualStrings(UNKNOWN, clientIp("", "", server.socket.handle, &buf));
}

test "zix utils peer: a sink sentinel and a stale descriptor answer UNKNOWN instead of aborting" {
    if (comptime builtin.target.os.tag == .windows) {
        std.log.info(".PEER: zig 0.16 std has no getpeername on windows, the answer is always UNKNOWN", .{});
        return;
    }

    var buf: [MAX_LEN]u8 = undefined;

    // The TLS path serves into a buffer and hands -1 where a socket would go. Reaching for a peer
    // there used to abort the process through std's EBADF unreachable.
    try std.testing.expectEqualStrings(UNKNOWN, host(@as(std.posix.fd_t, -1), &buf));
    try std.testing.expectEqualStrings(UNKNOWN, endpoint(@as(std.posix.fd_t, -1), &buf));
    try std.testing.expectEqualStrings(UNKNOWN, clientIp("", "", @as(std.posix.fd_t, -1), &buf));

    // A descriptor number that was never opened is the same class of answer, not a crash.
    try std.testing.expectEqualStrings(UNKNOWN, host(@as(std.posix.fd_t, 4096), &buf));
    try std.testing.expectEqualStrings(UNKNOWN, endpoint(@as(std.posix.fd_t, 4096), &buf));

    std.log.info(".PEER: sentinel and stale descriptors answer UNKNOWN without aborting", .{});
}

/// Loopback port for the connected-peer test below, unique across the tree.
const TEST_PORT: u16 = 18601;

test "zix utils peer: a real IPv4 peer is named with and without its port" {
    if (comptime builtin.target.os.tag == .windows) {
        std.log.info(".PEER: zig 0.16 std has no getpeername on windows, the answer is always UNKNOWN", .{});
        return;
    }

    var threaded: std.Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", TEST_PORT);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer client.close(io);

    const served = try server.accept(io);
    defer served.close(io);

    // The server side sees the client's loopback address, port and all.
    var buf: [MAX_LEN]u8 = undefined;
    const named_host = host(served.socket.handle, &buf);

    var endpoint_buf: [MAX_LEN]u8 = undefined;
    const named_endpoint = endpoint(served.socket.handle, &endpoint_buf);

    std.log.info(".PEER: a direct client is named {s} and {s}", .{ named_host, named_endpoint });

    try std.testing.expectEqualStrings("127.0.0.1", named_host);
    try std.testing.expect(std.mem.startsWith(u8, named_endpoint, "127.0.0.1:"));
    try std.testing.expect(!std.mem.eql(u8, named_endpoint, "127.0.0.1:0"));

    // The whole point of the fallback: no proxy header, and the record still names the client.
    var client_buf: [MAX_LEN]u8 = undefined;
    try std.testing.expectEqualStrings(
        "127.0.0.1",
        clientIp("", "", served.socket.handle, &client_buf),
    );

    // A proxy header still wins over a real peer, because behind a proxy the peer is the proxy.
    try std.testing.expectEqualStrings(
        "203.0.113.7",
        clientIp("203.0.113.7", "", served.socket.handle, &client_buf),
    );
}
