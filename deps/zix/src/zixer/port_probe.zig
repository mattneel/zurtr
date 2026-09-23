//! zixer port probe: whether a listener outside this daemon already owns a port

const std = @import("std");

const net = std.Io.net;

/// The address to dial when probing the one a site is about to listen on.
///
/// Note:
/// - A wildcard listener answers on loopback as well, and loopback is the one
///   address every supported platform lets a client dial. Windows refuses a
///   connect to 0.0.0.0 outright, so probing the wildcard as written would
///   read every port free there. Since 0.0.0.0 is the default site ip, that is
///   the common case rather than a corner of one.
///
/// Param:
/// addr - net.IpAddress (the address the caller is about to listen on)
///
/// Return:
/// - the loopback address of the same family and port, for a wildcard
/// - addr unchanged, for anything else
fn dialTarget(addr: net.IpAddress) net.IpAddress {
    return switch (addr) {
        .ip4 => |ip4| if (ip4.eql(net.Ip4Address.unspecified(ip4.port)))
            .{ .ip4 = net.Ip4Address.loopback(ip4.port) }
        else
            addr,
        .ip6 => |ip6| if (ip6.eql(net.Ip6Address.unspecified(ip6.port)))
            .{ .ip6 = net.Ip6Address.loopback(ip6.port) }
        else
            addr,
    };
}

/// Whether something already listens on this address.
///
/// Note:
/// - A tcp site listens with reuse_address, and std pairs that with
///   SO_REUSEPORT on posix, so a second daemon binds the same port without an
///   error and the kernel then splits arriving connections between the two
///   listeners. Half the traffic reaches a stranger, and a caller sees a reply
///   that never comes rather than a refused start. Windows has no
///   SO_REUSEPORT, but its SO_REUSEADDR is the permissive one and allows the
///   same overlap. The daemon registry only sees sites inside this process, so
///   this probe is what catches an owner in another one.
/// - A connect answers where a strict bind cannot: a live listener accepts it,
///   while a socket left in TIME_WAIT, which is what reuse_address exists to
///   survive, refuses it.
/// - No connect timeout is set, because the std.Io.Threaded backend panics on
///   one. It needs none: the dial target is an address this machine owns, so
///   the local stack answers at once, with a refusal when no listener is there.
/// - What it does not see is a stranger pinned to one interface while this site
///   takes the wildcard. The bind itself still reports that case whenever the
///   kernel does.
///
/// Param:
/// io - std.Io
/// addr - net.IpAddress (the address the caller is about to listen on)
///
/// Return:
/// - true when a listener answered, so a bind would join it instead of failing
/// - false when nothing answered, so the port is free to bind
pub fn isTaken(io: std.Io, addr: net.IpAddress) bool {
    const target = dialTarget(addr);

    const stream = target.connect(io, .{ .mode = .stream, .protocol = .tcp }) catch return false;
    stream.close(io);

    return true;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //
// These bind in the 189xx band, and every other zixer test port sits below
// 32768 too, under the ephemeral range every supported platform allocates
// outgoing source ports from. A bind inside that range races the kernel: an
// outgoing connection on the box can hold the port, and a closed one keeps
// holding it for the length of TIME_WAIT. reuse_address does not rescue that
// case: a plain client socket never sets it, so the kernel keeps the conflict
// and the listen fails with AddressInUse for a reason that has nothing to do
// with what is under test.

test "zix zixer: port probe, a port nothing listens on reads free" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 18930);

    try std.testing.expect(!isTaken(io, addr));
}

test "zix zixer: port probe, a live listener reads taken and frees on close" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try net.IpAddress.parse("127.0.0.1", 18931);

    var server = try addr.listen(io, .{ .reuse_address = true, .kernel_backlog = 8 });
    try std.testing.expect(isTaken(io, addr));

    server.deinit(io);

    try std.testing.expect(!isTaken(io, addr));
}

test "zix zixer: port probe, a listener on one port leaves its neighbour free" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const held = try net.IpAddress.parse("127.0.0.1", 18932);
    const free = try net.IpAddress.parse("127.0.0.1", 18933);

    var server = try held.listen(io, .{ .reuse_address = true, .kernel_backlog = 8 });
    defer server.deinit(io);

    try std.testing.expect(isTaken(io, held));
    try std.testing.expect(!isTaken(io, free));
}

test "zix zixer: port probe, a wildcard site is probed through loopback" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const wildcard = try net.IpAddress.parse("0.0.0.0", 18935);

    // 0.0.0.0 is the default site ip, so this is the shape most collisions
    // arrive in. Dialing it as written is an error on Windows.
    var server = try wildcard.listen(io, .{ .reuse_address = true, .kernel_backlog = 8 });
    try std.testing.expect(isTaken(io, wildcard));

    server.deinit(io);

    try std.testing.expect(!isTaken(io, wildcard));
}

test "zix zixer: port probe, dial target swaps only the wildcard for loopback" {
    const wildcard4 = try net.IpAddress.parse("0.0.0.0", 18936);
    try std.testing.expectEqual(net.Ip4Address.loopback(18936), dialTarget(wildcard4).ip4);

    const written4 = try net.IpAddress.parse("127.0.0.1", 18936);
    try std.testing.expectEqual(net.Ip4Address.loopback(18936), dialTarget(written4).ip4);

    const routable4 = try net.IpAddress.parse("10.0.0.7", 18936);
    try std.testing.expect(dialTarget(routable4).ip4.eql(routable4.ip4));

    const wildcard6 = try net.IpAddress.parse("::", 18936);
    try std.testing.expect(dialTarget(wildcard6).ip6.eql(net.Ip6Address.loopback(18936)));

    const loopback6 = try net.IpAddress.parse("::1", 18936);
    try std.testing.expect(dialTarget(loopback6).ip6.eql(net.Ip6Address.loopback(18936)));
}
