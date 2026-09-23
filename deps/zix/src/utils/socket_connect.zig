//! Portable bounded tcp connect: start a handshake without parking the caller, and give up on it at
//! a deadline the caller names.
//!
//! What:
//!   One helper, one concern. std.Io cannot bound a connect on any target zix builds for: every
//!   ConnectOptions.timeout other than .none is a TODO panic in both zig 0.16 backends. A caller
//!   that owes its own client an answer inside a budget therefore has nowhere else to go, and
//!   without this an upstream that swallows the SYN parks the exchange for as long as the operating
//!   system keeps retrying, which on linux defaults to past two minutes.
//!
//! Note:
//! - The shape is the textbook one. A non-blocking connect returns at once, the socket becomes
//!   writable when the handshake settles either way, and the pending socket error is the only thing
//!   that tells a refusal from a success. The readiness wait is socket_poll, so the waiting half is
//!   one code path on every target that gets here.
//! - The socket goes back to blocking before it is handed over. Every caller drives it with a std
//!   reader and writer afterwards, and those expect a blocking descriptor.
//! - Windows is NOT bounded here. A socket there is an AFD handle driven through ntdll, so the
//!   three calls this needs have no std entry and nothing in common with the posix ones. A windows
//!   caller gets std's own connect, which is what every caller had before this file existed, and
//!   the budget goes unused rather than half applied.
//! - A budget of 0 is the caller asking for no bound at all, and takes the same std connect. That
//!   leaves an unconfigured site on the behaviour it already had.

const std = @import("std");
const builtin = @import("builtin");
const monotonic_clock = @import("monotonic_clock.zig");
const socket_poll = @import("socket_poll.zig");

/// Whether this target can hold a connect to a budget. See the module note for why windows cannot.
pub const bounded_here = builtin.os.tag != .windows;

/// Which flavour of the posix calls this build links. The linux syscalls take usize arguments and
/// return one, the libc entries are variadic and need fixed-width values, and nothing else about
/// the sequence differs.
const uses_libc = std.posix.system == std.c;

pub const Error = error{
    /// The budget ran out with the handshake unfinished. Nothing is known about the peer past its
    /// silence, which is the case a gateway answers 504 for.
    ZixConnectTimeout,
    /// The connect ended with no connection: refused, unreachable, or a local end that could not
    /// start one.
    ZixConnectFailed,
};

/// Connect to address, giving up after budget_ms.
///
/// Note:
/// - The budget covers this one handshake. A caller trying several addresses in turn spends it once
///   per address, so its own worst case is the budget times the addresses it is willing to try.
/// - The returned stream carries the address it reached, where std's own connect would carry the
///   local end it bound to. Nothing on an upstream leg reads that field, and the remote is the
///   useful one of the two, so the difference is left standing rather than paid for with a second
///   address conversion.
///
/// Param:
/// io - std.Io (only used by the unbounded path)
/// address - *const std.Io.net.IpAddress (the peer to reach)
/// budget_ms - u32 (0 asks for no bound)
///
/// Return:
/// - std.Io.net.Stream, connected and blocking, owned by the caller
/// - error.ZixConnectTimeout when the budget ran out first
/// - error.ZixConnectFailed when the connect ended without a connection
pub fn withinBudget(io: std.Io, address: *const std.Io.net.IpAddress, budget_ms: u32) Error!std.Io.net.Stream {
    if (comptime bounded_here) {
        if (budget_ms != 0) return bounded(address, budget_ms);
    }

    return unbounded(io, address);
}

/// std's own connect, for the two cases that ask for no bound.
fn unbounded(io: std.Io, address: *const std.Io.net.IpAddress) Error!std.Io.net.Stream {
    return address.connect(io, .{ .mode = .stream, .protocol = .tcp }) catch |err| switch (err) {
        error.Timeout => error.ZixConnectTimeout,
        else => error.ZixConnectFailed,
    };
}

/// The bounded handshake: open, start, wait, ask, hand over.
fn bounded(address: *const std.Io.net.IpAddress, budget_ms: u32) Error!std.Io.net.Stream {
    var target: Sockaddr = undefined;
    const target_len = toSockaddr(address, &target);

    const handle = openStream(address.*) orelse return error.ZixConnectFailed;
    errdefer closeHandle(handle);

    if (!startConnect(handle, &target, target_len)) return error.ZixConnectFailed;

    // Writable is how a non-blocking connect reports that it is over, whichever way it went.
    const settled = socket_poll.waitReady(handle, socket_poll.WRITABLE, budget_ms) catch false;
    if (!settled) return error.ZixConnectTimeout;

    if (!connectedCleanly(handle)) return error.ZixConnectFailed;
    if (!markBlocking(handle)) return error.ZixConnectFailed;

    return .{ .socket = .{ .handle = handle, .address = address.* } };
}

/// Storage wide enough for either address family, so one pointer serves both connect calls.
const Sockaddr = extern union {
    ip4: std.posix.sockaddr.in,
    ip6: std.posix.sockaddr.in6,
};

/// Fill out with the platform address for address, and say how many bytes of it count.
fn toSockaddr(address: *const std.Io.net.IpAddress, out: *Sockaddr) std.posix.socklen_t {
    switch (address.*) {
        .ip4 => |v4| {
            out.* = .{ .ip4 = .{
                .port = std.mem.nativeToBig(u16, v4.port),
                .addr = @bitCast(v4.bytes),
            } };

            return @sizeOf(std.posix.sockaddr.in);
        },
        .ip6 => |v6| {
            out.* = .{ .ip6 = .{
                .port = std.mem.nativeToBig(u16, v6.port),
                .flowinfo = v6.flow,
                .addr = v6.bytes,
                .scope_id = v6.interface.index,
            } };

            return @sizeOf(std.posix.sockaddr.in6);
        },
    }
}

/// A non-blocking, close-on-exec tcp socket of the right family, or null when the local end had
/// nothing left to give.
fn openStream(address: std.Io.net.IpAddress) ?std.posix.fd_t {
    const family: u32 = switch (address) {
        .ip4 => std.posix.AF.INET,
        .ip6 => std.posix.AF.INET6,
    };

    const opened = std.posix.system.socket(family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    if (std.posix.errno(opened) != .SUCCESS) return null;

    const handle: std.posix.fd_t = @intCast(opened);
    if (!markNonBlocking(handle) or !markCloseOnExec(handle)) {
        closeHandle(handle);

        return null;
    }

    return handle;
}

/// Begin the handshake. In progress counts as started: that is the whole reason the socket is
/// non-blocking, and the readiness wait is what finishes the story.
fn startConnect(handle: std.posix.fd_t, target: *const Sockaddr, target_len: std.posix.socklen_t) bool {
    const started = std.posix.system.connect(handle, @ptrCast(target), target_len);

    return switch (std.posix.errno(started)) {
        .SUCCESS, .INPROGRESS, .ALREADY, .INTR => true,
        else => false,
    };
}

/// Whether the settled handshake left a connected socket. The pending socket error is the only
/// place a non-blocking connect reports its outcome: the socket turns writable either way.
fn connectedCleanly(handle: std.posix.fd_t) bool {
    var pending: u32 = 0;
    var pending_len: std.posix.socklen_t = @sizeOf(u32);

    const asked = std.posix.system.getsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&pending), &pending_len);
    if (std.posix.errno(asked) != .SUCCESS) return false;

    return pending == 0;
}

fn markNonBlocking(handle: std.posix.fd_t) bool {
    const flags = fileFlags(handle, std.posix.F.GETFL, 0) orelse return false;
    const nonblock: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });

    return fileFlags(handle, std.posix.F.SETFL, flags | nonblock) != null;
}

fn markBlocking(handle: std.posix.fd_t) bool {
    const flags = fileFlags(handle, std.posix.F.GETFL, 0) orelse return false;
    const nonblock: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });

    return fileFlags(handle, std.posix.F.SETFL, flags & ~nonblock) != null;
}

fn markCloseOnExec(handle: std.posix.fd_t) bool {
    return fileFlags(handle, std.posix.F.SETFD, std.posix.FD_CLOEXEC) != null;
}

/// One fcntl over both flavours. See uses_libc for what differs.
fn fileFlags(handle: std.posix.fd_t, cmd: i32, arg: u32) ?u32 {
    const answered = if (comptime uses_libc)
        std.posix.system.fcntl(handle, @as(c_int, @intCast(cmd)), @as(c_uint, arg))
    else
        std.posix.system.fcntl(handle, cmd, @as(usize, arg));

    if (std.posix.errno(answered) != .SUCCESS) return null;

    return @intCast(answered);
}

fn closeHandle(handle: std.posix.fd_t) void {
    _ = std.posix.system.close(handle);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

/// An address inside the documentation range of rfc 5737. Nothing routable answers there, so a SYN
/// aimed at it is dropped rather than refused, which is the shape a bound exists for.
const BLACKHOLE_IP: []const u8 = "192.0.2.1";

test "zix utils: socket_connect a reachable listener is connected inside the budget" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18937);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    const client = try withinBudget(io, &addr, 3_000);
    defer client.close(io);
    const accepted = try server.accept(io);
    defer accepted.close(io);

    // Blocking again is what a std writer on this socket needs, and a short write that completes
    // is what proves it.
    var write_buf: [32]u8 = undefined;
    var writer = client.writer(io, &write_buf);
    try writer.interface.writeAll("bounded-connect");
    try writer.interface.flush();

    var read_buf: [32]u8 = undefined;
    var reader = accepted.reader(io, &read_buf);
    var got: [15]u8 = undefined;
    try reader.interface.readSliceAll(&got);
    try testing.expectEqualStrings("bounded-connect", &got);
}

test "zix utils: socket_connect a budget of zero still reaches a listener" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18938);
    var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
    defer server.deinit(io);

    // No bound configured takes std's own connect, which is what every caller had before.
    const client = try withinBudget(io, &addr, 0);
    defer client.close(io);
    const accepted = try server.accept(io);
    accepted.close(io);
}

test "zix utils: socket_connect a closed port fails rather than waiting out the budget" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Bound and dropped, so the port is known to have nobody on it.
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18939);
    var server = try addr.listen(io, .{ .kernel_backlog = 1, .reuse_address = true });
    server.deinit(io);

    // A refusal is an answer, so it has to arrive as a failure and not as the budget elapsing.
    try testing.expectError(error.ZixConnectFailed, withinBudget(io, &addr, 10_000));
}

test "zix utils: socket_connect a silent address gives up on the budget" {
    if (comptime !bounded_here) {
        std.log.info("connect budgets are a posix path, see the module note, test skipped", .{});
        return;
    }

    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse(BLACKHOLE_IP, 80);

    const started_ms = monotonic_clock.nowMs(io);
    const outcome = withinBudget(io, &addr, 400);
    const spent_ms = monotonic_clock.nowMs(io) - started_ms;

    if (outcome) |stream| {
        stream.close(io);
        std.log.info("the documentation address answered on this box, nothing to bound, test skipped", .{});

        return;
    } else |err| {
        if (err == error.ZixConnectFailed) {
            std.log.info("this box has no route to the documentation address, so no handshake started, test skipped", .{});

            return;
        }

        try testing.expectEqual(error.ZixConnectTimeout, err);
    }

    // Waited for its budget and not the operating system's own retry limit, which is minutes.
    try testing.expect(spent_ms >= 300);
    try testing.expect(spent_ms < 5_000);
}
