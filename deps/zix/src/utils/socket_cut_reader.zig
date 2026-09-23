//! Socket read side that outlives a socket_cut: the reader a cut-able connection is served over.
//!
//! What:
//!   socket_cut wakes a thread parked on a socket from outside its loop. On POSIX that is a
//!   half-close, and every reader already reports it as end-of-stream, so the std stream reader is
//!   the whole story there. On Windows the cut has to cancel the receive already parked in the
//!   kernel, and std's own socket reader answers a cancelled receive with unreachable (zig 0.16 and
//!   0.17 alike), which panics the process instead of ending the read. A Windows build therefore
//!   reads through windows_io, where a cancelled receive is 0 bytes, the same as a peer that closed.
//!
//! Note:
//! - One call shape on both platforms: init takes the stream, the io, and the buffer, and the
//!   caller passes &reader.interface exactly as it did with stream.reader.
//! - Only a caller whose socket another thread may cut needs this. Everything else keeps using the
//!   std stream reader, which is what this is on POSIX anyway.
//! - The send side is socket_cut_writer, for the same reason one tick later: the escalation cancels
//!   a parked send, and std's socket writer calls that unreachable too. A connection under a bound
//!   wants both.

const std = @import("std");
const builtin = @import("builtin");
const win_io = @import("windows_io.zig");

const is_windows = builtin.os.tag == .windows;

/// The reader type this platform serves a cut-able socket with.
pub const Reader = if (is_windows) WindowsReader else std.Io.net.Stream.Reader;

/// Open a reader over a socket another thread may cut.
///
/// Param:
/// stream - std.Io.net.Stream (the accepted socket)
/// io - std.Io (unused on Windows, where one receive is one ntdll ioctl on the handle)
/// buffer - []u8 (the reader's own buffer, must outlive the reader)
///
/// Return:
/// - Reader, whose .interface is what every caller passes on
pub fn init(stream: std.Io.net.Stream, io: std.Io, buffer: []u8) Reader {
    if (comptime is_windows) return WindowsReader.init(stream, buffer);

    return stream.reader(io, buffer);
}

// --------------------------------------------------------- //

/// std's stream reader with one difference: a receive the cut cancelled ends the stream rather
/// than reaching an unreachable branch.
///
/// Note:
/// - Only the vtable's stream is given. The Reader's own default readVec builds on it and already
///   picks the larger of the caller's slice and this buffer, so a one-byte read still costs one
///   receive per buffer fill rather than one per byte.
const WindowsReader = struct {
    interface: std.Io.Reader,
    handle: std.posix.socket_t,

    fn init(stream: std.Io.net.Stream, buffer: []u8) WindowsReader {
        return .{
            .interface = .{
                .vtable = &.{ .stream = streamImpl },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
            .handle = stream.socket.handle,
        };
    }

    /// One receive into whatever destination the caller offered.
    ///
    /// Note:
    /// - windows_io reads a cancelled or already-disconnected receive as 0 bytes, which is
    ///   end-of-stream here, the same answer a POSIX read gives on a socket after SHUT_RD.
    fn streamImpl(io_r: *std.Io.Reader, io_w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const reader: *WindowsReader = @alignCast(@fieldParentPtr("interface", io_r));
        const dest = limit.slice(try io_w.writableSliceGreedy(1));

        const got = win_io.readOnce(reader.handle, dest) catch return error.ReadFailed;
        if (got == 0) return error.EndOfStream;

        io_w.advance(got);

        return got;
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;
const socket_cut = @import("socket_cut.zig");

/// A connected loopback pair: what a site accepted, and the client holding the other end.
const TestPair = struct {
    server: std.Io.net.Server,
    client: std.Io.net.Stream,
    accepted: std.Io.net.Stream,

    fn open(io: std.Io, port: u16) !TestPair {
        const addr = try std.Io.net.IpAddress.parse("127.0.0.1", port);
        var server = try addr.listen(io, .{ .kernel_backlog = 4, .reuse_address = true });
        errdefer server.deinit(io);

        const client = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
        errdefer client.close(io);
        const accepted = try server.accept(io);

        return .{ .server = server, .client = client, .accepted = accepted };
    }

    fn send(pair: *const TestPair, io: std.Io, bytes: []const u8) !void {
        var write_buf: [128]u8 = undefined;
        var writer = pair.client.writer(io, &write_buf);

        try writer.interface.writeAll(bytes);
        try writer.interface.flush();
    }

    fn close(pair: *TestPair, io: std.Io) void {
        pair.accepted.close(io);
        pair.client.close(io);
        pair.server.deinit(io);
    }
};

test "zix utils: socket_cut_reader, an uncut socket reads what the peer sent" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TestPair.open(io, 18999);
    defer pair.close(io);

    try pair.send(io, "through-the-reader");

    var read_buf: [64]u8 = undefined;
    var reader = init(pair.accepted, io, &read_buf);

    var got: [18]u8 = undefined;
    try reader.interface.readSliceAll(&got);
    try testing.expectEqualStrings("through-the-reader", &got);
}

test "zix utils: socket_cut_reader, a cut ends a read that nothing had arrived for" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TestPair.open(io, 18887);
    defer pair.close(io);

    // The client never sends anything, so this read has nowhere to wake from except the cut.
    const Parked = struct {
        var short_read: ?usize = null;

        fn run(stream: std.Io.net.Stream, parked_io: std.Io) void {
            var read_buf: [64]u8 = undefined;
            var reader = init(stream, parked_io, &read_buf);

            var want: [4]u8 = undefined;
            short_read = reader.interface.readSliceShort(&want) catch return;
        }
    };

    const parked = try std.Thread.spawn(.{}, Parked.run, .{ pair.accepted, io });

    // Give the thread time to actually park in its read before the cut lands.
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    socket_cut.shutdownRead(pair.accepted.socket.handle);
    parked.join();

    try testing.expectEqual(@as(?usize, 0), Parked.short_read);
}

test "zix utils: socket_cut_reader, a cut keeps the bytes that did arrive" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TestPair.open(io, 18869);
    defer pair.close(io);

    // Part of a request head and nothing more, which is the shape an edge answers 408 to: the
    // count that comes back is what the client managed to send before its budget ran out.
    try pair.send(io, "GET / HTTP/1.1\r\n");

    const Parked = struct {
        var short_read: ?usize = null;

        fn run(stream: std.Io.net.Stream, parked_io: std.Io) void {
            var read_buf: [64]u8 = undefined;
            var reader = init(stream, parked_io, &read_buf);

            var want: [64]u8 = undefined;
            short_read = reader.interface.readSliceShort(&want) catch return;
        }
    };

    const parked = try std.Thread.spawn(.{}, Parked.run, .{ pair.accepted, io });

    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(50), .awake) catch {};
    socket_cut.shutdownRead(pair.accepted.socket.handle);
    parked.join();

    try testing.expectEqual(@as(?usize, 16), Parked.short_read);
}
