//! Socket send side that outlives a socket_cut: the writer a cut-able connection is served over.
//!
//! What:
//!   The escalation cut takes the send side away, which is how a thread parked writing to a peer
//!   that stopped reading is freed. On POSIX that send fails and every writer reports it. On
//!   Windows the escalation has to cancel the send already parked in the kernel, and std's own
//!   socket writer answers a cancelled send with unreachable (zig 0.16 and 0.17 alike), which
//!   panics the process instead of failing the write. A Windows build therefore sends through
//!   windows_io, where a cancelled send is an error like any other broken connection.
//!
//! Note:
//! - One call shape on both platforms: init takes the stream, the io, and the buffer, and the
//!   caller passes &writer.interface exactly as it did with stream.writer.
//! - The counterpart of socket_cut_reader. A connection under a bound needs both, since the first
//!   cut reaches a parked read and the escalation reaches a parked send.
//! - sendFile is left at the default, which answers Unimplemented. That is what std's own socket
//!   writer answers on zig 0.16 too, so a caller's fallback path is reached the same way.

const std = @import("std");
const builtin = @import("builtin");
const win_io = @import("windows_io.zig");

const is_windows = builtin.os.tag == .windows;

/// The writer type this platform serves a cut-able socket with.
pub const Writer = if (is_windows) WindowsWriter else std.Io.net.Stream.Writer;

/// Open a writer over a socket another thread may cut.
///
/// Param:
/// stream - std.Io.net.Stream (the accepted socket)
/// io - std.Io (unused on Windows, where one send is one ntdll ioctl on the handle)
/// buffer - []u8 (the writer's own buffer, must outlive the writer)
///
/// Return:
/// - Writer, whose .interface is what every caller passes on
pub fn init(stream: std.Io.net.Stream, io: std.Io, buffer: []u8) Writer {
    if (comptime is_windows) return WindowsWriter.init(stream, buffer);

    return stream.writer(io, buffer);
}

// --------------------------------------------------------- //

/// std's stream writer with one difference: a send the cut cancelled fails the write rather than
/// reaching an unreachable branch.
const WindowsWriter = struct {
    interface: std.Io.Writer,
    handle: std.posix.socket_t,

    fn init(stream: std.Io.net.Stream, buffer: []u8) WindowsWriter {
        return .{
            .interface = .{
                .vtable = &.{ .drain = drain },
                .buffer = buffer,
                .end = 0,
            },
            .handle = stream.socket.handle,
        };
    }

    /// One send of the next bytes owed to the socket.
    ///
    /// Note:
    /// - windows_io fails a cancelled or disconnected send, which is error.WriteFailed here, the
    ///   answer a POSIX write gives once the send side is gone.
    /// - One chunk per call rather than one vectored send of everything the caller offered. A
    ///   partial drain is what the contract expects, and the caller comes straight back for the
    ///   rest, so the cost is one ioctl per chunk on the paths that pass several.
    fn drain(io_w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        const writer: *WindowsWriter = @alignCast(@fieldParentPtr("interface", io_w));
        const chunk = nextChunk(io_w.buffered(), data, splat) orelse return 0;

        const sent = win_io.writeOnce(writer.handle, chunk) catch return error.WriteFailed;
        if (sent == 0) return error.WriteFailed;

        return io_w.consume(sent);
    }

    /// The next bytes owed: whatever is buffered, else the first slice with anything in it. The
    /// last slice is the splat pattern, so it is owed only when splat asks for a copy of it.
    ///
    /// Return:
    /// - []const u8 the chunk to send, never empty
    /// - null when the caller asked for nothing at all
    fn nextChunk(buffered: []const u8, data: []const []const u8, splat: usize) ?[]const u8 {
        if (buffered.len != 0) return buffered;
        if (data.len == 0) return null;

        for (data[0 .. data.len - 1]) |bytes| {
            if (bytes.len != 0) return bytes;
        }

        const pattern = data[data.len - 1];
        if (pattern.len == 0 or splat == 0) return null;

        return pattern;
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

    fn close(pair: *TestPair, io: std.Io) void {
        pair.accepted.close(io);
        pair.client.close(io);
        pair.server.deinit(io);
    }
};

test "zix utils: socket_cut_writer, an uncut socket sends what the peer reads" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TestPair.open(io, 18802);
    defer pair.close(io);

    var write_buf: [64]u8 = undefined;
    var writer = init(pair.accepted, io, &write_buf);

    try writer.interface.writeAll("HTTP/1.1 408 request timeout\r\n\r\n");
    try writer.interface.flush();

    var read_buf: [64]u8 = undefined;
    var reader = pair.client.reader(io, &read_buf);

    var got: [32]u8 = undefined;
    try reader.interface.readSliceAll(&got);
    try testing.expectEqualStrings("HTTP/1.1 408 request timeout\r\n\r\n", &got);
}

test "zix utils: socket_cut_writer, a body past the buffer drains in order" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TestPair.open(io, 18803);
    defer pair.close(io);

    // A buffer far smaller than the payload, so the writer has to drain several times and every
    // partial send has to be accounted for in order.
    var write_buf: [16]u8 = undefined;
    var writer = init(pair.accepted, io, &write_buf);

    var payload: [512]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast('a' + index % 26);

    try writer.interface.writeAll(&payload);
    try writer.interface.flush();

    var read_buf: [128]u8 = undefined;
    var reader = pair.client.reader(io, &read_buf);

    var got: [512]u8 = undefined;
    try reader.interface.readSliceAll(&got);
    try testing.expectEqualSlices(u8, &payload, &got);
}

test "zix utils: socket_cut_writer, the escalation frees a writer parked on a peer that stopped reading" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The client never reads a byte, which fills both socket buffers and parks the sender.
    var pair = try TestPair.open(io, 18804);
    defer pair.close(io);

    const Parked = struct {
        var failed: ?bool = null;

        /// Far more than any platform buffers, so the writer is parked long before the last chunk.
        const TOTAL_BYTES: usize = 64 * 1024 * 1024;

        fn run(stream: std.Io.net.Stream, parked_io: std.Io) void {
            var write_buf: [4096]u8 = undefined;
            var writer = init(stream, parked_io, &write_buf);

            var chunk: [64 * 1024]u8 = @splat('x');
            var sent: usize = 0;

            while (sent < TOTAL_BYTES) : (sent += chunk.len) {
                writer.interface.writeAll(&chunk) catch {
                    failed = true;

                    return;
                };
                writer.interface.flush() catch {
                    failed = true;

                    return;
                };
            }

            failed = false;
        }
    };

    const parked = try std.Thread.spawn(.{}, Parked.run, .{ pair.accepted, io });

    // Give the writer time to fill the buffers and park in its send.
    std.Io.sleep(io, std.Io.Duration.fromMilliseconds(200), .awake) catch {};
    try testing.expect(Parked.failed == null);

    socket_cut.shutdownBoth(pair.accepted.socket.handle);
    parked.join();

    try testing.expectEqual(@as(?bool, true), Parked.failed);
}
