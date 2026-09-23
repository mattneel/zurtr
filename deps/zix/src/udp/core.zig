//! zix udp raw-bytes core types (ADR-049): the handler signature and the reply sink.

const std = @import("std");
const datagram = @import("datagram.zig");

const posix = std.posix;
const IpAddress = std.Io.net.IpAddress;

// --------------------------------------------------------- //

/// The reply queue handed to a raw handler. Replies are copied into the batch and flushed together,
/// so handler-local reply bytes are safe and the sender path needs no address conversion.
pub const Sink = struct {
    batch: *datagram.SendBatch,
    fd: posix.socket_t,
    sender: posix.sockaddr.in6,

    /// Reply to the sender of the datagram currently being handled (no address conversion).
    pub fn reply(self: *Sink, bytes: []const u8) void {
        self.enqueue(self.sender, bytes);
    }

    /// Reply to an explicit peer.
    pub fn replyTo(self: *Sink, peer: *const IpAddress, bytes: []const u8) void {
        self.enqueue(datagram.ipToSockaddr6(peer.*), bytes);
    }

    fn enqueue(self: *Sink, dest: posix.sockaddr.in6, bytes: []const u8) void {
        if (self.batch.queue(dest, bytes)) return;

        // The batch is full: flush what is queued, then queue this reply into the empty batch.
        self.batch.flush(self.fd) catch return;
        _ = self.batch.queue(dest, bytes);
    }
};

/// A raw datagram handler: the datagram bytes, the peer, and a sink to reply through.
pub const HandlerFn = *const fn (datagram: []const u8, peer: *const IpAddress, sink: *Sink) void;

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix udp: Sink coalesces replies into the batch" {
    var batch = try datagram.SendBatch.init(std.testing.allocator, 4, 64);
    defer batch.deinit();

    const sender = try datagram.parseBind("127.0.0.1", 5000);
    var sink = Sink{ .batch = &batch, .fd = undefined, .sender = sender };

    sink.reply("one");
    const peer = try std.Io.net.IpAddress.parse("10.0.0.2", 6000);
    sink.replyTo(&peer, "two");

    try std.testing.expectEqual(@as(usize, 2), batch.count);
    try std.testing.expectEqualStrings("onetwo", batch.data[0..batch.used]);
}
