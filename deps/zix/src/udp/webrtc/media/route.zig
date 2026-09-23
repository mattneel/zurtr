//! zix media routes into one receiver (RFC 3550 5.1, RFC 7667 3.7).
//!
//! What:
//! - Which source feeds which of one receiver's streams, and how that source's numbering is
//!   presented there. One of these belongs to each receiving peer.
//!
//! Note:
//! - A forwarder cannot pass a source's numbering along untouched forever. The moment one output
//!   stream is fed by a different source, the sequence numbers and the timestamps jump, and the
//!   receiver reads a jump as loss. The offsets in forward.Mapping are what hides that, and this
//!   table is where they are kept.
//! - The default route is the source's own identifier with no offsets, which is what a broadcast
//!   of one sender needs and is the honest thing to start from: nothing has been renumbered yet.
//! - What was last sent is tracked per route, because a source switch is computed from it and a
//!   retransmission request is answered against it. Neither is answerable from the mapping alone.
//! - Bounded and allocation-free, the same as the stream set beside it.

const std = @import("std");

const forward = @import("forward.zig");
const rtp = @import("rtp.zig");

/// How many sources may feed one receiver.
pub const MAX_ROUTES: usize = 8;

/// What stops a route from being admitted.
pub const Error = error{
    /// This receiver already carries MAX_ROUTES sources.
    ZixTooManyRoutes,
};

/// One source, as one receiver sees it.
pub const Route = struct {
    /// The identifier the source sends under.
    source_ssrc: u32,
    /// How that source's numbering is presented to this receiver.
    mapping: forward.Mapping,
    /// The last numbers this route put on the wire, for a switch and for a retransmission.
    last_sequence: u16 = 0,
    last_timestamp: u32 = 0,
    /// False until the first packet, so the two fields above are not read as real numbers.
    started: bool = false,

    /// Record what a forwarded packet carried.
    ///
    /// Param:
    /// header - rtp.Header (the source's own header, before the mapping is applied)
    ///
    /// Return:
    /// - void
    pub fn sent(self: *Route, header: rtp.Header) void {
        self.last_sequence = self.mapping.sequenceFor(header.sequence);
        self.last_timestamp = self.mapping.timestampFor(header.timestamp);
        self.started = true;
    }
};

/// Every source feeding one receiver.
///
/// Usage:
/// ```zig
/// var routes: Table = .{};
/// const carried = try routes.admit(header.ssrc);
///
/// const packet = try forward.reseal(stream, carried.mapping, buffer, plain_len);
/// carried.sent(header);
/// ```
pub const Table = struct {
    entries: [MAX_ROUTES]Route = undefined,
    /// How many sources this receiver carries.
    live: usize = 0,

    /// The route for a source, admitting it the first time it is seen.
    ///
    /// Note:
    /// - A source arrives on its own identifier and with no offsets. Renumbering starts when
    ///   `switchSource` is called and not before.
    ///
    /// Param:
    /// source_ssrc - u32 (the identifier the sending peer put on the packet)
    ///
    /// Return:
    /// - *Route, valid until this table is written over
    /// - error.ZixTooManyRoutes
    pub fn admit(self: *Table, source_ssrc: u32) Error!*Route {
        if (self.find(source_ssrc)) |known| return known;

        if (self.live == MAX_ROUTES) return error.ZixTooManyRoutes;

        self.entries[self.live] = .{
            .source_ssrc = source_ssrc,
            .mapping = .{ .ssrc = source_ssrc },
        };
        self.live += 1;

        return &self.entries[self.live - 1];
    }

    /// The route for a source already admitted, or null.
    ///
    /// Param:
    /// source_ssrc - u32
    ///
    /// Return:
    /// - ?*Route
    pub fn find(self: *Table, source_ssrc: u32) ?*Route {
        for (self.entries[0..self.live]) |*entry| {
            if (entry.source_ssrc == source_ssrc) return entry;
        }

        return null;
    }

    /// The source behind one of this receiver's streams.
    ///
    /// Note:
    /// - The direction a keyframe request travels. A receiver names the identifier it sees, and
    ///   the peer that has to be asked is the one sending under the identifier this gives back.
    ///
    /// Param:
    /// carried_ssrc - u32 (the identifier this receiver sees)
    ///
    /// Return:
    /// - ?u32
    pub fn sourceOf(self: *Table, carried_ssrc: u32) ?u32 {
        for (self.entries[0..self.live]) |*entry| {
            if (entry.mapping.ssrc == carried_ssrc) return entry.source_ssrc;
        }

        return null;
    }

    /// Feed an output stream from a different source, continuing its numbering.
    ///
    /// Note:
    /// - The output identifier is kept, so the receiver sees one stream that never stopped. The
    ///   new source picks up at the number after the last one sent.
    /// - Whoever was feeding that stream is dropped here. One output stream has one source, and
    ///   leaving the old one in the table means a keyframe request is answered by asking a peer
    ///   that stopped sending.
    /// - A stream that has sent nothing yet takes the new source unchanged, because there is no
    ///   numbering to continue from.
    ///
    /// Param:
    /// carried_ssrc - u32 (the identifier this receiver already sees)
    /// source_ssrc - u32 (the identifier of the source taking over)
    /// first - rtp.Header (that source's first packet)
    ///
    /// Return:
    /// - *Route for the new source
    /// - error.ZixTooManyRoutes
    pub fn switchSource(
        self: *Table,
        carried_ssrc: u32,
        source_ssrc: u32,
        first: rtp.Header,
    ) Error!*Route {
        var next_sequence: u16 = first.sequence;
        var next_timestamp: u32 = first.timestamp;

        var index: usize = 0;
        while (index < self.live) {
            const entry = &self.entries[index];

            if (entry.mapping.ssrc != carried_ssrc or entry.source_ssrc == source_ssrc) {
                index += 1;

                continue;
            }

            if (entry.started) {
                next_sequence = entry.last_sequence +% 1;
                next_timestamp = entry.last_timestamp;
            }

            self.entries[index] = self.entries[self.live - 1];
            self.live -= 1;
        }

        const route = try self.admit(source_ssrc);
        route.mapping = forward.Mapping.continuing(carried_ssrc, first, next_sequence, next_timestamp);

        return route;
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

/// One header of `ssrc`, so a test reads as a packet arriving and not as four numbers.
fn sourceHeader(ssrc: u32, sequence: u16, timestamp: u32) rtp.Header {
    return .{
        .has_padding = false,
        .has_extension = false,
        .csrc_count = 0,
        .marker = false,
        .payload_type = 96,
        .sequence = sequence,
        .timestamp = timestamp,
        .ssrc = ssrc,
    };
}

test "zix media: route admit, a new source arrives on its own identifier with nothing renumbered" {
    var routes: Table = .{};

    try std.testing.expectEqual(@as(usize, 0), routes.live);
    try std.testing.expect(routes.find(0x1111_1111) == null);

    const route = try routes.admit(0x1111_1111);

    try std.testing.expectEqual(@as(u32, 0x1111_1111), route.mapping.ssrc);
    try std.testing.expectEqual(@as(u16, 0), route.mapping.sequence_offset);
    try std.testing.expectEqual(@as(u32, 0), route.mapping.timestamp_offset);
    try std.testing.expect(!route.started);
}

test "zix media: route admit, the same source comes back to the same route" {
    var routes: Table = .{};

    const first = try routes.admit(0x1111_1111);
    first.mapping.sequence_offset = 500;

    const again = try routes.admit(0x1111_1111);

    try std.testing.expectEqual(first, again);
    try std.testing.expectEqual(@as(u16, 500), again.mapping.sequence_offset);
    try std.testing.expectEqual(@as(usize, 1), routes.live);
}

test "zix media: route sent, what went out is what the mapping made of the source" {
    var routes: Table = .{};

    const route = try routes.admit(0x1111_1111);
    route.mapping.sequence_offset = 1000;
    route.mapping.timestamp_offset = 90000;

    route.sent(sourceHeader(0x1111_1111, 100, 9000));

    try std.testing.expect(route.started);
    try std.testing.expectEqual(@as(u16, 1100), route.last_sequence);
    try std.testing.expectEqual(@as(u32, 99000), route.last_timestamp);
}

test "zix media: route switchSource, the receiver's stream picks up where it stopped" {
    var routes: Table = .{};

    const first = try routes.admit(0x1111_1111);
    first.sent(sourceHeader(0x1111_1111, 500, 42000));

    // A second source takes over the stream the receiver already sees, starting its own numbering
    // wherever RTP happened to start it.
    const second = try routes.switchSource(0x1111_1111, 0x2222_2222, sourceHeader(0x2222_2222, 20000, 777000));

    try std.testing.expectEqual(@as(u32, 0x1111_1111), second.mapping.ssrc);
    try std.testing.expectEqual(@as(u16, 501), second.mapping.sequenceFor(20000));
    try std.testing.expectEqual(@as(u32, 42000), second.mapping.timestampFor(777000));
    try std.testing.expectEqual(@as(u16, 502), second.mapping.sequenceFor(20001));
}

test "zix media: route switchSource, a stream that has sent nothing takes the source unchanged" {
    var routes: Table = .{};

    _ = try routes.admit(0x1111_1111);

    const taken = try routes.switchSource(0x1111_1111, 0x2222_2222, sourceHeader(0x2222_2222, 20000, 777000));

    try std.testing.expectEqual(@as(u16, 20000), taken.mapping.sequenceFor(20000));
    try std.testing.expectEqual(@as(u32, 777000), taken.mapping.timestampFor(777000));
}

test "zix media: route sourceSequence, a request names the number the receiver saw" {
    // The direction a retransmission request travels: back through the mapping, to the number the
    // source itself sent.
    var routes: Table = .{};

    const route = try routes.admit(0x1111_1111);
    route.mapping.sequence_offset = 1000;

    route.sent(sourceHeader(0x1111_1111, 100, 9000));

    try std.testing.expectEqual(@as(u16, 100), route.mapping.sourceSequence(route.last_sequence));
}

test "zix media: route sourceOf, the identifier a receiver sees names the peer to ask" {
    var routes: Table = .{};

    _ = try routes.admit(0x1111_1111);

    // Before any switch the two identifiers are the same one.
    try std.testing.expectEqual(@as(?u32, 0x1111_1111), routes.sourceOf(0x1111_1111));
    try std.testing.expectEqual(@as(?u32, null), routes.sourceOf(0x9999_9999));

    // After a switch the receiver still names the old identifier, and the peer to ask is the new
    // source behind it.
    _ = try routes.switchSource(0x1111_1111, 0x2222_2222, sourceHeader(0x2222_2222, 20000, 777000));

    try std.testing.expectEqual(@as(?u32, 0x2222_2222), routes.sourceOf(0x1111_1111));
    try std.testing.expectEqual(@as(usize, 1), routes.live);
}

test "zix media: route admit, a receiver past the ceiling is refused" {
    var routes: Table = .{};

    for (0..MAX_ROUTES) |index| {
        _ = try routes.admit(@intCast(index + 1));
    }

    try std.testing.expectError(error.ZixTooManyRoutes, routes.admit(0xFFFF_FFFF));
    try std.testing.expect(routes.find(1) != null);
}
