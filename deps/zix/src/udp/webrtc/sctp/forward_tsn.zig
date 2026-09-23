//! zix SCTP FORWARD TSN chunk, partial reliability (RFC 3758 3.2).
//!
//! What:
//! - The chunk a sender uses to say "stop waiting for those, they are never coming". It moves
//!   the receiver's cumulative point forward past data the sender gave up on, and names the
//!   stream sequence each ordered stream was skipped to.
//! - This is what makes an unreliable data channel possible: without it, a message the sender
//!   abandoned would block every later message on the association forever.
//!
//! Note:
//! - Both sides must have announced FORWARD-TSN-SUPPORTED in their INIT (RFC 3758 3.1). Sending
//!   this to a peer that did not is a protocol violation, and the check belongs to the
//!   association that saw both handshakes.
//! - The stream list covers ORDERED streams only. An unordered message has no stream sequence to
//!   skip to, so listing one would tell the receiver to skip messages that were never sent.
//! - The list holds the HIGHEST skipped sequence per stream, one entry per stream, not one per
//!   abandoned message. A sender that abandons five messages on one stream sends one entry.
//! - A receiver applies this even when it has already received some of the TSNs being skipped.
//!   The point moves forward and the runs above it stay, which is what makes it safe to send
//!   more than once.

const std = @import("std");

/// The new cumulative TSN, before any stream entries.
pub const FIXED_LEN: usize = 4;

/// One stream entry: the stream identifier and the sequence it was skipped to.
pub const ENTRY_LEN: usize = 4;

/// Everything that stops a FORWARD TSN from being read or built.
pub const Error = error{
    /// Fewer bytes than the new cumulative TSN needs, or a half entry at the end.
    ZixTruncated,
    /// The output buffer is too small.
    ZixNoSpace,
};

/// One ordered stream and the sequence it was skipped to.
pub const StreamEntry = struct {
    stream_identifier: u16,
    /// The largest stream sequence number being skipped on that stream.
    stream_sequence: u16,
};

/// A parsed FORWARD TSN, borrowing the chunk value it was read from.
pub const ForwardTsn = struct {
    /// Everything up to and including this TSN counts as received.
    new_cumulative_tsn: u32,
    /// The stream entry list, still packed.
    entries: []const u8,

    /// How many streams are named.
    ///
    /// Return:
    /// - usize
    pub fn entryCount(self: ForwardTsn) usize {
        return self.entries.len / ENTRY_LEN;
    }

    /// One stream entry by position.
    ///
    /// Param:
    /// index - usize
    ///
    /// Return:
    /// - ?StreamEntry, null past the end of the list
    pub fn entry(self: ForwardTsn, index: usize) ?StreamEntry {
        if (index >= self.entryCount()) return null;

        const at = index * ENTRY_LEN;

        return .{
            .stream_identifier = std.mem.readInt(u16, self.entries[at..][0..2], .big),
            .stream_sequence = std.mem.readInt(u16, self.entries[at + 2 ..][0..2], .big),
        };
    }

    /// The sequence a given stream was skipped to.
    ///
    /// Param:
    /// stream_identifier - u16
    ///
    /// Return:
    /// - ?u16, null when the stream is not named
    pub fn sequenceFor(self: ForwardTsn, stream_identifier: u16) ?u16 {
        var index: usize = 0;

        while (self.entry(index)) |item| : (index += 1) {
            if (item.stream_identifier == stream_identifier) return item.stream_sequence;
        }

        return null;
    }
};

/// Size of the chunk value for a given number of stream entries.
///
/// Param:
/// entry_count - usize
///
/// Return:
/// - usize
pub fn valueLen(entry_count: usize) usize {
    return FIXED_LEN + entry_count * ENTRY_LEN;
}

/// Read a FORWARD TSN chunk.
///
/// Param:
/// value - []const u8 (chunk value, so everything after the 4-byte chunk header)
///
/// Return:
/// - ForwardTsn borrowing `value`
/// - error.ZixTruncated if the body is short or ends mid-entry
pub fn read(value: []const u8) Error!ForwardTsn {
    if (value.len < FIXED_LEN) return error.ZixTruncated;

    const entries = value[FIXED_LEN..];

    if (entries.len % ENTRY_LEN != 0) return error.ZixTruncated;

    return .{
        .new_cumulative_tsn = std.mem.readInt(u32, value[0..4], .big),
        .entries = entries,
    };
}

/// Write a FORWARD TSN chunk value.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// new_cumulative_tsn - u32 (the point the receiver should move to)
/// entries - []const StreamEntry (ordered streams only, one entry per stream)
///
/// Return:
/// - []const u8 chunk value
/// - error.ZixNoSpace if the buffer cannot hold the TSN and every entry
pub fn write(out: []u8, new_cumulative_tsn: u32, entries: []const StreamEntry) Error![]const u8 {
    const total = valueLen(entries.len);

    if (out.len < total) return error.ZixNoSpace;

    std.mem.writeInt(u32, out[0..4], new_cumulative_tsn, .big);

    var at: usize = FIXED_LEN;

    for (entries) |item| {
        std.mem.writeInt(u16, out[at..][0..2], item.stream_identifier, .big);
        std.mem.writeInt(u16, out[at + 2 ..][0..2], item.stream_sequence, .big);
        at += ENTRY_LEN;
    }

    return out[0..total];
}

// --------------------------------------------------------------------------------------- //
// test cases

test "zix sctp: forward tsn write, a point with no streams round trips" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, 0x0A0B0C0D, &.{});

    try std.testing.expectEqual(FIXED_LEN, value.len);

    const parsed = try read(value);

    try std.testing.expectEqual(@as(u32, 0x0A0B0C0D), parsed.new_cumulative_tsn);
    try std.testing.expectEqual(@as(usize, 0), parsed.entryCount());
    try std.testing.expect(parsed.entry(0) == null);
}

test "zix sctp: forward tsn write, stream entries round trip in order" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, 500, &.{
        .{ .stream_identifier = 1, .stream_sequence = 9 },
        .{ .stream_identifier = 3, .stream_sequence = 41 },
    });

    try std.testing.expectEqual(valueLen(2), value.len);

    const parsed = try read(value);

    try std.testing.expectEqual(@as(usize, 2), parsed.entryCount());
    try std.testing.expectEqual(@as(u16, 1), parsed.entry(0).?.stream_identifier);
    try std.testing.expectEqual(@as(u16, 9), parsed.entry(0).?.stream_sequence);
    try std.testing.expectEqual(@as(u16, 3), parsed.entry(1).?.stream_identifier);
    try std.testing.expectEqual(@as(u16, 41), parsed.entry(1).?.stream_sequence);
}

test "zix sctp: forward tsn read, a named stream is found and an unnamed one is not" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, 500, &.{
        .{ .stream_identifier = 1, .stream_sequence = 9 },
        .{ .stream_identifier = 3, .stream_sequence = 41 },
    });

    const parsed = try read(value);

    try std.testing.expectEqual(@as(u16, 41), parsed.sequenceFor(3).?);
    try std.testing.expect(parsed.sequenceFor(2) == null);
}

test "zix sctp: forward tsn read, a body shorter than the TSN errors" {
    const short: [3]u8 = @splat(0);

    try std.testing.expectError(error.ZixTruncated, read(&short));
}

test "zix sctp: forward tsn read, a body ending mid-entry errors" {
    const ragged: [6]u8 = .{ 0, 0, 0, 5, 0, 1 };

    try std.testing.expectError(error.ZixTruncated, read(&ragged));
}

test "zix sctp: forward tsn write, a buffer too small errors" {
    var buf: [6]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, write(&buf, 5, &.{
        .{ .stream_identifier = 1, .stream_sequence = 1 },
    }));
}

test "zix sctp: forward tsn write, a TSN at the top of its range survives" {
    var buf: [32]u8 = undefined;
    const parsed = try read(try write(&buf, 0xFFFFFFFF, &.{}));

    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), parsed.new_cumulative_tsn);
}

test "zix sctp: forward tsn write, the wire layout is four bytes then pairs" {
    var buf: [32]u8 = undefined;
    const value = try write(&buf, 1, &.{.{ .stream_identifier = 0x0203, .stream_sequence = 0x0405 }});

    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 1, 0x02, 0x03, 0x04, 0x05 }, value);
}
