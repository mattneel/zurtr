//! zix WebRTC data channel registry (RFC 8831 6.4, RFC 8832 6).
//!
//! What:
//! - The set of channels living on one association: which identifiers are taken, which one to
//!   open the next channel on, and what to hand back when a message arrives on a stream.
//!
//! Note:
//! - Admission control lives here, because it is the only place that can see the whole set. A
//!   peer is free to open as many channels as the association has streams and to give each one a
//!   64 KiB label (RFC 8832 7), so a ceiling on both is the difference between a busy endpoint
//!   and one that has run out of memory.
//! - An identifier is free once its channel has been reported closed and removed, never before.
//!   Reusing one while the peer still has the old channel would attach the peer's messages to a
//!   channel it never opened.
//! - `find` hands back a pointer into the table, and `add` may move the table. Finish with one
//!   pointer before adding, which is a rule the callers in this directory follow rather than
//!   something the type can enforce.

const std = @import("std");

const channel = @import("channel.zig");
const stream_id = @import("stream_id.zig");

/// Ceilings that keep one peer from making this endpoint hold memory it did not choose to.
pub const Limits = struct {
    /// How many channels may exist at once, opened from either side.
    max_channels: usize = 64,
    /// Longest label this endpoint accepts.
    max_label_bytes: usize = 256,
    /// Longest protocol name this endpoint accepts.
    max_protocol_bytes: usize = 64,
};

/// Everything that can go wrong holding a set of channels.
pub const Error = error{
    OutOfMemory,
    /// The table is at `max_channels`.
    ZixTooManyChannels,
    /// A channel already sits on that identifier.
    ZixStreamInUse,
    /// A label or protocol longer than this endpoint accepts.
    ZixFieldTooLong,
    /// The identifier belongs to the other side, or is outside what the association negotiated.
    ZixBadStreamIdentifier,
};

/// The channels on one association.
pub const Registry = struct {
    allocator: std.mem.Allocator,
    /// Which half of the identifier space this endpoint opens on.
    role: stream_id.Role,
    limits: Limits,
    entries: std.ArrayList(channel.Channel),

    /// Build an empty registry.
    ///
    /// Param:
    /// allocator - std.mem.Allocator (must reclaim, channels free their label as they go)
    /// role - stream_id.Role (from the DTLS handshake)
    /// limits - Limits
    ///
    /// Return:
    /// - Registry
    pub fn init(allocator: std.mem.Allocator, role: stream_id.Role, limits: Limits) Registry {
        return .{
            .allocator = allocator,
            .role = role,
            .limits = limits,
            .entries = .empty,
        };
    }

    /// Free every channel still held.
    ///
    /// Return:
    /// - void
    pub fn deinit(self: *Registry) void {
        for (self.entries.items) |*item| item.deinit(self.allocator);

        self.entries.deinit(self.allocator);
    }

    /// How many channels exist.
    ///
    /// Return:
    /// - usize
    pub fn count(self: Registry) usize {
        return self.entries.items.len;
    }

    /// The channel on a stream identifier.
    ///
    /// Note:
    /// - The pointer is valid until the next `add` or `remove`.
    ///
    /// Param:
    /// stream_identifier - u16
    ///
    /// Return:
    /// - ?*channel.Channel
    pub fn find(self: *Registry, stream_identifier: u16) ?*channel.Channel {
        for (self.entries.items) |*item| {
            if (item.stream_identifier == stream_identifier) return item;
        }

        return null;
    }

    /// The channel at a position, for walking the whole set.
    ///
    /// Param:
    /// index - usize
    ///
    /// Return:
    /// - ?*channel.Channel
    pub fn at(self: *Registry, index: usize) ?*channel.Channel {
        if (index >= self.entries.items.len) return null;

        return &self.entries.items[index];
    }

    /// Take a channel into the set.
    ///
    /// Note:
    /// - The identifier is checked against the role of whoever opened the channel, which is what
    ///   stops a peer opening on identifiers this endpoint hands out (RFC 8832 6).
    ///
    /// Param:
    /// fields - channel.Fields
    /// negotiated_streams - u16 (streams the association settled on)
    ///
    /// Return:
    /// - *channel.Channel, valid until the next `add` or `remove`
    /// - error.ZixTooManyChannels, error.ZixStreamInUse, error.ZixBadStreamIdentifier, error.ZixFieldTooLong
    /// - error.OutOfMemory
    pub fn add(self: *Registry, fields: channel.Fields, negotiated_streams: u16) Error!*channel.Channel {
        if (self.entries.items.len >= self.limits.max_channels) return error.ZixTooManyChannels;
        if (fields.label.len > self.limits.max_label_bytes) return error.ZixFieldTooLong;
        if (fields.protocol.len > self.limits.max_protocol_bytes) return error.ZixFieldTooLong;
        if (!self.mayOpen(fields.stream_identifier, fields.opener, negotiated_streams)) {
            return error.ZixBadStreamIdentifier;
        }
        if (self.find(fields.stream_identifier) != null) return error.ZixStreamInUse;

        const opened = try channel.Channel.init(self.allocator, fields);
        errdefer {
            var owned = opened;
            owned.deinit(self.allocator);
        }

        try self.entries.append(self.allocator, opened);

        return &self.entries.items[self.entries.items.len - 1];
    }

    /// Drop a channel and free what it holds.
    ///
    /// Param:
    /// stream_identifier - u16
    ///
    /// Return:
    /// - bool, whether there was one to drop
    pub fn remove(self: *Registry, stream_identifier: u16) bool {
        for (self.entries.items, 0..) |*item, index| {
            if (item.stream_identifier != stream_identifier) continue;

            item.deinit(self.allocator);
            _ = self.entries.orderedRemove(index);

            return true;
        }

        return false;
    }

    /// Drop one channel that has finished closing, if there is one.
    ///
    /// Note:
    /// - This is what frees an identifier for reuse, so it is called once the close has been
    ///   reported to the application and not before.
    ///
    /// Return:
    /// - ?u16, the identifier that is now free
    pub fn takeClosed(self: *Registry) ?u16 {
        for (self.entries.items) |item| {
            if (item.state != .CLOSED) continue;

            const identifier = item.stream_identifier;
            _ = self.remove(identifier);

            return identifier;
        }

        return null;
    }

    /// The lowest identifier this endpoint may open a new channel on.
    ///
    /// Param:
    /// negotiated_streams - u16 (streams the association settled on)
    ///
    /// Return:
    /// - ?u16, null when every identifier this endpoint owns is taken
    pub fn availableIdentifier(self: *Registry, negotiated_streams: u16) ?u16 {
        var candidate: ?u16 = stream_id.first(self.role);

        while (candidate) |identifier| : (candidate = stream_id.next(identifier)) {
            if (!stream_id.usable(identifier, negotiated_streams)) return null;
            if (self.find(identifier) == null) return identifier;
        }

        return null;
    }

    /// Whether a channel may be opened on an identifier by the side that asked.
    fn mayOpen(self: Registry, stream_identifier: u16, opener: bool, negotiated_streams: u16) bool {
        if (!stream_id.usable(stream_identifier, negotiated_streams)) return false;

        const expected = if (opener) self.role else stream_id.peerRole(self.role);

        return stream_id.ownedBy(expected, stream_identifier);
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

const NEGOTIATED: u16 = 128;

test "zix datachannel: registry init, an empty registry holds nothing" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{});
    defer channels.deinit();

    try std.testing.expectEqual(@as(usize, 0), channels.count());
    try std.testing.expectEqual(@as(?*channel.Channel, null), channels.find(0));
}

test "zix datachannel: registry add, a channel is found on its identifier" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{});
    defer channels.deinit();

    _ = try channels.add(.{ .stream_identifier = 0, .label = "chat", .opener = true }, NEGOTIATED);

    const found = channels.find(0) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqualStrings("chat", found.label);
    try std.testing.expectEqual(@as(usize, 1), channels.count());
}

test "zix datachannel: registry add, the same identifier twice is refused" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{});
    defer channels.deinit();

    _ = try channels.add(.{ .stream_identifier = 0, .opener = true }, NEGOTIATED);

    try std.testing.expectError(
        error.ZixStreamInUse,
        channels.add(.{ .stream_identifier = 0, .opener = true }, NEGOTIATED),
    );
}

test "zix datachannel: registry add, this endpoint cannot open on the peer's half" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{});
    defer channels.deinit();

    try std.testing.expectError(
        error.ZixBadStreamIdentifier,
        channels.add(.{ .stream_identifier = 1, .opener = true }, NEGOTIATED),
    );
}

test "zix datachannel: registry add, the peer cannot open on this endpoint's half" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{});
    defer channels.deinit();

    // Accepting this would let the peer take an identifier this endpoint is about to hand out.
    try std.testing.expectError(
        error.ZixBadStreamIdentifier,
        channels.add(.{ .stream_identifier = 2, .opener = false }, NEGOTIATED),
    );
}

test "zix datachannel: registry add, an identifier past the negotiated streams is refused" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{});
    defer channels.deinit();

    try std.testing.expectError(
        error.ZixBadStreamIdentifier,
        channels.add(.{ .stream_identifier = 128, .opener = true }, NEGOTIATED),
    );
}

test "zix datachannel: registry add, the table stops at its ceiling" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{ .max_channels = 2 });
    defer channels.deinit();

    _ = try channels.add(.{ .stream_identifier = 0, .opener = true }, NEGOTIATED);
    _ = try channels.add(.{ .stream_identifier = 2, .opener = true }, NEGOTIATED);

    try std.testing.expectError(
        error.ZixTooManyChannels,
        channels.add(.{ .stream_identifier = 4, .opener = true }, NEGOTIATED),
    );
}

test "zix datachannel: registry add, a label past the ceiling is refused" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{ .max_label_bytes = 4 });
    defer channels.deinit();

    try std.testing.expectError(
        error.ZixFieldTooLong,
        channels.add(.{ .stream_identifier = 0, .label = "far too long", .opener = true }, NEGOTIATED),
    );
}

test "zix datachannel: registry add, a protocol past the ceiling is refused" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{ .max_protocol_bytes = 2 });
    defer channels.deinit();

    try std.testing.expectError(
        error.ZixFieldTooLong,
        channels.add(.{ .stream_identifier = 0, .protocol = "zix", .opener = true }, NEGOTIATED),
    );
}

test "zix datachannel: registry availableIdentifier, the client walks the even half" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{});
    defer channels.deinit();

    try std.testing.expectEqual(@as(?u16, 0), channels.availableIdentifier(NEGOTIATED));

    _ = try channels.add(.{ .stream_identifier = 0, .opener = true }, NEGOTIATED);

    try std.testing.expectEqual(@as(?u16, 2), channels.availableIdentifier(NEGOTIATED));

    _ = try channels.add(.{ .stream_identifier = 2, .opener = true }, NEGOTIATED);

    try std.testing.expectEqual(@as(?u16, 4), channels.availableIdentifier(NEGOTIATED));
}

test "zix datachannel: registry availableIdentifier, the server walks the odd half" {
    var channels = Registry.init(std.testing.allocator, .DTLS_SERVER, .{});
    defer channels.deinit();

    try std.testing.expectEqual(@as(?u16, 1), channels.availableIdentifier(NEGOTIATED));

    _ = try channels.add(.{ .stream_identifier = 1, .opener = true }, NEGOTIATED);

    try std.testing.expectEqual(@as(?u16, 3), channels.availableIdentifier(NEGOTIATED));
}

test "zix datachannel: registry availableIdentifier, a channel the peer opened does not take a turn" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{});
    defer channels.deinit();

    _ = try channels.add(.{ .stream_identifier = 1, .opener = false }, NEGOTIATED);

    // The peer's channel sits in the odd half, so nothing this endpoint hands out moves.
    try std.testing.expectEqual(@as(?u16, 0), channels.availableIdentifier(NEGOTIATED));
}

test "zix datachannel: registry availableIdentifier, a narrow association runs out" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{});
    defer channels.deinit();

    _ = try channels.add(.{ .stream_identifier = 0, .opener = true }, 2);

    try std.testing.expectEqual(@as(?u16, null), channels.availableIdentifier(2));
}

test "zix datachannel: registry remove, the identifier becomes available again" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{});
    defer channels.deinit();

    _ = try channels.add(.{ .stream_identifier = 0, .opener = true }, NEGOTIATED);

    try std.testing.expect(channels.remove(0));
    try std.testing.expectEqual(@as(usize, 0), channels.count());
    try std.testing.expectEqual(@as(?u16, 0), channels.availableIdentifier(NEGOTIATED));
}

test "zix datachannel: registry remove, an identifier with no channel says so" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{});
    defer channels.deinit();

    try std.testing.expect(!channels.remove(0));
}

test "zix datachannel: registry takeClosed, only a finished channel is taken" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{});
    defer channels.deinit();

    const opened = try channels.add(.{ .stream_identifier = 0, .opener = true }, NEGOTIATED);
    opened.beginClosing();

    try std.testing.expectEqual(@as(?u16, null), channels.takeClosed());

    opened.noteOutgoingReset();
    opened.noteIncomingReset();

    try std.testing.expectEqual(@as(?u16, 0), channels.takeClosed());
    try std.testing.expectEqual(@as(?u16, null), channels.takeClosed());
    try std.testing.expectEqual(@as(usize, 0), channels.count());
}

test "zix datachannel: registry at, the whole set can be walked" {
    var channels = Registry.init(std.testing.allocator, .DTLS_CLIENT, .{});
    defer channels.deinit();

    _ = try channels.add(.{ .stream_identifier = 0, .opener = true }, NEGOTIATED);
    _ = try channels.add(.{ .stream_identifier = 2, .opener = true }, NEGOTIATED);

    var seen: usize = 0;
    var index: usize = 0;
    while (channels.at(index)) |item| : (index += 1) {
        try std.testing.expectEqual(@as(u16, @intCast(index * 2)), item.stream_identifier);
        seen += 1;
    }

    try std.testing.expectEqual(@as(usize, 2), seen);
}
