//! zix WebRTC data channel stream reset driver (RFC 6525 5, RFC 8831 6.7).
//!
//! What:
//! - The half of RFC 6525 a data channel actually uses: ask the peer to let one stream go back to
//!   sequence zero, answer the same ask coming the other way, and keep the request numbering
//!   straight in both directions.
//!
//! Note:
//! - Exactly one request may be outstanding at a time (RFC 6525 5.1.1). A second one is refused
//!   here rather than queued, because the layer above already knows which channels are waiting to
//!   close and can ask again on its next turn.
//! - One request names one stream. The wire form allows a list and this reader accepts one, since
//!   a peer may batch. Sending one at a time keeps the outstanding request tied to a single
//!   channel, which is what makes an answer unambiguous.
//! - A RE-CONFIG chunk is not carried by a TSN, so it can overtake DATA chunks that are still
//!   being retransmitted. That is why RFC 6525 5.2.2 E2 exists: a reset whose Sender's Last
//!   Assigned TSN is ahead of what has arrived is held, answered "In progress", and performed
//!   once the gap closes. Without that hold, closing a channel drops the last message sent on it.
//! - A repeat of a request already answered gets the same answer again and is not performed twice
//!   (RFC 6525 5.2.1). A retransmitted request looks exactly like a new one otherwise.
//! - An Incoming SSN Reset request is answered "Denied". RFC 8831 6.7 closes a channel by
//!   resetting the sender's own outgoing stream, so a peer asking this endpoint to reset its
//!   outgoing stream is not part of a data channel close, and a clear refusal is better than a
//!   partial implementation of a path nothing here takes.
//! - An SSN/TSN reset is not answered at all. Performing one means rewinding both TSN counters
//!   mid-association, which nothing in this stack can do, and there is no reader for it here.

const std = @import("std");

const parameter = @import("../sctp/parameter.zig");
const reconfig = @import("../sctp/reconfig.zig");
const serial = @import("../sctp/serial.zig");

/// Room for one request or one answer, which is a single parameter naming at most one stream.
pub const MAX_VALUE_BYTES: usize = 64;

/// How many streams a held request can name. A batching peer past this is refused rather than
/// half-performed.
pub const MAX_DEFERRED_STREAMS: usize = 8;

/// Everything that can go wrong driving a reset.
pub const Error = error{
    /// A parameter longer than the buffers here.
    ZixNoSpace,
    /// A parameter region that ends mid-parameter.
    ZixTruncated,
    /// A parameter length below the parameter header size.
    ZixBadLength,
};

/// The answer to a request this endpoint sent.
pub const Completed = struct {
    request_sequence: u32,
    /// The stream the request named.
    stream_identifier: u16,
    result: reconfig.Result,

    /// Whether the peer performed the reset, or found nothing that needed doing.
    ///
    /// Return:
    /// - bool
    pub fn isSuccess(self: Completed) bool {
        return switch (self.result) {
            .SUCCESS_NOTHING_TO_DO, .SUCCESS_PERFORMED => true,
            else => false,
        };
    }
};

/// What one arriving RE-CONFIG chunk turned out to be.
pub const Handled = struct {
    /// The peer reset these outgoing streams of its own, so nothing more arrives on them.
    /// Borrowed from the chunk value. Absent when the request was held or refused.
    peer_reset: ?reconfig.OutgoingReset = null,
    /// The peer answered a request from here.
    completed: ?Completed = null,
};

/// A held request that has now been performed.
pub const Release = struct {
    streams: [MAX_DEFERRED_STREAMS]u16,
    /// How many of `streams` are filled.
    count: usize,
    /// The request named no streams, which means every one of them.
    all: bool,
};

/// A request held until the data in front of it arrives (RFC 6525 5.2.2 E2).
const Deferred = struct {
    request_sequence: u32,
    last_assigned_tsn: u32,
    /// Copied, because the request does not outlive the datagram it came in.
    streams: [MAX_DEFERRED_STREAMS]u16,
    count: usize,
    all: bool,
};

/// The last request answered, so a retransmission of it gets the same answer.
const Answered = struct {
    request_sequence: u32,
    result: reconfig.Result,
};

/// Drives stream resets over one association.
///
/// Usage:
/// ```zig
/// var driver = Driver.init(local_initial_tsn, peer_initial_tsn);
///
/// if (try driver.requestReset(stream_identifier, association.lastAssignedTsn())) {
///     // A packet carrying it goes out on the next turn.
/// }
///
/// if (driver.nextPending()) |value| _ = try association.sendReconfig(value, &out);
/// ```
pub const Driver = struct {
    /// The sequence number the next request from here carries (RFC 6525 4.1).
    next_request_sequence: u32,
    /// The sequence number the peer's next request is expected to carry.
    peer_next_sequence: u32,
    /// The outstanding request, kept so the retransmission RFC 6525 5.1.1 asks for can resend
    /// the same bytes. Length zero means there is none.
    request: [MAX_VALUE_BYTES]u8,
    request_len: usize,
    request_sequence: u32,
    request_stream: u16,
    request_sent: bool,
    /// The answer to the peer's request, waiting to go out. Length zero means there is none.
    answer: [MAX_VALUE_BYTES]u8,
    answer_len: usize,
    deferred: ?Deferred,
    last_answered: ?Answered,

    /// Build a driver for one association.
    ///
    /// Note:
    /// - Both counters start at the initial TSN of the side that owns them, which is what
    ///   RFC 6525 4.1 says a request sequence number is initialized to.
    ///
    /// Param:
    /// initial_tsn - u32 (this endpoint's first TSN)
    /// peer_initial_tsn - u32 (the peer's first TSN, from its INIT or INIT ACK)
    ///
    /// Return:
    /// - Driver
    pub fn init(initial_tsn: u32, peer_initial_tsn: u32) Driver {
        return .{
            .next_request_sequence = initial_tsn,
            .peer_next_sequence = peer_initial_tsn,
            .request = @splat(0),
            .request_len = 0,
            .request_sequence = 0,
            .request_stream = 0,
            .request_sent = false,
            .answer = @splat(0),
            .answer_len = 0,
            .deferred = null,
            .last_answered = null,
        };
    }

    /// Whether a request is already waiting for its answer.
    ///
    /// Return:
    /// - bool
    pub fn isBusy(self: Driver) bool {
        return self.request_len != 0;
    }

    /// Ask the peer to let one outgoing stream go back to sequence zero.
    ///
    /// Note:
    /// - The last assigned TSN is what tells the peer how much data to take before performing
    ///   the reset, so it has to be the last TSN this endpoint handed out, not the next one.
    ///
    /// Param:
    /// stream_identifier - u16
    /// last_assigned_tsn - u32 (the last TSN this endpoint assigned to a DATA chunk)
    ///
    /// Return:
    /// - bool, false when a request is already outstanding and this one has to wait
    /// - error.ZixNoSpace, error.ZixBadLength
    pub fn requestReset(self: *Driver, stream_identifier: u16, last_assigned_tsn: u32) Error!bool {
        if (self.isBusy()) return false;

        const sequence = self.next_request_sequence;
        const written = reconfig.writeOutgoingReset(&self.request, .{
            .request_sequence = sequence,
            // The peer reads this to match one of its own requests, and there is none being
            // answered here, so it names the last sequence the peer is known to have used.
            .response_sequence = serial.Tsn.previous(self.peer_next_sequence),
            .last_assigned_tsn = last_assigned_tsn,
        }, &.{stream_identifier}) catch |err| switch (err) {
            error.ZixNoSpace => return error.ZixNoSpace,
            error.ZixBadLength => return error.ZixBadLength,
            error.ZixTruncated => return error.ZixTruncated,
        };

        self.request_len = written.len;
        self.request_sequence = sequence;
        self.request_stream = stream_identifier;
        self.request_sent = false;
        self.next_request_sequence = serial.Tsn.next(sequence);

        return true;
    }

    /// The next RE-CONFIG value that has to go out.
    ///
    /// Note:
    /// - An answer goes before a request, because the peer is waiting on the answer and this
    ///   endpoint is only waiting on itself.
    /// - The slice borrows the driver and stays valid until the next call that builds one.
    ///
    /// Return:
    /// - ?[]const u8, a whole RE-CONFIG chunk value
    pub fn nextPending(self: *Driver) ?[]const u8 {
        if (self.answer_len != 0) {
            const len = self.answer_len;
            self.answer_len = 0;

            return self.answer[0..len];
        }

        if (self.request_len == 0 or self.request_sent) return null;

        self.request_sent = true;

        return self.request[0..self.request_len];
    }

    /// The outstanding request again, for the retransmission its timer asks for.
    ///
    /// Return:
    /// - ?[]const u8, null when nothing is outstanding or it has not gone out once yet
    pub fn retransmit(self: *Driver) ?[]const u8 {
        if (self.request_len == 0 or !self.request_sent) return null;

        return self.request[0..self.request_len];
    }

    /// Handle one arriving RE-CONFIG chunk value.
    ///
    /// Note:
    /// - Any answer this produces is left waiting for `nextPending`, so one buffer serves both
    ///   the chunk that arrived and the one going back.
    ///
    /// Param:
    /// value - []const u8 (borrowed, everything after the chunk header)
    /// cumulative_tsn - u32 (the highest TSN with nothing missing below it)
    ///
    /// Return:
    /// - Handled, borrowing `value`
    /// - error.ZixTruncated, error.ZixBadLength, error.ZixNoSpace
    pub fn handleValue(self: *Driver, value: []const u8, cumulative_tsn: u32) Error!Handled {
        parameter.validate(value) catch |err| switch (err) {
            error.ZixTruncated => return error.ZixTruncated,
            error.ZixBadLength => return error.ZixBadLength,
            error.ZixNoSpace => return error.ZixNoSpace,
        };

        var outcome: Handled = .{};
        var iterator = parameter.Iterator{ .region = value };

        while (iterator.next()) |item| {
            switch (item.kind) {
                .OUTGOING_SSN_RESET => outcome.peer_reset = try self.onOutgoingReset(item.value, cumulative_tsn),
                .RECONFIG_RESPONSE => outcome.completed = try self.onResponse(item.value),
                .INCOMING_SSN_RESET => try self.denyIncomingReset(item.value),
                .ADD_OUTGOING_STREAMS, .ADD_INCOMING_STREAMS => try self.denyAddStreams(item.value),
                else => {},
            }
        }

        return outcome;
    }

    /// Perform a held request once the data in front of it has arrived.
    ///
    /// Param:
    /// cumulative_tsn - u32 (the highest TSN with nothing missing below it)
    ///
    /// Return:
    /// - ?Release, the streams to reset now
    /// - error.ZixNoSpace
    pub fn releaseDeferred(self: *Driver, cumulative_tsn: u32) Error!?Release {
        const held = self.deferred orelse return null;

        if (serial.Tsn.greaterThan(held.last_assigned_tsn, cumulative_tsn)) return null;

        try self.buildAnswer(held.request_sequence, .SUCCESS_PERFORMED);

        self.last_answered = .{ .request_sequence = held.request_sequence, .result = .SUCCESS_PERFORMED };
        self.deferred = null;

        return .{ .streams = held.streams, .count = held.count, .all = held.all };
    }

    /// An Outgoing SSN Reset arrived, which is the peer closing one or more channels.
    fn onOutgoingReset(self: *Driver, value: []const u8, cumulative_tsn: u32) Error!?reconfig.OutgoingReset {
        const request = reconfig.readOutgoingReset(value) catch |err| switch (err) {
            error.ZixTruncated => return error.ZixTruncated,
            error.ZixBadLength => return error.ZixBadLength,
            error.ZixNoSpace => return error.ZixNoSpace,
        };

        if (self.last_answered) |answered| {
            if (answered.request_sequence == request.request_sequence) {
                // A retransmission of something already dealt with. The same answer goes back
                // and nothing is performed a second time (RFC 6525 5.2.1).
                try self.buildAnswer(answered.request_sequence, answered.result);

                return null;
            }
        }

        if (request.request_sequence != self.peer_next_sequence) {
            try self.buildAnswer(request.request_sequence, .ERROR_BAD_SEQUENCE_NUMBER);

            return null;
        }

        self.peer_next_sequence = serial.Tsn.next(self.peer_next_sequence);

        if (serial.Tsn.greaterThan(request.last_assigned_tsn, cumulative_tsn)) {
            return try self.holdRequest(request);
        }

        try self.buildAnswer(request.request_sequence, .SUCCESS_PERFORMED);

        self.last_answered = .{ .request_sequence = request.request_sequence, .result = .SUCCESS_PERFORMED };

        return request;
    }

    /// Hold a request whose data has not all arrived (RFC 6525 5.2.2 E2).
    fn holdRequest(self: *Driver, request: reconfig.OutgoingReset) Error!?reconfig.OutgoingReset {
        if (request.streamCount() > MAX_DEFERRED_STREAMS) {
            // Holding it means copying the list, and refusing is better than performing a reset
            // that would drop data still on its way.
            try self.buildAnswer(request.request_sequence, .DENIED);

            self.last_answered = .{ .request_sequence = request.request_sequence, .result = .DENIED };

            return null;
        }

        var held: Deferred = .{
            .request_sequence = request.request_sequence,
            .last_assigned_tsn = request.last_assigned_tsn,
            .streams = @splat(0),
            .count = request.streamCount(),
            .all = request.streamCount() == 0,
        };

        for (0..held.count) |index| held.streams[index] = request.stream(index).?;

        try self.buildAnswer(request.request_sequence, .IN_PROGRESS);

        self.deferred = held;
        self.last_answered = .{ .request_sequence = request.request_sequence, .result = .IN_PROGRESS };

        return null;
    }

    /// A Re-configuration Response arrived, which answers a request from here.
    fn onResponse(self: *Driver, value: []const u8) Error!?Completed {
        const response = reconfig.readResponse(value) catch |err| switch (err) {
            error.ZixTruncated => return error.ZixTruncated,
            error.ZixBadLength => return error.ZixBadLength,
            error.ZixNoSpace => return error.ZixNoSpace,
        };

        if (self.request_len == 0) return null;
        if (response.response_sequence != self.request_sequence) return null;

        // "In progress" says the peer took the request and is holding it, so the request stays
        // outstanding and its real answer comes later (RFC 6525 5.2.2 E2).
        if (response.result == .IN_PROGRESS) return null;

        const completed: Completed = .{
            .request_sequence = self.request_sequence,
            .stream_identifier = self.request_stream,
            .result = response.result,
        };

        self.request_len = 0;
        self.request_sent = false;

        return completed;
    }

    /// Refuse a request that this endpoint reset its own outgoing streams.
    fn denyIncomingReset(self: *Driver, value: []const u8) Error!void {
        const request = reconfig.readIncomingReset(value) catch |err| switch (err) {
            error.ZixTruncated => return error.ZixTruncated,
            error.ZixBadLength => return error.ZixBadLength,
            error.ZixNoSpace => return error.ZixNoSpace,
        };

        try self.buildAnswer(request.request_sequence, .DENIED);
    }

    /// Refuse a request to widen the association.
    fn denyAddStreams(self: *Driver, value: []const u8) Error!void {
        const request = reconfig.readAddStreams(value) catch |err| switch (err) {
            error.ZixTruncated => return error.ZixTruncated,
            error.ZixBadLength => return error.ZixBadLength,
            error.ZixNoSpace => return error.ZixNoSpace,
        };

        try self.buildAnswer(request.request_sequence, .DENIED);
    }

    /// Put an answer in the outbound slot.
    fn buildAnswer(self: *Driver, response_sequence: u32, result: reconfig.Result) Error!void {
        const written = reconfig.writeResponse(&self.answer, .{
            .response_sequence = response_sequence,
            .result = result,
        }) catch |err| switch (err) {
            error.ZixNoSpace => return error.ZixNoSpace,
            error.ZixBadLength => return error.ZixBadLength,
            error.ZixTruncated => return error.ZixTruncated,
        };

        self.answer_len = written.len;
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

const LOCAL_TSN: u32 = 1_000;
const PEER_TSN: u32 = 5_000;

/// Build the RE-CONFIG value a peer would send to close one stream.
fn peerResetValue(out: []u8, sequence: u32, stream_identifier: u16, last_assigned_tsn: u32) ![]const u8 {
    return reconfig.writeOutgoingReset(out, .{
        .request_sequence = sequence,
        .response_sequence = LOCAL_TSN - 1,
        .last_assigned_tsn = last_assigned_tsn,
    }, &.{stream_identifier});
}

/// Build the RE-CONFIG value a peer would send to answer a request.
fn peerResponseValue(out: []u8, sequence: u32, result: reconfig.Result) ![]const u8 {
    return reconfig.writeResponse(out, .{ .response_sequence = sequence, .result = result });
}

test "zix datachannel: reset requestReset, the first request carries the initial TSN" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    try std.testing.expect(try driver.requestReset(0, 1_042));

    const value = driver.nextPending() orelse return error.TestUnexpectedResult;
    const parsed = try reconfig.readOutgoingReset(value[parameter.HEADER_LEN..]);

    try std.testing.expectEqual(LOCAL_TSN, parsed.request_sequence);
    try std.testing.expectEqual(@as(u32, 1_042), parsed.last_assigned_tsn);
    try std.testing.expectEqual(@as(?u16, 0), parsed.stream(0));
}

test "zix datachannel: reset requestReset, the response sequence names the peer's last one" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    try std.testing.expect(try driver.requestReset(0, 1_042));

    const value = driver.nextPending() orelse return error.TestUnexpectedResult;
    const parsed = try reconfig.readOutgoingReset(value[parameter.HEADER_LEN..]);

    try std.testing.expectEqual(PEER_TSN - 1, parsed.response_sequence);
}

test "zix datachannel: reset requestReset, a second request waits for the first to be answered" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    try std.testing.expect(try driver.requestReset(0, 1_042));
    try std.testing.expect((try driver.requestReset(2, 1_042)) == false);
    try std.testing.expect(driver.isBusy());
}

test "zix datachannel: reset requestReset, the sequence advances once the first is answered" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    try std.testing.expect(try driver.requestReset(0, 1_042));
    _ = driver.nextPending();

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    const answer = try peerResponseValue(&buf, LOCAL_TSN, .SUCCESS_PERFORMED);
    const handled = try driver.handleValue(answer, PEER_TSN);

    try std.testing.expect(handled.completed != null);
    try std.testing.expect(!driver.isBusy());
    try std.testing.expect(try driver.requestReset(2, 1_050));

    const value = driver.nextPending() orelse return error.TestUnexpectedResult;
    const parsed = try reconfig.readOutgoingReset(value[parameter.HEADER_LEN..]);

    try std.testing.expectEqual(LOCAL_TSN + 1, parsed.request_sequence);
}

test "zix datachannel: reset nextPending, a request goes out once and then only on retransmit" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    try std.testing.expect(try driver.requestReset(0, 1_042));

    try std.testing.expect(driver.nextPending() != null);
    try std.testing.expect(driver.nextPending() == null);
    try std.testing.expect(driver.retransmit() != null);
}

test "zix datachannel: reset retransmit, nothing comes back before the request has gone out" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    try std.testing.expect(try driver.requestReset(0, 1_042));
    try std.testing.expect(driver.retransmit() == null);
}

test "zix datachannel: reset handleValue, a peer request with all data present is performed" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    const request = try peerResetValue(&buf, PEER_TSN, 1, 5_010);
    const handled = try driver.handleValue(request, 5_010);

    const reset = handled.peer_reset orelse return error.TestUnexpectedResult;

    try std.testing.expect(reset.covers(1));

    const answer = driver.nextPending() orelse return error.TestUnexpectedResult;
    const parsed = try reconfig.readResponse(answer[parameter.HEADER_LEN..]);

    try std.testing.expectEqual(PEER_TSN, parsed.response_sequence);
    try std.testing.expectEqual(reconfig.Result.SUCCESS_PERFORMED, parsed.result);
}

test "zix datachannel: reset handleValue, a request ahead of the data is held and answered in progress" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    const request = try peerResetValue(&buf, PEER_TSN, 1, 5_010);

    // Everything up to 5005 has arrived and the peer sent up to 5010, so five chunks are still
    // on their way and the reset cannot happen yet.
    const handled = try driver.handleValue(request, 5_005);

    try std.testing.expect(handled.peer_reset == null);

    const answer = driver.nextPending() orelse return error.TestUnexpectedResult;
    const parsed = try reconfig.readResponse(answer[parameter.HEADER_LEN..]);

    try std.testing.expectEqual(reconfig.Result.IN_PROGRESS, parsed.result);
}

test "zix datachannel: reset releaseDeferred, the held request runs when the data catches up" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    const request = try peerResetValue(&buf, PEER_TSN, 1, 5_010);
    _ = try driver.handleValue(request, 5_005);
    _ = driver.nextPending();

    try std.testing.expect((try driver.releaseDeferred(5_009)) == null);

    const release = (try driver.releaseDeferred(5_010)) orelse return error.TestUnexpectedResult;

    try std.testing.expectEqual(@as(usize, 1), release.count);
    try std.testing.expectEqual(@as(u16, 1), release.streams[0]);
    try std.testing.expect(!release.all);

    const answer = driver.nextPending() orelse return error.TestUnexpectedResult;
    const parsed = try reconfig.readResponse(answer[parameter.HEADER_LEN..]);

    try std.testing.expectEqual(reconfig.Result.SUCCESS_PERFORMED, parsed.result);
}

test "zix datachannel: reset releaseDeferred, nothing held gives nothing back" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    try std.testing.expect((try driver.releaseDeferred(9_999)) == null);
}

test "zix datachannel: reset handleValue, a repeated request is answered again but not performed" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    const request = try peerResetValue(&buf, PEER_TSN, 1, 5_010);

    _ = try driver.handleValue(request, 5_010);
    _ = driver.nextPending();

    const again = try driver.handleValue(request, 5_010);

    try std.testing.expect(again.peer_reset == null);

    const answer = driver.nextPending() orelse return error.TestUnexpectedResult;
    const parsed = try reconfig.readResponse(answer[parameter.HEADER_LEN..]);

    try std.testing.expectEqual(reconfig.Result.SUCCESS_PERFORMED, parsed.result);
}

test "zix datachannel: reset handleValue, a request out of sequence is refused" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    const request = try peerResetValue(&buf, PEER_TSN + 5, 1, 5_010);
    const handled = try driver.handleValue(request, 5_010);

    try std.testing.expect(handled.peer_reset == null);

    const answer = driver.nextPending() orelse return error.TestUnexpectedResult;
    const parsed = try reconfig.readResponse(answer[parameter.HEADER_LEN..]);

    try std.testing.expectEqual(reconfig.Result.ERROR_BAD_SEQUENCE_NUMBER, parsed.result);
}

test "zix datachannel: reset handleValue, two peer requests in a row both run" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    _ = try driver.handleValue(try peerResetValue(&buf, PEER_TSN, 1, 5_010), 5_010);
    _ = driver.nextPending();

    var second: [MAX_VALUE_BYTES]u8 = undefined;
    const handled = try driver.handleValue(try peerResetValue(&second, PEER_TSN + 1, 3, 5_020), 5_020);

    const reset = handled.peer_reset orelse return error.TestUnexpectedResult;

    try std.testing.expect(reset.covers(3));
}

test "zix datachannel: reset handleValue, an answer to a request nobody sent is ignored" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    const answer = try peerResponseValue(&buf, LOCAL_TSN, .SUCCESS_PERFORMED);
    const handled = try driver.handleValue(answer, PEER_TSN);

    try std.testing.expect(handled.completed == null);
}

test "zix datachannel: reset handleValue, an answer naming another request is ignored" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    try std.testing.expect(try driver.requestReset(0, 1_042));
    _ = driver.nextPending();

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    const answer = try peerResponseValue(&buf, LOCAL_TSN + 7, .SUCCESS_PERFORMED);
    const handled = try driver.handleValue(answer, PEER_TSN);

    try std.testing.expect(handled.completed == null);
    try std.testing.expect(driver.isBusy());
}

test "zix datachannel: reset handleValue, an in progress answer leaves the request outstanding" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    try std.testing.expect(try driver.requestReset(0, 1_042));
    _ = driver.nextPending();

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    const answer = try peerResponseValue(&buf, LOCAL_TSN, .IN_PROGRESS);
    const handled = try driver.handleValue(answer, PEER_TSN);

    try std.testing.expect(handled.completed == null);
    try std.testing.expect(driver.isBusy());
}

test "zix datachannel: reset handleValue, a denial completes the request and says so" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    try std.testing.expect(try driver.requestReset(4, 1_042));
    _ = driver.nextPending();

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    const answer = try peerResponseValue(&buf, LOCAL_TSN, .DENIED);
    const handled = try driver.handleValue(answer, PEER_TSN);

    const completed = handled.completed orelse return error.TestUnexpectedResult;

    try std.testing.expectEqual(@as(u16, 4), completed.stream_identifier);
    try std.testing.expect(!completed.isSuccess());
    try std.testing.expect(!driver.isBusy());
}

test "zix datachannel: reset handleValue, an incoming reset request is denied" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    const request = try reconfig.writeIncomingReset(&buf, PEER_TSN, &.{1});
    _ = try driver.handleValue(request, PEER_TSN);

    const answer = driver.nextPending() orelse return error.TestUnexpectedResult;
    const parsed = try reconfig.readResponse(answer[parameter.HEADER_LEN..]);

    try std.testing.expectEqual(reconfig.Result.DENIED, parsed.result);
}

test "zix datachannel: reset handleValue, a request to widen the association is denied" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    const request = try reconfig.writeAddStreams(&buf, .ADD_OUTGOING_STREAMS, .{
        .request_sequence = PEER_TSN,
        .count = 16,
    });
    _ = try driver.handleValue(request, PEER_TSN);

    const answer = driver.nextPending() orelse return error.TestUnexpectedResult;
    const parsed = try reconfig.readResponse(answer[parameter.HEADER_LEN..]);

    try std.testing.expectEqual(reconfig.Result.DENIED, parsed.result);
}

test "zix datachannel: reset handleValue, a value ending mid-parameter is refused" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    const request = try peerResetValue(&buf, PEER_TSN, 1, 5_010);

    try std.testing.expectError(error.ZixTruncated, driver.handleValue(request[0 .. request.len - 4], 5_010));
}

test "zix datachannel: reset nextPending, an answer goes out before a request" {
    var driver = Driver.init(LOCAL_TSN, PEER_TSN);

    try std.testing.expect(try driver.requestReset(0, 1_042));

    var buf: [MAX_VALUE_BYTES]u8 = undefined;
    _ = try driver.handleValue(try peerResetValue(&buf, PEER_TSN, 1, 5_010), 5_010);

    const first = driver.nextPending() orelse return error.TestUnexpectedResult;
    const kind: parameter.Type = @enumFromInt(std.mem.readInt(u16, first[0..2], .big));

    try std.testing.expectEqual(parameter.Type.RECONFIG_RESPONSE, kind);

    const second = driver.nextPending() orelse return error.TestUnexpectedResult;
    const next_kind: parameter.Type = @enumFromInt(std.mem.readInt(u16, second[0..2], .big));

    try std.testing.expectEqual(parameter.Type.OUTGOING_SSN_RESET, next_kind);
}
