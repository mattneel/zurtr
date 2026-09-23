//! zix SCTP stream reconfiguration, the RE-CONFIG chunk (RFC 6525).
//!
//! What:
//! - Resetting a stream's sequence numbering back to zero without tearing down the association,
//!   which is how one data channel closes while the others keep running (RFC 8831 6.7).
//! - Adding streams to a running association, so a peer can open more channels than it asked for
//!   at handshake time.
//!
//! Note:
//! - The chunk carries one or two of the request parameters, and the answer to any of them is a
//!   Re-configuration Response naming the same request sequence number. Requests and responses
//!   are matched by that number, never by order of arrival.
//! - The request sequence number starts at the sender's initial TSN and counts up by one per
//!   request. It is a separate counter from the TSN itself and never restarts.
//! - An outgoing reset request also carries the sender's last assigned TSN. The receiver holds
//!   the reset until it has taken everything up to that TSN, or the reset would drop data that
//!   was still in flight.
//! - A request with no stream numbers means every stream. That is a whole-association reset and
//!   is rarely what a data channel wants, so `streamCount` of zero is worth checking for.
//! - Both peers must have listed RE-CONFIG in SUPPORTED-EXTENSIONS during the handshake. The
//!   check belongs to the association, which is what saw both INITs.

const std = @import("std");

const parameter = @import("parameter.zig");

/// Request sequence, response sequence, last assigned TSN.
pub const OUTGOING_FIXED_LEN: usize = 12;

/// Request sequence only.
pub const INCOMING_FIXED_LEN: usize = 4;

/// Response sequence and result.
pub const RESPONSE_FIXED_LEN: usize = 8;

/// The response with both optional TSN fields present.
pub const RESPONSE_WITH_TSN_LEN: usize = RESPONSE_FIXED_LEN + 8;

/// Request sequence, stream count, reserved.
pub const ADD_STREAMS_LEN: usize = 8;

/// One stream number in a request list.
pub const STREAM_LEN: usize = 2;

/// Everything that stops a reconfiguration parameter from being read or built.
pub const Error = error{
    /// Fewer bytes than the parameter needs, or a list ending mid-entry.
    ZixTruncated,
    /// A parameter length below the parameter header size.
    ZixBadLength,
    /// The output buffer is too small.
    ZixNoSpace,
};

/// What the peer made of a request (RFC 6525 4.4 Table 3).
pub const Result = enum(u32) {
    /// The request was valid and there was nothing that needed doing.
    SUCCESS_NOTHING_TO_DO = 0,
    SUCCESS_PERFORMED = 1,
    /// Understood and refused.
    DENIED = 2,
    ERROR_WRONG_SSN = 3,
    ERROR_REQUEST_IN_PROGRESS = 4,
    ERROR_BAD_SEQUENCE_NUMBER = 5,
    /// Accepted, and the answer comes later.
    IN_PROGRESS = 6,
    _,
};

/// A request to reset this sender's own outgoing streams (RFC 6525 4.1).
pub const OutgoingReset = struct {
    request_sequence: u32,
    /// The incoming request this answers, or the last one seen minus one.
    response_sequence: u32,
    /// The last TSN the sender assigned. The reset waits for everything up to it.
    last_assigned_tsn: u32,
    /// The stream number list, still packed. Empty means every stream.
    streams: []const u8,

    /// How many streams are named. Zero means all of them.
    ///
    /// Return:
    /// - usize
    pub fn streamCount(self: OutgoingReset) usize {
        return self.streams.len / STREAM_LEN;
    }

    /// One stream number by position.
    ///
    /// Param:
    /// index - usize
    ///
    /// Return:
    /// - ?u16
    pub fn stream(self: OutgoingReset, index: usize) ?u16 {
        return readStream(self.streams, index);
    }

    /// Whether a given stream is covered, list or no list.
    ///
    /// Param:
    /// stream_identifier - u16
    ///
    /// Return:
    /// - bool
    pub fn covers(self: OutgoingReset, stream_identifier: u16) bool {
        return listCovers(self.streams, stream_identifier);
    }
};

/// A request that the peer reset ITS outgoing streams (RFC 6525 4.2).
pub const IncomingReset = struct {
    request_sequence: u32,
    /// The stream number list, still packed. Empty means every stream.
    streams: []const u8,

    /// How many streams are named. Zero means all of them.
    ///
    /// Return:
    /// - usize
    pub fn streamCount(self: IncomingReset) usize {
        return self.streams.len / STREAM_LEN;
    }

    /// One stream number by position.
    ///
    /// Param:
    /// index - usize
    ///
    /// Return:
    /// - ?u16
    pub fn stream(self: IncomingReset, index: usize) ?u16 {
        return readStream(self.streams, index);
    }

    /// Whether a given stream is covered, list or no list.
    ///
    /// Param:
    /// stream_identifier - u16
    ///
    /// Return:
    /// - bool
    pub fn covers(self: IncomingReset, stream_identifier: u16) bool {
        return listCovers(self.streams, stream_identifier);
    }
};

/// The answer to any request (RFC 6525 4.4).
pub const Response = struct {
    response_sequence: u32,
    result: Result,
    /// Only carried when answering a full SSN and TSN reset.
    sender_next_tsn: ?u32 = null,
    /// Only carried when answering a full SSN and TSN reset.
    receiver_next_tsn: ?u32 = null,

    /// Whether the request was accepted, whether or not it needed doing.
    ///
    /// Return:
    /// - bool
    pub fn isSuccess(self: Response) bool {
        return switch (self.result) {
            .SUCCESS_NOTHING_TO_DO, .SUCCESS_PERFORMED => true,
            else => false,
        };
    }
};

/// A request to widen the association (RFC 6525 4.5, 4.6).
pub const AddStreams = struct {
    request_sequence: u32,
    /// How many streams to add. Which direction depends on the parameter type it came in.
    count: u16,
};

/// Read an Outgoing SSN Reset Request parameter value.
///
/// Param:
/// value - []const u8 (parameter value, so everything after the 4-byte parameter header)
///
/// Return:
/// - OutgoingReset borrowing `value`
/// - error.ZixTruncated if the value is short or ends mid-stream-number
pub fn readOutgoingReset(value: []const u8) Error!OutgoingReset {
    if (value.len < OUTGOING_FIXED_LEN) return error.ZixTruncated;

    const streams = value[OUTGOING_FIXED_LEN..];

    if (streams.len % STREAM_LEN != 0) return error.ZixTruncated;

    return .{
        .request_sequence = std.mem.readInt(u32, value[0..4], .big),
        .response_sequence = std.mem.readInt(u32, value[4..8], .big),
        .last_assigned_tsn = std.mem.readInt(u32, value[8..12], .big),
        .streams = streams,
    };
}

/// Read an Incoming SSN Reset Request parameter value.
///
/// Param:
/// value - []const u8 (parameter value)
///
/// Return:
/// - IncomingReset borrowing `value`
/// - error.ZixTruncated if the value is short or ends mid-stream-number
pub fn readIncomingReset(value: []const u8) Error!IncomingReset {
    if (value.len < INCOMING_FIXED_LEN) return error.ZixTruncated;

    const streams = value[INCOMING_FIXED_LEN..];

    if (streams.len % STREAM_LEN != 0) return error.ZixTruncated;

    return .{
        .request_sequence = std.mem.readInt(u32, value[0..4], .big),
        .streams = streams,
    };
}

/// Read a Re-configuration Response parameter value.
///
/// Param:
/// value - []const u8 (parameter value)
///
/// Return:
/// - Response
/// - error.ZixTruncated if the value is shorter than the two required fields
pub fn readResponse(value: []const u8) Error!Response {
    if (value.len < RESPONSE_FIXED_LEN) return error.ZixTruncated;

    var response: Response = .{
        .response_sequence = std.mem.readInt(u32, value[0..4], .big),
        .result = @enumFromInt(std.mem.readInt(u32, value[4..8], .big)),
    };

    // RFC 6525 4.4: either both TSN fields are there or neither is.
    if (value.len >= RESPONSE_WITH_TSN_LEN) {
        response.sender_next_tsn = std.mem.readInt(u32, value[8..12], .big);
        response.receiver_next_tsn = std.mem.readInt(u32, value[12..16], .big);
    }

    return response;
}

/// Read an Add Outgoing or Add Incoming Streams parameter value.
///
/// Param:
/// value - []const u8 (parameter value)
///
/// Return:
/// - AddStreams
/// - error.ZixTruncated if the value is short
pub fn readAddStreams(value: []const u8) Error!AddStreams {
    if (value.len < ADD_STREAMS_LEN) return error.ZixTruncated;

    return .{
        .request_sequence = std.mem.readInt(u32, value[0..4], .big),
        .count = std.mem.readInt(u16, value[4..6], .big),
    };
}

/// The three numbers an outgoing reset request carries, without its stream list.
pub const OutgoingFields = struct {
    request_sequence: u32,
    /// The incoming request this answers, or the last one seen minus one.
    response_sequence: u32,
    /// The last TSN this sender assigned.
    last_assigned_tsn: u32,
};

/// Write an Outgoing SSN Reset Request as a whole parameter.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// fields - OutgoingFields
/// streams - []const u16 (streams to reset, empty for all of them)
///
/// Return:
/// - []const u8, the whole parameter including its header and padding
/// - error.ZixNoSpace, error.ZixBadLength
pub fn writeOutgoingReset(out: []u8, fields: OutgoingFields, streams: []const u16) Error![]const u8 {
    var body: [OUTGOING_FIXED_LEN + MAX_STREAMS * STREAM_LEN]u8 = undefined;

    if (streams.len > MAX_STREAMS) return error.ZixNoSpace;

    std.mem.writeInt(u32, body[0..4], fields.request_sequence, .big);
    std.mem.writeInt(u32, body[4..8], fields.response_sequence, .big);
    std.mem.writeInt(u32, body[8..12], fields.last_assigned_tsn, .big);
    writeStreams(body[OUTGOING_FIXED_LEN..], streams);

    return parameter.write(out, .OUTGOING_SSN_RESET, body[0 .. OUTGOING_FIXED_LEN + streams.len * STREAM_LEN]);
}

/// Write an Incoming SSN Reset Request as a whole parameter.
///
/// Param:
/// out - []u8
/// request_sequence - u32
/// streams - []const u16 (streams the peer should reset, empty for all of them)
///
/// Return:
/// - []const u8, the whole parameter
/// - error.ZixNoSpace, error.ZixBadLength
pub fn writeIncomingReset(out: []u8, request_sequence: u32, streams: []const u16) Error![]const u8 {
    var body: [INCOMING_FIXED_LEN + MAX_STREAMS * STREAM_LEN]u8 = undefined;

    if (streams.len > MAX_STREAMS) return error.ZixNoSpace;

    std.mem.writeInt(u32, body[0..4], request_sequence, .big);
    writeStreams(body[INCOMING_FIXED_LEN..], streams);

    return parameter.write(out, .INCOMING_SSN_RESET, body[0 .. INCOMING_FIXED_LEN + streams.len * STREAM_LEN]);
}

/// Write a Re-configuration Response as a whole parameter.
///
/// Param:
/// out - []u8
/// response - Response (both TSN fields go out together or not at all)
///
/// Return:
/// - []const u8, the whole parameter
/// - error.ZixNoSpace
pub fn writeResponse(out: []u8, response: Response) Error![]const u8 {
    var body: [RESPONSE_WITH_TSN_LEN]u8 = undefined;

    std.mem.writeInt(u32, body[0..4], response.response_sequence, .big);
    std.mem.writeInt(u32, body[4..8], @intFromEnum(response.result), .big);

    const sender = response.sender_next_tsn orelse
        return parameter.write(out, .RECONFIG_RESPONSE, body[0..RESPONSE_FIXED_LEN]);
    const receiver = response.receiver_next_tsn orelse
        return parameter.write(out, .RECONFIG_RESPONSE, body[0..RESPONSE_FIXED_LEN]);

    std.mem.writeInt(u32, body[8..12], sender, .big);
    std.mem.writeInt(u32, body[12..16], receiver, .big);

    return parameter.write(out, .RECONFIG_RESPONSE, &body);
}

/// Write an Add Outgoing or Add Incoming Streams request as a whole parameter.
///
/// Param:
/// out - []u8
/// kind - parameter.Type (ADD_OUTGOING_STREAMS or ADD_INCOMING_STREAMS)
/// request - AddStreams
///
/// Return:
/// - []const u8, the whole parameter
/// - error.ZixNoSpace
pub fn writeAddStreams(out: []u8, kind: parameter.Type, request: AddStreams) Error![]const u8 {
    var body: [ADD_STREAMS_LEN]u8 = undefined;

    std.mem.writeInt(u32, body[0..4], request.request_sequence, .big);
    std.mem.writeInt(u16, body[4..6], request.count, .big);
    std.mem.writeInt(u16, body[6..8], 0, .big);

    return parameter.write(out, kind, &body);
}

/// How many stream numbers one request can name here. A data channel closes one stream pair at a
/// time, so the ceiling only exists to keep the list on the stack.
pub const MAX_STREAMS: usize = 32;

/// Pack a stream number list.
fn writeStreams(out: []u8, streams: []const u16) void {
    for (streams, 0..) |identifier, index| {
        std.mem.writeInt(u16, out[index * STREAM_LEN ..][0..2], identifier, .big);
    }
}

/// One stream number out of a packed list.
fn readStream(streams: []const u8, index: usize) ?u16 {
    if (index >= streams.len / STREAM_LEN) return null;

    return std.mem.readInt(u16, streams[index * STREAM_LEN ..][0..2], .big);
}

/// Whether a packed list covers a stream. An empty list covers every stream.
fn listCovers(streams: []const u8, stream_identifier: u16) bool {
    if (streams.len == 0) return true;

    var index: usize = 0;
    while (readStream(streams, index)) |identifier| : (index += 1) {
        if (identifier == stream_identifier) return true;
    }

    return false;
}

// --------------------------------------------------------------------------------------- //
// test cases

test "zix sctp: reconfig outgoing, a request naming one stream round trips" {
    var buf: [64]u8 = undefined;
    const written = try writeOutgoingReset(&buf, .{
        .request_sequence = 1000,
        .response_sequence = 999,
        .last_assigned_tsn = 5000,
    }, &.{7});

    try parameter.validate(written);
    const found = parameter.find(written, .OUTGOING_SSN_RESET).?;
    const request = try readOutgoingReset(found.value);

    try std.testing.expectEqual(@as(u32, 1000), request.request_sequence);
    try std.testing.expectEqual(@as(u32, 999), request.response_sequence);
    try std.testing.expectEqual(@as(u32, 5000), request.last_assigned_tsn);
    try std.testing.expectEqual(@as(usize, 1), request.streamCount());
    try std.testing.expectEqual(@as(u16, 7), request.stream(0).?);
}

test "zix sctp: reconfig outgoing, the parameter length follows the RFC formula" {
    var buf: [64]u8 = undefined;
    const written = try writeOutgoingReset(&buf, .{
        .request_sequence = 1,
        .response_sequence = 0,
        .last_assigned_tsn = 2,
    }, &.{ 1, 2 });

    // 16 + 2 * N with the 4-byte parameter header counted, so 16 + 4 = 20.
    try std.testing.expectEqual(@as(u16, 20), std.mem.readInt(u16, written[2..4], .big));
}

test "zix sctp: reconfig outgoing, an empty list means every stream" {
    var buf: [64]u8 = undefined;
    const written = try writeOutgoingReset(&buf, .{
        .request_sequence = 1,
        .response_sequence = 0,
        .last_assigned_tsn = 2,
    }, &.{});

    const request = try readOutgoingReset(parameter.find(written, .OUTGOING_SSN_RESET).?.value);

    try std.testing.expectEqual(@as(usize, 0), request.streamCount());
    try std.testing.expect(request.covers(0));
    try std.testing.expect(request.covers(65535));
}

test "zix sctp: reconfig outgoing, a named list covers only what it names" {
    var buf: [64]u8 = undefined;
    const written = try writeOutgoingReset(&buf, .{
        .request_sequence = 1,
        .response_sequence = 0,
        .last_assigned_tsn = 2,
    }, &.{ 4, 9 });

    const request = try readOutgoingReset(parameter.find(written, .OUTGOING_SSN_RESET).?.value);

    try std.testing.expect(request.covers(4));
    try std.testing.expect(request.covers(9));
    try std.testing.expect(!request.covers(5));
}

test "zix sctp: reconfig incoming, a request round trips" {
    var buf: [64]u8 = undefined;
    const written = try writeIncomingReset(&buf, 77, &.{ 2, 3, 4 });

    try parameter.validate(written);
    const request = try readIncomingReset(parameter.find(written, .INCOMING_SSN_RESET).?.value);

    try std.testing.expectEqual(@as(u32, 77), request.request_sequence);
    try std.testing.expectEqual(@as(usize, 3), request.streamCount());
    try std.testing.expectEqual(@as(u16, 3), request.stream(1).?);
    try std.testing.expect(request.stream(3) == null);
}

test "zix sctp: reconfig response, a plain answer carries no TSN fields" {
    var buf: [32]u8 = undefined;
    const written = try writeResponse(&buf, .{
        .response_sequence = 1000,
        .result = .SUCCESS_PERFORMED,
    });

    try std.testing.expectEqual(@as(u16, 12), std.mem.readInt(u16, written[2..4], .big));

    const response = try readResponse(parameter.find(written, .RECONFIG_RESPONSE).?.value);

    try std.testing.expectEqual(@as(u32, 1000), response.response_sequence);
    try std.testing.expectEqual(Result.SUCCESS_PERFORMED, response.result);
    try std.testing.expect(response.isSuccess());
    try std.testing.expect(response.sender_next_tsn == null);
}

test "zix sctp: reconfig response, both TSN fields travel together" {
    var buf: [32]u8 = undefined;
    const written = try writeResponse(&buf, .{
        .response_sequence = 1000,
        .result = .SUCCESS_PERFORMED,
        .sender_next_tsn = 4000,
        .receiver_next_tsn = 9000,
    });

    try std.testing.expectEqual(@as(u16, 20), std.mem.readInt(u16, written[2..4], .big));

    const response = try readResponse(parameter.find(written, .RECONFIG_RESPONSE).?.value);

    try std.testing.expectEqual(@as(u32, 4000), response.sender_next_tsn.?);
    try std.testing.expectEqual(@as(u32, 9000), response.receiver_next_tsn.?);
}

test "zix sctp: reconfig response, one TSN field alone is written as neither" {
    var buf: [32]u8 = undefined;
    const written = try writeResponse(&buf, .{
        .response_sequence = 1,
        .result = .SUCCESS_PERFORMED,
        .sender_next_tsn = 4000,
    });

    // RFC 6525 4.4 allows both or neither, so a half-filled answer goes out as the short form.
    try std.testing.expectEqual(@as(u16, 12), std.mem.readInt(u16, written[2..4], .big));
}

test "zix sctp: reconfig response, a failure result is not a success" {
    var buf: [32]u8 = undefined;

    for ([_]Result{ .DENIED, .ERROR_WRONG_SSN, .ERROR_BAD_SEQUENCE_NUMBER, .IN_PROGRESS }) |result| {
        const written = try writeResponse(&buf, .{ .response_sequence = 1, .result = result });
        const response = try readResponse(parameter.find(written, .RECONFIG_RESPONSE).?.value);

        try std.testing.expect(!response.isSuccess());
    }
}

test "zix sctp: reconfig response, nothing to do still counts as success" {
    var buf: [32]u8 = undefined;
    const written = try writeResponse(&buf, .{
        .response_sequence = 1,
        .result = .SUCCESS_NOTHING_TO_DO,
    });

    const response = try readResponse(parameter.find(written, .RECONFIG_RESPONSE).?.value);

    try std.testing.expect(response.isSuccess());
}

test "zix sctp: reconfig response, an unknown result comes back as a number" {
    var buf: [32]u8 = undefined;
    const written = try writeResponse(&buf, .{ .response_sequence = 1, .result = @enumFromInt(99) });
    const response = try readResponse(parameter.find(written, .RECONFIG_RESPONSE).?.value);

    try std.testing.expectEqual(@as(u32, 99), @intFromEnum(response.result));
    try std.testing.expect(!response.isSuccess());
}

test "zix sctp: reconfig add streams, both directions use the same layout" {
    var buf: [32]u8 = undefined;

    const outgoing = try writeAddStreams(&buf, .ADD_OUTGOING_STREAMS, .{ .request_sequence = 5, .count = 16 });
    const request = try readAddStreams(parameter.find(outgoing, .ADD_OUTGOING_STREAMS).?.value);

    try std.testing.expectEqual(@as(u32, 5), request.request_sequence);
    try std.testing.expectEqual(@as(u16, 16), request.count);
    try std.testing.expectEqual(@as(u16, 12), std.mem.readInt(u16, outgoing[2..4], .big));

    var other: [32]u8 = undefined;
    const incoming = try writeAddStreams(&other, .ADD_INCOMING_STREAMS, .{ .request_sequence = 6, .count = 8 });

    try std.testing.expectEqual(@as(u16, 8), (try readAddStreams(parameter.find(incoming, .ADD_INCOMING_STREAMS).?.value)).count);
}

test "zix sctp: reconfig read, a value shorter than its fixed fields errors" {
    const short: [11]u8 = @splat(0);

    try std.testing.expectError(error.ZixTruncated, readOutgoingReset(&short));
    try std.testing.expectError(error.ZixTruncated, readIncomingReset(short[0..3]));
    try std.testing.expectError(error.ZixTruncated, readResponse(short[0..7]));
    try std.testing.expectError(error.ZixTruncated, readAddStreams(short[0..7]));
}

test "zix sctp: reconfig read, a stream list ending mid-number errors" {
    const ragged: [13]u8 = @splat(0);

    try std.testing.expectError(error.ZixTruncated, readOutgoingReset(&ragged));
    try std.testing.expectError(error.ZixTruncated, readIncomingReset(ragged[0..5]));
}

test "zix sctp: reconfig write, more streams than the ceiling errors" {
    var buf: [256]u8 = undefined;
    const many: [MAX_STREAMS + 1]u16 = @splat(1);

    try std.testing.expectError(error.ZixNoSpace, writeIncomingReset(&buf, 1, &many));
}

test "zix sctp: reconfig write, a buffer too small errors" {
    var buf: [8]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, writeIncomingReset(&buf, 1, &.{ 1, 2 }));
}
