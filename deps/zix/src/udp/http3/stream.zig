//! zix HTTP/3 QUIC streams and connection IDs (RFC 9000 2.1 / 3 / 5.1.1 / 19.15, Layer Q).
//!
//! What:
//! - The stream id namespace (Table 1), the send / receive state machines a stream walks through
//!   (Figure 2 / Figure 3), and the connection-id pool with its active_connection_id_limit.
//! - State machines are transition functions: a null result is an event that is not legal in that
//!   state, which is how the terminal and invalid edges are proven. Validated against the RFC
//!   diagrams and crafted NEW_CONNECTION_ID frames in the tests below.
//!
//! Note:
//! - Implemented and unit-tested, but not wired into the serve path yet (deferred). It backs
//!   connection migration and CID pooling, which the v1 engine does not use. NEW_CONNECTION_ID is
//!   currently skipped in request.zig.

const std = @import("std");

const varint = @import("varint.zig");

/// The four stream types from the two low bits of a stream id (RFC 9000 2.1, Table 1).
pub const StreamType = enum { client_bidi, server_bidi, client_uni, server_uni };

/// Classify a stream id (RFC 9000 2.1): bit 0x01 is the initiator, bit 0x02 the directionality.
pub fn streamType(id: u64) StreamType {
    return switch (id & 0x03) {
        0x00 => .client_bidi,
        0x01 => .server_bidi,
        0x02 => .client_uni,
        0x03 => .server_uni,
        else => unreachable,
    };
}

/// Whether the stream was initiated by the client (RFC 9000 2.1): the low bit is 0.
pub fn clientInitiated(id: u64) bool {
    return id & 0x01 == 0;
}

/// Whether the stream is unidirectional (RFC 9000 2.1): the second bit is 1.
pub fn unidirectional(id: u64) bool {
    return id & 0x02 != 0;
}

// --------------------------------------------------------------- //

/// The sending part state machine (RFC 9000 3.1, Figure 2).
pub const SendState = enum { ready, send, data_sent, data_recvd, reset_sent, reset_recvd };

/// Events that drive the sending part (RFC 9000 3.1).
pub const SendEvent = enum { send_stream, send_fin, recv_all_acks, send_reset, recv_reset_ack };

/// Apply a sending-part event (RFC 9000 3.1, Figure 2). A null result means the event is not legal
/// in that state, including the terminal "Data Recvd" / "Reset Recvd" states.
pub fn sendTransition(state: SendState, event: SendEvent) ?SendState {
    return switch (state) {
        .ready => switch (event) {
            .send_stream => .send,
            .send_reset => .reset_sent,
            else => null,
        },
        .send => switch (event) {
            .send_fin => .data_sent,
            .send_reset => .reset_sent,
            else => null,
        },
        .data_sent => switch (event) {
            .recv_all_acks => .data_recvd,
            .send_reset => .reset_sent,
            else => null,
        },
        .reset_sent => switch (event) {
            .recv_reset_ack => .reset_recvd,
            else => null,
        },
        .data_recvd, .reset_recvd => null,
    };
}

/// The receiving part state machine (RFC 9000 3.2, Figure 3).
pub const RecvState = enum { recv, size_known, data_recvd, data_read, reset_recvd, reset_read };

/// Events that drive the receiving part (RFC 9000 3.2).
pub const RecvEvent = enum { recv_stream, recv_fin, recv_all_data, app_read_all, recv_reset, app_read_reset };

/// Apply a receiving-part event (RFC 9000 3.2, Figure 3). A null result means the event is not legal
/// in that state, including the terminal "Data Read" / "Reset Read" states.
pub fn recvTransition(state: RecvState, event: RecvEvent) ?RecvState {
    return switch (state) {
        .recv => switch (event) {
            .recv_stream => .recv,
            .recv_fin => .size_known,
            .recv_reset => .reset_recvd,
            else => null,
        },
        .size_known => switch (event) {
            .recv_all_data => .data_recvd,
            .recv_reset => .reset_recvd,
            else => null,
        },
        .data_recvd => switch (event) {
            .app_read_all => .data_read,
            .recv_reset => .reset_recvd,
            else => null,
        },
        .reset_recvd => switch (event) {
            .app_read_reset => .reset_read,
            else => null,
        },
        .data_read, .reset_read => null,
    };
}

// --------------------------------------------------------------- //

/// The connection-id errors an endpoint MUST raise (RFC 9000 19.15 / 5.1.1).
pub const ConnIdError = error{
    ZixTruncated,
    /// Connection ID length out of 1..20, or Retire Prior To > Sequence Number: FRAME_ENCODING_ERROR.
    ZixFrameEncodingError,
    /// The active connection ID count exceeds active_connection_id_limit: CONNECTION_ID_LIMIT_ERROR.
    ZixConnectionIdLimitError,
};

/// The validated fields of a NEW_CONNECTION_ID frame (RFC 9000 19.15).
pub const NewConnId = struct { seq: u64, retire_prior_to: u64, length: u8 };

/// Parse and field-validate a NEW_CONNECTION_ID frame body, the bytes after the 0x18 type
/// (RFC 9000 19.15). The connection ID length MUST be 1..20, and Retire Prior To MUST be <= Sequence
/// Number, both FRAME_ENCODING_ERROR otherwise.
pub fn parseNewConnectionId(body: []const u8) ConnIdError!NewConnId {
    var pos: usize = 0;

    const seq_vi = varint.read(body[pos..]) catch return error.ZixTruncated;
    pos += seq_vi.len;

    const retire_vi = varint.read(body[pos..]) catch return error.ZixTruncated;
    pos += retire_vi.len;

    if (retire_vi.value > seq_vi.value) return error.ZixFrameEncodingError;
    if (pos >= body.len) return error.ZixTruncated;

    const length = body[pos];
    if (length < 1 or length > 20) return error.ZixFrameEncodingError;

    return .{ .seq = seq_vi.value, .retire_prior_to = retire_vi.value, .length = length };
}

/// The pool of connection IDs a peer has issued to us (RFC 9000 5.1.1). Issuance is sequential, so
/// the active count is (highest sequence + 1) minus the retire floor.
pub const ConnIdPool = struct {
    limit: u64,
    highest_seq: u64 = 0,
    retire_floor: u64 = 0,

    /// The number of connection IDs not yet retired (RFC 9000 5.1.1).
    pub fn active(self: ConnIdPool) u64 {
        return self.highest_seq + 1 - self.retire_floor;
    }

    /// Account a validated NEW_CONNECTION_ID frame. Retire Prior To only advances (a non-increasing
    /// value is ignored, 19.15), and exceeding the limit is a CONNECTION_ID_LIMIT_ERROR.
    pub fn onNewConnectionId(self: *ConnIdPool, frame: NewConnId) ConnIdError!void {
        if (frame.seq > self.highest_seq) self.highest_seq = frame.seq;
        if (frame.retire_prior_to > self.retire_floor) self.retire_floor = frame.retire_prior_to;

        if (self.active() > self.limit) return error.ZixConnectionIdLimitError;
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

fn hexBytes(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;

    return out;
}

test "zix http3: RFC 9000 2.1 stream id classification" {
    try std.testing.expectEqual(StreamType.client_bidi, streamType(0));
    try std.testing.expectEqual(StreamType.server_bidi, streamType(1));
    try std.testing.expectEqual(StreamType.client_uni, streamType(2));
    try std.testing.expectEqual(StreamType.server_uni, streamType(3));

    const max_id: u64 = (@as(u64, 1) << 62) - 1;
    try std.testing.expectEqual(StreamType.server_uni, streamType(max_id));
    try std.testing.expect(clientInitiated(4) and !clientInitiated(5));
    try std.testing.expect(unidirectional(2) and !unidirectional(0));
}

test "zix http3: RFC 9000 3.1 sending stream states" {
    try std.testing.expectEqual(SendState.send, sendTransition(.ready, .send_stream).?);
    try std.testing.expectEqual(SendState.data_sent, sendTransition(.send, .send_fin).?);
    try std.testing.expectEqual(SendState.data_recvd, sendTransition(.data_sent, .recv_all_acks).?);
    try std.testing.expectEqual(SendState.reset_sent, sendTransition(.ready, .send_reset).?);
    try std.testing.expectEqual(SendState.reset_recvd, sendTransition(.reset_sent, .recv_reset_ack).?);
    try std.testing.expect(sendTransition(.data_recvd, .send_reset) == null);
    try std.testing.expect(sendTransition(.ready, .recv_all_acks) == null);
}

test "zix http3: RFC 9000 3.2 receiving stream states" {
    try std.testing.expectEqual(RecvState.size_known, recvTransition(.recv, .recv_fin).?);
    try std.testing.expectEqual(RecvState.data_recvd, recvTransition(.size_known, .recv_all_data).?);
    try std.testing.expectEqual(RecvState.data_read, recvTransition(.data_recvd, .app_read_all).?);
    try std.testing.expectEqual(RecvState.reset_recvd, recvTransition(.recv, .recv_reset).?);
    try std.testing.expectEqual(RecvState.reset_read, recvTransition(.reset_recvd, .app_read_reset).?);
    try std.testing.expect(recvTransition(.data_read, .recv_stream) == null);
    try std.testing.expect(recvTransition(.size_known, .app_read_all) == null);
}

test "zix http3: RFC 9000 19.15 / 5.1.1 NEW_CONNECTION_ID validation and limit" {
    const nci_ok = try parseNewConnectionId(&hexBytes("010008" ++ "f067a5502a4262b5" ++ "0102030405060708090a0b0c0d0e0f10"));
    try std.testing.expect(nci_ok.seq == 1 and nci_ok.length == 8);

    try std.testing.expectError(error.ZixFrameEncodingError, parseNewConnectionId(&hexBytes("010000")));
    try std.testing.expectError(error.ZixFrameEncodingError, parseNewConnectionId(&hexBytes("010015")));
    try std.testing.expectError(error.ZixFrameEncodingError, parseNewConnectionId(&hexBytes("010208")));

    var pool = ConnIdPool{ .limit = 2 };
    try pool.onNewConnectionId(.{ .seq = 1, .retire_prior_to = 0, .length = 8 });
    try std.testing.expectEqual(@as(u64, 2), pool.active());
    try std.testing.expectError(error.ZixConnectionIdLimitError, pool.onNewConnectionId(.{ .seq = 2, .retire_prior_to = 0, .length = 8 }));

    var pool2 = ConnIdPool{ .limit = 2 };
    try pool2.onNewConnectionId(.{ .seq = 1, .retire_prior_to = 0, .length = 8 });
    try pool2.onNewConnectionId(.{ .seq = 2, .retire_prior_to = 1, .length = 8 });
    try std.testing.expectEqual(@as(u64, 2), pool2.active());

    try pool2.onNewConnectionId(.{ .seq = 2, .retire_prior_to = 0, .length = 8 });
    try std.testing.expectEqual(@as(u64, 1), pool2.retire_floor);
}
