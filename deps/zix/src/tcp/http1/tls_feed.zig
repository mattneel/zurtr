//! zix http1 tls request feed: what to do with a request as its bytes arrive over TLS.
//!
//! What:
//! - The rule that lets an upload of any size reach a handler through a fixed per-connection buffer.
//!   A body that cannot fit is never buffered: the head is parked, the remaining body bytes are
//!   counted as they arrive and dropped, and the parked request is served once the count reaches the
//!   declared length. So the buffer bounds the HEAD, not the body, and connection memory stays flat
//!   no matter how large the upload is.
//! - Only the decision lives here. Reading, decrypting, writing and dispatching stay with the two
//!   TLS paths that own them (tls_mux.zig for .EPOLL and .URING, tls_serve.zig for .ASYNC), which
//!   send an answer very differently. The rule is identical, so it is written once.
//!
//! Note:
//! - This is the shape the cleartext event loops already use (dispatch/epoll.zig,
//!   dispatch/uring.zig). Those keep their own copy because they drain with MSG_TRUNC off a socket
//!   rather than counting decrypted plaintext, and their buffer is a slab slice rather than an
//!   inline array.

const std = @import("std");

/// What the caller must do with the request at the front of its buffer.
pub const Step = union(enum) {
    /// Serve it. body_len bytes of body start at body_offset, request_len bytes are consumed.
    SERVE: Serve,
    /// Not all here yet. Keep reading.
    WAIT,
    /// The declared body is past what the server accepts. Answer 413 and close.
    REFUSE_BODY,
    /// The head alone does not fit the buffer. Answer 431 and close.
    REFUSE_HEAD,
};

/// The parts of a serve decision the caller needs to act on.
pub const Serve = struct {
    /// Body bytes available in the buffer. 0 for a body that was counted off the wire instead.
    body_len: usize,
    /// Body bytes counted off the wire for this request, which is what bodyReceived() answers.
    received: u64,
    /// Buffer bytes this request consumes, so the caller can slide the remainder to the front.
    request_len: usize,
};

/// Request bytes held across TLS records for one connection.
///
/// Note:
/// - The upload size lives in drain as a counter, never in the buffer, so this struct is the same
///   size for a 5 byte body and a 5 GiB one. That is the whole reason the ceiling is gone.
pub const State = struct {
    /// Live bytes in the caller's buffer.
    filled: usize = 0,
    /// Body bytes still owed by the peer for a body too large to buffer.
    drain: usize = 0,
    /// Body bytes of the draining request counted off the wire so far.
    drain_received: usize = 0,
    /// Head bytes parked at the front of the buffer while the body drains. Non-zero means a request
    /// is waiting for its body to finish arriving.
    pending_head_len: usize = 0,

    /// Whether a request was part way through arriving.
    ///
    /// Note:
    /// - A peer that hangs up here is owed an answer, because a bare close reads the same to it as a
    ///   crash, a timeout, or a dropped connection. One that leaves between requests is owed nothing.
    ///
    /// Return:
    /// - bool
    pub fn inFlight(self: State) bool {
        return self.filled > 0 or self.pending_head_len > 0;
    }

    /// Take body bytes for a draining request.
    ///
    /// Note:
    /// - The hot path of a large upload: two adds and no copy, because these bytes are counted where
    ///   the transport left them rather than accumulated into the buffer.
    ///
    /// Param:
    /// plaintext - []const u8 (bytes just decrypted)
    ///
    /// Return:
    /// - []const u8 (what is left after the body took its share, a pipelined request or empty)
    pub fn takeDrain(self: *State, plaintext: []const u8) []const u8 {
        const taken = @min(plaintext.len, self.drain);
        self.drain -= taken;
        self.drain_received += taken;

        return plaintext[taken..];
    }

    /// Expose the parked head again, so the next classify serves the request the drain was for.
    /// Called once the drain reaches zero. The head never moved, because every served request slides
    /// the remainder to the front of the buffer.
    pub fn releaseParked(self: *State) void {
        self.filled = self.pending_head_len;
    }

    /// Copy what fits of an arriving chunk into the caller's buffer.
    ///
    /// Note:
    /// - A plaintext chunk can be larger than the buffer, so the caller loops: copy what fits, serve
    ///   what completed, come back for the rest. Treating one chunk as one bufferful is what made
    ///   the first draft of this drop bytes.
    ///
    /// Param:
    /// buf - []u8 (the connection's request buffer)
    /// plaintext - []const u8 (bytes just decrypted)
    ///
    /// Return:
    /// - []const u8 (what did not fit, empty when it all did)
    pub fn fill(self: *State, buf: []u8, plaintext: []const u8) []const u8 {
        const take = @min(plaintext.len, buf.len - self.filled);
        @memcpy(buf[self.filled..][0..take], plaintext[0..take]);
        self.filled += take;

        return plaintext[take..];
    }

    /// Whether the buffer is full with no whole request in it, which only an oversized head can
    /// cause: a body drains instead of filling it.
    pub fn headOverflowed(self: State, buf_len: usize) bool {
        return self.filled >= buf_len;
    }

    /// Decide what to do with the request at the front of the buffer.
    ///
    /// Note:
    /// - Call only with a fully parsed head. An incomplete head is the caller's WAIT, since the
    ///   parser is the one that reports it.
    /// - The parked branch comes first: a request re-entering after its drain finished has its body
    ///   counted already, and its declared length no longer describes anything in the buffer.
    ///
    /// Param:
    /// body_offset - usize (bytes of head, so the body starts here)
    /// content_length - usize (the declared body length)
    /// buf_len - usize (capacity of the connection's request buffer)
    /// max_request_body - usize (declared bodies past this are refused, 0 removes the check)
    ///
    /// Return:
    /// - Step
    pub fn classify(self: *State, body_offset: usize, content_length: usize, buf_len: usize, max_request_body: usize) Step {
        if (self.pending_head_len > 0) {
            const received = self.drain_received;
            self.pending_head_len = 0;
            self.drain_received = 0;

            return .{ .SERVE = .{ .body_len = 0, .received = received, .request_len = body_offset } };
        }

        // Refused on the declared length alone, before a byte of the body is read or counted, so a
        // declared size cannot make the connection consume an arbitrary body.
        if (max_request_body != 0 and content_length > max_request_body) return .REFUSE_BODY;

        const total = body_offset + content_length;

        if (total <= self.filled) {
            return .{ .SERVE = .{ .body_len = content_length, .received = content_length, .request_len = total } };
        }

        if (total > buf_len) {
            // Larger than the buffer can ever hold. Park the head and count the rest off the wire
            // instead of trying to keep it.
            const present_body = self.filled - body_offset;
            self.drain = content_length - present_body;
            self.drain_received = present_body;
            self.pending_head_len = body_offset;
            self.filled = 0;

            return .WAIT;
        }

        return .WAIT;
    }

    /// Drop a served request, keeping any pipelined bytes at the front.
    ///
    /// Param:
    /// buf - []u8 (the connection's request buffer)
    /// request_len - usize (bytes the served request consumed)
    pub fn consume(self: *State, buf: []u8, request_len: usize) void {
        const remaining = self.filled - request_len;
        if (remaining > 0) std.mem.copyForwards(u8, buf[0..remaining], buf[request_len..self.filled]);

        self.filled = remaining;
    }
};

// --------------------------------------------------------- //
// Test support: a whole request as a client would send it, then fed in chunks of a chosen size,
// which is how a record layer delivers it.

/// What a driven feed observed, so a test asserts on behaviour rather than on fields.
const Observed = struct {
    served: usize = 0,
    last_received: u64 = 0,
    last_body_len: usize = 0,
    refused_body: bool = false,
    refused_head: bool = false,
    peak_filled: usize = 0,
    bytes_copied: u64 = 0,
};

fn headLen(body_len: usize) usize {
    var probe: [128]u8 = undefined;
    const head = std.fmt.bufPrint(&probe, "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: {d}\r\n\r\n", .{body_len}) catch unreachable;

    return head.len;
}

fn buildRequest(buf: []u8, body_len: usize) []const u8 {
    const head = std.fmt.bufPrint(buf, "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: {d}\r\n\r\n", .{body_len}) catch unreachable;
    @memset(buf[head.len..][0..body_len], 'A');

    return buf[0 .. head.len + body_len];
}

/// Minimal head parse for the tests: the engine has a real parser, and what is under test here is
/// the decision that follows it.
fn testParse(bytes: []const u8) ?struct { body_offset: usize, content_length: usize } {
    const terminator = std.mem.indexOf(u8, bytes, "\r\n\r\n") orelse return null;

    var content_length: usize = 0;
    var headers = std.mem.splitSequence(u8, bytes[0..terminator], "\r\n");
    while (headers.next()) |header| {
        const colon = std.mem.indexOfScalar(u8, header, ':') orelse continue;
        if (!std.ascii.eqlIgnoreCase(header[0..colon], "content-length")) continue;

        content_length = std.fmt.parseInt(usize, std.mem.trim(u8, header[colon + 1 ..], " "), 10) catch 0;
    }

    return .{ .body_offset = terminator + 4, .content_length = content_length };
}

/// Drive a whole request through the state machine the way both TLS paths do, in chunks.
fn driveFeed(state: *State, buf: []u8, bytes: []const u8, chunk: usize, max_request_body: usize) Observed {
    var seen = Observed{};
    var offset: usize = 0;

    while (offset < bytes.len) {
        const end = @min(offset + chunk, bytes.len);
        var rest = bytes[offset..end];
        offset = end;

        while (true) {
            if (state.drain > 0) {
                rest = state.takeDrain(rest);
                if (state.drain > 0) break;

                state.releaseParked();
            } else {
                if (rest.len == 0) break;

                if (state.headOverflowed(buf.len)) {
                    seen.refused_head = true;

                    return seen;
                }

                const before = state.filled;
                rest = state.fill(buf, rest);
                seen.bytes_copied += state.filled - before;
                seen.peak_filled = @max(seen.peak_filled, state.filled);
            }

            while (state.filled > 0) {
                const parsed = testParse(buf[0..state.filled]) orelse break;

                switch (state.classify(parsed.body_offset, parsed.content_length, buf.len, max_request_body)) {
                    .SERVE => |serve| {
                        seen.served += 1;
                        seen.last_received = serve.received;
                        seen.last_body_len = serve.body_len;
                        state.consume(buf, serve.request_len);
                    },
                    .WAIT => break,
                    .REFUSE_BODY => {
                        seen.refused_body = true;

                        return seen;
                    },
                    .REFUSE_HEAD => {
                        seen.refused_head = true;

                        return seen;
                    },
                }
            }
        }
    }

    return seen;
}

test "zix http1: TLS feed serves a body that fits the buffer from it" {
    var buf: [4096]u8 = undefined;
    var wire: [4096]u8 = undefined;
    var state = State{};

    const seen = driveFeed(&state, &buf, buildRequest(&wire, 100), 64, 0);

    try std.testing.expectEqual(@as(usize, 1), seen.served);
    try std.testing.expectEqual(@as(u64, 100), seen.last_received);
    try std.testing.expectEqual(@as(usize, 100), seen.last_body_len);
}

test "zix http1: TLS feed counts a body past the buffer instead of holding it" {
    const body_len: usize = 190000;

    var buf: [1024]u8 = undefined;
    const wire = try std.testing.allocator.alloc(u8, body_len + 256);
    defer std.testing.allocator.free(wire);

    var state = State{};
    const seen = driveFeed(&state, &buf, buildRequest(wire, body_len), 16384, 0);

    try std.testing.expectEqual(@as(usize, 1), seen.served);
    try std.testing.expectEqual(@as(u64, body_len), seen.last_received);

    // Nothing of the body was handed over, and nothing of it was held: the buffer only ever carried
    // one bufferful, which is what removes the ceiling.
    try std.testing.expectEqual(@as(usize, 0), seen.last_body_len);
    try std.testing.expect(seen.peak_filled <= buf.len);
    try std.testing.expect(seen.bytes_copied <= buf.len);
}

test "zix http1: TLS feed holds the boundary body and drains one past it" {
    var wire: [4096]u8 = undefined;

    // The body length whose head plus body lands exactly on the buffer. A fixed point, because the
    // head carries the declared length as decimal, so changing the body can change the head too.
    var exact: usize = 1024 - headLen(1024);
    while (headLen(exact) + exact != 1024) exact = 1024 - headLen(exact);

    {
        var buf: [1024]u8 = undefined;
        var state = State{};

        const seen = driveFeed(&state, &buf, buildRequest(&wire, exact), 512, 0);

        try std.testing.expectEqual(@as(usize, 1), seen.served);
        try std.testing.expectEqual(exact, seen.last_body_len);
    }

    {
        var buf: [1024]u8 = undefined;
        var state = State{};

        const seen = driveFeed(&state, &buf, buildRequest(&wire, exact + 1), 512, 0);

        try std.testing.expectEqual(@as(usize, 1), seen.served);
        try std.testing.expectEqual(@as(usize, 0), seen.last_body_len);
        try std.testing.expectEqual(@as(u64, exact + 1), seen.last_received);
    }
}

test "zix http1: TLS feed leaves a request pipelined behind a drained body intact" {
    const body_len: usize = 60000;
    const follow = "GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n";

    var buf: [1024]u8 = undefined;
    const wire = try std.testing.allocator.alloc(u8, body_len + 256 + follow.len);
    defer std.testing.allocator.free(wire);

    var state = State{};
    const upload = buildRequest(wire, body_len);
    @memcpy(wire[upload.len..][0..follow.len], follow);

    const seen = driveFeed(&state, &buf, wire[0 .. upload.len + follow.len], 16384, 0);

    // The drain has to stop exactly at the body end, or the second request is eaten as body and
    // never answered.
    try std.testing.expectEqual(@as(usize, 2), seen.served);
    try std.testing.expectEqual(@as(u64, 0), seen.last_received);
}

test "zix http1: TLS feed refuses a declared body past the limit before it arrives" {
    var buf: [1024]u8 = undefined;
    var wire: [4096]u8 = undefined;
    var state = State{};

    const head = std.fmt.bufPrint(&wire, "POST /upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 65536\r\n\r\n", .{}) catch unreachable;
    const seen = driveFeed(&state, &buf, head, 512, 8192);

    try std.testing.expect(seen.refused_body);
    try std.testing.expectEqual(@as(usize, 0), seen.served);
    try std.testing.expectEqual(@as(usize, 0), state.drain);
}

test "zix http1: TLS feed refuses a head larger than the buffer" {
    var buf: [128]u8 = undefined;
    var state = State{};

    var long_head: [512]u8 = undefined;
    @memset(&long_head, 'H');

    const seen = driveFeed(&state, &buf, &long_head, 512, 0);

    try std.testing.expect(seen.refused_head);
    try std.testing.expectEqual(@as(usize, 0), seen.served);
}

test "zix http1: TLS feed answers the same however the records were chopped" {
    const body_len: usize = 40000;

    const wire = try std.testing.allocator.alloc(u8, body_len + 256);
    defer std.testing.allocator.free(wire);

    for ([_]usize{ 1, 7, 512, 16384, 65536 }) |chunk| {
        var buf: [1024]u8 = undefined;
        var state = State{};

        const seen = driveFeed(&state, &buf, buildRequest(wire, body_len), chunk, 0);

        try std.testing.expectEqual(@as(usize, 1), seen.served);
        try std.testing.expectEqual(@as(u64, body_len), seen.last_received);
        try std.testing.expect(seen.peak_filled <= buf.len);
    }
}

test "zix http1: TLS feed holds the same memory for a 50 KB upload and a 2 MiB one" {
    const small_body: usize = 50000;
    const large_body: usize = 2 * 1024 * 1024;

    const wire = try std.testing.allocator.alloc(u8, large_body + 256);
    defer std.testing.allocator.free(wire);

    var buf: [1024]u8 = undefined;
    var small_state = State{};
    const small_seen = driveFeed(&small_state, &buf, buildRequest(wire, small_body), 16384, 0);

    var large_state = State{};
    const large_seen = driveFeed(&large_state, &buf, buildRequest(wire, large_body), 16384, 0);

    try std.testing.expectEqual(@as(u64, small_body), small_seen.last_received);
    try std.testing.expectEqual(@as(u64, large_body), large_seen.last_received);

    // A 2 MiB upload demands no more buffer than a 50 KB one, which is the claim the whole design
    // rests on. Both are one head, and the head is two bytes longer at the larger declared length.
    try std.testing.expect(large_seen.peak_filled - small_seen.peak_filled <= 2);
}

test "zix http1: TLS feed reports a request in flight only while one is arriving" {
    var state = State{};

    // Between requests: the peer owes nothing and is owed nothing.
    try std.testing.expect(!state.inFlight());

    // Head or body still buffering.
    state.filled = 40;
    try std.testing.expect(state.inFlight());

    // Parked on a drain, so the buffer is empty but a request is still open.
    state.filled = 0;
    state.pending_head_len = 49;
    try std.testing.expect(state.inFlight());
}

test "zix http1: TLS feed drain takes only the body, never the bytes after it" {
    var state = State{};
    state.drain = 10;
    state.pending_head_len = 49;

    const rest = state.takeDrain("0123456789GET /ping");

    try std.testing.expectEqual(@as(usize, 0), state.drain);
    try std.testing.expectEqual(@as(usize, 10), state.drain_received);
    try std.testing.expectEqualStrings("GET /ping", rest);
}
