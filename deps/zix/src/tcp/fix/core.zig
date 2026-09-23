//! zix fix core: parsing, building, checksum, session handler.
//! All functions are pub for test imports.
//! No heap allocation. Zero-copy field parsing (slices into caller buffer).

const std = @import("std");
const builtin = @import("builtin");
const win_io = @import("../../utils/windows_io.zig");
const Logger = @import("../../logger/logger.zig").Logger;

pub const SOH: u8 = 0x01;
pub const VERSION: []const u8 = "FIX.4.2";
pub const MAX_FIELDS: usize = 64;
pub const MAX_MSG_SIZE: usize = 8192;
pub const CHECKSUM_MODULUS: u32 = 256;
/// Backing size of the per-request stack arena on FixContext.allocator. Stack-based
/// (std.heap.FixedBufferAllocator), no heap call, keeps the FIX core zero-heap-allocation.
pub const FIX_CTX_ARENA_BYTES: usize = 4096;

// --------------------------------------------------------- //

/// FIX 4.x standard tag numbers (nonexhaustive).
/// Use @enumFromInt for custom or extension tags not listed here.
///
/// Note:
/// - Members are PascalCase ON PURPOSE: they mirror the FIX protocol field names
///   verbatim (ClOrdID, MsgSeqNum, HeartBtInt), exactly as the spec and every FIX
///   engine spell them. This is the one enum exempt from the project UPPER_CASE
///   convention. Do NOT rename to UPPER_CASE or otherwise change a member until the
///   FIX community updates the field name in the spec.
pub const Tag = enum(u16) {
    Account = 1,
    AvgPx = 6,
    BeginString = 8,
    BodyLength = 9,
    CheckSum = 10,
    ClOrdID = 11,
    CumQty = 14,
    Currency = 15,
    ExecID = 17,
    ExecTransType = 20,
    HandlInst = 21,
    SecurityIDSource = 22,
    LastPx = 31,
    LastShares = 32,
    MsgSeqNum = 34,
    MsgType = 35,
    OrderID = 37,
    OrderQty = 38,
    OrdStatus = 39,
    OrdType = 40,
    OrigClOrdID = 41,
    PossDupFlag = 43,
    Price = 44,
    RefSeqNum = 45,
    SecurityID = 48,
    SenderCompID = 49,
    SenderSubID = 50,
    SendingTime = 52,
    Side = 54,
    Symbol = 55,
    TargetCompID = 56,
    TargetSubID = 57,
    Text = 58,
    TimeInForce = 59,
    TransactTime = 60,
    TradeDate = 75,
    PossResend = 97,
    EncryptMethod = 98,
    StopPx = 99,
    ExDestination = 100,
    HeartBtInt = 108,
    TestReqID = 112,
    OrigSendingTime = 122,
    GapFillFlag = 123,
    NoRelatedSym = 146,
    ExecType = 150,
    LeavesQty = 151,
    SecurityType = 167,
    MaturityMonthYear = 200,
    SecurityExchange = 207,
    NoMDEntries = 268,
    LastMsgSeqNumProcessed = 369,
    NoPartyIDs = 453,
    NoUnderlyings = 539,
    NoLegs = 555,
    _,
};

/// FIX MsgType (tag 35) string constants: FIX 4.0 through 4.4.
/// Use these instead of raw string literals in route tables and sendMessage calls.
pub const MsgType = struct {
    // Session (handled internally by serveConn, do not route these)
    pub const Heartbeat: []const u8 = "0";
    pub const TestRequest: []const u8 = "1";
    pub const ResendRequest: []const u8 = "2";
    pub const Reject: []const u8 = "3";
    pub const SequenceReset: []const u8 = "4";
    pub const Logout: []const u8 = "5";
    pub const Logon: []const u8 = "A";

    // --------------------------------------------------------- //

    // Application: FIX 4.0 / 4.1
    pub const IOI: []const u8 = "C";
    pub const NewOrderSingle: []const u8 = "D";
    pub const NewOrderList: []const u8 = "E";
    pub const OrderCancelRequest: []const u8 = "F";
    pub const OrderCancelReplaceRequest: []const u8 = "G";
    pub const OrderStatusRequest: []const u8 = "H";
    pub const Allocation: []const u8 = "J";
    pub const ListCancelRequest: []const u8 = "K";
    pub const ListExecute: []const u8 = "L";
    pub const ListStatusRequest: []const u8 = "M";
    pub const ListStatus: []const u8 = "N";
    pub const AllocationACK: []const u8 = "P";
    pub const Quote: []const u8 = "S";
    pub const IOIAcknowledgement: []const u8 = "6";
    pub const ExecutionReport: []const u8 = "8";
    pub const OrderCancelReject: []const u8 = "9";

    // --------------------------------------------------------- //

    // Application: FIX 4.2
    pub const QuoteRequest: []const u8 = "R";
    pub const SettlementInstructions: []const u8 = "T";
    pub const MarketDataRequest: []const u8 = "V";
    pub const MarketDataSnapshot: []const u8 = "W";
    pub const MarketDataIncremental: []const u8 = "X";
    pub const MarketDataRequestReject: []const u8 = "Y";
    pub const BusinessMessageReject: []const u8 = "j";

    // --------------------------------------------------------- //

    // Application: FIX 4.3
    pub const QuoteCancel: []const u8 = "Z";
    pub const QuoteStatusRequest: []const u8 = "a";
    pub const MassQuoteAcknowledgement: []const u8 = "b";
    pub const SecurityDefinitionRequest: []const u8 = "c";
    pub const SecurityDefinition: []const u8 = "d";
    pub const SecurityStatusRequest: []const u8 = "e";
    pub const SecurityStatus: []const u8 = "f";
    pub const TradingSessionStatusRequest: []const u8 = "g";
    pub const TradingSessionStatus: []const u8 = "h";
    pub const MassQuote: []const u8 = "i";

    // --------------------------------------------------------- //

    // Application: FIX 4.4 (two-character types)
    pub const TradeCaptureReport: []const u8 = "AE";
    pub const OrderMassStatusRequest: []const u8 = "AF";
    pub const QuoteRequestReject: []const u8 = "AG";
    pub const RFQRequest: []const u8 = "AH";
};

pub const Field = struct {
    tag: Tag,
    value: []const u8,
};

pub const BuildField = struct {
    tag: Tag,
    value: []const u8,
};

// --------------------------------------------------------- //

/// Scan buf for the end of the first complete FIX message.
///
/// Return:
/// - index one past the final SOH of the tag-10 field
/// - null if no complete message found
pub fn findMessageEnd(buf: []const u8) ?usize {
    var i: usize = 0;
    while (i + 4 <= buf.len) : (i += 1) {
        if (buf[i] == SOH and buf[i + 1] == '1' and buf[i + 2] == '0' and buf[i + 3] == '=') {
            const value_start = i + 4;
            const end = std.mem.indexOfScalarPos(u8, buf, value_start, SOH) orelse return null;
            return end + 1;
        }
    }
    return null;
}

/// Parse tag=value fields from a raw FIX message buf.
/// Fields are zero-copy slices into buf.
///
/// Return:
/// - !usize (number of fields parsed)
/// - error.ZixTooManyFields if out is too small
/// - error.ZixBadTag if a tag cannot be parsed as u16
pub fn parseFields(buf: []const u8, out: []Field) !usize {
    var count: usize = 0;
    var i: usize = 0;
    while (i < buf.len) {
        if (count >= out.len) return error.ZixTooManyFields;
        const eq = std.mem.indexOfScalarPos(u8, buf, i, '=') orelse break;
        const soh = std.mem.indexOfScalarPos(u8, buf, eq + 1, SOH) orelse break;
        const tag_num = std.fmt.parseInt(u16, buf[i..eq], 10) catch return error.ZixBadTag;
        out[count] = .{ .tag = @enumFromInt(tag_num), .value = buf[eq + 1 .. soh] };
        count += 1;
        i = soh + 1;
    }
    return count;
}

/// Return the value of the first field with the given tag, or null.
pub fn getField(fields: []const Field, tag: Tag) ?[]const u8 {
    for (fields) |f| {
        if (f.tag == tag) return f.value;
    }
    return null;
}

/// Sum of all bytes in buf, mod 256.
pub fn computeChecksum(buf: []const u8) u8 {
    var sum: u32 = 0;
    for (buf) |b| sum += b;
    return @truncate(sum % CHECKSUM_MODULUS);
}

/// Verify the tag-10 CheckSum field in a complete raw FIX message.
/// Sum covers all bytes from the start through (and including) the SOH of the
/// last field before tag 10.
pub fn verifyChecksum(raw: []const u8) bool {
    var i: usize = 0;
    while (i + 4 <= raw.len) : (i += 1) {
        if (raw[i] == SOH and raw[i + 1] == '1' and raw[i + 2] == '0' and raw[i + 3] == '=') {
            const checksum = computeChecksum(raw[0 .. i + 1]);
            const value_start = i + 4;
            const soh = std.mem.indexOfScalarPos(u8, raw, value_start, SOH) orelse return false;
            const checksum_value = std.fmt.parseInt(u8, raw[value_start..soh], 10) catch return false;
            return checksum == checksum_value;
        }
    }
    return false;
}

/// Build a complete FIX 4.2 message into out.
///
/// Param:
/// sender - []const u8 (our SenderCompID)
/// target - []const u8 (peer TargetCompID)
/// seq - u32 (outbound sequence)
/// msgtype - []const u8 (tag-35 value)
/// extra - []const BuildField (additional body fields after the standard header)
///
/// Return:
/// - number of bytes written
pub fn buildMessage(
    out: []u8,
    sender: []const u8,
    target: []const u8,
    seq: u32,
    msgtype: []const u8,
    extra: []const BuildField,
) !usize {
    var body: [MAX_MSG_SIZE]u8 = undefined;
    var bp: usize = 0;

    bp += (try std.fmt.bufPrint(body[bp..], "35={s}\x01", .{msgtype})).len;
    bp += (try std.fmt.bufPrint(body[bp..], "49={s}\x01", .{sender})).len;
    bp += (try std.fmt.bufPrint(body[bp..], "56={s}\x01", .{target})).len;
    bp += (try std.fmt.bufPrint(body[bp..], "34={d}\x01", .{seq})).len;
    bp += (try std.fmt.bufPrint(body[bp..], "52=20260520-00:00:00\x01", .{})).len;
    for (extra) |f| {
        bp += (try std.fmt.bufPrint(body[bp..], "{d}={s}\x01", .{ @intFromEnum(f.tag), f.value })).len;
    }

    var pos: usize = 0;
    pos += (try std.fmt.bufPrint(out[pos..], "8={s}\x01", .{VERSION})).len;
    pos += (try std.fmt.bufPrint(out[pos..], "9={d}\x01", .{bp})).len;
    if (pos + bp > out.len) return error.NoSpaceLeft;
    @memcpy(out[pos..][0..bp], body[0..bp]);
    pos += bp;

    const checksum = computeChecksum(out[0..pos]);
    pos += (try std.fmt.bufPrint(out[pos..], "10={d:0>3}\x01", .{checksum})).len;

    return pos;
}

/// Return the current wall-clock time in nanoseconds (Unix epoch basis).
pub fn wallClockNs() u64 {
    if (comptime builtin.target.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.REALTIME, &ts);
        return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
    }

    if (comptime builtin.target.os.tag == .windows) return win_io.wallClockNs();

    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.REALTIME, &ts);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

// --------------------------------------------------------- //

/// Handler function type for routed application messages.
///
/// Param:
/// req - *FixRequest (typed view over the received message's fields)
/// res - *FixResponse (builder for the reply, sendMessage)
/// ctx - *FixContext (per-connection env: io, deadline, isExpired)
///
/// Return:
/// - anyerror!void, errors pass through silently (no auto-reply on error)
pub const HandlerFn = *const fn (req: *FixRequest, res: *FixResponse, ctx: *FixContext) anyerror!void;

/// A route entry mapping a FIX MsgType (tag 35) to a handler function.
pub const FixRoute = struct {
    /// MsgType value (tag 35) to match (e.g. "D" for NewOrderSingle).
    msg_type: []const u8,
    /// Handler invoked when a message with this MsgType arrives.
    handler: HandlerFn,
    /// Per-route handler timeout in milliseconds. 0 = use server default (handler_timeout_ms).
    timeout_ms: u32 = 0,
};

/// Zero-copy view over the parsed fields of one received FIX message.
pub const FixRequest = struct {
    fields: []const Field,

    /// Return the value of the first field with the given tag, or null.
    pub fn getField(self: FixRequest, tag: Tag) ?[]const u8 {
        for (self.fields) |f| {
            if (f.tag == tag) return f.value;
        }

        return null;
    }
};

// --------------------------------------------------------- //
// Framed-engine response sink (ADR-037 Phase 4 extension). While a sink is
// installed (tl_resp_sink, the .URING ring path), FIX replies stage into it and
// coalesce into one ring send, otherwise they go straight to the fd (the blocking
// serveConn path), preserving the existing behavior.

/// Read some bytes from fd: the ntdll shim on Windows, std.posix.read elsewhere.
fn readOnceFD(fd: std.posix.fd_t, buf: []u8) !usize {
    if (comptime builtin.os.tag == .windows) return win_io.readOnce(fd, buf);

    return std.posix.read(fd, buf);
}

/// Poll fd for POLL.IN with a timeout. Windows has no poll here: report one
/// ready descriptor and let the read block (session timeouts degrade there).
///
/// Return:
/// - usize (ready count, 0 on timeout)
/// - null on a poll error
fn pollInFD(fd: std.posix.fd_t, timeout_ms: i32) ?usize {
    if (comptime builtin.os.tag == .windows) return 1;

    var poll_fd = [1]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};

    return std.posix.poll(&poll_fd, timeout_ms) catch null;
}

fn rawFixWrite(fd: std.posix.fd_t, data: []const u8) error{BrokenPipe}!void {
    if (comptime builtin.os.tag == .windows) return win_io.writeAll(fd, data);

    var remaining = data;
    while (remaining.len > 0) {
        const rc = std.posix.system.write(fd, remaining.ptr, remaining.len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) return error.BrokenPipe;

                remaining = remaining[n..];
            },
            .INTR => continue,
            else => return error.BrokenPipe,
        }
    }
}

/// Coalescing sink for the FIX .URING path. Oversize writes flush straight to the
/// fd (safe under the ring's half-duplex guarantee).
pub const RespSink = struct {
    fd: std.posix.fd_t,
    buf: []u8,
    len: usize = 0,
    failed: bool = false,

    pub fn append(self: *RespSink, bytes: []const u8) void {
        if (bytes.len > self.buf.len) {
            self.flush();
            rawFixWrite(self.fd, bytes) catch {
                self.failed = true;
            };

            return;
        }

        if (self.len + bytes.len > self.buf.len) self.flush();

        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    pub fn flush(self: *RespSink) void {
        if (self.len == 0) return;

        rawFixWrite(self.fd, self.buf[0..self.len]) catch {
            self.failed = true;
        };
        self.len = 0;
    }
};

/// Active sink for the current worker thread (set by the FIX ring worker).
pub threadlocal var tl_resp_sink: ?*RespSink = null;

/// Write bytes to the connection: into the sink when installed (coalesced ring
/// send), otherwise straight to the fd (the blocking serveConn path).
pub fn writeAllFD(fd: std.posix.fd_t, data: []const u8) error{BrokenPipe}!void {
    if (tl_resp_sink) |sink| {
        sink.append(data);

        return if (sink.failed) error.BrokenPipe else {};
    }

    return rawFixWrite(fd, data);
}

// --------------------------------------------------------- //

/// Builder over buildMessage plus the SOH-framed write. Independent of FixContext
/// (not borrowed from it), so a handler can send after the context it was handed
/// goes out of scope, e.g. from a captured closure.
pub const FixResponse = struct {
    /// SenderCompID of the peer (from their Logon message, tag 49). The outgoing target.
    sender_comp_id: []const u8,
    /// Our own SenderCompID (the server comp_id from config). The outgoing sender.
    target_comp_id: []const u8,
    _fd: std.posix.fd_t,
    _seq_out: *u32,
    /// Whether a message for the request in flight was handed to the wire. Read by the engine on a
    /// handler error, so a handler that already answered is not followed by a Reject the peer would
    /// read as a second, contradictory answer.
    sent: bool = false,

    /// Build and send a FIX message to the peer.
    ///
    /// Note:
    /// - Both failures used to be swallowed here, so a handler could not tell a delivered message
    ///   from one that never left. They are reported now: `try` hands them to the engine, which
    ///   answers the peer with a Reject, and a handler that wants to answer differently catches
    ///   them itself.
    ///
    /// Param:
    /// msg_type - []const u8 (tag-35 value, e.g. "8" for ExecutionReport)
    /// extra - []const BuildField (additional body fields after the standard header)
    ///
    /// Return:
    /// - void
    /// - error.ZixFixMessageTooLarge when the built message does not fit MAX_MSG_SIZE
    /// - error.BrokenPipe when the peer is gone
    pub fn sendMessage(self: *FixResponse, msg_type: []const u8, extra: []const BuildField) !void {
        var out_buf: [MAX_MSG_SIZE]u8 = undefined;
        const n = buildMessage(&out_buf, self.target_comp_id, self.sender_comp_id, self._seq_out.*, msg_type, extra) catch {
            return error.ZixFixMessageTooLarge;
        };

        self._seq_out.* += 1;
        self.sent = true;

        // Routes through tl_resp_sink on the ring (coalesced send), direct
        // posix write under the blocking serveConn path (sink null).
        return writeAllFD(self._fd, out_buf[0..n]);
    }
};

/// Per-connection context passed to each routed handler.
pub const FixContext = struct {
    /// SenderCompID of the peer (from their Logon message, tag 49).
    sender_comp_id: []const u8,
    /// Our own SenderCompID (the server comp_id from config, tag 56 in their message).
    target_comp_id: []const u8,
    /// Absolute deadline in nanoseconds (wall clock). Null = no deadline.
    /// Set at dispatch from the server-wide handler_timeout_ms, tightened by a
    /// matching Route.timeout_ms inside the router. Handler may read and overwrite.
    deadline_ns: ?u64 = null,
    /// Io backend for the connection. Carried for symmetry with the other engines'
    /// Context, and for a handler that needs to make a driver call inline.
    io: std.Io,
    /// Per-request scratch allocator, backed by a stack buffer (FixContext parity
    /// without a heap call, keeps the FIX core zero-heap-allocation).
    allocator: std.mem.Allocator,
    _fd: std.posix.fd_t,
    _seq_out: *u32,

    /// Return a copy with the deadline set to now + ms.
    pub fn withTimeout(self: FixContext, ms: u64) FixContext {
        var ctx = self;
        ctx.deadline_ns = wallClockNs() + ms * std.time.ns_per_ms;

        return ctx;
    }

    /// Set the deadline to now + ms in place.
    pub fn setTimeout(self: *FixContext, ms: u64) void {
        self.deadline_ns = wallClockNs() + ms * std.time.ns_per_ms;
    }

    /// Return a copy with an explicit absolute deadline (wall-clock nanoseconds).
    pub fn withDeadline(self: FixContext, deadline_ns: u64) FixContext {
        var ctx = self;
        ctx.deadline_ns = deadline_ns;

        return ctx;
    }

    /// Whether the deadline has passed. False when no deadline is set.
    pub fn isExpired(self: *const FixContext) bool {
        return self.timedOut();
    }

    /// Whether the deadline has passed. False when no deadline is set. The
    /// handler must check this explicitly, it does not interrupt anything.
    pub fn timedOut(self: *const FixContext) bool {
        const deadline = self.deadline_ns orelse return false;

        return wallClockNs() >= deadline;
    }
};

/// Build the trio and invoke a routed handler, mirroring Http1's core.invokeHandler (ADR-062).
///
/// Note:
/// - A handler that returns an error without having sent anything leaves the peer waiting on a
///   message that will never come. The engine answers it with a Reject (35=3) carrying the
///   RefSeqNum of the message that failed, so the peer learns which one was refused.
/// - A handler that already sent a message is left alone. A Reject after an answer reads to the
///   peer as a second, contradictory reply to the same message.
/// - An error the handler swallows itself is the handler's own business. The engine answers an
///   error the handler RETURNS, nothing else.
pub inline fn invokeHandler(handler_fn: HandlerFn, fields: []const Field, ctx: *FixContext) void {
    var req = FixRequest{ .fields = fields };
    var res = FixResponse{
        .sender_comp_id = ctx.sender_comp_id,
        .target_comp_id = ctx.target_comp_id,
        ._fd = ctx._fd,
        ._seq_out = ctx._seq_out,
    };

    handler_fn(&req, &res, ctx) catch {
        if (res.sent) return;

        const ref_seq = getField(fields, .MsgSeqNum) orelse "0";
        res.sendMessage(MsgType.Reject, &[_]BuildField{
            .{ .tag = .RefSeqNum, .value = ref_seq },
            .{ .tag = .Text, .value = HANDLER_ERROR_TEXT },
        }) catch {};
    };
}

/// Reject text (tag 58) the engine answers with when a handler returned an error without sending
/// anything. Deliberately says nothing about what failed: the counterparty is not the audience for
/// a server-side fault, and a handler that knows the detail sends its own Reject instead.
const HANDLER_ERROR_TEXT: []const u8 = "handler error";

// --------------------------------------------------------- //

/// Options for serveConn.
pub const FixServeOpts = struct {
    /// Optional logger. When non-null, session() is called after each message processed.
    logger: ?*Logger = null,
    /// Default HeartBtInt (seconds) echoed in the Logon response when the client omits tag 108.
    default_heartbeat_secs: u32 = 30,
    /// Heartbeat timeout in milliseconds. 0 = disabled.
    /// When non-zero: after this interval with no incoming message, a TestRequest (35=1) is sent.
    /// If no response arrives within another interval, a Logout (35=5) is sent and the connection closes.
    /// Note: applies only after Logon completes (peer CompID known). Before Logon, timeout closes silently.
    heartbeat_timeout_ms: u32 = 0,
    /// Idle connection timeout in milliseconds. 0 = disabled.
    /// When non-zero and heartbeat_timeout_ms is 0: connection is closed if no message arrives
    /// within this interval (no TestRequest is sent before closing).
    conn_timeout_ms: u32 = 0,
    /// Server-wide default handler processing timeout in milliseconds. 0 = disabled.
    /// Applied to each routed message dispatch. Per-route FixRoute.timeout_ms overrides this.
    handler_timeout_ms: u32 = 0,
    /// Application message handler, built via Fix.Router(&[_]Fix.Route{...}).dispatch.
    /// Null = echo all non-session messages (backward compat).
    handler: ?HandlerFn = null,
};

/// Serve one FIX connection: Logon handshake, route/echo loop, Logout.
/// Closes the stream before returning.
///
/// Param:
/// comp_id - []const u8 (the server's SenderCompID)
/// opts - FixServeOpts (logger, timeouts, and optional application routes)
pub fn serveConn(stream: std.Io.net.Stream, io: std.Io, comp_id: []const u8, opts: FixServeOpts) !void {
    defer stream.close(io);
    var rd_buf: [MAX_MSG_SIZE]u8 = undefined;
    var wr_buf: [MAX_MSG_SIZE]u8 = undefined;
    var reader = stream.reader(io, &rd_buf);
    var writer = stream.writer(io, &wr_buf);
    const fd = stream.socket.handle;

    var recv_buf: [MAX_MSG_SIZE * 2]u8 = undefined;
    var recv_len: usize = 0;

    var seq_out: u32 = 1;
    var peer_comp_id: [64]u8 = undefined;
    var peer_len: usize = 0;
    var sent_test_request: bool = false;

    outer: while (true) {
        const msg_end = if (opts.heartbeat_timeout_ms > 0) hb: {
            const timeout_ms: i32 = @intCast(@min(opts.heartbeat_timeout_ms, @as(u32, std.math.maxInt(i32))));
            while (true) {
                if (findMessageEnd(recv_buf[0..recv_len])) |end| break :hb end;
                if (recv_len >= recv_buf.len) return error.ZixMessageTooLarge;
                const nready = pollInFD(fd, timeout_ms) orelse break :outer;
                if (nready == 0) {
                    if (peer_len > 0) {
                        var hb_out: [MAX_MSG_SIZE]u8 = undefined;
                        if (sent_test_request) {
                            const n = buildMessage(&hb_out, comp_id, peer_comp_id[0..peer_len], seq_out, MsgType.Logout, &.{}) catch break :outer;
                            seq_out += 1;
                            writer.interface.writeAll(hb_out[0..n]) catch {};
                            writer.interface.flush() catch {};
                        } else {
                            sent_test_request = true;
                            var test_req_id_buf: [16]u8 = undefined;
                            const test_req_id = std.fmt.bufPrint(&test_req_id_buf, "{d}", .{seq_out}) catch "1";
                            const extra = [_]BuildField{.{ .tag = .TestReqID, .value = test_req_id }};
                            const n = buildMessage(&hb_out, comp_id, peer_comp_id[0..peer_len], seq_out, MsgType.TestRequest, &extra) catch break :outer;
                            seq_out += 1;
                            writer.interface.writeAll(hb_out[0..n]) catch {};
                            writer.interface.flush() catch {};
                            continue;
                        }
                    }
                    break :outer;
                }
                const n = readOnceFD(fd, recv_buf[recv_len..]) catch break :outer;
                if (n == 0) break :outer;
                recv_len += n;
            }
            unreachable;
        } else if (opts.conn_timeout_ms > 0) conn_to: {
            const timeout_ms: i32 = @intCast(@min(opts.conn_timeout_ms, @as(u32, std.math.maxInt(i32))));
            while (true) {
                if (findMessageEnd(recv_buf[0..recv_len])) |end| break :conn_to end;
                if (recv_len >= recv_buf.len) return error.ZixMessageTooLarge;
                const nready = pollInFD(fd, timeout_ms) orelse break :outer;
                if (nready == 0) break :outer;
                const n = readOnceFD(fd, recv_buf[recv_len..]) catch break :outer;
                if (n == 0) break :outer;
                recv_len += n;
            }
            unreachable;
        } else no_hb: {
            while (true) {
                if (findMessageEnd(recv_buf[0..recv_len])) |end| break :no_hb end;
                if (recv_len >= recv_buf.len) return error.ZixMessageTooLarge;
                const b = reader.interface.takeByte() catch break :outer;
                recv_buf[recv_len] = b;
                recv_len += 1;
            }
            unreachable;
        };

        sent_test_request = false;

        const raw = recv_buf[0..msg_end];

        var fields: [MAX_FIELDS]Field = undefined;
        const field_count = parseFields(raw, &fields) catch return;
        const fslice = fields[0..field_count];

        if (!verifyChecksum(raw)) return;

        const msgtype = getField(fslice, .MsgType) orelse return;
        const sender = getField(fslice, .SenderCompID) orelse "";

        const remaining = recv_len - msg_end;
        if (remaining > 0) {
            std.mem.copyForwards(u8, recv_buf[0..remaining], recv_buf[msg_end..recv_len]);
        }
        recv_len = remaining;

        var out_buf: [MAX_MSG_SIZE]u8 = undefined;

        const seq_in = std.fmt.parseInt(u64, getField(fslice, .MsgSeqNum) orelse "0", 10) catch 0;

        if (std.mem.eql(u8, msgtype, MsgType.Logon)) {
            @memcpy(peer_comp_id[0..sender.len], sender);
            peer_len = sender.len;
            var hb_buf: [8]u8 = undefined;
            const hb_default = std.fmt.bufPrint(&hb_buf, "{d}", .{opts.default_heartbeat_secs}) catch "30";
            const hb_int = getField(fslice, .HeartBtInt) orelse hb_default;
            const extra = [_]BuildField{
                .{ .tag = .EncryptMethod, .value = "0" },
                .{ .tag = .HeartBtInt, .value = hb_int },
            };
            const n = try buildMessage(&out_buf, comp_id, peer_comp_id[0..peer_len], seq_out, MsgType.Logon, &extra);
            seq_out += 1;
            try writer.interface.writeAll(out_buf[0..n]);
            try writer.interface.flush();
            if (opts.logger) |lg| lg.session(msgtype, sender, comp_id, seq_in, "Logon");
        } else if (std.mem.eql(u8, msgtype, MsgType.Logout)) {
            const n = try buildMessage(&out_buf, comp_id, peer_comp_id[0..peer_len], seq_out, MsgType.Logout, &.{});
            seq_out += 1;
            try writer.interface.writeAll(out_buf[0..n]);
            try writer.interface.flush();
            if (opts.logger) |lg| lg.session(msgtype, sender, comp_id, seq_in, "Logout");
            break :outer;
        } else if (std.mem.eql(u8, msgtype, MsgType.Heartbeat)) {
            var extra_buf: [1]BuildField = undefined;
            var extra_len: usize = 0;
            if (getField(fslice, .TestReqID)) |test_req_id| {
                extra_buf[0] = .{ .tag = .TestReqID, .value = test_req_id };
                extra_len = 1;
            }
            const n = try buildMessage(&out_buf, comp_id, peer_comp_id[0..peer_len], seq_out, MsgType.Heartbeat, extra_buf[0..extra_len]);
            seq_out += 1;
            try writer.interface.writeAll(out_buf[0..n]);
            try writer.interface.flush();
            if (opts.logger) |lg| lg.session(msgtype, sender, comp_id, seq_in, "Heartbeat");
        } else if (std.mem.eql(u8, msgtype, MsgType.TestRequest)) {
            const test_req_id = getField(fslice, .TestReqID) orelse "0";
            const extra = [_]BuildField{.{ .tag = .TestReqID, .value = test_req_id }};
            const n = try buildMessage(&out_buf, comp_id, peer_comp_id[0..peer_len], seq_out, MsgType.Heartbeat, &extra);
            seq_out += 1;
            try writer.interface.writeAll(out_buf[0..n]);
            try writer.interface.flush();
            if (opts.logger) |lg| lg.session(msgtype, sender, comp_id, seq_in, "TestRequest");
        } else if (opts.handler != null and peer_len > 0) {
            var arena_buf: [FIX_CTX_ARENA_BYTES]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
            var ctx = FixContext{
                .sender_comp_id = peer_comp_id[0..peer_len],
                .target_comp_id = comp_id,
                .deadline_ns = if (opts.handler_timeout_ms > 0)
                    wallClockNs() + @as(u64, opts.handler_timeout_ms) * std.time.ns_per_ms
                else
                    null,
                .io = io,
                .allocator = fba.allocator(),
                ._fd = fd,
                ._seq_out = &seq_out,
            };

            invokeHandler(opts.handler.?, fslice, &ctx);
            if (opts.logger) |lg| lg.session(msgtype, peer_comp_id[0..peer_len], comp_id, seq_in, "dispatch");
        } else {
            var body_fields: [MAX_FIELDS]BuildField = undefined;
            var body_count: usize = 0;
            for (fslice) |f| {
                switch (f.tag) {
                    .BeginString, .BodyLength, .MsgType, .SenderCompID, .TargetCompID, .MsgSeqNum, .SendingTime, .CheckSum => {},
                    else => {
                        if (body_count < body_fields.len) {
                            body_fields[body_count] = .{ .tag = f.tag, .value = f.value };
                            body_count += 1;
                        }
                    },
                }
            }
            const n = try buildMessage(
                &out_buf,
                comp_id,
                peer_comp_id[0..peer_len],
                seq_out,
                msgtype,
                body_fields[0..body_count],
            );
            seq_out += 1;
            try writer.interface.writeAll(out_buf[0..n]);
            try writer.interface.flush();
            if (opts.logger) |lg| lg.session(msgtype, sender, comp_id, seq_in, "msg");
        }
    }
}

// --------------------------------------------------------- //

/// Per-connection FIX session state for the .URING ring path. seq_out is the
/// outbound sequence number, peer_comp_id is the peer's SenderCompID captured at
/// Logon. Lives on the ring connection slot across recv completions.
pub const FixRingState = struct {
    seq_out: u32 = 1,
    peer_comp_id: [64]u8 = undefined,
    peer_len: usize = 0,
    /// Monotonic ms of the last inbound activity (the .URING heartbeat timer).
    last_activity_ms: u64 = 0,
    /// True once a TestRequest was sent on idle and a reply is awaited.
    sent_test_request: bool = false,
};

/// One ring process pass result: bytes consumed from the front of recv (whole
/// messages only) and whether the session should close (Logout or a protocol
/// error).
pub const FixRingResult = struct {
    consumed: usize,
    close: bool,
};

/// Resumable FIX message processor for the .URING ring path. Dispatches every
/// complete message in recv (session admin Logon/Logout/Heartbeat/TestRequest and
/// routed application messages), with every reply written through the installed
/// sink (tl_resp_sink) so the whole batch coalesces into one ring send. The caller
/// installs the sink, owns recv accumulation, and compacts the unconsumed tail
/// with the returned consumed count.
///
/// Note:
/// - This is the reactive half of the FIX session: it replies to peer
///   Heartbeat/TestRequest but does not drive the proactive idle-heartbeat timer
///   (server-initiated TestRequest/Logout on silence), which on the ring would
///   need an io_uring timeout SQE. The blocking serveConn keeps that timer.
///
/// Return:
/// - FixRingResult (consumed bytes, close flag)
/// Messages processed on this worker thread (skew counter). Owned by the worker
/// (threadlocal, plain increment, no contention), read and reported through the
/// system logger at worker exit so REUSEPORT skew across workers is measurable.
pub threadlocal var tl_messages_served: u64 = 0;

pub fn processFixRing(state: *FixRingState, comp_id: []const u8, opts: FixServeOpts, recv: []const u8, fd: std.posix.fd_t, io: std.Io) FixRingResult {
    var consumed: usize = 0;

    while (true) {
        const rem = recv[consumed..];
        const msg_end = findMessageEnd(rem) orelse break;
        const raw = rem[0..msg_end];
        consumed += msg_end;
        tl_messages_served += 1;

        var fields: [MAX_FIELDS]Field = undefined;
        const field_count = parseFields(raw, &fields) catch return .{ .consumed = consumed, .close = true };
        const fslice = fields[0..field_count];

        if (!verifyChecksum(raw)) return .{ .consumed = consumed, .close = true };

        const msgtype = getField(fslice, .MsgType) orelse return .{ .consumed = consumed, .close = true };
        const sender = getField(fslice, .SenderCompID) orelse "";
        const seq_in = std.fmt.parseInt(u64, getField(fslice, .MsgSeqNum) orelse "0", 10) catch 0;

        var out_buf: [MAX_MSG_SIZE]u8 = undefined;

        if (std.mem.eql(u8, msgtype, MsgType.Logon)) {
            @memcpy(state.peer_comp_id[0..sender.len], sender);
            state.peer_len = sender.len;
            var hb_buf: [8]u8 = undefined;
            const hb_default = std.fmt.bufPrint(&hb_buf, "{d}", .{opts.default_heartbeat_secs}) catch "30";
            const hb_int = getField(fslice, .HeartBtInt) orelse hb_default;
            const extra = [_]BuildField{
                .{ .tag = .EncryptMethod, .value = "0" },
                .{ .tag = .HeartBtInt, .value = hb_int },
            };
            const n = buildMessage(&out_buf, comp_id, state.peer_comp_id[0..state.peer_len], state.seq_out, MsgType.Logon, &extra) catch return .{ .consumed = consumed, .close = true };
            state.seq_out += 1;
            writeAllFD(fd, out_buf[0..n]) catch {};
            if (opts.logger) |lg| lg.session(msgtype, sender, comp_id, seq_in, "Logon");
        } else if (std.mem.eql(u8, msgtype, MsgType.Logout)) {
            const n = buildMessage(&out_buf, comp_id, state.peer_comp_id[0..state.peer_len], state.seq_out, MsgType.Logout, &.{}) catch return .{ .consumed = consumed, .close = true };
            state.seq_out += 1;
            writeAllFD(fd, out_buf[0..n]) catch {};
            if (opts.logger) |lg| lg.session(msgtype, sender, comp_id, seq_in, "Logout");

            return .{ .consumed = consumed, .close = true };
        } else if (std.mem.eql(u8, msgtype, MsgType.Heartbeat)) {
            var extra_buf: [1]BuildField = undefined;
            var extra_len: usize = 0;
            if (getField(fslice, .TestReqID)) |test_req_id| {
                extra_buf[0] = .{ .tag = .TestReqID, .value = test_req_id };
                extra_len = 1;
            }
            const n = buildMessage(&out_buf, comp_id, state.peer_comp_id[0..state.peer_len], state.seq_out, MsgType.Heartbeat, extra_buf[0..extra_len]) catch return .{ .consumed = consumed, .close = true };
            state.seq_out += 1;
            writeAllFD(fd, out_buf[0..n]) catch {};
            if (opts.logger) |lg| lg.session(msgtype, sender, comp_id, seq_in, "Heartbeat");
        } else if (std.mem.eql(u8, msgtype, MsgType.TestRequest)) {
            const test_req_id = getField(fslice, .TestReqID) orelse "0";
            const extra = [_]BuildField{.{ .tag = .TestReqID, .value = test_req_id }};
            const n = buildMessage(&out_buf, comp_id, state.peer_comp_id[0..state.peer_len], state.seq_out, MsgType.Heartbeat, &extra) catch return .{ .consumed = consumed, .close = true };
            state.seq_out += 1;
            writeAllFD(fd, out_buf[0..n]) catch {};
            if (opts.logger) |lg| lg.session(msgtype, sender, comp_id, seq_in, "TestRequest");
        } else if (opts.handler != null and state.peer_len > 0) {
            var arena_buf: [FIX_CTX_ARENA_BYTES]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&arena_buf);
            var ctx = FixContext{
                .sender_comp_id = state.peer_comp_id[0..state.peer_len],
                .target_comp_id = comp_id,
                .deadline_ns = if (opts.handler_timeout_ms > 0)
                    wallClockNs() + @as(u64, opts.handler_timeout_ms) * std.time.ns_per_ms
                else
                    null,
                .io = io,
                .allocator = fba.allocator(),
                ._fd = fd,
                ._seq_out = &state.seq_out,
            };

            invokeHandler(opts.handler.?, fslice, &ctx);
            if (opts.logger) |lg| lg.session(msgtype, state.peer_comp_id[0..state.peer_len], comp_id, seq_in, "dispatch");
        } else {
            var body_fields: [MAX_FIELDS]BuildField = undefined;
            var body_count: usize = 0;
            for (fslice) |f| {
                switch (f.tag) {
                    .BeginString, .BodyLength, .MsgType, .SenderCompID, .TargetCompID, .MsgSeqNum, .SendingTime, .CheckSum => {},
                    else => {
                        if (body_count < body_fields.len) {
                            body_fields[body_count] = .{ .tag = f.tag, .value = f.value };
                            body_count += 1;
                        }
                    },
                }
            }
            const n = buildMessage(&out_buf, comp_id, state.peer_comp_id[0..state.peer_len], state.seq_out, msgtype, body_fields[0..body_count]) catch return .{ .consumed = consumed, .close = true };
            state.seq_out += 1;
            writeAllFD(fd, out_buf[0..n]) catch {};
            if (opts.logger) |lg| lg.session(msgtype, sender, comp_id, seq_in, "msg");
        }
    }

    return .{ .consumed = consumed, .close = false };
}

/// Monotonic clock in milliseconds, for the .URING heartbeat timer.
pub fn monotonicMs() u64 {
    if (comptime builtin.target.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        const s: u64 = if (ts.sec >= 0) @intCast(ts.sec) else 0;
        const ms: u64 = if (ts.nsec >= 0) @as(u64, @intCast(ts.nsec)) / 1_000_000 else 0;

        return s * 1000 + ms;
    }

    if (comptime builtin.target.os.tag == .windows) return win_io.monotonicUs() / std.time.us_per_ms;

    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(.MONOTONIC, &ts);
    const s: u64 = if (ts.sec >= 0) @intCast(ts.sec) else 0;
    const ms: u64 = if (ts.nsec >= 0) @as(u64, @intCast(ts.nsec)) / 1_000_000 else 0;

    return s * 1000 + ms;
}

/// Per-connection heartbeat tick for the .URING ring, called from the per-worker
/// periodic timer. When the session is logged in and idle past hb_ms, sends a
/// TestRequest on the first tick and a Logout on the next (written straight to fd,
/// outside the sink, since the timer fires between recv/send cycles). The caller
/// reaps the connection when this returns true.
///
/// Return:
/// - bool (true means Logout was sent after continued silence: reap the connection)
pub fn fixHeartbeatTick(state: *FixRingState, comp_id: []const u8, fd: std.posix.fd_t, now_ms: u64, hb_ms: u32) bool {
    if (hb_ms == 0 or state.peer_len == 0) return false;
    if (now_ms - state.last_activity_ms < hb_ms) return false;

    var out_buf: [MAX_MSG_SIZE]u8 = undefined;

    if (state.sent_test_request) {
        const n = buildMessage(&out_buf, comp_id, state.peer_comp_id[0..state.peer_len], state.seq_out, MsgType.Logout, &.{}) catch return true;
        state.seq_out += 1;
        rawFixWrite(fd, out_buf[0..n]) catch {};

        return true;
    }

    state.sent_test_request = true;
    var id_buf: [16]u8 = undefined;
    const id = std.fmt.bufPrint(&id_buf, "{d}", .{state.seq_out}) catch "1";
    const extra = [_]BuildField{.{ .tag = .TestReqID, .value = id }};
    const n = buildMessage(&out_buf, comp_id, state.peer_comp_id[0..state.peer_len], state.seq_out, MsgType.TestRequest, &extra) catch return false;
    state.seq_out += 1;
    rawFixWrite(fd, out_buf[0..n]) catch {};

    return false;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Test fd sentinel: Windows descriptors are opaque pointers, POSIX are ints.
const TEST_FD: std.posix.fd_t = if (builtin.os.tag == .windows) std.os.windows.INVALID_HANDLE_VALUE else -1;

test "zix fix: findMessageEnd returns null for empty buf" {
    try std.testing.expect(findMessageEnd("") == null);
}

test "zix fix: findMessageEnd returns null when tag 10 absent" {
    const buf = "8=FIX.4.2\x019=5\x0135=A\x01";
    try std.testing.expect(findMessageEnd(buf) == null);
}

test "zix fix: findMessageEnd finds end of a complete message" {
    const buf = "8=FIX.4.2\x019=5\x0135=A\x0110=123\x01";
    const end = findMessageEnd(buf);
    try std.testing.expect(end != null);
    try std.testing.expectEqual(buf.len, end.?);
}

test "zix fix: findMessageEnd stops at first message when two are present" {
    const msg1 = "8=FIX.4.2\x019=5\x0135=A\x0110=001\x01";
    const msg2 = "8=FIX.4.2\x019=5\x0135=5\x0110=002\x01";
    const buf = msg1 ++ msg2;
    const end = findMessageEnd(buf);
    try std.testing.expect(end != null);
    try std.testing.expectEqual(msg1.len, end.?);
}

test "zix fix: parseFields extracts all tag=value pairs" {
    const msg = "8=FIX.4.2\x019=5\x0135=A\x0149=CLIENT\x0156=SERVER\x0134=1\x01";
    var fields: [16]Field = undefined;
    const n = try parseFields(msg, &fields);
    try std.testing.expectEqual(6, n);
    try std.testing.expectEqual(Tag.BeginString, fields[0].tag);
    try std.testing.expectEqualStrings("FIX.4.2", fields[0].value);
    try std.testing.expectEqual(Tag.MsgType, fields[2].tag);
    try std.testing.expectEqualStrings("A", fields[2].value);
    try std.testing.expectEqual(Tag.TargetCompID, fields[4].tag);
    try std.testing.expectEqualStrings("SERVER", fields[4].value);
}

test "zix fix: parseFields returns error.ZixBadTag on non-numeric tag" {
    const msg = "bad=value\x01";
    var fields: [4]Field = undefined;
    try std.testing.expectError(error.ZixBadTag, parseFields(msg, &fields));
}

test "zix fix: getField finds a tag" {
    const fields = [_]Field{
        .{ .tag = .BeginString, .value = "FIX.4.2" },
        .{ .tag = .MsgType, .value = "D" },
        .{ .tag = .SenderCompID, .value = "CLIENT" },
    };
    try std.testing.expectEqualStrings("D", getField(&fields, .MsgType).?);
    try std.testing.expectEqualStrings("CLIENT", getField(&fields, .SenderCompID).?);
}

test "zix fix: getField returns null for absent tag" {
    const fields = [_]Field{.{ .tag = .BeginString, .value = "FIX.4.2" }};
    try std.testing.expect(getField(&fields, .MsgType) == null);
}

test "zix fix: computeChecksum of empty buf is 0" {
    try std.testing.expectEqual(0, computeChecksum(""));
}

test "zix fix: computeChecksum wraps at 256" {
    const buf: [256]u8 = @splat(0x01);
    try std.testing.expectEqual(0, computeChecksum(&buf));
}

test "zix fix: computeChecksum known value" {
    const buf = "8=FIX.4.2\x01";
    try std.testing.expectEqual(31, computeChecksum(buf));
}

test "zix fix: buildMessage produces a verifiable checksum" {
    var out: [MAX_MSG_SIZE]u8 = undefined;
    const n = try buildMessage(&out, "SERVER", "CLIENT", 1, "A", &.{
        .{ .tag = .EncryptMethod, .value = "0" },
        .{ .tag = .HeartBtInt, .value = "30" },
    });
    try std.testing.expect(verifyChecksum(out[0..n]));
}

test "zix fix: buildMessage parses back with correct MsgType and CompIDs" {
    var out: [MAX_MSG_SIZE]u8 = undefined;
    const n = try buildMessage(&out, "SRV", "CLT", 5, "D", &.{
        .{ .tag = .ClOrdID, .value = "ORD001" },
        .{ .tag = .Symbol, .value = "AAPL" },
    });
    var fields: [MAX_FIELDS]Field = undefined;
    const field_count = try parseFields(out[0..n], &fields);
    const fslice = fields[0..field_count];

    try std.testing.expectEqualStrings("D", getField(fslice, .MsgType).?);
    try std.testing.expectEqualStrings("SRV", getField(fslice, .SenderCompID).?);
    try std.testing.expectEqualStrings("CLT", getField(fslice, .TargetCompID).?);
    try std.testing.expectEqualStrings("5", getField(fslice, .MsgSeqNum).?);
    try std.testing.expectEqualStrings("ORD001", getField(fslice, .ClOrdID).?);
    try std.testing.expectEqualStrings("AAPL", getField(fslice, .Symbol).?);
}

test "zix fix: verifyChecksum returns false for tampered byte" {
    var out: [MAX_MSG_SIZE]u8 = undefined;
    const n = try buildMessage(&out, "S", "C", 1, "0", &.{});
    out[5] ^= 0xFF;
    try std.testing.expect(!verifyChecksum(out[0..n]));
}

test "zix fix: bodyLength field equals byte count from tag 35 to last SOH before tag 10" {
    var out: [MAX_MSG_SIZE]u8 = undefined;
    const n = try buildMessage(&out, "SRV", "CLT", 1, "A", &.{
        .{ .tag = .EncryptMethod, .value = "0" },
    });
    const raw = out[0..n];

    var fields: [MAX_FIELDS]Field = undefined;
    const field_count = try parseFields(raw, &fields);
    const body_len_str = getField(fields[0..field_count], .BodyLength).?;
    const body_len = try std.fmt.parseInt(usize, body_len_str, 10);

    const tag35_start = std.mem.indexOf(u8, raw, "35=").?;

    var i: usize = 0;
    var tag10_soh: usize = 0;
    while (i + 4 <= raw.len) : (i += 1) {
        if (raw[i] == SOH and raw[i + 1] == '1' and raw[i + 2] == '0' and raw[i + 3] == '=') {
            tag10_soh = i + 1;
            break;
        }
    }
    const measured = tag10_soh - tag35_start;
    try std.testing.expectEqual(body_len, measured);
}

test "zix fix: MsgType session constants match FIX 4.x spec" {
    try std.testing.expectEqualStrings("0", MsgType.Heartbeat);
    try std.testing.expectEqualStrings("1", MsgType.TestRequest);
    try std.testing.expectEqualStrings("2", MsgType.ResendRequest);
    try std.testing.expectEqualStrings("3", MsgType.Reject);
    try std.testing.expectEqualStrings("4", MsgType.SequenceReset);
    try std.testing.expectEqualStrings("5", MsgType.Logout);
    try std.testing.expectEqualStrings("A", MsgType.Logon);
}

test "zix fix: MsgType application single-char constants" {
    try std.testing.expectEqualStrings("8", MsgType.ExecutionReport);
    try std.testing.expectEqualStrings("9", MsgType.OrderCancelReject);
    try std.testing.expectEqualStrings("D", MsgType.NewOrderSingle);
    try std.testing.expectEqualStrings("F", MsgType.OrderCancelRequest);
    try std.testing.expectEqualStrings("G", MsgType.OrderCancelReplaceRequest);
    try std.testing.expectEqualStrings("V", MsgType.MarketDataRequest);
    try std.testing.expectEqualStrings("W", MsgType.MarketDataSnapshot);
    try std.testing.expectEqualStrings("X", MsgType.MarketDataIncremental);
    try std.testing.expectEqualStrings("j", MsgType.BusinessMessageReject);
}

test "zix fix: MsgType application two-char constants" {
    try std.testing.expectEqualStrings("AE", MsgType.TradeCaptureReport);
    try std.testing.expectEqualStrings("AF", MsgType.OrderMassStatusRequest);
    try std.testing.expectEqualStrings("AG", MsgType.QuoteRequestReject);
    try std.testing.expectEqualStrings("AH", MsgType.RFQRequest);
}

test "zix fix: fixHeartbeatTick sends TestRequest then Logout on idle" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    var state = FixRingState{};
    @memcpy(state.peer_comp_id[0..6], "CLIENT");
    state.peer_len = 6;
    state.last_activity_ms = 0;

    // Not idle yet (now - last < hb): no write, no state change.
    try std.testing.expect(!fixHeartbeatTick(&state, "ZIX", fds[1], 100, 200));
    try std.testing.expect(!state.sent_test_request);

    // Idle: first tick sends a TestRequest (35=1) and returns false.
    try std.testing.expect(!fixHeartbeatTick(&state, "ZIX", fds[1], 1000, 200));
    try std.testing.expect(state.sent_test_request);

    var buf: [512]u8 = undefined;
    const n1 = try std.posix.read(fds[0], &buf);
    var f1: [MAX_FIELDS]Field = undefined;
    const c1 = try parseFields(buf[0..findMessageEnd(buf[0..n1]).?], &f1);
    try std.testing.expectEqualStrings(MsgType.TestRequest, getField(f1[0..c1], .MsgType).?);

    // Still idle on the next tick: sends Logout (35=5) and returns true (reap).
    try std.testing.expect(fixHeartbeatTick(&state, "ZIX", fds[1], 2000, 200));

    const n2 = try std.posix.read(fds[0], &buf);
    var f2: [MAX_FIELDS]Field = undefined;
    const c2 = try parseFields(buf[0..findMessageEnd(buf[0..n2]).?], &f2);
    try std.testing.expectEqualStrings(MsgType.Logout, getField(f2[0..c2], .MsgType).?);
}

test "zix fix: fixHeartbeatTick is a no-op before Logon or when disabled" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var state = FixRingState{};
    state.last_activity_ms = 0;

    // peer_len == 0 (not logged in): no-op even when long idle.
    try std.testing.expect(!fixHeartbeatTick(&state, "ZIX", -1, 99999, 200));

    // hb_ms == 0 (disabled): no-op even when logged in.
    state.peer_len = 6;
    try std.testing.expect(!fixHeartbeatTick(&state, "ZIX", -1, 99999, 0));
}

test "zix fix: processFixRing counts each complete message in tl_messages_served" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var state = FixRingState{};
    const msg = "8=FIX.4.2\x019=5\x0135=A\x0110=001\x01";

    const before = tl_messages_served;
    _ = processFixRing(&state, "ZIX", .{}, msg, -1, undefined);

    try std.testing.expectEqual(before + 1, tl_messages_served);
}

test "zix fix: FixRequest.getField finds a tag and returns null for a missing one" {
    const fields = [_]Field{
        .{ .tag = .MsgType, .value = "D" },
        .{ .tag = .Symbol, .value = "AAPL" },
    };
    const req = FixRequest{ .fields = &fields };

    try std.testing.expectEqualStrings("D", req.getField(.MsgType).?);
    try std.testing.expectEqualStrings("AAPL", req.getField(.Symbol).?);
    try std.testing.expect(req.getField(.ClOrdID) == null);
}

test "zix fix: FixResponse.sendMessage is byte-identical to a direct buildMessage write" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    var seq: u32 = 1;
    var res = FixResponse{ .sender_comp_id = "CLIENT", .target_comp_id = "SERVER", ._fd = fds[1], ._seq_out = &seq };
    try res.sendMessage(MsgType.ExecutionReport, &[_]BuildField{.{ .tag = .ClOrdID, .value = "ORD1" }});

    var buf: [MAX_MSG_SIZE]u8 = undefined;
    const n = try std.posix.read(fds[0], &buf);

    var expected: [MAX_MSG_SIZE]u8 = undefined;
    const expected_n = try buildMessage(&expected, "SERVER", "CLIENT", 1, MsgType.ExecutionReport, &[_]BuildField{.{ .tag = .ClOrdID, .value = "ORD1" }});

    try std.testing.expectEqualStrings(expected[0..expected_n], buf[0..n]);
    try std.testing.expectEqual(@as(u32, 2), seq);
}

test "zix fix: FixContext.withTimeout, withDeadline, and timedOut" {
    var seq: u32 = 1;
    const base = FixContext{
        .sender_comp_id = "CLIENT",
        .target_comp_id = "SERVER",
        .io = undefined,
        .allocator = std.testing.allocator,
        ._fd = TEST_FD,
        ._seq_out = &seq,
    };

    try std.testing.expect(!base.isExpired());
    try std.testing.expect(!base.timedOut());

    const future = base.withTimeout(60_000);
    try std.testing.expect(future.deadline_ns != null);
    try std.testing.expect(!future.timedOut());

    const past = base.withDeadline(1);
    try std.testing.expect(past.timedOut());
    try std.testing.expect(past.isExpired());
}

test "zix fix: FixContext.setTimeout mutates the deadline in place" {
    var seq: u32 = 1;
    var ctx = FixContext{
        .sender_comp_id = "CLIENT",
        .target_comp_id = "SERVER",
        .io = undefined,
        .allocator = std.testing.allocator,
        ._fd = TEST_FD,
        ._seq_out = &seq,
    };

    try std.testing.expect(ctx.deadline_ns == null);

    ctx.setTimeout(60_000);

    try std.testing.expect(ctx.deadline_ns != null);
    try std.testing.expect(!ctx.timedOut());
}

test "zix fix: invokeHandler builds the trio and reaches the handler" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    const captured = struct {
        var msgtype: []const u8 = "";
        fn handler(req: *FixRequest, res: *FixResponse, ctx: *FixContext) anyerror!void {
            msgtype = req.getField(.MsgType) orelse "";
            _ = ctx;

            try res.sendMessage(MsgType.Heartbeat, &.{});
        }
    };
    captured.msgtype = "";

    var seq: u32 = 1;
    var ctx = FixContext{
        .sender_comp_id = "CLIENT",
        .target_comp_id = "SERVER",
        .io = undefined,
        .allocator = std.testing.allocator,
        ._fd = fds[1],
        ._seq_out = &seq,
    };

    const fields = [_]Field{.{ .tag = .MsgType, .value = "D" }};
    invokeHandler(captured.handler, &fields, &ctx);

    try std.testing.expectEqualStrings("D", captured.msgtype);

    var buf: [MAX_MSG_SIZE]u8 = undefined;
    const n = try std.posix.read(fds[0], &buf);
    try std.testing.expect(n > 0);
}

// --------------------------------------------------------- //
// Handler-error completion: the peer is answered once, and only when the handler left it waiting

/// Drive one handler over a socketpair and hand back everything the peer end received.
fn fixWireOf(handler_fn: HandlerFn, buf: []u8) ![]u8 {
    const linux = std.os.linux;

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer _ = linux.close(fds[0]);

    var seq: u32 = 1;
    var ctx = FixContext{
        .sender_comp_id = "CLIENT",
        .target_comp_id = "SERVER",
        .io = undefined,
        .allocator = std.testing.allocator,
        ._fd = fds[1],
        ._seq_out = &seq,
    };

    const fields = [_]Field{
        .{ .tag = .MsgType, .value = "D" },
        .{ .tag = .MsgSeqNum, .value = "77" },
    };
    invokeHandler(handler_fn, &fields, &ctx);

    // Closed before the read so the peer sees EOF rather than blocking on a live socket.
    _ = linux.close(fds[1]);

    const n = std.posix.read(fds[0], buf) catch 0;

    return buf[0..n];
}

/// Returns an error having sent nothing. The engine owes the peer a Reject.
fn fixErrorBeforeAnswerHandler(_: *FixRequest, _: *FixResponse, _: *FixContext) anyerror!void {
    return error.ZixHandlerBoom;
}

/// Answers, then returns an error. The engine must not add a Reject on top of the answer.
fn fixAnswerThenErrorHandler(_: *FixRequest, res: *FixResponse, _: *FixContext) anyerror!void {
    try res.sendMessage(MsgType.ExecutionReport, &[_]BuildField{.{ .tag = .ClOrdID, .value = "ORD1" }});

    return error.ZixHandlerBoom;
}

/// Swallows its own failure and returns cleanly. The engine adds nothing, the handler owns it.
fn fixSwallowedErrorHandler(_: *FixRequest, res: *FixResponse, _: *FixContext) anyerror!void {
    res.sendMessage(MsgType.ExecutionReport, &[_]BuildField{.{ .tag = .ClOrdID, .value = "ORD1" }}) catch {
        // The send is against a live socketpair here, so reaching this block at all means the
        // wire broke and the message count below would be reading a truncated stream.
        return error.ZixHandlerBoom;
    };
}

/// Count complete FIX messages in a raw byte stream, by their tag-8 opening.
fn countFixMessages(wire: []const u8) usize {
    return std.mem.count(u8, wire, "8=" ++ VERSION);
}

test "zix fix: a handler error with nothing sent is answered with a Reject" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("this test drives a Linux socketpair, test skipped", .{});
        return;
    }

    var buf: [MAX_MSG_SIZE]u8 = undefined;
    const wire = try fixWireOf(fixErrorBeforeAnswerHandler, &buf);

    std.log.info(".WIRE: {d} bytes, {d} messages", .{ wire.len, countFixMessages(wire) });

    try std.testing.expectEqual(@as(usize, 1), countFixMessages(wire));
    try std.testing.expect(std.mem.indexOf(u8, wire, "35=" ++ MsgType.Reject) != null);
    try std.testing.expect(std.mem.indexOf(u8, wire, "45=77") != null);
    try std.testing.expect(std.mem.indexOf(u8, wire, "58=handler error") != null);
}

test "zix fix: a handler that answered before failing gets no Reject on top" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("this test drives a Linux socketpair, test skipped", .{});
        return;
    }

    var buf: [MAX_MSG_SIZE]u8 = undefined;
    const wire = try fixWireOf(fixAnswerThenErrorHandler, &buf);

    try std.testing.expectEqual(@as(usize, 1), countFixMessages(wire));
    try std.testing.expect(std.mem.indexOf(u8, wire, "35=" ++ MsgType.ExecutionReport) != null);
    try std.testing.expect(std.mem.indexOf(u8, wire, "35=" ++ MsgType.Reject) == null);
}

test "zix fix: an error the handler swallows itself gets nothing from the engine" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("this test drives a Linux socketpair, test skipped", .{});
        return;
    }

    var buf: [MAX_MSG_SIZE]u8 = undefined;
    const wire = try fixWireOf(fixSwallowedErrorHandler, &buf);

    try std.testing.expectEqual(@as(usize, 1), countFixMessages(wire));
    try std.testing.expect(std.mem.indexOf(u8, wire, "35=" ++ MsgType.Reject) == null);
}

test "zix fix: sendMessage reports a dead peer instead of swallowing it" {
    if (comptime builtin.target.os.tag != .linux) {
        std.log.info("this test drives a Linux socketpair, test skipped", .{});
        return;
    }

    const linux = std.os.linux;

    var fds: [2]i32 = undefined;
    try std.testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer _ = linux.close(fds[1]);

    // The peer end goes first, so the send below has nowhere to land.
    _ = linux.close(fds[0]);

    var seq: u32 = 1;
    var res = FixResponse{ .sender_comp_id = "CLIENT", .target_comp_id = "SERVER", ._fd = fds[1], ._seq_out = &seq };

    const result = res.sendMessage(MsgType.Heartbeat, &.{});

    try std.testing.expectError(error.BrokenPipe, result);
}
