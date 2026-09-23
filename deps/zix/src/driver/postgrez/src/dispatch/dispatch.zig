//! Dispatch model: how the driver multiplexes socket I/O across connections.
//!
//! Note:
//! - ASYNC is the existing Executor (a thread pool of blocking connections,
//!   one round trip in flight per worker). It is the default and is untouched
//!   by this module.
//! - EPOLL and URING are one single thread that owns K non-blocking
//!   connections and pipelines many requests per connection, so the wire
//!   stays full without a thread per in-flight request. Transport here is
//!   that single-thread multiplexed path.
//! - Transport reuses the real Conn for connect, TLS negotiation and the
//!   SCRAM handshake, then runs the pipelined loop on the raw connection fd.
//!   Request bytes and reply parsing stay the caller's job (frontend.* to
//!   build a request, backend.decode to read a reply), so the wire protocol
//!   is shared with the blocking path, only the socket pump changes.
//! - Cleartext only: the raw-fd loop cannot drive a TLS session, so open()
//!   rejects a config with tls set. The blocking Conn/Pool path keeps TLS.

const std = @import("std");
const linux = std.os.linux;
const lib = @import("../lib.zig");
const conn_mod = @import("../conn.zig");

const Conn = conn_mod.Conn;
const Fd = std.posix.fd_t;

/// Default per-connection pipeline depth: requests a connection may owe
/// before submit stops filling it.
pub const DEFAULT_WINDOW: usize = 64;

/// Per-connection outbound staging: holds queued request bytes until the
/// socket accepts them.
const OUT_BUF: usize = 32 * 1024;
/// Per-connection inbound staging: holds reply bytes until whole replies frame.
const IN_BUF: usize = 64 * 1024;

/// Which transport pumps the socket, re-exported from the config home in
/// lib.zig: ASYNC selects the blocking Executor path, EPOLL and URING select
/// the multiplexed Transport.
pub const DispatchModel = lib.DispatchModel;

/// Reply sink: called once per completed request, in submit order per
/// connection. reply borrows the connection receive buffer and is valid only
/// for the duration of the call (copy what must outlive it).
///
/// Param:
/// context - ?*anyopaque (the caller pointer passed in Options)
/// tag - u64 (the routing tag submitted with the request)
/// reply - []const u8 (raw backend messages up to and including ReadyForQuery)
pub const OnReply = *const fn (context: ?*anyopaque, tag: u64, reply: []const u8) void;

// --------------------------------------------------------- //

/// Byte length of one complete reply at the front of bytes: every backend
/// message up to and including the first ReadyForQuery ('Z'). One request
/// that ends in Sync answers with exactly one such reply.
///
/// Return:
/// - usize length when a whole reply is present
/// - null when more bytes are needed
fn replyLen(bytes: []const u8) ?usize {
    var pos: usize = 0;

    while (true) {
        if (pos + 5 > bytes.len) return null;

        const length = std.mem.readInt(u32, bytes[pos + 1 ..][0..4], .big);
        if (length < 4) return null;

        const total = 1 + @as(usize, length);
        if (pos + total > bytes.len) return null;

        const tag = bytes[pos];
        pos += total;

        if (tag == 'Z') return pos;
    }
}

// --------------------------------------------------------- //

/// One multiplexed connection: the handshaked Conn plus its pipeline state.
const Channel = struct {
    conn: *Conn,
    fd: Fd,
    out: []u8,
    out_len: usize = 0,
    out_sent: usize = 0,
    in: []u8,
    in_len: usize = 0,
    inflight: usize = 0,
    tags: []u64,
    tag_head: usize = 0,
    tag_tail: usize = 0,

    /// Room for another request: under the window and with outbound space for
    /// a request of request_len bytes.
    fn accepts(self: *const Channel, window: usize, request_len: usize) bool {
        if (self.inflight >= window) return false;

        return self.out_len + request_len <= self.out.len;
    }

    /// Stage one request: append its bytes and remember its tag in submit
    /// order. accepts() must have returned true.
    fn stage(self: *Channel, request: []const u8, tag: u64) void {
        @memcpy(self.out[self.out_len..][0..request.len], request);
        self.out_len += request.len;

        self.tags[self.tag_tail] = tag;
        self.tag_tail = (self.tag_tail + 1) % self.tags.len;
        self.inflight += 1;
    }

    /// Oldest owed tag (caller ensures inflight > 0).
    fn popTag(self: *Channel) u64 {
        const tag = self.tags[self.tag_head];
        self.tag_head = (self.tag_head + 1) % self.tags.len;

        return tag;
    }

    /// Drop the sent prefix once the socket took the whole outbound buffer.
    fn clearSent(self: *Channel) void {
        if (self.out_sent < self.out_len) return;

        self.out_len = 0;
        self.out_sent = 0;
    }
};

// --------------------------------------------------------- //

pub const Transport = struct {
    pub const Options = struct {
        /// EPOLL or URING (ASYNC is rejected: that path is the Executor).
        model: DispatchModel = .EPOLL,
        /// Connections the transport owns and multiplexes.
        conns: usize,
        /// Requests one connection may owe before submit stops filling it.
        window: usize = DEFAULT_WINDOW,
        context: ?*anyopaque = null,
        on_reply: OnReply,
        /// Named prepared statements to create on every connection before the
        /// pipelined loop starts. Each entry is one pre-encoded Parse (named
        /// statement) plus Sync, so the caller then submits Bind and Execute
        /// against the name and the server never re-parses per request. Empty
        /// skips the warm-up.
        prepare: []const []const u8 = &.{},
    };

    allocator: std.mem.Allocator,
    model: DispatchModel,
    window: usize,
    context: ?*anyopaque,
    on_reply: OnReply,
    channels: []Channel,
    cursor: usize = 0,

    epoll_fd: Fd = -1,
    ring: ?linux.IoUring = null,
    send_armed: []bool = &.{},

    const Self = @This();

    /// Open K connections (blocking connect + handshake through the real
    /// Conn), switch each to non-blocking, and build the reactor.
    ///
    /// Note:
    /// - config drives the connection (host, auth, protocol). tls must be OFF.
    /// - Every leftover byte the handshake read ahead seeds the receive
    ///   buffer, so no reply prefix is lost.
    ///
    /// Return:
    /// - *Transport, deinit closes the connections and frees everything
    /// - error.PostgrezAsyncUsesExecutor when model is ASYNC
    /// - error.PostgrezTlsUnsupported when config.tls is not OFF
    /// - connect or allocation errors
    pub fn open(allocator: std.mem.Allocator, io: std.Io, config: lib.Config, options: Options) !*Self {
        if (options.model == .ASYNC) return error.PostgrezAsyncUsesExecutor;
        if (config.tls != .OFF) return error.PostgrezTlsUnsupported;
        if (options.conns == 0 or options.window == 0) return error.PostgrezBadOptions;

        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const channels = try allocator.alloc(Channel, options.conns);
        errdefer allocator.free(channels);

        var opened: usize = 0;
        errdefer closeChannels(allocator, channels[0..opened]);
        while (opened < options.conns) : (opened += 1) {
            channels[opened] = try openChannel(allocator, io, config, options.window);
        }

        // Warm-up runs on the still-blocking fds (simple send + recv), then
        // every fd switches to non-blocking for the reactor.
        if (options.prepare.len > 0) try prepareChannels(channels, options.prepare);

        for (channels) |*channel| setNonBlock(channel.fd);

        self.* = .{
            .allocator = allocator,
            .model = options.model,
            .window = options.window,
            .context = options.context,
            .on_reply = options.on_reply,
            .channels = channels,
        };

        try self.armReactor();

        return self;
    }

    /// Stop the reactor, close the connections, free everything. The caller
    /// must have drained the in-flight requests it cares about.
    pub fn deinit(self: *Self) void {
        if (self.ring) |*ring| ring.deinit();
        if (self.epoll_fd >= 0) _ = linux.close(self.epoll_fd);
        if (self.send_armed.len > 0) self.allocator.free(self.send_armed);

        closeChannels(self.allocator, self.channels);
        self.allocator.free(self.channels);
        self.allocator.destroy(self);
    }

    // --------------------------------------------------------- //

    /// Queue one pre-encoded request (a full Sync-terminated exchange) under
    /// a routing tag. The transport fills the least loaded connection.
    ///
    /// Return:
    /// - true when staged (its reply will reach on_reply in submit order)
    /// - false when every connection is at the window or lacks outbound room
    ///   (poll to make progress, then retry)
    pub fn submit(self: *Self, request: []const u8, tag: u64) bool {
        var scanned: usize = 0;
        while (scanned < self.channels.len) : (scanned += 1) {
            const channel = &self.channels[self.cursor];
            self.cursor = (self.cursor + 1) % self.channels.len;

            if (channel.accepts(self.window, request.len)) {
                channel.stage(request, tag);

                return true;
            }
        }

        return false;
    }

    /// Drive the reactor once: flush staged requests, read replies, and fire
    /// on_reply for every request completed this turn.
    ///
    /// Return:
    /// - usize count of replies delivered this call (0 when idle)
    /// - error.PostgrezConnectionClosed when a peer closed mid-flight
    pub fn poll(self: *Self) !usize {
        return switch (self.model) {
            .EPOLL => self.pollEpoll(),
            .URING => self.pollUring(),
            .ASYNC => unreachable,
        };
    }

    /// Requests owed across every connection (diagnostics).
    pub fn pending(self: *const Self) usize {
        var total: usize = 0;
        for (self.channels) |channel| total += channel.inflight;

        return total;
    }

    // --------------------------------------------------------- //

    fn armReactor(self: *Self) !void {
        switch (self.model) {
            .EPOLL => {
                const created = linux.epoll_create1(0);
                if (std.posix.errno(created) != .SUCCESS) return error.PostgrezEpollCreate;
                self.epoll_fd = @intCast(created);

                for (self.channels, 0..) |*channel, index| {
                    var event = linux.epoll_event{ .events = interest(channel), .data = .{ .ptr = index } };
                    _ = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_ADD, channel.fd, &event);
                }
            },
            .URING => {
                const entries: u16 = @intCast(std.math.ceilPowerOfTwo(usize, self.channels.len * 4) catch 4096);
                self.ring = try linux.IoUring.init(entries, 0);

                self.send_armed = try self.allocator.alloc(bool, self.channels.len);
                @memset(self.send_armed, false);

                for (self.channels, 0..) |*channel, index| {
                    _ = try self.ring.?.recv((index << 1) | OP_RECV, channel.fd, .{ .buffer = channel.in[channel.in_len..] }, 0);
                }
            },
            .ASYNC => unreachable,
        }
    }

    fn pollEpoll(self: *Self) !usize {
        var events: [256]linux.epoll_event = undefined;
        const count = linux.epoll_wait(self.epoll_fd, &events, events.len, WAIT_MS);

        var completed: usize = 0;
        for (events[0..count]) |event| {
            const index: usize = @intCast(event.data.ptr);
            const channel = &self.channels[index];

            if (event.events & linux.EPOLL.OUT != 0) {
                channel.out_sent += writeNb(channel.fd, channel.out[channel.out_sent..channel.out_len]);
                channel.clearSent();
            }

            if (event.events & linux.EPOLL.IN != 0) {
                const nread = readNb(channel.fd, channel.in[channel.in_len..]);
                if (nread == 0) return error.PostgrezConnectionClosed;

                channel.in_len += nread;
                completed += self.deliver(channel);
            }

            var next = linux.epoll_event{ .events = interest(channel), .data = .{ .ptr = index } };
            _ = linux.epoll_ctl(self.epoll_fd, linux.EPOLL.CTL_MOD, channel.fd, &next);
        }

        return completed;
    }

    fn pollUring(self: *Self) !usize {
        var ring = &self.ring.?;

        for (self.channels, 0..) |*channel, index| {
            if (!self.send_armed[index] and channel.out_sent < channel.out_len) {
                _ = ring.send((index << 1) | OP_SEND, channel.fd, channel.out[channel.out_sent..channel.out_len], 0) catch {};
                self.send_armed[index] = true;
            }
        }

        _ = try ring.submit_and_wait(1);

        var completed: usize = 0;
        while (ring.cq_ready() > 0) {
            const cqe = try ring.copy_cqe();
            const index: usize = @intCast(cqe.user_data >> 1);
            const op = cqe.user_data & 1;
            const channel = &self.channels[index];

            if (cqe.res <= 0) return error.PostgrezConnectionClosed;
            const done: usize = @intCast(cqe.res);

            if (op == OP_SEND) {
                channel.out_sent += done;
                self.send_armed[index] = false;
                channel.clearSent();
            } else {
                channel.in_len += done;
                completed += self.deliver(channel);
                _ = try ring.recv((index << 1) | OP_RECV, channel.fd, .{ .buffer = channel.in[channel.in_len..] }, 0);
            }
        }

        return completed;
    }

    /// Frame every whole reply now buffered, hand each to on_reply in submit
    /// order, and compact what stays.
    fn deliver(self: *Self, channel: *Channel) usize {
        var completed: usize = 0;

        while (channel.in_len > 0) {
            const len = replyLen(channel.in[0..channel.in_len]) orelse break;
            const reply = channel.in[0..len];
            const tag = channel.popTag();

            self.on_reply(self.context, tag, reply);
            channel.inflight -= 1;
            completed += 1;

            std.mem.copyForwards(u8, channel.in[0 .. channel.in_len - len], channel.in[len..channel.in_len]);
            channel.in_len -= len;
        }

        return completed;
    }
};

// --------------------------------------------------------- //

/// Reactor-less single-connection pipeline for a caller that owns its own
/// event loop (zix.Http1's .URING external watch): submit stages and flushes
/// non-blocking, pump reads and delivers framed replies, the caller watches
/// the fd for readability itself. options.model and options.conns are
/// ignored, a Line is always one connection.
pub const Line = struct {
    allocator: std.mem.Allocator,
    channel: Channel,
    window: usize,
    context: ?*anyopaque,
    on_reply: OnReply,

    /// Open one connection (blocking connect, handshake, and prepare
    /// warm-up), then switch it non-blocking for the caller's loop.
    ///
    /// Return:
    /// - *Line, deinit closes the connection and frees everything
    /// - error.PostgrezTlsUnsupported when config.tls is not OFF
    /// - connect or allocation errors
    pub fn open(allocator: std.mem.Allocator, io: std.Io, config: lib.Config, options: Transport.Options) !*Line {
        if (config.tls != .OFF) return error.PostgrezTlsUnsupported;
        if (options.window == 0) return error.PostgrezBadOptions;

        const self = try allocator.create(Line);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .channel = try openChannel(allocator, io, config, options.window),
            .window = options.window,
            .context = options.context,
            .on_reply = options.on_reply,
        };
        errdefer closeChannels(allocator, self.one());

        if (options.prepare.len > 0) try prepareChannels(self.one(), options.prepare);

        setNonBlock(self.channel.fd);

        return self;
    }

    pub fn deinit(self: *Line) void {
        closeChannels(self.allocator, self.one());
        self.allocator.destroy(self);
    }

    /// The connection fd, for the caller's readable watch.
    pub fn fd(self: *const Line) Fd {
        return self.channel.fd;
    }

    /// Queue one pre-encoded request under a routing tag. Staged only: the
    /// caller flushes once per batch (pump flushes too), so many requests
    /// leave in one write instead of one packet each.
    ///
    /// Return:
    /// - true when staged (its reply reaches on_reply in submit order)
    /// - false when the window or outbound buffer is full (pump, then retry)
    pub fn submit(self: *Line, request: []const u8, tag: u64) bool {
        if (!self.channel.accepts(self.window, request.len)) return false;

        self.channel.stage(request, tag);

        return true;
    }

    /// Push staged bytes at the socket, non-blocking, safe to call any time.
    pub fn flush(self: *Line) void {
        const channel = &self.channel;
        if (channel.out_sent >= channel.out_len) return;

        channel.out_sent += writeNb(channel.fd, channel.out[channel.out_sent..channel.out_len]);
        channel.clearSent();
    }

    /// Read whatever the socket holds and deliver every framed reply.
    ///
    /// Return:
    /// - usize count of replies delivered this call (0 when nothing whole)
    /// - error.PostgrezConnectionClosed when the peer closed the connection
    pub fn pump(self: *Line) !usize {
        const channel = &self.channel;

        var completed: usize = 0;
        while (channel.in_len < channel.in.len) {
            const rc = linux.read(channel.fd, channel.in.ptr + channel.in_len, channel.in.len - channel.in_len);
            switch (std.posix.errno(rc)) {
                .SUCCESS => {
                    if (rc == 0) return error.PostgrezConnectionClosed;

                    channel.in_len += rc;
                    completed += self.deliverLine();
                },
                .AGAIN => break,
                .INTR => {},
                else => return error.PostgrezConnectionClosed,
            }
        }

        self.flush();

        return completed;
    }

    /// Requests owed on the connection.
    pub fn pending(self: *const Line) usize {
        return self.channel.inflight;
    }

    fn one(self: *Line) []Channel {
        return @as(*[1]Channel, @ptrCast(&self.channel))[0..];
    }

    fn deliverLine(self: *Line) usize {
        const channel = &self.channel;

        var completed: usize = 0;
        while (channel.in_len > 0) {
            const len = replyLen(channel.in[0..channel.in_len]) orelse break;
            const tag = channel.popTag();

            self.on_reply(self.context, tag, channel.in[0..len]);
            channel.inflight -= 1;
            completed += 1;

            std.mem.copyForwards(u8, channel.in[0 .. channel.in_len - len], channel.in[len..channel.in_len]);
            channel.in_len -= len;
        }

        return completed;
    }
};

// --------------------------------------------------------- //

const OP_RECV: u64 = 0;
const OP_SEND: u64 = 1;

/// epoll_wait timeout: bounds a quiet poll so a caller loop can check its own
/// exit between turns.
const WAIT_MS: i32 = 100;

/// Interest for a channel: always readable, writable while output is owed.
fn interest(channel: *const Channel) u32 {
    var events: u32 = linux.EPOLL.IN;
    if (channel.out_sent < channel.out_len) events |= linux.EPOLL.OUT;

    return events;
}

fn openChannel(allocator: std.mem.Allocator, io: std.Io, config: lib.Config, window: usize) !Channel {
    const conn = try Conn.connect(allocator, io, config);
    errdefer conn.deinit();

    const fd = conn.stream.socket.handle;
    setNoDelay(fd);

    const out = try allocator.alloc(u8, OUT_BUF);
    errdefer allocator.free(out);
    const in = try allocator.alloc(u8, IN_BUF);
    errdefer allocator.free(in);
    const tags = try allocator.alloc(u64, window + 1);
    errdefer allocator.free(tags);

    // seed the receive buffer with whatever the handshake read past the last
    // startup message, so no reply prefix is dropped
    const leftover = conn.stream_reader.interface.buffered();
    var seeded: usize = 0;
    if (leftover.len > 0 and leftover.len <= in.len) {
        @memcpy(in[0..leftover.len], leftover);
        seeded = leftover.len;
    }

    return .{
        .conn = conn,
        .fd = fd,
        .out = out,
        .in = in,
        .in_len = seeded,
        .tags = tags,
    };
}

fn closeChannels(allocator: std.mem.Allocator, channels: []Channel) void {
    for (channels) |channel| {
        allocator.free(channel.tags);
        allocator.free(channel.in);
        allocator.free(channel.out);
        channel.conn.deinit();
    }
}

fn setNoDelay(fd: Fd) void {
    var one: i32 = 1;
    _ = linux.setsockopt(fd, linux.IPPROTO.TCP, linux.TCP.NODELAY, @ptrCast(&one), 4);
}

fn setNonBlock(fd: Fd) void {
    const flags = linux.fcntl(fd, std.posix.F.GETFL, 0);
    const nonblock: usize = @as(u32, @bitCast(std.posix.O{ .NONBLOCK = true }));
    _ = linux.fcntl(fd, std.posix.F.SETFL, flags | nonblock);
}

fn readNb(fd: Fd, buf: []u8) usize {
    const rc = linux.read(fd, buf.ptr, buf.len);

    return if (std.posix.errno(rc) == .SUCCESS) rc else 0;
}

fn writeNb(fd: Fd, buf: []const u8) usize {
    const rc = linux.write(fd, buf.ptr, buf.len);

    return if (std.posix.errno(rc) == .SUCCESS) rc else 0;
}

// --------------------------------------------------------- //

/// Send every prepared-statement request on each channel and wait for its
/// reply, on the still-blocking fd. Runs once before the reactor arms, so a
/// blocking send and recv is enough. A statement that fails to parse
/// (ErrorResponse) fails the open.
///
/// Param:
/// channels - []Channel (the freshly connected, still-blocking connections)
/// prepares - []const []const u8 (one pre-encoded Parse plus Sync each)
///
/// Return:
/// - void when every statement is prepared on every channel
/// - error.PostgrezPrepareFailed on a server ErrorResponse
/// - error.PostgrezPrepareOverflow when a reply exceeds the receive buffer
/// - connection errors
fn prepareChannels(channels: []Channel, prepares: []const []const u8) !void {
    for (channels) |*channel| {
        for (prepares) |request| try sendAllBlocking(channel.fd, request);

        var acked: usize = 0;
        while (acked < prepares.len) {
            if (scanReply(channel.in[0..channel.in_len])) |framed| {
                if (framed.is_error) return error.PostgrezPrepareFailed;

                std.mem.copyForwards(u8, channel.in[0 .. channel.in_len - framed.len], channel.in[framed.len..channel.in_len]);
                channel.in_len -= framed.len;
                acked += 1;

                continue;
            }

            if (channel.in_len == channel.in.len) return error.PostgrezPrepareOverflow;

            const nread = try recvBlocking(channel.fd, channel.in[channel.in_len..]);
            if (nread == 0) return error.PostgrezConnectionClosed;

            channel.in_len += nread;
        }
    }
}

/// One framed reply: its byte length and whether it carried an ErrorResponse.
const FramedReply = struct {
    len: usize,
    is_error: bool,
};

/// Frame one whole reply (up to and including ReadyForQuery) and note whether
/// any message in it is an ErrorResponse ('E').
///
/// Return:
/// - FramedReply when a whole reply is present
/// - null when more bytes are needed
fn scanReply(bytes: []const u8) ?FramedReply {
    const total = replyLen(bytes) orelse return null;

    var is_error = false;
    var pos: usize = 0;
    while (pos < total) {
        const length = std.mem.readInt(u32, bytes[pos + 1 ..][0..4], .big);
        if (bytes[pos] == 'E') is_error = true;

        pos += 1 + @as(usize, length);
    }

    return .{ .len = total, .is_error = is_error };
}

fn sendAllBlocking(fd: Fd, bytes: []const u8) !void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = linux.write(fd, bytes.ptr + sent, bytes.len - sent);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return error.PostgrezConnectionClosed;

                sent += rc;
            },
            .INTR => {},
            else => return error.WriteFailed,
        }
    }
}

fn recvBlocking(fd: Fd, buf: []u8) !usize {
    while (true) {
        const rc = linux.read(fd, buf.ptr, buf.len);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return rc,
            .INTR => {},
            else => return error.ReadFailed,
        }
    }
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "postgrez dispatch: replyLen frames up to ReadyForQuery" {
    // one CommandComplete ('C', payload 5) then ReadyForQuery ('Z', payload 5)
    const one_reply = [_]u8{
        'C', 0, 0, 0, 5, 0,
        'Z', 0, 0, 0, 5, 'I',
    };
    try testing.expectEqual(@as(?usize, one_reply.len), replyLen(&one_reply));

    // 'Z' alone is a full reply
    const bare_ready = [_]u8{ 'Z', 0, 0, 0, 5, 'I' };
    try testing.expectEqual(@as(?usize, 6), replyLen(&bare_ready));
}

test "postgrez dispatch: replyLen returns null on a partial reply" {
    // header promises a 5-byte payload but only 3 arrived
    const partial = [_]u8{ 'Z', 0, 0, 0, 5, 'I' };
    try testing.expectEqual(@as(?usize, null), replyLen(partial[0..4]));

    // a non-terminal message with no following 'Z' yet
    const no_ready = [_]u8{ 'C', 0, 0, 0, 5, 0 };
    try testing.expectEqual(@as(?usize, null), replyLen(&no_ready));
}

test "postgrez dispatch: replyLen frames two back-to-back replies" {
    const two = [_]u8{
        'Z', 0, 0, 0, 5, 'I',
        'Z', 0, 0, 0, 5, 'T',
    };
    const first = replyLen(&two).?;
    try testing.expectEqual(@as(usize, 6), first);
    try testing.expectEqual(@as(?usize, 6), replyLen(two[first..]));
}

test "postgrez dispatch: open rejects ASYNC" {
    // Transport.open unconditionally references armReactor's io_uring code
    // below this guard, so the whole function fails to compile outside
    // Linux regardless of which dispatch model is actually passed here.
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("Transport is Linux-only to compile, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    try testing.expectError(error.PostgrezAsyncUsesExecutor, Transport.open(testing.allocator, threaded.io(), .{
        .user = "tester",
    }, .{ .model = .ASYNC, .conns = 1, .on_reply = noopReply }));
}

test "postgrez dispatch: open rejects TLS" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    try testing.expectError(error.PostgrezTlsUnsupported, Transport.open(testing.allocator, threaded.io(), .{
        .user = "tester",
        .tls = .REQUIRE,
    }, .{ .model = .EPOLL, .conns = 1, .on_reply = noopReply }));
}

test "postgrez dispatch: open surfaces the connect error with no server" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    // port 1 on loopback: nothing listens, connect is refused fast
    try testing.expectError(error.ConnectionRefused, Transport.open(testing.allocator, threaded.io(), .{
        .user = "tester",
        .ip = "127.0.0.1",
        .port = 1,
    }, .{ .model = .EPOLL, .conns = 1, .on_reply = noopReply }));
}

fn noopReply(context: ?*anyopaque, tag: u64, reply: []const u8) void {
    _ = context;
    _ = tag;
    _ = reply;
}

test "postgrez dispatch: scanReply frames a reply and flags ErrorResponse" {
    // ParseComplete ('1', length 4) then ReadyForQuery ('Z')
    const ok = [_]u8{ '1', 0, 0, 0, 4, 'Z', 0, 0, 0, 5, 'I' };
    const ok_framed = scanReply(&ok).?;
    try testing.expectEqual(@as(usize, ok.len), ok_framed.len);
    try testing.expect(!ok_framed.is_error);

    // ErrorResponse ('E', length 6, two payload bytes) then ReadyForQuery
    const bad = [_]u8{ 'E', 0, 0, 0, 6, 0, 0, 'Z', 0, 0, 0, 5, 'E' };
    const bad_framed = scanReply(&bad).?;
    try testing.expectEqual(@as(usize, bad.len), bad_framed.len);
    try testing.expect(bad_framed.is_error);

    // partial: no ReadyForQuery yet
    const partial = [_]u8{ '1', 0, 0, 0, 4 };
    try testing.expectEqual(@as(?FramedReply, null), scanReply(&partial));
}

test "postgrez dispatch: Line stages, flushes, and delivers a framed reply" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    var out_buf: [256]u8 = undefined;
    var in_buf: [256]u8 = undefined;
    var tags: [8]u64 = undefined;

    const Capture = struct {
        var got_tag: u64 = 0;
        var got_len: usize = 0;
        fn onReply(context: ?*anyopaque, tag: u64, reply: []const u8) void {
            _ = context;
            got_tag = tag;
            got_len = reply.len;
        }
    };

    var line = Line{
        .allocator = testing.allocator,
        .channel = .{ .conn = undefined, .fd = fds[0], .out = &out_buf, .in = &in_buf, .tags = &tags },
        .window = 4,
        .context = null,
        .on_reply = Capture.onReply,
    };
    setNonBlock(fds[0]);

    try testing.expect(line.submit("QRY", 42));
    try testing.expectEqual(@as(usize, 1), line.pending());
    line.flush();

    var peer: [16]u8 = undefined;
    const got = try recvBlocking(fds[1], &peer);
    try testing.expectEqualStrings("QRY", peer[0..got]);

    const reply = [_]u8{ 'Z', 0, 0, 0, 5, 'I' };
    try sendAllBlocking(fds[1], &reply);

    try testing.expectEqual(@as(usize, 1), try line.pump());
    try testing.expectEqual(@as(u64, 42), Capture.got_tag);
    try testing.expectEqual(@as(usize, reply.len), Capture.got_len);
    try testing.expectEqual(@as(usize, 0), line.pending());
}

test "postgrez dispatch: Line pump surfaces a closed peer" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]i32 = undefined;
    try testing.expectEqual(@as(usize, 0), linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds));
    defer _ = linux.close(fds[0]);

    var out_buf: [64]u8 = undefined;
    var in_buf: [64]u8 = undefined;
    var tags: [4]u64 = undefined;

    var line = Line{
        .allocator = testing.allocator,
        .channel = .{ .conn = undefined, .fd = fds[0], .out = &out_buf, .in = &in_buf, .tags = &tags },
        .window = 2,
        .context = null,
        .on_reply = noopReply,
    };
    setNonBlock(fds[0]);

    try testing.expect(line.submit("Q", 1));
    _ = linux.close(fds[1]);

    try testing.expectError(error.PostgrezConnectionClosed, line.pump());
}
