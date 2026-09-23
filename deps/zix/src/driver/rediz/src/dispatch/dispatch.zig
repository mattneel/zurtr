//! Dispatch model: how the driver multiplexes socket I/O across connections.
//!
//! Note:
//! - ASYNC is the existing Pool of blocking connections, one round trip in
//!   flight per held connection. It is the default and is untouched by this
//!   module.
//! - EPOLL and URING are one single thread that owns K non-blocking
//!   connections and pipelines many commands per connection, so the wire
//!   stays full without a thread per in-flight command. Transport here is
//!   that single-thread multiplexed path.
//! - Transport reuses the real Conn for connect and the RESP handshake, then
//!   runs the pipelined loop on the raw connection fd. Command bytes and
//!   reply parsing stay the caller's job (resp.encodeCommand to build a
//!   command, resp.decode to read a reply), so the wire protocol is shared
//!   with the blocking path, only the socket pump changes.
//! - Cleartext only: the raw-fd loop cannot drive a TLS session, so open()
//!   rejects a config with tls set. The blocking Conn/Pool path keeps TLS.

const std = @import("std");
const linux = std.os.linux;
const lib = @import("../lib.zig");
const conn_mod = @import("../conn.zig");

const Conn = conn_mod.Conn;
const Fd = std.posix.fd_t;

/// Default per-connection pipeline depth: commands a connection may owe
/// before submit stops filling it.
pub const DEFAULT_WINDOW: usize = 64;

/// Per-connection outbound staging: holds queued command bytes until the
/// socket accepts them.
const OUT_BUF: usize = 32 * 1024;
/// Per-connection inbound staging: holds reply bytes until whole replies frame.
const IN_BUF: usize = 64 * 1024;

/// Deepest RESP aggregate the framer walks, guards the recursion.
const MAX_DEPTH: usize = 32;

/// Which transport pumps the socket, re-exported from the config home in
/// lib.zig: ASYNC selects the blocking Pool path, EPOLL and URING select the
/// multiplexed Transport.
pub const DispatchModel = lib.DispatchModel;

/// Reply sink: called once per completed command, in submit order per
/// connection. reply borrows the connection receive buffer and is valid only
/// for the duration of the call (copy what must outlive it).
///
/// Param:
/// context - ?*anyopaque (the caller pointer passed in Options)
/// tag - u64 (the routing tag submitted with the command)
/// reply - []const u8 (one raw RESP reply)
pub const OnReply = *const fn (context: ?*anyopaque, tag: u64, reply: []const u8) void;

// --------------------------------------------------------- //

/// Byte length of one complete RESP reply at the front of bytes.
///
/// Return:
/// - usize length when a whole reply is present
/// - null when more bytes are needed (or a marker is unknown, which stalls
///   framing so the caller notices the malformed stream)
fn replyLen(bytes: []const u8) ?usize {
    return frameLen(bytes, 0);
}

fn frameLen(bytes: []const u8, depth: usize) ?usize {
    if (depth >= MAX_DEPTH) return null;
    if (bytes.len == 0) return null;

    const eol = std.mem.indexOf(u8, bytes, "\r\n") orelse return null;
    const marker = bytes[0];
    const head = bytes[1..eol];

    switch (marker) {
        '+', '-', ':', '#', ',', '(', '_' => return eol + 2,
        '$', '!', '=' => {
            const declared = std.fmt.parseInt(i64, head, 10) catch return null;
            if (declared < 0) return eol + 2;

            const total = eol + 2 + @as(usize, @intCast(declared)) + 2;
            if (bytes.len < total) return null;

            return total;
        },
        '*', '~', '>', '%' => {
            const declared = std.fmt.parseInt(i64, head, 10) catch return null;
            if (declared < 0) return eol + 2;

            var elements: usize = @intCast(declared);
            if (marker == '%') elements *= 2;

            var pos = eol + 2;
            var remaining = elements;
            while (remaining > 0) : (remaining -= 1) {
                const child = frameLen(bytes[pos..], depth + 1) orelse return null;
                pos += child;
            }

            return pos;
        },
        else => return null,
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

    /// Room for another command: under the window and with outbound space for
    /// a command of command_len bytes.
    fn accepts(self: *const Channel, window: usize, command_len: usize) bool {
        if (self.inflight >= window) return false;

        return self.out_len + command_len <= self.out.len;
    }

    /// Stage one command: append its bytes and remember its tag in submit
    /// order. accepts() must have returned true.
    fn stage(self: *Channel, command: []const u8, tag: u64) void {
        @memcpy(self.out[self.out_len..][0..command.len], command);
        self.out_len += command.len;

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
        /// EPOLL or URING (ASYNC is rejected: that path is the Pool).
        model: DispatchModel = .EPOLL,
        /// Connections the transport owns and multiplexes.
        conns: usize,
        /// Commands one connection may owe before submit stops filling it.
        window: usize = DEFAULT_WINDOW,
        context: ?*anyopaque = null,
        on_reply: OnReply,
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
    /// - error.RedizAsyncUsesPool when model is ASYNC
    /// - error.RedizTlsUnsupported when config.tls is not OFF
    /// - connect or allocation errors
    pub fn open(allocator: std.mem.Allocator, io: std.Io, config: lib.Config, options: Options) !*Self {
        if (options.model == .ASYNC) return error.RedizAsyncUsesPool;
        if (config.tls != .OFF) return error.RedizTlsUnsupported;
        if (options.conns == 0 or options.window == 0) return error.RedizBadOptions;

        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const channels = try allocator.alloc(Channel, options.conns);
        errdefer allocator.free(channels);

        var opened: usize = 0;
        errdefer closeChannels(allocator, channels[0..opened]);
        while (opened < options.conns) : (opened += 1) {
            channels[opened] = try openChannel(allocator, io, config, options.window);
        }

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
    /// must have drained the in-flight commands it cares about.
    pub fn deinit(self: *Self) void {
        if (self.ring) |*ring| ring.deinit();
        if (self.epoll_fd >= 0) _ = linux.close(self.epoll_fd);
        if (self.send_armed.len > 0) self.allocator.free(self.send_armed);

        closeChannels(self.allocator, self.channels);
        self.allocator.free(self.channels);
        self.allocator.destroy(self);
    }

    // --------------------------------------------------------- //

    /// Queue one pre-encoded command under a routing tag. The transport fills
    /// the least loaded connection.
    ///
    /// Return:
    /// - true when staged (its reply will reach on_reply in submit order)
    /// - false when every connection is at the window or lacks outbound room
    ///   (poll to make progress, then retry)
    pub fn submit(self: *Self, command: []const u8, tag: u64) bool {
        var scanned: usize = 0;
        while (scanned < self.channels.len) : (scanned += 1) {
            const channel = &self.channels[self.cursor];
            self.cursor = (self.cursor + 1) % self.channels.len;

            if (channel.accepts(self.window, command.len)) {
                channel.stage(command, tag);

                return true;
            }
        }

        return false;
    }

    /// Drive the reactor once: flush staged commands, read replies, and fire
    /// on_reply for every command completed this turn.
    ///
    /// Return:
    /// - usize count of replies delivered this call (0 when idle)
    /// - error.RedizConnectionClosed when a peer closed mid-flight
    pub fn poll(self: *Self) !usize {
        return switch (self.model) {
            .EPOLL => self.pollEpoll(),
            .URING => self.pollUring(),
            .ASYNC => unreachable,
        };
    }

    /// Commands owed across every connection (diagnostics).
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
                if (std.posix.errno(created) != .SUCCESS) return error.RedizEpollCreate;
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
                if (nread == 0) return error.RedizConnectionClosed;

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

            if (cqe.res <= 0) return error.RedizConnectionClosed;
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
    setNonBlock(fd);

    const out = try allocator.alloc(u8, OUT_BUF);
    errdefer allocator.free(out);
    const in = try allocator.alloc(u8, IN_BUF);
    errdefer allocator.free(in);
    const tags = try allocator.alloc(u64, window + 1);
    errdefer allocator.free(tags);

    // seed the receive buffer with whatever the handshake read past the last
    // handshake reply, so no reply prefix is dropped
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
// --------------------------------------------------------- //

const testing = std.testing;

test "rediz dispatch: replyLen frames the simple reply kinds" {
    try testing.expectEqual(@as(?usize, 5), replyLen("+OK\r\n"));
    try testing.expectEqual(@as(?usize, 4), replyLen(":1\r\n"));
    try testing.expectEqual(@as(?usize, 22), replyLen("-ERR unknown command\r\n"));

    // bulk string: header, body, trailing CRLF
    try testing.expectEqual(@as(?usize, 11), replyLen("$5\r\nhello\r\n"));

    // null bulk has no body
    try testing.expectEqual(@as(?usize, 5), replyLen("$-1\r\n"));
}

test "rediz dispatch: replyLen frames a nested array in one reply" {
    const nested = "*3\r\n$1\r\na\r\n:2\r\n*1\r\n+deep\r\n";
    try testing.expectEqual(@as(?usize, nested.len), replyLen(nested));
}

test "rediz dispatch: replyLen returns null on a partial reply" {
    // bulk header promises 5 bytes, only 3 present
    try testing.expectEqual(@as(?usize, null), replyLen("$5\r\nhel"));

    // array announces two elements, only one framed
    try testing.expectEqual(@as(?usize, null), replyLen("*2\r\n+one\r\n"));

    // no CRLF yet
    try testing.expectEqual(@as(?usize, null), replyLen("+OK"));
}

test "rediz dispatch: replyLen frames two back-to-back replies" {
    const two = "+OK\r\n:7\r\n";
    const first = replyLen(two).?;
    try testing.expectEqual(@as(usize, 5), first);
    try testing.expectEqual(@as(?usize, 4), replyLen(two[first..]));
}

test "rediz dispatch: open rejects ASYNC" {
    // Transport.open unconditionally references armReactor's io_uring code
    // below this guard, so the whole function fails to compile outside
    // Linux regardless of which dispatch model is actually passed here.
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("Transport is Linux-only to compile, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    try testing.expectError(error.RedizAsyncUsesPool, Transport.open(testing.allocator, threaded.io(), .{}, .{
        .model = .ASYNC,
        .conns = 1,
        .on_reply = noopReply,
    }));
}

test "rediz dispatch: open rejects TLS" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    try testing.expectError(error.RedizTlsUnsupported, Transport.open(testing.allocator, threaded.io(), .{
        .tls = .REQUIRE,
    }, .{ .model = .EPOLL, .conns = 1, .on_reply = noopReply }));
}

test "rediz dispatch: open surfaces the connect error with no server" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();

    // port 1 on loopback: nothing listens, connect is refused fast
    try testing.expectError(error.ConnectionRefused, Transport.open(testing.allocator, threaded.io(), .{
        .ip = "127.0.0.1",
        .port = 1,
    }, .{ .model = .EPOLL, .conns = 1, .on_reply = noopReply }));
}

fn noopReply(context: ?*anyopaque, tag: u64, reply: []const u8) void {
    _ = context;
    _ = tag;
    _ = reply;
}
