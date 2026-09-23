//! gRPC h2c client: unary and streaming calls.

const std = @import("std");
const h2 = @import("../Http2.zig");
const frm = @import("frame.zig");
const status_mod = @import("status.zig");
const GrpcClientConfig = @import("config.zig").GrpcClientConfig;
const win_io = @import("../../../utils/windows_io.zig");

pub const GrpcStatus = status_mod.GrpcStatus;

// --------------------------------------------------------- //

fn applySocketTimeout(sock_fd: std.posix.fd_t, recv_ms: u32, send_ms: u32) void {
    // setsockopt timeouts are POSIX-only: on Windows recvResponse gates the
    // blocking frame read with a poll instead.
    if (comptime @import("builtin").target.os.tag == .windows) return;

    if (recv_ms == 0 and send_ms == 0) return;

    if (recv_ms > 0) {
        const recv_tv = std.posix.timeval{ .sec = @intCast(recv_ms / 1000), .usec = @intCast((recv_ms % 1000) * 1000) };
        std.posix.setsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&recv_tv)) catch {};
    }

    if (send_ms > 0) {
        const send_tv = std.posix.timeval{ .sec = @intCast(send_ms / 1000), .usec = @intCast((send_ms % 1000) * 1000) };
        std.posix.setsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&send_tv)) catch {};
    }
}

// --------------------------------------------------------- //

/// Response event returned by recvResponse().
pub const GrpcClientResponse = union(enum) {
    data: []const u8,
    status: GrpcStatus,
};

// --------------------------------------------------------- //

/// Scratch buffer for HPACK-decoding a response header block.
const HDEC_SCRATCH_SIZE: usize = 4096;
/// DATA-frame payload staging buffer: one 64 KiB body plus a small margin for the
/// gRPC length-prefix and framing overhead.
const PAYLOAD_SCRATCH_SIZE: usize = 64 * 1024 + 256;

/// gRPC h2c client. One TCP connection, sequential calls.
///
/// Usage:
/// ```zig
/// var client = try GrpcClient.connect(.{ .ip = "127.0.0.1", .port = 8083 }, io);
/// defer client.deinit();
/// const data = try client.unary("/pkg.Svc/Method", "application/grpc+proto", req, &buf);
/// ```
pub const GrpcClient = struct {
    const Self = @This();

    fd: std.posix.fd_t,
    next_sid: u31,
    /// Receive timeout carried for the Windows poll gate in recvResponse.
    /// POSIX targets enforce it through SO_RCVTIMEO on the socket instead.
    recv_timeout_ms: u32,
    hdec: h2.HpackDecoder,
    hdec_scratch: [HDEC_SCRATCH_SIZE]u8,
    resp_hdrs: [h2.MAX_HEADERS]h2.Header,
    resp_hdr_count: usize,
    payload_scratch: [PAYLOAD_SCRATCH_SIZE]u8,

    /// Unconsumed tail of the current DATA frame's payload (points into `payload_scratch`). A server may
    /// pack several length-prefixed gRPC messages into one DATA frame, so `recvResponse` drains them one
    /// per call from here before reading the next frame.
    data_rest: []const u8,
    /// Whether the DATA frame backing `data_rest` carried END_STREAM (report OK once its messages drain).
    data_end_stream: bool,

    // --------------------------------------------------------- //

    /// Connect to a gRPC h2c server and perform the HTTP/2 preface exchange.
    ///
    /// Return:
    /// - !Self
    /// - error.ZixPortNotConfigured if config.port is 0
    pub fn connect(config: GrpcClientConfig, io: std.Io) !Self {
        if (config.port == 0) return error.ZixPortNotConfigured;

        const addr = try std.Io.net.IpAddress.resolve(io, config.ip, config.port);
        const stream = try addr.connect(io, .{ .mode = .stream, .protocol = .tcp });
        const fd = stream.socket.handle;

        if (comptime @import("builtin").target.os.tag != .windows) {
            // std.posix.TCP is void on the BSDs in Zig 0.16: TCP_NODELAY is 1 there.
            const nodelay: u32 = if (comptime std.posix.TCP != void) std.posix.TCP.NODELAY else 1;

            std.posix.setsockopt(
                fd,
                std.posix.IPPROTO.TCP,
                nodelay,
                std.mem.asBytes(&@as(c_int, 1)),
            ) catch {};
        }

        applySocketTimeout(fd, config.recv_timeout_ms, config.send_timeout_ms);

        try h2.writeAllFD(fd, h2.PREFACE);
        try h2.sendSettingsFD(fd, &.{
            .{ h2.SETTINGS_INITIAL_WINDOW_SIZE, h2.DEFAULT_WINDOW_SIZE },
            .{ h2.SETTINGS_MAX_FRAME_SIZE, h2.DEFAULT_MAX_FRAME_SIZE },
        });

        return .{
            .fd = fd,
            .next_sid = 1,
            .recv_timeout_ms = config.recv_timeout_ms,
            .hdec = h2.HpackDecoder.init(),
            .hdec_scratch = undefined,
            .resp_hdrs = undefined,
            .resp_hdr_count = 0,
            .payload_scratch = undefined,
            .data_rest = &.{},
            .data_end_stream = false,
        };
    }

    /// Close the underlying TCP connection.
    pub fn deinit(self: *Self) void {
        if (comptime @import("builtin").target.os.tag == .windows) {
            @import("../../../utils/windows_io.zig").close(self.fd);
            return;
        }

        _ = std.posix.system.close(self.fd);
    }

    // --------------------------------------------------------- //

    /// Open a new h2 stream and send the initial gRPC request headers.
    /// Advertises grpc-accept-encoding: gzip so the server may compress responses.
    ///
    /// Return:
    /// - !u31 (stream ID for subsequent sendMessage / recvResponse calls)
    pub fn openStream(self: *Self, path: []const u8, content_type: []const u8) !u31 {
        const sid = self.next_sid;
        self.next_sid += 2;

        var hbuf: [h2.HPACK_ENCODE_SCRATCH]u8 = undefined;
        var enc = h2.HpackEncoder.init(&hbuf);
        try enc.writeHeader(":method", "POST");
        try enc.writeHeader(":path", path);
        try enc.writeHeader(":scheme", "http");
        try enc.writeHeader(":authority", "grpc");
        try enc.writeHeader("content-type", content_type);
        try enc.writeHeader("te", "trailers");
        try enc.writeHeader("grpc-accept-encoding", "identity,gzip");
        const hblock = enc.encoded();

        try h2.writeFrameHeaderFD(self.fd, .{
            .length = @intCast(hblock.len),
            .frame_type = h2.FRAME_TYPE_HEADERS,
            .flags = h2.FLAG_END_HEADERS,
            .stream_id = sid,
        });
        try h2.writeAllFD(self.fd, hblock);
        return sid;
    }

    /// Send one gRPC message on a stream. Does not set END_STREAM.
    pub fn sendMessage(self: *Self, sid: u31, data: []const u8) !void {
        var prefix: [5]u8 = undefined;
        frm.writeGrpcPrefix(&prefix, false, @intCast(data.len));
        try h2.writeFrameHeaderFD(self.fd, .{
            .length = @intCast(5 + data.len),
            .frame_type = h2.FRAME_TYPE_DATA,
            .flags = 0,
            .stream_id = sid,
        });
        try h2.writeAllFD(self.fd, &prefix);
        try h2.writeAllFD(self.fd, data);
    }

    /// Half-close the stream from the client side (empty DATA with END_STREAM).
    pub fn endStream(self: *Self, sid: u31) !void {
        try h2.writeFrameHeaderFD(self.fd, .{
            .length = 0,
            .frame_type = h2.FRAME_TYPE_DATA,
            .flags = h2.FLAG_END_STREAM,
            .stream_id = sid,
        });
    }

    // --------------------------------------------------------- //

    /// Receive the next event on the specified stream.
    /// Handles SETTINGS, WINDOW_UPDATE, and PING frames transparently. A DATA frame may pack several
    /// length-prefixed gRPC messages (a server-streaming server coalesces them), so each call returns the
    /// next message, draining a frame's leftover before reading a new one.
    ///
    /// Return:
    /// - !GrpcClientResponse (.data for each gRPC response message, .status for the trailer)
    /// - error.ZixRecvTimeout when recv_timeout_ms is set and no frame arrives in
    ///   time on Windows (POSIX targets time out through SO_RCVTIMEO instead)
    pub fn recvResponse(self: *Self, sid: u31, buf: []u8) !GrpcClientResponse {
        while (true) {
            // Drain the next message still packed in the last DATA frame before reading a new one. A
            // server may coalesce several length-prefixed gRPC messages into one DATA frame, so one frame
            // can yield several recvResponse results.
            if (self.data_rest.len >= frm.grpc_prefix_len) {
                const compress_flag = self.data_rest[0] != 0;
                const msg_len = std.mem.readInt(u32, self.data_rest[1..frm.grpc_prefix_len], .big);
                const msg_end = frm.grpc_prefix_len + @as(usize, msg_len);
                if (msg_end > self.data_rest.len) return error.ZixTruncatedMessage;

                const msg = self.data_rest[frm.grpc_prefix_len..msg_end];
                self.data_rest = self.data_rest[msg_end..];

                const data_len = try decodeMessage(compress_flag, msg, buf);

                return .{ .data = buf[0..data_len] };
            }

            // The buffered frame is drained. If it carried END_STREAM, that is the OK result.
            if (self.data_end_stream) {
                self.data_end_stream = false;
                self.data_rest = &.{};

                return .{ .status = GrpcStatus.OK };
            }
            self.data_rest = &.{};

            if (comptime @import("builtin").target.os.tag == .windows) {
                // SO_RCVTIMEO does not apply to the ntdll read path, so gate
                // the blocking frame read with a poll on Windows.
                if (self.recv_timeout_ms > 0) {
                    if (!try win_io.pollReady(self.fd, win_io.POLLIN, self.recv_timeout_ms)) {
                        return error.ZixRecvTimeout;
                    }
                }
            }

            const fh = try h2.readFrameHeader(self.fd);
            if (fh.length > self.payload_scratch.len) return error.ZixFrameTooLarge;
            const payload = self.payload_scratch[0..fh.length];
            if (fh.length > 0) try h2.recvExact(self.fd, payload);

            switch (fh.frame_type) {
                h2.FRAME_TYPE_SETTINGS => {
                    if ((fh.flags & h2.FLAG_ACK) == 0) try h2.sendSettingsAckFD(self.fd);
                },
                h2.FRAME_TYPE_WINDOW_UPDATE => {},
                h2.FRAME_TYPE_PING => {
                    if ((fh.flags & h2.FLAG_ACK) == 0) {
                        var ping_payload: [8]u8 = undefined;
                        @memcpy(&ping_payload, payload[0..8]);

                        try h2.sendPingAckFD(self.fd, ping_payload);
                    }
                },
                h2.FRAME_TYPE_HEADERS => {
                    if (fh.stream_id != sid) continue;
                    self.resp_hdr_count = try self.hdec.decode(
                        payload,
                        &self.resp_hdrs,
                        &self.hdec_scratch,
                    );
                    for (self.resp_hdrs[0..self.resp_hdr_count]) |hdr| {
                        if (std.mem.eql(u8, hdr.name, "grpc-status")) {
                            const code = std.fmt.parseInt(u8, hdr.value, 10) catch 2;
                            return .{ .status = @enumFromInt(code) };
                        }
                    }
                    if ((fh.flags & h2.FLAG_END_STREAM) != 0)
                        return .{ .status = GrpcStatus.OK };
                },
                h2.FRAME_TYPE_DATA => {
                    if (fh.stream_id != sid) continue;

                    // Buffer the whole payload, the loop top drains its messages one per call.
                    self.data_rest = payload;
                    self.data_end_stream = (fh.flags & h2.FLAG_END_STREAM) != 0;
                },
                h2.FRAME_TYPE_GOAWAY => return error.ZixServerGoaway,
                h2.FRAME_TYPE_RST_STREAM => return error.ZixStreamReset,
                else => {},
            }
        }
    }

    /// Decode one gRPC message body (optionally gzip-compressed) into `buf`, returning the byte length.
    fn decodeMessage(compress_flag: bool, msg: []const u8, buf: []u8) !usize {
        if (compress_flag) {
            var in_reader = std.Io.Reader.fixed(msg);
            var decomp = std.compress.flate.Decompress.init(&in_reader, .gzip, &.{});
            var out_writer = std.Io.Writer.fixed(buf);

            return decomp.reader.stream(&out_writer, .unlimited) catch return error.ZixDecompressFailed;
        }

        const data_len = @min(msg.len, buf.len);
        @memcpy(buf[0..data_len], msg[0..data_len]);

        return data_len;
    }

    // --------------------------------------------------------- //

    /// Unary call: send one message, receive one response.
    ///
    /// Return:
    /// - ![]const u8 (slice into buf containing the response message payload)
    pub fn unary(
        self: *Self,
        path: []const u8,
        content_type: []const u8,
        req_data: []const u8,
        buf: []u8,
    ) ![]const u8 {
        const sid = try self.openStream(path, content_type);
        try self.sendMessage(sid, req_data);
        try self.endStream(sid);

        var got_data: ?[]const u8 = null;
        while (true) {
            const resp = try self.recvResponse(sid, buf);
            switch (resp) {
                .data => |d| got_data = d,
                .status => |st| {
                    if (@intFromEnum(st) != 0) return error.ZixGrpcError;
                    return got_data orelse &.{};
                },
            }
        }
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix grpc: GrpcClient.connect port zero returns PortNotConfigured" {
    const gpa = std.testing.allocator;
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    try std.testing.expectError(
        error.ZixPortNotConfigured,
        GrpcClient.connect(.{ .ip = "127.0.0.1", .port = 0 }, io),
    );
}

test "zix grpc: applySocketTimeout, zero ms is a no-op on real socket" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    const sock_fd: std.posix.fd_t = @intCast(linux.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0));
    try std.testing.expect(sock_fd > 0);
    defer _ = linux.close(sock_fd);

    applySocketTimeout(sock_fd, 0, 0);

    var recv_tv: std.posix.timeval = undefined;
    var opt_len: std.posix.socklen_t = @sizeOf(std.posix.timeval);
    _ = linux.getsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, @ptrCast(&recv_tv), &opt_len);
    try std.testing.expectEqual(@as(isize, 0), recv_tv.sec);
    try std.testing.expectEqual(@as(i64, 0), recv_tv.usec);
}

test "zix grpc: applySocketTimeout, sets SO_RCVTIMEO on real socket" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    const linux = std.os.linux;
    const sock_fd: std.posix.fd_t = @intCast(linux.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0));
    try std.testing.expect(sock_fd > 0);
    defer _ = linux.close(sock_fd);

    applySocketTimeout(sock_fd, 2500, 0);

    var recv_tv: std.posix.timeval = undefined;
    var opt_len: std.posix.socklen_t = @sizeOf(std.posix.timeval);
    _ = linux.getsockopt(sock_fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, @ptrCast(&recv_tv), &opt_len);
    try std.testing.expectEqual(@as(isize, 2), recv_tv.sec);
    try std.testing.expectEqual(@as(i64, 500_000), recv_tv.usec);
}

test "zix grpc: applySocketTimeout, short timeout does not fire when data arrives immediately" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer {
        _ = std.os.linux.close(fds[0]);
        _ = std.os.linux.close(fds[1]);
    }

    applySocketTimeout(fds[0], 50, 0);

    const written: usize = @intCast(std.os.linux.write(fds[1], "data".ptr, 4));
    try std.testing.expectEqual(@as(usize, 4), written);

    var buf: [8]u8 = undefined;
    const n: usize = @intCast(std.os.linux.read(fds[0], &buf, buf.len));
    try std.testing.expect(n > 0);
    try std.testing.expectEqualSlices(u8, "data", buf[0..n]);
}

test "zix grpc: recvResponse drains multiple messages coalesced in one DATA frame" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    var fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(usize, 0), std.os.linux.socketpair(std.os.linux.AF.UNIX, std.os.linux.SOCK.STREAM, 0, &fds));
    defer {
        _ = std.os.linux.close(fds[0]);
        _ = std.os.linux.close(fds[1]);
    }

    // One DATA frame (END_STREAM) carrying two length-prefixed messages, the shape a server-streaming
    // server produces when it coalesces messages into a single frame.
    var payload: [2 * (frm.grpc_prefix_len + 3)]u8 = undefined;
    frm.writeGrpcPrefix(payload[0..frm.grpc_prefix_len], false, 3);
    @memcpy(payload[frm.grpc_prefix_len..][0..3], "aaa");
    frm.writeGrpcPrefix(payload[frm.grpc_prefix_len + 3 ..][0..frm.grpc_prefix_len], false, 3);
    @memcpy(payload[2 * frm.grpc_prefix_len + 3 ..][0..3], "bbb");

    try h2.writeFrameHeaderFD(fds[1], .{
        .length = @intCast(payload.len),
        .frame_type = h2.FRAME_TYPE_DATA,
        .flags = h2.FLAG_END_STREAM,
        .stream_id = 1,
    });
    try h2.writeAllFD(fds[1], &payload);

    var client = GrpcClient{
        .fd = fds[0],
        .next_sid = 3,
        .recv_timeout_ms = 0,
        .hdec = h2.HpackDecoder.init(),
        .hdec_scratch = undefined,
        .resp_hdrs = undefined,
        .resp_hdr_count = 0,
        .payload_scratch = undefined,
        .data_rest = &.{},
        .data_end_stream = false,
    };

    var buf: [32]u8 = undefined;

    // First call reads the frame and returns the first message, the second drains the leftover, the
    // third reports OK from the buffered END_STREAM without reading another frame.
    const r1 = try client.recvResponse(1, &buf);
    try std.testing.expect(r1 == .data);
    try std.testing.expectEqualSlices(u8, "aaa", r1.data);

    const r2 = try client.recvResponse(1, &buf);
    try std.testing.expect(r2 == .data);
    try std.testing.expectEqualSlices(u8, "bbb", r2.data);

    const r3 = try client.recvResponse(1, &buf);
    try std.testing.expect(r3 == .status);
    try std.testing.expectEqual(GrpcStatus.OK, r3.status);
}
