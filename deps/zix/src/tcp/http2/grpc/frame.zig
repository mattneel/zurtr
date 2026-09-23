//! gRPC 5-byte message prefix codec, gRPC frame send functions, and gzip codec.

const std = @import("std");
const socket_pair = @import("../../../utils/socket_pair.zig");
const fd_io = @import("../../../utils/fd_io.zig");
const h2 = @import("../Http2.zig");

// --------------------------------------------------------- //

/// gRPC length-prefix header size: 1 compress flag + 4 message length bytes.
pub const grpc_prefix_len: usize = 5;

/// HTTP/2 frame header length in octets (re-exported from the h2 frame module).
const FRAME_HEADER_LEN = h2.FRAME_HEADER_LEN;

/// HPACK scratch for the comptime cached :status response HEADERS block.
const status_block_scratch: usize = 128;

/// Full HEADERS or trailer frame send buffer: the HPACK block plus the frame header.
pub const headers_frame_scratch: usize = 600;

/// Output headroom over the input length when gzip-compressing a gRPC message:
/// covers the gzip header, trailer, and the length-prefix so the result never overflows.
pub const gzip_framing_headroom: usize = 128;

/// gRPC 5-byte length-prefix header.
pub const GrpcPrefix = struct {
    compress: bool,
    msg_len: u32,
};

/// Parse the 5-byte gRPC prefix from the start of body.
pub fn readGrpcPrefix(body: []const u8) error{ZixTooShort}!GrpcPrefix {
    if (body.len < grpc_prefix_len) return error.ZixTooShort;
    const msg_len = std.mem.readInt(u32, body[1..grpc_prefix_len], .big);
    return .{ .compress = body[0] != 0, .msg_len = msg_len };
}

/// Write a 5-byte gRPC prefix into buf.
pub fn writeGrpcPrefix(buf: *[grpc_prefix_len]u8, compress: bool, msg_len: u32) void {
    buf[0] = if (compress) 1 else 0;
    std.mem.writeInt(u32, buf[1..grpc_prefix_len], msg_len, .big);
}

// --------------------------------------------------------- //

/// The default gRPC content-type. Its response HEADERS block is the same on every call, so it
/// is HPACK-encoded once at comptime and memcpy'd on the hot path instead of re-encoded.
pub const GRPC_CONTENT_TYPE = "application/grpc+proto";

/// Comptime HPACK block for the initial response HEADERS (:status 200, content-type proto).
const HEADERS_PROTO_BLOCK = blk: {
    var buf: [status_block_scratch]u8 = undefined;
    var enc = h2.HpackEncoder.init(&buf);
    enc.writeHeader(":status", "200") catch unreachable;
    enc.writeHeader("content-type", GRPC_CONTENT_TYPE) catch unreachable;
    const encoded = enc.encoded();

    var out: [encoded.len]u8 = undefined;
    @memcpy(&out, encoded);
    break :blk out;
};

/// Comptime HPACK block for the OK trailer (grpc-status: 0, no message), the common close.
const TRAILER_OK_BLOCK = blk: {
    var buf: [64]u8 = undefined;
    var enc = h2.HpackEncoder.init(&buf);
    enc.writeHeader("grpc-status", "0") catch unreachable;
    const encoded = enc.encoded();

    var out: [encoded.len]u8 = undefined;
    @memcpy(&out, encoded);
    break :blk out;
};

/// Stamp a HEADERS frame header (with stream_id and flags) plus a precomputed HPACK block into
/// out. Return: bytes written.
fn emitCachedHeaders(out: []u8, stream_id: u31, flags: u8, block: []const u8) usize {
    var fh: [FRAME_HEADER_LEN]u8 = undefined;
    h2.encodeFrameHeader(&fh, .{
        .length = @intCast(block.len),
        .frame_type = h2.FRAME_TYPE_HEADERS,
        .flags = flags,
        .stream_id = stream_id,
    });
    @memcpy(out[0..FRAME_HEADER_LEN], &fh);
    @memcpy(out[FRAME_HEADER_LEN..][0..block.len], block);
    return FRAME_HEADER_LEN + block.len;
}

/// Encode initial response HEADERS (:status 200, content-type) into out. No END_STREAM.
/// The default gRPC content-type takes a precomputed block (no HPACK encode on the hot path).
/// Return:
/// - bytes written into out.
pub fn buildGrpcHeaders(out: []u8, stream_id: u31, content_type: []const u8) usize {
    if (std.mem.eql(u8, content_type, GRPC_CONTENT_TYPE)) {
        return emitCachedHeaders(out, stream_id, h2.FLAG_END_HEADERS, &HEADERS_PROTO_BLOCK);
    }

    var hdr_buf: [h2.HPACK_ENCODE_SCRATCH]u8 = undefined;
    var hpack_enc = h2.HpackEncoder.init(&hdr_buf);
    hpack_enc.writeHeader(":status", "200") catch return 0;
    hpack_enc.writeHeader("content-type", content_type) catch return 0;
    const hblock = hpack_enc.encoded();

    var fh: [FRAME_HEADER_LEN]u8 = undefined;
    h2.encodeFrameHeader(&fh, .{
        .length = @intCast(hblock.len),
        .frame_type = h2.FRAME_TYPE_HEADERS,
        .flags = h2.FLAG_END_HEADERS,
        .stream_id = stream_id,
    });
    @memcpy(out[0..FRAME_HEADER_LEN], &fh);
    @memcpy(out[FRAME_HEADER_LEN..][0..hblock.len], hblock);
    return FRAME_HEADER_LEN + hblock.len;
}

/// Encode the 9-byte DATA frame header plus the 5-byte gRPC prefix into out (14 bytes).
/// The caller appends the message payload after these 14 bytes.
///
/// Param:
/// compress - bool (true sets compress flag 1 in the gRPC prefix)
///
/// Return:
/// - bytes written into out (always 14).
pub fn buildGrpcDataHeader(out: []u8, stream_id: u31, msg_len: usize, compress: bool) usize {
    var fh: [FRAME_HEADER_LEN]u8 = undefined;
    h2.encodeFrameHeader(&fh, .{
        .length = @intCast(5 + msg_len),
        .frame_type = h2.FRAME_TYPE_DATA,
        .flags = 0,
        .stream_id = stream_id,
    });
    @memcpy(out[0..FRAME_HEADER_LEN], &fh);
    writeGrpcPrefix(out[FRAME_HEADER_LEN .. FRAME_HEADER_LEN + grpc_prefix_len], compress, @intCast(msg_len));
    return 14;
}

/// Encode initial response HEADERS (:status 200, content-type, grpc-encoding: gzip) into out.
/// No END_STREAM. Use when the server will send gzip-compressed DATA frames.
///
/// Return:
/// - bytes written into out.
pub fn buildGrpcHeadersGzip(out: []u8, stream_id: u31, content_type: []const u8) usize {
    var hdr_buf: [h2.HPACK_ENCODE_SCRATCH]u8 = undefined;
    var hpack_enc = h2.HpackEncoder.init(&hdr_buf);
    hpack_enc.writeHeader(":status", "200") catch return 0;
    hpack_enc.writeHeader("content-type", content_type) catch return 0;
    hpack_enc.writeHeader("grpc-encoding", "gzip") catch return 0;
    const hblock = hpack_enc.encoded();

    var fh: [FRAME_HEADER_LEN]u8 = undefined;
    h2.encodeFrameHeader(&fh, .{
        .length = @intCast(hblock.len),
        .frame_type = h2.FRAME_TYPE_HEADERS,
        .flags = h2.FLAG_END_HEADERS,
        .stream_id = stream_id,
    });
    @memcpy(out[0..FRAME_HEADER_LEN], &fh);
    @memcpy(out[FRAME_HEADER_LEN..][0..hblock.len], hblock);
    return FRAME_HEADER_LEN + hblock.len;
}

// --------------------------------------------------------- //

/// Decompress a gzip-encoded gRPC body in-place.
/// Walks all 5+N messages, decompresses each message with compress flag 1.
/// Messages with compress flag 0 are copied as-is.
/// All output messages have compress=0 in their 5-byte prefix.
///
/// Return:
/// - byte count written into out_buf
/// - error.ZixTruncatedBody if the body is malformed
/// - error.ZixDecompressFailed if gzip decompression fails
/// - error.ZixBufferTooSmall if out_buf cannot hold the decompressed result
pub fn decompressGrpcBody(body: []const u8, out_buf: []u8) !usize {
    const flate = std.compress.flate;

    var in_pos: usize = 0;
    var out_pos: usize = 0;

    while (in_pos + grpc_prefix_len <= body.len) {
        const compress_flag = body[in_pos] != 0;
        const msg_len = std.mem.readInt(u32, body[in_pos + 1 ..][0..4], .big);
        const total = grpc_prefix_len + @as(usize, msg_len);

        if (in_pos + total > body.len) return error.ZixTruncatedBody;

        if (compress_flag) {
            if (out_pos + grpc_prefix_len > out_buf.len) return error.ZixBufferTooSmall;

            const compressed = body[in_pos + grpc_prefix_len ..][0..msg_len];
            var in_reader = std.Io.Reader.fixed(compressed);
            var decomp = flate.Decompress.init(&in_reader, .gzip, &.{});
            var out_writer = std.Io.Writer.fixed(out_buf[out_pos + grpc_prefix_len ..]);
            const decomp_len = decomp.reader.stream(&out_writer, .unlimited) catch return error.ZixDecompressFailed;

            out_buf[out_pos] = 0;
            std.mem.writeInt(u32, out_buf[out_pos + 1 ..][0..4], @intCast(decomp_len), .big);
            out_pos += grpc_prefix_len + decomp_len;
        } else {
            if (out_pos + total > out_buf.len) return error.ZixBufferTooSmall;
            @memcpy(out_buf[out_pos..][0..total], body[in_pos..][0..total]);
            out_pos += total;
        }

        in_pos += total;
    }

    return out_pos;
}

/// Compress data using gzip and write the result into out_buf.
/// out_buf must be at least data.len + 128 bytes to guarantee no overflow.
/// Uses level_1 (fastest) compression for low-latency response paths.
///
/// Return:
/// - compressed byte count
/// - error.ZixCompressFailed if gzip compression fails or out_buf is too small
pub fn compressGrpcMessage(data: []const u8, out_buf: []u8) !usize {
    const flate = std.compress.flate;

    const work_buf = try std.heap.smp_allocator.alloc(u8, flate.max_window_len);
    defer std.heap.smp_allocator.free(work_buf);

    const comp = try std.heap.smp_allocator.create(flate.Compress);
    defer std.heap.smp_allocator.destroy(comp);

    var out_writer = std.Io.Writer.fixed(out_buf);
    comp.* = flate.Compress.init(&out_writer, work_buf, .gzip, flate.Compress.Options.level_1) catch return error.ZixCompressFailed;
    comp.writer.writeAll(data) catch return error.ZixCompressFailed;
    comp.finish() catch return error.ZixCompressFailed;

    return out_writer.end;
}

/// Encode trailer HEADERS (grpc-status, grpc-message) into out. FLAG_END_STREAM.
/// Return:
/// - bytes written into out.
pub fn buildGrpcTrailer(out: []u8, stream_id: u31, grpc_status: u8, grpc_message: []const u8) usize {
    if (grpc_status == 0 and grpc_message.len == 0) {
        return emitCachedHeaders(out, stream_id, h2.FLAG_END_HEADERS | h2.FLAG_END_STREAM, &TRAILER_OK_BLOCK);
    }

    var hdr_buf: [h2.HPACK_ENCODE_SCRATCH]u8 = undefined;
    var hpack_enc = h2.HpackEncoder.init(&hdr_buf);
    var status_str: [4]u8 = undefined;
    const status_s = std.fmt.bufPrint(&status_str, "{d}", .{grpc_status}) catch "0";
    hpack_enc.writeHeader("grpc-status", status_s) catch return 0;
    if (grpc_message.len > 0) hpack_enc.writeHeader("grpc-message", grpc_message) catch return 0;
    const hblock = hpack_enc.encoded();

    var fh: [FRAME_HEADER_LEN]u8 = undefined;
    h2.encodeFrameHeader(&fh, .{
        .length = @intCast(hblock.len),
        .frame_type = h2.FRAME_TYPE_HEADERS,
        .flags = h2.FLAG_END_HEADERS | h2.FLAG_END_STREAM,
        .stream_id = stream_id,
    });
    @memcpy(out[0..FRAME_HEADER_LEN], &fh);
    @memcpy(out[FRAME_HEADER_LEN..][0..hblock.len], hblock);
    return FRAME_HEADER_LEN + hblock.len;
}

/// Encode a trailers-only error response (no DATA frame) into out.
/// Includes :status 200 and content-type per gRPC spec.
/// Return:
/// - bytes written into out.
pub fn buildGrpcError(out: []u8, stream_id: u31, grpc_status: u8, grpc_message: []const u8) usize {
    var hdr_buf: [h2.HPACK_ENCODE_SCRATCH]u8 = undefined;
    var hpack_enc = h2.HpackEncoder.init(&hdr_buf);
    hpack_enc.writeHeader(":status", "200") catch return 0;
    hpack_enc.writeHeader("content-type", "application/grpc+proto") catch return 0;
    var status_str: [4]u8 = undefined;
    const status_s = std.fmt.bufPrint(&status_str, "{d}", .{grpc_status}) catch "0";
    hpack_enc.writeHeader("grpc-status", status_s) catch return 0;
    if (grpc_message.len > 0) hpack_enc.writeHeader("grpc-message", grpc_message) catch return 0;
    const hblock = hpack_enc.encoded();

    var fh: [FRAME_HEADER_LEN]u8 = undefined;
    h2.encodeFrameHeader(&fh, .{
        .length = @intCast(hblock.len),
        .frame_type = h2.FRAME_TYPE_HEADERS,
        .flags = h2.FLAG_END_HEADERS | h2.FLAG_END_STREAM,
        .stream_id = stream_id,
    });
    @memcpy(out[0..FRAME_HEADER_LEN], &fh);
    @memcpy(out[FRAME_HEADER_LEN..][0..hblock.len], hblock);
    return FRAME_HEADER_LEN + hblock.len;
}

/// Send initial response HEADERS (:status 200, content-type). No END_STREAM.
pub fn sendGrpcHeadersFD(fd: std.posix.fd_t, stream_id: u31, content_type: []const u8) !void {
    var buf: [headers_frame_scratch]u8 = undefined;
    const n = buildGrpcHeaders(&buf, stream_id, content_type);
    try h2.writeAllFD(fd, buf[0..n]);
}

/// Send one DATA frame with 5-byte gRPC prefix. No END_STREAM.
pub fn sendGrpcDataFD(fd: std.posix.fd_t, stream_id: u31, message: []const u8) !void {
    var head: [14]u8 = undefined;
    _ = buildGrpcDataHeader(&head, stream_id, message.len, false);

    try h2.writeAllFD(fd, &head);
    try h2.writeAllFD(fd, message);
}

/// Send trailer HEADERS (grpc-status, grpc-message). FLAG_END_STREAM.
pub fn sendGrpcTrailerFD(fd: std.posix.fd_t, stream_id: u31, grpc_status: u8, grpc_message: []const u8) !void {
    var buf: [headers_frame_scratch]u8 = undefined;
    const n = buildGrpcTrailer(&buf, stream_id, grpc_status, grpc_message);
    try h2.writeAllFD(fd, buf[0..n]);
}

/// Send trailers-only error response (no DATA frame). Includes :status 200 and content-type per gRPC spec.
pub fn sendGrpcErrorFD(fd: std.posix.fd_t, stream_id: u31, grpc_status: u8, grpc_message: []const u8) !void {
    var buf: [headers_frame_scratch]u8 = undefined;
    const n = buildGrpcError(&buf, stream_id, grpc_status, grpc_message);
    try h2.writeAllFD(fd, buf[0..n]);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix grpc: cached buildGrpcHeaders proto decodes to status 200 + content-type" {
    var buf: [128]u8 = undefined;
    const n = buildGrpcHeaders(&buf, 1, GRPC_CONTENT_TYPE);
    const fh = h2.parseFrameHeader(buf[0..9]);
    try std.testing.expectEqual(h2.FRAME_TYPE_HEADERS, fh.frame_type);
    try std.testing.expectEqual(h2.FLAG_END_HEADERS, fh.flags);

    var decoder = h2.HpackDecoder.init();
    var headers: [8]h2.Header = undefined;
    var scratch: [256]u8 = undefined;
    const count = try decoder.decode(buf[9..n], &headers, &scratch);

    var saw_status = false;
    var saw_ct = false;
    for (headers[0..count]) |h| {
        if (std.mem.eql(u8, h.name, ":status") and std.mem.eql(u8, h.value, "200")) saw_status = true;
        if (std.mem.eql(u8, h.name, "content-type") and std.mem.eql(u8, h.value, GRPC_CONTENT_TYPE)) saw_ct = true;
    }
    try std.testing.expect(saw_status and saw_ct);
}

test "zix grpc: cached buildGrpcTrailer OK decodes to grpc-status 0 with END_STREAM" {
    var buf: [64]u8 = undefined;
    const n = buildGrpcTrailer(&buf, 3, 0, "");
    const fh = h2.parseFrameHeader(buf[0..9]);
    try std.testing.expectEqual(h2.FRAME_TYPE_HEADERS, fh.frame_type);
    try std.testing.expectEqual(h2.FLAG_END_HEADERS | h2.FLAG_END_STREAM, fh.flags);

    var decoder = h2.HpackDecoder.init();
    var headers: [8]h2.Header = undefined;
    var scratch: [256]u8 = undefined;
    const count = try decoder.decode(buf[9..n], &headers, &scratch);

    var saw_status = false;
    for (headers[0..count]) |h| {
        if (std.mem.eql(u8, h.name, "grpc-status") and std.mem.eql(u8, h.value, "0")) saw_status = true;
    }
    try std.testing.expect(saw_status);
}

test "zix grpc: buildGrpcHeadersGzip includes grpc-encoding header" {
    var buf: [256]u8 = undefined;
    const n = buildGrpcHeadersGzip(&buf, 1, GRPC_CONTENT_TYPE);
    const fh = h2.parseFrameHeader(buf[0..9]);
    try std.testing.expectEqual(h2.FRAME_TYPE_HEADERS, fh.frame_type);
    try std.testing.expectEqual(h2.FLAG_END_HEADERS, fh.flags);

    var decoder = h2.HpackDecoder.init();
    var headers: [8]h2.Header = undefined;
    var scratch: [256]u8 = undefined;
    const count = try decoder.decode(buf[9..n], &headers, &scratch);

    var saw_encoding = false;
    for (headers[0..count]) |h| {
        if (std.mem.eql(u8, h.name, "grpc-encoding") and std.mem.eql(u8, h.value, "gzip")) saw_encoding = true;
    }
    try std.testing.expect(saw_encoding);
}

test "zix grpc: buildGrpcDataHeader compress flag false" {
    var buf: [14]u8 = undefined;
    _ = buildGrpcDataHeader(&buf, 1, 10, false);
    try std.testing.expectEqual(@as(u8, 0), buf[9]);
}

test "zix grpc: buildGrpcDataHeader compress flag true" {
    var buf: [14]u8 = undefined;
    _ = buildGrpcDataHeader(&buf, 1, 10, true);
    try std.testing.expectEqual(@as(u8, 1), buf[9]);
}

test "zix grpc: compressGrpcMessage and decompressGrpcBody roundtrip" {
    const original = "hello grpc compression";

    var comp_buf: [256]u8 = undefined;
    const comp_len = try compressGrpcMessage(original, &comp_buf);
    try std.testing.expect(comp_len > 0);
    try std.testing.expect(comp_len < comp_buf.len);

    var body: [256]u8 = undefined;
    body[0] = 1;
    std.mem.writeInt(u32, body[1..5], @intCast(comp_len), .big);
    @memcpy(body[5..][0..comp_len], comp_buf[0..comp_len]);

    var out_buf: [256]u8 = undefined;
    const out_len = try decompressGrpcBody(body[0 .. 5 + comp_len], &out_buf);

    try std.testing.expect(out_len == 5 + original.len);
    try std.testing.expectEqual(@as(u8, 0), out_buf[0]);
    const msg_len = std.mem.readInt(u32, out_buf[1..5], .big);
    try std.testing.expectEqual(@as(u32, original.len), msg_len);
    try std.testing.expectEqualStrings(original, out_buf[5..][0..original.len]);
}

test "zix grpc: decompressGrpcBody passes through uncompressed messages" {
    var body: [12]u8 = undefined;
    writeGrpcPrefix(body[0..5], false, 7);
    @memcpy(body[5..], "abcdefg");

    var out_buf: [32]u8 = undefined;
    const n = try decompressGrpcBody(&body, &out_buf);
    try std.testing.expectEqual(@as(usize, 12), n);
    try std.testing.expectEqualSlices(u8, &body, out_buf[0..n]);
}

test "zix grpc: decompressGrpcBody truncated body returns error" {
    var body: [5]u8 = undefined;
    writeGrpcPrefix(&body, false, 100);
    var out_buf: [256]u8 = undefined;
    try std.testing.expectError(error.ZixTruncatedBody, decompressGrpcBody(&body, &out_buf));
}

test "zix grpc: readGrpcPrefix too short" {
    const body = [_]u8{ 0, 0, 0 };
    try std.testing.expectError(error.ZixTooShort, readGrpcPrefix(&body));
}

test "zix grpc: readGrpcPrefix and writeGrpcPrefix roundtrip" {
    var body: [5]u8 = undefined;
    writeGrpcPrefix(&body, false, 42);
    const p = try readGrpcPrefix(&body);
    try std.testing.expect(!p.compress);
    try std.testing.expectEqual(@as(u32, 42), p.msg_len);
}

test "zix grpc: writeGrpcPrefix compress flag set" {
    var body: [5]u8 = undefined;
    writeGrpcPrefix(&body, true, 0);
    try std.testing.expectEqual(@as(u8, 1), body[0]);
}

test "zix grpc: readGrpcPrefix exactly 5 bytes is valid" {
    var body: [5]u8 = undefined;
    writeGrpcPrefix(&body, false, 0);
    const p = try readGrpcPrefix(&body);
    try std.testing.expectEqual(@as(u32, 0), p.msg_len);
}

test "zix grpc: sendGrpcErrorFD includes content-type header" {
    var pair = try socket_pair.Pair.open(std.testing.allocator);
    defer pair.deinit();
    const pipe_fds = pair.fds;

    try sendGrpcErrorFD(pipe_fds[1], 1, 3, "");

    var buf: [256]u8 = undefined;
    const n = try fd_io.readOnce(pipe_fds[0], &buf);
    const hpack_block = buf[9..n];

    var decoder = h2.HpackDecoder.init();
    var headers: [8]h2.Header = undefined;
    var scratch: [256]u8 = undefined;
    const header_count = try decoder.decode(hpack_block, &headers, &scratch);

    var found = false;
    for (headers[0..header_count]) |header| {
        if (std.mem.eql(u8, header.name, "content-type") and
            std.mem.eql(u8, header.value, "application/grpc+proto"))
        {
            found = true;
            break;
        }
    }

    try std.testing.expect(found);
}
