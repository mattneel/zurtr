//! gzip and deflate codec over std.compress.flate.
//!
//! Note:
//! - The DEFLATE algorithm is RFC 1951. The gzip container is RFC 1952, the deflate
//!   (zlib) container is RFC 1950. std supplies all of them, so this file is a thin,
//!   dependency-free wrapper.
//! - The HTTP `deflate` content coding is zlib-WRAPPED DEFLATE (RFC 1950), NOT raw
//!   DEFLATE. So the deflate functions here use the zlib container, which is what the
//!   `deflate` token means on the wire. Raw DEFLATE (no header or footer) is a rarer,
//!   separate case and is not produced here.
//! - Transport-agnostic: it compresses and decompresses bytes and knows nothing about
//!   HTTP. The Accept-Encoding negotiation and the Content-Encoding / Vary headers
//!   live in the compression.zig facade and the per-engine write paths, not here.

const std = @import("std");

const flate = std.compress.flate;
const Container = flate.Container;

/// Compression effort. Maps to the std.compress.flate presets the codebase already
/// uses, so it stays valid across the supported Zig versions.
pub const Level = enum {
    /// Fastest, lowest ratio. For low-latency response paths.
    FASTEST,
    /// Balanced default. Matches the Http1 sendGzipFD path.
    DEFAULT,
};

/// Errors the gzip / deflate encoders can raise. Shares BufferTooSmall and OutOfMemory with
/// brotli.EncodeError, so a caller can switch codecs without changing its error handling.
pub const EncodeError = error{
    ZixCompressFailed,
    ZixBufferTooSmall,
    OutOfMemory,
};

/// Errors the gzip / deflate decoders surface, identical to brotli.DecodeError. An output that
/// overflows a caller buffer is BufferTooSmall. An over-cap alloc-variant output is OutputTooLarge.
pub const DecodeError = error{
    ZixDecompressFailed,
    ZixOutputTooLarge,
    ZixBufferTooSmall,
    OutOfMemory,
};

/// Upper bound on the compressed output size for a given input length. Safe for both
/// the gzip and zlib containers (gzip has the larger framing overhead).
///
/// Note:
/// - Weaker guarantee than brotli.compressBound. std has no store fallback, so the encoder may emit
///   fixed-Huffman blocks for incompressible data, where a literal costs up to 9 bits: the output
///   can exceed the input and the worst case is input * 9 / 8 (not the stored-block 5-bytes-per-block
///   bound). Add 5 bytes per 65535-byte block, the gzip header (10), and the trailer (8 = CRC32 +
///   ISIZE). The two bounds are not interchangeable.
///
/// Param:
/// input_len - usize (uncompressed byte count)
///
/// Return:
/// - usize (a length out_buf can safely be sized to)
pub fn compressBound(input_len: usize) usize {
    const blocks = input_len / 65535 + 1;

    return input_len + input_len / 8 + 5 * blocks + 18;
}

fn options(level: Level) flate.Compress.Options {
    return switch (level) {
        .FASTEST => flate.Compress.Options.level_1,
        .DEFAULT => flate.Compress.Options.default,
    };
}

/// Compress data into a caller-provided buffer using the given container.
///
/// Note:
/// - out_buf must be at least compressBound(data.len) to guarantee no overflow.
/// - allocator is used only for the transient history window and compressor state,
///   both freed before return, so the caller owns no codec memory.
///
/// Param:
/// allocator - std.mem.Allocator (transient codec scratch, freed before return)
/// data - []const u8 (bytes to compress)
/// out_buf - []u8 (destination, sized via compressBound)
/// level - Level (effort)
/// container - Container (.gzip or .zlib)
///
/// Return:
/// - usize (compressed byte count written into out_buf)
/// - error.ZixBufferTooSmall if out_buf cannot hold the result
/// - error.ZixCompressFailed if the codec fails
fn compressContainer(
    allocator: std.mem.Allocator,
    data: []const u8,
    out_buf: []u8,
    level: Level,
    container: Container,
) !usize {
    if (out_buf.len < compressBound(data.len)) return error.ZixBufferTooSmall;

    const work_buf = try allocator.alloc(u8, flate.max_window_len);
    defer allocator.free(work_buf);

    // flate.Compress is about 230 KB. Build it through a heap-allocated error-union
    // slot so its by-value init result is written there via sret, never onto the
    // caller stack. A handler runs on a small worker thread stack (about 512 KB), so
    // a 230 KB stack temporary here would overflow it. `if (slot.*) |*comp|` then
    // borrows the payload in place, with no 230 KB copy out.
    const slot = try allocator.create(std.Io.Writer.Error!flate.Compress);
    defer allocator.destroy(slot);

    var out_writer = std.Io.Writer.fixed(out_buf);
    slot.* = flate.Compress.init(&out_writer, work_buf, container, options(level));

    const comp: *flate.Compress = if (slot.*) |*payload| payload else |_| return error.ZixCompressFailed;
    comp.writer.writeAll(data) catch return error.ZixCompressFailed;
    comp.finish() catch return error.ZixCompressFailed;

    return out_writer.end;
}

fn compressContainerAlloc(allocator: std.mem.Allocator, data: []const u8, level: Level, container: Container) ![]u8 {
    const buf = try allocator.alloc(u8, compressBound(data.len));
    errdefer allocator.free(buf);

    const written = try compressContainer(allocator, data, buf, level, container);

    return allocator.realloc(buf, written);
}

/// Decompress a stream of the given container into a caller-provided buffer.
///
/// Note:
/// - No allocator: the inflate path streams without a history window here.
///
/// Param:
/// compressed - []const u8 (compressed bytes)
/// out_buf - []u8 (destination for the inflated bytes)
/// container - Container (.gzip or .zlib)
///
/// Return:
/// - usize (inflated byte count written into out_buf)
/// - error.ZixBufferTooSmall if out_buf cannot hold the inflated result
/// - error.ZixDecompressFailed if the stream is malformed
fn decompressContainer(compressed: []const u8, out_buf: []u8, container: Container) !usize {
    var in_reader = std.Io.Reader.fixed(compressed);
    var decomp = flate.Decompress.init(&in_reader, container, &.{});

    var out_writer = std.Io.Writer.fixed(out_buf);
    const n = decomp.reader.stream(&out_writer, .unlimited) catch |err| switch (err) {
        error.WriteFailed => return error.ZixBufferTooSmall,
        else => return error.ZixDecompressFailed,
    };

    return n;
}

fn decompressContainerAlloc(allocator: std.mem.Allocator, compressed: []const u8, max_out: usize, container: Container) ![]u8 {
    const buf = try allocator.alloc(u8, max_out);
    errdefer allocator.free(buf);

    var in_reader = std.Io.Reader.fixed(compressed);
    var decomp = flate.Decompress.init(&in_reader, container, &.{});

    var out_writer = std.Io.Writer.fixed(buf);
    const n = decomp.reader.stream(&out_writer, .unlimited) catch |err| switch (err) {
        error.WriteFailed => return error.ZixOutputTooLarge,
        else => return error.ZixDecompressFailed,
    };

    return allocator.realloc(buf, n);
}

// gzip (RFC 1952). The HTTP `gzip` content coding.

/// gzip compress into a caller buffer sized via compressBound. See compressContainer.
pub fn compressGzip(allocator: std.mem.Allocator, data: []const u8, out_buf: []u8, level: Level) EncodeError!usize {
    return compressContainer(allocator, data, out_buf, level, .gzip);
}

/// gzip compress into a freshly allocated buffer shrunk to the exact result size.
pub fn compressGzipAlloc(allocator: std.mem.Allocator, data: []const u8, level: Level) EncodeError![]u8 {
    return compressContainerAlloc(allocator, data, level, .gzip);
}

/// gzip decompress into a caller buffer. See decompressContainer.
pub fn decompressGzip(compressed: []const u8, out_buf: []u8) DecodeError!usize {
    return decompressContainer(compressed, out_buf, .gzip);
}

/// gzip decompress into a freshly allocated buffer, capped at max_out (bomb guard).
pub fn decompressGzipAlloc(allocator: std.mem.Allocator, compressed: []const u8, max_out: usize) DecodeError![]u8 {
    return decompressContainerAlloc(allocator, compressed, max_out, .gzip);
}

// deflate. The HTTP `deflate` content coding is zlib-wrapped DEFLATE (RFC 1950), so
// these use the zlib container, not raw DEFLATE.

/// deflate (zlib) compress into a caller buffer sized via compressBound.
pub fn compressDeflate(allocator: std.mem.Allocator, data: []const u8, out_buf: []u8, level: Level) EncodeError!usize {
    return compressContainer(allocator, data, out_buf, level, .zlib);
}

/// deflate (zlib) compress into a freshly allocated buffer shrunk to the exact size.
pub fn compressDeflateAlloc(allocator: std.mem.Allocator, data: []const u8, level: Level) EncodeError![]u8 {
    return compressContainerAlloc(allocator, data, level, .zlib);
}

/// deflate (zlib) decompress into a caller buffer.
pub fn decompressDeflate(compressed: []const u8, out_buf: []u8) DecodeError!usize {
    return decompressContainer(compressed, out_buf, .zlib);
}

/// deflate (zlib) decompress into a freshly allocated buffer, capped at max_out.
pub fn decompressDeflateAlloc(allocator: std.mem.Allocator, compressed: []const u8, max_out: usize) DecodeError![]u8 {
    return decompressContainerAlloc(allocator, compressed, max_out, .zlib);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "zix compression: flate gzip roundtrip ascii" {
    const original = "the quick brown fox jumps over the lazy dog";

    const packed_bytes = try compressGzipAlloc(testing.allocator, original, .DEFAULT);
    defer testing.allocator.free(packed_bytes);

    const restored = try decompressGzipAlloc(testing.allocator, packed_bytes, 1024);
    defer testing.allocator.free(restored);

    try testing.expectEqualStrings(original, restored);
}

test "zix compression: flate gzip roundtrip empty input" {
    const original = "";

    const packed_bytes = try compressGzipAlloc(testing.allocator, original, .DEFAULT);
    defer testing.allocator.free(packed_bytes);

    const restored = try decompressGzipAlloc(testing.allocator, packed_bytes, 64);
    defer testing.allocator.free(restored);

    try testing.expectEqual(@as(usize, 0), restored.len);
}

test "zix compression: flate gzip roundtrip every byte value (binary safe)" {
    var original: [256]u8 = undefined;
    for (&original, 0..) |*byte, index| byte.* = @intCast(index);

    const packed_bytes = try compressGzipAlloc(testing.allocator, &original, .DEFAULT);
    defer testing.allocator.free(packed_bytes);

    const restored = try decompressGzipAlloc(testing.allocator, packed_bytes, 512);
    defer testing.allocator.free(restored);

    try testing.expectEqualSlices(u8, &original, restored);
}

test "zix compression: flate gzip highly compressible shrinks" {
    var original: [4096]u8 = undefined;
    @memset(&original, 'A');

    const packed_bytes = try compressGzipAlloc(testing.allocator, &original, .DEFAULT);
    defer testing.allocator.free(packed_bytes);

    try testing.expect(packed_bytes.len < original.len);
}

test "zix compression: flate gzip output respects compressBound" {
    var original: [8192]u8 = undefined;
    var seed: u32 = 2654435761;
    for (&original) |*byte| {
        seed = seed *% 1664525 +% 1013904223;
        byte.* = @truncate(seed >> 16);
    }

    const packed_bytes = try compressGzipAlloc(testing.allocator, &original, .DEFAULT);
    defer testing.allocator.free(packed_bytes);

    try testing.expect(packed_bytes.len <= compressBound(original.len));
}

test "zix compression: flate gzip header magic and method" {
    var out_buf: [128]u8 = undefined;
    const written = try compressGzip(testing.allocator, "magic check", &out_buf, .DEFAULT);

    try testing.expect(written >= 3);
    try testing.expectEqual(@as(u8, 0x1f), out_buf[0]);
    try testing.expectEqual(@as(u8, 0x8b), out_buf[1]);
    try testing.expectEqual(@as(u8, 0x08), out_buf[2]);
}

test "zix compression: flate gzip both levels roundtrip" {
    var original: [512]u8 = undefined;
    for (&original, 0..) |*byte, index| byte.* = @intCast('a' + (index % 26));

    inline for (.{ Level.FASTEST, Level.DEFAULT }) |level| {
        const packed_bytes = try compressGzipAlloc(testing.allocator, &original, level);
        defer testing.allocator.free(packed_bytes);

        const restored = try decompressGzipAlloc(testing.allocator, packed_bytes, 4096);
        defer testing.allocator.free(restored);

        try testing.expectEqualSlices(u8, &original, restored);
    }
}

test "zix compression: flate gzip decode external gzip vector (CLI interop)" {
    // Produced by the gzip CLI: printf 'hello, gzip' | gzip -c
    // The header mtime is zeroed here, but decode ignores it regardless.
    const vector = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xcb\x48\xcd\xc9\xc9\xd7" ++
        "\x51\x48\xaf\xca\x2c\x00\x00\x4a\x9b\xb1\x5c\x0b\x00\x00\x00";

    var out_buf: [32]u8 = undefined;
    const n = try decompressGzip(vector, &out_buf);

    try testing.expectEqualStrings("hello, gzip", out_buf[0..n]);
}

test "zix compression: flate gzip decompress into too-small buffer errors" {
    var original: [256]u8 = undefined;
    @memset(&original, 'A');

    const packed_bytes = try compressGzipAlloc(testing.allocator, &original, .DEFAULT);
    defer testing.allocator.free(packed_bytes);

    var tiny: [8]u8 = undefined;

    try testing.expectError(error.ZixBufferTooSmall, decompressGzip(packed_bytes, &tiny));
}

test "zix compression: flate gzip decompress past the cap errors" {
    var original: [1024]u8 = undefined;
    @memset(&original, 'A');

    const packed_bytes = try compressGzipAlloc(testing.allocator, &original, .DEFAULT);
    defer testing.allocator.free(packed_bytes);

    try testing.expectError(error.ZixOutputTooLarge, decompressGzipAlloc(testing.allocator, packed_bytes, 16));
}

test "zix compression: flate gzip malformed stream errors" {
    const garbage = "\x1f\x8b\x08\x00 not really gzip past the header";

    var out_buf: [64]u8 = undefined;

    try testing.expectError(error.ZixDecompressFailed, decompressGzip(garbage, &out_buf));
}

test "zix compression: flate gzip compress into undersized buffer errors" {
    var original: [64]u8 = undefined;
    @memset(&original, 'A');

    var out_buf: [4]u8 = undefined;

    try testing.expectError(error.ZixBufferTooSmall, compressGzip(testing.allocator, &original, &out_buf, .DEFAULT));
}

test "zix compression: flate deflate roundtrip ascii" {
    const original = "the quick brown fox jumps over the lazy dog";

    const packed_bytes = try compressDeflateAlloc(testing.allocator, original, .DEFAULT);
    defer testing.allocator.free(packed_bytes);

    const restored = try decompressDeflateAlloc(testing.allocator, packed_bytes, 1024);
    defer testing.allocator.free(restored);

    try testing.expectEqualStrings(original, restored);
}

test "zix compression: flate deflate roundtrip every byte value (binary safe)" {
    var original: [256]u8 = undefined;
    for (&original, 0..) |*byte, index| byte.* = @intCast(index);

    const packed_bytes = try compressDeflateAlloc(testing.allocator, &original, .DEFAULT);
    defer testing.allocator.free(packed_bytes);

    const restored = try decompressDeflateAlloc(testing.allocator, packed_bytes, 512);
    defer testing.allocator.free(restored);

    try testing.expectEqualSlices(u8, &original, restored);
}

test "zix compression: flate deflate zlib container header (the deflate token is zlib-wrapped, not raw)" {
    var out_buf: [128]u8 = undefined;
    const written = try compressDeflate(testing.allocator, "zlib header check", &out_buf, .DEFAULT);

    // zlib (RFC 1950) starts with CMF=0x78 (deflate, 32K window). Raw DEFLATE would
    // not, so this guards against accidentally emitting raw under the deflate token.
    try testing.expect(written >= 2);
    try testing.expectEqual(@as(u8, 0x78), out_buf[0]);
    try testing.expect((@as(u16, out_buf[0]) * 256 + out_buf[1]) % 31 == 0);
}

test "zix compression: flate deflate decode external zlib vector (python zlib.compress interop)" {
    // Produced by python: zlib.compress(b'hello, deflate'), the RFC 1950 form an HTTP
    // client sends under Content-Encoding: deflate.
    const vector = "\x78\x9c\xcb\x48\xcd\xc9\xc9\xd7\x51\x48\x49\x4d\xcb\x49\x2c\x49\x05\x00\x26\xad\x05\x36";

    var out_buf: [32]u8 = undefined;
    const n = try decompressDeflate(vector, &out_buf);

    try testing.expectEqualStrings("hello, deflate", out_buf[0..n]);
}

test "zix compression: flate deflate gzip and deflate produce distinct headers" {
    var gzip_buf: [128]u8 = undefined;
    var deflate_buf: [128]u8 = undefined;

    const gzip_n = try compressGzip(testing.allocator, "same input, two containers", &gzip_buf, .DEFAULT);
    const deflate_n = try compressDeflate(testing.allocator, "same input, two containers", &deflate_buf, .DEFAULT);

    // gzip magic 0x1f 0x8b vs zlib 0x78, so the first byte alone distinguishes them.
    try testing.expect(gzip_n >= 1 and deflate_n >= 1);
    try testing.expectEqual(@as(u8, 0x1f), gzip_buf[0]);
    try testing.expectEqual(@as(u8, 0x78), deflate_buf[0]);
}

test "zix compression: flate deflate a gzip stream does not decode as deflate" {
    const packed_gzip = try compressGzipAlloc(testing.allocator, "container mismatch", .DEFAULT);
    defer testing.allocator.free(packed_gzip);

    var out_buf: [64]u8 = undefined;

    try testing.expectError(error.ZixDecompressFailed, decompressDeflate(packed_gzip, &out_buf));
}
