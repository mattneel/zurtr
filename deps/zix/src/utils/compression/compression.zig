//! Response compression facade.
//!
//! Note:
//! - This is the policy layer over the codecs: it decides WHICH content coding to use
//!   (Accept-Encoding negotiation, RFC 9110 section 12.5.3), WHETHER a body is worth
//!   compressing (size floor plus already-compressed media types), and dispatches to
//!   the matching codec. The codecs themselves (flate.zig, brotli.zig) are
//!   transport-agnostic and know nothing about HTTP.
//! - gRPC does NOT use this facade. It runs its own grpc-encoding per-message
//!   negotiation, a different protocol layer, and only reuses the flate codec.
//! - The producible set is brotli, gzip, deflate, plus identity. Each has its own codec
//!   (brotli.zig, flate.zig). The negotiation here picks one against the client's
//!   Accept-Encoding and the rest of the policy (size floor, already-compressed types).

const std = @import("std");

pub const flate = @import("flate.zig");
pub const flate_fast = @import("flate_fast.zig");
pub const brotli = @import("brotli.zig");

/// Compression effort, forwarded to the codec.
pub const Level = flate.Level;

/// Default size floor: bodies smaller than this are not worth compressing, the header
/// and CPU cost outweighs the saving. Tunable per deployment via the engine config.
pub const min_size_default: usize = 256;

/// The codings this engine can actually produce, in server-preference order. identity
/// is always an implicit fallback and is not listed here. gzip leads (broad support,
/// and the in-tree brotli encoder is not yet competitive with gzip on small bodies),
/// then deflate, then brotli. So brotli is served when the client prefers it (a higher
/// q, or br as the only offered coding), while gzip stays the default at equal q.
pub const supported_default = [_]Encoding{ .GZIP, .DEFLATE, .BR };

/// An HTTP content coding.
pub const Encoding = enum {
    IDENTITY,
    GZIP,
    DEFLATE,
    BR,

    /// The Accept-Encoding / Content-Encoding token for this coding.
    ///
    /// Return:
    /// - []const u8
    pub fn token(self: Encoding) []const u8 {
        return switch (self) {
            .IDENTITY => "identity",
            .GZIP => "gzip",
            .DEFLATE => "deflate",
            .BR => "br",
        };
    }

    /// The Content-Encoding header value to emit, or null for identity (no header).
    ///
    /// Return:
    /// - []const u8 for a real coding
    /// - null for identity, where no Content-Encoding header is sent
    pub fn contentEncoding(self: Encoding) ?[]const u8 {
        return if (self == .IDENTITY) null else self.token();
    }
};

/// Pick the content coding to use for a response, honouring the client Accept-Encoding
/// preferences against the server-producible set.
///
/// Note:
/// - Policy is compression-leaning (the common server behaviour): the
///   best producible coding is chosen whenever it is acceptable (q greater than 0).
///   identity only wins when the client lists it EXPLICITLY with a strictly higher q.
///   An unlisted or wildcard-matched identity does not suppress compression.
/// - Among producible codings, the highest client q wins. At equal q, the earlier entry
///   in supported wins (server preference order).
/// - An absent header defaults to identity (conservative, only compress when the client
///   asks). An empty field value means the client wants identity only (RFC 9110).
///
/// Param:
/// accept_encoding - ?[]const u8 (the raw Accept-Encoding field value, or null if absent)
/// supported - []const Encoding (producible codings in server-preference order)
///
/// Return:
/// - Encoding (the chosen coding, possibly identity)
/// - null when nothing is acceptable (identity is forbidden via q=0 and no producible
///   coding is acceptable), which the caller answers with 406 Not Acceptable
pub fn negotiate(accept_encoding: ?[]const u8, supported: []const Encoding) ?Encoding {
    const header = accept_encoding orelse return .IDENTITY;

    const trimmed = std.mem.trim(u8, header, " \t");
    if (trimmed.len == 0) return .IDENTITY;

    const identity = scan(trimmed, "identity");
    const identity_available = identity.explicit orelse identity.wildcard orelse 1000;

    var best_encoding: ?Encoding = null;
    var best_quality: u16 = 0;
    for (supported) |encoding| {
        const match = scan(trimmed, encoding.token());
        const quality = match.explicit orelse match.wildcard orelse 0;

        if (quality > best_quality) {
            best_quality = quality;
            best_encoding = encoding;
        }
    }

    if (best_encoding) |encoding| {
        if (best_quality > 0) {
            if (identity.explicit) |identity_quality| {
                if (identity_quality > best_quality) return .IDENTITY;
            }

            return encoding;
        }
    }

    if (identity_available > 0) return .IDENTITY;

    return null;
}

/// The qualities a coding token carries in the header: its explicit entry and the
/// wildcard entry, each in milli units (0 to 1000), or null when not present.
const Scan = struct {
    explicit: ?u16 = null,
    wildcard: ?u16 = null,
};

/// Scan the header for a coding token, capturing both an explicit entry and a wildcard.
///
/// Param:
/// header - []const u8 (trimmed Accept-Encoding value)
/// token - []const u8 (coding name to score, matched case-insensitively)
///
/// Return:
/// - Scan (explicit and wildcard qualities, each null when absent)
fn scan(header: []const u8, token: []const u8) Scan {
    var result: Scan = .{};

    var entry_iter = std.mem.splitScalar(u8, header, ',');
    while (entry_iter.next()) |raw_entry| {
        const entry = std.mem.trim(u8, raw_entry, " \t");
        if (entry.len == 0) continue;

        var field_iter = std.mem.splitScalar(u8, entry, ';');
        const name = std.mem.trim(u8, field_iter.next().?, " \t");

        var quality: u16 = 1000;
        while (field_iter.next()) |raw_param| {
            const param = std.mem.trim(u8, raw_param, " \t");

            if (param.len >= 2 and (param[0] == 'q' or param[0] == 'Q') and param[1] == '=') {
                quality = parseQuality(std.mem.trim(u8, param[2..], " \t"));
            }
        }

        if (std.mem.eql(u8, name, "*")) {
            result.wildcard = quality;
        } else if (std.ascii.eqlIgnoreCase(name, token)) {
            result.explicit = quality;
        }
    }

    return result;
}

/// Parse an HTTP quality value into milli units (0 to 1000).
///
/// Note:
/// - Grammar is ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] ). A malformed value
///   is treated leniently as 1000 (as if no q param was present), never as a silent 0
///   that would wrongly forbid a coding.
///
/// Param:
/// text - []const u8 (the value after q=)
///
/// Return:
/// - u16 (0 to 1000)
fn parseQuality(text: []const u8) u16 {
    if (text.len == 0) return 1000;

    if (text[0] == '1') return 1000;
    if (text[0] != '0') return 1000;

    if (text.len == 1) return 0;
    if (text[1] != '.') return 0;

    var fraction: u16 = 0;
    var scale: u16 = 100;
    var index: usize = 2;
    while (index < text.len and scale > 0) : (index += 1) {
        const digit = text[index];
        if (digit < '0' or digit > '9') break;

        fraction += @as(u16, digit - '0') * scale;
        scale /= 10;
    }

    return fraction;
}

/// Whether a response body is worth compressing.
///
/// Note:
/// - Skips bodies under the size floor and media types that are already compressed
///   (re-compressing them wastes CPU and can grow the body).
///
/// Param:
/// body_len - usize (uncompressed body length)
/// content_type - []const u8 (response Content-Type, with or without parameters)
/// min_size - usize (size floor, see min_size_default)
///
/// Return:
/// - bool (true when compression should be applied)
pub fn shouldCompress(body_len: usize, content_type: []const u8, min_size: usize) bool {
    if (body_len < min_size) return false;
    if (isAlreadyCompressed(content_type)) return false;

    return true;
}

fn isAlreadyCompressed(content_type: []const u8) bool {
    const semicolon = std.mem.indexOfScalar(u8, content_type, ';') orelse content_type.len;
    const media_type = std.mem.trim(u8, content_type[0..semicolon], " \t");

    const compressed_prefixes = [_][]const u8{
        "image/jpeg",
        "image/png",
        "image/gif",
        "image/webp",
        "image/avif",
        "video/",
        "audio/",
        "application/zip",
        "application/gzip",
        "application/x-gzip",
        "application/zstd",
        "application/x-brotli",
        "font/woff",
        "font/woff2",
    };

    for (compressed_prefixes) |prefix| {
        if (startsWithIgnoreCase(media_type, prefix)) return true;
    }

    return false;
}

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;

    return std.ascii.eqlIgnoreCase(haystack[0..prefix.len], prefix);
}

/// Encode a body with the chosen coding into a freshly allocated buffer.
///
/// Param:
/// allocator - std.mem.Allocator (owns the returned slice)
/// encoding - Encoding (chosen coding)
/// data - []const u8 (uncompressed body)
/// level - Level (effort, ignored for identity)
///
/// Return:
/// - []u8 (owned, free with the same allocator. For identity it is a copy of data)
pub fn encode(allocator: std.mem.Allocator, encoding: Encoding, data: []const u8, level: Level) ![]u8 {
    return switch (encoding) {
        .IDENTITY => allocator.dupe(u8, data),
        .GZIP => flate.compressGzipAlloc(allocator, data, level),
        .DEFLATE => flate.compressDeflateAlloc(allocator, data, level),
        .BR => brotli.compressBrotliAlloc(allocator, data, level),
    };
}

/// Encode a body with the chosen coding into a caller-provided buffer.
///
/// Note:
/// - The into-buffer counterpart of encode, for a caller that assembles a
///   response around the encoded bytes with no extra copy (reserve-prefix
///   assembly). The allocator feeds only transient codec scratch, freed or
///   reclaimed before return.
///
/// Param:
/// allocator - std.mem.Allocator (transient codec scratch)
/// encoding - Encoding (chosen coding)
/// data - []const u8 (uncompressed body)
/// out_buf - []u8 (destination)
/// level - Level (effort, ignored for identity)
///
/// Return:
/// - usize (encoded byte count written into out_buf)
/// - error.ZixBufferTooSmall when out_buf cannot hold the result
pub fn encodeInto(allocator: std.mem.Allocator, encoding: Encoding, data: []const u8, out_buf: []u8, level: Level) !usize {
    switch (encoding) {
        .IDENTITY => {
            if (out_buf.len < data.len) return error.ZixBufferTooSmall;

            @memcpy(out_buf[0..data.len], data);
            return data.len;
        },
        .GZIP => return flate.compressGzip(allocator, data, out_buf, level),
        .DEFLATE => return flate.compressDeflate(allocator, data, out_buf, level),
        .BR => return brotli.compressBrotli(allocator, data, out_buf, level),
    }
}

/// Decode a body encoded with the given coding into a freshly allocated buffer.
///
/// Param:
/// allocator - std.mem.Allocator (owns the returned slice)
/// encoding - Encoding (coding the data is in)
/// data - []const u8 (encoded body)
/// max_out - usize (decompression-bomb ceiling, ignored for identity)
///
/// Return:
/// - []u8 (owned, free with the same allocator)
pub fn decode(allocator: std.mem.Allocator, encoding: Encoding, data: []const u8, max_out: usize) ![]u8 {
    return switch (encoding) {
        .IDENTITY => allocator.dupe(u8, data),
        .GZIP => flate.decompressGzipAlloc(allocator, data, max_out),
        .DEFLATE => flate.decompressDeflateAlloc(allocator, data, max_out),
        .BR => brotli.decompressBrotliAlloc(allocator, data, max_out),
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

const gzip_only = [_]Encoding{.GZIP};
const gzip_then_deflate = [_]Encoding{ .GZIP, .DEFLATE };
const deflate_then_gzip = [_]Encoding{ .DEFLATE, .GZIP };

test "zix compression: negotiate absent header defaults to identity" {
    try testing.expectEqual(Encoding.IDENTITY, negotiate(null, &gzip_only).?);
}

test "zix compression: negotiate empty field means identity only" {
    try testing.expectEqual(Encoding.IDENTITY, negotiate("", &gzip_only).?);
    try testing.expectEqual(Encoding.IDENTITY, negotiate("   ", &gzip_only).?);
}

test "zix compression: negotiate simple gzip" {
    try testing.expectEqual(Encoding.GZIP, negotiate("gzip", &gzip_only).?);
}

test "zix compression: negotiate gzip requested but not producible falls back to identity" {
    const none = [_]Encoding{};

    try testing.expectEqual(Encoding.IDENTITY, negotiate("gzip", &none).?);
}

test "zix compression: negotiate unsupported coding requested falls back to identity" {
    try testing.expectEqual(Encoding.IDENTITY, negotiate("br", &gzip_only).?);
    try testing.expectEqual(Encoding.IDENTITY, negotiate("deflate", &gzip_only).?);
}

test "zix compression: negotiate gzip forbidden via q=0 falls back to identity" {
    try testing.expectEqual(Encoding.IDENTITY, negotiate("gzip;q=0", &gzip_only).?);
    try testing.expectEqual(Encoding.IDENTITY, negotiate("gzip;q=0.000", &gzip_only).?);
}

test "zix compression: negotiate client prefers identity by quality" {
    try testing.expectEqual(Encoding.IDENTITY, negotiate("gzip;q=0.5, identity;q=1", &gzip_only).?);
}

test "zix compression: negotiate client prefers gzip by quality" {
    try testing.expectEqual(Encoding.GZIP, negotiate("gzip;q=1, identity;q=0.5", &gzip_only).?);
}

test "zix compression: negotiate equal quality prefers compression over identity" {
    try testing.expectEqual(Encoding.GZIP, negotiate("gzip, identity", &gzip_only).?);
    try testing.expectEqual(Encoding.GZIP, negotiate("gzip;q=1, identity;q=1", &gzip_only).?);
}

test "zix compression: negotiate explicit identity with higher q suppresses compression" {
    try testing.expectEqual(Encoding.IDENTITY, negotiate("gzip;q=0.5, identity;q=0.9", &gzip_only).?);
    try testing.expectEqual(Encoding.GZIP, negotiate("gzip;q=0.9, identity;q=0.5", &gzip_only).?);
}

test "zix compression: negotiate wildcard identity does not suppress compression" {
    try testing.expectEqual(Encoding.GZIP, negotiate("gzip;q=0.5, *", &gzip_only).?);
}

test "zix compression: negotiate wildcard makes gzip acceptable" {
    try testing.expectEqual(Encoding.GZIP, negotiate("*", &gzip_only).?);
}

test "zix compression: negotiate wildcard q=0 forbids everything" {
    try testing.expectEqual(@as(?Encoding, null), negotiate("*;q=0", &gzip_only));
}

test "zix compression: negotiate identity q=0 with no producible coding is 406" {
    try testing.expectEqual(@as(?Encoding, null), negotiate("identity;q=0", &gzip_only));
}

test "zix compression: negotiate identity q=0 but gzip offered uses gzip" {
    try testing.expectEqual(Encoding.GZIP, negotiate("identity;q=0, gzip", &gzip_only).?);
}

test "zix compression: negotiate identity q=0 with wildcard uses gzip" {
    try testing.expectEqual(Encoding.GZIP, negotiate("identity;q=0, *", &gzip_only).?);
}

test "zix compression: negotiate case insensitive coding names" {
    try testing.expectEqual(Encoding.GZIP, negotiate("GZIP", &gzip_only).?);
    try testing.expectEqual(Encoding.GZIP, negotiate("GZip;Q=1", &gzip_only).?);
}

test "zix compression: negotiate surrounding whitespace tolerated" {
    try testing.expectEqual(Encoding.GZIP, negotiate("  gzip , deflate  ", &gzip_only).?);
    try testing.expectEqual(Encoding.GZIP, negotiate("gzip; q=0.9", &gzip_only).?);
}

test "zix compression: negotiate tiny non-zero quality still acceptable" {
    try testing.expectEqual(Encoding.GZIP, negotiate("gzip;q=0.001", &gzip_only).?);
}

test "zix compression: negotiate highest client quality wins among producible" {
    try testing.expectEqual(Encoding.GZIP, negotiate("deflate;q=0.5, gzip;q=0.8", &gzip_then_deflate).?);
    try testing.expectEqual(Encoding.DEFLATE, negotiate("deflate;q=0.9, gzip;q=0.8", &gzip_then_deflate).?);
}

test "zix compression: negotiate equal quality breaks ties by server preference" {
    try testing.expectEqual(Encoding.GZIP, negotiate("gzip;q=0.5, deflate;q=0.5", &gzip_then_deflate).?);
    try testing.expectEqual(Encoding.DEFLATE, negotiate("gzip;q=0.5, deflate;q=0.5", &deflate_then_gzip).?);
}

test "zix compression: negotiate unknown coding ignored, producible one chosen" {
    try testing.expectEqual(Encoding.GZIP, negotiate("br, gzip", &gzip_only).?);
}

test "zix compression: encoding token and content-encoding header" {
    try testing.expectEqualStrings("gzip", Encoding.GZIP.token());
    try testing.expectEqualStrings("identity", Encoding.IDENTITY.token());
    try testing.expectEqualStrings("gzip", Encoding.GZIP.contentEncoding().?);
    try testing.expectEqual(@as(?[]const u8, null), Encoding.IDENTITY.contentEncoding());
}

test "zix compression: shouldCompress below the floor is skipped" {
    try testing.expect(!shouldCompress(64, "text/html", min_size_default));
    try testing.expect(shouldCompress(4096, "text/html", min_size_default));
}

test "zix compression: shouldCompress already-compressed media types are skipped" {
    try testing.expect(!shouldCompress(4096, "image/jpeg", min_size_default));
    try testing.expect(!shouldCompress(4096, "video/mp4", min_size_default));
    try testing.expect(!shouldCompress(4096, "application/zip", min_size_default));
    try testing.expect(!shouldCompress(4096, "font/woff2", min_size_default));
}

test "zix compression: shouldCompress content-type parameters are ignored" {
    try testing.expect(shouldCompress(4096, "text/html; charset=utf-8", min_size_default));
    try testing.expect(!shouldCompress(4096, "IMAGE/JPEG; quality=90", min_size_default));
}

test "zix compression: encode identity is a passthrough copy" {
    const original = "passthrough body";

    const out = try encode(testing.allocator, .IDENTITY, original, .DEFAULT);
    defer testing.allocator.free(out);

    try testing.expectEqualStrings(original, out);
    try testing.expect(out.ptr != original.ptr);
}

test "zix compression: encode then decode gzip roundtrips" {
    const original = "facade roundtrip over the gzip codec";

    const packed_bytes = try encode(testing.allocator, .GZIP, original, .DEFAULT);
    defer testing.allocator.free(packed_bytes);

    const restored = try decode(testing.allocator, .GZIP, packed_bytes, 1024);
    defer testing.allocator.free(restored);

    try testing.expectEqualStrings(original, restored);
}

test "zix compression: encode then decode deflate roundtrips" {
    const original = "facade roundtrip over the deflate codec";

    const packed_bytes = try encode(testing.allocator, .DEFLATE, original, .DEFAULT);
    defer testing.allocator.free(packed_bytes);

    const restored = try decode(testing.allocator, .DEFLATE, packed_bytes, 1024);
    defer testing.allocator.free(restored);

    try testing.expectEqualStrings(original, restored);
}

test "zix compression: encode then decode brotli roundtrips" {
    const original = "facade roundtrip over the brotli codec, repeated for a real match. " ++
        "facade roundtrip over the brotli codec, repeated for a real match.";

    const packed_bytes = try encode(testing.allocator, .BR, original, .DEFAULT);
    defer testing.allocator.free(packed_bytes);

    const restored = try decode(testing.allocator, .BR, packed_bytes, 1024);
    defer testing.allocator.free(restored);

    try testing.expectEqualStrings(original, restored);
}

test "zix compression: encodeInto gzip writes into the caller buffer and roundtrips" {
    const original = "facade into-buffer roundtrip over the gzip codec, repeated for a real match. " ++
        "facade into-buffer roundtrip over the gzip codec, repeated for a real match.";

    var out: [512]u8 = undefined;
    const written = try encodeInto(testing.allocator, .GZIP, original, &out, .DEFAULT);

    const restored = try decode(testing.allocator, .GZIP, out[0..written], 1024);
    defer testing.allocator.free(restored);

    try testing.expectEqualStrings(original, restored);
}

test "zix compression: encodeInto identity copies and rejects a short buffer" {
    var out: [8]u8 = undefined;
    const written = try encodeInto(testing.allocator, .IDENTITY, "abc", &out, .DEFAULT);
    try testing.expectEqualStrings("abc", out[0..written]);

    var tiny: [2]u8 = undefined;
    try testing.expectError(error.ZixBufferTooSmall, encodeInto(testing.allocator, .IDENTITY, "abc", &tiny, .DEFAULT));
}

test "zix compression: negotiate supported_default leads with gzip, brotli when the client prefers it" {
    try testing.expectEqual(Encoding.BR, negotiate("br", &supported_default).?);
    try testing.expectEqual(Encoding.DEFLATE, negotiate("deflate", &supported_default).?);
    try testing.expectEqual(Encoding.GZIP, negotiate("gzip", &supported_default).?);
    // equal q: gzip wins on server preference order.
    try testing.expectEqual(Encoding.GZIP, negotiate("gzip, deflate, br", &supported_default).?);
    // the client can still steer to brotli with a higher q or by forbidding gzip.
    try testing.expectEqual(Encoding.BR, negotiate("gzip;q=0.5, br;q=1", &supported_default).?);
    try testing.expectEqual(Encoding.BR, negotiate("gzip;q=0, deflate;q=0, br", &supported_default).?);
}
