//! zix SCTP variable-length parameters (RFC 9260 3.2.1).
//!
//! What:
//! - The type-length-value blocks that fill the body of the control chunks: INIT and INIT ACK
//!   carry the state cookie and the extension flags this way, RE-CONFIG carries stream reset
//!   requests, and ERROR carries its causes.
//! - Same walking and writing surface as a chunk region, over a different registry.
//!
//! Note:
//! - A parameter type and a chunk type are different numbering spaces, so they are different
//!   files. What they share is the 4-byte alignment rule, which is a property of the wire format
//!   rather than of either registry.
//! - Parameter types are unique across all chunks (RFC 9260 3.2.1). Type 5 means an IPv4 address
//!   wherever it appears, so one registry covers every chunk that carries parameters.
//! - The top two bits of the type say what to do with a parameter this endpoint does not know,
//!   the same trick chunk types use, but the actions are scoped to the chunk being parsed rather
//!   than to the whole packet.
//! - Under DTLS there are no address parameters to send: RFC 8261 6.1 forbids IPv4 Address, IPv6
//!   Address, and Supported Address Types, because SCTP over DTLS is always single-homed. They
//!   stay in the registry so an arriving one is recognised and ignored rather than reported.

const std = @import("std");

/// Type and length.
pub const HEADER_LEN: usize = 4;

/// Every parameter starts on a 4-byte boundary (RFC 9260 3.2.1).
pub const ALIGNMENT: usize = 4;

/// Largest value the length field can hold.
pub const MAX_PARAMETER_LEN: usize = std.math.maxInt(u16);

/// Framing faults that make the enclosing chunk undecodable.
pub const Error = error{
    /// A parameter claims to run past the end of the region.
    ZixTruncated,
    /// A parameter length below the header size, which cannot be right at any type.
    ZixBadLength,
    /// The region has no room for another parameter.
    ZixNoSpace,
};

/// Parameter types this build knows.
///
/// Note:
/// - Non-exhaustive. An unknown type is still represented, because what happens next is decided
///   from its number, see `unknownAction`.
pub const Type = enum(u16) {
    /// Opaque blob echoed back in a HEARTBEAT ACK (RFC 9260 3.3.5).
    HEARTBEAT_INFO = 0x0001,
    /// Forbidden under DTLS, recognised so it is ignored quietly (RFC 8261 6.1).
    IPV4_ADDRESS = 0x0005,
    /// Forbidden under DTLS, recognised so it is ignored quietly (RFC 8261 6.1).
    IPV6_ADDRESS = 0x0006,
    /// The signed blob an INIT ACK hands out and a COOKIE ECHO hands back (RFC 9260 3.3.3.1).
    STATE_COOKIE = 0x0007,
    /// Reports back the parameters the sender did not understand (RFC 9260 3.2.2).
    UNRECOGNIZED_PARAMETER = 0x0008,
    /// Asks for a longer cookie lifetime (RFC 9260 3.3.2.1).
    COOKIE_PRESERVATIVE = 0x0009,
    HOST_NAME_ADDRESS = 0x000B,
    /// Forbidden under DTLS, recognised so it is ignored quietly (RFC 8261 6.1).
    SUPPORTED_ADDRESS_TYPES = 0x000C,
    /// RFC 6525 4.1, the request that closes a data channel.
    OUTGOING_SSN_RESET = 0x000D,
    /// RFC 6525 4.2.
    INCOMING_SSN_RESET = 0x000E,
    /// RFC 6525 4.3.
    SSN_TSN_RESET = 0x000F,
    /// RFC 6525 4.4, the answer to any of the three requests above.
    RECONFIG_RESPONSE = 0x0010,
    /// RFC 6525 4.5.
    ADD_OUTGOING_STREAMS = 0x0011,
    /// RFC 6525 4.6.
    ADD_INCOMING_STREAMS = 0x0012,
    /// Lists the chunk types the sender supports, which is how RE-CONFIG is advertised
    /// (RFC 5061 4.2.7).
    SUPPORTED_EXTENSIONS = 0x8008,
    /// Announces that the sender handles FORWARD TSN (RFC 3758 3.1).
    FORWARD_TSN_SUPPORTED = 0xC000,
    _,
};

/// What an endpoint does with a parameter type it does not recognise (RFC 9260 3.2.1 Table 3).
pub const UnknownAction = enum {
    /// Stop reading parameters in this chunk.
    STOP,
    /// Stop reading parameters in this chunk and report the type back.
    STOP_AND_REPORT,
    /// Ignore this parameter and read the next one.
    SKIP,
    /// Ignore this parameter, read the next one, and report the type back.
    SKIP_AND_REPORT,
};

/// One parameter, borrowed from the region it was read out of.
pub const Parameter = struct {
    kind: Type,
    /// Everything after the 4-byte header, padding excluded.
    value: []const u8,
    /// Where this parameter's header starts inside the region.
    offset: usize,
};

/// Size a parameter of `len` bytes occupies once padded to the next 4-byte boundary.
///
/// Param:
/// len - usize (parameter length as the length field states it, header included)
///
/// Return:
/// - usize
pub fn paddedLen(len: usize) usize {
    return std.mem.alignForward(usize, len, ALIGNMENT);
}

/// The handling rule carried in the top two bits of the type number.
///
/// Param:
/// kind - Type
///
/// Return:
/// - UnknownAction
pub fn unknownAction(kind: Type) UnknownAction {
    return switch (@intFromEnum(kind) >> 14) {
        0 => .STOP,
        1 => .STOP_AND_REPORT,
        2 => .SKIP,
        else => .SKIP_AND_REPORT,
    };
}

/// Whether this build decodes the parameter type.
///
/// Param:
/// kind - Type
///
/// Return:
/// - bool
pub fn isKnown(kind: Type) bool {
    return switch (kind) {
        .HEARTBEAT_INFO,
        .IPV4_ADDRESS,
        .IPV6_ADDRESS,
        .STATE_COOKIE,
        .UNRECOGNIZED_PARAMETER,
        .COOKIE_PRESERVATIVE,
        .HOST_NAME_ADDRESS,
        .SUPPORTED_ADDRESS_TYPES,
        .OUTGOING_SSN_RESET,
        .INCOMING_SSN_RESET,
        .SSN_TSN_RESET,
        .RECONFIG_RESPONSE,
        .ADD_OUTGOING_STREAMS,
        .ADD_INCOMING_STREAMS,
        .SUPPORTED_EXTENSIONS,
        .FORWARD_TSN_SUPPORTED,
        => true,
        else => false,
    };
}

/// Check that every parameter in a region is framed correctly.
///
/// Note:
/// - Call this once before iterating. `Iterator` trusts the region afterwards.
/// - The last parameter of a chunk may end without its padding (RFC 9260 3.2).
///
/// Param:
/// region - []const u8 (the part of a chunk value that holds parameters)
///
/// Return:
/// - void
/// - error.ZixBadLength if a parameter claims a length below the header size
/// - error.ZixTruncated if a parameter runs past the end of the region
pub fn validate(region: []const u8) Error!void {
    var pos: usize = 0;

    while (pos < region.len) {
        if (region.len - pos < HEADER_LEN) return error.ZixTruncated;

        const len = std.mem.readInt(u16, region[pos + 2 ..][0..2], .big);

        if (len < HEADER_LEN) return error.ZixBadLength;
        if (region.len - pos < len) return error.ZixTruncated;

        const advance = paddedLen(len);

        pos += if (region.len - pos < advance) region.len - pos else advance;
    }
}

/// Walks the parameters of a validated region.
///
/// Note:
/// - Only construct this over a region `validate` has accepted.
pub const Iterator = struct {
    region: []const u8,
    pos: usize = 0,

    /// The next parameter, or null at the end of the region.
    ///
    /// Return:
    /// - ?Parameter
    pub fn next(self: *Iterator) ?Parameter {
        if (self.region.len - self.pos < HEADER_LEN) return null;

        const start = self.pos;
        const kind: Type = @enumFromInt(std.mem.readInt(u16, self.region[start..][0..2], .big));
        const len = std.mem.readInt(u16, self.region[start + 2 ..][0..2], .big);
        const advance = paddedLen(len);

        self.pos += if (self.region.len - start < advance) self.region.len - start else advance;

        return .{
            .kind = kind,
            .value = self.region[start + HEADER_LEN ..][0 .. len - HEADER_LEN],
            .offset = start,
        };
    }
};

/// First parameter of a given type in a validated region.
///
/// Param:
/// region - []const u8 (validated parameter region)
/// kind - Type
///
/// Return:
/// - ?Parameter
pub fn find(region: []const u8, kind: Type) ?Parameter {
    var iterator = Iterator{ .region = region };

    while (iterator.next()) |item| {
        if (item.kind == kind) return item;
    }

    return null;
}

/// How much of a region a receiver is allowed to read.
///
/// Note:
/// - An unknown parameter whose type says STOP cancels every parameter after it (RFC 9260
///   3.2.1). What was already read stays read, so this is a prefix length rather than an error.
/// - Every parameter this build cares about sits in the skip range, so under DTLS this returns
///   the whole region in practice. It matters when a peer sends something from the stop range
///   ahead of the state cookie, where using the cookie anyway would be wrong.
///
/// Param:
/// region - []const u8 (validated parameter region)
///
/// Return:
/// - usize, the length of the prefix that may be read
pub fn readableLen(region: []const u8) usize {
    var iterator = Iterator{ .region = region };

    while (iterator.next()) |item| {
        if (isKnown(item.kind)) continue;

        switch (unknownAction(item.kind)) {
            .STOP, .STOP_AND_REPORT => return item.offset,
            .SKIP, .SKIP_AND_REPORT => continue,
        }
    }

    return region.len;
}

/// Unknown parameters whose type asks to be reported back to the sender.
///
/// Note:
/// - Scanning stops after a parameter from the stop range, matching `readableLen`.
/// - Repeats are not merged. Each report echoes a whole parameter, so two of the same type are
///   two distinct things to hand back.
///
/// Param:
/// region - []const u8 (validated parameter region)
/// out - []Parameter (caller storage, the scan stops when it is full)
///
/// Return:
/// - []Parameter, a prefix of `out`
pub fn collectReportable(region: []const u8, out: []Parameter) []Parameter {
    var count: usize = 0;

    var iterator = Iterator{ .region = region };
    while (iterator.next()) |item| {
        if (isKnown(item.kind)) continue;

        const action = unknownAction(item.kind);
        const report = action == .STOP_AND_REPORT or action == .SKIP_AND_REPORT;

        if (report and count < out.len) {
            out[count] = item;
            count += 1;
        }

        if (action == .STOP or action == .STOP_AND_REPORT) break;
    }

    return out[0..count];
}

/// Write one whole parameter, header then value then padding.
///
/// Param:
/// out - []u8 (buffer to write into, from its start)
/// kind - Type
/// value - []const u8 (parameter body, padding excluded)
///
/// Return:
/// - []const u8 covering header, value, and padding
/// - error.ZixNoSpace if the buffer cannot hold the padded parameter
/// - error.ZixBadLength if the value is too long for the 16-bit length field
pub fn write(out: []u8, kind: Type, value: []const u8) Error![]const u8 {
    const len = HEADER_LEN + value.len;

    if (len > MAX_PARAMETER_LEN) return error.ZixBadLength;

    const total = paddedLen(len);

    if (out.len < total) return error.ZixNoSpace;

    std.mem.writeInt(u16, out[0..2], @intFromEnum(kind), .big);
    std.mem.writeInt(u16, out[2..4], @intCast(len), .big);
    @memcpy(out[HEADER_LEN..][0..value.len], value);
    @memset(out[len..total], 0);

    return out[0..total];
}

// --------------------------------------------------------------------------------------- //
// test cases

test "zix sctp: parameter registry, the known types decode and an unassigned one does not" {
    try std.testing.expect(isKnown(.STATE_COOKIE));
    try std.testing.expect(isKnown(.FORWARD_TSN_SUPPORTED));
    try std.testing.expect(isKnown(.OUTGOING_SSN_RESET));
    try std.testing.expect(!isKnown(@enumFromInt(0x0003)));
    try std.testing.expect(!isKnown(@enumFromInt(0xC001)));
}

test "zix sctp: parameter unknown action, the top two bits of the type decide it" {
    try std.testing.expectEqual(UnknownAction.STOP, unknownAction(@enumFromInt(0x0000)));
    try std.testing.expectEqual(UnknownAction.STOP, unknownAction(@enumFromInt(0x3FFF)));
    try std.testing.expectEqual(UnknownAction.STOP_AND_REPORT, unknownAction(@enumFromInt(0x4000)));
    try std.testing.expectEqual(UnknownAction.SKIP, unknownAction(@enumFromInt(0x8000)));
    try std.testing.expectEqual(UnknownAction.SKIP_AND_REPORT, unknownAction(@enumFromInt(0xC000)));
}

test "zix sctp: parameter unknown action, the extension types carry the action their RFC expects" {
    // A peer without partial reliability reports the flag back instead of failing the handshake.
    try std.testing.expectEqual(UnknownAction.SKIP_AND_REPORT, unknownAction(.FORWARD_TSN_SUPPORTED));
    try std.testing.expectEqual(UnknownAction.SKIP, unknownAction(.SUPPORTED_EXTENSIONS));

    // A cookie that cannot be understood has to stop the handshake, not be skipped.
    try std.testing.expectEqual(UnknownAction.STOP, unknownAction(.STATE_COOKIE));
}

test "zix sctp: parameter write, a value round trips through the iterator" {
    var buf: [32]u8 = undefined;
    const written = try write(&buf, .STATE_COOKIE, "cookie-bytes");

    try std.testing.expectEqual(@as(usize, 16), written.len);
    try std.testing.expectEqual(@as(u16, 16), std.mem.readInt(u16, written[2..4], .big));

    try validate(written);

    var iterator = Iterator{ .region = written };
    const item = iterator.next().?;

    try std.testing.expectEqual(Type.STATE_COOKIE, item.kind);
    try std.testing.expectEqualStrings("cookie-bytes", item.value);
    try std.testing.expect(iterator.next() == null);
}

test "zix sctp: parameter write, an unaligned value is zero padded and the length excludes it" {
    var buf: [16]u8 = undefined;
    const written = try write(&buf, .HEARTBEAT_INFO, "xyz");

    try std.testing.expectEqual(@as(usize, 8), written.len);
    try std.testing.expectEqual(@as(u16, 7), std.mem.readInt(u16, written[2..4], .big));
    try std.testing.expectEqual(@as(u8, 0), written[7]);
}

test "zix sctp: parameter write, an empty value gives a bare header" {
    var buf: [8]u8 = undefined;
    const written = try write(&buf, .FORWARD_TSN_SUPPORTED, &.{});

    try std.testing.expectEqualSlices(u8, &.{ 0xC0, 0x00, 0x00, 0x04 }, written);
}

test "zix sctp: parameter write, a buffer too small errors" {
    var buf: [4]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, write(&buf, .STATE_COOKIE, "abcd"));
}

test "zix sctp: parameter find, the right type is picked out of a mixed region" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    pos += (try write(buf[pos..], .FORWARD_TSN_SUPPORTED, &.{})).len;
    pos += (try write(buf[pos..], .STATE_COOKIE, "the-cookie")).len;
    pos += (try write(buf[pos..], .SUPPORTED_EXTENSIONS, &.{ 130, 192 })).len;

    const region = buf[0..pos];
    try validate(region);

    try std.testing.expectEqualStrings("the-cookie", find(region, .STATE_COOKIE).?.value);
    try std.testing.expectEqual(@as(usize, 0), find(region, .FORWARD_TSN_SUPPORTED).?.value.len);
    try std.testing.expectEqualSlices(u8, &.{ 130, 192 }, find(region, .SUPPORTED_EXTENSIONS).?.value);
    try std.testing.expect(find(region, .IPV4_ADDRESS) == null);
}

test "zix sctp: parameter find, the first of a repeated type is returned" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;

    pos += (try write(buf[pos..], .HEARTBEAT_INFO, "aaaa")).len;
    pos += (try write(buf[pos..], .HEARTBEAT_INFO, "bbbb")).len;

    const region = buf[0..pos];
    try validate(region);

    try std.testing.expectEqualStrings("aaaa", find(region, .HEARTBEAT_INFO).?.value);
}

test "zix sctp: parameter validate, a length below the header size errors" {
    const region: [4]u8 = .{ 0x00, 0x07, 0x00, 0x02 };

    try std.testing.expectError(error.ZixBadLength, validate(&region));
}

test "zix sctp: parameter validate, a parameter running past the region errors" {
    const region: [4]u8 = .{ 0x00, 0x07, 0x00, 0x10 };

    try std.testing.expectError(error.ZixTruncated, validate(&region));
}

test "zix sctp: parameter validate, the last parameter may arrive without its padding" {
    var buf: [16]u8 = undefined;
    const first = try write(&buf, .FORWARD_TSN_SUPPORTED, &.{});
    _ = try write(buf[first.len..], .HEARTBEAT_INFO, "xyz");

    // 4 for the flag, then 7 of a 7-byte parameter whose single padding byte was left off.
    const region = buf[0..11];
    try validate(region);

    var iterator = Iterator{ .region = region };
    _ = iterator.next().?;

    try std.testing.expectEqualStrings("xyz", iterator.next().?.value);
    try std.testing.expect(iterator.next() == null);
}

test "zix sctp: parameter validate, an empty region is accepted" {
    try validate(&.{});
    try std.testing.expect(find(&.{}, .STATE_COOKIE) == null);
}

test "zix sctp: parameter readable, a region of known types is readable whole" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;

    pos += (try write(buf[pos..], .FORWARD_TSN_SUPPORTED, &.{})).len;
    pos += (try write(buf[pos..], .STATE_COOKIE, "abcd")).len;

    const region = buf[0..pos];
    try validate(region);

    try std.testing.expectEqual(pos, readableLen(region));
}

test "zix sctp: parameter readable, an unknown type from the stop range cuts the region short" {
    var buf: [48]u8 = undefined;
    var pos: usize = 0;

    pos += (try write(buf[pos..], .FORWARD_TSN_SUPPORTED, &.{})).len;
    const stop_at = pos;
    pos += (try write(buf[pos..], @enumFromInt(0x0003), "no")).len;
    pos += (try write(buf[pos..], .STATE_COOKIE, "abcd")).len;

    const region = buf[0..pos];
    try validate(region);

    // The cookie is past the stop, so a receiver must not use it even though `find` sees it.
    try std.testing.expectEqual(stop_at, readableLen(region));
    try std.testing.expect(find(region[0..readableLen(region)], .STATE_COOKIE) == null);
}

test "zix sctp: parameter readable, an unknown type from the skip range does not cut it short" {
    var buf: [48]u8 = undefined;
    var pos: usize = 0;

    pos += (try write(buf[pos..], @enumFromInt(0x8003), "skip")).len;
    pos += (try write(buf[pos..], .STATE_COOKIE, "abcd")).len;

    const region = buf[0..pos];
    try validate(region);

    try std.testing.expectEqual(pos, readableLen(region));
}

test "zix sctp: parameter reportable, only unknown types from the report ranges are collected" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    pos += (try write(buf[pos..], .STATE_COOKIE, "known")).len;
    pos += (try write(buf[pos..], @enumFromInt(0x8003), "skip quietly")).len;
    pos += (try write(buf[pos..], @enumFromInt(0xC003), "skip loudly")).len;

    const region = buf[0..pos];
    try validate(region);

    var found: [4]Parameter = undefined;
    const reportable = collectReportable(region, &found);

    try std.testing.expectEqual(@as(usize, 1), reportable.len);
    try std.testing.expectEqualStrings("skip loudly", reportable[0].value);
}

test "zix sctp: parameter reportable, a stop-and-report type is reported and ends the scan" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    pos += (try write(buf[pos..], @enumFromInt(0x4001), "stop loudly")).len;
    pos += (try write(buf[pos..], @enumFromInt(0xC003), "never seen")).len;

    const region = buf[0..pos];
    try validate(region);

    var found: [4]Parameter = undefined;
    const reportable = collectReportable(region, &found);

    try std.testing.expectEqual(@as(usize, 1), reportable.len);
    try std.testing.expectEqualStrings("stop loudly", reportable[0].value);
}

test "zix sctp: parameter reportable, the scan stops when caller storage runs out" {
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    pos += (try write(buf[pos..], @enumFromInt(0xC003), "one")).len;
    pos += (try write(buf[pos..], @enumFromInt(0xC004), "two")).len;

    const region = buf[0..pos];
    try validate(region);

    var found: [1]Parameter = undefined;
    const reportable = collectReportable(region, &found);

    try std.testing.expectEqual(@as(usize, 1), reportable.len);
    try std.testing.expectEqualStrings("one", reportable[0].value);
}
