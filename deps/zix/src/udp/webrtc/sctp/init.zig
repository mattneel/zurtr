//! zix SCTP initiation chunks, INIT and INIT ACK (RFC 9260 3.3.2, 3.3.3).
//!
//! What:
//! - The five fixed fields both chunks carry, and the parameters that follow them. The two
//!   chunks have the same layout, so one reader and one builder serve both, and the chunk type
//!   is chosen by the caller putting the body into a packet.
//! - The checks RFC 9260 3.3.2 states as MUST on the fixed fields, so a peer that sends a zero
//!   initiate tag or zero streams is rejected here rather than deeper in the association.
//!
//! Note:
//! - What separates the two chunks is which parameters are allowed, not the layout. An INIT ACK
//!   adds the state cookie and may report unrecognised parameters back, an INIT never carries a
//!   cookie.
//! - Under DTLS neither chunk carries addresses (RFC 8261 6.1), so the parameter list is short:
//!   the state cookie, the two extension flags, and whatever the peer sent that this build does
//!   not know.
//! - The two extension flags are asymmetric. Partial reliability is announced with its own
//!   parameter (FORWARD-TSN-SUPPORTED), while stream reset is announced by listing the RE-CONFIG
//!   chunk type inside SUPPORTED-EXTENSIONS. Both have to be sent to get a browser data channel
//!   that can close cleanly.
//! - The stream counts are a request, not a negotiation. Each side ends up using
//!   min(what it asked for, what the peer offered), which the association computes.

const std = @import("std");

const chunk = @import("chunk.zig");
const parameter = @import("parameter.zig");

/// Initiate tag, a_rwnd, outbound streams, inbound streams, initial TSN.
pub const FIXED_LEN: usize = 16;

/// Smallest receive window a peer is allowed to advertise (RFC 9260 3.3.2).
pub const MIN_ADVERTISED_RWND: u32 = 1500;

/// How many chunk types one SUPPORTED-EXTENSIONS parameter can announce. Two are in use here,
/// RE-CONFIG and FORWARD TSN, and the ceiling only exists to keep the list on the stack.
pub const MAX_SUPPORTED_EXTENSIONS: usize = 8;

/// Everything that makes an initiation chunk unusable.
pub const Error = error{
    /// Fewer bytes than the fixed fields need, or a parameter running past the end.
    ZixTruncated,
    /// A parameter length below the parameter header size.
    ZixBadLength,
    /// The initiate tag is zero, which RFC 9260 3.3.2 forbids.
    ZixZeroInitiateTag,
    /// The advertised receive window is below 1500.
    ZixSmallWindow,
    /// Either stream count is zero, which RFC 9260 3.3.2 forbids.
    ZixZeroStreams,
    /// The output buffer cannot hold what was asked for.
    ZixNoSpace,
};

/// The fixed fields, which are the same in INIT and INIT ACK.
pub const Fixed = struct {
    /// What the peer must put in the verification tag of every packet it sends back. Never zero.
    initiate_tag: u32,
    /// Receive buffer the sender has dedicated to this association, in bytes.
    advertised_rwnd: u32,
    /// How many outbound streams the sender wants.
    outbound_streams: u16,
    /// How many inbound streams the sender will accept.
    inbound_streams: u16,
    /// First TSN the sender will use.
    initial_tsn: u32,
};

/// A parsed INIT or INIT ACK body, borrowing the chunk value it was read from.
pub const Initiation = struct {
    fixed: Fixed,
    /// The whole parameter region after the fixed fields.
    parameters: []const u8,
    /// How much of that region may be read, see parameter.readableLen.
    readable_len: usize,

    /// The parameters a receiver is allowed to act on.
    ///
    /// Return:
    /// - []const u8
    pub fn readable(self: Initiation) []const u8 {
        return self.parameters[0..self.readable_len];
    }

    /// The state cookie, present in an INIT ACK and never in an INIT.
    ///
    /// Return:
    /// - ?[]const u8
    pub fn stateCookie(self: Initiation) ?[]const u8 {
        const found = parameter.find(self.readable(), .STATE_COOKIE) orelse return null;

        return found.value;
    }

    /// Whether the sender announced partial reliability (RFC 3758 3.1).
    ///
    /// Return:
    /// - bool
    pub fn supportsForwardTsn(self: Initiation) bool {
        return parameter.find(self.readable(), .FORWARD_TSN_SUPPORTED) != null;
    }

    /// Whether the sender listed a chunk type in SUPPORTED-EXTENSIONS (RFC 5061 4.2.7).
    ///
    /// Param:
    /// kind - chunk.Type
    ///
    /// Return:
    /// - bool
    pub fn supportsChunk(self: Initiation, kind: chunk.Type) bool {
        const found = parameter.find(self.readable(), .SUPPORTED_EXTENSIONS) orelse return false;

        return std.mem.indexOfScalar(u8, found.value, @intFromEnum(kind)) != null;
    }

    /// Whether the sender can reset streams, which is how a data channel closes (RFC 6525).
    ///
    /// Return:
    /// - bool
    pub fn supportsReconfig(self: Initiation) bool {
        return self.supportsChunk(.RE_CONFIG);
    }

    /// Unknown parameters the sender asked to have reported back.
    ///
    /// Param:
    /// out - []parameter.Parameter (caller storage)
    ///
    /// Return:
    /// - []parameter.Parameter, a prefix of `out`
    pub fn reportable(self: Initiation, out: []parameter.Parameter) []parameter.Parameter {
        return parameter.collectReportable(self.parameters, out);
    }
};

/// Read an INIT or INIT ACK body.
///
/// Note:
/// - The fixed-field rules are checked here because every one of them makes the association
///   impossible, and RFC 9260 3.3.2 answers each with a discard or an ABORT rather than with a
///   half-built association.
///
/// Param:
/// value - []const u8 (chunk value, so everything after the 4-byte chunk header)
///
/// Return:
/// - Initiation borrowing `value`
/// - error.ZixTruncated, error.ZixBadLength, error.ZixZeroInitiateTag, error.ZixSmallWindow,
///   error.ZixZeroStreams
pub fn read(value: []const u8) Error!Initiation {
    if (value.len < FIXED_LEN) return error.ZixTruncated;

    const fixed: Fixed = .{
        .initiate_tag = std.mem.readInt(u32, value[0..4], .big),
        .advertised_rwnd = std.mem.readInt(u32, value[4..8], .big),
        .outbound_streams = std.mem.readInt(u16, value[8..10], .big),
        .inbound_streams = std.mem.readInt(u16, value[10..12], .big),
        .initial_tsn = std.mem.readInt(u32, value[12..16], .big),
    };

    if (fixed.initiate_tag == 0) return error.ZixZeroInitiateTag;
    if (fixed.advertised_rwnd < MIN_ADVERTISED_RWND) return error.ZixSmallWindow;
    if (fixed.outbound_streams == 0 or fixed.inbound_streams == 0) return error.ZixZeroStreams;

    const region = value[FIXED_LEN..];
    try parameter.validate(region);

    return .{
        .fixed = fixed,
        .parameters = region,
        .readable_len = parameter.readableLen(region),
    };
}

/// Builds an INIT or INIT ACK body into a caller buffer.
///
/// Note:
/// - Produces the chunk value. The caller decides whether it goes out as an INIT or an INIT ACK,
///   and both must travel alone in their packet (RFC 9260 3).
///
/// Usage:
/// ```zig
/// var buf: [256]u8 = undefined;
/// var builder = try init.Builder.begin(&buf, .{
///     .initiate_tag = local_tag,
///     .advertised_rwnd = 128 * 1024,
///     .outbound_streams = 128,
///     .inbound_streams = 128,
///     .initial_tsn = local_tsn,
/// });
/// try builder.addForwardTsnSupported();
/// try builder.addSupportedExtensions(&.{ .RE_CONFIG, .FORWARD_TSN });
/// try builder.addStateCookie(cookie);
///
/// try writer.addChunk(.INIT_ACK, 0, builder.chunkValue());
/// ```
pub const Builder = struct {
    buf: []u8,
    len: usize,

    /// Write the fixed fields and start the parameter region.
    ///
    /// Param:
    /// buf - []u8 (output buffer)
    /// fixed - Fixed
    ///
    /// Return:
    /// - Builder
    /// - error.ZixNoSpace if the buffer cannot hold the fixed fields
    /// - error.ZixZeroInitiateTag, error.ZixSmallWindow, error.ZixZeroStreams if the caller's own fields
    ///   break the rules a receiver would reject them for
    pub fn begin(buf: []u8, fixed: Fixed) Error!Builder {
        if (buf.len < FIXED_LEN) return error.ZixNoSpace;
        if (fixed.initiate_tag == 0) return error.ZixZeroInitiateTag;
        if (fixed.advertised_rwnd < MIN_ADVERTISED_RWND) return error.ZixSmallWindow;
        if (fixed.outbound_streams == 0 or fixed.inbound_streams == 0) return error.ZixZeroStreams;

        std.mem.writeInt(u32, buf[0..4], fixed.initiate_tag, .big);
        std.mem.writeInt(u32, buf[4..8], fixed.advertised_rwnd, .big);
        std.mem.writeInt(u16, buf[8..10], fixed.outbound_streams, .big);
        std.mem.writeInt(u16, buf[10..12], fixed.inbound_streams, .big);
        std.mem.writeInt(u32, buf[12..16], fixed.initial_tsn, .big);

        return .{ .buf = buf, .len = FIXED_LEN };
    }

    /// Append a parameter of any type.
    ///
    /// Param:
    /// kind - parameter.Type
    /// value - []const u8
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSpace, error.ZixBadLength
    pub fn addParameter(self: *Builder, kind: parameter.Type, value: []const u8) Error!void {
        const written = try parameter.write(self.buf[self.len..], kind, value);

        self.len += written.len;
    }

    /// Append the state cookie an INIT ACK hands out.
    ///
    /// Param:
    /// cookie - []const u8
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSpace
    pub fn addStateCookie(self: *Builder, cookie: []const u8) Error!void {
        return self.addParameter(.STATE_COOKIE, cookie);
    }

    /// Announce partial reliability (RFC 3758 3.1). The parameter has no value.
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSpace
    pub fn addForwardTsnSupported(self: *Builder) Error!void {
        return self.addParameter(.FORWARD_TSN_SUPPORTED, &.{});
    }

    /// Announce the chunk types this endpoint understands (RFC 5061 4.2.7).
    ///
    /// Note:
    /// - Listing RE_CONFIG here is what tells a peer it may close one data channel without
    ///   tearing down the association.
    ///
    /// Param:
    /// kinds - []const chunk.Type
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSpace if the list is longer than MAX_SUPPORTED_EXTENSIONS or does not fit
    pub fn addSupportedExtensions(self: *Builder, kinds: []const chunk.Type) Error!void {
        var list: [MAX_SUPPORTED_EXTENSIONS]u8 = undefined;

        if (kinds.len > list.len) return error.ZixNoSpace;

        for (kinds, 0..) |kind, index| list[index] = @intFromEnum(kind);

        return self.addParameter(.SUPPORTED_EXTENSIONS, list[0..kinds.len]);
    }

    /// Report a parameter back to the sender, wrapped whole (RFC 9260 3.3.3.1.2).
    ///
    /// Note:
    /// - The inner parameter's padding lands exactly where the outer parameter's padding would,
    ///   because the outer header is itself 4 bytes. So the outer length counts the inner header
    ///   and value, and nothing else.
    ///
    /// Param:
    /// unknown - parameter.Parameter (as it arrived)
    ///
    /// Return:
    /// - void
    /// - error.ZixNoSpace, error.ZixBadLength
    pub fn addUnrecognized(self: *Builder, unknown: parameter.Parameter) Error!void {
        const start = self.len;
        const inner_len = parameter.HEADER_LEN + unknown.value.len;

        if (self.buf.len - start < parameter.HEADER_LEN) return error.ZixNoSpace;

        const inner = try parameter.write(
            self.buf[start + parameter.HEADER_LEN ..],
            unknown.kind,
            unknown.value,
        );

        std.mem.writeInt(u16, self.buf[start..][0..2], @intFromEnum(parameter.Type.UNRECOGNIZED_PARAMETER), .big);
        std.mem.writeInt(u16, self.buf[start + 2 ..][0..2], @intCast(parameter.HEADER_LEN + inner_len), .big);

        self.len = start + parameter.HEADER_LEN + inner.len;
    }

    /// The finished chunk value.
    ///
    /// Return:
    /// - []const u8
    pub fn chunkValue(self: Builder) []const u8 {
        return self.buf[0..self.len];
    }
};

// --------------------------------------------------------------------------------------- //
// test cases

const sample_fixed: Fixed = .{
    .initiate_tag = 0x12345678,
    .advertised_rwnd = 128 * 1024,
    .outbound_streams = 128,
    .inbound_streams = 128,
    .initial_tsn = 0x0000ABCD,
};

test "zix sctp: init build, the fixed fields round trip" {
    var buf: [64]u8 = undefined;
    const builder = try Builder.begin(&buf, sample_fixed);

    const parsed = try read(builder.chunkValue());

    try std.testing.expectEqual(sample_fixed, parsed.fixed);
    try std.testing.expectEqual(@as(usize, 0), parsed.parameters.len);
}

test "zix sctp: init build, an empty INIT body is exactly the fixed fields" {
    var buf: [64]u8 = undefined;
    const builder = try Builder.begin(&buf, sample_fixed);

    try std.testing.expectEqual(FIXED_LEN, builder.chunkValue().len);
}

test "zix sctp: init build, the extension flags come back as the peer would read them" {
    var buf: [64]u8 = undefined;
    var builder = try Builder.begin(&buf, sample_fixed);
    try builder.addForwardTsnSupported();
    try builder.addSupportedExtensions(&.{ .RE_CONFIG, .FORWARD_TSN });

    const parsed = try read(builder.chunkValue());

    try std.testing.expect(parsed.supportsForwardTsn());
    try std.testing.expect(parsed.supportsReconfig());
    try std.testing.expect(parsed.supportsChunk(.FORWARD_TSN));
    try std.testing.expect(!parsed.supportsChunk(.PAD));
}

test "zix sctp: init read, a body with no extension parameters announces nothing" {
    var buf: [64]u8 = undefined;
    const builder = try Builder.begin(&buf, sample_fixed);

    const parsed = try read(builder.chunkValue());

    try std.testing.expect(!parsed.supportsForwardTsn());
    try std.testing.expect(!parsed.supportsReconfig());
    try std.testing.expect(parsed.stateCookie() == null);
}

test "zix sctp: init build, an INIT ACK carries the state cookie back out" {
    var buf: [128]u8 = undefined;
    var builder = try Builder.begin(&buf, sample_fixed);
    try builder.addForwardTsnSupported();
    try builder.addStateCookie("a-signed-cookie");

    const parsed = try read(builder.chunkValue());

    try std.testing.expectEqualStrings("a-signed-cookie", parsed.stateCookie().?);
    try std.testing.expect(parsed.supportsForwardTsn());
}

test "zix sctp: init build, an unrecognised parameter is wrapped whole" {
    var buf: [128]u8 = undefined;
    var builder = try Builder.begin(&buf, sample_fixed);
    try builder.addUnrecognized(.{ .kind = @enumFromInt(0xC003), .value = "odd", .offset = 0 });

    const parsed = try read(builder.chunkValue());
    const wrapper = parameter.find(parsed.readable(), .UNRECOGNIZED_PARAMETER).?;

    // The value is a whole parameter: type 0xC003, length 7, then the three bytes.
    try std.testing.expectEqual(@as(usize, 7), wrapper.value.len);
    try std.testing.expectEqual(@as(u16, 0xC003), std.mem.readInt(u16, wrapper.value[0..2], .big));
    try std.testing.expectEqual(@as(u16, 7), std.mem.readInt(u16, wrapper.value[2..4], .big));
    try std.testing.expectEqualStrings("odd", wrapper.value[4..7]);
}

test "zix sctp: init read, an unknown parameter that asks to be reported is collected" {
    var buf: [128]u8 = undefined;
    var builder = try Builder.begin(&buf, sample_fixed);
    try builder.addParameter(@enumFromInt(0xC003), "report me");
    try builder.addForwardTsnSupported();

    const parsed = try read(builder.chunkValue());

    var found: [4]parameter.Parameter = undefined;
    const reportable = parsed.reportable(&found);

    try std.testing.expectEqual(@as(usize, 1), reportable.len);
    try std.testing.expectEqualStrings("report me", reportable[0].value);

    // Reporting it does not stop the flag after it from being read.
    try std.testing.expect(parsed.supportsForwardTsn());
}

test "zix sctp: init read, an unknown parameter from the stop range hides what follows it" {
    var buf: [128]u8 = undefined;
    var builder = try Builder.begin(&buf, sample_fixed);
    try builder.addParameter(@enumFromInt(0x0004), "stop");
    try builder.addStateCookie("never used");

    const parsed = try read(builder.chunkValue());

    try std.testing.expect(parsed.stateCookie() == null);
}

test "zix sctp: init read, a body shorter than the fixed fields errors" {
    const short: [15]u8 = @splat(0);

    try std.testing.expectError(error.ZixTruncated, read(&short));
}

test "zix sctp: init read, a zero initiate tag errors" {
    var buf: [64]u8 = undefined;
    const builder = try Builder.begin(&buf, sample_fixed);
    const body = buf[0..builder.len];
    std.mem.writeInt(u32, body[0..4], 0, .big);

    try std.testing.expectError(error.ZixZeroInitiateTag, read(body));
}

test "zix sctp: init read, a receive window under 1500 errors" {
    var buf: [64]u8 = undefined;
    const builder = try Builder.begin(&buf, sample_fixed);
    const body = buf[0..builder.len];
    std.mem.writeInt(u32, body[4..8], 1499, .big);

    try std.testing.expectError(error.ZixSmallWindow, read(body));
}

test "zix sctp: init read, a window of exactly 1500 is accepted" {
    var buf: [64]u8 = undefined;
    var fixed = sample_fixed;
    fixed.advertised_rwnd = MIN_ADVERTISED_RWND;

    const builder = try Builder.begin(&buf, fixed);
    const parsed = try read(builder.chunkValue());

    try std.testing.expectEqual(MIN_ADVERTISED_RWND, parsed.fixed.advertised_rwnd);
}

test "zix sctp: init read, a zero stream count errors on either side" {
    var buf: [64]u8 = undefined;
    const builder = try Builder.begin(&buf, sample_fixed);
    const body = buf[0..builder.len];

    std.mem.writeInt(u16, body[8..10], 0, .big);
    try std.testing.expectError(error.ZixZeroStreams, read(body));

    std.mem.writeInt(u16, body[8..10], 128, .big);
    std.mem.writeInt(u16, body[10..12], 0, .big);
    try std.testing.expectError(error.ZixZeroStreams, read(body));
}

test "zix sctp: init build, the same rules are checked before writing" {
    var buf: [64]u8 = undefined;
    var fixed = sample_fixed;

    fixed.initiate_tag = 0;
    try std.testing.expectError(error.ZixZeroInitiateTag, Builder.begin(&buf, fixed));

    fixed = sample_fixed;
    fixed.advertised_rwnd = 1000;
    try std.testing.expectError(error.ZixSmallWindow, Builder.begin(&buf, fixed));

    fixed = sample_fixed;
    fixed.outbound_streams = 0;
    try std.testing.expectError(error.ZixZeroStreams, Builder.begin(&buf, fixed));
}

test "zix sctp: init build, a buffer too small for the fixed fields errors" {
    var buf: [15]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, Builder.begin(&buf, sample_fixed));
}

test "zix sctp: init build, a parameter that does not fit errors and leaves the body usable" {
    var buf: [24]u8 = undefined;
    var builder = try Builder.begin(&buf, sample_fixed);

    try std.testing.expectError(error.ZixNoSpace, builder.addStateCookie("this cookie is far too long"));

    const parsed = try read(builder.chunkValue());
    try std.testing.expectEqual(sample_fixed.initiate_tag, parsed.fixed.initiate_tag);
}

test "zix sctp: init read, a parameter running past the body errors" {
    var buf: [24]u8 = undefined;
    var builder = try Builder.begin(&buf, sample_fixed);
    try builder.addForwardTsnSupported();

    const body = buf[0..builder.len];
    std.mem.writeInt(u16, body[FIXED_LEN + 2 ..][0..2], 40, .big);

    try std.testing.expectError(error.ZixTruncated, read(body));
}
