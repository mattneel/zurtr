//! zix SDP candidate attribute (RFC 8839 5.1).
//!
//! What:
//! - The `a=candidate` attribute: the text form of one transport address a peer can be reached
//!   at, and the reverse.
//!
//! Note:
//! - The transport is written "UDP", which is what the RFC 8839 5.1 grammar spells, and read
//!   without case, because the RFC 8829 examples and several browsers write "udp". Refusing one
//!   spelling would drop candidates that are otherwise fine.
//! - A candidate whose address is a host name is refused. RFC 8839 5.1 says an agent must ignore
//!   those, and nothing here resolves names, so reading one and doing nothing with it would only
//!   move the problem.
//! - Only the fields up to the type are read. The related address, the related port, and any
//!   extension are diagnostic (RFC 8839 5.1), and an ice-lite agent never sends to them.
//! - The priority is computed by the side that owns the candidate and carried as it stands. Both
//!   peers order their checks by these numbers, so recomputing one on the way in would make the
//!   two orders disagree.

const std = @import("std");

const ice = @import("../ice/candidate.zig");
const address = @import("address.zig");

const IpAddress = std.Io.net.IpAddress;

/// The attribute name this lives under.
pub const ATTRIBUTE: []const u8 = "candidate";

/// The attribute that says no more candidates are coming (RFC 8838 8).
pub const END_OF_CANDIDATES: []const u8 = "end-of-candidates";

/// The longest attribute value this writes.
pub const MAX_VALUE_LEN: usize = ice.MAX_FOUNDATION_LEN + 1 + 3 + 1 + 3 + 1 + 10 + 1 +
    address.MAX_ADDRESS_LEN + 1 + 5 + 1 + 3 + 1 + 5;

/// Everything that stops a candidate from being read or written.
pub const Error = error{
    /// Fewer fields than a candidate needs, or one that is not a number.
    ZixMalformed,
    /// A transport, address form, or candidate type this endpoint does not use.
    ZixUnsupported,
    /// The output buffer is too small.
    ZixNoSpace,
};

/// One candidate as it was written, borrowed from the description it came from.
pub const Parsed = struct {
    foundation: []const u8,
    component: ice.Component,
    transport: ice.Transport,
    priority: u32,
    /// The address text, which is an IP address and never a host name.
    address: []const u8,
    port: u16,
    kind: ice.Type,
};

/// Read an `a=candidate` attribute value.
///
/// Param:
/// value - []const u8 (everything after `candidate:`)
///
/// Return:
/// - Parsed borrowing `value`
/// - error.ZixMalformed if a field is missing or is not a number
/// - error.ZixUnsupported for a transport, component, or type this endpoint does not use
pub fn read(value: []const u8) Error!Parsed {
    var fields = std.mem.tokenizeScalar(u8, value, ' ');

    const foundation = fields.next() orelse return error.ZixMalformed;
    const component_field = fields.next() orelse return error.ZixMalformed;
    const transport_field = fields.next() orelse return error.ZixMalformed;
    const priority_field = fields.next() orelse return error.ZixMalformed;
    const host = fields.next() orelse return error.ZixMalformed;
    const port_field = fields.next() orelse return error.ZixMalformed;
    const typ = fields.next() orelse return error.ZixMalformed;
    const kind_field = fields.next() orelse return error.ZixMalformed;

    if (!std.mem.eql(u8, typ, "typ")) return error.ZixMalformed;
    if (foundation.len == 0 or foundation.len > ice.MAX_FOUNDATION_LEN) return error.ZixMalformed;
    if (!isAddress(host)) return error.ZixUnsupported;

    return .{
        .foundation = foundation,
        .component = try componentFor(component_field),
        .transport = try transportFor(transport_field),
        .priority = std.fmt.parseInt(u32, priority_field, 10) catch return error.ZixMalformed,
        .address = host,
        .port = std.fmt.parseInt(u16, port_field, 10) catch return error.ZixMalformed,
        .kind = try typeFor(kind_field),
    };
}

/// Write an `a=candidate` attribute value for one of this endpoint's own candidates.
///
/// Note:
/// - The foundation is computed here rather than taken, because it is a function of the
///   candidate and two candidates that share one must produce the same text.
///
/// Param:
/// out - []u8 (at least MAX_VALUE_LEN)
/// entry - ice.Candidate
///
/// Return:
/// - []const u8, the value alone, with no attribute name
/// - error.ZixNoSpace
pub fn write(out: []u8, entry: ice.Candidate) Error![]const u8 {
    var foundation: [ice.MAX_FOUNDATION_LEN]u8 = undefined;
    const foundation_text = ice.writeFoundation(&foundation, entry) catch return error.ZixNoSpace;

    var host: [address.MAX_ADDRESS_LEN]u8 = undefined;
    const host_text = address.writeAddress(&host, entry.address) catch return error.ZixNoSpace;

    var at: usize = 0;
    at += try put(out[at..], foundation_text);
    at += try put(out[at..], " ");
    at += try putNumber(out[at..], @intFromEnum(entry.component));
    at += try put(out[at..], " ");
    at += try put(out[at..], transportName(entry.transport));
    at += try put(out[at..], " ");
    at += try putNumber(out[at..], entry.priority);
    at += try put(out[at..], " ");
    at += try put(out[at..], host_text);
    at += try put(out[at..], " ");
    at += try putNumber(out[at..], address.portOf(entry.address));
    at += try put(out[at..], " typ ");
    at += try put(out[at..], typeName(entry.kind));

    return out[0..at];
}

/// The transport as it goes out.
///
/// Param:
/// transport - ice.Transport
///
/// Return:
/// - []const u8
pub fn transportName(transport: ice.Transport) []const u8 {
    return switch (transport) {
        .UDP => "UDP",
        .TCP => "TCP",
    };
}

/// The candidate type as it goes out.
///
/// Param:
/// kind - ice.Type
///
/// Return:
/// - []const u8
pub fn typeName(kind: ice.Type) []const u8 {
    return switch (kind) {
        .HOST => "host",
        .SERVER_REFLEXIVE => "srflx",
        .PEER_REFLEXIVE => "prflx",
        .RELAYED => "relay",
    };
}

/// Whether the text is an IP address rather than a host name.
fn isAddress(text: []const u8) bool {
    if (text.len == 0) return false;
    // A colon means IPv6, which RFC 8839 5.1 says to tell apart exactly this way.
    if (std.mem.indexOfScalar(u8, text, ':') != null) return true;

    for (text) |character| {
        if (character == '.') continue;
        if (character >= '0' and character <= '9') continue;

        return false;
    }

    return true;
}

/// The component a number stands for.
fn componentFor(text: []const u8) Error!ice.Component {
    const number = std.fmt.parseInt(u16, text, 10) catch return error.ZixMalformed;

    return switch (number) {
        1 => .RTP,
        2 => .RTCP,
        else => error.ZixUnsupported,
    };
}

/// The transport a name stands for, whatever case it came in.
fn transportFor(text: []const u8) Error!ice.Transport {
    if (std.ascii.eqlIgnoreCase(text, "udp")) return .UDP;
    if (std.ascii.eqlIgnoreCase(text, "tcp")) return .TCP;

    return error.ZixUnsupported;
}

/// The candidate type a name stands for.
fn typeFor(text: []const u8) Error!ice.Type {
    if (std.mem.eql(u8, text, "host")) return .HOST;
    if (std.mem.eql(u8, text, "srflx")) return .SERVER_REFLEXIVE;
    if (std.mem.eql(u8, text, "prflx")) return .PEER_REFLEXIVE;
    if (std.mem.eql(u8, text, "relay")) return .RELAYED;

    return error.ZixUnsupported;
}

/// Copy text into a buffer, checking there is room.
fn put(out: []u8, text: []const u8) Error!usize {
    if (out.len < text.len) return error.ZixNoSpace;

    @memcpy(out[0..text.len], text);

    return text.len;
}

/// Write an unsigned number in base ten.
fn putNumber(out: []u8, value: u32) Error!usize {
    var digits: [10]u8 = undefined;
    var count: usize = 0;
    var left = value;

    while (true) {
        digits[count] = '0' + @as(u8, @intCast(left % 10));
        count += 1;
        left /= 10;

        if (left == 0) break;
    }

    if (out.len < count) return error.ZixNoSpace;

    for (0..count) |index| out[index] = digits[count - 1 - index];

    return count;
}

// --------------------------------------------------------------------------------------- //
// test cases

const sample: []const u8 = "1 1 udp 2113929471 203.0.113.200 10200 typ host";

test "zix sdp: candidate read, the JSEP sample reads field for field" {
    const parsed = try read(sample);

    try std.testing.expectEqualStrings("1", parsed.foundation);
    try std.testing.expectEqual(ice.Component.RTP, parsed.component);
    try std.testing.expectEqual(ice.Transport.UDP, parsed.transport);
    try std.testing.expectEqual(@as(u32, 2113929471), parsed.priority);
    try std.testing.expectEqualStrings("203.0.113.200", parsed.address);
    try std.testing.expectEqual(@as(u16, 10200), parsed.port);
    try std.testing.expectEqual(ice.Type.HOST, parsed.kind);
}

test "zix sdp: candidate read, the transport is taken in either case" {
    // RFC 8839 5.1 spells it upper case and the RFC 8829 examples spell it lower, so both are
    // already on the wire.
    try std.testing.expectEqual(ice.Transport.UDP, (try read("1 1 UDP 100 192.0.2.1 9 typ host")).transport);
    try std.testing.expectEqual(ice.Transport.UDP, (try read("1 1 udp 100 192.0.2.1 9 typ host")).transport);
}

test "zix sdp: candidate read, an IPv6 address is taken" {
    const parsed = try read("1 1 UDP 100 2001:db8::a8fd 9 typ host");

    try std.testing.expectEqualStrings("2001:db8::a8fd", parsed.address);
}

test "zix sdp: candidate read, the trailing fields of a reflexive candidate are passed over" {
    const parsed = try read("2 1 UDP 1694498815 192.0.2.3 45664 typ srflx raddr 203.0.113.141 rport 8998");

    try std.testing.expectEqual(ice.Type.SERVER_REFLEXIVE, parsed.kind);
    try std.testing.expectEqualStrings("192.0.2.3", parsed.address);
    try std.testing.expectEqual(@as(u16, 45664), parsed.port);
}

test "zix sdp: candidate read, a missing field is refused" {
    try std.testing.expectError(error.ZixMalformed, read("1 1 UDP 100 192.0.2.1 9 typ"));
    try std.testing.expectError(error.ZixMalformed, read("1 1 UDP 100 192.0.2.1 9"));
    try std.testing.expectError(error.ZixMalformed, read(""));
}

test "zix sdp: candidate read, a missing typ keyword is refused" {
    try std.testing.expectError(error.ZixMalformed, read("1 1 UDP 100 192.0.2.1 9 xyz host"));
}

test "zix sdp: candidate read, a host name is refused" {
    // RFC 8839 5.1 says to ignore these, and nothing here resolves a name.
    try std.testing.expectError(error.ZixUnsupported, read("1 1 UDP 100 host.example.com 9 typ host"));
}

test "zix sdp: candidate read, an unknown transport is refused" {
    try std.testing.expectError(error.ZixUnsupported, read("1 1 SCTP 100 192.0.2.1 9 typ host"));
}

test "zix sdp: candidate read, an unknown candidate type is refused" {
    try std.testing.expectError(error.ZixUnsupported, read("1 1 UDP 100 192.0.2.1 9 typ other"));
}

test "zix sdp: candidate read, a component outside the two is refused" {
    try std.testing.expectError(error.ZixUnsupported, read("1 3 UDP 100 192.0.2.1 9 typ host"));
}

test "zix sdp: candidate read, a priority that is not a number is refused" {
    try std.testing.expectError(error.ZixMalformed, read("1 1 UDP high 192.0.2.1 9 typ host"));
}

test "zix sdp: candidate read, a foundation longer than the field allows is refused" {
    const long = "1234567890123456789012345678901234567890";

    try std.testing.expectError(error.ZixMalformed, read(long ++ " 1 UDP 100 192.0.2.1 9 typ host"));
}

test "zix sdp: candidate write, a host candidate comes out in RFC 8839 order" {
    const entry = ice.Candidate.host(
        .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 200 }, .port = 10200 } },
        .RTP,
        ice.SINGLE_ADDRESS_PREFERENCE,
    );

    var buf: [MAX_VALUE_LEN]u8 = undefined;
    const written = try write(&buf, entry);
    const parsed = try read(written);

    try std.testing.expectEqual(ice.Transport.UDP, parsed.transport);
    try std.testing.expectEqual(ice.Type.HOST, parsed.kind);
    try std.testing.expectEqualStrings("203.0.113.200", parsed.address);
    try std.testing.expectEqual(@as(u16, 10200), parsed.port);
    try std.testing.expectEqual(entry.priority, parsed.priority);
}

test "zix sdp: candidate write, an IPv6 candidate comes out compressed" {
    var bytes: [16]u8 = @splat(0);
    bytes[0] = 0x20;
    bytes[1] = 0x01;
    bytes[15] = 0x01;

    const entry = ice.Candidate.host(
        .{ .ip6 = .{ .bytes = bytes, .port = 9091 } },
        .RTP,
        ice.SINGLE_ADDRESS_PREFERENCE,
    );

    var buf: [MAX_VALUE_LEN]u8 = undefined;
    const written = try write(&buf, entry);

    try std.testing.expect(std.mem.indexOf(u8, written, "2001::1 9091 typ host") != null);
}

test "zix sdp: candidate write, the transport goes out upper case" {
    const entry = ice.Candidate.host(
        .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9 } },
        .RTP,
        ice.SINGLE_ADDRESS_PREFERENCE,
    );

    var buf: [MAX_VALUE_LEN]u8 = undefined;

    try std.testing.expect(std.mem.indexOf(u8, try write(&buf, entry), " UDP ") != null);
}

test "zix sdp: candidate write, a short buffer errors" {
    const entry = ice.Candidate.host(
        .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9 } },
        .RTP,
        ice.SINGLE_ADDRESS_PREFERENCE,
    );

    var buf: [8]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, write(&buf, entry));
}

test "zix sdp: candidate write, the component number is the one ICE assigns" {
    const entry = ice.Candidate.host(
        .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9 } },
        .RTCP,
        ice.SINGLE_ADDRESS_PREFERENCE,
    );

    var buf: [MAX_VALUE_LEN]u8 = undefined;
    const parsed = try read(try write(&buf, entry));

    try std.testing.expectEqual(ice.Component.RTCP, parsed.component);
}

test "zix sdp: candidate, two candidates on one address share a foundation text" {
    const first = ice.Candidate.host(
        .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9 } },
        .RTP,
        ice.SINGLE_ADDRESS_PREFERENCE,
    );
    const second = ice.Candidate.host(
        .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 5000 } },
        .RTCP,
        ice.SINGLE_ADDRESS_PREFERENCE,
    );

    var first_buf: [MAX_VALUE_LEN]u8 = undefined;
    var second_buf: [MAX_VALUE_LEN]u8 = undefined;

    const first_parsed = try read(try write(&first_buf, first));
    const second_parsed = try read(try write(&second_buf, second));

    try std.testing.expect(first.sharesFoundation(second));
    try std.testing.expectEqualStrings(first_parsed.foundation, second_parsed.foundation);
}
