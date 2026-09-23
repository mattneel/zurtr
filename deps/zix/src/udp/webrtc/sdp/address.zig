//! zix SDP address text form (RFC 8866 5.7, RFC 5952).
//!
//! What:
//! - How an address is spelled in a session description, which is a network type, an address
//!   type, and the address itself, and the reverse.
//!
//! Note:
//! - Only "IN" exists as a network type in practice, and only IP4 and IP6 as address types. A
//!   description naming anything else is for a network this endpoint cannot reach, so it is
//!   refused rather than carried around unread.
//! - IPv6 is written the RFC 5952 way: lower-case hex, no leading zeros in a group, and the
//!   longest run of zero groups collapsed to "::". Two spellings of one address are the same
//!   address, and a peer comparing them as text sees two.
//! - A "c=" line address can also be a host name, which nothing here resolves. ICE forbids an
//!   agent from putting a name in its own candidates (RFC 8839 5.1), and the connection address
//!   in a WebRTC description is never the one traffic goes to, so the text is handed back as it
//!   stands and the reader decides.

const std = @import("std");

const IpAddress = std.Io.net.IpAddress;

/// The only network type a session description uses.
pub const NET_TYPE: []const u8 = "IN";

/// Longest address text this writes, which is a full IPv6 address with no compression.
pub const MAX_ADDRESS_LEN: usize = 45;

/// Longest "c=" line value this writes.
pub const MAX_CONNECTION_LEN: usize = NET_TYPE.len + 1 + 3 + 1 + MAX_ADDRESS_LEN;

/// The address a peer sets when it has nothing to offer yet (RFC 8839 4.3.1).
pub const UNSPECIFIED_IP4: []const u8 = "0.0.0.0";

/// The IPv6 form of the same.
pub const UNSPECIFIED_IP6: []const u8 = "::";

/// Everything that stops an address from being read or written.
pub const Error = error{
    /// A connection line without all three of its fields.
    ZixMalformed,
    /// A network type or address type this endpoint does not use.
    ZixUnsupported,
    /// The output buffer is too small.
    ZixNoSpace,
};

/// Which kind of address is being spelled.
pub const Family = enum {
    IP4,
    IP6,

    /// The address type as it appears in a description.
    ///
    /// Return:
    /// - []const u8
    pub fn name(self: Family) []const u8 {
        return switch (self) {
            .IP4 => "IP4",
            .IP6 => "IP6",
        };
    }
};

/// One "c=" line, borrowed from the description it came from.
pub const Connection = struct {
    family: Family,
    /// The address text, which may be a host name.
    address: []const u8,
};

/// Which family an address belongs to.
///
/// Param:
/// address - IpAddress
///
/// Return:
/// - Family
pub fn familyOf(address: IpAddress) Family {
    return switch (address) {
        .ip4 => .IP4,
        .ip6 => .IP6,
    };
}

/// Read a "c=" line value.
///
/// Param:
/// value - []const u8 (everything after `c=`, such as "IN IP4 192.0.2.3")
///
/// Return:
/// - Connection borrowing `value`
/// - error.ZixMalformed if any of the three fields is missing
/// - error.ZixUnsupported for a network or address type this endpoint does not use
pub fn readConnection(value: []const u8) Error!Connection {
    var fields = std.mem.tokenizeScalar(u8, value, ' ');

    const net_type = fields.next() orelse return error.ZixMalformed;
    const addr_type = fields.next() orelse return error.ZixMalformed;
    const address = fields.next() orelse return error.ZixMalformed;

    if (!std.mem.eql(u8, net_type, NET_TYPE)) return error.ZixUnsupported;

    const family: Family = if (std.mem.eql(u8, addr_type, "IP4"))
        .IP4
    else if (std.mem.eql(u8, addr_type, "IP6"))
        .IP6
    else
        return error.ZixUnsupported;

    return .{ .family = family, .address = address };
}

/// Write a "c=" line value.
///
/// Param:
/// out - []u8 (buffer to write into, from its start, at least MAX_CONNECTION_LEN)
/// family - Family
/// address - []const u8 (already in its text form)
///
/// Return:
/// - []const u8, the value alone, with no line type and no terminator
/// - error.ZixNoSpace
pub fn writeConnection(out: []u8, family: Family, address: []const u8) Error![]const u8 {
    const total = NET_TYPE.len + 1 + family.name().len + 1 + address.len;

    if (out.len < total) return error.ZixNoSpace;

    var at: usize = 0;
    at += copy(out[at..], NET_TYPE);
    out[at] = ' ';
    at += 1;
    at += copy(out[at..], family.name());
    out[at] = ' ';
    at += 1;
    at += copy(out[at..], address);

    return out[0..total];
}

/// Write the text form of an address, without its port.
///
/// Param:
/// out - []u8 (at least MAX_ADDRESS_LEN)
/// address - IpAddress
///
/// Return:
/// - []const u8
/// - error.ZixNoSpace
pub fn writeAddress(out: []u8, address: IpAddress) Error![]const u8 {
    return switch (address) {
        .ip4 => |addr| writeIp4(out, addr.bytes),
        .ip6 => |addr| writeIp6(out, addr.bytes),
    };
}

/// The port an address carries.
///
/// Param:
/// address - IpAddress
///
/// Return:
/// - u16
pub fn portOf(address: IpAddress) u16 {
    return switch (address) {
        .ip4 => |addr| addr.port,
        .ip6 => |addr| addr.port,
    };
}

/// Write a dotted-quad address.
fn writeIp4(out: []u8, bytes: [4]u8) Error![]const u8 {
    var at: usize = 0;

    for (bytes, 0..) |byte, index| {
        if (index != 0) {
            if (at >= out.len) return error.ZixNoSpace;

            out[at] = '.';
            at += 1;
        }

        at += try writeDecimal(out[at..], byte);
    }

    return out[0..at];
}

/// Write an address the RFC 5952 way.
fn writeIp6(out: []u8, bytes: [16]u8) Error![]const u8 {
    var groups: [8]u16 = undefined;
    for (&groups, 0..) |*group, index| {
        group.* = std.mem.readInt(u16, bytes[index * 2 ..][0..2], .big);
    }

    const run = longestZeroRun(groups);

    var at: usize = 0;
    var index: usize = 0;
    while (index < groups.len) {
        if (run.len >= 2 and index == run.start) {
            // One colon here plus the one the next group writes makes the "::".
            if (at + 1 >= out.len) return error.ZixNoSpace;

            out[at] = ':';
            at += 1;
            if (run.start + run.len == groups.len) {
                out[at] = ':';
                at += 1;
            }

            index += run.len;
            continue;
        }

        // A run starting at zero already wrote the first colon, and the index has moved past it
        // by the time this is reached, so one test covers both cases.
        if (index != 0) {
            if (at >= out.len) return error.ZixNoSpace;

            out[at] = ':';
            at += 1;
        }

        at += try writeHex(out[at..], groups[index]);
        index += 1;
    }

    return out[0..at];
}

/// The longest run of zero groups, which is what "::" stands in for.
fn longestZeroRun(groups: [8]u16) struct { start: usize, len: usize } {
    var best_start: usize = 0;
    var best_len: usize = 0;

    var index: usize = 0;
    while (index < groups.len) {
        if (groups[index] != 0) {
            index += 1;
            continue;
        }

        const start = index;
        while (index < groups.len and groups[index] == 0) index += 1;

        // Strictly longer, so the first of two equal runs is the one taken (RFC 5952 4.2.3).
        if (index - start > best_len) {
            best_start = start;
            best_len = index - start;
        }
    }

    return .{ .start = best_start, .len = best_len };
}

/// Write an unsigned number in base ten.
fn writeDecimal(out: []u8, value: u16) Error!usize {
    var digits: [5]u8 = undefined;
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

/// Write a group in lower-case hex with no leading zeros.
fn writeHex(out: []u8, value: u16) Error!usize {
    const alphabet = "0123456789abcdef";

    var digits: [4]u8 = undefined;
    var count: usize = 0;
    var left = value;

    while (true) {
        digits[count] = alphabet[left & 0x0F];
        count += 1;
        left >>= 4;

        if (left == 0) break;
    }

    if (out.len < count) return error.ZixNoSpace;

    for (0..count) |index| out[index] = digits[count - 1 - index];

    return count;
}

/// Copy into a buffer already known to be long enough.
fn copy(out: []u8, text: []const u8) usize {
    @memcpy(out[0..text.len], text);

    return text.len;
}

// --------------------------------------------------------------------------------------- //
// test cases

/// Build an IPv6 address out of eight groups, for the tests below.
fn ip6(groups: [8]u16) IpAddress {
    var bytes: [16]u8 = undefined;
    for (groups, 0..) |group, index| std.mem.writeInt(u16, bytes[index * 2 ..][0..2], group, .big);

    return .{ .ip6 = .{ .bytes = bytes, .port = 0 } };
}

test "zix sdp: address readConnection, the three fields come back" {
    const parsed = try readConnection("IN IP4 192.0.2.3");

    try std.testing.expectEqual(Family.IP4, parsed.family);
    try std.testing.expectEqualStrings("192.0.2.3", parsed.address);
}

test "zix sdp: address readConnection, IPv6 is read the same way" {
    const parsed = try readConnection("IN IP6 2001:db8::a8fd");

    try std.testing.expectEqual(Family.IP6, parsed.family);
    try std.testing.expectEqualStrings("2001:db8::a8fd", parsed.address);
}

test "zix sdp: address readConnection, a missing field is refused" {
    try std.testing.expectError(error.ZixMalformed, readConnection("IN IP4"));
    try std.testing.expectError(error.ZixMalformed, readConnection("IN"));
    try std.testing.expectError(error.ZixMalformed, readConnection(""));
}

test "zix sdp: address readConnection, another network type is refused" {
    try std.testing.expectError(error.ZixUnsupported, readConnection("XX IP4 192.0.2.3"));
    try std.testing.expectError(error.ZixUnsupported, readConnection("IN IP9 192.0.2.3"));
}

test "zix sdp: address readConnection, a host name is handed back unresolved" {
    const parsed = try readConnection("IN IP4 host.example.com");

    try std.testing.expectEqualStrings("host.example.com", parsed.address);
}

test "zix sdp: address writeConnection, the value is the three fields in order" {
    var buf: [MAX_CONNECTION_LEN]u8 = undefined;

    try std.testing.expectEqualStrings("IN IP4 192.0.2.3", try writeConnection(&buf, .IP4, "192.0.2.3"));
    try std.testing.expectEqualStrings("IN IP6 ::", try writeConnection(&buf, .IP6, "::"));
}

test "zix sdp: address writeConnection, a short buffer errors" {
    var buf: [8]u8 = undefined;

    try std.testing.expectError(error.ZixNoSpace, writeConnection(&buf, .IP4, "192.0.2.3"));
}

test "zix sdp: address writeAddress, a dotted quad" {
    var buf: [MAX_ADDRESS_LEN]u8 = undefined;
    const address: IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9 } };

    try std.testing.expectEqualStrings("192.0.2.1", try writeAddress(&buf, address));
}

test "zix sdp: address writeAddress, every octet width is handled" {
    var buf: [MAX_ADDRESS_LEN]u8 = undefined;
    const address: IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 9, 99, 255 }, .port = 0 } };

    try std.testing.expectEqualStrings("0.9.99.255", try writeAddress(&buf, address));
}

test "zix sdp: address writeAddress, an IPv6 address with no zero run" {
    var buf: [MAX_ADDRESS_LEN]u8 = undefined;
    const address = ip6(.{ 0x2001, 0x0db8, 0x1234, 0x5678, 0x9abc, 0xdef0, 0x0001, 0x0002 });

    try std.testing.expectEqualStrings("2001:db8:1234:5678:9abc:def0:1:2", try writeAddress(&buf, address));
}

test "zix sdp: address writeAddress, the longest zero run collapses" {
    var buf: [MAX_ADDRESS_LEN]u8 = undefined;
    const address = ip6(.{ 0x2001, 0x0db8, 0, 0, 0, 0, 0, 0xa8fd });

    try std.testing.expectEqualStrings("2001:db8::a8fd", try writeAddress(&buf, address));
}

test "zix sdp: address writeAddress, a zero run at the start collapses" {
    var buf: [MAX_ADDRESS_LEN]u8 = undefined;
    const address = ip6(.{ 0, 0, 0, 0, 0, 0, 0, 1 });

    try std.testing.expectEqualStrings("::1", try writeAddress(&buf, address));
}

test "zix sdp: address writeAddress, a zero run at the end collapses" {
    var buf: [MAX_ADDRESS_LEN]u8 = undefined;
    const address = ip6(.{ 0x2001, 0x0db8, 0, 0, 0, 0, 0, 0 });

    try std.testing.expectEqualStrings("2001:db8::", try writeAddress(&buf, address));
}

test "zix sdp: address writeAddress, an all zero address is two colons" {
    var buf: [MAX_ADDRESS_LEN]u8 = undefined;

    try std.testing.expectEqualStrings("::", try writeAddress(&buf, ip6(@splat(0))));
}

test "zix sdp: address writeAddress, a single zero group is written out" {
    var buf: [MAX_ADDRESS_LEN]u8 = undefined;
    const address = ip6(.{ 0x2001, 0, 0x1234, 0x5678, 0x9abc, 0xdef0, 0x0001, 0x0002 });

    // RFC 5952 4.2.2: one zero group is not shortened, because "::" would say nothing about how
    // many groups it stands for.
    try std.testing.expectEqualStrings("2001:0:1234:5678:9abc:def0:1:2", try writeAddress(&buf, address));
}

test "zix sdp: address writeAddress, the first of two equal runs is the one collapsed" {
    var buf: [MAX_ADDRESS_LEN]u8 = undefined;
    const address = ip6(.{ 0x2001, 0, 0, 0x1234, 0x5678, 0, 0, 0x0001 });

    try std.testing.expectEqualStrings("2001::1234:5678:0:0:1", try writeAddress(&buf, address));
}

test "zix sdp: address writeAddress, a short buffer errors" {
    var buf: [4]u8 = undefined;
    const address: IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 0 } };

    try std.testing.expectError(error.ZixNoSpace, writeAddress(&buf, address));
}

test "zix sdp: address familyOf, the union tag decides" {
    const four: IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 0 } };

    try std.testing.expectEqual(Family.IP4, familyOf(four));
    try std.testing.expectEqual(Family.IP6, familyOf(ip6(@splat(0))));
}

test "zix sdp: address portOf, the port comes back whichever family it is" {
    const four: IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9091 } };
    const six = ip6(.{ 0, 0, 0, 0, 0, 0, 0, 1 });

    try std.testing.expectEqual(@as(u16, 9091), portOf(four));
    try std.testing.expectEqual(@as(u16, 0), portOf(six));
}
