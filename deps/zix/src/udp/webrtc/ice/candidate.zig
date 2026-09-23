//! zix ICE candidate model (RFC 8445 4.1.1 / 5.1.1 / 5.1.2).
//!
//! What:
//! - A candidate is one transport address a peer can be reached at, together with how it was
//!   learned and how much the peer wants it used. ICE pairs the candidates from both sides,
//!   orders the pairs by priority, and checks them.
//! - Holds the priority formula, the type preferences, and the foundation, which are the three
//!   things every candidate needs before it can be published or paired.
//!
//! Note:
//! - An ice-lite agent has host candidates and nothing else (RFC 8445 4.2). It sits on an address
//!   it already knows, so there is nothing to gather: no STUN server to ask, no relay to
//!   allocate, and no reflexive address to discover.
//! - The text form, the `a=candidate` line, is not here. It is written by the session description
//!   alongside every other address in the offer, and that is where the address formatting
//!   belongs.
//! - The base of a candidate is the local address packets actually leave from. For a host
//!   candidate the base is the candidate itself, which is why `host` sets both.

const std = @import("std");

const IpAddress = std.Io.net.IpAddress;

/// Highest type preference RFC 8445 5.1.2.2 allows. The field is 8 bits but 127 is reserved.
pub const MAX_TYPE_PREFERENCE: u8 = 126;

/// Local preference to use when a peer has exactly one address to offer (RFC 8445 5.1.2.1).
pub const SINGLE_ADDRESS_PREFERENCE: u16 = 65535;

/// Longest foundation string RFC 8445 15.1 allows.
pub const MAX_FOUNDATION_LEN: usize = 32;

/// How a candidate was learned, which is what its type preference is drawn from.
pub const Type = enum {
    /// An address the peer holds directly on one of its own interfaces.
    HOST,
    /// An address a STUN server reported back, seen through a NAT.
    SERVER_REFLEXIVE,
    /// An address learned from a connectivity check arriving from an unexpected source.
    PEER_REFLEXIVE,
    /// An address allocated on a TURN relay.
    RELAYED,

    /// Recommended type preference (RFC 8445 5.1.2.2), highest for the paths with the fewest
    /// hops. Direct beats reflexive, and anything beats a relay.
    pub fn preference(self: Type) u8 {
        return switch (self) {
            .HOST => 126,
            .PEER_REFLEXIVE => 110,
            .SERVER_REFLEXIVE => 100,
            .RELAYED => 0,
        };
    }
};

/// Transport a candidate runs over. WebRTC data channels and media are UDP, TCP candidates exist
/// for the cases where UDP is blocked outright (RFC 6544).
pub const Transport = enum { UDP, TCP };

/// Which stream of a media description a candidate serves (RFC 8445 4.1.1.1). A data channel and
/// a media stream with RTP and RTCP multiplexed both use component 1 alone.
pub const Component = enum(u8) {
    RTP = 1,
    RTCP = 2,
};

/// One transport address a peer offers.
pub const Candidate = struct {
    kind: Type,
    transport: Transport,
    component: Component,
    /// The address a peer sends to.
    address: IpAddress,
    /// The local address packets leave from, equal to address for a host candidate.
    base: IpAddress,
    /// The address this one was derived from, for a reflexive or relayed candidate. Diagnostic
    /// only, ICE never sends to it.
    related: ?IpAddress = null,
    priority: u32,

    /// Build a host candidate, the only kind an ice-lite agent has.
    ///
    /// Param:
    /// address - std.Io.net.IpAddress (the address the peer is reachable at)
    /// component - Component
    /// local_preference - u16 (which of this peer's own addresses to prefer, use
    ///                    SINGLE_ADDRESS_PREFERENCE when there is only one)
    ///
    /// Return:
    /// - Candidate
    pub fn host(address: IpAddress, component: Component, local_preference: u16) Candidate {
        return .{
            .kind = .HOST,
            .transport = .UDP,
            .component = component,
            .address = address,
            .base = address,
            .priority = priorityOf(.HOST, local_preference, component),
        };
    }

    /// Whether two candidates would share a foundation: same type, same base address, same
    /// transport (RFC 8445 5.1.1.3).
    ///
    /// Note:
    /// - The base address is compared without its port, because two candidates on the same
    ///   interface are the same path however many ports they use.
    pub fn sharesFoundation(self: Candidate, other: Candidate) bool {
        if (self.kind != other.kind) return false;
        if (self.transport != other.transport) return false;

        return sameHost(self.base, other.base);
    }
};

/// Candidate priority (RFC 8445 5.1.2.1).
///
/// Note:
/// - The formula is `(2^24) * type preference + (2^8) * local preference + (256 - component)`,
///   which packs the three into one 32-bit number that sorts the way ICE wants: type dominates,
///   then the peer's own preference between its addresses, then the component.
/// - Both peers compute pair priorities from these, so a candidate whose priority is computed
///   differently on each side makes the two check orders disagree.
///
/// Param:
/// kind - Type
/// local_preference - u16
/// component - Component
///
/// Return:
/// - u32
pub fn priorityOf(kind: Type, local_preference: u16, component: Component) u32 {
    const type_part: u32 = @as(u32, kind.preference()) << 24;
    const local_part: u32 = @as(u32, local_preference) << 8;
    // Widened first: the component id is a u8, and 256 does not fit one.
    const component_part: u32 = 256 - @as(u32, @intFromEnum(component));

    return type_part + local_part + component_part;
}

/// Write a candidate's foundation (RFC 8445 5.1.1.3).
///
/// Note:
/// - The foundation is an opaque identifier, not a value with meaning. All ICE asks is that two
///   candidates share it when they have the same type, base address, and transport, and differ
///   otherwise. A hash over exactly those three fields satisfies that by construction.
/// - The STUN or TURN server a candidate came from is part of the rule in RFC 8445, and is left
///   out here because an ice-lite agent has host candidates only, which never have one.
///
/// Param:
/// out - []u8 (destination, MAX_FOUNDATION_LEN is always enough)
/// candidate - Candidate
///
/// Return:
/// - []const u8 (the foundation, borrowing out)
/// - error.ZixNoSpace when out is too small
pub fn writeFoundation(out: []u8, candidate: Candidate) error{ZixNoSpace}![]const u8 {
    var hash = std.hash.Fnv1a_32.init();
    hash.update(&.{@intFromEnum(candidate.kind)});
    hash.update(&.{@intFromEnum(candidate.transport)});

    switch (candidate.base) {
        .ip4 => |addr| {
            hash.update(&.{1});
            hash.update(&addr.bytes);
        },
        .ip6 => |addr| {
            hash.update(&.{2});
            hash.update(&addr.bytes);
        },
    }

    var digits: [10]u8 = undefined;
    const text = std.fmt.bufPrint(&digits, "{d}", .{hash.final()}) catch unreachable;

    if (text.len > out.len) return error.ZixNoSpace;

    @memcpy(out[0..text.len], text);

    return out[0..text.len];
}

/// Whether two addresses name the same host, ignoring the port.
fn sameHost(left: IpAddress, right: IpAddress) bool {
    return switch (left) {
        .ip4 => |addr| switch (right) {
            .ip4 => |other| std.mem.eql(u8, &addr.bytes, &other.bytes),
            .ip6 => false,
        },
        .ip6 => |addr| switch (right) {
            .ip4 => false,
            .ip6 => |other| std.mem.eql(u8, &addr.bytes, &other.bytes),
        },
    };
}

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

const TEST_ADDRESS: IpAddress = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 8998 } };

test "zix ice: candidate priority, the RFC 8445 formula for a single-address host" {
    const priority = priorityOf(.HOST, SINGLE_ADDRESS_PREFERENCE, .RTP);

    // (2^24 * 126) + (2^8 * 65535) + (256 - 1)
    try std.testing.expectEqual(@as(u32, 2113929216 + 16776960 + 255), priority);
    try std.testing.expectEqual(@as(u32, 2130706431), priority);
}

test "zix ice: candidate priority, type dominates local preference dominates component" {
    const host_lowest = priorityOf(.HOST, 0, .RTCP);
    const reflexive_highest = priorityOf(.SERVER_REFLEXIVE, SINGLE_ADDRESS_PREFERENCE, .RTP);
    try std.testing.expect(host_lowest > reflexive_highest);

    const preferred_address = priorityOf(.HOST, 100, .RTCP);
    const other_address = priorityOf(.HOST, 99, .RTP);
    try std.testing.expect(preferred_address > other_address);

    // Component is the last tiebreak, so RTP edges out RTCP on an otherwise identical candidate.
    try std.testing.expect(priorityOf(.HOST, 100, .RTP) > priorityOf(.HOST, 100, .RTCP));
}

test "zix ice: candidate priority, the highest possible value still fits 32 bits" {
    const highest = priorityOf(.HOST, SINGLE_ADDRESS_PREFERENCE, .RTP);
    try std.testing.expect(highest < std.math.maxInt(u32));

    // A relayed candidate loses the whole top byte, which is the point of the type preference.
    try std.testing.expect(priorityOf(.RELAYED, SINGLE_ADDRESS_PREFERENCE, .RTP) < (1 << 24));
}

test "zix ice: candidate type, the recommended preferences are ordered by directness" {
    try std.testing.expectEqual(@as(u8, 126), Type.HOST.preference());
    try std.testing.expectEqual(@as(u8, 110), Type.PEER_REFLEXIVE.preference());
    try std.testing.expectEqual(@as(u8, 100), Type.SERVER_REFLEXIVE.preference());
    try std.testing.expectEqual(@as(u8, 0), Type.RELAYED.preference());

    try std.testing.expect(Type.HOST.preference() <= MAX_TYPE_PREFERENCE);
}

test "zix ice: candidate host, the base is the candidate itself" {
    const candidate = Candidate.host(TEST_ADDRESS, .RTP, SINGLE_ADDRESS_PREFERENCE);

    try std.testing.expectEqual(Type.HOST, candidate.kind);
    try std.testing.expectEqual(Transport.UDP, candidate.transport);
    try std.testing.expectEqual(Component.RTP, candidate.component);
    try std.testing.expectEqual(@as(?IpAddress, null), candidate.related);
    try std.testing.expectEqualSlices(u8, &TEST_ADDRESS.ip4.bytes, &candidate.base.ip4.bytes);
    try std.testing.expectEqual(TEST_ADDRESS.ip4.port, candidate.base.ip4.port);
    try std.testing.expectEqual(priorityOf(.HOST, SINGLE_ADDRESS_PREFERENCE, .RTP), candidate.priority);
}

test "zix ice: candidate foundation, same type base and transport share it" {
    const first = Candidate.host(TEST_ADDRESS, .RTP, SINGLE_ADDRESS_PREFERENCE);

    // Same interface, another port: same path, so the same foundation.
    var second = first;
    second.address = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 9099 } };
    second.base = second.address;

    var first_buf: [MAX_FOUNDATION_LEN]u8 = undefined;
    var second_buf: [MAX_FOUNDATION_LEN]u8 = undefined;

    try std.testing.expect(first.sharesFoundation(second));
    try std.testing.expectEqualStrings(
        try writeFoundation(&first_buf, first),
        try writeFoundation(&second_buf, second),
    );
}

test "zix ice: candidate foundation, a different type base or transport separates it" {
    const base = Candidate.host(TEST_ADDRESS, .RTP, SINGLE_ADDRESS_PREFERENCE);

    var other_type = base;
    other_type.kind = .SERVER_REFLEXIVE;

    var other_transport = base;
    other_transport.transport = .TCP;

    var other_base = base;
    other_base.base = .{ .ip4 = .{ .bytes = .{ 198, 51, 100, 7 }, .port = 8998 } };

    var other_family = base;
    other_family.base = .{ .ip6 = .{ .bytes = @splat(0), .port = 8998 } };

    var left: [MAX_FOUNDATION_LEN]u8 = undefined;
    var right: [MAX_FOUNDATION_LEN]u8 = undefined;
    const reference = try writeFoundation(&left, base);

    for ([_]Candidate{ other_type, other_transport, other_base, other_family }) |candidate| {
        try std.testing.expect(!base.sharesFoundation(candidate));
        try std.testing.expect(!std.mem.eql(u8, reference, try writeFoundation(&right, candidate)));
    }
}

test "zix ice: candidate foundation, the value is ice-chars and fits the published cap" {
    const candidate = Candidate.host(TEST_ADDRESS, .RTP, SINGLE_ADDRESS_PREFERENCE);

    var buf: [MAX_FOUNDATION_LEN]u8 = undefined;
    const foundation = try writeFoundation(&buf, candidate);

    try std.testing.expect(foundation.len > 0);
    try std.testing.expect(foundation.len <= MAX_FOUNDATION_LEN);

    for (foundation) |char| try std.testing.expect(char >= '0' and char <= '9');

    var too_small: [MAX_FOUNDATION_LEN]u8 = undefined;
    try std.testing.expectError(error.ZixNoSpace, writeFoundation(too_small[0 .. foundation.len - 1], candidate));
}
