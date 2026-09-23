//! zixer cleartext companion: which status moves a request to https, and which authority it names

const std = @import("std");

/// A request that may be repeated by simply following the Location, so the
/// long-standing status is the right one (rfc 9110 15.4.2).
const REPLAYABLE_METHODS = [_][]const u8{ "GET", "HEAD" };

/// Longest authority zixer will put in a Location. Well past any real host
/// name, and short enough that the header cannot be grown from outside.
pub const MAX_AUTHORITY_BYTES: usize = 255;

/// The redirect status for one request method.
///
/// Note:
/// - 301 lets a user agent turn the repeat into a GET, which rfc 9110 15.4.2
///   allows for historical reasons. That is harmless for a GET and wrong for
///   anything else: a POST would arrive at the https origin with no body.
/// - 308 (rfc 9110 15.4.9) is the same permanence with the method and body
///   kept, so every other method takes it.
///
/// Param:
/// method - []const u8 (the request method as sent)
///
/// Return:
/// - 301 for GET and HEAD
/// - 308 for everything else
pub fn statusFor(method: []const u8) u16 {
    for (REPLAYABLE_METHODS) |replayable| {
        if (std.ascii.eqlIgnoreCase(method, replayable)) return 301;
    }

    return 308;
}

/// The reason phrase that goes with statusFor.
pub fn reasonFor(status: u16) []const u8 {
    return if (status == 301) "Moved Permanently" else "Permanent Redirect";
}

/// Whether a value is a bare authority zixer is willing to put in a Location.
///
/// Note:
/// - This is the SEC-4 guard. The Location line is built from a value the
///   client sent, so the check is about what that value can be turned into,
///   not about whether the name resolves. A slash would end the authority and
///   start a path, an at sign would move the real host behind userinfo, and a
///   control character would break the header line.
/// - The accepted shape is a host name or ipv4 literal with an optional port,
///   or a bracketed ipv6 literal with an optional port. Nothing else.
///
/// Param:
/// value - []const u8 (the Host header value, or a configured host)
///
/// Return:
/// - true when the value is safe to name as an origin
pub fn usableAuthority(value: []const u8) bool {
    if (value.len == 0 or value.len > MAX_AUTHORITY_BYTES) return false;

    if (value[0] == '[') return usableBracketed(value);

    var colons: usize = 0;
    for (value) |byte| {
        if (byte == ':') {
            colons += 1;
            continue;
        }

        if (!isHostByte(byte)) return false;
    }
    if (colons > 1) return false;

    return portIsDigits(value);
}

/// The authority to name in the Location line.
///
/// Note:
/// - A site that named its own host is never told otherwise, which is what
///   closes SEC-4 outright: the client's Host stops reaching the reply at all.
/// - A site that named none echoes the client's Host, still the behaviour the
///   acme companion always had, but only once it has passed usableAuthority.
///
/// Param:
/// configured - ?[]const u8 (the site's redirect_host, null when unset)
/// requested - []const u8 (the client's Host header value, may be empty)
///
/// Return:
/// - the authority to use
/// - null when there is none to trust, and the caller owes a local status
pub fn authorityFor(configured: ?[]const u8, requested: []const u8) ?[]const u8 {
    if (configured) |named| return named;
    if (!usableAuthority(requested)) return null;

    return requested;
}

/// The authority with any port removed, in the form a Location origin needs.
///
/// Note:
/// - A bracketed ipv6 literal keeps its brackets. Without them the colons of
///   the address itself read as the port separator, and the Location comes out
///   pointing nowhere.
///
/// Param:
/// authority - []const u8 (already through usableAuthority)
///
/// Return:
/// - []const u8 the host part, a slice of authority
pub fn originHost(authority: []const u8) []const u8 {
    if (authority.len != 0 and authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return authority;

        return authority[0 .. close + 1];
    }

    if (std.mem.indexOfScalar(u8, authority, ':')) |colon| return authority[0..colon];

    return authority;
}

fn usableBracketed(value: []const u8) bool {
    const close = std.mem.indexOfScalar(u8, value, ']') orelse return false;
    if (close < 2) return false;

    for (value[1..close]) |byte| {
        if (byte != ':' and !std.ascii.isHex(byte)) return false;
    }

    const rest = value[close + 1 ..];
    if (rest.len == 0) return true;
    if (rest[0] != ':') return false;

    return allDigits(rest[1..]);
}

fn portIsDigits(value: []const u8) bool {
    const colon = std.mem.indexOfScalar(u8, value, ':') orelse return true;

    return allDigits(value[colon + 1 ..]);
}

fn allDigits(value: []const u8) bool {
    if (value.len == 0) return false;

    for (value) |byte| {
        if (!std.ascii.isDigit(byte)) return false;
    }

    return true;
}

fn isHostByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '.' or byte == '-' or byte == '_';
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "zix zixer: https redirect, only the replayable methods keep the old status" {
    try testing.expectEqual(@as(u16, 301), statusFor("GET"));
    try testing.expectEqual(@as(u16, 301), statusFor("HEAD"));
    try testing.expectEqual(@as(u16, 301), statusFor("head"));

    // A 301 here lets the agent drop the body and turn the repeat into a GET.
    try testing.expectEqual(@as(u16, 308), statusFor("POST"));
    try testing.expectEqual(@as(u16, 308), statusFor("PUT"));
    try testing.expectEqual(@as(u16, 308), statusFor("PATCH"));
    try testing.expectEqual(@as(u16, 308), statusFor("DELETE"));
    try testing.expectEqual(@as(u16, 308), statusFor("OPTIONS"));
}

test "zix zixer: https redirect, the reason phrase follows the status" {
    try testing.expectEqualStrings("Moved Permanently", reasonFor(301));
    try testing.expectEqualStrings("Permanent Redirect", reasonFor(308));
}

test "zix zixer: https redirect, an ordinary authority passes" {
    try testing.expect(usableAuthority("example.com"));
    try testing.expect(usableAuthority("example.com:8443"));
    try testing.expect(usableAuthority("sub.example.co.uk"));
    try testing.expect(usableAuthority("my-site.test"));
    try testing.expect(usableAuthority("192.0.2.10"));
    try testing.expect(usableAuthority("192.0.2.10:443"));
    try testing.expect(usableAuthority("[::1]"));
    try testing.expect(usableAuthority("[2001:db8::1]:8443"));
}

test "zix zixer: https redirect, anything that could reshape the location is refused" {
    // A slash ends the authority, so everything after it would be a path the
    // client wrote into zixer's own Location line.
    try testing.expect(!usableAuthority("example.com/evil"));
    try testing.expect(!usableAuthority("evil.com/@example.com"));

    // Userinfo hides the real host behind an at sign.
    try testing.expect(!usableAuthority("example.com@evil.com"));

    // A control byte or a space breaks the header line itself.
    try testing.expect(!usableAuthority("example.com\r\nX-Evil: 1"));
    try testing.expect(!usableAuthority("example .com"));
    try testing.expect(!usableAuthority("example.com\x00"));

    // A scheme is not an authority.
    try testing.expect(!usableAuthority("https://example.com"));

    // Ports have to be numbers, and there has to be one after the colon.
    try testing.expect(!usableAuthority("example.com:"));
    try testing.expect(!usableAuthority("example.com:https"));
    try testing.expect(!usableAuthority("a:1:2"));

    // Bare ipv6 without brackets has no way to tell the port apart.
    try testing.expect(!usableAuthority("2001:db8::1"));
    try testing.expect(!usableAuthority("[2001:db8::1"));
    try testing.expect(!usableAuthority("[]"));
    try testing.expect(!usableAuthority("[::1]:x"));
    try testing.expect(!usableAuthority("[gg::1]"));

    try testing.expect(!usableAuthority(""));

    var oversized: [MAX_AUTHORITY_BYTES + 1]u8 = @splat('a');
    try testing.expect(!usableAuthority(&oversized));
}

test "zix zixer: https redirect, a named host is used and the client's is not" {
    // Whatever the client claimed, the reply names the site's own host.
    try testing.expectEqualStrings("example.com", authorityFor("example.com", "evil.com").?);
    try testing.expectEqualStrings("example.com", authorityFor("example.com", "").?);

    // Unset, the client's Host stands in, once it has passed the guard.
    try testing.expectEqualStrings("client.test", authorityFor(null, "client.test").?);
    try testing.expectEqual(@as(?[]const u8, null), authorityFor(null, "client.test/evil"));
    try testing.expectEqual(@as(?[]const u8, null), authorityFor(null, ""));
}

test "zix zixer: https redirect, the origin host drops the port and keeps the brackets" {
    try testing.expectEqualStrings("example.com", originHost("example.com:8443"));
    try testing.expectEqualStrings("example.com", originHost("example.com"));

    // The brackets are what keep the address apart from a port, so they stay.
    try testing.expectEqualStrings("[::1]", originHost("[::1]:8443"));
    try testing.expectEqualStrings("[2001:db8::1]", originHost("[2001:db8::1]"));
}
