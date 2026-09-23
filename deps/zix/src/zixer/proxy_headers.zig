//! zixer proxy header rules: hop-by-hop strip (rfc 9110) and Forwarded (rfc 7239)

const std = @import("std");

const request_scheme = @import("request_scheme.zig");

/// Via element zixer appends on both legs (rfc 9110 intermediary rule).
pub const VIA: []const u8 = "1.1 zixer";

/// The fixed hop-by-hop list from rfc 9110. These never cross zixer in either
/// direction. Transfer-Encoding and Trailer sit here because zixer re-frames
/// the body itself (re-originate, the rfc 9112 smuggling defense).
const HOP_BY_HOP = [_][]const u8{
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
};

/// True when name never crosses the proxy. Content-Length is stripped too:
/// zixer emits its own framing header for the rebuilt message.
pub fn isStripped(name: []const u8) bool {
    for (HOP_BY_HOP) |hop| {
        if (std.ascii.eqlIgnoreCase(name, hop)) return true;
    }

    return std.ascii.eqlIgnoreCase(name, "content-length");
}

/// True when name appears as a token in a Connection header value. Anything
/// named there is hop-by-hop as well (rfc 9110).
pub fn namedInConnection(name: []const u8, connection_value: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, connection_value, ',');
    while (tokens.next()) |token| {
        const trimmed = std.mem.trim(u8, token, " \t");
        if (trimmed.len != 0 and std.ascii.eqlIgnoreCase(name, trimmed)) return true;
    }

    return false;
}

/// The Host or authority value without its port. A bracketed IPv6 literal
/// keeps its inner address, a bare IPv6 literal (several colons) stays
/// whole.
pub fn stripHostPort(host: []const u8) []const u8 {
    if (host.len == 0) return host;

    if (host[0] == '[') {
        if (std.mem.indexOfScalar(u8, host, ']')) |close| return host[1..close];

        return host;
    }

    if (std.mem.indexOfScalar(u8, host, ':')) |first| {
        if (std.mem.lastIndexOfScalar(u8, host, ':').? == first) return host[0..first];
    }

    return host;
}

/// Widest address text a client can produce: a full ipv6 literal in brackets
/// with its port.
pub const CLIENT_IP_MAX: usize = 64;

/// The client's address with no port, which is what a header naming one
/// address is expected to carry.
///
/// Note:
/// - An ipv6 client comes back bare, without its brackets, because the
///   brackets exist to separate the address from a port that is not here.
///
/// Param:
/// buf - []u8 (scratch, CLIENT_IP_MAX bytes, must outlive the returned slice)
/// addr - std.Io.net.IpAddress (the accepted connection's peer)
///
/// Return:
/// - []const u8, a slice into buf
/// - "" when the address does not fit, which no real address does
pub fn clientIp(buf: []u8, addr: std.Io.net.IpAddress) []const u8 {
    var out = std.Io.Writer.fixed(buf);
    out.print("{f}", .{addr}) catch return "";

    return stripHostPort(out.buffered());
}

/// Write the Forwarded header line for one client (rfc 7239).
///
/// Note:
/// - The for= node is always quoted: the address carries a port, and rfc 7239
///   requires the quoted form as soon as a port (or an ipv6 bracket) appears.
/// - host is the client's original Host value, empty skips the parameter.
/// - The proto parameter comes from the site, never from the client. See
///   request_scheme for why a claimed scheme is not usable here.
///
/// Param:
/// out - *std.Io.Writer (upstream request head in progress)
/// client_addr - std.Io.net.IpAddress (accepted connection's peer)
/// host - []const u8 (original Host header value, may be empty)
/// scheme - request_scheme.Scheme (how the client reached this site)
///
/// Return:
/// - void, the full `Forwarded: ...\r\n` line is written
pub fn writeForwarded(out: *std.Io.Writer, client_addr: std.Io.net.IpAddress, host: []const u8, scheme: request_scheme.Scheme) !void {
    try out.print("Forwarded: for=\"{f}\";proto={s}", .{ client_addr, scheme.token() });
    if (host.len != 0) try out.print(";host=\"{s}\"", .{host});
    try out.writeAll("\r\n");
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: proxy headers, hop-by-hop and framing names are stripped" {
    try std.testing.expect(isStripped("Connection"));
    try std.testing.expect(isStripped("keep-alive"));
    try std.testing.expect(isStripped("Proxy-Authenticate"));
    try std.testing.expect(isStripped("proxy-authorization"));
    try std.testing.expect(isStripped("TE"));
    try std.testing.expect(isStripped("Trailer"));
    try std.testing.expect(isStripped("Transfer-Encoding"));
    try std.testing.expect(isStripped("Upgrade"));
    try std.testing.expect(isStripped("Content-Length"));
}

test "zix zixer: proxy headers, end-to-end names pass" {
    try std.testing.expect(!isStripped("Host"));
    try std.testing.expect(!isStripped("Accept"));
    try std.testing.expect(!isStripped("Authorization"));
    try std.testing.expect(!isStripped("Cookie"));
    try std.testing.expect(!isStripped("Forwarded"));
    try std.testing.expect(!isStripped("Via"));
}

test "zix zixer: proxy headers, connection tokens mark extra hop-by-hop names" {
    try std.testing.expect(namedInConnection("X-Custom-Hop", "close, X-Custom-Hop"));
    try std.testing.expect(namedInConnection("x-custom-hop", " X-Custom-Hop "));

    try std.testing.expect(!namedInConnection("Accept", "close, X-Custom-Hop"));
    try std.testing.expect(!namedInConnection("Accept", ""));
}

test "zix zixer: proxy headers, host port strip keeps every literal shape" {
    try std.testing.expectEqualStrings("example.com", stripHostPort("example.com:8443"));
    try std.testing.expectEqualStrings("example.com", stripHostPort("example.com"));
    try std.testing.expectEqualStrings("::1", stripHostPort("[::1]:443"));
    try std.testing.expectEqualStrings("::1", stripHostPort("[::1]"));
    try std.testing.expectEqualStrings("fe80::1:2", stripHostPort("fe80::1:2"));
    try std.testing.expectEqualStrings("", stripHostPort(""));
}

test "zix zixer: proxy headers, the client ip token drops the port and the brackets" {
    var buf: [CLIENT_IP_MAX]u8 = undefined;

    const ip4 = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 60 }, .port = 51000 } };
    try std.testing.expectEqualStrings("192.0.2.60", clientIp(&buf, ip4));

    const loopback = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 127, 0, 0, 1 }, .port = 8080 } };
    try std.testing.expectEqualStrings("127.0.0.1", clientIp(&buf, loopback));

    const ip6 = try std.Io.net.IpAddress.parse("2001:db8::1", 443);
    try std.testing.expectEqualStrings("2001:db8::1", clientIp(&buf, ip6));

    // A buffer too small for the address answers empty rather than a cut-off
    // address, which would name a different client.
    var tiny: [4]u8 = undefined;
    try std.testing.expectEqualStrings("", clientIp(&tiny, ip4));
}

test "zix zixer: proxy headers, forwarded line quotes the node and carries host" {
    var line_buf: [128]u8 = undefined;
    var out = std.Io.Writer.fixed(&line_buf);

    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 60 }, .port = 51000 } };
    try writeForwarded(&out, addr, "example.com", .HTTP);

    try std.testing.expectEqualStrings("Forwarded: for=\"192.0.2.60:51000\";proto=http;host=\"example.com\"\r\n", out.buffered());
}

test "zix zixer: proxy headers, forwarded line without host skips the parameter" {
    var line_buf: [128]u8 = undefined;
    var out = std.Io.Writer.fixed(&line_buf);

    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 10, 0, 0, 9 }, .port = 40000 } };
    try writeForwarded(&out, addr, "", .HTTP);

    try std.testing.expectEqualStrings("Forwarded: for=\"10.0.0.9:40000\";proto=http\r\n", out.buffered());
}

test "zix zixer: proxy headers, the forwarded proto follows the site and not the client" {
    var line_buf: [128]u8 = undefined;
    const addr = std.Io.net.IpAddress{ .ip4 = .{ .bytes = .{ 192, 0, 2, 60 }, .port = 51000 } };

    var secure = std.Io.Writer.fixed(&line_buf);
    try writeForwarded(&secure, addr, "example.com", .HTTPS);
    try std.testing.expectEqualStrings("Forwarded: for=\"192.0.2.60:51000\";proto=https;host=\"example.com\"\r\n", secure.buffered());

    var plain = std.Io.Writer.fixed(&line_buf);
    try writeForwarded(&plain, addr, "example.com", .HTTP);
    try std.testing.expect(std.mem.indexOf(u8, plain.buffered(), ";proto=http;") != null);
}
