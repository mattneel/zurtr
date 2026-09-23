//! zixer request scheme: how a client reached this site, and the token that names it

const std = @import("std");

/// How a client reached zixer on this site's own listener.
///
/// Note:
/// - The source is the site's own tls setting and nothing else. A client can
///   claim any `:scheme` pseudo-header or X-Forwarded-Proto it likes, and a
///   backend that trusts the claim would be told a cleartext request arrived
///   over https. An operator who does want to trust an inbound claim has to
///   ask for it, which is a key that does not exist yet.
/// - This is the one source for both the rfc 7239 proto parameter and the
///   `$scheme` token a site file can put in a header value.
pub const Scheme = enum {
    HTTP,
    HTTPS,

    /// The scheme of a site, from the one setting that decides it.
    ///
    /// Param:
    /// tls - bool (the site's tls flag, already validated)
    ///
    /// Return:
    /// - Scheme
    pub fn ofSite(tls: bool) Scheme {
        return if (tls) .HTTPS else .HTTP;
    }

    /// The lowercase token this scheme is written as, in a url and in the
    /// Forwarded proto parameter (rfc 7239 5.4).
    ///
    /// Return:
    /// - []const u8, "http" or "https"
    pub fn token(scheme: Scheme) []const u8 {
        return switch (scheme) {
            .HTTP => "http",
            .HTTPS => "https",
        };
    }
};

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "zix zixer: request scheme, the site's tls flag is the whole source" {
    try testing.expectEqual(Scheme.HTTPS, Scheme.ofSite(true));
    try testing.expectEqual(Scheme.HTTP, Scheme.ofSite(false));
}

test "zix zixer: request scheme, each scheme has one lowercase token" {
    try testing.expectEqualStrings("http", Scheme.HTTP.token());
    try testing.expectEqualStrings("https", Scheme.HTTPS.token());
}
