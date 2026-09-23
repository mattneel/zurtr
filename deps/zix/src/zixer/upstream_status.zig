//! zixer upstream leg: what a client is told when no attempt produced a connection

const std = @import("std");

const upstream_conn = @import("upstream_conn.zig");

/// One local reply an edge writes for itself. The reason phrase is http1's
/// alone, the multiplexed edges carry the status and the proxy-error only.
pub const Answer = struct {
    status: u16,
    reason: []const u8,
    /// The rfc 9209 Proxy-Status error parameter.
    proxy_error: []const u8,
};

/// At least one upstream never answered its handshake inside the site's
/// budget. rfc 9110 15.6.5 is exactly this case: no timely response.
pub const TIMED_OUT: Answer = .{
    .status = 504,
    .reason = "upstream connect timeout",
    .proxy_error = "connection_timeout",
};

/// Every upstream answered, and every answer was no.
pub const REFUSED: Answer = .{
    .status = 502,
    .reason = "all upstreams failed",
    .proxy_error = "connection_refused",
};

/// Which reply a finished round of attempts earned.
///
/// Note:
/// - One timeout is enough for the 504. The client spent the wait either way,
///   and silence is the more useful thing to report: a refusal names a backend
///   that is up and saying no, a timeout names one that may not be there at
///   all.
///
/// Param:
/// any_timed_out - bool (true when some attempt ran out of budget)
///
/// Return:
/// - Answer, TIMED_OUT or REFUSED
pub fn afterAttempts(any_timed_out: bool) Answer {
    return if (any_timed_out) TIMED_OUT else REFUSED;
}

/// Whether this failed connect is one that spent the whole budget.
///
/// Param:
/// err - upstream_conn.ConnectError (what the connect ended with)
///
/// Return:
/// - true only for a handshake that never got an answer
pub fn ranOutOfTime(err: upstream_conn.ConnectError) bool {
    return err == error.ZixConnectTimeout;
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

const testing = std.testing;

test "zix zixer: upstream status, a round with a timeout in it answers 504" {
    const timed_out = afterAttempts(true);
    try testing.expectEqual(@as(u16, 504), timed_out.status);
    try testing.expectEqualStrings("connection_timeout", timed_out.proxy_error);
    try testing.expectEqualStrings("upstream connect timeout", timed_out.reason);
}

test "zix zixer: upstream status, a round of plain failures answers 502" {
    const refused = afterAttempts(false);
    try testing.expectEqual(@as(u16, 502), refused.status);
    try testing.expectEqualStrings("connection_refused", refused.proxy_error);
    try testing.expectEqualStrings("all upstreams failed", refused.reason);
}

test "zix zixer: upstream status, only the elapsed budget counts as out of time" {
    try testing.expect(ranOutOfTime(error.ZixConnectTimeout));

    try testing.expect(!ranOutOfTime(error.ZixConnectFailed));
    try testing.expect(!ranOutOfTime(error.ZixerBadUpstreamAddress));
}
