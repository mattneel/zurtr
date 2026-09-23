//! zixer worker count: how many accept loops one site runs

const std = @import("std");
const builtin = @import("builtin");

/// Whether two listeners on this platform can hold one port and have the
/// kernel hand each of them a share of the accepted connections.
///
/// Note:
/// - Posix pairs SO_REUSEADDR with SO_REUSEPORT inside std's listen, and
///   SO_REUSEPORT is what balances accepts across sockets.
/// - Windows has SO_REUSEADDR alone, where a second bind takes the port
///   over instead of joining it. A site there keeps one accept loop
///   however many workers the config asks for.
pub const PORT_SHARING: bool = switch (builtin.os.tag) {
    .windows => false,
    else => true,
};

/// Threads this process may actually run on.
///
/// Note:
/// - On Linux std reads this from sched_getaffinity, so a daemon pinned to
///   a cpuset reports the cores it was given, not the ones the box has. A
///   cpu quota (a share of time rather than a set of cores) is not a mask,
///   so it does not show up here and a quota-limited daemon should name a
///   worker count instead of asking for 0.
/// - An unreadable count falls back to 1, which is the old behaviour.
///
/// Return:
/// - usize (at least 1)
pub fn available() usize {
    return std.Thread.getCpuCount() catch 1;
}

/// Accept loops one site runs, from the configured value.
///
/// Note:
/// - 0 means "every thread this process was given", which is what a
///   container under a cpuset wants: the cpuset stays the one place the
///   core count is written.
/// - A platform that cannot share a listen port resolves to 1. Binding a
///   second listener there would take the port from the first rather than
///   join it, so the extra workers would serve nothing.
///
/// Param:
/// configured - usize (main.cfg workers, 0 for every available thread)
/// available_threads - usize (what available() reported)
///
/// Return:
/// - usize (at least 1)
pub fn resolve(configured: usize, available_threads: usize) usize {
    if (!PORT_SHARING) return 1;

    const wanted = if (configured == 0) available_threads else configured;

    return @max(1, wanted);
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix zixer: worker count, zero means every available thread" {
    const expected: usize = if (PORT_SHARING) 12 else 1;
    try std.testing.expectEqual(expected, resolve(0, 12));
}

test "zix zixer: worker count, a named count is taken as written" {
    const expected: usize = if (PORT_SHARING) 4 else 1;
    try std.testing.expectEqual(expected, resolve(4, 12));
    try std.testing.expectEqual(@as(usize, 1), resolve(1, 12));
}

test "zix zixer: worker count, an unreadable thread count still gives one loop" {
    try std.testing.expectEqual(@as(usize, 1), resolve(0, 0));
    try std.testing.expectEqual(@as(usize, 1), resolve(0, 1));
}

test "zix zixer: worker count, available reports at least one thread" {
    try std.testing.expect(available() >= 1);
}

test "zix zixer: worker count, a platform without port sharing keeps one loop" {
    if (PORT_SHARING) {
        std.log.info("zix zixer: worker count single-listener case needs a platform without SO_REUSEPORT", .{});

        return;
    }

    try std.testing.expectEqual(@as(usize, 1), resolve(8, 12));
}
