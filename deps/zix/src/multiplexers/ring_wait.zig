//! zix io_uring bounded completion wait (ADR-037).
//!
//! One responsibility: enter a worker ring asking for a batch of completions and come back within
//! a deadline, whether or not the batch filled. Kept apart from ring.zig, which owns the user_data
//! codec alone.

const std = @import("std");
const linux = std.os.linux;
const IoUring = linux.IoUring;

/// Whether a completion wait on this ring can be bounded from inside the wait itself.
///
/// Note:
/// - IORING_FEAT_EXT_ARG is reported by the kernel at ring setup (Linux 5.11 and up). Without it
///   there is no safe bound for a batch wait, so the caller has to ask for one completion instead.
///
/// Param:
/// ring - *const IoUring (an initialized ring, so its feature word is filled in)
///
/// Return:
/// - bool
pub fn boundedWaitSupported(ring: *const IoUring) bool {
    return (ring.features & linux.IORING_FEAT_EXT_ARG) != 0;
}

/// Submit the staged SQEs and wait for up to wait_nr completions, returning once the deadline has
/// passed even when fewer than wait_nr arrive.
///
/// Note:
/// - The deadline travels with the wait (IORING_ENTER_EXT_ARG), so the kernel starts its timer
///   inside the wait, after sampling the state the wakeup is judged against. An IORING_OP_TIMEOUT
///   submission cannot stand in for that: its timer starts during submission, so a deadline that
///   expires before the wait begins is already part of that sample, and the wait then parks on a
///   completion count the ring may never reach. That is a hang, not a late wakeup.
/// - Only correct where boundedWaitSupported(ring) says so. Elsewhere the caller waits for a
///   single completion, which anything already queued satisfies.
/// - A deadline that passes on a short batch is the intended outcome and not a failure, so ETIME
///   returns normally and the caller reaps whatever landed.
///
/// Param:
/// ring - *IoUring (the calling thread's own ring, submitted and reaped by that thread only)
/// wait_nr - u32 (completions to coalesce into one wakeup, 1 or more)
/// timeout_ns - i64 (how long a short batch may be held)
///
/// Return:
/// - void once the wait returns, with or without a full batch
/// - error.SignalInterrupt when a signal arrived first, so the caller retries the pass
/// - error.RingWaitFailed on any other ring failure, so the caller leaves its loop
pub fn submitAndWaitTimeout(ring: *IoUring, wait_nr: u32, timeout_ns: i64) error{ SignalInterrupt, RingWaitFailed }!void {
    const deadline: linux.kernel_timespec = .{ .sec = 0, .nsec = timeout_ns };
    const wait_arg: linux.io_uring_getevents_arg = .{
        .sigmask = 0,
        .sigmask_sz = 0,
        .pad = 0,
        .ts = @intFromPtr(&deadline),
    };
    const ring_fd: u64 = @bitCast(@as(i64, ring.fd));

    const submitted = ring.flush_sq();
    const res = linux.syscall6(
        .io_uring_enter,
        ring_fd,
        submitted,
        wait_nr,
        linux.IORING_ENTER_GETEVENTS | linux.IORING_ENTER_EXT_ARG,
        @intFromPtr(&wait_arg),
        @sizeOf(linux.io_uring_getevents_arg),
    );

    return switch (linux.errno(res)) {
        .SUCCESS, .TIME => {},
        .INTR => error.SignalInterrupt,
        else => error.RingWaitFailed,
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

/// Monotonic nanoseconds, so a test can tell a wait that held from one that returned at once.
fn testMonotonicNanos() u64 {
    var now: linux.timespec = undefined;
    _ = linux.clock_gettime(.MONOTONIC, &now);

    return @as(u64, @intCast(now.sec)) * std.time.ns_per_s + @as(u64, @intCast(now.nsec));
}

/// A small ring for the wait cases, or null when io_uring is unavailable here (a sandbox, a low
/// RLIMIT_MEMLOCK, an old kernel). The caller logs and returns rather than failing the suite.
fn testRing() ?IoUring {
    return IoUring.init(8, 0) catch null;
}

/// Stage count no-op submissions, each of which completes on its own with nothing to wait for.
fn testStageNops(ring: *IoUring, count: usize) !void {
    var staged: usize = 0;
    while (staged < count) : (staged += 1) {
        const sqe = try ring.get_sqe();
        sqe.prep_nop();
        sqe.user_data = staged + 1;
    }
}

test "zix multiplexers io_uring: bounded wait, the probe reads the ring's own feature word" {
    var ring = testRing() orelse {
        std.log.info("bounded wait: io_uring unavailable here, the feature probe case did not run", .{});
        return;
    };
    defer ring.deinit();

    // Either answer is valid on a given kernel. What matters is that the probe reads the feature
    // the ring reported rather than assuming one, since a false makes every caller fall back.
    try std.testing.expectEqual((ring.features & linux.IORING_FEAT_EXT_ARG) != 0, boundedWaitSupported(&ring));
}

test "zix multiplexers io_uring: bounded wait, an empty ring returns instead of parking" {
    var ring = testRing() orelse {
        std.log.info("bounded wait: io_uring unavailable here, the empty ring case did not run", .{});
        return;
    };
    defer ring.deinit();

    if (!boundedWaitSupported(&ring)) {
        std.log.info("bounded wait: this kernel has no IORING_FEAT_EXT_ARG, the empty ring case did not run", .{});
        return;
    }

    // BUG-001 in one call: nothing is armed, so no completion can ever arrive. A wait that is not
    // bounded from inside the wait never comes back, so reaching the assertions is the result.
    const started = testMonotonicNanos();
    try submitAndWaitTimeout(&ring, 32, 5 * std.time.ns_per_ms);
    const waited = testMonotonicNanos() - started;

    var cqes: [8]linux.io_uring_cqe = undefined;

    try std.testing.expect(waited >= std.time.ns_per_ms);
    try std.testing.expectEqual(@as(u32, 0), try ring.copy_cqes(&cqes, 0));
}

test "zix multiplexers io_uring: bounded wait, a batch shorter than wait_nr still returns" {
    var ring = testRing() orelse {
        std.log.info("bounded wait: io_uring unavailable here, the short batch case did not run", .{});
        return;
    };
    defer ring.deinit();

    if (!boundedWaitSupported(&ring)) {
        std.log.info("bounded wait: this kernel has no IORING_FEAT_EXT_ARG, the short batch case did not run", .{});
        return;
    }

    // The shape that stranded connections: some completions are ready, fewer than the wait asked
    // for, and no further completion is coming. The deadline has to hand the short batch over.
    try testStageNops(&ring, 3);

    try submitAndWaitTimeout(&ring, 32, 5 * std.time.ns_per_ms);

    var cqes: [8]linux.io_uring_cqe = undefined;

    try std.testing.expectEqual(@as(u32, 3), try ring.copy_cqes(&cqes, 0));
}

test "zix multiplexers io_uring: bounded wait, a full batch returns without holding the deadline" {
    var ring = testRing() orelse {
        std.log.info("bounded wait: io_uring unavailable here, the full batch case did not run", .{});
        return;
    };
    defer ring.deinit();

    if (!boundedWaitSupported(&ring)) {
        std.log.info("bounded wait: this kernel has no IORING_FEAT_EXT_ARG, the full batch case did not run", .{});
        return;
    }

    // The hot path: the batch fills, so the wait must not sit out the rest of its window.
    try testStageNops(&ring, 4);

    const started = testMonotonicNanos();
    try submitAndWaitTimeout(&ring, 4, std.time.ns_per_s);
    const waited = testMonotonicNanos() - started;

    try std.testing.expect(waited < std.time.ns_per_s);

    var cqes: [8]linux.io_uring_cqe = undefined;

    try std.testing.expectEqual(@as(u32, 4), try ring.copy_cqes(&cqes, 0));
}

test "zix multiplexers io_uring: bounded wait, a single-completion wait behaves like the plain one" {
    var ring = testRing() orelse {
        std.log.info("bounded wait: io_uring unavailable here, the single completion case did not run", .{});
        return;
    };
    defer ring.deinit();

    if (!boundedWaitSupported(&ring)) {
        std.log.info("bounded wait: this kernel has no IORING_FEAT_EXT_ARG, the single completion case did not run", .{});
        return;
    }

    try testStageNops(&ring, 1);

    try submitAndWaitTimeout(&ring, 1, std.time.ns_per_s);

    var cqes: [8]linux.io_uring_cqe = undefined;

    try std.testing.expectEqual(@as(u32, 1), try ring.copy_cqes(&cqes, 0));
}
