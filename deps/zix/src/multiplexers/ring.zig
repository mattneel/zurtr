//! zix io_uring shared runtime primitives (ADR-037).
//!
//! Engine-agnostic helpers for the .URING dispatch model: the completion
//! routing tag and the user_data codec. zix.Http1 is the first engine to use
//! these (one ring per worker, shared-nothing), and the later engines
//! (WebSocket, gRPC, Http) reuse the same codec so a connection slot is keyed
//! by fd and guarded against fd reuse the same way everywhere.

const std = @import("std");
const linux = std.os.linux;

/// Completion routing tag, carried in the top byte of user_data so the loop
/// knows which handler a CQE belongs to without a per-fd lookup first. timeout
/// is the per-worker periodic timer (used by zix.Fix for proactive heartbeats):
/// engines that do not arm a timer treat it as a no-op. close is a ring close
/// (prep_close) submitted in place of a synchronous linux.close at teardown: its
/// CQE carries no connection (the slot is already cleared), so every engine
/// treats it as a no-op. The tls_* ops route the dual-listener TLS side
/// (config.tls_port): accept on the TLS listener, ciphertext recv, and the
/// staged-ciphertext flush send. Engines without a TLS side treat them as no-ops.
/// external routes a watched foreign fd (a driver socket living on the worker
/// ring, zix.Http1 only), other engines treat it as a no-op.
pub const OpKind = enum(u8) { accept, recv, send, timeout, close, tls_accept, tls_recv, tls_send, external };

/// Decoded user_data fields.
pub const Decoded = struct { op: OpKind, gen: u24, fd: linux.fd_t };

/// Pack op, generation, and fd into one u64 for a SQE's user_data.
///
/// Note:
/// - Layout: op in the top byte, generation in the next 24 bits, fd in the low
///   32 bits. The generation guards against fd reuse: a connection can close
///   and its fd be re-accepted while stale CQEs for the old connection are
///   still in the completion queue, and those must not touch the new one.
///
/// Param:
/// op - OpKind (which completion handler the CQE routes to)
/// gen - u24 (per-connection generation, bumped on each accept)
/// fd - linux.fd_t (the connection or listener file descriptor)
///
/// Return:
/// - u64 (the packed user_data)
pub fn packUserData(op: OpKind, gen: u24, fd: linux.fd_t) u64 {
    const fd_bits: u32 = @bitCast(fd);

    return (@as(u64, @intFromEnum(op)) << 56) | (@as(u64, gen) << 32) | fd_bits;
}

/// Decode a SQE's user_data back into its op, generation, and fd.
///
/// Param:
/// user_data - u64 (the value packed by packUserData)
///
/// Return:
/// - Decoded
pub fn unpackUserData(user_data: u64) Decoded {
    return .{
        .op = @enumFromInt(@as(u8, @intCast(user_data >> 56))),
        .gen = @intCast((user_data >> 32) & 0xff_ff_ff),
        .fd = @bitCast(@as(u32, @intCast(user_data & 0xff_ff_ff_ff))),
    };
}

// --------------------------------------------------------- //
// --------------------------------------------------------- //

test "zix multiplexers io_uring: user_data round trip preserves op, gen, fd" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    const packed_value = packUserData(.send, 0xabcdef, 1234);
    const decoded = unpackUserData(packed_value);

    try std.testing.expectEqual(OpKind.send, decoded.op);
    try std.testing.expectEqual(@as(u24, 0xabcdef), decoded.gen);
    try std.testing.expectEqual(@as(linux.fd_t, 1234), decoded.fd);
}

test "zix multiplexers io_uring: user_data each op kind decodes back" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    inline for (.{ OpKind.accept, OpKind.recv, OpKind.send, OpKind.timeout, OpKind.close, OpKind.external }) |op| {
        const decoded = unpackUserData(packUserData(op, 1, 7));
        try std.testing.expectEqual(op, decoded.op);
        try std.testing.expectEqual(@as(u24, 1), decoded.gen);
        try std.testing.expectEqual(@as(linux.fd_t, 7), decoded.fd);
    }
}

test "zix multiplexers io_uring: user_data max generation does not bleed into fd" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }
    const decoded = unpackUserData(packUserData(.recv, 0xff_ff_ff, 65535));

    try std.testing.expectEqual(@as(u24, 0xff_ff_ff), decoded.gen);
    try std.testing.expectEqual(@as(linux.fd_t, 65535), decoded.fd);
}
