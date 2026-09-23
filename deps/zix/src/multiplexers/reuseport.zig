//! SO_ATTACH_REUSEPORT_CBPF connection steering, shared by the per-core
//! dispatch models (.EPOLL / .URING) of every engine.
//!
//! What:
//! - `steeringProgram`: the three-instruction classic BPF program
//!   (ld cpu, mod #N, ret A). The kernel then hands a new connection (TCP) or
//!   packet (UDP) to group index = receiving CPU mod N instead of hashing the
//!   4-tuple, so the socket serving it belongs to the core that received it.
//! - `attachCpuSteering`: one setsockopt on a group member. Attaching through
//!   any member installs the program for the whole group. Silent no-op when
//!   the kernel lacks the option (pre-4.5), keeping the default hash.
//! - `BindOrderGate`: serializes worker binds into worker-id order at startup,
//!   so group index i is worker i (the pinToCpu slot i) and the program's
//!   cpu-mod-N index lands on the worker pinned nearest that CPU.
//!
//! Note:
//! - Classic BPF, not extended: a plain instruction array through setsockopt,
//!   unprivileged, no bpf(2) syscall, so it works inside the unprivileged
//!   containers where the entries run (eBPF needs CAP_BPF and bpf(2), both
//!   commonly blocked there).
//! - An out-of-range index (a CPU beyond the group while workers are still
//!   binding) falls back to the kernel hash, so startup stays correct.

const std = @import("std");

// Classic BPF opcode fields (linux/bpf_common.h + linux/filter.h), spelled out
// so the program below reads as instructions rather than numbers.

/// Instruction class: load into the accumulator.
const BPF_LD: u16 = 0x00;
/// Instruction class: arithmetic on the accumulator.
const BPF_ALU: u16 = 0x04;
/// Instruction class: return.
const BPF_RET: u16 = 0x06;
/// Load size: 32-bit word.
const BPF_W: u16 = 0x00;
/// Load mode: absolute offset (here the ancillary-data space).
const BPF_ABS: u16 = 0x20;
/// ALU op: modulo by the constant operand.
const BPF_MOD: u16 = 0x90;
/// Operand source: the constant k.
const BPF_K: u16 = 0x00;
/// Return source: the accumulator.
const BPF_A: u16 = 0x10;

/// Base of the classic-BPF ancillary data space (linux/filter.h SKF_AD_OFF).
const SKF_AD_OFF: i32 = -0x1000;
/// Ancillary field: the CPU processing this packet (SKF_AD_CPU).
const SKF_AD_CPU: i32 = 36;

/// setsockopt option name (linux/socket.h): attach a classic BPF REUSEPORT
/// group selector.
const SO_ATTACH_REUSEPORT_CBPF: u32 = 51;

/// One classic BPF instruction (linux struct sock_filter).
pub const SockFilter = extern struct {
    code: u16,
    jt: u8 = 0,
    jf: u8 = 0,
    k: u32,
};

/// The program descriptor passed to setsockopt (linux struct sock_fprog).
const SockFprog = extern struct {
    len: u16,
    filter: [*]const SockFilter,
};

/// Build the steering program for a REUSEPORT group of group_size members:
/// ld cpu, mod #group_size, ret A. The modulo keeps the index in range when
/// packets arrive on CPUs outside the worker range (loopback, fewer RX queues
/// than workers): placement degrades to round-robin-by-arrival-CPU, never
/// worse than the default hash.
pub fn steeringProgram(group_size: u32) [3]SockFilter {
    return .{
        .{ .code = BPF_LD | BPF_W | BPF_ABS, .k = @bitCast(SKF_AD_OFF + SKF_AD_CPU) },
        .{ .code = BPF_ALU | BPF_MOD | BPF_K, .k = group_size },
        .{ .code = BPF_RET | BPF_A, .k = 0 },
    };
}

/// Whether the group really steers by receiving CPU, or fell back to the default 4-tuple hash.
pub const Steered = enum {
    /// The program is installed, so a connection lands on the worker pinned to the receiving CPU.
    ATTACHED,
    /// The kernel refused it. Placement is still correct, just hash-based rather than CPU-affine.
    UNAVAILABLE,
};

/// Set once the refusal has been reported, so a group of workers says it once and not per worker.
var steering_reported: std.atomic.Value(bool) = .init(false);

const log = std.log.scoped(.zix_reuseport);

/// Attach the steering program through one member of the REUSEPORT group (the
/// kernel installs it group-wide, so the last attach wins and every worker
/// attaching the same program is idempotent). Call after the member joined
/// the group.
///
/// Note:
/// - A kernel without SO_ATTACH_REUSEPORT_CBPF (pre-4.5) leaves the group on the default hash,
///   which serves correctly and only loses the cache affinity. That fallback used to be silent,
///   so an operator who set reuseport_cbpf could not tell whether it took effect.
/// - The refusal is reported once per process, not once per worker: the program is installed
///   group-wide, so every worker in the group fails the same way for the same reason.
///
/// Return:
/// - Steered.ATTACHED when the group steers by CPU
/// - Steered.UNAVAILABLE when it kept the default hash
pub fn attachCpuSteering(fd: std.posix.fd_t, group_size: usize) Steered {
    if (group_size == 0) return .UNAVAILABLE;

    const prog = steeringProgram(@intCast(@min(group_size, std.math.maxInt(u32))));
    const fprog = SockFprog{ .len = prog.len, .filter = &prog };

    std.posix.setsockopt(fd, std.posix.SOL.SOCKET, SO_ATTACH_REUSEPORT_CBPF, std.mem.asBytes(&fprog)) catch |err| {
        if (!steering_reported.swap(true, .acq_rel))
            log.warn("reuseport_cbpf was asked for and this kernel refused it ({s}), the group keeps the default 4-tuple hash", .{@errorName(err)});

        return .UNAVAILABLE;
    };

    return .ATTACHED;
}

/// Startup gate serializing the workers' REUSEPORT joins into worker-id order,
/// so group index i is worker i (the pinToCpu slot i) and cpu-mod-N steering
/// lands on the worker pinned nearest the receiving CPU. Without it the joins
/// race and the index-to-worker mapping is an arbitrary permutation (still
/// skew-free, but the cache-affinity benefit is lost). Bind is startup-only,
/// so the wait is a yield loop, never a hot-path cost.
pub const BindOrderGate = struct {
    next: std.atomic.Value(usize) = .init(0),

    /// Block (yielding) until it is worker_id's turn to bind.
    pub fn waitTurn(self: *BindOrderGate, worker_id: usize) void {
        while (self.next.load(.acquire) != worker_id) std.Thread.yield() catch {};
    }

    /// Release the next worker. Call once the listener joined the group.
    pub fn done(self: *BindOrderGate) void {
        _ = self.next.fetchAdd(1, .release);
    }
};

/// Steering wiring threaded through a dispatch worker ctx: the shared bind
/// order gate plus the REUSEPORT group size for the program. A ctx carries
/// null when steering is off (the default), so the hot structures are
/// unchanged and every gate call is a no-op.
pub const Steering = struct {
    gate: *BindOrderGate,
    group_size: usize,
};

/// One worker's turn on the bind order gate. begin() waits for the turn,
/// release() passes it to the next worker. release() is idempotent so a defer
/// can back-stop the early error returns between bind and release without
/// wedging the siblings. A null steering makes both calls no-ops.
pub const BindTurn = struct {
    gate: ?*BindOrderGate,
    released: bool = false,

    pub fn begin(steering: ?Steering, worker_id: usize) BindTurn {
        const gate = if (steering) |steer| steer.gate else null;
        if (gate) |gate_ptr| gate_ptr.waitTurn(worker_id);

        return .{ .gate = gate };
    }

    pub fn release(self: *BindTurn) void {
        if (self.released) return;

        self.released = true;
        if (self.gate) |gate_ptr| gate_ptr.done();
    }
};

// --------------------------------------------------------------- //
// --------------------------------------------------------------- //

test "zix multiplexers: steeringProgram encodes ld cpu, mod N, ret A" {
    const prog = steeringProgram(6);

    try std.testing.expectEqual(@as(u16, BPF_LD | BPF_W | BPF_ABS), prog[0].code);
    try std.testing.expectEqual(@as(u32, @bitCast(@as(i32, -0x1000 + 36))), prog[0].k);
    try std.testing.expectEqual(@as(u16, BPF_ALU | BPF_MOD | BPF_K), prog[1].code);
    try std.testing.expectEqual(@as(u32, 6), prog[1].k);
    try std.testing.expectEqual(@as(u16, BPF_RET | BPF_A), prog[2].code);
}

test "zix multiplexers: SockFprog matches the C sock_fprog layout" {
    try std.testing.expectEqual(@as(usize, 0), @offsetOf(SockFprog, "len"));
    try std.testing.expectEqual(@as(usize, @sizeOf(usize)), @offsetOf(SockFprog, "filter"));
    try std.testing.expectEqual(@as(usize, 8), @sizeOf(SockFilter));
}

test "zix multiplexers: attachCpuSteering is a no-op on a zero-size group" {
    if (comptime @import("builtin").target.os.tag != .linux) {
        std.log.info("EPOLL/URING is Linux-only, test skipped", .{});
        return;
    }

    try std.testing.expectEqual(Steered.UNAVAILABLE, attachCpuSteering(-1, 0));
}

test "zix multiplexers: BindOrderGate releases workers in id order" {
    var gate = BindOrderGate{};

    // Worker 0 passes immediately, later ids pass only after done() calls.
    gate.waitTurn(0);
    gate.done();
    gate.waitTurn(1);
    gate.done();
    try std.testing.expectEqual(@as(usize, 2), gate.next.load(.acquire));
}

test "zix multiplexers: BindTurn release is idempotent and null steering is a no-op" {
    var gate = BindOrderGate{};
    const steering = Steering{ .gate = &gate, .group_size = 4 };

    var turn = BindTurn.begin(steering, 0);
    turn.release();
    turn.release();
    try std.testing.expectEqual(@as(usize, 1), gate.next.load(.acquire));

    var off_turn = BindTurn.begin(null, 7);
    off_turn.release();
    try std.testing.expectEqual(@as(usize, 1), gate.next.load(.acquire));
}

test "zix multiplexers: reuseport, an empty group cannot steer" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("SO_ATTACH_REUSEPORT_CBPF is Linux-only, test skipped", .{});
        return;
    }

    try std.testing.expectEqual(Steered.UNAVAILABLE, attachCpuSteering(@as(std.posix.fd_t, -1), 0));
}

test "zix multiplexers: reuseport, a real reuseport socket takes the program" {
    if (comptime @import("builtin").os.tag != .linux) {
        std.log.info("SO_ATTACH_REUSEPORT_CBPF is Linux-only, test skipped", .{});
        return;
    }

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 18993);
    var srv = addr.listen(io, .{ .mode = .stream, .reuse_address = true, .kernel_backlog = 8 }) catch {
        std.log.info("the loopback port could not be bound, test skipped", .{});
        return;
    };
    defer srv.deinit(io);

    try std.testing.expectEqual(Steered.ATTACHED, attachCpuSteering(srv.socket.handle, 4));
}
