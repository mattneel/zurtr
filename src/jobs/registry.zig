//! Action binding: what a `kind` means, and what a job body is handed when it runs.
//!
//! A job row carries `kind` (an action id), `version` (the action version at insert) and `payload`
//! (the action's `Input`, already serialized). Jobs never decodes the payload itself: the codec is the
//! application's, which is the same split `domain` makes when it takes a decode function as a
//! comptime parameter instead of owning one. What lives here is the lookup and the `Ctx` a body is
//! invoked with, so the queue can hand a bound action everything it needs and nothing more.
//!
//! Two rules the contract states, both enforced here rather than trusted:
//!
//!   * **A version is checked before a body runs.** A row written by an older deployment of an
//!     action, whose `Input` has since changed shape, must fail the job with a diagnostic. It must
//!     never be decoded as if it were current, because decoding the wrong bytes into the right struct
//!     is the failure that corrupts data quietly.
//!   * **A principal is never a user.** The runner's principal is `system.jobs:<queue>`; an action
//!     that needs a real one carries it in its own `Input`, explicitly, so the authority a job runs
//!     with is visible in the row rather than implied by the queue it came from.

const std = @import("std");
const data = @import("../data/root.zig");
const cancel = @import("cancel.zig");

pub const Error = error{
    /// The row's `kind` is not registered in this process.
    UnknownKind,
    /// The row's `kind` is registered, but not at the row's `version`.
    UnsupportedVersion,
    /// Two bindings claim the same `(kind, version)`; the lookup would depend on declaration order.
    DuplicateKind,
    /// A binding with an empty kind cannot be looked up.
    EmptyKind,
};

/// What a step boundary reports: the queue's cancellation, or a database failure while the boundary was
/// being taken.
pub const StepError = data.Error || error{
    /// The job body observed a cancellation request at a step boundary.
    Cancelled,
};

/// The prefix of the principal every job body runs with: `system.jobs:<queue>`.
pub const principal_prefix = "system.jobs:";

/// What a job body is handed.
///
/// `tx` is the **current step's** transaction, not the job's: a step is what a body commits, which is
/// what makes "effects already recorded stay recorded" true when a later step is rolled back or the job
/// is cancelled. The boundary is also what makes cancellation observable at all — a single-writer
/// engine cannot record a cancellation request from another process while this job holds the write
/// lock, so each boundary releases it and takes the next one.
pub const Ctx = struct {
    /// The row this invocation is for.
    job_id: i64,
    /// Which attempt this is, counting from 1. The claim bumps it.
    attempt: u32,
    queue: []const u8,
    /// `system.jobs:<queue>`, unless a caller of `invokeBound` overrode it.
    principal: []const u8,
    io: std.Io,
    /// Owns everything the body allocates for this invocation. Released after the body returns.
    allocator: std.mem.Allocator,
    now_ms: i64,
    /// The current step's transaction, when the runner established one. Opaque to the body beyond
    /// passing it to the data module, exactly as `domain.Ctx` treats it. The runner replaces it at each
    /// boundary, so a body must read it from here rather than keeping its own copy.
    tx: ?*data.Tx = null,
    /// Set by the step hook when a boundary could not be taken. `checkpoint` reports it, which fails the
    /// job through the runner's normal failure path rather than letting the body write outside a
    /// transaction.
    step_failure: ?data.Error = null,
    /// The cancellations this worker currently knows about (see `cancel.zig`).
    cancel: cancel.View = .{},
    /// The runner's per-job step hook: renews the lease, refreshes the cancel snapshot and takes the
    /// next transaction when they are due. Set by the runner; absent in unit tests, where a boundary is
    /// only a cancellation check.
    on_step: ?*const fn (user: ?*anyopaque, ctx: *Ctx) void = null,
    on_step_user: ?*anyopaque = null,

    /// Whether a cancellation has been requested for this job. Answered from the worker's snapshot, so
    /// it is a binary search rather than a database round trip.
    pub fn cancelled(self: *const Ctx) bool {
        return self.cancel.has(self.job_id);
    }

    /// A step boundary: the only place a running job may be interrupted, and the only place its work so
    /// far becomes durable.
    ///
    /// Everything a body does between two of these is its own uninterrupted business. That is the whole
    /// of the cooperative contract: cancellation is observed here or not at all, which is also why
    /// `checkpoint` is where the lease is renewed and where the step commits — a body that never checks
    /// in cannot be cancelled, cannot keep a lease, and gets no durability for the work it has done.
    pub fn checkpoint(self: *Ctx) StepError!void {
        if (self.on_step) |hook| hook(self.on_step_user, self);

        if (self.step_failure) |err| return err;
        if (self.cancelled()) return error.Cancelled;
    }
};

/// A registered action, at one version.
pub const Binding = struct {
    kind: []const u8,
    version: i32,
    /// Decode the stored payload with the application's codec, run the action, return its result
    /// summary. Whatever it returns is stored in the job's `result` column, which the contract keeps
    /// as a summary on purpose: large results belong in application tables, not in the queue.
    run: *const fn (ctx: *Ctx, payload: []const u8) anyerror![]const u8,
};

/// A `(kind, version)` pair found in the table, for the startup sweep.
pub const StoredKind = struct {
    kind: []const u8,
    version: i32,
};

/// The application's job registry: which kinds this deployment can run, and at which versions.
///
/// Comptime-constructible from a literal (`Registry.init(&.{ ... })`), and validated by the runner at
/// startup, because "unknown kinds fail loudly at startup, not at run time" only holds if something
/// actually looks at the table at startup — which is `checkStored`.
pub const Registry = struct {
    bindings: []const Binding,

    pub fn init(bindings: []const Binding) Registry {
        return .{ .bindings = bindings };
    }

    /// Reject a registry that could not answer a lookup unambiguously. Called at startup; a
    /// duplicate is a deployment bug, and finding it here rather than by watching which of two
    /// functions ran is the difference between a failed boot and a mystery.
    pub fn validate(self: Registry) Error!void {
        for (self.bindings, 0..) |binding, index| {
            if (binding.kind.len == 0) return error.EmptyKind;
            for (self.bindings[0..index]) |earlier| {
                if (earlier.version == binding.version and std.mem.eql(u8, earlier.kind, binding.kind)) {
                    return error.DuplicateKind;
                }
            }
        }
    }

    pub fn find(self: Registry, kind: []const u8, version: i32) ?*const Binding {
        for (self.bindings) |*binding| {
            if (binding.version == version and std.mem.eql(u8, binding.kind, kind)) return binding;
        }

        return null;
    }

    /// Resolve a row's binding, or say precisely what is wrong with it.
    pub fn resolve(self: Registry, kind: []const u8, version: i32) Error!*const Binding {
        if (self.find(kind, version)) |binding| return binding;

        // Distinguish the two failures. "This process has never heard of that kind" and "it knows the
        // kind but not that version" are different operational problems: the first is a missing
        // deployment, the second is a job left over from an older one.
        for (self.bindings) |binding| {
            if (std.mem.eql(u8, binding.kind, kind)) return error.UnsupportedVersion;
        }

        return error.UnknownKind;
    }

    /// The startup sweep: every kind the table holds must resolve. A job whose kind does not is failed
    /// terminally when it is claimed; this is the check that finds it before the queue does.
    pub fn checkStored(self: Registry, stored: []const StoredKind) Error!void {
        for (stored) |entry| _ = try self.resolve(entry.kind, entry.version);
    }
};

/// `system.jobs:<queue>`, allocated from `allocator`.
pub fn principalFor(allocator: std.mem.Allocator, queue: []const u8) std.mem.Allocator.Error![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ principal_prefix, queue });
}

test "a binding is found by kind and version, and the two failures are told apart" {
    const registry = Registry.init(&.{
        .{ .kind = "invoice.send", .version = 1, .run = noop },
        .{ .kind = "invoice.send", .version = 2, .run = noop },
        .{ .kind = "invoice.archive", .version = 1, .run = noop },
    });
    try registry.validate();

    try std.testing.expectEqual(@as(i32, 2), registry.find("invoice.send", 2).?.version);
    try std.testing.expectEqual(@as(i32, 1), registry.find("invoice.archive", 1).?.version);
    try std.testing.expect(registry.find("invoice.send", 3) == null);

    // A kind that was never deployed and a version that predates this deployment are different
    // problems, and the error says which one it is.
    try std.testing.expectError(error.UnknownKind, registry.resolve("invoice.missing", 1));
    try std.testing.expectError(error.UnsupportedVersion, registry.resolve("invoice.send", 7));
}

test "a registry that could answer ambiguously or not at all is rejected at startup" {
    const duplicate = Registry.init(&.{
        .{ .kind = "a", .version = 1, .run = noop },
        .{ .kind = "a", .version = 1, .run = noop },
    });
    try std.testing.expectError(error.DuplicateKind, duplicate.validate());

    // The same kind at two versions is exactly what versioning is for, and is not a duplicate.
    const versioned = Registry.init(&.{
        .{ .kind = "a", .version = 1, .run = noop },
        .{ .kind = "a", .version = 2, .run = noop },
    });
    try versioned.validate();

    const empty = Registry.init(&.{.{ .kind = "", .version = 1, .run = noop }});
    try std.testing.expectError(error.EmptyKind, empty.validate());
}

test "the startup sweep names the row that cannot be resolved" {
    const registry = Registry.init(&.{
        .{ .kind = "invoice.send", .version = 1, .run = noop },
    });

    try registry.checkStored(&.{
        .{ .kind = "invoice.send", .version = 1 },
        .{ .kind = "invoice.send", .version = 1 },
    });
    try std.testing.expectError(error.UnknownKind, registry.checkStored(&.{
        .{ .kind = "invoice.send", .version = 1 },
        .{ .kind = "invoice.cancel", .version = 1 },
    }));
    try std.testing.expectError(error.UnsupportedVersion, registry.checkStored(&.{
        .{ .kind = "invoice.send", .version = 9 },
    }));
}

test "a checkpoint is the only place cancellation is observed" {
    var ctx = Ctx{
        .job_id = 42,
        .attempt = 1,
        .queue = "default",
        .principal = "system.jobs:default",
        .io = std.testing.io,
        .allocator = std.testing.allocator,
        .now_ms = 0,
    };

    // Nothing known: the checkpoint is a no-op and the body continues.
    try ctx.checkpoint();
    try std.testing.expect(!ctx.cancelled());

    // The snapshot is what the body sees; nothing else about the ctx changes.
    ctx.cancel = .{ .ids = &.{ 7, 42 } };
    try std.testing.expect(ctx.cancelled());
    try std.testing.expectError(error.Cancelled, ctx.checkpoint());
}

test "the step hook runs before the cancellation check, so a lease is renewed even on the last step" {
    const Hook = struct {
        var calls: usize = 0;
        fn run(_: ?*anyopaque, ctx: *Ctx) void {
            calls += 1;
            // A hook that learns about a cancellation on this tick makes it visible to this
            // checkpoint, which is the ordering the contract's reaper tick depends on.
            ctx.cancel = .{ .ids = &.{99} };
        }
    };

    Hook.calls = 0;
    var ctx = Ctx{
        .job_id = 99,
        .attempt = 1,
        .queue = "default",
        .principal = "system.jobs:default",
        .io = std.testing.io,
        .allocator = std.testing.allocator,
        .now_ms = 0,
        .on_step = Hook.run,
    };

    try std.testing.expectError(error.Cancelled, ctx.checkpoint());
    try std.testing.expectEqual(@as(usize, 1), Hook.calls);
}

test "a job body runs as the system principal of its queue, never as a user" {
    const allocator = std.testing.allocator;
    const principal = try principalFor(allocator, "mail");
    defer allocator.free(principal);

    try std.testing.expectEqualStrings("system.jobs:mail", principal);
}

fn noop(_: *Ctx, _: []const u8) anyerror![]const u8 {
    return &.{};
}
