//! zurtr — a native application framework built on zix.
//!
//! Seven modules, compiled only when used:
//!   Application, Live UI, Domain, Data, Jobs, Agents, Development.
//!
//! Nothing is implemented yet beyond the vendored transport; this root file is
//! the seam where the module surface lands.

const std = @import("std");

/// Vendored zix transport (deps/zix): HTTP/1.1 and HTTP/3 on one origin, WebTransport for the live
/// channel, and the in-tree drivers (`postgrez`, `rediz`) the data module builds on. Re-exported so
/// applications and modules above the framework can reach transport types without a direct dependency
/// on the vendored path.
pub const zix = @import("zix");

/// Shared runtime primitives (ownership, pools, ids, clocks).
pub const runtime = struct {
    pub const pool = @import("runtime/pool.zig");
    /// Bounded lock-free multi-producer multi-consumer queue: the substrate under per-worker queues,
    /// work stealing, and cross-worker completion delivery.
    pub const mpmc = @import("runtime/mpmc.zig");
    pub const task = @import("runtime/task.zig");
};

/// Live UI: session state, events, render/patch, protocol.
pub const live = struct {
    pub const protocol = @import("live/protocol.zig");
    /// The worker's bus: sessions subscribe to topics, committed writes publish to them.
    pub const pubsub = @import("live/pubsub.zig");
    /// The render tree a generated template writes into. ZEEX names this in every file it emits
    /// (`zurtr.live.tree.Builder`), so it is not an internal detail of this namespace: moving it
    /// breaks templates, not just callers.
    pub const tree = @import("live/tree.zig");
};

/// Domain: resources, typed actions, validation, authorization, relationships.
///
/// The code lives in `src/domain/`; this export is what makes it reachable, and what makes the module
/// inventory below agree with the tree.
pub const domain = struct {
    pub const action = @import("domain/action.zig");
    pub const policy = @import("domain/policy.zig");
    pub const validation = @import("domain/validation.zig");
};

/// ZScript: the QuickJS seam. Behavior the host can replace without a native rebuild.
///
/// The engine is behind `-Dzscript`; the seam's own types do not need it, so a build that never asks
/// for the engine never pays for one.
pub const zscript = @import("zscript");

/// ZEEX: JSX templates lowered to Zig at build time, by a script the vendored engine runs.
///
/// The compiler needs the script engine, so it is reachable only in builds that have one; the generated
/// code needs nothing but this framework.
pub const zeex = if (@import("build_options").zscript) @import("zeex/compile.zig") else struct {};

/// Data: queries, transactions, migrations, adapters.
///
/// The adapter itself is `data.turso`, which needs the vendored binding; the contract types here
/// (`Value`, `Tier`, `Database`, `Tx`) do not, so a build that never asks for an adapter never pays
/// for one.
pub const data = @import("data/root.zig");

/// Jobs: durable queues, schedules, retries, concurrency, cancellation.
///
/// The queue needs the data contract's types and nothing else — the adapter that stores it is chosen by
/// the application — so a build without one still compiles this module. Its database-backed tests are
/// compiled only when the adapter is built, because that is when there is a binding to test against.
pub const jobs = @import("jobs/root.zig");

/// What this build contains, for `zurtr modules` and `zurtr build --report`.
///
/// The architecture names eight modules; this table says which of them exist in
/// the tree and which are still declarations. It is a status report, not a
/// feature list: a module moves to `.implemented` when its first real surface
/// lands, and the inventory is read from here rather than maintained twice.
pub const Module = struct {
    name: []const u8,
    state: State,
    surface: []const u8,

    pub const State = enum {
        /// Declared in `docs/architecture/overview.md` only.
        declared,
        /// Has real code in the tree, named in `surface`.
        implemented,
    };
};

pub const modules = [_]Module{
    .{ .name = "runtime", .state = .implemented, .surface = "pool" },
    .{ .name = "live", .state = .implemented, .surface = "protocol" },
    .{ .name = "data", .state = .implemented, .surface = "contract + Turso adapter (memory, file, sync, distributed)" },
    .{ .name = "domain", .state = .implemented, .surface = "resources, typed actions, validation, authorization" },
    .{ .name = "jobs", .state = .implemented, .surface = "durable queue, schedules, retries, cancellation" },
    .{ .name = "agents", .state = .declared, .surface = "signals, decisions, effects, checkpoints" },
    .{ .name = "app", .state = .declared, .surface = "config, routes, middleware, auth, lifecycle" },
    .{ .name = "dev", .state = .declared, .surface = "incremental builds, reload, diagnostics, tests" },
};

test "zurtr module builds and links the transport" {
    try std.testing.expect(@sizeOf(zix.Http.Request) > 0);
}

test {
    _ = runtime.pool;
    _ = runtime.mpmc;
    _ = runtime.task;
    _ = live.protocol;
    _ = live.pubsub;
    _ = live.tree;
    _ = data;
    _ = domain;
    _ = jobs;
    if (comptime @import("build_options").zscript) _ = zeex;

    // ZEEX writes `@import("zurtr")` and `zurtr.live.tree.Builder` into every generated file, and its
    // own test can only parse that output for syntax — a semantic lookup fails in a user's build, not
    // in the compiler's test. So the names it depends on are checked here, where both sides are visible.
    comptime {
        if (!@hasDecl(live, "tree")) @compileError("zeex emits zurtr.live.tree.Builder, but live has no `tree`");
        if (!@hasDecl(live.tree, "Builder")) @compileError("zeex emits zurtr.live.tree.Builder, but there is no `Builder`");
    }
}
