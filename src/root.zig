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
};

/// Live UI: session state, events, render/patch, protocol.
pub const live = struct {
    pub const protocol = @import("live/protocol.zig");
    /// The worker's bus: sessions subscribe to topics, committed writes publish to them.
    pub const pubsub = @import("live/pubsub.zig");
};

/// Script: the QuickJS seam. Behavior the host can replace without a native rebuild.
///
/// The engine is behind `-Dscript`; the seam's own types do not need it, so a build that never asks
/// for the engine never pays for one.
pub const script = @import("script/root.zig");

/// Data: queries, transactions, migrations, adapters.
///
/// The adapter itself is `data.turso`, which needs the vendored binding; the contract types here
/// (`Value`, `Tier`, `Database`, `Tx`) do not, so a build that never asks for an adapter never pays
/// for one.
pub const data = @import("data/root.zig");

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
    .{ .name = "domain", .state = .declared, .surface = "resources, typed actions, validation, authorization" },
    .{ .name = "jobs", .state = .declared, .surface = "durable queues, schedules, retries, cancellation" },
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
    _ = live.protocol;
    _ = live.pubsub;
    _ = data;
}
