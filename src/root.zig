//! zurtr — a native application framework built on swerver.
//!
//! Seven modules, compiled only when used:
//!   Application, Live UI, Domain, Data, Jobs, Agents, Development.
//!
//! Nothing is implemented yet beyond the vendored transport; this root file is
//! the seam where the module surface lands.

const std = @import("std");

/// Vendored swerver transport (deps/swerver). Re-exported so applications and
/// modules above the framework can reach transport types without a direct
/// dependency on the vendored path.
pub const swerver = @import("swerver");

test "zurtr module builds and links swerver" {
    try std.testing.expect(@sizeOf(swerver.response.Response) > 0);
}
