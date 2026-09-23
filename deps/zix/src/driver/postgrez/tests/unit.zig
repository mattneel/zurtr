//! postgrez unit test root: no server needed.
//!
//! Note:
//! - Pulls every in-file test of the module through the root import, plus
//!   the scripted mock-backend scenarios that live here.

const std = @import("std");
const postgrez = @import("postgrez");

test {
    std.testing.refAllDecls(postgrez);
    _ = postgrez;
}
