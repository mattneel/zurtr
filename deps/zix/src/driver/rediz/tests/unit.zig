//! rediz unit test root: no server needed.
//!
//! Note:
//! - Pulls every in-file test of the module through the root import, the
//!   scripted mock-server scenarios live next to the code they test.

const std = @import("std");
const rediz = @import("rediz");

test {
    std.testing.refAllDecls(rediz);
    _ = rediz;
}
