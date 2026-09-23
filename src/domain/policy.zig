//! `zurtr.domain` authorization: principals, policies and read predicates.
//!
//! ## Design
//!
//! A `Policy` is a plain, allocation-free value with four parts:
//!
//! * `fallback` — the decision when nothing else applies. `Policy{}` is `.deny`,
//!   so a resource or action that forgets to authorize denies by default.
//! * `rule` — a comptime-known `*const fn (Principal) Decision`.
//! * `predicate` — a comptime-known `*const fn (Principal, scratch) ?Query`
//!   that narrows a read to the rows the principal may see.
//! * `children` — conjuncts, evaluated in declaration order.
//!
//! There is no vtable, no allocation and no closure: rule and predicate
//! functions are plain functions, and anything that needs configuration bakes it
//! in at comptime (`userRole(0b010)`, `all_of(.{ ... })`). Because a decision is a
//! function of the *principal alone*, an invocation can be denied before its
//! payload is decoded or validated — a denied caller learns nothing at all.
//! Authorization that depends on the input belongs in the action body, which
//! returns `error.Denied`.
//!
//! Evaluation precedence, used by `decide`: children (conjunction, first denial
//! wins and later children are not consulted), then `rule`, then `fallback`.
//! `all_of` builds the conjunction case; its result is comptime-foldable when
//! its inputs are, so `comptime decide(...)` works.

const std = @import("std");

/// Identity behind an invocation. A missing principal is `anonymous` and is
/// never absent.
pub const Principal = union(enum) {
    anonymous,
    user: struct {
        id: u64,
        /// Application-defined role bitmask.
        roles: u16,
    },
    service: struct { name: []const u8 },
    system: struct { role: []const u8 },
};

/// The outcome of a policy evaluation. `Decision` names the *operation*
/// decision; a `deny` must never carry details about what was denied.
pub const Decision = enum { allow, deny };

/// Parameter binding for SQL predicates. Mirrors `zurtr.data.Param`; it is
/// defined here so `policy` has no dependency on the data module, and the data
/// module maps its own `Param` into this one.
pub const Param = union(enum) {
    null,
    bool: bool,
    int: i64,
    float: f64,
    text: []const u8,
    bytes: []const u8,
    uuid: [16]u8,
    timestamp_micros: i64,
};

/// An authorization policy. See the module docs for the design.
pub const Policy = struct {
    const Self = @This();

    /// SQL predicate for the read-authorization path: a fragment ANDed into the
    /// resource query plus the parameters it references.
    pub const Query = struct {
        /// SQL fragment, e.g. `"tenant_id = $1"`.
        sql: []const u8,
        /// Values bound to the fragment's placeholders, in order.
        params: []const Param,

        /// The predicate of a policy that authorizes every row.
        pub const tautology: Query = .{ .sql = "true", .params = &.{} };
    };

    /// A decision function of the principal.
    pub const RuleFn = *const fn (Principal) Decision;

    /// A row filter. `scratch` is caller-provided storage for the returned
    /// query's parameters (see `sqlPredicate`); returning `null` means the
    /// principal has no authorized row set, and the read is denied.
    pub const PredicateFn = *const fn (Principal, scratch: []Param) ?Query;

    /// Decision when there are neither children nor a rule. Deny, so a default
    /// value denies.
    fallback: Decision = .deny,
    /// Principal predicate, when the policy was built by `check`/`userRole`.
    rule: ?RuleFn = null,
    /// Row filter, when the policy was built by `filter`.
    predicate: ?PredicateFn = null,
    /// Conjuncts, in evaluation order; built by `all_of`.
    children: []const Policy = &.{},

    /// Denies every principal: the default policy.
    pub fn deny() Self {
        return .{};
    }

    /// Allows every principal, including `anonymous`. Use explicitly for public
    /// resources and tools; it is never a default.
    pub fn allow() Self {
        return .{ .fallback = .allow };
    }

    /// The conjunction of `policies` (a tuple literal, e.g.
    /// `all_of(.{ a, b })`): allows only if every conjunct allows. Conjuncts are
    /// evaluated in order and the first denial short-circuits the rest.
    ///
    /// At most one conjunct may carry a SQL predicate (checked at comptime): the
    /// read path ANDs a single predicate into the query, so a conjunction of row
    /// filters is written as one predicate function. The empty conjunction
    /// allows.
    pub fn all_of(comptime policies: anytype) Self {
        const Children = struct {
            const items: [policies.len]Policy = blk: {
                var out: [policies.len]Policy = undefined;
                for (policies, 0..) |p, i| {
                    if (@TypeOf(p) != Policy) {
                        @compileError("domain.policy.all_of expects Policy values; element " ++
                            std.fmt.comptimePrint("{d}", .{i}) ++ " is " ++ @typeName(@TypeOf(p)));
                    }
                    out[i] = p;
                }
                break :blk out;
            };
        };
        const conjunction: Self = comptime .{ .fallback = .allow, .children = &Children.items };
        comptime {
            if (predicateCount(conjunction) > 1) {
                @compileError("domain.policy.all_of: at most one conjunct may carry a SQL predicate; " ++
                    "combine row filters inside a single `filter` predicate function");
            }
        }
        return conjunction;
    }

    /// A policy that decides with `rule`, a plain function of the principal.
    pub fn check(comptime rule: RuleFn) Self {
        return .{ .rule = rule };
    }

    /// Allows `user` principals whose role bitmask intersects `mask`; denies
    /// `anonymous`, `service` and `system` principals.
    pub fn userRole(comptime mask: u16) Self {
        const Rules = struct {
            fn decide(principal: Principal) Decision {
                return switch (principal) {
                    .user => |u| if (u.roles & mask != 0) .allow else .deny,
                    else => .deny,
                };
            }
        };
        return .{ .rule = &Rules.decide };
    }

    /// A read policy: admits the principal and narrows the read to the rows
    /// `predicate` selects. A predicate that returns `null` (no authorized row
    /// set) denies the read.
    pub fn filter(comptime predicate: PredicateFn) Self {
        return .{ .fallback = .allow, .predicate = predicate };
    }

    /// The read-authorization predicate for `principal`, or `null` when the read
    /// must be denied.
    ///
    /// `null` never means "no filter": the caller must return zero rows (a denied
    /// read is not an error at the data layer) and must never run the query
    /// unfiltered. A non-null result is ANDed into the query before `order
    /// by`/`limit`; it is `Query.tautology` when the policy allows every row.
    ///
    /// Parameters are written into `scratch`, which the returned query borrows,
    /// so `scratch` must outlive the query; size it for the largest predicate in
    /// use (every policy builds its own query, so one buffer is enough).
    pub fn sqlPredicate(self: Self, principal: Principal, scratch: []Param) ?Query {
        if (decide(self, principal) == .deny) return null;
        if (self.predicate) |predicate| return predicate(principal, scratch);
        for (self.children) |child| {
            if (child.hasPredicate()) return child.sqlPredicate(principal, scratch);
        }
        return Query.tautology;
    }

    /// True when this policy (or a conjunct of it) narrows a read.
    pub fn hasPredicate(self: Self) bool {
        if (self.predicate != null) return true;
        for (self.children) |child| {
            if (child.hasPredicate()) return true;
        }
        return false;
    }
};

/// Evaluates `policy` for `principal`: conjuncts in order (short-circuiting on
/// the first denial), then the policy's rule, then its fallback.
pub fn decide(policy: Policy, principal: Principal) Decision {
    if (policy.children.len != 0) {
        for (policy.children) |child| {
            if (decide(child, principal) == .deny) return .deny;
        }
        return .allow;
    }
    if (policy.rule) |rule| return rule(principal);
    return policy.fallback;
}

/// Number of SQL predicates in a policy tree. `all_of` uses it to keep the read
/// path to a single predicate, and `sqlPredicate` relies on that count when it
/// descends into conjuncts.
fn predicateCount(policy: Policy) usize {
    var count: usize = if (policy.predicate != null) 1 else 0;
    for (policy.children) |child| count += predicateCount(child);
    return count;
}

const testing = std.testing;

/// Records which rules were consulted, so short-circuiting is observable.
var consulted: [8]u8 = undefined;
var consulted_len: usize = 0;

fn resetConsulted() void {
    consulted_len = 0;
}

fn note(tag: u8) void {
    consulted[consulted_len] = tag;
    consulted_len += 1;
}

fn allowA(principal: Principal) Decision {
    _ = principal;
    note('a');
    return .allow;
}

fn denyB(principal: Principal) Decision {
    _ = principal;
    note('b');
    return .deny;
}

fn allowC(principal: Principal) Decision {
    _ = principal;
    note('c');
    return .allow;
}

fn systemMaintenance(principal: Principal) Decision {
    return switch (principal) {
        .system => |s| if (std.mem.eql(u8, s.role, "maintenance")) .allow else .deny,
        else => .deny,
    };
}

fn ownerFilter(principal: Principal, scratch: []Param) ?Policy.Query {
    const user = switch (principal) {
        .user => |u| u,
        else => return null,
    };
    if (scratch.len < 1) return null;
    scratch[0] = .{ .int = @intCast(user.id) };
    return .{ .sql = "owner_id = $1", .params = scratch[0..1] };
}

fn tracedOwnerFilter(principal: Principal, scratch: []Param) ?Policy.Query {
    note('f');
    return ownerFilter(principal, scratch);
}

test "deny is the default and admits nobody" {
    const principals = [_]Principal{
        .anonymous,
        .{ .user = .{ .id = 1, .roles = 0xffff } },
        .{ .service = .{ .name = "billing" } },
        .{ .system = .{ .role = "maintenance" } },
    };
    var scratch: [1]Param = undefined;

    for (principals) |principal| {
        try testing.expectEqual(Decision.deny, decide(Policy{}, principal));
        try testing.expectEqual(Decision.deny, decide(Policy.deny(), principal));
        try testing.expect(Policy.deny().sqlPredicate(principal, &scratch) == null);
    }
}

test "allow admits every principal kind and filters nothing" {
    const principals = [_]Principal{
        .anonymous,
        .{ .user = .{ .id = 1, .roles = 0 } },
        .{ .service = .{ .name = "billing" } },
        .{ .system = .{ .role = "maintenance" } },
    };
    var scratch: [1]Param = undefined;

    for (principals) |principal| {
        try testing.expectEqual(Decision.allow, decide(Policy.allow(), principal));
        const query = Policy.allow().sqlPredicate(principal, &scratch).?;
        try testing.expectEqualStrings("true", query.sql);
        try testing.expectEqual(@as(usize, 0), query.params.len);
        try testing.expect(!Policy.allow().hasPredicate());
    }
}

test "all_of is a conjunction that short-circuits on the first denial" {
    const conjunction = Policy.all_of(.{ Policy.check(&allowA), Policy.check(&denyB), Policy.check(&allowC) });

    resetConsulted();
    try testing.expectEqual(Decision.deny, decide(conjunction, .anonymous));
    // `c` is never consulted: denial short-circuits.
    try testing.expectEqualStrings("ab", consulted[0..consulted_len]);

    resetConsulted();
    const all_allow = Policy.all_of(.{ Policy.check(&allowA), Policy.check(&allowC) });
    try testing.expectEqual(Decision.allow, decide(all_allow, .anonymous));
    try testing.expectEqualStrings("ac", consulted[0..consulted_len]);

    try testing.expectEqual(Decision.allow, decide(Policy.all_of(.{}), .anonymous));
    try testing.expectEqual(Decision.deny, decide(Policy.all_of(.{ Policy.allow(), Policy.deny() }), .anonymous));
}

test "userRole gates on the role bitmask" {
    const readers = Policy.userRole(0b010);

    try testing.expectEqual(Decision.allow, decide(readers, .{ .user = .{ .id = 7, .roles = 0b110 } }));
    try testing.expectEqual(Decision.deny, decide(readers, .{ .user = .{ .id = 7, .roles = 0b001 } }));
    try testing.expectEqual(Decision.deny, decide(readers, .anonymous));
    try testing.expectEqual(Decision.deny, decide(readers, .{ .service = .{ .name = "billing" } }));
    try testing.expectEqual(Decision.deny, decide(readers, .{ .system = .{ .role = "maintenance" } }));
}

test "check accepts an application rule over every principal kind" {
    try testing.expectEqual(Decision.allow, decide(Policy.check(&systemMaintenance), .{ .system = .{ .role = "maintenance" } }));
    try testing.expectEqual(Decision.deny, decide(Policy.check(&systemMaintenance), .{ .system = .{ .role = "app" } }));
    try testing.expectEqual(Decision.deny, decide(Policy.check(&systemMaintenance), .{ .user = .{ .id = 1, .roles = 0xffff } }));
}

test "filter narrows the read with a borrowed parameter buffer" {
    const policy = Policy.filter(&ownerFilter);
    const principal: Principal = .{ .user = .{ .id = 7, .roles = 0 } };
    var scratch: [2]Param = @splat(.null);

    try testing.expectEqual(Decision.allow, decide(policy, principal));
    const query = policy.sqlPredicate(principal, &scratch).?;
    try testing.expectEqualStrings("owner_id = $1", query.sql);
    try testing.expectEqual(@as(usize, 1), query.params.len);
    try testing.expectEqual(Param{ .int = 7 }, query.params[0]);
    try testing.expectEqual(Param{ .int = 7 }, scratch[0]);
    try testing.expect(policy.hasPredicate());
}

test "a filter with no authorized row set denies the read" {
    const policy = Policy.filter(&ownerFilter);
    var scratch: [1]Param = undefined;

    // The principal passes the (permissive) policy, but the predicate cannot
    // select a row set for it: the read must be denied, not widened.
    try testing.expectEqual(Decision.allow, decide(policy, .anonymous));
    try testing.expect(policy.sqlPredicate(.anonymous, &scratch) == null);
}

test "a denied policy never consults its predicate" {
    const policy = Policy.all_of(.{ Policy.deny(), Policy.filter(&tracedOwnerFilter) });
    var scratch: [1]Param = undefined;

    resetConsulted();
    try testing.expect(policy.sqlPredicate(.{ .user = .{ .id = 3, .roles = 0 } }, &scratch) == null);
    try testing.expectEqual(@as(usize, 0), consulted_len);
}

test "a conjunction keeps its single predicate and its rule decision" {
    const policy = Policy.all_of(.{ Policy.userRole(0b001), Policy.filter(&ownerFilter) });
    var scratch: [1]Param = undefined;

    const authorized: Principal = .{ .user = .{ .id = 9, .roles = 0b001 } };
    try testing.expectEqual(Decision.allow, decide(policy, authorized));
    const query = policy.sqlPredicate(authorized, &scratch).?;
    try testing.expectEqualStrings("owner_id = $1", query.sql);
    try testing.expectEqual(Param{ .int = 9 }, query.params[0]);

    // The rule denies, so the predicate is never reached and the read is denied.
    const unauthorized: Principal = .{ .user = .{ .id = 9, .roles = 0b100 } };
    try testing.expectEqual(Decision.deny, decide(policy, unauthorized));
    try testing.expect(policy.sqlPredicate(unauthorized, &scratch) == null);
}

test "the predicate budget counts nested conjuncts" {
    const nested = comptime Policy.all_of(.{
        Policy.all_of(.{ Policy.filter(&ownerFilter), Policy.allow() }),
        Policy.userRole(0b001),
    });

    // The comptime guard in `all_of` rejects a second predicate; this asserts the
    // counting it relies on (std.testing has no `expectCompileError` in this Zig
    // version, so the rejection itself cannot be exercised from a test).
    comptime {
        if (predicateCount(nested) != 1) {
            @compileError("predicateCount must see the nested conjunct's predicate");
        }
        if (predicateCount(Policy.all_of(.{ Policy.filter(&ownerFilter), Policy.allow() })) != 1) {
            @compileError("predicateCount must count a direct predicate");
        }
        if (predicateCount(Policy.allow()) != 0) {
            @compileError("predicateCount must ignore predicate-free policies");
        }
    }

    var scratch: [1]Param = undefined;
    const authorized: Principal = .{ .user = .{ .id = 4, .roles = 0b001 } };
    try testing.expectEqualStrings("owner_id = $1", nested.sqlPredicate(authorized, &scratch).?.sql);
}

test "decisions fold at comptime for comptime-known inputs" {
    comptime {
        if (decide(Policy.deny(), .anonymous) != .deny) @compileError("deny must fold");
        if (decide(Policy.allow(), .anonymous) != .allow) @compileError("allow must fold");
        if (decide(Policy.userRole(0b1), .{ .user = .{ .id = 1, .roles = 0b1 } }) != .allow) {
            @compileError("userRole must fold");
        }
        if (decide(Policy.all_of(.{ Policy.allow(), Policy.deny() }), .anonymous) != .deny) {
            @compileError("all_of must fold");
        }
    }
}
