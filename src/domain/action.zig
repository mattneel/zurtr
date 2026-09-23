//! `zurtr.domain` actions: an operation declared once, invoked from every
//! surface (HTTP endpoint, live event, job, agent tool).
//!
//! ```zig
//! pub const CreateInvoice = Action(struct {
//!     pub const name = "invoice.create";
//!     pub const version = 1;
//!     pub const Input = struct { customer_id: u64, amount: i64 };
//!     pub const Output = struct { id: u64 };
//!     pub const policy = Policy.all_of(.{ Policy.userRole(0b001) });
//!
//!     pub fn validate(alloc: std.mem.Allocator, input: Input) Validation(Input) { ... }
//!     pub fn run(ctx: *Ctx, input: Input) Error!Output { ... }
//! });
//! ```
//!
//! ## Ordering (normative)
//!
//! 1. **policy** — a denied principal returns `denied` and nothing else: no field
//!    codes, no messages, and (in `invoke`) no decode of the payload either. A
//!    denied caller learns nothing about the input shape.
//! 2. **decode** (`invoke` only) — with the caller-supplied codec; failures
//!    report as a validation error with code `malformed`.
//! 3. **validate** — `Spec.validate` returns field-keyed errors with stable codes.
//! 4. **run** — the operation; its taxonomy errors map onto the matching
//!    `Result` variant and anything unknown becomes `internal`.
//!
//! Authorization is therefore a function of the principal only (see `policy`):
//! input-dependent denials belong in the action body, which returns
//! `error.Denied`.
//!
//! ## Decoding
//!
//! `invoke` takes the codec as a comptime parameter
//! (`fn (std.mem.Allocator, []const u8) anyerror!Input`, see `DecodeFn`), so the
//! domain core has no codec dependency and `invoke` has no indirect call:
//!
//! ```zig
//! const result = CreateInvoice.invoke(&ctx, inv, body, std.json.parseFromSliceLeaky(Input, ...));
//! ```
//! Surfaces that already hold a decoded value call `invokeTyped` directly.

const std = @import("std");
const validation = @import("validation.zig");
const policy = @import("policy.zig");

pub const Principal = policy.Principal;
pub const Policy = policy.Policy;
pub const Decision = policy.Decision;

/// Domain error taxonomy, mapped per surface by `app`/`live`.
pub const Error = error{ Validation, Denied, NotFound, Conflict, Unavailable, Timeout, Internal };

/// The surface an invocation arrived from. It never changes an action's
/// semantics; it exists for observability and surface-specific mapping.
pub const Surface = enum { http, live, job, agent };

/// Everything a surface knows about the call before the action runs. A missing
/// principal is `anonymous`, never absent.
pub const Invocation = struct {
    principal: Principal,
    surface: Surface,
};

/// Minimal logging seam for `Ctx`. `null` in `Ctx` means "no logging".
pub const Logger = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const Level = enum { info, warn, err };

    pub const VTable = struct {
        write: *const fn (ptr: *anyopaque, level: Level, message: []const u8) void,
    };

    pub fn log(self: Logger, level: Level, message: []const u8) void {
        self.vtable.write(self.ptr, level, message);
    }
};

/// Execution context handed to `Spec.run` (and to `Spec.validate` as its
/// allocator). Surfaces build it; actions only read it.
pub const Ctx = struct {
    /// The principal of the invocation. `invoke`/`invokeTyped` stamp this from
    /// `Invocation.principal`, so policy, `run` and nested invocations cannot
    /// observe two different principals for one call.
    principal: Principal,
    /// Owns everything the action allocates for this call.
    allocator: std.mem.Allocator,
    /// Wall clock in milliseconds since the Unix epoch.
    now_ms: i64,
    /// The transaction the surface established, if any: HTTP handlers and job
    /// runners set it, live events set it for transactional actions. Nested
    /// invocations share it, so composite operations stay atomic.
    ///
    /// Opaque at this layer; `txAs` downcasts it.
    tx: ?*anyopaque = null,
    log: ?Logger = null,

    /// Downcasts the opaque transaction handle. `Tx` MUST be the type the
    /// surface established (the data module's `Tx`); any other type reinterprets
    /// the pointer and is a bug.
    pub fn txAs(self: Ctx, comptime Tx: type) ?*Tx {
        const handle = self.tx orelse return null;
        return @ptrCast(@alignCast(handle));
    }
};

/// True when values of `T` can cross a surface boundary as declared data.
///
/// The rule:
///  * `void`, `bool`, integers, floats and enums are allowed; the check recurses
///    into optional payloads, array elements, struct fields (skipping `comptime`
///    fields, which carry no data) and tagged-union fields.
///  * the only allowed pointer is a slice of `u8` — `[]const u8`/`[]u8` with or
///    without a sentinel: string and binary payloads whose lifetime semantics the
///    surface defines.
///  * everything else is rejected: other pointers (including `*T`, `[*]T`,
///    slices of non-`u8`, and function pointers), error sets and error unions,
///    functions, opaque types, vectors, untagged or packed unions, and
///    comptime-only types.
pub fn isSerializable(comptime T: type) bool {
    return switch (@typeInfo(T)) {
        .void, .bool, .int, .float, .@"enum" => true,
        .optional => |optional| isSerializable(optional.child),
        .array => |array| isSerializable(array.child),
        .pointer => |pointer| pointer.size == .slice and pointer.child == u8,
        .@"struct" => |structure| blk: {
            for (structure.field_types, structure.field_attrs) |field_type, attrs| {
                if (attrs.@"comptime") continue;
                if (!isSerializable(field_type)) break :blk false;
            }
            break :blk true;
        },
        .@"union" => |tagged| blk: {
            if (tagged.tag_type == null or tagged.layout == .@"packed") break :blk false;
            for (tagged.field_types) |field_type| {
                if (!isSerializable(field_type)) break :blk false;
            }
            break :blk true;
        },
        else => false,
    };
}

/// An action declared by a spec. See the module docs for the spec shape and for
/// the invocation order.
pub fn Action(comptime Spec: type) type {
    return struct {
        const Self = @This();

        comptime {
            ensureSpec(Spec);
        }

        /// Stable action identifier, e.g. `"invoice.create"`.
        pub const name: []const u8 = Spec.name;
        /// Bumped on incompatible input changes.
        pub const version: u32 = Spec.version;
        pub const Input = Spec.Input;
        /// `void` for actions that produce no value.
        pub const Output = Spec.Output;
        /// The domain error taxonomy actions may fail with.
        pub const errors = Error;
        /// The spec's declared out-of-process effects (`.{ .http, .email }`), if
        /// any; `jobs`/`agents` read this to require recorded results.
        pub const effects = if (@hasDecl(Spec, "effects")) Spec.effects else .{};

        /// The shape `invoke` accepts as its decoder: the application's codec.
        pub const DecodeFn = fn (std.mem.Allocator, []const u8) anyerror!Input;

        pub const Result = union(enum) {
            ok: Output,
            /// Field-keyed input failures. The payload owns its copies: the
            /// caller deinits it. Also used for a payload that could not be
            /// decoded (field `""`, code `malformed`) and for a `run` that
            /// returns `error.Validation` (field `""`, code `invalid`).
            validation: validation.Validation(Input),
            denied,
            not_found,
            conflict,
            unavailable,
            timeout,
            internal,
        };

        /// Invokes the action with an already-decoded input.
        pub fn invokeTyped(ctx: *Ctx, inv: Invocation, input: Input) Result {
            if (!authorize(ctx, inv)) return .denied;
            return validateAndRun(ctx, input);
        }

        /// Invokes the action from raw bytes, decoding with `decode`. Policy runs
        /// before the decoder: the payload of a denied caller is never parsed.
        pub fn invoke(ctx: *Ctx, inv: Invocation, input_bytes: []const u8, comptime decode: anytype) Result {
            comptime ensureDecoder(decode, Input, name);
            if (!authorize(ctx, inv)) return .denied;
            const input = decode(ctx.allocator, input_bytes) catch return .{ .validation = malformed(ctx) };
            return validateAndRun(ctx, input);
        }

        /// Normative ordering, step 1: authorization precedes validation and
        /// decoding, so a denied caller learns nothing about the input shape.
        /// Also stamps `ctx.principal` from the invocation: one principal per
        /// call.
        fn authorize(ctx: *Ctx, inv: Invocation) bool {
            ctx.principal = inv.principal;
            return policy.decide(Spec.policy, inv.principal) == .allow;
        }

        /// Steps 3 and 4: validate, then run.
        fn validateAndRun(ctx: *Ctx, input: Input) Result {
            var checked = Spec.validate(ctx.allocator, input);
            if (!checked.isOk()) return .{ .validation = checked };
            checked.deinit();

            const output = Spec.run(ctx, input) catch |err| return failed(ctx, err);
            return .{ .ok = output };
        }

        /// Maps a `run` failure onto the result. Anything outside the taxonomy
        /// is a bug in the action, so it becomes `internal`.
        fn failed(ctx: *Ctx, err: anyerror) Result {
            return switch (err) {
                error.Denied => .denied,
                error.NotFound => .not_found,
                error.Conflict => .conflict,
                error.Unavailable => .unavailable,
                error.Timeout => .timeout,
                error.Validation => .{ .validation = fieldless(ctx, "invalid", "the action rejected the input") },
                else => .internal,
            };
        }

        fn malformed(ctx: *Ctx) validation.Validation(Input) {
            return fieldless(ctx, "malformed", "the input could not be decoded");
        }

        /// A failure that is not tied to a decoded field: field `""` means "the
        /// input as a whole", and the code carries the meaning.
        fn fieldless(ctx: *Ctx, code: []const u8, message: []const u8) validation.Validation(Input) {
            return validation.Validation(Input).init(ctx.allocator).fail("", code, message);
        }
    };
}

/// Checks the spec shape and the action's static properties. Called from a
/// comptime block, so every failure is a compile error next to the declaration.
fn ensureSpec(comptime Spec: type) void {
    comptime {
        const label = "domain.Action (spec " ++ @typeName(Spec) ++ ")";
        if (@typeInfo(Spec) != .@"struct") {
            @compileError(label ++ ": the spec must be a struct type");
        }
        for (.{ "name", "version", "Input", "Output", "policy", "validate", "run" }) |member| {
            if (!@hasDecl(Spec, member)) {
                @compileError(label ++ ": missing required member `" ++ member ++ "`");
            }
        }

        const action_name: []const u8 = Spec.name;
        if (action_name.len == 0) {
            @compileError(label ++ ": `name` must not be empty");
        }
        if (!isActionName(action_name)) {
            @compileError(label ++ ": `name` \"" ++ action_name ++ "\" must match ^[a-z0-9_.]+$");
        }

        if (!isVersion(Spec.version)) {
            @compileError(label ++ ": `version` must be an integer >= 1 that fits in u32");
        }

        if (@TypeOf(Spec.policy) != Policy) {
            @compileError(label ++ ": `policy` must be a `Policy` value (it is " ++ @typeName(@TypeOf(Spec.policy)) ++
                "); declare one explicitly — a missing policy is a denial, not a default");
        }

        if (!isSerializable(Spec.Input)) {
            @compileError(label ++ ": `Input` carries data the surfaces cannot pass (" ++ @typeName(Spec.Input) ++
                "); only []const u8/[]u8 slices may be borrowed — copy anything else into the action's allocator");
        }
        if (!isSerializable(Spec.Output)) {
            @compileError(label ++ ": `Output` carries data the surfaces cannot pass (" ++ @typeName(Spec.Output) ++
                "); only []const u8/[]u8 slices may be borrowed — copy anything else into the action's allocator");
        }

        const validate_label = label ++ ": `validate` must be `fn (std.mem.Allocator, Input) Validation(Input)`";
        const validate_info = fnInfo(Spec.validate, validate_label);
        if (validate_info.param_types.len != 2) @compileError(validate_label);
        const validate_alloc = validate_info.param_types[0] orelse @compileError(validate_label);
        const validate_input = validate_info.param_types[1] orelse @compileError(validate_label);
        if (validate_alloc != std.mem.Allocator or validate_input != Spec.Input) @compileError(validate_label);
        const validate_ret = validate_info.return_type orelse @compileError(validate_label);
        if (validate_ret != validation.Validation(Spec.Input)) @compileError(validate_label);

        const run_label = label ++ ": `run` must be `fn (*Ctx, Input) Error!Output` with an error set inside the domain taxonomy";
        const run_info = fnInfo(Spec.run, run_label);
        if (run_info.param_types.len != 2) @compileError(run_label);
        const run_ctx = run_info.param_types[0] orelse @compileError(run_label);
        const run_input = run_info.param_types[1] orelse @compileError(run_label);
        if (run_ctx != *Ctx or run_input != Spec.Input) @compileError(run_label);
        const run_ret = run_info.return_type orelse @compileError(run_label);
        const run_union = switch (@typeInfo(run_ret)) {
            .error_union => |union_info| union_info,
            else => @compileError(run_label),
        };
        if (run_union.payload != Spec.Output) @compileError(run_label);
        if (!errorSetFits(run_union.error_set, Error)) @compileError(run_label);
    }
}

/// Action names are identifiers for tools, jobs and audit records, so they are
/// restricted to lowercase ascii, digits, `_` and `.`.
fn isActionName(comptime name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |char| {
        if (!std.ascii.isLower(char) and !std.ascii.isDigit(char) and char != '_' and char != '.') return false;
    }
    return true;
}

/// `version` is a positive integer that fits in `u32`.
fn isVersion(comptime version: anytype) bool {
    return switch (@typeInfo(@TypeOf(version))) {
        .comptime_int => version >= 1 and version <= std.math.maxInt(u32),
        .int => version >= 1 and version <= std.math.maxInt(u32),
        else => false,
    };
}

fn fnInfo(comptime f: anytype, comptime label: []const u8) std.builtin.Type.Fn {
    return switch (@typeInfo(@TypeOf(f))) {
        .@"fn" => |info| info,
        .pointer => |pointer| switch (@typeInfo(pointer.child)) {
            .@"fn" => |info| info,
            else => @compileError(label ++ " (found " ++ @typeName(@TypeOf(f)) ++ ")"),
        },
        else => @compileError(label ++ " (found " ++ @typeName(@TypeOf(f)) ++ ")"),
    };
}

/// True when every error in `Sub` is a member of `Super`. An inferred error set
/// (`anyerror`) does not fit: the taxonomy is closed.
fn errorSetFits(comptime Sub: type, comptime Super: type) bool {
    const sub_names = @typeInfo(Sub).error_set.error_names orelse return false;
    const super_names = @typeInfo(Super).error_set.error_names orelse return false;
    for (sub_names) |name| {
        var found = false;
        for (super_names) |super_name| {
            if (std.mem.eql(u8, name, super_name)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

/// Checks a caller-supplied decoder against `DecodeFn`.
fn ensureDecoder(comptime decode: anytype, comptime Input: type, comptime action_name: []const u8) void {
    comptime {
        const label = "domain.Action(\"" ++ action_name ++ "\").invoke: `decode` must be " ++
            "`fn (std.mem.Allocator, []const u8) anyerror!Input`";
        const info = fnInfo(decode, label);
        if (info.param_types.len != 2) @compileError(label);
        const alloc_param = info.param_types[0] orelse @compileError(label);
        const bytes_param = info.param_types[1] orelse @compileError(label);
        if (alloc_param != std.mem.Allocator or bytes_param != []const u8) @compileError(label);
        const ret = info.return_type orelse @compileError(label);
        const payload = switch (@typeInfo(ret)) {
            .error_union => |union_info| union_info.payload,
            else => @compileError(label),
        };
        if (payload != Input) @compileError(label);
    }
}

const testing = std.testing;

// --- test scaffolding -------------------------------------------------------

var validate_calls: u32 = 0;
var run_calls: u32 = 0;
var decode_calls: u32 = 0;
var seen_now_ms: i64 = 0;
var seen_principal: ?Principal = null;

fn resetProbes() void {
    validate_calls = 0;
    run_calls = 0;
    decode_calls = 0;
    seen_now_ms = 0;
    seen_principal = null;
}

/// Reads `"<customer_id>:<amount>"`, so `invoke`'s decode path is exercised
/// without pulling a codec into the domain core.
fn decodeInvoice(alloc: std.mem.Allocator, bytes: []const u8) anyerror!CreateInvoice.Input {
    _ = alloc;
    decode_calls += 1;
    const separator = std.mem.indexOfScalar(u8, bytes, ':') orelse return error.BadFormat;
    return .{
        .customer_id = try std.fmt.parseInt(u64, bytes[0..separator], 10),
        .amount = try std.fmt.parseInt(i64, bytes[separator + 1 ..], 10),
    };
}

const CreateInvoice = Action(struct {
    pub const name = "invoice.create";
    pub const version = 2;
    pub const Input = struct { customer_id: u64, amount: i64 };
    pub const Output = struct { id: u64, amount: i64 };
    pub const policy = Policy.all_of(.{Policy.userRole(0b001)});

    pub fn validate(alloc: std.mem.Allocator, input: Input) validation.Validation(Input) {
        validate_calls += 1;
        var v = validation.Validation(Input).init(alloc);
        if (input.amount <= 0) v = v.fail("amount", "min", "must be positive");
        return v.ok(input);
    }

    pub fn run(ctx: *Ctx, input: Input) Error!Output {
        run_calls += 1;
        seen_now_ms = ctx.now_ms;
        seen_principal = ctx.principal;
        return .{ .id = input.customer_id * 1000 + @as(u64, @intCast(input.amount)), .amount = input.amount };
    }
});

/// A second action: `Input` of another shape, `Output = void`, declared effects.
const ProbeAction = Action(struct {
    pub const name = "probe.decode";
    pub const version = 1;
    pub const Input = struct { n: u32 };
    pub const Output = void;
    pub const policy = Policy.allow();
    pub const effects = .{ .http, .email };

    pub fn validate(alloc: std.mem.Allocator, input: Input) validation.Validation(Input) {
        return validation.Validation(Input).init(alloc).ok(input);
    }

    pub fn run(ctx: *Ctx, input: Input) Error!Output {
        _ = ctx;
        _ = input;
    }
});

fn decodeCount(alloc: std.mem.Allocator, bytes: []const u8) anyerror!ProbeAction.Input {
    _ = alloc;
    return .{ .n = try std.fmt.parseInt(u32, bytes, 10) };
}

/// Run failures are selected from the test, one taxonomy error at a time.
var next_run_error: ?Error = null;

const FailingAction = Action(struct {
    pub const name = "probe.fail";
    pub const version = 1;
    pub const Input = struct { value: u32 };
    pub const Output = u32;
    pub const policy = Policy.allow();

    pub fn validate(alloc: std.mem.Allocator, input: Input) validation.Validation(Input) {
        return validation.Validation(Input).init(alloc).ok(input);
    }

    pub fn run(ctx: *Ctx, input: Input) Error!Output {
        _ = ctx;
        if (next_run_error) |err| return err;
        return input.value;
    }
});

const Variant = enum { ok, validation, denied, not_found, conflict, unavailable, timeout, internal };

fn variant(result: anytype) Variant {
    return switch (result) {
        .ok => .ok,
        .validation => .validation,
        .denied => .denied,
        .not_found => .not_found,
        .conflict => .conflict,
        .unavailable => .unavailable,
        .timeout => .timeout,
        .internal => .internal,
    };
}

fn authorizedCtx() Ctx {
    return .{
        .principal = .anonymous,
        .allocator = testing.allocator,
        .now_ms = 1_700_000_000_000,
    };
}

const reader: Principal = .{ .user = .{ .id = 4, .roles = 0b001 } };
const stranges: Principal = .{ .user = .{ .id = 5, .roles = 0b100 } };

test "happy path: policy, validation, then run" {
    resetProbes();
    var ctx = authorizedCtx();

    const result = CreateInvoice.invokeTyped(&ctx, .{ .principal = reader, .surface = .http }, .{
        .customer_id = 7,
        .amount = 250,
    });

    switch (result) {
        .ok => |output| {
            try testing.expectEqual(@as(u64, 7250), output.id);
            try testing.expectEqual(@as(i64, 250), output.amount);
        },
        else => return error.ExpectedOk,
    }
    try testing.expectEqual(@as(u32, 1), validate_calls);
    try testing.expectEqual(@as(u32, 1), run_calls);
    // The context reaches `run` unchanged, with the invocation's principal.
    try testing.expectEqual(@as(i64, 1_700_000_000_000), seen_now_ms);
    try testing.expectEqual(reader, seen_principal.?);
}

test "the same action yields the same result on every surface" {
    resetProbes();
    var ctx = authorizedCtx();
    const input = CreateInvoice.Input{ .customer_id = 3, .amount = 5 };

    const from_http = CreateInvoice.invokeTyped(&ctx, .{ .principal = reader, .surface = .http }, input);
    const from_job = CreateInvoice.invokeTyped(&ctx, .{ .principal = reader, .surface = .job }, input);
    const from_agent = CreateInvoice.invokeTyped(&ctx, .{ .principal = reader, .surface = .agent }, input);

    switch (from_http) {
        .ok => |http_output| {
            try testing.expectEqual(http_output.id, from_job.ok.id);
            try testing.expectEqual(http_output.id, from_agent.ok.id);
        },
        else => return error.ExpectedOk,
    }
    try testing.expectEqual(@as(u32, 3), run_calls);
}

test "policy precedes validation: a denied principal learns nothing" {
    resetProbes();
    var ctx = authorizedCtx();

    const result = CreateInvoice.invokeTyped(&ctx, .{ .principal = stranges, .surface = .http }, .{
        .customer_id = 7,
        .amount = -1,
    });

    try testing.expectEqual(Variant.denied, variant(result));
    // Neither validation nor the operation ran, so no field code leaked.
    try testing.expectEqual(@as(u32, 0), validate_calls);
    try testing.expectEqual(@as(u32, 0), run_calls);
}

test "policy precedes decoding: denied bytes are never parsed" {
    resetProbes();
    var ctx = authorizedCtx();

    // Malformed bytes would report `malformed` for an authorized principal;
    // for a denied one the result is a bare denial.
    const denied = CreateInvoice.invoke(&ctx, .{ .principal = stranges, .surface = .job }, "not an invoice", decodeInvoice);
    try testing.expectEqual(Variant.denied, variant(denied));
    try testing.expectEqual(@as(u32, 0), decode_calls);
    try testing.expectEqual(@as(u32, 0), validate_calls);

    const decoded = CreateInvoice.invoke(&ctx, .{ .principal = reader, .surface = .job }, "7:250", decodeInvoice);
    switch (decoded) {
        .ok => |output| try testing.expectEqual(@as(u64, 7250), output.id),
        else => return error.ExpectedOk,
    }
    try testing.expectEqual(@as(u32, 1), decode_calls);
}

test "a payload that cannot be decoded reports a malformed failure" {
    resetProbes();
    var ctx = authorizedCtx();

    const result = CreateInvoice.invoke(&ctx, .{ .principal = reader, .surface = .http }, "garbage", decodeInvoice);
    switch (result) {
        .validation => |payload| {
            var errors = payload;
            defer errors.deinit();
            try testing.expectEqual(@as(usize, 1), errors.errors().len);
            try testing.expectEqualStrings("", errors.errors()[0].field);
            try testing.expectEqualStrings("malformed", errors.errors()[0].code);
            // Nothing was decoded, so no input is carried.
            try testing.expectEqual(@as(?CreateInvoice.Input, null), errors.value());
        },
        else => return error.ExpectedValidation,
    }
    try testing.expectEqual(@as(u32, 1), decode_calls);
    try testing.expectEqual(@as(u32, 0), validate_calls);
    try testing.expectEqual(@as(u32, 0), run_calls);
}

test "validation failures are field-keyed and stop before run" {
    resetProbes();
    var ctx = authorizedCtx();

    const result = CreateInvoice.invokeTyped(&ctx, .{ .principal = reader, .surface = .live }, .{
        .customer_id = 7,
        .amount = 0,
    });

    switch (result) {
        .validation => |payload| {
            var errors = payload;
            defer errors.deinit();
            try testing.expectEqual(@as(usize, 1), errors.errors().len);
            try testing.expectEqualStrings("amount", errors.errors()[0].field);
            try testing.expectEqualStrings("min", errors.errors()[0].code);
            try testing.expect(!errors.isOk());
        },
        else => return error.ExpectedValidation,
    }
    try testing.expectEqual(@as(u32, 1), validate_calls);
    try testing.expectEqual(@as(u32, 0), run_calls);
}

test "run failures map onto the taxonomy" {
    const cases = [_]struct { err: Error, expected: Variant }{
        .{ .err = error.Denied, .expected = .denied },
        .{ .err = error.NotFound, .expected = .not_found },
        .{ .err = error.Conflict, .expected = .conflict },
        .{ .err = error.Unavailable, .expected = .unavailable },
        .{ .err = error.Timeout, .expected = .timeout },
        .{ .err = error.Internal, .expected = .internal },
    };
    var ctx = authorizedCtx();

    for (cases) |case| {
        next_run_error = case.err;
        const result = FailingAction.invokeTyped(&ctx, .{ .principal = reader, .surface = .job }, .{ .value = 1 });
        try testing.expectEqual(case.expected, variant(result));
    }

    // A `run` that fails validation without field data still surfaces as a
    // validation failure (surfaces map it to 422), not as an internal error.
    next_run_error = error.Validation;
    const rejected = FailingAction.invokeTyped(&ctx, .{ .principal = reader, .surface = .job }, .{ .value = 1 });
    switch (rejected) {
        .validation => |payload| {
            var errors = payload;
            defer errors.deinit();
            try testing.expectEqual(@as(usize, 1), errors.errors().len);
            try testing.expectEqualStrings("", errors.errors()[0].field);
            try testing.expectEqualStrings("invalid", errors.errors()[0].code);
        },
        else => return error.ExpectedValidation,
    }
    next_run_error = null;
}

test "generated surface reflects the spec" {
    comptime {
        if (!std.mem.eql(u8, "invoice.create", CreateInvoice.name)) @compileError("name must come from the spec");
        if (CreateInvoice.version != 2) @compileError("version must come from the spec");
        if (@typeInfo(CreateInvoice.Input).@"struct".field_names.len != 2) {
            @compileError("Input must come from the spec");
        }
        if (CreateInvoice.errors != Error) @compileError("errors exposes the domain taxonomy");
        if (@sizeOf(@TypeOf(CreateInvoice.effects)) != 0) @compileError("a spec without effects declares none");
        if (@typeInfo(@TypeOf(ProbeAction.effects)).@"struct".field_names.len != 2) {
            @compileError("a spec's effects must be forwarded");
        }
        if (ProbeAction.Output != void) @compileError("void outputs are allowed");
    }
}

test "ctx exposes the transaction handle and the logger seam" {
    var tx: u64 = 42;
    var ctx = Ctx{
        .principal = .anonymous,
        .allocator = testing.allocator,
        .now_ms = 0,
        .tx = &tx,
        .log = .{ .ptr = &tx, .vtable = &.{ .write = captureLog } },
    };

    try testing.expectEqual(@as(?*u64, &tx), ctx.txAs(u64));

    var no_tx = ctx;
    no_tx.tx = null;
    try testing.expectEqual(@as(?*u64, null), no_tx.txAs(u64));

    ctx.log.?.log(.info, "invoice.created");
    try testing.expectEqualStrings("invoice.created", logged[0..logged_len]);
}

var logged: [32]u8 = undefined;
var logged_len: usize = 0;

fn captureLog(ptr: *anyopaque, level: Logger.Level, message: []const u8) void {
    _ = ptr;
    _ = level;
    @memcpy(logged[0..message.len], message);
    logged_len = message.len;
}

test "the serializability guard accepts plain data" {
    const Address = struct { street: []const u8, zip: u32 };
    const Status = enum(u8) { draft, sent };
    const Payload = union(enum) { none, note: []const u8 };

    comptime {
        if (!isSerializable(void)) @compileError("void is serializable");
        if (!isSerializable(u64)) @compileError("integers are serializable");
        if (!isSerializable(f64)) @compileError("floats are serializable");
        if (!isSerializable(bool)) @compileError("bools are serializable");
        if (!isSerializable(Status)) @compileError("enums are serializable");
        if (!isSerializable([]const u8)) @compileError("byte slices are serializable");
        if (!isSerializable([]u8)) @compileError("mutable byte slices are serializable");
        if (!isSerializable(?[]const u8)) @compileError("optional payloads are checked recursively");
        if (!isSerializable([4]u8)) @compileError("byte arrays are serializable");
        if (!isSerializable(Address)) @compileError("structs are checked recursively");
        if (!isSerializable(Payload)) @compileError("tagged unions are checked recursively");
        if (!isSerializable(struct { id: u64, when: i64, tags: [2][]const u8 })) {
            @compileError("arrays of byte slices are serializable");
        }
        if (!isSerializable(struct { comptime marker: type = u8, value: u32 })) {
            @compileError("comptime fields carry no data and are skipped");
        }
    }
}

test "the serializability guard rejects borrowed pointers and non-data types" {
    const Untagged = extern union { a: u32, b: f32 };
    const Callback = *const fn (u32) void;
    const Foreign = struct { rows: []const []const u8 };

    comptime {
        if (isSerializable(*const u8)) @compileError("single-item pointers are rejected");
        if (isSerializable([*]const u8)) @compileError("many-item pointers are rejected");
        if (isSerializable([]const u64)) @compileError("non-byte slices are rejected");
        if (isSerializable([]const []const u8)) @compileError("slices of slices are rejected");
        if (isSerializable(?*u64)) @compileError("optional pointers are rejected");
        if (isSerializable(Foreign)) @compileError("nested non-byte slices are rejected");
        if (isSerializable(std.mem.Allocator)) @compileError("vtables are rejected");
        if (isSerializable(Callback)) @compileError("function pointers are rejected");
        if (isSerializable(Error)) @compileError("error sets are rejected");
        if (isSerializable(Error!u32)) @compileError("error unions are rejected");
        if (isSerializable(anyopaque)) @compileError("opaque types are rejected");
        if (isSerializable(@Vector(2, f32))) @compileError("vectors are rejected");
        if (isSerializable(Untagged)) @compileError("untagged unions are rejected");
        if (isSerializable([]const u8)) {} else @compileError("byte slices stay accepted");
    }
}

test "the spec guards accept valid declarations and reject invalid ones" {
    comptime {
        if (!isActionName("invoice.create")) @compileError("dotted names are valid");
        if (!isActionName("invoice_create_v2")) @compileError("underscores and digits are valid");
        if (isActionName("")) @compileError("empty names are invalid");
        if (isActionName("Invoice.create")) @compileError("uppercase names are invalid");
        if (isActionName("invoice-create")) @compileError("dashes are invalid");
        if (isActionName("invoice create")) @compileError("spaces are invalid");
        if (isActionName("invoice.cre\u{00e9}te")) @compileError("non-ascii names are invalid");

        if (!isVersion(1)) @compileError("version 1 is valid");
        if (!isVersion(@as(u32, 7))) @compileError("u32 versions are valid");
        if (isVersion(0)) @compileError("version 0 is invalid");
        if (isVersion(-1)) @compileError("negative versions are invalid");
        if (isVersion(std.math.maxInt(u32) + 1)) @compileError("versions must fit in u32");
        if (isVersion(1.5)) @compileError("versions are integers");

        if (!errorSetFits(error{NotFound}, Error)) @compileError("taxonomy subsets fit");
        if (!errorSetFits(Error, Error)) @compileError("the taxonomy fits itself");
        if (errorSetFits(error{Syntax}, Error)) @compileError("outside errors do not fit");
        if (errorSetFits(anyerror, Error)) @compileError("the taxonomy is closed");
    }

    // The checks above are the predicates `ensureSpec` rejects specs with: a
    // spec that violates them fails to compile, which this Zig version cannot
    // assert from a test (std.testing has no `expectCompileError`), so the
    // predicates are exercised directly. The positive half of the same guarantee
    // is that the specs in this file instantiate at all.
    comptime {
        if (!isSerializable(CreateInvoice.Input)) @compileError("a valid spec's Input passes the guard");
        if (!isSerializable(CreateInvoice.Output)) @compileError("a valid spec's Output passes the guard");
    }
}

test "invoke decodes with the caller's codec" {
    var ctx = authorizedCtx();
    const bytes = "1234";

    const result = ProbeAction.invoke(&ctx, .{ .principal = reader, .surface = .agent }, bytes, decodeCount);
    switch (result) {
        .ok => {},
        else => return error.ExpectedOk,
    }
}
