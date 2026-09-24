# Module contract: Domain (`zurtr.domain`)

Scope: resources, typed actions, validation, authorization, relationships.
The domain is where an application's operations are declared once and reused by
every surface (HTTP endpoint, live event, job, agent tool).

Status: the three files that exist are implemented and exported —
`src/domain/action.zig` (`Action`, `Ctx`, `Invocation`, `Result`),
`src/domain/policy.zig` (`Principal`, `Policy`, `decide`) and
`src/domain/validation.zig` (`Validation`) — and `src/root.zig` reaches them as
`zurtr.domain.{action,policy,validation}`, which is what makes the module
inventory agree with the tree. That was `decisions.md` **D7**, and D7 is
**resolved**: the ruling was to move the inventory to `implemented` rather than
leave the code unexported, and to state `validate`'s real signature
(`fn (std.mem.Allocator, Input) Validation(Input)`) in this contract, which the
spec shape below does. `src/root.zig`'s `modules` table carries domain as
`.implemented` with the surface "resources, typed actions, validation,
authorization"; of those, the resource/relationship layer (§Resources) is still
contract only — there is no file for it — and both of the modules that would map
a domain error to a surface are incomplete: `app` is declared (no code), and
`live` is a wire codec with no session layer, so `ErrKind.authz` exists on the
wire with nothing producing it.

## Actions

```zig
pub fn Action(comptime Spec: type) type;

// Spec shape (concrete Zig declarations, no DSL strings):
//   pub const name = "invoice.create";     // stable id: ^[a-z0-9_.]+$, non-empty
//   pub const version = 1;                 // >= 1, fits in u32; bumped on incompatible input change
//   pub const Input = struct { ... };      // plain data
//   pub const Output = struct { ... };     // plain data or void
//   pub const policy = Policy.all_of(.{ Policy.userRole(0b001) });  // required; default: deny
//   pub fn validate(allocator: Allocator, input: Input) Validation(Input);  // structural checks
//   pub fn run(ctx: *Ctx, input: Input) Error!Output;      // the operation
//   pub const effects = .{ .http, .email };                // optional, declared effects
```

Every one of those shapes is checked at comptime by `ensureSpec`, so a misshapen
spec is a compile error next to the declaration rather than a failure at the
first invocation. The generated surface is `name`, `version`, `Input`, `Output`,
`errors` (the domain taxonomy), `effects` (`.{}` when the spec declares none)
and `Result`.

Rules:

- `Input`/`Output` are plain data. `isSerializable` is the guard, and it is
  narrower than "a struct": `void`, `bool`, integers, floats and enums are
  allowed; the guard recurses into optionals, arrays, struct fields (skipping
  `comptime` fields) and tagged-union fields; **the only allowed pointer is a
  slice of `u8`**. Other pointers — including `*T`, `[*]T`, slices of anything
  else, and function pointers — error sets, error unions, functions, opaque
  types, vectors, untagged unions and packed unions are rejected. Handlers that
  need to carry data across an await copy it into the action's allocator.
- **Policy, then decode, then validation, then `run`.** Decoding belongs to
  `invoke` only: it takes the codec as a comptime parameter
  (`pub const DecodeFn = fn (std.mem.Allocator, []const u8) anyerror!Input`), so
  the domain core has no codec dependency, and a payload that fails to decode
  reports as a validation error with field `""` and code `malformed`. Surfaces
  that already hold a decoded value call `invokeTyped` and skip it. The ordering
  is the point: a principal that may not invoke an action learns nothing about
  its input shape, and a denied caller's bytes are never parsed.
- `invoke`/`invokeTyped` stamp `ctx.principal` from the invocation, so policy,
  `run` and nested invocations cannot observe two different principals for one
  call.
- `run` receives `Ctx`:

  ```zig
  pub const Ctx = struct {
      principal: Principal,
      allocator: std.mem.Allocator,
      now_ms: i64,           // wall clock, milliseconds since the epoch
      tx: ?*anyopaque = null, // the surface's transaction; opaque here, `txAs(T)` downcasts it
      log: ?Logger = null,    // a one-method seam; `null` means "no logging"
  };
  ```

  There is no `data` handler and no `jobs` handle in `Ctx` in this tree: an
  action that needs either reaches it through the surface that built the context
  (`ctx.txAs(data.Tx)`) or through its own `Input`. `tx` is non-null when the
  invoking surface established a transaction — that part of the contract holds —
  and nested invocations share the same handle, so composite operations stay
  atomic.
- Validation runs before `run` and its failures stop the run: `validate` returns
  field-keyed errors with stable codes, safe to return; authz errors are uniform
  and carry nothing. A `run` that returns `error.Validation` is reported as a
  validation failure with field `""` and code `invalid` (surfaces map it to
  422), and anything outside the taxonomy becomes `internal`.
- Output: `Result` is a union of `ok`, `validation`, `denied`, `not_found`,
  `conflict`, `unavailable`, `timeout`, `internal`. A failure that is not tied to
  a field uses field `""` and puts the meaning in the code.
- Effects that leave the process are declared (`pub const effects = .{ .http,
  .email }`) so `jobs`/`agents` can require recorded results (`contracts.md` §5).
  Nothing in the tree reads `effects` yet: the declaration is forwarded and
  comptime-checked, and the module that would enforce it is `agents`, which is
  declared.

## Authorization (`policy.zig`)

A `Policy` is a plain, allocation-free value with four parts, and there is no
vtable, no allocation and no closure:

```zig
pub const Policy = struct {
    fallback: Decision = .deny,          // `Policy{}` denies, so a forgotten policy denies
    rule: ?RuleFn = null,                // *const fn (Principal) Decision
    predicate: ?PredicateFn = null,      // *const fn (Principal, scratch []Param) ?Query
    children: []const Policy = &.{},     // conjuncts, declaration order
};
pub const Query = struct { sql: []const u8, params: []const Param };
```

- **A decision is a function of the principal alone.** That is what lets an
  invocation be denied before its payload is decoded or validated. Authorization
  that depends on the input belongs in the action body, which returns
  `error.Denied`.
- **Precedence** (`decide`): conjuncts in order, the first denial short-circuiting
  the rest; then `rule`; then `fallback`. `all_of` builds the conjunction
  (the empty one allows) and its result is comptime-foldable, so
  `comptime decide(...)` works. At most one conjunct may carry a SQL predicate —
  checked at comptime, because the read path ANDs a single predicate into the
  query.
- Builders: `Policy.deny()` (the default), `Policy.allow()` (explicit; never a
  default), `Policy.check(rule)`, `Policy.userRole(mask)` (user principals whose
  role bitmask intersects `mask`; every other kind is denied), and
  `Policy.filter(predicate)` for reads.
- **Read predicates.** `Policy.sqlPredicate(principal, scratch)` returns the SQL
  fragment to AND into a resource query, or `null` when the read must be denied.
  `null` never means "no filter": the caller must return zero rows and must never
  run the query unfiltered; a non-null result is `Query.tautology` when the
  policy allows every row. Parameters are written into the caller's `scratch`,
  which the returned query borrows, so the buffer must outlive it.
- `Principal` is a union: `anonymous`, `user: {id, roles}`, `service: {name}`,
  `system: {role}`. A missing principal is `anonymous`, never absent.
- **Surfaces.** The contract is that every externally-triggered operation carries
  an `Invocation`, and `Invocation = .{ principal, surface }` with
  `surface ∈ {http, live, job, agent}` — it carries no transaction, because the
  transaction is the surface's, not the invocation's. The mapping of a denied
  result onto a surface is `app`'s (403 for HTTP) and `live`'s
  (`ErrKind.authz`, which the wire codec in `src/live/protocol.zig` carries);
  both of those modules are declared, so today a denied result is a `Result`
  variant and nothing turns it into a status code. `jobs` has no mapping of its
  own either: `registry.Binding.run` returns `anyerror`, so the application's
  binding is where a denial becomes an error — and where the contract's rule
  that retrying a denied job is a bug would be enforced.

## Resources (declared, not built)

A resource is a descriptor used by `data` and `live`:

```
pub const Invoice = Resource("invoices", struct {
    id:        Column(u64, .{ .pk = true, .generated = true }),
    number:    Column([]const u8, .{}),
    amount:    Column(i64, .{}),                 // minor units
    status:    Column(Status, .{ .enum = Status }),
    created_at:Column(i64, .{ .timestamp = true, .generated = true }),
}, .{
    pub const read = policy.read_invoices;       // null policy = denied unless public
    pub const write = policy.write_invoices;
    pub const relationships = .{ .customer = .{ .belongs_to = Customer, .field = "customer_id" } };
});
```

`Resource`, `Column` and the relationship declarations exist only in this
document. `src/domain/` has no file for them, `src/data/` has no
`query(Resource)`, and no test exercises them, so the inventory entry's
"resources" is a target rather than a description. What the section fixes is the
intent:

- Column descriptors drive query construction, form metadata, and typed row
  decoding; they never replace SQL — `data` still emits plain SQL.
- Relationships are declarations (belongs_to / has_many / has_one), used by
  query construction (joins) and form metadata; no lazy loading exists or will be
  added — reads are explicit.
- `Resource` exposes `pub const fields` for form/validation metadata generation
  at comptime.

## Validation (`validation.zig`)

`Validation(T)` accumulates field-keyed errors and is the only failure channel of
an action's structural checks:

```zig
pub fn Validation(comptime T: type) type;
Validation(Input).init(allocator)      // the allocator owns every copy made from here on
v = v.fail(field, code, message)       // one field failure
v = v.merge(other)                     // other's errors after this one's, copied
v.ok(value)                            // the carried value; recorded errors are not cleared
v.isOk() / v.value() / v.errors() / v.dropped() / v.hasError(field, code)
```

- `ok`, `fail` and `merge` take `self` by value and return the updated value, so
  a call site must reassign: the value a call returns owns the copies, and
  dropping it leaks them. `deinit` releases them.
- **Field names are supplied by the caller** — `fail(field, code, message)`
  copies all three strings, so a validation stays valid after the source buffers
  die. Nothing derives field names from the struct's comptime: that generation is
  the resource layer's job (§Resources, not built). Codes are stable strings
  (client-side rendering keys off codes, not messages); field `""` means "the
  input as a whole".
- **A failure is a failure even when it cannot be stored.** Past `max_errors`
  (32), and when a copy cannot be allocated, the failure is not retained but is
  counted in `dropped`, and a non-zero `dropped` makes `isOk` false — so a
  hostile input cannot make a failing request allocate without bound, and an
  allocation failure can never be silently turned into an acceptance.
- Declaration-level validations (length, range, format, enum membership,
  required) would be compiled from `Column` options plus explicit rules declared
  in the resource; runtime validations (uniqueness, cross-field) are `validate`
  functions and may consult the database through `ctx`. The first half waits on
  §Resources; the second half is `validate` as above.

## Errors

Domain error set (mapped per surface):

```
error{ Validation, Denied, NotFound, Conflict, Unavailable, Timeout, Internal }
```

- `Ctx.run`'s error set must fit inside it (`errorSetFits`), so an action cannot
  invent a failure class the surfaces do not know; an inferred error set
  (`anyerror`) does not fit, because the taxonomy is closed. A `run` failure
  outside the taxonomy becomes `Result.internal`.
- `NotFound` is produced by lookups; whether a surface maps it to 404 or a
  generic denial is a surface decision (404 for authorized principals, 403 for
  denied reads — never letting a `Denied` distinguish existence).
- Unique/FK violations are mapped from the adapter's `Error.Conflict`
  (`src/data/root.zig`) into `Result.conflict`; the constraint name is not
  carried today, and the adapter's own mapping is the place it would come from
  (`src/data/turso_adapter.zig`).

## Testing requirements

The tests live in the module's own files and run under `zig build test-zurtr`
(`src/domain/` has no step of its own). What is pinned today:

- Ordering — "policy precedes validation: a denied principal learns nothing"
  asserts that neither `validate` nor `run` ran; "policy precedes decoding:
  denied bytes are never parsed" asserts the decoder was not called.
- Validation — "validation failures are field-keyed and stop before run", "a
  payload that cannot be decoded reports a malformed failure"; in
  `validation.zig`: accumulation with stable codes, `fail` copies its strings,
  the `max_errors` cap with `dropped` counted, a failed allocation counted and
  still failing, `merge` ordering and value adoption.
- Taxonomy — "run failures map onto the taxonomy" walks every variant, and
  `Error` membership is checked at comptime by "the spec guards accept valid
  declarations and reject invalid ones".
- Policies — "deny is the default and admits nobody", "all_of is a conjunction
  that short-circuits on the first denial", "userRole gates on the role
  bitmask", "filter narrows the read with a borrowed parameter buffer", "a filter
  with no authorized row set denies the read", "a denied policy never consults
  its predicate", "the predicate budget counts nested conjuncts", "decisions
  fold at comptime for comptime-known inputs".
- The serializability guard accepts plain data and rejects borrowed pointers and
  non-data types (two comptime tests); `ctx.txAs` and the logger seam are
  exercised by "ctx exposes the transaction handle and the logger seam".
- Surface parity — "the same action yields the same result on every surface"
  asserts the same output from `http`, `job` and `agent` invocations of one
  action. This is the contract's action/job/agent reuse requirement, discharged
  at the `invoke` level rather than end to end: it exercises the three
  `Surface` values, not three real surfaces, because `app` and `live` sessions
  do not exist yet.

Not yet tested, because the code does not exist: nested invocation sharing a
transaction (there is no `ctx.invoke`; a nested call is another `invoke` with the
same `Ctx`), resource read policies returning zero rows, and a resource without
a read policy being denied by default.
