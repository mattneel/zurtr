# Module contract: Domain (`zurtr.domain`)

Scope: resources, typed actions, validation, authorization, relationships.
The domain is where an application's operations are declared once and reused by
every surface (HTTP endpoint, live event, job, agent tool).

## Actions

```zig
pub fn Action(comptime Spec: type) type;

// Spec shape (concrete Zig declarations, no DSL strings):
//   pub const name = "invoice.create";     // stable id
//   pub const version = 1;                 // bumped on incompatible input change
//   pub const Input = struct { ... };      // plain data
//   pub const Output = struct { ... };     // plain data or void
//   pub const policy = Policy.all_of(.{ invoice_write });  // default: deny
//   pub fn validate(input: Input) Validation(Input);       // structural checks
//   pub fn run(ctx: *Ctx, input: Input) Error!Output;      // the operation
```

Rules:

- `Input`/`Output` are plain data (no pointers/slices into borrowed buffers
  beyond `[]const u8` string/binary payloads with owned lifetime semantics
  defined by the surface). Handlers that need to carry data across an await
  copy it into the action's allocator.
- Validation runs before policy evaluation? No: **policy first, then
  validation** — a principal that may not invoke an action learns nothing about
  its input shape from error details. Validation errors are field-keyed and
  safe to return; authz errors are uniform.
- `run` receives `Ctx`: `{ data: *Database, tx: ?*Tx, principal, allocator,
  now, log, jobs: JobsHandle }`. `tx` is non-null when the invoking surface
  established a transaction (HTTP handler and job runner do; live events do
  when the action is declared `transactional`).
- Nested action invocation passes the same `Tx` by default
  (`ctx.invoke(Other, input)`), so composite operations stay atomic.
- Effects that leave the process are declared (`pub const effects = .{ .http,
  .email }`) so `jobs`/`agents` can require recorded results
  (`contracts.md` §5).

## Authorization

- Policies are values: `Policy = struct { sql, params }` predicates over the
  action's resource, or `Policy.deny`/`Policy.allow` for non-SQL cases; a
  policy is a function of `(principal, input)`.
- Surface contract: every invocation carries `Invocation { principal, tx,
  surface }`; a missing principal is `anonymous`, never absent.
- `app` maps authz failures to 403 (HTTP) and `error.kind = authz` (live);
  jobs fail terminally (retrying a denied job is a bug).

## Resources

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

- Column descriptors drive query construction, form metadata, and typed row
  decoding; they never replace SQL — `data` still emits plain SQL.
- Relationships are declarations (belongs_to / has_many / has_one), used by
  query construction (joins) and form metadata; no lazy loading exists or will
  be added — reads are explicit.
- `Resource` exposes `pub const fields` for form/validation metadata generation
  at comptime.

## Validation

- `Validation(T)` accumulates field errors:
  `pub fn Validation(comptime T: type) type` with `.ok(value)`,
  `.fail(field, code, message)`, `.merge(other)`; field names come from the
  struct comptime, codes are stable strings (client-side rendering keys off
  codes, not messages).
- Declaration-level validations (length, range, format, enum membership,
  required) are compiled from `Column` options plus explicit rules declared in
  the resource; runtime validations (uniqueness, cross-field) are `validate`
  functions and may consult the database through `ctx`.

## Errors

Domain error set (mapped per surface):

```
error{ Validation, Denied, NotFound, Conflict, Unavailable, Timeout, Internal }
```

- `NotFound` is produced by lookups; whether a surface maps it to 404 or a
  generic denial is a surface decision (404 for authorized principals, 403 for
  denied reads — never letting a `Denied` distinguish existence).
- Unique/FK violations are mapped from adapter `conflict` with the constraint
  name when available.

## Testing requirements

- Policy-first ordering: a denied invocation with invalid input reports
  `Denied`, not validation details.
- Validation: field-keyed errors, stable codes, `merge` accumulation.
- Nested invocation shares the transaction: inner failure rolls back outer
  writes.
- Read policies: a resource read with a denied principal returns zero rows; a
  resource without a read policy is denied by default.
- Action/job/agent reuse: the same action runs from a job and an HTTP surface
  with identical semantics (one integration test asserting both surfaces
  produce the same stored result).
