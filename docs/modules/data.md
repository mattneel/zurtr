# Module contract: Data (`zurtr.data`)

Scope: queries, transactions, migrations, adapters. PostgreSQL is the first
adapter; the interface is adapter-shaped so others can follow without changing
callers.

## Adapter interface

```zig
pub const Param = union(enum) {
    null,
    bool: bool,
    int: i64,
    float: f64,
    text: []const u8,
    bytes: []const u8,
    uuid: [16]u8,
    timestamp_micros: i64, // UTC
};

pub const Database = struct {
    ptr: *anyopaque,
    vtable: *const VTable,
    pub const VTable = struct {
        exec:    *const fn (ctx: *anyopaque, tx: ?*Tx, sql: []const u8, params: []const Param) Error!ExecResult,
        query:   *const fn (ctx: *anyopaque, tx: ?*Tx, sql: []const u8, params: []const Param, rows: *RowSink) Error!void,
        begin:   *const fn (ctx: *anyopaque, mode: TxMode) Error!*Tx,
        commit:  *const fn (ctx: *anyopaque, tx: *Tx) Error!void,
        rollback:*const fn (ctx: *anyopaque, tx: *Tx) Error!void,
        close:   *const fn (ctx: *anyopaque) void,
    };
};
pub const ExecResult = struct { rows_affected: u64 };
pub const TxMode = enum { read_write, read_only };
```

- One `Database` per role process. The PostgreSQL adapter owns a connection
  pool; `begin` checks out a connection from the pool for the tx lifetime.
- `Tx` is a handle, not thread-safe, not storable. It must be committed or
  rolled back explicitly; dropping it without either is a rollback plus a
  recorded diagnostic (`contracts.md` §3).
- **Two execution modes in the adapter**, chosen by the caller's context:
  - *parked* (reactor paths): the operation hands off to the event loop and
    the HTTP handler parks; used by `app`/`live`.
  - *blocking* (role processes: jobs/agents): the operation blocks the role
    loop with a timeout and is retried on transient failure. Blocking mode is
    never reachable from a reactor thread — the type of the calling context
    decides (a `Ctx` in a reactor path has no blocking API).
- Errors are mapped to the framework taxonomy (`contracts.md` §5):
  `unavailable` (pool exhausted, connection lost), `conflict` (unique/FK
  violation, serialization failure), `timeout`, `syntax` (bug), `internal`.

## Rows

`RowSink` is a push-style cursor: `pub fn row(self: *RowSink, columns: []const Value) !void`
with columns borrowed for the duration of the call; implementations copy what
they keep. `Value` mirrors `Param` minus `null` ambiguity: `null` is a distinct
tag. Column names and PG type OIDs are available via `RowSink.describe()`.
There is deliberately no lazy iterator API in v1: borrow-scope bugs are the
main risk this design removes.

## Migrations

- Migrations are ordered `(version: i64, name, sql)` records declared in Zig
  (comptime array in the app), stored applied in `zurtr_schema_migrations`.
- Each migration runs in its own transaction; migration order is by version;
  duplicate or gap-free? — duplicates rejected, gaps allowed.
- `zurtr migrate` applies pending migrations; dev mode applies on start;
  release apps require an explicit migrate step (no silent schema changes).
- Down-migrations are not supported in v1 (forward-only), matching the
  single-executable deployment model.

## Query construction and read authorization

- Explicit SQL through `Database.query`/`exec` is always available.
- Resource reads go through `data.query(Resource)` which builds
  `select ... from <table> [where ...] [order by ...] [limit ...]`.
- **Read authorization compiles into the predicate**: a resource declares a
  read policy `fn (principal) ?Policy` where
  `Policy = struct { sql: []const u8, params: []const Param }`; the builder
  ANDs it into every query before `order by`/`limit` (so pagination and
  aggregates are computed over authorized rows only). A resource with no read
  policy is denied unless explicitly declared `public`. Post-filtering a page
  is a contract violation and there is no API for it.
- Write policies are checked by `domain` before `insert`/`update`/`delete`;
  the generated statements include the policy predicate as a guard so a denied
  write affects zero rows and reports `authz`, not `conflict`.

## PostgreSQL adapter

- Transport: the vendored swerver PG client (`deps/swerver/src/db/pg`), which
  already implements the park/resume integration for reactor paths.
- Pool: N connections per worker (`DB_POOL_SIZE`, default 4 dev / 8 prod),
  lazily connected, health-checked on borrow, with connect timeout.
- Prepared statements: server-side prepared statements cached per connection,
  keyed by SQL hash; `unknown`/`deallocate` handled on schema change.
- `LISTEN`/`NOTIFY` support is exposed to `jobs` (see `jobs.md`).
- Types: binary format for all values; explicit decoders per `Value` tag;
  unknown OIDs surface as `text` bytes, never silently coerced.

## Testing requirements

- Param encoding/decoding round-trips against a live local PostgreSQL in the
  integration test suite (`zurtr build test-db`), skipped when
  `ZURTR_DB_URL` is unset; unit tests never require a database.
- Transaction semantics tests: commit persists, rollback discards, scope-exit
  rolls back, unique violation maps to `conflict`, pool exhaustion maps to
  `unavailable` and recovers.
- Read-policy tests: policy predicate applied before `limit`, denied reads
  return zero rows (not an error), `public` resources bypass policy.
