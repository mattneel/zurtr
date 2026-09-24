# Module contract: Data (`zurtr.data`)

Scope: queries, transactions, migrations, adapters. The interface is
adapter-shaped; **Turso is the first adapter**, opened at one of four tiers, and
PostgreSQL remains a declared adapter (see the end of this file).

## Adapter interface

The implemented types are `src/data/root.zig`'s; the contract names them
`zurtr.data.*` and this is what they are:

```zig
pub const Value = union(enum) {           // the contract's `Param`
    null,
    boolean: bool,
    integer: i64,
    float: f64,
    text: []const u8,
    bytes: []const u8,
    uuid: [16]u8,
    timestamp_micros: i64, // UTC
};

pub const Database = struct {
    context: *anyopaque,
    vtable: *const VTable,
    tier: Tier,                          // how it was opened; read-only after construction
    uncommitted_transactions: u64 = 0,   // dropped-handle counter (see below)
    pub const VTable = struct {
        exec:    *const fn (context: *anyopaque, tx: ?*Tx, sql: []const u8, params: []const Value) Error!ExecResult,
        query:   *const fn (context: *anyopaque, tx: ?*Tx, sql: []const u8, params: []const Value, sink: RowSink) Error!void,
        begin:   *const fn (context: *anyopaque, mode: TxMode) Error!*Tx,
        commit:  *const fn (context: *anyopaque, tx: *Tx) Error!void,
        rollback:*const fn (context: *anyopaque, tx: *Tx) Error!void,
        close:   *const fn (context: *anyopaque) void,
    };
};
pub const ExecResult = struct { rows_affected: u64 };
pub const TxMode = enum { read_write, read_only };
```

Two names differ from the earlier revision of this contract and are worth
calling out, because `jobs` and `domain` both cite them: the value type is
`Value`, not `Param` (`domain.policy` defines its own `Param` for the read
predicate, and says why), and the tags are `boolean`/`integer`, not
`bool`/`int`.

`Tier` is what a database was opened as — `.memory`, `.file`,
`.sync(Sync)`, `.distributed(Distributed)` — and `Tier.describe()` is its
one-line form for logs and reports. `Lease` is declared beside it for the
`.distributed` write lease, but nothing reads its `ttl_ms`: the adapter's
`Engine.claimLease` hard-codes a one-second expiry, which is what the
two-process tests are sized around (`src/data/turso_adapter.zig`,
`src/data/nodes_test.zig`).

- One `Database` per role process, and the Turso adapter keeps that literally:
  one engine, one connection, no pool (`src/data/turso_adapter.zig`). The pool
  below belongs to the PostgreSQL adapter, which is declared and not built.
- `Tx` is a handle, not thread-safe, not storable: `Tx.commit`/`Tx.rollback` set
  a `done` flag so a second attempt is a no-op rather than a second statement.
  **The contract's rule that a tx dropped without either is rolled back with a
  recorded diagnostic is not implemented.** `uncommitted_transactions` exists
  and is never incremented, and the adapter does not roll back a dropped
  handle: `Engine.begin` refuses a second transaction while one is live
  (`error.Operation`) and `releaseTxHandle` reclaims the handle only on the next
  `begin` or on `close`, so a `*Tx` dropped mid-scope leaves the connection
  inside a transaction until the engine closes. `contracts.md` §3 and this
  document say what should be true; the counter is where it would be recorded.
- One transaction at a time, per engine, is enforced rather than assumed: a
  second `begin` while one is live is `error.Operation` (`src/data/root.zig`'s
  `Error` set has that member too, and this section used to omit it).
  Nesting is a surface concern, expressed with savepoints.
- **Execution mode is the caller's, not the adapter's.** The parked/blocking split in earlier revisions
  of this contract is gone (`docs/architecture/decisions.md`, D1): the framework has two execution
  classes — synchronous, and the `.ASYNC` lane, where a driver round trip parks the fiber and never the
  worker. Here that means one adapter with one call shape: it blocks the role loop that calls it and
  yields the fiber that calls it. Timeouts and retry policy for role processes live in the caller
  (jobs/agents), which is where the taxonomy's `unavailable` and `timeout` classes become policy; the
  adapter keeps no deadline of its own.
- Errors are mapped to the framework taxonomy (`contracts.md` §5):
  `unavailable` (dependency down, connection lost, out of memory — the
  PostgreSQL pool's exhaustion belongs here), `conflict` (unique/FK violation,
  serialization failure, a busy engine), `timeout`, `syntax` (the SQL does not
  compile: a programmer error), `operation` (the engine refused it — a
  constraint, a type mismatch, a closed handle, a read-only database) and
  `internal` (a bug in the adapter or the engine's own state). The adapter's
  mapping is by *consequence* rather than by name, and it is the two `mapError`
  functions at the end of `src/data/turso_adapter.zig`.

## Rows

`RowSink` is a push-style cursor: `pub fn row(self: RowSink, columns: []const Value) Error!void`,
with columns borrowed for the duration of the call; implementations copy what
they keep. `Value` mirrors the contract's `Param` minus `null` ambiguity: `null`
is a distinct tag. There is deliberately no lazy iterator API in v1:
borrow-scope bugs are the main risk this design removes.

Column *names* are not available: `RowSink` is two fields (`context` and a
`push` function) and nothing else — there is no `describe()`, and the PostgreSQL
type OIDs that would come with a live PG adapter have nowhere to arrive. A
caller that needs names can select them into a row it decodes positionally, which
is what `jobs` does (`src/jobs/root.zig`'s `decodeJob`), and the value tags it
can expect are the five the adapter produces: `null`, `integer`, `float`, `text`,
`bytes` (`toDataValue`; `boolean`, `uuid` and `timestamp_micros` are encodable
but come back as `integer`/`bytes`, which is the mapping SQLite forces).

## Migrations

**Not implemented.** There is no migration API in `src/data/root.zig`, no
`zurtr_schema_migrations` anywhere in the tree, and no `zurtr migrate` command
(`src/main.zig` ships `modules` and `new`, and lists `migrate` among the
commands that arrive with the modules they drive). What the contract asks for,
when it is built:

- Migrations are ordered `(version: i64, name, sql)` records declared in Zig
  (comptime array in the app), stored applied in `zurtr_schema_migrations`.
- Each migration runs in its own transaction; migration order is by version;
  duplicates rejected, gaps allowed.
- `zurtr migrate` applies pending migrations; dev mode applies on start;
  release apps require an explicit migrate step (no silent schema changes).
- Down-migrations are not supported in v1 (forward-only), matching the
  single-executable deployment model.

The stand-in in the tree is the one the adapter and `jobs` both use: every
statement is `IF NOT EXISTS`, so applying a module's schema on every start is
idempotent and startup is the only migration step those modules need.
`src/jobs/schema.zig` also exports its statements (`zurtr.jobs.storage.statements`)
so an application that owns its ordered migration list can fold them in once the
runner exists — which is why it exports them rather than keeping them private.

## Query construction and read authorization

- Explicit SQL through `Database.query`/`exec` is always available, and it is
  all that exists today: `data.query(Resource)` does not, because there is no
  resource layer (`docs/modules/domain.md` §Resources).
- **Read authorization compiles into the predicate**, and the predicate half is
  implemented in `src/domain/policy.zig`:
  `Policy.sqlPredicate(principal, scratch)` returns
  `Policy.Query = { sql: []const u8, params: []const Param }` — the fragment to
  AND into a resource query before `order by`/`limit` — or `null` when the read
  must be denied. `null` never means "no filter": the caller returns zero rows
  and never runs the query unfiltered, and `Query.tautology` (`sql = "true"`) is
  what a policy that allows every row returns. The builder that would consume it
  is the resource layer above, which is not built.
- A resource with no read policy is denied unless explicitly declared `public`;
  post-filtering a page is a contract violation and there is no API for it.
- Write policies are checked by `domain` before `insert`/`update`/`delete`;
  the generated statements include the policy predicate as a guard so a denied
  write affects zero rows and reports `authz`, not `conflict`. Nothing generates
  those statements yet.

## Turso adapter (`zurtr.data.turso`)

Small on purpose: the adapter owns one `turso.Database` and one
`turso.Connection` per role process — no pool, no sharing — exactly as
§"Adapter interface" requires ("one `Database` per role process"). The binding is
vendored at `deps/turso`; its native SDK Kit is
compiled from Rust source, so the adapter is behind `-Dturso` and the base build never sees it.

Parameters cross as a runtime `[]const Value` and are mapped into the binding's own runtime `Value`;
rows come back through `Row.value(index)`, so a query never needs to know its column types at
comptime. Row slices are borrowed for the duration of the sink call and the scratch is reused between
rows, which is what keeps a long result set flat.

### Tiers

The tier is the whole of an adapter's durability and reach, and it is chosen at `open`:

| Tier | Where the data lives | Survives | Reach |
| :- | :- | :- | :- |
| `.memory` | the process | nothing | one node |
| `.file` | one path on one machine | process exit | one node |
| `.sync` | a local file plus a remote database | the machine | every node syncing that remote |
| `.distributed` | a local file per node, one logical database | the machine | many nodes, one writer |

Tiers 1 and 2 are complete and tested. `.sync` opens in a build that has the sync SDK Kit
(`-Dturso-sync=true`, which builds a second native library): the local file is opened and serves SQL
immediately, and the remote half is the caller's to drive — `Engine.push`, `pull`, `syncPass` and
`stats`, one operation per call, no threads and no timers, which is what the binding requires.
`-Dturso-sync=false` has no `turso_sync` module at all, so the tier is refused with `error.Unavailable`
rather than opened as a local file that would never synchronize. A `.sync` path must also be relative
to the working directory: the engine hands its own file requests (metadata, changes log, WAL) to the
transport as paths derived from the database's, and the transport resolves them under the working
directory and refuses absolute ones — an absolute path is refused with `error.Operation`.

`.distributed` opens, because its enforceable half is local and real: reads from any node, writes only
from the lease holder. It also asks the engine for its experimental multiprocess WAL coordination,
without which a second live process cannot open the file at all — that is what `test-data-nodes` exists
to prove, with two real processes over one file.

### The sync tier's remote

What is proven, and how: two local databases, one remote, both directions. The test that does it needs
a server, so it runs only when the build is told where one is:

```sh
# tursodb's sync server, from the pinned upstream checkout:
#   cargo build --release --package turso_cli --bin tursodb
#   tursodb --sync-server 127.0.0.1:8080 /tmp/tursodb-sync/server.db
zig build test-data -Dturso=true -Dturso-sync=true -Dsync-remote=http://127.0.0.1:8080
```

It pushes from one database, bootstraps a second one from the remote and reads the first one's row
there, then writes from the second and pulls that row into the first. It runs against a server on this
machine or against the same URL tunnelled to another box (`fly proxy 18080:8080 -a <app>` — the
endpoint stays loopback, which is what lets the plain-HTTP rule hold); the test does not care which,
because it only knows the URL. Without `-Dsync-remote` the test skips and the rest of the suite still
covers the tier: that it opens over a local file with no server at all, and that an operation against a
remote that does not answer comes back as `error.Unavailable` — mapped, not a panic and not a silent
success.

What the round trip does *not* cover — the token path, TLS, a kill inside a write, and one anomaly seen
once — is written down under "Not proven here" below, so a reader does not have to infer it from the
flags that happen to be in the test.

What is deliberately *not* here: scheduling, retry and conflict policy. `pull` is one operation, not a
loop; a `Busy`/`Conflict` outcome is the caller's to retry, and nothing runs in the background. Remote
state also arrives on demand rather than at open: a fresh local file is opened without the network (the
engine's deferred bootstrap) and meets the remote on its first `pull`/`syncPass`.

### The write lease

`.distributed` means several nodes over one logical database, and the primitive that makes that
coherent is a lease rather than a lock: one row in `zurtr_write_lease`, one holder, an expiry the
holder renews. It is held through the database itself, so a node that can write data can renew its
lease and a node that cannot reach the database cannot hold one. A node that dies holding the lease
loses it when the expiry passes and the next claimant takes over with no coordination step in between.

Implemented for every tier (`Engine.claimLease`, `leaseHolder`, `releaseLease`; the table is created on
open at every tier), which is what makes it
testable without a remote: two claimants, one winner, an expiry, and a stale holder that cannot release
someone else's lease. A lease lasts one second — `claimLease` writes `now + 1_000_000` microseconds —
and it is enforced where writes begin rather than trusted to the caller: `Engine.begin` claims the lease
for a read-write transaction on the `.distributed` tier and answers `error.Conflict` when somebody else
holds it, while reads never need it (one writer, many readers). The recovery sentence above is a claim about a node that *does not* get to exit,
so it is tested that way: `test-data-nodes` kills a holder mid-hold with `SIGKILL` and the survivor's
takeover is asserted from its own output — see "Testing requirements" below.

### Not proven here

Limits of the tiers above, stated so the next reader does not have to rediscover them:

- **`auth_token` is untested.** The tier's token is forwarded verbatim as the `Authorization` header's
  value, and every endpoint these tests have been run against (`tursodb --sync-server`) has no
  authentication at all — the tests pass `auth_token = null`, so no server has ever checked that header.
- **TLS is proven only as far as "an https URL is parsed and dialled by the client".** Both round trips
  ran over plain HTTP to a loopback host, which is the only scheme the transport allows without TLS (the
  cross-box run went through `fly proxy`, which keeps the URL loopback). A reader should take `https://`
  in `remote` as accepted and dialled, not as verified against a certificate chain.
- **The crash case kills a holder between transactions.** `test-data-nodes` proves that a `SIGKILL`ed
  holder loses its lease when the expiry passes and that the file it held is afterwards readable, with
  exactly the row it committed and nothing half-written. It says nothing about a process killed *inside*
  a write.
- **One anomaly, seen once and not reproduced:** a single-process (`.file`) open of a file written by the
  engine's multiprocess mode saw fewer rows than the multiprocess writer had committed. It has not
  recurred on demand, the two-process tests no longer read that way — they open at the tier they wrote
  with — and nothing depends on the old behaviour. If a legacy open ever looks short of a multiprocess
  write, start there.

## Declared: PostgreSQL

- Transport: zix's `postgrez` driver (the vendored zix under `deps/zix`), which is where the PostgreSQL
  protocol lives now that zurtr's transport is zix. There is no parked mode to build for it (see
  `docs/architecture/decisions.md`); the work this adapter still needs is the pool, the prepared-statement
  cache and the decoders below.
- Pool: N connections per worker (`DB_POOL_SIZE`, default 4 dev / 8 prod),
  lazily connected, health-checked on borrow, with connect timeout.
- Prepared statements: server-side prepared statements cached per connection,
  keyed by SQL hash; `unknown`/`deallocate` handled on schema change.
- `LISTEN`/`NOTIFY` is **not** implemented and nothing in the tree exposes it: this adapter does not
  own a listener connection and `jobs` does not wait on one. Job wakeups go through the outbox path in
  `jobs.md`, which does not need the database to push.
- Types: binary format for all values; explicit decoders per `Value` tag;
  unknown OIDs surface as `text` bytes, never silently coerced.

## Testing requirements

- Param encoding/decoding round-trips against a live database are not in the suite today: every test
  that exists runs without a server, and the one that needs a live *sync* endpoint is skipped unless
  `-Dsync-remote=<url>` is given (below). There is no `test-db` step and no `ZURTR_DB_URL` anywhere in
  the tree; a live-database integration suite arrives with the PostgreSQL adapter, which is declared and
  not built.
- The steps that exist: `zig build test-zurtr` (the framework module),
  `zig build test-zix` (the vendored transport), `zig build test-data -Dturso=true`
  (`src/data/tests.zig`, 11 tests) and `zig build test-data-nodes -Dturso=true`
  (`src/data/nodes_test.zig`, 2 tests, below), `zig build test-cli` (the project
  generator, `src/scaffold.zig`), and — with `-Dzscript=true` —
  `test-zscript`, `test-zeex` and `test-zeex-live`. `zig build test` aggregates
  all of them **except `test-cli`**: it depends on the zurtr, zix, data, nodes,
  script, zeex and zeex-live runs, and the generator's tests are a step only
  (`build.zig`).
- Turso: `zig build test-data -Dturso=true` runs the tier tests — every value tag round-tripping,
  a unique violation mapping to `conflict`, commit and rollback semantics (including that a
  transaction reads its own uncommitted writes, and that the adapter releases a `Tx` handle rather than
  leaking it to the caller's allocator), reopen durability for the
  file tier, the write lease, the sync tier's behaviour with and without the SDK Kit, and the
  `.distributed` tier's refusal to write without the lease. It runs against the real native SDK Kit, and
  it is part of `zig build test -Dturso=true`. Its `build_options` carry `turso_sync` and
  `sync_remote`, which is why the one test that needs a server can skip (`error.SkipZigTest`) instead of
  being excluded.
- Turso, across processes: `zig build test-data-nodes -Dturso=true` builds `src/data/node.zig` and runs it
  as two unrelated processes over one `.distributed` database file, twice over and both asserted: a
  holder that *exits* without releasing (the follower reads its row, is refused with `conflict`, takes
  over once the lease expires), and a holder that is **killed mid-hold** with `SIGKILL` (uncatchable, so
  no handler, no flush and no release — the survivor opens the still-held file, sees exactly the killed
  holder's committed row and nothing half-written, is refused by the dead holder's lease, and takes over
  when it expires). The pids, the signal the holder died by and each attempt's outcome are in the
  harness's output, so "two processes, killed not exited" is checkable rather than assumed. Both cases
  assert liveness against the process table (`kill(pid, 0)`, `running()`) rather than against the lease
  row, which outlives its holder by a second.
- Turso, against a live sync endpoint: `zig build test-data -Dturso=true -Dturso-sync=true
  -Dsync-remote=<url>` adds the round trip described under "The sync tier's remote"; without the flag
  that one test skips.
- Transaction semantics tests, as they stand: commit persists, rollback discards,
  a unique violation maps to `conflict` (`src/data/tests.zig`). Two rules the
  contract states are **not** tested because they are not implemented: a
  `Tx` dropped without commit or rollback being rolled back with a recorded
  diagnostic (`uncommitted_transactions`), and pool exhaustion mapping to
  `unavailable` — there is no pool to exhaust until the PostgreSQL adapter
  exists.
- Read-policy tests live with the policy, not with the adapter:
  `src/domain/policy.zig` pins a filter narrowing a read with a borrowed
  parameter buffer, a filter with no authorized row set denying the read, and a
  denied policy never consulting its predicate. What is missing is the layer
  between: no resource declares a read policy, no builder ANDs one into a query,
  and no test asserts a denied read returning zero rows instead of an error.
