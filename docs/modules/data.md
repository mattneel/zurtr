# Module contract: Data (`zurtr.data`)

Scope: queries, transactions, migrations, adapters. The interface is
adapter-shaped; **Turso is the first adapter**, opened at one of four tiers, and
PostgreSQL remains a declared adapter (see the end of this file).

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
- **Execution mode is the caller's, not the adapter's.** The parked/blocking split in earlier revisions
  of this contract is gone (`docs/architecture/decisions.md`, D1): the framework has two execution
  classes — synchronous, and the `.ASYNC` lane, where a driver round trip parks the fiber and never the
  worker. Here that means one adapter with one call shape: it blocks the role loop that calls it and
  yields the fiber that calls it. Timeouts and retry policy for role processes live in the caller
  (jobs/agents), which is where the taxonomy's `unavailable` and `timeout` classes become policy; the
  adapter keeps no deadline of its own.
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

## Turso adapter (`zurtr.data.turso`)

`examples`-free and small on purpose: the adapter owns one `turso.Database` and one
`turso.Connection` per role process — no pool, no sharing — exactly as §"Adapter interface" requires
("one `Database` per role process"). The binding is vendored at `deps/turso`; its native SDK Kit is
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

What still needs a live endpoint, and one with credentials: the `auth_token` path. The tier's token is
sent as the `Authorization` header's value on every request the engine makes, but every server this has
been run against (`tursodb --sync-server`) has no authentication at all, so that header is unproven —
the tests above pass `auth_token = null`. TLS is likewise proven only as far as "an https URL is
accepted by the transport and dialled by it"; the round trips above are plain HTTP to a loopback host,
which is the only scheme the transport allows without TLS.

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

Implemented for every tier (`Engine.claimLease`, `leaseHolder`, `releaseLease`), which is what makes it
testable without a remote: two claimants, one winner, an expiry, and a stale holder that cannot release
someone else's lease. The recovery sentence above is a claim about a node that *does not* get to exit,
so it is tested that way: `test-data-nodes` kills a holder mid-hold with `SIGKILL` and the survivor's
takeover is asserted from its own output — see "Testing requirements" below.

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
- The steps that exist: `zig build test-zurtr` (the framework), `zig build test-zix` (the vendored
  transport), `zig build test-data -Dturso=true` and `zig build test-data-nodes -Dturso=true` (below),
  and `zig build test-zscript -Dzscript=true` (the QuickJS layer). `zig build test` aggregates
  whichever of them the configuration asked for.
- Turso: `zig build test-data -Dturso=true` runs the tier tests — every value tag round-tripping,
  a unique violation mapping to `conflict`, commit and rollback semantics, reopen durability for the
  file tier, the write lease, and (with `-Dturso-sync=true`) the sync tier opening over a local file
  and refusing to pretend when its remote does not answer. It runs against the real native SDK Kit, and
  it is part of `zig build test -Dturso=true`.
- Turso, across processes: `zig build test-data-nodes -Dturso=true` builds `src/data/node.zig` and runs it
  as two unrelated processes over one `.distributed` database file, twice over and both asserted: a
  holder that *exits* without releasing (the follower reads its row, is refused with `conflict`, takes
  over once the lease expires), and a holder that is **killed mid-hold** with `SIGKILL` (uncatchable, so
  no handler, no flush and no release — the survivor opens the still-held file, sees exactly the killed
  holder's committed row and nothing half-written, is refused by the dead holder's lease, and takes over
  when it expires). The pids, the signal the holder died by and each attempt's outcome are in the
  harness's output, so "two processes, killed not exited" is checkable rather than assumed.
- Turso, against a live sync endpoint: `zig build test-data -Dturso=true -Dturso-sync=true
  -Dsync-remote=<url>` adds the round trip described under "The sync tier's remote"; without the flag
  that one test skips.
- Transaction semantics tests: commit persists, rollback discards, scope-exit
  rolls back, unique violation maps to `conflict`, pool exhaustion maps to
  `unavailable` and recovers.
- Read-policy tests: policy predicate applied before `limit`, denied reads
  return zero rows (not an error), `public` resources bypass policy.
