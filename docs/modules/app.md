# Module contract: Application (`zurtr.app`)

Scope: assembly and lifecycle. `app` owns configuration, routes, middleware,
authentication, telemetry, and the bridges that wire `domain`, `data`, `live`,
`jobs`, and `agents` to HTTP and to each other. It is the only module allowed
to depend on all others.

Status: **declared** — no implementation in this tree (`src/root.zig`'s module
table). The configuration sketch below names types the tree does not have yet;
the exceptions are the transport type and the database handle, which are named
after the real ones (`deps/zix/src/tcp/http1/config.zig`, `src/data/root.zig`).

## Configuration

```zig
pub const Config = struct {
    server: zix.Http1.ServerConfig,  // listeners, workers, limits
    db: data.Tier,                   // where the data lives: memory|file|sync|distributed
    app: struct { name: []const u8, secret: Secret, base_url: []const u8 },
    live: live.Config,               // queue bounds, idle timeout, snapshot policy
    jobs: jobs.Config,               // queues, lease, backoff, retention
    telemetry: telemetry.Config,
};
```

- Config is a Zig value with `std.process` environment overrides
  (`ZURTR__DB__URL`, `ZURTR__SERVER__PORT`, …): double-underscore path
  addressing, type-checked at startup, unknown keys rejected.
- Secrets come from the environment or a file (`_FILE` suffix); never logged;
  `Secret` type does not print its contents (a `format` that prints
  `<redacted>` and a comptime guard that prevents `@field` access from
  bypassing it).
- Startup order is fixed and observable: parse config → connect DB → apply
  migrations (dev only) → build registries → bind listeners → serve. Each step
  logs one line with duration; a later step's failure exits non-zero with the
  failed step named.

## Routes and handlers

- Routes are declared in one table (the "narrow registration table"):
  `app.get("/invoices/:id", Invoice.Show)` where the handler is a Zig function
  or a domain action binding (`app.action(invoice.create)`).
- A route handler receives `app.Ctx` (principal, db, tx scope, allocator,
  request view) and returns `app.Reply` — HTML (a `live` tree), JSON (typed
  value), redirect, an action result, or `deferred`/`parked` (per
  `contracts.md` §1).
- Middleware: ordered, explicit list (`middleware.Chain` extended with
  authenticated/session/telemetry entries); no implicit global middleware.
- Static assets: served from a build-produced asset map (hashed names, cache
  headers, precompressed variants when compression is enabled in the server
  config; brotli and flate are in-tree, `deps/zix/src/utils/compression/`).

## Authentication and principals

- Principal types: `anonymous`, `user{id, roles}`, `service{name}`,
  `system{role}` (jobs/agents). Every surface carries one (see `contracts.md`
  §4).
- Session cookies for browser flows: signed, `HttpOnly`, `SameSite=Lax`,
  `Secure` outside dev; the signing key is the configured `app.secret`.
- Live connections are authenticated once; each event is authorized per event
  (§4). A principal change (logout/role change) invalidates the connection's
  cached principal and applies to subsequent events.

## Bridges

- **Actions bridge**: an action can be exposed as an HTTP route, a live event
  target, or a job kind by naming it in the corresponding registry. The bridge
  decodes the surface payload into `Action.Input`, runs policy → validation →
  `run`, and maps the result per surface. One implementation, three surfaces —
  no per-surface copies of domain logic.
- **Pub/sub**: live sessions subscribe to topics
  (`pubsub.subscribe(:invoice, id)`); `app` publishes after committed writes
  (`pubsub.publish(tx, topic, payload)` → a transactional notification, delivery
  after commit). Subscribers receive `Info` messages on the session owner
  thread.

  The tree's bus (`src/live/pubsub.zig`) is the worker-local broker — publish
  and subscribe, no transaction and no database. The transactional form above
  has nowhere to go today: the only built adapter is Turso, which is
  SQLite-compatible and has no `LISTEN`/`NOTIFY`, and zix's `postgrez` driver
  (which does have it, `deps/zix/src/driver/postgrez/src/notify.zig`) backs no
  built adapter. The durable substitute is the outbox described in
  `docs/modules/live.md` and `docs/modules/data.md`; which one `app` uses is
  unresolved.
- **Jobs bridge**: `jobs` runs in its role process; the web role enqueues.
  Job completion that must reach a live session is published through pub/sub
  (the slice uses exactly this path).

## Telemetry

- Structured logs (`std.log` scoped per module, JSON in release, human in dev),
  request logs with route, status, duration, principal id, and a request id.
- Metrics: counters/histograms exposed at `/metrics` when enabled
  (requests, errors, park duration, live sessions, queue depth, job
  outcomes). No external agent required.
- Tracing hooks: a `Telemetry.Span` interface with a no-op implementation; an
  OTel exporter can implement it without other modules changing.

## Lifecycle and shutdown

- `app.run(allocator, App)` builds the server and runs it; `SIGTERM` drains,
  sessions terminate with a `close` notice, jobs finish
  their current step and stop leasing. zix's HTTP/1.1 server has no drain or
  shutdown entry point in the tree today (`deps/zix/src/tcp/http1/server.zig`),
  so graceful shutdown is this module's to build.
- Release builds never start without an applied schema: `zurtr migrate` is a
  separate step; dev mode applies migrations automatically and refuses to start
  if a migration would be destructive (drop/alter type) without
  `--allow-destructive`.

## Testing requirements

- Config: env overrides win, unknown keys rejected, secrets never printed
  (assert on formatted output).
- Actions bridge: the same action through HTTP/live/job surfaces yields
  identical persisted results and identical policy decisions (one shared test
  table across surfaces).
- Pub/sub: publishes inside a rolled-back transaction never reach subscribers;
  committed publishes do, exactly once per subscriber.
- Shutdown: SIGTERM stops accepting, drains in-flight requests, terminates
  sessions, exits 0 within the drain timeout.
