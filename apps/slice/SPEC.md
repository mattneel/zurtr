# Slice application spec (first integration milestone)

The slice is the framework's integration test: one small application that
exercises every module's central promise. It is not a demo — its acceptance is
machine-checked by `zurtr test --e2e` and the dev-latency harness.

Status: **not implemented** — `apps/slice/` contains this specification and
nothing else. There is no application source, no `migrations/` directory and no
e2e script in the tree yet. The one piece that does exist is the browser half of
the live protocol (`assets/zurtr_live.js`, with its self-test page
`assets/zurtr_live_test.html`).

## Application: `tasks`

A single live page where an authenticated user creates tasks; creating a task
durably enqueues a summarization job; the job's result appears on the page
without a reload.

### Schema (planned: `apps/slice/migrations/0001_init.sql`, not in the tree)

```sql
create table users (
  id         integer primary key autoincrement,
  username   text not null unique,
  created_at integer not null              -- microseconds since the epoch, UTC
);
create table tasks (
  id         integer primary key autoincrement,
  user_id    integer not null references users(id),
  title      text not null,
  created_at integer not null
);

create table summaries (
  task_id    integer primary key references tasks(id),
  body       text not null,
  created_at integer not null
);
-- plus the framework's tables (zurtr_jobs, zurtr_schema_migrations)
```

Dialect: Turso / SQLite, the adapter the tree builds (`decisions.md` D5/D6) —
integer autoincrement keys, integer microsecond instants, `blob` for bytes, one
writer per database file. Bootstrap is a temporary database file rather than
`createdb`, and the delivery that used to be a notification is the outbox
(`decisions.md` D4).

### Domain

- Resource `Task` with read policy: `user_id = current_user`, write policy:
  same, `public = false`.
- Action `task.create`: `Input { title: []const u8 }`, validation: trimmed
  length 3..80 (codes `too_short`/`too_long`), policy: authenticated user
  (anonymous → `Denied`), effect: insert into `tasks`, then
  `jobs.enqueue(tx, .{ .action = task.summarize, .input = { task_id } ,
  .idempotency_key = "task/<id>/summarize" })` in the same transaction.
- Action `task.summarize` (job surface): reads the task, produces a summary
  row (deterministic: `"task <id>: <title> (<n> words)"`), publishes
  `task_summary` on topic `user/<user_id>/tasks`.

### Live view `TasksPage`

- `State { tasks: []Task, summaries: []Summary, form_error: ?FieldError, pending_title: []const u8 }`.
- Events: `submit` (payload: title), `dismiss_error`.
- Info: `task_summary` (payload: task_id, body).
- Render: list of tasks (keyed by task id), each with an optional summary line;
  the form below; validation errors rendered from `form_error`.
- Subscribes on init to `user/<user_id>/tasks`.

### Routes

- `GET /tasks` → live page (initial HTML, session token).
- `GET /zurtr/live` → the live channel: WebTransport over HTTP/3, with a WebSocket endpoint as the documented fallback (`decisions.md` D3).
- `POST /zurtr/upload` → session-scoped upload endpoint (server side planned;
  the browser half is in `assets/zurtr_live.js`, which posts to
  `/zurtr/upload?token=…`, and its self-test page exercises it).
- `GET /login?as=<username>` (dev-only, `--dev` flag) → sets the signed session
  cookie for a seeded user; refused in release builds.
- `GET /healthz` → `200 ok`.

## Acceptance checks (the e2e script)

`zurtr test --e2e` boots the app against a temporary database (a file under the
test's scratch directory, migrations applied) on an ephemeral port, drives it
with an HTTP client and a live-channel client, then deletes the file. Every
check below is asserted; the script exits non-zero on the first failure and
prints the failing check.

1. **Initial render**: `GET /tasks` (with the session cookie) returns 200, HTML
   containing the task list and the session token; `GET /tasks` without the
   cookie redirects to `/login` (auth gate, not a 500).
2. **Attach**: the live client sends `hello` with the token and rev from the
   HTML; the server replies `ready` and the client's `rev` advances.
3. **Invalid form**: `submit` with title `"ab"` produces an `error` message
   with `kind=validation` and field key `title`/code `too_short`; the page
   patch does not add a task; the database has no new `tasks` row and no new
   `zurtr_jobs` row.
4. **Anonymous denial**: a second live session without the cookie cannot submit
   (connection is refused at attach, or the event returns `kind=authz`).
5. **Valid form, atomic write**: `submit` with a valid title produces a patch
   adding the task; the database shows exactly one `tasks` row **and** one
   `zurtr_jobs` row for the same event. A deliberate failure case
   (`POST /debug/fail-after-task`, dev-only) rolls back both rows — asserted in
   the same run to prove the transaction, not the happy path, is the mechanism.
6. **Job execution**: within 5 seconds a second patch arrives (the outbox and the bus) adding
   the summary line; `summaries` has exactly one row for the task; the job row
   is `completed`.
7. **Idempotency**: re-running the job for the same task (via
   `POST /debug/replay-job`) does not create a second `summaries` row and does
   not publish a second patch (asserted by message count).
8. **Reconnect**: the live client drops the channel mid-session, reconnects with
   the last rev and pending event ids, and receives either continued patches or
   a `resync` whose HTML contains both the task and its summary; no event is
   applied twice (task count stable).
9. **Read authorization**: a second user's session sees zero tasks (the
   policy-filtered list), and `GET /tasks` for the first user still shows one.
10. **Shutdown**: SIGTERM drains; the process exits 0 within the drain timeout.

## Dev-latency acceptance (harness)

`zurtr dev --measure` on the slice app performs two scripted edits — one in a
handler (`GET /healthz` body string) and one in a component (the task list
item's text) — and reports edit→paint per phase. Acceptance: total
edit-to-DOM-paint < 1000 ms for both edits, recorded in
`measurements/dev-latency.json`, on this workstation.

## Out of scope for the slice (tracked by module contracts)

- Password/OAuth authentication (dev login stands in), upload UI, agent
  workflows (the `agents` module has its own tests), the declared PostgreSQL
  adapter, TLS, HTTP/2, and multi-worker session affinity.
