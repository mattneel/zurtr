# zurtr — architecture decisions

The rulings behind the changes in `docs/architecture/` and `docs/modules/`. Each
entry is the call that was open, the ruling, and why. Documents link here instead
of restating the reasoning.

Status: normative. Where a module contract and a decision disagree, the decision
wins and the contract is the thing to fix. An entry whose ruling has since landed
in the tree, whose subject is another tree, or whose "why" cites a path that is
not vendored, carries a closing note (`Resolved.`, `Where.`, `Which tree.`) — a
decision records a call, and these say where to check it against the tree.

## D1 — The parked execution class is dead; the `.ASYNC` lane is the mechanism

**Ruling.** Do not design a park sentinel. The framework has **two** execution
classes: synchronous, and the async lane. zix's `.ASYNC` model runs each
connection as a fiber whose `std.Io` is a yielding backend, so a driver round
trip parks the fiber instead of the worker
(`deps/zix/src/tcp/http1/dispatch/async.zig`, `context.zig`).

**Why.** The parked class existed to keep the reactor free while one operation
was in flight, and swerver's park sentinel was how it was expressed. The
property, not the mechanism, was the point: fiber parking gives the same
property, and the sentinel, the fixed plain-data stash and the "one park per
request" rule all go with it. Designing a second mechanism now would be
building what the transport already provides.

## D2 — Deferred completions are confined to `.ASYNC`; a wake source is future work

**Ruling.** A completion that originates outside the connection's own fiber is
delivered inside the `.ASYNC` lane, where the parked fiber already has a resume
point. A transport-level wake source for the loop models (`.EPOLL`, `.URING`) is
the future path, and is named as an open item rather than assumed.

**Why.** zix's HTTP/1.1 dispatch exposes no way for another thread to wake a
loop — `runEpoll` / `runAsync` are the entry points, and there is no external-fd
registration, no eventfd and no completion queue in the tree — so the deferred
handle plus registered wake fd that `contracts.md` §1.3 used to require has
nothing to register with. Confining it to `.ASYNC` keeps the rule (ownership,
generation validation, bounded queues) without inventing transport surface.

Related: the comment in `src/runtime/pool.zig` that said completions wake "via
the transport's wake fd" was wrong and was corrected to describe the `.ASYNC`
delivery it actually has.

## D3 — WebTransport is the channel; WebSocket is the documented fallback

**Ruling.** The live channel is WebTransport over HTTP/3. An explicit
`ws://` / `wss://` endpoint selects the WebSocket fallback. The client does not
downgrade by itself.

**Why.** The docs and the shipped client were the stale side: they spoke
WebSocket while the transport's own notes (`src/root.zig`, `build.zig`,
`deps/zix/UPSTREAM.md`) and the vendored transport both say WebTransport, and
zix carries the WebTransport binding the live channel was built for. Frames stay
the same text JSON; over WebTransport they are newline-delimited on one
bidirectional stream, the convention zix's own example uses — which is
`examples/tls/webtransport_live.html` **in zix's repository**: `examples/` is
not part of the vendored set (`deps/zix/UPSTREAM.md`), so this entry names the
upstream path rather than a path to read from this checkout.

Stated plainly because it is not proven: no zurtr endpoint serves the
WebTransport path yet, and `assets/zurtr_live_test.html` stubs WebSocket, so the
self-test exercises the fallback. The WebTransport branch has been exercised
only to its opening handshake. The fallback has since gained a real endpoint on
the other side of that: the generated application's live route upgrades through
`zix.Http1.WebSocket.serve` (`src/scaffold/templates/app/src/main.zig.tpl`), so
the fallback is what a generated project actually serves.

## D4 — The outbox is the durable path; the broker fans out to present subscribers

**Ruling.** A committed write publishes to the worker-local broker for
subscribers that are present, and records the event in the outbox in the same
transaction as the state change. There is no `pg_notify` anywhere in the
framework.

**Why.** The only built adapter is Turso, which is SQLite-compatible and has no
`LISTEN`/`NOTIFY`; a notification-based publish is a mechanism the storage
cannot provide. The broker is already non-durable by design
(`src/live/pubsub.zig`), and the outbox is what makes a missed message
recoverable — a view that missed events resyncs from a revisioned snapshot.

**Where it stands.** The non-durability and the absence of `pg_notify` are
facts of the tree: the broker's own header states it drops what nobody is
subscribed to, and no `LISTEN`/`NOTIFY`/`pg_notify` appears in `src/`. The
outbox itself is contract-level — no outbox type or table exists yet, and the
queue does not wait on one: job wake-up is a poll (`src/jobs/schema.zig`).

## D5 — Jobs use Turso/SQLite primitives; PostgreSQL stays declared

**Ruling.** The durable queue is expressed in SQLite-compatible terms: integer
microsecond timestamps, `blob` payloads, `integer primary key autoincrement`,
one-statement claims inside a write transaction, and a polled wake-up with the
outbox for delivery. The PostgreSQL adapter remains declared and unbuilt.

**Why.** The dialect has to match the adapter that exists. `SKIP LOCKED` and
`LISTEN`/`NOTIFY` are PostgreSQL features the built adapter does not have, and a
queue is not a place to claim a capability the storage lacks.

**Where it landed.** `src/jobs/` is the implementation and `src/jobs/schema.zig`
is the dialect table, one row per substitution. One detail is stated more
loosely here than the code: a claim is a select-then-update inside one write
transaction (`src/jobs/root.zig`: the candidate select, then the guarded update
whose `rows_affected` is the only verdict), not a single statement — the two are
separate because the `WHERE` is the whole guard.

## D6 — The slice is specified in the same dialect

**Ruling.** `apps/slice/SPEC.md`'s schema, bootstrap and wake-up wording follow
D5: SQLite-shaped DDL, a database file rather than `createdb`, and the outbox
for the job-result patch.

**Why.** The slice is the acceptance test for the framework as it stands. A
PostgreSQL-shaped slice would test a database the tree does not open.

## D7 — `src/domain/` is wired in; the doc notes the real signature

**Ruling.** The domain module's code is the module: the inventory moves to
implemented rather than the code staying unexported. `validate` takes the
allocator as its first parameter, and the contract states that shape.

**Why.** The module table and the tree disagreed; the code is the more
expensive artifact and the contract is the cheaper one to correct. The
`fn (std.mem.Allocator, Input) Validation(Input)` shape is what
`src/domain/action.zig` enforces at comptime (the `validate` label it builds
from `@TypeOf`).

**Resolved.** Both sides moved, and they agree now: `src/root.zig` exports
`domain` (`action`, `policy`, `validation`) and its `modules` table says
`.implemented` for the row, `zurtr modules` prints that, and
`docs/modules/domain.md` states the code's status and the `validate` signature.
`overview.md`'s module table reads its status column from that table, so it has
one place to be right.

## D8 — No WebSocket route kind yet

**Ruling.** With D3, the framework-facing WebSocket layer is a fallback concern.
`docs/architecture/zix-websocket.md` keeps what zix already provides (handshake,
frame codec, engine-owned pump, promotion under every dispatch model) and keeps
the route kind, handler struct and message-level codec rules as a proposal.

**Why.** Two thirds of the original note's premise is now implemented in the
transport; the remaining third is a framework API nobody needs until the
fallback is actually used.

## D9 — The module-per-file claim is a target

**Ruling.** "Every module is a separate Zig module with explicit imports" stays
in `overview.md`, marked as the packaging target rather than a description.

**Why.** It reads as intent and it is intent: `build.zig` declares one framework
module (`zurtr`, rooted at `src/root.zig`) and the vendored dependencies as
modules — but the tree is no longer only that, and the difference is not
packaging. `zscript` (`src/zscript/root.zig`) and `zigeval`
(`tools/zigeval_listen.zig`) are modules of their own because a relative import
cannot cross a module boundary and both are reached from below the root: ZEEX's
compiler is under `src/zeex/` and imports `zscript`, and the live editor under
`tools/` imports both the framework and the evaluator. So read the ruling as
"module-per-file is not yet how applications are packaged", not as "this tree
has one module".

## D10 — `docs/modules/data.md`

**Ruling.** The file belongs to another agent. The `LISTEN`/`NOTIFY` exposure
line and the `zurtr build test-db` / `ZURTR_DB_URL` testing line are that
owner's to fix.

**Why.** Ownership, not disagreement: both items are stale in the same way D4
and D5 describe.

**Resolved.** Both lines were fixed by that owner: `docs/modules/data.md` now
states that `LISTEN`/`NOTIFY` is not implemented and that nothing in the tree
exposes it, and that there is no `test-db` step and no `ZURTR_DB_URL` anywhere
— the step is `test-data` with `-Dturso` (`build.zig`).

## D11 — The WebRTC media comment was wrong

**Ruling.** The header comment in zix's `src/udp/webrtc/Webrtc.zig` that says
media is not carried yet is corrected. Media forwarding is implemented and
wired.

**Why.** The code routes media through `media/mux.zig` and
`media/peer_media.zig` with a real forward path (`media/forward.zig`), the
SRTP profiles are selected by `carry_media`, and the WebRTC docs describe the
path. The comment contradicted the code it sits on.

**Which tree.** The paths are right in both trees — the media files are
`src/udp/webrtc/media/{mux,peer_media,forward}.zig` in zix's tree (`~/src/zix`)
and in the vendored copy. What differs is the comment: zix's tree carries the
corrected header (`6da53081`, with three other claims), while the vendored pin
zurtr builds from (`deps/zix`, `5df894c3`) still says media is not carried. So
the contradiction this entry describes is real in zurtr's tree today and is a
re-vendor away from being gone — the code it contradicts is already there:
`deps/zix/src/udp/webrtc/connection.zig` imports `media/mux.zig` and
`media/peer_media.zig`, the SRTP profiles are selected by `carry_media`
(`config.zig`, used in `sdp/answer.zig`), and `media/forward.zig` is the forward
path.

## D12 — jzon's CI claim is softened to what CI backs

**Ruling.** The claim that every tier runs on both supported Zig versions is
removed; the seven-target half stays, because all seven legs really do run the
suite.

**Why.** Every workflow is pinned to Zig 0.16.0; nothing in `.github/workflows`
tests a 0.17 toolchain, and no CI leg is being added in this pass.

**Where it is now.** jzon's copy of the claim is `~/src/zix/docs/jzon/`
(`README-en.md`, `README-id.md`) and reads "Every tier runs on all seven CI
targets (all seven are pinned to Zig 0.16; there is no 0.17 CI leg)" — the
softened form, committed in `6da53081`. The workflow files themselves are in
jzon's own repository, not in zix or in zurtr (`~/src/zix/src/jzon` is the
source drop and carries no `.github/`), so the seven legs are asserted by that
sentence rather than checkable from this checkout.

## D13 — zix's 0.17 support is stated at the revision the consumer builds

**Ruling.** The requirements block names `0.17.0-dev.2264+230c63650`, the
revision zurtr builds zix with (`~/src/zurtr/deps/zix/UPSTREAM.md`), and names
the CI coverage gap instead of implying coverage.

**Why.** The previous line named a revision no consumer builds and no CI leg
exercises. A version claim is only useful if it is the one in use.

**Where.** `~/src/zix/README-en.md` (and `README-id.md`) under Requirements:
`0.17.x (Experimental): 0.17.0-dev.2264+230c63650 (the revision zurtr builds zix
with)`, followed by the gap — "CI covers 0.16 only".

## D14 — `conn_timeout_ms`'s field comment was the wrong side

**Ruling.** The prometheuz field comment claiming the value bounds the connect
phase is corrected to say it is accepted for API-shape parity and not yet
enforced.

**Why.** `http_client.zig` discards the value (`_ = connect_timeout_ms;`, in
`connectTcp`), which is what the documentation page already said. The field
comment promised behaviour the code does not have.

**Which tree.** The corrected comment is zix's
(`~/src/zix/src/driver/prometheuz/src/config.zig`, `ScrapeConfig.conn_timeout_ms`
— "Accepted for API-shape parity and NOT yet enforced", `6da53081`). The vendored
copy zurtr builds against still carries the old sentence ("Bounds the TCP
connect phase in milliseconds, 0 disables",
`deps/zix/src/driver/prometheuz/src/config.zig`), while the discarding code is
present in both (`deps/zix/src/driver/prometheuz/src/http_client.zig`), so the
stale comment is a re-vendor away from being gone.

## D15 — The `.ASYNC` diagram in `hld-http`

**Ruling.** Corrected to the tree (one accept loop, `io.async` per connection)
and noted here rather than treated as a design change.

**Why.** The ConnQueue in the old diagram does not exist anywhere under `src/`.
If a pooled concurrency mode is still intended, the ADR is where that is said.

**Where.** `~/src/zix/docs/hld-http-en.md` — the `.ASYNC` section now reads one
accept thread with `io.async(handleConnection)` per connection, and the name
`ConnQueue` appears nowhere in that file. One textual remnant of the name
survives in the sources: `src/channel/channel.zig`'s note that its blocking
send/recv use mutex plus condition "same as ConnQueue in server.zig", where
`src/tcp/http1/server.zig` has no such type. That is a stale comment in the
zix tree (both the vendored copy and `~/src/zix`), not a pooled mode in hiding.

## D16 — `live.tree` stays exported from the framework root

**Ruling.** `zurtr.live.tree` is public surface, not an internal of the `live`
namespace: ZEEX writes `zurtr.live.tree.Builder` into every file it emits
(`src/zeex/compile.zig`, both for a view's `render` and for each component's
slot), so unexporting or moving it breaks generated templates rather than
internal callers (`dae8366`).

**Why.** The export was missing, and the failure had the worst possible shape:
every generated file named a namespace that did not exist, so the first build of
a generated project failed inside code its author never wrote, with nothing
pointing at the framework. `src/root.zig` now asserts both names at comptime
(`live.tree` and `tree.Builder`) — ZEEX's own test can only parse its output for
syntax, and a semantic lookup fails in a user's build, not in the compiler's
test.
