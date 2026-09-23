# Module contract: Live UI (`zurtr.live`)

Scope: stateful server-rendered interfaces. The module owns session state,
the typed event pipeline, the render representation, patch generation, and the
client protocol. It does not import `domain`; the binding of events to domain
actions lives in `app`.

Status: the wire codec (`src/live/protocol.zig`), the render tree
(`src/live/tree.zig`), the patcher (`src/live/patch.zig`) and the worker's bus
(`src/live/pubsub.zig`) are implemented. The session lifecycle below — attach,
resume, terminate, backpressure, the `app` binding — is contract only: there is
no session type in the tree yet.

## Session lifecycle

1. **Initial render.** An HTTP request handled by `app` builds a `live.Session`
   descriptor (view type, initial state, route) and renders the initial HTML
   with `live.tree`. The HTML carries the session token and per-element patch
   ids.
2. **Attach.** The browser opens a **WebTransport** session to the live path and
   sends `hello` with the token and the client's last `rev`. The worker either
   attaches to the live session, resumes from a serializable snapshot, or
   answers `resync`. A deployment that cannot serve HTTP/3 configures a
   WebSocket endpoint instead, which is the documented fallback
   (`decisions.md` D3).
3. **Events.** Client event batches are decoded into the view's typed
   `Event` union. The session owner processes them serially. Each event is
   validated and authorized before the handler runs (§`contracts.md` §4).
4. **Render + patch.** After each event (or info message), the view re-renders
   into a new `tree.Tree`; the module diffs it against the session's retained
   previous tree and emits patch ops with a new `rev`.
5. **Terminate.** On socket close, idle timeout, or shutdown, `terminate` runs
   once with the final state; all session-owned memory is freed.

One owner per session: all mutations happen on the session's worker thread.
Asynchronous completions (job results, pub/sub, timers) are delivered into the
owner's queue as `Info` messages, never by touching session state directly.

## The bus (`live/pubsub.zig`)

A session subscribes to topics; anything that has just committed a write publishes to a topic; every
subscriber that is *present* is handed the message. Subscription is server-side and component-driven
(`Subscribes on init to user/<user_id>/tasks`) — the client has no subscribe message, and cannot ask for
a topic the component did not declare.

What the broker is, precisely:

- **Worker-local, single-threaded.** It belongs to the worker that owns the sessions, and every operation
  happens on that thread. One owner per session is the rule it rests on, so a lock would be a lie.
- **Delivery is per session.** A subscription carries the receiver for the session that owns it: the
  session's queue gets an `Info` message, which is how `live.md` requires asynchronous completions to
  arrive — never by touching session state from outside its owner.
- **Ordered, with a gap-checkable sequence.** Messages carry a per-broker monotonic `seq` in publication
  order, so a subscriber can tell it missed something and ask for a resync rather than render a stale
  view.
- **Exactly once per present subscriber.** Subscribing twice is one subscription (a reconnect that
  re-initializes a session must not duplicate its view), and `unsubscribeAll` on terminate makes a gone
  session unreachable.
- **Not durable, not transactional.** A publish with no subscribers is dropped, and one during a
  reconnect is gone. The durable path is the outbox: the event commits in the same transaction as the
  state change, and a view that missed events resyncs from a revisioned snapshot. `app` publishes *after*
  the commit for the same reason — a subscriber must never act on a write that was rolled back
  (`decisions.md` D4: there is no `pg_notify`, and the storage cannot provide one).

This is also the seam distribution hangs off: the bus already carries "this happened" between a job, a
session and an agent on one worker, and putting `data`'s tiers underneath it is what carries the same
statement between machines.

## A view is a component, in Zig or in JavaScript

A view is the component contract below, and its parts may come from either language:

| Part | Zig | JavaScript (QuickJS) |
| :- | :- | :- |
| `render` | a ZEEX template (JSX, lowered at build time) | a template too — the template is data, not code |
| `init`, `handleEvent`, `handleInfo`, `terminate` | plain functions | functions in a loaded script revision |

The correspondence is deliberate: a `TasksPage` is one declaration, and where its handlers live is a
deployment choice rather than an architecture. A Zig view is compiled and typed end to end. A scripted
view is loaded as a revision (`zurtr.script`) and its handlers call the same host functions a Zig handler
would — authorization, validation and transactions included — so a reload changes behaviour without
changing authority. See `docs/modules/script.md` for what a script can reach, and `agents.md` for the
same rule applied to durable workflows.

What is *not* on the table is a second renderer: both languages produce the same `tree.Tree`, and the
patcher does not know which one made it.

### Interaction is the wire protocol, not a framework

Reactivity is server-driven, exactly as §"Live protocol" describes: an event goes up with a client id, the
server runs the handler, re-renders, diffs and sends patches addressed by node id. There is no client-side
state machine to keep in sync, because the client has no state to keep — which is the property that makes
resync always correct (a full render is the same operation as a patch).

### The client is a DOM bridge, and QuickJS stays on the server

The browser runs a bundled, prebuilt bridge and nothing else. Shipping the engine to the client as well
would mean two runtimes to keep in agreement about the same view, megabytes of payload, and a client that
can drift from the server's idea of the page — for no capability the patch protocol does not already have.

### Hooks, when they come

An escape hatch for client-owned behaviour is already expressible: `raw` nodes are client-owned DOM
regions the server never patches into. A hook is therefore a `raw` region with a mount callback registered
against its `data-z` id — client-side code that owns its subtree, exactly where the server has promised
not to write. Nothing in the tree, the patcher or the protocol has to change for it, which is why it can
be deferred without costing anything later.

## Render representation

A single representation serves initial HTML and later patches (see
`tree.zig` for the frozen API):

- Nodes: `element`, `text`, `raw`, `fragment`. No component nodes: components
  expand at render time; identity is expressed by keys and structure.
- Every element gets a per-render numeric id emitted as `data-z="<id>"` in
  HTML. Ids are the patch addressing scheme.
- **Keys** (`key`) mark children of lists whose identity must survive
  reordering: matching is (tag, key) at a position, not position alone.
- `raw` regions are client-owned DOM: the server never patches inside them.
- Strings are interned per tree; all tree memory lives in one arena that is
  freed as a unit.

### Patch ops

```
{"op":"text",    "id":<id>, "value":"..."}
{"op":"attr",    "id":<id>, "name":"...", "value":"..."|null}
{"op":"replace", "id":<id>, "html":"..."}
{"op":"insert",  "parent":<id>, "index":<n>, "html":"..."}
{"op":"remove",  "id":<id>}
{"op":"move",    "id":<id>, "parent":<id>, "index":<n>}
```

Rules: ops apply in order; `html` fragments carry new ids; a diff that cannot
express a change structurally degrades to `replace` of the nearest ancestor
with a keyed or component boundary. An unchanged tree yields zero ops.

## Protocol (text frames, JSON; binary frames are a later optimization)

**Channel.** WebTransport over HTTP/3, on the same origin as the page
(`decisions.md` D3). Frames are the same text JSON either way; over WebTransport
they are newline-delimited on one bidirectional stream — the convention zix's
own examples use (`deps/zix/examples/tls/webtransport_live.html`) — and
datagrams carry the notes that may be dropped. A `ws://` / `wss://` endpoint
selects the **WebSocket fallback**, where one frame is one WebSocket message;
the client never downgrades by itself. What the shipped self-test
(`assets/zurtr_live_test.html`) exercises is the fallback — it stubs
WebSocket — while the WebTransport channel has been exercised only to its
opening handshake.

Client → server:

```
{"t":"hello","token":"...","rev":<n>,"pending":[<event-ids>]}
{"t":"events","batch":[{"id":<u64>,"ev":"<name>","payload":{...}}]}
{"t":"ack","rev":<n>}
{"t":"resync_req"}
```

Server → client:

```
{"t":"ready","rev":<n>,"resume":<bool>}
{"t":"patch","rev":<n>,"ops":[...],"forms":{...},"focus":{...},"nav":{...}}
{"t":"resync","rev":<n>,"html":"<full page>"}
{"t":"error","event":<id>,"kind":"validation|authz|conflict|unavailable|internal","fields":{...},"message":"..."}
{"t":"redirect","to":"..."}
```

- `rev` is the server revision; every state change increments it.
- Event ids are client-generated and monotonic; the server acknowledges by
  including processed ids in the next `patch` (`"acks":[...]`), so a
  reconnecting client resends only unacknowledged events.
- **Reconnect**: the client presents `rev` + pending ids. The server continues
  the session when the revision gap is within the retained patch window and
  the session is alive; otherwise it sends `resync` (full HTML + fresh rev).
  Resync is always correct; incremental replay is an optimization.
- **Backpressure**: outbound queue is bounded by bytes and message count.
  Over the soft limit the session coalesces (intermediate patches dropped,
  latest full render kept); over the hard limit the server sends `resync` and
  closes the socket, requiring a fresh attach. Slow clients never stall the
  reactor or the session owner.
- **Forms**: the patch message may carry form field values for inputs the
  server intentionally rewrites; the client preserves focus/selection and
  uncommitted values otherwise (§`contracts.md` §6).
- **Uploads**: `POST` to a session-scoped upload endpoint with the session
  token; the result is delivered to the session as an `Info` message
  (`upload_done` / `upload_failed`) with a store handle. Upload payloads are
  never held in session state, only handles (ownership table, §2).
- **Navigation**: same-session navigation (`nav`) re-initializes the view
  against the same socket and renders a full patch; cross-session navigation
  responds `redirect`.

## Component contract

```
State     — a concrete struct, sized at compile time.
Event     — union(enum) of named event variants with typed payloads.
Info      — union(enum) of asynchronous messages (job results, pub/sub, timers, uploads).
init      — fn(Init) State               (context: route params, principal, session services)
handleEvent — fn(*State, Event, Ctx) Result
handleInfo  — fn(*State, Info, Ctx) Result
render    — fn(*const State, *Builder) NodeId
terminate — fn(*State, Ctx) void          (explicit; always called once)
```

`Ctx` gives the event arena allocator, the principal, and the domain/db
services. Handlers return `Result`: `.none` (state changed; re-render),
`.reply(Reply)` (structured client error/notice), `.redirect(...)`, or
`.stop` (terminate session).

Comptime verification: `Event` and `Info` variants each carry a declared wire
name; the module builds the decoder table from the union at comptime and
rejects duplicate names, non-decodable payloads, and handlers that do not
accept their own event type. Components are functions with typed properties
and explicit identity (key); a component identity change (key change) is a
replace, never a silent state transfer.

## Testing requirements

- `tree_test`: HTML golden cases (escaping, attributes, void elements, raw
  pass-through), id assignment stability.
- `patch_test`: diff correctness — text/attr changes, keyed insert/remove,
  keyed reorder, subtree replace, no-op → empty, and apply-to-HTML
  equivalence: applying a patch to the old HTML must produce the new HTML
  (checked structurally on the tree, not by string equality).
- `protocol_test`: frame encode/decode round-trips, unknown-type and malformed
  payload rejection, revision monotonicity, ack accounting.
- `session_test`: single-owner invariants, backpressure coalescing, resync on
  revision gap, terminate-once semantics.
