# Module contract: Live UI (`zurtr.live`)

Scope: stateful server-rendered interfaces. The module owns session state,
the typed event pipeline, the render representation, patch generation, and the
client protocol. It does not import `domain` — none of `src/live/` does — and
the binding of events to domain actions lives in `app`.

Status: four files are implemented — the wire codec (`src/live/protocol.zig`),
the render tree (`src/live/tree.zig`), the patcher (`src/live/patch.zig`) and the
worker's bus (`src/live/pubsub.zig`) — and three of them are exported from the
framework root as `zurtr.live.{protocol,pubsub,tree}` (`src/root.zig`). The
fourth is **not**: nothing in the tree imports `src/live/patch.zig`, so no build
step compiles it and its 17 tests do not ride in `zig build test-zurtr`. It is
implemented and unreachable, which is worth knowing before trusting a green
suite to cover patch generation.

`zurtr.live.tree` being exported is not a convenience. ZEEX names it in every
file it emits (`pub fn render(props: anytype, b: *zurtr.live.tree.Builder) !void`),
and it was not exported until `dae8366` — before that, every generated template
failed in the *application's* build while ZEEX's own tests stayed green, because
those tests parse the generated source for syntax rather than resolving its
names. `src/root.zig`'s test block now asserts the two names ZEEX depends on
(`live.tree` and `live.tree.Builder`) at comptime, in a build where both sides
are visible. Moving the export breaks templates, not just callers
(`docs/modules/zeex.md`, `decisions.md`).

The session lifecycle below — attach, resume, terminate, backpressure, the `app`
binding — is contract only: there is no session type in the tree, and nothing
serves a socket.

## Session lifecycle

1. **Initial render.** An HTTP request handled by `app` builds a `live.Session`
   descriptor (view type, initial state, route) and renders the initial HTML
   with the render tree (`Tree.writeHtml`). The HTML carries the session token
   and per-element patch ids — the ids are `tree.zig`'s `z-id` attributes; the
   token is the session layer's, which does not exist.
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
subscriber that is *present* is handed the message:

```zig
Broker.subscribe(session: SessionId, topic: []const u8, receiver: Receiver) Error!void
Broker.unsubscribe(session, topic) void
Broker.unsubscribeAll(session) void
Broker.publish(topic: []const u8, payload_json: []const u8) Error!usize   // how many deliveries landed
Broker.subscriberCount(topic) usize
```

Subscription is server-side and component-driven (`Subscribes on init to
user/<user_id>/tasks`) — the client has no subscribe message (`ClientMsg` is
`hello`/`events`/`ack`/`resync_req` and nothing else), and cannot ask for a topic
the component did not declare. The component-driven half is contract; the
message surface that makes it possible is not.

What the broker is, precisely:

- **Worker-local, single-threaded.** It belongs to the worker that owns the sessions, and every operation
  happens on that thread. One owner per session is the rule it rests on, so a lock would be a lie.
- **Delivery is per session.** A subscription carries the `Receiver` for the session that owns it
  (`context` + a `deliver` function), and the message it is handed names that session, its topic, its
  payload and a sequence number: the session's queue gets an `Info` message, which is how this document
  requires asynchronous completions to arrive — never by touching session state from outside its owner.
  A receiver that refuses its message is skipped for that publication (`error.ReceiverFailed`) and is not
  counted as delivered; an allocator failure inside one stops the publication.
- **Ordered, with a gap-checkable sequence.** `Message.seq` is the broker's own `published` counter,
  incremented once per publication and stamped on every delivery, so a subscriber can tell it missed
  something and ask for a resync rather than render a stale view.
- **Exactly once per present subscriber.** Subscribing twice is one subscription (a reconnect that
  re-initializes a session must not duplicate its view), and `unsubscribeAll` on terminate makes a gone
  session unreachable — that is what `terminate` is specified to call.
- **Not durable, not transactional.** A publish with no subscribers is dropped — and is not an error, it
  is the ordinary case for a worker whose sessions have gone away. The durable path is the outbox: the
  event commits in the same transaction as the state change, and a view that missed events resyncs from a
  revisioned snapshot. The bus itself has no transactional form: `publish` takes a topic and bytes, not a
  transaction, so "publish after the commit" is a rule the caller keeps (`decisions.md` D4: there is no
  `pg_notify`, and the storage cannot provide one).

This is also the seam distribution hangs off: the bus already carries "this happened" between a job, a
session and an agent on one worker, and putting `data`'s tiers underneath it is what carries the same
statement between machines.

## A view is a component, in Zig or in JavaScript

A view is the component contract below, and its parts may come from either language:

| Part | Zig | JavaScript (QuickJS) |
| :- | :- | :- |
| `render` | a ZEEX template (JSX, lowered at build time, `docs/modules/zeex.md`) | a template too — the template is data, not code |
| `init`, `handleEvent`, `handleInfo`, `terminate` | plain functions | functions in a loaded script revision |

The correspondence is deliberate: a `TasksPage` is one declaration, and where its handlers live is a
deployment choice rather than an architecture. A Zig view is compiled and typed end to end. A scripted
view is loaded as a revision (`zurtr.zscript`) and its handlers call the same host functions a Zig handler
would — authorization, validation and transactions included — so a reload changes behaviour without
changing authority. See `docs/modules/zscript.md` for what a script can reach, and `agents.md` for the
same rule applied to durable workflows.

What is *not* on the table is a second renderer: both languages produce the same `tree.Tree`, and the
patcher does not know which one made it.

### Interaction is the wire protocol, not a framework

Reactivity is server-driven, exactly as §"Live protocol" describes: an event goes up with a client id, the
server runs the handler, re-renders, diffs and sends patches addressed by node id. There is no client-side
state machine to keep in sync, because the client has no state to keep — which is the property that makes
resync always correct (a full render is the same operation as a patch).

### The client is a DOM bridge, and QuickJS stays on the server

The browser runs a bundled, prebuilt bridge (`assets/zurtr_live.js`) and nothing else. Shipping the engine
to the client as well would mean two runtimes to keep in agreement about the same view, megabytes of
payload, and a client that can drift from the server's idea of the page — for no capability the patch
protocol does not already have.

### Hooks, when they come

An escape hatch for client-owned behaviour is already expressible: `raw` nodes are client-owned DOM
regions the server never patches into. A hook is therefore a `raw` region with a mount callback registered
against its `z-id` id — client-side code that owns its subtree, exactly where the server has promised
not to write. Nothing in the tree, the patcher or the protocol has to change for it, which is why it can
be deferred without costing anything later.

## Render representation (`live/tree.zig`)

A single representation serves initial HTML and later patches:

- Nodes: `Kind = {element, text, raw, fragment}`. No component nodes: components
  expand at render time; identity is expressed by keys and structure.
- **A node's id is its index in the tree's node list**, so `node(id).id == id`,
  and every element emits `z-id="<its own id>"` in addition to its user
  attributes. `fragment` emits only its children (never a `z-id`), `raw` emits
  its bytes verbatim, `text` emits escaped text. Ids are the patch addressing
  scheme and are stable for as long as the tree lives.
- **Keys** (`key: u32`, `0` = keyless) mark children of lists whose identity must
  survive reordering: keyed children match across positions by key, keyless ones
  match positionally within the keyless subsequence.
- `raw` regions are client-owned DOM: the server never patches inside them.
- Strings are interned per tree (`StrId`, with `empty_str = 0` meaning the empty
  string and never stored); all tree memory — nodes, string bytes, child/attr
  slices, the interning index — lives in one arena that `Tree.deinit` frees as a
  unit. Serialization is deterministic: the same tree always produces the same
  bytes.
- The API a view uses: `Builder.init(tree)` (which creates the root `fragment` at
  id 0, so a `Builder` tree always renders), `element(tag, attrs, key)`,
  `fragment(key)`, `text`, `raw`, `close`, and `deinit` — which closes every
  node left open, so a forgotten `close` cannot silently drop children. `text` /
  `raw` append leaves to the innermost open node; a `close` with nothing open, or
  any append after the root is closed, is `error.NotOpen`.
- Attribute specs are `AttrSpec{ name, value: ?[]const u8 }`, and a `null` value
  **omits the attribute** — which is why a bare HTML attribute is rendered as an
  empty value rather than through that route (the `toggle` attribute kind in
  `docs/modules/zeex.md`).
- `writeHtml(w, root)` streams the HTML; `writeHtmlAlloc(gpa, root)` is the
  convenience form. Void tags (`isVoidTag`) emit no closing tag.

### Patch ops (`live/patch.zig`)

```
{"op":"text",    "id":<id>, "value":"..."}
{"op":"attr",    "id":<id>, "name":"...", "value":"..."|null}
{"op":"replace", "id":<id>, "html":"..."}
{"op":"insert",  "parent":<id>, "index":<n>, "html":"..."}
{"op":"remove",  "id":<id>}
{"op":"move",    "id":<id>, "parent":<id>, "index":<n>}
```

These are the wire shapes `patch.writeJson` emits, and the `Op` union is their
source. Two coordinate rules go with them, because they are where a client
implementation goes wrong:

- Every op addresses nodes in the **previous** (currently rendered) tree —
  `replace.id`, `insert.parent`, `move.parent`, `remove.id`, `move.id` — while
  new markup (`replace.html`, `insert.html`) is rendered from the **next** tree
  and installed verbatim, ids included. A parent may be a matched `fragment`,
  which emits no markup of its own: a client resolves that by inlining the
  fragment's children into the nearest rendered ancestor and offsetting the
  index.
- `index` is a position in the **final** child list of the parent: 0 is "first
  child" and `child_count` is "append". Clients apply ops in order with
  remove-then-insert semantics.

Matching and fallbacks, as implemented:

- Nodes match on `(kind, tag)`; keys decide which children are candidates. The
  root is always matched when kind and tag agree, and a root that disagrees is a
  single `replace`.
- A candidate pair whose `(kind, tag)` disagree is a `replace` when it keeps its
  position, otherwise `remove` + `insert`.
- Unmatched previous children are `remove`d; unmatched next children are
  `insert`ed. A keyed child that survives matching but must move left is one
  `move`; a displaced *keyless* child, or one whose kind or tag also changed,
  falls back to `remove` + `insert`, which is always correct. A keyed reorder
  therefore costs one op per displaced child, never a whole-list replace.
- Identical trees produce zero ops, and matched `raw` nodes are opaque.
- Matching is allocation-free: `diff` allocates nothing beyond appends to the
  caller's op list, and reconciles each child list with linear scans (O(n²) work
  per parent, where n is its child count).

## Protocol (text frames, JSON; binary frames are a later optimization)

**Channel.** WebTransport over HTTP/3, on the same origin as the page
(`decisions.md` D3). Frames are the same text JSON either way; over WebTransport
they are newline-delimited on one bidirectional stream, and datagrams carry the
notes that may be dropped. A `ws://` / `wss://` endpoint selects the
**WebSocket fallback**, where one frame is one WebSocket message; the client
never downgrades by itself. The framing is the channel's: `protocol.zig` is
envelope-only and decodes **exactly one JSON document per frame** (trailing
non-whitespace is `Malformed`), so the stream delimiter is the transport's
business and the codec's tests never see one. The vendored transport carries no
example to point at — `deps/zix/UPSTREAM.md` records that zix's `examples/` are
excluded from the vendored set — so D3 is where the convention is written down.
What the shipped self-test (`assets/zurtr_live_test.html`, with the bridge in
`assets/zurtr_live.js`) exercises is the fallback — it stubs WebSocket, and says
so — while the WebTransport channel has been exercised only to its opening
handshake.

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
{"t":"patch","rev":<n>,"acks":[...],"ops":[...],"forms":{...},"focus":{...},"nav":{...}}
{"t":"resync","rev":<n>,"html":"<full page>"}
{"t":"error","event":<id>,"kind":"validation|authz|conflict|unavailable|internal","fields":{...},"message":"..."}
{"t":"redirect","to":"..."}
```

Decoding is deliberately coarse — a frame is one of the four client messages or
it is rejected:

- Object field order is not significant and JSON whitespace is allowed; unknown
  object fields are **ignored** (forward compatibility), while a repeated known
  field name is `Malformed` — `std.json.Scanner` emits duplicate keys, so every
  field loop tracks "already seen" explicitly.
- Four decode errors and no others: `Malformed`, `UnknownType`, `TooLarge`,
  `MissingField`. The set is frozen and has no allocation variant: every
  allocation the decoder makes is bounded by a limit below, so a failed
  allocation is reported as `TooLarge`.
- Limits, enforced where each quantity becomes known: total frame 64 KiB
  (`max_message_bytes`, checked before parsing), 256 events per batch, 128 bytes
  per event name, 256 bytes per token, 1024 pending ids, 16 KiB of raw JSON per
  event payload.
- Encoding is compact JSON with a fixed field order; `ops`, `forms`, `focus`,
  `nav` and `fields` are inserted **verbatim** (already serialized by the render
  and patch layers) and are not re-encoded or validated; a `null` optional is
  omitted from the object, never emitted as `null`.

Semantics the session layer owes on top of the envelope:

- `rev` is the server revision; every state change increments it.
- Event ids are client-generated and monotonic; the server acknowledges by
  including processed ids in the next `patch` (`"acks":[...]`, which the encoder
  always writes), so a reconnecting client resends only unacknowledged events.
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
render    — fn(*const State, *Builder) NodeId   (contract; see below)
terminate — fn(*State, Ctx) void          (explicit; always called once)
```

`Ctx` gives the event arena allocator, the principal, and the domain/db
services. Handlers return `Result`: `.none` (state changed; re-render),
`.reply(Reply)` (structured client error/notice), `.redirect(...)`, or
`.stop` (terminate session).

The one `render` signature that exists today is ZEEX's, and it is not the one
above: a generated view is
`pub fn render(props: anytype, b: *zurtr.live.tree.Builder) !void` — it builds
into a `Builder` and returns nothing, because the tree's ids are assigned as
nodes are added. A `NodeId`-returning `render` would mean the session layer
owns a builder and takes the root id back; no session layer exists to do that,
so the two shapes have not been reconciled, and the exported contract is
ZEEX's.

Comptime verification: the contract's `Event`/`Info` decoder table is not built
anywhere yet — `protocol.zig` carries an event's payload as opaque raw JSON
(`Event.payload_json`, kept verbatim so the typed decoder sees exactly what the
client sent), and the session layer is what would own that table, the duplicate
wire-name rejection, and the handler-signature checks. Components are functions
with typed properties and explicit identity (key); a component identity change
(key change) is a replace, never a silent state transfer.

## Testing requirements

The tests are in-file and run under `zig build test-zurtr`, except where noted:

- `tree.zig` (8 tests): HTML golden cases (escaping, attributes, void elements,
  raw pass-through), id assignment stability and determinism across two
  builders, interning, unclosed nodes closed by `deinit`, and `error.NotOpen`
  after the root is closed.
- `patch.zig` (17 tests): keyed permutation, mixed insert/remove/move/text/attr
  edits, randomized keyed lists, identical and empty trees → zero ops, keyed
  reorder costing one move per displaced child, keyless displacement falling
  back to remove+insert, tag change and root kind change replacing, nested
  fragments, matched `raw` opacity, and the JSON encoding of every op kind.
  **These do not run in any build step**: nothing imports the file, so they are
  compiled only by a `zig test src/live/patch.zig`-style invocation, which no
  step performs.
- `protocol.zig` (22 tests): frame encode/decode round-trips, unknown-type and
  malformed payload rejection, field reordering, duplicate-field and
  trailing-content rejection, `ack` and `pending` round-trips through both
  directions, optional-field omission on encode, and every limit at its boundary
  and one past it. What the file explicitly does **not** cover is what an `ack`
  means or how `rev` advances — that is session semantics, and the module says
  so in its own header.
- `pubsub.zig` (5 tests): per-subscriber addressing, double subscribe as one
  subscription, `unsubscribeAll` releasing topics and making a gone session
  unreachable, monotonic sequence in publication order, and a topic with no
  subscribers not being an error.
- `session_test`: does not exist. There is no session type, so single-owner
  invariants, backpressure coalescing, resync on revision gap and terminate-once
  semantics are unproven rather than tested.
