# zix change: deferred application responses

Vendored-tree design note (see `deps/zix/UPSTREAM.md`). Status: designed, not
implemented. Written against the previously vendored swerver tree, which the
transport swap removed; the requirement it encodes is still the framework's —
the mechanism is not. See `overview.md` §Execution model (class 3) and
`contracts.md` §1.3 for the rules a producer and consumer must satisfy.

## What exists today (zix)

- `HandlerFn` is synchronous: the handler produces its response before it
  returns, and the body is copied into the write path
  (`deps/zix/src/tcp/http1/core.zig`).
- Three dispatch models, chosen in the server config
  (`deps/zix/src/tcp/http1/config.zig`): `.EPOLL` and `.URING` are
  shared-nothing worker loops with their own `SO_REUSEPORT` listener
  (`dispatch/epoll.zig`, `dispatch/uring.zig`); `.ASYNC` runs each connection as
  a fiber on a thread pool (`dispatch/async.zig`, `io.async(connEntry, …)`). In
  `.ASYNC` the request's `std.Io` is a yielding backend, so a driver round trip
  parks the connection's *fiber* and the worker keeps running
  (`dispatch/async.zig`, `context.zig`).
- A post-dispatch hook exists for the WebSocket promotion and is honored by
  every model: the handler records a thread-local request
  (`core.requestWebSocket`) and the owning loop consumes it right after the
  handler returns (`core.takeWebSocket` — call sites in `dispatch/epoll.zig`,
  `dispatch/uring.zig`, `tls_serve.zig`, `tls_mux.zig`, and `core.zig` for the
  `.ASYNC` blocking path).
- What does **not** exist: any way for a thread other than the owning loop to
  wake it. The HTTP/1.1 dispatch entry points are `runEpoll` / `runAsync`; there
  is no external-fd registration, no completion queue and no eventfd anywhere in
  the tree. `deps/zix/src/channel/channel.zig` is a fiber-safe in-process
  channel, but nothing drives a server loop with one.
- The Postgres driver is a `std.Io` driver
  (`deps/zix/src/driver/postgrez/src/conn.zig`); its pool parks exhausted callers
  on a futex (`pool.zig`) — a blocking park, not a reactor park.

The mechanism this note was written against — a park sentinel
(`Response.parked`, `conn.x402 = .db_parked`), an `ffi_bridge` ring, and
`IoRuntime.registerWake` — belonged to the swerver tree and has no counterpart
here. What remains true is the shape below: one in-flight operation per request,
resumed by the loop, with the request buffer held across the handoff; and, for
completions that originate outside the loop, a validated handle plus owned
response data.

## Design

**Handle**

```zig
pub const DeferredHandle = struct {
    conn_index: u32,
    conn_id: u64,          // generation: rejects recycled slots
    request_id: u64,       // per-connection monotonic, from the request being answered
    worker_id: u32,        // which worker owns the reactor
};
```

**Completion**

```zig
pub const Completion = struct {
    handle: DeferredHandle,
    status: u16,
    headers: []const Header,   // owned by the producer, freed by the consumer
    body: []u8,                // owned by the producer, freed by the consumer
    keep_alive: bool,
};
```

- Producers (any thread in the worker process) push to a per-worker queue and
  signal the loop; the loop drains it each turn, in the same places it already
  does per-turn bookkeeping.
- On drain: look up the connection, require `conn.id == handle.conn_id` and
  `conn.state != .closed`, require the connection to be parked on a deferred
  reservation, then serialize the response through the normal write path
  (HTTP/1.1 first; HTTP/2 and HTTP/3 return the deferred request failed closed
  with 500 in v1).
- Stale handles: drop and increment a `deferred_dropped` counter; never touch a
  recycled connection.
- Ownership: the consumer frees `headers`/`body` with the server allocator after
  the response is copied into the write path. The producer must not touch them
  after `complete`.

**Handler API**

```zig
// HTTP/1.1 only in v1
pub fn defer(self: *HandlerContext) Response;              // reserves the connection; sentinel response
pub fn deferHandle(self: *HandlerContext) ?DeferredHandle; // valid only right after defer()
```

The reservation has to be explicit in zix: there is no park sentinel to extend,
so the loop can only honor a deferral the handler recorded, in the same
post-dispatch hook the WebSocket promotion uses.

**Limits and failure**

- Bounded queue (default 1024 completions/worker); full → the producer blocks
  (role processes) or sheds (`error.QueueFull`).
- Per-connection deferred timeout (default 30s): the housekeeping tick fails the
  request closed with 504 and clears the reservation, so a lost producer cannot
  pin a connection forever.
- Worker shutdown: drain completions, then fail remaining deferred requests
  closed. Connection close while deferred: the handle is invalidated
  (generation/id check does the work); the completion is dropped.

**Wake path — the open call**

This is the piece with no zix counterpart: the designs above assume a
loop-integrated wake source, and zix's HTTP/1.1 loops have none. Two shapes fit
the tree as it stands, and neither is chosen here:

- zix grows a wake source for its loops (an external fd registered with the
  epoll/uring loops, or a turn-interval poll), and the deferred class works in
  every model; or
- the deferred class is confined to `.ASYNC`, where a driver round trip already
  parks the connection's fiber and a completion is just a resume.

## Integration points

The version of this note that named swerver files (`runtime/connection.zig`,
`server/http1.zig`, `server/dispatch.zig`, `runtime/io.zig`, `server.zig`,
`lib.zig`) described a tree that is not vendored. In zix, the files this design
touches are:

| File | Role |
| --- | --- |
| `deps/zix/src/tcp/http1/core.zig` | handler dispatch and the post-dispatch hook |
| `deps/zix/src/tcp/http1/dispatch/{epoll,uring,async}.zig` | the loops |
| `deps/zix/src/tcp/http1/context.zig` | the per-request context |
| `deps/zix/src/lib.zig` | the transport's exported surface |

Where a deferred reservation is honored, and how the wake path resolves, are
decisions this note deliberately leaves open.

## Tests

- Unit: queue push/drain ordering, capacity behavior, stale-handle rejection
  (simulate a recycled connection id), timeout sweep, ownership freeing (no
  leaks under `std.testing.allocator`).
- Integration: a test handler defers, a helper thread completes after 10 ms, and
  the response arrives with the right body; a second handler defers and never
  completes → 504 after the timeout; a third defers then disconnects → no crash,
  completion dropped, counter incremented.
