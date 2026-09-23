# swerver change: deferred application responses

Vendored-tree design note (see `deps/swerver/UPSTREAM.md`). Status: designed,
not implemented. Complements swerver's existing park/resume.

## What exists today

- `HandlerFn` is synchronous: `fn (ctx) Response`; the body must be valid at
  return (copied into the write queue).
- **Park/resume** exists for engine-owned async ops: the handler returns the
  park sentinel (`Response.parked`, `status == 0`), `http1.handleParkSentinel`
  sets `conn.x402 = .db_parked`, and the resume path
  (`dispatch.pgResume` / `ffiResumeCompletion` / wasm completion) validates the
  connection generation and calls `restartConnIo(server, conn_index, conn_id)`.
- Cross-thread completion plumbing exists only for the FFI embedded mode
  (`ffi_bridge` ring + `IoRuntime.registerWake` / `.wake`). Note
  `runtime/io.zig`: the io_uring backends' wake is not yet ring-safe.

Park is one-op, plain-data-stash, reactor-driven. It cannot serve completions
that originate outside the reactor (another thread, a job runner, a timer in
another process) nor responses that need heap-owned bodies assembled off-loop.

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

- Producers (any thread in the worker process) push to a per-worker MPSC queue
  (`io.completions`) and call `io.wake()`; the reactor drains it each loop turn
  (same place `ffi_bridge` completions are drained).
- On drain: look up the connection, require `conn.id == handle.conn_id` and
  `conn.state != .closed`, require `conn.x402 == .deferred` (set when the
  request parked on a deferred handle), then serialize the response through the
  normal write path (HTTP/1.1 first; HTTP/2/H3 return `error.Unsupported` and
  the deferred request is failed closed with 500 in v1).
- Stale handles: drop and increment `stats.deferred_dropped`; never touch a
  recycled connection.
- Ownership: consumer frees `headers`/`body` with the server allocator after
  the response is copied into the write queue. Producer must not touch them
  after `complete`.

**Handler API**

```zig
// in HandlerContext, HTTP/1.1 only in v1
pub fn defer(self: *HandlerContext) response.Response;   // returns the sentinel; sets .deferred
pub fn deferHandle(self: *HandlerContext) ?DeferredHandle; // valid only right after defer()
```

`handleParkSentinel` gains the `.deferred` branch: the sentinel is accepted only
if `ctx.defer()` was called for this request (tracked in the connection's park
slot); otherwise the existing "sentinel without live park" 500 applies.

**Limits and failure**

- Bounded queue (`deferred_queue_capacity`, default 1024 completions/worker);
  full → producer blocks (role processes) or sheds (`error.QueueFull`).
- Per-connection deferred timeout (`deferred_timeout_ms`, default 30s): the
  housekeeping tick fails the request closed with 504 and clears the park, so a
  lost producer cannot pin a connection forever.
- Worker shutdown: drain completions, then fail remaining deferred requests
  closed. Connection close while deferred: the handle is invalidated
  (generation/id check does the work); the completion is dropped.

**Wake path**

- `registerWake()` is called by `runLoop` for every worker (not only embedded
  servers). For io_uring backends, either implement a ring-safe wake (eventfd
  registered as an external fd) or document that deferred completions degrade
  to a poll interval on those backends; the epoll/kqueue self-pipe path is the
  v1 target.

## Integration points

| File | Change |
| --- | --- |
| `runtime/connection.zig` | `.deferred` in the park state enum; `request_id` counter; deferred deadline field |
| `server/http1.zig` | `handleParkSentinel` deferred branch; park-slot bookkeeping in `HandlerContext` |
| `server/dispatch.zig` | drain completions next to the ffi ring drain; `deferredResume` (validate + serialize + `restartConnIo`); housekeeping timeout sweep |
| `runtime/io.zig` | completion queue + wake for all workers; counters |
| `server.zig` | `Server.complete(handle, completion)` public entry; shutdown drain |
| `lib.zig` | export `DeferredHandle`, `Completion` |

## Tests

- Unit: queue push/drain ordering, capacity behavior, stale-handle rejection
  (simulate a recycled connection id), timeout sweep, ownership freeing (no
  leaks under `std.testing.allocator`).
- Integration: a test handler defers, a helper thread completes after 10 ms,
  the response arrives with the right body; a second test defers and never
  completes → 504 after the timeout; a third defers then disconnects → no
  crash, completion dropped, counter incremented.
