# zix change: native WebSocket server endpoints

Vendored-tree design note (see `deps/zix/UPSTREAM.md`). Status: the transport
half is implemented in zix; the framework-facing route and handler layer below
is designed, not implemented. Written against the previously vendored swerver
tree, which the transport swap removed.

## What exists today (zix)

- `deps/zix/src/tcp/http1/websocket.zig` is a native server endpoint, not a
  proxy: frame codec (`parseFrame`, `buildHeader`, `buildFrame`), the handshake
  (`acceptKey`, `upgrade` — computes `Sec-WebSocket-Accept` and writes
  `101 Switching Protocols` on the connection's own fd), an engine-owned frame
  pump (`serve`, `serveTls`, `serveBlocking`, `pump`, `pumpRing`) and outbound
  helpers (`send`, `sendFD`, `broadcast`). Exported as `Http1.WebSocket` and
  `Http1.WsFrameFn` (`deps/zix/src/tcp/http1/Http1.zig`).
- A handler promotes its connection by calling `Http1.WebSocket.serve(...)`,
  which records a thread-local request (`core.requestWebSocket`); the owning loop
  consumes it right after the handler returns (`core.takeWebSocket` — call sites
  in `dispatch/epoll.zig`, `dispatch/uring.zig`, `tls_serve.zig`, `tls_mux.zig`,
  and `core.zig` for the `.ASYNC` blocking path). The promotion is honored under
  every dispatch model.
- The parallel `Http` surface has the same shape
  (`deps/zix/src/tcp/http/websocket.zig`), and the zixer edge carries the proxy
  and tunnel paths (`deps/zix/src/zixer/ws_tunnel.zig`,
  `deps/zix/src/zixer/http2_ws_bridge.zig` — the RFC 8441 extended-CONNECT
  bridge).
- What is missing is the framework-facing layer: the router has no WebSocket
  route kind (`deps/zix/src/tcp/http1/router.zig` —
  `RouteKind = enum(u8) { EXACT, PREFIX, PARAM }`), the engine hands frames to a
  single `*const fn (fd, opcode, payload) void` with no context pointer and no
  per-connection user slot, and the codec enforces none of the message-level
  rules below (an unmasked client frame is unmasked-as-absent rather than
  rejected, frames are not assembled, and there is no message size cap, close
  policy or UTF-8 check).

## Design

**Route API** (router):

```zig
pub const WsHandler = struct {
    ctx: *anyopaque,
    on_open: *const fn (ctx: *anyopaque, conn: *WsConn) void,
    on_message: *const fn (ctx: *anyopaque, conn: *WsConn, msg: Message) void,
    on_close: *const fn (ctx: *anyopaque, conn: *WsConn, code: u16, reason: []const u8) void,
};
pub const Message = struct { opcode: Opcode, payload: []const u8 }; // payload valid during the call
// router.ws("/zurtr/live", ws_handler);
```

- Handlers run on the worker thread, like HTTP handlers, with the same
  no-blocking rule. Outbound writes go through the existing write path.
- `WsConn` exposes `sendText`, `sendBinary`, `ping`, `close(code, reason)`,
  buffer identity (`conn_index`, `conn_id`) and a per-connection user slot
  (`*anyopaque`) owned by the handler's framework layer. zix's `WsFrameFn`
  carries the fd alone, so both the context pointer and the slot are part of
  this layer, not of the engine.

**Handshake**

- The accept-key computation and the 101 response exist (`websocket.zig`). The
  framework's rules on top of them are the design: a `.ws` route with a valid
  upgrade request (method GET, `Sec-WebSocket-Version: 13`, base64 16-byte
  `Sec-WebSocket-Key`) upgrades on the connection itself (no tunneling, no
  second connection); a non-upgrade request to a `.ws` route → 426 Upgrade
  Required; subprotocol choice is offered to the handler, none by default.

**Frame codec rules** (the part `websocket.zig` does not enforce today)

- Opcodes: continuation, text, binary, close, ping, pong.
- Client→server frames MUST be masked (RFC 6455 §5.1): unmasked → close 1002.
- Fragmentation: continuation assembly with a bounded message size
  (`ws_max_message_bytes`, default 1 MiB) and bounded fragment count; control
  frames may interleave and must not be fragmented; control payload ≤ 125.
- Control handling: ping → pong (unless a close is in flight); close → echo
  close and transition to draining; protocol errors → close with the right code
  (1002 protocol error, 1007 invalid payload for text UTF-8 failures, 1009 too
  big).
- Buffers: frames are parsed out of the connection read buffer; assembled
  messages use a bounded per-connection heap buffer only when fragmented (no
  per-frame allocation).

**Write path**

- `sendText`/`sendBinary` build a frame (server→client unmasked) into a pool
  buffer and enqueue it; partial writes use the existing write machinery.
  Backpressure is reported to the handler (which may drop or coalesce) rather
  than buffering without bound.
- Close: a close frame is queued, then the socket closes after the write drains,
  with a `ws_close_timeout_ms` cap.

**Connection state**

```
ws_state: ?*WsState,       // heap-allocated lazily on upgrade
// WsState: handler ptr, user slot ptr, fragmented-message buffer,
//          fragment count, close_sent/close_received, message size counters
```

The struct is heap-allocated on upgrade and freed on close.

**Timeouts and lifecycle**

- The connection timeout applies, refreshed on any frame.
- Ping keepalive: optional per-route interval; a missed pong within
  `pong_timeout_ms` closes the connection.
- On worker shutdown/drain: send close 1001 (going away), then close.
- HTTP/2 and HTTP/3: not supported in v1 (RFC 8441 CONNECT later); a `.ws` route
  on those protocols responds 501. zix's RFC 8441 support lives in the zixer
  edge bridge, not in the HTTP/2 server.

## Integration points

The version of this note that named swerver files (`proxy/websocket.zig`,
`dispatch.zig`, `router/router.zig`, `runtime/connection.zig`,
`server/http1.zig`, `lib.zig`) described a tree that is not vendored. In zix the
files this design touches are:

| File | Role |
| --- | --- |
| `deps/zix/src/tcp/http1/websocket.zig` | codec, handshake, pump, send helpers (exists) |
| `deps/zix/src/tcp/http1/core.zig` | dispatch and the post-dispatch promotion hook |
| `deps/zix/src/tcp/http1/router.zig` | route kinds — the `.ws` kind is new |
| `deps/zix/src/tcp/http1/Http1.zig` | the exported surface — the handler type is new |
| `deps/zix/src/tcp/http1/{tls_serve,tls_mux}.zig` | the TLS serve paths that already consume the handoff |

## Tests

- Codec: masked/unmasked, all opcodes, fragmentation incl. interleaved control
  frames, oversize rejection (1009), unmasked rejection (1002), invalid UTF-8
  text (1007), close echo, ping/pong, 125-byte control limit, partial frames
  split across reads. `websocket.zig` carries the frame-level tests of this set
  today; the message-level rules above are new.
- Handshake: known-answer accept-hash test (RFC 6455 example key →
  `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`), bad version → 426, missing key → 400.
- Integration: a test server with a ws echo route driven by a raw TCP client
  (masked frames) asserting echo, ping/pong, close handshake and the connection
  returning cleanly; a fragmented 2 MiB message is rejected with 1009 without
  growing memory unboundedly.
