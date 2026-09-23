# swerver change: native WebSocket server endpoints

Vendored-tree design note. Status: designed, not implemented. Complements
swerver's existing WebSocket **proxy** support.

## What exists today

- `proxy/websocket.zig`: `isWebSocketUpgrade(req)` (Upgrade + Connection
  header checks), `performUpgrade` (client-side handshake to an upstream), and
  `isValid101`.
- `dispatch.zig`: on an upgrade request, swerver performs the upstream
  handshake and then marks **both** connections `is_tunnel` with
  `tunnel_peer_index`/`tunnel_peer_id`; `handleTunnelRead` forwards raw bytes
  with no HTTP parsing; `closeTunnel` tears both sides down.
- There is no server-side handshake responder, no frame codec, and no route
  type for WebSocket handlers.

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

- Handlers run on the reactor thread, like HTTP handlers, with the same
  no-blocking rule. Outbound writes go through existing write-queue mechanics.
- `WsConn` exposes `sendText`, `sendBinary`, `ping`, `close(code, reason)`,
  buffer identity (`conn_index`, `conn_id`), and per-connection user slot
  (`*anyopaque`) owned by the handler's framework layer.

**Handshake**

- On a matched `.ws` route with a valid upgrade request (method GET,
  `Sec-WebSocket-Version: 13`, base64 16-byte `Sec-WebSocket-Key`), swerver
  replies `101 Switching Protocols` with
  `Sec-WebSocket-Accept = base64(sha1(key ++ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))`
  and switches the connection to WS mode (`conn.ws_state != null`,
  `conn.protocol`-level parsing disabled).
- Subprotocol negotiation: the handler may return a chosen subprotocol;
  none by default.
- Non-upgrade request to a `.ws` route → 426 Upgrade Required.
- Handshake response is written through the write queue (no tunneling, no
  second connection).

**Frame codec** (`src/ws/frame.zig`, pure, unit-tested)

- Opcodes: continuation, text, binary, close, ping, pong.
- Client→server frames MUST be masked (RFC 6455 §5.1): unmasked → close 1002.
- Fragmentation: continuation assembly with a bounded message size
  (`ws_max_message_bytes`, default 1 MiB) and bounded fragment count; control
  frames may interleave and must not be fragmented; control payload ≤ 125.
- Control handling: ping → pong (unless a close is in flight); close →
  echo close and transition to draining; protocol errors → close with the
  right code (1002 protocol error, 1007 invalid payload for text UTF-8
  failures, 1009 too big).
- Buffers: frames are parsed out of the connection read buffer; assembled
  messages use a bounded per-connection heap buffer only when fragmented
  (no per-frame allocation).

**Write path**

- `sendText`/`sendBinary` build a frame (server→client unmasked) into a pool
  buffer and enqueue; partial writes use the existing write-queue/pending
  machinery. Backpressure uses the existing `write_paused` flag: the WS layer
  reports "paused" to the handler (which may drop/coalesce) rather than
  buffering without bound.
- Close: a close frame is queued, then the socket closes after the write
  drains (existing `close_after_write`), with a `ws_close_timeout_ms` cap.

**Connection state** (`runtime/connection.zig`)

```
ws_state: ?*WsState,       // heap-allocated lazily on upgrade
// WsState: handler ptr, user slot ptr, fragmented-message buffer,
//          fragment count, close_sent/close_received, message size counters
```

The struct is heap-allocated on upgrade and freed on close (keeps
`Connection` size unchanged for the non-WS path).

**Timeouts and lifecycle**

- Idle timeout: existing connection timeout applies, refreshed on any frame.
- Ping keepalive: optional per-route interval; a missed pong within
  `pong_timeout_ms` closes the connection.
- On worker shutdown/drain: send close 1001 (going away), then close.
- HTTP/2/HTTP/3: not supported in v1 (RFC 8441 CONNECT later); a `.ws` route
  on those protocols responds 501.

## Integration points

| File | Change |
| --- | --- |
| `src/ws/frame.zig` | new: codec + tests |
| `src/ws/handshake.zig` | new: accept-key computation, header validation |
| `router/router.zig` | route kind `.ws`, `router.ws(...)`, dispatch to `on_open` on upgrade |
| `server/dispatch.zig` | upgrade detection on matched ws route (before proxy tunnel path), frame read loop in `handleRead`, WS close path |
| `runtime/connection.zig` | `ws_state`, close bookkeeping |
| `server/http1.zig` | 101 response emission (status line, no content-length) |
| `lib.zig` | export the ws API surface |

## Tests

- Codec: masked/unmasked, all opcodes, fragmentation incl. interleaved control
  frames, oversize rejection (1009), unmasked rejection (1002), invalid UTF-8
  text (1007), close echo, ping/pong, 125-byte control limit, partial frames
  split across reads.
- Handshake: known-answer accept-hash test (RFC 6455 example key →
  `s3pPLMBiTxaQ9kYGzzhZRbK+xOo=`), bad version → 426, missing key → 400.
- Integration: a test server with a ws echo route driven by a raw TCP client
  (masked frames) asserting echo, ping/pong, close handshake, and the
  connection returning cleanly; a fragmented 2 MiB message is rejected with
  1009 without growing memory unboundedly.
