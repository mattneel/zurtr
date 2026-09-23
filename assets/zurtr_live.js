/*!
 * zurtr live browser bridge - no-build-step DOM client for the zurtr Live UI. Spec:
 * docs/modules/live.md §Render representation (data-z ids), §Patch ops, §Protocol (frames);
 * contracts.md §6 (focus/selection/form survival, resync); dev.md (paint beacon). One global: window.ZurtrLive.
 *
 * The live channel is WebTransport over HTTP/3 (docs/architecture/decisions.md D3); an explicit
 * `ws://` / `wss://` endpoint selects the WebSocket fallback, and this client never downgrades on
 * its own. The WebTransport path is written to the transport's own convention but is unexercised:
 * no zurtr endpoint serves it yet, and zurtr_live_test.html stubs WebSocket only.
 */
(function () {
  "use strict";
  const FLUSH_MS = 10, BATCH_MAX = 64, CHANGE_MS = 100, PENDING_MAX = 256; // protocol tunables
  const BACKOFF_MIN = 100, BACKOFF_MAX = 5000;
  const cfg = { token: null, rev: 0, endpoint: null };
  const pending = new Map(); // event id -> {id, ev, payload, el}: sent, not yet acked
  const timers = new Map();  // element -> data-z-change debounce timer
  let sock = null, tries = 0, retryT = 0, flushT = 0, closed = false;
  let nextId = 1, batch = [], delegated = false, beacon = false, readyDone = false, readyResolve = null;
  const ready = new Promise((resolve) => { readyResolve = resolve; });
  const warn = (...a) => console.warn("[zurtr]", ...a);
  const isOpen = () => !!sock && sock.readyState === 1;
  const near = (n, sel) => (n && n.nodeType === 1 && n.closest) ? n.closest(sel) : null;
  const FIELDS = "INPUT TEXTAREA SELECT"; // (`v == null` is deliberate)
  const isField = (el) => FIELDS.indexOf(el.tagName) >= 0;
  const attr = (el, n) => (el && el.getAttribute ? el.getAttribute(n) : null);
  const esc = (v) => (window.CSS && CSS.escape) ? CSS.escape(String(v)) : String(v);
  // Ids are resolved against the live DOM on use, so a resync needs no index rebuild.
  const one = (s, sel) => { try { return s.querySelector(sel); } catch (e) { return null; } };
  const q = (s, id) => id == null ? null : one(s, '[data-z="' + esc(id) + '"]');
  const qName = (s, n) => n ? one(s, '[name="' + esc(n) + '"]') : null;
  // Server HTML carries fresh ids; <template> parses it inertly (no script execution).
  const fragment = (html) => {
    const t = document.createElement("template");
    t.innerHTML = typeof html === "string" ? html : "";
    return t.content;
  };

  // patch ops (live.md §Patch ops), on-the-wire shapes included

  function applyOp(scope, op, touched) {
    if (!op || typeof op !== "object" || typeof op.op !== "string") return false;
    let el = null, parent = null, v = null, off = false, rest = null, node = null;
    switch (op.op) {
      case "text": // {"op":"text","id":n,"value":"…"} -> the element's single text child
        el = q(scope, op.id); if (!el) return false;
        v = op.value == null ? "" : String(op.value);
        for (let i = 0; i < el.childNodes.length; i++) if (el.childNodes[i].nodeType === 3) { node = el.childNodes[i]; break; }
        if (node) node.textContent = v; else el.insertBefore(document.createTextNode(v), el.firstChild);
        return true;
      case "attr": // {"op":"attr","id":n,"name":…,"value":…} -> set, null removes
        el = q(scope, op.id); if (!el || typeof op.name !== "string" || !op.name) return false;
        off = op.value == null;
        if (off) el.removeAttribute(op.name); else el.setAttribute(op.name, String(op.value));
        // an explicit value rewrite beats the uncommitted value (contracts.md §6)
        if (op.name === "value" && isField(el)) { touched.add(el); el.value = off ? "" : String(op.value); }
        return true;
      case "replace": // {"op":"replace","id":n,"html":…} -> identity changes
        el = q(scope, op.id); if (!el) return false;
        el.outerHTML = typeof op.html === "string" ? op.html : "";
        return true;
      case "insert": // {"op":"insert","parent":n,"index":k,"html":…} -> html at child index k
        parent = q(scope, op.parent); if (!parent) return false;
        parent.insertBefore(fragment(op.html), parent.childNodes[Math.max(0, Math.min(parent.childNodes.length, op.index | 0))] || null);
        return true;
      case "remove": // {"op":"remove","id":n}
        el = q(scope, op.id); if (!el) return false;
        el.remove();
        return true;
      case "move": // {"op":"move","id":n,"parent":m,"index":k} -> k indexes the list without the moved element
        el = q(scope, op.id); parent = q(scope, op.parent); if (!el || !parent) return false;
        rest = [];
        for (let i = 0; i < parent.childNodes.length; i++) if (parent.childNodes[i] !== el) rest.push(parent.childNodes[i]);
        parent.insertBefore(el, rest[Math.max(0, Math.min(rest.length, op.index | 0))] || null);
        return true;
      default: return false; // unknown op kinds are skipped and counted, never thrown (live.md §Patch ops)
    }
  }

  function snapFocus() {
    const el = document.activeElement;
    if (!el || el === document.body || el === document.documentElement) return null;
    const snap = { el }; // selection survives alongside focus (contracts.md §6)
    if (typeof el.selectionStart === "number") { snap.start = el.selectionStart; snap.end = el.selectionEnd; }
    return snap;
  }

  function snapValues(scope) {
    const out = [];
    // a file input's value is not restorable
    for (const el of scope.querySelectorAll("input,textarea,select")) {
      if (el.type !== "file") out.push({ el, value: el.value, multi: el.multiple ? Array.from(el.selectedOptions, (o) => o.value) : null });
    }
    return out;
  }

  function keepValues(snaps, touched) {
    for (const s of snaps) {
      // detached = replaced by the server: identity, and the uncommitted value, are gone
      if (!s.el.isConnected || touched.has(s.el)) continue;
      if (s.multi) for (const o of s.el.options) o.selected = s.multi.indexOf(o.value) >= 0;
      else if (s.el.value !== s.value) s.el.value = s.value;
    }
  }

  /** Apply a patch batch; returns {applied, skipped}. `forms` = patch form overrides. */
  function applyOps(root, ops, forms) {
    const scope = root && root.querySelector ? root : document, summary = { applied: 0, skipped: 0 };
    if (!Array.isArray(ops)) {
      if (ops != null) warn("applyOps: ops is not an array");
      return summary;
    }
    if (!ops.length) return summary;
    const snaps = snapValues(scope), focus = snapFocus();
    const scroll = { x: window.scrollX, y: window.scrollY };
    const touched = new Set(); // controls whose value the server deliberately rewrote
    for (const op of ops) {
      let ok = false;
      try { ok = applyOp(scope, op, touched); } catch (e) { warn("op failed:", op && op.op, e && e.message); }
      if (ok) summary.applied++; else summary.skipped++;
    }
    if (forms && typeof forms === "object") { // a forms entry forces that field's value (live.md §Protocol)
      for (const name of Object.keys(forms)) {
        const control = qName(scope, name), value = forms[name];
        if (!control) continue;
        touched.add(control);
        if (control.type === "checkbox") control.checked = !!value;
        else if (control.type === "radio") control.checked = control.value === String(value);
        else control.value = value == null ? "" : String(value);
      }
    }
    keepValues(snaps, touched);
    if (window.scrollX !== scroll.x || window.scrollY !== scroll.y) window.scrollTo(scroll.x, scroll.y);
    if (focus && focus.el.isConnected) { // restored by identity; never into a replaced or removed element
      if (document.activeElement !== focus.el) focus.el.focus({ preventScroll: true });
      if (focus.start !== undefined) try { focus.el.setSelectionRange(focus.start, focus.end); } catch (e) {}
    }
    return summary;
  }

  function fieldVal(el) { // one JSON value per control kind
    if (el.tagName === "SELECT" && el.multiple) return Array.from(el.selectedOptions, (o) => o.value);
    if (el.type === "checkbox") return el.checked;
    if (el.type === "radio") return el.checked ? el.value : undefined;
    return el.type === "file" ? undefined : el.value;
  }

  function collectFields(form, out) {
    for (const el of form.elements) {
      if (!el.name || el.disabled || el.tagName === "BUTTON" || el.tagName === "FIELDSET" || el.tagName === "OUTPUT") continue;
      const value = fieldVal(el);
      if (value !== undefined) out[el.name] = value; // unchecked radios are omitted
    }
  }

  // data-z-val is JSON: an object merges into the payload, anything else becomes `value`.
  function payloadOf(el) {
    const payload = {}, raw = attr(el, "data-z-val");
    if (raw !== null) {
      let p = null, ok = true;
      try { p = JSON.parse(raw); } catch (e) { ok = false; }
      if (!ok) payload.value = raw;
      else if (p && typeof p === "object" && !Array.isArray(p)) Object.assign(payload, p);
      else payload.value = p;
    }
    // "plus form fields" = the element's own form (form-associated controls)
    if (el.tagName === "FORM") collectFields(el, payload);
    else if (el.form) collectFields(el.form, payload);
    else if (el.tagName === "BUTTON" || isField(el)) payload[el.name || "value"] = fieldVal(el);
    return payload;
  }

  function fire(e, sel) {
    const el = near(e.target, "[" + sel + "]");
    if (el) sendEvent(el.getAttribute(sel), payloadOf(el), el);
    return el;
  }

  const onClick = (e) => fire(e, "data-z-ev");
  const onKeyDown = (e) => { if (e.key === "Enter" && !e.isComposing) fire(e, "data-z-key"); }; // send on Enter

  function onSubmit(e) {
    const form = near(e.target, "[data-z-form]");
    if (!form) return;
    e.preventDefault(); // the client owns the submit; the server decides what happens next
    sendEvent(form.getAttribute("data-z-form"), payloadOf(form), form);
  }

  function onChange(e) {
    const target = e.target;
    if (!target || target.nodeType !== 1) return;
    if (target.type === "file" && target.hasAttribute("data-z-upload")) upload(target); // live.md §Protocol §Uploads
    const el = near(target, "[data-z-change]");
    if (!el) return;
    const name = el.getAttribute("data-z-change"), prev = timers.get(el);
    if (prev) clearTimeout(prev);
    timers.set(el, setTimeout(() => { // data-z-change: send on change, debounced 100 ms
      timers.delete(el);
      sendEvent(name, payloadOf(el), el);
    }, CHANGE_MS));
  }

  function upload(input) {
    const name = input.getAttribute("data-z-upload"), files = input.files;
    if (!name || !files || !files.length) return;
    const body = new FormData(), field = input.name || attr(input, "data-z-val") || "file";
    let total = 0, sent = 0;
    for (const f of files) { body.append(field, f, f.name); total += f.size; }
    // XHR, not fetch: upload progress is only observable through XHR progress events.
    const xhr = new XMLHttpRequest();
    const report = (loaded, tot, done, error) => input.dispatchEvent(new CustomEvent("zurtr:upload",
      { bubbles: true, detail: { name: name, loaded: loaded, total: tot, done: done, error: error } }));
    xhr.open("POST", "/zurtr/upload?token=" + encodeURIComponent(cfg.token || ""), true);
    xhr.upload.onprogress = (e) => { sent = e.loaded; report(e.loaded, e.lengthComputable ? e.total : total, false, null); };
    xhr.onload = () => { // no assumption beyond non-2xx = error
      const ok = xhr.status >= 200 && xhr.status < 300;
      report(sent || total, total, ok, ok ? null : "HTTP " + xhr.status);
    };
    xhr.onerror = () => report(sent, total, false, "network error");
    try { xhr.send(body); } catch (e) { report(0, total, false, e && e.message); }
  }

  // --- the live channel ----------------------------------------------------
  // WebTransport is the channel (Live UI over HTTP/3, one origin with the page); a `ws://` /
  // `wss://` endpoint selects the WebSocket fallback. Frames are the same text JSON either way;
  // over WebTransport they are newline-delimited on one bidirectional stream, the convention
  // zix's own examples use (deps/zix/examples/tls/webtransport_live.html). This client never
  // downgrades by itself: a deployment that needs the fallback configures a ws:// endpoint
  // (decisions.md D3).
  const LIVE_PATH = "/zurtr/live";
  const encoder = new TextEncoder(), decoder = new TextDecoder();

  function webSocketLink(url) {
    const s = new WebSocket(url);
    const link = { kind: "websocket", url, readyState: 0, onopen: null, onmessage: null, onclose: null, onerror: null };
    link.send = (text) => s.send(text);
    link.close = () => s.close();
    s.onopen = () => { link.readyState = 1; if (link.onopen) link.onopen(); };
    s.onmessage = (m) => { if (link.onmessage) link.onmessage(m && m.data); };
    s.onclose = () => { link.readyState = 3; if (link.onclose) link.onclose(); };
    s.onerror = () => { if (link.onerror) link.onerror(); };
    return link;
  }

  function webTransportLink(url) {
    const link = { kind: "webtransport", url, readyState: 0, onopen: null, onmessage: null, onclose: null, onerror: null, send: null, close: null };
    (async () => {
      try {
        const session = new WebTransport(url);
        link.session = session;
        await session.ready;
        const stream = await session.createBidirectionalStream();
        const writer = stream.writable.getWriter();
        const reader = stream.readable.getReader();
        link.readyState = 1; // before onopen: the handshake frames go out on the same stream
        link.send = (text) => { writer.write(encoder.encode(text + "\n")).catch((e) => { if (link.onerror) link.onerror(e); }); };
        link.close = () => { try { session.close(); } catch (e) { warn("session close failed:", e && e.message); } };
        if (link.onopen) link.onopen();
        let buffer = "";
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          for (let end; (end = buffer.indexOf("\n")) >= 0;) {
            const line = buffer.slice(0, end);
            buffer = buffer.slice(end + 1);
            if (line && link.onmessage) link.onmessage(line); // one frame per line, like the server writes them
          }
        }
      } catch (e) {
        if (link.readyState === 0) { warn("webtransport open failed:", (e && e.message) || e); if (link.onerror) link.onerror(e); }
      }
      link.readyState = 3;
      if (link.onclose) link.onclose();
    })();
    return link;
  }

  function openLink(endpoint) {
    return endpoint.transport === "websocket" ? webSocketLink(endpoint.url) : webTransportLink(endpoint.url);
  }

  function send(frame) {
    if (!isOpen()) return false;
    try { sock.send(JSON.stringify(frame)); return true; } catch (e) { warn("send failed:", e && e.message); return false; }
  }

  function remember(ev, el) {
    pending.set(ev.id, { id: ev.id, ev: ev.ev, payload: ev.payload, el });
    while (pending.size > PENDING_MAX) { // bounded queue: oldest dropped with a warning
      const oldest = pending.keys().next().value;
      pending.delete(oldest);
      warn("pending queue over " + PENDING_MAX + "; dropped event " + oldest);
    }
  }

  function planFlush() { if (!flushT && batch.length) flushT = setTimeout(flush, FLUSH_MS); }

  function flush() {
    if (flushT) { clearTimeout(flushT); flushT = 0; }
    if (!batch.length) return;
    if (!isOpen()) { if (sock) planFlush(); return; } // still connecting: keep them queued
    send({ t: "events", batch: batch.splice(0, BATCH_MAX) });
    if (batch.length) planFlush();
  }

  function sendEvent(name, payload, source) {
    if (typeof name !== "string" || !name) { warn("sendEvent needs an event name"); return null; }
    const ev = { id: nextId++, ev: name, payload: payload && typeof payload === "object" ? payload : {} };
    batch.push(ev);
    remember(ev, source || null); // pending until acknowledged, resent on reconnect
    if (batch.length >= BATCH_MAX) flush(); else planFlush(); // flush on 64 events or the 10 ms timer
    return ev.id;
  }

  function drop(reason) {
    if (!pending.size) return;
    console.info("[zurtr] dropping " + pending.size + " unacked event(s): " + reason);
    pending.clear();
  }

  // {"t":"ready","rev":n,"resume":bool}
  function onReady(msg) {
    if (typeof msg.rev === "number" && Number.isFinite(msg.rev)) cfg.rev = msg.rev;
    if (msg.resume === true && pending.size && isOpen()) { // resumed: resend only the unacked events
      send({ t: "events", batch: Array.from(pending.values(), (p) => ({ id: p.id, ev: p.ev, payload: p.payload })) });
    } else if (msg.resume === false) drop("session was not resumed"); // contracts.md §6
    if (!readyDone) { readyDone = true; readyResolve(api); }
  }

  // {"t":"patch","rev":n,"ops":[…],"forms":{…},"focus":{…},"nav":{…},"acks":[…]}
  function onPatch(msg) {
    if (msg.ops !== undefined && !Array.isArray(msg.ops)) warn("patch.ops is not an array");
    applyOps(document.body || document.documentElement, Array.isArray(msg.ops) ? msg.ops : [], msg.forms);
    const at = performance.now(); // t_paint mark for the dev latency harness (dev.md §Development loop)
    if (typeof msg.rev === "number" && Number.isFinite(msg.rev)) cfg.rev = msg.rev;
    if (Array.isArray(msg.acks)) for (const id of msg.acks) pending.delete(id);
    // patch.focus (shape not frozen): server-requested focus beats the client's restore
    if (msg.focus && typeof msg.focus === "object") { const t = q(document.body, msg.focus.id); if (t && t.focus) t.focus(); }
    if (msg.nav && typeof msg.nav.url === "string") try { history.pushState(null, "", msg.nav.url); } catch (e) {}
    send({ t: "ack", rev: cfg.rev });
    if (beacon || (beacon = !!document.querySelector("[data-z-beacon]"))) {
      send({ t: "beacon", phase: "paint", at: at }); // dev-only paint beacon (dev.md §Development loop)
    }
  }

  // {"t":"resync","rev":n,"html":"…"} - resync is always correct (live.md §Protocol)
  function onResync(msg) {
    if (typeof msg.html !== "string") { warn("resync without html; ignoring"); return; }
    (document.body || document.documentElement).innerHTML = msg.html;
    if (typeof msg.rev === "number" && Number.isFinite(msg.rev)) cfg.rev = msg.rev;
    for (const [el, timer] of timers) { // re-scan: drop timers for vanished elements
      if (!el.isConnected) { clearTimeout(timer); timers.delete(el); }
    }
    delegate(); // idempotent: delegation lives on `document`, so it survives the body swap
    drop("resync"); // a fresh revision: pre-resync events are void
  }

  // {"t":"error","event":id,"kind":"…","fields":{…},"message":"…"}
  function onError(msg) {
    const entry = pending.get(msg.event);
    if (entry) pending.delete(msg.event); // rejected: never acked, never resent
    const src = entry && entry.el;
    const form = src && src.nodeType === 1 ? (src.tagName === "FORM" ? src : src.form || near(src, "form")) : null;
    const scope = form || document.body || document.documentElement;
    const fields = msg.fields && typeof msg.fields === "object" ? msg.fields : {};
    const detail = { event: msg.event, kind: msg.kind || "operation", message: msg.message || "", fields };
    scope.dispatchEvent(new CustomEvent("zurtr:error", { bubbles: true, detail }));
    const name = Object.keys(fields)[0]; // focus the first invalid field the server named
    if (name) { const f = qName(scope, name); if (f && f.focus) f.focus(); }
  }

  // {"t":"redirect","to":"…"} - cross-session navigation
  function onRedirect(msg) {
    if (typeof msg.to === "string" && msg.to) location.assign(msg.to);
    else warn("redirect without a destination; ignoring");
  }

  const handlers = { ready: onReady, patch: onPatch, resync: onResync, error: onError, redirect: onRedirect };

  function onMessage(data) {
    if (typeof data !== "string") { warn("ignoring non-text frame"); return; } // binary is a later optimization
    let msg = null;
    try { msg = JSON.parse(data); } catch (e) { warn("ignoring malformed frame:", e && e.message); return; }
    if (!msg || typeof msg !== "object" || Array.isArray(msg) || !handlers[msg.t]) {
      warn("ignoring unusable frame");
      return;
    }
    try { handlers[msg.t](msg); } catch (e) { warn("frame handler failed:", e && e.message); } // never escapes
  }

  function retryLater() {
    if (closed || retryT) return;
    const base = Math.min(BACKOFF_MAX, BACKOFF_MIN * Math.pow(2, tries++));
    const delay = Math.round(base * (0.5 + Math.random() * 0.5)); // exponential backoff with jitter
    retryT = setTimeout(() => { retryT = 0; connect(); }, delay);
  }

  function connect() {
    closed = false;
    if (sock && (sock.readyState === 0 || sock.readyState === 1)) return;
    if (!cfg.endpoint || !cfg.token) { warn("not connecting: missing " + (cfg.endpoint ? "session token" : "live endpoint")); return; }
    try { sock = openLink(cfg.endpoint); }
    catch (e) { warn("open failed:", e && e.message); sock = null; retryLater(); return; }
    const s = sock;
    // hello {token, rev, pending}, then drain the offline queue (live.md §Protocol)
    s.onopen = () => {
      tries = 0;
      send({ t: "hello", token: cfg.token, rev: cfg.rev, pending: Array.from(pending.keys()) });
      flush();
    };
    s.onmessage = (data) => onMessage(data);
    s.onclose = () => { if (sock === s) sock = null; if (!closed) retryLater(); };
    s.onerror = (e) => warn(s.kind + " error:", (e && e.message) || s.url);
  }

  function disconnect() {
    closed = true; // an explicit disconnect never schedules a reconnect
    if (retryT) { clearTimeout(retryT); retryT = 0; }
    if (flushT) { clearTimeout(flushT); flushT = 0; }
    for (const timer of timers.values()) clearTimeout(timer);
    timers.clear();
    const s = sock;
    sock = null;
    if (s) {
      s.onopen = s.onmessage = s.onerror = s.onclose = null;
      try { s.close(); } catch (e) { warn("close failed:", e && e.message); }
    }
  }

  function readConfig(options) {
    const opts = options && typeof options === "object" ? options : {};
    const meta = one(document, "[data-z-live-config]"), raw = meta && (meta.getAttribute("content") || attr(meta, "data-z-live-config"));
    let blob = null;
    if (raw) { try { blob = JSON.parse(raw); } catch (e) { warn("bad data-z-live-config JSON:", e && e.message); } }
    const sources = [meta, document.documentElement, document.body].filter(Boolean);
    const first = (...vals) => { for (const v of vals) if (v != null) return v; return null; };
    // options beat page attributes, which beat the meta-tag JSON blob
    const pick = (key, name) => first(opts[key], ...sources.map((el) => el.getAttribute(name)), blob && blob[key]);
    const token = pick("token", "data-z-token"), ws = pick("ws", "data-z-ws"), wt = pick("wt", "data-z-wt"), rev = Number(pick("rev", "data-z-rev") || 0);
    cfg.token = token == null ? null : String(token);
    // Endpoint precedence: an explicit WebTransport URL, then an explicit WebSocket URL (that
    // endpoint selects the fallback transport), then the page's own origin as the WebTransport
    // channel - https, or localhost/127.0.0.1 where the browser treats the origin as secure.
    const wsUrl = typeof ws === "string" && ws ? ws : null;
    const wtUrl = typeof wt === "string" && wt ? wt : null;
    const secure = location.protocol === "https:" || location.hostname === "localhost" || location.hostname === "127.0.0.1";
    if (wtUrl) cfg.endpoint = { transport: "webtransport", url: wtUrl };
    else if (wsUrl) cfg.endpoint = { transport: "websocket", url: wsUrl };
    else if (secure) cfg.endpoint = { transport: "webtransport", url: "https://" + location.host + LIVE_PATH };
    else cfg.endpoint = { transport: "websocket", url: "ws://" + location.host + LIVE_PATH };
    cfg.rev = Number.isFinite(rev) ? Math.max(cfg.rev, rev) : cfg.rev; // never regress a revision we already saw
  }

  function delegate() {
    if (delegated) return;
    delegated = true;
    document.addEventListener("click", onClick, true);
    document.addEventListener("submit", onSubmit, true);
    document.addEventListener("change", onChange, true);
    document.addEventListener("keydown", onKeyDown, true); // one capture-phase listener per attribute
  }

  function start(options) {
    readConfig(options);
    delegate();
    connect();
    return api;
  }

  const api = { version: "1.0.0", ready, start, connect, disconnect, applyOps, sendEvent, flush };
  window.ZurtrLive = api;
})();
