// Child targets of a page: out-of-process (cross-site) iframes and
// dedicated Workers, at any depth. One DevTools session per page
// auto-attaches to them while they are paused before their first script,
// lets every registered handler set them up, then lets them run. Scripts
// use it through ctx.childTargets(page, handler) (core/browse.js).
//
// A handler gets a Target: { type, url, parent, send(method, params),
// on(event, fn) }. send() talks to that iframe or Worker only; on()
// receives its DevTools events (after the matching domain is enabled).
//
// Chrome lets a paused target run as soon as ANY attached session says
// so, and Playwright says so right after its own setup. installResumeGate()
// holds Playwright's go-ahead until the handlers here are done (at most
// HOLD_MS), so their setup always happens before the target's first line.

const path = require("path");

const HANDLER_MS = 5000; // per handler, so a slow one can't freeze the target
const CALL_MS = 10000;   // per DevTools call
const HOLD_MS = 3000;    // longest a new target waits for the handlers

const timeout = (p, ms, what) => {
  let t;
  return Promise.race([p, new Promise((_, rej) => { t = setTimeout(() => rej(new Error(`${what} timed out`)), ms); })]).finally(() => clearTimeout(t));
};

class Target {
  constructor(parent, sessionId, info) {
    this.type = info.type;
    this.url = info.url;
    this.targetId = info.targetId;
    this.parent = parent.type ? parent : null;
    this._sid = sessionId;
    this._up = parent._raw;
    this._seq = 0;
    this._pending = new Map();
    this._listeners = new Map();
    this.children = new Map();
    this.closed = false;
    this._raw = (method, params) => this.send(method, params);
  }

  send(method, params = {}) {
    if (this.closed) return Promise.reject(new Error("target closed"));
    const id = ++this._seq;
    const p = new Promise((resolve, reject) => this._pending.set(id, { resolve, reject }));
    this._up("Target.sendMessageToTarget", { sessionId: this._sid, message: JSON.stringify({ id, method, params }) })
      .catch((e) => this._settle({ id, error: { message: e.message } }));
    return timeout(p, CALL_MS, method).finally(() => this._pending.delete(id));
  }

  on(event, fn) {
    if (!this._listeners.has(event)) this._listeners.set(event, []);
    this._listeners.get(event).push(fn);
    return this;
  }

  _settle(m) {
    const p = this._pending.get(m.id);
    if (!p) return;
    if (m.error) p.reject(new Error(m.error.message)); else p.resolve(m.result);
  }

  _close() {
    this.closed = true;
    for (const p of this._pending.values()) p.reject(new Error("target closed"));
    for (const c of this.children.values()) c._close();
  }
}

/**
 * Start watching a page's child targets.
 * @param {import("playwright").CDPSession} cdp  a session for the page
 * @param {(t: Target) => any} onError  called with (handlerError, target)
 * @returns {{ add(handler): void }}
 */
async function watchChildren(cdp, onError = () => {}) {
  const handlers = [];
  const root = { children: new Map(), _raw: (m, p) => cdp.send(m, p) };

  async function attached(parent, ev) {
    const t = new Target(parent, ev.sessionId, ev.targetInfo);
    parent.children.set(ev.sessionId, t);
    for (const h of handlers) await timeout(Promise.resolve().then(() => h(t)), HANDLER_MS, "child target handler").catch((e) => onError(e, t));
    // Their own iframes and Workers, before they start.
    if (t.type === "iframe" || t.type === "worker") await t.send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: false }).catch(() => {});
    release(t.targetId);
    await t.send("Runtime.runIfWaitingForDebugger").catch(() => {});
  }
  function detached(parent, sessionId) {
    const t = parent.children.get(sessionId);
    if (t) { t._close(); parent.children.delete(sessionId); }
  }
  // Messages from a child arrive wrapped once per level.
  function receive(t, raw) {
    let m;
    try { m = JSON.parse(raw); } catch (e) { return; }
    if (m.id !== undefined) return t._settle(m);
    if (m.method === "Target.attachedToTarget") attached(t, m.params);
    else if (m.method === "Target.detachedFromTarget") detached(t, m.params.sessionId);
    else if (m.method === "Target.receivedMessageFromTarget") { const c = t.children.get(m.params.sessionId); if (c) receive(c, m.params.message); }
    for (const fn of t._listeners.get(m.method) || []) { try { fn(m.params); } catch (e) { onError(e, t); } }
  }

  cdp.on("Target.attachedToTarget", (ev) => attached(root, ev));
  cdp.on("Target.detachedFromTarget", (ev) => detached(root, ev.sessionId));
  cdp.on("Target.receivedMessageFromTarget", (ev) => { const t = root.children.get(ev.sessionId); if (t) receive(t, ev.message); });
  await cdp.send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: false });
  watchers++;
  return { add: (h) => handlers.push(h) };
}

// --- resume gate ------------------------------------------------------------
let watchers = 0;
const gates = new Map(); // targetId -> { wait, open }

function gate(targetId) {
  let g = gates.get(targetId);
  if (!g) {
    let open;
    const wait = new Promise((r) => { open = r; });
    g = { wait, open };
    gates.set(targetId, g);
    setTimeout(() => { open(); gates.delete(targetId); }, HOLD_MS + 5000).unref?.();
  }
  return g;
}
function release(targetId) { if (targetId) gate(targetId).open(); }

// Wraps Playwright's DevTools pipe for every browser it launches from now
// on. Playwright internals: returns false (and changes nothing) when they
// are not where expected; test/unit.test.js checks they are.
let gateInstalled = false;
function installResumeGate() {
  if (gateInstalled) return true;
  let server;
  try { server = require(path.join(path.dirname(require.resolve("playwright-core/package.json")), "lib", "coreBundle.js")).server; } catch (e) { return false; }
  const P = server && server.BrowserContext && server.BrowserContext.prototype;
  if (!P || typeof P.initialize !== "function") return false;
  const initialize = P.initialize;
  P.initialize = function (...args) {
    try { hookConnection(this._browser && this._browser._connection); } catch (e) { /* leave Playwright as is */ }
    return initialize.apply(this, args);
  };
  gateInstalled = true;
  return true;
}

function hookConnection(conn) {
  const t = conn && conn._transport;
  if (!t || t.sbxGate || typeof t.send !== "function" || typeof t.onmessage !== "function") return;
  t.sbxGate = true;
  const childOf = new Map(); // Playwright's session id -> target id
  const receive = t.onmessage;
  t.onmessage = (m) => {
    const p = m && m.params;
    if (m.method === "Target.attachedToTarget" && p && (p.targetInfo.type === "worker" || p.targetInfo.type === "iframe")) childOf.set(p.sessionId, p.targetInfo.targetId);
    else if (m.method === "Target.detachedFromTarget" && p) childOf.delete(p.sessionId);
    return receive(m);
  };
  const send = t.send.bind(t);
  t.send = (m) => {
    const targetId = m.method === "Runtime.runIfWaitingForDebugger" && watchers > 0 && childOf.get(m.sessionId);
    if (!targetId) return send(m);
    Promise.race([gate(targetId).wait, new Promise((r) => setTimeout(r, HOLD_MS))]).then(() => send(m));
  };
}

module.exports = { watchChildren, installResumeGate };
