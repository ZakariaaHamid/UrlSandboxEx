// The script API. A script may export, besides the plain hooks:
//
//   when: { url, title, text, dom, request }   run only on matching pages
//   async setup(api)    each page and popup, before navigation: register
//                       observers (api.net.on, api.code.on)
//   async run(api)      once, on the main page, after load, if `when` matched
//
// Everything here is invisible to the page: reads run in an isolated
// world, observation happens in DevTools or in Node, nothing is injected.
// core/scripts.js turns these exports into ordinary hooks. docs/api.md is
// the reference.

const { withIsolatedWorld } = require("./isolated_eval.js");

const LEVELS = new Set(["bad", "warn", "info"]);
const BODY_MS = 10000;
const DRAIN_MS = 10000;

const timeout = (p, ms, value = null) => {
  let t;
  return Promise.race([p, new Promise((r) => { t = setTimeout(() => r(value), ms); })]).finally(() => clearTimeout(t));
};

// String: case-insensitive substring; RegExp: as is.
function test(pattern, value) {
  if (pattern === undefined || pattern === null) return true;
  const v = String(value ?? "");
  return pattern instanceof RegExp ? (pattern.lastIndex = 0, pattern.test(v)) : v.toLowerCase().includes(String(pattern).toLowerCase());
}

// "POST", "document|script" or a RegExp: the whole value must match.
const exact = (p) => (p === undefined || p === null || p instanceof RegExp ? p : new RegExp(`^(?:${p})$`, "i"));

// --- per-page state shared by all scripts ------------------------------------
function pageState(ctx, page) {
  const all = (ctx.state.api = ctx.state.api || { pages: new Map(), findings: [], tags: new Set() });
  if (!all.pages.has(page)) {
    const st = { requests: [], code: null, codeListeners: [], pending: new Set() };
    page.on("request", (r) => { if (st.requests.length < 5000) st.requests.push(r.url()); });
    all.pages.set(page, st);
  }
  return { all, st: all.pages.get(page) };
}

// One debugger per target (page, cross-site iframes, Workers) for every
// script's code.on(): generated code (eval, new Function, string timers)
// and blob:/data: scripts. Breakpoints stay off, so `debugger;` traps
// measure nothing.
const PLAYWRIGHT_CODE = /utilityScript\.evaluate|injected\.previewNode|class InjectedScript|__playwright/;
async function startCode(ctx, page, st) {
  if (st.code) return st.code;
  st.code = (async () => {
    if (ctx.engine !== "chromium") return false;
    const seen = new Set();
    const watch = async (target, kind, targetUrl) => {
      const quiet = () => {
        target.send("Debugger.setSkipAllPauses", { skip: true }).catch(() => {});
        target.send("Debugger.setBreakpointsActive", { active: false }).catch(() => {});
      };
      target.on("Debugger.paused", () => { target.send("Debugger.resume").catch(() => {}); quiet(); });
      target.on("Debugger.scriptParsed", (ev) => {
        if (ev.url && !/^(blob|data):/.test(ev.url)) return; // files are in the network capture
        if (ev.executionContextAuxData && ev.executionContextAuxData.isDefault === false) return; // isolated worlds
        const p = target.send("Debugger.getScriptSource", { scriptId: ev.scriptId }).then(({ scriptSource: source }) => {
          if (!source || PLAYWRIGHT_CODE.test(source.slice(0, 400000))) return;
          const sha256 = ctx.sha256(source);
          if (seen.has(sha256)) return;
          seen.add(sha256);
          const frame = ev.stackTrace?.callFrames?.[0];
          const item = { source, sha256, target: kind, targetUrl: typeof targetUrl === "function" ? targetUrl() : targetUrl, url: ev.url || null, from: frame ? `${frame.url}:${frame.lineNumber}` : null };
          for (const fn of st.codeListeners) {
            const r = Promise.resolve().then(() => fn(item)).catch((e) => { ctx.log.apiErrors = [...(ctx.log.apiErrors || []), `code.on: ${e.message}`].slice(-20); });
            st.pending.add(r); r.finally(() => st.pending.delete(r));
          }
        }).catch(() => {});
        st.pending.add(p); p.finally(() => st.pending.delete(p));
      });
      await target.send("Debugger.enable");
      quiet();
    };
    const cdp = await ctx.context.newCDPSession(page);
    await watch({ send: (m, p) => cdp.send(m, p), on: (e, f) => cdp.on(e, f) }, "page", () => page.url());
    await ctx.childTargets(page, (t) => (t.type === "iframe" || t.type === "worker" ? watch(t, t.type, t.url) : null));
    return true;
  })();
  return st.code;
}

// --- `when` ---------------------------------------------------------------------
async function matches(api, cond) {
  if (!cond) return true;
  if (typeof cond === "function") return !!(await cond(api));
  if (Array.isArray(cond)) { for (const c of cond) if (await matches(api, c)) return true; return false; }
  if (!test(cond.url, api.page.url())) return false;
  if (cond.title !== undefined && !test(cond.title, await api.page.title())) return false;
  if (cond.request !== undefined && !api._requests().some((u) => test(cond.request, u))) return false;
  if (cond.dom !== undefined && !(await api.page.read((sel) => !!document.querySelector(sel), cond.dom).catch(() => false))) return false;
  if (cond.text !== undefined && !test(cond.text, await api.page.text())) return false;
  return true;
}

// --- the api object ---------------------------------------------------------------
// g: { gate: "open" | "pending" | "closed", held: [] }, one per script:
// emit calls wait in `held` until `when` matches on the main page.
function makeApi(ctx, script, g = { gate: "open", held: [] }) {
  const page = ctx.page;
  const { all, st } = pageState(ctx, page);
  const out = (fn) => { if (g.gate === "open") fn(); else if (g.gate === "pending") g.held.push(fn); };
  const logOf = () => (ctx.log[script.name] = ctx.log[script.name] || {});
  const fail = (where, e) => { ctx.log.apiErrors = [...(ctx.log.apiErrors || []), `${script.name} ${where}: ${e.message}`].slice(-20); };
  const track = (p) => { st.pending.add(p); p.finally(() => st.pending.delete(p)); return p; };

  const read = (fn, arg) => withIsolatedWorld(page, ctx.context, () => page.evaluate(fn, arg));

  const api = {
    name: script.name,
    settings: ctx.settings,
    persona: ctx.persona,
    identity: ctx.identity,
    isPopup: !!ctx.isPopup,
    playwright: { page, context: ctx.context },
    human: () => ctx.require("humanize.js"),

    page: {
      url: () => page.url(),
      title: () => page.title().catch(() => ""),
      read,
      text: () => read(() => (document.body ? document.body.innerText : "").slice(0, 200000)).catch(() => ""),
      html: () => page.content().catch(() => ""),
      query: (selector) => read((sel) => Array.from(document.querySelectorAll(sel)).slice(0, 200).map((el) => ({
        tag: el.tagName.toLowerCase(), text: (el.innerText || el.value || "").slice(0, 500),
        attrs: Object.fromEntries(Array.from(el.attributes).map((a) => [a.name, a.value.slice(0, 500)])),
      })), selector).catch(() => []),
      async waitFor(cond, { timeout: ms = 15000 } = {}) {
        for (const end = Date.now() + ms; Date.now() < end; await new Promise((r) => setTimeout(r, 250))) if (await matches(api, cond)) return true;
        return false;
      },
    },

    net: {
      // kind: "request" | "response"; filter: { url, method, type, status }
      on(kind, filter, fn) {
        if (typeof filter === "function") { fn = filter; filter = {}; }
        if (kind !== "request" && kind !== "response") throw new Error(`net.on: unknown kind "${kind}"`);
        page.on(kind, (x) => {
          const req = kind === "request" ? x : x.request();
          if (!test(filter.url, req.url()) || !test(exact(filter.method), req.method()) || !test(exact(filter.type), req.resourceType())) return;
          if (kind === "response" && filter.status !== undefined && ![].concat(filter.status).includes(x.status())) return;
          const ev = { url: req.url(), method: req.method(), type: req.resourceType(), headers: req.headers(), postData: req.postData() };
          if (kind === "response") Object.assign(ev, {
            status: x.status(), responseHeaders: x.headers(),
            body: () => timeout(x.body().catch(() => null), BODY_MS),
            text: async () => { const b = await timeout(x.body().catch(() => null), BODY_MS); return b ? b.toString("utf8") : null; },
          });
          track(Promise.resolve().then(() => fn(ev)).catch((e) => fail(`net.on(${kind})`, e)));
        });
      },
    },

    code: {
      // fn({ source, sha256, target, targetUrl, url, from }) for each new
      // piece of generated code, in the page and its iframes and Workers.
      on(fn) {
        st.codeListeners.push((item) => fn(item));
        api._ready.push(startCode(ctx, page, st));
      },
    },

    emit: {
      finding(level, text) {
        if (!LEVELS.has(level)) throw new Error(`emit.finding: level must be bad, warn or info, not "${level}"`);
        out(() => { if (all.findings.length < 200) all.findings.push({ level, text: String(text).slice(0, 300), script: script.name }); });
      },
      tag(tag) {
        const t = String(tag).toLowerCase().replace(/[^a-z0-9:._-]+/g, "-").slice(0, 40);
        if (t) out(() => all.tags.add(t));
      },
      ioc: (type, value, context = "") => out(() => ctx.ioc(type, value, context || script.name)),
      dump: (name, data, opts) => out(() => ctx.dump(name, data, opts)),
      log: (key, value) => out(() => { logOf()[key] = value; }),
    },

    _ready: [],
    _requests: () => st.requests,
    async _decide() {
      if (g.gate !== "pending") return g.gate === "open";
      if (!(await matches(api, script.when).catch((e) => (fail("when", e), false)))) return false;
      g.gate = "open";
      for (const fn of g.held.splice(0)) fn();
      logOf().matched = true;
      return true;
    },
    _close() { if (g.gate === "pending") { g.gate = "closed"; g.held.length = 0; logOf().matched = false; } },
    _drain: () => timeout(Promise.allSettled([...st.pending]), DRAIN_MS),
  };
  return api;
}

// Hooks for core/scripts.js: setup -> page, run -> interact (and before
// capture if `when` only matched late), findings and tags into the result.
function apiHooks(mod) {
  const apis = new WeakMap(); // page -> api
  const ran = { done: false };
  const g = { gate: mod.when ? "pending" : "open", held: [] };
  const apiFor = (ctx) => { if (!apis.has(ctx.page)) apis.set(ctx.page, makeApi(ctx, mod, g)); return apis.get(ctx.page); };
  const tryRun = async (ctx) => {
    if (ran.done || ctx.isPopup || typeof mod.run !== "function") return;
    const api = apiFor(ctx);
    if (!(await api._decide())) return;
    ran.done = true;
    try { await mod.run(api); } catch (e) { ctx.log.apiErrors = [...(ctx.log.apiErrors || []), `${mod.name} run: ${e.message}`].slice(-20); }
  };
  return {
    async page(ctx) {
      const api = apiFor(ctx);
      if (typeof mod.setup === "function") await mod.setup(api);
      await Promise.all(api._ready.splice(0));
    },
    interact: typeof mod.run === "function" ? tryRun : undefined,
    on: {
      async beforeCapture(ctx) {
        await tryRun(ctx);
        const api = apiFor(ctx);
        await api._drain();
        if (!(await api._decide())) api._close();
      },
      afterCapture(ctx, result) {
        const all = ctx.state.api;
        if (!all) return;
        result.scriptFindings = all.findings;
        result.scriptTags = [...all.tags];
      },
    },
  };
}

module.exports = { apiHooks, makeApi, test };
