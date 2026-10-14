// Script loader. Everything beyond "open the URL and capture" is a script:
// a CommonJS module exporting any of
//   name                         label (default: file name)
//   settings: { section: {} }    defaults, merged section by section
//   personas: { name: {} }       browser personas, merged by name
//   services(ctx)                start processes in the jail; return them
//   launch(ctx, opts)            adjust Playwright launch options
//   context(ctx, opts)           adjust browser-context options
//   ready(ctx)                   once, after launch
//   page(ctx)                    each page/popup, before navigation
//   navigate(ctx)                replace the plain goto(url); return
//                                { response, via } or null (first wins)
//   interact(ctx)                after load
//   on: { event(ctx, payload) }  Node-side event handlers (see browse.js)
//   after(host)                  ON THE HOST, after the visit (network
//                                access, no jail; the input is hostile
//                                page data): exporters, lookups, alerts
//   ui: { "section.key": { options: [..], suggestions: [..], help } }
//                                optional hints for the web UI's settings form
// The first comment paragraph of the file is its description in the web UI.
// Hooks run in script order; launch/context options pass through each
// script in turn, so later scripts override earlier ones.
//
// ctx: settings, persona, engine, locale, timezoneId, proxy, env, state
// (shared across hooks), log (saved in result.json), identity, page,
// context, version, isPopup, navError, dump(name, data, {append}),
// ioc(type, value, context), sha256(buf), require(lib) (lib modules),
// childTargets(page, handler) (cross-site iframes and Workers, see
// lib/targets.js), onSession(fn) (runs on every new DevTools session).

const fs = require("fs");
const path = require("path");

const BUILTIN_DIR = path.resolve(__dirname, "..", "scripts");
const LIB_DIR = path.resolve(__dirname, "..", "lib");
const EXAMPLES_DIR = path.resolve(__dirname, "..", "examples");
const HOOKS = ["services", "launch", "context", "ready", "page", "navigate", "interact", "setup", "run", "after"];

// Bare names are built-in scripts; anything else is a path.
function resolveScript(ref, baseDir = process.cwd()) {
  if (!/^[a-z0-9-]+$/i.test(ref)) return path.resolve(baseDir, ref);
  const p = path.join(BUILTIN_DIR, `${ref}.js`);
  if (!fs.existsSync(p)) throw new Error(`no built-in script "${ref}" (have: ${fs.readdirSync(BUILTIN_DIR).map((f) => f.replace(/\.js$/, "")).join(", ")})`);
  return p;
}

// require(), but re-read when the file changed (long-running web server).
const mtimes = new Map();
function requireFresh(file) {
  const m = fs.statSync(file).mtimeMs;
  if (mtimes.has(file) && mtimes.get(file) !== m) delete require.cache[require.resolve(file)];
  mtimes.set(file, m);
  return require(file);
}

// Scripts written against the script API (lib/api.js): setup, run, when.
const usesApi = (m) => typeof m.setup === "function" || typeof m.run === "function" || m.when !== undefined;
function withApi(m) {
  const { apiHooks } = require("../lib/api.js");
  const h = apiHooks(m);
  const chain = (a, b) => (a && b ? async (...x) => { await a(...x); await b(...x); } : a || b);
  const on = { ...(m.on || {}) };
  for (const [ev, fn] of Object.entries(h.on)) on[ev] = chain(on[ev], fn);
  const own = { hooks: HOOKS.filter((k) => typeof m[k] === "function").concat(m.when !== undefined ? ["when"] : []), on: Object.keys(m.on || {}) };
  return { ...m, page: chain(m.page, h.page), interact: chain(m.interact, h.interact), on, own };
}

function loadScripts(refs, baseDir) {
  return refs.map((ref) => {
    const file = resolveScript(ref, baseDir);
    const mod = requireFresh(file);
    if (!mod || typeof mod !== "object") throw new Error(`${file}: a script must export an object`);
    const m = { ...mod, name: mod.name || path.basename(file, ".js"), file };
    return usesApi(m) ? withApi(m) : m;
  });
}

function mergeSections(mods, key) {
  const out = {};
  for (const m of mods) for (const [k, v] of Object.entries(m[key] || {})) {
    out[k] = v && typeof v === "object" && !Array.isArray(v) ? { ...(out[k] || {}), ...v } : v;
  }
  return out;
}

function compose(mods) {
  const settings = mergeSections(mods, "settings");
  const events = {};
  for (const m of mods) for (const [ev, fn] of Object.entries(m.on || {})) (events[ev] = events[ev] || []).push({ fn, script: m.name });

  const each = async (hook, ctx) => { for (const m of mods) if (typeof m[hook] === "function") await m[hook](ctx); };
  const reduce = async (hook, ctx, opts) => {
    for (const m of mods) if (typeof m[hook] === "function") opts = (await m[hook](ctx, opts)) || opts;
    return opts;
  };

  return {
    name: mods.map((m) => m.name).join("+") || "core",
    settings,
    personas: { default: { engine: "chromium" }, ...mergeSections(mods, "personas") },
    events,
    scan: { settleMs: 5000, navTimeoutMs: 30000, ...(settings.scan || {}) },
    display: { width: 1920, height: 1080, depth: 24, ...(settings.display || {}) },
    hasInteract: mods.some((m) => typeof m.interact === "function"),
    async services(ctx) {
      const procs = [];
      for (const m of mods) if (typeof m.services === "function") procs.push(...((await m.services(ctx)) || []));
      return procs.filter(Boolean);
    },
    // Security defaults, not stealth: the apt-updated Google Chrome build
    // and Chrome's own sandbox (Playwright disables it by default).
    launch: (ctx) => reduce("launch", ctx, {
      headless: false, env: { ...ctx.env }, args: [],
      ...(ctx.engine === "chromium" ? { chromiumSandbox: true, ...(fs.existsSync("/opt/google/chrome/chrome") ? { channel: "chrome" } : {}) } : {}),
    }),
    contextOptions: (ctx) => reduce("context", ctx, { ignoreHTTPSErrors: true }),
    ready: (ctx) => each("ready", ctx),
    page: (ctx) => each("page", ctx),
    async navigate(ctx) {
      for (const m of mods) {
        if (typeof m.navigate !== "function") continue;
        const r = await m.navigate(ctx);
        if (r) return r;
      }
      return null;
    },
    async after(host) {
      for (const m of mods) {
        if (typeof m.after !== "function") continue;
        try { await m.after(host); } catch (e) { host.errors.push(`${m.name}.after: ${e.message}`); }
      }
    },
    // Scripts share scan.interactBudgetMs; past it the rest are skipped, so
    // capture always happens well before the visit's hard limit.
    async interact(ctx) {
      ctx.log = ctx.log || {};
      const end = Date.now() + ((settings.scan && settings.scan.interactBudgetMs) || 150000);
      for (const m of mods) {
        if (typeof m.interact !== "function") continue;
        if (Date.now() > end) { (ctx.log.skipped = ctx.log.skipped || []).push(m.name); continue; }
        const t = Date.now();
        try { await m.interact(ctx); } catch (e) { ctx.log[`${m.name}.error`] = e.message; }
        (ctx.log.interactMs = ctx.log.interactMs || {})[m.name] = Date.now() - t;
      }
      return ctx.log;
    },
  };
}

const sandboxRequire = (p) => require(path.resolve(LIB_DIR, p));

// Every installed script (built-ins, the examples, then cfg.scriptDirs),
// described for the web UI. Keys are bare names; a name already taken gets
// its folder prefixed.
function scriptLibrary(cfg) {
  const dirs = [...new Set([BUILTIN_DIR, EXAMPLES_DIR, ...(cfg.scriptDirs || []).map((d) => path.resolve(cfg._dir || process.cwd(), d.replace(/^~(?=\/|$)/, require("os").homedir())))])];
  const out = [];
  for (const dir of dirs) {
    let files = [];
    try { files = fs.readdirSync(dir).filter((f) => f.endsWith(".js")).sort(); } catch (e) { continue; }
    for (const f of files) {
      const file = path.join(dir, f);
      let mod;
      try { [mod] = loadScripts([file]); } catch (e) { out.push({ key: f, file, error: e.message }); continue; }
      let key = path.basename(f, ".js");
      if (out.some((x) => x.key === key)) key = `${path.basename(dir)}/${key}`;
      const head = fs.readFileSync(file, "utf8").match(/^(?:#!.*\n)?((?:\/\/.*\n)+)/);
      const description = head ? head[1].split("\n").map((l) => l.replace(/^\/\/ ?/, "")).join(" ").split(/(?<=\.)\s+(?=[A-Z])/)[0].replace(/^\S+(?: -|:) /, "").trim() : "";
      const hooks = (mod.own ? mod.own.hooks : HOOKS.filter((k) => typeof mod[k] === "function"))
        .concat((mod.own ? mod.own.on : Object.keys(mod.on || {})).map((e) => `on:${e}`));
      out.push({ key, file, builtin: dir === BUILTIN_DIR, example: dir === EXAMPLES_DIR, name: mod.name, description, hooks, host: typeof mod.after === "function",
        settings: mod.settings || {}, personas: Object.keys(mod.personas || {}), ui: mod.ui || {} });
    }
  }
  return out;
}

module.exports = { loadScripts, compose, sandboxRequire, scriptLibrary };
