#!/usr/bin/env node
// UrlSandboxEx web UI: submit URLs, watch the queue, review scans.
//
//   node web/server.js        (config: `web` in sbx.config.jsonc)
//
// No login: it listens on loopback (reach it over an SSH tunnel). Requests
// whose Host header isn't a known name are refused (DNS rebinding) and
// cross-origin POSTs are refused (CSRF), so other sites open in the
// analyst's browser can't drive it.
// Everything shown comes from hostile pages, so: every value is escaped,
// URLs are shown defanged and never as links, artifacts are served as
// downloads (screenshots as images), and a strict CSP applies.

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const { PNG } = require("pngjs");
const { loadConfig } = require("../core/config");
const { scriptLibrary } = require("../core/scripts");
const { normalizeRequest, applyRequest, loadProfiles, saveProfile, deleteProfile, PATH_RE } = require("../core/profiles");
const { sbxScan } = require("../urlsandboxex");
const report = require("../core/report");
const { parseUrls, MAX_BATCH } = require("../core/urls");
const fingerprint = require("../core/fingerprint");

const cfg = loadConfig(process.argv.slice(2).filter((a) => a.includes("=")).map((a) => a.replace(/^--set=?/, "")));

const countryNames = (() => { try { return new Intl.DisplayNames(["en"], { type: "region" }); } catch (e) { return { of: (c) => c }; } })();
const countryName = (cc) => { try { return countryNames.of(cc.toUpperCase()); } catch (e) { return cc.toUpperCase(); } };
const AUDIT = path.join(cfg.outDir, "audit.jsonl");
fs.mkdirSync(cfg.outDir, { recursive: true });
const HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", cfg.web.host, ...(cfg.web.allowedHosts || [])].map((h) => String(h).toLowerCase()));


// ------------------------------------------------------------ rendering --
class Raw { constructor(s) { this.s = s; } }
const raw = (s) => new Raw(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
function html(strings, ...vals) {
  let out = strings[0];
  vals.forEach((v, i) => {
    const s = v instanceof Raw ? v.s : Array.isArray(v) ? v.map((x) => (x instanceof Raw ? x.s : esc(x))).join("") : esc(v);
    out += s + strings[i + 1];
  });
  return raw(out);
}
const defang = (u) => String(u ?? "").replace(/^http/i, "hxxp").replace(/\./g, "[.]");
const hostOf = (u) => { try { return new URL(u).hostname; } catch (e) { return ""; } };
const site = (h) => String(h).split(".").slice(-2).join("."); // rough registrable domain
const ago = (t) => { const s = Math.round((Date.now() - new Date(t)) / 1000); return s < 60 ? `${s}s ago` : s < 3600 ? `${Math.round(s / 60)}m ago` : s < 86400 ? `${Math.round(s / 3600)}h ago` : new Date(t).toISOString().slice(0, 16).replace("T", " "); };
const bytes = (n) => (n == null || n < 0 ? "-" : n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} kB` : `${(n / 1048576).toFixed(1)} MB`);
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;

function page(title, body, { active = "", q = "" } = {}) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin"><title>${esc(title)} · UrlSandboxEx</title><link rel="icon" href="/static/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="/static/app.css"><script src="/static/app.js"></script></head>
<body><header class="top"><a class="brand" href="/" title="Scans"><span class="logo" aria-hidden="true"></span>UrlSandboxEx</a>
${active === "scans" ? "" : `<form class="search" action="/" method="get" role="search"><input type="search" name="q" value="${esc(q)}" placeholder="Search scans, domains, IPs, hashes…" aria-label="Search scans" id="global-search"></form>`}
<div class="top-right"><a class="queue-pill" id="queue-pill" href="/#queue" hidden><span class="dot"></span><span id="queue-pill-text"></span></a>
<button type="button" class="icon-btn" id="theme" title="Theme: follows the system" aria-label="Theme"><svg class="ic ic-auto" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M12 3.5v17a8.5 8.5 0 0 0 0-17z" class="fill"/></svg><svg class="ic ic-light" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="4.5"/><path d="M12 2v2.5M12 19.5V22M2 12h2.5M19.5 12H22M4.9 4.9l1.8 1.8M17.3 17.3l1.8 1.8M4.9 19.1l1.8-1.8M17.3 6.7l1.8-1.8"/></svg><svg class="ic ic-dark" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5z"/></svg></button>
<a class="button primary small" href="/#new" data-focus="#urls">New scan</a></div></header>
<main>${body.s}</main>
<div class="toasts" id="toasts" aria-live="polite"></div>
<div class="overlay lightbox" id="lightbox" hidden><button type="button" class="icon-btn" data-close aria-label="Close">✕</button><div class="lb-body"><img alt=""></div><p class="lb-caption"></p></div>
</body></html>`;
}

// --------------------------------------------------------------- scans --
const ID_RE = /^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$/;
function readScan(id) {
  const dir = path.join(cfg.outDir, id);
  if (!ID_RE.test(id) || !fs.existsSync(path.join(dir, "result.json"))) return null;
  const result = JSON.parse(fs.readFileSync(path.join(dir, "result.json"), "utf8"));
  let iocs = [];
  try { iocs = JSON.parse(fs.readFileSync(path.join(dir, "iocs.json"), "utf8")); } catch (e) { /* none */ }
  return { id, dir, result, iocs };
}
const isSink = (i) => i.context.some((c) => c.startsWith("credential submission"));
const errorOf = (r) => (r.fatalError ? "failed" : r.navError ? "nav error" : r.timedOut ? "timed out" : null);

// Analyst triage, per scan: <scan>/triage.json { verdict, tags, notes, updatedAt }.
const VERDICTS = ["malicious", "suspicious", "benign"];
function readTriage(id) {
  try { return JSON.parse(fs.readFileSync(path.join(cfg.outDir, id, "triage.json"), "utf8")); } catch (e) { return {}; }
}
function writeTriage(id, t) {
  const cur = readTriage(id);
  const next = {
    verdict: t.verdict === undefined ? cur.verdict || null : VERDICTS.includes(t.verdict) ? t.verdict : null,
    tags: t.tags === undefined ? cur.tags || [] : [...new Set(String(t.tags).split(",").map((x) => x.trim().toLowerCase().replace(/[^\w .:-]/g, "").slice(0, 30)).filter(Boolean))].slice(0, 12),
    notes: t.notes === undefined ? cur.notes || "" : String(t.notes).slice(0, 5000),
    updatedAt: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(cfg.outDir, id, "triage.json"), JSON.stringify(next, null, 2));
  return next;
}

// One row per scan for lists and search; cached until result.json or triage.json changes.
const listCache = new Map();
const mtime = (p) => { try { return fs.statSync(p).mtimeMs; } catch (e) { return 0; } };
function scanSummary(id) {
  const dir = path.join(cfg.outDir, id);
  const m = mtime(path.join(dir, "result.json"));
  if (!m) return null;
  const key = `${m}:${mtime(path.join(dir, "triage.json"))}`;
  const c = listCache.get(id);
  if (c && c.key === key) return c.row;
  let s;
  try { s = readScan(id); } catch (e) { return null; }
  if (!s) return null;
  const r = s.result, t = readTriage(id);
  const top = report.findings(s).filter((f) => f.level !== "info" || /^Redirected/.test(f.text));
  const row = {
    id, url: r.url, finalUrl: r.finalUrl, title: r.title, status: r.httpStatus, error: errorOf(r),
    iocs: s.iocs.length, sinks: s.iocs.filter(isSink).length, downloads: (r.downloads || []).length,
    persona: r.persona, at: new Date(m), thumb: !!r.screenshot, verdict: t.verdict || null, tags: [...new Set([...(t.tags || []), ...(r.scriptTags || [])])],
    findings: top.slice(0, 3).map((f) => ({ level: f.level, text: f.text })),
    text: [r.url, r.finalUrl, r.title, r.persona, id, t.verdict, ...(t.tags || []), ...(r.scriptTags || []), t.notes, ...s.iocs.map((i) => i.value)].join("\n").toLowerCase(),
  };
  listCache.set(id, { key, row });
  return row;
}
const allIds = () => fs.readdirSync(cfg.outDir).filter((d) => ID_RE.test(d)).sort().reverse();
// Search: every term must appear in the URL, title, verdict, tags, notes or any indicator. Defanged input works.
function listScans({ q = "", show = "", offset = 0, limit = 100 } = {}) {
  const terms = String(q).toLowerCase().replace(/hxxp/g, "http").replace(/\[\.\]|\(\.\)/g, ".").split(/\s+/).filter(Boolean);
  const want = (r) => {
    if (terms.some((t) => !r.text.includes(t))) return false;
    if (show === "sink") return r.sinks > 0;
    if (show === "error") return !!r.error;
    if (show === "untriaged") return !r.verdict;
    if (VERDICTS.includes(show)) return r.verdict === show;
    return true;
  };
  const rows = allIds().map(scanSummary).filter((r) => r && want(r));
  return { total: rows.length, rows: rows.slice(offset, offset + limit) };
}

// HAR -> request rows (cached per scan; HARs can be large).
const harCache = new Map();
function networkOf(s) {
  const p = path.join(s.dir, s.result.har || "assets/traffic.har");
  let st; try { st = fs.statSync(p); } catch (e) { return []; }
  const c = harCache.get(p);
  if (c && c.mtime === st.mtimeMs) return c.rows;
  let entries = [];
  try { entries = JSON.parse(fs.readFileSync(p, "utf8")).log.entries; } catch (e) { /* unreadable */ }
  const t0 = entries.length ? new Date(entries[0].startedDateTime).getTime() : 0;
  const hdrs = (h) => (h || []).map((x) => `${x.name}: ${x.value}`).join("\n");
  const rows = entries.slice(0, 2000).map((e, i) => ({
    i: i + 1, method: e.request.method, url: e.request.url, host: hostOf(e.request.url),
    status: e.response.status || 0, type: e._resourceType || "other", mime: (e.response.content?.mimeType || "").split(";")[0],
    size: e.response._transferSize ?? e.response.content?.size, ms: Math.round(e.time || 0),
    at: Math.round(new Date(e.startedDateTime).getTime() - t0),
    reqHeaders: hdrs(e.request.headers), resHeaders: hdrs(e.response.headers),
    post: e.request.postData?.text ? e.request.postData.text.slice(0, 8000) : null,
    redirect: e.response.redirectURL || null,
  }));
  harCache.set(p, { mtime: st.mtimeMs, rows });
  if (harCache.size > 20) harCache.delete(harCache.keys().next().value);
  return rows;
}

// Small screenshot for the list (box-filtered, cached as thumb.png).
function thumbnail(dir, file) {
  const out = path.join(dir, "thumb.png");
  if (fs.existsSync(out)) return out;
  const src = PNG.sync.read(fs.readFileSync(path.join(dir, file)));
  const W = 240, f = src.width / W, H = Math.min(150, Math.floor(src.height / f));
  const dst = new PNG({ width: W, height: H });
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const acc = [0, 0, 0, 0]; let n = 0;
    for (let sy = Math.floor(y * f); sy < Math.min(src.height, Math.floor((y + 1) * f)); sy++) {
      for (let sx = Math.floor(x * f); sx < Math.min(src.width, Math.floor((x + 1) * f)); sx++) {
        const k = (sy * src.width + sx) * 4;
        acc[0] += src.data[k]; acc[1] += src.data[k + 1]; acc[2] += src.data[k + 2]; acc[3] += src.data[k + 3]; n++;
      }
    }
    const k = (y * W + x) * 4;
    for (let c = 0; c < 4; c++) dst.data[k + c] = n ? acc[c] / n : 255;
  }
  fs.writeFileSync(out, PNG.sync.write(dst));
  return out;
}

// --------------------------------------------------------------- queue --
const jobs = []; // { id, url, request, batchId?, state, scanId, error, queuedAt, startedAt, finishedAt }
let running = 0;
// Single scans go ahead of batch items, so a big batch never blocks a quick lookup.
function pump() {
  while (running < cfg.web.maxConcurrent) {
    const job = jobs.find((j) => j.state === "queued" && !j.batchId) || jobs.find((j) => j.state === "queued");
    if (!job) return;
    running++; job.state = "running"; job.startedAt = new Date().toISOString(); batchUpdate(job);
    Promise.resolve().then(() => { const a = applyRequest(cfg, job.request); return sbxScan(job.url, a.cfg, a.opts); })
      .then(({ dir }) => { job.state = "done"; job.scanId = path.basename(dir); })
      .catch((e) => { job.state = "failed"; job.error = e.message; })
      .finally(() => { running--; job.finishedAt = new Date().toISOString(); audit({ event: "scan-finished", url: job.url, scanId: job.scanId || null, state: job.state, batch: job.batchId }); batchUpdate(job); pump(); });
  }
}
function audit(o) { fs.appendFileSync(AUDIT, JSON.stringify({ t: new Date().toISOString(), ...o }) + "\n"); }
const jobJson = (j) => ({ id: j.id, batchId: j.batchId || null, url: j.url, persona: j.request.persona || "desktop", state: j.state, scanId: j.scanId || null, error: j.error || null, queuedAt: j.queuedAt, startedAt: j.startedAt || null, finishedAt: j.finishedAt || null });

// ------------------------------------------------------------- batches --
// Saved to <outDir>/batches/<id>.json, so a restart resumes them.
const BATCH_DIR = path.join(cfg.outDir, "batches");
fs.mkdirSync(BATCH_DIR, { recursive: true });
const batches = new Map();
const saveBatch = (b) => { delete b._mtime; fs.writeFileSync(path.join(BATCH_DIR, `${b.id}.json`), JSON.stringify(b)); };
// Batches run by `urlsandboxex` on the command line write the same files; pick up new
// ones and refresh those the CLI is still updating.
function syncBatches() {
  let files = [];
  try { files = fs.readdirSync(BATCH_DIR).filter((f) => f.endsWith(".json")); } catch (e) { return; }
  for (const f of files) {
    const id = f.slice(0, -5), known = batches.get(id);
    if (known && known.source !== "cli") continue;
    try {
      const m = fs.statSync(path.join(BATCH_DIR, f)).mtimeMs;
      if (known && known._mtime === m) continue;
      const b = JSON.parse(fs.readFileSync(path.join(BATCH_DIR, f), "utf8"));
      b._mtime = m;
      batches.set(id, b);
    } catch (e) { /* being written */ }
  }
  const sorted = [...batches.values()].sort((x, y) => (x.createdAt < y.createdAt ? -1 : 1));
  batches.clear();
  for (const b of sorted) batches.set(b.id, b);
}
function batchUpdate(job) {
  const b = job.batchId && batches.get(job.batchId);
  if (!b) return;
  Object.assign(b.items[job.index], { state: job.state, scanId: job.scanId || null, error: job.error || null, jobId: job.id });
  saveBatch(b);
}
function enqueue(url, request, extra = {}) {
  const job = { id: crypto.randomBytes(6).toString("hex"), url, request, state: "queued", queuedAt: new Date().toISOString(), ...extra };
  jobs.push(job);
  return job;
}
const batchStats = (b) => {
  const c = { total: b.items.length, queued: 0, running: 0, done: 0, failed: 0, cancelled: 0, sinks: 0 };
  for (const it of b.items) {
    c[it.state] = (c[it.state] || 0) + 1;
    if (it.scanId) { const r = scanSummary(it.scanId); if (r?.sinks) c.sinks++; }
  }
  c.finished = c.done + c.failed + c.cancelled;
  c.active = c.queued + c.running > 0;
  return c;
};
for (const f of fs.readdirSync(BATCH_DIR).filter((x) => x.endsWith(".json")).sort()) {
  try {
    const b = JSON.parse(fs.readFileSync(path.join(BATCH_DIR, f), "utf8"));
    batches.set(b.id, b);
    if (b.source === "cli") continue; // the CLI process runs its own
    b.items.forEach((it, index) => { if (it.state === "queued" || it.state === "running") { it.state = "queued"; it.jobId = enqueue(it.url, b.request, { batchId: b.id, index }).id; } });
    saveBatch(b);
  } catch (e) { console.error(`batch ${f}: ${e.message}`); }
}

// ------------------------------------------------- customization model --
// The scan form is generated from the installed scripts: which run (in
// order) and every setting they declare, prefilled with the effective
// default (script default overlaid by sbx.config.jsonc `settings`).
const getPath = (o, p) => p.split(".").reduce((a, k) => (a && typeof a === "object" ? a[k] : undefined), o);
const isPlain = (v) => v && typeof v === "object" && !Array.isArray(v);
function model() {
  const lib = scriptLibrary(cfg);
  const defaultKeys = (cfg.scripts || []).map((ref) => {
    const f = /^[a-z0-9-]+$/i.test(ref) ? null : path.resolve(cfg._dir || process.cwd(), ref);
    return lib.find((x) => (f ? x.file === f : x.key === ref && x.builtin))?.key;
  }).filter(Boolean);
  const fields = new Map(); // "section.key" -> { def, script, ui }
  // Effective default: config settings, else the fingerprint profile, else the script's.
  let fp = {};
  try { fp = fingerprint.load(cfg).profile?.settings || {}; } catch (e) { /* shown as script defaults */ }
  for (const sc of lib) {
    const walk = (obj, pre) => {
      for (const [k, v] of Object.entries(obj)) {
        const p = pre ? `${pre}.${k}` : k;
        if (isPlain(v)) walk(v, p);
        else if (p.includes(".") && !fields.has(p)) { const c = getPath(cfg.settings, p) ?? getPath(fp, p); fields.set(p, { def: c !== undefined ? c : v, script: sc.key, ui: sc.ui?.[p] || {} }); }
      }
    };
    walk(sc.settings || {}, "");
  }
  const personas = [...new Set(lib.flatMap((x) => x.personas || []))];
  return { lib, defaultKeys, fields, personas: personas.length ? personas : ["default"] };
}
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function coerce(raw, def, p) {
  raw = String(raw ?? "").trim();
  if (typeof def === "number") { if (raw === "") return def; const n = Number(raw); if (!Number.isFinite(n)) throw new Error(`${p} must be a number`); return n; }
  if (typeof def === "boolean") return raw === "true";
  if (Array.isArray(def)) {
    const parts = raw.split(",").map((x) => x.trim()).filter(Boolean);
    return def.length && def.every((x) => typeof x === "number") ? parts.map((x) => { const n = Number(x); if (!Number.isFinite(n)) throw new Error(`${p}: numbers only`); return n; }) : parts;
  }
  return raw === "" && def === null ? null : raw;
}
// A rejected form, shown again as typed (not validated; display only).
function looseFromForm(b) {
  const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
  const overrides = {};
  for (const [k, v] of Object.entries(b)) if (k.startsWith("set.")) overrides[k.slice(4)] = Array.isArray(v) ? v[v.length - 1] : v;
  return { persona: b.persona, country: b.country, profile: b.profile, scripts: b.scriptsShown ? list(b.script) : null, overrides, extraText: String(b.extra || "") };
}
// Scan form / profile form -> request (validated).
function requestFromForm(b, m = model()) {
  const list = (v) => (v === undefined ? [] : Array.isArray(v) ? v : [v]);
  const overrides = {};
  for (const [k, v] of Object.entries(b)) {
    if (!k.startsWith("set.")) continue;
    const p = k.slice(4), f = m.fields.get(p);
    if (!f) continue;
    const val = coerce(Array.isArray(v) ? v[v.length - 1] : v, f.def, p);
    if (!same(val, f.def)) overrides[p] = val;
  }
  for (const line of String(b.extra || "").split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))) {
    const i = line.indexOf("=");
    const p = line.slice(0, i).trim();
    if (i < 1 || !PATH_RE.test(p)) throw new Error(`More settings: "${line}" is not section.key=value`);
    let v = line.slice(i + 1).trim();
    try { v = JSON.parse(v); } catch (e) { /* plain string */ }
    overrides[p] = v;
  }
  const scripts = b.scriptsShown ? list(b.script) : null;
  const req = normalizeRequest({ persona: b.persona, country: b.country, scripts: scripts && !same(scripts, m.defaultKeys) ? scripts : null, overrides, profile: b.profile }, m.lib);
  const pool = new Set((req.scripts || m.defaultKeys).flatMap((k) => m.lib.find((x) => x.key === k)?.personas || []));
  if (req.persona && pool.size && !pool.has(req.persona)) throw new Error(`persona "${req.persona}" isn't defined by the selected scripts (have: ${[...pool].join(", ")})`);
  return req;
}

// --------------------------------------------------------------- app ----
const app = express();
app.disable("x-powered-by");
app.use((req, res, next) => {
  const host = String(req.headers.host || "").toLowerCase().replace(/:\d+$/, "");
  if (!HOSTS.has(host)) return res.status(421).type("text/plain").send("unknown host (add it to web.allowedHosts)");
  if (req.method === "POST") {
    let origin = null;
    try { origin = new URL(req.headers.origin || req.headers.referer).host; } catch (e) { /* missing/"null" */ }
    if (origin !== req.headers.host) return res.status(403).type("text/plain").send("cross-origin request refused");
  }
  res.set({
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin", "X-Frame-Options": "DENY", "Cache-Control": "no-store",
  });
  next();
});
app.use("/static", express.static(path.join(__dirname, "public"), { maxAge: 0 }));
app.use(express.urlencoded({ extended: false, limit: "2mb" }));
app.get("/favicon.ico", (req, res) => res.sendStatus(204));

// ------------------------------------------------------------- forms ----
const shown = (v) => (Array.isArray(v) ? v.join(", ") : v === null || v === undefined ? "" : String(v));
function settingField(p, f, cur) {
  const name = `set.${p}`, val = cur !== undefined ? cur : f.def, label = p.split(".").slice(1).join(".");
  const attrs = raw(`data-default="${esc(shown(f.def))}"`);
  const changed = shown(val) !== shown(f.def) ? "changed" : "";
  const help = f.ui.help ? html`<small>${f.ui.help}</small>` : "";
  if (f.ui.options || typeof f.def === "boolean") {
    const opts = f.ui.options || ["true", "false"];
    return html`<label class="${changed}" title="${p}">${label}<select name="${name}" ${attrs}>${opts.map((o) => html`<option ${String(o) === shown(val) ? raw("selected") : ""}>${o}</option>`)}</select>${help}</label>`;
  }
  const list = f.ui.suggestions ? `dl-${p.replace(/\W/g, "-")}` : null;
  return html`<label class="${changed}" title="${p}">${label}<input name="${name}" value="${shown(val)}" ${attrs} ${typeof f.def === "number" ? raw('type="number" step="any"') : raw('type="text" spellcheck="false" autocomplete="off"')} ${list ? raw(`list="${list}"`) : ""} placeholder="${f.def === null ? "empty" : ""}">${list ? html`<datalist id="${list}">${f.ui.suggestions.map((o) => html`<option value="${o}">`)}</datalist>` : ""}${help}</label>`;
}

// The customization panel, prefilled from a request (profile, earlier scan or form).
function optionsPanel(request = {}, { source = "" } = {}) {
  const m = model();
  const rq = request || {};
  const active = rq.scripts || [...m.defaultKeys, ...(rq.extraScripts || [])];
  const order = [...active, ...m.defaultKeys.filter((k) => !active.includes(k)), ...m.lib.map((x) => x.key).filter((k) => !active.includes(k) && !m.defaultKeys.includes(k))];
  const profiles = Object.keys(loadProfiles(cfg));
  const over = rq.overrides || {};
  const extras = rq.extraText ?? Object.entries(over).filter(([p]) => !m.fields.has(p)).map(([p, v]) => `${p}=${typeof v === "string" ? v : JSON.stringify(v)}`).join("\n");
  const persona = rq.persona || (m.personas.includes("desktop") ? "desktop" : m.personas[0]);
  return html`<div id="options-body" data-source="${source}">
  <div class="profile-bar">
    <label>Profile<select id="profile" name="profile"><option value="">None</option>${profiles.map((n) => html`<option value="${n}" ${n === rq.profile ? raw("selected") : ""}>${n}</option>`)}</select></label>
    <div class="actions"><input id="profile-name" placeholder="Profile name" maxlength="40" value="${rq.profile || ""}" aria-label="Profile name"><button type="button" id="profile-save">Save profile</button>${rq.profile ? html`<button type="button" id="profile-delete" class="danger">Delete</button>` : ""}<button type="button" id="options-reset" title="Back to the configured defaults">Reset</button></div>
  </div>
  <div class="grid-form">
    <label>Persona<select name="persona">${m.personas.map((p) => html`<option ${p === persona ? raw("selected") : ""}>${p}</option>`)}</select><small>browser and device to present</small></label>
  </div>
  <h3>Scripts <span class="muted normal">run top to bottom; untick to skip, open to change settings</span></h3>
  <input type="hidden" name="scriptsShown" value="1">
  <div class="scripts">${order.map((k) => {
    const sc = m.lib.find((x) => x.key === k);
    if (!sc) return "";
    if (sc.error) return html`<div class="script broken"><b>${sc.key}</b> <span class="error">failed to load: ${sc.error}</span></div>`;
    const fieldsHere = [...m.fields].filter(([, f]) => f.script === k);
    const on = active.includes(k);
    return html`<details class="script" ${fieldsHere.some(([p]) => over[p] !== undefined) ? raw("open") : ""}>
      <summary><input type="checkbox" name="script" value="${k}" ${on ? raw("checked") : ""} data-default="${m.defaultKeys.includes(k) ? "1" : "0"}" aria-label="Run ${k}">
        <span class="script-name">${k}${sc.builtin ? "" : html`<span class="badge">${sc.example ? "example" : "custom"}</span>`}${sc.host ? html`<span class="badge warn" title="Has an after() hook that runs on the host, outside the jail">host hook</span>` : ""}</span>
        <span class="script-desc">${sc.description}</span>
        <span class="hooks">${sc.hooks.map((h) => html`<span class="badge type">${h}</span>`)}${fieldsHere.length ? html`<span class="badge">${plural(fieldsHere.length, "setting")}</span>` : ""}</span></summary>
      ${fieldsHere.length ? html`<div class="grid-form script-settings">${fieldsHere.map(([p, f]) => settingField(p, f, over[p]))}</div>` : html`<p class="muted small script-settings">No settings.</p>`}
    </details>`;
  })}</div>
  <label class="more">More settings <small>one <code>section.key=value</code> per line, for anything not listed above (e.g. <code>scan.navTimeoutMs=45000</code>, <code>window.width=1440</code>)</small>
    <textarea name="extra" rows="2" spellcheck="false" placeholder="scan.navTimeoutMs=45000">${extras}</textarea></label>
</div>`;
}
const summaryOf = (rq) => {
  if (!rq) return "defaults";
  const n = Object.keys(rq.overrides || {}).length;
  const parts = [rq.profile && `profile ${rq.profile}`, rq.persona && rq.persona !== "desktop" && rq.persona, rq.country && rq.country.toUpperCase(), rq.scripts && "custom scripts", n && plural(n, "setting")].filter(Boolean);
  return parts.join(" · ") || "defaults";
};

// -------------------------------------------------------------- home ----
const verdictBadge = (v) => (v ? html`<span class="verdict v-${v}">${v}</span>` : html`<span class="verdict v-none">untriaged</span>`);
const findingBadges = (r) => html`${(r.findings || []).map((f) => html`<span class="badge ${f.level === "info" ? "" : f.level}" title="${f.text}">${f.text.length > 46 ? `${f.text.slice(0, 44)}…` : f.text}</span>`)}`;
const scanRow = (r) => html`<tr class="clickable scan-row" data-href="/scans/${r.id}" data-id="${r.id}" data-url="${r.url}" data-verdict="${r.verdict || ""}">
  <td class="sel"><input type="checkbox" class="pick" aria-label="Select scan"></td>
  <td class="thumb">${r.thumb ? html`<img src="/scans/${r.id}/thumb.png" alt="" loading="lazy" width="96" height="60" data-lightbox="/scans/${r.id}/file/screenshot.png" data-caption="${defang(r.finalUrl || r.url)}">` : html`<span class="noshot"></span>`}</td>
  <td class="target"><div class="mono url" title="${defang(r.url)}">${defang(r.url)}</div>${hostOf(r.finalUrl) && hostOf(r.finalUrl) !== hostOf(r.url) ? html`<div class="final">→ <span class="mono">${defang(hostOf(r.finalUrl))}</span></div>` : ""}<div class="title">${r.title || html`<span class="muted">no title</span>`}<span class="muted"> · ${r.persona}</span></div>
    ${r.tags.length ? html`<div class="tags">${r.tags.map((t) => html`<span class="tag">${t}</span>`)}</div>` : ""}</td>
  <td>${verdictBadge(r.verdict)}</td>
  <td>${r.error ? html`<span class="badge bad">${r.error}</span>` : html`<span class="badge ${r.status >= 400 ? "warn" : "ok"}">${r.status ?? "-"}</span>`}</td>
  <td class="findings">${findingBadges(r)}</td>
  <td class="num">${r.iocs}</td><td class="when" title="${new Date(r.at).toISOString()}" data-at="${new Date(r.at).toISOString()}">${ago(r.at)}</td>
  <td class="row-actions hover-actions"><button type="button" class="copy" data-copy="${r.url}" title="Copy URL">Copy</button><a class="button small" href="/?from=${r.id}#new" title="Edit &amp; rescan">Rescan</a></td></tr>`;

const scansTable = (rows) => html`<tbody id="scan-rows">${rows.map(scanRow)}</tbody>`;
const SHOWS = [["", "All"], ["untriaged", "Untriaged"], ["malicious", "Malicious"], ["suspicious", "Suspicious"], ["benign", "Benign"], ["sink", "Credentials sent"], ["error", "Errors"]];

function home(req, res, { error = null, text = "", request = null, source = "", batchName = "" } = {}) {
  const q = String(req.query?.q || ""), show = SHOWS.some(([k]) => k === req.query?.show) ? req.query.show : "";
  const list = listScans({ q, show });
  const all = allIds().map(scanSummary).filter(Boolean);
  const today = new Date().toISOString().slice(0, 10);
  const stat = { total: all.length, today: all.filter((r) => new Date(r.at).toISOString().startsWith(today)).length, sinks: all.filter((r) => r.sinks).length, untriaged: all.filter((r) => !r.verdict).length, malicious: all.filter((r) => r.verdict === "malicious").length };
  syncBatches();
  const recentBatches = [...batches.values()].slice(-8).reverse();
  res.status(error ? 400 : 200).send(page("Scans", html`
  <section class="card hero" id="new">
    <form method="post" action="/scans" class="submit" id="scan-form">
      <div class="submit-main">
        <textarea id="urls" name="urls" rows="1" required spellcheck="false" autocomplete="off" placeholder="Paste URLs to scan, one or many; defanged (hxxp, [.]) and bare domains are fine">${text}</textarea>
        <button class="primary big" type="submit">Scan</button>
      </div>
      <div class="bulk-bar"><label class="button small file-pick">Load .txt / .csv<input type="file" id="url-file" accept=".txt,.csv,.tsv,.log,text/plain,text/csv" hidden></label>
        <span class="muted small" id="url-count"></span>
        <input name="batchName" id="batch-name" placeholder="Batch name (optional)" maxlength="80" value="${batchName || req.body?.batchName || ""}" ${batchName ? "" : raw("hidden")}></div>
      ${error ? html`<p class="error">${error}</p>` : ""}
      <details class="options" ${request || error ? raw("open") : ""}><summary>Customize <span class="muted" id="options-summary">(${source || summaryOf(request)})</span></summary>
        <p class="hint">Got a decoy, block page or blank? Try the android persona, the <b>arrival</b> script (arrive from webmail) or <b>clock</b> (business hours). Save a setup as a profile to reuse it; <code>urlsandboxex --profile=NAME</code> uses the same profiles.</p>
        ${optionsPanel(request, { source })}</details>
      ${cfg.egress.residentialProxy ? "" : html`<p class="hint warn-text">Egress is this server's datacenter IP, so kits that check IP reputation may show a decoy. Configure egress.residentialProxy.</p>`}
    </form>
  </section>
  ${stat.total ? html`<section class="stats">
    <a class="stat" href="/"><b>${stat.total}</b><span>scans</span></a>
    <a class="stat" href="/"><b>${stat.today}</b><span>today</span></a>
    <a class="stat ${stat.untriaged ? "attn" : ""}" href="/?show=untriaged#scans"><b>${stat.untriaged}</b><span>untriaged</span></a>
    <a class="stat ${stat.sinks ? "bad" : ""}" href="/?show=sink#scans"><b>${stat.sinks}</b><span>credentials sent</span></a>
    <a class="stat ${stat.malicious ? "bad" : ""}" href="/?show=malicious#scans"><b>${stat.malicious}</b><span>malicious</span></a></section>` : ""}
  <section class="card" id="queue" hidden><div class="row"><h2>Queue</h2><span class="muted" id="queue-status"></span></div>
    <table class="table"><tbody id="queue-rows"></tbody></table></section>
  <section class="card" id="scans-card"><div class="row"><h2>Scans <span class="count" id="scan-total">${list.total}</span></h2>
    <div class="actions"><input class="filter big-filter" type="search" id="scan-search" value="${q}" placeholder="Search URLs, titles, domains, IPs, hashes, tags…" aria-label="Search scans" autocomplete="off"></div></div>
    <div class="seg wrap" role="group" aria-label="Show" id="scan-show">${SHOWS.map(([k, l]) => html`<button type="button" class="${k === show ? "on" : ""}" data-filter-show="${k}">${l}</button>`)}</div>
    ${stat.total ? html`<div class="scroll"><table class="table scans" id="scans"><thead><tr><th class="sel"><input type="checkbox" id="pick-all" aria-label="Select all shown"></th><th></th><th>Target</th><th>Verdict</th><th>HTTP</th><th>Key findings</th><th class="num">IOCs</th><th>When</th><th></th></tr></thead>${scansTable(list.rows)}</table></div>
      <p class="muted empty-filter" id="scan-empty" ${list.total ? raw("hidden") : ""}>No scans match. <a href="/">Clear filters</a></p>
      <div class="more"><button type="button" id="scan-more" ${list.total > list.rows.length ? "" : raw("hidden")} data-offset="${list.rows.length}">Show more</button></div>`
    : html`<div class="empty onboarding"><p><b>No scans yet.</b></p><p class="muted">Paste a URL above (or drop a .txt / .csv of URLs) and press Scan. Each scan opens it in a jailed Chrome that behaves like a person (it gets past CAPTCHAs and delays and types test credentials) and collects screenshots, the network trace and indicators.</p></div>`}
  </section>
  ${recentBatches.length ? html`<section class="card"><div class="row"><h2>Batches</h2></div><table class="table"><tbody>${recentBatches.map((b) => { const c = batchStats(b); return html`<tr class="clickable" data-href="/batches/${b.id}">
      <td class="target"><b>${b.name}</b><div class="muted small">${ago(b.createdAt)} · ${summaryOf(b.request)}</div></td><td class="batch-progress">${progress(c)}</td>
      <td class="right">${c.active ? html`<span class="badge state running">${c.finished}/${c.total}</span>` : html`<span class="badge state done">${c.total} done</span>`}${c.failed ? html` <span class="badge state failed">${c.failed} failed</span>` : ""}${c.sinks ? html` <span class="badge bad">${c.sinks} credential sinks</span>` : ""}</td></tr>`; })}</tbody></table></section>` : ""}
  <div class="selbar" id="selbar" hidden><span id="sel-count"></span>
    <button type="button" data-bulk="verdict:malicious">Malicious</button><button type="button" data-bulk="verdict:suspicious">Suspicious</button><button type="button" data-bulk="verdict:benign">Benign</button>
    <button type="button" data-bulk="export">Export IOCs</button><button type="button" data-bulk="rescan">Rescan</button><button type="button" data-bulk="delete" class="danger">Delete</button>
    <button type="button" class="link" data-bulk="clear">Clear</button></div>
  </section>`, { active: "scans" }));
}
app.get("/", (req, res) => {
  if (req.query.from) {
    const s = readScan(String(req.query.from));
    if (s) return home(req, res, { text: s.result.url, request: s.result.sbx?.request || { persona: s.result.persona }, source: `from scan ${s.id}` });
  }
  if (req.query.batch && getBatch(req.query.batch)) {
    const b = getBatch(req.query.batch);
    return home(req, res, { text: b.items.map((i) => i.url).join("\n"), request: b.request, source: `from batch ${b.name}`, batchName: `${b.name} (rescan)` });
  }
  if (req.query.profile) {
    const p = loadProfiles(cfg)[req.query.profile];
    if (p) return home(req, res, { request: { ...p, profile: String(req.query.profile) } });
  }
  home(req, res);
});
app.get("/partials/options", (req, res) => {
  const p = req.query.profile ? loadProfiles(cfg)[req.query.profile] : null;
  res.send(optionsPanel(p ? { ...p, profile: String(req.query.profile) } : null).s);
});
const fail = (res, e) => res.status(400).json({ error: e.message });
app.post("/profiles", (req, res) => {
  try { saveProfile(cfg, String(req.body.profileName || "").trim(), requestFromForm(req.body)); audit({ event: "profile-saved", name: req.body.profileName }); res.json({ ok: true }); } catch (e) { fail(res, e); }
});
app.post("/profiles/delete", (req, res) => {
  try { deleteProfile(cfg, String(req.body.profileName || "")); audit({ event: "profile-deleted", name: req.body.profileName }); res.json({ ok: true }); } catch (e) { fail(res, e); }
});
app.get("/partials/scans", (req, res) => {
  const offset = Math.max(0, Number(req.query.offset) || 0);
  const list = listScans({ q: req.query.q || "", show: req.query.show || "", offset });
  res.json({ html: scansTable(list.rows).s, total: list.total, next: offset + list.rows.length < list.total ? offset + list.rows.length : null });
});
app.post("/scans/:id/triage", (req, res) => {
  if (!ID_RE.test(req.params.id) || !fs.existsSync(path.join(cfg.outDir, req.params.id))) return res.sendStatus(404);
  const t = writeTriage(req.params.id, { verdict: req.body.verdict, tags: req.body.tags, notes: req.body.notes });
  audit({ event: "triage", scanId: req.params.id, verdict: t.verdict });
  res.json(t);
});
// Bulk actions on selected scans: verdict:<v>, delete.
app.post("/scans/bulk", (req, res) => {
  const ids = String(req.body.ids || "").split(",").filter((id) => ID_RE.test(id) && fs.existsSync(path.join(cfg.outDir, id)));
  const action = String(req.body.action || "");
  if (action.startsWith("verdict:")) for (const id of ids) writeTriage(id, { verdict: action.slice(8) });
  else if (action === "delete") for (const id of ids) { fs.rmSync(path.join(cfg.outDir, id), { recursive: true, force: true }); listCache.delete(id); }
  else return res.status(400).json({ error: "unknown action" });
  audit({ event: "bulk", action, ids });
  res.json({ ok: true, n: ids.length });
});
app.get("/export/iocs.csv", (req, res) => {
  const ids = String(req.query.ids || "").split(",").filter((id) => ID_RE.test(id) && fs.existsSync(path.join(cfg.outDir, id, "result.json")));
  const entries = ids.map((id) => { const sc = report.loadScan(path.join(cfg.outDir, id)); return { url: sc.result.url, state: "done", scan: sc }; });
  res.set("Content-Disposition", `attachment; filename="urlsandboxex-iocs-${ids.length}-scans.csv"`).type("text/csv").send(report.iocsCsv(entries));
});

app.post("/scans", (req, res) => {
  const { urls, bad } = parseUrls(req.body.urls ?? req.body.url);
  // One URL plus junk is probably a typo: say so. In a list, junk is skipped (and listed on the batch).
  const problem = !urls.length ? (bad.length ? `No URLs found (not URLs: ${bad.slice(0, 3).join(", ")}${bad.length > 3 ? ` +${bad.length - 3} more` : ""})` : "Enter at least one URL.")
    : urls.length === 1 && bad.length ? `Not a valid http(s) URL: ${bad.slice(0, 3).join(", ")}${bad.length > 3 ? ` (+${bad.length - 3} more)` : ""}`
    : urls.length > MAX_BATCH ? `${urls.length} URLs found; a batch takes at most ${MAX_BATCH}. Split the list.` : null;
  if (problem) return home(req, res, { error: problem, text: req.body.urls || "", request: req.body.request ? null : looseFromForm(req.body) });
  let request;
  try {
    request = req.body.request ? normalizeRequest(JSON.parse(req.body.request), scriptLibrary(cfg)) : requestFromForm(req.body);
  } catch (e) {
    let prefill = null;
    try { prefill = req.body.request ? JSON.parse(req.body.request) : looseFromForm(req.body); } catch (x) { /* show defaults */ }
    return home(req, res, { error: e.message, text: req.body.urls || "", request: prefill });
  }
  while (jobs.length > 3000 && jobs[0].state !== "queued" && jobs[0].state !== "running") jobs.shift();
  if (urls.length === 1) {
    const job = enqueue(urls[0], request);
    audit({ event: "scan-queued", url: urls[0], request });
    pump();
    return res.redirect(303, `/jobs/${job.id}`);
  }
  const b = {
    id: crypto.randomBytes(5).toString("hex"), name: String(req.body.batchName || "").trim().slice(0, 80) || `${urls.length} URLs`,
    createdAt: new Date().toISOString(), request, skipped: bad.slice(0, 500), items: urls.map((url) => ({ url, state: "queued" })),
  };
  batches.set(b.id, b);
  b.items.forEach((it, index) => { it.jobId = enqueue(it.url, request, { batchId: b.id, index }).id; });
  saveBatch(b);
  audit({ event: "batch-created", batch: b.id, urls: urls.length, skipped: bad.length, request });
  pump();
  res.redirect(303, `/batches/${b.id}`);
});

// ---------------------------------------------------------------- jobs --
app.get("/api/queue", (req, res) => res.json({
  running, queued: jobs.filter((j) => j.state === "queued").length,
  jobs: jobs.filter((j) => !j.batchId).slice(-30).map(jobJson),
  batches: [...batches.values()].slice(-10).map((b) => { const c = batchStats(b); return { id: b.id, name: b.name, ...c }; }).filter((b) => b.active),
}));
app.get("/api/jobs/:id", (req, res) => { const j = jobs.find((x) => x.id === req.params.id); return j ? res.json(jobJson(j)) : res.sendStatus(404); });
app.get("/jobs/:id", (req, res) => {
  const j = jobs.find((x) => x.id === req.params.id);
  if (!j) return notFound(res, "This job is gone (the queue is kept in memory and resets when the server restarts).");
  if (j.scanId) return res.redirect(303, `/scans/${j.scanId}`);
  const ahead = jobs.filter((x) => x.state === "queued" && x.queuedAt < j.queuedAt).length;
  res.send(page("Scanning", html`
  <section class="card job" data-job="${j.id}">
    <div class="spinner ${j.state === "failed" ? "stopped" : ""}" aria-hidden="true"></div>
    <h1 class="mono url">${defang(j.url)}</h1>
    <p class="job-state" id="job-state">${j.state === "failed" ? html`<span class="error">Failed: ${j.error}</span>` : j.state === "queued" ? `Queued${ahead ? `, ${plural(ahead, "scan")} ahead` : ""}` : "Scanning…"}</p>
    <ol class="steps" id="job-steps"><li data-step="queued">Queued</li><li data-step="running">Browsing like a person, waiting out delays and gates</li><li data-step="done">Collecting indicators</li></ol>
    <p class="muted">Usually 15 to 40 s. <span id="job-elapsed" data-since="${j.startedAt || j.queuedAt}"></span> This page opens the report when it's ready.</p>
    <p><a href="/">Back to scans</a></p>
  </section>`));
});

// ------------------------------------------------------------ batches ---
const progress = (c) => html`<div class="progress" title="${c.finished} of ${c.total} finished"><span class="p-done" data-w="${(100 * c.done / c.total).toFixed(2)}"></span><span class="p-failed" data-w="${(100 * (c.failed + c.cancelled) / c.total).toFixed(2)}"></span><span class="p-running" data-w="${(100 * c.running / c.total).toFixed(2)}"></span></div>`;
const batchChips = (c) => html`<div class="chips">
  <span class="badge">${c.finished} / ${c.total} finished</span>
  ${c.running ? html`<span class="badge state running">${c.running} running</span>` : ""}${c.queued ? html`<span class="badge state queued">${c.queued} queued</span>` : ""}
  ${c.done ? html`<span class="badge state done">${c.done} done</span>` : ""}${c.failed ? html`<span class="badge state failed">${c.failed} failed</span>` : ""}${c.cancelled ? html`<span class="badge">${c.cancelled} cancelled</span>` : ""}
  ${c.sinks ? html`<span class="badge bad">credentials sent on ${plural(c.sinks, "site")}</span>` : ""}</div>`;
function batchRows(b) {
  return html`<tbody id="batch-rows">${b.items.map((it, i) => {
    const r = it.scanId ? scanSummary(it.scanId) : null;
    const flags = [r?.sinks ? "sink" : "", it.state === "failed" || r?.error ? "error" : "", it.state === "queued" || it.state === "running" ? "pending" : ""].join(" ");
    return html`<tr class="${r ? "clickable" : ""}" ${r ? raw(`data-href="/scans/${esc(r.id)}"`) : ""} data-flags="${flags}">
      <td class="num muted">${i + 1}</td>
      <td class="thumb">${r?.thumb ? html`<img src="/scans/${r.id}/thumb.png" alt="" loading="lazy" width="120" height="75">` : html`<span class="noshot"></span>`}</td>
      <td class="target"><div class="mono url">${defang(it.url)}</div>${r && hostOf(r.finalUrl) && hostOf(r.finalUrl) !== hostOf(it.url) ? html`<div class="final">→ <span class="mono">${defang(hostOf(r.finalUrl))}</span></div>` : ""}${r?.title ? html`<div class="title">${r.title}</div>` : ""}${it.error ? html`<div class="error small">${it.error}</div>` : ""}</td>
      <td>${r ? (r.error ? html`<span class="badge bad">${r.error}</span>` : html`<span class="badge ${r.status >= 400 ? "warn" : "ok"}">${r.status ?? "-"}</span>`) : html`<span class="badge state ${it.state}">${it.state}</span>`}</td>
      <td class="findings">${r ? html`${r.verdict ? html`${verdictBadge(r.verdict)} ` : ""}${findingBadges(r)}` : ""}</td>
      <td class="num">${r ? r.iocs : ""}</td></tr>`;
  })}</tbody>`;
}
const getBatch = (id) => { syncBatches(); return batches.get(String(id)); };

app.get("/batches/:id", (req, res) => {
  const b = getBatch(req.params.id);
  if (!b) return notFound(res, "No such batch.");
  const c = batchStats(b);
  const exp = (f) => `/batches/${b.id}/${f}`;
  res.send(page(b.name, html`
  <div class="crumbs"><a href="/">Scans</a> / batch</div>
  <section class="card head" id="batch" data-batch="${b.id}" data-active="${c.active ? "1" : ""}">
    <div class="head-main">
      <h1>${b.name}</h1>
      <p class="muted small">${b.source === "cli" ? "Started from the command line · " : ""}Created ${ago(b.createdAt)} · ${summaryOf(b.request)}${b.skipped?.length ? ` · ${plural(b.skipped.length, "non-URL token")} skipped` : ""}</p>
      <div id="batch-stats">${progress(c)}${batchChips(c)}</div>
    </div>
    <div class="actions">
      <form method="post" action="/batches/${b.id}/cancel" id="cancel-form" ${c.queued && b.source !== "cli" ? "" : raw("hidden")}><button class="danger" title="Don't start the queued scans; running ones finish">Cancel queued</button></form>
      <form method="post" action="/batches/${b.id}/retry" id="retry-form" ${c.failed + c.cancelled && !c.active ? "" : raw("hidden")}><button title="Queue the failed and cancelled URLs again">Retry failed</button></form>
      <a class="button" href="/?batch=${b.id}#new" title="Same URLs, change scripts or settings">Edit &amp; rescan all</a>
      <details class="menu"><summary class="button">Export ▾</summary><div class="menu-list">
        <a href="${exp("report.html")}">Report (HTML)</a><a href="${exp("report.md")}">Report (Markdown)</a><a href="${exp("summary.csv")}">Summary (CSV)</a><a href="${exp("iocs.csv")}">All indicators (CSV)</a><a href="${exp("iocs.json")}">All indicators (JSON)</a><a href="${exp("urls.txt")}">URL list</a></div></details>
    </div>
  </section>
  ${b.skipped?.length ? html`<details class="card"><summary class="muted">Skipped ${plural(b.skipped.length, "token")} that aren't URLs</summary><p class="mono small value">${b.skipped.join("  ")}</p></details>` : ""}
  <section class="card"><div class="row"><h2>URLs <span class="count">${c.total}</span></h2>
    <div class="actions"><div class="seg" role="group" aria-label="Show">
      <button type="button" class="on" data-show="">All</button><button type="button" data-show="sink">Credentials sent</button><button type="button" data-show="error">Failed</button><button type="button" data-show="pending">Pending</button></div>
      <input class="filter" type="search" data-filter="#batch-table" placeholder="Filter" aria-label="Filter URLs"></div></div>
    <div class="scroll"><table class="table scans" id="batch-table"><thead><tr><th class="num">#</th><th></th><th>Target</th><th>Result</th><th>Findings</th><th class="num">IOCs</th></tr></thead>${batchRows(b)}</table></div>
    <p class="muted empty-filter" hidden>No URLs match.</p>
  </section>`));
});
app.get("/api/batches/:id", (req, res) => {
  const b = getBatch(req.params.id);
  if (!b) return res.sendStatus(404);
  const c = batchStats(b);
  res.json({ ...c, cli: b.source === "cli", stats: html`${progress(c)}${batchChips(c)}`.s, rows: batchRows(b).s });
});
app.post("/batches/:id/cancel", (req, res) => {
  const b = getBatch(req.params.id);
  if (!b) return notFound(res, "No such batch.");
  for (const j of jobs) if (j.batchId === b.id && j.state === "queued") { j.state = "cancelled"; batchUpdate(j); }
  audit({ event: "batch-cancelled", batch: b.id });
  res.redirect(303, `/batches/${b.id}`);
});
app.post("/batches/:id/retry", (req, res) => {
  const b = getBatch(req.params.id);
  if (!b) return notFound(res, "No such batch.");
  b.source = "web";
  b.items.forEach((it, index) => { if (it.state === "failed" || it.state === "cancelled") { Object.assign(it, { state: "queued", error: null }); it.jobId = enqueue(it.url, b.request, { batchId: b.id, index }).id; } });
  saveBatch(b);
  audit({ event: "batch-retried", batch: b.id });
  pump();
  res.redirect(303, `/batches/${b.id}`);
});
// Exports across the whole batch (values are hostile: CSV cells are formula-guarded).
const download = (res, name, type, body) => res.set("Content-Disposition", `attachment; filename="${name}"`).type(type).send(body);
app.get("/batches/:id/:file(summary.csv|iocs.csv|iocs.json|urls.txt|report.html|report.md)", (req, res) => {
  const b = getBatch(req.params.id);
  if (!b) return res.sendStatus(404);
  const name = `urlsandboxex-batch-${b.id}-${req.params.file}`;
  if (req.params.file === "urls.txt") return download(res, name, "text/plain", b.items.map((i) => i.url).join("\n") + "\n");
  const entries = b.items.map((it) => ({ url: it.url, state: it.state, error: it.error, scan: it.scanId && ID_RE.test(it.scanId) && fs.existsSync(path.join(cfg.outDir, it.scanId, "result.json")) ? report.loadScan(path.join(cfg.outDir, it.scanId)) : null }));
  const f = req.params.file;
  if (f === "summary.csv") return download(res, name, "text/csv", report.summaryCsv(entries));
  if (f === "iocs.csv") return download(res, name, "text/csv", report.iocsCsv(entries));
  if (f === "iocs.json") return download(res, name, "application/json", report.iocsJson(entries));
  if (f === "report.md") return download(res, name, "text/markdown", report.batchMarkdown(b, entries));
  download(res, name, "text/html", report.batchHtml(b, entries));
});

// --------------------------------------------------------------- scan ---
function notFound(res, msg = "No such scan.") {
  res.status(404).send(page("Not found", html`<section class="card empty"><h1>Not found</h1><p class="muted">${msg}</p><p><a class="button" href="/">All scans</a></p></section>`));
}
const tab = (id, label, count) => html`<a href="#${id}" role="tab" data-tab="${id}">${label}${count != null ? html` <span class="count">${count}</span>` : ""}</a>`;
const kv = (pairs) => html`<dl class="facts">${pairs.filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => html`<div><dt>${k}</dt><dd>${v}</dd></div>`)}</dl>`;
const copyBtn = (v, label = "Copy") => html`<button type="button" class="copy" data-copy="${v}" title="Copy">${label}</button>`;
const IOC_ORDER = ["url", "domain", "ip", "email", "sha256", "telegramBotToken", "telegramChatId", "wallet", "qr"];

app.get("/scans/:id", (req, res) => {
  const s = readScan(req.params.id);
  if (!s) return notFound(res);
  const r = s.result, file = (p) => `/scans/${s.id}/file/${p.split("/").map(encodeURIComponent).join("/")}`;
  if (!fs.existsSync(path.join(s.dir, "report.html"))) { try { report.writeScanReports(s.dir); } catch (e) { /* older scan without data */ } }
  const sinks = s.iocs.filter(isSink);
  const types = [...new Set(s.iocs.map((i) => i.type))].sort((a, b) => ((IOC_ORDER.indexOf(a) + 1 || 99) - (IOC_ORDER.indexOf(b) + 1 || 99)));
  const iocs = [...s.iocs].sort((a, b) => types.indexOf(a.type) - types.indexOf(b.type));
  const net = networkOf(s);
  const finalSite = site(hostOf(r.finalUrl));
  let artifacts = [];
  try { artifacts = fs.readdirSync(path.join(s.dir, "artifacts")).filter((f) => f !== "script-iocs.jsonl").map((f) => ({ f, size: fs.statSync(path.join(s.dir, "artifacts", f)).size })); } catch (e) { /* none */ }
  // The file a sha256 indicator is the hash of, as a download.
  const saved = (i) => {
    if (i.type !== "sha256" || !/^[0-9a-f]{64}$/.test(i.value)) return "";
    const rel = ["downloads", "assets"].map((d) => `${d}/${i.value}`).find((f) => fs.existsSync(path.join(s.dir, f)));
    return rel ? html`<a class="button small" href="${file(rel)}" title="Save the file with this hash (as .bin)">Save</a>` : "";
  };
  const eg = r.sbx?.egress || {};
  const err = r.fatalError || r.navError || (r.timedOut ? "The visit hit its time limit; results are partial." : null);
  const rq = r.sbx?.request || { persona: r.persona };
  const domains = new Set(net.map((n) => n.host).filter(Boolean));
  const cons = r.console || [];
  const st = r.structure || {};
  const timings = Object.entries(r.timings || {});
  const totalT = timings.reduce((a, [, v]) => a + v, 0) || 1;
  const shots = [["Viewport", r.screenshot], ["Full page", r.screenshotFull]].filter(([, f]) => f);
  const found = report.findings(s);
  const tri = readTriage(s.id);
  const ids = allIds(), at = ids.indexOf(s.id);
  const newer = at > 0 ? ids[at - 1] : null, older = at >= 0 && at < ids.length - 1 ? ids[at + 1] : null;
  const hosts = new Set([hostOf(r.url), hostOf(r.finalUrl)].filter(Boolean));
  const history = ids.filter((id) => id !== s.id).map(scanSummary).filter((x) => x && (hosts.has(hostOf(x.url)) || hosts.has(hostOf(x.finalUrl)))).slice(0, 12);
  const span = Math.max(1, ...net.map((n) => n.at + n.ms));

  res.send(page(defang(r.url), html`
  <div class="crumbs"><a href="/">Scans</a> / <span class="mono">${s.id}</span>
    <span class="pager">${newer ? html`<a href="/scans/${newer}" id="nav-newer" title="Newer scan">← newer</a>` : ""}${older ? html`<a href="/scans/${older}" id="nav-older" title="Older scan">older →</a>` : ""}</span></div>
  <section class="card head sticky-head" data-scan="${s.id}">
    <div class="head-main">
      <h1 class="mono url">${defang(r.url)} ${copyBtn(r.url, "Copy URL")}</h1>
      <div class="chips">
        ${errorOf(r) ? html`<span class="badge bad">${errorOf(r)}</span>` : html`<span class="badge ${r.httpStatus >= 400 ? "warn" : "ok"}">HTTP ${r.httpStatus ?? "-"}</span>`}
        ${sinks.length ? html`<a class="badge bad" href="#indicators">credentials sent to ${plural(sinks.length, "endpoint")}</a>` : ""}
        ${(r.downloads || []).length ? html`<a class="badge warn" href="#artifacts">${plural(r.downloads.length, "download")}</a>` : ""}
        ${(r.popups || []).length ? html`<span class="badge">${plural(r.popups.length, "popup")}</span>` : ""}
        ${st.passwordFields ? html`<span class="badge">${plural(st.passwordFields, "password field")}</span>` : ""}
        ${(r.scriptTags || []).map((t) => html`<span class="tag" title="Tag set by a script">${t}</span>`)}
        <span class="badge">${r.persona}</span><span class="badge">${(eg.country || "?").toUpperCase()} · ${eg.mode || "?"}</span>
        <span class="badge" title="${new Date(fs.statSync(path.join(s.dir, "result.json")).mtime).toISOString()}">${ago(fs.statSync(path.join(s.dir, "result.json")).mtime)} · ${Math.round((r.sbx?.durationMs || 0) / 1000)}s</span>
      </div>
    </div>
    <div class="actions">
      <div class="seg verdict-set" role="group" aria-label="Verdict" data-scan="${s.id}">${VERDICTS.map((v) => html`<button type="button" class="vb-${v} ${tri.verdict === v ? "on" : ""}" data-verdict="${v}" title="Mark ${v}">${v}</button>`)}</div>
      <form method="post" action="/scans" id="rescan-form"><input type="hidden" name="urls" value="${r.url}"><input type="hidden" name="request" value="${JSON.stringify(rq)}"><button class="primary" title="Same URL, same scripts and settings">Rescan</button></form>
      <a class="button" href="/?from=${s.id}#new" id="edit-rescan" title="Change scripts or settings, then scan again">Edit &amp; rescan</a>
      <button type="button" class="copy-fetch" data-src="${file("report.md")}" title="Copy a Markdown summary for a ticket or chat">Copy summary</button>
      <details class="menu"><summary class="button">Export ▾</summary><div class="menu-list">
        <a href="${file("report.html")}">Report (HTML)</a><a href="${file("report.md")}">Report (Markdown)</a><a href="${file("iocs.csv")}">Indicators (CSV)</a><a href="${file("iocs.json")}">Indicators (JSON)</a><a href="${file("result.json")}">result.json</a>${r.har ? html`<a href="${file(r.har)}">Network (HAR)</a>` : ""}</div></details>
    </div>
  </section>
  ${err ? html`<section class="card alert"><b>${errorOf(r) === "timed out" ? "Partial result" : "Error"}</b><pre class="mono">${String(err).split("\n").slice(0, 4).join("\n")}</pre></section>` : ""}
  ${sinks.length ? html`<section class="card alert"><h2>Credentials were sent</h2><p class="muted">The test values typed into the page left the browser to:</p>
    <ul class="sinks">${sinks.map((i) => html`<li><span class="mono">${defang(i.value)}</span> ${copyBtn(i.value)} <span class="muted">${i.context.filter((c) => c.startsWith("credential submission")).join("; ")}</span></li>`)}</ul></section>` : ""}

  <nav class="tabs" role="tablist">
    ${tab("overview", "Overview")}${tab("indicators", "Indicators", s.iocs.length)}${tab("network", "Network", net.length)}${tab("page", "Page")}${tab("artifacts", "Artifacts", artifacts.length + (r.downloads || []).length + 2)}${tab("console", "Console", cons.length)}${tab("log", "Log")}
  </nav>

  <section class="panel" id="tab-overview">
    ${found.length ? html`<div class="card findings-card"><h2>Key findings</h2><ul class="findings-list">${found.map((f) => html`<li class="f-${f.level}"><a href="#${f.tab}"><span class="dot-${f.level}" aria-hidden="true"></span>${f.text}</a></li>`)}</ul></div>` : html`<div class="card findings-card"><p class="muted">Nothing stood out: no credentials sent, downloads, password fields or exfiltration channels.</p></div>`}
    <div class="overview">
      <div class="card shot-card">
        ${shots.length ? html`<div class="seg shot-switch" role="group">${shots.map(([l], i) => html`<button type="button" class="${i ? "" : "on"}" data-shot="${i}">${l}</button>`)}</div>
          ${shots.map(([l, f], i) => html`<a class="shot ${i ? "tall" : ""}" data-shot-panel="${i}" ${i ? raw("hidden") : ""} href="${file(f)}" target="_blank" rel="noopener" data-lightbox="${file(f)}" data-caption="${l}: ${defang(r.finalUrl)}"><img src="${file(f)}" alt="${l} screenshot" ${i ? raw('loading="lazy"') : ""}></a>`)}`
        : html`<div class="empty muted">No screenshot.</div>`}
      </div>
      <div class="card">
        <h2>Summary</h2>
        ${kv([
          ["Final URL", html`<span class="mono url-wrap">${defang(r.finalUrl)}</span>`],
          ["Title", r.title],
          ["Redirects", (r.redirectChain || []).length > 1 ? plural(r.redirectChain.length - 1, "hop") : "none"],
          ["Requests", html`${net.length} to ${plural(domains.size, "domain")}`],
          ["Forms", (st.forms || []).length ? html`${(st.forms || []).map((f) => html`<div class="mono small">${(f.method || "get").toUpperCase()} ${defang(f.action)}</div>`)}` : "none"],
          ["Egress", html`${eg.mode === "residential" ? "residential proxy" : "this server"}: ${eg.ip || "?"} · ${eg.org || ""}${eg.hosting ? " (datacenter)" : ""}<div class="muted small">exit ${eg.country ? countryName(eg.country) : "unknown"}${eg.requested ? html`, asked for ${countryName(eg.requested)}${eg.requested !== eg.country ? html` <span class="warn-text">(mismatch)</span>` : ""}` : ""}${eg.locale ? ` · browser ${eg.locale}, ${eg.timezone || "?"}` : ""}</div>`],
          ["Browser", `${r.engine} ${r.browserVersion || ""} · ${r.persona}`],
          ["Scripts", html`${String(r.scripts || "core").split("+").map((x) => html`<span class="badge type">${x}</span> `)}`],
          ["Customized", Object.keys(rq.overrides || {}).length || rq.profile || rq.country ? html`${rq.profile ? html`<div>profile <b>${rq.profile}</b></div>` : ""}${rq.country ? html`<div>egress ${rq.country.toUpperCase()}</div>` : ""}${Object.entries(rq.overrides || {}).map(([k, v]) => html`<div class="mono small">${k} = ${JSON.stringify(v)}</div>`)}` : "no (defaults)"],
        ])}
        ${(r.redirectChain || []).length > 1 || r.arrivedVia ? html`<h3>Redirect chain</h3><ol class="chain mono">${r.arrivedVia ? html`<li class="muted">${defang(r.arrivedVia)} (stand-in referrer page)</li>` : ""}${(r.redirectChain || []).map((u) => html`<li>${defang(u)}</li>`)}</ol>` : ""}
      </div>
    </div>
    <div class="overview lower">
      <div class="card triage" data-scan="${s.id}"><div class="row"><h2>Analyst notes</h2><span class="muted small" id="triage-state">${tri.updatedAt ? `saved ${ago(tri.updatedAt)}` : ""}</span></div>
        <label>Tags <small>comma-separated, e.g. o365, kit:tycoon, campaign-42</small><input id="triage-tags" value="${(tri.tags || []).join(", ")}" autocomplete="off" spellcheck="false"></label>
        <label>Notes<textarea id="triage-notes" rows="4" placeholder="What you saw, why the verdict, next steps…">${tri.notes || ""}</textarea></label>
        <p class="muted small">Saved automatically. Searchable from the scan list.</p></div>
      <div class="card"><h2>Other scans of this site <span class="count">${history.length}</span></h2>
        ${history.length ? html`<table class="table compact"><tbody>${history.map((h) => html`<tr class="clickable" data-href="/scans/${h.id}"><td class="when">${ago(h.at)}</td><td class="mono url">${defang(h.url)}</td><td>${h.verdict ? verdictBadge(h.verdict) : ""} ${h.error ? html`<span class="badge bad">${h.error}</span>` : html`<span class="badge">${h.status ?? "-"}</span>`}</td><td class="muted">${h.persona}</td></tr>`)}</tbody></table>`
        : html`<p class="muted">First scan of ${defang([...hosts].join(", "))}. Rescan with another persona or country to compare what the kit shows.</p>`}</div>
    </div>
    ${(r.timeline || []).length > 1 ? html`<div class="card"><h2>Page states <span class="count">${r.timeline.length}</span></h2><p class="muted small">A screenshot each time the page changed, in order.</p><div class="shots states">${r.timeline.map((t, i) => html`<figure><a href="${file(t.file)}" target="_blank" rel="noopener" data-lightbox="${file(t.file)}" data-caption="${`${i + 1}. +${(t.at / 1000).toFixed(1)} s · ${t.reason} · ${defang(t.url)}`}"><img src="${file(t.file)}" alt="State ${i + 1}" loading="lazy"></a><figcaption><b>${i + 1}.</b> +${(t.at / 1000).toFixed(1)} s · ${t.reason}<br><span class="mono">${defang(t.url)}</span></figcaption></figure>`)}</div></div>` : ""}
    ${(r.popups || []).length ? html`<div class="card"><h2>Popups</h2><div class="shots">${r.popups.map((p, i) => html`<figure>${p.screenshot ? html`<a href="${file(p.screenshot)}" target="_blank" rel="noopener"><img src="${file(p.screenshot)}" alt="Popup ${i + 1}" loading="lazy"></a>` : ""}<figcaption class="mono">${defang(p.url)}</figcaption></figure>`)}</div></div>` : ""}
  </section>

  <section class="panel card" id="tab-indicators">
    ${s.iocs.length ? html`<div class="row"><div class="chips" data-chips="#iocs">${types.map((t) => html`<button type="button" class="chip" data-type="${t}">${t} <span class="count">${s.iocs.filter((i) => i.type === t).length}</span></button>`)}</div>
      <div class="actions"><input class="filter" type="search" data-filter="#iocs" placeholder="Filter" aria-label="Filter indicators"><button type="button" class="copy-visible" data-table="#iocs">Copy visible</button></div></div>
    <div class="scroll"><table class="table" id="iocs"><thead><tr><th>Type</th><th>Value</th><th>Seen as</th><th></th></tr></thead><tbody>
    ${iocs.map((i) => html`<tr data-type="${i.type}" data-value="${i.value}" class="${isSink(i) ? "hot" : ""}"><td><span class="badge type">${i.type}</span></td><td class="mono value">${i.type === "url" || i.type === "domain" || i.type === "email" ? defang(i.value) : i.value}</td><td class="ctx">${report.contextText(i)}</td><td class="row-actions">${copyBtn(i.value)}${saved(i)}</td></tr>`)}
    </tbody></table></div><p class="muted empty-filter" hidden>No indicators match.</p>`
    : html`<p class="muted">No indicators.</p>`}
  </section>

  <section class="panel card" id="tab-network">
    ${net.length ? html`<div class="row"><div class="chips" data-chips="#net">${[...new Set(net.map((n) => n.type))].map((t) => html`<button type="button" class="chip" data-type="${t}">${t} <span class="count">${net.filter((n) => n.type === t).length}</span></button>`)}</div>
      <input class="filter" type="search" data-filter="#net" placeholder="Filter" aria-label="Filter requests"></div>
    <div class="scroll"><table class="table net" id="net"><thead><tr><th class="num">#</th><th>Method</th><th>Status</th><th>Type</th><th>Host</th><th>Path</th><th class="num">Size</th><th class="num">Time</th><th class="wf-h">Timeline</th></tr></thead><tbody>
    ${net.map((n) => html`<tr class="clickable expander ${n.host && site(n.host) !== finalSite ? "third" : ""} ${n.post ? "has-post" : ""}" data-type="${n.type}"><td class="num muted">${n.i}</td><td>${n.method}${n.post ? html` <span class="badge warn" title="Has a request body">body</span>` : ""}</td>
      <td><span class="status s${String(n.status)[0]}">${n.status || "failed"}</span></td><td class="muted">${n.type}</td><td class="mono host" title="${defang(n.host)}">${defang(n.host)}</td>
      <td class="mono path" title="${defang(n.url)}">${(() => { try { const u = new URL(n.url); return u.pathname + u.search; } catch (e) { return n.url; } })()}</td><td class="num">${bytes(n.size)}</td><td class="num">${n.ms} ms</td>
      <td class="wf"><span class="wf-bar t-${n.type}" data-x="${(100 * n.at / span).toFixed(2)}" data-w="${Math.max(0.4, 100 * n.ms / span).toFixed(2)}" title="+${(n.at / 1000).toFixed(2)} s, ${n.ms} ms"></span></td></tr>
      <tr class="detail" hidden><td colspan="9"><div class="detail-grid">
        <div><h4>URL</h4><pre>${defang(n.url)}</pre>${n.redirect ? html`<h4>Redirects to</h4><pre>${defang(n.redirect)}</pre>` : ""}${n.post ? html`<h4>Request body</h4><pre>${n.post}</pre>` : ""}<p class="muted small">+${(n.at / 1000).toFixed(2)} s · ${n.mime || "no content type"}</p></div>
        <div><h4>Request headers</h4><pre>${n.reqHeaders}</pre></div><div><h4>Response headers</h4><pre>${n.resHeaders}</pre></div></div></td></tr>`)}
    </tbody></table></div><p class="muted empty-filter" hidden>No requests match.</p>
    <p class="muted small">Highlighted rows go to a different site than the final page. Click a row for headers and bodies.${net.length >= 2000 ? " Showing the first 2000 requests; the HAR has all." : ""}</p>`
    : html`<p class="muted">No network trace.</p>`}
  </section>

  <section class="panel card" id="tab-page">
    <h2>Forms</h2>
    ${(st.forms || []).length ? html`<table class="table"><thead><tr><th>Method</th><th>Action</th></tr></thead><tbody>${st.forms.map((f) => html`<tr><td>${(f.method || "get").toUpperCase()}</td><td class="mono value">${defang(f.action)}</td></tr>`)}</tbody></table>` : html`<p class="muted">None at capture time.</p>`}
    <h2>Cookies <span class="count">${(r.cookies || []).length}</span></h2>
    ${(r.cookies || []).length ? html`<div class="scroll"><table class="table"><thead><tr><th>Domain</th><th>Name</th><th>Value</th><th>Flags</th></tr></thead><tbody>${r.cookies.map((c) => html`<tr><td class="mono">${defang(c.domain)}</td><td class="mono">${c.name}</td><td class="mono value">${String(c.value).slice(0, 200)}</td><td class="muted">${[c.httpOnly && "HttpOnly", c.secure && "Secure", c.sameSite].filter(Boolean).join(" ")}</td></tr>`)}</tbody></table></div>` : html`<p class="muted">None.</p>`}
    <h2>Storage</h2>
    ${["local", "session"].map((k) => { const e = Object.entries(st.storage?.[k] || {}); return e.length ? html`<h3>${k}Storage</h3><table class="table"><tbody>${e.map(([a, b]) => html`<tr><td class="mono">${a}</td><td class="mono value">${String(b).slice(0, 500)}</td></tr>`)}</tbody></table>` : ""; })}
    ${!Object.keys(st.storage?.local || {}).length && !Object.keys(st.storage?.session || {}).length ? html`<p class="muted">Empty.</p>` : ""}
    ${(r.websocket || []).length ? html`<h2>WebSocket frames <span class="count">${r.websocket.length}</span></h2><div class="scroll"><table class="table"><tbody>${r.websocket.slice(0, 300).map((w) => html`<tr><td class="muted">${w.dir}</td><td class="mono">${defang(hostOf(w.url))}</td><td class="mono value">${w.payload.slice(0, 600)}</td></tr>`)}</tbody></table></div>` : ""}
    <h2>Links <span class="count">${(st.links || []).length}</span></h2>
    ${(st.links || []).length ? html`<ul class="files">${[...new Set(st.links)].map((l) => html`<li>${defang(l)}</li>`)}</ul>` : html`<p class="muted">None.</p>`}
  </section>

  <section class="panel card" id="tab-artifacts">
    ${(r.downloads || []).length ? html`<div class="callout warn"><b>Downloaded files are live samples.</b> They are served as .bin; handle them in an analysis environment.</div>
      <table class="table"><thead><tr><th>File name</th><th>SHA-256</th><th class="num">Size</th><th></th></tr></thead><tbody>${r.downloads.map((d) => html`<tr><td>${d.suggestedFilename}</td><td class="mono value">${d.sha256 || "not saved"}</td><td class="num">${bytes(d.size)}</td><td class="row-actions">${d.sha256 ? html`${copyBtn(d.sha256)}<a class="button small" href="${file(`downloads/${d.sha256}`)}">Download</a>` : ""}</td></tr>`)}</tbody></table>` : ""}
    <table class="table files-table"><thead><tr><th>File</th><th></th><th class="num">Size</th></tr></thead><tbody>
    ${[["Network trace", r.har], ["Rendered DOM", r.dom], ["Egress connections", "connections.jsonl"]].filter(([, f]) => f && fs.existsSync(path.join(s.dir, f))).map(([n, f]) => html`<tr><td><a href="${file(f)}">${path.basename(f)}</a></td><td class="muted">${n}</td><td class="num">${bytes(fs.statSync(path.join(s.dir, f)).size)}</td></tr>`)}
    ${artifacts.map(({ f, size }) => html`<tr><td><a href="${file(`artifacts/${f}`)}">${f}</a></td><td class="muted">from scripts</td><td class="num">${bytes(size)}</td></tr>`)}
    </tbody></table>
  </section>

  <section class="panel card" id="tab-console">
    ${cons.length ? html`<div class="row"><div class="chips" data-chips="#console">${[...new Set(cons.map((c) => c.type))].map((t) => html`<button type="button" class="chip" data-type="${t}">${t} <span class="count">${cons.filter((c) => c.type === t).length}</span></button>`)}</div><input class="filter" type="search" data-filter="#console" placeholder="Filter" aria-label="Filter console"></div>
      <table class="table console" id="console"><tbody>${cons.map((c) => html`<tr data-type="${c.type}" class="c-${c.type}"><td class="muted">${c.type}</td><td class="mono value">${c.text}</td></tr>`)}</tbody></table><p class="muted empty-filter" hidden>No messages match.</p>`
    : html`<p class="muted">The page logged nothing.</p>`}
  </section>

  <section class="panel card" id="tab-log">
    ${timings.length ? html`<h2>Where the time went</h2><div class="timing">${timings.map(([k, v]) => html`<span class="seg-${k.replace(/\W/g, "")}" data-w="${(100 * v / totalT).toFixed(2)}" title="${k}: ${v} ms"></span>`)}</div>
      <ul class="legend">${timings.map(([k, v]) => html`<li><span class="sw seg-${k.replace(/\W/g, "")}"></span>${k} <span class="muted">${(v / 1000).toFixed(1)} s</span></li>`)}</ul>` : ""}
    <h2>Script log</h2><pre class="log">${JSON.stringify(r.log || {}, null, 2)}</pre>
  </section>`));
});

app.get("/scans/:id/thumb.png", (req, res) => {
  const s = ID_RE.test(req.params.id) && path.join(cfg.outDir, req.params.id);
  if (!s || !fs.existsSync(path.join(s, "screenshot.png"))) return res.sendStatus(404);
  try { res.set("Cache-Control", "private, max-age=86400").type("image/png").sendFile(thumbnail(s, "screenshot.png")); } catch (e) { res.sendStatus(404); }
});

// Files: images inline, everything else as a plain-text or binary download.
app.get(/^\/scans\/([^/]+)\/file\/(.+)$/, (req, res) => {
  const s = readScan(req.params[0]);
  if (!s) return res.sendStatus(404);
  const rel = decodeURIComponent(req.params[1]);
  const p = path.resolve(s.dir, rel);
  if (!p.startsWith(s.dir + path.sep) || rel.includes("\0") || !fs.existsSync(p) || !fs.statSync(p).isFile()) return res.sendStatus(404);
  if (/\.png$/i.test(p)) return res.type("image/png").sendFile(p);
  const binary = rel.startsWith("downloads/") || rel.startsWith("assets/") && !/traffic\.har$/.test(rel);
  res.set("Content-Disposition", `attachment; filename="${path.basename(p).replace(/[^\w.-]/g, "_")}${binary ? ".bin" : ""}"`);
  res.type(binary ? "application/octet-stream" : "text/plain; charset=utf-8").sendFile(p);
  if (rel.startsWith("downloads/")) audit({ event: "sample-downloaded", scanId: s.id, file: rel });
});

app.use((req, res) => notFound(res, "Nothing here."));
// Never show stack traces.
app.use((err, req, res, next) => { console.error(err); res.status(500).type("text/plain").send("internal error"); });

app.listen(cfg.web.port, cfg.web.host, () => {
  console.log(`UrlSandboxEx web UI on http://${cfg.web.host}:${cfg.web.port}`);
  pump(); // resume saved batches
  if (!/^(127\.|localhost$|::1$)/.test(cfg.web.host)) console.warn(`WARNING: web.host ${cfg.web.host} is not loopback and the UI has no login; anyone who can reach it can run scans.`);
});
