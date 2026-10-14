#!/usr/bin/env node
// urlsandboxex: open a URL in a jailed browser and extract indicators.
//
//   urlsandboxex <url ...> [--file=PATH|-] [--parallel=N] [--name=NAME]
//       [--out=PATH] [--format=text|json|md|html]
//       [--profile=NAME] [--persona=NAME] [--scripts=a,b,...] [--script=FILE ...]
//       [--country=CC] [--referer=URL] [--set key.path=value ...]
//   urlsandboxex script check FILE [--persona=NAME] [--pages=quick|all|none|a,b]
//   urlsandboxex fingerprint [show|rotate]
//
// One URL scans it and prints the result; several (arguments, --file, or
// stdin with --file=-; any text: defanged, CSV, e-mail bodies) run as a
// batch, --parallel at a time, also listed in the web UI. Every scan writes
// report.html / report.md into its directory; --out writes the report (one
// scan: .html/.md/.json by extension) or a self-contained batch folder.
//
// Core: jail, egress, browse + capture, IOC extraction. Everything else is
// a script (scripts/, or your own files): --scripts replaces the list,
// --script appends one. Scripts' `after` hooks run here, on the host. Script settings can be overridden without code via
// `settings` in sbx.config.jsonc or --set settings.<section>.<key>=value.
// --profile applies a profile saved in the web UI; other flags override it.
// Output: <outDir>/<id>/: iocs.json/.csv, result.json, screenshots,
// assets/ (bodies + traffic.har), dom.html.txt, downloads/, artifacts/,
// connections.jsonl.

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { loadConfig, deepMerge } = require("./core/config");
const { runVisit } = require("./core/jail");
const { proxyFor, resolveExit, countryMode } = require("./core/egress");
const fingerprint = require("./core/fingerprint");
const ids = require("./lib/identity");
const { extractIocs, toCsv } = require("./core/iocs");
const report = require("./core/report");
const { parseUrls, MAX_BATCH } = require("./core/urls");
const { loadScripts, compose } = require("./core/scripts");

function parseArgs(argv) {
  const o = { _: [], set: [], script: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const m = /^--([^=]+)(?:=(.*))?$/s.exec(a);
    if (!m) { o._.push(a); continue; }
    const [, k, v] = m;
    const val = v !== undefined ? v : (k === "set" || k === "script" ? argv[++i] : true);
    if (k === "set" || k === "script") o[k].push(val); else o[k] = val;
  }
  return o;
}

const pick = (a) => a[Math.floor(Math.random() * a.length)];

// Concrete typed values for this visit, so we can see where they went.
// Configured canary values, else generated ones (the fingerprint profile's
// generator, or a fresh one).
function identityFor(settings) {
  const id = { emails: [], passwords: [], phones: [], names: [], ...(settings.identity || {}) };
  const gen = id.generator || ids.newSpec(Math.random);
  return {
    emails: [id.emails.length ? pick(id.emails) : ids.email(gen)],
    passwords: [id.passwords.length ? pick(id.passwords) : ids.password(gen)],
    phones: id.phones.length ? [pick(id.phones)] : [],
    names: id.names.length ? [pick(id.names)] : [],
    seeds: [ids.seedPhrase()],
  };
}

async function sbxScan(url, cfg, opts = {}) {
  const log = opts.log || (() => {});
  const u = new URL(url);
  if (!/^https?:$/.test(u.protocol)) throw new Error("only http(s) URLs");

  // Script paths from the config resolve relative to it; from the CLI, to the cwd.
  const files = [
    ...loadScripts(opts.scripts || cfg.scripts, opts.scripts ? process.cwd() : cfg._dir),
    ...loadScripts(opts.extraScripts || [], process.cwd()),
  ].map((m) => m.file);
  const S = compose(loadScripts(files));
  // Script defaults < fingerprint profile < config settings, --set, web UI.
  const settings = S.settings;
  const fp = fingerprint.load(cfg);
  for (const [k, v] of Object.entries(fingerprint.scanSettings(fp))) settings[k] = deepMerge(settings[k], v);
  for (const [k, v] of Object.entries(cfg.settings || {})) settings[k] = deepMerge(settings[k], v);
  const personaName = opts.persona || (S.personas.desktop ? "desktop" : "default");
  if (!S.personas[personaName]) throw new Error(`unknown persona "${personaName}" (scripts define: ${Object.keys(S.personas).join(", ")})`);

  const id = `${new Date().toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15)}-${crypto.randomBytes(3).toString("hex")}`;
  const dir = path.join(cfg.outDir, id);
  fs.mkdirSync(dir, { recursive: true, mode: 0o750 });

  // Egress (residential session or this host); its country sets the
  // browser's language/timezone.
  const country = (opts.country || cfg.egress.country).toLowerCase();
  let upstream = null, geo = null, egress;
  try {
    if (cfg.egress.residentialProxy) upstream = proxyFor(cfg.egress.residentialProxy, { country });
    geo = await resolveExit(upstream, cfg.egress.geoLookupUrl);
    egress = { mode: upstream ? "residential" : "direct", requested: countryMode(cfg.egress.residentialProxy) === "choose" ? country : null, ip: geo.ip, country: geo.countryCode, locale: geo.locale, timezone: geo.timezoneId, org: geo.org, asn: geo.asn, hosting: geo.hosting, mobile: geo.mobile };
  } catch (e) {
    egress = { mode: upstream ? "residential" : "direct", error: e.message };
  }
  log(`egress: ${egress.mode} ${egress.ip || ""} ${egress.country || ""} ${egress.org || ""}${egress.error ? ` (geo lookup failed: ${egress.error})` : ""}`);

  const identity = identityFor(settings);
  const job = {
    url: u.toString(), persona: personaName, scripts: files, settings, identity,
    referer: opts.referer || null,
    geo: geo ? { locale: geo.locale, timezoneId: geo.timezoneId } : null,
    hardCeilingMs: (cfg.jail.timeoutSec - 20) * 1000,
  };
  log(`visiting ${job.url} as ${personaName}, scripts: ${S.name}`);
  const r = await runVisit({ cfg, visitDir: dir, job, upstream });
  const result = r.result || { url: job.url, fatalError: `visit produced no result (exit ${r.exitCode})\n${r.stderrTail}` };
  result.sbx = { id, request: opts.request || null, fingerprint: { source: fp.source, seed: fp.profile?.seed || null }, egress, identity, egressStats: r.egress, exitCode: r.exitCode, durationMs: r.durationMs };
  const iocs = extractIocs(dir, result, identity);

  // Host-side `after` hooks: exporters, lookups, alerts. They may add
  // indicators (host.ioc) and files (host.dump -> artifacts/).
  const host = {
    url: job.url, dir, result, iocs, settings, errors: [],
    ioc(type, value, context = "") {
      if (value === undefined || value === null || value === "") return;
      const hit = iocs.find((i) => i.type === type && i.value === String(value));
      if (hit) { if (context && !hit.context.includes(context)) hit.context.push(context); }
      else iocs.push({ type, value: String(value), context: context ? [context] : [] });
    },
    dump(name, data) {
      const p = path.join(dir, "artifacts", String(name).replace(/[^a-zA-Z0-9._-]+/g, "_"));
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.writeFileSync(p, typeof data === "string" || Buffer.isBuffer(data) ? data : JSON.stringify(data, null, 2));
      return p;
    },
  };
  await S.after(host);
  if (host.errors.length) result.sbx.afterErrors = host.errors;

  fs.writeFileSync(path.join(dir, "result.json"), JSON.stringify(result, null, 2));
  fs.writeFileSync(path.join(dir, "iocs.json"), JSON.stringify(iocs, null, 2));
  fs.writeFileSync(path.join(dir, "iocs.csv"), toCsv(iocs));
  try { report.writeScanReports(dir); } catch (e) { log(`report: ${e.message}`); }
  return { dir, result, iocs };
}

const USAGE = `usage: urlsandboxex <url ...> [--file=PATH|-] [--parallel=N] [--name=NAME] [--out=PATH]
           [--format=text|json|md|html] [--profile=NAME] [--persona=NAME] [--country=CC]
           [--scripts=a,b] [--script=FILE] [--referer=URL] [--set key.path=value]
       urlsandboxex script check FILE [--persona=NAME] [--pages=quick|all|none|a,b] [--parallel=N]
       urlsandboxex fingerprint [show|rotate]`;

// Errors in how the command was called (exit 2, not 1).
const usage = (msg) => Object.assign(new Error(msg), { usage: true });

// Shared scan options from flags (and --profile).
function scanSetup(o) {
  let cfg = loadConfig(o.set), base = {};
  if (o.profile) {
    const { loadProfiles, applyRequest } = require("./core/profiles");
    const p = loadProfiles(cfg)[o.profile];
    if (!p) throw usage(`no profile "${o.profile}" (have: ${Object.keys(loadProfiles(cfg)).join(", ") || "none"})`);
    ({ cfg, opts: base } = applyRequest(cfg, { ...p, profile: o.profile }));
    for (const s of o.set) { const i = s.indexOf("="); if (s.startsWith("settings.")) require("./core/config").setPath(cfg, s.slice(0, i), s.slice(i + 1)); }
  }
  const opts = {
    ...base, referer: o.referer,
    ...(o.persona ? { persona: o.persona } : {}), ...(o.country ? { country: o.country } : {}),
    ...(o.scripts !== undefined ? { scripts: String(o.scripts === true ? "" : o.scripts).split(",").filter(Boolean) } : {}),
    extraScripts: [...(base.extraScripts || []), ...o.script],
  };
  return { cfg, opts };
}

const tty = process.stderr.isTTY;
const paint = (code, s) => (tty ? `\x1b[${code}m${s}\x1b[0m` : s);
const line = (sm) => [sm.error ? paint(31, sm.error) : `HTTP ${sm.status ?? "-"}`, report.hostOf(sm.finalUrl) !== report.hostOf(sm.url) ? `→ ${report.hostOf(sm.finalUrl)}` : "",
  `${sm.iocs} IOCs`, sm.sinks.length ? paint("1;31", `CREDENTIALS SENT → ${sm.sinks.map((u) => report.hostOf(u) || u).join(", ")}`) : "", sm.downloads ? paint(33, `${sm.downloads} download(s)`) : ""].filter(Boolean).join(" · ");

function writeOut(file, s) {
  const ext = path.extname(file).toLowerCase();
  const body = ext === ".md" ? report.scanMarkdown(s) : ext === ".json" ? JSON.stringify({ ...report.summarize(s), dir: s.dir, iocs: s.iocs }, null, 2) : report.scanHtml(s);
  fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
  fs.writeFileSync(file, body);
}

async function single(url, o, cfg, opts, format) {
  const log = format === "text" ? (m) => console.error(`[urlsandboxex] ${m}`) : () => {};
  const { dir } = await sbxScan(url, cfg, { ...opts, log });
  const s = report.loadScan(dir), sm = report.summarize(s);
  if (o.out) writeOut(o.out, s);
  if (format === "json") console.log(JSON.stringify({ ...sm, dir, report: path.join(dir, "report.html"), iocs: s.iocs }, null, 2));
  else if (format === "md") process.stdout.write(report.scanMarkdown(s));
  else if (format === "html") process.stdout.write(report.scanHtml(s));
  else {
    console.log(`\n${report.defang(sm.url)}\n  ${line(sm)}\n  final: ${report.defang(sm.finalUrl)}\n  title: ${sm.title ?? ""}`);
    if (sm.errorText) console.log(`  error: ${String(sm.errorText).split("\n")[0]}`);
    for (const [t, list] of Object.entries(s.iocs.reduce((g, i) => ((g[i.type] = g[i.type] || []).push(i), g), {}))) {
      console.log(`\n${t} (${list.length})`);
      for (const i of list.slice(0, 25)) console.log(`  ${["url", "domain", "email"].includes(t) ? report.defang(i.value) : i.value}  (${i.context.slice(0, 2).join("; ")})`);
      if (list.length > 25) console.log(`  … ${list.length - 25} more in iocs.json`);
    }
    console.log(`\nreport: ${path.join(dir, "report.html")}${o.out ? `\n        ${path.resolve(o.out)}` : ""}\noutput: ${dir}`);
  }
  return sm.error === "failed" ? 1 : 0;
}

async function bulk(urls, bad, o, cfg, opts, format) {
  const parallel = Math.max(1, Math.min(16, Number(o.parallel) || cfg.web?.maxConcurrent || 2));
  const b = {
    id: crypto.randomBytes(5).toString("hex"), name: String(o.name || `${urls.length} URLs (cli)`).slice(0, 80), createdAt: new Date().toISOString(),
    source: "cli", request: opts.request || null, skipped: bad.slice(0, 500), items: urls.map((url) => ({ url, state: "queued" })),
  };
  const batchFile = path.join(cfg.outDir, "batches", `${b.id}.json`);
  fs.mkdirSync(path.dirname(batchFile), { recursive: true });
  const save = () => fs.writeFileSync(batchFile, JSON.stringify(b));
  save();
  const say = format === "text" || format === "json" ? (m) => console.error(m) : () => {};
  say(`[urlsandboxex] batch ${b.id}: ${urls.length} URLs, ${parallel} at a time${bad.length ? `, ${bad.length} non-URL tokens skipped` : ""}`);
  const entries = urls.map((url) => ({ url, state: "queued", error: null, scan: null }));
  let next = 0, finished = 0;
  const width = String(urls.length).length;
  const worker = async () => {
    while (next < urls.length) {
      const i = next++, e = entries[i];
      e.state = b.items[i].state = "running"; save();
      try {
        const { dir } = await sbxScan(e.url, cfg, opts);
        e.scan = report.loadScan(dir); e.state = "done";
        Object.assign(b.items[i], { state: "done", scanId: e.scan.id });
      } catch (err) {
        e.state = "failed"; e.error = err.message;
        Object.assign(b.items[i], { state: "failed", error: err.message });
      }
      save();
      finished++;
      say(`[${String(finished).padStart(width)}/${urls.length}] ${report.defang(e.url)}  ${e.scan ? line(report.summarize(e.scan)) : paint(31, `failed: ${e.error}`)}`);
    }
  };
  const stop = () => { for (const it of b.items) if (it.state === "queued" || it.state === "running") it.state = "cancelled"; save(); process.exit(130); };
  process.once("SIGINT", stop);
  await Promise.all(Array.from({ length: Math.min(parallel, urls.length) }, worker));

  const dir = path.join(cfg.outDir, "batches", b.id);
  const index = report.writeBatchReports(b, entries, dir);
  if (o.out) report.writeBatchReports(b, entries, path.resolve(o.out), { copyScans: true });
  const sums = entries.map((e) => (e.scan ? report.summarize(e.scan) : null));
  if (format === "json") console.log(JSON.stringify({ batch: b.id, name: b.name, dir, report: index, skipped: bad, results: entries.map((e, i) => ({ url: e.url, state: e.state, error: e.error, ...(sums[i] ? { ...sums[i], dir: e.scan.dir } : {}) })) }, null, 2));
  else if (format === "md") process.stdout.write(report.batchMarkdown(b, entries));
  else if (format === "html") process.stdout.write(report.batchHtml(b, entries, (s) => path.join(s.dir, "report.html")));
  else {
    const done = entries.filter((e) => e.state === "done").length, failed = entries.length - done;
    const sinks = sums.filter((x) => x && x.sinks.length);
    console.log(`\n${b.name}: ${done} scanned${failed ? `, ${paint(31, `${failed} failed`)}` : ""}${sums.filter((x) => x?.error).length ? `, ${sums.filter((x) => x?.error).length} with page errors` : ""}`);
    if (sinks.length) { console.log(paint("1;31", `credentials sent on ${sinks.length} site(s):`)); for (const x of sinks) console.log(`  ${report.defang(x.url)} → ${x.sinks.map(report.defang).join(", ")}`); }
    console.log(`\nreport:  ${index}${o.out ? `\n         ${path.join(path.resolve(o.out), "index.html")}` : ""}\nexports: ${dir}/{summary.csv,iocs.csv,iocs.json,report.md}`);
  }
  return entries.some((e) => e.state === "failed") ? 1 : 0;
}

// urlsandboxex fingerprint [show|rotate]
function fingerprintCommand([action = "show", ...rest]) {
  const cfg = loadConfig(rest.filter((a) => a.startsWith("--set=")).map((a) => a.slice(6)));
  if (action !== "show" && action !== "rotate") { console.error("usage: urlsandboxex fingerprint [show|rotate]"); process.exit(2); }
  const fp = action === "rotate" ? fingerprint.rotate(cfg) : fingerprint.load(cfg);
  if (fp.source === "off") { console.log("fingerprint: off (scripts' built-in defaults)"); return; }
  const s = fp.profile.settings || {};
  const where = fp.source === "auto" ? `generated, ${fp.path}` : `yours, ${fp.path || "inline in the config"}; used as given`;
  console.log(`fingerprint ${fp.profile.seed || ""} (${where})${action === "rotate" ? ": new profile" : ""}`);
  if (s.display) console.log(`  screen   ${s.display.width}x${s.display.height}, panel ${s.display.panelTop ?? 0}px`);
  if (s.window) console.log(`  window   ${s.window.width}x${s.window.height} at ${s.window.x},${s.window.y}${fp.source === "auto" ? " (varies slightly per scan)" : ""}`);
  if (s.humanize) console.log(`  pace     speed ${s.humanize.speed}, keys ${s.humanize.keyMsMin}-${s.humanize.keyMsMax} ms, mouse curve ${s.humanize.curve}`);
  if (s.interact) console.log(`  dwell    ${s.interact.minDwellMs}-${s.interact.maxDwellMs} ms`);
  if (s.delays) console.log(`  delays   fast-forward ${s.delays.fastForwardMs / 1000} s`);
  const g = s.identity?.generator;
  if (g) console.log(`  identity e.g. ${ids.email(g)} / ${ids.password(g)} (domains: ${g.domains.join(", ")})`);
  console.log("Explicit settings in the config, --set and the web UI override these.");
}

async function main() {
  const argv = process.argv.slice(2);
  if (argv[0] === "fingerprint") return fingerprintCommand(argv.slice(1));
  if (argv[0] === "script") {
    if (argv[1] !== "check") { console.error(USAGE); process.exit(2); }
    return require("./tools/script-check").check(argv.slice(2));
  }
  const o = parseArgs(argv);
  if (o.help || o.h) { console.log(USAGE); process.exit(0); }
  const format = o.json ? "json" : String(o.format || "text");
  if (!["text", "json", "md", "html"].includes(format)) { console.error(`urlsandboxex: --format must be text, json, md or html\n${USAGE}`); process.exit(2); }
  let text = o._.join("\n");
  if (o.file) text += `\n${fs.readFileSync(o.file === "-" || o.file === true ? 0 : o.file, "utf8")}`;
  else if (!o._.length && !process.stdin.isTTY) text += `\n${fs.readFileSync(0, "utf8")}`;
  const { urls, bad } = parseUrls(text);
  if (!urls.length) { console.error(bad.length ? `urlsandboxex: no URLs found (not URLs: ${bad.slice(0, 5).join(", ")})` : USAGE); process.exit(2); }
  if (urls.length > MAX_BATCH) throw usage(`${urls.length} URLs; at most ${MAX_BATCH} per batch`);
  const { cfg, opts } = scanSetup(o);
  const code = urls.length === 1 && !o.name ? await single(urls[0], o, cfg, opts, format) : await bulk(urls, bad, o, cfg, opts, format);
  process.exit(code);
}

if (require.main === module) main().catch((e) => { console.error(`urlsandboxex: ${e.message}`); process.exit(e.usage ? 2 : 1); });

module.exports = { sbxScan };
