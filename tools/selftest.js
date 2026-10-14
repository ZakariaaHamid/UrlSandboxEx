#!/usr/bin/env node
// Evasion coverage: run every built technique page of the research
// harness (techniques.json, coverage "page:<slug>") through the REAL jailed
// sandbox and grade each one from the beacons that page logged.
//
//   node tools/selftest.js [--persona=desktop] [--scripts=a,b] [--script=FILE] [--only=a,b] [--parallel=3]
//                          [--base=http://127.0.0.1:3000] [--bench=PATH]
//
// --bench is the harness checkout (techniques.json, logs/, results/); it
// defaults to $SBX_BENCH, then ../benchmark next to this project.
//
// Oracle: a page's gate is "defeated" when, during this scan, it logged a
// beacon with timedOut:false or any success flag === true (most gate pages
// report {<thing>: revealed, timedOut: !revealed}). "evaded" = the page
// only logged failures/timeouts or nothing. The fingerprint probe is graded
// by its contradiction report and automation score instead.

const fs = require("fs");
const path = require("path");
const os = require("os");
const { loadConfig } = require("../core/config");

const benchArg = process.argv.slice(2).find((a) => a.startsWith("--bench="));
const ROOT = path.resolve(benchArg ? benchArg.slice(8) : process.env.SBX_BENCH || path.join(__dirname, "..", "..", "benchmark"));
const LOG = path.join(ROOT, "logs", "visits.jsonl");

function args() {
  const o = {};
  for (const a of process.argv.slice(2)) { const [k, v] = a.replace(/^--/, "").split(/=(.*)/s); o[k] = v ?? true; }
  return o;
}

function slugs() {
  const t = JSON.parse(fs.readFileSync(path.join(ROOT, "techniques.json"), "utf8")).items;
  const s = new Set();
  for (const i of t) if (i.status === "built" && i.coverage.startsWith("page:")) s.add(i.coverage.slice(5));
  return ["fingerprint-probe", ...[...s].sort()];
}

function readLogSince(offset) {
  const fd = fs.openSync(LOG, "r");
  const size = fs.fstatSync(fd).size;
  const buf = Buffer.alloc(Math.max(0, size - offset));
  fs.readSync(fd, buf, 0, buf.length, offset);
  fs.closeSync(fd);
  return buf.toString("utf8").split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch (e) { return null; } }).filter(Boolean);
}

const NEUTRAL_KEYS = new Set(["timedOut", "error", "elapsedMs", "phase"]);

function grade(slug, events) {
  const mine = events.filter((e) => e.techniqueId === slug);
  const beacons = mine.filter((e) => e.event === "beacon").map((e) => e.data || {});
  if (slug === "fingerprint-probe") {
    const rep = mine.filter((e) => e.event === "contradiction-report").pop();
    const probe = beacons.find((b) => b.summary);
    const mism = rep ? Object.entries(rep.data.checks).filter(([, v]) => v.mismatch === true).map(([k]) => k) : null;
    return { outcome: rep ? (mism.length ? "tells" : "clean") : "no-report", detail: { contradictions: mism, automationScore: probe?.summary?.looksAutomatedScore, summary: probe?.summary } };
  }
  if (!mine.length) return { outcome: "no-pageview", detail: {} };
  // Needs credentials saved in the browser profile, so it is not an evasion check.
  if (slug === "autofill-trap") return { outcome: "n/a", detail: { note: "requires saved browser credentials" } };
  // Informational pages (no gate to pass); checked via extracted IOCs instead.
  if (slug === "text-salting" || slug === "qr-code-redirect") return { outcome: "n/a", detail: { note: "informational page" } };
  // Single-use link: content on the first fetch = defeated. The demo token is
  // shared, so once any visitor burned it the page can't be graded until
  // the harness restarts.
  if (slug === "single-use-token") {
    const uses = beacons.filter((b) => "alreadyUsed" in b);
    if (uses.some((b) => b.alreadyUsed === false)) return { outcome: "defeated", detail: { uses: uses.length } };
    return { outcome: uses.length ? "n/a" : "no-beacon", detail: { note: "token already used before this run (restart the harness to re-test)" } };
  }
  // Traps: "defeated" means the sandbox did NOT fall for them.
  const trapKeys = { "honeypot-link": "hiddenFieldFilled", "hidden-slider-trap": "hiddenSliderTriggered" };
  if (trapKeys[slug]) {
    const sprung = beacons.some((b) => b[trapKeys[slug]] === true) || mine.some((e) => /honeypot|trap-hit/i.test(e.event || ""));
    return { outcome: sprung ? "evaded" : "defeated", detail: { beacons: beacons.slice(0, 4).map((b) => JSON.stringify(b).slice(0, 200)) } };
  }
  let success = false, failure = false;
  for (const b of beacons) {
    if (b.timedOut === false) success = true;
    if (b.timedOut === true) failure = true;
    if (b.showDecoy === false) success = true;           // cloak pages: real content served
    if (b.likelyPrivate === false) success = true;       // incognito detection: looks like a normal profile
    if (b.hop === "final") success = true;               // redirect chain followed to the end
    if (b.showDecoy === true || b.servedDecoy === true) failure = true;
    for (const [k, v] of Object.entries(b)) {
      if (NEUTRAL_KEYS.has(k)) continue;
      if (v === true) success = true;
      if (/reveal/i.test(k) && ((typeof v === "number" && v > 0) || (typeof v === "string" && v.length))) success = true;
    }
  }
  return { outcome: success ? "defeated" : beacons.length ? "evaded" : "no-beacon", detail: { beacons: beacons.slice(0, 6).map((b) => JSON.stringify(b).slice(0, 300)) } };
}

// Scan `list` (page slugs) and grade each page. Used by main() and by
// `urlsandboxex script check` (tools/script-check.js).
async function runSuite({ base = "http://127.0.0.1:3000", persona = "desktop", list = slugs(), scripts = null, extraScripts = [], parallel = 3, set = [], onResult = () => {} } = {}) {
  const { sbxScan } = require("../urlsandboxex"); // here, not at the top: urlsandboxex.js loads this file too
  const host = new URL(base).host;
  const cfg = loadConfig([`egress.allow=${JSON.stringify([host])}`, `outDir=${JSON.stringify(path.join(os.tmpdir(), "sbx-selftest"))}`, ...set]);
  const results = {};
  let next = 0;
  await Promise.all(Array.from({ length: Math.max(1, parallel) }, async () => {
    while (next < list.length) {
      const slug = list[next++];
      const offset = fs.statSync(LOG).size;
      const t0 = Date.now();
      let scan = null, err = null;
      try { scan = await sbxScan(`${base}/pages/${slug}`, cfg, { persona, scripts, extraScripts }); } catch (e) { err = e.message; }
      await new Promise((r) => setTimeout(r, 1500)); // late beacons
      const g = grade(slug, readLogSince(offset));
      const r = scan?.result || {};
      results[slug] = {
        ...g, finalUrl: r.finalUrl || null, error: err || r.navError || r.fatalError || null, interactionError: r.interaction?.error || null,
        scriptErrors: Object.entries(r.log || {}).filter(([k]) => /\.error$|^apiErrors$|^childTargetErrors$|^sessionSetupError$|Error$/.test(k)).map(([k, v]) => `${k}: ${[].concat(v).join("; ")}`.slice(0, 300)),
        seconds: Math.round((Date.now() - t0) / 1000), dir: scan?.dir || null,
      };
      onResult(slug, results[slug]);
    }
  }));
  return results;
}

const line = (slug, r) => `${r.outcome.padEnd(11)} ${slug.padEnd(32)} ${r.seconds}s ${r.outcome === "evaded" || r.outcome.startsWith("no-") ? (r.detail.beacons || []).join(" ").slice(0, 160) : ""}${r.outcome === "tells" ? r.detail.contradictions.join(",") : ""}`;

async function main() {
  const o = args();
  const persona = o.persona || "desktop";
  const startAll = Date.now();
  const results = await runSuite({
    base: o.base, persona, list: o.only ? o.only.split(",") : slugs(), parallel: Number(o.parallel || 3),
    scripts: o.scripts ? o.scripts.split(",") : null, extraScripts: o.script ? [o.script] : [], set: o.set ? [o.set] : [],
    onResult: (slug, r) => console.log(line(slug, r)),
  });
  const counts = {};
  for (const r of Object.values(results)) counts[r.outcome] = (counts[r.outcome] || 0) + 1;
  const out = path.join(ROOT, "results", `sbx_selftest_${persona}${o.only ? "_partial" : ""}.json`);
  fs.writeFileSync(out, JSON.stringify({ at: new Date().toISOString(), persona, counts, minutes: Math.round((Date.now() - startAll) / 60000), results }, null, 2));
  console.log(`\n${JSON.stringify(counts)} -> ${out}`);
  process.exit(0);
}

if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });

module.exports = { runSuite, slugs, line, grade, LOG };
