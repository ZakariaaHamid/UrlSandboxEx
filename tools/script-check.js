// urlsandboxex script check: does a script make the sandbox easier to detect or
// evade?
//
//   urlsandboxex script check FILE [--persona=desktop] [--pages=quick|all|none|a,b,c]
//                         [--parallel=3] [--base=http://127.0.0.1:3000]
//
// 1. Detection: scans tools/tamper-probe.html (served here) twice without
//    the script and once with it. Any value that is the same in both
//    runs without the script and different with it (a function that no
//    longer looks native, a new global, a changed navigator value, a
//    DevTools leak, foreign code calling DOM APIs) is a failure.
// 2. Evasion: when the research harness is running, scans its pages
//    without and with the script; a page that passed and no longer does,
//    or a new fingerprint inconsistency, is a failure (retried once).
// A script that throws also fails. Exit 0 pass, 1 fail, 2 usage.

const fs = require("fs");
const os = require("os");
const http = require("http");
const path = require("path");
const { loadScripts } = require("../core/scripts");
const { loadConfig } = require("../core/config");

// Fingerprinting, anti-debugging, CAPTCHAs, behaviour, iframes, obfuscation
// and delivery: what a script that hooks, reads or waits could disturb.
const QUICK = [
  "fingerprint-probe", "devtools-anti-debug", "incognito-detect", "visibility-gate",
  "turnstile-gate", "recaptcha-gate", "fake-captcha-gate", "cloak-decoy-gate",
  "mouse-behavior-gate", "honeypot-link", "iframe-embedded-form", "nested-iframe-form",
  "js-obfuscator-output", "aes-webcrypto-payload", "delayed-js-reveal", "html-smuggling-blob",
  "websocket-reveal", "clickfix-clipboard",
];
const PASSED = new Set(["defeated", "clean", "n/a"]);

function usage(msg) {
  if (msg) console.error(msg);
  console.error("usage: urlsandboxex script check FILE [--persona=desktop] [--pages=quick|all|none|a,b,c] [--parallel=3] [--base=URL]");
  process.exit(2);
}

// --- detection probe ------------------------------------------------------------
async function probeRuns(file, persona, log) {
  const html = fs.readFileSync(path.join(__dirname, "tamper-probe.html"));
  const reports = {};
  const server = http.createServer((req, res) => {
    const run = new URL(req.url, "http://x").searchParams.get("run");
    if (req.method === "POST" && req.url.startsWith("/report")) {
      let body = ""; req.on("data", (d) => { body += d; if (body.length > 2e6) req.destroy(); });
      req.on("end", () => { try { reports[run] = JSON.parse(body); } catch (e) { /* partial */ } res.end("ok"); });
      return;
    }
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.end(html);
  }).listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  const host = `127.0.0.1:${server.address().port}`;
  const cfg = loadConfig([`egress.allow=${JSON.stringify([host])}`, `outDir=${JSON.stringify(path.join(os.tmpdir(), "sbx-script-check"))}`]);
  const { sbxScan } = require("../urlsandboxex");
  const scan = async (run, extraScripts) => {
    const r = await sbxScan(`http://${host}/?run=${run}`, cfg, { persona, extraScripts }).catch((e) => ({ error: e.message }));
    for (let i = 0; i < 20 && !reports[run]; i++) await new Promise((x) => setTimeout(x, 250));
    log(`  ${reports[run] ? "probe ok   " : "no report  "} ${run}`);
    return { report: reports[run] || null, result: r.result || null, error: r.error || r.result?.fatalError || null };
  };
  try {
    log(`\ndetection probe (${persona})`);
    return { a: await scan("without-1", []), b: await scan("without-2", []), w: await scan("with", [file]) };
  } finally { server.close(); }
}

// Leaves of a report as path -> JSON text; arrays stay whole.
function leaves(o, prefix = "", out = {}) {
  for (const [k, v] of Object.entries(o || {})) {
    const p = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) leaves(v, p, out); else out[p] = JSON.stringify(v);
  }
  return out;
}

function probeDiff({ a, b, w }) {
  if (!a.report || !b.report) return { problems: [], broken: `the probe page did not report without the script (${a.error || b.error || "no report"})` };
  if (!w.report) return { problems: [`no probe report with the script (${w.error || "the page did not finish"})`] };
  const A = leaves(a.report), B = leaves(b.report), W = leaves(w.report);
  const problems = [];
  for (const k of Object.keys(A)) {
    if (A[k] !== B[k] || W[k] === A[k]) continue; // unstable without the script, or unchanged
    const before = JSON.parse(A[k]), after = W[k] === undefined ? undefined : JSON.parse(W[k]);
    if (Array.isArray(before) && Array.isArray(after)) {
      const added = after.filter((x) => !before.includes(x)), removed = before.filter((x) => !after.includes(x));
      problems.push(`page can see ${k}: ${[added.length && `added ${added.slice(0, 8).join(", ")}${added.length > 8 ? "..." : ""}`, removed.length && `removed ${removed.slice(0, 8).join(", ")}`].filter(Boolean).join("; ")}`);
    } else problems.push(`page can see ${k}: ${A[k]} without the script, ${W[k]} with it`);
  }
  return { problems, compared: Object.keys(A).filter((k) => A[k] === B[k]).length };
}

async function check(argv) {
  const o = { persona: "desktop", pages: "quick", parallel: "3", base: "http://127.0.0.1:3000" };
  const files = [];
  for (const a of argv) {
    const m = a.match(/^--(\w+)=(.*)$/s);
    if (m) o[m[1]] = m[2]; else if (!a.startsWith("--")) files.push(a); else usage(`unknown option ${a}`);
  }
  if (files.length !== 1) usage("give one script file");
  const file = path.resolve(files[0]);
  if (!fs.existsSync(file)) usage(`no such file: ${file}`);

  // 1. It loads, and what it declares.
  let mod;
  try { [mod] = loadScripts([file]); } catch (e) { console.error(`FAIL  the script does not load: ${e.message}`); process.exit(1); }
  const hooks = (mod.own ? mod.own.hooks : Object.keys(mod).filter((k) => typeof mod[k] === "function")).join(", ") || "none";
  console.log(`script ${mod.name}: ${hooks}${mod.after ? " (after() runs on the host)" : ""}`);

  // 2. Detection probe.
  const problems = [];
  const log = (l) => console.log(l);
  const pd = probeDiff(await probeRuns(file, o.persona, log));
  if (pd.broken) { console.error(`\nFAIL  ${pd.broken}`); process.exit(1); }
  console.log(`  ${pd.compared} values compared, ${pd.problems.length} changed`);
  problems.push(...pd.problems);

  // 3. Evasion pages, if the research harness is running.
  const suite = require("./selftest");
  let harness = o.pages !== "none";
  if (harness) {
    try { await fetch(`${o.base}/`, { signal: AbortSignal.timeout(5000) }); } catch (e) { harness = false; console.log(`\nnote: the research harness is not reachable at ${o.base}; evasion pages skipped`); }
    if (harness && !fs.existsSync(suite.LOG)) { harness = false; console.log(`\nnote: no harness log at ${suite.LOG} (pass --bench=PATH or set SBX_BENCH); evasion pages skipped`); }
  }
  if (!harness) return verdict(mod, problems, "the detection probe");
  const list = o.pages === "quick" ? QUICK : o.pages === "all" ? suite.slugs() : o.pages.split(",");
  const run = (label, extraScripts, pages) => {
    console.log(`\n${label} (${pages.length} pages, ${o.persona})`);
    return suite.runSuite({ base: o.base, persona: o.persona, list: pages, parallel: Number(o.parallel), extraScripts, onResult: (slug, r) => console.log(`  ${suite.line(slug, r)}`) });
  };

  // Without, then with. Never at the same time: grading reads the
  // harness log per page.
  const base = await run("without the script", [], list);
  // Pages that could not be graded without the script say nothing about it.
  const ungraded = list.filter((s) => base[s].outcome.startsWith("no-") || base[s].error);
  if (ungraded.length > list.length / 2) {
    console.error(`\nFAIL  the sandbox could not test ${ungraded.length} of ${list.length} pages without the script; fix that first`);
    const errs = [...new Set(ungraded.map((s) => base[s].error).filter(Boolean))].slice(0, 3);
    for (const e of errs) console.error(`  ${String(e).split("\n")[0]}`);
    process.exit(1);
  }
  let withIt = await run(`with ${mod.name}`, [file], list);

  const worse = (slug, a = base, b = withIt) => PASSED.has(a[slug].outcome) && !PASSED.has(b[slug].outcome);
  const newTells = (slug, b = withIt) => {
    if (slug !== "fingerprint-probe") return [];
    const before = new Set(base[slug].detail?.contradictions || []);
    return (b[slug].detail?.contradictions || []).filter((c) => !before.has(c));
  };
  // One retry for anything that got worse: pages can fail once under load.
  const suspects = list.filter((s) => worse(s) || newTells(s).length);
  if (suspects.length) {
    const again = await run("retrying pages that got worse", [file], suspects);
    withIt = { ...withIt, ...again };
  }

  for (const slug of ungraded) console.log(`note: ${slug} could not be graded without the script (${base[slug].outcome}); not counted`);
  for (const slug of list) {
    if (ungraded.includes(slug)) continue;
    if (worse(slug)) problems.push(`${slug}: ${base[slug].outcome} without the script, ${withIt[slug].outcome} with it`);
    const tells = newTells(slug);
    if (tells.length) problems.push(`${slug}: new fingerprint inconsistency: ${tells.join(", ")}`);
    for (const e of withIt[slug].scriptErrors || []) if (!(base[slug].scriptErrors || []).includes(e)) problems.push(`${slug}: ${e}`);
    if (withIt[slug].error && !base[slug].error) problems.push(`${slug}: scan failed: ${String(withIt[slug].error).split("\n")[0]}`);
  }
  const median = (r) => { const v = Object.values(r).map((x) => x.seconds).sort((a, b) => a - b); return v[Math.floor(v.length / 2)] || 0; };
  const slower = median(withIt) - median(base);
  console.log(`\nmedian time per page: ${median(base)}s without, ${median(withIt)}s with`);
  if (slower > Math.max(5, median(base) / 2)) console.log(`note: the script makes scans ${slower}s slower`);
  return verdict(mod, problems, `the detection probe and ${list.length} harness pages`);
}

function verdict(mod, problems, what) {
  if (!problems.length) { console.log(`\nPASS  no regressions with ${mod.name} on ${what}`); process.exit(0); }
  console.log(`\nFAIL  ${problems.length} problem(s) with ${mod.name}:`);
  for (const p of problems) console.log(`  - ${p}`);
  process.exit(1);
}

module.exports = { check };
