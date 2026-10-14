#!/usr/bin/env node
// One visit = one browser, one persona. Runs INSIDE the jail (core/jail.js):
// no network except the egress proxy's unix socket at /run/sbx/egress.sock,
// and /work (this visit's output directory) as the only writable,
// persistent path. Reads /work/job.json; writes /work/result.json plus
// screenshots, HAR, DOM and captured assets.

const fs = require("fs");
const net = require("net");
const path = require("path");

const workDir = path.resolve(process.argv[2] || "/work");
const BRIDGE_PORT = Number(process.env.SBX_BRIDGE_PORT || 18080);
const EGRESS_SOCK = "/run/sbx/egress.sock";

// Chrome can't speak to a unix-socket proxy, so a loopback TCP listener
// inside the jail's own network namespace forwards to it.
function startBridge() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer((c) => {
      const u = net.connect(EGRESS_SOCK);
      c.pipe(u); u.pipe(c);
      const done = () => { c.destroy(); u.destroy(); };
      c.on("error", done); u.on("error", done); c.on("close", done); u.on("close", done);
    });
    srv.once("error", reject);
    srv.listen(BRIDGE_PORT, "127.0.0.1", () => resolve(srv));
  });
}

async function main() {
  const jobPath = path.join(workDir, "job.json");
  const job = JSON.parse(fs.readFileSync(jobPath, "utf8"));
  fs.unlinkSync(jobPath);
  fs.mkdirSync(process.env.HOME, { recursive: true });

  // Scripts are code, so they're loaded again here, inside the jail; the
  // host already merged their settings with config overrides.
  const { loadScripts, compose } = require("./scripts");
  const S = compose(loadScripts(job.scripts));
  Object.assign(S.settings, job.settings);
  S.scan = { ...S.scan, ...(job.settings.scan || {}) };
  S.display = { ...S.display, ...(job.settings.display || {}) };

  const bridge = await startBridge();
  const { browse } = require("./browse");
  const started = Date.now();
  let result;
  try {
    result = await browse(job, S, { outDir: workDir, proxy: { server: `http://127.0.0.1:${BRIDGE_PORT}` }, identity: job.identity });
  } catch (e) {
    result = { url: job.url, fatalError: String((e && e.stack) || e).slice(0, 2000) };
  }
  result.visitDurationMs = Date.now() - started;
  fs.writeFileSync(path.join(workDir, "result.json"), JSON.stringify(result, null, 2));
  bridge.close();
}

main().then(() => process.exit(0), (e) => {
  try { fs.writeFileSync(path.join(workDir, "result.json"), JSON.stringify({ fatalError: String((e && e.stack) || e).slice(0, 2000) })); } catch (e2) { /* nothing left to do */ }
  process.exit(1);
});
