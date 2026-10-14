// Runs one visit (core/visit.js) in a rootless bubblewrap jail:
//   - its own network namespace with no route out; the only way out is the
//     egress proxy (egress_proxy.js) over a bind-mounted unix socket;
//   - read-only system, private /tmp, no capabilities; the visit directory
//     (mounted at /work) is the only persistent writable path;
//   - Chrome's own namespace + seccomp sandbox nested inside;
//   - memory/CPU/task limits via a user systemd scope when available, and
//     a wall-clock timeout.
// /usr/local/lib/sbx/bwrap is a bwrap copy only the `sbx` group may run,
// with an AppArmor profile allowing user namespaces (deploy/setup.sh), so
// Ubuntu's unprivileged-userns restriction stays on for everything else.

const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn, spawnSync } = require("child_process");
const { startEgressProxy } = require("./egress_proxy");

const SANDBOX_DIR = path.resolve(__dirname, "..");           // the project, node_modules included
const PW_BROWSERS = process.env.PLAYWRIGHT_BROWSERS_PATH || path.join(os.homedir(), ".cache", "ms-playwright");
const ESPEAK_VARIANTS = "/usr/lib/x86_64-linux-gnu/espeak-ng-data/voices/!v";
const BRIDGE_PORT = 18080;

let userScopeOk = null;
function canUseUserScope() {
  if (userScopeOk === null) {
    const r = spawnSync("systemd-run", ["--user", "--scope", "--quiet", "true"], { stdio: "ignore", timeout: 10000 });
    userScopeOk = r.status === 0;
  }
  return userScopeOk;
}

// Outer stage: root only inside its own user+network namespace, to add a
// dummy LAN interface, then exec the inner jail (unprivileged, no
// capabilities) in that network namespace. With only loopback, WebRTC
// yields no ICE candidates; a real computer shows its LAN interface as an
// mDNS .local candidate. The interface goes nowhere. No page code runs here.
function outerArgs(bwrapPath, innerArgs, visitDir) {
  const lan = `192.168.${Math.random() < 0.6 ? 1 : 0}.${2 + Math.floor(Math.random() * 200)}`;
  const setup = [
    "ip link add eth0 type dummy",
    `ip addr add ${lan}/24 dev eth0`,
    "ip link set eth0 up",
    "ip route add default dev eth0",
    'exec "$@"',
  ].join(" && ");
  return [
    // Read-only view of the host for `ip` and the inner bwrap, plus the
    // visit directory writable so the inner jail's /work bind can be too.
    "--ro-bind", "/", "/", "--bind", visitDir, visitDir, "--dev", "/dev", "--proc", "/proc",
    "--unshare-user", "--uid", "0", "--gid", "0", "--unshare-net", "--cap-add", "ALL",
    "--die-with-parent",
    "--", "/bin/sh", "-c", setup, "sbx-net", bwrapPath, ...innerArgs,
  ];
}

function bwrapArgs(cfg, visitDir, runDir, scriptFiles = []) {
  const a = [
    "--ro-bind", "/usr", "/usr",
    "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64", "--symlink", "usr/bin", "/bin", "--symlink", "usr/sbin", "/sbin",
    "--ro-bind", "/etc", "/etc",
    "--ro-bind-try", "/opt/google", "/opt/google",
    "--ro-bind", SANDBOX_DIR, SANDBOX_DIR,
    "--ro-bind-try", PW_BROWSERS, PW_BROWSERS,
    "--ro-bind", runDir, "/run/sbx",
    "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/dev/shm",
    "--tmpfs", "/tmp", "--tmpfs", "/var",
  ];
  // Config files can hold the residential proxy password: blank them for
  // anything inside the jail (the project directory is mounted above).
  for (const f of new Set([path.join(SANDBOX_DIR, "sbx.config.jsonc"), path.resolve("sbx.config.jsonc"), process.env.SBX_CONFIG].filter(Boolean).map((p) => path.resolve(p)))) {
    if (fs.existsSync(f)) a.push("--ro-bind", "/dev/null", f);
  }
  // espeak-ng exposes every voice x variant (13k+ speechSynthesis voices,
  // an obvious tell); hiding the variants leaves one per language.
  if (fs.existsSync(ESPEAK_VARIANTS)) a.push("--tmpfs", ESPEAK_VARIANTS);
  // Analysts' scripts (and anything next to them they require), read-only
  // at their real paths. After the tmpfs mounts, which would otherwise
  // hide a script kept under /tmp or /var.
  const dirs = new Set(scriptFiles.filter((f) => !f.startsWith(SANDBOX_DIR + path.sep)).map((f) => path.dirname(f)));
  for (const d of dirs) a.push("--ro-bind", d, d);
  a.push(
    "--bind", visitDir, "/work",
    // Every namespace except the network one, which the outer stage set up.
    "--unshare-user", "--uid", "1000", "--gid", "1000",
    "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
    "--hostname", "localhost",
    "--die-with-parent", "--new-session", "--cap-drop", "ALL",
    "--clearenv",
    "--setenv", "PATH", "/usr/bin:/bin",
    "--setenv", "HOME", "/tmp/home",
    "--setenv", "XDG_RUNTIME_DIR", "/tmp/xdg",
    "--setenv", "LANG", "C.UTF-8",
    "--setenv", "PLAYWRIGHT_BROWSERS_PATH", PW_BROWSERS,
    "--setenv", "SBX_BRIDGE_PORT", String(BRIDGE_PORT),
    "--setenv", "SBX_JAILED", "1",
    "--chdir", "/tmp",
    "--",
    "/usr/bin/timeout", "-k", "10", String(cfg.jail.timeoutSec),
    process.execPath, path.join(__dirname, "visit.js"), "/work",
  );
  return a;
}

/**
 * @param {object} o
 * @param {object} o.cfg       loaded config
 * @param {string} o.visitDir  output directory for this visit (created by caller)
 * @param {object} o.job       { url, persona, scripts, settings, identity, geo, ... }
 *                             (proxy credentials never go in here)
 * @param {object|null} o.upstream  residential proxy (stays outside the jail)
 * @returns {Promise<{result: object|null, exitCode: number|null, stderrTail: string, durationMs: number, egress: object}>}
 */
async function runVisit({ cfg, visitDir, job, upstream = null }) {
  if (!fs.existsSync(cfg.jail.bwrap)) throw new Error(`${cfg.jail.bwrap} missing, run deploy/setup.sh`);
  // Run directories left by visits that were killed (crash, OOM): older than an hour.
  for (const f of fs.readdirSync(os.tmpdir())) {
    if (!f.startsWith("sbx-run-")) continue;
    const p = path.join(os.tmpdir(), f);
    try { if (Date.now() - fs.statSync(p).mtimeMs > 3600000) fs.rmSync(p, { recursive: true, force: true }); } catch (e) { /* another user's, or gone */ }
  }
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), "sbx-run-"));
  const proxy = await startEgressProxy({
    socketPath: path.join(runDir, "egress.sock"),
    logPath: path.join(visitDir, "connections.jsonl"),
    upstream,
    allow: cfg.egress.allow || [],
  });
  fs.writeFileSync(path.join(visitDir, "job.json"), JSON.stringify(job));

  let cmd = cfg.jail.bwrap;
  let args = outerArgs(cfg.jail.bwrap, bwrapArgs(cfg, visitDir, runDir, job.scripts || []), visitDir);
  if (canUseUserScope()) {
    args = ["--user", "--scope", "--quiet", "--collect",
      "-p", `MemoryMax=${cfg.jail.memoryMax}`, "-p", "MemorySwapMax=0", "-p", `CPUQuota=${cfg.jail.cpuQuota}`, "-p", "TasksMax=768",
      cmd, ...args];
    cmd = "systemd-run";
  }

  const started = Date.now();
  const { exitCode, stderrTail } = await new Promise((resolve) => {
    const child = spawn(cmd, args, { stdio: ["ignore", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (d) => { stderr = (stderr + d.toString()).slice(-6000); });
    const killer = setTimeout(() => child.kill("SIGKILL"), (cfg.jail.timeoutSec + 30) * 1000);
    child.on("close", (code) => { clearTimeout(killer); resolve({ exitCode: code, stderrTail: tail(stderr) }); });
    child.on("error", (e) => { clearTimeout(killer); resolve({ exitCode: null, stderrTail: String(e) }); });
  });
  await proxy.close();
  fs.rmSync(runDir, { recursive: true, force: true });
  // A browser profile the jail could not remove (Chrome still writing).
  for (const f of fs.readdirSync(visitDir)) if (f.startsWith(".profile-")) fs.rmSync(path.join(visitDir, f), { recursive: true, force: true, maxRetries: 3 });

  let result = null;
  try { result = JSON.parse(fs.readFileSync(path.join(visitDir, "result.json"), "utf8")); } catch (e) { /* reported below */ }
  // Only a checkpoint: the visit was killed (memory or time limit) before it finished.
  if (result && result.partial) result.fatalError = `the visit was stopped before it finished (exit ${exitCode === null ? "by a signal, probably the memory limit" : exitCode}); partial result`;
  return { result, exitCode, stderrTail, durationMs: Date.now() - started, egress: proxy.stats };
}

function tail(s) {
  return s.split("\n").filter((l) => l && !/keysym|xkbcomp|XKEYBOARD|libEGL|not fatal to the X server/i.test(l)).slice(-15).join("\n");
}

module.exports = { runVisit };
