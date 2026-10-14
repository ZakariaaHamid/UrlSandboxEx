// The fingerprint profile: every value a kit could use to recognise this
// installation (screen and window geometry, interaction timing, typed
// identities, fast-forward amount), as script settings.
//
// config `fingerprint`:
//   "auto" (default)  generated from a random seed into outDir/fingerprint.json
//                     on first use; `urlsandboxex fingerprint rotate` draws a new one.
//                     Each scan also varies the window slightly.
//   "PATH" or {...}   your own profile, used exactly as given (missing keys
//                     keep the scripts' defaults); never generated, varied
//                     or rotated.
//   "off"             the scripts' built-in defaults.
// Explicit config `settings`, --set and web UI choices always win.

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const identity = require("../lib/identity");

// Common desktop screens, weighted by how often they occur.
const SCREENS = [[1920, 1080, 30], [1366, 768, 10], [1536, 864, 10], [2560, 1440, 9], [1440, 900, 6], [1680, 1050, 5], [1600, 900, 5],
  [1280, 1024, 3], [1280, 800, 3], [1920, 1200, 4], [2560, 1080, 2], [3440, 1440, 2], [1360, 768, 2]];
const PANELS = [24, 27, 28, 30, 32, 36, 40];

// Deterministic random numbers from a seed.
function rng(seed) {
  let h = crypto.createHash("sha256").update(String(seed)).digest().readUInt32LE(0);
  return () => { h = (h + 0x6d2b79f5) | 0; let t = Math.imul(h ^ (h >>> 15), 1 | h); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

function generate(seed = crypto.randomBytes(8).toString("hex")) {
  const r = rng(seed);
  const between = (a, b) => a + r() * (b - a);
  const int = (a, b) => Math.round(between(a, b));
  const total = SCREENS.reduce((a, s) => a + s[2], 0);
  let roll = r() * total, screen = SCREENS[0];
  for (const s of SCREENS) { if ((roll -= s[2]) < 0) { screen = s; break; } }
  const [sw, sh] = screen;
  const panelTop = PANELS[Math.floor(r() * PANELS.length)];
  const maximized = r() < 0.4;
  const ww = maximized ? sw : Math.max(1024, Math.round(sw * between(0.7, 0.95)));
  const wh = maximized ? sh - panelTop : Math.max(700, Math.round((sh - panelTop) * between(0.8, 0.97)));
  const minDwell = int(200, 450);
  const stepsMin = int(10, 18);
  const stepMs = int(3, 7);
  const keyMs = int(30, 80);
  return {
    version: 1, seed, createdAt: new Date().toISOString(),
    settings: {
      display: { width: sw, height: sh, panelTop },
      window: { width: ww, height: wh, x: maximized ? 0 : int(0, sw - ww), y: maximized ? panelTop : int(panelTop, Math.max(panelTop, sh - wh)) },
      interact: { minDwellMs: minDwell, maxDwellMs: minDwell + int(300, 700), passiveMoves: int(4, 9) },
      humanize: {
        speed: Math.round(between(0.8, 1.25) * 100) / 100, curve: Math.round(between(0.12, 0.35) * 100) / 100,
        mouseStepsMin: stepsMin, mouseStepsMax: stepsMin + int(8, 16), mouseStepMsMin: stepMs, mouseStepMsMax: stepMs + int(8, 18),
        keyMsMin: keyMs, keyMsMax: keyMs + int(100, 220),
      },
      delays: { fastForwardMs: int(90, 150) * 1000 },
      identity: { generator: identity.newSpec(r) },
    },
  };
}

// { source, path, profile } for this config.
function load(cfg) {
  const ref = cfg.fingerprint === undefined ? "auto" : cfg.fingerprint;
  if (ref === "off" || ref === false) return { source: "off", profile: null };
  if (ref && typeof ref === "object") return { source: "user", path: null, profile: ref };
  if (ref === "auto") {
    const p = path.join(cfg.outDir, "fingerprint.json");
    try { return { source: "auto", path: p, profile: JSON.parse(fs.readFileSync(p, "utf8")) }; } catch (e) { if (e.code !== "ENOENT") throw new Error(`${p}: ${e.message}`); }
    const profile = generate();
    fs.mkdirSync(cfg.outDir, { recursive: true });
    try { fs.writeFileSync(p, JSON.stringify(profile, null, 2), { mode: 0o640, flag: "wx" }); } catch (e) {
      if (e.code === "EEXIST") return { source: "auto", path: p, profile: JSON.parse(fs.readFileSync(p, "utf8")) }; // a parallel scan won
      throw e;
    }
    return { source: "auto", path: p, profile };
  }
  const p = path.resolve(cfg._dir || process.cwd(), String(ref).replace(/^~(?=\/|$)/, require("os").homedir()));
  try { return { source: "user", path: p, profile: JSON.parse(fs.readFileSync(p, "utf8")) }; } catch (e) { throw new Error(`fingerprint profile ${p}: ${e.message}`); }
}

// Settings for one scan. Generated profiles vary the window a little per
// scan; a user's profile is used exactly as given.
function scanSettings(fp, r = Math.random) {
  const s = JSON.parse(JSON.stringify(fp.profile?.settings || {}));
  if (fp.source !== "auto" || !s.window || !s.display) return s;
  const { width: sw, height: sh, panelTop = 0 } = s.display, w = s.window;
  if (w.x > 0 || w.y > panelTop) { // not maximized
    w.width = Math.min(sw, w.width + Math.round((r() - 0.5) * 40));
    w.height = Math.min(sh - panelTop, w.height + Math.round((r() - 0.5) * 30));
    w.x = Math.max(0, Math.min(sw - w.width, w.x + Math.round((r() - 0.5) * 60)));
    w.y = Math.max(panelTop, Math.min(sh - w.height, w.y + Math.round((r() - 0.5) * 40)));
  }
  return s;
}

function rotate(cfg) {
  const fp = load(cfg);
  if (fp.source !== "auto") throw new Error(fp.source === "off" ? "fingerprint is \"off\" in the config" : `the fingerprint profile is yours (${fp.path || "inline in the config"}); edit it, or set "fingerprint": "auto"`);
  const profile = generate();
  fs.writeFileSync(fp.path, JSON.stringify(profile, null, 2), { mode: 0o640 });
  return { ...fp, profile };
}

module.exports = { generate, load, scanSettings, rotate, rng };
