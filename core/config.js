// Configuration: defaults below, overlaid by the first JSONC file found
// ($SBX_CONFIG, ./sbx.config.jsonc, sbx.config.jsonc,
// ~/.config/sbx/config.jsonc), overlaid by --set key.path=value flags.

const fs = require("fs");
const os = require("os");
const path = require("path");

const DEFAULTS = {
  // Where each scan's output directory is created.
  outDir: path.join(os.homedir(), "sbx-scans"),

  // Scripts run on every visit, in order: built-in names (scripts/) or
  // paths relative to the config file. [] = core only.
  scripts: ["stealth", "challenges", "interact", "delays", "dynamic-code", "indicators"],

  // Extra folders of scripts the web UI offers (relative to the config
  // file). Built-ins are always offered.
  scriptDirs: [],

  // Overrides for scripts' settings, section by section
  // (e.g. { "interact": { "mode": "passive" } }).
  settings: {},

  egress: {
    // Residential/mobile proxy URL template; {country}, {session}. http(s)://
    // only (Chromium can't authenticate to SOCKS5). Empty = host's own IP.
    residentialProxy: "",
    country: "us",
    geoLookupUrl: "http://ip-api.com/json/?fields=status,message,countryCode,timezone,isp,org,as,mobile,hosting,query",
    // host:port exceptions to the "public internet only" policy.
    allow: [],
  },

  // Web UI (web/server.js). No login: it serves loopback only; reach it
  // over an SSH tunnel. allowedHosts: extra Host header names to accept
  // (e.g. a reverse proxy's name); anything else is refused.
  web: { host: "127.0.0.1", port: 8090, allowedHosts: [], maxConcurrent: 2 },

  jail: {
    bwrap: "/usr/local/lib/sbx/bwrap",
    memoryMax: "2G",
    cpuQuota: "200%",
    timeoutSec: 240,
  },
};

function stripJsonComments(text) {
  let out = "", inStr = false, esc = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i], n = text[i + 1];
    if (inStr) {
      out += c;
      if (esc) esc = false; else if (c === "\\") esc = true; else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; out += c; continue; }
    if (c === "/" && n === "/") { while (i < text.length && text[i] !== "\n") i++; out += "\n"; continue; }
    if (c === "/" && n === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++; i++; continue; }
    out += c;
  }
  return out.replace(/,(\s*[}\]])/g, "$1"); // trailing commas
}

function isObj(v) { return v && typeof v === "object" && !Array.isArray(v); }

function deepMerge(base, over) {
  if (!isObj(base) || !isObj(over)) return over === undefined ? base : over;
  const out = { ...base };
  for (const [k, v] of Object.entries(over)) out[k] = isObj(v) && isObj(base[k]) ? deepMerge(base[k], v) : v;
  return out;
}

function setPath(obj, dotted, rawValue) {
  let value;
  try { value = JSON.parse(rawValue); } catch (e) { value = rawValue; }
  const keys = dotted.split(".");
  let o = obj;
  for (const k of keys.slice(0, -1)) { if (!isObj(o[k])) o[k] = {}; o = o[k]; }
  o[keys[keys.length - 1]] = value;
}

function configPath() {
  const candidates = [process.env.SBX_CONFIG, path.resolve("sbx.config.jsonc"), path.join(__dirname, "..", "sbx.config.jsonc"), path.join(os.homedir(), ".config", "sbx", "config.jsonc")];
  return candidates.find((p) => p && fs.existsSync(p)) || null;
}

/**
 * @param {string[]} [sets] "a.b=value" overrides (value parsed as JSON when possible)
 */
function loadConfig(sets = []) {
  const file = configPath();
  let cfg = DEFAULTS;
  if (file) {
    const user = JSON.parse(stripJsonComments(fs.readFileSync(file, "utf8")));
    cfg = deepMerge(DEFAULTS, user);
    cfg._dir = path.dirname(file);
  }
  cfg = JSON.parse(JSON.stringify(cfg));
  for (const s of sets) {
    const i = s.indexOf("=");
    if (i < 1) throw new Error(`--set expects key.path=value, got "${s}"`);
    setPath(cfg, s.slice(0, i), s.slice(i + 1));
  }
  cfg.outDir = cfg.outDir.replace(/^~(?=\/|$)/, os.homedir());
  return cfg;
}

module.exports = { loadConfig, stripJsonComments, deepMerge, setPath };
