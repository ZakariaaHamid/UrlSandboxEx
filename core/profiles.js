// Scan requests and saved profiles (web UI and `urlsandboxex --profile`).
//
// A request is the per-scan customization:
//   { persona, country, scripts: [library keys], overrides: { "section.key": value } }
// Only installed scripts can be named (core/scripts.js scriptLibrary), so a
// request never brings code of its own. Profiles are named requests stored
// in <outDir>/profiles.json.

const fs = require("fs");
const path = require("path");
const { scriptLibrary } = require("./scripts");
const { deepMerge, setPath } = require("./config");

const PATH_RE = /^[A-Za-z_][\w-]*(\.[A-Za-z_][\w-]*)+$/;
const FORBIDDEN = /(^|\.)(__proto__|prototype|constructor)(\.|$)/;
const NAME_RE = /^[\w .-]{1,40}$/;

// Validates untrusted input; throws with a message fit for the analyst.
function normalizeRequest(input, lib) {
  const r = input && typeof input === "object" ? input : {};
  const keys = new Set(lib.filter((s) => !s.error).map((s) => s.key));
  const out = { persona: null, country: null, scripts: null, overrides: {} };
  if (r.persona) { if (!/^[\w-]{1,40}$/.test(r.persona)) throw new Error("invalid persona"); out.persona = r.persona; }
  if (r.country) { if (!/^[a-z]{2}$/i.test(r.country)) throw new Error("country must be a 2-letter code"); out.country = r.country.toLowerCase(); }
  if (Array.isArray(r.scripts)) {
    const unknown = r.scripts.filter((k) => !keys.has(k));
    if (unknown.length) throw new Error(`unknown script(s): ${unknown.join(", ")}`);
    out.scripts = [...new Set(r.scripts)];
  }
  for (const [k, v] of Object.entries(r.overrides || {})) {
    if (!PATH_RE.test(k) || FORBIDDEN.test(k)) throw new Error(`invalid setting name "${k}" (use section.key)`);
    if (JSON.stringify(v).length > 4000) throw new Error(`setting ${k} is too long`);
    out.overrides[k] = v;
  }
  // Requests saved by the first web UI version.
  if (r.interaction) out.overrides["interact.mode"] = r.interaction;
  if (r.arrival || r.clock) {
    out.scripts = out.scripts || null;
    if (r.arrival) out.overrides["arrival.from"] = r.arrival;
    if (r.clock) out.overrides["clock.mode"] = r.clock;
    out.extraScripts = [r.arrival && "arrival", r.clock && "clock"].filter(Boolean);
  }
  if (r.profile && NAME_RE.test(r.profile)) out.profile = r.profile;
  return out;
}

// -> { cfg, opts } for sbxScan(url, cfg, opts).
function applyRequest(cfg, req) {
  const lib = scriptLibrary(cfg);
  const r = normalizeRequest(req, lib);
  const fileOf = (k) => lib.find((s) => s.key === k).file;
  const settings = {};
  for (const [k, v] of Object.entries(r.overrides)) setPath(settings, k, JSON.stringify(v));
  const opts = { persona: r.persona || undefined, country: r.country || undefined, request: r };
  if (r.scripts) opts.scripts = r.scripts.map(fileOf);
  if (r.extraScripts) opts.extraScripts = r.extraScripts.map(fileOf);
  return { cfg: { ...cfg, settings: deepMerge(cfg.settings || {}, settings) }, opts };
}

const fileFor = (cfg) => path.join(cfg.outDir, "profiles.json");
function loadProfiles(cfg) {
  try { return JSON.parse(fs.readFileSync(fileFor(cfg), "utf8")); } catch (e) { return {}; }
}
function saveProfile(cfg, name, req) {
  if (!NAME_RE.test(name || "")) throw new Error("profile names: letters, digits, space . _ - (max 40)");
  const all = loadProfiles(cfg);
  all[name] = { ...normalizeRequest(req, scriptLibrary(cfg)), profile: undefined, savedAt: new Date().toISOString() };
  fs.writeFileSync(fileFor(cfg), JSON.stringify(all, null, 2));
}
function deleteProfile(cfg, name) {
  const all = loadProfiles(cfg);
  delete all[name];
  fs.writeFileSync(fileFor(cfg), JSON.stringify(all, null, 2));
}

module.exports = { normalizeRequest, applyRequest, loadProfiles, saveProfile, deleteProfile, PATH_RE };
