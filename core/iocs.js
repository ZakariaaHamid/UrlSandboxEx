// Core indicator extraction (runs on the host after the visit): what the
// page touched, served and sent. Scripts add more via ctx.ioc()
// (artifacts/script-iocs.jsonl), merged here.

const fs = require("fs");
const path = require("path");

const readJson = (p) => { try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch (e) { return null; } };
const readText = (p) => { try { return fs.readFileSync(p, "utf8"); } catch (e) { return ""; } };
const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch (e) { return null; } };
const isLoopback = (ip) => /^\[?(127\.|::1\]?$)/.test(String(ip));
// Registrable domain, roughly (two labels; three for common second-level ccTLDs).
const apex = (h) => { if (!h) return ""; const p = h.split("."); return p.slice(/^(co|com|org|net|gov|ac|edu)$/.test(p[p.length - 2]) && p.length > 2 ? -3 : -2).join("."); };

/**
 * @param {string} dir     visit directory
 * @param {object} result  result.json
 * @param {object} typed   { emails, passwords, seeds } the sandbox typed
 */
function extractIocs(dir, result, typed = {}) {
  const map = new Map();
  const add = (type, value, context) => {
    if (value === null || value === undefined || value === "") return;
    const k = `${type}|${value}`;
    if (!map.has(k)) map.set(k, { type, value: String(value), context: [] });
    if (context && !map.get(k).context.includes(context)) map.get(k).context.push(context);
  };
  const entries = readJson(path.join(dir, result.har || "assets/traffic.har"))?.log?.entries || [];

  add("url", result.url, "submitted");
  for (const u of result.redirectChain || []) add("url", u, "redirect hop");
  if (/^https?:/.test(result.finalUrl || "")) add("url", result.finalUrl, "final");
  for (const p of result.popups || []) if (/^https?:/.test(p.url || "")) add("url", p.url, "popup");
  for (const d of result.downloads || []) { add("url", d.url, `download ${d.suggestedFilename || ""}`); add("sha256", d.sha256, `downloaded file${d.suggestedFilename ? ` "${d.suggestedFilename}"` : ""}`); }
  for (const w of result.websocket || []) add("url", w.url, "websocket");
  if (result.tls?.subjectName) add("tls", `${result.tls.subjectName} | issuer=${result.tls.issuer} | ${fmt(result.tls.validFrom)}..${fmt(result.tls.validTo)}`, "final host certificate");

  // Hosts the page contacted, and their real IPs from the egress log (the
  // HAR sees the in-jail bridge). Hosts only in the egress log are Chrome's
  // own background traffic, not the page's.
  const pageHosts = new Set();
  for (const e of entries) {
    if (result.arrivedVia && e.request?.url === result.arrivedVia) continue; // stand-in page served locally (arrival script)
    const h = hostOf(e.request?.url);
    if (!h) continue;
    pageHosts.add(h); add("domain", h, "contacted");
    if (e.serverIPAddress && !isLoopback(e.serverIPAddress)) add("ip", e.serverIPAddress.replace(/^\[|\]$/g, ""), h);
    const body = e.response?.content?.text;
    if (body && e.response.content.size > 0) {
      const buf = Buffer.from(body, e.response.content.encoding === "base64" ? "base64" : "utf8");
      const type = (e.response.content.mimeType || "").split(";")[0].trim();
      add("sha256", require("crypto").createHash("sha256").update(buf).digest("hex"), `response body${type ? ` (${type})` : ""} of ${e.request.url}`.slice(0, 300));
    }
  }
  for (const line of readText(path.join(dir, "connections.jsonl")).split("\n")) {
    if (!line) continue;
    try {
      const c = JSON.parse(line);
      if (c.blocked) add("domain", c.host, `blocked by egress policy (${c.blocked})`);
      else if (pageHosts.has(c.host) && c.address) add("ip", c.address, c.host);
    } catch (e) { /* partial line */ }
  }

  // Where the typed values went: credential-submission endpoints.
  const needles = [];
  for (const v of [...(typed.emails || []), ...(typed.passwords || [])]) if (v && v.length >= 5) needles.push(v, encodeURIComponent(v), Buffer.from(v).toString("base64").replace(/=+$/, ""));
  const seedWords = (typed.seeds || []).flatMap((p) => p.split(" "));
  const hit = (s) => s && (needles.some((n) => s.includes(n)) || seedWords.filter((w) => s.includes(w)).length >= 3);
  // The kit's own sites: the submitted URL and its redirect hops (not the
  // final page, which after a submission is often the real service).
  const kitApexes = new Set([result.url, ...(result.redirectChain || [])].map((u) => apex(hostOf(u))));
  for (const e of entries) {
    const body = e.request?.postData?.text || "";
    const decoded = /^[A-Za-z0-9+/=\s]{16,}$/.test(body) ? Buffer.from(body, "base64").toString("utf8") : "";
    if (hit(e.request?.url) || hit(body) || hit(decoded)) add("url", e.request.url, `credential submission (${e.request.method}${kitApexes.has(apex(hostOf(e.request.url))) ? "" : ", third-party"})`);
  }
  for (const w of result.websocket || []) if (w.dir === "sent" && hit(w.payload)) add("url", w.url, "credential submission (websocket)");

  // Script-contributed indicators, and URLs in script artifacts (decoded code).
  const art = path.join(dir, "artifacts");
  for (const line of readText(path.join(art, "script-iocs.jsonl")).split("\n")) {
    try { if (line) { const i = JSON.parse(line); add(i.type, i.value, i.context); } } catch (e) { /* skip */ }
  }
  try {
    for (const f of fs.readdirSync(art)) {
      if (!/\.(js|txt)$/.test(f)) continue; // code/text; .jsonl metadata isn't swept
      let n = 0;
      for (const m of readText(path.join(art, f)).matchAll(/https?:\/\/[^\s"'`<>()\\]{4,300}/g)) {
        if (++n > 200) break;
        add("url", m[0].replace(/[.,;]+$/, ""), `in artifact ${f}`);
      }
    }
  } catch (e) { /* no artifacts */ }
  return [...map.values()];
}

function fmt(t) { return t ? new Date(t * 1000).toISOString().slice(0, 10) : "?"; }

// Quoted CSV cell; values from hostile pages that a spreadsheet would run
// as a formula (=, +, -, @, tab, CR first) get a leading apostrophe.
const csvCell = (s) => `"${String(s ?? "").replace(/^([=+\-@\t\r])/, "'$1").replace(/"/g, '""')}"`;
const csvRows = (header, rows) => [header.join(","), ...rows.map((r) => r.map(csvCell).join(","))].join("\n") + "\n";

function toCsv(iocs) {
  return csvRows(["type", "value", "context"], iocs.map((i) => [i.type, i.value, i.context.join("; ")]));
}

module.exports = { extractIocs, toCsv, csvRows };
