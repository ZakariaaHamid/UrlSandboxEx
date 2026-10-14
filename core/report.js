// Reports from a finished scan directory: self-contained HTML (offline,
// screenshot embedded, no scripts, CSP that blocks any fetch) and Markdown
// (tickets, chat), per scan and per batch, plus the batch CSV/JSON exports.
// Everything in a scan is hostile page data: escaped, URLs defanged, never
// linked.

const fs = require("fs");
const path = require("path");
const { csvRows } = require("./iocs");

const isSink = (i) => i.context.some((c) => c.startsWith("credential submission"));
// A checkpoint (result.partial) without fatalError is a scan still running;
// with one, a visit that was killed.
const errorOf = (r) => (r.partial && !r.fatalError ? "in progress" : r.partial ? "stopped, partial" : r.fatalError ? "failed" : r.navError ? "nav error" : r.timedOut ? "timed out" : null);
const defang = (u) => String(u ?? "").replace(/^http/i, "hxxp").replace(/\./g, "[.]");
const hostOf = (u) => { try { return new URL(u).hostname; } catch (e) { return ""; } };
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const md = (v) => `\`${String(v ?? "").replace(/`/g, "ˋ").replace(/\|/g, "\\|").replace(/\n/g, " ")}\``;
const mdText = (v) => String(v ?? "").replace(/([\\`*_[\]<>|#])/g, "\\$1").replace(/\n/g, " ");
// "Seen as" text, with any URL in it defanged. Scans made before the
// wording changed said "<mime> <url>" and "download <name> (downloads/...)".
const oldHashContext = (c) => {
  let m = c.match(/^(?:body|([\w.+-]+\/[\w.+-]+)(?:;\s*[^\s;]+)*) (https?:\/\/\S+)$/i);
  if (m) return `response body${m[1] ? ` (${m[1]})` : ""} of ${m[2]}`;
  m = c.match(/^download (.*?) ?\(downloads\/<sha256>\)$/);
  return m ? `downloaded file${m[1] ? ` "${m[1]}"` : ""}` : c;
};
const contextText = (i) => i.context.map((c) => (i.type === "sha256" ? oldHashContext(c) : c)).join("; ").replace(/\bhttps?:\/\/[^\s;]+/gi, (u) => defang(u));
const shown = (i) => (["url", "domain", "email"].includes(i.type) ? defang(i.value) : i.value);
const TYPE_ORDER = ["url", "domain", "ip", "email", "sha256", "telegramBotToken", "telegramChatId", "wallet", "qr"];
const byType = (iocs) => {
  const g = {};
  for (const i of iocs) (g[i.type] = g[i.type] || []).push(i);
  return Object.entries(g).sort(([a], [b]) => (TYPE_ORDER.indexOf(a) + 1 || 99) - (TYPE_ORDER.indexOf(b) + 1 || 99));
};

function loadScan(dir) {
  const result = JSON.parse(fs.readFileSync(path.join(dir, "result.json"), "utf8"));
  let iocs = [];
  try { iocs = JSON.parse(fs.readFileSync(path.join(dir, "iocs.json"), "utf8")); } catch (e) { /* none */ }
  return { id: path.basename(dir), dir, result, iocs };
}

// Key facts of one scan (terminal, tables, exports).
function summarize(s) {
  const r = s.result;
  return {
    id: s.id, url: r.url, finalUrl: r.finalUrl, title: r.title, status: r.httpStatus, error: errorOf(r),
    errorText: r.fatalError || r.navError || (r.timedOut ? "visit timed out" : null),
    iocs: s.iocs.length, sinks: s.iocs.filter(isSink).map((i) => i.value), downloads: (r.downloads || []).length,
    persona: r.persona, durationMs: r.sbx?.durationMs || 0,
  };
}

const facts = (s) => {
  const r = s.result, eg = r.sbx?.egress || {}, rq = r.sbx?.request || {};
  const ov = Object.entries(rq.overrides || {});
  return [
    ["Final URL", defang(r.finalUrl)],
    ["Title", r.title || ""],
    ["HTTP status", r.httpStatus ?? "-"],
    ["Redirects", (r.redirectChain || []).length > 1 ? `${r.redirectChain.length - 1}` : "none"],
    ["Forms", (r.structure?.forms || []).map((f) => `${(f.method || "get").toUpperCase()} ${defang(f.action)}`).join("; ") || "none"],
    ["Password fields", r.structure?.passwordFields ?? 0],
    ["Egress", `${eg.mode || "?"} ${eg.ip || ""} ${(eg.country || "").toUpperCase()} ${eg.org || ""}${eg.hosting ? " (datacenter)" : ""}`.trim()],
    ["Browser", `${r.engine || ""} ${r.browserVersion || ""} · persona ${r.persona}`],
    ["Scripts", String(r.scripts || "core").replace(/\+/g, ", ")],
    ...((r.scriptTags || []).length ? [["Tags", r.scriptTags.join(", ")]] : []),
    ["Customized", [rq.profile && `profile ${rq.profile}`, rq.country && `country ${rq.country.toUpperCase()}`, ...ov.map(([k, v]) => `${k}=${JSON.stringify(v)}`)].filter(Boolean).join("; ") || "no"],
    ["Scanned", `${s.id.slice(0, 4)}-${s.id.slice(4, 6)}-${s.id.slice(6, 8)} ${s.id.slice(9, 11)}:${s.id.slice(11, 13)} UTC · ${Math.round((r.sbx?.durationMs || 0) / 1000)} s`],
  ];
};
const site = (h) => String(h || "").split(".").slice(-2).join(".");
const COMMAND = /\b(powershell|pwsh|cmd(\.exe)?\s*\/c|mshta|rundll32|regsvr32|certutil|bitsadmin|curl\s|wget\s|iex\b|invoke-|bash\s+-c|osascript|msiexec)\b/i;

// What an analyst should look at first, worst first. tab = web report tab.
function findings(s) {
  const r = s.result, out = [];
  const add = (level, text, tab) => out.push({ level, text, tab });
  for (const f of r.scriptFindings || []) if (["bad", "warn", "info"].includes(f.level)) add(f.level, `${f.text} (${f.script})`, "overview");
  const sinks = s.iocs.filter(isSink);
  if (sinks.length) add("bad", `Credentials typed into the page were sent to ${[...new Set(sinks.map((i) => hostOf(i.value) || i.value))].map(defang).join(", ")}`, "indicators");
  for (const d of r.downloads || []) add("bad", `Delivered a file: ${d.suggestedFilename} (${d.size ?? "?"} bytes, sha256 ${d.sha256 ? d.sha256.slice(0, 16) + "…" : "not saved"})`, "artifacts");
  // Our own interaction copies selected page text and pastes short numeric
  // codes; anything else on the clipboard was put there by the page (ClickFix).
  const key = (t) => String(t).toLowerCase().replace(/&#?\w+;/g, "").replace(/[^a-z0-9]+/g, "");
  let pageText = "";
  try { pageText = key(fs.readFileSync(path.join(s.dir, r.dom || "dom.html.txt"), "utf8").replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]+>/g, " ")); } catch (x) { /* no DOM */ }
  for (const c of s.iocs.filter((i) => i.type === "clipboard")) {
    const v = String(c.value).replace(/\s+/g, " ").trim();
    if (COMMAND.test(v)) add("bad", `Clipboard holds a command (ClickFix): ${v.slice(0, 120)}`, "indicators");
    else if (v && pageText && !/^\d{4,8}$/.test(v) && !pageText.includes(key(v.slice(0, 80)))) add("warn", `The page put text on the clipboard (ClickFix?): ${v.slice(0, 120)}`, "indicators");
  }
  const exfil = s.iocs.filter((i) => i.context.some((c) => c.startsWith("exfil endpoint")) || i.type === "telegramBotToken");
  if (exfil.length) add("bad", `Exfiltration channel in page code: ${exfil.slice(0, 3).map((i) => (i.type === "url" ? defang(hostOf(i.value)) : `${i.type}`)).join(", ")}`, "indicators");
  const e = r.fatalError || r.navError;
  if (e) add("bad", `Scan error: ${String(e).split("\n")[0].slice(0, 160)}`, "log");
  if (r.timedOut) add("warn", "The visit hit its time limit; results are partial", "log");
  const qr = s.iocs.filter((i) => i.context.includes("QR code on page"));
  if (qr.length) add("warn", `QR code on the page points to ${qr.map((i) => defang(hostOf(i.value) || i.value)).join(", ")}`, "indicators");
  const st = r.structure || {};
  if (st.passwordFields) add("warn", `Password field on the page${(st.forms || []).length ? "" : " (no <form>: submitted by script)"}`, "page");
  const fsite = site(hostOf(r.finalUrl));
  for (const f of st.forms || []) if (hostOf(f.action) && site(hostOf(f.action)) !== fsite) add("warn", `Form posts to another site: ${defang(hostOf(f.action))}`, "page");
  if (fsite && site(hostOf(r.url)) !== fsite) add("info", `Redirected to another site: ${defang(hostOf(r.finalUrl))}${(r.redirectChain || []).length > 2 ? ` via ${r.redirectChain.length - 2} hop(s)` : ""}`, "overview");
  for (const c of r.log?.challenges || []) {
    if (!c.kind) continue;
    if (c.solved) { add("info", `${c.kind}: ${c.audio || "got past it"}`, "log"); continue; }
    const why = c.audio ? `${c.audio}${/withheld|refused/.test(c.audio) ? "; a residential exit (egress.residentialProxy) usually avoids this" : ""}` : "";
    add("warn", `${c.kind}: not solved${why ? `. ${why}` : ""}`, "log");
  }
  if (r.log?.fastForward?.changed) add("info", "Content appeared only after waiting (delay fast-forwarded)", "overview");
  // Device code phishing: the page shows the attacker's code and sends the
  // victim to the provider's real device login; entering it signs the
  // attacker in. Real pages of those providers are not flagged.
  const DEVICE = /login\.microsoftonline\.com\/[^/]+\/oauth2\/(v2\.0\/)?deviceauth|microsoft\.com\/devicelogin|aka\.ms\/devicelogin|google\.com\/device\b|github\.com\/login\/device/i;
  const PROVIDERS = /(^|\.)(microsoft|microsoftonline|live|office|google|github)\.com$/i;
  const deviceHit = [...(r.popups || []).map((p) => p.url), r.finalUrl, ...(r.redirectChain || []), ...(st.links || [])].find((u) => DEVICE.test(u || ""));
  if (deviceHit && !PROVIDERS.test(hostOf(r.url))) add("bad", `Device code phishing: the page sends visitors to ${defang(hostOf(deviceHit))}'s device login with a code it shows`, "overview");
  if ((r.popups || []).length) add("info", `Opened ${r.popups.length} popup(s): ${r.popups.map((p) => defang(hostOf(p.url))).join(", ")}`, "overview");
  if ((r.websocket || []).length) add("info", `${r.websocket.length} WebSocket frame(s) to ${[...new Set(r.websocket.map((w) => defang(hostOf(w.url))))].join(", ")}`, "page");
  let dyn = 0;
  try { dyn = fs.readFileSync(path.join(s.dir, "artifacts", "dynamic-code.jsonl"), "utf8").split("\n").filter(Boolean).length; } catch (x) { /* none */ }
  if (dyn) add("info", `${dyn} dynamically generated script(s) captured (eval / new Function)`, "artifacts");
  const eg = r.sbx?.egress || {};
  if (eg.requested && eg.country && eg.requested !== eg.country) add("warn", `Asked to exit in ${eg.requested.toUpperCase()} but the proxy exited in ${eg.country.toUpperCase()}; language and timezone follow ${eg.country.toUpperCase()}`, "overview");
  if (r.sbx?.egress?.hosting) add("info", "Datacenter egress: kits that check IP reputation may have shown a decoy", "overview");
  const rank = { bad: 0, warn: 1, info: 2 };
  return out.filter((f, i) => out.findIndex((g) => g.text === f.text) === i).sort((a, b) => rank[a.level] - rank[b.level]);
}
const alerts = (s) => findings(s).filter((f) => f.level !== "info").map((f) => [f.level, f.text]);
const domains = (s) => {
  const counts = {};
  try {
    const har = JSON.parse(fs.readFileSync(path.join(s.dir, s.result.har || "assets/traffic.har"), "utf8"));
    for (const e of har.log.entries) { const h = hostOf(e.request.url); if (h) counts[h] = (counts[h] || 0) + 1; }
  } catch (e) { /* no trace */ }
  return Object.entries(counts).sort((a, b) => b[1] - a[1]);
};

function scanMarkdown(s) {
  const r = s.result, out = [];
  out.push(`# UrlSandboxEx report: ${md(defang(r.url))}`, "");
  for (const [, a] of alerts(s)) out.push(`> **${mdText(a)}**`, "");
  out.push("| | |", "|---|---|", ...facts(s).map(([k, v]) => `| ${k} | ${k === "Title" ? mdText(v) : md(v)} |`), "");
  if ((r.redirectChain || []).length > 1 || r.arrivedVia) {
    out.push("## Redirect chain", "");
    if (r.arrivedVia) out.push(`0. ${md(defang(r.arrivedVia))} (stand-in referrer page)`);
    r.redirectChain.forEach((u, i) => out.push(`${i + 1}. ${md(defang(u))}`));
    out.push("");
  }
  out.push(`## Indicators (${s.iocs.length})`, "");
  for (const [t, list] of byType(s.iocs)) {
    out.push(`### ${t} (${list.length})`, "", "| Value | Seen as |", "|---|---|", ...list.map((i) => `| ${md(shown(i))} | ${mdText(contextText(i))} |`), "");
  }
  const d = domains(s);
  if (d.length) out.push("## Domains contacted", "", "| Domain | Requests |", "|---|---|", ...d.map(([h, n]) => `| ${md(defang(h))} | ${n} |`), "");
  out.push("## Files", "", `Scan directory: ${md(s.dir)}`, "", "- `screenshot.png`, `screenshot_full.png`, `assets/traffic.har`, `dom.html.txt`, `iocs.csv`, `iocs.json`, `result.json`", "");
  return out.join("\n");
}

const CSS = `body{margin:0;background:#f5f6f8;color:#16191d;font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:28px 20px 60px}h1{font-size:18px;margin:4px 0 10px;word-break:break-all}h2{font-size:15px;margin:28px 0 10px}h3{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#667085;margin:18px 0 6px}
.k{color:#667085;font-size:12px;text-transform:uppercase;letter-spacing:.06em}.card{background:#fff;border:1px solid #e4e7ec;border-radius:12px;padding:16px 18px;margin-top:14px}
.mono,code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}table{width:100%;border-collapse:collapse;font-size:13px}td,th{padding:6px 8px;border-bottom:1px solid #e4e7ec;text-align:left;vertical-align:top}th{color:#667085;font-size:11px;text-transform:uppercase}
td.v{word-break:break-all}.facts td:first-child{color:#667085;width:140px}.alert{border-radius:10px;padding:10px 14px;margin-top:10px;font-weight:600}.alert.bad{background:#fdeceb;color:#a32a20}.alert.warn{background:#fff4e0;color:#8a5200}
.shot{display:block;max-width:100%;border:1px solid #e4e7ec;border-radius:8px;margin-top:14px}.badge{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:999px;background:#f0f2f5;color:#667085;margin-right:4px}
.ok{background:#e7f6ed;color:#1a7f45}.bad{background:#fdeceb;color:#c0362c}.warn{background:#fff4e0;color:#9a5b00}a{color:#3b5bdb}footer{margin-top:30px;color:#98a2b3;font-size:12px}`;
const htmlDoc = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; img-src data:; style-src 'unsafe-inline'">
<meta name="referrer" content="no-referrer"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${esc(title)}</title><style>${CSS}</style></head>
<body><main>${body}<footer>Generated by UrlSandboxEx on ${new Date().toISOString().replace("T", " ").slice(0, 16)} UTC. URLs are defanged; nothing in this file loads anything.</footer></main></body></html>`;

function scanHtml(s) {
  const r = s.result;
  let shot = "";
  try { if (r.screenshot) shot = `<img class="shot" alt="Screenshot of the page" src="data:image/png;base64,${fs.readFileSync(path.join(s.dir, r.screenshot)).toString("base64")}">`; } catch (e) { /* none */ }
  const status = errorOf(r) ? `<span class="badge bad">${esc(errorOf(r))}</span>` : `<span class="badge ${r.httpStatus >= 400 ? "warn" : "ok"}">HTTP ${esc(r.httpStatus ?? "-")}</span>`;
  const d = domains(s);
  return htmlDoc(`UrlSandboxEx report: ${defang(r.url)}`, `
<div class="k">UrlSandboxEx scan report</div><h1 class="mono">${esc(defang(r.url))}</h1>
<div>${status}<span class="badge">${esc(r.persona)}</span><span class="badge">${esc((r.sbx?.egress?.country || "?").toUpperCase())}</span><span class="badge">${s.iocs.length} indicators</span></div>
${alerts(s).map(([k, a]) => `<div class="alert ${k}">${esc(a)}</div>`).join("")}
${shot}
<div class="card"><table class="facts">${facts(s).map(([k, v]) => `<tr><td>${esc(k)}</td><td class="v${k === "Title" ? "" : " mono"}">${esc(v)}</td></tr>`).join("")}</table></div>
${(r.redirectChain || []).length > 1 || r.arrivedVia ? `<h2>Redirect chain</h2><div class="card"><ol class="mono">${r.arrivedVia ? `<li>${esc(defang(r.arrivedVia))} (stand-in referrer page)</li>` : ""}${r.redirectChain.map((u) => `<li>${esc(defang(u))}</li>`).join("")}</ol></div>` : ""}
<h2>Indicators (${s.iocs.length})</h2>
${byType(s.iocs).map(([t, list]) => `<h3>${esc(t)} (${list.length})</h3><div class="card"><table><tr><th>Value</th><th>Seen as</th></tr>${list.map((i) => `<tr${isSink(i) ? ' class="bad"' : ""}><td class="v mono">${esc(shown(i))}</td><td>${esc(contextText(i))}</td></tr>`).join("")}</table></div>`).join("")}
${d.length ? `<h2>Domains contacted</h2><div class="card"><table><tr><th>Domain</th><th>Requests</th></tr>${d.map(([h, n]) => `<tr><td class="mono">${esc(defang(h))}</td><td>${n}</td></tr>`).join("")}</table></div>` : ""}
<h2>Files</h2><div class="card mono">${esc(s.dir)}<br>screenshot.png · screenshot_full.png · assets/traffic.har · dom.html.txt · iocs.csv · iocs.json · result.json</div>`);
}

// Writes report.html and report.md into the scan directory.
function writeScanReports(dir) {
  const s = loadScan(dir);
  fs.writeFileSync(path.join(dir, "report.html"), scanHtml(s));
  fs.writeFileSync(path.join(dir, "report.md"), scanMarkdown(s));
  return { html: path.join(dir, "report.html"), md: path.join(dir, "report.md") };
}

// ------------------------------------------------------------- batches --
// entries: [{ url, state, error, scan: loadScan() result or null }]
const summaryCsv = (entries) => csvRows(["url", "state", "scan_id", "final_url", "http_status", "title", "error", "credentials_sent_to", "downloads", "iocs"],
  entries.map(({ url, state, error, scan: s }) => [url, state, s?.id || "", s?.result.finalUrl || "", s?.result.httpStatus ?? "", s?.result.title || "", error || (s && errorOf(s.result)) || "",
    s ? s.iocs.filter(isSink).map((i) => i.value).join(" ") : "", s ? (s.result.downloads || []).length : "", s ? s.iocs.length : ""]));
const iocsCsv = (entries) => csvRows(["scan_id", "url", "type", "value", "context"],
  entries.flatMap(({ url, scan: s }) => (s ? s.iocs.map((i) => [s.id, url, i.type, i.value, i.context.join("; ")]) : [])));
const iocsJson = (entries) => JSON.stringify(entries.filter((e) => e.scan).map(({ url, scan: s }) => ({ scanId: s.id, url, finalUrl: s.result.finalUrl, iocs: s.iocs })), null, 2);

// linkFor(scan) -> relative path of that scan's report.html, or null.
function batchHtml(b, entries, linkFor = () => null) {
  const n = (st) => entries.filter((e) => e.state === st).length;
  const sinkSites = entries.filter((e) => e.scan && e.scan.iocs.some(isSink)).length;
  return htmlDoc(`UrlSandboxEx batch: ${b.name}`, `
<div class="k">UrlSandboxEx batch report</div><h1>${esc(b.name)}</h1>
<div><span class="badge">${entries.length} URLs</span><span class="badge ok">${n("done")} done</span>${n("failed") ? `<span class="badge bad">${n("failed")} failed</span>` : ""}${n("cancelled") ? `<span class="badge">${n("cancelled")} cancelled</span>` : ""}${sinkSites ? `<span class="badge bad">credentials sent on ${sinkSites} site(s)</span>` : ""}</div>
<div class="card"><table><tr><th>#</th><th>URL</th><th>Result</th><th>Final host</th><th>Credentials sent to</th><th>IOCs</th><th></th></tr>
${entries.map((e, i) => { const s = e.scan, sm = s && summarize(s), link = s && linkFor(s); return `<tr><td>${i + 1}</td><td class="v mono">${esc(defang(e.url))}</td>
<td>${sm ? (sm.error ? `<span class="badge bad">${esc(sm.error)}</span>` : `<span class="badge ${sm.status >= 400 ? "warn" : "ok"}">${esc(sm.status ?? "-")}</span>`) : `<span class="badge">${esc(e.state)}</span>${e.error ? ` ${esc(e.error)}` : ""}`}</td>
<td class="mono">${sm ? esc(defang(hostOf(sm.finalUrl))) : ""}</td><td class="v mono">${sm ? esc(sm.sinks.map(defang).join(", ")) : ""}</td><td>${sm ? sm.iocs : ""}</td><td>${link ? `<a href="${esc(link)}">report</a>` : ""}</td></tr>`; }).join("")}</table></div>`);
}
function batchMarkdown(b, entries) {
  const out = [`# UrlSandboxEx batch: ${mdText(b.name)}`, "", "| # | URL | Result | Final host | Credentials sent to | IOCs | Scan |", "|---|---|---|---|---|---|---|"];
  entries.forEach((e, i) => {
    const sm = e.scan && summarize(e.scan);
    out.push(`| ${i + 1} | ${md(defang(e.url))} | ${sm ? (sm.error || sm.status) : e.state} | ${sm ? md(defang(hostOf(sm.finalUrl))) : ""} | ${sm && sm.sinks.length ? md(sm.sinks.map(defang).join(", ")) : ""} | ${sm ? sm.iocs : ""} | ${sm ? md(sm.id) : ""} |`);
  });
  return out.join("\n") + "\n";
}

// Writes a batch's reports and exports into outDir; with copyScans, each
// scan's report.html is copied under scans/ so the folder is self-contained.
function writeBatchReports(b, entries, outDir, { copyScans = false } = {}) {
  fs.mkdirSync(outDir, { recursive: true });
  let linkFor = (s) => path.relative(outDir, path.join(s.dir, "report.html"));
  if (copyScans) {
    fs.mkdirSync(path.join(outDir, "scans"), { recursive: true });
    for (const { scan: s } of entries) if (s) { try { fs.copyFileSync(path.join(s.dir, "report.html"), path.join(outDir, "scans", `${s.id}.html`)); } catch (e) { /* no report */ } }
    linkFor = (s) => `scans/${s.id}.html`;
  }
  const files = { "index.html": batchHtml(b, entries, linkFor), "report.md": batchMarkdown(b, entries), "summary.csv": summaryCsv(entries), "iocs.csv": iocsCsv(entries), "iocs.json": iocsJson(entries) };
  for (const [f, body] of Object.entries(files)) fs.writeFileSync(path.join(outDir, f), body);
  return path.join(outDir, "index.html");
}

module.exports = { findings, loadScan, summarize, isSink, errorOf, defang, hostOf, scanHtml, scanMarkdown, writeScanReports, summaryCsv, iocsCsv, iocsJson, batchHtml, batchMarkdown, writeBatchReports, contextText };
