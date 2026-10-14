// URL extraction for scan input (CLI and web UI): URLs in any text (lists,
// CSV/TSV columns, e-mail bodies), defanged (hxxp, [.]), bare domains.
// Deduplicated, in order; tokens that aren't URLs come back in `bad`.

const MAX_BATCH = 1000;

function parseUrls(text) {
  const out = new Set(), bad = [];
  for (const orig of String(text || "").split(/[\s,;|]+/).filter(Boolean)) {
    let s = orig.replace(/^[<"'(\[]+|[>"')\];.]+$/g, "").replace(/^hxxp/i, "http").replace(/^fxp/i, "ftp")
      .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, ".").replace(/\[:\]/g, ":").replace(/\[\/\]/g, "/");
    if (!s) continue;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
      // bare: a real-looking host (letters in the TLD, or a dotted quad), not "3.5" or "2026-10-01"
      const host = s.split(/[/?#:]/)[0];
      if (!/^([a-z0-9-]+\.)+[a-z][a-z0-9-]+$/i.test(host) && !/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) { bad.push(orig); continue; }
      s = `https://${s}`;
    }
    try {
      const u = new URL(s);
      if (!/^https?:$/.test(u.protocol) || !u.hostname.includes(".") && u.hostname !== "localhost") throw new Error();
      out.add(u.toString());
    } catch (e) { bad.push(orig); }
  }
  return { urls: [...out], bad };
}

module.exports = { parseUrls, MAX_BATCH };
