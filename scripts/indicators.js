// indicators: operator-specific indicators beyond what the core extracts
// (URLs, domains, IPs, hashes, TLS, credential submissions): exfil
// endpoints (Telegram bots, Discord webhooks, form/webhook services),
// e-mail and wallet addresses in page code, clipboard contents during the
// visit (ClickFix), and QR codes on the page. Contributed via ctx.ioc().

const fs = require("fs");
const path = require("path");

const RE = {
  telegramBotToken: /(?:^|[^0-9])(\d{8,10}:[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])/g, // follows "bot" directly in API URLs
  telegramChatId: /chat_id["'=:\s]+(-?\d{6,})/gi,
  email: /\b([A-Za-z0-9._%+-]{2,}@[A-Za-z0-9.-]+\.[A-Za-z]{2,24})\b/g,
  ethWallet: /\b(0x[a-fA-F0-9]{40})\b/g,
};

module.exports = {
  name: "indicators",

  // Clipboard: read the X11 CLIPBOARD outside the page (hooking
  // navigator.clipboard would be visible to it).
  async page(ctx) {
    if (ctx.isPopup || ctx.engine === "webkit") return;
    const { execFile } = require("child_process");
    // Polled often: our own interaction copies page text too, and must not
    // overwrite a page's write before it is seen.
    let last = null, busy = false;
    ctx.state.clipboard = [];
    ctx.state.clipTimer = setInterval(() => {
      if (busy) return;
      busy = true;
      execFile("xclip", ["-selection", "clipboard", "-o"], { env: ctx.env, timeout: 1500 }, (err, out) => {
        busy = false;
        if (!err && out && out !== last) { last = out; ctx.state.clipboard.push(String(out).slice(0, 5000)); }
      });
    }, 150);
  },

  on: {
    beforeCapture(ctx) { clearInterval(ctx.state.clipTimer); },

    afterCapture(ctx, result) {
      const typed = new Set(ctx.identity?.emails || []);
      // Minus what the interaction itself copied or pasted (lib/humanize.js).
      let own = new Set();
      try { own = ctx.require("humanize.js").ownClipboard(); } catch (e) { /* no interaction */ }
      for (const c of ctx.state.clipboard || []) {
        if (own.has(c.replace(/\s+/g, " ").trim())) continue;
        ctx.ioc("clipboard", c, "clipboard contents during the visit");
      }

      // Code and markup the page served or generated.
      const texts = [];
      const dir = path.join(ctx.outDir, "assets");
      for (const f of fs.readdirSync(dir)) {
        const p = path.join(dir, f);
        if (f === "traffic.har" || fs.statSync(p).size > 3e6) continue;
        const b = fs.readFileSync(p);
        if (b.subarray(0, 512).includes(0)) continue; // binary
        texts.push(b.toString("utf8"));
      }
      const art = path.join(ctx.outDir, "artifacts");
      for (const f of fs.readdirSync(art)) if (/\.(js|txt|jsonl)$/.test(f) && f !== "script-iocs.jsonl") texts.push(fs.readFileSync(path.join(art, f), "utf8"));
      if (result.dom) texts.push(fs.readFileSync(path.join(ctx.outDir, result.dom), "utf8"));
      const blob = texts.join("\n");

      const { extractExfilEndpoints } = ctx.require("exfil_patterns.js");
      let host = ""; try { host = new URL(result.finalUrl).hostname; } catch (e) { /* none */ }
      for (const n of extractExfilEndpoints(blob, host).named) ctx.ioc("url", n.value, `exfil endpoint (${n.type})`);
      for (const m of blob.matchAll(RE.telegramBotToken)) ctx.ioc("telegramBotToken", m[1], "in page code");
      for (const m of blob.matchAll(RE.telegramChatId)) ctx.ioc("telegramChatId", m[1], "in page code");
      for (const m of blob.matchAll(RE.email)) if (!typed.has(m[1]) && !/\.(png|jpe?g|gif|svg|webp|js|css)$/i.test(m[1])) ctx.ioc("email", m[1], "in page code");
      for (const m of blob.matchAll(RE.ethWallet)) ctx.ioc("wallet", m[1], "ETH-format address in page code");

      // QR codes on the page (quishing).
      const { decodeQrFromFile } = ctx.require("qr_detect.js");
      // Viewport at full resolution; below the fold, a fast half-resolution pass.
      const qrOf = (f, opts) => f && decodeQrFromFile(path.join(ctx.outDir, f), opts);
      const qrs = [qrOf(result.screenshot) || qrOf(result.screenshotFull, { halfRes: true }), ...(result.popups || []).map((p) => qrOf(p.screenshot))];
      for (const q of qrs) if (q) ctx.ioc(/^https?:\/\//i.test(q) ? "url" : "qr", q, "QR code on page");
    },
  },
};
