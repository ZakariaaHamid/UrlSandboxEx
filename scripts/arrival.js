// arrival: reach the URL the way a victim does: by clicking a link on
// the page they came from, instead of a direct navigation. A stand-in page
// is served at the referring URL from a route (Chrome may still preconnect
// to that origin, as for any navigation, but fetches nothing from it), and a
// real mouse click on a link to the target navigates the tab. The
// target then sees what a click produces: Referer / document.referrer set
// by the browser per the referrer policy, Sec-Fetch-Site: cross-site, a
// user-activated navigation, history.length 2.
//
// settings.arrival.from: a preset name below or any URL; null = direct.
// Presets are starting points: adjust the URL/policy to what the targeted
// campaign's delivery channel actually sends.

const PRESETS = {
  gmail: { url: "https://mail.google.com/mail/u/0/", policy: "origin" },
  outlook: { url: "https://outlook.live.com/mail/0/", policy: "origin" },
  office365: { url: "https://outlook.office.com/mail/", policy: "origin" },
  google: { url: "https://www.google.com/search?q=account+login", policy: "origin" },
  bing: { url: "https://www.bing.com/search?q=account+login", policy: "origin-when-cross-origin" },
  linkedin: { url: "https://www.linkedin.com/feed/", policy: "origin" },
  sharepoint: { url: "https://contoso.sharepoint.com/:b:/s/Finance/shared", policy: "strict-origin-when-cross-origin" },
  teams: { url: "https://teams.microsoft.com/", policy: "strict-origin-when-cross-origin" },
};

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

module.exports = {
  name: "arrival",

  settings: { arrival: { from: null } },

  ui: { "arrival.from": { suggestions: Object.keys(PRESETS), help: "a preset (gmail, outlook, ...) or any referring URL; empty = direct" } },

  async navigate(ctx) {
    const from = ctx.settings.arrival.from;
    if (!from) return null;
    const ref = PRESETS[from] || { url: from, policy: "strict-origin-when-cross-origin" };
    const { page } = ctx;
    // Inline empty icon: otherwise Chrome fetches the real site's favicon.
    const stub = `<!doctype html><meta charset="utf-8"><meta name="referrer" content="${esc(ref.policy)}"><link rel="icon" href="data:,"><title>Inbox</title>
      <body style="font:15px sans-serif;margin:40px"><p>Please review the document below.</p>
      <p><a id="sbx-link" href="${esc(ctx.url)}">${esc(ctx.url)}</a></p></body>`;
    await page.route(ref.url, (r) => r.fulfill({ contentType: "text/html", body: stub }));
    await page.goto(ref.url, { waitUntil: "domcontentloaded" });
    await page.unroute(ref.url);

    const box = await page.locator("#sbx-link").boundingBox();
    const x = box.x + Math.min(box.width - 4, 10 + Math.random() * Math.min(120, box.width / 2));
    const y = box.y + box.height / 2;
    const { moveMouseHumanlike } = ctx.require("humanize.js");
    await moveMouseHumanlike(page, 100 + Math.random() * 200, 80 + Math.random() * 60, x, y).catch(() => {});
    await page.waitForTimeout(300 + Math.random() * 500);
    const [response] = await Promise.all([
      page.waitForNavigation({ waitUntil: "domcontentloaded", timeout: ctx.settings.scan?.navTimeoutMs || 30000 }),
      page.mouse.click(x, y, { delay: 60 + Math.random() * 80 }),
    ]);
    ctx.log.arrival = { from: ref.url, policy: ref.policy };
    return { response, via: ref.url };
  },

  PRESETS,
};
