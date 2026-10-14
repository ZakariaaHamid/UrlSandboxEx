// Page states: a screenshot each time the page changes, so the report shows
// every step a kit went through (gate, CAPTCHA, login, error, hand-off), not
// only the last one.
// The core watches the page (address, title, amount of text, fields,
// frames) from its own isolated world, invisible to the page. Scripts and
// libraries mark moments the page itself can't show, such as a CAPTCHA
// solved inside its iframe: timeline.snap(page, "reason").

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const MAX_STATES = 40;
const TICK_MS = 700;
const recorders = new WeakMap(); // Page -> recorder

// What a person would notice as "the page changed".
const SIGNATURE = `(() => {
  const b = document.body;
  const text = b ? b.innerText.length : 0;
  const fields = document.querySelectorAll("input:not([type=hidden]), textarea, select").length;
  const frames = document.querySelectorAll("iframe").length;
  const dialogs = document.querySelectorAll("dialog[open], [role=dialog], [aria-modal=true]").length;
  return [location.href, document.title, Math.round(text / 40), fields, frames, dialogs].join("|");
})()`;

function start(page, context, outDir, t0 = Date.now()) {
  const dir = path.join(outDir, "states");
  const entries = [], seen = new Map(); // image hash -> entry
  let stopped = false, busy = Promise.resolve(), last = 0, cdp = null, world = null, sig = null;

  // auto: a change the watcher noticed; a script's own label replaces it
  // when both describe the same screenshot.
  const snap = (reason, auto = false) => (busy = busy.then(async () => {
    if (stopped || entries.length >= MAX_STATES || page.isClosed()) return;
    const wait = 300 - (Date.now() - last);
    if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    const img = await page.screenshot({ timeout: 5000 }).catch(() => null);
    if (!img || blank(img)) return; // between two pages: nothing to see
    const h = crypto.createHash("sha256").update(img).digest("hex");
    if (seen.has(h)) { // nothing visible changed
      const e = seen.get(h);
      if (e.auto && !auto) Object.assign(e, { reason, auto: false });
      return;
    }
    last = Date.now();
    fs.mkdirSync(dir, { recursive: true });
    const file = `states/${String(entries.length + 1).padStart(2, "0")}.png`;
    fs.writeFileSync(path.join(outDir, file), img);
    const e = { at: Date.now() - t0, reason, url: page.url(), title: await page.title().catch(() => ""), file };
    Object.defineProperty(e, "auto", { value: auto, writable: true, enumerable: false });
    seen.set(h, e);
    entries.push(e);
  }).catch(() => {}));

  const signature = async () => {
    if (!cdp) cdp = await context.newCDPSession(page);
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        if (!world) {
          const { frameTree } = await cdp.send("Page.getFrameTree");
          world = (await cdp.send("Page.createIsolatedWorld", { frameId: frameTree.frame.id, worldName: "" })).executionContextId;
        }
        const r = await cdp.send("Runtime.evaluate", { expression: SIGNATURE, contextId: world, returnByValue: true });
        return r.result.value;
      } catch (e) { world = null; } // navigated: a new document needs a new world
    }
    return null;
  };

  const onNav = (f) => { if (f === page.mainFrame()) world = null; };
  page.on("framenavigated", onNav);
  (async () => {
    while (!stopped && !page.isClosed()) {
      await new Promise((r) => setTimeout(r, TICK_MS));
      const s = await signature().catch(() => null);
      if (!s || s === sig) continue;
      const prev = sig;
      sig = s;
      // Let it render, then check it settled.
      await new Promise((r) => setTimeout(r, 400));
      if ((await signature().catch(() => null)) !== s) continue;
      await snap(entries.length ? whatChanged(prev, s) : "loaded", true);
    }
  })();

  const rec = {
    snap,
    entries,
    async stop() {
      stopped = true;
      page.off("framenavigated", onNav);
      await busy;
      if (cdp) await cdp.detach().catch(() => {});
      return entries;
    },
  };
  recorders.set(page, rec);
  return rec;
}

// One colour from edge to edge (sampled): a page still painting.
function blank(png) {
  try {
    const { data, width, height } = require("pngjs").PNG.sync.read(png);
    const at = (x, y) => { const i = (y * width + x) * 4; return data[i] << 16 | data[i + 1] << 8 | data[i + 2]; };
    const first = at(0, 0);
    for (let y = 0; y < height; y += 7) for (let x = 0; x < width; x += 7) if (at(x, y) !== first) return false;
    return true;
  } catch (e) { return false; }
}

// The first difference a person would name.
function whatChanged(a, b) {
  const [ua, ta, xa, fa, ifa, da] = String(a || "").split("|"), [ub, tb, xb, fb, ifb, db] = b.split("|");
  if (ua !== ub) return (ua || "").split("#")[0] === ub.split("#")[0] ? "address changed" : "navigated";
  if (da !== db) return +db > +da ? "dialog opened" : "dialog closed";
  if (fa !== fb) return "form changed";
  if (ta !== tb) return "title changed";
  if (ifa !== ifb) return +ifb > +ifa ? "frame added" : "frame removed";
  return +xb > +xa ? "content added" : "content changed";
}

// For scripts and libraries: record the page now (no-op if not recording).
const snap = (page, reason) => (recorders.get(page) ? recorders.get(page).snap(reason) : Promise.resolve());

module.exports = { start, snap, whatChanged, blank, MAX_STATES };
