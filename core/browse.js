// Core visit: start a display, launch the browser the scripts describe,
// open the URL, let the scripts act, capture. Runs inside the jail.
//
// Captured (always): traffic.har (headers + bodies), every response body
// under assets/ (by sha256), downloads under downloads/ (by sha256, no
// extension), redirect chain, WebSocket frames, console, cookies, storage,
// TLS certificate, screenshots, rendered DOM (as .txt), popups.
//
// Events dispatched to scripts' `on` handlers: request, response,
// requestfailed, console, dialog, download, popup, websocket,
// framenavigated, worker, pageerror, load (Playwright objects), and the
// lifecycle events beforeNavigate, afterNavigate, beforeCapture,
// afterCapture (payload: the result object so far).

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawn } = require("child_process");
const playwright = require("playwright");
const { watchChildren, installResumeGate } = require("../lib/targets");
const { sandboxRequire } = require("./scripts");

// A step that must not hold up the visit (closing a browser that hangs).
const within = (p, ms) => Promise.race([Promise.resolve(p).catch(() => {}), new Promise((r) => setTimeout(r, ms))]);
const sha256 = (b) => crypto.createHash("sha256").update(b).digest("hex");
const MAX_BODY = 15 * 1024 * 1024, MAX_TOTAL = 80 * 1024 * 1024;
const FULL_MAX_H = 16000; // px, full-page screenshot height cap
// Popups kept open. Later ones are recorded (URL, title, screenshot) and
// closed: same-site tabs share one renderer, so a page that opens many
// (by design or through our clicks) would exhaust the jail's memory.
const MAX_OPEN_POPUPS = 2;

async function waitFor(cond, timeoutMs, stepMs = 20) {
  for (const end = Date.now() + timeoutMs; Date.now() < end; await new Promise((r) => setTimeout(r, stepMs))) if (cond()) return true;
  return false;
}

async function startDisplay(d) {
  const display = `:${100 + Math.floor(Math.random() * 800)}`;
  // -nolisten local: no abstract socket; inside the jail /tmp is private,
  // so the display is unreachable from outside.
  const x = spawn("Xvfb", [display, "-screen", "0", `${d.width}x${d.height}x${d.depth || 24}`, "-nolisten", "tcp", "-nolisten", "local"], { stdio: "ignore" });
  await new Promise((res, rej) => { x.once("spawn", res); x.once("error", rej); });
  await waitFor(() => fs.existsSync(`/tmp/.X11-unix/X${display.slice(1)}`), 5000);
  const procs = [x];
  if (d.windowManager) {
    const rc = path.join(os.tmpdir(), `openbox-${display.slice(1)}.xml`);
    fs.writeFileSync(rc, `<?xml version="1.0"?><openbox_config xmlns="http://openbox.org/3.4/rc"><margins><top>${d.panelTop || 0}</top><bottom>0</bottom><left>0</left><right>0</right></margins><focus><focusNew>yes</focusNew></focus><desktops><number>1</number></desktops></openbox_config>`);
    const wm = spawn("openbox", ["--config-file", rc], { env: { ...process.env, DISPLAY: display }, stdio: "ignore" });
    wm.on("error", () => {});
    procs.push(wm); // ready well before the browser window appears
  }
  return { display, stop: () => procs.reverse().forEach((p) => { try { p.kill("SIGKILL"); } catch (e) { /* gone */ } }) };
}

/**
 * @param {object} job  { url, persona, geo, referer, hardCeilingMs }
 * @param {object} S    composed scripts (core/scripts.js compose())
 * @param {object} o    { outDir, proxy, identity }; identity: values typed into forms
 */
async function browse(job, S, { outDir, proxy, identity = null }) {
  const persona = S.personas[job.persona] || S.personas.default;
  const engine = persona.engine || "chromium";
  const artifactsDir = path.join(outDir, "artifacts");
  const assetsDir = path.join(outDir, "assets");
  fs.mkdirSync(artifactsDir, { recursive: true });
  fs.mkdirSync(assetsDir, { recursive: true });

  let artifactBytes = 0;
  const log = {};
  const ctx = {
    url: job.url, settings: S.settings, persona, engine, proxy, outDir, log, state: {}, identity,
    locale: (persona.locale && persona.locale !== "auto" && persona.locale) || job.geo?.locale || "en-US",
    timezoneId: (persona.timezoneId && persona.timezoneId !== "auto" && persona.timezoneId) || job.geo?.timezoneId || null,
    jailed: process.env.SBX_JAILED === "1",
    playwright, require: sandboxRequire, sha256,
    dump(name, data, { append = false } = {}) {
      const buf = Buffer.isBuffer(data) ? data : Buffer.from(typeof data === "string" ? data : JSON.stringify(data, null, 2));
      if (artifactBytes + buf.length > MAX_TOTAL) return null;
      const p = path.join(artifactsDir, String(name).replace(/[^a-zA-Z0-9._-]+/g, "_").slice(0, 120));
      (append ? fs.appendFileSync : fs.writeFileSync)(p, buf);
      artifactBytes += buf.length;
      return path.relative(outDir, p);
    },
    ioc(type, value, context = "") {
      if (value === undefined || value === null || value === "") return;
      fs.appendFileSync(path.join(artifactsDir, "script-iocs.jsonl"), JSON.stringify({ type, value: String(value), context }) + "\n");
    },
  };
  const pending = new Set();
  // Event handlers run concurrently with the visit; each gets HOOK_MS so a
  // stuck hook can't stall capture (flush waits on them).
  const HOOK_MS = 30000;
  const emit = (ev, c, payload) => {
    for (const { fn, script } of S.events[ev] || []) {
      let timer;
      const limit = new Promise((_, rej) => { timer = setTimeout(() => rej(new Error(`timed out after ${HOOK_MS / 1000}s`)), HOOK_MS); });
      const p = Promise.race([Promise.resolve().then(() => fn(c, payload)), limit]).catch((e) => { log[`${script}.${ev}.error`] = e.message; }).finally(() => clearTimeout(timer));
      pending.add(p); p.finally(() => pending.delete(p));
    }
  };
  // Waits for hooks and body captures, but never longer than maxMs: a page
  // that keeps reloading iframes (Turnstile does) must not stall capture.
  const flush = async (maxMs = 20000) => {
    const end = Date.now() + maxMs;
    while (pending.size && Date.now() < end) {
      await Promise.race([Promise.allSettled([...pending]), new Promise((r) => setTimeout(r, Math.max(0, end - Date.now())))]);
    }
  };

  // Save what is known so far, with a screenshot, so a visit killed later
  // (out of memory, time limit) still leaves a partial result. The final
  // write replaces it.
  const checkpoint = async (p) => {
    await p.screenshot({ path: path.join(outDir, "screenshot.png"), timeout: 5000 }).then(() => { result.screenshot = "screenshot.png"; }).catch(() => {});
    result.finalUrl = p.url();
    result.title = await p.title().catch(() => result.title || null);
    try { fs.writeFileSync(path.join(outDir, "result.json"), JSON.stringify({ ...result, partial: true, log, timings })); } catch (e) { /* best effort */ }
  };

  // Per-phase durations (ms), saved as result.timings.
  const timings = {};
  let mark = Date.now();
  const lap = (name) => { const now = Date.now(); timings[name] = now - mark; mark = now; };
  const disp = await startDisplay(S.display);
  lap("display");
  ctx.env = { ...process.env, DISPLAY: disp.display };
  const services = await S.services(ctx).catch(() => []);
  lap("services");
  const profileDir = fs.mkdtempSync(path.join(outDir, ".profile-"));
  let context;
  const result = { url: job.url, engine, persona: job.persona, scripts: S.name };

  const work = (async () => {
    const launchOpts = await S.launch(ctx);
    const contextOpts = await S.contextOptions(ctx);
    if (engine === "chromium" && !installResumeGate()) log.resumeGate = "unavailable: child-target setup may race the target's first script";
    const launch = () => playwright[engine].launchPersistentContext(profileDir, {
      ...launchOpts, ...contextOpts, ...(proxy ? { proxy } : {}),
      acceptDownloads: true,
      recordHar: { path: path.join(assetsDir, "traffic.har"), content: "embed" },
    });
    // One retry: a browser can occasionally die during startup.
    context = await launch().catch(async (e) => { log.launchRetry = String(e.message || e).split("\n")[0]; return launch(); });
    const page = context.pages()[0] || await context.newPage();
    ctx.context = context;
    // DevTools sessions. Chrome takes some overrides (navigator.platform)
    // from the most recently attached session only, so every session a
    // script or helper opens first gets what ctx.onSession registered.
    const sessionSetup = [];
    ctx.onSession = (fn) => { sessionSetup.push(fn); };
    if (engine === "chromium") {
      const open = context.newCDPSession.bind(context);
      context.newCDPSession = async (target) => {
        const s = await open(target);
        for (const fn of sessionSetup) await Promise.resolve().then(() => fn(s, target)).catch((e) => { log.sessionSetupError = e.message; });
        return s;
      };
    }
    // Cross-site iframes and Workers (lib/targets.js), one watcher per page.
    const watchers = new Map();
    ctx.childTargets = async (p, handler) => {
      if (engine !== "chromium") return false;
      if (!watchers.has(p)) watchers.set(p, context.newCDPSession(p).then((s) => watchChildren(s, (e, t) => { log.childTargetErrors = [...(log.childTargetErrors || []), `${t.type}: ${e.message}`].slice(-20); })));
      (await watchers.get(p)).add(handler);
      return true;
    };
    ctx.version = engine === "chromium"
      ? (((await (await context.newCDPSession(page)).send("Browser.getVersion").catch(() => ({}))).product || "").split("/")[1] || "")
      : await page.evaluate(() => navigator.userAgent).catch(() => "");
    result.browserVersion = ctx.version;
    lap("launch");
    await S.ready(ctx);

    // --- core capture ----------------------------------------------------
    let total = 0;
    const websocket = [], consoleLog = [], downloads = [], popups = [];
    const attach = (p, isPopup) => {
      const c = { ...ctx, page: p, isPopup };
      for (const ev of ["request", "response", "requestfailed", "console", "dialog", "download", "popup", "websocket", "framenavigated", "worker", "pageerror", "load"]) {
        if (S.events[ev]) p.on(ev, (x) => emit(ev, c, x));
      }
      p.on("response", (r) => {
        const t = (async () => {
          // body() never settles for some responses (a frame replaced while loading).
          const body = await Promise.race([r.body().catch(() => null), new Promise((res) => setTimeout(() => res(null), 10000))]);
          if (!body || !body.length || body.length > MAX_BODY || total > MAX_TOTAL) return;
          total += body.length;
          fs.writeFileSync(path.join(assetsDir, sha256(body)), body);
        })();
        pending.add(t); t.finally(() => pending.delete(t));
      });
      p.on("websocket", (ws) => {
        ws.on("framesent", (f) => websocket.push({ url: ws.url(), dir: "sent", payload: String(f.payload).slice(0, 4000) }));
        ws.on("framereceived", (f) => websocket.push({ url: ws.url(), dir: "received", payload: String(f.payload).slice(0, 4000) }));
      });
      p.on("console", (m) => { try { consoleLog.push({ type: m.type(), text: m.text().slice(0, 2000) }); } catch (e) { /* closed */ } });
      // A person clicks OK on alert/confirm (fake-CAPTCHA kits rely on it)
      // but stays on the page when asked "leave site?".
      p.on("dialog", (d) => (d.type() === "beforeunload" ? d.dismiss() : d.accept()).catch(() => {}));
      p.on("download", async (d) => {
        const tmp = await d.path().catch(() => null);
        const entry = { url: d.url(), suggestedFilename: d.suggestedFilename() };
        if (tmp) {
          const buf = fs.readFileSync(tmp);
          entry.sha256 = sha256(buf); entry.size = buf.length;
          fs.mkdirSync(path.join(outDir, "downloads"), { recursive: true });
          fs.writeFileSync(path.join(outDir, "downloads", entry.sha256), buf); // no extension: never executable by accident
        }
        downloads.push(entry);
        await d.delete().catch(() => {});
      });
      return c;
    };
    const mainCtx = attach(page, false);
    const record = async (e) => {
      const n = popups.indexOf(e) + 1;
      e.url = e.p.url();
      e.title = await e.p.title().catch(() => null);
      await e.p.screenshot({ path: path.join(outDir, `popup_${n}.png`), timeout: 8000 }).then(() => { e.screenshot = `popup_${n}.png`; }).catch(() => {});
    };
    context.on("page", (p) => {
      if (p === page) return;
      const c = attach(p, true);
      const e = { p };
      popups.push(e);
      Promise.resolve(S.page(c)).catch(() => {});
      if (popups.filter((x) => !x.closed).length <= MAX_OPEN_POPUPS) return;
      e.closed = true;
      e.task = p.waitForLoadState("load", { timeout: 8000 }).catch(() => {}).then(() => record(e)).then(() => p.close()).catch(() => {});
    });
    await S.page(mainCtx);
    // A screenshot each time the page changes (states/NN.png).
    const states = sandboxRequire("timeline.js").start(page, context, outDir);
    result.timeline = states.entries;

    // --- navigate ----------------------------------------------------------
    lap("ready+page");
    emit("beforeNavigate", mainCtx, { url: job.url });
    let resp = null;
    try {
      const nav = await S.navigate(mainCtx);
      if (nav) { resp = nav.response; result.arrivedVia = nav.via || null; }
      else resp = await page.goto(job.url, { waitUntil: "domcontentloaded", timeout: S.scan.navTimeoutMs, ...(job.referer ? { referer: job.referer } : {}) });
    } catch (e) { result.navError = String(e.message || e).split("\n")[0]; }
    result.httpStatus = resp ? resp.status() : null;
    if (resp) {
      const hops = []; let r = resp.request();
      while (r) { hops.unshift(r.url()); r = r.redirectedFrom(); }
      result.redirectChain = hops;
      result.tls = await resp.securityDetails().catch(() => null);
      result.server = await resp.serverAddr().catch(() => null);
      result.mainHeaders = await resp.allHeaders().catch(() => null);
    }
    lap("navigate");
    emit("afterNavigate", mainCtx, result);
    await checkpoint(page);

    // --- scripts act -------------------------------------------------------
    mainCtx.navError = result.navError || null;
    if (S.hasInteract) await S.interact(mainCtx);
    else await page.waitForTimeout(S.scan.settleMs);

    // --- capture -------------------------------------------------------------
    lap("interact");
    await checkpoint(page);
    emit("beforeCapture", mainCtx, result);
    await flush();
    // After beforeCapture: a CAPTCHA solved there is a state too.
    await within(states.stop(), 8000);
    const iso = (fn) => sandboxRequire("isolated_eval.js").withIsolatedWorld(page, context, fn);
    result.finalUrl = page.url();
    result.title = await page.title().catch(() => null);
    await page.screenshot({ path: path.join(outDir, "screenshot.png"), timeout: 10000 }).then(() => { result.screenshot = "screenshot.png"; }).catch(() => {});
    // Full page at CSS pixels, at most the viewport's width and FULL_MAX_H
    // tall: a huge page (accidental or meant to kill scanners) at a phone's
    // pixel ratio would otherwise exhaust the GPU process's memory.
    const dims = await iso(() => page.evaluate(() => ({ w: innerWidth, h: Math.max(document.documentElement.scrollHeight, document.body ? document.body.scrollHeight : 0) }))).catch(() => null);
    const clip = dims && dims.w > 0 && dims.h > 0 ? { x: 0, y: 0, width: dims.w, height: Math.min(dims.h, FULL_MAX_H) } : null;
    if (clip && dims.h > FULL_MAX_H) result.screenshotFullClipped = true;
    await page.screenshot({ path: path.join(outDir, "screenshot_full.png"), fullPage: true, scale: "css", timeout: 15000, ...(clip ? { clip } : {}) }).then(() => { result.screenshotFull = "screenshot_full.png"; }).catch(() => {});
    const html = await page.content().catch(() => null);
    if (html) { fs.writeFileSync(path.join(outDir, "dom.html.txt"), html); result.dom = "dom.html.txt"; }
    result.structure = await iso(() => page.evaluate(() => ({
      forms: Array.from(document.forms).map((f) => ({ action: f.action, method: f.method })),
      passwordFields: document.querySelectorAll('input[type="password"]').length,
      links: Array.from(document.links).slice(0, 300).map((a) => a.href),
      storage: { local: { ...localStorage }, session: { ...sessionStorage } },
    }))).catch(() => null);
    result.popups = [];
    for (const e of popups) {
      await (e.closed ? within(e.task, 10000) : record(e));
      result.popups.push({ url: e.url, title: e.title, ...(e.screenshot ? { screenshot: e.screenshot } : {}) });
    }
    result.cookies = await context.cookies().catch(() => []);
    Object.assign(result, { websocket, console: consoleLog.slice(0, 500), downloads, har: "assets/traffic.har" });
    await flush(10000);
    await within(context.close(), 20000); // flushes the HAR
    lap("capture");
    emit("afterCapture", { ...ctx, page: null }, result);
    await flush();
    lap("afterCapture");
    result.log = log;
    result.timings = timings;
    return result;
  })();

  try {
    return await Promise.race([work, new Promise((r) => setTimeout(() => r({ ...result, timedOut: true, log }), job.hardCeilingMs || 200000))]);
  } finally {
    // Bounded, and never throwing: the result must survive a browser that
    // hangs or keeps writing to its profile.
    if (context) await within(context.close(), 8000);
    for (const p of services) { try { p.kill("SIGKILL"); } catch (e) { /* gone */ } }
    disp.stop();
    try { fs.rmSync(profileDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 200 }); } catch (e) { /* removed with the visit directory's tmp */ }
  }
}

module.exports = { browse };
