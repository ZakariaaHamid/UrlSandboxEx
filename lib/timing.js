// Delay-based evasion (delayed reveals, "wait for the scanner to leave").
//   waitForSettled: keep observing in real time while the page is busy
//     (DOM/URL changing, requests in flight, a "loading/verifying" text),
//     until it's been quiet for quietMs or maxMs passes.
//   fastForward: advance Chromium's virtual clock so far-future timers
//     fire now; Date, performance.now() and timers move together. Meant to
//     run last, after the page has already decided what to show.

const PLACEHOLDER = /\b(loading|please wait|redirecting|verifying|checking|one moment|just a moment|chargement|cargando|wird geladen|carregando|caricamento)\b/i;

async function snapshot(page) {
  return page.evaluate(() => {
    const t = document.body ? document.body.innerText || "" : "";
    return { sig: `${location.href}|${document.getElementsByTagName("*").length}|${t.length}|${document.title}`, text: t.slice(0, 2000) };
  }).catch(() => ({ sig: "err", text: "" }));
}

/**
 * @returns {Promise<{waitedMs: number, reason: string}>}
 */
async function waitForSettled(page, { quietMs = 4000, maxMs = 45000 } = {}) {
  const start = Date.now();
  let inflight = 0;
  const onReq = () => { inflight++; };
  const onDone = () => { inflight = Math.max(0, inflight - 1); };
  page.on("request", onReq); page.on("requestfinished", onDone); page.on("requestfailed", onDone);
  let last = await snapshot(page);
  let lastChange = Date.now();
  let reason = "quiet";
  try {
    while (Date.now() - start < maxMs) {
      await page.waitForTimeout(250);
      const s = await snapshot(page);
      if (s.sig !== last.sig) { last = s; lastChange = Date.now(); continue; }
      const busy = inflight > 0 || PLACEHOLDER.test(s.text.slice(0, 600)) || s.text.trim().length < 20;
      if (!busy && Date.now() - lastChange >= quietMs) { reason = "quiet"; break; }
      if (busy && Date.now() - lastChange >= quietMs * 4) { reason = "busy-but-static"; break; }
      reason = "max";
    }
  } finally {
    page.off("request", onReq); page.off("requestfinished", onDone); page.off("requestfailed", onDone);
  }
  return { waitedMs: Date.now() - start, reason };
}

/**
 * Advance Chromium virtual time by budgetMs (no-op on other engines).
 * @returns {Promise<{advancedMs: number, changed: boolean}|null>}
 */
async function fastForward(page, context, budgetMs = 60000) {
  let cdp;
  try { cdp = await context.newCDPSession(page); } catch (e) { return null; } // not Chromium
  const before = await snapshot(page);
  try {
    const expired = new Promise((resolve) => { cdp.once("Emulation.virtualTimeBudgetExpired", resolve); setTimeout(resolve, 15000); });
    await cdp.send("Emulation.setVirtualTimePolicy", { policy: "advance", budget: budgetMs, maxVirtualTimeTaskStarvationCount: 5000 });
    await expired;
  } catch (e) {
    await cdp.detach().catch(() => {});
    return { advancedMs: 0, changed: false, error: e.message };
  }
  // Virtual time can't be switched off again, and a free-running "advance"
  // policy fires every timer back to back (pages with retry/poll loops then
  // spin: Turnstile reloads its iframe until the browser runs out of
  // memory). Keep it moving at wall-clock pace instead: a small budget per
  // tick, for as long as the page lives.
  const TICK = 200;
  const grant = () => cdp.send("Emulation.setVirtualTimePolicy", { policy: "advance", budget: TICK }).catch(() => clearInterval(ticker));
  const ticker = setInterval(grant, TICK);
  ticker.unref?.();
  page.once("close", () => clearInterval(ticker));
  await grant();
  await page.waitForTimeout(300).catch(() => {});
  const after = await snapshot(page);
  return { advancedMs: budgetMs, changed: after.sig !== before.sig };
}

module.exports = { waitForSettled, fastForward };
