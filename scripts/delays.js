// delays: beat "wait it out" evasion without waiting it out. Watch the
// page in real time while it is visibly busy (changing, requests in
// flight, "loading…"), then advance Chromium's virtual clock so long timers
// (30-90 s reveals) fire now; Date, performance.now() and timers move
// together. If that reveals new content (a late form), interact with it
// too. Engines without virtual time (Firefox, WebKit) wait in real time.

module.exports = {
  name: "delays",

  settings: { delays: { settleMaxMs: 20000, quietMs: 1500, fastForwardMs: 90000, realWaitMs: 15000 } },

  ui: {
    "delays.settleMaxMs": { help: "longest real-time wait for the page to go quiet" },
    "delays.fastForwardMs": { help: "virtual time to skip ahead (Chromium); 0 = off" },
    "delays.realWaitMs": { help: "Firefox/WebKit: plain wait instead of fast-forward" },
  },

  async interact(ctx) {
    if (ctx.navError) return;
    const cfg = ctx.settings.delays;
    const { waitForSettled, fastForward } = ctx.require("timing.js");
    const { withIsolatedWorld } = ctx.require("isolated_eval.js");
    const iso = (fn) => withIsolatedWorld(ctx.page, ctx.context, fn);
    const settle = (maxMs) => iso(() => waitForSettled(ctx.page, { maxMs, quietMs: cfg.quietMs })).catch((e) => ({ error: e.message }));

    if (cfg.settleMaxMs > 0) ctx.log.settle = await settle(cfg.settleMaxMs);

    if (ctx.engine !== "chromium") {
      if (cfg.realWaitMs > 0) await ctx.page.waitForTimeout(cfg.realWaitMs);
      return;
    }
    if (cfg.fastForwardMs <= 0) return;
    ctx.log.fastForward = await iso(() => fastForward(ctx.page, ctx.context, cfg.fastForwardMs)).catch((e) => ({ error: e.message }));
    if (!ctx.log.fastForward?.changed) return;
    await settle(15000);
    // Content that appeared only after the delay gets the same interaction.
    const mode = ctx.settings.interact?.mode;
    if (mode && mode !== "passive") {
      const { humanize } = ctx.require("humanize.js");
      await iso(() => humanize(ctx.page, { allowClicks: mode === "interactive-clicks", allowTyping: true, minDwellMs: 300, maxDwellMs: 800 })).catch(() => {});
      ctx.log.lateInteraction = true;
      await settle(10000);
    }
  },
};
