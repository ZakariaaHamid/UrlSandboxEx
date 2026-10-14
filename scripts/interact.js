// interact: behave like a person on the page: mouse paths, scrolling,
// typing the configured identity into fields, clicking gate controls
// (fake CAPTCHAs, sliders, press-and-hold, wizards and more; see humanize.js).
// All page reads run in an isolated world (invisible to page hooks).

module.exports = {
  name: "interact",

  settings: {
    // passive | interactive (typing, no clicks) | interactive-clicks
    // Dwell = pause after interacting, for the page to react; waiting for
    // delayed content is the `delays` script's job (much faster).
    // credentialFlow: fill login steps (email, password, code) and submit
    // them, up to credentialSteps pages (lib/credflow.js).
    interact: { mode: "interactive-clicks", minDwellMs: 300, maxDwellMs: 800, passiveMoves: 6, credentialFlow: true, credentialSteps: 4, credentialBudgetMs: 45000, credentialSkipDomains: [] },
    // Pace and shape of movement and typing (lib/humanize.js). The
    // fingerprint profile picks its own values per installation.
    humanize: { speed: 1, curve: 0.25, mouseStepsMin: 15, mouseStepsMax: 30, mouseStepMsMin: 4, mouseStepMsMax: 18, keyMsMin: 40, keyMsMax: 220 },
    // Typed into forms. Use canary mailboxes on a domain you control;
    // kits check MX records and account existence. Empty = generated
    // values (lib/identity.js).
    identity: { emails: [], passwords: [], phones: [], names: [] },
  },

  ui: {
    "interact.mode": { options: ["passive", "interactive", "interactive-clicks"], help: "passive: mouse and scroll only; interactive: also typing; interactive-clicks: also clicks" },
    "identity.emails": { help: "typed into forms (comma-separated; one is picked per scan). Empty = generated values" },
    "interact.credentialFlow": { help: "fill and submit login steps (email, password, one-time code) to see where credentials go; submits only in interactive-clicks mode" },
    "humanize.speed": { help: "multiplies every pause: below 1 is faster, above 1 slower" },
    "humanize.curve": { help: "how far mouse paths bow sideways (0 = straight lines)" },
    "humanize.keyMsMin": { help: "shortest pause between keystrokes" },
  },

  async interact(ctx) {
    const cfg = ctx.settings.interact;
    const { page, context } = ctx;
    ctx.log.interaction = cfg.mode;
    if (ctx.navError) return;
    // A kit that already sent the browser to the real service: look, don't touch.
    const realService = ctx.require("sites.js").isRealService(page.url(), cfg.credentialSkipDomains || []);
    if (realService) ctx.log.interaction = "passive (a real service's site)";
    if (cfg.mode === "passive" || realService) {
      // light mouse/scroll activity only
      for (let i = 0; i < cfg.passiveMoves; i++) {
        await page.mouse.move(200 + Math.random() * 900, 150 + Math.random() * 500, { steps: 10 + Math.floor(Math.random() * 10) }).catch(() => {});
        await page.waitForTimeout(300 + Math.random() * 500);
      }
      await page.mouse.wheel(0, 300 + Math.random() * 300).catch(() => {});
      return;
    }
    const humanize = ctx.require("humanize.js");
    const { withIsolatedWorld } = ctx.require("isolated_eval.js");
    humanize.setIdentity(ctx.identity || ctx.settings.identity);
    humanize.setTuning(ctx.settings.humanize);
    ctx.require("sites.js").setSkipDomains(cfg.credentialSkipDomains);
    // Framework pages (React, Next.js) reset fields typed before they finish loading.
    await page.waitForLoadState("load", { timeout: 10000 }).catch(() => {});
    const clicks = cfg.mode === "interactive-clicks";
    const bounded = (p, ms) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error(`timed out after ${ms} ms`)), ms))]);

    const general = async () => {
      const limit = Math.max(cfg.minDwellMs, cfg.maxDwellMs) + 30000;
      humanize.setDeadline(Date.now() + limit);
      await bounded(withIsolatedWorld(page, context, () => humanize.humanize(page, {
        allowClicks: clicks, allowTyping: true, minDwellMs: cfg.minDwellMs, maxDwellMs: Math.max(cfg.minDwellMs, cfg.maxDwellMs),
      })), limit + 10000).catch((e) => { ctx.log.interactError = e.message; });
    };
    const credentials = async () => {
      const { credentialFlow } = ctx.require("credflow.js");
      // A CAPTCHA shown only after the form is filled (scripts/challenges.js settings).
      const ch = ctx.settings.challenges;
      const end = Date.now() + cfg.credentialBudgetMs;
      const extra = ch ? 2 * (ch.laterBudgetMs || 15000) : 0; // time a CAPTCHA mid-flow may add
      humanize.setDeadline(end + extra);
      ctx.log.credentials = await bounded(withIsolatedWorld(page, context, () => credentialFlow(page, {
        identity: ctx.identity || {}, maxSteps: cfg.credentialSteps, submit: clicks, deadline: end, skipDomains: cfg.credentialSkipDomains || [],
        solveChallenges: ch ? () => ctx.require("challenges.js").handleChallenges(page, {
          budgetMs: ch.laterBudgetMs || 15000, allowClicks: clicks,
          audio: ch.audio || ch.images ? { whisperDir: ch.audio ? ch.whisperDir : "/nonexistent", visionDir: ch.images ? ch.visionDir : null, lang: String(ctx.locale || "en").split("-")[0] } : null,
        }) : null,
      })), cfg.credentialBudgetMs + extra + 10000).catch((e) => [{ error: e.message }]);
    };
    // A login form in plain view is filled first, before general clicking
    // can submit it empty. Otherwise general interaction goes first: it
    // passes the gates (fake CAPTCHAs, press-and-hold) that hide the form.
    const formFirst = cfg.credentialFlow && await withIsolatedWorld(page, context, () => ctx.require("credflow.js").hasFields(page)).catch(() => false);
    if (formFirst) {
      await credentials();
      // The kit often hands the victim to the real service: nothing to do there.
      if (!ctx.require("sites.js").isRealService(page.url(), cfg.credentialSkipDomains || [])) await general();
    }
    else { await general(); if (cfg.credentialFlow) await credentials(); }
    humanize.setDeadline(0);
  },
};
