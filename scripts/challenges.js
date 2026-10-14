// challenges: get through what stands in front of the payload:
// Cloudflare interstitial / Turnstile, reCAPTCHA v2 and hCaptcha
// checkboxes (human-path mouse click, trusted events), reCAPTCHA image
// puzzles (object recognition, or their audio version, both on this server),
// and Chrome's own
// permission prompts (geolocation, clipboard, notifications: a real X11
// click on "Allow"). Runs before `interact` (first pass) and again right
// before capture (widgets that appear only after interaction).

// The clip is spoken in the browser's language.
const audioOpts = (ctx) => {
  const c = ctx.settings.challenges;
  if (!c.audio && !c.images) return null;
  return { whisperDir: c.audio ? c.whisperDir : "/nonexistent", visionDir: c.images ? c.visionDir : null, lang: String(ctx.locale || "en").split("-")[0] };
};

module.exports = {
  name: "challenges",

  settings: { challenges: { budgetMs: 30000, laterBudgetMs: 15000, permissionPrompts: true, audio: true, whisperDir: "/usr/local/lib/sbx/whisper", images: true, visionDir: "/usr/local/lib/sbx/vision" } },
  ui: {
    "challenges.images": { help: "solve reCAPTCHA image puzzles with object recognition on this server (YOLOX, CLIP)" },
    "challenges.audio": { help: "if the image puzzle fails, solve its audio version, transcribed on this server (whisper.cpp)" },
  },

  async interact(ctx) {
    const cfg = ctx.settings.challenges;
    const passive = ctx.settings.interact?.mode === "passive";
    if (cfg.permissionPrompts && !passive && ctx.engine === "chromium") {
      ctx.state.promptWatcher = ctx.require("prompts.js").watchPermissionPrompts(ctx.env);
    }
    if (ctx.navError) return;
    const { withIsolatedWorld } = ctx.require("isolated_eval.js");
    const { handleChallenges } = ctx.require("challenges.js");
    ctx.log.challenges = await withIsolatedWorld(ctx.page, ctx.context, () => handleChallenges(ctx.page, { budgetMs: cfg.budgetMs, allowClicks: !passive, audio: audioOpts(ctx) })).catch((e) => [{ kind: "error", note: e.message }]);
  },

  on: {
    async beforeCapture(ctx) {
      const cfg = ctx.settings.challenges;
      if (!ctx.navError) {
        const { withIsolatedWorld } = ctx.require("isolated_eval.js");
        const { handleChallenges } = ctx.require("challenges.js");
        const later = await withIsolatedWorld(ctx.page, ctx.context, () => handleChallenges(ctx.page, { budgetMs: cfg.laterBudgetMs, allowClicks: ctx.settings.interact?.mode !== "passive", audio: audioOpts(ctx) })).catch(() => []);
        ctx.log.challenges = [...(ctx.log.challenges || []), ...later.filter((c) => c.kind !== "cloudflare-interstitial")];
      }
      if (ctx.state.promptWatcher) ctx.log.permissionPrompts = await ctx.state.promptWatcher.stop();
    },
  },
};
