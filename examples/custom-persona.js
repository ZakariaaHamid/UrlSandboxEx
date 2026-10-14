// Example script: add a persona, tweak launch, add an interaction step.
// Use: urlsandboxex --script=examples/custom-persona.js --persona=de-android <url>
// (appended after the default scripts, so its hooks run last and win).

module.exports = {
  name: "custom-persona",

  personas: {
    // A German Android victim arriving from a webmail.
    "de-android": {
      engine: "chromium", device: "Pixel 7", locale: "de-DE", timezoneId: "Europe/Berlin",
      userAgent: (major) => `Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Mobile Safari/537.36`,
      clientHints: { platform: "Android", platformVersion: "14.0.0", architecture: "", model: "Pixel 7", mobile: true, bitness: "64", wow64: false, formFactors: ["Mobile"] },
      platform: "Linux armv8l", hardwareConcurrency: 8,
      extraHTTPHeaders: { "Sec-Fetch-Site": "cross-site" },
    },
  },

  // Override other scripts' settings (same as `settings` in sbx.config.jsonc).
  settings: { interact: { minDwellMs: 25000, maxDwellMs: 40000 } },

  launch(ctx, opts) {
    if (ctx.engine === "chromium") opts.args.push("--force-color-profile=srgb");
    return opts;
  },

  // Runs after the other scripts' interact() (script order).
  async interact(ctx) {
    if (ctx.navError) return;
    await ctx.page.mouse.wheel(0, 600).catch(() => {});
    await ctx.page.waitForTimeout(2000);
  },
};
