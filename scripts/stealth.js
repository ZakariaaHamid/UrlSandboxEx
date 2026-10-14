// stealth: look like a real visitor's browser: personas, native
// language/timezone matching the exit IP, a real window on a real screen,
// mobile Client Hints, audio devices and speech voices, native
// navigator.webdriver=false. Check changes with test/detector.html.

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

// Accept-Language as Chrome builds it (it-IT -> it-IT,it,en-US,en).
function acceptLanguages(locale) {
  const out = [locale];
  const base = locale.split("-")[0];
  if (base !== locale) out.push(base);
  if (base !== "en") out.push("en-US", "en");
  else if (locale !== "en-US") { out.splice(1, 1); out.push("en-US", "en"); }
  return [...new Set(out)];
}

function device(ctx) {
  if (!ctx.persona.device) return null;
  const d = { ...ctx.playwright.devices[ctx.persona.device] };
  delete d.defaultBrowserType;
  return d;
}

// The --disable-features list Playwright passes to Chromium, read from the
// installed Playwright (empty if its layout changed; test/unit.test.js
// checks it).
let pwDisabled = null;
function playwrightDisabledFeatures() {
  if (pwDisabled) return pwDisabled;
  try {
    const dir = path.dirname(require.resolve("playwright-core/package.json"));
    const src = fs.readFileSync(path.join(dir, "lib", "coreBundle.js"), "utf8");
    const m = src.match(/disabledFeatures = \[([\s\S]*?)\]\.filter\(Boolean\)/);
    pwDisabled = m ? [...m[1].replace(/\/\/.*$/gm, "").matchAll(/"([\w-]+)"/g)].map((x) => x[1]) : [];
  } catch (e) { pwDisabled = []; }
  return pwDisabled;
}

function quiet(cmd, args, env) {
  try { const p = spawn(cmd, args, { stdio: "ignore", env }); p.on("error", () => {}); return p; } catch (e) { return null; }
}

module.exports = {
  name: "stealth",

  settings: {
    // Real desktops have a window manager and a panel (availHeight < height).
    display: { width: 1920, height: 1080, depth: 24, windowManager: true, panelTop: 32 },
    // Desktop window: real (no viewport emulation), not maximized.
    window: { width: 1680, height: 1000, x: 96, y: 40 },
  },

  personas: {
    desktop: { engine: "chromium" },
    android: {
      engine: "chromium", device: "Pixel 7",
      userAgent: (major) => `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Mobile Safari/537.36`,
      clientHints: { platform: "Android", platformVersion: "14.0.0", architecture: "", model: "Pixel 7", mobile: true, bitness: "64", wow64: false, formFactors: ["Mobile"] },
      platform: "Linux armv8l",
      hardwareConcurrency: 8,
    },
    iphone: { engine: "webkit", device: "iPhone 15" },
    firefox: { engine: "firefox" },
    safari: { engine: "webkit" },
  },

  // Audio devices (enumerateDevices() is empty without an audio server)
  // and speech voices (speech-dispatcher, started before Chrome asks).
  async services(ctx) {
    const dir = path.join(require("os").tmpdir(), "xdg");
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    ctx.env.XDG_RUNTIME_DIR = dir;
    const pa = path.join(dir, "sbx.pa");
    fs.writeFileSync(pa, [
      "load-module module-native-protocol-unix",
      'load-module module-null-sink sink_name=Speakers sink_properties=device.description="Built-in\\ Audio\\ Analog\\ Stereo"',
      'load-module module-virtual-source source_name=Microphone master=Speakers.monitor source_properties=device.description="Built-in\\ Audio\\ Analog\\ Stereo"',
      "set-default-sink Speakers", "set-default-source Microphone", "",
    ].join("\n"));
    const procs = [
      quiet("pulseaudio", ["-n", "--daemonize=no", "--exit-idle-time=-1", "--disable-shm=yes", "-F", pa, "--log-level=error"], ctx.env),
      quiet("speech-dispatcher", ["-s", "-t", "0", "-l", "1"], ctx.env),
    ];
    // Both start while the browser launches; ready() waits for their sockets.
    const sockets = [path.join(dir, "pulse", "native"), path.join(dir, "speech-dispatcher", "speechd.sock")];
    ctx.state.servicesReady = (async () => {
      for (const end = Date.now() + 2000; Date.now() < end && !sockets.every((s) => fs.existsSync(s)); ) await new Promise((r) => setTimeout(r, 25));
    })();
    return procs;
  },

  launch(ctx, opts) {
    const { engine, locale, timezoneId, persona } = ctx;
    // Language + timezone on the browser process itself: navigator.languages,
    // Accept-Language, Intl and Date agree everywhere, workers included.
    if (timezoneId) opts.env.TZ = timezoneId;
    opts.env.LANG = `${locale.replace("-", "_")}.UTF-8`;
    opts.env.LANGUAGE = acceptLanguages(locale).map((l) => l.replace("-", "_")).join(":");
    const win = persona.window || ctx.settings.window;
    if (engine === "chromium") {
      opts.args.push(
        "--kiosk-printing",                              // window.print() would hang the page
        "--disable-blink-features=AutomationControlled", // native navigator.webdriver === false
        "--enable-speech-dispatcher",                    // real speechSynthesis voices
        "--auto-accept-camera-and-microphone-capture",   // = a person clicking "Allow"
        "--auto-select-screen-capture-source",           // title-free, any UI language
        "--auto-accept-this-tab-capture",
        `--lang=${locale}`, `--accept-lang=${acceptLanguages(locale).join(",")}`,
      );
      // RenderDocument gives each new document a fresh renderer frame that
      // learns its window position a moment later, so an inline script on
      // the first page could see outerWidth 0. Chrome honours only the last
      // --disable-features, so this one carries Playwright's list too.
      const pwFeatures = playwrightDisabledFeatures();
      if (pwFeatures.length) opts.args.push(`--disable-features=${[...pwFeatures, "RenderDocument"].join(",")}`);
      if (!device(ctx)?.isMobile) opts.args.push(`--window-size=${win.width},${win.height}`, `--window-position=${win.x},${win.y}`);
      // Outside a jail only: no WebRTC around the proxy. In the jail UDP has
      // no route out, and this policy would hide the LAN host candidate.
      if (ctx.proxy && !ctx.jailed) opts.args.push("--force-webrtc-ip-handling-policy=disable_non_proxied_udp");
    } else if (engine === "firefox") {
      opts.firefoxUserPrefs = {
        "print.always_print_silent": true, "print.show_print_progress": false,
        "dom.webdriver.enabled": false,
        "intl.accept_languages": acceptLanguages(locale).join(","), "intl.locale.requested": locale,
        ...(opts.firefoxUserPrefs || {}),
      };
    }
    opts.args.push(...(persona.launchArgs || []));
    return opts;
  },

  context(ctx, opts) {
    const d = device(ctx) || {};
    Object.assign(opts, d);
    if (ctx.engine === "webkit") { opts.locale = ctx.locale; if (ctx.timezoneId) opts.timezoneId = ctx.timezoneId; }
    else if (!d.isMobile) opts.viewport = null; // real window on a real screen
    if (ctx.persona.extraHTTPHeaders) opts.extraHTTPHeaders = ctx.persona.extraHTTPHeaders;
    return Object.assign(opts, ctx.persona.contextOptions || {});
  },

  // Once after launch: this Chrome build's exact brand list (GREASE
  // included), for mobile Client Hints. From a stub https page, no network.
  async ready(ctx) {
    await ctx.state.servicesReady;
    if (ctx.engine !== "chromium" || !ctx.persona.clientHints) return;
    const p = await ctx.context.newPage();
    try {
      await p.route("https://brands.sbx.invalid/", (r) => r.fulfill({ contentType: "text/html", body: "<title>x</title>" }));
      await p.goto("https://brands.sbx.invalid/");
      ctx.state.brands = await p.evaluate(async () => navigator.userAgentData && ({ brands: navigator.userAgentData.brands, fullVersionList: (await navigator.userAgentData.getHighEntropyValues(["fullVersionList"])).fullVersionList }));
    } catch (e) { /* fall back to empty brands */ } finally { await p.close().catch(() => {}); }
  },

  async page(ctx) {
    const { page, context, persona, engine, version } = ctx;
    if (engine === "chromium" && (persona.hardwareConcurrency || persona.clientHints)) {
      // UA + full Client Hints + navigator.platform together, using this
      // build's real brand list; CPU count. Registered for every DevTools
      // session (see ctx.onSession) and set on each cross-site iframe.
      const major = String(version).split(".")[0];
      const rb = ctx.state.brands || {};
      const ua = persona.clientHints && {
        userAgent: typeof persona.userAgent === "function" ? persona.userAgent(major) : persona.userAgent,
        ...(persona.platform ? { platform: persona.platform } : {}),
        userAgentMetadata: { brands: rb.brands || [], fullVersionList: rb.fullVersionList || [], fullVersion: version, ...persona.clientHints },
      };
      const hc = persona.hardwareConcurrency && { hardwareConcurrency: persona.hardwareConcurrency };
      const apply = async (target) => {
        if (ua) await target.send("Emulation.setUserAgentOverride", ua).catch(() => {});
        if (hc) await target.send("Emulation.setHardwareConcurrencyOverride", hc).catch(() => {});
      };
      if (!ctx.state.sessionSetup) { ctx.state.sessionSetup = true; ctx.onSession((s) => apply(s)); }
      await context.newCDPSession(page); // kept open: holds the overrides
      await ctx.childTargets(page, async (t) => {
        if (t.type === "iframe") return apply(t);
        if (t.type !== "worker") return;
        if (hc) await t.send("Emulation.setHardwareConcurrencyOverride", hc).catch(() => {});
        // Workers take navigator.platform from the build, not from the
        // override: set it before the Worker's first line runs. The getter
        // is a bound native function (prints as native code, no prototype,
        // the right name); only an exact toString comparison differs.
        if (ua && ua.platform) {
          await t.send("Runtime.evaluate", { expression: `(() => { const P = WorkerNavigator.prototype, d = Object.getOwnPropertyDescriptor(P, "platform"); if (!d || !d.get) return; const get = String.prototype.valueOf.bind(${JSON.stringify(ua.platform)}); Object.defineProperty(get, "name", { value: "get platform" }); Object.defineProperty(P, "platform", { get, set: undefined, enumerable: d.enumerable, configurable: d.configurable }); })()\n//# sourceURL=stealth-worker-platform` }).catch(() => {});
        }
      });
    }
    if (ctx.isPopup) return;
    if (engine === "webkit") {
      // WebKit has no native switch for navigator.webdriver.
      await context.addInitScript(() => { try { if (navigator.webdriver) Object.defineProperty(Object.getPrototypeOf(navigator), "webdriver", { get: () => false, configurable: true, enumerable: true }); } catch (e) { /* ignore */ } });
    }
    for (const s of persona.initScripts || []) await context.addInitScript(/\.m?js$/.test(s) && fs.existsSync(s) ? fs.readFileSync(s, "utf8") : s);
  },

  acceptLanguages,
  playwrightDisabledFeatures,
};
