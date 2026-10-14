// Provider challenges in front of the payload: Cloudflare's interstitial
// and Turnstile, reCAPTCHA v2 and hCaptcha checkboxes. These live in
// cross-origin iframes (often in closed shadow roots), out of reach of
// page DOM queries. No solver, no token injection: wait (managed modes
// pass on their own for a genuine browser on a clean IP), then move the
// real mouse along a human path and click the checkbox (trusted CDP input).
// A reCAPTCHA image puzzle (served after a bad risk score) is switched to
// its audio version and solved by transcribing the clip locally with
// whisper.cpp; hCaptcha puzzles are reported unsolved.

const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFile } = require("child_process");
const { moveMouseHumanlike, typeChars } = require("./humanize");
const vision = require("./vision");
const timeline = require("./timeline");

const WIDGETS = [
  { kind: "turnstile", frame: /challenges\.cloudflare\.com\/.*(turnstile|challenge-platform)/i, // checkbox sits at the widget's left edge
    target: async (frame, box) => ({ x: box.x + 28 + Math.random() * 6, y: box.y + box.height / 2 + (Math.random() * 6 - 3) }) },
  { kind: "recaptcha", frame: /\/recaptcha\/(api2|enterprise)\/anchor/i,
    target: async (frame, box) => elementPoint(frame, "#recaptcha-anchor, .recaptcha-checkbox", box) },
  { kind: "hcaptcha", frame: /hcaptcha\.com\/.*(checkbox|frame=checkbox)/i,
    target: async (frame, box) => elementPoint(frame, "#checkbox", box) },
];

async function elementPoint(frame, selector, fallbackBox) {
  const b = await frame.locator(selector).first().boundingBox({ timeout: 2000 }).catch(() => null);
  const box = b || { x: fallbackBox.x + 10, y: fallbackBox.y + fallbackBox.height / 2 - 12, width: 24, height: 24 };
  return { x: box.x + box.width * (0.3 + Math.random() * 0.4), y: box.y + box.height * (0.3 + Math.random() * 0.4) };
}

// Widget markup/scripts present but its iframe not loaded yet.
async function widgetMarkupPresent(page) {
  return page.evaluate(() => !!document.querySelector(
    '.cf-turnstile, [data-sitekey], .g-recaptcha, .h-captcha, script[src*="challenges.cloudflare.com"], script[src*="recaptcha"], script[src*="hcaptcha"]'
  )).catch(() => false);
}

function isInterstitialTitle(t) {
  return /^(just a moment|un instant|einen moment|un momento|um momento|attention required|checking your browser|ddos-guard|please wait)/i.test(t || "");
}

// The image/audio puzzle a checkbox escalates to after a bad risk score.
const PUZZLE = { recaptcha: /\/recaptcha\/(api2|enterprise)\/bframe/i, hcaptcha: /hcaptcha\.com\/.*frame=challenge/i };
async function puzzleShown(page, kind) {
  if (!PUZZLE[kind]) return false;
  for (const f of page.frames()) {
    if (!PUZZLE[kind].test(f.url())) continue;
    const el = await f.frameElement().catch(() => null);
    const b = el && await el.boundingBox().catch(() => null);
    // On screen: a closed puzzle stays in the page, parked at -10000px.
    if (b && b.width > 100 && b.height > 100 && b.y + b.height > 0) return true;
  }
  return false;
}

// --- reCAPTCHA audio ---------------------------------------------------------
const run = (cmd, args, ms) => new Promise((resolve, reject) => execFile(cmd, args, { timeout: ms, maxBuffer: 1 << 20 }, (e, out) => (e ? reject(e) : resolve(String(out)))));
const BLOCKED = /automated queries|automatiche|automatisierte|automatizadas|automatisées|automatizadas|geautomatiseerde/i;

async function transcribe(mp3, { whisperDir, lang }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audio-"));
  try {
    fs.writeFileSync(path.join(dir, "a.mp3"), mp3);
    await run("ffmpeg", ["-loglevel", "error", "-y", "-i", path.join(dir, "a.mp3"), "-ar", "16000", "-ac", "1", path.join(dir, "a.wav")], 20000);
    const out = await run(path.join(whisperDir, "whisper-cli"), ["-m", path.join(whisperDir, "ggml-base.bin"), "-f", path.join(dir, "a.wav"), "-l", lang || "auto", "-t", "2", "-nt", "-np"], 60000);
    return out.toLowerCase().replace(/[^\p{L}\p{N}\s]/gu, " ").replace(/\s+/g, " ").trim();
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

// Audio clips as the player fetches them (it preloads each new clip when
// it appears), in the page's own session. An empty body means Google
// withheld the clip. The puzzle is a cross-site iframe, so its traffic is
// watched on the context, not the page.
function watchClips(page) {
  const ctx = page.context(), clips = [];
  const onResponse = async (r) => {
    if (!/\/recaptcha\/(api2|enterprise)\/payload/.test(r.url())) return;
    const type = (await r.allHeaders().catch(() => ({})))["content-type"] || "";
    if (r.request().resourceType() !== "media" && !/audio/.test(type)) return;
    clips.push(await r.body().catch(() => Buffer.alloc(0)));
  };
  ctx.on("response", onResponse);
  return { clips, stop: () => ctx.off("response", onResponse) };
}

async function nextClip(page, bframe, cursor, watch, seen) {
  for (let i = 0; i < 16 && watch.clips.length <= seen; i++) await page.waitForTimeout(250);
  if (watch.clips.length <= seen) {
    // Not preloaded: press PLAY.
    const play = await bframe.locator(".rc-audiochallenge-play-button button").first().boundingBox({ timeout: 3000 }).catch(() => null);
    if (play) {
      const pt = { x: play.x + play.width / 2, y: play.y + play.height / 2 };
      await moveMouseHumanlike(page, cursor.x, cursor.y, pt.x, pt.y).catch(() => {});
      await page.mouse.click(pt.x, pt.y);
      Object.assign(cursor, pt);
      for (let i = 0; i < 32 && watch.clips.length <= seen; i++) await page.waitForTimeout(250);
    }
  }
  return watch.clips.length > seen ? watch.clips[watch.clips.length - 1] : null;
}

async function solveRecaptchaAudio(page, cursor, opts) {
  if (!fs.existsSync(path.join(opts.whisperDir, "whisper-cli"))) return { note: "audio solving is not installed: run deploy/setup.sh" };
  const end = Date.now() + 75000;
  const bframe = () => page.frames().find((f) => PUZZLE.recaptcha.test(f.url()));
  const click = async (locator) => {
    const b = await locator.boundingBox({ timeout: 4000 }).catch(() => null);
    if (!b) return false;
    const pt = { x: b.x + b.width * (0.3 + Math.random() * 0.4), y: b.y + b.height * (0.3 + Math.random() * 0.4) };
    await moveMouseHumanlike(page, cursor.x, cursor.y, pt.x, pt.y).catch(() => {});
    await page.waitForTimeout(80 + Math.random() * 200);
    await page.mouse.click(pt.x, pt.y);
    Object.assign(cursor, pt);
    return true;
  };
  let bf = bframe();
  const watch = watchClips(page);
  try {
  if (!bf || !(await click(bf.locator("#recaptcha-audio-button")))) return { note: "no audio option" };
  for (let attempt = 1; attempt <= 3 && Date.now() < end; attempt++) {
    const seen = watch.clips.length;
    await page.waitForTimeout(1500 + Math.random() * 1000);
    bf = bframe();
    if (!bf) return { note: "the puzzle closed" };
    const text = await bf.locator("body").innerText({ timeout: 3000 }).catch(() => "");
    if (BLOCKED.test(text)) return { note: "Google refused the audio as automated traffic" };
    const mp3 = await nextClip(page, bf, cursor, watch, attempt === 1 ? 0 : seen);
    if (!mp3) return { note: "no audio clip" };
    if (!mp3.length) return { note: "Google withheld the audio, a sign of bad IP reputation" };
    const answer = await transcribe(mp3, opts).catch(() => "");
    if (!answer) return { note: "audio not understood" };
    if (!(await click(bf.locator("#audio-response")))) return { note: "no answer field" };
    await typeChars(page, answer);
    await page.waitForTimeout(200 + Math.random() * 400);
    await click(bf.locator("#recaptcha-verify-button"));
    for (let i = 0; i < 12; i++) { await page.waitForTimeout(400); if (await solved(page, "recaptcha")) return { solved: true, attempts: attempt }; }
    // A wrong answer or "multiple correct solutions required" brings a new clip.
  }
  return { note: "audio answers not accepted" };
  } finally { watch.stop(); }
}

// --- reCAPTCHA images ----------------------------------------------------------
// Which tiles show the target. 4x4 grids are one photo: boxes from the
// detector, mapped onto the tiles. 3x3 grids are separate photos: each tile
// is checked by the detector (COCO classes) and by CLIP.
// A screenshot of the element's area of the page. Element screenshots wait
// for the element to be "stable" (animation frames), which never happens in
// some reCAPTCHA frames.
async function shot(locator) {
  const box = await locator.boundingBox({ timeout: 4000 });
  if (!box) throw new Error("tile not visible");
  return locator.page().screenshot({ clip: box, timeout: 6000 });
}

async function pickTiles(bf, target, n, only, dir) {
  const c = vision.CLASSES[target], coco = c.coco === undefined ? [] : [].concat(c.coco);
  const tiles = bf.locator("td.rc-imageselect-tile");
  const picked = [];
  if (n === 4 && coco.length) {
    const grid = await shot(bf.locator("table").first());
    const box = await bf.locator("table").first().boundingBox();
    const size = box.width / 4;
    const hits = (await vision.detect(dir, grid, { minScore: 0.3 })).filter((b) => coco.includes(b.cls));
    for (let i = 0; i < 16; i++) {
      const tx = (i % 4) * size, ty = Math.floor(i / 4) * size;
      const covered = hits.some((b) => Math.max(0, Math.min(b.x2, tx + size) - Math.max(b.x1, tx)) * Math.max(0, Math.min(b.y2, ty + size) - Math.max(b.y1, ty)) > 0.06 * size * size);
      if (covered) picked.push(i);
    }
    return picked;
  }
  for (const i of only || [...Array(n * n).keys()]) {
    const img = await shot(tiles.nth(i)).catch((e) => { picked.errors = picked.errors || String(e.message).split("\n")[0]; return null; });
    if (!img) continue;
    const yolo = coco.length && (await vision.detect(dir, img, { minScore: 0.35 })).some((b) => coco.includes(b.cls));
    const clip = await vision.clipScore(dir, img, target);
    if (yolo || clip.best === target || clip.p >= (n === 4 ? 0.25 : 0.3)) picked.push(i);
  }
  return picked;
}

async function solveRecaptchaImages(page, cursor, opts) {
  if (!vision.ready(opts.visionDir)) return { note: "image solving is not installed: run deploy/setup.sh" };
  const end = Date.now() + 100000;
  const bframe = () => page.frames().find((f) => PUZZLE.recaptcha.test(f.url()));
  const click = async (locator) => {
    const b = await locator.boundingBox({ timeout: 4000 }).catch(() => null);
    if (!b) return false;
    const pt = { x: b.x + b.width * (0.25 + Math.random() * 0.5), y: b.y + b.height * (0.25 + Math.random() * 0.5) };
    await moveMouseHumanlike(page, cursor.x, cursor.y, pt.x, pt.y).catch(() => {});
    await page.waitForTimeout(60 + Math.random() * 160);
    await page.mouse.click(pt.x, pt.y);
    Object.assign(cursor, pt);
    return true;
  };
  const srcs = (bf) => bf.evaluate(() => Array.from(document.querySelectorAll("td.rc-imageselect-tile img")).map((i) => i.src)).catch(() => []);
  let rounds = 0;
  const trace = [];
  for (; rounds < 8 && Date.now() < end; rounds++) {
    await page.waitForTimeout(1200 + Math.random() * 800);
    const bf = bframe();
    if (!bf) return { note: "the puzzle closed" };
    if (await solved(page, "recaptcha")) return { solved: true, rounds, trace };
    if (!(await bf.locator("td.rc-imageselect-tile").count().catch(() => 0))) return { note: "no image tiles", trace };
    const word = await bf.locator(".rc-imageselect-desc-wrapper strong").first().innerText({ timeout: 4000 }).catch(() => "");
    const target = vision.classFor(word);
    const n = /44/.test(await bf.locator("table").first().getAttribute("class", { timeout: 3000 }).catch(() => "")) ? 4 : 3;
    if (!target) { trace.push(`${n}x${n} "${word}": unknown, reloaded`); await click(bf.locator("#recaptcha-reload-button")); continue; } // an object we do not know: ask for another
    await timeline.snap(page, `reCAPTCHA puzzle: ${word}`);
    let picked = await pickTiles(bf, target, n, null, opts.visionDir);
    const step = { grid: `${n}x${n}`, target, picked: [...picked], waves: 0, ...(picked.errors ? { error: picked.errors } : {}) };
    trace.push(step);
    for (const i of picked.sort(() => Math.random() - 0.5)) await click(bf.locator("td.rc-imageselect-tile").nth(i));
    // Dynamic grids replace clicked tiles with new photos: check those too.
    for (let wave = 0; n === 3 && picked.length && wave < 5; wave++) {
      const before = await srcs(bf);
      await page.waitForTimeout(4200 + Math.random() * 800);
      const after = await srcs(bf);
      const fresh = picked.filter((i) => after[i] && after[i] !== before[i]);
      if (!fresh.length) break;
      picked = await pickTiles(bf, target, n, fresh, opts.visionDir);
      step.waves++;
      for (const i of picked) await click(bf.locator("td.rc-imageselect-tile").nth(i));
    }
    await page.waitForTimeout(300 + Math.random() * 500);
    await timeline.snap(page, picked.length ? "reCAPTCHA tiles selected" : "reCAPTCHA: no matching tile, skip");
    await click(bf.locator("#recaptcha-verify-button"));
    for (let i = 0; i < 10; i++) { await page.waitForTimeout(400); if (await solved(page, "recaptcha")) { step.result = "accepted"; return { solved: true, rounds: rounds + 1, trace }; } }
    // Not yet: Google shows another puzzle, or asks to select more (then reload).
    const more = await bf.locator(".rc-imageselect-error-select-more, .rc-imageselect-error-dynamic-more").first().isVisible().catch(() => false);
    const wrong = await bf.locator(".rc-imageselect-incorrect-response").first().isVisible().catch(() => false);
    step.result = more ? "select more" : wrong ? "incorrect" : "another puzzle";
    if (more) await click(bf.locator("#recaptcha-reload-button"));
  }
  return { note: `image puzzles not solved after ${rounds} round(s)`, trace };
}

async function solved(page, kind) {
  return page.evaluate((k) => {
    const sel = { turnstile: '[name="cf-turnstile-response"]', recaptcha: '[name="g-recaptcha-response"], #g-recaptcha-response', hcaptcha: '[name="h-captcha-response"]' }[k];
    return Array.from(document.querySelectorAll(sel)).some((e) => (e.value || "").length > 20);
  }, kind).catch(() => false);
}

/**
 * Wait out / click through provider challenges. Bounded by budgetMs.
 * @returns {Promise<Array<{kind, clicked, solved, note?}>>}
 */
async function handleChallenges(page, { budgetMs = 30000, allowClicks = true, audio = null } = {}) {
  const started = Date.now();
  const deadline = started + budgetMs;
  const log = [];
  const seen = new Map();
  let cursor = { x: 200 + Math.random() * 300, y: 200 + Math.random() * 200 };

  // Interstitial: the page title says so until the challenge clears and
  // the browser is redirected to the real page.
  if (isInterstitialTitle(await page.title().catch(() => ""))) {
    log.push({ kind: "cloudflare-interstitial", clicked: false, solved: false });
  }

  while (Date.now() < deadline) {
    let acted = false;
    for (const frame of page.frames()) {
      const w = WIDGETS.find((x) => x.frame.test(frame.url()));
      if (!w) continue;
      const key = `${w.kind}:${frame.url().slice(0, 120)}`;
      const state = seen.get(key) || { kind: w.kind, clicked: 0, solved: false };
      seen.set(key, state);
      if (state.solved) continue;
      if (await solved(page, w.kind)) { state.solved = true; await timeline.snap(page, `${w.kind} solved`); continue; }
      // Escalated to a puzzle: reCAPTCHA's audio version once, then stop waiting.
      // Invisible reCAPTCHA opens the puzzle without a click; clicking its
      // badge then would close it, so a puzzle on screen is solved first.
      if (state.puzzle || ((state.clicked || w.kind === "recaptcha") && await puzzleShown(page, w.kind))) {
        if (!state.puzzle && w.kind === "recaptcha" && audio && allowClicks) {
          // The image puzzle itself first (Google withholds audio from
          // low-reputation IPs), then its audio version.
          const img = audio.visionDir ? await solveRecaptchaImages(page, cursor, audio).catch((e) => ({ note: `image solving failed: ${e.message}` })) : { note: "image solving off" };
          state.rounds = img.trace;
          if (img.solved) { state.audio = `solved the image puzzle (${img.rounds} round${img.rounds > 1 ? "s" : ""})`; state.solved = true; await timeline.snap(page, "reCAPTCHA solved"); continue; }
          const r = await solveRecaptchaAudio(page, cursor, audio).catch((e) => ({ note: `audio solving failed: ${e.message}` }));
          state.audio = r.solved ? `solved by audio (${r.attempts} attempt${r.attempts > 1 ? "s" : ""})` : `${img.note}; audio: ${r.note}`;
          if (r.solved) { state.solved = true; await timeline.snap(page, "reCAPTCHA solved by audio"); continue; }
        }
        state.puzzle = true;
        continue;
      }
      const el = await frame.frameElement().catch(() => null);
      const box = el && await el.boundingBox().catch(() => null);
      if (!box || box.width < 20 || box.height < 20) continue; // invisible/managed mode: just wait
      // Give a managed widget a moment to pass on its own before clicking.
      if (!state.firstSeen) { state.firstSeen = Date.now(); continue; }
      if (Date.now() - state.firstSeen < 2500 + Math.random() * 1500) continue;
      if (!allowClicks || state.clicked >= 2) continue;
      const pt = await w.target(frame, box);
      await moveMouseHumanlike(page, cursor.x, cursor.y, pt.x, pt.y).catch(() => {});
      await page.waitForTimeout(120 + Math.random() * 250);
      await page.mouse.down(); await page.waitForTimeout(60 + Math.random() * 90); await page.mouse.up();
      cursor = pt; state.clicked++; acted = true; state.urlAtClick = page.url();
      await page.waitForTimeout(800);
      await timeline.snap(page, `${w.kind} clicked`);
    }
    const titleNow = await page.title().catch(() => "");
    const pending = [...seen.values()].some((s) => !s.solved && !s.puzzle);
    const loading = !seen.size && Date.now() - started < 12000 && await widgetMarkupPresent(page);
    if (!pending && !loading && !isInterstitialTitle(titleNow)) break;
    await page.waitForTimeout(acted ? 2500 : 1000);
  }
  for (const s of seen.values()) {
    if (!s.solved) s.solved = await solved(page, s.kind);
    // The page left the gate after our click: it let us through.
    if (!s.solved && s.clicked && !s.puzzle && s.urlAtClick && page.url() !== s.urlAtClick) { s.solved = true; s.audio = "the page moved on after the click"; }
    log.push({ kind: s.kind, clicked: s.clicked > 0, solved: s.solved, ...(s.audio ? { audio: s.audio } : {}), ...(s.rounds && s.rounds.length ? { rounds: s.rounds } : {}), note: s.solved ? undefined : s.puzzle ? "escalated to a puzzle, a sign of bad IP reputation" : "not solved within budget" });
  }
  const inter = log.find((l) => l.kind === "cloudflare-interstitial");
  if (inter) inter.solved = !isInterstitialTitle(await page.title().catch(() => ""));
  return log;
}

module.exports = { handleChallenges };
