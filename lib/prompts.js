// Clicks "Allow" on Chrome's permission prompts (geolocation, clipboard,
// notifications) the way a person does. The prompt is browser UI, so CDP
// input can't reach it; granting the permission over CDP after the request
// doesn't resolve the pending prompt; and pre-granting makes
// navigator.permissions.query() report "granted" for a site never visited.
// So: capture the X display, find the prompt's buttons, click with a real
// X11 pointer event (xdotool).
//
// Layouts: a stack of 2-3 equal-width tonal buttons (rgb 211,227,253) whose
// first button allows, or two side-by-side pills where the right one is
// "Allow". Camera/mic/screen capture use Chrome switches instead (stealth).

const { execFile } = require("child_process");
const { PNG } = require("pngjs");

const BUTTON = [211, 227, 253];
const near = (d, i) => Math.abs(d[i] - BUTTON[0]) <= 4 && Math.abs(d[i + 1] - BUTTON[1]) <= 4 && Math.abs(d[i + 2] - BUTTON[2]) <= 4;

function grabScreen(env) {
  return new Promise((resolve) => {
    execFile("import", ["-window", "root", "png:-"], { env, encoding: "buffer", maxBuffer: 32 << 20, timeout: 4000 }, (err, out) => {
      if (err || !out?.length) return resolve(null);
      try { resolve(PNG.sync.read(out)); } catch (e) { resolve(null); }
    });
  });
}

// Bands of button color: [{x0, x1, y0, y1}]
function findButtonStack(png, { yMin = 110, yMax = 760, xMax = 1100 } = {}) {
  // Per row: extent and coverage of button-colored pixels (labels inside
  // the buttons interrupt runs, so measure coverage, not runs).
  // Per row: the widest segment of button-colored pixels, bridging gaps
  // < 40px (labels inside buttons interrupt the color); the window frame
  // shares the color but is only a few pixels wide.
  const rows = [];
  for (let y = yMin; y < Math.min(yMax, png.height); y++) {
    let best = null, seg = null, lastHit = -1000;
    for (let x = 0; x < Math.min(xMax, png.width); x++) {
      if (!near(png.data, (y * png.width + x) * 4)) continue;
      if (seg && x - lastHit < 40) { seg.x1 = x; seg.count++; }
      else { seg = { x0: x, x1: x, count: 1 }; }
      lastHit = x;
      if (!best || seg.x1 - seg.x0 > best.x1 - best.x0) best = seg;
    }
    const ok = best && best.x1 - best.x0 >= 180 && best.x1 - best.x0 <= 520 && best.count / (best.x1 - best.x0 + 1) >= 0.35;
    rows.push(ok ? { x0: best.x0, x1: best.x1 } : null);
  }
  const bands = [];
  let cur = null;
  rows.forEach((r, k) => {
    const y = yMin + k;
    if (r && cur && Math.abs(r.x0 - cur.x0) <= 25 && Math.abs(r.x1 - cur.x1) <= 25) { cur.y1 = y; cur.x0 = Math.min(cur.x0, r.x0); cur.x1 = Math.max(cur.x1, r.x1); }
    else { if (cur && cur.y1 - cur.y0 >= 20) bands.push(cur); cur = r ? { x0: r.x0, x1: r.x1, y0: y, y1: y } : null; }
  });
  if (cur && cur.y1 - cur.y0 >= 20) bands.push(cur);
  // A prompt: >= 2 bands, same width, stacked within ~70px of each other.
  for (let i = 0; i + 1 < bands.length; i++) {
    const a = bands[i], b = bands[i + 1];
    const sameWidth = Math.abs((a.x1 - a.x0) - (b.x1 - b.x0)) <= 12 && Math.abs(a.x0 - b.x0) <= 12;
    if (sameWidth && b.y0 - a.y1 < 30 && a.y1 - a.y0 <= 60) return [a, ...bands.slice(i + 1).filter((x) => Math.abs(x.x0 - a.x0) <= 12)];
  }
  return null;
}

// Two-button prompts (clipboard, notifications): "Block" and "Allow" pills
// side by side; Allow is the RIGHT one. Rows through the pills' plain
// edges show exactly two short button-colored segments.
function findPillPair(png, { yMin = 110, yMax = 760, xMax = 1100 } = {}) {
  const hits = [];
  for (let y = yMin; y < Math.min(yMax, png.height); y++) {
    const segs = [];
    let seg = null;
    for (let x = 8; x < Math.min(xMax, png.width); x++) {
      const on = near(png.data, (y * png.width + x) * 4);
      if (on) { if (seg && x - seg.x1 <= 2) seg.x1 = x; else { seg = { x0: x, x1: x }; segs.push(seg); } }
    }
    const wide = segs.filter((g) => g.x1 - g.x0 >= 30);
    if (wide.length === 2) {
      const [a, b] = wide;
      const wa = a.x1 - a.x0, wb = b.x1 - b.x0, gap = b.x0 - a.x1;
      if (wa <= 120 && wb <= 120 && gap >= 3 && gap <= 24) hits.push({ y, a, b });
    }
  }
  if (hits.length < 4) return null;
  // Group hits whose right pill lines up; take the first group spanning a pill.
  const groups = [];
  for (const h of hits) {
    const g = groups.find((x) => Math.abs(x.b.x0 - h.b.x0) <= 6 && h.y - x.y1 <= 30);
    if (g) { g.y1 = h.y; g.b = { x0: Math.min(g.b.x0, h.b.x0), x1: Math.max(g.b.x1, h.b.x1) }; }
    else groups.push({ y0: h.y, y1: h.y, b: { ...h.b } });
  }
  const pill = groups.find((g) => g.y1 - g.y0 >= 20 && g.y1 - g.y0 <= 60);
  return pill ? { x0: pill.b.x0, x1: pill.b.x1, y0: pill.y0, y1: pill.y1 } : null;
}

function xdo(env, args) {
  return new Promise((resolve) => execFile("xdotool", args, { env, timeout: 3000 }, () => resolve()));
}

/**
 * Start watching for permission prompts on the jail's display.
 * @returns {{stop: () => Promise<Array<{at, x, y}>>}}
 */
function watchPermissionPrompts(env, { intervalMs = 1500 } = {}) {
  const clicks = [];
  let stopped = false, busy = false;
  const timer = setInterval(async () => {
    if (busy || stopped || !env.DISPLAY) return;
    busy = true;
    try {
      const png = await grabScreen(env);
      const stack = png && findButtonStack(png);
      const pill = png && !stack && findPillPair(png);
      const b = stack ? stack[0] : pill;
      if (b && clicks.length < 6) {
        const half = (b.x1 - b.x0) / 2;
        const x = Math.round(b.x0 + half + (Math.random() - 0.5) * Math.min(40, half));
        const y = Math.round((b.y0 + b.y1) / 2 + (Math.random() * 6 - 3));
        await xdo(env, ["mousemove", "--sync", String(x), String(y)]);
        await new Promise((r) => setTimeout(r, 150 + Math.random() * 200));
        await xdo(env, ["click", "1"]);
        clicks.push({ at: new Date().toISOString(), x, y, layout: stack ? "stack" : "pair" });
      }
    } finally { busy = false; }
  }, intervalMs);
  return {
    stop: async () => { stopped = true; clearInterval(timer); while (busy) await new Promise((r) => setTimeout(r, 50)); return clicks; },
  };
}

module.exports = { watchPermissionPrompts, findButtonStack, findPillPair };
