// Human-interaction simulation for the sandbox's browser sessions: bezier mouse
// movement, scrolling, hovering, typing into form fields, and working through
// interaction gates (fake CAPTCHAs, sliders, press-and-hold, drag-and-drop,
// wizards, OTP fields, math CAPTCHAs, touch gestures, sensor/orientation prompts).
// Movement, hovering and scrolling are read-only and always on. Clicking is
// opt-in via { allowClicks: true }, since a blind click on an unknown page could
// submit a form or trigger a download. Typed values come from the configured fake
// identity (setIdentity()); hidden honeypot elements are never typed into or clicked.

const path = require("path");
const { isRealService } = require("./sites");

function randomBetween(min, max) {
  return min + Math.random() * (max - min);
}

// Timing and movement, from settings.humanize (scripts/interact.js), so
// each installation moves and types at its own pace.
const tuning = { speed: 1, curve: 0.25, mouseStepsMin: 15, mouseStepsMax: 30, mouseStepMsMin: 4, mouseStepMsMax: 18, keyMsMin: 40, keyMsMax: 220 };
function setTuning(t = {}) { for (const k of Object.keys(tuning)) if (Number.isFinite(t[k])) tuning[k] = t[k]; }
// What this file put on the clipboard (copied selections, pasted codes), so
// the clipboard watcher (scripts/indicators.js) does not report our own text.
const ownClipboard = new Set();
const noteClipboard = (t) => { if (t) ownClipboard.add(String(t).replace(/\s+/g, " ").trim()); };

// Every pause in this file, scaled by the speed. Past the deadline
// (setDeadline) a pause throws, which stops whatever step is running.
let deadline = Infinity;
const setDeadline = (t) => { deadline = t || Infinity; };
const pause = (page, ms) => {
  if (Date.now() > deadline) return Promise.reject(new Error("interaction time budget used up"));
  return page.waitForTimeout(Math.max(0, ms * tuning.speed));
};
// A hold a gate measures: the speed may lengthen it, never shorten it below
// the threshold it is meant to clear.
const hold = (page, ms) => pause(page, Math.max(ms, ms / tuning.speed));

// Quadratic-bezier path between two points; human mouse movement is never
// perfectly linear, and mouse-behavior gates check for that.
function bezierPoints(x0, y0, x1, y1, steps) {
  // Control point offset sideways, proportional to distance.
  const dist = Math.hypot(x1 - x0, y1 - y0);
  const bow = randomBetween(-tuning.curve, tuning.curve) * dist;
  const midX = (x0 + x1) / 2 - (y1 - y0) * (bow / (dist || 1));
  const midY = (y0 + y1) / 2 + (x1 - x0) * (bow / (dist || 1));
  const points = [];
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const x = (1 - t) * (1 - t) * x0 + 2 * (1 - t) * t * midX + t * t * x1;
    const y = (1 - t) * (1 - t) * y0 + 2 * (1 - t) * t * midY + t * t * y1;
    points.push({ x, y });
  }
  return points;
}

async function moveMouseHumanlike(page, x0, y0, x1, y1) {
  const steps = Math.round(randomBetween(tuning.mouseStepsMin, tuning.mouseStepsMax));
  const path = bezierPoints(x0, y0, x1, y1, steps);
  for (const p of path) {
    await page.mouse.move(p.x, p.y);
    // Variable inter-step delay; a fixed cadence is itself a bot tell.
    await pause(page, randomBetween(tuning.mouseStepMsMin, tuning.mouseStepMsMax));
  }
}

// Returns visible, human-reachable text-entry fields (text/email/tel/url/number,
// textarea, contenteditable), skipping honeypots: zero size, near-zero opacity,
// off-viewport, tabindex="-1", clipped or not hit-testable. Password fields are
// never touched.
async function findVisibleTextFields(page, maxFields) {
  return page.evaluate((max) => {
    // Recurses into open shadow roots, which a plain querySelectorAll() does not
    // pierce. Closed roots are a real browser boundary and are left alone.
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    // textarea, contenteditable and tel/url inputs accept the same click+type flow
    // as a text input. [contenteditable] also matches contenteditable="false", so
    // el.isContentEditable is checked explicitly below.
    // type="number" silently drops non-numeric keystrokes, so it gets a numeric
    // fake value (fakeNumberValue()) instead of the shared default.
    const candidates = deepQueryAll(document,
      'input[type="text"], input[type="email"], input[type="tel"], input[type="url"], input[type="number"], input:not([type]), textarea, [contenteditable]'
    );
    // Math CAPTCHA ("What is 7 + 4?"): finds the question in visible page text and
    // computes the answer. Anchored on the "what is" prefix to avoid matching dates,
    // phone numbers or prices.
    let mathCaptchaAnswer = null;
    try {
      const bodyText = document.body.innerText || document.body.textContent || "";
      const mathMatch = bodyText.match(/what\s+is\s+(\d{1,3})\s*([+\-])\s*(\d{1,3})/i);
      if (mathMatch) {
        const left = parseInt(mathMatch[1], 10), right = parseInt(mathMatch[3], 10);
        mathCaptchaAnswer = String(mathMatch[2] === "+" ? left + right : left - right);
      }
    } catch (e) { /* not fatal */ }
    // Segmented OTP inputs: maxlength="1" boxes sharing a parent with 4+ such
    // siblings form one group, and each box gets its own digit of an N-digit code
    // found in page text (N = group size). Grouping happens before honeypot/
    // visibility filtering and counts already-filled boxes, so later rounds still
    // see the full group and correct positions.
    const otpDigitForEl = new Map();
    try {
      const maxLenOneEls = deepQueryAll(document, 'input[maxlength="1"]');
      const groupsByParent = new Map();
      for (const el of maxLenOneEls) {
        if (!el.parentElement) continue;
        if (!groupsByParent.has(el.parentElement)) groupsByParent.set(el.parentElement, []);
        groupsByParent.get(el.parentElement).push(el);
      }
      const otpBodyText = document.body.innerText || document.body.textContent || "";
      for (const group of groupsByParent.values()) {
        if (group.length < 4) continue;
        const codeMatch = otpBodyText.match(new RegExp("\\b(\\d{" + group.length + "})\\b"));
        if (!codeMatch) continue;
        const code = codeMatch[1];
        group.forEach((el, idx) => otpDigitForEl.set(el, code[idx]));
      }
    } catch (e) { /* not fatal */ }
    const results = [];
    for (const el of candidates) {
      if (el.disabled || el.readOnly) continue;
      if (el.hasAttribute("contenteditable") && !el.isContentEditable) continue;
      // Skips already-filled fields so repeated calls (for fields that appear only
      // after earlier input, e.g. progressive login forms) never retype into them.
      // contenteditable has no .value, so its textContent is checked instead.
      const currentText = el.isContentEditable ? el.textContent : el.value;
      if (currentText && currentText.trim().length > 0) continue;
      // Chromium reports tabIndex -1 for a contenteditable without an explicit
      // tabindex attribute, so tabIndex<0 is only a honeypot signal for other fields.
      if (el.tabIndex < 0 && !el.isContentEditable) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      const rect = el.getBoundingClientRect();
      // Near-zero opacity normally marks a honeypot, except when a <canvas> overlaps
      // the field: canvas-drawn login forms overlay transparent real inputs on
      // painted boxes, and a human would type there.
      if (parseFloat(style.opacity) < 0.1) {
        const overlapsCanvas = Array.from(document.querySelectorAll("canvas")).some((c) => {
          const cr = c.getBoundingClientRect();
          return !(rect.right < cr.left || rect.left > cr.right || rect.bottom < cr.top || rect.top > cr.bottom);
        });
        if (!overlapsCanvas) continue;
      }
      // clip-path/clip hide a field at paint time while its layout box stays
      // full-size, so the size checks don't catch it.
      if (style.clipPath && style.clipPath !== "none") continue;
      if (style.clip && style.clip !== "auto" && style.position !== "static") continue;
      // A pointer-events:none field is visible but unclickable by a human.
      if (style.pointerEvents === "none") continue;
      if (rect.width < 2 || rect.height < 2) continue;
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
      const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
      // Final reachability check via elementFromPoint(), which covers ancestor
      // overflow clipping, z-index covering, and anything else that blocks a real
      // click. Accepts the element, a descendant, or (for shadow DOM) the shadow host,
      // which is what a top-level elementFromPoint() returns for shadow content.
      const hit = document.elementFromPoint(cx, cy);
      const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
      if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
      // Tagged so the typing loop can re-measure the element's current position
      // right before interacting (see refreshFieldPosition()).
      const idx = results.length;
      el.setAttribute("data-hs-field-idx", String(idx));
      // "Type CONFIRM to continue" fields: takes the required word from the
      // placeholder. Requires an ALL-CAPS token so ordinary placeholders like
      // "Type your name" don't yield a word.
      const placeholderText = el.placeholder || "";
      const typePrefixMatch = placeholderText.match(/^type\s+/i);
      const confirmMatch = typePrefixMatch ? placeholderText.slice(typePrefixMatch[0].length).match(/^([A-Z][A-Z0-9_-]{1,20})\b/) : null;
      results.push({
        x: cx, y: cy, idx,
        isEmail: el.type === "email" || /e-?mail/i.test(el.name + el.id + el.placeholder + (el.getAttribute("aria-label") || "") + (el.labels ? Array.from(el.labels).map((l) => l.textContent).join(" ") : "")),
            isPassword: el.type === "password",
        isNumber: el.type === "number",
        isTextarea: el.tagName === "TEXTAREA",
        confirmWord: confirmMatch ? confirmMatch[1] : null,
        mathCaptchaAnswer,
        otpDigit: otpDigitForEl.get(el) || null,
      });
      if (results.length >= max) break;
    }
    return results;
  }, maxFields);
}

// Elements a cursor plausibly rests on (buttons, links, controls), used by the
// mouse-movement loop so hover-triggered reveals fire. Uses the same
// visibility/hit-test filtering as findVisibleTextFields(), so hidden honeypot
// elements are never hovered.
const HOVER_SAFE_SELECTOR = 'button, a[href], [role="button"], input[type="submit"], input[type="button"], input[type="checkbox"], input[type="radio"], summary, [onclick], [style*="cursor"]';

// Click targets. Plain a[href] is excluded: clicking a link navigates away from
// the page under analysis. a[download] is allowed because it saves a file
// instead of navigating (same-origin/data:/blob: URLs only; Playwright accepts
// downloads by default). Checkbox/radio are allowed since toggling them only
// changes local state.
const CLICK_SAFE_SELECTOR = 'button, [role="button"], input[type="submit"], input[type="button"], input[type="checkbox"], input[type="radio"], summary, [onclick], [style*="cursor"], a[download]';

// Finds visible, hit-testable elements matching selector. With
// includeCursorFallback, also includes elements whose computed cursor is
// pointer/grab/zoom-in/zoom-out; that full-document getComputedStyle() scan is
// costly, so findHoverableElements() disables it.
async function findInteractiveElements(page, maxEls, selector, includeCursorFallback = true) {
  return page.evaluate(({ max, sel, includeCursorFallback }) => {
    // Same shadow-DOM piercing as findVisibleTextFields().
    function deepQueryAll(root, s) {
      let out = Array.from(root.querySelectorAll(s));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, s));
      }
      return out;
    }
    // Union of explicit selector matches and elements whose computed cursor marks
    // them clickable (pointer, zoom-in/zoom-out), which covers class-styled custom
    // buttons with addEventListener() handlers. All <a> tags are excluded from the
    // cursor branch: every link gets cursor:pointer from the UA stylesheet, and
    // clicking one navigates away.
    const bySelector = deepQueryAll(document, sel);
    const candidates = bySelector.slice();
    if (includeCursorFallback) {
      const bySelectorSet = new Set(bySelector);
      for (const el of deepQueryAll(document, "*")) {
        if (bySelectorSet.has(el)) continue;
        if (el.tagName === "A") continue;
        let cursor;
        try { cursor = getComputedStyle(el).cursor; } catch (e) { continue; }
        if (cursor === "pointer" || cursor === "zoom-in" || cursor === "zoom-out") candidates.push(el);
      }
    }
    const results = [];
    for (const el of candidates) {
      if (el.disabled) continue;
      // No tabIndex<0 check here: plain divs/spans default to tabIndex -1 without
      // any honeypot intent.
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      if (style.clipPath && style.clipPath !== "none") continue;
      if (style.clip && style.clip !== "auto" && style.position !== "static") continue;
      if (style.pointerEvents === "none") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) continue;
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
      const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(cx, cy);
      // Shadow host counts as a hit; see findVisibleTextFields().
      const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
      if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
      results.push({ x: cx, y: cy });
      if (results.length >= max) break;
    }
    return results;
  }, { max: maxEls, sel: selector, includeCursorFallback });
}

// Same as findInteractiveElements(), but for same-origin iframes, with
// coordinates translated by the iframe's on-page offset. Cross-origin frames
// throw on evaluate() and are skipped.
async function findInteractiveElementsInFrames(page, maxEls, selector) {
  const results = [];
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    if (results.length >= maxEls) break;
    let frameResults;
    try {
      frameResults = await frame.evaluate(({ max, sel }) => {
        function deepQueryAll(root, s) {
          let out = Array.from(root.querySelectorAll(s));
          for (const el of root.querySelectorAll("*")) {
            if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, s));
          }
          return out;
        }
        const candidates = deepQueryAll(document, sel);
        const out = [];
        for (const el of candidates) {
          if (el.disabled) continue;
          const style = getComputedStyle(el);
          if (style.display === "none" || style.visibility === "hidden") continue;
          if (parseFloat(style.opacity) < 0.1) continue;
          if (style.clipPath && style.clipPath !== "none") continue;
          if (style.clip && style.clip !== "auto" && style.position !== "static") continue;
          if (style.pointerEvents === "none") continue;
          const rect = el.getBoundingClientRect();
          if (rect.width < 2 || rect.height < 2) continue;
          if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
          const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
          const hit = document.elementFromPoint(cx, cy);
          const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
          if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
          out.push({ x: cx, y: cy });
          if (out.length >= max) break;
        }
        return out;
      }, { max: maxEls - results.length, sel: selector });
    } catch (e) {
      continue; // cross-origin or inaccessible frame
    }
    if (!frameResults || frameResults.length === 0) continue;
    const frameElement = await frame.frameElement().catch(() => null);
    if (!frameElement) continue;
    const box = await frameElement.boundingBox().catch(() => null);
    if (!box) continue;
    for (const r of frameResults) {
      results.push({ x: box.x + r.x, y: box.y + r.y });
      if (results.length >= maxEls) break;
    }
  }
  return results;
}

async function findHoverableElements(page, maxEls) {
  const found = await findInteractiveElements(page, maxEls, HOVER_SAFE_SELECTOR, false);
  if (found.length >= maxEls) return found;
  const inFrames = await findInteractiveElementsInFrames(page, maxEls - found.length, HOVER_SAFE_SELECTOR).catch(() => []);
  return found.concat(inFrames);
}

async function findClickableElements(page, maxEls) {
  const found = await findInteractiveElements(page, maxEls, CLICK_SAFE_SELECTOR);
  if (found.length >= maxEls) return found;
  const inFrames = await findInteractiveElementsInFrames(page, maxEls - found.length, CLICK_SAFE_SELECTOR).catch(() => []);
  return found.concat(inFrames);
}

// Button-like elements for press-and-hold gates. Excludes checkboxes/radios and
// labels whose .control is a checkbox/radio: a second interaction toggles them
// back off after an earlier click checked them.
async function findHoldableElements(page, maxEls) {
  return page.evaluate((max) => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    const selector = 'button, [role="button"], input[type="submit"], input[type="button"], summary, [onclick], [style*="cursor"], a[download]';
    // Cursor-based fallback; <a> tags excluded (see findInteractiveElements()).
    const bySelector = deepQueryAll(document, selector);
    const bySelectorSet = new Set(bySelector);
    const candidates = bySelector.slice();
    for (const el of deepQueryAll(document, "*")) {
      if (bySelectorSet.has(el)) continue;
      if (el.tagName === "A") continue;
      let cursor;
      try { cursor = getComputedStyle(el).cursor; } catch (e) { continue; }
      if (cursor === "pointer" || cursor === "zoom-in" || cursor === "zoom-out") candidates.push(el);
    }
    const results = [];
    for (const el of candidates) {
      if (el.disabled) continue;
      if (el.tagName === "LABEL" && el.control && (el.control.type === "checkbox" || el.control.type === "radio")) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      if (style.clipPath && style.clipPath !== "none") continue;
      if (style.clip && style.clip !== "auto" && style.position !== "static") continue;
      if (style.pointerEvents === "none") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) continue;
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
      const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(cx, cy);
      const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
      if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
      results.push({ x: cx, y: cy });
      if (results.length >= max) break;
    }
    return results;
  }, maxEls);
}

async function pressAndHoldClickable(page, holdMs = 1500) {
  let target = null;
  try {
    const found = await findHoldableElements(page, 1);
    if (found.length > 0) target = found[0];
  } catch (e) { /* fall through: nothing to hold */ }
  if (!target) return;
  try {
    await page.mouse.move(target.x, target.y);
    await pause(page, randomBetween(100, 250));
    await page.mouse.down();
    await hold(page, holdMs);
    await page.mouse.up();
  } catch (e) { /* not fatal */ }
}

// Double-clicks a button-like element for "double-click to confirm" gates.
// Separate click steps are too far apart in time to form a native dblclick;
// mouse.click() with clickCount: 2 produces a real one.
async function doubleClickClickable(page) {
  let target = null;
  try {
    const found = await findHoldableElements(page, 1);
    if (found.length > 0) target = found[0];
  } catch (e) { /* fall through: nothing to double-click */ }
  if (!target) return;
  try {
    await page.mouse.move(target.x, target.y);
    // Short cosmetic pause; a click has no minimum duration.
    await pause(page, randomBetween(60, 120));
    await page.mouse.click(target.x, target.y, { clickCount: 2 });
  } catch (e) { /* not fatal */ }
}

// Right-clicks a button-like element for gates that wait on a 'contextmenu'
// event, which left clicks never fire.
async function rightClickClickable(page) {
  let target = null;
  try {
    const found = await findHoldableElements(page, 1);
    if (found.length > 0) target = found[0];
  } catch (e) { /* fall through: nothing to right-click */ }
  if (!target) return;
  try {
    await page.mouse.move(target.x, target.y);
    await pause(page, randomBetween(60, 120));
    await page.mouse.click(target.x, target.y, { button: "right" });
  } catch (e) { /* not fatal */ }
}

// Finds handle-in-track swipe widgets for touch-only swipe gates.
// Playwright's touchscreen only supports tap() and mouse events never produce
// touch events, so swipes are dispatched via CDP Input.dispatchTouchEvent
// (Chromium only; newCDPSession() throws on Firefox/WebKit).
async function findTouchSwipeHandles(page, maxEls) {
  return page.evaluate((max) => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    // Geometry heuristic (touch-only widgets carry no semantic marker): a small,
    // roughly square, absolutely positioned handle inside a much wider track of
    // similar height.
    const candidates = deepQueryAll(document, "div, span, a, button");
    const results = [];
    for (const el of candidates) {
      if (results.length >= max) break;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      if (style.pointerEvents === "none") continue;
      if (style.position !== "absolute" && style.position !== "fixed") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 20 || rect.width > 90) continue;
      if (rect.height < 20 || rect.height > 90) continue;
      const aspect = rect.width / rect.height;
      if (aspect < 0.5 || aspect > 2) continue;
      const parent = el.parentElement;
      if (!parent) continue;
      const prect = parent.getBoundingClientRect();
      if (prect.width < rect.width * 2) continue;
      if (prect.height > rect.height * 2.5) continue;
      if (rect.top < 0 || rect.left < 0 || rect.bottom > innerHeight || rect.right > innerWidth) continue;
      const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
      if (!hit || (hit !== el && !el.contains(hit))) continue;
      results.push({
        x: rect.left + rect.width / 2, y: rect.top + rect.height / 2,
        width: rect.width,
        trackRight: prect.right, trackTop: prect.top, trackHeight: prect.height,
      });
    }
    return results;
  }, maxEls);
}

// Swipes the first found handle across its track via CDP touch events.
// sharedCdp: an open CDP session to reuse instead of opening and detaching a new
// one (see the humanize() call site).
async function performTouchSwipe(page, sharedCdp) {
  try {
    const browser = page.context().browser();
    if (!browser || browser.browserType().name() !== "chromium") return;
  } catch (e) { return; }
  let handles;
  try {
    handles = await findTouchSwipeHandles(page, 2);
  } catch (e) { return; }
  if (!handles || handles.length === 0) return;
  const handle = handles[0];
  const startX = handle.x, startY = handle.y;
  const endX = handle.trackRight - handle.width / 2 - 4;
  const endY = handle.trackTop + handle.trackHeight / 2;
  let cdp = sharedCdp;
  if (!cdp) {
    try {
      cdp = await page.context().newCDPSession(page);
    } catch (e) { return; }
  }
  try {
    await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: startX, y: startY }] });
    const steps = Math.round(randomBetween(8, 14));
    for (let i = 1; i <= steps; i++) {
      const t = i / steps;
      const x = startX + (endX - startX) * t;
      const y = startY + (endY - startY) * t;
      await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x, y }] });
      await pause(page, randomBetween(20, 60));
    }
    await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
  } catch (e) { /* not fatal */ }
  if (!sharedCdp) {
    try { await cdp.detach(); } catch (e) { /* not fatal */ }
  }
}

// Finds full-area swipe-up surfaces (lock-screen style) that have no handle.
// Detected by CSS touch-action none/pan-x/pan-y, which custom touch-gesture
// handlers set to suppress native scrolling and zooming.
async function findSwipeUpAreas(page, maxEls) {
  return page.evaluate((max) => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    const results = [];
    for (const el of deepQueryAll(document, "*")) {
      if (el === document.body || el === document.documentElement) continue;
      // Canvas drawing surfaces also set touch-action:none; drawOnCanvases()
      // handles them.
      if (el.tagName === "CANVAS") continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      const ta = style.touchAction;
      if (ta !== "none" && ta !== "pan-x" && !ta.startsWith("pan-x ")) continue;
      const rect = el.getBoundingClientRect();
      // Gesture surfaces are large; excludes small icons with the same touch-action.
      if (rect.width < 80 || rect.height < 80) continue;
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
      const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
      const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
      if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
      results.push({
        startX: rect.left + rect.width / 2, startY: rect.bottom - Math.min(20, rect.height / 4),
        endX: rect.left + rect.width / 2, endY: rect.top + Math.min(20, rect.height / 4),
      });
      if (results.length >= max) break;
    }
    return results;
  }, maxEls);
}

async function performSwipeUp(page, sharedCdp) {
  try {
    const browser = page.context().browser();
    if (!browser || browser.browserType().name() !== "chromium") return;
  } catch (e) { return; }
  let areas;
  try {
    areas = await findSwipeUpAreas(page, 1);
  } catch (e) { return; }
  if (!areas || areas.length === 0) return;
  const area = areas[0];
  let cdp = sharedCdp;
  if (!cdp) {
    try {
      cdp = await page.context().newCDPSession(page);
    } catch (e) { return; }
  }
  try {
    await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: area.startX, y: area.startY }] });
    const steps = Math.round(randomBetween(8, 14));
    for (let i = 1; i <= steps; i++) {
      const t = i / steps;
      const x = area.startX + (area.endX - area.startX) * t;
      const y = area.startY + (area.endY - area.startY) * t;
      await cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x, y }] });
      await pause(page, randomBetween(20, 60));
    }
    await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
  } catch (e) { /* not fatal */ }
  if (!sharedCdp) {
    try { await cdp.detach(); } catch (e) { /* not fatal */ }
  }
}

// Touch long-press (CDP touchStart, ~650-800ms wait with no touchMove,
// touchEnd) for gates listening only to touch events; pressAndHoldClickable()
// uses mouse events. Targets come from findHoldableElements(). Chromium only.
async function performTouchLongPress(page, sharedCdp) {
  try {
    const browser = page.context().browser();
    if (!browser || browser.browserType().name() !== "chromium") return;
  } catch (e) { return; }
  let target = null;
  try {
    const found = await findHoldableElements(page, 1);
    if (found.length > 0) target = found[0];
  } catch (e) { /* fall through: nothing to long-press */ }
  if (!target) return;
  let cdp = sharedCdp;
  if (!cdp) {
    try {
      cdp = await page.context().newCDPSession(page);
    } catch (e) { return; }
  }
  try {
    await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: target.x, y: target.y }] });
    await hold(page, randomBetween(650, 850));
    await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
  } catch (e) { /* not fatal */ }
  if (!sharedCdp) {
    try { await cdp.detach(); } catch (e) { /* not fatal */ }
  }
}

// Finds a large, non-interactive, zoomable-looking surface (media or similar).
// performTouchPinch() below pinches open on it with two simultaneous CDP touch
// points (for gates checking e.touches.length === 2), then pinches back closed.
// Both bail out when no surface is found. Chromium only.
async function findPinchableSurfaces(page) {
  return page.evaluate(() => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    const candidates = deepQueryAll(document, "img, canvas, video, svg, div, section, figure");
    const results = [];
    for (const el of candidates) {
      if (el === document.body || el === document.documentElement) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      // Click-family targets are not pinch surfaces.
      if (style.cursor === "pointer") continue;
      const tag = el.tagName.toLowerCase();
      const isMedia = tag === "img" || tag === "canvas" || tag === "video" || tag === "svg";
      const rect = el.getBoundingClientRect();
      if (rect.width < 120 || rect.height < 120) continue;
      // Excludes page-layout wrappers.
      if (!isMedia && rect.width > innerWidth * 0.7 && rect.height > innerHeight * 0.7) continue;
      if (!isMedia && el.children.length > 0) continue;
      if (rect.top < 0 || rect.left < 0 || rect.bottom > innerHeight || rect.right > innerWidth) continue;
      const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
      if (!hit || (hit !== el && !el.contains(hit))) continue;
      results.push({ x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 });
      break;
    }
    return results;
  });
}

async function performTouchPinch(page, sharedCdp) {
  try {
    const browser = page.context().browser();
    if (!browser || browser.browserType().name() !== "chromium") return;
  } catch (e) { return; }
  let surfaces;
  try {
    surfaces = await findPinchableSurfaces(page);
  } catch (e) { return; }
  if (!surfaces || surfaces.length === 0) return;
  const cx = surfaces[0].x, cy = surfaces[0].y;
  let cdp = sharedCdp;
  if (!cdp) {
    try {
      cdp = await page.context().newCDPSession(page);
    } catch (e) { return; }
  }
  try {
    const startHalfDist = randomBetween(8, 15);
    const endHalfDist = randomBetween(90, 130);
    async function pinchStep(fromHalf, toHalf, steps, minWait, maxWait) {
      for (let i = 0; i <= steps; i++) {
        const t = i / steps;
        const halfDist = fromHalf + (toHalf - fromHalf) * t;
        const points = [
          { x: cx - halfDist, y: cy, id: 0 },
          { x: cx + halfDist, y: cy, id: 1 },
        ];
        await cdp.send("Input.dispatchTouchEvent", { type: i === 0 ? "touchStart" : "touchMove", touchPoints: points });
        await pause(page, randomBetween(minWait, maxWait));
      }
      await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
    }
    // Open pinch, at a human-looking pace.
    await pinchStep(startHalfDist, endHalfDist, Math.round(randomBetween(5, 7)), 15, 30);
    // Pinch back to the starting distance: the open pinch also triggers Chromium's
    // native pinch-zoom, and visualViewport.scale != 1 makes every later
    // coordinate-based action miss (getBoundingClientRect() stays in layout
    // coordinates). Kept fast; nothing on the page watches this half.
    await pinchStep(endHalfDist, startHalfDist, 2, 8, 15);
  } catch (e) { /* not fatal */ }
  if (!sharedCdp) {
    try { await cdp.detach(); } catch (e) { /* not fatal */ }
  }
}

// Rotates the emulated screen (CDP Emulation.setDeviceMetricsOverride with
// screenOrientation) to fire screen.orientation 'change' for "rotate your device"
// gates, then reverts width/height/orientation so later coordinate-based steps
// see the original viewport. Chromium only, and only on touch-capable profiles.
async function performOrientationFlip(page, sharedCdp) {
  try {
    const browser = page.context().browser();
    if (!browser || browser.browserType().name() !== "chromium") return;
  } catch (e) { return; }
  let isTouchCapable = false;
  try {
    isTouchCapable = await page.evaluate(() => navigator.maxTouchPoints > 0);
  } catch (e) { return; }
  if (!isTouchCapable) return;
  const viewport = page.viewportSize();
  if (!viewport) return;
  let cdp = sharedCdp;
  if (!cdp) {
    try {
      cdp = await page.context().newCDPSession(page);
    } catch (e) { return; }
  }
  try {
    const isPortrait = viewport.height >= viewport.width;
    await cdp.send("Emulation.setDeviceMetricsOverride", {
      width: viewport.height, height: viewport.width, deviceScaleFactor: 0, mobile: true,
      screenOrientation: isPortrait ? { type: "landscapePrimary", angle: 90 } : { type: "portraitPrimary", angle: 0 },
    });
    // 'change' fires as soon as the override applies; this just clears one tick.
    await pause(page, randomBetween(80, 150));
    // Revert immediately; later steps rely on the original viewport.
    await cdp.send("Emulation.setDeviceMetricsOverride", {
      width: viewport.width, height: viewport.height, deviceScaleFactor: 0, mobile: true,
      screenOrientation: isPortrait ? { type: "portraitPrimary", angle: 0 } : { type: "landscapePrimary", angle: 90 },
    });
  } catch (e) { /* not fatal */ }
  if (!sharedCdp) {
    try { await cdp.detach(); } catch (e) { /* not fatal */ }
  }
}

// Simulates a phone tilt via CDP DeviceOrientation.setDeviceOrientationOverride,
// for gates requiring beta to change from its baseline reading. Chromium only,
// touch-capable profiles only.
async function performDeviceTilt(page, sharedCdp) {
  try {
    const browser = page.context().browser();
    if (!browser || browser.browserType().name() !== "chromium") return;
  } catch (e) { return; }
  let isTouchCapable = false;
  try {
    isTouchCapable = await page.evaluate(() => navigator.maxTouchPoints > 0);
  } catch (e) { return; }
  if (!isTouchCapable) return;
  let cdp = sharedCdp;
  if (!cdp) {
    try {
      cdp = await page.context().newCDPSession(page);
    } catch (e) { return; }
  }
  try {
    const baseBeta = randomBetween(-10, 10);
    await cdp.send("DeviceOrientation.setDeviceOrientationOverride", { alpha: randomBetween(0, 360), beta: baseBeta, gamma: randomBetween(-10, 10) });
    await pause(page, randomBetween(60, 100));
    const tiltedBeta = baseBeta + (Math.random() < 0.5 ? 1 : -1) * randomBetween(30, 60);
    await cdp.send("DeviceOrientation.setDeviceOrientationOverride", { alpha: randomBetween(0, 360), beta: tiltedBeta, gamma: randomBetween(-10, 10) });
    // Required: cdp.send() resolving does not guarantee the event reached the
    // renderer, and detaching right away can cut off its delivery.
    await pause(page, randomBetween(60, 100));
  } catch (e) { /* not fatal */ }
  if (!sharedCdp) {
    try { await cdp.detach(); } catch (e) { /* not fatal */ }
  }
}

// Fires a real back-navigation for pages that pushState() a step and only reveal on popstate.
// Runs only when history.state is non-null (pushState was called on this page), because a back
// navigation reloads the document and would discard state built by earlier typing.
// Uses in-page history.back(): Playwright's page.goBack() is a silent no-op on Firefox.
// If the navigation left the original origin+pathname, history.forward() restores it.
async function performHistoryBack(page) {
  let beforeUrl;
  try {
    beforeUrl = page.url();
  } catch (e) { return; }
  let historyLength, hasPushedState;
  try {
    historyLength = await page.evaluate(() => history.length);
    hasPushedState = await page.evaluate(() => history.state !== null && history.state !== undefined);
  } catch (e) { return; }
  if (historyLength < 2 || !hasPushedState) return;
  try {
    await page.evaluate(() => history.back());
  } catch (e) { return; }
  await pause(page, randomBetween(200, 400));
  let afterUrl;
  try {
    afterUrl = page.url();
  } catch (e) { afterUrl = null; }
  let samePage = false;
  try {
    const before = new URL(beforeUrl);
    const after = new URL(afterUrl);
    samePage = before.origin === after.origin && before.pathname === after.pathname;
  } catch (e) { /* samePage stays false: treat as unsafe, restore below */ }
  if (!samePage) {
    try {
      await page.evaluate(() => history.forward());
    } catch (e) { /* not fatal */ }
  }
}

// Moves the cursor out through the top edge of the viewport (mouseout with relatedTarget null,
// clientY <= 0) to trigger exit-intent overlays. Other mouse moves are clamped away from the edges.
// Movement only, so it is not gated behind allowClicks.
async function performExitIntentMove(page) {
  const viewport = page.viewportSize() || { width: 1280, height: 800 };
  try {
    const startX = randomBetween(viewport.width * 0.3, viewport.width * 0.7);
    await page.mouse.move(startX, randomBetween(20, 60));
    await pause(page, randomBetween(80, 180));
    await page.mouse.move(startX + randomBetween(-40, 40), randomBetween(-20, -5), { steps: 4 });
  } catch (e) { /* not fatal */ }
}

// Finds prose blocks for a select-text gate and tags them with data-hs-select-idx so a Locator
// can be built (selectText() needs a Locator, not coordinates). Skips text inside controls and
// prefers leaf blocks over containers.
async function findSelectableTextBlocks(page, maxEls) {
  return page.evaluate((max) => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    // Headings are excluded: a select-text gate targets prose, and page titles come first in document order.
    const candidates = deepQueryAll(document, "p, span, li, td, blockquote, div");
    const results = [];
    for (const el of candidates) {
      if (results.length >= max) break;
      if (el.closest("button, a, input, textarea, select, [role='button']")) continue;
      // Skip shared page chrome (metadata badge, banner, footer nav).
      if (el.closest(".meta, .banner, .footer-nav")) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      if (style.userSelect === "none" || style.webkitUserSelect === "none") continue;
      const text = (el.textContent || "").trim();
      if (text.length < 15 || text.length > 400) continue;
      // Prefer leaf text: skip elements that contain further block-level children.
      const hasBlockChildren = Array.from(el.children).some((child) => {
        const childStyle = getComputedStyle(child);
        return childStyle.display !== "inline" && childStyle.display !== "none";
      });
      if (hasBlockChildren) continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 10 || rect.height < 10) continue;
      if (rect.top < 0 || rect.left < 0 || rect.bottom > innerHeight || rect.right > innerWidth) continue;
      const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(cx, cy);
      const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
      if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
      const idx = results.length;
      el.setAttribute("data-hs-select-idx", String(idx));
      results.push({ idx });
    }
    return results;
  }, maxEls);
}

// Drag-selects a text block with selectText() (real selection + selectionchange), then presses
// Ctrl/Cmd+C so the browser fires a real 'copy' event for copy-the-code gates.
async function performTextSelection(page) {
  let candidates;
  try {
    candidates = await findSelectableTextBlocks(page, 1);
  } catch (e) { return; }
  if (!candidates || candidates.length === 0) return;
  try {
    await page.locator(`[data-hs-select-idx="${candidates[0].idx}"]`).selectText();
    // Short grace period; selectText() already waits for the selection to apply.
    await pause(page, randomBetween(40, 90));
    noteClipboard(await page.evaluate(() => String(window.getSelection())).catch(() => ""));
    await page.keyboard.press("ControlOrMeta+C");
  } catch (e) { /* not fatal */ }
  try {
    await page.evaluate(() => {
      document.querySelectorAll("[data-hs-select-idx]").forEach((el) => el.removeAttribute("data-hs-select-idx"));
    });
  } catch (e) { /* not fatal */ }
}

// Resizes the actual browser window via CDP (Browser.setWindowBounds) and restores it, for pages
// with no emulated viewport. Fires real 'resize' events. Chromium only.
async function resizeRealWindow(page) {
  let cdp;
  try { cdp = await page.context().newCDPSession(page); } catch (e) { return; }
  try {
    const { windowId, bounds } = await cdp.send("Browser.getWindowForTarget");
    const screenW = await page.evaluate(() => screen.availWidth).catch(() => bounds.width);
    const room = screenW - bounds.width;
    const delta = Math.round(Math.min(randomBetween(180, 280), room));
    // Widen if there is room; a full-width window is narrowed and widened back instead.
    if (delta >= 160) {
      // Widen; drag the left edge too when the right side has no room.
      const left = Math.max(0, Math.min(bounds.left, screenW - (bounds.width + delta)));
      await cdp.send("Browser.setWindowBounds", { windowId, bounds: { left, width: bounds.width + delta } });
      await pause(page, randomBetween(250, 450));
    } else {
      // No room to widen (a maximized window): narrow, then widen back, as a person would.
      const shrink = Math.round(randomBetween(180, 280));
      await cdp.send("Browser.setWindowBounds", { windowId, bounds: { width: bounds.width - shrink } });
      await pause(page, randomBetween(400, 700));
      await cdp.send("Browser.setWindowBounds", { windowId, bounds: { width: bounds.width } });
      await pause(page, randomBetween(250, 450));
    }
    await cdp.send("Browser.setWindowBounds", { windowId, bounds: { left: bounds.left, top: bounds.top, width: bounds.width, height: bounds.height } }).catch(() => {});
  } catch (e) { /* not fatal */ } finally {
    await cdp.detach().catch(() => {});
  }
}

async function performWindowResize(page) {
  const original = page.viewportSize();
  if (!original) return resizeRealWindow(page);
  try {
    await page.setViewportSize({ width: original.width + Math.round(randomBetween(180, 280)), height: original.height });
    // Short grace period; setViewportSize() already waits for the new size to apply.
    await pause(page, randomBetween(60, 120));
  } catch (e) { /* not fatal */ }
  try {
    await page.setViewportSize(original);
  } catch (e) { /* not fatal */ }
}

// Exits pointer lock if a page engaged it. While locked, mouse input is relative, so later
// coordinate-based clicks silently miss. Called at several points in the click phase because any
// ordinary click can trigger the lock.
async function releasePointerLockIfEngaged(page) {
  try {
    const wasLocked = await page.evaluate(() => {
      if (!document.pointerLockElement) return false;
      document.exitPointerLock();
      return true;
    });
    if (wasLocked) {
      await pause(page, randomBetween(30, 80));
    }
  } catch (e) { /* not fatal */ }
}

// findHoldableElements() for same-origin iframes; coordinates are translated into top-page space
// via the iframe's boundingBox(). Keeps the same exclusion of labels bound to checkboxes/radios.
async function findHoldableElementsInFrames(page, maxEls) {
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    let found;
    try {
      found = await frame.evaluate((max) => {
        const selector = 'button, [role="button"], input[type="submit"], input[type="button"], summary, [onclick], [style*="cursor"], a[download]';
        // Class-styled buttons are matched by computed cursor:pointer; <a> tags are excluded from that fallback.
        const bySelector = Array.from(document.querySelectorAll(selector));
        const bySelectorSet = new Set(bySelector);
        const candidates = bySelector.slice();
        for (const el of document.querySelectorAll("*")) {
          if (bySelectorSet.has(el)) continue;
          if (el.tagName === "A") continue;
          let cursor;
          try { cursor = getComputedStyle(el).cursor; } catch (e) { continue; }
          if (cursor === "pointer" || cursor === "zoom-in" || cursor === "zoom-out") candidates.push(el);
        }
        const results = [];
        for (const el of candidates) {
          if (el.disabled) continue;
          if (el.tagName === "LABEL" && el.control && (el.control.type === "checkbox" || el.control.type === "radio")) continue;
          const style = getComputedStyle(el);
          if (style.display === "none" || style.visibility === "hidden") continue;
          if (parseFloat(style.opacity) < 0.1) continue;
          if (style.pointerEvents === "none") continue;
          const rect = el.getBoundingClientRect();
          if (rect.width < 2 || rect.height < 2) continue;
          if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
          const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
          const hit = document.elementFromPoint(cx, cy);
          if (!hit || (hit !== el && !el.contains(hit))) continue;
          results.push({ x: cx, y: cy });
          if (results.length >= max) break;
        }
        return results;
      }, maxEls);
    } catch (e) {
      continue; // cross-origin (or otherwise inaccessible) frame: skip it
    }
    if (!found || found.length === 0) continue;
    const frameElement = await frame.frameElement().catch(() => null);
    if (!frameElement) continue;
    const box = await frameElement.boundingBox().catch(() => null);
    if (!box) continue;
    return found.map((f) => ({ x: box.x + f.x, y: box.y + f.y }));
  }
  return [];
}

async function pressAndHoldClickableInFrames(page, holdMs = 1500) {
  let targets;
  try {
    targets = await findHoldableElementsInFrames(page, 1);
  } catch (e) {
    return;
  }
  if (!targets || targets.length === 0) return;
  const target = targets[0];
  try {
    await page.mouse.move(target.x, target.y);
    await pause(page, randomBetween(100, 250));
    await page.mouse.down();
    await hold(page, holdMs);
    await page.mouse.up();
  } catch (e) { /* not fatal */ }
}

// Clicks through multi-step wizards whose next button only appears after the previous click.
// Uses the narrower holdable selector (no checkbox/radio inputs) and skips labels bound to a
// checkbox/radio, since clicking those toggles the control. Clicked elements are marked with
// data-hs-wizard-clicked; rounds are bounded by maxRounds.
async function clickThroughSequentialSteps(page, maxRounds = 3) {
  const selector = 'button, [role="button"], input[type="submit"], input[type="button"], summary, [onclick], [style*="cursor"], a[download]';
  for (let round = 0; round < maxRounds; round++) {
    let target;
    try {
      target = await page.evaluate((sel) => {
        function deepQueryAll(root, s) {
          let out = Array.from(root.querySelectorAll(s));
          for (const el of root.querySelectorAll("*")) {
            if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, s));
          }
          return out;
        }
        // Class-styled buttons are matched by computed cursor:pointer; <a> tags are excluded from that fallback.
        const bySelector = deepQueryAll(document, sel);
        const bySelectorSet = new Set(bySelector);
        const candidates = bySelector.slice();
        for (const el of deepQueryAll(document, "*")) {
          if (bySelectorSet.has(el)) continue;
          if (el.tagName === "A") continue;
          let cursor;
          try { cursor = getComputedStyle(el).cursor; } catch (e) { continue; }
          if (cursor === "pointer" || cursor === "zoom-in" || cursor === "zoom-out") candidates.push(el);
        }
        for (const el of candidates) {
          if (el.disabled) continue;
          if (el.hasAttribute("data-hs-wizard-clicked")) continue;
          if (el.tagName === "LABEL" && el.control && (el.control.type === "checkbox" || el.control.type === "radio")) continue;
          const style = getComputedStyle(el);
          if (style.display === "none" || style.visibility === "hidden") continue;
          if (parseFloat(style.opacity) < 0.1) continue;
          if (style.pointerEvents === "none") continue;
          const rect = el.getBoundingClientRect();
          if (rect.width < 2 || rect.height < 2) continue;
          if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
          const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
          const hit = document.elementFromPoint(cx, cy);
          const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
          if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
          el.setAttribute("data-hs-wizard-clicked", "1");
          return { x: cx, y: cy };
        }
        return null;
      }, selector);
    } catch (e) {
      break;
    }
    if (!target) break;
    try {
      let tapped = false;
      try {
        await page.touchscreen.tap(target.x, target.y);
        tapped = true;
      } catch (e) { /* no touch support on this profile; fall back below */ }
      if (!tapped) {
        await page.mouse.click(target.x, target.y);
      }
    } catch (e) { /* not fatal; stop rather than guess further */ }
    await pause(page, randomBetween(300, 700));
  }
  await page.evaluate(() => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    deepQueryAll(document, "[data-hs-wizard-clicked]").forEach((el) => el.removeAttribute("data-hs-wizard-clicked"));
  }).catch(() => {});
}

// clickThroughSequentialSteps() for same-origin iframes, with the same label-for-checkbox exclusion.
async function clickThroughSequentialStepsInFrames(page, maxRounds = 3) {
  const selector = 'button, [role="button"], input[type="submit"], input[type="button"], summary, [onclick], [style*="cursor"], a[download]';
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    let handledAny = false;
    for (let round = 0; round < maxRounds; round++) {
      let target;
      try {
        target = await frame.evaluate((sel) => {
          // Class-styled buttons are matched by computed cursor:pointer; <a> tags are excluded from that fallback.
          const bySelector = Array.from(document.querySelectorAll(sel));
          const bySelectorSet = new Set(bySelector);
          const candidates = bySelector.slice();
          for (const el of document.querySelectorAll("*")) {
            if (bySelectorSet.has(el)) continue;
            if (el.tagName === "A") continue;
            let cursor;
            try { cursor = getComputedStyle(el).cursor; } catch (e) { continue; }
            if (cursor === "pointer" || cursor === "zoom-in" || cursor === "zoom-out") candidates.push(el);
          }
          for (const el of candidates) {
            if (el.disabled) continue;
            if (el.hasAttribute("data-hs-wizard-clicked")) continue;
            if (el.tagName === "LABEL" && el.control && (el.control.type === "checkbox" || el.control.type === "radio")) continue;
            const style = getComputedStyle(el);
            if (style.display === "none" || style.visibility === "hidden") continue;
            if (parseFloat(style.opacity) < 0.1) continue;
            if (style.pointerEvents === "none") continue;
            const rect = el.getBoundingClientRect();
            if (rect.width < 2 || rect.height < 2) continue;
            if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
            const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
            const hit = document.elementFromPoint(cx, cy);
            if (!hit || (hit !== el && !el.contains(hit))) continue;
            el.setAttribute("data-hs-wizard-clicked", "1");
            return { x: cx, y: cy };
          }
          return null;
        }, selector);
      } catch (e) {
        break; // cross-origin (or otherwise inaccessible) frame: skip it
      }
      if (!target) break;
      handledAny = true;
      const frameElement = await frame.frameElement().catch(() => null);
      if (!frameElement) break;
      const box = await frameElement.boundingBox().catch(() => null);
      if (!box) break;
      const pageX = box.x + target.x, pageY = box.y + target.y;
      try {
        let tapped = false;
        try {
          await page.touchscreen.tap(pageX, pageY);
          tapped = true;
        } catch (e) { /* no touch support on this profile; fall back below */ }
        if (!tapped) {
          await page.mouse.click(pageX, pageY);
        }
      } catch (e) { /* not fatal; stop rather than guess further */ }
      await pause(page, randomBetween(300, 700));
    }
    await frame.evaluate(() => {
      document.querySelectorAll("[data-hs-wizard-clicked]").forEach((el) => el.removeAttribute("data-hs-wizard-clicked"));
    }).catch(() => {});
    if (handledAny) break;
  }
}

// Finds a drag-to-unlock slider handle ([role="slider"]) and its track container, so the caller can
// drag a real distance. A single click never starts a drag.
async function findSliderElement(page) {
  return page.evaluate(() => {
    // Pierces open shadow roots, like findVisibleTextFields().
    function deepQuery(root, selector) {
      const found = root.querySelector(selector);
      if (found) return found;
      for (const child of root.querySelectorAll("*")) {
        if (child.shadowRoot) {
          const inner = deepQuery(child.shadowRoot, selector);
          if (inner) return inner;
        }
      }
      return null;
    }
    // Fallback when no [role="slider"] exists: custom handles styled with cursor:grab/grabbing.
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    let el = deepQuery(document, '[role="slider"]');
    if (!el) {
      for (const candidate of deepQueryAll(document, "*")) {
        let cursor;
        try { cursor = getComputedStyle(candidate).cursor; } catch (e) { continue; }
        if (cursor === "grab" || cursor === "grabbing") { el = candidate; break; }
      }
    }
    if (!el) return null;
    const style = getComputedStyle(el);
    if (style.display === "none" || style.visibility === "hidden") return null;
    if (parseFloat(style.opacity) < 0.1) return null;
    if (style.pointerEvents === "none") return null;
    const rect = el.getBoundingClientRect();
    if (rect.width < 2 || rect.height < 2) return null;
    const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
    // The hit-test may return the shadow host rather than the element itself.
    const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
    if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) return null;
    const container = el.parentElement ? el.parentElement.getBoundingClientRect() : rect;
    return {
      x: rect.left + rect.width / 2, y: rect.top + rect.height / 2,
      width: rect.width, containerRight: container.right, containerTop: container.top, containerHeight: container.height,
    };
  });
}

// findSliderElement() for same-origin iframes. Every position field (handle and container) is
// offset by the iframe's on-page position.
async function findSliderElementInFrames(page) {
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    let slider;
    try {
      slider = await frame.evaluate(() => {
        function deepQuery(root, selector) {
          const found = root.querySelector(selector);
          if (found) return found;
          for (const child of root.querySelectorAll("*")) {
            if (child.shadowRoot) {
              const inner = deepQuery(child.shadowRoot, selector);
              if (inner) return inner;
            }
          }
          return null;
        }
        // Same cursor:grab fallback as findSliderElement().
        function deepQueryAll(root, selector) {
          let out = Array.from(root.querySelectorAll(selector));
          for (const el of root.querySelectorAll("*")) {
            if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
          }
          return out;
        }
        let el = deepQuery(document, '[role="slider"]');
        if (!el) {
          for (const candidate of deepQueryAll(document, "*")) {
            let cursor;
            try { cursor = getComputedStyle(candidate).cursor; } catch (e) { continue; }
            if (cursor === "grab" || cursor === "grabbing") { el = candidate; break; }
          }
        }
        if (!el) return null;
        const style = getComputedStyle(el);
        if (style.display === "none" || style.visibility === "hidden") return null;
        if (parseFloat(style.opacity) < 0.1) return null;
        if (style.pointerEvents === "none") return null;
        const rect = el.getBoundingClientRect();
        if (rect.width < 2 || rect.height < 2) return null;
        const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
        const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
        if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) return null;
        const container = el.parentElement ? el.parentElement.getBoundingClientRect() : rect;
        return {
          x: rect.left + rect.width / 2, y: rect.top + rect.height / 2,
          width: rect.width, containerRight: container.right, containerTop: container.top, containerHeight: container.height,
        };
      });
    } catch (e) {
      continue; // cross-origin (or otherwise inaccessible) frame: skip it
    }
    if (!slider) continue;
    const frameElement = await frame.frameElement().catch(() => null);
    if (!frameElement) continue;
    const box = await frameElement.boundingBox().catch(() => null);
    if (!box) continue;
    return {
      x: box.x + slider.x, y: box.y + slider.y, width: slider.width,
      containerRight: box.x + slider.containerRight, containerTop: box.y + slider.containerTop,
      containerHeight: slider.containerHeight,
    };
  }
  return null;
}

async function dragSlider(page, slider) {
  const startX = slider.x, startY = slider.y;
  // Stop about half a handle short of the track's right edge, as a real drag would.
  const endX = slider.containerRight - slider.width / 2 - 4;
  const endY = slider.containerTop + slider.containerHeight / 2;
  await page.mouse.move(startX, startY);
  await page.mouse.down();
  const steps = Math.round(randomBetween(8, 14));
  for (let i = 1; i <= steps; i++) {
    const t = i / steps;
    const x = startX + (endX - startX) * t;
    const y = startY + (endY - startY) * t;
    await page.mouse.move(x, y, { steps: 2 });
    await pause(page, randomBetween(20, 60));
  }
  await page.mouse.up();
}

// Finds visible native <input type="range"> elements and computes each thumb's position from
// min/max/value (defaults 0/100). Their implicit slider role does not match [role="slider"].
// Applies the same visibility and hit-test honeypot checks as the text-field finder.
async function findNativeRangeInputs(page, maxEls) {
  return page.evaluate((max) => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    const candidates = deepQueryAll(document, 'input[type="range"]');
    const results = [];
    for (const el of candidates) {
      if (el.disabled || el.readOnly) continue;
      if (el.tabIndex < 0) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      if (style.clipPath && style.clipPath !== "none") continue;
      if (style.clip && style.clip !== "auto" && style.position !== "static") continue;
      if (style.pointerEvents === "none") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) continue;
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
      const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(cx, cy);
      const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
      if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
      const min = el.min !== "" ? Number(el.min) : 0;
      const max = el.max !== "" ? Number(el.max) : 100;
      const value = el.value !== "" ? Number(el.value) : (min + max) / 2;
      const frac = max > min ? (value - min) / (max - min) : 0.5;
      const idx = results.length;
      el.setAttribute("data-hs-range-idx", String(idx));
      results.push({
        idx,
        startX: rect.left + rect.width * frac,
        y: rect.top + rect.height / 2,
        left: rect.left, right: rect.right, width: rect.width,
      });
      if (results.length >= max) break;
    }
    return results;
  }, maxEls);
}

// Moves each native range thumb most of the way toward its max, then presses ArrowRight a few
// times as a keyboard reinforcement (arrow-key stepping works on every engine).
async function dragNativeRangeInputs(page, maxEls = 2) {
  let candidates;
  try {
    candidates = await findNativeRangeInputs(page, maxEls);
  } catch (e) {
    return;
  }
  for (const range of candidates) {
    try {
      const targetFrac = randomBetween(0.75, 0.95);
      const endX = range.left + range.width * targetFrac;
      // Click the track first to jump the thumb: on Firefox a drag starting off the thumb registers
      // no change, while a click anywhere on the track works on every engine.
      await page.mouse.click(endX, range.y);
      await pause(page, randomBetween(100, 250));
      // Then a short drag nudge from the thumb's new position.
      const nudgeStartX = Math.max(range.left, endX - range.width * 0.05);
      await page.mouse.move(nudgeStartX, range.y);
      await page.mouse.down();
      const steps = Math.round(randomBetween(4, 8));
      for (let i = 1; i <= steps; i++) {
        const t = i / steps;
        const x = nudgeStartX + (endX - nudgeStartX) * t;
        await page.mouse.move(x, range.y, { steps: 2 });
        await pause(page, randomBetween(20, 60));
      }
      await page.mouse.up();
      await pause(page, randomBetween(100, 250));
      const nudges = Math.round(randomBetween(2, 5));
      for (let i = 0; i < nudges; i++) {
        await page.keyboard.press("ArrowRight").catch(() => {});
        await pause(page, randomBetween(30, 90));
      }
    } catch (e) { /* not fatal; move on to the next candidate */ }
  }
  await page.evaluate(() => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    deepQueryAll(document, "[data-hs-range-idx]").forEach((el) => el.removeAttribute("data-hs-range-idx"));
  }).catch(() => {});
}

// findNativeRangeInputs() for same-origin iframes; positions are offset by the iframe's on-page position.
async function findNativeRangeInputsInFrames(page, maxEls) {
  const results = [];
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    if (results.length >= maxEls) break;
    let candidates;
    try {
      candidates = await frame.evaluate((max) => {
        const els = Array.from(document.querySelectorAll('input[type="range"]'));
        const out = [];
        for (const el of els) {
          if (el.disabled || el.readOnly) continue;
          const style = getComputedStyle(el);
          if (style.display === "none" || style.visibility === "hidden") continue;
          if (parseFloat(style.opacity) < 0.1) continue;
          if (style.pointerEvents === "none") continue;
          const rect = el.getBoundingClientRect();
          if (rect.width < 2 || rect.height < 2) continue;
          if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
          const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
          if (!hit || (hit !== el && !el.contains(hit))) continue;
          const min = el.min !== "" ? Number(el.min) : 0;
          const max2 = el.max !== "" ? Number(el.max) : 100;
          const value = el.value !== "" ? Number(el.value) : (min + max2) / 2;
          const frac = max2 > min ? (value - min) / (max2 - min) : 0.5;
          out.push({ startX: rect.left + rect.width * frac, y: rect.top + rect.height / 2, left: rect.left, width: rect.width });
          if (out.length >= max) break;
        }
        return out;
      }, maxEls - results.length);
    } catch (e) {
      continue; // cross-origin (or otherwise inaccessible) frame: skip it
    }
    if (!candidates || candidates.length === 0) continue;
    const frameElement = await frame.frameElement().catch(() => null);
    if (!frameElement) continue;
    const box = await frameElement.boundingBox().catch(() => null);
    if (!box) continue;
    for (const c of candidates) {
      results.push({ startX: box.x + c.startX, y: box.y + c.y, left: box.x + c.left, width: c.width });
      if (results.length >= maxEls) break;
    }
  }
  return results;
}

// Same click, nudge and arrow-key sequence as dragNativeRangeInputs(), on iframe candidates
// already translated to top-page coordinates. Keyboard input goes to the focused element in any frame.
async function dragNativeRangeInputsInFrames(page, maxEls = 2) {
  let candidates;
  try {
    candidates = await findNativeRangeInputsInFrames(page, maxEls);
  } catch (e) {
    return;
  }
  for (const range of candidates) {
    try {
      const targetFrac = randomBetween(0.75, 0.95);
      const endX = range.left + range.width * targetFrac;
      await page.mouse.click(endX, range.y);
      await pause(page, randomBetween(100, 250));
      const nudgeStartX = Math.max(range.left, endX - range.width * 0.05);
      await page.mouse.move(nudgeStartX, range.y);
      await page.mouse.down();
      const steps = Math.round(randomBetween(4, 8));
      for (let i = 1; i <= steps; i++) {
        const t = i / steps;
        const x = nudgeStartX + (endX - nudgeStartX) * t;
        await page.mouse.move(x, range.y, { steps: 2 });
        await pause(page, randomBetween(20, 60));
      }
      await page.mouse.up();
      await pause(page, randomBetween(100, 250));
      const nudges = Math.round(randomBetween(2, 5));
      for (let i = 0; i < nudges; i++) {
        await page.keyboard.press("ArrowRight").catch(() => {});
        await pause(page, randomBetween(30, 90));
      }
    } catch (e) { /* not fatal; move on to the next candidate */ }
  }
}

// Walks the tab order and nudges any focused range input or role="slider" with ArrowRight.
// Handles sliders that preventDefault() all pointer events, which also blocks focus-on-click.
// Tab has no side effects, and only sliders are acted on; bounded by maxTabs and maxSliders.
async function tabToRangeSlidersAndNudge(page, maxTabs = 40, maxSliders = 2) {
  // Skip the Tab walk entirely when the page has no slider to reach.
  const any = await page.evaluate(() => {
    const sel = 'input[type="range"], [role="slider"]';
    const walk = (root) => !!root.querySelector(sel) || Array.from(root.querySelectorAll("*")).some((el) => {
      if (el.shadowRoot && walk(el.shadowRoot)) return true;
      if (el.tagName === "IFRAME") { try { return !!el.contentDocument && walk(el.contentDocument); } catch (e) { return false; } }
      return false;
    });
    return !!walk(document);
  }).catch(() => true);
  if (!any) return;
  let handled = 0;
  for (let i = 0; i < maxTabs && handled < maxSliders; i++) {
    try {
      await page.keyboard.press("Tab");
    } catch (e) {
      break;
    }
    await pause(page, randomBetween(30, 80));
    let isSlider;
    try {
      isSlider = await page.evaluate(() => {
        const el = document.activeElement;
        if (!el || el === document.body) return false;
        const isRange = el.tagName === "INPUT" && el.type === "range";
        const isAriaSlider = el.getAttribute && el.getAttribute("role") === "slider";
        if (!isRange && !isAriaSlider) return false;
        if (el.dataset.hsTabNudged === "1") return false;
        // Ignore invisible sliders: opacity/clip-path-hidden elements remain Tab-reachable (honeypot risk).
        const style = getComputedStyle(el);
        if (parseFloat(style.opacity) < 0.1) return false;
        if (style.clipPath && style.clipPath !== "none") return false;
        if (style.clip && style.clip !== "auto" && style.position !== "static") return false;
        if (style.pointerEvents === "none") return false;
        const rect = el.getBoundingClientRect();
        if (rect.width < 2 || rect.height < 2) return false;
        el.dataset.hsTabNudged = "1";
        return true;
      });
    } catch (e) {
      continue;
    }
    if (!isSlider) continue;
    handled++;
    const nudges = Math.round(randomBetween(3, 7));
    for (let j = 0; j < nudges; j++) {
      await page.keyboard.press("ArrowRight").catch(() => {});
      await pause(page, randomBetween(30, 90));
    }
    await pause(page, randomBetween(100, 250));
  }
  await page.evaluate(() => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    deepQueryAll(document, "[data-hs-tab-nudged]").forEach((el) => el.removeAttribute("data-hs-tab-nudged"));
  }).catch(() => {});
}

// Finds native HTML5 drag-and-drop source/target pairs (draggable="true"). Synthetic mouse events
// never start a native drag session, so the caller uses page.dragAndDrop().
// Drop targets are assumed to be DOM siblings of the source; nothing standard marks a drop slot,
// so targets elsewhere in the page are not found. Bounded by maxSources and maxTargetsPerSource.
async function findDragAndDropCandidates(page, maxSources = 2, maxTargetsPerSource = 2) {
  return page.evaluate(({ maxSources, maxTargetsPerSource }) => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    function isVisible(el) {
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") return false;
      if (parseFloat(style.opacity) < 0.1) return false;
      if (style.clipPath && style.clipPath !== "none") return false;
      if (style.pointerEvents === "none") return false;
      const rect = el.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) return false;
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) return false;
      return true;
    }
    const sources = deepQueryAll(document, '[draggable="true"]').filter(isVisible);
    const pairs = [];
    for (const src of sources) {
      if (pairs.length >= maxSources) break;
      if (!src.parentElement) continue;
      // Draggable siblings are valid targets too (reorderable lists mark every item draggable).
      const siblings = Array.from(src.parentElement.children)
        .filter((el) => el !== src && isVisible(el))
        .slice(0, maxTargetsPerSource);
      if (siblings.length === 0) continue;
      const srcIdx = pairs.length;
      src.setAttribute("data-hs-drag-src", String(srcIdx));
      // An element can be a target for several sources, so the attribute holds a space-separated
      // token list and is queried with ~=.
      siblings.forEach((tgt, tgtIdx) => {
        const tag = srcIdx + "-" + tgtIdx;
        const existing = tgt.getAttribute("data-hs-drag-tgt");
        tgt.setAttribute("data-hs-drag-tgt", existing ? existing + " " + tag : tag);
      });
      pairs.push({ srcIdx, targetCount: siblings.length });
    }
    return pairs;
  }, { maxSources, maxTargetsPerSource });
}

async function performDragAndDrop(page, maxSources = 2, maxTargetsPerSource = 2) {
  let pairs;
  try {
    pairs = await findDragAndDropCandidates(page, maxSources, maxTargetsPerSource);
  } catch (e) {
    return;
  }
  for (const pair of pairs) {
    for (let tgtIdx = 0; tgtIdx < pair.targetCount; tgtIdx++) {
      try {
        await page.dragAndDrop(
          `[data-hs-drag-src="${pair.srcIdx}"]`,
          `[data-hs-drag-tgt~="${pair.srcIdx}-${tgtIdx}"]`
        );
        await pause(page, randomBetween(150, 350));
      } catch (e) { /* not fatal; try the next candidate target */ }
    }
  }
  await page.evaluate(() => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    deepQueryAll(document, "[data-hs-drag-src]").forEach((el) => el.removeAttribute("data-hs-drag-src"));
    deepQueryAll(document, "[data-hs-drag-tgt]").forEach((el) => el.removeAttribute("data-hs-drag-tgt"));
  }).catch(() => {});
}

// Finds native <audio controls>/<video controls> elements and targets a point near the left of
// the control bar, where engines draw the play toggle (inside UA shadow DOM, not queryable).
// A real mouse click is a user gesture, which autoplay policy requires; play() from script is not.
async function findMediaPlayButtons(page, maxEls) {
  return page.evaluate((max) => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    const candidates = deepQueryAll(document, "audio[controls], video[controls]");
    const results = [];
    for (const el of candidates) {
      if (el.hasAttribute("disabled")) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      if (style.pointerEvents === "none") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) continue;
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
      const x = rect.left + Math.min(20, rect.width * 0.15);
      const y = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(x, y);
      const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
      if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
      results.push({ x, y });
      if (results.length >= max) break;
    }
    return results;
  }, maxEls);
}

async function clickMediaPlayButtons(page, maxEls = 2) {
  let candidates;
  try {
    candidates = await findMediaPlayButtons(page, maxEls);
  } catch (e) {
    return;
  }
  for (const target of candidates) {
    try {
      await moveMouseHumanlike(page, target.x - randomBetween(20, 60), target.y, target.x, target.y);
      await pause(page, randomBetween(100, 250));
      await page.mouse.click(target.x, target.y);
      await pause(page, randomBetween(150, 400));
    } catch (e) { /* not fatal; move on to the next candidate */ }
  }
}

// findMediaPlayButtons() for same-origin iframes; targets are offset by the iframe's on-page position.
async function findMediaPlayButtonsInFrames(page, maxEls) {
  const results = [];
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    if (results.length >= maxEls) break;
    let candidates;
    try {
      candidates = await frame.evaluate((max) => {
        const els = Array.from(document.querySelectorAll("audio[controls], video[controls]"));
        const out = [];
        for (const el of els) {
          if (el.hasAttribute("disabled")) continue;
          const style = getComputedStyle(el);
          if (style.display === "none" || style.visibility === "hidden") continue;
          if (parseFloat(style.opacity) < 0.1) continue;
          if (style.pointerEvents === "none") continue;
          const rect = el.getBoundingClientRect();
          if (rect.width < 2 || rect.height < 2) continue;
          if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
          const x = rect.left + Math.min(20, rect.width * 0.15);
          const y = rect.top + rect.height / 2;
          const hit = document.elementFromPoint(x, y);
          if (!hit || (hit !== el && !el.contains(hit))) continue;
          out.push({ x, y });
          if (out.length >= max) break;
        }
        return out;
      }, maxEls - results.length);
    } catch (e) {
      continue; // cross-origin (or otherwise inaccessible) frame: skip it
    }
    if (!candidates || candidates.length === 0) continue;
    const frameElement = await frame.frameElement().catch(() => null);
    if (!frameElement) continue;
    const box = await frameElement.boundingBox().catch(() => null);
    if (!box) continue;
    for (const c of candidates) {
      results.push({ x: box.x + c.x, y: box.y + c.y });
      if (results.length >= maxEls) break;
    }
  }
  return results;
}

async function clickMediaPlayButtonsInFrames(page, maxEls = 2) {
  let candidates;
  try {
    candidates = await findMediaPlayButtonsInFrames(page, maxEls);
  } catch (e) {
    return;
  }
  for (const target of candidates) {
    try {
      await moveMouseHumanlike(page, target.x - randomBetween(20, 60), target.y, target.x, target.y);
      await pause(page, randomBetween(100, 250));
      await page.mouse.click(target.x, target.y);
      await pause(page, randomBetween(150, 400));
    } catch (e) { /* not fatal; move on to the next candidate */ }
  }
}

// Re-reads a tagged field's current position right before interacting, since filling an earlier
// field can shift layout.
async function refreshFieldPosition(page, idx) {
  return page.evaluate((i) => {
    // Pierces open shadow roots, like findVisibleTextFields().
    function deepQuery(root, selector) {
      const found = root.querySelector(selector);
      if (found) return found;
      for (const child of root.querySelectorAll("*")) {
        if (child.shadowRoot) {
          const inner = deepQuery(child.shadowRoot, selector);
          if (inner) return inner;
        }
      }
      return null;
    }
    const el = deepQuery(document, `[data-hs-field-idx="${i}"]`);
    if (!el) return null;
    const rect = el.getBoundingClientRect();
    if (rect.width < 1 || rect.height < 1) return null;
    return { x: rect.left + rect.width / 2, y: rect.top + rect.height / 2 };
  }, idx);
}

// Typed identity, set via setIdentity() from the scan (urlsandboxex.js). Kits check what is typed (MX
// records, account existence), so canary mailboxes on a domain you control work best; otherwise
// values come from the generator in lib/identity.js.
const identity = { emails: [], passwords: [], phones: [], names: [] };
const ids = require("./identity");
let spec = null;
const fallbackSpec = () => (spec = spec || ids.newSpec(Math.random));
function setIdentity(id = {}) {
  for (const k of Object.keys(identity)) identity[k] = Array.isArray(id[k]) ? id[k].filter(Boolean) : [];
}
function pick(arr) { return arr[Math.floor(Math.random() * arr.length)]; }

function fakeEmailValue() {
  return identity.emails.length ? pick(identity.emails) : ids.email(fallbackSpec());
}

// Configured password, or a generated one.
function fakePasswordValue() {
  return identity.passwords.length ? pick(identity.passwords) : ids.password(fallbackSpec());
}

// Other text fields (username, name, ...): a configured name, else the email's local part.
// Number fields get digits only, since browsers drop non-numeric keystrokes in type="number" inputs.
function fakeTextValue() {
  if (identity.names.length) return pick(identity.names);
  return fakeEmailValue().split("@")[0];
}

function fakeNumberValue() {
  if (identity.phones.length) return pick(identity.phones).replace(/\D/g, "");
  return String(Math.floor(Math.random() * 900000 + 100000));
}

// Types into visible text fields inside same-origin iframes, offsetting coordinates by the iframe's
// on-page position. Cross-origin frames throw in frame.evaluate() and are skipped.
// Uses the same selector and checks as findVisibleTextFields() (textarea, contenteditable, tel,
// url, number; skip fields that already have content), and digit-only values for number inputs.
async function typeIntoIframeFields(page, maxFieldsPerFrame = 1) {
  if (isRealService(page.url())) return; // a real service, not the kit: never type there
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    let candidates;
    try {
      candidates = await frame.evaluate((max) => {
        const els = Array.from(document.querySelectorAll(
          'input[type="text"], input[type="email"], input[type="tel"], input[type="url"], input[type="number"], input:not([type]), textarea, [contenteditable]'
        ));
        // Math-CAPTCHA answer computed from the iframe's own body text.
        let mathCaptchaAnswer = null;
        try {
          const bodyText = document.body.innerText || document.body.textContent || "";
          const mathMatch = bodyText.match(/what\s+is\s+(\d{1,3})\s*([+\-])\s*(\d{1,3})/i);
          if (mathMatch) {
            const left = parseInt(mathMatch[1], 10), right = parseInt(mathMatch[3], 10);
            mathCaptchaAnswer = String(mathMatch[2] === "+" ? left + right : left - right);
          }
        } catch (e) { /* not fatal */ }
        const results = [];
        for (const el of els) {
          if (el.disabled || el.readOnly) continue;
          if (el.hasAttribute("contenteditable") && !el.isContentEditable) continue;
          const currentText = el.isContentEditable ? el.textContent : el.value;
          if (currentText && currentText.trim().length > 0) continue;
          if (el.tabIndex < 0 && !el.isContentEditable) continue;
          const style = getComputedStyle(el);
          if (style.display === "none" || style.visibility === "hidden") continue;
          if (parseFloat(style.opacity) < 0.1) continue;
          if (style.clipPath && style.clipPath !== "none") continue;
          if (style.clip && style.clip !== "auto" && style.position !== "static") continue;
          if (style.pointerEvents === "none") continue;
          const rect = el.getBoundingClientRect();
          if (rect.width < 2 || rect.height < 2) continue;
          if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
          const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
          const hit = document.elementFromPoint(cx, cy);
          if (!hit || (hit !== el && !el.contains(hit))) continue;
          // Type-to-confirm word extraction, as in findVisibleTextFields().
          const placeholderText = el.placeholder || "";
          const typePrefixMatch = placeholderText.match(/^type\s+/i);
          const confirmMatch = typePrefixMatch ? placeholderText.slice(typePrefixMatch[0].length).match(/^([A-Z][A-Z0-9_-]{1,20})\b/) : null;
          results.push({
            x: cx, y: cy,
            isEmail: el.type === "email" || /e-?mail/i.test(el.name + el.id + el.placeholder + (el.getAttribute("aria-label") || "") + (el.labels ? Array.from(el.labels).map((l) => l.textContent).join(" ") : "")),
            isPassword: el.type === "password",
            isNumber: el.type === "number",
            confirmWord: confirmMatch ? confirmMatch[1] : null,
            mathCaptchaAnswer,
          });
          if (results.length >= max) break;
        }
        return results;
      }, maxFieldsPerFrame);
    } catch (e) {
      continue; // cross-origin (or otherwise inaccessible) frame: skip it
    }
    if (!candidates || candidates.length === 0) continue;
    const frameElement = await frame.frameElement().catch(() => null);
    if (!frameElement) continue;
    const box = await frameElement.boundingBox().catch(() => null);
    if (!box) continue;
    for (const c of candidates) {
      const target = { x: box.x + c.x, y: box.y + c.y };
      try {
        await moveMouseHumanlike(page, target.x + randomBetween(-10, 10), target.y + randomBetween(-10, 10), target.x, target.y);
        await page.mouse.click(target.x, target.y);
      } catch (e) { continue; }
      await pause(page, randomBetween(100, 300));
      const value = c.mathCaptchaAnswer ? c.mathCaptchaAnswer : c.confirmWord ? c.confirmWord : c.isNumber ? fakeNumberValue() : c.isEmail ? fakeEmailValue() : c.isPassword ? fakePasswordValue() : fakeTextValue();
      fillerTyped.add(String(value));
      for (const ch of value) {
        await page.keyboard.type(ch);
        await pause(page, randomBetween(tuning.keyMsMin, tuning.keyMsMax));
      }
      await pause(page, randomBetween(200, 500));
    }
  }
}

async function typeIntoVisibleFields(page, maxFields = 2, pressEnterAfter = false) {
  if (isRealService(page.url())) return; // a real service, not the kit: never type there
  // Re-query in bounded rounds: fields can appear only after earlier ones are filled.
  // Already-filled fields are skipped by findVisibleTextFields().
  const MAX_ROUNDS = 3;
  for (let round = 0; round < MAX_ROUNDS; round++) {
    let fields;
    try {
      fields = await findVisibleTextFields(page, maxFields);
    } catch (e) {
      break;
    }
    if (fields.length === 0) break;
    for (const field of fields) {
      // Re-measure before interacting; fall back to the original coordinates if the marker is gone.
      const fresh = await refreshFieldPosition(page, field.idx).catch(() => null);
      const target = fresh || field;
      await moveMouseHumanlike(page, target.x + randomBetween(-10, 10), target.y + randomBetween(-10, 10), target.x, target.y);
      try { await page.mouse.click(target.x, target.y); } catch (e) { continue; }
      await pause(page, randomBetween(100, 300));
      const value = field.otpDigit ? field.otpDigit : field.mathCaptchaAnswer ? field.mathCaptchaAnswer : field.confirmWord ? field.confirmWord : field.isNumber ? fakeNumberValue() : field.isEmail ? fakeEmailValue() : field.isPassword ? fakePasswordValue() : fakeTextValue();
      fillerTyped.add(String(value));
      for (const ch of value) {
        await page.keyboard.type(ch);
        // Variable inter-keystroke delay.
        await pause(page, randomBetween(tuning.keyMsMin, tuning.keyMsMax));
      }
      await pause(page, randomBetween(200, 500));
      // Enter can submit a form, so it is gated behind the same opt-in as clicking.
      if (pressEnterAfter) {
        try { await page.keyboard.press("Enter"); } catch (e) { /* not fatal */ }
        await pause(page, randomBetween(200, 500));
      }
      // Textareas: Ctrl/Cmd+Enter for composers where plain Enter inserts a newline.
      if (pressEnterAfter && field.isTextarea) {
        try { await page.keyboard.press("ControlOrMeta+Enter"); } catch (e) { /* not fatal */ }
        await pause(page, randomBetween(200, 500));
      }
    }
    // Clear markers every round so indices from an earlier round do not collide with new ones.
    await clearFieldMarkers(page);
  }
}

// Removes data-hs-field-idx markers, including inside open shadow roots.
async function clearFieldMarkers(page) {
  await page.evaluate(() => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    deepQueryAll(document, "[data-hs-field-idx]").forEach((el) => el.removeAttribute("data-hs-field-idx"));
  }).catch(() => {});
}

// Paste-only fields listen for 'paste', which typing never fires. pasteIntoVisibleFields() writes a
// code with navigator.clipboard.writeText() (no permission needed) and presses Ctrl/Cmd+V, so the
// browser's native paste fires with real clipboardData. Ctrl+A selects any typed content first so
// the paste replaces it, except in email fields, which keep the typed address.
function fakeVerificationCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

async function findPasteableFields(page, maxEls) {
  return page.evaluate((max) => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    const candidates = deepQueryAll(document,
      'input[type="text"], input[type="email"], input[type="tel"], input[type="url"], input:not([type]), textarea'
    );
    const results = [];
    for (const el of candidates) {
      if (el.disabled || el.readOnly) continue;
      if (el.tabIndex < 0) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      if (style.clipPath && style.clipPath !== "none") continue;
      if (style.clip && style.clip !== "auto" && style.position !== "static") continue;
      if (style.pointerEvents === "none") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) continue;
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
      const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(cx, cy);
      const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
      if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
      const idx = results.length;
      el.setAttribute("data-hs-paste-idx", String(idx));
      results.push({ x: cx, y: cy, idx, isEmail: el.type === "email" || /e-?mail/i.test(el.name + el.id + el.placeholder + (el.getAttribute("aria-label") || "") + (el.labels ? Array.from(el.labels).map((l) => l.textContent).join(" ") : "")), filled: !!el.value });
      if (results.length >= max) break;
    }
    return results;
  }, maxEls);
}

// Pastes into each field: email fields that already hold the typed address
// are left alone (an empty one gets the address), others get a code.
async function pasteInto(page, fields) {
  if (isRealService(page.url())) return; // a real service, not the kit: never type there
  const code = fakeVerificationCode();
  for (const field of fields) {
    if (field.isEmail && field.filled) continue;
    const text = field.isEmail ? fakeEmailValue() : code;
    noteClipboard(text);
    fillerTyped.add(text);
    try { await page.evaluate((t) => navigator.clipboard.writeText(t), text); } catch (e) { return; }
    try {
      await moveMouseHumanlike(page, field.x + randomBetween(-10, 10), field.y + randomBetween(-10, 10), field.x, field.y);
      await page.mouse.click(field.x, field.y);
      await pause(page, randomBetween(100, 250));
      await page.keyboard.press("ControlOrMeta+A");
      await page.keyboard.press("ControlOrMeta+V");
      await pause(page, randomBetween(200, 400));
    } catch (e) { /* not fatal; try the next candidate */ }
  }
}

async function pasteIntoVisibleFields(page, maxFields = 1) {
  let candidates;
  try {
    candidates = await findPasteableFields(page, maxFields);
  } catch (e) {
    return;
  }
  if (!candidates || candidates.length === 0) return;
  await pasteInto(page, candidates);
  await page.evaluate(() => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    deepQueryAll(document, "[data-hs-paste-idx]").forEach((el) => el.removeAttribute("data-hs-paste-idx"));
  }).catch(() => {});
}

// Finds paste-only fields inside same-origin iframes (e.g. an embedded 2FA widget).
// Field positions are translated to top-page coordinates via the iframe's offset; the
// paste itself uses the same clipboard-write + Ctrl+V path as pasteIntoVisibleFields().
async function findPasteableFieldsInFrames(page, maxFieldsPerFrame) {
  const results = [];
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    if (results.length >= maxFieldsPerFrame) break;
    let candidates;
    try {
      candidates = await frame.evaluate((max) => {
        const els = Array.from(document.querySelectorAll(
          'input[type="text"], input[type="email"], input[type="tel"], input[type="url"], input:not([type]), textarea'
        ));
        const out = [];
        for (const el of els) {
          if (el.disabled || el.readOnly) continue;
          if (el.tabIndex < 0) continue;
          const style = getComputedStyle(el);
          if (style.display === "none" || style.visibility === "hidden") continue;
          if (parseFloat(style.opacity) < 0.1) continue;
          if (style.clipPath && style.clipPath !== "none") continue;
          if (style.clip && style.clip !== "auto" && style.position !== "static") continue;
          if (style.pointerEvents === "none") continue;
          const rect = el.getBoundingClientRect();
          if (rect.width < 2 || rect.height < 2) continue;
          if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
          const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
          const hit = document.elementFromPoint(cx, cy);
          if (!hit || (hit !== el && !el.contains(hit))) continue;
          out.push({ x: cx, y: cy, isEmail: el.type === "email" || /e-?mail/i.test(el.name + el.id + el.placeholder + (el.getAttribute("aria-label") || "") + (el.labels ? Array.from(el.labels).map((l) => l.textContent).join(" ") : "")), filled: !!el.value });
          if (out.length >= max) break;
        }
        return out;
      }, maxFieldsPerFrame - results.length);
    } catch (e) {
      continue; // cross-origin or inaccessible frame; skip
    }
    if (!candidates || candidates.length === 0) continue;
    const frameElement = await frame.frameElement().catch(() => null);
    if (!frameElement) continue;
    const box = await frameElement.boundingBox().catch(() => null);
    if (!box) continue;
    for (const c of candidates) {
      results.push({ x: box.x + c.x, y: box.y + c.y, isEmail: c.isEmail, filled: c.filled });
      if (results.length >= maxFieldsPerFrame) break;
    }
  }
  return results;
}

async function pasteIntoIframeFields(page, maxFieldsPerFrame = 1) {
  let candidates;
  try {
    candidates = await findPasteableFieldsInFrames(page, maxFieldsPerFrame);
  } catch (e) {
    return;
  }
  if (candidates && candidates.length) await pasteInto(page, candidates);
}

// Finds visible <select> elements (e.g. "select your bank" gates), applying the same
// shadow-DOM and honeypot visibility checks as findVisibleTextFields().
// Selecting an option only changes local state, so it runs without allowClicks.
// Uses its own marker attribute (data-hs-select-idx) to avoid colliding with data-hs-field-idx.
// page.selectOption() pierces open shadow roots but not iframes; see selectDropdownOptionsInFrames().
async function findSelectableDropdowns(page, maxSelects) {
  return page.evaluate((max) => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    const candidates = deepQueryAll(document, "select");
    const results = [];
    for (const el of candidates) {
      if (el.disabled) continue;
      if (el.tabIndex < 0) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      if (style.clipPath && style.clipPath !== "none") continue;
      if (style.clip && style.clip !== "auto" && style.position !== "static") continue;
      if (style.pointerEvents === "none") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) continue;
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
      const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(cx, cy);
      const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
      if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
      const options = Array.from(el.options)
        .filter((o) => !o.disabled && o.value !== "" && !o.selected)
        .map((o) => o.value);
      if (options.length === 0) continue;
      const idx = results.length;
      el.setAttribute("data-hs-select-idx", String(idx));
      // Multi-selects may require 2+ options, so they are flagged and handled with an array.
      results.push({ idx, options, multiple: el.multiple });
      if (results.length >= max) break;
    }
    return results;
  }, maxSelects);
}

async function selectDropdownOptions(page, maxSelects = 1) {
  let candidates;
  try {
    candidates = await findSelectableDropdowns(page, maxSelects);
  } catch (e) {
    return;
  }
  for (const candidate of candidates) {
    let value;
    if (candidate.multiple) {
      const shuffled = [...candidate.options].sort(() => Math.random() - 0.5);
      const count = Math.min(shuffled.length, Math.round(randomBetween(2, 3)));
      value = shuffled.slice(0, count);
    } else {
      value = candidate.options[Math.floor(Math.random() * candidate.options.length)];
    }
    try {
      await page.selectOption(`[data-hs-select-idx="${candidate.idx}"]`, value);
      await pause(page, randomBetween(150, 400));
    } catch (e) { /* not fatal; try the next candidate */ }
  }
  await page.evaluate(() => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    deepQueryAll(document, "[data-hs-select-idx]").forEach((el) => el.removeAttribute("data-hs-select-idx"));
  }).catch(() => {});
}

// Selects options in <select> elements inside same-origin iframes via frame.selectOption(),
// since page.selectOption() does not reach iframe documents. Cross-origin frames throw and are skipped.
async function selectDropdownOptionsInFrames(page, maxSelectsPerFrame = 1) {
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    let candidates;
    try {
      candidates = await frame.evaluate((max) => {
        const els = Array.from(document.querySelectorAll("select"));
        const results = [];
        for (const el of els) {
          if (el.disabled) continue;
          const style = getComputedStyle(el);
          if (style.display === "none" || style.visibility === "hidden") continue;
          if (parseFloat(style.opacity) < 0.1) continue;
          if (style.pointerEvents === "none") continue;
          const rect = el.getBoundingClientRect();
          if (rect.width < 2 || rect.height < 2) continue;
          if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
          const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
          if (!hit || (hit !== el && !el.contains(hit))) continue;
          const options = Array.from(el.options).filter((o) => !o.disabled && o.value !== "" && !o.selected).map((o) => o.value);
          if (options.length === 0) continue;
          const idx = results.length;
          el.setAttribute("data-hs-select-idx", String(idx));
          results.push({ idx, options, multiple: el.multiple });
          if (results.length >= max) break;
        }
        return results;
      }, maxSelectsPerFrame);
    } catch (e) {
      continue; // cross-origin or inaccessible frame; skip
    }
    if (!candidates || candidates.length === 0) continue;
    for (const candidate of candidates) {
      let value;
      if (candidate.multiple) {
        const shuffled = [...candidate.options].sort(() => Math.random() - 0.5);
        const count = Math.min(shuffled.length, Math.round(randomBetween(2, 3)));
        value = shuffled.slice(0, count);
      } else {
        value = candidate.options[Math.floor(Math.random() * candidate.options.length)];
      }
      try {
        await frame.selectOption(`[data-hs-select-idx="${candidate.idx}"]`, value);
        await pause(page, randomBetween(150, 400));
      } catch (e) { /* not fatal; try the next candidate */ }
    }
    await frame.evaluate(() => {
      document.querySelectorAll("[data-hs-select-idx]").forEach((el) => el.removeAttribute("data-hs-select-idx"));
    }).catch(() => {});
  }
}

// Finds visible native input[type="date"] fields (e.g. date-of-birth age gates).
// These are filled with page.fill() rather than typed: per-character typing into a date
// field's segments leaves the value empty on WebKit, while fill() works on all three engines.
async function findDateInputs(page, maxEls) {
  return page.evaluate((max) => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    const candidates = deepQueryAll(document, 'input[type="date"]');
    const results = [];
    for (const el of candidates) {
      if (el.disabled || el.readOnly) continue;
      if (el.tabIndex < 0) continue;
      if (el.value) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      if (style.clipPath && style.clipPath !== "none") continue;
      if (style.clip && style.clip !== "auto" && style.position !== "static") continue;
      if (style.pointerEvents === "none") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) continue;
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
      const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(cx, cy);
      const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
      if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
      const idx = results.length;
      el.setAttribute("data-hs-date-idx", String(idx));
      results.push({ idx });
      if (results.length >= max) break;
    }
    return results;
  }, maxEls);
}

async function fillDateInputs(page, maxEls = 1) {
  let candidates;
  try {
    candidates = await findDateInputs(page, maxEls);
  } catch (e) {
    return;
  }
  for (const c of candidates) {
    try {
      // Synthetic, non-identifying adult date of birth.
      const year = 1970 + Math.floor(randomBetween(0, 35));
      const month = String(1 + Math.floor(randomBetween(0, 12))).padStart(2, "0");
      const day = String(1 + Math.floor(randomBetween(0, 28))).padStart(2, "0");
      await page.fill(`[data-hs-date-idx="${c.idx}"]`, `${year}-${month}-${day}`);
      await pause(page, randomBetween(150, 400));
    } catch (e) { /* not fatal; try the next candidate */ }
  }
  await page.evaluate(() => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    deepQueryAll(document, "[data-hs-date-idx]").forEach((el) => el.removeAttribute("data-hs-date-idx"));
  }).catch(() => {});
}

const DUMMY_UPLOAD_FILE = path.join(__dirname, "fixtures", "dummy-upload.txt");

// Finds visible <input type="file"> elements; they only ever receive the synthetic dummy file.
async function findFileInputs(page, maxEls) {
  return page.evaluate((max) => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    const candidates = deepQueryAll(document, 'input[type="file"]');
    const results = [];
    for (const el of candidates) {
      if (el.disabled) continue;
      if (el.tabIndex < 0) continue;
      if (el.files && el.files.length > 0) continue;
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      if (style.clipPath && style.clipPath !== "none") continue;
      if (style.clip && style.clip !== "auto" && style.position !== "static") continue;
      if (style.pointerEvents === "none") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 2 || rect.height < 2) continue;
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
      const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(cx, cy);
      const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
      if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
      const idx = results.length;
      el.setAttribute("data-hs-file-idx", String(idx));
      results.push({ idx });
      if (results.length >= max) break;
    }
    return results;
  }, maxEls);
}

async function fillFileInputs(page, maxEls = 1) {
  let candidates;
  try {
    candidates = await findFileInputs(page, maxEls);
  } catch (e) {
    return;
  }
  for (const candidate of candidates) {
    try {
      await page.setInputFiles(`[data-hs-file-idx="${candidate.idx}"]`, DUMMY_UPLOAD_FILE);
      await pause(page, randomBetween(150, 400));
    } catch (e) { /* not fatal; try the next candidate */ }
  }
  await page.evaluate(() => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    deepQueryAll(document, "[data-hs-file-idx]").forEach((el) => el.removeAttribute("data-hs-file-idx"));
  }).catch(() => {});
}

// Sets the synthetic dummy file on file inputs inside same-origin iframes via
// frame.setInputFiles(), since page.setInputFiles() cannot reach iframe documents.
async function fillFileInputsInFrames(page, maxFilesPerFrame = 1) {
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    let candidates;
    try {
      candidates = await frame.evaluate((max) => {
        const els = Array.from(document.querySelectorAll('input[type="file"]'));
        const results = [];
        for (const el of els) {
          if (el.disabled) continue;
          if (el.files && el.files.length > 0) continue;
          const style = getComputedStyle(el);
          if (style.display === "none" || style.visibility === "hidden") continue;
          if (parseFloat(style.opacity) < 0.1) continue;
          if (style.pointerEvents === "none") continue;
          const rect = el.getBoundingClientRect();
          if (rect.width < 2 || rect.height < 2) continue;
          if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
          const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
          if (!hit || (hit !== el && !el.contains(hit))) continue;
          const idx = results.length;
          el.setAttribute("data-hs-file-idx", String(idx));
          results.push({ idx });
          if (results.length >= max) break;
        }
        return results;
      }, maxFilesPerFrame);
    } catch (e) {
      continue; // cross-origin or inaccessible frame; skip
    }
    if (!candidates || candidates.length === 0) continue;
    for (const candidate of candidates) {
      try {
        await frame.setInputFiles(`[data-hs-file-idx="${candidate.idx}"]`, DUMMY_UPLOAD_FILE);
        await pause(page, randomBetween(150, 400));
      } catch (e) { /* not fatal; try the next candidate */ }
    }
    await frame.evaluate(() => {
      document.querySelectorAll("[data-hs-file-idx]").forEach((el) => el.removeAttribute("data-hs-file-idx"));
    }).catch(() => {});
  }
}

// Finds file drop zones: elements that accept dropped files via drag/drop listeners with no
// <input type="file">. Listeners are not observable from outside, so this relies on the
// visual convention of a dashed border.
async function findFileDropZones(page, maxEls) {
  return page.evaluate((max) => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    const results = [];
    for (const el of deepQueryAll(document, "*")) {
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      if (style.pointerEvents === "none") continue;
      const hasDashedBorder = style.borderTopStyle === "dashed" || style.borderRightStyle === "dashed" || style.borderBottomStyle === "dashed" || style.borderLeftStyle === "dashed";
      if (!hasDashedBorder) continue;
      // A dashed border alone also matches unrelated widgets (right-click targets, slider zones,
      // puzzle slots); a real drop zone pairs it with explanatory text, so require both.
      const text = (el.textContent || "").toLowerCase();
      if (!/drag|drop|upload|file/.test(text)) continue;
      const rect = el.getBoundingClientRect();
      // Excludes dashed decorative dividers, which are never sizeable targets.
      if (rect.width < 40 || rect.height < 40) continue;
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
      const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(cx, cy);
      const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
      if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
      const idx = results.length;
      el.setAttribute("data-hs-dropzone-idx", String(idx));
      results.push({ idx, x: cx, y: cy });
      if (results.length >= max) break;
    }
    return results;
  }, maxEls);
}

// Simulates an OS file drop by dispatching dragenter/dragover/drop DragEvents carrying a
// synthetic File in a DataTransfer (works on Chromium, Firefox and WebKit). dragover is sent
// first because many drop zones only accept a drop after calling preventDefault() there.
async function performFileDrop(page, maxEls = 1) {
  let candidates;
  try {
    candidates = await findFileDropZones(page, maxEls);
  } catch (e) {
    return;
  }
  for (const candidate of candidates) {
    try {
      await page.evaluate(({ idx, x, y }) => {
        const el = document.querySelector('[data-hs-dropzone-idx="' + idx + '"]');
        if (!el) return;
        const file = new File(["dummy file content for automated interaction testing"], "document.jpg", { type: "image/jpeg" });
        const dt = new DataTransfer();
        dt.items.add(file);
        const opts = { bubbles: true, cancelable: true, dataTransfer: dt, clientX: x, clientY: y };
        el.dispatchEvent(new DragEvent("dragenter", opts));
        el.dispatchEvent(new DragEvent("dragover", opts));
        el.dispatchEvent(new DragEvent("drop", opts));
      }, candidate);
      await pause(page, randomBetween(150, 400));
    } catch (e) { /* not fatal; try the next candidate */ }
  }
  await page.evaluate(() => {
    document.querySelectorAll("[data-hs-dropzone-idx]").forEach((el) => el.removeAttribute("data-hs-dropzone-idx"));
  }).catch(() => {});
}

// Finds visible, hit-testable canvases to draw a signature stroke on (e.g. "sign below"
// consent gates that check drawn pixels). Canvases under 20px are skipped as likely
// fingerprinting canvases. Drawing only changes local pixels, so it runs without allowClicks.
async function findDrawableCanvases(page, maxEls) {
  return page.evaluate((max) => {
    function deepQueryAll(root, selector) {
      let out = Array.from(root.querySelectorAll(selector));
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
      }
      return out;
    }
    const candidates = deepQueryAll(document, "canvas");
    const results = [];
    for (const el of candidates) {
      const style = getComputedStyle(el);
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (parseFloat(style.opacity) < 0.1) continue;
      if (style.pointerEvents === "none") continue;
      const rect = el.getBoundingClientRect();
      if (rect.width < 20 || rect.height < 20) continue;
      if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
      const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
      const hit = document.elementFromPoint(cx, cy);
      const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
      if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
      results.push({ left: rect.left, top: rect.top, width: rect.width, height: rect.height });
      if (results.length >= max) break;
    }
    return results;
  }, maxEls);
}

async function drawOnCanvases(page, maxEls = 1) {
  let candidates;
  try {
    candidates = await findDrawableCanvases(page, maxEls);
  } catch (e) {
    return;
  }
  for (const c of candidates) {
    try {
      // A few connected wavy strokes, shaped like a hand-drawn signature.
      const startX = c.left + c.width * 0.15;
      const startY = c.top + c.height * 0.6;
      await page.mouse.move(startX, startY);
      await page.mouse.down();
      const steps = Math.round(randomBetween(16, 24));
      for (let i = 1; i <= steps; i++) {
        const t = i / steps;
        const x = c.left + c.width * (0.15 + 0.7 * t);
        const y = c.top + c.height * (0.5 + 0.22 * Math.sin(t * Math.PI * 3));
        await page.mouse.move(x, y, { steps: 2 });
        await pause(page, randomBetween(10, 30));
      }
      await page.mouse.up();
      await pause(page, randomBetween(150, 350));
    } catch (e) { /* not fatal; try the next candidate */ }
  }
}

// Finds drawable canvases inside same-origin iframes (same 20px minimum), translating
// positions to top-page coordinates; drawing reuses the coordinate-based mouse stroke.
async function findDrawableCanvasesInFrames(page, maxEls) {
  const results = [];
  for (const frame of page.frames()) {
    if (frame === page.mainFrame()) continue;
    if (results.length >= maxEls) break;
    let candidates;
    try {
      candidates = await frame.evaluate((max) => {
        const els = Array.from(document.querySelectorAll("canvas"));
        const out = [];
        for (const el of els) {
          const style = getComputedStyle(el);
          if (style.display === "none" || style.visibility === "hidden") continue;
          if (parseFloat(style.opacity) < 0.1) continue;
          if (style.pointerEvents === "none") continue;
          const rect = el.getBoundingClientRect();
          if (rect.width < 20 || rect.height < 20) continue;
          if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
          const hit = document.elementFromPoint(rect.left + rect.width / 2, rect.top + rect.height / 2);
          if (!hit || (hit !== el && !el.contains(hit))) continue;
          out.push({ left: rect.left, top: rect.top, width: rect.width, height: rect.height });
          if (out.length >= max) break;
        }
        return out;
      }, maxEls - results.length);
    } catch (e) {
      continue; // cross-origin or inaccessible frame; skip
    }
    if (!candidates || candidates.length === 0) continue;
    const frameElement = await frame.frameElement().catch(() => null);
    if (!frameElement) continue;
    const box = await frameElement.boundingBox().catch(() => null);
    if (!box) continue;
    for (const c of candidates) {
      results.push({ left: box.x + c.left, top: box.y + c.top, width: c.width, height: c.height });
      if (results.length >= maxEls) break;
    }
  }
  return results;
}

async function drawOnCanvasesInFrames(page, maxEls = 1) {
  let candidates;
  try {
    candidates = await findDrawableCanvasesInFrames(page, maxEls);
  } catch (e) {
    return;
  }
  for (const c of candidates) {
    try {
      const startX = c.left + c.width * 0.15;
      const startY = c.top + c.height * 0.6;
      await page.mouse.move(startX, startY);
      await page.mouse.down();
      const steps = Math.round(randomBetween(16, 24));
      for (let i = 1; i <= steps; i++) {
        const t = i / steps;
        const x = c.left + c.width * (0.15 + 0.7 * t);
        const y = c.top + c.height * (0.5 + 0.22 * Math.sin(t * Math.PI * 3));
        await page.mouse.move(x, y, { steps: 2 });
        await pause(page, randomBetween(10, 30));
      }
      await page.mouse.up();
      await pause(page, randomBetween(150, 350));
    } catch (e) { /* not fatal; try the next candidate */ }
  }
}

// Runs the full human-like interaction sequence on a page, then dwells briefly so
// the page can react. Waiting out delayed content is the caller's job (the
// `delays` script). Clicks are opt-in via allowClicks; typing is on by default.
async function humanize(page, { allowClicks = false, allowTyping = true, minDwellMs = 300, maxDwellMs = 800 } = {}) {
  const viewport = page.viewportSize() || { width: 1280, height: 800 };
  let cursor = { x: randomBetween(50, viewport.width - 50), y: randomBetween(50, viewport.height - 50) };
  await page.mouse.move(cursor.x, cursor.y);

  const moveCount = Math.round(randomBetween(2, 4));
  for (let i = 0; i < moveCount; i++) {
    const target = { x: randomBetween(20, viewport.width - 20), y: randomBetween(20, viewport.height - 20) };
    await moveMouseHumanlike(page, cursor.x, cursor.y, target.x, target.y);
    cursor = target;
    await pause(page, randomBetween(80, 250));
  }

  // Rest the cursor on a couple of button/link-shaped elements to trigger hover-gated reveals
  // (350-600ms clears typical hover thresholds).
  try {
    const hoverTargets = await findHoverableElements(page, 2);
    for (const target of hoverTargets) {
      await moveMouseHumanlike(page, cursor.x, cursor.y, target.x, target.y);
      cursor = target;
      await hold(page, randomBetween(350, 600));
    }
  } catch (e) { /* no hoverable elements found; not fatal */ }

  // Scroll toward the bottom in several human-sized steps, capped so infinite-scroll pages
  // cannot loop forever; this triggers scroll/IntersectionObserver-gated reveals.
  // On touch-capable profiles (navigator.maxTouchPoints > 0) page.mouse.wheel() is skipped:
  // it throws on mobile WebKit, and on mobile Chromium it silently offsets all later
  // page.mouse coordinates. window.scrollBy() is used instead and still fires scroll events.
  try {
    const MAX_SCROLL_STEPS = 12;
    let wheelUnsupported = await page.evaluate(() => navigator.maxTouchPoints > 0).catch(() => false);
    for (let i = 0; i < MAX_SCROLL_STEPS; i++) {
      const atBottom = await page.evaluate(() => {
        return window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 4;
      }).catch(() => true);
      if (atBottom) break;
      const dy = randomBetween(450, 850);
      if (!wheelUnsupported) {
        try {
          await page.mouse.wheel(0, dy);
        } catch (e) {
          wheelUnsupported = true;
          await page.evaluate((amount) => window.scrollBy(0, amount), dy).catch(() => {});
        }
      } else {
        await page.evaluate((amount) => window.scrollBy(0, amount), dy).catch(() => {});
      }
      await pause(page, randomBetween(120, 300));
    }
  } catch (e) { /* page may not be scrollable; not fatal */ }

  // Scroll inner containers too: horizontal carousels and fixed-height vertical boxes
  // ("scroll to the bottom of the terms"), found in one DOM pass. Requires an explicit
  // overflow scroll/auto style (bare size comparisons match ordinary layout boxes) and
  // excludes <pre>/<code>/<textarea>. Touch profiles use element.scrollBy() for the same
  // wheel reason as above; a temporary attribute tags each container for that fallback.
  try {
    const scrollContainers = await page.evaluate(() => {
      function deepQueryAll(root, selector) {
        let out = Array.from(root.querySelectorAll(selector));
        for (const el of root.querySelectorAll("*")) {
          if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, selector));
        }
        return out;
      }
      const results = [];
      for (const el of deepQueryAll(document, "*")) {
        if (el === document.body || el === document.documentElement) continue;
        const style = getComputedStyle(el);
        if (style.display === "none" || style.visibility === "hidden") continue;
        if (el.tagName === "PRE" || el.tagName === "CODE" || el.tagName === "TEXTAREA") continue;
        const scrollableX = (style.overflowX === "scroll" || style.overflowX === "auto") && el.scrollWidth > el.clientWidth + 10;
        const scrollableY = (style.overflowY === "scroll" || style.overflowY === "auto") && el.scrollHeight > el.clientHeight + 10;
        if (!scrollableX && !scrollableY) continue;
        if (el.clientWidth < 20 || el.clientHeight < 20) continue;
        const rect = el.getBoundingClientRect();
        if (rect.width < 20 || rect.height < 20) continue;
        if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
        const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
        const hit = document.elementFromPoint(cx, cy);
        if (!hit || (hit !== el && !el.contains(hit))) continue;
        el.setAttribute("data-hs-carousel-idx", String(results.length));
        results.push({ x: cx, y: cy, idx: results.length, axisX: scrollableX, axisY: scrollableY });
        if (results.length >= 3) break;
      }
      return results;
    }).catch(() => []);
    if (scrollContainers && scrollContainers.length > 0) {
      let wheelUnsupportedH = await page.evaluate(() => navigator.maxTouchPoints > 0).catch(() => false);
      for (const c of scrollContainers) {
        await page.mouse.move(c.x, c.y).catch(() => {});
        const axes = [];
        if (c.axisX) axes.push("x");
        if (c.axisY) axes.push("y");
        for (const axis of axes) {
          // Step until the container reports it is at its edge; the cap is only a safety ceiling
          // (narrow mobile viewports can make a box several thousand px tall).
          const MAX_CONTAINER_STEPS = 20;
          for (let i = 0; i < MAX_CONTAINER_STEPS; i++) {
            const atEdge = await page.evaluate(({ idx, axis }) => {
              const el = document.querySelector('[data-hs-carousel-idx="' + idx + '"]');
              if (!el) return true;
              return axis === "x"
                ? el.scrollLeft + el.clientWidth >= el.scrollWidth - 4
                : el.scrollTop + el.clientHeight >= el.scrollHeight - 4;
            }, { idx: c.idx, axis }).catch(() => true);
            if (atEdge) break;
            const amount = randomBetween(150, 350);
            const dx = axis === "x" ? amount : 0;
            const dy = axis === "y" ? amount : 0;
            if (!wheelUnsupportedH) {
              try {
                await page.mouse.wheel(dx, dy);
              } catch (e) {
                wheelUnsupportedH = true;
                await page.evaluate(({ idx, dx, dy }) => {
                  const el = document.querySelector('[data-hs-carousel-idx="' + idx + '"]');
                  if (el) el.scrollBy({ left: dx, top: dy });
                }, { idx: c.idx, dx, dy }).catch(() => {});
              }
            } else {
              await page.evaluate(({ idx, dx, dy }) => {
                const el = document.querySelector('[data-hs-carousel-idx="' + idx + '"]');
                if (el) el.scrollBy({ left: dx, top: dy });
              }, { idx: c.idx, dx, dy }).catch(() => {});
            }
            await pause(page, randomBetween(150, 350));
          }
        }
      }
      await page.evaluate(() => {
        document.querySelectorAll("[data-hs-carousel-idx]").forEach((el) => el.removeAttribute("data-hs-carousel-idx"));
      }).catch(() => {});
    }
  } catch (e) { /* not fatal */ }

  if (allowTyping) {
    // Typing (never submitting) is on by default; honeypot and password exclusions bound the risk.
    // Pass { allowTyping: false } to disable. Pressing Enter afterward can submit a form, so it
    // is tied to allowClicks.
    await typeIntoVisibleFields(page, 2, allowClicks).catch(() => {});
    // Paste via a real Ctrl+V keystroke into paste-only fields.
    await pasteIntoVisibleFields(page, 1).catch(() => {});
    await typeIntoIframeFields(page, 1).catch(() => {});
    await pasteIntoIframeFields(page, 1).catch(() => {});
    // Dropdowns, date inputs, file inputs, file drops and canvas drawing only change local
    // state, so they run here with typing rather than behind allowClicks.
    await selectDropdownOptions(page, 1).catch(() => {});
    await selectDropdownOptionsInFrames(page, 1).catch(() => {});
    await fillDateInputs(page, 1).catch(() => {});
    // File inputs and drop zones only ever receive a synthetic dummy file.
    await fillFileInputs(page, 1).catch(() => {});
    await fillFileInputsInFrames(page, 1).catch(() => {});
    await performFileDrop(page, 1).catch(() => {});
    await drawOnCanvases(page, 1).catch(() => {});
    await drawOnCanvasesInFrames(page, 1).catch(() => {});
  }

  if (allowClicks) {
    // Drag a role="slider" widget first (it needs a real drag, not a click), so pages with both
    // a slider and other clickables get the richer interaction.
    let handledSlider = false;
    try {
      const slider = (await findSliderElement(page)) || (await findSliderElementInFrames(page).catch(() => null));
      if (slider) {
        cursor = { x: slider.x, y: slider.y };
        await dragSlider(page, slider);
        handledSlider = true;
      }
    } catch (e) { /* fall through to plain click */ }

    if (handledSlider) {
      await pause(page, randomBetween(100, 300));
    } else {
    // Prefer a real interactive element (a random point rarely hits a small target), falling
    // back to a random point. Uses the click-safe list, not the hover list, so links that
    // navigate away are never clicked.
    let target = null;
    try {
      const clickable = await findClickableElements(page, 1);
      if (clickable.length > 0) target = clickable[0];
    } catch (e) { /* fall through to random point */ }
    if (!target) target = { x: randomBetween(20, viewport.width - 20), y: randomBetween(20, viewport.height - 20) };
    // Hover before clicking, like a real cursor arriving at a target.
    await moveMouseHumanlike(page, cursor.x, cursor.y, target.x, target.y);
    await pause(page, randomBetween(100, 300));
    // Use exactly one modality: touchscreen.tap() (which also produces the synthesized click
    // and throws on contexts without hasTouch), falling back to mouse.click(). Doing both
    // double-fires handlers such as window.open().
    let tapped = false;
    try {
      await page.touchscreen.tap(target.x, target.y);
      tapped = true;
    } catch (e) { /* no touch support on this profile; fall back below */ }
    if (!tapped) {
      try { await page.mouse.click(target.x, target.y); } catch (e) { /* not fatal */ }
    }

    // Click one more element for two-step patterns (e.g. a modal's "I Agree", then a background
    // button). A single extra click keeps the cost low compared with the full multi-round
    // clickThroughSequentialSteps(). The search excludes the element at target's coordinates,
    // since a clicked button that stays visible would otherwise be found again.
    let secondTarget = null;
    try {
      secondTarget = await page.evaluate((t) => {
        function deepQueryAll(root, s) {
          let out = Array.from(root.querySelectorAll(s));
          for (const el of root.querySelectorAll("*")) {
            if (el.shadowRoot) out = out.concat(deepQueryAll(el.shadowRoot, s));
          }
          return out;
        }
        const prevEl = document.elementFromPoint(t.x, t.y);
        // A checkbox/radio and its <label> toggle the same control; compare the effective control
        // (label.control or the element itself) so the second click does not toggle it back off.
        function effectiveControl(el) {
          if (el && el.tagName === "LABEL" && el.control) return el.control;
          return el;
        }
        const prevIdentity = effectiveControl(prevEl);
        const sel = 'button, [role="button"], input[type="submit"], input[type="button"], input[type="checkbox"], input[type="radio"], summary, [onclick], [style*="cursor"], a[download]';
        const bySelector = deepQueryAll(document, sel);
        const bySelectorSet = new Set(bySelector);
        const candidates = bySelector.slice();
        for (const el of deepQueryAll(document, "*")) {
          if (bySelectorSet.has(el)) continue;
          if (el.tagName === "A") continue;
          let cursor;
          try { cursor = getComputedStyle(el).cursor; } catch (e) { continue; }
          if (cursor === "pointer" || cursor === "zoom-in" || cursor === "zoom-out") candidates.push(el);
        }
        for (const el of candidates) {
          if (el === prevEl) continue;
          if (effectiveControl(el) === prevIdentity) continue;
          if (el.disabled) continue;
          if (el.tagName === "LABEL" && el.control && (el.control.type === "checkbox" || el.control.type === "radio")) continue;
          const style = getComputedStyle(el);
          if (style.display === "none" || style.visibility === "hidden") continue;
          if (parseFloat(style.opacity) < 0.1) continue;
          if (style.clipPath && style.clipPath !== "none") continue;
          if (style.clip && style.clip !== "auto" && style.position !== "static") continue;
          if (style.pointerEvents === "none") continue;
          let rect = el.getBoundingClientRect();
          if (rect.width < 2 || rect.height < 2) continue;
          // A candidate below the fold is scrolled into view and re-measured: a showModal() dialog
          // locks body scroll, so the earlier page scroll may never have reached it.
          let scrolled = false;
          if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) {
            try { el.scrollIntoView({ block: "center", inline: "center" }); } catch (e) { try { el.scrollIntoView(true); } catch (e2) { continue; } }
            scrolled = true;
            rect = el.getBoundingClientRect();
            if (rect.width < 2 || rect.height < 2) continue;
            if (rect.right < 0 || rect.bottom < 0 || rect.left > window.innerWidth || rect.top > window.innerHeight) continue;
          }
          const cx = rect.left + rect.width / 2, cy = rect.top + rect.height / 2;
          const hit = document.elementFromPoint(cx, cy);
          const hitIsShadowHostOfEl = hit && hit.shadowRoot && hit.shadowRoot.contains(el);
          if (!hit || (hit !== el && !el.contains(hit) && !hitIsShadowHostOfEl)) continue;
          return { x: cx, y: cy, scrolled };
        }
        return null;
      }, target);
    } catch (e) { /* not fatal */ }
    if (secondTarget) {
      // After scrollIntoView() the layout is updated but the rendered frame can lag, so wait
      // before tapping at the new coordinates.
      if (secondTarget.scrolled) {
        await pause(page, randomBetween(150, 300));
      }
      let tapped2 = false;
      try {
        await page.touchscreen.tap(secondTarget.x, secondTarget.y);
        tapped2 = true;
      } catch (e) { /* no touch support on this profile; fall back below */ }
      if (!tapped2) {
        try { await page.mouse.click(secondTarget.x, secondTarget.y); } catch (e) { /* not fatal */ }
      }
    }
    }

    // Release pointer lock if a click engaged it, before later steps that need absolute
    // mouse coordinates.
    await releasePointerLockIfEngaged(page).catch(() => {});

    // Touch gestures run early: a touch-only gate is usually the only control on its page,
    // and running them late risks missing page-side timeouts. One CDP session is shared by all
    // touch functions to avoid per-call session setup cost.
    try {
      const browser = page.context().browser();
      if (browser && browser.browserType().name() === "chromium") {
        const sharedTouchCdp = await page.context().newCDPSession(page).catch(() => null);
        if (sharedTouchCdp) {
          await performTouchSwipe(page, sharedTouchCdp).catch(() => {});
          await performSwipeUp(page, sharedTouchCdp).catch(() => {});
          await performTouchLongPress(page, sharedTouchCdp).catch(() => {});
          await performTouchPinch(page, sharedTouchCdp).catch(() => {});
          await performOrientationFlip(page, sharedTouchCdp).catch(() => {});
          await performDeviceTilt(page, sharedTouchCdp).catch(() => {});
          await sharedTouchCdp.detach().catch(() => {});
        }
      }
    } catch (e) { /* not fatal: no touch support on this engine/profile */ }

    // Not touch- or Chromium-specific; performHistoryBack() guards against navigating off the page.
    await performHistoryBack(page).catch(() => {});

    // Native <input type="range"> is distinct from role="slider" widgets.
    await dragNativeRangeInputs(page, 2).catch(() => {});
    await dragNativeRangeInputsInFrames(page, 2).catch(() => {});
    // Keyboard-only sliders reached by Tab focus traversal.
    await tabToRangeSlidersAndNudge(page).catch(() => {});

    // Native HTML5 drag-and-drop uses Playwright's dragAndDrop() rather than raw mouse events.
    await performDragAndDrop(page, 2, 2).catch(() => {});

    // Native <audio>/<video> play buttons live in UA shadow DOM and need a coordinate click.
    await clickMediaPlayButtons(page, 2).catch(() => {});
    await clickMediaPlayButtonsInFrames(page, 2).catch(() => {});

    // Sustained press for press-and-hold gates; 1350ms leaves margin over typical 1200ms thresholds.
    await pressAndHoldClickable(page, 1350).catch(() => {});
    await pressAndHoldClickableInFrames(page, 1350).catch(() => {});

    await doubleClickClickable(page).catch(() => {});

    await rightClickClickable(page).catch(() => {});

    // Selects text for "select this text to continue" gates.
    await performTextSelection(page).catch(() => {});

    // "Widen your browser" gates; setViewportSize() works on all engines.
    await performWindowResize(page).catch(() => {});

    // Release pointer lock again: any of the click-family steps above may have triggered it.
    await releasePointerLockIfEngaged(page).catch(() => {});

    // Multi-step wizards run last, building on whatever earlier steps already advanced.
    await clickThroughSequentialSteps(page, 3).catch(() => {});
    await clickThroughSequentialStepsInFrames(page, 3).catch(() => {});

    // Final pointer-lock release: later steps can re-click a lock-requesting element, so this
    // runs after every click-family step.
    await releasePointerLockIfEngaged(page).catch(() => {});
  }

  // Exit-intent move is the last interaction, but before the dwell wait so it fires within
  // typical page-side timeouts.
  await performExitIntentMove(page).catch(() => {});

  // Randomized dwell before finishing, outlasting gates that reveal content after a delay.
  await pause(page, randomBetween(minDwellMs, maxDwellMs));
}

// Type text with this installation's keystroke timing (lib/credflow.js).
// Filler text typed into fields, so the credential flow can tell it from a
// value the kit prefilled (field may have truncated it).
const fillerTyped = new Set();
const typedFiller = (v) => !!v && [...fillerTyped].some((t) => t === v || (v.length >= 3 && t.startsWith(v)));

async function typeChars(page, text) {
  for (const ch of String(text)) {
    await page.keyboard.type(ch);
    await pause(page, randomBetween(tuning.keyMsMin, tuning.keyMsMax));
  }
}

module.exports = { humanize, setIdentity, setTuning, setDeadline, moveMouseHumanlike, typeChars, typedFiller, pause, hold, randomBetween, ownClipboard: () => ownClipboard };
