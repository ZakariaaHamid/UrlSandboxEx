// Runs Playwright page/frame .evaluate() calls in a CDP isolated world
// instead of the page's main world (Chromium only). A page that wraps DOM
// APIs and inspects new Error().stack would otherwise see "eval at
// evaluate" / "UtilityScript.evaluate" frames whenever we query the DOM.
// An isolated world shares the DOM but not the JS heap, so page hooks
// never run for our calls.
// Cross-site iframes (other processes) get their isolated world through
// their own session. Limits: page JS globals aren't visible from the
// isolated world; a frame that can't be told apart from a sibling (same URL
// and name) falls back to Playwright's normal evaluate.

let installed = 0;
let origEvaluate = null;
const active = new Map(); // Page -> state

// Frame id in a session's frame tree: the root, or a unique url+name match.
async function frameIdIn(cdp, frame, isRoot) {
  const { frameTree } = await cdp.send("Page.getFrameTree");
  if (isRoot) return frameTree.frame.id;
  const matches = [];
  (function walk(n) {
    for (const c of n.childFrames || []) {
      if (c.frame.url === frame.url() && (c.frame.name || "") === (frame.name() || "")) matches.push(c.frame.id);
      walk(c);
    }
  })(frameTree);
  return matches.length === 1 ? matches[0] : null;
}

// The session that can address `frame`: the page's, or for a frame in
// another process (a cross-site iframe), that iframe's own session.
async function sessionFor(state, frame) {
  if (frame.page() !== state.page) return null;
  const inPage = await frameIdIn(state.cdp, frame, frame === state.page.mainFrame()).catch(() => null);
  if (inPage) return { cdp: state.cdp, fid: inPage };
  for (let f = frame; f && f !== state.page.mainFrame(); f = f.parentFrame()) {
    let cdp = state.frameSessions.get(f);
    if (cdp === undefined) {
      cdp = await state.page.context().newCDPSession(f).catch(() => null); // only out-of-process frames have one
      state.frameSessions.set(f, cdp);
    }
    if (!cdp) continue;
    const fid = await frameIdIn(cdp, frame, f === frame).catch(() => null);
    if (fid) return { cdp, fid };
  }
  return null;
}

async function worldFor(state, frame) {
  const where = await sessionFor(state, frame);
  if (!where) return null;
  const cached = state.worlds.get(where.fid);
  if (cached) return { cdp: where.cdp, id: cached };
  const { executionContextId } = await where.cdp.send("Page.createIsolatedWorld", { frameId: where.fid, worldName: "", grantUniveralAccess: false });
  state.worlds.set(where.fid, executionContextId);
  return { cdp: where.cdp, id: executionContextId };
}

async function isolatedEvaluate(state, frame, fn, arg) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const world = await worldFor(state, frame);
    if (!world) return null;
    try {
      const res = typeof fn === "function"
        ? await world.cdp.send("Runtime.callFunctionOn", { functionDeclaration: fn.toString(), executionContextId: world.id, arguments: arg === undefined ? [] : [{ value: arg }], returnByValue: true, awaitPromise: true, userGesture: false })
        : await world.cdp.send("Runtime.evaluate", { expression: String(fn), contextId: world.id, returnByValue: true, awaitPromise: true });
      if (res.exceptionDetails) {
        const d = res.exceptionDetails;
        throw new Error(d.exception?.description || d.text || "evaluation failed");
      }
      return { value: res.result.value };
    } catch (e) {
      // Navigation destroyed the world: drop the cache and retry once.
      if (/context|Cannot find|not found|destroyed/i.test(e.message) && attempt === 0) { state.worlds.clear(); continue; }
      throw e;
    }
  }
  return null;
}

/**
 * Run fn() with every evaluate() on `page`'s frames redirected to an
 * isolated world. No-op (just runs fn) for non-Chromium engines.
 */
async function withIsolatedWorld(page, context, fn) {
  let cdp;
  try { cdp = await context.newCDPSession(page); } catch (e) { return fn(); }
  const FrameProto = Object.getPrototypeOf(page.mainFrame());
  if (!installed++) {
    origEvaluate = FrameProto.evaluate;
    FrameProto.evaluate = async function (pageFunction, arg) {
      const state = active.get(this.page());
      if (state && !hasHandles(arg)) {
        try {
          const r = await isolatedEvaluate(state, this, pageFunction, arg);
          if (r) return r.value;
        } catch (e) {
          if (!/Cannot find|context|not found/i.test(e.message)) throw e;
        }
      }
      return origEvaluate.call(this, pageFunction, arg);
    };
  }
  const state = { page, cdp, worlds: new Map(), frameSessions: new Map() };
  active.set(page, state);
  // Page.evaluate goes through mainFrame().evaluate in the client, but
  // guard the direct path too.
  const pageEval = page.evaluate;
  page.evaluate = (f, a) => page.mainFrame().evaluate(f, a);
  try {
    return await fn();
  } finally {
    page.evaluate = pageEval;
    active.delete(page);
    if (!--installed) FrameProto.evaluate = origEvaluate;
    await cdp.detach().catch(() => {});
    for (const s of state.frameSessions.values()) if (s) await s.detach().catch(() => {});
  }
}

function hasHandles(arg) {
  if (!arg || typeof arg !== "object") return false;
  if (typeof arg.asElement === "function" || typeof arg.evaluate === "function") return true;
  return Object.values(arg).some((v) => v && typeof v === "object" && (typeof v.asElement === "function" || typeof v.evaluate === "function"));
}

module.exports = { withIsolatedWorld };
