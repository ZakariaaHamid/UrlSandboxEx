// Example script: in-page function hooks that log calls (arguments,
// results, resolved promise values) to artifacts/calls.jsonl, and dump
// every atob() output.
// Use: urlsandboxex --script=examples/function-hooks.js <url>
//
// Trade-off: hooks run IN the page. Functions are wrapped in Proxies, so
// Function.prototype.toString still reports native code, but a determined
// kit can still notice (e.g. an extra stack frame when a hooked function
// throws). The default `dynamic-code` script captures eval/new Function
// code without touching the page; prefer it when stealth matters.

const HOOKS = ["atob", "Function", "fetch", "document.write", "crypto.subtle.decrypt", "WebSocket.prototype.send"];

function installer(list, marker) {
  return `(() => {
    const M = ${JSON.stringify(marker)}, MAX = 20000, debug = console.debug.bind(console), j = JSON.stringify;
    const clip = (v) => { try { return typeof v === "string" ? v.slice(0, MAX) : (v == null || typeof v !== "object") ? v : j(v).slice(0, MAX); } catch (e) { return "[unserializable]"; } };
    const send = (o) => { try { debug(M + j(o)); } catch (e) {} };
    for (const name of ${JSON.stringify(list)}) {
      try {
        const parts = name.split("."), key = parts.pop();
        const obj = parts.reduce((o, k) => o && o[k], globalThis), fn = obj && obj[key];
        if (typeof fn !== "function") continue;
        const proxy = new Proxy(fn, {
          apply(t, self, args) {
            const r = Reflect.apply(t, self, args), rec = { fn: name, args: args.map(clip), t: Date.now() };
            if (r && typeof r.then === "function") r.then((v) => send({ ...rec, resolved: clip(v) }), () => {}); else send({ ...rec, result: clip(r) });
            return r;
          },
          construct(t, args, nt) { send({ fn: name, construct: true, args: args.map(clip), t: Date.now() }); return Reflect.construct(t, args, nt); },
        });
        const d = Object.getOwnPropertyDescriptor(obj, key);
        if (d && "value" in d) Object.defineProperty(obj, key, { ...d, value: proxy }); else obj[key] = proxy;
      } catch (e) {}
    }
  })();`;
}

module.exports = {
  name: "function-hooks",

  async page(ctx) {
    if (!ctx.state.hookMarker) ctx.state.hookMarker = `⁣h${ctx.sha256(String(Math.random())).slice(0, 10)}:`;
    const M = ctx.state.hookMarker;
    if (!ctx.isPopup) await ctx.context.addInitScript(installer(HOOKS, M));
    ctx.page.on("console", (msg) => {
      const text = msg.text();
      if (!text.startsWith(M)) return;
      const call = JSON.parse(text.slice(M.length));
      ctx.dump("calls.jsonl", JSON.stringify(call) + "\n", { append: true });
      if (call.fn === "atob" && typeof call.result === "string") ctx.dump(`atob-${call.t}.txt`, call.result);
    });
  },
};
