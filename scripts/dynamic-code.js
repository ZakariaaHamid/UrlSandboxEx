// dynamic-code: dump code that never existed as a file (eval, new
// Function, setTimeout(string), blob: and data: scripts), in the page and
// in its cross-site iframes and Workers: the decoded stages of obfuscated
// loaders. The debugger runs with breakpoints off, so the page can't see
// it and a `debugger;` timing trap measures 0 ms.

module.exports = {
  name: "dynamic-code",

  setup(api) {
    api.code.on((c) => {
      api.emit.dump(`dynamic-${c.sha256.slice(0, 16)}.js`, c.source);
      api.emit.dump("dynamic-code.jsonl", JSON.stringify({ sha256: c.sha256, length: c.source.length, target: c.target, targetUrl: c.targetUrl, url: c.url, from: c.from }) + "\n", { append: true });
    });
  },
};
