// clickfix-signature: flag ClickFix lures, fake "verify you are human"
// pages that put a command on the clipboard and tell the visitor to paste
// it into the Run dialog or a terminal.
//
// This file is the reference for writing scripts with the script API
// (docs/api.md): `when` limits it to pages that look like a lure, `setup`
// registers observers before the page loads, `run` inspects the page after
// the other scripts have interacted with it, and `emit` reports findings,
// tags and files. Nothing here is visible to the page.

// Commands a lure stages: shell launchers and download cradles.
const COMMAND = /\b(powershell(\.exe)?\s+-|pwsh\s+-|mshta(\.exe)?\s+https?:|cmd(\.exe)?\s+\/c|rundll32|regsvr32|certutil\s+-urlcache|bitsadmin|curl\s+[^|]*\|\s*(ba)?sh|wget\s+[^|]*\|\s*(ba)?sh|iex\s*\(|invoke-expression)/i;
const CLIPBOARD_WRITE = /navigator\.clipboard\.writeText|document\.execCommand\(\s*["']copy["']/;
const RUN_INSTRUCTIONS = /(win(dows)?\s*(key)?\s*\+\s*r\b|windows\s+key\s+and\s+r|press\s+ctrl\s*\+\s*v|paste\s+(it\s+)?(into|in)\s+(the\s+)?(run|terminal|command)|run\s+dialog|open\s+(the\s+)?terminal)/i;

module.exports = {
  name: "clickfix-signature",

  settings: {
    clickfixSignature: { scanScripts: true },
  },
  ui: {
    "clickfixSignature.scanScripts": { help: "also search the page's HTML and script files for clipboard writes" },
  },

  // Only pages with a checkbox or button and human-check wording. Findings
  // from setup() are kept until this matches and dropped if it never does.
  when: {
    text: /robot|human|verif|captcha|cloudflare|security check/i,
    dom: "input[type=checkbox], button, [role=button], [role=checkbox]",
  },

  setup(api) {
    // Generated code anywhere (page, iframes, Workers): a staged command.
    api.code.on((c) => {
      const m = c.source.match(COMMAND);
      if (!m) return;
      api.emit.finding("bad", `Generated code contains a command: ${m[0]}`);
      api.emit.tag("clickfix");
      api.emit.dump(`clickfix-code-${c.sha256.slice(0, 12)}.js`, c.source);
    });

    // HTML and script files that write to the clipboard.
    if (api.settings.clickfixSignature.scanScripts) {
      api.net.on("response", { type: "document|script" }, async (r) => {
        const body = await r.text();
        if (!body || !CLIPBOARD_WRITE.test(body)) return;
        const cmd = body.match(COMMAND);
        api.emit.finding(cmd ? "bad" : "warn", `${r.type === "document" ? "Page" : "Script"} writes to the clipboard${cmd ? ` and contains a command (${cmd[0]})` : ""}`);
        api.emit.ioc("url", r.url, "writes to the clipboard");
        api.emit.tag("clickfix");
      });
    }
  },

  // After load and interaction: does the page tell the visitor where to
  // paste?
  async run(api) {
    const text = await api.page.text();
    const m = text.match(RUN_INSTRUCTIONS);
    if (m) {
      api.emit.finding("bad", `Page tells the visitor to paste a command ("${m[0]}")`);
      api.emit.tag("clickfix");
    }
    api.emit.log("checked", { url: api.page.url(), instructions: m ? m[0] : null });
  },
};
