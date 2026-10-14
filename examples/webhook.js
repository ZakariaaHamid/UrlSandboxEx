// Example host-side script: POST a summary of each scan to a webhook
// (Slack-compatible "text" plus the structured data).
// Use: urlsandboxex --script=examples/webhook.js --set settings.webhook.url=https://... <url>
//
// `after` runs on the host after the visit, with network access and no
// jail; everything in `host` comes from a hostile page, so treat it as data.

module.exports = {
  name: "webhook",

  settings: { webhook: { url: null, minIocs: 1 } },

  async after(host) {
    const cfg = host.settings.webhook;
    if (!cfg.url || host.iocs.length < cfg.minIocs) return;
    const r = host.result;
    const pick = (type) => host.iocs.filter((i) => i.type === type).map((i) => i.value).slice(0, 10);
    const summary = {
      url: host.url, finalUrl: r.finalUrl || null, title: r.title || null, httpStatus: r.httpStatus ?? null,
      credentialSinks: host.iocs.filter((i) => i.context.some((c) => c.startsWith("credential submission"))).map((i) => i.value),
      domains: pick("domain"), ips: pick("ip"), output: host.dir,
    };
    const res = await fetch(cfg.url, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: `urlsandboxex: ${summary.url} -> ${summary.finalUrl} (${host.iocs.length} indicators)`, ...summary }),
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) throw new Error(`webhook HTTP ${res.status}`);
  },
};
