// Unit tests for the sandbox's own logic (no browser, no jail):
//   npm test   (or: node --test test/)
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const net = require("net");
const { PNG } = require("pngjs");

const { makeBlockList, isBlocked, startEgressProxy } = require("../core/egress_proxy");
const { findButtonStack, findPillPair } = require("../lib/prompts");
const { loadConfig, stripJsonComments } = require("../core/config");
const { loadScripts, compose } = require("../core/scripts");
const { acceptLanguages } = require("../scripts/stealth");
const { extractIocs } = require("../core/iocs");
const { proxyFor } = require("../core/egress");

// Temporary directories for a test; all removed when the run ends.
const made = [];
const tmpdir = (prefix) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix)); made.push(d); return d; };
process.on("exit", () => { for (const d of made) fs.rmSync(d, { recursive: true, force: true }); });

const fixture = (f) => PNG.sync.read(fs.readFileSync(path.join(__dirname, "fixtures", f)));

test("egress policy blocks private, loopback, metadata and own addresses, allows public", () => {
  const bl = makeBlockList();
  for (const a of ["127.0.0.1", "10.2.3.4", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "0.0.0.0"]) assert.equal(isBlocked(bl, a), true, a);
  for (const a of ["8.8.8.8", "1.1.1.1", "2606:4700:10::6814:179a", "23.215.0.136"]) assert.equal(isBlocked(bl, a), false, a);
});

test("egress proxy: blocks metadata and loopback, honors allow-list, logs", async () => {
  const dir = tmpdir("sbx-t-");
  const target = http.createServer((q, r) => r.end("hello")).listen(0, "127.0.0.1");
  await new Promise((r) => target.once("listening", r));
  const port = target.address().port;
  const proxy = await startEgressProxy({ socketPath: path.join(dir, "e.sock"), logPath: path.join(dir, "log.jsonl"), allow: [`127.0.0.1:${port}`] });
  const viaProxy = (url) => new Promise((resolve) => {
    const s = net.connect(path.join(dir, "e.sock"));
    s.on("connect", () => s.write(`GET ${url} HTTP/1.1\r\nHost: ${new URL(url).host}\r\nConnection: close\r\n\r\n`));
    let buf = ""; s.on("data", (d) => { buf += d; }); s.on("end", () => resolve(buf)); s.on("error", () => resolve(buf));
  });
  assert.match(await viaProxy(`http://127.0.0.1:${port}/`), /^HTTP\/1\.1 200[\s\S]*hello$/);
  assert.match(await viaProxy("http://169.254.169.254/latest/meta-data/"), /^HTTP\/1\.1 403/);
  assert.match(await viaProxy("http://127.0.0.1:22/"), /^HTTP\/1\.1 403/);
  await proxy.close(); target.close();
  const log = fs.readFileSync(path.join(dir, "log.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
  assert.equal(log.filter((l) => l.blocked).length, 2);
});

test("permission prompt detection: 3-button stack, 2-button pair (Allow is right), none", () => {
  const stack = findButtonStack(fixture("prompt.png"));
  assert.equal(stack.length, 3);
  const pair = findPillPair(fixture("prompt_clip.png"));
  assert.ok(pair && pair.x0 > 340, "must pick the right-hand (Allow) pill");
  assert.ok(findPillPair(fixture("prompt_notif.png")));
  assert.equal(findButtonStack(fixture("no_prompt.png")), null);
  assert.equal(findPillPair(fixture("no_prompt.png")), null);
});

test("accept-languages look like Chrome's", () => {
  assert.deepEqual(acceptLanguages("it-IT"), ["it-IT", "it", "en-US", "en"]);
  assert.deepEqual(acceptLanguages("en-US"), ["en-US", "en"]);
  assert.deepEqual(acceptLanguages("en-GB"), ["en-GB", "en-US", "en"]);
});

test("config: JSONC comments/trailing commas, --set overrides", () => {
  assert.deepEqual(JSON.parse(stripJsonComments('{ // c\n "a": "x//y", /* b */ "b": [1,], }')), { a: "x//y", b: [1] });
  const c = loadConfig(["scan.persona=android", "egress.allow=[\"127.0.0.1:3000\"]"]);
  assert.equal(c.scan.persona, "android");
  assert.deepEqual(c.egress.allow, ["127.0.0.1:3000"]);
});

test("residential proxy template: per-session credentials, refuses socks", () => {
  const p = proxyFor("http://user-{country}-s-{session}:pw@gw.example:7777", { country: "DE", session: "abc" });
  assert.equal(p.server, "http://gw.example:7777");
  assert.equal(p.username, "user-de-s-abc");
  assert.throws(() => proxyFor("socks5://u:p@gw:1080", { country: "us" }), /http/);
});

test("scripts: compose in order, merge personas/settings, opts flow through launch hooks", async () => {
  const dir = tmpdir("sbx-s-");
  fs.writeFileSync(path.join(dir, "a.js"), "module.exports = { settings: { x: { a: 1, b: 1 } }, personas: { p: { engine: 'firefox' } }, launch(ctx, o) { o.args.push('A'); return o; } };");
  fs.writeFileSync(path.join(dir, "b.js"), "module.exports = { settings: { x: { b: 2 } }, launch(ctx, o) { o.args.push('B'); }, async interact(ctx) { ctx.log.b = true; } };");
  const S = compose(loadScripts(["a.js", "b.js"], dir));
  assert.deepEqual(S.settings.x, { a: 1, b: 2 });
  assert.equal(S.personas.p.engine, "firefox");
  assert.ok(S.personas.default, "core default persona always present");
  assert.deepEqual((await S.launch({ env: {} })).args, ["A", "B"]);
  const ilog = await S.interact({ log: {} });
  assert.equal(ilog.b, true);
  assert.equal(typeof ilog.interactMs.b, "number");
  assert.throws(() => loadScripts(["nope"]), /no built-in script/);
});

test("stealth script: desktop Chromium has no viewport emulation, native locale/TZ, Chrome sandbox on; webkit emulates", async () => {
  const S = compose(loadScripts(["stealth"]));
  const pw = require("playwright");
  const ctx = (p) => ({ settings: S.settings, persona: S.personas[p], engine: S.personas[p].engine, locale: "de-DE", timezoneId: "Europe/Berlin", env: {}, playwright: pw, jailed: true });
  const d = await S.contextOptions(ctx("desktop"));
  assert.equal(d.viewport, null);
  assert.equal(d.locale, undefined);
  const w = await S.contextOptions(ctx("iphone"));
  assert.equal(w.locale, "de-DE");
  const l = await S.launch(ctx("desktop"));
  assert.ok(l.chromiumSandbox);
  assert.ok(l.args.includes("--accept-lang=de-DE,de,en-US,en"));
  assert.equal(l.env.TZ, "Europe/Berlin");
});

test("core IOCs: credential sink to third party, real IPs, no browser background hosts, script IOCs merged", () => {
  const dir = tmpdir("sbx-ioc-");
  fs.mkdirSync(path.join(dir, "assets")); fs.mkdirSync(path.join(dir, "artifacts"));
  const email = "canary.42@corp.example";
  fs.writeFileSync(path.join(dir, "assets", "traffic.har"), JSON.stringify({ log: { entries: [
    { request: { url: "https://login.evil.example/", method: "GET" }, response: { headers: [], content: {} }, serverIPAddress: "127.0.0.1" },
    { request: { url: "https://collect.other.example/p", method: "POST", postData: { text: `u=${encodeURIComponent(email)}` } }, response: { headers: [], content: {} } },
  ] } }));
  fs.writeFileSync(path.join(dir, "connections.jsonl"), [
    { host: "login.evil.example", port: 443, address: "203.0.113.9" },
    { host: "update.googleapis.com", port: 443, address: "142.250.1.1" },
    { host: "169.254.169.254", port: 80, blocked: "private-or-local-address" },
  ].map((x) => JSON.stringify(x)).join("\n"));
  fs.writeFileSync(path.join(dir, "artifacts", "script-iocs.jsonl"), JSON.stringify({ type: "telegramBotToken", value: "123:abc", context: "test" }) + "\n");
  fs.writeFileSync(path.join(dir, "artifacts", "dynamic-x.js"), 'var k = "https://stage2.evil.example/c";');
  const iocs = extractIocs(dir, { url: "https://login.evil.example/", finalUrl: "https://login.evil.example/", har: "assets/traffic.har" }, { emails: [email], passwords: [] });
  const has = (type, re) => iocs.some((i) => i.type === type && re.test(i.value));
  assert.ok(iocs.some((i) => /credential submission.*third-party/.test(i.context.join())));
  assert.ok(has("ip", /^203\.0\.113\.9$/) && !has("ip", /^127\./));
  assert.ok(!has("domain", /googleapis/));
  assert.ok(has("domain", /169\.254/));
  assert.ok(has("telegramBotToken", /^123:abc$/));
  assert.ok(has("url", /stage2\.evil\.example/));
});

test("core IOCs: a recovery phrase sent as JSON is a credential submission; scattered words are not", () => {
  const dir = tmpdir("sbx-ioc-");
  fs.mkdirSync(path.join(dir, "assets"));
  const seed = require("../lib/identity").seedPhrase();
  const w = seed.split(" ");
  assert.equal(w.length, 12);
  fs.writeFileSync(path.join(dir, "assets", "traffic.har"), JSON.stringify({ log: { entries: [
    { request: { url: "https://wallet.evil.example/api/receive-data", method: "POST", postData: { text: JSON.stringify({ passphrase: seed }) } }, response: { headers: [], content: {} } },
    { request: { url: "https://ads.example/t", method: "POST", postData: { text: `q=${w[0]}` } }, response: { headers: [], content: {} } },
  ] } }));
  const iocs = extractIocs(dir, { url: "https://wallet.evil.example/", har: "assets/traffic.har" }, { emails: [], passwords: [], seeds: [seed] });
  const sinks = iocs.filter((i) => /credential submission/.test(i.context.join())).map((i) => i.value);
  assert.deepEqual(sinks, ["https://wallet.evil.example/api/receive-data"]);
});

test("clock: business-hours shifts only outside hours, to the next allowed day; fixed sets the time", () => {
  const { offsetSeconds } = require("../scripts/clock");
  const cfg = { mode: "business-hours", from: "09:00", to: "17:30", at: "10:15", days: [1, 2, 3, 4, 5] };
  const tz = "Europe/Berlin";
  assert.equal(offsetSeconds(cfg, tz, new Date("2026-10-14T09:00:00Z")), 0, "Wed 11:00 local: inside hours");
  assert.equal(offsetSeconds(cfg, tz, new Date("2026-10-14T05:00:00Z")), 3 * 3600 + 15 * 60, "Wed 07:00 -> 10:15 same day");
  assert.equal(offsetSeconds(cfg, tz, new Date("2026-10-16T18:00:00Z")), (2 * 24 + 14) * 3600 + 15 * 60, "Fri 20:00 -> Mon 10:15");
  assert.equal(offsetSeconds({ ...cfg, mode: "fixed", at: "03:00" }, tz, new Date("2026-10-14T09:00:00Z")), -8 * 3600);
  assert.equal(offsetSeconds({ ...cfg, mode: "off" }, tz), 0);
});

test("scripts: navigate (first non-null wins) and host-side after hooks", async () => {
  const S = compose([
    { name: "a", navigate: async () => null, after: async (h) => { h.seen.push("a"); } },
    { name: "b", navigate: async () => ({ response: "R", via: "x" }), after: async () => { throw new Error("boom"); } },
    { name: "c", navigate: async () => ({ response: "never" }) },
  ]);
  assert.deepEqual(await S.navigate({}), { response: "R", via: "x" });
  const host = { seen: [], errors: [] };
  await S.after(host);
  assert.deepEqual(host.seen, ["a"]);
  assert.match(host.errors[0], /b\.after: boom/);
});

test("profiles: requests name only installed scripts, validate settings, merge into config", () => {
  const { normalizeRequest, applyRequest } = require("../core/profiles");
  const { scriptLibrary } = require("../core/scripts");
  const { loadConfig } = require("../core/config");
  const cfg = { ...loadConfig(), scriptDirs: [] };
  const lib = scriptLibrary(cfg);
  assert.ok(lib.find((s) => s.key === "interact" && s.builtin && s.hooks.includes("interact") && s.description));
  assert.throws(() => normalizeRequest({ scripts: ["/tmp/evil.js"] }, lib), /unknown script/);
  assert.throws(() => normalizeRequest({ overrides: { "__proto__.x": 1 } }, lib), /invalid setting/);
  assert.throws(() => normalizeRequest({ overrides: { "a.constructor.b": 1 } }, lib), /invalid setting/);
  assert.throws(() => normalizeRequest({ overrides: { flat: 1 } }, lib), /invalid setting/);
  assert.throws(() => normalizeRequest({ country: "usa" }, lib), /2-letter/);
  const { cfg: c, opts } = applyRequest({ ...cfg, settings: { interact: { minDwellMs: 1 } } }, { scripts: ["stealth", "interact", "arrival"], overrides: { "interact.mode": "passive", "arrival.from": "gmail" } });
  assert.deepEqual(c.settings.interact, { minDwellMs: 1, mode: "passive" });
  assert.equal(c.settings.arrival.from, "gmail");
  assert.ok(opts.scripts.every((f) => path.isAbsolute(f) && fs.existsSync(f)));
  // first web UI version's requests still rescan
  const legacy = normalizeRequest({ persona: "android", interaction: "passive", arrival: "outlook" }, lib);
  assert.deepEqual([legacy.overrides, legacy.extraScripts], [{ "interact.mode": "passive", "arrival.from": "outlook" }, ["arrival"]]);
});

test("urls: extract from messy text, refang, dedupe, skip non-URLs", () => {
  const { parseUrls } = require("../core/urls");
  const { urls, bad } = parseUrls(`id,url,seen\n1,hxxps://evil[.]example/login,2026-10-01\n2,"https://evil.example/login"\nsee (bad.example.net/x); 3.5 ftp://x.example javascript:alert(1) 10.0.0.1/admin`);
  assert.deepEqual(urls, ["https://evil.example/login", "https://bad.example.net/x", "https://10.0.0.1/admin"]);
  assert.ok(bad.includes("3.5") && bad.includes("2026-10-01") && bad.includes("ftp://x.example") && bad.includes("javascript:alert(1)"));
});

test("report: markdown and html escape and defang hostile values", () => {
  const { scanMarkdown, scanHtml } = require("../core/report");
  const dir = tmpdir("sbx-report-");
  const s = { id: "20261013-000000-abcdef", dir, iocs: [{ type: "url", value: "https://x.example/<script>|`", context: ["credential submission (POST)"] }],
    result: { url: "https://x.example/", finalUrl: "https://x.example/", title: "<img src=x onerror=alert(1)> | **bold**", httpStatus: 200, persona: "desktop", redirectChain: ["https://x.example/"] } };
  const h = scanHtml(s), m = scanMarkdown(s);
  assert.ok(!h.includes("<img src=x") && !h.includes("<script>") && h.includes("hxxps://x[.]example") && h.includes("default-src 'none'"));
  assert.ok(m.includes("\\<img") && m.includes("\\|") && !m.includes("https://x.example"));
  assert.ok(h.includes("Credentials typed into the page were sent to"));
});

test("stealth: Playwright's disabled features are found and merged", () => {
  const { playwrightDisabledFeatures } = require("../scripts/stealth");
  const f = playwrightDisabledFeatures();
  // If Playwright moves this list, the merge would silently drop it.
  for (const name of ["Translate", "HttpsUpgrades", "PaintHolding"]) assert.ok(f.includes(name), name);
});

test("targets: resume gate hooks into Playwright", () => {
  assert.equal(require("../lib/targets").installResumeGate(), true);
});

test("targets: handlers run on nested children before they resume", async () => {
  const { watchChildren } = require("../lib/targets");
  const EventEmitter = require("events");
  const cdp = new EventEmitter();
  const sent = [];
  // A fake page session: one iframe, which has one Worker.
  cdp.send = async (method, params) => {
    sent.push([method, params]);
    if (method !== "Target.sendMessageToTarget") return {};
    const inner = JSON.parse(params.message);
    const reply = (sid, msg) => setImmediate(() => cdp.emit("Target.receivedMessageFromTarget", { sessionId: sid, message: JSON.stringify(msg) }));
    if (params.sessionId === "F") {
      if (inner.method === "Target.sendMessageToTarget") {
        const deeper = JSON.parse(inner.params.message);
        reply("F", { id: inner.id, result: {} });
        reply("F", { method: "Target.receivedMessageFromTarget", params: { sessionId: "W", message: JSON.stringify({ id: deeper.id, result: { echo: deeper.method } }) } });
        return {};
      }
      reply("F", { id: inner.id, result: {} });
      if (inner.method === "Runtime.runIfWaitingForDebugger") reply("F", { method: "Target.attachedToTarget", params: { sessionId: "W", targetInfo: { type: "worker", url: "blob:x", targetId: "w1" } } });
    }
    return {};
  };
  const w = await watchChildren(cdp);
  const seen = [];
  w.add(async (t) => { seen.push(`${t.type}:${t.parent ? t.parent.type : "page"}`); seen.push((await t.send("Debugger.enable")) ? "sent" : "?"); });
  cdp.emit("Target.attachedToTarget", { sessionId: "F", targetInfo: { type: "iframe", url: "https://x.example/", targetId: "f1" } });
  await new Promise((r) => setTimeout(r, 100));
  assert.deepEqual(seen, ["iframe:page", "sent", "worker:iframe", "sent"]);
  // The iframe was resumed only after its handler and nested auto-attach.
  const order = sent.filter(([m, p]) => m === "Target.sendMessageToTarget" && p.sessionId === "F").map(([, p]) => JSON.parse(p.message).method);
  assert.deepEqual(order.slice(0, 3), ["Debugger.enable", "Target.setAutoAttach", "Runtime.runIfWaitingForDebugger"]);
});

test("api: findings from setup wait for `when` and are dropped if it never matches", async () => {
  const { makeApi } = require("../lib/api");
  const fakePage = (url) => ({ url: () => url, title: async () => "t", on() {}, context: () => ({}) });
  for (const [url, kept] of [["https://evil.example/login", 1], ["https://benign.example/", 0]]) {
    const ctx = { page: fakePage(url), state: {}, log: {}, settings: {}, ioc() {}, dump() {} };
    const g = { gate: "pending", held: [] };
    const api = makeApi(ctx, { name: "t", when: { url: /evil/, request: "exfil" } }, g);
    api.emit.finding("bad", "seen early");
    api.emit.tag("Kit:Test");
    assert.equal(ctx.state.api.findings.length, 0); // held
    api._requests().push("https://x.example/exfil.php");
    if (!(await api._decide())) api._close();
    assert.equal(ctx.state.api.findings.length, kept, url);
    assert.deepEqual([...ctx.state.api.tags], kept ? ["kit:test"] : []);
  }
  assert.throws(() => makeApi({ page: fakePage("x"), state: {}, log: {} }, { name: "t" }).emit.finding("high", "x"), /level/);
});

test("api: scripts using setup/run/when become ordinary hooks", () => {
  const [m] = loadScripts([path.join(__dirname, "..", "examples", "clickfix-signature.js")]);
  assert.equal(typeof m.page, "function");
  assert.equal(typeof m.interact, "function");
  assert.equal(typeof m.on.beforeCapture, "function");
  assert.deepEqual(m.own.hooks, ["setup", "run", "when"]);
  const { test: match } = require("../lib/api");
  assert.ok(match("SIGN IN", "please sign in") && match(/^a/, "abc") && !match("zzz", "abc") && match(undefined, "x"));
});

test("fingerprint: generated profiles are deterministic, varied and fit the screen", () => {
  const fp = require("../core/fingerprint");
  assert.deepEqual(fp.generate("abc").settings, fp.generate("abc").settings);
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const { display: d, window: w, interact, humanize } = fp.generate(`s${i}`).settings;
    seen.add(`${d.width}x${d.height}/${w.width}x${w.height}@${w.x},${w.y}`);
    assert.ok(w.x >= 0 && w.y >= d.panelTop && w.x + w.width <= d.width && w.y + w.height <= d.height, `window fits ${i}`);
    assert.ok(interact.minDwellMs < interact.maxDwellMs && humanize.keyMsMin < humanize.keyMsMax && humanize.mouseStepsMin < humanize.mouseStepsMax);
    for (let j = 0; j < 5; j++) {
      const v = fp.scanSettings({ source: "auto", profile: { settings: { display: d, window: w } } }).window;
      assert.ok(v.x >= 0 && v.y >= d.panelTop && v.x + v.width <= d.width && v.y + v.height <= d.height, `varied window fits ${i}`);
    }
  }
  assert.ok(seen.size > 140, `only ${seen.size} distinct geometries`); // maximized windows repeat, as on real machines
});

test("fingerprint: a user's profile is used as given and never rotated", () => {
  const fp = require("../core/fingerprint");
  const dir = tmpdir("sbx-fp-");
  const file = path.join(dir, "mine.json");
  const mine = { settings: { window: { width: 1300, height: 820, x: 70, y: 40 }, display: { width: 1440, height: 900, panelTop: 25 } } };
  fs.writeFileSync(file, JSON.stringify(mine));
  const cfg = { fingerprint: file, outDir: dir };
  const loaded = fp.load(cfg);
  assert.equal(loaded.source, "user");
  assert.deepEqual(fp.scanSettings(loaded), mine.settings);
  assert.throws(() => fp.rotate(cfg), /yours/);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), mine);
  const auto = fp.load({ outDir: dir });
  assert.equal(auto.source, "auto");
  assert.deepEqual(fp.load({ outDir: dir }).profile, auto.profile); // reused, not regenerated
  assert.notEqual(fp.rotate({ outDir: dir }).profile.seed, auto.profile.seed);
  assert.equal(fp.load({ fingerprint: "off", outDir: dir }).profile, null);
});

test("identity: generated values look real and vary by profile", () => {
  const ids = require("../lib/identity");
  const { rng } = require("../core/fingerprint");
  const a = ids.newSpec(rng("one")), b = ids.newSpec(rng("two"));
  assert.notDeepEqual(a.domains, b.domains);
  for (let i = 0; i < 100; i++) {
    const e = ids.email(a), p = ids.password(a);
    assert.match(e, /^[a-z][a-z._0-9]+@[a-z-]+\.(com|net|co|io|org)$/);
    assert.ok(!/\.test$|example/.test(e), e);
    assert.ok(p.length >= 8 && /\d/.test(p) && /[A-Z]/.test(p), p);
  }
});

test("sites: real services are recognised, kits on hosting platforms are not", () => {
  const { isRealService, site, setSkipDomains } = require("../lib/sites");
  for (const u of ["https://login.microsoftonline.com/common/oauth2", "https://contoso.sharepoint.com/sites/Finance", "https://outlook.office.com/mail/", "https://accounts.google.com/"]) assert.equal(isRealService(u), true, u);
  for (const u of ["https://o365-secure-login.vercel.app/", "https://sharepoint-docs-view.pages.dev/", "https://keycloak-auth-portal.netlify.app/", "https://login-outlook365.yzz.me/"]) assert.equal(isRealService(u), false, u);
  assert.equal(site("https://a.b.co.uk/x"), "b.co.uk");
  setSkipDomains(["corp.example"]); // your own Keycloak or ADFS
  assert.equal(isRealService("https://sso.corp.example/realms/staff/protocol/openid-connect/auth"), true);
  setSkipDomains([]);
});

test("third-party credential submissions are judged against the kit, not the final page", () => {
  const { extractIocs } = require("../core/iocs");
  const dir = tmpdir("sbx-kit-");
  fs.mkdirSync(path.join(dir, "assets"));
  const entry = (url, method, body) => ({ request: { url, method, postData: body ? { text: body } : undefined }, response: { status: 200, content: { size: 0 } } });
  fs.writeFileSync(path.join(dir, "assets", "traffic.har"), JSON.stringify({ log: { entries: [
    entry("https://kit.vercel.app/api/contact", "POST", "email=victim%40corp.example&pw=Secret123!"),
    entry("https://api.telegram.org/bot1/sendMessage", "POST", "text=victim@corp.example Secret123!"),
  ] } }));
  const result = { url: "https://kit.vercel.app/", finalUrl: "https://www.realservice.example/", redirectChain: ["https://kit.vercel.app/"] };
  const iocs = extractIocs(dir, result, { emails: ["victim@corp.example"], passwords: ["Secret123!"] });
  const ctx = (u) => iocs.find((i) => i.value === u).context.join(";");
  assert.match(ctx("https://kit.vercel.app/api/contact"), /credential submission \(POST\)$/);
  assert.match(ctx("https://api.telegram.org/bot1/sendMessage"), /third-party/);
});

test("vision: puzzle instructions map to objects in several languages", () => {
  const { classFor } = require("../lib/vision");
  const cases = { autobus: "bus", biciclette: "bicycle", motocicli: "motorcycle", crosswalks: "crosswalk", "traffic lights": "traffic light",
    Hydranten: "fire hydrant", voitures: "car", "strisce pedonali": "crosswalk", escaleras: "stairs", ponts: "bridge", palmeras: "palm tree", taxis: "taxi" };
  for (const [word, cls] of Object.entries(cases)) assert.equal(classFor(word), cls, word);
  assert.equal(classFor("unicorns"), null);
});

const visionDir = "/usr/local/lib/sbx/vision";
test("vision: recognises objects on real puzzle tiles", { skip: !require("../lib/vision").ready(visionDir) && "models not installed" }, async () => {
  const v = require("../lib/vision");
  const read = (f) => fs.readFileSync(path.join(__dirname, "fixtures", f));
  // 4x4 grid (388 px): one bus over the middle columns, lower rows.
  const bus = (await v.detect(visionDir, read("recaptcha-bus-4x4.png"))).find((b) => b.cls === 5);
  assert.ok(bus && bus.x1 > 97 && bus.x2 < 291 && bus.y1 > 97, JSON.stringify(bus));
  // A 3x3 tile with a motorcycle, and one with only cars.
  const moto = await v.clipScore(visionDir, read("recaptcha-motorcycle-tile.png"), "motorcycle");
  const cars = await v.clipScore(visionDir, read("recaptcha-cars-tile.png"), "motorcycle");
  assert.ok(moto.best === "motorcycle" || moto.p >= 0.3, JSON.stringify(moto));
  assert.ok(cars.p < 0.1, JSON.stringify(cars));
});

test("page states: changes are named the way a person would see them", () => {
  const { whatChanged } = require("../lib/timeline");
  const sig = (url, title = "t", text = 10, fields = 2, frames = 1, dialogs = 0) => [url, title, text, fields, frames, dialogs].join("|");
  assert.equal(whatChanged(sig("https://k.example/a"), sig("https://k.example/b")), "navigated");
  assert.equal(whatChanged(sig("https://k.example/a"), sig("https://k.example/a#step2")), "address changed");
  assert.equal(whatChanged(sig("https://k.example/"), sig("https://k.example/", "t", 10, 2, 1, 1)), "dialog opened");
  assert.equal(whatChanged(sig("https://k.example/"), sig("https://k.example/", "t", 10, 3)), "form changed");
  assert.equal(whatChanged(sig("https://k.example/"), sig("https://k.example/", "t", 14)), "content added");
});

test("humanize: the profile's speed never shortens a hold below its threshold", async () => {
  const h = require("../lib/humanize");
  const waits = [];
  const page = { waitForTimeout: async (ms) => { waits.push(ms); } };
  for (const speed of [0.8, 1, 1.25]) { h.setTuning({ speed }); await h.hold(page, 1350); }
  h.setTuning({ speed: 1 });
  assert.ok(waits.every((ms) => ms >= 1350 - 1e-9), JSON.stringify(waits));
  assert.ok(waits[2] > 1350); // a slow profile holds longer
});

test("timeline: a one-colour frame between two pages is not a state", () => {
  const { blank } = require("../lib/timeline");
  const { PNG } = require("pngjs");
  const png = new PNG({ width: 64, height: 48 });
  png.data.fill(0xf3);
  assert.equal(blank(PNG.sync.write(png)), true);
  png.data[(20 * 64 + 30) * 4] = 0; // a few dark pixels: content
  for (let i = 0; i < 64 * 48 * 4; i += 4 * 9) png.data[i] = 0;
  assert.equal(blank(PNG.sync.write(png)), false);
});
