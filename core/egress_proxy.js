// The jailed browser's only way out: Chrome uses a loopback proxy inside
// the jail, bridged to this server over a unix socket. Running egress here,
// outside the jail, gives:
//   - SSRF policy: hostnames are resolved here and the connection goes to
//     the checked address, so a page can't reach loopback, private ranges,
//     cloud metadata or this host (DNS rebinding included);
//   - residential upstream, with credentials kept out of the jail;
//   - no UDP/WebRTC path to the host's real IP (the jail has no route);
//   - a log of every connection and blocked attempt.
// HTTPS is a byte-for-byte CONNECT tunnel, so servers see Chrome's own TLS
// fingerprint; plain HTTP is forwarded with the browser's header order and
// casing preserved.

const http = require("http");
const net = require("net");
const dns = require("dns").promises;
const fs = require("fs");

const BLOCKED_V4 = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"];
// ::ffff:0:0/96 (IPv4-mapped) is deliberately absent: net.BlockList
// matches plain IPv4 addresses against it too. Mapped addresses are
// unwrapped and checked against the IPv4 list instead (isBlocked below).
const BLOCKED_V6 = ["::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "fec0::/10", "ff00::/8"];

function makeBlockList() {
  const bl = new net.BlockList();
  for (const c of BLOCKED_V4) { const [a, p] = c.split("/"); bl.addSubnet(a, Number(p), "ipv4"); }
  for (const c of BLOCKED_V6) { const [a, p] = c.split("/"); bl.addSubnet(a, Number(p), "ipv6"); }
  // Every address of this host, public ones included.
  for (const addrs of Object.values(require("os").networkInterfaces())) {
    for (const a of addrs || []) bl.addAddress(a.address, a.family === "IPv6" ? "ipv6" : "ipv4");
  }
  return bl;
}

function isBlocked(bl, address) {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped) return bl.check(mapped[1], "ipv4");
  return bl.check(address, net.isIP(address) === 6 ? "ipv6" : "ipv4");
}

/**
 * @param {object} o
 * @param {string} o.socketPath       unix socket to listen on
 * @param {string} [o.logPath]        JSONL connection log
 * @param {{server: string, username?: string, password?: string}|null} [o.upstream]  residential HTTP proxy
 * @param {string[]} [o.allow]        "host:port" exceptions to the private-address policy (e.g. the local test harness)
 * @returns {Promise<{close: () => Promise<void>, stats: object}>}
 */
async function startEgressProxy({ socketPath, logPath = null, upstream = null, allow = [] }) {
  const blockList = makeBlockList();
  const allowSet = new Set(allow.map((s) => s.toLowerCase()));
  const stats = { connections: 0, blocked: 0, bytesIn: 0, bytesOut: 0 };
  const logStream = logPath ? fs.createWriteStream(logPath, { flags: "a" }) : null;
  const log = (entry) => { if (logStream) logStream.write(JSON.stringify({ t: new Date().toISOString(), ...entry }) + "\n"); };
  const upstreamUrl = upstream ? new URL(upstream.server) : null;
  const upstreamAuth = upstream && upstream.username ? "Basic " + Buffer.from(`${upstream.username}:${upstream.password || ""}`).toString("base64") : null;

  // Direct mode: resolve and police. Upstream mode: the residential proxy
  // resolves on its side (it can't reach our private ranges anyway); only
  // literal private IPs are refused up front.
  async function resolveTarget(host, port) {
    const bare = host.replace(/^\[|\]$/g, "");
    if (allowSet.has(`${bare}:${port}`.toLowerCase())) return { ok: true, address: bare, addresses: [bare] };
    const family = net.isIP(bare);
    if (family) {
      return isBlocked(blockList, bare) ? { ok: false, reason: "private-or-local-address", address: bare } : { ok: true, address: bare, addresses: [bare] };
    }
    if (upstream) return { ok: true, address: null };
    let addrs;
    try { addrs = await dns.lookup(bare, { all: true, verbatim: true }); } catch (e) { return { ok: false, reason: `dns:${e.code || e.message}` }; }
    if (!addrs.length) return { ok: false, reason: "dns:no-address" };
    const bad = addrs.find((a) => isBlocked(blockList, a.address));
    if (bad) return { ok: false, reason: "resolves-to-private-or-local-address", address: bad.address };
    // Interleave families (v6, v4, v6, ...) so a broken route for one
    // family falls back quickly, like a browser's Happy Eyeballs.
    const v6 = addrs.filter((a) => a.family === 6).map((a) => a.address), v4 = addrs.filter((a) => a.family === 4).map((a) => a.address);
    const order = [];
    for (let i = 0; i < Math.max(v6.length, v4.length); i++) { if (v6[i]) order.push(v6[i]); if (v4[i]) order.push(v4[i]); }
    return { ok: true, address: order[0], addresses: order };
  }

  // Raw TCP stream to host:port, direct or tunnelled through the upstream.
  // Happy Eyeballs (RFC 8305-style): start the next address 250ms after the
  // previous one, keep the first that connects, drop the rest.
  function raceConnect(addresses, port) {
    return new Promise((resolve, reject) => {
      let done = false, failed = 0;
      const sockets = [];
      const timers = [];
      addresses.forEach((addr, i) => {
        timers.push(setTimeout(() => {
          if (done) return;
          const s = net.connect({ host: addr, port });
          sockets.push(s);
          s.once("connect", () => {
            if (done) { s.destroy(); return; }
            done = true; timers.forEach(clearTimeout);
            for (const o of sockets) if (o !== s) o.destroy();
            resolve(s);
          });
          s.once("error", (e) => { if (++failed === addresses.length && !done) { done = true; reject(e); } });
        }, i * 250));
      });
      setTimeout(() => { if (!done) { done = true; sockets.forEach((x) => x.destroy()); reject(new Error("connect timeout")); } }, 20000);
    });
  }

  async function openStream(host, port, address, addresses = [address]) {
    if (!upstream) return raceConnect(addresses, port);
    return new Promise((resolve, reject) => {
      const s = net.connect({ host: upstreamUrl.hostname, port: Number(upstreamUrl.port) || 80 });
      s.setTimeout(30000, () => s.destroy(new Error("upstream timeout")));
      s.once("error", reject);
      s.once("connect", () => {
        const target = net.isIP(host) === 6 ? `[${host}]:${port}` : `${host}:${port}`;
        s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${upstreamAuth ? `Proxy-Authorization: ${upstreamAuth}\r\n` : ""}\r\n`);
        let buf = Buffer.alloc(0);
        const onData = (d) => {
          buf = Buffer.concat([buf, d]);
          const end = buf.indexOf("\r\n\r\n");
          if (end === -1) { if (buf.length > 16384) s.destroy(new Error("upstream: oversized CONNECT reply")); return; }
          s.removeListener("data", onData);
          const status = Number(buf.slice(0, end).toString().split(" ")[1]);
          if (status !== 200) return reject(new Error(`upstream CONNECT ${status}`));
          s.setTimeout(0);
          const rest = buf.slice(end + 4);
          if (rest.length) s.unshift(rest);
          resolve(s);
        };
        s.on("data", onData);
      });
    });
  }

  function count(a, b) {
    a.on("data", (d) => { stats.bytesOut += d.length; });
    b.on("data", (d) => { stats.bytesIn += d.length; });
  }

  const server = http.createServer(async (req, res) => {
    // Plain-HTTP proxying: absolute-form request URL.
    let target;
    try { target = new URL(req.url); } catch (e) { res.writeHead(400).end(); return; }
    if (target.protocol !== "http:") { res.writeHead(400).end(); return; }
    const port = Number(target.port) || 80;
    stats.connections++;
    const r = await resolveTarget(target.hostname, port);
    if (!r.ok) {
      stats.blocked++;
      log({ kind: "http", host: target.hostname, port, blocked: r.reason, address: r.address || null });
      res.writeHead(403, { "Content-Type": "text/plain" }).end("blocked by sandbox egress policy");
      return;
    }
    log({ kind: "http", host: target.hostname, port, address: r.address, method: req.method });
    const headers = [];
    for (let i = 0; i < req.rawHeaders.length; i += 2) {
      if (/^proxy-/i.test(req.rawHeaders[i])) continue;
      headers.push(req.rawHeaders[i], req.rawHeaders[i + 1]);
    }
    let stream;
    try { stream = await openStream(target.hostname, port, r.address, r.addresses); } catch (e) {
      log({ kind: "http", host: target.hostname, port, error: e.message });
      res.writeHead(502).end();
      return;
    }
    // No `agent` option: Node only honors createConnection when no agent is
    // given (agent:false silently opens its own socket to localhost:80).
    const preq = http.request({ createConnection: () => stream, method: req.method, path: target.pathname + target.search, headers, setHost: false });
    preq.on("response", (pres) => {
      const raw = [];
      for (let i = 0; i < pres.rawHeaders.length; i += 2) raw.push(pres.rawHeaders[i], pres.rawHeaders[i + 1]);
      res.writeHead(pres.statusCode, pres.statusMessage, raw);
      pres.on("data", (d) => { stats.bytesIn += d.length; });
      pres.pipe(res);
    });
    preq.on("error", () => { if (!res.headersSent) res.writeHead(502); res.end(); });
    req.pipe(preq);
  });

  server.on("connect", async (req, clientSocket, head) => {
    const m = /^\[?([^\]]+)\]?:(\d+)$/.exec(req.url || "");
    if (!m) { clientSocket.end("HTTP/1.1 400 Bad Request\r\n\r\n"); return; }
    const host = m[1], port = Number(m[2]);
    stats.connections++;
    const r = await resolveTarget(host, port);
    if (!r.ok) {
      stats.blocked++;
      log({ kind: "connect", host, port, blocked: r.reason, address: r.address || null });
      clientSocket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
      return;
    }
    let up;
    try { up = await openStream(host, port, r.address, r.addresses); } catch (e) {
      log({ kind: "connect", host, port, error: e.message });
      clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
      return;
    }
    log({ kind: "connect", host, port, address: r.address });
    clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    if (head && head.length) up.write(head);
    count(clientSocket, up);
    up.pipe(clientSocket);
    clientSocket.pipe(up);
    const done = () => { up.destroy(); clientSocket.destroy(); };
    up.on("error", done); clientSocket.on("error", done);
    up.on("close", done); clientSocket.on("close", done);
  });
  server.on("clientError", (e, s) => s.destroy());
  // CONNECT tunnels leave the HTTP server's bookkeeping, so track sockets
  // ourselves to tear everything down when the visit ends.
  const sockets = new Set();
  server.on("connection", (s) => { sockets.add(s); s.on("close", () => sockets.delete(s)); });

  try { fs.unlinkSync(socketPath); } catch (e) { /* not there */ }
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen(socketPath, resolve); });
  fs.chmodSync(socketPath, 0o600);

  return {
    stats,
    close: () => new Promise((resolve) => {
      server.close(() => { if (logStream) logStream.end(resolve); else resolve(); });
      for (const s of sockets) s.destroy();
      setTimeout(resolve, 2000).unref();
    }),
  };
}

module.exports = { startEgressProxy, makeBlockList, isBlocked };
