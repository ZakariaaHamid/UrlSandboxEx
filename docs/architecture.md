# Architecture

```
host                                   jail (bubblewrap, no network)
urlsandboxex.js / web/server.js                 core/visit.js -> core/browse.js
  config, scripts                        Xvfb, window manager, audio
  egress proxy  <--- unix socket --->    Google Chrome (own sandbox on)
  run the jail                           script hooks, capture
  indicators, after() hooks, reports
```

## Jail (`core/jail.js`)

- Rootless, two stages. The outer one gives the jail its own network
  namespace with a dummy LAN interface and no route out.
- The inner one has no capabilities, a read-only system and a private
  `/tmp`; only the visit directory is writable. The project directory is
  read-only, with the config file (proxy password) blanked.
- Chrome's own sandbox runs inside. Memory, CPU and task limits come from
  a systemd user scope; `jail.timeoutSec` ends the visit.
- Only the `sbx` group can run the bubblewrap copy; AppArmor allows it
  user namespaces.

## Egress (`core/egress_proxy.js`)

The browser's only way out. It resolves names itself and blocks loopback,
private, link-local and metadata addresses and this host's IPs, including
via DNS rebinding. HTTPS is tunnelled untouched (real TLS fingerprint).
With a residential proxy it chains through a new sticky session per
visit. Every connection is logged to `connections.jsonl`.

## Browser (`core/browse.js`)

Phases, timed in `result.timings`: display and services; launch, `ready`
and `page` hooks; navigation; `interact` hooks; capture; `afterCapture`.

- Script reads run in DevTools isolated worlds, cross-site iframes
  included: the page sees no injected code.
- New cross-site iframes and Workers stay paused until the scripts' setup
  for them is done (`lib/targets.js`).
- Overrides scripts register with `ctx.onSession` are applied to every
  DevTools session, so no session can undo them.
- Hooks and body reads have time limits, so a page that never settles
  cannot stall capture.

After the jail exits, the host builds indicators (`core/iocs.js`), runs
`after` hooks and writes reports (`core/report.js`).

## Security model

- Page code runs only in Chrome, in the jail, which cannot write outside
  its visit directory or reach the host, the LAN or cloud metadata.
- Scripts are trusted, chosen by the operator; the web UI never accepts
  code. `after` hooks run on the host.
- Page-derived data is hostile: escaped, URLs defanged, artifacts served
  as downloads, samples saved without extensions, CSV formula-safe.
- The web UI listens on loopback, refuses unknown Host headers and
  cross-origin POSTs, and sends a strict CSP.
