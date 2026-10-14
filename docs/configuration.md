# Configuration

The first file found is used: `$SBX_CONFIG`, `./sbx.config.jsonc`,
`sbx.config.jsonc` next to `urlsandboxex.js`, `~/.config/sbx/config.jsonc`. JSON
with comments. Missing keys keep their defaults; `--set key.path=value`
overrides any key for one run.

| Key | Default | Meaning |
|---|---|---|
| `outDir` | `~/sbx-scans` | scans, batches, profiles, audit log |
| `scripts` | `stealth, challenges, interact, delays, dynamic-code, indicators` | scripts run on every visit, in order |
| `scriptDirs` | `[]` | extra script folders for the web UI (built-ins and `examples/` are always listed) |
| `settings` | `{}` | script settings, by section (see [Scripts](scripts.md)) |
| `fingerprint` | `"auto"` | fingerprint profile: `"auto"`, a file path, an inline object, or `"off"` (below) |
| `egress.residentialProxy` | empty | proxy URL template with `{country}` and `{session}`; empty uses this host's IP |
| `egress.country` | `us` | proxy exit country |
| `egress.geoLookupUrl` | ip-api.com | exit IP geolocation service |
| `egress.allow` | `[]` | `host:port` pairs reachable despite the public-only policy |
| `web.host`, `web.port` | `127.0.0.1`, `8090` | web UI address |
| `web.allowedHosts` | `[]` | extra Host names to accept (reverse proxy) |
| `web.maxConcurrent` | `2` | parallel scans in the web UI; CLI default `--parallel` |
| `jail.bwrap` | `/usr/local/lib/sbx/bwrap` | bubblewrap installed by `setup.sh` |
| `jail.memoryMax`, `jail.cpuQuota`, `jail.timeoutSec` | `2G`, `200%`, `240` | limits per scan |

## Fingerprint profile

Everything a kit could use to recognise this installation, as script
settings: screen and window geometry, interaction pace, mouse and typing
timing, fast-forward amount, and the generator for typed identities.

- `"auto"`: generated from a random seed into `outDir/fingerprint.json` on
  first use, so no two installations look alike. Each scan also varies the
  window slightly. `urlsandboxex fingerprint rotate` draws a new profile when this
  one is burned; `urlsandboxex fingerprint show` prints it.
- A path or an object: your profile, `{ "settings": { ... } }`, used
  exactly as given: never generated, varied or rotated; keys you
  leave out keep the scripts' defaults.
- `"off"`: the scripts' built-in defaults.

Explicit `settings`, `--set` and web UI choices always override the
profile.

## Residential proxy

Kits serve datacenter IPs a decoy. Set a provider template; each visit
gets a new `{session}`, so its own sticky exit IP. HTTP(S) proxies only
(Chromium cannot authenticate to SOCKS5). Credentials stay on the host.

```jsonc
"egress": {
  "residentialProxy": "http://brd-customer-ID-zone-ZONE-country-{country}-session-{session}:PASS@brd.superproxy.io:33335",
  "country": "us"
}
```

More templates are in `sbx.config.example.jsonc`. Language and timezone
follow the exit IP.

## Typed identity

`interact` types an identity into forms, by default generated from the
fingerprint profile (realistic names, company domains, passwords). Kits
that check MX records or account existence still reject invented
addresses; use mailboxes on a domain you control:

```jsonc
"settings": { "identity": { "emails": ["j.morgan@canary.example"], "passwords": ["Spring2026!"] } }
```

Every request that carried a typed value is reported.
