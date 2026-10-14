# Getting started

Requirements: Ubuntu 24.04 (x86_64, systemd), Node.js 22, root once for
setup, 2 GB of memory per concurrent scan.

## Install

From `UrlSandboxEx/`:

```
npm install
npm link                        # installs the urlsandboxex command
sudo deploy/setup.sh            # Chrome, bubblewrap, Xvfb, audio, CAPTCHA models, jail policy
sudo usermod -aG sbx "$USER"    # then log in again
```

Optional, only for the `firefox`, `safari` and `iphone` personas (the
default personas use Google Chrome): `npx playwright install firefox webkit`.

`setup.sh` is idempotent. It installs Google Chrome stable (auto-updated),
the display and audio services the browser needs, and a copy of `bwrap`
that only the `sbx` group may run, with an AppArmor profile allowing it
user namespaces. Until you log in again, prefix commands with
`sg sbx -c "..."`. Without `npm link`, run `node urlsandboxex.js` instead.

## Configure

Optional. `cp sbx.config.example.jsonc sbx.config.jsonc` and edit. Set
`egress.residentialProxy`, or kits that check IP reputation will serve
this server a decoy. See [Configuration](configuration.md).

## Scan

```
urlsandboxex https://example.com
```

Prints the findings and indicators and the path of the scan directory
(`~/sbx-scans/<id>/`, with `report.html`).

## Web UI

```
node web/server.js              # 127.0.0.1:8090
ssh -L 8090:127.0.0.1:8090 user@host    # from your workstation
```

See [Web UI](web-ui.md).
