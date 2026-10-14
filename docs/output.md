# Output

Each scan: `outDir/<YYYYMMDD-HHMMSS-random>/`.

| File | Contents |
|---|---|
| `report.html`, `report.md` | the report; self-contained, values escaped, URLs defanged |
| `result.json` | everything recorded (below) |
| `iocs.json`, `iocs.csv` | indicators |
| `states/NN.png` | a screenshot each time the page changed (load, navigation, new content, CAPTCHA and login steps), at most 40; listed in `timeline` |
| `screenshot.png`, `screenshot_full.png`, `popup_N.png` | screenshots (popups past the second are captured and closed, to bound memory) |
| `dom.html.txt` | rendered DOM |
| `assets/` | every response body, named by sha256, and `traffic.har` |
| `downloads/` | delivered files, named by sha256, no extension |
| `artifacts/` | files written by scripts (generated code, script indicators) |
| `connections.jsonl` | every connection the egress proxy made or blocked |
| `triage.json` | verdict, tags, notes |

## result.json

| Field | Meaning |
|---|---|
| `url`, `finalUrl`, `redirectChain`, `arrivedVia` | navigation |
| `httpStatus`, `mainHeaders`, `tls`, `title` | main response |
| `engine`, `browserVersion`, `persona`, `scripts` | how it was scanned |
| `structure` | forms, password fields, links, storage |
| `cookies`, `websocket`, `console`, `downloads`, `popups` | activity |
| `timeline` | page states: `{ at, reason, url, title, file }`, `at` in ms from the start |
| `scriptFindings`, `scriptTags` | findings and tags reported by scripts |
| `log`, `timings` | script log, milliseconds per phase |
| `navError`, `fatalError`, `timedOut` | failures |
| `sbx.egress` | exit IP, country, organisation, datacenter flag |
| `sbx.identity`, `sbx.request` | values typed; profile, persona, scripts and overrides used |

## Indicators

Each has `type`, `value` and `context` (where it was seen).

| Type | Source |
|---|---|
| `url` | submitted, redirects, final, popups, downloads, WebSockets, exfil endpoints, QR codes; `credential submission` when it carried a typed value |
| `domain` | contacted hosts; hosts the egress policy blocked |
| `ip` | resolved addresses |
| `sha256` | each response body as received (after decompression) and each download; the files are in `assets/` and `downloads/` |
| `tls` | final host's certificate |
| `clipboard` | clipboard contents during the visit |
| `email`, `wallet`, `telegramBotToken`, `telegramChatId`, `qr` | found in page code or QR codes |

## Batches

`outDir/batches/<id>.json` holds the URLs, their state and scan IDs. CLI
batches also get `outDir/batches/<id>/` with `index.html`, `report.md`,
`summary.csv`, `iocs.csv`, `iocs.json`. CSV cells that could run as
spreadsheet formulas are prefixed with an apostrophe.

`outDir/profiles.json` holds saved profiles; `outDir/audit.jsonl` the web
UI activity log.
