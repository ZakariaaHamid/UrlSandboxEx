# Command line

```
urlsandboxex <url ...> [options]
```

## Input

Arguments, a file (`--file=PATH`) or standard input (`--file=-`). Any
text works: URLs are pulled out of lists, CSV, e-mail bodies; defanged
forms (`hxxp`, `[.]`) are restored, bare domains get `https://`,
duplicates and non-URLs are dropped.

One URL is a single scan; two or more are a batch (up to 1000). `--name`
makes a batch of one URL.

## Options

| Option | Effect |
|---|---|
| `--file=PATH` | read URLs from a file; `-` reads standard input |
| `--parallel=N` | batch scans run at once (default `web.maxConcurrent`, max 16) |
| `--name=NAME` | batch name, shown in the web UI and reports |
| `--out=PATH` | one scan: write the report to PATH (`.html`, `.md` or `.json` by extension); batch: write a self-contained report folder |
| `--format=F` | what goes to standard output: `text` (default), `json`, `md`, `html`; `--json` is the same as `--format=json` |
| `--profile=NAME` | apply a profile saved in the web UI; other options override it |
| `--persona=NAME` | `desktop` (default), `android`, `iphone`, `firefox`, `safari` |
| `--country=CC` | residential proxy exit country (ignored without a proxy) |
| `--scripts=a,b` | replace the script list; `--scripts=` runs the core alone |
| `--script=FILE` | add a script (repeatable); built-in names work too, e.g. `--script=arrival` |
| `--referer=URL` | Referer header for the first request |
| `--set key.path=value` | override any config key (repeatable); values are parsed as JSON when possible |

## Examples

```
urlsandboxex hxxps://evil[.]example/login
urlsandboxex https://evil.example --out=evil.html
urlsandboxex https://evil.example --persona=android --country=de
urlsandboxex https://evil.example --script=arrival --set settings.arrival.from=outlook
urlsandboxex --file=feed.csv --parallel=3 --name=today
grep -h http mails/*.eml | urlsandboxex --file=- --out=report/
urlsandboxex https://evil.example --format=json | jq .sinks
```

## Output

- One scan prints its result, indicators and the report path. A batch
  prints a line per URL on standard error, then a summary.
- Every scan writes `report.html` and `report.md` in its directory. A
  batch also writes `index.html`, `report.md`, `summary.csv`, `iocs.csv`
  and `iocs.json` to `~/sbx-scans/batches/<id>/`; `--out=DIR` puts them,
  with each scan's report, in one folder you can share.
- `--format=json` prints a summary (a `results` array for a batch); `md`
  and `html` print the report.
- CLI batches show in the web UI while they run. Ctrl+C cancels the rest.

## Fingerprint

`urlsandboxex fingerprint show` prints the current profile; `urlsandboxex fingerprint rotate`
replaces a generated one. See [Configuration](configuration.md#fingerprint-profile).

## Checking a script

`urlsandboxex script check FILE` exits 1 if a script makes the sandbox detectable
or easier to evade. See [Script API](api.md#checking-a-script).

## Exit status

| Code | Meaning |
|---|---|
| 0 | every URL was scanned (page errors such as DNS failures are results) |
| 1 | at least one scan failed to run |
| 2 | usage error, or no URLs found in the input |
