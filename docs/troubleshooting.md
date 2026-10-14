# Troubleshooting

| Problem | Fix |
|---|---|
| `/usr/local/lib/sbx/bwrap missing` | run `sudo deploy/setup.sh` |
| Permission denied when a scan starts | join the `sbx` group and log in again, or use `sg sbx -c "..."` |
| Local or private addresses fail | blocked on purpose; allow one for a run: `--set 'egress.allow=["127.0.0.1:3000"]'` |
| Decoy, 404 or blank page | likely cloaking: set `egress.residentialProxy` and `--country`; try `--persona=android`; add `--script=arrival` (e.g. `outlook`) or `--script=clock` |
| Scan hits the time limit | `result.json` has `timedOut: true`; see `timings`. Raise `jail.timeoutSec` or lower `delays.settleMaxMs` |
| Out of memory | raise `jail.memoryMax`, or lower `web.maxConcurrent` / `--parallel` |
| reCAPTCHA "image puzzles not solved" | `log.challenges[].rounds` shows each round; a residential exit (`egress.residentialProxy`) means fewer and easier rounds |
| reCAPTCHA "image solving is not installed" or "audio solving is not installed" | run `sudo deploy/setup.sh` |
| "Copy failed" in the web UI | open it as `http://127.0.0.1:8090` through the SSH tunnel |
| `unknown host` | add the name to `web.allowedHosts` |

Logs: a scan's `result.json` (`log`, `timings`, `navError`, `fatalError`)
and `connections.jsonl`; `outDir/audit.jsonl`; the web server's output.
