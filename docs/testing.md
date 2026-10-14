# Testing

## Unit tests

```
npm test
```

No browser or jail needed.

## Evasion harness

The research harness (`../benchmark`, on `http://127.0.0.1:3000`) serves
one page per evasion technique, 117 in all, each reporting whether its
content was revealed.

```
node tools/selftest.js [--persona=android] [--parallel=3] [--only=a,b] [--script=FILE]
```

Results go to the harness's `results/sbx_selftest_<persona>.json`
(`--bench=PATH` or `SBX_BENCH` if it lives elsewhere, `--base` for another
URL). Outcomes: `defeated` (real content reached), `evaded`, `n/a`
(informational), and `clean`/`tells` for the fingerprint probe.

Current: 106 to 107 of 117 defeated on desktop, 109 to 110 on android. The desktop
misses need phone sensors (use android), `arrival` (referrer gates) or
`clock` (business hours). A fingerprint profile with a full-width window
also fails the "widen your window" gate, as a maximized browser would.

## Checking a script

```
urlsandboxex script check FILE [--persona=android] [--pages=quick|all|none|a,b]
```

See [Script API](api.md#checking-a-script).

## reCAPTCHA audio

`test/recaptcha-mock/` reproduces reCAPTCHA v2's checkbox, image puzzle and
audio challenge offline (cross-site frames, preloaded clip, token field),
so the audio solver can be tested without Google:

```
python3 test/recaptcha-mock/server.py &
urlsandboxex http://127.0.0.1:3014/ --set 'egress.allow=["127.0.0.1:3014","localhost:3014"]'
```

`log.challenges` should read `solved by audio`.

## Fingerprint pages

`test/detector.html` and `test/instrument-test.html` show what anti-bot
and anti-debugging code sees:

```
python3 -m http.server 3011 --directory test &
urlsandboxex http://127.0.0.1:3011/detector.html --set 'egress.allow=["127.0.0.1:3011"]'
```
