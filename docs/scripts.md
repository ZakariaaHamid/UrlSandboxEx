# Scripts

The core opens the URL and captures it; everything else is a script. To
write one, start with the [script API](api.md). This page lists the
built-ins and the lower-level hooks.

Choose scripts with `"scripts"` in the config, `--scripts=a,b` (replace),
`--script=FILE` (add), or the web UI. They run in list order;
`--scripts=` runs the core alone. Override settings with
`--set settings.<section>.<key>=value` or in the web UI.

## Built-in

| Script | Does |
|---|---|
| `stealth` | personas (`desktop`, `android`, `iphone`, `firefox`, `safari`) consistent in iframes and Workers; language and timezone from the exit IP; real window, window manager, audio devices and voices; native `webdriver=false` |
| `challenges` | clicks Cloudflare, Turnstile, reCAPTCHA v2 and hCaptcha checkboxes along a human path; solves reCAPTCHA image puzzles with object recognition on this server (YOLOX-s and CLIP), falling back to their audio version (whisper.cpp), no third party involved; hCaptcha puzzles are reported, not solved; clicks "Allow" on Chrome permission prompts |
| `interact` | moves, scrolls, types the identity, pastes codes, works gate controls (checkboxes, sliders, press-and-hold, wizards, drag-and-drop, signatures); then completes login steps (below) |
| `delays` | waits while the page is busy, then fast-forwards the virtual clock so delayed content appears without waiting |
| `dynamic-code` | saves generated code (`eval`, `new Function`, string timers, `blob:`/`data:` scripts) from the page, iframes and Workers to `artifacts/` |
| `indicators` | exfil endpoints (Telegram, Discord, webhooks, form services), e-mail and wallet addresses, clipboard contents, QR codes |

Optional, add with `--script=NAME`:

| Script | Does |
|---|---|
| `arrival` | arrives by clicking a link on the referring page: `settings.arrival.from` = `gmail`, `outlook`, `office365`, `sharepoint`, `teams`, `google`, `bing`, `linkedin` or a URL |
| `clock` | shifts the page's clock into business hours (`clock.mode`: `business-hours`, `fixed`, `off`); changes the page, so opt-in |

## Login steps

`interact` fills each step of a kit's login like a victim: email or
username, password, one-time code, phone or name, or a wallet's 12-word
recovery phrase, then submits (button or Enter) and follows the next step,
up to `credentialSteps`. A form in plain view is filled before the general
interaction, so random clicks never submit it empty; a form behind a gate
(fake CAPTCHA, press-and-hold) is filled after it. A landing page with no
fields gets one click on its "Sign in" button. It waits for the page to finish loading and types again
what a late-loading page wiped. Fields the kit filled in (the victim's
address from the link) are kept. A CAPTCHA that appears only once the
form is filled (the submit button stays disabled until it passes) is
solved, then the form is submitted again. It follows the kit to its next
stage on another site (often cloud storage), submits a step the kit
already filled in, and stops when it reaches a real service. It never
fills the login pages of well-known real services
(Microsoft 365, SharePoint, Google and others). Add your own identity
provider, for example a Keycloak or ADFS at `sso.corp.example`, with
`--set 'settings.interact.credentialSkipDomains=["corp.example"]'`. Where
the values went is reported as credential submissions; the steps are in
`result.json` `log.credentials`. Submitting needs `interactive-clicks`.

## Settings

Built-in defaults below. The [fingerprint profile](configuration.md#fingerprint-profile)
replaces many of them per installation; your config overrides both.

| Setting | Default |
|---|---|
| `interact.mode` | `interactive-clicks` (`passive`: mouse and scroll; `interactive`: also typing) |
| `interact.minDwellMs`, `maxDwellMs` | 300, 800 |
| `interact.passiveMoves` | 6 |
| `interact.credentialFlow`, `credentialSteps`, `credentialBudgetMs` | true, 4, 45000 |
| `interact.credentialSkipDomains` | `[]` (added to the built-in list of real services) |
| `humanize.speed` | 1 (multiplies every pause) |
| `humanize.curve` | 0.25 (mouse path bow; 0 is straight) |
| `humanize.mouseStepsMin`, `mouseStepsMax`, `mouseStepMsMin`, `mouseStepMsMax` | 15, 30, 4, 18 |
| `humanize.keyMsMin`, `keyMsMax` | 40, 220 |
| `identity.emails`, `passwords`, `phones`, `names` | empty: generated values |
| `challenges.budgetMs`, `laterBudgetMs` | 30000, 15000 |
| `challenges.permissionPrompts` | true |
| `challenges.images`, `visionDir` | true, `/usr/local/lib/sbx/vision` |
| `challenges.audio`, `whisperDir` | true, `/usr/local/lib/sbx/whisper` |
| `delays.settleMaxMs`, `quietMs` | 20000, 1500 |
| `delays.fastForwardMs` | 90000 (0 disables) |
| `delays.realWaitMs` | 15000 (Firefox and WebKit) |
| `clock.from`, `to`, `at`, `days`, `date` | `09:00`, `17:30`, `10:15`, Monday to Friday, today |
| `display.width`, `height`, `windowManager`, `panelTop` | 1920, 1080, true, 32 |
| `window.width`, `height`, `x`, `y` | 1680, 1000, 96, 40 |
| `scan.navTimeoutMs`, `settleMs`, `interactBudgetMs` | 30000, 5000, 150000 |

## Low-level hooks

```js
// mine: one sentence, shown in the web UI.
module.exports = {
  name: "mine",
  settings: { mine: { depth: 2 } },
  ui: { "mine.depth": { help: "how many links to follow" } },   // options, suggestions, help
  personas: { "de-android": { engine: "chromium", device: "Pixel 7", locale: "de-DE" } },
  services(ctx) { return []; },        // processes started in the jail
  launch(ctx, opts) { return opts; },  // Playwright launch options
  context(ctx, opts) { return opts; }, // browser context options
  ready(ctx) {},                       // once, after launch
  page(ctx) {},                        // each page and popup, before navigation
  navigate(ctx) { return null; },      // replace goto(): { response, via }
  interact(ctx) {},                    // after load
  on: { response(ctx, res) {} },       // Node-side events, 30 s each
  after(host) {},                      // on the host, after the visit
};
```

Hooks run in script order; `launch` and `context` options pass through
each script; the first `navigate` returning a value wins. Events:
`request`, `response`, `requestfailed`, `console`, `dialog`, `download`,
`popup`, `websocket`, `framenavigated`, `worker`, `pageerror`, `load`,
`beforeNavigate`, `afterNavigate`, `beforeCapture`, `afterCapture`.

`ctx`: `settings`, `persona`, `engine`, `locale`, `timezoneId`, `env`,
`page`, `context`, `version`, `isPopup`, `navError`, `state` (shared
scratch), `log` (saved in `result.json`), `dump(name, data, {append})`,
`ioc(type, value, context)`, `sha256(buf)`, `require(lib)` (a module from
`lib/`), and:

- `childTargets(page, handler)`: `handler(t)` runs for each cross-site
  iframe and Worker, at any depth, while it is paused before its first
  line (5 s at most). `t` has `type`, `url`, `parent`,
  `send(method, params)` and `on(event, fn)`. Set things up there; reading
  the target's `navigator` or `location` before it runs can crash the page.
- `onSession(fn)`: `fn(session)` runs on every DevTools session opened
  afterwards. Chrome takes some overrides (`navigator.platform`) from the
  newest session only, so register page-visible overrides here.

`after(host)` runs on the host with network access: `host` has `url`,
`dir`, `result`, `iocs`, `settings`, `ioc()`, `dump()` and `errors`. Its
input comes from a hostile page. The web UI marks such scripts "host hook".

Scripts run in the jail; files outside the project are mounted read-only.

## Examples

| File | Shows |
|---|---|
| `examples/clickfix-signature.js` | the script API: `when`, `code.on`, `net.on`, `run`, findings and tags |
| `examples/custom-persona.js` | a persona, a launch option, an interaction step |
| `examples/function-hooks.js` | in-page hooks on `atob`, `fetch`...; visible to the page, so it fails `urlsandboxex script check` |
| `examples/webhook.js` | an `after` hook posting each scan to a webhook |

The web UI lists the examples and any folder in `scriptDirs`; edits are
picked up without a restart.
