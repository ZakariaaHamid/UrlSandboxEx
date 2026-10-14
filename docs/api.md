# Script API

How to write a script. Everything it does is invisible to the page.
Complete example: `examples/clickfix-signature.js`.

```js
// my-kit: one sentence, shown in the web UI.
module.exports = {
  name: "my-kit",
  settings: { myKit: { minLength: 200 } },                  // --set or web UI
  ui: { "myKit.minLength": { help: "ignore shorter code" } },
  when: { text: /sign in/i, dom: "input[type=password]" },  // optional

  setup(api) {                                               // before the page loads
    api.code.on((c) => { if (/atob\(/.test(c.source)) api.emit.dump(`stage-${c.sha256}.js`, c.source); });
    api.net.on("request", { method: "POST" }, (r) => api.emit.ioc("url", r.url, "form post"));
  },
  async run(api) {                                           // after load and interaction
    if ((await api.page.query("form")).length > 1) api.emit.finding("warn", "several forms");
    api.emit.tag("kit:mine");
  },
};
```

## Lifecycle

- `setup(api)`: each page and popup, before navigation. Register
  observers here.
- `run(api)`: once, on the main page, after load and after the scripts
  listed before it interacted. If `when` matches only later, just before
  capture.
- `when`: `run` happens only on matching pages, and whatever `setup`
  observers emitted is kept only if the page matches by capture time.
  A kit-specific script stays silent elsewhere.

`when` keys, all of which must match (an array of objects matches if any
does; a function `async (api) => boolean` also works):

| Key | Tests |
|---|---|
| `url`, `title`, `text` | current URL, title, visible text |
| `dom` | a CSS selector finds an element |
| `request` | a request URL the page made |

Strings match as case-insensitive substrings; RegExps as written.

## api.page

Reads run in an isolated world: same DOM, none of the page's JavaScript.

| Call | Returns |
|---|---|
| `url()`, `title()`, `text()`, `html()` | URL, title, visible text, rendered HTML |
| `query(selector)` | up to 200 elements as `{ tag, text, attrs }` |
| `read(fn, arg)` | `fn(arg)` in the isolated world; return plain data |
| `waitFor(condition, { timeout })` | waits for a `when`-style condition; `true` or `false` |

## api.net

`api.net.on("request" | "response", filter, fn)`, observed in the
browser's network layer; iframes and Workers included.

Filter keys: `url` (substring or RegExp), `method` (`"POST"`,
`"GET|POST"`), `type` (`"document"`, `"script"`, `"xhr"`,
`"document|script"`...), `status` (responses: a number or list).

`fn` gets `{ url, method, type, headers, postData }`, and for responses
`status`, `responseHeaders`, `body()` and `text()`.

## api.code

`api.code.on(fn)`: every piece of generated code (`eval`, `new Function`,
string timers, `blob:`/`data:` scripts) in the page, its cross-site
iframes and Workers, once each. `fn` gets `{ source, sha256, target,
targetUrl, url, from }`, `target` being `"page"`, `"iframe"` or
`"worker"`. The debugger never pauses, so `debugger;` traps measure
nothing.

## api.emit

| Call | Effect |
|---|---|
| `finding(level, text)` | key finding, `"bad"`, `"warn"` or `"info"`; shown in the report and scan list |
| `tag(tag)` | scan tag, shown in the scan list and searchable |
| `ioc(type, value, context)` | indicator |
| `dump(name, data, { append })` | file in `artifacts/` |
| `log(key, value)` | entry in `result.json` `log`, under the script's name |

Also: `api.settings`, `api.persona`, `api.identity`, `api.isPopup`,
`api.human()` (the interaction library) and `api.playwright` (`{ page,
context }`). Raw Playwright calls such as `page.evaluate` run in the
page's own world, where a kit can detect them.

## Checking a script

```
urlsandboxex script check FILE [--persona=android] [--pages=quick|all|none|a,b]
```

1. Detection: a probe page is scanned twice without the script and once
   with it. It records what a careful kit checks: whether about 50 hooked
   objects and 20 call paths still look native, globals and property
   shapes, `navigator` and screen values, DevTools leaks, foreign code
   calling DOM APIs, the same in a Worker. Any value stable without the
   script that changes with it fails.
2. Evasion, if the research harness runs: 18 of its pages without and
   with the script (`all`: 117; `none`: skip). A page that stops passing,
   or a new fingerprint inconsistency, fails; failures are retried once.

A script that throws also fails. `examples/function-hooks.js` fails
(it replaces `document.write`); `examples/clickfix-signature.js` passes.

## Staying invisible

- Read with `api.page`, observe with `api.net` and `api.code`; do not wrap
  page functions.
- Change what the page sees only on purpose, through a persona or
  `ctx.onSession` ([Scripts](scripts.md)).
- Run `urlsandboxex script check` before deploying.
