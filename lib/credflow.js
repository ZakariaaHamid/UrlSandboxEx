// Credential flows: fill a kit's login steps the way a victim does and
// submit them, so the scan shows where each value goes. Email or username,
// then password, then a one-time code, over several pages or in one.
// Values are the scan's identity (canary or generated). Honeypot fields are
// skipped. Page reads run in the caller's isolated world.

const { moveMouseHumanlike, typeChars, pause, randomBetween, typedFiller } = require("./humanize");

const { site, isRealService } = require("./sites");
const timeline = require("./timeline");

const CAPTCHA_FRAME = /challenges\.cloudflare\.com|google\.com\/recaptcha\/|recaptcha\.net\/recaptcha\/|hcaptcha\.com/i;

const SUBMIT = /^(next|continue|sign ?in|log ?in|submit|verify|confirm|proceed|go|let'?s go|ok|send|unlock|access|view( document)?|download|weiter|anmelden|suivant|connexion|se connecter|continuer|siguiente|iniciar sesi[oó]n|acceder|avanti|accedi|próximo|entrar|volgende|inloggen|dalej|zaloguj|ileri|giriş)\b/i;
const SIGNIN = /^(sign ?in|log ?in|login|connexion|se connecter|anmelden|iniciar sesi[oó]n|accedi|entrar|inloggen|zaloguj|giriş yap|my account|access (your )?(wallet|account))$/i;
const NOT_SUBMIT = /forgot|reset|create|sign ?up|register|help|privacy|terms|cookie|cancel|back|another|different/i;

// Visible, fillable fields and the likely submit control, in page order.
function scan() {
  const visible = (el) => {
    if (el.disabled || el.readOnly || el.tabIndex < 0 || el.closest("[aria-hidden=true]")) return false;
    const st = getComputedStyle(el);
    if (st.display === "none" || st.visibility === "hidden" || parseFloat(st.opacity) < 0.1 || st.pointerEvents === "none") return false;
    const r = el.getBoundingClientRect();
    if (r.width < 8 || r.height < 8 || r.bottom < 0 || r.right < 0 || r.top > innerHeight || r.left > innerWidth) return false;
    const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    return !!hit && (hit === el || el.contains(hit) || hit.contains(el) || (el.labels && [...el.labels].some((l) => l.contains(hit))));
  };
  const labelledBy = (el) => (el.getAttribute("aria-labelledby") || "").split(/\s+/).map((id) => document.getElementById(id)?.textContent || "").join(" ");
  const describe = (el) => [el.name, el.id, el.placeholder, el.getAttribute("autocomplete"), el.getAttribute("aria-label"), labelledBy(el), ...(el.labels ? [...el.labels].map((l) => l.textContent) : [])].join(" ").toLowerCase();
  const kindOf = (el) => {
    const t = (el.type || "text").toLowerCase(), d = describe(el), max = el.maxLength > 0 ? el.maxLength : 0;
    if (t === "password" || (t === "text" && /passw|kennwort|contrase|mot de passe|senha|wachtwoord|hasło|şifre/.test(d))) return "password";
    if (/one-time-code/.test(d) || (/otp|code|pin|token|verif|2fa|mfa/.test(d) && (max === 0 || max <= 8))) return "code";
    if (t === "email" || /e-?mail|e-?posta|e-?posta|courriel|correo|user|usuario|utilisateur|utente|benutzer|kullan|gebruiker|użytkownik|login|account|konto|cuenta|compte|conta|identifi|anmelde/.test(d)) return "email";
    if (t === "tel" || /phone|mobile|tel\b|cell/.test(d)) return "phone";
    if (/name/.test(d) && !/user/.test(d)) return "name";
    // An unlabelled text field before a password field in the same form is
    // the username, whatever language its label is in.
    const pw = el.form ? el.form.querySelector("input[type=password]") : null;
    if ((t === "text" || t === "") && pw && (el.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING)) return "email";
    return null;
  };
  // Nothing is written to the page (no marker attributes): fields are
  // addressed by position.
  // Wallet kits ask for the recovery phrase: a grid of 12 or 24 unlabelled
  // word boxes, or one text area. A step fills either that or the login.
  const seedPage = /(recovery|seed|secret|mnemonic|wallet|backup) ?(phrase|words?)|\b(12|24)[- ]word|passphrase/i.test(document.body ? document.body.innerText.slice(0, 20000) : "");
  const all = [...document.querySelectorAll("input:not([type]), input[type=text], input[type=email], input[type=password], input[type=tel], input[type=number], textarea")];
  const wordBox = (el) => el.tagName === "TEXTAREA" || (!kindOf(el) && el.type !== "number") || (el.type === "password" && !/pass|pwd/.test(describe(el)));
  const seedBoxes = seedPage ? all.filter((el) => wordBox(el) && visible(el)) : [];
  const seedMode = seedBoxes.length >= 12 || seedBoxes.some((el) => el.tagName === "TEXTAREA" && el.getBoundingClientRect().height > 40);
  const fields = [];
  let last = null;
  for (const el of seedMode ? seedBoxes : all) {
    const kind = seedMode ? "seed" : el.tagName === "TEXTAREA" ? null : kindOf(el);
    if (!kind || !visible(el)) continue;
    const r = el.getBoundingClientRect();
    fields.push({ kind, x: r.left + r.width / 2, y: r.top + r.height / 2, value: el.value || "", maxLength: el.maxLength > 0 ? el.maxLength : 0, ...(seedMode ? { n: fields.length, whole: el.tagName === "TEXTAREA" } : {}) });
    last = el;
  }
  let submit = null;
  if (last) {
    const text = (b) => (b.innerText || b.value || b.getAttribute("aria-label") || "").trim().replace(/\s+/g, " ");
    const inForm = last.form ? [...last.form.querySelectorAll("button, input[type=submit], input[type=button], [role=button]")] : [];
    const anywhere = [...document.querySelectorAll("button, input[type=submit], input[type=button], [role=button], a[href='#'], a:not([href])")];
    const candidates = [...inForm, ...anywhere].filter((b) => visible(b) && !NOT.test(text(b)));
    const lastBottom = last.getBoundingClientRect().bottom;
    const score = (b) => {
      const r = b.getBoundingClientRect(), t = text(b);
      return (inForm.includes(b) ? 3 : 0) + (b.type === "submit" ? 3 : 0) + (OK.test(t) ? 4 : 0) + (r.top >= lastBottom - 5 ? 1 : -2) - Math.abs(r.top - lastBottom) / 400;
    };
    const best = candidates.sort((a, b) => score(b) - score(a))[0];
    if (best && score(best) > 0) { const r = best.getBoundingClientRect(); submit = { x: r.left + r.width / 2, y: r.top + r.height / 2, text: text(best).slice(0, 40) }; }
  }
  // No fields: the login is often behind a "Sign in" button or link.
  let signIn = null;
  if (!fields.length) {
    const el = [...document.querySelectorAll("a, button, [role=button]")].find((b) => SIGNIN.test((b.innerText || b.getAttribute("aria-label") || "").trim()) && visible(b));
    if (el) { const r = el.getBoundingClientRect(); signIn = { x: r.left + r.width / 2, y: r.top + r.height / 2, text: (el.innerText || "").trim().slice(0, 40) }; }
  }
  return { fields, submit, signIn, url: location.href, sig: `${location.href}|${document.title}|${fields.map((f) => f.kind).join(",")}|${Math.round((document.body ? document.body.innerText.length : 0) / 50)}` };
}

const scanSource = `(${scan.toString()})()`.replace("NOT.test", `${NOT_SUBMIT}.test`).replace("OK.test", `${SUBMIT}.test`).replace("SIGNIN.test", `${SIGNIN}.test`);

async function ready(page) {
  await page.waitForLoadState("load", { timeout: 10000 }).catch(() => {});
  // DOM stable for a moment: frameworks (React, Vue) render after load.
  let last = -1;
  for (let i = 0; i < 12; i++) {
    const n = await page.evaluate(() => (document.body ? document.body.innerHTML.length : 0)).catch(() => -1);
    if (n === last) break;
    last = n;
    await page.waitForTimeout(250);
  }
}

const valueFor = (kind, id, max, f = {}) => {
  if (kind === "seed") { const w = (id.seeds?.[0] || "").split(" "); return f.whole ? w.join(" ") : w[f.n % w.length]; }
  if (kind === "email") return id.emails?.[0];
  if (kind === "password") return id.passwords?.[0];
  if (kind === "phone") return id.phones?.[0] || `2025550${Math.floor(100 + Math.random() * 900)}`;
  if (kind === "name") return id.names?.[0];
  if (kind === "code") return String(Math.floor(Math.random() * 1e8)).padStart(8, "0").slice(0, max >= 4 && max <= 8 ? max : 6);
  return null;
};

async function fill(page, f, value) {
  await moveMouseHumanlike(page, f.x + randomBetween(-60, 60), f.y + randomBetween(-30, 30), f.x, f.y).catch(() => {});
  await page.mouse.click(f.x, f.y);
  await pause(page, randomBetween(120, 300));
  if (f.value) await page.keyboard.press("ControlOrMeta+A");
  await typeChars(page, value);
  await pause(page, randomBetween(150, 400));
}

/**
 * @returns {Promise<Array<{url, filled, submitted, changed}>>}
 */
// solveChallenges: called when a submit changed nothing and a CAPTCHA is on
// the page; returns the challenge log (lib/challenges.js).
async function credentialFlow(page, { identity = {}, maxSteps = 4, submit = true, deadline = Date.now() + 45000, skipDomains = [], solveChallenges = null } = {}) {
  const steps = [];
  let kitSite = site(page.url());
  if (isRealService(page.url(), skipDomains)) return [{ url: page.url(), note: "a legitimate service's site: not filled" }];
  for (let n = 0; n < maxSteps && Date.now() < deadline; n++) {
    await ready(page);
    // Kits send the victim on to the real service after taking the
    // credentials: never type into it. Another unknown site is the kit's
    // next stage (often on cloud storage): carry on there.
    if (n && site(page.url()) !== kitSite) {
      if (isRealService(page.url(), skipDomains)) { steps.push({ url: page.url(), note: "reached a legitimate service: stopped" }); break; }
      steps.push({ url: page.url(), note: "the kit's next stage, on another site" });
      kitSite = site(page.url());
    }
    let s = await page.evaluate(scanSource).catch(() => null);
    // After a submit, kits show a spinner before the next field: wait for
    // the form to hold still.
    for (let still = 0, end = Math.min(deadline, Date.now() + 8000); n && still < 3 && Date.now() < end;) {
      await page.waitForTimeout(500);
      const next = await page.evaluate(scanSource).catch(() => null);
      still = next && s && next.sig === s.sig && next.fields.length === s.fields.length ? still + 1 : 0;
      s = next;
    }
    if (s && !s.fields.length && s.signIn && !n) {
      await moveMouseHumanlike(page, s.signIn.x + randomBetween(-80, 80), s.signIn.y + randomBetween(-40, 40), s.signIn.x, s.signIn.y).catch(() => {});
      await page.mouse.click(s.signIn.x, s.signIn.y).catch(() => {});
      steps.push({ url: s.url, clicked: s.signIn.text || "sign in" });
      await page.waitForTimeout(1500);
      await ready(page);
      if (site(page.url()) !== kitSite && isRealService(page.url(), skipDomains)) { steps.push({ url: page.url(), note: "reached a legitimate service: stopped" }); break; }
      s = await page.evaluate(scanSource).catch(() => null);
    }
    // A next stage often draws its form a few seconds after loading.
    for (const end = Math.min(deadline, Date.now() + 10000); n && (!s || !s.fields.length) && Date.now() < end;) {
      await page.waitForTimeout(500);
      s = await page.evaluate(scanSource).catch(() => null);
    }
    if (!s || !s.fields.length) { if (!n) steps.push({ url: page.url(), note: "no credential fields" }); break; }
    const step = { url: s.url, filled: [], submitted: null, changed: false };
    // Empty fields only: a value the kit filled in (often the victim's
    // address from the link) stays, as a victim would leave it.
    for (const f of s.fields) {
      const v = valueFor(f.kind, identity, f.maxLength, f);
      // Our generic filler's text is replaced; a kit's prefilled value stays.
      if (!v || (f.value && !typedFiller(f.value))) continue;
      await fill(page, f, v);
      step.filled.push(f.kind);
    }
    // Frameworks that hydrate late wipe what was typed: check and type again.
    await pause(page, 600);
    const again = await page.evaluate(scanSource).catch(() => null);
    for (const f of again?.fields || []) {
      const v = valueFor(f.kind, identity, f.maxLength, f);
      if (v && !f.value && step.filled.includes(f.kind)) { await fill(page, f, v); step.retyped = (step.retyped || 0) + 1; }
    }
    // Nothing new to give on the same page: the flow ended. A new page with
    // the victim's details already in (the kit carried them over) is
    // submitted as it is, as a victim would.
    if (!step.filled.length && n && (s.url === steps.filter((x) => x.filled).pop()?.url || !(again || s).submit)) break;
    if (step.filled.length) await timeline.snap(page, `filled: ${[...new Set(step.filled)].join(", ")}`);
    if (!submit) { steps.push(step); break; }
    const before = again?.sig || s.sig;
    const send = async (target) => {
      if (target) {
        await moveMouseHumanlike(page, target.x + randomBetween(-80, 80), target.y + randomBetween(-40, 40), target.x, target.y).catch(() => {});
        await page.mouse.click(target.x, target.y);
        step.submitted = target.text || "button";
      } else {
        await page.keyboard.press("Enter");
        step.submitted = "Enter";
      }
      // Wait for the next step: a navigation or a changed form.
      for (const end = Math.min(deadline, Date.now() + 10000); Date.now() < end; await page.waitForTimeout(400)) {
        const now = await page.evaluate(scanSource).catch(() => null); // null while navigating
        if (now && now.sig !== before) { step.changed = true; await page.waitForTimeout(500); await timeline.snap(page, `after submitting (${step.submitted})`); return; }
      }
    };
    await send((again || s).submit);
    // A CAPTCHA that appears once the form is filled keeps the submit
    // button disabled until it passes: solve it, then submit again.
    if (!step.changed && solveChallenges && Date.now() < deadline && page.frames().some((f) => CAPTCHA_FRAME.test(f.url()))) {
      const t = Date.now();
      step.challenges = await solveChallenges().catch((e) => [{ kind: "error", note: e.message }]);
      deadline += Date.now() - t; // the CAPTCHA has its own budget
      if (step.challenges.some((c) => c.solved)) {
        const now = await page.evaluate(scanSource).catch(() => null);
        if (now && now.sig !== before) step.changed = true; // the CAPTCHA submitted the form itself
        else if (now) await send(now.submit);
      }
    }
    steps.push(step);
    if (!step.changed) break;
  }
  return steps;
}

// Whether the page shows credential fields now (no gate in front of them).
const hasFields = (page) => page.evaluate(scanSource).then((s) => !!(s && s.fields.length)).catch(() => false);

module.exports = { credentialFlow, hasFields };
