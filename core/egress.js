// Residential/mobile egress (any provider, via a URL template) and exit-IP
// geolocation. IP-reputation cloaking (decoy redirects served before any
// HTML/JS) can't be beaten by the browser, only by a residential IP.
// Each visit uses its own sticky session, so the IP geolocated here is the
// one the browser gets, and its language/timezone can match it.

const crypto = require("crypto");
const { ProxyAgent, fetch } = require("undici");

// Typical browser locale per country, to keep Accept-Language/Intl
// consistent with the egress IP. Unknown countries fall back to en-US.
const COUNTRY_LOCALE = {
  us: "en-US", gb: "en-GB", ca: "en-CA", au: "en-AU", nz: "en-NZ", ie: "en-IE", in: "en-IN", sg: "en-SG", za: "en-ZA", ng: "en-NG", ph: "en-PH",
  de: "de-DE", at: "de-AT", ch: "de-CH", fr: "fr-FR", be: "fr-BE", lu: "fr-LU", es: "es-ES", mx: "es-MX", ar: "es-AR", co: "es-CO", cl: "es-CL", pe: "es-PE",
  it: "it-IT", pt: "pt-PT", br: "pt-BR", nl: "nl-NL", se: "sv-SE", no: "nb-NO", dk: "da-DK", fi: "fi-FI", pl: "pl-PL", cz: "cs-CZ", sk: "sk-SK",
  hu: "hu-HU", ro: "ro-RO", bg: "bg-BG", gr: "el-GR", tr: "tr-TR", ru: "ru-RU", ua: "uk-UA", il: "he-IL", sa: "ar-SA", ae: "ar-AE", eg: "ar-EG",
  ma: "fr-MA", dz: "ar-DZ", tn: "ar-TN", jp: "ja-JP", kr: "ko-KR", cn: "zh-CN", tw: "zh-TW", hk: "zh-HK", th: "th-TH", vn: "vi-VN", id: "id-ID",
  my: "ms-MY", pk: "en-PK", bd: "bn-BD",
};

/**
 * Expand the provider template for one sticky session.
 * @returns {{server, username?, password?}} Playwright-style proxy
 */
function proxyFor(template, { country, session = crypto.randomBytes(6).toString("hex") }) {
  const filled = template.replaceAll("{country}", encodeURIComponent(country.toLowerCase())).replaceAll("{session}", encodeURIComponent(session));
  const u = new URL(filled);
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(`egress.residentialProxy must be http:// or https:// (Chromium can't authenticate to SOCKS5), got ${u.protocol}`);
  }
  const out = { server: `${u.protocol}//${u.host}` };
  if (u.username) out.username = decodeURIComponent(u.username);
  if (u.password) out.password = decodeURIComponent(u.password);
  return out;
}

/**
 * Exit IP + geo of a proxy session (or of this host when proxy is null).
 */
async function resolveExit(proxy, geoLookupUrl, timeoutMs = 15000) {
  let dispatcher;
  if (proxy) {
    const u = new URL(proxy.server);
    if (proxy.username) u.username = encodeURIComponent(proxy.username);
    if (proxy.password) u.password = encodeURIComponent(proxy.password);
    dispatcher = new ProxyAgent({ uri: u.toString() });
  }
  try {
    const res = await fetch(geoLookupUrl, { dispatcher, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new Error(`geo lookup HTTP ${res.status}`);
    const j = await res.json();
    if (j.status && j.status !== "success") throw new Error(`geo lookup failed: ${j.message || j.status}`);
    const cc = (j.countryCode || "").toLowerCase();
    return {
      ip: j.query || j.ip || null, countryCode: cc || null, timezoneId: j.timezone || null,
      locale: COUNTRY_LOCALE[cc] || "en-US", org: j.org || j.isp || null, asn: j.as || null,
      hosting: j.hosting === true, mobile: j.mobile === true,
    };
  } finally {
    if (dispatcher) await dispatcher.close().catch(() => {});
  }
}

// What the per-scan country does with this config: "none" (no proxy, scans
// use this host's IP), "fixed" (the template hardcodes a country) or "choose".
const countryMode = (template) => (!template ? "none" : template.includes("{country}") ? "choose" : "fixed");

module.exports = { proxyFor, resolveExit, countryMode };
