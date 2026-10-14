// Real services: the sandbox never types into or submits their pages,
// even when a kit sends the browser there (lib/credflow.js, lib/humanize.js).

const LEGIT = ["google.com", "microsoftonline.com", "microsoft.com", "live.com", "office.com", "outlook.com", "apple.com", "icloud.com", "amazon.com",
  "paypal.com", "facebook.com", "instagram.com", "linkedin.com", "twitter.com", "x.com", "discord.com", "github.com", "dropbox.com", "adobe.com",
  "docusign.com", "docusign.net", "yahoo.com", "aol.com", "netflix.com", "spotify.com", "roblox.com", "steamcommunity.com", "steampowered.com",
  "binance.com", "coinbase.com", "xfinity.com", "comcast.net", "att.com", "verizon.com", "wellsfargo.com", "chase.com", "bankofamerica.com",
  "dhl.com", "fedex.com", "ups.com", "usps.com", "blogger.com", "okta.com", "salesforce.com", "zoom.us", "slack.com", "atlassian.com", "booking.com", "sharepoint.com", "onedrive.live.com"];

// Registrable domain, roughly: enough to tell "same site" apart.
const site = (u) => { try { const p = new URL(u).hostname.split("."); return p.slice(/^(co|com|org|net|gov|ac|edu)$/.test(p[p.length - 2]) && p.length > 2 ? -3 : -2).join("."); } catch (e) { return ""; } };

const extra = new Set();
const setSkipDomains = (list = []) => { extra.clear(); for (const d of list) extra.add(String(d).toLowerCase()); };
const isRealService = (url, more = []) => { const s = site(url); return LEGIT.includes(s) || extra.has(s) || more.includes(s); };

module.exports = { site, isRealService, setSkipDomains };
