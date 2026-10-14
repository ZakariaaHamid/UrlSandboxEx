// Exfiltration endpoints found in page code: where a kit sends what it
// harvests. A hardcoded bot token or webhook ties otherwise unrelated kits
// to one operator.

const EXFIL_ENDPOINT_PATTERNS = [
  { name: "telegram-bot-api", re: /https?:\/\/api\.telegram\.org\/bot[A-Za-z0-9_:-]+\/\w+/g },
  { name: "discord-webhook", re: /https?:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g },
  { name: "webhook-site", re: /https?:\/\/webhook\.site\/[a-f0-9-]{20,}/g },
  { name: "formsubmit", re: /https?:\/\/formsubmit\.co\/[^\s"'`)]+/g },
  { name: "google-apps-script", re: /https?:\/\/script\.google(?:usercontent)?\.com\/macros\/s\/[\w-]+\/exec/g },
  // Serverless drops: the kit's frontend sends fields straight to a
  // third-party service, no backend of its own.
  { name: "emailjs", re: /https?:\/\/api\.emailjs\.com\/api\/v[\d.]{1,5}\/email\/send(?:-form)?/g },
  { name: "google-forms", re: /https?:\/\/docs\.google\.com\/forms\/d\/e\/[\w-]{10,80}\/formResponse/g },
  { name: "firebase-rtdb", re: /https?:\/\/[a-z0-9-]{1,60}\.firebaseio\.com\/[^\s"'`)<>!;,[\]{}]{0,200}\.json/gi },
  { name: "firestore-rest", re: /https?:\/\/firestore\.googleapis\.com\/v1\/projects\/[\w-]{1,60}\/databases\/\(default\)\/documents\/[^\s"'`)<>!;,[\]{}]{0,200}/g },
  { name: "supabase-rest", re: /https?:\/\/[a-z0-9]{10,40}\.supabase\.co\/rest\/v1\/[^\s"'`)<>!;,[\]{}]{0,200}/gi },
  { name: "make-integromat-webhook", re: /https?:\/\/hook(?:-\d+)?\.(?:integromat\.com|(?:eu|us)\d{0,2}\.make\.com)\/[\w-]{5,80}/g },
  { name: "zapier-webhook", re: /https?:\/\/hooks\.zapier\.com\/hooks\/catch\/\d+\/[\w-]{3,60}/g },
  { name: "slack-webhook", re: /https?:\/\/hooks\.slack\.com\/services\/T[\w]{5,20}\/B[\w]{5,20}\/[\w]{10,40}/g },
  { name: "pipedream-webhook", re: /https?:\/\/[a-z0-9]{10,40}\.m\.pipedream\.net/gi },
  { name: "ntfy-topic", re: /https?:\/\/ntfy\.sh\/[\w-]{3,80}/g },
  // Visitor-tracking links: not exfil, but campaign-specific.
  { name: "ip-logger", re: /https?:\/\/(?:www\.)?(?:iplogger\.org|grabify\.link|2no\.co|blasze\.com)\/[\w-]{2,50}/gi },
];

// Hosts excluded from the generic URL sweep: common CDNs/libraries,
// Cloudflare's own challenge infrastructure, and the SVG namespace URI.
const COMMON_NOISE_HOSTS = new Set([
  "fonts.googleapis.com", "fonts.gstatic.com", "cdnjs.cloudflare.com",
  "code.jquery.com", "ajax.googleapis.com", "www.googletagmanager.com",
  "www.google-analytics.com", "challenges.cloudflare.com", "www.gstatic.com",
  "www.cloudflare.com", "challenges.fed.cloudflare.com",
  "challenges.cloudflare-cn.com", "challenges-staging.cloudflare.com",
  "www.w3.org",
]);

/**
 * @returns {{named: Array<{type, value}>, genericUrls: string[]}}
 *   named: matches of the patterns above; genericUrls: other absolute URLs
 *   (excluding the page's own host and noise hosts), at most 25.
 */
function extractExfilEndpoints(jsContent, pageHost) {
  const named = [];
  for (const { name, re } of EXFIL_ENDPOINT_PATTERNS) {
    for (const m of jsContent.matchAll(re)) named.push({ type: name, value: m[0] });
  }
  const genericUrls = new Set();
  // Path length is bounded: minified code can run for kilobytes without
  // any of the excluded separator characters.
  for (const m of jsContent.matchAll(/https?:\/\/[a-zA-Z0-9.-]+(?:\/[^\s"'`)<>!;,[\]{}]{0,500})?/g)) {
    try {
      const h = new URL(m[0]).hostname;
      if (h !== pageHost && !COMMON_NOISE_HOSTS.has(h)) genericUrls.add(m[0]);
    } catch (e) { /* not a URL */ }
  }
  return { named, genericUrls: [...genericUrls].slice(0, 25) };
}

module.exports = { EXFIL_ENDPOINT_PATTERNS, extractExfilEndpoints };
