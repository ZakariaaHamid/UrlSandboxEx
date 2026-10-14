// Decodes QR codes from screenshots ("quishing": the link is rendered as an
// image so URL/link analysis misses it), and compares the QR destination's
// domain with the page's.

const fs = require("fs");
const { PNG } = require("pngjs");
const jsQR = require("jsqr");
// Registrable domain, roughly (two labels; three under common second-level ccTLDs).
function eTldPlusOneGuess(h) {
  const p = String(h || "").split(".");
  return p.slice(/^(co|com|org|net|gov|ac|edu)$/.test(p[p.length - 2]) && p.length > 2 ? -3 : -2).join(".");
}

// Downsample by 2 (nearest pixel): 4x fewer pixels to scan.
function half(img) {
  const w = img.width >> 1, h = img.height >> 1, out = new Uint8ClampedArray(w * h * 4);
  const src = new Uint32Array(img.data.buffer, img.data.byteOffset, img.data.length >> 2), dst = new Uint32Array(out.buffer);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) dst[y * w + x] = src[2 * y * img.width + 2 * x];
  return { data: out, width: w, height: h };
}

/**
 * @param {string} pngPath
 * @param {{halfRes?: boolean}} [opts] - halfRes: scan at half resolution, normal
 *   polarity only (~6x faster; for tall full-page screenshots).
 * @returns {string|null} the raw decoded QR payload (typically a URL), or null if no QR code
 *   was found, or decoding failed. Never throws.
 */
function decodeQrFromFile(pngPath, opts = {}) {
  try {
    const png = PNG.sync.read(fs.readFileSync(pngPath));
    let img = { data: new Uint8ClampedArray(png.data.buffer, png.data.byteOffset, png.data.length), width: png.width, height: png.height };
    if (opts.halfRes) img = half(img);
    const result = jsQR(img.data, img.width, img.height, { inversionAttempts: opts.halfRes ? "dontInvert" : "attemptBoth" });
    return result ? result.data : null;
  } catch (e) {
    return null;
  }
}

/**
 * @param {string|null} qrPayload - decodeQrFromFile()'s output
 * @param {string} pageUrl - the scanned page's own finalUrl
 * @returns {{isUrl: boolean, mismatched: boolean, qrHost: string|null, payload: string|null}}
 */
function analyzeQrPayload(qrPayload, pageUrl) {
  if (!qrPayload) return { isUrl: false, mismatched: false, qrHost: null, payload: null };
  let qrHost;
  try { qrHost = new URL(qrPayload).hostname; } catch (e) { return { isUrl: false, mismatched: false, qrHost: null, payload: qrPayload }; }
  let pageHost = null;
  try { pageHost = new URL(pageUrl).hostname; } catch (e) { /* leave null */ }
  const mismatched = !!(pageHost && eTldPlusOneGuess(qrHost) !== eTldPlusOneGuess(pageHost));
  return { isUrl: true, mismatched, qrHost, payload: qrPayload };
}

module.exports = { decodeQrFromFile, analyzeQrPayload };
