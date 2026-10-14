// Run once by deploy/setup.sh: CLIP text embeddings for the objects
// reCAPTCHA image puzzles ask for, so scans only need CLIP's image half.
//   node tools/build-vision.js <dir with clip_text_q.onnx and tokenizer.json>
// Writes <dir>/prompts.json.

const fs = require("fs");
const path = require("path");
const ort = require("onnxruntime-node");
const { CLASSES, NEGATIVES } = require("../lib/vision");

const dir = process.argv[2];
const tok = JSON.parse(fs.readFileSync(path.join(dir, "tokenizer.json"), "utf8"));
const vocab = tok.model.vocab;
const ranks = new Map(tok.model.merges.map((m, i) => [Array.isArray(m) ? m.join(" ") : m, i]));
const suffix = tok.model.end_of_word_suffix || "</w>";

// CLIP's BPE for plain lowercase ASCII words (all the prompts are).
function bpe(word) {
  let parts = [...word.slice(0, -1), word.slice(-1) + suffix];
  for (;;) {
    let best = null;
    for (let i = 0; i < parts.length - 1; i++) {
      const r = ranks.get(`${parts[i]} ${parts[i + 1]}`);
      if (r !== undefined && (best === null || r < best.r)) best = { r, i };
    }
    if (!best) return parts;
    parts = [...parts.slice(0, best.i), parts[best.i] + parts[best.i + 1], ...parts.slice(best.i + 2)];
  }
}
const encode = (text) => [49406, ...text.toLowerCase().match(/[a-z]+|[0-9]|[^\s a-z0-9]+/g).flatMap((w) => bpe(w).map((t) => {
  if (vocab[t] === undefined) throw new Error(`no token for ${t}`);
  return vocab[t];
})), 49407];

const TEMPLATES = ["a photo of {}.", "a street view photo of {}.", "a blurry photo of {}.", "a close-up photo of {}."];

(async () => {
  const s = await ort.InferenceSession.create(path.join(dir, "clip_text_q.onnx"));
  const embed = async (text) => {
    const ids = encode(text);
    const out = await s.run({ input_ids: new ort.Tensor("int64", BigInt64Array.from(ids.map(BigInt)), [1, ids.length]) });
    return Array.from(out.text_embeds.data);
  };
  const mean = async (phrase) => {
    const vs = [];
    for (const t of TEMPLATES) vs.push(await embed(t.replace("{}", phrase)));
    const m = vs[0].map((_, i) => vs.reduce((a, v) => a + v[i], 0) / vs.length);
    const n = Math.hypot(...m);
    return m.map((x) => +(x / n).toFixed(6));
  };
  const out = { classes: {}, negatives: {} };
  for (const [name, c] of Object.entries(CLASSES)) out.classes[name] = await mean(c.prompt);
  for (const n of NEGATIVES) out.negatives[n] = await mean(n);
  fs.writeFileSync(path.join(dir, "prompts.json"), JSON.stringify(out));
  console.log(`prompts.json: ${Object.keys(out.classes).length} classes, ${NEGATIVES.length} negatives`);
})();
