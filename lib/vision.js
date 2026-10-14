// Image recognition for reCAPTCHA image puzzles, on this server's CPU:
// YOLOX-s finds objects and their boxes (COCO classes), CLIP ViT-B/32 tells
// whether a tile shows things COCO lacks (crosswalks, stairs, bridges...).
// Models and precomputed text embeddings live in visionDir (deploy/setup.sh).

const fs = require("fs");
const path = require("path");
const { PNG } = require("pngjs");

// What puzzles ask for. `words`: the target as it appears in the
// instructions, in the languages browsers commonly use; checked in order,
// so specific names come before general ones. `coco`: YOLOX class id(s).
const CLASSES = {
  "fire hydrant": { prompt: "a fire hydrant", coco: 10, words: ["fire hydrant", "hydrant", "idrant", "boca de incendio", "bocas de incendio", "bouche d'incendie", "bouches d'incendie", "hidrante", "brandkraan", "brandkranen", "hydrant"] },
  "traffic light": { prompt: "a traffic light", coco: 9, words: ["traffic light", "semafor", "semáforo", "feux de circulation", "feu de circulation", "ampel", "verkeerslicht", "sygnaliz", "trafik ışı"] },
  "parking meter": { prompt: "a parking meter", coco: 12, words: ["parking meter", "parchimetr", "parquímetro", "parcmètre", "parkuhr", "parkeermeter", "parkometr"] },
  crosswalk: { prompt: "a pedestrian crosswalk with zebra stripes", words: ["crosswalk", "strisce pedonali", "attraversament", "paso de peatones", "pasos de peatones", "passage piéton", "passages piétons", "faixa de pedestre", "faixas de pedestres", "zebrastreifen", "fußgängerüberweg", "zebrapad", "oversteekplaats", "przejści", "yaya geçidi"] },
  bus: { prompt: "a bus", coco: 5, words: ["bus", "autobus", "autobús", "ônibus", "onibus", "otobüs"] },
  motorcycle: { prompt: "a motorcycle", coco: 3, words: ["motorcycle", "motorbike", "motocicl", "moto", "motorrad", "motorräder", "motorfiets", "motocykl", "motosiklet"] },
  bicycle: { prompt: "a bicycle", coco: 1, words: ["bicycle", "bike", "bicicl", "vélo", "velo", "fahrrad", "fahrräder", "fiets", "rower", "bisiklet"] },
  tractor: { prompt: "a tractor", words: ["tractor", "trattor", "tracteur", "trator", "traktor", "ciągnik"] },
  taxi: { prompt: "a yellow taxi cab", words: ["taxi", "táxi"] },
  car: { prompt: "a car", coco: [2, 7], words: ["car", "vehicle", "auto", "macchin", "veicol", "coche", "carro", "voiture", "véhicule", "wagen", "fahrzeug", "samoch", "araba", "araç"] },
  boat: { prompt: "a boat", coco: 8, words: ["boat", "barc", "bateau", "boot", "łód", "tekne"] },
  bridge: { prompt: "a bridge", words: ["bridge", "pont", "puente", "ponte", "brücke", "brug", "most", "köprü"] },
  stairs: { prompt: "stairs", words: ["stair", "scal", "escaler", "escalier", "escada", "treppe", "trap", "schod", "merdiven"] },
  chimney: { prompt: "a chimney on a roof", words: ["chimney", "camin", "chimenea", "cheminée", "chaminé", "schornstein", "schoorste", "komin", "baca"] },
  "palm tree": { prompt: "a palm tree", words: ["palm", "palma", "palme", "palmera", "palmier", "palmeira", "palmboom", "palmiye"] },
  mountain: { prompt: "mountains or hills", words: ["mountain", "hill", "montagn", "collin", "montaña", "colina", "montanha", "berg", "hügel", "heuvel", "gór", "dağ", "tepe"] },
};
// What tiles show when they do not show the target.
const NEGATIVES = ["a road", "a building", "trees", "the sky", "a parking lot", "grass", "a sidewalk", "a house", "a street"];

function classFor(instruction) {
  const t = String(instruction || "").toLowerCase();
  for (const [name, c] of Object.entries(CLASSES)) if (c.words.some((w) => t.includes(w))) return name;
  return null;
}

let ort = null, sessions = {}, prompts = null;
const session = async (dir, file) => {
  ort = ort || require("onnxruntime-node");
  return (sessions[file] = sessions[file] || ort.InferenceSession.create(path.join(dir, file), { intraOpNumThreads: 2 }));
};

// RGB(A) PNG -> W x H float planes, bilinear.
function resize(png, w, h) {
  const out = new Float32Array(3 * w * h), sx = png.width / w, sy = png.height / h;
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const fx = Math.min(png.width - 1, (x + 0.5) * sx - 0.5), fy = Math.min(png.height - 1, (y + 0.5) * sy - 0.5);
    const x0 = Math.max(0, Math.floor(fx)), y0 = Math.max(0, Math.floor(fy)), x1 = Math.min(png.width - 1, x0 + 1), y1 = Math.min(png.height - 1, y0 + 1);
    const ax = Math.max(0, fx - x0), ay = Math.max(0, fy - y0);
    for (let c = 0; c < 3; c++) {
      const p = (xx, yy) => png.data[(yy * png.width + xx) * 4 + c];
      out[c * w * h + y * w + x] = (p(x0, y0) * (1 - ax) + p(x1, y0) * ax) * (1 - ay) + (p(x0, y1) * (1 - ax) + p(x1, y1) * ax) * ay;
    }
  }
  return out;
}

// CLIP: probability that the image shows `target`, against the other
// classes and plain scenery.
const MEAN = [0.48145466, 0.4578275, 0.40821073], STD = [0.26862954, 0.26130258, 0.27577711];
async function clipScore(dir, pngBuf, target) {
  prompts = prompts || JSON.parse(fs.readFileSync(path.join(dir, "prompts.json"), "utf8"));
  const s = await session(dir, "clip_vision_q.onnx");
  const px = resize(PNG.sync.read(pngBuf), 224, 224);
  for (let c = 0; c < 3; c++) for (let i = 0; i < 224 * 224; i++) px[c * 224 * 224 + i] = (px[c * 224 * 224 + i] / 255 - MEAN[c]) / STD[c];
  const e = (await s.run({ pixel_values: new ort.Tensor("float32", px, [1, 3, 224, 224]) })).image_embeds.data;
  const n = Math.hypot(...e);
  const sim = (v) => v.reduce((a, x, i) => a + x * e[i], 0) / n;
  const labels = [...Object.keys(prompts.classes).map((k) => [k, prompts.classes[k]]), ...Object.entries(prompts.negatives)];
  const logits = labels.map(([, v]) => 100 * sim(v));
  const m = Math.max(...logits), ex = logits.map((l) => Math.exp(l - m)), sum = ex.reduce((a, b) => a + b, 0);
  const i = labels.findIndex(([k]) => k === target);
  return { p: ex[i] / sum, best: labels[logits.indexOf(m)][0] };
}

// YOLOX-s (official export: raw outputs, BGR 0..255, letterboxed 640x640).
async function detect(dir, pngBuf, { minScore = 0.3 } = {}) {
  const s = await session(dir, "yolox_s.onnx");
  const png = PNG.sync.read(pngBuf);
  const r = Math.min(640 / png.width, 640 / png.height), w = Math.round(png.width * r), h = Math.round(png.height * r);
  const scaled = resize(png, w, h), input = new Float32Array(3 * 640 * 640).fill(114);
  for (let c = 0; c < 3; c++) for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) input[c * 640 * 640 + y * 640 + x] = scaled[(2 - c) * w * h + y * w + x]; // RGB -> BGR
  const out = (await s.run({ images: new ort.Tensor("float32", input, [1, 3, 640, 640]) })).output;
  const [, n, k] = out.dims, d = out.data, boxes = [];
  let i = 0;
  for (const stride of [8, 16, 32]) {
    const g = 640 / stride;
    for (let gy = 0; gy < g; gy++) for (let gx = 0; gx < g; gx++, i++) {
      const o = i * k, obj = d[o + 4];
      if (obj < minScore) continue;
      let cls = 0;
      for (let c = 1; c < k - 5; c++) if (d[o + 5 + c] > d[o + 5 + cls]) cls = c;
      const score = obj * d[o + 5 + cls];
      if (score < minScore) continue;
      const cx = (d[o] + gx) * stride, cy = (d[o + 1] + gy) * stride, bw = Math.exp(d[o + 2]) * stride, bh = Math.exp(d[o + 3]) * stride;
      boxes.push({ cls, score, x1: (cx - bw / 2) / r, y1: (cy - bh / 2) / r, x2: (cx + bw / 2) / r, y2: (cy + bh / 2) / r });
    }
  }
  if (i !== n) throw new Error(`unexpected YOLOX output (${n} rows)`);
  // Non-maximum suppression per class.
  const iou = (a, b) => { const w = Math.max(0, Math.min(a.x2, b.x2) - Math.max(a.x1, b.x1)), h = Math.max(0, Math.min(a.y2, b.y2) - Math.max(a.y1, b.y1)); const inter = w * h; return inter / ((a.x2 - a.x1) * (a.y2 - a.y1) + (b.x2 - b.x1) * (b.y2 - b.y1) - inter); };
  const kept = [];
  for (const b of boxes.sort((a, c) => c.score - a.score)) if (!kept.some((q) => q.cls === b.cls && iou(q, b) > 0.45)) kept.push(b);
  return kept;
}

const ready = (dir) => ["yolox_s.onnx", "clip_vision_q.onnx", "prompts.json"].every((f) => fs.existsSync(path.join(dir, f)));

module.exports = { CLASSES, NEGATIVES, classFor, clipScore, detect, ready };
