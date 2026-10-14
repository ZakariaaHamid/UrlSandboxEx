// npm postinstall: keep only this platform's onnxruntime binary (the
// package ships every platform, about 290 MB).
const fs = require("fs"), path = require("path");
const bin = path.join(__dirname, "..", "node_modules", "onnxruntime-node", "bin");
if (fs.existsSync(bin)) for (const napi of fs.readdirSync(bin)) for (const plat of fs.readdirSync(path.join(bin, napi))) {
  const dir = path.join(bin, napi, plat);
  if (plat !== process.platform) { fs.rmSync(dir, { recursive: true, force: true }); continue; }
  for (const arch of fs.readdirSync(dir)) if (arch !== process.arch) fs.rmSync(path.join(dir, arch), { recursive: true, force: true });
}
