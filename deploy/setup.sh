#!/bin/bash
# One-time host setup for UrlSandboxEx (the urlsandboxex command).
# Idempotent. Run with sudo, then add analysts to the `sbx` group:
#   sudo deploy/setup.sh && sudo usermod -aG sbx <user>   (re-login after)
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)

echo "== Google Chrome stable (auto-updated by apt; the sandbox's main engine)"
if [[ ! -f /etc/apt/sources.list.d/google-chrome.list ]]; then
  curl -fsSL https://dl.google.com/linux/linux_signing_key.pub | gpg --dearmor --yes -o /usr/share/keyrings/google-chrome.gpg
  echo "deb [arch=amd64 signed-by=/usr/share/keyrings/google-chrome.gpg] https://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list
  apt-get update -qq
fi
install -m 0644 "$HERE/50sbx-google-chrome" /etc/apt/apt.conf.d/50sbx-google-chrome

echo "== packages"
# bubblewrap: jail; xvfb+openbox: real display + window manager;
# pulseaudio, espeak-ng, speech-dispatcher: real audio devices and voices;
# xclip: clipboard capture without page hooks; xdotool+imagemagick: click
# "Allow" on permission prompts; iproute2: jail LAN interface; ffmpeg,
# git, cmake, g++: CAPTCHA audio transcription (whisper.cpp, below).
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
  google-chrome-stable bubblewrap xvfb openbox pulseaudio pulseaudio-utils \
  espeak-ng speech-dispatcher speech-dispatcher-espeak-ng xclip xdotool \
  imagemagick x11-utils iproute2 zip yara unattended-upgrades \
  fonts-noto-core fonts-noto-color-emoji fonts-liberation \
  ffmpeg git cmake g++ make

echo "== CAPTCHA audio: whisper.cpp (pinned release) and its multilingual base model"
WHISPER_TAG=v1.9.4
WHISPER_MODEL_SHA256=60ed5bc3dd14eea856493d334349b405782ddcaf0028d4b5df4088345fba2efe
W=/usr/local/lib/sbx/whisper
install -d -m 0755 "$W"
if [[ ! -x "$W/whisper-cli" || "$(cat "$W/VERSION" 2>/dev/null)" != "$WHISPER_TAG" ]]; then
  B=$(mktemp -d)
  git clone -q --depth 1 --branch "$WHISPER_TAG" https://github.com/ggml-org/whisper.cpp "$B/src"
  cmake -S "$B/src" -B "$B/build" -DBUILD_SHARED_LIBS=OFF -DWHISPER_BUILD_TESTS=OFF -DWHISPER_BUILD_SERVER=OFF -DCMAKE_BUILD_TYPE=Release >/dev/null
  cmake --build "$B/build" -j "$(nproc)" --target whisper-cli >/dev/null
  install -m 0755 "$B/build/bin/whisper-cli" "$W/whisper-cli"
  echo "$WHISPER_TAG" > "$W/VERSION"
  rm -rf "$B"
fi
if ! echo "$WHISPER_MODEL_SHA256  $W/ggml-base.bin" | sha256sum -c --status 2>/dev/null; then
  curl -fsSL -o "$W/ggml-base.bin.tmp" https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-base.bin
  echo "$WHISPER_MODEL_SHA256  $W/ggml-base.bin.tmp" | sha256sum -c --status || { echo "whisper model checksum mismatch" >&2; exit 1; }
  mv "$W/ggml-base.bin.tmp" "$W/ggml-base.bin"; chmod 0644 "$W/ggml-base.bin"
fi

echo "== CAPTCHA images: YOLOX-s and CLIP ViT-B/32 (quantized), pinned by checksum"
V=/usr/local/lib/sbx/vision
HF=https://huggingface.co/Xenova/clip-vit-base-patch32/resolve/main
install -d -m 0755 "$V"
fetch() { # url, destination, sha256
  if ! echo "$3  $2" | sha256sum -c --status 2>/dev/null; then
    curl -fsSL -o "$2.tmp" "$1"
    echo "$3  $2.tmp" | sha256sum -c --status || { echo "$(basename "$2"): checksum mismatch" >&2; exit 1; }
    mv "$2.tmp" "$2"; chmod 0644 "$2"
  fi
}
fetch https://github.com/Megvii-BaseDetection/YOLOX/releases/download/0.1.1rc0/yolox_s.onnx "$V/yolox_s.onnx" c5c2d13e59ae883e6af3b45daea64af4833a4951c92d116ec270d9ddbe998063
fetch "$HF/onnx/vision_model_quantized.onnx" "$V/clip_vision_q.onnx" 583fd1110a514667812fee7d684952aaf82a99b959760c8d7dca7e0ab9839299
if [[ ! -f "$V/prompts.json" ]]; then
  # Text embeddings for the puzzle objects, computed once; the text model is not kept.
  T=$(mktemp -d)
  fetch "$HF/onnx/text_model_quantized.onnx" "$T/clip_text_q.onnx" 73baab855d406190da9faa498cfedf65f15cf309f4cc7385b7b032e6d08e5c3a
  fetch "$HF/tokenizer.json" "$T/tokenizer.json" f7f3b7af117d467b58374797691a6438d3e6b9e9cef800dfd5dced7f697a90cd
  node "$HERE/../tools/build-vision.js" "$T"
  install -m 0644 "$T/prompts.json" "$V/prompts.json"
  rm -rf "$T"
fi

echo "== jail: bwrap that only the sbx group may run, with user namespaces"
getent group sbx >/dev/null || groupadd --system sbx
install -d -m 0755 /usr/local/lib/sbx
install -o root -g sbx -m 0750 /usr/bin/bwrap /usr/local/lib/sbx/bwrap
install -m 0644 "$HERE/apparmor-sbx-bwrap" /etc/apparmor.d/sbx-bwrap
apparmor_parser -r /etc/apparmor.d/sbx-bwrap

echo "== Chrome policy (no 'unsupported command-line flag' infobar)"
install -d -m 0755 /etc/opt/chrome/policies/managed
install -m 0644 "$HERE/chrome-policy-sbx.json" /etc/opt/chrome/policies/managed/sbx.json

echo "== done. Members of group sbx can run: urlsandboxex <url>"
