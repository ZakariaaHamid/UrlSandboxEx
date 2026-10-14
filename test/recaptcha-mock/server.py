# Serves the mock on 127.0.0.1:3014 (page) and localhost:3014 (frames: a
# different site, so they run out of process like the real widget).
import http.server, os, subprocess, tempfile
here = os.path.dirname(os.path.abspath(__file__))
clip = os.path.join(tempfile.gettempdir(), "mock-recaptcha.mp3")
if not os.path.exists(clip):
    wav = clip + ".wav"
    subprocess.run(["espeak-ng", "-v", "en", "-s", "140", "-w", wav, "four seven one nine"], check=True)
    subprocess.run(["ffmpeg", "-loglevel", "error", "-y", "-i", wav, "-b:a", "64k", clip], check=True)
class H(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **k): super().__init__(*a, directory=here, **k)
    def do_GET(self):
        if self.path.startswith("/recaptcha/api2/payload"):
            body = open(clip, "rb").read()
            self.send_response(200); self.send_header("Content-Type", "audio/mp3"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body); return
        if self.path.startswith("/recaptcha/api2/"):
            body = open(os.path.join(here, self.path.split("?")[0].lstrip("/")), "rb").read()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8"); self.end_headers(); self.wfile.write(body); return
        super().do_GET()
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(("127.0.0.1", 3014), H).serve_forever()
