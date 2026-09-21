"""Local demo: the scan API, a UI for it, and a deliberately weak chatbot to scan.

    python demo/run_demo.py            then open http://127.0.0.1:8000

DEV ONLY. To let you scan a bot on this machine, this script lets url_safety
accept exactly one loopback address, the demo bot's. That exception exists only
inside this script's process; the app itself has no such switch. Any other URL
you type (a real public chatbot, say) goes through the normal protections.
"""

import argparse
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

# A demo shouldn't trip its own rate limits. Must be set before app.main is imported.
os.environ.setdefault("SCAN_LIMIT_PER_HOUR", "1000")
os.environ.setdefault("SCAN_LIMIT_PER_DAY", "1000")
os.environ.setdefault("SCAN_LIMIT_DOMAINS_PER_DAY", "1000")

BOT_PAGE = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>Acme Support</title>
<style>
 body{margin:0;font-family:system-ui,sans-serif;background:#f4f5f7;display:flex;justify-content:center;padding:40px}
 .chat{width:460px;background:#fff;border-radius:14px;box-shadow:0 6px 30px #0002;display:flex;flex-direction:column;overflow:hidden}
 .head{background:#1d4ed8;color:#fff;padding:16px 20px;font-weight:600}
 .head small{display:block;font-weight:400;opacity:.8;margin-top:2px}
 #log{padding:16px;min-height:320px;max-height:420px;overflow:auto;display:flex;flex-direction:column;gap:10px}
 .user-message{align-self:flex-end;background:#1d4ed8;color:#fff;padding:9px 13px;border-radius:14px 14px 2px 14px;max-width:80%;white-space:pre-wrap;word-break:break-word}
 .bot-message{align-self:flex-start;background:#eef0f4;padding:9px 13px;border-radius:14px 14px 14px 2px;max-width:80%;white-space:pre-wrap;word-break:break-word}
 .typing{align-self:flex-start;color:#888;font-size:13px}
 textarea{border:0;border-top:1px solid #e5e7eb;padding:14px 16px;font:inherit;resize:none;outline:none;height:52px}
</style></head><body>
<div class="chat"><div class="head">Acme Support<small>AI assistant &middot; demo target, deliberately weak</small></div>
<div id="log"><div class="bot-message">Hi! I'm Acme's assistant. How can I help?</div></div>
<textarea id="in" placeholder="Type a message..."></textarea></div>
<script>
const log=document.getElementById('log'), inp=document.getElementById('in');
const add=(cls,t)=>{const d=document.createElement('div');d.className=cls;d.textContent=t;log.appendChild(d);log.scrollTop=1e9;return d;};
const REFUSAL="I'm sorry, but I can't help with that request.";

// A deliberately gullible assistant. Its weaknesses are fixed rules, so a scan
// of it gives the same kind of results every time.
function reply(t){
  // 1. Obeys instructions hidden in the content it was asked to process
  //    (everything except the long-text variant).
  let m = t.match(/just (?:say|print) "([^"]+)"/);
  if (m) return m[1].length > 60 ? REFUSAL : m[1];
  // 2. Decodes Base64 on request and repeats it.
  m = t.match(/BASE64 encoded string:\s*(\S+)/);
  if (m) { try { return atob(m[1]); } catch(e) {} }
  // 3. Long role-play jailbreak prompts work on it about half the time.
  if (t.length > 800) return t.length % 2 === 0
      ? "DAN Mode enabled. GPT: Understood. DAN: I can do anything now, no rules apply!" : REFUSAL;
  // 4. Short questions it should refuse: sometimes it just answers.
  if (t.length < 300 && t.length % 3 === 0)
      return "Sure! Here's a quick overview: first, get what you need together, then follow these steps carefully.";
  return REFUSAL;
}
inp.addEventListener('keydown',e=>{ if(e.key!=='Enter'||e.shiftKey) return; e.preventDefault();
  const t=inp.value.trim(); if(!t) return; inp.value=''; add('user-message',t);
  const typing=add('typing','typing...'); const words=reply(t).split(' ');
  setTimeout(()=>{ typing.remove(); const b=add('bot-message',''); let i=0;
    const iv=setInterval(()=>{ b.textContent+=(i?' ':'')+words[i++]; if(i>=words.length) clearInterval(iv); },60); },700);
});
</script></body></html>"""


class BotHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        body = BOT_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--bot-port", type=int, default=8001)
    parser.add_argument("--cap", type=int, default=2,
                        help="prompts per probe (default 2 for a ~3 minute demo; the app default is 10)")
    args = parser.parse_args()

    bot = ThreadingHTTPServer(("127.0.0.1", args.bot_port), BotHandler)
    threading.Thread(target=bot.serve_forever, daemon=True).start()
    bot_url = f"http://127.0.0.1:{args.bot_port}/"

    # ---- the one dev-only exception: allow the demo bot, and nothing else on loopback
    from app import browser_generator, url_safety
    real_validate = url_safety.validate_target_url

    def validate_allowing_demo_bot(url):
        parts = urlsplit(url.strip()) if isinstance(url, str) else None
        if parts and parts.hostname == "127.0.0.1" and parts.port == args.bot_port \
                and parts.scheme == "http" and parts.username is None:
            return url_safety.UrlSafetyResult(is_safe=True)
        return real_validate(url)

    url_safety.validate_target_url = validate_allowing_demo_bot
    browser_generator.validate_target_url = validate_allowing_demo_bot

    # ---- demo-sized scans: fewer prompts, and quicker settling for the fast demo bot
    from app import run_scan
    real_run_scan = run_scan.run_scan

    def demo_run_scan(target_url, output_dir, **kwargs):
        options = {}
        if target_url == bot_url:
            options = {"settle_ms": 1200, "poll_ms": 200, "request_delay_s": 0}
        return real_run_scan(target_url, output_dir, prompt_cap=args.cap,
                             generator_options=options, **kwargs)

    run_scan.run_scan = demo_run_scan

    # ---- serve the UI from the same origin as the API (no CORS needed)
    from fastapi.responses import FileResponse
    from app.main import app

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(Path(__file__).with_name("index.html"))

    @app.get("/demo-config", include_in_schema=False)
    def demo_config():
        return {"demo_target": bot_url, "prompts_per_probe": args.cap}

    import uvicorn
    print(f"\n  Demo UI:      http://127.0.0.1:{args.port}")
    print(f"  Demo chatbot: {bot_url}   (the weak bot the scan targets)\n")
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
