"""Offline tests for the phone-app relay (Desk side): encryption, phone rules, pairing, request handling.

Run: python test_relay_offline.py
"""
import base64
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from relay import client, envelope, pairing, policy  # noqa: E402

ok = fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1
    else:
        fail += 1
        print("FAIL:", name)


def raises(fn):
    try:
        fn()
        return False
    except envelope.EnvelopeError:
        return True


KEY = os.urandom(32)
CH = "ab" * 16

# ---------- envelope ----------
rid, blob = envelope.make_request(KEY, CH, "GET", "/case")
req = envelope.unseal(KEY, CH, "req", blob)
check("request round trip", req["m"] == "GET" and req["p"] == "/case" and req["id"] == rid)
check("wrong key fails", raises(lambda: envelope.unseal(os.urandom(32), CH, "req", blob)))
check("other channel fails", raises(lambda: envelope.unseal(KEY, "cd" * 16, "req", blob)))
check("turned around (req as res) fails", raises(lambda: envelope.unseal(KEY, CH, "res", blob)))
bad = bytearray(blob)
bad[20] ^= 1
check("one flipped bit fails", raises(lambda: envelope.unseal(KEY, CH, "req", bytes(bad))))
check("garbage fails", raises(lambda: envelope.unseal(KEY, CH, "req", b"\x02abc")))
res = envelope.seal(KEY, CH, "res", {"id": rid, "s": 200}, rid=rid)
check("response bound to its request", envelope.unseal(KEY, CH, "res", res, rid=rid)["s"] == 200 and
      raises(lambda: envelope.unseal(KEY, CH, "res", res, rid="x" * 24)))
big = b"<p>hello</p>" * 5000
b, z = envelope.pack_body(big)
check("bodies compressed and restored", z == 1 and envelope.unpack_body(b, z) == big and len(b) < len(big) / 5)
bomb = base64.b64encode(__import__("zlib").compress(b"\0" * (envelope.MAX_BODY + 10))).decode()
check("decompression bomb refused", raises(lambda: envelope.unpack_body(bomb, 1)))
g = envelope.ReplayGuard()
g.check("a" * 24, time.time())
check("replay refused", raises(lambda: g.check("a" * 24, time.time())))
check("old request refused", raises(lambda: g.check("b" * 24, time.time() - 600)))
check("future request refused", raises(lambda: g.check("c" * 24, time.time() + 600)))
check("bad id refused", raises(lambda: g.check("short", time.time())))

# ---------- phone rules ----------
allowed = [("GET", "/"), ("GET", "/case"), ("GET", "/threatmap.json?hours=24"), ("POST", "/msgcheck", b"text=hello"),
           ("POST", "/lookup", b"do=maigret&target=amy"), ("POST", "/prescreen", b"address=rXYZ")]
for m, p, *bd in allowed:
    check(f"allowed: {m} {p}", policy.check(m, p, bd[0] if bd else b"") is None)
refused = [("GET", "/relay"), ("GET", "/relay?x=1"), ("POST", "/relay", b"do=pair"), ("GET", "/setup"), ("POST", "/update", b"do=apply"),
           ("GET", "/share"), ("POST", "/share", b""), ("GET", "/secretscan"), ("GET", "/alerts"), ("GET", "/extension"),
           ("GET", "/agentguard"), ("DELETE", "/case"), ("POST", "/numbercheck", b"do=key&key=abc"), ("POST", "/malware", b"do=key&key=x"),
           ("POST", "/msgcheck", b"text=x&api_token=y"), ("POST", "/evidence", b"do=seal"), ("GET", "http://evil/"), ("GET", "//evil/x"),
           ("GET", "/x\r\nHost: evil"), ("GET", "/kit/../setup"), ("POST", "/lookup", b"x", "multipart/form-data; boundary=a")]
for m, p, *rest in refused:
    check(f"refused: {m} {p[:30]}", policy.check(m, p, rest[0] if rest else b"", rest[1] if len(rest) > 1 else "") is not None)

# ---------- a stand-in Desk on 127.0.0.1 ----------
seen = []


class Desk(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        seen.append(("GET", self.path, self.headers.get("X-ScamHunter-Via")))
        if self.path == "/go":
            self.send_response(303)
            self.send_header("Location", "/case")
            self.end_headers()
            return
        body = base64.b64encode(os.urandom(900 * 1024)) if self.path == "/huge" else b"<html>DESK " + self.path.encode() + b"</html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(n)
        seen.append(("POST", self.path, data))
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"POSTED " + data)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Desk)
threading.Thread(target=srv.serve_forever, daemon=True).start()
PORT = srv.server_address[1]


def ask(method, path, body=b""):
    rid, blob = envelope.make_request(KEY, CH, method, path, body, "application/x-www-form-urlencoded")
    out = envelope.unseal(KEY, CH, "res", client.handle(blob, KEY, CH, PORT), rid=rid)
    return out["s"], out.get("loc"), envelope.unpack_body(out["b"], out["z"])


s, loc, body = ask("GET", "/case")
check("GET through the relay", s == 200 and body == b"<html>DESK /case</html>" and seen[-1] == ("GET", "/case", "phone"))
s, loc, body = ask("POST", "/msgcheck", b"text=hi+there")
check("POST through the relay", body == b"POSTED text=hi+there" and seen[-1] == ("POST", "/msgcheck", b"text=hi+there"))
s, loc, body = ask("GET", "/go")
check("redirect passed back, not followed", s == 303 and loc == "/case")
n = len(seen)
s, loc, body = ask("GET", "/relay")
check("blocked page answered without touching the Desk", s == 403 and b"Only at the computer" in body and len(seen) == n)
s, loc, body = ask("GET", "/huge")
check("oversized page replaced by a short notice", s == 413 and b"Too large" in body)
rid, blob = envelope.make_request(KEY, CH, "GET", "/case")
client.handle(blob, KEY, CH, PORT)
check("same request twice refused", raises(lambda: client.handle(blob, KEY, CH, PORT)))
rid, blob = envelope.make_request(KEY, CH, "GET", "/case", ts=time.time() - 3600)
check("stale request refused", raises(lambda: client.handle(blob, KEY, CH, PORT)))

# ---------- pairing ----------
tmp = tempfile.mkdtemp()
old = os.getcwd()
os.chdir(tmp)
try:
    posts = []
    pairing.GET = lambda url: (200, json.dumps({"ok": True, "service": "scamhunter-relay", "configured": True}).encode())
    pairing.POST = lambda url, h, body: posts.append((url, h, body)) or (200, b'{"ok":true}')
    check("non-https worker refused", pairing.set_worker("http://relay.example.com") is not None)
    check("junk worker refused", pairing.set_worker("https://evil.com/x?y") is not None)
    check("worker accepted", pairing.set_worker("https://scamhunter-relay.matt.workers.dev/") is None)
    r = pairing.load()
    check("worker saved, admin key made", r["worker"] == "https://scamhunter-relay.matt.workers.dev" and len(r["admin_key"]) >= 40)
    check("not paired yet", not pairing.paired())

    qr, why = pairing.pair()
    r = pairing.load()
    url, h, body = posts[-1]
    reg = json.loads(body)
    check("registered with the admin key", url.endswith("/register") and h["Authorization"] == "Bearer " + r["admin_key"])
    check("Worker gets only hashes of the tokens", reg["desk_hash"] == hashlib.sha256(r["desk_token"].encode()).hexdigest()
          and r["desk_token"] not in body.decode() and r["phone_token"] not in body.decode())
    check("Worker never gets the encryption key", r["key"] not in body.decode())
    p = json.loads(base64.urlsafe_b64decode(qr[6:] + "=" * (-len(qr[6:]) % 4)))
    check("QR holds worker, channel, phone token and key", qr.startswith("shtd1:") and p == {"u": r["worker"], "c": r["channel"], "t": r["phone_token"], "k": r["key"]})
    check("QR doesn't hold the desk token or admin key", r["desk_token"] not in json.dumps(p) and r["admin_key"] not in json.dumps(p))
    check("paired", pairing.paired() and len(base64.b64decode(r["key"])) == 32)

    old_channel = r["channel"]
    qr2, _ = pairing.pair()
    check("re-pairing unregisters the old channel first", any(u.endswith("/unregister") and json.loads(b)["channel"] == old_channel for u, _, b in posts)
          and pairing.load()["channel"] != old_channel)
    pairing.unpair()
    r = pairing.load()
    check("unpair clears everything but the Worker", pairing.paired() is False and r.get("worker") and r.get("admin_key") and "key" not in r)

    pairing.POST = lambda url, h, body: (401, b"{}")
    check("Worker without the key: clear message", "admin key" in (pairing.pair()[1] or ""))

    import securestore
    check("relay secrets are in the sealed set", securestore.NESTED["relay"] >= {"admin_key", "desk_token", "phone_token", "key"})

    runs = []
    pairing.RUN = lambda args, **kw: runs.append((args, kw)) or subprocess.CompletedProcess(args, 0, "Success", "")
    real_which = pairing.wrangler
    pairing.wrangler = lambda: ["npx", "--yes", "wrangler@4"]
    check("admin key installed", pairing.install_admin_key() is None)
    args, kw = runs[-1]
    ak = pairing.load()["admin_key"]
    check("key piped in, never on the command line", ak not in " ".join(args) and kw["input"].strip() == ak and "secret" in args and "ADMIN_KEY" in args)
    pairing.RUN = lambda args, **kw: subprocess.CompletedProcess(args, 1, "", f"error: something about {kw['input'].strip()}")
    why = pairing.install_admin_key()
    check("errors never echo the key", why and ak not in why and "***" in why)
    pairing.RUN = lambda args, **kw: subprocess.CompletedProcess(args, 0, "Deployed scamhunter-relay\n  https://scamhunter-relay.matt.workers.dev\n", "")
    check("deploy finds the address", pairing.deploy_worker() == ("https://scamhunter-relay.matt.workers.dev", None))
    pairing.wrangler = lambda: None
    check("no Node.js: clear message", "Node.js" in pairing.deploy_worker()[1])
    pairing.wrangler = real_which

    # ---------- page ----------
    from relay import web
    pairing.POST = lambda url, h, body: (200, b'{"ok":true}')
    h = web.post({"do": "pair"})
    check("pairing page shows the QR once", "<svg" in h and "Anyone who scans this" in h)
    h2 = web.page()
    check("QR not on the page afterwards", "<svg" not in h2 and "shtd1:" not in h2)
    check("unpair button", "Unpair" in h2)
finally:
    os.chdir(old)
    shutil.rmtree(tmp, ignore_errors=True)
    pairing.GET = pairing.POST = None

# ---------- the background connection ----------
tmp = tempfile.mkdtemp()
os.chdir(tmp)
try:
    k = os.urandom(32)
    with open("config.json", "w") as f:
        json.dump({"relay": {"worker": "https://r.example.workers.dev", "channel": CH, "desk_token": "dt", "phone_token": "pt",
                             "key": base64.b64encode(k).decode(), "admin_key": "x" * 40}}, f)
    rid1, b1 = envelope.make_request(k, CH, "GET", "/case")
    rid2, b2 = envelope.make_request(os.urandom(32), CH, "GET", "/case")
    stop = threading.Event()

    class FakeWS:
        def __init__(self):
            self.sent = []
            self.msgs = [json.dumps({"id": "w1", "b": base64.b64encode(b1).decode()}), json.dumps({"id": "w2", "b": base64.b64encode(b2).decode()}), "not json"]

        def __iter__(self):
            for m in self.msgs:
                yield m
            time.sleep(0.5)
            stop.set()

        def send(self, s):
            self.sent.append(json.loads(s))

        def close(self):
            pass
    fw = FakeWS()
    conns = []
    client.run(stop, PORT, log=lambda *_: None, connect=lambda url, tok: conns.append((url, tok)) or fw)
    check("connects to the Worker's desk socket with the desk token", conns[0] == (f"wss://r.example.workers.dev/c/{CH}/desk", "dt"))
    by = {m["id"]: m for m in fw.sent}
    out = envelope.unseal(k, CH, "res", base64.b64decode(by["w1"]["b"]), rid=rid1)
    check("answers a good request", out["s"] == 200)
    check("bad request gets a plain error, no content", "err" in by["w2"] and "b" not in by["w2"])
finally:
    os.chdir(old)
    shutil.rmtree(tmp, ignore_errors=True)
srv.shutdown()

# ---------- wiring ----------
src = open(os.path.join(ROOT, "desk.py"), encoding="utf-8").read()
check("desk routes + background thread", src.count('path == "/relay"') == 2 and "relay_client.run" in src)
from deskui import shell  # noqa: E402
check("Settings tab lists it", any(p == "/relay" for _, _, _, groups in shell.SECTIONS for _, pages in groups for p, _, _ in pages))
reqs = open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8").read()
check("new libraries pinned with hashes", all(f"{n}==" in reqs for n in ("cryptography", "cffi", "pycparser", "segno")))

r = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "export_relay_vectors.py"), "--check"], capture_output=True, text=True)
check("phone app's encryption vectors match this code", r.returncode == 0)

print(f"relay: {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
