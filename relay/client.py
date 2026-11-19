"""The Desk's side of the relay: connect out to your Worker and answer the paired phone.

Runs as a background thread in the Desk. Each message from the Worker is a phone request, encrypted
end to end; it is opened, checked (timestamp, replay, relay/policy.py), passed to this Desk at
127.0.0.1, and the answer goes back encrypted. Nothing listens for connections from the internet.
"""
import base64
import json
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from relay import envelope, pairing, policy

MAX_RESPONSE = 700 * 1024          # the Worker's WebSocket messages are capped at 1 MiB; base64 adds a third
STATE = {"connected": False, "since": None, "last_error": None, "last_request": None, "requests": 0, "refused": 0}
_guard = envelope.ReplayGuard()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def local(port, method, path, body, ctype):
    """Ask this Desk (127.0.0.1) -- returns (status, content_type, location, bytes)."""
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body if method == "POST" else None, method=method,
                                 headers={"Content-Type": ctype or "application/x-www-form-urlencoded", "X-ScamHunter-Via": "phone"})
    try:
        with _opener.open(req, timeout=40) as r:
            return r.status, r.headers.get("Content-Type", ""), r.headers.get("Location", ""), r.read(envelope.MAX_BODY + 1)
    except urllib.error.HTTPError as ex:
        return ex.code, ex.headers.get("Content-Type", ""), ex.headers.get("Location", ""), ex.read(envelope.MAX_BODY + 1)


def _page(title, text, status=403):
    html = (f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<body style='font:20px/1.5 system-ui;padding:20px'><h1>{title}</h1><p>{text}</p><p><a href='/'>Back to the Desk</a></p>")
    return status, "text/html; charset=utf-8", "", html.encode()


def handle(blob, key, channel, port):
    """Encrypted request -> encrypted response (bytes), or raises EnvelopeError (the Worker gets a plain error)."""
    req = envelope.unseal(key, channel, "req", blob)
    _guard.check(req.get("id"), req.get("ts"))
    method, path = req.get("m"), req.get("p")
    body = envelope.unpack_body(req.get("b"), req.get("z"))
    why = policy.check(method, path, body, req.get("ct", ""))
    STATE["last_request"] = time.strftime("%Y-%m-%d %H:%M:%S")
    STATE["requests"] += 1
    if why:
        STATE["refused"] += 1
        st, ct, loc, data = _page("Only at the computer", why[0].upper() + why[1:] + ".")
    else:
        try:
            st, ct, loc, data = local(port, method, path, body, req.get("ct", ""))
        except Exception as ex:
            st, ct, loc, data = _page("The Desk didn't answer", f"({str(ex)[:80]})", 502)
    if len(data) > envelope.MAX_BODY:
        st, ct, loc, data = _page("Too large for the phone", "Open this page on the computer.", 413)
    b, z = envelope.pack_body(data)
    out = envelope.seal(key, channel, "res", {"id": req["id"], "s": st, "ct": ct, "loc": loc, "b": b, "z": z}, rid=req["id"])
    if len(out) > MAX_RESPONSE:
        st, ct, loc, data = _page("Too large for the phone", "This page is too big to send to the phone. Open it on the computer.", 413)
        b, z = envelope.pack_body(data)
        out = envelope.seal(key, channel, "res", {"id": req["id"], "s": st, "ct": ct, "loc": loc, "b": b, "z": z}, rid=req["id"])
    return out


def run(stop_evt, port=8787, log=print, connect=None):
    """Keep a connection to the Worker while paired. `connect` is a test hook."""
    backoff = 2
    pool = ThreadPoolExecutor(max_workers=4)
    while not stop_evt.is_set():
        r = pairing.load()
        if not pairing.paired():
            STATE.update(connected=False)
            stop_evt.wait(15)
            continue
        key, channel = base64.b64decode(r["key"]), r["channel"]
        url = r["worker"].replace("https://", "wss://", 1) + f"/c/{channel}/desk"
        try:
            if connect:
                ws = connect(url, r["desk_token"])
            else:
                import nettls
                from websockets.sync.client import connect as wsconnect
                ws = wsconnect(url, additional_headers={"Authorization": "Bearer " + r["desk_token"]}, ssl=nettls.context(),
                               open_timeout=20, max_size=2 * 1024 * 1024, ping_interval=25, ping_timeout=20)
            lock = threading.Lock()
            STATE.update(connected=True, since=time.strftime("%Y-%m-%d %H:%M:%S"), last_error=None)
            log("phone relay: connected to your Worker")
            backoff = 2

            def answer(msg):
                wid = msg.get("id")
                try:
                    out = {"id": wid, "b": base64.b64encode(handle(base64.b64decode(msg.get("b") or ""), key, channel, port)).decode()}
                except envelope.EnvelopeError as ex:
                    STATE["refused"] += 1
                    out = {"id": wid, "err": str(ex)}
                except Exception as ex:
                    out = {"id": wid, "err": "the Desk hit an error"}
                    log(f"phone relay: {ex!r}")
                with lock:
                    ws.send(json.dumps(out))

            for raw in ws:
                if stop_evt.is_set() or pairing.load().get("channel") != channel:
                    break                                   # unpaired or re-paired: drop this connection
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                if isinstance(msg, dict) and msg.get("id"):
                    pool.submit(answer, msg)
            ws.close()
        except Exception as ex:
            STATE.update(connected=False, last_error=str(ex)[:160])
            code = getattr(getattr(ex, "rcvd", None), "code", None) or getattr(ex, "code", None)
            if code in (4001, 4002) or "401" in str(ex):
                backoff = 60                                # not allowed / re-paired: no point hammering the Worker
        STATE.update(connected=False)
        if pairing.load().get("channel") != channel:
            backoff = 1                                     # a new pairing: connect on the new channel right away
        stop_evt.wait(backoff)
        backoff = min(backoff * 2, 300)
