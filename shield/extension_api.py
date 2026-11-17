"""Desk side of the ScamHunter Guard browser extension.

The extension works on its own with the attack list built into it (extension/feed.json, part of
each signed release). Connected to the Desk with a pairing code it also gets your same-day
incident list, your address book and phone alerts. Every API call needs that code in the
X-ScamHunter-Ext header; web pages can't send it, so websites can't read your address book.

  GET  /api/ext/feed                       -> known scammer addresses and attack hosts
  POST /api/ext/check  {"addresses": [..]} -> known-bad / saved status (address book stays here)
  POST /api/ext/report {"event": {...}}    -> logged; serious events alert your phone

    python -m shield.extension_api build   # refresh extension/feed.json from the campaign feed
"""
import hmac
import html
import json
import os
import secrets
import sys
from datetime import datetime

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXT_DIR = os.path.join(HERE, "extension")
CFG = "config.json"
LOG = "extension_events.jsonl"


def _cfg():
    try:
        with open(CFG, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return {}


def token():
    import securestore
    c = _cfg()
    t = securestore.reveal(c.get("extension_token"))
    if not t:
        t = c["extension_token"] = secrets.token_urlsafe(18)
        securestore.save(c, CFG)
    return t


def authorized(headers):
    got = headers.get("X-ScamHunter-Ext") or ""
    return bool(got) and hmac.compare_digest(got, token())


def _norm(a):
    from shield.clipguard import _k
    return _k(a)


def feed(include_local=True):
    """{"addresses": {address: label}, "domains": {domain: label}} -- campaign feed (+ your same-day list)."""
    import threatfeed
    out = {"addresses": {}, "domains": {}}
    for c in threatfeed.campaigns():
        label = f"the {c['name']} campaign ({c.get('first_seen', '')})"
        for e in c.get("addresses", []):
            out["addresses"][_norm(e["address"])] = label
        for d in c.get("domains", []):
            out["domains"][d.lower()] = label
    if include_local:
        try:
            from shield import compromised
            d = compromised.load()
            for a, v in d.get("addresses", {}).items():
                out["addresses"].setdefault(_norm(a), f"your incident list ({v.get('label') or 'incident'})")
            for dom, v in d.get("domains", {}).items():
                if v.get("status") == "compromised":
                    out["domains"].setdefault(dom, f"your incident list ({v.get('label') or 'incident'})")
        except Exception:
            pass
    return out


def build():
    """Write the attack list built into the extension (shipped and signed with each release)."""
    path = os.path.join(EXT_DIR, "feed.json")
    data = feed(include_local=False)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, indent=1, sort_keys=True)
        f.write("\n")
    return path


def api(path, method, body, query):
    if path == "/api/ext/feed" and method == "GET":
        return 200, feed()
    if path == "/api/ext/check" and method == "POST":
        from shield.clipguard import bad_reasons, book, _k
        b = book()
        res = []
        for a in (body.get("addresses") or [])[:10]:
            a = str(a)
            why = bad_reasons(a)
            res.append({"address": a, "bad": why[0] if why else None, "saved": (b.get(_k(a)) or {}).get("label")})
        return 200, {"results": res}
    if path == "/api/ext/report" and method == "POST":
        ev = body.get("event") or {}
        ev = {k: str(v)[:500] for k, v in ev.items() if k in ("kind", "url", "address", "original", "replaced", "host", "campaign", "what")}
        ev["time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")
        if ev.get("kind") in ("swap", "attack_host", "paste_blocked", "copied_bad", "page_bad"):
            try:
                import alerts
                alerts.send("Browser: STOP", f"{ev['kind']} on {ev.get('url', '?')[:120]}\n"
                            f"{ev.get('replaced') or ev.get('address') or ev.get('host') or ''} {ev.get('campaign', '')}",
                            critical=ev["kind"] == "swap", key=f"ext-{ev['kind']}-{ev.get('replaced') or ev.get('address') or ev.get('host')}")
            except Exception:
                pass
        return 200, {"ok": True}
    return 404, {"error": "unknown endpoint"}


def events(n=20):
    try:
        with open(LOG, encoding="utf-8") as f:
            return [json.loads(l) for l in f.readlines()[-n:]][::-1]
    except Exception:
        return []


e = lambda s: html.escape(str(s if s is not None else ""), quote=True)


def page():
    ev = "".join(f"<tr><td>{e(x.get('time'))}</td><td>{e(x.get('kind'))}</td><td style='word-break:break-all'>{e(x.get('url'))}</td>"
                 f"<td style='word-break:break-all'>{e(x.get('replaced') or x.get('address') or x.get('host') or x.get('what'))}</td></tr>" for x in events())
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Browser extension</title><style>body{{font:19px/1.5 Segoe UI,Arial,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;color:#111}}
.code{{font:22px Consolas,monospace;background:#f2f2f2;padding:10px 14px;border-radius:8px;display:inline-block;user-select:all}}
li{{margin:6px 0}}table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #ddd;padding:6px;font-size:15px;text-align:left}}</style></head>
<body><h1>ScamHunter Guard for your browser</h1>
<p>The extension watches pages as they run. It warns you when a page swaps a crypto address you copy, loads code from known attack servers,
or shows a known scammer's address, and it blocks pasting a known scammer address.</p>
<h2>Install it (Chrome or Edge)</h2><ol>
<li>Open <b>edge://extensions</b> (Edge) or <b>chrome://extensions</b> (Chrome) in the address bar.</li>
<li>Turn on <b>Developer mode</b>.</li>
<li>Click <b>Load unpacked</b> and choose this folder:<br><span class=code>{e(EXT_DIR)}</span></li>
<li>Pin the ScamHunter Guard shield icon to the toolbar.</li></ol>
<h2>Connect it to this Desk</h2>
<p>Click the extension icon &rarr; <b>Connect to Desk</b>, and paste this code:</p><p><span class=code>{e(token())}</span></p>
<p>Connected, it uses your address book, your same-day incident list and your phone alerts. Keep the code private.</p>
<h2>What it has caught</h2><table><tr><th>When</th><th>What</th><th>Page</th><th>Detail</th></tr>{ev or "<tr><td colspan=4>Nothing yet.</td></tr>"}</table>
</body></html>"""


if __name__ == "__main__":
    if sys.argv[1:2] == ["build"]:
        sys.path.insert(0, HERE)
        print(build())
