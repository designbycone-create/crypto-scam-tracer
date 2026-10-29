"""ScamHunter Desk -- one program that runs everything.

Launch this and it:
  * starts and SUPERVISES every watcher in the background (restarts any that
    die, so nothing silently stops), and
  * serves a local dashboard in your browser with:
      - a live status line (is everything running, when was the last ledger seen),
      - where YOUR funds are right now (parked, or cashed out to an exchange),
      - the NETWORK behind the scam -- every wallet and exchange it uses,
        built up continuously as an evidence record,
      - one-click freeze / preservation drafts, and
      - downloadable evidence (map + IC3-ready text) to hand to law enforcement.

    python desk.py            # start everything, open the dashboard
    python desk.py --no-open  # background mode (autostart)
Standard-library only.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
STATUS_FILE = "desk_status.json"
FMT = "%Y-%m-%d %H:%M:%S"

_WALLET = "xrpl_watcher.py" if os.path.exists(os.path.join(HERE, "xrpl_watcher.py")) \
    else "scam_wallet_watcher.py"

# (label, argv, logfile)
SERVICES = [
    ("Wallet watcher", [sys.executable, "-u", _WALLET], "watcher_desk.log"),
    ("Network watcher", [sys.executable, "-u", "-m", "scam_investigator.netwatch"], "netwatch_desk.log"),
    ("Network mapper", [sys.executable, "-u", "-m", "scam_investigator.network_intel"], "network_intel_desk.log"),
    ("Multi-chain tracer", [sys.executable, "-u", "-m", "multichain", "watch"], "mc_desk.log"),
]

_state_lock = threading.Lock()
_state = {}


def _now():
    return datetime.now().strftime(FMT)


def _write_status():
    with _state_lock:
        snap = dict(_state)
    try:
        with open(STATUS_FILE, "w", encoding="utf-8") as f:
            json.dump({"updated": _now(), "services": snap}, f)
    except Exception:
        pass


def supervise(label, argv, logfile, stop_evt):
    """Keep one child process alive. Restart with backoff if it exits."""
    restarts = -1
    while not stop_evt.is_set():
        restarts += 1
        backoff = min(3 + restarts, 30) if restarts else 3
        lf = None
        proc = None
        try:
            lf = open(logfile, "a", encoding="utf-8", errors="replace")
            lf.write(f"\n--- [{_now()}] desk starting {label} ---\n")
            lf.flush()
            proc = subprocess.Popen(argv, cwd=HERE, stdout=lf, stderr=subprocess.STDOUT)
            with _state_lock:
                _state[label] = {"pid": proc.pid, "alive": True, "restarts": restarts, "started": _now()}
            _write_status()
            while not stop_evt.is_set():
                if proc.poll() is not None:
                    break
                time.sleep(2)
        except Exception as e:
            with _state_lock:
                _state[label] = {"pid": None, "alive": False, "restarts": restarts, "error": str(e)}
            _write_status()
        finally:
            if proc is not None and proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
            if lf is not None:
                try:
                    lf.close()
                except Exception:
                    pass
        if stop_evt.is_set():
            break
        with _state_lock:
            if _state.get(label, {}).get("alive"):
                _state[label] = {"pid": None, "alive": False, "restarts": restarts, "last_exit": _now()}
        _write_status()
        time.sleep(backoff)


# ----------------------------------------------------------- helpers --------

def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except Exception:
        return None


def _tail(path, n=12):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.readlines()[-n:]
    except Exception:
        return []


def _ago(ts):
    """Seconds since a 'YYYY-mm-dd HH:MM:SS' local timestamp, or None."""
    try:
        return max(0, int((datetime.now() - datetime.strptime(ts.strip(), FMT)).total_seconds()))
    except Exception:
        return None


def _fmt_ago(s):
    if s is None:
        return "never"
    if s < 90:
        return f"{s}s ago"
    if s < 5400:
        return f"{s // 60} min ago"
    return f"{s // 3600} h ago"


def _case():
    return _read_json("victim.json") or {}


def _freeze_links():
    out = []
    net = _read_json("network_map.json") or {}
    case = _case()
    try:
        from scam_investigator import netreport
        seen = set()
        for ep in net.get("endpoints", []):
            k = (ep.get("address"), ep.get("destination_tag"))
            if k in seen:
                continue
            seen.add(k)
            lbl, url = netreport.gmail_action(ep, net.get("root"), case=case)
            out.append((ep.get("label") or ep.get("address", "")[:16], f"{ep.get('xrp', 0):,.0f} XRP", lbl, url))
    except Exception:
        pass
    mc = _read_json("mc_map.json") or {}
    try:
        from multichain import report as mcreport
        for op in mc.get("freeze_ops", []):
            lbl, url = mcreport.action_for(op, case)
            who = op.get("label") or f"{op.get('issuer','')} {op.get('asset','')}".strip()
            out.append((who or op.get("address", "")[:16], op.get("chain", ""), lbl, url))
    except Exception:
        pass
    return out


def _network_stats():
    net = _read_json("scam_network.json")
    if not net:
        return None
    nodes = net.get("nodes", {})
    eps = net.get("endpoints", [])
    exch = {}
    for ep in eps:
        name = (ep.get("label") or "unlabeled custodial").split("(")[0].strip()
        exch.setdefault(name, {"deposits": 0, "xrp": 0.0})
        exch[name]["deposits"] += 1
        exch[name]["xrp"] += ep.get("xrp") or 0
    return {
        "wallets": len(nodes),
        "hubs": sum(1 for n in nodes.values() if str(n.get("role", "")).startswith("intermediate")),
        "exchange_points": len({e["address"] for e in eps}),
        "deposits": len(eps),
        "flows": len(net.get("edges", [])),
        "xrp_to_exchanges": sum(e.get("xrp") or 0 for e in eps),
        "exchanges": sorted(exch.items(), key=lambda kv: -kv[1]["xrp"]),
    }


# ----------------------------------------------------------- dashboard ------

def render():
    e = lambda s: (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    status = _read_json(STATUS_FILE) or {}
    svc = status.get("services", {})
    case = _case()
    net = _read_json("network_map.json") or {}

    # --- live status line ---
    alive_n = sum(1 for label, _, _ in SERVICES if svc.get(label, {}).get("alive"))
    hb = _read_json("netwatch.heartbeat") or {}
    hb_age = _ago(hb.get("time", "")) if hb else None
    mapper_age = _ago(_read_text("network_intel.heartbeat") or "")
    ledger_ok = hb_age is not None and hb_age < 60
    all_ok = alive_n == len(SERVICES) and ledger_ok
    root = net.get("root", "")
    hops = [a for a in net.get("watchlist", []) if a != root]
    endpoints = net.get("endpoints", [])
    funds_state = ("CASHED OUT — act now" if endpoints else
                   ("parked (not yet cashed out)" if hops else "mapping…"))
    status_color = "#16a34a" if all_ok else ("#d97706" if alive_n else "#dc2626")
    status_line = (
        f"<div class=status style='border-color:{status_color}'>"
        f"<span class=dot style='background:{status_color}'></span>"
        f"<b>{'ALL SYSTEMS LIVE' if all_ok else ('PARTIAL — check below' if alive_n else 'DOWN')}</b>"
        f" &nbsp;·&nbsp; {alive_n}/{len(SERVICES)} watchers running"
        f" &nbsp;·&nbsp; last XRPL ledger seen <b>{_fmt_ago(hb_age)}</b>"
        + (f" (#{e(hb.get('ledger'))})" if hb.get("ledger") else "")
        + f" &nbsp;·&nbsp; network mapped <b>{_fmt_ago(mapper_age)}</b>"
        f" &nbsp;·&nbsp; your funds: <b>{e(funds_state)}</b></div>")

    # --- watcher cards ---
    cards = ""
    for label, _, _ in SERVICES:
        s = svc.get(label, {})
        alive = s.get("alive")
        dot = "#16a34a" if alive else "#dc2626"
        txt = "running" if alive else "down (restarting)"
        extra = f"up since {s.get('started','')[11:16]}" if alive else f"restarts: {s.get('restarts', 0)}"
        if label == "Network watcher" and alive:
            extra += f" · ledger {_fmt_ago(hb_age)}"
        if label == "Network mapper" and alive:
            extra += f" · mapped {_fmt_ago(mapper_age)}"
        cards += (f"<div class=card><span class=dot style='background:{dot}'></span>"
                  f"<b>{e(label)}</b><br><small class=mut>{txt} · {e(extra)}</small></div>")

    # --- your funds ---
    if endpoints:
        loc = "<p class=warn><b>&#9888; Your funds have reached an exchange — use the freeze requests below now.</b></p><ul>"
        seen = set()
        for ep in endpoints:
            if ep["address"] in seen:
                continue
            seen.add(ep["address"])
            loc += (f"<li><b>{e(ep.get('label') or 'unlabeled exchange')}</b> — {ep.get('xrp',0):,.0f} XRP "
                    f"(tag {e(ep.get('destination_tag'))})</li>")
        loc += "</ul>"
    elif hops:
        loc = ("<p class=ok>Your funds are <b>parked</b> in these wallets, which are being watched live. "
               "The moment they move to an exchange you'll get a phone alert and a freeze draft here.</p><ul>"
               + "".join(f"<li class=m>{e(h)}</li>" for h in hops) + "</ul>")
    else:
        loc = "<p class=mut>Mapping in progress&hellip;</p>"

    # --- the network behind the scam ---
    ns = _network_stats()
    if ns:
        exrows = "".join(
            f"<tr><td><b>{e(name)}</b></td><td>{v['deposits']}</td><td>{v['xrp']:,.0f}</td></tr>"
            for name, v in ns["exchanges"][:15])
        network = (
            f"<div class=row4><div class=card><small class=mut>Wallets in network</small><br><span class=big>{ns['wallets']}</span></div>"
            f"<div class=card><small class=mut>Consolidation wallets</small><br><span class=big>{ns['hubs']}</span></div>"
            f"<div class=card><small class=mut>Exchange deposits</small><br><span class=big>{ns['deposits']}</span></div>"
            f"<div class=card><small class=mut>XRP pushed to exchanges</small><br><span class=big>{ns['xrp_to_exchanges']:,.0f}</span></div></div>"
            f"<p class=mut>These wallets receive from the scam wallet and relay funds onward — the laundering layer of the operation, moving other victims' money too. Every one is logged for the record.</p>"
            f"<table><tr><th>Exchange / service the network uses</th><th>Deposits</th><th>XRP</th></tr>{exrows}</table>"
            f"<p style='margin-top:12px'><a class=btn href='/network' target=_blank>Open full network map</a> "
            f"<a class=btn href='/ic3' target=_blank>IC3 evidence record</a> "
            f"<a class='btn alt' href='/ic3?download=1'>Download for IC3 / exchanges</a></p>")
    else:
        network = "<p class=mut>Building the network record — the first full map takes a few minutes, then it keeps growing.</p>"

    # --- freeze actions ---
    links = _freeze_links()
    if links:
        acts = "<table><tr><th>Target</th><th>Detail</th><th>Action</th></tr>"
        for who, detail, lbl, url in links:
            acts += (f"<tr><td>{e(who)}</td><td>{e(detail)}</td>"
                     f"<td><a class=btn href='{e(url)}' target=_blank>{e(lbl)}</a></td></tr>")
        acts += "</table>"
    else:
        acts = ("<p class=mut>No freeze request for your own funds yet — they haven't reached an exchange. "
                "Meanwhile, the evidence record above is ready to send to IC3 and to every exchange the network uses.</p>")

    events = _tail("netwatch_events.log", 8) + _tail("network_intel_desk.log", 4) + _tail("mc_events.log", 4)
    ev = "".join(f"<div class=ev>{e(x.rstrip())}</div>" for x in events if x.strip()) or "<div class=mut>No events yet.</div>"

    stolen = case.get("tx_hash", "")
    return f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<meta http-equiv=refresh content=15>
<title>ScamHunter Desk</title><style>
:root{{--bg:#0f1115;--fg:#e8eaf0;--mut:#9aa1b2;--line:#262b36;--acc:#5aa2ff;--warn:#ff6a5a}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:960px;margin:0 auto;padding:18px}}
h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:14px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:24px 0 8px}}
.status{{border:2px solid;border-radius:12px;padding:10px 14px;margin:12px 0;font-size:14px}}
.row{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}}
.row4{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px;margin-bottom:10px}}
.card{{border:1px solid var(--line);border-radius:12px;padding:12px}} .big{{font-size:24px;font-weight:700}}
.dot{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:7px;vertical-align:middle}}
.m{{font-family:ui-monospace,monospace;font-size:12px}} .mut{{color:var(--mut)}} .ok{{color:#86efac}} .warn{{color:var(--warn)}}
ul{{margin:6px 0;padding-left:18px}} a{{color:var(--acc)}}
.btn{{display:inline-block;background:var(--acc);color:#07101f;padding:7px 13px;border-radius:8px;text-decoration:none;font-weight:600;margin:2px 4px 2px 0}}
.btn.alt{{background:transparent;color:var(--acc);border:1px solid var(--acc)}}
table{{width:100%;border-collapse:collapse;font-size:13px}} td,th{{border-bottom:1px solid var(--line);padding:7px;text-align:left}}
.ev{{font-family:ui-monospace,monospace;font-size:12px;color:var(--mut);padding:2px 0;border-bottom:1px solid var(--line)}}
small{{font-size:12px}}</style></head><body>
<h1>&#128737;&#65039; ScamHunter Desk</h1>
{status_line}

<h2>Watchers</h2><div class=row>{cards}</div>

<h2>Your funds</h2>{loc}

<h2>The network behind this scam</h2>{network}

<h2>Freeze / preservation actions</h2>{acts}

<h2>Recent activity</h2>{ev}

<p class=mut style=margin-top:20px><small>Scam wallet: <span class=m>{e(root)}</span>{(' · your tx: <span class=m>'+e(stolen[:24])+'&hellip;</span>') if stolen else ''}<br>
All drafts are for your review before sending. Data is public and verifiable on the XRP Ledger.</small></p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype, extra=None):
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path in ("/", "/index.html"):
            return self._send(render(), "text/html; charset=utf-8")
        if path == "/network":
            body = _read_text("scam_network.html") or "<p>Network map not built yet — check back in a few minutes.</p>"
            return self._send(body, "text/html; charset=utf-8")
        if path == "/ic3":
            body = _read_text("ic3_evidence.txt") or "Evidence record not built yet — check back in a few minutes."
            extra = {}
            if "download" in query:
                extra["Content-Disposition"] = f'attachment; filename="scam-network-evidence-{datetime.now():%Y%m%d}.txt"'
            return self._send(body, "text/plain; charset=utf-8", extra)
        self.send_response(404)
        self.end_headers()


def _free_port(preferred):
    for p in (preferred, 0):
        try:
            s = socket.socket()
            s.bind(("127.0.0.1", p))
            port = s.getsockname()[1]
            s.close()
            return port
        except Exception:
            continue
    return preferred


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--no-open", action="store_true")
    a = ap.parse_args()
    os.chdir(HERE)

    stop_evt = threading.Event()
    for label, argv, logfile in SERVICES:
        threading.Thread(target=supervise, args=(label, argv, logfile, stop_evt), daemon=True).start()

    port = _free_port(a.port)
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print("ScamHunter Desk running.")
    print("  Dashboard:", url)
    print("  Supervising:", ", ".join(l for l, _, _ in SERVICES))
    print("  Close this window (or Ctrl+C) to stop everything.")
    if not a.no_open:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set()
        print("\nStopping watchers")
        time.sleep(1)


if __name__ == "__main__":
    main()
