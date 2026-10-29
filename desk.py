"""ScamHunter Desk -- one program that runs everything.

Launch this and it:
  * starts and SUPERVISES all the watchers in the background (restarts any that
    die, so they never silently stop), and
  * serves a simple local dashboard in your browser showing, at a glance:
      - whether each watcher is alive,
      - where your stolen funds currently are (parked in a wallet, or cashed
        out to an exchange),
      - every real freeze opportunity, with a one-click button to open the
        drafted request, and
      - the latest activity.

One double-click (run_desk.cmd on Windows) starts the whole thing. Close the
window to stop everything. Standard-library only.

  python desk.py            # start supervisor + dashboard, open the browser
  python desk.py --no-open  # don't auto-open a browser
  python desk.py --port 8787
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
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
STATUS_FILE = "desk_status.json"

# Which XRPL wallet watcher file this install has (generalized vs. original).
_WALLET = "xrpl_watcher.py" if os.path.exists(os.path.join(HERE, "xrpl_watcher.py")) \
    else "scam_wallet_watcher.py"

# The processes the desk supervises. (label, argv, logfile)
SERVICES = [
    ("Wallet watcher", [sys.executable, "-u", _WALLET], "watcher_desk.log"),
    ("Network watcher", [sys.executable, "-u", "-m", "scam_investigator.netwatch"], "netwatch_desk.log"),
    ("Multi-chain tracer", [sys.executable, "-u", "-m", "multichain", "watch"], "mc_desk.log"),
]

_state_lock = threading.Lock()
_state = {}   # label -> {pid, alive, restarts, started, last_exit}


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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
        # back off more on repeated rapid failures, so a broken child can't spin
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
            prev = _state.get(label, {})
            if prev.get("alive"):
                _state[label] = {"pid": None, "alive": False, "restarts": restarts, "last_exit": _now()}
        _write_status()
        time.sleep(backoff)


# ----------------------------------------------------------- dashboard ------

def _read_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _tail(path, n=12):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.readlines()[-n:]
    except Exception:
        return []


def _case():
    return _read_json("victim.json") or {}


def _freeze_links():
    """Build (label, where, url) one-click actions for real XRPL + multichain cash-outs."""
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


def render():
    e = lambda s: (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
    status = _read_json(STATUS_FILE) or {}
    svc = status.get("services", {})
    case = _case()
    net = _read_json("network_map.json") or {}

    # watcher status cards
    cards = ""
    for label, _, _ in SERVICES:
        s = svc.get(label, {})
        alive = s.get("alive")
        dot = "#16a34a" if alive else "#dc2626"
        txt = "running" if alive else "down (will restart)"
        extra = f"pid {s.get('pid')}" if alive else f"restarts: {s.get('restarts', 0)}"
        cards += (f"<div class=card><span class=dot style='background:{dot}'></span>"
                  f"<b>{e(label)}</b><br><small class=mut>{txt} · {e(extra)}</small></div>")

    # where are the funds
    root = net.get("root", "")
    hops = [a for a in net.get("watchlist", []) if a != root]
    endpoints = net.get("endpoints", [])
    if endpoints:
        loc = "<p class=warn><b>⚠ Funds have reached an exchange — act on the freeze requests below.</b></p><ul>"
        seen = set()
        for ep in endpoints:
            if ep["address"] in seen:
                continue
            seen.add(ep["address"])
            loc += (f"<li><b>{e(ep.get('label') or 'unlabeled exchange')}</b> — {ep.get('xrp',0):,.0f} XRP "
                    f"(tag {e(ep.get('destination_tag'))})</li>")
        loc += "</ul>"
    elif hops:
        loc = ("<p class=ok>Your funds are <b>parked</b> in reused wallets — not yet cashed out. "
               "You'll be alerted the instant they move to an exchange.</p><ul>"
               + "".join(f"<li class=m>{e(h)}</li>" for h in hops) + "</ul>")
    else:
        loc = "<p class=mut>Mapping in progress…</p>"

    # freeze actions
    links = _freeze_links()
    if links:
        acts = "<table><tr><th>Target</th><th>Detail</th><th>Action</th></tr>"
        for who, detail, lbl, url in links:
            acts += (f"<tr><td>{e(who)}</td><td>{e(detail)}</td>"
                     f"<td><a class=btn href='{e(url)}' target=_blank>{e(lbl)}</a></td></tr>")
        acts += "</table>"
    else:
        acts = "<p class=mut>No freeze requests yet — none are valid until your funds reach an exchange. This is expected while funds are parked.</p>"

    # recent activity
    events = _tail("netwatch_events.log", 10) + _tail("mc_events.log", 6)
    ev = "".join(f"<div class=ev>{e(x.rstrip())}</div>" for x in events) or "<div class=mut>No events yet.</div>"

    stolen = case.get("tx_hash", "")
    return f"""<!doctype html><html><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<meta http-equiv=refresh content=15>
<title>ScamHunter Desk</title><style>
:root{{--bg:#0f1115;--fg:#e8eaf0;--mut:#9aa1b2;--line:#262b36;--acc:#5aa2ff;--ok:#16a34a;--warn:#ff6a5a}}
body{{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:0 auto;padding:18px}}
h1{{font-size:22px;margin:0}} h2{{font-size:15px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:22px 0 8px}}
.row{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}}
.card{{border:1px solid var(--line);border-radius:12px;padding:12px}}
.dot{{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:7px;vertical-align:middle}}
.m{{font-family:ui-monospace,monospace;font-size:12px}} .mut{{color:var(--mut)}} .ok{{color:#86efac}} .warn{{color:var(--warn)}}
ul{{margin:6px 0;padding-left:18px}} a{{color:var(--acc)}}
.btn{{display:inline-block;background:var(--acc);color:#07101f;padding:6px 12px;border-radius:8px;text-decoration:none;font-weight:600}}
table{{width:100%;border-collapse:collapse;font-size:13px}} td,th{{border-bottom:1px solid var(--line);padding:7px;text-align:left}}
.ev{{font-family:ui-monospace,monospace;font-size:12px;color:var(--mut);padding:2px 0;border-bottom:1px solid var(--line)}}
small{{font-size:12px}}</style></head><body>
<h1>🛡️ ScamHunter Desk</h1>
<p class=mut>Case: stolen-fund tracing · {e(case.get('scam_type') or 'cryptocurrency fraud')} · updated {e(status.get('updated',''))} · auto-refreshes</p>

<h2>Watchers</h2><div class=row>{cards or '<div class=mut>starting…</div>'}</div>

<h2>Where your funds are</h2>{loc}

<h2>Freeze / preservation actions</h2>{acts}

<h2>Recent activity</h2>{ev}

<p class=mut style=margin-top:20px><small>Scam wallet: <span class=m>{e(root)}</span>{(' · your tx: <span class=m>'+e(stolen[:24])+'…</span>') if stolen else ''}<br>
Freeze requests are drafts — review before sending. Downstream hops are leads, not proof a later transfer carries your specific funds.</small></p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path not in ("/", "/index.html"):
            self.send_response(404)
            self.end_headers()
            return
        body = render().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


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
        print("\nStopping watchers…")
        time.sleep(1)


if __name__ == "__main__":
    main()
