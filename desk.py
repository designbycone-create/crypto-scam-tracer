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
    ("Multi-chain tracer", [sys.executable, "-u", "-m", "multichain", "watch", "--interval", "300"], "mc_desk.log"),
    # freeze kits, issued-token freeze scan, incident feeds, exchange status, scam radar, risk signals
    ("Responder", [sys.executable, "-u", "-m", "responder.daemon"], "responder_desk.log"),
]

XRPL_ONLY = {"Wallet watcher", "Network watcher", "Network mapper"}


def _xrpl_case():
    try:
        from freezekit import setup as _s
        return _s.xrpl_case()
    except Exception:
        return True


_state_lock = threading.Lock()
_state = {}
_procs = {}   # label -> running Popen (so setup can restart everything with the new case)


def restart_all():
    """Stop every watcher; supervise() restarts each one, reading the new config."""
    for label, proc in list(_procs.items()):
        try:
            if proc.poll() is None:
                proc.terminate()
        except Exception:
            pass


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
        if label in XRPL_ONLY and not _xrpl_case():
            # this case has no XRP Ledger wallet -> the XRPL watchers aren't needed
            with _state_lock:
                _state[label] = {"pid": None, "alive": False, "skipped": True, "restarts": max(restarts, 0)}
            _write_status()
            stop_evt.wait(15)
            continue
        restarts += 1
        backoff = min(3 + restarts, 30) if restarts else 3
        lf = None
        proc = None
        try:
            lf = open(logfile, "a", encoding="utf-8", errors="replace")
            lf.write(f"\n--- [{_now()}] desk starting {label} ---\n")
            lf.flush()
            proc = subprocess.Popen(argv, cwd=HERE, stdout=lf, stderr=subprocess.STDOUT)
            _procs[label] = proc
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


def alert_flusher(stop_evt, interval=120):
    """Keep retrying queued phone alerts (critical first) until delivered."""
    while not stop_evt.is_set():
        try:
            import alerts
            alerts.flush()
        except Exception:
            pass
        stop_evt.wait(interval)


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
    alive_n = sum(1 for label, _, _ in SERVICES if svc.get(label, {}).get("alive") or svc.get(label, {}).get("skipped"))
    xrpl_on = _xrpl_case()
    hb = _read_json("netwatch.heartbeat") or {}
    hb_age = _ago(hb.get("time", "")) if hb else None
    mapper_age = _ago(_read_text("network_intel.heartbeat") or "")
    ledger_ok = (hb_age is not None and hb_age < 60) or not xrpl_on
    all_ok = alive_n == len(SERVICES) and ledger_ok
    root = net.get("root", "")
    hops = [a for a in net.get("watchlist", []) if a != root]
    try:   # where YOUR funds landed, on any chain (XRPL record + multi-chain tracer)
        from freezekit import kit as _kit
        _r, _targets, _it, _ops = _kit.collect()
        my_targets = [t for t in _targets.values() if t["yours"]]
    except Exception:
        _kit, my_targets = None, []
    mc = _read_json("mc_map.json") or {}
    mc_cases = [c for c in (_read_json("config.json") or {}).get("cases") or [] if c.get("chain") != "xrpl"]
    endpoints = my_targets
    funds_state = ("CASHED OUT — act now" if my_targets else
                   ("parked (not yet cashed out)" if hops or mc_cases else "mapping…"))
    try:
        import alerts
        pend = alerts.pending()
        ast = alerts.state()
    except Exception:
        pend, ast = [], {}
    crit = [p for p in pend if p.get("critical")]
    alerts_txt = ("phone alerts OK" if not pend else
                  f"{len(pend)} alert(s) waiting to deliver" + (f" ({len(crit)} CRITICAL)" if crit else ""))
    banner = ""
    if pend:
        rows = "".join(f"<li><b>{e(p['title'])}</b> <small class=mut>queued {e(p.get('queued_at',''))}"
                       f" · tries {p.get('attempts',0)}</small><br><small>{e(p['message'][:240])}</small></li>"
                       for p in sorted(pend, key=lambda i: (not i.get('critical'), i.get('queued_at','')))[:8])
        banner = (f"<div class=banner><b>&#9888; {len(pend)} phone alert(s) could not be delivered yet</b>"
                  f" &mdash; retrying automatically every 2 minutes"
                  f"{(' (last error: ' + e(str(ast.get('last_error',''))[:80]) + ')') if ast.get('last_error') else ''}."
                  f" Act on these from this page:<ul>{rows}</ul></div>")
    status_color = "#16a34a" if all_ok else ("#d97706" if alive_n else "#dc2626")
    if crit:
        status_color = "#dc2626"
    status_line = (
        f"<div class=status style='border-color:{status_color}'>"
        f"<span class=dot style='background:{status_color}'></span>"
        f"<b>{'ALL SYSTEMS LIVE' if all_ok else ('PARTIAL — check below' if alive_n else 'DOWN')}</b>"
        f" &nbsp;·&nbsp; {alive_n}/{len(SERVICES)} watchers running"
        + ((f" &nbsp;·&nbsp; last XRPL ledger seen <b>{_fmt_ago(hb_age)}</b>"
            + (f" (#{e(hb.get('ledger'))})" if hb.get("ledger") else "")
            + f" &nbsp;·&nbsp; network mapped <b>{_fmt_ago(mapper_age)}</b>") if xrpl_on else
           f" &nbsp;·&nbsp; multi-chain trace updated <b>{e(mc.get('generated', 'pending'))}</b>")
        + f" &nbsp;·&nbsp; your funds: <b>{e(funds_state)}</b>"
        f" &nbsp;·&nbsp; <b>{e(alerts_txt)}</b></div>")

    # --- watcher cards ---
    cards = ""
    for label, _, _ in SERVICES:
        s = svc.get(label, {})
        alive = s.get("alive")
        dot = "#16a34a" if alive else ("#6b7280" if s.get("skipped") else "#dc2626")
        txt = "running" if alive else ("not needed for this case" if s.get("skipped") else "down (restarting)")
        extra = (f"up since {s.get('started','')[11:16]}" if alive else
                 ("no XRP Ledger wallet in this case" if s.get("skipped") else f"restarts: {s.get('restarts', 0)}"))
        if label == "Network watcher" and alive:
            extra += f" · ledger {_fmt_ago(hb_age)}"
        if label == "Network mapper" and alive:
            extra += f" · mapped {_fmt_ago(mapper_age)}"
        cards += (f"<div class=card><span class=dot style='background:{dot}'></span>"
                  f"<b>{e(label)}</b><br><small class=mut>{txt} · {e(extra)}</small></div>")

    # --- your funds ---
    if my_targets:
        loc = "<p class=warn><b>&#9888; Your funds have reached an exchange — use the freeze requests below now.</b></p><ul>"
        for t in my_targets:
            mine_d = [d for d in t["deposits"] if d["yours"]]
            tags = sorted({str(d["tag"]) for d in mine_d if d.get("tag") is not None})
            loc += (f"<li><b>{e(t['entry'].get('name') or 'unlabeled exchange')}</b> — {e(_kit.amt_str(mine_d))}"
                    + (f" (tag {e(', '.join(tags))})" if tags else
                       f" (deposit account {e(mine_d[0]['address'][:12])}… on {e(_kit._chain_name(mine_d[0].get('chain')))})")
                    + f" <a href='/submit#{e(t['id'])}'>freeze kit</a></li>")
        loc += "</ul>"
    elif mc_cases:
        s_ = mc.get("summary") or {}
        loc = (f"<p class=ok>Following your funds across <b>{e(', '.join(s_.get('chains') or [c['chain'] for c in mc_cases]))}</b> "
               f"&mdash; {s_.get('total_nodes', 0)} wallet(s) mapped so far, re-checked every 5 minutes. When they reach an exchange "
               f"you'll get an alert and a freeze kit here.</p><ul>"
               + "".join(f"<li class=m>{e(c['chain'])}: {e(c['address'])}</li>" for c in mc_cases) + "</ul>")
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
            f"<p style='margin-top:12px'><a class=btn href='/graph' target=_blank>Interactive network graph</a> "
            f"<a class='btn alt' href='/network' target=_blank>Full network table</a> "
            f"<a class=btn href='/ic3' target=_blank>IC3 evidence record</a> "
            f"<a class='btn alt' href='/ic3?download=1'>Download for IC3 / exchanges</a></p>")
    else:
        network = ("<p class=mut>" + ("Building the network record — the first full map takes a few minutes, then it keeps growing."
                   if xrpl_on else "Every wallet and exchange the multi-chain tracer finds is recorded as it goes.")
                   + "</p><p><a class=btn href='/graph' target=_blank>Interactive network graph</a></p>")

    # --- freeze actions: the Submission Center ---
    try:
        from freezekit import tracker
        st = tracker.load()
        tgs = st.get("targets", {})
        mine = {k: v for k, v in tgs.items() if v.get("yours")}
        done = sum(1 for k, v in st.get("status", {}).items() if v.get("state") in ("submitted", "acknowledged", "frozen", "not needed"))
        if mine:
            items = "".join(f"<li><b>{e(v.get('name') or k)}</b> — {e(v.get('amount_str') or str(v.get('xrp', 0)) + ' XRP')} · cash-out "
                            f"{e(tracker.elapsed(v.get('yours_since') or v.get('detected', '')))} "
                            f"<a href='/submit#{e(k)}'>open kit</a></li>" for k, v in mine.items())
            acts = (f"<p class=warn><b>Your funds reached {len(mine)} platform(s). Freeze kits are built.</b></p><ul>{items}</ul>"
                    f"<p><a class=btn href='/submit'>Open Submission Center</a> "
                    f"<a class='btn alt' href='/kit/_case/officer_packet.html' target=_blank>Print Officer Packet</a> "
                    f"<small class=mut>{done} step(s) marked done · {len(tgs) - len(mine)} other network cash-out point(s) documented</small></p>")
        elif tgs:
            acts = (f"<p class=mut>Your own funds haven't reached an exchange. {len(tgs)} network cash-out point(s) are documented "
                    f"with officer-ready kits.</p><p><a class=btn href='/submit'>Open Submission Center</a></p>")
        else:
            acts = "<p class=mut>Freeze kits appear here as soon as the network map finds a cash-out point.</p>"
    except Exception as ex:
        acts = f"<p class=mut>Submission Center unavailable ({e(ex)}).</p>"

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
.banner{{border:2px solid #dc2626;background:#2a1215;border-radius:12px;padding:10px 14px;margin:10px 0;font-size:14px}}
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
<div class=nav style="margin-bottom:8px"><a href='/'>Desk</a> &nbsp; <a href='/graph'>Network graph</a> &nbsp; <a href='/submit'>Submission Center</a> &nbsp; <a href='/incident'>Incident mode</a> &nbsp; <a href='/radar'>Scam radar</a> &nbsp; <a href='/intel'>Threat intel</a> &nbsp; <a href='/check'>Claim checker</a></div>
<h1>&#128737;&#65039; ScamHunter Desk</h1>
<div style="font-size:12px;color:#86efac">Free for victims &middot; never asks for money or a seed phrase &middot; never sends anything without you</div>
{status_line}
{banner}

<h2>Watchers</h2><div class=row>{cards}</div>

<h2>Your funds</h2>{loc}

<h2>The network behind this scam</h2>{network}

<h2>Freeze requests &mdash; Submission Center</h2>{acts}

<h2>Recent activity</h2>{ev}

<p class=mut style=margin-top:20px><small>Scam wallet: <span class=m>{e(root or ', '.join(c['address'] for c in mc_cases))}</span>{(' · your tx: <span class=m>'+e(stolen[:24])+'&hellip;</span>') if stolen else ''}<br>
Nothing is ever sent without you. <a href='/setup'>Case setup</a>. Data is public and verifiable on each blockchain.</small></p>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body, ctype, extra=None, code=200):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        path, _, query = self.path.partition("?")
        try:
            from freezekit import web
        except Exception:
            web = None
        from freezekit import setup as _setup
        if path in ("/", "/index.html"):
            if _setup.needed():
                return self._redirect("/setup")
            return self._send(render(), "text/html; charset=utf-8")
        if path == "/setup":
            return self._send(_setup.page(), "text/html; charset=utf-8")
        if path == "/network":
            body = _read_text("scam_network.html") or "<p>Network map not built yet — check back in a few minutes.</p>"
            return self._send(body, "text/html; charset=utf-8")
        if path == "/ic3":
            body = _read_text("ic3_evidence.txt") or "Evidence record not built yet — check back in a few minutes."
            extra = {}
            if "download" in query:
                extra["Content-Disposition"] = f'attachment; filename="scam-network-evidence-{datetime.now():%Y%m%d}.txt"'
            return self._send(body, "text/plain; charset=utf-8", extra)
        if path == "/graph":
            from scam_investigator import graphview
            return self._send(graphview.render(), "text/html; charset=utf-8")
        if web is not None:
            if path == "/submit":
                return self._send(web.submission_center(), "text/html; charset=utf-8")
            if path == "/incident":
                return self._send(web.incident_page(), "text/html; charset=utf-8")
            if path == "/radar":
                return self._send(web.radar_page(), "text/html; charset=utf-8")
            if path == "/intel":
                from urllib.parse import parse_qs
                q = (parse_qs(query).get("q") or [""])[0]
                return self._send(web.intel_page(q), "text/html; charset=utf-8")
            if path == "/check":
                return self._send(web.check_page(), "text/html; charset=utf-8")
            if path.startswith("/kit/"):
                r = web.kit_file(path[5:])
                if r:
                    return self._send(r[0], r[1])
        self._send("Not found", "text/plain", code=404)

    def _redirect(self, where):
        self.send_response(303)
        self.send_header("Location", where)
        self.end_headers()

    def _local_origin(self):
        """Only accept form posts from the Desk's own pages (blocks cross-site POSTs)."""
        src = self.headers.get("Origin") or self.headers.get("Referer") or ""
        if not src:
            return True
        from urllib.parse import urlparse
        return (urlparse(src).hostname or "") in ("127.0.0.1", "localhost")

    def do_POST(self):
        from urllib.parse import parse_qs
        if not self._local_origin():
            return self._send("Forbidden", "text/plain", code=403)
        n = min(int(self.headers.get("Content-Length") or 0), 2_000_000)
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode("utf-8", "replace")).items()}
        from freezekit import web
        path = self.path.partition("?")[0]
        try:
            if path == "/setup/lookup":
                from freezekit import setup as _setup
                from freezekit import chainlookup
                return self._send(json.dumps(chainlookup.lookup(form.get("q", ""))), "application/json")
            if path == "/setup":
                from freezekit import setup as _setup
                ok, info = _setup.save(form)
                if not ok:
                    return self._send(_setup.page(info, prefill=form), "text/html; charset=utf-8")
                threading.Thread(target=lambda: (time.sleep(1), restart_all()), daemon=True).start()
                return self._send(_setup.done_page(info), "text/html; charset=utf-8")
            if path == "/submit/status":
                web.handle_status_post(form)
                ref = self.headers.get("Referer") or "/submit"
                self.send_response(303)
                self.send_header("Location", "/submit" + ("#" + form["key"].split(":")[0] if ":" in form.get("key", "") else ""))
                self.end_headers()
                return
            if path == "/incident":
                return self._send(web.incident_post(form), "text/html; charset=utf-8")
            if path == "/check":
                return self._send(web.check_post(form), "text/html; charset=utf-8")
        except Exception as ex:
            return self._send(f"Error: {ex}", "text/plain", code=500)
        self._send("Not found", "text/plain", code=404)


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


def ensure_deps():
    """Make sure the Python running the Desk has the watchers' dependencies.
    (Windows often has several Pythons; the watchers run under this one.)"""
    try:
        import websockets  # noqa: F401
        return
    except ImportError:
        pass
    req = os.path.join(HERE, "requirements.txt")
    print("Installing dependencies for", sys.executable, flush=True)
    for extra in (["--user"], []):
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "-q", *extra, "-r", req], check=True, timeout=600)
            return
        except Exception as e:
            print("  pip attempt failed:", e, flush=True)


def main():
    ensure_deps()
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    ap.add_argument("--no-open", action="store_true")
    a = ap.parse_args()
    os.chdir(HERE)

    stop_evt = threading.Event()
    for label, argv, logfile in SERVICES:
        threading.Thread(target=supervise, args=(label, argv, logfile, stop_evt), daemon=True).start()

    threading.Thread(target=alert_flusher, args=(stop_evt,), daemon=True).start()

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
