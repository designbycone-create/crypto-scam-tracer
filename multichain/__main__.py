"""Multi-chain scam-fund tracer -- CLI and automated daemon.

  # one-shot trace from a seed address (the chain the funds landed on)
  python -m multichain trace --chain tron --address TXXXX [--after 2026-10-28T00:00:00Z]

  # resume across a custodial crossing once you learn where funds came out
  python -m multichain resume --handoff h1 --to-chain ethereum --to-address 0xXXXX

  # re-render the detailed log / regenerate all reports from the saved map
  python -m multichain map
  python -m multichain report

  # pull swap/bridge leads out of the XRPL watcher's map as open handoffs
  python -m multichain importxrpl

  # AUTOMATED: run forever, re-trace every known address, auto-draft reports,
  # phone-alert on anything new. Autostart this like the XRPL watchers.
  python -m multichain watch [--interval 900]
"""
import argparse
import json
import os
import time

from . import entities, report
from .engine import Tracer
from .mapview import render_html

try:
    import scamconfig
except Exception:
    scamconfig = None

MAP = "mc_map.json"
HTML = "mc_map.html"
EVENTLOG = "mc_events.log"
NTFY_TOPIC = ((scamconfig.get("ntfy_topic") if scamconfig else "") or os.environ.get("NTFY_TOPIC", "")).strip()


def _parse_after(s):
    if not s:
        return None
    import datetime as dt
    try:
        return int(dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
    except Exception:
        return None


def _save_and_render(t):
    t.save(MAP)
    with open(HTML, "w", encoding="utf-8") as f:
        f.write(render_html(t.state()))


def _log(line):
    import datetime as dt
    stamp = f"[{dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {line}"
    print(stamp, flush=True)
    try:
        with open(EVENTLOG, "a", encoding="utf-8") as f:
            f.write(stamp + "\n")
    except Exception:
        pass


def phone(title, msg, actions=None, critical=True, key=None):
    try:
        import alerts
        alerts.send(f"[MULTICHAIN] {title}", msg, critical=critical, actions=actions, key=key)
        return
    except ImportError:
        pass
    if not NTFY_TOPIC:
        return
    import urllib.request
    try:
        payload = {"topic": NTFY_TOPIC, "title": f"[MULTICHAIN] {title}", "message": msg,
                   "priority": 5, "tags": ["globe_with_meridians"]}
        if actions:
            payload["actions"] = [{"action": "view", "label": l, "url": u, "clear": True}
                                  for (l, u) in actions[:3]]
        req = urllib.request.Request("https://ntfy.sh/", data=json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception as ex:
        _log(f"(phone alert failed: {ex})")


def _summarize(t):
    s = t.summary()
    return (f"{s['total_nodes']} nodes across {len(s['chains'])} chain(s) "
            f"({', '.join(s['chains']) or '—'}); {s['exchanges']} exchange, {s['bridges']} bridge, "
            f"{s['mixers']} mixer; {s['open_handoffs']} open handoff(s); "
            f"{s['freeze_opportunities']} freeze opportunity(ies).")


def cmd_trace(a):
    entities.refresh(log=_log)
    t = Tracer.load(MAP, max_nodes=a.max_nodes, max_depth=a.max_depth, cross_evm=not a.no_cross_evm, log=_log)
    t.trace([(a.chain, a.address, _parse_after(a.after))])
    _save_and_render(t)
    drafts = report.write_all(t.state(), case=report.load_case(a.victim))
    print(_summarize(t))
    print(f"Detailed log: {os.path.abspath(HTML)}")
    print(f"Reports ({len(drafts)}): {os.path.abspath('mc_reports')}  (review before sending)")


def cmd_resume(a):
    t = Tracer.load(MAP, max_nodes=a.max_nodes, max_depth=a.max_depth)
    if not t.resolve_handoff(a.handoff, a.to_chain, a.to_address, _parse_after(a.after)):
        raise SystemExit(f"No handoff '{a.handoff}'. Run 'handoffs' to list them.")
    t.trace([])  # resolved handoff is re-seeded automatically
    _save_and_render(t)
    report.write_all(t.state(), case=report.load_case(a.victim))
    print(f"Resumed {a.handoff} -> {a.to_chain}:{a.to_address}")
    print(_summarize(t))


def cmd_map(a):
    t = Tracer.load(MAP)
    with open(HTML, "w", encoding="utf-8") as f:
        f.write(render_html(t.state()))
    print(f"{os.path.abspath(HTML)}")
    print(_summarize(t))


def cmd_report(a):
    t = Tracer.load(MAP)
    drafts = report.write_all(t.state(), case=report.load_case(a.victim))
    print(f"{len(drafts)} report(s) in {os.path.abspath('mc_reports')}")


def cmd_handoffs(a):
    t = Tracer.load(MAP)
    if not t.handoffs:
        print("No handoffs yet.")
        return
    for h in t.handoffs:
        rt = h.get("resolved_to")
        where = f"-> {rt['chain']}:{rt['address']}" if rt else "(open)"
        print(f"  {h['id']}  [{h['status']}]  {h['chain']}:{h['address']}  via {h.get('service')}  {where}")


def _import_xrpl(t, path="network_map.json"):
    """Turn each swap/bridge endpoint in the XRPL watcher's map into an open
    handoff here. Idempotent. Returns how many new handoffs were added."""
    if not os.path.exists(path):
        return 0
    try:
        with open(path, encoding="utf-8") as f:
            xm = json.load(f)
    except Exception:
        return 0
    added = 0
    for ep in xm.get("endpoints", []):
        if not ep.get("is_swap"):
            continue
        a_ = ep["address"]
        if any(h["chain"] == "xrpl" and h["address"] == a_ for h in t.handoffs):
            continue
        t.handoffs.append({"id": f"h{len(t.handoffs)+1}", "chain": "xrpl", "address": a_,
                           "service": ep.get("swap_name") or ep.get("label"), "status": "open",
                           "depth": ep.get("depth", 0), "resolved_to": None,
                           "note": "funds left XRPL via this swap/bridge; resume when destination is known"})
        added += 1
    return added


def cmd_importxrpl(a):
    """Read the XRPL watcher's map and turn each swap/bridge endpoint into an
    open handoff here, so a cross-chain crossing becomes a lead to resume."""
    if not os.path.exists(a.xrpl_map):
        raise SystemExit(f"{a.xrpl_map} not found (run this from the scam-watcher folder).")
    t = Tracer.load(MAP)
    added = _import_xrpl(t, a.xrpl_map)
    _save_and_render(t)
    print(f"Imported {added} XRPL swap handoff(s). Run 'handoffs' to list, then 'resume' when you learn the destination.")


def cmd_watch(a):
    entities.refresh(log=_log)
    print("Multi-chain tracer (automated).", flush=True)
    print("Phone push:", f"ON (ntfy '{NTFY_TOPIC}')" if NTFY_TOPIC else "off (set NTFY_TOPIC)", flush=True)
    case = report.load_case(a.victim)
    while True:
        try:
            entities.refresh(log=_log)  # only hits network when stale
            t = Tracer.load(MAP, max_nodes=a.max_nodes, max_depth=a.max_depth, cross_evm=not a.no_cross_evm, log=_log)
            before = (len(t.nodes), len(t.endpoints), len(t.freeze_ops))
            imported = _import_xrpl(t, getattr(a, "xrpl_map", "network_map.json"))  # auto-pick-up XRPL swap leads
            if imported:
                _log(f"imported {imported} new XRPL swap handoff(s); resolve with 'resume' once destination is known")
            # re-trace every original seed and every resolved handoff
            t.trace([tuple(s) for s in t.seeds])
            after = (len(t.nodes), len(t.endpoints), len(t.freeze_ops))
            _save_and_render(t)
            drafts = report.write_all(t.state(), case=case)
            if after != before:
                new_nodes = after[0] - before[0]
                new_eps = after[1] - before[1]
                new_fz = after[2] - before[2]
                _log(f"CHANGE: +{new_nodes} nodes, +{new_eps} endpoints, +{new_fz} freeze ops. "
                     f"{len(drafts)} report(s) drafted.")
                acts = None
                ops = t.state().get("freeze_ops", [])
                if ops:
                    acts = [report.action_for(ops[-1], case)]
                phone("Trace advanced - new freeze opportunity",
                      f"The cross-chain trace grew: +{new_eps} endpoint(s), +{new_fz} freeze op(s). "
                      f"Reports drafted in mc_reports\\. Tap to act.", actions=acts)
            else:
                _log("no change")
        except Exception as ex:
            _log(f"cycle error: {ex!r}")
        time.sleep(max(60, a.interval))


def main():
    p = argparse.ArgumentParser(prog="multichain", description="Trace stolen crypto across chains; draft freeze reports.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--max-nodes", type=int, default=300)
        sp.add_argument("--max-depth", type=int, default=8)
        sp.add_argument("--no-cross-evm", action="store_true", help="Don't probe the same address across EVM chains")
        sp.add_argument("--victim", default="victim.json")

    tr = sub.add_parser("trace", help="Trace forward from a seed address")
    tr.add_argument("--chain", required=True)
    tr.add_argument("--address", required=True)
    tr.add_argument("--after", help="ISO time; only follow funds moving at/after this")
    common(tr)

    rs = sub.add_parser("resume", help="Resolve a handoff and continue the trace on the next chain")
    rs.add_argument("--handoff", required=True)
    rs.add_argument("--to-chain", required=True)
    rs.add_argument("--to-address", required=True)
    rs.add_argument("--after")
    common(rs)

    mp = sub.add_parser("map", help="Re-render the detailed HTML log from the saved map")
    rp = sub.add_parser("report", help="Regenerate all freeze/takedown report drafts")
    rp.add_argument("--victim", default="victim.json")
    sub.add_parser("handoffs", help="List cross-chain handoff leads")
    ix = sub.add_parser("importxrpl", help="Import swap/bridge leads from the XRPL watcher's map")
    ix.add_argument("--xrpl-map", default="network_map.json")

    w = sub.add_parser("watch", help="Automated: run forever, re-trace, draft reports, phone-alert on changes")
    w.add_argument("--interval", type=int, default=900, help="Seconds between cycles (default 900)")
    w.add_argument("--xrpl-map", default="network_map.json", help="XRPL watcher map to auto-import swap leads from")
    common(w)

    a = p.parse_args()
    {"trace": cmd_trace, "resume": cmd_resume, "map": cmd_map, "report": cmd_report,
     "handoffs": cmd_handoffs, "importxrpl": cmd_importxrpl, "watch": cmd_watch}[a.cmd](a)


if __name__ == "__main__":
    main()
