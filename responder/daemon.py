"""Responder service (the Desk supervises this): keeps freeze kits current and
runs the early-warning jobs on a schedule.

  every 1 min   rebuild freeze kits; NEW cash-out of your funds -> critical alert
  every 15 min  issued-token scan (RLUSD etc.) -> critical alert on a freezable holding
  every 30 min  incident feeds, exchange status, scam radar rotation
  every 6 h     risk signals

    python -m responder.daemon [--port 8787]
"""
import argparse
import time
import traceback
from datetime import datetime

DESK = "http://127.0.0.1:{port}"


def _log(msg):
    print(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}", flush=True)


def _alert(title, msg, key, critical=True, url=None):
    try:
        import alerts
        acts = [("SEAL 911 (Telegram)", "https://t.me/seal_911_bot")] if critical else []
        if url:
            acts.append(("Submission Center (PC)", url))
        alerts.send(title, msg, critical=critical, key=key, actions=acts or None)
    except Exception as e:
        _log(f"(alert failed: {e})")


def _heartbeat():
    try:
        with open("responder.heartbeat", "w", encoding="utf-8") as f:
            f.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    except Exception:
        pass


def job_kits(desk):
    from freezekit import kit
    r = kit.build(log=_log)
    for tid in r["new"]:
        t = r["targets"][tid]
        ent = t["entry"]
        yours = [d for d in t["deposits"] if d["yours"]]
        tags = ", ".join(sorted({str(d["tag"]) for d in yours}))
        dl = (f" {ent['name']} needs a law-enforcement request within {ent['deadline_hours']}h of your victim report."
              if ent.get("deadline_hours") else "")
        _alert(f"FREEZE PACKET READY: {ent.get('name', 'unidentified exchange')}",
               f"Your funds reached {ent.get('name', 'an exchange')} (tag {tags}). The freeze kit is built.{dl}\n"
               f"1) SEAL 911 now  2) victim report  3) officer packet to police.",
               key=f"kit:{tid}", url=f"{desk}/submit#{tid}")


def job_tokens(desk, seen):
    """Alert ONLY for tokens from a known, accountable issuer (RLUSD, ...) that can
    still be frozen / clawed back. Other holdings are listed in the Submission
    Center without alerts (meme-token issuers rarely act)."""
    import json as _json
    from freezekit import xrpl_tokens
    try:
        with open("token_alerts_sent.json", encoding="utf-8") as f:
            seen |= set(_json.load(f))
    except Exception:
        pass
    r = xrpl_tokens.scan(xrpl_tokens.network_wallets(), log=_log)
    for h in r["holdings"]:
        if not h.get("issuer_name") or h["frozen_by_issuer"] or not (h["freezable"] or h["clawback"]) \
                or h["balance"] < 50:   # dust isn't worth a freeze request
            continue
        k = f"tok:{h['wallet']}:{h['issuer']}:{h['currency']}"
        if k in seen:
            continue
        seen.add(k)
        _alert(f"FREEZABLE {h['currency']} in scam network",
               f"{h['balance']:,.2f} {h['currency']} held by {h['wallet']}. {h['issuer_name']} "
               f"can {'claw back' if h['clawback'] else 'freeze'} it. Request is in the Submission Center.",
               key=k, url=f"{desk}/submit#issuers")
    try:
        with open("token_alerts_sent.json", "w", encoding="utf-8") as f:
            _json.dump(sorted(seen), f)
    except Exception:
        pass


def job_feeds_status_radar():
    from . import incident, status, radar, intel
    intel.refresh(log=_log)          # only re-downloads once a day
    incident.pull_feeds(log=_log)
    status.check(log=_log)
    new = radar.rotate(log=_log)
    if new:
        _alert("Scam radar: new lookalike domains",
               "New certificates for: " + ", ".join(new[:6]) + ("" if len(new) <= 6 else f" (+{len(new)-6})"),
               key=f"radar:{new[0]}", critical=False)


def job_attribution():
    from scam_investigator import attribution, operators
    attribution.run(log=_log)
    operators.run(log=_log)


def job_risk():
    from . import risk
    risk.scan(log=_log)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8787)
    a = ap.parse_args()
    desk = DESK.format(port=a.port)
    _log("Responder running: freeze kits, token freeze scan, incident feeds, radar, risk.")
    sched = [(60, job_kits, (desk,)), (900, job_tokens, (desk, set())),
             (1800, job_feeds_status_radar, ()), (3600, job_attribution, ()), (21600, job_risk, ())]
    last = {fn.__name__: 0 for _, fn, _ in sched}
    last["job_tokens"] = time.time() - 840       # first token scan ~1 min after start
    last["job_feeds_status_radar"] = time.time() - 1680
    last["job_risk"] = time.time() - 21300
    last["job_attribution"] = time.time() - 3480     # first pass ~2 min after start
    while True:
        for every, fn, args in sched:
            if time.time() - last[fn.__name__] >= every:
                last[fn.__name__] = time.time()
                try:
                    fn(*args)
                except Exception as e:
                    _log(f"{fn.__name__} error: {e!r}")
                    traceback.print_exc()
        _heartbeat()
        time.sleep(10)


if __name__ == "__main__":
    main()
