"""Perpetual scam-network watcher.

Runs forever. Seeds from the scam wallet, back-maps the stolen funds forward
in time (see netmap.py), then subscribes live to every non-exchange wallet in
the network. Whenever a watched wallet sends funds:

  * to a NEW private wallet  -> that wallet is added to the live watch set and
                               the network map (the network auto-expands), and
                               a phone alert fires.
  * to an exchange / custodial deposit -> a CASH-OUT alert fires (this is the
                               actionable moment: contact that exchange with the
                               tx hash and destination tag to request a freeze /
                               records). Exchanges are endpoints; we do not watch
                               past them.

State persists to disk (network_map.json) so the map keeps growing across
restarts. Every event is appended to netwatch_events.log, and the human-
readable map (network_map.html) is rewritten after every change -- that is the
detailed log, available on demand at any time.

Phone alerts via ntfy: set NTFY_TOPIC in the environment.
Requires: pip install websockets
"""
import asyncio
import json
import os
import urllib.request
from datetime import datetime, timezone

import websockets

from . import netmap, netreport
from .ledger import SERVERS, Ledger, xrp, ripple_time
from .trace import load_labels

try:
    import scamconfig
except Exception:
    scamconfig = None

MAP_JSON = "network_map.json"
MAP_HTML = "network_map.html"
EVENT_LOG = "netwatch_events.log"
HEARTBEAT = "netwatch.heartbeat"

SCAM_WALLET = (scamconfig.scam_wallet() if scamconfig else "") or os.environ.get("SCAM_WALLET", "").strip()
NTFY_TOPIC = ((scamconfig.get("ntfy_topic") if scamconfig else "") or os.environ.get("NTFY_TOPIC", "")).strip()
MAX_NODES = 400
MIN_XRP = 25


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_event(line):
    stamp = f"[{now()}] {line}"
    print(stamp, flush=True)
    try:
        with open(EVENT_LOG, "a", encoding="utf-8") as f:
            f.write(stamp + "\n")
    except Exception:
        pass


def phone(title, msg, actions=None, critical=False, key=None):
    """Send a phone alert through the reliable outbox (retries on failure)."""
    try:
        import alerts
        alerts.send(f"[NETWORK] {title}", msg, critical=critical, actions=actions, key=key)
        return
    except ImportError:
        pass
    if not NTFY_TOPIC:
        return
    try:
        payload = {"topic": NTFY_TOPIC, "title": f"[NETWORK] {title}", "message": msg,
                   "priority": 5, "tags": ["rotating_light"]}
        if actions:
            payload["actions"] = [{"action": "view", "label": lbl, "url": url, "clear": True}
                                  for (lbl, url) in actions[:3]]
        req = urllib.request.Request("https://ntfy.sh/", data=json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        log_event(f"(phone alert failed: {e})")


def load_map():
    if os.path.exists(MAP_JSON):
        try:
            with open(MAP_JSON, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None


def save_map(net):
    net["generated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    netmap.save(net, MAP_JSON)
    try:
        with open(MAP_HTML, "w", encoding="utf-8") as f:
            f.write(netmap.render_html(net))
    except Exception as e:
        log_event(f"(map html write failed: {e})")


async def backfill():
    log_event("Back-mapping the network (stolen funds, time-forward)...")
    net = await netmap.map_network(SCAM_WALLET, max_nodes=MAX_NODES, min_xrp=MIN_XRP)
    save_map(net)
    s = net["summary"]
    log_event(f"Map: {s['total_nodes']} nodes, {s['hop_wallets']} hop wallets, "
              f"{s['cash_out_points']} cash-out points, {s['edges']} flows.")
    for a in net["watchlist"]:
        if a != SCAM_WALLET:
            log_event(f"  watching hop: {a}")
    for ep in net["endpoints"]:
        log_event(f"  cash-out: {ep['xrp']:.2f} XRP -> {ep.get('label') or ep['address']} "
                  f"(tag {ep.get('destination_tag')}) {ep['time']}")
    # Draft freeze requests for any cash-outs found during back-mapping.
    try:
        drafts = netreport.write_all_from_map(net, case=netreport.load_case())
        if drafts:
            log_event(f"Drafted {len(drafts)} freeze request(s) in network_reports\\ (review and send).")
    except Exception as ex:
        log_event(f"(report drafting failed: {ex})")
    return net


def _refresh_summary(net):
    hop_wallets = [a for a, n in net["nodes"].items() if not n.get("is_exchange") and a != net["root"]]
    net["summary"] = {"total_nodes": len(net["nodes"]), "hop_wallets": len(hop_wallets),
                      "cash_out_points": len({e["address"] for e in net.get("endpoints", [])}),
                      "edges": len(net["edges"])}


async def _process(net, tx, meta, seen):
    """Record a live payment from a watched wallet; expand the map; alert.
    Returns True if the map changed."""
    if tx.get("TransactionType") != "Payment" or meta.get("TransactionResult") != "tesSUCCESS":
        return False
    sender = tx.get("Account")
    node = net["nodes"].get(sender)
    if not node or node.get("is_exchange"):
        return False
    h = tx.get("hash")
    if not h or h in seen:
        return False
    amt = xrp(meta.get("delivered_amount", tx.get("Amount")))
    if amt is None or amt < MIN_XRP:
        return False
    dest = tx.get("Destination")
    tag = tx.get("DestinationTag")
    seen.add(h)

    labels = load_labels()
    async with Ledger() as L:
        dn = await netmap._describe(L, dest, labels, True)
    if dest not in net["nodes"]:
        net["nodes"][dest] = dn
    net["edges"].append({"hash": h, "time": ripple_time(tx.get("date")), "epoch": None,
                         "from": sender, "to": dest, "destination_tag": tag, "xrp": amt,
                         "depth": (node.get("depth", 0) or 0) + 1})

    if dn["is_exchange"]:
        is_swap = dn.get("is_swap")
        net["nodes"][dest]["role"] = ("bridge / swap (funds may leave XRPL)" if is_swap
                                      else "exchange / cash-out point")
        ep = {"address": dest, "label": dn["label"], "destination_tag": tag,
              "xrp": amt, "hash": h, "time": ripple_time(tx.get("date")),
              "is_swap": is_swap, "swap_name": dn.get("swap_name")}
        net.setdefault("endpoints", []).append(ep)
        # Auto-DRAFT (never auto-send) a freeze/preservation report for this endpoint.
        report_path = None
        try:
            report_path = netreport.write_report(ep, net["root"], case=netreport.load_case())
        except Exception as ex:
            log_event(f"(report draft failed: {ex})")
        # Phone actions that work FROM THE PHONE: SEAL 911 (fastest freeze route),
        # the transaction, and the Desk's Submission Center (on your PC).
        actions = [("SEAL 911 (Telegram)", "https://t.me/seal_911_bot"),
                   ("View transaction", f"https://livenet.xrpl.org/transactions/{h}"),
                   ("Submission Center (PC)", "http://127.0.0.1:8787/submit")]
        if is_swap:
            name = dn.get("swap_name") or dn.get("label") or dest
            log_event(f"BRIDGE/SWAP: {amt:.2f} XRP from {sender[:10]}... -> {name} tag {tag}  "
                      f"-- funds may be LEAVING XRPL  tx {h}"
                      + (f"  | freeze-request draft: {report_path}" if report_path else ""))
            phone("⚠ BRIDGE/SWAP - funds may be leaving XRPL",
                  f"{amt:,.0f} XRP reached {name} (tag {tag}). Funds may be converting to another "
                  f"asset/chain - act fast. 1) SEAL 911 now 2) Submission Center on your PC has the freeze kit.",
                  actions=actions, critical=True, key=h)
        else:
            log_event(f"CASH-OUT: {amt:.2f} XRP from {sender[:10]}... -> {dn.get('label') or dest} tag {tag}  tx {h}"
                      + (f"  | freeze-request draft: {report_path}" if report_path else ""))
            phone("CASH-OUT -> freeze request ready",
                  f"{amt:,.0f} XRP reached {dn.get('label') or dest} (tag {tag}). 1) SEAL 911 now "
                  f"2) Submission Center on your PC has the freeze kit + officer packet.", actions=actions,
                  critical=True, key=h)
    else:
        net["nodes"][dest]["role"] = "hop wallet"
        if dest not in net["watchlist"]:
            net["watchlist"].append(dest)
        log_event(f"NETWORK EXPANDED: {amt:.2f} XRP from {sender[:10]}... -> NEW hop {dest}  tx {h}")
        phone("Scam network expanded",
              f"{amt:,.0f} XRP moved to a new wallet now being watched: {dest}. tx {h}", key=h)
    _refresh_summary(net)
    return True


async def watch():
    net = load_map()
    if net is None:
        net = await backfill()
    else:
        log_event(f"Loaded existing map: {net['summary']['total_nodes']} nodes. Refreshing...")
        net = await backfill()  # refresh to catch anything since last run

    seen = {e["hash"] for e in net.get("edges", [])}

    def watch_set():
        return [a for a, n in net["nodes"].items() if not n.get("is_exchange")]

    attempt = 0
    while True:
        server = SERVERS[attempt % len(SERVERS)]
        attempt += 1
        try:
            async with websockets.connect(server, ping_interval=20, ping_timeout=20, max_size=2**24) as ws:
                subs = set(watch_set())
                await ws.send(json.dumps({"id": "sub", "command": "subscribe", "accounts": list(subs),
                                          "streams": ["ledger"]}))
                log_event(f"Live on {server}. Watching {len(subs)} wallet(s) across the network.")
                attempt = 0
                while True:
                    try:
                        raw = await asyncio.wait_for(ws.recv(), timeout=90)
                    except asyncio.TimeoutError:
                        raise ConnectionError("no ledger for 90s - subscription stale, reconnecting")
                    msg = json.loads(raw)
                    if msg.get("type") == "ledgerClosed":
                        # heartbeat: proves the subscription is actually receiving
                        try:
                            with open(HEARTBEAT, "w", encoding="utf-8") as hb:
                                hb.write(json.dumps({"time": now(), "ledger": msg.get("ledger_index"),
                                                     "watching": len(subs)}))
                        except Exception:
                            pass
                        continue
                    if msg.get("type") != "transaction" or not msg.get("validated", False):
                        continue
                    tx = dict(msg.get("tx_json") or msg.get("transaction") or {})
                    tx["hash"] = msg.get("hash", tx.get("hash"))
                    if await _process(net, tx, msg.get("meta", {}), seen):
                        save_map(net)
                        new = set(watch_set()) - subs
                        if new:
                            await ws.send(json.dumps({"id": "sub2", "command": "subscribe", "accounts": list(new)}))
                            subs |= new
                            log_event(f"Now watching {len(subs)} wallet(s).")
        except Exception as e:
            log_event(f"Connection issue on {server}: {e!r} - reconnecting in 5s")
            await asyncio.sleep(5)


def main():
    print("XRPL scam-NETWORK watcher (perpetual)", flush=True)
    if not SCAM_WALLET:
        print("No scam wallet configured. Set \"scam_wallet\" in config.json (or the SCAM_WALLET\n"
              "environment variable) to the address that received the stolen funds, then run again.",
              flush=True)
        return
    print("Root scam wallet:", SCAM_WALLET, flush=True)
    print("Phone push:", f"ON (ntfy '{NTFY_TOPIC}')" if NTFY_TOPIC else "off (set ntfy_topic in config.json)", flush=True)
    try:
        asyncio.run(watch())
    except KeyboardInterrupt:
        print("stopped")


if __name__ == "__main__":
    main()
