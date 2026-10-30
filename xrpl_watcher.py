"""
scam_wallet_watcher.py — live XRPL watcher for scam wallets.

Watches one or more XRP Ledger addresses in real time and alerts the moment
XRP LEAVES a watched wallet, recording where it went and whether a destination
tag was used (a tag usually means the funds hit an exchange deposit account,
which is the one point where an exchange can freeze them).

Alerts: console + log file + Windows beep/popup + optional phone push (ntfy).
Requires: Python 3.9+, `pip install websockets`

Run (Windows):
    python scam_wallet_watcher.py
Optional phone push (install the free "ntfy" app, subscribe to a hard-to-guess topic):
    set NTFY_TOPIC=your-secret-topic-name
    python scam_wallet_watcher.py
"""

import asyncio
import csv
import json
import os
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone

import websockets

try:
    import scamconfig
except Exception:   # allow running the file directly from its own folder
    import importlib.util as _ilu
    _spec = _ilu.spec_from_file_location("scamconfig",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "scamconfig.py"))
    scamconfig = _ilu.module_from_spec(_spec); _spec.loader.exec_module(scamconfig)

try:
    import alerts
except Exception:
    alerts = None

# ---------------------------------------------------------------- config ----
# Addresses to watch come from config.json -> "watched_wallets".
WATCHED = dict(scamconfig.get("watched_wallets") or {})
# Only the wallets YOU configured push to your phone. Hops added by
# follow-the-money are logged here and watched properly (time-forward) by the
# Network watcher, so pushing them too would just burn the alert quota.
ORIGINAL = set(WATCHED)
MAX_AUTO_HOPS = 25
# Incident mode (responder/incident.py): attacker wallets pasted by the user.
INCIDENT = set()


def _load_incident():
    """Merge incident-mode XRPL addresses into the watch list. Returns new ones."""
    try:
        from responder import incident
        lst = incident.xrpl_watch_list()
    except Exception:
        return set()
    new = {a for a in lst if a not in WATCHED}
    for a in new:
        WATCHED[a] = lst[a]
    INCIDENT.update(lst)
    return new


_load_incident()

# Public XRPL WebSocket servers, tried in order on (re)connect.
SERVERS = scamconfig.get("servers") or [
    "wss://xrplcluster.com",
    "wss://s1.ripple.com",
    "wss://s2.ripple.com",
]

LOG_CSV = "scam_wallet_activity.csv"
NTFY_TOPIC = (scamconfig.get("ntfy_topic") or "").strip()   # empty = phone push off
DROPS = 1_000_000
RIPPLE_EPOCH = 946684800  # seconds between 1970-01-01 and 2000-01-01

# ------------------------------------------------------------- helpers ------

def now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def ripple_time(t) -> str:
    if t is None:
        return ""
    return datetime.fromtimestamp(t + RIPPLE_EPOCH, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def fmt_amount(amount) -> str:
    if amount is None:
        return "?"
    if isinstance(amount, str):  # XRP in drops
        return f"{int(amount) / DROPS:,.6f} XRP"
    if isinstance(amount, dict):  # issued token / MPT
        cur = amount.get("currency") or amount.get("mpt_issuance_id", "token")
        return f"{amount.get('value')} {cur}"
    return str(amount)


def log_row(row: dict) -> None:
    new = not os.path.exists(LOG_CSV)
    with open(LOG_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(row.keys()))
        if new:
            w.writeheader()
        w.writerow(row)


def desktop_alert(title: str, msg: str) -> None:
    """Beep + popup on Windows; harmless no-op elsewhere."""
    if sys.platform != "win32":
        print("\a", end="")
        return
    try:
        import winsound
        for _ in range(3):
            winsound.Beep(1200, 300)
    except Exception:
        pass
    try:
        import ctypes
        # Popup in a thread so it never blocks the watcher.
        threading.Thread(
            target=lambda: ctypes.windll.user32.MessageBoxW(0, msg, title, 0x40030),
            daemon=True,
        ).start()
    except Exception:
        pass


def phone_alert(title: str, msg: str, critical: bool = False, key: str = None) -> None:
    if alerts is not None:
        alerts.send(title, msg, critical=critical, key=key)
        return
    if not NTFY_TOPIC:
        return
    try:
        req = urllib.request.Request(
            f"https://ntfy.sh/{NTFY_TOPIC}",
            data=msg.encode("utf-8"),
            headers={"Title": title, "Priority": "urgent", "Tags": "rotating_light"},
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"[{now()}] phone push failed: {e}")


def alert(title: str, msg: str, push: bool = True, critical: bool = False, key: str = None) -> None:
    print("\n" + "!" * 70 + f"\n{title}\n{msg}\n" + "!" * 70 + "\n")
    if push:
        desktop_alert(title, msg)
        phone_alert(title, msg, critical=critical, key=key)


# ------------------------------------------------------- classification -----

def classify(tx: dict, meta: dict, validated: bool):
    """Return (direction, watched_addr) for a tx touching a watched wallet."""
    sender = tx.get("Account")
    dest = tx.get("Destination")
    if sender in WATCHED:
        return "OUTGOING", sender
    if dest in WATCHED:
        return "INCOMING", dest
    return "OTHER", next((a for a in WATCHED if a in json.dumps(meta)), None)


def handle_tx(tx: dict, meta: dict, validated: bool, source: str) -> None:
    if not validated:
        return  # only act on final, validated ledger results
    direction, addr = classify(tx, meta, validated)
    if addr is None:
        return

    ttype = tx.get("TransactionType")
    result = meta.get("TransactionResult", "?")
    delivered = meta.get("delivered_amount", tx.get("Amount"))
    dest = tx.get("Destination", "")
    tag = tx.get("DestinationTag")
    tx_hash = tx.get("hash", "")
    when = ripple_time(tx.get("date"))

    row = {
        "seen_at": now(), "ledger_time": when, "direction": direction,
        "type": ttype, "result": result, "watched": addr,
        "from": tx.get("Account", ""), "to": dest,
        "destination_tag": "" if tag is None else tag,
        "amount": fmt_amount(delivered), "hash": tx_hash, "source": source,
    }
    log_row(row)

    label = WATCHED[addr]
    if direction == "OUTGOING" and result == "tesSUCCESS":
        exch_hint = (f"Destination tag {tag} — LIKELY AN EXCHANGE DEPOSIT. "
                     "Contact that exchange + update IC3 NOW."
                     if tag is not None else
                     "No destination tag — probably another private wallet (scammer hop). "
                     "Watch that address next.")
        alert(
            "SCAM WALLET MOVED FUNDS",
            f"{label}\n{fmt_amount(delivered)} sent\nTo: {dest}\n{exch_hint}\n"
            f"Tx: {tx_hash}\nhttps://livenet.xrpl.org/transactions/{tx_hash}",
            # your own wallets push every move; incident (attacker) wallets push when
            # funds hit an exchange (tag) -- that is the freeze moment
            push=addr in ORIGINAL or (addr in INCIDENT and tag is not None),
            critical=tag is not None, key=tx_hash,
        )
        if dest and dest not in WATCHED and tag is None and len(WATCHED) - len(ORIGINAL) < MAX_AUTO_HOPS:
            # Follow the money: auto-add the next hop (takes effect on next subscribe).
            WATCHED[dest] = f"next hop from {addr[:8]}…"
            print(f"[{now()}] Added {dest} to watch list (follow-the-money).")
    elif direction == "OUTGOING":
        print(f"[{now()}] Outgoing {ttype} attempt FAILED ({result}) — {tx_hash}")
    elif direction == "INCOMING":
        print(f"[{now()}] New victim payment in: {fmt_amount(delivered)} from {tx.get('Account')} ({when})")
    else:
        alert("SCAM WALLET ACTIVITY", f"{label}\n{ttype} ({result}) touched the wallet.\nTx: {tx_hash}",
              push=addr in ORIGINAL, key=tx_hash)


# ----------------------------------------------------------- main loop ------

async def rpc(ws, req: dict) -> dict:
    await ws.send(json.dumps(req))
    while True:
        msg = json.loads(await ws.recv())
        if msg.get("id") == req.get("id"):
            return msg


async def snapshot(ws, seen: set) -> None:
    """Balance + recent history, so nothing is missed while disconnected."""
    for i, addr in enumerate(list(WATCHED)):
        info = await rpc(ws, {"id": f"info{i}", "command": "account_info",
                              "account": addr, "ledger_index": "validated"})
        bal = info.get("result", {}).get("account_data", {}).get("Balance")
        print(f"[{now()}] {addr}  balance: {fmt_amount(bal) if bal else 'not found'}")

        hist = await rpc(ws, {"id": f"tx{i}", "command": "account_tx",
                              "account": addr, "limit": 20, "forward": False})
        for t in reversed(hist.get("result", {}).get("transactions", [])):
            tx = t.get("tx_json") or t.get("tx", {})
            tx = {**tx, "hash": t.get("hash", tx.get("hash"))}
            if tx["hash"] in seen:
                continue
            seen.add(tx["hash"])
            if tx.get("Account") == addr:  # any outgoing in history is worth flagging
                handle_tx(tx, t.get("meta", {}), t.get("validated", True), "history")


async def watch() -> None:
    seen: set = set()
    attempt = 0
    while True:
        server = SERVERS[attempt % len(SERVERS)]
        attempt += 1
        try:
            async with websockets.connect(server, ping_interval=20, ping_timeout=20) as ws:
                print(f"[{now()}] Connected to {server}")
                await snapshot(ws, seen)
                subscribed = set(WATCHED)
                await rpc(ws, {"id": "sub", "command": "subscribe", "accounts": list(subscribed),
                               "streams": ["ledger"]})   # ledger ticks keep the loop (and incident pickup) alive
                print(f"[{now()}] Watching {len(subscribed)} address(es) live. Ctrl+C to stop.\n")
                attempt = 0
                last_inc = time.time()
                async for raw in ws:
                    if time.time() - last_inc > 60:   # pick up newly pasted incident addresses
                        last_inc = time.time()
                        if _load_incident():
                            new = set(WATCHED) - subscribed
                            if new:
                                await ws.send(json.dumps({"id": "subinc", "command": "subscribe", "accounts": list(new)}))
                                subscribed |= new
                                print(f"[{now()}] Incident mode: now watching {len(new)} more address(es).")
                    msg = json.loads(raw)
                    if msg.get("type") != "transaction":
                        continue
                    tx = msg.get("tx_json") or msg.get("transaction", {})
                    tx = {**tx, "hash": msg.get("hash", tx.get("hash"))}
                    if tx["hash"] in seen:
                        continue
                    seen.add(tx["hash"])
                    handle_tx(tx, msg.get("meta", {}), msg.get("validated", False), "live")
                    new = set(WATCHED) - subscribed
                    if new:  # follow-the-money additions
                        await ws.send(json.dumps({"id": "sub2", "command": "subscribe", "accounts": list(new)}))
                        subscribed |= new
        except Exception as e:
            print(f"[{now()}] Connection issue on {server}: {e!r} — reconnecting in 5s")
            await asyncio.sleep(5)


if __name__ == "__main__":
    print("XRPL scam wallet watcher")
    if not WATCHED:
        print("No wallets to watch. Copy config.example.json to config.json and add at least one\n"
              "address under \"watched_wallets\", then run again.")
        sys.exit(1)
    print("Watching:", ", ".join(WATCHED))
    print("Phone push:", f"ON (ntfy topic '{NTFY_TOPIC}')" if NTFY_TOPIC else "off (set ntfy_topic in config.json)")
    try:
        asyncio.run(watch())
    except KeyboardInterrupt:
        print("\nStopped. Activity log:", os.path.abspath(LOG_CSV))
