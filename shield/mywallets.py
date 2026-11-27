"""My wallets: watch YOUR OWN wallet addresses and alert the moment money leaves one.

Added from the hardware wallet check ("Watch this wallet"). Only public addresses are kept: a recovery phrase
or any run of words is refused before anything is saved. The watcher uses the Desk's existing chain code
(multichain adapters; shield.xrpl for the XRP Ledger) and the Desk's usual alerts. It can't stop a drain;
it tells you within minutes, which matters for freeze requests.
"""
import json
import os
import re
import time
from datetime import datetime

import securestore

CFG = "config.json"
STATE = "mywallets_state.json"
B58 = "1-9A-HJ-NP-Za-km-z"
CHAINS = {   # key: (label, address pattern)
    "xrpl": ("XRP Ledger", rf"r[{B58}]{{24,34}}"),
    "bitcoin": ("Bitcoin", rf"(bc1[0-9a-z]{{25,62}}|[13][{B58}]{{25,34}})"),
    "ethereum": ("Ethereum", r"0x[0-9a-fA-F]{40}"),
    "bsc": ("BNB Smart Chain", r"0x[0-9a-fA-F]{40}"),
    "polygon": ("Polygon", r"0x[0-9a-fA-F]{40}"),
    "base": ("Base", r"0x[0-9a-fA-F]{40}"),
    "arbitrum": ("Arbitrum One", r"0x[0-9a-fA-F]{40}"),
    "optimism": ("Optimism", r"0x[0-9a-fA-F]{40}"),
    "avalanche": ("Avalanche C-Chain", r"0x[0-9a-fA-F]{40}"),
    "tron": ("Tron", rf"T[{B58}]{{33}}"),
    "solana": ("Solana", rf"[{B58}]{{32,44}}"),
}
XRPL_RPC = None        # test hook: f(method, params) -> dict
ADAPTER = None         # test hook: f(chain) -> object with outgoing(address, after_epoch) and available()


def _cfg():
    try:
        with open(CFG, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return {}


def wallets():
    return list(_cfg().get("my_wallets") or [])


def _save(ws):
    cfg = securestore.reveal_config(_cfg())
    cfg["my_wallets"] = ws
    securestore.save(cfg, CFG)


def valid(address, chain):
    if chain not in CHAINS:
        return False
    return bool(re.fullmatch(CHAINS[chain][1], (address or "").strip()))


def guess_chain(address):
    a = (address or "").strip()
    for k in ("xrpl", "ethereum", "tron", "bitcoin", "solana"):
        if re.fullmatch(CHAINS[k][1], a):
            return k
    return None


def add(address, chain, label=""):
    """Returns None or why not. Never stores anything that isn't one public address."""
    from deskui import seedguard
    a = (address or "").strip()
    if seedguard.looks_like_seed(a) or seedguard.is_word_run(a):
        return "seed"
    if not valid(a, chain):
        return f"That doesn't look like a {CHAINS.get(chain, ('', ''))[0] or 'wallet'} address. Paste the public address only."
    ws = wallets()
    if any(w["address"] == a and w["chain"] == chain for w in ws):
        return None
    ws.append({"address": a, "chain": chain, "label": (label or "")[:60], "added": datetime.now().strftime("%Y-%m-%d %H:%M"),
               "since": int(time.time())})
    _save(ws)
    return None


def remove(address, chain):
    _save([w for w in wallets() if not (w["address"] == address and w["chain"] == chain)])


def _state():
    try:
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _xrpl_out(address, since):
    from shield import xrpl
    r = (XRPL_RPC or xrpl.rpc)("account_tx", {"account": address, "ledger_index_min": -1, "ledger_index_max": -1, "limit": 30, "forward": False}) or {}
    out = []
    for t in r.get("transactions", []):
        tx = t.get("tx_json") or t.get("tx") or {}
        meta = t.get("meta") or {}
        ep = (tx.get("date") or 0) + 946684800
        if meta.get("TransactionResult") == "tesSUCCESS" and tx.get("TransactionType") == "Payment" and tx.get("Account") == address and ep > since:
            amt = tx.get("DeliverMax") or tx.get("Amount")
            what = f"{int(amt) / 1e6:g} XRP" if isinstance(amt, str) else f"{(amt or {}).get('value', '?')} {(amt or {}).get('currency', '')}"
            out.append({"txid": t.get("hash") or tx.get("hash", ""), "epoch": ep, "to": tx.get("Destination", ""), "what": what})
    return out


def _chain_out(address, chain, since):
    if ADAPTER:
        ad = ADAPTER(chain)
    else:
        from multichain.registry import get_adapter
        ad = get_adapter(chain)
    ok, why = ad.available()
    if not ok:
        raise RuntimeError(why or "this network needs a key in Settings")
    return [{"txid": t.txid, "epoch": t.epoch or 0, "to": t.to, "what": f"{t.amount:g} {t.asset}"}
            for t in ad.outgoing(address, after_epoch=since) if (t.epoch or 0) > since]


def check_once(send=None, log=print):
    """Look at each wallet once. Returns the new outgoing payments found (each also alerted once)."""
    st = _state()
    found = []
    for w in wallets():
        key = f"{w['chain']}:{w['address']}"
        s = st.setdefault(key, {})
        since = max(int(w.get("since") or 0), int(s.get("last_epoch") or 0))
        try:
            outs = _xrpl_out(w["address"], since) if w["chain"] == "xrpl" else _chain_out(w["address"], w["chain"], since)
            s.update({"checked": datetime.now().strftime("%Y-%m-%d %H:%M"), "error": ""})
        except Exception as ex:
            s.update({"checked": datetime.now().strftime("%Y-%m-%d %H:%M"), "error": f"{type(ex).__name__}: {str(ex)[:120]}"})
            continue
        for o in sorted(outs, key=lambda o: o["epoch"]):
            s["last_epoch"] = max(int(s.get("last_epoch") or 0), o["epoch"])
            found.append({**o, **w})
            title = f"Money left your wallet: {o['what']}"
            msg = (f"{CHAINS[w['chain']][0]} wallet {w['address'][:10]}... sent {o['what']} to {o['to'][:14]}... "
                   "If this wasn't you, open Incident mode on the Desk now.")
            if send:
                send(title, msg, key=f"mywallet:{key}:{o['txid']}")
            else:
                try:
                    import alerts
                    alerts.send(title, msg, critical=True, key=f"mywallet:{key}:{o['txid']}")
                except Exception as ex:
                    log(f"(alert not sent: {ex})")
            try:
                from deskui import data as deskdata
                deskdata.note("crypto", "stop", title, msg, "/incident")
            except Exception:
                pass
    tmp = STATE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f)
    os.replace(tmp, STATE)
    return found


def status():
    st = _state()
    return [{**w, "label_chain": CHAINS.get(w["chain"], (w["chain"],))[0], **st.get(f"{w['chain']}:{w['address']}", {})} for w in wallets()]


def run(stop_evt, interval=300, log=print):
    while not stop_evt.is_set():
        if wallets():
            try:
                check_once(log=log)
            except Exception as ex:
                log(f"(My wallets check skipped: {type(ex).__name__})")
        stop_evt.wait(interval)
