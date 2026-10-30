"""Early-warning risk signals for wallets in the scam network.

XRPL (from the evidence map + live account data):
  fresh        account activated in the last 7 days (throwaway wallet)
  collector    receives from many distinct senders (victim-collection wallet)
  fan_out      sends to many distinct destinations (laundering splitter)
  drained      moved large sums but now holds ~nothing (swept)
  exchange_fed activated / funded by an exchange account (KYC lead!)
EVM (needs a free Etherscan key; same key the multi-chain tracer uses):
  eip7702      the EOA has an EIP-7702 delegation (code 0xef0100...) -- the
               vector in the Oct-2026 Binance hot-wallet drain
  mixer_funded received funds from Tornado Cash / an OFAC-listed address

Output: risk.json  {address: {"chain", "score", "signals": [...], ...}}
"""
import json
import time
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

OUT = "risk.json"
RIPPLE_EPOCH = 946684800

# Tornado Cash ETH pools + router/proxy (published, immutable contracts)
TORNADO = {
    "0x12d66f87a04a9e220743712ce6d9bb1b5616b8fc",  # 0.1 ETH
    "0x47ce0c6ed5b0ce3d3a51fdb1c52dc66a7c3c2936",  # 1 ETH
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf",  # 10 ETH
    "0xa160cdab225685da1d56aa342ad8841c3b53f291",  # 100 ETH
    "0xd90e2f925da726b50c4ed8d0fb90ad053324f31b",  # router
    "0x722122df12d4e14e13ac3b6895a86e84145b6967",  # proxy
}


def _j(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


# ------------------------------------------------------------------ XRPL ----

def xrpl_graph_signals(net):
    """Signals computable from the recorded flows alone (no network calls)."""
    senders, dests, out_xrp = defaultdict(set), defaultdict(set), defaultdict(float)
    for e in net.get("edges", []):
        senders[e.get("to")].add(e.get("from"))
        dests[e.get("from")].add(e.get("to"))
        out_xrp[e.get("from")] += float(e.get("xrp") or 0)
    res = {}
    for a, n in net.get("nodes", {}).items():
        sig = []
        if len(senders[a]) >= 10:
            sig.append(f"collector: received from {len(senders[a])} distinct wallets")
        if len(dests[a]) >= 10:
            sig.append(f"fan_out: sent to {len(dests[a])} distinct wallets")
        bal = n.get("balance_xrp")
        try:
            bal = float(bal) if bal is not None else None
        except (TypeError, ValueError):
            bal = None
        if bal is not None and out_xrp[a] >= 500 and bal < 5:
            sig.append(f"drained: moved {out_xrp[a]:,.0f} XRP, now holds {bal:,.2f}")
        res[a] = sig
    return res


def xrpl_activation(addr, _rpc=None):
    """(activated_utc, activator) from the account's first transaction."""
    from freezekit.xrpl_tokens import _rpc as rpc
    rpc = _rpc or rpc
    r = rpc("account_tx", {"account": addr, "ledger_index_min": -1, "ledger_index_max": -1,
                           "limit": 3, "forward": True})
    for t in r.get("transactions", []):
        tx = t.get("tx_json") or t.get("tx") or {}
        if tx.get("TransactionType") == "Payment" and tx.get("Destination") == addr:
            when = datetime.fromtimestamp((tx.get("date") or 0) + RIPPLE_EPOCH, tz=timezone.utc)
            return when, tx.get("Account")
    return None, None


def scan_xrpl(max_live=60, log=print, pause=0.2, _rpc=None):
    net = _j("scam_network.json") or _j("network_map.json") or {}
    labels = {a: (n.get("label") or "") for a, n in net.get("nodes", {}).items()}
    graph = xrpl_graph_signals(net)
    out = {}
    live_budget = max_live
    # live checks for the most connected wallets first
    order = sorted(graph, key=lambda a: -len(graph[a]))
    for a in order:
        sig = list(graph[a])
        rec = {"chain": "xrpl", "label": labels.get(a), "signals": sig}
        if live_budget > 0:
            live_budget -= 1
            try:
                when, by = xrpl_activation(a, _rpc)
                if when:
                    rec["activated"] = when.strftime("%Y-%m-%d %H:%M UTC")
                    rec["activated_by"] = by
                    age = (datetime.now(timezone.utc) - when).days
                    if age <= 7:
                        sig.append(f"fresh: activated {age} day(s) ago")
                    lbl = (labels.get(by) or "") if by else ""
                    try:
                        from freezekit import channels
                        is_exch = bool(lbl) and channels.exchange_for(lbl)[0] is not None
                    except Exception:
                        is_exch = False
                    if is_exch:
                        sig.append(f"exchange_fed: activated by {lbl} ({by}) -- the exchange holds KYC for whoever withdrew")
                time.sleep(pause)
            except Exception as e:
                log(f"risk: {a[:10]}.. live check skipped ({e})")
        rec["score"] = len(sig)
        if sig:
            out[a] = rec
    return out


# ------------------------------------------------------------------- EVM ----

def _etherscan(params):
    try:
        from multichain.adapters.evm import api_key, V2
    except Exception:
        return None
    key = api_key()
    if not key:
        return None
    params = {**params, "apikey": key}
    url = V2 + "?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "ScamHunter/1.0"}), timeout=20) as r:
        return json.loads(r.read())


def eip7702_delegate(addr, chainid=1, _q=None):
    """Return the delegate contract if addr is an EIP-7702 delegated EOA, else None."""
    q = _q or _etherscan
    r = q({"chainid": chainid, "module": "proxy", "action": "eth_getCode", "address": addr, "tag": "latest"})
    code = (r or {}).get("result") or ""
    if isinstance(code, str) and code.lower().startswith("0xef0100") and len(code) >= 48:
        return "0x" + code[8:48]
    return None


def mixer_funded(addr, chainid=1, _q=None):
    q = _q or _etherscan
    r = q({"chainid": chainid, "module": "account", "action": "txlistinternal", "address": addr,
           "page": 1, "offset": 100, "sort": "asc"})
    hits = []
    for t in (r or {}).get("result") or []:
        if isinstance(t, dict) and (t.get("from") or "").lower() in TORNADO and (t.get("to") or "").lower() == addr.lower():
            hits.append(t.get("hash"))
    try:
        from multichain import entities
        r2 = q({"chainid": chainid, "module": "account", "action": "txlist", "address": addr,
                "page": 1, "offset": 50, "sort": "asc"})
        for t in (r2 or {}).get("result") or []:
            if isinstance(t, dict) and (t.get("to") or "").lower() == addr.lower() and \
                    entities.is_sanctioned("ethereum", t.get("from") or ""):
                hits.append(t.get("hash"))
    except Exception:
        pass
    return hits


def scan_evm(addresses, log=print, pause=0.25, _q=None):
    out = {}
    for a in addresses:
        sig = []
        try:
            d = eip7702_delegate(a, _q=_q)
            if d:
                sig.append(f"eip7702: EOA delegates its code to {d} (hot-wallet drain vector)")
            m = mixer_funded(a, _q=_q)
            if m:
                sig.append(f"mixer_funded: received from Tornado/OFAC-listed address ({len(m)} tx)")
        except Exception as e:
            log(f"risk: {a[:10]}.. EVM check skipped ({e})")
        if sig:
            out[a] = {"chain": "ethereum", "signals": sig, "score": len(sig) * 2}
        time.sleep(pause)
    return out


def scan(log=print):
    res = {"scanned": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "wallets": {}}
    try:
        res["wallets"].update(scan_xrpl(log=log))
    except Exception as e:
        log(f"risk xrpl scan failed: {e}")
    evm = []
    mc = _j("mc_map.json") or {}
    for n in mc.get("nodes", {}).values():
        if str(n.get("address", "")).startswith("0x") and n.get("type") == "wallet":
            evm.append(n["address"])
    try:
        from . import incident
        evm += [r["address"] for r in incident.load()["addresses"] if r["chain"] == "ethereum"]
    except Exception:
        pass
    if evm:
        res["wallets"].update(scan_evm(list(dict.fromkeys(evm))[:60], log=log))
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    return res


if __name__ == "__main__":
    r = scan()
    top = sorted(r["wallets"].items(), key=lambda kv: -kv[1]["score"])[:20]
    for a, v in top:
        print(f"{v['score']}  {v['chain']:8} {a}  " + " | ".join(v["signals"]))
