"""Read the victim's payment from ANY supported chain, for the setup wizard.

Paste a transaction hash / signature or an explorer link; we figure out which
chain it is on and return who paid whom, how much, and when. No API keys:
  XRP Ledger      public full-history servers
  Bitcoin         mempool.space
  Ethereum + EVM  public RPC (Ethereum, BNB, Polygon, Arbitrum, Base, Optimism, Avalanche)
                  native coin and ERC-20 transfers (USDT/USDC...)
  Tron            TronGrid (TRX and TRC-20 such as USDT)
  Solana          public RPC (SOL and SPL tokens such as USDC/USDT)
"""
import json
import re
import urllib.request
from datetime import datetime, timezone

UA = {"User-Agent": "ScamHunter/1.0", "Content-Type": "application/json"}
EVM_RPC = {
    "ethereum": "https://ethereum-rpc.publicnode.com",
    "bsc": "https://bsc-rpc.publicnode.com",
    "polygon": "https://polygon-bor-rpc.publicnode.com",
    "arbitrum": "https://arbitrum-one-rpc.publicnode.com",
    "base": "https://base-rpc.publicnode.com",
    "optimism": "https://optimism-rpc.publicnode.com",
    "avalanche": "https://avalanche-c-chain-rpc.publicnode.com",
}
NATIVE = {"ethereum": "ETH", "bsc": "BNB", "polygon": "POL", "arbitrum": "ETH", "base": "ETH",
          "optimism": "ETH", "avalanche": "AVAX"}
CHAIN_NAMES = {"xrpl": "XRP Ledger", "bitcoin": "Bitcoin", "tron": "Tron", "solana": "Solana",
               "ethereum": "Ethereum", "bsc": "BNB Smart Chain", "polygon": "Polygon", "arbitrum": "Arbitrum",
               "base": "Base", "optimism": "Optimism", "avalanche": "Avalanche"}
_ERC20_DEC = {"USDT": 6, "USDC": 6}


def _post(url, payload, timeout=20):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "ScamHunter/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _iso(ep):
    return datetime.fromtimestamp(ep, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ep else ""


def _fmt(x):
    return f"{x:,.8f}".rstrip("0").rstrip(".")


# ------------------------------------------------------------------ chains --

def xrpl(h):
    from .setup import lookup_tx as _x
    r = _x(h)
    if r.get("ok"):
        r.update({"chain": "xrpl", "epoch": _epoch_from_iso(r.get("time"))})
    return r if r.get("ok") else None


def _epoch_from_iso(s):
    try:
        return int(datetime.strptime(s.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp())
    except Exception:
        return None


def bitcoin(h):
    try:
        tx = _get(f"https://mempool.space/api/tx/{h.lower()}")
    except Exception:
        return None
    ins = [v.get("prevout", {}).get("scriptpubkey_address") for v in tx.get("vin", [])]
    outs = [(o.get("scriptpubkey_address"), (o.get("value") or 0) / 1e8) for o in tx.get("vout", [])
            if o.get("scriptpubkey_address") and o.get("scriptpubkey_address") not in ins]
    ep = (tx.get("status") or {}).get("block_time")
    r = {"ok": True, "chain": "bitcoin", "hash": tx.get("txid"), "from": ins[0] if ins else None,
         "time": _iso(ep), "epoch": ep}
    if len(outs) == 1:
        r.update({"to": outs[0][0], "amount": f"{_fmt(outs[0][1])} BTC"})
    else:
        r.update({"to": None, "candidates": [{"to": a, "amount": f"{_fmt(v)} BTC"} for a, v in outs],
                  "warning": "This Bitcoin transaction paid several addresses. Pick the scammer's address below."})
    return r


def evm(h):
    for chain, url in EVM_RPC.items():
        try:
            tx = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionByHash", "params": [h]}).get("result")
        except Exception:
            continue
        if not tx:
            continue
        frm, to, inp = tx.get("from"), tx.get("to"), tx.get("input") or "0x"
        amount = f"{_fmt(int(tx.get('value') or '0x0', 16) / 1e18)} {NATIVE[chain]}"
        token = None
        if inp.startswith("0xa9059cbb") and len(inp) >= 138:        # ERC-20 transfer(to, amount)
            token = to
            to = "0x" + inp[34:74]
            raw = int(inp[74:138], 16)
            sym = None
            try:
                from multichain import entities
                s = entities.stablecoin_for(chain, token)
                sym = s[0] if s else None
            except Exception:
                pass
            amount = f"{_fmt(raw / 10 ** _ERC20_DEC.get(sym, 18))} {sym}" if sym else f"{raw} base units of token {token[:10]}…"
        ep = None
        try:
            blk = _post(url, {"jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber",
                              "params": [tx.get("blockNumber"), False]}).get("result") or {}
            ep = int(blk.get("timestamp", "0x0"), 16) or None
        except Exception:
            pass
        return {"ok": True, "chain": chain, "hash": h, "from": frm, "to": to, "amount": amount,
                "time": _iso(ep), "epoch": ep, "token": token}
    return None


def tron(h):
    try:
        tx = _post("https://api.trongrid.io/wallet/gettransactionbyid", {"value": h.lower(), "visible": True})
    except Exception:
        return None
    if not tx or not tx.get("raw_data"):
        return None
    c = tx["raw_data"]["contract"][0]
    v = c["parameter"]["value"]
    ep = int((tx["raw_data"].get("timestamp") or 0) / 1000) or None
    r = {"ok": True, "chain": "tron", "hash": tx.get("txID"), "from": v.get("owner_address"), "time": _iso(ep), "epoch": ep}
    if c.get("type") == "TransferContract":
        r.update({"to": v.get("to_address"), "amount": f"{_fmt((v.get('amount') or 0) / 1e6)} TRX"})
    elif c.get("type") == "TriggerSmartContract" and (v.get("data") or "").startswith("a9059cbb"):
        from responder.addresses import b58check_encode
        d = v["data"]
        r["to"] = b58check_encode(bytes.fromhex("41" + d[32:72]))
        raw = int(d[72:136], 16)
        sym = None
        try:
            from multichain import entities
            s = entities.stablecoin_for("tron", v.get("contract_address"))
            sym = s[0] if s else None
        except Exception:
            pass
        r["amount"] = f"{_fmt(raw / 10 ** _ERC20_DEC.get(sym, 6))} {sym or 'TRC-20 tokens'}"
    else:
        return None
    return r


def solana(sig):
    from multichain.adapters.solana import rpc, parse_transfers
    try:
        tx = rpc("getTransaction", [sig, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}])
    except Exception:
        return None
    ts = parse_transfers(tx, None, sig) if tx else []
    if not ts:
        return None
    t = max(ts, key=lambda x: x.amount or 0)
    return {"ok": True, "chain": "solana", "hash": sig, "from": t.frm, "to": t.to,
            "amount": f"{_fmt(t.amount)} {t.asset}", "time": _iso(t.epoch), "epoch": t.epoch}


# ------------------------------------------------------------------ router --

def lookup(text):
    text = (text or "").strip()
    m = re.search(r"\b0x[0-9a-fA-F]{64}\b", text)
    if m:
        return evm(m.group(0)) or {"ok": False, "error": "Not found on Ethereum or the EVM chains we check."}
    m = re.search(r"\b[1-9A-HJ-NP-Za-km-z]{80,90}\b", text)
    if m:
        return solana(m.group(0)) or {"ok": False, "error": "Solana signature not found (or no transfer in it)."}
    m = re.search(r"\b[0-9A-Fa-f]{64}\b", text)
    if not m:
        return {"ok": False, "error": "No transaction hash found. Paste the hash/signature or the explorer link."}
    h = m.group(0)
    low = text.lower()
    order = [xrpl, bitcoin, tron]
    if "mempool" in low or "blockstream" in low or "btc" in low or "bitcoin" in low:
        order = [bitcoin, xrpl, tron]
    elif "tron" in low:
        order = [tron, xrpl, bitcoin]
    for fn in order:
        try:
            r = fn(h)
        except Exception:
            r = None
        if r and r.get("ok"):
            return r
    return {"ok": False, "error": "Couldn't find that transaction on the XRP Ledger, Bitcoin or Tron."}


def detect_address(a):
    """Possible chains for a pasted scammer address."""
    from responder.addresses import extract
    found = extract(a or "")
    if not found:
        return []
    chain = found[0][0]
    if chain == "ethereum":
        return list(EVM_RPC)
    return [chain]
