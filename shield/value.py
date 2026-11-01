"""Dollars at risk per approval: what a spender could take RIGHT NOW.

at_risk = min(current token balance, allowance) x USD price
Prices come from DefiLlama's free, key-less price API (coins.llama.fi).
Approvals are then sorted by severity first, dollars second, so the one that
can empty the most money is at the top. Missing price -> shown as "price unknown",
never as $0.
"""
import json
import urllib.request

LLAMA = "https://coins.llama.fi/prices/current/"
SLUG = {"ethereum": "ethereum", "bsc": "bsc", "polygon": "polygon", "arbitrum": "arbitrum",
        "base": "base", "optimism": "optimism", "avalanche": "avax", "opbnb": "op_bnb", "tron": "tron", "solana": "solana"}
ORDER = {"danger": 0, "high": 1, "review": 2, "ok": 3}

PRICE_GET = None   # test hook: f(keys) -> {key: price}


def prices(keys):
    if not keys:
        return {}
    if PRICE_GET:
        return PRICE_GET(keys)
    out = {}
    keys = sorted(set(keys))
    for i in range(0, len(keys), 60):
        url = LLAMA + ",".join(keys[i:i + 60])
        req = urllib.request.Request(url, headers={"User-Agent": "ScamHunter-Shield"})
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.loads(r.read())
        for k, v in (d.get("coins") or {}).items():
            if v.get("price") is not None:
                out[k] = float(v["price"])
    return out


def _balance(chain, wallet, token):
    from . import evm
    try:
        raw = int(evm.call(chain, token, "0x70a08231" + evm.pad(wallet)[2:]) or "0x0", 16)
        _, dec = evm.token_meta(chain, token)
        return raw / 10 ** dec
    except Exception:
        return None


def enrich(res, wallet):
    """Add 'balance', 'usd_price', 'usd_at_risk' to EVM ERC-20 / Permit2 approvals; total in res['usd_at_risk']."""
    items = [(c, a) for c, v in (res.get("chains") or {}).items() for a in v
             if c in SLUG and a.get("kind") in ("erc20", "permit2") and str(a.get("token", "")).startswith("0x")]
    keys = {f"{SLUG[c]}:{a['token'].lower()}" for c, a in items}
    try:
        px = prices(list(keys))
    except Exception as e:
        res.setdefault("notes", []).append(f"Dollar values unavailable right now (price service: {str(e)[:60]}).")
        px = {}
    total = 0.0
    for c, a in items:
        bal = _balance(c, wallet, a["token"])
        p = px.get(f"{SLUG[c]}:{a['token'].lower()}")
        a["balance"], a["usd_price"] = bal, p
        if bal is None or p is None:
            a["usd_at_risk"] = None
            continue
        exposed = bal if a.get("unlimited") or a.get("amount") is None else min(bal, a["amount"])
        a["usd_at_risk"] = round(exposed * p, 2)
        if a.get("risk") in ("danger", "high", "review"):
            total += a["usd_at_risk"]
    for c in res.get("chains") or {}:
        res["chains"][c].sort(key=lambda a: (ORDER.get(a.get("risk"), 9), -(a.get("usd_at_risk") or 0)))
    res["usd_at_risk"] = round(total, 2)
    return res
