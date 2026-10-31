"""Tron support for shield (TronGrid, key-less): TRC-20 approvals, account-
permission hijack, drains, and history for the pre-screen.

Tron's signature scam: the drainer gets the victim to sign an
AccountPermissionUpdate, after which the attacker's key controls the account
(the victim can still see the balance but can't move it). We check for that
first.
"""
import json
import urllib.request

API = "https://api.trongrid.io"
UA = {"User-Agent": "ScamHunter-Shield/0.2", "Content-Type": "application/json", "Accept": "application/json"}
APPROVE = "095ea7b3"
UNLIMITED = 2 ** 200
KNOWN = {"TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": ("USDT", 6), "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8": ("USDC", 6)}

GET = None    # test hooks
POST = None


def _get(path):
    if GET:
        return GET(path)
    with urllib.request.urlopen(urllib.request.Request(API + path, headers=UA), timeout=25) as r:
        return json.loads(r.read())


def _post(path, body):
    if POST:
        return POST(path, body)
    req = urllib.request.Request(API + path, data=json.dumps(body).encode(), headers=UA)
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read())


def to_hex20(b58):
    from responder.addresses import _b58decode
    raw = _b58decode(b58)
    return raw[1:21].hex() if raw and len(raw) >= 21 else None


def from_hex41(h):
    from responder.addresses import b58check_encode
    return b58check_encode(bytes.fromhex(h))


def _const(owner, contract, selector, param=""):
    r = _post("/wallet/triggerconstantcontract", {"owner_address": owner, "contract_address": contract,
                                                   "function_selector": selector, "parameter": param, "visible": True})
    res = (r or {}).get("constant_result") or []
    return res[0] if res else None


def token_meta(owner, token):
    if token in KNOWN:
        return KNOWN[token]
    sym, dec = "TRC-20", 6
    try:
        dec = int(_const(owner, token, "decimals()") or "6", 16)
    except Exception:
        pass
    try:
        raw = bytes.fromhex(_const(owner, token, "symbol()") or "")
        if len(raw) >= 64:
            sym = raw[64:64 + int.from_bytes(raw[32:64], "big")].decode("utf-8", "ignore") or sym
    except Exception:
        pass
    return sym, dec


def is_contract(addr):
    try:
        return bool((_post("/wallet/getcontract", {"value": addr, "visible": True}) or {}).get("bytecode"))
    except Exception:
        return None


def approvals(wallet):
    out, seen = [], set()
    data = (_get(f"/v1/accounts/{wallet}/transactions?only_from=true&limit=200&visible=true") or {}).get("data", [])
    for tx in data:
        try:
            c = tx["raw_data"]["contract"][0]
            v = c["parameter"]["value"]
        except (KeyError, IndexError):
            continue
        d = v.get("data") or ""
        if c.get("type") != "TriggerSmartContract" or not d.startswith(APPROVE):
            continue
        token, spender = v.get("contract_address"), from_hex41("41" + d[8 + 24:8 + 64])
        if (token, spender) in seen:
            continue
        seen.add((token, spender))
        try:
            cur = int(_const(wallet, token, "allowance(address,address)",
                             to_hex20(wallet).rjust(64, "0") + to_hex20(spender).rjust(64, "0")) or "0", 16)
        except Exception:
            continue
        if cur == 0:
            continue
        sym, dec = token_meta(wallet, token)
        out.append({"chain": "tron", "kind": "trc20", "token": token, "symbol": sym, "spender": spender,
                    "amount": None if cur >= UNLIMITED else cur / 10 ** dec, "unlimited": cur >= UNLIMITED,
                    "spender_is_contract": is_contract(spender),
                    "revoke": f"https://tronscan.org/#/address/{wallet}",
                    "revoke_hint": "Revoke in TronScan (connect wallet > approvals) or your wallet's authorization manager."})
    return out


def takeover(wallet):
    """Account-permission hijack check. Returns findings [(level, text)]."""
    acct = _post("/wallet/getaccount", {"address": wallet, "visible": True}) or {}
    found = []
    perms = [("owner", acct.get("owner_permission"))] + [("active", p) for p in acct.get("active_permission") or []]
    for name, p in perms:
        if not p:
            continue
        keys = {k.get("address"): int(k.get("weight") or 0) for k in p.get("keys") or []}
        thr = int(p.get("threshold") or 1)
        others = [k for k in keys if k != wallet]
        if others and keys.get(wallet, 0) < thr:
            found.append(("danger", f"Your {name} permission is controlled by {', '.join(others)} -- this account has been "
                                    "taken over (Tron permission-update scam). You can't move funds yourself; contact SEAL 911."))
        elif others:
            found.append(("high", f"Extra key(s) on your {name} permission: {', '.join(others)}. If you didn't add them, "
                                  "remove them now (TronScan > Permissions)."))
    return found


def drains(wallet):
    out = []
    rows = (_get(f"/v1/accounts/{wallet}/transactions/trc20?limit=200") or {}).get("data", [])
    for t in rows:
        if t.get("from") != wallet:
            continue
        txid = t.get("transaction_id")
        try:
            tx = _post("/wallet/gettransactionbyid", {"value": txid, "visible": True}) or {}
            initiator = tx["raw_data"]["contract"][0]["parameter"]["value"].get("owner_address")
            called = tx["raw_data"]["contract"][0]["parameter"]["value"].get("contract_address")
        except Exception:
            continue
        if initiator == wallet:
            continue
        info = t.get("token_info") or {}
        dec = int(info.get("decimals") or 6)
        out.append({"chain": "tron", "hash": txid, "time": int((t.get("block_timestamp") or 0) / 1000),
                    "tokens": [{"token": info.get("address"), "symbol": info.get("symbol") or "TRC-20",
                                "amount": int(t.get("value") or 0) / 10 ** dec, "to": t.get("to")}],
                    "tx_sender": initiator, "drainer_contract": initiator if called == info.get("address") else called,
                    "receivers": {t.get("to"): int(t.get("value") or 0)}})
    return out
