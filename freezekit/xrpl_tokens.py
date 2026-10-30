"""XRPL issuer-freeze detection.

XRP itself can never be frozen. But if the network swaps stolen XRP into an
ISSUED token (RLUSD, other stablecoins, IOUs), the issuer usually CAN act:
  * freeze that holder's trust line   (unless the issuer set NoFreeze)
  * claw the tokens back              (if the issuer enabled AllowTrustLineClawback)

This scans every wallet in the scam network for issued-token balances, reads
each issuer's flags, and records which holdings are freezable / clawback-able
and whether the issuer has ALREADY frozen the line. Results: token_holdings.json.

Standard library only (XRPL JSON-RPC over HTTPS).
"""
import json
import time
import urllib.request
from datetime import datetime

from . import channels

OUT = "token_holdings.json"
RPC = ["https://xrplcluster.com/", "https://s1.ripple.com:51234/", "https://s2.ripple.com:51234/"]

LSF_NO_FREEZE = 0x00200000
LSF_GLOBAL_FREEZE = 0x00400000
LSF_ALLOW_CLAWBACK = 0x80000000


def currency_name(code):
    if code and len(code) == 40:
        try:
            s = bytes.fromhex(code).rstrip(b"\x00").decode("ascii", "ignore").strip()
            if s:
                return s
        except Exception:
            pass
    return code


def issuer_flags(flags):
    flags = int(flags or 0)
    return {"no_freeze": bool(flags & LSF_NO_FREEZE),
            "global_freeze": bool(flags & LSF_GLOBAL_FREEZE),
            "clawback": bool(flags & LSF_ALLOW_CLAWBACK)}


def _rpc(method, params, _post=None):
    body = json.dumps({"method": method, "params": [params]}).encode()
    last = None
    for url in RPC:
        try:
            if _post:
                return _post(url, method, params)
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as r:
                res = json.loads(r.read()).get("result", {})
            if res.get("status") == "error" and res.get("error") not in ("actNotFound",):
                last = res.get("error")
                continue
            return res
        except Exception as e:
            last = e
    raise ConnectionError(f"XRPL RPC failed: {last}")


def account_lines(addr, _post=None):
    lines, marker = [], None
    for _ in range(10):
        p = {"account": addr, "ledger_index": "validated", "limit": 400}
        if marker:
            p["marker"] = marker
        res = _rpc("account_lines", p, _post)
        lines += res.get("lines", [])
        marker = res.get("marker")
        if not marker:
            break
    return lines


def scan(addresses, log=print, max_wallets=300, _post=None, pause=0.15):
    holdings, issuers = [], {}
    for i, a in enumerate(list(addresses)[:max_wallets]):
        try:
            lines = account_lines(a, _post)
        except Exception as e:
            log(f"token scan: {a[:10]}.. skipped ({e})")
            continue
        for ln in lines:
            try:
                bal = float(ln.get("balance", "0"))
            except ValueError:
                continue
            if bal <= 0:
                continue   # positive balance = this wallet HOLDS tokens issued by the peer
            iss = ln.get("account")
            if iss not in issuers:
                try:
                    info = _rpc("account_info", {"account": iss, "ledger_index": "validated"}, _post)
                    issuers[iss] = issuer_flags(info.get("account_data", {}).get("Flags"))
                except Exception:
                    issuers[iss] = {"no_freeze": None, "global_freeze": None, "clawback": None}
                key, ent = channels.issuer_for_xrpl(iss)
                issuers[iss]["name"] = ent["name"] if ent else None
                issuers[iss]["key"] = key
            f = issuers[iss]
            holdings.append({
                "wallet": a, "issuer": iss, "issuer_name": f.get("name"),
                "currency": currency_name(ln.get("currency")), "currency_raw": ln.get("currency"),
                "balance": bal,
                "frozen_by_issuer": bool(ln.get("freeze_peer")) or bool(f.get("global_freeze")),
                "freezable": f.get("no_freeze") is False,
                "clawback": bool(f.get("clawback")),
            })
        if pause:
            time.sleep(pause)
    out = {"scanned": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
           "wallets_scanned": min(len(list(addresses)), max_wallets),
           "holdings": sorted(holdings, key=lambda h: -h["balance"]), "issuers": issuers}
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    return out


def network_wallets():
    """Every wallet the evidence map and the freeze map know about."""
    addrs = []
    for path in ("scam_network.json", "network_map.json"):
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            continue
        addrs += list(d.get("nodes", {}).keys()) + list(d.get("watchlist", []))
        if d.get("root"):
            addrs.insert(0, d["root"])
    # Exchange / custodial wallets hold thousands of customers' tokens -- not the
    # scammers'. Only scan the network's own wallets.
    exch = set()
    for path in ("scam_network.json", "network_map.json"):
        d = {}
        try:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
        except Exception:
            pass
        exch |= {e.get("address") for e in d.get("endpoints", [])}
        exch |= {a for a, n in d.get("nodes", {}).items()
                 if n.get("is_exchange") or n.get("label")   # any named service/exchange
                 or any(w in str(n.get("role", "")) for w in ("exchange", "swap", "custodial", "victim"))}
    seen, out = set(exch), []
    for a in addrs:
        if isinstance(a, str) and a.startswith("r") and a not in seen:
            seen.add(a)
            out.append(a)
    return out


def load():
    try:
        with open(OUT, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None
