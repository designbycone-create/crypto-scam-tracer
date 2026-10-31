"""Pre-screen: a background check on a wallet BEFORE you send to it.

    python -m shield.prescreen <address> [--chain ethereum] [--tag 123] [--me <your wallet>]

Returns a one-page verdict:
  STOP      known scam / sanctioned / part of a network we track / compromised list
  CAUTION   behaves like a scam wallet, lookalike of one you've used, poisoning,
            missing destination tag, wrong network, brand-new with no history
  NO RED FLAGS FOUND   ...which is never a guarantee: a brand-new clean wallet
            has no history to judge.

Checks
  1 known bad     threat intel (ScamSniffer, OFAC...), your case networks,
                  incidents, same-day compromised list, operator groups
  2 identity      known exchange / service / verified domain owner
  3 behavior      fresh, victim-collector, pass-through, drained, empty
  4 network       direct counterparties that are flagged
  5 mistakes      address poisoning (lookalike of your past recipients, or it
                  sent you dust), XRPL destination tag, EVM wrong network
Every check is logged (prescreen_log.jsonl) with its result: an audit trail
for businesses that must show they screened a counterparty.
"""
import json
import statistics
import sys
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone

LOG = "prescreen_log.jsonl"
UA = {"User-Agent": "ScamHunter-Prescreen/0.1", "Content-Type": "application/json", "Accept": "application/json"}
DAY = 86400

# test hooks
XRPL_RPC = None   # f(method, params) -> result dict
HTTP_GET = None   # f(url) -> parsed json


def _get(url):
    if HTTP_GET:
        return HTTP_GET(url)
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=25) as r:
        return json.loads(r.read())


def _xrpl(method, params):
    if XRPL_RPC:
        return XRPL_RPC(method, params)
    from scam_investigator.attribution import _rpc
    return _rpc(method, params)


# ------------------------------------------------------------- history -----
# Normalized movement: {"dir": "in"|"out", "cp": counterparty, "amount": float, "asset": str, "t": epoch}

def history_xrpl(addr, limit=400):
    info = (_xrpl("account_info", {"account": addr, "ledger_index": "validated"}) or {}).get("account_data")
    if not info:
        return {"exists": False, "moves": [], "balance": 0.0, "flags": 0, "domain": None}
    moves, marker = [], None
    for _ in range(3):
        p = {"account": addr, "ledger_index_min": -1, "ledger_index_max": -1, "limit": 200, "forward": False}
        if marker:
            p["marker"] = marker
        r = _xrpl("account_tx", p) or {}
        for t in r.get("transactions", []):
            tx = t.get("tx_json") or t.get("tx") or {}
            meta = t.get("meta") or {}
            if tx.get("TransactionType") != "Payment" or meta.get("TransactionResult") != "tesSUCCESS":
                continue
            amt = meta.get("delivered_amount", tx.get("Amount"))
            if isinstance(amt, str):
                v, asset = int(amt) / 1e6, "XRP"
            elif isinstance(amt, dict):
                v, asset = float(amt.get("value", 0)), amt.get("currency")
            else:
                continue
            ep = (tx.get("date") or 0) + 946684800
            if tx.get("Destination") == addr:
                moves.append({"dir": "in", "cp": tx.get("Account"), "amount": v, "asset": asset, "t": ep,
                              "tag": tx.get("DestinationTag")})
            elif tx.get("Account") == addr:
                moves.append({"dir": "out", "cp": tx.get("Destination"), "amount": v, "asset": asset, "t": ep})
        marker = r.get("marker")
        if not marker or len(moves) >= limit:
            break
    dom = None
    if info.get("Domain"):
        try:
            dom = bytes.fromhex(info["Domain"]).decode("utf-8", "replace")
        except ValueError:
            pass
    return {"exists": True, "moves": moves, "balance": int(info.get("Balance", 0)) / 1e6,
            "flags": int(info.get("Flags") or 0), "domain": dom}


def history_evm(addr, chain):
    from . import evm
    a = addr.lower()
    moves = []
    for tx in evm.explorer(chain, module="account", action="txlist", address=a, page=1, offset=400, sort="desc"):
        v = int(tx.get("value") or 0) / 1e18
        if tx.get("isError") == "1" or v == 0:
            continue
        d = "in" if (tx.get("to") or "").lower() == a else "out"
        moves.append({"dir": d, "cp": (tx.get("from") if d == "in" else tx.get("to") or "").lower(),
                      "amount": v, "asset": "native", "t": int(tx.get("timeStamp") or 0)})
    for t in evm.explorer(chain, module="account", action="tokentx", address=a, page=1, offset=400, sort="desc"):
        dec = int(t.get("tokenDecimal") or 18)
        d = "in" if (t.get("to") or "").lower() == a else "out"
        moves.append({"dir": d, "cp": (t.get("from") if d == "in" else t.get("to") or "").lower(),
                      "amount": int(t.get("value") or 0) / 10 ** dec, "asset": t.get("tokenSymbol") or "token",
                      "t": int(t.get("timeStamp") or 0)})
    code = evm.get_code(chain, a) or "0x"
    try:
        bal = int(evm.rpc(chain, "eth_getBalance", [a, "latest"]) or "0x0", 16) / 1e18
    except Exception:
        bal = None
    return {"exists": bool(moves) or code not in ("0x", "0x0"), "moves": moves, "balance": bal, "code": code}


def history_tron(addr):
    moves = []
    base = "https://api.trongrid.io/v1/accounts/" + addr
    try:
        for tx in (_get(base + "/transactions?limit=200&visible=true") or {}).get("data", []):
            c = tx["raw_data"]["contract"][0]
            if c.get("type") != "TransferContract":
                continue
            v = c["parameter"]["value"]
            d = "in" if v.get("to_address") == addr else "out"
            moves.append({"dir": d, "cp": v.get("owner_address") if d == "in" else v.get("to_address"),
                          "amount": (v.get("amount") or 0) / 1e6, "asset": "TRX", "t": int((tx.get("block_timestamp") or 0) / 1000)})
        for t in (_get(base + "/transactions/trc20?limit=200") or {}).get("data", []):
            d = "in" if t.get("to") == addr else "out"
            dec = int((t.get("token_info") or {}).get("decimals") or 6)
            moves.append({"dir": d, "cp": t.get("from") if d == "in" else t.get("to"),
                          "amount": int(t.get("value") or 0) / 10 ** dec,
                          "asset": (t.get("token_info") or {}).get("symbol") or "TRC20", "t": int((t.get("block_timestamp") or 0) / 1000)})
    except Exception:
        pass
    return {"exists": bool(moves), "moves": moves, "balance": None}


def history_btc(addr):
    moves = []
    try:
        for tx in _get(f"https://mempool.space/api/address/{addr}/txs") or []:
            ins = [(v.get("prevout") or {}).get("scriptpubkey_address") for v in tx.get("vin", [])]
            ep = (tx.get("status") or {}).get("block_time") or int(time.time())
            if addr in ins:
                for o in tx.get("vout", []):
                    if o.get("scriptpubkey_address") not in (addr, None):
                        moves.append({"dir": "out", "cp": o["scriptpubkey_address"], "amount": o.get("value", 0) / 1e8, "asset": "BTC", "t": ep})
            else:
                got = sum(o.get("value", 0) for o in tx.get("vout", []) if o.get("scriptpubkey_address") == addr)
                if got:
                    moves.append({"dir": "in", "cp": next((i for i in ins if i), None), "amount": got / 1e8, "asset": "BTC", "t": ep})
    except Exception:
        pass
    return {"exists": bool(moves), "moves": moves, "balance": None}


# ------------------------------------------------------------- checks ------

def _known_bad(addr):
    hits = []
    try:
        from responder import intel
        for src, det in intel.check(addr):
            hits.append(f"{src}: {det}")
    except Exception:
        pass
    try:
        from . import compromised
        h = compromised.check_address(addr)
        if h:
            hits.append(f"Same-day incident list: {h}")
    except Exception:
        pass
    try:
        with open("operators.json", encoding="utf-8") as f:
            g = json.load(f).get("wallet_group", {}).get(addr)
        if g:
            hits.append(f"Member of {g}, an operator group in a scam network you track")
    except Exception:
        pass
    return hits


def _identity(addr, chain):
    if chain == "xrpl":
        try:
            from scam_investigator.attribution import _known_labels, _xrpscan
            lbl = _known_labels().get(addr) or _xrpscan(addr)
            if lbl:
                return lbl
        except Exception:
            pass
        try:
            with open("attribution.json", encoding="utf-8") as f:
                a = json.load(f).get(addr) or {}
            if a.get("confidence") in ("verified", "likely"):
                return f"{a['name']} ({a['confidence']})"
        except Exception:
            pass
        return None
    try:
        from multichain import entities
        ent = entities.classify("ethereum" if chain not in ("tron", "bitcoin", "solana") else chain, addr)
        return f"{ent['name']} ({ent['type']})" if ent else None
    except Exception:
        return None


def behavior(h, now=None):
    """Score behavior from normalized history. Returns list of (level, text)."""
    now = now or time.time()
    moves = sorted(h.get("moves", []), key=lambda m: m["t"])
    out = []
    if not h.get("exists") or not moves:
        return [("caution", "No history at all on this chain: a brand-new or unused address can't be vetted. "
                            "Scam wallets are often created hours before they're used.")]
    first = moves[0]["t"]
    age_days = (now - first) / DAY if first else None
    if age_days is not None and age_days < 7:
        out.append(("caution", f"Fresh: first activity {max(0, age_days):.1f} day(s) ago."))
    ins = [m for m in moves if m["dir"] == "in"]
    outs = [m for m in moves if m["dir"] == "out"]
    senders = Counter(m["cp"] for m in ins)
    receivers = Counter(m["cp"] for m in outs)
    if len(senders) >= 15 and len(receivers) <= max(3, len(senders) // 8):
        out.append(("caution", f"Victim-collector pattern: received from {len(senders)} different wallets, "
                               f"but pays out to only {len(receivers)} -- how giveaway and investment-scam wallets look."))
    vin, vout = sum(m["amount"] for m in ins), sum(m["amount"] for m in outs)
    if ins and outs and vin and vout / vin > 0.8:
        holds = []
        oi = 0
        for m in ins:
            while oi < len(outs) and outs[oi]["t"] < m["t"]:
                oi += 1
            if oi < len(outs):
                holds.append(outs[oi]["t"] - m["t"])
        if holds and statistics.median(holds) < 6 * 3600 and len(ins) >= 5:
            out.append(("caution", f"Pass-through: money is forwarded on quickly (typically within "
                                   f"{statistics.median(holds) / 3600:.1f} h) -- typical of laundering hops."))
    bal = h.get("balance")
    if bal is not None and vin > 1000 and bal < vin * 0.01:
        out.append(("info", f"Holds almost nothing ({bal:,.2f}) despite {vin:,.0f} received: funds don't stay here."))
    return out


def _network(moves, limit=60):
    flagged = []
    seen = set()
    for m in moves:
        cp = m.get("cp")
        if not cp or cp in seen:
            continue
        seen.add(cp)
        hits = _known_bad(cp)
        if hits:
            flagged.append(f"{'received from' if m['dir'] == 'in' else 'sent to'} {cp} -- {hits[0]}")
        if len(seen) >= limit:
            break
    return flagged


def _lookalike(a, b):
    return a != b and len(a) == len(b) and a[:4].lower() == b[:4].lower() and a[-4:].lower() == b[-4:].lower()


def mistakes(addr, chain, h, tag=None, me=None, my_history=None):
    out = []
    if chain == "xrpl" and h.get("flags", 0) & 0x00020000 and not tag:
        out.append(("stop", "This XRP Ledger account REQUIRES a destination tag (it's an exchange-style account). "
                            "Sending without one usually means the exchange can't credit you. Get the tag first."))
    if chain == "xrpl" and h.get("exists") is False:
        out.append(("info", "This XRP Ledger address isn't activated yet: you must send at least the reserve amount, "
                            "and it has no history to check."))
    if my_history:
        past = {m["cp"] for m in my_history.get("moves", []) if m["dir"] == "out" and m.get("cp")}
        twins = [p for p in past if _lookalike(addr, p)]
        if twins:
            out.append(("stop", f"ADDRESS POISONING: this looks like {twins[0]}, which you've sent to before -- same start and end, "
                                "different middle. Copy the address from the original source, never from your history."))
        dust = [m for m in my_history.get("moves", []) if m["dir"] == "in" and m.get("cp") == addr and m["amount"] <= 0.0001]
        if dust:
            out.append(("stop", "This address sent your wallet a zero / dust transfer -- the classic poisoning trick to plant "
                                "a lookalike in your history."))
    return out


def _log(entry):
    try:
        with open(LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def screen(addr, chain=None, tag=None, me=None, log=print):
    from freezekit.chainlookup import detect_address
    addr = (addr or "").strip()
    fams = detect_address(addr)
    if not fams:
        return {"ok": False, "error": "That isn't a wallet address we recognize (XRP Ledger, EVM, Tron, Bitcoin, Solana)."}
    if chain not in fams:
        chain = fams[0]
    key = addr.lower() if addr.startswith("0x") else addr
    findings = []   # (level, section, text)
    for hit in _known_bad(key):
        findings.append(("stop", "Known bad", hit))
    ident = _identity(key, chain)
    if ident:
        findings.append(("info", "Identity", f"Identified as {ident}. Make sure this is the service you meant to pay."))
    try:
        if chain == "xrpl":
            h = history_xrpl(addr)
        elif chain in ("tron",):
            h = history_tron(addr)
        elif chain == "bitcoin":
            h = history_btc(addr)
        elif chain == "solana":
            h = {"exists": None, "moves": []}
            findings.append(("info", "Behavior", "Solana behavior checks aren't in this draft yet; list checks still apply."))
        else:
            from . import evm
            h = history_evm(addr, chain) if evm.available(chain) else {"exists": None, "moves": []}
            if (h.get("code") or "0x").lower().startswith("0xef0100"):
                findings.append(("caution", "Behavior", "EIP-7702 delegated wallet: its code is controlled by "
                                 f"0x{h['code'][8:48]}. Unusual for a normal recipient."))
            if h.get("exists") is False and len(fams) > 1:
                findings.append(("caution", "Mistakes", f"No activity on {chain}. If you expect this address to be active, "
                                 "check you're sending on the right network."))
    except Exception as e:
        h = {"exists": None, "moves": []}
        findings.append(("info", "Behavior", f"Couldn't read history right now ({str(e)[:80]})."))
    is_service = bool(ident)
    if h.get("exists") is not None and chain != "solana":
        for lvl, txt in behavior(h):
            if is_service and "collector" in txt:
                continue   # exchanges receive from everyone; not a scam signal
            findings.append((lvl, "Behavior", txt))
    for txt in _network(h.get("moves", [])):
        findings.append(("caution", "Network", txt))
    myh = None
    if me:
        try:
            mfam = detect_address(me)
            mchain = chain if chain in mfam else (mfam[0] if mfam else None)
            myh = (history_xrpl(me) if mchain == "xrpl" else history_tron(me) if mchain == "tron"
                   else history_btc(me) if mchain == "bitcoin" else history_evm(me, mchain) if mchain else None)
        except Exception:
            myh = None
    for lvl, txt in mistakes(addr, chain, h, tag, me, myh):
        findings.append((lvl, "Mistakes", txt))
    levels = {f[0] for f in findings}
    verdict = "STOP" if "stop" in levels else ("CAUTION" if "caution" in levels else "NO RED FLAGS FOUND")
    res = {"ok": True, "address": addr, "chain": chain, "verdict": verdict, "identity": ident,
           "findings": [{"level": l, "section": s, "text": t} for l, s, t in findings],
           "stats": {"movements": len(h.get("moves", [])), "balance": h.get("balance")},
           "checked": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
           "note": "Advisory only. 'No red flags found' is not a guarantee -- new scam wallets have no history."}
    _log({"time": res["checked"], "address": addr, "chain": chain, "verdict": verdict,
          "findings": [f["text"][:160] for f in res["findings"]]})
    return res


if __name__ == "__main__":
    args = sys.argv[1:]
    opt = lambda k: args[args.index(k) + 1] if k in args else None
    r = screen(args[0], opt("--chain"), opt("--tag"), opt("--me"))
    if not r.get("ok"):
        sys.exit(r["error"])
    print(f"\n{r['verdict']}  {r['address']} ({r['chain']})")
    for f in r["findings"]:
        print(f"  [{f['level']:7}] {f['section']}: {f['text']}")
    print(" ", r["note"])
