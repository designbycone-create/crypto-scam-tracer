"""Check my wallet: every open approval, read live, flagged, with revoke links.

Covers
  ERC-20 Approval            allowance(owner, spender) re-read live (revoked = gone)
  NFT ApprovalForAll         isApprovedForAll(owner, operator) re-read live
  Permit2 (Uniswap)          allowance(owner, token, spender) incl. expiration

Risk levels (worst first)
  danger   spender is on a scam/drainer list (threat intel, compromised list,
           an incident) -> revoke now
  high     unlimited (or effectively unlimited) allowance to an address that is
           NOT a contract (a plain wallet can't be a legit dApp), or NFT
           "approve all" to a non-contract
  review   unlimited allowance to a contract (normal for DEXes; revoke if you
           don't use it anymore)
  ok       limited allowance

    python -m shield.approvals 0xYourWallet [chain ...]
"""
import sys
import time

from . import evm

APPROVAL = "0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925"
APPROVAL_FOR_ALL = "0x17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31"
PERMIT2 = "0x000000000022d473030f116ddee9f6b43ac78ba3"
PERMIT2_APPROVAL = "0xda9fa7c1b00402c17d0161b249b1ab8bbec047c5a52207b9c112deffd817036b"
PERMIT2_PERMIT = "0xc6a377bfc4eb120024a8ac08eef205be16b817020812c73223e81d1bdb9708ec"
UNLIMITED = 2 ** 200   # anything this large is "unlimited" in practice


def revoke_url(wallet, chain):
    return f"https://revoke.cash/address/{wallet}?chainId={evm.CHAINS[chain][0]}"


def _flagged(addr):
    """(source, detail) if the spender is on any list we hold, else None."""
    a = addr.lower()
    try:
        from responder import intel
        for src, det in intel.check(a):
            return src, det
    except Exception:
        pass
    try:
        from . import compromised
        hit = compromised.check_address(a)
        if hit:
            return "Compromised-site list", hit
    except Exception:
        pass
    return None


def _logs(chain, topic0, owner, address=None):
    p = {"module": "logs", "action": "getLogs", "fromBlock": 0, "toBlock": "latest",
         "topic0": topic0, "topic1": evm.pad(owner), "topic0_1_opr": "and"}
    if address:
        p["address"] = address
    return evm.explorer(chain, **p)


def scan_chain(wallet, chain, pause=0.25):
    wallet = wallet.lower()
    out, seen = [], set()
    # ERC-20 + NFT single approvals share the Approval signature; ERC-721 has 4 topics.
    for lg in _logs(chain, APPROVAL, wallet):
        t = lg.get("topics") or []
        if len(t) < 3:
            continue
        token, spender = lg["address"].lower(), evm.topic_addr(t[2])
        if len(t) == 4 or (token, spender) in seen:
            continue   # ERC-721 single-token approvals: superseded on transfer; skip in draft
        seen.add((token, spender))
        try:
            cur = int(evm.call(chain, token, "0xdd62ed3e" + evm.pad(wallet)[2:] + evm.pad(spender)[2:]) or "0x0", 16)
        except Exception:
            continue
        if cur == 0:
            continue
        sym, dec = evm.token_meta(chain, token)
        out.append({"chain": chain, "kind": "erc20", "token": token, "symbol": sym, "spender": spender,
                    "amount": None if cur >= UNLIMITED else cur / 10 ** dec, "unlimited": cur >= UNLIMITED})
        time.sleep(pause)
    for lg in _logs(chain, APPROVAL_FOR_ALL, wallet):
        t = lg.get("topics") or []
        if len(t) < 3:
            continue
        coll, op = lg["address"].lower(), evm.topic_addr(t[2])
        if (coll, op, "all") in seen:
            continue
        seen.add((coll, op, "all"))
        try:
            on = int(evm.call(chain, coll, "0xe985e9c5" + evm.pad(wallet)[2:] + evm.pad(op)[2:]) or "0x0", 16)
        except Exception:
            continue
        if on:
            out.append({"chain": chain, "kind": "nft_all", "token": coll, "symbol": "NFT collection",
                        "spender": op, "amount": None, "unlimited": True})
    for topic in (PERMIT2_APPROVAL, PERMIT2_PERMIT):
        for lg in _logs(chain, topic, wallet, address=PERMIT2):
            t = lg.get("topics") or []
            if len(t) < 4:
                continue
            token, spender = evm.topic_addr(t[2]), evm.topic_addr(t[3])
            if (token, spender, "p2") in seen:
                continue
            seen.add((token, spender, "p2"))
            try:
                raw = evm.call(chain, PERMIT2, "0x927da105" + evm.pad(wallet)[2:] + evm.pad(token)[2:] + evm.pad(spender)[2:])
                b = bytes.fromhex(raw[2:])
                amt, exp = int.from_bytes(b[0:32], "big"), int.from_bytes(b[32:64], "big")
            except Exception:
                continue
            if amt == 0 or (exp and exp < time.time()):
                continue
            sym, dec = evm.token_meta(chain, token)
            out.append({"chain": chain, "kind": "permit2", "token": token, "symbol": sym, "spender": spender,
                        "amount": None if amt >= 2 ** 150 else amt / 10 ** dec, "unlimited": amt >= 2 ** 150,
                        "expires": exp})
    # risk grading
    code_cache = {}
    for a in out:
        sp = a["spender"]
        flag = _flagged(sp)
        if sp not in code_cache:
            code_cache[sp] = evm.get_code(chain, sp)
        is_contract = (code_cache[sp] or "0x") not in ("0x", "0x0")
        a["spender_is_contract"] = is_contract
        if flag:
            a["risk"], a["why"] = "danger", f"spender is on {flag[0]} ({flag[1]})"
        elif a["unlimited"] and code_cache[sp] is not None and not is_contract:
            a["risk"], a["why"] = "high", "unlimited approval to a plain wallet, not an app contract"
        elif a["unlimited"]:
            a["risk"], a["why"] = "review", "unlimited approval; revoke if you no longer use this app"
        else:
            a["risk"], a["why"] = "ok", "limited approval"
        a["revoke"] = revoke_url(wallet, chain)
    order = {"danger": 0, "high": 1, "review": 2, "ok": 3}
    return sorted(out, key=lambda a: order[a["risk"]])


def scan(wallet, chains=None, log=print):
    chains = chains or [c for c in evm.CHAINS if evm.available(c)]
    res = {"wallet": wallet, "chains": {}, "skipped": []}
    for c in chains:
        if not evm.available(c):
            res["skipped"].append(c)
            continue
        try:
            res["chains"][c] = scan_chain(wallet, c)
        except Exception as e:
            log(f"approvals: {c} failed ({e})")
            res["chains"][c] = []
            res.setdefault("errors", {})[c] = str(e)[:120]
    allx = [a for v in res["chains"].values() for a in v]
    res["summary"] = {k: sum(1 for a in allx if a["risk"] == k) for k in ("danger", "high", "review", "ok")}
    return res


if __name__ == "__main__":
    r = scan(sys.argv[1], sys.argv[2:] or None)
    for c, items in r["chains"].items():
        for a in items:
            amt = "UNLIMITED" if a["unlimited"] else a["amount"]
            print(f"[{a['risk']:6}] {c:9} {a['symbol']:10} -> {a['spender']}  {amt}  {a['why']}")
    print(r["summary"], "skipped:", r["skipped"])
