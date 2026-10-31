"""I signed something: find the drain, the drainer and where the money went.

A drainer never asks the victim to SEND. The victim signs an approval/permit;
then the drainer sends its own transaction that pulls tokens out with
transferFrom. So a drain shows up as a token transfer OUT of the victim's
wallet in a transaction the victim did NOT send.

For each such transaction we record
  drainer      the contract/wallet that sent the pulling transaction (tx.to /
               tx.from of the drain tx)
  receivers    where the tokens landed; when one drain tx splits the loot
               (e.g. ~80/20), the smaller recurring cut is typically the kit
               operator's FEE wallet -- the thread that links many sites
               to one operator
and return everything the Desk needs: revoke-first actions, tracer seeds,
and a case summary.

    python -m shield.drain 0xVictimWallet [chain ...]
"""
import sys
from collections import Counter, defaultdict

from . import evm


def _own_sent(chain, wallet):
    sent = set()
    for tx in evm.explorer(chain, module="account", action="txlist", address=wallet, page=1, offset=1000, sort="desc"):
        if (tx.get("from") or "").lower() == wallet:
            sent.add((tx.get("hash") or "").lower())
    return sent


def find_chain(wallet, chain, since_epoch=None):
    wallet = wallet.lower()
    sent = _own_sent(chain, wallet)
    drains = defaultdict(lambda: {"hash": None, "time": None, "out": [], "in_tx": []})
    toks = evm.explorer(chain, module="account", action="tokentx", address=wallet, page=1, offset=1000, sort="desc")
    for t in toks:
        h = (t.get("hash") or "").lower()
        if (t.get("from") or "").lower() != wallet or h in sent:
            continue
        try:
            ep = int(t.get("timeStamp") or 0)
        except ValueError:
            ep = 0
        if since_epoch and ep < since_epoch:
            continue
        d = drains[h]
        d["hash"], d["time"] = h, ep
        dec = int(t.get("tokenDecimal") or 18)
        d["out"].append({"token": (t.get("contractAddress") or "").lower(), "symbol": t.get("tokenSymbol") or "token",
                         "amount": int(t.get("value") or 0) / 10 ** dec, "to": (t.get("to") or "").lower()})
    results = []
    for h, d in drains.items():
        try:
            tx = evm.rpc(chain, "eth_getTransactionByHash", [h]) or {}
            rc = evm.rpc(chain, "eth_getTransactionReceipt", [h]) or {}
        except Exception:
            tx, rc = {}, {}
        sender = (tx.get("from") or "").lower()
        contract = (tx.get("to") or "").lower()
        # every token transfer in the drain tx: shows the split between affiliate and kit operator
        split = Counter()
        for lg in rc.get("logs", []):
            tp = lg.get("topics") or []
            if len(tp) == 3 and tp[0] == "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef":
                if evm.topic_addr(tp[1]) == wallet or evm.topic_addr(tp[1]) == contract:
                    split[evm.topic_addr(tp[2])] += int(lg.get("data") or "0x0", 16)
        split.pop(wallet, None)
        if contract in split and len(split) > 1:
            split.pop(contract)   # contract only passed the tokens through to the real receivers
        results.append({"chain": chain, "hash": h, "time": d["time"], "tokens": d["out"], "tx_sender": sender,
                        "drainer_contract": contract, "receivers": dict(split) or {o["to"]: 1 for o in d["out"]}})
    return results


def analyze(wallet, chains=None, since_epoch=None, log=print):
    chains = chains or [c for c in evm.CHAINS if evm.available(c)]
    drains = []
    for c in chains:
        try:
            drains += find_chain(wallet, c, since_epoch)
        except Exception as e:
            log(f"drain: {c} failed ({e})")
    receivers_all = Counter()
    for d in drains:
        for r in d["receivers"]:
            receivers_all[(d["chain"], r)] += 1
    # fee wallet heuristic: a receiver that takes the SMALLER share in split drains, repeatedly
    fee = Counter()
    for d in drains:
        if len(d["receivers"]) >= 2:
            small = min(d["receivers"].items(), key=lambda kv: kv[1])[0]
            fee[(d["chain"], small)] += 1
    seeds = sorted({(c, r) for (c, r) in receivers_all})
    contracts = sorted({(d["chain"], d["drainer_contract"]) for d in drains if d["drainer_contract"]})
    try:
        from .approvals import scan as approvals_scan
        appr = approvals_scan(wallet, chains=list({d["chain"] for d in drains}) or chains, log=log)
    except Exception as e:
        appr = {"error": str(e)}
    return {
        "wallet": wallet, "drains": sorted(drains, key=lambda d: d["time"] or 0),
        "drainer_contracts": contracts, "receivers": seeds,
        "likely_fee_wallets": [k for k, n in fee.most_common() if n >= 1],
        "open_approvals": appr,
        "next_steps": [
            "REVOKE every approval marked danger/high now (revoke.cash links below) - an open approval keeps draining new deposits.",
            "Move anything left in this wallet to a NEW wallet created on a clean device. Treat this wallet as burned.",
            "SEAL 911 (Telegram @seal_911_bot): send the drainer contract + receiver wallets below.",
            "Report the site you connected to: Chainabuse, Google Safe Browsing, the domain's registrar abuse form.",
            "Start tracing: the receiver wallets are seeded into the multi-chain tracer; USDT/USDC there can be frozen by the issuer.",
        ],
    }


def seed_tracer(result):
    """Hand receivers to the multi-chain tracer (same mechanism as Incident mode)."""
    try:
        from responder.incident import _seed_multichain
    except Exception:
        return 0
    n = 0
    for chain, addr in result.get("receivers", []):
        n += bool(_seed_multichain(chain, addr, None))
    return n


if __name__ == "__main__":
    r = analyze(sys.argv[1], sys.argv[2:] or None)
    for d in r["drains"]:
        print(d["chain"], d["hash"], [f"{t['amount']:.4f} {t['symbol']}" for t in d["tokens"]], "->", list(d["receivers"]))
    print("drainer contracts:", r["drainer_contracts"])
    print("likely fee wallets:", r["likely_fee_wallets"])
