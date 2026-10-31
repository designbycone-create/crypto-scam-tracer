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


def find_chain(wallet, chain, since_epoch=None):
    """EVM: token transfers OUT of the wallet in transactions the wallet did not send."""
    wallet = wallet.lower()
    drains = defaultdict(lambda: {"hash": None, "time": None, "out": []})
    for t in evm.token_transfers(chain, wallet):
        h = (t.get("hash") or "").lower()
        if (t.get("from") or "").lower() != wallet:
            continue
        try:
            ep = int(t.get("timeStamp") or 0)
        except ValueError:
            ep = 0
        if since_epoch and ep and ep < since_epoch:
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
        except Exception:
            tx = {}
        sender = (tx.get("from") or "").lower()
        if not sender or sender == wallet:
            continue          # the wallet sent this itself: a normal transfer, not a drain
        contract = (tx.get("to") or "").lower()
        try:
            rc = evm.rpc(chain, "eth_getTransactionReceipt", [h]) or {}
        except Exception:
            rc = {}
        split = Counter()
        for lg in rc.get("logs", []):
            tp = lg.get("topics") or []
            if len(tp) == 3 and tp[0] == evm.TRANSFER and evm.topic_addr(tp[1]) in (wallet, contract):
                split[evm.topic_addr(tp[2])] += int(lg.get("data") or "0x0", 16)
        split.pop(wallet, None)
        if contract in split and len(split) > 1:
            split.pop(contract)   # contract only passed the tokens through to the real receivers
        results.append({"chain": chain, "hash": h, "time": d["time"], "tokens": d["out"], "tx_sender": sender,
                        "drainer_contract": contract, "receivers": dict(split) or {o["to"]: 1 for o in d["out"]}})
    return results


def analyze(wallet, chains=None, since_epoch=None, log=print):
    from .approvals import family
    fam, fam_chains = family(wallet)
    drains, notes = [], []
    if fam == "evm":
        chains = chains or fam_chains
        for c in chains:
            n = evm.coverage_note(c)
            if n:
                notes.append(n)
            try:
                drains += find_chain(wallet, c, since_epoch)
            except Exception as e:
                log(f"drain: {c} failed ({e})")
    elif fam in ("tron", "solana", "xrpl"):
        chains = [fam]
        try:
            drains += __import__(f"shield.{fam}", fromlist=["x"]).drains(wallet)
        except Exception as e:
            log(f"drain: {fam} failed ({e})")
    elif fam == "bitcoin":
        chains = ["bitcoin"]
        notes.append("Bitcoin has no approvals: if coins left without you, the seed/private key was exposed. Every outgoing "
                     "transaction is signed by your key, so we can't separate yours from the thief's -- check your outgoing "
                     "history and start a case with the thief's address.")
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
        appr = approvals_scan(wallet, chains=(list({d["chain"] for d in drains}) or chains) if fam == "evm" else None, log=log)
    except Exception as e:
        appr = {"error": str(e)}
    taken = [t for l, t in (appr.get("takeover") or []) if l == "danger"] if isinstance(appr, dict) else []
    steps = [
            "REVOKE every permission marked danger/high now (links and instructions below) - an open approval keeps draining new deposits.",
            "Move anything left in this wallet to a NEW wallet created on a clean device. Treat this wallet as burned.",
            "SEAL 911 (Telegram @seal_911_bot): send the drainer contract + receiver wallets below.",
            "Report the site you connected to: Chainabuse, Google Safe Browsing, the domain's registrar abuse form.",
            "Start tracing: the receiver wallets are seeded into the multi-chain tracer; USDT/USDC there can be frozen by the issuer."]
    if taken:
        steps = ["ACCOUNT TAKEN OVER: " + taken[0],
                 "Contact SEAL 911 now (Telegram @seal_911_bot) -- they can sometimes race the attacker or coordinate a rescue.",
                 "Stop sending anything to this address (including from exchanges) -- the attacker can move it.",
                 ] + steps[2:]
    return {
        "wallet": wallet, "family": fam, "notes": notes, "drains": sorted(drains, key=lambda d: d["time"] or 0),
        "drainer_contracts": contracts, "receivers": seeds,
        "likely_fee_wallets": [k for k, n in fee.most_common() if n >= 1],
        "open_approvals": appr,
        "next_steps": steps,
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
