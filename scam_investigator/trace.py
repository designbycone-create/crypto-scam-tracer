"""Follow the money: hop-by-hop trace of funds leaving a scam wallet.

The goal is to find the point where stolen XRP lands somewhere that keeps
records on its customers (an exchange or other custodial service). That is
the one place a freeze or a law-enforcement subpoena can reach.
"""
import json
import os
import urllib.request

from .ledger import Ledger, xrp, ripple_time

HERE = os.path.dirname(__file__)
LABELS_FILE = os.path.join(HERE, "labels.json")

# Exchanges almost always set "Require Destination Tag" on their deposit
# accounts so they can tell customers apart. (Sequence numbers are NOT a
# signal: new accounts start their sequence at the creation ledger index.)
LSF_REQUIRE_DEST_TAG = 0x00020000


def load_labels():
    try:
        with open(LABELS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def xrpscan_name(addr):
    """Public label from XRPScan's API, if it has one (best effort)."""
    try:
        req = urllib.request.Request(f"https://api.xrpscan.com/api/v1/account/{addr}",
                                     headers={"User-Agent": "scam-investigator/1.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read().decode())
        name = data.get("accountName") or {}
        if isinstance(name, dict) and name.get("name"):
            return name.get("name"), name.get("desc") or ""
    except Exception:
        pass
    return None, None


async def describe_account(L, addr, labels, use_xrpscan=True):
    info = await L.account_info(addr) or {}
    label = labels.get(addr)
    source = "labels.json" if label else None
    if not label and use_xrpscan:
        n, d = xrpscan_name(addr)
        if n:
            label, source = f"{n} {('(' + d + ')') if d else ''}".strip(), "xrpscan"
    return {
        "address": addr,
        "balance_xrp": xrp(info.get("Balance")) if info else None,
        "sequence": info.get("Sequence"),
        "exists": bool(info),
        "domain": bytes.fromhex(info["Domain"]).decode(errors="replace") if info.get("Domain") else None,
        "requires_dest_tag": bool((info.get("Flags") or 0) & LSF_REQUIRE_DEST_TAG),
        "label": label,
        "label_source": source,
    }


def classify(tx):
    """Return the direction of a payment relative to its account."""
    return tx.get("TransactionType"), tx.get("_meta", {}).get("TransactionResult")


async def profile_wallet(L, addr):
    """Incoming victims, outgoing payments, and who activated the wallet."""
    txs = await L.account_tx(addr, forward=True)
    incoming, outgoing, activation = [], [], None
    for tx in txs:
        ttype, result = classify(tx)
        if result != "tesSUCCESS":
            continue
        meta = tx["_meta"]
        delivered = meta.get("delivered_amount", tx.get("Amount"))
        row = {
            "hash": tx["hash"], "time": ripple_time(tx.get("date")), "type": ttype,
            "from": tx.get("Account"), "to": tx.get("Destination"),
            "destination_tag": tx.get("DestinationTag"), "source_tag": tx.get("SourceTag"),
            "xrp": xrp(delivered), "amount_raw": delivered if not isinstance(delivered, str) else None,
        }
        created = any(n.get("CreatedNode", {}).get("LedgerEntryType") == "AccountRoot"
                      and n["CreatedNode"].get("NewFields", {}).get("Account") == addr
                      for n in meta.get("AffectedNodes", []))
        if created and activation is None:
            activation = row
        if tx.get("Account") == addr:
            outgoing.append(row)
        elif tx.get("Destination") == addr:
            incoming.append(row)
    return {"incoming": incoming, "outgoing": outgoing, "activation": activation, "tx_count": len(txs)}


async def trace(start, max_depth=4, min_xrp=50, use_xrpscan=True):
    """Breadth-first trace from `start`. Stops at exchange deposits, labeled
    services, and payments below `min_xrp` (dust and fee noise)."""
    labels = load_labels()
    async with Ledger() as L:
        root_profile = await profile_wallet(L, start)
        nodes = {start: await describe_account(L, start, labels, use_xrpscan)}
        nodes[start]["role"] = "scam wallet"
        edges, endpoints = [], []
        frontier, seen = [(start, 0)], {start}
        profiles = {start: root_profile}

        while frontier:
            addr, depth = frontier.pop(0)
            prof = profiles.get(addr) or await profile_wallet(L, addr)
            profiles[addr] = prof
            for p in prof["outgoing"]:
                if p["type"] != "Payment" or (p["xrp"] is not None and p["xrp"] < min_xrp):
                    continue
                dest = p["to"]
                edges.append({**p, "depth": depth + 1})
                if dest not in nodes:
                    nodes[dest] = await describe_account(L, dest, labels, use_xrpscan)
                n = nodes[dest]
                custodial = (p["destination_tag"] is not None or n["label"] is not None
                             or n["requires_dest_tag"])
                if custodial:
                    n["role"] = "likely exchange / custodial deposit"
                    endpoints.append({"address": dest, "label": n["label"], "destination_tag": p["destination_tag"],
                                      "xrp": p["xrp"], "hash": p["hash"], "time": p["time"], "depth": depth + 1})
                elif dest not in seen and depth + 1 < max_depth:
                    n["role"] = "intermediate wallet (hop)"
                    seen.add(dest)
                    frontier.append((dest, depth + 1))
                else:
                    n.setdefault("role", "untraced (depth limit)")

        # Who sent the victims' money, and who activated the wallet
        senders = {}
        for p in root_profile["incoming"]:
            senders.setdefault(p["from"], {"payments": 0, "xrp": 0.0})
            senders[p["from"]]["payments"] += 1
            senders[p["from"]]["xrp"] += p["xrp"] or 0
        for s in senders:
            if s not in nodes:
                nodes[s] = await describe_account(L, s, labels, use_xrpscan)
            nodes[s].setdefault("role", "victim payment source")
        act = root_profile["activation"]
        if act and act["from"] not in nodes:
            nodes[act["from"]] = await describe_account(L, act["from"], labels, use_xrpscan)

    return {
        "start": start,
        "server": "XRPL mainnet",
        "summary": {
            "balance_xrp": nodes[start]["balance_xrp"],
            "victim_payments": len(root_profile["incoming"]),
            "victim_sources": len(senders),
            "total_received_xrp": round(sum(p["xrp"] or 0 for p in root_profile["incoming"]), 6),
            "outgoing_payments": len(root_profile["outgoing"]),
            "exchange_endpoints": len(endpoints),
        },
        "activation": act,
        "victim_sources": senders,
        "incoming": root_profile["incoming"],
        "edges": edges,
        "endpoints": endpoints,
        "nodes": nodes,
    }
