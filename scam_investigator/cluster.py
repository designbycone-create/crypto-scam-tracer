"""Address clustering: find wallets the same operator likely controls.

On the XRP Ledger there is no UTXO co-spend heuristic, so clustering leans
on relationships that are strong signals of common control:

  1. Common funder   - the account that activated the scam wallet also
                       activated other accounts (siblings funded from one
                       source in a tight time window).
  2. Shared cash-out - the scam wallet and another wallet both pay out to
                       the same destination (+ destination tag).
  3. Same regular key / signer list - cryptographic shared control.
  4. Same Domain field - operators reuse a Domain across wallets.

Each finding is a *lead*, not proof. The output says which signal fired so a
human (or law enforcement) can weigh it. Nothing here identifies a person.
"""
from .ledger import Ledger, xrp, ripple_time
from .trace import LSF_REQUIRE_DEST_TAG, load_labels


async def _is_custodial(L, addr, labels):
    """Is this account an exchange / custodial wallet? If so, 'siblings it
    funded' are ordinary customers, not a cluster — and walking its history
    is huge. Detect via label or the Require-Destination-Tag flag."""
    if addr in labels:
        return True, f"labeled: {labels[addr]}"
    info = await L.account_info(addr) or {}
    if (info.get("Flags") or 0) & LSF_REQUIRE_DEST_TAG:
        return True, "account requires a destination tag (exchange deposit pattern)"
    return False, None


async def _funded_accounts(L, funder, limit_pages=25):
    """Accounts this funder activated (created), with time + amount."""
    txs = await L.account_tx(funder, forward=True, max_pages=limit_pages)
    created = []
    for tx in txs:
        if tx.get("TransactionType") != "Payment":
            continue
        for n in tx.get("_meta", {}).get("AffectedNodes", []):
            c = n.get("CreatedNode", {})
            if c.get("LedgerEntryType") == "AccountRoot":
                acct = c.get("NewFields", {}).get("Account")
                if acct and acct != funder:
                    created.append({"account": acct, "time": ripple_time(tx.get("date")),
                                    "xrp": xrp(tx.get("Amount")), "hash": tx["hash"]})
    return created


async def _outgoing_dests(L, addr):
    txs = await L.account_tx(addr, forward=True)
    dests = {}
    for tx in txs:
        if tx.get("Account") == addr and tx.get("TransactionType") == "Payment" \
           and tx.get("_meta", {}).get("TransactionResult") == "tesSUCCESS":
            key = (tx.get("Destination"), tx.get("DestinationTag"))
            dests.setdefault(key, 0)
            dests[key] += xrp(tx.get("_meta", {}).get("delivered_amount", tx.get("Amount"))) or 0
    return dests


async def cluster(scam_wallet, funder=None, max_siblings=40):
    """Build a cluster of leads around a scam wallet."""
    leads = {"common_funder": [], "shared_cashout": [], "shared_key": [], "shared_domain": [], "notes": []}
    labels = load_labels()
    async with Ledger() as L:
        info = await L.account_info(scam_wallet) or {}

        # Determine the funder if not supplied: first incoming payment that created the account.
        if funder is None:
            txs = await L.account_tx(scam_wallet, forward=True)
            for tx in txs:
                if any(n.get("CreatedNode", {}).get("NewFields", {}).get("Account") == scam_wallet
                       for n in tx.get("_meta", {}).get("AffectedNodes", [])):
                    funder = tx.get("Account")
                    break

        # 1. Common-funder siblings — but skip if the funder is an exchange.
        siblings = []
        if funder:
            custodial, why = await _is_custodial(L, funder, labels)
            if custodial:
                leads["notes"].append(f"Funder {funder} is an exchange/custodial wallet ({why}); "
                                      "accounts it funded are ordinary customers, not a cluster. "
                                      "Common-funder clustering skipped. The lead here is the exchange's "
                                      "own records on the customer behind that withdrawal.")
                leads["funder_is_exchange"] = {"funder": funder, "reason": why}
                siblings = []
            else:
                siblings = await _funded_accounts(L, funder)
                for s in siblings[:max_siblings]:
                    if s["account"] != scam_wallet:
                        leads["common_funder"].append(s)
                leads["notes"].append(f"Funder {funder} activated {len(siblings)} account(s). "
                                      "Siblings activated near the same time are stronger leads.")

        # 2. Shared cash-out: do siblings pay out to the same place the scam wallet does?
        scam_dests = await _outgoing_dests(L, scam_wallet)
        for s in leads["common_funder"][:max_siblings]:
            d = await _outgoing_dests(L, s["account"])
            shared = set(scam_dests) & set(d)
            if shared:
                leads["shared_cashout"].append({"account": s["account"],
                                                "shared_destinations": [{"to": k[0], "tag": k[1]} for k in shared]})

        # 3 & 4. Cryptographic / domain overlaps on the scam wallet itself
        if info.get("RegularKey"):
            leads["shared_key"].append({"scam_wallet_regular_key": info["RegularKey"],
                                        "note": "Any other account with this same RegularKey is co-controlled."})
        if info.get("Domain"):
            try:
                dom = bytes.fromhex(info["Domain"]).decode(errors="replace")
                leads["shared_domain"].append({"domain": dom, "note": "Operators reuse a Domain across wallets."})
            except Exception:
                pass

    leads["summary"] = {
        "funder": funder,
        "sibling_accounts": len(leads["common_funder"]),
        "shared_cashout_wallets": len(leads["shared_cashout"]),
    }
    return leads
