"""Three kinds of statement, kept apart on purpose.

FACT       Something the public ledger itself records. Always carries the
           transaction hash (or ledger object) it comes from, the raw response
           it was read from (sha256 of a captured blob), and -- once
           corroborated -- the second independent server that agreed.
           Anyone can re-check it without trusting ScamHunter.
DERIVED    A deterministic computation over FACTs (a path from the victim's
           payment to an exchange deposit; a sum). Lists the FACT ids it
           uses and the algorithm name/version. Re-running gives the same answer.
INFERENCE  An opinion produced by a heuristic (e.g. "this address belongs to
           exchange X", "these wallets are run by one operator"). Names the
           heuristic, its version, the FACTs it rests on, a confidence band,
           and the heuristic's documented failure modes. Never presented as fact.

The heuristic registry below is the methodology a witness would be asked
about under FRE 702 / Daubert: what it does, what it assumes, how it fails,
how it was tested. Every INFERENCE must name an entry here.
"""
import hashlib
import json

from .capture import canonical

KINDS = ("FACT", "DERIVED", "INFERENCE")
CONFIDENCE = ("low", "moderate", "high")

HEURISTICS = {
    "exchange-label/1": {
        "name": "Exchange attribution from published labels",
        "does": "Marks an address as belonging to an exchange when it appears in a public label list "
                "(XRPScan/Bithomp names, exchange-published addresses, community lists).",
        "assumes": "The label source was correct when published and the address has not changed hands.",
        "fails_when": ["Label list is wrong or stale", "Address was recycled or reassigned",
                       "Scammer chose a lookalike address that resembles a labelled one"],
        "safeguards": "Label source and retrieval time are recorded; two sources preferred; "
                      "for XRPL, a destination tag on the deposit is consistent with a custodial exchange.",
        "testing": "tests/test_evidence_offline.py exercises a labelled and an unlabelled address.",
    },
    "deposit-sweep/1": {
        "name": "Exchange deposit address via sweep pattern",
        "does": "Treats an unlabelled wallet as an exchange deposit address when it only receives and then "
                "forwards everything to a labelled exchange hot wallet.",
        "assumes": "Exchanges sweep customer deposit addresses to hot wallets.",
        "fails_when": ["Scammer imitates the sweep pattern with their own wallets",
                       "A personal wallet happens to forward everything once"],
        "safeguards": "Requires the sweep target to be a labelled exchange; reported as INFERENCE, "
                      "never as the exchange's admission.",
        "testing": "Unit test with a mock sweep and a mock non-sweep.",
    },
    "common-funder/1": {
        "name": "Common operator via shared funding source",
        "does": "Groups wallets that were activated (first funded) by the same account.",
        "assumes": "Whoever funds a new wallet usually controls it.",
        "fails_when": ["The funder is an exchange or faucet that funds many unrelated customers",
                       "Wallet-creation services"],
        "safeguards": "Funders that are labelled exchanges/services are excluded.",
        "testing": "Unit test excludes an exchange funder.",
    },
    "taint-follow/1": {
        "name": "Follow-the-funds path (first-in/first-out, largest outflow)",
        "does": "From the victim's payment, follows each wallet's subsequent outgoing payments in time order.",
        "assumes": "Funds received are the funds sent next. On a ledger money is fungible, so this is "
                   "a tracing convention, not a physical identity of coins.",
        "fails_when": ["Wallet mixes the victim's funds with others' (commingling)",
                       "Swaps/AMM/bridges change the asset"],
        "safeguards": "Each hop's amounts and times are FACTs; the convention is stated in the report; "
                      "commingled hops are flagged.",
        "testing": "Deterministic: same input ledger data always yields the same path.",
    },
    "behavior-signal/1": {
        "name": "Pre-screen behaviour signals (fresh wallet, pass-through, wallet factory, collector)",
        "does": "Flags wallet behaviour common in scam infrastructure.",
        "assumes": "Signals are risk indicators only; legitimate wallets can show them.",
        "fails_when": ["History is incomplete (limited by public data source)", "Legitimate new users"],
        "safeguards": "Signals requiring full history are suppressed when history is incomplete; "
                      "coverage limits are printed.",
        "testing": "shield/test_prescreen_offline.py",
    },
    # Mixer heuristics (the kind Noxos is still battle-testing). Registered so any use is
    # labelled as low-confidence INFERENCE with its failure modes, never presented as a link.
    "mixer-timing/1": {
        "name": "Mixer deposit/withdrawal timing and amount match",
        "does": "Pairs a mixer withdrawal with a deposit when amounts match and the gap is short or distinctive.",
        "assumes": "The depositor withdrew soon after and did not wait for the anonymity set to grow.",
        "fails_when": ["Many users deposit the same pool denomination in the same window (large anonymity set)",
                       "Depositor deliberately waited or split across pools",
                       "Coincidental timing"],
        "safeguards": "Reports the anonymity-set size for the window; confidence is capped at 'low' unless "
                      "independently corroborated (e.g. relayer or gas-funding link).",
        "testing": "Requires measured error rate via evidence/validate.py before use above 'low'.",
    },
    "relayer-linkage/1": {
        "name": "Shared relayer / gas-funding / tooling fingerprint",
        "does": "Links mixer withdrawals that used the same relayer, were gas-funded by the same address, or "
                "share transaction-construction fingerprints.",
        "assumes": "Public relayers serve many users; only a private or rarely used relayer is distinctive.",
        "fails_when": ["Popular public relayer (shared by thousands)", "Common wallet software produces the same fingerprint"],
        "safeguards": "Relayer popularity (users served in the period) is reported alongside the link.",
        "testing": "Requires measured error rate via evidence/validate.py before use above 'low'.",
    },
}

UNVALIDATED_CAP = {"mixer-timing/1": "low", "relayer-linkage/1": "low"}


def _id(kind, body):
    return kind[0] + "-" + hashlib.sha256(canonical(body).encode()).hexdigest()[:16]


class Findings:
    def __init__(self):
        self.items = {}

    def fact(self, chain, tx_hash, statement, fields, source_sha256, source_server):
        """`fields`: the exact ledger values asserted (e.g. Account, Destination, Amount, DestinationTag,
        ledger_index, close_time). These are re-checked against the raw blob by the verifier."""
        body = {"kind": "FACT", "chain": chain, "tx_hash": tx_hash, "statement": statement, "fields": fields}
        fid = _id("FACT", body)
        body.update({"id": fid, "sources": [{"sha256": source_sha256, "server": source_server}],
                     "corroborated": False})
        self.items.setdefault(fid, body)
        return fid

    def corroborate(self, fid, source_sha256, source_server, agrees, diff=None):
        f = self.items[fid]
        f["sources"].append({"sha256": source_sha256, "server": source_server, "agrees": agrees, "diff": diff})
        f["corroborated"] = all(s.get("agrees", True) for s in f["sources"]) and len(
            {s["server"] for s in f["sources"]}) >= 2

    def derived(self, statement, from_ids, algorithm, result):
        self._check(from_ids)
        body = {"kind": "DERIVED", "statement": statement, "from": sorted(from_ids),
                "algorithm": algorithm, "result": result}
        fid = _id("DERIVED", body)
        body["id"] = fid
        self.items.setdefault(fid, body)
        return fid

    def inference(self, statement, from_ids, heuristic, confidence, basis=""):
        if heuristic not in HEURISTICS:
            raise ValueError(f"unknown heuristic {heuristic!r}: every inference must use a documented method")
        if confidence not in CONFIDENCE:
            raise ValueError("confidence must be low/moderate/high")
        cap = UNVALIDATED_CAP.get(heuristic)
        if cap and CONFIDENCE.index(confidence) > CONFIDENCE.index(cap):
            raise ValueError(f"{heuristic} has no measured error rate yet; confidence is capped at {cap!r}")
        self._check(from_ids)
        body = {"kind": "INFERENCE", "statement": statement, "from": sorted(from_ids), "heuristic": heuristic,
                "confidence": confidence, "basis": basis,
                "known_failure_modes": HEURISTICS[heuristic]["fails_when"]}
        fid = _id("INFERENCE", body)
        body["id"] = fid
        self.items.setdefault(fid, body)
        return fid

    def _check(self, ids):
        missing = [i for i in ids if i not in self.items]
        if missing:
            raise ValueError(f"references unknown finding(s): {missing}")

    def by_kind(self, kind):
        return [v for v in self.items.values() if v["kind"] == kind]

    def to_json(self):
        return json.dumps(sorted(self.items.values(), key=lambda v: (KINDS.index(v["kind"]), v["id"])),
                          indent=2, ensure_ascii=False)


# --- XRPL helpers: turn a captured `tx` response into a FACT ----------------

XRPL_FIELDS = ("TransactionType", "Account", "Destination", "DestinationTag", "SourceTag", "Amount",
               "Fee", "Sequence", "ledger_index", "date")


def xrpl_tx_fields(resp):
    r = resp.get("result", resp) if isinstance(resp, dict) else {}
    tx = r.get("tx_json") or r.get("tx") or r
    out = {k: (tx.get(k) if k in tx else r.get(k)) for k in XRPL_FIELDS}
    meta = r.get("meta") or {}
    out["delivered_amount"] = meta.get("delivered_amount")
    out["result"] = meta.get("TransactionResult")
    out["validated"] = r.get("validated")
    return {k: v for k, v in out.items() if v is not None}


def describe_xrpl(f):
    amt = f.get("delivered_amount", f.get("Amount"))
    if isinstance(amt, str):
        amt = f"{int(amt) / 1e6:,.6f} XRP"
    elif isinstance(amt, dict):
        amt = f"{amt.get('value')} {amt.get('currency')} (issuer {amt.get('issuer')})"
    tag = f", destination tag {f['DestinationTag']}" if "DestinationTag" in f else ""
    return f"{f.get('Account')} sent {amt} to {f.get('Destination')}{tag} (ledger {f.get('ledger_index')}, result {f.get('result')})"
