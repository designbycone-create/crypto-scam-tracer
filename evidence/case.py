"""Build a sealed court bundle from the Desk's own case files.

Reads victim.json (the victim's payment tx) and cashouts.jsonl (each cash-out the
watcher caught: exchange address, destination tag, tx hash), turns each
transaction into a two-server-corroborated FACT, and states the exchange
attribution as an INFERENCE (exchange-label/1). Then seals the bundle.

    from evidence import case; case.seal()        # or the Desk's /evidence page
"""
import json
import os
import re
from datetime import datetime

from . import corroborate, package
from .facts import Findings

TXH = re.compile(r"^[0-9A-Fa-f]{64}$")


def _j(p, default):
    try:
        with open(p, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return default


def cashouts():
    """Cash-outs from the live watcher (cashouts.jsonl, 'your funds' path') and from the network map
    (network_map.json endpoints: exchange deposits made by any wallet in the mapped scam network)."""
    out = {}
    for ep in (_j("network_map.json", {}) or {}).get("endpoints", []) or []:
        if ep.get("hash"):
            out[ep["hash"]] = dict(ep, source="network map")
    try:
        with open("cashouts.jsonl", encoding="utf-8-sig") as f:
            for line in f:
                try:
                    ep = json.loads(line)
                    out[ep["hash"]] = dict(ep, source="live watcher (your funds' path)")
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    return list(out.values())


def plan():
    """What a seal would include, without any network calls (for the Desk page)."""
    v = _j("victim.json", {})
    vtx = (v.get("tx_hash") or "").strip()
    return {"victim_tx": vtx if TXH.match(vtx) else None, "cashouts": cashouts(),
            "scam_wallet": v.get("scam_wallet"), "ic3": v.get("ic3_id")}


def seal(examiner_name="", examiner_role="", case_id=None, log=print):
    p = plan()
    f = Findings()
    errors = []
    vid = None
    if p["victim_tx"]:
        try:
            vid, _ = corroborate.xrpl_fact(f, p["victim_tx"].upper())
        except Exception as e:
            errors.append(f"victim payment {p['victim_tx'][:12]}...: {e}")
    hop_ids = []
    for ep in p["cashouts"]:
        h = (ep.get("hash") or "").upper()
        if not TXH.match(h):
            continue
        try:
            fid, fct = corroborate.xrpl_fact(f, h)
        except Exception as e:
            errors.append(f"cash-out {h[:12]}...: {e}")
            continue
        hop_ids.append(fid)
        label = ep.get("swap_name") if ep.get("is_swap") else ep.get("label")
        if label:
            tag = fct["fields"].get("DestinationTag")
            what = "bridge/swap service" if ep.get("is_swap") else "exchange"
            stmt = (f"{fct['fields'].get('Destination')} is an address of {what} {label!s}"
                    + (f"; destination tag {tag} identifies the receiving customer account at that service" if tag is not None else ""))
            f.inference(stmt, [fid], "exchange-label/1", "moderate",
                        basis=f"published label '{label}', recorded by the {ep.get('source', 'watcher')} ({ep.get('detected') or ep.get('time')})")
    if vid and hop_ids:
        f.derived(f"After the victim's payment to the scam wallet, wallets in the mapped scam network made {len(hop_ids)} "
                  "payment(s) to exchange/bridge addresses; each fact shows the sending account. The wallets' link to the "
                  "scam wallet comes from the network map. Whether a given payment carried the victim's own funds is a "
                  "tracing convention, not a ledger fact (see methodology).",
                  [vid] + hop_ids, "taint-follow/1", {"cashouts": len(hop_ids)})
    if not f.items:
        raise RuntimeError("Nothing to seal: no readable transactions. " + "; ".join(errors))
    cid = case_id or ("SH-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    scope = {"Purpose": "Document the movement of funds from the victim's payment to exchange/bridge cash-out points",
             "Scam wallet": p["scam_wallet"] or "(not set)", "IC3 complaint": p["ic3"] or "(not set)",
             "Transactions examined": len(f.by_kind("FACT"))}
    if errors:
        scope["Could not be read (excluded)"] = "; ".join(errors)
    actions = "custody_log.jsonl" if os.path.exists("custody_log.jsonl") else None
    res = package.build(f, cid, scope=scope, examiner={"name": examiner_name, "role": examiner_role},
                        actions_log=actions)
    res["errors"] = errors
    res["counts"] = {k: len(f.by_kind(k)) for k in ("FACT", "DERIVED", "INFERENCE")}
    log(f"Sealed {cid}: {res['counts']} -> {res['zip']}")
    return res
