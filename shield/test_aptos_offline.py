"""Offline test: Aptos support (shapes copied from real mainnet transactions, Nov 2026).
    python shield/test_aptos_offline.py
"""
import os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(tempfile.mkdtemp())
from shield import aptos as ap, approvals, drain, prescreen
from responder.addresses import extract
from freezekit.chainlookup import detect_address

ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
VICTIM = "0xcf869189c785beaaad2f5c636ced4805aeae9cbf49070dc93aed2f16b99012a"     # 63 hex: Aptos drops leading zeros
RCV = "0xc30ae4d5347a6787a636221034619fd1e43993f4e6e34ddd7fde4bf87dea2efc"
DRAINER = "0x" + "d" * 64
USDT = "0x357b0b74bc833e95a115ad22604854d6b0fca151cecd94111770e5d6ffc9dc2b"
S_V, S_R, S_D, S_VA = "0x" + "7" * 64, "0x" + "8" * 64, "0x" + "9" * 64, "0x" + "6" * 64
now = int(time.time())


def ftx(ver, fn, amount, to_store, to_owner_in_changes=True, meta=USDT, from_store=S_V, ts=None):
    ch = [{"address": from_store, "data": {"type": "0x1::fungible_asset::FungibleStore", "data": {"metadata": {"inner": meta}}}},
          {"address": from_store, "data": {"type": "0x1::object::ObjectCore", "data": {"owner": VICTIM}}},
          {"address": to_store, "data": {"type": "0x1::fungible_asset::FungibleStore", "data": {"metadata": {"inner": meta}}}}]
    if to_owner_in_changes:
        ch.append({"address": to_store, "data": {"type": "0x1::object::ObjectCore", "data": {"owner": RCV}}})
    return {"type": "user_transaction", "version": str(ver), "hash": f"0xh{ver}", "sender": VICTIM, "success": True,
            "timestamp": str(((ts or now - 3600)) * 1_000_000), "payload": {"function": fn, "arguments": []},
            "events": [{"type": "0x1::fungible_asset::Withdraw", "data": {"amount": str(amount), "store": from_store}},
                       {"type": "0x1::fungible_asset::Deposit", "data": {"amount": str(amount), "store": to_store}},
                       {"type": "0x1::transaction_fee::FeeStatement", "data": {}}],
            "changes": ch}


TXS = [ftx(100, "0x1::primary_fungible_store::transfer", 4093141921, S_R),
       ftx(101, "0xbadbad::airdrop::claim_rewards", 900_000_000, S_D, to_owner_in_changes=False),
       ftx(102, "0x1::aptos_account::transfer", 250_000_000, S_R, meta="0xa", from_store=S_VA)]
ACCOUNT_RES = {"signer_capability_offer": {"for": {"vec": []}}, "rotation_capability_offer": {"for": {"vec": [DRAINER]}}}


def GET(path):
    if path.startswith(f"/accounts/{ap.norm(VICTIM)}/transactions"):
        return TXS
    if path == f"/accounts/{ap.norm(VICTIM)}":
        return {"sequence_number": "3", "authentication_key": ap.norm(VICTIM)}
    if path.endswith("/resource/0x1::account::Account"):
        return {"data": ACCOUNT_RES}
    if path == f"/accounts/{ap.norm(S_D)}/resource/0x1::object::ObjectCore":
        return {"data": {"owner": DRAINER}}
    if path.endswith("/resource/0x1::fungible_asset::Metadata"):
        return {"data": {"symbol": "USDt", "decimals": 6}}
    if path == "/view:balance":
        return ["150000000"]
    if path.startswith("/transactions/by_hash/0xh100"):
        return TXS[0]
    return None


ap.GET = GET
ap.GQL = lambda q, v: (_ for _ in ()).throw(RuntimeError("429 anonymous rate limit"))

# detection
r.append(ok(extract(f"send to {RCV} now") == [("aptos", RCV)], "64-hex address detected as Aptos"))
r.append(ok(extract("0x10ed43c718714eb63d5aa57b78b54704e256024e")[0][0] == "ethereum", "40-hex is still EVM"))
r.append(ok(detect_address(VICTIM) == ["aptos"] and ap.norm(VICTIM).startswith("0x0cf8") and len(ap.norm(VICTIM)) == 66,
            "63-hex address normalized with the leading zero Aptos drops"))
r.append(ok(approvals.family(RCV) == ("aptos", ["aptos"]), "shield routes Aptos addresses to the Aptos module"))

# parsing
m = ap.moves_for(TXS[0], VICTIM)
r.append(ok(len(m) == 1 and m[0]["dir"] == "out" and m[0]["cp"] == ap.norm(RCV) and abs(m[0]["amount"] - 4093.141921) < 1e-6
            and m[0]["asset"] == "USDt", "fungible-asset transfer: receiver from store owner, amount with token decimals"))
m = ap.moves_for(TXS[1], VICTIM)
r.append(ok(m and m[0]["cp"] == ap.norm(DRAINER), "store owner looked up when not in the transaction's changes"))
m = ap.moves_for(TXS[2], VICTIM)
r.append(ok(m and m[0]["asset"] == "APT" and m[0]["amount"] == 2.5, "APT (0xa) amounts use 8 decimals"))

# shield
res = approvals.scan(VICTIM)
lv = [l for l, _ in res["takeover"]]
r.append(ok("danger" in lv and any("replace your account's key" in t for _, t in res["takeover"]),
            "rotation-capability offer flagged as DANGER (account takeover)"))
r.append(ok(any("no token approvals" in n for n in res["notes"]), "explains Aptos has no approvals"))
d = ap.drains(VICTIM)
r.append(ok(len(d) == 1 and d[0]["function"] == "0xbadbad::airdrop::claim_rewards" and ap.norm(DRAINER) in d[0]["receivers"],
            "drain: assets pulled by an unknown 'claim' contract found; plain transfers ignored"))
a = drain.analyze(VICTIM)
r.append(ok(a and (a.get("drains") or a.get("findings") or a.get("chains")), "drain.analyze runs for Aptos"))

# pre-screen
p = prescreen.screen(RCV)
r.append(ok(p["ok"] and p["chain"] == "aptos", f"pre-screen accepts Aptos ({p.get('verdict')})"))
p = prescreen.screen(VICTIM)
covs = [f["text"] for f in p["findings"] if f["section"] == "Coverage"]
r.append(ok(p["ok"] and covs and "RECEIVED" in covs[0], "pre-screen states that received payments weren't checked without an indexer key"))
r.append(ok(not any("Fresh" in f["text"] for f in p["findings"]), "no false 'fresh wallet' claim when history is incomplete"))

# tracer adapter
from multichain.registry import get_adapter
outs = get_adapter("aptos").outgoing(VICTIM)
r.append(ok(len(outs) == 3 and {o.to for o in outs} == {ap.norm(RCV), ap.norm(DRAINER)} and outs[0].chain == "aptos",
            "tracer adapter returns outgoing Aptos transfers"))

# setup lookup by hash
from freezekit import chainlookup
lk = chainlookup.aptos_tx("0xh100")
r.append(ok(lk and lk["to"] == ap.norm(RCV) and "USDt" in lk["amount"], "setup lookup finds the scammer from an Aptos tx hash"))

print(f"{sum(r)}/{len(r)} passed")
sys.exit(0 if all(r) else 1)
