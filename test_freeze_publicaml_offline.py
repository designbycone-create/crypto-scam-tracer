"""Offline tests: on-chain issuer-freeze check and the Public AML second opinion in the pre-screen.
    python test_freeze_publicaml_offline.py
"""
import json, os, shutil, sys, tempfile
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
WORK = tempfile.mkdtemp(prefix="sh_freeze_")
os.chdir(WORK)
from shield import evm, tron, issuerfreeze as F, publicaml as P, prescreen  # noqa: E402

ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
LAZ = "0x08723392ed15743cc38513c4925f5e6be5c17243"
CLEAN = "0x1111111111111111111111111111111111111111"
seen = []

def rpc(chain, method, params):
    seen.append((chain, params[0]["to"], params[0]["data"][:10]))
    frozen = params[0]["data"].endswith(LAZ[2:])
    return "0x" + "0" * 63 + ("1" if frozen else "0")

evm.RPC_POST = rpc
res = F.check(LAZ, "ethereum")
r.append(ok([(x["token"], x["frozen"]) for x in res] == [("USDT", True), ("USDC", True)], "sanctioned address: USDT and USDC both frozen on Ethereum"))
r.append(ok(("ethereum", "0xdAC17F958D2ee523a2206206994597C13D831ec7", "0xe47d6060") in seen and
            ("ethereum", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0xfe575a87") in seen,
            "asks Tether's and Circle's own contracts with the right functions"))
r.append(ok(all(not x["frozen"] for x in F.check(CLEAN, "ethereum")), "ordinary address: not frozen"))
r.append(ok([x["token"] for x in F.check(LAZ, "base")] == ["USDC"] and F.check(LAZ, "bsc") == [], "USDC checked on Base; chains without a verified contract skipped"))
r.append(ok(any(l == "stop" and "Tether has frozen USDT" in t for l, t in F.findings(LAZ, "ethereum")), "frozen address -> STOP finding in plain words"))
evm.RPC_POST = lambda *a: (_ for _ in ()).throw(OSError("rpc down"))
r.append(ok(all(x["frozen"] is None for x in F.check(LAZ, "ethereum")) and F.findings(LAZ, "ethereum") == [],
            "RPC failure is 'unknown', never reported as not frozen or frozen"))
tron.POST = lambda path, body: {"constant_result": ["0" * 63 + ("1" if body["parameter"].endswith("aa" * 20) else "0")]}
real_hex = tron.to_hex20
tron.to_hex20 = lambda a: "aa" * 20 if a == "TFrozenXXXXXXXXXXXXXXXXXXXXXXXXXXX" else "bb" * 20
r.append(ok(F.check("TFrozenXXXXXXXXXXXXXXXXXXXXXXXXXXX", "tron")[0]["frozen"] is True and
            F.check("TCleanXXXXXXXXXXXXXXXXXXXXXXXXXXXX", "tron")[0]["frozen"] is False, "Tron USDT freeze read via TronGrid"))
tron.to_hex20 = real_hex

# Public AML
calls = []
def pa(url, body):
    calls.append(body)
    a = body["addresses"][0]["wallet_address"]
    if a == LAZ:
        return {"entities": [{"wallet_address": a, "label": "Lazarus Group", "axes": {"legal_status": {"category": "sanction"}},
                              "risk": {"score": 100.0, "level": "CRITICAL", "breakdown": {"propagated_sources": [
                                  {"category": "sanction", "source": "ofac:sdn_advanced", "hops": 0}]}}}], "not_found": []}
    if a == "THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa":
        return {"entities": [{"label": None, "axes": {}, "risk": {"score": 50.0, "level": "MEDIUM"}}], "not_found": []}
    if a == "0xC4026b06D82b0F0B363eda0642D61CfbDc17884e":
        return {"entities": [{"label": None, "axes": {}, "risk": {"score": 0.0, "level": "LOW"}}], "not_found": []}
    return {"entities": [], "not_found": [{"reason": "address_not_found"}]}
P.POST = pa
f = P.findings(LAZ, "ethereum")
r.append(ok(f[0][0] == "stop" and "Lazarus Group" in f[0][1] and "ofac:sdn_advanced" in f[0][1], "sanctioned address: STOP with who and why"))
r.append(ok(P.findings("THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa", "tron")[0][0] == "caution", "medium score: caution"))
low = P.findings("0xC4026b06D82b0F0B363eda0642D61CfbDc17884e", "ethereum")
r.append(ok(low[0][0] == "info" and "not a guarantee" in low[0][1], "low score shown as info with 'not a guarantee', never as safe"))
nf = P.findings("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bitcoin")
r.append(ok("not the same as clean" in nf[0][1], "not found: says it's not the same as clean"))
n = len(calls)
r.append(ok(P.findings(LAZ, "polygon") == [] and len(calls) == n, "chains Public AML doesn't cover aren't sent"))
json.dump({"publicaml": False}, open("config.json", "w"))
r.append(ok(P.findings(LAZ, "ethereum") == [] and len(calls) == n, "\"publicaml\": false keeps every lookup on this computer"))
os.remove("config.json")
P.POST = lambda *a: (_ for _ in ()).throw(OSError("down"))
r.append(ok(P.findings(LAZ, "ethereum") == [], "Public AML down: silently skipped"))

# pre-screen integration: the OPTIMJACK address stays STOP even though Public AML scores it 0
P.POST = pa
evm.RPC_POST = rpc
prescreen.history_evm = lambda a, c, *k, **kw: {"exists": True, "moves": [], "balance": None}
res = prescreen.screen("0xC4026b06D82b0F0B363eda0642D61CfbDc17884e", "ethereum", log=lambda *_: None)
secs = {x["section"] for x in res["findings"]}
r.append(ok(res["verdict"] == "STOP" and "Public AML" in secs, "campaign address: STOP from our feed even though Public AML scores it 0"))
res = prescreen.screen(LAZ, "ethereum", log=lambda *_: None)
r.append(ok(res["verdict"] == "STOP" and "Issuer freeze" in secs | {x["section"] for x in res["findings"]}, "frozen address: STOP with an issuer-freeze line"))
from shield import web  # noqa: E402
page = web.prescreen_page({"addr": LAZ}, res)
r.append(ok("freezeradar.com/explorer?address=" + LAZ in page, "result page links to FreezeRadar's freeze history"))

os.chdir(ROOT); shutil.rmtree(WORK, ignore_errors=True)
print(f"{sum(r)}/{len(r)} passed"); sys.exit(0 if all(r) else 1)
