"""Offline test for shield (simulated chain data, no network): python shield/test_shield_offline.py"""
import json, os, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(tempfile.mkdtemp())
from shield import evm, approvals, drain, sitewatch, compromised, web
V = "0x1111111111111111111111111111111111111111"
USDT = "0xdac17f958d2ee523a2206206994597c13d831ec7"
DEX = "0x3333333333333333333333333333333333333333"      # contract
EOA = "0x4444444444444444444444444444444444444444"      # plain wallet
BAD = "0x5555555555555555555555555555555555555555"      # listed drainer
NFT = "0x6666666666666666666666666666666666666666"
AFF = "0x7777777777777777777777777777777777777777"; FEE = "0x8888888888888888888888888888888888888888"
DTX = "0x" + "d" * 64
pad = evm.pad
def http(url):
    if "action=getLogs" in url:
        if approvals.APPROVAL[2:] in url:
            return {"result": [{"address": USDT, "topics": [approvals.APPROVAL, pad(V), pad(DEX)]},
                               {"address": USDT, "topics": [approvals.APPROVAL, pad(V), pad(EOA)]},
                               {"address": USDT, "topics": [approvals.APPROVAL, pad(V), pad(BAD)]}]}
        if approvals.APPROVAL_FOR_ALL[2:] in url:
            return {"result": [{"address": NFT, "topics": [approvals.APPROVAL_FOR_ALL, pad(V), pad(EOA)]}]}
        return {"result": []}
    if "action=txlist" in url:
        return {"result": [{"hash": "0xmine", "from": V}]}
    if "action=tokentx" in url:
        return {"result": [{"hash": DTX, "from": V, "to": BAD, "value": str(1000 * 10**6), "tokenDecimal": "6",
                            "tokenSymbol": "USDT", "contractAddress": USDT, "timeStamp": "1793300000"}]}
    return {"result": []}
def rpc(chain, method, params):
    if method == "eth_call":
        to, data = params[0]["to"], params[0]["data"]
        if data == "0x313ce567": return hex(6)
        if data == "0x95d89b41": s=b"USDT"; return "0x"+(32).to_bytes(32,'big').hex()+len(s).to_bytes(32,'big').hex()+s.ljust(32,b'\0').hex()
        if data.startswith("0xdd62ed3e"):
            sp = "0x" + data[-40:]
            return hex(2**256 - 1) if sp in (DEX, EOA, BAD) else "0x0"
        if data.startswith("0xe985e9c5"): return hex(1)
        return "0x0"
    if method == "eth_getCode":
        return "0x6080" if params[0] in (DEX, BAD) else "0x"
    if method == "eth_getTransactionByHash": return {"from": "0x9999999999999999999999999999999999999999", "to": BAD}
    if method == "eth_getTransactionReceipt":
        T = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
        return {"logs": [{"topics": [T, pad(V), pad(BAD)], "data": hex(1000 * 10**6)},
                         {"topics": [T, pad(BAD), pad(AFF)], "data": hex(800 * 10**6)},
                         {"topics": [T, pad(BAD), pad(FEE)], "data": hex(200 * 10**6)}]}
evm.HTTP_GET, evm.RPC_POST = http, rpc
compromised.add(f"Drainer contract {BAD} on pickle.finance and flap.sh", "Step Drainer test")
r = approvals.scan(V, ["ethereum"])
for a in r["chains"]["ethereum"]: print(a["risk"], a["kind"], a["spender"][:8], a["why"])
print(r["summary"])
d = drain.analyze(V, ["ethereum"])
print("drains", len(d["drains"]), "receivers", d["receivers"], "fee", d["likely_fee_wallets"], "contracts", d["drainer_contracts"])
print("check_domain:", compromised.check_domain("https://app.pickle.finance/vaults"))
# sitewatch
state = {"ns": "ns1.cloudflare.com", "reg": "Name.com, Inc.", "lock": True, "script": "a", "host3p": None}
def get(url):
    if "cloudflare-dns" in url and "type=NS" in url: return json.dumps({"Answer": [{"data": state["ns"] + "."}]})
    if "cloudflare-dns" in url: return json.dumps({"Answer": [{"data": "1.2.3.4"}]})
    if "rdap.org" in url: return json.dumps({"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", state["reg"]]]]}],
                                            "status": ["client transfer prohibited"] if state["lock"] else ["active"]})
    if "crt.sh" in url: return json.dumps([{"issuer_name": "C=US, O=Let's Encrypt, CN=R11", "not_before": "2026-10-01T00:00:00"}])
    if url.endswith("/main.js"): return "code-" + state["script"]
    if "evil-cdn" in url: return "drainer"
    return "<script src='/main.js'></script>" + ("<script src='https://evil-cdn.xyz/kit.js'></script>" if state["host3p"] else "")
sitewatch.GET = get
sitewatch.add(["pickle.finance"]); sitewatch.check()
print("baseline:", sitewatch.load()["sites"]["pickle.finance"]["level"])
state["script"] = "b"; r1 = sitewatch.check()["sites"]["pickle.finance"]; print("deploy only:", r1["level"], r1["signals"])
state["host3p"] = True; r2 = sitewatch.check()["sites"]["pickle.finance"]; print("new 3p host:", r2["level"], r2["signals"])
alerts = []; state["ns"] = "ns1.evil-dns.net"
r3 = sitewatch.check(alert=lambda d, s: alerts.append((d, s)))["sites"]["pickle.finance"]; print("ns hijack:", r3["level"], r3["signals"], "alerted:", bool(alerts))
html = web.shield_page(V, "check", r) + web.shield_page(V, "drain", d) + web.sitewatch_page() + web.compromised_page()
print("pages ok", len(html))


