"""Offline tests for the November 2026 threat update: campaign feed entries and new message-checker rules.

Run: python test_threat_update_offline.py
"""
import os
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

ok = fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1
    else:
        fail += 1
        print("FAIL:", name)


tmp = tempfile.mkdtemp()
old = os.getcwd()
os.chdir(tmp)                      # no local incident / intel lists: only what ships in the release
try:
    import threatfeed
    from responder import addresses as A
    from shield import msgcheck as M

    camps = {c["id"]: c for c in threatfeed.campaigns()}

    # ---------- every campaign is well-formed and sourced ----------
    check("ids unique", len(camps) == len(threatfeed.campaigns()))
    for c in camps.values():
        check(f"{c['id']} has date", re.fullmatch(r"\d{4}-\d{2}-\d{2}", c.get("first_seen", "")) is not None)
        check(f"{c['id']} has sources", c.get("sources") and all(s["url"].startswith("https://") and s["title"] for s in c["sources"]))
        check(f"{c['id']} has advice", c.get("summary") and c.get("user_advice"))
    for cid in ("binance-heist-2026-10", "binance-compensation-scams-2026-11", "facestealer-2026-11", "midterm-scams-2026-10",
                "lunex-clickfix-2026-10", "optimjack-2026-11"):
        check(f"campaign present: {cid}", cid in camps)

    # ---------- the FBI Binance list ----------
    b = camps["binance-heist-2026-10"]
    chains = {}
    for e in b["addresses"]:
        chains[e["chain"]] = chains.get(e["chain"], 0) + 1
    check("628 addresses as the FBI published", len(b["addresses"]) == 628)
    check("608 / 19 / 1 by chain", chains == {"ethereum": 608, "bitcoin": 19, "solana": 1})
    valid = {"ethereum": A.is_evm, "bitcoin": lambda a: A.is_segwit(a, "bc") or A.is_btc_legacy(a), "solana": A.is_solana}
    check("every address valid for its chain", all(valid[e["chain"]](e["address"]) for e in b["addresses"]))
    check("ethereum checksummed (mixed case)", all(e["address"][2:] != e["address"][2:].lower() for e in b["addresses"] if e["chain"] == "ethereum"))
    check("no duplicates", len({e["address"].lower() for e in b["addresses"]}) == 628)
    check("warn-only: not traced", b.get("trace") is False)

    first_eth = next(e["address"] for e in b["addresses"] if e["chain"] == "ethereum")
    check("lookup by address", threatfeed.campaign_for_address(first_eth)["id"] == "binance-heist-2026-10")
    check("lookup ignores case on EVM", threatfeed.campaign_for_address(first_eth.lower())["id"] == "binance-heist-2026-10")
    btc = next(e["address"] for e in b["addresses"] if e["chain"] == "bitcoin")
    check("lookup bitcoin", threatfeed.campaign_for_address(btc)["id"] == "binance-heist-2026-10")

    from shield.clipguard import bad_reasons
    check("copy-paste guard warns", bool(bad_reasons(first_eth)))
    from shield import extension_api
    check("browser extension feed has it", any(v.startswith("the Binance heist") for v in extension_api.feed(include_local=False)["addresses"].values()))

    # seed_tracer: OPTIMJACK traced, Binance list not
    from responder import incident
    seen = []
    real_add = incident.add
    incident.add = lambda text, **kw: seen.append((kw.get("label"), len(text.split()))) or []
    try:
        threatfeed.seed_tracer(log=lambda *_: None)
    finally:
        incident.add = real_add
    labels = [s[0] for s in seen]
    check("OPTIMJACK still traced", any("OPTIMJACK" in (l or "") for l in labels))
    check("Binance list not traced", not any("Binance" in (l or "") for l in labels))

    # ---------- FaceStealer domains ----------
    check("FaceStealer domain flagged", threatfeed.campaign_for_host("uu01webzoom.us")["id"] == "facestealer-2026-11")
    check("subdomain flagged", threatfeed.campaign_for_host("join.teams.livemeet.us")["id"] == "facestealer-2026-11")
    check("real zoom not flagged", threatfeed.campaign_for_host("zoom.us") is None)
    r = M.check("Join my meeting here: https://uu01webzoom.us/j/8812")
    check("message with FaceStealer link = likely scam", r["verdict"] == "LIKELY SCAM")

    # ---------- new message rules: this month's lures (paraphrased) ----------
    scams = {
        "SAFU Reconciliation Desk: your BTC address was returned as unclaimed. To receive your payout send the 0.0042 BTC wallet-verification fee.": "LIKELY SCAM",
        "Binance compensation: claim your $150 reward now. A small activation payment of 20 USDT is required.": "LIKELY SCAM",
        "Binance Hack Also Impacts Trust Wallet Users. Please verify your wallet before Nov 7 or your account will be suspended.": "LIKELY SCAM",
        "Verify you are human: press Win+R, paste the code with Ctrl+V and press Enter.": "LIKELY SCAM",
        "Join our campaign investment pool! When our candidate wins, every member gets a 5x payout.": "LIKELY SCAM",
        "This is Agent Brown with the IC3. We have recovered your stolen crypto funds and can release them after a processing fee.": "LIKELY SCAM",
        "Sorry, your audio isn't working on my end. There's a known Zoom issue, please install this audio driver update and rejoin.": "SUSPICIOUS",
    }
    for text, want in scams.items():
        got = M.check(text)["verdict"]
        check(f"{want}: {text[:40]}", got == want or (want == "SUSPICIOUS" and got == "LIKELY SCAM"))
    check("campaign wording named", any(f["rule"] == "campaign_text" for f in M.check("Message from the SAFU Reconciliation Desk")["findings"]))
    check("advice for pasted commands", any("ran a command" in a for a in M.check("Open PowerShell and paste this to verify").get("advice", [])))

    fine = ["Your Amazon refund of $23.10 has been issued to your original payment method.",
            "Hi Mom, the Zoom link for Sunday is in the calendar invite. See you then!",
            "Thanks for donating to our campaign. Your contribution is not tax deductible.",
            "I bought a new leather wallet today, it was on sale.",
            "The bus terminal is closed on Sunday, run over to the north station instead.",
            "The FBI recovered stolen art from a museum in Ohio, news reports said.",
            "Your refund was processed. There is no fee.",
            "My camera isn't working, can we just do a phone call instead?"]
    for text in fine:
        check(f"no false alarm: {text[:40]}", M.check(text)["verdict"] == "NO RED FLAGS FOUND")
finally:
    os.chdir(old)
    shutil.rmtree(tmp, ignore_errors=True)

print(f"threat update: {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
