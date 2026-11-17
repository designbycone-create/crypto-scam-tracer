"""Export the message checker's rules (and a parity sample) for the Android app, so the phone and
the Desk judge messages the same way.

    python tools/export_mobile_rules.py          # writes the two files below
    python tools/export_mobile_rules.py --check  # exit 1 if they're out of date (used by the tests)

  android/app/src/main/assets/scam_rules.json   rules, link lists, campaign feed
  android/app/src/test/resources/parity.json    sample messages + the Desk's verdicts; the app's unit
                                                test must reach the same verdicts
"""
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
RULES_OUT = os.path.join(ROOT, "android", "app", "src", "main", "assets", "scam_rules.json")
PARITY_OUT = os.path.join(ROOT, "android", "app", "src", "test", "resources", "parity.json")

SAMPLES = [
    "E-ZPass: You have an unpaid toll of $4.15. Pay within 24 hours to avoid a late fee: https://ezpass-tolls-pay.top/pay",
    "USPS: Your package is on hold due to an incomplete address. Update here: https://usps.redeliver-info.com",
    "Grandpa it's me, I had an accident and the lawyer says I need $3,000 sent today. Please don't tell mom.",
    "This is the Social Security Administration. Your SSN has been suspended and there is a warrant for your arrest.",
    "Wells Fargo fraud department: unauthorized transaction. Transfer your savings to a safe account now. Don't hang up.",
    "Your boss here, I need you to buy 5 Apple gift cards for a client. Keep this between us.",
    "Hi, is this Linda? My uncle is a trading mentor, our VIP group gets 30% monthly returns guaranteed.",
    "To withdraw your 52,000 USDT profit you must first pay a 10% tax to unlock the account.",
    "Lost money to a crypto scam? Our certified ethical hackers can recover your stolen funds. Small upfront fee.",
    "Remote job: earn $300/day completing tasks. Recharge your account with USDT to unlock higher commission orders.",
    "Your computer has been infected. Call Microsoft support and install AnyDesk so we can fix it.",
    "Trust Wallet support: to verify your wallet, reply with your 12-word recovery phrase.",
    "Officer Daniels: to clear the warrant, deposit the cash at a Bitcoin ATM today.",
    "PayPal: your account is limited. Restore access: https://paypal-secure-login.xyz/verify",
    "Medicare: your benefits will be suspended. Read us the verification code we just texted you.",
    "Congratulations, you won the Publishers sweepstakes! Pay the $250 processing fee to claim your prize.",
    "My darling, I need money for the ticket to come see you, please send $800 by Zelle.",
    "Your Amazon.com order #112-4432 has shipped. Track your package at https://www.amazon.com/progress-tracker.",
    "Chase: Your statement is ready. Log in at chase.com to view it.",
    "Reminder: your appointment with Dr. Lee is tomorrow at 2pm. Reply C to confirm.",
    "Mom, I'm at the hospital with Dad for his checkup, call me when you can.",
    "I bought some bitcoin on Coinbase today, price is up.",
    "Please complete the review tasks in Jira by Friday.",
    "Police arrested a man accused of a Social Security scam, the news said Tuesday.",
    "Grandma it​s me, in jail, need bail money",
    "Hey are we still on for dinner Saturday?",
]


def build():
    from shield import msgcheck as M
    from shield import extension_api
    rules = {"version": 1,
             "rules": [{"id": i, "weight": w, "why": msg, "pattern": rx} for i, w, msg, rx in M.RULES],
             "decisive": sorted(M.DECISIVE),
             "shorteners": sorted(M.SHORTENERS),
             "risky_tlds": sorted(M.RISKY_TLDS),
             "brands": M.BRANDS,
             "url_pattern": M._URL.pattern,
             "hidden_chars": "[​-‏⁠﻿]",
             "campaign": extension_api.feed(include_local=False)}
    cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:          # no local incident or intel lists: same knowledge as the phone
        os.chdir(tmp)
        try:
            parity = [{"text": t, "verdict": (r := M.check(t))["verdict"],
                       "rules": sorted({f["rule"] for f in r["findings"]})} for t in SAMPLES]
        finally:
            os.chdir(cwd)
    return rules, parity


def dumps(o):
    return json.dumps(o, indent=1, ensure_ascii=True, sort_keys=True) + "\n"


if __name__ == "__main__":
    rules, parity = build()
    if "--check" in sys.argv:
        stale = [p for p, o in ((RULES_OUT, rules), (PARITY_OUT, parity))
                 if not os.path.exists(p) or open(p, encoding="utf-8").read() != dumps(o)]
        print("out of date: " + ", ".join(stale) if stale else "up to date")
        sys.exit(1 if stale else 0)
    for p, o in ((RULES_OUT, rules), (PARITY_OUT, parity)):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(dumps(o))
        print("wrote", os.path.relpath(p, ROOT))
