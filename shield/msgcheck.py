"""Message checker: paste a text, email, DM or voicemail transcript -> plain-language red flags.

Works on any scam, not only crypto: fake bank / government / delivery / tech-support messages,
gift-card and crypto-ATM demands, "grandchild in jail" and voice-clone emergencies, job and
romance scams, fake investment platforms, and "we can recover your lost money" follow-ups.

Everything runs on this computer: the message is never sent anywhere. Links and crypto
addresses in it are checked against the campaign feed, your incident list and public scam lists.

Verdicts are deliberately careful:
  LIKELY SCAM       several strong signs together
  SUSPICIOUS        at least one strong sign, or several weaker ones
  NO RED FLAGS FOUND  -- never "safe": a clever scam can avoid every rule

    python -m shield.msgcheck "text of the message"
"""
import html
import re
import sys
import urllib.parse

# Each rule: (id, weight, plain-language explanation, regex). Weight 3 = strong, 2 = medium, 1 = weak.
# Rules in DECISIVE are, on their own, enough to call a message a likely scam.
RULES = [
    # how they want to be paid -- the most reliable sign of all
    ("gift_cards", 3, "Asks for payment in gift cards. No real company, agency or court is ever paid in gift cards.",
     r"\b(gift ?cards?|itunes card|apple card|google play card|steam card|target card|vanilla (visa|card))\b"),
    ("crypto_atm", 3, "Tells you to put cash into a Bitcoin / crypto ATM. Government agencies and banks never ask for this.",
     r"\b(bitcoin|crypto|btc)\s*(atm|kiosk|machine)\b|\bcoinflip\b|\bbitcoin depot\b"),
    ("cash_courier", 3, "Says someone will come to pick up cash or gold from you. That is a known courier scam.",
     r"\b(courier|driver|agent|officer)\b.{0,40}\b(pick ?up|collect)\b|\b(gold bars?|cash) .{0,30}\b(pick ?up|collect|courier)\b"),
    ("move_money_safe", 3, "Tells you to move your money to a 'safe' account. Real banks never tell you to move money to protect it.",
     r"\b(safe|secure|protected|new) (account|wallet)\b.{0,60}\b(transfer|move|send|deposit)\b|\b(transfer|move) (your|all) (money|funds|savings)\b"),
    ("wire_zelle", 2, "Wants a wire transfer, Zelle, Cash App or Venmo payment. Money sent that way is almost never recoverable.",
     r"\b(wire transfer|wire the|western union|moneygram|zelle|cash ?app|venmo)\b"),
    ("crypto_pay", 2, "Asks you to pay or deposit in cryptocurrency (USDT, Bitcoin and similar).",
     r"\b(send|deposit|pay|transfer)\b.{0,40}\b(usdt|tether|bitcoin|btc|eth|crypto|usdc)\b"),
    # what they want from you
    ("codes", 3, "Asks for a verification code, password or PIN. Anyone who asks for the code sent to you is trying to get into your account.",
     r"\b(verification|security|one[- ]time|otp|2fa|login|confirmation) code\b|\b(read|tell|give|send) (me|us) (the )?(code|pin|password)\b"),
    ("seed", 3, "Asks for a wallet recovery (seed) phrase or private key. Nobody legitimate ever needs these; whoever has them owns the wallet.",
     r"\b(seed|recovery|secret|mnemonic) (phrase|words)\b|\bprivate key\b|\b12[- ]words?\b|\b24[- ]words?\b"),
    ("remote_access", 3, "Wants you to install a remote-access app (AnyDesk, TeamViewer and similar) or share your screen. That gives them control of your computer.",
     r"\b(anydesk|teamviewer|ultraviewer|rustdesk|logmein|screenconnect|quick ?assist|share (your )?screen|remote (access|desktop|support))\b"),
    ("secrecy", 3, "Tells you to keep it secret or not to tell family or your bank. Scammers isolate their targets; real officials don't.",
     r"\b(don'?t|do not|never) (tell|inform|talk to|mention)\b.{0,40}\b(anyone|family|bank|teller|police|wife|husband|son|daughter|kids|mom|dad|mother|father|parents|grandpa|grandma)\b|\bkeep (this|it) (secret|confidential|between us)\b|\bgag order\b"),
    ("stay_on_line", 2, "Pressures you to stay on the phone or not hang up. That stops you from checking with anyone.",
     r"\b(don'?t|do not) hang up\b|\bstay on the (line|phone)\b"),
    # who they claim to be
    ("gov_threat", 3, "Claims to be a government agency or police threatening arrest, a warrant, or a suspended Social Security number. Agencies don't threaten arrest by phone, text or email.",
     r"\b(irs|social security|ssa|medicare|fbi|dea|ftc|sheriff|marshal|police|customs|immigration)\b.{0,80}\b(arrest|warrant|suspend|suspended|lawsuit|jail|legal action|penalty)\b"),
    ("bank_fraud_dept", 2, "Says it's your bank's fraud department. Hang up and call the number on the back of your card instead.",
     r"\b(fraud (department|team|alert)|suspicious (activity|transaction|charge)|unauthori[sz]ed (charge|transaction|purchase))\b"),
    ("tech_support", 2, "A tech-support or virus warning asking you to call or click. Microsoft, Apple and others don't send these.",
     r"\b(your (computer|device|pc|account) (is|has been) (infected|hacked|compromised|locked))\b|\b(geek squad|norton|mcafee|microsoft|apple) (renewal|subscription|support)\b.{0,60}\b(call|charge|refund)\b"),
    ("delivery_toll", 2, "A delivery or unpaid-toll text with a link. These are among the most common scam texts.",
     r"\b(usps|ups|fedex|dhl|package|parcel|shipment)\b.{0,60}\b(redeliver|on hold|unable to deliver|address (issue|incomplete)|fee)\b|\b(unpaid|outstanding) (toll|tolls|e-?zpass|sunpass)\b"),
    ("refund_overpay", 2, "Says you were refunded or paid too much and must send the difference back. That's an overpayment scam.",
     r"\b(over ?paid|overpayment|refunded too much|sent too much|accidentally (sent|refunded))\b"),
    # emotional hooks
    ("family_emergency", 3, "A family emergency (accident, jail, bail, hospital) with a request for money. Voices can now be cloned with AI: hang up and call that person on their own number.",
     r"(?=[\s\S]*(\b(money|bail|bond|send|sent|wire|pay|paid|cash|gift ?cards?|venmo|zelle|cash ?app)\b|\$\s?\d))"
     r"\b(grandma|grandpa|grandmother|grandfather|mom|dad|it'?s me)\b.{0,120}\b(jail|bail|arrested|accident|hospital|lawyer|attorney)\b"
     r"|\b(bail|bond) (money|payment)\b"),
    ("new_number", 1, "Says it's someone you know texting from a new number. Confirm by calling their old number.",
     r"\b(new (phone|number)|lost my phone|this is my new number)\b"),
    ("prize", 3, "Says you won a prize, lottery or sweepstakes but must pay a fee or taxes first. Real prizes never charge you.",
     r"\b(you('ve| have)? won|winner|lottery|sweepstakes|prize|jackpot)\b.{0,120}\b(fee|tax|taxes|processing|shipping and handling|pay|send)\b"),
    ("romance_money", 2, "Someone you know only online is asking for money. Romance scammers build trust for weeks, then ask.",
     r"\b(my love|my dear|darling|sweetheart|honey|babe)\b.{0,200}\b(money|send|transfer|help me|loan|fee|ticket|visa)\b"),
    # money-making pitches
    ("guaranteed_returns", 3, "Promises guaranteed or very high returns. Real investments never guarantee profit.",
     r"\b(guaranteed|risk[- ]free|no risk)\b.{0,40}\b(profit|returns?|income|gains?)\b|\b\d{2,4}\s?% (daily|weekly|monthly|return|profit)\b|\b(double|triple) your (money|investment|crypto)\b"),
    ("trading_mentor", 2, "An investment 'mentor', VIP group or trading platform you were introduced to by a stranger. This is how 'pig-butchering' scams start.",
     r"\b(mentor|vip group|signal group|trading (platform|app|teacher)|investment (group|club|platform)|liquidity mining|arbitrage (bot|platform))\b"),
    ("withdrawal_fee", 3, "Says you must pay a fee or tax before you can withdraw your money. That is the final stage of an investment scam: the money is gone.",
     r"\b(withdraw(al)?|unlock|release)\b.{0,60}\b(fee|tax|deposit|margin|verification payment|unfreeze)\b"),
    ("wrong_number", 1, "A friendly 'wrong number' opener. Scam groups use these to start a conversation that ends in a fake investment.",
     r"^\s*(hi|hello|hey)[,!. ]+(is this|are you)\b|\bsorry,? (wrong number|i (think|guess) i have the wrong)\b"),
    ("task_job", 3, "A job that pays you to 'complete tasks' or review products, but asks you to deposit money first. That's a task scam.",
     r"\b(tasks?|orders?|reviews?|ratings?)\b.{0,60}\b(commission|recharge|top ?up|deposit|unlock)\b|\b(work from home|remote job)\b.{0,80}\b(telegram|whatsapp|deposit)\b"),
    ("recovery_scam", 3, "Offers to recover money you already lost to a scam, usually for an upfront fee. These are almost always a second scam. Real help (police, IC3, the FTC) is free.",
     r"\b(recover|recovery|retrieve|get back)\b.{0,60}\b(lost|stolen|scammed)\b.{0,60}\b(funds|money|crypto|bitcoin|assets)\b|\b(fund|asset|crypto) recovery\b|\b(ethical )?hackers? (can|will) (recover|get back)\b"),
    # pressure
    ("urgency", 1, "Pressures you to act right now. Scammers rush you so you don't stop and check.",
     r"\b(act now|immediately|urgent|within (24|48) hours|right away|final (notice|warning)|last chance|expires? today)\b"),
    ("account_threat", 1, "Says your account will be closed, locked or suspended.",
     r"\b(account|card|service)\b.{0,30}\b(suspended|locked|closed|deactivated|disabled|terminated|frozen)\b"),
]
_RX = [(i, w, msg, re.compile(rx, re.I | re.S | re.M)) for i, w, msg, rx in RULES]
DECISIVE = {"gift_cards", "crypto_atm", "cash_courier", "move_money_safe", "seed", "withdrawal_fee", "recovery_scam",
            "task_job", "bad_address", "bad_link", "family_emergency", "gov_threat", "prize"}

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
              "rb.gy", "t.ly", "s.id", "tiny.cc", "lnkd.in", "qrco.de"}
RISKY_TLDS = {"top", "xyz", "icu", "cc", "click", "link", "rest", "cfd", "sbs", "buzz", "monster", "cyou", "zip", "mov",
              "support", "live", "online", "shop", "vip", "lat", "bond", "loan", "work", "kim", "country"}
# brand -> its real domains. A link naming the brand on any other domain is a lookalike.
BRANDS = {"paypal": ["paypal.com"], "apple": ["apple.com", "icloud.com"], "amazon": ["amazon.com", "amazon.co.uk", "amzn.to"],
          "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"], "netflix": ["netflix.com"],
          "coinbase": ["coinbase.com"], "binance": ["binance.com", "binance.us"], "kraken": ["kraken.com"],
          "metamask": ["metamask.io"], "trustwallet": ["trustwallet.com"], "ledger": ["ledger.com"],
          "usps": ["usps.com"], "fedex": ["fedex.com"], "ups": ["ups.com"], "dhl": ["dhl.com"],
          "irs": ["irs.gov"], "ssa": ["ssa.gov"], "medicare": ["medicare.gov"], "chase": ["chase.com"],
          "wellsfargo": ["wellsfargo.com"], "bankofamerica": ["bankofamerica.com", "bofa.com"],
          "venmo": ["venmo.com"], "zelle": ["zellepay.com"], "cashapp": ["cash.app"], "ezpass": ["e-zpassny.com", "ezpassnj.com", "e-zpassiag.com"],
          "facebook": ["facebook.com", "fb.com"], "instagram": ["instagram.com"], "google": ["google.com", "goo.gl", "youtube.com"],
          "walmart": ["walmart.com"], "costco": ["costco.com"], "geeksquad": ["bestbuy.com"]}
_URL = re.compile(r"\b((?:https?://|www\.)[^\s<>\"')\]]+|(?<![@\w])[a-z0-9][a-z0-9-]{0,62}(?:\.[a-z0-9-]{1,63})*\.(?:"
                  + "|".join(sorted(RISKY_TLDS | {"com", "net", "org", "io", "co", "app", "info", "biz", "us", "me", "ly", "to", "gl", "gov"}, key=lambda t: (-len(t), t)))
                  + r")(?:/[^\s<>\"')\]]*)?)", re.I)


def _registered(host):
    parts = host.split(".")
    return ".".join(parts[-3:]) if len(parts) > 2 and parts[-2] in ("co", "com", "org", "net", "gov") and len(parts[-1]) == 2 \
        else ".".join(parts[-2:])


def check_link(raw):
    """[(weight, explanation)] for one link."""
    u = raw if re.match(r"https?://", raw, re.I) else "http://" + raw
    try:
        p = urllib.parse.urlsplit(u)
        host = (p.hostname or "").lower().rstrip(".")
    except ValueError:
        return [(2, f"The link {raw} is malformed.")]
    out = []
    if not host:
        return out
    try:
        import threatfeed
        c = threatfeed.campaign_for_host(host)
        if c:
            out.append((4, f"The link goes to {host}, known attacker infrastructure ({c['name']})."))
    except Exception:
        pass
    try:
        from shield import compromised
        h = compromised.check_domain(host)
        if h and not out:
            out.append((4, f"The link: {h}."))
    except Exception:
        pass
    try:
        from responder import intel
        for src, det in intel.check(host):
            if src != "Your cases":
                out.append((4, f"The link's site {host} is on a scam list ({src})."))
                break
    except Exception:
        pass
    reg = _registered(host)
    if re.fullmatch(r"[\d.]+", host):
        out.append((2, f"The link goes to a bare number address ({host}) instead of a company name."))
    if host.startswith("xn--") or ".xn--" in host:
        out.append((2, f"The link {host} uses look-alike international letters."))
    if reg in SHORTENERS:
        out.append((1, f"The link is shortened ({reg}), which hides where it really goes."))
    if "@" in (p.netloc or ""):
        out.append((2, "The link hides its real destination after an @ sign."))
    tld = host.rsplit(".", 1)[-1]
    flat = re.sub(r"[^a-z0-9]", "", host)
    for brand, real in BRANDS.items():
        if brand in flat and reg not in real and not any(host == r or host.endswith("." + r) for r in real):
            out.append((4, f"The link mentions {brand} but goes to {reg}, which isn't {brand}'s website."))
            break
    if tld in RISKY_TLDS and not out:
        out.append((1, f"The link uses a web address ending (.{tld}) that scammers favor."))
    return out


def check(text):
    """{'verdict', 'level', 'score', 'findings': [{weight, why}], 'types', 'links', 'addresses', 'advice'}"""
    t = (text or "")[:20000]
    flat = re.sub(r"[​-‏⁠﻿]", "", t)        # zero-width tricks used to dodge filters
    findings, types = [], []
    for rid, w, msg, rx in _RX:
        if rx.search(flat):
            findings.append({"weight": w, "why": msg, "rule": rid})
            types.append(rid)
    if flat != t:
        findings.append({"weight": 2, "why": "The message hides invisible characters, a trick used to slip past spam filters.", "rule": "hidden_chars"})
    links = []
    for m in _URL.finditer(flat):
        raw = m.group(1).rstrip(".,;:!?")
        if raw.lower() in {x["link"].lower() for x in links}:
            continue
        lf = check_link(raw)
        links.append({"link": raw, "flags": [x[1] for x in lf]})
        for w, why in lf:
            findings.append({"weight": min(w, 3), "why": why, "rule": "bad_link" if w >= 4 else "link"})
    addrs = []
    try:
        from responder.addresses import extract
        from shield.clipguard import bad_reasons
        for chain, a in extract(flat):
            why = bad_reasons(a)
            addrs.append({"chain": chain, "address": a, "bad": why})
            if why:
                findings.append({"weight": 3, "why": f"It contains a known scammer's {chain} address: {why[0]}.", "rule": "bad_address"})
            else:
                findings.append({"weight": 1, "why": f"It contains a {chain} wallet address. Never send to an address from a message you didn't expect.", "rule": "address"})
    except Exception:
        pass
    strong = sum(1 for f in findings if f["weight"] >= 3)
    score = sum(f["weight"] for f in findings)
    decisive = any(f["rule"] in DECISIVE for f in findings)
    if decisive or strong >= 2 or (strong >= 1 and score >= 5) or score >= 7:
        verdict, level = "LIKELY SCAM", "stop"
    elif strong >= 1 or score >= 3:
        verdict, level = "SUSPICIOUS", "caution"
    else:
        verdict, level = "NO RED FLAGS FOUND", "info"
    findings.sort(key=lambda f: -f["weight"])
    return {"verdict": verdict, "level": level, "score": score, "findings": findings, "types": types,
            "links": links, "addresses": addrs, "advice": advice(level, types)}


def advice(level, types):
    if level == "info":
        return ["No warning signs matched, but no checker catches everything. If it asks for money, codes or personal "
                "details, contact the company or person yourself using a number or website you already know."]
    out = ["Don't reply, don't click links, and don't call any number in the message."]
    if {"family_emergency", "new_number"} & set(types):
        out.append("Call the family member on the number you already have for them. Agree on a family code word for emergencies.")
    if {"bank_fraud_dept", "move_money_safe", "codes", "account_threat"} & set(types):
        out.append("Call your bank using the number on the back of your card.")
    if {"gov_threat"} & set(types):
        out.append("Government agencies don't threaten arrest by phone, text or email. Hang up.")
    if {"remote_access", "tech_support"} & set(types):
        out.append("If you already let them into your computer, disconnect it from the internet and have it checked.")
    if {"recovery_scam"} & set(types):
        out.append("Real help after a scam is free: report it at ic3.gov and reportfraud.ftc.gov. ScamHunter can trace crypto at no cost.")
    out.append("If you already sent money: contact your bank or the payment app right away, then report it at ic3.gov "
               "(and reportfraud.ftc.gov). If it was crypto, start a case in the ScamHunter Desk.")
    return out


# ---------------------------------------------------------------- Desk page /msgcheck ----

e = lambda s: html.escape(str(s if s is not None else ""), quote=True)
CSS = """body{font-family:Segoe UI,Arial,sans-serif;font-size:19px;max-width:900px;margin:24px auto;padding:0 16px;color:#111;background:#fff;line-height:1.45}
h1{font-size:32px}textarea{width:100%;box-sizing:border-box;font-size:18px;min-height:200px;padding:10px}
button{font-size:20px;padding:10px 22px;cursor:pointer}.v{font-size:30px;font-weight:700;padding:14px 18px;border-radius:10px;margin:18px 0 8px}
.stop{background:#b00020;color:#fff}.caution{background:#f2b01e;color:#111}.info{background:#e8f0fe;color:#111}
li{margin:6px 0}.hint{color:#444;font-size:16px}.mono{font-family:Consolas,monospace;word-break:break-all}"""


def page(text="", result=None):
    res = ""
    if result:
        f = "".join(f"<li>{'&#9888;&#65039; ' if x['weight'] >= 3 else ''}{e(x['why'])}</li>" for x in result["findings"])
        a = "".join(f"<li>{e(x)}</li>" for x in result["advice"])
        res = (f"<div class='v {result['level']}'>{e(result['verdict'])}</div>"
               + (f"<h2>What we noticed</h2><ul>{f}</ul>" if f else "")
               + f"<h2>What to do</h2><ul>{a}</ul>")
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Message checker</title><style>{CSS}</style></head><body>
<h1>Is this message a scam?</h1>
<p>Paste a text message, email, social media DM, or what a caller said. It's checked on this computer only; nothing is sent anywhere.</p>
<form method=post action=/msgcheck><textarea name=text placeholder="Paste the message here">{e(text)}</textarea>
<p><button>Check it</button></p></form>{res}
<p class=hint>This checker looks for the warning signs scams share. It can miss a new trick, so when money, passwords or codes are involved,
always check with the company or person yourself, using a number you already know.</p></body></html>"""


def post(form):
    t = form.get("text", "")
    return page(t, check(t) if t.strip() else None)


if __name__ == "__main__":
    r = check(" ".join(sys.argv[1:]) or sys.stdin.read())
    print(r["verdict"])
    for f in r["findings"]:
        print(f"  [{f['weight']}] {f['why']}")
