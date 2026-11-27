"""Desk page /hwcheck: New hardware wallet check (Crypto & Wallets > Protect).

Seven short questions before someone sets up a new hardware wallet, then a plain result; on the computer a USB
check (shield/usbcheck.py); "Watch this wallet" (shield/mywallets.py); and a private custody record. Screens and
wording follow design/redesign/DESK_REDESIGN.md and the spec "New Hardware Wallet Check".

What it can't do, said on every result: no software can find a chip hidden inside a device. The page never says
a wallet is "safe", "genuine" or "verified", never asks for a recovery phrase or PIN, refuses one if pasted
(nothing is kept or sent), and never contacts anyone.

Answers travel in the page address (?a=ledger,maker,...): there is nothing secret in them, and it means the
Back button and the phone app work without any stored state.
"""
import html
import json
import os
import re
import secrets
import threading
import time
from datetime import datetime
from urllib.parse import quote

from deskui import icons, seedguard
from shield import mywallets, usbcheck

e = lambda s: html.escape(str(s if s is not None else ""), quote=True)
CUSTODY_DIR = "hardware_wallets"
HIDDEN_CHIP = "This can't detect a hidden chip inside a device."
MAX_FILE = 10 * 1024 * 1024
OK_TYPES = {"image/jpeg": ".jpg", "image/png": ".png", "image/heic": ".heic", "image/webp": ".webp", "application/pdf": ".pdf"}

# (id, question, hint, [(code, answer, level, why-if-flagged)])   level: stop | careful | ok
QUESTIONS = [
    ("brand", "Which wallet did you buy?", "", [
        ("ledger", "Ledger", "ok", ""), ("trezor", "Trezor", "ok", ""),
        ("other", "A different brand", "careful", "It's a brand this check doesn't know the setup of."),
        ("unknown", "I don't know", "careful", "You're not sure which brand it is.")]),
    ("where", "Where did you buy it?", "", [
        ("maker", "The maker's own store", "ok", ""), ("shop", "A well-known shop", "ok", ""),
        ("private", "A private seller or an online marketplace", "careful", "You bought it from a private seller or an online marketplace."),
        ("gift", "It was a gift", "careful", "It was a gift, so you don't know where it came from."),
        ("named", "A seller named in a warning (like CryptoBillis)", "stop",
         "That seller is named in a known attack: wallets it resold had a hidden chip that stole recovery phrases."),
        ("unknown", "I don't know", "careful", "You don't know where it was bought.")]),
    ("phrase", "Did a recovery phrase come in the box?", "A recovery phrase is 12 or 24 words. A new wallet should not include one.", [
        ("yes", "Yes, words came in the box", "stop", "A recovery phrase came in the box. Real wallets make a new one on their own screen."),
        ("no", "No", "ok", ""), ("unknown", "I don't know", "careful", "You're not sure whether words came in the box.")]),
    ("pin", "Did the wallet already have a PIN?", "", [
        ("yes", "Yes, it already had a PIN", "stop", "It already had a PIN, so someone set it up before you."),
        ("created", "No, it asked me to create one", "ok", ""),
        ("notyet", "I have not turned it on yet", "careful", "You haven't turned it on yet, so the PIN step isn't checked."),
        ("unknown", "I don't know", "careful", "You're not sure whether it already had a PIN.")]),
    ("seal", "Is the seal broken, or is the device scratched?", "", [
        ("yes", "Yes", "stop", "The seal was broken or the device was scratched: it may have been opened."),
        ("no", "No", "ok", ""), ("unknown", "I don't know", "careful", "You're not sure about the seal.")]),
    ("site", "Did anyone tell you to use a website or app that was not on the maker's list?", "", [
        ("yes", "Yes", "stop", "Someone told you to use a website or app that isn't on the maker's list."), ("no", "No", "ok", "")]),
    ("rush", "Did anyone rush you, or offer to set it up for you?", "", [
        ("yes", "Yes", "stop", "Someone rushed you or offered to set it up: that's how setup scams work."), ("no", "No", "ok", "")]),
]
QIDS = [q[0] for q in QUESTIONS]
STOP_STEPS = ["Do not plug it in, and do not move money onto it.",
              "Contact the maker using an address you looked up yourself, not one from the box or the seller.",
              "Keep the box, the receipt and anything that came with it."]
_usb = {}           # token -> {"before": [...], "at": epoch, "brand": ...}
_lock = threading.Lock()


# ------------------------------------------------------------------ answers and the result ----
def parse(a):
    """'ledger,maker,no' -> ['ledger','maker','no'], keeping only valid answers in order."""
    out = []
    for i, code in enumerate((a or "").split(",")[:len(QUESTIONS)]):
        if code not in {c for c, *_ in QUESTIONS[i][3]}:
            break
        out.append(code)
    return out


def evaluate(answers):
    """(level, why list). Any STOP answer makes it STOP; Be careful answers still show under Why."""
    stops, careful = [], []
    for (qid, _q, _h, opts), code in zip(QUESTIONS, answers):
        for c, _label, lv, why in opts:
            if c == code and lv != "ok":
                (stops if lv == "stop" else careful).append(why)
    if stops:
        return "stop", stops + careful
    if careful:
        return "careful", careful
    return "ok", []


def _a(answers):
    return ",".join(answers)


def _url(answers=None, **kw):
    q = []
    if answers:
        q.append("a=" + quote(_a(answers)))
    q += [f"{k}={quote(str(v))}" for k, v in kw.items()]
    return "/hwcheck" + ("?" + "&".join(q) if q else "")


def _page(title, body):
    return (f"<!doctype html><html><head><meta charset=utf-8><title>{e(title)}</title></head><body>"
            f"<div class=page-head><h1>{e(title)}</h1></div>{body}</body></html>")


def _info(text):
    return f"<div class=callout role=note>{icons.svg('info', 28)}<p style='margin:0'><b>Info.</b> {e(text)}</p></div>"


# ------------------------------------------------------------------ screens ----
def start():
    body = ("<p class=lead>Seven short questions about a new wallet, before you set it up.</p>" + _info(HIDDEN_CHIP)
            + "<section class=card style='margin-top:1.5rem'><ol class=steps>"
              "<li class=now><span class=n>1</span><span>Answer 7 questions</span></li>"
              "<li><span class=n>2</span><span>On a computer, plug the wallet in so the Desk can read the device name</span></li>"
              "<li><span class=n>3</span><span>Save a custody record if you want a paper trail</span></li></ol>"
              f"<div class=actions><a class='btn btn-primary' href='{_url(step='q')}'>Start the check</a>"
              f"<a class='btn btn-quiet' href='{_url(step='watch')}'>I only want to watch an address</a></div></section>")
    return _page("New hardware wallet check", body)


def question(answers):
    i = len(answers)
    qid, q, hint, opts = QUESTIONS[i]
    segs = "".join(f"<i class='{'done' if k < i else 'on' if k == i else ''}'></i>" for k in range(len(QUESTIONS)))
    buttons = "".join(f"<a class=answer href='{_url(answers + [c])}'>{e(label)}</a>" for c, label, *_ in opts)
    back = _url(answers[:-1], step="q") if answers else _url()
    return _page("New hardware wallet check",
                 f"<section class=card><p class=kicker>Question {i + 1} of {len(QUESTIONS)}</p><div class=segs aria-hidden=true>{segs}</div>"
                 f"<h2>{e(q)}</h2>" + (f"<p class=hint>{e(hint)}</p>" if hint else "")
                 + f"<div role=group aria-label='{e(q)}'>{buttons}</div><a class='btn btn-quiet' href='{back}'>Back</a></section>")


def result(answers, phone=False):
    level, why = evaluate(answers)
    redo = f"<a class='btn btn-quiet' href='{_url(step='q')}'>See the questions again</a>"
    custody = f"<a class='btn btn-quiet' href='{_url(answers, step='custody')}'>Save a custody record</a>"
    if level == "stop":
        steps = "".join(f"<li><span class=n>{k}</span><span>{e(s)}</span></li>" for k, s in enumerate(STOP_STEPS, 1))
        card = icons.result("stop", sentence="Do not use this wallet. Do not type any words that came with it into a website or an app.",
                            why=why, extra=f"<p class=note><b>Info.</b> {e(HIDDEN_CHIP)}</p><ol class=steps>{steps}</ol>",
                            actions=f"<a class='btn btn-stop' href='/compromised'>What to do next</a>{redo}{custody}")
    elif level == "careful":
        usb = "" if phone else f"<a class='btn btn-secondary' href='{_url(answers, step='unplug')}'>Check the USB name on this computer</a>"
        card = icons.result("careful", sentence="Something about this purchase needs a closer look before you move money onto it.",
                            why=why, extra=f"<p class=note><b>Info.</b> {e(HIDDEN_CHIP)}</p>",
                            actions=f"<a class='btn btn-primary' href='{_url(answers, step='next')}'>See what to check next</a>{usb}{custody}")
    else:
        main = (f"<a class='btn btn-primary' href='{_url(answers, step='phoneusb')}'>Do this step at your computer</a>" if phone else
                f"<a class='btn btn-primary' href='{_url(answers, step='unplug')}'>Continue to the USB check</a>")
        card = icons.result("ok", sentence="These answers did not show a known setup trick.",
                            why=["Bought new, from the maker or a well-known shop.", "No recovery phrase came in the box.",
                                 "It asked you to create a PIN.", "The seal was intact.", "Nobody pointed you to an unlisted site or rushed you."],
                            extra=f"<p class=note><b>Info.</b> {e(HIDDEN_CHIP)}</p>",
                            actions=f"{main}<a class='btn btn-secondary' href='{_url(answers, step='watch')}'>Watch this wallet</a>{custody}")
    return _page("New hardware wallet check", card)


def next_steps(answers):
    level, why = evaluate(answers)
    items = ["Check the maker's website (type the address yourself) for how a new device should arrive and set up.",
             "Turn it on yourself. It must ask you to create a PIN and show a brand-new recovery phrase on its own screen.",
             "Run the maker's own genuine check in their official app.",
             "Send a small test amount first, wait a few days, then move the rest.",
             "If anything doesn't match, stop and contact the maker."]
    body = (icons.result("careful", "What to check next", "", why) +
            "<section class=card style='margin-top:1.5rem'><h2>Before you move money onto it</h2><ol class=steps>"
            + "".join(f"<li><span class=n>{k}</span><span>{e(s)}</span></li>" for k, s in enumerate(items, 1))
            + f"</ol><div class=actions><a class='btn btn-primary' href='{_url(answers, step='watch')}'>Watch this wallet</a>"
              f"<a class='btn btn-secondary' href='{_url(answers)}'>Back to the result</a></div></section>")
    return _page("New hardware wallet check", body)


def phone_usb(answers):
    return _page("New hardware wallet check", icons.result(
        "info", "Do this step at your computer", "This phone cannot see a USB wallet. Open the Desk on your computer and plug the wallet in there.",
        actions=f"<a class='btn btn-primary' href='{_url(answers)}'>Back to the result</a>"))


def unplug(answers):
    return _page("Unplug the wallet", "<section class=card><p class=kicker>Computer only</p><ol class=steps>"
                 "<li class=now><span class=n>1</span><span>Unplug the wallet</span></li><li><span class=n>2</span><span>Plug it in and wait</span></li>"
                 "<li><span class=n>3</span><span>Read the device name</span></li></ol>"
                 "<p style='margin-top:1rem'>Take the wallet out of this computer. Leave it unplugged.</p>"
                 f"<form method=post action=/hwcheck><input type=hidden name=do value=usb_start><input type=hidden name=a value='{e(_a(answers))}'>"
                 f"<button class='btn btn-primary'>It's unplugged</button></form>"
                 f"<a class='btn btn-quiet' href='{_url(answers)}'>Back to the result</a></section>")


def plug_in(answers, token):
    js = ("<script>(function(){var n=60,el=document.getElementById('cd'),bar=document.getElementById('cdbar'),seen=0,quiet=0;"
          f"var go=function(){{location.href='{_url(answers, step='usb', t=token)}';}};"
          "var t=setInterval(function(){n--;el.textContent=n;bar.style.width=(100*n/60)+'%';"
          "if(n%2===0){fetch('/hwcheck/usb.json?t=" + token + "',{cache:'no-store'}).then(function(r){return r.json()}).then(function(j){"
          "if(j.new>0){if(j.new===seen){quiet++;}else{seen=j.new;quiet=0;} if(quiet>=2){clearInterval(t);go();}}}).catch(function(){});}"
          "if(n<=0){clearInterval(t);document.getElementById('cdlabel').textContent='Time is up. Reading the device name…';go();}},1000);})();</script>")
    return _page("Now plug it in", "<section class=card><p class=kicker>Computer only</p>"
                 "<p>Use the cable that came with the wallet. The Desk reads the device name only. It does not read your keys.</p>"
                 "<p class=count id=cd aria-live=off>60</p><p id=cdlabel>seconds left</p><div class=bar><span id=cdbar style='width:100%'></span></div>"
                 f"<div class=actions><a class='btn btn-primary' href='{_url(answers, step='usb', t=token)}'>It's plugged in: read it now</a>"
                 f"<a class='btn btn-secondary' href='{_url(answers)}'>Cancel and unplug</a></div></section>" + js)


def usb_result(answers, token):
    with _lock:
        job = _usb.get(token)
    if not job:
        return _page("Device name", icons.result("info", "Start the USB check again", "That check expired. Unplug the wallet and start again.",
                                                 actions=f"<a class='btn btn-primary' href='{_url(answers, step='unplug')}'>Start again</a>"))
    try:
        after = usbcheck.snapshot()
    except usbcheck.NotAvailable as ex:
        return _page("Device name", icons.result("info", "The device list isn't available", str(ex),
                                                 actions=f"<a class='btn btn-primary' href='{_url(answers)}'>Back to the result</a>"))
    new = usbcheck.new_devices(job["before"], after)
    brand = answers[0] if answers else "unknown"
    level, sentence, rows = usbcheck.judge(new, brand)
    level_q, _ = evaluate(answers)
    if level_q == "stop":          # the USB step never turns a STOP into a clear result
        level = "stop"
    now = datetime.now().strftime("Today, %H:%M")
    tr = "".join(f"<tr><td>{e(r['name'])}</td><td>{e(r['maker'])}</td><td>{now}</td>"
                 f"<td>{icons.chip({'Yes': 'ok', 'No': 'stop', 'Not sure': 'caution'}[r['known']], r['known'])}</td><td>{e(r['note'])}</td></tr>"
                 for r in rows)
    table = ("<div class=table-wrap style='margin-top:1.5rem'><table class=data><thead><tr><th>Device name</th><th>Maker shown</th>"
             "<th>First seen on this computer</th><th>Known wallet maker</th><th>Notes</th></tr></thead><tbody>"
             + (tr or "<tr><td colspan=5>Nothing new appeared.</td></tr>") + "</tbody></table></div>")
    with _lock:
        _usb.pop(token, None)
    _remember_usb(answers, level, rows)
    return _page("Device name", icons.result({"info": "info"}.get(level, level), sentence=sentence,
                                             extra="<p class=note>A matching name does not mean the inside of the device was checked.</p>",
                                             actions=(f"<a class='btn btn-primary' href='{_url(answers, step='watch')}'>Watch this wallet</a>"
                                                      if level == "ok" else f"<a class='btn btn-primary' href='{_url(answers)}'>Back to the result</a>")
                                             + f"<a class='btn btn-quiet' href='{_url(answers, step='custody')}'>Save a custody record</a>")
                 + table)


def usb_status(token):
    with _lock:
        job = _usb.get(token)
    if not job:
        return {"new": 0, "gone": True}
    try:
        return {"new": len(usbcheck.new_devices(job["before"], usbcheck.snapshot()))}
    except usbcheck.NotAvailable:
        return {"new": 0, "error": True}


def watch(answers, msg=None, level="info", value=""):
    chain_opts = "".join(f"<option value={k}>{e(v[0])}</option>" for k, v in mywallets.CHAINS.items())
    warn = ""
    if level == "stop":
        warn = icons.result("stop", sentence="Those look like recovery words. Never paste them here. The Desk does not need them. "
                                             "Do not give those words to anyone.",
                            actions=f"<a class='btn btn-stop' href='{_url(answers, step='watch')}'>Clear the box</a>") + "<div style='height:1.5rem'></div>"
    elif msg:
        warn = icons.result(level, sentence=msg) + "<div style='height:1.5rem'></div>"
    rows = "".join(f"<tr><td>{e(w['label_chain'])}</td><td class=addr>{e(w['address'])}</td><td>{e(w.get('checked') or 'Not yet')}</td>"
                   f"<td>{e(w.get('error') or 'Watching')}</td></tr>" for w in mywallets.status())
    listing = ("<section class=card style='margin-top:1.5rem'><h2>Wallets being watched</h2><div class=table-wrap><table class=data><thead><tr>"
               f"<th>Network</th><th>Address</th><th>Last checked</th><th>Status</th></tr></thead><tbody>{rows}</tbody></table></div></section>") if rows else ""
    return _page("Watch this wallet", warn + "<section class=card><p>The Desk checks this address every few minutes and alerts you the moment "
                 "money leaves it. It can't stop a payment, but minutes matter for freeze requests.</p>"
                 f"<form method=post action=/hwcheck autocomplete=off><input type=hidden name=do value=watch><input type=hidden name=a value='{e(_a(answers))}'>"
                 "<div class=field><label for=wa>Wallet address</label><p class=hint>Paste the public address only.</p>"
                 f"<input type=text id=wa name=address value='{e(value)}' spellcheck=false autocapitalize=off required></div>"
                 f"<div class=field><label for=wc>Network</label><select id=wc name=chain>{chain_opts}</select></div>"
                 "<button class='btn btn-primary'>Watch this wallet</button></form>"
                 "<p class=note>Tip: send a small amount first, wait a few days, then move the rest.</p></section>" + listing)


def custody(answers, msg=None, level="info", saved=None):
    top = icons.result(level, sentence=msg) + "<div style='height:1.5rem'></div>" if msg else ""
    if saved:
        return _page("Custody record", icons.result("info", "Saved on this computer", f"Saved at {saved['time']}. File: {saved['file']}",
                                                    actions=f"<a class='btn btn-primary' href='{_url(answers)}'>Done</a>"))
    f = lambda name, label, hint="", req=False, typ="text": (
        f"<div class=field><label for={name}>{e(label)}</label>" + (f"<p class=hint>{'Required. ' if req else ''}{e(hint)}</p>" if hint or req else "")
        + f"<input type={typ} id={name} name={name}{' required' if req else ''}></div>")
    return _page("Custody record", top + "<section class=card><p>A paper trail of this purchase, kept only on this computer. "
                 "It goes into an IC3 report or officer packet only if you choose. The Desk never asks for a recovery phrase.</p>"
                 f"<form method=post action=/hwcheck enctype=multipart/form-data><input type=hidden name=do value=custody><input type=hidden name=a value='{e(_a(answers))}'>"
                 + f("maker", "Maker", "The name printed on the box.", True) + f("seller", "Seller", "Store or person.", True)
                 + f("date", "Date bought", "", True, "date") + f("price", "Price paid", "Numbers, and the currency. Example: 149 USD", True)
                 + f("order", "Order number") + f("serial", "Serial number", "From the box or the device screen. Not the recovery phrase.")
                 + "<div class=upload><strong>Receipt</strong><p class=hint>Photo or PDF, under 10 MB.</p><input type=file name=receipt accept='image/*,application/pdf'></div>"
                   "<div class=upload style='margin-top:1rem'><strong>Photos</strong><p class=hint>Up to 4 photos of the box and the seal.</p>"
                   "<input type=file name=photos accept='image/*' multiple></div>"
                   "<div class=actions><button class='btn btn-primary'>Save custody record</button></div></form></section>")


# ------------------------------------------------------------------ requests ----
def page(query, phone=False):
    from urllib.parse import parse_qs
    q = {k: v[0] for k, v in parse_qs(query or "").items()}
    answers = parse(q.get("a", ""))
    step = q.get("step", "")
    if step == "watch":
        return watch(answers)
    if step == "custody":
        return custody(answers)
    if len(answers) < len(QUESTIONS):
        return question(answers) if (answers or step == "q") else start()
    if step == "next":
        return next_steps(answers)
    if step in ("unplug", "usb", "phoneusb") and phone:
        return phone_usb(answers)
    if step == "unplug":
        return unplug(answers)
    if step == "usb":
        return usb_result(answers, q.get("t", ""))
    return result(answers, phone)


def post(form, files=None, phone=False):
    answers = parse(form.get("a", ""))
    do = form.get("do")
    if do == "usb_start":
        if phone:
            return phone_usb(answers)
        try:
            before = usbcheck.snapshot()
        except usbcheck.NotAvailable as ex:
            return _page("Device name", icons.result("info", "The device list isn't available", str(ex),
                                                     actions=f"<a class='btn btn-primary' href='{_url(answers)}'>Back to the result</a>"))
        token = secrets.token_urlsafe(12)
        with _lock:
            for k in [k for k, v in _usb.items() if time.time() - v["at"] > 900]:
                _usb.pop(k)
            _usb[token] = {"before": before, "at": time.time()}
        return plug_in(answers, token)
    if do == "watch":
        addr, chain = form.get("address", ""), form.get("chain", "")
        why = mywallets.add(addr, chain)
        if why == "seed":
            return watch(answers, level="stop")          # the words are not echoed back, saved or sent
        if why:
            return watch(answers, why, "careful", value=addr if " " not in addr.strip() else "")
        return watch(answers, "Now watching this wallet. You'll get an alert the moment money leaves it.", "info")
    if do == "custody":
        return save_custody(answers, form, files or {})
    return page("")


def save_custody(answers, form, files):
    missing = [lbl for k, lbl in (("maker", "Maker"), ("seller", "Seller"), ("date", "Date bought"), ("price", "Price paid")) if not form.get(k, "").strip()]
    if missing:
        return custody(answers, "Please fill in: " + ", ".join(missing) + ".", "careful")
    blob = " ".join(form.get(k, "") for k in ("maker", "seller", "order", "serial", "price"))
    if seedguard.looks_like_seed(form.get("serial", "")) or seedguard.looks_like_seed(blob):
        return custody(answers, "That looks like recovery words. They were not saved. The serial number is on the box or the device screen.", "stop")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    folder = os.path.join(CUSTODY_DIR, stamp)
    os.makedirs(folder, exist_ok=True)
    kept = []
    uploads = [("receipt", f) for f in files.get("receipt", [])][:1] + [("photo", f) for f in files.get("photos", [])][:4]
    for k, (kind, (fname, ctype, data)) in enumerate(uploads, 1):
        if not data:
            continue
        ext = OK_TYPES.get((ctype or "").lower())
        if not ext or len(data) > MAX_FILE:
            return custody(answers, "Use a photo or a PDF under 10 MB.", "careful")
        name = f"{kind}-{k}{ext}"
        with open(os.path.join(folder, name), "wb") as fh:
            fh.write(data)
        kept.append(name)
    rec = {"saved": datetime.now().strftime("%Y-%m-%d %H:%M"), "answers": dict(zip(QIDS, answers)),
           "result": evaluate(answers)[0] if len(answers) == len(QUESTIONS) else None,
           **{k: form.get(k, "").strip()[:200] for k in ("maker", "seller", "date", "price", "order", "serial")}, "files": kept}
    path = os.path.join(folder, "record.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=2)
    try:            # hash every file into the Desk's tamper-evident custody log
        from freezekit import custody as chain_log
        for n in kept + ["record.json"]:
            chain_log.record(os.path.join(folder, n), "saved", "hardware wallet custody record")
    except Exception:
        pass
    return custody(answers, saved={"time": rec["saved"][11:], "file": path})


def _remember_usb(answers, level, rows):
    try:
        from deskui import data as deskdata
        deskdata.note("crypto", {"ok": "ok", "careful": "caution", "stop": "stop"}.get(level, "info"),
                      "Hardware wallet USB check: " + {"ok": "name matches", "careful": "needs a closer look", "stop": "STOP"}.get(level, "nothing new"),
                      ", ".join(r["name"] for r in rows)[:180], "/hwcheck")
    except Exception:
        pass


def parse_multipart(ctype, body):
    """(form, files) from a multipart/form-data body. files: {field: [(filename, content type, bytes)]}."""
    from email.parser import BytesParser
    from email.policy import HTTP
    msg = BytesParser(policy=HTTP).parsebytes(b"Content-Type: " + ctype.encode("latin-1") + b"\r\n\r\n" + body)
    form, files = {}, {}
    if not msg.is_multipart():
        return form, files
    for part in msg.iter_parts():
        name = part.get_param("name", header="content-disposition")
        if not name:
            continue
        fname = part.get_filename()
        data = part.get_payload(decode=True) or b""
        if fname is not None:
            files.setdefault(name, []).append((fname, part.get_content_type(), data))
        else:
            form[name] = data.decode("utf-8", "replace")
    return form, files
