"""Offline tests for the New hardware wallet check (shield/hwcheck.py, usbcheck.py, mywallets.py) and the quick check.

Run: python test_hwcheck_offline.py
"""
import html as htmlmod
import json
import os
import re
import shutil
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

import securestore  # noqa: E402
from deskui import quick, seedguard  # noqa: E402
from relay import policy  # noqa: E402
from shield import hwcheck as hw, mywallets, usbcheck  # noqa: E402

ok = fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1
    else:
        fail += 1
        print("FAIL:", name)


tmp = tempfile.mkdtemp()
os.chdir(tmp)
securestore.BACKEND = (lambda b: b"S" + b[::-1], lambda b: b[1:][::-1])
SEED = "abandon ability able about above absent absorb abstract absurd abuse access accident"
CLEAN = ["ledger", "maker", "no", "created", "no", "no", "no"]
BANNED = re.compile(r"\b(safe|genuine|verified)\b", re.I)

# ---- rules
check("clean answers -> no red flags", hw.evaluate(CLEAN)[0] == "ok")
for i, code in [(2, "yes"), (3, "yes"), (5, "yes"), (4, "yes"), (6, "yes"), (1, "named")]:
    a = CLEAN[:]; a[i] = code
    check(f"STOP on {hw.QIDS[i]}={code}", hw.evaluate(a)[0] == "stop")
for i, code in [(0, "other"), (0, "unknown"), (1, "private"), (1, "gift"), (2, "unknown"), (3, "notyet"), (4, "unknown")]:
    a = CLEAN[:]; a[i] = code
    check(f"careful on {hw.QIDS[i]}={code}", hw.evaluate(a)[0] == "careful")
a = CLEAN[:]; a[2] = "yes"; a[1] = "gift"
lv, why = hw.evaluate(a)
check("STOP keeps careful reasons under Why", lv == "stop" and len(why) == 2)
check("parse drops bad answers", hw.parse("ledger,bogus,no") == ["ledger"])
check("parse keeps order", hw.parse(",".join(CLEAN)) == CLEAN)

# ---- screens
U = lambda x: htmlmod.unescape(x)
check("start screen", "Start the check" in hw.page("") and hw.HIDDEN_CHIP in U(hw.page("")))
q2 = hw.page("a=ledger")
check("question 2 of 7", "Question 2 of 7" in q2 and "Where did you buy it?" in q2)
check("question links carry answers", "a=ledger%2Cmaker" in q2)
for ans in (CLEAN, ["ledger", "gift", "no", "created", "no", "no", "no"], ["ledger", "maker", "yes", "created", "no", "no", "no"]):
    html = hw.page("a=" + ",".join(ans))
    check(f"result never says safe/genuine/verified ({hw.evaluate(ans)[0]})", not BANNED.search(re.sub(r"<[^>]+>", " ", html)))
    check(f"result keeps the hidden-chip line ({hw.evaluate(ans)[0]})", hw.HIDDEN_CHIP in U(html))
stop_html = hw.page("a=" + ",".join(["ledger", "maker", "yes", "created", "no", "no", "no"]))
check("STOP has no Watch this wallet", "Watch this wallet" not in stop_html and "What to do next" in stop_html)
check("clear result offers USB on the computer", "Continue to the USB check" in hw.page("a=" + ",".join(CLEAN)))
check("clear result on the phone sends you to the computer", "Do this step at your computer" in hw.page("a=" + ",".join(CLEAN), phone=True))
check("phone can't start the USB check", "Do this step at your computer" in hw.post({"do": "usb_start", "a": ",".join(CLEAN)}, phone=True))

# ---- USB judging
LEDGER = [{"InstanceId": "USB\\VID_2C97&PID_4015\\0001", "FriendlyName": "Nano X", "Class": "USB", "Manufacturer": "Ledger"},
          {"InstanceId": "HID\\VID_2C97&PID_4015&MI_00\\7&1", "FriendlyName": "USB Input Device", "Class": "HIDClass"}]
BASE = [{"InstanceId": "USB\\VID_046D&PID_C52B\\5&1", "FriendlyName": "Logitech receiver", "Class": "USB"}]
new = usbcheck.new_devices(BASE, BASE + LEDGER)
check("only new devices", len(new) == 2)
check("Ledger matches", usbcheck.judge(new, "ledger")[0] == "ok")
check("Ledger chosen but Trezor shown -> STOP", usbcheck.judge([{"InstanceId": "USB\\VID_1209&PID_53C1\\1", "FriendlyName": "Trezor", "Class": "USB"}], "ledger")[0] == "stop")
check("Trezor 1209:53c1 recognised", usbcheck.maker({"InstanceId": "USB\\VID_1209&PID_53C1\\1"}) == "Trezor")
check("other 1209 devices aren't Trezor", usbcheck.maker({"InstanceId": "USB\\VID_1209&PID_0001\\1"}) is None)
kb = new + [{"InstanceId": "HID\\VID_2C97&PID_4015&MI_02\\7&2", "FriendlyName": "HID Keyboard Device", "Class": "Keyboard"}]
check("hidden keyboard -> STOP", usbcheck.judge(kb, "ledger")[0] == "stop")
check("Coldcard's keyboard feature allowed", usbcheck.judge([{"InstanceId": "USB\\VID_D13E&PID_CC10\\1", "Class": "Keyboard", "FriendlyName": "Coldcard"}], "other")[0] == "ok")
check("extra drive -> careful", usbcheck.judge(new + [{"InstanceId": "USBSTOR\\X", "FriendlyName": "Disk", "Class": "DiskDrive"}], "ledger")[0] == "careful")
check("nothing new -> info", usbcheck.judge([], "ledger")[0] == "info")
check("unknown maker, other brand -> careful", usbcheck.judge([{"InstanceId": "USB\\VID_1234&PID_5678\\1", "Class": "USB"}], "other")[0] == "careful")
# full USB flow with a fake device list
state = {"devs": BASE}
usbcheck.LIST = lambda: state["devs"]
pg = hw.post({"do": "usb_start", "a": ",".join(CLEAN)})
tok = re.search(r"[?&]t=([A-Za-z0-9_-]+)", pg).group(1)
check("countdown page", "seconds left" in pg and "Now plug it in" in pg)
state["devs"] = BASE + LEDGER
check("poll sees the new devices", hw.usb_status(tok)["new"] == 2)
res = hw.page(f"a={','.join(CLEAN)}&step=usb&t={tok}")
check("USB table shown", "Known wallet maker" in res and "Nano X" in res and "A matching name does not mean" in res)
check("USB result never says safe/genuine/verified", not BANNED.search(re.sub(r"<[^>]+>", " ", res)))
pg = hw.post({"do": "usb_start", "a": "ledger,maker,yes,created,no,no,no"})
tok = re.search(r"[?&]t=([A-Za-z0-9_-]+)", pg).group(1)
check("USB never turns a STOP into a clear result", "STOP" in hw.page(f"a=ledger,maker,yes,created,no,no,no&step=usb&t={tok}"))
usbcheck.LIST = None

# ---- Watch this wallet: recovery words refused, never echoed or saved
for bad in (SEED, "hello there friend", SEED.replace(" ", "  ")):
    out = hw.post({"do": "watch", "address": bad, "chain": "xrpl", "a": ""})
    check(f"words refused ({bad[:12]})", "Those look like recovery words" in out and "abandon" not in out and "hello there" not in out)
check("nothing saved after refusals", not os.path.exists("config.json") or "abandon" not in open("config.json").read())
check("wrong chain refused", "doesn't look like" in U(hw.post({"do": "watch", "address": "0x" + "a" * 40, "chain": "xrpl"})))
XR = "rN7n7otQDd6FczFgLdSqtcsAUxDkw6fzRH"
check("good address saved", "Now watching" in hw.post({"do": "watch", "address": XR, "chain": "xrpl"}))
check("saved in config", mywallets.wallets()[0]["address"] == XR)
since = mywallets.wallets()[0]["since"]
mywallets.XRPL_RPC = lambda m, p: {"transactions": [
    {"hash": "OLD", "tx_json": {"TransactionType": "Payment", "Account": XR, "Destination": "rX", "Amount": "5000000", "date": since - 946684800 - 60}, "meta": {"TransactionResult": "tesSUCCESS"}},
    {"hash": "NEW1", "tx_json": {"TransactionType": "Payment", "Account": XR, "Destination": "rScammerAddressXXXXXXXXXXXXXX", "Amount": "250000000", "date": since - 946684800 + 60}, "meta": {"TransactionResult": "tesSUCCESS"}},
    {"hash": "IN", "tx_json": {"TransactionType": "Payment", "Account": "rOther", "Destination": XR, "Amount": "1", "date": since - 946684800 + 90}, "meta": {"TransactionResult": "tesSUCCESS"}},
    {"hash": "FAILED", "tx_json": {"TransactionType": "Payment", "Account": XR, "Destination": "rX", "Amount": "9", "date": since - 946684800 + 99}, "meta": {"TransactionResult": "tecUNFUNDED"}}]}
sent = []
f = mywallets.check_once(send=lambda t, m, key: sent.append((t, key)))
check("one new outgoing payment alerted", len(f) == 1 and f[0]["txid"] == "NEW1" and "250 XRP" in sent[0][0])
check("not alerted twice", mywallets.check_once(send=lambda t, m, key: sent.append(1)) == [])
class FakeAd:
    def available(self): return False, "Ethereum needs an Etherscan key"
mywallets.ADAPTER = lambda c: FakeAd()
mywallets.add("0x" + "b" * 40, "ethereum")
mywallets.check_once(send=lambda *a, **k: None)
st = {w["chain"]: w for w in mywallets.status()}
check("missing key labelled precisely", "Etherscan key" in st["ethereum"]["error"])

# ---- custody record
form = {"do": "custody", "a": ",".join(CLEAN), "maker": "Ledger", "seller": "ledger.com", "date": "2026-11-26", "price": "149 USD", "serial": "ABC123"}
out = hw.post(form, {"receipt": [("r.pdf", "application/pdf", b"%PDF-1.4 test")], "photos": [("p.jpg", "image/jpeg", b"\xff\xd8x")] * 6})
check("custody saved", "Saved on this computer" in out)
recs = [os.path.join(dp, f) for dp, _, fs in os.walk("hardware_wallets") for f in fs]
check("receipt + 4 photos + record (5th+ photo dropped)", len(recs) == 6)
rec = json.load(open([r for r in recs if r.endswith("record.json")][0]))
check("record content", rec["maker"] == "Ledger" and rec["result"] == "ok" and len(rec["files"]) == 5)
check("seed in serial refused", "recovery words" in hw.post({**form, "serial": SEED}))
check("missing required field", "Please fill in" in hw.post({**form, "seller": ""}))
check("bad file type refused", "Use a photo or a PDF" in hw.post(form, {"receipt": [("x.exe", "application/x-msdownload", b"MZ")]}))
ct = "multipart/form-data; boundary=XX"
body = (b"--XX\r\nContent-Disposition: form-data; name=\"maker\"\r\n\r\nTrezor\r\n--XX\r\nContent-Disposition: form-data; name=\"receipt\"; filename=\"r.png\"\r\n"
        b"Content-Type: image/png\r\n\r\n\x89PNG\r\n--XX--\r\n")
fm, fl = hw.parse_multipart(ct, body)
check("multipart parsed", fm.get("maker") == "Trezor" and fl["receipt"][0][1] == "image/png" and fl["receipt"][0][2] == b"\x89PNG")
check("custody folder is private (gitignored)", "hardware_wallets/" in open(os.path.join(ROOT, ".gitignore")).read())

# ---- quick check routing
check("quick: seed refused", quick.route(SEED)[0] == "seed" and "abandon" not in quick.page("seed"))
check("quick: XRP address", quick.route(XR) == ("address", XR))
check("quick: EVM address", quick.route("0x" + "c" * 40)[0] == "address")
check("quick: phone number", quick.route("(251) 555-0100") == ("number", "2515550100"))
check("quick: message", quick.route("Your account is locked, click here")[0] == "message")
check("quick: plain sentence isn't a seed", not seedguard.looks_like_seed("Hi grandma this is your grandson I need help please send money today"))

# ---- phone rules
check("phone may answer questions", policy.check("GET", "/hwcheck?a=ledger") is None)
check("phone may add a watch address", policy.check("POST", "/hwcheck", b"do=watch&address=r1&chain=xrpl", "application/x-www-form-urlencoded") is None)
check("phone can't upload a custody record", policy.check("POST", "/hwcheck", b"x", "multipart/form-data; boundary=x") is not None)
check("phone may use the quick check", policy.check("POST", "/quick", b"q=hello", "application/x-www-form-urlencoded") is None)

os.chdir(ROOT)
shutil.rmtree(tmp, ignore_errors=True)
print(f"{ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
