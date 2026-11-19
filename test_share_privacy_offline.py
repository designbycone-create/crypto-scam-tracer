"""Offline tests: sharing ScamHunter never shares your case.
  * privacy_guard finds your own case details (wallets, tx IDs, IC3 number, tags, email, phone)
    in files, and ignores exchange names and public exchange wallets;
  * a release isn't signed if your case details are in it;
  * a share copy holds only the signed program files, is checked first, and refuses if needed;
  * 'just protect me' skips case setup; the FTC key is saved encrypted from the Desk.
    python test_share_privacy_offline.py
"""
import json, os, shutil, sys, tempfile, zipfile
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
WORK = tempfile.mkdtemp(prefix="sh_share_")
os.chdir(WORK)
ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
import securestore as S
S.BACKEND = (lambda b: b"SEALED1" + bytes(x ^ 0x5a for x in b), lambda b: bytes(x ^ 0x5a for x in b[7:]))
import privacy_guard as P, release_sig as R  # noqa: E402

SCAM = "rLrDarYHqNJnZwxuRXXuR1HHrBJKL7gbkm"
TX = "B" * 63 + "7"
KUCOIN_PUBLIC = json.load(open(os.path.join(ROOT, "freezekit", "channels.json")))
pub_addr = next(iter(__import__("re").findall(r"\br[1-9A-HJ-NP-Za-km-z]{24,34}\b", open(os.path.join(ROOT, "scam_investigator", "labels.json")).read())), None)
case = os.path.join(WORK, "case"); os.makedirs(case)
json.dump({"name": "Pat Example", "email": "pat.victim@example.org", "phone": "251-555-0199", "ic3_id": "I2611170042ABCD",
           "scam_wallet": SCAM, "tx_hash": TX}, open(os.path.join(case, "victim.json"), "w"))
json.dump([{"name": "KuCoin", "address": pub_addr, "tag": 2097644724}], open(os.path.join(case, "submissions.json"), "w"))
json.dump({"scam_wallet": SCAM, "ntfy_topic": S.protect("secret-topic")}, open(os.path.join(case, "config.json"), "w"))
vals = P.case_values(case)
r.append(ok({SCAM, TX, "I2611170042ABCD", "2097644724", "251-555-0199"} <= vals, "collects wallet, tx ID, IC3 number, deposit tag, phone"))
r.append(ok("KuCoin" not in vals and "Pat Example" not in vals and (pub_addr is None or pub_addr not in vals),
            "ignores exchange names, the copyright-style name, and public exchange wallets"))
r.append(ok(not any(v.startswith("dpapi:") for v in vals), "encrypted values aren't treated as case details"))

prog = os.path.join(WORK, "prog"); os.makedirs(os.path.join(prog, "shield"))
open(os.path.join(prog, "desk.py"), "w").write("print('hi')\n")
open(os.path.join(prog, "shield", "x.py"), "w").write("# exchanges: KuCoin, Binance\n")
r.append(ok(P.find(prog, vals) == {}, "clean program: nothing found"))
open(os.path.join(prog, "shield", "test_y.py"), "w").write(f'SCAM = "{SCAM}"\n')
hits = P.find(prog, vals)
r.append(ok(list(hits) == [os.path.join(prog, "shield", "test_y.py")], "a test file with the real scam wallet is caught"))

# signing refuses
sk = os.urandom(32)
R._load_private = lambda path=None: sk
os.environ["SCAMHUNTER_CASE_DIR"] = case
try:
    R.sign_folder(prog, "t"); refused = False
except SystemExit as ex:
    refused = "NOT SIGNED" in str(ex) and "test_y.py" in str(ex) and SCAM not in str(ex)
r.append(ok(refused and not os.path.exists(os.path.join(prog, R.MANIFEST)), "release with your case details is NOT signed (file named, value not shown)"))
os.remove(os.path.join(prog, "shield", "test_y.py"))
R.sign_folder(prog, "t")
r.append(ok(os.path.exists(os.path.join(prog, R.MANIFEST)), "clean release signs normally"))

# share copy
from freezekit import share_web as W
W.HERE = prog
R.RELEASE_PUBKEY = R.public_key(sk).hex()
for f in ("config.json", "victim.json", "submissions.json"):
    shutil.copy(os.path.join(case, f), os.path.join(prog, f))      # the user's private files sit in the same folder
open(os.path.join(prog, "prescreen_log.jsonl"), "w").write("{}\n")
out = os.path.join(WORK, "Downloads")
okc, msg, path = W.make_copy(out, case)
names = zipfile.ZipFile(path).namelist() if path else []
r.append(ok(okc and sorted(names) == sorted(["ScamHunter/desk.py", "ScamHunter/shield/x.py", "ScamHunter/RELEASE.json", "ScamHunter/RELEASE.sig", "ScamHunter/INSTALL.cmd"]),
            f"share copy = signed program files + signature + INSTALL.cmd only ({len(names)} files)"))
r.append(ok(not any(n.endswith(("config.json", "victim.json", "submissions.json", "prescreen_log.jsonl")) for n in names), "none of your case files are in it"))
blob = b"".join(zipfile.ZipFile(path).read(n) for n in names)
r.append(ok(SCAM.encode() not in blob and b"pat.victim" not in blob, "no case value anywhere inside the zip"))
open(os.path.join(prog, "shield", "x.py"), "a").write(f"# {SCAM}\n")
okc2, msg2, _ = W.make_copy(out, case)
r.append(ok(not okc2 and "doesn't match its signed release" in msg2, "a program file changed after signing: no share copy"))
R.sign_folder(prog, "t") if False else None
os.remove(path)
# re-sign including the leak (simulating a bad release that got signed elsewhere) -> guard still refuses
man = json.load(open(os.path.join(prog, R.MANIFEST)))
os.environ["SCAMHUNTER_CASE_DIR"] = os.path.join(WORK, "nocase")
aside = os.path.join(WORK, "aside"); os.makedirs(aside)
for f in ("config.json", "victim.json", "submissions.json", "prescreen_log.jsonl"):
    shutil.move(os.path.join(prog, f), os.path.join(aside, f))
R.sign_folder(prog, "t")                       # signed without the private files, but with the leaked wallet in x.py
for f in os.listdir(aside):
    shutil.move(os.path.join(aside, f), os.path.join(prog, f))
okc3, msg3, p3 = W.make_copy(out, case)
r.append(ok(not okc3 and "x.py" in msg3 and SCAM not in msg3 and not p3, "a signed release that contains your case: share copy refused"))
shutil.copy(os.path.join(ROOT, ".gitignore"), os.path.join(prog, ".gitignore"))
r.append(ok(W._private("config.json") and W._private("evidence_store/a/b.json") and W._private("x.log") and not W._private("shield/x.py")
            and not W._private("config.example.json"), "private-file rule: settings, evidence, logs yes; program files and examples no"))
os.environ["SCAMHUNTER_CASE_DIR"] = os.path.join(WORK, "nocase")
for f in ("victim.json", "submissions.json", "prescreen_log.jsonl"):
    os.remove(os.path.join(prog, f))
open(os.path.join(prog, "shield", "x.py"), "w").write("# clean\n")
json.dump({"ntfy_topic": S.protect("only-encrypted-keys-here")}, open(os.path.join(prog, "config.json"), "w"))
R.sign_folder(prog, "t")                       # a release that (wrongly) lists config.json
okc4, msg4, p4 = W.make_copy(out, case)
r.append(ok(not okc4 and "config.json" in msg4 and not p4, "a release that lists config.json (even with only encrypted keys): share copy refused"))
page = W.page()
r.append(ok("127.0.0.1" in page and "irm https://raw.githubusercontent.com" in page and "victim.json" in page, "share page: privacy explained, install line ready to send"))

# install.ps1 can install a share copy only after checking its signature
ps = open(os.path.join(ROOT, "install.ps1")).read()
r.append(ok("SCAMHUNTER_FROM" in ps and "release_sig.py`\" verify" in ps and "failed its signature check" in ps and "TrimEnd('\\')" in ps,
            "installer: share copy is signature-checked first, refused if it fails"))

# 'just protect me'
os.chdir(os.path.join(WORK, "Downloads"))
from freezekit import setup as SU
r.append(ok(SU.needed(), "fresh install with no case: setup page shown"))
SU.protect_only()
r.append(ok(not SU.needed() and json.load(open("config.json"))["protect_only"] is True, "'just protect me' skips case setup"))
src = open(os.path.join(ROOT, "desk.py"), encoding="utf-8").read()
r.append(ok('form.get("do") == "protect"' in src and "just protect me" in open(os.path.join(ROOT, "freezekit", "setup.py"), encoding="utf-8").read(),
            "the setup page offers it and the Desk handles it"))

# FTC key from the Desk, encrypted
from shield import callerlist as C
kid = C.save_key("FTC-KEY-abcdef123")
r.append(ok(kid and "FTC-KEY-abcdef123" not in open("config.json").read() and C.key() == "FTC-KEY-abcdef123", "FTC key saved encrypted from the Desk; Key ID shown"))
r.append(ok(kid in C.page() and "FTC-KEY" not in C.page(), "number-check page shows the Key ID, never the key"))
r.append(ok("saved" in C.post({"do": "key", "key": "FTC-KEY-abcdef123"}), "the key form works"))

# wiring
from deskui import shell
r.append(ok(shell.section_for("/share")[0] == "settings" and src.count('"/share"') == 2, "Share page is in Settings with GET and POST routes"))
r.append(ok(os.path.exists(os.path.join(ROOT, "SETUP.md")) and "fa946f505ab1ef57" in open(os.path.join(ROOT, "SETUP.md"), encoding="utf-8").read(),
            "SETUP.md exists and names the signing key"))

os.chdir(ROOT)
shutil.rmtree(WORK, ignore_errors=True)
print(f"{sum(r)}/{len(r)} passed"); sys.exit(0 if all(r) else 1)
