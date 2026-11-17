"""Offline tests: 'Secrets left in the open' finds seed phrases, private keys, wallet files, API keys
and password notes in files; ignores look-alikes (transaction hashes, public keys, prose, word
lists, placeholders, encrypted values); and never shows or saves the secret itself.
    python test_secretscan_offline.py
"""
import hashlib, json, os, shutil, sys, tempfile, time, zipfile
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
WORK = tempfile.mkdtemp(prefix="sh_secrets_")
os.chdir(WORK)
ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
from shield import secretscan as S  # noqa: E402

B58 = S.B58
def b58check(payload):
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(raw, "big"); s = ""
    while n:
        n, m = divmod(n, 58); s = B58[m] + s
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + s

SEED12 = "legal winner thank year wave sausage worth useful legal winner thank yellow"          # BIP-39 test vector (valid)
SEED24 = " ".join(["abandon"] * 23 + ["art"])                                               # BIP-39 test vector (valid)
NOTSEED = "ocean ladder garden cotton rabbit silent planet window orange pilot river castle"  # 12 list words, bad checksum
PRIV = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
TXH = "9f2c3e0d4b8a7c6e5f1029384756abcdef0123456789abcdef0123456789abcd"
WIF = b58check(b"\x80" + bytes(range(1, 33)) + b"\x01")
BADWIF = WIF[:-1] + ("2" if WIF[-1] != "2" else "3")
XPRV = b58check(bytes.fromhex("0488ADE4") + bytes(9) + bytes(32) + b"\0" + bytes(range(1, 33)))
GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

home = os.path.join(WORK, "home"); docs = os.path.join(home, "Documents"); cloud = os.path.join(home, "OneDrive", "Notes")
code = os.path.join(home, "Documents", "project")
for d in (docs, cloud, code, os.path.join(code, "node_modules")):
    os.makedirs(d, exist_ok=True)
w = lambda p, t: open(p, "w", encoding="utf-8").write(t)
w(os.path.join(docs, "my wallet.txt"), "MetaMask backup\n" + "\n".join(f"{i}. {x}" for i, x in enumerate(SEED12.split(), 1)) + "\n")
w(os.path.join(cloud, "important.txt"), "keep safe: " + SEED24)
w(os.path.join(docs, "words.txt"), NOTSEED)
w(os.path.join(code, "story.py"), f'"""{NOTSEED}"""')
w(os.path.join(docs, "keys.txt"), f"eth private key: 0x{PRIV}\ntx hash: {TXH}\npublic key: {PRIV[::-1]}\nbtc: {WIF}\nold: {BADWIF}\nmaster: {XPRV}\n")
w(os.path.join(code, ".env"), f"API_KEY=realvalue123456\nDB_PASSWORD=changeme\nSECRET_TOKEN=dpapi:QUJDREVGR0g=\nGITHUB={GH}\n")
w(os.path.join(code, "id_rsa"), "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
w(os.path.join(docs, "UTC--2026-01-01T00-00-00Z--abc"), '{"crypto": {"ciphertext": "aa", "kdf": "scrypt"}}')
w(os.path.join(docs, "id.json"), json.dumps(list(range(64))))
w(os.path.join(docs, "logins.txt"), "bank password: Hunter2!!\nemail pwd: blue-sky-9\n")
w(os.path.join(code, "settings.py"), 'password = "x"  # read from env\nPASSWORD_NOTE = "pwd: example"\n')
w(os.path.join(code, "node_modules", "leak.txt"), SEED12)
shutil.copy(os.path.join(ROOT, "shield", "bip39_english.txt"), os.path.join(docs, "wordlist.txt"))
with zipfile.ZipFile(os.path.join(docs, "Recovery.docx"), "w") as z:
    z.writestr("word/document.xml", "<w:document><w:body>" + "".join(f"<w:p><w:r><w:t>{x}</w:t></w:r></w:p>" for x in SEED12.split()) + "</w:body></w:document>")

res, files, cut = S.scan([home])
by = lambda name: [x for x in res if os.path.basename(x["path"]) == name]
kinds = lambda name: sorted(x["kind"] for x in by(name))
r.append(ok(kinds("my wallet.txt") == ["seed"] and by("my wallet.txt")[0]["level"] == "stop", "numbered 12-word seed in a note: URGENT (checksum valid)"))
r.append(ok(kinds("Recovery.docx") == ["seed"], "seed typed into a Word document: found"))
i24 = by("important.txt")
r.append(ok([x["kind"] for x in i24] == ["seed"] and i24[0]["cloud"] and "syncs to the cloud" in i24[0]["advice"], "24-word seed in a OneDrive folder: found, flagged as copied online"))
r.append(ok(kinds("words.txt") == ["seed?"] and by("words.txt")[0]["level"] == "high", "12 seed words with a bad checksum in a note: IMPORTANT (maybe a phrase)"))
r.append(ok(not by("story.py"), "the same words in program code: ignored"))
kk = by("keys.txt")
whats = sorted(x["what"] for x in kk)
r.append(ok(sum(1 for x in kk if x["what"] == "64-character hex private key") == 1 and kk[0]["line"] == 1,
            "labelled hex private key found; transaction hash and public key ignored"))
r.append(ok(any("WIF" in x for x in whats) and sum(1 for x in whats if "WIF" in x) == 1, "Bitcoin WIF key found; one with a bad checksum ignored"))
r.append(ok(any("xprv" in x for x in whats), "extended private key (xprv) found"))
env = by(".env")
r.append(ok(sorted(x["what"] for x in env) == ["GitHub token", "secret setting API_KEY"], "env file: real API key and GitHub token found; placeholder and encrypted value ignored"))
r.append(ok(kinds("id_rsa") == ["key"], "SSH private key found"))
r.append(ok(kinds("UTC--2026-01-01T00-00-00Z--abc") == ["keystore", "keystore"] and by("UTC--2026-01-01T00-00-00Z--abc")[0]["level"] == "caution",
            "Ethereum keystore file: TIDY UP (encrypted, password-dependent)"))
r.append(ok(sorted(kinds("id.json")) == ["key", "wallet"], "Solana keypair file found"))
r.append(ok(kinds("logins.txt") == ["passwords"] and "2 password" in by("logins.txt")[0]["what"], "password note: found once with a count"))
r.append(ok(not by("settings.py"), "password settings in program code: ignored"))
r.append(ok(not by("leak.txt"), "node_modules and other tool folders are skipped"))
r.append(ok(not by("wordlist.txt"), "a list of all 2048 seed words is a word list, not a phrase"))

# never shows or saves the secret
blob = json.dumps(res)
leaks = [s for s in (PRIV, WIF, XPRV, GH, "realvalue123456", "Hunter2", "blue-sky", "legal winner", "abandon abandon", "art") if s in blob.replace(WORK, "")]
r.append(ok(not leaks, f"results contain no secret (no keys, tokens, passwords or seed words) {leaks or ''}"))
summ = open(S.SUMMARY).read()
r.append(ok(WORK not in summ and "home" not in summ and json.loads(summ)["counts"]["stop"] >= 6, "the saved summary has counts only: no file names, no secrets"))
order = [x["level"] for x in res]
r.append(ok(order == sorted(order, key={"stop": 0, "high": 1, "caution": 2}.get), "results sorted urgent first"))

# the Desk page
S.default_folders = lambda: [home]
html = S.page()
r.append(ok("Scan now" in html and home in html and "never shown or saved" in html, "page lists folders and the privacy promise"))
outside = os.path.join(WORK, "elsewhere"); os.makedirs(outside)
S.post({"do": "scan"}, [outside])
r.append(ok(not S._job["running"] and S._job["folders"] != [outside], "a folder that wasn't offered can't be smuggled in through the form"))
S.post({"do": "scan"}, [home])
for _ in range(200):
    if not S._job["running"]:
        break
    time.sleep(0.05)
html = S.page()
r.append(ok("URGENT" in html and "my wallet.txt" in html and PRIV not in html and "legal winner" not in html, "results page: urgent items with file and advice, never the secret"))
r.append(ok(S.reveal_in_folder("9999") is False and S.reveal_in_folder("../etc") is False, "'Show in folder' only accepts a result number"))

# wired into the Desk
from deskui import shell
src = open(os.path.join(ROOT, "desk.py"), encoding="utf-8").read()
r.append(ok(shell.section_for("/secretscan")[0] == "defense" and src.count('"/secretscan"') == 2, "page is in the Online Defense tab with GET and POST routes"))
from deskui import data
r.append(ok(any(e["href"] == "/secretscan" and "files checked" in e["detail"] for e in data.feed()), "a finished scan shows in the live feed (counts only)"))

os.chdir(ROOT)
shutil.rmtree(WORK, ignore_errors=True)
print(f"{sum(r)}/{len(r)} passed"); sys.exit(0 if all(r) else 1)
