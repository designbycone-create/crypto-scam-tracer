"""Offline tests: keys and tokens in config.json are stored encrypted, and every part of the Desk
that uses them still gets the real value. Windows' protection (DPAPI) is replaced by a stand-in
here; the real one is proven on Windows with `python securestore.py selftest`.
    python test_securestore_offline.py
"""
import json, os, shutil, sys, tempfile
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
WORK = tempfile.mkdtemp(prefix="sh_sec_")
os.chdir(WORK)
ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
import securestore as S  # noqa: E402

KEY = b"\x5a"
def fake_protect(b):
    return b"SEALED1" + bytes(x ^ KEY[0] for x in b)
def fake_unprotect(b):
    if not b.startswith(b"SEALED1"):
        raise OSError("not ours")
    return bytes(x ^ KEY[0] for x in b[7:])
S.BACKEND = (fake_protect, fake_unprotect)

SECRETS = {"ftc_api_key": "FTCKEY-abc123", "ntfy_topic": "scamhunter-private-topic", "etherscan_key": "ETHKEY999",
           "bsc_rpc": "https://bsc.example/v1/RPCKEY777", "extension_token": "EXTTOKEN555", "agentguard_token": "AGTOKEN444",
           "bithomp_token": "BITHOMP333"}
cfg = {"scam_wallet": "rScamWallet", "cases": [{"chain": "ethereum", "address": "0xabc"}], "clipguard": True,
       "telegram": {"bot_token": "123456:TELEGRAMSECRET", "chat_id": "42"},
       "alert_email": {"smtp_host": "smtp.gmail.com", "username": "me@example.com", "app_password": "APPPASSWORD16"}, **SECRETS}
json.dump(cfg, open("config.json", "w"), indent=2)

n = S.migrate()
raw = open("config.json").read()
plain = [v for v in list(SECRETS.values()) + ["TELEGRAMSECRET", "APPPASSWORD16"] if v in raw]
r.append(ok(n == 9 and not plain, f"all 9 secrets encrypted on disk (none readable in the file) {plain or ''}"))
d = json.loads(raw)
r.append(ok(d["scam_wallet"] == "rScamWallet" and d["cases"][0]["address"] == "0xabc" and d["telegram"]["chat_id"] == "42"
            and d["alert_email"]["username"] == "me@example.com" and d["clipguard"] is True, "ordinary settings stay readable"))
r.append(ok(S.migrate() == 0 and open("config.json").read() == raw, "running again changes nothing (already encrypted)"))

# every consumer still gets the real value
import scamconfig
scamconfig._cache = None
r.append(ok(scamconfig.get("ftc_api_key") == "FTCKEY-abc123" and scamconfig.get("bsc_rpc") == SECRETS["bsc_rpc"]
            and scamconfig.get("telegram")["bot_token"] == "123456:TELEGRAMSECRET", "central settings loader: real values"))
from shield import callerlist, evm
r.append(ok(callerlist.key() == "FTCKEY-abc123", "FTC caller list gets its key"))
r.append(ok(evm._cfg("bsc_rpc") == SECRETS["bsc_rpc"] and evm._cfg("etherscan_key") == "ETHKEY999", "chain lookups get their keys"))
from freezekit import chainlookup
r.append(ok(chainlookup._rpc_for("bsc", "PUBLIC") == SECRETS["bsc_rpc"], "wallet lookups use your personal RPC endpoint"))
import alerts
scamconfig._cache = None
ch = alerts.channels(critical=True)
r.append(ok("telegram" in ch and "ntfy" in ch and alerts._topic() == "scamhunter-private-topic", f"alerts: channels ready with real topic/token ({ch})"))
sent = []
import urllib.request
real_urlopen = urllib.request.urlopen
class _Resp:
    def __enter__(s): return s
    def __exit__(s, *a): pass
    def read(s): return b'{"ok":true}'
    status = 200
urllib.request.urlopen = lambda req, *a, **k: (sent.append(getattr(req, "full_url", str(req)) + " " + (getattr(req, "data", b"") or b"").decode()), _Resp())[1]
try:
    alerts._post_telegram({"title": "t", "message": "m", "critical": False})
    alerts._post_ntfy({"title": "t", "message": "m", "critical": False, "actions": []})
except Exception as ex:
    print("  (send error:", ex, ")")
urllib.request.urlopen = real_urlopen
r.append(ok(any("bot123456:TELEGRAMSECRET/sendMessage" in u for u in sent) and any('"topic": "scamhunter-private-topic"' in u for u in sent)
            and not any("dpapi:" in u for u in sent), f"Telegram and ntfy are called with the real token and topic ({len(sent)} calls)"))
from shield import extension_api
from agentguard import token as ag_token
r.append(ok(extension_api.token() == "EXTTOKEN555" and extension_api.authorized({"X-ScamHunter-Ext": "EXTTOKEN555"})
            and not extension_api.authorized({"X-ScamHunter-Ext": S.protect("EXTTOKEN555")}), "browser extension pairing still works (sealed value is not a password)"))
r.append(ok(ag_token() == "AGTOKEN444", "agent firewall token still works"))
from freezekit import alerts_web, setup
r.append(ok("scamhunter-private-topic" in alerts_web.page(), "Alerts page shows your real ntfy topic"))
r.append(ok("scamhunter-private-topic" in setup.page() and "ETHKEY999" not in setup.page(), "Setup page: real topic, keys stay masked"))

# writers keep things encrypted
alerts.set_enabled("telegram", False)
r.append(ok("TELEGRAMSECRET" not in open("config.json").read() and json.load(open("config.json"))["alerts_enabled"]["telegram"] is False,
            "turning a channel off keeps every key encrypted"))
c = json.load(open("config.json")); c.pop("extension_token"); json.dump(c, open("config.json", "w"))
t = extension_api.token()
r.append(ok(t and t not in open("config.json").read(), "a new extension token is saved encrypted"))
ok_, why = setup.save({"scam_wallet": "0x08723392ed15743cc38513c4925f5e6be5c17243", "ntfy_topic": "scamhunter-new-topic",
                        "etherscan_key": "NEWETHKEY"})
raw = open("config.json").read()
scamconfig._cache = None
r.append(ok(ok_ is True and "NEWETHKEY" not in raw and "scamhunter-new-topic" not in raw and scamconfig.get("etherscan_key") == "NEWETHKEY",
            f"setup saves new keys encrypted, and they read back ({why if ok_ is not True else 'saved'})"))
from shield import clipguard
clipguard.post({"do": "off"})
r.append(ok("FTCKEY" not in open("config.json").read() and json.load(open("config.json"))["clipguard"] is False, "other settings pages keep keys encrypted"))

# sealed by another account / computer: treated as not set, never guessed or crashed
foreign = "dpapi:" + "QUJDREVGRw=="
r.append(ok(S.reveal(foreign) == "", "a value sealed elsewhere reads as 'not set'"))
S.BACKEND = None
r.append(ok(S.protect("x") == "x" and S.migrate() == 0, "no Windows protection (Mac/Linux): values left as they are"))
if os.name != "nt":
    r.append(ok(oct(os.stat("config.json").st_mode)[-3:] == "600", "Mac/Linux: config.json readable by your account only"))
S.BACKEND = (fake_protect, lambda b: b"different")
json.dump({"ftc_api_key": "PLAIN"}, open("c2.json", "w"))
try:
    S.migrate("c2.json"); r.append(ok(False, "broken encryption refused"))
except RuntimeError:
    r.append(ok(json.load(open("c2.json"))["ftc_api_key"] == "PLAIN", "if a value wouldn't come back exactly, nothing is changed"))

# the release signing key can be sealed the same way
S.BACKEND = (fake_protect, fake_unprotect)
import release_sig as R
kp = os.path.join(WORK, "signing.key")
sk = os.urandom(32); open(kp, "w").write(sk.hex())
real_pub, R.RELEASE_PUBKEY = R.RELEASE_PUBKEY, R.public_key(sk).hex()
done = R.protect_key(kp)
r.append(ok(done and sk.hex() not in open(kp).read() and R._load_private(kp) == sk, "signing key sealed, and it still signs (reads back exactly)"))
open(kp, "w").write(os.urandom(32).hex())
try:
    R.protect_key(kp); r.append(ok(False, "a key that doesn't match the trusted public key is refused"))
except SystemExit:
    r.append(ok(not open(kp).read().startswith("dpapi:"), "a key that doesn't match the trusted public key is refused, file untouched"))
R.RELEASE_PUBKEY = real_pub

os.chdir(ROOT)
shutil.rmtree(WORK, ignore_errors=True)
print(f"{sum(r)}/{len(r)} passed"); sys.exit(0 if all(r) else 1)
