"""Offline test of one-click updates (no network): install, user data untouched, auto-rollback, undo.
    python test_updater_offline.py
"""
import io, json, os, shutil, sys, tempfile, zipfile
ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
import updater

ok = lambda c, m: print(("PASS " if c else "FAIL ") + m) or bool(c)
r = []
OLD, NEW, BAD = "a" * 40, "b" * 40, "c" * 40
home = tempfile.mkdtemp()
for f, t in {"desk.py": "v1", "shield/x.py": "old", "config.json": '{"secret": 1}', "victim.json": "{}", "VERSION": OLD,
             "shield/test_allchains_offline.py": "import sys; sys.exit(0)"}.items():
    os.makedirs(os.path.dirname(os.path.join(home, f)) or home, exist_ok=True)
    open(os.path.join(home, f), "w").write(t)


def zipof(sha, files):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for f, t in files.items():
            z.writestr(f"crypto-scam-tracer-{sha}/{f}", t)
    return b.getvalue()


ARCH = {NEW: zipof(NEW, {"desk.py": "v2", "shield/x.py": "new", "shield/y.py": "added", "requirements.txt": "",
                         "shield/test_allchains_offline.py": "import sys; sys.exit(0)"}),
        BAD: zipof(BAD, {"desk.py": "v3-broken", "requirements.txt": "",
                         "shield/test_allchains_offline.py": "import sys; print('1 failed'); sys.exit(1)"})}
HEAD = {"sha": NEW}


def http(url):
    if url.endswith("/commits/" + updater.BRANCH):
        return json.dumps({"sha": HEAD["sha"], "commit": {"message": "Add Aptos\n\nbody", "committer": {"date": "2026-11-01T20:00:00Z"}}}).encode()
    if "/compare/" in url:
        return json.dumps({"commits": [{"commit": {"message": "Add Aptos"}}, {"commit": {"message": "Telegram page"}}]}).encode()
    for sha, data in ARCH.items():
        if url.endswith(f"/archive/{sha}.zip"):
            return data
    raise OSError("404 " + url)


updater.HTTP = http
updater.HERE = home
updater.VERSION_FILE = os.path.join(home, "VERSION")
updater.STATE = os.path.join(home, "update_state.json")
updater.BACKUPS = os.path.join(home, "backups")
updater.TESTS = ["shield/test_allchains_offline.py"]

s = updater.check(force=True)
r.append(ok(s["available"] and s["changes"] == ["Telegram page", "Add Aptos"], "check: update available, lists what's new"))
res = updater.apply()
rd = lambda f: open(os.path.join(home, f)).read()
r.append(ok(res["ok"] and rd("desk.py") == "v2" and rd("shield/y.py") == "added" and rd("VERSION") == NEW, "apply: new code installed and version recorded"))
r.append(ok(rd("config.json") == '{"secret": 1}' and rd("victim.json") == "{}", "user data (config, case) untouched"))
r.append(ok(open(os.path.join(res["backup"], "desk.py")).read() == "v1", "replaced files backed up first"))
r.append(ok(not updater.check(force=True)["available"], "after update: up to date"))

HEAD["sha"] = BAD
try:
    updater.apply()
    r.append(ok(False, "failing self-test rolls back"))
except RuntimeError as e:
    r.append(ok("rolled back" in str(e) and rd("desk.py") == "v2" and rd("VERSION") == NEW, "new version failing its self-tests is rolled back automatically"))

HEAD["sha"] = NEW
u = updater.undo()
r.append(ok(rd("desk.py") == "v1" and rd("shield/x.py") == "old" and rd("VERSION") == OLD
            and not os.path.exists(os.path.join(home, "shield/y.py")), "undo restores the previous version and removes files the update added"))

ARCH["d" * 40] = zipof("e" * 40, {"desk.py": "evil"})
try:
    updater.apply("d" * 40)
    r.append(ok(False, "mismatched download refused"))
except RuntimeError:
    r.append(ok(rd("desk.py") == "v1", "download that doesn't match the requested version is refused; nothing changed"))

# ---- signed releases ----
import release_sig as rs
SK = bytes(range(32)); PK = rs.public_key(SK).hex(); SK2 = bytes(range(1, 33))
src_mod = open(os.path.join(ROOT, "release_sig.py")).read()
import re as _re
open(os.path.join(home, "release_sig.py"), "w").write(_re.sub(r'RELEASE_PUBKEY = "[0-9a-f]*"', f'RELEASE_PUBKEY = "{PK}"', src_mod, count=1))


def signed_zip(sha, files, sk=SK, tamper=None):
    d = tempfile.mkdtemp()
    for f, t in files.items():
        os.makedirs(os.path.dirname(os.path.join(d, f)) or d, exist_ok=True)
        open(os.path.join(d, f), "w").write(t)
    fh = rs.file_hashes(d); meta = {"signed_at": "t", "note": ""}
    sig = rs.sign(sk, rs.canonical(fh) + rs.canonical(meta))
    files = dict(files, **{"RELEASE.json": json.dumps({"pubkey": rs.public_key(sk).hex(), "files": fh, "meta": meta}),
                           "RELEASE.sig": sig.hex()})
    if tamper:
        files.update(tamper)
    return zipof(sha, files)


base = {"desk.py": "v4", "requirements.txt": "", "shield/test_allchains_offline.py": "import sys; sys.exit(0)"}
for code, (zipdata, expect_ok, msg) in {
    "1" * 40: (signed_zip("1" * 40, base), True, "release signed by the trusted key installs"),
    "2" * 40: (signed_zip("2" * 40, base, tamper={"desk.py": "v4-evil"}), False, "a file changed after signing is refused"),
    "3" * 40: (signed_zip("3" * 40, base, sk=SK2), False, "a release signed by a different key is refused"),
    "4" * 40: (zipof("4" * 40, base), False, "an unsigned release is refused once a key is trusted"),
}.items():
    ARCH[code] = zipdata
    before = rd("desk.py")
    try:
        res2 = updater.apply(code)
        r.append(ok(expect_ok and rd("desk.py") == "v4" and "verified" in res2["signature"], msg))
    except RuntimeError as e:
        r.append(ok((not expect_ok) and rd("desk.py") == before and "NOT installed" in str(e), msg + f" ({str(e)[:60]})"))

shutil.rmtree(home, ignore_errors=True)
print(f"{sum(r)}/{len(r)} passed")
sys.exit(0 if all(r) else 1)
