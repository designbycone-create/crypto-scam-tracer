"""One-click updates for ScamHunter Desk.

    check()   -> what's installed, what's newest on GitHub, and what changed (cached 6 h)
    apply()   -> download that exact commit, back up the code it replaces, install it, run the
                 offline tests, and roll back automatically if any fail
    undo()    -> put back the code from the last update's backup

Rules it keeps:
  * Only ever runs when the user clicks "Install update". Never automatic.
  * Downloads only from github.com over HTTPS, pinned to the exact commit it showed the user.
  * Never touches user data: config.json, victim.json, case files, logs and evidence are not in the
    repository, so nothing in the download can overwrite them. Files are added or replaced, never deleted.
  * Every replaced file is backed up first (backups/update_<from>_<time>/).
"""
import io
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile

REPO = "designbycone-create/crypto-scam-tracer"
BRANCH = "main"
HERE = os.path.dirname(os.path.abspath(__file__))
VERSION_FILE = os.path.join(HERE, "VERSION")
STATE = os.path.join(HERE, "update_state.json")
BACKUPS = os.path.join(HERE, "backups")
TESTS = ["shield/test_allchains_offline.py", "shield/test_aptos_offline.py", "freezekit/test_alerts_web_offline.py"]
UA = {"User-Agent": "ScamHunter-Updater", "Accept": "application/vnd.github+json"}

HTTP = None   # test hook: f(url) -> bytes


def _get(url, timeout=30):
    if HTTP:
        return HTTP(url)
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


def _json(url):
    return json.loads(_get(url))


def installed():
    try:
        with open(VERSION_FILE, encoding="utf-8") as f:
            return f.read().strip() or None
    except Exception:
        return None


def _state():
    try:
        with open(STATE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(s):
    with open(STATE, "w", encoding="utf-8") as f:
        json.dump(s, f, indent=1)


def check(force=False, max_age=6 * 3600):
    """{'installed', 'latest', 'latest_date', 'available', 'changes': [msg...], 'checked'} (cached)."""
    s = _state()
    if not force and s.get("checked") and time.time() - s["checked"] < max_age and s.get("installed") == installed():
        return s
    cur = installed()
    head = _json(f"https://api.github.com/repos/{REPO}/commits/{BRANCH}")
    latest = head["sha"]
    changes = []
    if cur and cur != latest:
        try:
            cmp = _json(f"https://api.github.com/repos/{REPO}/compare/{cur}...{latest}")
            changes = [c["commit"]["message"].split("\n")[0] for c in cmp.get("commits", [])][::-1][:30]
        except Exception:
            changes = []
    elif not cur:
        changes = [head["commit"]["message"].split("\n")[0]]
    s = dict(_state())        # keep last_backup etc.
    s.update({"installed": cur, "latest": latest, "latest_date": head["commit"]["committer"]["date"],
              "available": cur != latest, "changes": changes, "checked": time.time(), "error": None})
    _save_state(s)
    return s


def _run_tests(root):
    failed = []
    for t in TESTS:
        p = os.path.join(root, t)
        if not os.path.exists(p):
            continue
        try:
            r = subprocess.run([sys.executable, p], cwd=root, capture_output=True, text=True, timeout=600)
            if r.returncode != 0:
                failed.append(f"{t}: {(r.stdout + r.stderr).strip().splitlines()[-1:] or ['failed']}")
        except Exception as e:
            failed.append(f"{t}: {e}")
    return failed


def _copy_tree(src_root, dst_root, backup_root=None, added=None):
    n = 0
    for d, _, files in os.walk(src_root):
        for fn in files:
            src = os.path.join(d, fn)
            rel = os.path.relpath(src, src_root)
            dst = os.path.join(dst_root, rel)
            if backup_root and os.path.exists(dst):
                b = os.path.join(backup_root, rel)
                os.makedirs(os.path.dirname(b), exist_ok=True)
                shutil.copy2(dst, b)
            elif added is not None and not os.path.exists(dst):
                added.append(rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            n += 1
    return n


def apply(sha=None, log=print):
    """Install commit `sha` (default: the latest from check()). Returns a result dict."""
    s = check(force=True) if not sha else _state()
    sha = sha or s.get("latest")
    if not sha:
        raise RuntimeError("couldn't reach GitHub to find the latest version")
    data = _get(f"https://github.com/{REPO}/archive/{sha}.zip", timeout=120)
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()
    top = names[0].split("/")[0]
    if not top.endswith(sha) or f"{top}/desk.py" not in names:
        raise RuntimeError("the download didn't look like ScamHunter at that version; nothing was changed")
    for n in names:
        if ".." in n.split("/") or n.startswith("/"):
            raise RuntimeError("unsafe path in download; nothing was changed")
    stage = os.path.join(HERE, "backups", f"_stage_{int(time.time())}")
    os.makedirs(stage, exist_ok=True)
    z.extractall(stage)
    src = os.path.join(stage, top)
    frm = (installed() or "unknown")[:7]
    bdir = os.path.join(BACKUPS, f"update_{frm}_{time.strftime('%Y%m%d_%H%M%S')}")
    os.makedirs(bdir, exist_ok=True)
    with open(os.path.join(bdir, "_previous_version.txt"), "w") as f:
        f.write(installed() or "")
    added = []
    n = _copy_tree(src, HERE, backup_root=bdir, added=added)
    with open(os.path.join(bdir, "_added_files.json"), "w") as f:
        json.dump(added, f)
    shutil.rmtree(stage, ignore_errors=True)
    log(f"installed {n} files from {sha[:7]}; testing")
    failed = _run_tests(HERE)
    if failed:
        _restore(bdir)                               # roll back: replaced files back, new files removed
        raise RuntimeError("the new version failed its self-tests, so it was rolled back: " + "; ".join(failed)[:300])
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--user", "-q", "-r", os.path.join(HERE, "requirements.txt")],
                       capture_output=True, timeout=300)
    except Exception:
        pass
    with open(VERSION_FILE, "w") as f:
        f.write(sha)
    st = _state()
    st.update({"installed": sha, "available": False, "last_backup": bdir, "updated_at": time.time(), "changes": []})
    _save_state(st)
    return {"ok": True, "version": sha, "files": n, "backup": bdir}


def _restore(bdir):
    meta = ("_previous_version.txt", "_added_files.json")
    for d, _, files in os.walk(bdir):
        for fn in files:
            src = os.path.join(d, fn)
            rel = os.path.relpath(src, bdir)
            if rel in meta:
                continue
            dst = os.path.join(HERE, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    try:
        added = json.load(open(os.path.join(bdir, "_added_files.json")))
    except Exception:
        added = []
    for rel in added:          # only files this update created; never anything of the user's
        p = os.path.join(HERE, rel)
        if os.path.isfile(p):
            os.remove(p)


def undo():
    bdir = _state().get("last_backup")
    if not bdir or not os.path.isdir(bdir):
        raise RuntimeError("no previous update to undo")
    prev = open(os.path.join(bdir, "_previous_version.txt")).read().strip() if os.path.exists(
        os.path.join(bdir, "_previous_version.txt")) else ""
    _restore(bdir)
    if prev:
        with open(VERSION_FILE, "w") as f:
            f.write(prev)
    st = _state()
    st.update({"installed": prev or None, "last_backup": None, "checked": 0})
    _save_state(st)
    return {"ok": True, "version": prev}


def relaunch_desk(stop_children):
    """Restart the whole Desk so new code loads: stop the watchers, start a fresh Desk a few seconds
    later (detached), and exit this one."""
    stop_children()
    vbs = os.path.join(HERE, "run_desk_hidden.vbs")
    if os.name == "nt" and os.path.exists(vbs):
        args = [os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "wscript.exe"), vbs]   # how the Desk normally starts: no window
    else:
        args = [sys.executable] + list(sys.argv)
    code = f"import subprocess,time;time.sleep(3);subprocess.Popen({args!r}, cwd={HERE!r})"
    kw = {}
    exe = sys.executable
    if os.name == "nt":
        kw["creationflags"] = 0x00000008 | 0x00000200    # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        w = sys.executable.replace("python.exe", "pythonw.exe")
        exe = w if os.path.exists(w) else sys.executable
    else:
        kw["start_new_session"] = True
    subprocess.Popen([exe, "-c", code], cwd=HERE, **kw)
    time.sleep(0.5)
    os._exit(0)


if __name__ == "__main__":
    if sys.argv[1:2] == ["apply"]:
        print(apply())
    elif sys.argv[1:2] == ["undo"]:
        print(undo())
    else:
        print(json.dumps(check(force=True), indent=1))
