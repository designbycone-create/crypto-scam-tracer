"""Secrets left in the open: find recovery (seed) phrases, private keys, wallet files, API keys and
password notes saved in ordinary files on this computer.

Why: a seed phrase typed into a note, a screenshot folder that syncs to the cloud, or a key in a
.env file is how many wallets get emptied. Key-stealing malware and automated attack tools search
a computer's files for exactly these, in seconds (1Password, "After the breach, attackers go
credential harvesting", Nov 2026).

What it promises:
  * Everything runs on this computer. Nothing is sent anywhere.
  * It never shows, logs or saves the secret itself: only the file, the line, and what kind of
    secret it is. Results are kept in memory only (a saved list of where your seed phrases are
    would help an intruder), and only the counts go to the Desk feed.
  * Seed phrases are checked against the BIP-39 checksum, so a real wallet phrase is told apart
    from a list of words.

Not covered: pictures (a photo or screenshot of a seed phrase needs text recognition) and
password-protected documents.

    python -m shield.secretscan <folder> [<folder> ...]
"""
import base64
import hashlib
import json
import os
import re
import threading
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SUMMARY = "secretscan_summary.json"          # counts and time only, never paths or secrets

with open(os.path.join(HERE, "bip39_english.txt"), encoding="utf-8") as _f:
    WORDS = _f.read().split()
INDEX = {w: i for i, w in enumerate(WORDS)}
assert len(WORDS) == 2048

TEXT_EXT = {".txt", ".md", ".rtf", ".csv", ".json", ".env", ".log", ".ini", ".cfg", ".conf", ".config", ".yaml", ".yml",
            ".toml", ".xml", ".html", ".htm", ".properties", ".ps1", ".bat", ".cmd", ".sh", ".py", ".js", ".ts", ".key", ".pem",
            ".sql", ".tex", ".note", ".rtfd", ""}
ZIP_EXT = {".docx": ["word/document.xml"], ".odt": ["content.xml"], ".xlsx": ["xl/sharedStrings.xml"], ".ods": ["content.xml"]}
DOC_EXT = {".txt", ".md", ".rtf", ".csv", ".note", ".rtfd", ".docx", ".odt", ".xlsx", ".ods", ".html", ".htm", ""}   # where people save notes
CONFIG_EXT = {".env", ".ini", ".cfg", ".conf", ".config", ".yaml", ".yml", ".toml", ".properties", ".json", ".ps1", ".sh", ".bat", ".cmd", ""}
WALLET_NAMES = {"wallet.dat": "Bitcoin Core wallet file", "seed.seco": "Exodus wallet seed file", "default_wallet": "Electrum wallet file",
                "id.json": "possible Solana keypair file"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "site-packages", "AppData", "$Recycle.Bin", "Windows",
             "Program Files", "Program Files (x86)", "ProgramData", ".cache", ".npm", ".gradle", ".m2", "backups", "callers_daily"}
CLOUD = ("onedrive", "dropbox", "google drive", "googledrive", "icloud", "box sync", "pcloud", "mega")
MAX_TEXT = 5_000_000
MAX_ZIP = 25_000_000

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58check(s):
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            return None
        n = n * 58 + i
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(s) - len(s.lstrip("1"))) + raw
    if len(raw) < 5:
        return None
    body, chk = raw[:-4], raw[-4:]
    return body if hashlib.sha256(hashlib.sha256(body).digest()).digest()[:4] == chk else None


def bip39_valid(words):
    """True if these 12/15/18/21/24 words are a real BIP-39 phrase (checksum matches)."""
    if len(words) not in (12, 15, 18, 21, 24) or any(w not in INDEX for w in words):
        return False
    bits = "".join(format(INDEX[w], "011b") for w in words)
    cs = len(words) // 3
    ent = int(bits[:-cs], 2).to_bytes((len(bits) - cs) // 8, "big")
    return format(hashlib.sha256(ent).digest()[0], "08b")[:cs] == bits[-cs:]


TOKEN_RX = [
    ("AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
]
PEM = re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY( BLOCK)?-----")
HEX64 = re.compile(r"(?<![0-9a-fA-Fx])(0x)?[0-9a-fA-F]{64}(?![0-9a-fA-F])")
KEYWORD = re.compile(r"priv|secret|key|seed|wallet|metamask|phantom", re.I)
NOT_PRIVATE = re.compile(r"\b(tx|txid|hash|transaction|sha-?256|checksum|digest|public|pub_?key|signature|sig|fingerprint|commit|address|block)", re.I)
WIF = re.compile(r"\b[5KLc9][1-9A-HJ-NP-Za-km-z]{50,51}\b")
XPRV = re.compile(r"\b[xtyzuv]prv[1-9A-HJ-NP-Za-km-z]{100,108}\b")
ENV_LINE = re.compile(r"^\s*(export\s+)?([A-Za-z0-9_.\-]*(SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|API_?KEY|ACCESS_?KEY|AUTH)[A-Za-z0-9_.\-]*)\s*[:=]\s*[\"']?([^\"'\s#]{8,})",
                      re.I)
PLACEHOLDER = re.compile(r"^(x+|\*+|your|changeme|example|placeholder|<|\$\{|%|dpapi:|none|null|true|false|test|dummy)", re.I)
PASSWORD_NOTE = re.compile(r"\b(password|passcode|passwd|pwd|pin)\b\s*[:=\-]\s*\S{4,}", re.I)

ADVICE = {
    "seed": ("This is a working wallet recovery phrase. Anyone who opens this file can empty that wallet. Move the funds to a NEW "
             "wallet (new phrase, written on paper or metal, never typed), then delete this file and empty the Recycle Bin."),
    "seed?": ("This looks like a list of wallet recovery words. If it's a real phrase, anyone who opens the file can empty the wallet: "
              "move the funds to a new wallet and delete the file."),
    "key": ("This looks like a wallet or server private key. Whoever has it controls what it protects. Move funds to a new wallet "
            "(or replace the key), then delete this file and empty the Recycle Bin."),
    "keystore": ("An encrypted wallet file. It's only as safe as its password: keep it off cloud folders and shared drives, "
                 "or delete it if you no longer use that wallet."),
    "token": ("A live access key for a service. Revoke it on that service's website, make a new one, and keep it in a "
              "password manager instead of a file."),
    "passwords": "Passwords written in a file. Move them into a password manager, then delete this file and empty the Recycle Bin.",
    "wallet": "A wallet file. Make sure it's protected by a strong password and isn't in a folder that syncs to the cloud.",
}
LEVEL = {"seed": "stop", "key": "stop", "token": "high", "seed?": "high", "passwords": "caution", "keystore": "caution", "wallet": "caution"}


def _text_of(path, ext):
    if ext in ZIP_EXT:
        if os.path.getsize(path) > MAX_ZIP:
            return None
        try:
            with zipfile.ZipFile(path) as z:
                parts = [z.read(n).decode("utf-8", "replace") for n in ZIP_EXT[ext] if n in z.namelist()]
        except Exception:
            return None
        xml = "\n".join(parts)
        xml = re.sub(r"</(w:p|text:p|si|row)>", "\n", xml)
        return re.sub(r"<[^>]+>", " ", xml)
    if os.path.getsize(path) > MAX_TEXT:
        return None
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError:
        return None
    if b"\0" in raw[:4096]:                                    # binary
        return None
    for enc in ("utf-8", "utf-16", "cp1252"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def scan_text(text, ext=""):
    """[(kind, line, what)] for one file's text. 'what' never contains the secret."""
    found = []
    lines = text.splitlines()
    # seed phrases: runs of 12+ consecutive BIP-39 words (numbering and punctuation ignored)
    import bisect
    nl = [m.start() for m in re.finditer("\n", text)]
    toks = [(m.group(0).lower(), bisect.bisect_left(nl, m.start()) + 1) for m in re.finditer(r"[A-Za-z]+", text)]
    i = 0
    while i < len(toks):
        j = i
        while j < len(toks) and toks[j][0] in INDEX:
            j += 1
        run = [t[0] for t in toks[i:j]]
        if 12 <= len(run) <= 48:          # longer than two 24-word phrases: a word list, not a phrase
            valid = next((n for n in (24, 21, 18, 15, 12) for s in range(0, len(run) - n + 1) if bip39_valid(run[s:s + n])), 0)
            if valid:
                found.append(("seed", toks[i][1], f"{valid}-word recovery phrase (checksum valid)"))
            elif ext in DOC_EXT:            # in program code, a sentence of common words is just a sentence
                found.append(("seed?", toks[i][1], f"{len(run)} recovery-phrase words in a row"))
            i = j
        elif len(run) > 48:
            i = j
        else:
            i = j + 1 if j == i else j
    for n, line in enumerate(lines, 1):
        if PEM.search(line):
            enc = "ENCRYPTED" in line
            found.append(("keystore" if enc else "key", n, "password-protected private key" if enc else "private key (PEM)"))
        ctx = line + " " + (lines[n - 2] if n > 1 else "")
        if HEX64.search(line) and KEYWORD.search(ctx) and not NOT_PRIVATE.search(ctx):
            found.append(("key", n, "64-character hex private key"))
        for m in WIF.finditer(line):
            b = _b58check(m.group(0))
            if b and b[0] in (0x80, 0xEF):
                found.append(("key", n, "Bitcoin-style private key (WIF, checksum valid)"))
        for m in XPRV.finditer(line):
            if _b58check(m.group(0)):
                found.append(("key", n, "extended private key (xprv, checksum valid)"))
        for label, rx in TOKEN_RX:
            if rx.search(line):
                found.append(("token", n, label))
        if ext in CONFIG_EXT:
            m = ENV_LINE.search(line)
            if m and not PLACEHOLDER.search(m.group(4)) and not any(rx.search(line) for _, rx in TOKEN_RX):
                found.append(("token", n, f"secret setting {m.group(2)}"))
    pw = [n for n, line in enumerate(lines, 1) if PASSWORD_NOTE.search(line)]
    if pw and ext in DOC_EXT:
        found.append(("passwords", pw[0], f"{len(pw)} password line(s)"))
    stripped = text.strip()
    if stripped.startswith("{") and '"ciphertext"' in stripped and '"kdf"' in stripped:
        found.append(("keystore", 1, "encrypted wallet keystore (JSON)"))
    if re.fullmatch(r"\[\s*(\d{1,3}\s*,\s*){63}\d{1,3}\s*\]", stripped):
        found.append(("key", 1, "Solana keypair (64-number secret key)"))
    seen, out = set(), []
    for f in found:
        if (f[0], f[1], f[2]) not in seen:
            seen.add((f[0], f[1], f[2]))
            out.append(f)
    return out


def default_folders():
    home = os.path.expanduser("~")
    names = ["Desktop", "Documents", "Downloads", "OneDrive", "Dropbox", "Google Drive", "iCloudDrive", "Pictures"]
    out = []
    for n in names:
        p = os.path.join(home, n)
        if os.path.isdir(p):
            out.append(p)
    return out


def scan(folders, progress=None, stop=None, max_files=300_000):
    results, files, t0 = [], 0, time.time()
    for root in folders:
        for d, dirs, names in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP_DIRS and not x.startswith(".") or x in (".env",)]
            if stop and stop.is_set():
                return results, files, True
            for name in names:
                p = os.path.join(d, name)
                low = name.lower()
                ext = os.path.splitext(low)[1] if not low.startswith(".env") else ".env"
                hits = []
                if low in WALLET_NAMES or low.startswith("utc--"):
                    hits.append(("keystore" if low.startswith("utc--") else "wallet", 0,
                                 "Ethereum keystore file" if low.startswith("utc--") else WALLET_NAMES[low]))
                if ext in TEXT_EXT or ext in ZIP_EXT:
                    files += 1
                    try:
                        text = _text_of(p, ext)
                    except OSError:
                        text = None
                    if text:
                        hits += scan_text(text, ext)
                cloud = any(c in p.lower() for c in CLOUD)
                for kind, line, what in hits:
                    results.append({"path": p, "kind": kind, "level": LEVEL[kind], "line": line, "what": what, "cloud": cloud,
                                    "advice": ADVICE[kind] + (" This folder syncs to the cloud, so a copy is also stored online: "
                                                              "treat it as exposed." if cloud and kind in ("seed", "key", "token") else "")})
                if progress and files % 200 == 0:
                    progress(files, len(results), d)
                if files >= max_files:
                    return results, files, True
    order = {"stop": 0, "high": 1, "caution": 2}
    results.sort(key=lambda r: (order[r["level"]], r["path"], r["line"]))
    _summary(results, files, time.time() - t0)
    return results, files, False


def _summary(results, files, secs):
    s = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "files": files, "seconds": round(secs, 1),
         "counts": {k: sum(1 for r in results if r["level"] == k) for k in ("stop", "high", "caution")}}
    try:
        with open(SUMMARY + ".tmp", "w", encoding="utf-8") as f:
            json.dump(s, f)
        os.replace(SUMMARY + ".tmp", SUMMARY)
    except OSError:
        pass
    return s


# ---------------------------------------------------------------- the Desk page ----

_job = {"running": False, "results": [], "files": 0, "folders": [], "started": None, "done": None, "where": "", "stop": None, "cut": False}
_lock = threading.Lock()


def start(folders):
    folders = [f for f in folders if f and os.path.isdir(f)]
    with _lock:
        if _job["running"] or not folders:
            return False
        ev = threading.Event()
        _job.update(running=True, results=[], files=0, folders=folders, started=time.strftime("%H:%M:%S"), done=None, stop=ev, cut=False)

    def run():
        def prog(n, hits, where):
            _job.update(files=n, where=where)
        try:
            res, n, cut = scan(folders, prog, ev)
        except Exception:
            res, n, cut = [], _job["files"], True
        _job.update(running=False, results=res, files=n, done=time.strftime("%H:%M:%S"), cut=cut)
    threading.Thread(target=run, daemon=True).start()
    return True


def reveal_in_folder(i):
    """Open Explorer at a file from the current results (by number only, never an arbitrary path)."""
    try:
        p = _job["results"][int(i)]["path"]
    except (ValueError, IndexError, KeyError):
        return False
    if os.name == "nt" and os.path.exists(p):
        import subprocess
        subprocess.Popen(["explorer", "/select,", p])
        return True
    return False


def page(msg=""):
    import html
    e = lambda s: html.escape(str(s), quote=True)
    j = _job
    css = ("body{font:20px/1.5 'Segoe UI',Arial,sans-serif;max-width:980px;margin:0 auto;padding:0 16px 40px;color:#111}"
           "h1{font-size:30px}.card{border:2px solid #ddd;border-radius:12px;padding:14px 16px;margin:12px 0}"
           ".stop{background:#fdecee;border-color:#b00020}.high{background:#fff3e0;border-color:#e65100}.caution{background:#fff8e6;border-color:#f2b01e}"
           ".ok{background:#e9f7ef;border-color:#2e7d32}button{font-size:20px;padding:10px 20px;border-radius:10px;cursor:pointer}"
           ".go{background:#0b6b3a;color:#fff;border:0}code{background:#f2f2f2;padding:2px 6px;border-radius:5px;word-break:break-all}"
           ".small{font-size:16px;color:#444}label{display:block;margin:4px 0}input[type=text]{font-size:18px;padding:8px;width:100%}")
    head = (f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>Secrets left in the open</title><style>{css}</style>"
            + ("<meta http-equiv=refresh content=3>" if j["running"] else "") + "</head><body>")
    out = [head, "<h1>Secrets left in the open</h1>",
           "<p>Finds wallet recovery phrases, private keys, wallet files, API keys and password notes saved in ordinary files on this "
           "computer: the things key-stealing malware and automated attack tools search for first. <b>Everything stays on this "
           "computer.</b> The secrets themselves are never shown or saved; you'll see which file, which line, and what to do.</p>"]
    if msg:
        out.append(f"<div class='card caution'>{e(msg)}</div>")
    if j["running"]:
        out.append(f"<div class=card><b>Scanning...</b> {j['files']:,} files checked so far.<div class=small>Now in: <code>{e(j['where'])}</code></div>"
                   "<form method=post><input type=hidden name=do value=stop><button>Stop</button></form></div>")
    elif j["done"]:
        res = j["results"]
        n = {k: sum(1 for r in res if r["level"] == k) for k in ("stop", "high", "caution")}
        if not res:
            out.append(f"<div class='card ok'><b>Nothing found</b> in {j['files']:,} files" + (" (scan stopped early)" if j["cut"] else "") +
                       ". Pictures aren't checked: if you ever photographed or screenshotted a recovery phrase, delete that picture too.</div>")
        else:
            out.append(f"<div class='card {'stop' if n['stop'] else 'high' if n['high'] else 'caution'}'><b>{len(res)} thing(s) found</b> in "
                       f"{j['files']:,} files: {n['stop']} urgent, {n['high']} important, {n['caution']} to tidy up."
                       + (" (scan stopped early)" if j["cut"] else "") + "</div>")
            labels = {"stop": "URGENT", "high": "IMPORTANT", "caution": "TIDY UP"}
            for i, r in enumerate(res):
                where = f"line {r['line']}" if r["line"] else "the file itself"
                out.append(f"<div class='card {r['level']}'><b>{labels[r['level']]}: {e(r['what'])}</b> ({where})"
                           f"<div><code>{e(r['path'])}</code></div><p>{e(r['advice'])}</p>"
                           + ("<form method=post style='margin:0'><input type=hidden name=do value=reveal>"
                              f"<input type=hidden name=i value={i}><button>Show in folder</button></form>" if os.name == "nt" else "")
                           + "</div>")
            out.append("<p class=small>After deleting a file, empty the Recycle Bin. If a recovery phrase or key was ever in a folder "
                       "that syncs to the cloud, or on a computer that had malware, assume it's been seen: move the funds to a new wallet.</p>")
    if not j["running"]:
        boxes = "".join(f"<label><input type=checkbox name=folder value='{e(p)}' checked> {e(p)}</label>" for p in default_folders())
        out.append("<form method=post class=card><input type=hidden name=do value=scan><b>Folders to check</b>"
                   f"{boxes or '<p>No standard folders found.</p>'}<label>Another folder (optional):<input type=text name=extra placeholder='C:\\Users\\you\\Notes'></label>"
                   "<button class=go>Scan now</button><div class=small>Usually takes a minute or two. Not checked: pictures, and "
                   "program or system folders.</div></form>")
    out.append("</body></html>")
    return "".join(out)


def post(form, folders=None):
    do = form.get("do")
    if do == "scan":
        chosen = [f for f in (folders or []) if f in default_folders()]
        extra = (form.get("extra") or "").strip().strip('"')
        if extra:
            chosen.append(os.path.expanduser(extra))
        if not start(chosen):
            return page("Choose at least one folder that exists (or wait for the current scan to finish).")
        return page()
    if do == "stop" and _job.get("stop"):
        _job["stop"].set()
        return page("Stopping...")
    if do == "reveal":
        return page("" if reveal_in_folder(form.get("i")) else "That file couldn't be shown (it may have been moved or deleted).")
    return page()


if __name__ == "__main__":
    import sys
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    res, n, cut = scan(sys.argv[1:] or default_folders())
    print(f"{n} files checked{' (stopped early)' if cut else ''}; {len(res)} found")
    for r in res:
        print(f"  [{r['level'].upper():7}] {r['what']} - {r['path']}" + (f" line {r['line']}" if r["line"] else ""))
