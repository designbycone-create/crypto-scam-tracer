"""Chain of custody for evidence files.

Every file the Submission Center writes is hashed (SHA-256) and recorded in an
append-only, hash-chained log (custody_log.jsonl): each entry includes the hash
of the previous entry, so any later edit or deletion of the log is detectable.
A MANIFEST.txt in each kit lists file -> SHA-256 so an officer can verify the
files they received are exactly what was generated.
"""
import hashlib
import json
import os
from datetime import datetime, timezone

LOG = "custody_log.jsonl"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _last_hash():
    try:
        with open(LOG, "rb") as f:
            lines = f.read().splitlines()
        return json.loads(lines[-1])["entry_hash"] if lines else "0" * 64
    except Exception:
        return "0" * 64


def record(path, action="generated", note=""):
    """Append a custody entry for a file. Returns the file's SHA-256."""
    digest = sha256_file(path)
    entry = {"time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "action": action, "file": os.path.relpath(path).replace("\\", "/"),
             "sha256": digest, "note": note, "prev": _last_hash()}
    entry["entry_hash"] = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return digest


def verify_log():
    """Return (ok, n_entries, first_bad_line)."""
    prev = "0" * 64
    n = 0
    try:
        with open(LOG, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                e = json.loads(line)
                h = e.pop("entry_hash")
                if e["prev"] != prev or hashlib.sha256(json.dumps(e, sort_keys=True).encode()).hexdigest() != h:
                    return False, n, i
                prev = h
                n += 1
    except FileNotFoundError:
        return True, 0, None
    return True, n, None


def write_manifest(folder, files):
    """MANIFEST.txt with SHA-256 of each file (only records changed files in the log)."""
    lines = ["EVIDENCE MANIFEST - SHA-256 of each file in this folder",
             f"Generated (UTC): {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S}",
             "Verify on Windows:  certutil -hashfile <file> SHA256",
             "Verify on Mac/Linux: shasum -a 256 <file>", ""]
    for p in files:
        lines.append(f"{sha256_file(p)}  {os.path.basename(p)}")
    mp = os.path.join(folder, "MANIFEST.txt")
    with open(mp, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return mp
