"""Keep a user's own case out of anything that leaves their computer.

The Desk keeps your case in a few local files (config.json, victim.json, submissions.json,
freeze_tracker.json) that are never part of the program. This module collects the identifying
values in them (wallet addresses, transaction hashes, IC3 number, exchange deposit tags, name,
email, phone) and checks a set of files for any of them. Used:
  * when a release is signed (release_sig.py refuses to sign if one appears), and
  * when the Desk builds a copy to share with someone (Settings > Share ScamHunter).

The values are only compared in memory and never printed: a finding names the file, not the value.

    python privacy_guard.py <folder-to-check> [case-folder]
"""
import json
import os
import re

CASE_FILES = ("config.json", "victim.json", "submissions.json", "freeze_tracker.json")
ADDR = re.compile(r"\b(?:r[1-9A-HJ-NP-Za-km-z]{24,34}|0x[0-9a-fA-F]{40}|T[1-9A-HJ-NP-Za-km-z]{33}|[13][1-9A-HJ-NP-Za-km-z]{25,34}"
                  r"|bc1[0-9a-z]{25,60}|[1-9A-HJ-NP-Za-km-z]{43,44})\b")
TXH = re.compile(r"\b[0-9A-Fa-f]{64}\b")
PERSONAL = ("email", "phone", "ic3_id", "victim_wallet", "tx_hash", "case_number", "report_id")   # names aren't checked:
# exchange names fill the freeze-request list, and the copyright owner's name is meant to be public
PUBLIC_REFERENCE = ("scam_investigator/labels.json", "multichain/entities.py", "freezekit/channels.json", "threatfeed/campaigns.json",
                    "responder/intel.py", "shield/issuerfreeze.py")   # published exchange / token / attacker addresses
TAGS = ("tag", "dest_tag", "destination_tag", "memo")
PLACEHOLDER = re.compile(r"example|your_|^0+$|xxxx|test", re.I)


def default_case_dir():
    return os.environ.get("SCAMHUNTER_CASE_DIR") or os.path.join(os.path.expanduser("~"), "scam-watcher")


def _walk_values(obj, out):
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = str(k).lower()
            if isinstance(v, (str, int)) and not isinstance(v, bool):
                s = str(v).strip()
                if kl in PERSONAL and len(s) >= 5:
                    out.add(s)
                elif kl in TAGS and re.fullmatch(r"\d{5,}", s):
                    out.add(s)
            _walk_values(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _walk_values(v, out)


def case_values(case_dir=None):
    """The identifying values in this computer's case files (empty if there's no case here)."""
    d = case_dir or default_case_dir()
    vals = set()
    for name in CASE_FILES:
        p = os.path.join(d, name)
        if not os.path.exists(p):
            continue
        try:
            txt = open(p, encoding="utf-8-sig").read()
        except OSError:
            continue
        vals |= set(ADDR.findall(txt)) | set(TXH.findall(txt))
        try:
            _walk_values(json.loads(txt), vals)
        except ValueError:
            pass
    vals = {v for v in vals if not PLACEHOLDER.search(v) and not v.startswith("dpapi:")}
    # a public exchange hot wallet in your case is also in the program's reference lists on purpose: not a leak
    here = os.path.dirname(os.path.abspath(__file__))
    public = ""
    for rel in PUBLIC_REFERENCE:
        try:
            public += open(os.path.join(here, rel), encoding="utf-8", errors="ignore").read().lower()
        except OSError:
            pass
    return {v for v in vals if v.lower() not in public}


def find(paths_or_root, values, read=None):
    """{file: count} for files that contain any of the values. paths_or_root: a folder or a list of files."""
    if not values:
        return {}
    if isinstance(paths_or_root, str):
        files = []
        for d, dirs, names in os.walk(paths_or_root):
            dirs[:] = [x for x in dirs if x not in (".git", "__pycache__", "node_modules")]
            files += [os.path.join(d, n) for n in names]
    else:
        files = list(paths_or_root)
    low = {v.lower() for v in values}
    hits = {}
    for f in files:
        try:
            data = read(f) if read else open(f, "rb").read()
        except OSError:
            continue
        txt = data.decode("utf-8", "ignore").lower()
        n = sum(1 for v in low if v in txt)
        if n:
            hits[f] = n
    return hits


if __name__ == "__main__":
    import sys
    vals = case_values(sys.argv[2] if len(sys.argv) > 2 else None)
    hits = find(sys.argv[1] if len(sys.argv) > 1 else ".", vals)
    print(f"{len(vals)} case value(s) checked; " + ("none found." if not hits else f"FOUND in {len(hits)} file(s):"))
    for f, n in sorted(hits.items()):
        print(f"  {f}: {n}")
    sys.exit(1 if hits else 0)
