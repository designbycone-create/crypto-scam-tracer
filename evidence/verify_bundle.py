#!/usr/bin/env python3
"""Independent verifier for a ScamHunter case bundle.

Uses only the Python standard library, so a police examiner, prosecutor's
expert or the defence's expert can run it without installing or trusting
ScamHunter. It does NOT import any ScamHunter code.

    python verify.py                 offline checks
    python verify.py --online        also re-read every FACT from public XRPL servers

Checks:
  1. Every file listed in manifest.json has the SHA-256 recorded there.
  2. No files were added to the bundle after it was sealed.
  3. The capture log's hash chain is intact (no entry altered, removed or reordered).
  4. Every raw evidence blob's file name equals its SHA-256 (content-addressed).
  5. Every FACT's asserted ledger values are actually present in the saved raw
     server response it cites, and every source blob is in the capture log.
  6. (--online) The public ledger, read now from independent servers, still
     returns the same values for every FACT.
Exit code 0 = all checks passed.
"""
import hashlib
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SERVERS = ["https://s2.ripple.com:51234/", "https://xrplcluster.com/"]
FIELDS = ("TransactionType", "Account", "Destination", "DestinationTag", "SourceTag", "Amount",
          "Fee", "Sequence", "ledger_index", "date")


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def canonical(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def tx_fields(resp):
    r = resp.get("result", resp) if isinstance(resp, dict) else {}
    tx = r.get("tx_json") or r.get("tx") or r
    out = {k: (tx.get(k) if k in tx else r.get(k)) for k in FIELDS}
    meta = r.get("meta") or {}
    out["delivered_amount"] = meta.get("delivered_amount")
    out["result"] = meta.get("TransactionResult")
    out["validated"] = r.get("validated")
    return {k: v for k, v in out.items() if v is not None}


def main(root=HERE, online=False, out=print):
    ok = True

    def check(cond, msg):
        nonlocal ok
        out(("  PASS  " if cond else "  FAIL  ") + msg)
        ok = ok and bool(cond)

    man = json.load(open(os.path.join(root, "manifest.json"), encoding="utf-8"))
    out(f"Case {man.get('case_id')}  sealed {man.get('sealed_utc')}  tool {man.get('tool', {}).get('git_commit')}")
    out(f"Manifest SHA-256: {sha(os.path.join(root, 'manifest.json'))}")

    out("\n1. File integrity")
    bad = [p for p, h in man["files"].items() if not os.path.exists(os.path.join(root, p)) or sha(os.path.join(root, p)) != h]
    check(not bad, f"{len(man['files'])} files match their recorded SHA-256" + (f" -- MISMATCH: {bad[:5]}" if bad else ""))

    out("\n2. Nothing added after sealing")
    present = set()
    for d, _, fs in os.walk(root):
        for f in fs:
            rel = os.path.relpath(os.path.join(d, f), root).replace(os.sep, "/")
            if rel not in ("manifest.json", "certification_template.md") and "__pycache__" not in rel:
                present.add(rel)
    extra = sorted(present - set(man["files"]))
    out("        (certification_template.md is the unsigned form written after sealing; it quotes the manifest hash)")
    check(not extra, "no unlisted files" + (f" -- EXTRA: {extra[:5]}" if extra else ""))

    out("\n3. Capture log chain")
    prev, n, logged = "0" * 64, 0, set()
    chain_ok, why = True, "intact"
    with open(os.path.join(root, "capture_log.jsonl"), encoding="utf-8") as f:
        for line in f:
            e = json.loads(line)
            h = e.pop("entry_hash")
            if e["prev_entry_hash"] != prev:
                chain_ok, why = False, f"chain broken at entry {e['seq']}"
                break
            if hashlib.sha256(canonical(e).encode()).hexdigest() != h:
                chain_ok, why = False, f"entry {e['seq']} altered"
                break
            logged.add(e["response_sha256"])
            prev, n = h, n + 1
    check(chain_ok, f"{n} read(s) logged, chain {why}")
    check(prev == man.get("capture_log_head"), "log ends at the head hash recorded when sealed")

    if man.get("seal_id"):
        fb = open(os.path.join(root, "findings.json"), "rb").read()
        sid = hashlib.sha256(fb + man["capture_log_head"].encode()).hexdigest()[:16].upper()
        check(sid == man["seal_id"], f"Seal ID {man['seal_id']} matches the findings and evidence log (the ID printed on every PDF page)")

    out("\n4. Raw evidence blobs")
    blobdir = os.path.join(root, "blobs")
    names = os.listdir(blobdir) if os.path.isdir(blobdir) else []
    wrong = [b for b in names if sha(os.path.join(blobdir, b)) != b]
    check(not wrong, f"{len(names)} blob(s) are content-addressed")

    out("\n5. Facts against raw data")
    findings = json.load(open(os.path.join(root, "findings.json"), encoding="utf-8"))
    facts = [x for x in findings if x["kind"] == "FACT"]
    for fct in facts:
        src = fct["sources"][0]["sha256"]
        p = os.path.join(blobdir, src)
        if not os.path.exists(p):
            check(False, f"{fct['id']}: source blob missing")
            continue
        got = tx_fields(json.load(open(p, encoding="utf-8")))
        mism = {k: (v, got.get(k)) for k, v in fct["fields"].items() if got.get(k) != v}
        check(not mism and src in logged, f"{fct['id']} tx {fct['tx_hash'][:12]}... fields match saved response"
              + ("" if src in logged else " (blob not in capture log!)") + (f" -- DIFF {mism}" if mism else ""))
        corr = [s for s in fct["sources"][1:] if s.get("agrees")]
        out(f"        corroborated by {len(corr)} independent server(s)" if corr else "        NOTE: not corroborated")
    ids = {x["id"] for x in findings}
    dangling = [x["id"] for x in findings if any(i not in ids for i in x.get("from", []))]
    check(not dangling, "every derived/inferred finding cites findings that exist in the bundle")

    if online:
        out("\n6. Live re-check against the public ledger")
        for fct in facts:
            if fct.get("chain") != "xrpl":
                out(f"  SKIP  {fct['id']} ({fct.get('chain')}: re-check with that chain's explorer)")
                continue
            for s in SERVERS:
                try:
                    body = json.dumps({"method": "tx", "params": [{"transaction": fct["tx_hash"], "api_version": 2}]}).encode()
                    req = urllib.request.Request(s, data=body, headers={"Content-Type": "application/json"})
                    got = tx_fields(json.loads(urllib.request.urlopen(req, timeout=30).read()))
                    mism = {k: (v, got.get(k)) for k, v in fct["fields"].items() if got.get(k) != v}
                    check(not mism, f"{fct['id']} via {s}" + (f" -- DIFF {mism}" if mism else ""))
                except Exception as e:
                    out(f"  WARN  {fct['id']} via {s}: could not reach ({e!r})")

    out("\nRESULT: " + ("ALL CHECKS PASSED" if ok else "ONE OR MORE CHECKS FAILED"))
    return ok


if __name__ == "__main__":
    sys.exit(0 if main(online="--online" in sys.argv) else 1)
