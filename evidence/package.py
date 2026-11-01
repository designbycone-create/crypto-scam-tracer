"""Seal a case bundle a qualified person can stand behind.

    from evidence.package import build
    path = build(findings, case_id="SH-2026-0001", scope={...}, examiner={...})

Produces case_<id>/ and case_<id>.zip containing:
  README.txt                 what's in the bundle and how to check it
  report.md                  scope, facts, derived results, inferences, limitations
  findings.json              machine-readable findings (FACT / DERIVED / INFERENCE)
  methodology.md             every heuristic used: what it does, assumptions, failure modes, testing
  certification_template.md  for the person who ran the tool (FRE 902(13)/(14)-style)
  capture_log.jsonl          hash-chained log of every external read
  blobs/<sha256>             raw server responses cited by the findings
  actions_log.jsonl          examiner's custody/actions log (if freezekit has one)
  tool.json                  tool version (git commit), Python, platform
  verify.py                  stand-alone verifier (standard library only)
  manifest.json              SHA-256 of every file above + capture-log head + seal time
"""
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone

from . import VERSION, capture
from .facts import HEURISTICS, Findings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

STANDARD_LIMITS = [
    "Blockchain records show which ADDRESSES moved value. They do not by themselves show which PERSON controls an "
    "address. Identification of a person requires records from the exchange or service that holds the account "
    "(obtained by subpoena or other legal process).",
    "Attribution of addresses to exchanges or operators is an INFERENCE from published labels and behaviour, not a "
    "fact recorded on the ledger. Each inference names its method and known failure modes in methodology.md.",
    "Following funds through a wallet that also holds other people's money is a tracing convention (stated per "
    "path); value on a ledger is fungible.",
    "Times in the capture log come from the examiner's computer clock. Authoritative times are the ledger close "
    "times recorded in each FACT.",
    "Coverage is limited to the public data sources named in the capture log; where a source limited history, "
    "the report says so.",
    "This report was produced with software. It is offered to support, not replace, the testimony of the person "
    "who ran it and any expert who reviews it.",
]


def _git():
    try:
        c = subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        d = subprocess.run(["git", "-C", ROOT, "status", "--porcelain"], capture_output=True, text=True, timeout=10)
        return c.stdout.strip() or "unknown", bool(d.stdout.strip())
    except Exception:
        return "unknown", None


def _sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _fmt_fact(f):
    corr = [s["server"] for s in f["sources"][1:] if s.get("agrees")]
    flag = f"corroborated ({', '.join(corr)})" if f.get("corroborated") else "NOT corroborated"
    return f"| {f['id']} | {f['chain']} | `{f['tx_hash']}` | {f['statement']} | {flag} |"


def methodology_md(used):
    out = ["# Methodology", "",
           "ScamHunter reads public ledger data, records every response it relied on, and separates its output into:",
           "", "* **FACT**: a value recorded on the public ledger, cited by transaction hash and re-checkable by anyone.",
           "* **DERIVED**: a deterministic computation over facts (the same input always gives the same output).",
           "* **INFERENCE**: an opinion produced by one of the documented heuristics below, with a confidence band.",
           "", "Facts are read from two independently operated ledger servers and recorded as agreeing or not.",
           "Every external read, including any served from cache, is written to a hash-chained log with the raw "
           "response saved under its SHA-256.", "", "## Heuristics used in this case", ""]
    for key in sorted(used) or ["(none)"]:
        h = HEURISTICS.get(key)
        if not h:
            out.append(f"* {key}")
            continue
        out += [f"### {h['name']}  (`{key}`)", "", f"**What it does.** {h['does']}", "",
                f"**Assumes.** {h['assumes']}", "", "**Known ways it can be wrong:**", ""]
        out += [f"* {x}" for x in h["fails_when"]]
        out += ["", f"**Safeguards.** {h['safeguards']}", "", f"**Testing.** {h['testing']}", ""]
    out += ["## Error rates", "",
            "No validated, published error rate exists for these heuristics (the same is true of commercial "
            "blockchain-analytics tools, a point raised in litigation). For that reason every inference is labelled "
            "as such, rests on cited facts, and should be corroborated by independent evidence, such as exchange "
            "account records obtained by legal process, before it is relied on.", ""]
    return "\n".join(out)


def certification_md(case_id, manifest_sha, examiner):
    name = examiner.get("name") or "____________________"
    return f"""# Certification of the person who produced this record (TEMPLATE)

**Not legal advice. Have an attorney review this before it is signed or filed.** It follows the pattern of
Federal Rules of Evidence 902(13) and 902(14), which let electronic records and copied data be authenticated by
the certification of a qualified person instead of live testimony, provided the opposing party gets reasonable
written notice and a chance to inspect (FRE 902(11)). State rules differ; where no equivalent rule exists,
authentication is by testimony under Rule 901(b)(1) and 901(b)(9). Certification goes to **authenticity
only**. Whether the contents are admissible (hearsay, relevance, expert-opinion rules) is a separate question.

---

I, {name}, declare:

1. I am over 18 and competent to make this declaration. My qualifications to operate the software described
   below are: ________________________________________________.

2. On ____________ (date) I used ScamHunter (open-source software; version and source-code commit recorded in
   `tool.json` of case bundle **{case_id}**) to retrieve records from the public XRP Ledger (and other
   public blockchains named in `capture_log.jsonl`) through the public servers listed in that log.

3. The software saved each server response as received and recorded its SHA-256 hash in a sequential,
   hash-chained log at the time of retrieval. The process produces an accurate result: each FACT in
   `findings.json` can be compared with the saved response and with the public ledger itself, and
   `verify.py` in the bundle performs that comparison.

4. On ____________ (date) I sealed the bundle. The SHA-256 hash of its `manifest.json` is:

   `{manifest_sha}`

   I ran `verify.py` and it reported ALL CHECKS PASSED. A copy of that output is attached as Exhibit __.

5. I did not alter any saved response. Statements labelled INFERENCE are opinions produced by the documented
   methods in `methodology.md`. They are not facts recorded on the ledger.

I declare under penalty of perjury under the laws of ______________ that the foregoing is true and correct.

Executed on ____________ at ______________.

______________________________
{name}
"""


def report_md(findings: Findings, case_id, scope, examiner, sealed, tool):
    facts, der, inf = findings.by_kind("FACT"), findings.by_kind("DERIVED"), findings.by_kind("INFERENCE")
    out = [f"# Blockchain tracing report: case {case_id}", "",
           f"Prepared with ScamHunter (commit `{tool['git_commit']}`, {VERSION}). Sealed {sealed}.",
           f"Examiner: {examiner.get('name') or '(name)'}. {examiner.get('role') or ''}", "",
           "## Scope", ""]
    for k, v in (scope or {}).items():
        out.append(f"* **{k}:** {v}")
    out += ["", f"## Facts recorded on the public ledger ({len(facts)})", "",
            "Each value below was read from a public server, saved byte-for-byte, and (where marked) confirmed by "
            "a second, independently operated server. Anyone can check a fact by looking up its transaction hash.",
            "", "| ID | Chain | Transaction | What the ledger records | Corroboration |", "|---|---|---|---|---|"]
    out += [_fmt_fact(f) for f in facts]
    out += ["", f"## Derived results ({len(der)})", ""]
    for d in der:
        out.append(f"* **{d['id']}** {d['statement']}  _(algorithm `{d['algorithm']}`; from {', '.join(d['from'])})_")
    out += ["", f"## Inferences: opinions, not facts ({len(inf)})", ""]
    for i in inf:
        out += [f"* **{i['id']}** {i['statement']}",
                f"  * Method `{i['heuristic']}` (see methodology.md). Confidence: **{i['confidence']}**. Based on {', '.join(i['from'])}.",
                f"  * Could be wrong if: {'; '.join(i['known_failure_modes'])}."]
        if i.get("basis"):
            out.append(f"  * Basis: {i['basis']}")
    out += ["", "## Limitations", ""] + [f"* {x}" for x in STANDARD_LIMITS]
    out += ["", "## How to check this report", "",
            "Run `python verify.py` in this folder (Python 3, no other software needed). Add `--online` to re-read "
            "every fact from the public ledger. See README.txt.", ""]
    return "\n".join(out)


def build(findings: Findings, case_id, scope=None, examiner=None, out_dir="evidence_bundles", actions_log=None,
          large_print=False):
    examiner = examiner or {}
    sealed = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    commit, dirty = _git()
    tool = {"name": "ScamHunter", "evidence_module": VERSION, "git_commit": commit, "uncommitted_changes": dirty,
            "source": "https://github.com/designbycone-create/crypto-scam-tracer",
            "python": sys.version.split()[0], "platform": platform.platform()}
    d = os.path.join(out_dir, f"case_{case_id}")
    if os.path.exists(d):
        raise FileExistsError(f"{d} exists: a sealed bundle is never overwritten; use a new case id or revision")
    os.makedirs(os.path.join(d, "blobs"))

    ok, n, bad, why = capture.verify_log()
    if not ok:
        raise RuntimeError(f"capture log failed its own integrity check at entry {bad}: {why}. Not sealing.")
    logsrc = os.path.join(capture.STORE, capture.LOG)
    shutil.copyfile(logsrc, os.path.join(d, "capture_log.jsonl"))
    head = "0" * 64
    with open(logsrc, encoding="utf-8") as f:
        for line in f:
            head = json.loads(line)["entry_hash"]

    cited = {s["sha256"] for x in findings.by_kind("FACT") for s in x["sources"] if s.get("sha256")}
    for h in cited:
        shutil.copyfile(os.path.join(capture.STORE, "blobs", h), os.path.join(d, "blobs", h))

    used = {i["heuristic"] for i in findings.by_kind("INFERENCE")}
    files = {
        "findings.json": findings.to_json(),
        "methodology.md": methodology_md(used),
        "report.md": report_md(findings, case_id, scope, examiner, sealed, tool),
        "tool.json": json.dumps(tool, indent=2),
        "README.txt": README.format(case_id=case_id),
    }
    for name, text in files.items():
        with open(os.path.join(d, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    shutil.copyfile(os.path.join(os.path.dirname(__file__), "verify_bundle.py"), os.path.join(d, "verify.py"))
    if actions_log and os.path.exists(actions_log):
        shutil.copyfile(actions_log, os.path.join(d, "actions_log.jsonl"))

    sid, pdf_note = None, None
    try:   # sealed PDF: written before the manifest so its hash is sealed with everything else
        from . import pdf as _pdf
        _, sid = _pdf.build(d, case_id, json.loads(files["findings.json"]), scope, examiner, tool, sealed, head,
                            STANDARD_LIMITS, large=large_print)
    except ImportError:
        pdf_note = "PDF not produced: the reportlab library is not installed (pip install reportlab)"

    def manifest_files():
        res = {}
        for root, _, fs in os.walk(d):
            for fn in fs:
                rel = os.path.relpath(os.path.join(root, fn), d).replace(os.sep, "/")
                if rel not in ("manifest.json", "certification_template.md"):
                    res[rel] = _sha(os.path.join(root, fn))
        return res

    # certification text quotes the manifest hash, so the manifest is sealed first and the
    # certification template is written after it; it is a form to be signed, not evidence.
    if sid is None:
        sid = hashlib.sha256(files["findings.json"].encode("utf-8") + head.encode()).hexdigest()[:16].upper()
    manifest = {"case_id": case_id, "sealed_utc": sealed, "tool": tool, "capture_log_head": head, "seal_id": sid,
                "capture_log_entries": n, "files": dict(sorted(manifest_files().items()))}
    with open(os.path.join(d, "manifest.json"), "w", encoding="utf-8", newline="\n") as f:
        json.dump(manifest, f, indent=2)
    msha = _sha(os.path.join(d, "manifest.json"))
    with open(os.path.join(d, "certification_template.md"), "w", encoding="utf-8", newline="\n") as f:
        f.write(certification_md(case_id, msha, examiner))

    zpath = d + ".zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, fs in os.walk(d):
            for fn in fs:
                p = os.path.join(root, fn)
                z.write(p, os.path.relpath(p, os.path.dirname(d)))
    return {"dir": d, "zip": zpath, "manifest_sha256": msha, "zip_sha256": _sha(zpath), "seal_id": sid,
            "pdf": None if pdf_note else os.path.join(d, "report.pdf"), "pdf_note": pdf_note}


README = """ScamHunter case bundle {case_id}
=================================

To check this bundle (needs Python 3 only, no ScamHunter install):

    python verify.py            offline: hashes, log chain, facts vs saved raw data
    python verify.py --online   also re-reads every fact from public XRP Ledger servers

What the files are:
  report.pdf                 the sealed court report (every page stamped with case ID, Seal ID, page number)
  report.md                  the same report as plain text
  findings.json              every finding, labelled FACT / DERIVED / INFERENCE
  methodology.md             how each inference was made and how it can be wrong
  capture_log.jsonl          every server response the tool read, in order, hash-chained
  blobs/                     the raw responses cited by the facts, named by their SHA-256
  tool.json                  exact software version (source code commit)
  manifest.json              SHA-256 of every file (record the manifest's own hash)
  certification_template.md  declaration for the person who produced this (attorney review required)
  verify.py                  the verifier

Every FACT can also be checked without any of this: look up its transaction hash on any public
XRP Ledger explorer (e.g. xrpscan.com, livenet.xrpl.org).
"""
