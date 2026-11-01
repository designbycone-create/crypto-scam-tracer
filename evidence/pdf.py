"""Sealed court PDF for a case bundle.

The PDF is written INSIDE the bundle before the manifest is sealed, so its SHA-256 is in manifest.json
and `verify.py` catches any edit to it. Every page carries the case ID, the Seal ID and a sequential
page stamp (e.g. SH-2026-0001-0007), so pages can't be swapped or dropped unnoticed.

Seal ID = first 16 hex of SHA-256(findings.json bytes + capture-log head hash). It ties the PDF to the
exact findings and evidence log; verify.py recomputes it.
"""
import hashlib
import json
import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

from .facts import HEURISTICS


def seal_id(findings_bytes, log_head):
    return hashlib.sha256(findings_bytes + log_head.encode()).hexdigest()[:16].upper()


def _esc(s):
    return (str(s if s is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _styles(large=False):
    ss = getSampleStyleSheet()
    base = 13 if large else 10
    st = {
        "title": ParagraphStyle("t", parent=ss["Title"], fontSize=base + 10, leading=base + 14, alignment=TA_LEFT),
        "h1": ParagraphStyle("h1", parent=ss["Heading1"], fontSize=base + 5, leading=base + 8, spaceBefore=10),
        "h2": ParagraphStyle("h2", parent=ss["Heading2"], fontSize=base + 2, leading=base + 5, spaceBefore=8),
        "body": ParagraphStyle("b", parent=ss["BodyText"], fontSize=base, leading=base + 4),
        "small": ParagraphStyle("s", parent=ss["BodyText"], fontSize=base - 1.5, leading=base + 2),
        "mono": ParagraphStyle("m", parent=ss["Code"], fontSize=base - 2, leading=base + 1, wordWrap="CJK"),
        "cell": ParagraphStyle("c", parent=ss["BodyText"], fontSize=base - 1.5, leading=base + 1.5, wordWrap="CJK"),
    }
    return st


def _table(rows, widths, st, header=True):
    data = [[c if isinstance(c, Paragraph) else Paragraph(_esc(c).replace("\n", "<br/>"), st["cell"]) for c in r]
            for r in rows]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8ecf3"))]
    t.setStyle(TableStyle(style))
    return t


def build(bundle_dir, case_id, findings, scope, examiner, tool, sealed, log_head, limits, large=False,
          filename="report.pdf"):
    st = _styles(large)
    with open(os.path.join(bundle_dir, "findings.json"), "rb") as f:
        sid = seal_id(f.read(), log_head)
    facts = sorted([x for x in findings if x["kind"] == "FACT"],
                   key=lambda x: (x.get("fields") or {}).get("ledger_index") or 0)     # ledger order
    der = [x for x in findings if x["kind"] == "DERIVED"]
    inf = [x for x in findings if x["kind"] == "INFERENCE"]
    exhibit = {}
    for i, x in enumerate(facts, 1):
        exhibit[x["id"]] = f"F-{i}"
    for i, x in enumerate(der, 1):
        exhibit[x["id"]] = f"D-{i}"
    for i, x in enumerate(inf, 1):
        exhibit[x["id"]] = f"I-{i}"
    ref = lambda ids: ", ".join(exhibit.get(i, i) for i in ids)

    E = []
    E.append(Paragraph("Blockchain Tracing Report", st["title"]))
    E.append(Paragraph(f"Case <b>{_esc(case_id)}</b> &nbsp;&middot;&nbsp; Seal ID <b>{sid}</b>", st["body"]))
    E.append(Spacer(1, 8))
    cover = [["Sealed (UTC)", sealed], ["Prepared by", f"{examiner.get('name') or '(name)'} {examiner.get('role') or ''}"],
             ["Software", f"ScamHunter, source commit {tool.get('git_commit')}"],
             ["Source code", tool.get("source", "")],
             ["Contents", f"{len(facts)} facts recorded on the public ledger, {len(der)} derived results, "
                          f"{len(inf)} inferences (opinions)"]]
    cover += [[k, v] for k, v in (scope or {}).items()]
    E.append(_table(cover, [1.6 * inch, 5.0 * inch], st, header=False))
    E.append(Spacer(1, 10))
    E.append(Paragraph(
        "<b>How to read this report.</b> A <b>FACT</b> is a value recorded on a public blockchain; anyone can check it "
        "by its transaction hash on any public explorer, and each was confirmed by a second, independently operated "
        "server where marked. A <b>DERIVED</b> result is a calculation over facts. An <b>INFERENCE</b> is an opinion "
        "produced by a named method with known failure modes; it is not a fact. Every page carries the case ID, the "
        "Seal ID and a page stamp. The accompanying bundle's <i>verify.py</i> checks this PDF, the raw data and the "
        "evidence log have not been altered.", st["body"]))
    E.append(Spacer(1, 6))
    E.append(Paragraph("<b>No software can make evidence admissible.</b> A court decides that, on the testimony of a "
                       "qualified person who sponsors this record. This report is offered to support that testimony.",
                       st["small"]))

    E.append(PageBreak())
    E.append(Paragraph("Facts recorded on the public ledger", st["h1"]))
    rows = [["Exhibit", "Chain / transaction", "What the ledger records", "Corroboration"]]
    for x in facts:
        corr = [s["server"] for s in x["sources"][1:] if s.get("agrees")]
        rows.append([exhibit[x["id"]], f"{x['chain']}\n{x['tx_hash']}", x["statement"],
                     ("Confirmed by " + ", ".join(corr)) if x.get("corroborated") else "NOT corroborated"])
    E.append(_table(rows, [0.6 * inch, 1.9 * inch, 2.6 * inch, 1.5 * inch], st))
    E.append(Paragraph("Raw server responses for each fact are saved in the bundle under blobs/, named by SHA-256: "
                       + "; ".join(f"{exhibit[x['id']]} = {x['sources'][0]['sha256'][:16]}..." for x in facts), st["small"]))

    if der:
        E.append(Paragraph("Derived results", st["h1"]))
        for x in der:
            E.append(Paragraph(f"<b>{exhibit[x['id']]}</b> {_esc(x['statement'])} <i>(method {_esc(x['algorithm'])}; "
                               f"from {ref(x['from'])})</i>", st["body"]))
    if inf:
        E.append(Paragraph("Inferences: opinions, not facts", st["h1"]))
        for x in inf:
            E.append(KeepTogether([
                Paragraph(f"<b>{exhibit[x['id']]}</b> {_esc(x['statement'])}", st["body"]),
                Paragraph(f"Method <b>{_esc(x['heuristic'])}</b> &middot; confidence <b>{_esc(x['confidence'])}</b> "
                          f"&middot; based on {ref(x['from'])}", st["small"]),
                Paragraph("Could be wrong if: " + _esc("; ".join(x["known_failure_modes"])), st["small"]),
                Spacer(1, 4)]))

    E.append(Paragraph("Limitations", st["h1"]))
    for l in limits:
        E.append(Paragraph("&bull; " + _esc(l), st["body"]))

    E.append(PageBreak())
    E.append(Paragraph("Methodology", st["h1"]))
    used = sorted({x["heuristic"] for x in inf})
    E.append(Paragraph("Facts are read from public ledger servers; each response is saved byte-for-byte and logged in a "
                       "hash-chained evidence log, including any served from cache. Each fact is re-read from a second, "
                       "independently operated server and the two are compared field by field.", st["body"]))
    for key in used:
        h = HEURISTICS.get(key, {})
        E.append(Paragraph(f"{_esc(h.get('name', key))} ({_esc(key)})", st["h2"]))
        E.append(Paragraph("<b>What it does.</b> " + _esc(h.get("does")), st["body"]))
        E.append(Paragraph("<b>Assumes.</b> " + _esc(h.get("assumes")), st["body"]))
        E.append(Paragraph("<b>Known ways it can be wrong.</b> " + _esc("; ".join(h.get("fails_when", []))), st["body"]))
        E.append(Paragraph("<b>Safeguards.</b> " + _esc(h.get("safeguards")), st["body"]))
    E.append(Paragraph("Measured error rates for these methods, on public ground truth, are published with the source "
                       "code (benchmark/RESULTS.md at the commit named on the cover).", st["small"]))

    E.append(Paragraph("Verifying this record", st["h1"]))
    E.append(Paragraph("1. Run <i>python verify.py</i> in the bundle folder (Python 3 only). It checks every file's "
                       "SHA-256 against manifest.json, the evidence log's hash chain, that every fact matches the saved "
                       "raw response, and recomputes the Seal ID. 2. Add <i>--online</i> to re-read each fact from public "
                       "servers. 3. Any fact can also be checked by hand on a public explorer by its transaction hash.",
                       st["body"]))
    E.append(Paragraph(f"Seal ID {sid} = first 16 hex digits of SHA-256(findings.json + evidence-log head "
                       f"{_esc(log_head[:16])}...).", st["mono"]))

    E.append(PageBreak())
    E.append(Paragraph("Certification of the person who produced this record (to be completed and signed)", st["h1"]))
    E.append(Paragraph("Draft for attorney review; not legal advice. Follows the pattern of Federal Rules of Evidence "
                       "902(13) and 902(14) (authenticity only).", st["small"]))
    name = _esc(examiner.get("name") or "______________________")
    cert = [f"I, {name}, declare:",
            "1. I am over 18 and competent to make this declaration. My qualifications are: ____________________________.",
            f"2. On __________ I used ScamHunter (source commit {_esc(tool.get('git_commit'))}) to retrieve the records in "
            f"case {_esc(case_id)} from public blockchain servers listed in the bundle's evidence log.",
            "3. The software saved each response as received and recorded its SHA-256 hash in a sequential, hash-chained "
            "log at the time of retrieval. Each fact in this report can be compared with the saved response and with "
            "the public ledger itself.",
            f"4. I ran verify.py on the sealed bundle (Seal ID {sid}) and it reported ALL CHECKS PASSED.",
            "5. Statements labelled INFERENCE are opinions produced by the documented methods; they are not facts recorded "
            "on the ledger.",
            "I declare under penalty of perjury under the laws of __________________ that the foregoing is true and correct.",
            "Executed on ______________ at ______________________."]
    for c in cert:
        E.append(Paragraph(c, st["body"]))
        E.append(Spacer(1, 4))
    E.append(Spacer(1, 24))
    E.append(Paragraph("______________________________<br/>" + name, st["body"]))

    stamp_prefix = f"SH-{case_id}"

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.5)
        canvas.setFillColor(colors.HexColor("#555555"))
        canvas.drawString(0.6 * inch, 0.45 * inch, f"Case {case_id}  |  Seal ID {sid}  |  Sealed {sealed}")
        canvas.drawRightString(LETTER[0] - 0.6 * inch, 0.45 * inch, f"{stamp_prefix}-{doc.page:04d}")
        canvas.restoreState()

    path = os.path.join(bundle_dir, filename)
    doc = SimpleDocTemplate(path, pagesize=LETTER, leftMargin=0.6 * inch, rightMargin=0.6 * inch,
                            topMargin=0.6 * inch, bottomMargin=0.75 * inch,
                            title=f"Blockchain Tracing Report {case_id}", author=examiner.get("name") or "",
                            subject=f"Seal ID {sid}", creator="ScamHunter")
    doc.build(E, onFirstPage=footer, onLaterPages=footer)
    return path, sid
