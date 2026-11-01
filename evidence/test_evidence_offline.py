"""Offline end-to-end test of the evidence chain (no network).

    python -m evidence.test_evidence_offline
"""
import io
import json
import os
import shutil
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="sh_evidence_")
os.environ["SCAMHUNTER_EVIDENCE_DIR"] = os.path.join(TMP, "store")

from evidence import capture, corroborate, package, validate  # noqa: E402
from evidence.facts import Findings  # noqa: E402

capture.STORE = os.environ["SCAMHUNTER_EVIDENCE_DIR"]

VICTIM = "rVictimXXXXXXXXXXXXXXXXXXXXXXXXXX"
SCAM = "rwW2qTeD3dfk74bfURPrPAwfz2XADmocaN"
EXCH = "rExchangeHotWalletXXXXXXXXXXXXXXX"
TX1, TX2 = "A" * 64, "B" * 64


def ledger(server, body):
    h = body["params"][0]["transaction"]
    tx = {TX1: {"Account": VICTIM, "Destination": SCAM, "Amount": "500000000", "ledger_index": 90000001},
          TX2: {"Account": SCAM, "Destination": EXCH, "Amount": "499000000", "DestinationTag": 1234567,
                "ledger_index": 90000050}}[h]
    tx = dict(tx, TransactionType="Payment", Fee="12", Sequence=7, date=800000000)
    return {"result": {"tx_json": tx, "hash": h, "ledger_index": tx["ledger_index"], "validated": True,
                       "meta": {"TransactionResult": "tesSUCCESS", "delivered_amount": tx["Amount"]}}}


passed = failed = 0


def ok(cond, msg):
    global passed, failed
    print(("PASS " if cond else "FAIL ") + msg)
    passed, failed = passed + bool(cond), failed + (not cond)


corroborate.POST = ledger
f = Findings()
a, fa = corroborate.xrpl_fact(f, TX1)
b, fb = corroborate.xrpl_fact(f, TX2)
ok(fa["corroborated"] and fb["corroborated"], "facts corroborated by two servers")
ok("500.000000 XRP" in fa["statement"], "fact statement readable: " + fa["statement"])

path = f.derived("Funds path victim -> scam wallet -> exchange", [a, b], "taint-follow/1", {"hops": 2})
inf = f.inference(f"{EXCH} is an exchange hot wallet; tag 1234567 identifies the customer account",
                  [b], "exchange-label/1", "moderate", "label list X")
try:
    f.inference("x", [a], "made-up/1", "high")
    ok(False, "unknown heuristic rejected")
except ValueError:
    ok(True, "unknown heuristic rejected")
try:
    f.inference("x", [a], "mixer-timing/1", "high")
    ok(False, "unvalidated mixer heuristic capped")
except ValueError:
    ok(True, "unvalidated mixer heuristic capped at low confidence")

# disagreement between servers is recorded, not hidden
def liar(server, body):
    r = ledger(server, body)
    if "cluster" in server:
        r["result"]["tx_json"]["Amount"] = "1"
        r["result"]["meta"]["delivered_amount"] = "1"
    return r
corroborate.POST = liar
g = Findings()
_, gx = corroborate.xrpl_fact(g, TX1)
ok(not gx["corroborated"] and gx["sources"][1]["diff"], "server disagreement recorded and fact NOT marked corroborated")
corroborate.POST = ledger

ok(capture.verify_log()[0], "capture log chain intact")

res = package.build(f, "TEST-1", scope={"Requested by": "test"}, examiner={"name": "Test Examiner"},
                    out_dir=os.path.join(TMP, "cases"))
ok(os.path.exists(res["zip"]), "bundle zip written")

sys.path.insert(0, res["dir"])
import importlib.util  # noqa: E402
spec = importlib.util.spec_from_file_location("bverify", os.path.join(res["dir"], "verify.py"))
bv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bv)
buf = []
ok(bv.main(res["dir"], out=buf.append), "independent verifier passes on untouched bundle")

# tamper 1: edit a saved raw response
bl = os.path.join(res["dir"], "blobs", fa["sources"][0]["sha256"])
orig = open(bl, "rb").read()
open(bl, "wb").write(orig.replace(b"500000000", b"900000000"))
ok(not bv.main(res["dir"], out=lambda *_: None), "verifier catches an altered raw response")
open(bl, "wb").write(orig)

# tamper 2: edit a finding
fp = os.path.join(res["dir"], "findings.json")
origf = open(fp, encoding="utf-8").read()
open(fp, "w", encoding="utf-8").write(origf.replace("500.000000 XRP", "5,000.000000 XRP"))
ok(not bv.main(res["dir"], out=lambda *_: None), "verifier catches an edited finding")
open(fp, "w", encoding="utf-8").write(origf)

# tamper 3: delete a log entry
lp = os.path.join(res["dir"], "capture_log.jsonl")
lines = open(lp, encoding="utf-8").readlines()
open(lp, "w", encoding="utf-8").writelines(lines[:1] + lines[2:])
ok(not bv.main(res["dir"], out=lambda *_: None), "verifier catches a removed log entry")
open(lp, "w", encoding="utf-8").writelines(lines)

# tamper 4: slip in an extra file
xp = os.path.join(res["dir"], "extra_evidence.txt")
open(xp, "w").write("planted")
ok(not bv.main(res["dir"], out=lambda *_: None), "verifier catches a file added after sealing")
os.remove(xp)
ok(bv.main(res["dir"], out=lambda *_: None), "bundle verifies again after restoring")

try:
    package.build(f, "TEST-1", out_dir=os.path.join(TMP, "cases"))
    ok(False, "sealed bundle not overwritten")
except FileExistsError:
    ok(True, "sealed bundle is never overwritten")

ok(res.get("pdf") and os.path.exists(res["pdf"]) and "report.pdf" in json.load(open(os.path.join(res["dir"], "manifest.json")))["files"],
   "sealed PDF produced inside the bundle and covered by the manifest")
pp = res["pdf"]; pdfb = open(pp, "rb").read()
open(pp, "wb").write(pdfb.replace(b"Blockchain", b"Blockchaim", 1))
ok(not bv.main(res["dir"], out=lambda *_: None), "verifier catches an edited PDF")
open(pp, "wb").write(pdfb)
ok(any("Seal ID" in l and "PASS" in l for l in buf), "verifier recomputes the Seal ID printed on every page")
rep = open(os.path.join(res["dir"], "report.md"), encoding="utf-8").read()
ok("Inferences: opinions, not facts" in rep and "Could be wrong if" in rep, "report separates inferences and lists failure modes")
cert = open(os.path.join(res["dir"], "certification_template.md"), encoding="utf-8").read()
ok(res["manifest_sha256"] in cert, "certification quotes the manifest hash")

# validation harness
validate.RUNNERS["exchange-label/1"] = lambda inp: inp["labelled"]
r = validate.evaluate([{"heuristic": "exchange-label/1", "case": i, "input": {"labelled": i % 10 != 0}, "truth": True}
                       for i in range(50)])["exchange-label/1"]
ok(r["n"] == 50 and r["fn"] == 5 and r["recall_95ci"][0] < 0.9 < r["recall_95ci"][1], "validation reports recall with 95% interval")

print("\n".join(buf))
print(f"\n{passed} passed, {failed} failed")
shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if failed else 0)
