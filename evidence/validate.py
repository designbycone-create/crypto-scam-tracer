"""Measure how often each heuristic is right: the error rates courts ask for.

Daubert/FRE 702 asks for a method's "known or potential rate of error". Commercial
tracing tools have been criticised in court for publishing none. Noxos says
publicly that it can't vouch for its new mixer-linkage engine yet. This module
is the missing step: run a heuristic against cases where the true answer is known
(ground truth), and record precision, recall and sample size with a confidence
interval. The results go into methodology.md.

Ground-truth file (JSONL), one labelled case per line:
  {"heuristic": "exchange-label/1", "case": "...", "input": {...}, "truth": true|false,
   "source": "how the truth is known (exchange confirmation, court record, seized key, own test txs)"}

Planting known transactions (e.g. sending small amounts through the path and
recording what the tool reports) is the same corroboration that let the court
in US v. Sterlingov accept blockchain tracing. Matt's own case can seed this,
because he knows which wallets are his.

    python -m evidence.validate ground_truth.jsonl
"""
import json
import math
import sys
from datetime import datetime, timezone

from .facts import HEURISTICS

RUNNERS = {}   # heuristic id -> f(input) -> bool prediction; register with @runner("id")


def runner(hid):
    def deco(fn):
        RUNNERS[hid] = fn
        return fn
    return deco


def wilson(k, n, z=1.96):
    """95% Wilson score interval for k successes in n trials."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def evaluate(cases):
    stats = {}
    for c in cases:
        hid = c["heuristic"]
        fn = RUNNERS.get(hid)
        s = stats.setdefault(hid, {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "skipped": 0, "errors": []})
        if fn is None:
            s["skipped"] += 1
            continue
        pred = bool(fn(c["input"]))
        truth = bool(c["truth"])
        key = ("t" if pred == truth else "f") + ("p" if pred else "n")
        s[key] += 1
        if pred != truth:
            s["errors"].append(c.get("case"))
    out = {}
    for hid, s in stats.items():
        tp, fp, fn_ = s["tp"], s["fp"], s["fn"]
        out[hid] = {**s, "n": tp + fp + s["tn"] + fn_,
                    "precision": tp / (tp + fp) if tp + fp else None,
                    "precision_95ci": wilson(tp, tp + fp),
                    "recall": tp / (tp + fn_) if tp + fn_ else None,
                    "recall_95ci": wilson(tp, tp + fn_),
                    "evaluated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    return out


def to_markdown(results):
    lines = ["## Measured error rates", "",
             "| Heuristic | Cases | Precision (95% CI) | Recall (95% CI) | False positives |", "|---|---|---|---|---|"]
    for hid, r in sorted(results.items()):
        def fmt(v, ci):
            return "n/a" if v is None else f"{v:.0%} ({ci[0]:.0%} to {ci[1]:.0%})"
        lines.append(f"| {HEURISTICS.get(hid, {}).get('name', hid)} | {r['n']} | {fmt(r['precision'], r['precision_95ci'])} | "
                     f"{fmt(r['recall'], r['recall_95ci'])} | {r['fp']} |")
    lines += ["", "Small samples give wide intervals; an interval is reported, never just a point estimate.", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    cases = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
    print(to_markdown(evaluate(cases)))
