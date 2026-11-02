"""Turn benchmark results into published error rates with 95% intervals.

Writes benchmark/RESULTS.md and benchmark/data/metrics.json.
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from benchmark import truth  # noqa: E402
from benchmark.run import RESULTS  # noqa: E402
from evidence.validate import wilson  # noqa: E402

ALIASES = {"okx": ["okx", "okex"], "htx": ["htx", "huobi"], "gate": ["gate.io", "gate io", "gateio", "gate"],
           "bitget": ["bitget"], "bitstamp": ["bitstamp"], "kucoin": ["kucoin"], "bitfinex": ["bitfinex"],
           "binance": ["binance"], "coinbase": ["coinbase"], "kraken": ["kraken"], "bybit": ["bybit"],
           "mexc": ["mexc"], "crypto.com": ["crypto.com"], "upbit": ["upbit"], "bithumb": ["bithumb"]}


def judge_label(label, exchange):
    """correct | wrong_exchange | other_label | none"""
    if not label:
        return "none"
    low = str(label).lower()
    if any(a in low for a in ALIASES.get(exchange, [exchange])):
        return "correct"
    if any(a in low for k, al in ALIASES.items() if k != exchange for a in al):
        return "wrong_exchange"
    return "other_label"


def rate(k, n):
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": (k / n) if n else None, "ci95": [round(lo, 3), round(hi, 3)]}


def compute(cases=None, results=None):
    cases = {c["id"]: c for c in (cases or truth.load())}
    res = results
    if res is None:
        res = []
        with open(RESULTS, encoding="utf-8") as f:
            res = [json.loads(l) for l in f if l.strip()]
    latest = {}
    for r in res:
        latest[(r["case"], r["test"])] = r
    m = {"errors_or_timeouts": sum(1 for r in latest.values() if r.get("error")), "by_chain": {}}
    ex = [c for c in cases.values() if c["group"] == "exchange"]
    bad = [c for c in cases.values() if c["group"] == "known_bad"]

    def val(c, t):
        r = latest.get((c["id"], t))
        return None if (r is None or r.get("error")) else r.get("value")

    # 1. exchange identification
    judged = [(c, judge_label(val(c, "identify"), c["exchange"])) for c in ex if (c["id"], "identify") in latest
              and not latest[(c["id"], "identify")].get("error")]
    correct = sum(1 for _, j in judged if j == "correct")
    wrong = sum(1 for _, j in judged if j == "wrong_exchange")
    other = sum(1 for _, j in judged if j == "other_label")
    m["identify"] = {"cases": len(judged), "correct": correct, "wrong_exchange": wrong, "other_label": other,
                     "none": sum(1 for _, j in judged if j == "none"),
                     "recall": rate(correct, len(judged)),
                     "precision_strict": rate(correct, correct + wrong + other),
                     "wrong_exchange_rate": rate(wrong, correct + wrong + other),
                     "examples_wrong": [(c["address"], c["exchange"], val(c, "identify")) for c, j in judged if j != "correct" and j != "none"][:10]}
    for ch in sorted({c["chain"] for c, _ in judged}):
        sub = [j for c, j in judged if c["chain"] == ch]
        m["by_chain"].setdefault(ch, {})["identify_recall"] = rate(sum(1 for j in sub if j == "correct"), len(sub))
    bad_judged = [(c, val(c, "identify")) for c in bad if (c["id"], "identify") in latest and not latest[(c["id"], "identify")].get("error")]
    exch_named = sum(1 for _, v in bad_judged if v and any(a in str(v).lower() for al in ALIASES.values() for a in al))
    m["identify_on_bad"] = {"cases": len(bad_judged), "named_an_exchange": rate(exch_named, len(bad_judged))}

    # 2. behaviour signals only
    def flagged(v):
        return bool(v) and v.get("verdict") in ("STOP", "CAUTION")
    # Behaviour can only be judged on wallets with readable on-chain activity: an address that was never
    # used has no behaviour. Those are counted separately (rule fixed before round 2 was drawn).
    active = lambda c: (val(c, "behaviour_only").get("movements") or 0) > 0
    bad_all = [c for c in bad if val(c, "behaviour_only")]
    ex_all = [c for c in ex if val(c, "behaviour_only")]
    bad_b, ex_b = [c for c in bad_all if active(c)], [c for c in ex_all if active(c)]
    m["empty_addresses"] = {"known_bad": len(bad_all) - len(bad_b), "exchange": len(ex_all) - len(ex_b)}
    tp = sum(1 for c in bad_b if flagged(val(c, "behaviour_only")))
    fp = sum(1 for c in ex_b if flagged(val(c, "behaviour_only")))
    m["behaviour_only"] = {"recall_on_known_bad": rate(tp, len(bad_b)),
                           "false_flag_rate_on_exchanges": rate(fp, len(ex_b)),
                           "precision_on_this_mix": rate(tp, tp + fp),
                           "no_history_bad": len(bad_all) - len(bad_b)}
    for ch in sorted({c["chain"] for c in bad_b + ex_b}):
        b = [c for c in bad_b if c["chain"] == ch]
        e = [c for c in ex_b if c["chain"] == ch]
        m["by_chain"].setdefault(ch, {}).update({
            "behaviour_recall": rate(sum(1 for c in b if flagged(val(c, "behaviour_only"))), len(b)),
            "behaviour_false_flags": rate(sum(1 for c in e if flagged(val(c, "behaviour_only"))), len(e))})
    # 3. as deployed (what a user sees) on exchanges
    ex_d = [c for c in ex if val(c, "as_deployed") and val(c, "behaviour_only") and active(c)]
    m["as_deployed_exchanges"] = {"false_flag_rate": rate(sum(1 for c in ex_d if flagged(val(c, "as_deployed"))), len(ex_d))}
    return m


def _fmt(r):
    if not r or not r["n"]:
        return "not measured"
    return f"{r['rate']:.0%} ({r['k']}/{r['n']}; 95% CI {r['ci95'][0]:.0%} to {r['ci95'][1]:.0%})"


def markdown(m, sources):
    i, b = m["identify"], m["behaviour_only"]
    lines = [f"# ScamHunter error-rate benchmark (round {m.get('round', '1')})", "",
             f"Run {time.strftime('%Y-%m-%d', time.gmtime())}. Every number below comes from running the released tool "
             "on public ground truth it does not itself use. Intervals are 95% Wilson score intervals; small samples give wide ones.", "",
             "## 1. Exchange identification (`exchange-label/1`)", "",
             f"- Named the right exchange: **{_fmt(i['recall'])}** of exchange-published wallets.",
             f"- When it named someone, it was right: **{_fmt(i['precision_strict'])}**.",
             f"- Named the WRONG exchange: **{_fmt(i['wrong_exchange_rate'])}** of the times it named one.",
             f"- Unlabelled (no name given; the tool says \"unidentified\"): {i['none']} of {i['cases']}.",
             f"- On known scam / sanctioned wallets, named an exchange: {_fmt(m['identify_on_bad']['named_an_exchange'])}.", "",
             "## 2. Pre-screen behaviour signals alone (`behavior-signal/1`), every list lookup switched off", "",
             f"- Flagged known scam / sanctioned wallets with on-chain activity: **{_fmt(b['recall_on_known_bad'])}**.",
             f"- Never-used addresses, not judged (no behaviour exists): {m['empty_addresses']['known_bad']} known-bad, "
             f"{m['empty_addresses']['exchange']} exchange-published.",
             f"- Wrongly flagged exchange wallets: **{_fmt(b['false_flag_rate_on_exchanges'])}**.",
             f"- As users actually run it (lists and identity on), exchange wallets flagged: {_fmt(m['as_deployed_exchanges']['false_flag_rate'])}.", "",
             "## By chain", "", "| Chain | Identification recall | Behaviour recall on bad | Behaviour false flags |", "|---|---|---|---|"]
    for ch, v in sorted(m["by_chain"].items()):
        lines.append(f"| {ch} | {_fmt(v.get('identify_recall'))} | {_fmt(v.get('behaviour_recall'))} | {_fmt(v.get('behaviour_false_flags'))} |")
    lines += ["", f"Tests that errored or timed out (excluded, never counted as passes): {m['errors_or_timeouts']}.", "",
              "## Limits", "",
              "- Exchange reserve wallets are busy institutional wallets, not typical personal wallets.",
              "- Sanctioned and listed scam wallets are often old or emptied; signals that need recent activity can't fire on them.",
              "- Behaviour signals are risk indicators, not proof. The pre-screen says so on every result.",
              "- Samples are drawn by hash, so anyone can rebuild the same case set from the sources below.", "",
              "## Ground-truth sources", ""]
    for k, s in sources.items():
        lines.append(f"- {s['what']}: {s['url']} (SHA-256 `{s['sha256'][:16]}…`, retrieved {s['retrieved']})")
    return "\n".join(lines) + "\n"


def write():
    m = compute()
    m["round"] = truth.ROUND
    with open(os.path.join(truth.DATA, "sources.json"), encoding="utf-8") as f:
        sources = json.load(f)
    with open(os.path.join(truth.DATA, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(m, f, indent=1)
    md = markdown(m, sources)
    out_md = os.path.join(HERE, "RESULTS.md" if truth.ROUND == "1" else f"RESULTS_round{truth.ROUND}.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write(md)
    print(md)
    return m


if __name__ == "__main__":
    write()
