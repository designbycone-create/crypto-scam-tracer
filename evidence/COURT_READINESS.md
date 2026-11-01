# Court readiness: what ScamHunter does, and what it can't promise

**Not legal advice.** Have a lawyer review any filing. No software makes evidence "admissible". A judge decides
that, and only after a qualified person sponsors the evidence (an examiner, an investigator, or an expert).
What the software *can* do is keep the record honest, complete and checkable, so that person can answer every
question they'll be asked. Don't market this as "airtight" or "court-admissible". Say **"built to court
evidentiary standards: every fact verifiable, every inference disclosed."**

## What a court tests, and how each test is met

| Test | Rule | What ScamHunter does |
|---|---|---|
| Is the record what it claims to be? | FRE 901; 902(13)/(14) certification with hash values | Raw server responses are saved byte-for-byte under their SHA-256. A hash-chained log covers every read, including cache hits. A sealed manifest. `verify.py` lets anyone check it. A certification template is included. |
| Was the record altered? | Chain of custody | Append-only hash chain, so editing, deleting or reordering any entry breaks it. Sealed bundles are never overwritten. The test suite proves the verifier catches all four kinds of tampering. |
| Is the method reliable, and reliably applied? | FRE 702 (2023 amendment: shown by a preponderance); *Daubert*; Ala. R. Evid. 702(b) | FACT / DERIVED / INFERENCE are kept separate. Every inference names a registered heuristic with its assumptions, known failure modes and safeguards (`methodology.md`). An inference that cites no documented method is refused. |
| Known error rate? | *Daubert* factor | `validate.py` measures precision and recall with 95% intervals against ground-truth cases. Mixer heuristics with no measured rate are capped at "low" confidence by code. |
| Can it be independently checked? | Testability, peer review | Open source with the exact commit recorded. Facts are confirmed against a second, independently run ledger server, and any disagreement is recorded rather than hidden. `verify.py --online` re-reads the live ledger. |
| Does it overclaim? | Lesson from *US v. Sterlingov* (D.D.C.) | The report's standard limitations say plainly that addresses are not people, that attribution is inference, that funds are fungible, and that local clocks are not authoritative. Identity comes from exchange records obtained by subpoena. |

## What's still needed from people, not code
1. **A sponsoring witness.** Whoever ran the tool signs the certification, or testifies.
2. **Notice.** Under FRE 902(11), the other side gets the bundle in advance (902(13)/(14) work through it).
3. **Corroboration.** Exchange KYC records tied to the deposit address and tag. In Sterlingov, the court
   leaned on independent corroboration such as undercover transactions.
4. **Ground truth for error rates.** Matt's own case is a start, since he knows his own wallets. More labelled
   cases (from exchange confirmations and court records) narrow the intervals.
5. **Hearsay and state rules.** Authentication is not the same as admissibility. Alabama follows Daubert for
   scientific evidence under 702(b). Check which certification rules your state has adopted.

## Using it
```python
from evidence import hooks; hooks.install()          # capture every network read
from evidence.facts import Findings
from evidence import corroborate, package
f = Findings()
a, _ = corroborate.xrpl_fact(f, "<victim payment tx hash>")
b, _ = corroborate.xrpl_fact(f, "<deposit to exchange tx hash>")
f.derived("Path victim -> exchange deposit", [a, b], "taint-follow/1", {"hops": 2})
f.inference("Destination is <exchange> hot wallet; tag N = customer account", [b], "exchange-label/1", "moderate")
package.build(f, "SH-2026-0001", scope={...}, examiner={"name": "..."})
```
Test with `python -m evidence.test_evidence_offline`.

## Sources
- FRE 702 (2023 amendment): https://www.sidley.com/en/insights/newsupdates/2023/12/amendments-to-federal-rule-of-evidence-702
- FRE 902(13)/(14): https://www.americanbar.org/groups/litigation/resources/newsletters/trial-evidence/new-federal-rules-evidence-90213-90214/
- US v. Sterlingov, Daubert ruling on blockchain tracing: https://www.courtlistener.com/docket/60166406/united-states-v-sterlingov/
- Critique of tracing-tool reliability: https://www.secjuice.com/
- Alabama Rule 702: https://www.alfainternational.com/
