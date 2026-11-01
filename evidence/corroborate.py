"""Read each transaction from two independent XRPL servers and record whether
they agree field-for-field. Both raw responses are captured as evidence.

The two default servers are run by different operators (Ripple, and the
community XRPL Cluster), so agreement isn't one party vouching for itself.
"""
import json
import urllib.request

from . import capture
from .facts import Findings, describe_xrpl, xrpl_tx_fields

SERVERS = ["https://s2.ripple.com:51234/", "https://xrplcluster.com/"]

POST = None   # test hook: f(server, body_dict) -> response dict


def _post(server, body):
    if POST:
        return POST(server, body)
    req = urllib.request.Request(server, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": "ScamHunter-evidence"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()


def fetch_tx(server, tx_hash):
    body = {"method": "tx", "params": [{"transaction": tx_hash, "binary": False, "api_version": 2}]}
    raw = _post(server, body)
    if isinstance(raw, dict):
        raw = json.dumps(raw, sort_keys=True).encode()
    digest = capture.record(f"xrpl-jsonrpc:{server}", "tx", body["params"][0], raw)
    return json.loads(raw), digest, raw


def xrpl_fact(findings: Findings, tx_hash, servers=None):
    """Fetch tx from the first server, record a FACT, corroborate with the rest.
    Returns (fact_id, fact_dict)."""
    servers = servers or SERVERS
    resp, digest, _ = fetch_tx(servers[0], tx_hash)
    fields = xrpl_tx_fields(resp)
    if not fields.get("validated"):
        raise ValueError(f"{tx_hash} is not in a validated ledger on {servers[0]} -- not usable as a fact")
    fid = findings.fact("xrpl", tx_hash, describe_xrpl(fields), fields, digest, servers[0])
    for s in servers[1:]:
        try:
            resp2, d2, _ = fetch_tx(s, tx_hash)
            f2 = xrpl_tx_fields(resp2)
            diff = {k: [fields.get(k), f2.get(k)] for k in set(fields) | set(f2) if fields.get(k) != f2.get(k)}
            findings.corroborate(fid, d2, s, agrees=not diff, diff=diff or None)
        except Exception as e:
            findings.corroborate(fid, None, s, agrees=False, diff={"error": repr(e)[:200]})
    return fid, findings.items[fid]
