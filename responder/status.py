"""Exchange status awareness.

During a hack or outage, exchanges pause deposits/withdrawals -- which changes
what you should do (a paused exchange is a window: funds there can't leave).
This reads public Atlassian-Statuspage APIs for exchanges that publish one
(configure in channels.json "status_url", or channels_overrides.json).
Exchanges without a public status API are shown as "no public status feed".
Output: exchange_status.json
"""
import json
import urllib.request
from datetime import datetime

from freezekit import channels

OUT = "exchange_status.json"


def check(keys=None, log=print, _get=None):
    res = {"checked": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "exchanges": {}}
    for key, ent in channels.directory()["exchanges"].items():
        if keys and key not in keys:
            continue
        url = ent.get("status_url")
        if not url:
            res["exchanges"][key] = {"name": ent["name"], "state": "no public status feed"}
            continue
        try:
            if _get:
                d = _get(url)
            else:
                req = urllib.request.Request(url.rstrip("/") + "/api/v2/summary.json",
                                             headers={"User-Agent": "ScamHunter/1.0"})
                with urllib.request.urlopen(req, timeout=15) as r:
                    d = json.loads(r.read())
            ind = (d.get("status") or {}).get("indicator", "unknown")
            incidents = [i.get("name") for i in d.get("incidents", [])][:3]
            xrp = {c.get("name"): c.get("status") for c in d.get("components", [])
                   if "xrp" in (c.get("name") or "").lower() and c.get("status") != "operational"}
            res["exchanges"][key] = {"name": ent["name"], "state": ind,
                                     "description": (d.get("status") or {}).get("description"),
                                     "incidents": incidents, "xrp_issues": xrp, "url": url}
        except Exception as e:
            res["exchanges"][key] = {"name": ent["name"], "state": "unreachable", "error": str(e)[:120]}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1)
    return res


def load():
    try:
        with open(OUT, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}
