"""Tiny HTTP helper shared by adapters. Standard-library only (urllib), so the
tool has no third-party dependency to install on a victim's machine."""
import json
import time
import urllib.parse
import urllib.request

_UA = "scam-investigator-multichain/1.0 (anti-fraud tracing)"


def http_json(url, params=None, timeout=40, headers=None, retries=2, backoff=1.5):
    if params:
        url = url + ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    hdrs = {"User-Agent": _UA, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:
            last = e
            if attempt < retries:
                time.sleep(backoff * (attempt + 1))
    raise last
