"""A site I use changed: front-end / domain hijack early warning.

A hijacked dApp keeps its REAL domain, so lookalike-domain radar can't see it.
What does change is the plumbing. For each watched domain we keep a baseline
and compare on every check:

  ns        nameservers changed                         (strong: DNS takeover)
  registrar registrar changed                           (strong: domain transfer)
  lock      clientTransferProhibited lock removed       (strong)
  ip        A records moved to entirely new addresses   (medium)
  cert      new certificate from an issuer never used before (medium)
  thirdparty scripts now loaded from a NEW outside host       (medium: how drainer kits get injected)
  scripts   first-party JavaScript files changed         (weak: normal deploys do this)

Alert rule: any strong signal, or two or more signals together. One weak
signal is logged, not alerted (sites deploy all the time).

Free sources: DNS-over-HTTPS (Cloudflare), RDAP (rdap.org), crt.sh, the site.

    python -m shield.sitewatch add pickle.finance app.uniswap.org
    python -m shield.sitewatch check
"""
import hashlib
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime

FILE = "sitewatch.json"
UA = {"User-Agent": "Mozilla/5.0 ScamHunter-Sitewatch/0.1", "Accept": "application/dns-json, application/json, */*"}
STRONG = {"ns", "registrar", "lock"}
DEFAULT_WATCH = ["app.uniswap.org", "app.aave.com", "curve.fi", "pancakeswap.finance", "jup.ag", "raydium.io",
                 "lido.fi", "app.1inch.io", "xrpl.org", "xaman.app"]

GET = None   # test hook: f(url) -> str


def _get(url, limit=1_500_000):
    if GET:
        return GET(url)
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read(limit).decode("utf-8", "replace")


def _apex(domain):
    parts = domain.split(".")
    return ".".join(parts[-3:]) if len(parts) > 2 and parts[-2] in ("co", "com", "org", "net") and len(parts[-1]) == 2 \
        else ".".join(parts[-2:])


def dns(name, rtype):
    try:
        d = json.loads(_get(f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(name)}&type={rtype}"))
        return sorted({a.get("data", "").rstrip(".").lower() for a in d.get("Answer", []) if a.get("data")})
    except Exception:
        return None


def rdap(domain):
    try:
        d = json.loads(_get(f"https://rdap.org/domain/{_apex(domain)}"))
    except Exception:
        return None
    reg = None
    for ent in d.get("entities", []):
        if "registrar" in (ent.get("roles") or []):
            for item in (ent.get("vcardArray") or [None, []])[1]:
                if item and item[0] == "fn":
                    reg = item[3]
    status = sorted(s.lower() for s in d.get("status", []))
    changed = next((e.get("eventDate") for e in d.get("events", []) if e.get("eventAction") == "last changed"), None)
    return {"registrar": reg, "status": status, "last_changed": changed,
            "locked": any("transfer prohibited" in s or "transferprohibited" in s.replace(" ", "") for s in status)}


def certs(domain):
    try:
        rows = json.loads(_get(f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json&exclude=expired") or "[]")
    except Exception:
        return None
    issuers = sorted({(r.get("issuer_name") or "").split("O=")[-1].split(",")[0].strip() for r in rows if r.get("issuer_name")})
    newest = max((r.get("not_before") or "" for r in rows), default="")
    return {"issuers": issuers, "newest": newest[:19]}


def scripts(domain):
    try:
        html = _get(f"https://{domain}/")
    except Exception:
        return None
    srcs = re.findall(r"<script[^>]+src=[\"']([^\"']+)", html, re.I)
    out = {}
    for s in srcs[:15]:
        u = urllib.parse.urljoin(f"https://{domain}/", s)
        host = urllib.parse.urlparse(u).hostname or ""
        if not (host == domain or host.endswith("." + _apex(domain))):
            out[u] = "third-party"        # record third-party script hosts too (a new one is a signal)
            continue
        try:
            out[u] = hashlib.sha256(_get(u, 8_000_000).encode()).hexdigest()[:16]
        except Exception:
            out[u] = "unreachable"
    return out


def snapshot(domain):
    return {"time": datetime.now().strftime("%Y-%m-%d %H:%M"), "ns": dns(_apex(domain), "NS"),
            "a": dns(domain, "A"), "rdap": rdap(domain), "certs": certs(domain), "scripts": scripts(domain)}


def compare(base, cur):
    sig = []
    if base.get("ns") and cur.get("ns") and set(base["ns"]) != set(cur["ns"]):
        sig.append(("ns", f"nameservers {', '.join(base['ns'])} -> {', '.join(cur['ns'])}"))
    br, cr = base.get("rdap") or {}, cur.get("rdap") or {}
    if br.get("registrar") and cr.get("registrar") and br["registrar"] != cr["registrar"]:
        sig.append(("registrar", f"registrar {br['registrar']} -> {cr['registrar']}"))
    if br.get("locked") and cr and cr.get("locked") is False:
        sig.append(("lock", "transfer lock removed"))
    if base.get("a") and cur.get("a") and not (set(base["a"]) & set(cur["a"])):
        sig.append(("ip", f"site moved to new addresses {', '.join(cur['a'][:3])}"))
    bc, cc = base.get("certs") or {}, cur.get("certs") or {}
    new_iss = set(cc.get("issuers") or []) - set(bc.get("issuers") or [])
    if bc.get("issuers") and new_iss:
        sig.append(("cert", f"certificate from a new issuer: {', '.join(sorted(new_iss))}"))
    bs, cs = base.get("scripts") or {}, cur.get("scripts") or {}
    if bs and cs:
        changed = [u for u in cs if u in bs and cs[u] != bs[u]]
        added_3p = [u for u in cs if u not in bs and cs[u] == "third-party"]
        if changed or set(cs) - set(bs):
            sig.append(("scripts", f"{len(changed)} script(s) changed, {len(set(cs) - set(bs))} new"))
        new_hosts = {urllib.parse.urlparse(u).hostname for u in added_3p} - \
            {urllib.parse.urlparse(u).hostname for u in bs}
        if new_hosts:
            # drainer kits are usually loaded from an outside host -- a medium signal on its own
            sig.append(("thirdparty", f"loads scripts from a new outside host: {', '.join(sorted(new_hosts))}"))
    kinds = {k for k, _ in sig}
    level = "alert" if (kinds & STRONG or len(kinds) >= 2) else ("notice" if sig else "ok")
    if kinds == {"thirdparty"} or kinds == {"ip"} or kinds == {"cert"}:
        level = "watch"   # one medium signal: shown in amber, re-checked, alert if anything else moves
    return level, sig


def load():
    try:
        with open(FILE, encoding="utf-8-sig") as f:
            d = json.load(f)
    except Exception:
        d = {}
    d.setdefault("sites", {})
    return d


def save(d):
    tmp = FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=1)
    os.replace(tmp, FILE)


def add(domains):
    d = load()
    added = []
    for dom in domains:
        dom = dom.lower().replace("https://", "").replace("http://", "").split("/")[0].strip()
        if dom and dom not in d["sites"]:
            d["sites"][dom] = {"added": datetime.now().strftime("%Y-%m-%d %H:%M"), "baseline": None, "last": None,
                               "level": "new", "signals": [], "history": []}
            added.append(dom)
    save(d)
    return added


def remove(domain):
    d = load()
    d["sites"].pop(domain, None)
    save(d)


def accept(domain):
    """User/team confirmed the change is legitimate: current state becomes the baseline."""
    d = load()
    s = d["sites"].get(domain)
    if s and s.get("last"):
        s["baseline"], s["level"], s["signals"] = s["last"], "ok", []
        save(d)


def check(log=print, alert=None):
    """Check every site. alert(domain, signals) is called for new alerts."""
    d = load()
    for dom, s in d["sites"].items():
        try:
            cur = snapshot(dom)
        except Exception as e:
            log(f"sitewatch: {dom} failed ({e})")
            continue
        s["last"] = cur
        if not s.get("baseline"):
            s["baseline"], s["level"] = cur, "ok"
            continue
        level, sig = compare(s["baseline"], cur)
        was, was_sig = s.get("level"), set(s.get("signals") or [])
        s["level"], s["signals"] = level, [m for _, m in sig]
        if level not in ("ok",):
            s["history"] = (s.get("history") or [])[-20:] + [{"time": cur["time"], "level": level, "signals": s["signals"]}]
        if level == "alert" and alert and (was != "alert" or set(s["signals"]) - was_sig):   # new or escalated
            alert(dom, s["signals"])
        if level == "notice":
            # weak change only (e.g. a normal deploy): roll the baseline forward for scripts
            s["baseline"]["scripts"] = cur.get("scripts")
    d["checked"] = datetime.now().strftime("%Y-%m-%d %H:%M")
    save(d)
    return d


if __name__ == "__main__":
    if sys.argv[1:2] == ["add"]:
        print(add(sys.argv[2:] or DEFAULT_WATCH))
    elif sys.argv[1:2] == ["check"]:
        r = check(alert=lambda dom, sig: print("ALERT", dom, sig))
        for dom, s in r["sites"].items():
            print(f"{s['level']:7} {dom}  {'; '.join(s['signals'])}")
    else:
        print(__doc__)
