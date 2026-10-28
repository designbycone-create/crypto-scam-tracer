"""Scam-site infrastructure scan.

Everything here is public-record lookup: DNS, RDAP (the modern WHOIS),
certificate-transparency logs, and one plain GET of the scam page's HTML
(no scripts run). The output tells you WHO HOSTS and WHO REGISTERED the
scam's infrastructure, and how to reach their abuse desks. The server IP
belongs to the hosting company, not the scammer's home. Unmasking the
person behind the account takes the provider's records, which law
enforcement can compel.
"""
import json
import re
import socket
import ssl
import urllib.parse
import urllib.request

UA = {"User-Agent": "Mozilla/5.0 (scam-investigator/1.0; abuse research)"}


def _ssl_ctx():
    """Prefer certifi's CA bundle when installed (fixes Windows CA gaps)."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def _get_json(url, timeout=15):
    req = urllib.request.Request(url, headers={**UA, "Accept": "application/json, application/dns-json, application/rdap+json"})
    with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


DOH_SERVERS = ["https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"]


def dns(domain):
    out = {}
    for rtype in ("A", "AAAA", "NS", "MX", "TXT", "CNAME"):
        errs = []
        for doh in DOH_SERVERS:
            try:
                q = urllib.parse.urlencode({"name": domain, "type": rtype})
                data = _get_json(f"{doh}?{q}")
                vals = [a["data"].strip('"') for a in data.get("Answer", []) if a.get("type") in (1, 28, 2, 15, 16, 5)]
                if vals:
                    out[rtype] = vals
                errs = []
                break
            except Exception as e:
                errs.append(f"{doh}: {e}")
        if errs:
            out.setdefault("_errors", []).append(f"{rtype}: {errs[-1]}")
    if not out.get("A") and not out.get("AAAA"):
        # Last resort: the operating system's own resolver
        try:
            ips = sorted({ai[4][0] for ai in socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)})
            if ips:
                out["A"] = [i for i in ips if ":" not in i]
                out["AAAA"] = [i for i in ips if ":" in i]
                out["_source"] = "system resolver"
        except Exception as e:
            out.setdefault("_errors", []).append(f"system resolver: {e}")
    return out


def _vcard_field(entity, field):
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == field:
            return item[3]
    return None


def _entities(obj):
    """Flatten RDAP entities into role -> {name, email, phone, url}."""
    found = {}
    def walk(ents):
        for e in ents or []:
            info = {"name": _vcard_field(e, "fn"), "email": _vcard_field(e, "email"),
                    "phone": _vcard_field(e, "tel"), "handle": e.get("handle")}
            for role in e.get("roles", []):
                found.setdefault(role, info)
            walk(e.get("entities"))
    walk(obj.get("entities"))
    return found


def rdap_domain(domain):
    try:
        d = _get_json(f"https://rdap.org/domain/{domain}")
    except Exception as e:
        return {"error": str(e)}
    events = {ev.get("eventAction"): ev.get("eventDate") for ev in d.get("events", [])}
    ents = _entities(d)
    return {
        "registrar": (ents.get("registrar") or {}).get("name"),
        "registrar_abuse": ents.get("abuse"),
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "updated": events.get("last changed"),
        "status": d.get("status"),
        "nameservers": [n.get("ldhName") for n in d.get("nameservers", [])],
        "registrant": ents.get("registrant"),  # usually privacy-redacted
    }


def rdap_ip(ip):
    try:
        d = _get_json(f"https://rdap.org/ip/{ip}")
    except Exception as e:
        return {"ip": ip, "error": str(e)}
    ents = _entities(d)
    return {
        "ip": ip,
        "network": d.get("name"),
        "range": f"{d.get('startAddress')} - {d.get('endAddress')}",
        "country": d.get("country"),
        "owner": (ents.get("registrant") or {}).get("name"),
        "abuse": ents.get("abuse"),
        "cdn_note": "Cloudflare proxies hide the real origin server; report to Cloudflare's abuse form and they forward to the host."
        if "CLOUDFLARE" in (d.get("name") or "").upper() else None,
    }


def cert_history(domain, limit=25):
    """Certificate-transparency log: sibling domains on the same certs.
    crt.sh is often slow/flaky, so this is best-effort with a short timeout."""
    try:
        rows = _get_json(f"https://crt.sh/?q={urllib.parse.quote(domain)}&output=json", timeout=12)
    except Exception as e:
        return {"error": str(e), "note": "crt.sh unavailable (external service); certificate history skipped."}
    names, issuers, first = set(), set(), None
    for r in rows:
        for n in (r.get("name_value") or "").split("\n"):
            names.add(n.strip().lower())
        issuers.add(r.get("issuer_name", "").split("O=")[-1].split(",")[0])
        nb = r.get("not_before")
        first = min(first, nb) if first and nb else (nb or first)
    return {"first_cert": first, "names": sorted(names)[:limit], "issuers": sorted(i for i in issuers if i)}


PATTERNS = {
    "xrp_addresses": r"\br[1-9A-HJ-NP-Za-km-z]{24,34}\b",
    "btc_addresses": r"\b(?:bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b",
    "eth_addresses": r"\b0x[a-fA-F0-9]{40}\b",
    "tawk_widgets": r"embed\.tawk\.to/([a-f0-9]{24})/([a-z0-9]+)",
    "telegram": r"(?:t\.me|telegram\.me)/[A-Za-z0-9_+/]+",
    "whatsapp": r"wa\.me/\d+",
    "youtube": r"(?:youtube\.com/(?:@|channel/|watch\?v=)|youtu\.be/)[A-Za-z0-9_\-@]+",
    "emails": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "analytics_ids": r"\b(?:UA-\d{4,10}-\d+|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{5,8})\b",
}


def scan_page(url, max_bytes=2_000_000):
    """One GET of the page source. Scripts are NOT executed."""
    ctx = _ssl_ctx()
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            html = r.read(max_bytes).decode("utf-8", "replace")
            final_url, status = r.geturl(), r.status
    except Exception as e:
        return {"url": url, "error": str(e)}
    found = {}
    for k, pat in PATTERNS.items():
        m = re.findall(pat, html)
        if k == "tawk_widgets":
            m = [f"property {a} / widget {b}" for a, b in m]
        vals = sorted(set(m))
        if vals:
            found[k] = vals[:40]
    req_host = urllib.parse.urlparse(url).hostname or ""
    final_host = urllib.parse.urlparse(final_url).hostname or ""
    if final_host and not final_host.endswith(req_host.replace("www.", "")):
        found["cloaking"] = [f"Automated visitors are redirected to {final_host}; the scam page is hidden from scanners. "
                             f"Use your own screenshots as evidence."]
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    scripts = sorted(set(re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.I)))
    return {"url": url, "final_url": final_url, "status": status, "title": title.group(1).strip() if title else None,
            "bytes": len(html), "indicators": found, "external_scripts": scripts[:40]}


def investigate_domain(domain):
    domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    d = dns(domain)
    ips = (d.get("A") or []) + (d.get("AAAA") or [])
    hosting = [rdap_ip(ip) for ip in ips[:4]]
    try:
        from .enrich import geolocate_ip
        for h in hosting:
            if not h.get("error"):
                h["geo"] = geolocate_ip(h["ip"])
    except Exception:
        pass
    return {
        "domain": domain,
        "dns": d,
        "registration": rdap_domain(domain),
        "hosting": hosting,
        "certificates": cert_history(domain),
        "page": scan_page(f"https://{domain}/"),
    }
