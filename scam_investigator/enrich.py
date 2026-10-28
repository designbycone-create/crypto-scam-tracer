"""Enrichment: server-IP geolocation, and OFAC sanctions screening.

Both use public data sources.

IP geolocation resolves a *server* IP to the hosting datacenter's city,
country, network (ASN) and abuse desk. This is the hosting company's
location, not any individual's home. It tells you which country's abuse
desk and police have jurisdiction over the machine.

Sanctions screening checks a crypto address against OFAC's published SDN
list. A hit means the address is already on a U.S. sanctions list, which
sharply raises law-enforcement priority and makes most exchanges freeze on
contact.
"""
import csv
import io
import json
import ssl
import urllib.request

from .osint import _ssl_ctx, UA

# --- Server IP geolocation -------------------------------------------------

# Public, keyless endpoints. ipwho.is is HTTPS and returns ASN + org.
# ip-api.com is the fallback (HTTP on the free tier).
GEO_ENDPOINTS = [
    ("ipwho.is", "https://ipwho.is/{ip}"),
    ("ip-api.com", "http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,asname,query"),
]


def geolocate_ip(ip):
    for name, tmpl in GEO_ENDPOINTS:
        try:
            req = urllib.request.Request(tmpl.format(ip=ip), headers=UA)
            with urllib.request.urlopen(req, timeout=12, context=_ssl_ctx()) as r:
                d = json.loads(r.read().decode("utf-8", "replace"))
            if name == "ipwho.is" and d.get("success"):
                conn = d.get("connection", {})
                return {"ip": ip, "country": d.get("country"), "country_code": d.get("country_code"),
                        "region": d.get("region"), "city": d.get("city"),
                        "org": conn.get("org") or conn.get("isp"), "asn": conn.get("asn"),
                        "network": conn.get("domain"), "source": name}
            if name == "ip-api.com" and d.get("status") == "success":
                return {"ip": ip, "country": d.get("country"), "country_code": d.get("countryCode"),
                        "region": d.get("regionName"), "city": d.get("city"),
                        "org": d.get("org") or d.get("isp"), "asn": d.get("as"),
                        "network": d.get("asname"), "source": name}
        except Exception:
            continue
    return {"ip": ip, "error": "geolocation unavailable"}


def geolocate_all(ips):
    return [geolocate_ip(ip) for ip in ips]


# --- OFAC sanctions screening ----------------------------------------------

# Screening uses a lightweight, purpose-built extract of every crypto
# address on OFAC's SDN list (maintained from the official SDN data). These
# are a few hundred KB of JSON, not the hundreds of MB of the full SDN XML.
# Per-asset files cover each chain; we load the ones relevant to what we
# screen (XRP addresses here) plus the common chains.
OFAC_SETS = {
    "XRP": "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_XRP.json",
    "ETH": "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_ETH.json",
    "BTC": "https://raw.githubusercontent.com/0xB10C/ofac-sanctioned-digital-currency-addresses/lists/sanctioned_addresses_BTC.json",
}
# Full SDN XML as a last-resort fallback (large; slow).
OFAC_FALLBACK = "https://sanctionslistservice.ofac.treas.gov/api/PublicationPreview/exports/SDN_ADVANCED.XML"

_ofac_cache = {"addresses": None, "source": None}


def _load_ofac():
    """Return (set_of_sanctioned_addresses, source_label) or (None, None)."""
    if _ofac_cache["addresses"] is not None:
        return _ofac_cache["addresses"], _ofac_cache["source"]
    addrs = set()
    ok = False
    for asset, url in OFAC_SETS.items():
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=10, context=_ssl_ctx()) as r:
                for a in json.loads(r.read().decode("utf-8", "replace")):
                    addrs.add(a)
            ok = True
        except Exception:
            continue
    if ok:
        _ofac_cache["addresses"], _ofac_cache["source"] = addrs, "OFAC SDN (crypto-address extract)"
        return addrs, _ofac_cache["source"]
    _ofac_cache["addresses"], _ofac_cache["source"] = None, None
    return None, None


def screen_addresses(addresses):
    """Return {address: on_sanctions_list bool or None if unavailable}."""
    sdn, _ = _load_ofac()
    if sdn is None:
        return {a: None for a in addresses}
    return {a: (a in sdn) for a in addresses}


def sanctions_summary(addresses):
    res = screen_addresses(addresses)
    hits = [a for a, v in res.items() if v]
    unavailable = any(v is None for v in res.values())
    return {"checked": len(addresses), "sanctioned": hits,
            "list_unavailable": unavailable, "source": _ofac_cache.get("source"),
            "note": "OFAC SDN list could not be fetched; screening skipped." if unavailable
            else ("MATCH: address is on the OFAC SDN list." if hits else "No addresses on the OFAC SDN list.")}
