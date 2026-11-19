"""Where in the world: country codes for headlines (by the countries they name) and for internet
addresses (DB-IP's free country database, CC BY 4.0, https://db-ip.com, downloaded monthly and
used only on this computer).
"""
import array
import bisect
import gzip
import ipaddress
import json
import os
import re
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DBIP_FILE = "dbip-country-lite.csv.gz"
DBIP_URL = "https://download.db-ip.com/free/dbip-country-lite-{ym}.csv.gz"
UA = {"User-Agent": "ScamHunter-ThreatDesk/1.0 (free scam-victim tool; github.com/designbycone-create/crypto-scam-tracer)"}

with open(os.path.join(HERE, "country_names.json"), encoding="utf-8") as _f:
    NAMES = json.load(_f)                       # ISO2 -> [names]

# words used in headlines that the official names miss (adjectives, short forms)
EXTRA = {"US": ["U.S.", "USA", "United States", "American", "Americans", "FBI", "CISA"], "GB": ["UK", "U.K.", "Britain", "British", "England", "Scotland", "Wales"],
         "RU": ["Russia", "Russian", "Kremlin", "Moscow"], "CN": ["China", "Chinese", "Beijing"], "KP": ["North Korea", "North Korean", "Pyongyang", "DPRK", "Lazarus"],
         "KR": ["South Korea", "South Korean", "Seoul"], "IR": ["Iran", "Iranian", "Tehran"], "UA": ["Ukraine", "Ukrainian", "Kyiv"], "IL": ["Israel", "Israeli"],
         "DE": ["German", "Germany", "Berlin"], "FR": ["French", "France", "Paris"], "IN": ["Indian", "India"], "JP": ["Japanese", "Japan"], "BR": ["Brazilian", "Brazil"],
         "CA": ["Canadian", "Canada"], "AU": ["Australian", "Australia"], "NL": ["Dutch", "Netherlands"], "ES": ["Spanish", "Spain"], "IT": ["Italian", "Italy"],
         "VN": ["Vietnam", "Vietnamese"], "TW": ["Taiwan", "Taiwanese"], "MX": ["Mexican", "Mexico"], "NG": ["Nigerian", "Nigeria"], "PK": ["Pakistani", "Pakistan"],
         "TR": ["Turkish", "Turkey", "Türkiye"], "PL": ["Polish", "Poland"], "RO": ["Romanian", "Romania"], "SG": ["Singapore"], "PH": ["Philippines", "Filipino"],
         "KH": ["Cambodia", "Cambodian"], "MM": ["Myanmar", "Burmese"], "TH": ["Thai", "Thailand"], "AE": ["UAE", "Emirates", "Dubai"], "SE": ["Swedish", "Sweden"],
         "CH": ["Swiss", "Switzerland"], "BY": ["Belarus", "Belarusian"], "GE": ["Georgian"], "IE": ["Irish", "Ireland"], "ZA": ["South African", "South Africa"]}


def _build():
    pats = []
    for cc, names in NAMES.items():
        for n in set(names) | set(EXTRA.get(cc, [])):
            if len(n) >= 3 or n in ("UK", "US", "UAE"):
                pats.append((n, cc))
    for cc, names in EXTRA.items():
        for n in names:
            pats.append((n, cc))
    pats = sorted(set(pats), key=lambda p: -len(p[0]))          # longest first: "North Korea" before "Korea"
    return [(re.compile(r"(?<![\w.])" + re.escape(n) + r"(?![\w])"), cc, n) for n, cc in pats]


_PATS = _build()


def countries_in(text):
    """ISO2 codes of countries a headline names, in order of first mention (case-sensitive: names are capitalised)."""
    found, taken = [], []
    for rx, cc, n in _PATS:
        for m in rx.finditer(text or ""):
            if any(a < m.end() and m.start() < b for a, b in taken):
                continue                                       # part of a longer name already matched
            if n == "Georgia" and re.search(r"Georgia(n)? (state|county|law|governor|resident)", text[m.start():m.end() + 12]):
                continue
            taken.append((m.start(), m.end()))
            found.append((m.start(), cc))
    out = []
    for _, cc in sorted(found):
        if cc not in out:
            out.append(cc)
    return out


# ---------------------------------------------------------------- IP -> country ----

_db = {"starts": None, "ends": None, "cc": None, "loaded": None}
GET = None          # test hook: f(url) -> bytes


def _dbip_path(data_dir="."):
    return os.path.join(data_dir, DBIP_FILE)


def refresh_dbip(data_dir=".", max_age_days=35, log=print):
    """Download DB-IP's free country file if it's missing or over a month old (about 5 MB)."""
    p = _dbip_path(data_dir)
    if os.path.exists(p) and time.time() - os.path.getmtime(p) < max_age_days * 86400:
        return False
    import nettls
    for back in (0, 1):                               # this month's file, or last month's early in a month
        t = time.gmtime(time.time() - back * 28 * 86400)
        url = DBIP_URL.format(ym=f"{t.tm_year}-{t.tm_mon:02d}")
        try:
            raw = GET(url) if GET else urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120,
                                                              context=nettls.context()).read()
            if raw[:2] != b"\x1f\x8b":
                raise ValueError("not a gzip file")
            with open(p + ".tmp", "wb") as f:
                f.write(raw)
            os.replace(p + ".tmp", p)
            _db["loaded"] = None
            log(f"threat map: DB-IP country database updated ({len(raw) // 1024} KB)")
            return True
        except Exception as ex:
            log(f"threat map: DB-IP download failed ({url.rsplit('/', 1)[-1]}): {str(ex)[:80]}")
    return False


def _load(data_dir="."):
    p = _dbip_path(data_dir)
    try:
        m = os.path.getmtime(p)
    except OSError:
        return False
    if _db["loaded"] == m:
        return True
    starts, ends, cc = array.array("L"), array.array("L"), bytearray()
    with gzip.open(p, "rt", encoding="utf-8") as f:
        for line in f:
            a, b, c = line.rstrip().split(",")
            if ":" in a:
                break                                  # IPv4 rows come first; IPv6 isn't used
            starts.append(int(ipaddress.IPv4Address(a)))
            ends.append(int(ipaddress.IPv4Address(b)))
            cc += (c[:2] if len(c) == 2 else "ZZ").encode()
    _db.update(starts=starts, ends=ends, cc=cc, loaded=m)
    return True


def country_of_ip(ip, data_dir="."):
    """ISO2 for an IPv4 address, or None (no database yet, IPv6, private, or unknown)."""
    try:
        n = int(ipaddress.IPv4Address(ip.split(":")[0] if ip.count(":") == 1 else ip))
    except ValueError:
        return None
    if not _load(data_dir):
        return None
    i = bisect.bisect_right(_db["starts"], n) - 1
    if i < 0 or n > _db["ends"][i]:
        return None
    c = _db["cc"][2 * i:2 * i + 2].decode()
    return None if c == "ZZ" else c
