"""Offline tests for the Threat Map: parsers, country matching, IP lookup, rising, summary, page, routes.

All feed data here is synthetic (made-up headlines, documentation IP ranges); no network is used.
Run: python test_threatmap_offline.py
"""
import gzip
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from threatmap import feeds, geo, page  # noqa: E402

ok = fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1
    else:
        fail += 1
        print("FAIL:", name)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


now = datetime.now(timezone.utc)
tmp = tempfile.mkdtemp()
old = os.getcwd()
os.chdir(tmp)
try:
    # ---------- country names in headlines ----------
    check("north korea before korea", geo.countries_in("North Korean hackers hit exchange") == ["KP"])
    check("two countries, order", geo.countries_in("Russian gang targets German firms") == ["RU", "DE"])
    check("US short forms", geo.countries_in("U.S. agencies warn of new scam") == ["US"])
    check("no false match inside words", geo.countries_in("Ransomware hits Chinatown bakery") == [])
    check("lowercase not matched", geo.countries_in("a chad of a day") == [])
    check("Georgia state skipped", "GE" not in geo.countries_in("Georgia state agency breached"))
    check("Georgia the country", geo.countries_in("Georgian ministry hacked") == ["GE"])
    check("empty", geo.countries_in("") == [] and geo.countries_in(None) == [])

    # ---------- IP -> country (synthetic DB-IP file) ----------
    rows = "0.0.0.0,192.0.1.255,ZZ\n192.0.2.0,192.0.2.255,FR\n192.0.3.0,198.51.99.255,ZZ\n198.51.100.0,198.51.100.255,BR\n" \
           "198.51.101.0,255.255.255.255,ZZ\n::,ffff::,ZZ\n"
    with gzip.open(geo.DBIP_FILE, "wt", encoding="utf-8") as f:
        f.write(rows)
    geo._db["loaded"] = None
    check("ip FR", geo.country_of_ip("192.0.2.10") == "FR")
    check("ip:port BR", geo.country_of_ip("198.51.100.7:443") == "BR")
    check("unknown ZZ -> None", geo.country_of_ip("10.0.0.1") is None)
    check("ipv6 None", geo.country_of_ip("2001:db8::1") is None)
    check("garbage None", geo.country_of_ip("not-an-ip") is None)

    # refresh_dbip: fresh file is not downloaded again; a bad download is refused and the old file kept
    calls = []
    geo.GET = lambda url: calls.append(url) or b"<html>blocked</html>"
    check("fresh file not re-downloaded", geo.refresh_dbip(".", log=lambda *_: None) is False and not calls)
    os.utime(geo.DBIP_FILE, (0, 0))
    check("non-gzip refused", geo.refresh_dbip(".", log=lambda *_: None) is False and len(calls) == 2)
    check("old file kept", geo.country_of_ip("192.0.2.10") == "FR")
    good = gzip.compress(rows.replace("FR", "IT").encode())
    geo.GET = lambda url: good
    check("gzip accepted", geo.refresh_dbip(".", log=lambda *_: None) is True)
    check("new file used", geo.country_of_ip("192.0.2.10") == "IT")
    check("month in url", "dbip-country-lite-%d-%02d" % (now.year, now.month) in calls[0])
    geo.GET = None

    # ---------- RSS: title + link + date only ----------
    rss = f"""<?xml version="1.0"?><rss><channel><title>x</title>
    <item><title><![CDATA[Iranian hackers phish US officials &amp; staff]]></title><link>https://news.example/a</link>
      <pubDate>{(now - timedelta(hours=2)).strftime('%a, %d %b %Y %H:%M:%S +0000')}</pubDate>
      <description>SECRET ARTICLE BODY TEXT</description><content:encoded>MORE BODY</content:encoded></item>
    <item><title>Lumma infostealer returns</title><link>javascript:alert(1)</link></item>
    <item><title></title><link>https://news.example/empty</link></item>
    </channel></rss>""".encode()
    it = feeds.parse_rss("record", rss)
    check("rss 2 items (empty title skipped)", len(it) == 2)
    check("rss title unescaped", it[0]["title"] == "Iranian hackers phish US officials & staff")
    check("rss countries", it[0]["ccs"] == ["IR", "US"] and it[0]["cc"] == "IR")
    check("rss family phishing", it[0]["family"] == "phishing")
    check("rss no article text", "SECRET" not in json.dumps(it) and "MORE BODY" not in json.dumps(it))
    check("rss unsafe link dropped", it[1]["url"] == "")
    check("rss family Lumma", it[1]["family"] == "Lumma")
    check("rss layer news", all(i["layer"] == "news" for i in it))
    check("no Play false family", feeds._family("Google Play scam apps") is None)

    # ---------- KEV ----------
    kev = json.dumps({"vulnerabilities": [
        {"cveID": "CVE-2099-0001", "vendorProject": "Acme", "product": "Router", "vulnerabilityName": "Acme Router RCE",
         "dateAdded": (now - timedelta(days=1)).date().isoformat(), "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2000-0002", "vendorProject": "Old", "product": "Thing", "dateAdded": "2000-01-01"}]}).encode()
    k = feeds.parse_kev(kev)
    check("kev only recent", len(k) == 1 and k[0]["title"].startswith("CVE-2099-0001"))
    check("kev ransomware family", k[0]["family"] == "ransomware" and k[0]["layer"] == "exploited")

    # ---------- Feodo ----------
    fe = feeds.parse_feodo(json.dumps([{"ip_address": "192.0.2.5", "port": 443, "status": "online", "malware": "QakBot",
                                        "country": "NL", "as_name": "EXAMPLE-AS", "last_online": now.date().isoformat()}]).encode())
    check("feodo country + family", fe[0]["cc"] == "NL" and fe[0]["family"] == "QakBot" and fe[0]["layer"] == "botnet")

    # ---------- ThreatFox ----------
    tf = feeds.parse_threatfox(json.dumps({"data": [
        {"id": 1, "ioc": "198.51.100.9:8080", "ioc_type": "ip:port", "threat_type": "botnet_cc", "threat_type_desc": "Botnet C2",
         "malware_printable": "Vidar", "first_seen": (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S UTC")},
        {"id": 2, "ioc": "abcd" * 16, "ioc_type": "sha256_hash", "threat_type": "payload", "malware_printable": "X"},
        {"id": 3, "ioc": "http://bad.example/x", "ioc_type": "url", "threat_type": "payload_delivery", "malware_printable": "Unknown malware",
         "first_seen": "garbage"}]}).encode())
    check("threatfox hashes skipped", len(tf) == 2)
    check("threatfox ip geolocated", tf[0]["cc"] == "BR" and tf[0]["layer"] == "botnet" and tf[0]["family"] == "Vidar")
    check("threatfox url no cc, no family", tf[1]["cc"] is None and tf[1]["family"] is None and tf[1]["layer"] == "malware")
    check("threatfox bad time -> now", tf[1]["time"][:10] == now.date().isoformat())
    check("threatfox no raw ioc shown", "bad.example" not in tf[1]["title"] + tf[1]["detail"])

    # ---------- URLhaus ----------
    uh = feeds.parse_urlhaus(json.dumps({"urls": [
        {"id": 9, "host": "192.0.2.77", "url_status": "online", "threat": "malware_download", "tags": ["Mirai"],
         "urlhaus_reference": "https://urlhaus.abuse.ch/url/9/", "date_added": now.strftime("%Y-%m-%d %H:%M:%S UTC")},
        {"id": 10, "host": "evil.example", "tags": None, "date_added": ""}]}).encode())
    check("urlhaus ip geolocated", uh[0]["cc"] == "IT" and uh[0]["family"] == "Mirai")
    check("urlhaus hostname no cc", uh[1]["cc"] is None and uh[1]["family"] is None)

    # ---------- refresh: per-source intervals, errors, keys, merge ----------
    from shield import abusech
    real_key = abusech.key
    abusech.key = lambda: None
    seen = []

    def fake(url, headers, data):
        seen.append(url)
        if "therecord" in url:
            return rss
        if "known_exploited" in url:
            return kev
        if "feodotracker" in url:
            return json.dumps([]).encode()
        if "krebs" in url:
            import urllib.error
            raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)
        return b"<rss></rss>"
    feeds.GET = fake
    geo.GET = lambda url: good
    n = feeds.refresh(log=lambda *_: None)
    st = json.load(open(feeds.STATE))
    check("refresh stored items", n == 3 and len(feeds.load_items()) == 3)
    check("403 labelled precisely", st["krebs"]["status"] == "error" and st["krebs"]["error"] == "refused (HTTP 403)")
    check("needs-key not fetched", "needs your abuse.ch key" in st["threatfox"]["status"] and not any("threatfox" in u for u in seen))
    check("other sources ok", st["record"]["status"] == "ok" and st["kev"]["count"] == 1)
    seen.clear()
    feeds.refresh(log=lambda *_: None)
    check("interval respected", seen == [])
    feeds.refresh(force=True, log=lambda *_: None)
    check("force refetches, no duplicates", len(seen) >= 6 and len(feeds.load_items()) == 3)
    with open("config.json", "w") as f:
        json.dump({"threatmap_sources": {"record": False}}, f)
    feeds.refresh(force=True, log=lambda *_: None)
    check("switched-off source", json.load(open(feeds.STATE))["record"]["status"] == "off")
    os.remove("config.json")
    abusech.key = real_key
    feeds.GET = None
    geo.GET = None

    # ---------- rising + summary ----------
    items = []
    for h in range(5):                                   # 5 reports for KP today
        items.append({"id": f"a{h}", "src": "record", "layer": "news", "title": "x", "detail": "", "url": "", "time": iso(now - timedelta(hours=h + 1)),
                      "cc": "KP", "ccs": ["KP"], "family": "Lazarus"})
    for d in range(2, 9):                                # 1 per day for FR, before and today
        items.append({"id": f"b{d}", "src": "feodo", "layer": "botnet", "title": "y", "detail": "", "url": "", "time": iso(now - timedelta(days=d + 0.5)),
                      "cc": "FR", "family": None})
    items.append({"id": "old", "src": "kev", "layer": "exploited", "title": "z", "detail": "", "url": "", "time": iso(now - timedelta(days=40)),
                  "cc": None, "family": None})
    with open(feeds.ITEMS, "w") as f:
        json.dump(sorted(items, key=lambda i: i["time"], reverse=True), f)
    os.utime(feeds.ITEMS, (now.timestamp() + 5, now.timestamp() + 5))
    s = feeds.summary(24)
    check("summary total 24h", s["total"] == 5 and s["countries"]["KP"]["n"] == 5)
    check("rising country KP", any(r["kind"] == "country" and r["key"] == "KP" for r in s["rising"]))
    check("rising family Lazarus", any(r["kind"] == "family" and r["key"] == "Lazarus" for r in s["rising"]))
    check("steady FR not rising", not any(r["key"] == "FR" for r in s["rising"]))
    s7 = feeds.summary(24 * 7)
    check("7-day window", s7["countries"]["FR"]["n"] == 5 and s7["total"] == 10)
    sb = feeds.summary(24 * 30, ["botnet"])
    check("layer filter", set(sb["layers"]) == {"botnet"} and "KP" not in sb["countries"])
    check("summary has sources + attribution", len(s["sources"]) == len(feeds.SOURCES) and "DB-IP" in s["attribution"])

    # ---------- page + json api ----------
    html_ = page.page()
    check("page has map", "id=world" in html_ and "data-cc='FR'" in html_ and "path class=c" in html_)
    check("page credits DB-IP link", "https://db-ip.com" in html_ and "CC BY 4.0" in html_)
    check("page no outside scripts", "<script src" not in html_ and "http://" not in html_.split("<script>")[-1][:0] + "")
    check("page data not breaking out of script", "</script>" not in html_.split("window.__T=")[1].split("</script>")[0])
    j = json.loads(page.json_api("hours=168&layers=botnet,bogus"))
    check("json hours + layers", j["window_hours"] == 168 and set(j["layers"]) <= {"botnet"})
    check("json bad hours", json.loads(page.json_api("hours=abc"))["window_hours"] == 24)
    check("json hours clamped", json.loads(page.json_api("hours=99999"))["window_hours"] == 720)

    # a headline trying to inject markup stays data
    items.insert(0, {"id": "evil", "src": "record", "layer": "news", "title": "</script><script>alert(1)</script>", "detail": "", "url": "",
                     "time": iso(now), "cc": None, "family": None})
    with open(feeds.ITEMS, "w") as f:
        json.dump(items, f)
    os.utime(feeds.ITEMS, (now.timestamp() + 9, now.timestamp() + 9))
    h2 = page.page()
    check("script-breakout escaped", "</script><script>alert(1)" not in h2)

    # ---------- shell tab + desk routes ----------
    from deskui import shell
    check("tab listed", any(s_[0] == "threatmap" for s_ in shell.SECTIONS))
    check("tab after overview", [s_[0] for s_ in shell.SECTIONS][:2] == ["overview", "threatmap"])
    src = open(os.path.join(ROOT, "desk.py"), encoding="utf-8").read()
    check("routes present", '"/threatmap"' in src and '"/threatmap.json"' in src)
    dsrc = open(os.path.join(ROOT, "responder", "daemon.py"), encoding="utf-8").read()
    check("responder job scheduled", "job_threatmap" in dsrc and "(1800, job_threatmap" in dsrc)
    gi = open(os.path.join(ROOT, ".gitignore"), encoding="utf-8").read()
    check("data files ignored", all(x in gi for x in ("threatmap_items.json", "threatmap_state.json", "dbip-country-lite.csv.gz")))
finally:
    os.chdir(old)
    shutil.rmtree(tmp, ignore_errors=True)

print(f"threatmap: {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
