"""Offline tests for the Threat Map's Bluesky / Mastodon sources. All posts are synthetic.

Run: python test_social_offline.py
"""
import json
import os
import shutil
import sys
import tempfile
import urllib.error

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from threatmap import feeds, social  # noqa: E402

ok = fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1
    else:
        fail += 1
        print("FAIL:", name)


from datetime import datetime, timedelta, timezone
_now = datetime.now(timezone.utc)


def ago(h):
    return (_now - timedelta(hours=h)).strftime("%Y-%m-%dT%H:%M:%SZ")


LONG = "North Korean hackers are running fake Zoom calls to drain crypto wallets " + "and steal more " * 20
BSKY = {"feed": [
    {"post": {"uri": "at://did:plc:abc/app.bsky.feed.post/3kaaa", "indexedAt": ago(2),
              "record": {"text": LONG, "createdAt": ago(3)}}},
    {"post": {"uri": "at://did:plc:abc/app.bsky.feed.post/3kbbb", "record": {"text": "Lovely sunset at the beach today", "createdAt": ago(4)}}},
    {"reason": {"$type": "app.bsky.feed.defs#reasonRepost"},
     "post": {"uri": "at://did:plc:zzz/app.bsky.feed.post/3kccc", "record": {"text": "Reposted ransomware news", "createdAt": ago(5)}}},
]}
MASTO_ACCT = {"id": "42"}
MASTO = [
    {"uri": "https://infosec.exchange/users/x/statuses/1", "url": "https://infosec.exchange/@x/1", "visibility": "public",
     "created_at": ago(1), "content": "<p>New <b>ClickFix</b> wave hits Brazilian users &amp; banks</p>"},
    {"uri": "https://infosec.exchange/users/x/statuses/2", "url": "https://infosec.exchange/@x/2", "visibility": "unlisted",
     "created_at": ago(1), "content": "<p>private-ish malware note</p>"},
    {"uri": "https://infosec.exchange/users/x/statuses/3", "url": "https://infosec.exchange/@x/3", "visibility": "public",
     "created_at": ago(1), "content": "<p>Coffee time</p>"},
]
calls = []


def fake(url):
    calls.append(url)
    if "public.api.bsky.app" in url:
        if "malwarebytes" in url:
            raise urllib.error.HTTPError(url, 403, "Forbidden", {}, None)
        return json.dumps(BSKY).encode()
    if "/accounts/lookup" in url:
        return json.dumps(MASTO_ACCT).encode()
    if "/statuses" in url:
        return json.dumps(MASTO).encode()
    raise AssertionError("unexpected url " + url)


tmp = tempfile.mkdtemp()
old = os.getcwd()
os.chdir(tmp)
try:
    # ---------- Bluesky ----------
    items, errs, tried = social.fetch("bsky", fake, log=lambda *_: None)
    nb = sum(1 for a, _ in social.accounts() if a.startswith("bsky:"))
    check("tried every bluesky account", tried == nb)
    check("one failing account reported, others kept", len(errs) == 1 and "refused (HTTP 403)" in errs[0] and items)
    check("reposts and off-topic posts dropped", all("sunset" not in i["title"] and "Reposted" not in i["title"] for i in items))
    one = items[0]
    excerpt = one["title"].split(": ", 1)[1]
    check("excerpt capped at 120 characters (+...)", len(excerpt) <= social.EXCERPT + 3 and excerpt.endswith("..."))
    check("credited to author", one["title"].startswith("Catalin Cimpanu:") or one["title"].split(":")[0] in {n.split(" (")[0] for _, n in social.ACCOUNTS})
    check("bsky link", one["url"].startswith("https://bsky.app/profile/") and one["url"].endswith("/post/3kaaa"))
    check("country from text", one["cc"] == "KP" and one["layer"] == "social" and one["src"] == "bluesky")
    check("time normalised", one["time"] == ago(3))

    # ---------- Mastodon ----------
    mi, merrs, mtried = social.fetch("masto", fake, log=lambda *_: None)
    nm = sum(1 for a, _ in social.accounts() if a.startswith("masto:"))
    check("tried every mastodon account", mtried == nm and not merrs)
    check("public, on-topic only (one per account)", len(mi) == nm)
    check("html stripped and unescaped", "ClickFix wave hits Brazilian users & banks" in mi[0]["title"] and "<" not in mi[0]["title"])
    check("mastodon country + family", mi[0]["cc"] == "BR" and mi[0]["family"] == "ClickFix")
    check("ids distinct per account", len({i["id"] for i in mi}) == nm)

    # ---------- config: add / remove ----------
    with open("config.json", "w") as f:
        json.dump({"threatmap_social": {"remove": ["bsky:404media.co"], "add": ["bsky:example.org", "masto:alice@infosec.exchange",
                                                                                "http://evil", "bsky:"]}}, f)
    acc = [a for a, _ in social.accounts()]
    check("remove works", "bsky:404media.co" not in acc)
    check("valid adds accepted", "bsky:example.org" in acc and "masto:alice@infosec.exchange" in acc)
    check("junk adds refused", "http://evil" not in acc and "bsky:" not in acc)
    os.remove("config.json")
    check("impostor ZachXBT account not followed", not any("zachxbt" in a.lower() for a, _ in social.ACCOUNTS))

    # ---------- through refresh(): statuses ----------
    from shield import abusech
    from threatmap import geo
    real_key = abusech.key
    abusech.key = lambda: None
    geo.GET = lambda url: b"x"
    feeds.GET = lambda url, h, d: fake(url) if ("bsky" in url or "/api/v1/" in url) else b"<rss></rss>"
    try:
        feeds.refresh(force=True, log=lambda *_: None)
        st = json.load(open(feeds.STATE))
        check("bluesky ok despite one account failing", st["bluesky"]["status"] == "ok" and st["bluesky"]["count"] >= 1)
        check("mastodon ok", st["mastodon"]["status"] == "ok" and st["mastodon"]["count"] == nm)
        check("social items stored", any(i["layer"] == "social" for i in feeds.load_items()))

        def down(url, h, d):
            if "bsky" in url:
                raise urllib.error.HTTPError(url, 503, "down", {}, None)
            return fake(url) if "/api/v1/" in url else b"<rss></rss>"
        feeds.GET = down
        feeds.refresh(force=True, log=lambda *_: None)
        st = json.load(open(feeds.STATE))
        check("all accounts failing = error, labelled", st["bluesky"]["status"] == "error" and "HTTP 503" in (st["bluesky"]["error"] or ""))
    finally:
        abusech.key = real_key
        feeds.GET = None
        geo.GET = None
    check("layer listed", feeds.LAYERS.get("social") == "Researchers' posts")
    s = feeds.summary(24 * 30)
    check("summary includes social", s["layers"].get("social", 0) >= 1)
finally:
    os.chdir(old)
    shutil.rmtree(tmp, ignore_errors=True)

print(f"social: {ok} passed, {fail} failed")
sys.exit(1 if fail else 0)
