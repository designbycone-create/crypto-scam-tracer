"""Posts from trusted security researchers and newsrooms on Bluesky and Mastodon (free, public, read-only).

Only named accounts are followed (a curated list below, which you can change in config.json under
"threatmap_social": {"add": [...], "remove": [...]}). There is no keyword search of the whole network:
Bluesky's search and Mastodon's hashtag feeds refuse anonymous access, and that refusal is respected.

Each post keeps its author, link, time and at most the first 120 characters of its text, so the Desk
never republishes anyone's post; click through to read it. Off-topic posts are dropped by a keyword
filter. Nothing is posted, liked or followed: no account is needed.

Providers are pluggable: X can be added later as one more provider with its own key and a monthly
spending cap (X charges per post read), without changing anything else.
"""
import html
import json
import re
import urllib.parse
from datetime import datetime, timezone

# account ids: "bsky:<handle>" or "masto:<user>@<server>". Checked Nov 18, 2026 (active, real owner).
ACCOUNTS = [
    ("masto:briankrebs@infosec.exchange", "Brian Krebs (Krebs on Security)"),
    ("masto:GossiTheDog@cyberplace.social", "Kevin Beaumont (security researcher)"),
    ("masto:wdormann@infosec.exchange", "Will Dormann (vulnerability analyst)"),
    ("masto:josephcox@infosec.exchange", "Joseph Cox (404 Media, scams and surveillance)"),
    ("bsky:campuscodi.risky.biz", "Catalin Cimpanu (Risky Business News)"),
    ("bsky:malwarebytes.com", "Malwarebytes Labs"),
    ("bsky:404media.co", "404 Media"),
]
EXCERPT = 120
TOPIC = re.compile(r"scam|phish|malware|ransom|hack|breach|exploit|vulnerab|cve-\d|crypto|bitcoin|wallet|fraud|stealer|botnet|"
                   r"zero[- ]?day|0day|clickfix|north korea|dprk|lazarus|attack|leak|spyware|backdoor|patch|cisa|ic3|fbi|deepfake|"
                   r"impersonat|extort|drainer|seed phrase|supply[- ]chain|npm|pypi", re.I)


def accounts():
    """The curated list, with the user's own additions / removals from config.json."""
    try:
        with open("config.json", encoding="utf-8-sig") as f:
            cfg = json.load(f).get("threatmap_social") or {}
    except Exception:
        cfg = {}
    drop = {a.lower() for a in cfg.get("remove", [])}
    out = [(a, n) for a, n in ACCOUNTS if a.lower() not in drop]
    for a in cfg.get("add", []):
        if isinstance(a, str) and re.fullmatch(r"(bsky:[\w.-]+|masto:\w+@[\w.-]+)", a) and a.lower() not in {x.lower() for x, _ in out}:
            out.append((a, a.split(":", 1)[1]))
    return out


def _text(s):
    s = re.sub(r"<br\s*/?>|</p>", " ", s or "")
    s = html.unescape(re.sub(r"<[^>]+>", "", s))
    return re.sub(r"\s+", " ", s).strip()


def _excerpt(s):
    s = _text(s)
    return s if len(s) <= EXCERPT else s[:EXCERPT].rsplit(" ", 1)[0] + "..."


def _iso(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def fetch_bsky(handle, get):
    q = urllib.parse.quote(handle)
    d = json.loads(get(f"https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed?actor={q}&limit=30&filter=posts_no_replies"))
    out = []
    for it in d.get("feed") or []:
        if it.get("reason"):                       # a repost of someone else
            continue
        p = it.get("post") or {}
        rec = p.get("record") or {}
        rkey = (p.get("uri") or "").rsplit("/", 1)[-1]
        if not rkey:
            continue
        out.append({"id": p.get("uri"), "text": rec.get("text") or "", "time": _iso(rec.get("createdAt") or p.get("indexedAt") or ""),
                    "url": f"https://bsky.app/profile/{handle}/post/{rkey}"})
    return out


def fetch_masto(acct, get):
    user, host = acct.split("@", 1)
    a = json.loads(get(f"https://{host}/api/v1/accounts/lookup?acct={urllib.parse.quote(user)}"))
    d = json.loads(get(f"https://{host}/api/v1/accounts/{a['id']}/statuses?limit=30&exclude_replies=true&exclude_reblogs=true"))
    return [{"id": s.get("uri") or s.get("url"), "text": s.get("content") or "", "time": _iso(s.get("created_at") or ""),
             "url": s.get("url") or ""} for s in d if s.get("visibility", "public") == "public"]


PROVIDERS = {"bsky": fetch_bsky, "masto": fetch_masto}       # later: "x" with a key and a spending cap


def fetch(provider, get, log=print):
    """Items from one provider's accounts. Returns (items, errors, tried) -- one failing account never stops the rest."""
    from threatmap import feeds, geo
    items, errors, tried = [], [], 0
    for acct, name in accounts():
        kind, ident = acct.split(":", 1)
        if kind != provider:
            continue
        tried += 1
        try:
            posts = PROVIDERS[kind](ident, get)
        except Exception as ex:
            code = getattr(ex, "code", None)
            errors.append(f"{ident}: " + (f"refused (HTTP {code})" if code in (401, 403) else f"HTTP {code}" if code else str(ex)[:60]))
            continue
        for p in posts:
            body = _text(p["text"])
            if not p["time"] or not p["url"].startswith("https://") or not TOPIC.search(body):
                continue
            ccs = geo.countries_in(body)
            items.append({"id": feeds._id(acct, p["id"]), "src": "bluesky" if kind == "bsky" else "mastodon", "layer": "social",
                          "title": f"{name.split(' (')[0]}: {_excerpt(p['text'])}", "detail": name, "url": p["url"], "time": p["time"],
                          "cc": ccs[0] if ccs else None, "ccs": ccs[:4], "family": feeds._family(body)})
    return items, errors, tried
