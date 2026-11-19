"""Desk page /relay (Settings > Phone app): set up your Worker, pair the phone, see the connection, unpair.

Only works at the computer: relay/policy.py refuses this page to the phone itself.
"""
import html

from relay import pairing

e = lambda s: html.escape(str(s if s is not None else ""), quote=True)

CSS = ("body{font:20px/1.5 'Segoe UI',Arial,sans-serif;max-width:980px;margin:0 auto;padding:0 16px 40px;color:#111}"
       "h1{font-size:30px}h2{font-size:24px;margin:26px 0 8px}.card{border:2px solid #ddd;border-radius:12px;padding:14px 16px;margin:12px 0}"
       ".stop{background:#fdecee;border-color:#b00020}.caution{background:#fff8e6;border-color:#f2b01e}.ok{background:#e9f7ef;border-color:#2e7d32}"
       ".info{background:#eef3fb;border-color:#9bb}button{font-size:19px;padding:9px 18px;border-radius:10px;cursor:pointer}"
       ".go{background:#0b6b3a;color:#fff;border:0}input[type=text]{font-size:19px;padding:9px;width:100%;box-sizing:border-box}"
       "code{background:#f2f2f2;padding:2px 6px;border-radius:5px;word-break:break-all}.small{font-size:16px;color:#444}"
       ".step{font-weight:700;color:#0b6b3a}.qr{background:#fff;display:inline-block;padding:12px;border-radius:12px}")


def _state():
    try:
        from relay import client
        return client.STATE
    except Exception:
        return {}


def _qr_svg(text):
    try:
        import segno
        return segno.make(text, error="m").svg_inline(scale=7)
    except Exception:
        return "<p class=small>(The QR picture needs the segno package; use the code below instead.)</p>"


def page(msg="", level="info", qr=None):
    r = pairing.load()
    out = [f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
           f"<title>Phone app</title><style>{CSS}</style></head><body><h1>Phone app</h1>",
           "<p>The <b>ScamHunter Threat Desk</b> app shows this Desk on your phone, at home or away. It reaches this computer through "
           "<b>your own</b> Cloudflare Worker (free). Everything is encrypted between this Desk and your phone; the Worker only passes "
           "along scrambled data it can't read. Nothing on this computer is opened to the internet.</p>"]
    if msg:
        out.append(f"<div class='card {level}'>{e(msg)}</div>")
    if qr:
        out.append("<div class='card caution'><h2 style='margin-top:0'>Scan this with the phone app</h2>"
                   "<p>Open <b>ScamHunter Threat Desk</b> on your phone, tap <b>Pair with my Desk</b>, and point the camera here.</p>"
                   f"<div class=qr>{_qr_svg(qr)}</div>"
                   "<p><b>Anyone who scans this can open your Desk.</b> Don't photograph it, share it or leave it on screen. "
                   "It's shown only now; to pair again later, make a new one (the old one stops working).</p>"
                   f"<details><summary>Can't scan? Paste this code into the app instead</summary><p><code>{e(qr)}</code></p></details></div>")
    # step 1: the Worker
    h = pairing.health() if r.get("worker") else None
    out.append("<h2><span class=step>1</span> Your Worker</h2>")
    if r.get("worker"):
        out.append(f"<div class='card {'ok' if h and h['reachable'] else 'caution'}'>Worker: <code>{e(r['worker'])}</code> &middot; "
                   + ("answering" if h and h["reachable"] else f"not answering ({e(h and h['status'])})") + "</div>")
    else:
        node = pairing.wrangler()
        out.append("<div class=card><p>Put the relay on your Cloudflare account (the free plan is enough). "
                   + ("Click the button: if Cloudflare asks you to log in, a browser window opens for you to approve it.</p>"
                      "<form method=post><input type=hidden name=do value=deploy><button class=go>Deploy my Worker</button>"
                      " <span class=small>Takes about a minute.</span></form>" if node else
                      "This needs Node.js (free, from nodejs.org). Install it, then come back to this page.</p>")
                   + "<details><summary>Or do it yourself</summary><p>In PowerShell:</p><pre><code>cd \"" + e(pairing.WORKER_DIR)
                   + "\"\nnpx --yes wrangler@4 deploy</code></pre><p>Then paste the address it prints (ending in <code>.workers.dev</code>):</p>"
                     "<form method=post><input type=hidden name=do value=worker><input type=text name=url placeholder='https://scamhunter-relay.yourname.workers.dev'>"
                     "<button>Use this Worker</button></form></details></div>")
    # step 2: the key
    out.append("<h2><span class=step>2</span> The Worker's key</h2>")
    if not r.get("worker"):
        out.append("<p class=small>After step 1.</p>")
    elif h and h.get("configured"):
        out.append("<div class='card ok'>The Worker has this Desk's key (only this Desk can set up pairings on it).</div>")
    else:
        out.append("<div class=card><p>This gives your Worker a secret key so that only this Desk can set up pairings on it. "
                   "The key goes straight from the Desk to Cloudflare; it isn't shown or saved anywhere else.</p>"
                   "<form method=post><input type=hidden name=do value=adminkey><button class=go>Give the Worker its key</button></form></div>")
    # step 3: pair
    st = _state()
    out.append("<h2><span class=step>3</span> Your phone</h2>")
    if pairing.paired():
        conn = st.get("connected")
        out.append(f"<div class='card {'ok' if conn else 'caution'}'><b>Paired</b> on {e(r.get('paired_at'))}. "
                   + (f"Connected to your Worker since {e(st.get('since'))}." if conn else
                      "Not connected to the Worker right now" + (f" ({e(st.get('last_error'))})" if st.get("last_error") else "") + "; it retries by itself.")
                   + f"<div class=small>Phone requests this session: {st.get('requests', 0)} (refused: {st.get('refused', 0)})"
                   + (f", last at {e(st.get('last_request'))}" if st.get("last_request") else "") + "</div>"
                   "<form method=post style='margin-top:10px'><input type=hidden name=do value=pair><button>Pair a different phone</button></form>"
                   "<form method=post style='margin-top:10px'><input type=hidden name=do value=unpair><button>Unpair: stop the phone's access now</button>"
                   " <span class=small>Use this right away if the phone is lost or stolen.</span></form></div>")
    elif h and h.get("configured"):
        out.append("<div class=card><p>Install the <b>ScamHunter Threat Desk</b> app on your phone, then:</p>"
                   "<form method=post><input type=hidden name=do value=pair><button class=go>Pair my phone</button></form></div>")
    else:
        out.append("<p class=small>After steps 1 and 2.</p>")
    out.append("<h2>What the phone can and can't do</h2><div class='card info small'>From the phone you can read everything on the Desk "
               "and run checks (messages, numbers, addresses, links, lookups). Settings, keys, updates, share copies, the secrets scan "
               "and this page only work here at the computer.</div></body></html>")
    return "".join(out)


def post(form):
    def g(k):
        v = form.get(k) or ""
        return (v[0] if v else "") if isinstance(v, list) else v
    do = g("do")
    if do == "worker":
        why = pairing.set_worker(g("url"))
        return page(why or "Worker found.", "caution" if why else "ok")
    if do == "deploy":
        url, why = pairing.deploy_worker()
        if why:
            return page(why, "caution")
        why = pairing.set_worker(url)
        return page(why or f"Your Worker is live at {url}.", "caution" if why else "ok")
    if do == "adminkey":
        why = pairing.install_admin_key()
        return page(why or "Done. The Worker now has this Desk's key.", "caution" if why else "ok")
    if do == "pair":
        qr, why = pairing.pair()
        return page(why, "caution") if why else page("", qr=qr)
    if do == "unpair":
        pairing.unpair()
        return page("Unpaired. The phone can't reach the Desk any more.", "ok")
    return page()
