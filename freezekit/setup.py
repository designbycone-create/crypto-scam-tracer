"""First-run setup wizard (served by the Desk at /setup).

A new user never edits JSON. They:
  1. paste the transaction (hash or explorer link) where they sent the funds;
     the wizard reads it from the ledger and fills in the scam wallet, their own
     wallet, the amount and the time -- or they paste the scam wallet directly;
  2. add their name / email / phone and any report numbers (all optional; used
     only in the drafts they choose to send);
  3. turn on alerts: an ntfy topic is generated for them, Telegram is optional.
Saving writes config.json + victim.json and restarts the watchers.
"""
import html
import json
import os
import re
import secrets
from datetime import datetime, timezone

e = lambda s: html.escape(str(s if s is not None else ""), quote=True)
RIPPLE_EPOCH = 946684800


def _j(p):
    try:
        with open(p, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return {}


def needed():
    cfg = _j("config.json")
    return not (cfg.get("scam_wallet") or cfg.get("watched_wallets"))


def lookup_tx(text, _post=None):
    """Hash or explorer link -> facts about the payment."""
    m = re.search(r"\b([0-9A-Fa-f]{64})\b", text or "")
    if not m:
        return {"ok": False, "error": "That doesn't contain a transaction hash (64 letters/numbers)."}
    h = m.group(1).upper()
    from scam_investigator.attribution import _rpc
    try:
        r = _rpc("tx", {"transaction": h, "binary": False}, _post)
    except Exception as ex:
        return {"ok": False, "error": f"Couldn't reach the XRP Ledger ({ex}). Try again in a minute."}
    if r.get("error") or r.get("status") == "error":
        return {"ok": False, "error": "Transaction not found on the XRP Ledger. Check the hash (this wizard covers XRP Ledger payments)."}
    tx = r.get("tx_json") or r
    meta = r.get("meta") or {}
    if tx.get("TransactionType") != "Payment":
        return {"ok": False, "error": f"That transaction is a {tx.get('TransactionType')}, not a payment."}
    amt = meta.get("delivered_amount", tx.get("Amount") or tx.get("DeliverMax"))
    amount = f"{int(amt) / 1e6:,.6f}".rstrip("0").rstrip(".") + " XRP" if isinstance(amt, str) else \
        f"{amt.get('value')} {amt.get('currency')}" if isinstance(amt, dict) else "?"
    date = tx.get("date") or r.get("date")
    when = datetime.fromtimestamp(date + RIPPLE_EPOCH, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if date else ""
    out = {"ok": True, "hash": h, "from": tx.get("Account"), "to": tx.get("Destination"),
           "tag": tx.get("DestinationTag"), "amount": amount, "time": when,
           "result": meta.get("TransactionResult")}
    if out["tag"] is not None:
        out["warning"] = ("This payment used a destination tag, which usually means it went INTO an exchange account. "
                          "If you paid the scammer from an exchange, paste the scammer's address in the box below instead.")
    return out


def _valid_xrpl(a):
    try:
        from responder.addresses import is_xrpl
        return is_xrpl(a)
    except Exception:
        return bool(re.fullmatch(r"r[1-9A-HJ-NP-Za-km-z]{24,34}", a or ""))


def save(form):
    scam = (form.get("scam_wallet") or "").strip()
    if not _valid_xrpl(scam):
        return False, "The scam wallet address isn't a valid XRP Ledger address."
    cfg = _j("config.json")
    topic = (form.get("ntfy_topic") or "").strip() or cfg.get("ntfy_topic") or f"scamhunter-{secrets.token_hex(5)}"
    cfg.update({"scam_wallet": scam,
                "watched_wallets": {**(cfg.get("watched_wallets") or {}), scam: form.get("scam_label") or "scam wallet (from setup)"},
                "ntfy_topic": topic, "min_xrp": cfg.get("min_xrp", 25), "victim_file": "victim.json"})
    victim = _j("victim.json")
    for k in ("name", "email", "phone", "victim_wallet", "tx_hash", "amount", "theft_time", "ic3_id", "scam_type"):
        v = (form.get(k) or "").strip()
        if v:
            victim[k] = v
    victim["scam_wallet"] = scam
    victim.setdefault("country", "US")
    victim.setdefault("scam_type", "a cryptocurrency scam")
    reps = [r.strip() for r in (form.get("reports") or "").splitlines() if r.strip()]
    if reps:
        victim["reports"] = reps
    for path, data in (("config.json", cfg), ("victim.json", victim)):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    return True, topic


CSS = """:root{--bg:#070a12;--card:rgba(17,23,38,.8);--line:rgba(255,255,255,.09);--fg:#e9edf7;--mut:#8a93ab;--acc:#3da9ff;--red:#ff4d6d;--ok:#2ee6a8}
*{box-sizing:border-box}body{margin:0;min-height:100vh;color:var(--fg);font:15px/1.55 Inter,system-ui,sans-serif;
background:radial-gradient(900px 600px at 80% -10%,rgba(61,169,255,.16),transparent 60%),radial-gradient(800px 600px at -10% 110%,rgba(255,46,99,.12),transparent 60%),var(--bg)}
.wrap{max-width:760px;margin:0 auto;padding:36px 18px 80px}
.brand{display:flex;gap:12px;align-items:center;font-weight:800;font-size:20px}
.logo{width:34px;height:34px;border-radius:11px;background:conic-gradient(from 210deg,#ff2e63,#b46cff,#3da9ff,#2ee6a8,#ff2e63);display:grid;place-items:center}
.logo::after{content:"";width:14px;height:14px;border-radius:50%;background:var(--bg)}
h1{font-size:30px;line-height:1.2;margin:26px 0 8px} .lead{color:var(--mut);margin:0 0 22px}
.pledge{border:1px solid rgba(46,230,168,.35);background:rgba(46,230,168,.07);border-radius:14px;padding:12px 14px;font-size:13.5px;margin:0 0 22px}
.step{background:var(--card);border:1px solid var(--line);border-radius:18px;padding:20px;margin:16px 0;backdrop-filter:blur(14px)}
.step h2{margin:0 0 4px;font-size:18px;display:flex;gap:10px;align-items:center}
.num{width:26px;height:26px;border-radius:50%;display:inline-grid;place-items:center;font-size:13px;font-weight:800;background:linear-gradient(135deg,#3da9ff,#b46cff)}
.hint{color:var(--mut);font-size:13.5px;margin:0 0 12px}
label{display:block;font-size:12.5px;font-weight:600;color:#c8cfe3;margin:12px 0 5px}
input,textarea{width:100%;background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.14);color:var(--fg);border-radius:11px;padding:11px 12px;font:14px Inter,system-ui,sans-serif;outline:none}
input:focus,textarea:focus{border-color:rgba(61,169,255,.7);box-shadow:0 0 0 3px rgba(61,169,255,.15)}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:13px}
.row{display:grid;grid-template-columns:1fr 1fr;gap:12px} @media(max-width:620px){.row{grid-template-columns:1fr}}
.btn{display:inline-flex;align-items:center;gap:8px;white-space:nowrap;border:0;border-radius:12px;padding:11px 16px;font:700 14px Inter,sans-serif;cursor:pointer;color:#fff;
background:linear-gradient(135deg,#3da9ff,#7c6cff);box-shadow:0 8px 24px rgba(61,169,255,.3);text-decoration:none}
.btn.big{width:100%;justify-content:center;padding:15px;font-size:16px;background:linear-gradient(135deg,#ff4d6d,#ff2e63);box-shadow:0 10px 30px rgba(255,46,99,.35)}
.btn.ghost{background:transparent;border:1px solid rgba(255,255,255,.18);box-shadow:none}
.found{display:none;margin-top:12px;border:1px solid rgba(61,169,255,.35);background:rgba(61,169,255,.07);border-radius:12px;padding:12px;font-size:13.5px}
.found b{color:#fff} .warn{color:#ffb020} .err{color:var(--red)} .mut{color:var(--mut)} a{color:#7cc4ff}
.or{display:flex;align-items:center;gap:10px;color:var(--mut);font-size:12px;margin:14px 0 0}.or::before,.or::after{content:"";flex:1;height:1px;background:var(--line)}
.topic{display:flex;gap:8px;align-items:center}"""


def page(msg="", prefill=None):
    cfg, vic = _j("config.json"), _j("victim.json")
    pf = {**vic, **(prefill or {})}
    topic = cfg.get("ntfy_topic") or f"scamhunter-{secrets.token_hex(5)}"
    first = needed()
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Set up ScamHunter Desk</title><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800&display=swap" rel=stylesheet>
<style>{CSS}</style></head><body><div class=wrap>
<div class=brand><div class=logo></div>ScamHunter Desk</div>
<h1>{'Let&rsquo;s start tracking your case' if first else 'Case setup'}</h1>
<p class=lead>Three short steps. Everything stays on this computer. You can change any of it later.</p>
<div class=pledge><b>Free for victims, always.</b> This tool never asks for money, a seed phrase or a &ldquo;recovery fee&rdquo;, never contacts anyone for you,
and never promises recovery. Never type your seed phrase or private key anywhere &mdash; this wizard doesn't need it.</div>
{f'<p class=err><b>{e(msg)}</b></p>' if msg else ''}
<form method=post action="/setup" id=f>

<div class=step><h2><span class=num>1</span>Where did your crypto go?</h2>
<p class=hint>Paste the transaction where you sent funds to the scammer &mdash; the hash, or the link from your wallet or an explorer
(XRPScan, Bithomp, livenet.xrpl.org). We read it from the public XRP Ledger and fill in the rest.</p>
<div class=topic><input id=txq class=mono placeholder="e.g. 1F7DA9E9...D390  or  https://xrpscan.com/tx/..." value="{e(pf.get('tx_hash',''))}">
<button type=button class=btn onclick=look()>Look it up</button></div>
<div id=found class=found></div>
<div class=or>or enter the scammer's wallet directly</div>
<label>Scammer's wallet address (XRP Ledger, starts with r)</label>
<input name=scam_wallet id=scam class=mono required value="{e(pf.get('scam_wallet') or cfg.get('scam_wallet',''))}" placeholder="r...">
<input type=hidden name=tx_hash id=h value="{e(pf.get('tx_hash',''))}"><input type=hidden name=victim_wallet id=vw value="{e(pf.get('victim_wallet',''))}">
<div class=row><div><label>Amount you lost</label><input name=amount id=amt value="{e(pf.get('amount',''))}" placeholder="500 XRP"></div>
<div><label>When</label><input name=theft_time id=when value="{e(pf.get('theft_time',''))}" placeholder="2026-10-27 15:39 UTC"></div></div>
<label>What kind of scam was it?</label><input name=scam_type value="{e(pf.get('scam_type',''))}" placeholder="fake giveaway, fake exchange, romance / investment scam...">
</div>

<div class=step><h2><span class=num>2</span>About you <span class=mut style="font-weight:500;font-size:13px">(optional)</span></h2>
<p class=hint>Only used inside the freeze requests and officer packet <i>you</i> choose to send. Nothing is sent anywhere by this tool.</p>
<div class=row><div><label>Your name</label><input name=name value="{e(pf.get('name',''))}"></div>
<div><label>Email</label><input name=email type=email value="{e(pf.get('email',''))}"></div></div>
<div class=row><div><label>Phone</label><input name=phone value="{e(pf.get('phone',''))}"></div>
<div><label>FBI IC3 complaint number</label><input name=ic3_id value="{e(pf.get('ic3_id',''))}" placeholder="file at ic3.gov"></div></div>
<label>Other report links / numbers (one per line: Chainabuse, police report...)</label>
<textarea name=reports rows=2>{e(chr(10).join(pf.get('reports', [])))}</textarea>
<p class=hint style="margin-top:10px">Haven't reported yet? <a href="https://www.ic3.gov" target=_blank>IC3</a> (US),
<a href="https://www.chainabuse.com/report" target=_blank>Chainabuse</a>, and your local police. The Desk builds the reports for you after setup.</p>
</div>

<div class=step><h2><span class=num>3</span>Alerts on your phone</h2>
<p class=hint>Install the free <a href="https://ntfy.sh" target=_blank>ntfy</a> app and subscribe to this private topic. You'll get an alert the moment
the scammer moves money &mdash; especially when it hits an exchange, which is when a freeze is possible.</p>
<div class=topic><input name=ntfy_topic id=topic class=mono value="{e(topic)}">
<a class="btn ghost" href="https://ntfy.sh/{e(topic)}" target=_blank id=tlink>Open</a></div>
<p class=hint style="margin-top:10px">Want a second channel (recommended)? After setup, run <span class=mono>python telegram_setup.py</span> to connect Telegram in about 2 minutes.</p>
</div>

<button class="btn big">Start tracking</button>
<p class=mut style="text-align:center;font-size:12.5px;margin-top:10px">The watchers start immediately. The first map of the scam network appears within a few minutes.</p>
</form></div>
<script>
document.getElementById('topic').addEventListener('input',e=>document.getElementById('tlink').href='https://ntfy.sh/'+encodeURIComponent(e.target.value));
async function look(){{const q=document.getElementById('txq').value, box=document.getElementById('found');box.style.display='block';box.innerHTML='Looking it up on the XRP Ledger&hellip;';
 try{{const r=await (await fetch('/setup/lookup',{{method:'POST',headers:{{'Content-Type':'application/x-www-form-urlencoded'}},body:'q='+encodeURIComponent(q)}})).json();
 if(!r.ok){{box.innerHTML='<span class=err>'+r.error+'</span>';return}}
 box.innerHTML=`Found it. <b>${{r.amount}}</b> sent on <b>${{r.time}}</b><br>from your wallet <span class=mono>${{r.from}}</span><br>to <span class=mono><b>${{r.to}}</b></span> &larr; the scammer's wallet`
  +(r.warning?`<br><span class=warn>${{r.warning}}</span>`:'')+(r.result&&r.result!=='tesSUCCESS'?`<br><span class=warn>Note: this transaction failed (${{r.result}}).</span>`:'');
 document.getElementById('scam').value=r.to;document.getElementById('h').value=r.hash;document.getElementById('vw').value=r.from;
 document.getElementById('amt').value=r.amount;document.getElementById('when').value=r.time;}}
 catch(x){{box.innerHTML='<span class=err>Lookup failed: '+x+'</span>'}}}}
</script></body></html>"""


def done_page(topic):
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<meta http-equiv=refresh content="8;url=/"><title>Tracking started</title><style>{CSS}</style></head><body><div class=wrap>
<div class=brand><div class=logo></div>ScamHunter Desk</div><h1>&#10003; Tracking started</h1>
<p class=lead>The watchers are restarting with your case. In a few minutes the Desk will show where your funds are, the network behind the scam,
and freeze kits for any exchange the money reaches.</p>
<div class=step><h2><span class=num>!</span>Do this now on your phone</h2><p>Open the ntfy app &rarr; <b>Subscribe to topic</b> &rarr; <span class=mono>{e(topic)}</span></p></div>
<p><a class=btn href="/">Open the Desk</a></p></div></body></html>"""
