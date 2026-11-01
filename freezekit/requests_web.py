"""Desk page /requests: build the exchange request kits and stablecoin freeze packets for the officer."""
import html
import os
import threading

from . import requests as rq

JOB = {"running": False, "made": [], "err": ""}
CSS = """<style>body{font:15px/1.55 system-ui,sans-serif;background:#0f1115;color:#e8eaf0;margin:0}.w{max-width:860px;margin:0 auto;
padding:22px 16px}a{color:#5aa2ff}.card{background:#151922;border:1px solid #262b36;border-radius:12px;padding:16px 18px;margin:14px 0}
.btn{display:inline-block;background:#3b6cff;color:#fff;border:0;border-radius:8px;padding:9px 14px;font-size:15px;cursor:pointer;
text-decoration:none;margin:4px 6px 4px 0}.mut{color:#9aa1b2}.ok{color:#86efac}.bad{color:#ff8a7a}</style>"""


def _shell(body, refresh=False):
    r = "<meta http-equiv=refresh content=4>" if refresh else ""
    return (f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>{r}"
            f"<title>Officer packets</title>{CSS}<div class=w><p><a href='/'>&larr; Desk</a></p>{body}</div>")


def _targets():
    try:
        from . import kit
        _root, targets, _iss, _ops = kit.collect()
        return [t for t in targets.values() if t.get("deposits")]
    except Exception:
        return []


def page():
    e = html.escape
    if JOB["running"]:
        return _shell("<h1>Building packets&hellip;</h1><p class=mut>Reading current stablecoin balances from the "
                      "blockchain. This page refreshes on its own.</p>", refresh=True)
    out = ["<h1>&#128193; Officer packets</h1>",
           "<p class=mut>Ready-to-file drafts for the police officer or attorney handling your case. Exchanges and "
           "stablecoin companies freeze accounts and release records only on law-enforcement or court request, so "
           "these are written for that person. ScamHunter never sends them.</p>"]
    if JOB["err"]:
        out.append(f"<div class=card><span class=bad>{e(JOB['err'])}</span></div>")
    if JOB["made"]:
        links = "".join(f"<li><a href='/kit/requests/{e(os.path.basename(p))}' target=_blank>{e(os.path.basename(p))}</a>"
                        f"{(' &middot; ' + e(n)) if n else ''}</li>" for p, n in JOB["made"])
        out.append(f"<div class=card><b class=ok>Ready</b><ul>{links}</ul><span class=mut>Saved in "
                   f"freeze_kits/requests on this computer.</span></div>")
    ts = _targets()
    rows = "".join(f"<li>{e((t.get('entry') or {}).get('name') or t['id'])}: {len(t['deposits'])} deposit(s)"
                   f"{' (on your funds&#39; path)' if t.get('yours') else ''}</li>" for t in ts)
    out.append(f"<div class=card><h3>Exchange request kits</h3><p>One PDF and one CSV per exchange: where the officer "
               f"files (only channels verified on the exchange's own page), the deposit facts, a draft preservation-and-"
               f"hold request, and the list of records to ask for.</p><ul>{rows or '<li>No exchange deposits found yet.</li>'}</ul>"
               "<form method=post action='/requests'><input type=hidden name=do value=exchanges>"
               f"<button class=btn {'disabled' if not ts else ''}>Build exchange kits</button></form></div>")
    out.append("<div class=card><h3>Stablecoin freeze packets</h3><p>Checks every wallet in the scam network for USDT and "
               "USDC right now, and builds a packet listing what each one holds and what to ask the issuer.</p>"
               "<form method=post action='/requests' style='display:inline'><input type=hidden name=do value=tether>"
               "<button class=btn>Tether (USDT) packet</button></form>"
               "<form method=post action='/requests' style='display:inline'><input type=hidden name=do value=circle>"
               "<button class=btn>Circle (USDC) packet</button></form></div>")
    return _shell("".join(out))


def post(form):
    do = form.get("do")
    if JOB["running"]:
        return page()

    def run():
        JOB.update(running=True, made=[], err="")
        try:
            if do == "exchanges":
                for t in _targets():
                    pdf, csvp = rq.exchange_kit(t)
                    JOB["made"] += [(pdf, (t.get("entry") or {}).get("name")), (csvp, "address and transaction list")]
            elif do in ("tether", "circle"):
                p, held = rq.stablecoin_packet(do)
                tok = rq.ISSUER[do]["token"]
                JOB["made"].append((p, f"{len(held)} address(es) holding {tok}" if held else f"no {tok} held right now"))
        except Exception as ex:
            JOB["err"] = str(ex)[:300]
        finally:
            JOB["running"] = False
    threading.Thread(target=run, daemon=True).start()
    return _shell("<h1>Building&hellip;</h1>", refresh=True).replace("content=4", "content=3;url=/requests")
