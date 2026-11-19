"""Overview dashboard and the section landing pages (Crypto & Wallets, Phone & Messages,
Online Defense, Settings). Everything is drawn in the page from /live.json, which refreshes
every 20 seconds -- no outside scripts, maps or fonts, so the Desk works the same offline.
"""
import html
import json
import os

from deskui import data, shell

HERE = os.path.dirname(os.path.abspath(__file__))
e = lambda s: html.escape(str(s if s is not None else ""), quote=True)


def _map():
    with open(os.path.join(HERE, "us_states.json"), encoding="utf-8") as f:
        return json.load(f)


CSS = """
:root{--bg:#060a12;--pan:#0b1322;--pan2:#0f1a2c;--line:#1c2a40;--fg:#e8eef9;--mut:#8ea3c2;--cy:#22d3ee;--red:#ff5470;--amb:#ffb020;--grn:#34d399}
*{box-sizing:border-box} html{background:#060a12}
body{margin:0;background:radial-gradient(1200px 600px at 50% -200px,#0d2140 0,var(--bg) 70%) fixed;color:var(--fg);
 font:18px/1.5 'Segoe UI',system-ui,Arial,sans-serif}
main{max-width:1320px;margin:0 auto;padding:0 18px 40px}
h1{font-size:28px;margin:6px 0 2px} .lead{color:var(--mut);margin:0 0 16px}
.lbl{font:600 12px/1.2 ui-monospace,Consolas,monospace;letter-spacing:.14em;text-transform:uppercase;color:var(--cy)}
.pan{background:linear-gradient(180deg,var(--pan2),var(--pan));border:1px solid var(--line);border-radius:16px;padding:16px}
.pan h2{font-size:21px;margin:4px 0 10px}
.grid{display:grid;gap:14px}
.g3{grid-template-columns:repeat(auto-fit,minmax(300px,1fr))}
.gmain{grid-template-columns:minmax(260px,320px) 1fr minmax(260px,340px)}
@media(max-width:1000px){.gmain{grid-template-columns:1fr}}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:12px 0}
.kpi{background:var(--pan);border:1px solid var(--line);border-radius:14px;padding:12px 14px}
.kpi b{display:block;font-size:30px;line-height:1.1} .kpi span{color:var(--mut);font-size:15px}
.status{display:flex;flex-wrap:wrap;align-items:center;gap:10px 18px;padding:10px 14px;border-radius:12px;border:1px solid var(--line);
 background:var(--pan);margin:10px 0 14px;font-size:16px}
.pulse{width:11px;height:11px;border-radius:50%;background:var(--grn);box-shadow:0 0 0 0 rgba(52,211,153,.7);animation:p 2s infinite}
.pulse.bad{background:var(--red);box-shadow:0 0 0 0 rgba(255,84,112,.7)}
@keyframes p{70%{box-shadow:0 0 0 10px rgba(0,0,0,0)}100%{box-shadow:0 0 0 0 rgba(0,0,0,0)}}
.tick{display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--line);padding:8px 0;overflow:hidden}
.tick .lbl{flex:0 0 190px}
.tick .rail{overflow:hidden;flex:1;mask-image:linear-gradient(90deg,transparent,#000 4%,#000 96%,transparent)}
.tick .run{display:flex;gap:10px;width:max-content;animation:run 60s linear infinite}
.tick:hover .run{animation-play-state:paused}
@keyframes run{to{transform:translateX(-50%)}}
@media(max-width:700px){.tick{flex-direction:column;align-items:stretch}.tick .lbl{flex:none}body{font-size:17px}h1{font-size:25px}}
.chip{display:inline-flex;flex-direction:column;min-width:210px;max-width:320px;padding:7px 12px;border-radius:10px;border:1px solid var(--line);
 background:var(--pan);color:var(--fg);text-decoration:none;font-size:15px}
.chip small{color:var(--mut);font:12px ui-monospace,Consolas,monospace;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.chip.stop{border-color:#6b1f2e;box-shadow:inset 3px 0 0 var(--red)} .chip.caution{box-shadow:inset 3px 0 0 var(--amb)}
.chip.ok,.chip.info{box-shadow:inset 3px 0 0 var(--cy)}
.seg{display:inline-flex;border:1px solid var(--line);border-radius:12px;overflow:hidden}
.seg button{background:transparent;color:var(--mut);border:0;padding:8px 14px;font:600 15px 'Segoe UI',system-ui;cursor:pointer}
.seg button.on{background:var(--cy);color:#04111c}
.rank{display:flex;align-items:center;gap:10px;padding:8px 10px;border:1px solid var(--line);border-radius:12px;margin:6px 0;background:var(--pan)}
.rank i{font:700 13px ui-monospace,Consolas,monospace;color:var(--cy);width:26px;font-style:normal}
.rank .nm{flex:1} .rank .nm small{display:block;color:var(--mut);font-size:13px}
.pct{font:700 13px ui-monospace,Consolas,monospace;color:var(--grn);background:#0b2a22;border-radius:999px;padding:3px 9px}
#usmap path{fill:#12223a;stroke:#2b4466;stroke-width:.8;cursor:pointer;transition:fill .2s}
#usmap path:hover{stroke:#fff;stroke-width:1.6}
.tip{position:fixed;pointer-events:none;background:#020611ee;border:1px solid var(--cy);border-radius:10px;padding:8px 12px;font-size:15px;display:none;z-index:50}
.bars .bar{display:grid;grid-template-columns:minmax(120px,1.2fr) 2fr auto;gap:8px;align-items:center;margin:7px 0;font-size:14px}
.bars .bar div{height:14px;border-radius:7px;background:linear-gradient(90deg,var(--red),var(--amb))}
.bars .bar em{font-style:normal;color:var(--mut);font:13px ui-monospace,Consolas,monospace}
.cols{display:flex;align-items:flex-end;gap:3px;height:90px;margin-top:8px}
.cols div{flex:1;background:var(--cy);opacity:.75;border-radius:3px 3px 0 0;min-height:2px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}
.tile{display:block;text-decoration:none;color:var(--fg);background:var(--pan);border:1px solid var(--line);border-radius:14px;padding:14px 16px;transition:.15s}
.tile:hover{border-color:var(--cy);transform:translateY(-2px)} .tile b{font-size:19px} .tile p{margin:4px 0 0;color:var(--mut);font-size:15px}
.grp{margin:20px 0 8px}
.sec{display:block;text-decoration:none;color:var(--fg)} .sec:hover{border-color:var(--cy)}
.sec .row{display:flex;gap:18px;flex-wrap:wrap;margin-top:8px} .sec .row div b{display:block;font-size:24px} .sec .row div span{color:var(--mut);font-size:14px}
.btn{display:inline-block;background:var(--cy);color:#04111c;font-weight:700;text-decoration:none;padding:8px 16px;border-radius:10px;margin-top:10px}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
.filters input[type=search]{background:var(--pan);border:1px solid var(--line);color:var(--fg);border-radius:10px;padding:8px 12px;font-size:16px;min-width:220px}
table.feed{width:100%;border-collapse:collapse;font-size:15px}
table.feed th{text-align:left;font:600 12px ui-monospace,Consolas,monospace;letter-spacing:.12em;text-transform:uppercase;color:var(--red);
 background:#2a0f18;padding:10px}
table.feed td{border-bottom:1px solid var(--line);padding:10px;vertical-align:top}
table.feed tr{cursor:pointer} table.feed tr:hover td{background:#0f1a2c}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px}
.lv-stop{background:var(--red)} .lv-caution{background:var(--amb)} .lv-info,.lv-ok{background:var(--cy)}
.mut{color:var(--mut)} .small{font-size:14px}
.empty{color:var(--mut);padding:10px 0}
"""

JS = r"""
const $=s=>document.querySelector(s), esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const SEC={crypto:'Crypto & Wallets',phone:'Phone & Messages',defense:'Online Defense',settings:'Settings'};
let D=window.__D, days=30, fsec=window.__SEC||'all', fwarn=false, fq='';
const num=n=>Number(n||0).toLocaleString();
function chips(list){ if(!list.length) return '<span class=empty>Nothing yet.</span>';
  const one=list.map(x=>`<a class="chip ${esc(x.lvl)}" href="${esc(x.href||'#')}"><b>${esc(x.title)}</b><small>${esc(x.t)} &middot; ${esc(x.detail)}</small></a>`).join('');
  return `<div class=run>${one}${one}</div>`; }
function ticks(){ const el=$('#ticks'); if(!el) return;
  const f=D.feed, row=(id,label,list)=>`<div class=tick><span class=lbl>${label}</span><div class=rail>${chips(list.slice(0,14))}</div></div>`;
  const ph=(D.phone.top||[]).map(t=>({lvl:t.reports>=10?'stop':'caution',title:t.number,detail:`${t.reports} reports · ${t.subject}`,t:'last '+(t.last||''),href:'/numbercheck?number='+t.raw}));
  el.innerHTML=row('c','&#9670; Crypto &middot; live',f.filter(x=>x.sec==='crypto'))
    +row('p','&#9670; Most-reported numbers',ph)
    +row('d','&#9670; Defense &middot; latest',f.filter(x=>x.sec==='defense'||x.sec==='settings')); }
function status(){ const el=$('#status'); if(!el) return; const s=D.services, ok=s.total>0&&!s.down.length;
  if(!s.total){ el.innerHTML=`<span class="pulse bad"></span><b>WATCHER STATUS UNKNOWN</b><span class=mut>the Desk couldn't read its status file; open My case to check</span>`; return; }
  el.innerHTML=`<span class="pulse ${ok?'':'bad'}"></span><b>${ok?'ALL SYSTEMS LIVE':'ATTENTION: '+esc(s.down.join(', '))+' down'}</b>`
   +`<span class=mut>${s.alive}/${s.total} watchers running</span><span class=mut>updated ${esc(D.generated.slice(11,16))}</span>`
   +`<span class=mut>FTC list: ${num(D.phone.numbers)} numbers, ${D.phone.days} days</span>`; }
function heat(v,max){ if(!v) return '#12223a'; const t=Math.sqrt(v/max); const h=t<.5?200-310*t:45-90*(t-.5); return `hsl(${(h+360)%360},${60+30*t}%,${24+28*t}%)`; }
function map(){ const svg=$('#usmap'); if(!svg) return; const st=D.phone.states||{}, max=Math.max(1,...Object.values(st));
  svg.querySelectorAll('path').forEach(p=>{ const v=st[p.dataset.n]||0; p.style.fill=heat(v,max); p.dataset.v=v; });
  const ranked=Object.entries(st).sort((a,b)=>b[1]-a[1]).slice(0,5), tot=Object.values(st).reduce((a,b)=>a+b,0)||1;
  const el=$('#topstates'); if(el) el.innerHTML=ranked.length?ranked.map(([n,v],i)=>`<div class=rank><i>0${i+1}</i><div class=nm>${esc(n)}<small>${num(v)} reports</small></div><span class=pct>${Math.round(100*v/tot)}%</span></div>`).join('')
     :'<div class=empty>State data starts with the next FTC download.</div>';
  const note=$('#mapnote'); if(note) note.textContent=D.phone.days_with_states<D.phone.days?`States are known for ${D.phone.days_with_states} of ${D.phone.days} days (the FTC data before that was saved without them).`:''; }
function bars(){ const el=$('#subjects'); if(!el) return; const s=D.phone.subjects||[], max=Math.max(1,...s.map(x=>x[1]));
  el.innerHTML=s.length?s.map(([k,v])=>`<div class=bar><span>${esc(k.length>46?k.slice(0,44)+'…':k)}</span><div style="width:${Math.max(3,100*v/max)}%"></div><em>${num(v)}</em></div>`).join(''):'<div class=empty>No reports yet.</div>';
  const c=$('#perday'); if(c){ const se=D.phone.series||[], m=Math.max(1,...se.map(x=>x[1])); c.innerHTML=se.map(([d,v])=>`<div title="${esc(d)}: ${num(v)} reports" style="height:${100*v/m}%"></div>`).join(''); } }
function latest(){ const el=$('#latest'); if(!el) return; const x=D.feed.find(f=>f.lvl==='stop'&&(fsec==='all'||f.sec===fsec));
  el.innerHTML=x?`<span class=lbl style="color:var(--red)">Latest warning</span><h2>${esc(x.title)}</h2><div class=small>&#9201; ${esc(x.t)}</div><div class="small mut">${esc(x.detail)}</div><a class=btn href="${esc(x.href)}">Open</a>`
   :`<span class=lbl>Latest warning</span><h2>None right now</h2><div class="small mut">Warnings from every part of the Desk show up here first.</div>`; }
function sections(){ const el=$('#sections'); if(!el) return; const c=D.crypto, p=D.phone, d=D.defense;
  const card=(h,t,lead,cells)=>`<a class="pan sec" href="${h}"><span class=lbl>${t}</span><h2>${lead}</h2><div class=row>${cells.map(([v,l])=>`<div><b>${v}</b><span>${l}</span></div>`).join('')}</div></a>`;
  el.innerHTML=card('/crypto','Crypto &amp; Wallets',c.yours?'Your funds reached an exchange: act now':'Your case and your wallets',[[num(c.wallets_mapped),'wallets mapped'],[num(c.cashout_points),'cash-out points'],[num(c.checks),'addresses checked'],[num(c.campaigns.length),'attack campaigns']])
   +card('/phone','Phone &amp; Messages','Scam calls and texts',[[num(p.numbers),'reported numbers'],[num(p.reports),'FTC reports'],[p.days,'days of data'],[num(p.msg_checks),'messages checked']])
   +card('/defense','Online Defense','Browser, websites, network, AI agents',[[num(d.ext_blocks),'browser blocks'],[num(d.site_alerts)+'/'+num(d.sites),'site alerts'],[num(d.agent_pending),'agent requests waiting'],[d.ext_paired?'on':'off','extension']]); }
function kpis(){ const el=$('#kpis'); if(!el) return; const k=window.__KPI(D); el.innerHTML=k.map(([v,l])=>`<div class=kpi><b>${v}</b><span>${l}</span></div>`).join(''); }
let shown=25;
function feed(){ const el=$('#feedrows'); if(!el) return; const q=fq.toLowerCase();
  const all=D.feed.filter(x=>(fsec==='all'||x.sec===fsec)&&(!fwarn||x.lvl==='stop'||x.lvl==='caution')&&(!q||(x.title+' '+x.detail).toLowerCase().includes(q)));
  const rows=all.slice(0,shown), more=$('#more'); if(more){ more.style.display=all.length>shown?'inline-block':'none'; more.textContent=`Show more (${all.length-shown})`; }
  el.innerHTML=rows.length?rows.map(x=>`<tr data-h="${esc(x.href)}"><td><span class="dot lv-${esc(x.lvl)}"></span>${esc(x.title)}<div class="small mut">${esc(x.detail)}</div></td><td class=small>${esc(x.t)}</td><td class=small>${esc(SEC[x.sec]||x.sec)}</td></tr>`).join('')
   :'<tr><td colspan=3 class=empty>Nothing matches.</td></tr>'; }
function draw(){ status(); ticks(); map(); bars(); latest(); sections(); kpis(); feed(); }
function seg(id,cb){ const el=$(id); if(!el) return; el.addEventListener('click',ev=>{ const b=ev.target.closest('button'); if(!b) return;
  el.querySelectorAll('button').forEach(x=>x.classList.toggle('on',x===b)); cb(b.dataset.v); }); }
seg('#range',v=>{days=+v; refresh();});
seg('#fsec',v=>{fsec=v; feed(); latest();});
const w=$('#fwarn'); if(w) w.addEventListener('change',()=>{fwarn=w.checked; feed();});
const qq=$('#fq'); if(qq) qq.addEventListener('input',()=>{fq=qq.value; feed();});
const mo=$('#more'); if(mo) mo.addEventListener('click',()=>{shown+=25; feed();});
const fr=$('#feedrows'); if(fr) fr.addEventListener('click',ev=>{ const r=ev.target.closest('tr[data-h]'); if(r&&r.dataset.h) location.href=r.dataset.h; });
const tip=$('#tip'), svg=$('#usmap');
if(svg){ svg.addEventListener('mousemove',ev=>{ const p=ev.target.closest('path'); if(!p){tip.style.display='none';return;}
    tip.innerHTML=`<b>${esc(p.dataset.n)}</b><br>${num(p.dataset.v)} scam-call reports`; tip.style.display='block';
    tip.style.left=(ev.clientX+14)+'px'; tip.style.top=(ev.clientY+14)+'px'; });
  svg.addEventListener('mouseleave',()=>tip.style.display='none'); }
async function refresh(){ try{ const r=await fetch('/live.json?days='+days,{cache:'no-store'}); if(r.ok){ D=await r.json(); draw(); } }catch(_){} }
draw(); setInterval(refresh,20000);
"""


def _page(title, body, kpi_js="d=>[]", sec="all"):
    d = data.live()
    blob = json.dumps(d).replace("</", "<\\/")
    return (f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{e(title)} - ScamHunter Threat Desk</title><style>{CSS}</style></head><body><main>{body}</main><div class=tip id=tip></div>"
            f"<script>window.__D={blob};window.__SEC={json.dumps(sec)};window.__KPI={kpi_js};</script><script>{JS}</script></body></html>")


def _usmap():
    m = _map()
    paths = "".join(f"<path data-n='{e(n)}' d='{d}'/>" for n, d in m["states"].items() if not n.endswith("@c"))
    return (f"<svg id=usmap viewBox='{m['viewBox']}' role=img aria-label='Map of scam-call reports by state' style='width:100%;height:auto'>{paths}</svg>"
            f"<div class='small mut' id=mapnote></div>")


def _feed_panel(fixed_sec=None):
    secs = "" if fixed_sec else ("<span class=seg id=fsec><button class=on data-v=all>All</button><button data-v=crypto>Crypto</button>"
                                 "<button data-v=phone>Phone</button><button data-v=defense>Defense</button><button data-v=settings>Settings</button></span>")
    return (f"<div class=pan style='margin-top:14px'><span class=lbl>Live feed</span><h2>What's happening</h2>"
            f"<div class=filters>{secs}<label class=small style='display:inline-flex;gap:6px;align-items:center'><input type=checkbox id=fwarn style='width:20px;height:20px'> Warnings only</label>"
            f"<input type=search id=fq placeholder='Search the feed'></div>"
            f"<table class=feed><thead><tr><th>What</th><th>When</th><th>Section</th></tr></thead><tbody id=feedrows></tbody></table><button class=btn id=more style='border:0;cursor:pointer;display:none'></button></div>")


def overview():
    body = ("<h1>Overview</h1><p class=lead>Everything the Desk is watching, at a glance. Pick a tab above to work in one area.</p>"
            "<div class=status id=status></div><div class=pan id=ticks style='padding:4px 14px'></div>"
            "<div class='grid gmain' style='margin-top:14px'>"
            "<div><div class=pan id=latest></div><div class=pan style='margin-top:14px'><span class=lbl>Scam calls &middot; top states</span>"
            "<h2>Where people are being called</h2><div id=topstates></div></div></div>"
            "<div class=pan><div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px'>"
            "<div><span class=lbl>Scam-call reports to the FTC</span><h2 style='margin:2px 0'>Live map</h2></div>"
            "<span class=seg id=range><button data-v=7>7 days</button><button data-v=14>14 days</button><button class=on data-v=30>30 days</button></span></div>"
            f"{_usmap()}<div class='small mut'>Source: FTC Do Not Call reported calls (unverified consumer reports), by the state of the person called.</div></div>"
            "<div><div class=pan><span class=lbl>Most-reported scam types</span><h2>What they're pretending to be</h2><div class=bars id=subjects></div></div>"
            "<div class=pan style='margin-top:14px'><span class=lbl>Reports per day</span><div class=cols id=perday></div></div></div>"
            "</div><div class='grid g3' id=sections style='margin-top:14px'></div>" + _feed_panel())
    return _page("Overview", body)


HUB = {
    "crypto": ("Protect your wallets, follow stolen funds, and build the case.",
               "d=>[[d.crypto.wallets_mapped.toLocaleString(),'wallets mapped'],[d.crypto.cashout_points,'cash-out points found'],"
               "[d.crypto.yours,'reached YOUR funds'],[d.crypto.checks,'addresses checked'],[d.crypto.stops,'checks that said STOP'],"
               "[d.crypto.campaigns.length,'attack campaigns known']]"),
    "phone": ("Check a caller or a message before you trust it.",
              "d=>[[d.phone.numbers.toLocaleString(),'reported numbers'],[d.phone.reports.toLocaleString(),'FTC reports'],"
              "[d.phone.days,'days of FTC data'],[d.phone.msg_checks,'messages checked here']]"),
    "defense": ("Your browser, the websites you use, your home network, and AI agents.",
                "d=>[[d.defense.ext_paired?'ON':'OFF','browser extension'],[d.defense.ext_blocks,'browser blocks'],"
                "[d.defense.sites,'websites watched'],[d.defense.site_alerts,'website alerts'],[d.defense.agent_pending,'agent requests waiting'],"
                "[(d.defense.exposure.worst||'not yet').toUpperCase(),'internet exposure (weekly)'],"
                "[d.defense.agent_denied,'agent actions denied']]"),
    "settings": ("Where alerts go, updates, and your case details.", "d=>[[d.services.alive+'/'+d.services.total,'watchers running']]"),
}


def hub(key):
    _, tab, home, groups = shell.section(key)
    lead, kpi = HUB[key]
    tiles = "".join(f"<div class=grp><span class=lbl>{e(g)}</span></div><div class=tiles>"
                    + "".join(f"<a class=tile href='{p}'><b>{e(l)}</b><p>{e(dsc)}</p></a>" for p, l, dsc in pages) + "</div>"
                    for g, pages in groups)
    extra = ""
    if key == "phone":
        extra = ("<div class='grid gmain' style='margin-top:14px'><div class=pan><span class=lbl>Top states</span><h2>Where people are being called</h2><div id=topstates></div></div>"
                 "<div class=pan><div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px'><h2 style='margin:0'>Scam-call reports by state</h2>"
                 "<span class=seg id=range><button data-v=7>7 days</button><button data-v=14>14 days</button><button class=on data-v=30>30 days</button></span></div>"
                 f"{_usmap()}</div><div class=pan><span class=lbl>Most-reported scam types</span><div class=bars id=subjects></div>"
                 "<span class=lbl>Reports per day</span><div class=cols id=perday></div></div></div>"
                 "<div class=pan style='margin-top:14px'><span class=lbl>Android app</span><h2>ScamHunter Guard for your phone</h2>"
                 "<p class=mut>Warns about reported scam numbers before you answer, checks messages, and helps report a scam call, in large print. "
                 "It downloads the same FTC list on Wi-Fi once a day. It only ever sees the caller's number, never the call itself.</p></div>")
    if key == "crypto":
        extra = "<div class=pan id=latest style='margin-top:14px'></div>"
    return _page(tab, f"<h1>{e(tab)}</h1><p class=lead>{e(lead)}</p><div class=kpis id=kpis></div>{tiles}{extra}"
                      + (_feed_panel(key) if key != "settings" else ""), kpi, key)
