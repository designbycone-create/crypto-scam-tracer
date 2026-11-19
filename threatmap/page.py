"""The Threat Map tab: an interactive world map of threats as they develop.

Drawn in the page from /threatmap.json (refreshed every 60 seconds); no outside scripts, maps or
fonts. Zoom with the wheel or the + / - buttons, drag to move, click a country for what's
happening there. Each source is credited at the bottom with its license.
"""
import html
import json
import os

from deskui import pages as deskpages
from threatmap import feeds

HERE = os.path.dirname(os.path.abspath(__file__))
e = lambda s: html.escape(str(s if s is not None else ""), quote=True)

# everyday names instead of the long official ones
SHORT = {"CN": "China", "TW": "Taiwan", "IR": "Iran", "RU": "Russia", "KR": "South Korea", "KP": "North Korea", "VN": "Vietnam", "SY": "Syria",
         "LA": "Laos", "BO": "Bolivia", "VE": "Venezuela", "TZ": "Tanzania", "MD": "Moldova", "CD": "DR Congo", "CG": "Congo",
         "GB": "United Kingdom", "US": "United States", "CZ": "Czechia", "MK": "North Macedonia", "PS": "Palestine", "BN": "Brunei",
         "FM": "Micronesia", "VA": "Vatican City", "HK": "Hong Kong", "MO": "Macau", "AE": "UAE", "DO": "Dominican Republic",
         "CF": "Central African Rep.", "BA": "Bosnia and Herzegovina", "CI": "Ivory Coast", "TL": "East Timor", "SZ": "Eswatini"}

CSS = """
.mapwrap{position:relative;background:#050912;border:1px solid var(--line);border-radius:16px;overflow:hidden;touch-action:none}
#world{width:100%;height:auto;display:block;cursor:grab}
#world.drag{cursor:grabbing}
#world .sea{fill:#071224;stroke:#16304f;stroke-width:.6}
#world path.c{stroke:#20395c;stroke-width:.4;vector-effect:non-scaling-stroke;transition:fill .25s;cursor:pointer}
#world path.c:hover{stroke:#fff;stroke-width:1.2}
#world path.c.sel{stroke:#22d3ee;stroke-width:1.8}
#world circle.pulse{fill:#ff5470;opacity:.85;pointer-events:none;animation:pz 2.4s ease-out infinite}
@keyframes pz{0%{opacity:.9}100%{opacity:.15}}
.mapctl{position:absolute;right:10px;top:10px;display:flex;flex-direction:column;gap:6px}
.mapctl button{width:40px;height:40px;border-radius:10px;border:1px solid var(--line);background:#0b1322;color:#fff;font-size:20px;cursor:pointer}
.legend{position:absolute;left:12px;bottom:10px;font:12px ui-monospace,Consolas,monospace;color:var(--mut);display:flex;align-items:center;gap:6px}
.legend i{display:inline-block;width:90px;height:8px;border-radius:4px;background:linear-gradient(90deg,#163150,#2f7fa3,#ffb020,#ff5470)}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:8px 0}
.chips label{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:999px;padding:6px 12px;font-size:15px;cursor:pointer;background:var(--pan)}
.chips input{width:18px;height:18px}
.rise{display:flex;align-items:center;gap:10px;border:1px solid #5b1f2c;background:#1a0b12;border-radius:12px;padding:8px 10px;margin:6px 0;cursor:pointer}
.rise b{flex:1;min-width:0} .rise .x{font:700 13px ui-monospace,Consolas,monospace;color:#ff8aa0;text-align:right;white-space:nowrap}
.badge{font:700 11px ui-monospace,Consolas,monospace;background:#ff5470;color:#fff;border-radius:6px;padding:2px 6px;letter-spacing:.08em}
.src{font-size:14px;color:var(--mut)} .src b{color:var(--fg)} .src .bad{color:#ff8aa0}
#cpanel h2{margin:2px 0 6px}
"""

JS = r"""
const $=s=>document.querySelector(s), esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const W=window.__W, NAMES=window.__N; let T=window.__T, hours=24, sel=null, fq='', layers=new Set(Object.keys(window.__L));
const LNAME=window.__L, num=n=>Number(n||0).toLocaleString();
const svg=$('#world'), g=$('#world g.view');
// ---- pan & zoom (viewBox) ----
let vb=[0,0,960,500]; const full=[0,0,960,500];
function setVB(){ svg.setAttribute('viewBox',vb.join(' ')); }
function zoom(f,cx,cy){ const nw=Math.min(960,Math.max(60,vb[2]*f)), nh=nw*500/960;
  cx=cx??vb[0]+vb[2]/2; cy=cy??vb[1]+vb[3]/2; vb=[cx-(cx-vb[0])*nw/vb[2], cy-(cy-vb[1])*nh/vb[3], nw, nh]; clamp(); setVB(); }
function clamp(){ vb[0]=Math.max(-200,Math.min(960-vb[2]+200,vb[0])); vb[1]=Math.max(-120,Math.min(500-vb[3]+120,vb[1])); }
function pt(ev){ const r=svg.getBoundingClientRect(); return [vb[0]+(ev.clientX-r.left)/r.width*vb[2], vb[1]+(ev.clientY-r.top)/r.height*vb[3]]; }
svg.addEventListener('wheel',ev=>{ev.preventDefault(); const [x,y]=pt(ev); zoom(ev.deltaY>0?1.2:1/1.2,x,y);},{passive:false});
let drag=null, moved=false, downOn=null;
svg.addEventListener('pointerdown',ev=>{drag=[ev.clientX,ev.clientY,vb[0],vb[1]]; moved=false; downOn=ev.target.closest('path.c');});
svg.addEventListener('pointermove',ev=>{ if(!drag) return; const r=svg.getBoundingClientRect();
  const dx=(ev.clientX-drag[0])/r.width*vb[2], dy=(ev.clientY-drag[1])/r.height*vb[3];
  if(!moved && Math.abs(ev.clientX-drag[0])+Math.abs(ev.clientY-drag[1])>4){ moved=true; svg.classList.add('drag'); try{svg.setPointerCapture(ev.pointerId);}catch(_){} }
  if(!moved) return;
  vb[0]=drag[2]-dx; vb[1]=drag[3]-dy; clamp(); setVB(); });
svg.addEventListener('pointerup',()=>{ if(drag && !moved && downOn){ sel=(sel===downOn.dataset.cc)?null:downOn.dataset.cc; draw(); }
  drag=null; downOn=null; svg.classList.remove('drag'); });
$('#zin').onclick=()=>zoom(1/1.5); $('#zout').onclick=()=>zoom(1.5); $('#zreset').onclick=()=>{vb=[...full]; setVB();};
// ---- colours ----
function heat(v,max){ if(!v) return '#0f1d33'; const t=Math.sqrt(v/max);
  const stops=[[22,49,80],[47,127,163],[255,176,32],[255,84,112]], p=t*3, i=Math.min(2,Math.floor(p)), f=p-i, a=stops[i], b=stops[i+1];
  return `rgb(${a.map((c,k)=>Math.round(c+(b[k]-c)*f)).join(',')})`; }
function draw(){
  const C=T.countries, max=Math.max(1,...Object.values(C).map(c=>c.n));
  g.querySelectorAll('path.c').forEach(p=>{ const c=C[p.dataset.cc]; p.style.fill=heat(c?c.n:0,max); p.classList.toggle('sel',p.dataset.cc===sel); });
  const rc=new Set(T.rising.filter(r=>r.kind==='country').map(r=>r.key));
  g.querySelectorAll('circle.pulse').forEach(c=>c.style.display=rc.has(c.dataset.cc)?'':'none');
  $('#total').textContent=num(T.total); $('#ctry').textContent=num(Object.keys(C).length); $('#unloc').textContent=num(T.unlocated);
  $('#risen').textContent=T.rising.length; $('#gen').textContent=T.generated.slice(11,16)+' UTC';
  const top=Object.entries(C).sort((a,b)=>b[1].n-a[1].n).slice(0,6), tot=Math.max(1,top.reduce((s,x)=>s+x[1].n,0));
  $('#top').innerHTML=top.length?top.map(([cc,c],i)=>`<div class=rank data-cc="${cc}" style="cursor:pointer"><i>0${i+1}</i><div class=nm>${esc(NAMES[cc]||cc)}<small>${num(c.n)} threats</small></div><span class=pct>${Math.round(100*c.n/tot)}%</span></div>`).join(''):'<div class=empty>Nothing in this window yet.</div>';
  $('#rising').innerHTML=T.rising.length?T.rising.map(r=>`<div class=rise data-cc="${r.kind==='country'?esc(r.key):''}" data-q="${r.kind==='family'?esc(r.key):''}"><span class=badge>RISING</span><b>${esc(r.kind==='country'?(NAMES[r.key]||r.key):r.key)}</b><span class=x title="${num(r.now)} in the last 24 hours; usually ${r.usual} a day">x${r.x}<br><span style="font-weight:400;color:var(--mut)">${num(r.now)} today</span></span></div>`).join('')
     :(T.learning_since
       ? `<div class=empty>Still learning what's normal. A source is only compared after a week of history (collecting since ${esc(T.learning_since.slice(0,10))}).</div>`
       : '<div class=empty>Nothing is clearly above its usual level right now.</div>');
  const fm=T.families, fmax=Math.max(1,...fm.map(f=>f[1]));
  $('#fams').innerHTML=fm.length?fm.map(([k,v])=>`<div class=bar data-q="${esc(k)}" style="cursor:pointer"><span>${esc(k)}</span><div style="width:${Math.max(3,100*v/fmax)}%"></div><em>${num(v)}</em></div>`).join(''):'<div class=empty>No named families yet.</div>';
  ticker(); panel(); feed(); sources(); }
function ticker(){ const it=T.items.slice(0,24); if(!it.length){$('#tick').innerHTML='<span class=empty>Waiting for the first feeds...</span>';return;}
  const one=it.map(x=>`<a class="chip ${x.layer==='news'?'info':x.layer==='exploited'?'caution':'stop'}" href="${esc(x.url||'#')}" target=_blank rel=noopener><b>${esc(x.title)}</b><small>${esc(x.time.slice(0,16).replace('T',' '))} &middot; ${esc(LNAME[x.layer])}${x.cc?' &middot; '+esc(NAMES[x.cc]||x.cc):''}</small></a>`).join('');
  $('#tick').innerHTML=`<div class=run>${one}${one}</div>`; }
function panel(){ const el=$('#cpanel'); if(!sel){ el.innerHTML='<span class=lbl>Country</span><h2>Click a country</h2><div class="small mut">See what\'s been reported there in this time window.</div>'; return; }
  const c=T.countries[sel]||{n:0,layers:{}}, its=T.items.filter(x=>(x.ccs||[x.cc]).includes(sel)).slice(0,12);
  el.innerHTML=`<span class=lbl>Country</span><h2>${esc(NAMES[sel]||sel)}</h2><div class=small>${num(c.n)} in the last ${hours<48?hours+' hours':hours/24+' days'}: `
   +Object.entries(c.layers).map(([l,n])=>`${esc(LNAME[l])} ${num(n)}`).join(' &middot; ')+`</div>`
   +(its.length?'<ul class=small style="padding-left:18px">'+its.map(x=>`<li><a href="${esc(x.url||'#')}" target=_blank rel=noopener style="color:#cfe3ff">${esc(x.title)}</a> <span class=mut>${esc(x.time.slice(0,10))}</span></li>`).join('')+'</ul>':'')
   +'<button class=btn style="border:0;cursor:pointer" id=clearsel>Show all countries</button>';
  $('#clearsel').onclick=()=>{sel=null; draw();}; }
let shown=30;
function feed(){ const q=fq.toLowerCase();
  const rows=T.items.filter(x=>(!sel||(x.ccs||[x.cc]).includes(sel))&&(!q||(x.title+' '+x.detail+' '+(x.family||'')).toLowerCase().includes(q)));
  $('#more').style.display=rows.length>shown?'inline-block':'none'; $('#more').textContent=`Show more (${rows.length-shown})`;
  $('#rows').innerHTML=rows.length?rows.slice(0,shown).map(x=>`<tr data-u="${esc(x.url)}"><td><span class="dot lv-${x.layer==='news'?'info':x.layer==='exploited'?'caution':'stop'}"></span>${esc(x.title)}<div class="small mut">${esc(x.detail)}</div></td><td class=small>${esc(x.time.slice(0,16).replace('T',' '))}</td><td class=small>${esc(x.cc?(NAMES[x.cc]||x.cc):'unknown')}</td><td class=small>${esc(LNAME[x.layer])}</td></tr>`).join('')
   :'<tr><td colspan=4 class=empty>Nothing matches.</td></tr>'; }
function sources(){ $('#srcs').innerHTML=T.sources.map(s=>`<div class=src><b>${esc(s.name)}</b> &middot; ${esc(s.license)} &middot; <a href="${esc(s.link)}" target=_blank rel=noopener style="color:#8ec5ff">${esc(s.link.replace('https://',''))}</a> &middot; <span class="${s.status==='ok'?'':'bad'}">${esc(s.status==='ok'?(s.count??0)+' items last fetch':s.error||s.status)}</span></div>`).join('')
; }
// ---- events ----
const tip=$('#tip');
g.addEventListener('mousemove',ev=>{ const p=ev.target.closest('path.c'); if(!p){tip.style.display='none';return;} const c=T.countries[p.dataset.cc];
  tip.innerHTML=`<b>${esc(NAMES[p.dataset.cc]||p.dataset.cc)}</b><br>${c?num(c.n)+' threats':'nothing reported'}`; tip.style.display='block'; tip.style.left=(ev.clientX+14)+'px'; tip.style.top=(ev.clientY+14)+'px'; });
g.addEventListener('mouseleave',()=>tip.style.display='none');
document.addEventListener('click',ev=>{ const r=ev.target.closest('[data-cc]'); if(r&&r.dataset.cc&&!r.closest('#world')){ sel=r.dataset.cc; draw(); $('.mapwrap').scrollIntoView({behavior:'smooth',block:'center'}); }
  const q=ev.target.closest('[data-q]'); if(q&&q.dataset.q){ fq=q.dataset.q; $('#fq').value=fq; feed(); $('#rows').scrollIntoView({behavior:'smooth',block:'center'}); } });
$('#range').addEventListener('click',ev=>{ const b=ev.target.closest('button'); if(!b) return; $('#range').querySelectorAll('button').forEach(x=>x.classList.toggle('on',x===b)); hours=+b.dataset.v; refresh(); });
$('#layers').addEventListener('change',()=>{ layers=new Set([...document.querySelectorAll('#layers input:checked')].map(i=>i.value)); refresh(); });
$('#fq').addEventListener('input',ev=>{fq=ev.target.value; feed();});
$('#more').onclick=()=>{shown+=30; feed();};
$('#rows').addEventListener('click',ev=>{ const r=ev.target.closest('tr[data-u]'); if(r&&r.dataset.u) window.open(r.dataset.u,'_blank','noopener'); });
async function refresh(){ try{ const r=await fetch(`/threatmap.json?hours=${hours}&layers=${[...layers].join(',')}`,{cache:'no-store'}); if(r.ok){T=await r.json(); draw();} }catch(_){} }
setVB(); draw(); setInterval(refresh,60000);
"""


def page():
    with open(os.path.join(HERE, "world.json"), encoding="utf-8") as f:
        w = json.load(f)
    paths = "".join(f"<path class=c data-cc='{cc}' d='{c['d']}'/>" for cc, c in w["countries"].items())
    pulses = "".join(f"<circle class=pulse data-cc='{cc}' cx='{c['c'][0]}' cy='{c['c'][1]}' r='5' style='display:none'/>" for cc, c in w["countries"].items())
    names = {cc: c["n"] for cc, c in w["countries"].items()}
    from threatmap import geo
    for cc, n in geo.NAMES.items():
        names.setdefault(cc, n[0])
    names.update(SHORT)
    data = json.dumps(feeds.summary(24)).replace("</", "<\\/")
    layer_chips = "".join(f"<label><input type=checkbox value={k} checked> {e(v)}</label>" for k, v in feeds.LAYERS.items())
    body = (
        "<h1>Threat Map</h1><p class=lead>Threats being reported around the world right now: security alerts and news, botnet servers, "
        "malware sites and newly exploited flaws. Zoom with the mouse wheel, drag to move, click a country.</p>"
        "<div class=status><span class=pulse></span><b><span id=total>0</span> threats</b><span class=mut>in <span id=ctry>0</span> countries</span>"
        "<span class=mut><span id=risen>0</span> rising</span><span class=mut><span id=unloc>0</span> with no location</span>"
        "<span class=mut>updated <span id=gen></span></span></div>"
        "<div class=pan style='padding:4px 14px'><div class=tick><span class=lbl>&#9670; Latest reports</span><div class=rail id=tick></div></div></div>"
        "<div style='display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-top:12px'>"
        f"<div class=chips id=layers>{layer_chips}</div>"
        "<span class=seg id=range><button class=on data-v=24>24 hours</button><button data-v=168>7 days</button><button data-v=720>30 days</button></span></div>"
        "<div class='grid gmain' style='margin-top:6px'>"
        "<div><div class=pan><span class=lbl style='color:#ff8aa0'>Rising threats</span><h2>Above their usual level</h2><div id=rising></div>"
        "<div class='small mut'>Last 24 hours compared with the average day of the week before.</div></div>"
        "<div class=pan style='margin-top:14px'><span class=lbl>Top countries</span><div id=top></div></div></div>"
        f"<div><div class=mapwrap><svg id=world viewBox='{w['viewBox']}' role=img aria-label='World map of reported threats'>"
        f"<g class=view><path class=sea d='{w['sphere']}'/>{paths}{pulses}</g></svg>"
        "<div class=mapctl><button id=zin title='Zoom in'>+</button><button id=zout title='Zoom out'>&minus;</button><button id=zreset title='Whole world'>&#8635;</button></div>"
        "<div class=legend>fewer <i></i> more</div></div>"
        "<div class=pan id=cpanel style='margin-top:14px'></div></div>"
        "<div><div class=pan><span class=lbl>Malware &amp; scam families</span><h2>Most active</h2><div class=bars id=fams></div>"
        "<div class='small mut'>Click one to see its reports.</div></div></div></div>"
        "<div class=pan style='margin-top:14px'><span class=lbl>Live feed</span><h2>Every report</h2><div class=filters>"
        "<input type=search id=fq placeholder='Search (e.g. ClickFix, ransomware, Russia)'></div>"
        "<table class=feed><thead><tr><th>What</th><th>When (UTC)</th><th>Where</th><th>Type</th></tr></thead><tbody id=rows></tbody></table>"
        "<button class=btn id=more style='border:0;cursor:pointer;display:none'></button></div>"
        "<div class=pan style='margin-top:14px'><span class=lbl>Sources</span><div id=srcs></div>"
        "<div class=src style='margin-top:8px'>Server locations: <a href='https://db-ip.com' target=_blank rel=noopener style='color:#8ec5ff'>IP Geolocation by DB-IP</a> "
        "(CC BY 4.0). Map: <a href='https://www.naturalearthdata.com' target=_blank rel=noopener style='color:#8ec5ff'>Natural Earth</a> (public domain) "
        "via world-atlas (ISC). Country names: i18n-iso-countries (MIT).</div>"
        "<div class='small mut' style='margin-top:6px'>Headlines are shown with their link only, never the article. Some abuse.ch data is free only for "
        "not-for-profit use under abuse.ch's terms; it uses your own key. Locations are where a server or address is registered, not necessarily "
        "where the people behind it are.</div></div>")
    head = deskpages.CSS + CSS
    return (f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>Threat Map - ScamHunter Threat Desk</title><style>{head}</style></head><body><main>{body}</main><div class=tip id=tip></div>"
            f"<script>window.__W=1;window.__N={json.dumps(names)};window.__L={json.dumps(feeds.LAYERS)};window.__T={data};</script>"
            f"<script>{JS}</script></body></html>")


def json_api(query):
    from urllib.parse import parse_qs
    q = parse_qs(query)
    try:
        hours = max(1, min(720, int((q.get("hours") or ["24"])[0])))
    except ValueError:
        hours = 24
    layers = [x for x in ((q.get("layers") or [""])[0]).split(",") if x in feeds.LAYERS] or None
    return json.dumps(feeds.summary(hours, layers))
