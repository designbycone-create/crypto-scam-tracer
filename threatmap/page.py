"""The Threat Map tab: an interactive world map of threats as they develop.

Drawn in the page from /threatmap.json (refreshed every 60 seconds); no outside scripts, maps or
fonts. Zoom with the wheel or the + / - buttons, drag to move, click a country for what's
happening there. Each source is credited at the bottom with its license.
"""
import html
import json
import os

from threatmap import feeds

HERE = os.path.dirname(os.path.abspath(__file__))
e = lambda s: html.escape(str(s if s is not None else ""), quote=True)

# everyday names instead of the long official ones
SHORT = {"CN": "China", "TW": "Taiwan", "IR": "Iran", "RU": "Russia", "KR": "South Korea", "KP": "North Korea", "VN": "Vietnam", "SY": "Syria",
         "LA": "Laos", "BO": "Bolivia", "VE": "Venezuela", "TZ": "Tanzania", "MD": "Moldova", "CD": "DR Congo", "CG": "Congo",
         "GB": "United Kingdom", "US": "United States", "CZ": "Czechia", "MK": "North Macedonia", "PS": "Palestine", "BN": "Brunei",
         "FM": "Micronesia", "VA": "Vatican City", "HK": "Hong Kong", "MO": "Macau", "AE": "UAE", "DO": "Dominican Republic",
         "CF": "Central African Rep.", "BA": "Bosnia and Herzegovina", "CI": "Ivory Coast", "TL": "East Timor", "SZ": "Eswatini"}

CSS = """/*nd-own*/
/* Night Desk tokens come from the Desk shell (deskui/nightdesk.css); this is only the map's own layout */
.tm-status{display:flex;flex-wrap:wrap;align-items:center;gap:.5rem 1.5rem;margin:0 0 1rem;color:var(--text-2)}
.tm-status b{color:var(--text)}
.tm-controls{display:flex;flex-wrap:wrap;gap:.75rem;align-items:center;justify-content:space-between;margin:0 0 1rem}
.seg{display:inline-flex;border:2px solid var(--line-strong);border-radius:var(--r-md);overflow:hidden}
.nd-page .seg button{border:0;border-radius:0;min-height:var(--min-btn);background:transparent;color:var(--text-2);padding:.6rem 1.1rem}
.nd-page .seg button.on{background:var(--teal);color:var(--teal-ink)}
.tm-layers{display:flex;flex-wrap:wrap;gap:.6rem}
.tm-layers label{display:inline-flex;align-items:center;gap:.55rem;min-height:var(--min-btn);padding:0 .9rem;border:1px solid var(--line);border-radius:var(--r-md);background:var(--bg-raised);cursor:pointer}
.mapwrap{position:relative;background:#0A1624;border:1px solid var(--line);border-radius:var(--r-lg);overflow:hidden;touch-action:none}
#world{width:100%;height:auto;display:block;cursor:grab;min-height:22rem}
#world.drag{cursor:grabbing}
#world .sea{fill:#0A1624;stroke:#1d3553;stroke-width:.6}
#world path.c{stroke:#2C415C;stroke-width:.4;vector-effect:non-scaling-stroke;transition:fill .25s;cursor:pointer}
#world path.c:hover{stroke:#F7F8FB;stroke-width:1.2}
#world path.c.sel{stroke:var(--teal);stroke-width:2}
#world circle.pulse{fill:#FF6B78;opacity:.85;pointer-events:none;animation:pz 2.4s ease-out infinite}
@keyframes pz{0%{opacity:.9}100%{opacity:.15}}
.mapctl{position:absolute;right:.75rem;top:.75rem;display:flex;flex-direction:column;gap:.5rem}
.nd-page .mapctl button{width:3.5rem;height:3.5rem;padding:0;background:var(--bg-raised);font-size:1.5rem}
.legend{position:absolute;left:1rem;bottom:.75rem;color:var(--text-2);display:flex;align-items:center;gap:.5rem;background:rgba(7,16,24,.85);padding:.2rem .6rem;border-radius:999px}
.legend i{display:inline-block;width:6rem;height:.6rem;border-radius:99px;background:linear-gradient(90deg,#163150,#2f7fa3,#F6C453,#FF6B78)}
.tm-side .card{margin:0 0 1rem}
.rise,.rank{display:flex;align-items:center;gap:.75rem;min-height:var(--min-btn);padding:.6rem .8rem;margin:.4rem 0;border:1px solid var(--line);border-radius:var(--r-md);background:var(--bg-sunken);cursor:pointer}
.rise b,.rank .nm{flex:1;min-width:0}
.rank i{font-style:normal;font-family:var(--mono);color:var(--teal)}
.rank .nm small,.rise .x small{display:block;color:var(--text-2);font-size:var(--nd-min)}
.rise .x{text-align:right;white-space:nowrap;font-weight:700;color:var(--careful-ink)}
.pct{font-family:var(--mono);font-weight:600}
.badge{display:inline-flex;align-items:center;gap:.3rem;font-weight:700;color:var(--careful-ink);background:var(--careful-bg);border:1px solid #6E5420;border-radius:999px;padding:.05rem .6rem}
.bars .bar{display:grid;grid-template-columns:minmax(7rem,1.2fr) 2fr auto;gap:.6rem;align-items:center;min-height:2.75rem;cursor:pointer}
.bars .bar div{height:.8rem;border-radius:99px;background:linear-gradient(90deg,#2f7fa3,#F6C453)}
.bars .bar em{font-style:normal;font-family:var(--mono)}
.tick{display:flex;align-items:center;gap:.75rem;overflow:hidden}
.tick .lbl{flex:0 0 auto;font-family:var(--display);color:var(--teal);font-weight:600}
.tick .rail{overflow:hidden;flex:1;mask-image:linear-gradient(90deg,transparent,#000 4%,#000 96%,transparent)}
.tick .run{display:flex;gap:.75rem;width:max-content;animation:run 70s linear infinite}
.tick:hover .run{animation-play-state:paused}
@keyframes run{to{transform:translateX(-50%)}}
.tick .chip{flex-direction:column;align-items:flex-start;min-width:16rem;max-width:22rem;padding:.5rem .9rem;border-radius:var(--r-md);text-decoration:none;color:var(--text)}
.tick .chip small{color:var(--text-2);font-size:var(--nd-min);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
.dot.lv-stop{background:var(--stop)} .dot.lv-caution{background:var(--careful)} .dot.lv-info,.dot.lv-ok{background:var(--info)}
.nd-page td .dot{display:inline-block;margin-right:.5rem;vertical-align:middle;box-shadow:none}
table.feed tr{cursor:pointer}
.empty{color:var(--text-2)}
.src{color:var(--text-2);margin:.25rem 0} .src b{color:var(--text)} .src .bad{color:var(--stop-ink)}
.tip{position:fixed;pointer-events:none;background:#071018;border:1px solid var(--teal);border-radius:var(--r-md);padding:.5rem .8rem;display:none;z-index:50}
@media(prefers-reduced-motion:reduce){.tick .run{animation:none}}
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
  $('#rising').innerHTML=T.rising.length?T.rising.map(r=>`<div class=rise data-cc="${r.kind==='country'?esc(r.key):''}" data-q="${r.kind==='family'?esc(r.key):''}"><span class=badge>Rising</span><b>${esc(r.kind==='country'?(NAMES[r.key]||r.key):r.key)}</b><span class=x title="${num(r.now)} in the last 24 hours; usually ${r.usual} a day">x${r.x}<br><span style="font-weight:400;color:var(--mut)">${num(r.now)} today</span></span></div>`).join('')
     :(T.learning_since
       ? `<div class=empty>Still learning what's normal. A source is only compared after a week of history (collecting since ${esc(T.learning_since.slice(0,10))}).</div>`
       : '<div class=empty>Nothing is clearly above its usual level right now.</div>');
  const fm=T.families, fmax=Math.max(1,...fm.map(f=>f[1]));
  $('#fams').innerHTML=fm.length?fm.map(([k,v])=>`<div class=bar data-q="${esc(k)}" style="cursor:pointer"><span>${esc(k)}</span><div style="width:${Math.max(3,100*v/fmax)}%"></div><em>${num(v)}</em></div>`).join(''):'<div class=empty>No named families yet.</div>';
  ticker(); panel(); feed(); sources(); }
function ticker(){ const it=T.items.slice(0,24); if(!it.length){$('#tick').innerHTML='<span class=empty>Waiting for the first feeds...</span>';return;}
  const one=it.map(x=>`<a class="chip ${(x.layer==='news'||x.layer==='social')?'info':x.layer==='exploited'?'caution':'stop'}" href="${esc(x.url||'#')}" target=_blank rel=noopener><b>${esc(x.title)}</b><small>${esc(x.time.slice(0,16).replace('T',' '))} &middot; ${esc(LNAME[x.layer])}${x.cc?' &middot; '+esc(NAMES[x.cc]||x.cc):''}</small></a>`).join('');
  $('#tick').innerHTML=`<div class=run>${one}${one}</div>`; }
function panel(){ const el=$('#cpanel'); if(!sel){ el.innerHTML='<h2>Pick a country</h2><p class=note>Click a country on the map to see what\'s been reported there in this time window.</p>'; return; }
  const c=T.countries[sel]||{n:0,layers:{}}, its=T.items.filter(x=>(x.ccs||[x.cc]).includes(sel)).slice(0,12);
  el.innerHTML=`<h2>${esc(NAMES[sel]||sel)}</h2><div class=small>${num(c.n)} in the last ${hours<48?hours+' hours':hours/24+' days'}: `
   +Object.entries(c.layers).map(([l,n])=>`${esc(LNAME[l])} ${num(n)}`).join(' &middot; ')+`</div>`
   +(its.length?'<ul class=small style="padding-left:18px">'+its.map(x=>`<li><a href="${esc(x.url||'#')}" target=_blank rel=noopener style="color:#cfe3ff">${esc(x.title)}</a> <span class=mut>${esc(x.time.slice(0,10))}</span></li>`).join('')+'</ul>':'')
   +'<div class=actions><button class="btn btn-secondary" id=clearsel>Show all countries</button></div>';
  $('#clearsel').onclick=()=>{sel=null; draw();}; }
let shown=30;
function feed(){ const q=fq.toLowerCase();
  const rows=T.items.filter(x=>(!sel||(x.ccs||[x.cc]).includes(sel))&&(!q||(x.title+' '+x.detail+' '+(x.family||'')).toLowerCase().includes(q)));
  $('#more').style.display=rows.length>shown?'inline-block':'none'; $('#more').textContent=`Show more (${rows.length-shown})`;
  $('#rows').innerHTML=rows.length?rows.slice(0,shown).map(x=>`<tr data-u="${esc(x.url)}"><td><span class="dot lv-${(x.layer==='news'||x.layer==='social')?'info':x.layer==='exploited'?'caution':'stop'}"></span>${esc(x.title)}<div class="small mut">${esc(x.detail)}</div></td><td class=small>${esc(x.time.slice(0,16).replace('T',' '))}</td><td class=small>${esc(x.cc?(NAMES[x.cc]||x.cc):'unknown')}</td><td class=small>${esc(LNAME[x.layer])}</td></tr>`).join('')
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
async function refresh(){ try{ const r=await fetch(`/threatmap.json?hours=${hours}&scope=${window.__S||'all'}&layers=${[...layers].join(',')}`,{cache:'no-store'}); if(r.ok){T=await r.json(); draw();} }catch(_){} }
const q0=new URLSearchParams(location.search).get('q'); if(q0){ fq=q0; $('#fq').value=q0; }
setVB(); draw(); setInterval(refresh,60000);
if(q0) setTimeout(()=>$('#rows').scrollIntoView({block:'center'}),300);
"""


SCOPE_TEXT = {
    "all": ("Threat Map", "Threats reported around the world right now: security alerts and news, botnet servers, malware sites and newly "
                          "exploited flaws."),
    "cyber": ("Cyber threat map", "Where the servers behind today's cyber attacks are: botnet control servers, malware download sites "
                                  "and newly exploited flaws. These are what the Desk's browser extension, malware check and exposure check "
                                  "watch for."),
    "crypto": ("Crypto threat map", "Malware that steals crypto wallets (stealers, clippers, drainer kits, the North Korean campaigns aimed "
                                    "at crypto firms and developers), and news about crypto theft and scams."),
}
SCOPE_LAYERS = {"all": None, "cyber": ("botnet", "malware", "exploited"), "crypto": None}


def page(scope="all"):
    scope = scope if scope in SCOPE_TEXT else "all"
    with open(os.path.join(HERE, "world.json"), encoding="utf-8") as f:
        w = json.load(f)
    paths = "".join(f"<path class=c data-cc='{cc}' d='{c['d']}'/>" for cc, c in w["countries"].items())
    pulses = "".join(f"<circle class=pulse data-cc='{cc}' cx='{c['c'][0]}' cy='{c['c'][1]}' r='5' style='display:none'/>" for cc, c in w["countries"].items())
    names = {cc: c["n"] for cc, c in w["countries"].items()}
    from threatmap import geo
    for cc, n in geo.NAMES.items():
        names.setdefault(cc, n[0])
    names.update(SHORT)
    layer_names = {k: v for k, v in feeds.LAYERS.items() if not SCOPE_LAYERS[scope] or k in SCOPE_LAYERS[scope]}
    data = json.dumps(feeds.summary(24, list(layer_names), scope)).replace("</", "<\\/")
    layer_chips = "".join(f"<label><input type=checkbox value={k} checked> {e(v)}</label>" for k, v in layer_names.items())
    title, lead = SCOPE_TEXT[scope]
    body = (
        f"<div class=page-head><h1>{e(title)}</h1><p class=lead>{e(lead)} Zoom with the mouse wheel or the + and &minus; buttons, "
        "drag to move, click a country.</p></div>"
        "<p class=tm-status><span><b><span id=total>0</span> threats</b> in <span id=ctry>0</span> countries</span>"
        "<span><span id=risen>0</span> rising</span><span><span id=unloc>0</span> on websites or with no location</span>"
        "<span>Updated <span id=gen></span></span></p>"
        "<div class=tm-controls><span class=seg id=range role=group aria-label='Time window'><button class=on data-v=24>Past day</button>"
        "<button data-v=168>Past week</button><button data-v=720>Past month</button></span>"
        f"<div class=tm-layers id=layers role=group aria-label='Kinds of threat'>{layer_chips}</div></div>"
        "<div class=map-layout><div>"
        f"<div class=mapwrap><svg id=world viewBox='{w['viewBox']}' role=img aria-label='World map of reported threats'>"
        f"<g class=view><path class=sea d='{w['sphere']}'/>{paths}{pulses}</g></svg>"
        "<div class=mapctl><button id=zin aria-label='Zoom in'>+</button><button id=zout aria-label='Zoom out'>&minus;</button>"
        "<button id=zreset aria-label='Whole world'>&#8635;</button></div><div class=legend>fewer <i></i> more</div></div>"
        "<section class=card id=cpanel style='margin-top:1.5rem'></section></div>"
        "<div class=tm-side><section class=card><h2>Rising threats</h2><div id=rising></div>"
        "<p class=note>Last 24 hours compared with the average day of the week before.</p></section>"
        "<section class=card><h2>Top countries</h2><div id=top></div></section>"
        "<section class=card><h2>Most active families</h2><div class=bars id=fams></div><p class=note>Pick one to see its reports.</p></section>"
        "</div></div>"
        "<section class=card style='margin-top:1.5rem'><div class=tick><span class=lbl>Latest reports</span><div class=rail id=tick></div></div></section>"
        "<section class=card style='margin-top:1.5rem'><h2>Every report</h2><div class=field><label for=fq>Search the reports</label>"
        "<input type=search id=fq placeholder='Example: ClickFix, ransomware, Russia'></div>"
        "<div class=table-wrap><table class=feed><thead><tr><th>What</th><th>When (UTC)</th><th>Where</th><th>Kind</th></tr></thead><tbody id=rows></tbody></table></div>"
        "<div class=actions><button class='btn btn-secondary' id=more style='display:none'></button></div></section>"
        "<section class=card style='margin-top:1.5rem'><h2>Sources</h2><div id=srcs></div>"
        "<p class=src style='margin-top:.75rem'>Server locations: <a href='https://db-ip.com' target=_blank rel=noopener>IP Geolocation by DB-IP</a> "
        "(CC BY 4.0). Map: <a href='https://www.naturalearthdata.com' target=_blank rel=noopener>Natural Earth</a> (public domain) "
        "via world-atlas (ISC). Country names: i18n-iso-countries (MIT).</p>"
        "<p class=note>Headlines are shown with their link only, never the article. Some abuse.ch data is free only for "
        "not-for-profit use under abuse.ch's terms; it uses your own key. Locations are where a server or address is registered, not necessarily "
        "where the people behind it are.</p></section>")
    head = CSS
    return (f"<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{e(title)} - ScamHunter Threat Desk</title><style>{head}</style></head><body>{body}<div class=tip id=tip></div>"
            f"<script>window.__W=1;window.__S={json.dumps(scope)};window.__N={json.dumps(names)};window.__L={json.dumps(layer_names)};window.__T={data};</script>"
            f"<script>{JS}</script></body></html>")


def json_api(query):
    from urllib.parse import parse_qs
    q = parse_qs(query)
    try:
        hours = max(1, min(720, int((q.get("hours") or ["24"])[0])))
    except ValueError:
        hours = 24
    layers = [x for x in ((q.get("layers") or [""])[0]).split(",") if x in feeds.LAYERS] or None
    scope = (q.get("scope") or ["all"])[0]
    return json.dumps(feeds.summary(hours, layers, scope if scope in feeds.SCOPES else "all"))


def preview(scope, href):
    """A map card for a section's landing page (like the scam-call map on Phone & Messages): drawn on the
    server from the last 7 days, no script needed. The full map is one click away."""
    with open(os.path.join(HERE, "world.json"), encoding="utf-8") as f:
        w = json.load(f)
    s = feeds.summary(24 * 7, list(SCOPE_LAYERS.get(scope) or feeds.LAYERS), scope)
    by = {cc: c["n"] for cc, c in s["countries"].items()}
    mx = max([1] + list(by.values()))
    names = {cc: c["n"] for cc, c in w["countries"].items()}
    from threatmap import geo
    for cc, n in geo.NAMES.items():
        names.setdefault(cc, n[0])
    names.update(SHORT)

    def fill(v):
        if not v:
            return "#132033"
        t = (v / mx) ** 0.5
        return f"hsl({int(200 - 170 * t)},{int(55 + 30 * t)}%,{int(22 + 30 * t)}%)"
    paths = "".join(f"<path d='{c['d']}' fill='{fill(by.get(cc, 0))}' stroke='#2C415C' stroke-width='.4'><title>{e(names.get(cc, cc))}: "
                    f"{by.get(cc, 0):,}</title></path>" for cc, c in w["countries"].items())
    top = sorted(by.items(), key=lambda kv: -kv[1])[:5]
    rows = "".join(f"<tr><td>{e(names.get(cc, cc))}</td><td>{n:,}</td></tr>" for cc, n in top) or \
        "<tr><td colspan=2>No reports with a location yet. The Desk collects them every few hours.</td></tr>"
    fams = ", ".join(e(f) for f, _ in s["families"][:4])
    title, lead = SCOPE_TEXT[scope]
    located = s["total"] - s["unlocated"]
    note = (f"<p class=note>{s['total']:,} reports in the last 7 days; {located:,} have a server location"
            + (f", the rest are on websites with no fixed location" if s["unlocated"] else "") + ". "
            "A location is where a server is registered, not where the people behind it are.</p>")
    return (f"<section class=card style='margin-top:1.5rem'><h2>{e(title)}</h2><p>{e(lead)}</p>"
            f"<div class=grid-12><div class=span-7><svg viewBox='{w['viewBox']}' role=img aria-label='{e(title)}' style='width:100%;height:auto'>"
            f"<path d='{w['sphere']}' fill='#0A1624'/>{paths}</svg></div>"
            f"<div class=span-5><table><thead><tr><th>Country</th><th>Reports</th></tr></thead><tbody>{rows}</tbody></table>"
            + (f"<p class=note>Most active: {fams}</p>" if fams else "") + "</div></div>" + note
            + f"<div class=actions><a class='btn btn-primary' href='{href}'>Open the full map</a></div></section>")
