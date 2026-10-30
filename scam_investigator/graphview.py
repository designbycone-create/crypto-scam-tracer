"""Interactive network graph (Arkham-style) for the Desk: /graph.

Builds the graph from the evidence map (scam_network.json), the freeze map
(network_map.json), attribution.json and your recorded cash-outs. Rendered in
the browser with Cytoscape.js (loaded from cdnjs). Click a node for details,
evidence and explorer links; flows from YOUR stolen funds are highlighted.
"""
import json
import math

CYTO = "https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"
MAX_NODES = 700


def _j(p):
    try:
        with open(p, encoding="utf-8-sig") as f:
            return json.load(f)
    except Exception:
        return {}


def build():
    ev, fm, att = _j("scam_network.json"), _j("network_map.json"), _j("attribution.json")
    root = ev.get("root") or fm.get("root")
    yours_hash = set()
    try:
        with open("cashouts.jsonl", encoding="utf-8") as f:
            for line in f:
                try:
                    yours_hash.add(json.loads(line)["hash"])
                except Exception:
                    pass
    except FileNotFoundError:
        pass
    yours_hash |= {e.get("hash") for e in fm.get("edges", [])}
    nodes = {}
    for src in (ev, fm):
        for a, n in src.get("nodes", {}).items():
            nodes.setdefault(a, {}).update({k: v for k, v in n.items() if v not in (None, "")})
    eps = {}
    for src in (ev, fm):
        for e in src.get("endpoints", []):
            eps.setdefault(e.get("address"), []).append(e)
    flows = {}
    for src in (ev, fm):
        for e in src.get("edges", []):
            if not e.get("from") or not e.get("to"):
                continue
            k = (e["from"], e["to"])
            f = flows.setdefault(k, {"xrp": 0.0, "n": 0, "yours": False, "first": e.get("time"), "hashes": set()})
            if e.get("hash") in f["hashes"]:
                continue
            f["hashes"].add(e.get("hash"))
            f["xrp"] += float(e.get("xrp") or 0)
            f["n"] += 1
            f["yours"] = f["yours"] or e.get("hash") in yours_hash
    # keep the most important nodes if huge
    keep = set([root]) | set(eps) | {a for (a, b), f in flows.items() if f["yours"]} | \
        {b for (a, b), f in flows.items() if f["yours"]}
    vol = {}
    for (a, b), f in flows.items():
        vol[a] = vol.get(a, 0) + f["xrp"]
        vol[b] = vol.get(b, 0) + f["xrp"]
    for a in sorted(vol, key=lambda x: -vol[x]):
        if len(keep) >= MAX_NODES:
            break
        keep.add(a)
    els = []
    for a in keep:
        if not a:
            continue
        n = nodes.get(a, {})
        at = att.get(a) or {}
        label = n.get("label") or (f"{at['name']}?" if at.get("name") else "") or ("SCAM WALLET" if a == root else "")
        role = str(n.get("role", ""))
        kind = ("root" if a == root else "exchange" if (a in eps or "exchange" in role or "custodial" in role)
                else "swap" if "swap" in role or "bridge" in role else "victim" if "victim" in role
                else "hub" if "intermediate" in role or "consolidation" in role else "wallet")
        dep = eps.get(a, [])
        els.append({"data": {
            "id": a, "label": label or a[:6] + "…", "kind": kind, "addr": a, "role": role,
            "named": label, "balance": n.get("balance_xrp"), "vol": round(vol.get(a, 0), 2),
            "yours": any(d.get("hash") in yours_hash for d in dep),
            "deposits": [{"tag": d.get("destination_tag"), "xrp": d.get("xrp"), "time": d.get("time"),
                          "hash": d.get("hash")} for d in dep[:30]],
            "attribution": at, "size": 18 + min(40, 6 * math.log10(1 + vol.get(a, 0))),
        }})
    for (a, b), f in flows.items():
        if a in keep and b in keep:
            els.append({"data": {"id": f"{a}>{b}", "source": a, "target": b, "xrp": round(f["xrp"], 2),
                                 "n": f["n"], "yours": f["yours"], "first": f["first"],
                                 "w": 1 + min(9, 1.6 * math.log10(1 + f["xrp"]))}})
    return {"root": root, "elements": els, "nodes": len([a for a in keep if a]),
            "total_nodes": len(set(nodes) | set(eps) | {a for k in flows for a in k})}


def render():
    g = build()
    data = json.dumps(g).replace("</", "<\\/")
    return f"""<!doctype html><html><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Scam network graph</title><script src="{CYTO}"></script><style>
html,body{{margin:0;height:100%;background:#0f1115;color:#e8eaf0;font:14px system-ui,sans-serif}} a{{color:#5aa2ff}}
#top{{position:fixed;top:0;left:0;right:0;height:44px;display:flex;gap:12px;align-items:center;padding:0 12px;white-space:nowrap;overflow:hidden;font-size:13px;background:#151922;border-bottom:1px solid #262b36;z-index:2}}
#top a{{color:#5aa2ff;font-weight:600;text-decoration:none}} #top input{{background:#0b0d12;color:#e8eaf0;border:1px solid #262b36;border-radius:6px;padding:5px;width:260px}}
#cy{{position:absolute;top:44px;left:0;right:340px;bottom:0}}
#side{{position:absolute;top:44px;right:0;width:340px;bottom:0;overflow:auto;background:#151922;border-left:1px solid #262b36;padding:12px;box-sizing:border-box}}
.m{{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}} .mut{{color:#9aa1b2}} .k{{display:inline-block;width:10px;height:10px;border-radius:50%;margin:0 4px 0 10px}}
label{{font-size:12px}} @media(max-width:1100px){{.legend{{display:none}}}} @media(max-width:700px){{#cy{{right:0;bottom:45%}}#side{{top:55%;width:100%}}}}
</style></head><body>
<div id=top><a href='/'>&larr; Desk</a><b>Scam network</b>
<span class=mut>{g['nodes']} of {g['total_nodes']} wallets</span>
<input id=q placeholder="Find address or name"> <label style="white-space:nowrap"><input type=checkbox id=onlyyours>only YOUR funds' path</label>
<span class="mut legend"><span class=k style=background:#ef4444></span>scam wallet<span class=k style=background:#f59e0b></span>laundering<span class=k style=background:#3b82f6></span>exchange<span class=k style=background:#a855f7></span>swap<span class=k style=background:#10b981></span>victim source</span></div>
<div id=cy></div><div id=side><p class=mut>Click a wallet for details. Scroll to zoom, drag to pan. Red edges = your stolen funds' path.</p></div>
<script>
const G={data};
const color={{root:'#ef4444',hub:'#f59e0b',wallet:'#9aa1b2',exchange:'#3b82f6',swap:'#a855f7',victim:'#10b981'}};
const cy=cytoscape({{container:document.getElementById('cy'),elements:G.elements,wheelSensitivity:0.25,
 style:[{{selector:'node',style:{{'background-color':e=>color[e.data('kind')]||'#9aa1b2','label':'data(label)','color':'#e8eaf0','font-size':9,
   'width':'data(size)','height':'data(size)','text-valign':'bottom','text-margin-y':3,'border-width':e=>e.data('yours')?4:0,'border-color':'#ff6a5a'}}}},
  {{selector:'edge',style:{{'width':'data(w)','line-color':e=>e.data('yours')?'#ff6a5a':'#3a4252','target-arrow-color':e=>e.data('yours')?'#ff6a5a':'#3a4252',
   'target-arrow-shape':'triangle','curve-style':'bezier','opacity':0.85}}}},
  {{selector:'.faded',style:{{'opacity':0.08}}}},{{selector:':selected',style:{{'border-width':4,'border-color':'#fff'}}}}],
 layout:{{name:'cose',animate:false,nodeRepulsion:9000,idealEdgeLength:90,numIter:1500}}}});
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c]));
cy.on('tap','node',ev=>{{const d=ev.target.data();let h=`<h3 style=margin-top:0>${{esc(d.named||'Unlabeled wallet')}}</h3>
<div class=m>${{esc(d.addr)}}</div><p class=mut>${{esc(d.role)}}</p>
<p>Balance: <b>${{d.balance==null?'?':Number(d.balance).toLocaleString()}} XRP</b><br>Volume in this map: ${{Number(d.vol).toLocaleString()}} XRP</p>
<p><a href="https://livenet.xrpl.org/accounts/${{d.addr}}" target=_blank>XRPL explorer</a> · <a href="https://xrpscan.com/account/${{d.addr}}" target=_blank>XRPScan</a> · <a href="https://bithomp.com/explorer/${{d.addr}}" target=_blank>Bithomp</a></p>`;
 if(d.attribution&&d.attribution.name){{h+=`<p><b>Attribution:</b> ${{esc(d.attribution.name)}} [${{esc(d.attribution.confidence)}}]</p><ul>`+d.attribution.evidence.map(e=>`<li><small>${{esc(e)}}</small></li>`).join('')+'</ul>'}}
 if(d.deposits.length){{h+='<p><b>Deposits received</b> (tag = customer account):</p><ul>'+d.deposits.map(x=>`<li><small>tag <b>${{esc(x.tag)}}</b> · ${{Number(x.xrp||0).toLocaleString()}} XRP · ${{esc(x.time)}} · <a href="https://livenet.xrpl.org/transactions/${{x.hash}}" target=_blank>tx</a></small></li>`).join('')+'</ul>'}}
 const n=ev.target.neighborhood();cy.elements().addClass('faded');ev.target.removeClass('faded');n.removeClass('faded');
 document.getElementById('side').innerHTML=h;}});
cy.on('tap',ev=>{{if(ev.target===cy)cy.elements().removeClass('faded')}});
document.getElementById('q').addEventListener('input',e=>{{const q=e.target.value.trim().toLowerCase();cy.elements().removeClass('faded');if(!q)return;
 const hit=cy.nodes().filter(n=>n.data('addr').toLowerCase().includes(q)||String(n.data('named')).toLowerCase().includes(q));
 if(hit.length){{cy.elements().addClass('faded');hit.removeClass('faded');hit.neighborhood().removeClass('faded');cy.fit(hit.closedNeighborhood(),80)}}}});
document.getElementById('onlyyours').addEventListener('change',e=>{{cy.elements().removeClass('faded');if(!e.target.checked)return;
 const y=cy.edges().filter(x=>x.data('yours'));cy.elements().addClass('faded');y.removeClass('faded');y.connectedNodes().removeClass('faded');cy.fit(y.connectedNodes(),60)}});
</script></body></html>"""
