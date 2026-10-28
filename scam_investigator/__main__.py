"""
XRPL Scam Investigator

  python -m scam_investigator investigate --address rXXXX --domain scam.com [--victim victim.json]
  python -m scam_investigator trace --address rXXXX
  python -m scam_investigator site --domain scam.com
  python -m scam_investigator registry publish --address rXXXX --domain scam.com [--ref URL] [--submit]
  python -m scam_investigator registry check --address rXXXX --registry rREGISTRY [--registry rOTHER]
"""
import argparse
import asyncio
import json
import os
import sys

from . import cease_desist, cluster, enrich, netmap, netreport, osint, registry, reports, trace

try:
    import scamconfig
except Exception:
    scamconfig = None


def _default_scam_wallet():
    return (scamconfig.scam_wallet() if scamconfig else "") or ""


def _load_victim(path):
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {"name": "", "email": "", "country": "US"}


def cmd_investigate(a):
    print(f"Tracing funds from {a.address} (depth {a.depth}, min {a.min_xrp} XRP)...")
    t = asyncio.run(trace.trace(a.address, a.depth, a.min_xrp, not a.no_xrpscan))
    infra = []
    for d in a.domain or []:
        print(f"Scanning infrastructure for {d} (incl. server geolocation)...")
        infra.append(osint.investigate_domain(d))

    print("Screening addresses against the OFAC SDN list...")
    screen = [a.address] + [e["address"] for e in t["endpoints"]] + list(t.get("victim_sources", {}))
    sanctions = enrich.sanctions_summary(sorted(set(screen)))

    cl = None
    if not a.no_cluster:
        print("Clustering related wallets...")
        try:
            cl = asyncio.run(cluster.cluster(a.address, funder=(t.get("activation") or {}).get("from")))
        except Exception as ex:
            cl = {"error": str(ex)}

    case = {
        "generated": reports.now(),
        "victim": _load_victim(a.victim),
        "domains": a.domain or [],
        "trace": t,
        "infrastructure": infra,
        "sanctions": sanctions,
        "cluster": cl,
        "labels": trace.load_labels(),
    }
    out = os.path.join(a.out, a.address)
    drafts = reports.build_case(case, out)
    s = t["summary"]
    print(f"\nBalance {s['balance_xrp']} XRP | received {s['total_received_xrp']} XRP from {s['victim_payments']} payments "
          f"| moved out {s['outgoing_payments']} | exchange hits {s['exchange_endpoints']}")
    for e in t["endpoints"]:
        print(f"  !! EXCHANGE DEPOSIT: {e['xrp']} XRP -> {e['address']} tag {e['destination_tag']} ({e.get('label') or 'unlabeled'})")
    if sanctions.get("sanctioned"):
        print(f"  !! OFAC SDN MATCH: {', '.join(sanctions['sanctioned'])}")
    if cl and cl.get("summary", {}).get("sibling_accounts"):
        print(f"  Cluster: funder activated {cl['summary']['sibling_accounts']} related account(s)")
    for dom in infra:
        for h in dom.get("hosting", []):
            g = h.get("geo") or {}
            if g and not g.get("error"):
                print(f"  Server {h['ip']}: {g.get('city')}, {g.get('country')} ({g.get('org')})")
    print(f"\nCase file: {os.path.abspath(os.path.join(out, 'report.html'))}")
    print(f"Drafts ({len(drafts)}): {os.path.abspath(os.path.join(out, 'drafts'))}")


def cmd_trace(a):
    print(json.dumps(asyncio.run(trace.trace(a.address, a.depth, a.min_xrp, not a.no_xrpscan)), indent=1, default=str))


def cmd_site(a):
    print(json.dumps(osint.investigate_domain(a.domain), indent=1, default=str))


def cmd_geoip(a):
    print(json.dumps(enrich.geolocate_ip(a.ip), indent=1, default=str))


def cmd_screen(a):
    print(json.dumps(enrich.sanctions_summary(a.address), indent=1, default=str))


def cmd_cluster(a):
    print(json.dumps(asyncio.run(cluster.cluster(a.address, funder=a.funder)), indent=1, default=str))


def cmd_netmap(a):
    """Build (or re-render) the scam-network map. With --from-saved, just
    re-render the on-demand detailed log from the persisted map."""
    if a.from_saved:
        with open("network_map.json", encoding="utf-8") as f:
            net = json.load(f)
    else:
        root = a.address or _default_scam_wallet()
        if not root:
            sys.exit("No scam wallet given. Pass --address or set \"scam_wallet\" in config.json.")
        a.address = root
        print(f"Mapping stolen funds forward from {a.address}...")
        net = asyncio.run(netmap.map_network(a.address, max_depth=a.depth,
                                             max_nodes=a.max_nodes, min_xrp=a.min_xrp))
        netmap.save(net, "network_map.json")
    with open("network_map.html", "w", encoding="utf-8") as f:
        f.write(netmap.render_html(net))
    s = net["summary"]
    print(f"Nodes {s['total_nodes']} | hop wallets {s['hop_wallets']} | "
          f"cash-out points {s['cash_out_points']} | flows {s['edges']}")
    for ep in {e['address']: e for e in net.get('endpoints', [])}.values():
        print(f"  cash-out: {ep.get('label') or ep['address']} (tag {ep.get('destination_tag')})")
    drafts = netreport.write_all_from_map(net, case=netreport.load_case())
    print(f"\nDetailed log: {os.path.abspath('network_map.html')}")
    print(f"Raw data:     {os.path.abspath('network_map.json')}")
    if drafts:
        print(f"Freeze-request drafts ({len(drafts)}): {os.path.abspath('network_reports')}  (review and send)")


def cmd_ceasedesist(a):
    """Generate a cease-and-desist / takedown letter for a host, registrar, or IP.
    Pulls target details from a live --domain scan, or takes them directly."""
    case = netreport.load_case(a.victim)
    scam = {"wallet": a.wallet or _default_scam_wallet(), "domain": a.domain,
            "victim_tx": case.get("tx_hash"), "total_xrp": a.total_xrp}
    targets = []
    if a.domain and not (a.ip or a.org):
        print(f"Scanning {a.domain} for host/registrar details...")
        info = osint.investigate_domain(a.domain)
        reg = info.get("registration", {})
        if reg.get("registrar_abuse"):
            targets.append({"org": reg.get("registrar"), "abuse": (reg["registrar_abuse"] or {}).get("email"),
                            "domain": a.domain})
        for h in info.get("hosting", []):
            if h.get("error"):
                continue
            g = h.get("geo") or {}
            targets.append({"org": (h.get("abuse") or {}).get("name") or h.get("network"),
                            "abuse": (h.get("abuse") or {}).get("email"), "ip": h["ip"],
                            "domain": a.domain, "network": h.get("network"),
                            "country": g.get("country") or h.get("country")})
    else:
        targets.append({"org": a.org, "abuse": a.abuse, "ip": a.ip, "domain": a.domain, "network": a.network})
    written = [cease_desist.write(t, case=case, scam=scam, deadline_hours=a.deadline,
                                  anonymous=not a.named) for t in targets if t.get("org") or t.get("ip")]
    for p in written:
        print("  wrote:", os.path.abspath(p))
    print(f"\n{len(written)} cease-and-desist letter(s) in {os.path.abspath('cease_desist')} (review before sending).")


def cmd_registry(a):
    if a.action == "publish":
        r = registry.publish(a.address, a.domain, a.category, a.ref, a.note, a.submit)
        print(json.dumps(r, indent=1))
    else:
        regs = a.registry or [x for x in os.environ.get("XRPL_REGISTRIES", "").split(",") if x]
        if not regs:
            sys.exit("Give --registry rADDRESS (or set XRPL_REGISTRIES=rA,rB).")
        hits = asyncio.run(registry.check(a.address, regs))
        print(json.dumps(hits, indent=1) if hits else f"{a.address}: not in the given registries.")


def main():
    p = argparse.ArgumentParser(prog="scam_investigator", description="Trace, document and report XRPL scams.")
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("investigate", help="Full case: trace + site scan + case file + report drafts")
    i.add_argument("--address", required=True)
    i.add_argument("--domain", action="append")
    i.add_argument("--victim", default="victim.json", help="JSON with your name, email, phone, country, tx_hash, amount, date, ic3_id, reports")
    i.add_argument("--out", default="cases")
    i.add_argument("--no-cluster", action="store_true", help="Skip address clustering")
    for x in (i, sub.add_parser("trace", help="Follow the money only")):
        if x is not i:
            x.add_argument("--address", required=True)
        x.add_argument("--depth", type=int, default=4)
        x.add_argument("--min-xrp", type=float, default=50)
        x.add_argument("--no-xrpscan", action="store_true", help="Skip public label lookups")
    s = sub.add_parser("site", help="Scan a scam domain's infrastructure only")
    s.add_argument("--domain", required=True)

    g = sub.add_parser("geoip", help="Geolocate a server IP (hosting datacenter)")
    g.add_argument("--ip", required=True)
    sc = sub.add_parser("screen", help="Screen address(es) against the OFAC SDN list")
    sc.add_argument("--address", required=True, action="append")
    cl = sub.add_parser("cluster", help="Find wallets the same operator likely controls")
    cl.add_argument("--address", required=True)
    cl.add_argument("--funder", help="Known funder account (optional; auto-detected otherwise)")

    nm = sub.add_parser("netmap", help="Map the scam network (stolen funds, time-forward); on-demand detailed log")
    nm.add_argument("--address", default=None, help="Scam wallet (root). Defaults to config.json scam_wallet.")
    nm.add_argument("--depth", type=int, default=6)
    nm.add_argument("--max-nodes", type=int, default=250)
    nm.add_argument("--min-xrp", type=float, default=25)
    nm.add_argument("--from-saved", action="store_true", help="Re-render the detailed log from network_map.json")

    cd = sub.add_parser("ceasedesist", help="Generate a cease-and-desist / takedown letter for a host, registrar, or IP")
    cd.add_argument("--domain", help="Scan this domain for host/registrar targets automatically")
    cd.add_argument("--ip")
    cd.add_argument("--org", help="Provider / organization name")
    cd.add_argument("--abuse", help="Abuse / compliance contact")
    cd.add_argument("--network", help="Network / ASN name")
    cd.add_argument("--wallet", default=None, help="Scam receiving wallet. Defaults to config.json scam_wallet.")
    cd.add_argument("--total-xrp", type=float, help="Total XRP taken (optional)")
    cd.add_argument("--victim", default="victim.json")
    cd.add_argument("--deadline", type=int, default=48, help="Response deadline in hours")
    cd.add_argument("--named", action="store_true", help="Sign with your name (default: anonymous, identity on file with FBI)")

    r = sub.add_parser("registry", help="Publish to / check the on-ledger scam registry")
    r.add_argument("action", choices=["publish", "check"])
    r.add_argument("--address", required=True)
    r.add_argument("--domain", action="append")
    r.add_argument("--category", default="giveaway-scam")
    r.add_argument("--ref", action="append", help="Report link, e.g. your Chainabuse URL")
    r.add_argument("--note")
    r.add_argument("--registry", action="append", help="Registry account(s) to check against")
    r.add_argument("--submit", action="store_true", help="Actually publish (otherwise dry run)")

    a = p.parse_args()
    {"investigate": cmd_investigate, "trace": cmd_trace, "site": cmd_site, "registry": cmd_registry,
     "geoip": cmd_geoip, "screen": cmd_screen, "cluster": cmd_cluster, "netmap": cmd_netmap,
     "ceasedesist": cmd_ceasedesist}[a.cmd](a)


if __name__ == "__main__":
    main()
