"""The chain-agnostic trace engine.

Given one or more seed addresses (each on some chain, with the time the stolen
funds arrived), it walks the money FORWARD IN TIME, hop by hop, building a
single graph that spans every chain. At each wallet it asks the entity layer
"who is this?" and acts:

  * exchange            -> terminal endpoint; a freeze report is owed here.
  * bridge / swap       -> terminal endpoint AND an open cross-chain HANDOFF:
                           the funds may leave this chain. A takedown/records
                           report is owed, and the trace resumes on the far side
                           once the destination address is known.
  * mixer / sanctioned  -> terminal; flagged for law enforcement (evidence).
  * ordinary wallet     -> expand: follow its outgoing transfers.

Freeze opportunities are captured everywhere, not just at exchanges: any hop
that receives USDT or USDC is recorded as an issuer-freeze opportunity, because
Tether / Circle can freeze that address directly on any chain.

Automation:
  * EVM chains share an address space, so an address seen on one EVM chain is
    automatically probed on every other configured EVM chain (cross_evm). This
    follows most EVM<->EVM bridge hops with no manual step.
  * Resolved handoffs are re-seeded automatically on the next run, so the map
    grows to the end of the trail as destinations become known.
"""
import json
import os
from datetime import datetime, timezone

from . import entities
from .core import CHAINS, iso_from_epoch, now_iso
from .registry import get_adapter

STABLE_ISSUER = {"USDT": "tether", "USDC": "circle"}


def nid(chain, addr):
    return f"{chain}:{addr}"


def _stable(transfer):
    """Return (symbol, issuer_key) if this transfer is a freezable stablecoin."""
    s = entities.stablecoin_for(transfer.chain, transfer.contract)
    if s:
        return s
    sym = (transfer.asset or "").upper()
    if sym in STABLE_ISSUER:
        return sym, STABLE_ISSUER[sym]
    return None


class Tracer:
    def __init__(self, max_nodes=300, max_depth=8, cross_evm=True, log=print):
        self.max_nodes = max_nodes
        self.max_depth = max_depth
        self.cross_evm = cross_evm
        self.log = log
        self.nodes, self.edges, self.endpoints = {}, [], []
        self.handoffs, self.freeze_ops = [], []
        self.seeds = []
        self._seen_tx = set()
        self._evm_queried = set()   # addresses already probed across EVM chains

    # ---- state load/save -------------------------------------------------
    @classmethod
    def load(cls, path="mc_map.json", **kw):
        t = cls(**kw)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            t.nodes = d.get("nodes", {})
            t.edges = d.get("edges", [])
            t.endpoints = d.get("endpoints", [])
            t.handoffs = d.get("handoffs", [])
            t.freeze_ops = d.get("freeze_ops", [])
            t.seeds = d.get("seeds", [])
            t._seen_tx = {e["txid"] for e in t.edges if e.get("txid")}
        return t

    def save(self, path="mc_map.json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.state(), f, indent=2, default=str)

    def state(self):
        return {
            "generated": now_iso(),
            "summary": self.summary(),
            "seeds": self.seeds,
            "nodes": self.nodes, "edges": self.edges,
            "endpoints": self.endpoints, "handoffs": self.handoffs,
            "freeze_ops": self.freeze_ops,
        }

    def summary(self):
        wallets = sum(1 for n in self.nodes.values() if n["type"] == "wallet")
        return {
            "chains": sorted({n["chain"] for n in self.nodes.values()}),
            "total_nodes": len(self.nodes), "wallets": wallets,
            "exchanges": sum(1 for n in self.nodes.values() if n["type"] == "exchange"),
            "bridges": sum(1 for n in self.nodes.values() if n["type"] == "bridge"),
            "mixers": sum(1 for n in self.nodes.values() if n["type"] == "mixer"),
            "open_handoffs": sum(1 for h in self.handoffs if h["status"] == "open"),
            "freeze_opportunities": len(self.freeze_ops),
            "edges": len(self.edges),
        }

    # ---- node handling ---------------------------------------------------
    def _describe(self, chain, addr):
        ent = entities.classify(chain, addr)
        typ = ent["type"] if ent else "wallet"
        return {
            "chain": chain, "address": addr,
            "label": ent["name"] if ent else None,
            "type": typ,
            "label_source": ent["source"] if ent else None,
            "role": {"exchange": "exchange / cash-out point",
                     "bridge": "bridge / swap (funds may leave this chain)",
                     "mixer": "mixer / sanctioned (law-enforcement evidence)",
                     "service": "known service"}.get(typ, "hop wallet"),
            "terminal": typ in ("exchange", "bridge", "mixer"),
            "freezable": [],
        }

    def _ensure_node(self, chain, addr):
        k = nid(chain, addr)
        if k not in self.nodes:
            self.nodes[k] = self._describe(chain, addr)
        return self.nodes[k]

    def _record_freeze_op(self, kind, chain, addr, detail):
        key = (kind, chain, addr, detail.get("asset"))
        if any((f["kind"], f["chain"], f["address"], f.get("asset")) == key for f in self.freeze_ops):
            return
        op = {"kind": kind, "chain": chain, "address": addr, "status": "open", **detail}
        self.freeze_ops.append(op)

    # ---- the walk --------------------------------------------------------
    def trace(self, seeds):
        """seeds: list of (chain, address, after_epoch|None). Extends the graph."""
        # include resolved handoffs as additional seeds (auto-continuation)
        frontier = []
        for (c, a, after) in seeds:
            if (c, a) not in [(s[0], s[1]) for s in self.seeds]:
                self.seeds.append((c, a, after))
            frontier.append((c, a, after, 0))
        for h in self.handoffs:
            if h["status"] == "resolved" and h.get("resolved_to"):
                rc, ra = h["resolved_to"]["chain"], h["resolved_to"]["address"]
                frontier.append((rc, ra, h.get("epoch"), h.get("depth", 0) + 1))

        visited = set()
        while frontier and len(self.nodes) < self.max_nodes:
            chain, addr, after, depth = frontier.pop(0)
            if not addr or (chain, addr) in visited or depth >= self.max_depth:
                continue
            visited.add((chain, addr))
            node = self._ensure_node(chain, addr)
            node["depth"] = depth

            if node["terminal"]:
                self._handle_terminal(node, depth)
                continue

            # Which chains to query this wallet on: its own, plus -- if it's an
            # EVM address -- every other EVM chain (shared address space). Nodes
            # are created only from transfers that actually exist, so a quiet
            # chain adds nothing.
            query_chains = [chain]
            if (self.cross_evm and CHAINS.get(chain) and CHAINS[chain].evm_chainid is not None
                    and addr not in self._evm_queried):
                query_chains += [ck for ck, ci in CHAINS.items()
                                 if ci.evm_chainid is not None and ck != chain]
                self._evm_queried.add(addr)

            for qc in query_chains:
                try:
                    adapter = get_adapter(qc)
                    ok, why = adapter.available()
                    if not ok:
                        if qc == chain:
                            node.setdefault("note", why)
                        continue
                    transfers = adapter.outgoing(addr, after_epoch=after)
                except Exception as e:
                    if qc == chain:
                        node.setdefault("note", f"lookup failed: {e}")
                    continue

                for tr in transfers:
                    if tr.txid in self._seen_tx:
                        continue
                    self._seen_tx.add(tr.txid)
                    # make the sending address visible on the chain it acted on
                    src = self._ensure_node(tr.chain, tr.frm)
                    src.setdefault("depth", depth)
                    dest = self._ensure_node(tr.chain, tr.to)
                    self.edges.append({"txid": tr.txid, "chain": tr.chain, "time": tr.time,
                                       "epoch": tr.epoch, "from": tr.frm, "to": tr.to,
                                       "asset": tr.asset, "amount": tr.amount,
                                       "contract": tr.contract, "depth": depth + 1})
                    st = _stable(tr)
                    if st:
                        sym, issuer = st
                        if not any(fz.get("asset") == sym for fz in dest["freezable"]):
                            dest["freezable"].append({"asset": sym, "issuer": issuer})
                        self._record_freeze_op("stablecoin_issuer", tr.chain, tr.to,
                                               {"asset": sym, "issuer": issuer, "amount": tr.amount,
                                                "txid": tr.txid, "time": tr.time})
                    frontier.append((tr.chain, tr.to, tr.epoch, depth + 1))
        return self

    def _handle_terminal(self, node, depth):
        chain, addr, typ = node["chain"], node["address"], node["type"]
        ep = {"chain": chain, "address": addr, "label": node["label"], "type": typ,
              "role": node["role"], "depth": depth}
        if not any(e["chain"] == chain and e["address"] == addr for e in self.endpoints):
            self.endpoints.append(ep)
        if typ == "exchange":
            self._record_freeze_op("exchange", chain, addr,
                                   {"label": node["label"], "asset": None})
        elif typ == "bridge":
            # open a cross-chain handoff lead (resume once destination is known)
            if not any(h["chain"] == chain and h["address"] == addr for h in self.handoffs):
                self.handoffs.append({"id": f"h{len(self.handoffs)+1}", "chain": chain,
                                      "address": addr, "service": node["label"],
                                      "status": "open", "depth": depth,
                                      "resolved_to": None,
                                      "note": "funds may have left this chain here"})
            self._record_freeze_op("bridge", chain, addr, {"label": node["label"], "asset": None})

    # ---- handoff resolution (manual or automated) ------------------------
    def resolve_handoff(self, handoff_id, dest_chain, dest_address, epoch=None):
        for h in self.handoffs:
            if h["id"] == handoff_id:
                h["status"] = "resolved"
                h["resolved_to"] = {"chain": dest_chain, "address": dest_address}
                if epoch:
                    h["epoch"] = epoch
                return True
        return False
