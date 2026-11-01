"""Aptos adapter: outgoing transfers from the wallet's own sent transactions (full history via the
fullnode REST API; "aptos_rpc" in config.json for a faster personal endpoint). Shares parsing with
shield.aptos, so plain transfers, swaps and scripts are all read the same way."""
from ..core import Adapter, Transfer, iso_from_epoch


class AptosAdapter(Adapter):
    def outgoing(self, address, after_epoch=None, min_native=None, limit=200):
        from shield import aptos as ap
        floor = self.info.min_native if min_native is None else min_native
        txs, _ = ap.sent_txs(address, limit=min(400, limit * 2))
        out = []
        for tx in txs:
            if tx.get("success") is False:
                continue
            for m in ap.moves_for(tx, address):
                if m["dir"] != "out" or not m.get("cp"):
                    continue
                if after_epoch is not None and m["t"] < after_epoch:
                    continue
                if m["asset"] == "APT" and m["amount"] < floor:
                    continue
                out.append(Transfer(chain="aptos", txid=tx.get("hash"), time=iso_from_epoch(m["t"]), epoch=m["t"],
                                    frm=ap.norm(address), to=m["cp"], asset=m["asset"], amount=m["amount"],
                                    contract=None if m["asset_id"] == ap.APT else m["asset_id"]))
            if len(out) >= limit:
                break
        out.sort(key=lambda t: t.epoch or 0, reverse=True)
        return out[:limit]
