"""Bitcoin adapter via mempool.space (free, no API key).

Bitcoin is UTXO, not accounts, so "outgoing from address X" means: transactions
in which X appears as an input (X is spending). The recipients are that
transaction's outputs that are NOT X itself (a crude but effective change
heuristic -- an output back to a spending input is change). Each recipient
output becomes one normalized Transfer.
"""
from ..core import Adapter, Transfer, iso_from_epoch
from ..util import http_json

API = "https://mempool.space/api"


class BitcoinAdapter(Adapter):
    def outgoing(self, address, after_epoch=None, min_native=None, limit=200):
        floor = self.info.min_native if min_native is None else min_native
        out = []
        # mempool.space returns up to ~50 confirmed txs per page (+ mempool).
        txs = http_json(f"{API}/address/{address}/txs")
        for tx in txs:
            inputs = {vin.get("prevout", {}).get("scriptpubkey_address") for vin in tx.get("vin", [])}
            if address not in inputs:
                continue  # address is not spending here -> not outgoing
            st = tx.get("status", {})
            ep = st.get("block_time")
            if after_epoch is not None and ep is not None and ep < after_epoch:
                continue
            for vout in tx.get("vout", []):
                dest = vout.get("scriptpubkey_address")
                if not dest or dest in inputs:
                    continue  # skip change back to an input address
                amt = (vout.get("value") or 0) / 1e8
                if amt < floor:
                    continue
                out.append(Transfer(
                    chain="bitcoin", txid=tx.get("txid"), time=iso_from_epoch(ep), epoch=ep,
                    frm=address, to=dest, asset="BTC", amount=amt))
                if len(out) >= limit:
                    return out
        return out
