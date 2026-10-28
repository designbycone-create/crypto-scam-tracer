"""Tron adapter via TronGrid (free, no API key). Covers native TRX and TRC20
tokens (USDT-TRC20 is the single most common laundering asset, so this matters).

?visible=true makes TronGrid return base58 (T...) addresses so we never have to
do hex<->base58 conversion ourselves (no dependency).
"""
from ..core import Adapter, Transfer, iso_from_epoch
from ..util import http_json

API = "https://api.trongrid.io"


class TronAdapter(Adapter):
    def outgoing(self, address, after_epoch=None, min_native=None, limit=200):
        floor = self.info.min_native if min_native is None else min_native
        out = []
        out += self._native(address, after_epoch, floor, limit)
        out += self._trc20(address, after_epoch, limit)
        out.sort(key=lambda t: t.epoch or 0, reverse=True)
        return out[:limit]

    def _native(self, address, after_epoch, floor, limit):
        res = []
        try:
            data = http_json(f"{API}/v1/accounts/{address}/transactions",
                             params={"only_from": "true", "limit": 100, "visible": "true"})
        except Exception:
            return res
        for tx in data.get("data", []):
            try:
                c = tx["raw_data"]["contract"][0]
                if c.get("type") != "TransferContract":
                    continue
                v = c["parameter"]["value"]
                ms = tx.get("block_timestamp")
                ep = int(ms / 1000) if ms else None
                if after_epoch is not None and ep is not None and ep < after_epoch:
                    continue
                amt = (v.get("amount") or 0) / 1e6
                if amt < floor:
                    continue
                res.append(Transfer(chain="tron", txid=tx.get("txID"), time=iso_from_epoch(ep),
                                    epoch=ep, frm=v.get("owner_address"), to=v.get("to_address"),
                                    asset="TRX", amount=amt))
            except Exception:
                continue
        return res

    def _trc20(self, address, after_epoch, limit):
        res = []
        try:
            data = http_json(f"{API}/v1/accounts/{address}/transactions/trc20",
                             params={"only_from": "true", "limit": 100, "visible": "true"})
        except Exception:
            return res
        for t in data.get("data", []):
            try:
                if (t.get("from") or "").lower() != address.lower():
                    continue
                ms = t.get("block_timestamp")
                ep = int(ms / 1000) if ms else None
                if after_epoch is not None and ep is not None and ep < after_epoch:
                    continue
                ti = t.get("token_info", {})
                dec = int(ti.get("decimals", 6))
                amt = int(t.get("value", 0)) / (10 ** dec)
                res.append(Transfer(chain="tron", txid=t.get("transaction_id"), time=iso_from_epoch(ep),
                                    epoch=ep, frm=t.get("from"), to=t.get("to"),
                                    asset=ti.get("symbol") or "TRC20", amount=amt,
                                    contract=ti.get("address")))
            except Exception:
                continue
        return res
