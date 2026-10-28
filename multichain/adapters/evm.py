"""EVM adapter via the Etherscan V2 multichain API -- ONE free API key works
across Ethereum, Polygon, BSC, Arbitrum, Base, Optimism, Avalanche, etc. (the
chainid parameter selects the chain). Covers native coin and ERC20 tokens.

The key is the only manual setup step in the whole tool. Set it once:
    setx ETHERSCAN_API_KEY <key>      (Windows, persistent)
or drop it in a file `etherscan.key` next to the tool. Until then, EVM chains
are simply skipped and BTC + Tron run fully automated with no key.
Get a free key at https://etherscan.io/apis .
"""
import os

from ..core import Adapter, Transfer, iso_from_epoch
from ..util import http_json

V2 = "https://api.etherscan.io/v2/api"


def api_key():
    k = os.environ.get("ETHERSCAN_API_KEY", "").strip()
    if k:
        return k
    try:
        import scamconfig
        if scamconfig.get("etherscan_key"):
            return scamconfig.get("etherscan_key").strip()
    except Exception:
        pass
    for p in ("etherscan.key", os.path.expanduser("~/etherscan.key")):
        if os.path.exists(p):
            try:
                with open(p, encoding="utf-8") as f:
                    return f.read().strip()
            except Exception:
                pass
    return ""


class EvmAdapter(Adapter):
    def available(self):
        return (bool(api_key()),
                "" if api_key() else "no Etherscan API key (set ETHERSCAN_API_KEY or etherscan.key); EVM chains skipped")

    def _q(self, **params):
        params.update({"chainid": self.info.evm_chainid, "apikey": api_key()})
        data = http_json(V2, params=params)
        if isinstance(data, dict) and data.get("status") == "0" and "result" in data \
                and not isinstance(data["result"], list):
            return []   # "No transactions found" etc.
        return data.get("result", []) if isinstance(data, dict) else []

    def outgoing(self, address, after_epoch=None, min_native=None, limit=200):
        floor = self.info.min_native if min_native is None else min_native
        out = []
        native = self.info.native
        for tx in self._q(module="account", action="txlist", address=address,
                          startblock=0, endblock=99999999, page=1, offset=200, sort="desc"):
            try:
                if (tx.get("from") or "").lower() != address.lower():
                    continue
                if tx.get("isError") == "1":
                    continue
                ep = int(tx.get("timeStamp"))
                if after_epoch is not None and ep < after_epoch:
                    continue
                amt = int(tx.get("value", "0")) / 1e18
                if amt < floor:
                    continue
                out.append(Transfer(chain=self.key, txid=tx.get("hash"), time=iso_from_epoch(ep),
                                    epoch=ep, frm=address, to=tx.get("to"), asset=native, amount=amt))
            except Exception:
                continue
        for t in self._q(module="account", action="tokentx", address=address,
                         startblock=0, endblock=99999999, page=1, offset=200, sort="desc"):
            try:
                if (t.get("from") or "").lower() != address.lower():
                    continue
                ep = int(t.get("timeStamp"))
                if after_epoch is not None and ep < after_epoch:
                    continue
                dec = int(t.get("tokenDecimal") or 18)
                amt = int(t.get("value", "0")) / (10 ** dec)
                out.append(Transfer(chain=self.key, txid=t.get("hash"), time=iso_from_epoch(ep),
                                    epoch=ep, frm=address, to=t.get("to"),
                                    asset=t.get("tokenSymbol") or "TOKEN", amount=amt,
                                    contract=(t.get("contractAddress") or "").lower()))
            except Exception:
                continue
        out.sort(key=lambda z: z.epoch or 0, reverse=True)
        return out[:limit]
