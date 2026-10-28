"""Thin XRP Ledger WebSocket client shared by every module."""
import asyncio
import json
from datetime import datetime, timezone

import websockets

SERVERS = ["wss://xrplcluster.com", "wss://s1.ripple.com", "wss://s2.ripple.com"]
DROPS = 1_000_000
RIPPLE_EPOCH = 946684800


def xrp(amount):
    """Drops string -> XRP float; token amounts -> None."""
    return int(amount) / DROPS if isinstance(amount, str) else None


def ripple_time(t):
    if t is None:
        return ""
    return datetime.fromtimestamp(t + RIPPLE_EPOCH, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class Ledger:
    """Usage: async with Ledger() as L: await L.account_info(addr)"""

    def __init__(self, servers=None):
        self.servers = servers or SERVERS
        self.ws = None
        self._id = 0

    async def __aenter__(self):
        last = None
        for s in self.servers:
            try:
                self.ws = await websockets.connect(s, ping_interval=20, ping_timeout=20, max_size=2**24)
                self.server = s
                return self
            except Exception as e:  # try next server
                last = e
        raise ConnectionError(f"No XRPL server reachable: {last!r}")

    async def __aexit__(self, *exc):
        if self.ws:
            await self.ws.close()

    async def rpc(self, command, **params):
        self._id += 1
        req = {"id": self._id, "command": command, **params}
        await self.ws.send(json.dumps(req))
        while True:
            msg = json.loads(await self.ws.recv())
            if msg.get("id") == req["id"]:
                if msg.get("status") == "error":
                    return {"error": msg.get("error"), **msg.get("result", {})}
                return msg.get("result", {})

    async def account_info(self, addr):
        r = await self.rpc("account_info", account=addr, ledger_index="validated", signer_lists=True)
        return r.get("account_data") if "error" not in r else None

    async def account_tx(self, addr, forward=True, max_pages=25):
        """All transactions for an account as normalized dicts (tx fields + meta + hash)."""
        out, marker = [], None
        for _ in range(max_pages):
            params = {"account": addr, "forward": forward, "limit": 200}
            if marker:
                params["marker"] = marker
            r = await self.rpc("account_tx", **params)
            for t in r.get("transactions", []):
                tx = dict(t.get("tx_json") or t.get("tx") or {})
                tx["hash"] = t.get("hash") or tx.get("hash")
                tx["_meta"] = t.get("meta", {})
                tx["_validated"] = t.get("validated", True)
                out.append(tx)
            marker = r.get("marker")
            if not marker:
                break
        return out


def run(coro):
    return asyncio.run(coro)
