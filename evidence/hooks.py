"""Install evidence capture on every network chokepoint the tool uses, without
editing each module: wraps the functions at import time.

    from evidence import hooks; hooks.install()

Wrapped:
  multichain.util.http_json            (BTC, Tron, EVM explorers, label lists)
  scam_investigator.attribution._rpc   (XRPL JSON-RPC: attribution, pre-screen, kits)
  scam_investigator.ledger.Ledger.rpc  (XRPL WebSocket: tracing, mapping)
  shield.evm._get / shield.evm.rpc     (EVM explorers + RPC)
  shield.tron._get / _post, multichain.adapters.solana.rpc
"""
import functools
import importlib

from . import capture

_done = set()


def _wrap_sync(mod_name, attr, source, req_fmt):
    try:
        mod = importlib.import_module(mod_name)
    except Exception:
        return False
    fn = getattr(mod, attr, None)
    if fn is None or getattr(fn, "_evidence", False) or (mod_name, attr) in _done:
        return False

    @functools.wraps(fn)
    def wrapper(*a, **kw):
        try:
            res = fn(*a, **kw)
        except Exception as e:
            capture.record(source, attr, req_fmt(a, kw), {"error": repr(e)[:300]}, status="error")
            raise
        capture.record(source, attr, req_fmt(a, kw), res)
        return res
    wrapper._evidence = True
    setattr(mod, attr, wrapper)
    _done.add((mod_name, attr))
    return True


def _ledger_ws():
    try:
        from scam_investigator import ledger
    except Exception:
        return False
    orig = ledger.Ledger.rpc
    if getattr(orig, "_evidence", False):
        return False

    async def rpc(self, command, **params):
        res = await orig(self, command, **params)
        capture.record(f"xrpl-ws:{getattr(self, 'server', '?')}", command, params, res,
                       status="error" if isinstance(res, dict) and res.get("error") else "ok")
        return res
    rpc._evidence = True
    ledger.Ledger.rpc = rpc
    return True


def install():
    n = 0
    n += _wrap_sync("multichain.util", "http_json", "http",
                    lambda a, kw: {"url": a[0] if a else kw.get("url"), "params": kw.get("params") or (a[1] if len(a) > 1 else None)})
    n += _wrap_sync("scam_investigator.attribution", "_rpc", "xrpl-jsonrpc",
                    lambda a, kw: {"method": a[0] if a else None, "params": a[1] if len(a) > 1 else None})
    n += _wrap_sync("shield.evm", "_get", "evm-explorer", lambda a, kw: {"url": a[0] if a else None})
    n += _wrap_sync("shield.evm", "rpc", "evm-rpc",
                    lambda a, kw: {"chain": a[0], "method": a[1], "params": a[2]} if len(a) > 2 else {"args": repr(a)[:300]})
    n += _wrap_sync("shield.tron", "_get", "tron", lambda a, kw: {"path": a[0] if a else None})
    n += _wrap_sync("shield.tron", "_post", "tron", lambda a, kw: {"path": a[0], "body": a[1]} if len(a) > 1 else {})
    n += _wrap_sync("multichain.adapters.solana", "rpc", "solana",
                    lambda a, kw: {"method": a[0], "params": a[1]} if len(a) > 1 else {})
    n += _ledger_ws()
    return n
