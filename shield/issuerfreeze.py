"""Is USDT or USDC at this address frozen by Tether or Circle? Read straight from their contracts.

Tether and Circle keep their freeze (blacklist) lists inside the token contracts, so the answer
comes from the blockchain itself, not from a third party. A frozen address can't move that token:
anything sent there is stuck, and the freeze usually means sanctions or a crime report.

Contracts verified on Nov 16, 2026 (symbol and name read from each contract, and the sanctioned
Lazarus Group address 0x0872...7243 confirmed frozen on every one).

    python -m shield.issuerfreeze <address> [chain]
"""
import sys

EVM = {   # chain -> [(token, issuer, contract, selector)]
    "ethereum": [("USDT", "Tether", "0xdAC17F958D2ee523a2206206994597C13D831ec7", "e47d6060"),    # isBlackListed(address)
                 ("USDC", "Circle", "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "fe575a87")],   # isBlacklisted(address)
    "base": [("USDC", "Circle", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "fe575a87")],
    "arbitrum": [("USDC", "Circle", "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", "fe575a87")],
    "polygon": [("USDC", "Circle", "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", "fe575a87")],
    "optimism": [("USDC", "Circle", "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", "fe575a87")],
    "avalanche": [("USDC", "Circle", "0xB97EF9Ef8734C71904D8002F8b6Bc66Dd9c48a6E", "fe575a87")],
}
TRON_USDT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


def check(addr, chain):
    """[{"token", "issuer", "chain", "frozen": bool|None}] for the stablecoins we can read on this chain.
    frozen None = couldn't read it right now (never reported as 'not frozen')."""
    out = []
    if chain in EVM and addr.lower().startswith("0x") and len(addr) == 42:
        from shield import evm
        for token, issuer, contract, sel in EVM[chain]:
            try:
                r = evm.call(chain, contract, "0x" + sel + "0" * 24 + addr.lower()[2:])
                frozen = bool(int(r, 16)) if r and r != "0x" else None
            except Exception:
                frozen = None
            out.append({"token": token, "issuer": issuer, "chain": chain, "frozen": frozen})
    elif chain == "tron" and addr.startswith("T"):
        from shield import tron
        try:
            h = tron.to_hex20(addr)
            r = tron._const(TRON_USDT, TRON_USDT, "isBlackListed(address)", "0" * 24 + h) if h else None
            frozen = bool(int(r, 16)) if r else None
        except Exception:
            frozen = None
        out.append({"token": "USDT", "issuer": "Tether", "chain": "tron", "frozen": frozen})
    return out


def findings(addr, chain):
    """(level, text) lines for the pre-screen."""
    res = []
    for r in check(addr, chain):
        if r["frozen"]:
            res.append(("stop", f"{r['issuer']} has frozen {r['token']} at this address on {chain}. {r['token']} sent here "
                                "can't be moved, and a freeze usually follows sanctions or a crime report."))
    return res


def freezeradar_url(addr):
    return "https://freezeradar.com/explorer?address=" + addr


if __name__ == "__main__":
    a = sys.argv[1]
    ch = sys.argv[2] if len(sys.argv) > 2 else ("tron" if a.startswith("T") else "ethereum")
    for r in check(a, ch):
        print(r)
