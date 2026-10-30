"""Chain-agnostic core: a normalized Transfer, the Adapter contract every chain
implements, and the chain registry.

The whole point of the multi-chain tracer is that the engine, the map, and the
report generator never care which blockchain they are looking at. They speak
only in Transfers and Nodes. Each supported chain provides an Adapter that
turns that chain's raw API into Transfers; adding a chain later means writing
one adapter and registering it -- nothing in the engine changes.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class Transfer:
    """One value movement, normalized across every chain.

    amount is human units of `asset` (e.g. 0.5 BTC, 1200.0 USDT), not base
    units. `contract` is the token contract address for token transfers (None
    for native coin). `dest_tag`/`memo` carry an exchange deposit routing id
    where the chain has one (XRPL destination tag, etc.)."""
    chain: str
    txid: str
    time: str                      # ISO-8601 UTC
    epoch: Optional[int]           # unix seconds, for time-forward ordering
    frm: str
    to: str
    asset: str                     # "BTC", "ETH", "TRX", "USDT", "USDC", ...
    amount: float
    contract: Optional[str] = None
    dest_tag: Optional[str] = None
    memo: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class ChainInfo:
    key: str                       # "bitcoin", "ethereum", "tron", "polygon", ...
    name: str
    native: str                    # native asset symbol
    kind: str                      # "utxo" or "account"
    tx_url: str                    # format string with {txid}
    addr_url: str                  # format string with {addr}
    min_native: float = 0.0        # default dust floor in native units
    evm_chainid: Optional[int] = None   # set for EVM chains (Etherscan V2)

    def explorer_tx(self, txid):
        return self.tx_url.format(txid=txid)

    def explorer_addr(self, addr):
        return self.addr_url.format(addr=addr)


# ---- supported chains ----------------------------------------------------
# EVM chains all share one adapter (Etherscan V2 multichain) keyed by chainid.
CHAINS = {
    "bitcoin":  ChainInfo("bitcoin", "Bitcoin", "BTC", "utxo",
                          "https://mempool.space/tx/{txid}",
                          "https://mempool.space/address/{addr}", min_native=0.0005),
    "tron":     ChainInfo("tron", "Tron", "TRX", "account",
                          "https://tronscan.org/#/transaction/{txid}",
                          "https://tronscan.org/#/address/{addr}", min_native=1.0),
    "ethereum": ChainInfo("ethereum", "Ethereum", "ETH", "account",
                          "https://etherscan.io/tx/{txid}",
                          "https://etherscan.io/address/{addr}", min_native=0.005, evm_chainid=1),
    "polygon":  ChainInfo("polygon", "Polygon", "POL", "account",
                          "https://polygonscan.com/tx/{txid}",
                          "https://polygonscan.com/address/{addr}", min_native=1.0, evm_chainid=137),
    "bsc":      ChainInfo("bsc", "BNB Smart Chain", "BNB", "account",
                          "https://bscscan.com/tx/{txid}",
                          "https://bscscan.com/address/{addr}", min_native=0.02, evm_chainid=56),
    "arbitrum": ChainInfo("arbitrum", "Arbitrum One", "ETH", "account",
                          "https://arbiscan.io/tx/{txid}",
                          "https://arbiscan.io/address/{addr}", min_native=0.005, evm_chainid=42161),
    "base":     ChainInfo("base", "Base", "ETH", "account",
                          "https://basescan.org/tx/{txid}",
                          "https://basescan.org/address/{addr}", min_native=0.005, evm_chainid=8453),
    "optimism": ChainInfo("optimism", "Optimism", "ETH", "account",
                          "https://optimistic.etherscan.io/tx/{txid}",
                          "https://optimistic.etherscan.io/address/{addr}", min_native=0.005, evm_chainid=10),
    "solana":   ChainInfo("solana", "Solana", "SOL", "account",
                          "https://solscan.io/tx/{txid}",
                          "https://solscan.io/account/{addr}", min_native=0.05),
    "avalanche":ChainInfo("avalanche", "Avalanche C-Chain", "AVAX", "account",
                          "https://snowtrace.io/tx/{txid}",
                          "https://snowtrace.io/address/{addr}", min_native=0.1, evm_chainid=43114),
}


def chain(key):
    c = CHAINS.get((key or "").lower())
    if not c:
        raise ValueError(f"Unknown chain '{key}'. Known: {', '.join(sorted(CHAINS))}")
    return c


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def iso_from_epoch(ep):
    if ep is None:
        return None
    return datetime.fromtimestamp(ep, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


class Adapter:
    """A chain adapter. Subclasses implement outgoing(); everything else is
    provided. Adapters are stateless and cheap to construct."""
    def __init__(self, info: ChainInfo):
        self.info = info

    @property
    def key(self):
        return self.info.key

    def outgoing(self, address, after_epoch=None, min_native=None, limit=200):
        """Return outgoing Transfers from `address` at time >= after_epoch,
        above the native/token floor, newest-first truncated to `limit`.
        Must be implemented per chain."""
        raise NotImplementedError

    def available(self):
        """(ok: bool, reason: str) — whether this adapter can run right now
        (e.g. EVM needs an API key)."""
        return True, ""
