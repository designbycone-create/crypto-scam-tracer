"""Build the right adapter for a chain key. Lazy imports avoid a circular
dependency (adapters import core)."""
from .core import chain


def get_adapter(chain_key):
    info = chain(chain_key)
    if info.key == "bitcoin":
        from .adapters.btc import BitcoinAdapter
        return BitcoinAdapter(info)
    if info.key == "tron":
        from .adapters.tron import TronAdapter
        return TronAdapter(info)
    if info.key == "solana":
        from .adapters.solana import SolanaAdapter
        return SolanaAdapter(info)
    if info.evm_chainid is not None:
        from .adapters.evm import EvmAdapter
        return EvmAdapter(info)
    raise ValueError(f"No adapter for chain '{chain_key}'")
