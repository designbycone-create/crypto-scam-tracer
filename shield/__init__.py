"""shield -- DRAFT protection layer (not yet wired into the Desk).

Retail protection around the wallet, and front-end monitoring for protocols:

  evm          shared EVM plumbing (logs, token transfers, eth_call), key-less
               where Blockscout covers the chain, Etherscan V2 key otherwise
  approvals    "Check my wallet": every open token approval (ERC-20, NFT
               ApprovalForAll, Permit2), current allowance read live, flagged
               against threat intel, with one-click revoke links
  drain        "I signed something": finds the drain transactions that pulled
               tokens out using an approval, the drainer contract, where the
               funds went, and a likely kit fee wallet; seeds the tracer
  sitewatch    "A site I use changed": watches real dApp domains for DNS,
               registrar, lock, certificate and script changes (hijack signals)
  compromised  same-day list of hijacked / drainer domains (paste from an
               incident post); checked by the claim checker

See shield/INTEGRATION.md for how to plug this into the Desk.
"""
