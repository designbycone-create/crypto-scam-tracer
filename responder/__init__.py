"""responder -- incident response and early warning.

  incident   -- paste attacker / scam addresses from ANY chain (or subscribe to
                public address feeds); XRPL ones are watched live, others are
                seeded into the multi-chain tracer.
  risk       -- early-warning signals on network wallets: brand-new accounts,
                fan-in (victim collectors), fan-out (laundering), drained
                wallets, mixer-funded / EIP-7702-delegated EVM wallets.
  status     -- exchange status-page awareness (where a public status API exists).
  radar      -- post-incident scam radar: watches public Certificate
                Transparency logs for new "refund / compensation / claim"
                lookalike domains.
  claimcheck -- paste a message, link or address: lists red flags and whether
                anything in it is already known to belong to the scam network.
"""
