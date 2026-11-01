"""evidence -- making ScamHunter output defensible in court.

What this package does (and what it can't):

  capture     Every external read (ledger servers, explorers, APIs) is saved
              raw, byte-for-byte, as a content-addressed blob (SHA-256) and
              logged in an append-only, hash-chained log -- INCLUDING reads
              answered from cache (a gap competitors admit to).
  facts       Separates three kinds of statement, because courts treat them
              differently:  FACT (directly on the public ledger, verifiable by
              anyone from a transaction hash), DERIVED (a deterministic
              computation over facts, e.g. a path), INFERENCE (a heuristic
              opinion -- named, versioned, with known failure modes).
  corroborate Every FACT is fetched from two independent ledger servers and
              must match field-for-field.
  package     A case bundle: report, facts, inferences, methodology, raw
              evidence blobs, manifest of SHA-256 hashes, custody log, tool
              version, and a certification template for the person who ran it.
  verify      A stand-alone, standard-library script anyone (an officer, the
              defense's expert) can run to check every hash, the log chain,
              that every FACT is present in the saved raw data, and -- online
              -- that the public ledger still says the same thing.

What no software can do: make evidence "admissible". A judge decides that,
on the testimony of a qualified person who sponsors the work (FRE 702 /
Ala. R. Evid. 702; authenticity via FRE 901 / 902(13)-(14)). This package
gives that person a record built to survive the questions they'll be asked.
"""
VERSION = "evidence-0.1"
