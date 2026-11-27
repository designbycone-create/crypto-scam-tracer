"""Recognise a pasted recovery phrase (12-24 BIP-39 words) so the Desk can refuse it on sight: never stored, never
sent, never echoed back. Used by the quick check and the hardware wallet check's "Watch this wallet" box."""
import os
import re

_LIST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "shield", "bip39_english.txt")
try:
    with open(_LIST, encoding="utf-8") as f:
        WORDS = {w.strip() for w in f if w.strip()}
except OSError:                       # fail closed: without the list, any run of 12+ plain words counts
    WORDS = set()


def looks_like_seed(text):
    toks = re.findall(r"[A-Za-z]+", text or "")
    if not 12 <= len(toks) <= 25:
        return False
    if re.search(r"[0-9]|[^\sA-Za-z0-9,.;:\-]", text or ""):   # addresses, numbers, links, quotes: not a bare word list
        return False
    if not WORDS:
        return True
    hits = sum(1 for t in toks if t.lower() in WORDS)
    return hits >= 0.9 * len(toks)


def is_word_run(text):
    """Any run of plain words (the address box expects ONE address, so this is refused too)."""
    toks = (text or "").split()
    return len(toks) >= 2 and all(re.fullmatch(r"[A-Za-z]+[,.;:]?", t) for t in toks)
