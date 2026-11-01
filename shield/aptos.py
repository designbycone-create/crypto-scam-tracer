"""Aptos support (Move-based chain; addresses are 0x + 64 hex).

Data sources
  fullnode REST  "aptos_rpc" in config.json (e.g. NodeReal https://aptos-mainnet.nodereal.io/v1/<key>/v1),
                 else the public Aptos Labs fullnode. Gives account state and every transaction the
                 wallet SENT (full history), each with its events and state changes.
  indexer        optional "aptos_indexer_key" (free Geomi key, geomi.dev). Adds what the wallet RECEIVED
                 from others. Tried anonymously when no key is set; Aptos Labs rate-limits that.

How a transfer is read
  Fungible assets move between "stores" (objects). Each tx carries Withdraw/Deposit events naming the
  store, and state changes naming each store's owner (ObjectCore) and token (FungibleStore.metadata).
  Missing ones are looked up. Netting withdrawals and deposits per owner gives who paid whom, for plain
  transfers, swaps and arbitrary scripts alike. Legacy coin events (owner in the event guid) also count.

Aptos has no ERC-20-style approvals. What it does have, and what drainers abuse:
  * signer capability offers   -- someone was granted the power to act as your account
  * rotation capability offers -- someone was granted the power to replace your key
  * a rotated authentication key (the key that controls the account is no longer the original)
"""
import calendar
import json
import time
import urllib.error
import urllib.parse
import urllib.request

PUBLIC = "https://api.mainnet.aptoslabs.com/v1"
INDEXER = "https://api.mainnet.aptoslabs.com/v1/graphql"
APT = "0xa"
UA = {"User-Agent": "ScamHunter-Shield/0.3", "Content-Type": "application/json"}
STANDARD_TRANSFERS = {"0x1::aptos_account::transfer", "0x1::aptos_account::transfer_coins",
                      "0x1::aptos_account::transfer_fungible_assets", "0x1::aptos_account::batch_transfer",
                      "0x1::aptos_account::batch_transfer_coins", "0x1::coin::transfer",
                      "0x1::primary_fungible_store::transfer", "0x1::aptos_account::create_account"}
ADMIN_FUNCS = ("rotate_authentication_key", "offer_signer_capability", "offer_rotation_capability",
               "revoke_signer_capability", "revoke_rotation_capability")

GET = None       # test hook: f(path) -> parsed json (path relative to the REST base, e.g. "/accounts/0x1")
GQL = None       # test hook: f(query, variables) -> data dict


def _cfg(k):
    try:
        import scamconfig
        return (scamconfig.get(k) or "").strip()
    except Exception:
        return ""


def base():
    b = _cfg("aptos_rpc") or PUBLIC
    b = b.rstrip("/")
    return b if b.endswith("/v1") else b + "/v1"


def norm(a):
    """Canonical 0x + 64 lowercase hex (Aptos often drops leading zeros)."""
    a = (a or "").strip().lower()
    if a.startswith("0x"):
        a = a[2:]
    return "0x" + a.rjust(64, "0")


def short(a):
    """0x1, 0xa: special addresses as Aptos writes them."""
    h = norm(a)[2:].lstrip("0")
    return "0x" + (h or "0")


def get(path, retries=2):
    if GET:
        return GET(path)
    url = base() + path
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            if e.code == 429 and attempt < retries:
                time.sleep(2 * (attempt + 1))
                continue
            raise


def gql(query, variables=None):
    if GQL:
        return GQL(query, variables or {})
    hdr = dict(UA)
    if _cfg("aptos_indexer_key"):
        hdr["Authorization"] = "Bearer " + _cfg("aptos_indexer_key")
    body = json.dumps({"query": query, "variables": variables or {}}).encode()
    with urllib.request.urlopen(urllib.request.Request(INDEXER, data=body, headers=hdr), timeout=30) as r:
        d = json.loads(r.read())
    if d.get("errors"):
        raise RuntimeError(str(d["errors"])[:160])
    return d.get("data") or {}


# ---------------------------------------------------------------- metadata --
_META = {APT: ("APT", 8)}
_OWNER = {}


def asset_meta(meta_addr):
    """(symbol, decimals) for a fungible-asset metadata object, or a coin type string."""
    if not meta_addr:
        return ("?", 0)
    if "::" in meta_addr:                                  # legacy coin type, e.g. 0x1::aptos_coin::AptosCoin
        if meta_addr == "0x1::aptos_coin::AptosCoin":
            return ("APT", 8)
        key = meta_addr
        if key not in _META:
            try:
                addr = meta_addr.split("::")[0]
                d = get(f"/accounts/{addr}/resource/" + urllib.parse.quote(f"0x1::coin::CoinInfo<{meta_addr}>", safe=""))
                dd = (d or {}).get("data") or {}
                _META[key] = (dd.get("symbol") or meta_addr.split("::")[-1], int(dd.get("decimals") or 0))
            except Exception:
                _META[key] = (meta_addr.split("::")[-1], 0)
        return _META[key]
    k = short(meta_addr)
    if k not in _META:
        try:
            d = get(f"/accounts/{norm(meta_addr)}/resource/0x1::fungible_asset::Metadata")
            dd = (d or {}).get("data") or {}
            _META[k] = (dd.get("symbol") or "FA", int(dd.get("decimals") or 0))
        except Exception:
            _META[k] = ("FA", 0)
    return _META[k]


def store_owner(store):
    s = norm(store)
    if s not in _OWNER:
        try:
            d = get(f"/accounts/{s}/resource/0x1::object::ObjectCore")
            _OWNER[s] = norm(((d or {}).get("data") or {}).get("owner")) if d else None
        except Exception:
            _OWNER[s] = None
    return _OWNER[s]


def _store_meta(store):
    try:
        d = get(f"/accounts/{norm(store)}/resource/0x1::fungible_asset::FungibleStore")
        return (((d or {}).get("data") or {}).get("metadata") or {}).get("inner")
    except Exception:
        return None


# ---------------------------------------------------------------- parsing ---
def flows(tx):
    """Net movement per (owner, asset) in one transaction: {(owner, asset_id): raw_delta}."""
    owners, metas = {}, {}
    for c in tx.get("changes") or []:
        d = c.get("data") or {}
        t = d.get("type") or ""
        a = c.get("address")
        if not a:
            continue
        if t == "0x1::object::ObjectCore":
            owners[norm(a)] = norm((d.get("data") or {}).get("owner"))
        elif t == "0x1::fungible_asset::FungibleStore":
            metas[norm(a)] = ((d.get("data") or {}).get("metadata") or {}).get("inner")
    net = {}
    for e in tx.get("events") or []:
        t, d = e.get("type") or "", e.get("data") or {}
        sign = None
        if t == "0x1::fungible_asset::Withdraw":
            sign = -1
        elif t == "0x1::fungible_asset::Deposit":
            sign = 1
        if sign is not None:
            st = norm(d.get("store"))
            own = owners.get(st) or store_owner(st)
            meta = metas.get(st) or _store_meta(st)
            if own and meta:
                k = (own, short(meta))
                net[k] = net.get(k, 0) + sign * int(d.get("amount") or 0)
            continue
        if t in ("0x1::coin::WithdrawEvent", "0x1::coin::DepositEvent"):      # legacy CoinStore events
            own = norm(((e.get("guid") or {}).get("account_address")))
            ta = ((tx.get("payload") or {}).get("type_arguments") or ["0x1::aptos_coin::AptosCoin"])[0]
            k = (own, ta)
            net[k] = net.get(k, 0) + (1 if "Deposit" in t else -1) * int(d.get("amount") or 0)
    return {k: v for k, v in net.items() if v}


def moves_for(tx, wallet):
    """Normalized moves for `wallet` in tx: [{dir, cp, amount, asset, asset_id, t, hash}]."""
    w = norm(wallet)
    net = flows(tx)
    t = int(int(tx.get("timestamp") or 0) / 1_000_000)
    out = []
    for (own, aid), raw in net.items():
        if own != w:
            continue
        sym, dec = asset_meta(aid)
        others = {o: v for (o, a2), v in net.items() if a2 == aid and o != w and (v > 0) != (raw > 0)}
        cp = max(others, key=lambda o: abs(others[o])) if others else None
        out.append({"dir": "in" if raw > 0 else "out", "cp": cp, "amount": abs(raw) / 10 ** dec, "asset": sym,
                    "asset_id": aid, "t": t, "hash": tx.get("hash"), "version": tx.get("version"),
                    "function": (tx.get("payload") or {}).get("function") or (tx.get("payload") or {}).get("type")})
    return out


# ---------------------------------------------------------------- account ---
def account(addr):
    return get(f"/accounts/{norm(addr)}")


def sent_txs(addr, limit=400):
    """Transactions the wallet sent (full history, newest first, up to `limit`)."""
    acct = account(addr)
    if not acct:
        return [], None
    seq = int(acct.get("sequence_number") or 0)
    out, hi = [], seq
    while hi > 0 and len(out) < limit:
        lo = max(0, hi - 100)
        page = get(f"/accounts/{norm(addr)}/transactions?start={lo}&limit={hi - lo}") or []
        out += page[::-1]          # newest first
        hi = lo
    return out[:limit], acct


def received_indexer(addr, limit=300):
    """Deposits into the wallet from others, via the indexer: [{version, amount_raw, asset_id, t}] or None."""
    q = """query($a:String!,$n:Int!){ fungible_asset_activities(where:{owner_address:{_eq:$a},type:{_like:"%Deposit%"},
           is_transaction_success:{_eq:true}}, order_by:{transaction_version:desc}, limit:$n){
           transaction_version amount asset_type transaction_timestamp } }"""
    try:
        rows = gql(q, {"a": norm(addr), "n": limit}).get("fungible_asset_activities") or []
    except Exception:
        return None
    out = []
    for r in rows:
        try:
            ts = r.get("transaction_timestamp") or ""
            t = calendar.timegm(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")) if ts else 0
        except Exception:
            t = 0
        out.append({"version": int(r["transaction_version"]), "amount_raw": int(r.get("amount") or 0),
                    "asset_id": short(r["asset_type"]) if "::" not in (r.get("asset_type") or "") else r["asset_type"], "t": t})
    return out


def history(addr, limit=400):
    """Normalized history for the pre-screen."""
    txs, acct = sent_txs(addr, limit)
    moves, seen = [], set()
    for tx in txs:
        if tx.get("success") is False:
            continue
        for m in moves_for(tx, addr):
            moves.append(m)
            seen.add(tx.get("version"))
    sent_complete = acct is not None and len(txs) >= int((acct or {}).get("sequence_number") or 0)
    rec = received_indexer(addr)
    if rec:
        for r in rec:
            if str(r["version"]) in {str(v) for v in seen}:
                continue
            try:
                tx = get(f"/transactions/by_version/{r['version']}")
                ms = [m for m in moves_for(tx, addr) if m["dir"] == "in"]
            except Exception:
                ms = []
            if ms:
                moves += ms
            else:
                sym, dec = asset_meta(r["asset_id"])
                moves.append({"dir": "in", "cp": None, "amount": r["amount_raw"] / 10 ** dec, "asset": sym,
                              "asset_id": r["asset_id"], "t": r["t"], "hash": None})
    bal = balance(addr)
    complete = bool(sent_complete and rec is not None and len(rec) < 300)
    cov = None
    if rec is None:
        cov = ("Aptos: everything this wallet SENT was checked; payments it RECEIVED from others weren't (add a free "
               "Geomi key as \"aptos_indexer_key\" for that), so collector / pass-through checks are limited.")
    elif not sent_complete or len(rec) >= 300:
        cov = f"Aptos: the most recent {limit} sent and 300 received transactions were checked."
    exists = acct is not None or bool(moves) or (bal or 0) > 0
    return {"exists": exists, "moves": sorted(moves, key=lambda m: m["t"]), "balance": bal,
            "complete": complete, "coverage": cov, "created": None}


def balance(addr):
    """APT balance (fungible-asset store), in APT."""
    try:
        body = json.dumps({"function": "0x1::primary_fungible_store::balance", "type_arguments": ["0x1::fungible_asset::Metadata"],
                           "arguments": [norm(addr), APT]}).encode()
        if GET:
            r = GET("/view:balance")
        else:
            with urllib.request.urlopen(urllib.request.Request(base() + "/view", data=body, headers=UA), timeout=20) as resp:
                r = json.loads(resp.read())
        return int((r or ["0"])[0]) / 1e8
    except Exception:
        return None


# ---------------------------------------------------------------- shield ----
def approvals(wallet):
    return []      # Aptos (Move) has no token approvals; standing permissions are covered by takeover()


def takeover(wallet):
    w = norm(wallet)
    found = []
    acct = account(w)
    if not acct:
        return found
    ak = norm(acct.get("authentication_key"))
    if ak != w:
        found.append(("high", "The key that controls this Aptos account has been changed from the original "
                              "(authentication key rotated). If you didn't do this in your wallet app, someone else controls it."))
    try:
        res = ((get(f"/accounts/{w}/resource/0x1::account::Account") or {}).get("data")) or {}
    except Exception:
        res = {}
    for field, what in (("signer_capability_offer", "act as your account (sign anything)"),
                        ("rotation_capability_offer", "replace your account's key (take it over)")):
        who = (((res.get(field) or {}).get("for") or {}).get("vec") or [])
        if who:
            found.append(("danger", f"This account has offered {short(who[0])} the power to {what}. Normal wallets "
                                    "never do this. Revoke it from a trusted wallet now, or move your funds."))
    try:
        for tx in (sent_txs(w, 25)[0]):
            f = ((tx.get("payload") or {}).get("function") or "")
            if any(k in f for k in ADMIN_FUNCS):
                found.append(("high", f"Your account recently ran {f.split('::')[-1]} (version {tx.get('version')}). "
                                      "This changes who controls the account."))
                break
    except Exception:
        pass
    return found


def drains(wallet, limit=40):
    """Recent sent transactions where assets left via something other than a plain transfer
    (scripts, unknown contracts). On Aptos the wallet signs these itself, usually via a malicious
    'claim' or 'verify' prompt."""
    out = []
    txs, _ = sent_txs(wallet, limit)
    for tx in txs:
        if tx.get("success") is False:
            continue
        p = tx.get("payload") or {}
        f = p.get("function") or p.get("type") or ""
        lost = [m for m in moves_for(tx, wallet) if m["dir"] == "out"]
        if not lost or f in STANDARD_TRANSFERS:
            continue
        net = flows(tx)
        receivers = {}
        for (own, aid), v in net.items():
            if v > 0 and own != norm(wallet) and any(m["asset_id"] == aid for m in lost):
                sym, dec = asset_meta(aid)
                receivers[own] = receivers.get(own, 0) + v / 10 ** dec
        out.append({"chain": "aptos", "hash": tx.get("hash"), "time": int(int(tx.get("timestamp") or 0) / 1_000_000),
                    "tokens": [{"token": m["asset_id"], "symbol": m["asset"], "amount": m["amount"], "to": m["cp"]} for m in lost],
                    "tx_sender": norm(wallet), "drainer_contract": f.split("::")[0] if "::" in f else f,
                    "function": f, "receivers": receivers})
    return out


def explorer_tx(h):
    return f"https://explorer.aptoslabs.com/txn/{h}?network=mainnet"


def explorer_addr(a):
    return f"https://explorer.aptoslabs.com/account/{norm(a)}?network=mainnet"
