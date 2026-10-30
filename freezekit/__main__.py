import argparse

from . import custody, kit, xrpl_tokens


def main():
    p = argparse.ArgumentParser(prog="freezekit", description="Build freeze kits / verify evidence custody.")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build", help="(Re)build all freeze kits from the watchers' maps")
    sub.add_parser("tokens", help="Scan network wallets for freezable issued tokens (RLUSD etc.)")
    sub.add_parser("verify", help="Verify the hash-chained custody log")
    a = p.parse_args()
    if a.cmd == "build":
        r = kit.build()
        print(f"{len(r['targets'])} target(s); {len(r['changed'])} file(s) changed. See freeze_kits/")
    elif a.cmd == "tokens":
        r = xrpl_tokens.scan(xrpl_tokens.network_wallets())
        print(f"{len(r['holdings'])} issued-token holding(s) across {r['wallets_scanned']} wallet(s).")
    else:
        ok, n, bad = custody.verify_log()
        print(f"custody log: {'INTACT' if ok else 'TAMPERED at line ' + str(bad)} ({n} entries)")


if __name__ == "__main__":
    main()
