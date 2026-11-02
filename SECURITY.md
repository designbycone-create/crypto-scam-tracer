# Security and release signing

ScamHunter is built for people who have already been scammed. They should never have to take our word
for anything, including that an update really came from us.

## Every release is signed

- Each release carries `RELEASE.json`, a list of every file with its SHA-256 fingerprint, and
  `RELEASE.sig`, an Ed25519 signature over that list made with the maintainer's private key.
- The private key lives only on the maintainer's own computer. It is not in this repository, on GitHub,
  or with anyone else.
- The matching public key is built into the app (`release_sig.py`) and printed below.
- The Desk's **Updates** page checks the signature and every file before installing. If the signature
  is wrong, a file was changed, or the release was signed by a different key, **nothing is installed**
  and the page says why.

Maintainer public key: `c266c6598392a472899e7562045ddda9825d15d13a4d6584bcfd47bc4780c60e`

Maintainer public key fingerprint: **`fa946f505ab1ef57`**

## How a release is made

1. Changes land on the `main` branch. Nobody's Desk installs from `main`.
2. The maintainer signs one exact version on their own computer:
   `powershell -ExecutionPolicy Bypass -File tools\sign_release.ps1 -Sha <commit>`
   The script downloads that version from GitHub, checks it, and writes `RELEASE.json` and `RELEASE.sig`.
   The private key never leaves that computer.
3. Those two files are committed, the signature is verified again from a clean download, and only then
   does the `stable` branch move to that commit.
4. Installs and the Desk's Updates page use `stable`. An unsigned or altered version can't reach users.

## Check a copy yourself

You need only Python, nothing from ScamHunter. In the folder you downloaded:

    python release_sig.py verify .

It prints `VERIFIED` and the key fingerprint, or `NOT VERIFIED` and the reason. Compare the fingerprint
with the one above and with the one shown on the Desk's Updates page.

## What ScamHunter never does

- Never asks for a seed phrase, private key, password, or money.
- Never sends a message, report, or freeze request without you pressing send.
- Never uploads your case: everything stays on your computer except the public blockchain lookups it
  makes and the alerts you turn on.
- Never installs an update by itself.

## Reporting a security problem

Open a private security advisory on the GitHub repository (Security tab → Report a vulnerability).
Please don't post exploit details in public issues.
