# Setting up ScamHunter Desk

A step-by-step guide for a new user on Windows. It takes about 10 minutes, plus a few optional
free keys you can add later. ScamHunter is free, and it will never ask you for money or a wallet
recovery (seed) phrase.

---

## 1. Install

**Option A: the install line (recommended).**

1. Click the Start menu, type **PowerShell**, press **Enter**.
2. Paste this line and press **Enter**:

   ```powershell
   irm https://raw.githubusercontent.com/designbycone-create/crypto-scam-tracer/stable/install.ps1 | iex
   ```

3. Wait about two minutes. It installs Python if needed, puts ScamHunter in
   `C:\Users\<you>\ScamHunter`, adds a **ScamHunter Desk** shortcut to your Desktop and Start
   menu, and opens the Desk in your browser.

**Option B: a share copy (a zip someone gave you).** Unzip it, open the `ScamHunter` folder, and
double-click **INSTALL.cmd**. It checks the copy's signature first and refuses to install a copy
that has been changed.

No administrator rights are needed either way. Every release is signed; the Desk's
**Settings → Updates** page shows the signing key, which should be **`fa946f505ab1ef57`**.

## 2. First start: your case (or skip it)

The Desk opens at **http://127.0.0.1:8787**. That address only works on this computer: other
computers, phones and the internet can't open your Desk.

- **If you lost crypto to a scam:** paste the transaction ID (or explorer link) of the payment you
  sent. The Desk fills in the scammer's wallet, your wallet, the amount and the time. Your name,
  email and IC3 number are optional and are only used in drafts *you* choose to send.
- **If you're here to protect yourself:** skip the case. Everything under **Phone & Messages**
  and **Online Defense** works without one.

Press **Start tracking**, or **I haven't lost anything — just protect me**, and you're on the
**Overview**. (You can add a case later in **Settings → Case setup**.)

## 3. Finding your way around

Every page has the same tabs across the top:

| Tab | Use it to |
|---|---|
| **Overview** | See everything at a glance: status, the scam-call map, the latest warning, the live feed. |
| **Crypto & Wallets** | Check an address before you send; protect your wallet; follow stolen funds; draft freeze requests; build evidence. |
| **Phone & Messages** | Check a phone number or a message. |
| **Online Defense** | Windows Defender and download / link checks; secrets left in files; the browser extension; your home network's exposure; AI-agent firewall. |
| **Settings** | Phone alerts, updates, case setup, sharing ScamHunter. |

## 4. Optional free keys (each adds more checks)

Each key is your own, entered on the Desk, and **stored encrypted** so only your Windows account
on this computer can read it. You only ever see a short Key ID afterwards.

| Key | Where to get it | Where to paste it | What it adds |
|---|---|---|---|
| **FTC data** | [api.data.gov/signup](https://api.data.gov/signup/) (name + email; the key arrives by email) | Phone & Messages → **Check a phone number** → *FTC data key* | The list of phone numbers reported to the FTC as scams / robocalls, and the scam-call map |
| **abuse.ch** | [auth.abuse.ch](https://auth.abuse.ch/): sign in with Google, GitHub, X or LinkedIn, connect a second sign-in, **Save profile**, then create the **Auth-Key** under *Optional* | Online Defense → **Malware & link check** → *abuse.ch lookups* | Known-malware files (MalwareBazaar) and malware links (URLhaus, ThreatFox). Free for personal, not-for-profit use |
| **Etherscan** | [etherscan.io/apis](https://etherscan.io/apis) (free account) | Settings → **Case setup** | Tracing on Ethereum and the chains built on it (Bitcoin and Tron need no key) |

## 5. Alerts on your phone (recommended)

**Settings → Alerts to your phone.** Connect Telegram (about two minutes, no typing commands) and
the free ntfy app. If a watched wallet moves money, or something urgent is found, you get a push
message. Use two channels so one being down never loses an alert.

## 6. The browser extension (recommended)

**Online Defense → Browser extension** walks you through adding it to Chrome or Edge. It blocks
address-swapping, wallet-draining pages and known attack scripts, and checks what you paste.

## 7. Updates

**Settings → Updates.** One click. Every update is signature-checked, backed up, self-tested,
and rolled back automatically if anything fails.

---

## Your privacy

- Everything runs on your computer. Your case is kept in files in the ScamHunter folder
  (`config.json`, `victim.json`, `submissions.json`, evidence and logs) that are **never** part of
  the program: they're not in updates, not on GitHub, and not in a share copy.
- Keys are encrypted with Windows' own protection.
- Lookups that do leave your computer go only to the service named on the page you're using
  (for example a blockchain explorer, the FTC, or abuse.ch), and only for what you asked about.
- To give ScamHunter to someone else: **Settings → Share ScamHunter**. It gives you a ready-to-send
  message with the install line, or makes a share copy that's checked against your own case
  details first.

## Uninstall

Close the Desk, delete the `C:\Users\<you>\ScamHunter` folder, and delete the **ScamHunter Desk**
shortcuts from the Desktop, the Start menu and the Startup folder (`shell:startup` in the Run box).

## Getting help

Open an issue at <https://github.com/designbycone-create/crypto-scam-tracer/issues>.
Please don't post your wallet addresses, transaction IDs, IC3 number or keys there.
