# Notice

**Code.** The source code in this repository is copyright (c) 2026 Matthew Cone /
FPH LLC and is licensed under the MIT License (see `LICENSE`). Development was
AI-assisted under the author's direction.

**Name and branding.** "ScamHunter Threat Desk™", "ScamHunter™" and the related logos (and the
earlier name "ScamHunter Desk™") are trademarks of FPH LLC. The MIT License covers the code, not the names: you may
use, change and redistribute the code, but a fork or derivative product must use
its own name and must not suggest it is made or endorsed by ScamHunter Threat Desk or
FPH LLC. This keeps victims able to tell the genuine, free tool from
impersonations — which matters, because recovery scammers impersonate trusted
tools.

**Editions.** This repository is the free victim edition and stays free and
open-source. A separate institutional edition (multi-case workspaces, agency
packets, signed evidence bundles) is developed privately by FPH LLC. See
`ROADMAP.md`.

Contact: open an issue at https://github.com/designbycone-create/crypto-scam-tracer/issues

## Third-party material included

| What | Where | Source | License |
|---|---|---|---|
| BIP-39 English word list (2048 words), used to recognise seed phrases saved in files | `shield/bip39_english.txt` | [python-mnemonic 0.21](https://github.com/trezor/python-mnemonic) by Trezor, copyright (c) 2013-2016 Pavol Rusnak; the word list is the one defined in [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt) (SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`) | MIT, see `third_party/python-mnemonic-LICENSE.txt` |
| US state outlines for the Desk's scam-call map (simplified and pre-drawn) | `deskui/us_states.json` | [us-atlas 3.0.1](https://github.com/topojson/us-atlas), copyright 2013-2019 Michael Bostock, built from US Census Bureau cartographic boundary files (public domain) | ISC, see `third_party/us-atlas-LICENSE.txt` |
| World country outlines for the Threat Map (simplified and pre-drawn) | `threatmap/world.json` | [world-atlas 2.0.2](https://github.com/topojson/world-atlas) countries-110m, copyright 2013-2019 Michael Bostock, built from [Natural Earth](https://www.naturalearthdata.com) (public domain) | ISC, see `third_party/world-atlas-LICENSE.txt` |
| Country names and codes for the Threat Map | `threatmap/country_names.json`, `threatmap/world.json` | [i18n-iso-countries 7.14.0](https://github.com/michaelwittig/node-i18n-iso-countries), copyright (c) 2016 Michael Wittig | MIT, see `third_party/i18n-iso-countries-LICENSE.txt` |

| QR code scanner in the Threat Desk phone app | `android/desk/` (Gradle dependency, not copied into this repository) | [ZXing Android Embedded 4.3.0](https://github.com/journeyapps/zxing-android-embedded) (copyright JourneyApps), with [ZXing](https://github.com/zxing/zxing) core and AndroidX Core / Fragment | Apache-2.0, see `third_party/zxing-android-embedded-LICENSE.txt` |

**Python libraries installed with the Desk** (pinned with their published hashes in `requirements.txt`, not copied into
this repository): websockets (BSD-3-Clause), certifi (MPL-2.0), reportlab (BSD), pillow (MIT-CMU), charset-normalizer (MIT),
cryptography (Apache-2.0 or BSD-3-Clause), cffi (MIT-0), pycparser (BSD-3-Clause), segno (BSD-3-Clause).

**Separate programs the Desk can start, not included:** "Look up a scammer" runs
[Maigret](https://github.com/soxoj/maigret) (MIT) and [SpiderFoot](https://github.com/smicallef/spiderfoot) (MIT)
if you have installed them yourself. The Desk starts them and reads their results; none of their code is part
of this repository. AGPL-licensed tools are never bundled or linked; they may only be run as separate programs.

**Downloaded at run time, not included:** the Threat Map's server locations use
[IP Geolocation by DB-IP](https://db-ip.com) (free country file, CC BY 4.0), downloaded
monthly to your computer. Threat Map feeds are fetched from each source and keep their own terms:
FBI IC3 and CISA KEV (US government works), abuse.ch Feodo Tracker (CC0), abuse.ch ThreatFox and
URLhaus (abuse.ch terms, not-for-profit use, your own key), and news headlines with links only
(The Record, BleepingComputer, Krebs on Security); article text is never copied. Posts from named
security researchers and newsrooms on Bluesky and Mastodon are read through each network's free public
API and shown as the author's name, a link, and at most the first 120 characters, credited to the author.
