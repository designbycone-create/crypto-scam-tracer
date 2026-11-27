# ScamHunter Threat Desk — Night Desk redesign

Build-from spec for the desktop Desk (1440 and 1024) and the phone app (Samsung Galaxy A25, 390 CSS px).

People using this are everyday adults, including seniors and people who have just been scammed. The screen can look like an instrument panel. The words stay plain. Each card has one main action.

Style reference is the mood of a dark operations console: ink background, teal signal light, amber caution, large type. Do not copy OsirisAI.live code, logos, images, or text. Fonts are Google Fonts only. Icons are inline SVG drawn for this product. No paid assets. No remote images.

Do not use the words **safe**, **genuine**, or **verified** on any result screen, status, or button.

## 0. How to read the mocks

Open these files in a browser. They are static HTML + `desk.css`. The only network request is Google Fonts.

| File | What it shows |
| --- | --- |
| `overview.html` | Desktop shell, tabs, Overview |
| `components.html` | Every shared part, including states |
| `layouts.html` | Checker, table, map, form, settings |
| `hardware-wallet.html` | New hardware wallet check, screen by screen |
| `my-website.html` | PatchPulse coming soon, then the later list |
| `phone.html` | Phone shell, safe areas, Home and a check |

Desktop type in the mocks is `rem` with the browser default root (16px). `1.25rem` = 20px. Do not set `html { font-size: 16px }` or any other px lock. Windows text scaling and browser zoom must be able to enlarge every control.

---

## 1. Design tokens

### Color

Measure contrast on the surface the text actually sits on. Body text is 20px regular on desktop and 18px regular on the phone, so it needs WCAG AA **4.5:1**, not the large-text 3:1 exception. These pairs all clear 4.5:1. Most clear 7:1.

| Token | Hex | Role |
| --- | --- | --- |
| `--bg` | `#071018` | Page background |
| `--bg-raised` | `#0E1724` | Sticky header, group menu, secondary fills |
| `--bg-sunken` | `#0A121C` | Inputs, sunken rows |
| `--card` | `#132033` | Cards, table body |
| `--card-2` | `#1A2940` | Hover row, nested well |
| `--line` | `#2C415C` | Hairline borders |
| `--line-strong` | `#3D5678` | Input borders, stronger dividers |
| `--text` | `#F7F8FB` | Primary text. 15.4:1 on `--card` |
| `--text-2` | `#D5DDEA` | Secondary text, pledge, timestamps. 12.0:1 on `--card` |
| `--text-3` | `#C5D0E0` | Hints. 10.5:1 on `--card`. Do not go dimmer |
| `--teal` | `#5EEAD4` | Brand signal, primary button fill, current-tab mark. Not a result color |
| `--teal-ink` | `#062821` | Text on teal buttons. 10.7:1 on `#5EEAD4` |
| `--ok` | `#7EE0C8` | OK / No red flags icon and accent. Blue-green, not pure green |
| `--ok-bg` | `#0E2C2A` | OK result panel |
| `--ok-ink` | `#C9F6EC` | Text on the OK panel |
| `--stop` | `#FF6B78` | STOP icon and input error border |
| `--stop-bg` | `#3A1218` | STOP panel |
| `--stop-ink` | `#FFD0D6` | Text on the STOP panel |
| `--stop-btn` | `#FF8A96` | STOP button fill. Label `#2A0A10` |
| `--careful` | `#F6C453` | Be careful, focus ring, Coming soon |
| `--careful-bg` | `#33260C` | Be careful panel |
| `--careful-ink` | `#FFE3A3` | Text on the Be careful panel |
| `--info` | `#8EB6FF` | Info icon |
| `--info-bg` | `#152743` | Info panel |
| `--info-ink` | `#D6E4FF` | Text on Info, and link text |
| `--down` | `#B9D4F2` | Website-is-down icon only |
| `--down-bg` | `#16324F` | Website-is-down panel |
| `--down-ink` | `#E4F0FC` | Text on that panel |
| `--focus` | `#F6C453` | 3px focus ring, offset 3px. 11.8:1 on `--bg` |

Disabled controls: background `#243044`, label `#C5D0E0`. Do not fade a button with opacity alone.

Links are `--info-ink`, always underlined, not teal. Teal is the brand signal so it is not also the only cue for a link.

Windows high contrast: honor `forced-colors: active`. Keep borders as `ButtonText` / `CanvasText`. Do not force the hex palette over system colors.

### Type

Load only these, `display=swap`:

- **Sora** 600 and 700 — brand, headings, the big countdown
- **Atkinson Hyperlegible** 400 and 700 — everything a person reads or taps
- **IBM Plex Mono** 400 and 600 — wallet addresses, serials, countdowns in tables

```
https://fonts.googleapis.com/css2?family=Atkinson+Hyperlegible:ital,wght@0,400;0,700;1,400&family=IBM+Plex+Mono:wght@400;600&family=Sora:wght@600;700&display=swap
```

There is no weight 500 in Atkinson. Use 400 or 700.

Desktop scale, at a 16px root. Nothing on the desktop UI is under 20px.

| Style | rem | px | Face |
| --- | --- | --- | --- |
| Display countdown | 4.5rem | 72 | Sora 600 |
| H1 | 2.25rem | 36 | Sora 600 |
| Result word | 2rem | 32 | Sora 600 |
| H2 | 1.75rem | 28 | Sora 600 |
| Lead | 1.35rem | 22 | Atkinson 400 |
| H3, button, body, table, tab, menu, badge | 1.25rem | 20 | Atkinson. Headings Sora 600. Buttons Atkinson 700 |
| Minimum | 1.25rem | 20 | — |

Phone scale. Nothing in the app is under 18px. The phone’s own status bar is drawn by the OS, not by the app.

| Style | rem | px |
| --- | --- | --- |
| H1 | 1.75rem | 28 |
| H2 | 1.5rem | 24 |
| Body, button, input, tab label, badge | 1.125rem | 18 |
| Minimum | 1.125rem | 18 |

Line height 1.5 for body, 1.25 for headings. Paragraphs max 68ch. Buttons line-height 1.2.

### Spacing

Base unit is 4px at the default root, stored as rem: 0.25, 0.5, 0.75, 1, 1.5, 2, 2.5, 3, 4 rem (4, 8, 12, 16, 24, 32, 40, 48, 64 px).

Use 16 for compact padding, 24 between cards, 32 for the desktop page margin, 40–48 inside a hero card.

### Radius, border, glow, shadow

- Controls and inputs: 12px
- Cards, menus, map: 16px
- Status pills: 999px
- Number discs on step lists: circle
- Border: 1px solid `--line`. Inputs and answer buttons: 2px solid `--line-strong`
- Focus: `outline: 3px solid #F6C453; outline-offset: 3px` on `:focus-visible` only
- Card shadow: `0 12px 32px rgba(0, 0, 0, 0.38)`
- Teal glow, used only on the live status dot and the brand mark: `0 0 0 1px rgba(94, 234, 212, 0.45), 0 0 22px rgba(94, 234, 212, 0.22)`
- STOP dot glow: `0 0 0 1px rgba(255, 107, 120, 0.5), 0 0 16px rgba(255, 107, 120, 0.35)`
- Do not glow body text or full cards. A grid of 1px lines at 3.5% teal sits on the page background only, 56px apart. Cards are solid `--card` so the grid never runs through words.

### Motion

`prefers-reduced-motion: reduce` turns off animation. The countdown is a number, not a spinning graphic. Loading always has a sentence, not a spinner alone.

---

## 2. Navigation and layout

Information order is always: tab, then group, then page.

### Desktop, 1440

```
| 32px |  brand row                                                    | 32px |
|      |  Overview | Threat Map | Crypto & Wallets | Phone | Defense | Settings |
| 32px |  group menu 300 | 24px |  page, fluid                              | 32px |
```

- Viewport width 1440. Page margin 32px left and right. No centered 960 column.
- 12-column grid inside the page column. Gap 24px. Columns are `minmax(0, 1fr)` so long addresses can shrink and wrap.
- Brand row min-height 72px: shield mark, “ScamHunter” (Sora), “Threat Desk”, then the pledge “Free. Never asks for money or a recovery phrase.”, then “Desk online” or “Desk offline”.
- Tab row min-height 56px. Six tabs. They wrap. They never sit in a scroll strip that hides a tab. Current tab: `--card` fill, 4px teal bar on top, text `--text`. Other tabs: `--text-2`.
- The brand row and tabs are one sticky header, solid `#071018`, z-index 20, with a bottom border. Opaque, so content cannot slide under the words.
- Group menu is the left column, 300px, sticky, card surface. Group names (Protect, My case, Investigate) are labels, not links. Page links are min-height 56, 20px. Current page: 4px teal inset bar and weight 700.
- Overview and Threat Map have no groups. Hide the menu and let the page use the full width (`grid-template-columns: 1fr`).
- Breadcrumbs sit above the H1: `Crypto & Wallets / Protect / New hardware wallet check`. Links underlined. The current page is text, not a link. Separator is “/”.

Page column at 1440 is 1440 − 64 − 300 − 24 = **1052px**.

### Desktop, 1024

Same structure. Margin 20px. Menu 260px. Gap 20px. Page column is 1024 − 40 − 260 − 20 = **704px**.

At 704px:

- Dashboard cards stack to one column (every 12-grid span becomes 12).
- Map list moves under the map.
- Activity feed time moves above the sentence.
- Tabs wrap to two rows. Header grows. Sticky header stays opaque.
- Pledge wraps under the brand, full width. Do not hide it.
- Do not switch to a hamburger. Every page in the current tab stays visible.

Below 800px (also the point where 200% Windows text no longer fits the 1024 arrangement): stack the group menu above the page, full width, still expanded.

### Phone, 390

The app does not paint the OS status bar or the OS gesture bar. The old bug was the app bar sitting under the status bar. Prevent it like this:

```css
.app {
  padding-top: max(32px, env(safe-area-inset-top, 0px));
  background: #071018;
}
.tabbar {
  position: fixed;
  left: 0; right: 0; bottom: 0;
  padding-bottom: max(24px, env(safe-area-inset-bottom, 0px));
}
.main {
  padding: 16px 16px calc(88px + max(24px, env(safe-area-inset-bottom, 0px)));
}
```

`viewport-fit=cover` is required or `env(safe-area-inset-*)` stays 0. The `max(32px, …)` and `max(24px, …)` still reserve space when a WebView reports 0. That 32px top strip is empty app background. The app bar starts under it. Do not put the title, the status, or a back button in that strip.

App bar, one row, min-height 64px: **ScamHunter** on the left, **Desk online** or **Desk offline** on the right (dot + words). Nothing else. Settings is a row on Home, not a crowded icon in the bar.

Bottom navigation, 5 items, fixed, above the OS gesture area:

| Item | Opens |
| --- | --- |
| Home | Overview |
| Map | Threat Map |
| Crypto | Crypto groups and pages |
| Phone | The two message checks |
| Defense | Online Defense pages, including My website |

Each item is icon + word, min-height 68px, label 18px, weight 700. Current item: teal word and a 3px teal bar on top. The five words are Home, Map, Crypto, Phone, Defense. They may wrap. Do not shrink them under 18px.

Page margin on the phone is 16px. One column. Primary button is full width.

Crypto, Phone, and Defense on the phone are lists: group heading, then one full-width row per page (min-height 56) with the one-line description. Tap opens the page. A back control at the top of a page says “Back” plus the parent name, and sits below the app bar, never in the status strip.

### Page header (everywhere)

1. Breadcrumb (desktop, when there is a parent)
2. Optional kicker in teal Sora (“Protect”)
3. H1, the page name
4. One lead sentence, 22px desktop / 18px phone, color `--text-2`
5. No second competing button in the header. The main action lives in the first card.

### New pages in the menu

Add these to the existing groups:

- Crypto & Wallets → Protect → **New hardware wallet check** (first item). Badge: New
- Online Defense → Protect → **My website** (last item). Badge: New

Badge text is the word “New” plus a small spark icon. Color is not the only signal.

---

## 3. Shared building blocks

### Result levels

Every result shows an icon and a word. Color repeats that meaning. It never replaces it.

| Level | Word on screen | Icon | Panel |
| --- | --- | --- | --- |
| Stop | STOP | Octagon with a bar | `--stop-bg` / `--stop-ink` |
| Caution | Be careful | Triangle with an exclamation | `--careful-bg` / `--careful-ink` |
| Clear | No red flags found | Ring with a center dot | `--ok-bg` / `--ok-ink` |
| Note | Info | Circle with a lowercase i | `--info-bg` / `--info-ink` |

Compact chips (feeds, tables) may use the short word **OK** for the clear level, still with the ring icon. The full result card says **No red flags found**, not OK alone, and not “safe”.

A fifth product status exists only for My website: **Website is down**. Broken-link icon, `--down-*` colors. It is not a STOP. Do not reuse it for scam results.

Result card anatomy:

- Icon tile 52px
- Word as H2
- One sentence
- “Why” as a short bulleted list
- One primary button
- Optional secondary button
- The limitation sentence when the check cannot see inside a device or a server

### Cards

Solid `--card`, 1px `--line`, radius 16, padding 32 desktop / 16 phone, shadow as above. Heading, then at most one paragraph, then one primary button. A secondary button is allowed only if it does not start a different task. Nested rows use `--bg-sunken`.

### Buttons

Min-height 56px (`3.5rem`). Horizontal padding 20px. Radius 12. Weight 700. Width hugs text on desktop. Full width on the phone and inside wizards.

| Kind | Fill | Text | When |
| --- | --- | --- | --- |
| Primary | `#5EEAD4` | `#062821` | The one next step. One per card |
| Secondary | transparent | `#F7F8FB` | Border `#3D5678`. Alternate, not the main job |
| Quiet | transparent | `#D6E4FF` underlined | “Back”, “See the questions again” |
| Stop | `#FF8A96` | `#2A0A10` | Only when the action is to halt or discard something dangerous |
| Disabled | `#243044` | `#C5D0E0` | Cannot submit. Say why next to it |

Hover lightens the primary fill to `#8FF3E4`. The label stays `#062821`. Focus ring is the amber outline, on top of any hover.

### Text input

Label above, weight 700. Hint under the label, color `--text-2`. Control min-height 56, 2px border `--line-strong`, fill `--bg-sunken`, text 20/18.

States: empty, focus (amber ring), filled, disabled, error. Error: border `--stop`, fill `#240E14`, and a sentence under the field that starts with the STOP icon and plain words. Do not rely on the red border.

### Large paste box

Same as a text input, min-height 176px, resize vertical. Placeholder text is an example, color `--text-3`, and it is not the label. The label is always visible (“Paste the message”).

### File upload

Dashed 2px border, sunken fill, padding 32. A sentence says what to add. Primary-styled button “Choose a file” (min-height 56). Hint of accepted types in words: “Photo or PDF”.

States:

- Empty
- File chosen: file name wraps, button “Remove file”
- Wrong type or too big: STOP icon + “Use a photo or a PDF under 10 MB.”
- Working: “Saving the file…” plus the progress bar. The file name stays visible.

### Tables

Real `<table>` on desktop with a header row. On the phone, each row becomes a card with the column name as a label above each value. Do not make people scroll sideways to read an address.

Address cells: IBM Plex Mono, 20px desktop / 18px phone, `overflow-wrap: anywhere; word-break: break-word; min-width: 0`. Example that must wrap:

`rEXAMPLEwrapTestAddressNotReal00000`

Header cells are 20px Sora, color `--text-2`, background `#10192A`. Row hover is a 4% teal wash plus the text does not change meaning.

### Step list

Ordered list, no browser numerals. Each row is a 48px disc plus a sentence.

- Upcoming: disc outlined
- Now: disc filled teal, text `#062821`, the row’s sentence in `--text`
- Done: disc `--ok-bg`, the word “Done” in the sentence is unnecessary if the disc contains a check and the step text is unchanged. The disc also contains the number, so the state is number + fill. Add visually hidden text “Current” or “Done” for screen readers.

### Progress

Question wizard: the sentence “Question 2 of 7” is the accessible name. Under it, 7 bars. Done bars are `#1E5C52`. The current bar is `#5EEAD4`. The rest are outlined. Bars are `aria-hidden`. The sentence carries the meaning.

Determinate jobs (USB wait, file save): a bar plus “48 seconds left” or “Saving the file…”. The number is the meaning. The bar can be hidden from assistive tech.

### Coming soon badge

Clock icon + the words “Coming soon”. Pill, careful colors. Used on PatchPulse and on any unfinished tool. Do not show a control that looks active.

### New badge

Spark icon + the word “New”. Same pill. Used on the two new menu items.

### Loading / waiting

Panel with an Info or teal icon, a sentence (“Checking this address. This can take a minute.”), a determinate bar when the job has a time, and a secondary button “Stop waiting” if the job can be cancelled. No spinner as the only content.

### Empty

Ring icon, heading “Nothing here yet”, one sentence that says what will appear, one button that starts the first real action.

### Error

STOP icon, heading in plain words (“The check did not finish”), one sentence that says the person’s input is still here, primary button “Try again”. No error code as the only text. A code may sit in `--text-2` after the sentence if support needs it.

### Phone chrome

Specified in section 2. Component names: `.appbar`, `.tabbar`, `.status-pill`.

Offline pill uses the amber dot and the words “Desk offline”. Online uses the teal dot and “Desk online”.

---

## 4. Page-type layouts

One layout each. Pages listed under a type use that type.

### 4.1 Dashboard

**Uses:** Overview. The Crypto, Phone, Defense, and Settings landings use a shorter version: H1, lead, then a stack of group cards instead of the live feed.

**Overview, top to bottom:**

1. Page header. H1 “Overview”. Lead: “Everything the Desk is watching. Pick a tab to work in one area.”
2. Full-width status card. H2 “6 watchers running”. Six rows: Multi-chain tracer, Responder, Copy-paste guard, Network watcher, Network mapper, Wallet watcher. Each row is a dot, the name, and the word “Running”. If one is down, the H2 becomes “5 of 6 watchers running” and that row says “Not running” with the Be careful icon and word. Color is not the only signal.
3. Two columns (7 and 5). At 1024, stack.
   - Recent activity. A list, not a table. Each item: time, result chip (icon + word), one sentence. Newest first. Quiet button “See all activity” only if the list is clipped at 6 items.
   - Rising threats this week. Up to 3 cards. Each: result chip, threat name, one sentence, one button “See this threat”.
4. Quick check card, full width. Label “Paste a wallet address, a phone number, or a message”. One paste box. One primary button: “Check this”. Hint: “One check at a time. The Desk will open the right page.”

### 4.2 Checker with a result

**Uses:** Check before you send. Wallet shield. Claim checker. Check a phone number. Is this message a scam? Malware & link check. Look up a scammer. Exposure check. Secrets left in the open. Scam radar (the radar’s “what we found” block). Copy-paste guard and Browser extension and Agent firewall use the same result card for their current status, with a settings row under it.

**Stack:**

1. Page header
2. Input card: one field or one paste box, one primary “Check”
3. Waiting state replaces the result area, not the input
4. One result card (section 3)
5. Optional detail table under the result, using the table layout rules
6. Error and empty states from section 3

The result never says safe, genuine, or verified. A clear wallet check says “No red flags found” and names what was looked at.

### 4.3 Step-by-step wizard

**Uses:** New hardware wallet check. Wallet compromised? Incident mode.

**Stack:**

1. Page header on the start screen only
2. Progress sentence (“Question 2 of 7” or “Step 2 of 4”) and the bars
3. One question as H1
4. One hint sentence if needed
5. Answer buttons, full width, stacked, min-height 64, one answer per button
6. Quiet “Back” under them. Back keeps earlier answers
7. Final screen is a result card, then the next single step

One question per screen. Do not put two questions on one screen.

### 4.4 Data table

**Uses:** Network table. Freeze requests. Officer packets. Court evidence. Threat intel.

**Stack:**

1. Page header
2. Filter row: one text input (“Filter this list”) and, if needed, result chips as toggles that include the word, not color swatches
3. The table, address rules from section 3
4. Empty state when the filter matches nothing: “Nothing matches that. Clear the filter.”
5. One primary button for the page’s real job, above the table: “Prepare a freeze request”, “Make an officer packet”, “Search threat intel”

Network graph is this layout’s sibling: the table is replaced by a graph canvas on the left and the same rows on the right. The rows are the accessible version of the picture. Every node that is drawn is also a row.

### 4.5 Map

**Uses:** Threat Map. (Network graph borrows the side list.)

**Stack:**

1. Page header. Lead: “Live reports the Desk has already collected.”
2. Filter row: “Past day” and “Past week” as two buttons (one selected), plus threat-family checkboxes with visible labels. A family that is off stays in the list with the word “Hidden”, so a person can turn it back on.
3. Map canvas, min-height 448 desktop. Pins are numbered discs with the result color and the number. The number matches the side list.
4. Side list “Threat families”: name, result chip, count in words (“4 reports”).
5. Still learning state replaces the pins, not the page: ring icon, H2 “Still learning”, sentence “The Desk is gathering live threat reports. The map fills in as reports come in. You can still run a check.”, button “Go to the quick check”.

Do not load map tiles from another site in the mock. Production may use a local SVG world outline. If a tile server is added later, the side list still has to carry every point in words.

### 4.6 Form

**Uses:** Case setup. Alerts to your phone. Share ScamHunter. Watch this wallet. Custody record. Phone app pairing.

**Stack:**

1. Page header
2. One card of fields, labels above, hints under labels
3. Required fields say “Required” in the hint
4. One primary button at the end (“Save case”, “Save alerts”, “Watch this wallet”)
5. After save, an Info result: “Saved on this computer.” plus the time. Do not say verified
6. Error state on the field that failed, and the button stays put

### 4.7 Settings

**Uses:** Updates. Phone app. Alerts to your phone (the on/off rows). Share ScamHunter. Sites I use. Agent firewall. Browser extension. Copy-paste guard.

**Stack:**

1. Page header
2. Rows. Each row is a card: title, one sentence, and one control (toggle, button, or status chip)
3. Toggle is a real button, min-height 56, min-width 88, label “On” or “Off”. Not a bare switch with no word
4. Updates row: version in Plex Mono, primary “Check for updates”, and a result chip for the last result (“Info · You have the current update” or “Be careful · An update is ready”)
5. Phone app row: pairing status “Desk online” / “Desk offline”, button “Show pairing code”

The Settings tab landing lists the five pages as rows: Alerts to your phone, Updates, Case setup, Share ScamHunter, Phone app.

---

## 5. New pages

### 5A. New hardware wallet check

Path suggestion: `/prescreen/hardware` or `/hwcheck`. Menu: Crypto & Wallets → Protect, first item, New badge.

This flow never asks for a recovery phrase. If one is pasted, the screen refuses it.

#### Scoring

Any STOP answer makes the result STOP. Careful answers are still listed under Why. If there is no STOP and at least one Careful, the result is Be careful. Otherwise it is No red flags found.

| Question | Answer | Adds |
| --- | --- | --- |
| 3. Recovery phrase in the box | Yes | STOP |
| 6. Unlisted website or app | Yes | STOP |
| 4. Already had a PIN | Yes | STOP |
| 1. Which wallet | A different brand, or I don’t know | Be careful |
| 2. Where bought | Private seller or marketplace, gift, or I don’t know | Be careful |
| 3. Phrase in the box | I don’t know | Be careful |
| 4. PIN | I don’t know, or I have not turned it on yet | Be careful |
| 5. Seal or scratches | Yes, or I don’t know | Be careful |
| 7. Rushed or offered help | Yes | Be careful |

Clear answers, all required together: Ledger or Trezor; maker’s own store or a well-known shop; no phrase in the box; it asked them to create a PIN; seal not broken and not scratched; no unlisted site or app; nobody rushed them or offered to set it up.

USB never upgrades a STOP into a clear result. On STOP, the primary action is what to do next, not the USB step. USB is the primary next step only after No red flags found, and only on the computer. On Be careful it is a secondary button.

#### Screen 1 — Start

- Kicker: Protect
- H1: New hardware wallet check
- Lead: Seven short questions about a new wallet, before you set it up.
- Info callout, icon + word Info: “This can’t detect a hidden chip inside a device.”
- Step list: 1 Answer 7 questions. 2 On a computer, plug the wallet in so the Desk can read the device name. 3 Save a custody record if you want a paper trail.
- Primary: Start the check
- Quiet: I only want to watch an address → screen 16

#### Screens 2–8 — One question each

Progress line “Question N of 7” and 7 bars. Quiet Back on every screen after the first. Answer buttons are the full width.

**Question 1 of 7.** Which wallet did you buy?

- Ledger
- Trezor
- A different brand
- I don’t know

**Question 2 of 7.** Where did you buy it?

- The maker’s own store
- A well-known shop
- A private seller or an online marketplace
- It was a gift
- I don’t know

**Question 3 of 7.** Did a recovery phrase come in the box?

Hint: A recovery phrase is 12 or 24 words. A new wallet should not include one.

- Yes, words came in the box
- No
- I don’t know

**Question 4 of 7.** Did the wallet already have a PIN?

- Yes, it already had a PIN
- No, it asked me to create one
- I have not turned it on yet
- I don’t know

**Question 5 of 7.** Is the seal broken, or is the device scratched?

- Yes
- No
- I don’t know

**Question 6 of 7.** Did anyone tell you to use a website or app that was not on the maker’s list?

- Yes
- No

**Question 7 of 7.** Did anyone rush you, or offer to set it up for you?

- Yes
- No

#### Screen 9 — Result STOP

- Icon + STOP
- Sentence: Do not use this wallet. Do not type any words that came with it into a website or an app.
- Why: one bullet per triggered rule, in the same plain words as the question
- Repeat the Info line: This can’t detect a hidden chip inside a device.
- Primary (stop style if the action is to halt): What to do next
- The next panel is a 3-step list: Do not plug it into a computer. Contact the maker using the address printed in a sealed booklet or on the maker’s own site that you looked up yourself. Keep the box.
- Quiet: See the questions again
- Quiet: Save a custody record
- Do not offer “Watch this wallet” on a STOP result

#### Screen 10 — Result Be careful

- Icon + Be careful
- Sentence: Something about this purchase needs a closer look before you move money onto it.
- Why: the careful answers, in plain words
- Same hidden-chip line
- Primary: See what to check next
- Secondary: Check the USB name on this computer (desktop only). On the phone, secondary is “Do this step at your computer”
- Quiet: Save a custody record

#### Screen 11 — Result No red flags found

- Icon + No red flags found
- Sentence: These answers did not show a known setup trick.
- Why: short list of what was answered, so the result is reviewable
- Hidden-chip line, still visible. This result is not a promise about the inside of the device
- Primary on desktop: Continue to the USB check
- Primary on phone: Do this step at your computer
- Secondary: Watch this wallet
- Quiet: Save a custody record

#### Screen 12 — USB, unplug (computer only)

- Step list, step 1 current
- H1: Unplug the wallet
- Sentence: Take the wallet out of this computer. Leave it unplugged.
- Primary: It’s unplugged

#### Screen 13 — USB, plug in (computer only)

- H1: Now plug it in
- Sentence: Use the cable that came with the wallet. The Desk reads the device name only. It does not read your keys.
- Big number, Sora, starting at 60, label “seconds left”
- Bar under the number
- At 0 the number becomes “0” and the sentence becomes “Time is up. Reading the device name…”
- Secondary: Cancel and unplug

#### Screen 14 — USB results (computer only)

Table columns: Device name, Maker shown, First seen on this computer, Known wallet maker, Notes.

Known wallet maker cell is the word Yes, No, or Not sure. Each uses an icon: Yes uses the OK ring and the word Yes (not “verified”), No uses STOP, Not sure uses Info.

Under the table, one sentence: “A matching name does not mean the inside of the device was checked.”

Primary: Watch this wallet, only if the question result was not STOP. If the question result was STOP, primary remains What to do next. The table is information only.

#### Screen 15 — Phone, instead of USB

Shown on the phone wherever the desktop would open screens 12–14.

- Info icon
- H1: Do this step at your computer
- Sentence: This phone cannot see a USB wallet. Open the Desk on your computer and plug the wallet in there.
- Primary: Back to the result
- The phone does not show a countdown and does not pretend to scan USB

#### Screen 16 — Watch this wallet

- H1: Watch this wallet
- Label: Wallet address
- Hint: Paste the public address only.
- One text field. Mono font once text is detected
- Primary: Watch this wallet

**Red warning state.** If the paste is 12 words or 24 words, or any other run of words rather than one address string:

- Do not save it. Do not send it. Clear it from the field as soon as the warning shows, or replace the field with the warning and a single button
- STOP panel: “Stop. Those look like recovery words. Never paste them here. The Desk does not need them. Do not give those words to anyone.”
- The only button: Clear the box
- Watch this wallet is disabled until the field holds one address-shaped string again

#### Screen 17 — Custody record

Form layout. Fields:

| Field | Required | Notes |
| --- | --- | --- |
| Maker | Yes | Ledger, Trezor, or what is printed on the box |
| Seller | Yes | Store or person |
| Date bought | Yes | Date control |
| Price paid | Yes | Hint: “Numbers, and the currency. Example: 149 USD” |
| Order number | No | |
| Receipt | No | File upload, photo or PDF |
| Serial number | No | Hint: “From the box or the device screen. Not the recovery phrase.” |
| Photos | No | Up to 4 photos of the box and the seal |

Primary: Save custody record

Saved state: Info card “Saved on this computer.” and the local time. List the saved files by name. Button “Done” returns to Crypto → Protect.

### 5B. My website

Path suggestion: `/mywebsite`. Menu: Online Defense → Protect, last item, New badge.

Two states. Ship the first. Build the second so it can replace the first without a new layout.

#### State 1 — Coming soon

Page header. H1 “My website”. Lead: “A later check for a website you own.”

One card:

- Badge: clock icon + Coming soon
- H2: PatchPulse — Coming soon
- Paragraph: “PatchPulse watches a website you own. It looks for unwanted changes, downtime, and known weak spots.”
- Link, underlined, worded as the host: `patchpulsehq.com` pointing at `https://patchpulsehq.com`. Hint under it: “Opens the PatchPulse site in your browser.”
- A separate line, weight 700: “PatchPulse is a separate paid product.”
- No primary button that implies PatchPulse is included or already purchased
- Quiet link back: “Other Online Defense tools”

#### State 2 — Later, a list of websites

Same page header. The coming-soon card is gone.

One primary at the top: “Check again”.

Then one card per site. Each card has the site address (wraps), the time of the last check, a status row (icon + the exact words below), and one button “See details”.

| Status words | Visual |
| --- | --- |
| All clear | OK ring, `--ok-*` |
| Needs attention | Triangle, `--careful-*`, word “Be careful” may sit beside it, but the status phrase stays “Needs attention” |
| Needs attention now | Octagon, `--stop-*`. The phrase stays “Needs attention now” |
| Website is down | Broken link, `--down-*`. Not a STOP |

Empty state if they have no sites yet: “No websites yet.” Sentence: “When PatchPulse is connected, sites you add will show up here.” Do not invent a fake purchase button.

---

## 6. Build rules checklist

- Desktop body, tabs, menus, tables, hints, and badges are at least 20px. Phone app text is at least 18px.
- Buttons and answer rows are at least 56px tall. Wizard answers are at least 64px.
- Root font size stays at the browser default. Sizes are rem. Buttons use min-height, not a fixed height. Text containers do not use `overflow: hidden` or `white-space: nowrap` (the status pill may stay on one line only while the words still fit; if they do not, the pill wraps).
- Address columns use `overflow-wrap: anywhere`.
- Test at 1440, 1024, and a 390-wide phone frame. Then test again with Windows display scaling at 150% and the browser font enlarged. At the largest size the menu must stack, not clip.
- Contrast pairs in section 1. Focus ring amber, 3px, offset 3px, on `:focus-visible`.
- `forced-colors` and `prefers-reduced-motion` covered.
- Result screens include an icon and a word. Never color alone.
- The words safe, genuine, and verified do not appear on result UI.
- Phone content starts below `max(32px, env(safe-area-inset-top))`. Bottom nav sits above `max(24px, env(safe-area-inset-bottom))`.
- Google Fonts only. Inline SVG only. No images from other sites.
