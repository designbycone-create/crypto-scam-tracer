// ScamHunter Guard -- content script: turns what inject.js sees into warnings, checks pastes and page text.
(() => {
  let feed = { addresses: {}, domains: {}, ready: false };
  const load = () => chrome.storage.local.get("feed", (r) => {
    if (r && r.feed) feed = { ...r.feed, ready: true };
    scanPage();
  });
  load();
  chrome.storage.onChanged.addListener((c) => { if (c.feed) load(); });

  const bad = (a) => feed.addresses[SH.norm(a)];
  const badHost = (h) => {
    h = String(h || "").toLowerCase();
    for (const d in feed.domains) if (h === d || h.endsWith("." + d)) return feed.domains[d];
    return null;
  };
  const report = (event) => { try { chrome.runtime.sendMessage({ type: "report", event: { ...event, url: location.href } }); } catch (e) {} };
  const warned = new Set();
  const once = (key, fn) => { if (!warned.has(key)) { warned.add(key); fn(); } };

  window.addEventListener("message", (e) => {
    if (e.source !== window || !e.data || e.data.__scamhunter !== 1) return;
    const m = e.data;
    if (m.kind === "swap") {
      once("swap" + m.replaced, () => {
        const known = bad(m.replaced);
        SH.banner("stop", "STOP: this page swapped the address you copied",
          `You copied ${m.original}, but the page put a different address on your clipboard` +
          (known ? ` (a known scammer address: ${known})` : "") + ". Don't paste it. This site is infected right now; get the address another way.",
          m.replaced);
        report({ kind: "swap", original: m.original, replaced: m.replaced, campaign: known || "" });
      });
    } else if (m.kind === "copied") {
      for (const a of m.addresses || []) {
        const known = bad(a);
        if (known) once("copied" + a, () => {
          SH.banner("stop", "STOP: you copied a known scammer's address", `This address belongs to ${known}. Don't send to it.`, a);
          report({ kind: "copied_bad", address: a, campaign: known });
        });
      }
    } else if (m.kind === "tamper") {
      once("tamper", () => {
        SH.banner("warn", "Warning: this page altered core browser functions",
          "Address-swapping malware does this. Don't copy or send crypto addresses from this page; check any address on your wallet's screen.");
        report({ kind: "tamper", what: m.what });
      });
    } else if (m.kind === "hosts") {
      for (const h of m.hosts || []) {
        const c = badHost(h);
        if (c) once("host" + h, () => {
          SH.banner("stop", "STOP: this page is loading known attack code",
            `It loads code from ${h}, which belongs to ${c}. Don't enter card details, passwords or crypto addresses on this page.`);
          report({ kind: "attack_host", host: h, campaign: c });
        });
      }
    }
  });

  if (window.top === window) {
    chrome.runtime.onMessage.addListener((m) => { if (m.type === "relay-banner") SH.show(m.level, m.title, m.body, m.address); });
  }

  // pasting a known scammer address anywhere is blocked; a saved address is confirmed by name
  document.addEventListener("paste", (e) => {
    const t = (e.clipboardData && e.clipboardData.getData("text")) || "";
    const found = SH.addrs(t);
    for (const a of found) {
      const known = bad(a);
      if (known) {
        e.preventDefault();
        e.stopImmediatePropagation();
        SH.banner("stop", "Paste blocked: known scammer address", `The address on your clipboard belongs to ${known}. It was not pasted.`, a);
        report({ kind: "paste_blocked", address: a, campaign: known });
        return;
      }
    }
    if (found.length) {
      try {
        chrome.runtime.sendMessage({ type: "check", addresses: found.slice(0, 3) }, (r) => {
          if (chrome.runtime.lastError || !r) return;
          for (const x of r.results || []) {
            if (x.bad) SH.banner("stop", "Known scammer address pasted", x.bad, x.address);
            else if (x.saved) SH.banner("ok", `Saved address: ${x.saved}`, "This matches your address book.", x.address);
          }
        });
      } catch (x) {}
    }
  }, true);

  // known scammer addresses shown on the page (a swapped page shows the attacker's address as if it were real)
  let timer = null;
  function scanPage() {
    if (!feed.ready || !document.body) return;
    const text = (document.body.innerText || "").slice(0, 500000);
    for (const a of SH.addrs(text)) {
      const known = bad(a);
      if (known) once("page" + a, () => {
        SH.banner("stop", "STOP: this page shows a known scammer's address",
          `This address belongs to ${known}. If the site says it's theirs, the site may be infected. Don't send to it.`, a);
        report({ kind: "page_bad", address: a, campaign: known });
      });
    }
  }
  const schedule = () => { clearTimeout(timer); timer = setTimeout(scanPage, 1500); };
  document.addEventListener("DOMContentLoaded", () => {
    scanPage();
    try { new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true, characterData: true }); } catch (e) {}
  });
})();
