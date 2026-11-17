// ScamHunter Guard -- runs inside the page itself (before the page's own scripts) to watch what
// scripts do with addresses you copy. It only reports to the extension; it never sends data anywhere.
(() => {
  if (window.__scamhunterInjected) return;
  window.__scamhunterInjected = true;
  const R = Reflect.apply, post = window.postMessage.bind(window);
  const now = () => Date.now();
  // address shapes (exact checks happen in the extension; here we only need to compare strings)
  const RX = /\b(0x[0-9a-fA-F]{40}|bc1[02-9ac-hj-np-z]{11,71}|ltc1[02-9ac-hj-np-z]{11,71}|(?:bitcoincash:)?[qp][02-9ac-hj-np-z]{41}|[EU]Q[A-Za-z0-9_-]{46}|T[1-9A-HJ-NP-Za-km-z]{33}|[13LMD][1-9A-HJ-NP-Za-km-z]{25,34}|r[1-9A-HJ-NP-Za-km-z]{24,34}|[1-9A-HJ-NP-Za-km-z]{32,44})\b/g;
  const addrs = (s) => (String(s || "").match(RX) || []).filter((a) => /\d/.test(a) && /[a-z]/i.test(a));
  const send = (kind, data) => { try { post({ __scamhunter: 1, kind, ...data }, "*"); } catch (e) {} };

  let copy = null;
  const writes = [];
  const record = (text, via) => {
    writes.push({ text: String(text), via, t: now() });
    if (writes.length > 20) writes.shift();
    if (!copy || now() - copy.t > 1500) {
      const a = addrs(text);
      if (a.length) send("copied", { addresses: a.slice(0, 5), via });   // a "copy" button: checked against known scammers
    }
  };
  try {
    const sd = DataTransfer.prototype.setData;
    DataTransfer.prototype.setData = function (fmt, data) {
      if (/text/i.test(String(fmt))) record(data, "setData");
      return R(sd, this, arguments);
    };
  } catch (e) {}
  try {
    const wt = Clipboard.prototype.writeText;
    Clipboard.prototype.writeText = function (text) { record(text, "writeText"); return R(wt, this, arguments); };
  } catch (e) {}

  const compare = (last) => {
    if (!copy) return;
    const sel = addrs(copy.selection);
    const wrote = writes.filter((w) => w.t >= copy.t - 5 && w.t <= copy.t + 1500).flatMap((w) => addrs(w.text));
    const swapped = sel.length ? wrote.filter((w) => !sel.includes(w)) : [];
    if (swapped.length) {
      send("swap", { original: sel[0], replaced: swapped[0], url: location.href });
      copy = null;
      return;
    }
    if (last) {        // no swap seen: still check what was copied against known scammer addresses
      const all = [...new Set(sel.concat(wrote))];
      if (all.length) send("copied", { addresses: all.slice(0, 5), via: "copy" });
      copy = null;
    }
  };
  window.addEventListener("copy", (e) => {
    let s = "";
    try {
      const t = e.target;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA") && typeof t.selectionStart === "number")
        s = t.value.substring(t.selectionStart, t.selectionEnd);
      if (!s) s = String(window.getSelection() || "");
    } catch (x) {}
    copy = { selection: s, t: now() };
    setTimeout(() => compare(false), 0);
    setTimeout(() => compare(false), 400);
    setTimeout(() => compare(true), 1200);
  }, true);

  // core JavaScript functions replaced: OPTIMJACK did this to rewrite addresses everywhere
  const C = Function.prototype.call, A = Function.prototype.apply;
  let tamperSent = false;
  const tamper = () => {
    if (tamperSent) return;
    if (Function.prototype.call !== C || Function.prototype.apply !== A) {
      tamperSent = true;
      send("tamper", { what: "Function.prototype.call/apply", url: location.href });
    }
  };
  [1500, 4000, 10000, 30000].forEach((ms) => setTimeout(tamper, ms));

  // every outside host the page loads code or data from, including scripts added later by other scripts
  try {
    const seen = new Set();
    const po = new PerformanceObserver((list) => {
      const hosts = [];
      for (const en of list.getEntries()) {
        try {
          const h = new URL(en.name).hostname.toLowerCase();
          if (h && !seen.has(h)) { seen.add(h); hosts.push(h); }
        } catch (x) {}
      }
      if (hosts.length) send("hosts", { hosts, url: location.href });
    });
    po.observe({ type: "resource", buffered: true });
  } catch (e) {}
})();
