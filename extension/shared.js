// ScamHunter Guard -- shared helpers for the content script: address matching and the warning banner.
const SH = (() => {
  const RX = /\b(0x[0-9a-fA-F]{40}|bc1[02-9ac-hj-np-z]{11,71}|ltc1[02-9ac-hj-np-z]{11,71}|(?:bitcoincash:)?[qp][02-9ac-hj-np-z]{41}|[EU]Q[A-Za-z0-9_-]{46}|T[1-9A-HJ-NP-Za-km-z]{33}|[13LMD][1-9A-HJ-NP-Za-km-z]{25,34}|r[1-9A-HJ-NP-Za-km-z]{24,34}|[1-9A-HJ-NP-Za-km-z]{32,44})\b/g;
  const norm = (a) => {
    a = String(a || "").trim();
    if (/^bitcoincash:/i.test(a)) a = a.split(":")[1];
    return /^0x/i.test(a) || /^[qp][02-9ac-hj-np-z]{41}$/i.test(a) ? a.toLowerCase() : a;
  };
  const addrs = (s) => [...new Set((String(s || "").match(RX) || []).filter((a) => /\d/.test(a) && /[a-z]/i.test(a)))];
  const chunk = (a) => String(a).replace(/(.{4})/g, "$1 ").trim();
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

  let host = null;
  function banner(level, title, body, address) {
    if (window.top !== window) {           // show it in the main page, not inside a small frame
      try { chrome.runtime.sendMessage({ type: "relay-banner", level, title, body, address }); } catch (e) {}
      return;
    }
    show(level, title, body, address);
  }
  function show(level, title, body, address) {
    const colors = { stop: ["#b00020", "#fff"], warn: ["#f2b01e", "#111"], ok: ["#1e7d32", "#fff"] }[level] || ["#333", "#fff"];
    if (!host) {
      host = document.createElement("div");
      host.setAttribute("data-scamhunter", "banner");
      host.style.cssText = "all:initial;position:fixed;z-index:2147483647;top:12px;left:50%;transform:translateX(-50%);width:min(760px,94vw)";
      (document.documentElement || document.body).appendChild(host);
      host.attachShadow({ mode: "open" });
    }
    const box = document.createElement("div");
    box.setAttribute("role", "alert");
    box.style.cssText = `font:18px/1.45 Segoe UI,Arial,sans-serif;background:${colors[0]};color:${colors[1]};border-radius:12px;` +
      "padding:16px 20px;margin-bottom:10px;box-shadow:0 6px 24px rgba(0,0,0,.35)";
    box.innerHTML = `<div style="font-size:${level === "stop" ? 26 : 20}px;font-weight:700;margin-bottom:6px">${esc(title)}</div>` +
      (address ? `<div style="font:20px/1.4 Consolas,monospace;margin:6px 0;word-break:break-all">${esc(chunk(address))}</div>` : "") +
      `<div>${esc(body)}</div><div style="margin-top:8px;font-size:14px;opacity:.85">ScamHunter Guard</div>`;
    const btn = document.createElement("button");
    btn.textContent = level === "stop" ? "I understand" : "OK";
    btn.style.cssText = "margin-top:10px;font:600 17px Segoe UI,Arial,sans-serif;padding:7px 16px;border-radius:8px;border:0;cursor:pointer";
    btn.onclick = () => box.remove();
    box.appendChild(btn);
    host.shadowRoot.appendChild(box);
    if (level === "ok") setTimeout(() => box.remove(), 6000);
  }
  return { norm, addrs, banner, show, chunk };
})();
