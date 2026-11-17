const m = (t) => (document.getElementById("m").textContent = t);
chrome.storage.local.get("token", (r) => { if (r.token) m("Connected."); });
document.getElementById("s").onclick = async () => {
  const t = document.getElementById("t").value.trim();
  if (!t) return m("Paste the code first.");
  try {
    const res = await fetch("http://127.0.0.1:8787/api/ext/feed", { headers: { "X-ScamHunter-Ext": t } });
    if (!res.ok) return m(res.status === 401 ? "That code isn't right. Copy it again from the Desk." : "The Desk answered " + res.status);
    await chrome.storage.local.set({ token: t });
    chrome.runtime.sendMessage({ type: "refresh" });
    m("Connected to your Desk.");
  } catch (e) { m("Couldn't reach the Desk. Is it running? (open it from the ScamHunter Desk icon)"); }
};
document.getElementById("x").onclick = () => chrome.storage.local.remove("token", () => m("Disconnected."));
