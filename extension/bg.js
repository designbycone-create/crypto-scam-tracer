// ScamHunter Guard -- background: keeps the known-attack list fresh and talks to the Desk (on this computer only).
const DESK = "http://127.0.0.1:8787";

async function token() {
  const r = await chrome.storage.local.get("token");
  return r.token || "";
}

async function desk(path, body) {
  const t = await token();
  if (!t) throw new Error("not paired");
  const res = await fetch(DESK + path, {
    method: body ? "POST" : "GET",
    headers: { "X-ScamHunter-Ext": t, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error("Desk answered " + res.status);
  return res.json();
}

async function refreshFeed() {
  let feed = null, source = "built in";
  try {
    feed = await desk("/api/ext/feed");
    source = "Desk";
  } catch (e) {
    try { feed = await (await fetch(chrome.runtime.getURL("feed.json"))).json(); } catch (x) {}
  }
  if (feed) await chrome.storage.local.set({ feed: { ...feed, source, updated: new Date().toISOString() } });
}

chrome.runtime.onInstalled.addListener(() => { refreshFeed(); chrome.alarms.create("feed", { periodInMinutes: 360 }); });
chrome.runtime.onStartup.addListener(refreshFeed);
chrome.alarms.onAlarm.addListener((a) => { if (a.name === "feed") refreshFeed(); });

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg.type === "check") {
    desk("/api/ext/check", { addresses: msg.addresses }).then(reply, () => reply(null));
    return true;
  }
  if (msg.type === "report") {
    const ev = msg.event || {};
    if (["swap", "paste_blocked", "copied_bad", "attack_host", "page_bad"].includes(ev.kind)) {
      chrome.notifications.create({ type: "basic", iconUrl: "icon128.png", priority: 2,
        title: "ScamHunter Guard: STOP", message: ev.kind === "swap" ? "A page swapped the crypto address you copied. Don't paste it."
          : ev.kind === "attack_host" ? `A page is loading known attack code (${ev.campaign || ev.host}).`
          : "A known scammer address was found. Don't send to it." });
    }
    desk("/api/ext/report", { event: ev }).catch(() => {});
  }
  if (msg.type === "relay-banner" && sender.tab) {
    chrome.tabs.sendMessage(sender.tab.id, msg, { frameId: 0 }).catch(() => {});
  }
  if (msg.type === "refresh") { refreshFeed().then(() => reply(true)); return true; }
});
