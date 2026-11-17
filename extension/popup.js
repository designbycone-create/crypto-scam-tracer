const show = () => chrome.storage.local.get(["feed", "token"], (r) => {
  const f = r.feed || {};
  const n = Object.keys(f.addresses || {}).length, d = Object.keys(f.domains || {}).length;
  document.getElementById("s").innerHTML =
    `<p>Watching for address swapping and known attack code on every page.</p>` +
    `<p><b>${n}</b> scammer addresses and <b>${d}</b> attack hosts known<br><small>from: ${f.source || "?"}, ${f.updated ? new Date(f.updated).toLocaleString() : "never"}</small></p>` +
    `<p>${r.token ? '<span class=ok>&#10003; Connected to your Desk</span> (address book + phone alerts)' : '<span class=no>Not connected to the Desk</span>: works on its own, without your address book or phone alerts.'}</p>`;
});
document.getElementById("r").onclick = () => chrome.runtime.sendMessage({ type: "refresh" }, show);
show();
