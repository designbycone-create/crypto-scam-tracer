// ScamHunter Threat Desk relay: a Cloudflare Worker you deploy on your own Cloudflare account.
//
// The Desk on your PC connects OUT to this Worker over a WebSocket; the paired phone app sends HTTPS
// requests here, and the Worker hands them to the Desk and returns the Desk's answer. Everything that
// passes through is encrypted end to end by the Desk and the phone (AES-256-GCM); this Worker never has
// the key and can't read or change it. It only checks who may use a channel, and enforces size and
// rate limits.
//
//   POST /register    (Bearer ADMIN_KEY)  {channel, desk_hash, phone_hash}   set up a pairing
//   POST /unregister  (Bearer ADMIN_KEY)  {channel}                          remove it
//   GET  /c/<channel>/desk  WebSocket     (Bearer desk token)                the Desk's connection
//   POST /c/<channel>/req   ciphertext    (Bearer phone token)               one request from the phone
//   GET  /health

const CHANNEL_RE = /^[0-9a-f]{32}$/;
const HASH_RE = /^[0-9a-f]{64}$/;
export const LIMITS = { reqBytes: 512 * 1024, perMinute: 120, waitMs: 45000 };

const enc = new TextEncoder();

export async function sha256hex(s) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function sameText(a, b) {
  // constant-time comparison of two equal-length hex strings
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let x = 0;
  for (let i = 0; i < a.length; i++) x |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return x === 0;
}

function bearer(req) {
  const h = req.headers.get("Authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
}

export function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}

export function toB64(buf) {
  const u = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  return btoa(s);
}

export function fromB64(b64) {
  const s = atob(b64);
  const u = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i);
  return u;
}

async function isAdmin(req, env) {
  const key = bearer(req);
  if (!env.ADMIN_KEY || env.ADMIN_KEY.length < 32 || !key) return false;
  return sameText(await sha256hex(key), await sha256hex(env.ADMIN_KEY));
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const p = url.pathname;
    if (p === "/health") return json({ ok: true, service: "scamhunter-relay", v: 1, configured: !!(env.ADMIN_KEY && env.ADMIN_KEY.length >= 32) });
    if (p === "/register" || p === "/unregister") {
      if (req.method !== "POST") return json({ error: "POST only" }, 405);
      if (!(await isAdmin(req, env))) return json({ error: "not allowed" }, 401);
      let body;
      try { body = await req.json(); } catch { return json({ error: "bad request" }, 400); }
      if (!CHANNEL_RE.test(body.channel || "")) return json({ error: "bad channel" }, 400);
      if (p === "/register" && !(HASH_RE.test(body.desk_hash || "") && HASH_RE.test(body.phone_hash || ""))) return json({ error: "bad hashes" }, 400);
      const stub = env.CHANNEL.get(env.CHANNEL.idFromName(body.channel));
      return stub.fetch("https://do" + p, { method: "POST", body: JSON.stringify(body) });
    }
    const m = p.match(/^\/c\/([0-9a-f]{32})\/(desk|req)$/);
    if (m) {
      const stub = env.CHANNEL.get(env.CHANNEL.idFromName(m[1]));
      return stub.fetch(req);
    }
    return json({ error: "not found" }, 404);
  },
};

export class Channel {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.pending = new Map();
    this.window = [];
  }

  upgrade(client) {
    return new Response(null, { status: 101, webSocket: client });
  }

  async fetch(req) {
    const p = new URL(req.url).pathname;
    if (p === "/register") {
      const b = await req.json();
      await this.state.storage.put("auth", { desk_hash: b.desk_hash, phone_hash: b.phone_hash });
      for (const ws of this.state.getWebSockets()) ws.close(4001, "re-paired");
      return json({ ok: true });
    }
    if (p === "/unregister") {
      await this.state.storage.deleteAll();
      for (const ws of this.state.getWebSockets()) ws.close(4002, "unpaired");
      return json({ ok: true });
    }
    const auth = await this.state.storage.get("auth");
    if (!auth) return json({ error: "this channel isn't paired" }, 404);
    const who = await sha256hex(bearer(req));
    if (p.endsWith("/desk")) {
      if (!sameText(who, auth.desk_hash)) return json({ error: "not allowed" }, 401);
      if ((req.headers.get("Upgrade") || "").toLowerCase() !== "websocket") return json({ error: "WebSocket expected" }, 426);
      for (const ws of this.state.getWebSockets()) ws.close(4003, "replaced by a newer Desk connection");
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.state.acceptWebSocket(server);
      return this.upgrade(client);
    }
    // a request from the phone
    if (req.method !== "POST") return json({ error: "POST only" }, 405);
    if (!sameText(who, auth.phone_hash)) return json({ error: "not allowed" }, 401);
    const now = Date.now();
    this.window = this.window.filter((t) => now - t < 60000);
    if (this.window.length >= LIMITS.perMinute) return json({ error: "too many requests, slow down" }, 429);
    this.window.push(now);
    const body = new Uint8Array(await req.arrayBuffer());
    if (body.length === 0 || body.length > LIMITS.reqBytes) return json({ error: "request too large" }, 413);
    const desk = this.state.getWebSockets()[0];
    if (!desk) return json({ error: "desk offline" }, 503);
    const id = crypto.randomUUID();
    const answer = new Promise((resolve) => {
      const timer = setTimeout(() => { this.pending.delete(id); resolve(null); }, LIMITS.waitMs);
      this.pending.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
    });
    try {
      desk.send(JSON.stringify({ id, b: toB64(body) }));
    } catch {
      this.pending.delete(id);
      return json({ error: "desk offline" }, 503);
    }
    const msg = await answer;
    if (!msg) return json({ error: "the Desk didn't answer in time" }, 504);
    if (msg.err) return json({ error: String(msg.err).slice(0, 200) }, 502);
    return new Response(fromB64(msg.b || ""), { status: 200, headers: { "Content-Type": "application/octet-stream", "Cache-Control": "no-store" } });
  }

  async webSocketMessage(ws, data) {
    let msg;
    try { msg = JSON.parse(typeof data === "string" ? data : new TextDecoder().decode(data)); } catch { return; }
    if (msg && msg.ping) { ws.send(JSON.stringify({ pong: msg.ping })); return; }
    const done = msg && this.pending.get(msg.id);
    if (done) { this.pending.delete(msg.id); done(msg); }
  }

  async webSocketClose(ws, code, reason) {
    try { ws.close(code, reason); } catch {}
  }
}
