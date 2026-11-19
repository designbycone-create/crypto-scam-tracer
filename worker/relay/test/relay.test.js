// Run: node --test test/relay.test.js   (no Cloudflare account needed: the Durable Object runtime is simulated)
import test from "node:test";
import assert from "node:assert/strict";
import worker, { Channel, LIMITS, sha256hex, toB64, fromB64 } from "../src/index.js";

const ADMIN = "a".repeat(48);
const CH = "0123456789abcdef0123456789abcdef";

class FakeSocket {
  constructor() { this.sent = []; this.closed = null; this.peer = null; }
  send(s) { this.sent.push(s); if (this.onSend) this.onSend(s); }
  close(code, reason) { this.closed = [code, reason]; }
}
globalThis.WebSocketPair = function () { const c = new FakeSocket(), s = new FakeSocket(); return { 0: c, 1: s }; };

function makeEnv() {
  const objects = new Map();
  const env = {
    ADMIN_KEY: ADMIN,
    CHANNEL: {
      idFromName: (n) => n,
      get: (id) => {
        if (!objects.has(id)) {
          const store = new Map();
          const sockets = [];
          const state = {
            storage: { get: async (k) => store.get(k), put: async (k, v) => store.set(k, v), deleteAll: async () => store.clear() },
            acceptWebSocket: (ws) => sockets.push(ws),
            getWebSockets: () => sockets.filter((w) => !w.closed),
          };
          const ch = new Channel(state, env);
          ch.upgrade = (client) => ({ status: 101, client });
          objects.set(id, ch);
        }
        const ch = objects.get(id);
        return { fetch: (r, init) => ch.fetch(typeof r === "string" ? new Request(r, init) : r) };
      },
    },
  };
  env.objects = objects;
  return env;
}

const req = (path, opts = {}) => new Request("https://relay.example" + path, opts);
const auth = (t) => ({ Authorization: "Bearer " + t });

async function register(env, desk = "desk-token-1", phone = "phone-token-1") {
  return worker.fetch(req("/register", { method: "POST", headers: auth(ADMIN),
    body: JSON.stringify({ channel: CH, desk_hash: await sha256hex(desk), phone_hash: await sha256hex(phone) }) }), env);
}

test("health says whether the admin key is set", async () => {
  const env = makeEnv();
  assert.equal((await (await worker.fetch(req("/health"), env)).json()).configured, true);
  env.ADMIN_KEY = "short";
  assert.equal((await (await worker.fetch(req("/health"), env)).json()).configured, false);
});

test("register needs the admin key and valid input", async () => {
  const env = makeEnv();
  const bad = await worker.fetch(req("/register", { method: "POST", headers: auth("wrong"), body: "{}" }), env);
  assert.equal(bad.status, 401);
  const r = await worker.fetch(req("/register", { method: "POST", headers: auth(ADMIN), body: JSON.stringify({ channel: "../x" }) }), env);
  assert.equal(r.status, 400);
  assert.equal((await register(env)).status, 200);
  env.ADMIN_KEY = "";
  assert.equal((await register(env)).status, 401, "an unset admin key never lets anyone in");
});

test("unknown paths and unpaired channels", async () => {
  const env = makeEnv();
  assert.equal((await worker.fetch(req("/anything"), env)).status, 404);
  assert.equal((await worker.fetch(req(`/c/${CH}/req`, { method: "POST", headers: auth("x"), body: "x" }), env)).status, 404);
});

test("desk connects only with its own token", async () => {
  const env = makeEnv();
  await register(env);
  const no = await worker.fetch(req(`/c/${CH}/desk`, { headers: { ...auth("phone-token-1"), Upgrade: "websocket" } }), env);
  assert.equal(no.status, 401, "the phone token can't pose as the Desk");
  const ok = await worker.fetch(req(`/c/${CH}/desk`, { headers: { ...auth("desk-token-1"), Upgrade: "websocket" } }), env);
  assert.equal(ok.status, 101);
});

test("phone request goes to the desk and the desk's answer comes back unchanged", async () => {
  const env = makeEnv();
  await register(env);
  await worker.fetch(req(`/c/${CH}/desk`, { headers: { ...auth("desk-token-1"), Upgrade: "websocket" } }), env);
  const ch = env.objects.get(CH);
  const server = ch.state.getWebSockets()[0];
  const blob = new Uint8Array([1, 2, 3, 250, 0, 7]);
  server.onSend = (s) => {
    const m = JSON.parse(s);
    assert.deepEqual([...fromB64(m.b)], [...blob], "the Worker passes the ciphertext through untouched");
    ch.webSocketMessage(server, JSON.stringify({ id: m.id, b: toB64(new Uint8Array([9, 9, 9])) }));
  };
  const r = await worker.fetch(req(`/c/${CH}/req`, { method: "POST", headers: auth("phone-token-1"), body: blob }), env);
  assert.equal(r.status, 200);
  assert.deepEqual([...new Uint8Array(await r.arrayBuffer())], [9, 9, 9]);
});

test("wrong phone token, desk offline, too large, desk error", async () => {
  const env = makeEnv();
  await register(env);
  const post = (t, body) => worker.fetch(req(`/c/${CH}/req`, { method: "POST", headers: auth(t), body }), env);
  assert.equal((await post("desk-token-1", "x")).status, 401, "the Desk token can't pose as the phone");
  assert.equal((await post("phone-token-1", "x")).status, 503);
  await worker.fetch(req(`/c/${CH}/desk`, { headers: { ...auth("desk-token-1"), Upgrade: "websocket" } }), env);
  assert.equal((await post("phone-token-1", new Uint8Array(LIMITS.reqBytes + 1))).status, 413);
  const ch = env.objects.get(CH);
  const server = ch.state.getWebSockets()[0];
  server.onSend = (s) => ch.webSocketMessage(server, JSON.stringify({ id: JSON.parse(s).id, err: "message failed its integrity check" }));
  const r = await post("phone-token-1", "x");
  assert.equal(r.status, 502);
});

test("rate limit", async () => {
  const env = makeEnv();
  await register(env);
  let last;
  for (let i = 0; i <= LIMITS.perMinute; i++) last = await worker.fetch(req(`/c/${CH}/req`, { method: "POST", headers: auth("phone-token-1"), body: "x" }), env);
  assert.equal(last.status, 429);
});

test("re-pairing and unpairing cut off the old connection", async () => {
  const env = makeEnv();
  await register(env);
  await worker.fetch(req(`/c/${CH}/desk`, { headers: { ...auth("desk-token-1"), Upgrade: "websocket" } }), env);
  const ch = env.objects.get(CH);
  const first = ch.state.getWebSockets()[0];
  await register(env, "desk-token-2", "phone-token-2");
  assert.ok(first.closed, "old Desk connection closed on re-pair");
  assert.equal((await worker.fetch(req(`/c/${CH}/req`, { method: "POST", headers: auth("phone-token-1"), body: "x" }), env)).status, 401, "old phone token no longer works");
  await worker.fetch(req("/unregister", { method: "POST", headers: auth(ADMIN), body: JSON.stringify({ channel: CH }) }), env);
  assert.equal((await worker.fetch(req(`/c/${CH}/req`, { method: "POST", headers: auth("phone-token-2"), body: "x" }), env)).status, 404);
});

test("a timed-out desk gives 504, not a hang", async () => {
  const env = makeEnv();
  await register(env);
  await worker.fetch(req(`/c/${CH}/desk`, { headers: { ...auth("desk-token-1"), Upgrade: "websocket" } }), env);
  const old = LIMITS.waitMs;
  LIMITS.waitMs = 50;
  try {
    const r = await worker.fetch(req(`/c/${CH}/req`, { method: "POST", headers: auth("phone-token-1"), body: "x" }), env);
    assert.equal(r.status, 504);
  } finally { LIMITS.waitMs = old; }
});

test("keep-alive pings are answered", async () => {
  const env = makeEnv();
  await register(env);
  await worker.fetch(req(`/c/${CH}/desk`, { headers: { ...auth("desk-token-1"), Upgrade: "websocket" } }), env);
  const ch = env.objects.get(CH);
  const s = ch.state.getWebSockets()[0];
  await ch.webSocketMessage(s, JSON.stringify({ ping: 5 }));
  assert.deepEqual(JSON.parse(s.sent.at(-1)), { pong: 5 });
});
