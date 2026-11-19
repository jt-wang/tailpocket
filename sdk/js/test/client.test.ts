import { test } from "node:test";
import assert from "node:assert/strict";
import { createTailPocket, TailPocketError, type TailPocketTransport } from "../client.ts";

/** A transport that records calls and answers from a table, like the native bridge would. */
function fake(answers: Record<string, unknown | ((args: any) => unknown)>) {
  const calls: { name: string; args: unknown; timeoutMs?: number }[] = [];
  const listeners = new Map<string, Set<(data: unknown) => void>>();
  const transport: TailPocketTransport = {
    async call(name, args, timeoutMs) {
      calls.push({ name, args, timeoutMs });
      if (!(name in answers)) throw new Error("unknown-function");
      const a = answers[name];
      return typeof a === "function" ? (a as (x: unknown) => unknown)(args) : a;
    },
    on(event, listener) {
      if (!listeners.has(event)) listeners.set(event, new Set());
      listeners.get(event)!.add(listener);
      return () => listeners.get(event)!.delete(listener);
    },
  };
  const emit = (event: string, data: unknown) => listeners.get(event)?.forEach((l) => l(data));
  return { transport, calls, emit, listeners };
}

const link = { address: "fd7a:115c:a1e0::1", port: 48931, name: "Mac", payload: "tok", key: "privkey:x" };

test("pair sends the invite and options, and waits longer than a host call's default", async () => {
  const f = fake({ "tailPocket.pair": link });
  const tailPocket = createTailPocket(f.transport);
  assert.deepEqual(await tailPocket.pair("tailpocket1:abc", { device: "Pixel", save: true }), link);
  assert.deepEqual(f.calls[0].args, { invite: "tailpocket1:abc", device: "Pixel", save: true });
  assert.ok((f.calls[0].timeoutMs ?? 0) > 90_000);
});

test("a v2 pairing hands the emoji to onEmoji while it waits, then stops listening", async () => {
  let f: ReturnType<typeof fake>;
  const seen: string[][] = [];
  f = fake({ "tailPocket.pair": () => { f.emit("tailPocket.pair.emoji", { emoji: ["🐶", "🌙", "🍕", "🔑"] }); return link; } });
  const tailPocket = createTailPocket(f.transport);
  assert.deepEqual(await tailPocket.pair("tailpocket2:abc", { device: "Pixel", onEmoji: (e) => seen.push(e) }), link);
  assert.deepEqual(seen, [["🐶", "🌙", "🍕", "🔑"]]);
  assert.deepEqual(f.calls[0].args, { invite: "tailpocket2:abc", device: "Pixel" }, "the callback stays in JavaScript");
  assert.ok((f.calls[0].timeoutMs ?? 0) > 90_000 + 60_000, "the computer's user gets their minute");
  assert.equal(f.listeners.get("tailPocket.pair.emoji")?.size, 0);
  f.emit("tailPocket.pair.emoji", { emoji: ["late"] });
  assert.equal(seen.length, 1);
});

test("a refusal after the emoji rejects with unauthorized and stops listening", async () => {
  let f: ReturnType<typeof fake>;
  f = fake({ "tailPocket.pair": () => { f.emit("tailPocket.pair.emoji", { emoji: ["🐶", "🌙", "🍕", "🔑"] }); throw new Error("unauthorized"); } });
  let shown = 0;
  await assert.rejects(createTailPocket(f.transport).pair("tailpocket2:abc", { device: "Pixel", onEmoji: () => shown++ }), (e: any) => e.code === "unauthorized");
  assert.equal(shown, 1);
  assert.equal(f.listeners.get("tailPocket.pair.emoji")?.size, 0);
});

test("setTailcatOnly goes to the bridge", async () => {
  const f = fake({ "tailPocket.setTailcatOnly": null });
  await createTailPocket(f.transport).setTailcatOnly(true);
  assert.deepEqual(f.calls, [{ name: "tailPocket.setTailcatOnly", args: { on: true }, timeoutMs: undefined }]);
});

test("a rejection becomes TailPocketError with the native code", async () => {
  const nsh = fake({ "tailPocket.connect": () => { throw new Error("not-paired"); } });
  await assert.rejects(createTailPocket(nsh.transport).connect(), (e: any) => e instanceof TailPocketError && e.code === "not-paired");
  const rn = fake({ "tailPocket.connect": () => { throw Object.assign(new Error("Not paired"), { code: "not-paired" }); } });
  await assert.rejects(createTailPocket(rn.transport).connect(), (e: any) => e.code === "not-paired");
});

test("connect returns the base URL and closes by handle", async () => {
  const f = fake({ "tailPocket.connect": { handle: 7, port: 50123, baseUrl: "http://127.0.0.1:50123/_tailpocket/TOK", token: "TOK" }, "tailPocket.disconnect": null });
  const c = await createTailPocket(f.transport).connect({ slot: "work" });
  assert.equal(c.baseUrl, "http://127.0.0.1:50123/_tailpocket/TOK");
  assert.ok(c.baseUrl.includes(`/_tailpocket/${c.token}`));
  assert.equal(c.token, "TOK");
  assert.equal(c.port, 50123);
  await c.close();
  assert.deepEqual(f.calls.map((x) => [x.name, x.args]), [["tailPocket.connect", { slot: "work" }], ["tailPocket.disconnect", { handle: 7 }]]);
});

test("nearby delivers host lists until stopped", async () => {
  const f = fake({ "tailPocket.nearby.start": null, "tailPocket.nearby.stop": null });
  const seen: string[][] = [];
  const stop = await createTailPocket(f.transport).nearby("_myapp._tcp", (hosts) => seen.push(hosts.map((h) => h.name)));
  f.emit("tailPocket.nearby", { hosts: [{ name: "Mac" }] });
  await stop();
  f.emit("tailPocket.nearby", { hosts: [{ name: "late" }] });
  assert.deepEqual(seen, [["Mac"]]);
  assert.deepEqual(f.calls.map((x) => x.name), ["tailPocket.nearby.start", "tailPocket.nearby.stop"]);
  assert.deepEqual(f.calls[0].args, { service: "_myapp._tcp" });
});

const invite = { v: 1, address: "fd7a:115c:a1e0::2", port: 48932, key: "nodekey:k", proof: "p", expiresAt: 1, name: "Mac" };

test("pairNearby shows the code, then finishes with the same operation and returns the invite to pair with", async () => {
  const f = fake({ "tailPocket.local.begin": { op: 3, code: "123456" }, "tailPocket.local.finish": invite, "tailPocket.local.cancel": null });
  const p = await createTailPocket(f.transport).pairNearby({ name: "Mac", device: "Pixel" });
  assert.equal(p.code, "123456");
  assert.deepEqual(await p.finish(), invite);
  assert.deepEqual(f.calls[1].args, { op: 3 });
  assert.ok((f.calls[1].timeoutMs ?? 0) > 300_000);
  await p.cancel();
  assert.deepEqual(f.calls[2], { name: "tailPocket.local.cancel", args: { op: 3 }, timeoutMs: undefined });
});

test("scan, keys, invites and the store go straight through", async () => {
  const f = fake({
    "tailPocket.scan": "tailpocket1:scanned", "tailPocket.newKey": "privkey:n", "tailPocket.publicKey": ({ key }: any) => (key === "privkey:n" ? "nodekey:n" : null),
    "tailPocket.decodeInvite": { v: 1, address: "fd7a::1", port: 48932, key: "nodekey:k", proof: "p", expiresAt: 1 },
    "tailPocket.inviteText": "tailpocket1:x", "tailPocket.store.link": null, "tailPocket.store.saveLink": null, "tailPocket.store.deleteLink": null, "tailPocket.store.phoneKey": "privkey:s",
  });
  const tailPocket = createTailPocket(f.transport);
  assert.equal(await tailPocket.scan(), "tailpocket1:scanned");
  assert.equal(await tailPocket.newKey(), "privkey:n");
  assert.equal(await tailPocket.publicKey("privkey:n"), "nodekey:n");
  assert.equal((await tailPocket.decodeInvite("tailpocket1:x")).port, 48932);
  assert.equal(await tailPocket.inviteText("see tailpocket1:x"), "tailpocket1:x");
  assert.equal(await tailPocket.store.link(), null);
  await tailPocket.store.saveLink(link, "work");
  await tailPocket.store.deleteLink();
  assert.equal(await tailPocket.store.phoneKey(), "privkey:s");
  assert.deepEqual(f.calls.find((c) => c.name === "tailPocket.store.saveLink")!.args, { link, slot: "work" });
  assert.ok(f.calls.find((c) => c.name === "tailPocket.scan")!.timeoutMs === 0, "a scan waits for the person");
});

test("the names it calls are the bridge's names", async () => {
  const names = new Set<string>();
  const t: TailPocketTransport = { async call(n) { names.add(n); return n === "tailPocket.local.begin" ? { op: 1, code: "1" } : n === "tailPocket.connect" ? { handle: 1, port: 1, baseUrl: "" } : null; }, on: () => () => {} };
  const tailPocket = createTailPocket(t);
  await tailPocket.newKey(); await tailPocket.publicKey("k"); await tailPocket.inviteText("t"); await tailPocket.decodeInvite("t"); await tailPocket.pair("t", { device: "d" });
  await tailPocket.decodeInvite2("t"); await tailPocket.setTailcatOnly(false);
  const conn = await tailPocket.connect(); await conn.sync(); await conn.path(); await conn.link(); await conn.close();
  await (await tailPocket.nearby("s", () => {}))(); const p = await tailPocket.pairNearby({ name: "n" }); await p.finish(); await p.cancel();
  await tailPocket.scan(); await tailPocket.store.phoneKey(); await tailPocket.store.saveLink(link); await tailPocket.store.link(); await tailPocket.store.deleteLink();
  const { readFileSync } = await import("node:fs");
  const kotlin = readFileSync(new URL("../../android/tailpocket/src/main/java/io/jingtao/tailpocket/Bridge.kt", import.meta.url), "utf8");
  const bridge = [...kotlin.matchAll(/"(tailPocket\.[a-zA-Z0-9.]+)"/g)].map((m) => m[1]).filter((n) => n !== "tailPocket.nearby" && n !== "tailPocket.pair.emoji"); // events
  assert.deepEqual([...names].sort(), [...new Set(bridge)].sort());
});

test("a connection syncs, reports its path and link by handle", async () => {
  const f = fake({ "tailPocket.connect": { handle: 7, port: 1, baseUrl: "" }, "tailPocket.sync": { name: "Mac", key: "k", pk: "PK" },
    "tailPocket.path": { route: "relay", relay: "relay.example.com" }, "tailPocket.link": { name: "Mac", key: "k" } });
  const c = await createTailPocket(f.transport).connect();
  assert.equal((await c.sync()).pk, "PK");
  assert.equal((await c.path(2000)).route, "relay");
  await c.link();
  assert.deepEqual(f.calls.slice(1).map((x) => [x.name, x.args]), [["tailPocket.sync", { handle: 7 }], ["tailPocket.path", { handle: 7, timeoutMs: 2000 }], ["tailPocket.link", { handle: 7 }]]);
});
