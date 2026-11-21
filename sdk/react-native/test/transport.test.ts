import { test } from "node:test";
import assert from "node:assert/strict";
import { createTailPocket } from "../../js/client.ts";
import { reactNativeTransport, type NativeTailPocket } from "../src/transport.ts";

/** The native module as React Native hands it over: call() → promise, events through an emitter. */
function fakeNative(answers: Record<string, unknown>) {
  const calls: [string, unknown][] = [];
  const listeners = new Map<string, Set<(d: unknown) => void>>();
  const module: NativeTailPocket = {
    async call(name, args) {
      calls.push([name, args]);
      if (answers[name] instanceof Error) throw answers[name];
      return answers[name] ?? null;
    },
    addListener() {},
    removeListeners() {},
  };
  const emitter = {
    addListener(event: string, l: (d: unknown) => void) {
      if (!listeners.has(event)) listeners.set(event, new Set());
      listeners.get(event)!.add(l);
      return { remove: () => listeners.get(event)!.delete(l) };
    },
  };
  return { module, emitter, calls, emit: (e: string, d: unknown) => listeners.get(e)?.forEach((l) => l(d)) };
}

test("calls go to the native module with their arguments (null when none)", async () => {
  const n = fakeNative({ "tailPocket.newKey": "privkey:n", "tailPocket.store.link": null });
  const tailPocket = createTailPocket(reactNativeTransport(n.module, n.emitter));
  assert.equal(await tailPocket.newKey(), "privkey:n");
  await tailPocket.store.link("work");
  assert.deepEqual(n.calls, [["tailPocket.newKey", null], ["tailPocket.store.link", { slot: "work" }]]);
});

test("a native rejection keeps its code", async () => {
  const n = fakeNative({ "tailPocket.connect": Object.assign(new Error("Not paired yet"), { code: "not-paired" }) });
  await assert.rejects(createTailPocket(reactNativeTransport(n.module, n.emitter)).connect(), (e: any) => e.code === "not-paired");
});

test("nearby events arrive through the emitter and stop with it", async () => {
  const n = fakeNative({});
  const seen: string[] = [];
  const stop = await createTailPocket(reactNativeTransport(n.module, n.emitter)).nearby("_x._tcp", (h) => seen.push(...h.map((x) => x.name)));
  n.emit("tailPocket.nearby", { hosts: [{ name: "Mac" }] });
  await stop();
  n.emit("tailPocket.nearby", { hosts: [{ name: "gone" }] });
  assert.deepEqual(seen, ["Mac"]);
});

test("the pairing emoji arrive through the emoji event while pair waits", async () => {
  const n = fakeNative({});
  const tailPocket = createTailPocket(reactNativeTransport(n.module, n.emitter));
  const shown: string[][] = [];
  n.module.call = async (name, args) => { n.calls.push([name, args]); n.emit("tailPocket.pair.emoji", { emoji: ["🐶", "🌙", "🍕", "🔑"] }); return { name: "Mac", key: "k" }; };
  await tailPocket.pair("tailpocket2:x", { device: "Pixel", onEmoji: (e) => shown.push(e) });
  assert.deepEqual(shown, [["🐶", "🌙", "🍕", "🔑"]]);
  await tailPocket.setTailcatOnly(true);
  assert.deepEqual(n.calls.at(-1), ["tailPocket.setTailcatOnly", { on: true }]);
  await tailPocket.setRoutes(["relay"]);
  assert.deepEqual(n.calls.at(-1), ["tailPocket.setRoutes", { routes: ["relay"] }]);
});

// RCTEventEmitter on iOS drops events missing from supportedEvents(): it must list every event the bridges emit.
test("the iOS module lists every bridge event", async () => {
  const { readFileSync } = await import("node:fs");
  const read = (p: string) => readFileSync(new URL(p, import.meta.url), "utf8");
  const emitted = new Set([...read("../../apple/Sources/TailPocket/Bridge.swift").matchAll(/emit\("(tailPocket\.[a-zA-Z.]+)"/g)].map((m) => m[1]));
  const supported = read("../ios/TailPocketModule.swift").match(/supportedEvents\(\) -> \[String\] \{ \[([^\]]*)\]/)![1];
  assert.deepEqual([...emitted].sort(), ["tailPocket.nearby", "tailPocket.pair.emoji"]);
  for (const e of emitted) assert.ok(supported.includes(`"${e}"`), e);
});

test("connect passes the native baseUrl and token through", async () => {
  const n = fakeNative({ "tailPocket.connect": { handle: 1, port: 5555, baseUrl: "http://127.0.0.1:5555/_tailpocket/TOK", token: "TOK" } });
  const c = await createTailPocket(reactNativeTransport(n.module, n.emitter)).connect();
  assert.equal(c.token, "TOK");
  assert.ok(c.baseUrl.endsWith(`/_tailpocket/${c.token}`));
});

test("without the native module it says how to fix that", () => {
  assert.throws(() => reactNativeTransport(undefined, undefined), /TailPocket native module is missing/);
});
