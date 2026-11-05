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

test("without the native module it says how to fix that", () => {
  assert.throws(() => reactNativeTransport(undefined, undefined), /TailPocket native module is missing/);
});
