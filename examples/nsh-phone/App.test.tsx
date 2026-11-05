import { expect, open, test } from "nsh/test";

const link = { address: "fd7a:115c:a1e0::1", port: 48931, name: "Studio Mac", payload: null, key: "privkey:synthetic" };
const tunnel = { handle: 1, port: 50123, baseUrl: "http://127.0.0.1:50123" };
const hello = { "GET http://127.0.0.1:50123/hello.txt": { body: "hello from the computer\n" } };

test("a paired phone connects and shows what the computer answered", async () => {
  const app = await open("./App.tsx", { host: { handlers: { "tailPocket.store.link": link, "tailPocket.connect": tunnel, "tailPocket.nearby.stop": null } }, network: hello });
  await app.waitFor("text:hello from the computer");
  expect(app.texts()).toContain("Studio Mac");
});

test("an unpaired phone scans the QR code, pairs and saves the computer", async () => {
  let paired: any = null;
  const app = await open("./App.tsx", {
    host: { handlers: {
      "tailPocket.store.link": null, "tailPocket.nearby.start": null, "tailPocket.nearby.stop": null, "tailPocket.scan": "tailpocket1:synthetic",
      "tailPocket.pair": (data: any) => { paired = data; return link; }, "tailPocket.connect": tunnel,
    } },
    network: hello,
  });
  await app.waitFor("text:Scan QR code");
  await app.press("id:scan");
  await app.waitFor("text:hello from the computer");
  expect(paired.invite).toBe("tailpocket1:synthetic");
  expect(paired.save).toBe(true);
});

test("a computer on the same Wi-Fi shows up; tapping it shows the code to confirm", async () => {
  let finished = false;
  let paired: any = null;
  const invite = { v: 1, address: "fd7a:115c:a1e0::2", port: 48932, key: "nodekey:k", proof: "p", expiresAt: 1, name: "Studio Mac" };
  const app = await open("./App.tsx", {
    host: { handlers: {
      "tailPocket.store.link": null, "tailPocket.nearby.start": null, "tailPocket.nearby.stop": null,
      "tailPocket.local.begin": (data: any) => ({ op: 9, code: data.name === "Studio Mac" ? "482913" : "000000" }),
      "tailPocket.local.finish": () => new Promise((resolve) => setTimeout(() => { finished = true; resolve(invite); }, 500)),
      "tailPocket.pair": (data: any) => { paired = data; return link; }, "tailPocket.connect": tunnel,
    } },
    network: hello,
  });
  await app.waitFor("text:Scan QR code");
  await app.host.send("tailPocket.nearby", { hosts: [{ name: "Studio Mac" }] });
  await app.press("text:Studio Mac");
  await app.waitFor("text:482913");
  await app.waitFor("text:hello from the computer");
  expect(finished).toBe(true);
  expect(paired.invite).toEqual(invite);
  expect(paired.save).toBe(true);
});

test("a failed pairing says why and lets the person try again", async () => {
  const app = await open("./App.tsx", {
    host: { handlers: {
      "tailPocket.store.link": null, "tailPocket.nearby.start": null, "tailPocket.nearby.stop": null, "tailPocket.scan": "tailpocket1:old",
      "tailPocket.pair": () => { throw new Error("expired"); },
    } },
  });
  await app.press("id:scan");
  await app.waitFor("text:This QR code has expired. Make a new one on the computer.");
  expect(app.texts()).toContain("Scan QR code");
});

test("forgetting the computer deletes the saved link and goes back to pairing", async () => {
  let deleted = false;
  const app = await open("./App.tsx", {
    host: { handlers: {
      "tailPocket.store.link": () => (deleted ? null : link), "tailPocket.connect": tunnel, "tailPocket.disconnect": null,
      "tailPocket.store.deleteLink": () => { deleted = true; return null; }, "tailPocket.nearby.start": null, "tailPocket.nearby.stop": null,
    } },
    network: hello,
  });
  await app.waitFor("text:hello from the computer");
  await app.press("id:forget");
  await app.waitFor("text:Scan QR code");
  expect(deleted).toBe(true);
});

test("an invite handed over at launch (a deep link) pairs without scanning", async () => {
  let paired: any = null;
  const app = await open("./App.tsx", {
    host: {
      params: { invite: "tailpocket1:from-link" },
      handlers: { "tailPocket.store.link": null, "tailPocket.pair": (data: any) => { paired = data; return link; }, "tailPocket.connect": tunnel, "tailPocket.nearby.start": null, "tailPocket.nearby.stop": null },
    },
    network: hello,
  });
  await app.waitFor("text:hello from the computer");
  expect(paired.invite).toBe("tailpocket1:from-link");
});
