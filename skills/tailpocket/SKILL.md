---
name: tailpocket
description: Use when a user wants their phone app to reach an app or server running on their computer from anywhere (home, mobile data, other Wi-Fi) without running a server, port forwarding or a VPN app, or asks to add QR-code pairing between a phone and a computer. Adds TailPocket to both sides and proves it works end to end.
---

# TailPocket: reach a computer's app from a phone app, from anywhere

The computer shows a QR code, the phone scans it once, and from then on the phone app gets a
`http://127.0.0.1:PORT` address that ends at a port on the computer, from any network. Traffic is
WireGuard-encrypted, peer to peer when the networks allow, relayed otherwise. The user's server and
protocol (HTTP, WebSocket, gRPC, raw TCP) stay as they are.

## 1. Ask the user only what you cannot find in their code

- Which port the computer-side server listens on. Look for it first (`listen(`, `PORT`, config files).
- Where the computer side may keep its state. It holds private keys: the OS keychain, or a file with
  mode 0600 outside the repository. Never a log or a committed file.

Everything else has a default below.

## 2. Get the packages

Every package is ready-built in the latest release; nothing to clone or build. The table in
`docs/INTEGRATE.md` section 0 (https://github.com/jt-wang/tailpocket/blob/main/docs/INTEGRATE.md) lists the
file for each stack. Download the test phone for this computer too, into a temp folder:

```sh
R=https://github.com/jt-wang/tailpocket/releases/download/v0.2.4
T=$(mktemp -d)   # 0700; the test phone's key goes here too
curl -fsSLo "$T/tailpocket-phone" "$R/tailpocket-phone-<os>-<arch>" && chmod +x "$T/tailpocket-phone"
```

Check each download against `$R/SHA256SUMS`.

## 3. The computer side

Pick the user's stack:

- Node: `npm install $R/tailpocket-node.tgz` (no other dependencies), then
  `import { TailPocketHost } from 'tailpocket'`. Shape it like
  `examples/node-host/server.mjs` and read `index.d.ts` in the installed package for every option.
- Go: package `connecthost`, see `docs/INTEGRATE.md` section 1.
- Anything else: download `$R/tailpocket-host-<os>-<arch>`, spawn it and speak JSON lines (`docs/HOST-IPC.md`).

```js
const connectHost = await TailPocketHost.start({
  forward: '127.0.0.1:<port>',
  identity: saved?.identity, allowed: saved?.allowed,   // restore, or every restart forgets the phones
  save: (state) => writeSecret(state),                  // called before each change; store it 0600
});
```

Add three things to the user's computer app:

1. **Add a phone.** `const pairing = await connectHost.pair()` opens a window (default 120 s) and
   `pairing.qr` is the text to show as a QR code. Render it in the app's own UI with any QR library.
   For a headless server, add a local-only trigger (a CLI subcommand, or an endpoint bound to
   127.0.0.1) and write the text to a 0600 file. The example prints it to the console for the demo;
   do not do that in a real app, since anyone holding the text can pair until it expires.
2. **Paired phones.** `await pairing.paired` gives `{ phone, device }`. The saved state keeps only
   the keys (`allowed`), so store the key-to-device-name map yourself if you show names.
3. **Remove a phone.** `connectHost.revoke(phone)` with the key from `paired` or `connectHost.allowed`.

Check before you touch the phone, with the test phone from step 2 (keys in a 0600 temp folder; the
QR text goes in on stdin, not on the command line, so it stays out of `ps` and shell history):

```sh
P="$T/tailpocket-phone"
$P pair -key "$T/phone.key" -out "$T/link.json" - < qr.txt   # prints: paired with "<name>"
$P connect -link "$T/link.json" &                             # keeps running; prints: listening 127.0.0.1:PORT base BASE token …
curl BASE/<a path the user's server answers>                  # BASE is http://127.0.0.1:PORT/_tailpocket/<token>
```

## 4. The phone side

Follow the paragraph for the user's phone stack in `docs/INTEGRATE.md` section 2 (Swift, Kotlin,
React Native, NSH). For every stack:

- Scan with the ready-made scanner and pairing screen unless the user already has a camera flow;
  any scanner works, since the QR text is decoded by `decodeInvite`.
- Store the phone key and the link with the provided Keychain or Keystore store.
- Point the app's existing networking at `connection.baseUrl` and build every URL by appending a
  path to it (`baseUrl + "/api"`). It carries a per-connection secret in its path; a request
  without it gets 403. Do not rewrite the app's protocol.
- Android: set `@xml/tailpocket_network_security_config`, or plain HTTP to 127.0.0.1 is refused.
- iOS: add `NSCameraUsageDescription`, `NSLocalNetworkUsageDescription` and the Bonjour service.

Optional: pairing on the same Wi-Fi without the camera, where both screens show a 6-digit code. See
`pairing.local({ service, confirm })` in `docs/INTEGRATE.md` sections 1 and 2.

## 5. Prove it, then report

Run these, with the real phone app if one is attached, otherwise with the test phone:

1. Pair by QR, then request the user's server through the phone's `127.0.0.1` address.
2. Reopen the phone app (with the test phone: stop `connect` and run it again): it connects without
   pairing.
3. Restart the computer side: the phone still connects.
4. Revoke the phone: its next request fails. A revoked test phone still prints `listening …`; the
   request through it is what fails (curl gets an empty reply), so check the request.

Also run the stack's own tests named in its `docs/INTEGRATE.md` paragraph. Tell the user which
steps you ran, with what, and which you could not run (for example, no physical phone attached).
