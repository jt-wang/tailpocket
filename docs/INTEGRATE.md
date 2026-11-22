# Integrating tailpocket (for people and their AI agents)

Follow the section for each side you are adding. Every step ends with a check you can run. Every
package comes ready-built from the [latest release](https://github.com/jt-wang/tailpocket/releases/latest):
nothing to clone, no Go or gomobile. To build them yourself, see [BUILD.md](BUILD.md).

## 0. The packages

`R=https://github.com/jt-wang/tailpocket/releases/download/v0.3.4` below.

| Side | Get it |
|---|---|
| Computer, Node | `npm install $R/tailpocket-node.tgz` (the helper for macOS, Linux and Windows is inside) |
| Computer, Go | `go get github.com/jt-wang/tailpocket@v0.3.4` |
| Computer, any language | the helper `$R/tailpocket-host-<os>-<arch>` (`darwin-arm64`, `darwin-amd64`, `linux-amd64`, `linux-arm64`, `windows-amd64.exe`) |
| Phone, Swift | Swift package `https://github.com/jt-wang/tailpocket`, from `0.3.4` |
| Phone, Kotlin | unzip `$R/tailpocket-android-m2.zip` into your project and add its `m2` folder as a Maven repository |
| Phone, React Native | `npm install $R/react-native-tailpocket.tgz` |
| Phone, NSH | `npm install $R/tailpocket-client.tgz`, and the native adapter from the Swift or Kotlin row |
| Test phone (command line) | `$R/tailpocket-phone-<os>-<arch>` |

`SHA256SUMS` in the release lists every file's hash.

## 1. The computer side

Decide two things first: the port your server listens on (`forward`), and where the state is
stored. The state holds private keys: use the OS keychain or a file with mode 0600, never a log.

**Node:** depend on the `tailpocket` package. Copy the shape of
`examples/node-host/server.mjs` (import from `'tailpocket'`): `TailPocketHost.start({forward, identity, allowed, save})`, then
`connectHost.pair({ttl, payload})` when the user asks to add a phone, show `pairing.qr` as a QR code, and
optionally `pairing.local({service, confirm})` for same-Wi-Fi pairing. Show `code` and `device` in
`confirm` and return the user's answer.

**Go:** import `github.com/jt-wang/tailpocket/connecthost`: `connecthost.New(connecthost.Config{…})`,
`h.Start(ctx)`, `h.Pair(ctx, connecthost.PairOptions{…})`, `p.QR(connectinvite.DefaultPrefix)`, `p.ServeLocal(ctx, …)`,
`p.Wait(ctx)`. Accept phone connections from `h.Listener()`; `connecthost.PhoneOf(conn)` names the phone.

**Any other language:** spawn `tailpocket-host` and follow [HOST-IPC.md](HOST-IPC.md).

Offer "remove this phone" in your UI: `connectHost.revoke(phone)`. It closes that phone's connections
at once, so send anything the phone should hear (such as "you were removed") before calling it.

Check: run your app, open a pairing window, and pair with the CLI phone:
`tailpocket-phone-<os>-<arch> pair -key phone.key -out link.json -` with the QR text on stdin, then
`connect -link link.json`, which prints a `base` URL with a token in its path, and request your server
under it (`curl <base>/`).

## 2. The phone side

Pick a Bonjour service type for your app (`_myapp._tcp`, at most 15 characters between `_` and
`._tcp`) and use the same one on both sides.

**iOS / macOS (Swift):** add the Swift package `https://github.com/jt-wang/tailpocket` (from `0.3.4`; it
downloads the prebuilt `TailPocketMobile.xcframework` from the release); depend on `TailPocket`
and, for the camera scanner and pairing view, `TailPocketUI`. In Info.plist add
`NSCameraUsageDescription`, `NSLocalNetworkUsageDescription`, and your service under
`NSBonjourServices`. Use `TailPocketKeychainStore` for the phone key and the paired computer. The fastest
path is `TailPocketPairingView` (scan or nearby, then `onPaired`); the pieces are `TailPocketQRScanner`,
`TailPocketNearbyHosts`, `TailPocketLocalPairing.begin`, `TailPocket.pair` and `TailPocket.connect`.
Check: `swift test`; with the computer running, `TAILPOCKET_LIVE=1 swift test --filter LiveTests` on macOS.

**Android (Kotlin):** unzip `tailpocket-android-m2.zip` into your project, add
`maven { url = uri("m2") }` (the path to that folder) and depend on
`io.jingtao.tailpocket:tailpocket:0.3.4` (and `tailpocket-ui` for the Compose
scanner and `TailPocketPairingScreen`). The libraries declare INTERNET, ACCESS_NETWORK_STATE and CAMERA.
Set `android:networkSecurityConfig="@xml/tailpocket_network_security_config"` on your
`<application>` (or add its `127.0.0.1` domain-config to your own config): Android refuses plain
HTTP to `TailPocketConnection.baseUrl` otherwise. Use `TailPocketKeystoreStore`. Check: `./gradlew test`, and
`scripts/e2e-android.sh` as a model for an instrumented test against a real host.

**NSH:** in the native app, `TailPocketNsh.attach(view)` (iOS: copy `sdk/apple/NSH/Sources` into your app next
to its NativeShell.xcframework, with the Swift package above; Android: copy `sdk/android/tailpocket-nsh` as a module
next to the Maven repository above). In
the NSH app, list the `tailPocket.*` names under `capabilities.host` in nsh.json (copy
`examples/nsh-phone/nsh.json`), allow `127.0.0.1` under `capabilities.network`, and
`import { tailPocket } from "tailpocket-client/nsh"`. Check: `nsh test` in your app with host handlers
(see `examples/nsh-phone/App.test.tsx`); `scripts/e2e-nsh-ios.sh` and `scripts/e2e-nsh-android.sh`
run the example against a real host.

**React Native (0.75+):** add `react-native-tailpocket` and
`import { tailPocket } from "react-native-tailpocket"`. Same calls as NSH. `examples/rn-phone` is a
complete app; copy from it:
- Android: `minSdkVersion = 26`, the Maven repository from the Kotlin step, and
  `android:networkSecurityConfig="@xml/tailpocket_network_security_config"` in place of the
  template's `usesCleartextTraffic`.
- iOS: the Info.plist keys from the Swift step, then `pod install`. The pod
  (`TailPocketReactNative`) pulls in the Swift package from GitHub.

Check: `scripts/e2e-rn-android.sh` and `scripts/e2e-rn-ios.sh` build the example and pair it with a
real host.

## 3. Prove it end to end

1. Start the computer side and open a pairing window.
2. Pair the phone by QR code, then close and reopen the phone app: it reconnects without pairing.
3. Restart the computer side with the saved state: the phone still connects.
4. Pair over the same Wi-Fi: both screens show the same 6-digit code.
5. Revoke the phone on the computer: its next connection fails.

## 4. What v0.3 adds

The packages above are v0.3.4. Everything in sections 1 to 3 applies, with these additions. Moving
from v0.2, read the upgrade notes under v0.3.0 in [CHANGELOG.md](../CHANGELOG.md) first.

### Defaults: nothing to configure

With no new settings, a v0.3 computer is reachable over Tailcat (tailcat.dev, as in v0.2) and, on
the same Wi-Fi, over the local network: it listens on its private addresses only (RFC 1918, CGNAT,
IPv6 ULA and link-local, at most 4), on a port derived from its key, follows address changes, and
accepts nothing there but a Noise handshake (a paired phone, or a phone pairing in an open window). No relay runs unless you add one.

- `noLan: true` (Go `Config.NoLAN`): no local network listener.
- `tailcatOnly: true` (Go `Config.TailcatOnly`): Tailcat only, as before v0.3. No local network
  listener, no relay connection, and v2 invites and routes list Tailcat alone. It cannot be combined
  with `relays` or `listen` (the helper fails with `invalid-config`). Pairings and phones from v0.2
  work as before.
- On the phone, `setTailcatOnly(true)` (Swift `TailPocket.setTailcatOnly`, Kotlin
  `TailPocket.setTailcatOnly`, JS/NSH/React Native `tailPocket.setTailcatOnly`, Go
  `connectphone.Options.TailcatOnly`) makes the phone ignore every relay and local network route an
  invite or a computer lists. Offer both switches to users who want Tailcat only.

### Routes you choose; Tailcat is optional (v0.3.2)

`routes` (Go `Config.Routes`) lists exactly the routes the computer runs: any of `tailcat`, `lan`,
`relay`. Leave it out and nothing changes. Without `tailcat` no Tailcat node starts and nothing
talks to tailcat.dev or DERP; pairing, emoji, revoke and route upgrades work over the others. Pair
with `emoji: true` windows (`qr2`); v1 codes need Tailcat.

```json
{"v":1,"forward":"127.0.0.1:7681","routes":["lan"]}
{"v":1,"forward":"127.0.0.1:7681","routes":["relay"],"relays":[{"url":"wss://relay.example.com","token":"…"}]}
{"v":1,"forward":"127.0.0.1:7681","routes":["lan","relay"],"relays":[{"url":"wss://relay.example.com","token":"…"}]}
```

On the phone, `setRoutes(["lan","relay"])` (Swift `try TailPocket.setRoutes`, Kotlin
`TailPocket.setRoutes`, JS `tailPocket.setRoutes`, Go `connectphone.Options.Routes`) keeps it off
Tailcat too: it starts no Tailcat client even when the computer lists one. `null` allows every route.
An empty, unknown or repeated route, or `routes` combined with `tailcatOnly`/`noLan`, is refused
(`invalid-config` with a `message` on the computer, `invalid-routes` on the phone). On the phone,
`setRoutes` (also `setRoutes(null)`) and `setTailcatOnly(true)` replace each other: the last call
decides. The setting lives in the app's process: call `setRoutes` at every launch before `pair` or
`connect`, and pass `null` only on purpose. Since v0.3.3, `setRoutes` takes an array of route types
or an explicit `null`, nothing else: `setRoutes()` with no argument, or `undefined` (for example a
setting that did not load), is refused with `invalid-arguments` (Swift and Kotlin bridges) or
`invalid-routes` (JS client) and changes nothing; in v0.3.2 it allowed every route. Save `keys` with
the state: a computer without Tailcat forgets a phone whose key it lost, and that phone pairs again.

### State: save `keys`

The state to save gains `keys`, each phone's end-to-end key. Pass it back (`keys` in the helper
config, Go `Config.Keys`). A computer started without it still accepts its phones over Tailcat and
never tells them they are unpaired; a phone's `sync` registers its key again.

### Pairing: compare emoji on the computer

Open the window with `pair({ttl, payload, emoji: true})` (Go: `PairOptions.Confirm`) and show
`pairing.qr2` (Go: `p.QR2(prefix)`). The phone pairs over the first route it reaches. Before
anything is saved, both screens show the same four emoji, derived from the Noise handshake on every
route, Tailcat included:

- Computer: a `request` event `{phone, device, route, emoji}` (Go: `Confirm(ctx, PairRequest)`).
  Show `device` and the emoji and ask the user whether the phone shows the same; answer with
  `confirm(true)` or `confirm(false)` within 55 s. No answer, a no, or the phone leaving ends the
  window, and its invite pairs nobody after that. With no `request` listener the phone is refused.
- Phone: `onEmoji` (Swift and Kotlin: required; JS: `pair(invite, {onEmoji})`) shows them. The user
  confirms on the computer only.

A window without `emoji` hands out only the v1 `qr` (Tailcat, as in v0.2). Same-Wi-Fi pairing
without a camera (`pairing.local`) still shows a 6-digit code on both screens; in v0.3 its
wire protocol is version 2 (the phone commits to its key before it sees the computer's), so phone
and computer must both be v0.3. A window lets at most 3 phones try and then
closes with `local-too-many-attempts` (Go: `connectlocal.ErrTooManyAttempts`, and the whole window
ends): tell the user to start again. `ServeLocal` runs once per window.

### Relays (optional)

Run your own `tailpocket-relay` (`cmd/tailpocket-relay`; it always needs a token) and list it in
`relays: [{url, token}]`. The relay passes only Noise ciphertext between a phone and the computer.

An opaque relay (`opaque: true`) skips TailPocket's Noise layer for apps that encrypt end to end
themselves. Anyone who knows the room reaches your app's port through it, so:

- You MUST set `appAuth: true` (Go `Relay.AppAuth`) on an opaque relay, and only when your app
  authenticates every connection itself (TLS with a pinned key and a per-device credential, for
  example). Without it the computer side refuses to start.
- An opaque connection has no phone identity: `PhoneOf` is "", the `identifyPhone` line and the
  `authorize` event say `opaque`. Revoking or disconnecting any phone closes every open opaque
  connection; your own credential check decides each new one.

### The phone's local forward (MUST)

`connect` opens a port on `127.0.0.1` that reaches the computer as this phone.
Any program on the phone can connect to a loopback port, so the forward lets nothing through without
the connection's token, and your app MUST follow these rules:

- Build every HTTP and WebSocket URL by appending to `baseUrl` (`baseURL` in Swift), which is
  `http://127.0.0.1:<port>/_tailpocket/<token>`: `"$baseUrl/api/info"`, `` `${baseUrl}/api/info` ``,
  `baseURL.appendingPathComponent("api/info")`. The forward removes the prefix, so your server sees
  `/api/info`. A URL resolved against "/" (`new URL("/api/info", baseUrl)`, `URL(string: "/api/info",
  relativeTo: baseURL)`, OkHttp's `resolve("/api/info")`) drops the prefix and gets 403. A client that
  cannot keep the prefix sends the header `Tailpocket-Token: <token>` on every request instead.
- A client of another protocol (your own TLS, for example) MUST start each connection with the line
  `TP-FWD <token>\n`; the forward removes it and then carries the bytes as they are. Without it, or
  with a wrong token, the connection is closed and the computer is never dialed.
- Keep the token (`token` on the connection) in memory only: never store, log or send it anywhere. A
  new `connect` gets a new token.

### When it cannot connect: tell the user why (v0.3.4)

A request through the forward that cannot reach the computer fails like a dropped connection. Then
read `lastFailure()` on the connection (Swift `try connection.lastFailure()`, Kotlin
`connection.lastFailure()`, JS `await conn.lastFailure()`) and show one of three messages instead of
"Connecting…" forever:

| `reason` | Show |
|---|---|
| `refused`, `handshake-closed` | "TailPocket isn't running on the computer, or it was reset. Open it there; if it was reset, pair again." |
| `no-answer` | "Can't reach the computer. Check it's on and awake; this network may block the connection." |
| `relay-down` | "Your relay server can't be reached." |

`null` means nothing failed since the last connection that worked; `revoked` keeps its own handling
(delete the link). The reason is not authenticated: offer pairing again as a button, never unpair or
delete the link because of it (SECURITY.md §6b). A Dial gives up after at most 30 s on its last route,
so on a network that drops packets the first request fails within that and `lastFailure` says
`no-answer`.

### Compatibility

- Phones on v0.2 keep using Tailcat with a v0.3 computer; nothing to pair again.
- Pairing over a v2 invite (`qr2`) and same-Wi-Fi pairing need v0.3 on both sides: upgrade the phone
  app and the computer together.
- A phone app moving to v0.3 MUST take its URLs from `baseUrl` (see above); code that builds
  `http://127.0.0.1:<port>` from the port gets 403.
