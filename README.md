# TailPocket

Your app runs on your computer. You want your phone app to reach it at home, on the train, and on
hotel Wi-Fi. Normally that means running a server in the middle, setting up port forwarding, or
asking every user to install a VPN app and make an account.

With TailPocket the computer shows a QR code and the phone app scans it once. From then on the
phone app reaches a port on that computer from any network. There is no server to run, no
account, and nothing to install besides your own app.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/what-it-is-dark.gif">
  <img src="docs/images/what-it-is-light.gif" width="100%" alt="A computer shows a QR code and a phone scans it once. From then on the phone app and the computer's app talk both ways, at home, on 5G and on hotel Wi-Fi. On the same Wi-Fi, the phone can pick the computer instead, and both screens show the same 6-digit code.">
</picture>

## Give your agent the skill

Tell your coding agent:

> Make my app reachable from my phone. Use the TailPocket skill: https://github.com/jt-wang/tailpocket/blob/main/skills/tailpocket/SKILL.md

The skill has the agent ask you only what it cannot find in your code (your server's port, where
to keep the keys), add pairing to your computer app, and add a QR scanner to your phone app. It then pairs
a test phone, reopens the app, restarts the host, and revokes the phone, and reports which of
those steps it ran. A fresh agent given only the skill and a sample Node app passed all four.

To install it as a skill, copy `skills/tailpocket` into your agent's skills folder (for Claude
Code, `~/.claude/skills/`).

## What you get

Both ends are small [Tailcat](https://github.com/tailscale/tailcat) nodes: WireGuard-encrypted,
peer to peer when the networks allow it, relayed otherwise. Your app keeps its own protocol: the
phone gets a `http://127.0.0.1:PORT` (or a raw stream) that ends at the port you chose on the
computer, so your existing HTTP, WebSocket or gRPC code works unchanged. On the same Wi-Fi the phone
can also find the computer over Bonjour and pair after the person checks a 6-digit code, with no
camera.

TailPocket is an independent open-source project built on Tailscale's Tailcat. Tailscale does not
make or support it.

| Side | Stack | Package |
|---|---|---|
| Computer | Go | `connecthost` |
| Computer | Node, or any language that can spawn a process | `sdk/node`, or the `tailpocket-host` helper over stdin/stdout |
| Phone | Swift (iOS 15+, macOS 13+) | Swift package `TailPocket`, plus `TailPocketUI` (QR scanner, pairing view) |
| Phone | Kotlin (Android 8+) | `tailpocket`, plus `tailpocket-ui` (Compose QR scanner, pairing screen) |
| Phone | NSH | `sdk/js/nsh.ts`, plus the native adapters `TailPocketNSH` (iOS) and `tailpocket-nsh` (Android) |
| Phone | React Native | `sdk/react-native` |
| Phone | Go, or a command line | `connectphone`, `tailpocket-phone` |

Every phone SDK has the same calls: scan, pair, find nearby computers, connect, and a Keychain or
Keystore store for the phone key and the paired computers. It came out of two phone companion
apps that were each building this pairing by hand.

## Try it in two minutes

You need Node 20 or newer. Everything else comes ready-built from the release.

```sh
mkdir tailpocket-try && cd tailpocket-try
R=https://github.com/jt-wang/tailpocket/releases/download/v0.3.1
npm install $R/tailpocket-node.tgz
curl -fsSLO https://raw.githubusercontent.com/jt-wang/tailpocket/main/examples/node-host/server.mjs
node server.mjs                                    # prints "QR tailpocket1:…", a one-time pairing code
```

In a second terminal in the same folder, play the phone (on a Mac with Apple silicon; the release has
`tailpocket-phone` for Intel Macs, Linux and Windows too):

```sh
curl -fsSLo phone https://github.com/jt-wang/tailpocket/releases/download/v0.3.1/tailpocket-phone-darwin-arm64 && chmod +x phone
pbpaste | ./phone pair -key phone.key -out link.json -   # copy the tailpocket1:… text first
./phone connect -link link.json                         # prints "listening 127.0.0.1:PORT base BASE token …"
curl BASE/hello.txt                                     # BASE is http://127.0.0.1:PORT/_tailpocket/<token>; "hello from the computer"
```

For a real phone, run one of the examples below. To build TailPocket from source, see
[docs/BUILD.md](docs/BUILD.md).

## Add it by hand

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/how-to-use-dark.gif">
  <img src="docs/images/how-to-use-light.gif" width="100%" alt="The code. On the computer: TailPocketHost.start in front of your server, then connectHost.pair and show pairing.qr. On the phone in Swift: scan, pair, save the link, connect, and fetch hello.txt from the local address. Then the same calls in Kotlin, React Native and NSH.">
</picture>

Both animations are also pages with a pause button: [docs/illustrations](docs/illustrations).

**The computer side (Node):** start a host that forwards phones to your server, open a pairing
window, show its `qr` text as a QR code.

```js
import { TailPocketHost } from 'tailpocket';

const connectHost = await TailPocketHost.start({
  forward: '127.0.0.1:3000',                 // your server
  identity: saved?.identity, allowed: saved?.allowed,
  save: (state) => writeSecret(state),       // keys and paired phones; store it like a password
});
const pairing = await connectHost.pair({ ttl: 120, payload: sessionToken });
showQR(pairing.qr);
pairing.local({ service: '_myapp._tcp', confirm: (code, device) => askUser(code, device) }); // same Wi-Fi
const { device } = await pairing.paired;
```

Go apps use `connecthost.New(connecthost.Config{…})`, `h.Pair(ctx, connecthost.PairOptions{…})` and `p.ServeLocal`
directly. Any other language spawns `tailpocket-host` and talks to it in JSON lines
([docs/HOST-IPC.md](docs/HOST-IPC.md)).

**The phone side (Swift):**

```swift
let invite = try TailPocket.decodeInvite(scannedText)
let link = try await TailPocket.pair(invite, phoneKey: try store.phoneKey(), device: UIDevice.current.name)
try store.saveLink(link)
let connection = try TailPocket.connect(link)        // connection.baseURL → your server
```

**Kotlin:** the same names on `TailPocket.default` (`decodeInvite`, `pair`, `connect`), with
`TailPocketKeystoreStore`. Android blocks plain HTTP by default, so point your manifest at
`@xml/tailpocket_network_security_config`, which allows `127.0.0.1` only.

**NSH and React Native:** one TypeScript API over the native SDKs.

```ts
const link = await tailPocket.pair(await tailPocket.scan(), { device: "My phone", save: true });
const { baseUrl } = await tailPocket.connect();
const answer = await fetch(baseUrl + "/hello.txt");
```

The full examples are `examples/nsh-phone` (its native side is one line:
`TailPocketNsh.attach(view)`) and `examples/rn-phone`.

Per stack, [docs/INTEGRATE.md](docs/INTEGRATE.md) lists the files to add, the permissions to
declare, and the test that proves it works. The skill points the agent there too.

## What has been tested

Measured with an Apple-silicon Mac as the computer, over Tailcat's default relays:

- QR pairing, Go phone to Go host: the pairing window opened in 1.5 s; pairing took 4.7 s from
  the phone reading the code to paired; the first round trip through the tunnel came back 4.1 s
  after connecting. A restarted host keeps its address and its phones; a
  revoked phone is refused.
- Same-Wi-Fi pairing through real Bonjour.
- End to end against the Node example host: the Swift package on macOS, the iOS Simulator (Swift
  the NSH app and the React Native app), an Android emulator (Kotlin, the NSH app and the React
  Native app).
- Unit tests in every package (`go test ./...`, `swift test`, `./gradlew test`, `npm test` in
  `sdk/node`, `sdk/js` and `sdk/react-native`, `nsh test` in `examples/nsh-phone`).
- A physical Android phone: scanned the QR code and connected over cellular.

Not tested yet: physical iPhones, Linux and Windows hosts (the binaries build),
Android's Bonjour discovery (the emulator cannot see the Mac's Bonjour), pairing links on iOS (the
simulator asks before opening one, so the iOS test passes the invite as a launch argument), and the
built-in Go Bonjour responder on macOS (macOS's own `dns-sd` is used there).

## How it works, and what it trusts

1. The computer runs a main Tailcat node that admits only the phones it has paired.
2. Opening a pairing window starts a second, short-lived node that admits exactly one key: a fresh
   key inside the QR code, together with a random proof. The QR code is the secret; it expires
   after the window (default 2 minutes, at most 15).
3. The phone uses that key to reach the pairing node and sends its own long-term public key.
   The computer adds it to the main node's allowlist and replies with the main node's address and
   your `payload`.
4. From then on the phone connects to the main node with its own key. Removing it from the
   allowlist (`revoke`) cuts it off.

Same-Wi-Fi pairing hands the same invite over the local network instead of through the camera:
an X25519 exchange, a 6-digit code both screens show, and the invite sealed with
ChaCha20-Poly1305. Relays only see encrypted WireGuard packets. Tailcat's default relays are free
and rate-limited; set `derpMapUrl` to use your own.

Details: [docs/PROTOCOL.md](docs/PROTOCOL.md) (pairing and wire formats),
[docs/HOST-IPC.md](docs/HOST-IPC.md) (the helper's JSON lines),
[docs/BRIDGE.md](docs/BRIDGE.md) (the function table NSH and React Native call).

## License

MIT. The pairing design comes from Voxt Mobile; some portions are adapted from DSH Mobile (MIT).
See [NOTICE](NOTICE).
