# Integrating tailpocket (for people and their AI agents)

Follow the section for each side you are adding. Every step ends with a check you can run. Every
package comes ready-built from the [latest release](https://github.com/jt-wang/tailpocket/releases/latest):
nothing to clone, no Go or gomobile. To build them yourself, see [BUILD.md](BUILD.md).

## 0. The packages

`R=https://github.com/jt-wang/tailpocket/releases/download/v0.2.4` below.

| Side | Get it |
|---|---|
| Computer, Node | `npm install $R/tailpocket-node.tgz` (the helper for macOS, Linux and Windows is inside) |
| Computer, Go | `go get github.com/jt-wang/tailpocket@v0.2.4` |
| Computer, any language | the helper `$R/tailpocket-host-<os>-<arch>` (`darwin-arm64`, `darwin-amd64`, `linux-amd64`, `linux-arm64`, `windows-amd64.exe`) |
| Phone, Swift | Swift package `https://github.com/jt-wang/tailpocket`, from `0.2.0` |
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
`connect -link link.json` and request your server through the printed `127.0.0.1` port.

## 2. The phone side

Pick a Bonjour service type for your app (`_myapp._tcp`, at most 15 characters between `_` and
`._tcp`) and use the same one on both sides.

**iOS / macOS (Swift):** add the Swift package `https://github.com/jt-wang/tailpocket` (from `0.2.0`; it
downloads the prebuilt `TailPocketMobile.xcframework` from the release); depend on `TailPocket`
and, for the camera scanner and pairing view, `TailPocketUI`. In Info.plist add
`NSCameraUsageDescription`, `NSLocalNetworkUsageDescription`, and your service under
`NSBonjourServices`. Use `TailPocketKeychainStore` for the phone key and the paired computer. The fastest
path is `TailPocketPairingView` (scan or nearby, then `onPaired`); the pieces are `TailPocketQRScanner`,
`TailPocketNearbyHosts`, `TailPocketLocalPairing.begin`, `TailPocket.pair` and `TailPocket.connect`.
Check: `swift test`; with the computer running, `TAILPOCKET_LIVE=1 swift test --filter LiveTests` on macOS.

**Android (Kotlin):** unzip `tailpocket-android-m2.zip` into your project, add
`maven { url = uri("m2") }` (the path to that folder) and depend on
`io.jingtao.tailpocket:tailpocket:0.2.4` (and `tailpocket-ui` for the Compose
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
