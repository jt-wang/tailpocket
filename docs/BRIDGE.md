# The bridge: one function table for JavaScript in native apps

`TailPocketBridge` (Swift and Kotlin) exposes every phone-side call as `name → (args) → result`
with JSON-shaped values. NSH (`TailPocketNsh.attach`) and React Native (`TailPocketModule`)
register these names as they are; `sdk/js/client.ts` gives them types. Another JavaScript host
(a WebView, Capacitor, …) needs only a few lines to forward `call(name, args)` and the events
`tailPocket.nearby` and `tailPocket.pair.emoji`.

Failures reject with a code: `invalid-arguments`, `invalid-invite`, `invalid-key`, `invalid-link`,
`expired`, `unauthorized` (after the pairing emoji: the computer's user said no or the code was spent; show a
new code on the computer), `unreachable`, `revoked` (the computer removed this phone: delete its link), `mismatch`,
`handshake-closed`, `unknown-handle`, `denied`, `local-failed`, `not-paired`, `unsupported`, `cancelled`,
`unknown-function`, `unknown-operation`, `nearby-not-started`, `failed`.

| Name | Arguments | Result |
|---|---|---|
| `tailPocket.newKey` | | a new private phone key |
| `tailPocket.publicKey` | `key` | its `nodekey:…`, or null |
| `tailPocket.inviteText` | `text`, `prefix?` | the invite inside `text` (a link, a QR payload), or null |
| `tailPocket.decodeInvite` | `text`, `prefix?` | `TailPocketInvite` |
| `tailPocket.decodeInvite2` | `text`, `prefix?` (default `tailpocket2:`) | `TailPocketInvite2`; a v1 invite comes back as one tailcat route |
| `tailPocket.scan` | `prefix?`, `prefix2?` | the first invite text from the camera with one of the prefixes; with neither, `tailpocket1:` or `tailpocket2:` (`cancelled`, `unsupported`) |
| `tailPocket.pair` | `invite` (text with `prefix2?` (default `tailpocket2:`) or `prefix?` (default `tailpocket1:`), `TailPocketInvite` or `TailPocketInvite2`; pairs over whichever route works), `device`, `save?`, `slot?`, `phoneKey?`, `timeoutMs?`, `derpMapUrl?` | `TailPocketHostLink`; `save` stores it under `slot` (default `"default"`). With a v2 invite it first emits `tailPocket.pair.emoji` (below) and resolves once the computer's user confirms, up to a minute after `timeoutMs` |
| `tailPocket.setTailcatOnly` | `on` | ; the phone's preference: `pair`, `connect` and `sync` then use only Tailcat, never the relay or `lan` routes a computer lists. Set it before `connect`; open connections keep theirs |
| `tailPocket.connect` | `link?` or `slot?`, `derpMapUrl?` | `{handle, port, baseUrl, token}`: `baseUrl` is `http://127.0.0.1:<port>/_tailpocket/<token>` (see below) |
| `tailPocket.disconnect` | `handle` | ; a link from the store is saved again if the computer sent new routes |
| `tailPocket.sync` | `handle`, `timeoutMs?` | the updated `TailPocketHostLink`, saved to its slot: registers the phone's end-to-end key over Tailcat (links from before v0.3) |
| `tailPocket.path` | `handle`, `timeoutMs?` | `{route, relay}`: `direct`, `relay` or `lan`; since v0.3.1 also `kind` (`lan`, `direct`, `derp`, `relay`), for `derp` `derpRegion`, `derpCode`, `derpHost`, for `relay` `relayHost`; rejects `revoked` once the computer removed the phone |
| `tailPocket.setRoutes` | `routes` | ; v0.3.2: the route types the phone may use, any of `"tailcat"`, `"lan"`, `"relay"`; `null` for all. Without `"tailcat"` the phone starts no Tailcat client. Rejects `invalid-routes` for an empty, unknown or repeated route, and `invalid-arguments` for a call without `routes` or with something that is no list of strings: only an explicit `null` allows every route. It turns `setTailcatOnly` off, and `setTailcatOnly` true clears it: the last call decides |
| `tailPocket.link` | `handle` | the link with the computer's latest routes |
| `tailPocket.nearby.start` | `service` | then `tailPocket.nearby` events: `{hosts: [{name}]}` |
| `tailPocket.nearby.stop` | | |
| `tailPocket.local.begin` | `name` (from `tailPocket.nearby`) or `address`, `device?`, `label?` | `{op, code}`: show `code` |
| `tailPocket.local.finish` | `op`, `timeoutMs?` | the `TailPocketInvite`, once the computer approves; pass it to `tailPocket.pair` |
| `tailPocket.local.cancel` | `op` | |
| `tailPocket.store.phoneKey` | | the phone key from the Keychain / Keystore, created on first use |
| `tailPocket.store.saveLink` | `link`, `slot?` | |
| `tailPocket.store.link` | `slot?` | `TailPocketHostLink` or null |
| `tailPocket.store.deleteLink` | `slot?` | |

Events:

| Event | Data | When |
|---|---|---|
| `tailPocket.nearby` | `{hosts: [{name}]}` | the computers on this Wi-Fi changed, after `tailPocket.nearby.start` |
| `tailPocket.pair.emoji` | `{emoji: ["🐶", "🌙", "🍕", "🔑"]}` | during `tailPocket.pair` with a v2 invite (v0.3.0-pre.4), once the computer waits for its user to compare: show them with "Check that your computer shows the same, then confirm there". `tailPocket.pair` then resolves with the link, or rejects `unauthorized` if the user said no. A phone pairing again after a lost reply gets the link with no event. `client.ts` delivers it to `pair`'s `onEmoji` |

`TailPocketHostLink.key` is the phone's private key: keep links in the store, not in JavaScript storage.

The forward behind `baseUrl` lets through only connections that carry `token`, since any program on the
phone can reach a loopback port. JavaScript MUST build every HTTP and WebSocket URL by appending to
`baseUrl` (`` `${baseUrl}/api/info` ``; the computer sees `/api/info`); `new URL("/api/info", baseUrl)`
drops the prefix and gets 403. A request that cannot keep the prefix MUST carry the header
`Tailpocket-Token: <token>` instead, and a client of another protocol (its own TLS) MUST start the
connection with the line `TP-FWD <token>\n`. Keep `token` in memory only: never store or log it.
