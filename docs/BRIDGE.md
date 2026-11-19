# The bridge: one function table for JavaScript in native apps

`TailPocketBridge` (Swift and Kotlin) exposes every phone-side call as `name → (args) → result`
with JSON-shaped values. NSH (`TailPocketNsh.attach`) and React Native (`TailPocketModule`)
register these names as they are; `sdk/js/client.ts` gives them types. Another JavaScript host
(a WebView, Capacitor, …) needs only a few lines to forward `call(name, args)` and one event.

Failures reject with a code: `invalid-arguments`, `invalid-invite`, `invalid-key`, `invalid-link`,
`expired`, `unreachable`, `revoked` (the computer removed this phone: delete its link), `mismatch`,
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
| `tailPocket.pair` | `invite` (text, `TailPocketInvite` or `TailPocketInvite2`; pairs over whichever route works), `device`, `save?`, `slot?`, `phoneKey?`, `timeoutMs?`, `derpMapUrl?` | `TailPocketHostLink`; `save` stores it under `slot` (default `"default"`) |
| `tailPocket.connect` | `link?` or `slot?`, `derpMapUrl?` | `{handle, port, baseUrl}` |
| `tailPocket.disconnect` | `handle` | ; a link from the store is saved again if the computer sent new routes |
| `tailPocket.sync` | `handle`, `timeoutMs?` | the updated `TailPocketHostLink`, saved to its slot: registers the phone's end-to-end key over Tailcat (links from before v0.3) |
| `tailPocket.path` | `handle`, `timeoutMs?` | `{route, relay}`: `direct`, `relay` or `lan`; rejects `revoked` once the computer removed the phone |
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

`TailPocketHostLink.key` is the phone's private key: keep links in the store, not in JavaScript storage.
