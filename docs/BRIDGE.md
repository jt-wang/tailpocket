# The bridge: one function table for JavaScript in native apps

`TailPocketBridge` (Swift and Kotlin) exposes every phone-side call as `name → (args) → result`
with JSON-shaped values. NSH (`TailPocketNsh.attach`) and React Native (`TailPocketModule`)
register these names as they are; `sdk/js/client.ts` gives them types. Another JavaScript host
(a WebView, Capacitor, …) needs only a few lines to forward `call(name, args)` and one event.

Failures reject with a code: `invalid-arguments`, `invalid-invite`, `invalid-key`, `invalid-link`,
`expired`, `unreachable`, `denied`, `local-failed`, `not-paired`, `unsupported`, `cancelled`,
`unknown-function`, `unknown-operation`, `nearby-not-started`, `failed`.

| Name | Arguments | Result |
|---|---|---|
| `tailPocket.newKey` | | a new private phone key |
| `tailPocket.publicKey` | `key` | its `nodekey:…`, or null |
| `tailPocket.inviteText` | `text`, `prefix?` | the invite inside `text` (a link, a QR payload), or null |
| `tailPocket.decodeInvite` | `text`, `prefix?` | `TailPocketInvite` |
| `tailPocket.scan` | `prefix?` | the invite text from the camera (`cancelled`, `unsupported`) |
| `tailPocket.pair` | `invite` (text or `TailPocketInvite`), `device`, `save?`, `slot?`, `phoneKey?`, `timeoutMs?`, `derpMapUrl?` | `TailPocketHostLink`; `save` stores it under `slot` (default `"default"`) |
| `tailPocket.connect` | `link?` or `slot?`, `derpMapUrl?` | `{handle, port, baseUrl}` |
| `tailPocket.disconnect` | `handle` | |
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
