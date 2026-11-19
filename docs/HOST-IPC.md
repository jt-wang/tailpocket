# tailpocket-host: the computer side for any language

`tailpocket-host` is a single static binary (`scripts/build-host.sh` builds macOS, Linux and
Windows). Your app spawns it and exchanges one JSON object per line over stdin and stdout. The Node
package (`sdk/node`) is a thin wrapper around it and a working reference.

Keep reading its stdout for as long as it runs: every state change waits for your `saved`
answer (10 s), and an unread pipe stalls pairing.

## Start

The first line you write is the configuration:

```json
{"v":1,"name":"Studio Mac","identity":"<from a previous save, or empty>","allowed":["nodekey:…"],
 "forward":"127.0.0.1:3000","port":0,"pairingPort":0,"derpMapUrl":"","identifyPhone":false}
```

`forward` is `host:port` or `unix:/path`. Zero ports mean the defaults (48931, 48932). Then the
helper writes `{"event":"ready","address":"…"}`; `address` is `""` until the first phone pairs.

v0.3 adds optional fields (the config stays `"v":1`; leave them out and nothing changes):

```json
{"keys":{"nodekey:…":"<Noise key>"},
 "relays":[{"url":"wss://relay.example.com","token":"<relay token>","opaque":false}],
 "listen":["192.168.1.20:7681"],"authorize":true,"audit":true}
```

- `keys`: `state.keys` from the last `save`. Without it, phones paired over the encrypted routes have
  to sync their key again over Tailcat.
- `relays`: tailpocket-relay servers to register with (`wss://`; `ws://` only to loopback). The token
  goes over stdin, never on a command line. `opaque: true` passes the phone's bytes to `forward`
  without TailPocket's encryption, for apps that run their own pinned TLS; those connections carry no
  phone key (`identifyPhone` writes an empty line).
- `listen`: addresses the host accepts encrypted connections on directly (route `lan`). Give
  addresses phones can dial; `0.0.0.0` and `::` are refused.
- `authorize`: every connection from a known phone waits for your `authorized` answer (5 s, then
  denied).
- `audit`: `audit` events for pairings, revokes, sessions and refusals.

## Commands (you → helper)

| Command | Fields | Effect |
|---|---|---|
| `pair` | `id`, `ttl` (seconds), `payload`, `qrPrefix` | open a pairing window |
| `local` | `id` (of an open window), `service`, `label`, `instance` | also offer it over Bonjour |
| `confirm` | `id`, `approve` | answer a `localCode` |
| `cancel` | `id` | close a window |
| `setAllowed` | `id`, `allowed` | replace the allowlist |
| `revoke` | `id`, `phone` | remove one phone; its encrypted sessions get bye `unpaired` |
| `disconnect` | `id`, `phone` | close one phone's connections, keep it paired (its sign-in ran out) |
| `status` | `id` | report address, routes and relays |
| `saved` | `id` (of a `save`), `ok` | you stored the state (or failed to) |
| `authorized` | `id` (of an `authorize`), `ok` | allow or deny that connection |

## Events (helper → you)

| Event | Fields | Meaning |
|---|---|---|
| `ready` | `address` | started |
| `save` | `id`, `state` (`{identity, allowed, keys}`) | store this, then send `saved`; the change waits for it |
| `pairing` | `id`, `qr`, `invite`, `qr2`, `invite2`, `expiresAt` | show `qr2` as a QR code to v0.3 phones, `qr` to older ones |
| `paired` | `id`, `phone`, `device`, `address` | a phone joined |
| `pairingClosed` | `id`, `reason` (`paired`, `expired`, `stopped`) | the window ended |
| `localCode` | `id`, `code`, `device` | show the code; ask the user; send `confirm` |
| `localCancelled` | `id` | the phone left before the user decided |
| `localDelivered` | `id` | the invite went to the approved phone |
| `allowed` | `id`, `allowed`, `address` | `setAllowed` or `revoke` took effect |
| `authorize` | `id`, `phone`, `route` (`tailcat`, `relay`, `lan`) | answer with `authorized` |
| `audit` | `kind` (`paired`, `revoked`, `conn-open`, `conn-close`, `denied`), `phone`, `route`, `reason`, `time` (ms) | log it |
| `disconnected` | `id`, `phone` | `disconnect` took effect |
| `status` | `id`, `address`, `routes`, `relays` (`{url: "up" or why not}`) | answers `status` |
| `error` | `code`, `id` (when it answers a command) | see below |

Error codes. At start: `invalid-config`, `unsupported-version`, `invalid-forward`,
`invalid-identity`, `invalid-allowed`, `start-failed` (these end the process); a bad `relays` or
`listen` entry is `invalid-config`. For a command:
`invalid-command`, `unknown-command`, `duplicate-id`, `unknown-pairing`, `pair-failed`,
`invalid-qr-prefix`, `local-unavailable`, `local-not-approved`, `local-failed`,
`nothing-to-confirm`, `invalid-allowed`, `operation-failed`.

`state.identity` contains private keys. Store it like a password; a lost identity means every phone
pairs again. `pairing.qr2` and `invite2` hold the window's secrets like `qr`: show them, do not log
them.

Close stdin (or end the process) to stop; the helper closes both nodes.
