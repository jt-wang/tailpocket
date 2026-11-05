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

## Commands (you → helper)

| Command | Fields | Effect |
|---|---|---|
| `pair` | `id`, `ttl` (seconds), `payload`, `qrPrefix` | open a pairing window |
| `local` | `id` (of an open window), `service`, `label`, `instance` | also offer it over Bonjour |
| `confirm` | `id`, `approve` | answer a `localCode` |
| `cancel` | `id` | close a window |
| `setAllowed` | `id`, `allowed` | replace the allowlist |
| `revoke` | `id`, `phone` | remove one phone |
| `saved` | `id` (of a `save`), `ok` | you stored the state (or failed to) |

## Events (helper → you)

| Event | Fields | Meaning |
|---|---|---|
| `ready` | `address` | started |
| `save` | `id`, `state` (`{identity, allowed}`) | store this, then send `saved`; the change waits for it |
| `pairing` | `id`, `qr`, `invite`, `expiresAt` | show `qr` as a QR code |
| `paired` | `id`, `phone`, `device`, `address` | a phone joined |
| `pairingClosed` | `id`, `reason` (`paired`, `expired`, `stopped`) | the window ended |
| `localCode` | `id`, `code`, `device` | show the code; ask the user; send `confirm` |
| `localCancelled` | `id` | the phone left before the user decided |
| `localDelivered` | `id` | the invite went to the approved phone |
| `allowed` | `id`, `allowed`, `address` | `setAllowed` or `revoke` took effect |
| `error` | `code`, `id` (when it answers a command) | see below |

Error codes. At start: `invalid-config`, `unsupported-version`, `invalid-forward`,
`invalid-identity`, `invalid-allowed`, `start-failed` (these end the process). For a command:
`invalid-command`, `unknown-command`, `duplicate-id`, `unknown-pairing`, `pair-failed`,
`invalid-qr-prefix`, `local-unavailable`, `local-not-approved`, `local-failed`,
`nothing-to-confirm`, `invalid-allowed`, `operation-failed`.

`state.identity` contains private keys. Store it like a password; a lost identity means every phone
pairs again.

Close stdin (or end the process) to stop; the helper closes both nodes.
