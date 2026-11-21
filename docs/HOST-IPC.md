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

v0.3 adds optional fields (the config stays `"v":1`; leave them out and nothing changes, except that
since v0.3.0-pre.4 the `lan` route is on by default, see `listen`):

```json
{"keys":{"nodekey:…":"<Noise key>"},
 "relays":[{"url":"wss://relay.example.com","token":"<relay token>","opaque":false,"appAuth":false}],
 "listen":["192.168.1.20:7681"],"noLan":false,"tailcatOnly":false,"routes":["tailcat","lan","relay"],
 "authorize":true,"audit":true}
```

- `keys`: `state.keys` from the last `save`. Without it, phones paired over the encrypted routes have
  to sync their key again over Tailcat.
- `relays`: tailpocket-relay servers to register with (`wss://`; `ws://` only to loopback). The token
  goes over stdin, never on a command line. `opaque: true` passes the phone's bytes to `forward`
  without TailPocket's encryption, for apps that run their own pinned TLS; those connections carry no
  phone key (`identifyPhone` writes an empty line) and `authorize` does not run for them.
- `appAuth` (v0.3.0-pre.4, per relay): required with `opaque: true`; see below. An opaque relay
  without it is `invalid-config` and the helper exits.
- `listen`: addresses the host accepts encrypted connections on directly (route `lan`). Give
  addresses phones can dial; `0.0.0.0` and `::` are refused. Since v0.3.0-pre.4 the `lan` route is on
  by default: with no `listen`, the host listens on every private address of the computer's Wi-Fi and
  Ethernet, follows them as they change, and uses a port derived from its key.
- `noLan` (v0.3.0-pre.4): no `lan` route at all: no listener, and invites and `status` routes list
  none. Together with `listen` it is `invalid-config`.
- `tailcatOnly` (v0.3.0-pre.4): the host as before v0.3: Tailcat only. It opens no local network
  listener, registers with no relay, and v2 invites and `status` routes list only Tailcat. Together with `relays` or
  `listen` it is `invalid-config`.
- `routes` (v0.3.2): exactly the routes to run, a non-empty list of `"tailcat"`, `"lan"`, `"relay"`.
  Leave it out for the behaviour above. Without `"tailcat"` the helper starts no Tailcat node and
  contacts no Tailcat or DERP server: `ready` and `status` have `address` `""`, only `emoji` windows
  exist (a `pair` without `emoji` fails with `emoji-required`), and `invite2` lists only `lan` and
  `relay`. `"relay"` needs `relays`, `relays` needs `"relay"`, `listen` needs `"lan"`, `derpMapUrl`
  needs `"tailcat"`, and `routes` does not go with `tailcatOnly` or `noLan`; each of these is
  `invalid-config` with a `message` saying which. Examples: LAN only `{"routes":["lan"]}`; your own
  relay only `{"routes":["relay"],"relays":[{"url":"wss://relay.example.com","token":"…"}]}`.
- `authorize`: every connection from a known phone waits for your `authorized` answer (5 s, then
  denied).
- `audit`: `audit` events for pairings, revokes, sessions and refusals.

### Opaque relays: your app MUST authenticate every connection

An opaque relay hands your `forward` port raw bytes from anyone who knows the relay room: TailPocket
checks no phone key on them, and `authorize` and `identifyPhone` see none. An app that configures an
opaque relay MUST therefore authenticate every connection itself before acting on it, for example
the way DSH does: TLS to a certificate key the phone pinned at pairing, plus a per-device bearer token
(delivered in the pairing `payload`) checked on every connection and revocable on its own. It MUST
then set `"appAuth": true` on that relay to declare that it does. Without `appAuth` the helper refuses
to start (`invalid-config`). `appAuth` is a promise you make, not something the helper can check: do
not set it to get past the error.

## Commands (you → helper)

| Command | Fields | Effect |
|---|---|---|
| `pair` | `id`, `ttl` (seconds), `payload`, `qrPrefix`, `qrPrefix2`, `emoji` | open a pairing window (see Pairing below) |
| `local` | `id` (of an open window), `service`, `label`, `instance` | also offer it over Bonjour |
| `confirm` | `id` (of the window), `approve` | answer that window's `localCode` or `pairRequest` |
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
| `pairing` | `id`, `expiresAt`, and `qr`, `invite` (v1 window) or `qr2`, `invite2` (`emoji` window) | show the QR text as a QR code or link |
| `pairRequest` | `id`, `phone`, `device`, `route` (`tailcat`, `relay`, `lan`), `emoji` (four, or null) | `emoji` windows: ask the user; send `confirm` |
| `pairRequestCancelled` | `id` | the phone left, the window closed, or 55 s passed before your `confirm`; the code is spent |
| `paired` | `id`, `phone`, `device`, `address` | a phone joined |
| `pairingClosed` | `id`, `reason` (`paired`, `expired`, `stopped`) | the window ended (a refused `pairRequest` ends it as `expired`) |
| `localCode` | `id`, `code`, `device` | show the code; ask the user; send `confirm` |
| `localCancelled` | `id` | the phone left before the user decided |
| `localDelivered` | `id` | the invite went to the approved phone |
| `allowed` | `id`, `allowed`, `address` | `setAllowed` or `revoke` took effect |
| `authorize` | `id`, `phone`, `route` (`tailcat`, `relay`, `lan`) | answer with `authorized` |
| `audit` | `kind` (`paired`, `revoked`, `conn-open`, `conn-close`, `denied`), `phone`, `route`, `reason`, `time` (ms) | log it |
| `disconnected` | `id`, `phone` | `disconnect` took effect |
| `status` | `id`, `address`, `routes`, `relays` (`{url: "up" or why not}`) | answers `status` |
| `error` | `code`, `id` (when it answers a command) | see below |

## Pairing

`pair` opens one of two kinds of window:

- Without `emoji` (as before v0.3.0-pre.4): a v1 window. `pairing` has `qr` and `invite` (prefix
  `qrPrefix`, default `tailpocket1:`), and no `qr2`. Any phone holding the code joins over Tailcat.
- With `"emoji": true`: a v2 window for v0.3 phones. `pairing` has `qr2` and `invite2` (prefix
  `qrPrefix2`, default `tailpocket2:`), every route the host has, and no v1 `qr` or `invite`. Every
  phone that pairs, over any route, first comes as a `pairRequest` with the four `emoji` its screen
  shows. Show them with `device` and ask the computer's user whether the phone shows the same; answer
  with `{"cmd":"confirm","id":…,"approve":true|false}` within 55 s. `true` lets the phone pair
  (`save`, then `paired`). `false`, no answer in time, or a phone that goes away (`pairRequestCancelled`)
  spends the code: the window closes with `pairingClosed` `expired`; open a new one to try again, and
  the phone reports `unauthorized`. A phone that pairs through `local` gets a v1 invite from Bonjour
  and comes as a `pairRequest` with `emoji: null`: it shows no emoji, so the user can only go by the
  name (the six-digit `localCode` before it already matched the phone). A phone pairing again after a
  lost reply is not asked twice.

`confirm` answers whatever the window waits for: a `localCode` (the Bonjour code check, `local`) or
a `pairRequest` (the emoji check, `emoji` windows). An `emoji` window that also serves `local` can
wait for both at once; `confirm` then answers the one that started waiting first. Each request waits
from the moment its event goes out, so a `confirm` sent right after it counts; with nothing waiting,
`confirm` fails with `nothing-to-confirm`.

Error codes. At start: `invalid-config`, `unsupported-version`, `invalid-forward`,
`invalid-identity`, `invalid-allowed`, `start-failed` (these end the process); a bad `relays` or
`listen` entry, an opaque relay without `appAuth`, `tailcatOnly` with `relays` or `listen`, `noLan`
with `listen`, and a contradictory `routes` are `invalid-config` (route errors add `message`). For a command:
`invalid-command`, `unknown-command`, `duplicate-id`, `unknown-pairing`, `pair-failed`,
`invalid-qr-prefix`, `emoji-required` (a v1 window on a host without Tailcat), `no-route` (a host
without Tailcat has no route up yet: no lan address, relay not registered), `local-unavailable`, `local-not-approved`, `local-too-many-attempts` (the
window answered `MaxAttempts` = 3 phones without an approval and closed: ask the user to start
again), `local-failed`,
`nothing-to-confirm`, `invalid-allowed`, `operation-failed`.

`state.identity` contains private keys. Store it like a password; a lost identity means every phone
pairs again. `pairing.qr2` and `invite2` hold the window's secrets like `qr`: show them, do not log
them.

Close stdin (or end the process) to stop; the helper closes both nodes.
