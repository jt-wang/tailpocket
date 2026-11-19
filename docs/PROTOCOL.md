# Protocol

v1 (below, first) is Tailcat only and unchanged in v0.3. v2 adds end-to-end encrypted routes over
tailpocket-relay and lan, and is in [the second half](#v2-routes-v03). A v0.3 host speaks both: a
phone paired over v1 keeps working without pairing again.

# Pairing protocol (v1)

Two Tailcat nodes run on the computer:

| Node | Virtual port | Admits |
|---|---|---|
| main | 48931 (`Config.Port`) | only the phone keys in the allowlist (`State.Allowed`) |
| pairing | 48932 (`Config.PairingPort`) | only the one-time key of one open window |

The main node never starts with an empty allowlist: Tailcat admits every client when its allowlist
is empty, so the host starts it after the first phone pairs. Tailcat has no call to remove a client.
`Revoke` removes one phone while the node keeps running: the host closes that phone's open
connections and closes each new one it opens, before the app sees it, so other phones stay
connected. `SetAllowed` restarts the main node with the new list, which drops every phone's
connections. The node key is part of `State.Identity`, so the address stays the same across
restarts.

## Invite

```json
{"v":1,"address":"<tailcat address of the pairing node>","port":48932,
 "key":"privkey:<one-time client key>","proof":"<43 chars>","expiresAt":1793000000,"name":"Studio Mac"}
```

- `key` is a private key the phone uses only to reach the pairing node; that node admits nothing else.
- `proof` is 32 random bytes, base64url without padding (43 characters).
- `expiresAt` is unix seconds; windows last 2 minutes by default, at most 15.
- QR and link form: `tailpocket1:` followed by base64url (no padding) of the zlib-compressed JSON, at most
  4096 characters. Apps may choose another prefix (2 to 32 printable ASCII characters, no spaces,
  one `:` at the end); both sides must use the same one.

Anyone holding an unexpired invite can pair once, so treat it as a secret: show it on screen, do
not log it.

## Pairing request

The phone connects to the pairing node with the invite's `key` and sends, over HTTP inside the tunnel:

```
POST /pair
Authorization: Bearer <proof>
Content-Type: application/json

{"phoneKey":"nodekey:<the phone's long-term public key>","device":"Pixel 9"}
```

Reply `200`:

```json
{"v":1,"address":"<tailcat address of the main node>","port":48931,"name":"Studio Mac","payload":"<your data>"}
```

`phoneKey` is a claim: the pairing node admits the invite's one-time key, so nothing on this
connection proves the phone holds the nodekey it names. That is v1's design, and the host takes no
Noise key with it (fields a pre.2 phone adds are ignored). A v0.3 phone that pairs over Tailcat
registers its Noise key right after, with key sync on the main node, where WireGuard proves the
nodekey (below). One consequence stays from v1: an invite holder can pair over Tailcat naming
another phone's nodekey, and that nodekey, paired without a Noise key, can then not pair over relay
or lan; its owner pairs over Tailcat and syncs, which works, since sync needs the nodekey's private
key. The invite holder gets no session as that phone on any route.

Errors: `401` wrong proof, `409` the window already belongs to another phone key, `410` expired,
`400` malformed body or key, `413` body over the limit, `503` the host could not save state or
produce the payload. The same phone retrying gets the same reply, so a lost response is safe to retry.

Before replying, the host saves the new allowlist (`Config.Save`) and adds the key to the main
node. A failed save refuses the pairing.

## Connecting

The phone keeps `{address, port, name, payload, key}` (`TailPocketHostLink`; `key` is its private key, so
store it like a password) and connects to the main node with its own key. Every accepted
connection is forwarded to the app's port. On the computer, `connecthost.PhoneOf(conn)` tells which phone
it is: the client's tunnel IP is `fd7a:115c:a1e0::/48` followed by the first 80 bits of its node
key, so the host maps it back to the key. The helper's `identifyPhone` option writes
`nodekey:…\n` as the first line of each forwarded connection instead.

## Same-Wi-Fi delivery

The host advertises `<instance>.<service>.local` (for example `_myapp._tcp`, TXT `v=1`) on a TCP
port bound to its private IPv4 LAN addresses, and accepts only peers on the same subnet. One phone
at a time:

1. phone → host: `{"v":1,"publicKey":"<base64 X25519>","device":"Pixel 9"}`
2. host → phone: `{"v":1,"publicKey":"<base64 X25519>"}`
3. Both sides compute:

   ```
   shared = X25519(own private, peer public)
   code   = "%06d" of uint64_be(SHA256(label ‖ phonePub ‖ hostPub ‖ shared)[0:8]) mod 1_000_000
   key    = HKDF-SHA256(ikm = shared, salt = phonePub ‖ hostPub, info = label ‖ " invitation", 32 bytes)
   ```

   The phone shows `code`; the computer shows it too and asks its user to approve.
4. host → phone: `{"v":1,"status":"approved","sealed":"<base64 nonce(12) ‖ ChaCha20-Poly1305(key, invite JSON) ‖ tag>"}`,
   or `{"v":1,"status":"denied","reason":"…"}`.

Messages are one JSON object per line. The default label is `tailpocket-local-pairing-v1`;
a phone and a host interoperate only with the same label. The phone then pairs with the decrypted
invite as above.

The code is what stops a neighbour on the same Wi-Fi from receiving the invite: they would need the
user to approve a code their phone did not show.

# v2: routes (v0.3)

A v2 host is reachable over up to three kinds of route. Tailcat stays as in v1, with its own
WireGuard and allowlist and nothing on top. The others carry a Noise session end to end between
phone and host, so a relay sees only ciphertext.

| Route | `t` | Fields | Encryption |
|---|---|---|---|
| Tailcat | `tailcat` | `a` (one address), `p` (port); in an invite only `inv` (a v1 invite object) | Tailcat (WireGuard) |
| tailpocket-relay | `relay` | `u` (`wss://…`; `ws://` only to loopback), `r` (room), `m` | Noise, or with `m: "opaque"` the app's own |
| direct TCP | `lan` | `a` (`host:port` addresses) | Noise |

Phones skip route types they do not know. A phone tries the route that worked last first, then the
others in the host's order; each route gets at most 10 s (each lan address 3 s) while others are left.

## Keys

The host's identity (`State.Identity`, JSON `{v:1,key,psk,region,noise,relay}`) gains two keys in
v0.3: `noise`, an X25519 private key phones pin, and `relay`, an Ed25519 seed that names the host's
room on relays. An identity from before v0.3 gets both on the first start and is saved before any
phone can learn them; the Tailcat key and address stay the same.

The phone's Noise key is derived from its Tailcat key, so a link needs no second secret and a link
from before v0.3 already has one:

```
noise private = SHA-256("tailpocket2 noise key\n" || Tailcat private key, 32 raw bytes)
noise public  = X25519(noise private, basepoint)
```

`State.Keys` maps each phone (`nodekey:…`) to its Noise public key (base64url, no padding).

## v2 invite

```
tailpocket2:<base64url, no padding, of the zlib-compressed JSON>
{"v":2,"name":"Studio Mac","exp":1793000000,
 "pk":"<host Noise public key>","psk":"<one-time code, 16 random bytes, base64url>",
 "via":[{"t":"tailcat","inv":{<v1 invite>}},{"t":"relay","u":"wss://relay.example.com","r":"<room>"},
        {"t":"lan","a":["192.168.1.20:7681"]}]}
```

Every route redeems the same window: the phone that joins first, over any route, owns it. A v1 QR
read as v2 (`DecodeV2`) is one `tailcat` route. Treat the invite as a secret, as in v1.

## Noise session

- The phone dials and sends a 4-byte preamble `TP2P` (pair) or `TP2C` (connect).
- Pair: `Noise_IKpsk2_25519_ChaChaPoly_SHA256`; connect: `Noise_IK_25519_ChaChaPoly_SHA256`; prologue
  `tailpocket2`; `github.com/flynn/noise` v1.1.0. The phone knows the host key from `pk`. Protocol
  version 2 (v0.3.0-pre.2). Version 1 was pre.1's AES-GCM: the suites differ, so a pre.1 phone's
  first handshake message does not decrypt at a pre.2 host (and the reverse), the host closes the
  connection, and the phone reports handshake-closed and tries its other routes, Tailcat among them.
  No `bye` is sent in that case; `bye proto-mismatch` is for a peer that speaks this suite with
  another `proto`.
- psk = `SHA-256("tailpocket2 psk" || code)`; cid = `base64url(SHA-256("tailpocket2 cid" || code)[:12])`.
- Handshake messages and records carry a 2-byte big-endian length. The first message's payload is
  `{"proto":2,"cid":"…"}` (pair) or `{"proto":2}`; nothing else, since it has no forward secrecy.
- After the handshake the phone sends `{"type":"hello","proto":2,"version":"…","phone":"nodekey:…"}`.
  Pairing adds `"device"` and `"proof"`: base64url of HMAC-SHA256 keyed with X25519(the nodekey's
  private key, the host's Noise key) over `"tailpocket2 pair"`, a zero byte and the handshake hash
  (`connectsecure.KeyProof`). The host computes the same with its Noise private key and the named
  nodekey, and turns a pairing without it away with `bye denied`: over relay and lan, holding an
  invite does not let anyone pair under another phone's nodekey (Tailcat pairing: see "Pairing
  request"). The host decides only then; turning a phone away, it sends one `bye` and
  nothing else. Admitted, it sends its own `hello`, and when pairing `{"type":"paired","phone","name","payload"}`.
- Limits: 5 s for the preamble and first message, 10 s to the decision, 16 handshakes at once per
  route (each relay and each lan address has its own) and 4 per source address on a lan route, 4
  sessions per phone (a fifth closes the oldest with `bye busy`).
- Records: `[stream u32][type u8][len u16][payload]`, types `open`, `data`, `close`, `window`,
  `rekey` (4, stream 0, empty); stream 0 is the control stream, phone streams are odd; 256 KiB
  window per stream, and 16 MiB received and not yet read by the app per session (more ends it).
- Rekey (Noise spec 11.3, flynn/noise `CipherState.Rekey`): each side rekeys its sending key after
  2^20 records or 10 minutes under one key, whichever comes first. It sends `rekey` as the last
  record under the old key, then changes key; the receiver changes key only after that record
  decrypted. The two directions rekey independently, so both sides rekeying at once needs nothing
  more. A receiver that gets more than 2^22 records under one key ends the session. ChaCha20-Poly1305
  with a 64-bit counter has no data limit a session can reach; rekeying bounds what one leaked
  session key opens to the records since the last rekey. A stream reads
  `io.EOF` only after a `close`; a broken pipe is `ErrConnLost`.
- Control stream: one JSON object per line, 4 KiB per line, 64 KiB unread. `hello`, `paired`,
  `{"type":"routes","via":[…]}` (sent once a session starts; the phone stores it), `ping`/`pong`
  (30 s; 60 s of silence closes), and `{"type":"bye","code":…}` with `unpaired`, `denied`, `busy`,
  `stopping`, `proto-mismatch`.

Each stream is one connection to the app, as on Tailcat: `connecthost.PhoneOf` names the phone.

**Only `bye unpaired` unpairs.** Close codes and HTTP refusals on a relay connection are not
encrypted; anyone on the path can send one, so the phone reports them as unreachable and tries the
next route. Phone libraries map: `bye unpaired` → revoked (delete the link), `bye denied` → refused,
`bye proto-mismatch` → mismatch, `bye busy` → unreachable, closed right after the first handshake
message → handshake-closed (the host is down or pins another key), anything else → unreachable.

## The local network: what the lan route protects against

TailPocket has no unencrypted listener on the local network. `Config.Listen` serves only the Noise
session above; same-Wi-Fi invite delivery (v1, above) seals the invite with the code the user
compares. A phone dials a `lan` route only through Noise, pinned to the host key from the invite
(or from key sync over Tailcat), and an invite or `routes` message that marks a `lan` route opaque
is rejected.

Someone on the same network, who can read, change, drop and send any packet, and who knows the
host's public key and the room (they are not secret):

| They try to | Result |
|---|---|
| read what the phone and the app say, or the app's token, the pairing code, the phone's name or key | only ciphertext: ChaCha20-Poly1305 records after a Noise IK handshake; the code goes in only as a psk, the name and key only inside the encrypted hello |
| change, reorder or replay records | the session ends (`ErrBadRecord`): each record is authenticated with its sequence number |
| connect as a phone that is not paired, or with a revoked key | turned away with `bye unpaired` before any stream reaches the app |
| pose as the computer at the address the phone dials | the handshake fails without the host's private key: the phone reports handshake-closed and sends the app nothing |
| replay a recorded pairing or connection | nothing: a pairing code is redeemed once and its window closes; a replayed handshake has no keys for the new ephemeral exchange |
| unpair the phone with a forged close or reset | the phone reports unreachable and keeps its link; only the encrypted `bye unpaired` unpairs |

It does not protect against:

- Denial of service: dropping or resetting the connection, flooding the port, holding handshake
  slots (16 per route, 4 per source address on lan, each for at most 10 s). Slots are per route, so
  strangers filling a relay's do not touch the lan route's; the phone tries its other routes.
- Traffic analysis: that a phone talks to this computer, when, and how many bytes.
- A stolen pairing code used before its window closes (it is a secret; show it, do not log it),
  or a stolen phone key or host identity.
- A compromised phone or computer.

The first handshake message has no forward secrecy, so it carries only the protocol version and the
window's cid; everything else waits for the encrypted hello.

## Opaque relay routes

`m: "opaque"` relays carry the phone's bytes to the app's port as they are, without Noise, for apps
that already terminate their own pinned TLS end to end. The host cannot tell which
phone a connection is from (`PhoneOf` is `""`), so the app authenticates it; Authorize and the
audit's phone field do not apply. Phones do not pair over opaque routes.

## Phones paired before v0.3: key sync

The main Tailcat node also serves virtual port 48933, for paired phones only:

```
POST /v2/sync
{}                                                     → 200 {"v":2,"pk":"<host Noise key>","via":[…]}
{"noise":"<the phone's Noise public key>","proof":"…"} → 200 the same, and the key is recorded

proof = base64url(HMAC-SHA256(X25519(the phone's Noise private key, pk),
                              "tailpocket2 noise" || 0x00 || "nodekey:…" || "\n" || noise))
```

The Tailcat connection proves the phone holds its nodekey and that `pk` comes from the host; the
proof shows it holds the Noise key it reports. A phone without `pk` (paired before v0.3) asks with
`{}` first. The host records (and saves, before it answers) the key; a missing or wrong proof gets
`403` and nothing is saved, so no phone can claim another's key. A phone that is not paired, or that
Authorize turns away, gets its connection closed. After one sync an old link carries `pk` and `via`
and uses every route; there is no new QR. A host before v0.3 does not serve the port, and the phone
keeps using Tailcat.

A v0.3 phone that pairs over Tailcat from a v2 invite syncs right after pairing; if that fails it
keeps a Tailcat-only link and syncs on a later connection.

An app that served phones over its own unencrypted local port before v0.3 closes that port when
every phone that used it has a key in `State.Keys`, or 3 days after the upgrade, whichever comes
first; until then it tells each phone without a key to open the new app version soon. During
those 3 days:

- A phone whose link has `pk` MUST NOT use the unencrypted port again, also when every encrypted
  route fails: someone on the network who blocks those must not be able to push it down to plain
  HTTP. The phone libraries have no unencrypted route to fall back to (they skip route types they
  do not know); an app that kept its own plain address for the computer MUST stop using it once the
  link has `pk`.
- The host app MUST refuse, on the unencrypted port, the credentials of every phone that has a
  key (or a Tailcat key at all), and serve there only phones that cannot get one.
- It MUST close the port as soon as no phone that needs it is left, not only after 3 days. A phone with
a Tailcat link that syncs late still reaches the host over Tailcat and gets every route on its first
sync. A phone paired on v0.3 never uses an unencrypted port.

## tailpocket-relay


1. Host: `GET /v1/host?room=R` with `Authorization: Bearer <relay token>`. `R` =
   `base64url(SHA-256(relay public key)[:16])`. The relay sends `{"type":"challenge","nonce"}`; the
   host answers `{"type":"register","pub","host","sig"}`, signing
   `"tailpocket-relay host v1\n" + host + "\n" + room + "\n" + nonce`, where host is the relay URL's
   host name, lower-cased, without port or trailing dot. The relay checks it against its required
   `--public-host` and answers `{"type":"ready"}`, or closes with 4403 (bad signature, room or host),
   4409 (room held), or HTTP 401 (token). The host stops retrying on those; otherwise it registers
   again with backoff from 1 s to 30 s.
2. Phone: `GET /v1/phone?room=R`, no token (4404 when no host holds the room).
3. The relay sends `{"type":"incoming","id"}`; the host opens `GET /v1/accept?room=R&id=…` with
   its token within 10 s (else 4408), and the relay copies binary messages both ways. Either side
   ending closes the other with 1001 `peer-gone`; close codes are never forwarded.
4. Limits: 100 rooms, 16 phones per room, 4 per source address, 30 `/v1/phone` per address per
   minute, 64 KiB per message, 4096 TCP connections (64 per address). The relay refuses to start
   without a token unless `--open`.

## Revoking

`connecthost.Revoke(phone)` saves the allowlist without the phone first, then sends each of its
encrypted sessions `bye unpaired`, then closes its Tailcat connections; new connections are refused
before the app sees them. An app that tells phones itself (a WebSocket close code inside its own
protocol) does that before calling `Revoke`. `Disconnect(phone)` closes a phone's connections
without unpairing it, for an app whose own sign-in for that phone ran out.

## Authorization and audit hooks

`Config.Authorize(phone, route)` runs for every connection from a known phone, on Tailcat
(including port 48933) and on the encrypted routes, before the app sees it; an error closes it (an
encrypted session gets `bye denied`). `Config.Audit` receives `paired`, `revoked`, `conn-open`,
`conn-close` and `denied` events with phone, route and reason, never keys, codes or payloads.
A pairing is checked in `PairOptions.Payload(phone)`, which sees the
route the phone pairs over; an error refuses it. Key sync on port 48933 is `Authorize(phone,
"tailcat")`. TailPocket implements no sign-in itself: an app adds OIDC or SAML behind these hooks, checks
per-operation permissions in its own server, and calls `Disconnect` when a sign-in expires.
