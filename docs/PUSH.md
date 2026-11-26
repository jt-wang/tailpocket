# Push notifications

A computer running a TailPocket host can wake a paired phone with a push notification, even when the app is closed.
The note is encrypted end to end. The computer seals it with a key only that phone holds. The push gateway
(`cmd/tailpocket-push`), APNs and FCM carry only the sealed bytes. The phone's notification extension opens it.

- Package `connectpush`: `Seal`, `Open`, and `Client` for the gateway API.
- Command `cmd/tailpocket-push`: the gateway. Its README covers config and deployment.
- `connectpush/testdata/vectors.json`: fixed vectors for the Swift and Kotlin implementations.
- Phone: `connectmobile` `Push*` functions (register, give, revoke) and, without the Go library, the openers for the
  notification extension: Swift `TailPocketPush` (product of the Swift package) and Kotlin `TailPocketPushReceiver`.
- Computer: `connecthost.Host.Push`, the helper's `push` command, Node `host.push()`.

```
phone ──register(token, generation)──▶ gateway ──▶ handle
phone ══ push key, kid, handle ══▶ computer          (over the encrypted TailPocket session)
computer ──send(handle, Seal(note))──▶ gateway ──▶ APNs / FCM ──▶ phone extension: Open(note)
```

## 1. Registering

1. The phone gets its device token from APNs (hex) or FCM (string).
2. For an app whose gateway checks attestation (§7) it gets a challenge (`POST /v1/challenge {app}`) and makes
   evidence bound to the request. It calls `POST /v1/register {app, platform, token, generation, attest?}` and gets
   `{handle, expires}`. `generation` starts at 1 and is a counter the phone keeps (see §5).
3. It makes a **push key** for each computer: 32 bytes from the system CSPRNG, with a key id `kid` of 1–64 bytes (no
   NUL; `PushNewKey` makes 16 random bytes as base64url). It stores the key where its notification code reads it (§3).
4. It sends the **push target** `{gateway, app, handle, kid, key}` (key as base64url) to that computer over the
   authenticated TailPocket session, never by any other path:
   - phones on Tailcat: `POST /v2/push {"target": {…}}` on the computer's control port, with the same peer check, body
     limit and authorization as `/v2/sync` → `200 {"ok":true}`, or 400 `{"error": "push-off" | "gateway-not-allowed" |
     "invalid"}`;
   - phones on a relay or lan route: `{"type":"push","id":n,"target":{…}}` on the Noise session's control stream →
     `{"type":"push-ack","id":n,"ok":true}` or `ok: false` with `error`;
   - `{"clear": true}` instead of `target` makes the computer forget it. A relay route in `opaque` mode carries the
     app's own encryption, not a TailPocket session, and is never used for this.

   The computer takes a target only for a gateway in its own `PushGateways` list (helper config `pushGateways`),
   and then sends to its own entry, never to the phone's spelling of it; gateway URLs are ASCII only.
   It keeps one per phone in its state, saved like the phone's keys, and deletes it when the phone is revoked or
   removed from the allowed list, when the gateway answers 410 or 403, and at start when the gateway is no longer
   configured.
5. It registers again, and sends the new handle, before `expires` (at most 30 days), whenever its token changes, and
   when a computer is removed (§5). It should make a new push key and kid at the same time. Each computer gets its own
   kid, so revoking one computer's key does not touch the others.

When a computer is removed, the phone revokes at its current generation (`/v1/revoke`), deletes that computer's push
key, registers at generation + 1, and gives the new handle to the computers that stay. A gateway that answers
`stale_generation` with `min_generation` moves the phone up to that value.

| | Go (`connectmobile`) | Swift (`TailPocket`) | Kotlin |
|---|---|---|---|
| New push key | `PushNewKey()` → `{kid, key}` | `TailPocket.pushNewKey()` | `TailPocket.pushNewKey()` |
| Challenge | `PushChallenge(gw, app, ms)` | `TailPocket.pushChallenge` | `pushChallenge` |
| Register | `PushRegister(gw, app, platform, token, gen, attest, ms)` → `{handle, expires}` | `TailPocket.pushRegister` | `pushRegister` |
| Revoke | `PushRevoke(…)` → `{}` | `TailPocket.pushRevoke` | `pushRevoke` |
| Give / clear | `PushGive(handle, targetJSON, ms)`, `PushClear(handle, ms)` | `connection.givePush`, `clearPush` | `connection.givePush`, `clearPush` |
| The whole flow | | `TailPocketPushPhone` (`register`, `give`, `revoke`, `forget`) | `TailPocketPushPhone` |
| Bridge (JavaScript) | | `tailPocket.push.register`, `.give`, `.revoke`, `.clear`, `.forget` ([BRIDGE.md](BRIDGE.md)) | same |

Error codes: `stale-generation` (with `minGeneration`), `attestation-required`, `attestation-failed`,
`attest-key-unknown` (attest a new key; `TailPocketPushPhone` does it once by itself), `rate-limited`, `push-refused`
(with the computer's `reason`), `push-unsupported` (a computer without push), `invalid-arguments`, `unreachable`,
`timeout`.

## 2. Sealed note, byte by byte

```
note      = JSON object: {"title","body","thread","url","kind": strings, omitted when empty;
                          "sent": int64 unix seconds (computer clock), "seq": uint64 ≥ 1}
json      = note as compact UTF-8 JSON (Go does not escape < > &; any valid JSON for the same values opens the same)
plaintext = uint16_be(len(json)) || json || 0x00 * (tier − 2 − len(json))
tier      = the smallest of 256, 1024, 2048 with len(json) + 2 ≤ tier; none fits → Seal fails (ErrTooLarge)
aad       = "tailpocket push 1" || 0x00 || app || 0x00 || kid
nonce     = 12 random bytes
sealed    = AES-256-GCM(key, nonce, plaintext, aad)   (ciphertext || 16-byte tag)
raw       = uint8(len(kid)) || kid || nonce || sealed
ct        = base64url(raw), no padding
```

| Offset | Length | Field |
|---|---|---|
| 0 | 1 | `k` = length of kid, 1–64 |
| 1 | k | kid (bytes, no NUL) |
| 1+k | 12 | nonce |
| 13+k | tier + 16 | AES-GCM ciphertext and tag |

The ciphertext length shows only which of the three tiers a note fits, not how long its text is. With a 64-byte kid
the largest `ct` is base64url(1 + 64 + 12 + 2048 + 16) = **2855** characters. That is under the gateway's 3000-character
limit, which leaves room in the 4096-byte APNs payload for the placeholder. With `kid` of 2 bytes, the three tiers give
383, 1418 and 2772 characters.

AES-256-GCM is used because iOS CryptoKit, `javax.crypto` on Android minSdk 26 (which has no ChaCha20-Poly1305) and the
Go standard library all have it. A nonce must never repeat under one key. Use a random nonce for each note, and make a
new key at least when the handle is renewed.

### Opening

`Open` refuses, and returns nothing of the note, unless every check passes, in this order:

1. `ct` is at most 3000 characters, only `A-Z a-z 0-9 - _`, and decodes strictly (no padding, no line breaks).
2. `k` is 1–64, kid has no NUL, and what follows the nonce is exactly a tier plus 16 bytes long.
3. There is a key for kid (`ErrUnknownKey`).
4. AES-GCM opens with the aad for **this app** and kid (`ErrAuth`). So a note sealed for another app, under another
   kid, or with any byte changed does not open.
5. Padding: the length prefix fits (`len ≤ tier − 2`) and every byte after the JSON is 0x00 (`ErrMalformed`).
6. The JSON parses. Unknown fields are ignored.
7. `sent` is no earlier than now − 24 h (`ErrExpired`) and no later than now + 5 min (`ErrFuture`).
8. `seq` is **greater** than the highest seq already accepted for kid (`ErrReplay`).

In Go: `Open(keys func(kid) ([32]byte, bool), app, ct, now, last func(kid) uint64) (Note, kid, error)`. After a
success, the caller stores the returned `Note.Seq` as the new highest for kid. Run `Open` and that store under one
lock.

`testdata/vectors.json` has seal vectors (key, kid, app, nonce, note, json, aad, padded plaintext, ct) for each tier,
and reject vectors with the error each must give. `go test ./connectpush -run TestVectors -update` rewrites the file.
Without `-update` the test fails if the code no longer gives the same bytes.

### Computer side

- Keep `seq` per kid, persisted, always increasing, starting at 1. Persist the next value **before** sending, so a
  crash cannot reuse one. A phone drops a note whose seq is not above the last it accepted, so a reused seq is lost.
- Set `sent` from the computer's clock.
- On `ErrTooLarge`, shorten the body and seal again.
- On `connectpush.ErrGone` (410), delete the handle. On 403 `expired` or `revoked`, stop using it and wait for a new
  one from the phone.

## 3. Phone requirements (hard requirements)

These rules are for the iOS Notification Service Extension (NSE) and the Android `FirebaseMessagingService`. The
gateway cannot enforce them. The gateway, Apple or Google could replay a note, and only the phone can stop that.

1. **Sequence numbers are the replay defence.** Persist, for each kid, the highest seq accepted. Accept only a larger
   one. The NSE starts as a new process for each push and keeps nothing in memory, so the value lives in **App Group
   storage** (a file or `UserDefaults(suiteName:)` in the app group container) shared by the app and the extension.
   - Write the new value durably before showing the note. If the write fails, show the placeholder, not the note.
   - Two extension processes can run at once, so do the read, check and write under a cross-process lock (for example
     `flock` on a file in the group container, or `NSFileCoordinator`).
   - On Android, store it with `SharedPreferences.commit()` (not `apply()`) or a file, under a lock.
2. **Time is a backstop, not the defence.** `sent` comes from the computer's clock and the phone's clock may be off.
   The 24-hour and 5-minute checks only bound how old a note can be. Never accept a note because of its time alone.
3. **Where the push key lives.** On iOS, in the Keychain with a shared **access group** (the app group), so the
   extension can read it, and `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`. Do **not** use `WhenUnlocked`: the
   extension runs while the phone is locked and could not read the key, so every push would show only the placeholder.
   On Android, wrap it with an Android Keystore key that does not require user authentication, in credential-encrypted
   storage (available after first unlock).
4. **On any failure, show only the placeholder**, or nothing. Never show bytes from a note that did not open.
5. Use `app` exactly as registered with the gateway as the `app` argument of Open.

The SDKs do all of this:

- **iOS**: the `TailPocketPush` library (CryptoKit, Security, Foundation; no Go framework, so it fits the extension's
  memory limit). `TailPocketPushReceiver` opens with `TailPocketPushCrypto.open`, reads keys from
  `TailPocketPushKeychain` (shared access group, `AfterFirstUnlockThisDeviceOnly`) and keeps seqs in
  `TailPocketPushSeqFile`: one JSON file in the App Group container, read, checked and written under `flock` on a
  lock file next to it, written to a temporary file with `F_FULLFSYNC`, renamed, and the directory synced, before
  the note is returned. A seq file that does not parse fails every note rather than restart from 0.
- **Android**: `TailPocketPushReceiver` with `TailPocketPushCrypto.open` (`AES/GCM/NoPadding`) and
  `TailPocketKeystorePushStore`: push keys wrapped by an Android Keystore AES key without user authentication, seqs
  saved with `commit()` under a lock. The lock is per process: keep the `FirebaseMessagingService` in the app's
  process (no `android:process`).

Notification Service Extension (target with the `TailPocketPush` library, the App Group and the Keychain group):

```swift
import TailPocketPush
import UserNotifications

final class NotificationService: UNNotificationServiceExtension {
    private let receiver = TailPocketPushReceiver(app: "io.jingtao.herdr", appGroup: "group.io.jingtao.herdr",
                                                  keychainAccessGroup: "ABCDE12345.io.jingtao.herdr.push")
    private var request: UNNotificationRequest?
    private var handler: ((UNNotificationContent) -> Void)?

    override func didReceive(_ request: UNNotificationRequest, withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        self.request = request
        handler = contentHandler
        contentHandler(receiver?.content(for: request) ?? TailPocketPushReceiver.placeholder(for: request))
    }

    override func serviceExtensionTimeWillExpire() {
        if let request, let handler { handler(TailPocketPushReceiver.placeholder(for: request)) }
    }
}
```

In the app, with the same groups:

```swift
let phone = TailPocketPushPhone(keychain: TailPocketPushKeychain(accessGroup: "ABCDE12345.io.jingtao.herdr.push"),
                                attester: TailPocketAppAttest(keychain: …, app: "io.jingtao.herdr")) // nil in strict mode
let reg = try await phone.register(gateway: "https://push.example.com", app: "io.jingtao.herdr",
                                   token: TailPocket.pushToken(deviceToken))
let kid = try await phone.give(connection, gateway: "https://push.example.com", app: "io.jingtao.herdr", registration: reg)
```

Android:

```kotlin
class PushService : FirebaseMessagingService() {
    private val receiver by lazy {
        val store = TailPocketKeystorePushStore(this) // keys and seqs
        TailPocketPushReceiver("io.jingtao.herdr", TailPocketPushPlaceholder("Herdr", "New activity"), store, store)
    }
    override fun onMessageReceived(message: RemoteMessage) {
        val shown = receiver.receive(message.data) // never throws; the placeholder on any failure
        // post a notification with shown.title and shown.body (and shown.note?.url / thread when it opened)
    }
    override fun onNewToken(token: String) { /* register again and give the new handle to each computer */ }
}
```

`TailPocketPushPhone(TailPocket.default, TailPocketKeystorePushStore(context), TailPocketPlayIntegrity.standard(context,
cloudProjectNumber))` registers, gives and revokes (pass `null` instead of the integrity source in strict mode). The
SDK compiles against `com.google.android.play:integrity` but does not ship it: an app that uses
`TailPocketPlayIntegrity` adds `implementation("com.google.android.play:integrity:1.4.0")`.

## 4. Gateway API

All endpoints take and return JSON (`Content-Type: application/json`), with a body of at most 8 KiB. Unknown fields
and trailing data are refused. Only `POST` is allowed on `/v1/*`. `GET`/`HEAD /healthz` answers `ok`. Every other path
is 404. CONNECT, absolute-URL request targets (`GET http://example.com/`) and `OPTIONS *` are 400: the gateway is
never a proxy.

### `POST /v1/challenge`

```json
{"app": "io.jingtao.herdr"}
```

→ `200 {"challenge": "…", "expires": 1792592300}`, only for an app with `attest` (else 400
`attest_not_configured`). A challenge is good for 5 minutes and one register or revoke, for this app only. The
gateway keeps nothing for it until it is used: it is MACed with a key derived from the handle key. A challenge whose
evidence does not pass is given back, so only successes fill the table of used ones.

### `POST /v1/register`

```json
{"app": "io.jingtao.herdr", "platform": "apns", "token": "<hex>", "generation": 1, "attest": null}
```

→ `200 {"handle": "…", "expires": 1792592000}`

- `app` must be in the config, and `platform` (`apns` or `fcm`) configured for it.
- APNs token: even-length hex of 16–200 bytes. FCM token: 32–1024 characters of `A-Z a-z 0-9 _ : . -`.
- `generation`: 1 to 2^53 − 1. Below the lowest valid generation for this token → `409 {"error":
  "stale_generation", "min_generation": N}`. Otherwise the lowest valid generation becomes `generation`, so every
  handle with a lower one stops working.
- `attest`: evidence, required when the app checks attestation for this platform (§7); otherwise leave it out.

### `POST /v1/revoke`

Same body as register. Every handle for this token with generation ≤ `generation` stops working (the lowest valid
generation becomes `generation + 1`). → `204`. It has the same checks and limits as register.

### `POST /v1/send`

```json
{"handle": "…", "ct": "<sealed note>", "collapse": "thread.1", "priority": "high"}
```

→ `202 {"status": "sent"}`

- The app and platform come **only** from the handle. A request cannot name them.
- `collapse` (optional): 1–64 characters of `A-Z a-z 0-9 . _ -`. It becomes `apns-collapse-id` or FCM `collapse_key`
  and is visible to Apple or Google, so use an opaque value.
- `priority` (optional): `high` (default) or `normal`. APNs priority 10 or 5, FCM `high` or `normal`.

The gateway opens the handle first. A handle that does not open gets 403, and the gateway makes no outside request.

What goes out:

- APNs, over HTTP/2: `POST https://api.push.apple.com/3/device/<token>` (or `api.sandbox.push.apple.com` for
  `env: sandbox`). Headers: `authorization: bearer <ES256 JWT>` (from the `.p8`, reused for 50 minutes), `apns-topic`,
  `apns-push-type: alert`, `apns-priority`, `apns-expiration` (now + 24 h) and optionally `apns-collapse-id`. Body:
  `{"aps":{"alert":{"title":<placeholder.title>,"body":<placeholder.body>},"mutable-content":1,"sound":"default"},"tp":<ct>}`.
- FCM: an OAuth token from `https://oauth2.googleapis.com/token`, obtained with an RS256 JWT from the service account
  and kept until a minute before it expires. Then `POST https://fcm.googleapis.com/v1/projects/<id>/messages:send`
  with `{"message":{"token":…,"data":{"tp":<ct>},"android":{"priority":…,"collapse_key":…,"ttl":"86400s"}}}`. This
  is a data-only message, and the app builds the notification after opening the note.

Those three hosts are fixed in the binary. The only thing a request adds to a URL is the device token from a handle
the gateway made itself, as hex for APNs and inside the JSON body for FCM. Redirects are not followed, no proxy is
taken from the environment, and the `token_uri` in the service account file is ignored.

## 5. Handles, byte by byte

A handle is the gateway's own sealed record. Because the gateway has no device database, a handle that opens is one it
gave out.

```
header = version (1) = 0x01 || key id (1) || len(app) (1) || app
aad    = "tailpocket push handle 1" || 0x00 || header
body   = platform (1: 1 APNs, 2 FCM) || issued (8) || expires (8) || generation (8) || source (8) || token
handle = base64url(header || nonce (12) || AES-256-GCM(handle_key[key id], nonce, body, aad)), no padding
```

Integers are big-endian, times unix seconds. The APNs token is stored as bytes and the FCM token as its string.
`source` is HMAC-SHA256(k, source address)[:8] with k = HMAC-SHA256(handle key, "tailpocket push source tag 1"),
which ties the handle to whoever registered it without storing that address.

Why the app id is in clear: `send` takes the app only from the handle, so the gateway must know which app it is before
deciding anything. Because the whole header, including the app id, the version and the key id, is the AES-GCM
associated data, changing any of those bytes makes the handle fail to open. A handle for app A presented as app B
gives 403 and no outside request. The alternative, an app-independent seal checked afterwards, would also work, but it
puts the binding in code that must remember to compare, instead of in the cipher.

A send is refused with 403 when the handle:

| Code | Why |
|---|---|
| `forbidden` | does not decode, is over 2048 characters, has another version, an unknown key id, any changed byte, or impossible times (issued more than 5 minutes ahead, or a lifetime over 30 days) |
| `not_configured` | is for an app or platform no longer in the config |
| `expired` | is past `expires` (at most 30 days, `handle_ttl_days`) |
| `revoked` | has a generation below the lowest valid one for its token (§1, §4) |

**Generations** let a phone cancel handles it gave out. When a computer is removed, the phone registers with
`generation + 1` (or calls revoke) and hands the new handle only to the computers it still trusts. The removed
computer's handle then gets 403. The gateway keeps, for each SHA-256(app || 0x00 || platform || 0x00 || token), the
lowest valid generation and when it was raised. These are kept in `state_file`, a JSON file written to a temporary
file, synced and renamed over the old one before the request is answered. An entry is dropped 31 days after its last
raise, when every handle below it has expired. The gateway refuses to start with a damaged state file, because
starting empty would bring revoked handles back. A phone that lost its counter gets 409 with `min_generation`, and
registers with that value or higher.

**Rotating the handle key**: give the new key a new `handle_key_id` and keep the old one in `old_handle_keys` until
`handle_ttl_days` have passed (see the gateway README).

## 6. Errors

All errors are `{"error": "<code>"}`. Text from Apple or Google is never passed on.

| Status | Code | Endpoint | Meaning |
|---|---|---|---|
| 400 | `proxy_request` | any | CONNECT, absolute URL or `*` as request target |
| 400 | `bad_request` | any | Not JSON, unknown field, wrong type, trailing data |
| 400 | `unknown_app` | register, revoke | App not in the config |
| 400 | `bad_token` | register, revoke | Token format wrong for the platform |
| 400 | `platform_not_configured` | register, revoke | The app has no `apns` or `fcm` |
| 400 | `bad_generation` | register, revoke | Missing, 0 or above 2^53 − 1 |
| 400 | `bad_ct` | send | Not a sealed note (§2) |
| 400 | `bad_collapse`, `bad_priority` | send | See §4 |
| 400 | `attest_not_configured` | challenge | The app does not check attestation |
| 401 | `attestation_required` | register, revoke | The app checks attestation for this platform and `attest` is missing |
| 401 | `bad_challenge` | register, revoke | The challenge is unknown, expired, used, or for another app: get a new one |
| 401 | `attestation_failed` | register, revoke | The evidence did not pass (§7) |
| 401 | `attest_key_unknown` | register, revoke | An App Attest assertion for a key the gateway never attested: attest a new key |
| 403 | `forbidden`, `not_configured`, `expired`, `revoked` | send | See §5. Nothing was sent |
| 404 | `not_found` | | Unknown path |
| 405 | `method_not_allowed` | | Wrong method |
| 409 | `stale_generation` | register | Generation below `min_generation` |
| 410 | `gone` | send | APNs: 410, or 400 `BadDeviceToken` / `Unregistered`. FCM: 404 or `UNREGISTERED`. Delete the handle |
| 413 | `too_large` | any | Body over 8 KiB, or `ct` over 3000 characters |
| 415 | `unsupported_media_type` | any | Not `application/json` |
| 429 | `rate_limited` | any | A limit in §7. `Retry-After: 60` |
| 429 | `blocked` | any | The source, or the source that registered this handle, is blocked. `Retry-After: 3600` |
| 502 | `upstream_failed` | send | APNs or FCM failed for any other reason. Retry later |
| 503 | `busy`, `state_unavailable` | | Too many pushes in flight; the state file could not be written (or is full) |
| 503 | `attestation_unavailable` | register, revoke | Play Integrity could not be reached. Retry later |

## 7. Limits and caller checks

| What | Limit |
|---|---|
| Requests per source address (IPv4 address, or IPv6 /64) | 600 per minute, all endpoints |
| Register + revoke per source address | 20 per hour |
| Register + revoke per app, all sources | `register_per_hour`, default 1000; for an app with `attest`, only requests whose evidence passed count |
| Sends per device (all handles of one app's token) | 10 per minute and 300 per day |
| Attestation-failure block | a source whose App Attest or Play Integrity evidence fails 3 times in a row is blocked for 1 hour on register and revoke; a success clears the count |
| Play Integrity decodes through Google, per app | `attest.android.decode_per_hour`, default 400 (none with local keys) |
| Bad-token block | a source with ≥ 10 of its last 20 push results and more than half of them "token not valid" is blocked for 1 hour on every endpoint, and so are handles it registered, from any address. Each result counts for the sender and for the source that registered the handle |
| Request body / `ct` | 8 KiB / 3000 characters |
| Pushes in flight | 256 |

Each limit counts in slots (10 s for minute limits, 10 min for the hour, 1 h for the day). No full window ever holds
more than the limit, though an event up to one slot older than the window may still count. Limits live in memory,
are swept every minute, and hold at most 65,536 addresses and 262,144 devices. When a table is full of live keys, new
keys are refused rather than old ones forgotten. A restart clears every limit and block.

### Attestation

Each app may set `attest: {"ios": {...}, "android": {...}}` (config in the gateway README). Then register and revoke
for that platform (`ios` for `apns` tokens, `android` for `fcm`) need `attest` evidence, and the limits above still
apply. A platform without it runs in strict mode.

The evidence is bound to the request through the **client data**, which the gateway rebuilds from the request:

```
client_data = "tailpocket push attest 1" \n op \n app \n platform \n token \n decimal(generation) \n challenge
              (op is "register" or "revoke")
hash        = SHA-256(client_data)
```

Evidence made for another operation, app, token, generation or challenge does not pass. Vector: op `register`, app
`io.jingtao.herdr`, platform `apns`, token `ab01`, generation 7, challenge `CHALLENGE` → base64url(hash) =
`sheS7aeIcwOE_y7yGLnYIxbFa7mWPSMvt3jDBZY0N4Q`.

**App Attest** (`DCAppAttestService`), evidence `{"challenge", "key_id", "attestation" | "assertion"}`, binary
fields in standard base64 as Apple returns them:

- First use of a key: `attestation = attestKey(key_id, clientDataHash: hash)`. The gateway checks the x5c chain to
  Apple's App Attest root CA (built in), that the nonce extension (1.2.840.113635.100.8.2) equals
  SHA-256(authData ‖ hash), that key_id is SHA-256 of the certified public key and equals the credential id, that
  rpIdHash is SHA-256(team_id "." bundle_id), the counter is 0 and the aaguid matches `env` (`appattest` or
  `appattestdevelop`). It then stores key_id → public key and counter in `state_file`; a key attested once cannot
  be attested again.
- Every later request: `assertion = generateAssertion(key_id, clientDataHash: hash)`. The gateway checks the ECDSA
  signature over SHA-256(authData ‖ hash) with the stored key, rpIdHash, and that the counter is **strictly greater**
  than the stored one, then stores the new counter. A key it does not know gives `attest_key_unknown`.
- Swift: `TailPocketAppAttest` keeps the key id in the Keychain group, attests a new key the first time and asserts
  after that.

**Play Integrity**, evidence `{"challenge", "token"}`. The phone asks for a token with `requestHash = base64url(hash)`
(standard request) or `nonce = base64url(hash)` (classic request, padding allowed). The gateway sends it to
`https://playintegrity.googleapis.com/v1/<package>:decodeIntegrityToken` with an OAuth token for the configured
service account, and requires: `requestDetails.requestHash` or `.nonce` equal to base64url(hash),
`requestPackageName` and `appIntegrity.packageName` equal to `package_name`, `timestampMillis` no older than 10 minutes
and no more than 1 minute ahead, `appRecognitionVerdict` `PLAY_RECOGNIZED`, every `certificateSha256Digest` in
`certificate_sha256`, and `MEETS_DEVICE_INTEGRITY` in `deviceRecognitionVerdict`. That host is added to the fixed
outbound list only for apps with `attest.android`.

The gateway decodes tokens one of two ways, chosen per app:
- **Locally (recommended)**, when `attest.android` has `decryption_key_file` and `verification_key_file`: the
  publisher's own response encryption keys (§11, Google step 7). The gateway decrypts the classic token (a compact
  JWE, `A256KW` + `A256GCM`) and checks Google's signature on the JWS inside (`ES256`); any other algorithm, a `zip`
  or `crit` header, or a standard-request token is refused. Google is never called and there is no decode budget.
  The app must make classic requests: `TailPocketPlayIntegrity.classic(context)`.
- **Through Google**, without those keys: `decodeIntegrityToken` as above. Each register or revoke that reaches this
  step costs one call, whether its token is real or not, so the gateway makes at most
  `attest.android.decode_per_hour` (default 400) a hour per app; over that it answers 503
  `attestation_unavailable` without calling Google. Kotlin: `TailPocketPlayIntegrity.standard(context,
  cloudProjectNumber)` or `.classic(context)`.

Either way, a source (IPv4 address or IPv6 /64) whose evidence fails 3 times in a row is blocked for 1 hour on
register and revoke (429 `blocked`), before it takes a challenge or reaches Google; a success clears its count. A
source's requests still being checked count with its failures, so at most 3 are checked at once and a source that
sends in parallel gets no more past the check than one that waits. Answers about the gateway rather than the evidence
(503 `attestation_unavailable` when Google is unreachable, answers 5xx, or the gateway cannot get its own access
token; `bad_challenge`; `attest_key_unknown`) count nothing.

## 8. Who sees what

| | Note text | Device token | Push key | Handle | Placeholder | Note length tier, kid, collapse, priority, times |
|---|---|---|---|---|---|---|
| Phone | yes | yes | yes | yes | yes | yes |
| Paired computer | yes (it writes it) | no | yes | yes | no | yes |
| Gateway | **no** | yes (in the handle) | **no** | yes | yes | yes |
| Apple / Google | **no** | yes | **no** | no | yes | yes |
| Removed computer, after revoke | old notes it wrote | no | its old key | old handle, now 403 | | |

The gateway also sees source IP addresses and when each request comes. Its log holds none of tokens, handles, `ct`
or addresses; it names a handle by the first 8 hex characters of SHA-256(handle). Its state file holds unkeyed
SHA-256 hashes of (app, platform, token), only for tokens whose generation was raised.

## 9. Running your own gateway

1. Build `cmd/tailpocket-push` or its Dockerfile.
2. Get an APNs `.p8` key and/or a Firebase service account for **your** apps.
3. Write a config with your app ids, placeholders and credentials, plus `handle_key_file` and `state_file`.
4. Run it behind TLS at your host name and back up the handle key.
5. Build your apps to register with your gateway's URL and to follow §3.

Details: [cmd/tailpocket-push/README.md](../cmd/tailpocket-push/README.md).

## 10. Known gaps

- In strict mode (no `attest`), anyone who knows a device token can register it or revoke its handles. Tokens are
  treated as secrets, but strict mode cannot tell the real app from someone with its token. Set `attest` for apps that
  can use App Attest and Play Integrity.
- App Attest: Apple's receipt and fraud metric are not checked, and a phone that loses its key id (reinstall)
  attests a new key; old keys stay in `state_file`. Play Integrity: only `MEETS_DEVICE_INTEGRITY` is required, not
  `MEETS_STRONG_INTEGRITY`, and apps not from Google Play (sideloaded, other stores) fail `PLAY_RECOGNIZED`.
- **Made-up Play Integrity tokens (PG4), without local keys.** The gateway cannot tell a made-up token from a real
  one without asking Google, so each one costs a decode until its source is blocked: at most 3 per source an hour,
  sent one at a time, all at once, or hanging up before the answer. About `decode_per_hour` / 3 sources (134 with the default; an IPv6 /64 is one
  source, so one /56 is enough) use up the hour, and the app's real Android phones then get 503 `attestation_unavailable` on register and revoke until the
  hour turns. With local keys (§7) this costs nothing and leaves no budget to use up: use them for any deployed
  gateway with `attest.android`.
- The attestation-failure block counts per source address, so phones behind one carrier NAT address share it:
  3 failures from anyone there block that address for everyone behind it for an hour.
- Limits and blocks are in memory and per process. A restart clears them, and several replicas each count separately.
- The gateway sees the device token, the source addresses and the timing of every push. Only the note's contents are
  hidden.

## 11. Setup for each app

These are the steps a publisher does once per app, here for `io.jingtao.herdr` with team id `ABCDE12345`; replace
both. Do them for every app the gateway serves (Herdr Anywhere, DSH Anywhere, Boop).

### Apple (developer.apple.com → Certificates, Identifiers & Profiles, and Xcode)

1. **Team ID**: Account → Membership details → Team ID (10 characters). It goes into the gateway as `apns.team_id`
   and is the prefix of the Keychain group below.
2. **App ID** of the app: Identifiers → the app's bundle id (`io.jingtao.herdr`) → tick **Push Notifications**,
   **App Groups** and **App Attest** → Save. The bundle id goes into the gateway as `apns.topic` (and is
   `ios.bundle_id` by default).
3. **App Group**: Identifiers → `+` → App Groups → `group.io.jingtao.herdr`. Then on the app's App ID, App Groups →
   Configure → select it.
4. **Notification Service Extension**: in Xcode, File → New → Target → Notification Service Extension, bundle id
   `io.jingtao.herdr.NotificationService` (Xcode registers the App ID with automatic signing; otherwise add it under
   Identifiers with App Groups ticked and the same group selected). Deployment target iOS 15 or later. Add the Swift
   package product **TailPocketPush** to this target only (the app target gets **TailPocket**). Put the code of §3 in
   `NotificationService.swift`.
5. **Capabilities in Xcode** (Signing & Capabilities, `+ Capability`):
   - app target: Push Notifications; App Groups → `group.io.jingtao.herdr`; Keychain Sharing → `io.jingtao.herdr.push`;
     App Attest (only for a gateway with `attest.ios`);
   - extension target: App Groups → the same group; Keychain Sharing → the same `io.jingtao.herdr.push`.

   Xcode writes the Keychain group as `$(AppIdentifierPrefix)io.jingtao.herdr.push`. In code pass the full group,
   `ABCDE12345.io.jingtao.herdr.push`, to `TailPocketPushKeychain(accessGroup:)` and to the receiver.
6. **App Attest environment**: the App Attest capability adds the entitlement
   `com.apple.developer.devicecheck.appattest-environment`. Set it to `production` in the app's `.entitlements` for
   builds that go to TestFlight and the App Store (Apple uses production for those in any case), and set the gateway's
   `attest.ios.env` to `production`. A debug build run from Xcode with `development` needs a gateway app with
   `env: development`; use a second gateway app id for it (for example `io.jingtao.herdr.dev` with the same `topic`,
   `apns.env: sandbox`, `attest.ios.env: development`), since debug builds also get sandbox APNs tokens.
7. **APNs key**: Keys → `+` → name it, tick **Apple Push Notifications service (APNs)** → Configure (environment
   Sandbox & Production, team scoped) → Continue → Register → **Download** `AuthKey_<KEYID>.p8`. It downloads only
   once: keep it in your secrets store. The 10-character Key ID is on the key's page. Gateway: `apns.key_id`,
   `apns.key_file`, and `apns.env` (`production` for TestFlight and App Store builds, `sandbox` for Xcode builds).
8. **In the app**: `UIApplication.shared.registerForRemoteNotifications()`, and in
   `application(_:didRegisterForRemoteNotificationsWithDeviceToken:)` pass `TailPocket.pushToken(deviceToken)` to
   `TailPocketPushPhone.register`, then `give` the handle to each computer. Ask for notification permission
   (`UNUserNotificationCenter.requestAuthorization`) as usual.

### Google (Firebase console, Google Cloud console, Play Console)

1. **Firebase project**: console.firebase.google.com → Add project (or add Firebase to an existing Google Cloud
   project). Project settings → General shows the **Project ID** (gateway `fcm.project_id`) and the **Project
   number** (for Play Integrity standard requests, `cloudProjectNumber`).
2. **Android app in Firebase**: Project settings → General → Add app → Android → package name `io.jingtao.herdr` →
   Register → download **`google-services.json`** into the app module (`app/`). Add the
   `com.google.gms.google-services` Gradle plugin and `com.google.firebase:firebase-messaging`, and declare the
   `FirebaseMessagingService` of §3 in the manifest (in the app's own process).
3. **FCM API**: Project settings → Cloud Messaging → check that **Firebase Cloud Messaging API (V1)** is enabled
   (enable it in the Cloud console if not).
4. **FCM service account**: Project settings → Service accounts → **Generate new private key** → a JSON file. This is
   `fcm.credentials_file`. Alternatively create one in the Cloud console (IAM & Admin → Service accounts → Create)
   with the role **Firebase Cloud Messaging API Admin** and add a JSON key. Keep the file secret.
5. **Play Console app integrity**: play.google.com/console → the app → **Protected with Play** (older consoles: Test
   and release → App integrity) → Play Integrity API → Get started → **Link Cloud project** → choose the Firebase
   project. Linking enables the **Google Play Integrity API** in that project; check under Cloud console → APIs &
   Services → Enabled APIs, and enable it there if it is missing.
6. **Play Integrity service account**: Cloud console of the linked project → IAM & Admin → Service accounts → Create
   (for example `play-integrity-decoder`) → Keys → Add key → JSON. Google's documentation asks only that it belong to
   the linked project and names no role; the gateway asks for the `playintegrity` OAuth scope. The FCM service
   account of step 4 also works if it is in the same project. Gateway: `attest.android.credentials_file` (defaults
   to `fcm.credentials_file`).
   **Quota**: before deploying, look up the project's Play Integrity quota (Play Console → the app → Play Integrity
   API settings, or Cloud console → APIs & Services → Google Play Integrity API → Quotas; the default is a daily
   limit per app). Set `attest.android.decode_per_hour` so that 24 × it stays below that daily limit, leaving room
   for the app's own use of the API; ask Google for a higher quota before raising it.
7. **Response encryption keys, for local decoding (recommended)**: Play Console → the app → Play Integrity API
   settings → Classic requests → Response encryption → Change → **Manage and download my response encryption keys**.
   Play Console asks for a public key of yours, gives back the keys encrypted to it, and you decrypt that file with
   your private key; Google's page developer.android.com/google/play/integrity/classic ("Decrypt and verify the
   integrity verdict locally") has the exact steps and command. The result is two base64 strings:
   - the **decryption key** (32 bytes, AES-256): one line in a file on the gateway, mode 600, for example
     `/etc/tailpocket-push/<app>-pi-decryption.key`; config `attest.android.decryption_key_file`. The gateway refuses
     to start if other users can read it. Keep it as secret as the handle key.
   - the **verification key** (a P-256 public key): one line in a file next to it, for example
     `/etc/tailpocket-push/<app>-pi-verification.key`; config `attest.android.verification_key_file`.
   Relative paths are read from the config file's directory. With these keys set, the gateway needs no Play
   Integrity service account (step 6), and the app uses `TailPocketPlayIntegrity.classic(context)`. Do not count on
   `decodeIntegrityToken` for classic tokens after the switch. Without them, skip this step, keep step 6 and the
   quota note.
8. **Signing certificate SHA-256**: Play Console → the app → Test and release → App integrity → **App signing** → "App
   signing key certificate" → SHA-256 certificate fingerprint. Put it in `attest.android.certificate_sha256` (colons
   allowed), with `attest.android.package_name` set to `io.jingtao.herdr`. Builds not installed from Google Play
   (debug builds from Android Studio) fail `PLAY_RECOGNIZED`: test them against a gateway app without `attest`, or
   through an internal testing track.
9. **In the app**: add `implementation("com.google.android.play:integrity:1.4.0")`, make
   `TailPocketPushPhone(TailPocket.default, TailPocketKeystorePushStore(context),
   TailPocketPlayIntegrity.classic(context))` with local keys (step 7), or
   `TailPocketPlayIntegrity.standard(context, <project number>)` without them), register with the token from
   `FirebaseMessaging.getInstance().token` and in `onNewToken`, and give the handle to each computer. On Android 13 and
   later ask for `POST_NOTIFICATIONS`.

### Gateway and computer

1. Add the app to the gateway config with `placeholder`, `apns` and/or `fcm`, and `attest` when you did the
   attestation steps (gateway README).
2. Give the computer's host the gateway URL in `PushGateways` (helper config `pushGateways`); a computer refuses
   targets for any other gateway.
3. Build the apps with the gateway URL they register with. The gateway's host and domain are not decided yet, and
   nothing here is deployed.
4. **Before going live with `attest.android`, check a made-up token against the real Play Integrity.** The limits in
   §7 and §10 count a made-up token as a failed attestation only because Google answers `decodeIntegrityToken` with
   400 for it; nobody has run that against Google yet. With the deployed gateway and its real config, get a challenge
   (`POST /v1/challenge {app}`) and send `POST /v1/register` with any FCM-shaped token and
   `"attest": {"challenge": "<it>", "token": "made-up"}`. Expect **401 `attestation_failed`**. A 503
   `attestation_unavailable` means a made-up token is not counted against its source: do not turn `attest.android`
   on through Google; use local keys (Google step 7) or report it. With local keys the same request must also give
   401 (decoded on the gateway, no call to Google). Repeat with a real token from a Play-installed build: expect 200.
