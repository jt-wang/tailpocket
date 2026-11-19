# Push notifications

A computer running a TailPocket host can wake a paired phone with a push notification, even when the app is closed.
The note is encrypted end to end. The computer seals it with a key only that phone holds. The push gateway
(`cmd/tailpocket-push`), APNs and FCM carry only the sealed bytes. The phone's notification extension opens it.

- Package `connectpush`: `Seal`, `Open`, and `Client` for the gateway API.
- Command `cmd/tailpocket-push`: the gateway. Its README covers config and deployment.
- `connectpush/testdata/vectors.json`: fixed vectors for the Swift and Kotlin implementations.

```
phone ──register(token, generation)──▶ gateway ──▶ handle
phone ══ push key, kid, handle ══▶ computer          (over the encrypted TailPocket session)
computer ──send(handle, Seal(note))──▶ gateway ──▶ APNs / FCM ──▶ phone extension: Open(note)
```

## 1. Registering

1. The phone gets its device token from APNs (hex) or FCM (string).
2. It calls `POST /v1/register {app, platform, token, generation}` and gets `{handle, expires}`. `generation` starts at
   1 and is a counter the phone keeps (see §5).
3. It makes a **push key**: 32 bytes from the system CSPRNG, with a key id `kid` of 1–64 bytes (no NUL; random
   base64url is a good choice). It stores both (see §6).
4. It sends `{gateway URL, app, handle, kid, push key}` to each paired computer over the encrypted TailPocket session,
   never by any other path.
5. It registers again, and sends the new handle, before `expires` (at most 30 days), whenever its token changes, and
   when a computer is removed (§5). It should make a new push key and kid at the same time. Each computer gets its own
   kid, so revoking one computer's key does not touch the others.

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

## 4. Gateway API

All endpoints take and return JSON (`Content-Type: application/json`), with a body of at most 8 KiB. Unknown fields
and trailing data are refused. Only `POST` is allowed on `/v1/*`. `GET`/`HEAD /healthz` answers `ok`. Every other path
is 404. CONNECT, absolute-URL request targets (`GET http://example.com/`) and `OPTIONS *` are 400: the gateway is
never a proxy.

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
- `attest`: evidence for an attestation verifier, when the app has one (§7).

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
| 401 | `attestation_failed` | register, revoke | The app's verifier refused the evidence |
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

## 7. Limits and caller checks

| What | Limit |
|---|---|
| Requests per source address (IPv4 address, or IPv6 /64) | 600 per minute, all endpoints |
| Register + revoke per source address | 20 per hour |
| Register + revoke per app, all sources | `register_per_hour`, default 1000 |
| Sends per device (all handles of one app's token) | 10 per minute and 300 per day |
| Bad-token block | a source with ≥ 10 of its last 20 push results and more than half of them "token not valid" is blocked for 1 hour on every endpoint, and so are handles it registered, from any address. Each result counts for the sender and for the source that registered the handle |
| Request body / `ct` | 8 KiB / 3000 characters |
| Pushes in flight | 256 |

Each limit counts in slots (10 s for minute limits, 10 min for the hour, 1 h for the day). No full window ever holds
more than the limit, though an event up to one slot older than the window may still count. Limits live in memory,
are swept every minute, and hold at most 65,536 addresses and 262,144 devices. When a table is full of live keys, new
keys are refused rather than old ones forgotten. A restart clears every limit and block.

**Attestation.** Each app may set `attest: {"ios": {...}, "android": {...}}`, which hands register and revoke to an
`attester` (`cmd/tailpocket-push/attest.go`) for App Attest or Play Integrity. Evidence must be bound to op, app,
token and generation. No verifier is built in yet, and setting `attest` stops the gateway at start. Without it the
app runs in the strict mode above.

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

- Anyone who knows a device token can register it or revoke its handles. Tokens are treated as secrets, but strict
  mode cannot tell the real app from someone with its token. Attestation closes this and is not built yet.
- Limits and blocks are in memory and per process. A restart clears them, and several replicas each count separately.
- The gateway sees the device token, the source addresses and the timing of every push. Only the note's contents are
  hidden.
