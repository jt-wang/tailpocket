# tailpocket-push

A push gateway for apps built on TailPocket. A computer that wants to wake a phone sends the gateway a note it has
already encrypted for that phone, and the gateway passes it to Apple Push Notification service (APNs) or Firebase
Cloud Messaging (FCM) with the app publisher's credentials. The phone's notification extension decrypts the note and
shows it.

One gateway serves any number of apps from one config file. It holds no database of devices and cannot read notes.
It sends only to devices that registered with it. Anyone who publishes an app can run their own gateway with their own
Apple and Firebase credentials. There is no shared default instance.

The wire format, the encryption and the phone-side rules are in [docs/PUSH.md](../../docs/PUSH.md).

## Who sees what

| Party | Sees | Cannot see |
|---|---|---|
| Gateway | App id, platform, device token (inside the handle it opens), the sealed note's length tier and key id, `collapse`, `priority`, source IP addresses, times | Title, body, thread, URL or kind of any note |
| Apple / Google | Device token, the app's fixed placeholder text, the sealed note, `collapse`, `priority`, times | Note contents |
| Computer | Its handles (opaque), the notes it seals | The device token, unless the phone tells it |
| Anyone on the network | TLS metadata only (with TLS in front) | Everything else |

What the phone's lock screen shows before the extension runs, and if it fails, is the placeholder from the config,
such as "Herdr: New activity". No field of a request can change the visible text.

The log has one line per event (`register`, `revoke`, `send … result=sent|gone|failed`, `refused`, `source-blocked`).
It names a handle only by the first 8 hex characters of its SHA-256 and never writes device tokens, handles, sealed
notes, IP addresses or text from Apple or Google. Refusals are logged at most 10 lines per minute per code.

## Run it

**1. Build** (Go 1.27.1 or later, from the repository root):

```sh
go build -o tailpocket-push ./cmd/tailpocket-push
```

**2. Get credentials** for each app:

- APNs: in the Apple Developer site, *Keys*, create a key with *Apple Push Notifications service* and download the
  `.p8` file. Note the 10-character key id and your team id. The topic is the app's bundle id.
- FCM: in the Firebase console, *Project settings → Service accounts → Generate new private key*. That JSON file is
  `credentials_file`. Its `token_uri` is ignored: the gateway always uses `https://oauth2.googleapis.com/token`.

`chmod 600` every credential file. The gateway warns at start when one is readable by other users.

**3. Write the config**, for example `/etc/tailpocket-push/push.json`:

```json
{
  "listen": "127.0.0.1:8443",
  "handle_key_file": "handle.key",
  "state_file": "state.json",
  "trust_proxy": ["127.0.0.1/32"],
  "apps": [
    {
      "id": "io.jingtao.herdr",
      "placeholder": {"title": "Herdr", "body": "New activity"},
      "apns": {"team_id": "ABCDE12345", "key_id": "KEY1234567", "key_file": "herdr-apns.p8",
               "topic": "io.jingtao.herdr", "env": "production"},
      "fcm": {"project_id": "herdr-prod", "credentials_file": "herdr-fcm.json"}
    },
    {
      "id": "io.jingtao.boop",
      "placeholder": {"title": "Boop", "body": "Something happened"},
      "apns": {"team_id": "ABCDE12345", "key_id": "KEY1234567", "key_file": "herdr-apns.p8",
               "topic": "io.jingtao.boop"}
    }
  ]
}
```

Relative file names are taken from the config file's directory.

**4. Start it** behind a TLS reverse proxy:

```sh
./tailpocket-push --config /etc/tailpocket-push/push.json
curl http://127.0.0.1:8443/healthz    # ok
```

On first start it creates `handle_key_file` (32 random bytes, mode 0600) and `state_file`. **Back up the handle key.**
Without it every handle already given out stops working, and every phone has to register again.

**5. Put TLS in front.** Either set `tls_cert` and `tls_key` in the config and listen on a public address (the files
are reloaded when they change), or use a proxy such as Caddy:

```
push.example.com {
    reverse_proxy 127.0.0.1:8443
}
```

With a proxy on the same machine, set `trust_proxy` to the proxy's own address so the per-address limits count the
client from `X-Forwarded-For`. Without it that header is ignored. Never trust `0.0.0.0/0`.

**6. Point the apps at it.** The phone app registers its device token and gets a handle. It gives the handle and its
push key to the computer over the encrypted TailPocket session. The computer uses `connectpush.Client` with
`URL: "https://push.example.com"`.

### In a container

```sh
docker build -f cmd/tailpocket-push/Dockerfile -t tailpocket-push .
docker run --rm --network host --user "$(id -u):$(id -g)" \
  -v /etc/tailpocket-push:/data \
  tailpocket-push --config /data/push.json --listen 127.0.0.1:8443
```

The image holds only the static binary (distroless) and runs as a non-root user. `/data` must be writable by that
user, because the gateway writes the handle key and the state file there. `--listen` on the command line overrides
`listen` in the config. The image's default is `0.0.0.0:8443`, so publish the port only where you mean to (for
example `-p 127.0.0.1:8443:8443`). With a published port the gateway sees the proxy as the Docker bridge gateway, so
trust that address instead of `127.0.0.1`.

## Config

| Field | Default | Meaning |
|---|---|---|
| `listen` | `127.0.0.1:8443` | Address to listen on |
| `tls_cert`, `tls_key` | | Serve HTTPS directly. Without them it serves plain HTTP and says so at start |
| `handle_key_file` | required | 32-byte key that seals handles. Created (0600) when missing |
| `handle_key_id` | `1` | 1–255: the number new handles carry. Change it to rotate keys |
| `old_handle_keys` | `[]` | `[{"id": 1, "file": "handle-1.key"}]`: retired keys whose handles still open |
| `handle_ttl_days` | `30` | How long a handle works, 1–30 days |
| `state_file` | required | JSON file with revoked generations. Created when missing; a damaged one stops the start |
| `trust_proxy` | `[]` | CIDRs of reverse proxies whose `X-Forwarded-For` is believed |
| `apps[].id` | required | App id the phone and computer use, 1–255 of `A-Z a-z 0-9 . _ -` |
| `apps[].placeholder` | required | `title` (≤128 bytes) and `body` (≤256 bytes): the only visible text of a push |
| `apps[].apns` | | `team_id`, `key_id`, `key_file` (.p8), `topic` (bundle id), `env` (`production` or `sandbox`, default `production`) |
| `apps[].fcm` | | `project_id`, `credentials_file` (service account JSON) |
| `apps[].register_per_hour` | `1000` | Registrations and revokes per hour for this app, from all sources together |
| `apps[].attest` | | `{"ios": {...}, "android": {...}}`: device attestation. **This build has no verifier, so setting it stops the start** (see below) |

Each app needs `apns`, `fcm` or both. Unknown fields are an error.

### Rotating the handle key

1. Create a new key file, for example `head -c 32 /dev/urandom > handle-2.key && chmod 600 handle-2.key`.
2. Set `"handle_key_file": "handle-2.key", "handle_key_id": 2` and move the old one into
   `"old_handle_keys": [{"id": 1, "file": "handle.key"}]`. Restart.
3. Phones re-register on their normal schedule, at least every 30 days, because handles expire. After
   `handle_ttl_days`, remove the old key.

### Attestation (not built in)

Without `attest`, an app runs in **strict mode**. The gateway checks token formats, limits registrations per address
and per app, and blocks sources whose tokens Apple or Google reject. App Attest (iOS) and Play Integrity (Android)
need the publisher's own setup and online calls to Apple and Google. The hook for them is the `attester` interface in
`attest.go`, which documents what a verifier must check. No verifier ships, and the gateway refuses to start with
`attest` set rather than run unchecked.

## Limits

| What | Limit | Answer |
|---|---|---|
| All API requests per source address (IPv4, or IPv6 /64) | 600 per minute | 429 `rate_limited` |
| `register` + `revoke` per source address | 20 per hour | 429 `rate_limited` |
| `register` + `revoke` per app | `register_per_hour` | 429 `rate_limited` |
| Sends per device (every handle of one token of one app) | 10 per minute, 300 per day | 429 `rate_limited` |
| A source whose last 20 push results hold at least 10, more than half of them rejected tokens | blocked 1 hour, every endpoint, and the handles it registered | 429 `blocked` |
| Request body | 8 KiB | 413 `too_large` |
| Sealed note | 3000 characters | 413 `too_large` |
| Pushes in flight | 256 | 503 `busy` |

All limits are kept in memory, swept every minute, and start empty after a restart.

## Running it for your own apps

Nothing in the gateway is tied to TailPocket's apps. Put your app ids, placeholders and credentials in the config and
deploy it at your own host name. Your apps then register with your gateway, and nobody else's credentials are
involved. To allow only your apps, list only your apps: a request for an app id that is not configured is refused
before anything else.
