# tailpocket-relay

Your phone is on mobile data, your computer is at home behind a router, and neither can open a port to the other.
tailpocket-relay is a small program you run on a machine you own that both can reach, such as a cheap VPS. The phone and
the computer each dial out to it, and it copies bytes between them.

The relay never holds a key that can read your session. Phone and computer encrypt end to end before anything reaches the relay: with TailPocket's Noise layer, or, in
opaque mode, with the app's own TLS, so the relay only passes ciphertext along. Nobody runs a relay for you: there is no
default address anywhere in TailPocket, and you decide where yours lives.

What the relay can see, and what it cannot:

| The relay sees | The relay cannot see |
|---|---|
| IP addresses of the phone and the computer | What you type, what the terminal shows, file contents |
| When each connection opens and closes | Which commands or agents you run |
| How many bytes go each way | Your pairing code or device token |
| The size and time of each message, so roughly when you type | the computer's Noise key |
| The room: a hash of the computer's relay key | |

Its log has one line per event (`host-up`, `host-down`, `phone-in`, `phone-paired`, `phone-out`, `refused`) with the
time, the first 6 characters of the room, the close code and the byte count. It does not log IP addresses, tokens,
full rooms or content.

## Run it

You need a machine with a public address and, for phones on the internet, a TLS certificate for its name. The examples
use `relay.example.com`.

**1. Build** (Go 1.27.1 or later, from the repository root):

```sh
go build -o tailpocket-relay ./cmd/tailpocket-relay
```

**2. Make a token.** Only someone with this token can register a computer on your relay. Phones do not need it.
The relay refuses tokens shorter than 16 bytes and warns when the file is readable by other users.

```sh
openssl rand -base64 32 > relay.token && chmod 600 relay.token
```

**3. Start it** behind a TLS reverse proxy (step 4). `--public-host` is the name phones and the computer connect to:

```sh
./tailpocket-relay --token-file relay.token --public-host relay.example.com   # listens on 127.0.0.1:8080
curl http://127.0.0.1:8080/healthz                                       # ok
```

the computer signs its registration for that name, so a relay that got the signature cannot pass it on to yours. The
relay never takes its name from a request, so the proxy needs nothing extra for this. The name is compared without its
port: two relays under one name on different ports accept each other's signatures.

**4. Put TLS in front.** Phones connect with `wss://relay.example.com`. Either let the relay do TLS itself with
`--tls-cert cert.pem --tls-key key.pem` and a public `--listen` address, or use a reverse proxy. The proxy must pass WebSocket
upgrades and keep idle connections open for more than 60 seconds; the relay pings every 30 seconds.

Caddy (proxies WebSockets and sets `X-Forwarded-For` without extra settings):

```
relay.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

nginx (closes a proxied connection after 60 seconds without data unless `proxy_read_timeout` is raised):

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 120s;
    proxy_send_timeout 120s;
}
```

With a proxy on the same machine, add `--trust-proxy 127.0.0.1/32` so the per-address limits count the phone's
address from `X-Forwarded-For` instead of the proxy's. Without `--trust-proxy` the relay ignores that header. Give
only the proxy's own address: `--trust-proxy 0.0.0.0/0` would let any client claim any address.

The relay reloads `--tls-cert` and `--tls-key` when the files change, so a renewed certificate needs no restart.

**5. Connect the computer** with the relay's `wss://` URL and the token (`connecthost.Config.Relays`, or `relays` in the
Node SDK and the helper). Phones learn the relay from the pairing QR code, and paired phones from the computer; a phone
paired before v0.3 learns it after one key sync over Tailcat (`Session.Sync`, `Sync` on mobile), with no new QR code.

### In a container

Build from the repository root:

```sh
docker build -f cmd/tailpocket-relay/Dockerfile -t tailpocket-relay .
docker run --rm --network host --user "$(id -u):$(id -g)" \
  -v "$PWD/relay.token:/run/secrets/relay.token:ro" \
  tailpocket-relay --token-file /run/secrets/relay.token \
  --public-host relay.example.com --listen 127.0.0.1:8080 --trust-proxy 127.0.0.1/32
```

The image has only the static binary (distroless) and runs as a non-root user.

- `--user "$(id -u):$(id -g)"` lets the relay read your `chmod 600` token file. Without it the container's own user
  cannot read the file and the relay exits with `permission denied`.
- `--network host` with `--listen 127.0.0.1:8080` puts the relay where a proxy on the same machine expects it, and the
  relay sees the proxy as `127.0.0.1`, so `--trust-proxy 127.0.0.1/32` is right.
- With a published port instead (`-p 127.0.0.1:8080:8080`, and no `--listen`), the relay sees the proxy as the
  Docker bridge gateway, not `127.0.0.1`. Trust that address instead:
  `--trust-proxy "$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')/32"`.

## Options

| Option | Default | What it does |
|---|---|---|
| `--listen ADDR` | `127.0.0.1:8080` | Address to listen on |
| `--token-file PATH` | | File with the token, one line. Or set `TAILPOCKET_RELAY_TOKEN` |
| `--open` | off | Anyone can register a room without a token, so anyone can also fill all `--max-rooms` rooms and lock your computer out. The relay refuses to start with no token unless this is set |
| `--tls-cert`, `--tls-key` | | Serve `wss://` directly. Without them it serves plain `ws://` and says so at start |
| `--max-rooms N` | 100 | Most computers registered at once |
| `--max-phones-per-room N` | 16 | Most phone connections per computer |
| `--phone-rate N` | 30 | Phone connections per source address in any 60 seconds |
| `--trust-proxy CIDR` | | Believe `X-Forwarded-For` from this proxy. Repeatable |
| `--public-host NAME` | required | The host name phones and the computer connect to, such as `relay.example.com`; a port is allowed and ignored. Registrations signed for another name get 4403 |
| `--max-conns N` | 4096 | Most TCP connections at once, counted from accept to close. The relay warns at start if `--max-rooms` would need more, or if the process may open fewer files than this plus 64 |
| `--version` | | Print the version |

Fixed limits: one source address may hold at most 64 TCP connections at once (a `--trust-proxy` address has no such
limit, since it stands for many users), at most 4 of a room's phone connections, and make at most 30 the computer
registrations in any 60 seconds. A connection over a connection limit is closed before anything is read. A source address is an IPv4 address, or an IPv6 /64. A single WebSocket message may
be at most 1 MiB; a bigger one closes that connection before any of it is passed on. Idle HTTP connections close
after 60 seconds. Refusals are logged at most 10 lines per minute for each code, then one line with how many more
there were.

## How it works

All endpoints are WebSocket except `/healthz`.

1. The computer opens `GET /v1/host?room=R` with `Authorization: Bearer <token>`. `R` is
   `base64url(SHA-256(pub)[:16])` of an Ed25519 key the computer keeps only for the relay. The relay sends a random
   nonce; the computer answers with its public key, the relay's host name and a signature over
   `"tailpocket-relay host v1\n" + host + "\n" + R + "\n" + nonce`. So only the holder of that key can take room `R`, the
   room stays the same across restarts, and another relay cannot pass a signature it got on to this one. The host name
   is lower case, without port or trailing dot.
2. A phone opens `GET /v1/phone?room=R`, with no token.
3. The relay tells the computer `{"type":"incoming","id":…}` on its registration connection.
4. The computer opens `GET /v1/accept?room=R&id=…` with the token within 10 seconds, and the relay copies binary
   messages between the two connections until one side closes.

When the computer's registration connection drops, its room is free at once and its phones are closed. When the computer
comes back with the same key while the relay still holds its old connection (a laptop that changed networks), the
relay pings the old one and gives the room to the new one if there is no answer within 3 seconds.

Close codes and HTTP answers:

| Code | Meaning |
|---|---|
| 400 | The room or id in the URL is not 22 base64url characters |
| 401 | Registration or accept without the right token |
| 404 | Accept for a phone that is not waiting (wrong id, or it gave up) |
| 429 | Too many requests from this source address in the last 60 seconds |
| 503 | The relay has `--max-rooms` rooms, or the room has `--max-phones-per-room` phones or 4 from this address |
| 1001 | The other end went away (reason `peer-gone`), or the computer's accept failed |
| 1008 | the computer did not send its registration within 10 seconds |
| 1009 | A message was larger than 1 MiB |
| 1011 | The relay could not tell the computer about the phone |
| 4403 | The room does not come from the key, the signature is wrong, or it was signed for another host name (logged as `wrong-host`) |
| 4404 | No computer is registered in this room (also sent when it leaves) |
| 4408 | the computer did not accept the phone within 10 seconds |
| 4409 | This room already has a live computer |

The relay never passes a close code from one end to the other: whatever one end sends, the other gets 1001
`peer-gone`. Close codes on relay connections are not encrypted, so neither end treats one as "unpaired" or anything
else about the device; that only comes over the encrypted connection.
