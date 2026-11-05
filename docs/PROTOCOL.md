# Pairing protocol (v1)

Two Tailcat nodes run on the computer:

| Node | Virtual port | Admits |
|---|---|---|
| main | 48931 (`Config.Port`) | only the phone keys in the allowlist (`State.Allowed`) |
| pairing | 48932 (`Config.PairingPort`) | only the one-time key of one open window |

The main node never starts with an empty allowlist: Tailcat admits every client when its allowlist
is empty, so the host starts it after the first phone pairs. Tailcat has no call to remove a client,
so `SetAllowed` and `Revoke` restart the main node with the new list. The node key is part of
`State.Identity`, so the address stays the same across restarts.

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
