# Security: what TailPocket guarantees, and the evidence

TailPocket's rule is **fail closed**: at worst a phone cannot connect. It must never let anyone
impersonate a phone or a computer, read or change what they send, use a TailPocket channel for
anything else, or take over a machine. Every claim below names the code and the tests that check
it; `go test -race ./...` runs them, and `TAILPOCKET_LIVE=1` adds the ones on the real Tailcat
network. The wire formats are in [PROTOCOL.md](PROTOCOL.md).

Audits this covers: the third-round cryptography audit of 83d4174 (H1, D1, L1, P1–P3, I1–I4), the
fail-closed audit of 83d4174 (O1, F1, T1, G1, G2, M1, F2, K1, N1, R1, A1) the pre.4 review
(H1 retries, branch `audit-v03-pre4` 64f7145) and the pre.5 review (L2, branch `audit-v03-pre5` db527de). Their failing tests
(branches `audit-v03-crypto` 2be300d and `audit-v03-failclosed` fb4b23e) are in this tree and pass.

## 1. The relay is not a proxy, an amplifier or an SSRF hop

`tailpocket-relay` dials nothing. It accepts WebSockets and passes each message, whole, to the one
connection paired with it in a room.

- No outbound code: a scan of the relay's sources finds no dialer, resolver, HTTP client, TLS or
  WebSocket dial or exec (`TestFailClosedRelaySourceNeverDialsOut`, with
  `TestFailClosedOutboundScanFindsDials` proving the scan finds them). Rooms, ids, URLs, the
  register message's fields and `X-Forwarded-For` naming a victim reach it 0 times
  (`TestFailClosedRequestFieldsAreNeverDialled`), and so do 17 proxy-shaped requests
  (`TestFailClosedNotAProxy`, `TestFailClosedRunningRelayIsNotAProxy`). CONNECT, absolute-form
  targets and `OPTIONS *` get 400.
- No amplification: before authentication every answer is at most 256 bytes and at most 8 times
  the request (`TestFailClosedNoAmplificationBeforeAuth`); a phone without a host is closed at once
  (`TestFailClosedPhoneWithoutHostClosesAtOnce`); a message goes once, to its pair only
  (`TestFailClosedForwardOnceToThePairOnly`).
- Rooms stay apart: a host only gets its own phones (`TestFailClosedAcceptOnlyItsOwnPhone`,
  `TestToken`, `TestOneHostPerRoom`, `TestReplayedRegister`, `TestWrongHost`).
- R1: the relay always needs a token (`--open` is gone, `TestOpenFlagRemoved`); `/v1/accept` is
  rate limited before the token is checked and answers 401 alike for every wrong token
  (`TestFailClosedAcceptRateAndTokenFirst`); request heads are capped at 8 KiB
  (`TestFailClosedRunningRelayHeaderLimits`). The README's message limit now says 64 KiB.
- L1: rate limits count IPv4 addresses and IPv6 /64s; a full table forgets its oldest entry instead
  of refusing newcomers, and one /48 holds at most 4096 entries, so it can only push out its own
  (`TestAuditOneSlash48LocksEveryoneOutOfPhoneRate`, `TestRateLimitOne48CannotEvictOthers`,
  `TestRateLimitFullTableForgetsOldest`).
- Found during this review: a peer that sent half of a large frame held its relay connection, and
  `Server.Close`, forever (the WebSocket library drains the frame without a deadline). The relay now
  closes such a connection's TCP within 5 s (`TestFailClosedBadFramesInAPair`).

The relay is trusted for nothing but availability: everything on it is Noise ciphertext (section 5).

## 2. The computer's helper and control port run nothing for anyone

- `tailpocket-host` talks only over stdin and stdout. Its sources import no `os/exec`, plugin or
  reverse proxy, open no listener and touch no file (`TestFailClosedHelperSourceRunsNothingListensNowhere`).
  The only connection it makes is to the app's own `forward` address.
- Its commands are exactly the reviewed ones; a new one fails `TestFailClosedIPCCommandsAreTheReviewedOnes`
  until it is reviewed. None runs a program or takes a path. 24 kinds of malformed input change
  nothing (`TestFailClosedMalformedIPC`); a line over 1 MiB ends the helper with an error event
  (`TestFailClosedOverlongIPCLineIsReported`).
- The Tailcat node serves two ports: the app's port and the control port. The control port answers
  only `POST /v2/sync` from a paired phone, with a 4 KiB body and an 8 KiB header limit; a revoked
  phone's connections close (`TestFailClosedControlPortOnlySync`,
  `TestFailClosedControlPortOnlyPairedPhones`, `TestFailClosedControlPortRevoked`,
  `TestAuthorizeCoversSync`, `TestSyncCannotTakeAnotherPhonesKey`).

## 3. The local network listener gives a stranger nothing

- It listens on private addresses only (RFC 1918, CGNAT, ULA, link-local), refuses connections from
  public sources (`TestLANRefusesPublicSources`), and speaks nothing but a Noise IKpsk2 handshake: a
  connection that does not complete one as a paired phone, or as a phone pairing in an open window
  with a valid invite, is closed before the app sees a byte. Handshake slots are limited per route and
  per source address.
- `noLan` turns it off; Tailcat-only mode (section 6) opens no listener at all
  (`TestTailcatOnlyListensNowhere`).
- M1: the built-in mDNS responder answers only queries from the receiving interface's own subnet
  (`TestAuditBuiltinResponderAnswersOffLinkUnicast`, `TestOnLinkOnly`; 1.79 million fuzzed packets in
  `FuzzAuditMDNSPackets` found nothing). An instance name cannot start with `-`
  (`TestInstanceIsNeverAnOption`).
- F2: a phone dials only literal private addresses from a lan route; loopback, public addresses and
  host names are refused when an invite or link is read (`TestAuditLanRouteAcceptsAnyAddress`).

## 4. Every parse or handshake error disconnects, with no fallback to weaker security

- Noise handshakes and records: any bad byte ends the session (`FuzzAuditHostFirstBytes`,
  `FuzzAuditFrames`, the connectsecure tests). A refusal names its reason in a bye; only an encrypted
  `unpaired` makes a phone delete its pairing, never a relay close code.
- K1: a computer that lost a phone's key but still allows the phone answers `busy`, not `unpaired`
  (`TestAuditLostKeysUnpairAPairedPhone`); only a removed phone hears `unpaired`.
- Same-Wi-Fi pairing v2 refuses v1 and every malformed or extra field without showing a code
  (`TestHostRejectsV1HelloAndMalformedHellos`, `TestHostDropsBadReveals`, `TestPhoneRejectsV1Host`).
- Invites: `FuzzAuditDecodeInvite`. N1: device names lose control, bidi and line-separator
  characters (`TestAuditDeviceNameKeepsFormatCharacters`).
- A1: refusals reach the app's audit hook at most 20 times a minute per reason, and the next one
  says how many were left out (`TestDeniedAuditEventsAreLimited`).

## 5. Pairing cannot be taken over, and a channel is only its owner's

- **Emoji on every route (D1).** A v2 pairing shows four emoji on both screens, taken from the
  Noise handshake hash (`HKDF(h, "tailpocket2 sas")`, 24 bits), on relay, lan and Tailcat (the
  Tailcat pairing port runs the same Noise pairing). The user confirms on the computer; a no, a
  timeout or the phone hanging up ends the window, so its invite pairs nobody after
  (`TestPairingSASMatchesBothSides`, `TestTailcatPairingShowsEmojiAndWaits`,
  `TestEmojiRefusedOrAbandonedEndsWindow`, `TestPhoneWithoutEmojiIsRefused`, `TestV2NeedsConfirm`,
  `TestV2InviteClosesV1Pair`). The phone shows them only after the computer says the request is
  pending (`TestNoEmojiWithoutPending`).
- **Same-Wi-Fi pairing (H1).** v1 let a neighbour make both 6-digit codes equal in about a second.
  v2 is commit-then-reveal: the phone commits to its key and a nonce before it sees the computer's,
  so a machine in the middle cannot pick its key after seeing the other side's
  (`TestAuditLocalPairingMITMMatchesCodes`, which fails if the commitment check is removed). It can
  still throw an attempt away: each key the computer hands out lets it compute the code the
  computer would show, without revealing anything. So a window hands its key to at most
  `MaxAttempts` = 3 commitments, to one source address at most once every 2 s, and closes after 3
  that were not approved (`local-too-many-attempts`; the user starts again). The phone starts one
  attempt per user action, so it gives the attacker one fixed code. The chance that a window pairs
  the attacker is therefore

  P ≤ MaxAttempts × 10^-6 = 3 × 10^-6 per window the user opens

  (the mod-10^6 bias adds under 10^-13), against 16% in a 2-minute window and 75% in a 15-minute one
  at pre.4's measured 1557 keys/s. The worst an attacker gets beyond that is a closed window.
  Tests: `TestAuditLocalPairingSilentRetries` (at most 2 keys in 3 s now),
  `TestWindowEndsAfterMaxAttempts`, `TestOneAnswerPerSourceGap`; each fails with its limit removed.
  The 3 attempts belong to the pairing window, not to one call: `ServeLocal` runs once per window and,
  when they run out, ends the window, QR code included (`TestAuditServeLocalAgainGivesNewAttempts`,
  `TestTooManyLocalAttemptsEndsTheWindow`).
  The 6-digit code stays behind the commitment; it is never turned into emoji.
- **Opaque relays (O1).** They skip the Noise layer for apps that encrypt end to end themselves, so
  the host refuses one unless the app sets `appAuth` (it authenticates every connection itself).
  Authorize runs with phone "" for each opaque connection, the identity line says `opaque`, and
  revoking or disconnecting any phone closes all open ones (`TestAuditOpaqueRelaySkipsAuthorize`,
  `TestAuditRevokedPhoneKeepsOpaqueRoute`, `TestAuditHelperForwardsStrangerOnOpaqueRelay`).
- **The phone's local forward (F1).** Any program on a phone can reach a 127.0.0.1 port. The forward
  now carries an HTTP request only under `/_tailpocket/<token>` or with the `Tailpocket-Token`
  header, and a raw connection only after the line `TP-FWD <token>`; the token is 256 random bits
  per `connect`, and anything else is answered 403 or closed without dialing the computer
  (`TestAuditForwardCarriesAnyLocalProcess`, `TestForwardCarriesOnlyRequestsWithTheToken`).

## 6. Tailcat-only mode (T1)

`tailcatOnly` on the computer opens no local network listener, connects to no relay and lists only
Tailcat in invites and routes; on the phone, `TailcatOnly` ignores every other route it is given.
Pairings from v0.2 keep working. On the real network, a Tailcat-only computer and phone hold no
listening TCP socket and connect over TCP only to port 443 of tailcat.dev and its DERP nodes
(`TestAuditTailcatOnlyOpensNothingElse`, `TestTailcatOnlyPhone`, `TestTailcatOnlyAndNoLANConfig`).

## 7. Push notifications

See [PUSH.md](PUSH.md); the gateway (`cmd/tailpocket-push`) is code only, not deployed.

- **The body is end to end.** The computer seals each note with the phone's push key (AES-256-GCM,
  the app and key id in the additional data); the gateway, APNs and FCM carry ciphertext. Notes are
  padded to 256, 1024 or 2048 bytes, so only the tier shows (P2). `Open` takes a note only with a
  sequence number above the last one for its key; the phone's extension MUST store that number in the
  App Group before it shows the note, under a lock shared with the app (P1).
- **Handles are sealed and bound to their app (P3).** A handle is AES-GCM under the gateway's key
  with its version, key id and app id in the additional data; a handle from another app, a changed
  byte or an unknown key id opens nothing, and the gateway answers 403 without contacting APNs or
  FCM. It sends only to handles it issued.
- **Handles end (G1).** A handle expires after at most 30 days. A phone revokes its handles with
  `/v1/revoke` (it raises the token's lowest valid generation, kept on disk; a corrupt state file
  stops the gateway rather than reviving revoked handles), and does so when a computer is removed, so
  that computer cannot push again.
- **Not yet: device attestation for `/v1/register` and `/v1/revoke` (G1).** They are rate limited
  (per source address, per app and per device) and a source that sends many invalid tokens is
  blocked, but App Attest and Play Integrity are not implemented: someone who learns a device token
  can register it, and push the app's fixed placeholder text to it. Implement them before the
  gateway is deployed; a config that asks for them refuses to start until then.
- **Nothing else is sent (G2).** Visible title and body come only from the gateway's config;
  `collapse` must match `[A-Za-z0-9._-]{1,64}` and `priority` is `high` or `normal`. The gateway
  connects only to APNs, FCM and Google OAuth, follows no redirect and uses no proxy; CONNECT,
  absolute-form targets and `OPTIONS *` get 400. Logs carry only a hash prefix of a handle.

## 8. Keys (I1–I4)

- **I1.** A phone's Noise key is a labelled SHA-256 of its Tailcat key: one-way, and a phone that
  uses the same Tailcat key with two computers has the same Noise key on both (they can tell).
- **I2.** The computer's Noise key is generated on its own and never equals its Tailcat node key:
  identity loading refuses one that does (`TestNoiseKeyIsNotTheTailcatKey`), because the phone's
  nodekey proof does X25519 with the Noise key.
- **I3.** Every primitive that touches a secret is constant time (x/crypto ChaCha20-Poly1305,
  crypto/ecdh X25519, `hmac.Equal`, `subtle.ConstantTimeCompare` for tokens and commitments). Swift
  and Kotlin call the same Go code through gomobile and do no protocol cryptography.
- **I4.** Store the phone's link (it holds the Tailcat key) and the computer's state (all its keys)
  in the Keychain or Keystore, never in plain files or cloud backups: `TailPocketKeychainStore` uses
  `AfterFirstUnlockThisDeviceOnly`, the Kotlin store a Keystore AES-GCM key. A push key the iOS
  notification extension reads lives in the App Group's keychain, also `AfterFirstUnlock`.

## Not defended

- Availability against anyone on the path: a relay, the Wi-Fi or Tailcat can drop traffic, and the
  room name is public, so its 16 phone slots can be filled. Phones go to their next route.
- A computer or phone that is itself compromised.
- What the user approves: the emoji and the 6-digit code protect a user who compares them.
