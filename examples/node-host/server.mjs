// A complete host in ~50 lines: an HTTP server that paired phones reach from anywhere.
//
//   node examples/node-host/server.mjs            # prints a pairing code; scan it with the phone
//   TAILPOCKET_SERVICE=_myapp._tcp node …                 # also lets phones on this Wi-Fi find it
//   TAILPOCKET_RELAY_URL=wss://relay.example.com TAILPOCKET_RELAY_TOKEN=… node …   # also over your tailpocket-relay
//   TAILPOCKET_EMOJI=1 node …                             # a v0.3 code (every route) with the emoji check
//
// TailPocketHostState (identity + paired phones) is kept in ./host-state.json; delete it to forget all phones.
import { createServer } from 'node:http';
import { readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
// The installed package, or the one in this repository when run from a checkout.
const { TailPocketHost } = await import('tailpocket').catch(() => import('../../sdk/node/index.js'));

const stateFile = process.env.TAILPOCKET_STATE ?? 'host-state.json';
let state = {};
try { state = JSON.parse(readFileSync(stateFile, 'utf8')); } catch {}

const web = createServer((req, res) => {
  if (req.url === '/hello.txt') return res.end('hello from the computer\n');
  res.writeHead(404).end();
});
await new Promise((resolve) => web.listen(0, '127.0.0.1', resolve));

const connectHost = await TailPocketHost.start({
  name: process.env.TAILPOCKET_NAME ?? 'Node example',
  forward: `127.0.0.1:${web.address().port}`,
  identity: state.identity,
  allowed: state.allowed,
  keys: state.keys,
  relays: process.env.TAILPOCKET_RELAY_URL ? [{ url: process.env.TAILPOCKET_RELAY_URL, token: process.env.TAILPOCKET_RELAY_TOKEN ?? '' }] : undefined,
  save: (next) => writeFileSync(stateFile, JSON.stringify(next), { mode: 0o600 }),
});

// TAILPOCKET_EMOJI=1 (or a relay) opens a v0.3 window: one code for every route, and the user compares the four
// emoji the phone shows with the ones printed here. Without it, a v0.2-style Tailcat code.
const emoji = process.env.TAILPOCKET_EMOJI === '1' || !!process.env.TAILPOCKET_RELAY_URL;
let ask;
const yes = async (question) => process.env.TAILPOCKET_AUTO_APPROVE === '1'
  || /^y/i.test(await (ask ??= createInterface({ input: process.stdin, output: process.stderr })).question(question));
const pairing = await connectHost.pair({ ttl: 300, payload: 'welcome', emoji });
if (emoji) {
  console.log(`QR2 ${pairing.qr2}`); // render it with any QR library, or paste it into the phone
  pairing.on('request', async ({ device, emoji: shown }) => {
    console.log(`EMOJI ${device} ${shown.join(' ')}`);
    pairing.confirm(await yes(`${device} shows ${shown.join(' ')}? [y/N] `));
  });
} else {
  console.log(`QR ${pairing.qr}`);
}
if (process.env.TAILPOCKET_SERVICE) {
  pairing.local({
    service: process.env.TAILPOCKET_SERVICE,
    confirm: (code, device) => yes(`${device} shows ${code}? [y/N] `),
  }).catch(() => {});
}
pairing.paired.then(({ device }) => console.log(`PAIRED ${device}`), () => console.log('EXPIRED'));
process.on('SIGINT', async () => { await connectHost.close(); web.close(); process.exit(0); });
process.on('SIGTERM', async () => { await connectHost.close(); web.close(); process.exit(0); });
