import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { TailPocketHost, TailPocketHostError } from '../index.js';

const fake = { command: process.execPath, args: [fileURLToPath(new URL('./fixtures/fake-helper.mjs', import.meta.url))] };

function start(options = {}) {
  const saved = [];
  return TailPocketHost.start({ helper: fake, name: 'Studio Mac', forward: '127.0.0.1:3000', save: async (s) => { saved.push(s); }, ...options })
    .then((host) => ({ host, saved }));
}

test('start reports the address and config errors', async () => {
  const { host } = await start();
  assert.equal(host.address, '');
  await host.close();
  await assert.rejects(start({ forward: 'refuse' }), (e) => e instanceof TailPocketHostError && e.code === 'invalid-forward');
  await assert.rejects(TailPocketHost.start({ helper: fake, forward: '127.0.0.1:1' }), /save/);
});

test('QR pairing: the app saves state before the phone joins', async () => {
  const { host, saved } = await start();
  const pairing = await host.pair({ ttl: 60, payload: 'token' });
  assert.equal(pairing.qr, 'tailpocket1:FAKE');
  const phone = await pairing.paired;
  assert.equal(phone.device, 'Pixel');
  assert.match(phone.phone, /^nodekey:/);
  assert.deepEqual(saved.at(-1).allowed, [phone.phone]);
  assert.equal(await pairing.closed, 'paired');
  assert.equal(host.address, 'tcFAKE');
  assert.deepEqual(host.allowed, [phone.phone]);
  await host.close();
});

test('a failing save refuses the change', async () => {
  const { host } = await start({ allowed: ['nodekey:' + 'cd'.repeat(32)] });
  host.options.save = async () => { throw new Error('disk full'); };
  await assert.rejects(host.revoke('nodekey:' + 'cd'.repeat(32)), (e) => e.code === 'operation-failed');
  await host.close();
});

test('expired window rejects paired', async () => {
  const { host } = await start();
  const pairing = await host.pair({ payload: 'expire' });
  await assert.rejects(pairing.paired, (e) => e.code === 'expired');
  await host.close();
});

test('same-Wi-Fi pairing asks the app to confirm the code', async () => {
  const { host } = await start();
  const pairing = await host.pair({ payload: 'wait' });
  const seen = [];
  await pairing.local({ service: '_myapp._tcp', confirm: async (code, device) => { seen.push([code, device]); return true; } });
  assert.deepEqual(seen, [['123456', 'Pixel']]);
  assert.equal((await pairing.paired).device, 'Pixel');
  await host.close();
});

test('denying the code rejects local()', async () => {
  const { host } = await start();
  const pairing = await host.pair({ payload: 'wait' });
  await assert.rejects(pairing.local({ service: '_myapp._tcp', confirm: async () => false }), (e) => e.code === 'local-not-approved');
  await host.close();
});

test('setAllowed and revoke', async () => {
  const a = 'nodekey:' + '01'.repeat(32), b = 'nodekey:' + '02'.repeat(32);
  const { host, saved } = await start();
  await host.setAllowed([a, b]);
  assert.deepEqual(host.allowed, [a, b]);
  await host.revoke(a);
  assert.deepEqual(host.allowed, [b]);
  assert.deepEqual(saved.at(-1).allowed, [b]);
  await host.close();
});

test('pair rejects after close', async () => {
  const { host } = await start();
  await host.close();
  await assert.rejects(host.pair(), /closed/);
});

test('v0.3: relays, authorize, audit, status and disconnect; no v2 QR without emoji', async () => {
  const phone = 'nodekey:' + 'cd'.repeat(32);
  const asked = [];
  let audited;
  const got = new Promise((resolve) => { audited = resolve; });
  const { host } = await start({
    allowed: [phone], relays: [{ url: 'wss://relay.example.com', token: 't' }],
    authorize: (p, route) => { asked.push([p, route]); return false; },
    audit: (e) => audited(e),
  });
  const e = await got;
  assert.deepEqual(asked, [[phone, 'relay']]);
  assert.equal(e.kind, 'denied');
  assert.ok(e.time instanceof Date);
  const pairing = await host.pair({ payload: 'wait' });
  assert.equal(pairing.qr, 'tailpocket1:FAKE');
  assert.equal(pairing.qr2, undefined, 'a window without emoji hands out no v2 invite');
  assert.equal(pairing.invite2, undefined);
  const st = await host.status();
  assert.equal(st.relays['wss://relay.example.com'], 'up');
  assert.equal(st.routes[0].t, 'relay');
  await host.disconnect(phone);
  await host.close();
});

test('emoji window: only the v2 invite, a request with the emoji, and confirm(true) pairs', async () => {
  const { host, saved } = await start();
  const pairing = await host.pair({ ttl: 60, payload: 'token', emoji: true });
  assert.equal(pairing.qr2, 'tailpocket2:FAKE');
  assert.equal(pairing.invite2.v, 2);
  assert.equal(pairing.qr, undefined, 'an emoji window hands out no v1 invite');
  assert.equal(pairing.invite, undefined);
  const request = await new Promise((resolve) => pairing.once('request', resolve));
  assert.deepEqual(request, { phone: 'nodekey:' + 'ab'.repeat(32), device: 'Pixel', route: 'relay', emoji: ['🐶', '🌙', '🍕', '🔑'] });
  pairing.confirm(true);
  const phone = await pairing.paired;
  assert.equal(phone.phone, request.phone);
  assert.deepEqual(saved.at(-1).allowed, [phone.phone]);
  assert.equal(await pairing.closed, 'paired');
  await host.close();
});

test('emoji window: confirm(false) refuses the phone and spends the code', async () => {
  const { host, saved } = await start();
  const pairing = await host.pair({ payload: 'token', emoji: true });
  pairing.on('request', () => pairing.confirm(false));
  await assert.rejects(pairing.paired, (e) => e.code === 'expired');
  assert.equal(await pairing.closed, 'expired');
  assert.equal(saved.length, 0);
  await host.close();
});

test('emoji window: no request listener refuses at once', async () => {
  const { host } = await start();
  const pairing = await host.pair({ payload: 'token', emoji: true });
  assert.equal(await pairing.closed, 'expired');
  await assert.rejects(pairing.paired, (e) => e.code === 'expired');
  await host.close();
});

test('emoji window: a phone that leaves before the answer cancels its request', async () => {
  const { host } = await start();
  const pairing = await host.pair({ payload: 'leave', emoji: true });
  const seen = [];
  pairing.on('request', (r) => seen.push(r.route));
  pairing.on('requestCancelled', () => seen.push('cancelled'));
  assert.equal(await pairing.closed, 'expired');
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(seen, ['lan', 'cancelled']);
  await host.close();
});

test('pre.4 config: tailcatOnly, noLan, and appAuth with an opaque relay', async () => {
  const only = await start({ tailcatOnly: true });
  assert.deepEqual((await only.host.status()).routes, [{ t: 'tailcat' }]);
  await only.host.close();
  const noLan = await start({ noLan: true, relays: [{ url: 'wss://relay.example.com', token: 't' }] });
  assert.deepEqual((await noLan.host.status()).routes.map((r) => r.t), ['relay']);
  await noLan.host.close();
  await assert.rejects(start({ tailcatOnly: true, relays: [{ url: 'wss://relay.example.com', token: 't' }] }), (e) => e.code === 'invalid-config');
  await assert.rejects(start({ relays: [{ url: 'wss://relay.example.com', token: 't', opaque: true }] }), (e) => e.code === 'invalid-config');
  const opaque = await start({ relays: [{ url: 'wss://relay.example.com', token: 't', opaque: true, appAuth: true }] });
  assert.equal((await opaque.host.status()).routes[0].m, 'opaque');
  await opaque.host.close();
});

test('v0.3.2 routes: a set without Tailcat, and bad sets rejected with the reason', async () => {
  const relayOnly = await start({ routes: ['relay'], relays: [{ url: 'wss://relay.example.com', token: 't' }] });
  assert.deepEqual((await relayOnly.host.status()).routes.map((r) => r.t), ['relay']);
  await relayOnly.host.close();
  for (const bad of [{ routes: [] }, { routes: ['relay'] }, { routes: ['lan'], tailcatOnly: true }]) {
    await assert.rejects(start(bad), (e) => e.code === 'invalid-config' && /invalid routes/.test(e.message));
  }
});
