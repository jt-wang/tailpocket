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
