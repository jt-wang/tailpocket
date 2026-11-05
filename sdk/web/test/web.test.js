import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { loadTailPocket, TailPocketError, tailPocketInviteText } from '../index.js';

after(async () => { (await loadTailPocket()).unload(); });

test('keys and invite decoding without network', async () => {
  const tc = await loadTailPocket();
  const key = tc.newKey();
  assert.match(key, /^privkey:/);
  assert.match(tc.publicKey(key), /^nodekey:/);
  assert.equal(tc.publicKey('junk'), null);
  assert.throws(() => tc.decodeInvite('tailpocket1:junk'), (e) => e instanceof TailPocketError && e.code === 'invalid-invite');
  await assert.rejects(tc.pair({ v: 1 }, key, 'x'), (e) => e.code === 'invalid-invite');
});

test('tailPocketInviteText finds the code in scanned text', () => {
  assert.equal(tailPocketInviteText(' tailpocket1:abc\n'), 'tailpocket1:abc');
  assert.equal(tailPocketInviteText('https://app.example/pair#tailpocket1:abc'), 'tailpocket1:abc');
  assert.equal(tailPocketInviteText('https://example.com'), null);
});

test('the browser example only calls methods the SDK has', async () => {
  const tc = await loadTailPocket();
  const page = readFileSync(new URL('../../../examples/web-phone/index.html', import.meta.url), 'utf8');
  const called = [...new Set([...page.matchAll(/tailPocket\.(\w+)\(/g)].map((m) => m[1]))];
  assert.ok(called.length > 0);
  assert.deepEqual(called.filter((name) => typeof tc[name] !== 'function'), []);
});

test('a browser-style phone pairs and fetches over the relays', { skip: process.env.TAILPOCKET_LIVE !== '1' && 'set TAILPOCKET_LIVE=1', timeout: 240_000 }, async () => {
  const { Host, bundledHelper } = await import('../../node/index.js');
  const web = createServer((req, res) => res.end(req.url === '/hello.txt' ? `hello ${req.headers['x-from']}\n` : 'no'));
  await new Promise((r) => web.listen(0, '127.0.0.1', r));
  const host = await Host.start({ helper: bundledHelper(), name: 'wasm host', forward: `127.0.0.1:${web.address().port}`, save: () => {} });
  try {
    const pairing = await host.pair({ ttl: 180, payload: 'web-token' });
    const tc = await loadTailPocket();
    const link = await tc.pair(tc.decodeInvite(pairing.qr), tc.newKey(), 'wasm phone');
    assert.equal(link.payload, 'web-token');
    assert.equal((await pairing.paired).device, 'wasm phone');
    const res = await tc.fetch(link, '/hello.txt', { headers: { 'x-from': 'the browser' } });
    assert.equal(res.status, 200);
    assert.equal(await res.text(), 'hello the browser\n');
  } finally {
    await host.close();
    web.close();
  }
});
