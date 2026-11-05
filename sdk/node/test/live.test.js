// Real helper, real Tailcat relays, the Go phone CLI as the phone. Opt in with TAILPOCKET_LIVE=1
// after scripts/build-host.sh.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { execFile, spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { TailPocketHost, tailPocketHelperPath } from '../index.js';

const live = process.env.TAILPOCKET_LIVE === '1';
const phoneCLI = fileURLToPath(new URL(`../../../build/tailpocket-phone-${process.platform === 'darwin' ? 'darwin' : 'linux'}-${process.arch === 'arm64' ? 'arm64' : 'amd64'}`, import.meta.url));

test('a phone pairs by QR and reaches the Node server', { skip: !live && 'set TAILPOCKET_LIVE=1', timeout: 240_000 }, async () => {
  const server = createServer((socket) => {
    let first = '';
    socket.once('data', (chunk) => { first = chunk.toString(); socket.end(`hello ${first.trim()} from node\n`); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const dir = mkdtempSync(join(tmpdir(), 'tailPocket-node-'));
  let state;
  const host = await TailPocketHost.start({ helper: tailPocketHelperPath(), name: 'node host', forward: `127.0.0.1:${server.address().port}`,
    save: (s) => { state = s; } });
  try {
    const pairing = await host.pair({ ttl: 180, payload: 'node-token' });
    const link = join(dir, 'link.json');
    await promisify(execFile)(phoneCLI, ['pair', '-device', 'cli phone', '-out', link, pairing.qr], { timeout: 150_000 });
    const phone = await pairing.paired;
    assert.equal(phone.device, 'cli phone');
    assert.deepEqual(state.allowed, [phone.phone]);
    assert.ok(host.address.startsWith('tc'));
    const reply = await new Promise((resolve, reject) => {
      const child = spawn(phoneCLI, ['dial', '-link', link]);
      let out = '';
      child.stdout.on('data', (d) => { out += d; });
      child.on('exit', () => resolve(out));
      child.on('error', reject);
      child.stdin.end('ping\n');
    });
    assert.equal(reply, 'hello ping from node\n');
    await host.revoke(phone.phone);
    assert.deepEqual(host.allowed, []);
    assert.equal(host.address, '');
  } finally {
    await host.close();
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
