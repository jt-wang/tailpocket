// A scripted stand-in for tailpocket-host that speaks the same protocol without any network.
import { createInterface } from 'node:readline';
const out = (v) => process.stdout.write(JSON.stringify(v) + '\n');
const lines = createInterface({ input: process.stdin });
let config, allowed = [], saveSerial = 0;
const waiting = new Map(), confirms = new Map();
let askSerial = 0;
const ask = (event) => new Promise((resolve) => { const id = 'a' + ++askSerial; waiting.set(id, resolve); out({ ...event, id }); });
const save = (state) => new Promise((resolve) => { const id = 's' + ++saveSerial; waiting.set(id, resolve); out({ event: 'save', id, state }); });
lines.on('line', async (line) => {
  const msg = JSON.parse(line);
  if (!config) {
    config = msg;
    if (config.forward === 'refuse') { out({ event: 'error', code: 'invalid-forward' }); process.exit(1); }
    const relays = config.relays ?? [];
    if (relays.some((r) => r.opaque && !r.appAuth) || (config.tailcatOnly && (relays.length || config.listen?.length)) || (config.noLan && config.listen?.length)) {
      out({ event: 'error', code: 'invalid-config' }); process.exit(1);
    }
    const set = config.routes;
    if (set && (!set.length || (set.includes('relay') !== relays.length > 0) || (!set.includes('lan') && config.listen?.length) || config.tailcatOnly || config.noLan)) {
      out({ event: 'error', code: 'invalid-config', message: 'connecthost: invalid routes' }); process.exit(1);
    }
    allowed = config.allowed ?? [];
    out({ event: 'ready', address: allowed.length ? 'tcFAKE' : '' });
    if (config.authorize) setTimeout(() => connect(allowed[0]), 20); // a paired phone connects
    return;
  }
  switch (msg.cmd) {
    case 'saved': case 'authorized': waiting.get(msg.id)?.(msg.ok); waiting.delete(msg.id); break;
    case 'status': {
      const routes = config.routes ? [...(config.relays ?? []).map((r) => ({ t: 'relay', u: r.url, r: 'ROOM' })),
        ...(config.routes.includes('lan') ? [{ t: 'lan', a: ['192.168.1.20'], p: 7681 }] : [])] : config.tailcatOnly ? [{ t: 'tailcat' }] : [...(config.relays ?? []).map((r) => ({ t: 'relay', u: r.url, r: 'ROOM', ...(r.opaque ? { m: 'opaque' } : {}) })),
        ...(config.noLan ? [] : [{ t: 'lan', a: ['192.168.1.20'], p: 7681 }])];
      out({ event: 'status', id: msg.id, address: '', routes, relays: Object.fromEntries((config.relays ?? []).map((r) => [r.url, 'up'])) });
      break;
    }
    case 'disconnect': out({ event: 'disconnected', id: msg.id, phone: msg.phone }); break;

    case 'pair':
      // As the helper: an emoji window hands out only the v2 invite, any other only the v1 one.
      out(msg.emoji
        ? { event: 'pairing', id: msg.id, qr2: (msg.qrPrefix2 ?? 'tailpocket2:') + 'FAKE', invite2: { v: 2, name: config.name }, expiresAt: 4102444800 }
        : { event: 'pairing', id: msg.id, qr: (msg.qrPrefix ?? 'tailpocket1:') + 'FAKE', invite: { v: 1, name: config.name }, expiresAt: 4102444800 });
      if (msg.payload === 'expire') { out({ event: 'pairingClosed', id: msg.id, reason: 'expired' }); break; }
      if (msg.emoji && msg.payload === 'leave') { // the phone asks, then goes away before the answer
        out({ event: 'pairRequest', id: msg.id, phone: 'nodekey:' + 'ab'.repeat(32), device: 'Pixel', route: 'lan', emoji: ['🐶', '🌙', '🍕', '🔑'] });
        out({ event: 'pairRequestCancelled', id: msg.id });
        out({ event: 'pairingClosed', id: msg.id, reason: 'expired' });
        break;
      }
      if (msg.emoji && msg.payload !== 'wait') {
        setTimeout(() => {
          confirms.set(msg.id, 'request');
          out({ event: 'pairRequest', id: msg.id, phone: 'nodekey:' + 'ab'.repeat(32), device: 'Pixel', route: 'relay', emoji: ['🐶', '🌙', '🍕', '🔑'] });
        }, 20);
        break;
      }
      if (msg.payload !== 'wait') setTimeout(() => join(msg.id), 20);
      break;
    case 'local':
      out({ event: 'localCode', id: msg.id, code: '123456', device: 'Pixel' });
      confirms.set(msg.id, 'local');
      break;
    case 'confirm': {
      const kind = confirms.get(msg.id);
      if (!kind) { out({ event: 'error', id: msg.id, code: 'nothing-to-confirm' }); break; }
      confirms.delete(msg.id);
      if (kind === 'request') {
        if (msg.approve) join(msg.id);
        else out({ event: 'pairingClosed', id: msg.id, reason: 'expired' }); // a no spends the code
        break;
      }
      if (msg.approve) { out({ event: 'localDelivered', id: msg.id }); join(msg.id); }
      else out({ event: 'error', id: msg.id, code: 'local-not-approved' });
      break;
    }
    case 'cancel': out({ event: 'pairingClosed', id: msg.id, reason: 'expired' }); break;
    case 'revoke': {
      const next = allowed.filter((k) => k !== msg.phone);
      if (await save({ identity: 'ID', allowed: next })) { allowed = next; out({ event: 'allowed', id: msg.id, allowed, address: allowed.length ? 'tcFAKE' : '' }); }
      else out({ event: 'error', id: msg.id, code: 'operation-failed' });
      break;
    }
    case 'setAllowed':
      if (await save({ identity: 'ID', allowed: msg.allowed })) { allowed = msg.allowed; out({ event: 'allowed', id: msg.id, allowed, address: allowed.length ? 'tcFAKE' : '' }); }
      else out({ event: 'error', id: msg.id, code: 'operation-failed' });
      break;
    default: out({ event: 'error', id: msg.id, code: 'unknown-command' });
  }
});
async function join(id) {
  const phone = 'nodekey:' + 'ab'.repeat(32);
  if (!(await save({ identity: 'ID', allowed: [...allowed, phone] }))) return;
  allowed.push(phone);
  out({ event: 'paired', id, phone, device: 'Pixel', address: 'tcFAKE' });
  out({ event: 'pairingClosed', id, reason: 'paired' });
}
async function connect(phone) {
  const ok = await ask({ event: 'authorize', phone, route: 'relay' });
  if (config.audit) out({ event: 'audit', kind: ok ? 'conn-open' : 'denied', phone, route: 'relay', reason: ok ? '' : 'authorize', time: 1790000000000 });
}
