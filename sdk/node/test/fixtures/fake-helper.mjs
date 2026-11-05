// A scripted stand-in for tailpocket-host that speaks the same protocol without any network.
import { createInterface } from 'node:readline';
const out = (v) => process.stdout.write(JSON.stringify(v) + '\n');
const lines = createInterface({ input: process.stdin });
let config, allowed = [], saveSerial = 0;
const waiting = new Map(), confirms = new Map();
const save = (state) => new Promise((resolve) => { const id = 's' + ++saveSerial; waiting.set(id, resolve); out({ event: 'save', id, state }); });
lines.on('line', async (line) => {
  const msg = JSON.parse(line);
  if (!config) {
    config = msg;
    if (config.forward === 'refuse') { out({ event: 'error', code: 'invalid-forward' }); process.exit(1); }
    allowed = config.allowed ?? [];
    out({ event: 'ready', address: allowed.length ? 'tcFAKE' : '' });
    return;
  }
  switch (msg.cmd) {
    case 'saved': waiting.get(msg.id)?.(msg.ok); waiting.delete(msg.id); break;
    case 'pair':
      out({ event: 'pairing', id: msg.id, qr: (msg.qrPrefix ?? 'tailpocket1:') + 'FAKE', invite: { v: 1, name: config.name }, expiresAt: 4102444800 });
      if (msg.payload === 'expire') { out({ event: 'pairingClosed', id: msg.id, reason: 'expired' }); break; }
      if (msg.payload !== 'wait') setTimeout(() => join(msg.id), 20);
      break;
    case 'local':
      out({ event: 'localCode', id: msg.id, code: '123456', device: 'Pixel' });
      confirms.set(msg.id, true);
      break;
    case 'confirm':
      if (!confirms.has(msg.id)) { out({ event: 'error', id: msg.id, code: 'nothing-to-confirm' }); break; }
      confirms.delete(msg.id);
      if (msg.approve) { out({ event: 'localDelivered', id: msg.id }); join(msg.id); }
      else out({ event: 'error', id: msg.id, code: 'local-not-approved' });
      break;
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
