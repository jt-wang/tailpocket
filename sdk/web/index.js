// Phone SDK for browsers and PWAs, backed by dist/tailpocket.wasm (the Go phone SDK compiled to
// WebAssembly). Browsers cannot send raw UDP, so traffic always goes through the relays over
// WebSockets, and there is no same-Wi-Fi discovery: pair by QR code or link.

export const TAILPOCKET_INVITE_PREFIX = 'tailpocket1:';

/** A failure with a fixed code (invalid-invite, expired, taken, unreachable, …). */
export class TailPocketError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

/** Finds invite text in scanned or pasted text: a bare code, or a link containing it. */
export function tailPocketInviteText(text, prefix = TAILPOCKET_INVITE_PREFIX) {
  const start = text.indexOf(prefix);
  if (start < 0) return null;
  const tail = /^[A-Za-z0-9_-]+/.exec(text.slice(start + prefix.length));
  return tail ? prefix + tail[0] : null;
}

const fail = (text) => {
  try {
    const v = JSON.parse(text);
    if (v && typeof v.error === 'string') return new TailPocketError(v.error);
  } catch {}
  return null;
};
const coded = (e) => (e instanceof TailPocketError ? e : new TailPocketError(e?.message || 'failed'));

let loading;

/**
 * Loads the WebAssembly module once. In a browser pass the URLs you serve them from; under Node the
 * files next to this module are read directly.
 * @param {{ wasmURL?: string|URL, execURL?: string|URL }} [options]
 */
export function loadTailPocket(options = {}) {
  loading ??= start(options).catch((e) => { loading = undefined; throw e; });
  return loading;
}

async function start({ wasmURL = new URL('./dist/tailpocket.wasm', import.meta.url), execURL = new URL('./dist/wasm_exec.js', import.meta.url) }) {
  wasmURL = new URL(wasmURL, import.meta.url);
  execURL = new URL(execURL, import.meta.url);
  if (!globalThis.Go) await import(execURL.href);
  const go = new globalThis.Go();
  let instance;
  if (wasmURL.protocol === 'file:') {
    const { readFile } = await import('node:fs/promises');
    ({ instance } = await WebAssembly.instantiate(await readFile(wasmURL), go.importObject));
  } else if (WebAssembly.instantiateStreaming) {
    ({ instance } = await WebAssembly.instantiateStreaming(fetch(wasmURL), go.importObject));
  } else {
    ({ instance } = await WebAssembly.instantiate(await (await fetch(wasmURL)).arrayBuffer(), go.importObject));
  }
  const ready = new Promise((resolve) => { globalThis.onTailPocketReady = resolve; });
  const exited = go.run(instance);
  await ready;
  const native = globalThis.tailPocketNative;
  return { ...api(native), async unload() { native.exit(); await exited; loading = undefined; } };
}

function api(native) {
  const linkText = (link) => (typeof link === 'string' ? link : JSON.stringify(link));
  return {
    /** A new phone identity: create once and store it (e.g. IndexedDB). */
    newKey: () => native.newKey(),
    publicKey: (key) => native.publicKey(key) || null,
    tailPocketInviteText,
    decodeInvite(text, prefix = TAILPOCKET_INVITE_PREFIX) {
      const out = native.decodeInvite(text, prefix);
      const err = fail(out);
      if (err) throw err;
      return JSON.parse(out);
    },
    /** Joins the computer's pairing window; returns the link to store. Store it like a password. */
    async pair(invite, phoneKey, device, { timeoutMs = 90_000 } = {}) {
      try {
        return JSON.parse(await native.pair(JSON.stringify(invite), phoneKey, device, timeoutMs));
      } catch (e) { throw coded(e); }
    },
    /** fetch() to the computer's server through the tunnel; returns a standard Response. */
    async fetch(link, path, init = {}) {
      let body = init.body;
      if (body != null && typeof body !== 'string' && !(body instanceof Uint8Array)) body = new Uint8Array(await new Response(body).arrayBuffer());
      const headers = Object.fromEntries(new Headers(init.headers ?? {}).entries());
      try {
        const r = await native.request(linkText(link), { method: init.method ?? 'GET', path, headers, body });
        return new Response(r.status === 204 || r.status === 304 ? null : r.body, { status: r.status, headers: r.headers });
      } catch (e) { throw coded(e); }
    },
    /** A raw byte stream to the computer's server. */
    async dial(link) {
      try { return await native.dial(linkText(link)); } catch (e) { throw coded(e); }
    },
  };
}

/**
 * Scans a QR code with the camera using the browser's BarcodeDetector (Chrome on Android and
 * desktop). Resolves with the invite text. Where BarcodeDetector is missing (Safari, Firefox) it
 * rejects with code "unsupported": decode frames with a QR library and pass the text to tailPocketInviteText.
 * @param {{ video: HTMLVideoElement, prefix?: string, signal?: AbortSignal }} options
 */
export async function scanTailPocketInvite({ video, prefix = TAILPOCKET_INVITE_PREFIX, signal }) {
  if (!('BarcodeDetector' in globalThis)) throw new TailPocketError('unsupported');
  const detector = new globalThis.BarcodeDetector({ formats: ['qr_code'] });
  const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } });
  video.srcObject = stream;
  await video.play();
  try {
    for (;;) {
      if (signal?.aborted) throw new TailPocketError('cancelled');
      for (const code of await detector.detect(video)) {
        const text = tailPocketInviteText(code.rawValue, prefix);
        if (text) return text;
      }
      await new Promise((r) => setTimeout(r, 200));
    }
  } finally {
    for (const track of stream.getTracks()) track.stop();
    video.srcObject = null;
  }
}
