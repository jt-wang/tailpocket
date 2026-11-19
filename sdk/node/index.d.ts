import { EventEmitter } from 'node:events';

export interface TailPocketHostState {
  /** Contains the node's private keys: store it like a password. */
  identity: string;
  allowed: string[];
  /** Each phone's Noise key for the end-to-end encrypted routes (v0.3). Pass it back as options.keys. */
  keys?: Record<string, string>;
}

/** A tailpocket-relay the host registers with. */
export interface TailPocketRelay {
  /** wss://…; ws:// only to a loopback address. */
  url: string;
  token: string;
  /** Pass the phone's bytes to `forward` without TailPocket's encryption (your app runs its own pinned TLS). */
  opaque?: boolean;
}

export interface TailPocketRoute {
  t: 'tailcat' | 'relay' | 'lan' | string;
  a?: string[];
  p?: number;
  u?: string;
  r?: string;
  m?: 'opaque';
}

export interface TailPocketAuditEvent {
  kind: 'paired' | 'revoked' | 'conn-open' | 'conn-close' | 'denied' | string;
  phone: string;
  route: string;
  reason?: string;
  time: Date;
}

export interface TailPocketHostOptions {
  /** Where each phone connection goes: "127.0.0.1:PORT" or "unix:/path". */
  forward: string;
  /** Store state; throw to refuse the change. Called before a change takes effect. */
  save(state: TailPocketHostState): Promise<void> | void;
  /** Restore a previous TailPocketHostState. */
  identity?: string;
  allowed?: string[];
  keys?: Record<string, string>;
  relays?: TailPocketRelay[];
  /** Addresses ("192.168.1.20:7681") phones reach directly, end-to-end encrypted. Not 0.0.0.0. */
  listen?: string[];
  /** Decide each connection from a paired phone; false (or no answer in 5 s) closes it. */
  authorize?(phone: string, route: string): Promise<boolean> | boolean;
  /** Pairings, revokes, sessions and refusals. Never keys, codes or payloads. */
  audit?(event: TailPocketAuditEvent): void;
  /** Shown on the phone while pairing. Default: the hostname. */
  name?: string;
  /** Write "nodekey:…\n" (the phone's key) as the first line of each forwarded connection. */
  identifyPhone?: boolean;
  /** Your own relay map instead of Tailcat's free, rate-limited default (https://tailcat.dev/derpmap.json). */
  derpMapUrl?: string;
  port?: number;
  pairingPort?: number;
  /** Helper binary path (default: bundled, or $TAILPOCKET_HOST), or a command to run. */
  helper?: string | { command: string; args?: string[] };
}

export interface TailPocketPairOptions {
  /** Seconds the window stays open (default 120, at most 900). */
  ttl?: number;
  /** Your data for the phone, delivered inside the tunnel (a token, settings…). */
  payload?: string;
  /** Prefix of the QR text (default "tailpocket1:"). The phone must use the same. */
  qrPrefix?: string;
  /** Prefix of the v2 QR text (default "tailpocket2:"). */
  qrPrefix2?: string;
}

export interface TailPocketPhone { phone: string; device: string }

export interface TailPocketLocalOptions {
  /** Bonjour type phones browse for, e.g. "_myapp._tcp". */
  service: string;
  /** Show code and device to the user; resolve true if the phone shows the same code. */
  confirm(code: string, device: string): Promise<boolean> | boolean;
  label?: string;
  instance?: string;
  /** The phone left before the user decided. */
  onCancel?(): void;
}

export interface TailPocketPairing {
  id: string;
  /** Text for a QR code or link. Anyone holding it can pair until it expires. */
  qr: string;
  invite: Record<string, unknown>;
  /** v2 invite for v0.3 phones: every route, the host's Noise key. Same secret as `qr`. */
  qr2: string;
  invite2: Record<string, unknown>;
  expiresAt: Date;
  paired: Promise<TailPocketPhone>;
  closed: Promise<'paired' | 'expired' | 'stopped' | string>;
  local(options: TailPocketLocalOptions): Promise<void>;
  cancel(): void;
}

export class TailPocketHostError extends Error { code: string }

export function tailPocketHelperPath(): string;

export class TailPocketHost extends EventEmitter {
  static start(options: TailPocketHostOptions): Promise<TailPocketHost>;
  readonly options: TailPocketHostOptions;
  /** The node's address, "" while no phone is paired. */
  address: string;
  allowed: string[];
  pair(options?: TailPocketPairOptions): Promise<TailPocketPairing>;
  setAllowed(phones: string[]): Promise<void>;
  revoke(phone: string): Promise<void>;
  disconnect(phone: string): Promise<void>;
  status(): Promise<{ address: string; routes: TailPocketRoute[]; relays: Record<string, string> }>;
  close(): Promise<void>;
}
