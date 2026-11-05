export const TAILPOCKET_INVITE_PREFIX: string;
export class TailPocketError extends Error { code: string }
export interface TailPocketInvite { v: number; address: string; port: number; key: string; proof: string; expiresAt: number; name?: string }
/** Store like a password: it holds the phone's private key. */
export interface TailPocketHostLink { address: string; port: number; name: string; payload?: string; key: string }
export interface TailPocketStream { read(): Promise<Uint8Array | null>; write(data: Uint8Array | string): Promise<void>; close(): void }
export interface TailPocket {
  newKey(): string;
  publicKey(key: string): string | null;
  tailPocketInviteText(text: string, prefix?: string): string | null;
  decodeInvite(text: string, prefix?: string): TailPocketInvite;
  pair(invite: TailPocketInvite, phoneKey: string, device: string, options?: { timeoutMs?: number }): Promise<TailPocketHostLink>;
  fetch(link: TailPocketHostLink | string, path: string, init?: RequestInit): Promise<Response>;
  dial(link: TailPocketHostLink | string): Promise<TailPocketStream>;
  /** Stops the WebAssembly runtime (needed for Node processes to exit). */
  unload(): Promise<void>;
}
export function tailPocketInviteText(text: string, prefix?: string): string | null;
export function loadTailPocket(options?: { wasmURL?: string | URL; execURL?: string | URL }): Promise<TailPocket>;
export function scanTailPocketInvite(options: { video: HTMLVideoElement; prefix?: string; signal?: AbortSignal }): Promise<string>;
