import type { TailPocketTransport } from "tailpocket-client";

/** The native module this package registers (TailPocketModule on Android and iOS). */
export interface NativeTailPocket {
  call(name: string, args: unknown): Promise<unknown>;
  addListener(event: string): void;
  removeListeners(count: number): void;
}
interface Emitter { addListener(event: string, listener: (data: any) => void): { remove(): void } }

/** React Native calls have no timeout of their own; the native side ends every call. */
export function reactNativeTransport(module: NativeTailPocket | undefined, emitter: Emitter | undefined): TailPocketTransport {
  if (!module || !emitter) {
    throw new Error("The TailPocket native module is missing: rebuild the app after installing react-native-tailpocket (pod install on iOS).");
  }
  return {
    call: (name, args) => module.call(name, args ?? null),
    on: (event, listener) => emitter.addListener(event, listener),
  };
}
