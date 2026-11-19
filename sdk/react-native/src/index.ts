// React Native: `import { tailPocket } from "react-native-tailpocket"`, then the same calls as NSH
// (see sdk/js/client.ts): tailPocket.scan(), tailPocket.pair(invite, { device, save: true, onEmoji }), tailPocket.connect() …
import { NativeEventEmitter, NativeModules } from "react-native";
import { createTailPocket } from "tailpocket-client";
import { reactNativeTransport } from "./transport";

export * from "tailpocket-client";

const native = NativeModules.TailPocket;
export const tailPocket = createTailPocket(reactNativeTransport(native, native ? new NativeEventEmitter(native) : undefined));
