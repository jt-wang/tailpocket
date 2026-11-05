// A React Native phone app that pairs with a computer by QR code, by a pairing link, or over the
// same Wi-Fi, then talks to it through the tunnel. Run the computer side with examples/node-host
// (TAILPOCKET_SERVICE=_tailpocket-demo._tcp for the same-Wi-Fi list).
import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Linking, Pressable, StyleSheet, Text, View } from 'react-native';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import { tailPocket, TailPocketError, type TailPocketConnection, type TailPocketHostLink, type TailPocketNearbyHost } from 'react-native-tailpocket';

const SERVICE = '_tailpocket-demo._tcp';
const DEVICE = 'RN phone';

const MESSAGES: Record<string, string> = {
  expired: 'This QR code has expired. Make a new one on the computer.',
  'invalid-invite': 'That QR code is not a pairing code.',
  unreachable: 'The computer did not answer. Check that it is running.',
  denied: 'The computer said no.',
  unsupported: 'This device has no camera scanner.',
};
const explain = (e: unknown) => (e instanceof TailPocketError ? MESSAGES[e.code] ?? `Pairing failed (${e.code}).` : String(e));

/** The invite in a pairing link: tailpocketdemo://pair?invite=tailpocket1:… */
const inviteIn = (url: string | null | undefined) => {
  const m = url?.match(/[?&]invite=([^&#]+)/);
  return m ? decodeURIComponent(m[1]) : null;
};

export default function App({ invite: launchInvite }: { invite?: string }) {
  const [link, setLink] = useState<TailPocketHostLink | null>(null);
  const [answer, setAnswer] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [nearby, setNearby] = useState<TailPocketNearbyHost[]>([]);
  const [code, setCode] = useState('');
  const connection = useRef<TailPocketConnection | null>(null);
  const stopNearby = useRef<(() => Promise<void>) | null>(null);
  const busyRef = useRef(false);

  const open = useCallback(async (l: TailPocketHostLink) => {
    setLink(l);
    await stopNearby.current?.();
    stopNearby.current = null;
    connection.current = await tailPocket.connect();
    const res = await fetch(connection.current.baseUrl + '/hello.txt');
    setAnswer(await res.text());
  }, []);

  const attempt = useCallback(async (work: () => Promise<TailPocketHostLink>) => {
    if (busyRef.current) return;
    busyRef.current = true;
    setBusy(true);
    setError('');
    try {
      await open(await work());
    } catch (e) {
      if (!(e instanceof TailPocketError && e.code === 'cancelled')) setError(explain(e));
    } finally {
      busyRef.current = false;
      setBusy(false);
      setCode('');
    }
  }, [open]);

  const pairWith = useCallback((invite: string) => attempt(() => tailPocket.pair(invite, { device: DEVICE, save: true })), [attempt]);
  const scan = () => attempt(async () => tailPocket.pair(await tailPocket.scan(), { device: DEVICE, save: true }));
  const pairNearby = (name: string) =>
    attempt(async () => {
      const pending = await tailPocket.pairNearby({ name, device: DEVICE });
      setCode(pending.code);
      return tailPocket.pair(await pending.finish(), { device: DEVICE, save: true });
    });
  const browse = useCallback(async () => {
    try {
      stopNearby.current = await tailPocket.nearby(SERVICE, setNearby);
    } catch {
      // No Bonjour on this device: the QR code still works.
    }
  }, []);
  const forget = async () => {
    await connection.current?.close();
    connection.current = null;
    await tailPocket.store.deleteLink();
    setLink(null);
    setAnswer('');
    await browse();
  };

  useEffect(() => {
    const sub = Linking.addEventListener('url', ({ url }) => {
      const invite = inviteIn(url);
      if (invite) pairWith(invite);
    });
    (async () => {
      const invite = launchInvite || inviteIn(await Linking.getInitialURL());
      if (invite) return pairWith(invite);
      const saved = await tailPocket.store.link().catch(() => null);
      if (saved) await open(saved).catch((e) => setError(explain(e)));
      else await browse();
    })();
    return () => {
      sub.remove();
      stopNearby.current?.();
      connection.current?.close();
    };
  }, [browse, launchInvite, open, pairWith]);

  return (
    <SafeAreaProvider>
      <SafeAreaView style={styles.screen}>
        {link ? (
          <View style={styles.column}>
            <Text style={styles.muted}>Connected to</Text>
            <Text style={styles.title}>{link.name}</Text>
            <Text style={styles.mono} testID="answer">{answer}</Text>
            <Pressable onPress={forget} style={styles.plain} testID="forget">
              <Text style={styles.danger}>Forget this computer</Text>
            </Pressable>
          </View>
        ) : (
          <View style={styles.column}>
            <Text style={styles.title}>Pair with your computer</Text>
            <Pressable onPress={scan} style={styles.primary} testID="scan">
              <Text style={styles.primaryText}>{busy && !code ? 'Pairing…' : 'Scan QR code'}</Text>
            </Pressable>
            {code ? (
              <>
                <Text style={styles.muted}>Check that the computer shows</Text>
                <Text style={styles.code}>{code}</Text>
              </>
            ) : nearby.length > 0 ? (
              <>
                <Text style={styles.muted}>On this Wi-Fi</Text>
                {nearby.map((h) => (
                  <Pressable key={h.name} onPress={() => pairNearby(h.name)} style={styles.outline}>
                    <Text>{h.name}</Text>
                  </Pressable>
                ))}
              </>
            ) : null}
          </View>
        )}
        {error ? <Text style={styles.danger} testID="error">{error}</Text> : null}
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, justifyContent: 'center', paddingHorizontal: 24, gap: 12 },
  column: { gap: 12 },
  title: { fontSize: 24, fontWeight: '600' },
  muted: { color: '#666' },
  mono: { fontFamily: 'monospace' },
  code: { fontSize: 30, fontFamily: 'monospace' },
  primary: { borderRadius: 8, backgroundColor: '#111', paddingVertical: 12, alignItems: 'center' },
  primaryText: { color: '#fff', fontSize: 16 },
  outline: { borderRadius: 8, borderWidth: 1, borderColor: '#ccc', paddingVertical: 12, paddingHorizontal: 16 },
  plain: { paddingVertical: 12, alignItems: 'center' },
  danger: { color: '#c00' },
});
