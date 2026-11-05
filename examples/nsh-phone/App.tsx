// A phone app in NSH that pairs with a computer by QR code or over the same Wi-Fi, then talks to it
// through the tunnel. Run the computer side with examples/node-host (TAILPOCKET_SERVICE=_tailpocket-demo._tcp).
import { host, mount, signal, Text, View } from "nsh";
import { tailPocket, TailPocketError, type TailPocketConnection, type TailPocketHostLink, type TailPocketNearbyHost } from "../../sdk/js/nsh.ts";

const SERVICE = "_tailpocket-demo._tcp";
const DEVICE = "NSH phone";

const MESSAGES: Record<string, string> = {
  expired: "This QR code has expired. Make a new one on the computer.",
  "invalid-invite": "That QR code is not a pairing code.",
  unreachable: "The computer did not answer. Check that it is running.",
  denied: "The computer said no.",
  unsupported: "This device has no camera scanner.",
};
const explain = (e: unknown) => (e instanceof TailPocketError ? MESSAGES[e.code] ?? `Pairing failed (${e.code}).` : String(e));

function App() {
  const link = signal<TailPocketHostLink | null>(null);
  const answer = signal("");
  const error = signal("");
  const busy = signal(false);
  const nearby = signal<TailPocketNearbyHost[]>([]);
  const code = signal("");
  let connection: TailPocketConnection | null = null;
  let stopNearby: (() => Promise<void>) | null = null;

  const open = async (l: TailPocketHostLink) => {
    link.set(l);
    await stopNearby?.();
    stopNearby = null;
    connection = await tailPocket.connect();
    const res = await fetch(connection.baseUrl + "/hello.txt");
    answer.set(await res.text());
  };
  const attempt = async (work: () => Promise<TailPocketHostLink>) => {
    if (busy()) return;
    busy.set(true);
    error.set("");
    try {
      await open(await work());
    } catch (e) {
      if (!(e instanceof TailPocketError && e.code === "cancelled")) error.set(explain(e));
    } finally {
      busy.set(false);
      code.set("");
    }
  };
  const scan = () => attempt(async () => tailPocket.pair(await tailPocket.scan(), { device: DEVICE, save: true }));
  const pairNearby = (name: string) =>
    attempt(async () => {
      const pending = await tailPocket.pairNearby({ name, device: DEVICE });
      code.set(pending.code);
      return tailPocket.pair(await pending.finish(), { device: DEVICE, save: true });
    });
  const browse = async () => {
    try {
      stopNearby = await tailPocket.nearby(SERVICE, (hosts) => nearby.set(hosts));
    } catch {
      // No Bonjour on this device: the QR code still works.
    }
  };
  const forget = async () => {
    await connection?.close();
    connection = null;
    await tailPocket.store.deleteLink();
    link.set(null);
    answer.set("");
    await browse();
  };

  (async () => {
    // An invite the embedding app hands over, e.g. from a deep link (host.params.invite).
    const invite = (host.params as { invite?: unknown })?.invite;
    if (typeof invite === "string" && invite) return attempt(() => tailPocket.pair(invite, { device: DEVICE, save: true }));
    const saved = await tailPocket.store.link().catch(() => null);
    if (saved) await open(saved).catch((e) => error.set(explain(e)));
    else await browse();
  })();

  return (
    <View class="flex-1 bg-background px-6 pt-[env(safe-area-inset-top)] justify-center gap-3">
      <If when={link()} else={
        <View class="gap-3">
          <Text class="text-foreground text-2xl font-semibold">Pair with your computer</Text>
          <View role="button" testID="scan" onPress={scan} class="rounded-(--radius) bg-primary py-3 items-center active:opacity-80">
            <Text class="text-primary-foreground text-base">{busy() && !code() ? "Pairing…" : "Scan QR code"}</Text>
          </View>
          <If when={code()}>
            <Text class="text-muted-foreground">Check that the computer shows</Text>
            <Text class="text-foreground text-3xl font-mono">{code()}</Text>
          </If>
          <If when={nearby().length > 0 && !code()}>
            <Text class="text-muted-foreground">On this Wi-Fi</Text>
            <Each of={nearby()} key={(h) => h.name}>
              {(h) => (
                <View role="button" onPress={() => pairNearby(h().name)} class="rounded-(--radius) border border-border py-3 px-4 active:opacity-60">
                  <Text class="text-foreground">{h().name}</Text>
                </View>
              )}
            </Each>
          </If>
        </View>
      }>
        {(l) => (
          <View class="gap-3">
            <Text class="text-muted-foreground">Connected to</Text>
            <Text class="text-foreground text-2xl font-semibold">{l().name}</Text>
            <Text class="text-foreground font-mono">{answer()}</Text>
            <View role="button" testID="forget" onPress={forget} class="py-3 items-center active:opacity-60">
              <Text class="text-destructive">Forget this computer</Text>
            </View>
          </View>
        )}
      </If>
      <If when={error()}><Text testID="error" class="text-destructive">{error()}</Text></If>
    </View>
  );
}

mount(App);
