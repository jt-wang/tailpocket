#!/bin/sh
# End to end on an Android emulator of this project's own (AVD tailpocket_e2e, never another one):
#   1. QR path: the Node example host prints an invite; the instrumented test pairs and fetches.
#   1b. The same through TailPocketBridge, the function table NSH and React Native forward to.
#   2. Same-Wi-Fi path: a second host advertises over Bonjour and auto-approves; the script finds its
#      port with dns-sd (the emulator's NAT hides Bonjour) and the test pairs through it.
# Needs scripts/build-host.sh and scripts/build-mobile.sh android first.
set -eu
cd "$(dirname "$0")/.."
: "${JAVA_HOME:=/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
export JAVA_HOME ANDROID_HOME
adb="$ANDROID_HOME/platform-tools/adb"
PORT="${TAILPOCKET_EMULATOR_PORT:-5600}"
export ANDROID_SERIAL="emulator-$PORT" # gradle installs only on this device

pids=""
cleanup() { for p in $pids; do kill "$p" 2>/dev/null || true; done; [ -n "${emu:-}" ] && "$adb" -s "$ANDROID_SERIAL" emu kill >/dev/null 2>&1 && wait "$emu" || true; }
trap cleanup EXIT

# An emulator that is still shutting down (an earlier run's) shows as offline: wait for it to go.
while "$adb" devices | grep -q "^$ANDROID_SERIAL[[:space:]]offline"; do sleep 1; done
if ! "$adb" devices | grep -q "^$ANDROID_SERIAL[[:space:]]device"; then
  "$ANDROID_HOME/emulator/emulator" -avd tailpocket_e2e -port "$PORT" -no-window -no-audio -no-boot-anim -no-snapshot-save >/dev/null 2>&1 &
  emu=$!
  "$adb" -s "$ANDROID_SERIAL" wait-for-device
  until [ "$("$adb" -s "$ANDROID_SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do sleep 2; done
fi

start_host() { # $1 log, rest: env
  log="$1"; shift
  env "$@" TAILPOCKET_STATE="$(mktemp)" node examples/node-host/server.mjs >"$log" 2>&1 &
  pids="$pids $!"
  for _ in $(seq 1 60); do grep -q '^QR ' "$log" && return 0; sleep 1; done
  cat "$log"; return 1
}

qrlog=$(mktemp); start_host "$qrlog" TAILPOCKET_NAME="e2e qr host"
qr=$(sed -n 's/^QR //p' "$qrlog")

bridgelog=$(mktemp); start_host "$bridgelog" TAILPOCKET_NAME="e2e bridge host"
bridgeqr=$(sed -n 's/^QR //p' "$bridgelog")

name="tailPocket e2e android $(date +%H%M%S)"
wifilog=$(mktemp); start_host "$wifilog" TAILPOCKET_NAME="$name" TAILPOCKET_SERVICE=_tcce2e._tcp TAILPOCKET_AUTO_APPROVE=1
port=""
for _ in $(seq 1 20); do
  port=$( (/usr/bin/dns-sd -L "$name" _tcce2e._tcp local & p=$!; sleep 2; kill $p) 2>/dev/null | sed -n 's/.*can be reached at [^:]*:\([0-9]*\) .*/\1/p' | head -1)
  [ -n "$port" ] && break
done
ip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1)
[ -n "$port" ] || { echo "Bonjour service not found"; exit 1; }

# Build the self-instrumenting test APK and run it with am instrument (no Gradle device runner needed).
(cd sdk/android && ./gradlew --offline -q :tailpocket:assembleDebugAndroidTest)
"$adb" install -r -t sdk/android/tailpocket/build/outputs/apk/androidTest/debug/tailpocket-debug-androidTest.apk >/dev/null
result=$("$adb" shell am instrument -w -e tailPocketInvite "$qr" -e tailPocketLocal "$ip:$port" -e tailPocketBridgeInvite "$bridgeqr" \
  io.jingtao.tailpocket.test/androidx.test.runner.AndroidJUnitRunner)
echo "$result" | tail -4
echo "$result" | grep -q '^OK (4 tests)' || { echo "FAIL: instrumented tests"; echo "$result" | head -40; exit 1; }
grep -q '^PAIRED Android emulator$' "$qrlog" && grep -q '^PAIRED Android emulator (Wi-Fi)$' "$wifilog" &&
  grep -q '^PAIRED Android bridge$' "$bridgelog" && echo "PASS: every host saw the emulator pair"
