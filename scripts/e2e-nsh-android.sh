#!/bin/sh
# End to end for NSH on Android: the example NSH app (examples/nsh-phone) runs in an NshView with
# TailPocketNsh attached, on an emulator (AVD $TAILPOCKET_AVD, default boop-35), pairs
# with the Node example host over Tailcat and shows the computer's /hello.txt.
# Needs nsh, scripts/build-host.sh and scripts/build-mobile.sh android first.
set -eu
cd "$(dirname "$0")/.."
: "${JAVA_HOME:=/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
export JAVA_HOME ANDROID_HOME
adb="$ANDROID_HOME/platform-tools/adb"
AVD="${TAILPOCKET_AVD:-boop-35}" # the emulator this script starts when none runs on PORT
PORT="${TAILPOCKET_EMULATOR_PORT:-5600}"
export ANDROID_SERIAL="emulator-$PORT"

pid=""
cleanup() { [ -n "$pid" ] && kill "$pid" 2>/dev/null; [ -n "${emu:-}" ] && "$adb" -s "$ANDROID_SERIAL" emu kill >/dev/null 2>&1 && wait "$emu" || true; }
trap cleanup EXIT

# An emulator that is still shutting down (an earlier run's) shows as offline: wait for it to go.
while "$adb" devices | grep -q "^$ANDROID_SERIAL[[:space:]]offline"; do sleep 1; done
if "$adb" devices | grep -q "^$ANDROID_SERIAL[[:space:]]device"; then
  # Reuse a running emulator only if it is $AVD: another one on this port may be someone else's.
  running=$("$adb" -s "$ANDROID_SERIAL" emu avd name 2>/dev/null | head -1 | tr -d '\r')
  if [ "$running" != "$AVD" ]; then
    echo "$(basename "$0"): $ANDROID_SERIAL runs AVD '${running:-unknown}', not $AVD; set TAILPOCKET_AVD or TAILPOCKET_EMULATOR_PORT" >&2
    exit 1
  fi
else
  if ! "$ANDROID_HOME/emulator/emulator" -list-avds | grep -Fxq -- "$AVD"; then
    echo "$(basename "$0"): no Android AVD named $AVD; set TAILPOCKET_AVD to one of: $("$ANDROID_HOME/emulator/emulator" -list-avds | tr '\n' ' ')" >&2
    exit 1
  fi
  "$ANDROID_HOME/emulator/emulator" -avd "$AVD" -port "$PORT" -no-window -no-audio -no-boot-anim -no-snapshot-save >/dev/null 2>&1 &
  emu=$!
  "$adb" -s "$ANDROID_SERIAL" wait-for-device
  until [ "$("$adb" -s "$ANDROID_SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do sleep 2; done
fi

rm -rf build/nsh-android-assets
(cd examples/nsh-phone && nsh build -o ../../build/nsh-android-assets/nsh-phone >/dev/null)
log=$(mktemp)
TAILPOCKET_STATE=$(mktemp) TAILPOCKET_NAME="nsh android host" node examples/node-host/server.mjs >"$log" 2>&1 &
pid=$!
for _ in $(seq 1 60); do grep -q '^QR ' "$log" && break; sleep 1; done
qr=$(sed -n 's/^QR //p' "$log")
[ -n "$qr" ] || { echo "the host printed no invite; its log, invite lines removed:"; { grep -v -E '^(QR|QR2) ' "$log" || true; }; exit 1; }

(cd sdk/android && ./gradlew --offline -q :tailpocket-nsh:assembleDebugAndroidTest)
"$adb" install -r -t sdk/android/tailpocket-nsh/build/outputs/apk/androidTest/debug/tailpocket-nsh-debug-androidTest.apk >/dev/null
result=$("$adb" shell am instrument -w -e tailPocketNshInvite "$qr" io.jingtao.tailpocket.nsh.test/androidx.test.runner.AndroidJUnitRunner)
echo "$result" | tail -3
echo "$result" | grep -q '^OK (1 test)' || { echo "FAIL: instrumented test"; echo "$result" | head -40; echo "host log, invite lines removed:"; { grep -v -E '^(QR|QR2) ' "$log" || true; }; exit 1; }
grep -q '^PAIRED NSH phone$' "$log" && echo "PASS: the computer saw the NSH app pair"
