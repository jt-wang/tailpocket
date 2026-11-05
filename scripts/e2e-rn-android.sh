#!/bin/sh
# End to end for React Native on Android: the example app (examples/rn-phone, a release build with
# the JavaScript bundled in) opens a pairing deep link on this project's own emulator (AVD tailpocket_e2e,
# never another one), pairs with the Node example host over Tailcat and shows the computer's
# /hello.txt. Needs scripts/build-host.sh, scripts/build-mobile.sh android, ./gradlew publish in
# sdk/android, and npm install in examples/rn-phone first.
set -eu
cd "$(dirname "$0")/.."
: "${JAVA_HOME:=/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
export JAVA_HOME ANDROID_HOME
adb="$ANDROID_HOME/platform-tools/adb"
PORT="${TAILPOCKET_EMULATOR_PORT:-5600}"
export ANDROID_SERIAL="emulator-$PORT"
APP=io.jingtao.tailpocket.rnphone

pid=""
cleanup() { [ -n "$pid" ] && kill "$pid" 2>/dev/null; [ -n "${emu:-}" ] && "$adb" -s "$ANDROID_SERIAL" emu kill >/dev/null 2>&1 && wait "$emu" || true; }
trap cleanup EXIT

# An emulator that is still shutting down (an earlier run's) shows as offline: wait for it to go.
while "$adb" devices | grep -q "^$ANDROID_SERIAL[[:space:]]offline"; do sleep 1; done
if ! "$adb" devices | grep -q "^$ANDROID_SERIAL[[:space:]]device"; then
  "$ANDROID_HOME/emulator/emulator" -avd tailpocket_e2e -port "$PORT" -no-window -no-audio -no-boot-anim -no-snapshot-save >/dev/null 2>&1 &
  emu=$!
  "$adb" -s "$ANDROID_SERIAL" wait-for-device
  until [ "$("$adb" -s "$ANDROID_SERIAL" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do sleep 2; done
fi

(cd examples/rn-phone/android && ./gradlew -q assembleRelease)
"$adb" uninstall "$APP" >/dev/null 2>&1 || true
"$adb" install examples/rn-phone/android/app/build/outputs/apk/release/app-release.apk >/dev/null

log=$(mktemp)
TAILPOCKET_STATE=$(mktemp) TAILPOCKET_NAME="rn android host" node examples/node-host/server.mjs >"$log" 2>&1 &
pid=$!
for _ in $(seq 1 60); do grep -q '^QR ' "$log" && break; sleep 1; done
qr=$(sed -n 's/^QR //p' "$log")
[ -n "$qr" ] || { echo "host did not print an invite"; cat "$log"; exit 1; }

# The invite is base64url after "tailpocket1:", so it needs no escaping in the link.
"$adb" shell am start -W -a android.intent.action.VIEW -d "tailpocketdemo://pair?invite=$qr" "$APP" >/dev/null

screen=""
for _ in $(seq 1 60); do
  screen=$("$adb" exec-out uiautomator dump /dev/tty 2>/dev/null || true)
  echo "$screen" | grep -q 'hello from the computer' && break
  echo "$screen" | grep -q 'resource-id="error"' && break
  # A freshly booted emulator can show "System UI isn't responding" over the app: tap Wait.
  wait_button=$(echo "$screen" | grep -o 'text="Wait"[^>]*bounds="[^"]*"' | sed 's/.*bounds="\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]"/\1 \2 \3 \4/' | awk '{print int(($1+$3)/2), int(($2+$4)/2)}')
  [ -n "$wait_button" ] && "$adb" shell input tap $wait_button
  sleep 2
done
if ! echo "$screen" | grep -q 'hello from the computer'; then
  echo "FAIL: the app did not show the computer's answer"
  echo "$screen" | grep -o 'text="[^"]*"' | grep -v 'text=""'
  echo "host:"; cat "$log"
  "$adb" logcat -d -s ReactNativeJS:V AndroidRuntime:E | tail -30
  exit 1
fi
echo "PASS: the RN app showed hello from the computer"
grep -q '^PAIRED RN phone$' "$log" && echo "PASS: the computer saw the RN app pair"
