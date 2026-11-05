#!/bin/sh
# End to end for React Native on the iOS Simulator: the example app (examples/rn-phone, a Release
# build with the JavaScript bundled in) starts with an invite, pairs with the Node example host over
# Tailcat and shows the computer's /hello.txt, read off a screenshot. Needs scripts/build-host.sh,
# scripts/build-mobile.sh apple, npm install and bundle exec pod install (in examples/rn-phone).
set -eu
cd "$(dirname "$0")/.."
DEVICE="${TAILPOCKET_SIMULATOR:-iPhone 15}"
APP=io.jingtao.tailpocket.rnphone
out=$(mktemp -d)

# By id: a name alone makes xcodebuild want that device on the newest iOS runtime.
udid=$(xcrun simctl list devices available | grep -F "    $DEVICE (" | head -1 | sed 's/.*(\([0-9A-F-]*\)).*/\1/')
[ -n "$udid" ] || { echo "no simulator named $DEVICE"; exit 1; }
booted=""
if ! xcrun simctl list devices booted | grep -q "$udid"; then xcrun simctl boot "$udid"; booted=1; fi
host=""
cleanup() { [ -n "$host" ] && kill "$host" 2>/dev/null; [ -n "$booted" ] && xcrun simctl shutdown "$udid"; rm -rf "$out"; }
trap cleanup EXIT

xcodebuild -workspace examples/rn-phone/ios/RnPhone.xcworkspace -scheme RnPhone -configuration Release \
  -destination "id=$udid" -derivedDataPath build/rn-phone-ios -quiet build
xcrun simctl uninstall "$udid" "$APP" 2>/dev/null || true
xcrun simctl install "$udid" build/rn-phone-ios/Build/Products/Release-iphonesimulator/RnPhone.app

log="$out/host.log"
TAILPOCKET_STATE="$out/state.json" TAILPOCKET_NAME="rn ios host" node examples/node-host/server.mjs >"$log" 2>&1 &
host=$!
for _ in $(seq 1 60); do grep -q '^QR ' "$log" && break; sleep 1; done
qr=$(sed -n 's/^QR //p' "$log")
[ -n "$qr" ] || { echo "host did not print an invite"; cat "$log"; exit 1; }

# A launch argument, not the pairing link: the simulator asks before it opens a link.
xcrun simctl launch "$udid" "$APP" -tailPocketInvite "$qr" >/dev/null

text=""
for _ in $(seq 1 60); do
  # simctl waits forever if the simulator shuts down under it; give each screenshot 30 s.
  perl -e 'alarm 30; exec @ARGV' xcrun simctl io "$udid" screenshot "$out/screen.png" >/dev/null 2>&1 || true
  text=$(swift scripts/screen-text.swift "$out/screen.png" 2>/dev/null || true)
  echo "$text" | grep -q 'hello from the computer' && break
  sleep 2
done
if ! echo "$text" | grep -q 'hello from the computer'; then
  echo "FAIL: the app did not show the computer's answer. On screen:"; echo "$text"
  echo "host:"; cat "$log"
  exit 1
fi
echo "PASS: the RN app showed hello from the computer"
grep -q '^PAIRED RN phone$' "$log" && echo "PASS: the computer saw the RN app pair"
