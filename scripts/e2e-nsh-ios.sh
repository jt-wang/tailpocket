#!/bin/sh
# End to end for NSH on the iOS Simulator: the example NSH app (examples/nsh-phone) runs in an
# NshAppView with TailPocketNsh attached, pairs with the Node example host over Tailcat and
# shows the computer's /hello.txt. Needs nsh, scripts/build-host.sh and scripts/build-mobile.sh apple.
set -eu
cd "$(dirname "$0")/.."
DEVICE="${TAILPOCKET_SIMULATOR:-iPhone 15}"
# By id: a name alone makes xcodebuild want that device on the newest iOS runtime.
udid=$(xcrun simctl list devices available | grep -F "    $DEVICE (" | head -1 | sed 's/.*(\([0-9A-F-]*\)).*/\1/')
[ -n "$udid" ] || { echo "no simulator named $DEVICE"; exit 1; }
NATIVE_SHELL="${NSH_IOS_XCFRAMEWORK:-$HOME/.nsh/embed/ios/NativeShell.xcframework}"
[ -e sdk/apple/NSH/NativeShell.xcframework ] || ln -s "$NATIVE_SHELL" sdk/apple/NSH/NativeShell.xcframework
(cd examples/nsh-phone && nsh build -o ../../build/nsh-phone >/dev/null)
log=$(mktemp)
TAILPOCKET_STATE=$(mktemp) TAILPOCKET_NAME="nsh e2e host" node examples/node-host/server.mjs >"$log" 2>&1 &
host=$!
trap 'kill $host 2>/dev/null; rm -f "$log"' EXIT
for _ in $(seq 1 60); do grep -q '^QR ' "$log" && break; sleep 1; done
qr=$(sed -n 's/^QR //p' "$log")
[ -n "$qr" ] || { echo "the host printed no invite; its log, invite lines removed:"; { grep -v -E '^(QR|QR2) ' "$log" || true; }; exit 1; }
cd sdk/apple/NSH
TEST_RUNNER_TAILPOCKET_NSH_INVITE="$qr" TEST_RUNNER_TAILPOCKET_NSH_BUNDLE="$PWD/../../../build/nsh-phone/bundle.js" \
  xcodebuild test -scheme TailPocketNSH -destination "id=$udid" -quiet
cd ../../..
grep -q '^PAIRED NSH phone' "$log" && echo "PASS: the computer saw the NSH app pair"
