#!/bin/sh
# End to end on the iOS Simulator: start the Node example host, hand its invite to an XCTest that
# runs in the simulator, which pairs over Tailcat and fetches /hello.txt through the tunnel.
# Needs scripts/build-host.sh and scripts/build-mobile.sh apple first.
set -eu
cd "$(dirname "$0")/.."
DEVICE="${TAILPOCKET_SIMULATOR:-iPhone 15}"
# By id: a name alone makes xcodebuild want that device on the newest iOS runtime.
udid=$(xcrun simctl list devices available | grep -F "    $DEVICE (" | head -1 | sed 's/.*(\([0-9A-F-]*\)).*/\1/')
[ -n "$udid" ] || { echo "no simulator named $DEVICE"; exit 1; }
log=$(mktemp); blog=$(mktemp)
TAILPOCKET_STATE=$(mktemp) TAILPOCKET_NAME="e2e host" node examples/node-host/server.mjs >"$log" 2>&1 &
host=$!
TAILPOCKET_STATE=$(mktemp) TAILPOCKET_NAME="e2e bridge host" node examples/node-host/server.mjs >"$blog" 2>&1 &
bhost=$!
trap 'kill $host $bhost 2>/dev/null; rm -f "$log" "$blog"' EXIT
for _ in $(seq 1 60); do grep -q '^QR ' "$log" && grep -q '^QR ' "$blog" && break; sleep 1; done
qr=$(sed -n 's/^QR //p' "$log"); bqr=$(sed -n 's/^QR //p' "$blog")
[ -n "$qr" ] && [ -n "$bqr" ] || { echo "host did not print an invite"; cat "$log" "$blog"; exit 1; }
TEST_RUNNER_TAILPOCKET_INVITE="$qr" TEST_RUNNER_TAILPOCKET_BRIDGE_INVITE="$bqr" xcodebuild test -scheme TailPocket-Package -destination "id=$udid" \
  -only-testing:TailPocketTests/SimulatorLiveTests -only-testing:TailPocketTests/UnitTests -quiet
grep -q '^PAIRED iOS Simulator' "$log" && grep -q '^PAIRED iOS bridge' "$blog" && echo "PASS: both hosts saw the simulator pair"
