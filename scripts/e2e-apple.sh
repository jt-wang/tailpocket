#!/bin/sh
# End to end on the iOS Simulator: start the Node example host, hand its invite to an XCTest that
# runs in the simulator, which pairs over Tailcat and fetches /hello.txt through the tunnel. A third
# host registers with a local tailpocket-relay; the simulator pairs and fetches over it alone.
# Needs scripts/build-host.sh and scripts/build-mobile.sh apple first.
set -eu
cd "$(dirname "$0")/.."
DEVICE="${TAILPOCKET_SIMULATOR:-iPhone 15}"
# By id: a name alone makes xcodebuild want that device on the newest iOS runtime.
udid=$(xcrun simctl list devices available | grep -F "    $DEVICE (" | head -1 | sed 's/.*(\([0-9A-F-]*\)).*/\1/')
[ -n "$udid" ] || { echo "no simulator named $DEVICE"; exit 1; }
log=$(mktemp); blog=$(mktemp); rlog=$(mktemp)
case "$(uname -m)" in arm64) arch=arm64 ;; *) arch=amd64 ;; esac
relay_port=$((40000 + $$ % 10000)); relay_token="relay-token-for-the-e2e-$$"
TAILPOCKET_RELAY_TOKEN="$relay_token" "build/tailpocket-relay-darwin-$arch" --listen "127.0.0.1:$relay_port" --public-host 127.0.0.1 >/dev/null 2>&1 &
relay=$!
TAILPOCKET_STATE=$(mktemp) TAILPOCKET_NAME="e2e relay host" TAILPOCKET_AUTO_APPROVE=1 TAILPOCKET_RELAY_URL="ws://127.0.0.1:$relay_port" TAILPOCKET_RELAY_TOKEN="$relay_token" \
  node examples/node-host/server.mjs >"$rlog" 2>&1 &
rhost=$!
TAILPOCKET_STATE=$(mktemp) TAILPOCKET_NAME="e2e host" node examples/node-host/server.mjs >"$log" 2>&1 &
host=$!
TAILPOCKET_STATE=$(mktemp) TAILPOCKET_NAME="e2e bridge host" node examples/node-host/server.mjs >"$blog" 2>&1 &
bhost=$!
trap 'kill $host $bhost $rhost $relay 2>/dev/null; rm -f "$log" "$blog" "$rlog"' EXIT
for _ in $(seq 1 60); do grep -q '^QR ' "$log" && grep -q '^QR ' "$blog" && grep -q '^QR2 ' "$rlog" && break; sleep 1; done
qr=$(sed -n 's/^QR //p' "$log"); bqr=$(sed -n 's/^QR //p' "$blog"); rqr=$(sed -n 's/^QR2 //p' "$rlog")
# An invite pairs a phone with that host: name the host that printed none, and show only its log, without
# any invite line (CI logs are public).
missing=""
[ -n "$qr" ] || missing="$missing e2e-host:$log"
[ -n "$bqr" ] || missing="$missing e2e-bridge-host:$blog"
[ -n "$rqr" ] || missing="$missing e2e-relay-host:$rlog"
if [ -n "$missing" ]; then
  for m in $missing; do
    echo "${m%%:*} printed no invite; its log, invite lines removed:"
    grep -v -E '^(QR|QR2) ' "${m#*:}" || true
  done
  exit 1
fi
TEST_RUNNER_TAILPOCKET_INVITE="$qr" TEST_RUNNER_TAILPOCKET_BRIDGE_INVITE="$bqr" TEST_RUNNER_TAILPOCKET_RELAY_INVITE="$rqr" xcodebuild test -scheme TailPocket-Package -destination "id=$udid" \
  -only-testing:TailPocketTests/SimulatorLiveTests -only-testing:TailPocketTests/UnitTests -quiet
grep -q '^PAIRED iOS Simulator' "$log" && grep -q '^PAIRED iOS bridge' "$blog" && grep -q '^PAIRED iOS relay' "$rlog" && echo "PASS: all three hosts saw the simulator pair"
