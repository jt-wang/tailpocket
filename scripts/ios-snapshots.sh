#!/bin/sh
# The iOS pairing screen's screenshot baselines (PairingScreenshotTests), on the simulator they were recorded
# with: iPhone 15 on iOS 17.0 unless TAILPOCKET_SNAPSHOT_SIMULATOR and TAILPOCKET_SNAPSHOT_IOS say otherwise.
# Another iOS version has no baselines and fails. TAILPOCKET_RECORD_SNAPSHOTS=1 records them instead.
# Shuts the simulator down afterwards if it booted it.
set -eu
cd "$(dirname "$0")/.."
DEVICE="${TAILPOCKET_SNAPSHOT_SIMULATOR:-iPhone 15}"
IOS="${TAILPOCKET_SNAPSHOT_IOS:-17.0}"
udid=$(xcrun simctl list devices available | awk -v os="-- iOS $IOS --" -v dev="    $DEVICE (" '
  /^-- / { here = ($0 == os); next }
  here && index($0, dev) == 1 && match($0, /[0-9A-F]{8}-[0-9A-F-]{27}/) { print substr($0, RSTART, RLENGTH); exit }')
if [ -z "$udid" ]; then
  echo "no simulator \"$DEVICE\" on iOS $IOS; available:" >&2
  xcrun simctl list devices available | grep -E '^--|iPhone' >&2
  exit 1
fi
was_booted=$(xcrun simctl list devices | grep -F "($udid) (Booted)" || true)
[ -n "$was_booted" ] || trap 'xcrun simctl shutdown "$udid" 2>/dev/null || true' EXIT
TEST_RUNNER_TAILPOCKET_RECORD_SNAPSHOTS="${TAILPOCKET_RECORD_SNAPSHOTS:-}" xcodebuild test -scheme TailPocket-Package \
  -destination "id=$udid" -only-testing:TailPocketUITests/PairingScreenshotTests -collect-test-diagnostics never -quiet
