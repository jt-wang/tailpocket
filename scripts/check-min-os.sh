#!/bin/sh
# Fails when any object in the framework needs a newer OS than Package.swift promises. Without
# -macosversion, gomobile's C objects take the build Mac's own macOS as their minimum (seen 2026-11-04:
# 27.0 next to the Go objects' 13.0), and apps targeting older macOS warn at link time.
# Usage: scripts/check-min-os.sh <TailPocketMobile.xcframework>
set -eu
fw="${1:?usage: scripts/check-min-os.sh <TailPocketMobile.xcframework>}"
ios=15.0 macos=13.0
status=0
for bin in $(find "$fw" -type f -path '*TailPocketMobile.framework*' -name TailPocketMobile); do
  case "$bin" in *macos*) want=$macos ;; *) want=$ios ;; esac
  worst=$(otool -l "$bin" | awk '/LC_BUILD_VERSION/{f=1} f&&$1=="minos"{print $2; f=0}' | sort -t. -k1,1n -k2,2n | tail -1)
  if [ "$(printf '%s\n%s\n' "$want" "$worst" | sort -t. -k1,1n -k2,2n | tail -1)" != "$want" ]; then
    echo "check-min-os: $bin needs $worst, more than $want" >&2
    status=1
  fi
done
exit $status
