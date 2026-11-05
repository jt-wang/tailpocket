#!/bin/sh
# Builds tailpocket-host (and the phone CLI) for every desktop platform into sdk/node/bin/.
# Usage: scripts/build-host.sh [goos-goarch ...]   (default: all five)
set -eu
cd "$(dirname "$0")/.."
targets="${*:-darwin-arm64 darwin-amd64 linux-amd64 linux-arm64 windows-amd64}"
mkdir -p sdk/node/bin build
for t in $targets; do
  os="${t%-*}"; arch="${t#*-}"; ext=""
  [ "$os" = windows ] && ext=".exe"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w" -tags ts_omit_ssh \
    -o "sdk/node/bin/tailpocket-host-$t$ext" ./cmd/tailpocket-host
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags="-s -w" -tags ts_omit_ssh \
    -o "build/tailpocket-phone-$t$ext" ./cmd/tailpocket-phone
  echo "built $t"
done
