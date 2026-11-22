#!/bin/sh
# Builds tailpocket-host (and the phone CLI and tailpocket-relay, into build/) for every desktop platform into sdk/node/bin/.
# Usage: scripts/build-host.sh [goos-goarch ...]   (default: all five)
set -eu
cd "$(dirname "$0")/.."
targets="${*:-darwin-arm64 darwin-amd64 linux-amd64 linux-arm64 windows-amd64}"
mkdir -p sdk/node/bin build
for t in $targets; do
  os="${t%-*}"; arch="${t#*-}"; ext=""
  [ "$os" = windows ] && ext=".exe"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags="-s -w" -tags ts_omit_ssh \
    -o "sdk/node/bin/tailpocket-host-$t$ext" ./cmd/tailpocket-host
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags="-s -w" -tags ts_omit_ssh \
    -o "build/tailpocket-phone-$t$ext" ./cmd/tailpocket-phone
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags="-s -w" \
    -o "build/tailpocket-relay-$t$ext" ./cmd/tailpocket-relay
  echo "built $t"
done
