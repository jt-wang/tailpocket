#!/bin/sh
# Smoke test of the three apps built on TailPocket against this checkout: each app's
# committed HEAD is copied to a temporary directory (their checkouts are not touched), pointed at this
# tree instead of its released TailPocket, built, and its own TailPocket tests run.
#   Herdr: companion (connecthost, connectinvite, connectphone, connectsecure): go build, vet, tests
#          of internal/tailcat and cmd/herdr-anywhere.
#   DSH:   tailcat module (connecthost, connectlocal, connectmobile, connectrelay): go build, vet,
#          tests of host and mobile.
#   Boop:  vendor/tailpocket replaced by sdk/node and a helper built here; test/pocket.test.ts (a fake
#          host), then Boop's own Pocket on the real helper over the local network only (no internet):
#          two phones pair through emoji windows and reach Boop; removing one device turns that phone
#          away as revoked while the other still gets through.
# Isolated: only each app's committed files, a fresh Go module cache (go.sum-checked downloads), and no
# node_modules (Boop's pocket tests import only node: modules; one that needs a package fails here).
# A step that fails means this tree breaks that app: fix TailPocket, or tell the app's thread what
# changed before releasing.
# Usage: scripts/smoke-downstream.sh [herdr|dsh|boop ...]   (default: all three)
# Checkouts: HERDR_DIR, DSH_DIR, BOOP_DIR (default: siblings herdr-anywhere, dsh-anywhere, boop, the public
# repositories, as CI checks them out). Point them at other checkouts to test those instead.
set -eu
cd "$(dirname "$0")/.."
tp=$(pwd)
parent=$(dirname "$tp")
: "${HERDR_DIR:=$parent/herdr-anywhere}" "${DSH_DIR:=$parent/dsh-anywhere}" "${BOOP_DIR:=$parent/boop}"
tmp=$(mktemp -d)
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf "$tmp"' EXIT
GOTOOLCHAIN=$(awk '$1 == "toolchain" {print $2}' go.mod)
export GOTOOLCHAIN GOFLAGS="-mod=mod -modcacherw" GOMODCACHE="$tmp/gomod" GOWORK=off

copy() { # copy <checkout> <dir>: the checkout's HEAD, without its uncommitted changes
  git -C "$1" rev-parse --verify -q HEAD >/dev/null || { echo "no git checkout at $1 (set ${3}_DIR)" >&2; exit 1; }
  mkdir -p "$2" && git -C "$1" archive HEAD | tar -x -C "$2"
  echo "== $3 at $(git -C "$1" rev-parse --short HEAD)"
}

gomod() { # gomod <module dir> <packages to test...>
  dir=$1; shift
  (cd "$dir" && go mod edit -replace "github.com/jt-wang/tailpocket=$tp" && go mod tidy >/dev/null &&
    go build ./... && go vet ./... && go test -count=1 "$@")
}

for app in ${*:-herdr dsh boop}; do
  case $app in
    herdr) copy "$HERDR_DIR" "$tmp/herdr" HERDR; gomod "$tmp/herdr/companion" ./internal/tailcat ./cmd/herdr-anywhere ;;
    dsh) copy "$DSH_DIR" "$tmp/dsh" DSH; gomod "$tmp/dsh/tailcat" ./host ./mobile ;;
    boop)
      copy "$BOOP_DIR" "$tmp/boop" BOOP
      plat=$(go env GOOS)-$(go env GOARCH)
      ./scripts/build-host.sh "$plat" >/dev/null
      rm -rf "$tmp/boop/vendor/tailpocket/bin" && mkdir "$tmp/boop/vendor/tailpocket/bin"
      cp sdk/node/index.js sdk/node/index.d.ts "$tmp/boop/vendor/tailpocket/"
      cp "sdk/node/bin/tailpocket-host-$plat" "$tmp/boop/vendor/tailpocket/bin/"
      cp scripts/smoke-boop.ts "$tmp/boop/test/"
      (cd "$tmp/boop" && node --test test/pocket.test.ts &&
        TAILPOCKET_PHONE="$tp/build/tailpocket-phone-$plat" TMPDIR="$tmp" node --test test/smoke-boop.ts) ;;
    *) echo "unknown app $app: herdr, dsh or boop" >&2; exit 2 ;;
  esac
  echo "PASS: $app"
done
