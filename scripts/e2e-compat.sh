#!/bin/sh
# The last release's tailpocket-host and tailpocket-phone against this tree's: downloads them for this
# machine's platform (checked against the release's SHA256SUMS), builds this tree's, and runs
# TestCompatReleasedBinaries (e2e/compat_test.go) for this host with the released phone, the released
# host with this phone, and this tree with itself. Needs internet for the download only; no Tailcat.
#   scripts/e2e-compat.sh          (the latest release; TAILPOCKET_COMPAT_VERSION=X.Y.Z for another)
set -eu
cd "$(dirname "$0")/.."
repo="${TAILPOCKET_RELEASE_REPO:-jt-wang/tailpocket}"
GOTOOLCHAIN=$(awk '$1 == "toolchain" {print $2}' go.mod)
export GOTOOLCHAIN
version="${TAILPOCKET_COMPAT_VERSION:-}"
if [ -z "$version" ]; then
  version=$(curl -fsSL "https://api.github.com/repos/$repo/releases/latest" |
    node -e 'let s = ""; process.stdin.on("data", d => s += d).on("end", () => console.log(JSON.parse(s).tag_name.replace(/^v/, "")))')
fi
platform="$(go env GOOS)-$(go env GOARCH)"
ext=""; [ "$(go env GOOS)" = windows ] && ext=.exe
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
mkdir "$dir/released" "$dir/tree"
url="https://github.com/$repo/releases/download/v$version"
curl -fsSL "$url/SHA256SUMS" -o "$dir/released/SHA256SUMS"
for n in host phone; do
  f="tailpocket-$n-$platform$ext"
  curl -fsSL "$url/$f" -o "$dir/released/$n"
  want=$(awk -v f="$f" 'substr($0, 67) == f {print $1}' "$dir/released/SHA256SUMS")
  got=$(shasum -a 256 "$dir/released/$n" | awk '{print $1}')
  [ -n "$want" ] && [ "$want" = "$got" ] || { echo "v$version $f does not match its SHA256SUMS"; exit 1; }
  chmod +x "$dir/released/$n"
  CGO_ENABLED=0 go build -trimpath -buildvcs=false -tags ts_omit_ssh -o "$dir/tree/$n" "./cmd/tailpocket-$n"
done
go test -c -o "$dir/e2e.test" ./e2e
status=0
for pair in "tree released" "released tree" "tree tree"; do
  set -- $pair
  echo "== host from $1, phone from $2 (released: v$version)"
  TAILPOCKET_COMPAT_HOST="$dir/$1/host" TAILPOCKET_COMPAT_PHONE="$dir/$2/phone" \
    "$dir/e2e.test" -test.count=1 -test.run '^TestCompatReleasedBinaries$' -test.v > "$dir/log" 2>&1 && rc=0 || rc=$?
  # Pairing invites never reach the log (it is pasted into issues and threads).
  grep -vE 'QR2?|tailpocket[12]:' "$dir/log" | grep -E '^(---|ok|FAIL|PASS)|_test.go|error' || true
  # Only an exit 0 with the test itself passing counts: no match, a skip or a failure all fail.
  if [ "$rc" -ne 0 ] || ! grep -q '^--- PASS: TestCompatReleasedBinaries ' "$dir/log"; then
    echo "FAIL: host from $1, phone from $2 (exit $rc)"; status=1
  fi
done
[ "$status" = 0 ] && echo "PASS: v$version and this tree work together both ways" || { echo "FAIL"; exit 1; }
