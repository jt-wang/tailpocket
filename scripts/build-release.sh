#!/bin/sh
# Builds every file a GitHub release attaches, into dist/release/, so people can use TailPocket without
# Go, gomobile or a checkout. Needs what the other build scripts need (Go, Xcode, the Android SDK).
# Two steps, because Package.swift holds the framework zip's checksum:
#   scripts/build-release.sh framework <version>   builds dist/framework/TailPocketMobile.xcframework.zip
#                                                  and prints its checksum
#   (put that checksum and the vX.Y.Z URL in Package.swift, commit: this is the commit to tag)
#   scripts/build-release.sh <version>             builds the rest from that commit, with a clean tree
# The Go programs are built without VCS stamping (scripts/build-host.sh, -buildvcs=false) and with -trimpath,
# so they depend only on the source files: anyone can rebuild them, and the npm packages that carry them,
# byte for byte from the public tag, a clone or a source download alike:
#   scripts/build-release.sh verify <version>      rebuilds those and compares them with the release's SHA256SUMS
# The Apple framework and the Android libraries are not reproducible this way (gomobile, the C toolchains
# and Gradle stamp times and paths); their sha256 is in SHA256SUMS and Package.swift.
# Every Go program and every native phone library (the framework's binaries, the AAR's .so files) must be
# built with the toolchain go.mod names, or the build fails. The npm packages are packed with Node from
# nodejs.org (it ships its own zlib): Node built against the system's zlib, as Homebrew's is, gzips the
# same tar differently, so verify compares the packages' tar, unzipped.
# TAILPOCKET_RELEASE_REPO (default jt-wang/tailpocket) is where the release's files are downloaded from.
set -eu
cd "$(dirname "$0")/.."
usage="usage: scripts/build-release.sh [framework] <version>"
: "${JAVA_HOME:=/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
export JAVA_HOME ANDROID_HOME
fw=dist/framework/TailPocketMobile.xcframework.zip
gover=$(awk '$1 == "toolchain" {print $2}' go.mod)

# go_versions <file>: the Go versions a library names, one per line. A Go executable or .so has build
# info; the framework's binaries are static archives, so read the version strings the runtime carries.
go_versions() {
  go version "$1" 2>/dev/null | awk '{print $NF}' | grep '^go1' ||
    strings -a "$1" | grep -oE 'go1\.[0-9]+\.[0-9]+' | sort -u
}
# check_go <file>...: fails unless each names exactly the toolchain go.mod names.
check_go() {
  for f in "$@"; do
    got=$(go_versions "$f" | sort -u | tr '\n' ' ')
    [ "$got" = "$gover " ] || { echo "$f is built with ${got:-no Go version}, go.mod says $gover"; exit 1; }
  done
}
# check_framework <zip>, check_aar <aar>: the same for every binary inside.
check_framework() {
  d=$(mktemp -d); unzip -q "$1" -d "$d"
  check_go $(find "$d" -type f -path '*TailPocketMobile.framework*' -name TailPocketMobile)
  echo "$(find "$d" -type f -path '*TailPocketMobile.framework*' -name TailPocketMobile | wc -l | tr -d ' ') framework binaries built with $gover"
  rm -rf "$d"
}
check_aar() {
  d=$(mktemp -d); unzip -q "$1" -d "$d"
  check_go "$d"/jni/*/*.so
  echo "$(ls "$d"/jni/*/*.so | wc -l | tr -d ' ') .so files built with $gover"
  rm -rf "$d"
}
# official_node: npm packs with the node on PATH; it must be nodejs.org's (bundled zlib).
official_node() {
  [ "$(node -p 'process.config.variables.node_shared_zlib')" = false ] ||
    { echo "$(command -v node) uses the system's zlib: put Node from nodejs.org first on PATH"; exit 1; }
}

if [ "${1:-}" = framework ]; then
  version="${2:?$usage}"
  rm -rf dist/framework build/apple && mkdir -p dist/framework
  ./scripts/build-mobile.sh apple
  (cd build/apple && ditto -c -k --norsrc --noextattr --noacl --keepParent TailPocketMobile.xcframework "$OLDPWD/$fw")
  check_framework "$fw"
  echo "Package.swift checksum: $(swift package compute-checksum "$fw")"
  echo "next: put it and releases/download/v$version in Package.swift, commit, then scripts/build-release.sh $version"
  exit 0
fi
if [ "${1:-}" = verify ]; then
  version="${2:?$usage}"
  repo="${TAILPOCKET_RELEASE_REPO:-jt-wang/tailpocket}"
  rm -rf dist/verify sdk/node/bin build && mkdir -p dist/verify
  curl -fsSL "https://github.com/$repo/releases/download/v$version/SHA256SUMS" -o dist/verify/SHA256SUMS.release
  ./scripts/build-host.sh
  cp sdk/node/bin/tailpocket-host-* build/tailpocket-phone-* build/tailpocket-relay-* dist/verify/
  (cd sdk/node && npm pack --silent --pack-destination "$OLDPWD/dist/verify") >/dev/null
  (cd sdk/js && npm pack --silent --pack-destination "$OLDPWD/dist/verify") >/dev/null
  mv "dist/verify/tailpocket-$version.tgz" dist/verify/tailpocket-node.tgz
  mv "dist/verify/tailpocket-client-$version.tgz" dist/verify/tailpocket-client.tgz
  cd dist/verify
  n=0
  for f in tailpocket-host-* tailpocket-phone-* tailpocket-relay-*; do
    want=$(awk -v f="$f" '$2 == f {print $1}' SHA256SUMS.release)
    got=$(shasum -a 256 "$f" | awk '{print $1}')
    if [ "$want" = "$got" ]; then echo "same      $f"; else echo "DIFFERENT $f"; n=$((n + 1)); fi
  done
  # npm packages: the release's file must match SHA256SUMS, then its tar (unzipped) the rebuilt one's,
  # since another zlib compresses the same tar differently.
  for f in tailpocket-node.tgz tailpocket-client.tgz; do
    curl -fsSL "https://github.com/$repo/releases/download/v$version/$f" -o "$f.release"
    want=$(awk -v f="$f" '$2 == f {print $1}' SHA256SUMS.release)
    [ "$(shasum -a 256 "$f.release" | awk '{print $1}')" = "$want" ] || { echo "$f from the release does not match SHA256SUMS"; exit 1; }
    if [ "$(gzip -dc "$f.release" | shasum -a 256)" = "$(gzip -dc "$f" | shasum -a 256)" ]; then
      echo "same      $f (tar)"
    else echo "DIFFERENT $f (tar)"; n=$((n + 1)); fi
  done
  [ "$n" = 0 ] && echo "every rebuilt file matches v$version" || { echo "$n files differ"; exit 1; }
  exit 0
fi
version="${1:?$usage}"

# The release is built from the commit that is tagged: nothing left to amend.
if [ -n "$(git status --porcelain)" ]; then
  git status --short; echo "the tree has changes: commit everything first (this is the commit to tag)"; exit 1
fi
[ -f "$fw" ] || { echo "no $fw: run scripts/build-release.sh framework $version first"; exit 1; }
sum=$(swift package compute-checksum "$fw")
grep -q "releases/download/v$version/TailPocketMobile.xcframework.zip" Package.swift &&
  grep -q "checksum: \"$sum\"" Package.swift ||
  { echo "Package.swift does not name v$version with checksum $sum"; exit 1; }
head=$(git rev-parse HEAD)
official_node
check_framework "$fw"

out=dist/release
rm -rf "$out" && mkdir -p "$out"
# Start from empty output folders, so files left by earlier builds never reach a release.
rm -rf sdk/node/bin build
tmp=$(mktemp -d) && trap 'rm -rf "$tmp"' EXIT

./scripts/build-host.sh
./scripts/build-mobile.sh android
(cd sdk/android && ./gradlew -q publish)

# The computer helper, the test phone and tailpocket-relay, one file per platform.
cp sdk/node/bin/tailpocket-host-* build/tailpocket-phone-* build/tailpocket-relay-* "$out/"

# npm packages, installable by URL. React Native's points its client dependency at this release's file.
(cd sdk/node && npm pack --silent --pack-destination "$tmp") >/dev/null
(cd sdk/js && npm pack --silent --pack-destination "$tmp") >/dev/null
mv "$tmp/tailpocket-$version.tgz" "$out/tailpocket-node.tgz"
mv "$tmp/tailpocket-client-$version.tgz" "$out/tailpocket-client.tgz"
mkdir "$tmp/rn" && cp -R sdk/react-native/package.json sdk/react-native/TailPocketReactNative.podspec \
  sdk/react-native/src sdk/react-native/ios sdk/react-native/android "$tmp/rn/"
rm -rf "$tmp/rn/android/build"
node -e '
  const f = process.argv[1], p = JSON.parse(require("fs").readFileSync(f, "utf8"));
  p.dependencies["tailpocket-client"] = `https://github.com/${process.argv[3]}/releases/download/v${process.argv[2]}/tailpocket-client.tgz`;
  require("fs").writeFileSync(f, JSON.stringify(p, null, 2) + "\n");' "$tmp/rn/package.json" "$version" "${TAILPOCKET_RELEASE_REPO:-jt-wang/tailpocket}"
(cd "$tmp/rn" && npm pack --silent --pack-destination "$tmp") >/dev/null
mv "$tmp/react-native-tailpocket-$version.tgz" "$out/react-native-tailpocket.tgz"

# Swift: the binary target Package.swift downloads when there is no local build/apple framework.
cp "$fw" "$out/"

# Android: a Maven repository folder with tailpocket-mobile, tailpocket and tailpocket-ui.
(cd build/android && ditto -c -k --norsrc --noextattr --noacl --keepParent m2 "$OLDPWD/$out/tailpocket-android-m2.zip")
check_aar build/android/tailpocket-mobile.aar

# No Go program may record a commit: then a build from the public tag, whose commit differs from this
# repository's, gives the same bytes.
for f in "$out"/tailpocket-host-* "$out"/tailpocket-phone-* "$out"/tailpocket-relay-*; do
  ! go version -m "$f" | grep -q "vcs\." || { echo "$f records VCS information"; exit 1; }
done
check_go "$out"/tailpocket-host-* "$out"/tailpocket-phone-* "$out"/tailpocket-relay-*
[ -z "$(git status --porcelain)" ] || { echo "the build changed tracked files"; exit 1; }

(cd "$out" && shasum -a 256 * > SHA256SUMS)
echo "Package.swift checksum: $sum"
echo "built from $head: tag this commit"
ls -l "$out"
