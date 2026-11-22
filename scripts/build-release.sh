#!/bin/sh
# Builds every file a GitHub release attaches, into dist/release/, so people can use TailPocket without
# Go, gomobile or a checkout. Needs what the other build scripts need (Go, Xcode, the Android SDK).
# Two steps, because Package.swift holds the framework zip's checksum and the Go programs record the
# commit they are built from (vcs.revision):
#   scripts/build-release.sh framework <version>   builds dist/framework/TailPocketMobile.xcframework.zip
#                                                  and prints its checksum (the framework records no commit)
#   (put that checksum and the vX.Y.Z URL in Package.swift, commit: this is the commit to tag)
#   scripts/build-release.sh <version>             builds the rest from that commit, with a clean tree, and
#                                                  checks every Go program records exactly HEAD
# TAILPOCKET_RELEASE_REPO (default jt-wang/tailpocket) is where the release's files are downloaded from.
set -eu
cd "$(dirname "$0")/.."
usage="usage: scripts/build-release.sh [framework] <version>"
: "${JAVA_HOME:=/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
export JAVA_HOME ANDROID_HOME
fw=dist/framework/TailPocketMobile.xcframework.zip

if [ "${1:-}" = framework ]; then
  version="${2:?$usage}"
  rm -rf dist/framework build/apple && mkdir -p dist/framework
  ./scripts/build-mobile.sh apple
  (cd build/apple && ditto -c -k --norsrc --noextattr --noacl --keepParent TailPocketMobile.xcframework "$OLDPWD/$fw")
  echo "Package.swift checksum: $(swift package compute-checksum "$fw")"
  echo "next: put it and releases/download/v$version in Package.swift, commit, then scripts/build-release.sh $version"
  exit 0
fi
version="${1:?$usage}"

# The commit the binaries record must be the one that is tagged: nothing left to amend.
if [ -n "$(git status --porcelain)" ]; then
  git status --short; echo "the tree has changes: commit everything first (the binaries record HEAD)"; exit 1
fi
[ -f "$fw" ] || { echo "no $fw: run scripts/build-release.sh framework $version first"; exit 1; }
sum=$(swift package compute-checksum "$fw")
grep -q "releases/download/v$version/TailPocketMobile.xcframework.zip" Package.swift &&
  grep -q "checksum: \"$sum\"" Package.swift ||
  { echo "Package.swift does not name v$version with checksum $sum"; exit 1; }
head=$(git rev-parse HEAD)

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

# Every Go program must record HEAD, unmodified, so the tag alone rebuilds them byte for byte.
for f in "$out"/tailpocket-host-* "$out"/tailpocket-phone-* "$out"/tailpocket-relay-*; do
  info=$(go version -m "$f")
  echo "$info" | grep -q "vcs.revision=$head" && echo "$info" | grep -q "vcs.modified=false" ||
    { echo "$f does not record $head unmodified"; exit 1; }
done
[ -z "$(git status --porcelain)" ] || { echo "the build changed tracked files"; exit 1; }

(cd "$out" && shasum -a 256 * > SHA256SUMS)
echo "Package.swift checksum: $sum"
echo "binaries record $head: tag this commit"
ls -l "$out"
