#!/bin/sh
# Builds every file a GitHub release attaches, into dist/release/, so people can use TailPocket without
# Go, gomobile or a checkout. Needs what the other build scripts need (Go, Xcode, the Android SDK).
# Usage: scripts/build-release.sh <version>   (for example 0.2.0; Package.swift must already name it)
# TAILPOCKET_RELEASE_REPO (default jt-wang/tailpocket) is where the release's files are downloaded from.
set -eu
cd "$(dirname "$0")/.."
version="${1:?usage: scripts/build-release.sh <version>}"
: "${JAVA_HOME:=/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
export JAVA_HOME ANDROID_HOME
out=dist/release
rm -rf "$out" && mkdir -p "$out"
# Start from empty output folders, so files left by earlier builds never reach a release.
rm -rf sdk/node/bin build
tmp=$(mktemp -d) && trap 'rm -rf "$tmp"' EXIT

./scripts/build-host.sh
./scripts/build-mobile.sh apple
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
(cd build/apple && ditto -c -k --norsrc --noextattr --noacl --keepParent TailPocketMobile.xcframework "$OLDPWD/$out/TailPocketMobile.xcframework.zip")

# Android: a Maven repository folder with tailpocket-mobile, tailpocket and tailpocket-ui.
(cd build/android && ditto -c -k --norsrc --noextattr --noacl --keepParent m2 "$OLDPWD/$out/tailpocket-android-m2.zip")

(cd "$out" && shasum -a 256 * > SHA256SUMS)
echo "Package.swift checksum: $(swift package compute-checksum "$out/TailPocketMobile.xcframework.zip")"
ls -l "$out"
