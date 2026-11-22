#!/bin/sh
# Builds the phone SDK's native libraries with gomobile (built from this module, not installed):
#   apple   → build/apple/TailPocketMobile.xcframework   (iOS 15+, simulator, macOS)
#   android → build/android/tailpocket-mobile.aar          (API 26+)
# Usage: scripts/build-mobile.sh [apple] [android]
set -eu
cd "$(dirname "$0")/.."
mkdir -p .dev/bin build/apple build/android
go build -o .dev/bin/gomobile golang.org/x/mobile/cmd/gomobile
go build -o .dev/bin/gobind golang.org/x/mobile/cmd/gobind
PATH="$PWD/.dev/bin:$PATH"
flags='-trimpath -ldflags=-s -w'
# gomobile records the module's directory in the libraries' build info (-trimpath does not remove
# it), so build through a fixed path that names no user or machine.
real=$(pwd -P)
ln -sfn "$real" /tmp/tailpocket-src
trap 'rm -f /tmp/tailpocket-src' EXIT
cd /tmp/tailpocket-src
# Fails when a built library still names this machine's checkout path.
check_paths() {
  dir=$(mktemp -d)
  for f in "$@"; do
    case "$f" in *.aar) unzip -q -o "$f" -d "$dir/$(basename "$f")" ;; *) cp "$f" "$dir/" ;; esac
  done
  if find "$dir" -type f -exec strings -a {} + | grep -qF -e "$real" -e "$HOME/"; then
    rm -rf "$dir"; echo "a built library contains this machine's paths"; exit 1
  fi
  rm -rf "$dir"
}
for target in ${*:-apple android}; do
  case "$target" in
  apple)
    rm -rf build/apple/TailPocketMobile.xcframework
    gomobile bind -target=ios,iossimulator,macos -iosversion=15 -macosversion=13 -trimpath -ldflags="-s -w" -tags ts_omit_ssh \
      -o build/apple/TailPocketMobile.xcframework ./connectmobile
    check_paths $(find build/apple/TailPocketMobile.xcframework -type f -path '*TailPocketMobile.framework*' -name TailPocketMobile)
    ./scripts/check-min-os.sh build/apple/TailPocketMobile.xcframework
    ;;
  android)
    : "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
    export ANDROID_HOME
    gomobile bind -target=android -androidapi 26 -javapkg io.jingtao.tailpocket -trimpath -ldflags="-s -w" -tags ts_omit_ssh \
      -o build/android/tailpocket-mobile.aar ./connectmobile
    check_paths build/android/tailpocket-mobile.aar
    # A local Maven repository, so the Android library modules can depend on it like any artifact.
    m2=build/android/m2/io/jingtao/tailpocket/tailpocket-mobile/0.3.4
    mkdir -p "$m2"
    cp build/android/tailpocket-mobile.aar "$m2/tailpocket-mobile-0.3.4.aar"
    printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' \
      '<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>' \
      '<groupId>io.jingtao.tailpocket</groupId><artifactId>tailpocket-mobile</artifactId><version>0.3.4</version>' \
      '<packaging>aar</packaging></project>' > "$m2/tailpocket-mobile-0.3.4.pom"
    ;;
  esac
  echo "built $target"
done
