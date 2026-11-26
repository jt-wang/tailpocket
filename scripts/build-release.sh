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
#   scripts/build-release.sh verify <version>      compares rebuilt files with the release and checks its mobile libraries
# The Apple framework and the Android libraries are not reproducible this way (gomobile, the C toolchains
# and Gradle stamp times and paths); their sha256 is in SHA256SUMS and Package.swift.
# Every Go program and every native phone library (the framework's binaries, the AAR's .so files) must be
# built with the toolchain go.mod names, or the build fails. The npm packages are packed with Node from
# nodejs.org (it ships its own zlib): Node built against the system's zlib, as Homebrew's is, gzips the
# same tar differently, so verify compares the packages' tar, unzipped.
# TAILPOCKET_RELEASE_REPO (default jt-wang/tailpocket) is where the release's files are downloaded from.
set -eu
cd "$(dirname "$0")/.."
usage="usage: scripts/build-release.sh [framework|verify] <version> | check-files <dir>"
: "${JAVA_HOME:=/Applications/Android Studio.app/Contents/jbr/Contents/Home}"
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
export JAVA_HOME ANDROID_HOME
fw=dist/framework/TailPocketMobile.xcframework.zip
gover=$(awk '$1 == "toolchain" {print $2}' go.mod)
[ -n "$gover" ] || { echo "go.mod does not name a Go toolchain" >&2; exit 1; }

# go_versions <file>: the Go versions a library names, one per line. A Go executable or .so has build
# info; the framework's binaries are static archives, so read the version strings the runtime carries.
go_versions() {
  go version "$1" 2>/dev/null | awk '{print $NF}' | grep '^go1' ||
    strings -a "$1" | grep -oE 'go1\.[0-9]+\.[0-9]+' | sort -u
}
# check_go <file>...: fails unless each names exactly the toolchain go.mod names.
check_go() {
  for f in "$@"; do
    got=$(go_versions "$f" | sort -u | paste -sd ' ' -)
    [ "$got" = "$gover" ] || { echo "$f is built with ${got:-no Go version}, go.mod says $gover" >&2; exit 1; }
  done
}
# check_framework <zip>, check_aar <aar>: the same for every binary inside.
check_framework() (
  d=$(mktemp -d)
  trap 'rm -rf "$d"' EXIT
  unzip -q "$1" -d "$d/framework"
  find "$d/framework" -type f -path '*/TailPocketMobile.framework/*' -name TailPocketMobile > "$d/binaries"
  count=$(wc -l < "$d/binaries" | tr -d ' ')
  [ "$count" -eq 3 ] || { echo "$1: expected exactly 3 framework binaries, found $count" >&2; exit 1; }
  ios=0 simulator=0 macos=0
  while IFS= read -r f; do
    rel=${f#"$d/framework/TailPocketMobile.xcframework/"}
    case "${rel%%/*}" in
      ios-*-simulator) simulator=$((simulator + 1)) ;;
      ios-*-*) ;; # A different iOS platform variant, not a device slice.
      ios-*) ios=$((ios + 1)) ;;
      macos-*) macos=$((macos + 1)) ;;
    esac
    check_go "$f"
  done < "$d/binaries"
  [ "$ios:$simulator:$macos" = 1:1:1 ] || {
    echo "$1: expected one binary each for iOS, iOS Simulator and macOS; found $ios, $simulator and $macos" >&2
    exit 1
  }
  echo "$count framework binaries built with $gover"
)
check_aar() (
  d=$(mktemp -d)
  trap 'rm -rf "$d"' EXIT
  unzip -q "$1" -d "$d"
  set -- "$d"/jni/*/*.so
  check_go "$@"
  echo "$# .so files built with $gover"
)
# The platforms of the Go programs, and the files every release has: 3 programs per platform, the 3 npm
# packages, the framework zip, the Android Maven zip and SHA256SUMS (21).
platforms="darwin-arm64 darwin-amd64 linux-amd64 linux-arm64 windows-amd64"
expected_assets() {
  for p in $platforms; do
    ext=""; [ "${p%-*}" = windows ] && ext=.exe
    for n in host phone relay; do echo "tailpocket-$n-$p$ext"; done
  done
  printf '%s\n' tailpocket-node.tgz tailpocket-client.tgz react-native-tailpocket.tgz \
    TailPocketMobile.xcframework.zip tailpocket-android-m2.zip SHA256SUMS
}
# check_assets <what>: the file names on stdin must be exactly expected_assets, no more and no fewer.
check_assets() (
  export LC_ALL=C
  d=$(mktemp -d)
  trap 'rm -rf "$d"' EXIT
  expected_assets | sort > "$d/want"
  sort > "$d/got"
  missing=$(comm -23 "$d/want" "$d/got" | paste -sd ' ' -)
  extra=$(comm -13 "$d/want" "$d/got" | paste -sd ' ' -)
  [ -z "$missing$extra" ] || { echo "$1: missing ${missing:-none}; not expected ${extra:-none}" >&2; exit 1; }
  echo "$1: exactly the $(wc -l < "$d/want" | tr -d ' ') release files"
)
# sums_names <SHA256SUMS>: the full file name of each line ("<64 hex>  name"). A line in any other shape
# comes out as "not a checksum line: …", a name check_assets never expects, so the check fails.
sums_names() {
  awk 'length($0) > 66 && substr($0, 1, 64) ~ /^[0-9a-f]+$/ && substr($0, 65, 2) == "  " { print substr($0, 67); next }
    { print "not a checksum line: " $0 }' "$1"
}
# dir_files <dir>: every entry in dir, hidden ones too; anything but a plain file is marked.
dir_files() (
  cd "$1"
  nl='
'
  # A name with a newline would read as two names: it is reported as one entry check_assets never expects.
  find . -mindepth 1 -maxdepth 1 -name "*$nl*" -exec echo "a name with a newline" \;
  find . -mindepth 1 -maxdepth 1 ! -name "*$nl*" -type f | sed 's#^\./##'
  find . -mindepth 1 -maxdepth 1 ! -name "*$nl*" ! -type f | sed 's#^\./#not a file: #'
)
# download_release_file <asset>: keep the downloaded copy separate from any rebuilt file.
download_release_file() {
  curl -fsSL "$release_url/$1" -o "$1.release"
  want=$(awk -v f="$1" 'substr($0, 67) == f {print $1}' SHA256SUMS.release)
  got=$(shasum -a 256 "$1.release")
  [ "${got%% *}" = "$want" ] || { echo "$1 from the release does not match SHA256SUMS" >&2; exit 1; }
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
# check-files <dir>: dir holds exactly the release's files (dist/release, or a release downloaded into an empty dir).
if [ "${1:-}" = check-files ]; then
  dir_files "${2:?usage: scripts/build-release.sh check-files <dir>}" | check_assets "$2"
  exit 0
fi
if [ "${1:-}" = verify ]; then
  version="${2:?$usage}"
  repo="${TAILPOCKET_RELEASE_REPO:-jt-wang/tailpocket}"
  release_url="https://github.com/$repo/releases/download/v$version"
  rm -rf dist/verify sdk/node/bin build && mkdir -p dist/verify
  (
    cd dist/verify
    curl -fsSL "$release_url/SHA256SUMS" -o SHA256SUMS.release
    { sums_names SHA256SUMS.release; echo SHA256SUMS; } | check_assets "SHA256SUMS of v$version"
    # The files on the release itself (public API, no token), so one uploaded but not in SHA256SUMS fails too.
    curl -fsSL "https://api.github.com/repos/$repo/releases/tags/v$version" -o release.json
    node -e 'for (const a of JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).assets) console.log(a.name)' \
      release.json | check_assets "the v$version release"
    download_release_file TailPocketMobile.xcframework.zip
    check_framework TailPocketMobile.xcframework.zip.release
    download_release_file tailpocket-android-m2.zip
    unzip -p tailpocket-android-m2.zip.release \
      "m2/io/jingtao/tailpocket/tailpocket-mobile/$version/tailpocket-mobile-$version.aar" > tailpocket-mobile.aar
    check_aar tailpocket-mobile.aar
  )
  ./scripts/build-host.sh $platforms
  cp sdk/node/bin/tailpocket-host-* build/tailpocket-phone-* build/tailpocket-relay-* dist/verify/
  (cd sdk/node && npm pack --silent --pack-destination "$OLDPWD/dist/verify") >/dev/null
  (cd sdk/js && npm pack --silent --pack-destination "$OLDPWD/dist/verify") >/dev/null
  mv "dist/verify/tailpocket-$version.tgz" dist/verify/tailpocket-node.tgz
  mv "dist/verify/tailpocket-client-$version.tgz" dist/verify/tailpocket-client.tgz
  cd dist/verify
  n=0
  for f in tailpocket-host-* tailpocket-phone-* tailpocket-relay-*; do
    want=$(awk -v f="$f" 'substr($0, 67) == f {print $1}' SHA256SUMS.release)
    got=$(shasum -a 256 "$f" | awk '{print $1}')
    if [ "$want" = "$got" ]; then echo "same      $f"; else echo "DIFFERENT $f"; n=$((n + 1)); fi
  done
  # npm packages: the release's file must match SHA256SUMS, then its tar (unzipped) the rebuilt one's,
  # since another zlib compresses the same tar differently.
  for f in tailpocket-node.tgz tailpocket-client.tgz; do
    download_release_file "$f"
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

./scripts/build-host.sh $platforms
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
dir_files "$out" | check_assets "$out"
echo "Package.swift checksum: $sum"
echo "built from $head: tag this commit"
ls -l "$out"
