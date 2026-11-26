#!/bin/sh
# Exercise verify's mobile checks offline, stopping before the unchanged host rebuild.
set -eu
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
repo="$tmp/test checkout"
assets="$tmp/assets"
export assets
mkdir -p "$repo/scripts" "$assets" "$tmp/bin"
cp scripts/build-release.sh "$repo/scripts/"
cp go.mod "$repo/"
gover=$(awk '$1 == "toolchain" {print $2}' go.mod)
version=0.0.0
framework=TailPocketMobile.xcframework.zip
android=tailpocket-android-m2.zip

cat > "$tmp/bin/curl" <<'EOF'
#!/bin/sh
set -eu
[ "$1" = -fsSL ] && [ "$3" = -o ] || exit 2
cp "$assets/${2##*/}" "$4"
EOF
cat > "$repo/scripts/build-host.sh" <<'EOF'
#!/bin/sh
echo 'Reached the host rebuild'
exit 99
EOF
chmod +x "$tmp/bin/curl" "$repo/scripts/build-host.sh"

make_framework() (
  cd "$assets"
  rm -rf "$framework" TailPocketMobile.xcframework
  mkdir TailPocketMobile.xcframework
  printf '%s\n' 'test fixture' > TailPocketMobile.xcframework/Info.plist
  i=1
  while [ "$i" -le "$1" ]; do
    case "$i" in
      1) slice=ios-arm64 ;;
      2) slice=ios-arm64_x86_64-simulator ;;
      3) slice=${3:-macos-arm64_x86_64} ;;
      *) slice=ios-arm64e ;;
    esac
    dir="TailPocketMobile.xcframework/$slice/TailPocketMobile.framework"
    mkdir -p "$dir"
    printf '%s\n' "$2" > "$dir/TailPocketMobile"
    i=$((i + 1))
  done
  zip -qr "$framework" TailPocketMobile.xcframework
)

make_android() (
  cd "$assets"
  rm -rf "$android" m2 jni
  aar_dir="m2/io/jingtao/tailpocket/tailpocket-mobile/$version"
  mkdir -p "$aar_dir" jni/arm64-v8a jni/x86_64
  printf '%s\n' "$gover" > jni/arm64-v8a/libgojni.so
  printf '%s\n' "$1" > jni/x86_64/libgojni.so
  zip -qr "$aar_dir/tailpocket-mobile-$version.aar" jni
  zip -qr "$android" m2
)

verify() (
  cd "$repo"
  PATH="$tmp/bin:$PATH" sh scripts/build-release.sh verify "$version"
)

expect_verify() {
  status=0
  verify > "$tmp/log" 2>&1 || status=$?
  if [ "$status" -ne "$1" ] || ! grep -Fq "$2" "$tmp/log"; then
    cat "$tmp/log" >&2
    echo "Expected exit $1 and message: $2 (got exit $status)" >&2
    exit 1
  fi
  echo "PASS: $2"
}

# The other release files are placeholders: verify only checks their names. SHA256SUMS lists every file
# but itself; release.json (the GitHub API's view of the release, saved as v$version) lists all 21.
others="tailpocket-node.tgz tailpocket-client.tgz react-native-tailpocket.tgz"
for p in darwin-arm64 darwin-amd64 linux-amd64 linux-arm64 windows-amd64; do
  ext=""; [ "$p" = windows-amd64 ] && ext=.exe
  others="$others tailpocket-host-$p$ext tailpocket-phone-$p$ext tailpocket-relay-$p$ext"
done
for f in $others; do echo placeholder > "$assets/$f"; done
# The GitHub API's JSON for a release, with an asset for each name.
release_json() {
  node -e 'const [v, ...names] = process.argv.slice(1);
    console.log(JSON.stringify({ tag_name: "v" + v, assets: names.map(name => ({ name,
      browser_download_url: `https://github.com/jt-wang/tailpocket/releases/download/v${v}/${name}` })) }, null, 2))' \
    "$version" "$@" > "$assets/v$version"
}
checksums() (
  cd "$assets"
  # shellcheck disable=SC2086
  shasum -a 256 "$framework" "$android" $others > SHA256SUMS
  # shellcheck disable=SC2086
  release_json "$framework" "$android" $others SHA256SUMS
)

make_android "$gover"
for count in 0 2 4; do
  make_framework "$count" "$gover"
  checksums
  expect_verify 1 "expected exactly 3 framework binaries, found $count"
done

make_framework 3 "$gover" ios-arm64e
checksums
expect_verify 1 "expected one binary each for iOS, iOS Simulator and macOS; found 2, 1 and 0"

make_framework 3 go1.0.0
checksums
expect_verify 1 "TailPocketMobile is built with go1.0.0, go.mod says $gover"

make_framework 3 "$gover"
make_android go1.0.0
checksums
expect_verify 1 "libgojni.so is built with go1.0.0, go.mod says $gover"

make_android "$gover"
expect_verify 1 "$android from the release does not match SHA256SUMS"
checksums
expect_verify 99 "Reached the host rebuild"

# Release files: exactly the 21, by name, in SHA256SUMS and on the release.
checksums
sed -i.bak '/tailpocket-relay-linux-arm64/d' "$assets/SHA256SUMS"
expect_verify 1 "SHA256SUMS of v$version: missing tailpocket-relay-linux-arm64; not expected none"
checksums
sed -i.bak 's/tailpocket-host-windows-amd64.exe$/tailpocket-host-windows-amd64/' "$assets/SHA256SUMS"
expect_verify 1 "missing tailpocket-host-windows-amd64.exe; not expected tailpocket-host-windows-amd64"
checksums
(cd "$assets" && shasum -a 256 "$framework" >> SHA256SUMS)
expect_verify 1 "SHA256SUMS of v$version: missing none; not expected TailPocketMobile.xcframework.zip"
checksums
# shellcheck disable=SC2086
(cd "$assets" && release_json "$framework" "$android" $others SHA256SUMS notes.txt)
expect_verify 1 "the v$version release: missing none; not expected notes.txt"
checksums
# shellcheck disable=SC2086
(cd "$assets" && release_json "$framework" $others SHA256SUMS)
expect_verify 1 "the v$version release: missing $android; not expected none"
checksums
# An extra asset whose url is on the line after its key: the names, not the text, are read.
checksums
node -e 'const f = process.argv[1], r = JSON.parse(require("fs").readFileSync(f, "utf8"));
  r.assets.push({ name: "extra.zip", browser_download_url: "x" });
  require("fs").writeFileSync(f, JSON.stringify(r, null, 2).replace(/"browser_download_url": /g, "\"browser_download_url\":\n"))' \
  "$assets/v$version"
expect_verify 1 "the v$version release: missing none; not expected extra.zip"
# A name with a suffix after a space is that whole name, not the name before the space.
checksums
sed -i.bak 's/  tailpocket-node.tgz$/  tailpocket-node.tgz backup/' "$assets/SHA256SUMS"
expect_verify 1 "SHA256SUMS of v$version: missing tailpocket-node.tgz; not expected tailpocket-node.tgz backup"
# A line with the name but no digest is not a checksum line.
checksums
sed -i.bak 's/^[0-9a-f]\{64\}  tailpocket-client.tgz$/tailpocket-client.tgz/' "$assets/SHA256SUMS"
expect_verify 1 "missing tailpocket-client.tgz; not expected not a checksum line: tailpocket-client.tgz"
checksums
expect_verify 99 "the v$version release: exactly the 21 release files"

# check-files: a directory with exactly the 21 passes; a hidden file, a folder or a missing one fails.
dir="$tmp/release dir"
mkdir -p "$dir"
# shellcheck disable=SC2086
(cd "$assets" && cp "$framework" "$android" $others SHA256SUMS "$dir/")
expect_files() {
  status=0
  (cd "$repo" && sh scripts/build-release.sh check-files "$dir") > "$tmp/log" 2>&1 || status=$?
  if [ "$status" -ne "$1" ] || ! grep -Fq "$2" "$tmp/log"; then
    cat "$tmp/log" >&2
    echo "Expected exit $1 and message: $2 (got exit $status)" >&2
    exit 1
  fi
  echo "PASS (files): $2"
}
expect_files 0 "exactly the 21 release files"
touch "$dir/.extra"
expect_files 1 "missing none; not expected .extra"
rm "$dir/.extra"; mkdir "$dir/notes"
expect_files 1 "missing none; not expected not a file: notes"
rmdir "$dir/notes"
# Two expected names joined by a newline into one file name: 20 entries, not 21.
mv "$dir/tailpocket-node.tgz" "$dir/tailpocket-node.tgz
tailpocket-client.tgz"; rm "$dir/tailpocket-client.tgz"
expect_files 1 "missing tailpocket-client.tgz tailpocket-node.tgz; not expected a name with a newline"
rm "$dir/tailpocket-node.tgz
tailpocket-client.tgz"; echo placeholder > "$dir/tailpocket-node.tgz"; echo placeholder > "$dir/tailpocket-client.tgz"
expect_files 0 "exactly the 21 release files"
rm "$dir/SHA256SUMS"
expect_files 1 "missing SHA256SUMS; not expected none"

# The release step (scripts/build-release.sh <version>) refuses a dirty tree, a missing framework zip, and
# a Package.swift that does not name this version's URL and the zip's checksum. A clean checkout of the
# fixture, a stub node (nodejs.org's, bundled zlib) and a stub swift whose compute-checksum is the zip's
# SHA-256, as SwiftPM's is, so this runs on Linux too.
mkdir -p "$tmp/relbin"
cat > "$tmp/relbin/node" <<'STUB'
#!/bin/sh
echo false
STUB
cat > "$tmp/relbin/swift" <<'STUB'
#!/bin/sh
set -eu
[ "$1 $2" = "package compute-checksum" ] || exit 2
shasum -a 256 "$3" | awk '{print $1}'
STUB
chmod +x "$tmp/relbin/node" "$tmp/relbin/swift"
fw="$repo/dist/framework/$framework"
package_swift() {
  printf '%s\n' "url: \"https://github.com/jt-wang/tailpocket/releases/download/v$1/$framework\"," \
    "checksum: \"$2\"" > "$repo/Package.swift"
  git -C "$repo" add -A && git -C "$repo" commit -qm fixture
}
release() (
  cd "$repo"
  PATH="$tmp/relbin:$tmp/bin:$PATH" sh scripts/build-release.sh "$version"
)
expect_release() {
  status=0
  release > "$tmp/log" 2>&1 || status=$?
  if [ "$status" -ne "$1" ] || ! grep -Fq "$2" "$tmp/log"; then
    cat "$tmp/log" >&2
    echo "Expected exit $1 and message: $2 (got exit $status)" >&2
    exit 1
  fi
  echo "PASS (release): $2"
}
git -C "$repo" init -q
git -C "$repo" config user.name test && git -C "$repo" config user.email test@example.com
printf '%s\n' dist/ > "$repo/.gitignore"
mkdir -p "$repo/dist/framework"
make_framework 3 "$gover"
package_swift "$version" "$(shasum -a 256 "$assets/$framework" | awk '{print $1}')"

expect_release 1 "no dist/framework/$framework: run scripts/build-release.sh framework $version first"
cp "$assets/$framework" "$fw"
expect_release 99 "Reached the host rebuild"
printf x >> "$fw"
expect_release 1 "Package.swift does not name v$version with checksum $(shasum -a 256 "$fw" | awk '{print $1}')"
cp "$assets/$framework" "$fw"
package_swift 9.9.9 "$(shasum -a 256 "$fw" | awk '{print $1}')"
expect_release 1 "Package.swift does not name v$version with checksum"
package_swift "$version" "$(shasum -a 256 "$fw" | awk '{print $1}')"
echo dirty >> "$repo/go.mod"
expect_release 1 "the tree has changes: commit everything first"
