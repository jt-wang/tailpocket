# Build TailPocket yourself

The [releases](https://github.com/jt-wang/tailpocket/releases) carry every package ready-built. Build from source to
change TailPocket itself or to check a release. You need Go 1.27, Node 20 or newer, Xcode for the Apple framework and
the Android SDK for the Android libraries.

```sh
git clone https://github.com/jt-wang/tailpocket && cd tailpocket
./scripts/build-host.sh               # computer helper → sdk/node/bin/, test phone → build/
./scripts/build-mobile.sh apple       # → build/apple/TailPocketMobile.xcframework
./scripts/build-mobile.sh android     # → build/android/tailpocket-mobile.aar and the Maven repository build/android/m2
(cd sdk/android && ./gradlew publish) # → the Kotlin libraries into build/android/m2
```

With `build/apple/TailPocketMobile.xcframework` present, `Package.swift` uses it instead of the release's download.
Packages can then be used from the checkout: `npm install <checkout>/sdk/node`, a local Swift package, or
`maven { url = uri("<checkout>/build/android/m2") }`. A React Native app linked to the checkout needs Metro to watch
`sdk/react-native` and `sdk/js` (see `examples/rn-phone/metro.config.js`).

A release is built in two steps: `./scripts/build-release.sh framework <version>` builds
`dist/framework/TailPocketMobile.xcframework.zip` and prints the checksum `Package.swift` needs. Put it and the
release URL in `Package.swift` and commit; then `./scripts/build-release.sh <version>`, with a clean tree, builds
every other release file into `dist/release/` from that commit.

## Check a release

The Go programs (`tailpocket-host-*`, `tailpocket-phone-*`, `tailpocket-relay-*`) rebuild byte for byte from the
release's tag, since v0.3.5. They are built with `-trimpath` and `-buildvcs=false`, so they record no path and no
commit, only the source; a clone of the tag and a source download give the same files. The build scripts use the Go
toolchain `go.mod` names (`toolchain` line, go1.27.4), also when another Go is installed. With Node 20 or newer,
set `version` to a published release that includes the updated verifier (v0.4.0 or later):

```sh
git clone --branch "v$version" https://github.com/jt-wang/tailpocket && cd tailpocket
./scripts/build-release.sh verify "$version"
```

For older tags, use the updated script in the tag's checkout; the verifier shipped with v0.3.6 only checks
the rebuilt files.

It downloads the release's `SHA256SUMS`, rebuilds those files into `dist/verify/` and says `same` or `DIFFERENT` for
each. `go version -m <file>` shows what a program was built with.

The npm packages that carry them (`tailpocket-node.tgz`, `tailpocket-client.tgz`) hold the same tar, but the gzip
around it depends on the zlib Node was built with: Node from nodejs.org bundles its own, Node from Homebrew or a Linux
distribution may use the system's, and the same tar then compresses to other bytes. So `verify` downloads both
packages, checks them against `SHA256SUMS`, and compares the unzipped tar (`same … (tar)`). Releases are packed with
Node from nodejs.org since v0.3.6; v0.3.5's were packed with Homebrew's (system zlib 1.2.12), so with another Node
only the unzipped tar matches.

The Android library `tailpocket-mobile.aar` (the Go code, built by gomobile) also rebuilds byte for byte, with the
Android SDK and the same NDK the release used: NDK 27.2.12479018 (clang 18.0.3; `sdkmanager "ndk;27.2.12479018"`).
Another NDK builds other `.so` files. `strings -a libgojni.so | grep 'clang version'` shows which built one. `./scripts/build-mobile.sh android` gives `build/android/tailpocket-mobile.aar`; compare
it with `io/jingtao/tailpocket/tailpocket-mobile/<version>/tailpocket-mobile-<version>.aar` inside
`tailpocket-android-m2.zip`. The m2 zip as a whole differs from build to build: Gradle writes the publish time into
each `maven-metadata.xml` (and its checksum files), and the zip records file times. The AARs and POMs in it, the
Kotlin libraries' included, were the same in two builds of v0.3.6. The Apple framework (`TailPocketMobile.xcframework.zip`) is not reproducible either.
Its Info.plist carries a build timestamp, and each of its 3 binaries (iOS, iOS Simulator, macOS) differs in 24
bytes per architecture: the static library's symbol table records when it was written, and so does the header of the
`go.o` member inside it. Their sha256 is in `SHA256SUMS`, and `Package.swift` pins the framework's
checksum. Building a release requires exactly three framework binaries, one each for iOS, iOS Simulator and
macOS, and the Go version named by `go.mod` in every Go program and mobile binary. `verify` checks both downloaded
mobile archives against `SHA256SUMS`, then checks the framework slices and the Go version of each framework
binary and AAR `.so`, without rebuilding them.
v0.3.3 to v0.3.5 shipped phone libraries built with go1.27.1. Releases
before v0.3.5 recorded this repository's private commit (`vcs.revision`) and cannot be rebuilt from the public tag
byte for byte.

## Tests

`sh scripts/build-release-test.sh` checks the release guards with deliberately broken mobile archives, and that the release step refuses a
Package.swift whose URL or checksum does not match the framework zip, without building artifacts or downloading a
release.

`go test ./...`, `swift test`, `./gradlew test` in `sdk/android`, `npm test` in `sdk/node`, `sdk/js` and
`sdk/react-native`. The `scripts/e2e-*.sh` scripts pair the examples with a real host on an Android emulator or the iOS
Simulator.
