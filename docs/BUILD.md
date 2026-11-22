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

The Go programs (`tailpocket-host-*`, `tailpocket-phone-*`, `tailpocket-relay-*`) and the npm packages that carry
them (`tailpocket-node.tgz`, `tailpocket-client.tgz`) rebuild byte for byte from the release's tag, since v0.3.5.
They are built with `-trimpath` and `-buildvcs=false`, so they record no path and no commit, only the source; a
clone of the tag and a source download give the same files. With Go 1.27.4 and Node 20 or newer:

```sh
git clone --branch v0.3.5 https://github.com/jt-wang/tailpocket && cd tailpocket
GOTOOLCHAIN=go1.27.4 ./scripts/build-release.sh verify 0.3.5
```

It downloads the release's `SHA256SUMS`, rebuilds those files into `dist/verify/` and says `same` or `DIFFERENT` for
each. `go version -m <file>` shows what a program was built with. The Apple framework
(`TailPocketMobile.xcframework.zip`) and the Android libraries (`tailpocket-android-m2.zip`) are not reproducible
this way: gomobile, the C toolchains and Gradle record build times and paths (the framework's Info.plist carries a
build timestamp). Their sha256 is in `SHA256SUMS`, and `Package.swift` pins the framework's checksum. Releases
before v0.3.5 recorded this repository's private commit (`vcs.revision`) and cannot be rebuilt from the public tag
byte for byte.

## Tests

`go test ./...`, `swift test`, `./gradlew test` in `sdk/android`, `npm test` in `sdk/node`, `sdk/js` and
`sdk/react-native`. The `scripts/e2e-*.sh` scripts pair the examples with a real host on an Android emulator or the iOS
Simulator.
