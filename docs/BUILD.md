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

`./scripts/build-release.sh <version>` builds every release file into `dist/release/` and prints the checksum
`Package.swift` needs.

## Tests

`go test ./...`, `swift test`, `./gradlew test` in `sdk/android`, `npm test` in `sdk/node`, `sdk/js` and
`sdk/react-native`. The `scripts/e2e-*.sh` scripts pair the examples with a real host on an Android emulator or the iOS
Simulator.
