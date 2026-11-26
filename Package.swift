// swift-tools-version:5.10
import Foundation
import PackageDescription

// The Go library as a binary target: this release's prebuilt framework, or your own build when
// scripts/build-mobile.sh apple has put one in build/apple/.
let localFramework = "build/apple/TailPocketMobile.xcframework"
let haveLocal = FileManager.default.fileExists(atPath: Context.packageDirectory + "/" + localFramework)
let mobile: Target = haveLocal
    ? .binaryTarget(name: "TailPocketMobile", path: localFramework)
    : .binaryTarget(name: "TailPocketMobile",
                    url: "https://github.com/jt-wang/tailpocket/releases/download/v0.4.0/TailPocketMobile.xcframework.zip",
                    checksum: "a4d4acb44c723ebb928de8d7516821d13d96e69aad4f9a846a6a28870628322b")

let package = Package(
    name: "TailPocket",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [
        .library(name: "TailPocket", targets: ["TailPocket"]),
        .library(name: "TailPocketUI", targets: ["TailPocketUI"]),
        // Opens push notes in a Notification Service Extension, without the Go framework (docs/PUSH.md §3).
        .library(name: "TailPocketPush", targets: ["TailPocketPush"]),
    ],
    targets: [
        mobile,
        .target(name: "TailPocketPush", path: "sdk/apple/Sources/TailPocketPush", linkerSettings: [.linkedFramework("Security")]),
        .target(name: "TailPocket", dependencies: ["TailPocketMobile", "TailPocketPush"], path: "sdk/apple/Sources/TailPocket",
                linkerSettings: [.linkedFramework("Security"), .linkedFramework("Network"), .linkedLibrary("resolv")]),
        .target(name: "TailPocketUI", dependencies: ["TailPocket"], path: "sdk/apple/Sources/TailPocketUI"),
        .testTarget(name: "TailPocketTests", dependencies: ["TailPocket"], path: "sdk/apple/Tests/TailPocketTests"),
        .testTarget(name: "TailPocketUITests", dependencies: ["TailPocketUI"], path: "sdk/apple/Tests/TailPocketUITests"),
        // Reads connectpush/testdata/vectors.json from the checkout.
        .testTarget(name: "TailPocketPushTests", dependencies: ["TailPocketPush"], path: "sdk/apple/Tests/TailPocketPushTests"),
    ]
)
