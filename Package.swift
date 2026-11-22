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
                    url: "https://github.com/jt-wang/tailpocket/releases/download/v0.3.5/TailPocketMobile.xcframework.zip",
                    checksum: "f08a4f8db7bcf317fc4c392c23a96eb7c06fffe558297e64aad8bd2c094ccb18")

let package = Package(
    name: "TailPocket",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [
        .library(name: "TailPocket", targets: ["TailPocket"]),
        .library(name: "TailPocketUI", targets: ["TailPocketUI"]),
    ],
    targets: [
        mobile,
        .target(name: "TailPocket", dependencies: ["TailPocketMobile"], path: "sdk/apple/Sources/TailPocket",
                linkerSettings: [.linkedFramework("Security"), .linkedFramework("Network"), .linkedLibrary("resolv")]),
        .target(name: "TailPocketUI", dependencies: ["TailPocket"], path: "sdk/apple/Sources/TailPocketUI"),
        .testTarget(name: "TailPocketTests", dependencies: ["TailPocket"], path: "sdk/apple/Tests/TailPocketTests"),
    ]
)
