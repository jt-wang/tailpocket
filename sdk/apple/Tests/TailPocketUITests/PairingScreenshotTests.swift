#if os(iOS)
import SwiftUI
@testable import TailPocket
@testable import TailPocketUI
import UIKit
import XCTest

/// Screenshot baselines of the pairing screen (PairingContent): light, dark with an error, a small screen with the
/// camera denied, the largest text with a code to confirm, and the keyboard up at large text, scrolled to the end. Compared with
/// Snapshots/iOS-<version>/<name>.png, since each iOS version draws text a little differently; no folder for the
/// running version fails. TEST_RUNNER_TAILPOCKET_RECORD_SNAPSHOTS=1 writes the baselines instead, and a mismatch
/// writes the actual image and a diff next to the baseline, as <name>-actual.png and <name>-diff.png (not kept).
/// Run by scripts/ios-snapshots.sh, on the simulator the baselines were recorded with.
///
/// The keyboard is drawn grey: it lives in a window of its own, out of reach of the test. Its height is given
/// to the screen as a bottom safe area, which is how the system tells a screen about it.
@available(iOS 16.0, *) // PairingContent
@MainActor
final class PairingScreenshotTests: XCTestCase {
    nonisolated static let phone = CGSize(width: 393, height: 852) // iPhone 15
    nonisolated static let small = CGSize(width: 375, height: 667) // iPhone SE
    nonisolated static let keyboard: CGFloat = 336 // the iPhone SE keyboard with its suggestion bar

    static let inputs = PairingModel.Inputs(
        prefix: TailPocket.defaultPrefix,
        pair: { _ in throw TailPocketError(code: "unreachable") },
        beginLocal: { _ in throw TailPocketError(code: "unreachable") },
        onPaired: { _ in })

    func testLight() throws {
        try assertSnapshot("pairing-light", PairingModel(camera: .available))
    }

    func testDarkWithError() throws {
        let m = PairingModel(camera: .available)
        m.status = .failed("That is not a pairing code.")
        m.pasted = "not-a-code"
        try assertSnapshot("pairing-dark", m, style: .dark)
    }

    func testSmallScreenCameraDenied() throws {
        try assertSnapshot("pairing-small", PairingModel(camera: .denied), size: Self.small)
    }

    func testLargestTextConfirmingACode() throws {
        let m = PairingModel(camera: .available)
        m.status = .code("482 913", "Studio Mac")
        m.hosts = [TailPocketNearbyHost(name: "Studio Mac", endpoint: .hostPort(host: "127.0.0.1", port: 1))]
        try assertSnapshot("pairing-large-text", m, nearby: true, text: .accessibility5)
    }

    func testKeyboardOpen() throws {
        let m = PairingModel(camera: .available)
        m.status = .failed("That is not a pairing code.")
        m.pasted = "tailpocket1:EXAMPLE-INVITE"
        // Taller than the space above the keyboard, scrolled to the end: the paste field must end above it.
        try assertSnapshot("pairing-keyboard", m, size: Self.small, text: .accessibility2, keyboard: Self.keyboard)
    }

    // MARK: -

    private func assertSnapshot(_ name: String, _ model: PairingModel, size: CGSize = phone, style: UIUserInterfaceStyle = .light,
                                nearby: Bool = false, text: DynamicTypeSize = .large, keyboard: CGFloat = 0,
                                file: StaticString = #filePath, line: UInt = #line) throws {
        let view = PairingContent(model: model, inputs: Self.inputs, showsNearby: nearby).dynamicTypeSize(text)
        let controller = UIHostingController(rootView: view)
        let window = UIWindow(frame: CGRect(origin: .zero, size: size))
        window.overrideUserInterfaceStyle = style
        window.rootViewController = controller
        controller.additionalSafeAreaInsets.bottom = keyboard
        window.makeKeyAndVisible()
        // Let SwiftUI lay out the List and settle.
        for _ in 0..<5 { RunLoop.main.run(until: Date().addingTimeInterval(0.1)); window.layoutIfNeeded() }
        if keyboard > 0 {
            // As far down as the list goes: where that stops depends on the bottom safe area the keyboard took.
            let list = try XCTUnwrap(Self.scrollView(in: window), "no scroll view in the pairing screen", file: file, line: line)
            list.contentOffset.y = max(-list.adjustedContentInset.top, list.contentSize.height + list.adjustedContentInset.bottom - list.bounds.height)
            for _ in 0..<3 { RunLoop.main.run(until: Date().addingTimeInterval(0.1)); window.layoutIfNeeded() }
        }

        let format = UIGraphicsImageRendererFormat()
        format.scale = 2
        let image = UIGraphicsImageRenderer(size: size, format: format).image { ctx in
            // drawHierarchy draws nothing here: the test's window belongs to no scene.
            window.layer.render(in: ctx.cgContext)
            if keyboard > 0 {
                UIColor.gray.setFill()
                ctx.fill(CGRect(x: 0, y: size.height - keyboard, width: size.width, height: keyboard))
            }
        }
        window.isHidden = true

        let dir = URL(fileURLWithPath: "\(file)").deletingLastPathComponent()
            .appendingPathComponent("Snapshots/iOS-\(UIDevice.current.systemVersion)")
        let baseline = dir.appendingPathComponent("\(name).png")
        if ProcessInfo.processInfo.environment["TAILPOCKET_RECORD_SNAPSHOTS"] == "1" {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try XCTUnwrap(image.pngData()).write(to: baseline)
            return
        }
        guard let expected = UIImage(contentsOfFile: baseline.path) else {
            return XCTFail("no baseline \(baseline.path): run on the simulator the baselines were recorded with (scripts/ios-snapshots.sh), or record them", file: file, line: line)
        }
        if let problem = try Self.compare(expected, image, out: dir.appendingPathComponent(name)) {
            XCTFail("\(name): \(problem) (actual and diff next to the baseline)", file: file, line: line)
        }
    }

    static func scrollView(in view: UIView) -> UIScrollView? {
        if let s = view as? UIScrollView { return s }
        return view.subviews.lazy.compactMap { scrollView(in: $0) }.first
    }

    /// A pixel differs when a channel is more than 16 off; up to 0.02% of the pixels may (anti-aliasing).
    static func compare(_ expected: UIImage, _ actual: UIImage, out: URL) throws -> String? {
        let (a, aw, ah) = try pixels(expected), (b, bw, bh) = try pixels(actual)
        guard aw == bw, ah == bh else {
            try actual.pngData()?.write(to: URL(fileURLWithPath: out.path + "-actual.png"))
            return "size \(bw)x\(bh), baseline \(aw)x\(ah)"
        }
        var diff = [UInt8](repeating: 0, count: a.count)
        var differing = 0
        for i in stride(from: 0, to: a.count, by: 4) {
            let off = (0..<4).contains { abs(Int(a[i + $0]) - Int(b[i + $0])) > 16 }
            if off { differing += 1; diff[i] = 255; diff[i + 3] = 255 } else { diff[i] = a[i] / 4; diff[i + 1] = a[i + 1] / 4; diff[i + 2] = a[i + 2] / 4; diff[i + 3] = 255 }
        }
        let allowed = aw * ah / 5000
        if differing <= allowed { return nil }
        try actual.pngData()?.write(to: URL(fileURLWithPath: out.path + "-actual.png"))
        let ctx = CGContext(data: &diff, width: aw, height: ah, bitsPerComponent: 8, bytesPerRow: aw * 4,
                            space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)
        if let cg = ctx?.makeImage() { try UIImage(cgImage: cg).pngData()?.write(to: URL(fileURLWithPath: out.path + "-diff.png")) }
        return "\(differing) pixels differ, at most \(allowed) allowed"
    }

    /// RGBA, 8 bits a channel, in the device RGB space: both images go through the same conversion.
    static func pixels(_ image: UIImage) throws -> ([UInt8], Int, Int) {
        let cg = try XCTUnwrap(image.cgImage)
        let (w, h) = (cg.width, cg.height)
        var data = [UInt8](repeating: 0, count: w * h * 4)
        let ctx = try XCTUnwrap(CGContext(data: &data, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                                          space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue))
        ctx.draw(cg, in: CGRect(x: 0, y: 0, width: w, height: h))
        return (data, w, h)
    }
}
#endif
