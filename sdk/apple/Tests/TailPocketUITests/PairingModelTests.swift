import AVFoundation
import Network
@testable import TailPocket
@testable import TailPocketUI
import XCTest

/// TailPocketPairingView's logic (PairingModel) and the scanner's filter, without a screen or a camera.
@MainActor
final class PairingModelTests: XCTestCase {
    // A valid v1 invite for "Studio Mac" (throwaway keys, expires in 2100), made with connectinvite.Encode.
    nonisolated static let invite = "tailpocket1:eNqMzt2SmjAcQPFX6fyvcSYbEyTcsazgaqsVHRFudvKFgNDQEKy003fv7Bv0PMCZ3x94QPjiAVfK6nGEEJwc0uRXHsfBbtPt5q-ET5i5V8Ta49Wsjmmhmk7zW7Q4fXzPSGWPeo0Tm8dvxXu-354XyLmslAfVE3UwbLKbbbR-bF3nst9nSve-QrJPnnkc3fp0Y6fifb1Z8B352V_iVn20Arf7HVqst5kZj8k97fLDBSfzjSf12aR1kdfPMr3M8k1O5bWuxfV1LE-0FRiBB4OxDkISsCX24K5nCGGwzeOu51AgoSSn2q8U42SJfBpI5ktJSIW1WlJGNdGSULXyA6QqHFC8XPmSCbQSAvvi826NqSCE6P8DD_RzaKweo0_YC8KEkAAhD37wXkMIJzepxnz5xiX8_TcAu4p5aA"
    nonisolated static let link = TailPocketHostLink(address: "tcLINK", port: 48932, name: "Studio Mac", payload: nil, key: "k")
    nonisolated static let host = TailPocketNearbyHost(name: "Studio Mac", endpoint: .hostPort(host: "127.0.0.1", port: 1))

    var paired: [TailPocketHostLink] = []
    var pairedInvites: [TailPocketInvite] = []
    let m = PairingModel(camera: .available)

    func inputs(pair: Result<TailPocketHostLink, Error> = .success(link),
                beginLocal: @escaping (TailPocketNearbyHost) async throws -> PairingModel.LocalPairing = { _ in throw TailPocketError(code: "unreachable") }) -> PairingModel.Inputs {
        .init(prefix: TailPocket.defaultPrefix,
              pair: { [unowned self] invite in pairedInvites.append(invite); return try pair.get() },
              beginLocal: beginLocal,
              onPaired: { [unowned self] in paired.append($0) })
    }

    func testScannedInvitePairsAndReturnsTheLink() async {
        m.scanning = true
        await m.scanned("myapp://pair?c=" + Self.invite, inputs())
        XCTAssertFalse(m.scanning)
        XCTAssertEqual(pairedInvites.map(\.hostName), ["Studio Mac"])
        XCTAssertEqual(paired, [Self.link])
        XCTAssertEqual(m.status, .idle)
    }

    func testTextWithoutAnInviteFailsWithoutPairing() async {
        for text in ["https://example.com", "tailpocket1:", "tailpocket1:junk"] {
            m.status = .idle
            await m.scanned(text, inputs())
            XCTAssertEqual(m.status, .failed("That is not a pairing code."), text)
        }
        XCTAssertTrue(pairedInvites.isEmpty)
        XCTAssertTrue(paired.isEmpty)
    }

    func testPairingFailuresSayWhatHappened() async {
        let cases = [
            "expired": "This pairing code has expired. Show a new one on the computer.",
            "taken": "Another phone already used this code.",
            "denied": "The computer did not approve this phone.",
            "unreachable": "Could not reach the computer. Check that it is online.",
            "timeout": "Could not reach the computer. Check that it is online.",
            "something-new": "Pairing failed.",
        ]
        for (code, text) in cases {
            m.status = .idle
            await m.pairText(Self.invite, inputs(pair: .failure(TailPocketError(code: code))))
            XCTAssertEqual(m.status, .failed(text), code)
        }
        XCTAssertEqual(pairedInvites.count, cases.count)
        XCTAssertTrue(paired.isEmpty)
    }

    func testNearbyShowsTheCodeUntilTheComputerApproves() async throws {
        var approve: CheckedContinuation<Void, Never>?
        var asked: [String] = []
        let pairing = inputs(beginLocal: { host in
            asked.append(host.name)
            return .init(code: "4821", finish: {
                await withCheckedContinuation { approve = $0 }
                return try TailPocket.decodeInvite(Self.invite)
            })
        })
        let task = Task { await m.pairNearby(Self.host, pairing) }
        let deadline = Date().addingTimeInterval(5)
        while approve == nil {
            guard Date() < deadline else { task.cancel(); return XCTFail("the code never waited for approval") }
            try await Task.sleep(nanoseconds: 10_000_000) // iOS 15: no Duration
        }
        XCTAssertEqual(asked, ["Studio Mac"])
        XCTAssertEqual(m.status, .code("4821", "Studio Mac"))
        XCTAssertTrue(paired.isEmpty)
        approve?.resume()
        await task.value
        XCTAssertEqual(paired, [Self.link])
        XCTAssertEqual(m.status, .idle)
    }

    func testNearbyFailureIsShown() async {
        await m.pairNearby(Self.host, inputs(beginLocal: { _ in throw TailPocketError(code: "denied") }))
        XCTAssertEqual(m.status, .failed("The computer did not approve this phone."))
        XCTAssertTrue(paired.isEmpty)
    }

    // The view hands the model its current arguments at each action: after the parent changes them
    // (A to B), only B's pair and onPaired run.
    func testTheLatestInputsAreUsed() async {
        var usedA = 0
        var a = inputs()
        a.pair = { _ in usedA += 1; return Self.link }
        a.onPaired = { _ in usedA += 1 }
        await m.pairText(Self.invite, a)
        XCTAssertEqual(usedA, 2)
        await m.pairText(Self.invite, inputs())
        XCTAssertEqual(usedA, 2)
        XCTAssertEqual(pairedInvites.count, 1)
        XCTAssertEqual(paired, [Self.link])
    }

    func testScannerOpensOnlyWithTheCameraAllowed() async {
        var asked = 0
        await m.scan(requestAccess: { asked += 1; return true })
        XCTAssertTrue(m.scanning)
        XCTAssertEqual(m.camera, .available)

        m.scanning = false
        await m.scan(requestAccess: { asked += 1; return false }) // the first prompt answered No
        XCTAssertFalse(m.scanning)
        XCTAssertEqual(m.camera, .denied)

        for camera in [PairingModel.Camera.denied, .unsupported] {
            m.camera = camera
            await m.scan(requestAccess: { asked += 1; return true })
            XCTAssertFalse(m.scanning)
        }
        XCTAssertEqual(asked, 2)
    }

    func testCameraState() {
        typealias C = PairingModel.Camera
        XCTAssertEqual(C(supported: true, authorization: .authorized), .available)
        XCTAssertEqual(C(supported: true, authorization: .notDetermined), .available)
        XCTAssertEqual(C(supported: true, authorization: .denied), .denied)
        XCTAssertEqual(C(supported: true, authorization: .restricted), .denied)
        XCTAssertEqual(C(supported: false, authorization: .authorized), .unsupported)
        XCTAssertEqual(C(supported: false, authorization: .denied), .unsupported)
    }

    func testScannerReportsTheFirstInviteOnce() {
        var f = ScanFilter(prefixes: ["tailpocket2:", "tailpocket1:"])
        XCTAssertNil(f.take([nil, "https://example.com"]))
        XCTAssertEqual(f.take(["hello", "x tailpocket1:abc y", "tailpocket2:def"]), "tailpocket1:abc")
        XCTAssertNil(f.take(["tailpocket2:def"]))
    }
}
