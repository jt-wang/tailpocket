import Foundation
import React
import TailPocket
import TailPocketUI

/// `NativeModules.TailPocket`: every bridge function through one `call(name, args)`.
@objc(TailPocket)
final class TailPocketModule: RCTEventEmitter {
    private var listening = false
    private lazy var tailPocket = TailPocketBridge(
        scanner: { prefix in
            guard #available(iOS 16.0, *) else { throw TailPocketError(code: "unsupported") }
            return try await TailPocketQRScanner.scan(from: await MainActor.run { RCTPresentedViewController() }, prefix: prefix)
        },
        emit: { [weak self] event, data in
            DispatchQueue.main.async { if self?.listening == true { self?.sendEvent(withName: event, body: data) } }
        })

    override static func requiresMainQueueSetup() -> Bool { false }
    override func supportedEvents() -> [String] { ["tailPocket.nearby"] }
    override func startObserving() { listening = true }
    override func stopObserving() { listening = false }

    @objc(call:args:resolve:reject:)
    func call(_ name: String, args: NSDictionary?, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) {
        let tailPocket = self.tailPocket
        let input = args as? [String: Any]
        Task {
            do {
                resolve(try await tailPocket.call(name, input))
            } catch let error as TailPocketError {
                reject(error.code, error.code, error)
            } catch {
                reject("failed", error.localizedDescription, error)
            }
        }
    }

    override func invalidate() {
        tailPocket.close()
        super.invalidate()
    }
}
