import AVFoundation
import Combine
import Foundation
import TailPocket

/// What TailPocketPairingView shows and does, apart from the view itself, so tests can drive it.
@MainActor
final class PairingModel: ObservableObject {
    enum Status: Equatable { case idle, code(String, String), working(String), failed(String) }

    /// Whether the scanner can be offered: `unsupported` hides it (no camera), `denied` explains why and
    /// offers Settings instead.
    enum Camera: Equatable {
        case available, denied, unsupported

        /// Not asked yet counts as available: the scanner asks when it opens.
        init(supported: Bool, authorization: AVAuthorizationStatus) {
            switch (supported, authorization) {
            case (false, _): self = .unsupported
            case (true, .denied), (true, .restricted): self = .denied
            default: self = .available
            }
        }
    }

    /// A same-Wi-Fi pairing begun with a computer: the code both screens show, and the wait for its approval.
    struct LocalPairing {
        let code: String
        let finish: () async throws -> TailPocketInvite
    }

    /// What the screen pairs with, from the view's current arguments: each action reads them anew, so a
    /// parent that changes them is followed.
    struct Inputs {
        var prefix: String
        var pair: (TailPocketInvite) async throws -> TailPocketHostLink
        var beginLocal: (TailPocketNearbyHost) async throws -> LocalPairing
        var onPaired: (TailPocketHostLink) -> Void
    }

    @Published var hosts: [TailPocketNearbyHost] = []
    @Published var status: Status = .idle
    @Published var scanning = false
    @Published var pasted = ""
    @Published var camera: Camera

    init(camera: Camera) { self.camera = camera }

    /// Opens the scanner once the camera may be used. `requestAccess` asks the first time and answers
    /// at once after that; a refusal shows the denied state instead of an empty scanner.
    func scan(requestAccess: () async -> Bool) async {
        guard camera == .available else { return }
        if await requestAccess() { scanning = true } else { camera = .denied }
    }

    /// Pairs with the invite found in scanned or pasted text.
    func pairText(_ text: String, _ inputs: Inputs) async {
        guard let code = TailPocket.inviteText(in: text, prefix: inputs.prefix) else {
            status = .failed("That is not a pairing code.")
            return
        }
        do { await finish(try TailPocket.decodeInvite(code, prefix: inputs.prefix), inputs) } catch { status = .failed(Self.message(error)) }
    }

    /// The scanner reported invite text: close it and pair.
    func scanned(_ text: String, _ inputs: Inputs) async {
        scanning = false
        await pairText(text, inputs)
    }

    func pairNearby(_ host: TailPocketNearbyHost, _ inputs: Inputs) async {
        status = .working("Connecting to \(host.name)…")
        do {
            let pending = try await inputs.beginLocal(host)
            status = .code(pending.code, host.name)
            await finish(try await pending.finish(), inputs)
        } catch {
            status = .failed(Self.message(error))
        }
    }

    private func finish(_ invite: TailPocketInvite, _ inputs: Inputs) async {
        status = .working("Pairing with \(invite.hostName.isEmpty ? "the computer" : invite.hostName)…")
        do {
            let link = try await inputs.pair(invite)
            status = .idle
            inputs.onPaired(link)
        } catch {
            status = .failed(Self.message(error))
        }
    }

    static func message(_ error: Error) -> String {
        switch (error as? TailPocketError)?.code {
        case "expired": return "This pairing code has expired. Show a new one on the computer."
        case "taken": return "Another phone already used this code."
        case "denied": return "The computer did not approve this phone."
        case "unreachable", "timeout": return "Could not reach the computer. Check that it is online."
        case "invalid-invite": return "That is not a pairing code."
        default: return "Pairing failed."
        }
    }
}

/// What the QR scanner reports: the invite text in the first payload that has one, once.
struct ScanFilter {
    let prefixes: [String]
    private var reported = false

    init(prefixes: [String]) { self.prefixes = prefixes }

    mutating func take(_ payloads: [String?]) -> String? {
        guard !reported else { return nil }
        for case let text? in payloads {
            if let invite = TailPocket.inviteText(in: text, prefixes: prefixes) {
                reported = true
                return invite
            }
        }
        return nil
    }
}
